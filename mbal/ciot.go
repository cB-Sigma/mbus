package mbal

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/cB-Sigma/iotcrypto/ccm"
	"github.com/cB-Sigma/mbus/wireless"
)

// Advanced M-Bus over CIoT (Annex C.4.3): CoAP over UDP (port 5683), the
// payload a COSE_Encrypt0 object (content format 16) whose content is a
// CBOR indefinite-length array of one-entry maps; key 20 holds the MBAL
// component {0: MBAL-CL, 1: M-Bus TPL bytes, 2: request ID}.

// CoAPPort is the UDP port of the advanced mechanism (C.4.3.2.3).
const CoAPPort = 5683

// CoAP message types and codes used by the annex (Table C.7).
const (
	CoAPCON uint8 = 0
	CoAPNON uint8 = 1
	CoAPACK uint8 = 2
	CoAPRST uint8 = 3

	CoAPPost    uint8 = 0x02 // 0.02
	CoAPChanged uint8 = 0x44 // 2.04
)

// COSE values of the annex.
const (
	ContentFormatCOSEEncrypt0 = 16 // CoAP content format and CBOR tag of COSE_Encrypt0
	coapOptContentFormat      = 12
	AlgAESCCM16_64_256        = 11 // COSE algorithm AES-CCM-16-64-256 (C.4.3.2.6.5)
	ProtocolMBAL              = 0xCF
	componentMBAL             = 20
)

// CoAPOption is one CoAP option.
type CoAPOption struct {
	Number uint16
	Value  []byte
}

// CoAP is a CoAP message (RFC 7252 header, as in Table C.6).
type CoAP struct {
	Type      uint8
	Code      uint8
	MessageID uint16
	Token     []byte
	Options   []CoAPOption
	Payload   []byte
}

// ParseCoAP reads a CoAP datagram.
func ParseCoAP(b []byte) (*CoAP, error) {
	if len(b) < 4 {
		return nil, errors.New("a CoAP message is at least 4 bytes")
	}
	if b[0]>>6 != 1 {
		return nil, fmt.Errorf("CoAP version %d is not 1", b[0]>>6)
	}
	m := &CoAP{Type: b[0] >> 4 & 3, Code: b[1], MessageID: binary.BigEndian.Uint16(b[2:4])}
	tkl := int(b[0] & 0x0F)
	if tkl > 8 || len(b) < 4+tkl {
		return nil, errors.New("CoAP token length is invalid")
	}
	m.Token = append([]byte(nil), b[4:4+tkl]...)
	p := b[4+tkl:]
	num := 0
	for len(p) > 0 {
		if p[0] == 0xFF {
			if len(p) == 1 {
				return nil, errors.New("CoAP payload marker without payload")
			}
			m.Payload = append([]byte(nil), p[1:]...)
			return m, nil
		}
		delta, length := int(p[0]>>4), int(p[0]&0x0F)
		p = p[1:]
		var err error
		if delta, p, err = coapExt(delta, p); err != nil {
			return nil, err
		}
		if length, p, err = coapExt(length, p); err != nil {
			return nil, err
		}
		if len(p) < length {
			return nil, errors.New("CoAP option is truncated")
		}
		num += delta
		if num > 0xFFFF {
			return nil, errors.New("CoAP option number is out of range")
		}
		m.Options = append(m.Options, CoAPOption{Number: uint16(num), Value: append([]byte(nil), p[:length]...)})
		p = p[length:]
	}
	return m, nil
}

func coapExt(v int, p []byte) (int, []byte, error) {
	switch v {
	case 13:
		if len(p) < 1 {
			return 0, nil, errors.New("CoAP option is truncated")
		}
		return 13 + int(p[0]), p[1:], nil
	case 14:
		if len(p) < 2 {
			return 0, nil, errors.New("CoAP option is truncated")
		}
		return 269 + int(binary.BigEndian.Uint16(p)), p[2:], nil
	case 15:
		return 0, nil, errors.New("CoAP option nibble 15 is reserved")
	}
	return v, p, nil
}

// ContentFormat is the content-format option's value, if present.
func (m *CoAP) ContentFormat() (uint, bool) {
	for _, o := range m.Options {
		if o.Number == coapOptContentFormat {
			var v uint
			for _, x := range o.Value {
				v = v<<8 | uint(x)
			}
			return v, true
		}
	}
	return 0, false
}

// Marshal encodes the message (options sorted by number).
func (m *CoAP) Marshal() []byte {
	b := []byte{1<<6 | m.Type&3<<4 | byte(len(m.Token)&0x0F), m.Code, byte(m.MessageID >> 8), byte(m.MessageID)}
	b = append(b, m.Token...)
	opts := append([]CoAPOption(nil), m.Options...)
	sort.SliceStable(opts, func(i, j int) bool { return opts[i].Number < opts[j].Number })
	last := 0
	for _, o := range opts {
		d, l := int(o.Number)-last, len(o.Value)
		last = int(o.Number)
		dn, dx := coapNibble(d)
		ln, lx := coapNibble(l)
		b = append(b, byte(dn<<4|ln))
		b = append(b, dx...)
		b = append(b, lx...)
		b = append(b, o.Value...)
	}
	if len(m.Payload) > 0 {
		b = append(b, 0xFF)
		b = append(b, m.Payload...)
	}
	return b
}

func coapNibble(v int) (int, []byte) {
	switch {
	case v < 13:
		return v, nil
	case v < 269:
		return 13, []byte{byte(v - 13)}
	}
	return 14, []byte{byte((v - 269) >> 8), byte(v - 269)}
}

// Ack is the piggy-backed acknowledgement of a confirmable request (same
// message ID and token) with code 2.04 and an optional payload.
func (m *CoAP) Ack(payload []byte) *CoAP {
	a := &CoAP{Type: CoAPACK, Code: CoAPChanged, MessageID: m.MessageID, Token: m.Token, Payload: payload}
	return a
}

// COSEHeader is what the COSE_Encrypt0 headers carry (C.4.3.2.6).
type COSEHeader struct {
	Alg              int64  // 0: no encryption (empty protected header)
	ProtocolID       uint64 // kid key 0: CFh for the MBAL interface
	ProtocolRevision uint64 // kid key 1
	IDType           uint64 // kid key 2: 0 = M-Bus M and A fields
	Device           []byte // kid key 3: M (2) and A (6)
	PartialIV        []byte // key 6: 6 bytes, bit 47 the direction
}

// Meter is the M-Bus address in the kid, when it has the M-Bus format.
func (h *COSEHeader) Meter() (wireless.Header, bool) {
	if h == nil || h.IDType != 0 || len(h.Device) != 8 {
		return wireless.Header{}, false
	}
	a, err := AddressFromBytes(h.Device)
	return a, err == nil
}

// CIoTContent is a decoded CoAP payload of the advanced mechanism.
type CIoTContent struct {
	// COSE is nil when the payload is the bare component array (as the
	// examples of C.4.3.4.3 show it).
	COSE      *COSEHeader
	Encrypted bool // content was AES-CCM protected (and decrypted)
	Messages  []Message
	// Proprietary holds the values of keys 0-19 (Table C.15).
	Proprietary map[uint64][]any
}

// COSEKeys returns the 256-bit key for a kid device (M and A, 8 bytes), or
// nil.
type COSEKeys func(device []byte) []byte

// ParseCIoT reads the CoAP payload of the advanced mechanism: a
// COSE_Encrypt0 (tagged or not) or, as in the annex's examples, the bare
// component array. Encrypted content needs keys.
func ParseCIoT(payload []byte, d Direction, keys COSEKeys) (*CIoTContent, error) {
	v, err := cborDecode(payload)
	if err != nil {
		return nil, err
	}
	if t, ok := v.(cborTag); ok {
		if t.Num != ContentFormatCOSEEncrypt0 {
			return nil, fmt.Errorf("CBOR tag %d is not COSE_Encrypt0", t.Num)
		}
		v = t.Val
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, errors.New("the CIoT payload is not a CBOR array")
	}
	out := &CIoTContent{}
	content := arr
	if isEncrypt0(arr) {
		plain, h, enc, err := openEncrypt0(arr, keys)
		out.COSE, out.Encrypted = h, enc
		if err != nil {
			return out, err
		}
		cv, err := cborDecode(plain)
		if err != nil {
			return out, fmt.Errorf("COSE content: %w", err)
		}
		if content, ok = cv.([]any); !ok {
			return out, errors.New("the COSE content is not a CBOR array")
		}
	}
	return out, out.components(content, d)
}

// isEncrypt0 tells a COSE_Encrypt0 [protected bstr, unprotected map,
// ciphertext bstr] from a component array (whose elements are maps).
func isEncrypt0(a []any) bool {
	if len(a) != 3 {
		return false
	}
	_, p := a[0].([]byte)
	_, u := a[1].(map[any]any)
	_, c := a[2].([]byte)
	return p && u && (c || a[2] == nil)
}

func openEncrypt0(a []any, keys COSEKeys) (plain []byte, h *COSEHeader, encrypted bool, err error) {
	prot := a[0].([]byte)
	unprot := a[1].(map[any]any)
	h = &COSEHeader{}
	if len(prot) > 0 {
		pv, err := cborDecode(prot)
		if err != nil {
			return nil, h, false, fmt.Errorf("COSE protected header: %w", err)
		}
		pm, ok := pv.(map[any]any)
		if !ok {
			return nil, h, false, errors.New("the COSE protected header is not a map")
		}
		if alg, ok := cborGet(pm, 1); ok {
			h.Alg, _ = cborInt(alg)
		}
	}
	if kid, ok := cborGet(unprot, 4); ok {
		if km, ok := kid.(map[any]any); ok {
			if v, ok := cborGet(km, 0); ok {
				h.ProtocolID, _ = cborUint(v)
			}
			if v, ok := cborGet(km, 1); ok {
				h.ProtocolRevision, _ = cborUint(v)
			}
			if v, ok := cborGet(km, 2); ok {
				h.IDType, _ = cborUint(v)
			}
			if v, ok := cborGet(km, 3); ok {
				h.Device, _ = v.([]byte)
			}
		}
	}
	if v, ok := cborGet(unprot, 6); ok {
		h.PartialIV, _ = v.([]byte)
	}
	if h.ProtocolID != 0 && h.ProtocolID != ProtocolMBAL {
		return nil, h, false, fmt.Errorf("COSE kid protocol %Xh is not the MBAL interface (CFh)", h.ProtocolID)
	}
	ct, _ := a[2].([]byte)
	if h.Alg == 0 {
		return ct, h, false, nil
	}
	if h.Alg != AlgAESCCM16_64_256 {
		return nil, h, true, fmt.Errorf("COSE algorithm %d is not supported (only AES-CCM-16-64-256, 11)", h.Alg)
	}
	if len(h.PartialIV) != 6 || len(h.Device) != 8 {
		return nil, h, true, errors.New("the COSE header lacks the 6-byte partial IV or the 8-byte device")
	}
	var key []byte
	if keys != nil {
		key = keys(h.Device)
	}
	if key == nil {
		return nil, h, true, ErrEncrypted
	}
	plain, err = OpenCOSE(key, h, prot, ct)
	return plain, h, true, err
}

// COSENonce is the 13-byte AES-CCM nonce (C.4.3.4.1, Table C.19): the
// identification ID type, the manufacturer (2 bytes) and the M-Bus ID (4
// bytes) as they are in the kid device field, then the partial IV.
func COSENonce(h *COSEHeader) ([]byte, error) {
	if len(h.PartialIV) != 6 || len(h.Device) < 6 {
		return nil, errors.New("the nonce needs the 6-byte partial IV and the device M and ID")
	}
	n := make([]byte, 0, 13)
	n = append(n, byte(h.IDType))
	n = append(n, h.Device[:6]...)
	return append(n, h.PartialIV...), nil
}

// coseAAD is the Enc_structure ["Encrypt0", protected, h”].
func coseAAD(prot []byte) []byte {
	b := []byte{0x83}
	b = cborAppendText(b, "Encrypt0")
	b = cborAppendBytes(b, prot)
	return cborAppendBytes(b, nil)
}

// OpenCOSE decrypts and authenticates COSE_Encrypt0 content with
// AES-CCM-16-64-256 (8-byte tag, 13-byte nonce).
func OpenCOSE(key []byte, h *COSEHeader, prot, ct []byte) ([]byte, error) {
	nonce, err := COSENonce(h)
	if err != nil {
		return nil, err
	}
	return ccmOpen(key, nonce, ct, coseAAD(prot), 8)
}

// SealCOSE encrypts content the same way (for replies and tests).
func SealCOSE(key []byte, h *COSEHeader, prot, plain []byte) ([]byte, error) {
	nonce, err := COSENonce(h)
	if err != nil {
		return nil, err
	}
	return ccmSeal(key, nonce, plain, coseAAD(prot), 8)
}

// BuildEncrypt0 encodes a tagged COSE_Encrypt0; with key nil the protected
// header is empty and the content travels in clear.
func BuildEncrypt0(h *COSEHeader, content, key []byte) ([]byte, error) {
	var prot []byte
	ct := content
	if key != nil {
		prot = cborAppendUint([]byte{0xA1}, 1)
		prot = cborAppendInt(prot, AlgAESCCM16_64_256)
		var err error
		if ct, err = SealCOSE(key, h, prot, content); err != nil {
			return nil, err
		}
	}
	b := cborHead(nil, 6, ContentFormatCOSEEncrypt0)
	b = append(b, 0x83)
	b = cborAppendBytes(b, prot)
	// unprotected: {4: {0: pid, 1: rev, 2: idtype, 3: device}, 6: partial IV}
	b = append(b, 0xA2, 0x04, 0xA4)
	b = append(cborAppendUint(append(cborAppendUint(append(cborAppendUint(append(b, 0x00), h.ProtocolID), 0x01), h.ProtocolRevision), 0x02), h.IDType), 0x03)
	b = cborAppendBytes(b, h.Device)
	b = cborAppendBytes(append(b, 0x06), h.PartialIV)
	return cborAppendBytes(b, ct), nil
}

func (c *CIoTContent) components(arr []any, d Direction) error {
	for i, e := range arr {
		m, ok := e.(map[any]any)
		if !ok || len(m) != 1 {
			return fmt.Errorf("payload component %d is not a one-entry CBOR map", i+1)
		}
		for k, v := range m {
			key, ok := k.(uint64)
			if !ok {
				return fmt.Errorf("payload component %d has a key that is not an unsigned integer", i+1)
			}
			if key < componentMBAL {
				if c.Proprietary == nil {
					c.Proprietary = map[uint64][]any{}
				}
				c.Proprietary[key] = append(c.Proprietary[key], v)
				continue
			}
			if key != componentMBAL {
				continue // not defined by this revision
			}
			mm, ok := v.(map[any]any)
			if !ok {
				return fmt.Errorf("MBAL component %d is not a CBOR map", i+1)
			}
			msg := Message{Tech: "coap", HasMBAL: true}
			cl, ok := cborGet(mm, 0)
			u, uok := cborUint(cl)
			if !ok || !uok {
				return fmt.Errorf("MBAL component %d has no MBAL-CL (key 0)", i+1)
			}
			if u > 0xFF {
				return fmt.Errorf("MBAL component %d: a 2-byte MBAL-CL (%04Xh) is reserved", i+1, u)
			}
			msg.Control = ParseControl(byte(u), d)
			if err := msg.Control.Check(); err != nil {
				return err
			}
			if tpl, ok := cborGet(mm, 1); ok {
				b, ok := tpl.([]byte)
				if !ok {
					return fmt.Errorf("MBAL component %d: the M-Bus TPL (key 1) is not a byte string", i+1)
				}
				msg.Upper = b
			}
			if rid, ok := cborGet(mm, 2); ok {
				r, ok := cborUint(rid)
				if !ok || r > 0xFFFF {
					return fmt.Errorf("MBAL component %d: the request ID (key 2) is not 0-65535", i+1)
				}
				v := uint16(r)
				msg.RequestID = &v
			}
			c.Messages = append(c.Messages, msg)
		}
	}
	return nil
}

// EncodeCIoT encodes MBAL messages as the content array
// [{20: {0: CL, 1: TPL, 2: request ID}}, …] (C.4.3.3.2, Table C.17).
func EncodeCIoT(msgs []Message) []byte {
	b := []byte{0x9F}
	for _, m := range msgs {
		n := uint64(1)
		if len(m.Upper) > 0 {
			n++
		}
		if m.RequestID != nil {
			n++
		}
		b = append(b, 0xA1, 0x14)
		b = cborHead(b, 5, n)
		b = cborAppendUint(append(b, 0x00), uint64(m.Control.Byte()))
		if len(m.Upper) > 0 {
			b = cborAppendBytes(append(b, 0x01), m.Upper)
		}
		if m.RequestID != nil {
			b = cborAppendUint(append(b, 0x02), uint64(*m.RequestID))
		}
	}
	return append(b, 0xFF)
}

// ---- AES-CCM (RFC 3610) -----------------------------------------------------

// ccmAEAD returns AES-CCM (libs/iotcrypto/ccm) for key, nonce and tag
// lengths, refusing a message of msgLen bytes that the nonce's length field
// cannot carry, with this package's error texts.
func ccmAEAD(key, nonce []byte, msgLen, tagLen int) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := ccm.New(blk, len(nonce), tagLen)
	if err != nil {
		return nil, errors.New("CCM parameters are invalid")
	}
	if l := 15 - len(nonce); l < 8 && msgLen >= 1<<(8*l) {
		return nil, errors.New("CCM message too long")
	}
	return a, nil
}

func ccmSeal(key, nonce, plain, aad []byte, tagLen int) ([]byte, error) {
	a, err := ccmAEAD(key, nonce, len(plain), tagLen)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, nonce, plain, aad), nil
}

var errCCMAuth = errors.New("COSE content does not authenticate (wrong key or tampered)")

func ccmOpen(key, nonce, ct, aad []byte, tagLen int) ([]byte, error) {
	if len(ct) < tagLen {
		return nil, errors.New("CCM ciphertext shorter than its tag")
	}
	a, err := ccmAEAD(key, nonce, len(ct)-tagLen, tagLen)
	if err != nil {
		return nil, err
	}
	plain, err := a.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, errCCMAuth
	}
	return plain, nil
}
