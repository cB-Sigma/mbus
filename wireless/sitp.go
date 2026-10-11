package wireless

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
)

// Security Information Transfer Protocol (EN 13757-7:2025 annex A): key
// management between a communication partner (us, the head end) and a
// meter. We build commands (CI C3h with a long TPL header, C6h short) and
// read the meter's responses (C4h short, C5h long). The APL is a list of
// blocks: block length (2 bytes, LSB first, counting from the block ID),
// block ID (from 0), block control field (BCF), recipient ID, data
// structure identifier (DSI), DSH1, DSH2 and the data structure content.

// SITP CI fields (table A.1).
const (
	CISITPCmdLong   byte = 0xC3
	CISITPRespShort byte = 0xC4
	CISITPRespLong  byte = 0xC5
	CISITPCmdShort  byte = 0xC6
)

// Block control field commands (table A.3); a response is the command
// with bit 7 set (A0h answers 20h).
const (
	SITPTransfer     byte = 0x00 // DSI 01h
	SITPActivate     byte = 0x01 // DSI 02h
	SITPDeactivate   byte = 0x02 // DSI 02h
	SITPDestroy      byte = 0x03 // DSI 02h
	SITPCombined     byte = 0x04 // DSI 03h
	SITPGenerate     byte = 0x05 // DSI 02h
	SITPGetInfo      byte = 0x06 // DSI 00h → 01h or 22h
	SITPListAll      byte = 0x07 // DSI 00h → 20h or 22h
	SITPListActive   byte = 0x08 // DSI 00h → 21h or 22h
	SITPListCounters byte = 0x09 // DSI 00h → 23h or 22h
	SITPSecuredData  byte = 0x20 // DSI 30h–37h → A0h
)

// Data structure identifiers (table A.5).
const (
	DSIEmpty        byte = 0x00
	DSIKey          byte = 0x01 // KWP: key, target time, key ID, version
	DSIKeyAction    byte = 0x02 // KWP: target time, key ID, version
	DSIKeyPair      byte = 0x03 // KWP: target time, activate and deactivate IDs/versions, option
	DSIAllKeys      byte = 0x20 // KWP: all key IDs and versions
	DSIActiveKeys   byte = 0x21 // key ID, version pairs
	DSIStatus       byte = 0x22 // one status byte
	DSIActiveCounts byte = 0x23 // key ID, version, key counter
	DSICertificate  byte = 0x10 // X.509 certificates, DER (OMS annex F table F.A.5)
	DSIKeyPairDER   byte = 0x11 // key pair, DER (RFC 5958), OMS annex F
	DSIHMACSHA256   byte = 0x31
	DSICMAC8        byte = 0x32
	DSICMAC16       byte = 0x33
	DSIGCM          byte = 0x34
	DSIGMAC         byte = 0x35
	DSICCM8         byte = 0x36
	DSICCM16        byte = 0x37
)

func isSITP(ci byte) bool { return ci >= CISITPCmdLong && ci <= CISITPCmdShort }

// Key IDs of OMS Volume 2 annex F (F.4.3.1, F.4.4.1, table F.A.8).
const (
	KeyIDMaster        byte = 0x00 // master key MK
	KeyIDGatewayCert1  byte = 0x81 // trust anchor: the gateway certificate
	KeyIDGatewayCert2  byte = 0x82
	KeyIDMeterCert     byte = 0x90 // the meter's TLS certificate (MTR_TLS_CRT)
	KeyIDMeterKeyPair  byte = 0xA0 // its key pair
	KeyVersionUnused   byte = 0xFF
	SITPStatusMismatch byte = 0x81
)

// SITPPlainKey is DSI 01h content without wrapping (DSH FFh FFh, only
// inside a TLS channel, OMS annex F table F.22): key, target time, key ID
// and version.
func SITPPlainKey(key []byte, at TargetTime, k KeyInfo) []byte {
	return append(append(append([]byte(nil), key...), at[:]...), k.ID, k.Version)
}

// SITPPlainAction is DSI 02h content without wrapping (table F.30).
func SITPPlainAction(at TargetTime, k KeyInfo) []byte {
	return append(append([]byte(nil), at[:]...), k.ID, k.Version)
}

// SITPPlainKeyPair is DSI 03h content without wrapping (table F.25).
func SITPPlainKeyPair(at TargetTime, activate, deactivate KeyInfo, counterReset bool) []byte {
	b := append(append([]byte(nil), at[:]...), activate.ID, activate.Version, deactivate.ID, deactivate.Version, 0)
	if counterReset {
		b[len(b)-1] = 1
	}
	return b
}

// TargetTimeOf is a 5-byte target time from its value as annex F writes
// it (3000000000h now, 3080000000h invalid), least significant byte first.
func TargetTimeOf(v uint64) TargetTime {
	var t TargetTime
	for i := range t {
		t[i] = byte(v >> (8 * i))
	}
	return t
}

// SITPBlock is one command or response block.
type SITPBlock struct {
	ID        byte
	BCF       byte
	Recipient byte
	DSI       byte
	DSH1      byte
	DSH2      byte
	Content   []byte
}

// ErrSITPLength is a block length below 6: the whole structure is ignored
// (the meter answers application error 15h).
var ErrSITPLength = errors.New("SITP block length below 6: the whole structure is ignored")

// EncodeSITP builds the APL of an SITP command.
func EncodeSITP(blocks ...SITPBlock) []byte {
	var b []byte
	for _, k := range blocks {
		b = binary.LittleEndian.AppendUint16(b, uint16(6+len(k.Content)))
		b = append(b, k.ID, k.BCF, k.Recipient, k.DSI, k.DSH1, k.DSH2)
		b = append(b, k.Content...)
	}
	return b
}

// ParseSITP splits an SITP APL into blocks. Idle fillers (2Fh) after the
// last block are skipped.
func ParseSITP(apl []byte) ([]SITPBlock, error) {
	var out []SITPBlock
	for len(apl) > 0 {
		if bytes.Count(apl, []byte{0x2F}) == len(apl) {
			break // idle fillers after the last block
		}
		if len(apl) < 2 {
			return nil, errTruncated
		}
		n := int(binary.LittleEndian.Uint16(apl))
		if n < 6 {
			return nil, ErrSITPLength
		}
		if len(apl) < 2+n {
			return nil, fmt.Errorf("SITP block of %d bytes, %d left", n, len(apl)-2)
		}
		b := apl[2 : 2+n]
		out = append(out, SITPBlock{ID: b[0], BCF: b[1], Recipient: b[2], DSI: b[3], DSH1: b[4], DSH2: b[5], Content: append([]byte(nil), b[6:]...)})
		apl = apl[2+n:]
	}
	return out, nil
}

// SITPStatusText names a status response byte (table A.14).
func SITPStatusText(s byte) string {
	switch {
	case s == 0x00:
		return "success"
	case s == 0x01:
		return "scheduled at the target time"
	case s == 0x08:
		return "busy"
	case s == 0x10:
		return "unspecified error"
	case s == 0x11:
		return "multiple blocks not supported"
	case s == 0x14:
		return "unknown recipient ID"
	case s == 0x15:
		return "unknown data structure"
	case s == 0x16:
		return "command and data structure do not match"
	case s == 0x17:
		return "data structure and content do not match"
	case s == 0x18:
		return "unknown or invalid wrapper key"
	case s == 0x19:
		return "unknown or invalid key ID or version"
	case s == 0x20:
		return "error in the data content"
	case s == 0x21:
		return "unknown or invalid key ID or version in the content"
	case s == 0x22:
		return "not allowed for the active key"
	case s == 0x23:
		return "target time error"
	case s == 0x24:
		return "key counter error"
	case s == 0x25:
		return "unwrapping failed"
	case s == 0x26:
		return "MAC error"
	case s == 0x27:
		return "unknown or invalid protocol identifier"
	case s >= 0xE0:
		return "manufacturer specific"
	case s == 0x81:
		return "key pair and certificate do not match"
	case s >= 0x80 && s <= 0x8F:
		return "reserved (asymmetric)"
	case s < 0x10:
		return "reserved status (no error)"
	}
	return "reserved error"
}

// TargetTime is a 5-byte type M date/time (EN 13757-3:2025 annex A),
// least significant byte first. All zero means "now".
type TargetTime [5]byte

// KeyInfo names a key: its Key ID and version (FFh: not used).
type KeyInfo struct{ ID, Version byte }

// The fixed plaintext lengths (MLI) of the wrapped structures.
const (
	mliKey     = 0x17
	mliAction  = 0x07
	mliKeyPair = 0x0A
)

// SITPWrapKey builds DSI 01h content: the new key wrapped with the wrapper
// key (KWP), for BCF 00h.
func SITPWrapKey(kek, key []byte, at TargetTime, k KeyInfo) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.New("SITP transfers AES-128 keys (16 bytes)")
	}
	p := append(append(append([]byte(nil), key...), at[:]...), k.ID, k.Version)
	return KWPWrap(kek, p)
}

// SITPWrapAction builds DSI 02h content for activate, deactivate, destroy
// and generate.
func SITPWrapAction(kek []byte, at TargetTime, k KeyInfo) ([]byte, error) {
	return KWPWrap(kek, append(append([]byte(nil), at[:]...), k.ID, k.Version))
}

// SITPWrapKeyPair builds DSI 03h content: activate one key and deactivate
// another at the same time, optionally resetting the counter.
func SITPWrapKeyPair(kek []byte, at TargetTime, activate, deactivate KeyInfo, counterReset bool) ([]byte, error) {
	p := append(append([]byte(nil), at[:]...), activate.ID, activate.Version, deactivate.ID, deactivate.Version, 0)
	if counterReset {
		p[len(p)-1] = 0x01
	}
	return KWPWrap(kek, p)
}

// SITPKey is the content of a DSI 01h structure after unwrapping.
type SITPKey struct {
	Key []byte
	At  TargetTime
	KeyInfo
}

// SITPUnwrapKey reads DSI 01h content (the answer to "get security
// information" for a generated key).
func SITPUnwrapKey(kek, content []byte) (SITPKey, error) {
	p, err := KWPUnwrap(kek, content)
	if err != nil {
		return SITPKey{}, err
	}
	if len(p) != mliKey {
		return SITPKey{}, fmt.Errorf("DSI 01h holds %d bytes, want %d", len(p), mliKey)
	}
	var k SITPKey
	k.Key = p[:16]
	copy(k.At[:], p[16:21])
	k.ID, k.Version = p[21], p[22]
	return k, nil
}

// SITPUnwrapAllKeys reads DSI 20h content: for each Key ID the versions
// the meter holds.
func SITPUnwrapAllKeys(kek, content []byte) (map[byte][]byte, error) {
	p, err := KWPUnwrap(kek, content)
	if err != nil {
		return nil, err
	}
	out := map[byte][]byte{}
	for len(p) > 0 {
		if len(p) < 2 || len(p) < 2+int(p[1]) || p[1] == 0 {
			return nil, errors.New("DSI 20h: a key entry is cut short")
		}
		out[p[0]] = append([]byte(nil), p[2:2+int(p[1])]...)
		p = p[2+int(p[1]):]
	}
	return out, nil
}

// SITPActiveKeys reads DSI 21h content.
func SITPActiveKeys(content []byte) ([]KeyInfo, error) {
	if len(content)%2 != 0 {
		return nil, errors.New("DSI 21h is key ID / version pairs")
	}
	var out []KeyInfo
	for i := 0; i < len(content); i += 2 {
		out = append(out, KeyInfo{content[i], content[i+1]})
	}
	return out, nil
}

// SITPKeyCounter is one entry of DSI 23h.
type SITPKeyCounter struct {
	KeyInfo
	Counter uint32
}

// SITPActiveCounters reads DSI 23h content.
func SITPActiveCounters(content []byte) ([]SITPKeyCounter, error) {
	if len(content)%6 != 0 {
		return nil, errors.New("DSI 23h is key ID, version and a 4-byte counter per key")
	}
	var out []SITPKeyCounter
	for i := 0; i < len(content); i += 6 {
		out = append(out, SITPKeyCounter{KeyInfo{content[i], content[i+1]}, binary.LittleEndian.Uint32(content[i+2:])})
	}
	return out, nil
}

// SITP directions of the IV/nonce of structures 34h–37h.
const (
	SITPDown byte = 0x01 // partner to meter
	SITPUp   byte = 0x02 // meter to partner
)

// SITPApp is the content of structures 31h–37h: end-to-end protected
// application data.
type SITPApp struct {
	KeyCounter uint32
	At         TargetTime
	PID        byte // 01h M-Bus, 02h application error, ... (table A.16)
	APDU       []byte
}

func (a SITPApp) body() []byte {
	return append(append(append([]byte(nil), a.At[:]...), a.PID), a.APDU...)
}

// sitpIV is the 12-byte GCM/GMAC IV (tables A.21, A.23): manufacturer,
// identification number, version, direction, key counter (MSB first).
func sitpIV(m Header, dir byte, kc uint32) []byte {
	b := binary.LittleEndian.AppendUint16(nil, m.MField)
	b = append(b, m.A[:5]...)
	b = append(b, dir)
	return binary.BigEndian.AppendUint32(b, kc)
}

// sitpNonce is the 13-byte CCM nonce (table A.26): address with device
// type, direction, key counter (MSB first).
func sitpNonce(m Header, dir byte, kc uint32) []byte {
	b := append(addr8(m), dir)
	return binary.BigEndian.AppendUint32(b, kc)
}

// SealSITPApp builds the content of a secured application data structure
// (DSI 31h–37h) with the key the block's DSH names.
func SealSITPApp(key []byte, dsi byte, meter Header, dir byte, a SITPApp) ([]byte, error) {
	kc := binary.LittleEndian.AppendUint32(nil, a.KeyCounter)
	body := a.body()
	switch dsi {
	case DSIHMACSHA256:
		h := hmac.New(sha256.New, key)
		h.Write(kc)
		h.Write(body)
		return append(append(kc, body...), h.Sum(nil)...), nil
	case DSICMAC8, DSICMAC16:
		mac, err := CMAC(key, append(append([]byte(nil), kc...), body...))
		if err != nil {
			return nil, err
		}
		n := 8
		if dsi == DSICMAC16 {
			n = 16
		}
		return append(append(kc, body...), mac[:n]...), nil
	case DSIGCM:
		ct, tag, err := gcmSeal(key, sitpIV(meter, dir, a.KeyCounter), nil, body, 12)
		if err != nil {
			return nil, err
		}
		return append(append(kc, ct...), tag...), nil
	case DSIGMAC:
		_, tag, err := gcmSeal(key, sitpIV(meter, dir, a.KeyCounter), body, nil, 12)
		if err != nil {
			return nil, err
		}
		return append(append(kc, body...), tag...), nil
	case DSICCM8, DSICCM16:
		n := 8
		if dsi == DSICCM16 {
			n = 16
		}
		out, err := ccm(key, sitpNonce(meter, dir, a.KeyCounter), nil, body, n, false)
		if err != nil {
			return nil, err
		}
		return append(kc, out...), nil
	}
	return nil, fmt.Errorf("%w: SITP data structure %02Xh", ErrUnsupport, dsi)
}

// OpenSITPApp checks and opens a secured application data structure.
func OpenSITPApp(key []byte, dsi byte, meter Header, dir byte, content []byte) (SITPApp, error) {
	var a SITPApp
	tagLen := map[byte]int{DSIHMACSHA256: 32, DSICMAC8: 8, DSICMAC16: 16, DSIGCM: 12, DSIGMAC: 12, DSICCM8: 8, DSICCM16: 16}[dsi]
	if tagLen == 0 {
		return a, fmt.Errorf("%w: SITP data structure %02Xh", ErrUnsupport, dsi)
	}
	if len(content) < 4+6+tagLen {
		return a, errTruncated
	}
	a.KeyCounter = binary.LittleEndian.Uint32(content)
	mid, tag := content[4:len(content)-tagLen], content[len(content)-tagLen:]
	var body []byte
	switch dsi {
	case DSIHMACSHA256:
		h := hmac.New(sha256.New, key)
		h.Write(content[:4])
		h.Write(mid)
		if subtle.ConstantTimeCompare(h.Sum(nil), tag) != 1 {
			return a, ErrMAC
		}
		body = mid
	case DSICMAC8, DSICMAC16:
		mac, err := CMAC(key, content[:len(content)-tagLen])
		if err != nil {
			return a, err
		}
		if subtle.ConstantTimeCompare(mac[:tagLen], tag) != 1 {
			return a, ErrMAC
		}
		body = mid
	case DSIGCM:
		p, err := gcmOpen(key, sitpIV(meter, dir, a.KeyCounter), nil, mid, tag)
		if err != nil {
			return a, err
		}
		body = p
	case DSIGMAC:
		if _, err := gcmOpen(key, sitpIV(meter, dir, a.KeyCounter), mid, nil, tag); err != nil {
			return a, err
		}
		body = mid
	case DSICCM8, DSICCM16:
		p, err := ccm(key, sitpNonce(meter, dir, a.KeyCounter), nil, content[4:], tagLen, true)
		if err != nil {
			return a, err
		}
		body = p
	}
	copy(a.At[:], body[:5])
	a.PID, a.APDU = body[5], append([]byte(nil), body[6:]...)
	return a, nil
}

// SITPResponse is a decoded response block.
type SITPResponse struct {
	Block  SITPBlock
	Status *byte // DSI 22h
	// Filled when the DSI carries it and the key to open it was known.
	Key      *SITPKey
	AllKeys  map[byte][]byte
	Active   []KeyInfo
	Counters []SITPKeyCounter
	App      *SITPApp
	// Certificate is a DSI 10h answer (OMS annex F F.4.4.2).
	Certificate *x509.Certificate
}

// ReadSITPResponses decodes the blocks of a response APL. wrapper returns
// the wrapper or end-to-end key a block's DSH1/DSH2 name (nil: unknown).
// A response whose BCF is not the command's with bit 7 set, or whose
// DSI is not allowed for it (table A.3), is refused.
func ReadSITPResponses(apl []byte, meter Header, wrapper func(id, version byte) []byte) ([]SITPResponse, error) {
	blocks, err := ParseSITP(apl)
	if err != nil {
		return nil, err
	}
	var out []SITPResponse
	for _, b := range blocks {
		r := SITPResponse{Block: b}
		if b.BCF&0x80 == 0 {
			return nil, fmt.Errorf("SITP block %d: BCF %02Xh is a command", b.ID, b.BCF)
		}
		if !sitpDSIAllowed(b.BCF, b.DSI) {
			return nil, fmt.Errorf("SITP block %d: data structure %02Xh does not answer BCF %02Xh", b.ID, b.DSI, b.BCF)
		}
		key := func() ([]byte, error) {
			if wrapper == nil {
				return nil, ErrNoKey
			}
			k := wrapper(b.DSH1, b.DSH2)
			if k == nil {
				return nil, ErrNoKey
			}
			return k, nil
		}
		switch b.DSI {
		case DSICertificate:
			c, err := x509.ParseCertificate(b.Content)
			if err != nil {
				return nil, fmt.Errorf("SITP block %d: certificate: %w", b.ID, err)
			}
			r.Certificate = c
		case DSIStatus:
			if len(b.Content) != 1 {
				return nil, errors.New("DSI 22h is one status byte")
			}
			s := b.Content[0]
			r.Status = &s
		case DSIKey:
			k, err := key()
			if err != nil {
				return nil, err
			}
			v, err := SITPUnwrapKey(k, b.Content)
			if err != nil {
				return nil, err
			}
			r.Key = &v
		case DSIAllKeys:
			k, err := key()
			if err != nil {
				return nil, err
			}
			if r.AllKeys, err = SITPUnwrapAllKeys(k, b.Content); err != nil {
				return nil, err
			}
		case DSIActiveKeys:
			if r.Active, err = SITPActiveKeys(b.Content); err != nil {
				return nil, err
			}
		case DSIActiveCounts:
			if r.Counters, err = SITPActiveCounters(b.Content); err != nil {
				return nil, err
			}
		default:
			k, err := key()
			if err != nil {
				return nil, err
			}
			a, err := OpenSITPApp(k, b.DSI, meter, SITPUp, b.Content)
			if err != nil {
				return nil, err
			}
			r.App = &a
		}
		out = append(out, r)
	}
	return out, nil
}

// sitpDSIAllowed is table A.3's response column.
func sitpDSIAllowed(bcf, dsi byte) bool {
	if dsi == DSIStatus {
		return true
	}
	switch bcf {
	case 0x86:
		return dsi == DSIKey || dsi == DSICertificate
	case 0x87:
		return dsi == DSIAllKeys
	case 0x88:
		return dsi == DSIActiveKeys
	case 0x89:
		return dsi == DSIActiveCounts
	case 0xA0:
		return dsi >= DSIHMACSHA256 && dsi <= DSICCM16
	}
	return bcf >= 0xF0 // manufacturer specific: any
}

// SITPResponseBCF is the BCF that answers a command.
func SITPResponseBCF(cmd byte) byte {
	if cmd == SITPSecuredData {
		return 0xA0
	}
	return cmd | 0x80
}
