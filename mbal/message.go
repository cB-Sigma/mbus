package mbal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	"github.com/cB-Sigma/mbus/records"
	"github.com/cB-Sigma/mbus/wireless"
)

// Message is one MBAL message: the control field and the M-Bus upper
// layers that follow it.
type Message struct {
	// Tech is the carrier: "lorawan", "udp", "coap", "mioty" or "wize".
	Tech string
	// WithCI: the MBAL CI field CFh preceded the control field.
	WithCI bool
	// HasMBAL is false for MIOTY payloads that carry M-Bus without an
	// MBAL (MPF 80h without CFh, or 81h).
	HasMBAL bool
	Control Control
	// Upper is the M-Bus upper layers from their first CI field (AFL, TPL
	// or APL); empty for messages without upper layers (ACC-NR, TPL-ACK…).
	Upper []byte
	// APL is application data without any CI field (MIOTY MPF 81h).
	APL []byte
	// RequestID pairs two-way requests and responses over CoAP (Annex
	// C.4.3.3.3, CBOR key 2); nil when absent.
	RequestID *uint16
}

// Errors a caller may test for.
var (
	ErrEmpty     = errors.New("the payload is empty")
	ErrNoMBAL    = errors.New("the payload does not start with the MBAL CI field CFh")
	ErrFPort     = errors.New("the LoRaWAN FPort is not an MBAL control field")
	ErrMIOTYMPF  = errors.New("the MIOTY MPF does not announce M-Bus (80h, 81h or 83h)")
	ErrEncrypted = errors.New("the payload is encrypted and no key is configured")
)

// split reads [CFh] MBAL-CL upper… ; ciRequired refuses a payload without
// the CI field.
func split(tech string, b []byte, d Direction, ciRequired bool) (*Message, error) {
	if len(b) == 0 {
		return nil, ErrEmpty
	}
	m := &Message{Tech: tech, HasMBAL: true}
	if b[0] == CI {
		m.WithCI = true
		b = b[1:]
	} else if ciRequired {
		return nil, ErrNoMBAL
	}
	if len(b) == 0 {
		return nil, errors.New("the MBAL CI field is not followed by a control field")
	}
	m.Control = ParseControl(b[0], d)
	if err := m.Control.Check(); err != nil {
		return m, err
	}
	m.Upper = b[1:]
	return m, nil
}

// Parse reads the generic MBAL layout: an optional CI field CFh, the
// control field, then the upper layers (7.1, Table 5). A version 1 control
// field is never CFh, so a leading CFh is the CI field (7.1, NOTE).
func Parse(b []byte, d Direction) (*Message, error) { return split("mbal", b, d, false) }

// ParseLoRaWAN reads M-Bus over LoRaWAN (Annex D.6.1, Table D.3): the
// FPort carries the control field and the FRMPayload starts with the CI
// field of the upper layers (no MBAL CI field). FPort 0 is LoRaWAN MAC
// signalling and 224-255 are reserved, so they are refused.
func ParseLoRaWAN(fport int, frm []byte, d Direction) (*Message, error) {
	if fport < 1 || fport > 223 {
		return nil, fmt.Errorf("%w: %d", ErrFPort, fport)
	}
	m := &Message{Tech: "lorawan", HasMBAL: true, Control: ParseControl(byte(fport), d), Upper: frm}
	if err := m.Control.Check(); err != nil {
		return m, err
	}
	return m, nil
}

// LoRaWANPort is the FPort that carries a control field (Annex D.6.1). A
// version 1 TPL-ACK uplink without access (00h) cannot be sent: FPort 0 is
// reserved for MAC commands.
func LoRaWANPort(c Control) (int, error) {
	p := int(c.Byte())
	if p < 1 || p > 223 {
		return 0, fmt.Errorf("control field %02X cannot be an FPort (1–223)", p)
	}
	return p, nil
}

// ParseUDP reads basic M-Bus over CIoT (Annex C.4.2.2, Table C.3): the UDP
// payload is the MBAL CI field CFh, the control field and the upper layers.
func ParseUDP(b []byte, d Direction) (*Message, error) { return split("udp", b, d, true) }

// BuildUDP is the UDP payload for a control field and upper layers.
func BuildUDP(c Control, upper []byte) []byte {
	return append([]byte{CI, c.Byte()}, upper...)
}

// MIOTY MPF values for M-Bus (Annex E.5.1, Table E.2).
const (
	MPFMBus    byte = 0x80 // M-Bus stack from a CI field; MBAL with its CI field possible
	MPFMBusAPL byte = 0x81 // M-Bus application data from a DIF; no MBAL
	MPFMBAL    byte = 0x83 // MBAL control field without CI field, then the upper layers
)

// ParseMIOTY reads the MIOTY data payload for an MPF value (Annex E.5.1,
// Tables E.2 and E.3). With 80h the payload is M-Bus from a CI field: an
// MBAL when that CI field is CFh, else upper layers without MBAL.
func ParseMIOTY(mpf byte, data []byte, d Direction) (*Message, error) {
	switch mpf {
	case MPFMBus:
		if len(data) > 0 && data[0] == CI {
			return split("mioty", data, d, true)
		}
		if len(data) == 0 {
			return nil, ErrEmpty
		}
		return &Message{Tech: "mioty", Upper: data}, nil
	case MPFMBusAPL:
		return &Message{Tech: "mioty", APL: data}, nil
	case MPFMBAL:
		return split("mioty", data, d, false)
	}
	return nil, fmt.Errorf("%w: %02Xh", ErrMIOTYMPF, mpf)
}

// ParseWize reads M-Bus over Wize (Annex F.4, Table F.5): the L6App byte
// is the MBAL CI field CFh and the L7 frame starts with the control field.
// l7 must be the plaintext L7 (the Wize L6 ciphering is not handled here).
func ParseWize(l6app byte, l7 []byte, d Direction) (*Message, error) {
	if l6app != CI {
		return nil, fmt.Errorf("%w: L6App is %02Xh", ErrNoMBAL, l6app)
	}
	m, err := split("wize", l7, d, false)
	if m != nil {
		m.WithCI = true
	}
	return m, err
}

// Wize L6 frame sizes around the L7 (Table F.5): L6Ctrl, L6NetwID,
// L6Cpt (2), L6App before; L6HashKenc (4), L6TStamp (2), L6HashKmac (2)
// after.
const (
	wizeL6Head  = 5
	wizeL6Trail = 8
)

// ParseWizeL6 reads an uplink Wize L6 frame whose L7 is in clear (the
// hash and timestamp fields are not checked here).
func ParseWizeL6(frame []byte) (*Message, error) {
	if len(frame) < wizeL6Head+1+wizeL6Trail {
		return nil, fmt.Errorf("a Wize L6 frame with an MBAL is at least %d bytes, got %d", wizeL6Head+1+wizeL6Trail, len(frame))
	}
	return ParseWize(frame[4], frame[wizeL6Head:len(frame)-wizeL6Trail], Uplink)
}

// WizeControl is the control field for a Wize DLL C-field (Annex F.4.2,
// Table F.6): version 1, the C-field's low nibble as function code, access
// 01 for DATA (SND-NR) and 00 for other uplinks, latency 11 (unused) on
// every downlink.
func WizeControl(cField byte, d Direction) Control {
	f := Function(cField & 0x0F)
	if d == Downlink {
		return NewDownlink(LatencyUnused, f)
	}
	a := AccessNone
	if f == FnSNDNR {
		a = AccessShort
	}
	return NewUplink(a, f)
}

// MeterAddress builds the link-layer address of a meter (manufacturer
// letters, 8-digit ID, version, device type) for DecodeUpper.
func MeterAddress(manufacturer, id string, version, deviceType byte) (wireless.Header, error) {
	m, err := records.ManufacturerField(manufacturer)
	if err != nil {
		return wireless.Header{}, err
	}
	if len(id) != 8 {
		return wireless.Header{}, fmt.Errorf("meter ID %q is not 8 digits", id)
	}
	var a [6]byte
	for i := range 4 {
		v, err := strconv.ParseUint(id[6-2*i:8-2*i], 16, 8)
		if err != nil {
			return wireless.Header{}, fmt.Errorf("meter ID %q is not 8 digits", id)
		}
		a[i] = byte(v)
	}
	a[4], a[5] = version, deviceType
	return addressHeader(m, a), nil
}

// AddressFromBytes reads M (2 bytes, little endian) and A (ID, version,
// device type) as they appear on the M-Bus link layer and in the COSE kid
// "device type and number" (Annex C, Table C.13).
func AddressFromBytes(b []byte) (wireless.Header, error) {
	if len(b) != 8 {
		return wireless.Header{}, fmt.Errorf("an M-Bus address is 8 bytes (M and A), got %d", len(b))
	}
	var a [6]byte
	copy(a[:], b[2:])
	return addressHeader(binary.LittleEndian.Uint16(b), a), nil
}

func addressHeader(m uint16, a [6]byte) wireless.Header {
	h := wireless.Header{MField: m, A: a, Version: a[4], DeviceType: a[5], Manufacturer: records.ManufacturerCode(m)}
	h.ID = fmt.Sprintf("%02X%02X%02X%02X", a[3], a[2], a[1], a[0])
	return h
}

// maxUpper is the longest upper layers that fit a CRC-less wM-Bus frame
// behind a synthetic link header (L is one byte).
const maxUpper = 255 - 9

// DecodeUpper decodes M-Bus upper layers (AFL, TPL with security modes 5
// and 7, APL data records) with package wireless. addr is the meter's
// link-layer address when the LPWAN identity maps to one (needed for a
// short TPL header's decryption; a long header carries its own); keys may
// be nil. The returned telegram's Meter is the long header's address, else
// addr; known reports whether either was available.
func DecodeUpper(upper []byte, addr *wireless.Header, keys wireless.KeyLookup) (tg *wireless.Telegram, known bool, err error) {
	if len(upper) == 0 {
		return nil, addr != nil, nil
	}
	var h wireless.Header
	if addr != nil {
		h = *addr
	}
	if len(upper) > maxUpper {
		return decodeLong(upper, h, addr != nil)
	}
	f := make([]byte, 0, 10+len(upper))
	f = append(f, byte(9+len(upper)), 0x44, byte(h.MField), byte(h.MField>>8))
	f = append(f, h.A[:]...)
	f = append(f, upper...)
	tg, err = wireless.Decode(f, wireless.FormatNoCRC, keys)
	if tg != nil {
		known = addr != nil || tg.HeaderKind == "long"
	}
	return tg, known, err
}

// decodeLong handles upper layers too long for a synthetic frame: an
// unencrypted TPL (no, short or long header) and its records.
func decodeLong(p []byte, h wireless.Header, known bool) (*wireless.Telegram, bool, error) {
	tg := &wireless.Telegram{Header: h, Meter: h, HeaderKind: "none", CI: p[0]}
	q := p[1:]
	switch tg.CI {
	case wireless.CINoHeader:
	case wireless.CIShortHeader:
		if len(q) < 4 {
			return tg, known, errors.New("the telegram ends inside a header")
		}
		tg.HeaderKind = "short"
		tg.Access, tg.Status, tg.Config = q[0], q[1], binary.LittleEndian.Uint16(q[2:4])
		q = q[4:]
	case wireless.CILongHeader:
		if len(q) < 12 {
			return tg, known, errors.New("the telegram ends inside a header")
		}
		tg.HeaderKind = "long"
		var a [6]byte
		copy(a[:4], q[:4])
		a[4], a[5] = q[6], q[7]
		tg.Meter = addressHeader(binary.LittleEndian.Uint16(q[4:6]), a)
		known = true
		tg.Access, tg.Status, tg.Config = q[8], q[9], binary.LittleEndian.Uint16(q[10:12])
		q = q[12:]
	default:
		return tg, known, fmt.Errorf("%w: CI field 0x%02X in upper layers longer than %d bytes", wireless.ErrUnsupport, tg.CI, maxUpper)
	}
	if tg.HeaderKind != "none" {
		tg.Mode = int(tg.Config >> 8 & 0x1F)
	}
	if tg.Mode != 0 {
		return tg, known, fmt.Errorf("%w: security mode %d in upper layers longer than %d bytes", wireless.ErrUnsupport, tg.Mode, maxUpper)
	}
	tg.APL = q
	var err error
	tg.Records, err = records.ParseRecords(q)
	return tg, known, err
}
