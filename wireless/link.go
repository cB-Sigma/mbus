package wireless

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/cB-Sigma/mbus/records"
)

// Link layer (EN 13757-4): frame formats A and B with their block CRCs, the
// data link layer header and the physical-layer 3-out-of-6 code of mode T.

// CRC computes the link-layer CRC of EN 13757-4 (polynomial 0x3D65, initial
// value 0, no reflection, result complemented), as used in both frame
// formats.
func CRC(b []byte) uint16 {
	var crc uint16
	for _, x := range b {
		crc ^= uint16(x) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x3D65
			} else {
				crc <<= 1
			}
		}
	}
	return ^crc
}

// FrameFormat says how a received frame carries its CRCs.
type FrameFormat string

const (
	// FormatAuto tries format A, then format B, then a frame whose CRCs a
	// receiver already removed.
	FormatAuto FrameFormat = "auto"
	// FormatA: L excludes CRCs; a 10-byte first block then 16-byte blocks,
	// each followed by its CRC (modes S, T and C).
	FormatA FrameFormat = "a"
	// FormatB: L includes CRCs; one CRC over the first 126 bytes and one
	// over the rest (mode C).
	FormatB FrameFormat = "b"
	// FormatNoCRC: a receiver checked and removed the CRCs.
	FormatNoCRC FrameFormat = "none"
)

// ErrCRC is returned for a frame whose CRCs do not match.
var ErrCRC = errors.New("wM-Bus frame CRC mismatch")

// StripCRC checks a frame's CRCs and returns it without them, with L set to
// the remaining length, and the format it was in.
func StripCRC(b []byte, f FrameFormat) ([]byte, FrameFormat, error) {
	if len(b) < 11 {
		return nil, "", fmt.Errorf("a wM-Bus frame is at least 11 bytes, got %d", len(b))
	}
	switch f {
	case FormatA:
		out, err := stripA(b)
		return out, FormatA, err
	case FormatB:
		out, err := stripB(b)
		return out, FormatB, err
	case FormatNoCRC:
		out := append([]byte(nil), b...)
		if int(out[0]) > len(out)-1 {
			return nil, "", fmt.Errorf("L field %d is longer than the %d bytes received", out[0], len(out)-1)
		}
		out = out[:int(out[0])+1]
		return out, FormatNoCRC, nil
	case FormatAuto, "":
		if out, err := stripA(b); err == nil {
			return out, FormatA, nil
		}
		if out, err := stripB(b); err == nil {
			return out, FormatB, nil
		}
		if int(b[0]) == len(b)-1 {
			return append([]byte(nil), b...), FormatNoCRC, nil
		}
		return nil, "", fmt.Errorf("%w in format A and B, and L does not match a CRC-less frame", ErrCRC)
	}
	return nil, "", fmt.Errorf("unknown frame format %q", f)
}

// FrameLenA is the on-air length of a format A frame with this L field.
func FrameLenA(l int) int {
	data := l - 9
	blocks := 1 + (data+15)/16
	return l + 1 + 2*blocks
}

func stripA(b []byte) ([]byte, error) {
	l := int(b[0])
	if l < 9 {
		return nil, fmt.Errorf("L field %d is too short", l)
	}
	n := FrameLenA(l)
	if len(b) < n {
		return nil, fmt.Errorf("format A frame with L=%d needs %d bytes, got %d", l, n, len(b))
	}
	out := make([]byte, 0, l+1)
	block := func(p []byte, crc []byte) error {
		if CRC(p) != uint16(crc[0])<<8|uint16(crc[1]) {
			return ErrCRC
		}
		out = append(out, p...)
		return nil
	}
	if err := block(b[:10], b[10:12]); err != nil {
		return nil, err
	}
	i, left := 12, l-9
	for left > 0 {
		k := min(16, left)
		if err := block(b[i:i+k], b[i+k:i+k+2]); err != nil {
			return nil, err
		}
		i += k + 2
		left -= k
	}
	return out, nil
}

func stripB(b []byte) ([]byte, error) {
	l := int(b[0])
	n := l + 1
	if l < 12 || len(b) < n {
		return nil, fmt.Errorf("format B frame with L=%d needs %d bytes, got %d", l, n, len(b))
	}
	b = b[:n]
	check := func(p []byte, crc []byte) bool { return CRC(p) == uint16(crc[0])<<8|uint16(crc[1]) }
	var out []byte
	if n <= 128 {
		if !check(b[:n-2], b[n-2:]) {
			return nil, ErrCRC
		}
		out = append(out, b[:n-2]...)
	} else {
		if n < 131 || !check(b[:126], b[126:128]) || !check(b[128:n-2], b[n-2:]) {
			return nil, ErrCRC
		}
		out = append(append(out, b[:126]...), b[128:n-2]...)
	}
	out[0] = byte(len(out) - 1)
	return out, nil
}

// AddCRCA builds a format A frame from a CRC-less one (for tests and
// simulators).
func AddCRCA(t []byte) []byte {
	out := make([]byte, 0, FrameLenA(int(t[0])))
	add := func(p []byte) {
		c := CRC(p)
		out = append(append(out, p...), byte(c>>8), byte(c))
	}
	add(t[:10])
	for i := 10; i < len(t); i += 16 {
		add(t[i:min(i+16, len(t))])
	}
	return out
}

// AddCRCB builds a format B frame from a CRC-less one.
func AddCRCB(t []byte) []byte {
	body := append([]byte(nil), t...)
	var out []byte
	if len(body)+2 <= 128 {
		body[0] = byte(len(body) + 1)
		c := CRC(body)
		return append(body, byte(c>>8), byte(c))
	}
	body[0] = byte(len(body) + 3)
	c1 := CRC(body[:126])
	out = append(append(out, body[:126]...), byte(c1>>8), byte(c1))
	c2 := CRC(body[126:])
	return append(append(out, body[126:]...), byte(c2>>8), byte(c2))
}

// threeOfSix maps each 6-bit mode T code word to its nibble (EN 13757-4).
var threeOfSix = map[byte]byte{
	0x16: 0x0, 0x0D: 0x1, 0x0E: 0x2, 0x0B: 0x3, 0x1C: 0x4, 0x19: 0x5, 0x1A: 0x6, 0x13: 0x7,
	0x2C: 0x8, 0x25: 0x9, 0x26: 0xA, 0x23: 0xB, 0x34: 0xC, 0x31: 0xD, 0x32: 0xE, 0x29: 0xF,
}

// Decode3of6 decodes a mode T (meter to other) chip sequence: every 12 bits
// are two code words for the high and low nibble of one byte. A trailing
// partial byte is ignored.
func Decode3of6(chips []byte) ([]byte, error) {
	var out []byte
	var acc uint32
	var bits int
	var hi byte
	half := false
	for _, c := range chips {
		acc = acc<<8 | uint32(c)
		bits += 8
		for bits >= 6 {
			w := byte(acc>>(bits-6)) & 0x3F
			bits -= 6
			n, ok := threeOfSix[w]
			if !ok {
				return out, fmt.Errorf("byte %d: %06b is not a 3-out-of-6 code word", len(out), w)
			}
			if !half {
				hi, half = n, true
			} else {
				out = append(out, hi<<4|n)
				half = false
			}
		}
	}
	return out, nil
}

// Encode3of6 is Decode3of6's inverse (for tests and simulators).
func Encode3of6(b []byte) []byte {
	rev := map[byte]byte{}
	for k, v := range threeOfSix {
		rev[v] = k
	}
	var out []byte
	var acc uint32
	var bits int
	for _, x := range b {
		for _, n := range []byte{x >> 4, x & 0x0F} {
			acc = acc<<6 | uint32(rev[n])
			bits += 6
			for bits >= 8 {
				out = append(out, byte(acc>>(bits-8)))
				bits -= 8
			}
		}
	}
	if bits > 0 {
		out = append(out, byte(acc<<(8-bits)))
	}
	return out
}

// Header is the data link layer header of a CRC-less frame.
type Header struct {
	L            int
	C            byte
	Manufacturer string // three letters from the M field
	MField       uint16
	ID           string // eight BCD digits of the A field's identification number
	Version      byte
	DeviceType   byte
	A            [6]byte // raw A field (ID, version, device type)
}

// Key identifies a meter: manufacturer and ID, e.g. "KAM-12345678".
func (h Header) Key() string { return h.Manufacturer + "-" + h.ID }

// Medium is the device type's name.
func (h Header) Medium() string { return records.Medium(h.DeviceType) }

// ParseHeader reads the link-layer header of a CRC-less frame.
func ParseHeader(t []byte) (Header, error) {
	if len(t) < 11 {
		return Header{}, fmt.Errorf("a wM-Bus frame is at least 11 bytes, got %d", len(t))
	}
	h := Header{L: int(t[0]), C: t[1], MField: uint16(t[2]) | uint16(t[3])<<8, Version: t[8], DeviceType: t[9]}
	copy(h.A[:], t[4:10])
	h.Manufacturer = records.ManufacturerCode(h.MField)
	h.ID = BCDID(t[4:8])
	return h, nil
}

// BCDID prints a 4-byte identification number sent least significant byte
// first (the A field's first four bytes) as its eight digits.
func BCDID(b []byte) string {
	return fmt.Sprintf("%02X%02X%02X%02X", b[3], b[2], b[1], b[0])
}

// C-field (EN 13757-4:2025, 12.5.4, Tables 33 to 35): bit 7 reserved (0),
// bit 6 PRM (1 = from the primary station), bit 5 FCB/ACD, bit 4 FCV/DFC,
// bits 3..0 the function code. downlink.go names SND-NR (44h), SND-IR
// (46h), CNF-IR (06h), SND-UD with FCV set (53h) and ACK (00h).
const (
	CPRM      = 0x40 // from the primary station
	CFCB      = 0x20 // ACD from a secondary station
	CFCV      = 0x10 // DFC from a secondary station
	CFunction = 0x0F // the function code bits

	CSndNKE  = 0x40 // link reset, to meter
	CSndUD2  = 0x43 // SND-UD with FCV cleared: answered with RSP-UD
	CSndUDF  = 0x73 // SND-UD, FCB and FCV set
	CSndUD3  = 0x45 // multicast/broadcast command, no reply
	CAccNR   = 0x47 // access opportunity, no application data
	CAccDMD  = 0x48 // access demand, answered with ACK
	CReqUD1  = 0x5A // alarm request (FCV set; 7Ah with FCB)
	CReqUD2  = 0x5B // data request (FCV set; 7Bh with FCB)
	CNACK    = 0x01 // NACK: the frame was not accepted
	CRspUD   = 0x08 // RSP-UD: answer with user data
	CReqUD1F = 0x7A // REQ-UD1 with FCB set
	CReqUD2F = 0x7B // REQ-UD2 with FCB set
)

// CFieldName names a C-field (its symbolic name in 12.5.4), or "0xNN".
func CFieldName(c byte) string {
	if c&CPRM != 0 {
		switch c & CFunction {
		case 0x0:
			return "SND-NKE"
		case 0x3:
			if c&CFCV == 0 {
				return "SND-UD2"
			}
			return "SND-UD"
		case 0x4:
			return "SND-NR"
		case 0x5:
			return "SND-UD3"
		case 0x6:
			return "SND-IR"
		case 0x7:
			return "ACC-NR"
		case 0x8:
			return "ACC-DMD"
		case 0xA:
			return "REQ-UD1"
		case 0xB:
			return "REQ-UD2"
		}
	} else {
		switch c & CFunction {
		case 0x0:
			return "ACK"
		case 0x1:
			return "NACK"
		case 0x6:
			return "CNF-IR"
		case 0x8:
			return "RSP-UD"
		}
	}
	return fmt.Sprintf("0x%02X", c)
}

// HardAddress reports whether an M field's most significant bit is clear:
// the A field is then a manufacturer-unique address, else an address that
// is only unique within radio range (12.5.5).
func HardAddress(m uint16) bool { return m&0x8000 == 0 }

// Radio modes (EN 13757-4:2025, 5.1 and Table 1; frame formats from the
// preamble clauses 6.4.3, 7.4.2.3, 8.4.3, 9.4.2, 10.4.2, 11.4.2):
//
//	S1, S1-m, S2  Manchester, format A only
//	T1, T2        3-out-of-6 from the meter (Manchester to it), format A only
//	R2            Manchester, format A only
//	C1, C2        NRZ, format A or B (the last sync byte tells which)
//	N1, N2        169 MHz GFSK/4GFSK, format A or B
//	F2, F2-m      433 MHz NRZ, format A or B
//
// Receivers: the iM871A delivers S, T and C; Amber modules S, T and C (the
// 169 MHz models N); rtl-wmbus style hex lines T, C and S. All of them hand
// over frames the radio already decoded (chip coding removed); the CRCs are
// checked here unless a receiver removed them.

// NormalizeLinkMode returns the canonical name of a radio (sub-)mode, e.g.
// "t1" → "T1", "s1m" → "S1-m", "N2g" → "N2g"; ok is false for anything else.
func NormalizeLinkMode(s string) (string, bool) {
	u := strings.ToUpper(strings.TrimSpace(s))
	switch u {
	case "S1", "S2", "T1", "T2", "R2", "C1", "C2", "N1", "N2", "F2":
		return u, true
	case "S1M", "S1-M":
		return "S1-m", true
	case "F2M", "F2-M":
		return "F2-m", true
	}
	// Mode N channels are often named by sub-mode letter (N1a..N2g).
	if len(u) == 3 && (u[:2] == "N1" || u[:2] == "N2") && u[2] >= 'A' && u[2] <= 'G' {
		return u[:2] + strings.ToLower(u[2:]), true
	}
	return "", false
}

// ModeFormats lists the frame formats a radio mode can carry.
func ModeFormats(mode string) []FrameFormat {
	m, ok := NormalizeLinkMode(mode)
	if !ok {
		return []FrameFormat{FormatA, FormatB}
	}
	switch m[0] {
	case 'S', 'T', 'R':
		return []FrameFormat{FormatA}
	}
	return []FrameFormat{FormatA, FormatB}
}

// SyncInterval is the interval from a synchronous message with access
// number acc to the next one (12.6.2): tNom scaled by
// 1 + (|acc − 128| − 64) / 2048, i.e. within ±1/32 of tNom.
func SyncInterval(acc byte, tNom time.Duration) time.Duration {
	d := int64(acc) - 128
	if d < 0 {
		d = -d
	}
	return time.Duration(int64(tNom) * (2048 + d - 64) / 2048)
}

// Extended link layer CC field bits (13.2.7, Table 50).
const (
	CCBidirectional = 0x80 // B
	CCFastDelay     = 0x40 // D: response delay
	CCSynchronized  = 0x20 // S
	CCHop           = 0x10 // H: relayed by a repeater
	CCPriority      = 0x08 // P
	CCAccessible    = 0x04 // A
	CCRepeated      = 0x02 // R: repeated access
	CCExtendedDelay = 0x01 // X (with D; mode N only)
)

// ECL bits of the variable ELL, CI 86h (13.2.6, Table 49).
const (
	ECLPayloadCRC = 0x80 // PLP
	ECLRXL        = 0x10 // RXLP
	ECLRTDMask    = 0x0C // RTDP: 01 = 1/256 s, 10 = 2 s, 11 reserved
	ECLSN         = 0x02 // SNP
	ECLAddress    = 0x01 // MAP: M2 and A2
)

// ellIV builds the AES-128 CTR initial counter block of 13.2.12 (Table 54):
// M and A of the link-layer first block (the sender, not M2/A2), the CC
// field with the repeater bits H and R cleared, SN, the frame number FN (0
// for the first frame a meter sends in a session) and the block counter,
// which starts at 0 and is the byte cipher.NewCTR increments.
func ellIV(m uint16, a [6]byte, cc byte, sn uint32, fn uint16) []byte {
	iv := make([]byte, 16)
	binary.LittleEndian.PutUint16(iv[0:2], m)
	copy(iv[2:8], a[:])
	iv[8] = cc &^ (CCHop | CCRepeated)
	binary.LittleEndian.PutUint32(iv[9:13], sn)
	binary.LittleEndian.PutUint16(iv[13:15], fn)
	return iv
}

// RXL (13.2.14, Tables 55 and 56): bit 7 set is reserved; bit 6 selects
// RSSI (0) or link margin (1); bits 5..0 are RL. RL 0 means no
// information, 1 and 63 are the open ends of the range.
func RXLValue(rxl byte) (kind string, value float64, ok bool) {
	rl := int(rxl & 0x3F)
	if rxl&0x80 != 0 || rl == 0 {
		return "", 0, false
	}
	if rxl&0x40 != 0 {
		return "linkMargin", float64(rl - 11), true // dB; 1 = −10 or below, 63 = +52 or above
	}
	return "rssi", float64(2*rl - 144), true // dBm; 1 = −142 or below, 63 = −18 or above
}

// RSSIToRL is RXLValue's inverse for an RSSI in dBm (Figure 1: −60 dBm
// gives 42).
func RSSIToRL(dBm float64) byte {
	rl := int(math.Round((dBm + 144) / 2))
	return byte(max(1, min(63, rl)))
}

// Relayed reports whether a CRC-less frame was relayed by a repeater: the
// hop bit H is set in the ELL CC field (13.2.7.5) or in a short or long
// TPL header's configuration field (EN 13757-7:2025, 7.7, security modes 0
// and 5).
func Relayed(t []byte) bool {
	k, err := dupNormalize(t)
	return err == nil && k.relayed
}

// DuplicateKey identifies a frame for duplicate detection (12.7): the
// CRC-less frame with the fields a simple repeater changes neutralised (the
// H and R bits of the ELL CC field and of a mode 0 or 5 TPL configuration
// field, and the RTD and RXL fields of a variable ELL). A frame heard
// directly and again through a repeater, or twice, gives the same key.
func DuplicateKey(t []byte) (string, error) {
	k, err := dupNormalize(t)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(k.frame), nil
}

type dupFrame struct {
	frame   []byte
	relayed bool
}

func dupNormalize(t []byte) (dupFrame, error) {
	if len(t) < 11 || int(t[0]) != len(t)-1 {
		return dupFrame{}, fmt.Errorf("not a CRC-less wM-Bus frame")
	}
	var out dupFrame
	b := append([]byte(nil), t[1:]...) // L is dropped: RTD/RXL removal changes it
	i := 9                             // CI
	ci := b[i]
	switch {
	case ci == CIELLV:
		if len(b) < i+4 {
			return out, errTruncated
		}
		out.relayed = b[i+1]&CCHop != 0
		b[i+1] &^= CCHop | CCRepeated
		ecl := b[i+3]
		j := i + 4
		if ecl&ECLAddress != 0 {
			j += 8
		}
		if ecl&ECLSN != 0 {
			j += 4
		}
		cut := 0
		if ecl&ECLRTDMask != 0 {
			cut += 2
		}
		if ecl&ECLRXL != 0 {
			cut++
		}
		if len(b) < j+cut {
			return out, errTruncated
		}
		b[i+3] &^= ECLRTDMask | ECLRXL
		out.frame = append(b[:j], b[j+cut:]...)
		return out, nil // the rest may be encrypted: left as is
	case ci >= CIELL2 && ci <= CIELL16:
		if len(b) < i+3 {
			return out, errTruncated
		}
		out.relayed = b[i+1]&CCHop != 0
		b[i+1] &^= CCHop | CCRepeated
		out.frame = b
		if ci == CIELL8 || ci == CIELL16 {
			return out, nil // payload encrypted or CRC-protected
		}
		i += 3
		if ci == CIELL10 {
			i += 8
		}
		if len(b) <= i {
			return out, nil
		}
		ci = b[i]
	}
	out.frame = b
	cfg := -1
	switch ci {
	case CIShortHeader:
		cfg = i + 3
	case CILongHeader:
		cfg = i + 11
	}
	if cfg > 0 && len(b) >= cfg+2 {
		if mode := b[cfg+1] & 0x1F; mode == 0 || mode == 5 {
			out.relayed = out.relayed || b[cfg]&0x01 != 0
			b[cfg] &^= 0x03
		}
	}
	return out, nil
}

// RunTimeDelay is the accumulated repeater delay a variable ELL carries
// (13.2.13): RTD in units of 1/256 s or 2 s as ECL selects.
func (e *ELL) RunTimeDelay() time.Duration {
	switch e.RTDRes {
	case 1:
		return time.Duration(e.RTD) * time.Second / 256
	case 2:
		return time.Duration(e.RTD) * 2 * time.Second
	}
	return 0
}
