package wireless

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cB-Sigma/mbus/records"
)

// Transport layer (EN 13757-7 / EN 13757-3 CI fields), the extended link
// layer (EN 13757-4) and the authentication and fragmentation layer; the
// security modes are in security.go (EN 13757-7:2025).

// CI field values handled here.
const (
	CINoHeader    byte = 0x78 // APL follows, no TPL header
	CIShortHeader byte = 0x7A
	CILongHeader  byte = 0x72
	CIELL2        byte = 0x8C // ELL: CC, ACC
	CIELL8        byte = 0x8D // ELL: CC, ACC, SN, payload CRC
	CIELL10       byte = 0x8E // ELL: CC, ACC, M2, A2 (the destination)
	CIELL16       byte = 0x8F // ELL: CC, ACC, M2, A2, SN, payload CRC
	CIELLV        byte = 0x86 // variable ELL: CC, ACC, ECL, then what ECL selects
	CIAFL         byte = 0x90
	CIAppError    byte = 0x70
	CIAlarm       byte = 0x71
)

// KeyLookup returns the AES-128 key of a meter ("MAN-ID" and the 8-digit
// ID are both offered), or nil.
type KeyLookup func(meter Header) []byte

// Telegram is a decoded wM-Bus telegram.
type Telegram struct {
	Header
	Format FrameFormat
	// Meter is the meter the data is from: the TPL long header's address
	// when present (a repeater or converter sent the frame), else the link
	// layer's.
	Meter Header
	CI    byte
	// TPL fields, when the frame has a short or long header.
	HeaderKind string // "none", "short" or "long"
	Access     byte
	Status     byte
	Config     uint16
	ConfigExt  byte // mode 7's configuration field extension
	Mode       int  // security mode from the configuration field
	Encrypted  bool
	// Sec is the TPL security of modes 5–10 (security.go).
	Sec *Security
	// SITP holds the blocks of a security information transfer (CI C3h to
	// C6h) instead of Records.
	SITP []SITPBlock
	// TLS holds a security mode 13 telegram's records (mode13.go).
	TLS *TLSInfo
	ELL *ELL
	AFL *AFL
	// APL is the application layer after decryption, idle fillers kept.
	APL     []byte
	Records []records.Record
	// Warnings name what a lenient option let through (Warn*).
	Warnings []string
}

// ELL is the extended link layer (EN 13757-4:2025, 13.2).
type ELL struct {
	CI, CC, ACC byte
	SN          uint32
	HasSN       bool
	// Variable ELL (CI 86h) only: the ECL field and what it selects.
	ECL    byte
	RTD    uint16 // run time delay, see RunTimeDelay
	RTDRes byte   // ECL RTDP: 1 = 1/256 s units, 2 = 2 s units
	HasRTD bool
	RXL    byte // reception level of the partner, see RXLValue
	HasRXL bool
	// M2 and A2: the destination (CI 8Eh, 8Fh, or 86h with MAP).
	M2      uint16
	A2      [6]byte
	HasAddr bool
}

// AFL is the authentication and fragmentation layer.
type AFL struct {
	FCL     uint16
	MCL     byte
	KI      uint16
	Counter uint32
	MAC     []byte
	ML      uint16
	// Fragments is the number of datagrams a reassembled message came in
	// (0 for an unfragmented one).
	Fragments int
	has       struct{ mcl, ki, mcr, mac, ml bool }
	fragMACs  []fragMAC // individual fragment authentication
}

// Error kinds a caller may count.
var (
	ErrNoKey     = errors.New("the telegram is encrypted and no key is configured for this meter")
	ErrDecrypt   = errors.New("decryption failed: the key is wrong (no 2F2F after decrypting)")
	ErrMAC       = errors.New("the telegram's MAC does not verify")
	ErrUnsupport = errors.New("unsupported")
	// ErrManufacturerCI is returned (with ErrUnsupport) for a
	// manufacturer-specific CI field (A0h to B7h); Telegram.APL then holds
	// what follows the CI field, undecoded.
	ErrManufacturerCI = errors.New("manufacturer-specific CI field")
	errTruncated      = errors.New("the telegram ends inside a header")
	errShortFrame     = errors.New("the telegram has no CI field")
)

// Decode checks and removes CRCs, then decodes headers, decrypts with the
// meter's key and decodes the data records. It keeps no state, so a
// fragmented message (AFL with more fragments) is refused; a Decoder
// reassembles them.
func Decode(frame []byte, format FrameFormat, keys KeyLookup) (*Telegram, error) {
	return (*Decoder)(nil).Decode(frame, format, keys)
}

// Decode is the package Decode with fragment reassembly (d may be nil).
func (d *Decoder) Decode(frame []byte, format FrameFormat, keys KeyLookup) (*Telegram, error) {
	t, f, err := StripCRC(frame, format)
	if err != nil {
		return nil, err
	}
	h, err := ParseHeader(t)
	if err != nil {
		return nil, err
	}
	tg := &Telegram{Header: h, Format: f, Meter: h, HeaderKind: "none"}
	if len(t) < 11 {
		return tg, errShortFrame
	}
	p := t[10:]
	// Extended link layer.
	if len(p) > 0 && (p[0] >= CIELL2 && p[0] <= CIELL16 || p[0] == CIELLV) {
		if p, err = tg.ell(p, keys); err != nil {
			return tg, err
		}
	}
	// Authentication and fragmentation layer.
	if len(p) > 0 && p[0] == CIAFL {
		var prev *AFL
		if d != nil {
			prev = d.pending(h, now(d))
		}
		if p, err = tg.afl(p, prev); err != nil {
			return tg, err
		}
		if tg.AFL.FCL&AFLMF != 0 || prev != nil {
			if d == nil {
				return tg, fmt.Errorf("%w: fragmented telegrams", ErrUnsupport)
			}
			var done bool
			if p, done, err = d.fragment(tg, p, now(d)); err != nil || !done {
				return tg, err
			}
		} else if tg.AFL.has.ml && int(tg.AFL.ML) != len(p) {
			return tg, fmt.Errorf("AFL.ML says %d bytes, %d follow", tg.AFL.ML, len(p))
		}
	}
	if len(p) == 0 {
		if tg.ELL != nil && tg.AFL == nil {
			return tg, nil // a link-layer frame with an ELL only (annex N.3.4 REQ-UD2)
		}
		return tg, errShortFrame
	}
	tpl := p // the TPDU as received, for MACs and counters
	tg.CI = p[0]
	p = p[1:]
	switch tg.CI {
	case CINoHeader, CICompactNone, CIFormatNone: // compact frames: compact.go
	case CIShortHeader, CICompactShort, CIFormatShort, CISITPRespShort, CISITPCmdShort, CITLSShort:
		if len(p) < 4 {
			return tg, errTruncated
		}
		tg.HeaderKind = "short"
		tg.Access, tg.Status, tg.Config = p[0], p[1], binary.LittleEndian.Uint16(p[2:4])
		p = p[4:]
	case CILongHeader, CICompactLong, CIFormatLong, CISITPRespLong, CISITPCmdLong, CIToMeterLong, CIToMeterNoAPL, CITLSToMeter, CITLSLong:
		if len(p) < 12 {
			return tg, errTruncated
		}
		tg.HeaderKind = "long"
		m := Header{MField: binary.LittleEndian.Uint16(p[4:6]), Version: p[6], DeviceType: p[7]}
		copy(m.A[:4], p[:4])
		m.A[4], m.A[5] = p[6], p[7]
		m.Manufacturer, m.ID = records.ManufacturerCode(m.MField), BCDID(p[:4])
		tg.Meter = m
		tg.Access, tg.Status, tg.Config = p[8], p[9], binary.LittleEndian.Uint16(p[10:12])
		p = p[12:]
	case CIAppError, CIAlarm:
		tg.APL = append([]byte(nil), p...)
		return tg, nil
	case CIPureShort, CIPureLong, CIClockShort, CIClockLong, CIAppErrShort, CIAppErrLong, CIAlarmShort, CIAlarmLong, CIToMeterShort,
		CIDLMSToMeterLong, CIDLMSToMeterShort, CIDLMSLong, CIDLMSShort:
		if p, err = tg.tplHeader(p); err != nil { // omsci.go
			return tg, err
		}
	default:
		if tg.CI <= 0x1F {
			// A DLMS/COSEM transport PDU (EN 13757-1:2021 8.2.4): no TPL
			// header; STSAP, DTSAP and a part of an APDU follow the CI.
			if len(p) < 2 {
				return tg, errTruncated
			}
			tg.HeaderKind = "none"
			tg.APL = append([]byte(nil), p...)
			return tg, nil
		}
		if tg.CI >= 0xA0 && tg.CI <= 0xB7 {
			// The manufacturer's own layout: APL keeps it for a meter
			// driver (package meters).
			tg.APL = append([]byte(nil), p...)
			return tg, fmt.Errorf("%w: %w 0x%02X", ErrUnsupport, ErrManufacturerCI, tg.CI)
		}
		return tg, fmt.Errorf("%w: CI field 0x%02X", ErrUnsupport, tg.CI)
	}
	if tg.HeaderKind != "none" {
		tg.Mode = int(tg.Config >> 8 & 0x1F)
	}
	raw := p
	if p, err = tg.secure(d, p, tpl, keys); err != nil {
		if errors.Is(err, ErrSecurityMode) {
			// A mode outside EN 13757-7 (a manufacturer's own scheme):
			// APL keeps the bytes as received for a meter driver.
			tg.APL = append([]byte(nil), raw...)
		}
		return tg, err
	}
	tg.APL = p
	if RawAPL(tg.CI) { // omsci.go: not data records
		return tg, nil
	}
	if isSITP(tg.CI) {
		// The decryption verification of modes 5 and 7 is not part of
		// the SITP blocks.
		if tg.Encrypted && (tg.Mode == 5 || tg.Mode == 7) {
			tg.APL = p[2:]
		}
		tg.SITP, err = ParseSITP(tg.APL) // sitp.go
		return tg, err
	}
	if isCompactCI(tg.CI) {
		return tg, ErrCompactFrame // FormatCache.Complete rebuilds the records
	}
	tg.Records, err = records.ParseRecords(p)
	return tg, err
}

func (tg *Telegram) ell(p []byte, keys KeyLookup) ([]byte, error) {
	// EN 13757-4:2025, 13.2 (Tables 43 to 49); multi-byte fields low byte
	// first.
	ci := p[0]
	e := &ELL{CI: ci}
	tg.ELL = e
	p = p[1:]
	if len(p) < 2 {
		return nil, errTruncated
	}
	e.CC, e.ACC = p[0], p[1]
	p = p[2:]
	addr, sn, rtd, rxl, pcrc := ci == CIELL10 || ci == CIELL16, ci == CIELL8 || ci == CIELL16, false, false, ci == CIELL8 || ci == CIELL16
	if ci == CIELLV {
		if len(p) < 1 {
			return nil, errTruncated
		}
		e.ECL = p[0]
		p = p[1:]
		addr, sn, rxl, pcrc = e.ECL&ECLAddress != 0, e.ECL&ECLSN != 0, e.ECL&ECLRXL != 0, e.ECL&ECLPayloadCRC != 0
		e.RTDRes = e.ECL & ECLRTDMask >> 2
		if rtd = e.RTDRes != 0; e.RTDRes == 3 {
			return nil, fmt.Errorf("%w: ELL run time delay resolution 11b", ErrUnsupport)
		}
	}
	if addr {
		if len(p) < 8 {
			return nil, errTruncated
		}
		e.M2, e.HasAddr = binary.LittleEndian.Uint16(p[:2]), true
		copy(e.A2[:], p[2:8])
		p = p[8:]
	}
	if sn {
		if len(p) < 4 {
			return nil, errTruncated
		}
		e.SN, e.HasSN = binary.LittleEndian.Uint32(p[:4]), true
		p = p[4:]
	}
	if rtd {
		if len(p) < 2 {
			return nil, errTruncated
		}
		e.RTD, e.HasRTD = binary.LittleEndian.Uint16(p[:2]), true
		p = p[2:]
	}
	if rxl {
		if len(p) < 1 {
			return nil, errTruncated
		}
		e.RXL, e.HasRXL = p[0], true
		p = p[1:]
	}
	// Encryption (13.2.11.2, 13.2.12) covers everything from the payload
	// CRC on; the counter block uses the sender's M and A from the first
	// block, never M2/A2.
	enc := e.SN >> 29
	if e.HasSN && enc != 0 {
		if enc != 1 {
			return nil, fmt.Errorf("%w: ELL encryption %d", ErrUnsupport, enc)
		}
		key := keys.lookup(tg.Header)
		if key == nil {
			return nil, ErrNoKey
		}
		dec, err := ctrXOR(key, ellIV(tg.Header.MField, tg.Header.A, e.CC, e.SN, 0), p)
		if err != nil {
			return nil, err
		}
		tg.Encrypted = true
		p = dec
	}
	if pcrc {
		if len(p) < 2 {
			return nil, errTruncated
		}
		// Meters send the payload CRC low byte first (Kamstrup's, in the
		// decrypted telegrams wmbusmeters keeps as test data, and
		// wmbusmeters reads it so); the high byte first order this
		// decoder read until 2026-10-11 is still accepted.
		le, be := uint16(p[0])|uint16(p[1])<<8, uint16(p[0])<<8|uint16(p[1])
		p = p[2:]
		if c := CRC(p); c != le && c != be {
			if tg.Encrypted {
				return nil, ErrDecrypt
			}
			return nil, fmt.Errorf("ELL payload %w", ErrCRC)
		}
	}
	return p, nil
}

// AFL field control bits (EN 13757-7:2025 clause 6): which fields are
// present, and more fragments follow.
const (
	AFLMF   = 1 << 14 // more fragments
	AFLMCLP = 1 << 13 // message control present
	AFLMLP  = 1 << 12 // message length present
	AFLMCRP = 1 << 11 // message counter present
	AFLMACP = 1 << 10 // MAC present
	AFLKIP  = 1 << 9  // key information present
)

// HasCounter reports whether the AFL carried a message counter.
func (a *AFL) HasCounter() bool { return a.has.mcr }

// macLen is the MAC length for an authentication type (AFL.MCL bits 0-3):
// AES-CMAC truncated to 2, 4, 8, 12 or 16 bytes, AES-GMAC 12 bytes.
func macLen(at byte) int {
	switch at {
	case 3:
		return 2
	case 4:
		return 4
	case 5:
		return 8
	case 6:
		return 12
	case 7:
		return 16
	case 8: // AES-GMAC (EN 13757-7:2025 table 6)
		return 12
	}
	return 0
}

// afl reads the AFL; it returns the rest and the AFL fields that enter the
// MAC (MCL, MCR and ML). prev is the AFL gathered from the earlier
// fragments of the same message, if any: a later fragment may carry the
// MAC without the MCL that gives its length.
func (tg *Telegram) afl(p []byte, prev *AFL) (rest []byte, err error) {
	if len(p) < 2 {
		return nil, errTruncated
	}
	n := int(p[1])
	if len(p) < 2+n || n < 2 {
		return nil, errTruncated
	}
	f, rest := p[2:2+n], p[2+n:]
	a := &AFL{FCL: binary.LittleEndian.Uint16(f[:2])}
	tg.AFL = a
	f = f[2:]
	take := func(k int) ([]byte, error) {
		if len(f) < k {
			return nil, errTruncated
		}
		v := f[:k]
		f = f[k:]
		return v, nil
	}
	if a.FCL&AFLMCLP != 0 {
		v, err := take(1)
		if err != nil {
			return nil, err
		}
		a.MCL, a.has.mcl = v[0], true
	}
	if a.FCL&AFLKIP != 0 {
		v, err := take(2)
		if err != nil {
			return nil, err
		}
		a.KI, a.has.ki = binary.LittleEndian.Uint16(v), true
	}
	if a.FCL&AFLMCRP != 0 {
		v, err := take(4)
		if err != nil {
			return nil, err
		}
		a.Counter, a.has.mcr = binary.LittleEndian.Uint32(v), true
	}
	if a.FCL&AFLMACP != 0 {
		mcl := a.MCL
		if !a.has.mcl && prev != nil && prev.has.mcl {
			mcl = prev.MCL
		}
		if !a.has.mcl && (prev == nil || !prev.has.mcl) {
			return nil, errors.New("the AFL carries a MAC but no MCL gives its length")
		}
		n := macLen(mcl & 0x0F)
		if n == 0 {
			return nil, fmt.Errorf("%w: AFL authentication type %d", ErrUnsupport, mcl&0x0F)
		}
		v, err := take(n)
		if err != nil {
			return nil, err
		}
		a.MAC, a.has.mac = append([]byte(nil), v...), true
	}
	if a.FCL&AFLMLP != 0 {
		v, err := take(2)
		if err != nil {
			return nil, err
		}
		a.ML, a.has.ml = binary.LittleEndian.Uint16(v), true
	}
	return rest, nil
}

func (k KeyLookup) lookup(h Header) []byte {
	if k == nil {
		return nil
	}
	return k(h)
}

// Mode5IV is the initialisation vector of security mode 5: the meter's M
// and A fields, then the access number eight times.
func (tg *Telegram) Mode5IV() []byte {
	iv := make([]byte, 16)
	binary.LittleEndian.PutUint16(iv[:2], tg.Meter.MField)
	copy(iv[2:8], tg.Meter.A[:])
	for i := 8; i < 16; i++ {
		iv[i] = tg.Access
	}
	return iv
}
