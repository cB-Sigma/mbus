package wired

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/cB-Sigma/mbus/records"
	"github.com/cB-Sigma/mbus/tpdu"
)

// Wired M-Bus link layer (EN 13757-2:2018+A1:2023 clause 5): FT1.2 of
// EN 60870-5-1 (5.7.1): the single characters ACK and NACK, the short
// frame and the control/long frame, each with its checksum and stop byte.

// Control field values (5.7.3, 5.7.7, annex F). FCV (bit 4) is set in
// SND_UD, REQ_UD1 and REQ_UD2 and clear in SND_NKE and SND_UD2.
const (
	CSndNke  = 0x40 // normalisation; FCV and FCB clear
	CSndUD   = 0x53 // send user data, answer ACK (0x73 with FCB)
	CSndUD2  = 0x43 // send user data, answer RSP_UD (A1:2023 5.7.3.4); FCV clear
	CReqUD2  = 0x5B // request class 2 data (0x7B with FCB)
	CReqUD1  = 0x5A // request class 1 data (0x7A with FCB)
	CRspUD   = 0x08 // respond user data (ACD 0x20, DFC 0x10 may be set)
	FCB      = 0x20
	FCV      = 0x10
	ACK      = 0xE5 // A1:2023 3.1.3
	NACK     = 0xA2 // A1:2023 3.1.4: the answer of a meter without SND_UD2
	startS   = 0x10
	startL   = 0x68
	stopByte = 0x16
	// MaxLongData is the most bytes after the CI field: the L field
	// counts C, A, CI and the data and is one byte.
	MaxLongData = 255 - 3
)

// Addresses (5.7.5).
const (
	AddrUnconfigured = 0    // every unconfigured slave answers
	AddrRepeater     = 0xFB // 251: management of the primary master repeater
	AddrReserved     = 0xFC // 252: reserved
	AddrSecondary    = 0xFD // 253: the slave(s) selected by secondary addressing
	AddrTest         = 0xFE // 254: test and diagnosis; every slave answers
	AddrBroadcast    = 0xFF // 255: broadcast; every slave executes, none answers
	// AddrBroadcastAns is the older name of AddrTest.
	AddrBroadcastAns = AddrTest
)

// CI fields.
const (
	CIAppReset     = 0x50
	CISetData      = 0x51
	CISelect       = 0x52
	CIRspVariable  = 0x72 // variable data, long header, LSB first
	CIRspVariableM = 0x76 // variable data, long header, MSB first
	CIRspFixed     = 0x73
	CIRspFixedM    = 0x77 // fixed data, multi-byte fields MSB first
	CIRspAlarm     = 0x71 // alarm status (answer to REQ_UD1)
	CIRspNoHeader  = 0x78
	CIRspShort     = 0x7A
	// A DLMS/COSEM APDU from the meter (EN 13757-1:2021 9.2.1, EN
	// 13757-7 CI table): long header 7Ch, short header 7Dh.
	CIRspDLMSLong  = 0x7C
	CIRspDLMSShort = 0x7D
)

// Frame is one M-Bus frame.
type Frame struct {
	Single bool // E5 (ACK)
	Nack   bool // A2 (NACK)
	C, A   byte
	Long   bool // control or long frame (with CI)
	CI     byte
	Data   []byte
}

// Encode serialises the frame.
func (f Frame) Encode() []byte {
	if f.Single {
		return []byte{ACK}
	}
	if f.Nack {
		return []byte{NACK}
	}
	if !f.Long {
		return []byte{startS, f.C, f.A, f.C + f.A, stopByte}
	}
	body := append([]byte{f.C, f.A, f.CI}, f.Data...)
	n := byte(len(body))
	out := append([]byte{startL, n, n, startL}, body...)
	return append(out, sum(body), stopByte)
}

func sum(b []byte) byte {
	var s byte
	for _, c := range b {
		s += c
	}
	return s
}

// Check reports a long frame whose data does not fit the one-byte L
// field; Encode would write a wrong length for it.
func (f Frame) Check() error {
	if f.Long && len(f.Data) > MaxLongData {
		return fmt.Errorf("a long frame carries at most %d data bytes after the CI field, not %d", MaxLongData, len(f.Data))
	}
	return nil
}

// ErrFrame is wrapped by framing errors (checksum, length, stop byte, or
// bytes that start no frame, as after a collision).
var ErrFrame = errors.New("invalid M-Bus frame")

// ReadFrame reads one frame. Unlike FT1.2 readers on a quiet line, a byte
// that starts no frame is an error: on M-Bus it means two slaves answered
// at once.
func ReadFrame(r io.ByteReader) (Frame, error) {
	c, err := r.ReadByte()
	if err != nil {
		return Frame{}, err
	}
	switch c {
	case ACK:
		return Frame{Single: true}, nil
	case NACK:
		return Frame{Nack: true}, nil
	case startS:
		b := make([]byte, 4)
		if err := readFull(r, b); err != nil {
			return Frame{}, err
		}
		if b[2] != b[0]+b[1] || b[3] != stopByte {
			return Frame{}, fmt.Errorf("%w: short frame checksum or stop byte wrong", ErrFrame)
		}
		return Frame{C: b[0], A: b[1]}, nil
	case startL:
		h := make([]byte, 3)
		if err := readFull(r, h); err != nil {
			return Frame{}, err
		}
		if h[0] != h[1] || h[2] != startL || h[0] < 3 {
			return Frame{}, fmt.Errorf("%w: long frame header %X", ErrFrame, h)
		}
		n := int(h[0])
		b := make([]byte, n+2)
		if err := readFull(r, b); err != nil {
			return Frame{}, err
		}
		if b[n] != sum(b[:n]) || b[n+1] != stopByte {
			return Frame{}, fmt.Errorf("%w: long frame checksum or stop byte wrong", ErrFrame)
		}
		return Frame{C: b[0], A: b[1], Long: true, CI: b[2], Data: append([]byte{}, b[3:n]...)}, nil
	}
	return Frame{}, fmt.Errorf("%w: unexpected byte %02X", ErrFrame, c)
}

func readFull(r io.ByteReader, b []byte) error {
	for i := range b {
		c, err := r.ReadByte()
		if err != nil {
			return err
		}
		b[i] = c
	}
	return nil
}

// SecondaryAddress identifies a slave: the 8-digit identification number,
// manufacturer, version and medium. In a selection pattern any ID digit
// may be F and the other fields their wildcard values.
type SecondaryAddress struct {
	ID           string // eight digits (F: any)
	Manufacturer uint16 // 0xFFFF: any
	Version      byte   // 0xFF: any
	Medium       byte   // 0xFF: any
}

// Wildcard matches every slave.
var Wildcard = SecondaryAddress{ID: "FFFFFFFF", Manufacturer: 0xFFFF, Version: 0xFF, Medium: 0xFF}

// Bytes is the 8-byte form used in selection and in the long header (ID
// in BCD, least significant byte first; manufacturer LSB first).
func (s SecondaryAddress) Bytes() ([]byte, error) {
	if len(s.ID) != 8 {
		return nil, fmt.Errorf("identification %q is not eight digits", s.ID)
	}
	b := make([]byte, 8)
	for i := 0; i < 4; i++ {
		hi, lo := s.ID[6-2*i], s.ID[7-2*i]
		h, err1 := nibble(hi)
		l, err2 := nibble(lo)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("identification %q has characters other than digits and F", s.ID)
		}
		b[i] = h<<4 | l
	}
	b[4], b[5], b[6], b[7] = byte(s.Manufacturer), byte(s.Manufacturer>>8), s.Version, s.Medium
	return b, nil
}

func nibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c == 'F' || c == 'f':
		return 0xF, nil
	}
	return 0, errors.New("bad digit")
}

// ParseSecondary reads the 8-byte form.
func ParseSecondary(b []byte) SecondaryAddress {
	return SecondaryAddress{ID: fmt.Sprintf("%02X%02X%02X%02X", b[3], b[2], b[1], b[0]),
		Manufacturer: uint16(b[4]) | uint16(b[5])<<8, Version: b[6], Medium: b[7]}
}

// Key is "MAN-ID", the device identifier used for discovered meters.
func (s SecondaryAddress) Key() string { return records.ManufacturerCode(s.Manufacturer) + "-" + s.ID }

// Matches reports whether a concrete address matches a selection pattern.
func (s SecondaryAddress) Matches(pattern SecondaryAddress) bool {
	for i := 0; i < 8 && i < len(pattern.ID) && i < len(s.ID); i++ {
		if p := pattern.ID[i]; p != 'F' && p != 'f' && p != s.ID[i] {
			return false
		}
	}
	return (pattern.Manufacturer == 0xFFFF || pattern.Manufacturer == s.Manufacturer) &&
		(pattern.Version == 0xFF || pattern.Version == s.Version) &&
		(pattern.Medium == 0xFF || pattern.Medium == s.Medium)
}

// Response is a decoded RSP_UD.
type Response struct {
	Address  SecondaryAddress // from the long header (CI 72/76)
	Access   byte
	Status   byte
	Records  []records.Record
	More     bool // the last record was DIF 1F: another telegram follows
	CI       byte
	Fixed    *FixedData // CI 73/77
	Alarm    []byte     // CI 71: the alarm status bytes
	ACD      bool       // the slave has class 1 (alarm) data waiting
	Primary  byte
	Header   bool
	DecodeOK bool
	// AppError is set for an application error response (CI 6Eh, 6Fh,
	// 70h, EN 13757-3:2025 clause 10.3).
	AppError *AppError
	// Selected marks a response of a selected application (CI 66h, 67h,
	// 68h, clause 7.3).
	Selected bool
	// DLMS is the DLMS/COSEM APDU of a CI 7Ch/7Dh response.
	DLMS []byte
	// TPDU is a transport PDU of a DLMS/COSEM APDU (CI 00h to 1Fh, EN
	// 13757-1:2021 8.2.4).
	TPDU *tpdu.TPDU
	// UnknownCI marks an answer with a CI this decoder does not know; its
	// data is the one manufacturer_data record.
	UnknownCI bool
}

// ParseResponse decodes an RSP_UD with a variable data structure.
func ParseResponse(f Frame) (*Response, error) {
	if !f.Long || f.C&0x4F != CRspUD {
		return nil, fmt.Errorf("not an RSP_UD (C=%02X)", f.C)
	}
	r := &Response{CI: f.CI, Primary: f.A, ACD: f.C&0x20 != 0}
	p := f.Data
	if f.CI <= 0x1F {
		tp, err := tpdu.ParseTPDU(append([]byte{f.CI}, p...))
		if err != nil {
			return nil, err
		}
		r.TPDU, r.DecodeOK = &tp, true
		return r, nil
	}
	switch f.CI {
	case CIRspFixed, CIRspFixedM:
		fd, err := ParseFixed(p, f.CI == CIRspFixedM)
		if err != nil {
			return nil, err
		}
		r.Fixed, r.Access, r.Status, r.DecodeOK = fd, fd.Access, fd.Status, true
		return r, nil
	case CIRspAlarm, CIAlarmShort, CIAlarmLong:
		// Alarm status (clause 9, annex D): data type D after the header.
		if p, err := r.header(f.CI, p); err != nil {
			return nil, err
		} else if len(p) == 0 {
			return nil, errors.New("an alarm status response without data")
		} else {
			r.Alarm = append([]byte(nil), p...)
		}
		r.DecodeOK = true
		return r, nil
	case CIAppErrNone, CIAppErrShort, CIAppErrLong:
		p, err := r.header(f.CI, p)
		if err != nil {
			return nil, err
		}
		e := ParseAppError(p)
		r.AppError, r.DecodeOK = &e, true
		return r, nil
	case CIRspDLMSLong, CIRspDLMSShort:
		p, err := r.header(f.CI, p)
		if err != nil {
			return nil, err
		}
		if len(p) == 0 {
			return nil, errors.New("a DLMS response without an APDU")
		}
		r.DLMS, r.DecodeOK = append([]byte(nil), p...), true
		return r, nil
	case CIRspSelected, CIRspSelShort, CIRspSelLong:
		var err error
		if p, err = r.header(f.CI, p); err != nil {
			return nil, err
		}
		r.Selected = true
	case CIRspVariable, CIRspVariableM:
		if len(p) < 12 {
			return nil, fmt.Errorf("the long header needs 12 bytes, got %d", len(p))
		}
		hdr := append([]byte{}, p[:8]...)
		if f.CI == CIRspVariableM {
			// MSB-first variant: reverse ID and manufacturer.
			hdr[0], hdr[1], hdr[2], hdr[3] = p[3], p[2], p[1], p[0]
			hdr[4], hdr[5] = p[5], p[4]
		}
		r.Address, r.Header = ParseSecondary(hdr), true
		r.Access, r.Status = p[8], p[9]
		p = p[12:]
	case CIRspNoHeader:
	case CIRspShort:
		if len(p) < 4 {
			return nil, errors.New("the short header needs 4 bytes")
		}
		r.Access, r.Status = p[0], p[1]
		p = p[4:]
	default:
		// Another CI (manufacturer specific A0h–B7h, or one of a later
		// edition): the answer is kept as raw manufacturer data (UnknownCI
		// set) instead of failing the read.
		r.UnknownCI = true
		r.Records = []records.Record{{DIF: 0x0F, Quantity: "manufacturer_data", Manufacturer: true,
			Value: strings.ToUpper(hex.EncodeToString(p)), Raw: append([]byte(nil), p...)}}
		return r, fmt.Errorf("CI %02X is not a variable, fixed, selected application, alarm or application error response; its data is kept as manufacturer_data", f.CI)
	}
	recs, err := records.ParseRecords(p)
	r.Records = recs
	if n := len(recs); n > 0 && recs[n-1].DIF == 0x1F {
		r.More = true
	}
	if err != nil {
		return r, err
	}
	r.DecodeOK = true
	return r, nil
}

// ParsePattern reads a secondary address pattern from configuration:
// "12345678", "1234FFFF", optionally with manufacturer, version and
// medium as "12345678.KAM.01.07" (use "*" or "FF" for any).
func ParsePattern(s string) (SecondaryAddress, error) {
	parts := strings.Split(strings.ToUpper(s), ".")
	a := Wildcard
	a.ID = parts[0]
	if _, err := a.Bytes(); err != nil {
		return a, err
	}
	if len(parts) > 4 {
		return a, fmt.Errorf("secondary address %q has more than four parts", s)
	}
	if len(parts) > 1 && parts[1] != "*" && parts[1] != "FFFF" {
		m, err := records.ManufacturerField(parts[1])
		if err != nil {
			return a, err
		}
		a.Manufacturer = m
	}
	for i, dst := range []*byte{&a.Version, &a.Medium} {
		if len(parts) > 2+i && parts[2+i] != "*" {
			v, err := strconv.ParseUint(parts[2+i], 16, 8)
			if err != nil {
				return a, fmt.Errorf("secondary address %q: %q is not a hex byte", s, parts[2+i])
			}
			*dst = byte(v)
		}
	}
	return a, nil
}

// header reads the TPL header a CI implies (none, short: access number,
// status, 2 bytes configuration; long: the 8-byte address first) and
// returns the rest.
// HasStatus reports whether the response carried a short or long header,
// so its Status is a TPL status byte (EN 13757-3:2025 10.2). Fixed data
// structures (CI 73h/77h) have a status byte with other bit meanings and
// are not included.
func (r *Response) HasStatus() bool {
	switch r.CI {
	case CIAlarmShort, CIAppErrShort, CIRspSelShort, CIRspShort, CIRspDLMSShort,
		CIAlarmLong, CIAppErrLong, CIRspSelLong, CIRspVariable, CIRspVariableM, CIRspDLMSLong:
		return true
	}
	return false
}

func (r *Response) header(ci byte, p []byte) ([]byte, error) {
	switch ci {
	case CIAlarmShort, CIAppErrShort, CIRspSelShort, CIRspShort, CIRspDLMSShort:
		if len(p) < 4 {
			return nil, errors.New("the short header needs 4 bytes")
		}
		r.Access, r.Status = p[0], p[1]
		return p[4:], nil
	case CIAlarmLong, CIAppErrLong, CIRspSelLong, CIRspVariable, CIRspDLMSLong:
		if len(p) < 12 {
			return nil, fmt.Errorf("the long header needs 12 bytes, got %d", len(p))
		}
		r.Address, r.Header = ParseSecondary(p[:8]), true
		r.Access, r.Status = p[8], p[9]
		return p[12:], nil
	}
	return p, nil
}
