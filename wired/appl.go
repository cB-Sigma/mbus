package wired

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Application layer procedures of EN 13757-3:2025 beyond reading data:
// application reset and select (clause 7), clock synchronisation (clause 8
// and annex E.3), alarm status (clause 9 and annex D), application errors
// and the status field (clause 10), baud rate switching (clause 11) and
// the synchronize action (clause 12). The encoders here build the
// application data of a SND_UD; Master (master.go) sends them.

// CI fields of the application procedures (EN 13757-3:2025 tables 27 and
// 29, clauses 8 to 12; the TPL header variant in brackets).
const (
	CIAppSelect      = 0x50 // application reset or select (no header); CIAppReset
	CIAppSelectLong  = 0x53 // the same with a long header
	CIAppSelectShort = 0x57 // the same with a short header (wM-Bus)
	CIReqSelected    = 0x54 // request of the selected application (no header)
	CIReqSelLong     = 0x55
	CIReqSelShort    = 0x56
	CIRspSelected    = 0x66 // response of the selected application (no header)
	CIRspSelShort    = 0x67 // wM-Bus only
	CIRspSelLong     = 0x68
	CISynchronize    = 0x5C // synchronize action, no data (clause 12)
	CIClockSync      = 0x6C // clock synchronisation (annex E.3), long header
	CIAppErrShort    = 0x6E // application error from the device (clause 10.3), short header
	CIAppErrLong     = 0x6F // long header
	CIAppErrNone     = 0x70
	CIAlarmShort     = 0x74 // alarm status with a short header (clause 9)
	CIAlarmLong      = 0x75
)

// ---- application select (clause 7.2) ---------------------------------------

// MaxApplication is the highest message application the three-byte
// subcode can carry (a + b + c with a = b = 15).
const MaxApplication = 45

// SelectSubcode encodes an application select subcode: the upper nibbles
// carry the message application (a, or 15 + b when a is 15, or 30 + c
// when a and b are 15) and the lower nibbles the block number (x in
// bits 0-3, y in 4-7, z in 8-11). Block 0 asks for every block. Only as
// many bytes as the application or block need are sent.
func SelectSubcode(app, block int) ([]byte, error) {
	if app < 0 || app > MaxApplication {
		return nil, fmt.Errorf("message application %d is not 0 to %d", app, MaxApplication)
	}
	if block < 0 || block > 0xFFF {
		return nil, fmt.Errorf("block %d is not 0 to 4095", block)
	}
	var hi []byte // upper nibbles
	switch {
	case app < 15:
		hi = []byte{byte(app)}
	case app < 30:
		hi = []byte{15, byte(app - 15)}
	default:
		hi = []byte{15, 15, byte(app - 30)}
	}
	n := len(hi)
	switch {
	case block > 0xFF && n < 3:
		n = 3
	case block > 0x0F && n < 2:
		n = 2
	}
	out := make([]byte, n)
	for i := range out {
		var h byte
		if i < len(hi) {
			h = hi[i]
		}
		out[i] = h<<4 | byte(block>>(4*i))&0x0F
	}
	return out, nil
}

// ParseSubcode decodes an application select subcode (up to 10 bytes;
// bytes after the third carry nothing defined and are ignored).
func ParseSubcode(b []byte) (app, block int, err error) {
	if len(b) == 0 {
		return 0, 0, nil
	}
	if len(b) > 10 {
		return 0, 0, fmt.Errorf("an application select subcode has at most 10 bytes, got %d", len(b))
	}
	for i := 0; i < len(b) && i < 3; i++ {
		block |= int(b[i]&0x0F) << (4 * i)
	}
	a := int(b[0] >> 4)
	app = a
	if a == 15 && len(b) > 1 {
		bb := int(b[1] >> 4)
		app = 15 + bb
		if bb == 15 && len(b) > 2 {
			app = 30 + int(b[2]>>4)
		}
	}
	return app, block, nil
}

// Applications names the message applications of EN 13757-3:2025 table
// 26 (codes 30 to 45 are manufacturer specific, 46 to 61 additional data
// for fixed network readout).
func Application(code int) string {
	switch {
	case code >= 0 && code < len(appNames):
		return appNames[code]
	case code >= 19 && code <= 25:
		return "reserved"
	case code >= 26 && code <= 45:
		return "manufacturer"
	case code >= 46 && code <= 61:
		return "fixed_network_additional"
	}
	return "reserved"
}

var appNames = []string{"all", "user_data", "simple_billing", "enhanced_billing", "multi_tariff_billing",
	"instantaneous", "load_profile", "static", "installation", "testing", "calibration", "manufacturing",
	"development", "selftest", "configuration", "user_defined", "mobile_readout", "fixed_network_readout",
	"consumer_information"}

// ---- application errors and the status field (clause 10) -------------------

// AppError is a general application error reported by a slave (CI 6Eh,
// 6Fh or 70h, EN 13757-3:2025 table 28).
type AppError struct {
	Code byte // first error code byte; 0 when the data field is empty
	Name string
	Data []byte // every byte after the CI (and header)
}

// Error names the code.
func (e AppError) Error() string {
	return fmt.Sprintf("the meter reports an application error %02Xh (%s)", e.Code, e.Name)
}

// ParseAppError decodes the application error bytes. An empty data field
// is an unspecified error.
func ParseAppError(b []byte) AppError {
	e := AppError{Data: append([]byte(nil), b...), Name: "unspecified"}
	if len(b) > 0 {
		e.Code = b[0]
		e.Name = AppErrorName(b[0])
	}
	return e
}

// AppErrorName names a first error code byte.
func AppErrorName(c byte) string {
	switch c {
	case 0x00:
		return "unspecified"
	case 0x01:
		return "ci_field"
	case 0x02:
		return "buffer_overflow"
	case 0x03:
		return "record_overflow"
	case 0x04:
		return "record_error"
	case 0x05:
		return "dife_overflow"
	case 0x06:
		return "vife_overflow"
	case 0x08:
		return "application_busy"
	case 0x09:
		return "credit_overflow"
	case 0x10:
		return "command_not_finished"
	case 0x11:
		return "no_function"
	case 0x12:
		return "data_error"
	case 0x13:
		return "routing_error"
	case 0x14:
		return "access_violation"
	case 0x15:
		return "parameter_error"
	case 0x16:
		return "size_error"
	case 0x17:
		return "message_structure_error"
	case 0x20:
		return "security_error"
	case 0x21:
		return "security_mechanism_not_supported"
	case 0x22:
		return "inadequate_security_method"
	case 0xF0:
		return "dynamic"
	}
	if c >= 0xF1 {
		return "manufacturer"
	}
	return "reserved"
}

// StatusInfo decodes the status byte of a short or long TPL header (EN
// 13757-7:2025 7.5.6, referenced by EN 13757-3:2025 10.2): bits 0-1 the
// application state, bit 2 power low, bit 3 permanent error, bit 4
// temporary error, bits 5-7 manufacturer specific.
func StatusInfo(s byte) map[string]any {
	return map[string]any{
		"raw":            int(s),
		"application":    [4]string{"ok", "busy", "error", "alarm"}[s&0x03],
		"powerLow":       s&0x04 != 0,
		"permanentError": s&0x08 != 0,
		"temporaryError": s&0x10 != 0,
		"manufacturer":   int(s >> 5),
	}
}

// ---- baud rate switching (clause 11) ---------------------------------------

var baudCI = map[int]byte{300: 0xB8, 600: 0xB9, 1200: 0xBA, 2400: 0xBB, 4800: 0xBC, 9600: 0xBD, 19200: 0xBE, 38400: 0xBF}

// BaudCI is the CI field that switches a slave to baud (table 29).
func BaudCI(baud int) (byte, error) {
	ci, ok := baudCI[baud]
	if !ok {
		return 0, fmt.Errorf("baud %d is not an M-Bus rate (300, 600, 1200, 2400, 4800, 9600, 19200 or 38400)", baud)
	}
	return ci, nil
}

// CIBaud is the baud rate a CI field B8h to BFh selects, 0 for others.
func CIBaud(ci byte) int {
	for b, c := range baudCI {
		if c == ci {
			return b
		}
	}
	return 0
}

// ---- clock synchronisation (clause 8, annex E.3) ---------------------------

// Clock synchronisation functions (TC field bits 0-3, table E.13); the
// data type is I (set) or J (differences, correction) for 0 to 3 and M
// for 4 to 7.
const (
	TCSetI       = 0x0
	TCAddJ       = 0x1
	TCSubtractJ  = 0x2
	TCCorrectJ   = 0x3
	TCSetM       = 0x4
	TCAddM       = 0x5
	TCSubtractM  = 0x6
	TCCorrectM   = 0x7
	tcNoReserved = 0x80 // bit 7: no reserved and command verification fields
)

// ClockSync is one clock synchronisation command.
type ClockSync struct {
	Function byte          // TCSetI … TCCorrectM
	Time     time.Time     // set, correction
	Diff     time.Duration // add, subtract (positive)
	// Legacy keeps the reserved (00h) and command verification (2Fh)
	// fields, for meters of the earlier editions (functions 0 to 2 only).
	Legacy bool
}

// Encode is the application data after the TPL header: the TC field, the
// date/time value and, for Legacy, the reserved and verification fields.
// Type I and J values are the local time of t's location.
func (c ClockSync) Encode() ([]byte, error) {
	f := c.Function & 0x0F
	if f > TCCorrectM {
		return nil, fmt.Errorf("clock function %d is reserved", f)
	}
	tc := f
	if !c.Legacy {
		tc |= tcNoReserved
	} else if f > TCSubtractJ {
		return nil, errors.New("the reserved and verification fields exist only for set time (I) and add or subtract (J)")
	}
	out := []byte{tc}
	switch f {
	case TCSetI:
		out = append(out, TypeI(c.Time)...)
	case TCCorrectJ:
		out = append(out, TypeJ(c.Time.Hour(), c.Time.Minute(), c.Time.Second())...)
	case TCAddJ, TCSubtractJ:
		if c.Diff < 0 || c.Diff >= 24*time.Hour {
			return nil, fmt.Errorf("a type J time difference is 0 to 23:59:59, got %s", c.Diff)
		}
		s := int(c.Diff / time.Second)
		out = append(out, TypeJ(s/3600, s/60%60, s%60)...)
	case TCSetM, TCCorrectM:
		out = append(out, 0xE5) // LVAR: 5 bytes, a 4-byte timer and the top byte
		out = append(out, TypeM(c.Time, 5)...)
	case TCAddM, TCSubtractM:
		if c.Diff < 0 {
			return nil, errors.New("the time difference must not be negative (use add or subtract)")
		}
		m, err := TypeMDuration(c.Diff, 5)
		if err != nil {
			return nil, err
		}
		out = append(out, 0xE5)
		out = append(out, m...)
	}
	if c.Legacy {
		n := 3
		if f != TCSetI {
			n = 6
		}
		out = append(out, make([]byte, n)...)
		out = append(out, 0x2F, 0x2F, 0x2F, 0x2F)
	}
	return out, nil
}

// TypeI encodes a date and time as data type I (annex A, 6 bytes, local
// time of t; day of week, week and daylight saving fields not given).
func TypeI(t time.Time) []byte {
	y := t.Year() % 100
	b := make([]byte, 6)
	b[0] = byte(t.Second())
	if isLeap(t.Year()) {
		b[0] |= 0x80
	}
	b[1] = byte(t.Minute())
	dow := (int(t.Weekday())+6)%7 + 1 // 1 Monday … 7 Sunday
	b[2] = byte(t.Hour()) | byte(dow)<<5
	// The year's low three bits are bits 29-31, its high four bits 36-39.
	b[3] = byte(t.Day()) | byte(y&0x07)<<5
	b[4] = byte(t.Month()) | byte(y>>3)<<4
	return b
}

func isLeap(y int) bool { return y%4 == 0 && (y%100 != 0 || y%400 == 0) }

// TypeJ encodes a time of day as data type J (3 bytes, local time).
func TypeJ(h, m, s int) []byte { return []byte{byte(s), byte(m), byte(h)} }

// epoch2013 is the starting time of data type M with bit X-1 clear.
var epoch2013 = time.Date(2013, 1, 1, 0, 0, 0, 0, time.UTC)

// TypeM encodes an absolute UTC time as data type M (annex A table A.12)
// in n bytes (2 to 10): seconds since 2013-01-01 UTC, resolution 1 s, no
// time offset given (01111b), so the meter keeps its configured zone.
// The LVAR byte (E0h + n) is not included.
func TypeM(t time.Time, n int) []byte {
	return typeM(int64(t.Sub(epoch2013)/time.Second), n, 0x01, 0x0F, false)
}

// TypeMDuration encodes a relative time (time offset 10000b) of d in
// whole seconds, n bytes.
func TypeMDuration(d time.Duration, n int) ([]byte, error) {
	s := int64(d / time.Second)
	if lim := int64(1) << (8*(n-1) - 1); s >= lim || s <= -lim {
		return nil, fmt.Errorf("a duration of %s does not fit %d bytes", d, n)
	}
	return typeM(s, n, 0x01, 0x10, false), nil
}

// typeM packs the duration (two's complement, lower n-1 bytes) and the
// top byte: bit 7 starting time (1 = 1970), bits 6-5 resolution, bits
// 4-0 time offset.
func typeM(v int64, n int, res, offset byte, unix bool) []byte {
	b := make([]byte, n)
	u := uint64(v)
	for i := 0; i < n-1; i++ {
		b[i] = byte(u >> (8 * i))
	}
	top := res&0x03<<5 | offset&0x1F
	if unix {
		top |= 0x80
	}
	b[n-1] = top
	return b
}

// MTime is a decoded data type M value.
type MTime struct {
	Relative bool          // time offset 10000b: a duration
	Invalid  bool          // the most negative duration
	Offset   int           // hours to UTC, -12 to 14; 15 not given
	Duration time.Duration // since the starting time, or the relative time
	Time     time.Time     // absolute: UTC
}

// ParseTypeM decodes n bytes of data type M (without the LVAR byte).
func ParseTypeM(b []byte) (MTime, error) {
	if len(b) < 2 || len(b) > 10 {
		return MTime{}, fmt.Errorf("data type M has 2 to 10 bytes, got %d", len(b))
	}
	n := len(b)
	top := b[n-1]
	var u uint64
	for i := n - 2; i >= 0; i-- {
		u = u<<8 | uint64(b[i])
	}
	bits := uint(8 * (n - 1))
	v := int64(u)
	if bits < 64 && u&(1<<(bits-1)) != 0 {
		v = int64(u | ^uint64(0)<<bits)
	}
	var m MTime
	off := int(top & 0x1F)
	if off >= 16 {
		off -= 32
	}
	m.Offset = off
	m.Relative = off == -16
	if bits < 64 && v == -(int64(1)<<(bits-1)) {
		m.Invalid = true
	}
	var unit time.Duration
	switch top >> 5 & 0x03 {
	case 0:
		unit = 2 * time.Second
	case 1:
		unit = time.Second
	case 2:
		unit = time.Second / 256
	case 3:
		unit = time.Second / 32768
	}
	m.Duration = time.Duration(v) * unit
	if top>>5&0x03 == 3 { // 1/32768 s is not a whole number of nanoseconds
		m.Duration = time.Duration(v) * time.Second / 32768
	}
	if !m.Relative {
		start := epoch2013
		if top&0x80 != 0 {
			start = time.Unix(0, 0).UTC()
		}
		m.Time = start.Add(m.Duration)
	}
	return m, nil
}

// Epoch2013 encodes t as the 4-byte EPOCH 2013 seconds used by the image
// transfer date and time fields (annex I.2.4.3).
func Epoch2013(t time.Time) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(t.Sub(epoch2013)/time.Second))
	return b
}
