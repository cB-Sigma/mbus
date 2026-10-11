package wired_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/cB-Sigma/mbus/wired"
)

// EN 13757-3:2025 clause 7.2: the subcode's upper nibbles carry the
// message application (a, 15 + b, 30 + c), the lower ones the block
// (x, y, z); the clause's own note: 50h F0h 00h equals 50h F0h.
//
// Covers: SIG-IPE-967
func TestMBusApplicationSelectSubcode(t *testing.T) {
	for _, c := range []struct {
		app, block int
		want       []byte
	}{
		{0, 0, []byte{0x00}},
		{3, 2, []byte{0x32}},
		{14, 15, []byte{0xEF}},
		{15, 0, []byte{0xF0, 0x00}},
		{17, 1, []byte{0xF1, 0x20}},
		{29, 0x123, []byte{0xF3, 0xE2, 0x01}},
		{30, 0, []byte{0xF0, 0xF0, 0x00}},
		{45, 0xABC, []byte{0xFC, 0xFB, 0xFA}},
		{2, 0x21, []byte{0x21, 0x02}},
	} {
		got, err := wired.SelectSubcode(c.app, c.block)
		if err != nil || !bytes.Equal(got, c.want) {
			t.Errorf("SelectSubcode(%d, %d) = % X %v, want % X", c.app, c.block, got, err, c.want)
		}
		app, block, err := wired.ParseSubcode(got)
		if err != nil || app != c.app || block != c.block {
			t.Errorf("ParseSubcode(% X) = %d, %d, %v", got, app, block, err)
		}
	}
	// The clause's note: F0 00 and F0 alone both mean application 15.
	for _, b := range [][]byte{{0xF0}, {0xF0, 0x00}} {
		if app, block, _ := wired.ParseSubcode(b); app != 15 || block != 0 {
			t.Errorf("ParseSubcode(% X) = %d, %d", b, app, block)
		}
	}
	if _, err := wired.SelectSubcode(46, 0); err == nil {
		t.Error("application 46 was encoded")
	}
	if _, err := wired.SelectSubcode(1, 0x1000); err == nil {
		t.Error("block 4096 was encoded")
	}
	if _, _, err := wired.ParseSubcode(make([]byte, 11)); err == nil {
		t.Error("an 11-byte subcode was accepted")
	}
	if wired.Application(2) != "simple_billing" || wired.Application(26) != "manufacturer" || wired.Application(50) != "fixed_network_additional" || wired.Application(62) != "reserved" {
		t.Error("table 26 names")
	}
}

// Annex A table A.12 examples 1 and 2 (data type M), annex E.3 table E.13
// (TC field) and annex A type I and J layouts.
//
// Covers: SIG-IPE-968
func TestMBusClockSynchronisation(t *testing.T) {
	// Example 1: 2013-01-02 01:02:03 UTC, 4-byte timer, 1 s resolution,
	// offset +1 h: 0B 60 01 00 21 after LVAR E5.
	m, err := wired.ParseTypeM([]byte{0x0B, 0x60, 0x01, 0x00, 0x21})
	if err != nil || m.Relative || m.Offset != 1 || !m.Time.Equal(time.Date(2013, 1, 2, 1, 2, 3, 0, time.UTC)) {
		t.Errorf("example 1 = %+v %v", m, err)
	}
	// Example 2: -34.5 s relative, 1/256 s resolution: 80 DD 50 after E3.
	m, err = wired.ParseTypeM([]byte{0x80, 0xDD, 0x50})
	if err != nil || !m.Relative || m.Duration != -34500*time.Millisecond {
		t.Errorf("example 2 = %+v %v", m, err)
	}
	// Our encoder: offset not provided (01111b), 1 s.
	enc := wired.TypeM(time.Date(2013, 1, 2, 1, 2, 3, 0, time.UTC), 5)
	if !bytes.Equal(enc, []byte{0x0B, 0x60, 0x01, 0x00, 0x2F}) {
		t.Errorf("TypeM = % X", enc)
	}
	if m, _ := wired.ParseTypeM(enc); m.Offset != 15 || !m.Time.Equal(time.Date(2013, 1, 2, 1, 2, 3, 0, time.UTC)) {
		t.Errorf("round trip = %+v", m)
	}
	// Set time, type M (TC 84h: function 4, no reserved fields).
	at := time.Date(2026, 9, 24, 6, 30, 0, 0, time.UTC)
	b, err := wired.ClockSync{Function: wired.TCSetM, Time: at}.Encode()
	secs := uint32(at.Sub(time.Date(2013, 1, 1, 0, 0, 0, 0, time.UTC)) / time.Second)
	want := []byte{0x84, 0xE5, byte(secs), byte(secs >> 8), byte(secs >> 16), byte(secs >> 24), 0x2F}
	if err != nil || !bytes.Equal(b, want) {
		t.Errorf("set M = % X %v, want % X", b, err, want)
	}
	// Set time, type I, legacy: TC 00h, 6 bytes, 3 reserved, 4 × 2Fh.
	// 2026-09-24 06:30:15 is a Thursday (day of week 4), 2024 a leap year.
	b, err = wired.ClockSync{Function: wired.TCSetI, Time: time.Date(2026, 9, 24, 6, 30, 15, 0, time.UTC), Legacy: true}.Encode()
	// year 26 = 0011010b: bits 29-31 = 010, bits 36-39 = 0011.
	want = []byte{0x00, 15, 30, 6 | 4<<5, 24 | 2<<5, 9 | 3<<4, 0, 0, 0, 0, 0x2F, 0x2F, 0x2F, 0x2F}
	if err != nil || !bytes.Equal(b, want) {
		t.Errorf("set I legacy = % X %v, want % X", b, err, want)
	}
	if ti := wired.TypeI(time.Date(2024, 2, 29, 0, 0, 0, 0, time.UTC)); ti[0]&0x80 == 0 {
		t.Errorf("leap year bit not set: % X", ti)
	}
	// Add 90 s, type J: TC 81h, 3 bytes s, min, h; legacy adds 6 + 4.
	b, _ = wired.ClockSync{Function: wired.TCAddJ, Diff: 90 * time.Second}.Encode()
	if !bytes.Equal(b, []byte{0x81, 30, 1, 0}) {
		t.Errorf("add J = % X", b)
	}
	b, _ = wired.ClockSync{Function: wired.TCSubtractJ, Diff: time.Second, Legacy: true}.Encode()
	if len(b) != 1+3+6+4 || b[0] != 0x02 {
		t.Errorf("subtract J legacy = % X", b)
	}
	// Subtract 10 s, type M relative (offset 10000b).
	b, _ = wired.ClockSync{Function: wired.TCSubtractM, Diff: 10 * time.Second}.Encode()
	if !bytes.Equal(b, []byte{0x86, 0xE5, 10, 0, 0, 0, 0x30}) {
		t.Errorf("subtract M = % X", b)
	}
	if _, err := (wired.ClockSync{Function: wired.TCCorrectM, Legacy: true}).Encode(); err == nil {
		t.Error("legacy fields with type M were encoded")
	}
	if _, err := (wired.ClockSync{Function: 9}).Encode(); err == nil {
		t.Error("a reserved TC function was encoded")
	}
	if _, err := (wired.ClockSync{Function: wired.TCAddJ, Diff: 25 * time.Hour}).Encode(); err == nil {
		t.Error("a type J difference over a day was encoded")
	}
	// EPOCH 2013 of image transfer: 0D 6D E5 xx xx xx xx 20.
	if e := wired.Epoch2013(time.Date(2013, 1, 2, 1, 2, 3, 0, time.UTC)); !bytes.Equal(e, []byte{0x0B, 0x60, 0x01, 0x00}) {
		t.Errorf("Epoch2013 = % X", e)
	}
}

// Clause 10 (table 28, status field) and clause 9 / annex D (alarm CIs
// with headers).
//
// Covers: SIG-IPE-969
func TestMBusApplicationErrorsAndAlarmCIs(t *testing.T) {
	for code, name := range map[byte]string{0x00: "unspecified", 0x01: "ci_field", 0x05: "dife_overflow", 0x08: "application_busy",
		0x15: "parameter_error", 0x17: "message_structure_error", 0x22: "inadequate_security_method", 0xF0: "dynamic",
		0xF5: "manufacturer", 0x07: "reserved", 0x30: "reserved"} {
		if got := wired.AppErrorName(code); got != name {
			t.Errorf("%02X = %s, want %s", code, got, name)
		}
	}
	// Application errors: 6Eh with a short header, 6Fh with a long one,
	// 70h without (EN 13757-7 CI table; OMS Vol 2 table 42 and the annex N.9
	// example, where 6Eh carries access number, status and configuration).
	if wired.CIAppErrShort != 0x6E || wired.CIAppErrLong != 0x6F || wired.CIAppErrNone != 0x70 {
		t.Errorf("application error CIs: short %02X long %02X none %02X", wired.CIAppErrShort, wired.CIAppErrLong, wired.CIAppErrNone)
	}
	hdr := []byte{0x78, 0x56, 0x34, 0x12, 0x24, 0x40, 0x01, 0x07, 0x2A, 0x02, 0, 0}
	for ci, data := range map[byte][]byte{wired.CIAppErrNone: {0x15}, wired.CIAppErrShort: {0x2A, 0x02, 0, 0, 0x15}, wired.CIAppErrLong: append(append([]byte{}, hdr...), 0x15)} {
		r, err := wired.ParseResponse(wired.Frame{Long: true, C: wired.CRspUD, A: 5, CI: ci, Data: data})
		if err != nil || r.AppError == nil || r.AppError.Code != 0x15 || r.AppError.Name != "parameter_error" {
			t.Errorf("CI %02X: %+v %v", ci, r, err)
			continue
		}
		if ci != wired.CIAppErrNone && (r.Access != 0x2A || r.Status != 0x02) {
			t.Errorf("CI %02X header: access %d status %d", ci, r.Access, r.Status)
		}
		var e wired.AppError
		if !errors.As(error(*r.AppError), &e) {
			t.Error("AppError is not an error")
		}
	}
	if r, _ := wired.ParseResponse(wired.Frame{Long: true, C: wired.CRspUD, CI: wired.CIAppErrNone}); r.AppError.Name != "unspecified" {
		t.Error("an empty application error is unspecified")
	}
	for ci, data := range map[byte][]byte{wired.CIAlarmShort: {1, 0, 0, 0, 0x08}, wired.CIAlarmLong: append(append([]byte{}, hdr...), 0x08)} {
		r, err := wired.ParseResponse(wired.Frame{Long: true, C: wired.CRspUD, CI: ci, Data: data})
		if err != nil || !bytes.Equal(r.Alarm, []byte{0x08}) {
			t.Errorf("alarm CI %02X: %+v %v", ci, r, err)
		}
	}
	if _, err := wired.ParseResponse(wired.Frame{Long: true, C: wired.CRspUD, CI: wired.CIAlarmLong, Data: hdr[:5]}); err == nil {
		t.Error("a short long header was accepted")
	}
	st := wired.StatusInfo(0x02 | 0x04 | 0x10 | 0xA0)
	if st["application"] != "error" || st["powerLow"] != true || st["permanentError"] != false || st["temporaryError"] != true || st["manufacturer"] != 5 {
		t.Errorf("status = %v", st)
	}
	// Selected application response (CI 68h, long header).
	r, err := wired.ParseResponse(wired.Frame{Long: true, C: wired.CRspUD, CI: wired.CIRspSelLong, Data: append(append([]byte{}, hdr...), 0x02, 0x5A, 0xE8, 0x03)})
	if err != nil || !r.Selected || !r.Header || len(r.Records) != 1 || r.Records[0].Name() != "flow_temperature" {
		t.Errorf("CI 68 = %+v %v", r, err)
	}
}

// Clause 11 table 29.
//
// Covers: SIG-IPE-970
func TestMBusBaudRateCodes(t *testing.T) {
	for baud, ci := range map[int]byte{300: 0xB8, 600: 0xB9, 1200: 0xBA, 2400: 0xBB, 4800: 0xBC, 9600: 0xBD, 19200: 0xBE, 38400: 0xBF} {
		got, err := wired.BaudCI(baud)
		if err != nil || got != ci || wired.CIBaud(ci) != baud {
			t.Errorf("%d: %02X %v", baud, got, err)
		}
	}
	if _, err := wired.BaudCI(115200); err == nil {
		t.Error("115200 has a CI")
	}
	if wired.CIBaud(0x72) != 0 {
		t.Error("CI 72 is a baud rate")
	}
	// The switch is a control frame (L = 3) to FEh.
	f := wired.Frame{C: wired.CSndUD, A: wired.AddrBroadcastAns, Long: true, CI: 0xBD}
	if !bytes.Equal(f.Encode(), []byte{0x68, 0x03, 0x03, 0x68, 0x53, 0xFE, 0xBD, 0x0E, 0x16}) {
		t.Errorf("control frame = % X", f.Encode())
	}
}

// Annex I: segment structure (table I.2), prepare (I.5 to I.8), transfer
// (I.17, I.18), completion response with the FFFFh tail marker (I.23,
// I.24), state responses (I.29).
//
// Covers: SIG-IPE-971
func TestMBusImageTransferCoding(t *testing.T) {
	id := wired.ImageID{Manufacturer: 0x2C2D, Version: 0x1B, DeviceType: 0x04, Image: 0x01020304}
	if !bytes.Equal(id.Bytes(), []byte{0x2D, 0x2C, 0x1B, 0x04, 0x04, 0x03, 0x02, 0x01}) {
		t.Errorf("image id = % X", id.Bytes())
	}
	seg, err := wired.PrepareCmd{Size: &wired.SizeInfo{Blocks: 300, BlockSize: 128}, ID: &id,
		MAC: &wired.MAC{Algorithm: 3, KeyID: 1, KeyVersion: 0xFF, Value: []byte{1, 2, 3, 4, 5, 6, 7, 8}}}.Segment(7)
	if err != nil {
		t.Fatal(err)
	}
	b := wired.EncodeSegments(seg)
	// SL = 3 + 5 + 8 + 19 = 35; SID 7; F 00; SF = MAC|SZIN|IDEN = 0Dh.
	if b[0] != 35 || b[1] != 0 || b[2] != 7 || b[3] != 0 || b[4] != 0x0D || !bytes.Equal(b[5:10], []byte{0x2C, 0x01, 0x80, 0x00, 0x00}) {
		t.Errorf("prepare = % X", b)
	}
	if mac := b[18:]; mac[0] != 3 || mac[1] != 1 || mac[2] != 0xFF || !bytes.Equal(mac[11:19], make([]byte, 8)) || len(mac) != 19 {
		t.Errorf("MAC field = % X (8-byte MAC padded with zeros)", mac)
	}
	segs, err := wired.ParseSegments(append(b, wired.EncodeSegments(wired.Segment{ID: 8, Function: 4})...))
	if err != nil || len(segs) != 2 || segs[0].ID != 7 || segs[1].Function != 4 {
		t.Errorf("segments = %+v %v", segs, err)
	}
	for _, bad := range [][]byte{{0x02, 0x00, 1, 2}, {0x09, 0x00, 1, 2, 3}, {0x03}} {
		if _, err := wired.ParseSegments(bad); !errors.Is(err, wired.ErrSegmentLength) {
			t.Errorf("% X: %v", bad, err)
		}
	}
	// Transfer: first, middle and last sequence states; remaining field.
	for blk, seq := range map[uint16]byte{0: wired.XferSeqFirst, 1: wired.XferSeqMiddle, 2: wired.XferSeqLast} {
		s := wired.TransferCmd{Block: blk, Blocks: 3, Remaining: true, Data: []byte{0xAA}}.Segment(1)
		if s.Sub&0x06 != seq || s.Sub&wired.XferREM == 0 || s.Params[2] != byte(2-blk) {
			t.Errorf("block %d: sub %02X params % X", blk, s.Sub, s.Params)
		}
		c, err := wired.ParseTransferCmd(s)
		if err != nil || c.Block != blk || !bytes.Equal(c.Data, []byte{0xAA}) {
			t.Errorf("parse block %d: %+v %v", blk, c, err)
		}
	}
	// Completion responses.
	cr, err := wired.ParseCompletionRsp(wired.EncodeCompletionRsp(1, []uint16{2, 5}, false))
	if err != nil || cr.Total != 2 || len(cr.Missing(8)) != 2 || cr.Missing(8)[1] != 5 {
		t.Errorf("lost 2, 5: %+v %v", cr, err)
	}
	cr, _ = wired.ParseCompletionRsp(wired.EncodeCompletionRsp(1, nil, true))
	if !cr.NoneReceived || len(cr.Missing(4)) != 4 {
		t.Errorf("none received: %+v", cr)
	}
	// Block 3 lost and everything after block 6 (FFFFh marker).
	tail := wired.Segment{ID: 1, Function: 0x83, Sub: wired.CmplRspLIB, Params: []byte{3, 0, 6, 0, 0xFF, 0xFF}}
	cr, _ = wired.ParseCompletionRsp(tail)
	if m := cr.Missing(9); len(m) != 4 || m[0] != 3 || m[1] != 6 || m[2] != 7 || m[3] != 8 {
		t.Errorf("tail = %v", m)
	}
	if cr, _ := wired.ParseCompletionRsp(wired.EncodeCompletionRsp(1, nil, false)); len(cr.Missing(5)) != 0 {
		t.Error("a complete transfer has missing blocks")
	}
	st, err := wired.ParseStateRsp(wired.Segment{Function: 0x85, Sub: 0x10 | 9, Params: id.Bytes()})
	if err != nil || st.State != wired.StateValidationSuccessful || st.ID == nil || st.ID.Image != 0x01020304 || wired.ImageStates[st.State] != "validation_successful" {
		t.Errorf("validate response = %+v %v", st, err)
	}
	if _, err := wired.ParseStateRsp(wired.Segment{Function: 0x83}); err == nil {
		t.Error("a completion response carries a state")
	}
	pr, err := wired.ParsePrepareRsp(wired.Segment{Function: 0x80, Sub: wired.PrepRspRDY | wired.PrepRspSZIN, Params: []byte{6, 0x10, 0, 0x40, 0, 0}})
	if err != nil || pr.Ready || pr.ResultName() != "image_too_big" || pr.Size == nil || pr.Size.Blocks != 16 || pr.Size.BlockSize != 64 {
		t.Errorf("prepare response = %+v %v", pr, err)
	}
	// Terminate uses IDEN in bit 2; the others in bit 1.
	if s := wired.SimpleCmd(1, wired.ImgTerminate, &id, wired.TermTIT, nil); s.Sub != wired.TermTIT|wired.TermIDEN {
		t.Errorf("terminate sub = %02X", s.Sub)
	}
	if s := wired.SimpleCmd(1, wired.ImgValidate, &id, 0, nil); s.Sub != wired.CmplIDEN || len(s.Params) != 8 {
		t.Errorf("validate = %+v", s)
	}
}
