package wireless

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

// Annex C of EN 13757-4:2025: the same meter ("CEN", 12345678h, version
// 01h, water) in mode S1/T1 (format A, C.1 and C.2) and C1 (format B with
// ELL 8Ch, C.3).
const (
	annexCFormatA = "0F44AE0C785634120107 4447 780B13436587 1E6D"
	annexCFormatB = "1444AE0C785634120107 8C2027 780B13436587 7AC5"
)

// Covers: SIG-IPE-930
func TestLinkAnnexCFrames(t *testing.T) {
	a := hx(t, annexCFormatA)
	if CRC(a[:10]) != 0x4447 || CRC(a[12:18]) != 0x1E6D {
		t.Fatalf("block CRCs %04X %04X", CRC(a[:10]), CRC(a[12:18]))
	}
	plain, f, err := StripCRC(a, FormatAuto)
	if err != nil || f != FormatA || !bytes.Equal(plain, hx(t, "0F44AE0C785634120107 780B13436587")) {
		t.Fatalf("format A: %X %s %v", plain, f, err)
	}
	if got := AddCRCA(plain); !bytes.Equal(got, a) || FrameLenA(0x0F) != len(a) {
		t.Errorf("AddCRCA %X", got)
	}
	h, _ := ParseHeader(plain)
	if h.Manufacturer != "CEN" || h.MField != 0x0CAE || h.ID != "12345678" || h.Version != 1 || h.DeviceType != 7 ||
		!HardAddress(h.MField) || CFieldName(h.C) != "SND-NR" {
		t.Errorf("header %+v", h)
	}

	b := hx(t, annexCFormatB)
	if CRC(b[:len(b)-2]) != 0x7AC5 {
		t.Fatalf("format B CRC %04X", CRC(b[:len(b)-2]))
	}
	plain, f, err = StripCRC(b, FormatAuto)
	if err != nil || f != FormatB || plain[0] != byte(len(plain)-1) || !bytes.Equal(plain[1:], b[1:len(b)-2]) {
		t.Fatalf("format B: %X %s %v", plain, f, err)
	}
	if got := AddCRCB(plain); !bytes.Equal(got, b) {
		t.Errorf("AddCRCB %X", got)
	}
	tg, err := Decode(b, FormatB, nil)
	if err != nil || tg.ELL == nil || tg.ELL.CC != CCSynchronized || tg.ELL.ACC != 0x27 || tg.ELL.HasSN {
		t.Fatalf("C1 telegram: %v %+v", err, tg)
	}
	if v := recordMap(tg.Records)["volume"]; math.Abs(v.Value.(float64)-876.543) > 1e-9 {
		t.Errorf("volume %v", v)
	}
}

// Covers: SIG-IPE-930
func TestLinkFormatBLengths(t *testing.T) {
	// Up to 128 bytes with L and CRC: one CRC; 131 to 256 bytes: a second
	// CRC over the bytes after the first 128 (12.4).
	for _, body := range []int{12, 126, 127, 128, 252} {
		plain := make([]byte, body)
		for i := range plain {
			plain[i] = byte(i * 7)
		}
		plain[0] = byte(body - 1)
		fb := AddCRCB(plain)
		want := body + 2
		if body > 126 {
			want = body + 4
		}
		if len(fb) != want || int(fb[0]) != len(fb)-1 {
			t.Errorf("body %d: %d bytes, L %d", body, len(fb), fb[0])
		}
		if len(fb) > 128 && CRC(fb[:126]) != binary.BigEndian.Uint16(fb[126:128]) {
			t.Errorf("body %d: first CRC not over the first 126 bytes", body)
		}
		back, _, err := StripCRC(fb, FormatB)
		if err != nil || !bytes.Equal(back[1:], plain[1:]) {
			t.Errorf("body %d: %v", body, err)
		}
	}
	// 129 and 130 bytes are not valid format B lengths.
	for _, n := range []int{129, 130} {
		b := make([]byte, n)
		b[0] = byte(n - 1)
		if _, err := stripB(b); err == nil {
			t.Errorf("%d-byte format B frame accepted", n)
		}
	}
}

// Covers: SIG-IPE-930
func TestLink3of6(t *testing.T) {
	// Table 10: nibble → 6-bit code word.
	want := []byte{22, 13, 14, 11, 28, 25, 26, 19, 44, 37, 38, 35, 52, 49, 50, 41}
	for n, w := range want {
		if threeOfSix[w] != byte(n) {
			t.Errorf("nibble %X: code %06b maps to %X", n, w, threeOfSix[w])
		}
	}
	if len(threeOfSix) != 16 {
		t.Errorf("%d code words", len(threeOfSix))
	}
	// C.2.3: the first 16 code words of the mode T1 example, most
	// significant nibble and bit first.
	codes := "010110 101001 011100 011100 100110 110010 010110 110100 " +
		"010011 101100 011001 011010 001011 011100 001101 001110"
	bits := strings.ReplaceAll(codes, " ", "")
	var chips []byte
	for i := 0; i < len(bits); i += 8 {
		var c byte
		for _, r := range bits[i : i+8] {
			c = c<<1 | byte(r-'0')
		}
		chips = append(chips, c)
	}
	frame := hx(t, annexCFormatA)
	if got := Encode3of6(frame[:8]); !bytes.Equal(got, chips) {
		t.Errorf("3-out-of-6 chips %X, want %X", got, chips)
	}
	if got, err := Decode3of6(chips); err != nil || !bytes.Equal(got, frame[:8]) {
		t.Errorf("decoded %X %v", got, err)
	}
}

// Covers: SIG-IPE-930
func TestLinkCField(t *testing.T) {
	for c, n := range map[byte]string{
		CSndNKE: "SND-NKE", CSndUD: "SND-UD", CSndUDF: "SND-UD", CSndUD2: "SND-UD2", CSndNR: "SND-NR",
		CSndUD3: "SND-UD3", CSndIR: "SND-IR", CAccNR: "ACC-NR", CAccDMD: "ACC-DMD",
		CReqUD1: "REQ-UD1", CReqUD1F: "REQ-UD1", CReqUD2: "REQ-UD2", CReqUD2F: "REQ-UD2",
		CACK: "ACK", 0x10: "ACK", CNACK: "NACK", CCnfIR: "CNF-IR", CRspUD: "RSP-UD", 0x28: "RSP-UD",
		0x49: "0x49", 0x02: "0x02",
	} {
		if got := CFieldName(c); got != n {
			t.Errorf("C %02X: %s, want %s", c, got, n)
		}
	}
	if HardAddress(0x8CAE) {
		t.Error("M field with MSBit set is a soft address")
	}
}

// Covers: SIG-IPE-930
func TestLinkSyncInterval(t *testing.T) {
	// Annex D: ACC 110 and 112 received 1661,563 s apart (111 missed) give
	// tNOM 850,083 s; the next interval is 830,159 s.
	tNom := time.Duration(850.083 * float64(time.Second))
	sum := SyncInterval(110, tNom) + SyncInterval(111, tNom)
	if d := sum - time.Duration(1661.563*float64(time.Second)); d.Abs() > time.Millisecond {
		t.Errorf("t110+t111 = %v", sum)
	}
	if d := SyncInterval(112, tNom) - time.Duration(830.159*float64(time.Second)); d.Abs() > time.Millisecond {
		t.Errorf("t112 = %v", SyncInterval(112, tNom))
	}
	if SyncInterval(128, 2048*time.Second) != 1984*time.Second || SyncInterval(0, 2048*time.Second) != 2112*time.Second {
		t.Error("interval bounds")
	}
}

// Covers: SIG-IPE-930
func TestLinkModes(t *testing.T) {
	for in, want := range map[string]string{
		"t1": "T1", "T2": "T2", "s1": "S1", "S1-m": "S1-m", "s1m": "S1-m", "S2": "S2", "R2": "R2",
		"c1": "C1", "C2": "C2", "N1": "N1", "n2g": "N2g", "N1A": "N1a", "F2": "F2", "f2-m": "F2-m",
	} {
		if got, ok := NormalizeLinkMode(in); !ok || got != want {
			t.Errorf("%s: %s %v", in, got, ok)
		}
	}
	for _, bad := range []string{"R1", "X1", "N3", "N1h", "T"} {
		if _, ok := NormalizeLinkMode(bad); ok {
			t.Errorf("%s accepted", bad)
		}
	}
	for m, n := range map[string]int{"S1": 1, "T1": 1, "R2": 1, "C1": 2, "N2a": 2, "F2": 2} {
		if len(ModeFormats(m)) != n {
			t.Errorf("%s formats %v", m, ModeFormats(m))
		}
	}
	tel := hx(t, annexCFormatB)
	for line, mode := range map[string]string{
		"C1;1;1;2026-09-01 10:00:00.000;97;148;12345678;0x" + strings.ReplaceAll(annexCFormatB, " ", ""): "C1",
		"R2;" + strings.ReplaceAll(annexCFormatB, " ", ""):                                               "R2",
		"N2a " + strings.ReplaceAll(annexCFormatB, " ", ""):                                              "N2a",
		"S1-m," + strings.ReplaceAll(annexCFormatB, " ", ""):                                             "S1-m",
		"F2:" + strings.ReplaceAll(annexCFormatB, " ", ""):                                               "F2",
		strings.ReplaceAll(annexCFormatB, " ", ""):                                                       "",
	} {
		got, err := ParseHexLine(line)
		if err != nil || got.LinkMode != mode || !bytes.Equal(got.Frame, tel) {
			t.Errorf("%q: %q %X %v", line, got.LinkMode, got.Frame, err)
		}
		if !IsHexText([]byte(line)) {
			t.Errorf("%q not recognised as a hex line", line)
		}
	}
}

// Covers: SIG-IPE-932
func TestLinkRXL(t *testing.T) {
	// Figure 1: RSSI −60, −80, −70 and −50 dBm give RL 42, 32, 37 and 47.
	for dbm, rl := range map[float64]byte{-60: 42, -80: 32, -70: 37, -50: 47, -150: 1, 0: 63} {
		if got := RSSIToRL(dbm); got != rl {
			t.Errorf("%v dBm: RL %d, want %d", dbm, got, rl)
		}
	}
	if k, v, ok := RXLValue(42); !ok || k != "rssi" || v != -60 {
		t.Errorf("RXL 42: %s %v %v", k, v, ok)
	}
	if k, v, ok := RXLValue(0x40 | 20); !ok || k != "linkMargin" || v != 9 {
		t.Errorf("link margin: %s %v %v", k, v, ok)
	}
	for _, b := range []byte{0, 0x40, 0x80 | 5} {
		if _, _, ok := RXLValue(b); ok {
			t.Errorf("RXL %02X has no value", b)
		}
	}
}

// ellHeader is the first block of the ELL tests (sender CEN 12345678).
const ellHeader = "00 44 AE0C 78563412 01 07"

// Covers: SIG-IPE-932
func TestELLCounterBlock(t *testing.T) {
	// 13.2.12: the counter block is M and A of the first block (not M2/A2),
	// CC with H and R cleared, SN, FN (0) and the block counter (from 0).
	key := hx(t, "000102030405060708090A0B0C0D0E0F")
	hdr := hx(t, ellHeader)
	cc := byte(CCBidirectional | CCAccessible)
	sn := uint32(1<<29 | 0x00ABCDE0 | 3)
	payload := hx(t, "78 0413 AC0D0000 0413 AC0D0000 0413 AC0D0000 0413 AC0D0000") // > 16 bytes: two blocks
	crc := CRC(payload)
	plain := append([]byte{byte(crc >> 8), byte(crc)}, payload...)
	iv := append(append(append([]byte{}, hdr[2:10]...), cc), 0xE3, 0xCD, 0xAB, 0x20, 0, 0, 0)
	if len(iv) != 16 {
		t.Fatal(len(iv))
	}
	enc, _ := ctrXOR(key, iv, plain)
	build := func(cc byte) []byte {
		f := append(append([]byte{}, hdr...), CIELL16, cc, 0x31)
		f = append(f, hx(t, "3330 11223344 01 31")...) // M2/A2: the destination
		f = binary.LittleEndian.AppendUint32(f, sn)
		f = append(f, enc...)
		f[0] = byte(len(f) - 1)
		return f
	}
	keys := func(Header) []byte { return key }
	for _, c := range []byte{cc, cc | CCHop | CCRepeated} {
		tg, err := Decode(build(c), FormatNoCRC, keys)
		if err != nil || !tg.Encrypted || !tg.ELL.HasAddr || tg.ELL.M2 != 0x3033 || tg.ELL.SN != sn {
			t.Fatalf("CC %02X: %v %+v", c, err, tg.ELL)
		}
		if len(tg.Records) != 4 {
			t.Errorf("CC %02X: records %v", c, tg.Records)
		}
	}
	if !bytes.Equal(ellIV(0x0CAE, [6]byte{0x78, 0x56, 0x34, 0x12, 1, 7}, cc|CCHop|CCRepeated, sn, 0), iv) {
		t.Error("ellIV differs from Table 54")
	}
}

// Covers: SIG-IPE-932
func TestELLVariable(t *testing.T) {
	// CI 86h (13.2.6, Tables 48 and 49): CC, ACC, ECL, then M2, A2, SN,
	// RTD, RXL and payload CRC as ECL selects, in that order.
	key := hx(t, "0F0E0D0C0B0A09080706050403020100")
	hdr := hx(t, ellHeader)
	h, _ := ParseHeader(append(hdr[:0:0], append(hdr, 0x78)...))
	payload := hx(t, "78 0413 AC0D0000")
	crc := CRC(payload)
	sn := uint32(1<<29 | 0x100)
	cc := byte(CCSynchronized | CCHop)
	enc, _ := ctrXOR(key, ellIV(h.MField, h.A, cc, sn, 0), append([]byte{byte(crc >> 8), byte(crc)}, payload...))
	ecl := byte(ECLPayloadCRC | ECLRXL | 0x04 | ECLSN | ECLAddress)
	p := append([]byte{CIELLV, cc, 0x42, ecl}, hx(t, "3330 11223344 01 31")...)
	p = binary.LittleEndian.AppendUint32(p, sn)
	p = append(p, 0x00, 0x02, 42) // RTD 512/256 s, RXL −60 dBm
	p = append(p, enc...)
	tg := &Telegram{Header: h}
	rest, err := tg.ell(p, func(Header) []byte { return key })
	if err != nil || !bytes.Equal(rest, payload) || !tg.Encrypted {
		t.Fatalf("variable ELL: %v %X", err, rest)
	}
	e := tg.ELL
	if e.ECL != ecl || !e.HasAddr || !e.HasSN || !e.HasRTD || e.RunTimeDelay() != 2*time.Second || !e.HasRXL || e.RXL != 42 {
		t.Errorf("ELL %+v", e)
	}
	// Minimal: CC, ACC, ECL only; then RTD in 2 s units and nothing else.
	tg = &Telegram{Header: h}
	if rest, err := tg.ell([]byte{CIELLV, 0, 1, 0x08, 5, 0, 0x78}, nil); err != nil || tg.ELL.RunTimeDelay() != 10*time.Second || !bytes.Equal(rest, []byte{0x78}) {
		t.Errorf("RTD only: %v %+v", err, tg.ELL)
	}
	if _, err := (&Telegram{Header: h}).ell([]byte{CIELLV, 0, 1, 0x0C, 0, 0}, nil); !errors.Is(err, ErrUnsupport) {
		t.Errorf("reserved RTD resolution: %v", err)
	}
}

// Covers: SIG-IPE-932
func TestLinkDuplicateKey(t *testing.T) {
	// 12.7: a copy relayed by a repeater (H set, maybe R) is a duplicate.
	mk := func(s string) []byte {
		f := hx(t, ellHeader+s)
		f[0] = byte(len(f) - 1)
		return f
	}
	direct := mk("8C 20 27 78 0B13436587")
	relayed := mk("8C 32 27 78 0B13436587")
	k1, err1 := DuplicateKey(direct)
	k2, err2 := DuplicateKey(relayed)
	if err1 != nil || err2 != nil || k1 != k2 || Relayed(direct) || !Relayed(relayed) {
		t.Errorf("ELL: %v %v %s %s", err1, err2, k1, k2)
	}
	if k3, _ := DuplicateKey(mk("8C 20 28 78 0B13436587")); k3 == k1 {
		t.Error("another access number is not a duplicate")
	}
	// Variable ELL: RTD and RXL change on the way, the rest does not.
	v1, _ := DuplicateKey(mk("86 20 27 00 780B13436587"))
	v2, _ := DuplicateKey(mk("86 30 27 14 0300 2A 780B13436587"))
	if v1 != v2 {
		t.Errorf("variable ELL: %s %s", v1, v2)
	}
	// TPL short header, security mode 5: H and R are config bits 0 and 1.
	s1, _ := DuplicateKey(mk("7A 27 00 1005 AABBCCDD"))
	s2, _ := DuplicateKey(mk("7A 27 00 1305 AABBCCDD"))
	if s1 != s2 || !Relayed(mk("7A 27 00 1105 AABBCCDD")) {
		t.Errorf("TPL: %s %s", s1, s2)
	}
	if _, err := DuplicateKey([]byte{1, 2}); err == nil {
		t.Error("short frame accepted")
	}
}
