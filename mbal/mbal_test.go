package mbal

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/cB-Sigma/mbus/records"
	"github.com/cB-Sigma/mbus/wireless"
)

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// longTPL is a long TPL header (meter KAM 12345678, version 1, water) with
// one unencrypted record: volume, 8-digit BCD, 1 l resolution = 12345.678 m3.
const (
	longTPL  = "72 78563412 2D2C 01 07 2A 00 0000 0C13 78563412"
	shortTPL = "7A 2B 00 0000 0C13 78563412"
)

// omsMode5 is the OMS Volume 2 security mode 5 example (link header, then
// a short TPL header from 7A); its key is 0102…0E0F11.
const (
	omsMode5    = "2E4493157856341233037A2A0020255923C95AAA26D1B2E7493B013EC4A6F6D3529B520EDFF0EA6DEFC99D6D69EBF3"
	omsMode5Key = "0102030405060708090A0B0C0D0E0F11"
)

func volume(t *testing.T, recs []records.Record) float64 {
	t.Helper()
	for _, r := range Readings(recs) {
		if r.Name == "volume" {
			if r.Unit != "m3" {
				t.Errorf("volume unit %q, want m3", r.Unit)
			}
			f, _ := r.Value.(float64)
			return f
		}
	}
	t.Fatalf("no volume reading in %+v", recs)
	return 0
}

// Covers: SIG-IPE-958
func TestControlFieldBits(t *testing.T) {
	// Every byte round-trips in both directions, bit by bit (Tables 6, 7).
	for d := Uplink; d <= Downlink; d++ {
		for b := 0; b < 256; b++ {
			c := ParseControl(byte(b), d)
			if c.Byte() != byte(b) {
				t.Fatalf("%s %02X round-trips to %02X", d, b, c.Byte())
			}
			if c.Version != uint8(b>>6) || c.Sub != uint8(b>>4&3) || c.Function != Function(b&0x0F) {
				t.Fatalf("%s %02X split into %+v", d, b, c)
			}
			if (c.Check() == nil) != (b>>6 == 0) {
				t.Fatalf("%s %02X: only version bits 00 are defined (Table 8)", d, b)
			}
		}
	}
	// The values used in Annexes B, C, D and E.
	for _, tc := range []struct {
		b      byte
		d      Direction
		sub    string
		name   string
		answer byte // 0: none
	}{
		{0x15, Uplink, "short", "ACC-DMD2", 0x2A},     // B.1, D.6.3.3
		{0x2A, Downlink, "asap", "REQ-UD1", 0},        // B.1
		{0x18, Uplink, "short", "RSP-UD", 0},          // B.1, B.2, C.4.3.4.3.3
		{0x14, Uplink, "short", "SND-NR", 0},          // B.2, D.6.3.2, E.5.3.2
		{0x2B, Downlink, "asap", "REQ-UD2", 0},        // B.2, D.6.3.4
		{0x12, Uplink, "short", "SND-UD", 0x10},       // B.3
		{0x10, Downlink, "delay", "TPL-ACK", 0},       // B.3
		{0x04, Uplink, "none", "SND-NR", 0},           // C.4.3.4.3.2
		{0x06, Uplink, "none", "SND-IR", 0x16},        // C.4.3.4.3.2
		{0x23, Downlink, "asap", "SND-UD2", 0},        // C.4.3.4.3.3, E.5.3.2
		{0x37, Downlink, "unused", "SND-NKE", 0},      // C.4.3.4.3.3
		{0x16, Uplink, "short", "SND-IR", 0x16},       // D.6.3.2 (answered by CNF-IR, 16h)
		{0x16, Downlink, "delay", "CNF-IR", 0},        // D.6.3.2
		{0x1A, Uplink, "short", "ACC-DMD", 0x10},      // Table 11: confirmed by TPL-ACK
		{0x13, Uplink, "short", "RFU", 0x11},          // Table 11 footnote a: TPL-NACK
		{0x1F, Uplink, "short", "unused", 0x11},       // Table 11: function code not used
		{0x35, Downlink, "unused", "SND-UD3", 0},      // Table 12
		{0x39, Downlink, "unused", "RFU", 0},          // Table 12
		{0x31, Downlink, "unused", "TPL-NACK", 0},     // Table 12
		{0x37, Uplink, "unused", "ACC-NR", 0},         // Table 11
		{0x20, Uplink, "unlimited", "TPL-ACK", 0},     // Table 9 access 10
		{0x0B, Uplink, "none", "RFU", 0x11},           // Table 11: Bh RFU
		{0x05, Downlink, "rfu", "SND-UD3", 0},         // Table 10 latency 00 RFU
		{0x3B, Downlink, "unused", "REQ-UD2", 0},      // Table 12
		{0x28, Uplink, "unlimited", "RSP-UD", 0},      // Table 11
		{0x2A, Uplink, "unlimited", "ACC-DMD", 0x10},  // Table 11
		{0x08, Downlink, "rfu", "RFU", 0},             // Table 12: 8h RFU
		{0x0C, Downlink, "rfu", "RFU", 0},             // Table 12: Ch RFU
		{0x0F, Downlink, "rfu", "unused", 0},          // Table 12
		{0x00, Uplink, "none", "TPL-ACK", 0},          // Table 11
		{0x01, Uplink, "none", "TPL-NACK", 0},         // Table 11
		{0x17, Uplink, "short", "ACC-NR", 0},          // Table 11, D.6.2.3
		{0x03, Downlink, "rfu", "SND-UD2", 0},         // Table 12
		{0x02, Downlink, "rfu", "SND-UD", 0},          // Table 12
		{0x04, Downlink, "rfu", "SND-NR", 0},          // Table 12
		{0x06, Downlink, "rfu", "CNF-IR", 0},          // Table 12
		{0x07, Downlink, "rfu", "SND-NKE", 0},         // Table 12
		{0x0A, Downlink, "rfu", "REQ-UD1", 0},         // Table 12
		{0x0B, Downlink, "rfu", "REQ-UD2", 0},         // Table 12
		{0x3A, Uplink, "unused", "ACC-DMD", 0x10},     // Table 11
		{0x25, Uplink, "unlimited", "ACC-DMD2", 0x2A}, // Table 11
	} {
		c := ParseControl(tc.b, tc.d)
		sub := c.Access().String()
		if tc.d == Downlink {
			sub = c.Latency().String()
		}
		if sub != tc.sub || c.Name() != tc.name || c.Version != 0 {
			t.Errorf("%s %02X = %s %s v%d, want %s %s", tc.d, tc.b, sub, c.Name(), c.Version+1, tc.sub, tc.name)
		}
		a, ok := Answer(c)
		if (tc.answer != 0) != ok || (ok && a.Byte() != tc.answer) {
			t.Errorf("answer to %s %02X = %v %02X, want %02X", tc.d, tc.b, ok, a.Byte(), tc.answer)
		}
		if f, err := ParseFunction(tc.d, c.Name()); c.Known() && (err != nil || f != c.Function) {
			t.Errorf("ParseFunction(%s) = %v, %v", c.Name(), f, err)
		}
	}
	if c := NewUplink(AccessShort, FnACCDMD2); c.Byte() != 0x15 {
		t.Errorf("NewUplink(short, ACC-DMD2) = %02X, want 15", c.Byte())
	}
	if c := NewDownlink(LatencyASAP, FnREQUD1); c.Byte() != 0x2A {
		t.Errorf("NewDownlink(asap, REQ-UD1) = %02X, want 2A", c.Byte())
	}
	if f, err := ParseFunction(Downlink, "req_ud2"); err != nil || f != FnREQUD2 {
		t.Errorf("ParseFunction(req_ud2) = %v, %v", f, err)
	}
	if _, err := ParseFunction(Uplink, "REQ-UD2"); err == nil {
		t.Error("REQ-UD2 is a downlink function only")
	}
}

// Covers: SIG-IPE-960
func TestConfirmedByAndAnswers(t *testing.T) {
	// "Confirmed by" column of Tables 11 and 12.
	for _, tc := range []struct {
		d    Direction
		f    Function
		want Function
		ok   bool
	}{
		{Uplink, FnSNDUD, FnTPLACK, true}, {Uplink, FnACCDMD2, FnREQUD1, true}, {Uplink, FnSNDIR, FnCNFIR, true},
		{Uplink, FnACCDMD, FnTPLACK, true}, {Uplink, FnSNDNR, 0, false}, {Uplink, FnRSPUD, 0, false},
		{Uplink, FnACCNR, 0, false}, {Uplink, FnTPLACK, 0, false},
		{Downlink, FnSNDUD, FnTPLACK, true}, {Downlink, FnSNDUD2, FnRSPUD, true}, {Downlink, FnREQUD1, FnRSPUD, true},
		{Downlink, FnREQUD2, FnRSPUD, true}, {Downlink, FnSNDNR, 0, false}, {Downlink, FnSNDUD3, 0, false},
		{Downlink, FnCNFIR, 0, false}, {Downlink, FnSNDNKE, 0, false},
	} {
		c := Control{Direction: tc.d, Function: tc.f}
		got, ok := c.ConfirmedBy()
		if ok != tc.ok || got != tc.want {
			t.Errorf("%s %s confirmed by %v %v, want %v %v", tc.d, c.Name(), got, ok, tc.want, tc.ok)
		}
	}
	// Access 00 asks to postpone a downlink (7.2.1.3 NOTE); 01 and 10 open a window.
	if ParseControl(0x04, Uplink).Reachable() || !ParseControl(0x14, Uplink).Reachable() ||
		!ParseControl(0x24, Uplink).Reachable() || ParseControl(0x34, Uplink).Reachable() {
		t.Error("Reachable does not follow Table 9")
	}
	// An RFU version gets no answer: we cannot interpret it.
	if _, ok := Answer(ParseControl(0x52, Uplink)); ok {
		t.Error("a version 2 control field was answered")
	}
	// Annex B.3 over UDP: SND-UD 12h answered by TPL-ACK 10h.
	a, _ := Answer(ParseControl(0x12, Uplink))
	if got := BuildUDP(a, nil); !bytes.Equal(got, []byte{0xCF, 0x10}) {
		t.Errorf("UDP TPL-ACK = % X", got)
	}
	// Over LoRaWAN the answer's control field is the FPort (Annex D.6.3.3: 2Ah = 42).
	a, _ = Answer(ParseControl(0x15, Uplink))
	if p, err := LoRaWANPort(a); err != nil || p != 42 {
		t.Errorf("REQ-UD1 FPort = %d, %v, want 42", p, err)
	}
	if _, err := LoRaWANPort(ParseControl(0x00, Uplink)); err == nil {
		t.Error("control field 00h cannot be FPort 0")
	}
}

// Covers: SIG-IPE-959
func TestGenericLayoutAndCI(t *testing.T) {
	up := hx(t, longTPL)
	// With the CI field CFh (Table 5) and without it.
	for _, p := range [][]byte{append([]byte{0xCF, 0x14}, up...), append([]byte{0x14}, up...)} {
		m, err := Parse(p, Uplink)
		if err != nil || m.Control.Byte() != 0x14 || !bytes.Equal(m.Upper, up) || m.WithCI != (p[0] == 0xCF) {
			t.Fatalf("Parse(% X) = %+v, %v", p[:2], m, err)
		}
	}
	if _, err := Parse(nil, Uplink); !errors.Is(err, ErrEmpty) {
		t.Errorf("empty payload: %v", err)
	}
	if _, err := Parse([]byte{0xCF}, Uplink); err == nil {
		t.Error("CI without control field accepted")
	}
	if _, err := Parse([]byte{0x94, 0x72}, Uplink); err == nil {
		t.Error("RFU version accepted")
	}
	// A message without upper layers (ACC-NR, D.6.2.3) decodes to no records.
	m, _ := Parse([]byte{0xCF, 0x17}, Uplink)
	if r := Decode(m, nil, nil); r.Err != nil || r.Telegram != nil || len(r.Records) != 0 {
		t.Errorf("ACC-NR decoded to %+v", r)
	}
}

// Covers: SIG-IPE-961
func TestLoRaWANLayout(t *testing.T) {
	// Annex D.6.3.2: SND-IR 16h on FPort 22 with a long TPL header, then
	// SND-NR 14h on FPort 20.
	m, err := ParseLoRaWAN(22, hx(t, longTPL), Uplink)
	if err != nil || m.Control.Name() != "SND-IR" || m.Control.Access() != AccessShort || m.WithCI {
		t.Fatalf("FPort 22: %+v, %v", m, err)
	}
	r := Decode(m, nil, nil)
	if r.Err != nil || r.Meter == nil || r.Meter.Key() != "KAM-12345678" || r.Meter.DeviceType != 7 {
		t.Fatalf("long header: %+v, meter %+v", r.Err, r.Meter)
	}
	if v := volume(t, r.Records); math.Abs(v-12345.678) > 1e-9 {
		t.Errorf("volume = %v", v)
	}
	if a, ok := Answer(m.Control); !ok || a.Byte() != 0x16 {
		t.Errorf("SND-IR answer = %v %02X, want CNF-IR 16h", ok, a.Byte())
	}
	// Short header: the meter is what the DevEUI maps to.
	m, err = ParseLoRaWAN(20, hx(t, shortTPL), Uplink)
	if err != nil || m.Control.Name() != "SND-NR" {
		t.Fatalf("FPort 20: %+v, %v", m, err)
	}
	addr, err := MeterAddress("KAM", "12345678", 1, 7)
	if err != nil {
		t.Fatal(err)
	}
	r = Decode(m, &addr, nil)
	if r.Err != nil || r.Telegram.HeaderKind != "short" || r.Telegram.Access != 0x2B || r.Meter.Key() != "KAM-12345678" {
		t.Fatalf("short header: %v %+v", r.Err, r.Telegram)
	}
	volume(t, r.Records)
	// Annex D.6.3.3 / D.6.3.4 ports: 21 ACC-DMD2, 24 RSP-UD, 42 REQ-UD1, 43 REQ-UD2.
	for p, want := range map[int]string{21: "ACC-DMD2", 24: "RSP-UD"} {
		if m, err := ParseLoRaWAN(p, nil, Uplink); err != nil || m.Control.Name() != want {
			t.Errorf("FPort %d = %v, %v", p, m, err)
		}
	}
	for p, want := range map[int]string{42: "REQ-UD1", 43: "REQ-UD2", 22: "CNF-IR"} {
		if m, err := ParseLoRaWAN(p, nil, Downlink); err != nil || m.Control.Name() != want {
			t.Errorf("downlink FPort %d = %v, %v", p, m, err)
		}
	}
	for _, p := range []int{0, 224, 255, -1} {
		if _, err := ParseLoRaWAN(p, nil, Uplink); !errors.Is(err, ErrFPort) {
			t.Errorf("FPort %d accepted", p)
		}
	}
	if _, err := ParseLoRaWAN(0x54, nil, Uplink); err == nil {
		t.Error("FPort 84 (version bits 01) accepted")
	}
}

// Covers: SIG-IPE-961
func TestUpperLayerSecurity(t *testing.T) {
	frame := hx(t, omsMode5)
	upper := frame[10:]
	link, err := wireless.ParseHeader(frame)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := ParseLoRaWAN(0x14, upper, Uplink)
	// Without a key: reported as encrypted, no records.
	r := Decode(m, &link, nil)
	if !r.Encrypted || len(r.Records) != 0 || r.Telegram.Mode != 5 {
		t.Fatalf("no key: encrypted=%v records=%d err=%v", r.Encrypted, len(r.Records), r.Err)
	}
	if meta := r.Meta(); meta["encrypted"] != true || meta["securityMode"] != 5 {
		t.Errorf("meta %v", meta)
	}
	// With the key and the meter address mapped from the LPWAN identity.
	key := hx(t, omsMode5Key)
	r = Decode(m, &link, func(wireless.Header) []byte { return key })
	if r.Err != nil || r.Encrypted || len(r.Records) == 0 || !r.Telegram.Encrypted {
		t.Fatalf("mode 5: %v, %d records", r.Err, len(r.Records))
	}
	want, _ := wireless.Decode(frame, wireless.FormatNoCRC, func(wireless.Header) []byte { return key })
	if len(want.Records) != len(r.Records) {
		t.Errorf("%d records over MBAL, %d over wM-Bus", len(r.Records), len(want.Records))
	}
}

// Covers: SIG-IPE-963
func TestBasicCIoTUDP(t *testing.T) {
	// Table C.3: CFh, MBAL-CL, then the TPL CI field and the APL.
	p := append([]byte{0xCF, 0x14}, hx(t, longTPL)...)
	m, err := ParseUDP(p, Uplink)
	if err != nil || !m.WithCI || m.Control.Name() != "SND-NR" || m.Tech != "udp" {
		t.Fatalf("%+v %v", m, err)
	}
	r := Decode(m, nil, nil)
	volume(t, r.Records)
	if _, err := ParseUDP(p[1:], Uplink); !errors.Is(err, ErrNoMBAL) {
		t.Errorf("a UDP payload without CFh: %v", err)
	}
	// Upper layers longer than a wM-Bus frame are still decoded (unencrypted).
	long := append(hx(t, longTPL), bytes.Repeat([]byte{0x2F}, 300)...)
	m, _ = ParseUDP(append([]byte{0xCF, 0x14}, long...), Uplink)
	r = Decode(m, nil, nil)
	if r.Err != nil || r.Meter == nil {
		t.Fatalf("long datagram: %v", r.Err)
	}
	volume(t, r.Records)
}

// Covers: SIG-IPE-964
func TestAESCCMVector(t *testing.T) {
	// RFC 3610 packet vector #1: M = 8, L = 2 (the parameters of
	// AES-CCM-16-64-*), 13-byte nonce, 8 bytes of AAD.
	key := hx(t, "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
	nonce := hx(t, "00000003020100A0A1A2A3A4A5")
	aad := hx(t, "0001020304050607")
	plain := hx(t, "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E")
	want := hx(t, "588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0")
	got, err := ccmSeal(key, nonce, plain, aad, 8)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("seal = % X, %v", got, err)
	}
	back, err := ccmOpen(key, nonce, got, aad, 8)
	if err != nil || !bytes.Equal(back, plain) {
		t.Fatalf("open = % X, %v", back, err)
	}
	got[3] ^= 1
	if _, err := ccmOpen(key, nonce, got, aad, 8); err == nil {
		t.Error("tampered ciphertext opened")
	}
}

// Covers: SIG-IPE-964
func TestAdvancedCIoTCoAP(t *testing.T) {
	tpl := hx(t, longTPL)
	// Figure C.7: POST, T=NON, MID 7D3Dh, payload [{20: {0: 04h, 1: frame}}, FFh].
	content := EncodeCIoT([]Message{{Control: NewUplink(AccessNone, FnSNDNR), Upper: tpl}})
	if content[0] != 0x9F || content[len(content)-1] != 0xFF {
		t.Fatalf("content is not an indefinite-length array: % X", content)
	}
	req := &CoAP{Type: CoAPNON, Code: CoAPPost, MessageID: 0x7D3D, Payload: content}
	dg := req.Marshal()
	if !bytes.Equal(dg[:4], []byte{0x50, 0x02, 0x7D, 0x3D}) {
		t.Fatalf("CoAP header % X, want 50 02 7D 3D", dg[:4])
	}
	back, err := ParseCoAP(dg)
	if err != nil || back.Type != CoAPNON || back.MessageID != 0x7D3D || !bytes.Equal(back.Payload, content) {
		t.Fatalf("ParseCoAP: %+v %v", back, err)
	}
	c, err := ParseCIoT(back.Payload, Uplink, nil)
	if err != nil || c.COSE != nil || len(c.Messages) != 1 {
		t.Fatalf("ParseCIoT: %+v %v", c, err)
	}
	if m := c.Messages[0]; m.Control.Byte() != 0x04 || m.Control.Name() != "SND-NR" || m.Control.Access() != AccessNone {
		t.Errorf("MBAL-CL %v", m.Control)
	}
	volume(t, Decode(&c.Messages[0], nil, nil).Records)

	// Figure C.10: request {0: 23h, 1: frame, 2: 45} downlink, response 18h with the same request ID.
	rid := uint16(45)
	reqC := EncodeCIoT([]Message{{Control: NewDownlink(LatencyASAP, FnSNDUD2), Upper: []byte{0x5B, 0x01}, RequestID: &rid}})
	c, err = ParseCIoT(reqC, Downlink, nil)
	if err != nil || c.Messages[0].Control.Name() != "SND-UD2" || c.Messages[0].Control.Latency() != LatencyASAP ||
		c.Messages[0].RequestID == nil || *c.Messages[0].RequestID != 45 {
		t.Fatalf("C.10 request: %+v %v", c, err)
	}
	// Figure C.11: {20: {0: 37h}} SND-NKE, latency unused, piggy-backed on the ACK with the request's MID.
	con := &CoAP{Type: CoAPCON, Code: CoAPPost, MessageID: 0x7F4C, Payload: content}
	ack := con.Ack(EncodeCIoT([]Message{{Control: NewDownlink(LatencyUnused, FnSNDNKE)}}))
	ab, err := ParseCoAP(ack.Marshal())
	if err != nil || ab.Type != CoAPACK || ab.Code != CoAPChanged || ab.MessageID != 0x7F4C {
		t.Fatalf("ACK: %+v %v", ab, err)
	}
	if c, err = ParseCIoT(ab.Payload, Downlink, nil); err != nil || c.Messages[0].Control.Byte() != 0x37 ||
		c.Messages[0].Control.Name() != "SND-NKE" {
		t.Fatalf("C.11: %+v %v", c, err)
	}
	// Proprietary keys 0-19 are kept apart; a 2-byte MBAL-CL is reserved.
	c, err = ParseCIoT(hx(t, "9F A1 05 43 010203 A1 14 A1 00 14 FF"), Uplink, nil)
	if err != nil || len(c.Proprietary[5]) != 1 || len(c.Messages) != 1 {
		t.Fatalf("proprietary: %+v %v", c, err)
	}
	if _, err := ParseCIoT(hx(t, "9F A1 14 A1 00 19 0114 FF"), Uplink, nil); err == nil {
		t.Error("a 2-byte MBAL-CL was accepted")
	}
	// Options: content format 16 (Table C.8) round-trips.
	req.Options = []CoAPOption{{Number: 12, Value: []byte{16}}}
	back, _ = ParseCoAP(req.Marshal())
	if cf, ok := back.ContentFormat(); !ok || cf != 16 || !bytes.Equal(req.Marshal()[4:6], []byte{0xC1, 0x10}) {
		t.Errorf("content format option: %v %v % X", cf, ok, req.Marshal()[4:6])
	}
	for _, bad := range []string{"", "50", "90020000", "58020000", "500200000D", "50020000FF", "50020000F0"} {
		if _, err := ParseCoAP(hx(t, bad)); err == nil {
			t.Errorf("CoAP % s accepted", bad)
		}
	}
}

// Covers: SIG-IPE-964
func TestCOSEEncrypt0(t *testing.T) {
	tpl := hx(t, longTPL)
	content := EncodeCIoT([]Message{{Control: NewUplink(AccessShort, FnSNDNR), Upper: tpl}})
	dev := hx(t, "2D2C 78563412 01 07") // KAM 12345678 v1 water, as on the link layer
	h := &COSEHeader{ProtocolID: ProtocolMBAL, IDType: 0, Device: dev, PartialIV: hx(t, "000000000001")}
	// Without encryption the protected header is empty (C.4.3.2.6.5).
	clear, err := BuildEncrypt0(h, content, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCIoT(clear, Uplink, nil)
	if err != nil || c.COSE == nil || c.Encrypted || len(c.Messages) != 1 {
		t.Fatalf("clear Encrypt0: %+v %v", c, err)
	}
	if a, ok := c.COSE.Meter(); !ok || a.Key() != "KAM-12345678" {
		t.Errorf("kid meter %v %v", a, ok)
	}
	// AES-CCM-16-64-256 with the nonce of Table C.19.
	key := bytes.Repeat([]byte{0x42}, 32)
	enc, err := BuildEncrypt0(h, content, key)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := COSENonce(h); !bytes.Equal(n, hx(t, "00 2D2C 78563412 000000000001")) {
		t.Errorf("nonce % X", n)
	}
	if _, err := ParseCIoT(enc, Uplink, nil); !errors.Is(err, ErrEncrypted) {
		t.Errorf("no key: %v", err)
	}
	c, err = ParseCIoT(enc, Uplink, func(d []byte) []byte {
		if bytes.Equal(d, dev) {
			return key
		}
		return nil
	})
	if err != nil || !c.Encrypted || len(c.Messages) != 1 || !bytes.Equal(c.Messages[0].Upper, tpl) {
		t.Fatalf("decrypt: %+v %v", c, err)
	}
	if c.COSE.Alg != AlgAESCCM16_64_256 {
		t.Errorf("alg %d", c.COSE.Alg)
	}
	enc[len(enc)-1] ^= 0x80
	if _, err := ParseCIoT(enc, Uplink, func([]byte) []byte { return key }); err == nil {
		t.Error("tampered COSE content accepted")
	}
}

// Covers: SIG-IPE-964
func TestCBORReader(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"00", "0"}, {"17", "23"}, {"1818", "24"}, {"190100", "256"}, {"1A00010000", "65536"},
		{"20", "-1"}, {"3863", "-100"}, {"43010203", "[1 2 3]"}, {"6161", "a"}, {"5F4101420203FF", "[1 2 3]"},
		{"9F0102FF", "[1 2]"}, {"A10102", "map[1:2]"}, {"BF0102FF", "map[1:2]"}, {"D0 80", "{16 []}"},
		{"F4", "false"}, {"F5", "true"}, {"F6", "<nil>"}, {"F93C00", "1"},
	} {
		v, err := cborDecode(hx(t, tc.in))
		if err != nil {
			t.Errorf("%s: %v", tc.in, err)
			continue
		}
		if got := strings.TrimSpace(fmtAny(v)); got != tc.want {
			t.Errorf("%s = %s, want %s", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "18", "43 0102", "9F01", "A101", "1C", "0000", "BF 40 01 FF", "3F",
		strings.Repeat("81", 20) + "00", "9B FFFFFFFFFFFFFFFF", "5F 01 FF"} {
		if _, err := cborDecode(hx(t, bad)); err == nil {
			t.Errorf("CBOR %s accepted", bad)
		}
	}
}

func fmtAny(v any) string {
	switch x := v.(type) {
	case []byte:
		s := "["
		for i, c := range x {
			if i > 0 {
				s += " "
			}
			s += itoa(int(c))
		}
		return s + "]"
	case []any:
		s := "["
		for i, c := range x {
			if i > 0 {
				s += " "
			}
			s += fmtAny(c)
		}
		return s + "]"
	case map[any]any:
		s := "map["
		for k, c := range x {
			s += fmtAny(k) + ":" + fmtAny(c)
		}
		return s + "]"
	case cborTag:
		return "{" + itoa(int(x.Num)) + " " + fmtAny(x.Val) + "}"
	case uint64:
		return itoa(int(x))
	case int64:
		return itoa(int(x))
	case float64:
		return itoa(int(x))
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case nil:
		return "<nil>"
	}
	return "?"
}

func itoa(i int) string {
	if i < 0 {
		return "-" + itoa(-i)
	}
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}

// Covers: SIG-IPE-965
func TestMIOTY(t *testing.T) {
	tpl := hx(t, longTPL)
	// MPF 80h with the MBAL CI field (Table E.3), MPF 83h without it.
	for _, tc := range []struct {
		mpf  byte
		data []byte
		ci   bool
	}{
		{MPFMBus, append([]byte{0xCF, 0x14}, tpl...), true},
		{MPFMBAL, append([]byte{0x14}, tpl...), false},
	} {
		m, err := ParseMIOTY(tc.mpf, tc.data, Uplink)
		if err != nil || !m.HasMBAL || m.WithCI != tc.ci || m.Control.Name() != "SND-NR" || !bytes.Equal(m.Upper, tpl) {
			t.Fatalf("MPF %02X: %+v %v", tc.mpf, m, err)
		}
		volume(t, Decode(m, nil, nil).Records)
	}
	// Figure E.3: SND-UD2 23h downlink, RSP-UD 18h uplink.
	if m, err := ParseMIOTY(MPFMBAL, []byte{0x23, 0x5B}, Downlink); err != nil || m.Control.Name() != "SND-UD2" {
		t.Errorf("E.3 command: %+v %v", m, err)
	}
	if m, err := ParseMIOTY(MPFMBAL, append([]byte{0x18}, tpl...), Uplink); err != nil || m.Control.Name() != "RSP-UD" {
		t.Errorf("E.3 response: %+v %v", m, err)
	}
	// MPF 80h without CFh: M-Bus without MBAL; 81h: records from the DIF.
	m, err := ParseMIOTY(MPFMBus, tpl, Uplink)
	if err != nil || m.HasMBAL || Decode(m, nil, nil).Meter == nil {
		t.Fatalf("MPF 80h without MBAL: %+v %v", m, err)
	}
	m, err = ParseMIOTY(MPFMBusAPL, hx(t, "0C13 78563412"), Uplink)
	if err != nil || m.HasMBAL {
		t.Fatalf("MPF 81h: %+v %v", m, err)
	}
	volume(t, Decode(m, nil, nil).Records)
	if meta := Decode(m, nil, nil).Meta(); meta["mbal"] != nil {
		t.Errorf("81h meta has an MBAL: %v", meta)
	}
	if _, err := ParseMIOTY(0x82, tpl, Uplink); !errors.Is(err, ErrMIOTYMPF) {
		t.Errorf("MPF 82h: %v", err)
	}
}

// Covers: SIG-IPE-966
func TestWize(t *testing.T) {
	tpl := hx(t, longTPL)
	// Table F.5: L6App is CFh, the L7 starts with the MBAL-CL.
	m, err := ParseWize(0xCF, append([]byte{0x14}, tpl...), Uplink)
	if err != nil || !m.WithCI || m.Control.Name() != "SND-NR" || m.Tech != "wize" {
		t.Fatalf("%+v %v", m, err)
	}
	volume(t, Decode(m, nil, nil).Records)
	if _, err := ParseWize(0x20, []byte{0x14}, Uplink); !errors.Is(err, ErrNoMBAL) {
		t.Errorf("L6App 20h: %v", err)
	}
	// A whole L6 frame: 5 header bytes, the L7, 8 trailer bytes.
	frame := append(hx(t, "44 01 0005 CF 14"), tpl...)
	frame = append(frame, make([]byte, 8)...)
	if m, err := ParseWizeL6(frame); err != nil || m.Control.Byte() != 0x14 || !bytes.Equal(m.Upper, tpl) {
		t.Fatalf("L6: %+v %v", m, err)
	}
	if _, err := ParseWizeL6(frame[:10]); err == nil {
		t.Error("short L6 frame accepted")
	}
	// Table F.6: the function code is the Wize DLL C-field's low nibble.
	for _, tc := range []struct {
		c    byte
		d    Direction
		want byte
		name string
	}{
		{0x46, Uplink, 0x06, "SND-IR"},   // INSTPING
		{0x06, Downlink, 0x36, "CNF-IR"}, // INSTPONG
		{0x44, Uplink, 0x14, "SND-NR"},   // DATA
		{0x54, Uplink, 0x14, "SND-NR"},   // DATA, priority
		{0x43, Downlink, 0x33, "SND-UD2"},
		{0x08, Uplink, 0x08, "RSP-UD"}, // RESPONSE
	} {
		if c := WizeControl(tc.c, tc.d); c.Byte() != tc.want || c.Name() != tc.name {
			t.Errorf("C-field %02X %s = %s, want %02X %s", tc.c, tc.d, c, tc.want, tc.name)
		}
	}
}

func FuzzParsers(f *testing.F) {
	f.Add([]byte{0xCF, 0x14, 0x78, 0x0C, 0x13, 1, 2, 3, 4})
	f.Add([]byte{0x50, 0x02, 0x7D, 0x3D, 0xFF, 0x9F, 0xA1, 0x14, 0xA2, 0x00, 0x04, 0x01, 0x41, 0x78, 0xFF})
	f.Fuzz(func(t *testing.T, b []byte) {
		if m, err := ParseUDP(b, Uplink); err == nil {
			Decode(m, nil, nil)
		}
		if c, err := ParseCoAP(b); err == nil {
			c.Marshal()
			if cc, err := ParseCIoT(c.Payload, Uplink, nil); err == nil {
				for i := range cc.Messages {
					Decode(&cc.Messages[i], nil, nil)
				}
			}
		}
		_, _ = cborDecode(b)
	})
}
