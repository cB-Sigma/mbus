package wireless

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/cB-Sigma/mbus/records"
)

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func recordMap(rs []records.Record) map[string]records.Record {
	m := map[string]records.Record{}
	for _, r := range rs {
		m[r.Name()] = r
	}
	return m
}

// omsMode5 is the security mode 5 example telegram of OMS Volume 2 (annex
// N), CRCs removed; its key is 0102…0E0F11.
const (
	omsMode5    = "2E4493157856341233037A2A0020255923C95AAA26D1B2E7493B013EC4A6F6D3529B520EDFF0EA6DEFC99D6D69EBF3"
	omsMode5Key = "0102030405060708090A0B0C0D0E0F11"
)

// Covers: SIG-IPE-200
func TestWMBusLinkLayer(t *testing.T) {
	// The CRC is CRC-16/EN-13757: its catalogue check value.
	if got := CRC([]byte("123456789")); got != 0xC2B7 {
		t.Fatalf("CRC(123456789) = %04X, want C2B7", got)
	}
	plain := hx(t, omsMode5)
	for _, tc := range []struct {
		name   string
		frame  []byte
		format FrameFormat
	}{
		{"format A", AddCRCA(plain), FormatA},
		{"format B", AddCRCB(plain), FormatB},
		{"no CRC", plain, FormatNoCRC},
	} {
		got, f, err := StripCRC(tc.frame, FormatAuto)
		if err != nil || f != tc.format || !bytes.Equal(got, plain) {
			t.Errorf("%s: auto detection gave %s, %v, equal=%v", tc.name, f, err, bytes.Equal(got, plain))
		}
		if got, _, err := StripCRC(tc.frame, tc.format); err != nil || !bytes.Equal(got, plain) {
			t.Errorf("%s: explicit format: %v", tc.name, err)
		}
	}
	// Format A: 47 bytes carry 1 + ceil(37/16) = 4 CRCs.
	if n := len(AddCRCA(plain)); n != 47+8 || FrameLenA(0x2E) != n {
		t.Errorf("format A length %d, FrameLenA %d, want 55", n, FrameLenA(0x2E))
	}
	// Long format B frame: two CRCs, one over the first 126 bytes.
	long := append([]byte{0}, bytes.Repeat([]byte{0x2F}, 150)...)
	copy(long[1:], plain[1:11])
	long[0] = byte(len(long) - 1)
	fb := AddCRCB(long)
	if int(fb[0]) != len(fb)-1 || len(fb) != len(long)+4 {
		t.Errorf("long format B: L=%d len=%d", fb[0], len(fb))
	}
	if got, _, err := StripCRC(fb, FormatB); err != nil || !bytes.Equal(got, long) {
		t.Errorf("long format B round trip: %v", err)
	}
	// Any flipped bit fails the CRC.
	bad := AddCRCA(plain)
	bad[20] ^= 0x01
	if _, _, err := StripCRC(bad, FormatA); !errors.Is(err, ErrCRC) {
		t.Errorf("corrupted format A frame: %v, want ErrCRC", err)
	}
	bad = AddCRCB(plain)
	bad[30] ^= 0x80
	if _, _, err := StripCRC(bad, FormatB); !errors.Is(err, ErrCRC) {
		t.Errorf("corrupted format B frame: %v, want ErrCRC", err)
	}
	// Link-layer header.
	h, err := ParseHeader(plain)
	if err != nil {
		t.Fatal(err)
	}
	if h.Manufacturer != "ELS" || h.ID != "12345678" || h.Version != 0x33 || h.DeviceType != 0x03 || h.Medium() != "gas" || h.C != 0x44 {
		t.Errorf("header = %+v", h)
	}
	if m, _ := records.ManufacturerField("KAM"); m != 0x2C2D || records.ManufacturerCode(0x2C2D) != "KAM" {
		t.Errorf("KAM = %04X", m)
	}
	// Mode T: 3-out-of-6 code, 0x00 → 010110 010110.
	if got := Encode3of6([]byte{0x00}); !bytes.Equal(got, []byte{0x59, 0x60}) {
		t.Errorf("3of6(00) = %X, want 5960 (010110 010110 + padding)", got)
	}
	chips := Encode3of6(plain)
	if len(chips) != (len(plain)*12+7)/8 {
		t.Errorf("3of6 length %d for %d bytes", len(chips), len(plain))
	}
	if back, err := Decode3of6(chips); err != nil || !bytes.Equal(back, plain) {
		t.Errorf("3of6 round trip: %v", err)
	}
	if _, err := Decode3of6([]byte{0xFF, 0xFF}); err == nil {
		t.Error("111111 decoded as a code word")
	}
}

// Covers: SIG-IPE-201
func TestWMBusSecurityMode5(t *testing.T) {
	key := hx(t, omsMode5Key)
	keys := func(h Header) []byte {
		if h.ID == "12345678" && h.Manufacturer == "ELS" {
			return key
		}
		return nil
	}
	for _, frame := range [][]byte{hx(t, omsMode5), AddCRCA(hx(t, omsMode5))} {
		tg, err := Decode(frame, FormatAuto, keys)
		if err != nil {
			t.Fatal(err)
		}
		if tg.HeaderKind != "short" || tg.Access != 0x2A || tg.Mode != 5 || !tg.Encrypted {
			t.Errorf("TPL = %s acc %X mode %d encrypted %v", tg.HeaderKind, tg.Access, tg.Mode, tg.Encrypted)
		}
		m := recordMap(tg.Records)
		if r := m["volume"]; r.Value != 28504.27 || r.Unit != "m3" {
			t.Errorf("volume = %v %s, want 28504.27 m3", r.Value, r.Unit)
		}
		if r := m["datetime"]; r.Value != "2008-05-31T23:50:00" {
			t.Errorf("datetime = %v", r.Value)
		}
		if r := m["error_flags"]; r.Value != "0000" {
			t.Errorf("error flags = %v", r.Value)
		}
	}
	if _, err := Decode(hx(t, omsMode5), FormatNoCRC, nil); !errors.Is(err, ErrNoKey) {
		t.Errorf("without a key: %v, want ErrNoKey", err)
	}
	wrong := func(Header) []byte { return hx(t, "00000000000000000000000000000000") }
	if _, err := Decode(hx(t, omsMode5), FormatNoCRC, wrong); !errors.Is(err, ErrDecrypt) {
		t.Errorf("wrong key: %v, want ErrDecrypt", err)
	}
	// Our own encrypted telegram with a long header: the IV uses the TPL's
	// meter address, not the repeater's link address.
	apl := append(hx(t, "2F2F 0413 39300000 02FD170000"), bytes.Repeat([]byte{0x2F}, 32)...)[:32]
	tg := &Telegram{Access: 0x11}
	m := Header{MField: 0x2C2D, Version: 0x1B, DeviceType: 0x16}
	copy(m.A[:], []byte{0x21, 0x43, 0x65, 0x87, 0x1B, 0x16})
	tg.Meter = m
	enc, _ := cbcEncrypt(key, tg.Mode5IV(), apl)
	frame := hx(t, "00 44 2D2C 99999999 01 32") // a repeater
	frame = append(frame, 0x72, 0x21, 0x43, 0x65, 0x87, 0x2D, 0x2C, 0x1B, 0x16, 0x11, 0x00, 0x20, 0x05)
	frame = append(frame, enc...)
	frame[0] = byte(len(frame) - 1)
	got, err := Decode(frame, FormatNoCRC, func(h Header) []byte {
		if h.ID == "87654321" {
			return key
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Meter.Key() != "KAM-87654321" || got.Header.Key() != "KAM-99999999" || got.Meter.Medium() != "cold water" {
		t.Errorf("meter %s via %s (%s)", got.Meter.Key(), got.Header.Key(), got.Meter.Medium())
	}
	if r := recordMap(got.Records)["volume"]; r.Value != 12.345 {
		t.Errorf("volume = %v, want 12.345", r.Value)
	}
}

// Covers: SIG-IPE-202
func TestWMBusSecurityMode7(t *testing.T) {
	// AES-CMAC, RFC 4493 section 4 examples.
	k := hx(t, "2b7e151628aed2a6abf7158809cf4f3c")
	msg := hx(t, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	for n, want := range map[int]string{0: "bb1d6929e95937287fa37d129b756746", 16: "070a16b46b4d4144f79bdd9dd04a287c",
		40: "dfa66747de9ae63030ca32611497c827", 64: "51f0bebf7e3b9d92fc49741779363cfe"} {
		got, _ := CMAC(k, msg[:n])
		if hex.EncodeToString(got) != want {
			t.Errorf("CMAC of %d bytes = %x, want %s", n, got, want)
		}
	}
	master := hx(t, "000102030405060708090A0B0C0D0E0F")
	frame := mode7Telegram(t, master, 0x00000102, false)
	keys := func(Header) []byte { return master }
	tg, err := Decode(frame, FormatNoCRC, keys)
	if err != nil {
		t.Fatal(err)
	}
	if tg.Mode != 7 || !tg.Encrypted || tg.AFL == nil || tg.AFL.Counter != 0x102 || len(tg.AFL.MAC) != 8 {
		t.Errorf("mode %d encrypted %v AFL %+v", tg.Mode, tg.Encrypted, tg.AFL)
	}
	if r := recordMap(tg.Records)["energy"]; r.Value != 1234.567 || r.Unit != "Wh" {
		t.Errorf("energy = %v %s", r.Value, r.Unit)
	}
	// A changed ciphertext byte, a wrong master key, a replayed MAC under a
	// different counter: all refused.
	bad := append([]byte(nil), frame...)
	bad[len(bad)-3] ^= 1
	if _, err := Decode(bad, FormatNoCRC, keys); !errors.Is(err, ErrMAC) {
		t.Errorf("changed ciphertext: %v, want ErrMAC", err)
	}
	if _, err := Decode(frame, FormatNoCRC, func(Header) []byte { return hx(t, omsMode5Key) }); !errors.Is(err, ErrMAC) {
		t.Errorf("wrong key: %v, want ErrMAC", err)
	}
	replay := append([]byte(nil), frame...)
	replay[15]++ // the AFL message counter's low byte
	if _, err := Decode(replay, FormatNoCRC, keys); !errors.Is(err, ErrMAC) {
		t.Errorf("changed counter: %v, want ErrMAC", err)
	}
	// ELL with AES-CTR (CI 0x8D) around an unencrypted TPL.
	ell := ellTelegram(t, master)
	tg, err = Decode(ell, FormatNoCRC, keys)
	if err != nil {
		t.Fatal(err)
	}
	if tg.ELL == nil || !tg.Encrypted || recordMap(tg.Records)["volume"].Value != 3.5 {
		t.Errorf("ELL telegram: %+v %+v", tg.ELL, tg.Records)
	}
	ell[len(ell)-1] ^= 0x55
	if _, err := Decode(ell, FormatNoCRC, keys); !errors.Is(err, ErrDecrypt) {
		t.Errorf("changed ELL payload: %v, want ErrDecrypt", err)
	}
	// The payload CRC low byte first, as Kamstrup meters send it (seen in
	// the decrypted telegrams of wmbusmeters' test data).
	if tg, err := Decode(ellTelegramCRC(t, master, true), FormatNoCRC, keys); err != nil || recordMap(tg.Records)["volume"].Value != 3.5 {
		t.Errorf("ELL payload CRC low byte first: %v", err)
	}
}

// mode7Telegram builds a mode 7 telegram: link header, AFL (MCL, counter,
// 8-byte MAC), short TPL with configuration field extension (KDF-A), and
// two encrypted blocks.
func mode7Telegram(t *testing.T, master []byte, counter uint32, _ bool) []byte {
	t.Helper()
	id := [4]byte{0x78, 0x56, 0x34, 0x12}
	kenc, _ := DeriveKey(master, DCEncMeter, counter, id)
	kmac, _ := DeriveKey(master, DCMACMeter, counter, id)
	apl := append(hx(t, "2F2F 0C00 67452301"), bytes.Repeat([]byte{0x2F}, 24)...) // BCD8 energy 1234567 mWh
	enc, _ := cbcEncrypt(kenc, make([]byte, 16), apl)
	tpl := append([]byte{0x7A, 0x33, 0x00, 0x20, 0x07, 0x10}, enc...)
	var mcr [4]byte
	binary.LittleEndian.PutUint32(mcr[:], counter)
	mcl := byte(0x05)
	mac, _ := CMAC(kmac, append(append([]byte{mcl}, mcr[:]...), tpl...))
	afl := []byte{0x90, 15, 0x00, 0x2C, mcl}
	afl = append(append(afl, mcr[:]...), mac[:8]...)
	frame := append(hx(t, "00 44 2D2C 78563412 01 02"), afl...)
	frame = append(frame, tpl...)
	frame[0] = byte(len(frame) - 1)
	return frame
}

func ellTelegram(t *testing.T, key []byte) []byte { return ellTelegramCRC(t, key, false) }

// ellTelegramCRC builds the ELL telegram with its payload CRC high byte
// first or, lowFirst, low byte first (as Kamstrup meters send it).
func ellTelegramCRC(t *testing.T, key []byte, lowFirst bool) []byte {
	t.Helper()
	hdr := hx(t, "00 44 2D2C 78563412 01 07")
	cc, sn := byte(0x20), uint32(1<<29|0x1234)
	payload := hx(t, "78 0413 AC0D0000") // no TPL header; volume 3.5 m3 (3500 l)
	crc := CRC(payload)
	plain := append([]byte{byte(crc >> 8), byte(crc)}, payload...)
	if lowFirst {
		plain[0], plain[1] = byte(crc), byte(crc>>8)
	}
	iv := make([]byte, 16)
	copy(iv[0:2], hdr[2:4])
	copy(iv[2:8], hdr[4:10])
	iv[8] = cc
	binary.LittleEndian.PutUint32(iv[9:13], sn)
	enc, _ := ctrXOR(key, iv, plain)
	frame := append(hdr, 0x8D, cc, 0x00)
	frame = binary.LittleEndian.AppendUint32(frame, sn)
	frame = append(frame, enc...)
	frame[0] = byte(len(frame) - 1)
	return frame
}

// Covers: SIG-IPE-203
func TestWMBusDataRecords(t *testing.T) {
	// The variable data response example of the M-Bus documentation (EN
	// 13757-3 style), carried here with a wireless link header: long TPL
	// header, then a BCD volume, a maximum volume flow in storage 5, and
	// an energy in tariff 2, subunit 1.
	frame := append(hx(t, "00 44 2440 78563412 01 07"),
		hx(t, "72 78563412 2440 01 07 55 00 0000 0313153100 DA023B1301 8B60043718 02")...)
	frame[0] = byte(len(frame) - 1)
	tg, err := Decode(frame, FormatNoCRC, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tg.Meter.Manufacturer != "PAD" || tg.Access != 0x55 || tg.Meter.Medium() != "water" {
		t.Errorf("meter %+v access %X", tg.Meter, tg.Access)
	}
	m := recordMap(tg.Records)
	want := map[string][2]any{
		"volume":             {12.565, "m3"},
		"volume_flow_max_s5": {0.113, "m3/h"},
		"energy_t2_u1":       {218370.0, "Wh"},
	}
	if len(m) != len(want) {
		t.Errorf("records %v", tg.Records)
	}
	for name, w := range want {
		if r, ok := m[name]; !ok || r.Value != w[0] || r.Unit != w[1] {
			t.Errorf("%s = %v %s, want %v %s (have %v)", name, r.Value, r.Unit, w[0], w[1], keysOf(m))
		}
	}
	// Types and tables.
	rs, err := records.ParseRecords(hx(t, strings.Join([]string{
		"01 FD1B 05",           // int8 digital input: hex
		"02 5A 9CFF",           // int16 flow temperature, -100 × 0.1 = -10.0 °C
		"04 2B 10270000",       // int32 power, 10000 W at 10^0
		"05 13 0000C03F",       // real32 1.5 × 10^-3 m3
		"0A 64 3412",           // BCD4 external temperature 1234 × 0.001
		"0C 13 785634F1",       // negative BCD8 (F in the top nibble)
		"42 6C 7F2C",           // date type G, storage 1
		"84 10 13 D2040000",    // DIFE: tariff 1; volume 1.234
		"C4 C1 01 13 01000000", // DIFE chain: storage 1|2<<1|4<<5…, subunit 1
		"04 93 3B 64000000",    // volume with a VIFE "accumulation only if positive"
		"04 94 72 64000000",    // VIFE multiplicative correction 10^-4
		"02 FD 48 E600",        // voltage 230 V at 10^-1
		"0D FD0C 03 434241",    // LVAR text "ABC" (reversed on the wire)
		"0D 13 C2 3412",        // LVAR positive BCD
		"0F 0102AB",            // manufacturer data to the end
	}, "")))
	if err != nil {
		t.Fatal(err)
	}
	get := func(i int) records.Record { return rs[i] }
	checks := []struct {
		i    int
		name string
		v    any
	}{
		{0, "digital_input", "05"},
		{1, "flow_temperature", -10.0},
		{2, "power", int64(10000)},
		{3, "volume", 0.0015},
		{4, "external_temperature", 1.234},
		{5, "volume", -1345.678},
		{6, "date_s1", "2019-12-31"},
		{7, "volume_t1", 1.234},
		{8, "volume_s35_u1", 0.001},
		{9, "volume_forward", 0.1},
		{10, "volume", 0.0001},
		{11, "voltage", 23.0},
		{12, "model_version", "ABC"},
		{13, "volume", 1.234},
		{14, "manufacturer_data", "0102AB"},
	}
	for _, c := range checks {
		if c.i >= len(rs) {
			t.Fatalf("only %d records", len(rs))
		}
		r := get(c.i)
		if r.Name() != c.name || !reflect.DeepEqual(r.Value, c.v) {
			t.Errorf("record %d = %s %v (%T), want %s %v", c.i, r.Name(), r.Value, r.Value, c.name, c.v)
		}
	}
	// Truncated records are errors, not panics.
	for _, b := range []string{"04", "0413", "041301", "84", "0D13", "0D13C5", "04FD", "04FC"} {
		if _, err := records.ParseRecords(hx(t, b)); err == nil {
			t.Errorf("%s: no error for a truncated record", b)
		}
	}
}

func keysOf(m map[string]records.Record) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Covers: SIG-IPE-204
func TestWMBusReceiverFraming(t *testing.T) {
	tel := hx(t, omsMode5)
	// iM871A: radio-link message indication with RSSI and CRC, after noise
	// and a device-management message that is skipped.
	im := func(ctl byte, msg byte, payload []byte, rssi byte) []byte {
		b := []byte{ctl, msg, byte(len(payload))}
		b = append(b, payload...)
		if ctl&IM871ARSSI != 0 {
			b = append(b, rssi)
		}
		if ctl&IM871ACRC != 0 {
			c := CRCX25(b)
			b = append(b, byte(c), byte(c>>8))
		}
		return append([]byte{IM871ASOF}, b...)
	}
	var stream []byte
	stream = append(stream, 0x00, 0x13)
	stream = append(stream, im(0x01, 0x02, []byte{1, 2, 3}, 0)...) // devmgmt: skipped
	bad := im(0x02|IM871ACRC, IM871AMsgInd, tel[1:], 0)
	bad[len(bad)-1] ^= 0xFF // CRC error: skipped
	stream = append(stream, bad...)
	stream = append(stream, im(0x02|IM871ARSSI|IM871ACRC, IM871AMsgInd, tel[1:], 0xB4)...)
	r := bufio.NewReader(bytes.NewReader(stream))
	got, err := ReadIM871A(r, false)
	if err != nil || !bytes.Equal(got.Frame, tel) || got.RSSI == nil || *got.RSSI != 0xB4 {
		t.Errorf("im871a: %v %X rssi %v", err, got.Frame, got.RSSI)
	}
	// CRCX25's catalogue check value.
	if c := CRCX25([]byte("123456789")); c != 0x906E {
		t.Errorf("CRC-16/X-25 check = %04X, want 906E", c)
	}
	// Amber command mode with RSSI byte and XOR checksum.
	amb := func(payload []byte) []byte {
		b := append([]byte{AmberStart, AmberDataInd, byte(len(payload))}, payload...)
		var cs byte
		for _, x := range b {
			cs ^= x
		}
		return append(b, cs)
	}
	stream = append([]byte{0x55}, amb(append(append([]byte(nil), tel[1:]...), 0xC8))...)
	got, err = ReadAmber(bufio.NewReader(bytes.NewReader(stream)), false, true)
	if err != nil || !bytes.Equal(got.Frame, tel) || got.RSSI == nil || *got.RSSI != 0xC8 {
		t.Errorf("amber: %v %X", err, got.Frame)
	}
	// Raw L framing, with CRCs in format A.
	got, err = ReadRaw(bufio.NewReader(bytes.NewReader(AddCRCA(tel))), FormatA)
	if err != nil || !bytes.Equal(got.Frame, AddCRCA(tel)) {
		t.Errorf("raw A: %v", err)
	}
	// Hex lines as rtl-wmbus-style tools print them.
	got, err = ParseHexLine("T1;1;1;2026-09-01 10:00:00.000;97;148;12345678;0x" + omsMode5 + "\n")
	if err != nil || got.LinkMode != "T1" || !bytes.Equal(got.Frame, tel) {
		t.Errorf("hex line: %v %s", err, got.LinkMode)
	}
	if _, err := ParseHexLine("hello world"); err == nil {
		t.Error("a line without a telegram parsed")
	}
}
