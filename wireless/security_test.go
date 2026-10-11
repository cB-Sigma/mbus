package wireless

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/cB-Sigma/mbus/records"
)

// Known-answer tests of the primitives the 2025 security modes use.
//
// Covers: SIG-IPE-918, SIG-SEC-686
func TestWMBusCryptoPrimitives(t *testing.T) {
	// AES-CCM: RFC 3610 packet vector #1 (13-byte nonce, 2-byte length,
	// 8-byte tag: the parameters of security mode 10 with an 8-byte tag).
	key := hx(t, "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
	nonce := hx(t, "00000003020100A0A1A2A3A4A5")
	aad := hx(t, "0001020304050607")
	plain := hx(t, "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E")
	got, err := ccm(key, nonce, aad, plain, 8, false)
	if err != nil || hex.EncodeToString(got) != "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0" {
		t.Fatalf("CCM seal = %x, %v", got, err)
	}
	back, err := ccm(key, nonce, aad, got, 8, true)
	if err != nil || !bytes.Equal(back, plain) {
		t.Fatalf("CCM open: %v", err)
	}
	got[3] ^= 1
	if _, err := ccm(key, nonce, aad, got, 8, true); !errors.Is(err, ErrMAC) {
		t.Errorf("CCM tampered: %v", err)
	}
	// AES-GCM: the SP 800-38D / McGrew–Viega test cases 1 and 2.
	zero := make([]byte, 16)
	if _, tag, _ := gcmSeal(zero, make([]byte, 12), nil, nil, 16); hex.EncodeToString(tag) != "58e2fccefa7e3061367f1d57a4e7455a" {
		t.Errorf("GCM case 1 tag %x", tag)
	}
	ct, tag, _ := gcmSeal(zero, make([]byte, 12), nil, zero, 12)
	if hex.EncodeToString(ct) != "0388dace60b6a392f328c2b971b2fe78" || hex.EncodeToString(tag) != "ab6e47d42cec13bdf53a67b2" {
		t.Errorf("GCM case 2: %x %x", ct, tag)
	}
	if p, err := gcmOpen(zero, make([]byte, 12), nil, ct, tag); err != nil || !bytes.Equal(p, zero) {
		t.Errorf("GCM open with a 12-byte tag: %v", err)
	}
	if _, err := gcmOpen(zero, make([]byte, 12), []byte{1}, ct, tag); !errors.Is(err, ErrMAC) {
		t.Errorf("GCM with changed AAD: %v", err)
	}
	// AES key wrap W: RFC 3394 4.1 (128-bit KEK, 128-bit key).
	blk, _ := aes.NewCipher(hx(t, "000102030405060708090A0B0C0D0E0F"))
	w := kwW(blk, hx(t, "A6A6A6A6A6A6A6A6"), hx(t, "00112233445566778899AABBCCDDEEFF"))
	if hex.EncodeToString(w) != "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5" {
		t.Errorf("KW = %x", w)
	}
	// KWP (the SITP wrapping): RFC 5649 section 6, both vectors.
	kek := hx(t, "5840DF6E29B02AF1AB493B705BF16EA1AE8338F4DCC176A8")
	for _, v := range []struct{ plain, wrapped string }{
		{"C37B7E6492584340BED12207808941155068F738", "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"},
		{"466F7250617369", "afbeb0f07dfbf5419200f2ccb50bb24f"},
	} {
		w, err := KWPWrap(kek, hx(t, v.plain))
		if err != nil || hex.EncodeToString(w) != v.wrapped {
			t.Errorf("KWP(%s) = %x, %v", v.plain, w, err)
		}
		p, err := KWPUnwrap(kek, w)
		if err != nil || !bytes.Equal(p, hx(t, v.plain)) {
			t.Errorf("KWP unwrap: %v", err)
		}
		w[5] ^= 1
		if _, err := KWPUnwrap(kek, w); err == nil {
			t.Error("KWP unwrap of a changed blob succeeded")
		}
	}
}

// testMeter is the meter of the frames built here.
func testMeter(t *testing.T) Header {
	t.Helper()
	m, _ := records.ManufacturerField("ABC")
	h := Header{MField: m, Version: 0x01, DeviceType: 0x07, A: [6]byte{0x78, 0x56, 0x34, 0x12, 0x01, 0x07}}
	h.Manufacturer, h.ID = "ABC", "12345678"
	return h
}

// linkFrame puts a link header (C 44h, SND-NR) in front of a TPDU and sets L.
func linkFrame(m Header, rest []byte) []byte {
	b := []byte{0, 0x44}
	b = binary.LittleEndian.AppendUint16(b, m.MField)
	b = append(append(b, m.A[:]...), rest...)
	b[0] = byte(len(b) - 1)
	return b
}

// sampleAPL is a volume record (13 kg? no: 12.345 m³, DIF 04 VIF 13).
var sampleAPL = []byte{0x04, 0x13, 0x39, 0x30, 0x00, 0x00}

func flip(b []byte, i int) []byte {
	c := append([]byte(nil), b...)
	c[i] ^= 0x01
	return c
}

// Covers: SIG-IPE-904
func TestWMBusMode5NBlocks(t *testing.T) {
	m := testMeter(t)
	key := hx(t, "000102030405060708090A0B0C0D0E0F")
	keys := func(Header) []byte { return key }
	// NNNN = 0: nothing is encrypted (clause 7.6.5), the data is plain.
	tpl := binary.LittleEndian.AppendUint16([]byte{CIShortHeader, 0x11, 0x00}, 0x0500)
	tpl = append(tpl, sampleAPL...)
	tg, err := Decode(linkFrame(m, tpl), FormatNoCRC, keys)
	if err != nil || tg.Encrypted || tg.Mode != 5 || len(tg.Records) != 1 {
		t.Fatalf("mode 5 with NNNN=0: %v enc=%v records=%d", err, tg.Encrypted, len(tg.Records))
	}
	// Two blocks encrypted, unencrypted data after them.
	sealed, err := SealTPL(CIShortHeader, false, m, 0x12, 0, 0, Seal{Mode: 5, Key: key, Unencrypted: sampleAPL}, sampleAPL)
	if err != nil {
		t.Fatal(err)
	}
	tg, err = Decode(linkFrame(m, sealed), FormatNoCRC, keys)
	if err != nil || !tg.Encrypted || len(tg.Records) != 2 || tg.Sec.UnencryptedLen != len(sampleAPL) {
		t.Fatalf("mode 5 partial encryption: %v %+v", err, tg.Sec)
	}
	if _, err := Decode(linkFrame(m, flip(sealed, 6)), FormatNoCRC, keys); !errors.Is(err, ErrDecrypt) {
		t.Errorf("changed ciphertext: %v", err)
	}
}

// Covers: SIG-IPE-905, SIG-IPE-901, SIG-IPE-909
func TestWMBusMode7Fields(t *testing.T) {
	m := testMeter(t)
	master := hx(t, "000102030405060708090A0B0C0D0E0F")
	keys := func(Header) []byte { return master }
	for _, tc := range []struct {
		name string
		s    Seal
	}{
		{"TPL counter, key version, padding", Seal{Mode: 7, Key: master, KDF: 1, KeyID: 3, KeyVersion: 9, Counter: 0x1234, CounterInTPL: true, Padding: true}},
		{"persistent key, no padding", Seal{Mode: 7, Key: master, KDF: 0, KeyVersion: -1, Counter: 5, CounterInTPL: true}},
	} {
		tpdu, err := SealTPL(CIShortHeader, false, m, 0x20, 0, 0, tc.s, sampleAPL)
		if err != nil {
			t.Fatal(err)
		}
		tg, err := Decode(linkFrame(m, tpdu), FormatNoCRC, keys)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		s := tg.Sec
		if s.KeyID != tc.s.KeyID || s.KeyVersion != tc.s.KeyVersion || s.KDF != tc.s.KDF || s.Counter != tc.s.Counter || s.CounterFrom != "tpl" || len(tg.Records) != 1 {
			t.Errorf("%s: %+v records %d", tc.name, s, len(tg.Records))
		}
		// The padding is removed: 2F2F and the record only.
		if !bytes.Equal(tg.APL, append([]byte{0x2F, 0x2F}, sampleAPL...)) && tc.s.Padding {
			t.Errorf("%s: APL %X", tc.name, tg.APL)
		}
	}
	// KDF selections 10b and 11b are reserved (table 26).
	tpdu, _ := SealTPL(CIShortHeader, false, m, 0x20, 0, 0, Seal{Mode: 7, Key: master, KDF: 1, KeyVersion: -1, Counter: 8, CounterInTPL: true}, sampleAPL)
	res := append([]byte(nil), tpdu...)
	res[5] = res[5]&0xCF | 0x20
	if _, err := Decode(linkFrame(m, res), FormatNoCRC, keys); !errors.Is(err, ErrUnsupport) {
		t.Errorf("KDF 10b: %v", err)
	}
	// Lenc and Lmac (partner to meter) differ from Kenc and Kmac.
	ke, km, _ := SessionKeys(master, 1, 8, m, false)
	le, lm, _ := SessionKeys(master, 1, 8, m, true)
	if bytes.Equal(ke, le) || bytes.Equal(km, lm) || bytes.Equal(ke, km) {
		t.Error("the four KDF-A keys are not distinct")
	}
	// With KDF-A and neither a TPL nor an AFL counter the key cannot be
	// derived.
	tpdu, _ = SealTPL(CIShortHeader, false, m, 0x20, 0, 0, Seal{Mode: 7, Key: master, KDF: 1, KeyVersion: -1, Counter: 7}, sampleAPL)
	if _, err := Decode(linkFrame(m, tpdu), FormatNoCRC, keys); err == nil {
		t.Error("mode 7 KDF-A without a counter decoded")
	}
	// The same TPL behind an AFL with the counter and an 8-byte CMAC; the
	// key information field enters the MAC (clause 9.3.2).
	ki := uint16(0x0913) // version 9, KDF-A, key 3
	s := Seal{Mode: 7, Key: master, KDF: 1, KeyID: 3, KeyVersion: -1, Counter: 77}
	tpdu, _ = SealTPL(CIShortHeader, false, m, 0x21, 0, 0, s, sampleAPL)
	framed, err := SealAFL(tpdu, m, master, 1, 77, 5, &ki, false)
	if err != nil {
		t.Fatal(err)
	}
	tg, err := Decode(linkFrame(m, framed), FormatNoCRC, keys)
	if err != nil || tg.Sec.CounterFrom != "afl" || !contains(tg.Sec.Verified, "afl-cmac") || tg.AFL.KI != ki {
		t.Fatalf("mode 7 with AFL CMAC: %v %+v", err, tg.Sec)
	}
	// Every byte of the MAC input matters: MCL, KI, MCR and the TPDU.
	for _, i := range []int{4, 5, 7, 12, len(framed) - 1} {
		if _, err := Decode(linkFrame(m, flip(framed, i)), FormatNoCRC, keys); !errors.Is(err, ErrMAC) && !errors.Is(err, ErrUnsupport) {
			t.Errorf("AFL byte %d changed: %v", i, err)
		}
	}
	// The MAC over MCL||MCR||TPDU without KI (the old input order) does not
	// verify when a KI is present.
	withoutKI := &AFL{MCL: 0x35, Counter: 77}
	withoutKI.has.mcl, withoutKI.has.mcr = true, true
	_, kmac, _ := SessionKeys(master, 1, 77, m, false)
	old, _ := CMAC(kmac, append(withoutKI.macInput(), tpdu...))
	if bytes.Equal(old[:8], framed[11:19]) {
		t.Error("the AFL MAC does not cover KI")
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Covers: SIG-IPE-902
func TestWMBusAFLGMAC(t *testing.T) {
	m := testMeter(t)
	master := hx(t, "0F0E0D0C0B0A09080706050403020100")
	keys := func(Header) []byte { return master }
	tpdu, _ := SealTPL(CIShortHeader, false, m, 0x30, 0, 0, Seal{Mode: 7, Key: master, KDF: 1, KeyVersion: -1, Counter: 1000}, sampleAPL)
	framed, err := SealAFL(tpdu, m, master, 1, 1000, 8, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if framed[1] != 2+1+4+12 {
		t.Errorf("AFLL %d, want 19 (FCL, MCL, MCR, 12-byte GMAC)", framed[1])
	}
	tg, err := Decode(linkFrame(m, framed), FormatNoCRC, keys)
	if err != nil || !contains(tg.Sec.Verified, "afl-gmac") || len(tg.Records) != 1 {
		t.Fatalf("AFL GMAC: %v %+v", err, tg.Sec)
	}
	if _, err := Decode(linkFrame(m, flip(framed, len(framed)-3)), FormatNoCRC, keys); !errors.Is(err, ErrMAC) {
		t.Errorf("changed TPDU under GMAC: %v", err)
	}
	// A reserved authentication type is refused.
	bad := append([]byte(nil), framed...)
	bad[4] = bad[4]&0xF0 | 0x09
	if _, err := Decode(linkFrame(m, bad), FormatNoCRC, keys); !errors.Is(err, ErrUnsupport) {
		t.Errorf("AT 9: %v", err)
	}
}

// Covers: SIG-IPE-906
func TestWMBusMode8(t *testing.T) {
	m := testMeter(t)
	master := hx(t, "2B7E151628AED2A6ABF7158809CF4F3C")
	mac2 := hx(t, "000102030405060708090A0B0C0D0E0F")
	ts := uint32(65757600) & 0xFFFFFF // 2015-02-01 02:00, clause 7.7.6's example
	if ts != 0xEB61A0 {
		t.Fatalf("time stamp example %X", ts)
	}
	for _, tc := range []struct {
		name string
		s    Seal
		long bool
	}{
		{"KDF-A, 4-byte counter, short header", Seal{Mode: 8, Key: master, KDF: 1, KeyID: 2, KeyVersion: -1, Counter: 369}, false},
		{"persistent key, 2-byte counter, unencrypted part, key version", Seal{Mode: 8, Key: master, KeyVersion: 4, Counter: 0x0102, CounterSize: 2, Unencrypted: sampleAPL}, false},
		{"MAC_2 and time stamp, long header", Seal{Mode: 8, Key: master, KDF: 1, KeyVersion: -1, Counter: 370, CounterSize: 3, MAC2Key: mac2, Timestamp: &ts}, true},
	} {
		ci := CIShortHeader
		if tc.long {
			ci = CILongHeader
		}
		tpdu, err := SealTPL(ci, tc.long, m, 0x40, 0x00, 0, tc.s, sampleAPL)
		if err != nil {
			t.Fatal(err)
		}
		frame := linkFrame(m, tpdu)
		d := &Decoder{MAC2Key: func(Header) []byte { return mac2 }}
		tg, err := d.Decode(frame, FormatNoCRC, func(Header) []byte { return master })
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if tg.Mode != 8 || !contains(tg.Sec.Verified, "mac1") || tg.Sec.Counter != tc.s.Counter || len(tg.Records) != 1+len(tc.s.Unencrypted)/6 {
			t.Errorf("%s: %+v records %d", tc.name, tg.Sec, len(tg.Records))
		}
		if tc.s.Timestamp != nil && (!contains(tg.Sec.Verified, "mac2") || tg.Sec.Timestamp == nil || *tg.Sec.Timestamp != ts) {
			t.Errorf("%s: MAC_2 / time stamp %+v", tc.name, tg.Sec)
		}
		// Without Kmac_2 the MAC_2 is reported, not trusted.
		if tc.s.Timestamp != nil {
			tg, err := Decode(frame, FormatNoCRC, func(Header) []byte { return master })
			if err != nil || !contains(tg.Sec.Unverified, "mac2") {
				t.Errorf("%s without Kmac_2: %v %+v", tc.name, err, tg.Sec)
			}
			// A changed time stamp breaks MAC_2 only.
			bad := flip(frame, len(frame)-3)
			d := &Decoder{MAC2Key: d.MAC2Key}
			if _, err := d.Decode(bad, FormatNoCRC, func(Header) []byte { return master }); !errors.Is(err, ErrMAC) {
				t.Errorf("%s: changed time stamp: %v", tc.name, err)
			}
		}
		// Tamper: ciphertext, counter and MAC_1.
		trailer := 4
		if tc.s.Timestamp != nil {
			trailer = 9
		}
		for _, i := range []int{len(frame) - trailer - 1, len(frame) - trailer} {
			if _, err := Decode(flip(frame, i), FormatNoCRC, func(Header) []byte { return master }); !errors.Is(err, ErrMAC) {
				t.Errorf("%s: byte %d changed: %v", tc.name, i, err)
			}
		}
	}
}

// Covers: SIG-IPE-907
func TestWMBusMode9(t *testing.T) {
	m := testMeter(t)
	key := hx(t, "FEFFE9928665731C6D6A8F9467308308")
	keys := func(Header) []byte { return key }
	for _, tc := range []struct {
		name string
		s    Seal
	}{
		{"tag, persistent key", Seal{Mode: 9, Key: key, KeyVersion: -1, Counter: 1}},
		{"tag, KDF-A, key version, unencrypted part", Seal{Mode: 9, Key: key, KDF: 1, KeyID: 5, KeyVersion: 2, Counter: 99, Unencrypted: sampleAPL}},
		{"no tag", Seal{Mode: 9, Key: key, KeyVersion: -1, Counter: 3, TagLen: -1}},
	} {
		tpdu, err := SealTPL(CIShortHeader, false, m, 0x50, 0x04, 0, tc.s, sampleAPL)
		if err != nil {
			t.Fatal(err)
		}
		frame := linkFrame(m, tpdu)
		tg, err := Decode(frame, FormatNoCRC, keys)
		if err != nil || len(tg.Records) != 1+len(tc.s.Unencrypted)/6 || tg.Sec.KeyID != tc.s.KeyID || tg.Sec.KeyVersion != tc.s.KeyVersion {
			t.Fatalf("%s: %v %+v", tc.name, err, tg.Sec)
		}
		if tc.s.TagLen < 0 {
			if !contains(tg.Sec.Unverified, "gcm-no-tag") {
				t.Errorf("%s: %+v", tc.name, tg.Sec)
			}
			continue
		}
		// The tag covers CI, access number, status, configuration field,
		// the lengths, the unencrypted data and the ciphertext.
		for _, i := range []int{11, 12, 13, 14, len(frame) - 13, len(frame) - 1} {
			if _, err := Decode(flip(frame, i), FormatNoCRC, keys); err == nil {
				t.Errorf("%s: byte %d changed and still decoded", tc.name, i)
			}
		}
	}
}

// Covers: SIG-IPE-908
func TestWMBusMode10(t *testing.T) {
	m := testMeter(t)
	key := hx(t, "404142434445464748494A4B4C4D4E4F")
	keys := func(Header) []byte { return key }
	for _, tagLen := range []int{4, 8, 12, 16} {
		for _, unenc := range [][]byte{nil, sampleAPL} {
			s := Seal{Mode: 10, Key: key, KDF: 1, KeyID: 1, KeyVersion: -1, Counter: 42, CounterInTPL: true, TagLen: tagLen, Unencrypted: unenc}
			tpdu, err := SealTPL(CILongHeader, true, m, 0x60, 0, 0, s, sampleAPL)
			if err != nil {
				t.Fatal(err)
			}
			frame := linkFrame(m, tpdu)
			tg, err := Decode(frame, FormatNoCRC, keys)
			if err != nil || !contains(tg.Sec.Verified, "ccm") || len(tg.Records) != 1+len(unenc)/6 || tg.Sec.EncryptedLen != len(sampleAPL) {
				t.Fatalf("tag %d unenc %d: %v %+v", tagLen, len(unenc), err, tg.Sec)
			}
			for _, i := range []int{21, 22, 25, len(frame) - tagLen - 1, len(frame) - 1} {
				if _, err := Decode(flip(frame, i), FormatNoCRC, keys); err == nil {
					t.Errorf("tag %d: byte %d changed and still decoded", tagLen, i)
				}
			}
		}
	}
	// Without a TPL counter the AFL's is used.
	s := Seal{Mode: 10, Key: key, KDF: 1, KeyVersion: -1, Counter: 43}
	tpdu, _ := SealTPL(CIShortHeader, false, m, 0x61, 0, 0, s, sampleAPL)
	framed, _ := SealAFL(tpdu, m, key, 1, 43, 4, nil, false)
	if tg, err := Decode(linkFrame(m, framed), FormatNoCRC, keys); err != nil || tg.Sec.CounterFrom != "afl" {
		t.Errorf("mode 10 with the AFL counter: %v", err)
	}
}

// EN 13757-7:2025 annex B: the gateway restores C”M = 367 and takes it as
// its own counter; the meter sends 369 and 370; the gateway sends its
// command with its counter raised by an offset (374); the meter's later
// answer carries 375.
//
// Covers: SIG-IPE-910, SIG-IPE-911
func TestWMBusMessageCounters(t *testing.T) {
	m := testMeter(t)
	master := hx(t, "000102030405060708090A0B0C0D0E0F")
	keys := func(Header) []byte { return master }
	var d Decoder
	d.SetCounters(CounterState{Meter: map[string]uint32{"ABC-12345678/0": 367}, Partner: map[string]uint32{"ABC-12345678/0": 367}})
	send := func(c uint32, acc byte) []byte {
		tpdu, _ := SealTPL(CIShortHeader, false, m, acc, 0, 0, Seal{Mode: 7, Key: master, KDF: 1, KeyVersion: -1, Counter: c, CounterInTPL: true}, sampleAPL)
		return linkFrame(m, tpdu)
	}
	f369 := send(369, 1)
	if _, err := d.Decode(f369, FormatNoCRC, keys); err != nil {
		t.Fatalf("369: %v", err)
	}
	st, changed := d.Counters()
	if st.Meter["ABC-12345678/0"] != 369 || st.Partner["ABC-12345678/0"] != 369 || !changed {
		t.Fatalf("after 369: %+v", st)
	}
	// The gateway's own counter: raised to C''M, then an offset ≤ 100.
	if c := d.NextPartnerCounter(m, 0, 5); c != 374 {
		t.Errorf("CCP = %d, want 374", c)
	}
	f370 := send(370, 2)
	if _, err := d.Decode(f370, FormatNoCRC, keys); err != nil {
		t.Fatalf("370: %v", err)
	}
	// The same frame again is a repeat; an older counter is a replay; a
	// counter equal to C''M with other content is a replay too.
	if _, err := d.Decode(f370, FormatNoCRC, keys); !errors.Is(err, ErrRepeat) {
		t.Errorf("repeat of 370: %v", err)
	}
	if _, err := d.Decode(f369, FormatNoCRC, keys); !errors.Is(err, ErrReplay) {
		t.Errorf("replay of 369: %v", err)
	}
	if _, err := d.Decode(send(370, 9), FormatNoCRC, keys); !errors.Is(err, ErrReplay) {
		t.Errorf("other message with counter 370: %v", err)
	}
	// A failed check does not advance C''M.
	bad := flip(send(371, 3), 20)
	d.Decode(bad, FormatNoCRC, keys)
	if st, _ := d.Counters(); st.Meter["ABC-12345678/0"] != 370 {
		t.Errorf("a failed message moved C''M to %d", st.Meter["ABC-12345678/0"])
	}
	// The meter's answer after our 374 carries 375: accepted; CCP stays
	// at our 374 until C''M passes it, then follows.
	if _, err := d.Decode(send(375, 4), FormatNoCRC, keys); err != nil {
		t.Fatal(err)
	}
	st, _ = d.Counters()
	if st.Meter["ABC-12345678/0"] != 375 || st.Partner["ABC-12345678/0"] != 375 {
		t.Errorf("after 375: %+v", st)
	}
	// Counters are kept per Key ID.
	tpdu, _ := SealTPL(CIShortHeader, false, m, 5, 0, 0, Seal{Mode: 7, Key: master, KDF: 1, KeyID: 1, KeyVersion: -1, Counter: 10, CounterInTPL: true}, sampleAPL)
	if _, err := d.Decode(linkFrame(m, tpdu), FormatNoCRC, keys); err != nil {
		t.Errorf("key 1, counter 10: %v", err)
	}
	// Roll-over: a small counter after one near the top is newer.
	if !newer(3, 0xFFFFFFF0) || newer(3, 0x7FFFFFFF) || !newer(371, 370) || newer(370, 370) {
		t.Error("counter comparison")
	}
	// KeyByID picks a key per Key ID; an unknown one falls back to the
	// meter's key.
	k1 := hx(t, "FFEEDDCCBBAA99887766554433221100")
	d2 := Decoder{KeyByID: func(_ Header, id, _ int) []byte {
		if id == 1 {
			return k1
		}
		return nil
	}}
	tpdu, _ = SealTPL(CIShortHeader, false, m, 6, 0, 0, Seal{Mode: 7, Key: k1, KDF: 1, KeyID: 1, KeyVersion: -1, Counter: 11, CounterInTPL: true}, sampleAPL)
	if _, err := d2.Decode(linkFrame(m, tpdu), FormatNoCRC, keys); err != nil {
		t.Errorf("key by ID: %v", err)
	}
}

// Covers: SIG-IPE-900, SIG-IPE-903
func TestWMBusAFLFragments2025(t *testing.T) {
	m := testMeter(t)
	master := hx(t, "000102030405060708090A0B0C0D0E0F")
	keys := func(Header) []byte { return master }
	apl := bytes.Repeat(sampleAPL, 12) // 72 bytes
	tpdu, _ := SealTPL(CIShortHeader, false, m, 0x70, 0, 0, Seal{Mode: 7, Key: master, KDF: 1, KeyVersion: -1, Counter: 500}, apl)
	_, kmac, _ := SessionKeys(master, 1, 500, m, false)
	parts := [][]byte{tpdu[:30], tpdu[30:60], tpdu[60:]}
	// Individual fragment authentication: every fragment carries a 4-byte
	// CMAC over MCL, MCR, ML and its own part.
	msg := &AFL{MCL: 0x24, Counter: 500, ML: uint16(len(tpdu))}
	msg.has.mcl, msg.has.mcr, msg.has.ml = true, true, true
	frames := make([][]byte, 3)
	for i, part := range parts {
		full, _ := CMAC(kmac, append(msg.macInput(), part...))
		fcl := uint16(i+1) | AFLMACP
		if i < 2 {
			fcl |= AFLMF
		}
		f := []byte{}
		if i == 0 {
			fcl |= AFLMCLP | AFLMCRP | AFLMLP
			f = binary.LittleEndian.AppendUint16(f, fcl)
			f = append(f, msg.MCL)
			f = binary.LittleEndian.AppendUint32(f, 500)
			f = append(f, full[:4]...)
			f = binary.LittleEndian.AppendUint16(f, msg.ML)
		} else {
			f = binary.LittleEndian.AppendUint16(f, fcl)
			f = append(f, full[:4]...)
		}
		frames[i] = linkFrame(m, append(append([]byte{CIAFL, byte(len(f))}, f...), part...))
	}
	var d Decoder
	for i := range 2 {
		if _, err := d.Decode(frames[i], FormatNoCRC, keys); !errors.Is(err, ErrFragment) {
			t.Fatalf("fragment %d: %v", i+1, err)
		}
	}
	tg, err := d.Decode(frames[2], FormatNoCRC, keys)
	if err != nil || tg.AFL.Fragments != 3 || len(tg.Records) != 12 || !contains(tg.Sec.Verified, "afl-cmac") {
		t.Fatalf("individual fragment authentication: %v", err)
	}
	// A changed middle fragment (its own MAC fixed up would need the key)
	// fails.
	var d2 Decoder
	d2.Decode(frames[0], FormatNoCRC, keys)
	d2.Decode(flip(frames[1], len(frames[1])-1), FormatNoCRC, keys)
	if _, err := d2.Decode(frames[2], FormatNoCRC, keys); !errors.Is(err, ErrMAC) {
		t.Errorf("changed fragment 2: %v", err)
	}
	// An unfragmented message (FID 0) drops a pending partial message and
	// decodes on its own.
	var d3 Decoder
	d3.Decode(frames[0], FormatNoCRC, keys)
	single, _ := SealAFL(tpdu, m, master, 1, 501, 5, nil, false)
	tpdu501, _ := SealTPL(CIShortHeader, false, m, 0x71, 0, 0, Seal{Mode: 7, Key: master, KDF: 1, KeyVersion: -1, Counter: 501}, apl)
	single, _ = SealAFL(tpdu501, m, master, 1, 501, 5, nil, false)
	if tg, err := d3.Decode(linkFrame(m, single), FormatNoCRC, keys); err != nil || len(tg.Records) != 12 {
		t.Errorf("unfragmented after a partial: %v", err)
	}
	if len(d3.partial) != 0 {
		t.Error("the partial message was kept")
	}
	// A later fragment without the first one is refused.
	var d4 Decoder
	if _, err := d4.Decode(frames[1], FormatNoCRC, keys); err == nil || errors.Is(err, ErrFragment) {
		t.Errorf("fragment 2 alone: %v", err)
	}
	// AFL.ML of an unfragmented message must match.
	a := &AFL{MCL: 0x05 | 0x40, Counter: 9, ML: uint16(len(tpdu501) + 1)}
	_ = a
	f := binary.LittleEndian.AppendUint16(nil, AFLMLP)
	f = binary.LittleEndian.AppendUint16(f, uint16(len(tpdu501)+1))
	if _, err := Decode(linkFrame(m, append(append([]byte{CIAFL, byte(len(f))}, f...), tpdu501...)), FormatNoCRC, keys); err == nil {
		t.Error("a wrong AFL.ML was accepted")
	}
	_ = time.Second
}
