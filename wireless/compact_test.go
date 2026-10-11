package wireless

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cB-Sigma/mbus/records"
)

// Test vectors: EN 13757-3:2025 G.5 (energy 123,4 Wh, volume 567,8 m3,
// power 901,2 W). The annex shows the Format Signature and the
// Full-Frame-CRC only as placeholders; the values here are computed with
// the G.3/G.4 CRC and pinned, and the check value of that CRC
// (EN 13757 CRC-16 over "123456789") anchors them.
const (
	g52Full    = "0202D20402152E16022A3423"
	g52Format  = "02020215022A"
	g52Sig     = 0x3B31
	g52FFC     = 0xA642
	g54Full    = "0202D20402152E162F2F2F2F2F2F022A3423"
	g54Format  = "020202152F2F2F2F2F2F022A"
	g54Sig     = 0x81CC
	g54FFC     = 0x69A6
	g5MeterKey = "KAM-12345678"
)

// wmFrame is a CRC-less wM-Bus telegram from meter KAM 12345678 (water)
// with the given TPL (CI onward).
func wmFrame(t *testing.T, tpl []byte) []byte {
	t.Helper()
	m, err := records.ManufacturerField("KAM")
	if err != nil {
		t.Fatal(err)
	}
	b := []byte{0, 0x44, byte(m), byte(m >> 8), 0x78, 0x56, 0x34, 0x12, 0x01, 0x07}
	b = append(b, tpl...)
	b[0] = byte(len(b) - 1)
	return b
}

func le16(v uint16) []byte { return []byte{byte(v), byte(v >> 8)} }

func cat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

func checkG5Records(t *testing.T, what string, rs []records.Record) {
	t.Helper()
	got := map[string]any{}
	for _, r := range rs {
		got[r.Name()] = r.Value
	}
	if got["energy"] != 123.4 || got["volume"] != 567.8 || got["power"] != 901.2 || len(rs) != 3 {
		t.Errorf("%s: records %v", what, got)
	}
}

// Covers: SIG-IPE-950
func TestCompactFrameCIFields(t *testing.T) {
	// Table G.2: frame kind and TPL header per CI; Table G.1: request CIs.
	for ci, want := range map[byte][2]string{
		0x78: {"full", "none"}, 0x7A: {"full", "short"}, 0x72: {"full", "long"},
		0x79: {"compact", "none"}, 0x7B: {"compact", "short"}, 0x73: {"compact", "long"},
		0x69: {"format", "none"}, 0x6A: {"format", "short"}, 0x6B: {"format", "long"},
		0x5B: {"", ""},
	} {
		k, h := FrameKind(ci)
		if k != want[0] || h != want[1] {
			t.Errorf("CI %02X: %s/%s, want %v", ci, k, h, want)
		}
		if isCompactCI(ci) != (want[0] == "compact" || want[0] == "format") {
			t.Errorf("CI %02X: isCompactCI wrong", ci)
		}
	}
	req := []byte{CIReqFullLong, CIReqCompactLong, CIReqFormatLong, CIReqFullShort, CIReqCompactShort, CIReqFormatShort}
	if !bytes.Equal(req, []byte{0x80, 0x84, 0x85, 0x93, 0x94, 0x95}) {
		t.Errorf("request CIs % X", req)
	}
	// Decode reads the header variant of each compact/format CI and hands
	// the application data on instead of parsing it as records.
	short := wmFrame(t, cat([]byte{CICompactShort, 0x01, 0x00, 0x00, 0x00}, le16(g52Sig), le16(g52FFC), hx(t, "D2042E163423")))
	tg, err := Decode(short, FormatNoCRC, nil)
	if !errors.Is(err, ErrCompactFrame) || tg.HeaderKind != "short" || tg.Access != 1 || len(tg.Records) != 0 {
		t.Fatalf("compact short: %v %+v", err, tg)
	}
	long := wmFrame(t, cat([]byte{CIFormatLong, 0x78, 0x56, 0x34, 0x12, 0x2D, 0x2C, 0x01, 0x07, 0x02, 0x00, 0x00, 0x00, 0x08}, le16(g52Sig), hx(t, g52Format)))
	tg, err = Decode(long, FormatNoCRC, nil)
	if !errors.Is(err, ErrCompactFrame) || tg.HeaderKind != "long" || tg.Access != 2 {
		t.Fatalf("format long: %v %+v", err, tg)
	}
}

// Covers: SIG-IPE-951
func TestCompactFrameSignatureAndCRC(t *testing.T) {
	// G.3 and G.4: CRC polynomial 3D65h, initial 0, complemented; its
	// check value over "123456789" is C2B7h.
	if c := CRC([]byte("123456789")); c != 0xC2B7 {
		t.Fatalf("CRC check value %04X", c)
	}
	for _, v := range []struct {
		full, format string
		sig, ffc     uint16
	}{{g52Full, g52Format, g52Sig, g52FFC}, {g54Full, g54Format, g54Sig, g54FFC}} {
		f, err := BuildFormat(hx(t, v.full))
		if err != nil || !bytes.Equal(f, hx(t, v.format)) {
			t.Errorf("format of %s = % X, %v", v.full, f, err)
		}
		if s := FormatSignature(f); s != v.sig {
			t.Errorf("signature %04X, want %04X", s, v.sig)
		}
		if c := FullFrameCRC(hx(t, v.full)); c != v.ffc {
			t.Errorf("full-frame CRC %04X, want %04X", c, v.ffc)
		}
		// Idle fillers after the last record are not part of the CRC; a
		// last data byte of 2F is.
		if c := FullFrameCRC(append(hx(t, v.full), 0x2F, 0x2F)); c != v.ffc {
			t.Errorf("full-frame CRC with trailing fillers %04X", c)
		}
	}
	if FullFrameCRC(hx(t, "01FD172F")) == FullFrameCRC(hx(t, "01FD17")) {
		t.Error("a data byte 2F was dropped from the CRC")
	}
}

// Covers: SIG-IPE-952
func TestCompactFrameRebuild(t *testing.T) {
	key := hx(t, omsMode5Key)
	keys := func(Header) []byte { return key }
	mode5 := func(hdr, plain, clear []byte) []byte {
		t.Helper()
		tg := Telegram{Meter: Header{MField: 0}, Access: hdr[1]}
		m, _ := records.ManufacturerField("KAM")
		tg.Meter.MField = m
		tg.Meter.A = [6]byte{0x78, 0x56, 0x34, 0x12, 0x01, 0x07}
		enc, err := cbcEncrypt(key, tg.Mode5IV(), plain)
		if err != nil {
			t.Fatal(err)
		}
		return wmFrame(t, cat(hdr, enc, clear))
	}
	fills := func(n int) []byte { return bytes.Repeat([]byte{0x2F}, n) }
	cases := []struct {
		name                  string
		full, format, compact []byte
		sig                   uint16
	}{
		{ // G.5.2: no data header
			name:    "G.5.2",
			full:    wmFrame(t, cat([]byte{0x78}, hx(t, g52Full))),
			format:  wmFrame(t, cat([]byte{0x69, 0x08}, le16(g52Sig), hx(t, g52Format))),
			compact: wmFrame(t, cat([]byte{0x79}, le16(g52Sig), le16(g52FFC), hx(t, "D2042E163423"))),
			sig:     g52Sig,
		},
		{ // G.5.3: short data header, no encryption
			name:    "G.5.3",
			full:    wmFrame(t, cat(hx(t, "7A01000000"), hx(t, g52Full))),
			format:  wmFrame(t, cat(hx(t, "6A0100000008"), le16(g52Sig), hx(t, g52Format))),
			compact: wmFrame(t, cat(hx(t, "7B01000000"), le16(g52Sig), le16(g52FFC), hx(t, "D2042E163423"))),
			sig:     g52Sig,
		},
		{ // G.5.4: short header, mode 5, one encrypted block, the rest clear
			name:    "G.5.4",
			full:    mode5(hx(t, "7A01001005"), cat(hx(t, "2F2F0202D20402152E16"), fills(6)), hx(t, "022A3423")),
			format:  mode5(hx(t, "6A01001005"), cat(hx(t, "2F2F0C"), le16(g54Sig), hx(t, "02020215"), fills(7)), hx(t, "022A")),
			compact: mode5(hx(t, "7B01001005"), cat(hx(t, "2F2F"), le16(g54Sig), le16(g54FFC), hx(t, "D2042E16"), fills(6)), hx(t, "3423")),
			sig:     g54Sig,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fc := NewFormatCache(0)
			// Before the format is known the compact frame cannot be read.
			tg, err := Decode(c.compact, FormatNoCRC, keys)
			info, err := fc.Complete(tg, err)
			if !errors.Is(err, ErrFormatUnknown) || info.Kind != KindCompact || info.Signature != c.sig || info.Known {
				t.Fatalf("unknown format: %v %+v", err, info)
			}
			// The format frame teaches it.
			tg, err = Decode(c.format, FormatNoCRC, keys)
			if info, err = fc.Complete(tg, err); err != nil || info.Kind != KindFormat || info.Signature != c.sig {
				t.Fatalf("format frame: %v %+v", err, info)
			}
			tg, err = Decode(c.compact, FormatNoCRC, keys)
			if info, err = fc.Complete(tg, err); err != nil || !info.Known {
				t.Fatalf("compact frame: %v %+v", err, info)
			}
			checkG5Records(t, "compact", tg.Records)
			rebuilt := tg.APL
			// The full frame decodes as before and is what was rebuilt.
			tg, err = Decode(c.full, FormatNoCRC, keys)
			if err != nil {
				t.Fatal(err)
			}
			checkG5Records(t, "full", tg.Records)
			want := tg.APL
			if tg.Encrypted {
				want = want[2:]
			}
			if !bytes.Equal(bytes.TrimRight(want, "\x2F"), bytes.TrimRight(rebuilt, "\x2F")) {
				t.Errorf("rebuilt % X, full % X", rebuilt, want)
			}

			// A full frame stands in for the format frame once the meter
			// is known to send compact frames.
			fc2 := NewFormatCache(0)
			tg, err = Decode(c.compact, FormatNoCRC, keys)
			_, _ = fc2.Complete(tg, err)
			tg, err = Decode(c.full, FormatNoCRC, keys)
			if info, err := fc2.Complete(tg, err); err != nil || info.Kind != KindFull || info.Signature != c.sig {
				t.Fatalf("full frame: %v %+v", err, info)
			}
			tg, err = Decode(c.compact, FormatNoCRC, keys)
			if _, err := fc2.Complete(tg, err); err != nil {
				t.Fatalf("compact after full: %v", err)
			}
			checkG5Records(t, "compact after full", tg.Records)
		})
	}

	// A compact frame whose values do not match the Full-Frame-CRC means
	// the cached format is outdated: it is dropped.
	fc := NewFormatCache(0)
	fc.Put(g5MeterKey, hx(t, g52Format))
	bad := wmFrame(t, cat([]byte{0x79}, le16(g52Sig), le16(g52FFC^1), hx(t, "D2042E163423")))
	tg, err := Decode(bad, FormatNoCRC, nil)
	if _, err := fc.Complete(tg, err); !errors.Is(err, ErrFullFrameCRC) {
		t.Errorf("wrong FFC: %v", err)
	}
	if _, ok := fc.Get(g5MeterKey, g52Sig); ok {
		t.Error("an outdated format was kept")
	}
	// A format frame whose bytes do not match its signature is refused.
	tg, err = Decode(wmFrame(t, cat([]byte{0x69, 0x08}, le16(g52Sig^1), hx(t, g52Format))), FormatNoCRC, nil)
	if _, err := fc.Complete(tg, err); !errors.Is(err, ErrFormatSignature) {
		t.Errorf("wrong signature: %v", err)
	}
	// Compact data shorter than its format.
	fc.Put(g5MeterKey, hx(t, g52Format))
	if _, _, err := fc.Expand(g5MeterKey, CICompactNone, cat(le16(g52Sig), le16(g52FFC), hx(t, "D204"))); err == nil {
		t.Error("short compact data accepted")
	}
	// The exported API for the wired side: unencrypted data after the TPL.
	fc.Put(g5MeterKey, hx(t, g52Format))
	full, sig, err := fc.Expand(g5MeterKey, CICompactNone, cat(le16(g52Sig), le16(g52FFC), hx(t, "D2042E163423")))
	if err != nil || sig != g52Sig || !bytes.Equal(full, hx(t, g52Full)) {
		t.Errorf("Expand: % X %04X %v", full, sig, err)
	}
}

// Covers: SIG-IPE-953
func TestCompactFormatCacheBoundAndSnapshot(t *testing.T) {
	fc := NewFormatCache(2)
	a := fc.Put("A", hx(t, "0202"))
	b := fc.Put("B", hx(t, "0203"))
	fc.Get("A", a) // A used more recently than B
	fc.Put("C", hx(t, "0204"))
	if _, ok := fc.Get("B", b); ok || fc.Len() != 2 {
		t.Errorf("least recently used not dropped: len %d", fc.Len())
	}
	saved, changed := fc.Snapshot()
	if !changed || len(saved) != 2 || saved[0].Meter != "A" || saved[0].Format != "0202" {
		t.Fatalf("snapshot %+v %v", saved, changed)
	}
	if _, changed := fc.Snapshot(); changed {
		t.Error("unchanged cache reported changed")
	}
	saved = append(saved, SavedFormat{Meter: "D", Signature: 1, Format: "0205"}) // wrong signature
	fc2 := NewFormatCache(0)
	fc2.Restore(saved)
	if fc2.Len() != 2 {
		t.Errorf("restored %d formats", fc2.Len())
	}
	if _, changed := fc2.Snapshot(); changed {
		t.Error("a restore marked the cache changed")
	}
	// Restored meters count as compact senders: full frames refresh them.
	if _, ok := fc2.Get("A", a); !ok {
		t.Error("restored format missing")
	}
}
