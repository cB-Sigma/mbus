package wireless

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
)

// Downlinks in security modes 7 to 10 with our counter and the partner
// keys (Lenc, Lmac): a meter-side Decoder opens each, and a changed byte is
// refused.
//
// Covers: SIG-IPE-919
func TestWMBusDownlinkModes8to10(t *testing.T) {
	gw := Gateway{Manufacturer: "XYZ", ID: "33445566", Version: 10}
	if err := gw.Validate(); err != nil {
		t.Fatal(err)
	}
	m := testMeter(t)
	key := hx(t, "000102030405060708090A0B0C0D0E0F")
	for _, mode := range []int{7, 8, 9, 10} {
		frame, err := EncodeDownlinkSealed(gw, m, Downlink{C: CSndUD, CI: CIToMeterLong, APL: sampleAPL}, 1, 1, DownlinkSeal{Mode: mode, Key: key, Counter: 42})
		if err != nil {
			t.Fatalf("mode %d: %v", mode, err)
		}
		d := &Decoder{MeterSide: true}
		tg, err := d.Decode(frame, FormatNoCRC, func(Header) []byte { return key })
		if err != nil || tg.Mode != mode || tg.Meter.Key() != m.Key() || tg.Sec.Counter != 42 || len(tg.Records) != 1 || len(tg.Sec.Verified) == 0 {
			t.Fatalf("mode %d: %v %+v", mode, err, tg)
		}
		// The meter-direction keys do not open it.
		if _, err := Decode(frame, FormatNoCRC, func(Header) []byte { return key }); err == nil {
			t.Errorf("mode %d opened with Kenc/Kmac", mode)
		}
		if _, err := (&Decoder{MeterSide: true}).Decode(flip(frame, len(frame)-1), FormatNoCRC, func(Header) []byte { return key }); err == nil {
			t.Errorf("mode %d: changed byte accepted", mode)
		}
	}
}

// Security modes EN 13757-7:2025 does not define are refused with the
// reason (7.5.8 table 19); the deprecated DES modes 2 and 3 are read with a
// DES key and marked deprecated (9.4.3).
//
// Covers: SIG-IPE-921, SIG-IPE-922
func TestWMBusOtherSecurityModes(t *testing.T) {
	m := testMeter(t)
	for mode, want := range map[int]string{1: "manufacturer specific", 4: "DSMR 2.2", 6: "reserved", 11: "reserved", 12: "reserved", 14: "reserved", 15: "DSMR 4.2.2", 31: "reserved"} {
		tpdu := binary.LittleEndian.AppendUint16([]byte{CIShortHeader, 1, 0}, uint16(mode)<<8)
		tpdu = append(tpdu, bytes.Repeat([]byte{0x11}, 16)...)
		_, err := Decode(linkFrame(m, tpdu), FormatNoCRC, func(Header) []byte { return make([]byte, 16) })
		if !errors.Is(err, ErrSecurityMode) || !strings.Contains(err.Error(), want) {
			t.Errorf("mode %d: %v", mode, err)
		}
	}
	desKey := hx(t, "0123456789ABCDEF")
	// Plain data holding the meter's ID (a fabrication number record,
	// DIF 0C VIF 78 with the ID's BCD digits) and a volume record.
	plain := append([]byte{0x0C, 0x78}, m.A[:4]...)
	plain = append(plain, sampleAPL...)
	for len(plain)%8 != 0 {
		plain = append(plain, 0x2F)
	}
	day := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	if g := typeG(day); g != 0x3958 {
		t.Errorf("type G of 2026-09-24 = %04X", g)
	}
	for _, mode := range []int{2, 3} {
		iv := make([]byte, 8)
		if mode == 3 {
			// Sent just before midnight: the ID in bytes 6 to 9 covers the
			// date bytes of the IV, so yesterday's date is found.
			plain = append([]byte{0x2F, 0x2F, 0x2F, 0x2F}, plain...)
			for len(plain)%8 != 0 {
				plain = append(plain, 0x2F)
			}
			iv = mode3IV(m, day.AddDate(0, 0, -1))
		}
		enc, _ := desCBCEncrypt(desKey, iv, plain)
		tpdu := binary.LittleEndian.AppendUint16([]byte{CIShortHeader, 1, 0}, uint16(mode)<<8|uint16(len(enc)))
		tpdu = append(tpdu, enc...)
		d := &Decoder{Now: func() time.Time { return day }, DESKey: func(Header) []byte { return desKey }}
		tg, err := d.Decode(linkFrame(m, tpdu), FormatNoCRC, nil)
		if err != nil || !tg.Encrypted || !contains(tg.Sec.Unverified, "deprecated-des") || len(tg.Records) != 2 {
			t.Errorf("mode %d: %v enc=%v sec=%+v records=%d", mode, err, tg.Encrypted, tg.Sec, len(tg.Records))
		}
		// Wrong key: the ID is not found.
		d.DESKey = func(Header) []byte { return hx(t, "FEDCBA9876543210") }
		if _, err := d.Decode(linkFrame(m, tpdu), FormatNoCRC, nil); !errors.Is(err, ErrDecrypt) {
			t.Errorf("mode %d wrong key: %v", mode, err)
		}
		// Without a DES key.
		if _, err := Decode(linkFrame(m, tpdu), FormatNoCRC, nil); !errors.Is(err, ErrNoKey) {
			t.Errorf("mode %d no key: %v", mode, err)
		}
	}
}

// Mode 7 downlinks leave AFL.KI out for the default key (Key ID 0, no key
// version) as OMS Volume 2 6.2.2 and annex N.12.2 do, so the meter keeps
// its KI flag clear; downlinkKeyInfo (or another Key ID) sends it.
//
// Covers: SIG-IPE-1459
func TestWMBusDownlinkKeyInfo(t *testing.T) {
	gw := Gateway{Manufacturer: "XYZ", ID: "33445566", Version: 10}
	if err := gw.Validate(); err != nil {
		t.Fatal(err)
	}
	m := testMeter(t)
	key := hx(t, "000102030405060708090A0B0C0D0E0F")
	for _, tc := range []struct {
		sec  DownlinkSeal
		want bool
	}{
		{DownlinkSeal{Mode: 7, Key: key, Counter: 5}, false},
		{DownlinkSeal{Mode: 7, Key: key, Counter: 5, KeyInfo: true}, true},
		{DownlinkSeal{Mode: 7, Key: key, Counter: 5, KeyID: 2}, true},
	} {
		f, err := EncodeDownlinkSealed(gw, m, Downlink{C: CSndUD, CI: CIToMeterLong, APL: sampleAPL}, 1, 1, tc.sec)
		if err != nil {
			t.Fatal(err)
		}
		fcl := binary.LittleEndian.Uint16(f[15:17])
		if got := fcl&AFLKIP != 0; got != tc.want {
			t.Errorf("%+v: KI present %v", tc.sec, got)
		}
		kd := func(_ Header, id, _ int) []byte { return key }
		if _, err := (&Decoder{MeterSide: true, KeyByID: kd}).Decode(f, FormatNoCRC, func(Header) []byte { return key }); err != nil {
			t.Errorf("%+v: %v", tc.sec, err)
		}
	}
}
