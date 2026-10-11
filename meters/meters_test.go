// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package meters

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/cB-Sigma/mbus/records"
	"github.com/cB-Sigma/mbus/wireless"
)

// The telegrams here are written for these tests from the layouts the
// drivers read; the values are ours.

// frame builds a CRC-less wM-Bus frame: L, C 44h, M, A (ID BCD low byte
// first, version, type), then the rest from the CI field on.
func frame(t *testing.T, man string, id uint32, ver, typ byte, rest ...byte) []byte {
	t.Helper()
	m, err := records.ManufacturerField(man)
	if err != nil {
		t.Fatal(err)
	}
	f := []byte{0, 0x44, byte(m), byte(m >> 8)}
	for i := 0; i < 4; i++ {
		f = append(f, byte(id%10|(id/10%10)<<4))
		id /= 100
	}
	f = append(f, ver, typ)
	f = append(f, rest...)
	f[0] = byte(len(f) - 1)
	return f
}

func read(t *testing.T, f []byte, keys wireless.KeyLookup) *Reading {
	t.Helper()
	tg, err := wireless.Decode(f, wireless.FormatNoCRC, keys)
	r, err := ReadKeys(tg, err, keys)
	if err != nil {
		t.Fatalf("% X: %v", f, err)
	}
	return r
}

func want(t *testing.T, r *Reading, name string, v any) {
	t.Helper()
	got, ok := r.Get(name)
	if !ok {
		t.Errorf("%s: no %s in %+v", r.Driver, name, r.Values)
		return
	}
	if f, ok := v.(float64); ok {
		g, _ := r.Float(name)
		if math.Abs(g-f) > 1e-9 {
			t.Errorf("%s: %s = %v, want %v", r.Driver, name, got.Value, v)
		}
		return
	}
	if got.Value != v {
		t.Errorf("%s: %s = %v, want %v", r.Driver, name, got.Value, v)
	}
}

func TestLookupPrefersExactAndDecoding(t *testing.T) {
	if d := Lookup(wireless.Header{Manufacturer: "TCH", Version: 0x45, DeviceType: 0x43}); d == nil || d.Name != "techem-compact5" {
		t.Fatalf("compact5: %+v", d)
	}
	// An IZAR's MVT is also in the model table; the decoding driver wins.
	if d := Lookup(wireless.Header{Manufacturer: "HYD", Version: 0x85, DeviceType: 0x07}); d == nil || d.Name != "diehl-izar" {
		t.Fatalf("izar: %+v", d)
	}
	// Any other Diehl-group meter falls to the group's driver.
	if d := Lookup(wireless.Header{Manufacturer: "SPL", Version: 1, DeviceType: 7}); d == nil || d.Name != "diehl" {
		t.Fatalf("diehl: %+v", d)
	}
	if d := Lookup(wireless.Header{Manufacturer: "XYZ", Version: 1, DeviceType: 7}); d != nil {
		t.Fatalf("unknown: %+v", d)
	}
	if len(Drivers()) < 100 || ByName("kamstrup-multical-21") == nil {
		t.Fatalf("%d drivers", len(Drivers()))
	}
}

func TestNoDriver(t *testing.T) {
	tg, err := wireless.Decode(frame(t, "XYZ", 12345678, 1, 7, 0xA0, 1, 2, 3), wireless.FormatNoCRC, nil)
	if _, err := Read(tg, err); !errors.Is(err, ErrNoDriver) || !errors.Is(err, wireless.ErrManufacturerCI) {
		t.Fatalf("%v", err)
	}
	// Plain records: values, and a computed temperature difference.
	r := read(t, frame(t, "XYZ", 12345678, 1, 4, 0x78, 0x0A, 0x5A, 0x50, 0x06, 0x0A, 0x5E, 0x20, 0x05), nil)
	want(t, r, "flow_temperature", 65.0)
	want(t, r, "temperature_difference", 13.0)
}

func TestTechem(t *testing.T) {
	r := read(t, frame(t, "TCH", 62626262, 0x45, 0x43, 0xA1, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x60, 0x20, 0x01, 0x00), nil)
	want(t, r, "energy", 528.0+288)
	want(t, r, "energy_current_period", 288.0)
	if r.DeviceType != 0x04 || r.SentDeviceType != 0x43 || r.Medium() != records.Medium(4) {
		t.Errorf("device type %02X %02X", r.DeviceType, r.SentDeviceType)
	}
	// radio 3: billing date 2023-12-31 (0x2F9F), 12.3 m3 then; today
	// 2024-02-10 (day in bits 4-8, month in 9-12), 4.5 m3 since.
	cur := uint16(2)<<9 | uint16(10)<<4
	r = read(t, frame(t, "TCH", 11223344, 0x74, 0x62, 0xA2, 0x06, 0x9F, 0x2F, 123, 0, byte(cur), byte(cur>>8), 45, 0), nil)
	want(t, r, "volume", 16.8)
	want(t, r, "billing_date", "2023-12-31")
	want(t, r, "current_date", "2024-02-10")
	// vario 4: 360 and 720 units of 1/3.6 kWh.
	r = read(t, frame(t, "TCH", 1, 0x27, 0xC3, 0xA2, 0, 0, 0, 0x68, 0x01, 0, 0, 0xD0, 0x02), nil)
	want(t, r, "energy", 300.0)
	// FHKV data III, layout 0Fh: one extra byte before the temperatures.
	r = read(t, frame(t, "TCH", 2, 0x94, 0x80, 0xA2, 0x0F, 0x9F, 0x2B, 100, 0, 0xA0, 0x06, 7, 0, 0x00, 0x66, 0x08, 0xB8, 0x0B), nil)
	want(t, r, "hca_units", 7.0)
	want(t, r, "room_temperature", 21.5)
	want(t, r, "radiator_temperature", 30.0)
	want(t, r, "billing_date", "2021-12-31")
	want(t, r, "current_date", "2022-03-10")
	r = read(t, frame(t, "TCH", 3, 0x76, 0xF0, 0xA0, 0x01, 0x9F, 0x2B), nil)
	want(t, r, "status", "smoke")
}

func TestApator(t *testing.T) {
	r := read(t, frame(t, "APT", 4444, 0x03, 0x03, 0xA0, 0xB8, 0x0B, 0, 0), nil) // 3000 thirds of a litre: one m3
	want(t, r, "volume", 1.0)
	// AT-WMBUS-16-2: 2F2F, the manufacturer record 0Fh, status, a date tag
	// and the volume tag.
	r = read(t, frame(t, "APA", 5, 0x05, 0x07, 0x7A, 1, 0, 0, 0, 0x2F, 0x2F, 0x0F, 1, 2, 3, 4, 5, 6, 7, 0x00, 1, 2, 3, 4, 0x10, 0x39, 0x30, 0, 0, 0xFF, 0xAB, 0xCD), nil)
	want(t, r, "volume", 12.345)
	// E-ITN: season start 2016-02-01 (low byte 41h), seal intact.
	r = read(t, frame(t, "APA", 6, 0x04, 0x08, 0xA0, 0x41, 0, 0, 120, 0, 0, 0, 3, 0, 0xB4, 0x2E, 0x00, 0x14, 0x80, 0x15), nil)
	want(t, r, "hca_units", 3.0)
	want(t, r, "season_start_date", "2016-02-01")
	want(t, r, "current_date", "2023-05-20")
	want(t, r, "room_temperature_average", 21.5)
	want(t, r, "status", "ok")
}

func TestApatorNA1(t *testing.T) {
	key := []byte("0123456789abcdef")
	f := frame(t, "APA", 4913581, 0x14, 0x07, 0xA0, 0x55, 0x01)
	plain := make([]byte, 16)
	// 123456 litres packed with multiplier 1: the low nibble and the
	// bits from 8 up.
	v := uint32(123456)
	binary.LittleEndian.PutUint32(plain[1:5], (v/16)<<8|v%16)
	binary.LittleEndian.PutUint32(plain[5:9], 3600*24) // 2000-01-02
	plain[9], plain[10] = 10, 0                        // 10 hours old
	plain[11] = 25                                     // 100 litres less
	plain[14] = 0x08
	blk, _ := aes.NewCipher(key)
	iv := make([]byte, 16)
	binary.LittleEndian.PutUint16(iv, binary.LittleEndian.Uint16(f[2:4]))
	copy(iv[2:8], f[4:10])
	for i := 8; i < 16; i++ {
		iv[i] = 0x55
	}
	enc := make([]byte, 16)
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(enc, plain)
	f = append(f, enc...)
	f[0] = byte(len(f) - 1)
	r := read(t, f, func(wireless.Header) []byte { return key })
	want(t, r, "volume", 123.456)
	want(t, r, "volume_history", 123.356)
	want(t, r, "meter_datetime", "2000-01-02T00:00:00")
	want(t, r, "history_datetime", "2000-01-01T14:00:00")
	want(t, r, "current_status", "leak")
	want(t, r, "frame_status", "summer_time")
	tg, err := wireless.Decode(f, wireless.FormatNoCRC, nil)
	if _, err := Read(tg, err); !errors.Is(err, wireless.ErrNoKey) {
		t.Errorf("no key: %v", err)
	}
}

func TestDiehl(t *testing.T) {
	// Real data: records scrambled under a test key of our own, the
	// checksum in the configuration field's high byte.
	recs := []byte{0x04, 0x13, 0x39, 0x30, 0x00, 0x00}
	f := frame(t, "HYD", 0, 0x8B, 0x07, 0x7A, 0x2A, 0x00)
	// The address as Diehl sends it: version, type, then the ID.
	copy(f[4:10], []byte{0x8B, 0x07, 0x78, 0x56, 0x34, 0x12})
	var sum byte
	for _, b := range recs {
		sum += b
	}
	cfg := uint16(sum&0xEF|0x10) << 8
	f = append(f, byte(cfg), byte(cfg>>8))
	tg := &wireless.Telegram{Header: mustHeader(t, f), CI: 0x7A, Access: 0x2A, Status: 0, Config: cfg}
	scr := diehlUnscramble(diehlSeed(testScramble1, tg, [3]byte{0x2A, 0, byte(cfg)}), recs)
	f = append(f, scr...)
	f[0] = byte(len(f) - 1)
	r := read(t, f, nil)
	if r.Driver != "diehl-hydrus" || r.ID != "12345678" || r.DeviceType != 7 {
		t.Fatalf("%+v", r)
	}
	want(t, r, "volume", 12.345)
	// Corrupt it: the check fails.
	f[len(f)-1] ^= 0x01
	tg2, err := wireless.Decode(f, wireless.FormatNoCRC, nil)
	if _, err := Read(tg2, err); !errors.Is(err, ErrDiehlCheck) {
		t.Errorf("corrupted: %v", err)
	}
	if k := DefaultKey(wireless.Header{Manufacturer: "DME"}); len(k) != 16 || DefaultKey(wireless.Header{Manufacturer: "KAM"}) != nil {
		t.Errorf("default key %X", k)
	}
	// Without keys: the scrambled telegram is refused, naming the option.
	SetMakerKeys(MakerKeys{})
	defer setTestMakerKeys()
	f[len(f)-1] ^= 0x01
	tg3, err := wireless.Decode(f, wireless.FormatNoCRC, nil)
	if _, err := Read(tg3, err); !errors.Is(err, ErrNoScramblingKey) || !strings.Contains(err.Error(), "SetMakerKeys") {
		t.Errorf("no keys: %v", err)
	}
	if DefaultKey(wireless.Header{Manufacturer: "DME"}) != nil {
		t.Error("a default key without SetMakerKeys")
	}
}

func TestIzar(t *testing.T) {
	f := frame(t, "SAP", 31415926, 0x10, 0x01, 0xA2, 0x01, 0x1D, 0x00, 0x13)
	tg := &wireless.Telegram{Header: mustHeader(t, f), CI: 0xA2}
	plain := []byte{0x4B, 0x88, 0x13, 0, 0, 0xA0, 0x0F, 0, 0, 0x9E, 0x26} // 5 and 4 m3, 2020-06-30
	scr := diehlUnscramble(diehlSeed(testScramble2, tg, [3]byte{0x01, 0x1D, 0x00}), plain)
	f = append(f, scr...)
	f[0] = byte(len(f) - 1)
	r := read(t, f, nil)
	if r.Driver != "diehl-izar" {
		t.Fatalf("%+v", r)
	}
	want(t, r, "volume", 5.0)
	want(t, r, "volume_billing_date", 4.0)
	want(t, r, "billing_date", "2020-06-30")
	want(t, r, "battery_remaining", 14.5)
	want(t, r, "transmit_period", 8.0)
	want(t, r, "alarms", "none")
	want(t, r, "manufacture_year", "2021")
}

func TestBFWAndZenner(t *testing.T) {
	p := []byte{0x7A, 1, 0, 0, 0, 0x2F, 0x2F, 0x11, 0x22, 0x02, 0x00, 0x01, 0x01, 0x00, 0x00}
	for k := 0; k < 9; k++ {
		e := []byte{0, 0, 0}
		if k == 8 {
			e = []byte{0x10, 0x23, 0x05}
		}
		p = append(p, e...)
	}
	p = append(p, 0x15, 0x06, 0x24)
	r := read(t, frame(t, "BFW", 11112222, 0x02, 0x08, p...), nil)
	want(t, r, "hca_units", 257.0)
	want(t, r, "hca_units_billing_date", 512.0)
	want(t, r, "hca_units_month_1", 773.0)
	want(t, r, "hca_units_month_2", 528.0)
	want(t, r, "device_date", "2024-06-15")

	r = read(t, frame(t, "ZRI", 11223344, 0x0B, 0x16, 0x7A, 0x05, 0, 0, 0, 0x2F, 0x2F, 0x0F, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0x30, 0), nil)
	want(t, r, "volume", 12.288)
	want(t, r, "volume_billing_date", 8.192)
	want(t, r, "status", "ok")
}

func mustHeader(t *testing.T, f []byte) wireless.Header {
	t.Helper()
	h, err := wireless.ParseHeader(f)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestQundisWalkBy(t *testing.T) {
	data := make([]byte, 28)
	copy(data[12:], []byte{0x56, 0x34, 0x12, 0x00}) // 123456 litres
	copy(data[16:], []byte{0x9F, 0x2C})             // 2020-12-31
	copy(data[18:], []byte{0x00, 0x00, 0x10, 0x00}) // 100000 litres
	copy(data[22:], []byte{0xAF, 0x26})             // 2021-06-15
	copy(data[24:], []byte{0x00, 0x00, 0x11, 0x00}) // 110000 litres
	rec := append([]byte{0x0D, 0xFF, 0x5F, byte(len(data))}, data...)
	r := read(t, frame(t, "QDS", 12345678, 0x35, 0x07, append([]byte{0x78}, rec...)...), nil)
	if r.Driver != "qundis-q-water" {
		t.Fatalf("%+v", r)
	}
	want(t, r, "volume", 123.456)
	want(t, r, "due_date", "2020-12-31")
	want(t, r, "volume_due_date", 100.0)
	want(t, r, "half_month_date", "2021-06-15")
	want(t, r, "volume_half_month_date", 110.0)
}

// Test keys of our own: the library ships no maker keys, and these are
// not any maker's.
var (
	testScramble1 = []byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE}
	testScramble2 = []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
)

func setTestMakerKeys() {
	SetMakerKeys(MakerKeys{DiehlScrambling: [][]byte{testScramble1, testScramble2}, DiehlAES: append(append([]byte(nil), testScramble2...), testScramble1...)})
}

func TestMain(m *testing.M) {
	setTestMakerKeys()
	os.Exit(m.Run())
}
