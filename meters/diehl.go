// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package meters

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/cB-Sigma/mbus/records"
	"github.com/cB-Sigma/mbus/wireless"
)

// The Diehl group (Diehl Metering, Hydrometer, Sappel and their brands:
// M fields DME, EWT, HYD, SAP, SPL) has a scheme of its own beside OMS:
//
//   - PRIOS telegrams (IZAR radio modules) carry a manufacturer CI field
//     (A0h to A7h) and a payload scrambled with a 32-bit linear feedback
//     shift register seeded from a key and the telegram's header;
//   - "real data" telegrams (CI 7Ah or 71h with bit 12 of the configuration
//     field set, a security mode EN 13757-7 reserves) carry ordinary data
//     records scrambled the same way, with a checksum;
//   - in both, the A field is sent with the version and device type first
//     (Sappel's PRIOS modules use the version byte as a fifth ID byte).
//
// The makers use default scrambling keys and a default AES key for their
// OMS telegrams. This library ships no keys: the caller supplies them
// with SetMakerKeys (or the meter's own key through ReadKeys).

var diehlMakers = map[string]bool{"DME": true, "EWT": true, "HYD": true, "SAP": true, "SPL": true}

// MakerKeys are manufacturers' default keys a caller supplies; the
// library ships none.
type MakerKeys struct {
	// DiehlScrambling are 8-byte keys of the Diehl group's PRIOS and
	// real-data scrambling, tried in order after the meter's own key.
	DiehlScrambling [][]byte
	// DiehlAES is the 16-byte default AES key of the Diehl group's OMS
	// telegrams, given by DefaultKey.
	DiehlAES []byte
}

var (
	makerMu   sync.RWMutex
	makerKeys MakerKeys
)

// SetMakerKeys sets the manufacturers' default keys the drivers may try
// (nil fields: none).
func SetMakerKeys(k MakerKeys) {
	makerMu.Lock()
	defer makerMu.Unlock()
	makerKeys = MakerKeys{DiehlAES: append([]byte(nil), k.DiehlAES...)}
	for _, s := range k.DiehlScrambling {
		if len(s) >= 8 {
			makerKeys.DiehlScrambling = append(makerKeys.DiehlScrambling, append([]byte(nil), s[:8]...))
		}
	}
}

// DefaultKey returns the maker's default AES-128 key a caller set with
// SetMakerKeys for a meter (today the Diehl group's), or nil. Use it in a
// wireless.KeyLookup when the meter's own key is not known.
func DefaultKey(h wireless.Header) []byte {
	if !diehlMakers[h.Manufacturer] {
		return nil
	}
	makerMu.RLock()
	defer makerMu.RUnlock()
	if len(makerKeys.DiehlAES) != 16 {
		return nil
	}
	return append([]byte(nil), makerKeys.DiehlAES...)
}

type diehlKind int

const (
	diehlNone diehlKind = iota
	diehlKindRealData
	diehlPrios
	diehlSapPrios
)

func diehlKindOf(tg *wireless.Telegram) diehlKind {
	if !diehlMakers[tg.Header.Manufacturer] || (tg.C != 0x44 && tg.C != 0x46) {
		return diehlNone
	}
	switch {
	case tg.CI == wireless.CIAlarm:
		return diehlKindRealData
	case tg.CI == wireless.CIShortHeader && tg.Config&0x1000 != 0:
		return diehlKindRealData
	case tg.CI >= 0xA0 && tg.CI <= 0xA7:
		if tg.Header.Manufacturer == "SAP" {
			return diehlSapPrios
		}
		return diehlPrios
	}
	return diehlNone
}

// diehlHeader rearranges a Diehl telegram's address as the maker sends it.
func diehlHeader(tg *wireless.Telegram) (wireless.Header, bool) {
	h := tg.Header
	switch diehlKindOf(tg) {
	case diehlKindRealData, diehlPrios:
		a := h.A
		h.Version, h.DeviceType = a[0], a[1]
		copy(h.A[:4], a[2:6])
		h.A[4], h.A[5] = a[0], a[1]
		h.ID = wireless.BCDID(h.A[:4])
		return h, true
	case diehlSapPrios:
		h.Version, h.DeviceType = 0x00, 0x07 // a water meter; the version byte is part of the ID
		return h, true
	}
	return h, false
}

// diehlSeed is the register's start: the key's two halves and the first
// twelve bytes after the L field, as big-endian words, all XORed.
func diehlSeed(key []byte, tg *wireless.Telegram, afterCI [3]byte) uint32 {
	k := binary.BigEndian.Uint32(key[:4]) ^ binary.BigEndian.Uint32(key[4:8])
	var head [12]byte
	head[0] = tg.C
	binary.LittleEndian.PutUint16(head[1:3], tg.Header.MField)
	copy(head[3:9], tg.Header.A[:])
	head[9] = tg.CI
	copy(head[10:12], afterCI[:2])
	// Words at frame offsets 2, 6 and 10 (L is offset 0).
	frame := append([]byte{0}, head[:]...)
	frame = append(frame, afterCI[2])
	return k ^ binary.BigEndian.Uint32(frame[2:6]) ^ binary.BigEndian.Uint32(frame[6:10]) ^ binary.BigEndian.Uint32(frame[10:14])
}

// diehlUnscramble runs the register: eight steps per byte (feedback from
// bits 1, 2, 11 and 31), then XOR with its low byte.
func diehlUnscramble(seed uint32, in []byte) []byte {
	out := make([]byte, len(in))
	r := seed
	for i, b := range in {
		for range 8 {
			bit := (r>>1 ^ r>>2 ^ r>>11 ^ r>>31) & 1
			r = r<<1 | bit
		}
		out[i] = b ^ byte(r)
	}
	return out
}

// diehlKeys are the scrambling keys to try: the caller's (its first eight
// bytes), then the maker keys the caller set (SetMakerKeys).
func diehlKeys(r *Reading) [][]byte {
	var ks [][]byte
	if k := r.key(); len(k) >= 8 {
		ks = append(ks, k[:8])
	}
	makerMu.RLock()
	defer makerMu.RUnlock()
	return append(ks, makerKeys.DiehlScrambling...)
}

// ErrNoScramblingKey is returned for a Diehl scrambled telegram when no
// key is known: supply the meter's key (ReadKeys) or the maker's keys
// (SetMakerKeys, MakerKeys.DiehlScrambling).
var ErrNoScramblingKey = errors.New("Diehl scrambled telegram: no scrambling key; supply one with meters.SetMakerKeys (MakerKeys.DiehlScrambling) or the meter's key through ReadKeys")

// ErrDiehlCheck is returned when no key unscrambles a Diehl telegram to
// data that passes its check.
var ErrDiehlCheck = errors.New("Diehl scrambled data: no key passes the check")

// AcceptPlainDiehl reads a Diehl "real data" telegram whose payload fails
// the check as already plain records when they decode to the end. Off by
// default; test data that stores telegrams unscrambled (as wmbusmeters'
// does) needs it.
var AcceptPlainDiehl = false

// diehlKindRealData unscrambles a real-data telegram's records.
func diehlRealData(tg *wireless.Telegram, r *Reading) error {
	p := tg.APL
	var after [3]byte
	after[0], after[1] = tg.Access, tg.Status
	after[2] = byte(tg.Config)
	check := byte(tg.Config>>8) & 0xEF
	for _, k := range diehlKeys(r) {
		dec := diehlUnscramble(diehlSeed(k, tg, after), p)
		var sum uint32
		for _, b := range dec {
			sum += uint32(b)
		}
		if byte(sum)&0xEF != check {
			continue
		}
		recs, err := records.ParseRecords(dec)
		r.addRecords(recs)
		r.set("diehl_scrambling", "unscrambled", "")
		return err
	}
	if AcceptPlainDiehl {
		if recs, err := records.ParseRecords(p); err == nil && len(recs) > 0 {
			r.addRecords(recs)
			r.set("diehl_scrambling", "not scrambled", "")
			return nil
		}
	}
	if len(diehlKeys(r)) == 0 {
		return ErrNoScramblingKey
	}
	return ErrDiehlCheck
}

// diehlGeneric reads any Diehl-group meter: real data telegrams are
// unscrambled into records; others are the decoder's.
func diehlGeneric(tg *wireless.Telegram, err error, r *Reading) error {
	if diehlKindOf(tg) == diehlKindRealData && errors.Is(err, wireless.ErrSecurityMode) {
		return diehlRealData(tg, r)
	}
	if (diehlKindOf(tg) == diehlPrios || diehlKindOf(tg) == diehlSapPrios) && errors.Is(err, wireless.ErrManufacturerCI) {
		return izar(tg, err, r)
	}
	return err
}

// izar reads an IZAR (PRIOS) water meter radio module's telegram.
func izar(tg *wireless.Telegram, err error, r *Reading) error {
	if kind := diehlKindOf(tg); kind != diehlPrios && kind != diehlSapPrios {
		return diehlGeneric(tg, err, r)
	}
	p := tg.APL
	if err := need(p, 9); err != nil {
		return err
	}
	var dec []byte
	for _, k := range diehlKeys(r) {
		d := diehlUnscramble(diehlSeed(k, tg, [3]byte{p[0], p[1], p[2]}), p[4:])
		if d[0] == 0x4B {
			dec = d
			break
		}
	}
	if dec == nil {
		if len(diehlKeys(r)) == 0 {
			return ErrNoScramblingKey
		}
		return ErrDiehlCheck
	}
	// Bytes 0-2 before the scrambled part: alarms, battery and the
	// transmission period. Unscrambled: a check byte (4Bh), the volume in
	// litres, the volume at the billing date and that date (type G).
	r.set("volume", float64(le(dec[1:5]))/1000, "m3")
	if len(dec) > 8 {
		r.set("volume_billing_date", float64(le(dec[5:9]))/1000, "m3")
	}
	if len(dec) > 10 {
		y := int(dec[10]&0xF0)>>1 | int(dec[9]&0xE0)>>5
		if y > 80 {
			y += 1900
		} else {
			y += 2000
		}
		r.set("billing_date", ymd(y, int(dec[10]&0x0F), int(dec[9]&0x1F)), "")
	}
	r.set("battery_remaining", float64(p[1]&0x1F)/2, "a")
	r.set("transmit_period", float64(int(1)<<(p[0]&0x0F+2)), "s")
	st := uint64(p[0]) | uint64(p[1])<<8 | uint64(p[2])<<16
	r.set("alarms", flags(st&0xFFE000, map[uint64]string{
		0x002000: "meter_blocked", 0x004000: "leak_earlier", 0x008000: "leak",
		0x010000: "mechanical_tamper_earlier", 0x020000: "mechanical_tamper",
		0x040000: "sensor_tamper_earlier", 0x080000: "sensor_tamper",
		0x100000: "submarine", 0x200000: "overflow", 0x400000: "underflow", 0x800000: "backflow",
	}, "none"), "")
	r.set("general_alarm", p[0]&0x80 != 0, "")
	if diehlKindOf(tg) == diehlSapPrios {
		// The printed serial: year of manufacture and six digits from the
		// ID bytes, letters from the rest of the A field.
		a := tg.Header.A
		digits := uint32(a[3]&0x03)<<24 | uint32(a[2])<<16 | uint32(a[1])<<8 | uint32(a[0])
		yy := digits / 1000000 % 100
		year := 2000 + yy
		if yy > 70 {
			year = 1900 + yy
		}
		r.set("manufacture_year", fmt.Sprintf("%d", year), "")
		r.set("serial_number", fmt.Sprintf("%06d", digits%1000000), "")
		letter := func(v byte) byte { return '@' + v }
		r.set("prefix", fmt.Sprintf("%c%02d%c%c", letter((a[5]&0x0F)<<1|a[4]>>7), yy, letter((a[4]&0x7C)>>2), letter((a[4]&0x03)<<3|a[3]>>5)), "")
	}
	return nil
}

func init() {
	for m := range diehlMakers {
		Register(&Driver{Name: "diehl", Model: "Diehl group meter", Detect: []MVT{{m, -1, -1}}, Decode: diehlGeneric})
	}
	Register(&Driver{
		Name: "diehl-izar", Model: "Diehl IZAR water meter radio module (PRIOS)",
		Detect: []MVT{{"HYD", 0x85, 0x07}, {"HYD", 0x86, 0x07}, {"SAP", -1, 0x15}, {"SAP", -1, 0x04}, {"SAP", 0x00, 0x07}, {"DME", 0x78, 0x07}, {"DME", 0x78, 0x06}},
		Decode: izar,
	})
}
