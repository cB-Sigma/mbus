// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package meters

import (
	"errors"
	"fmt"

	"github.com/cB-Sigma/mbus/wireless"
)

// Techem (TCH) meters send their readings after a manufacturer-specific
// CI field (A0h to A2h) in their own fixed layouts.

// mfctPayload returns the bytes after a manufacturer-specific CI field,
// or the decoder's error when the telegram is not of that kind.
func mfctPayload(tg *wireless.Telegram, err error) ([]byte, error) {
	if errors.Is(err, wireless.ErrManufacturerCI) || (err == nil && tg.CI >= 0xA0 && tg.CI <= 0xB7) {
		return tg.APL, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("CI field 0x%02X is not a manufacturer-specific one", tg.CI)
}

// techemCurrentDate is the current date of the radio 3 and FHKV layouts:
// day in bits 4-8, month in bits 9-12 and no year; the year is the
// previous billing date's, or the next one when the day falls on or
// before the billing date in the year.
func techemCurrentDate(cur uint64, prevYear, prevMonth, prevDay int, fixZero bool) string {
	d, m := int(cur>>4&0x1F), int(cur>>9&0x0F)
	if fixZero {
		if d == 0 {
			d = 1
		}
		if m == 0 {
			m = 12
		}
	}
	y := prevYear
	if m < prevMonth || m == prevMonth && d <= prevDay {
		y++
	}
	return ymd(y, m, d)
}

// techemTypes maps Techem's own device type codes to EN 13757-3 ones.
var techemTypes = map[byte]byte{0x43: 0x04, 0xC3: 0x04, 0x62: 0x06, 0x72: 0x16, 0x80: 0x08, 0xF0: 0x1A}

func init() {
	Register(&Driver{
		Name: "techem-compact5", Model: "Techem compact V heat meter",
		Detect:      []MVT{{"TCH", 0x45, 0x04}, {"TCH", 0x45, 0xC3}, {"TCH", 0x22, 0x43}, {"TCH", 0x45, 0x43}, {"TCH", 0x39, 0x43}},
		DeviceTypes: techemTypes,
		Decode: func(tg *wireless.Telegram, err error, r *Reading) error {
			p, err := mfctPayload(tg, err)
			if err != nil {
				return err
			}
			if err := need(p, 10); err != nil {
				return err
			}
			// Bytes 3-5: the energy of the previous period, 7-9: of the
			// current one, both in kWh.
			prev, cur := float64(le(p[3:6])), float64(le(p[7:10]))
			r.set("energy", prev+cur, "kWh")
			r.set("energy_current_period", cur, "kWh")
			r.set("energy_previous_period", prev, "kWh")
			return nil
		},
	})
	Register(&Driver{
		Name: "techem-vario451", Model: "Techem vario 4 heat meter",
		Detect:      []MVT{{"TCH", 0x27, 0x04}, {"TCH", 0x27, 0xC3}},
		DeviceTypes: techemTypes,
		Decode: func(tg *wireless.Telegram, err error, r *Reading) error {
			p, err := mfctPayload(tg, err)
			if err != nil {
				return err
			}
			if err := need(p, 9); err != nil {
				return err
			}
			// Bytes 3-4 and 7-8: previous and current period in units of
			// 1/3.6 kWh (MJ).
			prev, cur := float64(le(p[3:5]))/3.6, float64(le(p[7:9]))/3.6
			r.set("energy", round(prev+cur, 6), "kWh")
			r.set("energy_current_period", round(cur, 6), "kWh")
			r.set("energy_previous_period", round(prev, 6), "kWh")
			return nil
		},
	})
	radio3 := func(tg *wireless.Telegram, err error, r *Reading) error {
		p, err := mfctPayload(tg, err)
		if err != nil {
			return err
		}
		if err := need(p, 9); err != nil {
			return err
		}
		// Byte 1-2: billing date; 3-4: volume at it (0.1 m3); 5-6: current
		// date; 7-8: volume since the billing date (0.1 m3).
		pd := le(p[1:3])
		prevY, prevM, prevD := 2000+int(pd>>9), int(pd>>5&0x0F), int(pd&0x1F)
		target, cur := float64(le(p[3:5]))/10, float64(le(p[7:9]))/10
		r.set("volume", round(target+cur, 3), "m3")
		r.set("volume_billing_date", target, "m3")
		r.set("volume_since_billing_date", cur, "m3")
		r.set("billing_date", ymd(prevY, prevM, prevD), "")
		r.set("current_date", techemCurrentDate(le(p[5:7]), prevY, prevM, prevD, false), "")
		return nil
	}
	Register(&Driver{
		Name: "techem-radio3", Model: "Techem radio 3 water meter",
		Detect:      []MVT{{"TCH", 0x74, 0x62}, {"TCH", 0x74, 0x72}},
		DeviceTypes: techemTypes,
		Decode:      radio3,
	})
	Register(&Driver{
		Name: "techem-radio3-legacy", Model: "Techem radio 3 water meter (older layout with monthly values)",
		Detect:      []MVT{{"TCH", 0x50, 0x72}},
		DeviceTypes: techemTypes,
		Decode: func(tg *wireless.Telegram, err error, r *Reading) error {
			p, err := mfctPayload(tg, err)
			if err != nil {
				return err
			}
			if err := need(p, 8+3*12); err != nil {
				return err
			}
			// Bytes 2-3: the current date; 4-6: the volume (0.1 m3); from
			// byte 8, twelve 2-byte entries 3 bytes apart, each holding two
			// half-month volumes (0.1 m3), newest first. A month's volume
			// is the two halves of its entry after the 15th, else the
			// second half of the entry before and the first of its own.
			cd := le(p[2:4])
			r.set("volume", float64(le(p[4:7]))/10, "m3")
			r.set("current_date", packedDate(cd), "")
			late := cd&0x1F > 15
			half := func(k int) (lo, hi uint64) { return uint64(p[8+3*k]), uint64(p[9+3*k]) }
			for k := 0; k < 12; k++ {
				lo, hi := half(k)
				v := lo + hi
				if !late {
					if k == 0 {
						v = lo
					} else {
						_, prevHi := half(k - 1)
						v = prevHi + lo
					}
				}
				r.set(fmt.Sprintf("volume_month_%d", k), float64(v)/10, "m3")
			}
			return nil
		},
	})
	Register(&Driver{
		Name: "techem-radio4", Model: "Techem radio 4 water meter",
		Detect:      []MVT{{"TCH", 0x95, 0x62}, {"TCH", 0x70, 0x62}, {"TCH", 0x95, 0x72}, {"TCH", 0x70, 0x72}},
		DeviceTypes: techemTypes,
		Decode: func(tg *wireless.Telegram, err error, r *Reading) error {
			p, err := mfctPayload(tg, err)
			if err != nil {
				return err
			}
			if err := need(p, 9); err != nil {
				return err
			}
			// Bytes 3-4: volume at the billing date, 7-8: since then,
			// both in 0.1 m3.
			target, cur := float64(le(p[3:5]))/10, float64(le(p[7:9]))/10
			r.set("volume", round(target+cur, 3), "m3")
			r.set("volume_billing_date", target, "m3")
			r.set("volume_since_billing_date", cur, "m3")
			return nil
		},
	})
	Register(&Driver{
		Name: "techem-fhkv-data-3", Model: "Techem FHKV data III heat cost allocator",
		Detect:      []MVT{{"TCH", 0x69, 0x80}, {"TCH", 0x94, 0x80}},
		DeviceTypes: techemTypes,
		Decode: func(tg *wireless.Telegram, err error, r *Reading) error {
			p, err := mfctPayload(tg, err)
			if err != nil {
				return err
			}
			if err := need(p, 13); err != nil {
				return err
			}
			// Byte 0 is the layout: 01h and 11h, or 0Fh with one more byte
			// before the temperatures. Then billing date, units at it,
			// current date, units now, room and radiator temperature
			// (0.01 Cel).
			t := 9
			switch p[0] {
			case 0x01, 0x11:
			case 0x0F:
				t = 10
			default:
				return fmt.Errorf("FHKV data III: layout 0x%02X not known", p[0])
			}
			if err := need(p, t+4); err != nil {
				return err
			}
			pd := le(p[1:3])
			prevY, prevM, prevD := 2000+int(pd>>9), int(pd>>5&0x0F), int(pd&0x1F)
			r.set("hca_units", float64(le(p[7:9])), "")
			r.set("hca_units_billing_date", float64(le(p[3:5])), "")
			r.set("billing_date", ymd(prevY, prevM, prevD), "")
			r.set("current_date", techemCurrentDate(le(p[5:7]), prevY, prevM, prevD, true), "")
			r.set("room_temperature", float64(le(p[t:t+2]))/100, "Cel")
			r.set("radiator_temperature", float64(le(p[t+2:t+4]))/100, "Cel")
			return nil
		},
	})
	Register(&Driver{
		Name: "techem-smoke-tsd2", Model: "Techem smoke detector TSD2",
		Detect:      []MVT{{"TCH", 0x76, 0xF0}},
		DeviceTypes: techemTypes,
		Decode: func(tg *wireless.Telegram, err error, r *Reading) error {
			p, err := mfctPayload(tg, err)
			if err != nil {
				return err
			}
			if err := need(p, 3); err != nil {
				return err
			}
			// Byte 0: state (0 normal, 1 smoke alarm); bytes 1-2: the
			// last billing date.
			state := "ok"
			switch p[0] {
			case 0:
			case 1:
				state = "smoke"
			default:
				state = fmt.Sprintf("state_%02X", p[0])
			}
			r.set("status", state, "")
			r.set("billing_date", packedDate(le(p[1:3])), "")
			return nil
		},
	})
}
