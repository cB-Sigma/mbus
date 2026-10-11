// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package meters

import (
	"bytes"
	"fmt"

	"github.com/cB-Sigma/mbus/wireless"
)

// recordsPayload returns the application data of a telegram whose data
// is not M-Bus records (the decoder's records error), or the error.
func recordsPayload(tg *wireless.Telegram, err error) ([]byte, error) {
	if err != nil && !recordsErr(err) {
		return nil, err
	}
	return tg.APL, nil
}

func recordsErr(err error) bool {
	s := err.Error()
	return len(s) > 7 && s[:7] == "record "
}

// bcd2 is one byte of two BCD digits.
func bcd2(b byte) int { return int(b>>4)*10 + int(b&0x0F) }

func init() {
	Register(&Driver{
		Name: "bfw-240-radio", Model: "BFW 240 radio heat cost allocator",
		Detect: []MVT{{"BFW", 0x02, 0x08}},
		Decode: func(tg *wireless.Telegram, err error, r *Reading) error {
			p, err := recordsPayload(tg, err)
			if err != nil {
				return err
			}
			if err := need(p, 40); err != nil {
				return err
			}
			// After 2F2F and two bytes: units at the last billing date and
			// now (high byte first), two bytes, nine 3-byte entries of two
			// 12-bit monthly values each (oldest first), and the date in
			// BCD (day, month, year).
			r.set("hca_units", float64(int(p[6])<<8|int(p[7])), "")
			r.set("hca_units_billing_date", float64(int(p[4])<<8|int(p[5])), "")
			for k := 0; k < 9; k++ {
				e := p[10+3*k : 13+3*k]
				back := 2 * (8 - k)
				r.set(fmt.Sprintf("hca_units_month_%d", back+1), float64(int(e[1]&0x0F)<<8|int(e[2])), "")
				r.set(fmt.Sprintf("hca_units_month_%d", back+2), float64(int(e[1]>>4)<<8|int(e[0])), "")
			}
			r.set("device_date", ymd(2000+bcd2(p[39]), bcd2(p[38]), bcd2(p[37])), "")
			return nil
		},
	})
	Register(&Driver{
		Name: "zenner-0b", Model: "Zenner water meter (version 0Bh)",
		Detect: []MVT{{"ZRI", 0x0B, 0x16}},
		Decode: func(tg *wireless.Telegram, err error, r *Reading) error {
			if err != nil {
				return err
			}
			p, ok := mfctRecord(tg)
			if !ok {
				return nil
			}
			if err := need(p, 12); err != nil {
				return err
			}
			// A status word, then the volume at the billing date and now,
			// in 1/256 litres.
			st := le(p[0:4])
			if st == 0 {
				r.set("status", "ok", "")
			} else {
				r.set("status", fmt.Sprintf("status_%X", st), "")
			}
			r.set("volume_billing_date", round(float64(le(p[4:8]))/256000, 6), "m3")
			r.set("volume", round(float64(le(p[8:12]))/256000, 6), "m3")
			return nil
		},
	})
	Register(&Driver{
		Name: "bmeters-rfm-tx1", Model: "B METERS RFM-TX1 water meter module",
		Detect: []MVT{{"BMT", 0x05, 0x07}},
		Decode: func(tg *wireless.Telegram, err error, r *Reading) error {
			p := tg.APL
			if err == nil {
				return nil
			}
			if len(p) < 19 || bytes.Equal(p, nil) {
				return err
			}
			// The configuration field announces a mode outside EN 13757-7.
			// Bytes 13-18: the meter's time in BCD (seconds first, year
			// last). The volume in bytes 2-5 is obfuscated with a table we
			// have no public description of, so it is not read.
			r.set("meter_datetime", fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d",
				2000+bcd2(p[18]), bcd2(p[17]), bcd2(p[16]), bcd2(p[15]), bcd2(p[14]), bcd2(p[13])), "")
			return nil
		},
	})
}
