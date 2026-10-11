// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package meters

import (
	"github.com/cB-Sigma/mbus/records"
	"github.com/cB-Sigma/mbus/wireless"
)

// Qundis meters send a "walk-by" manufacturer record (variable length,
// VIF FFh, VIFE 5Fh) beside their standard records: from its byte 12 the
// current reading (8 BCD digits), the last due date (type G), the reading
// at it, the half-month date (type G) and the reading then; byte 9
// names the unit (litres, kWh or allocator units); without it a heat
// meter counts 0.1 kWh (the older Q heat).

func qundisWalkBy(scale float64, unit, quantity string) func(*wireless.Telegram, error, *Reading) error {
	return func(tg *wireless.Telegram, err error, r *Reading) error {
		if err != nil {
			return err
		}
		for _, rec := range tg.Records {
			if rec.DIF&0x0F != 0x0D || rec.VIF != 0xFF || len(rec.VIFE) == 0 || rec.VIFE[0]&0x7F != 0x5F || len(rec.Raw) < 28 {
				continue
			}
			p := rec.Raw
			// Byte 9 is the VIF of the readings where it is a known one: litres
			// (13h), kWh (06h) or heat cost allocation units (6Eh).
			scale, unit, quantity := scale, unit, quantity
			switch p[9] {
			case 0x13:
				scale, unit, quantity = 0.001, "m3", "volume"
			case 0x06:
				scale, unit, quantity = 1, "kWh", "energy"
			case 0x6E:
				scale, unit, quantity = 1, "", "hca_units"
			}
			bcd := func(b []byte) (float64, bool) {
				var v float64
				for i := len(b) - 1; i >= 0; i-- {
					hi, lo := b[i]>>4, b[i]&0x0F
					if hi > 9 || lo > 9 {
						return 0, false
					}
					v = v*100 + float64(hi)*10 + float64(lo)
				}
				return v, true
			}
			if _, has := r.Get(quantity); !has {
				if v, ok := bcd(p[12:16]); ok {
					r.set(quantity, round(v*scale, 6), unit)
				}
			}
			if d := records.TypeG(p[16:18]); d != "" {
				r.set("due_date", d, "")
			}
			if v, ok := bcd(p[18:22]); ok {
				r.set(quantity+"_due_date", round(v*scale, 6), unit)
			}
			if d := records.TypeG(p[22:24]); d != "" {
				r.set("half_month_date", d, "")
			}
			if v, ok := bcd(p[24:28]); ok {
				r.set(quantity+"_half_month_date", round(v*scale, 6), unit)
			}
			return nil
		}
		return nil
	}
}

func init() {
	water := ByName("qundis-q-water")
	water.Decode = qundisWalkBy(0.001, "m3", "volume")
	heat := ByName("qundis-q-heat")
	heat.Decode = qundisWalkBy(0.1, "kWh", "energy")
	ByName("qundis-q-caloric").Decode = qundisWalkBy(1, "", "hca_units")
}
