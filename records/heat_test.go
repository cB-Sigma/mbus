// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package records

import (
	"math"
	"testing"
)

// Heat meter records written for this test from EN 13757-3:2025 tables
// (no third-party telegram): an energy in 12-digit BCD with VIF 01h
// (0.01 Wh), stored energies of storage 1 (binary) and storage 17 (a
// DIFE), a date of storage 1 that is all ones (no date: invalid), an
// external temperature, the operating time in days and manufacturer
// data. Stored values keep their own names, so they never overwrite the
// current ones.
func TestHeatMeterRecordsSelfMade(t *testing.T) {
	recs, err := ParseRecords(hx(t, "0E01 641320000000"+"4406 E8030000"+"C40806 10270000"+"426C FFFF"+"0265 B40E"+"0227 ED02"+"0F 0102"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Record{}
	for _, r := range recs {
		got[r.Name()+"|"+r.Unit] = r
	}
	for k, w := range map[string]float64{
		"energy|Wh": 2013.64, "energy_s1|Wh": 1e6, "energy_s17|Wh": 1e7,
		"external_temperature|Cel": 37.64, "operating_time|d": 749,
	} {
		r, ok := got[k]
		v, isF := r.Value.(float64)
		if i, isI := r.Value.(int64); isI {
			v, isF = float64(i), true
		}
		if !ok || !isF || math.Abs(v-w) > 1e-6*math.Max(1, w) {
			t.Errorf("%s = %v, want %v (all %v)", k, r.Value, w, keysOf(recordMap(recs)))
		}
	}
	if d := got["date_s1|"]; !d.Invalid || d.Quality() != "invalid" {
		t.Errorf("all-ones date: %v %q", d.Value, d.Quality())
	}
	if m := recs[len(recs)-1]; m.DIF != 0x0F || len(m.Raw) != 2 {
		t.Errorf("manufacturer data %+v", m)
	}
}
