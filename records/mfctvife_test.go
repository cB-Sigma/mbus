// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package records

import (
	"encoding/hex"
	"math"
	"strings"
	"testing"
)

// A standard VIF followed by a manufacturer-specific VIFE: Value stays
// raw, BaseValue is what the VIF alone says.
func TestManufacturerVIFEBaseValue(t *testing.T) {
	for _, tc := range []struct {
		hex  string
		raw  string
		base float64
		unit string
	}{
		{"02 93 FF 20 3412", "1234", 4.66, "m3"},      // volume 1e-3 m3, VIFE FF 20
		{"02 FD C8 FF 01 1009", "0910", 232.0, "V"},   // voltage 1e-1 V, phase-like VIFE
		{"02 AC FF 01 F6FF", "FFF6", -100, "W"},       // power 10 W, signed
		{"04 94 7F 25000000", "00000025", 0.37, "m3"}, // volume 1e-2 m3, VIFE 7F
	} {
		b, _ := hex.DecodeString(strings.ReplaceAll(tc.hex, " ", ""))
		recs, err := ParseRecords(b)
		if err != nil || len(recs) != 1 {
			t.Fatalf("%s: %v %+v", tc.hex, err, recs)
		}
		r := recs[0]
		v, ok := r.BaseValue.(float64)
		if !r.Manufacturer || r.Value != tc.raw || !ok || math.Abs(v-tc.base) > 1e-9 || r.Unit != tc.unit {
			t.Errorf("%s: value %v base %v unit %q", tc.hex, r.Value, r.BaseValue, r.Unit)
		}
	}
	// No manufacturer VIFE: no base value.
	recs, _ := ParseRecords([]byte{0x04, 0x13, 0x39, 0x30, 0, 0})
	if recs[0].BaseValue != nil {
		t.Errorf("plain record: %v", recs[0].BaseValue)
	}
}
