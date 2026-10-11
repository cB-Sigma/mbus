package records

import (
	"encoding/json"
	"reflect"
	"testing"
)

// EN 13757-7:2025 7.5.6: bits 0-1 are the application state, bit 2 power
// low, bit 3 permanent error, bit 4 temporary error, bits 5-7 manufacturer
// specific.
//
// Covers: SIG-IPE-2735
func TestStatusFlagsBits(t *testing.T) {
	for _, tc := range []struct {
		s    byte
		want []string
	}{
		{0x00, []string{}},
		{0x01, []string{"application_busy"}},
		{0x02, []string{"application_error"}},
		{0x03, []string{"abnormal_condition"}},
		{0x04, []string{"power_low"}},
		{0x08, []string{"permanent_error"}},
		{0x10, []string{"temporary_error"}},
		{0x20, []string{"manufacturer_5"}},
		{0x40, []string{"manufacturer_6"}},
		{0x80, []string{"manufacturer_7"}},
		{0x1C, []string{"power_low", "permanent_error", "temporary_error"}},
		{0x95, []string{"application_busy", "power_low", "temporary_error", "manufacturer_7"}},
		{0xE2, []string{"application_error", "manufacturer_5", "manufacturer_6", "manufacturer_7"}},
		{0xFF, []string{"abnormal_condition", "power_low", "permanent_error", "temporary_error", "manufacturer_5", "manufacturer_6", "manufacturer_7"}},
	} {
		if got := StatusFlags(tc.s); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("StatusFlags(%02X) = %q, want %q", tc.s, got, tc.want)
		}
	}
	// Every combination: each bit maps to its own name and nothing else.
	app := [4]string{"", "application_busy", "application_error", "abnormal_condition"}
	names := [8]string{2: "power_low", 3: "permanent_error", 4: "temporary_error", 5: "manufacturer_5", 6: "manufacturer_6", 7: "manufacturer_7"}
	for s := 0; s < 256; s++ {
		want := []string{}
		if a := app[s&3]; a != "" {
			want = append(want, a)
		}
		for bit := 2; bit < 8; bit++ {
			if s&(1<<bit) != 0 {
				want = append(want, names[bit])
			}
		}
		got := StatusFlags(byte(s))
		if !reflect.DeepEqual(got, want) {
			t.Errorf("StatusFlags(%02X) = %q, want %q", s, got, want)
		}
		if b, _ := json.Marshal(got); s == 0 && string(b) != "[]" {
			t.Errorf("no bit set is written as %s, want []", b)
		}
	}
}
