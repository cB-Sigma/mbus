// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package records

// statusBits names bits 2 to 7 of the TPL status byte (EN 13757-7:2025
// 7.5.6, used by EN 13757-3:2025 10.2 for wired M-Bus).
var statusBits = [...]string{2: "power_low", 3: "permanent_error", 4: "temporary_error",
	5: "manufacturer_5", 6: "manufacturer_6", 7: "manufacturer_7"}

// StatusFlags names the set bits of a TPL status byte: the application
// state of bits 0-1 (01 busy, 10 error, 11 abnormal condition) and then
// each of bits 2 to 7 that is set, in bit order. No bit set gives an
// empty, non-nil slice so the value is written as [].
func StatusFlags(s byte) []string {
	out := []string{}
	switch s & 0x03 {
	case 1:
		out = append(out, "application_busy")
	case 2:
		out = append(out, "application_error")
	case 3:
		out = append(out, "abnormal_condition")
	}
	for bit := 2; bit < 8; bit++ {
		if s&(1<<bit) != 0 {
			out = append(out, statusBits[bit])
		}
	}
	return out
}
