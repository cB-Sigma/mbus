// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package records

import (
	"fmt"
	"strings"
)

// ManufacturerCode turns an M field into its three letters (EN 13757-3:
// each letter is its ASCII code minus 64, in five bits, first letter
// highest).
func ManufacturerCode(m uint16) string {
	b := []byte{byte(m>>10&0x1F) + 64, byte(m>>5&0x1F) + 64, byte(m&0x1F) + 64}
	for _, c := range b {
		if c < 'A' || c > 'Z' {
			return fmt.Sprintf("%04X", m)
		}
	}
	return string(b)
}

// ManufacturerField is ManufacturerCode's inverse.
func ManufacturerField(code string) (uint16, error) {
	code = strings.ToUpper(code)
	if len(code) != 3 {
		return 0, fmt.Errorf("manufacturer %q is not three letters", code)
	}
	var m uint16
	for i := range 3 {
		c := code[i]
		if c < 'A' || c > 'Z' {
			return 0, fmt.Errorf("manufacturer %q is not three letters", code)
		}
		m = m<<5 | uint16(c-64)
	}
	return m, nil
}

// Medium names a device type code (EN 13757-3 / OMS).
func Medium(t byte) string {
	if n, ok := media[t]; ok {
		return n
	}
	return fmt.Sprintf("0x%02X", t)
}

var media = map[byte]string{
	0x00: "other", 0x01: "oil", 0x02: "electricity", 0x03: "gas", 0x04: "heat", 0x05: "steam",
	0x06: "warm water", 0x07: "water", 0x08: "heat cost allocator", 0x09: "compressed air",
	0x0A: "cooling (outlet)", 0x0B: "cooling (inlet)", 0x0C: "heat (inlet)", 0x0D: "heat/cooling",
	0x0E: "bus/system component", 0x0F: "unknown", 0x15: "hot water", 0x16: "cold water",
	0x17: "dual water", 0x18: "pressure", 0x19: "A/D converter", 0x1A: "smoke detector",
	0x1B: "room sensor", 0x1C: "gas detector", 0x20: "breaker (electricity)", 0x21: "valve",
	0x25: "customer unit", 0x28: "waste water", 0x29: "garbage", 0x31: "communication controller",
	0x32: "unidirectional repeater", 0x33: "bidirectional repeater", 0x36: "radio converter (system side)",
	0x37: "radio converter (meter side)",
}
