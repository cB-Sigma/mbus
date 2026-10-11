// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package meters

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// errShort is returned when a payload is shorter than its layout.
var errShort = errors.New("the manufacturer's payload is shorter than its layout")

// le reads an unsigned little-endian integer of len(b) bytes.
func le(b []byte) uint64 {
	var v uint64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// need checks that p has at least n bytes.
func need(p []byte, n int) error {
	if len(p) < n {
		return fmt.Errorf("%w (%d bytes, %d needed)", errShort, len(p), n)
	}
	return nil
}

// ymd formats a date; month 0 or day 0 gives "".
func ymd(y, m, d int) string {
	if m < 1 || m > 12 || d < 1 || d > 31 {
		return ""
	}
	return fmt.Sprintf("%04d-%02d-%02d", y, m, d)
}

// packedDate is the 16-bit date many manufacturers use: day in bits 0-4,
// month in bits 5-8, years since 2000 above.
func packedDate(v uint64) string {
	return ymd(2000+int(v>>9), int(v>>5&0x0F), int(v&0x1F))
}

// flags joins the names of the set bits of v, or returns none.
func flags(v uint64, names map[uint64]string, none string) string {
	var out []string
	for bit := uint64(1); bit != 0 && bit <= v; bit <<= 1 {
		if v&bit == 0 {
			continue
		}
		if n, ok := names[bit]; ok {
			out = append(out, n)
		} else {
			out = append(out, fmt.Sprintf("bit_%d", bitIndex(bit)))
		}
	}
	if len(out) == 0 {
		return none
	}
	return strings.Join(out, ",")
}

func bitIndex(b uint64) int {
	n := 0
	for b > 1 {
		b >>= 1
		n++
	}
	return n
}

// since2000 is a count of seconds since 2000-01-01 00:00 as a date and
// time text.
func since2000(sec uint64) string {
	return time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(sec) * time.Second).Format("2006-01-02T15:04:05")
}
