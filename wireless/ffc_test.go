// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package wireless

import (
	"encoding/binary"
	"errors"
	"testing"
)

// A compact frame whose Full-Frame-CRC does not match its rebuilt records
// is refused by default; IgnoreFullFrameCRC rebuilds it and warns.
func TestIgnoreFullFrameCRC(t *testing.T) {
	m := testMeter(t)
	full := []byte{0x04, 0x13, 0x39, 0x30, 0x00, 0x00}
	format, err := BuildFormat(full)
	if err != nil {
		t.Fatal(err)
	}
	apl := binary.LittleEndian.AppendUint16([]byte{CICompactNone}, FormatSignature(format))
	apl = binary.LittleEndian.AppendUint16(apl, FullFrameCRC(full)^0x0101) // wrong
	apl = append(apl, 0x39, 0x30, 0x00, 0x00)
	frame := linkFrame(m, apl)

	for _, lenient := range []bool{false, true} {
		c := NewFormatCache(4)
		c.IgnoreFullFrameCRC = lenient
		c.Put(m.Key(), format)
		tg, err := Decode(frame, FormatNoCRC, nil)
		info, err := c.Complete(tg, err)
		if !lenient {
			if !errors.Is(err, ErrFullFrameCRC) || len(tg.Warnings) != 0 {
				t.Fatalf("strict: %v %v", err, tg.Warnings)
			}
			continue
		}
		if err != nil || len(tg.Records) != 1 || tg.Records[0].Value != 12.345 || info.Warning != WarnFullFrameCRC || len(tg.Warnings) != 1 {
			t.Fatalf("lenient: %v %+v %+v", err, info, tg)
		}
		if _, _, err := c.Expand(m.Key(), CICompactNone, apl[1:]); !errors.Is(err, ErrFullFrameCRCIgnored) {
			t.Errorf("Expand: %v", err)
		}
	}
	// A correct CRC carries no warning with the option on.
	good := append([]byte(nil), apl...)
	binary.LittleEndian.PutUint16(good[3:5], FullFrameCRC(full))
	c := NewFormatCache(4)
	c.IgnoreFullFrameCRC = true
	c.Put(m.Key(), format)
	tg, err := Decode(linkFrame(m, good), FormatNoCRC, nil)
	if info, err := c.Complete(tg, err); err != nil || info.Warning != "" || len(tg.Warnings) != 0 {
		t.Errorf("good CRC: %v %+v", err, info)
	}
}
