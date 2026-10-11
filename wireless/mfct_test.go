// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package wireless

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// A manufacturer-specific CI field and a security mode outside
// EN 13757-7 are still refused, but the payload is kept in APL for a meter
// driver.
func TestManufacturerPayloadKept(t *testing.T) {
	m := testMeter(t)
	tg, err := Decode(linkFrame(m, []byte{0xA2, 0x01, 0x02, 0x03}), FormatNoCRC, nil)
	if !errors.Is(err, ErrUnsupport) || !errors.Is(err, ErrManufacturerCI) || tg.CI != 0xA2 || !bytes.Equal(tg.APL, []byte{1, 2, 3}) {
		t.Fatalf("CI A2h: %v %+v", err, tg)
	}
	tpdu := binary.LittleEndian.AppendUint16([]byte{CIShortHeader, 1, 0}, uint16(24)<<8)
	tpdu = append(tpdu, 0x11, 0x22)
	tg, err = Decode(linkFrame(m, tpdu), FormatNoCRC, nil)
	if !errors.Is(err, ErrSecurityMode) || tg.Mode != 24 || !bytes.Equal(tg.APL, []byte{0x11, 0x22}) {
		t.Fatalf("mode 24: %v %+v", err, tg)
	}
}
