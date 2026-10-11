// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package wireless

import (
	"encoding/binary"
	"errors"
	"testing"
)

// A mode 2 telegram whose plaintext begins with the 2F2F idle fillers but
// does not hold the meter's ID: refused by default (the ID is our check),
// read with DESCheck2F2F, and still refused with a wrong key.
func TestDESMode2Check2F2F(t *testing.T) {
	m := testMeter(t)
	desKey := hx(t, "0123456789ABCDEF")
	plain := append([]byte{0x2F, 0x2F}, sampleAPL...)
	for len(plain)%8 != 0 {
		plain = append(plain, 0x2F)
	}
	enc, _ := desCBCEncrypt(desKey, make([]byte, 8), plain)
	tpdu := binary.LittleEndian.AppendUint16([]byte{CIShortHeader, 1, 0}, uint16(2)<<8|uint16(len(enc)))
	tpdu = append(tpdu, enc...)
	frame := linkFrame(m, tpdu)

	d := &Decoder{DESKey: func(Header) []byte { return desKey }}
	if _, err := d.Decode(frame, FormatNoCRC, nil); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("default: %v", err)
	}
	d.DESCheck2F2F = true
	tg, err := d.Decode(frame, FormatNoCRC, nil)
	if err != nil || !tg.Encrypted || len(tg.Records) != 1 || !contains(tg.Sec.Verified, "decrypt-2f2f") || !contains(tg.Sec.Unverified, "des-id") {
		t.Fatalf("2F2F check: %v %+v", err, tg)
	}
	d.DESKey = func(Header) []byte { return hx(t, "FEDCBA9876543210") }
	if _, err := d.Decode(frame, FormatNoCRC, nil); !errors.Is(err, ErrDecrypt) {
		t.Errorf("wrong key: %v", err)
	}
}
