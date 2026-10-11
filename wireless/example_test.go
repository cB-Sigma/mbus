// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package wireless_test

import (
	"encoding/binary"
	"fmt"

	"github.com/cB-Sigma/mbus/records"
	"github.com/cB-Sigma/mbus/wireless"
)

// A meter's SND-NR with a short TPL header, encrypted in security mode 5,
// decoded with the meter's key.
func ExampleDecode() {
	key := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	mf, _ := records.ManufacturerField("ABC")
	meter := wireless.Header{MField: mf, A: [6]byte{0x78, 0x56, 0x34, 0x12, 0x01, 0x07}}
	tpl, err := wireless.SealTPL(wireless.CIShortHeader, false, meter, 0x2A, 0, 0,
		wireless.Seal{Mode: 5, Key: key, KeyVersion: -1}, []byte{0x04, 0x13, 0x39, 0x30, 0x00, 0x00})
	if err != nil {
		panic(err)
	}
	frame := binary.LittleEndian.AppendUint16([]byte{0, wireless.CSndNR}, mf)
	frame = append(append(frame, meter.A[:]...), tpl...)
	frame[0] = byte(len(frame) - 1)

	tg, err := wireless.Decode(frame, wireless.FormatNoCRC, func(wireless.Header) []byte { return key })
	if err != nil {
		panic(err)
	}
	fmt.Println(tg.Meter.Key(), tg.Meter.Medium(), "mode", tg.Mode)
	for _, r := range tg.Records {
		fmt.Println(r.Name(), r.Value, r.Unit)
	}
	// With CRCs, as a radio receives it (frame format A).
	fmt.Println(len(wireless.AddCRCA(frame)) - len(frame))
	// Output:
	// ABC-12345678 water mode 5
	// volume 12.345 m3
	// 6
}
