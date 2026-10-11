// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package records_test

import (
	"fmt"

	"github.com/cB-Sigma/mbus/records"
)

// A volume (DIF 04h, VIF 13h: 32-bit integer, litres) and a flow
// temperature (DIF 02h, VIF 5Ah: 16-bit integer, 0.1 °C).
func ExampleParseRecords() {
	recs, err := records.ParseRecords([]byte{0x04, 0x13, 0x39, 0x30, 0x00, 0x00, 0x02, 0x5A, 0xD7, 0x00})
	if err != nil {
		panic(err)
	}
	for _, r := range recs {
		fmt.Println(r.Name(), r.Value, r.Unit)
		if code, ok := r.OBIS(0x07); ok { // in a water meter (annex H)
			fmt.Println("  obis", code)
		}
	}
	fmt.Println(records.ManufacturerCode(0x0443), records.Medium(0x07))
	// Output:
	// volume 12.345 m3
	//   obis 8.0.1.0.0.255
	// flow_temperature 21.5 Cel
	// ABC water
}
