// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tpdu_test

import (
	"fmt"

	"github.com/cB-Sigma/mbus/tpdu"
)

// A 300-byte APDU goes as two transport PDUs and is joined again.
func ExampleSegmentAPDU() {
	apdu := make([]byte, 300)
	var r tpdu.Reassembler
	for _, t := range tpdu.SegmentAPDU(apdu, tpdu.SAPPublicClient, tpdu.SAPManagement) {
		got, err := r.Add(t)
		if err != nil {
			panic(err)
		}
		fmt.Println(len(t.Data), got != nil)
	}
	// Output:
	// 248 false
	// 52 true
}
