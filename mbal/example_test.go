// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mbal_test

import (
	"fmt"

	"github.com/cB-Sigma/mbus/mbal"
)

// An uplink SND-NR as a UDP payload: the MBAL control field, then the
// upper layers (here a TPL without header and a volume record).
func ExampleParseUDP() {
	b := mbal.BuildUDP(mbal.NewUplink(mbal.AccessShort, mbal.FnSNDNR), []byte{0x78, 0x04, 0x13, 0x39, 0x30, 0x00, 0x00})
	m, err := mbal.ParseUDP(b, mbal.Uplink)
	if err != nil {
		panic(err)
	}
	fmt.Println(mbal.FunctionName(mbal.Uplink, m.Control.Function), m.Control.Access(), len(m.Upper))
	res := mbal.Decode(m, nil, nil)
	for _, r := range mbal.Readings(res.Records) {
		fmt.Println(r.Name, r.Value, r.Unit)
	}
	// Output:
	// SND-NR short 7
	// volume 12.345 m3
}
