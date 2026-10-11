// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package wired_test

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/cB-Sigma/mbus/wired"
)

// A master on a bus behind a serial-to-IP converter: find the meters by
// the secondary address search, select the first and read its data
// records. (It needs a bus, so it is compiled but not run; the mbus-sim
// module runs the same steps against its simulated bus.)
func ExampleMaster() {
	conn, err := net.Dial("tcp", "192.0.2.20:10001") // wired.OpenSerial for a local port
	if err != nil {
		panic(err)
	}
	p := wired.NewPort(conn)
	defer p.Close()
	m := wired.NewMaster(2400)
	m.Timeout, m.Retries = 300*time.Millisecond, 2
	m.SetPort(p, 2400)

	ctx := context.Background()
	found, err := m.Search(ctx)
	if err != nil || len(found) == 0 {
		panic(fmt.Sprint("no meter found: ", err))
	}
	fmt.Println(found[0].Key()) // ABC-12345678
	a, err := m.Select(ctx, wired.Target{Secondary: &found[0]})
	if err != nil {
		panic(err)
	}
	_, err = m.ReadTelegrams(ctx, a, 8, func(t wired.Telegram) error {
		for _, r := range t.Records {
			fmt.Println(r.Name(), r.Value, r.Unit) // volume 12.345 m3
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
}

// A REQ_UD2 to primary address 5 with the frame count bit set.
func ExampleFrame_Encode() {
	fmt.Printf("% X\n", wired.Frame{C: wired.CReqUD2 | wired.FCB, A: 5}.Encode())
	// Output:
	// 10 7B 05 80 16
}
