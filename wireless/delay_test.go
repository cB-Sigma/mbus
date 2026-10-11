// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package wireless

import (
	"bytes"
	"testing"
	"time"
)

func TestResponseDelay(t *testing.T) {
	fast := &Telegram{ELL: &ELL{CC: CCBidirectional | CCFastDelay}}
	slow := &Telegram{ELL: &ELL{CC: CCBidirectional}}
	for _, tc := range []struct {
		mode   string
		tg     *Telegram
		lo, hi time.Duration
		ok     bool
	}{
		{"S2", nil, 3 * time.Millisecond, 15 * time.Millisecond, true},
		{"t2", slow, 2 * time.Millisecond, 3 * time.Millisecond, true},
		{"C2", fast, 99500 * time.Microsecond, 100500 * time.Microsecond, true},
		{"C2", slow, 999500 * time.Microsecond, 1000500 * time.Microsecond, true},
		{"C2", &Telegram{}, 99500 * time.Microsecond, 100500 * time.Microsecond, true},
		{"N2a", fast, 0, 0, false},
		{"", nil, 0, 0, false},
	} {
		lo, hi, ok := ResponseDelay(tc.mode, tc.tg)
		if lo != tc.lo || hi != tc.hi || ok != tc.ok {
			t.Errorf("%s: %v %v %v", tc.mode, lo, hi, ok)
		}
	}
}

// With LinkMode set, the scheduler waits for the meter's response window
// (fast or slow by the D bit) before it writes the frame.
func TestSchedulerWaitsForResponseWindow(t *testing.T) {
	m := testMeter(t)
	gw := Gateway{Manufacturer: "XYZ", ID: "33445566", Version: 1}
	if err := gw.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		cc   byte
		want time.Duration
	}{
		{CCBidirectional | CCFastDelay, 100 * time.Millisecond},
		{CCBidirectional, time.Second},
	} {
		var waited time.Duration
		var out bytes.Buffer
		s := &Scheduler{Gateway: gw, Framer: FramerIM871A, Timeout: time.Minute, LinkMode: "C2",
			Wait: func(d time.Duration) { waited = d }}
		s.SetWriter(&out)
		s.Enqueue(m.Key(), &Pending{ID: "a", Frame: Downlink{C: CSndNKE, CI: CIToMeterLong}, Queued: time.Now()})
		tg := &Telegram{Header: m, Meter: m, ELL: &ELL{CI: CIELL2, CC: tc.cc, ACC: 1}}
		tg.C = 0x44
		for _, e := range s.After(m.Key(), tg, true) {
			e()
		}
		if out.Len() == 0 {
			t.Fatalf("CC %02X: nothing sent", tc.cc)
		}
		if d := tc.want - waited; d < 0 || d > 5*time.Millisecond {
			t.Errorf("CC %02X: waited %v, want about %v", tc.cc, waited, tc.want)
		}
	}
}
