// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package wireless

import (
	"strings"
	"time"
)

// ResponseDelay is the window, counted from the end of a meter's
// transmission, in which the meter listens for a gateway's frame
// (EN 13757-4:2025, the response delay tRO of tables 5, 8 and 15): modes
// S 3 to 15 ms, T 2 to 3 ms, C 99,5 to 100,5 ms, or 999,5 to 1 000,5 ms
// when the meter asks for the slow delay (the D bit of the extended link
// layer's CC field clear; without an extended link layer the fast delay
// is the default). ok is false for a mode not covered here (R, N, F).
func ResponseDelay(linkMode string, tg *Telegram) (lo, hi time.Duration, ok bool) {
	m, _ := NormalizeLinkMode(linkMode)
	switch strings.ToUpper(m[:min(1, len(m))]) {
	case "S":
		return 3 * time.Millisecond, 15 * time.Millisecond, true
	case "T":
		return 2 * time.Millisecond, 3 * time.Millisecond, true
	case "C":
		if tg != nil && tg.ELL != nil && tg.ELL.CC&CCFastDelay == 0 {
			return 999500 * time.Microsecond, 1000500 * time.Microsecond, true
		}
		return 99500 * time.Microsecond, 100500 * time.Microsecond, true
	}
	return 0, 0, false
}

// responseWait is how long the scheduler waits, after the telegram that
// opened a window was handed to it at received, before writing a frame:
// the middle of the meter's response window, less the time already gone.
func (s *Scheduler) responseWait(tg *Telegram, received, now time.Time) time.Duration {
	if s.LinkMode == "" {
		return 0
	}
	lo, hi, ok := ResponseDelay(s.LinkMode, tg)
	if !ok {
		return 0
	}
	d := lo + (hi-lo)/2 - s.StickLatency - now.Sub(received)
	if d < 0 {
		return 0
	}
	return d
}
