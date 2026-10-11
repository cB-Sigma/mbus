package wired

import (
	"time"
)

// Link layer timing and datagram sequencing of the master, from EN
// 13757-2:2018+A1:2023: a byte is 11 bits on the line (5.4: start, eight
// data bits, even parity, stop); a slave begins its answer between 11 bit
// times and 330 bit times + 50 ms after the master's datagram ends
// (5.7.6, Figure 8); a receiver needs 11 bit times of idle line to see a
// datagram end (5.5.3); a gap of more than 22 bit times ends a datagram
// (5.5.2). An unanswered datagram is sent up to three times in all, and
// so is one answered with a damaged reply (5.7.6, A1).

// bits is how long n bits take at the baud rate.
func bits(n, baud int) time.Duration {
	if baud <= 0 {
		baud = 2400
	}
	return time.Duration(n) * time.Second / time.Duration(baud)
}

// BitTime is one bit at the baud rate.
func BitTime(baud int) time.Duration { return bits(1, baud) }

// FrameTime is how long n bytes take on the line.
func FrameTime(n, baud int) time.Duration { return bits(11*n, baud) }

// MaxAnswerDelay is the latest a slave may begin its answer after the
// master's datagram ends: 330 bit times + 50 ms (5.7.6).
func MaxAnswerDelay(baud int) time.Duration { return bits(330, baud) + 50*time.Millisecond }

// maxFrame is the longest datagram: a long frame with L = 255.
const maxFrame = 4 + 255 + 2

// quietAfter is the pause after a datagram nobody answers (a broadcast)
// before the next one: its own transmission, then 11 bit times of idle
// line so receivers see it end (5.5.3), and 50 ms for the slaves to act
// on it, the same slack the answer window allows (F-2056).
func quietAfter(n, baud int) time.Duration {
	return bits(11*n+11, baud) + 50*time.Millisecond
}

// QuietAfter is the pause after an unanswered datagram of n bytes.
func QuietAfter(n, baud int) time.Duration { return quietAfter(n, baud) }
