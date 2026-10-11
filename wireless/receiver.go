package wireless

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Receiver framings: how a byte stream from a USB/serial receiver (or the
// same stream relayed over TCP) is cut into telegrams.

// Received is one telegram as a receiver delivered it.
type Received struct {
	Frame    []byte // starts with the L field
	RSSI     *int   // receiver-reported RSSI (raw receiver units, or dBm when RSSIdBm)
	RSSIdBm  bool
	LinkMode string // "T1", "C1", "N2a" … (NormalizeLinkMode) when the source says
}

// Framer names.
const (
	FramerIM871A = "im871a" // IMST iM871A / WiMOD HCI
	FramerAmber  = "amber"  // Würth/Amber AMB8465 and relatives, command mode
	FramerRaw    = "raw"    // L-field framing (Amber transparent mode, bare radios)
	FramerHex    = "hex"    // one hexadecimal telegram per line (rtl-wmbus style, gateways)
)

// iM871A HCI: start byte, control/endpoint, message ID, length, payload,
// then an optional 32-bit timestamp, RSSI byte and CRC-16 as the control
// nibble announces.
const (
	IM871ASOF       = 0xA5 // start of frame
	IM871ARadioLink = 0x02 // the radio link endpoint
	IM871AMsgInd    = 0x03 // radio link: a received telegram
	IM871ADataReq   = 0x01 // radio link: send a telegram
	IM871ATimestamp = 0x20 // control bit: a timestamp follows
	IM871ARSSI      = 0x40 // control bit: an RSSI byte follows
	IM871ACRC       = 0x80 // control bit: a CRC-16 follows
)

// CRCX25 is the CRC-16 of the WiMOD HCI (polynomial 0x1021 reflected,
// initial 0xFFFF, complemented).
func CRCX25(b []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, x := range b {
		crc ^= uint16(x)
		for range 8 {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0x8408
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

// ReadIM871A reads one radio-link message indication, skipping other
// messages and garbage.
func ReadIM871A(r *bufio.Reader, withL bool) (Received, error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return Received{}, err
		}
		if b != IM871ASOF {
			continue
		}
		hdr := make([]byte, 3)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return Received{}, err
		}
		ctl, n := hdr[0], int(hdr[2])
		extra := 0
		if ctl&IM871ATimestamp != 0 {
			extra += 4
		}
		if ctl&IM871ARSSI != 0 {
			extra++
		}
		if ctl&IM871ACRC != 0 {
			extra += 2
		}
		body := make([]byte, n+extra)
		if _, err := io.ReadFull(r, body); err != nil {
			return Received{}, err
		}
		if ctl&IM871ACRC != 0 {
			all := append(append([]byte(nil), hdr...), body[:len(body)-2]...)
			got := uint16(body[len(body)-2]) | uint16(body[len(body)-1])<<8
			if CRCX25(all) != got {
				continue // corrupt HCI frame: resynchronise
			}
		}
		if ctl&0x0F != IM871ARadioLink || hdr[1] != IM871AMsgInd || n < 10 {
			continue
		}
		out := Received{Frame: withLField(body[:n], withL)}
		if ctl&IM871ARSSI != 0 {
			i := n
			if ctl&IM871ATimestamp != 0 {
				i += 4
			}
			v := int(body[i])
			out.RSSI = &v
		}
		return out, nil
	}
}

// Amber command mode: 0xFF, command, length, payload, XOR checksum of every
// byte before it. Received radio telegrams are command 0x03.
const (
	AmberStart   = 0xFF // start of a command
	AmberDataInd = 0x03 // a received telegram
	AmberDataReq = 0x00 // send a telegram
)

// ReadAmber reads one received radio telegram in Amber command mode,
// skipping other commands; rssiByte says an RSSI byte follows the telegram.
func ReadAmber(r *bufio.Reader, withL, rssiByte bool) (Received, error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return Received{}, err
		}
		if b != AmberStart {
			continue
		}
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return Received{}, err
		}
		body := make([]byte, int(hdr[1])+1)
		if _, err := io.ReadFull(r, body); err != nil {
			return Received{}, err
		}
		cs := byte(AmberStart) ^ hdr[0] ^ hdr[1]
		for _, x := range body[:len(body)-1] {
			cs ^= x
		}
		if cs != body[len(body)-1] || hdr[0] != AmberDataInd {
			continue
		}
		p := body[:len(body)-1]
		var out Received
		if rssiByte && len(p) > 0 {
			v := int(p[len(p)-1])
			out.RSSI = &v
			p = p[:len(p)-1]
		}
		if len(p) < 10 {
			continue
		}
		out.Frame = withLField(p, withL)
		return out, nil
	}
}

// ReadRaw reads an L-framed telegram; format says how many bytes follow L.
func ReadRaw(r *bufio.Reader, format FrameFormat) (Received, error) {
	l, err := r.ReadByte()
	if err != nil {
		return Received{}, err
	}
	n := int(l)
	if format == FormatA {
		n = FrameLenA(int(l)) - 1
	}
	buf := make([]byte, n+1)
	buf[0] = l
	if _, err := io.ReadFull(r, buf[1:]); err != nil {
		return Received{}, err
	}
	return Received{Frame: buf}, nil
}

func withLField(p []byte, has bool) []byte {
	if has {
		return append([]byte(nil), p...)
	}
	return append([]byte{byte(len(p))}, p...)
}

var errNoHex = errors.New("no telegram in the line")

// ParseHexLine finds the telegram in a text line: the longest run of hex
// digits (an optional 0x prefix is dropped). A leading field naming a radio
// mode of EN 13757-4 ("T1;", "C1 ", "S1-m,", "R2:", "N2a;", "F2;" ...)
// gives the link mode.
func ParseHexLine(line string) (Received, error) {
	line = strings.TrimSpace(line)
	var out Received
	if i := strings.IndexAny(line, ";, \t:"); i > 0 {
		if m, ok := NormalizeLinkMode(line[:i]); ok {
			out.LinkMode = m
		}
	}
	best := ""
	for _, f := range strings.FieldsFunc(line, func(c rune) bool {
		return !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == 'x' || c == 'X')
	}) {
		f = strings.TrimPrefix(strings.TrimPrefix(f, "0x"), "0X")
		if strings.ContainsAny(f, "xX") {
			continue
		}
		if len(f) > len(best) {
			best = f
		}
	}
	if len(best) < 22 || len(best)%2 != 0 {
		return out, errNoHex
	}
	b, err := hex.DecodeString(best)
	if err != nil {
		return out, fmt.Errorf("telegram is not hexadecimal: %w", err)
	}
	out.Frame = b
	return out, nil
}

// IsHexText reports whether a datagram is hexadecimal text.
func IsHexText(b []byte) bool {
	s := strings.TrimSpace(string(b))
	if len(s) < 22 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == 'x' || c == 'X' || c == ';' || c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == ',' || c == ':' || c == '-' || c == '.' || strings.ContainsRune("STRCNFMmGg", c)) {
			return false
		}
	}
	return true
}

// Reader cuts a receiver's byte stream into telegrams with one of the
// framings (Framer*): WithL says the receiver's telegrams start with their
// L field (iM871A and Amber; otherwise it is computed), RSSIByte that an
// Amber stick appends an RSSI byte, Format how many bytes follow L in the
// raw framing. A hex stream skips lines without a telegram.
type Reader struct {
	Framer   string
	WithL    bool
	RSSIByte bool
	Format   FrameFormat

	r       *bufio.Reader
	pending error
}

// NewReader reads telegrams from r with a framing.
func NewReader(r io.Reader, framer string) *Reader {
	return &Reader{Framer: framer, r: bufio.NewReader(r)}
}

// Read returns the next telegram, or the stream's error.
func (rd *Reader) Read() (Received, error) {
	switch rd.Framer {
	case FramerIM871A:
		return ReadIM871A(rd.r, rd.WithL)
	case FramerAmber:
		return ReadAmber(rd.r, rd.WithL, rd.RSSIByte)
	case FramerRaw:
		return ReadRaw(rd.r, rd.Format)
	}
	for {
		if rd.pending != nil {
			return Received{}, rd.pending
		}
		line, err := rd.r.ReadString('\n')
		rd.pending = err
		if line == "" {
			continue
		}
		if t, perr := ParseHexLine(line); perr == nil {
			return t, nil
		}
	}
}
