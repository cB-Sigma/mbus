// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package wireless

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Setting a receiver stick's radio mode, and reading the text output of
// CUL sticks (culfw) and of rtl-wmbus (an SDR receiver). The command and
// mode codes are those of the makers' published interface documents
// (IMST WiMOD wM-Bus HCI, Würth Elektronik AMB8465 manual, culfw command
// reference, the rtl-wmbus README).

// More framer names.
const (
	FramerCUL      = "cul"      // CUL / nanoCUL running culfw: "b" + hex lines
	FramerRTLWMBUS = "rtlwmbus" // rtl-wmbus: "mode;crc;3of6;time;rssi;rssi;id;0xhex" lines
)

// iM871A device management endpoint and the messages used here.
const (
	IM871ADevMgmt       = 0x01
	IM871APingReq       = 0x01
	IM871APingRsp       = 0x02
	IM871ASetConfigReq  = 0x03
	IM871ASetConfigRsp  = 0x04
	IM871AGetDevInfoReq = 0x0F
	IM871AGetDevInfoRsp = 0x10
)

// iM871A link modes (the HCI's radio mode parameter).
const (
	IM871AModeS1  = 0x00
	IM871AModeS1m = 0x01
	IM871AModeS2  = 0x02
	IM871AModeT1  = 0x03
	IM871AModeT2  = 0x04
	IM871AModeR2  = 0x05
	IM871AModeC1A = 0x06
	IM871AModeC1B = 0x07
	IM871AModeC2A = 0x08
	IM871AModeC2B = 0x09
	// IM871AModeCT receives C1 and T1 together (or N1a on N-band
	// hardware), on firmware that has it.
	IM871AModeCT = 0x0A
)

// Amber (AMB8465 and relatives) command mode: the set-mode request and
// its confirmation, and the mode codes of a collector.
const (
	AmberSetModeReq = 0x04
	AmberSetModeCnf = 0x84
	AmberModeS2     = 0x03 // collector, S1 and S1-m
	AmberModeT2     = 0x08 // collector, T1 and T2 (bidirectional)
	AmberModeC2T2   = 0x09 // collector, C and T together
	AmberModeR2     = 0x0B
	AmberModeC2     = 0x0E // collector, C (bidirectional)
)

// IM871AFrame encodes an HCI message with its CRC.
func IM871AFrame(endpoint, msg byte, payload []byte) []byte {
	hdr := []byte{IM871ACRC | endpoint&0x0F, msg, byte(len(payload))}
	body := append(hdr, payload...)
	crc := CRCX25(body)
	return append(append([]byte{IM871ASOF}, body...), byte(crc), byte(crc>>8))
}

// IM871ASetLinkMode is the SET_CONFIG request that sets only the link
// mode; persist stores it in the stick's non-volatile memory.
func IM871ASetLinkMode(mode byte, persist bool) []byte {
	var nv byte
	if persist {
		nv = 1
	}
	// Byte 0: store in NVM; byte 1: the first group of "parameter
	// present" flags with only the radio mode set; byte 2: the mode.
	return IM871AFrame(IM871ADevMgmt, IM871ASetConfigReq, []byte{nv, 0x02, mode})
}

// AmberSetMode is the command-mode request that selects a mode.
func AmberSetMode(mode byte) []byte {
	f := []byte{AmberStart, AmberSetModeReq, 1, mode}
	return append(f, xorAll(f))
}

func xorAll(b []byte) byte {
	var x byte
	for _, c := range b {
		x ^= c
	}
	return x
}

// ErrStickRefused is returned when a stick answers a command with an error
// status.
var ErrStickRefused = errors.New("the receiver stick refused the command")

// HCIMessage is one WiMOD HCI message.
type HCIMessage struct {
	Endpoint, ID byte
	Payload      []byte
}

// ReadHCI reads the next well-formed HCI message (a bad CRC is skipped).
func ReadHCI(r *bufio.Reader) (HCIMessage, error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return HCIMessage{}, err
		}
		if b != IM871ASOF {
			continue
		}
		hdr := make([]byte, 3)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return HCIMessage{}, err
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
			return HCIMessage{}, err
		}
		if ctl&IM871ACRC != 0 {
			all := append(append([]byte(nil), hdr...), body[:len(body)-2]...)
			if CRCX25(all) != uint16(body[len(body)-2])|uint16(body[len(body)-1])<<8 {
				continue
			}
		}
		return HCIMessage{Endpoint: ctl & 0x0F, ID: hdr[1], Payload: body[:n]}, nil
	}
}

// deadline applies ctx's deadline to a connection that supports one.
func deadline(ctx context.Context, rw io.ReadWriter) func() {
	type dl interface{ SetDeadline(time.Time) error }
	c, ok := rw.(dl)
	if !ok {
		return func() {}
	}
	if t, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(t)
	}
	return func() { _ = c.SetDeadline(time.Time{}) }
}

// await runs f until it returns or ctx ends. On a connection without
// deadlines a read can outlive ctx; it ends with the connection.
func await(ctx context.Context, f func() error) error {
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ConfigureIM871A sets an iM871A's link mode and waits for its
// confirmation. Telegrams that arrive meanwhile are dropped. Not checked
// against a real stick (see the README).
func ConfigureIM871A(ctx context.Context, rw io.ReadWriter, mode byte, persist bool) error {
	defer deadline(ctx, rw)()
	if _, err := rw.Write(IM871ASetLinkMode(mode, persist)); err != nil {
		return err
	}
	br := bufio.NewReader(rw)
	return await(ctx, func() error {
		for {
			m, err := ReadHCI(br)
			if err != nil {
				return err
			}
			if m.Endpoint != IM871ADevMgmt || m.ID != IM871ASetConfigRsp {
				continue
			}
			if len(m.Payload) < 1 || m.Payload[0] != 0 {
				return fmt.Errorf("%w: iM871A SET_CONFIG status % X", ErrStickRefused, m.Payload)
			}
			return nil
		}
	})
}

// ConfigureAmber sets an Amber stick's mode (command mode) and waits for
// the confirmation.
func ConfigureAmber(ctx context.Context, rw io.ReadWriter, mode byte) error {
	defer deadline(ctx, rw)()
	if _, err := rw.Write(AmberSetMode(mode)); err != nil {
		return err
	}
	br := bufio.NewReader(rw)
	return await(ctx, func() error {
		for {
			b, err := br.ReadByte()
			if err != nil {
				return err
			}
			if b != AmberStart {
				continue
			}
			hdr := make([]byte, 2)
			if _, err := io.ReadFull(br, hdr); err != nil {
				return err
			}
			body := make([]byte, int(hdr[1])+1)
			if _, err := io.ReadFull(br, body); err != nil {
				return err
			}
			if xorAll(append([]byte{AmberStart, hdr[0], hdr[1]}, body[:len(body)-1]...)) != body[len(body)-1] || hdr[0] != AmberSetModeCnf {
				continue
			}
			if len(body) < 2 || body[0] != 0 {
				return fmt.Errorf("%w: Amber set mode status % X", ErrStickRefused, body[:len(body)-1])
			}
			return nil
		}
	})
}

// CUL receive modes: the culfw command and the answer it prints.
var culModes = map[string][2]string{
	"T1": {"brt", "TMODE"}, "S1": {"brs", "SMODE"}, "C1": {"brc", "CMODE"},
}

// ConfigureCUL starts a culfw stick's Wireless M-Bus receiver in mode
// "T1", "S1" or "C1" (C1 also receives T1), then turns on the LQI and
// RSSI suffix the CUL framer expects (X21).
func ConfigureCUL(ctx context.Context, rw io.ReadWriter, mode string) error {
	m, ok := culModes[strings.ToUpper(mode)]
	if !ok {
		return fmt.Errorf("CUL: mode %q is not T1, S1 or C1", mode)
	}
	defer deadline(ctx, rw)()
	if _, err := io.WriteString(rw, m[0]+"\r\n"); err != nil {
		return err
	}
	br := bufio.NewReader(rw)
	err := await(ctx, func() error {
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return err
			}
			if strings.TrimSpace(line) == m[1] {
				return nil
			}
		}
	})
	if err != nil {
		return err
	}
	_, err = io.WriteString(rw, "X21\r\n")
	return err
}

// ParseCULLine reads a culfw telegram line: "b" and the frame in hex
// (frame format A, CRCs included) or "bY" and a format B frame, then the
// LQI and RSSI bytes (X21). RSSI is in dBm (the CC1101's raw value / 2 -
// 74). Other lines (command answers) give errNoHex.
func ParseCULLine(line string) (Received, error) {
	s := strings.TrimSpace(line)
	if len(s) < 2 || s[0] != 'b' {
		return Received{}, errNoHex
	}
	s = s[1:]
	if s[0] == 'Y' {
		s = s[1:]
	}
	if len(s) < 22+4 || len(s)%2 != 0 {
		return Received{}, errNoHex
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return Received{}, fmt.Errorf("CUL line: %w", err)
	}
	rssi := int(int8(b[len(b)-1]))/2 - 74
	return Received{Frame: b[:len(b)-2], RSSI: &rssi, RSSIdBm: true}, nil
}

// ParseRTLWMBUSLine reads an rtl-wmbus line: link mode, CRC ok (1/0),
// 3-out-of-6 ok (1/0), time, packet RSSI, current RSSI, link-layer ID and
// the telegram as 0x and hex digits. Lines whose checks failed give an
// error.
func ParseRTLWMBUSLine(line string) (Received, error) {
	f := strings.Split(strings.TrimSpace(line), ";")
	if len(f) < 8 || !strings.HasPrefix(f[7], "0x") {
		return Received{}, errNoHex
	}
	if f[1] != "1" || f[2] != "1" {
		return Received{}, fmt.Errorf("rtl-wmbus: telegram failed its checks (crc %s, 3-out-of-6 %s)", f[1], f[2])
	}
	b, err := hex.DecodeString(f[7][2:])
	if err != nil || len(b) < 11 {
		return Received{}, fmt.Errorf("rtl-wmbus: telegram is not hexadecimal: %v", err)
	}
	out := Received{Frame: b} // its RSSI is the SDR's own scale, not dBm
	if m, ok := NormalizeLinkMode(f[0]); ok {
		out.LinkMode = m
	}
	if v, err := strconv.ParseFloat(f[4], 64); err == nil {
		r := int(v)
		out.RSSI = &r
	}
	return out, nil
}
