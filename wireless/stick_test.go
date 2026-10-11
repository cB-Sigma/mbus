// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package wireless

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestIM871ASetLinkModeFrame(t *testing.T) {
	f := IM871ASetLinkMode(IM871AModeC1A, false)
	if !bytes.Equal(f[:7], []byte{0xA5, 0x81, 0x03, 0x03, 0x00, 0x02, 0x06}) || len(f) != 9 {
		t.Fatalf("% X", f)
	}
	m, err := ReadHCI(bufio.NewReader(bytes.NewReader(append([]byte{0x00, 0x11}, f...))))
	if err != nil || m.Endpoint != IM871ADevMgmt || m.ID != IM871ASetConfigReq || !bytes.Equal(m.Payload, []byte{0, 2, 6}) {
		t.Fatalf("%+v %v", m, err)
	}
	// A changed byte fails the CRC and is skipped.
	bad := append([]byte(nil), f...)
	bad[6] ^= 1
	if _, err := ReadHCI(bufio.NewReader(bytes.NewReader(bad))); !errors.Is(err, io.EOF) {
		t.Errorf("bad CRC: %v", err)
	}
}

// stick answers each request on a pipe with what answer returns.
func stick(t *testing.T, answer func(req []byte) []byte) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		buf := make([]byte, 64)
		for {
			n, err := b.Read(buf)
			if err != nil {
				return
			}
			if out := answer(buf[:n]); out != nil {
				if _, err := b.Write(out); err != nil {
					return
				}
			}
		}
	}()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a
}

func TestConfigureIM871A(t *testing.T) {
	var got []byte
	c := stick(t, func(req []byte) []byte {
		got = append([]byte(nil), req...)
		// A telegram indication first, then the confirmation.
		ind := IM871AFrame(IM871ARadioLink, IM871AMsgInd, bytes.Repeat([]byte{0x44}, 12))
		return append(ind, IM871AFrame(IM871ADevMgmt, IM871ASetConfigRsp, []byte{0})...)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := ConfigureIM871A(ctx, c, IM871AModeT1, true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, IM871ASetLinkMode(IM871AModeT1, true)) {
		t.Errorf("request % X", got)
	}
	c = stick(t, func([]byte) []byte { return IM871AFrame(IM871ADevMgmt, IM871ASetConfigRsp, []byte{1}) })
	if err := ConfigureIM871A(ctx, c, IM871AModeT1, false); !errors.Is(err, ErrStickRefused) {
		t.Errorf("refused: %v", err)
	}
	// No answer: the context ends it.
	c = stick(t, func([]byte) []byte { return nil })
	short, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	if err := ConfigureIM871A(short, c, IM871AModeT1, false); err == nil {
		t.Error("no answer accepted")
	}
}

func TestConfigureAmber(t *testing.T) {
	if f := AmberSetMode(AmberModeC2T2); !bytes.Equal(f, []byte{0xFF, 0x04, 0x01, 0x09, 0xFF ^ 0x04 ^ 0x01 ^ 0x09}) {
		t.Fatalf("% X", f)
	}
	cnf := func(st byte) []byte {
		f := []byte{AmberStart, AmberSetModeCnf, 1, st}
		return append(f, xorAll(f))
	}
	c := stick(t, func([]byte) []byte { return cnf(0) })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := ConfigureAmber(ctx, c, AmberModeT2); err != nil {
		t.Fatal(err)
	}
	c = stick(t, func([]byte) []byte { return cnf(1) })
	if err := ConfigureAmber(ctx, c, AmberModeT2); !errors.Is(err, ErrStickRefused) {
		t.Errorf("refused: %v", err)
	}
}

func TestCUL(t *testing.T) {
	cmdc := make(chan string, 4)
	c := stick(t, func(req []byte) []byte {
		cmdc <- strings.TrimSpace(string(req))
		if strings.HasPrefix(string(req), "brc") {
			return []byte("CMODE\r\n")
		}
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := ConfigureCUL(ctx, c, "c1"); err != nil {
		t.Fatal(err)
	}
	if a, b := <-cmdc, <-cmdc; a != "brc" || b != "X21" {
		t.Errorf("commands %q %q", a, b)
	}
	if err := ConfigureCUL(ctx, c, "N1"); err == nil {
		t.Error("mode N1 accepted")
	}
	frame := "1E44AE4C9956341268077A36001000_2F2F0413390000002F2F2F2F2F2F2F2F2F2F2F"
	frame = strings.ReplaceAll(frame, "_", "")
	r, err := ParseCULLine("b" + frame + "40" + "F6" + "\r\n")
	if err != nil || r.RSSI == nil || *r.RSSI != -79 || !r.RSSIdBm || len(r.Frame) != len(frame)/2 {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := ParseCULLine("TMODE"); err == nil {
		t.Error("answer line read as a telegram")
	}
	rd := NewReader(strings.NewReader("TMODE\r\nbY"+frame+"40F6\r\n"), FramerCUL)
	if got, err := rd.Read(); err != nil || len(got.Frame) != len(frame)/2 {
		t.Fatalf("reader: %+v %v", got, err)
	}
}

func TestRTLWMBUS(t *testing.T) {
	line := "C1;1;1;2026-01-05 10:00:00.000;117;99;12345678;0x1E44AE4C99563412680778040F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F"
	r, err := ParseRTLWMBUSLine(line)
	if err != nil || r.LinkMode != "C1" || r.RSSI == nil || *r.RSSI != 117 || r.Frame[0] != 0x1E {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := ParseRTLWMBUSLine(strings.Replace(line, "C1;1;1", "C1;0;1", 1)); err == nil {
		t.Error("failed CRC accepted")
	}
	rd := NewReader(strings.NewReader("rtl_wmbus starting\n"+line+"\n"), FramerRTLWMBUS)
	if got, err := rd.Read(); err != nil || got.LinkMode != "C1" {
		t.Fatalf("reader: %+v %v", got, err)
	}
}
