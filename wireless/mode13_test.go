package wireless

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// A message too long for one datagram is sent in AFL fragments with the
// CMAC over the whole message in the last one (OMS Volume 2 6.2.4), and it
// verifies after reassembly; a changed fragment fails.
//
// Covers: SIG-IPE-1462
func TestWMBusAFLMessageMACFrames(t *testing.T) {
	m := testMeter(t)
	key := hx(t, "000102030405060708090A0B0C0D0E0F")
	gw := Header{MField: 0x6A49, A: [6]byte{0x66, 0x55, 0x44, 0x33, 0x0A, 0x31}}
	for _, n := range []int{30, 211, 212, 215, 400, 700} {
		rec := append([]byte{tlsHandshake, 3, 3, byte(n >> 8), byte(n)}, bytes0(n)...)
		tpdu := SealMode13(CITLSShort, false, m, 1, 0, 0, TLSPROT, rec)
		frames, err := SealAFLFrames(LinkHead(CRspUD, m.MField, m.A), gw, CRspUD, CRspUD, 0x80, 1, tpdu, key, 9, m, false)
		if err != nil {
			t.Fatal(err)
		}
		ok := func(*Telegram, *TLSInfo) ([]byte, error) { return nil, nil }
		d := Decoder{TLS: ok}
		var tg *Telegram
		for i, f := range frames {
			if len(f) > 256 {
				t.Fatalf("%d bytes: frame %d is %d bytes", n, i, len(f))
			}
			tg, err = d.Decode(f, FormatNoCRC, func(Header) []byte { return key })
			if i < len(frames)-1 && err != ErrFragment {
				t.Fatalf("%d bytes: fragment %d: %v", n, i, err)
			}
		}
		if err != nil || !contains(tg.Sec.Verified, "afl-cmac") {
			t.Errorf("%d bytes (%d frames): %v", n, len(frames), err)
		}
		if len(frames) > 1 {
			d2 := Decoder{TLS: ok}
			for i, f := range frames {
				if i == 0 {
					f = flip(f, len(f)-1)
				}
				_, err = d2.Decode(f, FormatNoCRC, func(Header) []byte { return key })
			}
			if err == nil {
				t.Errorf("%d bytes: a changed fragment verified", n)
			}
		}
	}
}

// bytes0 is n bytes of 2Fh.
func bytes0(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 0x2F
	}
	return b
}

// Mode 13 framing: the configuration field and CFE rules of annex F
// tables F.3 to F.6, and the record checks.
//
// Covers: SIG-IPE-1455
func TestWMBusMode13Framing(t *testing.T) {
	m := testMeter(t)
	ok := func(*Telegram, *TLSInfo) ([]byte, error) { return nil, nil }
	dec := func(tpdu []byte) error {
		_, err := (&Decoder{TLS: ok}).Decode(linkFrame(m, tpdu), FormatNoCRC, nil)
		return err
	}
	app := []byte{tlsAppData, 3, 3, 0, 2, 0xAA, 0xBB}
	if err := dec(SealMode13(CIShortHeader, false, m, 1, 0, 0, TLSPROT, app)); err != nil {
		t.Errorf("application record: %v", err)
	}
	for name, tpdu := range map[string][]byte{
		"N not FFh":       append(binary.LittleEndian.AppendUint16([]byte{CIShortHeader, 1, 0}, 0x0D10), append([]byte{TLSPROT}, app...)...),
		"CFE 2":           SealMode13(CIShortHeader, false, m, 1, 0, 0, 2, app),
		"TLS 1.1":         SealMode13(CIShortHeader, false, m, 1, 0, 0, TLSPROT, []byte{tlsAppData, 3, 2, 0, 0}),
		"short record":    SealMode13(CIShortHeader, false, m, 1, 0, 0, TLSPROT, []byte{tlsAppData, 3, 3, 0, 9, 1}),
		"content 18h":     SealMode13(CIShortHeader, false, m, 1, 0, 0, TLSPROT, []byte{0x18, 3, 3, 0, 0}),
		"chan from meter": SealMode13(CIShortHeader, false, m, 1, 0, 0, TLSCHAN, ChannelRequestRecord),
	} {
		if err := dec(tpdu); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Without a TLS channel mode 13 is refused as unsupported.
	if _, err := Decode(linkFrame(m, SealMode13(CIShortHeader, false, m, 1, 0, 0, TLSPROT, app)), FormatNoCRC, nil); !errors.Is(err, ErrUnsupport) {
		t.Errorf("mode 13 without TLS: %v", err)
	}
	// A long TPDU is split into AFL fragments behind ELL 8Eh with FID 1…n,
	// MF and ML in the first (F.D.4), and reassembles.
	gw := Header{MField: 0x6A49, A: [6]byte{0x66, 0x55, 0x44, 0x33, 0x0A, 0x31}}
	long := SealMode13(CITLSToMeter, true, m, 3, 0, 0, TLSPROT, append([]byte{tlsHandshake, 3, 3, 0x01, 0xF4}, bytes.Repeat([]byte{0x0B}, 500)...))
	frames := SplitTLSFrames(LinkHead(0, gw.MField, gw.A), m, CSndUDF, CSndUD, CCGateway, 3, long)
	if len(frames) != 3 || frames[0][1] != CSndUDF || frames[1][1] != CSndUD || frames[0][10] != CIELL10 {
		t.Fatalf("%d fragments", len(frames))
	}
	var got *TLSInfo
	d := &Decoder{MeterSide: true, TLS: func(_ *Telegram, i *TLSInfo) ([]byte, error) { got = i; return nil, nil }}
	for i, f := range frames {
		_, err := d.Decode(f, FormatNoCRC, nil)
		if i < 2 && !errors.Is(err, ErrFragment) || i == 2 && err != nil {
			t.Fatalf("fragment %d: %v", i+1, err)
		}
	}
	if got == nil || len(got.Records) != 505 {
		t.Errorf("reassembled records: %v", got)
	}
}

// With the OMS profile a fragmented message over 16 kbytes is refused
// (OMS Volume 2 6.2.5); EN 13757-7 alone allows up to 64 kbytes.
//
// Covers: SIG-IPE-1458
func TestWMBusOMSMessageCap(t *testing.T) {
	m := testMeter(t)
	gw := Header{MField: 0x6A49, A: [6]byte{0x66, 0x55, 0x44, 0x33, 0x0A, 0x31}}
	body := bytes.Repeat([]byte{0x0B}, 17*1024)
	rec := append([]byte{tlsHandshake, 3, 3, byte(len(body) >> 8), byte(len(body))}, body...)
	tpdu := SealMode13(CITLSToMeter, true, m, 1, 0, 0, TLSPROT, rec)
	frames := SplitTLSFrames(LinkHead(0, gw.MField, gw.A), m, CSndUDF, CSndUD, CCGateway, 1, tpdu)
	run := func(d *Decoder) error {
		var err error
		for _, f := range frames {
			if _, err = d.Decode(f, FormatNoCRC, nil); err != nil && !errors.Is(err, ErrFragment) {
				return err
			}
		}
		return err
	}
	ok := func(*Telegram, *TLSInfo) ([]byte, error) { return nil, nil }
	if err := run(&Decoder{MeterSide: true, TLS: ok, MaxMessage: OMSMaxMessage}); err == nil || !strings.Contains(err.Error(), "longer than 16384") {
		t.Errorf("OMS profile: %v", err)
	}
	// Without the profile the record is too long for TLS itself (16 kbytes
	// plus overhead is refused by the record check), but reassembly works.
	if err := run(&Decoder{MeterSide: true, TLS: ok}); err == nil || strings.Contains(err.Error(), "fragmented message longer") {
		t.Errorf("EN 13757 limit: %v", err)
	}
}
