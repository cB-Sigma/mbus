package wired_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/cB-Sigma/mbus/wired"
)

// The water meter example telegram published with the M-Bus
// documentation (m-bus.com, "variable data structure" example): ID
// 12345678, manufacturer PAD, version 1, medium water, access number 0x55.
const published = "681f1f68080272785634122440010755000000031315310" + "0da023b13018b60043718021816"

// Covers: SIG-IPE-310
func TestMBusFrames(t *testing.T) {
	f, err := wired.ReadFrame(bytes.NewReader(unhex(t, published)))
	if err != nil {
		t.Fatal(err)
	}
	r, err := wired.ParseResponse(f)
	if err != nil {
		t.Fatal(err)
	}
	if r.Address.ID != "12345678" || r.Address.Key() != "PAD-12345678" || r.Address.Version != 1 || r.Address.Medium != 7 || r.Access != 0x55 || r.More {
		t.Errorf("header = %+v", r)
	}
	want := map[string]struct {
		v    float64
		unit string
	}{"volume": {12.565, "m3"}, "volume_flow_max_s5": {0.113, "m3/h"}, "energy_t2_u1": {218370, "Wh"}}
	if len(r.Records) != 3 {
		t.Fatalf("records = %+v", r.Records)
	}
	for _, rec := range r.Records {
		w, ok := want[rec.Name()]
		if !ok {
			t.Errorf("unexpected record %s", rec.Name())
			continue
		}
		v := rec.Value
		if i, ok := v.(int64); ok {
			v = float64(i)
		}
		if !near(v, w.v) || rec.Unit != w.unit {
			t.Errorf("%s = %v %s, want %v %s", rec.Name(), rec.Value, rec.Unit, w.v, w.unit)
		}
	}
	// Re-encoding gives the published bytes.
	if got := hex.EncodeToString(f.Encode()); got != published {
		t.Errorf("re-encoded %s", got)
	}
	// Hand-built short and control frames (checksum = sum of C and A).
	sel, _ := wired.SecondaryAddress{ID: "12345678", Manufacturer: 0xFFFF, Version: 0xFF, Medium: 0xFF}.Bytes()
	for want, fr := range map[string]wired.Frame{
		"1040014116":                         {C: wired.CSndNke, A: 1},
		"107b017c16":                         {C: wired.CReqUD2 | wired.FCB, A: 1},
		"105bfd5816":                         {C: wired.CReqUD2, A: wired.AddrSecondary},
		"e5":                                 {Single: true},
		"680b0b6853fd5278563412ffffffffb216": {Long: true, C: wired.CSndUD, A: wired.AddrSecondary, CI: wired.CISelect, Data: sel},
		"6803036853fe50a116":                 {Long: true, C: wired.CSndUD, A: wired.AddrBroadcastAns, CI: wired.CIAppReset},
	} {
		if got := hex.EncodeToString(fr.Encode()); got != want {
			t.Errorf("%+v encoded %s, want %s", fr, got, want)
		}
		back, err := wired.ReadFrame(bytes.NewReader(unhex(t, want)))
		if err != nil || back.C != fr.C || back.A != fr.A || back.CI != fr.CI || !bytes.Equal(back.Data, fr.Data) && len(fr.Data) > 0 {
			t.Errorf("%s decoded %+v %v", want, back, err)
		}
	}
	// Damaged frames and collision garbage.
	for _, bad := range []string{"1040014216", "681f1e68", "33", published[:len(published)-4] + "1916"} {
		if _, err := wired.ReadFrame(bytes.NewReader(unhex(t, bad))); !errors.Is(err, wired.ErrFrame) {
			t.Errorf("%s: %v, want ErrFrame", bad, err)
		}
	}
	// Secondary addresses: patterns, wildcards and matching.
	p, err := wired.ParsePattern("1234ffff.pad.*.07")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Address.Matches(p) || r.Address.Matches(wired.SecondaryAddress{ID: "1234FFFF", Manufacturer: 0xFFFF, Version: 0xFF, Medium: 4}) {
		t.Errorf("matching against %+v", p)
	}
	for _, bad := range []string{"123", "1234567X", "12345678.KAMX", "12345678.KAM.ZZ"} {
		if _, err := wired.ParsePattern(bad); err == nil {
			t.Errorf("pattern %q accepted", bad)
		}
	}
	// A telegram ending in DIF 1F announces more telegrams.
	more := wired.Frame{Long: true, C: wired.CRspUD, A: 5, CI: wired.CIRspVariable, Data: append(unhex(t, "785634122440010756000000"), 0x03, 0x13, 0x01, 0x00, 0x00, 0x1F)}
	if r, err := wired.ParseResponse(more); err != nil || !r.More {
		t.Errorf("more-follows telegram: %+v %v", r, err)
	}
}
