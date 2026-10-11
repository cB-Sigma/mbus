package wired_test

import (
	"bytes"
	"testing"

	"github.com/cB-Sigma/mbus/wired"
)

// The fixed data structure example published with the M-Bus
// documentation (m-bus.com, application layer, CI 73h): meter 12345678 at
// primary address 5, access number 10, BCD counters, medium water,
// counter 1 = 1 l (actual), counter 2 = 135 l (unit 3Eh: same unit,
// historic).
const publishedFixed = "6813136808057378563412" + "0a00e97e010000003501000" + "03c16"

// Covers: SIG-IPE-666
func TestMBusFixedDataStructure(t *testing.T) {
	f, err := wired.ReadFrame(bytes.NewReader(unhex(t, publishedFixed)))
	if err != nil {
		t.Fatal(err)
	}
	r, err := wired.ParseResponse(f)
	if err != nil {
		t.Fatal(err)
	}
	fd := r.Fixed
	if fd == nil || fd.ID != "12345678" || fd.Access != 10 || fd.Medium != "water" || r.Primary != 5 {
		t.Fatalf("fixed = %+v", fd)
	}
	c1, c2 := fd.Counters[0], fd.Counters[1]
	if c1.Quantity != "volume" || c1.Unit != "m3" || !near(c1.Value, 0.001) || c1.Historic {
		t.Errorf("counter 1 = %+v", c1)
	}
	if c2.Quantity != "volume" || c2.Unit != "m3" || !near(c2.Value, 0.135) || !c2.Historic || c2.UnitCode != 0x3E {
		t.Errorf("counter 2 = %+v", c2)
	}
	// CI 77h: the same content, multi-byte fields most significant first;
	// status bit 0 selects signed binary counters.
	msb := []byte{0x12, 0x34, 0x56, 0x78, 0x0A, 0x01, 0x05, 0x85, 0xFF, 0xFF, 0xFF, 0xFE, 0x00, 0x00, 0x01, 0x00}
	fd, err = wired.ParseFixed(msb, true)
	if err != nil {
		t.Fatal(err)
	}
	// Medium bits: 0x85>>6 = 2 (low), 0x05>>6 = 0 → electricity; units
	// 05h kWh and 05h kWh; counters -2 and 256 (binary).
	if fd.ID != "12345678" || fd.Medium != "electricity" || fd.Counters[0].Value != -2000 || fd.Counters[0].Unit != "Wh" || fd.Counters[1].Value != 256000 {
		t.Errorf("CI 77 = %+v", fd)
	}
	if _, err := wired.ParseFixed(msb[:10], false); err == nil {
		t.Error("a short fixed structure was accepted")
	}
	bad := append([]byte(nil), unhex(t, "785634120a00e97e")...)
	bad = append(bad, 0x0A, 0, 0, 0, 0, 0, 0, 0) // counter 1 not BCD
	if fd, err := wired.ParseFixed(bad, false); err != nil || fd.Counters[0].Valid || !fd.Counters[1].Valid {
		t.Errorf("non-BCD counter: %+v %v", fd, err)
	}
}
