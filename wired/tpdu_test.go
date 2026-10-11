package wired_test

import (
	"bytes"
	"testing"

	"github.com/cB-Sigma/mbus/tpdu"
)

// Covers: SIG-IPE-2233
func TestDLMSTransportTPDU(t *testing.T) {
	// EN 13757-1:2021 8.2.4 Tables 7, 8: CI 000 FIN FFFF, STSAP, DTSAP, data.
	short := tpdu.SegmentAPDU([]byte{0xC0, 0x01}, tpdu.SAPPublicClient, tpdu.SAPManagement)
	if len(short) != 1 || !bytes.Equal(short[0].Encode(), []byte{0x10, 0x10, 0x01, 0xC0, 0x01}) {
		t.Fatalf("short APDU: %+v", short)
	}
	apdu := make([]byte, 16*248+10) // 17 TPDUs: the counter wraps
	for i := range apdu {
		apdu[i] = byte(i)
	}
	tps := tpdu.SegmentAPDU(apdu, 0x01, 0x10)
	if len(tps) != 17 || tps[0].Counter != 0 || tps[15].Counter != 15 || tps[16].Counter != 0 || !tps[16].FIN || tps[15].FIN ||
		len(tps[0].Data) != tpdu.TPDUMaxData {
		t.Fatalf("segments %d, last %+v", len(tps), tps[len(tps)-1].Counter)
	}
	var r tpdu.Reassembler
	var got []byte
	for _, tp := range tps {
		p, err := tpdu.ParseTPDU(tp.Encode())
		if err != nil {
			t.Fatal(err)
		}
		if got, err = r.Add(p); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got, apdu) {
		t.Fatal("reassembly lost data")
	}
	// A doubled TPDU (counter repeated) aborts; the next APDU starts at 0.
	if _, err := r.Add(tps[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(tps[0]); err == nil {
		t.Error("a doubled TPDU accepted")
	}
	if p, err := r.Add(short[0]); err != nil || !bytes.Equal(p, []byte{0xC0, 0x01}) {
		t.Errorf("after the abort: %v %v", p, err)
	}
	// CI with bits 8 to 6 set belongs to EN 13757-3 traffic; data over 248 bytes is refused.
	for _, bad := range [][]byte{{0x72, 1, 1}, {0x10, 1}, append([]byte{0x10, 1, 1}, make([]byte, 249)...)} {
		if _, err := tpdu.ParseTPDU(bad); err == nil {
			t.Errorf("% X accepted", bad[:3])
		}
	}
}
