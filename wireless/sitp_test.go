package wireless

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"testing"
)

// Covers: SIG-IPE-913, SIG-IPE-914
func TestWMBusSITPKeyManagement(t *testing.T) {
	kek := hx(t, "101112131415161718191A1B1C1D1E1F")
	newKey := hx(t, "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF")
	at := TargetTime{0, 0, 0, 0, 0}
	// Transfer: DSI 01h wraps 23 bytes (MLI 17h) into 32 (table A.7).
	c, err := SITPWrapKey(kek, newKey, at, KeyInfo{ID: 2, Version: 1})
	if err != nil || len(c) != 32 {
		t.Fatalf("DSI 01h: %d bytes, %v", len(c), err)
	}
	k, err := SITPUnwrapKey(kek, c)
	if err != nil || !bytes.Equal(k.Key, newKey) || k.ID != 2 || k.Version != 1 {
		t.Fatalf("unwrap DSI 01h: %+v %v", k, err)
	}
	// ICV and MLI: the first 8 bytes of the unwrapped semiblocks are
	// A65959A6 00000017.
	blk, _ := aes.NewCipher(kek)
	iv, _ := kwWInv(blk, c)
	if !bytes.Equal(iv, hx(t, "A65959A600000017")) {
		t.Errorf("DSI 01h ICV/MLI %X", iv)
	}
	// Activate/deactivate/destroy/generate: DSI 02h, 7 bytes → 16.
	c2, _ := SITPWrapAction(kek, at, KeyInfo{ID: 2, Version: 1})
	if len(c2) != 16 {
		t.Errorf("DSI 02h is %d bytes, want 16", len(c2))
	}
	// Combined: DSI 03h, 10 bytes → 24.
	c3, _ := SITPWrapKeyPair(kek, at, KeyInfo{2, 1}, KeyInfo{1, 0}, true)
	if len(c3) != 24 {
		t.Errorf("DSI 03h is %d bytes, want 24", len(c3))
	}
	// A wrong wrapper key fails the ICV check.
	if _, err := SITPUnwrapKey(hx(t, "00000000000000000000000000000000"), c); err == nil {
		t.Error("unwrapped with the wrong key")
	}
	// A command APL with two blocks and its round trip.
	apl := EncodeSITP(
		SITPBlock{ID: 0, BCF: SITPTransfer, DSI: DSIKey, DSH1: 0x10, DSH2: 0xFF, Content: c},
		SITPBlock{ID: 1, BCF: SITPActivate, DSI: DSIKeyAction, DSH1: 0x10, DSH2: 0xFF, Content: c2},
	)
	if binary.LittleEndian.Uint16(apl) != 6+32 || apl[2] != 0 || apl[3] != 0x00 || apl[5] != 0x01 {
		t.Errorf("block header % X", apl[:8])
	}
	blocks, err := ParseSITP(append(apl, 0x2F, 0x2F))
	if err != nil || len(blocks) != 2 || blocks[1].BCF != SITPActivate || !bytes.Equal(blocks[1].Content, c2) {
		t.Fatalf("parse: %v %+v", err, blocks)
	}
	// A block length below 6 voids the whole structure.
	bad := append([]byte{5, 0, 0, 0, 0, 0, 0}, apl...)
	if _, err := ParseSITP(bad); !errors.Is(err, ErrSITPLength) {
		t.Errorf("BL 5: %v", err)
	}
}

// Covers: SIG-IPE-915, SIG-IPE-916
func TestWMBusSITPResponses(t *testing.T) {
	m := testMeter(t)
	kek := hx(t, "101112131415161718191A1B1C1D1E1F")
	e2e := hx(t, "303132333435363738393A3B3C3D3E3F")
	wrapper := func(id, ver byte) []byte {
		switch id {
		case 0x10:
			return kek
		case 0x11:
			return e2e
		}
		return nil
	}
	gen := hx(t, "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF")
	wrappedKey, _ := SITPWrapKey(kek, gen, TargetTime{}, KeyInfo{3, 0})
	all := []byte{0x00, 1, 0x00, 0x03, 2, 0x00, 0x01}
	wrappedAll, _ := KWPWrap(kek, all)
	app, _ := SealSITPApp(e2e, DSICCM8, m, SITPUp, SITPApp{KeyCounter: 12, PID: 0x01, APDU: sampleAPL})
	resp := EncodeSITP(
		SITPBlock{ID: 0, BCF: 0x81, DSI: DSIStatus, DSH1: 0x10, DSH2: 0xFF, Content: []byte{0x01}},
		SITPBlock{ID: 1, BCF: 0x86, DSI: DSIKey, DSH1: 0x10, DSH2: 0xFF, Content: wrappedKey},
		SITPBlock{ID: 2, BCF: 0x87, DSI: DSIAllKeys, DSH1: 0x10, DSH2: 0xFF, Content: wrappedAll},
		SITPBlock{ID: 3, BCF: 0x88, DSI: DSIActiveKeys, DSH1: 0x00, DSH2: 0x0F, Content: []byte{0, 0, 3, 1}},
		SITPBlock{ID: 4, BCF: 0x89, DSI: DSIActiveCounts, DSH1: 0x00, DSH2: 0x0F, Content: []byte{3, 1, 0x78, 0x01, 0, 0}},
		SITPBlock{ID: 5, BCF: 0xA0, DSI: DSICCM8, DSH1: 0x11, DSH2: 0xFF, Content: app},
	)
	// The response arrives as a meter telegram with CI C4h (short header).
	tpdu, _ := SealTPL(CISITPRespShort, false, m, 0x33, 0, 0, Seal{Mode: 0}, resp)
	tg, err := Decode(linkFrame(m, tpdu), FormatNoCRC, nil)
	if err != nil || len(tg.SITP) != 6 || tg.HeaderKind != "short" {
		t.Fatalf("C4h telegram: %v, %d blocks", err, len(tg.SITP))
	}
	rs, err := ReadSITPResponses(tg.APL, tg.Meter, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	if *rs[0].Status != 0x01 || SITPStatusText(*rs[0].Status) != "scheduled at the target time" {
		t.Errorf("status %v", rs[0].Status)
	}
	if !bytes.Equal(rs[1].Key.Key, gen) || rs[1].Key.ID != 3 {
		t.Errorf("DSI 01h: %+v", rs[1].Key)
	}
	if len(rs[2].AllKeys[0x00]) != 1 || len(rs[2].AllKeys[0x03]) != 2 {
		t.Errorf("DSI 20h: %v", rs[2].AllKeys)
	}
	if len(rs[3].Active) != 2 || rs[3].Active[1] != (KeyInfo{3, 1}) {
		t.Errorf("DSI 21h: %v", rs[3].Active)
	}
	if rs[4].Counters[0].Counter != 0x178 {
		t.Errorf("DSI 23h: %v", rs[4].Counters)
	}
	if rs[5].App == nil || rs[5].App.KeyCounter != 12 || !bytes.Equal(rs[5].App.APDU, sampleAPL) {
		t.Errorf("DSI 36h: %+v", rs[5].App)
	}
	// A DSI that does not answer its BCF is refused (table A.3).
	wrong := EncodeSITP(SITPBlock{ID: 0, BCF: 0x88, DSI: DSIActiveCounts, Content: []byte{3, 1, 0, 0, 0, 0}})
	if _, err := ReadSITPResponses(wrong, m, wrapper); err == nil {
		t.Error("DSI 23h accepted for BCF 88h")
	}
	// End-to-end structures: every mechanism round-trips downlink, and a
	// changed byte or the wrong direction fails.
	for _, dsi := range []byte{DSIHMACSHA256, DSICMAC8, DSICMAC16, DSIGCM, DSIGMAC, DSICCM8, DSICCM16} {
		a := SITPApp{KeyCounter: 7, At: TargetTime{1, 2, 3, 4, 5}, PID: 0x01, APDU: []byte{0x02, 0xFD, 0x1B, 0x00, 0x01}}
		c, err := SealSITPApp(e2e, dsi, m, SITPDown, a)
		if err != nil {
			t.Fatal(err)
		}
		got, err := OpenSITPApp(e2e, dsi, m, SITPDown, c)
		if err != nil || got.KeyCounter != 7 || got.At != a.At || !bytes.Equal(got.APDU, a.APDU) {
			t.Errorf("DSI %02X round trip: %v %+v", dsi, err, got)
		}
		if _, err := OpenSITPApp(e2e, dsi, m, SITPDown, flip(c, 6)); !errors.Is(err, ErrMAC) {
			t.Errorf("DSI %02X changed: %v", dsi, err)
		}
		if dsi >= DSIGCM {
			if _, err := OpenSITPApp(e2e, dsi, m, SITPUp, c); !errors.Is(err, ErrMAC) {
				t.Errorf("DSI %02X other direction: %v", dsi, err)
			}
		}
		if dsi == DSIGCM || dsi == DSICCM8 || dsi == DSICCM16 {
			if bytes.Contains(c, a.APDU) {
				t.Errorf("DSI %02X left the APDU in clear", dsi)
			}
		}
	}
}
