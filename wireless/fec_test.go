package wireless

import (
	"bytes"
	"errors"
	"testing"
)

// Covers: SIG-IPE-931
func TestFECHeader(t *testing.T) {
	// Table 40: ID 01h is header 0421h, ID 1Fh is 7FFFh; bit 15 is 0.
	if FECHeader(FECIDReedSolomon) != 0x0421 || FECHeader(0x1F) != 0x7FFF || FECHeader(0) != 0 {
		t.Errorf("headers %04X %04X", FECHeader(1), FECHeader(0x1F))
	}
	// One corrupted copy is outvoted; bit 15 is ignored.
	for _, h := range []uint16{0x0421, 0x8421, 0x0431, 0x0021, 0x7C21} {
		if FECID(h) != FECIDReedSolomon {
			t.Errorf("FECID(%04X) = %02X", h, FECID(h))
		}
	}
}

// Covers: SIG-IPE-931
func TestFECGenerator(t *testing.T) {
	// The CCSDS roots a^(11j), j = 112..143, pair up as inverses, so g(x) is
	// monic of degree 32 and its coefficients are symmetric.
	if len(rsGen) != 33 || rsGen[0] != 1 {
		t.Fatalf("g(x) has %d coefficients", len(rsGen))
	}
	for i := range 33 {
		if rsGen[i] != rsGen[32-i] {
			t.Fatalf("g(x) not symmetric at %d: %X", i, rsGen)
		}
	}
	// beta = a^11 generates all 255 non-zero elements.
	seen := map[byte]bool{}
	for i := range 255 {
		seen[gfPow(i)] = true
	}
	if len(seen) != 255 || seen[0] {
		t.Errorf("beta generates %d elements", len(seen))
	}
}

// Covers: SIG-IPE-931
func TestFECCorrects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		frame  string
		format FrameFormat
	}{
		{"annex C.1 format A", annexCFormatA, FormatA},
		{"annex C.3 format B", annexCFormatB, FormatB},
	} {
		frame := hx(t, tc.frame)
		dg, err := EncodeFEC(frame)
		if err != nil {
			t.Fatal(err)
		}
		if len(dg) != len(frame)+2+32 || dg[len(frame)] != 0x21 || dg[len(frame)+1] != 0x04 {
			t.Fatalf("%s: datagram %X", tc.name, dg)
		}
		// Trailing postamble bytes are ignored.
		clean := append(append([]byte(nil), dg...), 0x55, 0x55)
		if got, n, err := DecodeFEC(clean, tc.format); err != nil || n != 0 || !bytes.Equal(got, frame) {
			t.Errorf("%s clean: %v %d", tc.name, err, n)
		}
		// 16 wrong bytes (frame after L, and check data) are corrected.
		bad := append([]byte(nil), dg...)
		var hit []int
		for i := 1; len(hit) < 16; i += 3 {
			if i == len(frame) || i == len(frame)+1 { // leave the FEC header
				continue
			}
			if i >= len(bad) {
				break
			}
			bad[i] ^= byte(0x5A + i)
			hit = append(hit, i)
		}
		if len(hit) != 16 {
			t.Fatalf("%s: only %d errors placed", tc.name, len(hit))
		}
		got, n, err := DecodeFEC(bad, tc.format)
		if err != nil || n != 16 || !bytes.Equal(got, frame) {
			t.Errorf("%s: 16 errors: %v %d %X", tc.name, err, n, got)
		}
		if _, _, err := StripCRC(got, tc.format); err != nil {
			t.Errorf("%s: corrected frame CRC: %v", tc.name, err)
		}
		// A 17th is too many.
		bad[len(bad)-1] ^= 0xFF
		if got, _, err := DecodeFEC(bad, tc.format); err == nil && bytes.Equal(got, frame) {
			t.Errorf("%s: 17 errors corrected", tc.name)
		}
		// A corrupted FEC header copy is outvoted.
		hdr := append([]byte(nil), dg...)
		hdr[len(frame)] ^= 0x10
		if _, _, err := DecodeFEC(hdr, tc.format); err != nil {
			t.Errorf("%s: header majority: %v", tc.name, err)
		}
	}
	// No FEC data after the frame.
	if _, _, err := DecodeFEC(hx(t, annexCFormatB), FormatB); !errors.Is(err, ErrFECAbsent) {
		t.Errorf("no FEC: %v", err)
	}
	if _, err := EncodeFEC(make([]byte, 224)); err == nil {
		t.Error("frame over 223 bytes accepted")
	}
	if _, _, err := DecodeFEC(hx(t, annexCFormatB), FormatNoCRC); err == nil {
		t.Error("FEC without a frame format accepted")
	}
}
