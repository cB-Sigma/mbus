package wireless

import (
	"errors"
	"fmt"
)

// Forward error correction (EN 13757-4:2025, 12.8).
//
// Optional FEC data follow the last byte of a frame (format A or B, with
// its CRCs) and precede the mode's postamble; nothing in the frame says
// whether they are there. They are a 16-bit FEC header, sent low byte
// first, holding a 5-bit FEC ID three times (bits 14-10, 9-5, 4-0; bit 15
// is 0) so that it can be read by a bitwise majority vote, then the check
// data of the algorithm the ID names. ID 01h is Reed-Solomon (255,223) with
// 8-bit symbols and 16 correctable symbols, field and generator polynomial
// as in CCSDS 131.0-B-5 (4.3.3, 4.3.4): GF(2^8) from x^8+x^7+x^2+x+1 and
// g(x) = product of (x - a^(11j)) for j = 112..143. A shorter frame is
// padded with 00h to 223 bytes for the computation and the padding is not
// sent. Table 41 allows it in modes S and T (unidirectional), C and N (both
// directions) and F (unidirectional), not in mode R.
//
// Where it plugs in: the receivers this adapter supports (iM871A, Amber,
// raw L-framed serial, hex lines) hand over frames the radio chip already
// cut at the L field, so any FEC bytes are gone. A receiver that sees the
// raw bit stream (an SDR front end) would, after removing the chip coding,
// pass the bytes from the L field on to DecodeFEC before StripCRC.
//
// Choices where the text is open (see the findings in the report): the
// frame bytes are the high-order information symbols with the padding in
// front of them (CCSDS virtual fill, i.e. a shortened code), the 32 check
// bytes are sent highest-order first, the conventional (not dual-basis)
// symbol representation is used, and frames longer than 223 bytes are not
// covered.

// FECIDReedSolomon is FEC ID 01h (header value 0421h).
const (
	FECIDReedSolomon = 0x01
	fecHeaderRS      = 0x0421
	rsN, rsK         = 255, 223
	rsParity         = rsN - rsK
	rsFCR            = 112 // first consecutive root, as a power of beta = a^11
)

// Errors of the FEC decoder.
var (
	ErrFECUncorrectable = errors.New("wM-Bus FEC: too many symbol errors to correct")
	ErrFECAbsent        = errors.New("wM-Bus FEC: no Reed-Solomon FEC data after the frame")
)

// FECHeader builds the 16-bit FEC header for an ID.
func FECHeader(id byte) uint16 {
	i := uint16(id & 0x1F)
	return i<<10 | i<<5 | i
}

// FECID reads the FEC ID from a header by bitwise majority of its three
// copies.
func FECID(h uint16) byte {
	a, b, c := h>>10&0x1F, h>>5&0x1F, h&0x1F
	return byte(a&b | a&c | b&c)
}

// gf is GF(2^8) with field polynomial x^8+x^7+x^2+x+1 (0x187). exp and log
// are taken over beta = a^11, the element the code's roots are powers of;
// beta is primitive because 11 and 255 are coprime.
type gfTables struct {
	exp [510]byte
	log [256]int
}

var gf = func() (t gfTables) {
	var alpha [255]byte
	x := 1
	for i := range 255 {
		alpha[i] = byte(x)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x187
		}
	}
	for i := range 255 {
		v := alpha[(11*i)%255]
		t.exp[i], t.exp[i+255] = v, v
		t.log[v] = i
	}
	return t
}()

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gf.exp[gf.log[a]+gf.log[b]]
}

func gfDiv(a, b byte) byte {
	if a == 0 {
		return 0
	}
	return gf.exp[(gf.log[a]-gf.log[b]+255)%255]
}

// gfPow is beta^e.
func gfPow(e int) byte { return gf.exp[((e%255)+255)%255] }

// rsGen is g(x), highest degree first (monic, 33 coefficients).
var rsGen = func() []byte {
	g := []byte{1}
	for j := rsFCR; j < rsFCR+rsParity; j++ {
		r := gfPow(j)
		next := make([]byte, len(g)+1)
		for i, c := range g {
			next[i] ^= c
			next[i+1] ^= gfMul(c, r)
		}
		g = next
	}
	return g
}()

// rsParityOf returns the 32 check bytes of up to 223 information bytes
// (padded in front with zeros).
func rsParityOf(info []byte) []byte {
	rem := make([]byte, rsParity)
	for _, d := range info {
		f := d ^ rem[0]
		copy(rem, rem[1:])
		rem[rsParity-1] = 0
		if f != 0 {
			for i := range rsParity {
				rem[i] ^= gfMul(rsGen[i+1], f)
			}
		}
	}
	return rem
}

// EncodeFEC appends the FEC header and Reed-Solomon check data to a frame
// as sent (format A or B with CRCs), for tests and simulators.
func EncodeFEC(frame []byte) ([]byte, error) {
	if len(frame) == 0 || len(frame) > rsK {
		return nil, fmt.Errorf("wM-Bus FEC covers frames of 1 to %d bytes, got %d", rsK, len(frame))
	}
	out := append([]byte(nil), frame...)
	out = append(out, byte(fecHeaderRS&0xFF), byte(fecHeaderRS>>8))
	return append(out, rsParityOf(frame)...), nil
}

// DecodeFEC takes the bytes following the sync word (frame, FEC header,
// check data, maybe more) and returns the corrected frame and the number of
// corrected bytes. The frame length comes from the L field in the given
// format (A or B), so an error in the L field itself is not recoverable.
func DecodeFEC(b []byte, format FrameFormat) ([]byte, int, error) {
	if len(b) < 1 {
		return nil, 0, ErrFECAbsent
	}
	n := int(b[0]) + 1
	switch format {
	case FormatA:
		n = FrameLenA(int(b[0]))
	case FormatB:
	default:
		return nil, 0, fmt.Errorf("FEC needs frame format A or B, got %q", format)
	}
	if n > rsK {
		return nil, 0, fmt.Errorf("wM-Bus FEC covers frames up to %d bytes, this one has %d", rsK, n)
	}
	if len(b) < n+2+rsParity {
		return nil, 0, ErrFECAbsent
	}
	if FECID(uint16(b[n])|uint16(b[n+1])<<8) != FECIDReedSolomon {
		return nil, 0, ErrFECAbsent
	}
	cw := make([]byte, rsN) // padding, frame, parity
	pad := rsK - n
	copy(cw[pad:], b[:n])
	copy(cw[rsK:], b[n+2:n+2+rsParity])
	fixed, err := rsCorrect(cw, pad)
	if err != nil {
		return nil, 0, err
	}
	return cw[pad : pad+n], fixed, nil
}

// rsCorrect corrects a 255-byte codeword in place (index 0 is the highest
// degree coefficient); errors in the first pad (virtual) positions mean the
// word is not correctable.
func rsCorrect(cw []byte, pad int) (int, error) {
	// Syndromes S_j = r(beta^(fcr+j)).
	var syn [rsParity]byte
	nonzero := false
	for j := range rsParity {
		x := gfPow(rsFCR + j)
		var s byte
		for _, c := range cw {
			s = gfMul(s, x) ^ c
		}
		syn[j] = s
		nonzero = nonzero || s != 0
	}
	if !nonzero {
		return 0, nil
	}
	// Berlekamp-Massey: error locator sigma(x), lowest degree first.
	sigma := []byte{1}
	prev := []byte{1}
	l, m, bb := 0, 1, byte(1)
	for k := range rsParity {
		d := syn[k]
		for i := 1; i <= l && i < len(sigma); i++ {
			d ^= gfMul(sigma[i], syn[k-i])
		}
		if d == 0 {
			m++
			continue
		}
		coef := gfDiv(d, bb)
		next := append([]byte(nil), sigma...)
		for len(next) < len(prev)+m {
			next = append(next, 0)
		}
		for i, p := range prev {
			next[i+m] ^= gfMul(coef, p)
		}
		if 2*l <= k {
			prev, l, bb, m = sigma, k+1-l, d, 1
		} else {
			m++
		}
		sigma = next
	}
	for len(sigma) > 1 && sigma[len(sigma)-1] == 0 {
		sigma = sigma[:len(sigma)-1]
	}
	if l > rsParity/2 || len(sigma)-1 != l {
		return 0, ErrFECUncorrectable
	}
	// Chien search: position p (degree 254-p) is in error when
	// sigma(beta^-(254-p)) = 0.
	var pos []int
	for p := range rsN {
		xinv := gfPow(-(rsN - 1 - p))
		var v byte
		for i := len(sigma) - 1; i >= 0; i-- {
			v = gfMul(v, xinv) ^ sigma[i]
		}
		if v == 0 {
			pos = append(pos, p)
		}
	}
	if len(pos) != l {
		return 0, ErrFECUncorrectable
	}
	// Forney: omega(x) = S(x) sigma(x) mod x^32; the error value at X is
	// X^(1-fcr) omega(X^-1) / sigma'(X^-1).
	omega := make([]byte, rsParity)
	for i := range rsParity {
		for j := 0; j <= i && j < len(sigma); j++ {
			omega[i] ^= gfMul(sigma[j], syn[i-j])
		}
	}
	for _, p := range pos {
		if p < pad {
			return 0, ErrFECUncorrectable
		}
		deg := rsN - 1 - p
		xinv := gfPow(-deg)
		var num, den byte
		for i := len(omega) - 1; i >= 0; i-- {
			num = gfMul(num, xinv) ^ omega[i]
		}
		// sigma'(x): odd-degree terms only (characteristic 2).
		for i := len(sigma) - 1; i >= 1; i-- {
			if i%2 == 1 {
				den ^= gfMul(sigma[i], gfPow(-deg*(i-1)))
			}
		}
		if den == 0 {
			return 0, ErrFECUncorrectable
		}
		cw[p] ^= gfMul(gfPow(deg*(1-rsFCR)), gfDiv(num, den))
	}
	return len(pos), nil
}
