package wireless

import (
	"encoding/binary"
)

// SealAFLFrames authenticates a TPDU with an 8-byte AFL CMAC (KDF-A, key
// and counter) and frames it: one datagram behind ELL 8Ch when it fits,
// else fragments behind ELL 8Eh naming peer with message authentication
// (EN 13757-7:2025 6.3; OMS Volume 2 6.2.4: MCL, MCR and ML in the first
// fragment, the MAC over MCL, MCR, ML and the whole TPDU in the last).
func SealAFLFrames(head []byte, peer Header, c, cNext, cc, acc byte, tpdu, key []byte, counter uint32, sender Header, toMeter bool) ([][]byte, error) {
	if one, err := SealAFL(tpdu, sender, key, 1, counter, 5, nil, toMeter); err != nil {
		return nil, err
	} else if 10+3+len(one) <= 255 {
		return SplitTLSFrames(head, peer, c, cNext, cc, acc, one), nil
	}
	_, kmac, err := SessionKeys(key, 1, counter, sender, toMeter)
	if err != nil {
		return nil, err
	}
	a := &AFL{MCL: 0x05 | 0x20 | 0x40, Counter: counter, ML: uint16(len(tpdu))}
	a.has.mcl, a.has.mcr, a.has.ml = true, true, true
	full, err := CMAC(kmac, append(a.macInput(), tpdu...))
	if err != nil {
		return nil, err
	}
	frame := func(c byte, parts ...[]byte) []byte {
		f := append([]byte{0}, head...)
		f[1] = c
		for _, p := range parts {
			f = append(f, p...)
		}
		f[0] = byte(len(f) - 1)
		return f
	}
	ell := []byte{CIELL10, cc, acc}
	ell = binary.LittleEndian.AppendUint16(ell, peer.MField)
	ell = append(ell, peer.A[:]...)
	const room = 255 - 10 - 11 - 2 // after link header, ELL and the AFL CI and AFLL
	var out [][]byte
	fid := byte(1)
	for rest := tpdu; len(rest) > 0; fid++ {
		fcl := uint16(fid)
		var opt []byte
		if fid == 1 {
			fcl |= AFLMCLP | AFLMCRP | AFLMLP
			opt = append(opt, a.MCL)
			opt = binary.LittleEndian.AppendUint32(opt, counter)
			opt = binary.LittleEndian.AppendUint16(opt, a.ML)
		}
		space := room - 2 - len(opt)
		n := min(len(rest), space)
		if n == len(rest) && n+8 > space {
			n = space - 8 // the last fragment needs room for the MAC
		}
		if n < len(rest) {
			fcl |= AFLMF
		} else {
			fcl |= AFLMACP
			opt = append(opt, full[:8]...)
		}
		afl := append(binary.LittleEndian.AppendUint16(nil, fcl), opt...)
		out = append(out, frame(c, ell, []byte{CIAFL, byte(len(afl))}, afl, rest[:n]))
		rest = rest[n:]
		c = cNext
	}
	return out, nil
}
