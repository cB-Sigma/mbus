package tpdu

import (
	"errors"
	"fmt"
)

// The transport sub-layer for DLMS/COSEM over the EN 60870-5-2 link layer
// (EN 13757-1:2021 8.2.4, Tables 7 and 8): each TPDU is a CI field (bits
// 8 to 6 zero, bit 5 FIN in the last TPDU of an APDU, bits 4 to 1 a
// fragment counter from 0 in the first TPDU of every APDU), the source and
// destination transport SAPs of one byte each (finding F-1205) and up to
// 248 data bytes. Wired and wireless M-Bus both carry it (package mbus
// re-exports it).

// TPDU limits and SAPs.
const (
	TPDUMaxData       = 248
	tpduFIN           = 0x10
	SAPBroadcast      = 0xFF // to every logical device of the called unit
	SAPManagement     = 0x01 // the management logical device
	SAPPublicClient   = 0x10 // the public client
	tpduCounterModulo = 16
)

// TPDU is one transport PDU.
type TPDU struct {
	FIN     bool
	Counter byte // 0 to 15
	STSAP   byte // the caller's logical device address
	DTSAP   byte // the called's
	Data    []byte
}

// Encode is the TPDU's bytes.
func (t TPDU) Encode() []byte {
	ci := t.Counter & 0x0F
	if t.FIN {
		ci |= tpduFIN
	}
	return append([]byte{ci, t.STSAP, t.DTSAP}, t.Data...)
}

// ParseTPDU reads one TPDU; a CI with any of bits 8 to 6 set is not one
// (it is an EN 13757-3 CI field of the bus's other traffic).
func ParseTPDU(b []byte) (TPDU, error) {
	if len(b) < 3 {
		return TPDU{}, errors.New("a TPDU needs CI, STSAP and DTSAP")
	}
	if b[0]&0xE0 != 0 {
		return TPDU{}, fmt.Errorf("CI %02X is not a DLMS transport CI (bits 8 to 6 must be 0)", b[0])
	}
	if len(b)-3 > TPDUMaxData {
		return TPDU{}, fmt.Errorf("a TPDU carries at most %d data bytes, not %d", TPDUMaxData, len(b)-3)
	}
	return TPDU{FIN: b[0]&tpduFIN != 0, Counter: b[0] & 0x0F, STSAP: b[1], DTSAP: b[2], Data: append([]byte(nil), b[3:]...)}, nil
}

// SegmentAPDU splits an APDU into TPDUs: counters from 0 (wrapping after
// 15), FIN in the last one (the only one for a short APDU).
func SegmentAPDU(apdu []byte, stsap, dtsap byte) []TPDU {
	var out []TPDU
	for i := 0; ; i++ {
		n := min(len(apdu), TPDUMaxData)
		out = append(out, TPDU{Counter: byte(i % tpduCounterModulo), STSAP: stsap, DTSAP: dtsap, Data: append([]byte(nil), apdu[:n]...)})
		apdu = apdu[n:]
		if len(apdu) == 0 {
			out[len(out)-1].FIN = true
			return out
		}
	}
}

// Reassembler joins TPDUs into APDUs. A counter out of sequence (a lost
// or doubled TPDU) aborts the APDU and re-initialises (8.2.4).
type Reassembler struct {
	buf     []byte
	next    byte
	started bool
	saps    [2]byte
}

// Add takes the next TPDU; it returns the APDU when the TPDU carries FIN.
func (r *Reassembler) Add(t TPDU) ([]byte, error) {
	if t.Counter != r.next || r.started && [2]byte{t.STSAP, t.DTSAP} != r.saps {
		r.Reset()
		return nil, fmt.Errorf("TPDU counter %d out of sequence or SAPs changed: the APDU is aborted", t.Counter)
	}
	if !r.started {
		r.started, r.saps = true, [2]byte{t.STSAP, t.DTSAP}
	}
	r.buf = append(r.buf, t.Data...)
	r.next = (r.next + 1) % tpduCounterModulo
	if !t.FIN {
		return nil, nil
	}
	apdu := r.buf
	r.Reset()
	return apdu, nil
}

// Reset re-initialises the reassembler.
func (r *Reassembler) Reset() { *r = Reassembler{} }
