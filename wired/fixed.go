package wired

import (
	"encoding/binary"
	"fmt"
	"math"
)

// Fixed data structure (EN 1434-3:1997, carried over into the M-Bus
// documentation's application layer; CI 73h, and 77h with multi-byte
// fields most significant byte first): identification number (8 BCD digits), access
// number, status, two medium/unit bytes and two 4-byte counters.

// Status bits of the fixed structure.
const (
	FixedBinary     = 0x01 // counters are signed binary, else BCD
	FixedStored     = 0x02 // counters were stored at a fixed date, else actual
	FixedPowerLow   = 0x04
	FixedPermanent  = 0x08 // permanent error
	FixedTemporary  = 0x10 // temporary error
	fixedUnitSame   = 0x3E // counter 2: counter 1's unit, historic value
	fixedStructSize = 16
)

// FixedCounter is one counter of a fixed data structure, scaled to its
// base unit.
type FixedCounter struct {
	Quantity string  // "energy", "volume", … or "" when the unit code has none
	Unit     string  // SenML / UCUM symbol like the variable-data records
	Value    float64 // scaled; raw when the unit code is not a physical unit
	UnitCode byte    // the 6-bit unit code as sent
	Historic bool    // stored at a fixed date (status bit, or unit code 3Eh)
	Valid    bool    // false when a BCD counter holds non-decimal digits
}

// FixedData is a decoded fixed data structure.
type FixedData struct {
	ID       string
	Access   byte
	Status   byte
	Medium   string
	Counters [2]FixedCounter
}

// fixedMedium names the 4-bit medium code of the fixed structure.
var fixedMedium = [16]string{"other", "oil", "electricity", "gas", "heat", "steam", "hot_water", "water",
	"hca", "reserved", "gas_mode2", "heat_mode2", "hot_water_mode2", "water_mode2", "hca_mode2", "reserved"}

// fixedUnit maps a unit code to quantity, unit and decimal exponent.
func fixedUnit(c byte) (q, unit string, exp int, ok bool) {
	type span struct {
		from    byte
		q, unit string
		exp     int
	}
	// Each span covers three codes: ×1, ×10, ×100.
	spans := []span{
		{0x02, "energy", "Wh", 0}, {0x05, "energy", "Wh", 3}, {0x08, "energy", "Wh", 6},
		{0x0B, "energy", "J", 3}, {0x0E, "energy", "J", 6}, {0x11, "energy", "J", 9},
		{0x14, "power", "W", 0}, {0x17, "power", "W", 3}, {0x1A, "power", "W", 6},
		{0x1D, "power", "J/h", 3}, {0x20, "power", "J/h", 6}, {0x23, "power", "J/h", 9},
		{0x26, "volume", "m3", -6}, {0x29, "volume", "m3", -3}, {0x2C, "volume", "m3", 0},
		{0x2F, "volume_flow", "m3/h", -6}, {0x32, "volume_flow", "m3/h", -3}, {0x35, "volume_flow", "m3/h", 0},
	}
	for _, s := range spans {
		if c >= s.from && c < s.from+3 {
			return s.q, s.unit, s.exp + int(c-s.from), true
		}
	}
	switch c {
	case 0x38:
		return "temperature", "Cel", -3, true
	case 0x39:
		return "hca", "", 0, true
	}
	return "", "", 0, false
}

// ParseFixed decodes the 16 data bytes of a CI 73h (msbFirst false) or
// 77h (msbFirst true) response.
func ParseFixed(p []byte, msbFirst bool) (*FixedData, error) {
	if len(p) < fixedStructSize {
		return nil, fmt.Errorf("the fixed data structure needs %d bytes, got %d", fixedStructSize, len(p))
	}
	b := append([]byte(nil), p[:fixedStructSize]...)
	if msbFirst {
		// Multi-byte fields arrive most significant byte first.
		for _, f := range [][2]int{{0, 4}, {6, 8}, {8, 12}, {12, 16}} {
			for i, j := f[0], f[1]-1; i < j; i, j = i+1, j-1 {
				b[i], b[j] = b[j], b[i]
			}
		}
	}
	fd := &FixedData{Access: b[4], Status: b[5]}
	id, ok := bcdDigits(b[0:4])
	if !ok {
		return nil, fmt.Errorf("identification number %X is not BCD", b[0:4])
	}
	fd.ID = fmt.Sprintf("%08d", id)
	u1, u2 := b[6], b[7]
	fd.Medium = fixedMedium[(u1>>6)|(u2>>6)<<2]
	for i, code := range []byte{u1 & 0x3F, u2 & 0x3F} {
		raw := b[8+4*i : 12+4*i]
		c := FixedCounter{UnitCode: code, Historic: fd.Status&FixedStored != 0, Valid: true}
		var n int64
		if fd.Status&FixedBinary != 0 {
			n = int64(int32(binary.LittleEndian.Uint32(raw)))
		} else {
			v, ok := bcdDigits(raw)
			n, c.Valid = v, ok
		}
		uc := code
		if i == 1 && code == fixedUnitSame {
			uc, c.Historic = u1&0x3F, true
		}
		q, unit, exp, known := fixedUnit(uc)
		c.Quantity, c.Unit, c.Value = q, unit, float64(n)
		if known {
			c.Value = float64(n) * math.Pow10(exp)
			// Keep decimal values tidy (0.001 × 123 = 0.123, not 0.12300000000000001).
			if exp < 0 {
				c.Value = math.Round(c.Value*math.Pow10(-exp)) / math.Pow10(-exp)
			}
		}
		fd.Counters[i] = c
	}
	return fd, nil
}

// bcdDigits reads packed BCD, least significant byte first.
func bcdDigits(b []byte) (int64, bool) {
	var n int64
	for i := len(b) - 1; i >= 0; i-- {
		hi, lo := b[i]>>4, b[i]&0x0F
		if hi > 9 || lo > 9 {
			return 0, false
		}
		n = n*100 + int64(hi)*10 + int64(lo)
	}
	return n, true
}
