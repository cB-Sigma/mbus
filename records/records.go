package records

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/cB-Sigma/dlms/obis"
)

// Application layer data records (EN 13757-3:2025 clause 6 and annexes A,
// B, C, E): DIF, DIFEs, VIF, VIFEs and data. Units are SenML / UCUM
// symbols ("Cel", "m3"). The code tables live in
// vif_tables.go.

// Record is one decoded data record.
type Record struct {
	DIF      byte
	DIFE     []byte
	VIF      byte   // primary VIF, extension bit included
	VIFE     []byte // every VIFE, extension bits included
	Function string // "instantaneous", "maximum", "minimum" or "error"
	Storage  int
	Tariff   int
	Subunit  int
	Quantity string // "volume", "energy", "flow_temperature", …
	Unit     string
	Modifier []string // meanings of combinable VIFEs
	Value    any      // float64, int64, string (dates, text, hex), map (types K, L)
	Raw      []byte   // the data field
	// Manufacturer marks manufacturer-specific data (DIF 0x0F/0x1F), a
	// manufacturer-specific VIF or VIFE; Value is then the data in hex.
	Manufacturer bool
	// Register marks a storage number that is a register number (a final
	// DIFE 00h, 6.3.5); Name then uses _r<n>.
	Register bool
	// RecordError is the record error signalled by a VIFE (6.4.8, table
	// 19), e.g. "data_overflow"; "" for none.
	RecordError string
	// Invalid marks a value coded as invalid (annex A: the reserved
	// minimum or all-ones integer, a NaN real, BCD digits A-E, the
	// invalid bit or pattern of a date/time); Value is then the data
	// field in hex digits.
	Invalid bool
	// Flags are the symbolic meanings of bit-field or enumerated data:
	// sensor status bits (6.5.3), installation conditions (table 14),
	// error flags and remote control (annex E, table C.4), sub device
	// types (6.5.2).
	Flags []string
	// action is the object action code + 1 (6.4.7), 0 when none.
	action int
	// BaseValue is, for a record whose VIF is followed by a manufacturer-
	// specific VIFE (7Fh or FFh), the data decoded as the VIF before it
	// says (number and Unit), nil otherwise. Value keeps the data raw: the
	// manufacturer may give the VIFE a meaning that changes the value
	// (commonly it only marks a phase or a variant).
	BaseValue any
	base      *vifInfo
	// declared is the OBIS code a declaration record gave this record
	// (annex H.3, ApplyOBISDeclarations).
	declared *obis.Code
}

// Quality is the reading quality of the record: "" for a
// normal value, otherwise "invalid" (an invalid coding) and the record
// error, comma-separated.
func (r Record) Quality() string {
	var q []string
	if r.Invalid {
		q = append(q, "invalid")
	}
	if r.RecordError != "" {
		q = append(q, r.RecordError)
	}
	return strings.Join(q, ",")
}

// Name is the record's point name: quantity, then the function, storage
// (or register), tariff and subunit when not the defaults, then modifiers.
func (r Record) Name() string {
	var b strings.Builder
	b.WriteString(r.Quantity)
	switch r.Function {
	case "maximum":
		b.WriteString("_max")
	case "minimum":
		b.WriteString("_min")
	case "error":
		b.WriteString("_err")
	}
	if r.Register {
		fmt.Fprintf(&b, "_r%d", r.Storage)
	} else if r.Storage > 0 {
		fmt.Fprintf(&b, "_s%d", r.Storage)
	}
	if r.Tariff > 0 {
		fmt.Fprintf(&b, "_t%d", r.Tariff)
	}
	if r.Subunit > 0 {
		fmt.Fprintf(&b, "_u%d", r.Subunit)
	}
	for _, m := range r.Modifier {
		b.WriteString("_" + m)
	}
	return b.String()
}

// Action is the generalized object layer action of a record sent master
// to slave (6.4.7, table 18); without an action VIFE it is "set". The
// same VIFE codes are record errors in the slave-to-master direction.
func (r Record) Action() string {
	if r.action == 0 {
		return "set"
	}
	return actions[r.action-1]
}

// MoreRecords reports whether the application layer ended with DIF 1Fh:
// the slave has more records in a following datagram (6.6).
func MoreRecords(recs []Record) bool {
	return len(recs) > 0 && recs[len(recs)-1].DIF == 0x1F
}

var functions = [4]string{"instantaneous", "maximum", "minimum", "error"}

// dataLen is the data field length per DIF data field code (table 4; -1:
// variable, -2: special).
var dataLen = [16]int{0, 1, 2, 3, 4, 4, 6, 8, 0, 1, 2, 3, 4, -1, 6, -2}

// DataLength is the length of the data field a DIF announces (its low
// four bits, table 4): -1 for variable length (LVAR), -2 for selection
// for readout.
func DataLength(dif byte) int { return dataLen[dif&0x0F] }

const (
	maxDIFE = 10 // 6.3.7
	maxVIFE = 10 // 6.4.1
)

// ParseRecords decodes the data records of an application layer.
func ParseRecords(p []byte) ([]Record, error) {
	out, err := parseRecords(p)
	if err != nil {
		return out, err
	}
	return expandProfiles(out), nil
}

func parseRecords(p []byte) ([]Record, error) {
	var out []Record
	for i := 0; i < len(p); {
		dif := p[i]
		i++
		switch dif {
		case 0x2F: // idle filler
			continue
		case 0x0F, 0x1F: // manufacturer-specific data to the end
			rest := p[i:]
			out = append(out, Record{DIF: dif, Quantity: "manufacturer_data", Manufacturer: true,
				Value: strings.ToUpper(hex.EncodeToString(rest)), Raw: append([]byte(nil), rest...)})
			return out, nil
		case 0x7F: // global readout request: no data
			continue
		}
		if dif&0x0F == 0x0F {
			return out, fmt.Errorf("record %d: reserved special DIF 0x%02X", len(out), dif)
		}
		r := Record{DIF: dif, Function: functions[dif>>4&0x03], Storage: int(dif >> 6 & 1)}
		ext := dif&0x80 != 0
		for n := 0; ext; n++ {
			if i >= len(p) {
				return out, fmt.Errorf("record %d: data ends inside the DIFEs", len(out))
			}
			if n >= maxDIFE {
				return out, fmt.Errorf("record %d: more than %d DIFEs", len(out), maxDIFE)
			}
			d := p[i]
			i++
			r.DIFE = append(r.DIFE, d)
			r.Storage |= int(d&0x0F) << (1 + 4*n)
			r.Tariff |= int(d>>4&0x03) << (2 * n)
			r.Subunit |= int(d>>6&1) << n
			ext = d&0x80 != 0
		}
		// A final DIFE 00h marks the storage number as a register number.
		if len(r.DIFE) > 0 && r.DIFE[len(r.DIFE)-1] == 0x00 {
			r.Register = true
		}
		if i >= len(p) {
			return out, fmt.Errorf("record %d: data ends before the VIF", len(out))
		}
		var err error
		var v vifInfo
		if v, i, err = parseVIF(p, i, &r); err != nil {
			return out, fmt.Errorf("record %d: %w", len(out), err)
		}
		n := dataLen[dif&0x0F]
		lvar := -1
		if n == -1 {
			if i >= len(p) {
				return out, fmt.Errorf("record %d: data ends before LVAR", len(out))
			}
			lvar = int(p[i])
			i++
			if n = LVARLength(lvar); n < 0 {
				return out, fmt.Errorf("record %d: reserved LVAR 0x%02X", len(out), lvar)
			}
		}
		if i+n > len(p) {
			return out, fmt.Errorf("record %d: the data field (%d bytes) runs past the end", len(out), n)
		}
		r.Raw = append([]byte(nil), p[i:i+n]...)
		i += n
		v.decode(&r, dif&0x0F, lvar)
		if r.base != nil {
			q := r.Quantity
			if bv, ok := r.base.value(&r, dif&0x0F, lvar, r.Raw); ok {
				if r.base.bin2 != 0 {
					if x, isInt := bv.(int64); isInt {
						bv = math.Ldexp(float64(x), r.base.bin2)
					}
				}
				r.BaseValue = bv
			}
			r.Quantity, r.base = q, nil
		}
		out = append(out, r)
	}
	return out, nil
}

// LVARLength is the length in bytes of a variable-length data field
// whose LVAR byte is l (EN 13757-3:2025 table 5), or -1 for a reserved
// code.
func LVARLength(l int) int {
	switch {
	case l <= 0xBF:
		return l
	case l <= 0xC9:
		return l - 0xC0
	case l >= 0xD0 && l <= 0xD9:
		return l - 0xD0
	case l >= 0xE0 && l <= 0xEF:
		return l - 0xE0
	case l >= 0xF0 && l <= 0xF4:
		return 4 * (l - 0xEC)
	case l == 0xF5:
		return 48
	case l == 0xF6:
		return 64
	}
	return -1
}

func parseVIF(p []byte, i int, r *Record) (vifInfo, int, error) {
	vif := p[i]
	i++
	r.VIF = vif
	var v vifInfo
	next := func() (byte, error) {
		if i >= len(p) {
			return 0, fmt.Errorf("data ends inside the VIFEs")
		}
		if len(r.VIFE) >= maxVIFE {
			return 0, fmt.Errorf("more than %d VIFEs", maxVIFE)
		}
		b := p[i]
		i++
		r.VIFE = append(r.VIFE, b)
		return b, nil
	}
	ext := vif&0x80 != 0
	c := vif & 0x7F
	switch {
	case vif == 0xFB || vif == 0xFD:
		e, err := next()
		if err != nil {
			return v, i, err
		}
		switch {
		case vif == 0xFB:
			v = r.fbTable(e & 0x7F)
		case e&0x7F == 0x7D: // second level table
			if e&0x80 == 0 {
				return v, i, fmt.Errorf("VIFE 0x7D without the extension bit")
			}
			if e, err = next(); err != nil {
				return v, i, err
			}
			v = r.fdfdTable(e & 0x7F)
		default:
			v = r.fdTable(e & 0x7F)
		}
		ext = e&0x80 != 0
	case (c == 0x7B || c == 0x7D) && !ext:
		// An extension VIF without its VIFE is not defined; meters do
		// send it (a Sensus PolluTherm's VIF 7Bh). The DIF still gives
		// the data's length, so the record is kept as an unknown quantity
		// and the records after it are read.
		v = r.set(fmt.Sprintf("vif_%02x", c), "", 0, vkNumber)
		v.table = tOther
		return v, i, nil
	case c == 0x7C:
		// Plain-text unit (6.4.1 b, C.2): the combinable VIFEs come
		// first, then the length and the text, rightmost character first.
		saved, start := *r, i
		var err error
		v, i, err = r.plainText(p, start, ext, true)
		if err != nil && ext {
			// Some meters (Elvaco CMa10, in libmbus's test frames) send
			// the length and text right after the VIF and the VIFEs
			// after the text; read that order when the standard one does
			// not fit the record.
			*r = saved
			if v2, i2, err2 := r.plainText(p, start, ext, false); err2 == nil {
				return v2, i2, nil
			}
			*r = saved
		}
		return v, i, err
	case c == 0x7E:
		v = r.set("any", "", 0, vkNumber)
		v.table = tOther
	case c == 0x7F:
		// Manufacturer VIF: the VIFEs and data are the manufacturer's.
		r.Manufacturer = true
		v = r.set("manufacturer_specific", "", 0, vkHex)
		v.table = tOther
		for ext {
			e, err := next()
			if err != nil {
				return v, i, err
			}
			ext = e&0x80 != 0
		}
		return v, i, nil
	default:
		v = r.primary(c)
	}
	if ext {
		var err error
		if i, err = r.combinable(p, i, &v); err != nil {
			return v, i, err
		}
	}
	if v.nonMetric != 0 && (v.kind == vkNumber || v.kind == vkUnsigned) {
		if u, d, ok := nonMetricUnit(v, v.nonMetric); ok {
			v.exp += d
			unit := u
			for _, m := range r.Modifier {
				unit = perUnit(unit, m)
			}
			r.Unit = unit
		}
	}
	return v, i, nil
}

// perUnit divides unit by a per-unit modifier's unit.
func perUnit(unit, mod string) string {
	for _, pu := range perUnits {
		if pu[0] == mod && pu[1] != "" {
			if unit == "" {
				return "1/" + pu[1]
			}
			return unit + "/" + pu[1]
		}
	}
	return unit
}

// combinable reads the orthogonal VIFEs after a VIF (6.4.6, table 16, and
// table 17 after FCh), applying the ones that change the value, unit or
// meaning.
// plainText reads a plain-text VIF's text and, when ext is set, its
// combinable VIFEs: before the text (vifeFirst, the standard's order) or
// after it.
func (r *Record) plainText(p []byte, i int, ext, vifeFirst bool) (vifInfo, int, error) {
	v := vifInfo{kind: vkNumber, table: tText}
	var err error
	if ext && vifeFirst {
		if i, err = r.combinable(p, i, &v); err != nil {
			return v, i, err
		}
	}
	if i >= len(p) || i+1+int(p[i]) > len(p) {
		return v, i, fmt.Errorf("plain-text VIF runs past the end")
	}
	n := int(p[i])
	txt := make([]byte, n)
	for k := range n {
		txt[k] = p[i+n-k]
	}
	i += 1 + n
	if ext && !vifeFirst {
		if i, err = r.combinable(p, i, &v); err != nil {
			return v, i, err
		}
	}
	v.text = string(txt)
	r.Quantity = "text_" + ResourceSafe(v.text)
	r.Unit = v.text
	for _, m := range r.Modifier {
		r.Unit = perUnit(r.Unit, m)
	}
	return v, i, nil
}

func (r *Record) combinable(p []byte, i int, v *vifInfo) (int, error) {
	mod := func(m string) { r.Modifier = append(r.Modifier, m) }
	fc := false // the previous VIFE was FCh: this one is from table 17
	mfct := false
	for {
		if i >= len(p) {
			return i, fmt.Errorf("data ends inside the VIFEs")
		}
		if len(r.VIFE) >= maxVIFE {
			return i, fmt.Errorf("more than %d VIFEs", maxVIFE)
		}
		e := p[i]
		i++
		r.VIFE = append(r.VIFE, e)
		c := e & 0x7F
		switch {
		case mfct:
			// manufacturer-specific VIFEs: not interpreted
		case fc:
			fc = false
			switch c {
			case 0x0D:
				v.nonMetric = 2
			case 0x11:
				if v.kind == vkNumber {
					v.kind = vkUnsigned
				}
			case 0x12:
				v.kind = vkBits
			case 0x13:
				mod("end")
				v.kind, v.exp, r.Unit = vkWhen, 0, ""
			default:
				if m, ok := fcModifiers[c]; ok {
					mod(m)
				} else {
					mod(fmt.Sprintf("vife_fc%02x", c))
				}
			}
		case c <= 0x0F || c >= 0x15 && c <= 0x1C:
			// Record error (slave to master) or object action (master to
			// slave): the same codes, kept as both.
			r.RecordError = recordErrors[c]
			if c <= 0x0F {
				r.action = int(c) + 1
			}
		case c == 0x10 || c == 0x11:
			// reserved
		case c == 0x12:
			mod("average")
		case c == 0x13:
			mod("inverse_compact_profile")
		case c == 0x14:
			mod("relative_deviation")
		case c == 0x1D:
			v.std = true
		case c == 0x1E:
			mod("compact_profile_reg")
		case c == 0x1F:
			mod("compact_profile")
		case c >= 0x20 && c <= 0x35:
			pu := perUnits[c]
			mod(pu[0])
			r.Unit = perUnit(r.Unit, pu[0])
		case c == 0x36:
			mod("times_s")
			r.Unit = times(r.Unit, "s")
		case c == 0x37:
			mod("times_s_per_v")
			r.Unit = times(r.Unit, "s/V")
		case c == 0x38:
			mod("times_s_per_a")
			r.Unit = times(r.Unit, "s/A")
		case c == 0x39:
			mod("start")
			v.kind, v.exp, r.Unit = vkWhen, 0, ""
		case c == 0x3A:
			mod("uncorrected")
		case c == 0x3B:
			mod("forward")
		case c == 0x3C:
			mod("backward")
		case c == 0x3D:
			v.nonMetric = 1
		case c == 0x3E:
			mod("base_conditions")
		case c == 0x3F:
			mod("obis")
			if v.kind == vkNumber {
				v.kind = vkUnsigned
			}
		case c == 0x40 || c == 0x48:
			mod([2]string{"lower_limit", "upper_limit"}[c>>3&1])
		case c == 0x41 || c == 0x49:
			mod([2]string{"lower_limit_exceeds", "upper_limit_exceeds"}[c>>3&1])
			v.kind, v.exp, v.bin2, r.Unit = vkUnsigned, 0, 0, ""
		case c >= 0x42 && c <= 0x4F && c&0x02 != 0: // E100 uf1b
			mod(fmt.Sprintf("%s_%s_exceed_%s", firstLast(c>>2), lowerUpper(c>>3), beginEnd(c)))
			v.kind, v.exp, v.bin2, r.Unit = vkWhen, 0, 0, ""
		case c == 0x44:
			mod("times_flow_temperature")
		case c == 0x45:
			mod("times_return_temperature")
		case c >= 0x50 && c <= 0x5F: // E101 ufnn
			mod(fmt.Sprintf("duration_%s_%s_exceed", firstLast(c>>2), lowerUpper(c>>3)))
			v.kind, v.exp, v.bin2, r.Unit = vkUnsigned, 0, 0, timeUnit(c)
		case c >= 0x60 && c <= 0x67: // E110 0fnn
			mod("duration_" + firstLast(c>>2))
			v.kind, v.exp, v.bin2, r.Unit = vkUnsigned, 0, 0, timeUnit(c)
		case c == 0x68 || c == 0x6C:
			mod([2]string{"during_lower_exceed", "during_upper_exceed"}[c>>2&1])
		case c == 0x69:
			mod("leakage")
		case c == 0x6D:
			mod("overflow")
		case c == 0x6A || c == 0x6B || c == 0x6E || c == 0x6F: // E110 1f1b
			mod(fmt.Sprintf("%s_%s", firstLast(c>>2), beginEnd(c)))
			v.kind, v.exp, v.bin2, r.Unit = vkWhen, 0, 0, ""
		case c >= 0x70 && c <= 0x77:
			v.exp += int(c&0x07) - 6
		case c >= 0x78 && c <= 0x7B:
			// The record is an additive correction constant, in
			// 10^(nn-3) units of the VIF.
			mod("offset")
			v.exp += int(c&0x03) - 3
		case c == 0x7C:
			fc = true
		case c == 0x7D:
			v.exp += 3
		case c == 0x7E:
			mod("future")
		case c == 0x7F:
			// the rest of the VIFEs and the data are manufacturer-specific
			mod("mfct")
			mfct = true
			r.Manufacturer = true
			if r.base == nil && v.kind != vkHex {
				base := *v
				r.base = &base
			}
			v.kind = vkHex
		default: // reserved (4Ch, 4Dh)
			mod(fmt.Sprintf("vife%02x", c))
		}
		if e&0x80 == 0 {
			if fc {
				return i, fmt.Errorf("VIFE 0xFC without a following VIFE")
			}
			return i, nil
		}
	}
}

func firstLast(b byte) string  { return [2]string{"first", "last"}[b&1] }
func lowerUpper(b byte) string { return [2]string{"lower", "upper"}[b&1] }
func beginEnd(b byte) string   { return [2]string{"begin", "end"}[b&1] }

func times(unit, by string) string {
	if unit == "" {
		return by
	}
	return unit + "." + by
}

// decode sets r.Value (and Invalid, Flags) from r.Raw.
func (v vifInfo) decode(r *Record, df byte, lvar int) {
	b := r.Raw
	val, ok := v.value(r, df, lvar, b)
	if !ok {
		r.Invalid = true
		val = hexLE(b)
	}
	r.Value = val
	if ok && (v.kind == vkBits || v.table == tFD && v.code == 0x1F) {
		r.Flags = v.flags(b)
	}
	if v.bin2 != 0 && ok {
		switch x := r.Value.(type) {
		case int64:
			r.Value = math.Ldexp(float64(x), v.bin2)
		case float64:
			r.Value = math.Ldexp(x, v.bin2)
		}
	}
}

// value decodes a data field; ok is false for an invalid value.
func (v vifInfo) value(r *Record, df byte, lvar int, b []byte) (any, bool) {
	switch v.kind {
	case vkDate:
		if df != 0x2 {
			return nil, false
		}
		return dateG(b)
	case vkDateTime, vkWhen:
		switch {
		case df == 0x2 && v.kind == vkWhen:
			return dateG(b)
		case df == 0x3:
			if r.Quantity == "datetime" {
				r.Quantity = "time"
			}
			return timeJ(b)
		case df == 0x4:
			return dateF(b)
		case df == 0x6:
			return dateI(b)
		case df == 0xD && lvar >= 0xE2 && lvar <= 0xEF:
			return typeM(r, b)
		}
		if v.kind == vkDateTime {
			return nil, false // table 10 footnote b
		}
	case vkDST:
		if df == 0x4 {
			return typeK(b), true
		}
	case vkListen:
		if df == 0xD && lvar == 0xEB {
			return typeL(b), true
		}
	case vkSubDevice:
		if df == 0xD && lvar > 0xBF || df == 0x5 {
			break
		}
		var names []string
		for _, x := range b {
			if x != 0 {
				names = append(names, subDeviceName(x))
			}
		}
		r.Flags = names
		return strings.Join(names, ","), true
	case vkContainer:
		if df == 0xD && lvar <= 0xBF {
			return strings.ToUpper(hex.EncodeToString(b)), true
		}
	}
	if v.table == tPrimary && v.code == 0x7A && (df == 0x6 || df == 0x7) {
		return hexLE(b), true // header identification (table 10)
	}
	switch {
	case df == 0x0 || df == 0x8:
		return nil, true
	case df == 0x5:
		f := math.Float32frombits(binary.LittleEndian.Uint32(b))
		if f != f {
			return nil, false // NaN: invalid (type H)
		}
		return scale(float64(f), v.exp), true
	case df == 0xD:
		return lvarValue(lvar, b, v.exp, v.kind)
	}
	if v.table == tPrimary && (v.code == 0x78 || v.code == 0x79) && df >= 0x1 && df <= 0x7 && df != 0x5 {
		// An identification number sent as a binary integer reads as
		// its decimal number, like one sent in BCD (annex A type C).
		return strconv.FormatUint(unsignedLE(b), 10), true
	}
	if v.kind == vkHex || v.kind == vkBits || v.kind == vkText {
		return hexLE(b), true
	}
	var n int64
	if df >= 0x9 && df <= 0xE {
		var ok bool
		if n, ok = bcd(b); !ok {
			return nil, false
		}
	} else if v.kind == vkUnsigned {
		u := unsignedLE(b)
		if u == 1<<(8*uint(len(b)))-1 || len(b) == 8 && u == math.MaxUint64 {
			return nil, false // type C: all ones is invalid
		}
		if u > math.MaxInt64 {
			return scale(float64(u), v.exp), true
		}
		n = int64(u)
	} else {
		if len(b) > 0 && unsignedLE(b) == 1<<(8*uint(len(b))-1) {
			return nil, false // type B: the most negative value is invalid
		}
		n = signedLE(b)
	}
	if v.exp == 0 {
		return n, true
	}
	return scaleInt(n, v.exp), true
}

func hexLE(b []byte) string {
	var s strings.Builder
	for i := len(b) - 1; i >= 0; i-- {
		fmt.Fprintf(&s, "%02X", b[i])
	}
	return s.String()
}

func unsignedLE(b []byte) uint64 {
	var u uint64
	for i := len(b) - 1; i >= 0; i-- {
		u = u<<8 | uint64(b[i])
	}
	return u
}

func signedLE(b []byte) int64 {
	u := unsignedLE(b)
	bits := uint(8 * len(b))
	if bits > 0 && bits < 64 && u&(1<<(bits-1)) != 0 {
		u |= ^uint64(0) << bits
	}
	return int64(u)
}

// bcd decodes little-endian BCD (type A); an F in the most significant
// digit marks a negative value, any other non-decimal digit an invalid
// value (annex B).
func bcd(b []byte) (int64, bool) {
	var n int64
	neg := false
	for i := len(b) - 1; i >= 0; i-- {
		hi, lo := b[i]>>4, b[i]&0x0F
		if i == len(b)-1 && hi == 0x0F {
			neg, hi = true, 0
		}
		if hi > 9 || lo > 9 {
			return 0, false
		}
		n = n*100 + int64(hi)*10 + int64(lo)
	}
	if neg {
		n = -n
	}
	return n, true
}

func scaleInt(n int64, exp int) float64 {
	if exp >= 0 {
		return float64(n) * math.Pow10(exp)
	}
	f, _ := strconv.ParseFloat(strconv.FormatInt(n, 10)+"e"+strconv.Itoa(exp), 64)
	return f
}

func scale(f float64, exp int) float64 {
	if exp == 0 {
		return f
	}
	x := f * math.Pow10(exp)
	s := strconv.FormatFloat(x, 'g', 12, 64)
	y, _ := strconv.ParseFloat(s, 64)
	return y
}

// lvarValue decodes variable-length data by its LVAR range (table 5).
func lvarValue(l int, b []byte, exp int, k vifKind) (any, bool) {
	switch {
	case l <= 0xBF:
		t := make([]byte, len(b))
		for i := range b {
			t[i] = b[len(b)-1-i]
		}
		return string(t), true
	case l >= 0xC0 && l <= 0xD9:
		n, ok := bcd(b)
		if !ok {
			return nil, false
		}
		if l >= 0xD0 {
			n = -n
		}
		if exp == 0 {
			return n, true
		}
		return scaleInt(n, exp), true
	case l >= 0xE0 && l <= 0xEF && len(b) <= 8 && k != vkHex && k != vkBits:
		if len(b) == 0 {
			return nil, true
		}
		if k == vkUnsigned {
			u := unsignedLE(b)
			if u > math.MaxInt64 {
				return scale(float64(u), exp), true
			}
			return scaleInt(int64(u), exp), true
		}
		if unsignedLE(b) == 1<<(8*uint(len(b))-1) {
			return nil, false
		}
		if exp == 0 {
			return signedLE(b), true
		}
		return scaleInt(signedLE(b), exp), true
	}
	return hexLE(b), true
}

// field formats a date or time field; wildcard fields ("every", "not
// specified") are shown as asterisks.
func field(v, width, wildcard int) string {
	if v == wildcard {
		return strings.Repeat("*", width)
	}
	return fmt.Sprintf("%0*d", width, v)
}

// fullYear maps a two-digit year: 00-80 are 2000-2080, 81-99 are
// 1981-1999 (annex A, tables A.5, A.6, A.8 notes).
func fullYear(y int) int {
	if y <= 80 {
		return 2000 + y
	}
	return 1900 + y
}

func yearOf(lo, hi byte) int { return int(lo>>5) | int(hi&0xF0)>>1 }

func yearField(y, hundred int, withHundred bool) string {
	if y == 127 {
		return "****"
	}
	if withHundred && hundred > 0 {
		return fmt.Sprintf("%04d", 1900+100*hundred+y)
	}
	return fmt.Sprintf("%04d", fullYear(y))
}

// dateG is type G (CP16, table A.6).
func dateG(b []byte) (any, bool) {
	if b[0] == 0xFF && b[1] == 0xFF || b[1]&0x0F == 0 {
		return nil, false // all ones, or month 0: no date (an all-zero field)
	}
	return yearField(yearOf(b[0], b[1]), 0, false) + "-" + field(int(b[1]&0x0F), 2, 15) + "-" + field(int(b[0]&0x1F), 2, 0), true
}

// dateF is type F (CP32, table A.5); bit 7 marks it invalid.
func dateF(b []byte) (any, bool) {
	if b[0]&0x80 != 0 || b[3]&0x0F == 0 {
		return nil, false // invalid bit, or month 0: no date
	}
	y := yearField(yearOf(b[2], b[3]), int(b[1]>>5&3), true)
	return y + "-" + field(int(b[3]&0x0F), 2, 15) + "-" + field(int(b[2]&0x1F), 2, 0) +
		"T" + field(int(b[1]&0x1F), 2, 31) + ":" + field(int(b[0]&0x3F), 2, 63) + ":00", true
}

// dateI is type I (CP48, table A.8); bit 15 marks it invalid.
func dateI(b []byte) (any, bool) {
	if b[1]&0x80 != 0 || b[4]&0x0F == 0 {
		return nil, false // invalid bit, or month 0: no date
	}
	return yearField(yearOf(b[3], b[4]), 0, false) + "-" + field(int(b[4]&0x0F), 2, 0) + "-" + field(int(b[3]&0x1F), 2, 0) +
		"T" + field(int(b[2]&0x1F), 2, 31) + ":" + field(int(b[1]&0x3F), 2, 63) + ":" + field(int(b[0]&0x3F), 2, 63), true
}

// timeJ is type J (CP24, table A.9); FFFFFFh is invalid.
func timeJ(b []byte) (any, bool) {
	if b[0] == 0xFF && b[1] == 0xFF && b[2] == 0xFF {
		return nil, false
	}
	return field(int(b[2]&0x1F), 2, 31) + ":" + field(int(b[1]&0x3F), 2, 63) + ":" + field(int(b[0]&0x3F), 2, 63), true
}

// sign5 is a 5-bit two's complement value.
func sign5(x int) int {
	if x&0x10 != 0 {
		return x - 32
	}
	return x
}

// typeK is type K, daylight savings (table A.10).
func typeK(b []byte) map[string]any {
	x := binary.LittleEndian.Uint32(b)
	m := map[string]any{
		"enabled":     x>>15&1 == 1,
		"begin_hour":  int(x & 0x1F),
		"begin_day":   int(x >> 8 & 0x1F),
		"begin_month": int(x >> 24 & 0x0F),
		"end_day":     int(x >> 16 & 0x1F),
		"end_month":   int(x >> 28 & 0x0F),
	}
	if off := sign5(int(x>>5&7) | int(x>>13&3)<<3); off != -16 {
		m["utc_offset_h"] = off
	}
	dev := int(x >> 21 & 3)
	if x>>23&1 == 0 {
		dev = -dev
	}
	m["deviation_h"] = dev
	return m
}

// typeL is type L, listening window management (table A.11): the weeks
// (1-53), days, hours (0-23) and quarters (1-4) of normal mode.
func typeL(b []byte) map[string]any {
	bit := func(i int) bool { return b[i/8]>>(i%8)&1 == 1 }
	weeks, days, hours, quarters := []int{}, []string{}, []int{}, []int{}
	for i := 0; i <= 52; i++ {
		if bit(i) {
			weeks = append(weeks, i+1)
		}
	}
	for i, d := range []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"} {
		if bit(53 + i) {
			days = append(days, d)
		}
	}
	for i := range 24 {
		if bit(60 + i) {
			hours = append(hours, i)
		}
	}
	for i := range 4 {
		if bit(84 + i) {
			quarters = append(quarters, i+1)
		}
	}
	return map[string]any{"weeks": weeks, "days": days, "hours": hours, "quarters": quarters}
}

var (
	epoch2013 = time.Date(2013, 1, 1, 0, 0, 0, 0, time.UTC)
	epochUnix = time.Unix(0, 0).UTC()
)

// typeM is type M, date and time or duration (table A.12): an absolute
// time as RFC 3339 (in the coded UTC offset when given), a relative time
// as seconds (Unit "s").
func typeM(r *Record, b []byte) (any, bool) {
	top := b[len(b)-1]
	d := b[:len(b)-1]
	if len(d) == 0 || len(d) > 8 {
		return nil, false
	}
	if unsignedLE(d) == 1<<(8*uint(len(d))-1) {
		return nil, false
	}
	n := signedLE(d)
	var secs float64
	switch top >> 5 & 3 {
	case 0:
		secs = float64(n) * 2
	case 1:
		secs = float64(n)
	case 2:
		secs = float64(n) / 256
	case 3:
		secs = float64(n) / 32768
	}
	off := sign5(int(top & 0x1F))
	if off == -16 {
		r.Unit = "s"
		return secs, true
	}
	base := epoch2013
	if top&0x80 != 0 {
		base = epochUnix
	}
	whole := math.Floor(secs)
	t := base.Add(time.Duration(whole)*time.Second + time.Duration((secs-whole)*1e9))
	if off >= -12 && off <= 14 {
		t = t.In(time.FixedZone("", off*3600))
	}
	return t.Format(time.RFC3339Nano), true
}

// ResourceSafe lowercases s and turns characters outside [a-z0-9_] into
// '_'.
func ResourceSafe(s string) string {
	b := []byte(strings.ToLower(s))
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			b[i] = '_'
		}
	}
	return string(b)
}

// TypeG formats a 2-byte date of type G (EN 13757-3 annex A) as
// YYYY-MM-DD, or "" when it codes no date.
func TypeG(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	v, ok := dateG(b)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}
