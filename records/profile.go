package records

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// Profiles (EN 13757-3:2025 Annex F). expandProfiles turns the profile
// records of a telegram into ordinary records, one per profile value, and
// adds the time of each value as a date/datetime record.
//
// Compact profiles (F.2) are variable-length records (DIF xDh) whose VIF
// chain carries an orthogonal VIFE 1Eh (with register numbers), 1Fh
// (compact profile) or 13h (inverse compact profile). The data is a
// spacing control byte (increment mode, spacing unit, element size), a
// spacing value byte and the elements. A base value record (same
// function, storage, tariff, subunit and VIF chain without the profile
// VIFE) and a base time record (a date/time with the same storage number)
// anchor the series.
//
// Naming of the expanded values (Record.Name):
//   - 1Eh, with register numbers: element k is register storage+k, so it
//     is named like an ordinary record of that register number
//     ("energy_r33_t1", 6.3.5), and its time is "datetime_r33".
//   - 1Fh and 13h: element k (k = 1 is the one next to the base value:
//     the oldest after it for 1Fh, the youngest before it for 13h) keeps
//     the profile's storage number and gets the modifier "p<k>"
//     ("volume_s8_p1"), its time "datetime_s8_p1".
//   - With spacing value 0 the elements are an array, not a time series:
//     no times; a spacing unit above 0 names the column ("c2" … "c4").
//
// The profile record itself is replaced by its elements. The standard
// load profile (F.1) is ordinary records per storage number with a
// storage interval (VIF FDh, VIFE 24h–29h), an optional count of storage
// numbers (FDh 22h) and the date of the last one; for it the dates of the
// other storage numbers are added ("date_s8" … "date_s11").

// Orthogonal VIFE codes that mark a compact profile (F.2.6–F.2.8).
const (
	vifeProfileRegister byte = 0x1E
	vifeProfile         byte = 0x1F
	vifeProfileInverse  byte = 0x13
)

// Increment modes of the spacing control byte (Table F.7).
const (
	incAbsolute = iota
	incIncrements
	incDecrements
	incSigned
)

// profileCode returns the profile VIFE of a record and its index in VIFE
// (-1 when it is not a compact profile). The first VIFE after FBh/FDh is
// a table code, not an orthogonal one.
func profileCode(r Record) (byte, int) {
	if r.DIF&0x0F != 0x0D || len(r.VIFE) == 0 {
		return 0, -1
	}
	start := 0
	if c := r.VIF & 0x7F; c == 0x7B || c == 0x7D {
		start = 1
	}
	if r.VIF&0x7F == 0x7C {
		return 0, -1 // plain-text units are not expanded
	}
	for i := start; i < len(r.VIFE); i++ {
		switch c := r.VIFE[i] & 0x7F; c {
		case vifeProfileRegister, vifeProfile, vifeProfileInverse:
			return c, i
		}
	}
	return 0, -1
}

// vifChain is a record's VIF and VIFEs with one VIFE left out and the
// extension bits set again.
func vifChain(r Record, skip int) []byte {
	chain := []byte{r.VIF & 0x7F}
	for i, e := range r.VIFE {
		if i != skip {
			chain = append(chain, e&0x7F)
		}
	}
	for i := 0; i < len(chain)-1; i++ {
		chain[i] |= 0x80
	}
	return chain
}

func sameChain(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i]&0x7F != b[i]&0x7F {
			return false
		}
	}
	return true
}

func isTimeRecord(r Record) bool {
	c := r.VIF & 0x7F
	_, ok := r.Value.(string)
	return (c == 0x6C || c == 0x6D) && ok && len(r.VIFE) == 0
}

// profileTime parses a date/datetime record's value.
func profileTime(r Record) (time.Time, string, bool) {
	s, _ := r.Value.(string)
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02"} {
		if len(s) == len(layout) {
			if t, err := time.Parse(layout, s); err == nil {
				return t, layout, true
			}
		}
	}
	return time.Time{}, "", false
}

// spacing is a profile's time step.
type spacing struct {
	unit   byte // 0 s, 1 min, 2 h, 3 d
	value  byte
	column int
}

// step returns t moved by k spacings (k may be negative); ok is false when
// the spacing is not a time step.
func (s spacing) step(t time.Time, k int) (time.Time, bool) {
	switch {
	case s.value == 0 || s.value == 251 || s.value == 252 || s.value == 255:
		return t, false
	case s.value <= 250:
		d := [4]time.Duration{time.Second, time.Minute, time.Hour, 24 * time.Hour}[s.unit]
		return t.Add(time.Duration(k) * time.Duration(s.value) * d), true
	case s.value == 254 && s.unit > 0:
		return addMonths(t, k*[4]int{0, 6, 3, 1}[s.unit]), true
	case s.value == 253 && s.unit == 3:
		return addHalfMonths(t, k)
	}
	return t, false
}

func lastDay(y int, m time.Month) int { return time.Date(y, m+1, 0, 0, 0, 0, 0, time.UTC).Day() }

// addMonths moves t by n months; the end of a month stays the end of a
// month and a day beyond the target month's length is clamped.
func addMonths(t time.Time, n int) time.Time {
	y, m, d := t.Date()
	first := time.Date(y, m+time.Month(n), 1, t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
	ld := lastDay(first.Year(), first.Month())
	if d == lastDay(y, m) || d > ld {
		d = ld
	}
	return first.AddDate(0, 0, d-1)
}

// addHalfMonths moves t by n half months, for series on the 1st and 16th
// or on the 15th and the last day of the month.
func addHalfMonths(t time.Time, n int) (time.Time, bool) {
	y, m, d := t.Date()
	var half, anchor int // anchor 0: 1st/16th, 1: 15th/last
	switch {
	case d == 1:
	case d == 16:
		half = 1
	case d == 15:
		anchor = 1
	case d == lastDay(y, m):
		anchor, half = 1, 1
	default:
		return t, false
	}
	pos := half + n
	months := int(math.Floor(float64(pos) / 2))
	half = pos - 2*months
	base := time.Date(y, m+time.Month(months), 1, t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
	day := [2][2]int{{1, 16}, {15, lastDay(base.Year(), base.Month())}}[anchor][half]
	return base.AddDate(0, 0, day-1), true
}

// elemSize is the byte length of a profile element by its DIF-style code
// (Table F.7: not 0Dh, not 0Fh); 0 when invalid.
func elemSize(code byte) int {
	switch code {
	case 0x0, 0x8, 0xD, 0xF:
		return 0
	}
	return dataLen[code]
}

// elemValue reads one element: an integer (binary or BCD) or a float,
// and whether it holds the "invalid" coding (Annex A types B and C).
func elemValue(code byte, b []byte, signed bool) (n int64, f float64, isFloat, invalid bool) {
	switch {
	case code == 0x5:
		v := float64(math.Float32frombits(binary.LittleEndian.Uint32(b)))
		return 0, v, true, math.IsNaN(v)
	case code >= 0x9:
		// BCD as EN 13757-3 annex B has it, like ordinary records: an F in
		// the most significant digit is a minus sign, any other digit A to
		// F makes the whole value invalid (F-132).
		v, ok := bcd(b)
		return v, 0, false, !ok
	}
	var u uint64
	for i := len(b) - 1; i >= 0; i-- {
		u = u<<8 | uint64(b[i])
	}
	bits := uint(8 * len(b))
	if !signed {
		all := uint64(math.MaxUint64)
		if bits < 64 {
			all = 1<<bits - 1
		}
		return int64(u), 0, false, u == all
	}
	if bits < 64 && u&(1<<(bits-1)) != 0 {
		u |= ^uint64(0) << bits
	}
	return int64(u), 0, false, (bits < 64 && int64(u) == -1<<(bits-1)) || (bits == 64 && int64(u) == math.MinInt64)
}

// profValue is a running profile value.
type profValue struct {
	n     int64
	f     float64
	float bool
	ok    bool
}

// synth decodes a value as an ordinary record with the profile's DIF
// (function, storage), DIFEs and VIF chain, so it gets the same quantity,
// unit and scaling as the base value.
func synth(p Record, chain []byte, v profValue) (Record, bool) {
	dif := p.DIF & 0xF0
	var data []byte
	switch {
	case !v.ok:
		// DIF data field 0: no data, the value is nil
	case v.float:
		dif |= 0x05
		data = binary.LittleEndian.AppendUint32(nil, math.Float32bits(float32(v.f)))
	default:
		dif |= 0x07
		data = binary.LittleEndian.AppendUint64(nil, uint64(v.n))
	}
	b := append([]byte{dif}, p.DIFE...)
	b = append(append(b, chain...), data...)
	rs, err := ParseRecords(b)
	if err != nil || len(rs) != 1 {
		return Record{}, false
	}
	return rs[0], true
}

// expandCompact expands one compact profile record; recs is the whole
// telegram (for the base value and base time).
func expandCompact(p Record, code byte, at int, recs []Record) ([]Record, bool) {
	raw := p.Raw
	if len(raw) < 2 {
		return nil, false
	}
	ctl, sv := raw[0], raw[1]
	size := elemSize(ctl & 0x0F)
	if size == 0 || (len(raw)-2)%size != 0 {
		return nil, false
	}
	mode := int(ctl >> 6)
	sp := spacing{unit: ctl >> 4 & 0x03, value: sv}
	if sv == 0 {
		sp.column = int(sp.unit) + 1
	}
	chain := vifChain(p, at)
	var base *Record
	var baseTime *Record
	for i := range recs {
		r := &recs[i]
		if _, j := profileCode(*r); j >= 0 {
			continue
		}
		if base == nil && r.Function == p.Function && r.Storage == p.Storage && r.Tariff == p.Tariff &&
			r.Subunit == p.Subunit && sameChain(append([]byte{r.VIF}, r.VIFE...), chain) {
			base = r
		}
		if baseTime == nil && r.Storage == p.Storage && isTimeRecord(*r) {
			baseTime = r
		}
	}
	var cur profValue
	if base != nil {
		// the base value's unscaled number is its data field
		if code := base.DIF & 0x0F; elemSize(code) > 0 && len(base.Raw) == elemSize(code) {
			n, f, isF, bad := elemValue(code, base.Raw, true)
			cur = profValue{n: n, f: f, float: isF, ok: !bad}
		}
	}
	haveBase := cur.ok
	var t0 time.Time
	var layout string
	var timed bool
	if baseTime != nil {
		t0, layout, timed = profileTime(*baseTime)
	}
	dir := 1
	if code == vifeProfileInverse {
		dir = -1
	}
	var out, times []Record
	count := (len(raw) - 2) / size
	for k := 1; k <= count; k++ {
		b := raw[2+(k-1)*size : 2+k*size]
		n, f, isF, bad := elemValue(ctl&0x0F, b, mode == incAbsolute || mode == incSigned)
		e := profValue{n: n, f: f, float: isF, ok: !bad}
		var v profValue
		switch {
		case mode == incAbsolute:
			v = e
		case k == 1 && !haveBase:
			v = e // no base value: the first entry is the first value
		case !cur.ok || !e.ok:
			v = profValue{}
		default:
			// difference = younger − older; the series walks from older to
			// younger (1Eh, 1Fh) or from younger to older (13h).
			sign := int64(1)
			if mode == incDecrements {
				sign = -1
			}
			sign *= int64(dir)
			v = profValue{n: cur.n + sign*e.n, f: cur.f + float64(sign)*e.f, float: cur.float || e.float, ok: true}
			if v.float && !cur.float {
				v.f = float64(cur.n) + float64(sign)*e.f
			}
		}
		cur = v
		r, ok := synth(p, chain, v)
		if !ok {
			return nil, false
		}
		r.Raw = append([]byte(nil), b...)
		r.Storage, r.Tariff, r.Subunit = p.Storage, p.Tariff, p.Subunit
		var mod []string
		if code == vifeProfileRegister {
			r.Storage = p.Storage + k
		} else {
			mod = []string{fmt.Sprintf("p%d", k)}
		}
		if sp.column > 1 {
			mod = append(mod, fmt.Sprintf("c%d", sp.column))
		}
		r.Modifier = append(r.Modifier, mod...)
		out = append(out, r)
		if timed {
			if tk, ok := sp.step(t0, dir*k); ok {
				tr := *baseTime
				tr.Storage, tr.Tariff, tr.Subunit, tr.Raw = r.Storage, 0, baseTime.Subunit, nil
				tr.Modifier = mod
				tr.Value = tk.Format(layout)
				times = append(times, tr)
			}
		}
	}
	return append(out, times...), true
}

// intOf returns an integer record value.
func intOf(v any) (int, bool) {
	switch x := v.(type) {
	case int64:
		return int(x), true
	case float64:
		if x == math.Trunc(x) {
			return int(x), true
		}
	}
	return 0, false
}

// standardProfileDates adds the dates of a standard load profile's
// storage numbers (F.1): the storage interval record (FDh 24h–29h) gives
// the first storage number and the step, the count (FDh 22h, same storage
// number) the last one, whose date is sent.
func standardProfileDates(recs []Record) []Record {
	var out []Record
	for _, iv := range recs {
		if iv.VIF != 0xFD || len(iv.VIFE) != 1 {
			continue
		}
		c := iv.VIFE[0]
		if c < 0x24 || c > 0x29 {
			continue
		}
		step, ok := intOf(iv.Value)
		if !ok || step <= 0 || iv.Storage == 0 {
			continue
		}
		first, last := iv.Storage, -1
		for _, r := range recs {
			if r.VIF == 0xFD && len(r.VIFE) == 1 && r.VIFE[0] == 0x22 && r.Storage == first {
				if n, ok := intOf(r.Value); ok && n > 0 {
					last = first + n - 1
				}
			}
		}
		var lastRec *Record
		for i := range recs {
			r := &recs[i]
			if isTimeRecord(*r) && r.Storage >= first && (last < 0 && (lastRec == nil || r.Storage > lastRec.Storage) || r.Storage == last) {
				lastRec = r
			}
		}
		if lastRec == nil {
			continue
		}
		tl, layout, ok := profileTime(*lastRec)
		if !ok {
			continue
		}
		have := map[string]bool{}
		for _, r := range append(recs, out...) {
			have[r.Name()] = true
		}
		for s := first; s < lastRec.Storage; s++ {
			back := lastRec.Storage - s
			var t time.Time
			switch c {
			case 0x28:
				t = addMonths(tl, -back*step)
			case 0x29:
				t = addMonths(tl, -12*back*step)
			default:
				d := [4]time.Duration{time.Second, time.Minute, time.Hour, 24 * time.Hour}[c-0x24]
				t = tl.Add(-time.Duration(back*step) * d)
			}
			dr := *lastRec
			dr.Storage, dr.Raw, dr.Value = s, nil, t.Format(layout)
			if !have[dr.Name()] {
				have[dr.Name()] = true
				out = append(out, dr)
			}
		}
	}
	return out
}

// expandProfiles turns EN 13757-3 Annex F profile records into ordinary
// records (see the comment at the top of this file). A profile that
// cannot be read is kept as it came.
func expandProfiles(recs []Record) []Record {
	var out []Record
	have := map[string]bool{}
	for _, r := range recs {
		have[r.Name()] = true
	}
	changed := false
	for _, r := range recs {
		code, at := profileCode(r)
		if at < 0 {
			out = append(out, r)
			continue
		}
		el, ok := expandCompact(r, code, at, recs)
		if !ok {
			out = append(out, r)
			continue
		}
		changed = true
		for _, e := range el {
			if isTimeRecord(e) && have[e.Name()] {
				continue // the base time or an earlier profile gave it
			}
			have[e.Name()] = true
			out = append(out, e)
		}
	}
	if extra := standardProfileDates(out); len(extra) > 0 {
		out = append(out, extra...)
		changed = true
	}
	if !changed {
		return recs
	}
	return out
}
