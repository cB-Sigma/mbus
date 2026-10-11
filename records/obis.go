package records

import (
	_ "embed"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/cB-Sigma/dlms/obis"
)

// M-Bus data records as OBIS codes (EN 13757-3:2025 annex H). The
// translation table is data (annexh.yaml); the OBIS model of package
// obis names and describes the codes. Records annex H does not list have
// no OBIS code, unless the meter declares one (H.3, VIFE 3Fh).

//go:embed annexh.yaml
var annexHYAML []byte

type annexHRule struct {
	T       string   `yaml:"t"`
	A       []any    `yaml:"a"`
	Q       string   `yaml:"q"`
	Unit    string   `yaml:"unit"`
	Mods    []string `yaml:"mods"`
	Storage string   `yaml:"storage"`
	CD      string   `yaml:"cd"`
	OBIS    string   `yaml:"obis"`

	anyMedium bool
	media     []byte
	c, d, e   byte
	fixedA    byte
}

var annexH = loadAnnexH()

type annexHTable struct {
	media map[byte]byte // device type → A
	rules []annexHRule
}

func loadAnnexH() annexHTable {
	var raw struct {
		Media []struct {
			Dev []int `yaml:"dev"`
			A   int   `yaml:"a"`
		} `yaml:"media"`
		Rules []annexHRule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(annexHYAML, &raw); err != nil {
		panic("wmbus: annexh.yaml: " + err.Error())
	}
	t := annexHTable{media: map[byte]byte{}}
	for _, m := range raw.Media {
		for _, d := range m.Dev {
			t.media[byte(d)] = byte(m.A)
		}
	}
	for _, r := range raw.Rules {
		for _, a := range r.A {
			switch v := a.(type) {
			case string:
				r.anyMedium = v == "any"
			case int:
				r.media = append(r.media, byte(v))
			}
		}
		code := r.CD
		if r.OBIS != "" { // "A.x.C.D.E": a fixed A, B from the subunit
			p := strings.Split(r.OBIS, ".")
			n, _ := strconv.Atoi(p[0])
			r.fixedA, code = byte(n), strings.Join(p[2:], ".")
		}
		p := strings.Split(code, ".")
		if len(p) != 3 {
			panic("wmbus: annexh.yaml: bad code " + code)
		}
		for i, dst := range []*byte{&r.c, &r.d, &r.e} {
			n, err := strconv.Atoi(p[i])
			if err != nil || n < 0 || n > 255 {
				panic("wmbus: annexh.yaml: bad code " + code)
			}
			*dst = byte(n)
		}
		switch r.Storage {
		case "current", "set", "vz", "dated":
		default:
			panic("wmbus: annexh.yaml: bad storage " + r.Storage)
		}
		t.rules = append(t.rules, r)
	}
	return t
}

// MediumA is the OBIS value group A of an M-Bus device type (annex H
// tables' headers); ok is false for device types annex H does not cover.
func MediumA(deviceType byte) (byte, bool) {
	a, ok := annexH.media[deviceType]
	return a, ok
}

// billingF reports a storage number that is a billing period counter
// value (Table H.1: 0 to 99, 101 to 125).
func billingF(s int) bool { return s >= 0 && s <= 99 || s >= 101 && s <= 125 }

// OBIS translates a record of a meter of the given device type to its
// OBIS code (annex H); ok is false when annex H has no row for it.
func (r Record) OBIS(deviceType byte) (obis.Code, bool) {
	if r.declared != nil {
		return *r.declared, true
	}
	if r.Manufacturer || r.Register || r.Subunit > 255 {
		return obis.Code{}, false
	}
	switch r.Function {
	case "instantaneous":
	case "maximum", "minimum":
		return r.extremeOBIS(deviceType)
	default:
		return obis.Code{}, false
	}
	a, ok := MediumA(deviceType)
	if !ok {
		a = 0
	}
	tariff, mods := r.Tariff, r.Modifier
	// H.6: the cooling records of a combined heat and cooling meter
	// carry tariff 1 or the backward flow VIFE.
	if deviceType == 0x0D {
		switch {
		case tariff == 1:
			a, tariff = 5, 0
		case slices.Contains(mods, "backward"):
			a, mods = 5, slices.DeleteFunc(slices.Clone(mods), func(m string) bool { return m == "backward" })
		}
	}
	if tariff != 0 {
		return r.tariffOBIS(deviceType, a, tariff, mods)
	}
	for _, rule := range annexH.rules {
		if rule.Q != r.Quantity || rule.Unit != "" && rule.Unit != r.Unit {
			continue
		}
		if !rule.anyMedium && !slices.Contains(rule.media, a) {
			continue
		}
		if !sameMods(rule.Mods, mods) {
			continue
		}
		f := byte(255)
		switch rule.Storage {
		case "current":
			if r.Storage != 0 {
				continue
			}
		case "set":
			if r.Storage != 1 {
				continue
			}
		case "vz":
			if r.Storage != 0 {
				if !billingF(r.Storage) {
					continue
				}
				f = byte(r.Storage)
			}
		case "dated":
			if r.Storage == 0 || !billingF(r.Storage) {
				continue
			}
			f = byte(r.Storage)
		}
		codeA := a
		if rule.anyMedium {
			codeA = rule.fixedA
		}
		return obis.Code{codeA, byte(r.Subunit), rule.c, rule.d, rule.e, f}, true
	}
	return obis.Code{}, false
}

// sameMods compares modifier lists as sets, ignoring the OBIS
// declaration marker.
func sameMods(want, got []string) bool {
	want = slices.DeleteFunc(slices.Clone(want), func(m string) bool { return m == "obis" })
	n := 0
	for _, m := range got {
		if m == "obis" {
			continue
		}
		if !slices.Contains(want, m) {
			return false
		}
		n++
	}
	return n == len(want)
}

// declaredOBIS reads the value of an OBIS declaration record (H.3, VIFE
// 3Fh): 12 BCD digits (a group AAh is invalid, read as 255) or a 48-bit
// binary number, A in the most significant byte.
func declaredOBIS(r Record) (obis.Code, bool) {
	var c obis.Code
	if len(r.Raw) != 6 {
		return c, false
	}
	bcd := r.DIF&0x0F == 0x0E
	for i := range 6 {
		b := r.Raw[5-i]
		if !bcd {
			c[i] = b
			continue
		}
		if b == 0xAA {
			c[i] = 255
			continue
		}
		hi, lo := b>>4, b&0x0F
		if hi > 9 || lo > 9 {
			return c, false
		}
		c[i] = hi*10 + lo
	}
	return c, true
}

// ApplyOBISDeclarations moves each OBIS declaration (H.3) onto the record
// it declares (the one before it with the same function, storage,
// tariff, subunit, quantity and modifiers) and drops the declaration
// records.
func ApplyOBISDeclarations(recs []Record) []Record {
	out := recs[:0:0]
	for _, r := range recs {
		if !slices.Contains(r.Modifier, "obis") {
			out = append(out, r)
			continue
		}
		code, ok := declaredOBIS(r)
		if !ok {
			out = append(out, r)
			continue
		}
		matched := false
		for i := len(out) - 1; i >= 0; i-- {
			o := &out[i]
			if o.Quantity == r.Quantity && o.Function == r.Function && o.Storage == r.Storage && o.Tariff == r.Tariff &&
				o.Subunit == r.Subunit && sameMods(r.Modifier, o.Modifier) && sameMods(o.Modifier, r.Modifier) {
				o.declared = &code
				matched = true
				break
			}
		}
		if !matched {
			out = append(out, r)
		}
	}
	return out
}

// OBISLabel is a label naming an OBIS code: "obis:" and the code.
func OBISLabel(c obis.Code) string { return "obis:" + c.String() }

// OBISPointName is the point name in OBIS naming mode: the name the OBIS
// model derives, or "obis_" and the code when the code has none.
func OBISPointName(c obis.Code) string {
	if n := obis.Name(c); n != "" {
		return n
	}
	return fmt.Sprintf("obis_%d_%d_%d_%d_%d_%d", c[0], c[1], c[2], c[3], c[4], c[5])
}

// Annex H translates only totals and current values (F-1301). Beyond it a
// record gets a code only where the OBIS model itself defines one:

// tariffOBIS gives a tariff record the code of its total with E the
// tariff, when the model defines E as that rate for the code
// (IEC 62056-6-1:2023 7.3.2 Table 15; EN 13757-1:2021 Tables 17, 25, 37,
// 47).
func (r Record) tariffOBIS(deviceType, a byte, tariff int, mods []string) (obis.Code, bool) {
	if tariff < 1 || tariff > 255 {
		return obis.Code{}, false
	}
	total := r
	total.Tariff = 0
	if deviceType == 0x0D && a == 5 {
		return obis.Code{}, false // H.6: a cooling record of a combined meter
	}
	total.Modifier = mods
	c, ok := total.OBIS(deviceType)
	if !ok || c.E() != 0 {
		return obis.Code{}, false
	}
	c[4] = byte(tariff)
	if i := obis.Describe(c); i.Kind != obis.Standard || i.Class != fmt.Sprintf("rate %d", tariff) {
		return obis.Code{}, false
	}
	return c, true
}

// extremeOBIS gives a maximum or minimum record the code of its current
// value with D the model's maximum or minimum processing for the medium
// (EN 13757-1:2021 Tables 16, 24 and 46: D 5 maximum, D 4 minimum of the
// current value); media whose D table has no such code (gas, electricity
// energy) stay uncoded.
func (r Record) extremeOBIS(deviceType byte) (obis.Code, bool) {
	cur := r
	cur.Function = "instantaneous"
	c, ok := cur.OBIS(deviceType)
	if !ok || c.D() != 0 || c.A() < 4 || c.A() > 9 {
		return obis.Code{}, false
	}
	want := "maximum"
	c[3] = 5
	if r.Function == "minimum" {
		want, c[3] = "minimum", 4
	}
	if i := obis.Describe(c); i.Kind != obis.Standard || !strings.HasPrefix(i.Processing, want) {
		return obis.Code{}, false
	}
	return c, true
}
