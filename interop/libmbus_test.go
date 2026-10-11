// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cB-Sigma/mbus/records"
	"github.com/cB-Sigma/mbus/wired"
)

// libmbus's test/test-frames hold RSP_UD frames of real meters (one .hex
// each) with the XML its parser prints for them; the .norm.xml variant
// scales every value to a base unit, which is what the records package
// does too, so that is the file compared here.

type lmData struct {
	Slave struct {
		ID           string `xml:"Id"`
		Manufacturer string
		Version      string
		Medium       string
		AccessNumber string
		Status       string
	} `xml:"SlaveInformation"`
	Records []lmRecord `xml:"DataRecord"`
}

type lmRecord struct {
	ID            string `xml:"id,attr"`
	Function      string
	StorageNumber string
	Tariff        string
	Device        string
	Unit          string
	Quantity      string
	Value         string
}

// lmMedium is the device type code behind each medium name libmbus prints
// (EN 13757-3 device types; the names are libmbus's).
var lmMedium = map[string]byte{
	"Other": 0x00, "Oil": 0x01, "Electricity": 0x02, "Gas": 0x03, "Heat: Outlet": 0x04,
	"Steam": 0x05, "Warm water (30-90°C)": 0x06, "Water": 0x07, "Heat Cost Allocator": 0x08,
	"Compressed Air": 0x09, "Cooling load meter: Outlet": 0x0A, "Cooling load meter: Inlet": 0x0B,
	"Heat: Inlet": 0x0C, "Heat / Cooling load meter": 0x0D, "Bus/System": 0x0E,
	"Unknown Medium": 0x0F, "Hot water (>=90°C)": 0x15, "Cold water": 0x16,
	"Dual register (hot/cold) Water meter": 0x17, "Pressure": 0x18, "A/D Converter": 0x19,
	"Breaker: Electricity": 0x20, "Valve: Gas or water": 0x21,
}

// lmFixedMedium maps libmbus's fixed-structure medium names to ours.
var lmFixedMedium = map[string]string{
	"Other": "other", "Oil": "oil", "Electricity": "electricity", "Gas": "gas", "Heat": "heat",
	"Steam": "steam", "Hot Water": "hot_water", "Water": "water", "H.C.A.": "hca",
}

// lmUnit converts one of our units to libmbus's normalised unit and factor.
var lmUnit = map[string]struct {
	unit   string
	factor float64
}{
	"Wh": {"Wh", 1}, "MWh": {"Wh", 1e6}, "J": {"J", 1}, "GJ": {"J", 1e9},
	"m3": {"m^3", 1}, "kg": {"kg", 1}, "t": {"kg", 1e3},
	"s": {"s", 1}, "min": {"s", 60}, "h": {"s", 3600}, "d": {"s", 86400},
	"W": {"W", 1}, "MW": {"W", 1e6}, "J/h": {"J/h", 1}, "GJ/h": {"J/h", 1e9},
	"m3/h": {"m^3/h", 1}, "m3/min": {"m^3/min", 1}, "m3/s": {"m^3/s", 1}, "kg/h": {"kg/h", 1},
	"Cel": {"°C", 1}, "K": {"K", 1}, "bar": {"bar", 1}, "V": {"V", 1}, "A": {"A", 1},
}

var lmFunction = map[string]string{
	"instantaneous": "Instantaneous value", "maximum": "Maximum value",
	"minimum": "Minimum value", "error": "Value during error state",
}

// The XML files declare ISO-8859-1 but are written in UTF-8 ("°C" is
// C2 B0), so they are read as they are.
func asIs(_ string, in io.Reader) (io.Reader, error) { return in, nil }

func readHexFrame(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.Join(strings.Fields(string(b)), ""))
}

// Categories of a difference that has a known cause; anything else is
// unexplained and fails the test.
const (
	catMfct       = "manufacturer-specific VIF/VIFE: we keep the data raw (hex), libmbus decodes it as the base VIF"
	catInvalid    = "value coded as invalid (annex A): we mark it invalid, libmbus prints the digits"
	catNoMeaning  = "VIF with no defined meaning (7Bh without VIFE): neither decoder gives one"
	catMfrZero    = "M field 0000h: we print it as 0000, libmbus as @@@"
	catDateOfVIFE = "combinable VIFE 50h-6Fh (duration of a limit exceed, date and time of): we apply it, libmbus prints the base quantity"
	catEveryYear  = "date with year 127 (all ones, 'every year'): we print ****, libmbus 2027"
)

// lmTally counts what the comparison found.
type lmTally struct {
	frames, parsed, headerOK, headerDiff         int
	records, recOK, recDiff, recMissing, recMore int
	explained                                    map[string]int
	diffs                                        []string // unexplained
	notes                                        []string // explained
}

func (c *lmTally) report(cat, format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	if cat == "" {
		c.diffs = append(c.diffs, s)
		return
	}
	c.explained[cat]++
	c.notes = append(c.notes, s+" ["+cat+"]")
}

// TestLibmbusTestFrames: interop with libmbus 0.10.3 test/test-frames (wired RSP_UD decoding)
func TestLibmbusTestFrames(t *testing.T) {
	dir := filepath.Join(checkout(t, libmbus), "test", "test-frames")
	hexes, err := filepath.Glob(filepath.Join(dir, "*.hex"))
	if err != nil || len(hexes) == 0 {
		t.Fatalf("no frames in %s: %v", dir, err)
	}
	c := lmTally{explained: map[string]int{}}
	for _, path := range hexes {
		name := strings.TrimSuffix(filepath.Base(path), ".hex")
		c.frames++
		raw, err := readHexFrame(path)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		f, err := wired.ReadFrame(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			c.report("", "%s: frame not read: %v", name, err)
			continue
		}
		resp, err := wired.ParseResponse(f)
		if err != nil {
			c.report("", "%s: response not decoded: %v", name, err)
			continue
		}
		c.parsed++
		xb, err := os.ReadFile(filepath.Join(dir, name+".norm.xml"))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		var want lmData
		d := xml.NewDecoder(bytes.NewReader(xb))
		d.CharsetReader = asIs
		if err := d.Decode(&want); err != nil {
			t.Errorf("%s.norm.xml: %v", name, err)
			continue
		}
		if resp.Fixed != nil {
			compareFixed(&c, name, resp.Fixed, &want)
			continue
		}
		compareHeader(&c, name, resp, &want)
		compareRecords(&c, name, resp.Records, want.Records)
	}
	t.Logf("libmbus %s (%s) test/test-frames: %d frames, %d decoded; headers %d equal, %d differ; records %d compared, %d equal, %d differ, %d only in libmbus, %d only in ours",
		libmbus.tag, libmbus.commit[:12], c.frames, c.parsed, c.headerOK, c.headerDiff, c.records, c.recOK, c.recDiff, c.recMissing, c.recMore)
	cats := make([]string, 0, len(c.explained))
	for k := range c.explained {
		cats = append(cats, k)
	}
	sort.Strings(cats)
	for _, k := range cats {
		t.Logf("explained, %d: %s", c.explained[k], k)
	}
	for _, s := range c.notes {
		t.Log("  " + s)
	}
	for _, s := range c.diffs {
		t.Error(s)
	}
	t.Logf("unexplained differences: %d", len(c.diffs))
}

func compareHeader(c *lmTally, name string, r *wired.Response, w *lmData) {
	var bad []string
	cat := ""
	wantID, _ := strconv.ParseInt(w.Slave.ID, 10, 64)
	gotID, _ := strconv.ParseInt(r.Address.ID, 10, 64)
	if wantID != gotID {
		bad = append(bad, fmt.Sprintf("id %s, libmbus %s", r.Address.ID, w.Slave.ID))
	}
	if m := records.ManufacturerCode(r.Address.Manufacturer); m != w.Slave.Manufacturer {
		bad = append(bad, fmt.Sprintf("manufacturer %s, libmbus %s", m, w.Slave.Manufacturer))
		if r.Address.Manufacturer == 0 && w.Slave.Manufacturer == "@@@" {
			cat = catMfrZero
		}
	}
	if v := strconv.Itoa(int(r.Address.Version)); v != w.Slave.Version {
		bad = append(bad, fmt.Sprintf("version %s, libmbus %s", v, w.Slave.Version))
	}
	if code, ok := lmMedium[w.Slave.Medium]; !ok {
		bad = append(bad, fmt.Sprintf("medium %q not in the name table", w.Slave.Medium))
	} else if code != r.Address.Medium {
		bad = append(bad, fmt.Sprintf("medium %02X, libmbus %q", r.Address.Medium, w.Slave.Medium))
	}
	if a := strconv.Itoa(int(r.Access)); a != w.Slave.AccessNumber {
		bad = append(bad, fmt.Sprintf("access %s, libmbus %s", a, w.Slave.AccessNumber))
	}
	if s := fmt.Sprintf("%02X", r.Status); s != w.Slave.Status {
		bad = append(bad, fmt.Sprintf("status %s, libmbus %s", s, w.Slave.Status))
	}
	if len(bad) == 0 {
		c.headerOK++
		return
	}
	if len(bad) > 1 {
		cat = ""
	}
	c.headerDiff++
	c.report(cat, "%s: header: %s", name, strings.Join(bad, "; "))
}

func compareFixed(c *lmTally, name string, f *wired.FixedData, w *lmData) {
	var bad []string
	if wantID, _ := strconv.ParseInt(w.Slave.ID, 10, 64); fmt.Sprintf("%08d", wantID) != f.ID {
		bad = append(bad, fmt.Sprintf("id %s, libmbus %s", f.ID, w.Slave.ID))
	}
	if m, ok := lmFixedMedium[w.Slave.Medium]; !ok || m != f.Medium {
		bad = append(bad, fmt.Sprintf("medium %s, libmbus %q", f.Medium, w.Slave.Medium))
	}
	if a := strconv.Itoa(int(f.Access)); a != w.Slave.AccessNumber {
		bad = append(bad, fmt.Sprintf("access %s, libmbus %s", a, w.Slave.AccessNumber))
	}
	if len(bad) == 0 {
		c.headerOK++
	} else {
		c.headerDiff++
		c.report("", "%s: fixed header: %s", name, strings.Join(bad, "; "))
	}
	for i, wr := range w.Records {
		c.records++
		if i >= 2 {
			c.recMissing++
			c.report("", "%s: fixed record %d only in libmbus", name, i)
			continue
		}
		got := f.Counters[i]
		// libmbus prints the raw counter with the unit code's name; ours
		// is scaled to the base unit.
		wv, err := strconv.ParseFloat(wr.Value, 64)
		if err != nil {
			c.recDiff++
			c.report("", "%s: fixed record %d: value %q", name, i, wr.Value)
			continue
		}
		ok := false
		switch wr.Unit {
		case "l":
			ok = got.Unit == "m3" && near(got.Value, wv/1000)
		case "Wh", "kWh", "MWh":
			ok = got.Unit == "Wh" && near(got.Value, wv*map[string]float64{"Wh": 1, "kWh": 1e3, "MWh": 1e6}[wr.Unit])
		case "m^3":
			ok = got.Unit == "m3" && near(got.Value, wv)
		case "reserved but historic":
			// Counter 2 with unit code 3Eh: counter 1's unit, a stored
			// value; libmbus prints it raw, ours is scaled like counter 1.
			ok = got.Historic && near(got.Value, wv*unitScale(f.Counters[0], w.Records[0]))
		default:
			ok = near(got.Value, wv)
		}
		if ok {
			c.recOK++
		} else {
			c.recDiff++
			c.report("", "%s: fixed record %d: ours %v %s (code %02X), libmbus %s %q", name, i, got.Value, got.Unit, got.UnitCode, wr.Value, wr.Unit)
		}
	}
}

// unitScale is the factor between our scaled counter 1 and libmbus's raw one.
func unitScale(got wired.FixedCounter, w lmRecord) float64 {
	wv, err := strconv.ParseFloat(w.Value, 64)
	if err != nil || wv == 0 {
		return 1
	}
	return got.Value / wv
}

// near compares within libmbus's printing precision (six decimals).
func near(a, b float64) bool {
	return a == b || math.Abs(a-b) <= 5e-7+1e-9*math.Max(math.Abs(a), math.Abs(b))
}

func compareRecords(c *lmTally, name string, got []records.Record, want []lmRecord) {
	for i := range max(len(got), len(want)) {
		if i >= len(got) {
			c.records++
			c.recMissing++
			c.report("", "%s: record %s only in libmbus: %+v", name, want[i].ID, want[i])
			continue
		}
		if i >= len(want) {
			c.recMore++
			c.report("", "%s: record %d only in ours: %s %v", name, i, got[i].Name(), got[i].Value)
			continue
		}
		c.records++
		if why, cat := compareRecord(got[i], want[i]); why != "" {
			c.recDiff++
			c.report(cat, "%s: record %s (DIF %02X VIF %02X VIFE %X): %s", name, want[i].ID, got[i].DIF, got[i].VIF, got[i].VIFE, why)
		} else {
			c.recOK++
		}
	}
}

func compareRecord(g records.Record, w lmRecord) (why, cat string) {
	if g.DIF == 0x0F || g.DIF == 0x1F {
		wantFn := map[byte]string{0x0F: "Manufacturer specific", 0x1F: "More records follow"}[g.DIF]
		if w.Function != wantFn {
			return fmt.Sprintf("function: DIF %02X, libmbus %q", g.DIF, w.Function), ""
		}
		wv := strings.ToUpper(strings.Join(strings.Fields(w.Value), ""))
		gv, _ := g.Value.(string)
		// libmbus prints the manufacturer-specific bytes last byte first.
		rev, _ := hex.DecodeString(wv)
		slices.Reverse(rev)
		if gv != wv && gv != strings.ToUpper(hex.EncodeToString(rev)) {
			return fmt.Sprintf("manufacturer data %s, libmbus %s", gv, wv), ""
		}
		return "", ""
	}
	var bad []string
	if fn := lmFunction[g.Function]; fn != w.Function {
		bad = append(bad, fmt.Sprintf("function %s, libmbus %q", g.Function, w.Function))
	}
	if s := strconv.Itoa(g.Storage); s != w.StorageNumber {
		bad = append(bad, fmt.Sprintf("storage %s, libmbus %s", s, w.StorageNumber))
	}
	if w.Tariff != "" && strconv.Itoa(g.Tariff) != w.Tariff {
		bad = append(bad, fmt.Sprintf("tariff %d, libmbus %s", g.Tariff, w.Tariff))
	}
	if w.Device != "" && strconv.Itoa(g.Subunit) != w.Device {
		bad = append(bad, fmt.Sprintf("subunit %d, libmbus %s", g.Subunit, w.Device))
	}
	if v := compareValue(g, w); v != "" {
		bad = append(bad, v)
	}
	if len(bad) == 0 {
		return "", ""
	}
	why = strings.Join(bad, "; ")
	switch {
	case g.Manufacturer:
		cat = catMfct
	case g.Invalid:
		cat = catInvalid
	case g.VIF == 0x7B && len(g.VIFE) == 0 && w.Quantity == "" && w.Function == "":
		cat = catNoMeaning
	case len(g.VIFE) == 1 && g.VIFE[0]&0x7F >= 0x50 && g.VIFE[0]&0x7F <= 0x6F:
		cat = catDateOfVIFE
	case strings.HasPrefix(fmt.Sprint(g.Value), "****-") && strings.HasPrefix(w.Value, "2027-"):
		cat = catEveryYear
	}
	return why, cat
}

// compareValue compares a record's value with libmbus's normalised one.
func compareValue(g records.Record, w lmRecord) string {
	if g.Manufacturer && g.BaseValue != nil {
		// A manufacturer VIFE after a standard VIF: compare the value the
		// VIF gives (records.Record.BaseValue), as libmbus decodes it.
		g.Value = g.BaseValue
	}
	desc := fmt.Sprintf("ours %s=%q %s, libmbus %q=%q %q", g.Name(), fmt.Sprint(g.Value), g.Unit, w.Quantity, w.Value, w.Unit)
	switch v := g.Value.(type) {
	case float64, int64:
		var gv float64
		if f, ok := v.(float64); ok {
			gv = f
		} else {
			gv = float64(v.(int64))
		}
		wv, err := strconv.ParseFloat(w.Value, 64)
		if err != nil {
			return "value: " + desc
		}
		if u, ok := lmUnit[g.Unit]; ok {
			if u.unit != w.Unit {
				return "unit: " + desc
			}
			gv *= u.factor
		}
		if !near(gv, wv) {
			return "value: " + desc
		}
		return ""
	case string:
		if v == w.Value {
			return ""
		}
		ws := strings.TrimSpace(w.Value)
		if wf, err := strconv.ParseFloat(ws, 64); err == nil {
			// Identifiers and BCD that we keep as digits, libmbus as a number.
			if gf, err := strconv.ParseFloat(v, 64); err == nil && near(gf, wf) {
				return ""
			}
			// Bit fields and type D/C data we keep as hex digits (most
			// significant first), libmbus as an integer, signed or not.
			if len(v) <= 16 && len(v)%2 == 0 {
				if u, err := strconv.ParseUint(v, 16, 64); err == nil {
					bits := uint(4 * len(v))
					s := int64(u)
					if bits < 64 && u&(1<<(bits-1)) != 0 {
						s -= 1 << bits
					}
					if near(float64(u), wf) || near(float64(s), wf) {
						return ""
					}
				}
			}
		}
		if dateEqual(v, ws) {
			return ""
		}
		if strings.EqualFold(strings.Join(strings.Fields(ws), ""), v) {
			return ""
		}
		return "value: " + desc
	}
	return "value type: " + desc
}

// dateEqual compares our ISO 8601 text with libmbus's ("…Z" for date and
// time, seconds always printed).
func dateEqual(ours, theirs string) bool {
	t := strings.TrimSuffix(theirs, "Z")
	if ours == t {
		return true
	}
	return len(ours) == 16 && ours+":00" == t
}
