// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cB-Sigma/mbus/meters"
	"github.com/cB-Sigma/mbus/records"
	"github.com/cB-Sigma/mbus/wired"
	"github.com/cB-Sigma/mbus/wireless"
)

// wmCase is one telegram of wmbusmeters' tests with the JSON it expects.
type wmCase struct {
	where  string // file:line
	driver string
	key    string   // hex, or "" for none
	alt    []string // keys the other tests give for this meter id
	hex    string
	json   map[string]any
}

// parseXMQTests reads tests/generated_tests.xmq: blocks of
// "test { args = '…' telegram = … json = '…' }".
func parseXMQTests(path string) ([]wmCase, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []wmCase
	var cur map[string]string
	start := 0
	for n, line := range strings.Split(string(f), "\n") {
		s := strings.TrimSpace(line)
		switch {
		case s == "test {":
			cur, start = map[string]string{}, n+1
		case s == "}" && cur != nil:
			c, err := wmFromArgs(fmt.Sprintf("%s:%d", filepath.Base(path), start), cur["args"], cur["telegram"], cur["json"])
			if err != nil {
				return nil, err
			}
			out = append(out, c)
			cur = nil
		case cur != nil:
			k, v, ok := strings.Cut(s, "=")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			v = strings.TrimSuffix(strings.TrimPrefix(v, "'"), "'")
			cur[strings.TrimSpace(k)] = v
		}
	}
	return out, nil
}

// parseDriverTests reads the "// Test:" blocks of a C++ driver.
func parseDriverTests(path string) ([]wmCase, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []wmCase
	lines := strings.Split(string(f), "\n")
	for i := 0; i < len(lines); i++ {
		args, ok := strings.CutPrefix(strings.TrimSpace(lines[i]), "// Test:")
		if !ok {
			continue
		}
		var tel, js string
		j := i + 1
		for ; j < len(lines) && j < i+6; j++ {
			s := strings.TrimSpace(lines[j])
			if t, ok := strings.CutPrefix(s, "// telegram="); ok && tel == "" {
				tel = t
			} else if strings.HasPrefix(s, "// {") && tel != "" {
				js = strings.TrimPrefix(s, "// ")
				break
			}
		}
		if tel == "" || js == "" {
			continue
		}
		c, err := wmFromArgs(fmt.Sprintf("%s:%d", filepath.Base(path), i+1), args, tel, js)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		i = j
	}
	return out, nil
}

// parseSimulation reads a simulations/*.txt file: telegram= lines, each
// usually followed by the JSON wmbusmeters prints for it. Keys are not in
// these files; they are looked up by meter id among the driver tests.
func parseSimulation(path string) ([]wmCase, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []wmCase
	lines := strings.Split(string(f), "\n")
	for i, line := range lines {
		t, ok := strings.CutPrefix(strings.TrimSpace(line), "telegram=")
		if !ok {
			continue
		}
		c := wmCase{where: fmt.Sprintf("%s:%d", filepath.Base(path), i+1), hex: cleanHex(t)}
		if i+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "{") {
			if err := json.Unmarshal([]byte(strings.TrimSpace(lines[i+1])), &c.json); err != nil {
				return nil, fmt.Errorf("%s: %v", c.where, err)
			}
			c.driver, _ = c.json["meter"].(string)
		}
		out = append(out, c)
	}
	return out, nil
}

func wmFromArgs(where, args, tel, js string) (wmCase, error) {
	a := strings.Fields(args)
	if len(a) < 4 {
		return wmCase{}, fmt.Errorf("%s: args %q", where, args)
	}
	c := wmCase{where: where, driver: a[1], hex: cleanHex(tel)}
	if k := a[3]; k != "NOKEY" {
		c.key = k
	}
	if err := json.Unmarshal([]byte(js), &c.json); err != nil {
		return wmCase{}, fmt.Errorf("%s: %v", where, err)
	}
	return c, nil
}

// cleanHex drops the markers wmbusmeters puts in a telegram's hex (|, _
// and # between the parts, "+n" seconds after it). A comma separates
// telegrams a test sends one after the other.
func cleanHex(s string) string {
	if i := strings.Index(s, "|+"); i >= 0 {
		s = s[:i]
	}
	return strings.NewReplacer("|", "", "_", "", " ", "", "#", "").Replace(s)
}

// wmDrivers is what the tests read from wmbusmeters' driver files
// (drivers/src/*.xmq), keyed by each driver's name and its aliases.
type wmDrivers struct {
	formats     map[string][][]byte // compact-frame formats ("difvif = …")
	proprietary map[string]bool     // cuts a proprietary payload up by byte position
	mvt         map[string][]string // "MAN,vv,tt" the driver detects
}

func readDrivers(root string) (wmDrivers, error) {
	files, _ := filepath.Glob(filepath.Join(root, "drivers", "src", "*.xmq"))
	d := wmDrivers{map[string][][]byte{}, map[string]bool{}, map[string][]string{}}
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			return d, err
		}
		names := []string{strings.TrimSuffix(filepath.Base(p), ".xmq")}
		var fs [][]byte
		var mvts []string
		prop := false
		for _, line := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok {
				continue
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			switch k {
			case "name", "aliases":
				// The driver's own name comes first; "name" lines of its
				// fields follow later and are not names of the driver.
				if len(names) == 1 || k == "aliases" {
					names = append(names, strings.Split(v, ",")...)
				}
			case "difvif":
				if f, err := hex.DecodeString(v); err == nil {
					fs = append(fs, f)
				}
			case "mvt":
				mvts = append(mvts, strings.ToUpper(strings.ReplaceAll(v, " ", "")))
			case "match_entire_payload", "match_entire_frame":
				prop = prop || v == "true"
			}
		}
		for _, n := range names {
			n = strings.TrimSpace(n)
			d.formats[n] = append(d.formats[n], fs...)
			d.proprietary[n] = d.proprietary[n] || prop
			d.mvt[n] = append(d.mvt[n], mvts...)
		}
	}
	return d, nil
}

// wmCompareMVT checks the manufacturer, version and device type we read
// against the ones the test's driver detects (a driver named explicitly
// in a test may also be given a meter it does not detect: then it is not
// counted as a difference, only noted).
func wmCompareMVT(c *wmTally, tc wmCase, hs ...wireless.Header) {
	list := c.drivers.mvt[tc.driver]
	if len(list) == 0 {
		return
	}
	var ours []string
	for _, h := range hs {
		s := fmt.Sprintf("%s,%02X,%02X", h.Manufacturer, h.Version, h.DeviceType)
		if slices.Contains(list, s) {
			c.mvtEq++
			return
		}
		ours = append(ours, s)
	}
	c.mvtOther++
	c.notes = append(c.notes, fmt.Sprintf("%s (%s): manufacturer,version,type %v not among the driver's %v", tc.where, tc.driver, ours, list))
}

// plainCopy handles a habit of wmbusmeters' test data: many telegrams are
// stored with the payload already decrypted (it begins with the 2F2F
// check bytes) while the TPL header still announces security mode 5 or 7;
// wmbusmeters accepts them when no key is configured. Our decoder rightly
// refuses them (ErrNoKey). plainCopy returns the same telegram with the
// mode cleared to 0 (and mode 7's configuration field extension removed),
// as a CRC-less frame, or nil when the telegram is not of that kind.
//
// The same is done for an extended link layer that announces AES-CTR
// encryption (Kamstrup's CI 8Dh) when its payload CRC checks over the
// stored bytes as they are, which proves them plaintext.
func plainCopy(frame []byte, tg *wireless.Telegram) []byte {
	if tg == nil {
		return nil
	}
	t, _, err := wireless.StripCRC(frame, wireless.FormatAuto)
	if err != nil {
		return nil
	}
	if e := tg.ELL; e != nil && e.HasSN && e.SN>>29 != 0 && tg.CI == 0 {
		sn := map[byte]int{wireless.CIELL8: 13, wireless.CIELL16: 21}[e.CI]
		if sn == 0 || t[10] != e.CI || sn+6 > len(t) {
			return nil
		}
		// The payload CRC, low byte first.
		crc := uint16(t[sn+4]) | uint16(t[sn+5])<<8
		if wireless.CRC(t[sn+6:]) != crc {
			return nil
		}
		out := append([]byte(nil), t...)
		out[sn+3] &^= 0xE0
		return out
	}
	if (tg.Mode != 5 && tg.Mode != 7) || tg.HeaderKind == "none" {
		return nil
	}
	var pat []byte
	if tg.HeaderKind == "short" {
		pat = []byte{tg.CI, tg.Access, tg.Status, byte(tg.Config), byte(tg.Config >> 8)}
	} else {
		pat = append([]byte{tg.CI}, tg.Meter.A[:4]...)
		pat = append(pat, byte(tg.Meter.MField), byte(tg.Meter.MField>>8), tg.Meter.Version, tg.Meter.DeviceType,
			tg.Access, tg.Status, byte(tg.Config), byte(tg.Config>>8))
	}
	i := bytes.Index(t[10:], pat)
	if i < 0 {
		return nil
	}
	cfg := 10 + i + len(pat) - 2 // the configuration field
	rest := cfg + 2
	if tg.Mode == 7 {
		rest++ // configuration field extension
	}
	if rest+2 > len(t) || t[rest] != 0x2F || t[rest+1] != 0x2F {
		return nil
	}
	out := append([]byte(nil), t[:cfg+2]...)
	c := uint16(out[cfg]) | uint16(out[cfg+1])<<8
	c &^= 0x1F << 8
	out[cfg], out[cfg+1] = byte(c), byte(c>>8)
	out = append(out, t[rest:]...)
	if tg.AFL != nil {
		// The AFL's MAC was computed over the ciphertext wmbusmeters did
		// not keep: drop the AFL (CI 90h, its length, the fields).
		a := 10 + map[byte]int{wireless.CIELL2: 3, wireless.CIELL8: 9, wireless.CIELL10: 11, wireless.CIELL16: 17}[out[10]]
		if a+2 > len(out) || out[a] != wireless.CIAFL || a+2+int(out[a+1]) > len(out) {
			return nil
		}
		out = append(out[:a:a], out[a+2+int(out[a+1]):]...)
	}
	out[0] = byte(len(out) - 1)
	return out
}

// wmMedium is the device type behind each "media" text wmbusmeters prints
// (EN 13757-3 device types; the texts are wmbusmeters').
var wmMedium = map[string][]byte{
	"other": {0x00}, "oil": {0x01}, "electricity": {0x02}, "gas": {0x03}, "heat": {0x04},
	"steam": {0x05}, "warm water": {0x06}, "water": {0x07},
	"heat cost allocation": {0x08}, "heat cost allocator": {0x08}, "compressed air": {0x09},
	"cooling load volume at outlet": {0x0A}, "cooling load volume at inlet": {0x0B},
	"heat volume at inlet": {0x0C}, "heat/cooling load": {0x0D}, "bus/system component": {0x0E},
	"unknown": {0x0F}, "hot water": {0x15}, "cold water": {0x16}, "pressure": {0x18},
	"smoke detector": {0x1A}, "room sensor": {0x1B}, "radio converter (meter side)": {0x37},
}

// wmField says which of our records a wmbusmeters field stands for: the
// quantity at storage 0, the given tariff, subunit 0, instantaneous, with
// no modifiers, converted to the field's unit.
type wmField struct {
	quantity string
	tariff   int
	unit     string // the field's unit suffix
}

var wmFields = map[string]wmField{
	"total_m3":                     {"volume", 0, "m3"},
	"total_volume_m3":              {"volume", 0, "m3"},
	"total_energy_consumption_kwh": {"energy", 0, "kwh"},
	"total_kwh":                    {"energy", 0, "kwh"},
	"volume_flow_m3h":              {"volume_flow", 0, "m3h"},
	"flow_m3h":                     {"volume_flow", 0, "m3h"},
	"power_kw":                     {"power", 0, "kw"},
	"current_power_consumption_kw": {"power", 0, "kw"},
	"flow_temperature_c":           {"flow_temperature", 0, "c"},
	"return_temperature_c":         {"return_temperature", 0, "c"},
	"current_consumption_hca":      {"hca_units", 0, "hca"},
	"on_time_h":                    {"on_time", 0, "h"},
	"operating_time_h":             {"operating_time", 0, "h"},
}

// shKey finds "<driver> <8-digit id> <32 hex digits>" in a test script.
var shKey = regexp.MustCompile(`[a-z0-9_]+[ \t]+([0-9]{8})[ \t]+([0-9A-Fa-f]{32})\b`)

var tariffField = regexp.MustCompile(`^total_energy_consumption_tariff_([1-9])_kwh$`)

// toUnit is the factor from one of our units to a wmbusmeters unit suffix.
func toUnit(ours, theirs string) (float64, bool) {
	f, ok := map[[2]string]float64{
		{"m3", "m3"}:  1,
		{"Wh", "kwh"}: 1e-3, {"MWh", "kwh"}: 1e3, {"J", "kwh"}: 1 / 3.6e6, {"GJ", "kwh"}: 1e9 / 3.6e6,
		{"m3/h", "m3h"}: 1, {"m3/min", "m3h"}: 60, {"m3/s", "m3h"}: 3600,
		{"W", "kw"}: 1e-3, {"MW", "kw"}: 1e3, {"J/h", "kw"}: 1 / 3.6e6,
		{"Cel", "c"}: 1, {"", "hca"}: 1,
		{"s", "h"}: 1.0 / 3600, {"min", "h"}: 1.0 / 60, {"h", "h"}: 1, {"d", "h"}: 24,
	}[[2]string{ours, theirs}]
	return f, ok
}

func number(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int64:
		return float64(x), true
	}
	return 0, false
}

// nearRel compares within the precision wmbusmeters prints.
func nearRel(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	m := max(a, -a, b, -b)
	return d <= 1e-6+1e-6*m
}

// Decode failures with a known cause; anything else is unexplained.
const (
	wmNoKey       = "encrypted, and wmbusmeters' test gives no key (NOKEY, or a simulation file with no key for that id)"
	wmMfctCI      = "manufacturer-specific CI field (A0h-B7h): the payload is the manufacturer's, not decoded by this library"
	wmCompact     = "compact frame whose format neither an earlier telegram of the test nor the driver's list gives"
	wmProprietary = "proprietary payload that the wmbusmeters driver cuts up by byte position (match_entire_payload or match_entire_frame in its driver file); not M-Bus data records"
	wmDiehl       = "Diehl group telegram (CI 7Ah, configuration field bit 12): the manufacturer's own scheme, which EN 13757-7 reserves as security modes 16-31"
	wmBroken      = "telegram broken on purpose (simulation_broken.txt says so)"
	wmTheirError  = "a telegram too short for its layout, for which wmbusmeters itself prints a decoding error"
	wmTail        = "the data records decode, then the last bytes of the application data do not (in these telegrams 2 or 3 bytes after the last record: an FFFFh filler or what looks like a CRC left in the stored telegram); we return the records with an error, wmbusmeters reports the values"
	wmFixedL      = "the test telegram's L field disagrees with its length; the harness set L to the length"
	wmEnhancedID  = "the driver takes the meter's id from an enhanced identification record (VIF 79h) of a Qundis walk-by telegram, not from the link or TPL address; medium and values not compared"
	wmUnchecked   = "a JSON line in simulation_metershell.txt that wmbusmeters' test does not check; the telegram's BCD 00005648 is 5.648 m3, as we decode"
	wmFFC         = "compact frame rebuilt with the format wmbusmeters' driver lists, but the result fails the Full-Frame-CRC that our decoder checks (wmbusmeters prints that CRC and does not check it)"
	wmDES         = "DES (mode 2) telegram that the test key decrypts, with a zero IV, to records led by 2F2F (wmbusmeters checks that) but without the meter id that our decoder requires in the plaintext as its check (EN 13757-7 9.4.3.2 as we read it); wmbusmeters' own comment doubts it is a real meter's telegram"
)

type wmTally struct {
	cases, telegrams, wireless, wiredN, decoded int
	withKey, decrypted, plain, compact          int
	tail, fixedL, idOther, mvtEq, mvtOther      int
	failed                                      map[string]int
	idEq, idDiff, mediumEq, mediumDiff          int
	mediumSkipped                               int
	fields, fieldEq, fieldDiff, fieldNoMatch    int
	fieldExplained, fieldElsewhere              int
	byDriver, allFields, allEq, allMissing      int
	invalidDates, lenient                       int
	missing                                     map[string]int // by "our driver/their driver"
	drivers                                     wmDrivers
	unexplained                                 []string
	notes                                       []string
}

// TestWmbusmetersTelegrams: interop with wmbusmeters 3.0.0 driver tests and simulations (wireless and wired decoding)
func TestWmbusmetersTelegrams(t *testing.T) {
	root := checkout(t, wmbusmeters)
	// wmbusmeters' test data stores some Diehl telegrams unscrambled.
	meters.AcceptPlainDiehl = true
	defer func() { meters.AcceptPlainDiehl = false }()
	// The Diehl group's default keys are not shipped with the library:
	// they are read from the wmbusmeters checkout, as a user would supply
	// them, and only for this run.
	if k, err := diehlKeysFrom(root); err != nil {
		t.Logf("Diehl default keys not found in the checkout (%v): scrambled Diehl telegrams stay undecoded", err)
	} else {
		meters.SetMakerKeys(k)
		defer meters.SetMakerKeys(meters.MakerKeys{})
	}
	cases, err := parseXMQTests(filepath.Join(root, "tests", "generated_tests.xmq"))
	if err != nil {
		t.Fatal(err)
	}
	ccs, _ := filepath.Glob(filepath.Join(root, "src", "driver_*.cc"))
	for _, p := range ccs {
		cs, err := parseDriverTests(p)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, cs...)
	}
	// Keys by meter id: from the driver tests, and from the meter
	// arguments of tests/*.sh ("name driver id key"), which also give some
	// wrong keys on purpose; every key named for an id is tried.
	keyByID := map[string][]string{}
	addKey := func(id, k string) {
		if id != "" && k != "" && !slices.Contains(keyByID[id], k) {
			keyByID[id] = append(keyByID[id], k)
		}
	}
	for _, c := range cases {
		id, _ := c.json["id"].(string)
		addKey(id, c.key)
	}
	scripts, _ := filepath.Glob(filepath.Join(root, "tests", "*.sh"))
	for _, p := range scripts {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range shKey.FindAllStringSubmatch(string(b), -1) {
			addKey(m[1], strings.ToUpper(m[2]))
		}
	}
	sims, _ := filepath.Glob(filepath.Join(root, "simulations", "simulation_*.txt"))
	for _, p := range sims {
		cs, err := parseSimulation(p)
		if err != nil {
			t.Fatal(err)
		}
		for i := range cs {
			if id, _ := cs[i].json["id"].(string); id != "" {
				cs[i].alt = keyByID[id]
			}
		}
		cases = append(cases, cs...)
	}
	for i := range cases {
		if id, _ := cases[i].json["id"].(string); id != "" && cases[i].key == "" && cases[i].alt == nil {
			cases[i].alt = keyByID[id]
		}
	}
	drivers, err := readDrivers(root)
	if err != nil {
		t.Fatal(err)
	}
	// The same telegram appears in several files: decode each once.
	seen := map[string]bool{}
	c := wmTally{failed: map[string]int{}, missing: map[string]int{}, drivers: drivers}
	for _, tc := range cases {
		h := strings.ToUpper(tc.hex)
		if seen[h] || h == "" {
			continue
		}
		seen[h] = true
		c.cases++
		var frames [][]byte
		for _, part := range strings.Split(h, ",") {
			if len(part)%2 == 1 {
				// One test's hex has a stray last digit (qwaterv2); the
				// telegram's L field does not count it.
				part = part[:len(part)-1]
			}
			b, err := hex.DecodeString(part)
			if err != nil {
				c.unexplained = append(c.unexplained, fmt.Sprintf("%s: hex: %v", tc.where, err))
				frames = nil
				break
			}
			frames = append(frames, b)
		}
		if len(frames) == 1 && len(frames[0]) > 5 && frames[0][0] == 0x68 && frames[0][len(frames[0])-1] == 0x16 {
			c.telegrams++
			c.wiredN++
			wmWired(&c, tc, frames[0])
			continue
		}
		if len(frames) > 0 {
			wmWireless(&c, tc, frames, drivers.formats[tc.driver])
		}
	}
	t.Logf("wmbusmeters %s (%s): %d distinct test telegrams, %d frames (%d wireless, %d wired) from tests/generated_tests.xmq, src/driver_*.cc and simulations/simulation_*.txt; %d frames decoded",
		wmbusmeters.tag, wmbusmeters.commit[:12], c.cases, c.telegrams, c.wireless, c.wiredN, c.decoded)
	t.Logf("of the decoded: %d decrypted with the test's AES or DES key (%d frames had a key); %d stored already decrypted by wmbusmeters (security mode cleared, see plainCopy); %d compact frames rebuilt; %d with an undecodable tail after the records; %d after correcting L",
		c.decrypted, c.withKey, c.plain, c.compact, c.tail, c.fixedL)
	t.Logf("meter id: %d equal, %d differ, %d from an enhanced identification record; manufacturer,version,type among the driver's detect list: %d, not (driver named explicitly): %d; medium: %d equal, %d differ, %d not compared; fields: %d compared, %d equal, %d differ (%d of them explained), %d with no plain record of that quantity at storage 0 (in %d of them a record with a tariff or modifier holds the value)",
		c.idEq, c.idDiff, c.idOther, c.mvtEq, c.mvtOther, c.mediumEq, c.mediumDiff, c.mediumSkipped, c.fields, c.fieldEq, c.fieldDiff, c.fieldExplained, c.fieldNoMatch, c.fieldElsewhere)
	t.Logf("decoded only with an opt-in lenient option (FormatCache.IgnoreFullFrameCRC, which wmbusmeters' behaviour matches): %d", c.lenient)
	t.Logf("meter drivers (package meters): %d frames the decoder left were read by a driver; every field wmbusmeters prints (numbers by unit, dates): %d compared, %d found among our values, %d not; %d dates coded invalid that wmbusmeters prints as dates (year 2100 or later, month 13 or more) not compared",
		c.byDriver, c.allFields, c.allEq, c.allMissing, c.invalidDates)
	mk := make([]string, 0, len(c.missing))
	for k := range c.missing {
		mk = append(mk, k)
	}
	sort.Strings(mk)
	for _, k := range mk {
		t.Logf("fields not found, %s: %d", k, c.missing[k])
	}
	keys := make([]string, 0, len(c.failed))
	for k := range c.failed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("not decoded, %d: %s", c.failed[k], k)
	}
	for _, s := range c.notes {
		t.Log("  " + s)
	}
	for _, s := range c.unexplained {
		t.Error(s)
	}
	t.Logf("unexplained: %d", len(c.unexplained))
}

// diehl are the M fields of the Diehl group, whose telegrams with CI 7Ah
// and bit 12 of the configuration field set carry the manufacturer's own
// layout (wmbusmeters, manufacturer_specificities.cc): DME, EWT, HYD,
// SAP, SPL.
var diehl = map[string]bool{"DME": true, "EWT": true, "HYD": true, "SAP": true, "SPL": true}

// recordsError reports an error of package records (the records before it
// were decoded and kept).
func recordsError(err error) bool { return strings.HasPrefix(err.Error(), "record ") }

// wmWireless decodes a test's telegrams in order (a full frame before the
// compact frames that use its format) and compares the last with the JSON.
func wmWireless(c *wmTally, tc wmCase, frames [][]byte, driverFormats [][]byte) {
	var cands [][]byte
	for _, k := range append([]string{tc.key}, tc.alt...) {
		if b, err := hex.DecodeString(k); err == nil && len(b) > 0 {
			cands = append(cands, b)
		}
	}
	var key []byte
	// A fresh Decoder per telegram: no counters carried between tests. A
	// 16-byte key is AES, an 8-byte key the DES of modes 2 and 3.
	// The test's AES key, else a maker's published default key (Diehl's,
	// as wmbusmeters adds it).
	noDefault := false
	aesKey := func(h wireless.Header) []byte {
		if k := sized(key, 16); k != nil {
			return k
		}
		if noDefault || key != nil {
			return nil
		}
		return meters.DefaultKey(h)
	}
	dec := func(f []byte, ff wireless.FrameFormat) (*wireless.Telegram, error) {
		// DESCheck2F2F: accept DES mode 2 by its 2F2F as wmbusmeters does.
		d := &wireless.Decoder{DESKey: func(wireless.Header) []byte { return sized(key, 8) }, DESCheck2F2F: true}
		return d.Decode(f, ff, aesKey)
	}
	cache := wireless.NewFormatCache(16)
	if len(frames) > 1 {
		// A FormatCache keeps a meter's full-frame format only once it
		// has seen that meter send a compact frame (it holds formats of
		// compact-sending meters only). A test's sequence is a full frame
		// and then its compact frame, so it is fed once beforehand, as a
		// receiver would have heard the meter's earlier compact frames.
		for _, b := range frames {
			tg, err := dec(b, wireless.FormatAuto)
			if p := plainCopy(b, tg); errors.Is(err, wireless.ErrNoKey) && p != nil {
				tg, err = dec(p, wireless.FormatNoCRC)
			}
			if tg != nil {
				cache.Complete(tg, err)
			}
		}
	}
	var last *wireless.Telegram
	var lastReading *meters.Reading
	for n, b := range frames {
		c.telegrams++
		c.wireless++
		where := tc.where
		if len(frames) > 1 {
			where = fmt.Sprintf("%s#%d", tc.where, n+1)
		}
		if len(cands) > 0 {
			c.withKey++
			key = cands[0]
		}
		tg, err := dec(b, wireless.FormatAuto)
		var reading *meters.Reading
		desCheck, ffcFail := false, false
		// A wrong key of the test scripts: try the meter's other keys.
		for i := 1; i < len(cands) && (errors.Is(err, wireless.ErrDecrypt) || errors.Is(err, wireless.ErrMAC)); i++ {
			key = cands[i]
			tg, err = dec(b, wireless.FormatAuto)
		}
		if len(cands) > 0 && (errors.Is(err, wireless.ErrDecrypt) || errors.Is(err, wireless.ErrMAC)) {
			// No key fits: the telegram may be stored decrypted.
			c.notes = append(c.notes, fmt.Sprintf("%s (%s): none of the %d keys the tests give decrypts it (%v); trying it as stored plaintext", where, tc.driver, len(cands), err))
			if tg != nil && tg.Mode == 2 && len(cands[0]) == 8 {
				p := desPlain(b, cands[0], tg)
				c.notes = append(c.notes, fmt.Sprintf("%s (%s): DES-CBC with a zero IV gives %X (meter id bytes %X)", where, tc.driver, p, tg.Meter.A[:4]))
				desCheck = bytes.HasPrefix(p, []byte{0x2F, 0x2F}) && !bytes.Contains(p, tg.Meter.A[:4])
			}
			key = nil
			tg, err = dec(b, wireless.FormatAuto)
		}
		if len(cands) == 0 && (errors.Is(err, wireless.ErrDecrypt) || errors.Is(err, wireless.ErrMAC)) {
			// The maker's default key does not fit: not that key's
			// telegram (or one stored decrypted).
			noDefault = true
			tg, err = dec(b, wireless.FormatAuto)
		}
		fixedL := false
		if errors.Is(err, wireless.ErrCRC) && len(b) > 11 && int(b[0]) != len(b)-1 {
			// The test data's L field disagrees with the bytes given
			// (wmbusmeters' simulation input does not check it).
			if _, _, errA := wireless.StripCRC(b, wireless.FormatA); errA != nil {
				fixed := append([]byte(nil), b...)
				fixed[0] = byte(len(fixed) - 1)
				tg, err = dec(fixed, wireless.FormatNoCRC)
				b, fixedL = fixed, true
			}
		}
		plain := false
		for range 2 {
			if !errors.Is(err, wireless.ErrNoKey) {
				break
			}
			p := plainCopy(b, tg)
			if p == nil {
				break
			}
			tg, err = dec(p, wireless.FormatNoCRC)
			b, plain = p, true
		}
		if tg != nil && (err == nil || errors.Is(err, wireless.ErrCompactFrame)) {
			_, err = cache.Complete(tg, err)
			if err != nil && isCompact(tg.CI) {
				if len(driverFormats) == 0 {
					// A simulation file names no driver: take the formats
					// of the driver that detects the meter.
					driverFormats = formatsByMVT(c, tg)
				}
				for _, f := range driverFormats {
					cache.Put(tg.Meter.Key(), f)
				}
				_, err = cache.Complete(tg, wireless.ErrCompactFrame)
				if errors.Is(err, wireless.ErrFullFrameCRC) {
					// wmbusmeters does not check that CRC: with the opt-in
					// IgnoreFullFrameCRC the frame decodes, with a warning.
					lc := wireless.NewFormatCache(16)
					lc.IgnoreFullFrameCRC = true
					for _, f := range driverFormats {
						lc.Put(tg.Meter.Key(), f)
					}
					if _, lerr := lc.Complete(tg, wireless.ErrCompactFrame); lerr == nil && len(tg.Warnings) > 0 {
						err = nil
						c.lenient++
						c.notes = append(c.notes, fmt.Sprintf("%s (%s): decoded only with FormatCache.IgnoreFullFrameCRC (warning: %s)", where, tc.driver, tg.Warnings[0]))
					} else {
						ffcFail = true
						c.notes = append(c.notes, fmt.Sprintf("%s (%s): IgnoreFullFrameCRC does not help: %v", where, tc.driver, lerr))
					}
				}
			}
			if err == nil && isCompact(tg.CI) {
				c.compact++
			}
		}
		tail := false
		if err != nil && tg != nil {
			// A meter driver (package meters) may read what the decoder
			// leaves: a manufacturer's payload or security scheme.
			if rd, rerr := meters.ReadKeys(tg, err, aesKey); rerr == nil && rd.Driver != "" {
				c.byDriver++
				c.notes = append(c.notes, fmt.Sprintf("%s (%s): read by driver %s (decoder: %v)", where, tc.driver, rd.Driver, err))
				err, reading = nil, rd
			}
		}
		if err != nil {
			cat := ""
			switch {
			case ffcFail:
				cat = wmFFC
			case desCheck:
				cat = wmDES
			case strings.Contains(fmt.Sprint(tc.json["status"]), "DECODING_ERROR"):
				cat = wmTheirError
			case c.drivers.proprietary[tc.driver]:
				cat = wmProprietary
			case errors.Is(err, wireless.ErrNoKey):
				cat = wmNoKey
			case tg != nil && isCompact(tg.CI):
				cat = wmCompact
			case tg != nil && tg.CI >= 0xA0 && tg.CI <= 0xB7:
				cat = wmMfctCI
			case tg != nil && tg.CI == wireless.CIShortHeader && diehl[tg.Meter.Manufacturer] && tg.Config>>8&0x10 != 0:
				cat = wmDiehl
			case strings.HasPrefix(tc.where, "simulation_broken.txt"):
				cat = wmBroken
			case tg != nil && recordsError(err) && len(tg.Records) > 0:
				tail = true
			}
			if !tail {
				if cat == "" {
					c.unexplained = append(c.unexplained, fmt.Sprintf("%s (%s, key %v): %v", where, tc.driver, tc.key != "", err))
					return
				}
				c.failed[cat]++
				c.notes = append(c.notes, fmt.Sprintf("%s (%s): not decoded: %v [%s]", where, tc.driver, err, cat))
				if tc.json != nil && n == len(frames)-1 {
					// Its fields count as not found.
					wmCompareReading(c, tc, &meters.Reading{Driver: "(not read)"})
				}
				return
			}
			c.tail++
			c.notes = append(c.notes, fmt.Sprintf("%s (%s): %d records, then: %v; the application data ends %X [%s]", where, tc.driver, len(tg.Records), err, tg.APL[max(0, len(tg.APL)-6):], wmTail))
		}
		c.decoded++
		if key != nil && !plain && tg.Encrypted {
			c.decrypted++
			how := fmt.Sprintf("TPL mode %d", tg.Mode)
			if tg.ELL != nil && tg.ELL.HasSN && tg.ELL.SN>>29 != 0 {
				how = "ELL AES-CTR"
			}
			c.notes = append(c.notes, fmt.Sprintf("%s (%s): decrypted with the test's key (%s)", where, tc.driver, how))
		}
		if plain {
			c.plain++
		}
		if fixedL {
			c.fixedL++
			c.notes = append(c.notes, fmt.Sprintf("%s (%s): decoded after setting L to the telegram's length [%s]", where, tc.driver, wmFixedL))
		}
		last = tg
		if reading == nil {
			// The records decoded (a tail error keeps those before it).
			reading, _ = meters.ReadKeys(tg, nil, aesKey)
		}
		lastReading = reading
	}
	if last == nil || tc.json == nil {
		return
	}
	tg := last
	wmCompareReading(c, tc, lastReading)
	if os.Getenv("SIGMA_MBUS_INTEROP_MVT") != "" && lastReading != nil {
		c.notes = append(c.notes, fmt.Sprintf("MVT %s %s,%02X,%02X", tc.driver, lastReading.Manufacturer, lastReading.Version, lastReading.SentDeviceType))
	}
	if id, _ := tc.json["id"].(string); id != "" {
		switch {
		case strings.EqualFold(id, tg.Meter.ID) || strings.EqualFold(id, tg.ID) || lastReading != nil && strings.EqualFold(id, lastReading.ID):
			c.idEq++
		case hasEnhancedID(tg.Records, id):
			c.idOther++
			c.notes = append(c.notes, fmt.Sprintf("%s (%s): id %s is in an enhanced identification record; link id %s [%s]", tc.where, tc.driver, id, tg.ID, wmEnhancedID))
			return
		default:
			c.idDiff++
			c.unexplained = append(c.unexplained, fmt.Sprintf("%s (%s): id %s (link %s), wmbusmeters %s", tc.where, tc.driver, tg.Meter.ID, tg.ID, id))
		}
	}
	if lastReading != nil && lastReading.Driver != "" {
		// The driver gives the device type and address as the maker means them.
		wmCompareMedium(c, tc, []byte{lastReading.DeviceType})
		wmCompareMVT(c, tc, wireless.Header{Manufacturer: lastReading.Manufacturer, Version: lastReading.Version, DeviceType: lastReading.SentDeviceType}, tg.Meter, tg.Header)
		wmCompareFields(c, tc, lastReading.Records)
		return
	}
	wmCompareMedium(c, tc, []byte{tg.Meter.DeviceType, tg.DeviceType})
	wmCompareMVT(c, tc, tg.Meter, tg.Header)
	wmCompareFields(c, tc, tg.Records)
}

func hasEnhancedID(recs []records.Record, id string) bool {
	for _, r := range recs {
		if r.Quantity == "enhanced_id" && len(r.Raw) >= 4 && wireless.BCDID(r.Raw[:4]) == id {
			return true
		}
	}
	return false
}

// desPlain decrypts the DES bytes of a mode 2 short-header telegram
// (CRC-less) with a zero IV, for the log.
func desPlain(frame, key []byte, tg *wireless.Telegram) []byte {
	n := int(tg.Config & 0xFF)
	start := 10 + 5 // link header, CI and the short TPL header
	if tg.HeaderKind != "short" || start+n > len(frame) || n%8 != 0 {
		return nil
	}
	blk, err := des.NewCipher(key)
	if err != nil {
		return nil
	}
	out := make([]byte, n)
	cipher.NewCBCDecrypter(blk, make([]byte, 8)).CryptBlocks(out, frame[start:start+n])
	return out
}

func sized(k []byte, n int) []byte {
	if len(k) == n {
		return k
	}
	return nil
}

func isCompact(ci byte) bool {
	k, _ := wireless.FrameKind(ci)
	return k == wireless.KindCompact || k == wireless.KindFormat
}

func wmWired(c *wmTally, tc wmCase, b []byte) {
	f, err := wired.ReadFrame(bufio.NewReader(bytes.NewReader(b)))
	if err != nil {
		c.unexplained = append(c.unexplained, fmt.Sprintf("%s (%s): wired frame: %v", tc.where, tc.driver, err))
		return
	}
	r, err := wired.ParseResponse(f)
	if err != nil {
		c.unexplained = append(c.unexplained, fmt.Sprintf("%s (%s): wired response: %v", tc.where, tc.driver, err))
		return
	}
	c.decoded++
	if tc.json == nil {
		return
	}
	if id, _ := tc.json["id"].(string); id != "" {
		if id == r.Address.ID {
			c.idEq++
		} else {
			c.idDiff++
			c.unexplained = append(c.unexplained, fmt.Sprintf("%s (%s): wired id %s, wmbusmeters %s", tc.where, tc.driver, r.Address.ID, id))
		}
	}
	wmCompareMedium(c, tc, []byte{r.Address.Medium})
	wmCompareFields(c, tc, r.Records)
	wmCompareReading(c, tc, meters.ReadRecords(records.ManufacturerCode(r.Address.Manufacturer), r.Address.ID, r.Address.Version, r.Address.Medium, r.Records))
}

// suffixUnit is the factor from one of our units to the unit a
// wmbusmeters field name ends with.
func suffixUnit(ours, suffix string) (float64, bool) {
	if f, ok := toUnit(ours, suffix); ok {
		return f, true
	}
	f, ok := map[[2]string]float64{
		{"L", "m3"}: 1e-3, {"kWh", "kwh"}: 1, {"GJ", "gj"}: 1, {"kW", "kw"}: 1,
		{"a", "y"}: 1, {"s", "s"}: 1, {"min", "s"}: 60, {"h", "s"}: 3600, {"d", "s"}: 86400,
		{"d", "d"}: 1, {"a", "d"}: 365, {"d", "y"}: 1 / 365.2422, {"mo", "month"}: 1,
		{"V", "v"}: 1, {"A", "a"}: 1, {"Hz", "hz"}: 1, {"bar", "bar"}: 1, {"%RH", "rh"}: 1, {"%", "pct"}: 1,
		{"%", "rh"}: 1, {"", "counter"}: 1, {"", "nr"}: 1, {"", "factor"}: 1, {"kvarh", "kvarh"}: 1, {"kVAh", "kvah"}: 1,
		{"varh", "kvarh"}: 1e-3, {"VAh", "kvah"}: 1e-3, {"m3/h", "m3h"}: 1, {"L/h", "m3h"}: 1e-3,
		{"Cel", "c"}: 1, {"K", "c"}: 1, {"m3", "m3"}: 1, {"Wh", "kwh"}: 1e-3, {"W", "kw"}: 1e-3,
	}[[2]string{ours, suffix}]
	return f, ok
}

var dateLike = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?$`)

// wmCompareReading compares every numeric field and every date
// wmbusmeters prints with the values of our reading (records and driver):
// a field is found when a value of a matching unit equals it (dates by
// text, to the minute). Names are not compared: the two projects name
// values differently.
func wmCompareReading(c *wmTally, tc wmCase, rd *meters.Reading) {
	if rd == nil {
		return
	}
	names := make([]string, 0, len(tc.json))
	for k := range tc.json {
		names = append(names, k)
	}
	sort.Strings(names)
	var missing []string
	for _, name := range names {
		switch name {
		case "timestamp", "id", "name", "meter", "media", "_":
			continue
		}
		want := tc.json[name]
		if s, ok := want.(string); ok {
			if !dateLike.MatchString(s) {
				continue
			}
			if y, _ := strconv.Atoi(s[:4]); y >= 2100 || s[5:7] > "12" {
				// wmbusmeters prints a date coded invalid (all ones) as a
				// date; our records mark it invalid.
				c.invalidDates++
				continue
			}
			c.allFields++
			found := false
			for _, v := range rd.Values {
				if o, ok := v.Value.(string); ok && dateLike.MatchString(o) && sameDate(o, s) {
					found = true
					break
				}
			}
			if found {
				c.allEq++
			} else {
				missing = append(missing, fmt.Sprintf("%s=%s", name, s))
			}
			continue
		}
		w, ok := number(want)
		if !ok {
			continue
		}
		i := strings.LastIndex(name, "_")
		if i < 0 {
			continue
		}
		suffix := name[i+1:]
		c.allFields++
		found := false
		for _, v := range rd.Values {
			x, ok := number(v.Value)
			if !ok {
				continue
			}
			f, ok := suffixUnit(v.Unit, suffix)
			if ok && nearRel(x*f, w) {
				found = true
				break
			}
		}
		if found {
			c.allEq++
		} else {
			missing = append(missing, fmt.Sprintf("%s=%v", name, w))
		}
	}
	c.allMissing += len(missing)
	if len(missing) > 0 {
		c.missing[rd.Driver+"/"+tc.driver] += len(missing)
		c.notes = append(c.notes, fmt.Sprintf("%s (%s, our driver %q): not among our values: %s", tc.where, tc.driver, rd.Driver, strings.Join(missing, ", ")))
	}
}

// sameDate compares two date texts to the minute.
func sameDate(a, b string) bool {
	n := func(s string) string {
		s = strings.Replace(s, " ", "T", 1)
		if len(s) > 16 {
			s = s[:16]
		}
		return s
	}
	return n(a) == n(b)
}

func wmCompareMedium(c *wmTally, tc wmCase, ours []byte) {
	m, _ := tc.json["media"].(string)
	codes, ok := wmMedium[m]
	if !ok {
		c.mediumSkipped++
		return
	}
	for _, o := range ours {
		for _, w := range codes {
			if o == w {
				c.mediumEq++
				return
			}
		}
	}
	c.mediumDiff++
	c.unexplained = append(c.unexplained, fmt.Sprintf("%s (%s): device type %02X, wmbusmeters media %q", tc.where, tc.driver, ours, m))
}

func wmCompareFields(c *wmTally, tc wmCase, recs []records.Record) {
	names := make([]string, 0, len(tc.json))
	for k := range tc.json {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		want, ok := number(tc.json[name])
		if !ok {
			continue
		}
		fm, ok := wmFields[name]
		if !ok {
			if m := tariffField.FindStringSubmatch(name); m != nil {
				n, _ := strconv.Atoi(m[1])
				fm, ok = wmField{"energy", n, "kwh"}, true
			}
		}
		if !ok {
			continue
		}
		c.fields++
		var cands []string
		matched := false
		for _, r := range recs {
			if r.Quantity != fm.quantity || r.Storage != 0 || r.Tariff != fm.tariff || r.Subunit != 0 ||
				r.Function != "instantaneous" || len(r.Modifier) > 0 || r.Manufacturer || r.Invalid {
				continue
			}
			v, ok := number(r.Value)
			f, fok := toUnit(r.Unit, fm.unit)
			if !ok || !fok {
				cands = append(cands, fmt.Sprintf("%s=%v %s", r.Name(), r.Value, r.Unit))
				continue
			}
			cands = append(cands, fmt.Sprintf("%s=%v %s", r.Name(), r.Value, r.Unit))
			if nearRel(v*f, want) {
				matched = true
				break
			}
		}
		switch {
		case matched:
			c.fieldEq++
		case len(cands) == 0:
			c.fieldNoMatch++
			// Say what the telegram does have of that quantity, and
			// whether one of those records holds the value.
			var other []string
			same := false
			for _, r := range recs {
				if r.Quantity != fm.quantity {
					continue
				}
				s := fmt.Sprintf("%s=%v %s", r.Name(), r.Value, r.Unit)
				v, ok := number(r.Value)
				f, fok := toUnit(r.Unit, fm.unit)
				if ok && fok && nearRel(v*f, want) {
					s += " (same value)"
					same = true
				}
				other = append(other, s)
			}
			if same {
				c.fieldElsewhere++
			}
			c.notes = append(c.notes, fmt.Sprintf("%s (%s): %s=%v: no plain %s record at storage 0; the telegram has %v", tc.where, tc.driver, name, want, fm.quantity, other))
		default:
			c.fieldDiff++
			msg := fmt.Sprintf("%s (%s): %s=%v, ours %s", tc.where, tc.driver, name, want, strings.Join(cands, ", "))
			cat := ""
			switch {
			case c.drivers.proprietary[tc.driver]:
				cat = wmProprietary
			case strings.HasPrefix(tc.where, "simulation_metershell.txt") && name == "total_m3" && want == 6.548:
				cat = wmUnchecked
			}
			if cat == "" {
				c.unexplained = append(c.unexplained, msg)
			} else {
				c.fieldExplained++
				c.notes = append(c.notes, msg+" ["+cat+"]")
			}
		}
	}
}

// diehlKeysFrom reads the Diehl group's two default keys from
// wmbusmeters' src/manufacturer_specificities.cc ("#define
// PRIOS_DEFAULT_KEY1 ..."): both seed the scrambling, the second doubled
// is the default AES key, as wmbusmeters uses them.
func diehlKeysFrom(root string) (meters.MakerKeys, error) {
	b, err := os.ReadFile(filepath.Join(root, "src", "manufacturer_specificities.cc"))
	if err != nil {
		return meters.MakerKeys{}, err
	}
	re := regexp.MustCompile(`#define PRIOS_DEFAULT_KEY([12])\s+"([0-9A-Fa-f]{16})"`)
	var k meters.MakerKeys
	found := map[string][]byte{}
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		v, err := hex.DecodeString(m[2])
		if err != nil {
			return k, err
		}
		found[m[1]] = v
	}
	if found["1"] == nil || found["2"] == nil {
		return k, errors.New("PRIOS_DEFAULT_KEY1 and KEY2 not defined")
	}
	k.DiehlScrambling = [][]byte{found["1"], found["2"]}
	k.DiehlAES = append(append([]byte(nil), found["2"]...), found["2"]...)
	return k, nil
}

// formatsByMVT gives the compact-frame formats of the wmbusmeters driver
// whose detect list holds the meter's manufacturer, version and type.
func formatsByMVT(c *wmTally, tg *wireless.Telegram) [][]byte {
	s := fmt.Sprintf("%s,%02X,%02X", tg.Meter.Manufacturer, tg.Meter.Version, tg.Meter.DeviceType)
	names := make([]string, 0, len(c.drivers.mvt))
	for n := range c.drivers.mvt {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if slices.Contains(c.drivers.mvt[n], s) && len(c.drivers.formats[n]) > 0 {
			return c.drivers.formats[n]
		}
	}
	return nil
}
