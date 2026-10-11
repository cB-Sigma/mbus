package records

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

// parse decodes hex records, failing the test on an error.
func parse(t *testing.T, s string) []Record {
	t.Helper()
	rs, err := ParseRecords(hx(t, s))
	if err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return rs
}

// one decodes a single record.
func one(t *testing.T, s string) Record {
	t.Helper()
	rs := parse(t, s)
	if len(rs) != 1 {
		t.Fatalf("%s: %d records", s, len(rs))
	}
	return rs[0]
}

type recWant struct {
	in   string
	name string
	unit string
	v    any
}

func checkRecs(t *testing.T, cases []recWant) {
	t.Helper()
	for _, c := range cases {
		r := one(t, c.in)
		if r.Name() != c.name || r.Unit != c.unit || !reflect.DeepEqual(r.Value, c.v) {
			t.Errorf("%s: %s %q %v (%T), want %s %q %v (%T)", c.in, r.Name(), r.Unit, r.Value, r.Value, c.name, c.unit, c.v, c.v)
		}
	}
}

// Covers: SIG-IPE-940
func TestRecordsDIB(t *testing.T) {
	// 6.3.2, 6.3.4: function field and the storage LSB.
	checkRecs(t, []recWant{
		{"01 13 05", "volume", "m3", 0.005},
		{"11 13 05", "volume_max", "m3", 0.005},
		{"21 13 05", "volume_min", "m3", 0.005},
		{"31 13 05", "volume_err", "m3", 0.005},
		{"41 13 05", "volume_s1", "m3", 0.005},
		// 6.3.7: DIFE bits 0-3 storage, 4-5 tariff, 6 subunit, concatenated.
		{"81 7F 13 05", "volume_s30_t3_u1", "m3", 0.005},
		{"C1 80 01 13 05", "volume_s33", "m3", 0.005},
		{"81 A0 20 13 05", "volume_t10", "m3", 0.005},
		// 6.3.5: a final DIFE 00h makes the storage number a register
		// number (annex F, table F.10 record).
		{"84 90 81 00 03 F0490200", "energy_r32_t1", "Wh", int64(150000)},
	})
	// Up to 10 DIFEs (6.3.7); an 11th is an error.
	if r := one(t, "81"+strings.Repeat("80", 9)+"01 13 05"); len(r.DIFE) != 10 || r.Storage != 1<<(1+4*9) {
		t.Errorf("10 DIFEs: %d storage %d", len(r.DIFE), r.Storage)
	}
	if _, err := ParseRecords(hx(t, "81"+strings.Repeat("80", 10)+"01 13 05")); err == nil {
		t.Error("11 DIFEs accepted")
	}
	// Table 6: special functions.
	rs := parse(t, "2F 2F 01 13 05 7F 2F 1F 0102")
	if len(rs) != 2 || rs[1].Quantity != "manufacturer_data" || rs[1].Value != "0102" || !rs[1].Manufacturer || !MoreRecords(rs) {
		t.Errorf("specials: %+v", rs)
	}
	if rs := parse(t, "01 13 05 0F AB"); MoreRecords(rs) || rs[1].Value != "AB" {
		t.Errorf("DIF 0F: %+v", rs)
	}
	for _, d := range []string{"3F", "4F", "5F", "6F", "8F", "CF"} {
		if _, err := ParseRecords(hx(t, d+"13 05")); err == nil {
			t.Errorf("reserved DIF %s accepted", d)
		}
	}
}

// Covers: SIG-IPE-941
func TestRecordsDataTypes(t *testing.T) {
	checkRecs(t, []recWant{
		// Table 4 lengths, type B (signed) by default.
		{"01 03 FE", "energy", "Wh", int64(-2)},
		{"03 03 FEFFFF", "energy", "Wh", int64(-2)},
		{"06 03 FEFFFFFFFFFF", "energy", "Wh", int64(-2)},
		{"07 03 FEFFFFFFFFFFFFFF", "energy", "Wh", int64(-2)},
		{"0E 03 785634120000", "energy", "Wh", int64(12345678)},
		{"09 03 42", "energy", "Wh", int64(42)},
		// Annex B: F in the most significant digit is a minus sign.
		{"0A 13 21F3", "volume", "m3", -0.321},
		// Type C where a VIFE declares it (table 17 11h).
		{"01 83 FC 11 FE", "energy", "Wh", int64(254)},
		// Table 5: LVAR binary, positive and negative BCD, text.
		{"0D 13 E2 3412", "volume", "m3", 4.66},
		{"0D 13 C2 3412", "volume", "m3", 1.234},
		{"0D 13 D2 3412", "volume", "m3", -1.234},
		{"0D 13 C0", "volume", "m3", 0.0},
		{"0D FD0C 03 434241", "model_version", "", "ABC"},
	})
	// Invalid codings (annex A, B): the value becomes the hex digits.
	for _, c := range []struct{ in, v string }{
		{"02 13 0080", "8000"},         // type B minimum
		{"01 FD 08 FF", "FF"},          // type C all ones
		{"05 13 0000C07F", "7FC00000"}, // type H NaN
		{"0A 13 2A03", "032A"},         // BCD digit A
		{"0A 13 F103", "03F1"},         // F not in the top digit
		{"0D 13 C2 3F12", "123F"},      // LVAR BCD
		{"07 13 0000000000000080", "8000000000000000"},
	} {
		r := one(t, c.in)
		if !r.Invalid || r.Value != c.v {
			t.Errorf("%s: invalid %v value %v", c.in, r.Invalid, r.Value)
		}
	}
	// LVAR F0h-F4h (16 to 32 bytes), F5h (48), F6h (64); other values
	// are reserved.
	for l, n := range map[string]int{"F0": 16, "F4": 32, "F5": 48, "F6": 64, "EF": 15} {
		r := one(t, "0D FD0B "+l+strings.Repeat("11", n))
		if len(r.Raw) != n || r.Value != strings.Repeat("11", n) {
			t.Errorf("LVAR %s: %d bytes %v", l, len(r.Raw), r.Value)
		}
	}
	for _, l := range []string{"CA", "CF", "DA", "DF", "F7", "FF"} {
		if _, err := ParseRecords(hx(t, "0D 13 "+l+"00000000")); err == nil {
			t.Errorf("reserved LVAR %s accepted", l)
		}
	}
	// Containers carry bytes in wire order (table 12 footnote f).
	if r := one(t, "0D FD 3B 03 7A0102"); r.Quantity != "wmbus_container" || r.Value != "7A0102" {
		t.Errorf("container %s %v", r.Quantity, r.Value)
	}
}

// Covers: SIG-IPE-942
func TestRecordsDateTimeTypes(t *testing.T) {
	checkRecs(t, []recWant{
		// Type G, with wildcards ("every month", "every day").
		{"02 6C 7F2C", "date", "", "2019-12-31"},
		{"02 6C 602F", "date", "", "2019-**-**"},
		// Type F with the hundred-year bits, and a year above 80.
		{"04 6D 1E2CAF06", "datetime", "", "2005-06-15T12:30:00"},
		{"04 6D 1E0CEFB6", "datetime", "", "1995-06-15T12:30:00"},
		// Type I (annex F, table F.10 record).
		{"06 6D 0B0C8D59130C", "datetime", "", "2010-03-25T13:12:11"},
		// Type J.
		{"03 6D 030201", "time", "", "01:02:03"},
		// Type M, annex A examples 1 and 2.
		{"0D 6D E5 0B60010021", "datetime", "", "2013-01-02T02:02:03+01:00"},
		{"0D 6D E3 80DD50", "datetime", "s", -34.5},
		// A VIFE "start date of" makes the value a date.
		{"02 93 39 7F2C", "volume_start", "", "2019-12-31"},
		{"04 FD 70 1E2CAF06", "battery_change", "", "2005-06-15T12:30:00"},
	})
	for _, in := range []string{
		"02 6C FFFF",         // type G
		"04 6D 9E0CEFB6",     // type F invalid bit
		"06 6D 0B8C8D59130C", // type I invalid bit
		"03 6D FFFFFF",       // type J
		"02 6D 7F2C",         // VIF 6Dh with a 16-bit field (table 10 footnote b)
		"0D 6D E3 008050",    // type M invalid duration
	} {
		if r := one(t, in); !r.Invalid {
			t.Errorf("%s: %v not invalid", in, r.Value)
		}
	}
	// Type K.
	r := one(t, "04 FD 72 2299BCA3")
	want := map[string]any{"enabled": true, "utc_offset_h": 1, "begin_hour": 2, "begin_day": 25,
		"begin_month": 3, "end_day": 28, "end_month": 10, "deviation_h": 1}
	if r.Name() != "daylight_savings" || !reflect.DeepEqual(r.Value, want) {
		t.Errorf("type K %s %v", r.Name(), r.Value)
	}
	// Type L, the two examples after table A.11.
	for in, w := range map[string]map[string]any{
		"0D FD 73 EB 0400000000 00C030 000000": {"weeks": []int{3}, "days": []string{"mon", "tue"}, "hours": []int{0, 1}, "quarters": []int{}},
		"0D FD 73 EB 0400000000 00C050 000030": {"weeks": []int{3}, "days": []string{"mon", "tue"}, "hours": []int{0, 2}, "quarters": []int{1, 2}},
	} {
		if r := one(t, in); !reflect.DeepEqual(r.Value, w) {
			t.Errorf("type L %v, want %v", r.Value, w)
		}
	}
}

// Covers: SIG-IPE-943
func TestRecordsPrimaryVIF(t *testing.T) {
	// Table 10, one code per range; data 1 (int8) shows the multiplier.
	checkRecs(t, []recWant{
		{"01 00 01", "energy", "Wh", 0.001},
		{"01 07 01", "energy", "Wh", 10000.0},
		{"01 08 01", "energy", "J", int64(1)},
		{"01 0F 01", "energy", "J", 10000000.0},
		{"01 10 01", "volume", "m3", 1e-6},
		{"01 18 01", "mass", "kg", 0.001},
		{"01 20 01", "on_time", "s", int64(1)},
		{"01 23 01", "on_time", "d", int64(1)},
		{"01 26 01", "operating_time", "h", int64(1)},
		{"01 2B 01", "power", "W", int64(1)},
		{"01 30 01", "power", "J/h", int64(1)},
		{"01 3E 01", "volume_flow", "m3/h", int64(1)},
		{"01 40 01", "volume_flow", "m3/min", 1e-7},
		{"01 48 01", "volume_flow", "m3/s", 1e-9},
		{"01 50 01", "mass_flow", "kg/h", 0.001},
		{"01 5B 01", "flow_temperature", "Cel", int64(1)},
		{"01 5C 01", "return_temperature", "Cel", 0.001},
		{"01 61 01", "temperature_difference", "K", 0.01},
		{"01 66 01", "external_temperature", "Cel", 0.1},
		{"01 68 01", "pressure", "bar", 0.001},
		{"01 6E 01", "hca_units", "", int64(1)},
		{"01 70 01", "averaging_duration", "s", int64(1)},
		{"01 77 01", "actuality_duration", "d", int64(1)},
		// A binary fabrication number (DIF 04) is its decimal number (12345678h), as a BCD one (DIF 0C) is its digits.
		{"04 78 78563412", "fabrication_number", "", "305419896"},
		{"0C 78 78563412", "fabrication_number", "", "12345678"},
		{"01 7A 05", "bus_address", "", int64(5)},
		{"06 7A 785634123301", "bus_address", "", "013312345678"},
		// Special VIFs (table 11): any VIF, manufacturer VIF whose VIFEs
		// are not interpreted.
		{"00 7E", "any", "", nil},
		{"02 FF 93 20 3412", "manufacturer_specific", "", "1234"},
		// Annex C.2 example: plain-text unit with combinable VIFEs first.
		// Its ASCII bytes spell "igal" (lower case).
		{"0C FC A2 73 04 6C616769 26084275", "text_igal_per_hour", "igal/h", 75420.826},
		// The text before the VIFEs, as an Elvaco CMa10 sends it ("%RH",
		// VIFE 74h: 10^-2), read when the standard order does not fit.
		{"02 FC 03 48 52 25 74 2215", "text__rh", "%RH", 54.1},
	})
	// Every primary code decodes (6Fh is reserved: a raw number).
	for c := 0; c <= 0x7A; c++ {
		r := one(t, "01"+hexByte(byte(c))+"01")
		if r.Quantity == "" || r.Value == nil && c != 0x6C && c != 0x6D {
			t.Errorf("VIF %02X: %+v", c, r)
		}
	}
	if r := one(t, "01 6F 01"); r.Quantity != "vif_6f" {
		t.Errorf("6F: %s", r.Quantity)
	}
}

func hexByte(b byte) string {
	return strings.ToUpper(string("0123456789ABCDEF"[b>>4]) + string("0123456789ABCDEF"[b&15]))
}

// Covers: SIG-IPE-944
func TestRecordsExtensionTables(t *testing.T) {
	checkRecs(t, []recWant{
		// Table 12 (VIF FDh).
		{"01 FD 02 05", "credit", "", 0.5},
		{"04 FD 08 03000000", "access_number", "", int64(3)},
		{"01 FD 09 87", "medium", "", int64(0x87)},
		{"01 FD 1C 05", "baud_rate", "Bd", int64(5)},
		{"01 FD 26 0F", "storage_interval", "h", int64(15)},
		{"01 FD 28 01", "storage_interval", "mo", int64(1)},
		{"01 FD 2D 05", "duration_since_readout", "min", int64(5)},
		{"01 FD 3A 05", "dimensionless", "", int64(5)},
		{"01 FD 3F 05", "transmission_period", "d", int64(5)},
		{"02 FD 48 E600", "voltage", "V", 23.0},
		{"02 FD 59 E803", "current", "A", 1.0},
		{"01 FD 6A 02", "duration_since_cumulation", "mo", int64(2)},
		{"01 FD 6F 02", "battery_operating_time", "a", int64(2)},
		{"01 FD 71 B0", "rf_level", "dBm", int64(-80)},
		{"21 FD 71 B0", "rf_level_min", "dBm", int64(-80)},
		{"02 FD 74 6E01", "battery_remaining", "d", int64(366)},
		{"01 FD 75 03", "meter_stop_count", "", int64(3)},
		// Table 13 (VIF FDh, VIFE FDh).
		{"02 FD FD 03 0A00", "battery_remaining", "a", int64(10)},
		{"02 FD FD 11 0A00", "co2", "[ppm]", 100.0},
		{"02 FD FD 19 0A00", "pm2_5", "ug/m3", int64(10)},
		{"02 FD FD 1B 0200", "particle_count", "/m3", 200000.0},
		{"02 FD FD 25 0A00", "turbidity", "FNU", 0.1},
		{"01 FD FD 27 46", "ph", "[pH]", 7.0},
		{"01 FD FD 38 50", "battery_status", "%", int64(80)},
		{"01 FD FD 3B 03", "distance", "mm", 30.0},
		// Table 15 (VIF FBh).
		{"01 FB 00 05", "energy", "MWh", 0.5},
		{"01 FB 03 05", "reactive_energy", "kvarh", 50.0},
		{"01 FB 06 23", "cop", "", 3.5},
		{"01 FB 0C 05", "energy", "Mcal", 0.5},
		{"01 FB 11 05", "volume", "m3", 5000.0},
		{"01 FB 16 05", "reactive_power", "kvar", 0.5},
		{"01 FB 19 05", "mass", "t", 5000.0},
		{"01 FB 21 05", "volume", "[ft_i]3", 0.5},
		{"02 FB 23 0807", "phase_i_u", "deg", 180.0},
		{"02 FB 2E F401", "frequency", "Hz", 50.0},
		{"01 FB 37 05", "apparent_power", "kVA", int64(5)},
		{"02 FB 68 0010", "rating_factor_k", "/h", 1.0},
		{"02 FB 6E 0008", "rating_factor_kd", "/kWh", 0.5},
		{"01 FB 75 05", "temperature_limit", "Cel", 0.05},
		{"01 FB 7B 05", "cum_max_active_power", "W", int64(5)},
		{"01 FB 3F 05", "vif_fb3f", "", int64(5)},
	})
	// Every code of the three tables decodes.
	for c := 0; c < 0x80; c++ {
		for _, pre := range []string{"FB", "FDFD"} {
			if r := one(t, "01"+pre+hexByte(byte(c))+"01"); r.Quantity == "" {
				t.Errorf("%s %02X: no quantity", pre, c)
			}
		}
		if c == 0x7D || c == 0x72 || c == 0x73 || c == 0x3B || c == 0x76 || c == 0x77 {
			continue
		}
		if r := one(t, "01 FD"+hexByte(byte(c))+"01"); r.Quantity == "" || r.Value == nil {
			t.Errorf("FD %02X: %+v", c, r)
		}
	}
	for _, b := range []string{"01FB", "01FD", "01FDFD", "01FD7D01"} {
		if _, err := ParseRecords(hx(t, b)); err == nil {
			t.Errorf("%s: truncated extension accepted", b)
		}
	}
}

// Covers: SIG-IPE-945
func TestRecordsCombinableVIFE(t *testing.T) {
	checkRecs(t, []recWant{
		{"02 93 22 0A00", "volume_per_hour", "m3/h", 0.01},
		{"02 93 2C 0A00", "volume_per_litre", "m3/L", 0.01},
		{"02 93 36 0A00", "volume_times_s", "m3.s", 0.01},
		{"02 93 3A 0A00", "volume_uncorrected", "m3", 0.01},
		{"02 93 3C 0A00", "volume_backward", "m3", 0.01},
		{"02 93 3E 0A00", "volume_base_conditions", "m3", 0.01},
		{"02 93 48 0A00", "volume_upper_limit", "m3", 0.01},
		{"02 93 49 0A00", "volume_upper_limit_exceeds", "", int64(10)},
		{"02 93 4B 7F2C", "volume_first_upper_exceed_end", "", "2019-12-31"},
		{"02 93 52 0500", "volume_duration_first_lower_exceed", "h", int64(5)},
		{"02 93 65 0500", "volume_duration_last", "min", int64(5)},
		{"02 93 6C 0A00", "volume_during_upper_exceed", "m3", 0.01},
		{"02 93 69 0A00", "volume_leakage", "m3", 0.01},
		{"02 93 6F 7F2C", "volume_last_end", "", "2019-12-31"},
		{"02 93 74 0A00", "volume", "m3", 1e-4},         // ×10^(4-6)
		{"02 93 7A 0A00", "volume_offset", "m3", 0.001}, // additive 10^(2-3)
		{"02 93 7D 0A00", "volume", "m3", int64(10)},
		{"02 93 12 0A00", "volume_average", "m3", 0.01},
		{"02 93 14 0A00", "volume_relative_deviation", "m3", 0.01},
		{"02 93 7E 0A00", "volume_future", "m3", 0.01},
		// Manufacturer VIFE: the rest is the manufacturer's.
		{"02 93 FF 20 3412", "volume_mfct", "m3", "1234"},
		// Table 17 after FCh.
		{"04 FD C9 FC 01 E6000000", "voltage_l1", "V", int64(230)},
		{"04 FD C9 FC 25 E6000000", "voltage_l1_l2", "V", int64(230)},
		{"04 83 FC 0A 01000000", "energy_q3", "Wh", int64(1)},
		{"04 83 FC 13 1E2CAF06", "energy_end", "", "2005-06-15T12:30:00"},
		{"02 FB 9A FC 18 2C01", "relative_humidity_outdoors", "%RH", 30.0},
		// Annex C: non-metric units (tables C.1, C.2).
		{"04 93 3D 64000000", "volume", "[gal_us]", int64(100)},
		{"04 93 FC 0D 64000000", "volume", "[gal_br]", int64(100)},
		{"04 BB 3D 64000000", "volume_flow", "[gal_us]/h", int64(100)},
		{"04 83 3D 0A000000", "energy", "[Btu_IT]", 10000.0},
		{"04 AE 3D 0A000000", "power", "[Btu_IT]/s", int64(10)},
		{"02 DA 3D E803", "flow_temperature", "[degF]", 100.0},
		{"02 FB F5 3D E803", "temperature_limit", "[degF]", 10.0},
	})
	// Up to 10 VIFEs (6.4.1).
	if r := one(t, "01 93"+strings.Repeat("A2", 9)+"22 05"); len(r.VIFE) != 10 {
		t.Errorf("10 VIFEs: %d", len(r.VIFE))
	}
	for _, b := range []string{"01 93" + strings.Repeat("A2", 10) + "22 05", "01 FD" + strings.Repeat("C9", 10) + "49 05", "01 93 FC", "01 93 7C 05"} {
		if _, err := ParseRecords(hx(t, b)); err == nil {
			t.Errorf("%s accepted", b)
		}
	}
	// Every combinable code parses.
	for c := 0; c < 0x80; c++ {
		in := "02 93" + hexByte(byte(c)) + "0A00"
		if c == 0x7C {
			in = "02 93 FC 01 0A00"
		}
		if _, err := ParseRecords(hx(t, in)); err != nil {
			t.Errorf("VIFE %02X: %v", c, err)
		}
		if _, err := ParseRecords(hx(t, "02 93 FC"+hexByte(byte(c))+"0A00")); err != nil {
			t.Errorf("VIFE FC %02X: %v", c, err)
		}
	}
}

// Covers: SIG-IPE-946
func TestRecordsErrorsAndActions(t *testing.T) {
	// 6.4.8, table 19: record errors, kept on the record; the name is
	// unchanged.
	for code, want := range map[string]string{"00": "", "01": "too_many_difes", "0B": "too_many_vifes",
		"0E": "vif_dif_mismatch", "15": "no_data", "16": "data_overflow", "17": "data_underflow",
		"18": "data_error", "1C": "premature_end", "08": "reserved_08"} {
		r := one(t, "00 93"+code)
		if r.RecordError != want || r.Name() != "volume" {
			t.Errorf("error %s: %q %s", code, r.RecordError, r.Name())
		}
	}
	// With data and more VIFEs after the error code.
	if r := one(t, "02 93 96 22 0A00"); r.RecordError != "data_overflow" || r.Name() != "volume_per_hour" {
		t.Errorf("%+v", r)
	}
	// 6.4.7, table 18: object actions in the master-to-slave direction.
	for code, want := range map[string]string{"": "set", "00": "set", "01": "add", "02": "subtract",
		"07": "clear", "0B": "freeze", "0F": "get"} {
		vif := "13"
		if code != "" {
			vif = "93" + code
		}
		if r := one(t, "04"+vif+"01000000"); r.Action() != want {
			t.Errorf("action %s: %s", code, r.Action())
		}
	}
}

// Covers: SIG-IPE-947
func TestRecordsSensorsAndSpecialSequences(t *testing.T) {
	// 6.5.2.2 example: a list of sub device types and the sensor values.
	rs := parse(t, "03 FD FD 01 03010E  02 66 4D01  01 FB 1B 4B  02 FD FD 10 E703")
	m := recordMap(rs)
	if r := m["sub_device_type"]; r.Value != "temperature,humidity,co2" || !reflect.DeepEqual(r.Flags, []string{"temperature", "humidity", "co2"}) {
		t.Errorf("sub devices %v %v", r.Value, r.Flags)
	}
	for name, w := range map[string][2]any{"external_temperature": {33.3, "Cel"}, "relative_humidity": {int64(75), "%RH"}, "co2": {int64(999), "[ppm]"}} {
		if r := m[name]; r.Value != w[0] || r.Unit != w[1] {
			t.Errorf("%s = %v %s", name, r.Value, r.Unit)
		}
	}
	// 6.5.2.3 example: sub device types per subunit.
	m = recordMap(parse(t, "01 FD FD 01 03  02 66 4D01  81 40 FD FD 01 01  81 40 FB 1B 4B  81 80 40 FD FD 01 0E  82 80 40 FD FD 10 E703"))
	for name, v := range map[string]any{"sub_device_type": "temperature", "external_temperature": 33.3,
		"sub_device_type_u1": "humidity", "relative_humidity_u1": int64(75), "sub_device_type_u2": "co2", "co2_u2": int64(999)} {
		if m[name].Value != v {
			t.Errorf("%s = %v, want %v (have %v)", name, m[name].Value, v, keysOf(m))
		}
	}
	// 6.5.4 example: approval class "A2".
	if r := one(t, "0D FD FD 3F 02 3241"); r.Name() != "approval_class" || r.Value != "A2" {
		t.Errorf("approval %s %v", r.Name(), r.Value)
	}
	// Tables 21-25: status bits; table 14: installation conditions.
	for in, w := range map[string][]string{
		"01 FD FD 40 25":   {"high_pressure", "battery_low", "mechanical_tamper"},
		"02 FD FD 41 0208": {"battery_low", "smoke_alarm"},
		"02 FD FD 42 C102": {"dismounted", "co_alarm", "co_level_300ppm"},
		"02 FD FD 43 8800": {"storage_state", "heat_alarm"},
		"01 FD FD 44 05":   {"open", "unlocked"},
		"01 FD FD 44 0E":   {"contact_unknown"},
		"01 FD FD 08 4D":   {"volume_display_k", "energy_display_m", "flow_pipe"},
	} {
		if r := one(t, in); !reflect.DeepEqual(r.Flags, w) {
			t.Errorf("%s: %v, want %v", in, r.Flags, w)
		}
	}
	// Annex C.3 example: close a valve with sequence counter 3.
	rs = parse(t, "04 FD 08 03000000 01 FD 1F 00")
	if rs[0].Value != int64(3) || rs[1].Name() != "remote_control" || !reflect.DeepEqual(rs[1].Flags, []string{"valve_closed"}) {
		t.Errorf("C.3: %+v", rs)
	}
	// Annex E.1: error flags FDh 97h 1Dh, three standardized bytes.
	r := one(t, "03 FD 97 1D 83 84 11")
	if r.Name() != "error_flags" || r.Value != "118483" || !reflect.DeepEqual(r.Flags,
		[]string{"mechanical_tamper", "battery_low", "leakage", "hist_mechanical_tamper", "hist_leakage"}) {
		t.Errorf("E.1: %s %v %v", r.Name(), r.Value, r.Flags)
	}
	// Without the standard-conform VIFE the bits are device specific.
	if r := one(t, "01 FD 17 03"); r.Flags != nil || r.Value != "03" {
		t.Errorf("error flags: %v", r.Flags)
	}
	// Annex E.2: remote control FDh 9Fh 1Dh.
	for in, w := range map[string][]string{
		"01 FD 9F 1D 43": {"power_increase", "normal_mode"},
		"01 FD 9F 1D 28": {"test_reception", "power_save_mode"},
		"01 FD 9F 1D 51": {"power_decrease", "test_emit_0101", "normal_mode"},
	} {
		if r := one(t, in); !reflect.DeepEqual(r.Flags, w) {
			t.Errorf("%s: %v, want %v", in, r.Flags, w)
		}
	}
}

// Covers: SIG-IPE-941
func FuzzParseRecords(f *testing.F) {
	for _, s := range []string{"0C FC A2 73 04 6C616769 26084275", "0D 6D E5 0B60010021", "04 FD 72 2299BCA3",
		"0D FD 73 EB 0400000000 00C030 000000", "03 FD 97 1D 83 84 11", "84 90 81 00 03 F0490200",
		"02 93 FC 13 7F2C", "03 FD FD 01 03010E", "0D 13 F5" + strings.Repeat("00", 48)} {
		b, _ := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		rs, _ := ParseRecords(b)
		for _, r := range rs {
			_ = r.Name()
			_ = r.Action()
		}
	})
}

// A record's invalid coding and record error become the reading quality
// the IPEs write.
//
// Covers: SIG-IPE-946
func TestRecordQuality(t *testing.T) {
	recs, err := ParseRecords([]byte{0x0A, 0x13, 0xAB, 0x12}) // 4-digit BCD with hex digits
	if err != nil || len(recs) != 1 || !recs[0].Invalid || recs[0].Quality() != "invalid" {
		t.Fatalf("recs = %+v %v", recs, err)
	}
	if q := (Record{Invalid: true, RecordError: "data_overflow"}).Quality(); q != "invalid,data_overflow" {
		t.Errorf("quality = %q", q)
	}
	if q := (Record{}).Quality(); q != "" {
		t.Errorf("a normal record has quality %q", q)
	}
}
