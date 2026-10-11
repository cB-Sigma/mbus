package records

import (
	"testing"
	"time"
)

// Test vectors: EN 13757-3:2025 Annex F examples (Tables F.2, F.10, F.12,
// F.14), expected values from their plain-data tables (F.1, F.9, F.11,
// F.13).

func profileMap(t *testing.T, h string) map[string]any {
	t.Helper()
	rs, err := ParseRecords(hx(t, h))
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	for _, r := range rs {
		if _, dup := m[r.Name()]; dup {
			t.Errorf("two records named %s", r.Name())
		}
		m[r.Name()] = r.Value
	}
	return m
}

func wantValues(t *testing.T, got map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v (%T), want %v", k, got[k], got[k], v)
		}
	}
}

// Covers: SIG-IPE-954
func TestProfileStandardLoadProfile(t *testing.T) {
	// Table F.2: count 5 and interval 1 month at storage 8, the date of
	// storage 12, volumes (litres) at storage 8 to 12.
	got := profileMap(t, "8904FD2205"+"8904FD2801"+"82066C1F15"+
		"8C041365000000"+"CC041309020000"+"8C051323040000"+"CC051355070000"+"8C061313100000")
	wantValues(t, got, map[string]any{
		"volume_s8": 0.065, "volume_s9": 0.209, "volume_s10": 0.423, "volume_s11": 0.755, "volume_s12": 1.013,
		// Table F.1: the end of each month
		"date_s12": "2008-05-31", "date_s11": "2008-04-30", "date_s10": "2008-03-31",
		"date_s9": "2008-02-29", "date_s8": "2008-01-31",
	})
}

// Covers: SIG-IPE-955
func TestProfileCompactWithRegisterNumbers(t *testing.T) {
	// Table F.10: absolute monthly energy (tariff 1) of an electricity
	// meter, registers 32 to 37, with a non-periodic value at 35.
	got := profileMap(t, "86808100 6D0000A0411135"+
		"84908100 03F0490200"+
		"8D908100 831E0A34FEA0860100D0FB0100"+
		"C6818100 6D0B0C8D59130C"+
		"C4918100 03905F0100"+
		"86828100 6D00008041140D"+
		"84928100 0350C30000"+
		"8D928100 831E0634FE00710200")
	// Table F.9, in Wh.
	wantValues(t, got, map[string]any{
		"energy_r32_t1": int64(150000), "energy_r33_t1": int64(100000), "energy_r34_t1": int64(130000),
		"energy_r35_t1": int64(90000), "energy_r36_t1": int64(50000), "energy_r37_t1": int64(160000),
		"datetime_r32": "2010-01-01T00:00:00", "datetime_r33": "2010-02-01T00:00:00",
		"datetime_r34": "2010-03-01T00:00:00", "datetime_r35": "2010-03-25T13:12:11",
		"datetime_r36": "2010-04-01T00:00:00", "datetime_r37": "2010-05-01T00:00:00",
	})
	if len(got) != 12 {
		t.Errorf("%d records: %v", len(got), got)
	}
}

// Covers: SIG-IPE-956
func TestProfileCompactAndInverse(t *testing.T) {
	// Table F.12: hourly volume increments (BCD) after the base value.
	got := profileMap(t, "8404 6D00204111"+"8B04 15003012"+"8D04 951F05690103 0211")
	wantValues(t, got, map[string]any{ // Table F.11
		"volume_s8": 12300.0, "volume_s8_p1": 12300.3, "volume_s8_p2": 12300.5, "volume_s8_p3": 12301.6,
		"datetime_s8": "2010-01-01T00:00:00", "datetime_s8_p1": "2010-01-01T01:00:00",
		"datetime_s8_p2": "2010-01-01T02:00:00", "datetime_s8_p3": "2010-01-01T03:00:00",
	})
	// Table F.14: the inverse profile walks back from the youngest value.
	got = profileMap(t, "8404 6D00234111"+"8B04 15163012"+"8D04 951305690111 0203")
	wantValues(t, got, map[string]any{ // Table F.13
		"volume_s8": 12301.6, "volume_s8_p1": 12300.5, "volume_s8_p2": 12300.3, "volume_s8_p3": 12300.0,
		"datetime_s8": "2010-01-01T03:00:00", "datetime_s8_p1": "2010-01-01T02:00:00",
		"datetime_s8_p2": "2010-01-01T01:00:00", "datetime_s8_p3": "2010-01-01T00:00:00",
	})

	// Decrements, signed differences, the invalid coding and a missing base
	// value (the first element is then the first value), 16-bit elements.
	got = profileMap(t, "8404 6D00204111"+ // base time
		"8D04 931F 08 A2 01 0500 FFFF 0300") // no base: 5, then decrements of FFFF (invalid) and 3
	wantValues(t, got, map[string]any{"volume_s8_p1": 0.005, "volume_s8_p2": nil, "volume_s8_p3": nil,
		"datetime_s8_p1": "2010-01-01T01:00:00"})
	got = profileMap(t, "8404 6D00204111"+"8404 1364000000"+
		"8D04 931F 08 E2 02 FEFF 0A00 0080") // signed: −2, +10, invalid (−32768)
	wantValues(t, got, map[string]any{"volume_s8": 0.1, "volume_s8_p1": 0.098, "volume_s8_p2": 0.108, "volume_s8_p3": nil,
		"datetime_s8_p1": "2010-01-01T02:00:00", "datetime_s8_p2": "2010-01-01T04:00:00"})
	// Spacing value 0: an array in column 2, no times.
	got = profileMap(t, "8404 6D00204111"+"8D04 931F 04 11 00 07 08")
	wantValues(t, got, map[string]any{"volume_s8_p1_c2": 0.007, "volume_s8_p2_c2": 0.008})
	if _, ok := got["datetime_s8_p1"]; ok {
		t.Error("an array got times")
	}
	// A profile that cannot be read (element size 0Dh) stays as it came.
	rs, _ := ParseRecords(hx(t, "8D04 931F 03 0D 01 00"))
	if len(rs) != 1 || rs[0].Raw == nil {
		t.Errorf("unreadable profile: %+v", rs)
	}
}

// Covers: SIG-IPE-956
func TestProfileSpacing(t *testing.T) {
	d := func(s string) time.Time { v, _ := time.Parse("2006-01-02", s); return v }
	for _, c := range []struct {
		sp   spacing
		from string
		k    int
		want string
	}{
		{spacing{unit: 3, value: 254}, "2008-01-31", 1, "2008-02-29"},
		{spacing{unit: 3, value: 254}, "2010-01-15", 2, "2010-03-15"},
		{spacing{unit: 2, value: 254}, "2010-01-01", 1, "2010-04-01"},
		{spacing{unit: 1, value: 254}, "2010-01-01", -1, "2009-07-01"},
		{spacing{unit: 3, value: 253}, "2010-01-16", 1, "2010-02-01"},
		{spacing{unit: 3, value: 253}, "2010-02-15", 1, "2010-02-28"},
		{spacing{unit: 3, value: 253}, "2010-02-28", -1, "2010-02-15"},
		{spacing{unit: 3, value: 7}, "2010-01-01", 2, "2010-01-15"},
	} {
		got, ok := c.sp.step(d(c.from), c.k)
		if !ok || got.Format("2006-01-02") != c.want {
			t.Errorf("%+v from %s by %d: %s %v, want %s", c.sp, c.from, c.k, got.Format("2006-01-02"), ok, c.want)
		}
	}
	for _, sp := range []spacing{{value: 0}, {value: 251}, {value: 255}, {unit: 0, value: 254}, {unit: 2, value: 253}} {
		if _, ok := sp.step(d("2010-01-01"), 1); ok {
			t.Errorf("%+v is a time step", sp)
		}
	}
}

// BCD base values and elements of a compact profile follow EN 13757-3
// annex B as ordinary records do: an F in the most significant digit is a
// minus sign, a digit A to E (or F elsewhere) makes the value invalid
// (F-132).
//
// Covers: SIG-IPE-956
func TestProfileCompactBCDAnnexB(t *testing.T) {
	// Increments 3, then F1 (minus one), then 11.
	got := profileMap(t, "8404 6D00204111"+"8B04 15003012"+"8D04 951F05690103 F111")
	wantValues(t, got, map[string]any{"volume_s8": 12300.0, "volume_s8_p1": 12300.3, "volume_s8_p2": 12300.2, "volume_s8_p3": 12301.3})
	// A digit A: that element is invalid, and so is every value after it.
	got = profileMap(t, "8404 6D00204111"+"8B04 15003012"+"8D04 951F05690103 0A11")
	wantValues(t, got, map[string]any{"volume_s8_p1": 12300.3, "volume_s8_p2": nil, "volume_s8_p3": nil})
	// A negative BCD base value (F in its top digit) is the base.
	got = profileMap(t, "8404 6D00204111"+"8B04 150030F2"+"8D04 951F05690103 0211")
	wantValues(t, got, map[string]any{"volume_s8": -2300.0, "volume_s8_p1": -2299.7})
}
