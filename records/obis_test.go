package records

import "testing"

// annexHCase is a data record (hex, DIF to data) of a meter of a device
// type and the OBIS code annex H gives it ("" for none).
type annexHCase struct {
	dev  byte
	rec  string
	want string
}

func checkAnnexH(t *testing.T, cases []annexHCase) {
	t.Helper()
	for _, c := range cases {
		recs, err := ParseRecords(hx(t, c.rec))
		if err != nil || len(recs) != 1 {
			t.Errorf("%s: %v %+v", c.rec, err, recs)
			continue
		}
		code, ok := recs[0].OBIS(c.dev)
		got := ""
		if ok {
			got = code.String()
		}
		if got != c.want {
			t.Errorf("device %02X record %s (%s %v s%d t%d u%d): OBIS %q, want %q", c.dev, c.rec, recs[0].Quantity, recs[0].Modifier,
				recs[0].Storage, recs[0].Tariff, recs[0].Subunit, got, c.want)
		}
	}
}

// Covers: SIG-IPE-2227
func TestAnnexHTranslation(t *testing.T) {
	// One vector per row kind of Tables H.2 to H.10, built from the DIF,
	// DIFE, VIF and VIFE bit patterns the tables print.
	checkAnnexH(t, []annexHCase{
		// H.2: ownership number, metering point ID (FD 11, FD 10), serial number (78).
		{0x07, "0D FD 11 02 41 42", "0.0.96.1.9.255"},
		{0x07, "0D FD 10 02 41 42", "0.0.96.1.10.255"},
		{0x03, "0C 78 78 56 34 12", "0.0.96.1.0.255"},
		// H.3 electricity: +A (VIF 0nnn), FB 0x (MWh) and FB 8x 7D; -A (VIFE 3C); recent values by storage.
		{0x02, "04 03 10 27 00 00", "1.0.1.8.0.255"},
		{0x02, "04 FB 00 10 27 00 00", "1.0.1.8.0.255"},
		{0x02, "04 FB 80 7D 10 27 00 00", "1.0.1.8.0.255"},
		{0x02, "84 04 03 10 27 00 00", "1.0.1.8.0.8"}, // storage 8 (DIFE storage bits 4 << 1) is VZ 8
		{0x02, "04 83 3C 10 27 00 00", "1.0.2.8.0.255"},
		{0x02, "04 6D 00 00 01 01", "1.0.0.9.1.255"},
		{0x02, "02 6C 01 01", "1.0.0.9.2.255"},
		{0x02, "04 74 3C 00 00 00", "1.0.0.1.2.255"},
		{0x02, "82 02 6C 01 01", "1.0.0.1.2.4"},
		{0x02, "04 71 0F 00 00 00", "1.0.0.8.0.255"},
		// H.4 heat cost allocator.
		{0x08, "04 6E 10 00 00 00", "4.0.1.0.0.255"},
		{0x08, "44 6E 10 00 00 00", "4.0.1.2.0.255"},
		{0x08, "42 6C 01 01", "4.0.0.1.10.255"},
		{0x08, "04 74 3C 00 00 00", "4.0.0.9.3.255"},
		{0x08, "02 FB 68 00 10", "4.0.0.4.0.255"},
		{0x08, "02 FB 6E 00 10", "4.0.0.4.6.255"},
		// H.5 cooling, H.7 heat: energy in Wh and GJ (0000 1nnn), power, flow, set date value.
		{0x0A, "04 06 10 27 00 00", "5.0.1.0.0.255"},
		{0x04, "04 0E 10 27 00 00", "6.0.1.0.0.255"},
		{0x04, "44 06 10 27 00 00", "6.0.1.2.0.255"},
		{0x04, "04 FB 09 10 27 00 00", "6.0.1.0.0.255"},
		{0x0C, "04 2B 10 00 00 00", "6.0.8.0.0.255"},
		{0x0C, "04 33 10 00 00 00", "6.0.8.0.0.255"},
		{0x04, "04 3B 10 00 00 00", "6.0.9.0.0.255"},
		{0x04, "04 71 0F 00 00 00", "6.0.0.8.5.255"},
		// H.6: the cooling records of a combined meter (tariff 1 via DIFE
		// 0001 0000, or VIFE 3C); its heat records stay A 6.
		{0x0D, "84 10 06 10 27 00 00", "5.0.1.0.0.255"},
		{0x0D, "04 86 3C 10 27 00 00", "5.0.1.0.0.255"},
		{0x0D, "C4 10 06 10 27 00 00", "5.0.1.2.0.255"},
		{0x0D, "04 06 10 27 00 00", "6.0.1.0.0.255"},
		// H.8 gas: Vm (VIFE 3A), Vtc (plain), Vb (VIFE 3E), with FD 3A / 7D variants; flow rates; base T and p.
		{0x03, "04 93 3A 10 27 00 00", "7.0.3.0.0.255"},
		{0x03, "04 93 FD 3A 10 27 00 00", "7.0.3.0.0.255"},
		{0x03, "04 13 10 27 00 00", "7.0.3.1.0.255"},
		{0x03, "04 93 7D 10 27 00 00", "7.0.3.1.0.255"},
		{0x03, "04 93 3E 10 27 00 00", "7.0.3.2.0.255"},
		{0x03, "84 04 93 3E 10 27 00 00", "7.0.3.2.0.8"},
		{0x03, "04 BB 3A 10 00 00 00", "7.0.43.15.0.255"},
		{0x03, "04 3B 10 00 00 00", "7.0.43.16.0.255"},
		{0x03, "04 BB 3E 10 00 00 00", "7.0.43.17.0.255"},
		{0x03, "02 D9 3E 10 00", "7.0.41.2.0.255"},
		{0x03, "02 E9 3E 10 00", "7.0.42.2.0.255"},
		{0x03, "04 71 0F 00 00 00", "7.0.0.8.28.255"},
		// H.9, H.10 water.
		{0x07, "04 13 10 27 00 00", "8.0.1.0.0.255"},
		{0x07, "04 93 7D 10 27 00 00", "8.0.1.0.0.255"},
		{0x07, "44 13 10 27 00 00", "8.0.1.2.0.255"},
		{0x06, "04 3B 10 00 00 00", "9.0.2.0.0.255"},
		{0x15, "04 13 10 27 00 00", "9.0.1.0.0.255"},
		{0x06, "04 71 0F 00 00 00", "9.0.0.8.6.255"},
		{0x06, "04 6D 00 00 01 01", "9.0.0.9.1.255"},
		// B is the subunit: DIFE with the subunit bit set.
		{0x07, "84 40 13 10 27 00 00", "8.1.1.0.0.255"},
		// Records annex H has no row for.

		{0x07, "84 01 13 10 27 00 00", ""}, // storage 2 of a water meter
		{0x07, "04 5B 10 00 00 00", ""},    // flow temperature of a water meter
		{0x03, "04 13 10 27 00 00", "7.0.3.1.0.255"},
		{0x31, "04 13 10 27 00 00", ""},       // device type without a table
		{0x02, "04 83 BC 3C 10 27 00 00", ""}, // backward twice
	})
}

// Covers: SIG-IPE-2228
func TestAnnexHOBISDeclaration(t *testing.T) {
	// H.3: a water meter's maximum flow rate (DIF 1Ah, VIF 3Bh, value
	// 123) and its OBIS declaration 8-0:2.5.0*255, as 12 BCD digits
	// (DIF 1Eh, VIF BBh 3Fh, AA 00 05 02 00 08) and as a 48-bit binary
	// number (DIF 16h, FF 00 05 02 00 08).
	for _, decl := range []string{"1E BB 3F AA 00 05 02 00 08", "16 BB 3F FF 00 05 02 00 08"} {
		recs, err := ParseRecords(hx(t, "1A 3B 23 01 "+decl))
		if err != nil || len(recs) != 2 {
			t.Fatalf("%s: %v %+v", decl, err, recs)
		}
		recs = ApplyOBISDeclarations(recs)
		if len(recs) != 1 {
			t.Fatalf("%s: declaration not applied: %+v", decl, recs)
		}
		code, ok := recs[0].OBIS(0x07)
		if !ok || code.String() != "8.0.2.5.0.255" || recs[0].Name() != "volume_flow_max" {
			t.Errorf("%s: %v %v %s", decl, code, ok, recs[0].Name())
		}
		if OBISLabel(code) != "obis:8.0.2.5.0.255" || OBISPointName(code) != "coldWaterFlowRateMax" {
			t.Errorf("label %s name %s", OBISLabel(code), OBISPointName(code))
		}
	}
	// A declaration without the record it declares stays a record.
	recs, _ := ParseRecords(hx(t, "16 BB 3F FF 00 05 02 00 08"))
	if recs = ApplyOBISDeclarations(recs); len(recs) != 1 {
		t.Errorf("orphan declaration: %+v", recs)
	}
}

// Covers: SIG-IPE-2621
func TestAnnexHGapsFromOBISModel(t *testing.T) {
	// Beyond annex H, a tariff record takes E = the tariff where the model
	// defines that rate (IEC 62056-6-1:2023 Table 15; EN 13757-1:2021
	// Tables 17, 25, 37, 47), and a maximum or minimum takes the medium's
	// D 5 or D 4 (EN 13757-1:2021 Tables 16, 24, 46). Everything else stays
	// uncoded.
	checkAnnexH(t, []annexHCase{
		{0x02, "84 10 03 10 27 00 00", "1.0.1.8.1.255"},    // electricity +A, tariff 1 (Table 15)
		{0x02, "84 30 03 10 27 00 00", "1.0.1.8.3.255"},    // tariff 3
		{0x07, "84 10 13 10 27 00 00", "8.0.1.0.1.255"},    // cold water volume, tariff 1 (Table 47)
		{0x03, "84 20 93 3A 10 27 00 00", "7.0.3.0.2.255"}, // gas Vm, tariff 2 (Table 37)
		{0x04, "84 10 06 10 27 00 00", "6.0.1.0.1.255"},    // heat energy, tariff 1 (Table 25)
		{0x07, "14 3B 10 00 00 00", "8.0.2.5.0.255"},       // water flow rate maximum (Table 46; H.3's example)
		{0x04, "14 2B 10 00 00 00", "6.0.8.5.0.255"},       // heat power maximum 1 (Table 24)
		{0x04, "24 2B 10 00 00 00", "6.0.8.4.0.255"},       // heat power minimum 1
		{0x07, "94 10 3B 10 00 00 00", "8.0.2.5.1.255"},    // water flow rate maximum, tariff 1
		// No code in the model.
		{0x07, "84 80 30 13 10 27 00 00", ""},           // water volume, tariff 12: Table 47 has 1 to 9
		{0x03, "14 93 3A 10 27 00 00", ""},              // gas index maximum: Table 32 has none
		{0x02, "14 03 10 27 00 00", ""},                 // electricity energy maximum
		{0x0D, "84 20 06 10 27 00 00", "6.0.1.0.2.255"}, // combined meter, heat, tariff 2
		{0x07, "34 13 10 27 00 00", ""},                 // value during error state
	})
}

func TestAnnexHTariff12Decodes(t *testing.T) {
	recs, err := ParseRecords(hx(t, "84 80 30 13 10 27 00 00"))
	if err != nil || recs[0].Tariff != 12 || recs[0].Storage != 0 {
		t.Fatalf("%+v %v", recs, err)
	}
}
