// The test frames in this file (frameMultical601, framePolluTherm,
// frameSensoStar2Records and the Ultraheat T230 records) are data from
// libmbus's test suite: Copyright (c) 2010-2012, Raditex Control AB. All
// rights reserved. Used under the BSD 3-Clause License, whose text is in
// this module's NOTICE; libmbus asks that rSCADA and Raditex Control be
// credited. No libmbus code is used.

package wired_test

import (
	"bytes"
	"testing"

	"github.com/cB-Sigma/mbus/records"
	"github.com/cB-Sigma/mbus/wired"
)

// Heat meter answers published with libmbus's test suite
// (github.com/rscada/libmbus, test/test-frames, BSD-3-Clause; each file's
// .norm.xml lists the decoded values the expectations below were checked
// against). Each is the meter's whole RSP_UD frame.
const (
	// kamstrup_multical_601.hex: Kamstrup Multical 601, ID 06855817,
	// medium heat (outlet).
	frameMultical601 = "68F7F76808117217588506" + "2D2C080404000000" +
		"0C78175885060406E791000004142CDB00000422D90300000459B9270000045D081200000461B1150000042D5B010000142DC0010000043B1F020000143B74020000841006000000008420060000000084401400000000848040140000000084C0400600000000046D1A2F65114406518200004414B2C30000542D26020000543B03040000C4100600000000C4200600000000C4401400000000C480401400000000C4C0400600000000426C5F1C0F00000000E7E40000636600000000000000000000000000005BC9A50234530000E0B20300899C68000000000001000107070901030000000000" +
		"9816"
	// sen_pollutherm.hex: Sensus PolluTherm, ID 21050076. Its third
	// record has VIF 7Bh without the extension bit, which the standard
	// does not define.
	framePolluTherm = "684242680808727600052118" + "4E310451000000" +
		"0C07640800000C14929879000C7B020300000C2C585400000A5A55070A5E94050B607660010C78760005210CFD10760005211F" +
		"B316"
	// EFE_Engelmann-Elster-SensoStar-2.hex: Engelmann SensoStar 2, a
	// fabrication number in binary (DIF 04).
	frameSensoStar2Records = "0478917B6F01046D172ECC13041500000000441500000000840115000000000406000000004406000000008401060000000084100600000000C410060000000084110600000000426CBF1C026CDF1C8420060000000084300600000000043B00000000143B19000000042B00000000142B0B000000025B1600025F150004610900000002230C0201FD17000490280B000000"
)

func responseRecords(t *testing.T, frame string) map[string]any {
	t.Helper()
	f, err := wired.ReadFrame(bytes.NewReader(unhex(t, frame)))
	if err != nil {
		t.Fatal(err)
	}
	r, err := wired.ParseResponse(f)
	if r == nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Errorf("not fully decoded: %v", err)
	}
	out := map[string]any{}
	for _, rec := range r.Records {
		v := rec.Value
		if i, ok := v.(int64); ok {
			v = float64(i)
		}
		out[rec.Name()+"|"+rec.Unit] = v
	}
	return out
}

// A published Kamstrup Multical 601 answer decodes to the values the
// libmbus suite gives: energy in kWh, volume, flow and return
// temperature, temperature difference, power and volume flow (current and
// maximum), the stored values of storage 1 kept apart from the current
// ones, and the tariff and subunit registers.
//
// Covers: SIG-CMD-092
func TestMBusHeatMeterMultical601(t *testing.T) {
	got := responseRecords(t, frameMultical601)
	for k, want := range map[string]float64{
		"energy|Wh":                37351000,
		"volume|m3":                561.08,
		"flow_temperature|Cel":     101.69,
		"return_temperature|Cel":   46.16,
		"temperature_difference|K": 55.53,
		"power|W":                  34700,
		"power_max|W":              44800,
		"volume_flow|m3/h":         0.543,
		"volume_flow_max|m3/h":     0.628,
		"energy_s1|Wh":             33361000,
		"volume_s1|m3":             500.98,
		"power_max_s1|W":           55000,
		"volume_flow_max_s1|m3/h":  1.027,
		"energy_t2|Wh":             0,
		"volume_u2|m3":             0,
		"energy_u3|Wh":             0,
		"energy_t1|Wh":             0,
		"volume_u1|m3":             0,
		"energy_s1_t1|Wh":          0,
	} {
		if v, ok := got[k]; !ok || !near(v, want) {
			t.Errorf("%s = %v, want %v", k, v, want)
		}
	}
	if got["fabrication_number|"] != "06855817" {
		t.Errorf("fabrication number %v", got["fabrication_number|"])
	}
}

// A heat meter record the standard does not define (VIF 7Bh without the
// extension bit, Sensus PolluTherm) is kept as an unknown quantity and
// the records after it are still read: power, volume flow, temperatures
// and the temperature difference.
//
// Covers: SIG-CMD-093
func TestMBusHeatMeterUnknownVIFKeepsTheRest(t *testing.T) {
	got := responseRecords(t, framePolluTherm)
	for k, want := range map[string]float64{
		"energy|Wh":                8640000,
		"volume|m3":                7998.92,
		"flow_temperature|Cel":     75.5,
		"return_temperature|Cel":   59.4,
		"temperature_difference|K": 16.076,
		"power|W":                  54580,
	} {
		if v, ok := got[k]; !ok || !near(v, want) {
			t.Errorf("%s = %v, want %v", k, v, want)
		}
	}
	if got["fabrication_number|"] != "21050076" {
		t.Errorf("fabrication number %v", got["fabrication_number|"])
	}
}

// A fabrication number sent as a binary integer (DIF 04) reads as its
// decimal number, as one sent in BCD does.
//
// Covers: SIG-CMD-094
func TestMBusFabricationNumberBinary(t *testing.T) {
	f := wired.Frame{Long: true, C: wired.CRspUD, A: 1, CI: wired.CIRspVariable, Data: append(unhex(t, "45330824C514000466270000"), unhex(t, frameSensoStar2Records)...)}
	r, err := wired.ParseResponse(f)
	if r == nil {
		t.Fatal(err)
	}
	if r.Records[0].Name() != "fabrication_number" || r.Records[0].Value != "24083345" {
		t.Errorf("fabrication number %v", r.Records[0].Value)
	}
}

// A Landis+Gyr Ultraheat T230 (libmbus landis+gyr_ultraheat_t230.hex)
// sends the dates of its tariff-1 maxima as type F dates (VIFE 6Fh); a
// maximum not reached yet has the date all zeros, which is no date (month
// 0) and reads as invalid rather than as 2000-00.
//
// Covers: SIG-CMD-097
func TestMBusHeatMeterZeroDateInvalid(t *testing.T) {
	recs, err := records.ParseRecords(unhex(t, "9410AD6F00000000"+"9410DA6F32147A18"))
	if err != nil || len(recs) != 2 {
		t.Fatalf("%v %v", recs, err)
	}
	if !recs[0].Invalid || recs[0].Quality() != "invalid" {
		t.Errorf("zero date: %v %q", recs[0].Value, recs[0].Quality())
	}
	if recs[1].Invalid || recs[1].Value != "2011-08-26T20:50:00" || recs[1].Name() != "flow_temperature_max_t1_last_end" {
		t.Errorf("date of the maximum flow temperature: %s = %v", recs[1].Name(), recs[1].Value)
	}
}
