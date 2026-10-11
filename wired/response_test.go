package wired_test

import (
	"reflect"
	"testing"

	"github.com/cB-Sigma/mbus/records"
	"github.com/cB-Sigma/mbus/wired"
)

// An answer with a CI this decoder does not know (a manufacturer-specific
// CI A0h–B7h, EN 13757-3) is kept as one manufacturer_data record instead
// of failing the read; the error still says what was seen.
// Covers: SIG-IPE-3518
func TestMBusUnknownCIKeptAsManufacturerData(t *testing.T) {
	r, err := wired.ParseResponse(wired.Frame{Long: true, C: wired.CRspUD, A: 5, CI: 0xA3, Data: []byte{0x01, 0x02, 0xAB}})
	if r == nil || !r.UnknownCI || len(r.Records) != 1 || r.Records[0].Value != "0102AB" || !r.Records[0].Manufacturer {
		t.Fatalf("CI A3: %+v", r)
	}
	if err == nil {
		t.Error("CI A3: no error to report")
	}
}

// EN 13757-3:2025 10.2: only responses with a short or long header carry
// the TPL status byte; the fixed data structure's status has other bits.
//
// Covers: SIG-IPE-2736
func TestMBusResponseStatusByte(t *testing.T) {
	long := append(unhex(t, "785634122440010755"), 0x0A, 0, 0)
	short := []byte{0x55, 0x0A, 0, 0}
	for _, tc := range []struct {
		name string
		ci   byte
		data []byte
		want []string // nil: no status byte
	}{
		{"variable, long header", wired.CIRspVariable, long, []string{"application_error", "permanent_error"}},
		{"variable, short header", wired.CIRspShort, short, []string{"application_error", "permanent_error"}},
		{"application error, long header", wired.CIAppErrLong, append(append([]byte{}, long...), 0x08), []string{"application_error", "permanent_error"}},
		{"application error, short header", wired.CIAppErrShort, append(append([]byte{}, short...), 0x08), []string{"application_error", "permanent_error"}},
		{"variable, no header", wired.CIRspNoHeader, []byte{0x03, 0x13, 0x01, 0x00, 0x00}, nil},
		{"application error, no header", wired.CIAppErrNone, []byte{0x08}, nil},
		{"fixed structure", wired.CIRspFixed, unhex(t, "78563412130A1415000000000000000000"), nil},
	} {
		r, err := wired.ParseResponse(wired.Frame{Long: true, C: wired.CRspUD, A: 5, CI: tc.ci, Data: tc.data})
		if r == nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if r.HasStatus() != (tc.want != nil) {
			t.Errorf("%s: HasStatus = %v", tc.name, r.HasStatus())
			continue
		}
		if tc.want != nil && !reflect.DeepEqual(records.StatusFlags(r.Status), tc.want) {
			t.Errorf("%s: flags %q, want %q", tc.name, records.StatusFlags(r.Status), tc.want)
		}
	}
}
