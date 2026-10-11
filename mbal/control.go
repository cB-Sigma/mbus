// Package mbal is the M-Bus adaptation layer (MBAL) of EN 13757-8:2023: the
// one-byte MBAL control field (optionally introduced by the CI field CFh)
// that carries M-Bus upper layers (AFL, TPL, APL of EN 13757-7 and -3)
// over LPWAN technologies, and the per-technology payload layouts of the
// annexes: LoRaWAN (FPort is the control field, Annex D.6), NB-IoT/LTE-M
// over UDP or CoAP/COSE/CBOR (Annex C.4), MIOTY (Annex E.5) and Wize
// (Annex F.4). The M-Bus upper layers are decoded with package wireless.
package mbal

import "fmt"

// CI is the CI field that introduces the MBAL (EN 13757-8 clause 7.1,
// Table 4). CCh to CEh are reserved.
const CI byte = 0xCF

// Direction is uplink (end device to head end) or downlink: the control
// field's bits 5-4 and its function codes differ between them (7.2.1.1).
type Direction uint8

const (
	Uplink   Direction = iota // from the meter
	Downlink                  // to the meter
)

// String is "uplink" or "downlink".
func (d Direction) String() string {
	if d == Downlink {
		return "downlink"
	}
	return "uplink"
}

// Version 1 is the only defined MBAL version: bits 7-6 = 00 (7.2.1.2).
const Version1 uint8 = 0

// Access is the uplink accessibility subfield, bits 5-4 (7.2.1.3, Table 9).
type Access uint8

const (
	AccessNone      Access = 0 // no access or temporarily no access
	AccessShort     Access = 1 // short or limited window after the transmission
	AccessUnlimited Access = 2 // unlimited or continuous access
	AccessUnused    Access = 3 // unused or unavailable
)

var accessNames = [4]string{"none", "short", "unlimited", "unused"}

// String names the access subfield.
func (a Access) String() string { return accessNames[a&3] }

// Latency is the downlink latency subfield, bits 5-4 (7.2.1.4, Table 10).
type Latency uint8

const (
	LatencyRFU    Latency = 0 // reserved
	LatencyDelay  Latency = 1 // the answer may come with a delay
	LatencyASAP   Latency = 2 // the answer is expected as soon as possible
	LatencyUnused Latency = 3 // unused or invalid
)

var latencyNames = [4]string{"rfu", "delay", "asap", "unused"}

// String names the latency subfield.
func (l Latency) String() string { return latencyNames[l&3] }

// Function is the function code subfield, bits 3-0 (7.2.1.5). Values
// shared by both directions carry both names.
type Function uint8

const (
	FnTPLACK  Function = 0x0 // both directions
	FnTPLNACK Function = 0x1 // both directions
	FnSNDUD   Function = 0x2 // both directions: confirmed by TPL-ACK
	FnSNDUD2  Function = 0x3 // downlink: confirmed by RSP-UD
	FnSNDNR   Function = 0x4 // both directions: no answer
	FnACCDMD2 Function = 0x5 // uplink: confirmed by REQ-UD1
	FnSNDUD3  Function = 0x5 // downlink: to several receivers, no answer
	FnSNDIR   Function = 0x6 // uplink: confirmed by CNF-IR
	FnCNFIR   Function = 0x6 // downlink
	FnACCNR   Function = 0x7 // uplink: no application data, opens access
	FnSNDNKE  Function = 0x7 // downlink: ends the session
	FnRSPUD   Function = 0x8 // uplink
	FnACCDMD  Function = 0xA // uplink: confirmed by TPL-ACK
	FnREQUD1  Function = 0xA // downlink: confirmed by RSP-UD or TPL-ACK
	FnREQUD2  Function = 0xB // downlink: confirmed by RSP-UD
	FnUnused  Function = 0xF // both directions: function code not used
)

// Symbolic names per direction (Tables 11 and 12); "" is RFU.
var (
	upNames = [16]string{0: "TPL-ACK", 1: "TPL-NACK", 2: "SND-UD", 4: "SND-NR", 5: "ACC-DMD2", 6: "SND-IR",
		7: "ACC-NR", 8: "RSP-UD", 0xA: "ACC-DMD", 0xF: "unused"}
	downNames = [16]string{0: "TPL-ACK", 1: "TPL-NACK", 2: "SND-UD", 3: "SND-UD2", 4: "SND-NR", 5: "SND-UD3",
		6: "CNF-IR", 7: "SND-NKE", 0xA: "REQ-UD1", 0xB: "REQ-UD2", 0xF: "unused"}
)

// FunctionName is the symbolic name of a function code in a direction, or
// "RFU".
func FunctionName(d Direction, f Function) string {
	n := upNames[f&0x0F]
	if d == Downlink {
		n = downNames[f&0x0F]
	}
	if n == "" {
		return "RFU"
	}
	return n
}

// ParseFunction is FunctionName's inverse (case-insensitive, "_" or "-").
func ParseFunction(d Direction, name string) (Function, error) {
	names := upNames
	if d == Downlink {
		names = downNames
	}
	n := normName(name)
	for i, v := range names {
		if v != "" && normName(v) == n {
			return Function(i), nil
		}
	}
	return 0, fmt.Errorf("%q is not an MBAL %s function", name, d)
}

func normName(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_' || c == '-' || c == ' ':
			continue
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		}
		b = append(b, c)
	}
	return string(b)
}

// Control is the MBAL control field (MBAL-CL, 7.2.1.1, Tables 6 and 7).
type Control struct {
	Direction Direction
	Version   uint8 // bits 7-6
	Sub       uint8 // bits 5-4: Access (uplink) or Latency (downlink)
	Function  Function
}

// ParseControl splits a control field byte.
func ParseControl(b byte, d Direction) Control {
	return Control{Direction: d, Version: b >> 6, Sub: b >> 4 & 0x03, Function: Function(b & 0x0F)}
}

// NewUplink builds a version 1 uplink control field.
func NewUplink(a Access, f Function) Control {
	return Control{Direction: Uplink, Sub: uint8(a) & 3, Function: f & 0x0F}
}

// NewDownlink builds a version 1 downlink control field.
func NewDownlink(l Latency, f Function) Control {
	return Control{Direction: Downlink, Sub: uint8(l) & 3, Function: f & 0x0F}
}

// Byte encodes the control field.
func (c Control) Byte() byte {
	return c.Version&3<<6 | c.Sub&3<<4 | byte(c.Function&0x0F)
}

// Access is the uplink access subfield.
func (c Control) Access() Access { return Access(c.Sub & 3) }

// Latency is the downlink latency subfield.
func (c Control) Latency() Latency { return Latency(c.Sub & 3) }

// Name is the function's symbolic name in the field's direction.
func (c Control) Name() string { return FunctionName(c.Direction, c.Function) }

// Known reports a defined function code (not RFU, not "unused").
func (c Control) Known() bool {
	n := c.Name()
	return n != "RFU" && n != "unused"
}

// Check refuses a control field this implementation cannot interpret: an
// RFU version (only version 1 is defined).
func (c Control) Check() error {
	if c.Version != Version1 {
		return fmt.Errorf("MBAL version bits %02b are reserved (only version 1, 00, is defined)", c.Version)
	}
	return nil
}

// Reachable reports whether an uplink announces an access window the head
// end may use now (access 01 or 10). With access 00 a downlink is better
// postponed (7.2.1.3, NOTE).
func (c Control) Reachable() bool {
	a := c.Access()
	return c.Direction == Uplink && (a == AccessShort || a == AccessUnlimited)
}

// ConfirmedBy is the function that answers this message, per the
// "Confirmed by" column of Tables 11 and 12 (ok false: no answer
// expected). REQ-UD1 is answered by RSP-UD, or TPL-ACK when there is no
// alarm data.
func (c Control) ConfirmedBy() (Function, bool) {
	if c.Direction == Uplink {
		switch c.Function {
		case FnSNDUD, FnACCDMD:
			return FnTPLACK, true
		case FnACCDMD2:
			return FnREQUD1, true
		case FnSNDIR:
			return FnCNFIR, true
		}
		return 0, false
	}
	switch c.Function {
	case FnSNDUD:
		return FnTPLACK, true
	case FnSNDUD2, FnREQUD1, FnREQUD2:
		return FnRSPUD, true
	}
	return 0, false
}

// Answer is the downlink control field a head end sends in reply to an
// uplink: the "Confirmed by" function (SND-UD and ACC-DMD: TPL-ACK;
// ACC-DMD2: REQ-UD1; SND-IR: CNF-IR), or TPL-NACK for a function code that
// is RFU or unused (Table 11, footnote a). ok is false when the uplink
// expects no answer. The latency asks for a quick answer where the head
// end asks for data (REQ-UD1, Annex B.1) and allows a delay otherwise
// (the TPL-ACK of Annex B.3, the CNF-IR of Annex D.6.3.2).
func Answer(up Control) (Control, bool) {
	if up.Direction != Uplink || up.Version != Version1 {
		return Control{}, false
	}
	if !up.Known() {
		return NewDownlink(LatencyDelay, FnTPLNACK), true
	}
	f, ok := up.ConfirmedBy()
	if !ok {
		return Control{}, false
	}
	l := LatencyDelay
	if f == FnREQUD1 {
		l = LatencyASAP
	}
	return NewDownlink(l, f), true
}

// String shows the control field's subfields and function.
func (c Control) String() string {
	sub := c.Access().String()
	if c.Direction == Downlink {
		sub = c.Latency().String()
	}
	return fmt.Sprintf("%02X %s v%d %s %s", c.Byte(), c.Direction, c.Version+1, sub, c.Name())
}

// Info is the control field as a JSON-friendly map for readings.
func (c Control) Info() map[string]any {
	m := map[string]any{
		"control":   fmt.Sprintf("%02X", c.Byte()),
		"version":   int(c.Version) + 1,
		"function":  c.Name(),
		"direction": c.Direction.String(),
	}
	if c.Direction == Uplink {
		m["access"] = c.Access().String()
	} else {
		m["latency"] = c.Latency().String()
	}
	return m
}
