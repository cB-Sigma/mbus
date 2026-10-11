package wireless

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/cB-Sigma/mbus/records"
)

// Sending to meters (EN 13757-4 link, EN 13757-7 transport layer, OMS
// Volume 2 annex N.7 and N.8 for the frame layout). A bidirectional meter
// listens only briefly after it transmits, so a downlink is queued and
// sent right after the meter's next telegram that opens that window:
//
//   - CNF-IR (C 06h) after the meter's installation request (SND-IR, C
//     46h), echoing its ELL and TPL access numbers;
//   - SND-UD (C 53h) with a TPL long header addressed to the meter (CI 5Bh
//     by default) and application data, encrypted in security mode 5 when
//     the meter has a key; sent after a telegram whose ELL communication
//     control has the bidirectional bit, and acknowledged by the meter with
//     ACK (C 00h);
//   - SND-NKE, SND-UD2, REQ-UD1 and REQ-UD2 (table 34) the same way.
//
// The frame's link address is the gateway's own (Gateway); the meter is
// named in the TPL long header. Of the receivers here only the iM871A and
// Amber framings can transmit (EncodeIM871A, EncodeAmber). Scheduler
// (scheduler.go) keeps the queue per meter and picks the window.

// Link-layer C fields of the frames a gateway sends and a meter answers
// with (link.go has the rest of tables 33 to 35).
const (
	CSndNR = 0x44 // SND-NR: a meter's spontaneous telegram
	CSndIR = 0x46 // SND-IR: installation request
	CCnfIR = 0x06 // CNF-IR: confirmation of an installation request
	CSndUD = 0x53 // SND-UD with FCV set (73h with FCB)
	CACK   = 0x00 // ACK
	// CCGateway is the CC field of our frames: bidirectional, as in the
	// OMS annex N examples of a gateway's CNF-IR and SND-UD.
	CCGateway = 0x84
	// CIToMeterLong is the TPL long header of application data sent to a
	// meter (EN 13757-7); CIToMeterNoAPL carries no application data.
	CIToMeterLong  byte = 0x5B
	CIToMeterNoAPL byte = 0x80
)

// Gateway is our own link-layer address for frames we send.
type Gateway struct {
	Manufacturer string `json:"manufacturer"`
	ID           string `json:"id"`
	Version      byte   `json:"version,omitempty"`
	DeviceType   *byte  `json:"deviceType,omitempty"` // default 31h, communication controller

	m uint16
	a [6]byte
}

// Validate checks the gateway's manufacturer and identification number
// and fills in its M and A fields (MField, A); call it before the gateway
// is used to send.
func (g *Gateway) Validate() error {
	m, err := records.ManufacturerField(g.Manufacturer)
	if err != nil {
		return fmt.Errorf("gateway: %w", err)
	}
	id, err := hex.DecodeString(g.ID)
	if err != nil || len(g.ID) != 8 || strings.ContainsAny(g.ID, "abcdefABCDEF") {
		return fmt.Errorf("gateway: id %q is not 8 decimal digits", g.ID)
	}
	g.m = m
	for i := range 4 {
		g.a[i] = id[3-i]
	}
	g.a[4] = g.Version
	g.a[5] = 0x31
	if g.DeviceType != nil {
		g.a[5] = *g.DeviceType
	}
	return nil
}

// MField is the gateway's M field (after Validate).
func (g Gateway) MField() uint16 { return g.m }

// A is the gateway's A field: identification number, version and device
// type (after Validate).
func (g Gateway) A() [6]byte { return g.a }

// Downlink is one frame to send to a meter.
type Downlink struct {
	C      byte   // CCnfIR, CSndUD, CSndUD2, CSndNKE, CReqUD1 or CReqUD2
	CI     byte   // TPL CI
	APL    []byte // application data (before encryption)
	Status byte   // TPL status sent by the gateway
}

// EncodeDownlink builds a CRC-less frame from the gateway to a meter:
// link header, ELL (CI 8Ch: CC, ACC), TPL long header naming the meter,
// and the application data (security mode 5 when key is set).
// ellACC and tplACC are the ELL and TPL access numbers.
func EncodeDownlink(gw Gateway, meter Header, dl Downlink, ellACC, tplACC byte, key []byte) ([]byte, error) {
	sec := DownlinkSeal{Mode: 5, Key: key}
	if key == nil || len(dl.APL) == 0 {
		sec.Mode = 0
	}
	return EncodeDownlinkSealed(gw, meter, dl, ellACC, tplACC, sec)
}

// DownlinkSeal says how a downlink is secured: mode 0, mode 5 with the
// meter's key, or modes 7 to 10 with KDF-A (Lenc, Lmac from the persistent
// key and our counter CCP, EN 13757-7:2025 clause 9.6): mode 7 behind an
// AFL with the counter and an 8-byte AES-CMAC (clause 9.3.2), mode 8 with
// MAC_1, mode 9 with its 12-byte GCM tag, mode 10 with an 8-byte CCM tag
// and the counter in the TPL.
type DownlinkSeal struct {
	Mode    int
	Key     []byte
	KeyID   int
	Counter uint32 // CCP, for mode 7
	// KeyInfo sends AFL.KI with mode 7. OMS Volume 2 6.2.2 makes a meter
	// repeat KI in its answers once we send it, so by default (false) it
	// is left out when the key is Key ID 0 without a key version (as in
	// the annex N.12.2 example) and sent otherwise.
	KeyInfo bool
}

// EncodeDownlinkSealed is EncodeDownlink with the security chosen.
func EncodeDownlinkSealed(gw Gateway, meter Header, dl Downlink, ellACC, tplACC byte, sec DownlinkSeal) ([]byte, error) {
	b := []byte{0, dl.C}
	b = binary.LittleEndian.AppendUint16(b, gw.m)
	b = append(b, gw.a[:]...)
	b = append(b, CIELL2, CCGateway, ellACC)
	seal := Seal{Mode: sec.Mode, Key: sec.Key, KeyVersion: -1}
	if sec.Mode >= 7 {
		seal = Seal{Mode: sec.Mode, Key: sec.Key, KDF: 1, KeyID: sec.KeyID, KeyVersion: -1, Counter: sec.Counter, ToMeter: true, CounterInTPL: sec.Mode == 10}
	}
	tpdu, err := SealTPL(dl.CI, true, meter, tplACC, dl.Status, 0, seal, dl.APL)
	if err != nil {
		return nil, err
	}
	if sec.Mode == 7 {
		var kp *uint16
		if sec.KeyInfo || sec.KeyID != 0 {
			ki := uint16(0xFF00) | 1<<4 | uint16(sec.KeyID&0x0F) // no key version, KDF-A
			kp = &ki
		}
		if tpdu, err = SealAFL(tpdu, meter, sec.Key, 1, sec.Counter, 5, kp, true); err != nil {
			return nil, err
		}
	}
	b = append(b, tpdu...)
	if len(b)-1 > 255 {
		return nil, errors.New("the downlink is longer than one datagram")
	}
	b[0] = byte(len(b) - 1)
	return b, nil
}

// EncodeIM871A frames a CRC-less telegram (sent without its L field
// unless withL) as an iM871A radio-link data request with the HCI CRC.
func EncodeIM871A(frame []byte, withL bool) []byte {
	p := frame
	if !withL {
		p = frame[1:]
	}
	b := append([]byte{IM871ARadioLink | IM871ACRC, IM871ADataReq, byte(len(p))}, p...)
	c := CRCX25(b)
	return append(append([]byte{IM871ASOF}, b...), byte(c), byte(c>>8))
}

// EncodeAmber frames a CRC-less telegram (sent without its L field unless
// withL) as an Amber command-mode data request.
func EncodeAmber(frame []byte, withL bool) []byte {
	p := frame
	if !withL {
		p = frame[1:]
	}
	b := append([]byte{AmberStart, AmberDataReq, byte(len(p))}, p...)
	var cs byte
	for _, x := range b {
		cs ^= x
	}
	return append(b, cs)
}

// The answers a meter owes to a frame we send (EN 13757-4:2025 tables 34
// and 35).
const (
	ExpectNone     = ""           // SND-NKE, CNF-IR
	ExpectACK      = "ack"        // SND-UD
	ExpectRSP      = "rsp"        // SND-UD2, REQ-UD2
	ExpectACKOrRSP = "ack-or-rsp" // REQ-UD1
)

// ExpectFor is the answer a meter owes to a frame with C field c.
func ExpectFor(c byte) string {
	switch c {
	case CSndUD:
		return ExpectACK
	case CSndUD2, CReqUD2:
		return ExpectRSP
	case CReqUD1:
		return ExpectACKOrRSP
	}
	return ExpectNone
}

// Answers reports whether a meter frame with C field c answers a frame
// that expects e (ACD and DFC bits ignored). A legacy meter may ACK an
// SND-UD2 (table 34 note c); NACK answers SND-UD and SND-UD2.
func Answers(e string, c byte) bool {
	if c&CPRM != 0 {
		return false
	}
	switch c &^ (CFCB | CFCV) {
	case CACK:
		return e != ExpectNone
	case CNACK:
		return e == ExpectACK || e == ExpectRSP
	case CRspUD:
		return e == ExpectRSP || e == ExpectACKOrRSP
	}
	return false
}

// ACCOr is the ELL access number, or def without an ELL.
func (e *ELL) ACCOr(def byte) byte {
	if e == nil {
		return def
	}
	return e.ACC
}
