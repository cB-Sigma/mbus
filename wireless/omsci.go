package wireless

import (
	"encoding/binary"
	"errors"

	"github.com/cB-Sigma/mbus/records"
)

// TPL CI fields whose application data are not data records, or that
// carry no application data (OMS Volume 2 v5.0.1 Table 42; EN 13757-7 CI
// field table): the short and long header variants. Annex N shows 6Ch
// (N.8.2), 6Eh with a short header (N.9) and 8Bh (N.6.2, N.8.2, N.10).
const (
	CIToMeterShort byte = 0x5A // command to a device, short header (5Bh: long)
	CIClockLong    byte = 0x6C // clock synchronisation, long header
	CIClockShort   byte = 0x6D // clock synchronisation, short header
	CIAppErrShort  byte = 0x6E // application error from the device, short header
	CIAppErrLong   byte = 0x6F // application error from the device, long header
	CIAlarmShort   byte = 0x74 // alarm from the device, short header
	CIAlarmLong    byte = 0x75 // alarm from the device, long header
	CIPureShort    byte = 0x8A // TPL only, from the device, short header
	CIPureLong     byte = 0x8B // TPL only, from the device, long header

	// DLMS/COSEM APDUs carried by M-Bus (EN 13757-1:2021 9.2.1 Figure 11,
	// EN 13757-7 CI table, EN 62056-7-3): to the meter 60h (long header)
	// and 61h (short), from the meter 7Ch (long) and 7Dh (short). The APDU
	// is kept as bytes; it is not decoded here.
	CIDLMSToMeterLong  byte = 0x60
	CIDLMSToMeterShort byte = 0x61
	CIDLMSLong         byte = 0x7C
	CIDLMSShort        byte = 0x7D
)

// IsDLMS reports a CI whose application data is a DLMS/COSEM APDU.
func IsDLMS(ci byte) bool {
	return ci == CIDLMSToMeterLong || ci == CIDLMSToMeterShort || ci == CIDLMSLong || ci == CIDLMSShort
}

func longHeaderCI(ci byte) bool {
	return ci == CIClockLong || ci == CIAppErrLong || ci == CIAlarmLong || ci == CIPureLong || ci == CIDLMSLong || ci == CIDLMSToMeterLong
}

// RawAPL reports a CI whose application data is kept as bytes
// (Telegram.APL) instead of being read as data records.
func RawAPL(ci byte) bool {
	switch ci {
	case CIClockLong, CIClockShort, CIAppErrShort, CIAppErrLong, CIAlarmShort, CIAlarmLong, CIPureShort, CIPureLong:
		return true
	case CIDLMSToMeterLong, CIDLMSToMeterShort, CIDLMSLong, CIDLMSShort:
		return true
	}
	return false
}

// tplHeader reads the short or long TPL header of the CIs above (p starts
// after the CI field).
func (tg *Telegram) tplHeader(p []byte) ([]byte, error) {
	if !longHeaderCI(tg.CI) {
		if len(p) < 4 {
			return nil, errTruncated
		}
		tg.HeaderKind = "short"
		tg.Access, tg.Status, tg.Config = p[0], p[1], binary.LittleEndian.Uint16(p[2:4])
		return p[4:], nil
	}
	if len(p) < 12 {
		return nil, errTruncated
	}
	tg.HeaderKind = "long"
	m := Header{MField: binary.LittleEndian.Uint16(p[4:6]), Version: p[6], DeviceType: p[7]}
	copy(m.A[:4], p[:4])
	m.A[4], m.A[5] = p[6], p[7]
	m.Manufacturer, m.ID = records.ManufacturerCode(m.MField), BCDID(p[:4])
	tg.Meter = m
	tg.Access, tg.Status, tg.Config = p[8], p[9], binary.LittleEndian.Uint16(p[10:12])
	return p[12:], nil
}

// OMS security profiles (OMS Volume 2 v5.0.1 clause 9.1, Table 43).
const (
	OMSProfileNone = "none" // security mode 0, no AFL MAC
	OMSProfileA    = "A"    // mode 5 (AES-CBC, persistent key), no MAC
	OMSProfileB    = "B"    // mode 7 with KDF-A and an AFL AES-CMAC of 8 bytes
	OMSProfileC    = "C"    // mode 13 (TLS)
	OMSProfileD    = "D"    // mode 10 with KDF-A, the counter in the TPL and an 8-byte CCM tag
)

// OMSProfile classifies a decoded telegram's protection by the OMS
// security profiles, or returns "" when the combination of security mode,
// key derivation and authentication is none of them (for example mode 7
// without the AFL MAC, a 4-byte CCM tag, modes 8 and 9, or a MAC on a
// mode 0 telegram).
func OMSProfile(tg *Telegram) string {
	if tg == nil || tg.HeaderKind == "none" && tg.AFL == nil {
		if tg != nil && tg.Mode == 0 {
			return OMSProfileNone
		}
		return ""
	}
	var afl *AFL
	var aflMAC bool
	var at byte
	if tg.AFL != nil {
		afl = tg.AFL
		aflMAC = afl.has.mac
		at = afl.MCL & 0x0F
	}
	kdf := -1
	if tg.Sec != nil {
		kdf = tg.Sec.KDF
	}
	switch tg.Mode {
	case 0:
		if !aflMAC {
			return OMSProfileNone
		}
	case 5:
		// Footnote b of Table 43: without an AFL the MAC mode is AT = 0.
		if !aflMAC && at == 0 {
			return OMSProfileA
		}
	case 7:
		if aflMAC && at == 5 && afl.has.mcr && kdf == 1 {
			return OMSProfileB
		}
	case 10:
		// Table 22: Z is always 1 (the counter is in the TPL).
		if kdf == 1 && tg.Sec != nil && tg.Sec.TagLen == 8 && tg.Sec.CounterFrom == "tpl" {
			return OMSProfileD
		}
	case 13:
		return OMSProfileC
	}
	return ""
}

// cbcBlocksField is the NNNN subfield of the configuration field of modes
// 5 and 7 for n encrypted blocks: 1111b (all that follows) from 15 blocks
// on, which leaves no room for unencrypted data after them (OMS Volume 2
// 7.2.4.3, 7.2.4.4).
func cbcBlocksField(n int, unencrypted int) (uint16, error) {
	switch {
	case n < 15:
		return uint16(n) << 4, nil
	case unencrypted == 0:
		return 0x0F << 4, nil
	}
	return 0, errors.New("partial encryption of more than 14 blocks cannot be announced (N = 1111b means all)")
}

// linkBidirectional is the link control bit B of a received telegram: the
// ELL's CC field when there is an ELL, else the configuration field of
// security modes 0 and 5, which carries the same bits (OMS Volume 2
// 5.2.2.2.3 and 7.2.4.8: the CC field wins when both exist).
func linkBidirectional(tg *Telegram) bool {
	if tg.ELL != nil {
		return tg.ELL.CC&CCBidirectional != 0
	}
	return tg.HeaderKind != "none" && (tg.Mode == 0 || tg.Mode == 5) && tg.Config&0x8000 != 0
}
