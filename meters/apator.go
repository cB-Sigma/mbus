// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package meters

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/cB-Sigma/mbus/wireless"
)

// Apator (APA, APT) meters: older water meters send the volume after a
// manufacturer CI field; the AT-WMBUS-16-2 module sends a tagged
// manufacturer record; the E-ITN heat cost allocators and the NA-1 water
// meter module have layouts of their own.

// mfctRecord returns the bytes of the manufacturer-specific data record
// (DIF 0Fh or 1Fh) of a decoded telegram.
func mfctRecord(tg *wireless.Telegram) ([]byte, bool) {
	for _, rec := range tg.Records {
		if rec.DIF == 0x0F || rec.DIF == 0x1F {
			return rec.Raw, true
		}
	}
	return nil, false
}

// apator162Lengths is the length of the data after each tag of the
// AT-WMBUS-16-2 manufacturer record (0: tag not known).
func apator162Len(tag byte) int {
	switch {
	case tag == 0x00, tag == 0x10, tag == 0x42, tag == 0xA0, tag == 0xA1, tag == 0xA4, tag == 0xF0:
		return 4
	case tag == 0x01, tag == 0x44, tag == 0xA6, tag >= 0xB6 && tag <= 0xBF, tag >= 0xC0 && tag <= 0xC7, tag == 0xD0, tag == 0xD3:
		return 3
	case tag == 0x11, tag == 0x41, tag == 0x43, tag == 0xB4, tag == 0xA7, tag == 0xA8, tag >= 0xAA && tag <= 0xAD:
		return 2
	case tag == 0x40, tag == 0x8B, tag == 0x8C:
		return 6
	case tag >= 0x71 && tag <= 0x7C:
		return 1 + 4*int(tag-0x70+1)
	case tag <= 0x84 && tag >= 0x80, tag == 0x86, tag == 0x87:
		return 10
	case tag == 0x85, tag == 0x88, tag == 0x8F:
		return 11
	case tag == 0x8A:
		return 9
	case tag == 0x8E:
		return 7
	case tag == 0xA2, tag == 0xA5, tag == 0xA9, tag == 0xAF:
		return 1
	case tag == 0xA3:
		return 7
	case tag == 0xB0:
		return 5
	case tag == 0xB1, tag == 0xB3:
		return 8
	case tag == 0xB2, tag == 0xB5:
		return 16
	}
	return 0
}

// apatorEITNDates decodes the E-ITN's 16-bit dates (day, month, years
// since 2000 in 5 bits each from bit 0, 5 and 9).
func apatorEITNDate(v uint64) string {
	return ymd(2000+int(v>>9&0x1F), int(v>>5&0x0F), int(v&0x1F))
}

func init() {
	Register(&Driver{
		Name: "apator-08", Model: "Apator water meter (CI A0h layout)",
		Detect: []MVT{{"APT", 0x03, 0x03}, {"APT", 0x0F, 0x0F}},
		Decode: func(tg *wireless.Telegram, err error, r *Reading) error {
			p, err := mfctPayload(tg, err)
			if err != nil {
				return err
			}
			if err := need(p, 4); err != nil {
				return err
			}
			// Bytes 0-3: the volume in thirds of a litre.
			r.set("volume", round(float64(le(p[:4]))/3000, 6), "m3")
			return nil
		},
	})
	Register(&Driver{
		Name: "apator-17-2", Model: "Apator water meter (device type 11h)",
		Detect:      []MVT{{"APT", 0x04, 0x11}},
		DeviceTypes: map[byte]byte{0x11: 0x07},
		Decode: func(tg *wireless.Telegram, err error, r *Reading) error {
			p, err := mfctPayload(tg, err)
			if err != nil {
				return err
			}
			if err := need(p, 4); err != nil {
				return err
			}
			// Bytes 0-3: the volume in thirds of a cubic metre.
			r.set("volume", round(float64(le(p[:4]))/3, 6), "m3")
			return nil
		},
	})
	Register(&Driver{
		Name: "apator-at-wmbus-16-2", Model: "Apator AT-WMBUS-16-2 water meter module",
		Detect: []MVT{{"APA", 0x05, 0x06}, {"APA", 0x05, 0x07}},
		Decode: func(tg *wireless.Telegram, err error, r *Reading) error {
			if err != nil {
				return err
			}
			p, ok := mfctRecord(tg)
			if !ok {
				return nil
			}
			// Seven status bytes, then tagged fields; tag 10h holds the
			// volume in litres. FFh fills up to a closing checksum.
			if len(p) < 7 {
				return errShort
			}
			r.set("status_raw", fmt.Sprintf("%X", p[:7]), "")
			for i := 7; i < len(p) && p[i] != 0xFF; {
				tag := p[i]
				n := apator162Len(tag)
				if n == 0 || i+1+n > len(p) {
					break // the checksum, or a tag not known
				}
				if tag == 0x10 {
					r.set("volume", float64(le(p[i+1:i+5]))/1000, "m3")
				}
				i += 1 + n
			}
			return nil
		},
	})
	Register(&Driver{
		Name: "apator-e-itn", Model: "Apator E-ITN 30 heat cost allocator",
		Detect: []MVT{{"APA", 0x04, 0x08}, {"APT", 0x04, 0x08}},
		Decode: func(tg *wireless.Telegram, err error, r *Reading) error {
			p, err := mfctPayload(tg, err)
			if err != nil {
				return err
			}
			if tg.CI == 0xB6 {
				// CI B6h: a length, that many bytes, then A0h and the
				// layout of CI A0h.
				if err := need(p, 1); err != nil {
					return err
				}
				n := int(p[0])
				if err := need(p, n+2); err != nil {
					return err
				}
				if p[n+1] != 0xA0 {
					return fmt.Errorf("E-ITN: CI B6h without A0h after %d bytes", n)
				}
				p = p[n+2:]
			}
			if err := need(p, 15); err != nil {
				return err
			}
			// Byte 0: the low byte of the season start date (the high
			// byte is A0h); 3-4: units at the season start; 5-6: the date
			// the seal was broken (0: never); 7-8: units now; 9-10: today;
			// 11-12 and 13-14: average room temperature of the previous
			// and current period (1/256 Cel).
			esb := le(p[5:7])
			r.set("hca_units", float64(le(p[7:9])), "")
			r.set("hca_units_previous_season", float64(le(p[3:5])), "")
			r.set("current_date", apatorEITNDate(le(p[9:11])), "")
			r.set("season_start_date", apatorEITNDate(0xA000|uint64(p[0])), "")
			if esb != 0 {
				r.set("seal_broken_date", apatorEITNDate(esb), "")
				r.set("status", "seal_broken", "")
			} else {
				r.set("status", "ok", "")
			}
			r.set("room_temperature_previous_average", float64(le(p[11:13]))/256, "Cel")
			r.set("room_temperature_average", float64(le(p[13:15]))/256, "Cel")
			return nil
		},
	})
	Register(&Driver{
		Name: "apator-na-1", Model: "Apator NA-1 water meter module",
		Detect: []MVT{{"APA", 0x14, 0x07}},
		Decode: func(tg *wireless.Telegram, err error, r *Reading) error {
			p, err := mfctPayload(tg, err)
			if err != nil {
				return err
			}
			if err := need(p, 18); err != nil {
				return err
			}
			// Byte 0: an access number for the IV; byte 1: frame status;
			// bytes 2-17: AES-128-CBC with the security mode 5 IV (M, A,
			// that access number eight times).
			fs := p[1]
			r.set("frame_status", flags(uint64(fs), map[uint64]string{
				0x01: "summer_time", 0x02: "history", 0x04: "max_speed_exceeded", 0x08: "device_access_error",
				0x10: "two_way_blocked", 0x20: "installation_frame", 0x40: "wrong_temperature", 0x80: "service_event",
			}, "ok"), "")
			key := r.key()
			if key == nil {
				return wireless.ErrNoKey
			}
			blk, err := aes.NewCipher(key)
			if err != nil {
				return err
			}
			iv := make([]byte, 16)
			iv[0], iv[1] = byte(tg.Header.MField), byte(tg.Header.MField>>8)
			copy(iv[2:8], tg.Header.A[:])
			for i := 8; i < 16; i++ {
				iv[i] = p[0]
			}
			d := make([]byte, 16)
			cipher.NewCBCDecrypter(blk, iv).CryptBlocks(d, p[2:18])
			// d[1:5]: the volume, packed: a multiplier 10^n in bits 4-5,
			// litres in the other bits; d[5:9]: seconds since 2000;
			// d[9:14]: the age of the historic value (hours) and its
			// difference; d[14], d[15]: current and historic status.
			raw := le(d[1:5])
			mult := []uint64{1, 10, 100, 1000}[raw>>4&3]
			total := float64(((raw>>8)*16+raw%16)*mult) / 1000
			r.set("volume", total, "m3")
			secs := le(d[5:9])
			r.set("meter_datetime", since2000(secs), "")
			age := uint64(d[10]>>2)*256 + uint64(d[9])
			delta := uint64(d[13])<<18 | uint64(d[12])<<10 | uint64(d[11])<<2 | uint64(d[10]&3)
			r.set("history_age", float64(age), "h")
			r.set("volume_history", round(total-float64(delta*mult)/1000, 6), "m3")
			r.set("history_datetime", since2000(secs-age*3600), "")
			alarm := map[uint64]string{
				0x01: "battery", 0x02: "magnetic_field", 0x04: "disconnected", 0x08: "leak",
				0x10: "no_change", 0x20: "reverse_flow", 0x40: "max_flow", 0x80: "min_flow",
			}
			r.set("current_status", flags(uint64(d[14]), alarm, "ok"), "")
			r.set("history_status", flags(uint64(d[15]), alarm, "ok"), "")
			return nil
		},
	})
}

var _ = errors.New
