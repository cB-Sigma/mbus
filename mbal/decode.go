package mbal

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/cB-Sigma/mbus/records"
	"github.com/cB-Sigma/mbus/wireless"
)

// Result is an MBAL message with its decoded upper layers.
type Result struct {
	Message *Message
	// Telegram is the decoded TPL/APL (nil when the message has no upper
	// layers or only CI-less application data).
	Telegram *wireless.Telegram
	// Meter is the meter's address when known (long TPL header, COSE kid
	// or the address the caller mapped the LPWAN identity to).
	Meter   *wireless.Header
	Records []records.Record
	// Err is why the upper layers were not (fully) decoded. Encrypted is
	// set for a telegram that is still encrypted (no or no matching key).
	Err       error
	Encrypted bool
}

// Decode decodes a message's upper layers. addr is the meter the LPWAN
// identity belongs to, if configured; keys give AES-128 keys for TPL
// security modes 5 and 7 (nil: encrypted telegrams stay undecoded).
func Decode(m *Message, addr *wireless.Header, keys wireless.KeyLookup) *Result {
	r := &Result{Message: m}
	if addr != nil {
		a := *addr
		r.Meter = &a
	}
	switch {
	case len(m.APL) > 0:
		r.Records, r.Err = records.ParseRecords(m.APL)
		return r
	case len(m.Upper) == 0:
		return r
	}
	tg, known, err := DecodeUpper(m.Upper, addr, keys)
	r.Telegram, r.Err = tg, err
	if tg != nil {
		if known {
			mt := tg.Meter
			r.Meter = &mt
		}
		r.Records = tg.Records
		r.Encrypted = tg.Mode != 0 && !tg.Encrypted
	}
	if errors.Is(err, wireless.ErrNoKey) {
		r.Encrypted = true
	}
	return r
}

// Reading is one data record as a point: named by Record.Name() (made
// unique with "_2", "_3" …), with unit and value.
type Reading struct {
	Name, Unit, Quantity string
	// Quality is Record.Quality(): "" normally, else the record's flags.
	Quality string
	Value   any
}

// Readings turns records into readings, skipping records without a
// function (such as idle fillers) that are not manufacturer data.
func Readings(recs []records.Record) []Reading {
	var out []Reading
	used := map[string]int{}
	for _, rc := range recs {
		if rc.Function == "" && !rc.Manufacturer {
			continue
		}
		name := rc.Name()
		used[name]++
		if n := used[name]; n > 1 {
			name = fmt.Sprintf("%s_%d", name, n)
		}
		out = append(out, Reading{Name: name, Unit: rc.Unit, Quantity: rc.Quantity, Quality: rc.Quality(), Value: rc.Value})
	}
	return out
}

// Meta is the message and telegram metadata for a metadata reading.
func (r *Result) Meta() map[string]any {
	m := map[string]any{"tech": r.Message.Tech}
	if r.Message.HasMBAL {
		mb := r.Message.Control.Info()
		mb["withCI"] = r.Message.WithCI
		if r.Message.RequestID != nil {
			mb["requestId"] = int(*r.Message.RequestID)
		}
		m["mbal"] = mb
	}
	if r.Meter != nil {
		m["meter"] = map[string]any{"manufacturer": r.Meter.Manufacturer, "id": r.Meter.ID,
			"version": int(r.Meter.Version), "medium": r.Meter.Medium()}
	}
	if tg := r.Telegram; tg != nil {
		m["ci"] = fmt.Sprintf("%02X", tg.CI)
		m["header"] = tg.HeaderKind
		m["securityMode"] = tg.Mode
		if tg.HeaderKind != "none" {
			m["accessNumber"] = int(tg.Access)
			m["status"] = int(tg.Status)
		}
		if tg.AFL != nil {
			m["afl"] = true
		}
		if tg.CI == wireless.CIAppError || tg.CI == wireless.CIAlarm {
			m["applicationData"] = strings.ToUpper(hex.EncodeToString(tg.APL))
		}
	}
	m["encrypted"] = r.Encrypted
	if r.Err != nil {
		m["error"] = r.Err.Error()
		if len(r.Message.Upper) > 0 && r.Telegram != nil && len(r.Records) == 0 {
			m["upper"] = strings.ToUpper(hex.EncodeToString(r.Message.Upper))
		}
	}
	return m
}
