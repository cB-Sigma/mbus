// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package meters

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"

	"github.com/cB-Sigma/mbus/records"
	"github.com/cB-Sigma/mbus/wireless"
)

// Value is one named reading of a meter.
type Value struct {
	// Name is snake_case: a record's name (records.Record.Name) for values
	// taken from data records, or the driver's name for the value.
	Name string
	// Value is a float64, an int64, a string (dates as YYYY-MM-DD or
	// YYYY-MM-DDThh:mm:ss, alarm and status texts) or a bool.
	Value any
	// Unit is a UCUM symbol ("m3", "kWh", "Cel", "h", "a"), "" for none.
	Unit string
}

// Reading is what a driver read from one telegram.
type Reading struct {
	// Driver is the driver's name, or "" when no driver knows the meter
	// (Values then holds its data records only).
	Driver string
	// Model is the meter's product name as its maker gives it.
	Model        string
	Manufacturer string // three letters
	ID           string // the meter's identification number
	Version      byte
	// DeviceType is the EN 13757-3 device type: the one sent, or the
	// standard code a driver maps a maker's own code to.
	DeviceType byte
	// SentDeviceType is the device type the telegram carried.
	SentDeviceType byte
	// Values are the data records' values (records.Record.Name), then
	// what the driver adds.
	Values []Value
	// Records are the data records the values were taken from, including
	// records a driver decoded from the manufacturer's payload.
	Records []records.Record

	keys  wireless.KeyLookup
	meter wireless.Header // as the driver reads it (Diehl addresses rearranged)
}

// key returns the meter's key from the caller's KeyLookup, or nil.
func (r *Reading) key() []byte {
	if r.keys == nil {
		return nil
	}
	return r.keys(r.meter)
}

// meterHeader is the meter's header as drivers look it up: the decoded
// one, except where a maker arranges the address differently (Diehl).
func meterHeader(tg *wireless.Telegram) wireless.Header {
	if h, ok := diehlHeader(tg); ok {
		return h
	}
	return tg.Meter
}

// Get returns the value of that name.
func (r *Reading) Get(name string) (Value, bool) {
	for _, v := range r.Values {
		if v.Name == name {
			return v, true
		}
	}
	return Value{}, false
}

// Float returns a numeric value of that name.
func (r *Reading) Float(name string) (float64, bool) {
	v, ok := r.Get(name)
	if !ok {
		return 0, false
	}
	switch x := v.Value.(type) {
	case float64:
		return x, true
	case int64:
		return float64(x), true
	}
	return 0, false
}

// set adds or replaces a value.
func (r *Reading) set(name string, v any, unit string) {
	for i := range r.Values {
		if r.Values[i].Name == name {
			r.Values[i] = Value{name, v, unit}
			return
		}
	}
	r.Values = append(r.Values, Value{name, v, unit})
}

// MVT is a manufacturer, version and device type a driver reads. A
// negative Version or DeviceType matches any.
type MVT struct {
	Manufacturer string
	Version      int
	DeviceType   int
}

func (m MVT) match(h wireless.Header) bool {
	return m.Manufacturer == h.Manufacturer && (m.Version < 0 || m.Version == int(h.Version)) &&
		(m.DeviceType < 0 || m.DeviceType == int(h.DeviceType))
}

// Driver reads one family of meters.
type Driver struct {
	// Name is the driver's name: maker and model, lower case, with
	// hyphens ("kamstrup-multical21").
	Name string
	// Model is the product name.
	Model string
	// Detect lists the manufacturer, version and device type combinations
	// the driver reads.
	Detect []MVT
	// DeviceTypes maps device type codes the maker uses outside
	// EN 13757-3 to the standard ones.
	DeviceTypes map[byte]byte
	// Decode adds what the driver reads to r. tg is the decoded telegram
	// and err the decoder's error, which the driver may resolve: a
	// manufacturer's CI field or security mode leaves the payload in
	// tg.APL. A driver that resolves it returns nil.
	Decode func(tg *wireless.Telegram, err error, r *Reading) error
}

var (
	mu       sync.RWMutex
	registry []*Driver
)

// Register adds a driver. A later driver for the same manufacturer,
// version and type takes precedence, so callers can override the built-in
// ones.
func Register(d *Driver) {
	mu.Lock()
	defer mu.Unlock()
	registry = append(registry, d)
}

// Drivers lists the registered drivers by name.
func Drivers() []*Driver {
	mu.RLock()
	defer mu.RUnlock()
	out := append([]*Driver(nil), registry...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Lookup returns the driver for a meter, or nil. Exact version and type
// matches win over wildcards; among equals the last registered wins.
func Lookup(h wireless.Header) *Driver {
	mu.RLock()
	defer mu.RUnlock()
	var best *Driver
	bestScore := -1
	for _, d := range registry {
		for _, m := range d.Detect {
			if !m.match(h) {
				continue
			}
			// Exact version and type first; among those, a driver that
			// decodes something over one that only names the model.
			score := 0
			if m.Version >= 0 {
				score += 2
			}
			if m.DeviceType >= 0 {
				score += 2
			}
			if d.Decode != nil {
				score++
			}
			if score >= bestScore {
				best, bestScore = d, score
			}
		}
	}
	return best
}

// ByName returns the driver of that name, or nil.
func ByName(name string) *Driver {
	mu.RLock()
	defer mu.RUnlock()
	for i := len(registry) - 1; i >= 0; i-- {
		if registry[i].Name == name {
			return registry[i]
		}
	}
	return nil
}

// ErrNoDriver is returned when the decoder could not read a telegram and
// no driver for the meter resolves it.
var ErrNoDriver = errors.New("no driver reads this meter's payload")

// Read reads a decoded telegram with the driver for its meter: tg and err
// are what wireless.Decode returned. Without a driver the reading holds
// the data records' values; with one, the driver's values follow them. A
// decoder error that the driver does not resolve is returned (wrapped
// with ErrNoDriver when there is no driver), with the reading so far.
func Read(tg *wireless.Telegram, err error) (*Reading, error) {
	return ReadKeys(tg, err, nil)
}

// ReadKeys is Read for drivers whose manufacturer layout is encrypted
// with the meter's key (keys may be nil; the makers' default keys a
// caller set with SetMakerKeys are tried then).
func ReadKeys(tg *wireless.Telegram, err error, keys wireless.KeyLookup) (*Reading, error) {
	if tg == nil {
		if err == nil {
			err = errors.New("no telegram")
		}
		return nil, err
	}
	h := meterHeader(tg)
	return readWith(Lookup(h), h, tg, err, keys)
}

// ReadWith reads a telegram with the given driver (nil: records only).
func ReadWith(d *Driver, tg *wireless.Telegram, err error) (*Reading, error) {
	return readWith(d, meterHeader(tg), tg, err, nil)
}

func readWith(d *Driver, h wireless.Header, tg *wireless.Telegram, err error, keys wireless.KeyLookup) (*Reading, error) {
	r := &Reading{Manufacturer: h.Manufacturer, ID: h.ID, Version: h.Version, DeviceType: h.DeviceType, SentDeviceType: h.DeviceType, keys: keys, meter: h}
	if err == nil || recordsTail(tg, err) {
		r.addRecords(tg.Records)
	}
	if d == nil {
		if err != nil && !recordsTail(tg, err) {
			return r, fmt.Errorf("%w: %w", ErrNoDriver, err)
		}
		return r, err
	}
	r.Driver, r.Model = d.Name, d.Model
	if t, ok := d.DeviceTypes[h.DeviceType]; ok {
		r.DeviceType = t
	}
	if d.Decode == nil {
		return r, err
	}
	return r, d.Decode(tg, err, r)
}

// recordsTail reports a records error after some records were decoded.
func recordsTail(tg *wireless.Telegram, err error) bool {
	return err != nil && len(tg.Records) > 0 && strings.HasPrefix(err.Error(), "record ")
}

// ReadRecords reads data records from a wired answer (or any source)
// with the driver for the meter.
func ReadRecords(manufacturer, id string, version, deviceType byte, recs []records.Record) *Reading {
	h := wireless.Header{Manufacturer: manufacturer, ID: id, Version: version, DeviceType: deviceType}
	mf, _ := records.ManufacturerField(manufacturer)
	h.MField = mf
	tg := &wireless.Telegram{Header: h, Meter: h, Records: recs}
	r, _ := Read(tg, nil)
	return r
}

func (r *Reading) addRecords(recs []records.Record) {
	for _, rec := range recs {
		r.Records = append(r.Records, rec)
		if rec.Quantity == "" || rec.Invalid {
			continue
		}
		v := rec.Value
		if rec.Manufacturer && rec.BaseValue != nil {
			v = rec.BaseValue // the VIF's reading of a manufacturer-marked record
		}
		r.Values = append(r.Values, Value{rec.Name(), v, rec.Unit})
	}
	// A heat meter's temperature difference, when it sends both
	// temperatures but not the difference.
	f, okF := r.Float("flow_temperature")
	t, okR := r.Float("return_temperature")
	if _, has := r.Get("temperature_difference"); okF && okR && !has {
		r.set("temperature_difference", round(f-t, 6), "K")
	}
}

// round keeps a computed value free of binary noise (x/3 and the like).
func round(x float64, digits int) float64 {
	p := math.Pow(10, float64(digits))
	return math.Round(x*p) / p
}

// Medium is the name of the reading's device type.
func (r *Reading) Medium() string { return records.Medium(r.DeviceType) }
