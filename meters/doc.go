// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package meters reads Wireless M-Bus telegrams with per-meter drivers:
// manufacturers' own payloads (a manufacturer-specific CI field, a
// manufacturer record, a maker's security scheme) and the model of meters
// whose data records are standard.
//
// Decode a telegram with package wireless, then hand the result and its
// error to Read:
//
//	tg, err := wireless.Decode(frame, wireless.FormatAuto, keys)
//	r, err := meters.ReadKeys(tg, err, keys)
//	v, _ := r.Float("volume")
//
// A Reading holds the data records' values (named as records.Record.Name)
// and what the driver adds. Register adds or overrides drivers. The
// layouts were established from public descriptions and checked against
// published test telegrams (see the module's PROVENANCE); none is
// certified by its manufacturer.
package meters
