// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package records decodes the M-Bus application layer that wired and
// wireless M-Bus share (EN 13757-3:2025): data records with their DIF,
// DIFEs, VIF and VIFEs (clause 6 and annexes A to C and E), the compact
// profiles of annex F, the OBIS codes of annex H (on
// .../libs/dlms/obis), manufacturer codes, device types and the TPL
// status byte.
//
// A record is named by its quantity, function, storage number, tariff
// and subunit ("volume", "energy_s1", "volume_flow_max", "power_t2_u1"),
// with a SenML/UCUM unit ("m3", "Wh", "Cel") and a value scaled to that
// unit; dates and times are ISO 8601 text. Records a meter sends in a
// form the standard does not define are kept (as raw hex or vif_XX) and
// the rest of the telegram is still decoded.
package records
