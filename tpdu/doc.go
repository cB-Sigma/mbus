// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package tpdu is the transport sub-layer that carries DLMS/COSEM APDUs
// over wired and wireless M-Bus (EN 13757-1:2021 8.2.4): an APDU split
// into transport PDUs with a fragment counter and FIN, and joined again.
package tpdu
