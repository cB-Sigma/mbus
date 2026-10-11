// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package wireless is Wireless M-Bus and OMS: the EN 13757-4 link layer
// (frame formats A and B with their CRCs, the 3-out-of-6 code, C fields,
// radio modes, FEC of mode F), the EN 13757-7:2025 transport and security
// layers (ELL, AFL with fragmentation, TPL short and long headers,
// security modes 5 and 7 to 10 and the deprecated DES modes 2 and 3,
// KDF-A, message counters with replay detection, mode 13 TLS records),
// security information transfer (SITP, annex A), compact frames (EN
// 13757-3:2025 annex G), the OMS Volume 2 profiles, the framings of
// receiver sticks (iM871A, Amber, raw, hexadecimal lines), and frames a
// gateway sends to bidirectional meters with a scheduler that sends one
// frame per receive window (Scheduler).
//
// Decode (or a Decoder, which keeps fragments and counters) turns a frame
// into a Telegram with the meter's header, the security facts and the
// data records (package records). Mode 13 TLS endpoints use
// github.com/cB-Sigma/tlsx, a crypto/tls fork with the
// brainpool curves and TLS 1.2 features BSI TR-03116-3 needs.
package wireless
