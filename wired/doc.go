// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package wired is wired M-Bus: the EN 13757-2:2018+A1:2023 link layer
// (FT1.2 frames, ACK and NACK, the frame count bit per address, repeats,
// answer timing, collisions) and the EN 13757-3:2025 application
// procedures of a master: primary and secondary addressing (a command to
// a meter named with wildcards goes only to one selected meter), the
// secondary address search, multi-telegram reads, class 1 data and
// alarms, application select and reset, set primary address, baud rate
// switch, clock synchronisation and image transfer (annex I); plus the
// fixed data structure, application errors and DLMS/COSEM responses.
//
// Master talks over a Port: a local serial port behind a level converter
// (OpenSerial, 8E1) or a transparent serial-to-IP converter (DialTCP).
// Data records are decoded by package records.
package wired
