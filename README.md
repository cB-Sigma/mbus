# mbus

Wired M-Bus, Wireless M-Bus and OMS in pure Go: a bus master, a telegram decoder with every security mode, data records with OBIS codes, and the M-Bus adaptation layer for LPWAN.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/mbus.svg)](https://pkg.go.dev/github.com/cB-Sigma/mbus) [![test](https://github.com/cB-Sigma/mbus/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/mbus/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.27.1-00ADD8.svg)](go.mod)

The wired master follows the EN 13757-2:2018+A1:2023 link layer and the
EN 13757-3:2025 procedures: frame count bits per address, repeats and
answer timing, primary and secondary selection, the wildcard search with
collision handling, multi-telegram reads, alarms, clock
synchronisation, baud rate switching and image transfer. The wireless
side decodes EN 13757-4 frames and the EN 13757-7:2025 and OMS security
layers (ELL, AFL, TPL; security modes 2, 3, 5, 7 to 10 and 13; SITP;
compact frames), reads iM871A and Amber receiver sticks, and schedules
downlinks into meters' receive windows. One decoder of data records
serves both, with the annex H translation to OBIS codes. No cgo. It was
written for SigmaM2M, a oneM2M platform, where it serves its wired
M-Bus, Wireless M-Bus, LoRaWAN and raw-payload integrations, and has no
dependency on it.

## Features

| Area | Implemented | Not implemented |
|---|---|---|
| Wired link (EN 13757-2:2018+A1:2023) | FT1.2 frames, ACK/NACK, SND_UD2, the frame count bit per address (A1 rules), three attempts, the answer window, an idle line after broadcasts, collisions in the search | Repeater management (address 251) beyond addressing; the physical layer (a level converter does it) |
| Wired application (EN 13757-3:2025) | Variable and fixed data, multi-telegram reads, alarms, application select and reset, set primary address (with a lost-ACK check), baud rate switching, clock synchronisation (types I, J, M), synchronize, application errors, image transfer (annex I), DLMS behind CI 60h/61h and 7Ch/7Dh, transport PDUs | Manufacturer-specific procedures |
| Data records | Every DIF/VIF of clause 6 and annex C, combinable VIFEs, LVAR, dates and times (types F, G, I, J, K, L, M), compact profiles (annex F), annex H OBIS codes, manufacturer codes, device types, TPL status flags | Legacy Fahrenheit codes keep their code (no unit); manufacturer-specific payloads (no per-meter drivers) |
| Wireless link (EN 13757-4:2025) | Formats A and B, CRCs, 3-out-of-6, mode F FEC, C fields, relayed (H) and repeated frames, duplicates | The radio (a receiver stick does it); setting a stick's mode |
| Security (EN 13757-7:2025, OMS) | Modes 2, 3 (DES, deprecated), 5, 7, 8, 9, 10, 13; ELL encryption; AFL MACs and fragments; KDF-A; counters and replay detection; SITP (annex A) both ways; OMS security profiles A to D (C: mode 13 TLS, annex F); sealing for meters and gateways | Response-delay timing of downlinks (the D bit) |
| Receivers | iM871A (HCI with CRC, RSSI, timestamp), Amber command mode, raw L framing, hex lines; a downlink `Scheduler` (one downlink per receive window, answers matched by access number) | Other sticks' native protocols |
| MBAL (EN 13757-8) | The control field and the LoRaWAN, UDP, CoAP/COSE/CBOR, MIOTY and Wize layouts | Network handling (the caller's) |
| DLMS over M-Bus (EN 13757-1:2021) | Transport PDUs (`tpdu`); with [dlms](https://github.com/cB-Sigma/dlms)'s `cosem`, DLMS APDUs inside M-Bus | |

## Choosing an M-Bus library

Compared from each project's source at the versions named, in October
2026. Cells marked "not checked" were not verified in the source. Check
the projects themselves before relying on a row.

| | this module | gombus v1.1.0 (Go) | wmbusmeters 3.0.0 (C++) | libmbus 0.10.3 (C) |
|---|---|---|---|---|
| Licence | Apache-2.0 | Apache-2.0 | GPL-3.0-or-later | BSD-3-Clause |
| What it is | Go library | Go library and a command | a program (daemon and command line) with meter drivers | C library and commands |
| Wired master: search, secondary addressing, multi-telegram reads | yes, with collision handling, frame count bits per address, repeats | yes (scan, secondary addressing, readdressing) | not checked | yes |
| Wired procedures: alarms, baud switch, clock sync, image transfer, application select and reset | yes | not checked | not checked | partial (not checked in detail) |
| Wireless decoding: formats A and B, CRCs | yes, and 3-out-of-6 and mode F FEC | yes | yes | no |
| Security modes | 2, 3, 5, 7, 8, 9, 10, 13; ELL and AFL; SITP | 0, 5, 7 (13 refused) | 5, 7, ELL AES-CTR; others not checked | none |
| Compact frames, OMS profiles A to D | yes | not checked | compact frames yes; profiles not checked | no |
| Receiver sticks | iM871A, Amber, raw, hex; a downlink scheduler | none (takes the telegram) | many dongles, including iM871A, Amber and rtl-sdr | serial and TCP for wired |
| Per-meter drivers (manufacturers' own payloads) | no: standard data records only | no | over a hundred | no |
| OBIS codes (EN 13757-3 annex H), MBAL (EN 13757-8) | yes | no | no | no |
| cgo / runtime | none, pure Go | none, pure Go | a C++ program | C (cgo from Go) |

Pick this module for a Go gateway or head end that needs the security
modes beyond 5 and 7, OMS profiles, receiver sticks, downlinks, OBIS
codes or MBAL, without cgo. Pick wmbusmeters when the meters in front of
you send manufacturer-specific payloads: it has drivers for over a
hundred meters and decodes telegrams this module leaves undecoded (see
the interop results below). Pick libmbus for wired M-Bus from C, and
gombus for a small Go wired master with plain or mode 5 and 7 wireless
decoding.

## Install

```
go get github.com/cB-Sigma/mbus@latest
```

Requires Go 1.27.1 or later (tlsx, the TLS of security mode 13, needs
it).

## Quick start

```go
import (
	"github.com/cB-Sigma/mbus/wired"
	"github.com/cB-Sigma/mbus/wireless"
)

// Wired: a converter on TCP (wired.OpenSerial for a local port).
conn, _ := net.Dial("tcp", "192.0.2.20:10001")
m := wired.NewMaster(2400)
m.SetPort(wired.NewPort(conn), 2400)
found, _ := m.Search(ctx)
a, _ := m.Select(ctx, wired.Target{Secondary: &found[0]})
m.ReadTelegrams(ctx, a, 8, func(t wired.Telegram) error {
	for _, r := range t.Records {
		fmt.Println(r.Name(), r.Value, r.Unit) // volume 12.345 m3
	}
	return nil
})

// Wireless: one telegram, with the meter's key.
tg, err := wireless.Decode(frame, wireless.FormatNoCRC, func(wireless.Header) []byte { return key })
```

The examples that run and check their output are
`wired.ExampleFrame_Encode`, `wireless.ExampleDecode`,
`records.ExampleParseRecords`, `tpdu.ExampleSegmentAPDU` and
`mbal.ExampleParseUDP`. `wired.ExampleMaster` needs a bus, so it
compiles but does not run here;
[mbus-sim](https://github.com/cB-Sigma/mbus-sim) runs the same steps
against its simulated bus.

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/mbus

| Package | What it does |
|---|---|
| `wired` | FT1.2 frames; `Master` (frame count bits, repeats, selection, `SelectOne`, the search, multi-telegram reads, REQ_UD1, application select and reset, set primary address, baud switch, clock synchronisation, image transfer); responses with variable or fixed data, application errors, DLMS APDUs; `Port` over a serial port (8E1) or a TCP converter |
| `wireless` | Frame formats, CRCs, 3-out-of-6, FEC; `Decode`/`Decoder` (ELL, AFL, TPL, security modes, replay detection, SITP, compact frames with `FormatCache`); `SealTPL`, `SealAFL`, `EncodeDownlink`; `Reader` for iM871A, Amber, raw and hex receivers; `Scheduler`; TLS endpoints of mode 13 |
| `records` | Data records, names and UCUM units, compact profiles, OBIS codes (annex H), manufacturer codes, device types, status flags |
| `tpdu` | DLMS/COSEM transport PDUs over M-Bus (EN 13757-1:2021 8.2.4) |
| `mbal` | The MBAL control field and the LoRaWAN, UDP, CoAP/COSE/CBOR, MIOTY and Wize layouts (EN 13757-8) |

## Testing

```
go test -race ./...
```

The tests use the worked examples of the standards (EN 13757-3:2025
annexes F and G), every example frame of OMS Specification Volume 2
annex N with its keys, the example telegrams of the M-Bus documentation,
four heat meter answers from libmbus's test suite (BSD-3-Clause, see
NOTICE), RFC 3610, 4493 and 5649 vectors, and fuzzing of the wired frame, record
and MBAL decoders. Tests carry `// Covers: SIG-...` comments: requirement IDs of
the SigmaM2M project's compliance report, which mean nothing else here.

The master's tests against a simulated bus are in
[mbus-sim](https://github.com/cB-Sigma/mbus-sim), so this module does not
depend on its simulator.

### Interop tested against

Against the published test data of two independent implementations, on
2026-10-11 (`interop/`, a nested test-only module that fetches the data
at run time and keeps none of it here;
`cd interop && SIGMA_MBUS_INTEROP=1 go test -v ./...`).

| Peer and data | Result |
|---|---|
| libmbus 0.10.3 (commit d617bd2), every frame of test/test-frames, compared record by record with libmbus's normalised XML | 76 of 76 frames decoded; headers 75 equal, 1 different (M field 0000h printed as 0000, libmbus prints @@@); records 942 compared, 906 equal, 36 different, every difference explained: 21 manufacturer-specific VIFs whose data we keep raw where libmbus decodes the base VIF, 9 values coded invalid (we mark them, libmbus prints the digits), 4 combinable VIFEs (limit-exceed durations) that we apply and libmbus ignores, 1 "every year" date, 1 VIF with no defined meaning |
| wmbusmeters 3.0.0 (commit ac4f295), the telegrams of its driver tests and simulation files with the keys they give, compared with the JSON wmbusmeters prints | 403 frames (364 wireless, 39 wired); 340 decoded. Meter ID 327 equal, 0 different; medium 323 equal, 0 different; values 540 compared, 484 equal, 1 different (explained), 55 where the driver reads a field that is not a plain record at storage 0. Not decoded, all explained: 48 proprietary payloads that wmbusmeters' drivers cut up by byte position, 4 manufacturer-specific CI fields, 3 Diehl group telegrams in the manufacturer's own security scheme, 4 encrypted with no key in the test, 2 compact frames whose format is not given (or whose rebuilt frame fails the full-frame CRC wmbusmeters does not check), 1 DES telegram without the meter ID our check requires, 1 broken on purpose |

These runs found and fixed two decoder bugs: the order of a plain-text
VIF's text and its combinable VIFEs as Elvaco meters send them, and the
byte order of the extended link layer's payload CRC. wmbusmeters
decoding the telegrams of our simulated meter is recorded in
[mbus-sim](https://github.com/cB-Sigma/mbus-sim). Also tested: the
worked examples of the standards and OMS (above).

Not yet: a real meter, receiver stick or master on a live bus; per-meter
drivers for manufacturers' own payloads (the 48 proprietary and 3 Diehl
telegrams above), planned for v0.2.0.

## Related repositories

- [mbus-sim](https://github.com/cB-Sigma/mbus-sim): a simulated wired
  M-Bus segment, wireless meters and receiver sticks.
- [dlms](https://github.com/cB-Sigma/dlms): DLMS/COSEM, whose OBIS model
  the records use and whose client carries DLMS inside M-Bus.
- [iotcrypto](https://github.com/cB-Sigma/iotcrypto): AES-CCM for
  security mode 10 and COSE.
- [tlsx](https://github.com/cB-Sigma/tlsx): the TLS of security mode 13.

## Status

v0.x: the API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam.
