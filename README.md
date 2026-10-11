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
compact frames), reads and configures iM871A, Amber and CUL receiver
sticks and reads rtl-wmbus, and schedules downlinks into meters' receive
windows with their response delays. One decoder of data records serves
both, with the annex H translation to OBIS codes, and per-meter drivers
read the manufacturers' own payloads (Techem, Apator, Diehl/IZAR, Qundis,
BFW, Zenner and others) and name 90 more meter models. No cgo. It was
written for SigmaM2M, a oneM2M platform, where it serves its wired
M-Bus, Wireless M-Bus, LoRaWAN and raw-payload integrations, and has no
dependency on it.

## Features

| Area | Implemented | Not implemented |
|---|---|---|
| Wired link (EN 13757-2:2018+A1:2023) | FT1.2 frames, ACK/NACK, SND_UD2, the frame count bit per address (A1 rules), three attempts, the answer window, an idle line after broadcasts, collisions in the search, management frames to the primary master repeater (address 251, `Master.Repeater`) | Named repeater commands: the standard reserves address 251 but leaves its commands to each repeater's maker; the physical layer (a level converter does it) |
| Wired application (EN 13757-3:2025) | Variable and fixed data, multi-telegram reads, alarms, application select and reset, set primary address (with a lost-ACK check), baud rate switching, clock synchronisation (types I, J, M), synchronize, application errors, image transfer (annex I), DLMS behind CI 60h/61h and 7Ch/7Dh, transport PDUs | Manufacturer-specific procedures |
| Data records | Every DIF/VIF of clause 6 and annex C, combinable VIFEs, LVAR, dates and times (types F, G, I, J, K, L, M), compact profiles (annex F), annex H OBIS codes, manufacturer codes, device types, TPL status flags; a standard VIF followed by a manufacturer VIFE also decoded as the VIF says (`Record.BaseValue`) | Legacy Fahrenheit codes keep their code (no unit) |
| Meter drivers (`meters`) | Manufacturers' own payloads: Techem compact V, vario 4, radio 3 and 4, FHKV data III, smoke detector; Apator 08, 17-2, AT-WMBUS-16-2, E-ITN, NA-1 (AES); Diehl/Hydrometer/Sappel PRIOS (IZAR) and "real data" scrambling, with keys the caller supplies (`SetMakerKeys` or the meter's key; the library ships no keys); BFW 240 radio; Zenner 0Bh; Qundis walk-by records (Q water, Q heat, Q caloric); B METERS RFM-TX1's clock; 90 more models named from their M, version and device type; device types makers use outside the standard mapped; `Register` adds or overrides drivers | The volume of the B METERS RFM-TX1 (obfuscated with a table we know no public description of); further manufacturer fields of meters whose standard records already decode (see the interop results) |
| Wireless link (EN 13757-4:2025) | Formats A and B, CRCs, 3-out-of-6, mode F FEC, C fields, relayed (H) and repeated frames, duplicates; compact frames whose Full-Frame-CRC fails can be accepted with a warning (`FormatCache.IgnoreFullFrameCRC`, off by default) | The radio (a receiver stick does it) |
| Security (EN 13757-7:2025, OMS) | Modes 2, 3 (DES, deprecated; mode 2 optionally checked by its 2F2F fillers as wmbusmeters does, `Decoder.DESCheck2F2F`), 5, 7, 8, 9, 10, 13; ELL encryption; AFL MACs and fragments; KDF-A; counters and replay detection; SITP (annex A) both ways; OMS security profiles A to D (C: mode 13 TLS, annex F); sealing for meters and gateways; the payload of a maker's own security mode or CI field kept for the drivers | |
| Receivers | iM871A (HCI with CRC, RSSI, timestamp), Amber command mode, CUL/nanoCUL (culfw), rtl-wmbus text, raw L framing, hex lines; setting the radio mode of iM871A, Amber and CUL sticks (`ConfigureIM871A`, `ConfigureAmber`, `ConfigureCUL`); a downlink `Scheduler` (one downlink per receive window, answers matched by access number, frames timed into the response delay of modes S, T and C, slow or fast by the D bit) | Radiocrafts and Embit sticks' native protocols; response delays of modes R, N and F |
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
| Security modes | 2, 3, 5, 7, 8, 9, 10, 13; ELL and AFL; SITP; Diehl scrambling | 0, 5, 7 (13 refused) | 5, 7, ELL AES-CTR, DES mode 2, Diehl scrambling; others not checked | none |
| Compact frames, OMS profiles A to D | yes | not checked | compact frames yes; profiles not checked | no |
| Receiver sticks | iM871A, Amber, CUL, rtl-wmbus, raw, hex; setting iM871A, Amber and CUL modes; a downlink scheduler | none (takes the telegram) | many dongles, including iM871A, Amber, CUL, RC1180, rtl-sdr (rtl-wmbus and rtl_433) | serial and TCP for wired |
| Per-meter drivers (manufacturers' own payloads) | 20 drivers of manufacturer data and 90 more models named (every manufacturer payload of wmbusmeters' tests but one meter's volume; see below) | no | over a hundred, with more manufacturer fields per meter | no |
| OBIS codes (EN 13757-3 annex H), MBAL (EN 13757-8) | yes | no | no | no |
| cgo / runtime | none, pure Go | none, pure Go | a C++ program | C (cgo from Go) |

Pick this module for a Go gateway or head end that needs the security
modes beyond 5 and 7, OMS profiles, receiver sticks, downlinks, OBIS
codes or MBAL, without cgo; its drivers read every manufacturer payload
in wmbusmeters' test data but one. Pick wmbusmeters when you need a
ready daemon, its wider range of receivers (RC1180, rtl_433), or the
manufacturer fields it reads beyond the standard records for meters
such as Waterstar M, B METERS Hydrodigit and Schneider iEM3000 (about 430 of the
3,264 values its tests print are not among ours, see below). Pick
libmbus for wired M-Bus from C, and
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
	"github.com/cB-Sigma/mbus/meters"
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

// Wireless: one telegram, with the meter's key, read with its driver.
keys := func(wireless.Header) []byte { return key }
tg, err := wireless.Decode(frame, wireless.FormatNoCRC, keys)
r, err := meters.ReadKeys(tg, err, keys) // r.Driver "techem-compact5", r.Float("energy")
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
| `wired` | FT1.2 frames; `Master` (frame count bits, repeats, selection, `SelectOne`, the search, multi-telegram reads, REQ_UD1, application select and reset, set primary address, baud switch, clock synchronisation, image transfer, frames to the repeater at address 251); responses with variable or fixed data, application errors, DLMS APDUs; `Port` over a serial port (8E1) or a TCP converter |
| `wireless` | Frame formats, CRCs, 3-out-of-6, FEC; `Decode`/`Decoder` (ELL, AFL, TPL, security modes, replay detection, SITP, compact frames with `FormatCache`); `SealTPL`, `SealAFL`, `EncodeDownlink`; `Reader` for iM871A, Amber, CUL, rtl-wmbus, raw and hex receivers; `ConfigureIM871A`, `ConfigureAmber`, `ConfigureCUL`; `Scheduler` with `ResponseDelay`; TLS endpoints of mode 13 |
| `records` | Data records, names and UCUM units, compact profiles, OBIS codes (annex H), manufacturer codes, device types, status flags |
| `meters` | Per-meter drivers: `Read`/`ReadKeys` a decoded telegram into named values, `Lookup`, `Register`, `Drivers`, `SetMakerKeys` and `DefaultKey` (makers' default keys, supplied by the caller; none ship) |
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
and MBAL decoders. The meter drivers' unit tests build telegrams in each
layout with values of their own; the stick commands are tested against
byte vectors and a fake stick on a pipe. Tests carry `// Covers: SIG-...` comments: requirement IDs of
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
| libmbus 0.10.3 (commit d617bd2), every frame of test/test-frames, compared record by record with libmbus's normalised XML | 76 of 76 frames decoded; headers 75 equal, 1 different (M field 0000h printed as 0000, libmbus prints @@@); records 942 compared, 927 equal (the 21 records with a manufacturer VIFE after a standard VIF compared by `BaseValue`), 15 different, every difference explained: 9 values coded invalid (we mark them, libmbus prints the digits), 4 combinable VIFEs (limit-exceed durations) that we apply and libmbus ignores, 1 "every year" date, 1 VIF with no defined meaning |
| wmbusmeters 3.0.0 (commit ac4f295), the telegrams of its driver tests and simulation files with the keys they give, compared with the JSON wmbusmeters prints | 403 frames (364 wireless, 39 wired); 396 decoded as the library ships (398 with the opt-in `FormatCache.IgnoreFullFrameCRC`, see below), 54 of them by a meter driver (`meters`): 47 of the 48 proprietary payloads (the 48th is the too-short telegram below), the 4 manufacturer-specific CI fields and the 3 Diehl telegrams (one scrambled, unscrambled with a default key; two stored unscrambled, read with `AcceptPlainDiehl`), with the Diehl default keys the test reads from the wmbusmeters checkout and passes to `SetMakerKeys`; the DES telegram decodes with `DESCheck2F2F`. Meter ID 381 equal, 0 different; medium 377 equal, 0 different. Every numeric field and date wmbusmeters prints, looked for among our reading's values of the same unit (names differ between the projects, so by value): 3,264 compared, 2,840 found, 424 not (with the lenient option on; they are fields the wmbusmeters drivers read from manufacturer data or compute, listed per driver by the test, the largest Waterstar M, B METERS Hydrodigit and Hydroclima, Schneider iEM3000 and Qundis Q heat monthly deltas); 71 more are dates coded invalid that wmbusmeters prints as dates (years past 2100, month 15), not compared. The frames not decoded are listed below. |

The 7 wmbusmeters frames the library does not decode by default:

| Telegram (wmbusmeters file:line) | Reason | Decodes with |
|---|---|---|
| generated_tests.xmq:1337 (Kamstrup flowIQ 2200 compact frame) | rebuilt with the format wmbusmeters' driver lists, the records fail the frame's Full-Frame-CRC, which wmbusmeters does not check | `FormatCache.IgnoreFullFrameCRC` (with a warning); values then equal wmbusmeters' |
| simulation_formulas.txt:1 (Kamstrup MULTICAL 21 compact frame) | the same: the driver's format rebuilds it, the Full-Frame-CRC does not match | `FormatCache.IgnoreFullFrameCRC` (with a warning) |
| simulation_bad_keys.txt:1 (Techem FHKV data IV) | encrypted (mode 5); the test runs it without a key, and with a wrong key, to check wmbusmeters' warnings | not decodable without the meter's key; wmbusmeters prints no reading either |
| simulation_broken.txt:6 and :9 (Engelmann, M field EFE) | encrypted (mode 5); the test gives no key, and its comments call the content broken | not decodable without the meter's key |
| simulation_broken.txt:3 | its last byte removed on purpose, so the link-layer CRCs fail | nothing (broken on purpose) |
| generated_tests.xmq:2090 (Techem TSD2) | the payload is 2 bytes, shorter than the layout | nothing; wmbusmeters prints a decoding error for it too |

So, with the lenient option on, every frame wmbusmeters reads from the
data given is read here too.

These runs found and fixed two decoder bugs: the order of a plain-text
VIF's text and its combinable VIFEs as Elvaco meters send them, and the
byte order of the extended link layer's payload CRC. wmbusmeters
decoding the telegrams of our simulated meter is recorded in
[mbus-sim](https://github.com/cB-Sigma/mbus-sim). Also tested: the
worked examples of the standards and OMS (above).

The meter drivers' layouts were checked only against these published
telegrams; the stick commands (iM871A, Amber, CUL) and the rtl-wmbus
and CUL readers only against byte vectors and the simulated stick in
mbus-sim.

Not yet, each needing hardware or data we do not have: a real meter,
receiver stick (to confirm the mode commands and the CUL and rtl-wmbus
output) or repeater on a live bus; Radiocrafts and Embit sticks'
protocols (no stick to check against); the remaining manufacturer
fields above, which need the makers' descriptions or more telegrams
with known values; the RFM-TX1 volume (no public description of its
obfuscation).

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
