# Provenance

## How the code was written

Written for SigmaM2M, a oneM2M platform, in Go from the standards below
and moved here from SigmaM2M's Wireless M-Bus, wired M-Bus and MBAL
adapters with `git mv`, so that repository's history follows the files. No code was ported or copied from another implementation:
the repository's history records no porting from wmbusmeters, libmbus,
jMBus, pyMeterBus or any other M-Bus stack, and a search of this module
for their names, comments, identifiers and porting markers finds only the
libmbus test data below. The AES-CCM of security mode 10 and of
mbal's COSE content (its own copy until 2026-10-06) comes from
the iotcrypto module's ccm package, the TLS of mode 13 from tlsx (both listed in
NOTICE).

Facts are not code: frame layouts, C and CI fields, DIF/VIF codes,
units, CRC polynomials, key derivation constants and OBIS codes are what
any implementation must use; the code around them is our own design. The
CRC tables are computed from their polynomials. No specification text is
reproduced; comments cite clause, table and annex numbers in our own
words.

What was added for this module (new files, "Copyright 2026 Abhinav
Gautam"): the scheduler of downlinks (wireless/scheduler.go, the queue
logic moved out of the adapter), the wired master (wired/master.go, the
link layer and procedures moved out of the adapter), the receiver
`Reader`, the package documentation, the examples and the tests
marked as new.

### v0.2.0 (2026-10-11)

New files, "Copyright 2026 Abhinav Gautam": the `meters` package,
wireless/stick.go and delay.go, records' `BaseValue`, and their tests.

- **Meter drivers (`meters`).** The manufacturers' payload layouts are
  facts (byte positions, scales, bit meanings, the Diehl group's
  scrambling register); the code and the
  value names are ours. The layouts were worked out from the published
  test telegrams of wmbusmeters and the values it prints for them, and,
  where a telegram alone did not settle a position or a scale, the facts
  were read from wmbusmeters' driver descriptions (drivers/src/*.xmq,
  src/driver_izar.cc, src/driver_qwater.cc, src/driver_qheat.cc,
  src/manufacturer_specificities.cc; GPL-3.0). No
  code, grammar, field name, lookup table or text of wmbusmeters was
  copied; the Go code is written from scratch around the facts and
  checked against the telegrams at run time (`interop/`), none of which
  is kept here. **No keys ship with the library:** the Diehl group's
  default scrambling and AES keys are supplied by the user
  (`SetMakerKeys`); the interop test reads them from the wmbusmeters
  checkout at run time, and the unit tests use keys of their own. One
  layout was left out because its only description is
  a table of constants in wmbusmeters' driver (the RFM-TX1 volume). The
  manufacturer, version and device type combinations of the named
  models are those of the published test telegrams; the model names are
  the makers' product names.
- **Receiver sticks.** Command and mode codes are the makers' published
  interface facts: IMST's WiMOD wM-Bus HCI (iM871A device management
  messages and link modes), Würth Elektronik's AMB8465 manual (command
  mode set-mode request, its confirmation and mode codes), the culfw
  command reference (brt, brs, brc, X21 and the "b" lines with LQI and
  RSSI) and the rtl-wmbus README (its output line); the codes were
  cross-checked against wmbusmeters' stick drivers (facts only). Not
  checked against real sticks.
- **Response delays** (`ResponseDelay`): EN 13757-4:2025 tables 5, 8
  and 15 (tRO of modes S, T and C, fast and slow). **Address 251**:
  EN 13757-2:2018+A1:2023 5.7.5, which reserves it and defines no
  commands.
- **DES mode 2 by its 2F2F fillers** (`DESCheck2F2F`, off by default):
  what wmbusmeters accepts; our default check stays the meter ID of
  EN 13757-7:2025 9.4.3.2.

The simulators (the wired bus, the wireless meter and the receiver
stick) and their commands were written with the decoders and moved into
the separate mbus-sim module on 2026-10-11, with the tests that drive
them, so this module does not depend on them.

## Standards followed

Licensed copies read in place (or, for OMS, the free download); none is
kept in the repository or redistributed.

| Package | Followed |
|---|---|
| `wired` | EN 13757-2:2018+A1:2023 (link layer: FT1.2 frames, the control field, the frame count bit per address, repeats, answer timing, collisions, the annex F frames); EN 13757-3:2025 clauses 7 to 12 and annexes D, E and I (application select and reset, alarms, application errors, baud rate switching, synchronize, clock synchronisation, image transfer), the fixed data structure; EN 13757-1:2021 9.2 (DLMS/COSEM over M-Bus) |
| `records` | EN 13757-3:2025 clause 6 and annexes A, B, C, E (data records, DIF/VIF/VIFE, data types), annex F (compact profiles) and annex H (OBIS), EN 13757-7:2025 7.5.6 (status byte) |
| `tpdu` | EN 13757-1:2021 8.2.4 (transport PDUs) |
| `wireless` | EN 13757-4:2025 (link layer, frame formats A and B, 3-out-of-6, modes, FEC); EN 13757-7:2025 (ELL, AFL, TPL, security modes 2, 3, 5, 7 to 10 and 13, KDF-A, counters, annex A SITP); EN 13757-3:2025 annex G (compact frames); OMS Specification Volume 2 (release E, 2023-12; security profiles, CI usage, annex F mode 13); BSI TR-03116-3 (TLS profile of mode 13); RFC 3394, 4493, 5649, 3610 |
| `mbal` | EN 13757-8:2023 (MBAL control field and the LoRaWAN, UDP/CoAP/COSE, MIOTY and Wize layouts); RFC 7252 (CoAP), RFC 8949 (CBOR) and COSE Encrypt0 with AES-CCM |

## Specification data

- `records/vif_tables.go`: the VIF/VIFE codes of EN 13757-3:2025 6.4 as
  facts (code, exponent, unit); quantity names (snake_case) and UCUM
  units are ours.
- `records/annexh.yaml`: annex H as rules over our quantity names, each
  naming the table rows it stands for (see its header).

## Test data

- **Standards' worked examples** (facts): EN 13757-3:2025 annex F and G
  examples (profile_test.go, compact_test.go, with the placeholder
  signatures computed and pinned); OMS Specification Volume 2 annex N,
  every example frame with its keys (wireless/omsannexn_test.go; the OMS
  Group publishes the specification for free download); RFC 3610, 4493
  and 5649 vectors.
- **m-bus.com examples**: the variable and fixed data structure example
  telegrams of the M-Bus documentation (wired/frame_test.go,
  fixed_test.go): 30- and 20-byte example frames, used as test data.
- **libmbus** (BSD-3-Clause, Copyright (c) 2010-2012 Raditex Control AB):
  four heat meter answers from its test/test-frames in
  wired/heat_test.go, with its notice there and in NOTICE.
- **Not included: wmbusmeters** (GPL-3.0). SigmaM2M's Wireless M-Bus
  adapter tests two unencrypted heat meter telegrams from wmbusmeters'
  simulations (simulation_t1.txt: Apator Elf, Qundis QHeat), checked
  against the values listed there. That test stays in SigmaM2M. This module tests the same kinds of records with telegrams
  written for it from the standard's tables (records/heat_test.go,
  TestHeatMeterRecordsSelfMade: 12-digit BCD energy with VIF 01h, stored
  values of storages 1 and 17, an all-ones date, external temperature,
  operating time, manufacturer data).
- **Meter drivers**: meters/meters_test.go builds telegrams in each
  layout with values chosen for the tests (no wmbusmeters telegram is
  included); wmbusmeters' telegrams are read only at run time by
  `interop/`.
- Everything else is written for the tests. Keys are test values.

## SigmaM2M traces

Tests carry `// Covers: SIG-...` comments and some comments name
SigmaM2M findings (`F-nnnn`). They are SigmaM2M requirement and finding
IDs that its compliance report collects; they mean nothing else here.
