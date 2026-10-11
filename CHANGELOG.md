# Changelog

## v0.2.0 (2026-10-11)

Added, all backwards compatible: existing functions keep their
signatures, and telegrams that decoded still decode the same way.

- Package `meters`: per-meter drivers. `Read`/`ReadKeys` turn a decoded
  telegram (and the decoder's error) into a `Reading` of named values;
  `Lookup`, `ByName`, `Drivers`, `Register`; `SetMakerKeys` takes makers'
  default keys from the caller (none ship) and `DefaultKey` gives the
  AES one back for a KeyLookup; without keys a Diehl scrambled telegram
  fails with `ErrNoScramblingKey`, which names the option. Drivers for manufacturers' own payloads:
  Techem compact V, vario 4, radio 3 (both layouts), radio 4, FHKV data
  III and the TSD2 smoke detector; Apator 08, 17-2, AT-WMBUS-16-2, E-ITN
  and NA-1 (AES); the Diehl group's PRIOS (IZAR) and "real data"
  scrambling; BFW 240 radio; Zenner (version 0Bh); Qundis walk-by records (Q
  water, Q heat, Q caloric); the B METERS RFM-TX1's clock.
  90 more models are named from their manufacturer, version and device
  type, and makers' own device type codes are mapped to standard
  ones. A heat meter's temperature difference is computed when it is
  not sent.
- `wireless`: a manufacturer-specific CI field (A0h-B7h) and a security
  mode outside EN 13757-7 keep their payload in `Telegram.APL` for the
  drivers; the error still wraps `ErrUnsupport`, and the new
  `ErrManufacturerCI` names the first case.
- `wireless.Decoder.DESCheck2F2F` (off by default): accept a DES mode 2
  telegram by its 2F2F fillers when the meter ID is not in it, as
  wmbusmeters does; marked "des-id" in `Security.Unverified`.
- Receiver sticks: `ConfigureIM871A` (link mode by SET_CONFIG, volatile
  or stored), `ConfigureAmber` (set-mode request) and `ConfigureCUL`
  (brt, brs, brc and X21) with their confirmations; `IM871AFrame`,
  `ReadHCI`, `IM871ASetLinkMode`, `AmberSetMode`; `Reader` framings
  `FramerCUL` and `FramerRTLWMBUS` with `ParseCULLine` and
  `ParseRTLWMBUSLine`.
- Downlink timing: `ResponseDelay` (EN 13757-4 tRO of modes S, T and C,
  fast or slow by the D bit), and `Scheduler.LinkMode`, `StickLatency`
  and `Wait` time each frame into the meter's response window.
- `wired.Master.Repeater`: management frames to the primary master
  repeater at address 251.
- `records.Record.BaseValue`: the value a standard VIF gives when a
  manufacturer-specific VIFE follows it (`Value` stays raw).
- Interop: every value wmbusmeters prints is now compared with the
  drivers' readings; libmbus records with manufacturer VIFEs are compared
  by `BaseValue` (927 of 942 equal, all differences explained).
- `records.TypeG` formats a type G date.
- `wireless.FormatCache.IgnoreFullFrameCRC` (off by default): rebuild a
  compact frame whose Full-Frame-CRC does not match, as wmbusmeters
  does, with a warning (`CompactInfo.Warning`, `Telegram.Warnings`,
  `ErrFullFrameCRCIgnored` from `Expand`).

## v0.1.0 (2026-10-11)

First release.
