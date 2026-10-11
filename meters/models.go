// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package meters

import "strings"

// Meters whose telegrams carry ordinary data records: the driver names
// the model, and the records give the values. The manufacturer, version
// and device type combinations are those seen in published telegrams of
// these meters.
var modelTable = []struct {
	name, model string
	mvt         string // "MAN,vv,tt MAN,vv,tt"
}{
	{"abb-b23", "ABB B23 electricity meter", "ABB,20,02"},
	{"actaris-actislink", "Actaris ActisLink water module", "ALK,04,07"},
	{"diehl-aerius", "Diehl AERIUS gas meter", "DME,30,03"},
	{"apator-amiplus", "Apator Amiplus electricity meter", "APA,01,02 APA,02,02 DEV,00,02 DEV,01,02 NES,03,02"},
	{"imt-aquastream", "Aquastream water meter", "IMT,01,07"},
	{"aventies-hca", "Aventies heat cost allocator", "AAA,55,08"},
	{"aventies-water", "Aventies water meter", "AAA,25,07"},
	{"zenner-c5-isf", "Zenner C5-ISF heat meter", "ZRI,88,04 ZRI,88,0D"},
	{"zenner-caltose", "Zenner Caltose heat cost allocator", "ZRI,FC,08"},
	{"diehl-dme-173", "Diehl water meter (version 63h)", "DME,63,07"},
	{"diehl-dme-07", "Diehl water meter (version 7Bh)", "DME,7B,07"},
	{"ebz-wmbe", "EBZ electricity meter", "EBZ,01,02"},
	{"emh-ehz-p", "EMH eHZ-P electricity meter", "EMH,02,02"},
	{"ei-electronics-ei6500", "Ei Electronics Ei650 smoke alarm", "EIE,0C,1A"},
	{"apator-elf-2", "Apator Elf 2 heat meter", "APA,42,0D"},
	{"apator-elf", "Apator Elf heat meter", "APA,40,04"},
	{"elster-gas", "Elster gas meter", "ELS,81,03"},
	{"elvaco-cma12w", "Elvaco CMa12w room sensor", "ELV,20,1B"},
	{"elvaco-sense", "Elvaco room sensor", "ELV,50,1B"},
	{"carlo-gavazzi-em24", "Carlo Gavazzi EM24 electricity meter", "GAV,00,02 KAM,33,02"},
	{"elster-merlin-868", "Elster Merlin 868 radio module", "ELR,11,37"},
	{"engelmann-faw", "Engelmann water meter", "EFE,00,07"},
	{"easymeter-esys-wm", "EasyMeter ESYS-WM electricity meter interface", "ESY,11,02 ETY,11,02"},
	{"ista-euris-ii", "Euris II heat cost allocator", "INE,55,08 RAM,55,08"},
	{"elster-ev200", "Elster EV200 water meter module", "ELR,0D,07"},
	{"maddalena-evo-868", "Maddalena EVO 868 water meter module", "MAD,50,07 MAD,50,16"},
	{"techem-fhkv-data-4", "Techem FHKV data IV heat cost allocator", "TCH,94,08"},
	{"fiorentini-water", "Fiorentini water meter", "FIO,01,07"},
	{"kamstrup-flowiq-2200", "Kamstrup flowIQ 2200 water meter", "KAW,3A,16 KAW,3C,16"},
	{"gran-system", "Gran-System electricity meter", "GSS,01,02"},
	{"gwf-gas", "GWF gas meter", "GWF,3C,03"},
	{"gwf-water", "GWF water meter", "GWF,01,0E GWF,3C,07"},
	{"engelmann-hcae2", "Engelmann HCA e2 heat cost allocator", "EFE,31,08"},
	{"bmeters-hydrocal-m3", "B METERS Hydrocal-M3 heat meter", "BMT,0B,0D"},
	{"bmeters-hydrocal-m4", "B METERS Hydrocal-M4 heat meter", "BMT,1A,0D"},
	{"bmeters-hydroclima", "B METERS Hydroclima heat cost allocator", "BMP,33,08 BMP,53,08 BMP,85,08"},
	{"bmeters-hydrodigit", "B METERS Hydrodigit water meter", "BMT,13,06 BMT,13,07 BMT,15,07 BMT,17,06 BMT,17,07"},
	{"diehl-hydrus", "Diehl HYDRUS water meter", "DME,70,06 DME,70,07 HYD,8B,06 HYD,8B,07 HYD,24,07 DME,76,07 DME,70,16"},
	{"sensus-iperl", "Sensus iPERL water meter", "SEN,68,07"},
	{"ista-heat", "ista heat meter", "IST,A9,04"},
	{"ista-water", "ista water meter", "IST,31,07"},
	{"itron-water", "Itron water meter", "ITW,00,07 ITW,00,16 ITW,03,07 ITW,33,07"},
	{"itron-heat", "Itron heat meter", "ITW,00,04"},
	{"bmeters-iwm-tx5", "B METERS IWM-TX5 water meter module", "BMT,18,06 BMT,18,07"},
	{"kaden-hca", "Kaden heat cost allocator", "VIP,1E,08"},
	{"kaden-water", "Kaden water meter", "KDN,01,07"},
	{"kamstrup-heat", "Kamstrup MULTICAL heat meter", "KAM,19,04 KAM,1C,04 KAM,30,04 KAM,30,0C KAM,34,0C KAM,35,04 KAM,39,04 KAM,40,0C"},
	{"kamstrup-pressure", "Kamstrup pressure sensor", "KAM,01,18"},
	{"lansen-door-window", "Lansen door and window detector", "LAS,07,1D"},
	{"lansen-pulse", "Lansen pulse counter", "LAS,0B,02 LAS,14,00"},
	{"lansen-repeater", "Lansen repeater", "LAS,0B,32"},
	{"lansen-smoke", "Lansen smoke detector", "LAS,03,1A"},
	{"lansen-th", "Lansen temperature and humidity sensor", "LAS,07,1B LAS,09,1B"},
	{"qundis-lse-07-17", "Qundis water meter (LSE)", "LSE,16,07 LSE,17,07 LSE,18,06 LSE,D8,07"},
	{"qundis-lse-08", "Qundis heat cost allocator (LSE)", "LSE,01,08"},
	{"maddalena-water", "Maddalena water meter", "MAD,01,07"},
	{"maddalena-microclima", "Maddalena Microclima heat meter", "MAD,00,04"},
	{"zenner-minomess", "Zenner Minomess water meter", "ZRI,00,07 ZRI,01,06 ZRI,01,16"},
	{"radio-4a-water", "radio 4a water meter", "HYD,FE,06 WEH,FE,07"},
	{"kamstrup-multical-21", "Kamstrup MULTICAL 21 water meter", "KAM,1B,16"},
	{"kamstrup-multical-403", "Kamstrup MULTICAL 403 heat meter", "KAM,34,0A"},
	{"weptech-munia", "Weptech Munia room sensor", "WEP,02,1B WEP,04,1B"},
	{"kamstrup-omnipower", "Kamstrup OMNIPOWER electricity meter", "KAM,30,02"},
	{"apator-op-041a", "Apator water meter (version 1Ah)", "APA,1A,07"},
	{"ecomess-picoflux", "Picoflux water meter", "ECM,05,07"},
	{"sensus-pollucom-f", "Sensus PolluCom F heat meter", "SEN,1D,04"},
	{"axioma-qalcosonic-w1", "Axioma Qalcosonic W1 water meter", "AXI,01,07 AXI,10,07"},
	{"qundis-q-caloric", "Qundis Q caloric heat cost allocator", "QDS,34,08 QDS,35,08 QDS,36,08 ZRI,FD,08"},
	{"qundis-q-heat-5-us", "Qundis Q heat 5 US heat meter", "LSE,23,04"},
	{"qundis-q-heat", "Qundis Q heat heat meter", "QDS,23,04 QDS,23,37 QDS,46,04 QDS,3E,04 QDS,3E,37 QDS,47,37 QDS,48,04 QDS,48,37"},
	{"landis-gyr-ultraheat-55-us", "Landis+Gyr heat meter (US)", "LUG,07,04 LUG,0A,04"},
	{"qundis-q-smoke", "Qundis Q smoke detector", "QDS,21,1A QDS,23,1A"},
	{"axioma-qalcosonic-e", "Axioma Qalcosonic heat meter", "AXI,0B,0D AXI,0C,0D"},
	{"qundis-q-water", "Qundis Q water meter", "QDS,17,06 QDS,17,07 QDS,18,06 QDS,19,07 QDS,1A,06 QDS,1A,07 QDS,1D,06 QDS,35,06 QDS,35,37 QDS,16,06 QDS,16,07 QDS,18,07 QDS,35,07"},
	{"bmeters-rfm-amb", "B METERS RFM-AMB room sensor", "BMT,10,1B"},
	{"diehl-sharky-774", "Diehl SHARKY 774 heat meter", "DME,41,04 DME,41,0C DME,41,0D"},
	{"diehl-sharky", "Diehl SHARKY heat meter", "DME,40,04 HYD,20,04"},
	{"engelmann-sensostar", "Engelmann SensoStar heat meter", "EFE,00,04"},
	{"sontex-868", "Sontex 868 heat cost allocator", "SON,16,08"},
	{"sontex-supercal", "Sontex Supercal heat meter", "SON,1B,04"},
	{"sontex-supercom-587", "Sontex Supercom 587 water meter", "SON,3C,06 SON,3C,07"},
	{"amt-topas-es-kr", "Topas ES KR water meter", "AMT,F1,07"},
	{"zenner-uiws", "Zenner water meter (version 99h)", "ZRI,99,07"},
	{"landis-gyr-ultraheat", "Landis+Gyr ULTRAHEAT heat meter", "LUG,04,04"},
	{"apator-ultrimis", "Apator Ultrimis water meter", "APA,01,16 APA,20,16"},
	{"amx-unismart", "Unismart gas meter", "AMX,01,03"},
	{"techem-vario-411", "Techem vario 4 heat meter (version 28h)", "TCH,28,04"},
	{"techem-vario-451-mid", "Techem vario 4 heat meter (MID)", "TCH,17,04"},
	{"dwz-waterstar-m", "Waterstar M water meter", "DWZ,00,06 DWZ,00,07 DWZ,02,06 EFE,70,07"},
	{"watertech-water", "Watertech water meter", "WTT,59,07"},
	{"wehrle-water", "Wehrle water meter", "WEH,03,07 WEH,FE,07"},
	{"qundis-whe-46x", "Qundis WHE 46x heat cost allocator", "LSE,18,08"},
	{"qundis-whe-5x", "Qundis WHE 5x heat cost allocator", "LSE,34,08"},
}

func parseMVT(s string) MVT {
	f := strings.Split(s, ",")
	h := func(x string) int {
		v := 0
		for _, c := range x {
			v = v * 16
			switch {
			case c >= '0' && c <= '9':
				v += int(c - '0')
			case c >= 'A' && c <= 'F':
				v += int(c-'A') + 10
			}
		}
		return v
	}
	return MVT{f[0], h(f[1]), h(f[2])}
}

func init() {
	for _, m := range modelTable {
		d := &Driver{Name: m.name, Model: m.model}
		for _, s := range strings.Fields(m.mvt) {
			v := parseMVT(s)
			d.Detect = append(d.Detect, v)
			if diehlMakers[v.Manufacturer] {
				d.Decode = diehlGeneric
			}
		}
		Register(d)
	}
}
