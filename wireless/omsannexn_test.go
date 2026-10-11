package wireless

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cB-Sigma/mbus/records"
)

// Test vectors from OMS Specification Volume 2, annex N (release E,
// 2023-12): every example frame of the annex, byte for byte, with its keys.
// Each vector is named by its annex subsection. frame is the column of
// bytes as transmitted (wM-Bus frames in format A with their CRCs, M-Bus
// frames as FT1.2 long or short frames); plain is the annex's column of
// the same bytes before encryption (CRCs as transmitted), where the frame
// is encrypted. The annex has no security mode 13 (TLS) example.
type annexNVector struct {
	sec, msg     string
	frame, plain string
}

var annexN = []annexNVector{
	{sec: "N.2.1", msg: "SND-NR (wM-Bus)",
		frame: "2E44931578563412330333637A2A0020255923C95AAA26D1B2E7493BC2AD013E" +
			"C4A6F6D3529B520EDFF0EA6DEFC955B29D6D69EBF3EC8A",
		plain: "2E44931578563412330333637A2A0020252F2F0C1427048502046D32C2AD371F" +
			"1502FD1700002F2F2F2F2F2F2F2F55B22F2F2F2F2FEC8A",
	},
	{sec: "N.2.2", msg: "RSP-UD (M-Bus)",
		frame: "6820206808FD7278563412931533032A0000000C1427048502046D32371F1502" +
			"FD1700008916",
	},
	{sec: "N.2.3", msg: "SND-NR (wM-Bus)",
		frame: "434493157856341233037AC98C2075900F002C25B30A000021924D4FBA372FB6" +
			"6E017A75002007109058475F4BC9D1281DF878B80A1B0F98B629024AAC727942" +
			"9398BFC549233C0140829B93BAA1",
		plain: "434493157856341233037AC98C2075900F002C25B30A000021924D4FBA372FB6" +
			"6E017A75002007102F2F0C142704D1288502046D32371F1502FD1700002F2F2F" +
			"93982F2F2F2F2F2F2F2F2F2FBAA1",
	},
	{sec: "N.2.4", msg: "REQ-UD2 (wM-Bus)",
		frame: "217B3A63665544330A315D178E84752448443322110337807856341280A49315" +
			"330375170000CDCD",
	},
	{sec: "N.2.4", msg: "RSP-UD (wM-Bus)",
		frame: "53082448443322110337D0468E80753A63665544330A31900F002C25E00AB30A" +
			"0000AF5D74DF73A600D972785634C027129315330375002007109058475F4BC9" +
			"55CF1DF878B80A1B0F98B629024AAC7279429398BFC549233C0140829B93BAA1",
		plain: "53082448443322110337D0468E80753A63665544330A31900F002C25E00AB30A" +
			"0000AF5D74DF73A600D972785634C027129315330375002007102F2F0C142704" +
			"55CF8502046D32371F1502FD1700002F2F2F93982F2F2F2F2F2F2F2F2F2FBAA1",
	},
	{sec: "N.2.5", msg: "RSP-UD (M-Bus)",
		frame: "683131680803900F002C25B30A0000A08518CCB022C5FD727856341293153303" +
			"7500100710D371C801D409B0D928D5659759C2EC935B16",
		plain: "683131680803900F002C25B30A0000A08518CCB022C5FD727856341293153303" +
			"75001007102F2F0C1427048502046D32371F152F2F5B16",
	},
	{sec: "N.2.6", msg: "SND-NR (wM-Bus)",
		frame: "30449315785634123303B56B8C20757A7500112A1001B30A0000C882C518038E" +
			"223BBC1091CEB8C0A1009D388A5A5E96F7883A5B5A7FD684D8",
		plain: "30449315785634123303B56B8C20757A7500112A1001B30A00000C14C5182704" +
			"8502046D32371F1502FD1700005A5E96F7883A5B5A7FD684D8",
	},
	{sec: "N.3.3", msg: "REQ-UD2 (wM-Bus - Fragment 1)",
		frame: "197B3A63665544330A31822E8C84118078563412496A010705170000CB20",
	},
	{sec: "N.3.3", msg: "RSP-UD (wM-Bus - Fragment1)",
		frame: "3908496A78563412010714648E80113A63665544330A319009017865D438B30A" +
			"000056007A050050071030539A7C63ABDB1CBCA6D43CB02D762A1E1626FEEF0E" +
			"8E95",
		plain: "3908496A78563412010714648E80113A63665544330A319009017865D438B30A" +
			"000056007A05005007102F2F0C1363AB79194100026CB2184C13943238008204" +
			"8E95",
	},
	{sec: "N.3.4", msg: "REQ-UD2 (wM-Bus - Fragment 2)",
		frame: "145B3A63665544330A3147398E8412496A78563412010753CF",
	},
	{sec: "N.3.4", msg: "RSP-UD (wM-Bus - Fragment2)",
		frame: "3908496A78563412010714648E80123A63665544330A3190020240C4E9B39027" +
			"8E41A48BAD1438BDE38D4D116630215F5DEFF6392B6BE31A9FC812757BE805B4" +
			"B186",
		plain: "3908496A78563412010714648E80123A63665544330A31900202406CE9B38111" +
			"8C0413905234008D04931F23FBFE215F60260039390034310068340010420078" +
			"B186",
	},
	{sec: "N.3.5", msg: "REQ-UD2 (wM-Bus - Fragment 3)",
		frame: "147B3A63665544330A31B60C8E8413496A785634120107C31F",
	},
	{sec: "N.3.5", msg: "RSP-UD (wM-Bus - Fragment3)",
		frame: "3B08496A78563412010763428E80133A63665544330A31900A0304BE41AF47ED" +
			"4C9CC11A7806CC3E0457C725B4B2CD8C9BE7FEF078777187CCEF8E2AF51CC729" +
			"9583EF7AC7F2",
		plain: "3B08496A78563412010763428E80133A63665544330A31900A0304BE41AF47ED" +
			"4C9CC11A78310010540030180086CD8C190064240003410002FD1700002F2F2F" +
			"95832F2FC7F2",
	},
	{sec: "N.4.3", msg: "REQ-UD2 (M-Bus - Fragment 1)",
		frame: "107BFD7816",
	},
	{sec: "N.4.3", msg: "RSP-UD (M-Bus - Fragment1)",
		frame: "682A2A68080390050170405D007278563412934410070500500528FCB763E51B" +
			"4A6D4FDDF2EEA906F61ED0DA7AB21616",
		plain: "682A2A68080390050170405D00727856341293441007050050052F2F0C137919" +
			"4100026CB2184C139432380082041616",
	},
	{sec: "N.4.4", msg: "REQ-UD2 (wM-Bus - Fragment 2)",
		frame: "105BFD5816",
	},
	{sec: "N.4.4", msg: "RSP-UD (M-Bus - Fragment2)",
		frame: "682727680803900202409787E1B2B5E34EF3C5903E3AE42427CDA9DB2407FA81" +
			"31EFB2259798E2B79BAAD13116",
		plain: "682727680803900202406C81118C0413905234008D04931F23FBFE6026003939" +
			"00343100683400104200783116",
	},
	{sec: "N.4.5", msg: "REQ-UD2 (wM-Bus - Fragment 3)",
		frame: "107BFD7816",
	},
	{sec: "N.4.5", msg: "RSP-UD (M-Bus - Fragment3)",
		frame: "68212168080390020300AF89B7506FEB16C22B151B3537FA272D55227562C63F" +
			"6C408383EB1616",
		plain: "68212168080390020300310010540030180086190064240003410002FD170000" +
			"2F2F2F2F2F1616",
	},
	{sec: "N.5.3", msg: "REQ-UD2 (wM-Bus - Fragment 1)",
		frame: "197B3A63665544330A31822E8C84118078563412A73D0107051700008449",
	},
	{sec: "N.5.3", msg: "RSP-UD (wM-Bus - Fragment1)",
		frame: "3808A73D785634120107609E8E80113A63665544330A3190050170401E8C5C00" +
			"7A0500492A1001B30A000002B12BDDB947A6B89CF8F54DE4BFC89CF836120820" +
			"60",
		plain: "3808A73D785634120107609E8E80113A63665544330A3190050170401E8C5C00" +
			"7A0500492A1001B30A00000C1379DDB9194100026CB2184C1394323800820420" +
			"60",
	},
	{sec: "N.5.4", msg: "REQ-UD2 (wM-Bus - Fragment 2)",
		frame: "145B3A63665544330A3147398E8412A73D7856341201071CA6",
	},
	{sec: "N.5.4", msg: "RSP-UD (wM-Bus - Fragment2)",
		frame: "3908A73D7856341201075B0D8E80123A63665544330A319002024085E9E0290B" +
			"675FE6DB08EE8B55812989108B08876B131CEF2145AC232C9CE243505181F012" +
			"DEBE",
		plain: "3908A73D7856341201075B0D8E80123A63665544330A31900202406CE9E08111" +
			"8C0413905234008D04931F23FBFE876B60260039390034310068340010420078" +
			"DEBE",
	},
	{sec: "N.5.5", msg: "REQ-UD2 (wM-Bus - Fragment 3)",
		frame: "147B3A63665544330A31B60C8E8413A73D7856341201078C76",
	},
	{sec: "N.5.5", msg: "RSP-UD (wM-Bus - Fragment3)",
		frame: "3608A73D78563412010718098E80133A63665544330A3190020300948399C52A" +
			"B98A7EC51DB7CDC02F51E17AAB87D99EC6B259D28BE41370F8741B9D99274E",
		plain: "3608A73D78563412010718098E80133A63665544330A31900203003183990010" +
			"5400301800861900642400034100D99E02FD170000E41370F8741B9D99274E",
	},
	{sec: "N.6.2", msg: "ACC-NR (wM-Bus)",
		frame: "1947934444332211553735728C20758B8877665593445508FF0400001393",
	},
	{sec: "N.6.3", msg: "SND-NR (wM-Bus)",
		frame: "30449344443322115537A3528C0075728877665593445508000410051B2F00DF" +
			"E2A782146D1513581CD2F83F3904D7570CFD1078563412FB35",
		plain: "30449344443322115537A3528C0075728877665593445508000410051B2F2F2F" +
			"0B6E341200426CFE044B6E563402D7570CFD1078563412FB35",
	},
	{sec: "N.6.4", msg: "RSP-UD (M-Bus with Encryption)",
		frame: "682C2C6808FD7288776655934455080004100500DFE2A782146D1513581CD2F8" +
			"3F39040CFD10785634120C78443322112616",
		plain: "682C2C6808FD728877665593445508000410052F2F0B6E341200426CFE044B6E" +
			"5634020CFD10785634120C78443322112616",
	},
	{sec: "N.7", msg: "SND-IR (wM-Bus)",
		frame: "51469315785634123303EFB58C80457A01004805D2B70B3FBC1A1580C85ED79B" +
			"92CAA1D95341B609EF603AD36294853A72B2067D26BD2B5FDDC2374D29D0CD08" +
			"AB4858C5614E8B56E6C2175962DB0F01AA2A62E1A7B12EE4B5F63F440569",
		plain: "51469315785634123303EFB58C80457A010048052F2F0DFD0C043447C85E4B42" +
			"0AFD0D05010AFD0E01010AFD0F00853A010DFD10213837363534333231303030" +
			"AB483030303030303030303437303934363562E13433323145442F2F0569",
	},
	{sec: "N.7", msg: "CNF-IR (wM-Bus)",
		frame: "19063A63665544330A3190728C84458078563412931533030119000093FD",
	},
	{sec: "N.8.2", msg: "SND-UD Adjust Clock Time (wM-Bus)",
		frame: "29532423563412900831888A8C84516C44227592934400077D00100572939ED8" +
			"2AB233D1A2A80BFFD3B7B6A908D7C5AA",
		plain: "29532423563412900831888A8C84516C44227592934400077D00100572932F2F" +
			"013201000000000000002F2F2F2FC5AA",
	},
	{sec: "N.8.2", msg: "ACK (wM-Bus)",
		frame: "1900242302618843290777838C80518B44227592934400077D020000A6B5",
	},
	{sec: "N.9", msg: "RSP-UD (wM-Bus)",
		frame: "21086850785634128F08E4F88C80157A02001005FD26EF68ACF65BAE39F9028B" +
			"FDC188D8A972D8DC",
		plain: "21086850785634128F08E4F88C80157A020010052F2F036E3930004239F96C3F" +
			"1C436EA05B00D8DC",
	},
	{sec: "N.9", msg: "RSP-UD (wM-Bus - Appl. Error)",
		frame: "12086850785634128F0896898C80156E0202000001B5A3",
	},
	{sec: "N.10", msg: "ACC-DMD (wM-Bus)",
		frame: "1948B05C114715081137B3658CA0518B16685438386B1907510000000EAC",
	},
	{sec: "N.10", msg: "ACK (wM-Bus)",
		frame: "19003A63785634120231C2BA8C80518016685438386B1907511700005537",
	},
	{sec: "N.11", msg: "SND-NKE (wM-Bus)",
		frame: "19403A63998877660C319BB78C843280443322119344100A03200000DA8E",
	},
	{sec: "N.12.1", msg: "SND-NR (wM-Bus)",
		frame: "33443A63785634125520E4C98CA4E5900F002C25B30A0000ED172368E6B527CE" +
			"A2FF7A7500100710B38C55009933A60441B123674F5938D299330813",
		plain: "33443A63785634125520E4C98CA4E5900F002C25B30A0000ED172368E6B527CE" +
			"A2FF7A75001007102F2F01FD1F01A6042F2F2F2F2F2F2F2F2F2F0813",
	},
	{sec: "N.12.2", msg: "SND-UD2 (wM-Bus)",
		frame: "4B433A6321436587083187718C8423900F002C25F00A000087E2777272442E67" +
			"603DC3785634123A635520512020FB1B071028B27359AC9B83ABCDC87FFDF8F2" +
			"BAD9FE8E1ED8F19718B7434C5EAED8663F15F33AC5CAA138",
		plain: "4B433A6321436587083187718C8423900F002C25F00A000087E2777272442E67" +
			"603DC3785634123A635520512020FB1B07102F2F1C000020003220000F000000" +
			"BAD900000000300101FD1F00FA41E2812D44F33A9B4DA138",
	},
	{sec: "N.12.3", msg: "RSP-UD (set breaker, successful)",
		frame: "43083A63785634125520F24F8C8423900F002C25F10A00001C566D47D3EEAB61" +
			"8754C451002007102DA57D884181FF44E5376C0F7C9F86100822C33CF7CDFDB8" +
			"3373411C20D477D8C5A67F375729",
		plain: "43083A63785634125520F24F8C8423900F002C25F10A00001C566D47D3EEAB61" +
			"8754C451002007102F2F1C0000A0FF44003220000F00000000000000300101FD" +
			"33731F00FA41E2812D449B4D5729",
	},
	{sec: "N.12.4", msg: "RSP-UD (set breaker, failure)",
		frame: "33083A6378563412552071588C8423900F002C25F10A0000422FB126DEC81437" +
			"5597C45102180710B315C2E1A072392E1EE74E3503AD479F0F0D1241",
		plain: "33083A6378563412552071588C8423900F002C25F10A0000422FB126DEC81437" +
			"5597C451021807102F2F070000A0392E002220001905050505051241",
	},
	{sec: "N.13", msg: "SND-NR (wM-Bus)",
		frame: "D344A73D785634120102ABFD8C200A900F002C25B30A0000B27C7EBE85D0A010" +
			"C9537A0A00B007100D5EE06C03088EAB5EFC73ACC3D839C7E87EB41FBF9559E6" +
			"3B7C6FAB2B352BF3F0A0936C5896781B376D78A5181DD0CD6ACD20BA2003D823" +
			"BE0A2ABB7F019F1642E9E4EAF1FC7E4E526F07931305C460A8E3DECCAF99A063" +
			"749A109E782BB116A47828148285EF59107F5493D8D280731ABE8F5BABFE1C42" +
			"4953E7D6EB1010CC6E0713326ABAA6E14EB296B108D294AD08FA939A7164E208" +
			"1325E1AF8F7E78BAB4B8B80F501C33CB06039F9941B1338367789109753989FD" +
			"1C5D5A87A27EA525BC99F13B3E3A1957",
		plain: "D344A73D785634120102ABFD8C200A900F002C25B30A0000B27C7EBE85D0A010" +
			"C9537A0A00B007102F2F0E0260998EAB010000000E823C513000000000CD016D" +
			"3B7CE20330CE0103951900000000CD01831378A5304108010305070908060402" +
			"000000007F0100000000000000010305070908060402C4600000000000000000" +
			"0000000103050709A47808CE01833C050300000000CD0183BC138F5B30410800" +
			"0000000000000000000103056ABA07090806040200000000000000000000E208" +
			"00010305070908060402000000000000060300C101740302FD971D00002F2F2F" +
			"2F2F5A872F2F2F2F2F2F2F2F2F2F1957",
	},
}

// Keys of the annex examples: the mode 5 AES keys and the individual master
// keys of the KDF (N.2.1 and N.7 use one key, N.8 another, the rest the
// master key 00 01 … 0F).
const (
	annexNKeyELS = "0102030405060708090A0B0C0D0E0F11"
	annexNKeyN8  = "82B0551191F51D66EFCDAB8967452301"
	annexNMaster = "000102030405060708090A0B0C0D0E0F"
	// annexNASP10 is N.12.2's application security key (Key ID 20h,
	// version 00h) of the SITP data structure 32h.
	annexNASP10 = "08154711081547110815471108154711"
)

func annexNKey(sec string) string {
	switch {
	case sec == "N.2.1" || sec == "N.7":
		return annexNKeyELS
	case strings.HasPrefix(sec, "N.8"):
		return annexNKeyN8
	}
	return annexNMaster
}

func annexNByName(t *testing.T, sec, msgPrefix string) annexNVector {
	t.Helper()
	for _, v := range annexN {
		if v.sec == sec && strings.HasPrefix(v.msg, msgPrefix) {
			return v
		}
	}
	t.Fatalf("no annex N vector %s %s", sec, msgPrefix)
	return annexNVector{}
}

// dropCRCA removes the CRC positions of a format A frame without checking
// them (the annex's plain column carries the CRCs of the encrypted frame).
func dropCRCA(b []byte) []byte {
	out := append([]byte(nil), b[:10]...)
	for i := 12; i < len(b); i += 18 {
		end := min(i+16, len(b)-2)
		out = append(out, b[i:end]...)
	}
	return out
}

// mbusAsLink checks an FT1.2 long frame's length, checksum and stop byte
// and returns its user data behind a wM-Bus style link header (L, the
// frame's C, a placeholder address), CRC-less, so that the security
// layers decode the bytes exactly as the M-Bus frame carries them. The
// placeholder address makes the decoder take the meter address from the
// TPL long header, as it must for M-Bus.
func mbusAsLink(t *testing.T, b []byte, checkSum bool) []byte {
	t.Helper()
	if len(b) < 9 || b[0] != 0x68 || b[3] != 0x68 || b[1] != b[2] || int(b[1])+6 != len(b) || b[len(b)-1] != 0x16 {
		t.Fatalf("not an FT1.2 long frame: % X", b)
	}
	ud := b[4 : len(b)-2]
	var cs byte
	for _, c := range ud {
		cs += c
	}
	if checkSum && cs != b[len(b)-2] {
		t.Fatalf("M-Bus checksum %02X, frame says %02X", cs, b[len(b)-2])
	}
	out := []byte{0, ud[0], 0xFF, 0xFF, ud[1], 0, 0, 0, 0, 0}
	out = append(out, ud[2:]...)
	out[0] = byte(len(out) - 1)
	return out
}

// payloadAfterAFL skips link header, ELL and AFL of a CRC-less frame.
func payloadAfterAFL(b []byte) []byte {
	i := 10
	switch b[i] {
	case CIELL2:
		i += 3
	case CIELL8:
		i += 9
	case CIELL10:
		i += 11
	case CIELL16:
		i += 17
	}
	if i < len(b) && b[i] == CIAFL {
		i += 2 + int(b[i+1])
	}
	return b[i:]
}

type annexNResult struct {
	tg    *Telegram
	err   error
	plain []byte // the annex's plaintext of the whole message (after the AFL)
}

// decodeAnnexN decodes every vector in annex order, fragments of one
// subsection chapter with one Decoder, and returns the results by index.
func decodeAnnexN(t *testing.T) []annexNResult {
	t.Helper()
	res := make([]annexNResult, len(annexN))
	decs := map[string]*Decoder{}
	msg := map[string][]byte{}
	for i, v := range annexN {
		b := hx(t, v.frame)
		if b[0] == 0x10 { // M-Bus short frame (REQ-UD2): checked in the frame test
			continue
		}
		chapter := v.sec
		if strings.Count(v.sec, ".") == 2 && (strings.HasPrefix(v.sec, "N.3") || strings.HasPrefix(v.sec, "N.4") || strings.HasPrefix(v.sec, "N.5")) {
			chapter = v.sec[:3] // one fragmented message per chapter
		}
		d := decs[chapter]
		if d == nil || chapter == v.sec {
			d = &Decoder{}
			decs[chapter] = d
		}
		var frame, plain []byte
		format := FormatA
		if b[0] == 0x68 {
			frame, format = mbusAsLink(t, b, true), FormatNoCRC
			if v.plain != "" {
				plain = mbusAsLink(t, hx(t, v.plain), false)
			}
		} else {
			frame = b
			if v.plain != "" {
				plain = dropCRCA(hx(t, v.plain))
			}
		}
		// Messages to a meter (SND-UD, SND-UD2) use the partner's
		// session keys: decode them as the meter does.
		d.MeterSide = frame[1] == 0x53 || frame[1] == 0x43
		key := hx(t, annexNKey(v.sec))
		tg, err := d.Decode(frame, format, func(Header) []byte { return key })
		res[i] = annexNResult{tg: tg, err: err}
		if plain != nil {
			if tg != nil && tg.AFL != nil {
				msg[chapter] = append(msg[chapter], payloadAfterAFL(plain)...)
				res[i].plain = msg[chapter]
			} else {
				res[i].plain = plain
			}
		}
	}
	return res
}

// Covers: SIG-IPE-1440
func TestOMSAnnexNFrames(t *testing.T) {
	res := decodeAnnexN(t)
	for i, v := range annexN {
		t.Run(v.sec+" "+v.msg, func(t *testing.T) {
			b := hx(t, v.frame)
			switch b[0] {
			case 0x10: // M-Bus short frame: C, A, checksum, stop
				if len(b) != 5 || b[3] != b[1]+b[2] || b[4] != 0x16 {
					t.Fatalf("short frame % X: checksum or stop byte wrong", b)
				}
				return
			case 0x68:
			default:
				if _, _, err := StripCRC(b, FormatA); err != nil {
					t.Fatalf("format A CRCs: %v", err)
				}
			}
			r := res[i]
			if r.tg == nil {
				t.Fatalf("no telegram: %v", r.err)
			}
			if r.tg.AFL != nil && r.tg.AFL.FCL&AFLMF != 0 {
				if !errors.Is(r.err, ErrFragment) {
					t.Fatalf("a fragment with more to follow: %v, want ErrFragment", r.err)
				}
				return
			}
			if r.err != nil {
				t.Fatalf("decode: %v", r.err)
			}
			if v.plain == "" {
				if r.tg.Encrypted {
					t.Fatal("the annex shows no plaintext but the telegram was decrypted")
				}
				return
			}
			if !r.tg.Encrypted || len(r.tg.APL) == 0 {
				t.Fatalf("encrypted=%v, APL % X", r.tg.Encrypted, r.tg.APL)
			}
			// The decrypted application data is the annex's plaintext:
			// it sits in the plain message where the ciphertext was, and
			// only idle fillers or the tag follow it.
			at := bytes.Index(r.plain, r.tg.APL)
			if at < 0 {
				t.Fatalf("decrypted APL\n% X\nis not in the annex plaintext\n% X", r.tg.APL, r.plain)
			}
			rest := r.plain[at+len(r.tg.APL):]
			if len(bytes.Trim(rest, "\x2F")) > 16 {
				t.Fatalf("%d plaintext bytes after the APL: % X", len(rest), rest)
			}
		})
	}
}

// annexNRecords are the values the annex's input parameters state.
var annexNRecords = map[string]map[string]string{
	"N.2.1": {"volume": "28504.27 m3", "datetime": "2008-05-31T23:50:00", "error_flags": "0000"},
	"N.2.2": {"volume": "28504.27 m3", "datetime": "2008-05-31T23:50:00", "error_flags": "0000"},
	"N.2.3": {"volume": "28504.27 m3", "datetime": "2008-05-31T23:50:00", "error_flags": "0000"},
	"N.2.4": {"volume": "28504.27 m3", "datetime": "2008-05-31T23:50:00", "error_flags": "0000"},
	"N.2.5": {"volume": "28504.27 m3", "datetime": "2008-05-31T23:50:00"},
	"N.2.6": {"volume": "28504.27 m3", "datetime": "2008-05-31T23:50:00", "error_flags": "0000"},
	// N.3 to N.5: current volume and date, the due date volume and the
	// twelve monthly values of 2012.
	"water": {"volume": "411.979 m3", "date": "2013-08-18", "volume_s1": "383.294 m3",
		"date_s8": "2012-01-01", "volume_s8": "345.29 m3", "volume_s8_p1": "347.95 m3",
		"volume_s8_p2": "351.889 m3", "volume_s8_p3": "355.023 m3", "volume_s8_p4": "358.491 m3",
		"volume_s8_p5": "362.701 m3", "volume_s8_p6": "365.879 m3", "volume_s8_p7": "371.289 m3",
		"volume_s8_p8": "373.119 m3", "volume_s8_p9": "375.105 m3", "volume_s8_p10": "377.569 m3",
		"volume_s8_p11": "381.672 m3", "date_s8_p11": "2012-12-01", "error_flags": "0000"},
	"N.6.3": {"hca_units": "1234", "date_s1": "2007-04-30", "hca_units_s1": "23456", "customer_location": "12345678"},
	"N.6.4": {"hca_units": "1234", "date_s1": "2007-04-30", "hca_units_s1": "23456", "customer_location": "12345678"},
	"N.7": {"model_version": "BKG4", "hardware_version": "0105", "firmware_version": "0101", "software_version": "0100",
		"customer_location": "DE1234564907400000000000012345678"},
	"N.9":    {"hca_units": "12345", "date_s1": "2009-12-31", "hca_units_s1": "23456"},
	"N.12.1": {"remote_control": "01"},
	"N.13": {"energy": "1996 Wh", "energy_backward": "305.1 Wh", "energy_s3": "1995 Wh",
		"energy_s3_backward": "305 Wh", "actuality_duration_s3": "3 s", "error_flags": "0000"},
}

// Covers: SIG-IPE-1441
func TestOMSAnnexNRecords(t *testing.T) {
	res := decodeAnnexN(t)
	seen := map[string]bool{}
	for i, v := range annexN {
		key := v.sec
		if strings.HasPrefix(v.sec, "N.3") || strings.HasPrefix(v.sec, "N.4") || strings.HasPrefix(v.sec, "N.5") {
			key = "water"
		}
		want := annexNRecords[key]
		r := res[i]
		if want == nil || r.tg == nil || len(r.tg.Records) == 0 {
			continue
		}
		seen[v.sec] = true
		got := map[string]string{}
		for _, rec := range r.tg.Records {
			got[rec.Name()] = strings.TrimSpace(fmt.Sprintf("%v %s", rec.Value, rec.Unit))
		}
		for name, w := range want {
			if got[name] != w {
				t.Errorf("%s %s: %s = %q, want %q", v.sec, v.msg, name, got[name], w)
			}
		}
	}
	for _, s := range []string{"N.2.1", "N.2.2", "N.2.3", "N.2.4", "N.2.5", "N.2.6", "N.3.5", "N.4.5", "N.5.5", "N.6.3", "N.6.4", "N.7", "N.9", "N.12.1", "N.13"} {
		if !seen[s] {
			t.Errorf("%s: no records decoded", s)
		}
	}
}

// Covers: SIG-IPE-1447
func TestOMSAnnexNInverseCompactProfile(t *testing.T) {
	// N.13: two inverse compact profiles (VIFE 13h) of 46 values, 8 s
	// apart, going back from the base values 1995 Wh and 305 Wh.
	imp := []float64{1994, 1991, 1986, 1979, 1970, 1962, 1956, 1952, 1950, 1950, 1950, 1950, 1950, 1950, 1950, 1950, 1950, 1950, 1950, 1950,
		1949, 1946, 1941, 1934, 1925, 1917, 1911, 1907, 1905, 1905, 1905, 1905, 1905, 1905, 1905, 1905, 1905, 1905, 1905, 1905, 1904, 1901, 1896, 1889, 1880, 1872}
	exp := []float64{305, 305, 305, 305, 305, 305, 305, 305, 305, 305, 304, 301, 296, 289, 280, 272, 266, 262, 260, 260, 260, 260, 260, 260, 260, 260, 260,
		260, 260, 260, 259, 256, 251, 244, 235, 227, 221, 217, 215, 215, 215, 215, 215, 215, 215, 215}
	v := annexNByName(t, "N.13", "SND-NR")
	tg, err := Decode(hx(t, v.frame), FormatA, func(Header) []byte { return hx(t, annexNMaster) })
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range tg.Records {
		got[r.Name()] = strings.TrimSpace(fmt.Sprintf("%v %s", r.Value, r.Unit))
	}
	for i := range imp {
		if w := fmt.Sprintf("%v Wh", imp[i]); got[fmt.Sprintf("energy_s3_p%d", i+1)] != w {
			t.Errorf("import #%d = %q, want %q", i+1, got[fmt.Sprintf("energy_s3_p%d", i+1)], w)
		}
		if w := fmt.Sprintf("%v Wh", exp[i]); got[fmt.Sprintf("energy_s3_backward_p%d", i+1)] != w {
			t.Errorf("export #%d = %q, want %q", i+1, got[fmt.Sprintf("energy_s3_backward_p%d", i+1)], w)
		}
	}
	if _, extra := got["energy_s3_p47"]; extra {
		t.Error("more than 46 profile values")
	}
}

var annexNMeterELS = func() Header {
	h, _ := ParseHeader([]byte{0, 0x44, 0x93, 0x15, 0x78, 0x56, 0x34, 0x12, 0x33, 0x03})
	return h
}()

// Covers: SIG-IPE-1442
func TestOMSAnnexNKeyDerivation(t *testing.T) {
	id := [4]byte{0x78, 0x56, 0x34, 0x12}
	for _, c := range []struct {
		sec     string
		dc      byte
		counter uint32
		want    string
	}{
		// N.2.3 (and N.2.4 to N.2.6, N.3, N.5, N.12.1, N.13): Kenc, Kmac.
		{"N.2.3 Kenc", DCEncMeter, 0x0AB3, "ECCF39D475D730B8284FDFDC1995D52F"},
		{"N.2.3 Kmac", DCMACMeter, 0x0AB3, "C9CD19FF5A9AAD5A6BBDA13BD2C4C7AD"},
		// N.12.2: the gateway's Lenc and Lmac.
		{"N.12.2 Lenc", DCEncOther, 0x0AF0, "C80712E720025DB9B4B50819C2445035"},
		{"N.12.2 Lmac", DCMACOther, 0x0AF0, "B68594D44212BBBBFD9905CC4021235B"},
		// N.12.3: the breaker's answer.
		{"N.12.3 Kenc", DCEncMeter, 0x0AF1, "B1F100E8F43BB4480295F1DC4F731655"},
		{"N.12.3 Kmac", DCMACMeter, 0x0AF1, "2ADD039729C2853E7816C5DE1C21BC69"},
	} {
		got, err := DeriveKey(hx(t, annexNMaster), c.dc, c.counter, id)
		if err != nil || !bytes.Equal(got, hx(t, c.want)) {
			t.Errorf("%s = %X (%v), want %s", c.sec, got, err, c.want)
		}
	}
}

// Covers: SIG-IPE-1442
func TestOMSAnnexNInitVectors(t *testing.T) {
	res := decodeAnnexN(t)
	// Mode 5 IVs: the meter's M and A fields and eight times the TPL
	// access number (the TPL long header's address when there is one).
	ivs := map[string]string{
		"N.2.1": "93157856341233032A2A2A2A2A2A2A2A",
		"N.4.5": "93447856341210070505050505050505",
		"N.6.3": "93448877665555080000000000000000",
		"N.6.4": "93448877665555080000000000000000",
		"N.7":   "93157856341233030101010101010101",
		"N.8.2": "93444422759200077D7D7D7D7D7D7D7D",
		"N.9":   "685078563412" + "8F08" + "0202020202020202",
	}
	done := map[string]bool{}
	for i, v := range annexN {
		want, ok := ivs[v.sec]
		if !ok || res[i].tg == nil || res[i].tg.Mode != 5 {
			continue
		}
		done[v.sec] = true
		if got := res[i].tg.Mode5IV(); !bytes.Equal(got, hx(t, want)) {
			t.Errorf("%s IV = %X, want %s", v.sec, got, want)
		}
	}
	// N.8.2's SND-UD is decoded as the meter does (CI 6Ch).
	for s := range ivs {
		if !done[s] {
			t.Errorf("%s: no mode 5 telegram decoded", s)
		}
	}
	// Mode 10 (N.2.6, N.5): nonce and associated data.
	for _, c := range []struct{ sec, frame, nonce, aad string }{
		{"N.2.6", annexNByName(t, "N.2.6", "SND-NR").frame, "93157856341233030000000AB3", "7A7500112A1001"},
	} {
		tg, err := Decode(hx(t, c.frame), FormatA, func(Header) []byte { return hx(t, annexNMaster) })
		if err != nil {
			t.Fatal(err)
		}
		if got := ccmNonce(tg.Meter, tg.Sec.Counter); !bytes.Equal(got, hx(t, c.nonce)) {
			t.Errorf("%s nonce = %X, want %s", c.sec, got, c.nonce)
		}
		if got := append(tg.tplHead(), 0x10, 0x01); !bytes.Equal(got, hx(t, c.aad)) {
			t.Errorf("%s associated data = %X, want %s", c.sec, got, c.aad)
		}
	}
	// N.5: the meter's address comes from the RSP-UD's link layer (A73D).
	for i, v := range annexN {
		if v.sec == "N.5.5" && res[i].tg != nil && res[i].tg.Sec != nil {
			tg := res[i].tg
			if got := ccmNonce(tg.Meter, tg.Sec.Counter); !bytes.Equal(got, hx(t, "A73D7856341201070000000AB3")) {
				t.Errorf("N.5.1 nonce = %X", got)
			}
			if got := append(tg.tplHead(), 0x10, 0x01); !bytes.Equal(got, hx(t, "7A0500492A1001")) {
				t.Errorf("N.5.1 associated data = %X", got)
			}
		}
	}
}

// Covers: SIG-IPE-1443
func TestOMSAnnexNMACs(t *testing.T) {
	res := decodeAnnexN(t)
	// AFL MACs (AES-CMAC truncated to 8 bytes) verified on every profile B
	// telegram; N.3.2 gives the whole CMAC of the fragmented message.
	for i, v := range annexN {
		tg := res[i].tg
		if tg == nil || tg.AFL == nil || !tg.AFL.has.mac || res[i].err != nil {
			continue
		}
		if tg.Sec == nil || !strings.Contains(strings.Join(tg.Sec.Verified, ","), "afl-cmac") {
			t.Errorf("%s %s: AFL MAC not verified (%v)", v.sec, v.msg, tg.Sec)
		}
		if v.sec == "N.3.5" && !bytes.Equal(tg.AFL.MAC, hx(t, "BE47ED4C9CC11A78581448F6774600EE")[:8]) {
			t.Errorf("N.3 message MAC = %X", tg.AFL.MAC)
		}
	}
	// N.5.2: the 8-byte CCM tag ends the message (in the last fragment).
	last := hx(t, annexNByName(t, "N.5.5", "RSP-UD").frame)
	noCRC, _, _ := StripCRC(last, FormatA)
	if tag := noCRC[len(noCRC)-8:]; !bytes.Equal(tag, hx(t, "E41370F8741B9D99")) {
		t.Errorf("N.5 tag = %X", tag)
	}
	// N.3.2: the untruncated CMAC over MCL, MCR, ML and the whole
	// (encrypted) TPDU of the three fragments, with Kmac.
	var tpdu []byte
	for _, s := range []string{"N.3.3", "N.3.4", "N.3.5"} {
		b, _, err := StripCRC(hx(t, annexNByName(t, s, "RSP-UD").frame), FormatA)
		if err != nil {
			t.Fatal(err)
		}
		tpdu = append(tpdu, payloadAfterAFL(b)...)
	}
	kmac, _ := DeriveKey(hx(t, annexNMaster), DCMACMeter, 0x0AB3, [4]byte{0x78, 0x56, 0x34, 0x12})
	in := append([]byte{0x65, 0xB3, 0x0A, 0x00, 0x00}, binary.LittleEndian.AppendUint16(nil, uint16(len(tpdu)))...)
	full, err := CMAC(kmac, append(in, tpdu...))
	if err != nil || !bytes.Equal(full, hx(t, "BE47ED4C9CC11A78581448F6774600EE")) {
		t.Errorf("N.3.2 CMAC = %X (%v)", full, err)
	}
}

func annexNHeader(t *testing.T, s string) Header {
	t.Helper()
	b := hx(t, s)
	h, err := ParseHeader(append(append([]byte{byte(len(b))}, b...), CINoHeader))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// annexNNoCRC is a vector's frame without its CRCs.
func annexNNoCRC(t *testing.T, sec, msg string) []byte {
	t.Helper()
	b, _, err := StripCRC(hx(t, annexNByName(t, sec, msg).frame), FormatA)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Covers: SIG-IPE-1444
func TestOMSAnnexNSealMeterFrames(t *testing.T) {
	mk := hx(t, annexNMaster)
	els := annexNHeader(t, "44 9315 78563412 33 03")
	breaker := annexNHeader(t, "44 3A63 78563412 55 20")
	omg := annexNHeader(t, "44 A73D 78563412 01 02")
	gasAPL := hx(t, "0C1427048502046D32371F1502FD170000")
	link := func(t *testing.T, head string, tpdu []byte) []byte {
		b := append(hx(t, head), tpdu...)
		b[0] = byte(len(b) - 1)
		return b
	}
	padding := false // N.12.4 uses TPL padding (P bit of the configuration field)
	b7 := func(t *testing.T, ci byte, long bool, m Header, acc, st byte, ctr uint32, toMeter bool, apl []byte) []byte {
		tpdu, err := SealTPL(ci, long, m, acc, st, 0, Seal{Mode: 7, Key: mk, KDF: 1, KeyVersion: -1, Counter: ctr, ToMeter: toMeter, Padding: padding}, apl)
		if err != nil {
			t.Fatal(err)
		}
		out, err := SealAFL(tpdu, m, mk, 1, ctr, 5, nil, toMeter)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	sitpAPL := func(t *testing.T, bcf byte, dir byte) []byte {
		content, err := SealSITPApp(hx(t, annexNASP10), DSICMAC8, breaker, dir,
			SITPApp{KeyCounter: 15, At: TargetTime{0, 0, 0, 0, 0x30}, PID: 0x01, APDU: hx(t, "01FD1F00")})
		if err != nil {
			t.Fatal(err)
		}
		return EncodeSITP(SITPBlock{ID: 0, BCF: bcf, Recipient: 0, DSI: DSICMAC8, DSH1: 0x20, DSH2: 0x00, Content: content})
	}
	cases := []struct {
		sec, msg string
		build    func(t *testing.T) []byte
		tail     bool // compare the TPDU only (the link and ELL are an adapter's)
	}{
		{"N.2.1", "SND-NR", func(t *testing.T) []byte {
			tpdu, err := SealTPL(CIShortHeader, false, els, 0x2A, 0x00, 0x2000, Seal{Mode: 5, Key: hx(t, annexNKeyELS)}, gasAPL)
			if err != nil {
				t.Fatal(err)
			}
			return link(t, "00 44 9315 78563412 33 03", tpdu)
		}, false},
		{"N.2.3", "SND-NR", func(t *testing.T) []byte {
			return link(t, "00 44 9315 78563412 33 03 8C 20 75", b7(t, CIShortHeader, false, els, 0x75, 0, 0x0AB3, false, gasAPL))
		}, false},
		{"N.2.4", "RSP-UD", func(t *testing.T) []byte {
			return b7(t, CILongHeader, true, els, 0x75, 0, 0x0AB3, false, gasAPL)
		}, true},
		{"N.2.6", "SND-NR", func(t *testing.T) []byte {
			tpdu, err := SealTPL(CIShortHeader, false, els, 0x75, 0, 0, Seal{Mode: 10, Key: mk, KDF: 1, KeyVersion: -1, Counter: 0x0AB3, CounterInTPL: true, TagLen: 8}, gasAPL)
			if err != nil {
				t.Fatal(err)
			}
			return link(t, "00 44 9315 78563412 33 03 8C 20 75", tpdu)
		}, false},
		{"N.12.1", "SND-NR", func(t *testing.T) []byte {
			return link(t, "00 44 3A63 78563412 55 20 8C A4 E5", b7(t, CIShortHeader, false, breaker, 0x75, 0, 0x0AB3, false, hx(t, "01FD1F01")))
		}, false},
		{"N.12.3", "RSP-UD (set breaker, successful)", func(t *testing.T) []byte {
			return link(t, "00 08 3A63 78563412 55 20 8C 84 23", b7(t, CISITPRespShort, false, breaker, 0x51, 0, 0x0AF1, false, sitpAPL(t, 0xA0, SITPUp)))
		}, false},
		{"N.12.4", "RSP-UD (set breaker, failure)", func(t *testing.T) []byte {
			apl := EncodeSITP(SITPBlock{ID: 0, BCF: 0xA0, DSI: DSIStatus, DSH1: 0x20, DSH2: 0x00, Content: []byte{0x19}})
			padding = true
			defer func() { padding = false }()
			return link(t, "00 08 3A63 78563412 55 20 8C 84 23", b7(t, CISITPRespShort, false, breaker, 0x51, 0x02, 0x0AF1, false, apl))
		}, false},
		{"N.13", "SND-NR", func(t *testing.T) []byte {
			tg, err := Decode(hx(t, annexNByName(t, "N.13", "SND-NR").frame), FormatA, func(Header) []byte { return mk })
			if err != nil {
				t.Fatal(err)
			}
			apl := bytes.TrimRight(tg.APL[2:], "\x2F")
			return link(t, "00 44 A73D 78563412 01 02 8C 20 0A", b7(t, CIShortHeader, false, omg, 0x0A, 0, 0x0AB3, false, apl))
		}, false},
	}
	for _, c := range cases {
		t.Run(c.sec, func(t *testing.T) {
			want := annexNNoCRC(t, c.sec, c.msg)
			got := c.build(t)
			if c.tail {
				want = want[len(want)-len(got):]
			} else if !bytes.Equal(AddCRCA(got), hx(t, annexNByName(t, c.sec, c.msg).frame)) {
				t.Errorf("with CRCs:\n got % X\nwant %s", AddCRCA(got), annexNByName(t, c.sec, c.msg).frame)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("\n got % X\nwant % X", got, want)
			}
		})
	}
}

// Covers: SIG-IPE-1445
func TestOMSAnnexNDownlinks(t *testing.T) {
	gw := func(t *testing.T, m, id string, v byte) Gateway {
		g := Gateway{Manufacturer: m, ID: id, Version: v}
		if err := g.Validate(); err != nil {
			t.Fatal(err)
		}
		return g
	}
	mk := hx(t, annexNMaster)
	els := annexNHeader(t, "44 9315 78563412 33 03")
	cases := []struct {
		sec, msg string
		build    func(t *testing.T) ([]byte, error)
	}{
		{"N.3.3", "REQ-UD2", func(t *testing.T) ([]byte, error) {
			return EncodeDownlink(gw(t, "XYZ", "33445566", 0x0A), annexNHeader(t, "7B 496A 78563412 01 07"),
				Downlink{C: 0x7B, CI: CIToMeterNoAPL, Status: 0x17}, 0x11, 0x05, nil)
		}},
		{"N.5.3", "REQ-UD2", func(t *testing.T) ([]byte, error) {
			return EncodeDownlink(gw(t, "XYZ", "33445566", 0x0A), annexNHeader(t, "7B A73D 78563412 01 07"),
				Downlink{C: 0x7B, CI: CIToMeterNoAPL, Status: 0x17}, 0x11, 0x05, nil)
		}},
		{"N.7", "CNF-IR", func(t *testing.T) ([]byte, error) {
			return EncodeDownlink(gw(t, "XYZ", "33445566", 0x0A), els, Downlink{C: CCnfIR, CI: CIToMeterNoAPL, Status: 0x19}, 0x45, 0x01, nil)
		}},
		{"N.8.2", "SND-UD", func(t *testing.T) ([]byte, error) {
			// Clock synchronisation (CI 6Ch): add 1 min 50 s (type J),
			// reserved bytes; security profile A with the meter's key.
			return EncodeDownlink(gw(t, "HYD", "90123456", 0x08), annexNHeader(t, "53 9344 44227592 00 07"),
				Downlink{C: CSndUD, CI: CIClockLong, APL: hx(t, "01 320100 000000000000")}, 0x51, 0x7D, hx(t, annexNKeyN8))
		}},
		{"N.11", "SND-NKE", func(t *testing.T) ([]byte, error) {
			return EncodeDownlink(gw(t, "XYZ", "66778899", 0x0C), annexNHeader(t, "40 9344 44332211 10 0A"),
				Downlink{C: 0x40, CI: CIToMeterNoAPL, Status: 0x20}, 0x32, 0x03, nil)
		}},
		{"N.12.2", "SND-UD2", func(t *testing.T) ([]byte, error) {
			// SITP command with an ASP10 structure (DSI 32h), profile B
			// towards the meter (Lenc, Lmac) and an AFL without KI.
			breaker := annexNHeader(t, "43 3A63 78563412 55 20")
			content, err := SealSITPApp(hx(t, annexNASP10), DSICMAC8, breaker, SITPDown,
				SITPApp{KeyCounter: 15, At: TargetTime{0, 0, 0, 0, 0x30}, PID: 0x01, APDU: hx(t, "01FD1F00")})
			if err != nil {
				return nil, err
			}
			apl := EncodeSITP(SITPBlock{BCF: SITPSecuredData, DSI: DSICMAC8, DSH1: 0x20, Content: content})
			tpdu, err := SealTPL(CISITPCmdLong, true, breaker, 0x51, 0x20, 0, Seal{Mode: 7, Key: mk, KDF: 1, KeyVersion: -1, Counter: 0x0AF0, ToMeter: true}, apl)
			if err != nil {
				return nil, err
			}
			if tpdu, err = SealAFL(tpdu, breaker, mk, 1, 0x0AF0, 5, nil, true); err != nil {
				return nil, err
			}
			b := append(hx(t, "00 43 3A63 21436587 08 31 8C 84 23"), tpdu...)
			b[0] = byte(len(b) - 1)
			return b, nil
		}},
	}
	for _, c := range cases {
		t.Run(c.sec+" "+c.msg, func(t *testing.T) {
			got, err := c.build(t)
			if err != nil {
				t.Fatal(err)
			}
			v := annexNByName(t, c.sec, c.msg)
			if want := annexNNoCRC(t, c.sec, c.msg); !bytes.Equal(got, want) {
				t.Errorf("\n got % X\nwant % X", got, want)
			}
			if !bytes.Equal(AddCRCA(got), hx(t, v.frame)) {
				t.Errorf("with CRCs:\n got % X\nwant %s", AddCRCA(got), v.frame)
			}
		})
	}
}

// Covers: SIG-IPE-1446
func TestOMSAnnexNSITP(t *testing.T) {
	res := decodeAnnexN(t)
	key := hx(t, annexNASP10)
	get := func(sec string) *Telegram {
		for i, v := range annexN {
			if v.sec == sec {
				if res[i].err != nil {
					t.Fatalf("%s: %v", sec, res[i].err)
				}
				return res[i].tg
			}
		}
		t.Fatalf("no %s", sec)
		return nil
	}
	// N.12.2: the gateway's command, end-to-end authenticated (ASP10).
	cmd := get("N.12.2")
	if len(cmd.SITP) != 1 || cmd.SITP[0].BCF != SITPSecuredData || cmd.SITP[0].DSI != DSICMAC8 || cmd.SITP[0].DSH1 != 0x20 {
		t.Fatalf("N.12.2 blocks %+v", cmd.SITP)
	}
	app, err := OpenSITPApp(key, DSICMAC8, cmd.Meter, SITPDown, cmd.SITP[0].Content)
	if err != nil || app.KeyCounter != 15 || app.At != (TargetTime{0, 0, 0, 0, 0x30}) || app.PID != 1 || !bytes.Equal(app.APDU, hx(t, "01FD1F00")) {
		t.Errorf("N.12.2 secured data = %+v (%v)", app, err)
	}
	if recs, err := records.ParseRecords(app.APDU); err != nil || len(recs) != 1 || recs[0].Name() != "remote_control" {
		t.Errorf("N.12.2 APDU records %v (%v)", recs, err)
	}
	// N.12.3: the breaker's answer carries the same structure (the
	// CMAC covers key counter and data, not the block header).
	rsp := get("N.12.3")
	rs, err := ReadSITPResponses(rsp.APL, rsp.Meter, func(id, v byte) []byte {
		if id == 0x20 && v == 0 {
			return key
		}
		return nil
	})
	if err != nil || len(rs) != 1 || rs[0].App == nil || rs[0].App.KeyCounter != 15 || !bytes.Equal(rs[0].App.APDU, hx(t, "01FD1F00")) {
		t.Errorf("N.12.3 responses %+v (%v)", rs, err)
	}
	// N.12.4: status 19h instead.
	fail := get("N.12.4")
	rs, err = ReadSITPResponses(fail.APL, fail.Meter, nil)
	if err != nil || len(rs) != 1 || rs[0].Status == nil || *rs[0].Status != 0x19 {
		t.Errorf("N.12.4 responses %+v (%v)", rs, err)
	}
	if fail.Status != 0x02 {
		t.Errorf("N.12.4 TPL status %02X, want 02h (application error)", fail.Status)
	}
}

// Covers: SIG-IPE-1448
func TestOMSSecurityProfile(t *testing.T) {
	// Annex N.1 lists the security profile of every example; the
	// classifier gives the same for each decoded message.
	want := map[string]string{
		"N.2.1": "A", "N.2.2": "none", "N.2.3": "B", "N.2.4 RSP-UD": "B", "N.2.5": "B", "N.2.6": "D",
		"N.3.5 RSP-UD": "B", "N.4.5 RSP-UD": "A", "N.5.5 RSP-UD": "D",
		"N.6.2": "none", "N.6.3": "A", "N.6.4": "A", "N.7 SND-IR": "A", "N.8.2 SND-UD": "A",
		"N.9 RSP-UD (wM-Bus)": "A", "N.9 RSP-UD (wM-Bus - Appl": "none", "N.10 ACC-DMD": "none", "N.10 ACK": "none",
		"N.11": "none", "N.12.1": "B", "N.12.2": "B", "N.12.3": "B", "N.12.4": "B", "N.13": "B",
		// Footnote d of Table 43: these messages use mode 0 without AFL
		// under every profile.
		"N.2.4 REQ-UD2": "none", "N.3.3 REQ-UD2": "none", "N.7 CNF-IR": "none", "N.8.2 ACK": "none",
	}
	res := decodeAnnexN(t)
	checked := 0
	for i, v := range annexN {
		for k, p := range want {
			sec, msg, _ := strings.Cut(k, " ")
			if v.sec != sec || !strings.HasPrefix(v.msg, msg) {
				continue
			}
			checked++
			if got := OMSProfile(res[i].tg); got != p {
				t.Errorf("%s %s: profile %q, want %q", v.sec, v.msg, got, p)
			}
		}
	}
	if checked < len(want) {
		t.Errorf("%d of %d annex messages checked", checked, len(want))
	}
	// Combinations that are no OMS profile.
	m := annexNHeader(t, "44 9315 78563412 33 03")
	mk := hx(t, annexNMaster)
	apl := hx(t, "0C1427048502046D32371F1502FD170000")
	decode := func(t *testing.T, tpdu []byte) *Telegram {
		t.Helper()
		b := append(hx(t, "00 44 9315 78563412 33 03"), tpdu...)
		b[0] = byte(len(b) - 1)
		tg, err := Decode(b, FormatNoCRC, func(Header) []byte { return mk })
		if err != nil {
			t.Fatal(err)
		}
		return tg
	}
	seal := func(t *testing.T, s Seal) []byte {
		t.Helper()
		s.Key, s.KeyVersion = mk, -1
		tpdu, err := SealTPL(CIShortHeader, false, m, 1, 0, 0, s, apl)
		if err != nil {
			t.Fatal(err)
		}
		return tpdu
	}
	aflWith := func(t *testing.T, tpdu []byte, at byte, kdf int) []byte {
		t.Helper()
		out, err := SealAFL(tpdu, m, mk, kdf, 7, at, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, c := range []struct {
		name string
		tpdu func(t *testing.T) []byte
		want string
	}{
		{"mode 7 counter in the TPL, no AFL MAC", func(t *testing.T) []byte {
			return seal(t, Seal{Mode: 7, KDF: 1, Counter: 7, CounterInTPL: true})
		}, ""},
		{"mode 7 with a 4-byte AFL CMAC", func(t *testing.T) []byte {
			return aflWith(t, seal(t, Seal{Mode: 7, KDF: 1, Counter: 7}), 4, 1)
		}, ""},
		{"mode 7 with the 8-byte AFL CMAC", func(t *testing.T) []byte {
			return aflWith(t, seal(t, Seal{Mode: 7, KDF: 1, Counter: 7}), 5, 1)
		}, "B"},
		{"mode 10 with a 4-byte tag", func(t *testing.T) []byte {
			return seal(t, Seal{Mode: 10, KDF: 1, Counter: 7, CounterInTPL: true, TagLen: 4})
		}, ""},
		{"mode 10 with an 8-byte tag", func(t *testing.T) []byte {
			return seal(t, Seal{Mode: 10, KDF: 1, Counter: 7, CounterInTPL: true, TagLen: 8})
		}, "D"},
		{"mode 10 with the counter in the AFL", func(t *testing.T) []byte {
			return aflWith(t, seal(t, Seal{Mode: 10, KDF: 1, Counter: 7, TagLen: 8}), 5, 1)
		}, ""},
		{"mode 10 with a persistent key", func(t *testing.T) []byte {
			return seal(t, Seal{Mode: 10, KDF: 0, Counter: 7, CounterInTPL: true, TagLen: 8})
		}, ""},
		{"mode 9", func(t *testing.T) []byte {
			return seal(t, Seal{Mode: 9, KDF: 1, Counter: 7})
		}, ""},
		{"mode 5 behind an AFL MAC", func(t *testing.T) []byte {
			return aflWith(t, seal(t, Seal{Mode: 5}), 5, 0)
		}, ""},
		{"mode 0 behind an AFL MAC", func(t *testing.T) []byte {
			return aflWith(t, seal(t, Seal{Mode: 0}), 5, 0)
		}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := OMSProfile(decode(t, c.tpdu(t))); got != c.want {
				t.Errorf("profile %q, want %q", got, c.want)
			}
		})
	}
	if OMSProfile(nil) != "" {
		t.Error("nil telegram classified")
	}
}

// Covers: SIG-IPE-1450
func TestOMSAnnexNTransportOnlyCIs(t *testing.T) {
	res := decodeAnnexN(t)
	find := func(sec, msg string) *Telegram {
		for i, v := range annexN {
			if v.sec == sec && strings.HasPrefix(v.msg, msg) {
				if res[i].err != nil {
					t.Fatalf("%s %s: %v", sec, msg, res[i].err)
				}
				return res[i].tg
			}
		}
		t.Fatalf("no %s %s", sec, msg)
		return nil
	}
	// N.6.2: ACC-NR of an RF adapter, CI 8Bh: the meter behind it is in
	// the long header, with its status (low power).
	acc := find("N.6.2", "ACC-NR")
	if acc.HeaderKind != "long" || acc.Meter.Key() != "QDS-55667788" || acc.Header.Key() != "QDS-11223344" ||
		acc.Status != 0x04 || acc.Access != 0xFF || len(acc.APL) != 0 || len(acc.Records) != 0 {
		t.Errorf("N.6.2: %+v", acc)
	}
	// N.8.2: clock synchronisation (CI 6Ch) decoded as the meter does:
	// TC 01h (add, type J), 00:01:50, reserved bytes, verification.
	clk := find("N.8.2", "SND-UD")
	if clk.Meter.Key() != "QDS-92752244" || !clk.Encrypted || !bytes.Equal(clk.APL, hx(t, "2F2F 01 320100 000000000000 2F2F2F2F")) {
		t.Errorf("N.8.2 clock sync: meter %s APL % X", clk.Meter.Key(), clk.APL)
	}
	// ... and the meter's ACK (8Bh) with the application error status.
	if ack := find("N.8.2", "ACK"); ack.HeaderKind != "long" || ack.Meter.Key() != "QDS-92752244" || ack.Status != 0x02 {
		t.Errorf("N.8.2 ACK: %+v", ack)
	}
	// N.9: application error with a short header (CI 6Eh), error 01h.
	if ae := find("N.9", "RSP-UD (wM-Bus - Appl"); ae.HeaderKind != "short" || ae.Access != 0x02 || ae.Status != 0x02 || !bytes.Equal(ae.APL, []byte{0x01}) {
		t.Errorf("N.9 application error: %+v", ae)
	}
	// N.10: ACC-DMD, CI 8Bh.
	if dmd := find("N.10", "ACC-DMD"); dmd.HeaderKind != "long" || dmd.Meter.Key() != "ZYX-38546816" {
		t.Errorf("N.10 ACC-DMD: %+v", dmd)
	}
	// The short/long partners of these CIs.
	for _, c := range []struct {
		ci   byte
		long bool
	}{{CIPureShort, false}, {CIClockShort, false}, {CIAppErrLong, true}, {CIAlarmShort, false}, {CIAlarmLong, true}} {
		tpdu, err := SealTPL(c.ci, c.long, annexNHeader(t, "44 9344 88776655 55 08"), 9, 0, 0, Seal{}, []byte{0x07})
		if err != nil {
			t.Fatal(err)
		}
		b := append(hx(t, "00 44 9344 44332211 55 37"), tpdu...)
		b[0] = byte(len(b) - 1)
		tg, err := Decode(b, FormatNoCRC, nil)
		if err != nil || tg.Access != 9 || tg.HeaderKind != map[bool]string{false: "short", true: "long"}[c.long] || !bytes.Equal(tg.APL, []byte{7}) || len(tg.Records) != 0 {
			t.Errorf("CI %02X: %+v (%v)", c.ci, tg, err)
		}
		if c.long && tg.Meter.Key() != "QDS-55667788" {
			t.Errorf("CI %02X meter %s", c.ci, tg.Meter.Key())
		}
	}
}

// Covers: SIG-IPE-1451
func TestOMSAnnexNLinkOnlyFrames(t *testing.T) {
	// N.3.4: the gateway's REQ-UD2 for the next fragment is a link frame
	// with a long ELL (destination address) and no TPL.
	for _, sec := range []string{"N.3.4", "N.3.5", "N.5.4", "N.5.5"} {
		tg, err := Decode(hx(t, annexNByName(t, sec, "REQ-UD2").frame), FormatA, nil)
		if err != nil {
			t.Fatalf("%s: %v", sec, err)
		}
		if tg.ELL == nil || !tg.ELL.HasAddr || tg.ELL.CI != CIELL10 || tg.C != 0x5B && tg.C != 0x7B || tg.CI != 0 || tg.Records != nil {
			t.Errorf("%s: %+v ELL %+v", sec, tg, tg.ELL)
		}
	}
	// Without the ELL, a frame without CI is still refused.
	if _, err := Decode(hx(t, "0A 7B 3A63 66554433 0A 31"), FormatNoCRC, nil); err == nil {
		t.Error("a frame without CI field decoded")
	}
}

// Covers: SIG-IPE-1452
func TestOMSLargeCBCMessages(t *testing.T) {
	// OMS Volume 2 7.2.4.3 and 7.2.4.4: N = 1111b disables partial
	// encryption so that more than 14 blocks can be encrypted (large,
	// fragmented messages). Sealing must not overflow N into the mode.
	m := annexNHeader(t, "44 9315 78563412 33 03")
	key := hx(t, annexNMaster)
	apl := bytes.Repeat(hx(t, "0C1427048502"), 50) // 300 bytes, 19 blocks with 2F2F
	for _, s := range []Seal{{Mode: 5, Key: key}, {Mode: 7, Key: key, KDF: 1, KeyVersion: -1, Counter: 9, CounterInTPL: true}} {
		tpdu, err := SealTPL(CILongHeader, true, m, 1, 0, 0, s, apl)
		if err != nil {
			t.Fatal(err)
		}
		cfg := binary.LittleEndian.Uint16(tpdu[11:13])
		if int(cfg>>8&0x1F) != s.Mode || cfg>>4&0x0F != 0x0F {
			t.Errorf("mode %d: configuration field %04X, want mode %d and N = 1111b", s.Mode, cfg, s.Mode)
		}
		d := &Decoder{}
		var frame []byte
		for i, part := 0, tpdu; len(part) > 0; i++ { // AFL fragments of at most 200 bytes
			n := min(len(part), 200)
			fcl := uint16(i+1) & 0xFF
			if n < len(part) {
				fcl |= AFLMF
			}
			b := append(hx(t, "00 44 9315 78563412 33 03 90 02"), byte(fcl), byte(fcl>>8))
			b = append(b, part[:n]...)
			b[0] = byte(len(b) - 1)
			part = part[n:]
			frame = b
			tg, err := d.Decode(frame, FormatNoCRC, func(Header) []byte { return key })
			if len(part) > 0 {
				if !errors.Is(err, ErrFragment) {
					t.Fatalf("mode %d fragment %d: %v", s.Mode, i+1, err)
				}
				continue
			}
			if err != nil || len(tg.Records) != 50 || tg.Sec.EncryptedLen != 304 {
				t.Errorf("mode %d: %d records, %d bytes encrypted (%v)", s.Mode, len(tg.Records), tg.Sec.EncryptedLen, err)
			}
		}
	}
	// With unencrypted data after 15 or more blocks N cannot say where
	// the encryption ends.
	if _, err := SealTPL(CILongHeader, true, m, 1, 0, 0, Seal{Mode: 5, Key: key, Unencrypted: []byte{0x01, 0xFD, 0x1F, 0x01}}, apl); err == nil {
		t.Error("partial encryption of 19 blocks sealed")
	}
}

// Covers: SIG-IPE-1453
func TestOMSAnnexGCompactProfiles(t *testing.T) {
	// OMS Volume 2 annex G.6 and G.7: the load profile of table G.1 as a
	// compact profile (increments, month spacing, end of month) and as an
	// inverse compact profile; both convert to the single data points of
	// tables G.5 and G.7.
	vol := map[int]string{0: "0.065 m3", 1: "0.209 m3", 2: "0.423 m3", 3: "0.755 m3", 4: "1.013 m3"}
	day := map[int]string{0: "2008-01-31", 1: "2008-02-29", 2: "2008-03-31", 3: "2008-04-30", 4: "2008-05-31"}
	for _, c := range []struct {
		name, hex string
		at        func(k int) int // month index (0 = January) of profile value k (0 = base)
	}{
		{"G.6 compact", "8C04136500000082046C1F118D04931F0A7AFE4401140232035802", func(k int) int { return k }},
		{"G.7 inverse compact", "8C04131310000082046C1F158D0493130A7AFE5802320314024401", func(k int) int { return 4 - k }},
	} {
		recs, err := records.ParseRecords(hx(t, c.hex))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := map[string]string{}
		for _, r := range recs {
			got[r.Name()] = strings.TrimSpace(fmt.Sprintf("%v %s", r.Value, r.Unit))
		}
		for k := 0; k <= 4; k++ {
			vn, dn := "volume_s8", "date_s8"
			if k > 0 {
				vn, dn = fmt.Sprintf("volume_s8_p%d", k), fmt.Sprintf("date_s8_p%d", k)
			}
			if got[vn] != vol[c.at(k)] || got[dn] != day[c.at(k)] {
				t.Errorf("%s value %d: %s = %q at %q, want %q at %q (all: %v)", c.name, k, vn, got[vn], got[dn], vol[c.at(k)], day[c.at(k)], got)
			}
		}
	}
}

// Covers: SIG-IPE-1454
func TestOMSLinkControlBits(t *testing.T) {
	res := decodeAnnexN(t)
	want := map[string]bool{
		"N.2.1":  false, // CF 2520h: synchronous, not bidirectional, no ELL
		"N.2.3":  false, // CC 20h
		"N.6.3":  false, // CC 00h
		"N.9":    true,  // CC 80h
		"N.12.1": true,  // CC A4h
	}
	for i, v := range annexN {
		if w, ok := want[v.sec]; ok && strings.HasPrefix(v.msg, "SND-NR") || ok && v.sec == "N.9" && v.msg == "RSP-UD (wM-Bus)" {
			if got := linkBidirectional(res[i].tg); got != w {
				t.Errorf("%s %s: bidirectional %v, want %v", v.sec, v.msg, got, w)
			}
		}
	}
	m := annexNHeader(t, "44 9315 78563412 33 03")
	key := hx(t, annexNKeyELS)
	for _, c := range []struct {
		name string
		ell  string
		hi   uint16
		want bool
	}{
		{"mode 5 without ELL, B set in the configuration field", "", 0x8000, true},
		{"mode 5 without ELL, B clear", "", 0x2000, false},
		{"ELL CC without B wins over the configuration field", "8C 20 01", 0x8000, false},
		{"ELL CC with B", "8C 80 01", 0x0000, true},
	} {
		tpdu, err := SealTPL(CIShortHeader, false, m, 1, 0, c.hi, Seal{Mode: 5, Key: key}, hx(t, "0C1427048502"))
		if err != nil {
			t.Fatal(err)
		}
		b := append(hx(t, "00 44 9315 78563412 33 03"+c.ell), tpdu...)
		b[0] = byte(len(b) - 1)
		tg, err := Decode(b, FormatNoCRC, func(Header) []byte { return key })
		if err != nil {
			t.Fatal(err)
		}
		if got := linkBidirectional(tg); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

// Covers: SIG-IPE-2133
func TestDLMSOverMBusCIs(t *testing.T) {
	// EN 13757-1:2021 9.2.1 Figure 11: a DLMS/COSEM APDU behind CI 7Ch
	// (long header) or 7Dh (short) from the meter, 60h or 61h to it. The
	// APDU (here a data-notification tag 0Fh start) is kept as bytes, not
	// read as data records.
	apdu := []byte{0x0F, 0x00, 0x00, 0x00, 0x01, 0x00}
	for _, c := range []struct {
		ci   byte
		long bool
	}{{CIDLMSLong, true}, {CIDLMSShort, false}, {CIDLMSToMeterLong, true}, {CIDLMSToMeterShort, false}} {
		tpdu, err := SealTPL(c.ci, c.long, annexNHeader(t, "44 9344 88776655 55 08"), 9, 0, 0, Seal{}, apdu)
		if err != nil {
			t.Fatal(err)
		}
		b := append(hx(t, "00 44 9344 44332211 55 37"), tpdu...)
		b[0] = byte(len(b) - 1)
		tg, err := Decode(b, FormatNoCRC, nil)
		if err != nil || !IsDLMS(tg.CI) || tg.Access != 9 || tg.HeaderKind != map[bool]string{false: "short", true: "long"}[c.long] ||
			!bytes.Equal(tg.APL, apdu) || len(tg.Records) != 0 {
			t.Errorf("CI %02X: %+v (%v)", c.ci, tg, err)
		}
	}
	if IsDLMS(CILongHeader) || IsDLMS(CIShortHeader) {
		t.Error("M-Bus data record CIs taken for DLMS")
	}
}
