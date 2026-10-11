package wireless

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// OMS Volume 2 annex N.3 (release E, 2023-12): a water meter (ZRI
// 12345678) answers with one mode 7 message in three RSP-UD fragments
// (frame format A, ELL CI 8E, AFL with FID 1, 2, 3; MCL, MCR and ML in
// the first fragment, the MAC in the last), master key 000102…0F, message
// counter 2739.
var omsFragments = []string{
	"3908496A78563412010714648E80113A63665544330A319009017865D438B30A000056007A050050071030539A7C63ABDB1CBCA6D43CB02D762A1E1626FEEF0E8E95",
	"3908496A78563412010714648E80123A63665544330A3190020240C4E9B390278E41A48BAD1438BDE38D4D116630215F5DEFF6392B6BE31A9FC812757BE805B4B186",
	"3B08496A78563412010763428E80133A63665544330A31900A0304BE41AF47ED4C9CC11A7806CC3E0457C725B4B2CD8C9BE7FEF078777187CCEF8E2AF51CC7299583EF7AC7F2",
}

// Covers: SIG-IPE-669
func TestWMBusFragmentedMessage(t *testing.T) {
	master := hx(t, "000102030405060708090A0B0C0D0E0F")
	keys := func(Header) []byte { return master }
	// The annex's session keys for counter 2739 (0x0AB3).
	id := [4]byte{0x78, 0x56, 0x34, 0x12}
	kenc, _ := DeriveKey(master, DCEncMeter, 0x0AB3, id)
	kmac, _ := DeriveKey(master, DCMACMeter, 0x0AB3, id)
	if hex.EncodeToString(kenc) != "eccf39d475d730b8284fdfdc1995d52f" || hex.EncodeToString(kmac) != "c9cd19ff5a9aad5a6bbda13bd2c4c7ad" {
		t.Fatalf("Kenc %x Kmac %x", kenc, kmac)
	}
	frags := make([][]byte, len(omsFragments))
	for i, s := range omsFragments {
		frags[i] = hx(t, s)
	}
	// Without a Decoder a fragment is refused as unsupported.
	if _, err := Decode(frags[0], FormatA, keys); !errors.Is(err, ErrUnsupport) {
		t.Errorf("stateless decode of a fragment: %v", err)
	}
	var d Decoder
	for i := range 2 {
		if _, err := d.Decode(frags[i], FormatA, keys); !errors.Is(err, ErrFragment) {
			t.Fatalf("fragment %d: %v, want ErrFragment", i+1, err)
		}
	}
	tg, err := d.Decode(frags[2], FormatA, keys)
	if err != nil {
		t.Fatal(err)
	}
	if tg.Mode != 7 || !tg.Encrypted || tg.AFL.Fragments != 3 || tg.AFL.Counter != 2739 || tg.AFL.ML != 86 || tg.Meter.Key() != "ZRI-12345678" {
		t.Errorf("telegram: mode %d enc %v AFL %+v meter %s", tg.Mode, tg.Encrypted, tg.AFL, tg.Meter.Key())
	}
	rm := recordMap(tg.Records)
	if r := rm["volume"]; r.Value != 411.979 || r.Unit != "m3" {
		t.Errorf("current volume = %v %s (records %v)", r.Value, r.Unit, keysOf(rm))
	}
	if r := rm["volume_s1"]; r.Value != 383.294 {
		t.Errorf("due date volume = %v", r.Value)
	}
	if len(d.partial) != 0 {
		t.Errorf("partial messages left: %d", len(d.partial))
	}

	// A changed byte in the middle fragment breaks the MAC over the whole
	// message.
	bad := append([]byte(nil), frags[1]...)
	bad[40] ^= 1 // inside the second block (the CRC is fixed below)
	fixCRCA(bad)
	var d2 Decoder
	d2.Decode(frags[0], FormatA, keys)
	d2.Decode(bad, FormatA, keys)
	if _, err := d2.Decode(frags[2], FormatA, keys); !errors.Is(err, ErrMAC) {
		t.Errorf("changed middle fragment: %v, want ErrMAC", err)
	}
	// A missing fragment: the last one does not follow the first.
	var d3 Decoder
	d3.Decode(frags[0], FormatA, keys)
	if _, err := d3.Decode(frags[2], FormatA, keys); err == nil || errors.Is(err, ErrFragment) {
		t.Errorf("gap: %v", err)
	}
	// A stale partial message is dropped.
	at := time.Unix(1_700_000_000, 0)
	d4 := Decoder{Now: func() time.Time { return at }}
	d4.Decode(frags[0], FormatA, keys)
	d4.Decode(frags[1], FormatA, keys)
	at = at.Add(FragmentTimeout + time.Second)
	if _, err := d4.Decode(frags[2], FormatA, keys); err == nil {
		t.Error("the last fragment completed a stale message")
	}
}

// fixCRCA recomputes the block CRCs of a format A frame in place.
func fixCRCA(b []byte) {
	put := func(from, to int) {
		c := CRC(b[from:to])
		b[to], b[to+1] = byte(c>>8), byte(c)
	}
	put(0, 10)
	for i := 12; i < len(b); i += 18 {
		end := min(i+16, len(b)-2)
		put(i, end)
	}
}
