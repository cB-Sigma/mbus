package wireless

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Transport layer security (EN 13757-7:2025 clauses 7.6, 7.7 and 9.2 to
// 9.6): the configuration field and its extension, the optional header
// and trailer fields of security modes 5, 7, 8, 9 and 10, message counters
// and the reaction to a failed check.
//
//   - mode 5: AES-128-CBC, IV from the meter address and the access number;
//   - mode 7: AES-128-CBC with IV 0 and an ephemeral key (KDF-A), TPL
//     counter (Z), key version (V), TPL padding (P); authenticated by the
//     AFL (AES-CMAC or AES-GMAC);
//   - mode 8: AES-128-CTR with MAC_1 (4-byte CMAC) and the optional MAC_2
//     (2-byte CMAC) with a transmission time stamp;
//   - mode 9: AES-128-GCM, 12-byte tag;
//   - mode 10: AES-128-CCM, tag of 4, 8, 12 or 16 bytes.
//
// For modes 5, 8, 9 and 10 the IV/nonce uses the TPL long header's address
// when there is one, else the link layer's (Telegram.Meter in both cases).

// Security is what a telegram's TPL says about its protection.
type Security struct {
	KeyID      int // 0–15 (Table 25)
	KeyVersion int // -1 when the message carries none
	KDF        int // 0 persistent key, 1 KDF-A
	// Counter is the message counter the mechanism used: the TPL's when
	// it has one, else the AFL's.
	Counter      uint32
	HasCounter   bool
	CounterFrom  string // "tpl" or "afl"
	Content      int    // CC subfield (Tables 21, 22)
	ContentIndex int    // IIII subfield (Table 23)
	// EncryptedLen and UnencryptedLen split the application data.
	EncryptedLen, UnencryptedLen int
	// TagLen is mode 10's CCM tag length (OMS profile D needs 8).
	TagLen int
	// Timestamp is mode 8's transmission time stamp: seconds since
	// 2013-01-01 00:00 (UTC is not stated; see findings).
	Timestamp *uint32
	// Verified lists the checks that passed: "decrypt-2f2f", "afl-cmac",
	// "afl-gmac", "mac1", "mac2", "gcm", "ccm".
	Verified []string
	// Unverified lists checks the telegram offers that could not be made
	// (e.g. "mac2" without a MAC_2 key).
	Unverified []string
	// aplEnc is how many bytes at the start of Telegram.APL were
	// encrypted (after TPL padding was removed).
	aplEnc int
}

// encLen is the number of leading APL bytes that were encrypted (the
// compact-frame code needs the boundary).
func (tg *Telegram) encLen(apl []byte) (int, error) {
	if tg.Sec == nil || tg.Sec.aplEnc > len(apl) {
		return 0, errors.New("no encrypted part")
	}
	return tg.Sec.aplEnc, nil
}

// More error kinds (EN 13757-7:2025 clause 9.5: a message failing the
// counter check, the authentication check or the decryption verification
// is discarded; the caller may report it to monitoring).
var (
	// ErrReplay: the message counter is not above the last verified one.
	ErrReplay = errors.New("the message counter is not newer than the last verified one (replay)")
	// ErrRepeat: the same message again (a repeat or a second receiver);
	// not an attack, but its counter is spent.
	ErrRepeat = errors.New("the same secured message was already accepted")
)

// counters keeps the verified meter counters C”M per meter and Key ID
// (clause 9.2.5) and our own partner counters CCP (clause 9.2.3).
type counters struct {
	mu   sync.Mutex
	cm   map[string]uint32 // "MAN-ID/keyID" → C''M
	last map[string][]byte // "MAN-ID/keyID" → TPDU of the last accepted message
	ccp  map[string]uint32 // "MAN-ID/keyID" → CCP
	// dirty is set when a counter changed since Counters was last read.
	dirty bool
}

func counterKey(m Header, keyID int) string { return fmt.Sprintf("%s/%d", m.Key(), keyID) }

// newer reports whether c is newer than last, allowing for a roll-over of
// the 32-bit counter (clause 9.2.5: the comparison should consider it). A
// counter far below a last value near the top is taken as rolled over.
func newer(c, last uint32) bool {
	if c > last {
		return true
	}
	return last >= 0xFFFF0000 && c < 0x00010000
}

// check applies the partner's reception rule: a counter at or below
// C”M is discarded. It does not store anything.
func (d *Decoder) checkCounter(m Header, keyID int, c uint32, tpdu []byte) error {
	if d == nil {
		return nil
	}
	d.ctr.mu.Lock()
	defer d.ctr.mu.Unlock()
	k := counterKey(m, keyID)
	last, ok := d.ctr.cm[k]
	if !ok || newer(c, last) {
		return nil
	}
	if c == last && bytes.Equal(d.ctr.last[k], tpdu) {
		return ErrRepeat
	}
	return ErrReplay
}

// verified stores C”M after a message passed its checks and raises CCP
// to it (clause 9.2.5).
func (d *Decoder) verified(m Header, keyID int, c uint32, tpdu []byte) {
	if d == nil {
		return
	}
	d.ctr.mu.Lock()
	defer d.ctr.mu.Unlock()
	if d.ctr.cm == nil {
		d.ctr.cm, d.ctr.last, d.ctr.ccp = map[string]uint32{}, map[string][]byte{}, map[string]uint32{}
	}
	k := counterKey(m, keyID)
	d.ctr.cm[k] = c
	d.ctr.last[k] = append([]byte(nil), tpdu...)
	if cp, ok := d.ctr.ccp[k]; !ok || newer(c, cp) {
		d.ctr.ccp[k] = c
	}
	d.ctr.dirty = true
}

// NextPartnerCounter returns the counter CCP for our next secured message
// to a meter (clause 9.2.3): the last one plus step (1–100), after it was
// raised to the meter's verified counter.
func (d *Decoder) NextPartnerCounter(m Header, keyID int, step uint32) uint32 {
	if step < 1 || step > 100 {
		step = 1
	}
	d.ctr.mu.Lock()
	defer d.ctr.mu.Unlock()
	if d.ctr.ccp == nil {
		d.ctr.cm, d.ctr.last, d.ctr.ccp = map[string]uint32{}, map[string][]byte{}, map[string]uint32{}
	}
	k := counterKey(m, keyID)
	c := d.ctr.ccp[k] + step
	d.ctr.ccp[k] = c
	d.ctr.dirty = true
	return c
}

// NextSITPCounter returns the next key counter of an SITP end-to-end key
// (annex A.9.1: kept by the command initiator, starting at 0, each
// command above the last).
func (d *Decoder) NextSITPCounter(m Header, keyID int) uint32 {
	d.ctr.mu.Lock()
	defer d.ctr.mu.Unlock()
	if d.ctr.ccp == nil {
		d.ctr.cm, d.ctr.last, d.ctr.ccp = map[string]uint32{}, map[string][]byte{}, map[string]uint32{}
	}
	k := fmt.Sprintf("%s/sitp%d", m.Key(), keyID)
	c := d.ctr.ccp[k] + 1
	d.ctr.ccp[k] = c
	d.ctr.dirty = true
	return c
}

// CounterState is the counters to keep across restarts (C”M must be
// stored permanently, clause 9.2.5).
type CounterState struct {
	Meter   map[string]uint32 `json:"meter"`   // C''M by "MAN-ID/keyID"
	Partner map[string]uint32 `json:"partner"` // CCP by "MAN-ID/keyID"
}

// Counters returns the counters and whether they changed since the last
// call.
func (d *Decoder) Counters() (CounterState, bool) {
	d.ctr.mu.Lock()
	defer d.ctr.mu.Unlock()
	s := CounterState{Meter: map[string]uint32{}, Partner: map[string]uint32{}}
	for k, v := range d.ctr.cm {
		s.Meter[k] = v
	}
	for k, v := range d.ctr.ccp {
		s.Partner[k] = v
	}
	ch := d.ctr.dirty
	d.ctr.dirty = false
	return s, ch
}

// ResetCounters sets a meter's counters for a Key ID back to 0 (after a
// master key update with message counter reset, OMS annex F table F.25).
func (d *Decoder) ResetCounters(m Header, keyID int) {
	d.ctr.mu.Lock()
	defer d.ctr.mu.Unlock()
	k := counterKey(m, keyID)
	delete(d.ctr.cm, k)
	delete(d.ctr.last, k)
	delete(d.ctr.ccp, k)
	d.ctr.dirty = true
}

// MarkCountersChanged marks the counters changed, so the next Counters
// call reports them to be saved again (after a failed save, say).
func (d *Decoder) MarkCountersChanged() {
	d.ctr.mu.Lock()
	d.ctr.dirty = true
	d.ctr.mu.Unlock()
}

// SetCounters restores saved counters (the higher of saved and current).
func (d *Decoder) SetCounters(s CounterState) {
	d.ctr.mu.Lock()
	defer d.ctr.mu.Unlock()
	if d.ctr.cm == nil {
		d.ctr.cm, d.ctr.last, d.ctr.ccp = map[string]uint32{}, map[string][]byte{}, map[string]uint32{}
	}
	for k, v := range s.Meter {
		if cur, ok := d.ctr.cm[k]; !ok || newer(v, cur) {
			d.ctr.cm[k] = v
		}
	}
	for k, v := range s.Partner {
		if cur, ok := d.ctr.ccp[k]; !ok || newer(v, cur) {
			d.ctr.ccp[k] = v
		}
	}
}

// key returns the persistent key for a Key ID and version: the Decoder's
// KeyByID when it knows one, else the meter's default key.
func (d *Decoder) key(keys KeyLookup, m Header, keyID, version int) []byte {
	if d != nil && d.KeyByID != nil {
		if k := d.KeyByID(m, keyID, version); k != nil {
			return k
		}
	}
	return keys.lookup(m)
}

// SessionKeys are the encryption and MAC keys of a message: with KDF-A
// (kdf 1) derived from the persistent key, the counter c and the meter,
// for a message to the meter when toMeter; with kdf 0 the persistent key.
func SessionKeys(master []byte, kdf int, c uint32, m Header, toMeter bool) (enc, mac []byte, err error) {
	switch kdf {
	case 0:
		return master, master, nil
	case 1:
		var id [4]byte
		copy(id[:], m.A[:4])
		de, dm := DCEncMeter, DCMACMeter
		if toMeter {
			de, dm = DCEncOther, DCMACOther
		}
		if enc, err = DeriveKey(master, de, c, id); err != nil {
			return nil, nil, err
		}
		mac, err = DeriveKey(master, dm, c, id)
		return enc, mac, err
	}
	return nil, nil, fmt.Errorf("%w: key derivation function %d (reserved)", ErrUnsupport, kdf)
}

// addr8 is the address block of the IVs and MACs: M, ID, version and
// device type, as in the link layer.
func addr8(m Header) []byte {
	b := binary.LittleEndian.AppendUint16(nil, m.MField)
	return append(b, m.A[:]...)
}

// tplHead is CI, access number, status and configuration field as
// transmitted (modes 9 and 10 authenticate them).
func (tg *Telegram) tplHead() []byte {
	return binary.LittleEndian.AppendUint16([]byte{tg.CI, tg.Access, tg.Status}, tg.Config)
}

// cfgBlocks is the encrypted length of modes 5 and 7 (16 × NNNN): all ones
// means the whole rest (clause 7.6.5), zero means nothing is encrypted.
func cfgBlocks(cfg uint16, rest int) int {
	n := int(cfg >> 4 & 0x0F)
	if n == 0x0F {
		return rest / 16 * 16
	}
	return n * 16
}

// secure parses the security mode's fields after the configuration field,
// checks counter and authentication, and decrypts. p is what follows the
// configuration field; tpdu is the TPL from its CI field to the end.
func (tg *Telegram) secure(d *Decoder, p, tpdu []byte, keys KeyLookup) ([]byte, error) {
	s := &Security{KeyVersion: -1}
	tg.Sec = s
	cfg := tg.Config
	take := func(k int) ([]byte, error) {
		if len(p) < k {
			return nil, errTruncated
		}
		v := p[:k]
		p = p[k:]
		return v, nil
	}
	aflKey := func() {
		if a := tg.AFL; a != nil && a.has.ki {
			s.KeyID, s.KDF = int(a.KI&0x0F), int(a.KI>>4&0x03)
			if v := int(a.KI >> 8); v != 0xFF {
				s.KeyVersion = v
			}
		}
	}
	aflCounter := func() {
		if !s.HasCounter && tg.AFL != nil && tg.AFL.has.mcr {
			s.Counter, s.HasCounter, s.CounterFrom = tg.AFL.Counter, true, "afl"
		}
	}
	switch tg.Mode {
	case 0:
		if tg.AFL != nil && tg.AFL.has.mac {
			aflKey()
			aflCounter()
			if err := tg.aflAuth(d, keys, s, tpdu); err != nil {
				return nil, err
			}
		}
		return p, nil
	case 5:
		s.Content = int(cfg >> 2 & 0x03)
		aflKey()
		aflCounter()
		n := cfgBlocks(cfg, len(p))
		s.EncryptedLen, s.UnencryptedLen = n, len(p)-n
		if n > len(p) {
			return nil, fmt.Errorf("the configuration field announces %d encrypted bytes but %d follow", n, len(p))
		}
		if tg.AFL != nil && tg.AFL.has.mac {
			if err := tg.aflAuth(d, keys, s, tpdu); err != nil {
				return nil, err
			}
		}
		if n == 0 {
			return p, nil
		}
		key := d.key(keys, tg.Meter, s.KeyID, s.KeyVersion)
		if key == nil {
			return nil, ErrNoKey
		}
		dec, err := cbcDecrypt(key, tg.Mode5IV(), p[:n])
		if err != nil {
			return nil, err
		}
		if !bytes.HasPrefix(dec, []byte{0x2F, 0x2F}) {
			return nil, ErrDecrypt
		}
		s.Verified = append(s.Verified, "decrypt-2f2f")
		tg.Encrypted = true
		s.aplEnc = len(dec)
		return append(dec, p[n:]...), tg.accept(d, s, tpdu)
	case 7:
		s.Content, s.ContentIndex = int(cfg>>14), int(cfg&0x07)
		cfe, err := take(1)
		if err != nil {
			return nil, err
		}
		tg.ConfigExt = cfe[0]
		s.KeyID, s.KDF = int(cfe[0]&0x0F), int(cfe[0]>>4&0x03)
		if cfe[0]&0x40 != 0 {
			v, err := take(1)
			if err != nil {
				return nil, err
			}
			s.KeyVersion = int(v[0])
		}
		if cfg&0x2000 != 0 {
			v, err := take(4)
			if err != nil {
				return nil, err
			}
			s.Counter, s.HasCounter, s.CounterFrom = binary.LittleEndian.Uint32(v), true, "tpl"
		}
		aflCounter()
		if s.KDF == 1 && !s.HasCounter {
			return nil, errors.New("mode 7 with KDF-A needs a message counter (TPL Z bit or AFL.MCR)")
		}
		n := cfgBlocks(cfg, len(p))
		if n > len(p) {
			return nil, fmt.Errorf("the configuration field announces %d encrypted bytes but %d follow", n, len(p))
		}
		s.EncryptedLen, s.UnencryptedLen = n, len(p)-n
		if err := tg.aflAuth(d, keys, s, tpdu); err != nil {
			return nil, err
		}
		if n == 0 {
			return p, tg.accept(d, s, tpdu)
		}
		master := d.key(keys, tg.Meter, s.KeyID, s.KeyVersion)
		if master == nil {
			return nil, ErrNoKey
		}
		kenc, _, err := SessionKeys(master, s.KDF, s.Counter, tg.Meter, d.meterSide())
		if err != nil {
			return nil, err
		}
		dec, err := cbcDecrypt(kenc, make([]byte, 16), p[:n])
		if err != nil {
			return nil, err
		}
		if !bytes.HasPrefix(dec, []byte{0x2F, 0x2F}) {
			return nil, ErrDecrypt
		}
		s.Verified = append(s.Verified, "decrypt-2f2f")
		// Clause 9.4.5.2 has the verification bytes removed; they are kept
		// here as the two idle fillers they are in the M-Bus APL, like mode
		// 5's, so records and compact frames see the same layout.
		if cfg&0x08 != 0 {
			k := int(dec[len(dec)-1])
			if k < 1 || k > 16 || k > len(dec) || !bytes.Equal(dec[len(dec)-k:], bytes.Repeat([]byte{byte(k)}, k)) {
				return nil, fmt.Errorf("%w: bad TPL padding", ErrDecrypt)
			}
			dec = dec[:len(dec)-k]
		}
		tg.Encrypted = true
		s.aplEnc = len(dec)
		return append(dec, p[n:]...), tg.accept(d, s, tpdu)
	case 8:
		return tg.mode8(d, s, p, tpdu, keys)
	case 9:
		return tg.mode9(d, s, p, tpdu, keys)
	case 10:
		return tg.mode10(d, s, p, tpdu, keys)
	case 2, 3:
		return tg.modeDES(d, s, p, tpdu)
	case 13:
		return tg.mode13(d, s, p, tpdu, keys) // mode13.go
	}
	return nil, modeRefusal(tg.Mode)
}

// ErrSecurityMode is returned for a security mode EN 13757-7:2025 does
// not define for this protocol (7.5.8 table 19).
var ErrSecurityMode = errors.New("security mode not defined by EN 13757-7:2025")

// modeRefusal explains why a security mode is not decoded (7.5.8 table
// 19): mode 1 is manufacturer specific (9.4.2); modes 4 and 15 are
// "specific usage" defined outside EN 13757-7 (DSMR 2.2 P2 and DSMR 4.2.2
// P2, bibliography entries 6 and 7; mode 13, OMS Volume 2 annex F TLS, is
// built in mode13.go); modes 6,
// 11, 12, 14 and 16 to 31 are reserved.
func modeRefusal(m int) error {
	switch m {
	case 1:
		return fmt.Errorf("%w: mode 1 is manufacturer specific (clause 9.4.2)", ErrSecurityMode)
	case 4:
		return fmt.Errorf("%w: mode 4 is a specific usage defined by DSMR 2.2 P2, not by EN 13757-7 (table 19)", ErrSecurityMode)
	case 15:
		return fmt.Errorf("%w: mode 15 is a specific usage defined by DSMR 4.2.2 P2, not by EN 13757-7 (table 19)", ErrSecurityMode)
	}
	return fmt.Errorf("%w: mode %d is reserved for future use (table 19)", ErrSecurityMode, m)
}

// meterSide reports whether this Decoder reads messages sent to a meter
// (a meter simulator, or tests of our own downlinks): KDF-A then derives
// Lenc and Lmac.
func (d *Decoder) meterSide() bool { return d != nil && d.MeterSide }

// modeDES decodes the deprecated DES-CBC modes 2 (IV 0) and 3 (IV from the
// meter ID, manufacturer and the current date in type G), clauses 7.7.3 and
// 9.4.3. The encrypted part must contain the header's identification number
// (9.4.3.2). DES is withdrawn; these modes are read only with a configured
// DES key, and the telegram is marked deprecated.
func (tg *Telegram) modeDES(d *Decoder, s *Security, p, _ []byte) ([]byte, error) {
	n := int(tg.Config & 0xFF)
	if n > len(p) || n%8 != 0 {
		return nil, fmt.Errorf("the configuration field announces %d DES-encrypted bytes (a multiple of 8) but %d follow", n, len(p))
	}
	s.EncryptedLen, s.UnencryptedLen = n, len(p)-n
	s.Unverified = append(s.Unverified, "deprecated-des")
	if n == 0 {
		return p, nil
	}
	var key []byte
	if d != nil && d.DESKey != nil {
		key = d.DESKey(tg.Meter)
	}
	if key == nil {
		return nil, fmt.Errorf("%w (mode %d needs a DES key, desKey)", ErrNoKey, tg.Mode)
	}
	id := tg.Meter.A[:4]
	try := func(iv []byte) ([]byte, bool) {
		dec, err := desCBCDecrypt(key, iv, p[:n])
		return dec, err == nil && bytes.Contains(dec, id)
	}
	if tg.Mode == 2 {
		dec, ok := try(make([]byte, 8))
		switch {
		case ok:
			s.Verified = append(s.Verified, "decrypt-id")
		case d != nil && d.DESCheck2F2F && bytes.HasPrefix(dec, []byte{0x2F, 0x2F}):
			s.Verified = append(s.Verified, "decrypt-2f2f")
			s.Unverified = append(s.Unverified, "des-id")
		default:
			return nil, ErrDecrypt
		}
		tg.Encrypted = true
		s.aplEnc = n
		return append(dec, p[n:]...), nil
	}
	// Mode 3: the meter's date is not sent; today's and yesterday's dates
	// (the telegram may cross midnight, or the clocks differ) are tried.
	// The date only changes bytes 6 and 7 of the first block: the ID
	// check (9.4.3.2) confirms the date only when the ID covers one of
	// them (finding F-169). Today's date is tried first.
	t := now(d)
	for _, day := range []time.Time{t, t.AddDate(0, 0, -1), t.AddDate(0, 0, 1)} {
		iv := mode3IV(tg.Meter, day)
		dec, err := desCBCDecrypt(key, iv, p[:n])
		if err != nil {
			return nil, err
		}
		at := idAt(dec, id)
		if at < 0 {
			continue
		}
		s.Verified = append(s.Verified, "decrypt-id")
		if at > 7 || at+4 <= 6 {
			s.Unverified = append(s.Unverified, "des-date")
		}
		tg.Encrypted = true
		s.aplEnc = n
		return append(dec, p[n:]...), nil
	}
	return nil, ErrDecrypt
}

// idAt is where the ID occurs in the first block (bytes 0–7 are the only
// ones the IV touches), or anywhere after it, or -1.
func idAt(b, id []byte) int {
	for i := 0; i+len(id) <= len(b); i++ {
		if bytes.Equal(b[i:i+len(id)], id) {
			return i
		}
	}
	return -1
}

// mode3IV: identification number, manufacturer, date (type G), each least
// significant byte first.
func mode3IV(m Header, day time.Time) []byte {
	iv := append([]byte(nil), m.A[:4]...)
	iv = binary.LittleEndian.AppendUint16(iv, m.MField)
	return binary.LittleEndian.AppendUint16(iv, typeG(day))
}

// typeG codes a date as EN 13757-3 type G: day in bits 0–4, month in 8–11,
// year (0–99, since 2000) with its low three bits in 5–7 and high four in
// 12–15.
func typeG(t time.Time) uint16 {
	y := uint16(t.Year() % 100)
	return uint16(t.Day()) | (y&0x07)<<5 | uint16(t.Month())<<8 | (y>>3)<<12
}

// accept runs the counter rules once a message passed its checks.
func (tg *Telegram) accept(d *Decoder, s *Security, tpdu []byte) error {
	if !s.HasCounter {
		return nil
	}
	if len(s.Verified) == 0 {
		return nil // nothing authenticated: the counter is not verified
	}
	d.verified(tg.Meter, s.KeyID, s.Counter, tpdu)
	return nil
}

// counterGate applies the reception rule before any key is used.
func (tg *Telegram) counterGate(d *Decoder, s *Security, tpdu []byte) error {
	if !s.HasCounter {
		return nil
	}
	return d.checkCounter(tg.Meter, s.KeyID, s.Counter, tpdu)
}

// aflAuth verifies the AFL's MAC (clause 9.3) with Kmac.
func (tg *Telegram) aflAuth(d *Decoder, keys KeyLookup, s *Security, tpdu []byte) error {
	a := tg.AFL
	if a == nil || (!a.has.mac && len(a.fragMACs) == 0) {
		return tg.counterGate(d, s, tpdu)
	}
	if err := tg.counterGate(d, s, tpdu); err != nil {
		return err
	}
	master := d.key(keys, tg.Meter, s.KeyID, s.KeyVersion)
	if master == nil {
		return ErrNoKey
	}
	if s.KDF == 1 && !s.HasCounter {
		return errors.New("the AFL MAC needs a message counter for KDF-A")
	}
	_, kmac, err := SessionKeys(master, s.KDF, s.Counter, tg.Meter, d.meterSide())
	if err != nil {
		return err
	}
	at := a.MCL & 0x0F
	check := func(fid byte, msg, mac []byte) error {
		in := append(a.macInput(), msg...)
		var got []byte
		switch {
		case at >= 3 && at <= 7:
			full, err := CMAC(kmac, in)
			if err != nil {
				return err
			}
			got = full[:macLen(at)]
		case at == 8:
			_, tag, err := gcmSeal(kmac, gmacIV(tg.Meter, s.Counter, fid), in, nil, 12)
			if err != nil {
				return err
			}
			got = tag
		default:
			return fmt.Errorf("%w: AFL authentication type %d", ErrUnsupport, at)
		}
		if len(mac) != len(got) || subtle.ConstantTimeCompare(got, mac) != 1 {
			return ErrMAC
		}
		return nil
	}
	if len(a.fragMACs) > 0 {
		// Individual fragment authentication: each fragment's MAC covers
		// the message fields and that fragment's part of the TPDU.
		for _, f := range a.fragMACs {
			if err := check(f.fid, f.data, f.mac); err != nil {
				return err
			}
		}
	} else if err := check(byte(a.FCL), tpdu, a.MAC); err != nil {
		return err
	}
	if at == 8 {
		s.Verified = append(s.Verified, "afl-gmac")
	} else {
		s.Verified = append(s.Verified, "afl-cmac")
	}
	return nil
}

// gmacIV is the 13-byte IV of AFL AES-GMAC (clause 9.3.3): address, then
// the message counter (most significant byte first, see findings) and the
// fragment ID.
func gmacIV(m Header, c uint32, fid byte) []byte {
	iv := addr8(m)
	iv = binary.BigEndian.AppendUint32(iv, c)
	return append(iv, fid)
}

// mode8 is AES-CTR with MAC_1 and MAC_2 (clauses 7.7.6, 9.4.6).
func (tg *Telegram) mode8(d *Decoder, s *Security, p, tpdu []byte, keys KeyLookup) ([]byte, error) {
	cfg := tg.Config
	all := p
	s.KeyID, s.KDF = int(cfg&0x0F), int(cfg>>13&0x03)
	i := 0
	var cfe byte
	if cfg&0x8000 != 0 {
		if len(p) < 1 {
			return nil, errTruncated
		}
		cfe = p[0]
		s.ContentIndex, s.Content = int(cfe>>4), int(cfe&0x03)
		i++
		if cfe&0x04 != 0 {
			if len(p) < i+1 {
				return nil, errTruncated
			}
			s.KeyVersion = int(p[i])
			i++
		}
	}
	lenE := -1
	if cfg&0x80 != 0 {
		if len(p) < i+1 {
			return nil, errTruncated
		}
		lenE = int(p[i])
		i++
	}
	zz := int(cfg >> 4 & 0x03)
	if zz == 0 {
		return nil, fmt.Errorf("%w: mode 8 counter size 00 (reserved)", ErrUnsupport)
	}
	csize := zz + 1
	if len(p) < i+csize {
		return nil, errTruncated
	}
	ctrBytes := p[i : i+csize]
	var c4 [4]byte
	copy(c4[:], ctrBytes)
	s.Counter, s.HasCounter, s.CounterFrom = binary.LittleEndian.Uint32(c4[:]), true, "tpl"
	i += csize
	trailer := 4
	if cfg&0x40 != 0 {
		trailer += 5
	}
	if len(p) < i+trailer {
		return nil, errTruncated
	}
	body := p[i : len(p)-trailer]
	tr := p[len(p)-trailer:]
	enc, unenc := body, []byte(nil)
	if lenE >= 0 {
		if lenE > len(body) {
			return nil, fmt.Errorf("Length(E) %d is longer than the %d bytes of data", lenE, len(body))
		}
		enc, unenc = body[:lenE], body[lenE:]
	}
	s.EncryptedLen, s.UnencryptedLen = len(enc), len(unenc)
	mac1 := tr[:4]
	if err := tg.counterGate(d, s, tpdu); err != nil {
		return nil, err
	}
	master := d.key(keys, tg.Meter, s.KeyID, s.KeyVersion)
	if master == nil {
		return nil, ErrNoKey
	}
	kenc, kmac1, err := SessionKeys(master, s.KDF, s.Counter, tg.Meter, d.meterSide())
	if err != nil {
		return nil, err
	}
	want, err := mode8MAC1(kmac1, tg.Meter, s.Counter, enc, unenc)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(want, mac1) != 1 {
		return nil, ErrMAC
	}
	s.Verified = append(s.Verified, "mac1")
	if cfg&0x40 != 0 {
		ts := uint32(tr[4]) | uint32(tr[5])<<8 | uint32(tr[6])<<16
		s.Timestamp = &ts
		var k2 []byte
		if d != nil && d.MAC2Key != nil {
			k2 = d.MAC2Key(tg.Meter)
		}
		if k2 == nil {
			s.Unverified = append(s.Unverified, "mac2")
		} else {
			// Everything after the configuration field up to MAC_1 and the
			// time stamp, as transmitted.
			in := append(addr8(tg.Meter), make([]byte, 8)...)
			in = append(in, tg.Access, tg.Status)
			in = binary.LittleEndian.AppendUint16(in, tg.Config)
			in = append(in, all[:len(all)-5]...)
			in = append(in, tr[4:7]...)
			full, err := CMAC(k2, in)
			if err != nil {
				return nil, err
			}
			if subtle.ConstantTimeCompare(full[:2], tr[7:9]) != 1 {
				return nil, ErrMAC
			}
			s.Verified = append(s.Verified, "mac2")
		}
	}
	plain, err := ctrXOR(kenc, mode8IV(tg.Meter, s.Counter), enc)
	if err != nil {
		return nil, err
	}
	tg.Encrypted = len(enc) > 0
	s.aplEnc = len(plain)
	return append(plain, unenc...), tg.accept(d, s, tpdu)
}

// mode8IV: address, counter (MSB first), two zero bytes and the block
// counter from 0 (Table 50).
func mode8IV(m Header, c uint32) []byte {
	iv := binary.BigEndian.AppendUint32(addr8(m), c)
	return append(iv, 0, 0, 0, 0)
}

// mode8MAC1: CMAC over address, counter (4 bytes as transmitted), four
// zero bytes, encrypted and unencrypted data; 4 bytes, MSB first.
func mode8MAC1(k []byte, m Header, c uint32, enc, unenc []byte) ([]byte, error) {
	in := binary.LittleEndian.AppendUint32(addr8(m), c)
	in = append(in, 0, 0, 0, 0)
	in = append(append(in, enc...), unenc...)
	full, err := CMAC(k, in)
	if err != nil {
		return nil, err
	}
	return full[:4], nil
}

// mode9 is AES-GCM (clauses 7.7.7, 9.4.7).
func (tg *Telegram) mode9(d *Decoder, s *Security, p, tpdu []byte, keys KeyLookup) ([]byte, error) {
	cfg := tg.Config
	s.KeyID, s.KDF = int(cfg&0x0F), int(cfg>>4&0x03)
	i := 0
	var aad []byte
	aad = append(aad, tg.tplHead()...)
	if cfg&0x4000 != 0 {
		if len(p) < 1 {
			return nil, errTruncated
		}
		s.KeyVersion = int(p[0])
		aad = append(aad, p[0])
		i++
	}
	readLen := func(two bool) (int, error) {
		if two {
			if len(p) < i+2 {
				return 0, errTruncated
			}
			aad = append(aad, p[i:i+2]...)
			v := int(binary.LittleEndian.Uint16(p[i:]))
			i += 2
			return v, nil
		}
		if len(p) < i+1 {
			return 0, errTruncated
		}
		aad = append(aad, p[i])
		v := int(p[i])
		i++
		return v, nil
	}
	lenE, err := readLen(cfg&0x40 != 0)
	if err != nil {
		return nil, err
	}
	lenU, err := readLen(cfg&0x80 != 0)
	if err != nil {
		return nil, err
	}
	if len(p) < i+4 {
		return nil, errTruncated
	}
	s.Counter, s.HasCounter, s.CounterFrom = binary.LittleEndian.Uint32(p[i:]), true, "tpl"
	i += 4
	tagLen := 0
	if cfg&0x2000 != 0 {
		tagLen = 12
	}
	if len(p) != i+lenE+lenU+tagLen {
		return nil, fmt.Errorf("mode 9: Length(E) %d, Length(U) %d and tag %d do not fill the %d bytes that follow", lenE, lenU, tagLen, len(p)-i)
	}
	enc, unenc, tag := p[i:i+lenE], p[i+lenE:i+lenE+lenU], p[i+lenE+lenU:]
	s.EncryptedLen, s.UnencryptedLen = lenE, lenU
	aad = append(aad, unenc...)
	if err := tg.counterGate(d, s, tpdu); err != nil {
		return nil, err
	}
	master := d.key(keys, tg.Meter, s.KeyID, s.KeyVersion)
	if master == nil {
		return nil, ErrNoKey
	}
	k, _, err := SessionKeys(master, s.KDF, s.Counter, tg.Meter, d.meterSide())
	if err != nil {
		return nil, err
	}
	iv := binary.BigEndian.AppendUint32(addr8(tg.Meter), s.Counter)
	var plain []byte
	if tagLen == 0 {
		// No tag: confidentiality only; nothing authenticates the counter.
		ks, _, err := gcmSeal(k, iv, nil, make([]byte, len(enc)), 12)
		if err != nil {
			return nil, err
		}
		plain = make([]byte, len(enc))
		subtle.XORBytes(plain, enc, ks)
		s.Unverified = append(s.Unverified, "gcm-no-tag")
	} else {
		if plain, err = gcmOpen(k, iv, aad, enc, tag); err != nil {
			return nil, err
		}
		s.Verified = append(s.Verified, "gcm")
	}
	tg.Encrypted = lenE > 0
	s.aplEnc = len(plain)
	return append(plain, unenc...), tg.accept(d, s, tpdu)
}

// ccmTagLen maps mode 10's CFE tag size subfield (Table 43).
var ccmTagLen = [4]int{4, 8, 12, 16}

// mode10 is AES-CCM (clauses 7.7.8, 9.4.8).
func (tg *Telegram) mode10(d *Decoder, s *Security, p, tpdu []byte, keys KeyLookup) ([]byte, error) {
	cfg := tg.Config
	s.Content = int(cfg >> 14)
	if len(p) < 2 {
		return nil, errTruncated
	}
	cfeRaw := p[:2]
	cfe := binary.LittleEndian.Uint16(cfeRaw)
	s.KeyID, s.KDF, s.ContentIndex = int(cfe&0x0F), int(cfe>>4&0x03), int(cfe>>10&0x0F)
	tagLen := ccmTagLen[cfe>>8&0x03]
	s.TagLen = tagLen
	aad := append(tg.tplHead(), cfeRaw...)
	i := 2
	if cfe&0x40 != 0 {
		if len(p) < i+1 {
			return nil, errTruncated
		}
		s.KeyVersion = int(p[i])
		aad = append(aad, p[i])
		i++
	}
	if cfg&0x2000 != 0 {
		if len(p) < i+4 {
			return nil, errTruncated
		}
		s.Counter, s.HasCounter, s.CounterFrom = binary.LittleEndian.Uint32(p[i:]), true, "tpl"
		i += 4
	}
	if !s.HasCounter && tg.AFL != nil && tg.AFL.has.mcr {
		s.Counter, s.HasCounter, s.CounterFrom = tg.AFL.Counter, true, "afl"
	}
	if !s.HasCounter {
		return nil, errors.New("mode 10 needs a message counter (TPL Z bit or AFL.MCR)")
	}
	if len(p) < i+tagLen {
		return nil, errTruncated
	}
	data, tag := p[i:len(p)-tagLen], p[len(p)-tagLen:]
	n := int(cfg & 0xFF)
	if n == 0xFF {
		n = len(data)
	}
	if n > len(data) {
		return nil, fmt.Errorf("the configuration field announces %d encrypted bytes but %d follow", n, len(data))
	}
	enc, unenc := data[:n], data[n:]
	s.EncryptedLen, s.UnencryptedLen = len(enc), len(unenc)
	aad = append(aad, unenc...)
	if err := tg.counterGate(d, s, tpdu); err != nil {
		return nil, err
	}
	master := d.key(keys, tg.Meter, s.KeyID, s.KeyVersion)
	if master == nil {
		return nil, ErrNoKey
	}
	k, _, err := SessionKeys(master, s.KDF, s.Counter, tg.Meter, d.meterSide())
	if err != nil {
		return nil, err
	}
	plain, err := ccm(k, ccmNonce(tg.Meter, s.Counter), aad, append(append([]byte(nil), enc...), tag...), tagLen, true)
	if err != nil {
		return nil, err
	}
	s.Verified = append(s.Verified, "ccm")
	tg.Encrypted = n > 0
	s.aplEnc = len(plain)
	return append(plain, unenc...), tg.accept(d, s, tpdu)
}

// ccmNonce: address, 00h, counter MSB first (Table 53).
func ccmNonce(m Header, c uint32) []byte {
	return binary.BigEndian.AppendUint32(append(addr8(m), 0), c)
}

// ---- encoding (simulators, tests and our own frames to meters) ------------

// Seal says how to secure a TPL.
type Seal struct {
	Mode int
	// Key is the mode 5 key or the persistent (master) key of modes 7–10.
	Key []byte
	// MAC2Key is mode 8's Kmac_2; with Timestamp set MAC_2 is added.
	MAC2Key    []byte
	Timestamp  *uint32
	KDF        int // 0 persistent, 1 KDF-A
	KeyID      int
	KeyVersion int // -1 for none
	Counter    uint32
	// CounterInTPL sets the Z bit (modes 7 and 10); mode 8 and 9 always
	// carry it. Without it the counter goes in the AFL (see SealAFL).
	CounterInTPL bool
	CounterSize  int  // mode 8: 2, 3 or 4 (default 4)
	Padding      bool // mode 7 TPL padding
	TagLen       int  // mode 9: 0 or 12 (default 12); mode 10: 4/8/12/16 (default 8)
	// ToMeter derives Lenc/Lmac (the partner's direction) with KDF-A.
	ToMeter bool
	// Unencrypted follows the encrypted part.
	Unencrypted []byte
}

// SealTPL builds a TPL from its CI field: header, configuration field and
// secured application data. meter is the address used for the IV (the
// long header's address when long is true, else the link layer's), acc
// and st the access number and status; hi holds the configuration field
// bits a mode leaves to the caller (B, A, S, CC...).
func SealTPL(ci byte, long bool, meter Header, acc, st byte, hi uint16, s Seal, apl []byte) ([]byte, error) {
	b := []byte{ci}
	if long {
		b = append(b, meter.A[:4]...)
		b = binary.LittleEndian.AppendUint16(b, meter.MField)
		b = append(b, meter.Version, meter.DeviceType)
	}
	b = append(b, acc, st)
	cfgAt := len(b)
	b = append(b, 0, 0)
	var cfg uint16
	switch s.Mode {
	case 0:
		cfg = hi
		b = append(append(b, apl...), s.Unencrypted...)
	case 5:
		p := append([]byte{0x2F, 0x2F}, apl...)
		for len(p)%16 != 0 {
			p = append(p, 0x2F)
		}
		tg := Telegram{Meter: meter, Access: acc}
		enc, err := cbcEncrypt(s.Key, tg.Mode5IV(), p)
		if err != nil {
			return nil, err
		}
		nb, err := cbcBlocksField(len(p)/16, len(s.Unencrypted)) // omsci.go
		if err != nil {
			return nil, err
		}
		cfg = hi&^0x1FF0 | 5<<8 | nb
		b = append(append(b, enc...), s.Unencrypted...)
	case 7:
		p := append([]byte{0x2F, 0x2F}, apl...)
		if s.Padding {
			k := 16 - len(p)%16
			p = append(p, bytes.Repeat([]byte{byte(k)}, k)...)
		} else {
			for len(p)%16 != 0 {
				p = append(p, 0x2F)
			}
		}
		kenc, _, err := SessionKeys(s.Key, s.KDF, s.Counter, meter, s.ToMeter)
		if err != nil {
			return nil, err
		}
		enc, err := cbcEncrypt(kenc, make([]byte, 16), p)
		if err != nil {
			return nil, err
		}
		nb, err := cbcBlocksField(len(p)/16, len(s.Unencrypted)) // omsci.go
		if err != nil {
			return nil, err
		}
		cfg = hi&0xC000 | 7<<8 | nb
		if s.Padding {
			cfg |= 0x08
		}
		cfe := byte(s.KDF&3)<<4 | byte(s.KeyID&0x0F)
		if s.KeyVersion >= 0 {
			cfe |= 0x40
		}
		b = append(b, cfe)
		if s.KeyVersion >= 0 {
			b = append(b, byte(s.KeyVersion))
		}
		if s.CounterInTPL {
			cfg |= 0x2000
			b = binary.LittleEndian.AppendUint32(b, s.Counter)
		}
		b = append(append(b, enc...), s.Unencrypted...)
	case 8:
		cs := s.CounterSize
		if cs == 0 {
			cs = 4
		}
		cfg = 0x8000 | uint16(s.KDF&3)<<13 | 8<<8 | uint16(cs-1)<<4 | uint16(s.KeyID&0x0F)
		cfe := byte(0)
		if s.KeyVersion >= 0 {
			cfe |= 0x04
		}
		b = append(b, cfe)
		if s.KeyVersion >= 0 {
			b = append(b, byte(s.KeyVersion))
		}
		if len(s.Unencrypted) > 0 {
			if len(apl) > 254 {
				return nil, errors.New("mode 8: unencrypted data needs Length(E) ≤ 254")
			}
			cfg |= 0x80
			b = append(b, byte(len(apl)))
		}
		b = append(b, binary.LittleEndian.AppendUint32(nil, s.Counter)[:cs]...)
		kenc, kmac1, err := SessionKeys(s.Key, s.KDF, s.Counter, meter, s.ToMeter)
		if err != nil {
			return nil, err
		}
		enc, err := ctrXOR(kenc, mode8IV(meter, s.Counter), apl)
		if err != nil {
			return nil, err
		}
		b = append(append(b, enc...), s.Unencrypted...)
		mac1, err := mode8MAC1(kmac1, meter, s.Counter, enc, s.Unencrypted)
		if err != nil {
			return nil, err
		}
		b = append(b, mac1...)
		if s.Timestamp != nil {
			cfg |= 0x40
			ts := *s.Timestamp
			b = append(b, byte(ts), byte(ts>>8), byte(ts>>16))
			binary.LittleEndian.PutUint16(b[cfgAt:], cfg)
			in := append(addr8(meter), make([]byte, 8)...)
			in = append(in, acc, st)
			in = append(in, b[cfgAt:]...)
			full, err := CMAC(s.MAC2Key, in)
			if err != nil {
				return nil, err
			}
			b = append(b, full[:2]...)
		}
	case 9:
		tagLen := s.TagLen
		if tagLen == 0 {
			tagLen = 12
		} else if tagLen < 0 {
			tagLen = 0
		}
		cfg = 9<<8 | uint16(s.KDF&3)<<4 | uint16(s.KeyID&0x0F)
		if tagLen == 12 {
			cfg |= 0x2000
		}
		var opt []byte
		if s.KeyVersion >= 0 {
			cfg |= 0x4000
			opt = append(opt, byte(s.KeyVersion))
		}
		if len(apl) > 255 {
			cfg |= 0x40
			opt = binary.LittleEndian.AppendUint16(opt, uint16(len(apl)))
		} else {
			opt = append(opt, byte(len(apl)))
		}
		if len(s.Unencrypted) > 255 {
			cfg |= 0x80
			opt = binary.LittleEndian.AppendUint16(opt, uint16(len(s.Unencrypted)))
		} else {
			opt = append(opt, byte(len(s.Unencrypted)))
		}
		k, _, err := SessionKeys(s.Key, s.KDF, s.Counter, meter, s.ToMeter)
		if err != nil {
			return nil, err
		}
		aad := binary.LittleEndian.AppendUint16([]byte{ci, acc, st}, cfg)
		aad = append(append(aad, opt...), s.Unencrypted...)
		ct, tag, err := gcmSeal(k, binary.BigEndian.AppendUint32(addr8(meter), s.Counter), aad, apl, 12)
		if err != nil {
			return nil, err
		}
		b = append(b, opt...)
		b = binary.LittleEndian.AppendUint32(b, s.Counter)
		b = append(append(b, ct...), s.Unencrypted...)
		if tagLen == 12 {
			b = append(b, tag...)
		}
	case 10:
		tagLen := s.TagLen
		if tagLen == 0 {
			tagLen = 8
		}
		ts := map[int]uint16{4: 0, 8: 1, 12: 2, 16: 3}[tagLen]
		if len(apl) > 254 {
			return nil, errors.New("mode 10: at most 254 encrypted bytes can be announced (FFh means all)")
		}
		// The exact count, also when all is encrypted, as OMS Volume 2
		// annex N.2.6 and N.5 do (the decoder also takes FFh for all).
		cfg = hi&0xC000 | 10<<8 | uint16(len(apl))
		cfe := ts<<8 | uint16(s.KDF&3)<<4 | uint16(s.KeyID&0x0F)
		if s.KeyVersion >= 0 {
			cfe |= 0x40
		}
		if s.CounterInTPL {
			cfg |= 0x2000
		}
		opt := binary.LittleEndian.AppendUint16(nil, cfe)
		if s.KeyVersion >= 0 {
			opt = append(opt, byte(s.KeyVersion))
		}
		aad := binary.LittleEndian.AppendUint16([]byte{ci, acc, st}, cfg)
		aad = append(append(aad, opt...), s.Unencrypted...)
		k, _, err := SessionKeys(s.Key, s.KDF, s.Counter, meter, s.ToMeter)
		if err != nil {
			return nil, err
		}
		out, err := ccm(k, ccmNonce(meter, s.Counter), aad, apl, tagLen, false)
		if err != nil {
			return nil, err
		}
		b = append(b, opt...)
		if s.CounterInTPL {
			b = binary.LittleEndian.AppendUint32(b, s.Counter)
		}
		b = append(append(append(b, out[:len(apl)]...), s.Unencrypted...), out[len(apl):]...)
	default:
		return nil, fmt.Errorf("%w: sealing security mode %d", ErrUnsupport, s.Mode)
	}
	binary.LittleEndian.PutUint16(b[cfgAt:], cfg)
	return b, nil
}

// SealAFL puts an AFL (CI 90h) in front of a TPDU, unfragmented, with the
// message counter and a MAC: at 3–7 AES-CMAC of 2–16 bytes, 8 AES-GMAC.
// ki, when not nil, is the key information field. meter is the address of
// the GMAC IV.
func SealAFL(tpdu []byte, meter Header, key []byte, kdf int, counter uint32, at byte, ki *uint16, toMeter bool) ([]byte, error) {
	a := &AFL{MCL: at | 0x20, Counter: counter}
	a.has.mcl, a.has.mcr = true, true
	fcl := uint16(AFLMCLP | AFLMCRP | AFLMACP)
	if ki != nil {
		a.KI, a.has.ki = *ki, true
		a.MCL |= 0x10
		fcl |= AFLKIP
	}
	_, kmac, err := SessionKeys(key, kdf, counter, meter, toMeter)
	if err != nil {
		return nil, err
	}
	in := append(a.macInput(), tpdu...)
	var mac []byte
	switch {
	case at >= 3 && at <= 7:
		full, err := CMAC(kmac, in)
		if err != nil {
			return nil, err
		}
		mac = full[:macLen(at)]
	case at == 8:
		if _, mac, err = gcmSeal(kmac, gmacIV(meter, counter, 0), in, nil, 12); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: AFL authentication type %d", ErrUnsupport, at)
	}
	f := binary.LittleEndian.AppendUint16(nil, fcl)
	f = append(f, a.MCL)
	if ki != nil {
		f = binary.LittleEndian.AppendUint16(f, *ki)
	}
	f = binary.LittleEndian.AppendUint32(f, counter)
	f = append(f, mac...)
	out := append([]byte{CIAFL, byte(len(f))}, f...)
	return append(out, tpdu...), nil
}
