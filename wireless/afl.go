package wireless

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Fragmented messages (EN 13757-7:2025 clause 6): a message longer than a
// datagram is sent in fragments, each with an AFL whose FCL carries the
// fragment ID (bits 0–7: 1 for the first fragment, counting up, never
// rolling over; 0 for an unfragmented message) and the more-fragments bit
// (MF). The TPL is only in the first fragment; MCL, KI, MCR and ML come
// with the first fragment only. The MAC is either in the last fragment
// (message authentication: it covers MCL, KI, MCR, ML and the whole
// reassembled TPDU) or in every fragment (individual fragment
// authentication: each covers the message fields and that fragment).

// ErrFragment is returned for a fragment that was kept until the rest of
// its message arrives.
var ErrFragment = errors.New("fragment of a longer message: waiting for the rest")

// FragmentTimeout is how long a partial message is kept.
const FragmentTimeout = 2 * time.Minute

const maxPartial = 256 // partial messages kept at once

// maxMessage is the longest reassembled message (AFL.ML is 16 bits:
// 64 kbytes, clause 6.3.7).
const maxMessage = 64 * 1024

// OMSMaxMessage is the OMS limit of a fragmented message (OMS Volume 2
// 6.2.5: 16 kbytes), applied with the omsProfile setting.
const OMSMaxMessage = 16 * 1024

func (d *Decoder) maxMessage() int {
	if d != nil && d.MaxMessage > 0 {
		return d.MaxMessage
	}
	return maxMessage
}

// Decoder decodes telegrams, reassembles fragmented messages and keeps
// the message counters (security.go). The zero value is ready; it is safe
// for concurrent use.
type Decoder struct {
	mu      sync.Mutex
	partial map[string]*partialMsg // by link-layer address
	ctr     counters
	// Now returns the time (tests); nil means time.Now.
	Now func() time.Time
	// KeyByID returns the persistent key of a meter for a Key ID and key
	// version (-1: none given), or nil to use the KeyLookup's key.
	KeyByID func(meter Header, keyID, version int) []byte
	// MAC2Key returns security mode 8's Kmac_2 of a meter, or nil (MAC_2
	// is then reported as not verified).
	MAC2Key func(meter Header) []byte
	// DESKey returns the 8-byte DES key of the deprecated modes 2 and 3.
	DESKey func(meter Header) []byte
	// DESCheck2F2F also accepts a mode 2 telegram whose decrypted data
	// begins with two idle fillers (2F2Fh) when the meter's ID is not in
	// it, as wmbusmeters does. Off by default: the ID is the check
	// EN 13757-7 gives, and two fixed bytes are a weaker one. A telegram
	// accepted this way is marked "des-id" in Security.Unverified.
	DESCheck2F2F bool
	// TLS processes security mode 13 records for the meter's TLS channel
	// (mode13.go); nil refuses mode 13.
	TLS TLSHandler
	// TLSEstablished reports whether a meter has an established TLS
	// channel (alerts inside it need no AFL CMAC).
	TLSEstablished func(meter Header) bool
	// MaxMessage caps a reassembled message (0: 64 kbytes, the AFL.ML
	// range of EN 13757-7; OMSMaxMessage under the OMS profile).
	MaxMessage int
	// MeterSide decodes messages sent to a meter (KDF-A derives Lenc and
	// Lmac): for meter simulators and checks of our own downlinks.
	MeterSide bool
}

type partialMsg struct {
	afl      AFL // fields gathered so far
	next     byte
	count    int
	data     []byte
	at       time.Time
	fragMACs []fragMAC
}

// fragMAC is one fragment's MAC under individual fragment authentication.
type fragMAC struct {
	fid       byte
	data, mac []byte
}

func now(d *Decoder) time.Time {
	if d != nil && d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func fid(a *AFL) byte { return byte(a.FCL) }

// pending returns the AFL gathered for a meter's partial message, if one
// is waiting and still fresh.
func (d *Decoder) pending(h Header, t time.Time) *AFL {
	d.mu.Lock()
	defer d.mu.Unlock()
	pm := d.partial[h.Key()]
	if pm == nil {
		return nil
	}
	if t.Sub(pm.at) > FragmentTimeout {
		delete(d.partial, h.Key())
		return nil
	}
	a := pm.afl
	return &a
}

// fragment adds a datagram's payload after the AFL to its message. It
// returns the whole message when this was the last fragment.
func (d *Decoder) fragment(tg *Telegram, p []byte, t time.Time) ([]byte, bool, error) {
	a := tg.AFL
	key := tg.Header.Key()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.partial == nil {
		d.partial = map[string]*partialMsg{}
	}
	pm := d.partial[key]
	if fid(a) == 0 && a.FCL&AFLMF == 0 {
		// An unfragmented message: whatever was pending cannot be
		// completed any more.
		delete(d.partial, key)
		return p, true, nil
	}
	if pm != nil && (t.Sub(pm.at) > FragmentTimeout || fid(a) != pm.next) {
		// A new message, or a gap: the old one cannot be completed.
		delete(d.partial, key)
		lost := pm
		pm = nil
		if fid(a) != lost.next && a.FCL&AFLMF == 0 {
			return nil, false, fmt.Errorf("fragment %d does not follow fragment %d; the message is incomplete", fid(a), lost.next-1)
		}
	}
	if pm == nil {
		if a.FCL&AFLMF == 0 {
			// Last fragment with no earlier one: not a fragmented message
			// after all (d.pending found nothing), decode it as it is.
			return p, true, nil
		}
		if len(d.partial) >= maxPartial {
			for k, o := range d.partial {
				if t.Sub(o.at) > FragmentTimeout {
					delete(d.partial, k)
				}
			}
			if len(d.partial) >= maxPartial {
				return nil, false, errors.New("too many partial messages")
			}
		}
		if fid(a) != 1 {
			return nil, false, fmt.Errorf("fragment %d without the first fragment", fid(a))
		}
		pm = &partialMsg{afl: AFL{}}
		d.partial[key] = pm
	}
	if a.has.mac && (a.FCL&AFLMF != 0 || len(pm.fragMACs) > 0) {
		pm.fragMACs = append(pm.fragMACs, fragMAC{fid(a), append([]byte(nil), p...), a.MAC})
	}
	pm.merge(a)
	pm.data = append(pm.data, p...)
	pm.next, pm.at = fid(a)+1, t
	pm.count++
	if len(pm.data) > d.maxMessage() {
		delete(d.partial, key)
		return nil, false, fmt.Errorf("a fragmented message longer than %d bytes", d.maxMessage())
	}
	if a.FCL&AFLMF != 0 {
		return nil, false, ErrFragment
	}
	delete(d.partial, key)
	merged := pm.afl
	merged.FCL = a.FCL
	merged.Fragments = pm.count
	merged.fragMACs = pm.fragMACs
	if len(pm.fragMACs) > 0 {
		merged.MAC, merged.has.mac = nil, false
	}
	*tg.AFL = merged
	if merged.has.ml && int(merged.ML) != len(pm.data) {
		return nil, false, fmt.Errorf("the reassembled message has %d bytes, AFL.ML says %d", len(pm.data), merged.ML)
	}
	return pm.data, true, nil
}

// merge takes the fields a fragment carries.
func (pm *partialMsg) merge(a *AFL) {
	m := &pm.afl
	if a.has.mcl {
		m.MCL, m.has.mcl = a.MCL, true
	}
	if a.has.ki {
		m.KI, m.has.ki = a.KI, true
	}
	if a.has.mcr {
		m.Counter, m.has.mcr = a.Counter, true
	}
	if a.has.mac {
		m.MAC, m.has.mac = a.MAC, true
	}
	if a.has.ml {
		m.ML, m.has.ml = a.ML, true
	}
}

// macInput is the AFL part of the MAC input (clause 9.3.2): MCL, KI, MCR
// and ML as present, in transmission order.
func (a *AFL) macInput() []byte {
	var b []byte
	if a.has.mcl {
		b = append(b, a.MCL)
	}
	if a.has.ki {
		b = binary.LittleEndian.AppendUint16(b, a.KI)
	}
	if a.has.mcr {
		b = binary.LittleEndian.AppendUint32(b, a.Counter)
	}
	if a.has.ml {
		b = binary.LittleEndian.AppendUint16(b, a.ML)
	}
	return b
}
