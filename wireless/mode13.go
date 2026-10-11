package wireless

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	tls "github.com/cB-Sigma/tlsx"
)

// Security mode 13: TLS 1.2 carried over wireless M-Bus (OMS Volume 2
// annex F, issue 5.0.1, release C). The meter (OMS end-device) is the TLS
// client and the gateway, which is us, the TLS server:
//
//   - the configuration field is CC, 0, mode 13, N = FFh; a one-byte
//     extension (CFE) names the protocol type: 0 TLSCHAN (channel request),
//     1 TLSPROT (handshake, alert, application records), F.3.2, F.3.3;
//   - after the CFE come one or more TLS records (type, 03 03, length MSB
//     first); a channel request is a record header of type 00h with zero
//     reserved bytes and length (tables F.8, F.10);
//   - the channel request and the meter's ClientHello, and alerts outside a
//     session, are protected by an AFL CMAC of at least 8 bytes (F.3.1,
//     table F.12); everything else by TLS;
//   - our messages use CI 5Fh with a long header naming the meter (handshake,
//     channel request) or 5Bh (application data); the meter's use 9Eh/9Fh
//     for handshakes and 7Ah/72h for application data (table F.7);
//   - a flight longer than one datagram is split with the AFL (FID, MF,
//     ML) behind an ELL 8Eh naming the meter (F.D.4).
//
// tlsx (github.com/cB-Sigma/tlsx, our crypto/tls fork) implements the server:
// ECDHE_ECDSA with AES-128/256 in GCM and in CBC (SHA-256, SHA-384) with
// encrypt-then-MAC (RFC 7366) required for CBC, on the annex F Table F.2
// curves brainpoolP256r1/P384r1/P512r1, secp256r1 and secp384r1
// (RFC 7027), with ECDSA
// certificates on those curves; the meter's max_fragment_length (RFC 6066)
// is honoured, and sessions resume by session ID (and ticket) (F-451).

// TLS record content types (table F.6).
const (
	tlsChannelRequest byte = 0x00
	tlsCCS            byte = 0x14
	tlsAlert          byte = 0x15
	tlsHandshake      byte = 0x16
	tlsAppData        byte = 0x17
)

// Mode 13 protocol types (CFE, table F.5).
const (
	TLSCHAN byte = 0x00
	TLSPROT byte = 0x01
)

// Mode 13 CI fields (EN 13757-7:2025 table 16 "specific usage"; annex F
// table F.7).
const (
	CITLSToMeter    byte   = 0x5F // long header, from the gateway
	CITLSShort      byte   = 0x9E // short header, from the meter
	CITLSLong       byte   = 0x9F // long header, from a meter behind an adapter
	cfgMode13       uint16 = 13<<8 | 0xFF
	mode13MaxRecord        = 16 * 1024
)

// TLSInfo is what a mode 13 telegram carried.
type TLSInfo struct {
	Protocol byte   // TLSCHAN or TLSPROT
	Types    []byte // content type of each record
	Records  []byte // the TLS records as received
	HSTypes  []byte // handshake message types seen in plaintext records
	Session  string // state reported by the channel ("handshake", "established")
}

// TLSHandler processes a mode 13 telegram's records for the meter's TLS
// channel and returns the application data they carried (nil for
// handshake and alert records).
type TLSHandler func(tg *Telegram, info *TLSInfo) ([]byte, error)

// splitRecords checks the record headers of a mode 13 TPL (after the CFE).
func splitRecords(protocol byte, p []byte) (*TLSInfo, error) {
	info := &TLSInfo{Protocol: protocol, Records: append([]byte(nil), p...)}
	for len(p) > 0 {
		if len(p) < 5 {
			return nil, errors.New("mode 13: a TLS record header is cut short")
		}
		ct, n := p[0], int(binary.BigEndian.Uint16(p[3:5]))
		switch {
		case protocol == TLSCHAN:
			if ct != tlsChannelRequest || p[1] != 0 || p[2] != 0 || n != 0 {
				return nil, errors.New("mode 13: a channel request is 00 00 00 00 00 (table F.10)")
			}
		case ct == tlsCCS || ct == tlsAlert || ct == tlsHandshake || ct == tlsAppData:
			// Annex F table F.11 shows 03 03; a ClientHello record may carry
			// 03 01 for compatibility (RFC 5246 appendix E.1), which TLS
			// stacks send and servers accept.
			hello := ct == tlsHandshake && n > 0 && len(p) > 5 && p[5] == 0x01
			if p[1] != 3 || p[2] != 3 && !(hello && p[2] == 1) {
				return nil, fmt.Errorf("mode 13: TLS version %d.%d, only TLS 1.2 (3.3)", p[1], p[2])
			}
		default:
			return nil, fmt.Errorf("mode 13: TLS content type %02Xh not allowed for protocol type %d (table F.6)", ct, protocol)
		}
		if len(p) < 5+n || n > mode13MaxRecord {
			return nil, fmt.Errorf("mode 13: TLS record of %d bytes, %d follow", n, len(p)-5)
		}
		info.Types = append(info.Types, ct)
		if ct == tlsHandshake && n > 0 {
			info.HSTypes = append(info.HSTypes, p[5])
		}
		p = p[5+n:]
	}
	if len(info.Types) == 0 {
		return nil, errors.New("mode 13: no TLS record")
	}
	return info, nil
}

// mode13 decodes a security mode 13 TPL (after the configuration field).
func (tg *Telegram) mode13(d *Decoder, s *Security, p, tpdu []byte, keys KeyLookup) ([]byte, error) {
	if tg.Config&0x2000 != 0 || tg.Config&0xFF != 0xFF {
		return nil, fmt.Errorf("mode 13: configuration field %04Xh (bit 13 must be 0, N must be FFh; annex F table F.3)", tg.Config)
	}
	s.Content = int(tg.Config >> 14)
	if len(p) < 1 {
		return nil, errTruncated
	}
	cfe := p[0]
	if cfe&0xF0 != 0 || cfe&0x0F > TLSPROT {
		return nil, fmt.Errorf("mode 13: CFE %02Xh (protocol types 0 and 1 only, table F.5)", cfe)
	}
	info, err := splitRecords(cfe, p[1:])
	if err != nil {
		return nil, err
	}
	tg.TLS = info
	s.KDF = 1 // the AFL CMAC keys come from the master key by KDF-A
	if tg.AFL != nil && tg.AFL.has.mcr {
		s.Counter, s.HasCounter, s.CounterFrom = tg.AFL.Counter, true, "afl"
	}
	// Channel requests, ClientHellos and alerts in the clear need the
	// AFL CMAC (F.3.1, F.3.4.2, F.3.4.4, table F.12).
	needMAC := cfe == TLSCHAN || bytes.Contains(info.HSTypes, []byte{0x01}) ||
		(bytes.Contains(info.Types, []byte{tlsAlert}) && !(d != nil && d.TLSEstablished != nil && d.TLSEstablished(tg.Meter)))
	if tg.AFL != nil && (tg.AFL.has.mac || len(tg.AFL.fragMACs) > 0) {
		if err := tg.aflAuth(d, keys, s, tpdu); err != nil {
			return nil, err
		}
		if tg.AFL.MCL&0x0F < 5 && needMAC {
			return nil, errors.New("mode 13: the AFL CMAC must be at least 8 bytes (annex F F.3.1)")
		}
	} else if needMAC {
		return nil, fmt.Errorf("%w: mode 13 channel request, ClientHello or unprotected alert without an AFL CMAC", ErrMAC)
	}
	if d == nil || d.TLS == nil {
		return nil, fmt.Errorf("%w: security mode 13 needs a TLS channel (Decoder.TLS)", ErrUnsupport)
	}
	apl, err := d.TLS(tg, info)
	if err != nil {
		return nil, err
	}
	if len(s.Verified) > 0 {
		if aerr := tg.accept(d, s, tpdu); aerr != nil {
			return nil, aerr
		}
	}
	if apl != nil {
		s.Verified = append(s.Verified, "tls")
		tg.Encrypted = true
		s.aplEnc = len(apl)
	}
	return apl, nil
}

// SealMode13 builds a mode 13 TPL from its CI field: header (long when
// long is set, naming meter), configuration field (CC in hi's bits 15–14),
// CFE and the records.
func SealMode13(ci byte, long bool, meter Header, acc, st byte, hi uint16, protocol byte, records []byte) []byte {
	b := []byte{ci}
	if long {
		b = append(b, meter.A[:4]...)
		b = binary.LittleEndian.AppendUint16(b, meter.MField)
		b = append(b, meter.Version, meter.DeviceType)
	}
	b = append(b, acc, st)
	b = binary.LittleEndian.AppendUint16(b, hi&0xC000|cfgMode13)
	b = append(b, protocol)
	return append(b, records...)
}

// ChannelRequestRecord is the TLSCHAN record (table F.10).
var ChannelRequestRecord = []byte{tlsChannelRequest, 0, 0, 0, 0}

// ---- transport: TLS bytes in and out of wM-Bus frames ---------------------

// tlsPipe is the net.Conn a TLS endpoint runs over: feed puts the records
// a frame carried in; Write collects what TLS sends, taken with drain.
type tlsPipe struct {
	mu      sync.Mutex
	cond    *sync.Cond
	in, out bytes.Buffer
	closed  bool
	blocked int  // times Read found nothing and waited
	waiting bool // a Read is waiting now
}

func newTLSPipe() *tlsPipe {
	p := &tlsPipe{}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *tlsPipe) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for p.in.Len() == 0 && !p.closed {
		p.blocked++
		p.waiting = true
		p.cond.Broadcast()
		p.cond.Wait()
		p.waiting = false
	}
	if p.in.Len() == 0 {
		return 0, io.EOF
	}
	return p.in.Read(b)
}

func (p *tlsPipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, net.ErrClosed
	}
	p.out.Write(b)
	return len(b), nil
}

func (p *tlsPipe) Close() error {
	p.mu.Lock()
	p.closed = true
	p.cond.Broadcast()
	p.mu.Unlock()
	return nil
}

// feed gives the TLS endpoint bytes and waits until it has consumed them
// and waits for more (or ends, or timeout passes).
func (p *tlsPipe) feed(b []byte, timeout time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	gen := p.blocked
	p.in.Write(b)
	p.cond.Broadcast()
	deadline := time.Now().Add(timeout)
	stop := time.AfterFunc(timeout, func() {
		p.mu.Lock()
		p.cond.Broadcast()
		p.mu.Unlock()
	})
	defer stop.Stop()
	for !(p.closed || p.waiting && p.in.Len() == 0 && (p.blocked > gen || len(b) == 0)) && time.Now().Before(deadline) {
		p.cond.Wait()
	}
}

// settle waits until the endpoint waits for input (after it started).
func (p *tlsPipe) settle(timeout time.Duration) { p.feed(nil, timeout) }

func (p *tlsPipe) drain() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	b := append([]byte(nil), p.out.Bytes()...)
	p.out.Reset()
	return b
}

func (p *tlsPipe) LocalAddr() net.Addr              { return pipeAddr{} }
func (p *tlsPipe) RemoteAddr() net.Addr             { return pipeAddr{} }
func (p *tlsPipe) SetDeadline(time.Time) error      { return nil }
func (p *tlsPipe) SetReadDeadline(time.Time) error  { return nil }
func (p *tlsPipe) SetWriteDeadline(time.Time) error { return nil }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "wmbus" }
func (pipeAddr) String() string  { return "wmbus-mode13" }

// TLSEndpoint is one side of a mode 13 TLS channel: the server (us) or,
// in simulators and tests, the meter's client.
type TLSEndpoint struct {
	pipe  *tlsPipe
	conn  *tls.Conn
	mu    sync.Mutex
	plain bytes.Buffer
	err   error
	done  chan struct{}
	start time.Time
	bytes int // TLS bytes both ways, for the session limit
	// established and state are set by the endpoint's goroutine once the
	// handshake is done (ConnectionState would wait on the handshake lock
	// while the handshake waits for input).
	established bool
	state       tls.ConnectionState
}

// feedTimeout bounds one step of the TLS endpoint (ECDHE and ECDSA on a
// busy host).
var feedTimeout = 10 * time.Second

func newEndpoint(conn func(net.Conn) *tls.Conn) *TLSEndpoint {
	e := &TLSEndpoint{pipe: newTLSPipe(), done: make(chan struct{}), start: time.Now()}
	e.conn = conn(e.pipe)
	go func() {
		defer close(e.done)
		if err := e.conn.Handshake(); err != nil {
			e.mu.Lock()
			e.err = err
			e.mu.Unlock()
			e.pipe.Close()
			return
		}
		cs := e.conn.ConnectionState()
		e.mu.Lock()
		e.established, e.state = true, cs
		e.mu.Unlock()
		buf := make([]byte, mode13MaxRecord)
		for {
			n, err := e.conn.Read(buf)
			e.mu.Lock()
			e.plain.Write(buf[:n])
			if err != nil {
				e.err = err
				e.mu.Unlock()
				e.pipe.Close()
				return
			}
			e.mu.Unlock()
		}
	}()
	return e
}

// NewTLSServer starts the gateway side of a channel.
func NewTLSServer(cfg *tls.Config) *TLSEndpoint {
	return newEndpoint(func(c net.Conn) *tls.Conn { return tls.Server(c, cfg) })
}

// NewTLSClient starts a meter side (simulators, tests); its ClientHello is
// ready with Output once it settled.
func NewTLSClient(cfg *tls.Config) *TLSEndpoint {
	e := newEndpoint(func(c net.Conn) *tls.Conn { return tls.Client(c, cfg) })
	e.pipe.settle(feedTimeout)
	return e
}

// Input gives the endpoint received records and returns the records it
// answers with and the application data they carried.
func (e *TLSEndpoint) Input(records []byte) (out, plain []byte, err error) {
	e.bytes += len(records)
	e.pipe.feed(records, feedTimeout)
	out = e.pipe.drain()
	e.bytes += len(out)
	e.mu.Lock()
	plain = append([]byte(nil), e.plain.Bytes()...)
	e.plain.Reset()
	err = e.err
	e.mu.Unlock()
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return out, plain, err
}

// Output takes what the endpoint sent on its own (the client's hello).
func (e *TLSEndpoint) Output() []byte { return e.pipe.drain() }

// Send encrypts application data into records.
func (e *TLSEndpoint) Send(plain []byte) ([]byte, error) {
	done := make(chan error, 1)
	go func() { _, err := e.conn.Write(plain); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			return nil, err
		}
	case <-time.After(feedTimeout):
		return nil, errors.New("mode 13: the TLS channel did not take the data")
	}
	out := e.pipe.drain()
	e.bytes += len(out)
	return out, nil
}

// Established reports whether the handshake completed.
func (e *TLSEndpoint) Established() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.established
}

// State is the connection state (after the handshake).
func (e *TLSEndpoint) State() tls.ConnectionState {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state
}

// Close ends the channel (close_notify goes to Output).
func (e *TLSEndpoint) Close() []byte {
	done := make(chan struct{})
	go func() { _ = e.conn.CloseWrite(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
	}
	out := e.pipe.drain()
	e.pipe.Close()
	return out
}

// Session limits of annex F F.3.1: 31 days and 5 Mbytes of TLS data.
const (
	TLSSessionLife  = 31 * 24 * time.Hour
	TLSSessionBytes = 5 << 20
)

// Expired reports whether the session reached a limit of F.3.1.
func (e *TLSEndpoint) Expired(now time.Time) bool {
	return now.Sub(e.start) > TLSSessionLife || e.bytes > TLSSessionBytes
}

// Mode13Suites are the cipher suites the gateway accepts, in preference
// order: ECDHE_ECDSA with AES-GCM, then with AES-CBC and encrypt-then-MAC.
// Annex F names no suite list of its own (it refers to BSI TR-03116-3);
// these are the four of its ClientHello example (F.D.3), and with
// encrypt-then-MAC offered the server uses GCM or encrypt-then-MAC
// (F.3.1) (F-555).
var Mode13Suites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
}

// Mode13Curves are the ECDHE curves the gateway accepts, in preference
// order: the curves of annex F Table F.2 (brainpoolP256r1 and P-256 are
// mandatory, the others recommended).
var Mode13Curves = []tls.CurveID{tls.BrainpoolP256r1, tls.CurveP256, tls.BrainpoolP384r1, tls.CurveP384, tls.BrainpoolP512r1}

// ServerConfig is the gateway's TLS configuration for mode 13: TLS 1.2
// only, the suites and curves above, ECDSA signatures with SHA-256 or
// SHA-384, client certificates required and checked against the meter CAs,
// no renegotiation, resumption by session ID (in memory) or ticket.
func ServerConfig(cert tls.Certificate, meterCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS12,
		MaxVersion:       tls.VersionTLS12,
		CipherSuites:     append([]uint16(nil), Mode13Suites...),
		CurvePreferences: append([]tls.CurveID(nil), Mode13Curves...),
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        meterCAs,
		Renegotiation:    tls.RenegotiateNever,
		// Meter certificates: the LMN profile of BSI TR-03116-3 6.3.
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return nil
			}
			return CheckLMNCertificate(raw[0])
		},
		Ext: tls.ConfigExt{
			// Encrypt-then-MAC accepted and used for CBC when the meter
			// offers it, GCM preferred (annex F F.3.1, BSI TR-03116-3
			// 6.4.2); meters installed before 2025 may use CBC without it
			// unless the caller requires it (a VerifyConnection hook, say).
			EncryptThenMAC:     true,
			SignatureSchemes:   []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512},
			ServerSessionCache: newSessionIDCache(1024),
		},
	}
}

// lmnCurves are the curves of BSI TR-03116-3 Table 4, which LMN
// certificates must use (6.3).
var lmnCurves = map[string]bool{"P-256": true, "P-384": true, "brainpoolP256r1": true, "brainpoolP384r1": true, "brainpoolP512r1": true}

// LMNMaxDays is the validity of a certificate the gateway makes for a
// meter: 7 years (BSI TR-03116-3 Table 17).
const LMNMaxDays = 7 * 365

// CheckLMNCertificate checks a gateway or meter certificate against the
// LMN profile of BSI TR-03116-3 6.3: an ECDSA key on a Table 4 curve and
// at most 7 years of validity.
func CheckLMNCertificate(der []byte) error {
	c, err := tls.ParseCertificate(der)
	if err != nil {
		return err
	}
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate %q: key is not ECDSA (BSI TR-03116-3 6.3)", c.Subject.CommonName)
	}
	if name := pub.Curve.Params().Name; !lmnCurves[name] {
		return fmt.Errorf("certificate %q: curve %s is not one of BSI TR-03116-3 Table 4", c.Subject.CommonName, name)
	}
	if c.NotAfter.After(c.NotBefore.AddDate(7, 0, 1)) { // Table 17: 7 years (a day's slack)
		return fmt.Errorf("certificate %q: valid for more than 7 years (BSI TR-03116-3 Table 17)", c.Subject.CommonName)
	}
	return nil
}

// sessionIDCache is the gateway's TLS 1.2 session-ID cache: the newest
// max sessions, in memory (a restart forgets them, like the channels).
type sessionIDCache struct {
	mu    sync.Mutex
	max   int
	m     map[string]*tls.SessionState
	order []string
}

func newSessionIDCache(max int) *sessionIDCache {
	return &sessionIDCache{max: max, m: map[string]*tls.SessionState{}}
}

func (c *sessionIDCache) Get(id string) (*tls.SessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.m[id]
	return s, ok
}

func (c *sessionIDCache) Put(id string, s *tls.SessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.m[id]; !ok {
		c.order = append(c.order, id)
	}
	c.m[id] = s
	for len(c.order) > c.max {
		delete(c.m, c.order[0])
		c.order = c.order[1:]
	}
}

// ---- frames -----------------------------------------------------------------

// SplitTLSFrames builds CRC-less frames for a TPDU (a TPL, or an AFL with
// its TPL): one datagram behind ELL 8Ch when it fits, else AFL fragments
// behind ELL 8Eh naming peer (annex F F.D.4: FID from 1, MF, ML in the
// first fragment, no MAC). head is the 10-byte link header after L (C, M,
// A); c is the C field of the first frame and cNext of the others.
func SplitTLSFrames(head []byte, peer Header, c, cNext, cc, acc byte, tpdu []byte) [][]byte {
	frame := func(c byte, parts ...[]byte) []byte {
		f := append([]byte{0}, head...)
		f[1] = c
		for _, p := range parts {
			f = append(f, p...)
		}
		f[0] = byte(len(f) - 1)
		return f
	}
	if 10+3+len(tpdu) <= 255 {
		return [][]byte{frame(c, []byte{CIELL2, cc, acc}, tpdu)}
	}
	ell := []byte{CIELL10, cc, acc}
	ell = binary.LittleEndian.AppendUint16(ell, peer.MField)
	ell = append(ell, peer.A[:]...)
	var out [][]byte
	const room = 255 - 10 - 11
	fid := byte(1)
	for rest := tpdu; len(rest) > 0; fid++ {
		fcl := uint16(fid)
		var opt []byte
		if fid == 1 {
			fcl |= AFLMCLP | AFLMLP
			opt = append(opt, 0x40) // MCL: ML present
			opt = binary.LittleEndian.AppendUint16(opt, uint16(len(tpdu)))
		}
		n := min(len(rest), room-2-2-len(opt))
		if n < len(rest) {
			fcl |= AFLMF
		}
		afl := append(binary.LittleEndian.AppendUint16(nil, fcl), opt...)
		out = append(out, frame(c, ell, []byte{CIAFL, byte(len(afl))}, afl, rest[:n]))
		rest = rest[n:]
		c = cNext
	}
	return out
}

// LinkHead is the 10 bytes after L of a frame sent from address h.
func LinkHead(c byte, m uint16, a [6]byte) []byte {
	b := binary.LittleEndian.AppendUint16([]byte{c}, m)
	return append(b, a[:]...)
}
