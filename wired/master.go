// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package wired

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/mbus/tpdu"
)

// Master is the primary station of a wired M-Bus segment (EN
// 13757-2:2018+A1:2023 clause 5, EN 13757-3:2025): it keeps the frame
// count bit of every address, repeats unanswered requests, selects slaves
// by primary or secondary address, searches the bus and runs the
// application procedures. Its line is a Port (SetPort), which can be
// replaced when the line is reopened; the frame count bits stay.
//
// A Master runs one transaction at a time: the caller serialises the
// methods that talk on the bus (a selection followed by a read is one
// transaction, so it holds its own lock around both).
type Master struct {
	// Timeout is the time to the first byte of an answer; zero is 2 s.
	// MaxAnswerDelay is the least a slave may take.
	Timeout time.Duration
	// Retries is how often an unanswered request, or one answered with a
	// damaged frame, is repeated (the standard's two: three attempts).
	Retries int
	// Log receives the search's notes; nil is slog.Default().
	Log *slog.Logger

	mu   sync.Mutex
	p    *Port
	baud int
	// fcb is the frame count bit of the last request to each address
	// (5.7.7); dirty253 is set once a request went to address 253 since
	// the last SND_NKE there or to everyone.
	fcb      map[byte]bool
	dirty253 bool
}

// NewMaster is a master with the standard's timing for the baud rate:
// answer timeout 10 s at 300 Bd, 2 s up to 2400 Bd, 1 s above, and two
// retries.
func NewMaster(baud int) *Master {
	t := time.Second
	switch {
	case baud <= 300:
		t = 10 * time.Second
	case baud <= 2400:
		t = 2 * time.Second
	}
	return &Master{Timeout: t, Retries: 2, baud: baud}
}

// ErrNoAnswer is the error of an exchange nobody answered.
var ErrNoAnswer = errors.New("no answer")

// SetPort gives the master its line at a baud rate (nil when the line is
// closed).
func (m *Master) SetPort(p *Port, baud int) {
	m.mu.Lock()
	m.p = p
	if baud > 0 {
		m.baud = baud
	}
	m.mu.Unlock()
}

// Port is the open line.
func (m *Master) Port() (*Port, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.p == nil {
		return nil, errors.New("the M-Bus line is not open")
	}
	return m.p, nil
}

// Baud is the line's rate.
func (m *Master) Baud() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.baud
}

func (m *Master) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

func (m *Master) timeout() time.Duration {
	if m.Timeout > 0 {
		return m.Timeout
	}
	return 2 * time.Second
}

// sequence sets the frame count bit of a frame to the slave at f.A
// (5.7.7): REQ_UD1 and REQ_UD2 toggle the address's bit, SND_UD carries
// the bit of the last request, SND_NKE clears the address's bit (the
// broadcast every address's) and SND_UD2 has FCV and FCB clear. The
// retries of one exchange repeat the frame unchanged, which a slave takes
// as a repetition. See F-2052 and F-2053 for why SND_UD carries the last
// request's bit.
func (m *Master) sequence(f Frame) Frame {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fcb == nil {
		m.fcb = map[byte]bool{}
	}
	fn := f.C &^ FCB
	switch {
	case !f.Long && f.C == CSndNke:
		if f.A == AddrBroadcast {
			clear(m.fcb)
			m.dirty253 = false
		} else {
			delete(m.fcb, f.A)
			if f.A == AddrSecondary {
				m.dirty253 = false
			}
		}
	case !f.Long && (fn == CReqUD1 || fn == CReqUD2):
		next := !m.fcb[f.A]
		m.fcb[f.A] = next
		f.C = fn
		if next {
			f.C |= FCB
		}
		if f.A == AddrSecondary {
			m.dirty253 = true
		}
	case f.Long && fn == CSndUD:
		f.C = fn
		if m.fcb[f.A] {
			f.C |= FCB
		}
	case f.Long && fn == CSndUD2:
		f.C = CSndUD2
	}
	return f
}

// link sends a frame and, when an answer is expected, reads one. An
// unanswered frame is repeated up to Retries times; so is one answered
// with a damaged frame, except in a search, where a damaged answer is a
// collision and is returned at once. A frame nobody answers is followed
// by a pause (quietAfter).
func (m *Master) link(ctx context.Context, f Frame, answer, search bool) (Frame, error) {
	if err := f.Check(); err != nil {
		return Frame{}, err
	}
	p, err := m.Port()
	if err != nil {
		return Frame{}, err
	}
	f = m.sequence(f)
	wire := f.Encode()
	baud := m.Baud()
	last := ErrNoAnswer
	for try := 0; try <= m.Retries; try++ {
		if ctx.Err() != nil {
			return Frame{}, ctx.Err()
		}
		p.Drain()
		if _, err := p.Write(wire); err != nil {
			return Frame{}, err
		}
		if !answer {
			t := time.NewTimer(quietAfter(len(wire), baud))
			select {
			case <-ctx.Done():
				t.Stop()
				return Frame{}, ctx.Err()
			case <-t.C:
			}
			return Frame{}, nil
		}
		r, err := readAnswer(p, m.timeout(), baud)
		switch {
		case errors.Is(err, ErrTimeout):
			last = ErrNoAnswer
			continue
		case errors.Is(err, ErrFrame) && !search:
			last = err
			p.quiet(baud)
			continue
		}
		return r, err
	}
	return Frame{}, last
}

// readAnswer waits up to timeout for the first byte of an answer, then
// allows the rest the time the longest frame takes at the baud rate (plus
// the timeout again as slack for converters).
func readAnswer(p *Port, timeout time.Duration, baud int) (Frame, error) {
	p.SetDeadline(time.Now().Add(timeout))
	defer p.SetDeadline(time.Time{})
	c, err := p.ReadByte()
	if err != nil {
		return Frame{}, err
	}
	p.SetDeadline(time.Now().Add(FrameTime(maxFrame, baud) + timeout))
	return ReadFrame(&firstByte{c: c, r: p})
}

// firstByte gives one byte already read, then the rest of r.
type firstByte struct {
	c    byte
	used bool
	r    io.ByteReader
}

func (b *firstByte) ReadByte() (byte, error) {
	if !b.used {
		b.used = true
		return b.c, nil
	}
	return b.r.ReadByte()
}

// quiet reads and drops bytes until the line has been idle for more than
// 22 bit times (5.5.2, at least 50 ms for converters), so the rest of a
// damaged answer is not taken for the next one.
func (p *Port) quiet(baud int) {
	gap := max(bits(22, baud), 50*time.Millisecond)
	defer p.SetDeadline(time.Time{})
	for i := 0; i < 4*maxFrame; i++ {
		p.SetDeadline(time.Now().Add(gap))
		if _, err := p.ReadByte(); err != nil {
			return
		}
	}
}

// Exchange sends a frame and reads one answer: the frame count bit is set
// by the link sequence, and an unanswered frame or a damaged answer is
// repeated up to Retries times. Without answer the frame is sent once and
// followed by the pause a datagram nobody answers needs.
func (m *Master) Exchange(ctx context.Context, f Frame, answer bool) (Frame, error) {
	return m.link(ctx, f, answer, false)
}

// ExpectACK sends a frame that is answered with E5; what names it in
// errors.
func (m *Master) ExpectACK(ctx context.Context, f Frame, what string) error {
	r, err := m.Exchange(ctx, f, true)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if r.Nack {
		return fmt.Errorf("%s: the meter answered NACK (not accepted)", what)
	}
	if !r.Single {
		return fmt.Errorf("%s: answered with C=%02X instead of an acknowledgement", what, r.C)
	}
	return nil
}

// Target names one slave: by its primary address, or (when Secondary is
// set) by its secondary address, which may have wildcards. Name is how
// errors call it.
type Target struct {
	Primary   byte
	Secondary *SecondaryAddress
	Name      string
}

// Select prepares a slave for REQ_UD2: SND_NKE to its primary address, or
// selection of its secondary address. It returns the address to poll.
func (m *Master) Select(ctx context.Context, t Target) (byte, error) {
	if t.Secondary == nil {
		a := t.Primary
		return a, m.ExpectACK(ctx, Frame{C: CSndNke, A: a}, "SND_NKE")
	}
	b, err := t.Secondary.Bytes()
	if err != nil {
		return 0, err
	}
	// Broadcast SND_NKE (no answer) deselects every slave and resets their
	// frame count bits, then the meter is selected.
	if _, err := m.Exchange(ctx, Frame{C: CSndNke, A: AddrBroadcast}, false); err != nil {
		return 0, err
	}
	if err := m.ExpectACK(ctx, Frame{C: CSndUD, A: AddrSecondary, Long: true, CI: CISelect, Data: b}, "selection of "+t.Secondary.ID); err != nil {
		return 0, err
	}
	return AddrSecondary, nil
}

// Full reports whether a secondary address names one meter: no part is
// a wildcard.
func Full(a *SecondaryAddress) bool {
	return a != nil && !strings.ContainsAny(a.ID, "Ff") && a.Manufacturer != 0xFFFF && a.Version != 0xFF && a.Medium != 0xFF
}

// SelectOne prepares a slave for a command that changes it. A slave named
// by a secondary address with wildcards (ID or ID.MAN, version and medium
// left open) can select several slaves sharing its identification
// number, which would all carry the command out and acknowledge as one
// (EN 13757-2: simultaneous single characters cannot be told apart). So
// the selected slaves are read once: a collision, or an answer from
// another address than the target's, refuses the command; otherwise the
// slave's full address is selected for the command. full is that address
// when it was read (nil otherwise).
func (m *Master) SelectOne(ctx context.Context, t Target) (a byte, full *SecondaryAddress, err error) {
	a, err = m.Select(ctx, t)
	if err != nil || t.Secondary == nil || Full(t.Secondary) {
		return a, nil, err
	}
	f, err := m.Exchange(ctx, Frame{C: CReqUD2, A: a}, true)
	if errors.Is(err, ErrFrame) {
		return 0, nil, fmt.Errorf("more than one meter answers the secondary address of meter %s (or the line is noisy); name the meter by its full secondary address ID.MAN.version.medium so the command reaches one meter", t.Name)
	}
	if err != nil {
		return 0, nil, fmt.Errorf("checking that one meter is selected: %w", err)
	}
	r, _ := ParseResponse(f)
	if r == nil || !r.Header || !r.Address.Matches(*t.Secondary) {
		return 0, nil, fmt.Errorf("checking that one meter is selected: the answer to the secondary address of meter %s has no matching long header", t.Name)
	}
	if !Full(&r.Address) {
		return a, nil, nil // one slave answered, but its address cannot be selected alone
	}
	addr := r.Address
	one := t
	one.Secondary = &addr
	a, err = m.Select(ctx, one)
	return a, &addr, err
}

// Telegram is one answer to REQ_UD2 in ReadTelegrams. ParseErr says what
// of it was not decoded; APDU is a whole DLMS/COSEM APDU (CI 7Ch/7Dh, or
// the transport PDUs up to the last one joined).
type Telegram struct {
	*Response
	ParseErr error
	APDU     []byte
}

// ReadTelegrams sends REQ_UD2 to the selected address a until the slave
// has no more telegrams (the last record is not DIF 1Fh), up to max
// telegrams, and passes each answer to fn. It stops at an application
// error (returned after fn saw it), a fixed data structure and a DLMS
// APDU, and returns how many telegrams were read. The frame count bit
// starts at 1 after SND_NKE or selection and toggles with each REQ_UD2.
func (m *Master) ReadTelegrams(ctx context.Context, a byte, max int, fn func(Telegram) error) (int, error) {
	var tre tpdu.Reassembler // DLMS transport PDUs (EN 13757-1:2021 8.2.4)
	n := 0
	for ; n < max; n++ {
		f, err := m.Exchange(ctx, Frame{C: CReqUD2, A: a}, true)
		if err != nil {
			return n, fmt.Errorf("REQ_UD2 (telegram %d): %w", n+1, err)
		}
		r, perr := ParseResponse(f)
		if r == nil {
			return n, fmt.Errorf("telegram %d: %w", n+1, perr)
		}
		t := Telegram{Response: r, ParseErr: perr}
		var terr error
		switch {
		case r.DLMS != nil:
			t.APDU = r.DLMS
		case r.TPDU != nil:
			t.APDU, terr = tre.Add(*r.TPDU)
		}
		if err := fn(t); err != nil {
			return n, err
		}
		if terr != nil {
			return n, fmt.Errorf("telegram %d: %w", n+1, terr)
		}
		if r.AppError != nil {
			// Clause 10.3: the slave answers with an application error
			// instead of data.
			return n, *r.AppError
		}
		if r.TPDU != nil && t.APDU == nil { // more transport PDUs follow
			continue
		}
		if r.Fixed != nil || t.APDU != nil || !r.More {
			n++
			break
		}
	}
	return n, nil
}

// RequestClass1 requests class 1 data (REQ_UD1, EN 13757-2 clause 5) of
// the selected address a. A slave with nothing to report acknowledges with
// E5 (a nil response); otherwise it answers RSP_UD, usually with an alarm
// status (CI 71h).
func (m *Master) RequestClass1(ctx context.Context, a byte) (*Response, error) {
	f, err := m.Exchange(ctx, Frame{C: CReqUD1 | FCB, A: a}, true)
	if err != nil {
		return nil, fmt.Errorf("REQ_UD1: %w", err)
	}
	if f.Single {
		return nil, nil
	}
	r, err := ParseResponse(f)
	if r == nil {
		return nil, fmt.Errorf("REQ_UD1 answer: %w", err)
	}
	return r, nil
}

// ConfirmAlarm confirms an alarm status (EN 13757-3:2025 annex D.1): a
// slave repeats its alarm frame until a REQ_UD1 with the frame count bit
// toggled confirms it; a one-time alarm is then answered with E5.
func (m *Master) ConfirmAlarm(ctx context.Context, a byte) error {
	_, err := m.Exchange(ctx, Frame{C: CReqUD1, A: a}, true)
	return err
}

// Reset sends an application reset (SND_UD CI 50h) to the selected
// address a.
func (m *Master) Reset(ctx context.Context, a byte) error {
	return m.ExpectACK(ctx, Frame{C: CSndUD, A: a, Long: true, CI: CIAppReset}, "application reset")
}

// SelectApplication selects a message application and block (EN
// 13757-3:2025 clause 7.2) at the selected address a.
func (m *Master) SelectApplication(ctx context.Context, a byte, app, block int) error {
	sub, err := SelectSubcode(app, block)
	if err != nil {
		return err
	}
	return m.ExpectACK(ctx, Frame{C: CSndUD, A: a, Long: true, CI: CIAppSelect, Data: sub}, "application select")
}

// CheckAppError reads the selected address a once: an application error
// answer (CI 6Eh-70h, clause 10.1) is returned as the AppError; err is a
// failed read.
func (m *Master) CheckAppError(ctx context.Context, a byte) (*AppError, error) {
	f, err := m.Exchange(ctx, Frame{C: CReqUD2 | FCB, A: a}, true)
	if err != nil {
		return nil, err
	}
	r, _ := ParseResponse(f)
	if r != nil && r.AppError != nil {
		return r.AppError, nil
	}
	return nil, nil
}

// ReadAddress reads the selected address a once for its long header: the
// slave's full secondary address.
func (m *Master) ReadAddress(ctx context.Context, a byte) (SecondaryAddress, error) {
	f, err := m.Exchange(ctx, Frame{C: CReqUD2 | FCB, A: a}, true)
	if err != nil {
		return SecondaryAddress{}, fmt.Errorf("reading the meter's address: %w", err)
	}
	r, _ := ParseResponse(f)
	if r == nil || !r.Header {
		return SecondaryAddress{}, errors.New("the meter's answer has no long header, so its address for the command is unknown")
	}
	return r.Address, nil
}

// LongHeader is the 12-byte TPL long header of a command to a slave: its
// address, our access number acc, status 0 and configuration 0 (no
// security).
func LongHeader(id SecondaryAddress, acc byte) ([]byte, error) {
	b, err := id.Bytes()
	if err != nil {
		return nil, err
	}
	return append(b, acc, 0, 0, 0), nil
}

// SetPrimary gives the slave t the primary address to (1 to 250): the
// address must be free (no slave acknowledges SND_NKE there), then the
// slave is selected alone (SelectOne) and sent the data record DIF 01h,
// VIF 7Ah. When its acknowledgement is lost, the repeats to the old
// address go unanswered; a slave answering at the new address (free
// before) then has it, and lostACK reports that case.
func (m *Master) SetPrimary(ctx context.Context, t Target, to byte) (lostACK bool, err error) {
	if to < 1 || to > 250 {
		return false, errors.New(`set-primary needs "address" 1 to 250`)
	}
	if err := m.ExpectACK(ctx, Frame{C: CSndNke, A: to}, "SND_NKE"); err == nil {
		return false, fmt.Errorf("a meter answers at primary address %d already; choose a free address", to)
	} else if !errors.Is(err, ErrNoAnswer) {
		return false, fmt.Errorf("checking that primary address %d is free: %w", to, err)
	}
	a, _, err := m.SelectOne(ctx, t)
	if err != nil {
		return false, err
	}
	if err := m.ExpectACK(ctx, Frame{C: CSndUD, A: a, Long: true, CI: CISetData, Data: []byte{0x01, 0x7A, to}}, "primary address change"); err != nil {
		if !errors.Is(err, ErrNoAnswer) || m.ExpectACK(ctx, Frame{C: CSndNke, A: to}, "SND_NKE") != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// SwitchBaud sends the baud rate switch of clause 11 (a control frame
// with the baud rate's CI) to address a, acknowledged at the old rate.
// The caller then reopens the line at the new rate; the slave must answer
// there within 2 minutes.
func (m *Master) SwitchBaud(ctx context.Context, a byte, baud int) error {
	ci, err := BaudCI(baud)
	if err != nil {
		return err
	}
	return m.ExpectACK(ctx, Frame{C: CSndUD, A: a, Long: true, CI: ci}, fmt.Sprintf("baud switch to %d", baud))
}

// ---- secondary address search -----------------------------------------------

// Probe selects a pattern and reports how many slaves match: 0, 1 (with
// its address) or 2 meaning "more than one" (a collision).
func (m *Master) Probe(ctx context.Context, pattern SecondaryAddress) (int, SecondaryAddress, error) {
	b, err := pattern.Bytes()
	if err != nil {
		return 0, SecondaryAddress{}, err
	}
	// A slave keeps one frame count bit for address 253 whichever
	// secondary address selected it (EN 13757-2 5.7.7), so after a read at
	// 253 every slave is normalised again before the next selection; else
	// a slave read before could take our request for a repetition.
	m.mu.Lock()
	dirty := m.dirty253
	m.mu.Unlock()
	if dirty {
		if _, err := m.Exchange(ctx, Frame{C: CSndNke, A: AddrBroadcast}, false); err != nil {
			return 0, SecondaryAddress{}, err
		}
	}
	r, err := m.link(ctx, Frame{C: CSndUD, A: AddrSecondary, Long: true, CI: CISelect, Data: b}, true, true)
	switch {
	case errors.Is(err, ErrNoAnswer):
		return 0, SecondaryAddress{}, nil
	case errors.Is(err, ErrFrame), err == nil && !r.Single:
		// Garbled or overlapping acknowledgements: a collision (EN
		// 13757-2 annex D), resolved by going a digit deeper.
		return 2, SecondaryAddress{}, nil
	case err != nil:
		return 0, SecondaryAddress{}, err
	}
	// Several slaves acknowledging at once can still look like one E5;
	// reading the selected slave tells.
	f, err := m.link(ctx, Frame{C: CReqUD2, A: AddrSecondary}, true, true)
	if errors.Is(err, ErrFrame) {
		return 2, SecondaryAddress{}, nil
	}
	if err != nil {
		return 0, SecondaryAddress{}, err
	}
	resp, _ := ParseResponse(f)
	if resp == nil || !resp.Header {
		return 2, SecondaryAddress{}, nil
	}
	return 1, resp.Address, nil
}

// Search runs the wildcard search over the identification digits, most
// significant first, going one digit deeper wherever slaves collide, and
// returns the slaves found (also when it fails part way).
func (m *Master) Search(ctx context.Context) ([]SecondaryAddress, error) {
	// Normalise every slave first: SND_NKE to the broadcast address clears
	// the selections and frame count bits (EN 13757-2 5.7.3.1).
	if _, err := m.Exchange(ctx, Frame{C: CSndNke, A: AddrBroadcast}, false); err != nil {
		return nil, err
	}
	var out []SecondaryAddress
	var walk func(prefix string) error
	walk = func(prefix string) error {
		for dgt := byte('0'); dgt <= '9'; dgt++ {
			pat := Wildcard
			pat.ID = prefix + string(dgt) + strings.Repeat("F", 7-len(prefix))
			n, a, err := m.Probe(ctx, pat)
			if err != nil {
				return err
			}
			switch {
			case n == 1:
				out = append(out, a)
			case n == 2 && len(prefix) < 7:
				if err := walk(prefix + string(dgt)); err != nil {
					return err
				}
			case n == 2:
				m.log().Warn("M-Bus slaves share an identification number; they differ only in manufacturer, version or medium", "id", pat.ID)
			}
		}
		return nil
	}
	err := walk("")
	return out, err
}

// ErrImageNoResponse is ImageCommand's error when the device sends no
// image transfer response (a device may not answer while it activates).
var ErrImageNoResponse = errors.New("no image transfer response")

// ImageCommand sends one image transfer command segment (EN 13757-3:2025
// annex I, CI C0h behind our long header hdr) to the selected address a
// and, when want is set, reads the response segment with the same segment
// ID.
func (m *Master) ImageCommand(ctx context.Context, a byte, hdr []byte, seg Segment, want bool) (Segment, error) {
	data := append(append([]byte(nil), hdr...), EncodeSegments(seg)...)
	if err := m.ExpectACK(ctx, Frame{C: CSndUD, A: a, Long: true, CI: CIImageCmdLong, Data: data}, "image transfer command"); err != nil {
		return Segment{}, err
	}
	if !want {
		return Segment{}, nil
	}
	f, err := m.Exchange(ctx, Frame{C: CReqUD2 | FCB, A: a}, true)
	if errors.Is(err, ErrNoAnswer) {
		return Segment{}, ErrImageNoResponse
	}
	if err != nil {
		return Segment{}, err
	}
	if f.Single || !f.Long {
		return Segment{}, ErrImageNoResponse
	}
	var p []byte
	switch f.CI {
	case CIImageRspLong:
		if len(f.Data) < 12 {
			return Segment{}, errors.New("the image transfer response's long header is short")
		}
		p = f.Data[12:]
	case CIImageRspShort:
		if len(f.Data) < 4 {
			return Segment{}, errors.New("the image transfer response's short header is short")
		}
		p = f.Data[4:]
	case CIAppErrNone, CIAppErrShort, CIAppErrLong:
		r, _ := ParseResponse(f)
		if r != nil && r.AppError != nil {
			return Segment{}, *r.AppError
		}
		return Segment{}, errors.New("an application error")
	default:
		return Segment{}, fmt.Errorf("the device answered with CI %02Xh instead of an image transfer response", f.CI)
	}
	segs, err := ParseSegments(p)
	if err != nil {
		return Segment{}, err
	}
	for _, s := range segs {
		if s.ID == seg.ID {
			return s, nil
		}
	}
	return Segment{}, fmt.Errorf("the response has no segment %d", seg.ID)
}
