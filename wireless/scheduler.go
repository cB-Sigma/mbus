// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package wireless

import (
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"time"
)

// A bidirectional meter listens only briefly after it transmits (EN
// 13757-4:2025 12.5.4 and 13.2.8), so a frame for it waits in a queue
// until the meter's next telegram that opens a receive window. Scheduler
// keeps those queues, one per meter, and decides after each telegram what
// is answered and what is sent:
//
//   - one frame per window, and none while a frame sent earlier still
//     waits for its answer (a meter answers one frame per window);
//   - an answer (ACK, NACK, RSP-UD) settles one waiting frame: the one
//     whose ELL access number it carries, else the oldest waiting, so a
//     meter that does not echo the access number is still matched;
//   - one frame count bit per meter, alternating with each new SND-UD,
//     REQ-UD1 and REQ-UD2 (FCV set) and reset by SND-NKE;
//   - a CNF-IR goes only after the meter's SND-IR and echoes its ELL and
//     TPL access numbers; the other frames take our own access number;
//   - a telegram relayed by a repeater (direct false) opens no window: the
//     meter's window follows its own transmission.
//
// The caller decodes the telegrams, chooses the security of each frame
// (Seal) and records the states (State); the scheduler writes the framed
// frames to the receiver (SetWriter).

// Downlink states reported through Scheduler.State.
const (
	StateQueued         = "queued"
	StateSent           = "sent"
	StateAcknowledged   = "acknowledged"
	StateAnswered       = "answered"
	StateRejected       = "rejected"
	StateUnacknowledged = "unacknowledged"
	StateExpired        = "expired"
	StateFailed         = "failed"
)

// AppRequest is a downlink the meter answers on the application layer
// after its link-layer ACK (a security information transfer, say).
type AppRequest interface {
	// AnsweredBy reports whether a telegram carries the answer.
	AnsweredBy(tg *Telegram) bool
}

// Pending is one frame queued for a meter.
type Pending struct {
	ID     string   // the caller's name for it (a command's ID)
	Action string   // what it does, for the caller's records
	Frame  Downlink // the frame, before its link and transport headers
	Queued time.Time
	Sent   time.Time // zero until sent
	// Await is set while the meter owes an answer; Window once the frame
	// went out in a meter's receive window, with ELLACC our ELL access
	// number in it. Acked is set when the link-layer ACK of an App request
	// arrived.
	Await  bool
	Window bool
	ELLACC byte
	Acked  bool
	// Expect is the answer the meter owes (ExpectFor(Frame.C)).
	Expect string
	// App, when set, is answered on the application layer (Scheduler.App).
	App AppRequest
	// Meter is the meter's header from the telegram whose window the frame
	// went in.
	Meter Header
}

// Scheduler is the downlink queue of a gateway. Its zero value is not
// usable: set Gateway (validated), Framer and Timeout.
type Scheduler struct {
	Gateway Gateway
	// Framer is FramerIM871A or FramerAmber; WithL sends the L field to the
	// receiver.
	Framer string
	WithL  bool
	// Timeout is how long a frame waits for a window, and a sent frame for
	// its answer.
	Timeout time.Duration
	// Seal chooses the security of a frame about to be sent in tg's
	// window; an error fails the frame with the error's text. Nil sends
	// without security.
	Seal func(dev string, tg *Telegram, p *Pending) (DownlinkSeal, error)
	// State is told each change of a frame's state (State*); detail says
	// more, or is empty. Nil records nothing.
	State func(dev string, p *Pending, state, detail string)
	// App reads the answer to an App request. keep says the request goes
	// on (it sent a following step), event is run with the other events.
	// Nil drops the request without an event.
	App func(dev string, p *Pending, tg *Telegram) (keep bool, event func())
	// LinkMode ("S2", "T2", "C2"), when set, times each frame into the
	// meter's response window (ResponseDelay): After waits until the
	// window's middle, counted from its call, less StickLatency (the
	// time the receiver took to deliver the telegram and will take to send
	// the frame). Empty sends at once, for sticks that time the answer
	// themselves.
	LinkMode     string
	StickLatency time.Duration
	// Wait sleeps (tests); nil is time.Sleep.
	Wait func(time.Duration)

	mu    sync.Mutex
	w     io.Writer
	queue map[string][]*Pending
	acc   byte
	fcb   map[string]bool
}

// SetWriter sets the receiver frames are written to (nil while it is not
// connected).
func (s *Scheduler) SetWriter(w io.Writer) {
	s.mu.Lock()
	s.w = w
	s.mu.Unlock()
}

// Transmit writes one CRC-less frame to the receiver with its framing.
func (s *Scheduler) Transmit(frame []byte) error {
	s.mu.Lock()
	w := s.w
	s.mu.Unlock()
	if w == nil {
		return errors.New("the receiver is not connected")
	}
	return s.write(w, frame)
}

func (s *Scheduler) write(w io.Writer, frame []byte) error {
	var err error
	if s.Framer == FramerIM871A {
		_, err = w.Write(EncodeIM871A(frame, s.WithL))
	} else {
		_, err = w.Write(EncodeAmber(frame, s.WithL))
	}
	return err
}

// Enqueue adds a frame to a meter's queue (dev names the meter).
func (s *Scheduler) Enqueue(dev string, p *Pending) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.queue == nil {
		s.queue = map[string][]*Pending{}
	}
	s.queue[dev] = append(s.queue[dev], p)
}

// Queued lists every meter's queue (copies of the lists, the same
// entries).
func (s *Scheduler) Queued() map[string][]*Pending {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]*Pending, len(s.queue))
	for dev, l := range s.queue {
		out[dev] = slices.Clone(l)
	}
	return out
}

func (s *Scheduler) state(dev string, p *Pending, state, detail string) func() {
	return func() {
		if s.State != nil {
			s.State(dev, p, state, detail)
		}
	}
}

// After runs after a meter's telegram: it settles the waiting frame a
// link-layer answer belongs to, passes application-layer answers to App,
// drops what timed out, and sends the meter's oldest queued frame when the
// telegram opens a receive window. direct is false for a telegram relayed
// by a repeater (hop bit H). It returns the state events in order, for the
// caller to run once it has recorded the queue.
func (s *Scheduler) After(dev string, tg *Telegram, direct bool) []func() {
	s.mu.Lock()
	list := s.queue[dev]
	w := s.w
	s.mu.Unlock()
	if len(list) == 0 {
		return nil
	}
	now := time.Now()
	// The waiting frame a link-layer answer settles.
	var target *Pending
	if tg.C&CPRM == 0 {
		for _, p := range list {
			if !p.Await || p.App != nil && p.Acked {
				continue
			}
			if p.App != nil && tg.C != CACK || p.App == nil && !Answers(p.Expect, tg.C) {
				continue
			}
			if tg.ELL != nil && p.Window && tg.ELL.ACC == p.ELLACC {
				target = p
				break
			}
			if target == nil {
				target = p
			}
		}
	}
	var keep []*Pending
	var events []func()
	for _, p := range list {
		switch {
		case p.App != nil && p.Await && p.App.AnsweredBy(tg):
			if s.App != nil {
				k, ev := s.App(dev, p, tg)
				if ev != nil {
					events = append(events, ev)
				}
				if k {
					p.Sent = now
					keep = append(keep, p)
				}
			}
			continue
		case p == target && p.App != nil:
			// Link-layer ACK; the application answer comes with the meter's
			// next response.
			p.Acked = true
			keep = append(keep, p)
			events = append(events, s.state(dev, p, StateAcknowledged, ""))
			continue
		case p == target:
			state, detail := StateAcknowledged, ""
			switch tg.C &^ (CFCB | CFCV) {
			case CRspUD:
				state, detail = StateAnswered, "RSP-UD; its data is written like any telegram"
			case CNACK:
				state, detail = StateRejected, "NACK: the meter refused the frame (buffer full, or SND-UD2 not supported)"
			}
			events = append(events, s.state(dev, p, state, detail))
			continue
		case p.Await && now.Sub(p.Sent) > s.Timeout:
			events = append(events, s.state(dev, p, StateUnacknowledged, "no answer from the meter"))
			continue
		case !p.Sent.IsZero() && !p.Await:
			continue // sent, and no answer is owed (SND-NKE, CNF-IR)
		case p.Sent.IsZero() && now.Sub(p.Queued) > s.Timeout:
			events = append(events, s.state(dev, p, StateExpired, "the meter opened no receive window in time"))
			continue
		}
		keep = append(keep, p)
	}
	// One frame per window, and none while one we sent still waits.
	var next *Pending
	for _, p := range keep {
		if p.Await && p.Window {
			next = nil
			break
		}
		if next == nil && p.Sent.IsZero() {
			next = p
		}
	}
	if p := next; p != nil && direct && w != nil {
		open := p.Frame.C == CCnfIR && tg.C == CSndIR ||
			p.Frame.C != CCnfIR && linkBidirectional(tg) && tg.C&CPRM != 0 // omsci.go
		if open {
			if d := s.responseWait(tg, now, time.Now()); d > 0 {
				if s.Wait != nil {
					s.Wait(d)
				} else {
					time.Sleep(d)
				}
			}
			ev, ok := s.send(dev, tg, p, w, now)
			if !ok {
				keep = slices.DeleteFunc(keep, func(x *Pending) bool { return x == p })
			}
			events = append(events, ev)
		}
	}
	keep = slices.DeleteFunc(keep, func(x *Pending) bool { return !x.Sent.IsZero() && !x.Await })
	s.mu.Lock()
	s.queue[dev] = keep
	s.mu.Unlock()
	return events
}

// send sends one queued frame in the window tg opened. It returns the
// state event and false when the frame failed (and leaves the queue).
func (s *Scheduler) send(dev string, tg *Telegram, p *Pending, w io.Writer, now time.Time) (func(), bool) {
	ellACC, tplACC := tg.ELL.ACCOr(0), tg.Access
	if p.Frame.C != CCnfIR {
		s.mu.Lock()
		s.acc++
		ellACC, tplACC = s.acc, s.acc
		if s.fcb == nil {
			s.fcb = map[string]bool{}
		}
		switch p.Frame.C {
		case CReqUD1, CReqUD2, CSndUD:
			if s.fcb[dev] {
				p.Frame.C |= CFCB
			}
			s.fcb[dev] = !s.fcb[dev]
		case CSndNKE:
			delete(s.fcb, dev)
		}
		s.mu.Unlock()
	}
	var sec DownlinkSeal
	if s.Seal != nil {
		var err error
		if sec, err = s.Seal(dev, tg, p); err != nil {
			return s.state(dev, p, StateFailed, err.Error()), false
		}
	}
	frame, err := EncodeDownlinkSealed(s.Gateway, tg.Meter, p.Frame, ellACC, tplACC, sec)
	if err == nil {
		err = s.write(w, frame)
	}
	if err != nil {
		return s.state(dev, p, StateFailed, err.Error()), false
	}
	p.Sent, p.Window, p.ELLACC = now, true, ellACC
	if p.Expect != ExpectNone {
		p.Await = true
	}
	p.Meter = tg.Meter
	return s.state(dev, p, StateSent, strings.ToUpper(hex.EncodeToString(frame))), true
}
