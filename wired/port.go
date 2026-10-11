package wired

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/goburrow/serial"
)

// OpenSerial opens a local serial port for an M-Bus level converter: 8
// data bits, even parity, 1 stop bit (EN 13757-2 5.4).
func OpenSerial(dev string, baud int) (io.ReadWriteCloser, error) {
	return serial.Open(&serial.Config{Address: dev, BaudRate: baud, DataBits: 8, StopBits: 1, Parity: "E", Timeout: 100 * time.Millisecond})
}

// DialTCP connects to a transparent serial-to-IP converter (which does
// the 8E1 UART framing itself), giving up after 10 s.
func DialTCP(ctx context.Context, address string) (io.ReadWriteCloser, error) {
	var d net.Dialer
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return d.DialContext(dctx, "tcp", address)
}

// Port turns a byte stream into ReadByte calls with a deadline. A reader
// goroutine feeds a channel, so serial read timeouts and TCP reads look
// the same.
type Port struct {
	rw       io.ReadWriteCloser
	in       chan []byte
	buf      []byte
	deadline time.Time
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	err      error
}

// ErrTimeout is what ReadByte returns after the deadline.
var ErrTimeout = errors.New("no answer within the timeout")

// NewPort reads rw in the background.
func NewPort(rw io.ReadWriteCloser) *Port {
	p := &Port{rw: rw, in: make(chan []byte, 64), done: make(chan struct{})}
	go p.read()
	return p
}

func (p *Port) read() {
	for {
		b := make([]byte, 256)
		n, err := p.rw.Read(b)
		if n > 0 {
			select {
			case p.in <- b[:n]:
			case <-p.done:
				return
			}
		}
		if err != nil {
			if errors.Is(err, serial.ErrTimeout) {
				continue
			}
			p.fail(err)
			return
		}
	}
}

func (p *Port) fail(err error) {
	p.mu.Lock()
	if p.err == nil {
		p.err = err
	}
	p.mu.Unlock()
	p.once.Do(func() { close(p.done) })
}

// Err is why the port stopped.
func (p *Port) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// Close ends the port.
func (p *Port) Close() error {
	p.fail(errors.New("closed"))
	return p.rw.Close()
}

// Write writes to the line; a failed write ends the port.
func (p *Port) Write(b []byte) (int, error) {
	select {
	case <-p.done:
		return 0, p.Err()
	default:
	}
	n, err := p.rw.Write(b)
	if err != nil {
		p.fail(err)
	}
	return n, err
}

// SetDeadline bounds the following ReadByte calls; zero waits forever.
func (p *Port) SetDeadline(t time.Time) { p.deadline = t }

// ReadByte returns the next byte, ErrTimeout after the deadline.
func (p *Port) ReadByte() (byte, error) {
	for len(p.buf) == 0 {
		var timer <-chan time.Time
		if !p.deadline.IsZero() {
			d := time.Until(p.deadline)
			if d <= 0 {
				select {
				case b := <-p.in:
					p.buf = b
					continue
				default:
					return 0, ErrTimeout
				}
			}
			t := time.NewTimer(d)
			defer t.Stop()
			timer = t.C
		}
		select {
		case b := <-p.in:
			p.buf = b
		case <-p.done:
			select {
			case b := <-p.in:
				p.buf = b
				continue
			default:
			}
			return 0, p.Err()
		case <-timer:
			return 0, ErrTimeout
		}
	}
	c := p.buf[0]
	p.buf = p.buf[1:]
	return c, nil
}

// Done is closed when the port stops (Err says why).
func (p *Port) Done() <-chan struct{} { return p.done }

// Drain discards whatever arrived so far (echoes, late answers).
func (p *Port) Drain() {
	p.buf = nil
	for {
		select {
		case <-p.in:
		default:
			return
		}
	}
}
