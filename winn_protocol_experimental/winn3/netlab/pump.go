package netlab

import (
	"errors"
	"fmt"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
)

// Duplex is two session.Drivers pumped by hand, with no goroutines and no
// carrier at all.
//
// Pair proves a property survives the real concurrency. Duplex proves what the
// property IS. The difference matters for exactly one class of question, and it
// is the class this lane was sent to answer: "the design tolerates half a
// window" is not a measurement, and no rig with a scheduler in it can turn it
// into one. Here the delivery order is a permutation the caller writes down, so
// the answer is a boundary rather than a distribution.
//
// The session driver is built for this: it holds no socket and no timer, takes
// an injected clock, and exposes Poll and Deliver. Nothing here reaches around
// the exported API.
type Duplex struct {
	Client  *session.Driver
	Gateway *session.Driver
	Clock   *StepClock

	// Window is the token window both ends were built with, which is both the
	// reordering tolerance and the burst-loss cliff.
	Window int

	// MaxMessageSize is what both sessions were built at.
	MaxMessageSize int
}

// DuplexConfig configures the exact rig.
type DuplexConfig struct {
	// TokenWindow sizes the receive window. Zero means core.DefaultTokenWindow.
	TokenWindow int

	// MaxMessageSize is the carrier ceiling. Zero means the plan floor for the
	// shipping [UDP, TCP, TLS] plan at carrier.DefaultPathMTU (1450), which is
	// 1338 — the same floor driver.NewSizing gives the Pair rig, derived from
	// the same constant so the two rigs cannot drift apart again. A literal
	// 1168 here would be the plan floor at 1280, a path no host may plan at
	// any more (driver.NewSizing refuses it), so this rig would be modelling a
	// session nothing ships.
	MaxMessageSize int

	// SendQueue bounds the inner-packet queue. Zero means the session default.
	SendQueue int

	// Tweak adjusts both configurations after the defaults are applied.
	Tweak func(*session.Config)
}

// NewDuplex builds the exact rig.
func NewDuplex(kr *Keyring, cfg DuplexConfig) (*Duplex, error) {
	clk := NewStepClock()
	size := cfg.MaxMessageSize
	if size == 0 {
		size = carrier.Floor(carrier.DefaultPathMTU, carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS)
	}
	base := func() session.Config {
		return session.Config{
			Core:           core.Config{Gateway: kr.Params, TokenWindow: cfg.TokenWindow},
			Padding:        core.PadBucket,
			MaxMessageSize: size,
			SendQueue:      cfg.SendQueue,
			Clock:          clk,
		}
	}
	ccfg := base()
	ccfg.Static = kr.ClientStatic
	ccfg.GatewayStatic = kr.GatewayPublic
	if cfg.Tweak != nil {
		cfg.Tweak(&ccfg)
	}
	cli, err := session.NewClient(ccfg)
	if err != nil {
		return nil, err
	}
	gcfg := base()
	gcfg.Static = kr.GatewayStatic
	gcfg.Accept = func([]byte) error { return nil }
	if cfg.Tweak != nil {
		cfg.Tweak(&gcfg)
	}
	gw, err := session.NewGateway(gcfg)
	if err != nil {
		return nil, err
	}
	win := cfg.TokenWindow
	if win == 0 {
		win = core.DefaultTokenWindow
	}
	return &Duplex{Client: cli, Gateway: gw, Clock: clk, Window: win, MaxMessageSize: size}, nil
}

// Drain empties one driver's outbox and returns the messages in the order the
// driver produced them, which is counter order.
func (d *Duplex) Drain(from *session.Driver) ([][]byte, error) {
	var out [][]byte
	for {
		msg, err := from.Poll()
		if err != nil {
			return out, err
		}
		if msg == nil {
			return out, nil
		}
		out = append(out, msg)
	}
}

// Deliver hands one message to a driver and returns the inner packets it
// carried.
func (d *Duplex) Deliver(to *session.Driver, msg []byte) ([][]byte, error) {
	return to.Deliver(msg)
}

// Exchange pumps both directions once and reports how many messages moved.
func (d *Duplex) Exchange() (int, error) {
	moved := 0
	c2g, err := d.Drain(d.Client)
	if err != nil {
		return moved, err
	}
	for _, m := range c2g {
		if _, err := d.Gateway.Deliver(m); err != nil {
			return moved, err
		}
		moved++
	}
	g2c, err := d.Drain(d.Gateway)
	if err != nil {
		return moved, err
	}
	for _, m := range g2c {
		if _, err := d.Client.Deliver(m); err != nil {
			return moved, err
		}
		moved++
	}
	return moved, nil
}

// Handshake pumps until both ends are established.
//
// When nothing moves it advances the injected clock to the earlier of the two
// next deadlines, which is how a hand-pumped rig drives a retransmission
// schedule without sleeping. A rig that advanced by a fixed step would either
// crawl or overshoot a probe budget.
func (d *Duplex) Handshake(rounds int) error {
	for i := 0; i < rounds; i++ {
		if d.Client.State() == session.StateEstablished &&
			d.Gateway.State() == session.StateEstablished {
			return nil
		}
		moved, err := d.Exchange()
		if err != nil {
			return err
		}
		if moved == 0 {
			d.advanceToDeadline()
		}
	}
	return fmt.Errorf("%w: handshake left client=%s gateway=%s (client err %v, gateway err %v)",
		ErrTimeout, d.Client.State(), d.Gateway.State(), d.Client.Err(), d.Gateway.Err())
}

// advanceToDeadline moves the clock to just past the earlier pending deadline.
func (d *Duplex) advanceToDeadline() {
	now := d.Clock.Now()
	var best time.Time
	for _, t := range []time.Time{d.Client.NextDeadline(), d.Gateway.NextDeadline()} {
		if t.IsZero() {
			continue
		}
		if best.IsZero() || t.Before(best) {
			best = t
		}
	}
	if best.IsZero() {
		d.Clock.Advance(time.Millisecond)
		return
	}
	if delta := best.Sub(now); delta > 0 {
		d.Clock.Advance(delta + time.Millisecond)
		return
	}
	d.Clock.Advance(time.Millisecond)
}

// Advance moves the injected clock.
func (d *Duplex) Advance(dur time.Duration) { d.Clock.Advance(dur) }

// Produce enqueues n inner packets on one driver and returns the sealed
// messages it emitted, in counter order.
//
// It deliberately returns the messages rather than delivering them: the whole
// point of this rig is that the caller decides the order they arrive in.
func (d *Duplex) Produce(from *session.Driver, n, payload int) ([][]byte, error) {
	var out [][]byte
	for i := 0; i < n; i++ {
		buf := make([]byte, payload)
		for j := range buf {
			buf[j] = byte(i*17 + j)
		}
		if err := from.Enqueue(buf); err != nil {
			return out, err
		}
		msgs, err := d.Drain(from)
		if err != nil {
			return out, err
		}
		if len(msgs) == 0 {
			return out, fmt.Errorf("%w: driver produced nothing for inner packet %d", ErrPumpStalled, i)
		}
		out = append(out, msgs...)
	}
	return out, nil
}

// ErrPumpStalled reports that a hand-pumped driver produced nothing when it
// should have.
var ErrPumpStalled = errors.New("winn3/netlab: pumped driver produced no message")

// DeliverPermuted delivers msgs in the order given by perm and reports how many
// carried at least one inner packet through.
//
// A message that does not open returns no packets AND no error — that is the
// session layer's deliberate discipline, since an unopenable message is noise,
// a scan, a replay or the far side of a desynchronisation and the four are
// indistinguishable by construction. So "opened" here is measured by what came
// out, which is the only thing a caller can observe.
func (d *Duplex) DeliverPermuted(to *session.Driver, msgs [][]byte, perm []int) (delivered int, err error) {
	for _, i := range perm {
		inner, err := to.Deliver(msgs[i])
		if err != nil {
			return delivered, err
		}
		delivered += len(inner)
	}
	return delivered, nil
}

// DisplacedOrder builds a permutation in which the message at index `at` is
// delivered exactly `distance` places late and everything else is in order.
//
// This is the exact instrument for the force-advance rule. With a window of
// 256 the rule retires the low edge to `counter - 128 + 1` on consuming
// `counter`, so a message displaced by `distance` is still inside the window
// while `distance <= 127` and is gone at 128. A shuffling generator could not
// tell those two apart.
func DisplacedOrder(n, at, distance int) []int {
	perm := make([]int, 0, n)
	for i := 0; i < n; i++ {
		if i == at {
			continue
		}
		perm = append(perm, i)
		if i == at+distance {
			perm = append(perm, at)
		}
	}
	if len(perm) < n {
		perm = append(perm, at)
	}
	return perm
}
