package driver

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// backoffEvent is one entry in the ordered record shared by the carrier and the
// clock below: a carrier presentation or a backoff timer being built.
type backoffEvent struct {
	backoff bool
	at      time.Time
	payload [][]byte
}

type backoffLog struct {
	mu     sync.Mutex
	events []backoffEvent
}

func (g *backoffLog) add(e backoffEvent) {
	g.mu.Lock()
	g.events = append(g.events, e)
	g.mu.Unlock()
}

func (g *backoffLog) snapshot() []backoffEvent {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]backoffEvent(nil), g.events...)
}

// backoffClock is the system clock, recording every carrierDrainBackoff timer.
type backoffClock struct{ log *backoffLog }

func (backoffClock) Now() time.Time { return time.Now() }

func (c backoffClock) NewTimer(d time.Duration) Timer {
	if d == carrierDrainBackoff {
		c.log.add(backoffEvent{backoff: true, at: time.Now()})
	}
	return SystemClock{}.NewTimer(d)
}

// fullBatchShortCarrier passes traffic through, except that once armed it holds
// its first send long enough for the outbox to fill, then answers the first
// full txCarrierBatchSize presentation with `accept` messages and nil error.
// Every armed presentation from that one on is recorded.
type fullBatchShortCarrier struct {
	*throttleCarrier
	accept int
	log    *backoffLog

	mu      sync.Mutex
	held    bool
	refused bool
	fired   chan struct{}
}

func (c *fullBatchShortCarrier) SendBatch(ctx context.Context, msgs []carrier.BatchMsg) (int, error) {
	if !c.armed.Load() {
		return c.inner.SendBatch(ctx, msgs)
	}
	c.mu.Lock()
	if !c.held {
		c.held = true
		c.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
		return c.inner.SendBatch(ctx, msgs)
	}
	refuse := !c.refused && len(msgs) == txCarrierBatchSize
	recording := c.refused || refuse
	if refuse {
		c.refused = true
	}
	c.mu.Unlock()
	if recording {
		p := make([][]byte, len(msgs))
		for k, m := range msgs {
			p[k] = append([]byte(nil), m.Payload[:m.N]...)
		}
		c.log.add(backoffEvent{at: time.Now(), payload: p})
	}
	if !refuse {
		return c.inner.SendBatch(ctx, msgs)
	}
	if c.accept > 0 {
		if _, err := c.inner.SendBatch(ctx, msgs[:c.accept]); err != nil {
			return 0, err
		}
	}
	close(c.fired)
	return c.accept, nil
}

// A full batch answered short with nil error must reach its retry only through
// the backoff, and the retry must present exactly the retained suffix.
func TestAFullBatchShortResultWithNoErrorRetriesOnlyAfterTheBackoff(t *testing.T) {
	t.Run("zero accepted", func(t *testing.T) { runFullBatchShortCase(t, 0) })
	t.Run("one accepted", func(t *testing.T) { runFullBatchShortCase(t, 1) })
}

func runFullBatchShortCase(t *testing.T, accept int) {
	krGw, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	krCli, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := core.NewPublicKey(krGw.Public())
	if err != nil {
		t.Fatal(err)
	}
	admission := make([]byte, 32)
	for i := range admission {
		admission[i] = byte(i*11 + 3)
	}
	params := core.GatewayParams{AdmissionKeys: [][]byte{admission}, GatewayID: []byte("winn3-backoff")}
	sz, err := NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	cliDev := newFloodDevice(sz.InnerMTU, 1<<13)
	gwDev := newFloodDevice(sz.InnerMTU, 1<<13)
	cliCar, gwCarUDP := loopbackUDPPair(t)
	log := &backoffLog{}
	gwCar := &fullBatchShortCarrier{throttleCarrier: newThrottle(gwCarUDP), accept: accept, log: log, fired: make(chan struct{})}

	cliLoop, err := NewClient(Config{
		Session: session.Config{Core: core.Config{Gateway: params}, Static: krCli, GatewayStatic: pub, Padding: core.PadBucket},
		Sizing:  sz, Carrier: cliCar,
		Tun: &tun.Config{Assign: tun.Assignment{V4: clientAddr(), RouterV4: gatewayAddr()}, Device: cliDev},
	})
	if err != nil {
		t.Fatal(err)
	}
	gwLoop, err := NewGateway(Config{
		Session: session.Config{Core: core.Config{Gateway: params}, Static: krGw, Accept: func([]byte) error { return nil }, Padding: core.PadBucket},
		Sizing:  sz, Carrier: gwCar,
		Tun:   &tun.Config{Assign: tun.Assignment{V4: gatewayAddr(), RouterV4: clientAddr()}, Device: gwDev},
		Clock: backoffClock{log: log},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer cliLoop.Close()
	defer gwLoop.Close()
	go func() { _ = cliLoop.Run(ctx) }()
	go func() { _ = gwLoop.Run(ctx) }()

	deadline := time.Now().Add(10 * time.Second)
	for !cliLoop.Carrying() || !gwLoop.Carrying() {
		if time.Now().After(deadline) {
			t.Fatal("tunnel did not reach carrying state")
		}
		time.Sleep(time.Millisecond)
	}

	pkt := ipv4Packet(gatewayAddr(), clientAddr(), make([]byte, sz.InnerMTU-28))
	gwCar.armed.Store(true)
	for i := 0; i < 4096; i++ {
		gwDev.offer(pkt)
	}
	select {
	case <-gwCar.fired:
	case <-time.After(10 * time.Second):
		t.Fatal("no full batch was presented while the outbox was full")
	}

	// Wait for the retry presentation.
	var events []backoffEvent
	deadline = time.Now().Add(5 * time.Second)
	for {
		events = events[:0]
		presentations := 0
		for _, e := range log.snapshot() {
			if !e.backoff && e.payload != nil {
				presentations++
			}
			events = append(events, e)
		}
		if presentations >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the retained suffix was never re-presented")
		}
		time.Sleep(time.Millisecond)
	}

	first, second := -1, -1
	for k, e := range events {
		if e.backoff {
			continue
		}
		if first < 0 {
			first = k
		} else {
			second = k
			break
		}
	}
	var backoffAt time.Time
	for _, e := range events[first+1 : second] {
		if e.backoff {
			backoffAt = e.at
			break
		}
	}
	if backoffAt.IsZero() {
		t.Fatalf("accept=%d: the retained suffix was re-presented %v after the short result with no backoff timer between",
			accept, events[second].at.Sub(events[first].at))
	}
	if gap := events[second].at.Sub(backoffAt); gap < carrierDrainBackoff {
		t.Fatalf("accept=%d: retry %v after the backoff timer was built, before it could fire (%v)", accept, gap, carrierDrainBackoff)
	}
	want := events[first].payload[accept:]
	got := events[second].payload
	if len(got) != len(want) {
		t.Fatalf("accept=%d: retry presented %d messages, want the %d retained", accept, len(got), len(want))
	}
	for k := range want {
		if !bytes.Equal(got[k], want[k]) {
			t.Fatalf("accept=%d: retry message %d is not the retained ciphertext verbatim", accept, k)
		}
	}
}
