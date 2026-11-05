package driver

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// throttleCarrier wraps a real BatchCarrier and models a send socket that can
// only drain a trickle: while armed, SendBatch accepts `passPerCall` datagrams
// and REFUSES the rest (partial success, err==nil), which is EWOULDBLOCK on a
// full UDP send buffer. loop.drain has already SEALED the whole accumulated
// batch (advancing the nonce counter) before it calls SendBatch, so every
// refused datagram is a sealed message the driver discards and can never
// re-send (re-sealing would reuse a nonce). This is the "messages sealed under
// the new epoch but never put on the wire" the production defect is built from.
type throttleCarrier struct {
	inner interface {
		carrier.Conn
		carrier.BatchCarrier
	}
	armed         atomic.Bool
	passPerCall   atomic.Int64
	discarded     atomic.Uint64
	discardTarget atomic.Int64
}

func newThrottle(inner *carrier.UDP) *throttleCarrier {
	return &throttleCarrier{inner: inner}
}

func (c *throttleCarrier) Send(ctx context.Context, msg []byte) error { return c.inner.Send(ctx, msg) }
func (c *throttleCarrier) Recv(ctx context.Context) ([]byte, error)   { return c.inner.Recv(ctx) }
func (c *throttleCarrier) MaxMessageSize() int                        { return c.inner.MaxMessageSize() }
func (c *throttleCarrier) Close() error                               { return c.inner.Close() }
func (c *throttleCarrier) Class() carrier.Class                       { return c.inner.Class() }
func (c *throttleCarrier) SetMaxMessageSize(n int) error              { return c.inner.SetMaxMessageSize(n) }
func (c *throttleCarrier) Stats() carrier.Stats                       { return c.inner.Stats() }
func (c *throttleCarrier) RecvBatch(ctx context.Context, m []carrier.BatchMsg) (int, error) {
	return c.inner.RecvBatch(ctx, m)
}

func (c *throttleCarrier) SendBatch(ctx context.Context, msgs []carrier.BatchMsg) (int, error) {
	if !c.armed.Load() {
		return c.inner.SendBatch(ctx, msgs)
	}
	// Refuse the whole batch (EWOULDBLOCK on a full send buffer): report 0 sent,
	// no error. loop.drain has already sealed these messages (nonce counter
	// advanced) and now discards them. Self-clear once the discarded run exceeds
	// the target so the stall is bounded to a handful of hot-loop iterations,
	// well under driver.maxSpins.
	d := c.discarded.Add(uint64(len(msgs)))
	if int64(d) >= c.discardTarget.Load() {
		c.armed.Store(false)
	}
	return 0, nil
}

// TestDownloadBackpressureDoesNotStrandTheReceiveWindow reproduces the production
// blackhole end to end: a sustained download into a send socket that can only
// trickle. The driver keeps sealing (advancing the send counter) and discarding
// the sealed-but-unsent messages, so the send counter races more than a full
// receive window (1024) ahead of what the client ever receives. From then on
// EVERY gateway datagram is out of the client's token window: the client counts
// them all unopenable while both ends remain Established at the SAME epoch, so
// the gateway still opens the client. Exactly the measured signature.
func TestDownloadBackpressureDoesNotStrandTheReceiveWindow(t *testing.T) {
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
		admission[i] = byte(i*13 + 3)
	}
	params := core.GatewayParams{AdmissionKeys: [][]byte{admission}, GatewayID: []byte("winn3-backpressure")}
	sz, err := NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}

	const ringDepth = 1 << 16
	cliDev := newFloodDevice(sz.InnerMTU, ringDepth)
	gwDev := newFloodDevice(sz.InnerMTU, ringDepth)
	cliCar, gwCarUDP := loopbackUDPPair(t)
	gwCar := newThrottle(gwCarUDP)

	cliLoop, err := NewClient(Config{
		Session: session.Config{Core: core.Config{Gateway: params}, Static: krCli, GatewayStatic: pub, Padding: core.PadBucket, SendQueue: 1 << 15},
		Sizing:  sz, Carrier: cliCar,
		Tun: &tun.Config{Assign: tun.Assignment{V4: clientAddr(), RouterV4: gatewayAddr()}, Device: cliDev},
	})
	if err != nil {
		t.Fatal(err)
	}
	gwLoop, err := NewGateway(Config{
		Session: session.Config{Core: core.Config{Gateway: params}, Static: krGw, Accept: func([]byte) error { return nil }, Padding: core.PadBucket, SendQueue: 1 << 15},
		Sizing:  sz, Carrier: gwCar,
		Tun: &tun.Config{Assign: tun.Assignment{V4: gatewayAddr(), RouterV4: clientAddr()}, Device: gwDev},
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

	payload := make([]byte, sz.InnerMTU-28)
	pkt := ipv4Packet(gatewayAddr(), clientAddr(), payload)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			gwDev.offer(pkt)
		}
	}()
	defer close(stop)

	// Let a healthy download run first.
	warmDeadline := time.Now().Add(3 * time.Second)
	for cliDev.took.Load() < 3000 && time.Now().Before(warmDeadline) {
		time.Sleep(2 * time.Millisecond)
	}
	healthy := cliDev.took.Load()
	if healthy < 500 {
		t.Fatalf("download never got healthy: delivered=%d", healthy)
	}

	// Now the send socket refuses (EWOULDBLOCK) for a contiguous run of sealed
	// messages larger than one full receive window (1024), then recovers. The
	// throttle self-clears at the target so the stall is only a few hot-loop
	// iterations (far under driver.maxSpins=4096).
	gwCar.discardTarget.Store(2048)
	gwCar.armed.Store(true)
	throttleDeadline := time.Now().Add(4 * time.Second)
	for gwCar.armed.Load() && time.Now().Before(throttleDeadline) {
		time.Sleep(1 * time.Millisecond)
	}
	gwCar.armed.Store(false)

	// Give the recovered socket time to deliver: if the window is NOT stranded,
	// delivery resumes; if it is, every datagram stays unopenable.
	recoverBase := cliDev.took.Load()
	time.Sleep(2 * time.Second)
	deliveredAfterRecover := cliDev.took.Load() - recoverBase

	cliSt := cliLoop.Session().Stats()
	gwSt := gwLoop.Session().Stats()
	t.Logf("healthy=%d discarded=%d deliveredAfterRecover=%d cliUnopenable=%d gwUnopenable=%d "+
		"epochs(cli=%d gw=%d) states(cli=%s gw=%s) carrying(cli=%v gw=%v)",
		healthy, gwCar.discarded.Load(), deliveredAfterRecover, cliSt.Unopenable, gwSt.Unopenable,
		cliLoop.Session().Epoch(), gwLoop.Session().Epoch(),
		cliLoop.Session().State(), gwLoop.Session().State(),
		cliLoop.Carrying(), gwLoop.Carrying())

	if cliLoop.Session().Epoch() != gwLoop.Session().Epoch() {
		t.Fatalf("epochs diverged (%d vs %d); this test targets the same-epoch window strand, not an epoch desync",
			cliLoop.Session().Epoch(), gwLoop.Session().Epoch())
	}
	// The defect: after the socket recovered, the client receives datagrams but
	// can open NONE of them (window stranded), so delivery does not resume.
	if deliveredAfterRecover < 500 {
		t.Fatalf("BLACKHOLE REPRODUCED: after the send socket recovered the client delivered only %d packets; "+
			"the receive window is stranded (cliUnopenable=%d, gwUnopenable=%d, both Established at epoch %d). "+
			"loop.drain sealed and discarded %d messages under backpressure, racing the send counter past the client's token window.",
			deliveredAfterRecover, cliSt.Unopenable, gwSt.Unopenable, cliLoop.Session().Epoch(), gwCar.discarded.Load())
	}
}
