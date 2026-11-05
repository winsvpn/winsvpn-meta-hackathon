package driver

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
)

func quietBackpressure(c *session.Config) {
	h := time.Hour
	c.Silence = session.Draw{Min: h, Mean: 2 * h, Max: 3 * h}
	c.Probe = session.Draw{Min: h, Mean: 2 * h, Max: 3 * h}
	c.RekeyInterval = session.Draw{Min: h, Mean: 2 * h, Max: 3 * h}
	c.MaxLostProbes = 1 << 20
	c.RekeyAfterBytes = 1 << 60
}

// holdSend blocks Send after the test arms it, so the write loop can be parked
// inside drain with a message already Poll'd out of the session queue.
type holdSend struct {
	carrier.Conn
	holding atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func newHoldSend(c carrier.Conn) *holdSend {
	return &holdSend{
		Conn:    c,
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
}

func (h *holdSend) arm() { h.holding.Store(true) }

func (h *holdSend) Send(ctx context.Context, msg []byte) error {
	if h.holding.Load() {
		select {
		case h.entered <- struct{}{}:
		default:
		}
		select {
		case <-h.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return h.Conn.Send(ctx, msg)
}

// queueFullSend counts carrier.ErrQueueFull on the client Send path. In a
// Pipe pair, client Send IS peer Deliver, so this is how a full peer inbox
// appears on this side of the seam. Production UDP is worse: the write
// succeeds and only the gateway's RecvErrors move. See the handoff.
type queueFullSend struct {
	carrier.Conn
	full atomic.Uint64
}

func (q *queueFullSend) Send(ctx context.Context, msg []byte) error {
	err := q.Conn.Send(ctx, msg)
	if errors.Is(err, carrier.ErrQueueFull) {
		q.full.Add(1)
	}
	return err
}

// TestAFullPeerInboxIsRetransmittedNotDropped pins the corrected backpressure
// contract in the Established data phase.
//
// A full carrier inbox refuses messages drain() has already SEALED (their
// transport nonce is spent). Discarding them there was the defect behind the
// one-way blackhole: once the send counter runs a full token window ahead of
// what the peer received, the peer's receive window is stranded permanently.
// Inner TCP cannot recover that, because the whole receive DIRECTION is dead,
// not a few packets. So the driver now HOLDS the refused sealed messages and
// retransmits the identical bytes (nonce-safe) once the inbox drains, and stops
// sealing new ones until then. tun.Outbound still counted TxPackets; the session
// stays established and the gate stays carrying; TxDroppedSink stays 0. The
// difference from the old contract: the bytes are delivered rather than silently
// lost. See loop.drain's txPending and TestDownloadBackpressureDoesNotStrandTheReceiveWindow.
func TestAFullPeerInboxIsRetransmittedNotDropped(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	const pipeDepth = 16
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{
		Class: carrier.ClassUDP, Depth: pipeDepth,
	})
	if err != nil {
		t.Fatal(err)
	}
	counted := &queueFullSend{Conn: cliCar}
	tweak := func(c *session.Config) {
		quietBackpressure(c)
		c.SendQueue = 4096
	}
	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: counted, local: clientAddr(), router: gatewayAddr(), tweak: tweak,
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, local: gatewayAddr(), router: clientAddr(), tweak: tweak,
	})
	defer cli.stop()
	defer gw.stop()

	cli.start(ctx)
	gw.start(ctx)
	cli.waitState(session.StateEstablished, 15*time.Second)
	waitFor(t, 10*time.Second, "the client gate to carry", func() bool {
		return cli.loop.Carrying()
	})
	waitFor(t, 10*time.Second, "the gateway gate to carry", func() bool {
		return gw.loop.Carrying()
	})

	// Park the gateway reader inside Inbound's device write so Recv stops
	// draining the inbox. Release MUST run before cancel: Gate.Set waits for
	// the enter() hold that Inbound is holding across the blocked write.
	gw.dev.block.Store(true)
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		gw.dev.block.Store(false)
		close(gw.dev.release)
	}
	defer release()

	const flood = 40
	// One inner packet per transport message. Coalescing 40 tiny payloads into
	// one Send would occupy a single inbox slot and never fill the pipe.
	body := make([]byte, sz.InnerMTU-20)
	markers := make([]byte, flood)
	for i := 0; i < flood; i++ {
		markers[i] = byte(i + 1)
		body[0] = markers[i]
		pkt := ipv4Packet(clientAddr(), gatewayAddr(), body)
		if err := cli.loop.Tunnel().Outbound(pkt); err != nil {
			t.Fatalf("Outbound %d: %v (SendQueue is 4096; Enqueue must not be the bound)", i, err)
		}
	}

	waitFor(t, 10*time.Second, "the gateway write to block", func() bool {
		select {
		case <-gw.dev.writing:
			return true
		default:
			return false
		}
	})
	waitFor(t, 10*time.Second, "client Send to see ErrQueueFull", func() bool {
		return counted.full.Load() >= 1
	})

	st := cli.loop.Tunnel().Stats()
	if st.TxPackets != uint64(flood) {
		t.Fatalf("TxPackets=%d, want %d: every Outbound returned nil, so the tun layer counted a send",
			st.TxPackets, flood)
	}
	if st.TxDroppedSink != 0 {
		t.Fatalf("TxDroppedSink=%d, want 0: Enqueue succeeded; a host watching only this counter sees a healthy tunnel",
			st.TxDroppedSink)
	}
	if st.TxDroppedClosed != 0 {
		t.Fatalf("TxDroppedClosed=%d, want 0: the gate was carrying", st.TxDroppedClosed)
	}
	// Corrected contract: a transient full inbox is NOT a silent send-path drop.
	// The refused sealed messages are held for retransmission, so SendFailed does
	// not move for them.
	if got := cli.loop.Stats().SendFailed; got != 0 {
		t.Fatalf("SendFailed=%d; a transient full inbox must be retransmitted, not discarded", got)
	}
	if cli.loop.Session().State() != session.StateEstablished {
		t.Fatalf("session is %s; a full inbox must not tear the session down", cli.loop.Session().State())
	}
	if !cli.loop.Carrying() {
		t.Fatal("the gate closed; a transient full inbox must leave the tunnel looking up")
	}

	release()

	arrived := map[byte]int{}
	deadline := time.Now().Add(5 * time.Second)
	for len(arrived) < flood && time.Now().Before(deadline) {
		select {
		case p := <-gw.dev.out:
			pl := payloadOf(p)
			if len(pl) > 0 {
				arrived[pl[0]]++
			}
		case <-time.After(20 * time.Millisecond):
		}
	}
	// Every marker must arrive: the driver retransmitted the sealed-but-unsent
	// messages once the inbox drained, so nothing the tun layer counted as sent
	// is silently lost. This is exactly what stops the send counter from racing
	// past the peer's token window and stranding its receive window.
	missing := 0
	for i := 0; i < flood; i++ {
		if arrived[markers[i]] == 0 {
			missing++
		}
	}
	if missing != 0 {
		t.Fatalf("%d of %d markers never arrived; the driver dropped sealed messages instead of retransmitting them", missing, flood)
	}
}

// TestAFullSendQueueDropsThroughTheOpenGateAsTxDroppedSink pins the other
// valve: when Poll cannot keep up (Send is parked, not failing), Enqueue
// returns session.ErrQueueFull and tun counts TxDroppedSink. The refused
// packet never reaches the peer. The gate stays carrying.
//
// TestSendQueueIsBounded covers Enqueue alone. TestSinkRefusalIsNotCountedAsSent
// covers a fake sink error. Neither drives a real session.ErrQueueFull through
// Tunnel.Outbound while the session is established.
func TestAFullSendQueueDropsThroughTheOpenGateAsTxDroppedSink(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	held := newHoldSend(cliCar)
	const queue = 4
	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: held, local: clientAddr(), router: gatewayAddr(),
		tweak: func(c *session.Config) {
			quietBackpressure(c)
			c.SendQueue = queue
		},
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, local: gatewayAddr(), router: clientAddr(),
		tweak: quietBackpressure,
	})
	defer cli.stop()
	defer gw.stop()

	cli.start(ctx)
	gw.start(ctx)
	cli.waitState(session.StateEstablished, 15*time.Second)
	waitFor(t, 10*time.Second, "the client gate to carry", func() bool {
		return cli.loop.Carrying()
	})

	held.arm()
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		close(held.release)
	}
	defer release()

	first := ipv4Packet(clientAddr(), gatewayAddr(), []byte("first"))
	if err := cli.loop.Tunnel().Outbound(first); err != nil {
		t.Fatalf("the first Outbound under an open gate: %v", err)
	}
	select {
	case <-held.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("write loop never entered the held Send; Poll did not take the first packet")
	}

	accepted := 1
	for i := 0; i < queue+8; i++ {
		pkt := ipv4Packet(clientAddr(), gatewayAddr(), []byte{byte('q'), byte(i)})
		err := cli.loop.Tunnel().Outbound(pkt)
		if errors.Is(err, session.ErrQueueFull) {
			t.Fatalf("queue filled before the dedicated overflow packet; slot %d: %v", i, err)
		}
		if err != nil {
			t.Fatalf("filling slot %d: %v", i, err)
		}
		accepted++
		if accepted >= 1+queue {
			break
		}
	}

	dropped := ipv4Packet(clientAddr(), gatewayAddr(), []byte("DROPPED"))
	if err := cli.loop.Tunnel().Outbound(dropped); !errors.Is(err, session.ErrQueueFull) {
		t.Fatalf("the overflow Outbound returned %v, want session.ErrQueueFull", err)
	}
	st := cli.loop.Tunnel().Stats()
	if st.TxDroppedSink != 1 {
		t.Fatalf("TxDroppedSink=%d, want 1", st.TxDroppedSink)
	}
	if st.TxDroppedClosed != 0 {
		t.Fatalf("TxDroppedClosed=%d, want 0: this is a queue drop, not a closed gate", st.TxDroppedClosed)
	}
	if st.TxPackets != uint64(accepted) {
		t.Fatalf("TxPackets=%d, want %d (the accepted packets, not the refused one)", st.TxPackets, accepted)
	}
	if cli.loop.Session().State() != session.StateEstablished {
		t.Fatalf("session is %s after a queue-full drop", cli.loop.Session().State())
	}
	if !cli.loop.Carrying() {
		t.Fatal("the gate closed on a queue-full drop")
	}

	release()

	deadline := time.Now().Add(5 * time.Second)
	sawDropped := false
	sawFirst := false
	for time.Now().Before(deadline) {
		select {
		case p := <-gw.dev.out:
			pl := payloadOf(p)
			if string(pl) == "DROPPED" {
				sawDropped = true
			}
			if string(pl) == "first" {
				sawFirst = true
			}
		case <-time.After(20 * time.Millisecond):
		}
	}
	if sawDropped {
		t.Fatal("the overflow payload reached the gateway; ErrQueueFull did not drop it")
	}
	if !sawFirst {
		t.Fatal("the first packet never arrived after release; the hold broke the path rather than filling the queue")
	}
}
