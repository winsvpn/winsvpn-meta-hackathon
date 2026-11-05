package driver

import (
	"context"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
)

// uplinkWire stands between the client carrier and the gateway carrier. It
// passes messages through, or swaps the next two, drops the next one, or
// blocks every send until released, so a test can make the outer flow do on
// purpose what a real path may do to it.
type uplinkWire struct {
	mu       sync.Mutex
	dst      *carrier.Pipe
	mode     string // "pass", "swap", "drop", "block"
	held     []byte
	seen     int
	released chan struct{}
}

func (w *uplinkWire) set(mode string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.mode, w.seen = mode, 0
	if mode == "block" {
		w.released = make(chan struct{})
	}
}

func (w *uplinkWire) release() {
	w.mu.Lock()
	ch := w.released
	w.mode, w.released = "pass", nil
	w.mu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (w *uplinkWire) holding() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.held != nil
}

func (w *uplinkWire) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seen
}

func (w *uplinkWire) out(msg []byte) error {
	cp := append([]byte(nil), msg...)
	w.mu.Lock()
	w.seen++
	switch w.mode {
	case "swap":
		if w.held == nil {
			w.held = cp
			w.mu.Unlock()
			return nil
		}
		held := w.held
		w.held, w.mode = nil, "pass"
		w.mu.Unlock()
		if err := w.dst.Deliver(cp); err != nil {
			return err
		}
		return w.dst.Deliver(held)
	case "drop":
		w.mode = "pass"
		w.mu.Unlock()
		return nil
	case "block":
		ch := w.released
		w.mu.Unlock()
		<-ch
		return w.dst.Deliver(cp)
	}
	w.mu.Unlock()
	return w.dst.Deliver(cp)
}

// TestOuterFlowAndQueueDepthReachLoopStatsOnTheRealPath drives the client to
// gateway direction through Pipe, readLoop, session.DeliverBatch and the
// gateway device, then reads Loop.Stats, which is what both status documents
// publish. A swapped pair is one outer reordering and no loss, and still
// reaches the gateway device in arrival order (the tunnel has no reorder
// buffer). A dropped message is one loss and no reordering. A blocked send
// leaves inner packets in the client's send queue, and Loop.Stats reports
// that depth while it stands.
func TestOuterFlowAndQueueDepthReachLoopStatsOnTheRealPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	clk := newStepClock()

	// Client sends cross the wire; gateway sends go straight to the client.
	wire := &uplinkWire{mode: "pass"}
	cliCar, err := carrier.NewPipe(carrier.PipeConfig{
		Class: carrier.ClassUDP, PathMTU: carrier.DefaultPathMTU, Out: wire.out,
	})
	if err != nil {
		t.Fatal(err)
	}
	gwCar, err := carrier.NewPipe(carrier.PipeConfig{
		Class: carrier.ClassUDP, PathMTU: carrier.DefaultPathMTU, Out: cliCar.Deliver,
	})
	if err != nil {
		t.Fatal(err)
	}
	wire.dst = gwCar

	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar, clock: clk,
		local: clientAddr(), router: gatewayAddr(),
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, clock: clk,
		local: gatewayAddr(), router: clientAddr(),
	})
	defer cli.stop()
	defer gw.stop()
	defer wire.release()

	cli.start(ctx)
	gw.start(ctx)
	cli.waitState(session.StateEstablished, 15*time.Second)
	gw.waitState(session.StateEstablished, 15*time.Second)
	waitFor(t, 5*time.Second, "both gates carrying", func() bool {
		return cli.loop.Carrying() && gw.loop.Carrying()
	})
	gw.dev.offer(t, ipv4Packet(gatewayAddr(), clientAddr(), []byte("device-proof")))
	_ = cli.dev.take(t, 10*time.Second)
	cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), []byte("baseline")))
	_ = gw.dev.take(t, 10*time.Second)

	agree := func(when string) session.Stats {
		t.Helper()
		ss := gw.loop.Session().Stats()
		ls := gw.loop.Stats()
		if ls.OuterReordered != ss.OuterReordered || ls.OuterLost != ss.OuterLost {
			t.Fatalf("%s: Loop.Stats reordered %d lost %d, session.Stats %d and %d; the published snapshot does not carry them",
				when, ls.OuterReordered, ls.OuterLost, ss.OuterReordered, ss.OuterLost)
		}
		if ls.OuterReorderDepth != ss.OuterReorderDepth {
			t.Fatalf("%s: Loop.Stats depth %v, session.Stats %v", when, ls.OuterReorderDepth, ss.OuterReorderDepth)
		}
		return ss
	}
	before := agree("baseline")

	// Swap: "first" is held on the wire, "second" overtakes it.
	wire.set("swap")
	cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), []byte("first")))
	waitFor(t, 5*time.Second, "the wire to hold the first message", wire.holding)
	cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), []byte("second")))
	if got := string(payloadOf(gw.dev.take(t, 10*time.Second))); got != "second" {
		t.Fatalf("the gateway device got %q first, want the overtaking %q", got, "second")
	}
	if got := string(payloadOf(gw.dev.take(t, 10*time.Second))); got != "first" {
		t.Fatalf("the gateway device got %q second, want %q", got, "first")
	}
	swapped := agree("after the swap")
	if swapped.OuterReordered != before.OuterReordered+1 || swapped.OuterLost != before.OuterLost {
		t.Fatalf("after one swap: reordered %d to %d, lost %d to %d; want +1 and +0",
			before.OuterReordered, swapped.OuterReordered, before.OuterLost, swapped.OuterLost)
	}
	// "first" landed one counter below "second": displacement 1, bucket 0.
	wantDepth := before.OuterReorderDepth
	wantDepth[0]++
	if swapped.OuterReorderDepth != wantDepth {
		t.Fatalf("after one adjacent swap the depth is %v, want %v", swapped.OuterReorderDepth, wantDepth)
	}

	// Drop: "lost" never arrives; "after-loss" does.
	wire.set("drop")
	cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), []byte("lost")))
	waitFor(t, 5*time.Second, "the wire to drop one message", func() bool { return wire.count() >= 1 })
	cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), []byte("after-loss")))
	if got := string(payloadOf(gw.dev.take(t, 10*time.Second))); got != "after-loss" {
		t.Fatalf("the gateway device got %q, want %q", got, "after-loss")
	}
	dropped := agree("after the drop")
	if dropped.OuterReordered != swapped.OuterReordered || dropped.OuterLost != swapped.OuterLost+1 {
		t.Fatalf("after one drop: reordered %d to %d, lost %d to %d; want +0 and +1",
			swapped.OuterReordered, dropped.OuterReordered, swapped.OuterLost, dropped.OuterLost)
	}

	// Block: the client's write loop sits in the carrier send, so later inner
	// packets stand in its session send queue.
	wire.set("block")
	cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), []byte("stuck")))
	waitFor(t, 5*time.Second, "the write loop to block in the carrier", func() bool { return wire.count() >= 1 })
	for _, p := range []string{"queued-1", "queued-2"} {
		cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), []byte(p)))
	}
	waitFor(t, 5*time.Second, "two packets standing in the client send queue", func() bool {
		return cli.loop.Session().Stats().DataQueueDepth >= 2
	})
	if ls, ss := cli.loop.Stats(), cli.loop.Session().Stats(); ls.DataQueueDepth != ss.DataQueueDepth || ls.DataQueueDepth < 2 {
		t.Fatalf("Loop.Stats send queue depth %d, session %d; want the same standing backlog of at least 2",
			ls.DataQueueDepth, ss.DataQueueDepth)
	}
	wire.release()
	for _, want := range []string{"stuck", "queued-1", "queued-2"} {
		if got := string(payloadOf(gw.dev.take(t, 10*time.Second))); got != want {
			t.Fatalf("after the release the gateway device got %q, want %q", got, want)
		}
	}
	waitFor(t, 5*time.Second, "the client send queue to drain", func() bool {
		return cli.loop.Stats().DataQueueDepth == 0
	})
}
