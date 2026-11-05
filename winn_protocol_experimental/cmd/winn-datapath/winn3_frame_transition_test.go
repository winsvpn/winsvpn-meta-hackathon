//go:build unix

package main

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// Round A2 v3: a status request that straddles the end of a live, proven round
// must not regress the tunnel to its initial state. Both windows are forced
// with the test-only pause points, so the interleaving is deterministic:
//
//   - successor: the status takes its owner snapshot while round one is live
//     and proven, then round one ends and an unproven round two is published
//     before the status reads any gate or counter.
//   - latched: the status takes its snapshot, then round one's loop returns
//     (its gate latched down) and its wrapper is held before it records the
//     round's end, and only then does the status read the gate.

// transitionFixture is two frame hosts that have carried a packet each way on
// round one, with the client's pause points installed before any round runs.
type transitionFixture struct {
	client, gateway *frameEngine
	firstLoop       *driver.Loop
	provenRx        uint64

	// armed makes the status hook act on the next status only; onStatus is
	// what it does there.
	armed    atomic.Bool
	onStatus func()

	// holdRoundEnd makes the first round's end wait in the wrapper, after
	// its loop has returned, until released.
	holdRoundEnd bool
	roundEnded   chan struct{}
	release      chan struct{}
	roundOnce    sync.Once
}

func newTransitionFixture(t *testing.T, ctx context.Context, holdRoundEnd bool) *transitionFixture {
	t.Helper()
	ring := newFrameKeyring(t)
	const pathMTU = 1500
	sizing, err := driver.NewSizing(pathMTU, mustClasses(t, "udp", "tcp", "tls")...)
	if err != nil {
		t.Fatal(err)
	}
	clientSock, clientAddr := loopbackSocket(t)
	gatewaySock, gatewayAddr := loopbackSocket(t)
	f := &transitionFixture{
		client:       startFrameEngine(t, ctx, ring.clientKeys, handOver(t, clientSock)),
		gateway:      startFrameEngine(t, ctx, ring.gatewayKeys, handOver(t, gatewaySock)),
		holdRoundEnd: holdRoundEnd,
		roundEnded:   make(chan struct{}),
		release:      make(chan struct{}),
	}
	// Installed before Create, so before any goroutine that reads them.
	f.client.server.statusHook = func() {
		if f.armed.CompareAndSwap(true, false) {
			f.onStatus()
		}
	}
	f.client.server.roundEndHook = func() {
		if !f.holdRoundEnd {
			return
		}
		f.roundOnce.Do(func() {
			close(f.roundEnded)
			<-f.release
		})
	}
	t.Cleanup(func() {
		select {
		case <-f.release:
		default:
			close(f.release)
		}
	})

	f.client.create(t, frameCreate(gatewayAddr, "10.8.1.3", "10.8.1.1", sizing, pathMTU))
	f.gateway.create(t, frameCreate(clientAddr, "10.8.1.1", "10.8.1.3", sizing, pathMTU))
	_ = f.client.ack(t)
	_ = f.gateway.ack(t)
	carryPacket(t, f.client, f.gateway, ipv4Packet([4]byte{10, 8, 1, 3}, [4]byte{10, 8, 1, 1}, []byte("up")), 45*time.Second)
	carryPacket(t, f.gateway, f.client, ipv4Packet([4]byte{10, 8, 1, 1}, [4]byte{10, 8, 1, 3}, []byte("down")), 20*time.Second)
	st := f.client.status(t)
	if st.Lifecycle != driver.LifecycleConnected || !st.PromotionReady || st.Posture != winn3PostureFull || st.RxPackets == 0 {
		t.Fatalf("round one is not live and proven: %+v", st)
	}
	f.firstLoop = f.client.server.currentLoop()
	f.provenRx = st.RxPackets
	return f
}

// straddle takes one status, running onStatus inside it after the owner
// snapshot.
func (f *transitionFixture) straddle(t *testing.T, onStatus func()) winn3Status {
	t.Helper()
	f.onStatus = onStatus
	f.armed.Store(true)
	var st winn3Status
	if err := json.Unmarshal([]byte(f.client.server.statusJSON("posture")), &st); err != nil {
		t.Fatal(err)
	}
	if f.armed.Load() {
		t.Fatal("the status hook never ran; the window was not forced")
	}
	return st
}

// requireRecovering is the coherent answer for a tunnel that was proven and
// has lost its round: recovering, hold, no promotion, and none of round one's
// evidence published as if it were current.
func (f *transitionFixture) requireRecovering(t *testing.T, st winn3Status) {
	t.Helper()
	if st.Lifecycle != driver.LifecycleRecovering {
		t.Errorf("lifecycle %q, want %q: a proven tunnel that lost its round regressed", st.Lifecycle, driver.LifecycleRecovering)
	}
	if st.Posture != winn3PostureHold || st.PromotionReady {
		t.Errorf("posture %q promotion_ready %v, want hold and false: never bootstrap after promotion", st.Posture, st.PromotionReady)
	}
	if st.RxPackets != 0 || st.MessagesReceived != 0 || st.TxPackets != 0 {
		t.Errorf("round one's evidence (rx_packets was %d) published as current: rx %d messages_received %d tx %d",
			f.provenRx, st.RxPackets, st.MessagesReceived, st.TxPackets)
	}
	if st.GateState == tun.StateCarrying.String() {
		t.Errorf("gate_state %q while no round is proven", st.GateState)
	}
}

// TestAStatusStraddlingASuccessorPublicationStaysRecovering is the
// counterexample's first window: owner snapshot on the live proven round,
// then that round ends and an unproven successor is published.
func TestAStatusStraddlingASuccessorPublicationStaysRecovering(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f := newTransitionFixture(t, ctx, false)
	st := f.straddle(t, func() {
		_ = f.gateway.loop(t).Close()
		waitUntil(t, 30*time.Second, "an unproven successor to be published", func() bool {
			return f.client.server.rounds.Load() == 2
		})
	})
	if l := f.client.server.currentLoop(); l == f.firstLoop {
		t.Fatal("no successor was published inside the window")
	}
	f.requireRecovering(t, st)
	// And the steady state after the window agrees.
	f.requireRecovering(t, f.client.status(t))
}

// TestAStatusStraddlingALatchedGateStaysRecovering is the counterexample's
// second window: owner snapshot on the live proven round, then its loop ends
// and latches the gate down while its wrapper has not yet recorded the end.
func TestAStatusStraddlingALatchedGateStaysRecovering(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f := newTransitionFixture(t, ctx, true)
	st := f.straddle(t, func() {
		_ = f.gateway.loop(t).Close()
		select {
		case <-f.roundEnded:
		case <-time.After(30 * time.Second):
			t.Error("round one's loop did not end")
		}
	})
	if gate := f.firstLoop.Tunnel().Gate().State(); gate == tun.StateCarrying {
		t.Fatalf("round one's gate is %s; the latched window was not reached", gate)
	}
	if f.client.server.recovering.Load() {
		t.Fatal("the wrapper recorded the round's end inside the window; it was not held")
	}
	f.requireRecovering(t, st)
	close(f.release)
	waitUntil(t, 30*time.Second, "a successor", func() bool { return f.client.server.rounds.Load() == 2 })
	f.requireRecovering(t, f.client.status(t))
}

// TestAProvenTunnelIsNeverToldToNarrow pins the posture rule the transition
// tests rely on: once the tunnel has proven delivery, a document without
// promotion says hold, whatever its lifecycle; before first proof it still says
// bootstrap.
func TestAProvenTunnelIsNeverToldToNarrow(t *testing.T) {
	for _, tc := range []struct {
		lifecycle  string
		ready      bool
		everProven bool
		want       string
	}{
		{driver.LifecycleConnecting, false, false, winn3PostureBootstrap},
		{driver.LifecycleConnected, true, true, winn3PostureFull},
		{driver.LifecycleConnected, false, true, winn3PostureHold},
		{driver.LifecycleRecovering, false, true, winn3PostureHold},
		{driver.LifecycleRecovering, false, false, winn3PostureHold},
		{driver.LifecycleBlocked, false, false, winn3PostureHold},
	} {
		st := winn3Status{Lifecycle: tc.lifecycle, PromotionReady: tc.ready, Posture: winn3Posture(tc.ready)}
		winn3HoldCaptureWhileRecovering(&st, tc.everProven)
		if st.Posture != tc.want {
			t.Errorf("lifecycle %q ready %v everProven %v: posture %q, want %q",
				tc.lifecycle, tc.ready, tc.everProven, st.Posture, tc.want)
		}
	}
}
