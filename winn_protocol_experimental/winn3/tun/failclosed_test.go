package tun

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The fail-closed property, in one sentence: if the session is not carrying, no
// inner packet reaches the session and no inner packet reaches the host — not a
// data packet, not a synthesised path-MTU packet, not a byte.
//
// This file proves it four different ways, because the project has a history of
// documents asserting properties the code did not have, and because each of the
// four catches a different way of getting it wrong:
//
//   - TestOnlyOneStateCarries catches a permissive predicate.
//   - TestNothingCrossesUnlessCarrying catches a path that skips the gate.
//   - TestGateDrainsInFlightSenders catches a teardown that returns before its
//     traffic has stopped.
//   - TestNoPacketCrossesAfterTheGateCloses catches the time-of-check window,
//     and TestFailClosedDetectorHasTeeth proves that last test can fail.

// TestOnlyOneStateCarries walks the whole domain of the State type, not the
// list of constants that happen to be declared today.
//
// The failure this catches: somebody adds StateDraining, writes MayCarry as
// "not down and not closed", and every state anyone forgets about becomes a
// carrying state. A test that iterates the declared constants would still pass.
func TestOnlyOneStateCarries(t *testing.T) {
	carrying := 0
	for i := 0; i < 256; i++ {
		s := State(i)
		if s.MayCarry() {
			carrying++
			if s != StateCarrying {
				t.Errorf("State(%d) = %s permits carrying; StateCarrying must be the only one", i, s)
			}
		}
	}
	if carrying != 1 {
		t.Fatalf("%d of 256 state values permit carrying; exactly one must", carrying)
	}
}

// TestGateStartsClosed pins the zero value. A Gate that was allocated and not
// configured, and a Tunnel whose session never came up, must both carry
// nothing.
func TestGateStartsClosed(t *testing.T) {
	var g Gate
	if g.State() != StateDown || g.State().MayCarry() {
		t.Fatalf("zero Gate is %s and carries; it must start closed", g.State())
	}
	f := newFixture(t) // deliberately not .carrying()
	if err := f.tun.Outbound(goodV4(64)); !errors.Is(err, ErrNotCarrying) {
		t.Fatalf("Outbound on a fresh tunnel: %v, want ErrNotCarrying", err)
	}
	if err := f.tun.Inbound(arrivingV4(64)); !errors.Is(err, ErrNotCarrying) {
		t.Fatalf("Inbound on a fresh tunnel: %v, want ErrNotCarrying", err)
	}
	f.quiet("fresh tunnel")
}

// packetClasses is the catalogue every fail-closed assertion is run against.
// It deliberately includes packets that are perfectly valid, because "the gate
// only stops the packets that were going to be dropped anyway" is not the
// property being claimed.
func packetClasses() []struct {
	name string
	pkt  []byte
} {
	a := fixtureAssign()
	return []struct {
		name string
		pkt  []byte
	}{
		{"valid ipv4", goodV4(200)},
		{"valid ipv6", goodV6(200)},
		{"valid ipv4 arriving", arrivingV4(200)},
		{"valid ipv6 arriving", arrivingV6(200)},
		{"ipv4 at the inner mtu", goodV4(fixtureInnerMTU - IPv4HeaderMin)},
		{"ipv4 one byte over the inner mtu", goodV4(fixtureInnerMTU - IPv4HeaderMin + 1)},
		{"ipv6 far over the inner mtu", goodV6(4000)},
		{"foreign source", v4cfg{src: peerV4(), dst: peerV4(), payload: 64}.build()},
		{"foreign destination", v4cfg{src: peerV4(), dst: peerV4(), payload: 64}.build()},
		{"multicast destination", v4cfg{src: a.V4, dst: v4a(224, 0, 0, 251), payload: 64}.build()},
		{"bad checksum", v4cfg{src: a.V4, dst: peerV4(), payload: 64, badChecksum: true}.build()},
		{"truncated header", goodV4(200)[:12]},
		{"empty", nil},
		{"single byte", []byte{0x45}},
		{"garbage", []byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}},
	}
}

// TestNothingCrossesUnlessCarrying is the exhaustive product: every value the
// State type can hold, crossed with every packet class, in both directions.
//
// The assertion is an "if and only if". Traffic crosses exactly when the state
// is StateCarrying, and in every one of the other 255 states the session sees
// nothing and the host device sees nothing. Adding a state cannot outgrow this
// test; adding a code path that bypasses the gate cannot survive it.
func TestNothingCrossesUnlessCarrying(t *testing.T) {
	classes := packetClasses()
	for i := 0; i < 256; i++ {
		state := State(i)
		if state.MayCarry() {
			continue
		}
		for _, tc := range classes {
			f := newFixture(t)
			f.gate.Set(state)

			if err := f.tun.Outbound(tc.pkt); !errors.Is(err, ErrNotCarrying) {
				t.Fatalf("state %s, %s: Outbound returned %v, want ErrNotCarrying", state, tc.name, err)
			}
			if err := f.tun.Inbound(tc.pkt); !errors.Is(err, ErrNotCarrying) {
				t.Fatalf("state %s, %s: Inbound returned %v, want ErrNotCarrying", state, tc.name, err)
			}
			f.quiet("state " + state.String() + ", " + tc.name)

			st := f.tun.Stats()
			if st.TxDroppedClosed != 1 || st.RxDroppedClosed != 1 {
				t.Fatalf("state %s, %s: fail-closed counters are tx=%d rx=%d, want 1 and 1",
					state, tc.name, st.TxDroppedClosed, st.RxDroppedClosed)
			}
			if st.TxPackets != 0 || st.RxPackets != 0 || st.PMTUSignals != 0 {
				t.Fatalf("state %s, %s: something was counted as delivered: %+v", state, tc.name, st)
			}
		}
	}

	// And the other half of the "if and only if": in the one carrying state the
	// valid packets do move, so the test above is not passing because the
	// tunnel is broken.
	f := newFixture(t).carrying()
	if err := f.tun.Outbound(goodV4(200)); err != nil {
		t.Fatalf("carrying: Outbound of a valid packet: %v", err)
	}
	if err := f.tun.Inbound(arrivingV4(200)); err != nil {
		t.Fatalf("carrying: Inbound of a valid packet: %v", err)
	}
	if f.sink.count() != 1 || f.dev.writeCount() != 1 {
		t.Fatalf("carrying: sink=%d device=%d, want 1 and 1", f.sink.count(), f.dev.writeCount())
	}
}

// TestClosedGateEmitsNoPathMTUSignal covers the one path that writes to the
// host without a packet having arrived from the tunnel.
//
// Synthesising a path-MTU packet is a write to the host's device. If the
// oversize check ran before the gate, a torn-down session would still be
// injecting packets into the host's stack — packets sourced from an inner
// router address that no longer routes anywhere.
func TestClosedGateEmitsNoPathMTUSignal(t *testing.T) {
	oversize := goodV4(fixtureInnerMTU) // header + payload comfortably over

	for _, state := range []State{StateDown, StateHandshaking, StateEpoch0, StateRekeying, StateClosed} {
		f := newFixture(t)
		f.gate.Set(state)
		if err := f.tun.Outbound(oversize); !errors.Is(err, ErrNotCarrying) {
			t.Fatalf("state %s: %v, want ErrNotCarrying", state, err)
		}
		f.quiet("oversize in state " + state.String())
		if st := f.tun.Stats(); st.PMTUSignals != 0 || st.TxDroppedOversize != 0 {
			t.Fatalf("state %s: oversize was processed past the gate: %+v", state, st)
		}
	}

	// Carrying, the same packet does produce the signal — so the assertion
	// above is about the gate and not about a dead code path.
	f := newFixture(t).carrying()
	if err := f.tun.Outbound(oversize); !errors.Is(err, ErrOversize) {
		t.Fatalf("carrying: %v, want ErrOversize", err)
	}
	if st := f.tun.Stats(); st.PMTUSignals != 1 {
		t.Fatalf("carrying: PMTUSignals=%d, want 1", st.PMTUSignals)
	}
	if f.sink.count() != 0 {
		t.Fatal("an oversize packet reached the session; it must never leave the host")
	}
}

// TestGateDrainsInFlightSenders proves the barrier half of the property.
//
// A kill switch that returns before its traffic has stopped has reported a
// safety property it does not have. Gate.Set must not return while a packet is
// still on its way to the session.
func TestGateDrainsInFlightSenders(t *testing.T) {
	f := newFixture(t).carrying()

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	f.sink.setHook(func([]byte) {
		once.Do(func() {
			close(entered)
			<-release
		})
	})

	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		_ = f.tun.Outbound(goodV4(64))
	}()
	<-entered

	setReturned := make(chan struct{})
	go func() {
		f.gate.Set(StateDown)
		close(setReturned)
	}()

	select {
	case <-setReturned:
		t.Fatal("Gate.Set returned while a packet was still in flight to the session")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case <-setReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("Gate.Set never returned after the in-flight packet completed")
	}
	<-sendDone

	// And nothing may cross afterwards.
	if err := f.tun.Outbound(goodV4(64)); !errors.Is(err, ErrNotCarrying) {
		t.Fatalf("after the drain: %v, want ErrNotCarrying", err)
	}
	if f.sink.count() != 1 {
		t.Fatalf("sink saw %d packets; only the one in flight before the close should have crossed", f.sink.count())
	}
}

// TestNoPacketCrossesAfterTheGateCloses is the concurrent version, and the one
// that would catch a check-then-use window.
//
// The detector is arranged so that it cannot produce a false positive: the
// "closed" flag is set only AFTER Gate.Set has returned, and Set does not
// return until every hold taken before it has been released. So any send or
// device write observed with the flag set is a packet that crossed after the
// tunnel was declared down. Run with -race, this also catches the state being
// read without synchronisation.
func TestNoPacketCrossesAfterTheGateCloses(t *testing.T) {
	f := newFixture(t).carrying()

	var closed atomic.Bool
	var violations atomic.Uint64
	detect := func([]byte) {
		if closed.Load() {
			violations.Add(1)
		}
	}
	f.sink.setHook(detect)
	f.dev.mu.Lock()
	f.dev.onWrite = detect
	f.dev.mu.Unlock()

	const workers = 8
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out := goodV4(64)
			in := arrivingV4(64)
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = f.tun.Outbound(out)
				_ = f.tun.Inbound(in)
			}
		}()
	}

	waitFor(t, "traffic to start", func() bool { return f.tun.Stats().TxPackets > 500 })

	f.gate.Set(StateDown)
	closed.Store(true)

	waitFor(t, "the closed path to be exercised", func() bool { return f.tun.Stats().TxDroppedClosed > 500 })

	close(stop)
	wg.Wait()

	if v := violations.Load(); v != 0 {
		t.Fatalf("%d packet(s) crossed after the gate closed", v)
	}
	st := f.tun.Stats()
	// RxDeviceWrites, not RxPackets. This guard asks "did the test actually
	// push traffic through", and the fixture drives Inbound directly rather
	// than through PumpOutbound, so its device never originates a packet and
	// the tunnel never becomes DeviceProven. RxPackets is a DELIVERY and would
	// be zero here for a reason that has nothing to do with what this test is
	// about; RxDeviceWrites is what the device took, which is the fact the
	// guard wants.
	if st.TxPackets == 0 || st.RxDeviceWrites == 0 {
		t.Fatalf("the test never carried anything: %+v", st)
	}
	if st.TxDroppedClosed == 0 || st.RxDroppedClosed == 0 {
		t.Fatalf("the test never exercised the closed path: %+v", st)
	}
}

// TestFailClosedDetectorHasTeeth points the detector from the test above at an
// implementation that HAS the window, and requires it to object.
//
// A passing invariant test that could never fail is worse than no test,
// because it turns an unverified claim into a verified-looking one. The core
// makes the same argument for its uniformity detector and it applies with more
// force here: this is the property the users' safety actually rests on.
func TestFailClosedDetectorHasTeeth(t *testing.T) {
	gate := NewGate()
	gate.Set(StateCarrying)
	sink := &fakeSink{}

	var closed atomic.Bool
	var violations atomic.Uint64
	sink.setHook(func([]byte) {
		if closed.Load() {
			violations.Add(1)
		}
	})

	checked := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		// The naive shape: read the state, then send. Nothing holds the gate
		// across the two statements, which is exactly the window Gate.enter /
		// Gate.leave removes by holding a read lock that Set must wait on.
		if !gate.State().MayCarry() {
			return
		}
		close(checked)
		<-release
		_ = sink.SendData(goodV4(32))
	}()

	<-checked
	gate.Set(StateDown)
	closed.Store(true)
	close(release)
	<-done

	if violations.Load() == 0 {
		t.Fatal("the detector accepted a packet sent after the gate closed; it cannot prove anything about the real path")
	}
}

// TestLifecycleWalk runs the sequence a real session goes through and checks
// the tunnel at every step, including the two that are easy to get wrong: a
// rekey in the middle of a live flow, and a teardown.
func TestLifecycleWalk(t *testing.T) {
	f := newFixture(t)

	steps := []struct {
		state State
		carry bool
	}{
		{StateDown, false},
		{StateHandshaking, false},
		{StateEpoch0, false}, // StrictPQ: epoch 0 carries no DATA
		{StateCarrying, true},
		{StateRekeying, false},
		{StateCarrying, true},
		{StateClosed, false},
		{StateDown, false},
	}

	var wantTx, wantRx uint64
	for _, s := range steps {
		f.gate.Set(s.state)
		errOut := f.tun.Outbound(goodV4(100))
		errIn := f.tun.Inbound(arrivingV4(100))
		if s.carry {
			wantTx++
			wantRx++
			if errOut != nil || errIn != nil {
				t.Fatalf("state %s: out=%v in=%v, want both nil", s.state, errOut, errIn)
			}
		} else {
			if !errors.Is(errOut, ErrNotCarrying) || !errors.Is(errIn, ErrNotCarrying) {
				t.Fatalf("state %s: out=%v in=%v, want ErrNotCarrying", s.state, errOut, errIn)
			}
		}
		st := f.tun.Stats()
		// The walk's subject is which gate states carry, so it counts what
		// crossed: RxDeviceWrites is the packet the device took. This fixture
		// never reads from its device, so it is never DeviceProven and
		// RxPackets — a corroborated delivery — is zero throughout. That the
		// gate still governs both directions is what the two assertions here
		// pin, and TestDeliveryNeedsAProvenDevice covers the corroboration.
		if st.TxPackets != wantTx || st.RxDeviceWrites != wantRx {
			t.Fatalf("state %s: tx=%d rx=%d, want %d and %d", s.state, st.TxPackets, st.RxDeviceWrites, wantTx, wantRx)
		}
		if st.RxPackets != 0 {
			t.Fatalf("state %s: RxPackets=%d on a device that has never spoken", s.state, st.RxPackets)
		}
		if uint64(f.sink.count()) != wantTx || uint64(f.dev.writeCount()) != wantRx {
			t.Fatalf("state %s: sink=%d device=%d, want %d and %d",
				s.state, f.sink.count(), f.dev.writeCount(), wantTx, wantRx)
		}
	}
}

// TestFalsePromoteCannotFlipTheGateOpen pins the gate's side of the
// false-promotion fix.
//
// The host promotes on promotionReady: Gate.State() == StateCarrying &&
// Stats().RxPackets > 0. The stats half — that a write into a void is a write,
// never a delivery — is covered in deviceproof_test.go. This test holds the
// other half: the gate must not be opened by that evidence, or by any memory
// that the tunnel once carried.
//
// After a real carrying session delivers packets and is then torn down,
// RxPackets > 0 and DeviceProven linger in the stats forever — they latch and
// never reset. Those are exactly the positives a false promotion is built
// from. If "open" were derived from traffic instead of from
// Set(StateCarrying) — if lingering delivery evidence could flip the gate back
// open — a teardown the user is told to trust would already have been undone,
// and re-auditing the closed tunnel would silently admit packets. It does not:
// the gate reads StateDown, promotionReady is false, and every packet is still
// refused.
func TestFalsePromoteCannotFlipTheGateOpen(t *testing.T) {
	f := newFixture(t)
	f.carrying()

	// Build the evidence a false promote is made of, genuinely: prove the
	// device by reading a real packet, then deliver one through the tunnel so
	// RxPackets > 0. None of this may be asserted by declaration; the whole
	// point is that the lingering stats match what a promotion predicate would
	// consult.
	f.dev.queue(goodV4(64))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = f.tun.PumpOutbound(ctx) }()
	waitFor(t, "the device to be proven", func() bool { return f.tun.Stats().DeviceReads > 0 })

	if err := f.tun.Inbound(arrivingV4(200)); err != nil {
		t.Fatalf("deliver a packet while carrying: %v", err)
	}
	if st := f.tun.Stats(); st.RxPackets != 1 {
		t.Fatalf("RxPackets=%d, want 1: the test never built the promotion evidence", st.RxPackets)
	}

	// Teardown. The delivery evidence above is still sitting in the stats,
	// latched and unreset, exactly as in a real session that has been up and
	// has gone back down.
	f.gate.Set(StateDown)
	sinkBefore := f.sink.count()
	devBefore := f.dev.writeCount()

	if f.gate.State() != StateDown {
		t.Fatalf("after teardown the gate reads %s, want StateDown", f.gate.State())
	}
	if promotionReady(f.tun) {
		t.Fatalf("promotionReady is true on a torn-down tunnel with RxPackets=%d: "+
			"the stale promotion evidence has left the gate reported open", f.tun.Stats().RxPackets)
	}

	// The gate stays closed operationally too: neither direction admits a
	// packet, and nothing is written anywhere.
	if err := f.tun.Outbound(goodV4(64)); !errors.Is(err, ErrNotCarrying) {
		t.Fatalf("Outbound with promotion evidence present on a closed gate: %v, want ErrNotCarrying", err)
	}
	if err := f.tun.Inbound(arrivingV4(64)); !errors.Is(err, ErrNotCarrying) {
		t.Fatalf("Inbound with promotion evidence present on a closed gate: %v, want ErrNotCarrying", err)
	}
	if f.sink.count() != sinkBefore || f.dev.writeCount() != devBefore {
		t.Fatalf("a packet crossed a gate that stale promotion evidence could not reopen: "+
			"sink %d->%d, device %d->%d", sinkBefore, f.sink.count(), devBefore, f.dev.writeCount())
	}
}

// TestSourceAddressViolationIsDroppedInEveryGatePosture pins the fail-closed
// authority's two-stage treatment of a foreign source, which is the gate's
// promotion story in one sentence:
//
//	A packet whose source is not the address assigned to this tunnel is
//	dropped in EVERY gate posture — fail-closed (ErrNotCarrying) before the
//	gate is ever promoted, and as an invalid source (ErrSourceNotOurs) once it
//	is. No byte of it reaches the session in either, because a session handed a
//	spoofed source is the reflector this whole layer exists to prevent.
//
// The distinction is the point. Before promotion the drop is the gate's and the
// packet is never even parsed; after promotion the drop is the validator's.
// Both must hold, or a host that trusts one stage has a hole in the other.
// Because the gate is the boundary the host promotes across — bootstrap ->
// StateCarrying -> the tunnel carries real traffic — a source that survives
// either half is a source this layer has promised, somewhere, to refuse.
func TestSourceAddressViolationIsDroppedInEveryGatePosture(t *testing.T) {
	foreign := v4cfg{src: peerV4(), dst: peerV4(), payload: 64}.build()

	// Bootstrap, and every non-carrying state: the gate refuses the packet
	// fail-closed before its source is ever looked at. The counter is
	// TxDroppedClosed, not TxDroppedInvalid — the parse never happened.
	for _, state := range []State{StateDown, StateHandshaking, StateEpoch0, StateRekeying, StateClosed} {
		f := newFixture(t)
		f.gate.Set(state)
		if err := f.tun.Outbound(foreign); !errors.Is(err, ErrNotCarrying) {
			t.Fatalf("state %s: foreign source returned %v, want ErrNotCarrying", state, err)
		}
		if n := f.sink.count(); n != 0 {
			t.Fatalf("state %s: %d byte(s) of a foreign source reached the session before promotion", state, n)
		}
		if st := f.tun.Stats(); st.TxDroppedClosed != 1 || st.TxDroppedInvalid != 0 {
			t.Fatalf("state %s: fail-closed counters %+v, want TxDroppedClosed=1 TxDroppedInvalid=0", state, st)
		}
	}

	// Promoted: the gate admits the packet for inspection and the source check
	// is what stops it. Now it is an invalid packet, counted differently, and
	// still nothing reaches the session.
	f := newFixture(t).carrying()
	if err := f.tun.Outbound(foreign); !errors.Is(err, ErrSourceNotOurs) {
		t.Fatalf("promoted: foreign source returned %v, want ErrSourceNotOurs", err)
	}
	if n := f.sink.count(); n != 0 {
		t.Fatalf("promoted: %d byte(s) of a foreign source reached the session", n)
	}
	if st := f.tun.Stats(); st.TxDroppedInvalid != 1 || st.TxPackets != 0 || st.TxDroppedClosed != 0 {
		t.Fatalf("promoted: counters %+v, want TxDroppedInvalid=1 TxPackets=0", st)
	}

	// Positive control: the promoted tunnel still carries a legitimate packet
	// from the assigned address, so neither half was green by accident.
	if err := f.tun.Outbound(goodV4(64)); err != nil {
		t.Fatalf("promoted: a valid packet after the refusal was rejected: %v", err)
	}
	if n := f.sink.count(); n != 1 {
		t.Fatalf("promoted: session saw %d packets, want exactly the one valid one", n)
	}
}

// waitFor spins until cond holds, with a bound so a broken implementation
// fails the test instead of hanging the suite.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		runtime.Gosched()
	}
}
