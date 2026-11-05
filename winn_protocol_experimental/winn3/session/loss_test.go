package session

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// silentDraw parks a schedule outside every rig's virtual-time budget.
//
// It used to say "far outside any test's horizon" and read {1h, 2h, 3h}, which
// was neither: soloEmissions spends about 4,900 s of virtual time, and the same
// one-hour figure in quietConfig produced 14 failures in 200 runs of
// TestKeepaliveIsNotAMetronome. The horizon is now a named number that
// requireQuietBudget checks each rig against — see "the virtual-time budget
// invariant" in fingerprint_test.go.
func silentDraw() Draw {
	return Draw{Min: quietHorizon, Mean: 2 * quietHorizon, Max: 3 * quietHorizon}
}

// TestReorderWithinTheWindowIsTolerated: the token window is the reordering
// tolerance, and every counter inside it is equally acceptable in any order.
func TestReorderWithinTheWindowIsTolerated(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	p.establish()
	p.resetDelivered()

	const n = 8
	for i := 0; i < n; i++ {
		if err := p.cli.Enqueue([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		p.drain() // one message per round, so the order is known
	}
	if len(p.toGw) != n {
		t.Fatalf("expected %d messages on the link, got %d", n, len(p.toGw))
	}
	for i, j := 0, len(p.toGw)-1; i < j; i, j = i+1, j-1 {
		p.toGw[i], p.toGw[j] = p.toGw[j], p.toGw[i]
	}
	p.deliver()

	if len(p.atGw) != n {
		t.Fatalf("gateway received %d packets out of %d sent in reverse order", len(p.atGw), n)
	}
	if p.gw.Stats().Unopenable != 0 {
		t.Errorf("reordering cost %d unopenable messages", p.gw.Stats().Unopenable)
	}
	seen := make(map[byte]bool)
	for _, pkt := range p.atGw {
		seen[pkt[0]] = true
	}
	if len(seen) != n {
		t.Errorf("received %d distinct packets, want %d", len(seen), n)
	}
}

// TestDuplicateIsRefusedWithoutHarmingTheGenuineCopy: a consumed token is
// erased, so a replay finds nothing — and the token window IS the replay filter,
// with no bitmap arithmetic to get subtly wrong.
func TestDuplicateIsRefusedWithoutHarmingTheGenuineCopy(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	p.establish()
	p.resetDelivered()

	if err := p.cli.Enqueue([]byte("once")); err != nil {
		t.Fatal(err)
	}
	p.drain()
	if len(p.toGw) != 1 {
		t.Fatalf("expected one message, got %d", len(p.toGw))
	}
	msg := p.toGw[0]
	p.toGw = [][]byte{msg, append([]byte(nil), msg...)}
	p.deliver()

	if len(p.atGw) != 1 {
		t.Fatalf("a duplicated message delivered %d packets, want 1", len(p.atGw))
	}
	if !bytes.Equal(p.atGw[0], []byte("once")) {
		t.Errorf("payload is %q", p.atGw[0])
	}
	if got := p.gw.Stats().Unopenable; got != 1 {
		t.Errorf("Unopenable is %d, want exactly the one replay", got)
	}
	if p.gw.State() != StateEstablished {
		t.Errorf("a replay changed the state to %s", p.gw.State())
	}
}

// TestBurstLossWithinTheWindowRecovers: losing fewer consecutive messages than
// the forward window is ordinary loss and the session carries on.
func TestBurstLossWithinTheWindowRecovers(t *testing.T) {
	const window = 64
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.Core.TokenWindow = window
		gw.Core.TokenWindow = window
	})
	p.establish()
	p.resetDelivered()

	start := p.nToGw
	const burst = window / 2
	p.filterToGw = func(idx int, _ []byte) bool { return idx < start || idx >= start+burst }

	for i := 0; i < burst; i++ {
		if err := p.cli.Enqueue([]byte("lost")); err != nil {
			t.Fatal(err)
		}
		p.run()
	}
	for i := 0; i < 10; i++ {
		if err := p.cli.Enqueue([]byte("kept")); err != nil {
			t.Fatal(err)
		}
		p.run()
	}
	if got := len(p.atGw); got != 10 {
		t.Fatalf("gateway received %d packets after a %d-message burst loss, want 10", got, burst)
	}
	if p.gw.State() != StateEstablished {
		t.Fatalf("gateway state is %s after a survivable burst loss", p.gw.State())
	}
}

// TestBurstLossBeyondTheWindowIsDetectedAndTornDown is the answer to §6.10 of
// the design, and the reasoning behind the answer is in the package doc.
//
// Losing more consecutive messages than the receiver's forward window leaves the
// receiver unable to place anything that follows, permanently. There is no
// in-band recovery: a resynchronisation message would have to be recognisable to
// a receiver that by construction cannot open anything from that sender, so it
// would have to be a new plaintext-distinguishable message class — failure F1.
// A rekey is no better, because REKEY_INIT travels inside the epoch the receiver
// has lost.
//
// So the driver detects it with unanswered liveness probes and tears the session
// down. The detecting end sends a best-effort CLOSE(CloseDesynchronised), which
// this test also checks reaches the peer: the peer's outbound direction is the
// dead one, but its inbound still works, so it learns immediately instead of
// waiting out its own probe budget.
func TestBurstLossBeyondTheWindowIsDetectedAndTornDown(t *testing.T) {
	const window = core.MinTokenWindow
	p := newPair(t, func(cli, gw *Config) {
		cli.Core.TokenWindow = window
		gw.Core.TokenWindow = window
		// The client must not detect anything on its own, so that what the test
		// observes at the client is what the CLOSE told it.
		cli.Silence = silentDraw()
		cli.Probe = silentDraw()
		cli.RekeyInterval = silentDraw()
		cli.RekeyAfterMessages = core.RejectAfterMessages
		cli.RekeyAfterBytes = 1 << 60
		// The gateway probes quickly.
		gw.Silence = silentDraw()
		gw.Probe = Draw{Min: time.Second, Mean: 2 * time.Second, Max: 3 * time.Second}
		gw.MaxLostProbes = 3
		gw.RekeyInterval = silentDraw()
		gw.RekeyAfterMessages = core.RejectAfterMessages
		gw.RekeyAfterBytes = 1 << 60
	})
	p.establish()
	p.resetDelivered()

	// A burst larger than the forward window, in one direction only.
	start := p.nToGw
	const burst = window * 3
	p.filterToGw = func(idx int, _ []byte) bool { return idx < start || idx >= start+burst }
	for i := 0; i < burst; i++ {
		if err := p.cli.Enqueue([]byte("gone")); err != nil {
			t.Fatal(err)
		}
		p.run()
	}
	p.filterToGw = nil

	// Delivery resumes, and the gateway cannot place any of it.
	for i := 0; i < 5; i++ {
		if err := p.cli.Enqueue([]byte("unplaceable")); err != nil {
			t.Fatal(err)
		}
		p.run()
	}
	if len(p.atGw) != 0 {
		t.Fatalf("gateway placed %d packets after a burst beyond its window; the regression is not being reproduced", len(p.atGw))
	}
	if p.gw.Stats().Unopenable == 0 {
		t.Fatal("gateway reported no unopenable messages; the burst did not desynchronise it")
	}
	if p.gw.State() != StateEstablished {
		t.Fatalf("gateway tore down on unopenable messages alone (state %s); teardown must be liveness-driven, not error-driven", p.gw.State())
	}

	// Now let the clock run. The gateway's probes go out, the client answers
	// them into the dead direction, and the gateway runs out of budget.
	for i := 0; i < 60 && !p.gw.State().Terminal(); i++ {
		p.clk.Advance(time.Second)
		p.run()
	}

	if !p.gw.State().Terminal() {
		t.Fatalf("gateway never detected the desynchronisation; state %s, probes lost %d",
			p.gw.State(), p.gw.Stats().ProbesLost)
	}
	if got := p.gw.LocalCloseReason(); got != CloseDesynchronised {
		t.Errorf("gateway closed with reason %s, want %s", got, CloseDesynchronised)
	}
	if err := p.gw.Err(); !errors.Is(err, ErrPeerUnreachable) {
		t.Errorf("gateway error is %v, want ErrPeerUnreachable", err)
	}
	if !p.gw.NeedsNewSession() {
		t.Error("gateway did not ask for a new session")
	}

	// The CLOSE travelled the direction that still worked.
	p.run()
	if !p.cli.State().Terminal() {
		t.Fatalf("client did not learn of the teardown; state %s", p.cli.State())
	}
	if got := p.cli.PeerCloseReason(); got != CloseDesynchronised {
		t.Errorf("client saw peer close reason %s, want %s", got, CloseDesynchronised)
	}
	if !p.cli.NeedsNewSession() {
		t.Error("client did not ask for a new session")
	}
	if n := p.cli.Stats().ProbesLost; n != 0 {
		t.Errorf("client lost %d probes; it should have learned from the CLOSE, not from its own budget", n)
	}
	if !p.cli.PeerCloseReason().NeedsNewSession() {
		t.Error("CloseDesynchronised should call for a new session")
	}
}

// TestInjectedNoiseNeverTearsDownASession is the reason the desynchronisation
// detector is liveness-based rather than error-based.
//
// A run of unopenable messages is exactly what a burst loss beyond the window
// produces. It is also exactly what an off-path attacker produces by spraying
// bytes at a known five-tuple. A detector that counted unopenable messages would
// be a teardown primitive handed to that attacker, and on a datagram carrier
// finding the five-tuple is not hard.
func TestInjectedNoiseNeverTearsDownASession(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		gw.Probe = Draw{Min: time.Second, Mean: 2 * time.Second, Max: 3 * time.Second}
		gw.MaxLostProbes = 3
	})
	p.establish()
	p.resetDelivered()

	junk := make([]byte, 300)
	for round := 0; round < 40; round++ {
		for i := 0; i < 250; i++ {
			if _, err := rand.Read(junk); err != nil {
				t.Fatal(err)
			}
			if _, err := p.gw.Deliver(junk); err != nil {
				t.Fatalf("Deliver returned an error for noise: %v", err)
			}
		}
		if err := p.cli.Enqueue([]byte("real")); err != nil {
			t.Fatal(err)
		}
		p.clk.Advance(time.Second)
		p.run()
	}

	if p.gw.State() != StateEstablished {
		t.Fatalf("10000 injected messages tore the session down: state %s, reason %s, err %v",
			p.gw.State(), p.gw.LocalCloseReason(), p.gw.Err())
	}
	if got := p.gw.Stats().Unopenable; got < 10000 {
		t.Errorf("only %d messages were counted unopenable; the noise was not delivered", got)
	}
	if got := len(p.atGw); got != 40 {
		t.Errorf("gateway received %d real packets alongside the noise, want 40", got)
	}
	if n := p.gw.Stats().ProbesLost; n != 0 {
		t.Errorf("noise caused %d probes to be counted lost", n)
	}
}

// TestTornDownSessionRefusesFurtherWork keeps a dead driver from looking alive.
func TestTornDownSessionRefusesFurtherWork(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	p.establish()

	if err := p.cli.Close(); err != nil {
		t.Fatal(err)
	}
	p.run()
	if p.cli.State() != StateClosed {
		t.Fatalf("client state is %s after Close", p.cli.State())
	}
	if p.gw.State() != StateClosed {
		t.Fatalf("gateway state is %s after receiving CLOSE", p.gw.State())
	}
	if got := p.gw.PeerCloseReason(); got != CloseNormal {
		t.Errorf("gateway saw reason %s, want %s", got, CloseNormal)
	}
	if p.gw.NeedsNewSession() {
		t.Error("an orderly close asked for a new session")
	}
	if err := p.cli.Enqueue([]byte("late")); !errors.Is(err, ErrClosed) {
		t.Errorf("Enqueue after close returned %v, want ErrClosed", err)
	}
	if _, err := p.cli.Deliver([]byte("late")); !errors.Is(err, ErrClosed) {
		t.Errorf("Deliver after close returned %v, want ErrClosed", err)
	}
	msg, err := p.cli.Poll()
	if msg != nil || err != nil {
		t.Errorf("Poll after close returned %v, %v", msg, err)
	}
	if !p.cli.NextDeadline().IsZero() {
		t.Error("a terminal driver still reports a deadline")
	}
	if err := p.cli.Close(); err != nil {
		t.Errorf("a second Close returned %v", err)
	}
}

// TestLostHandshakeResponseIsRecoveredByAFreshInitiation is the handshake
// half of the replay window, seen from the client.
//
// A byte-identical retransmission is the right answer when the INITIATION was
// lost (the gateway never saw it). It is useless when the RESPONSE was lost:
// Responder.ReadInitiation has already called replayCache.remember, so the
// copy returns ErrReplay and Driver.Deliver swallows that as Unopenable with
// no error and no byte on the wire. To the client that is total silence —
// indistinguishable from a censor — until Retry.FreshAfter draws a new
// ephemeral, which hashes differently and passes the cache.
//
// The pieces exist separately: TestReplayedInitiationRejected (core),
// TestHandshakeReplayObservability S1 (gateway.Handle), and
// TestHandshakeRetriesThenDemandsACarrierChange (client emits identical then
// fresh, against a gateway that never sees any of them). Nothing joined
// "gateway accepted, response dropped, identical copy refused, fresh copy
// establishes". That join is the path a lossy mobile network actually takes.
func TestLostHandshakeResponseIsRecoveredByAFreshInitiation(t *testing.T) {
	t.Run("fresh_ephemeral_recovers", func(t *testing.T) {
		p := newPair(t, func(cli, gw *Config) {
			quietConfig(cli)
			quietConfig(gw)
			cli.Retry = Retry{Base: time.Second, Cap: 2 * time.Second, Attempts: 8, FreshAfter: 2}
			// Keep the half-open gateway alive across the client's retry
			// budget: tickInitiating tears a responder down at handshakeBudget
			// if the PQ ratchet has not finished, and that would mask the
			// replay-cache behaviour this test is measuring.
			gw.Retry = Retry{Base: time.Minute, Cap: time.Minute, Attempts: 8}
		})
		// Drop only the first gateway→client message: the RESPONSE to the
		// original initiation. Later messages (the response to the fresh
		// handshake, then PQ) must flow or the recovery cannot be observed.
		p.filterToCli = func(idx int, _ []byte) bool { return idx > 0 }

		p.drain()
		if len(p.toGw) != 1 {
			t.Fatalf("client emitted %d initiations, want 1", len(p.toGw))
		}
		first := append([]byte(nil), p.toGw[0]...)
		p.deliver()
		p.drain()
		if p.nToCli != 1 {
			t.Fatalf("gateway emitted %d messages after the first initiation, want 1 (the lost response)", p.nToCli)
		}
		if p.cli.State() != StateInitiating {
			t.Fatalf("client state is %s after a lost response; it must still be initiating", p.cli.State())
		}
		if p.gw.State().Terminal() {
			t.Fatalf("gateway is already terminal (%s / %v) after accepting the initiation", p.gw.State(), p.gw.Err())
		}

		identicalReplays := 0
		sawFresh := false
		for i := 0; i < 16 && p.cli.State() == StateInitiating; i++ {
			dl := p.cli.NextDeadline()
			if dl.IsZero() {
				t.Fatal("client has no retry deadline while still initiating")
			}
			now := p.clk.Now()
			if dl.After(now) {
				p.clk.Advance(dl.Sub(now) + time.Nanosecond)
			}
			p.drain()
			for _, m := range p.toGw {
				if bytes.Equal(m, first) {
					identicalReplays++
				} else {
					sawFresh = true
				}
			}
			p.deliver()
			if sawFresh {
				p.run()
				break
			}
		}

		if identicalReplays == 0 {
			t.Fatal("client never retransmitted the identical initiation; the replay-cache refusal was not exercised")
		}
		if !sawFresh {
			t.Fatalf("client never emitted a fresh initiation after %d identical replays; a lost RESPONSE is unrecoverable without one (state %s err %v)",
				identicalReplays, p.cli.State(), p.cli.Err())
		}
		if got := p.gw.Stats().Unopenable; got < uint64(identicalReplays) {
			t.Fatalf("gateway Unopenable is %d, want at least the %d identical replays (each must be refused silently)",
				got, identicalReplays)
		}
		if p.cli.State() != StateEstablished || p.gw.State() != StateEstablished {
			t.Fatalf("states after a lost response and a fresh initiation: %s / %s (%v / %v)",
				p.cli.State(), p.gw.State(), p.cli.Err(), p.gw.Err())
		}

		p.resetDelivered()
		if err := p.cli.Enqueue([]byte("after lost response")); err != nil {
			t.Fatal(err)
		}
		p.run()
		if len(p.atGw) != 1 || !bytes.Equal(p.atGw[0], []byte("after lost response")) {
			t.Fatalf("recovered session carried %#v, want one data packet", p.atGw)
		}
	})

	t.Run("identical_retries_alone_cannot_recover", func(t *testing.T) {
		// Negative control: FreshAfter larger than Attempts means the client
		// never draws a new ephemeral. The gateway's replay cache then makes
		// a lost RESPONSE a permanent hang until the retry budget expires.
		// If this subtest goes green while the session ESTABLISHES, the
		// replay cache is not refusing the copies and the recovery test
		// above is measuring something else.
		p := newPair(t, func(cli, gw *Config) {
			quietConfig(cli)
			quietConfig(gw)
			cli.Retry = Retry{Base: time.Second, Cap: 2 * time.Second, Attempts: 4, FreshAfter: 9}
			gw.Retry = Retry{Base: time.Minute, Cap: time.Minute, Attempts: 8}
		})
		p.filterToCli = func(int, []byte) bool { return false }

		p.drain()
		if len(p.toGw) != 1 {
			t.Fatalf("client emitted %d initiations, want 1", len(p.toGw))
		}
		first := append([]byte(nil), p.toGw[0]...)
		p.deliver()

		for i := 0; i < 20 && !p.cli.State().Terminal(); i++ {
			dl := p.cli.NextDeadline()
			if dl.IsZero() {
				break
			}
			now := p.clk.Now()
			if dl.After(now) {
				p.clk.Advance(dl.Sub(now) + time.Nanosecond)
			}
			p.drain()
			for _, m := range p.toGw {
				if !bytes.Equal(m, first) {
					t.Fatal("client emitted a fresh initiation; FreshAfter was supposed to exceed Attempts")
				}
			}
			p.deliver()
		}
		if p.cli.State() == StateEstablished || p.gw.State() == StateEstablished {
			t.Fatal("the session established on identical retransmissions alone; the replay cache is not refusing them")
		}
		if !p.cli.State().Terminal() {
			t.Fatalf("client never gave up; state %s err %v", p.cli.State(), p.cli.Err())
		}
		if p.gw.Stats().Unopenable == 0 {
			t.Fatal("gateway counted no unopenable messages; the identical retries never reached it")
		}
	})
}
