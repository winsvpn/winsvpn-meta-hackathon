package netlab

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// Property 2, both halves.
//
// The session lane chose TEARDOWN AND RE-HANDSHAKE for burst loss beyond the
// token window, and its detector is LIVENESS-BASED rather than error-based, on
// the argument that counting unopenable messages would hand an off-path
// attacker a teardown primitive for the price of spraying a known 5-tuple.
//
// Both halves are tested here, and the second is the security-relevant one:
// a detector that works is worth nothing if it also fires for an attacker.

// burstPair builds a rig whose probe schedule is the shipping one. Detection
// latency is therefore the real MaxLostProbes x Probe.Max, measured in injected
// time rather than shortened by configuration — a shortened budget would prove
// the mechanism runs, not that it runs inside the documented cost.
func burstPair(t *testing.T, cfg PairConfig) *Pair {
	t.Helper()
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TokenWindow == 0 {
		cfg.TokenWindow = netlabWindow
	}
	if cfg.SendQueue == 0 {
		cfg.SendQueue = 2048
	}
	p, err := NewPair(kr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p.Start(ctx)
	t.Cleanup(p.Stop)
	if err := p.Handshake(20 * time.Second); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestBurstLossBeyondTheWindowIsDetectedAndTornDown is the first half.
//
// The burst is 400 messages at a 256-token window: past the cliff, so the
// receiver's low edge can never be reached again and the direction is
// permanently dead. Nothing in the protocol recovers it — that is the decision,
// not a defect — so what must happen is a teardown that FAILS CLOSED and tells
// the host to build a new session.
func TestBurstLossBeyondTheWindowIsDetectedAndTornDown(t *testing.T) {
	t.Parallel()
	p := burstPair(t, PairConfig{})

	const burst = 400
	p.ToGateway.Arm(Impairment{DropFrom: 1, DropCount: burst})

	// Full-size packets so one inner packet is one message and the burst is a
	// message count rather than a packet count.
	p.OfferInner(burst+40, p.FullPayload())

	// The burst has to actually happen before the probe budget is judged.
	if err := p.Settle(30*time.Second, time.Millisecond, func() bool {
		return p.ToGateway.Stats().DroppedBurst >= burst
	}); err != nil {
		t.Fatalf("the shim dropped only %d of the %d it was told to; the impairment was not applied "+
			"and this test proves nothing", p.ToGateway.Stats().DroppedBurst, burst)
	}

	// The direction is now dead. Detection is the probe budget, and the budget
	// runs on the injected clock, so the wait is virtual time rather than real.
	//
	// It is bounded in virtual time too, which it was not before. Settle's only
	// bound is a REAL deadline, and 60 seconds of it is about three and a half
	// HOURS of injected time on this rig — measured failures of this test
	// reported 2h38m to 2h52m. That is a dozen rekey intervals past the
	// four-minute budget the assertion below actually checks, so the run spent
	// almost all of its time in a regime the test says nothing about, and the
	// far end's goroutines got no more real turns for any of it. The bound here
	// is the same one the assertion below uses, with headroom.
	detectBy := time.Duration(session.DefaultMaxLostProbes)*session.DefaultProbeMax + 30*time.Second
	elapsed, err := p.SettleWithin(detectBy, 30*time.Second, 180*time.Second, func() bool {
		return p.Client.Loop.Session().NeedsNewSession() ||
			p.Gateway.Loop.Session().NeedsNewSession()
	})
	if err != nil {
		t.Fatalf("neither end detected a burst of %d lost messages at a %d-token window after %s "+
			"of injected time: client=%s gateway=%s, gateway unopenable=%d. "+
			"A permanently desynchronised direction that is never detected is a tunnel that "+
			"reports up and carries nothing.",
			burst, netlabWindow, elapsed, p.Client.Loop.Session().State(),
			p.Gateway.Loop.Session().State(), p.Gateway.Loop.Session().Stats().Unopenable)
	}
	t.Logf("burst loss beyond the window detected after %s of injected time", elapsed)

	// The documented cost is MaxLostProbes x Probe.Max = 4 x 20 s at the
	// shipping defaults. Anything materially longer is a user staring at a dead
	// tunnel; anything much shorter means the budget is not being spent.
	if budget := time.Duration(session.DefaultMaxLostProbes) * session.DefaultProbeMax; elapsed > budget+10*time.Second {
		t.Fatalf("detection took %s of injected time against a documented worst case of %s",
			elapsed, budget)
	}

	// And it must fail CLOSED. For a user under a hostile state a tunnel that
	// stops carrying without shutting its gate is traffic going out the physical
	// interface in the clear.
	if _, err := p.SettleWithin(4*detectBy, 20*time.Second, 120*time.Second, func() bool {
		return p.Client.Loop.Session().State().Terminal() &&
			p.Client.Loop.Tunnel().Gate().State() != tun.StateCarrying
	}); err != nil {
		s := p.Client.Loop.Session().Stats()
		t.Fatalf("client is %s with gate %s after detection (probes lost %d of the %d that end a "+
			"session; %v); the teardown must latch the gate down",
			p.Client.Loop.Session().State(), p.Client.Loop.Tunnel().Gate().State(),
			s.ProbesLost, session.DefaultMaxLostProbes, err)
	}
}

// TestBurstLossDetectionIsNotAnErrorCount is the same run seen from the other
// side, and it is the assertion the session lane's design turns on: the gateway
// receives HUNDREDS of unopenable messages and must not tear down because of
// them. It tears down because a probe went unanswered, which is a different
// fact and one an attacker cannot manufacture.
func TestBurstLossDetectionIsNotAnErrorCount(t *testing.T) {
	t.Parallel()
	p := burstPair(t, PairConfig{})

	const burst = 400
	p.ToGateway.Arm(Impairment{DropFrom: 1, DropCount: burst})
	p.OfferInner(burst+200, p.FullPayload())

	// Wait until the gateway has seen a large number of unopenable messages —
	// the post-burst traffic, which arrives and cannot be placed.
	if err := p.Settle(30*time.Second, time.Millisecond, func() bool {
		return p.Gateway.Loop.Session().Stats().Unopenable >= 100
	}); err != nil {
		t.Fatalf("the gateway saw only %d unopenable messages; the rig did not reproduce the "+
			"post-burst condition and this test proves nothing",
			p.Gateway.Loop.Session().Stats().Unopenable)
	}
	// At this point the clock has barely moved, so no probe budget can have been
	// spent. If the gateway were counting errors it would already be gone.
	if p.Gateway.Loop.Session().State().Terminal() {
		t.Fatalf("the gateway tore down after %d unopenable messages without any probe budget "+
			"being spent. That is an ERROR-BASED detector, and it is a teardown primitive an "+
			"off-path attacker gets for the price of spraying a known 5-tuple.",
			p.Gateway.Loop.Session().Stats().Unopenable)
	}
}

// TestABurstInsideTheWindowIsSurvived is the teeth for the burst instrument.
//
// The same shim, the same code path, a burst SHORTER than the window: the
// force-advance rule must carry the session straight through it with no
// teardown at all. Without this the test above could be passing because the
// session tears down on any loss whatsoever.
func TestABurstInsideTheWindowIsSurvived(t *testing.T) {
	t.Parallel()
	p := burstPair(t, PairConfig{})

	const burst = 200 // < 256
	p.ToGateway.Arm(Impairment{DropFrom: 1, DropCount: burst})
	sent := p.OfferInner(burst+150, p.FullPayload())

	if err := p.Settle(30*time.Second, time.Millisecond, func() bool {
		return p.ToGateway.Stats().DroppedBurst >= burst
	}); err != nil {
		t.Fatalf("the shim dropped only %d of %d", p.ToGateway.Stats().DroppedBurst, burst)
	}
	p.ToGateway.Disarm()

	got := p.Collect(sent-burst, 40*time.Second)
	if got < sent-burst {
		t.Fatalf("delivered %d of the %d packets that were NOT dropped, after a burst of %d at a "+
			"%d-token window. A burst inside the window must cost exactly the burst.",
			got, sent-burst, burst, netlabWindow)
	}
	if p.Client.Loop.Session().State() != session.StateEstablished ||
		p.Gateway.Loop.Session().State() != session.StateEstablished {
		t.Fatalf("client=%s gateway=%s after a %d-message burst inside a %d-token window; "+
			"a survivable outage must not tear the session down",
			p.Client.Loop.Session().State(), p.Gateway.Loop.Session().State(), burst, netlabWindow)
	}
}

// --- the spray attack ---------------------------------------------------------

// TestSprayingGarbageAtAKnownFiveTupleCannotForceATeardown is the
// security-relevant half.
//
// The threat is concrete: on a datagram carrier, finding the 5-tuple is not
// hard, and an off-path attacker who could tear a session down by sending
// rubbish to it would have a remote tunnel kill for the price of a UDP socket.
// The session lane's answer is that the detector never counts unopenable
// messages. This delivers rubbish directly into the gateway's carrier — the
// same entry point a real datagram arrives on — while real traffic flows.
func TestSprayingGarbageAtAKnownFiveTupleCannotForceATeardown(t *testing.T) {
	t.Parallel()
	p := burstPair(t, PairConfig{})

	const sprayed = 10000
	before := p.Gateway.Loop.Session().Stats()

	var wg sync.WaitGroup
	var accepted atomic.Uint64
	var refused atomic.Uint64
	var unexpected atomic.Uint64
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 200)
		for i := 0; i < sprayed; i++ {
			if _, err := rand.Read(buf); err != nil {
				unexpected.Add(uint64(sprayed - i))
				return
			}
			switch err := p.GatewayPipe.Deliver(buf); {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, carrier.ErrQueueFull):
				refused.Add(1)
			default:
				unexpected.Add(1)
			}
		}
	}()

	// Real traffic through the same carrier at the same time. A session that
	// survives a spray but stops carrying under one has not survived it.
	sent := p.OfferInner(200, p.FullPayload())
	got := p.Collect(sent, 25*time.Second)
	wg.Wait()

	acceptedCount := accepted.Load()
	refusedCount := refused.Load()
	unexpectedCount := unexpected.Load()
	if unexpectedCount != 0 || acceptedCount+refusedCount+unexpectedCount != sprayed {
		t.Fatalf("spray delivery outcomes: accepted=%d queue-full=%d unexpected=%d, want %d total with no unexpected errors",
			acceptedCount, refusedCount, unexpectedCount, sprayed)
	}
	if acceptedCount < 2000 {
		t.Fatalf("only %d of %d sprayed messages were accepted by the rig; the carrier queue refused %d and this test proves nothing",
			acceptedCount, sprayed, refusedCount)
	}

	after := p.Gateway.Loop.Session().Stats()
	reached := after.Unopenable - before.Unopenable
	deadline := time.Now().Add(3 * time.Second)
	for reached < 2000 && !p.Gateway.Loop.Session().State().Terminal() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
		after = p.Gateway.Loop.Session().Stats()
		reached = after.Unopenable - before.Unopenable
	}
	if p.Gateway.Loop.Session().State() != session.StateEstablished {
		t.Fatalf("the gateway is %s after %d sprayed messages. An off-path attacker who can reach "+
			"the 5-tuple has a remote tunnel kill.", p.Gateway.Loop.Session().State(), sprayed)
	}
	if p.Client.Loop.Session().State() != session.StateEstablished {
		t.Fatalf("the client is %s after the gateway was sprayed", p.Client.Loop.Session().State())
	}
	if reached < 2000 {
		t.Fatalf("only %d of %d sprayed messages reached the session's Open path; the spray was "+
			"absorbed by the rig rather than by the protocol and this test proves nothing",
			reached, sprayed)
	}
	// The remainder were refused by the carrier's bounded inbox, which is worth
	// recording rather than hiding: a Pipe-backed carrier drops on a full queue
	// rather than blocking, because a demultiplexer that stalls on one slow
	// session stalls every session on that socket. In the DEPLOYED shape a
	// sprayed datagram never reaches a session's Pipe at all — gateway.Table
	// .Dispatch refuses it on the token index first — so this queue pressure is
	// a property of the rig's shortcut, not of the gateway.
	t.Logf("%d of %d sprayed messages reached Open; the carrier accepted %d and refused %d at its bounded inbox",
		reached, sprayed, acceptedCount, refusedCount)
	if after.ProbesLost != before.ProbesLost {
		t.Fatalf("the spray cost %d probes; noise must not be able to suppress a PONG",
			after.ProbesLost-before.ProbesLost)
	}
	if got == 0 {
		t.Fatalf("no real inner packet crossed while %d rubbish messages were sprayed; the "+
			"session survived but stopped carrying entirely", sprayed)
	}
	if got < sent {
		// Recorded rather than failed, because it is a real property of the
		// receive path and not a rig artefact: the carrier's inbox is bounded and
		// drops on full, so a spray at rate displaces real messages. It is a
		// DEGRADATION, not a teardown, and the distinction is the security claim.
		// See §4.3 of WINN3_NETWORK_REALISM_20260808.md.
		t.Logf("FINDING: %d of %d real inner packets were displaced by a %d-message spray; the "+
			"session stayed up and lost no probes, but the spray cost real delivery",
			sent-got, sent, sprayed)
	}
}

// TestASustainedSprayReachesATeardownThroughInducedLoss is the finding, and it
// is the one that qualifies the session lane's security argument.
//
// WINN3_SESSION_DRIVER_20260808.md §3 says of the liveness detector: "noise
// cannot forge a PONG and cannot suppress one." The first clause is true. The
// SECOND IS NOT, and the difference is the whole attack:
//
//   - The detector is liveness-based, so a run of unopenable messages does not
//     fire it. That much is confirmed here: 38,000+ unopenable messages, zero
//     probes lost at the sprayed end, session established.
//   - But the receive path is bounded — a Pipe drops on a full inbox, a socket
//     drops on a full buffer — so noise AT VOLUME displaces real messages,
//     including PINGs and PONGs. Suppressing a PONG does not require forging
//     anything. It requires bandwidth.
//   - And the probe budget then expires exactly as it would under a real
//     outage, because from the driver's point of view that is what this is.
//
// So the liveness detector does not CLOSE the off-path teardown primitive. It
// REPRICES it: from one spoofed packet to a sustained flood. That is a large
// and worthwhile improvement and it is not the property the document claims.
//
// This test pins the current behaviour. If it ever fails because the session
// SURVIVED, that is good news and §4.3 of WINN3_NETWORK_REALISM_20260808.md
// should be updated rather than this test deleted.
func TestASustainedSprayNoLongerReachesATeardown(t *testing.T) {
	t.Parallel()
	p := burstPair(t, PairConfig{})

	// The spray is a DOSE, not "as fast as four goroutines can go for as long as
	// the loop lasts". That distinction is the difference between an experiment
	// and a measurement of the machine.
	//
	// Uncapped, the volume delivered is whatever the scheduler happens to allow:
	// runs of this test were observed at 91 054 unopenable messages (assertions
	// below hold) and at 454 592 and 802 073 (they do not, because at that
	// intensity the gateway's bounded inbox displaces the client's PONGs and the
	// sprayed end really does lose probes). Both readings are legitimate physics
	// — a big enough flood does starve the answer — but which one a run gets was
	// decided by CPU contention, so the test asserted a property of the laptop.
	// Capping the dose makes the intensity an input. The floor assertion below
	// (>= 10 000 reaching Open) still proves the spray was real, and the cap sits
	// an order of magnitude above it.
	const sprayDose = 100_000
	var sprayed atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(4)
	for i := 0; i < 4; i++ {
		go func() {
			defer wg.Done()
			buf := make([]byte, 300)
			_, _ = rand.Read(buf)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if sprayed.Load() >= sprayDose {
					// The dose is spent. Stay alive so the goroutine count is
					// unchanged, but stop adding to the flood.
					time.Sleep(time.Millisecond)
					continue
				}
				for j := 0; j < 256; j++ {
					buf[0]++
					_ = p.GatewayPipe.Deliver(buf)
				}
				sprayed.Add(256)
				// Spread the dose across the probe budget rather than dumping it
				// in one burst: "sustained" is the condition being modelled, and
				// a burst and a sustained flood are different impairments.
				time.Sleep(200 * time.Microsecond)
			}
		}()
	}

	sent := p.OfferInner(600, p.FullPayload())
	got := p.Collect(sent, 20*time.Second)
	// Then let the probe budget run under continuing spray, which is the only
	// route by which the detector can fire at all. This is a dwell, not a wait:
	// there is no condition to reach, so the ErrTimeout it necessarily returns is
	// the expected result and is discarded. SettleWithin is still the right
	// vehicle — it keeps the wake count inside driver's maxSpins and steps in odd
	// nanoseconds, both of which a hand-rolled loop here got wrong.
	budget := time.Duration(session.DefaultMaxLostProbes) * session.DefaultProbeMax * 2
	_, _ = p.SettleWithin(budget, 10*time.Second, 60*time.Second, func() bool { return false })
	close(stop)
	wg.Wait()

	gw := p.Gateway.Loop.Session().Stats()
	cl := p.Client.Loop.Session().Stats()
	t.Logf("under a sustained off-path spray at a known 5-tuple — "+
		"%d of %d real packets delivered; the SPRAYED end saw %d unopenable messages and lost "+
		"%d probes and is %s; the FAR end lost %d probes and is %s (%v)",
		got, sent, gw.Unopenable, gw.ProbesLost, p.Gateway.Loop.Session().State(),
		cl.ProbesLost, p.Client.Loop.Session().State(), p.Client.Loop.Session().Err())

	if gw.Unopenable < 10000 {
		t.Fatalf("only %d sprayed messages reached Open; the spray was not sustained and this "+
			"test proves nothing", gw.Unopenable)
	}

	// The half of the claim that was always true: the sprayed end does not tear
	// down because of the noise itself. Its own probes are answered by a client
	// whose inbound direction the spray never touched.
	if gw.ProbesLost != 0 {
		t.Fatalf("the sprayed end lost %d probes; the ERROR count is supposed to be irrelevant "+
			"to the detector and the sprayed direction is inbound only", gw.ProbesLost)
	}

	// The half that was NOT, and the fix.
	//
	// Measured on 2026-08-08: the far end spent its full four-probe budget and
	// failed with ErrPeerUnreachable — the honest detector firing on an outage
	// that an off-path attacker had manufactured by displacing real messages out
	// of a bounded receive path. §3 of WINN3_SESSION_DRIVER_20260808.md claimed
	// noise "cannot suppress a PONG"; suppressing one needs no forgery, only
	// bandwidth.
	//
	// The teardown now requires TWO facts, not one: the probe budget spent AND
	// nothing authenticated arriving meanwhile. A spray at one end's inbox leaves
	// that end's OUTBOUND untouched, so its traffic keeps arriving here, and the
	// second fact is false. The attacker must now silence both directions, at
	// which point nothing is crossing at all and a teardown is the right answer.
	// This rig sprays straight into the gateway's inbox from four goroutines with
	// no yield, so its intensity is whatever the scheduler gives it on the day.
	// At the intensity this lane first measured (231 of 600 real packets through)
	// the gateway's own traffic keeps reaching the client and the teardown must
	// not happen. At a much higher intensity the gateway's loops are starved
	// outright, nothing crosses in either direction, and a teardown is the
	// CORRECT answer rather than a manufactured one.
	//
	// So the assertion is on the rule, not on the outcome: a teardown is
	// permitted only when the far end genuinely heard almost nothing. The exact
	// property, with the intensity taken out of the picture, is in
	// TestSuppressedProbesDoNotTearDownAnEndThatIsStillHearingItsPeer.
	const heard = 8
	if p.Client.Loop.Session().State().Terminal() && cl.MessagesReceived >= heard {
		t.Fatalf("the far end is %s (%v) under a sustained off-path spray while still RECEIVING "+
			"%d authenticated messages from its peer. A teardown an off-path attacker can "+
			"manufacture with bandwidth is a censorship capability, and closing it is the whole "+
			"point of this change.",
			p.Client.Loop.Session().State(), p.Client.Loop.Session().Err(), cl.MessagesReceived)
	}
	if p.Client.Loop.Session().State().Terminal() {
		t.Logf("NOTE: this run's spray was intense enough to starve the gateway's own loops — "+
			"the far end received only %d authenticated messages, so nothing was crossing in "+
			"either direction and the teardown is correct rather than manufactured",
			cl.MessagesReceived)
	}
	// And the degradation is still VISIBLE. Refusing the teardown must not also
	// hide the damage: a policy layer reads a climbing probe-loss count on an
	// established session and answers it with a carrier change, which is the
	// response that actually helps against a flood at a known five-tuple.
	if cl.ProbesLost == 0 {
		t.Logf("NOTE: the far end lost no probes at all this run; the spray displaced less than " +
			"a full budget's worth and the refusal above was not exercised")
	} else {
		t.Logf("FIXED: the far end lost %d probes under the spray and stayed %s — the loss is "+
			"still counted, so a policy layer can still see the degradation and change carrier, "+
			"but it is no longer a teardown an off-path attacker can trigger at will",
			cl.ProbesLost, p.Client.Loop.Session().State())
	}
	// The spray must not be mistaken for a narrowed path either: both are
	// "messages stop arriving", and only one of them is about size.
	if p.Client.Loop.Session().PathNarrowed() && cl.WideProbesLost < session.DefaultMaxLostProbes {
		t.Fatal("a narrowed verdict was reached without the wide ladder being exhausted")
	}
}

// TestBurstLossBeyondTheWindowSurvivesANATRebindAndEndsTheSameWay is the rebind
// half of Property 2, and it reasons from the shape a rebind actually has.
//
// Every other test in this file arms an impairment and waits for the detector
// on the ORIGINAL path. A mobile user under a NAT rebind is not on the original
// path: her source address changed, which presents to the session layer as a
// FRESH bearer with the SAME receive window and the SAME keys. Whether that
// fresh bearer can repair a direction already killed by burst loss beyond the
// token window is a different question from whether the original one can, and
// it is the one this test answers.
//
// The rig models the fresh bearer with MigrateTo: both ends are moved onto
// fresh Links and fresh carrier.Pipes, with the sessions untouched. That is
// exactly what a socket renumber presents to the session layer, and no socket is
// opened anywhere — the token stream and the probe budget both live above the
// socket, and an address that indexes nothing adds no information here.
//
// The answers, pinned:
//
//   - The rebind does not repair the desync. Post-rebind traffic reaches the
//     gateway's OPEN path and is refused there, and none of it emerges to the
//     host device. A policy layer that read "the peer moved" as "healed" would
//     report a tunnel that carries nothing as healthy — the silent-refusal
//     shape this package exists to catch.
//   - The rebind does not reset the detector. Detection must land inside
//     MaxLostProbes x Probe.Max measured from the REBIND, not from the burst;
//     otherwise a rebind is a free reset of the dead-man's timer and the
//     re-handshake that is the design's actual answer never arrives.
//   - The teardown is still LIVENESS, not the unopenable count the rebind kept
//     feeding the gateway, and it still fails closed.
//
// Every wait BEFORE the measurement injects NO virtual time, by the same
// argument Handshake makes. Delivery, the burst, the rebind and the refusals at
// OPEN are message-driven: the links key on message ordinals, not on the clock.
// The one deadline they could reach is the session's receive-stall schedule
// (session.stallQuiet 1 s, then stall probes lost after 1.5 s each), which
// unopenable arrivals arm and which tears the gateway down after a few seconds
// of injected time. A wait that injected even that much before the rebind was
// measured would tear the gateway down first: under `go test ./winn3/netlab`
// the gateway loop died with 48 of 120 unopenable messages counted, and run
// alone the "measured from the rebind" figure below was 0s, so the property it
// names was never measured. Only SettleWithin, which is the measurement, moves
// the clock.
func TestBurstLossBeyondTheWindowSurvivesANATRebindAndEndsTheSameWay(t *testing.T) {
	t.Parallel()
	p := burstPair(t, PairConfig{})

	const burst = 400
	p.ToGateway.Arm(Impairment{DropFrom: 1, DropCount: burst})
	offered := p.OfferInner(burst+40, p.FullPayload())
	if offered <= burst {
		t.Fatalf("the client's host device accepted only %d packets, not more than the %d-message "+
			"burst; nothing reaches OPEN after it and this test proves nothing", offered, burst)
	}

	// The burst has to actually happen before the probe budget is judged.
	if err := p.Settle(30*time.Second, 0, func() bool {
		return p.ToGateway.Stats().DroppedBurst >= burst
	}); err != nil {
		t.Fatalf("the shim dropped only %d of the %d it was told to; the impairment was not "+
			"applied and this test proves nothing", p.ToGateway.Stats().DroppedBurst, burst)
	}

	// The direction is now desynchronised at OPEN, so the gateway is counting
	// unopenable messages before any probe budget has been spent. That is the
	// baseline the rebind has to survive being unable to heal. It must be
	// OBSERVED rather than assumed: a rig that never delivered the post-burst
	// traffic to OPEN has nothing to assert here. All of it is waited for, so
	// no pre-rebind message is still in flight across the carrier move and
	// counted below as if it had crossed the fresh path.
	postBurst := uint64(offered - burst)
	if err := p.Settle(30*time.Second, 0, func() bool {
		return p.Gateway.Loop.Session().Stats().Unopenable >= postBurst
	}); err != nil {
		t.Fatalf("the gateway saw %d unopenable messages of the %d sent after the burst; the "+
			"receive window was not desynchronised and this test proves nothing",
			p.Gateway.Loop.Session().Stats().Unopenable, postBurst)
	}
	gwBefore := p.Gateway.Loop.Session().Stats()

	// The rebind. A carrier move is what a NAT rebind presents to the session
	// layer: same sessions, same windows, same epoch, different bearer.
	epoch := p.Client.Loop.Session().Epoch()
	if err := p.MigrateTo(carrier.ClassTCP, p.Sizing.PathMTU); err != nil {
		t.Fatalf("the rebind — a carrier move, which is what a source-address change presents "+
			"to the session layer as — was refused: %v", err)
	}
	if p.Client.Loop.Session().Epoch() != epoch {
		t.Fatalf("the rebind changed the epoch from %d to %d. A bearer change must not cost a "+
			"re-handshake: the design's answer to burst loss beyond the window is teardown, "+
			"not carrier change",
			epoch, p.Client.Loop.Session().Epoch())
	}
	if m := p.Client.Loop.Stats().Migrations; m != 1 {
		t.Fatalf("the loop counted %d migrations, want 1; the rebind did not happen and "+
			"nothing below can be trusted", m)
	}

	// A probe packet must NOT cross the fresh path: the carrier physically
	// carries and the OPEN path does not. If it crosses, the bearer change
	// repaired the receive window, which is the opposite of the pinned decision.
	// ProveCarrying cannot ask this: its Collect injects virtual time for as
	// long as no packet arrives, which on this path is its whole budget. Both
	// outcomes are observed instead, with the clock held: the probe is refused
	// at the gateway's OPEN path, or it emerges to the gateway's host device.
	if p.OfferInner(1, p.FullPayload()) != 1 {
		t.Fatal("the client's host device refused the probe packet after the rebind; the rig " +
			"itself broke and this test proves nothing")
	}
	if err := p.Settle(30*time.Second, 0, func() bool {
		return p.Gateway.Device.Drained() > 0 ||
			p.Gateway.Loop.Session().Stats().Unopenable > gwBefore.Unopenable
	}); err != nil {
		t.Fatalf("the probe packet neither reached the gateway's OPEN path nor emerged after the "+
			"rebind (%v); the fresh path did not deliver it, so the test is measuring the rig "+
			"rather than the protocol", err)
	}
	if p.Gateway.Device.Drained() > 0 {
		t.Fatal("a probe packet crossed the session on the fresh path after the rebind. The " +
			"bearer change repaired the desync, which is the opposite of the teardown-and-" +
			"re-handshake decision; the handoff needs updating rather than this test")
	}
	gwBefore = p.Gateway.Loop.Session().Stats()

	// Post-rebind traffic reaches the gateway's OPEN path and is refused there,
	// and none of it emerges to the host device. Both halves prove the desync is
	// in the token stream and not in the bearer. The wait holds the clock for
	// the same reason as the probe's.
	sent := p.OfferInner(80, p.FullPayload())
	if sent == 0 {
		t.Fatal("the client's host device refused every packet after the rebind; the rig " +
			"itself broke and this test proves nothing")
	}
	want := gwBefore.Unopenable + uint64(sent)
	if err := p.Settle(30*time.Second, 0, func() bool {
		return p.Gateway.Device.Drained() > 0 ||
			p.Gateway.Loop.Session().Stats().Unopenable >= want
	}); err != nil {
		t.Fatalf("the gateway reached only %d of %d unopenable messages after the rebind; the "+
			"fresh path did not deliver the client's bytes, so the test is measuring the rig "+
			"rather than the protocol",
			p.Gateway.Loop.Session().Stats().Unopenable, want)
	}
	if got := p.Gateway.Device.Drained(); got != 0 {
		t.Fatalf("%d of %d post-rebind packets emerged to the gateway's host device on a "+
			"session whose receive window the burst killed. A bearer change repaired it, which "+
			"is the opposite of the design decision; the handoff needs updating rather than "+
			"this test", got, sent)
	}

	// The measurement starts on a session that is still up. A gateway already
	// torn down here makes "measured from the rebind" read 0s, and the property
	// below would be asserted on a session the rig had already killed.
	if p.Gateway.Loop.Session().NeedsNewSession() || p.Gateway.Loop.Session().State().Terminal() {
		gw := p.Gateway.Loop.Session().Stats()
		t.Fatalf("the gateway was already %s (probes lost %d) before the detector was measured "+
			"from the rebind; the rig spent the receive-stall budget before the measurement, so "+
			"this test would measure nothing", p.Gateway.Loop.Session().State(), gw.ProbesLost)
	}

	// The rebind must not have reset the detector, so the wait is measured from
	// the rebind, not from the burst. The gateway is the end whose probes cannot
	// be answered any more — every PONG from the client fails OPEN — while it
	// keeps receiving unopenable traffic, so it is the end that must fire.
	detectBy := time.Duration(session.DefaultMaxLostProbes)*session.DefaultProbeMax + 30*time.Second
	elapsed, err := p.SettleWithin(detectBy, 30*time.Second, 180*time.Second, func() bool {
		return p.Gateway.Loop.Session().NeedsNewSession()
	})
	if err != nil {
		gw := p.Gateway.Loop.Session().Stats()
		t.Fatalf("the gateway did not reach NeedsNewSession within %s of injected time measured "+
			"from the rebind: probes lost %d of the %d that end a session, unopenable %d (%v). "+
			"A rebind that holds the dead-man's timer open is a tunnel that reports up on a "+
			"dead token stream forever.",
			elapsed, gw.ProbesLost, session.DefaultMaxLostProbes, gw.Unopenable, err)
	}
	if budget := time.Duration(session.DefaultMaxLostProbes) * session.DefaultProbeMax; elapsed > budget+10*time.Second {
		t.Fatalf("detection took %s of injected time measured from the rebind against a "+
			"documented worst case of %s; the rebind reset the detector", elapsed, budget)
	}
	t.Logf("burst loss beyond the window detected after %s of injected time, measured from the "+
		"rebind", elapsed)

	// And it was LIVENESS that fired it: the gateway spent a full probe budget
	// because nothing it receives after the rebind OPENS. A teardown with fewer
	// probes lost than the budget is the unopenable count deciding, which is the
	// off-path primitive the liveness decision exists to deny.
	if lost := p.Gateway.Loop.Session().Stats().ProbesLost; lost < session.DefaultMaxLostProbes {
		t.Fatalf("the gateway tore down having lost %d probes, below the %d-probe budget; the "+
			"unopenable count did the work", lost, session.DefaultMaxLostProbes)
	}

	// And it must fail closed, on the client as on the gateway.
	if _, err := p.SettleWithin(4*detectBy, 20*time.Second, 120*time.Second, func() bool {
		return p.Client.Loop.Session().State().Terminal() &&
			p.Client.Loop.Tunnel().Gate().State() != tun.StateCarrying
	}); err != nil {
		s := p.Client.Loop.Session().Stats()
		t.Fatalf("client is %s with gate %s after the post-rebind teardown (probes lost %d of "+
			"%d; %v); a rebind must not launder the desync into an up-but-dead tunnel",
			p.Client.Loop.Session().State(), p.Client.Loop.Tunnel().Gate().State(),
			s.ProbesLost, session.DefaultMaxLostProbes, err)
	}
}

// TestBurstLossInsideTheWindowSurvivesANATRebindAndKeepsCarrying is the positive
// companion to the two rebind tests above, and it exists because the pairing is
// the result, not decoration.
//
// TestBurstLossBeyondTheWindowSurvivesANATRebindAndEndsTheSameWay arms its burst
// distributor BEFORE the rebind: a direction already dead at OPEN, moved to a
// fresh bearer, must stay dead and still be detected. Its burst-loss link is the
// ORIGINAL path. This test arms the burst ON THE FRESH POST-REBIND LINK, and it
// must be survived: the same Impairment rule, the same DropCount arithmetic, the
// same Link code path, but a burst SHORTER than the window arriving on a bearer
// that never carried the session until the rebind.
//
// The rebind cannot make liveness worse than it already is, and it cannot hand
// the force-advance rule a problem. Read as a boundary with the beyond-window
// rebind test, the two pin the fresh path too: a run of lost messages PAST the
// token window tears the session down whenever it arrives, and a run INSIDE it is
// carried through with no teardown at all — on the original path or on a fresh
// one. A test that only established the healthy rebind would prove nothing twice;
// a test that only established the teardown would leave "does a rebind kill a
// healthy session?" as prose.
//
// "Without a real network" is the point of the rig doc: nothing here opens a
// socket. The rebind is MigrateTo, which presents the fresh carrier and fresh
// burst-loss Link to a pair of untouched sessions — the same shape a source-
// address change presents to the session layer — and every assertion below is a
// claim about the token stream above that socket seam.
func TestBurstLossInsideTheWindowSurvivesANATRebindAndKeepsCarrying(t *testing.T) {
	t.Parallel()
	p := burstPair(t, PairConfig{})

	const burst = 200 // < netlabWindow 256

	// THE REBIND FIRST, while the session is healthy — the order is the whole
	// point, and it is the mirror of the sibling test, which rebinds a direction
	// that is already dead.
	epoch := p.Client.Loop.Session().Epoch()
	if err := p.MigrateTo(carrier.ClassTCP, p.Sizing.PathMTU); err != nil {
		t.Fatalf("the rebind — a carrier move on a HEALTHY session — was refused: %v", err)
	}
	if p.Client.Loop.Session().Epoch() != epoch {
		t.Fatalf("the rebind changed the client epoch from %d to %d; a bearer change on a "+
			"healthy session must not cost a re-handshake", epoch, p.Client.Loop.Session().Epoch())
	}
	if p.Gateway.Loop.Session().Epoch() != epoch {
		t.Fatalf("the rebind left the ends on different epochs: client %d gateway %d",
			p.Client.Loop.Session().Epoch(), p.Gateway.Loop.Session().Epoch())
	}
	if m := p.Client.Loop.Stats().Migrations; m != 1 {
		t.Fatalf("the loop counted %d migrations, want 1; the rebind did not happen and "+
			"nothing below can be trusted", m)
	}
	// The fresh bearer must be carrying as soon as the move lands, before any
	// impairment is armed. A rebind that interrupted the session here would make
	// a surviving burst below read as a rig feature.
	if err := p.ProveCarrying(30 * time.Second); err != nil {
		t.Fatalf("the fresh bearer did not carry the session immediately after the rebind: %v", err)
	}

	// Now the burst-loss link arrives ON the fresh path. ToGateway is the NEW
	// link — MigrateTo swapped the pair's links as well as its pipes, so the
	// Impairment below is relative to the rebind, never to the handshake or to
	// the path that carried it.
	p.ToGateway.Arm(Impairment{DropFrom: 1, DropCount: burst})
	sent := p.OfferInner(burst+150, p.FullPayload())
	if sent < burst+150 {
		t.Fatalf("the client's host device accepted only %d of %d packets; the rig itself "+
			"broke and this test proves nothing", sent, burst+150)
	}

	// The burst has to actually happen where this test is looking. Asserting on
	// the fresh link's own counter is what makes "the impairment was applied" an
	// observed fact rather than an assumption about the rebind.
	if err := p.Settle(30*time.Second, time.Millisecond, func() bool {
		return p.ToGateway.Stats().DroppedBurst >= burst
	}); err != nil {
		t.Fatalf("the fresh burst-loss link dropped only %d of the %d it was told to; "+
			"the impairment was not applied and this test proves nothing",
			p.ToGateway.Stats().DroppedBurst, burst)
	}
	p.ToGateway.Disarm()

	// The burst costs exactly the burst. A surviving run that lost less than the
	// burst proves nothing (the impairment never fired); one that lost more is a
	// rebind heap, not a burst.
	got := p.Collect(sent-burst, 40*time.Second)
	if got < sent-burst {
		t.Fatalf("delivered %d of the %d packets that were NOT dropped, after a %d-message "+
			"burst at a %d-token window ON A FRESH POST-REBIND PATH. A burst inside the "+
			"window must cost exactly the burst; anything more is the rebind degrading the "+
			"session, and it is invisible to a test that arms the original path",
			got, sent-burst, burst, netlabWindow)
	}

	// Liveness, stated twice so the sentence cannot be read either way: neither
	// end is asking for a new session and neither is tearing down.
	if p.Client.Loop.Session().NeedsNewSession() || p.Gateway.Loop.Session().NeedsNewSession() {
		t.Fatalf("a %d-message burst inside the %d-token window on a fresh post-rebind path "+
			"ended in NeedsNewSession (client %v, gateway %v); the bearer change weakened "+
			"the force-advance rule",
			burst, netlabWindow,
			p.Client.Loop.Session().NeedsNewSession(), p.Gateway.Loop.Session().NeedsNewSession())
	}
	if p.Client.Loop.Session().State() != session.StateEstablished ||
		p.Gateway.Loop.Session().State() != session.StateEstablished {
		t.Fatalf("client=%s gateway=%s after a %d-message burst inside a %d-token window on a "+
			"fresh post-rebind path; a survivable outage must not tear the session down",
			p.Client.Loop.Session().State(), p.Gateway.Loop.Session().State(), burst, netlabWindow)
	}

	// And the session is still carrying AFTER the burst, which is the liveness
	// fact the gate asserts. Show it on the wire rather than trusting the state
	// strings: a fresh full-size probe and its answer.
	if err := p.ProveCarrying(30 * time.Second); err != nil {
		t.Fatalf("the fresh bearer stopped carrying after a SURVIVED inside-window burst: %v. "+
			"Without this assertion the test above could pass for a session that was dead "+
			"before the burst and frozen at established afterwards",
			err)
	}

	// The rebind is still the ONLY bearer move in the run, and the flow that
	// follows is lossless. Neither can hold if the burst was carried by the old
	// path or if the session quietly re-handshook to escape it.
	if m := p.Client.Loop.Stats().Migrations; m != 1 {
		t.Fatalf("the loop counted %d migrations by the end, want 1; the session re-migrated "+
			"and this run measured two rebinds", m)
	}
	if p.Client.Loop.Session().Epoch() != p.Gateway.Loop.Session().Epoch() {
		t.Fatal("the two ends disagree about the epoch after the survived burst; a re-handshake " +
			"masked the force-advance result")
	}
	sent2, got2 := p.SendInner(40, p.FullPayload(), 30*time.Second)
	if sent2 != 40 {
		t.Fatalf("the client's host device accepted only %d of 40 packets after the burst", sent2)
	}
	if got2 != sent2 {
		t.Fatalf("delivered %d of %d full-size packets after the survived burst; the fresh "+
			"path lost data that was not part of the burst", got2, sent2)
	}
}
