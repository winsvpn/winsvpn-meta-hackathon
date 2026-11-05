package netlab

import (
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/session"
)

// This file is the answer to the only question that matters about a rig: was
// anything actually impaired?
//
// A rig that reports everything passing on its first run has most likely
// impaired nothing, and every green row in this package would then be evidence
// of nothing at all. So each instrument is run TWICE through the same test
// body: once inside tolerance, where the protocol must carry every packet, and
// once past it, where it must lose exactly what the shim took. A shim that did
// nothing fails the second run; a shim that dropped everything fails the first.
//
// The sibling lanes proved their guards the same way — the tun lane pointed its
// fail-closed detector at a check-then-send implementation and required it to
// object, the session lane fed its metronome detector the measured 25.000-second
// series, and the carrier lane ran its own clamping backoff through its own
// atom detector.

// reorderRun displaces exactly ONE message by exactly `distance` places through
// the real three-goroutine loop, and reports what arrived.
func reorderRun(t *testing.T, distance uint64) (sent, got int, st LinkStats) {
	t.Helper()
	p := burstPair(t, PairConfig{})
	p.ToGateway.Arm(Impairment{ReorderAt: 50, ReorderDistance: distance})

	sent = p.OfferInner(300, p.FullPayload())
	got = p.Collect(sent, 40*time.Second)
	st = p.ToGateway.Stats()
	return sent, got, st
}

// TestTheReorderShimIsRealBecauseTheSameRunBreaksPastTolerance.
func TestTheReorderShimIsRealBecauseTheSameRunBreaksPastTolerance(t *testing.T) {
	t.Parallel()

	// Inside tolerance: 60 < 127. Nothing may be lost.
	sent, got, st := reorderRun(t, 60)
	if st.Reordered != 1 || st.MaxDisplacement != 60 {
		t.Fatalf("the shim reordered %d messages at displacement %d; it was told to displace "+
			"exactly one by exactly 60", st.Reordered, st.MaxDisplacement)
	}
	if got != sent {
		t.Fatalf("lost %d packets at a displacement of 60, which is inside the %d-place "+
			"tolerance", sent-got, netlabWindow/2-1)
	}

	// Past it: 200 > 127. Exactly the displaced message must be lost, and
	// exactly one — not the run behind it, which is what a broken force-advance
	// would cost.
	sent2, got2, st2 := reorderRun(t, 200)
	if st2.Reordered != 1 || st2.MaxDisplacement != 200 {
		t.Fatalf("the shim reordered %d messages at displacement %d; it was told to displace "+
			"exactly one by exactly 200", st2.Reordered, st2.MaxDisplacement)
	}
	if got2 != sent2-1 {
		t.Fatalf("delivered %d of %d with ONE message displaced by 200 places at a %d-token "+
			"window. Exactly one packet must be lost: fewer means the shim did not displace "+
			"anything and every reorder result in this package is worthless; more means the "+
			"force-advance rule is discarding traffic it was supposed to keep.",
			got2, sent2, netlabWindow)
	}
}

// lossRun drops every Nth message and reports what arrived.
func lossRun(t *testing.T, every uint64) (sent, got int, st LinkStats) {
	t.Helper()
	p := burstPair(t, PairConfig{})
	if every > 0 {
		p.ToGateway.Arm(Impairment{DropEvery: every})
	}
	sent = p.OfferInner(200, p.FullPayload())
	got = p.Collect(sent, 30*time.Second)
	return sent, got, p.ToGateway.Stats()
}

// TestTheLossShimIsRealBecauseTheSameRunLosesExactlyWhatItTook.
//
// Ordinary loss has no recovery layer under it — a lost DATA frame is recovered
// by inner TCP, which this rig does not have — so the arithmetic is exact and
// the assertion can be an equality rather than a bound. That is worth having:
// an inequality would pass against a shim that dropped twice what it claimed.
func TestTheLossShimIsRealBecauseTheSameRunLosesExactlyWhatItTook(t *testing.T) {
	t.Parallel()

	// No impairment: the control.
	sent, got, st := lossRun(t, 0)
	if got != sent || st.DroppedPeriodic != 0 {
		t.Fatalf("an unimpaired link lost %d of %d packets", sent-got, sent)
	}

	// One in ten.
	const every = 10
	sent2, got2, st2 := lossRun(t, every)
	if st2.DroppedPeriodic == 0 {
		t.Fatal("the shim dropped nothing with DropEvery=10; every loss result in this package " +
			"would be measuring an unimpaired link")
	}

	// The expectation is the shim's OWN RULE applied to the data burst, not the
	// shim's own counter.
	//
	// Those were the same number until 2026-08-10 and are not any more. The data
	// occupies the first sent2 ordinals on the link, so DropEvery=N takes exactly
	// sent2/N of it — measured at 20 of 200, in every run. But Collect can never
	// reach its want on an impaired link, so it waits out its whole budget, and
	// the session's own control traffic keeps crossing the still-armed link for
	// the rest of it. Those messages share the ordinal space, so ordinals 210 and
	// 220 land on control rather than data and DroppedPeriodic comes back 21 or
	// 22 while exactly 20 data packets were lost.
	//
	// The raise did not cause that, it consumed the margin that was hiding it:
	// 200 messages of 1338 bytes take longer to pump than 200 of 1168, so the
	// tail grew past the first multiple of ten and the two quantities came apart.
	// Pinning to the rule keeps the assertion an exact equality — which is the
	// point of it, per the comment above — and makes it independent of how long
	// the tail happens to be. It is also the stricter of the two: comparing the
	// session's loss against the shim's self-report would pass a shim that
	// miscounted consistently, and the shim's books are audited on their own by
	// TestTheLinkAccountsForEveryMessageItWasOffered.
	dataDropped := sent2 / every
	if got2 != sent2-dataDropped {
		t.Fatalf("delivered %d of %d with one message in %d dropped from the burst; want exactly "+
			"%d delivered. Fewer means the session is losing packets the shim did deliver, more "+
			"means something under it is recovering loss that has no recovery layer (link %+v)",
			got2, sent2, every, sent2-dataDropped, st2)
	}
	if st2.DroppedPeriodic < uint64(dataDropped) {
		t.Fatalf("the shim counted %d periodic drops but the burst alone must have cost %d; "+
			"the counter is behind what the link actually took (link %+v)",
			st2.DroppedPeriodic, dataDropped, st2)
	}
}

// TestTheLinkAccountsForEveryMessageItWasOffered is the shim's own audit.
//
// offered = delivered + dropped + still held, with duplicates counted on the
// delivered side. Without this a counter could be moving for the wrong reason
// and every "the impairment was applied" assertion elsewhere would rest on it.
func TestTheLinkAccountsForEveryMessageItWasOffered(t *testing.T) {
	t.Parallel()
	p := burstPair(t, PairConfig{})
	// The cap is the planning path MTU, which is where it has to sit for this
	// test to measure what it says it measures. Link.Offer applies the path-MTU
	// gate FIRST and returns, so a cap below the full-size outer packet stops
	// every full-size message before the loss, reorder and duplicate rules are
	// ever reached — and this test's subject is those three rules balancing the
	// books. It read a literal 1300 until 2026-08-10, chosen when the plan floor
	// was 1168 and a UDP/IPv4-wrapped message was 1196; at the 1450 default the
	// same message is 1366, so 1300 silently turned every rule below it off.
	p.ToGateway.Arm(Impairment{
		DropEvery:       7,
		DuplicateEvery:  5,
		ReorderPeriod:   11,
		ReorderDistance: 20,
		MaxOuterPacket:  p.Sizing.PathMTU,
		OuterOverhead:   28,
	})
	sent := p.OfferInner(200, p.FullPayload())
	p.Collect(sent, 12*time.Second)
	// A little more traffic so the reorder buffer is exercised rather than
	// merely filled.
	p.OfferInner(60, 64)
	_ = p.Collect(60, 5*time.Second)

	st := p.ToGateway.Stats()
	dropped := st.DroppedOversize + st.DroppedBurst + st.DroppedPeriodic + st.DroppedRandom
	// Delivered counts duplicates, so subtract them to get distinct messages out.
	distinctOut := st.Delivered - st.Duplicated
	if distinctOut+dropped+uint64(st.Held) != st.Offered {
		t.Fatalf("the link's own books do not balance: offered %d, delivered %d (of which %d "+
			"duplicates), dropped %d, held %d. Every 'the impairment was applied' assertion in "+
			"this package reads these counters.",
			st.Offered, st.Delivered, st.Duplicated, dropped, st.Held)
	}
	if st.SinkRefused != 0 {
		t.Fatalf("the far-side sink refused %d messages that the link still counted as delivered; "+
			"the books balance and the packets did not arrive", st.SinkRefused)
	}
	if st.Duplicated == 0 || st.Reordered == 0 || st.DroppedPeriodic == 0 {
		t.Fatalf("one of the rules never fired: duplicated=%d reordered=%d droppedPeriodic=%d",
			st.Duplicated, st.Reordered, st.DroppedPeriodic)
	}
}

// TestAPerfectLinkIsLoopback is the other end of the same argument. Every proof
// before this package was written on loopback, so an unarmed Link must be
// indistinguishable from one — otherwise the impairment results are being
// compared against a baseline that is itself impaired.
//
// The Unopenable assertion is a DELTA since 2026-08-10, and the delta is taken
// only after a real round trip (ProveCarrying), for a reason that is measured
// rather than assumed. A handshake retransmission scheduled on an injected
// clock can, on a loaded machine once in tens of runs, be delivered to the
// gateway a moment after the gateway installed its session. Deliver then counts
// it in Stats.Unopenable, which is CORRECT of the session layer — a replayed
// initiation is indistinguishable from noise — and rig.go's Handshake comment
// documents the measurement: step=300ms → injected 900ms → HandshakeMessagesSent
// 2–3 → gateway Unopenable 1–3 (6/6). Nothing about that event says the unarmed
// link was impaired, so an absolute `Unopenable == 0` attributed the handshake's
// own retransmissions to the shim and flaked ~1 in 84 runs with no impairment
// armed anywhere. The rig removed the source of the firing (Handshake injects no
// virtual time, so the retry deadline cannot be reached; establish() clears
// phaseAt and waitForWork stops its timer), and this test now asserts what its
// name claims: during the unarmed data phase, NO new message failed to open.
// The baseline sits after proof that the link is genuinely alive, so the delta
// measures exactly the window this test is about and cannot be satisfied by a
// rig that never carried anything.
func TestAPerfectLinkIsLoopback(t *testing.T) {
	t.Parallel()
	p := burstPair(t, PairConfig{})

	// A real round trip proves the link is alive before the books are trusted.
	// Without it a rig whose link was silently dead could satisfy the delta
	// below vacuously by moving no packets at all.
	if err := p.ProveCarrying(20 * time.Second); err != nil {
		t.Fatalf("nothing crossed the unarmed link before the measurement: %v", err)
	}
	baseUnopenable := p.Gateway.Loop.Session().Stats().Unopenable

	sent := p.OfferInner(400, p.FullPayload())
	got := p.Collect(sent, 40*time.Second)
	st := p.ToGateway.Stats()
	if got != sent {
		t.Fatalf("an unarmed link delivered %d of %d (link %+v)", got, sent, st)
	}
	if st.DroppedOversize+st.DroppedBurst+st.DroppedPeriodic+st.DroppedRandom != 0 ||
		st.Reordered != 0 || st.Duplicated != 0 || st.Held != 0 {
		t.Fatalf("an unarmed link is not a perfect link: %+v", st)
	}
	if s := p.Gateway.Loop.Session().Stats(); s.Unopenable != baseUnopenable {
		t.Fatalf("%d messages failed to open on a perfect link during the unarmed data phase "+
			"(%d before the measurement, %d after); the shim or the session dropped a message "+
			"it was supposed to open", s.Unopenable-baseUnopenable, baseUnopenable, s.Unopenable)
	}
}

// TestTeethInterleavedBurstLossAndReorderStayBounded is the teeth stress the
// brief asks for: burst loss and reorder both armed on the SAME direction at
// the same time, through the real three-goroutine rig, with the reordering
// asserted to stay BOUNDED.
//
// A rig that prods one impairment at a time proves nothing about the two
// interacting. Both funnel through the same force-advance rule in
// core/replay.go: a burst of lost messages retires the low edge over a run of
// live counters the receiver never sees, while reordering delays other
// messages behind it. The claim when they act together is that reordering is
// still bounded — every displaced message moves by at most the keep bound
// (half the window minus one) and, inside that bound, costs nothing on top of
// the burst's own take.
//
// Three assertions carry the teeth, and each has a failure mode checked by the
// mutation protocol rather than asserted by name:
//
//   - BOTH instruments fire. DroppedBurst must swallow the configured run and
//     Reordered must be non-zero, or every number below is measuring a link
//     that did not degrade the way this test says it did.
//   - BOUNDED reordering. The shim's recorded max displacement must be exactly
//     the configured distance — the reorder rule is exact by construction, so
//     any other value means it stopped applying its own arithmetic — and it
//     must sit strictly inside the window's keep bound. A displacement at or
//     past half the window is a message the receiver force-advances out, which
//     is guaranteed loss rather than bounded reordering.
//   - Nothing beyond the burst is lost. After disarming, every held reordered
//     message arrives, the delivered count balances to "sent minus the burst",
//     and neither end tears down: a survivable stress must leave both sessions
//     established and neither asking for a new one.
//
// Mutating link.go's reorder release to displace by four times the configured
// distance turns every one of these red (MaxDisplacement stops matching,
// breaches the keep bound, and the displaced messages are dropped past
// tolerance), which is what "the assertion can fail" means here.
//
// offer is capped so (offer - burst) sits strictly inside the keep bound.
// OfferInner queues every packet on Device.in before Settle runs, and the
// write loop keeps blasting them until Disarm. A delayed Disarm then dumps
// held messages into a receive window that has already force-advanced past
// them. Measured 2026-08-12: offer=400 (250 post-burst > 127 keep) failed
// 249/250 under a parallel suite in 40.02s (link Offered=439); the same body
// with no other tests running delivered 250/250 in 0.01s with Held=6 at
// Settle. Disarm is also invoked inside the Settle cond, so a descheduled
// test goroutine cannot sit between "impairments fired" and the flush.
func TestTeethInterleavedBurstLossAndReorderStayBounded(t *testing.T) {
	t.Parallel()
	p := burstPair(t, PairConfig{})

	const (
		burst        = 150 // < netlabWindow 256, so the burst is inside the cliff
		reorderEvery = 11
		reorderDist  = 60 // inside the keep bound netlabWindow/2-1 == 127
		keepBound    = netlabWindow/2 - 1
		offer        = burst + keepBound - 16 // 261; 111 post-burst < 127 even if Disarm waits until the queue drains
	)

	// Both instruments on the same direction at the same time. This is the
	// interleaving the brief is about: a censor's burst outage and a congested
	// path's reordering are not an either/or.
	p.ToGateway.Arm(Impairment{
		DropFrom:        1,
		DropCount:       burst,
		ReorderPeriod:   reorderEvery,
		ReorderDistance: reorderDist,
	})

	sent := p.OfferInner(offer, p.FullPayload())
	if sent < int(burst) {
		t.Fatalf("the client's host device accepted only %d of %d packets, fewer than the "+
			"%d-message burst; the rig itself broke and this test proves nothing",
			sent, offer, burst)
	}

	// The negative assertions below mean nothing if the impairments never fired.
	// Disarm the moment they have, before the still-queued post-burst packets
	// can advance the receiver's window past the held messages.
	var fired LinkStats
	var disarmed bool
	if err := p.Settle(30*time.Second, time.Millisecond, func() bool {
		st := p.ToGateway.Stats()
		if st.DroppedBurst >= burst && st.Reordered >= 1 {
			if !disarmed {
				fired = st
				p.ToGateway.Disarm()
				disarmed = true
			}
			return true
		}
		return false
	}); err != nil {
		st := p.ToGateway.Stats()
		t.Fatalf("the interleaved rig dropped %d of %d burst messages and reordered %d "+
			"(link %+v); one of the two instruments never fired and every value below "+
			"measures a direction that was not impaired the way this test says",
			st.DroppedBurst, burst, st.Reordered, st)
	}

	if fired.MaxDisplacement != reorderDist {
		t.Fatalf("the reorder shim displaced by up to %d places, not the %d it was configured "+
			"with; the exact reorder rule is not applying its own distance",
			fired.MaxDisplacement, reorderDist)
	}
	if fired.MaxDisplacement > uint64(keepBound) {
		t.Fatalf("a message was displaced %d places, at/past the %d-place keep bound of a "+
			"%d-token window; the receiver force-advances such a message out, so the "+
			"interleaved run manufactured guaranteed loss rather than bounded reordering",
			fired.MaxDisplacement, keepBound, netlabWindow)
	}

	want := sent - int(burst)
	got := p.Collect(want, 40*time.Second)
	if got != want {
		t.Fatalf("interleaved burst loss (%d) + reorder (%d places) delivered %d of the %d "+
			"non-burst packets; a burst inside the window must cost exactly the burst and "+
			"a bounded reorder must cost nothing on top of it (link %+v fired %+v)",
			burst, reorderDist, got, want, p.ToGateway.Stats(), fired)
	}
	if p.Client.Loop.Session().NeedsNewSession() || p.Gateway.Loop.Session().NeedsNewSession() {
		t.Fatalf("the interleaved burst+bounded-reorder run ended in NeedsNewSession "+
			"(client %v, gateway %v); an inside-window burst with bounded reorder must not "+
			"tear the session down",
			p.Client.Loop.Session().NeedsNewSession(), p.Gateway.Loop.Session().NeedsNewSession())
	}
	if p.Client.Loop.Session().State() != session.StateEstablished ||
		p.Gateway.Loop.Session().State() != session.StateEstablished {
		t.Fatalf("client=%s gateway=%s after an inside-window burst interleaved with bounded "+
			"reorder; a survivable stress must leave both ends established",
			p.Client.Loop.Session().State(), p.Gateway.Loop.Session().State())
	}
}
