package netlab

import (
	"context"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
)

// The prediction under test, from the brief: "the design tolerates half a
// window by the force-advance rule — 128 packets at a 256-token window."
//
// The rule in winn3/core/replay.go is:
//
//	if half := size/2; counter >= low+half { forceAdvance(counter - half + 1) }
//
// so consuming counter c retires the low edge to c-half+1, and a message whose
// counter is BELOW that is gone. A message displaced by d positions is
// therefore still inside the window while d <= half-1 and lost at d == half.
//
// That is 127, not 128. The claim is off by one, and this file measures the
// boundary rather than asserting either number.

const netlabWindow = 256

func newReorderDuplex(t *testing.T) *Duplex {
	t.Helper()
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDuplex(kr, DuplexConfig{TokenWindow: netlabWindow, SendQueue: 2048})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Handshake(200); err != nil {
		t.Fatal(err)
	}
	return d
}

// displacementSurvives reports whether a single message displaced by exactly
// `distance` positions still reaches the far side.
func displacementSurvives(t *testing.T, distance int) bool {
	t.Helper()
	d := newReorderDuplex(t)

	const n = 400
	const at = 150
	msgs, err := d.Produce(d.Client, n, 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != n {
		t.Fatalf("produced %d messages for %d inner packets; the rig is coalescing and the "+
			"displacement would not be a counter distance", len(msgs), n)
	}
	got, err := d.DeliverPermuted(d.Gateway, msgs, DisplacedOrder(n, at, distance))
	if err != nil {
		t.Fatalf("gateway refused delivery at distance %d: %v", distance, err)
	}
	if got != n && got != n-1 {
		t.Fatalf("distance %d delivered %d of %d inner packets; expected all or all-but-the-displaced-one, "+
			"so something other than the force-advance rule is dropping traffic", distance, got, n)
	}
	return got == n
}

// TestReorderToleranceIsHalfTheWindowMinusOne is the measurement. It sweeps the
// boundary rather than asserting a remembered constant, and it requires the
// answer to be a CLIFF: monotone, with exactly one transition. A tolerance that
// was probabilistic would show up here as a ragged edge.
func TestReorderToleranceIsHalfTheWindowMinusOne(t *testing.T) {
	t.Parallel()
	half := netlabWindow / 2

	// The two sides of the boundary, measured.
	if !displacementSurvives(t, half-1) {
		t.Fatalf("a message displaced by %d was LOST at a %d-token window; "+
			"the force-advance rule tolerates less than the handoff documents claim", half-1, netlabWindow)
	}
	if displacementSurvives(t, half) {
		t.Fatalf("a message displaced by %d SURVIVED at a %d-token window; "+
			"the window is wider than winn3/core/replay.go's force-advance rule allows, "+
			"which means the replay filter is not the exact filter it claims to be", half, netlabWindow)
	}

	// And the shape either side, so the boundary is a cliff and not a coincidence.
	for _, d := range []int{1, 2, 63, 100, half - 2} {
		if !displacementSurvives(t, d) {
			t.Fatalf("displacement %d was lost but %d survived; the tolerance is not monotone", d, half-1)
		}
	}
	for _, d := range []int{half + 1, half + 40, netlabWindow - 1} {
		if displacementSurvives(t, d) {
			t.Fatalf("displacement %d survived but %d did not; the tolerance is not monotone", d, half)
		}
	}
}

// TestTheClaimedHalfWindowIsOffByOne states the finding as its own failing
// assertion, so a later reader who changes the rule sees WHICH claim moved.
func TestTheClaimedHalfWindowIsOffByOne(t *testing.T) {
	t.Parallel()
	half := netlabWindow / 2
	if displacementSurvives(t, half) {
		t.Fatalf("the documented tolerance of %d (half a %d-token window) now holds; "+
			"WINN3_NETWORK_REALISM_20260808.md §3.1 records that it did NOT, and the "+
			"handoff needs updating rather than this test deleting", half, netlabWindow)
	}
}

// TestReorderCostsNothingWhenItIsToleratedchecks the half of the property that
// is easy to forget: inside tolerance, a reordered message must not merely
// arrive, it must arrive INTACT and must not disturb anything around it.
func TestReorderCostsNothingWhenItIsTolerated(t *testing.T) {
	t.Parallel()
	d := newReorderDuplex(t)

	const n = 400
	msgs, err := d.Produce(d.Client, n, 64)
	if err != nil {
		t.Fatal(err)
	}

	// Every message in the run displaced by 100 places, not just one.
	perm := make([]int, 0, n)
	for i := 0; i < n; i += 101 {
		end := i + 101
		if end > n {
			end = n
		}
		block := make([]int, 0, end-i)
		for j := end - 1; j >= i; j-- {
			block = append(block, j)
		}
		perm = append(perm, block...)
	}
	got, err := d.DeliverPermuted(d.Gateway, msgs, perm)
	if err != nil {
		t.Fatal(err)
	}
	if got != n {
		t.Fatalf("delivered %d of %d inner packets with every block of 101 fully reversed; "+
			"a reversal of 100 places is inside the %d-place tolerance and must cost nothing",
			got, n, netlabWindow/2-1)
	}
	if st := d.Gateway.Stats(); st.Unopenable != 0 {
		t.Fatalf("%d messages failed to open under tolerated reorder; the window is not "+
			"order-independent inside its bound", st.Unopenable)
	}
	if d.Gateway.State() != session.StateEstablished {
		t.Fatalf("gateway is %s after tolerated reorder; reorder inside the window must not "+
			"be a teardown trigger", d.Gateway.State())
	}
}

// TestADuplicateIsRefusedExactlyAndCostsNothing covers the third thing the
// token window is: an exact replay filter. A duplicate is what a retransmitting
// middlebox and a replaying attacker both produce, and a filter that let the
// second copy through would deliver one inner IP packet twice.
func TestADuplicateIsRefusedExactlyAndCostsNothing(t *testing.T) {
	t.Parallel()
	d := newReorderDuplex(t)

	const n = 64
	msgs, err := d.Produce(d.Client, n, 64)
	if err != nil {
		t.Fatal(err)
	}
	perm := make([]int, 0, 2*n)
	for i := 0; i < n; i++ {
		perm = append(perm, i, i)
	}
	got, err := d.DeliverPermuted(d.Gateway, msgs, perm)
	if err != nil {
		t.Fatal(err)
	}
	if got != n {
		t.Fatalf("delivered %d inner packets from %d messages each sent twice; the token "+
			"window is supposed to be an EXACT replay filter, so the answer is %d", got, n, n)
	}
	if st := d.Gateway.Stats(); st.Unopenable != uint64(n) {
		t.Fatalf("Unopenable is %d after %d duplicates; every duplicate must be counted and "+
			"none may be delivered", st.Unopenable, n)
	}
	if d.Gateway.State() != session.StateEstablished {
		t.Fatalf("gateway is %s after %d duplicates; a replay must not be a teardown trigger "+
			"or a censor gets one for the price of a capture", d.Gateway.State(), n)
	}
}

// TestReorderSurvivesTheRealPumpIsTheEndToEndConfirmation runs the same
// property through the actual three-goroutine loop over an impaired link, so
// the exact rig's answer is not the only evidence.
func TestReorderSurvivesTheRealPumpIsTheEndToEndConfirmation(t *testing.T) {
	t.Parallel()
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPair(kr, PairConfig{TokenWindow: netlabWindow, SendQueue: 2048})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	if err := p.Handshake(20 * time.Second); err != nil {
		t.Fatal(err)
	}

	// Prove a round trip, then take the baseline for the unopenable count.
	//
	// The count is baselined rather than required to be zero outright because a
	// zero test attributes the HANDSHAKE's own retransmissions to the reorder
	// shim. Evidence that they are unrelated: TestAPerfectLinkIsLoopback, which
	// arms no impairment at all, was measured reporting 1 and 2 messages "failed
	// to open on a perfect link" under load — with no reorder anywhere in the
	// run, so neither the shim nor the force-advance rule can be responsible. A
	// slow handshake retransmits, the duplicate arrives after the session is
	// installed, and session.Driver.Deliver counts it as unopenable, which is
	// correct of it and nothing to do with displacement.
	//
	// The delta below is exactly as strict about the property this test is for:
	// a message that was merely LATE must still open. It just stops charging
	// that property for something that happened before the impairment existed.
	if err := p.ProveCarrying(20 * time.Second); err != nil {
		t.Fatalf("nothing crossed before the impairment was armed: %v", err)
	}
	baseUnopenable := p.Gateway.Loop.Session().Stats().Unopenable

	// One in every eight messages held back by 60 places — well inside the
	// 127-place tolerance the exact rig measured, and far outside anything
	// loopback has ever produced.
	p.ToGateway.Arm(Impairment{ReorderPeriod: 8, ReorderDistance: 60})

	// Full-size packets, one per message. The session coalesces small packets
	// ten to a message, so a rig that offered small ones would apply a tenth of
	// the displacement it configured.
	const n = 300
	sent := p.OfferInner(n, p.FullPayload())

	// Collect until everything that has not arrived is accounted for by the
	// shim's own buffer, rather than sitting out a fixed 40 seconds.
	//
	// The fixed wait was not merely slow, it was corrosive. The tail is held for
	// good — nothing follows it to trigger its release — so the old
	// Collect(sent, 40s) ALWAYS ran the full budget, and all the while the
	// session kept probing across the same link and the gateway's receive window
	// kept advancing past messages the shim was still holding. Given enough of
	// that, a held message ages out of the 127-place tolerance and arrives
	// unopenable, which is a failure the rig manufactured by waiting. Measured:
	// "1 messages failed to open at the gateway under a tolerated displacement".
	// Leaving as soon as the books balance keeps the exposure near a second.
	got := 0
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
		got += p.Collect(sent-got, 250*time.Millisecond)
		if sent-got <= p.ToGateway.Stats().Held {
			break
		}
	}

	st := p.ToGateway.Stats()
	if st.Reordered == 0 {
		t.Fatalf("the link reordered nothing; the impairment was not applied and this test proves "+
			"nothing (link %+v, client loop %+v, gateway loop %+v, client tun %+v)",
			st, p.Client.Loop.Stats(), p.Gateway.Loop.Stats(), p.Client.Loop.Tunnel().Stats())
	}
	if st.MaxDisplacement != 60 {
		t.Fatalf("max displacement was %d, want exactly 60; the shim did not displace what it claimed",
			st.MaxDisplacement)
	}

	// The tail sits in the reorder buffer because nothing followed it — which is
	// what a real held packet does, and is the reason the accounting is
	// arrived + still-in-flight rather than a bare total. Disarming releases
	// them, and every one must then arrive: a displacement of 60 is inside the
	// 127-place tolerance, so the ONLY packets missing may be the ones the shim
	// is still holding.
	//
	// The accounting below is an INEQUALITY in packets and then an EQUALITY
	// after the release, and the reason is a measured false failure. It used to
	// read `got + st.Held != sent`, which silently assumes every message the
	// shim holds carries exactly one inner packet. It does not: the session's
	// own liveness probes are messages too, they cross the same link, and
	// ReorderPeriod holds every EIGHTH message whatever it happens to contain.
	// A captured failure: 307 messages offered for 300 inner packets — seven of
	// them control — with 8 held and 293 delivered, so 293+8=301 and the test
	// failed for being off by exactly the one PING that landed on a multiple of
	// eight. Whether a probe lands there is a coin toss the machine's load
	// decides, which is a 1-in-8 false red on a conformance assertion.
	//
	// A held message carries at most one inner packet, so "packets outstanding
	// must not exceed messages held" is true regardless of what is in them, and
	// the release below then demands every last packet — which is stronger than
	// the equality it replaces, because that one tolerated `sent-got` missing
	// packets as long as the number happened to match.
	if sent-got > st.Held {
		t.Fatalf("delivered %d of %d inner packets with only %d messages still held by the shim, "+
			"so %d packets are unaccounted for; a displacement of 60 is inside the %d-place "+
			"tolerance, and the only packets that may be missing are ones the shim is still "+
			"holding (link %+v)",
			got, sent, st.Held, (sent-got)-st.Held, netlabWindow/2-1, st)
	}
	p.ToGateway.Disarm()
	if rest := p.Collect(sent-got, 20*time.Second); got+rest != sent {
		t.Fatalf("after disarming, %d of the %d inner packets still owed arrived, %d of %d "+
			"overall; a message that was merely late must still be openable (link %+v)",
			rest, sent-got, got+rest, sent, p.ToGateway.Stats())
	}
	if ds := p.Gateway.Loop.Stats(); ds.InnerRejected != 0 {
		t.Fatalf("the gateway's tun layer rejected %d inner packets under reorder; a reordered "+
			"packet is still a valid packet", ds.InnerRejected)
	}
	if s := p.Gateway.Loop.Session().Stats(); s.Unopenable != baseUnopenable {
		t.Fatalf("%d messages failed to open at the gateway under a tolerated displacement "+
			"(%d before the impairment was armed, %d after); the force-advance rule dropped "+
			"something it was supposed to hold",
			s.Unopenable-baseUnopenable, baseUnopenable, s.Unopenable)
	}
}

// TestTheWindowRefusesAMessageTooFarAHEAD is the other edge, and it is the one
// nobody writes a test for. holds() bounds the window at BOTH ends, so a
// message that arrives far in front of the low edge is refused exactly as one
// that arrives far behind it is.
func TestTheWindowRefusesAMessageTooFarAhead(t *testing.T) {
	t.Parallel()
	d := newReorderDuplex(t)

	const n = 400
	msgs, err := d.Produce(d.Client, n, 64)
	if err != nil {
		t.Fatal(err)
	}
	// Deliver message 300 first, with low still at 0. 300 >= 0+256, so the
	// token is not in the index at all.
	inner, err := d.Gateway.Deliver(msgs[300])
	if err != nil {
		t.Fatal(err)
	}
	if len(inner) != 0 {
		t.Fatalf("a message %d counters ahead of the low edge was delivered at a %d-token "+
			"window; the window bound is not being applied at the high edge", 300, netlabWindow)
	}
	if st := d.Gateway.Stats(); st.Unopenable != 1 {
		t.Fatalf("Unopenable is %d, want 1", st.Unopenable)
	}
	// And it stays lost: the rest of the run arriving in order does not rescue it.
	perm := make([]int, 0, n-1)
	for i := 0; i < n; i++ {
		if i == 300 {
			continue
		}
		perm = append(perm, i)
	}
	got, err := d.DeliverPermuted(d.Gateway, msgs, perm)
	if err != nil {
		t.Fatal(err)
	}
	if got != n-1 {
		t.Fatalf("delivered %d of the remaining %d inner packets after one arrived too early; "+
			"an early arrival must cost exactly itself", got, n-1)
	}
}

// TestCoreWindowBoundsAreWhatThisFileAssumes pins the constants the numbers
// above are derived from, so a change to core's window sizing breaks this file
// loudly rather than silently moving every boundary it measures.
func TestCoreWindowBoundsAreWhatThisFileAssumes(t *testing.T) {
	t.Parallel()
	if core.MinTokenWindow > netlabWindow || netlabWindow > core.MaxTokenWindow {
		t.Fatalf("this file measures at a %d-token window, outside core's [%d,%d]",
			netlabWindow, core.MinTokenWindow, core.MaxTokenWindow)
	}
	if core.DefaultTokenWindow != 1024 {
		t.Fatalf("core.DefaultTokenWindow is %d, not 1024; the SHIPPING reorder tolerance is "+
			"half of it minus one (%d) and the handoff document says 511",
			core.DefaultTokenWindow, core.DefaultTokenWindow/2-1)
	}
}
