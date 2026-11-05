package dpbridge

import (
	"errors"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/datapath"
	"winsvpn.local/winnprotocol/winn3/carrier"
)

func at(sec int) time.Time {
	return time.Date(2026, 8, 8, 12, 0, sec, 0, time.UTC)
}

// TestNameMappingAgreesOnUDPSurvival is the cross-check that catches a
// mis-mapping, and it is deliberately not a table of expected strings.
//
// Two enumerations describe the same world in two vocabularies. What must agree
// is the only property either of them uses to decide anything: whether a carrier
// still works on a network that drops UDP. Asserting the strings would pass with
// ClassTLS mapped to a UDP carrier as long as somebody wrote the same wrong
// string in the test; asserting the property cannot.
func TestNameMappingAgreesOnUDPSurvival(t *testing.T) {
	for _, class := range []carrier.Class{
		carrier.ClassUnknown, carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS,
	} {
		name := CarrierName(class)
		if got, want := datapath.CarrierSurvivesUDPBlock(name), class.SurvivesUDPBlock(); got != want {
			t.Fatalf("class %s maps to %q: datapath says survives=%v, winn3 says %v",
				class, name, got, want)
		}
		if class.Stream() && datapath.CarrierTransportOf(name) != datapath.TransportTCP {
			t.Fatalf("stream class %s maps to %q, which the datapath does not call TCP", class, name)
		}
	}
	// An unknown class must not acquire a name, and the empty name must not
	// promise survival. The safe default for "we cannot tell" is not to promise.
	if CarrierName(carrier.ClassUnknown) != "" {
		t.Fatal("an unknown class was given a plausible carrier name")
	}
	if datapath.CarrierSurvivesUDPBlock("") {
		t.Fatal("the empty carrier name promises UDP-block survival")
	}
}

// TestClassForRoundTrips checks the inverse over the two names that have a v3
// carrier, and pins the TLS choice: the datapath's HTTP/2 carrier is TLS, and a
// host that dialled bare TCP for it would be 22 bytes wider than the plan floor
// charged.
func TestClassForRoundTrips(t *testing.T) {
	if got := ClassFor(datapath.CarrierDirectAWG); got != carrier.ClassUDP {
		t.Fatalf("direct-awg maps back to %s", got)
	}
	if got := ClassFor(datapath.CarrierHTTP2); got != carrier.ClassTLS {
		t.Fatalf("http2-stream maps back to %s, want tls", got)
	}
	if got := ClassFor("something-else"); got != carrier.ClassUnknown {
		t.Fatalf("an unknown name maps to %s, want unknown", got)
	}
	for _, c := range []carrier.Class{carrier.ClassUDP, carrier.ClassTLS} {
		if got := ClassFor(CarrierName(c)); got != c {
			t.Fatalf("%s round-tripped to %s", c, got)
		}
	}
}

// TestPlanCollapsesTheTwoStreamClasses checks the de-duplication, and then
// checks the thing that makes it necessary: the datapath refuses a plan that
// names one carrier twice, so a v3 plan of UDP, TCP, TLS must arrive as two
// entries or the policy will not build at all.
func TestPlanCollapsesTheTwoStreamClasses(t *testing.T) {
	got := Plan([]carrier.Class{carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS})
	if len(got) != 2 {
		t.Fatalf("the plan is %v, want two entries", got)
	}
	if got[0] != datapath.CarrierDirectAWG || got[1] != datapath.CarrierHTTP2 {
		t.Fatalf("the plan is %v, want the datagram carrier then the stream carrier", got)
	}
	if _, err := NewPolicy(
		datapath.EscalationConfig{Mode: datapath.EscalationObserve},
		[]carrier.Class{carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS},
		carrier.ClassUDP,
	); err != nil {
		t.Fatalf("the committed policy refused a v3 plan: %v", err)
	}
	// An unknown class is dropped rather than given a name, which leaves a plan
	// the datapath validates on its own terms.
	if got := Plan([]carrier.Class{carrier.ClassUnknown, carrier.ClassUDP}); len(got) != 1 {
		t.Fatalf("an unknown class survived into the plan: %v", got)
	}
}

// TestAnAllUDPPlanIsRefused checks that the committed refusal is reached rather
// than reimplemented. A plan with no successor that survives a UDP block is not
// an escalation plan, and the rule lives in datapath's normalizeEscalationPlan.
func TestAnAllUDPPlanIsRefused(t *testing.T) {
	_, err := NewPolicy(
		datapath.EscalationConfig{Mode: datapath.EscalationObserve},
		[]carrier.Class{carrier.ClassUDP},
		carrier.ClassUDP,
	)
	if err == nil {
		t.Fatal("a plan whose only carrier rides UDP was accepted")
	}
}

// TestScenarioBIsDiagnosedAndAnswered is the measured defect, driven all the way
// through: 24 datagrams sent, none received, budget spent.
//
// The datapath must call it blocked and must name a successor that actually
// helps. Both facts come from the committed code; this test asserts that the
// evidence arrives there in a form it can use.
func TestScenarioBIsDiagnosedAndAnswered(t *testing.T) {
	policy, err := NewPolicy(
		datapath.EscalationConfig{Mode: datapath.EscalationObserve},
		[]carrier.Class{carrier.ClassUDP, carrier.ClassTLS},
		carrier.ClassUDP,
	)
	if err != nil {
		t.Fatal(err)
	}

	sig := carrier.Signal{
		Class:       carrier.ClassUDP,
		NeedsChange: true,
		Stats:       carrier.Stats{Sent: 24, SentBytes: 24 * 1168},
	}
	ev := Assess(policy, sig, at(0), at(30))

	if ev.Assessment.Verdict != datapath.VerdictBlocked {
		t.Fatalf("verdict is %s, want blocked; reason %q",
			ev.Assessment.Verdict, ev.Assessment.Reason)
	}
	if ev.Assessment.Recommended == "" {
		t.Fatal("a blocked carrier produced no recommendation")
	}
	if !ev.Assessment.RecommendedSurvivesUDPBlock {
		t.Fatalf("the recommendation %q does not survive a UDP block",
			ev.Assessment.Recommended)
	}
	if got := ClassFor(ev.Assessment.Recommended); got != carrier.ClassTLS {
		t.Fatalf("the recommendation maps back to %s, which a host cannot dial as a stream carrier", got)
	}
	if !ev.NeedsCarrierChange {
		t.Fatal("the session's own signal was lost on the way through")
	}
}

// TestHealthyCarrierIsNeverCalledBlocked is the direction that matters most: a
// false blocked verdict tears down a tunnel that was working, and the user is
// then rebuilt onto a slower carrier for no reason.
func TestHealthyCarrierIsNeverCalledBlocked(t *testing.T) {
	policy, err := NewPolicy(
		datapath.EscalationConfig{Mode: datapath.EscalationObserve},
		[]carrier.Class{carrier.ClassUDP, carrier.ClassTLS},
		carrier.ClassUDP,
	)
	if err != nil {
		t.Fatal(err)
	}
	sig := carrier.Signal{
		Class: carrier.ClassUDP,
		Stats: carrier.Stats{Sent: 400, Delivered: 380, LastDelivered: at(29)},
	}
	ev := Assess(policy, sig, at(0), at(30))
	if ev.Assessment.Verdict != datapath.VerdictHealthy {
		t.Fatalf("a carrier that delivered a datagram one second ago is %s: %q",
			ev.Assessment.Verdict, ev.Assessment.Reason)
	}
	if ev.Assessment.Recommended != "" {
		t.Fatal("a healthy carrier produced a recommendation to leave it")
	}
}

// TestInboundIsSourcedFromArrivalNotFromRead is the counter bug, checked at the
// place where it would do the most damage.
//
// The escalation lane shipped a verdict sourced from a counter that moved on the
// HOST's read. On this path the same mistake tells a policy layer about how
// promptly this process drained a queue rather than about the network, so a busy
// handset looks censored and a live tunnel is torn down to be rebuilt on a
// slower carrier. carrier.Pipe is the only carrier with a queue between arrival
// and read, which makes it the only place the property is testable.
func TestInboundIsSourcedFromArrivalNotFromRead(t *testing.T) {
	pipe, err := carrier.NewPipe(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := pipe.Deliver([]byte("a message that has arrived and not been read")); err != nil {
			t.Fatal(err)
		}
	}
	// Nothing is read. Deliberately.
	sig := carrier.Observe(nil, pipe)
	obs := Observation(sig, at(0), time.Now())
	if !obs.InboundSeen {
		t.Fatal("five messages arrived and the observation reports nothing inbound; " +
			"the counter is being read from the delivery path rather than the receive path")
	}
}

// TestForeignDatagramsCannotHoldTheVerdictOff is the failover-suppression
// attack, stated at this layer.
//
// An off-path attacker who has found the five-tuple can spray datagrams at it.
// If those moved the delivery counters, the attacker could hold a blocked
// carrier's health indicator up and pin a user on a transport carrying nothing,
// for the price of one spoofed packet per second. winn3/carrier closes it by
// counting them as Foreign and nothing else; what this checks is that the bridge
// does not undo that by reading the wrong field.
func TestForeignDatagramsCannotHoldTheVerdictOff(t *testing.T) {
	policy, err := NewPolicy(
		datapath.EscalationConfig{Mode: datapath.EscalationObserve},
		[]carrier.Class{carrier.ClassUDP, carrier.ClassTLS},
		carrier.ClassUDP,
	)
	if err != nil {
		t.Fatal(err)
	}
	sig := carrier.Signal{
		Class: carrier.ClassUDP,
		Stats: carrier.Stats{Sent: 24, Foreign: 5000},
	}
	obs := Observation(sig, at(0), at(30))
	if obs.InboundSeen {
		t.Fatal("foreign datagrams were counted as inbound traffic")
	}
	if got := policy.Evaluate(obs).Verdict; got != datapath.VerdictBlocked {
		t.Fatalf("verdict is %s; a spray of foreign datagrams held the blocked verdict off", got)
	}
}

// TestObservationFailsTowardsTheWorkingTunnel pins the two directions of the
// timestamp edge case, because they are not symmetric.
//
// A carrier that counted an arrival but left no timestamp must be read as
// "something arrived just now", not as "nothing ever arrived". The first costs a
// late escalation; the second tears down a working tunnel.
func TestObservationFailsTowardsTheWorkingTunnel(t *testing.T) {
	noStamp := carrier.Signal{Stats: carrier.Stats{Sent: 24, Delivered: 3}}
	obs := Observation(noStamp, at(0), at(30))
	if !obs.InboundSeen {
		t.Fatal("an arrival without a timestamp was read as no arrival at all")
	}
	if obs.SinceInbound != 0 {
		t.Fatalf("SinceInbound is %s with no timestamp, want zero", obs.SinceInbound)
	}

	nothing := carrier.Signal{Stats: carrier.Stats{Sent: 24}}
	if Observation(nothing, at(0), at(30)).InboundSeen {
		t.Fatal("a carrier that delivered nothing reports inbound traffic")
	}

	// Clock skew between the carrier's clock and the caller's must not produce a
	// negative interval, which would read as "arrived in the future".
	skewed := carrier.Signal{Stats: carrier.Stats{Sent: 1, Delivered: 1, LastDelivered: at(90)}}
	got := Observation(skewed, at(60), at(30))
	if got.SinceInbound < 0 || got.Elapsed < 0 {
		t.Fatalf("clock skew produced negative evidence: %+v", got)
	}
}

// TestEvidenceCombinesNothing checks the boundary this package draws. The
// session's §4.2 signal and the datapath's datagram verdict are different claims
// about different things, and a caller that acts on one must be able to see the
// other. Merging them here would erase a distinction the caller needs: a session
// whose handshake budget is spent on a carrier that is demonstrably delivering
// datagrams is a gateway problem, not a censorship problem.
func TestEvidenceCombinesNothing(t *testing.T) {
	policy, err := NewPolicy(
		datapath.EscalationConfig{Mode: datapath.EscalationObserve},
		[]carrier.Class{carrier.ClassUDP, carrier.ClassTLS},
		carrier.ClassUDP,
	)
	if err != nil {
		t.Fatal(err)
	}
	sig := carrier.Signal{
		Class:           carrier.ClassUDP,
		NeedsChange:     true,
		NeedsNewSession: true,
		Stats:           carrier.Stats{Sent: 40, Delivered: 40, LastDelivered: at(29)},
	}
	ev := Assess(policy, sig, at(0), at(30))

	if ev.Assessment.Verdict != datapath.VerdictHealthy {
		t.Fatalf("the session's signal changed the link verdict to %s", ev.Assessment.Verdict)
	}
	if !ev.NeedsCarrierChange || !ev.NeedsNewSession {
		t.Fatal("the link verdict changed the session's signals")
	}
}

// TestARebindIsNotABlockAndABlockIsNotARebind is the whole of §5.3 of
// WINN3_NETWORK_REALISM_20260808.md, resolved.
//
// The two failures are byte-for-byte identical in a datagram carrier's old
// counters — Foreign climbing at line rate, Delivered frozen, LastDelivered
// stuck at the moment of the change — and they want opposite responses. A rebind
// wants the return path updated; a block wants a carrier-class escalation. Get
// it wrong in the escalation direction and every mobile user pays a re-handshake
// and ~43 s of dead tunnel each time they change cell.
//
// The discriminator is carrier.Stats.PeerMoves, and it is sound because only an
// AEAD-authenticated event can move it: carrier.UDP.SetPeer's contract is that
// it is called from the source of a datagram that DISPATCHED. Foreign is not and
// can never be the discriminator — an off-path attacker produces exactly the
// same Foreign climb, and following it would hand that attacker the return path.
func TestARebindIsNotABlockAndABlockIsNotARebind(t *testing.T) {
	policy, err := NewPolicy(
		datapath.EscalationConfig{Mode: datapath.EscalationObserve},
		[]carrier.Class{carrier.ClassUDP, carrier.ClassTLS},
		carrier.ClassUDP,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Scenario B, the measured censorship failure: sent a lot, never heard
	// anything, and a spray of foreign datagrams at the five-tuple on top.
	blocked := carrier.Signal{
		Class: carrier.ClassUDP,
		Stats: carrier.Stats{Sent: 240, Foreign: 5000},
	}
	bev := Assess(policy, blocked, at(0), at(60))
	if bev.Assessment.Verdict != datapath.VerdictBlocked {
		t.Fatalf("a carrier that never heard anything is %s, want blocked", bev.Assessment.Verdict)
	}
	if bev.Rebound {
		t.Fatal("a blocked carrier with 5000 foreign datagrams was reported as a rebind. " +
			"Foreign is exactly as consistent with an off-path attacker as with mobility, so " +
			"reading it as mobility both misses the censor AND suggests following the attacker.")
	}

	// The same shape, plus the one thing a censor cannot produce: the peer moved,
	// on authenticated evidence.
	rebound := blocked
	rebound.Stats.PeerMoves = 1
	rebound.Stats.LastPeerMove = at(58)
	rev := Assess(policy, rebound, at(0), at(60))
	if !rev.Rebound {
		t.Fatal("an authenticated peer move inside the window was not reported as a rebind")
	}
	if rev.Assessment.Verdict == datapath.VerdictBlocked {
		t.Fatalf("a rebound carrier is %s. A NAT rebind must not trigger a carrier-class "+
			"escalation: the transport is fine, the user changed cell, and escalating costs "+
			"them a re-handshake for it.", rev.Assessment.Verdict)
	}
	if !Observation(rebound, at(0), at(60)).InboundSeen {
		t.Fatal("an authenticated peer move was not counted as inbound evidence; it is STRONGER " +
			"than Delivered, which only says a message arrived, not that it opened")
	}

	// And the window closes. A move long enough ago stops excusing a carrier that
	// has heard nothing since, or a single rebind would suppress escalation for
	// the rest of the session's life.
	stale := rebound
	stale.Stats.LastPeerMove = at(1)
	if Rebound(stale, at(0), at(600), DefaultRebindWindow) {
		t.Fatalf("a peer move %s ago is still excusing a silent carrier; the window is %s",
			at(600).Sub(at(1)), DefaultRebindWindow)
	}
	// It is STALLED rather than BLOCKED, and that is the honest verdict: a
	// carrier that once had an authenticated peer move demonstrably carried
	// traffic at some point, which is exactly the distinction datapath draws
	// between the two. What matters is that it is no longer being excused.
	if got := Assess(policy, stale, at(0), at(600)).Assessment.Verdict; got == datapath.VerdictHealthy {
		t.Fatalf("a carrier silent for %s since its last peer move is still %s; one rebind must "+
			"not suppress escalation for the rest of the session's life",
			at(600).Sub(at(1)), got)
	}

	// A move recorded BEFORE this carrier was opened belongs to its predecessor
	// and says nothing about it.
	inherited := rebound
	inherited.Stats.LastPeerMove = at(5)
	if Rebound(inherited, at(30), at(60), DefaultRebindWindow) {
		t.Fatal("a peer move from before this carrier was opened was read as its own")
	}
}

// TestPathNarrowedRidesBesideTheVerdictRatherThanInsideIt pins the second signal
// this package now carries, and the reason it cannot be folded into the verdict.
//
// A narrowed outer path produces a PERFECTLY HEALTHY datagram assessment: every
// write succeeds, because a DF path reports nothing, and small traffic flows
// both ways so LastDelivered is fresh. A caller reading only the Assessment
// would conclude the link was fine while every large transfer on it silently
// died. There is no counter in datapath's vocabulary for that, so it arrives
// beside the verdict.
func TestPathNarrowedRidesBesideTheVerdictRatherThanInsideIt(t *testing.T) {
	policy, err := NewPolicy(
		datapath.EscalationConfig{Mode: datapath.EscalationObserve},
		[]carrier.Class{carrier.ClassUDP, carrier.ClassTLS},
		carrier.ClassUDP,
	)
	if err != nil {
		t.Fatal(err)
	}
	sig := carrier.Signal{
		Class:        carrier.ClassUDP,
		PathNarrowed: true,
		Stats:        carrier.Stats{Sent: 400, Delivered: 120, LastDelivered: at(59)},
	}
	ev := Assess(policy, sig, at(0), at(60))
	if ev.Assessment.Verdict != datapath.VerdictHealthy {
		t.Fatalf("the datagram verdict is %s; a narrowed path really does look healthy to a "+
			"counter that cannot see message sizes, and pretending otherwise here would be this "+
			"package inventing a rule", ev.Assessment.Verdict)
	}
	if !ev.PathNarrowed {
		t.Fatal("the session's size-aware verdict was dropped on the way through, which leaves " +
			"the caller with a healthy link and a tunnel that carries nothing large")
	}
	if Assess(policy, carrier.Signal{Class: carrier.ClassUDP,
		Stats: sig.Stats}, at(0), at(60)).PathNarrowed {
		t.Fatal("PathNarrowed was invented rather than passed through")
	}
}

// TestNewPolicyAdoptsTheClassesPlanNotTheConfigs is the admission edge this
// package's own doc comment states and nothing else pins: NewPolicy OVERWRITES
// cfg.Plan from classes, so the plan the escalation decision validates is the
// plan the message-size floor was computed over. A caller that seeded cfg.Plan
// with a stale or unusable value must not be able to push it through.
//
// Two directions are asserted so the test has teeth in both. Positive: a
// cfg.Plan whose entry has no dialer — which would fail normalize on its own —
// is replaced by the classes-derived plan and the policy builds. Negative: a
// cfg.Plan that is ITSELF valid (it names a UDP-block survivor) is still
// overruled: all-UDP classes yield an all-UDP plan and must be refused even
// though the caller's cfg.Plan would have slipped a TCP successor through.
func TestNewPolicyAdoptsTheClassesPlanNotTheConfigs(t *testing.T) {
	// Positive: garbage cfg.Plan must be overwritten, not honoured.
	policy, err := NewPolicy(
		datapath.EscalationConfig{
			Mode: datapath.EscalationObserve,
			// Deliberately unusable; NewPolicy's contract is to overwrite this.
			Plan: []string{"no-such-carrier"},
		},
		[]carrier.Class{carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS},
		carrier.ClassUDP,
	)
	if err != nil {
		t.Fatalf("an unusable cfg.Plan survived and broke the policy: %v", err)
	}
	got := policy.Plan()
	if len(got) != 2 || got[0] != datapath.CarrierDirectAWG || got[1] != datapath.CarrierHTTP2 {
		t.Fatalf("policy plan is %v, want [direct-awg http2-stream] taken from classes", got)
	}

	// Negative: a cfg.Plan that is individually valid must still not be adopted
	// over what classes say. All-UDP classes name no UDP-block survivor, so the
	// committed plan must be refused even though cfg.Plan carries a TCP
	// successor the caller might have hoped to smuggle in.
	_, err = NewPolicy(
		datapath.EscalationConfig{
			Mode: datapath.EscalationObserve,
			// Valid cfg.Plan: names a survivor after the head.
			Plan: []string{datapath.CarrierDirectAWG, datapath.CarrierHTTP2},
		},
		[]carrier.Class{carrier.ClassUDP}, // classes allow no successor that survives UDP
		carrier.ClassUDP,
	)
	if err == nil {
		t.Fatal("all-UDP classes produced a plan with no UDP-block survivor, but a valid " +
			"cfg.Plan slipped a TCP successor through: admission must follow classes, not cfg.Plan")
	}
}

// TestEvidenceCarriesTheCarriersOwnFatalError pins a field every other test in
// this file leaves alone: Evidence.CarrierErr. A dead carrier and a session
// that wants a different carrier are different facts, and the caller that owns
// the sockets needs the carrier's own last fatal error to see the first.
//
// Both directions are asserted: the error must be recorded when present, and
// must NOT be invented when absent — the second is the negative half the
// catalogue's survivor shape keeps losing.
func TestEvidenceCarriesTheCarriersOwnFatalError(t *testing.T) {
	policy, err := NewPolicy(
		datapath.EscalationConfig{Mode: datapath.EscalationObserve},
		[]carrier.Class{carrier.ClassUDP, carrier.ClassTLS},
		carrier.ClassUDP,
	)
	if err != nil {
		t.Fatal(err)
	}

	sentinel := errors.New("carrier is dead")
	sig := carrier.Signal{
		Class:      carrier.ClassUDP,
		CarrierErr: sentinel,
		Stats:      carrier.Stats{Sent: 400, Delivered: 380, LastDelivered: at(29)},
	}
	ev := Assess(policy, sig, at(0), at(30))
	if ev.CarrierErr != sentinel {
		t.Fatalf("the carrier's fatal error was dropped from Evidence: got %v, want %v",
			ev.CarrierErr, sentinel)
	}
	if ev.Assessment.Verdict != datapath.VerdictHealthy {
		t.Fatalf("recording a CarrierErr rewrote the link verdict to %s; a dead carrier and a "+
			"healthy link are different facts and must both survive", ev.Assessment.Verdict)
	}

	clean := Assess(policy, carrier.Signal{
		Class: carrier.ClassUDP,
		Stats: carrier.Stats{Sent: 400, Delivered: 380, LastDelivered: at(29)},
	}, at(0), at(30))
	if clean.CarrierErr != nil {
		t.Fatalf("Evidence invented a carrier error out of nothing: %v", clean.CarrierErr)
	}
}

// TestEvidenceRecordsDivergenceWhenTheFrameViolatesPolicy is the blocked
// direction of "Evidence combines nothing". The datapath's verdict and the
// session's §4.2 signal are different claims about different things. A frame
// that violates policy — a carrier that sent its budget of datagrams and never
// heard a single one answer — yields a BLOCKED assessment whether or not the
// session's own budget signal has fired yet. Both sides must survive in the
// Evidence, because erasing either side of that divergence hides the
// distinction the package exists to preserve.
func TestEvidenceRecordsDivergenceWhenTheFrameViolatesPolicy(t *testing.T) {
	policy, err := NewPolicy(
		datapath.EscalationConfig{Mode: datapath.EscalationObserve},
		[]carrier.Class{carrier.ClassUDP, carrier.ClassTLS},
		carrier.ClassUDP,
	)
	if err != nil {
		t.Fatal(err)
	}

	// The policy-violating frame, with the session silent: the datapath has its
	// own evidence of a dead link that the session's budget signal has not yet
	// encoded. The divergence must be reported, not resolved one way.
	sig := carrier.Signal{
		Class: carrier.ClassUDP,
		Stats: carrier.Stats{Sent: 240},
	}
	ev := Assess(policy, sig, at(0), at(60))
	if ev.Assessment.Verdict != datapath.VerdictBlocked {
		t.Fatalf("a frame that violates policy (sent %d, heard nothing) is %s, want blocked",
			sig.Stats.Sent, ev.Assessment.Verdict)
	}
	if ev.NeedsCarrierChange {
		t.Fatal("Evidence resolved the divergence by forcing the session's signal onto the " +
			"verdict; the caller must be able to see that the datapath called it blocked " +
			"while the session had not yet")
	}

	// The same frame once the session's signal does fire: both stay visible, the
	// verdict stays blocked, and the recommendation still helps.
	sig.NeedsChange = true
	ev2 := Assess(policy, sig, at(0), at(60))
	if ev2.Assessment.Verdict != datapath.VerdictBlocked {
		t.Fatalf("blocked frame is %s when the session agrees, want blocked", ev2.Assessment.Verdict)
	}
	if !ev2.NeedsCarrierChange {
		t.Fatal("the session's spent-handshake signal was dropped from Evidence")
	}
	if !ev2.Assessment.RecommendedSurvivesUDPBlock {
		t.Fatalf("recommendation %q does not survive a UDP block", ev2.Assessment.Recommended)
	}
}
