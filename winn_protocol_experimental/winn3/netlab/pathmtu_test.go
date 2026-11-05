package netlab

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// Property 4: a real path MTU.
//
// Two things to test. The tun layer REFUSES to start when the inner MTU would
// fall below the IPv6 floor of 1280, and it synthesises an inward-only ICMP
// path-MTU signal for an oversize inner packet. Both hold. The third thing —
// which the brief asked for and which nothing in the tree covers — is a
// MID-SESSION MTU drop, and that is where this property breaks.

// --- the refusal --------------------------------------------------------------

// TestTheIPv6FloorRefusalHoldsAtTheBoundary walks the boundary rather than
// asserting one value, so a change to the arithmetic moves the failure to the
// number that moved.
//
// It covers both guards on the same fact, at the same byte:
//
//  1. driver.NewSizing refuses a planning path MTU one byte below the boundary
//     (added 2026-08-10 with the fleet raise to 1450), and
//  2. tun.New still refuses an inner IPv6 assignment below the floor, which is
//     what catches a host that reached the same inner MTU some other way.
func TestTheIPv6FloorRefusalHoldsAtTheBoundary(t *testing.T) {
	t.Parallel()
	// A UDP-only plan needs 1357 of outer path before inner IPv6 is possible;
	// a plan that includes TLS needs 1421. Both numbers come from the carrier
	// lane and both are checked here through driver.NewSizing, which is the one
	// place a host computes them.
	cases := []struct {
		name     string
		plan     []carrier.Class
		wantPath int
	}{
		{"udp only", []carrier.Class{carrier.ClassUDP}, 1357},
		{"the shipping plan", []carrier.Class{carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS}, 1421},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// One byte below the boundary is the dead zone, and since 2026-08-10
			// NewSizing REFUSES it rather than returning a sizing with InnerIPv6
			// false. That is a strictly stronger contract and this assertion
			// moved with it: a host that plans here builds a session which
			// resolves, bootstraps and carries, and can never promote, so the
			// only safe answer is to refuse at the door. Both wrapped errors are
			// named because callers switch on them separately — ErrConfig is
			// "your configuration is wrong" and ErrPathMTUDeadZone is the one a
			// host can act on by raising the path MTU.
			belowMessage := carrier.Floor(c.wantPath-1, c.plan...)
			belowInnerMTU := carrier.InnerMTU(belowMessage)
			if belowInnerMTU >= tun.IPv6MinLinkMTU {
				t.Fatalf("a %d-byte path yields an inner MTU of %d, which is not below the "+
					"%d-byte floor; %d is not the boundary this case claims it is",
					c.wantPath-1, belowInnerMTU, tun.IPv6MinLinkMTU, c.wantPath)
			}
			switch _, err := driver.NewSizing(c.wantPath-1, c.plan...); {
			case err == nil:
				t.Fatalf("NewSizing accepted a %d-byte path for plan %v, which floors the inner "+
					"interface at %d — below the %d RFC 8200 requires of any link carrying "+
					"IPv6. The session would carry and could never promote, which is the "+
					"failure the refusal exists to make loud.",
					c.wantPath-1, c.plan, belowInnerMTU, tun.IPv6MinLinkMTU)
			case !errors.Is(err, driver.ErrPathMTUDeadZone):
				t.Fatalf("NewSizing refused a %d-byte path with %v, which does not wrap "+
					"ErrPathMTUDeadZone; a host cannot tell this apart from any other "+
					"configuration error and so cannot know that raising the path MTU fixes it",
					c.wantPath-1, err)
			case !errors.Is(err, driver.ErrConfig):
				t.Fatalf("the dead-zone refusal at %d does not wrap ErrConfig: %v", c.wantPath-1, err)
			}

			at, err := driver.NewSizing(c.wantPath, c.plan...)
			if err != nil {
				t.Fatal(err)
			}
			if !at.InnerIPv6 {
				t.Fatalf("a %d-byte path reports inner IPv6 as impossible at inner MTU %d; "+
					"the documented boundary is %d", c.wantPath, at.InnerMTU, c.wantPath)
			}
			if at.MinPathMTUForInnerIPv6 != c.wantPath {
				t.Fatalf("MinPathMTUForInnerIPv6 is %d, want %d", at.MinPathMTUForInnerIPv6, c.wantPath)
			}

			// And the SECOND refusal, which is the one that still has to hold
			// even though the driver now refuses first: a v6 assignment below
			// the floor must not build. The two are independent guards on the
			// same fact, and the tun layer's is the one that catches a host
			// which computed its sizing some other way. Installing the route
			// anyway is the alternative that was declined on purpose — it looks
			// exactly like working IPv6 until the first full-size packet.
			//
			// The sizing is taken straight from the carrier arithmetic rather
			// than from NewSizing, precisely because NewSizing will no longer
			// hand back a dead-zone sizing to test with.
			dev := NewDevice(belowInnerMTU)
			_, err = tun.New(tun.Config{
				Assign: tun.Assignment{
					V4: V4(10, 64, 0, 2),
					V6: mustV6(),
				},
				Device:                  dev,
				Sink:                    nullSink{},
				Clock:                   NewStepClock(),
				CarrierFloorMessageSize: belowMessage,
			})
			if err == nil {
				t.Fatalf("tun.New built a tunnel with an inner IPv6 assignment at inner MTU %d, "+
					"below the %d-byte RFC 8200 floor. That is a tunnel that black holes every "+
					"full-size v6 packet and reports itself up.", belowInnerMTU, tun.IPv6MinLinkMTU)
			}
		})
	}
}

// --- the inward signal --------------------------------------------------------

// TestTheOversizeSignalIsARealICMPMessageAndGoesOnlyInward checks the signal
// the way a receiving stack does, and checks that nothing left through the
// carrier.
//
// A synthesised ICMP message with the wrong type, the wrong code or a bad
// checksum is discarded silently by every stack, which turns the path-MTU
// signal into an invisible black hole — so a counter saying "signal emitted" is
// not evidence. This reads the message.
func TestTheOversizeSignalIsARealICMPMessageAndGoesOnlyInward(t *testing.T) {
	t.Parallel()
	p := burstPair(t, PairConfig{})

	before := p.Client.Loop.Stats().MessagesSent
	// One byte over the inner MTU, with DF set. An IPv4 packet WITHOUT DF gets
	// no signal at all by design, so the rig's builder sets it.
	over := IPv4Packet(p.ClientAddr, p.GatewayAddr, make([]byte, p.Sizing.InnerMTU-20+1))
	if !p.Client.Device.Offer(over) {
		t.Fatal("device would not accept the oversize packet")
	}
	if err := p.Settle(10*time.Second, time.Millisecond, func() bool {
		return p.Client.Loop.Tunnel().Stats().TxDroppedOversize > 0
	}); err != nil {
		t.Fatalf("the tun layer did not drop an oversize packet: %+v",
			p.Client.Loop.Tunnel().Stats())
	}

	pkt, ok := p.Client.Device.Take(5 * time.Second)
	if !ok {
		t.Fatalf("no path-MTU signal was written back to the host: %+v",
			p.Client.Loop.Tunnel().Stats())
	}
	mtu, ok := IsICMPv4FragNeeded(pkt)
	if !ok {
		t.Fatalf("the packet written back to the host is not an ICMPv4 Destination "+
			"Unreachable / Fragmentation Needed message: % x", pkt[:minInt(len(pkt), 40)])
	}
	if mtu != p.Sizing.InnerMTU {
		t.Fatalf("the signal names a next-hop MTU of %d; the tunnel's inner MTU is %d, and a "+
			"host that believed the wrong number would keep black holing", mtu, p.Sizing.InnerMTU)
	}
	if after := p.Client.Loop.Stats().MessagesSent; after != before {
		t.Fatalf("%d messages were sent to the carrier for an oversize inner packet; the signal "+
			"is inward-only and an oversize packet is dropped, never fragmented", after-before)
	}
	if st := p.ToGateway.Stats(); st.MaxOuterSeen > p.Sizing.MessageSize {
		t.Fatalf("a %d-byte message reached the link for a %d-byte plan floor; something "+
			"fragmented or oversent", st.MaxOuterSeen, p.Sizing.MessageSize)
	}
}

// --- the mid-session drop: this is where it breaks ---------------------------

// TestAMidSessionMTUDropBlackHolesEveryFullSizeFlowWhileTheTunnelReportsUp is
// the finding, and it is the most dangerous behaviour this lane found.
//
// The inner MTU is fixed for the life of the interface — the tun lane says so
// in its §6.6 and calls it a known weakness. What nothing in the tree states is
// the CONSEQUENCE when the outer path narrows underneath a live session:
//
//   - the tun layer's own check still passes, because the inner packet fits the
//     inner MTU it was configured with, so NO path-MTU signal is synthesised;
//   - the message is sealed, handed to the carrier and written, and the write
//     succeeds, because a constrained path with DF set reports nothing;
//   - so every full-size flow black holes with no error anywhere;
//   - and the liveness detector cannot see it, because a PING is a small
//     message and small messages still fit.
//
// The tunnel therefore reported "up", small packets kept working, large
// transfers stalled, and the report came from a country where nobody can attach
// a debugger. That is the exact failure the plan floor exists to prevent on
// migration, reached by a route the plan floor does not cover.
//
// EVERY ONE OF THOSE FACTS STILL HOLDS, and this test still asserts them all,
// because none of them can be fixed where they happen: the tun layer genuinely
// cannot see the outer path, and a DF path genuinely reports nothing. What
// changed is the last bullet. A liveness probe now has a SIZE, so the session
// can ask the question the layers below it cannot: does this path carry the
// traffic I actually send? The verdict is PathNarrowed, it is not a teardown,
// and SetMaxMessageSize is the answer to it.
func TestAMidSessionMTUDropIsInvisibleBelowTheSessionAndVisibleToIt(t *testing.T) {
	t.Parallel()
	// The in-band rekey is pushed out of the way. This run covers many minutes of
	// injected time and a ratchet clears the liveness ladders by design — probes
	// queued under the old epoch are unopenable by the peer, so carrying their
	// ladders across the cut would count a ratchet as loss. That is correct
	// behaviour and a different test's subject.
	p := burstPair(t, PairConfig{Tweak: func(c *session.Config) {
		c.RekeyInterval = session.Draw{Min: 12 * time.Hour, Mean: 24 * time.Hour, Max: 48 * time.Hour}
	}})

	// A clean full-size flow first, so the black hole below is a change and not
	// a rig that never carried anything.
	sent := p.OfferInner(20, p.FullPayload())
	if got := p.Collect(sent, 40*time.Second); got != sent {
		t.Fatalf("delivered %d of %d before the path narrowed", got, sent)
	}

	// The path narrows to 900 bytes of outer packet. A UDP/IPv4 carrier charges
	// 28, so anything above an 872-byte message is now gone.
	const outerCap = 900
	p.ToGateway.Arm(Impairment{MaxOuterPacket: outerCap, OuterOverhead: 28})

	const big = 200
	bigSent := p.OfferInner(big, p.FullPayload())
	bigGot := p.Collect(bigSent, 3*time.Second)

	st := p.ToGateway.Stats()
	if st.DroppedOversize == 0 {
		t.Fatalf("the shim dropped nothing at a %d-byte cap while %d full-size packets were "+
			"offered; the impairment was not applied (link %+v)", outerCap, bigSent, st)
	}
	if bigGot != 0 {
		t.Fatalf("%d of %d full-size packets crossed a path capped at %d bytes; the shim is "+
			"leaking", bigGot, bigSent, outerCap)
	}

	// Nothing reported an error. This is the part that matters.
	ds := p.Client.Loop.Stats()
	if ds.SendFailed != 0 {
		t.Fatalf("the carrier reported %d send failures; a constrained path with DF set does "+
			"NOT report anything to the sender, so the rig is not modelling one", ds.SendFailed)
	}
	if s := p.Client.Loop.Tunnel().Stats(); s.TxDroppedOversize != 0 || s.PMTUSignals != 0 {
		t.Fatalf("the tun layer dropped %d oversize packets and emitted %d path-MTU signals for "+
			"a drop in the OUTER path; it cannot see the outer path, and a rig that showed it "+
			"could would be measuring itself", s.TxDroppedOversize, s.PMTUSignals)
	}

	// And now the two halves of the danger, asserted.
	//
	// 1. Small packets still work, so every user-visible health check passes.
	//    They are offered one at a time: the session coalesces DATA frames until
	//    the message budget is spent, and a coalesced batch is not small.
	const smallN = 20
	smallGot := 0
	for i := 0; i < smallN; i++ {
		p.OfferInner(1, 64)
		smallGot += p.Collect(1, 2*time.Second)
	}
	if smallGot != smallN {
		t.Fatalf("only %d of %d SMALL packets crossed the narrowed path; the finding is that "+
			"small traffic keeps working, so if it does not the rig is wrong", smallGot, smallN)
	}

	// 1b. The second edge of the same finding, and the one that makes the black
	//     hole harder to diagnose than "big packets fail": a BATCH of small
	//     packets is coalesced into one message and then padded to this
	//     session's bucket ladder, and the result is frequently over the cap. So
	//     the surviving fraction depends on the traffic's batching and on a
	//     random per-session draw, not on a size a user could reason about.
	beforeBatch := p.ToGateway.Stats().DroppedOversize
	batchSent := p.OfferInner(smallN, 64)
	batchGot := p.Collect(batchSent, 4*time.Second)
	afterBatch := p.ToGateway.Stats().DroppedOversize
	t.Logf("FINDING: %d of %d small packets survived when offered ONE AT A TIME, but %d of %d "+
		"survived when offered as a batch (%d further messages dropped oversize) — coalescing "+
		"plus the padding ladder put a batch of 64-byte packets over the same cap",
		smallGot, smallN, batchGot, batchSent, afterBatch-beforeBatch)

	// 2. The tunnel still says it is up, and the gate is still carrying, after a
	//    full liveness budget of injected time has passed.
	budget := time.Duration(session.DefaultMaxLostProbes) * session.DefaultProbeMax * 2
	// 2. And the fix. Every fact above still holds — no send error, no path-MTU
	//    signal, small packets fine — so nothing BELOW the session can see this.
	//    The session can, because its liveness probes now have a size: the wide
	//    ladder fails while the narrow ladder is answered, and that pair is a
	//    proof and a disproof rather than an inference.
	//
	//    The verdict must be NARROWED and must NOT be a teardown. Tearing down
	//    would be actively wrong: a re-handshake crosses the same path and lands
	//    in the same place, having cost the user their session.
	//
	// The wait is bounded in INJECTED time rather than in real time, and the
	// budget is generous rather than tight. The wide ladder needs MaxLostProbes
	// losses, the ladders alternate once the first wide probe fails, and a probe
	// only fires once inbound has gone quiet for a draw — so the number of probe
	// slots inside any fixed span is a property of the draws, not a constant.
	// (Settle is deliberately NOT used here: it advances the clock until a REAL
	// deadline, which on this rig is hours of injected time and a dozen rekeys.)
	//
	// The generosity is deliberate and was measured twice. A verdict needs
	// MaxLostProbes=4 WIDE losses, the ladders alternate after the first one, and
	// each wide probe costs a full Probe.Max to expire while each probe slot in
	// between is its own draw from [3 s, 20 s]. A lucky run reaches the verdict
	// in 2m40s; an unlucky sequence of draws needs more than twice that, and a
	// four-minute ceiling was measured failing at 3 of the 4 wide losses with the
	// budget simply spent. Nothing about that is a defect, so the ceiling is
	// twelve budgets and the wait exits the moment the verdict lands — the common
	// case still costs about three seconds of real time.
	//
	// The rekey timer is not a factor here: this test pins RekeyInterval to
	// 12-48 HOURS at the top precisely so a ratchet cannot clear the ladders
	// mid-run.
	narrowIn, narrowErr := p.SettleWithin(12*budget, 30*time.Second, 180*time.Second, func() bool {
		return p.Client.Loop.Session().PathNarrowed() || p.Client.Loop.Session().State().Terminal()
	})
	if !p.Client.Loop.Session().PathNarrowed() {
		s := p.Client.Loop.Session().Stats()
		t.Fatalf("on a path that black holes every full-size message the session does NOT "+
			"report a narrowed path after %s of injected time (state %s, err %v, wide probes "+
			"sent %d lost %d, narrow lost %d, probes lost %d; %v). That is the failure this fix "+
			"exists for: the tunnel reports up while the user's traffic silently dies.",
			narrowIn, p.Client.Loop.Session().State(), p.Client.Loop.Session().Err(),
			s.WideProbesSent, s.WideProbesLost, s.NarrowProbesLost, s.ProbesLost, narrowErr)
	}
	if st := p.Client.Loop.Session().State(); st != session.StateEstablished {
		t.Fatalf("the client is %s (%v) on a path that still carries small messages; a narrowed "+
			"path is a verdict to act on, not a teardown — re-handshaking crosses the same path",
			st, p.Client.Loop.Session().Err())
	}
	if p.Client.Loop.Tunnel().Gate().State() != tun.StateCarrying {
		t.Fatalf("the session is established but the gate is %s", p.Client.Loop.Tunnel().Gate().State())
	}
	s := p.Client.Loop.Session().Stats()
	if s.PathNarrowedFor == 0 {
		t.Fatal("PathNarrowed is true but PathNarrowedFor never moved; an operator watching the " +
			"counters would see nothing")
	}
	t.Logf("FIXED: after %s of injected time on a path that black holes every full-size message "+
		"the tunnel is %s with the gate %s and %d full-size packets lost — with zero send errors, "+
		"zero path-MTU signals and every small packet delivered, exactly as before — and the "+
		"session now REPORTS it: wide probes sent %d, wide lost %d, narrow lost %d, "+
		"narrowed verdicts %d.",
		narrowIn, p.Client.Loop.Session().State(), p.Client.Loop.Tunnel().Gate().State(), bigSent,
		s.WideProbesSent, s.WideProbesLost, s.NarrowProbesLost, s.PathNarrowedFor)

	// 3. The lever. A verdict a host cannot answer is a light on a dashboard
	//    nobody in Myanmar can see. Telling the session the ceiling the path
	//    actually carries clears the verdict, on positive evidence: a wide probe
	//    at the NEW size is answered.
	fits := outerCap - 28
	if err := p.Client.Loop.Session().SetMaxMessageSize(fits); err != nil {
		t.Fatalf("SetMaxMessageSize(%d) on a narrowed session: %v", fits, err)
	}
	if err := p.Gateway.Loop.Session().SetMaxMessageSize(fits); err != nil {
		t.Fatalf("gateway SetMaxMessageSize(%d): %v", fits, err)
	}
	// Derive the virtual-time budget from the driver's live Probe interval rather
	// than hardcoding 40 s of real time (which pours ~10 000 s virtual and trips
	// maxSpins). Clearing the verdict needs one answered wide probe: at most
	// Probe.Max, with headroom for the slot draw.
	probeMax := p.Client.Loop.Session().ProbeDraw().Max
	if wProbe := p.Gateway.Loop.Session().ProbeDraw().Max; wProbe > probeMax {
		probeMax = wProbe
	}
	clearBudget := 3 * probeMax
	requirePairBudget(t, p, clearBudget, exerciseProbe)
	if _, err := p.SettleWithin(clearBudget, 5*time.Second, 60*time.Second, func() bool {
		return !p.Client.Loop.Session().PathNarrowed()
	}); err != nil {
		s := p.Client.Loop.Session().Stats()
		t.Fatalf("the narrowed verdict did not clear after the session was told the path carries "+
			"%d bytes (wide sent %d, wide lost %d; %v)", fits, s.WideProbesSent, s.WideProbesLost, err)
	}
	if st := p.Client.Loop.Session().State(); st != session.StateEstablished {
		t.Fatalf("the client is %s after being resized to fit the path", st)
	}
	t.Logf("and the lever works: told the path carries %d bytes, the verdict cleared and the "+
		"session stayed up with no re-handshake", fits)
}

// TestADeadPathIsUnreachableAndNotNarrowed is the discrimination, asserted from
// the other side.
//
// A narrowed path and a dead one both expire a probe budget. If the detector
// could not tell them apart the fix above would be worse than the defect: every
// genuine outage would be reported as "the path narrowed" and no session would
// ever tear down, which for a user under a hostile state means a gate that never
// latches and traffic leaving in the clear.
//
// The distinction is round-trip evidence in the narrow class. On a dead path
// there is none, because nothing crosses at any size.
func TestADeadPathIsUnreachableAndNotNarrowed(t *testing.T) {
	t.Parallel()
	p := burstPair(t, PairConfig{})

	sent := p.OfferInner(10, 64)
	if got := p.Collect(sent, 20*time.Second); got != sent {
		t.Fatalf("delivered %d of %d before the path died", got, sent)
	}

	// A cap below the smallest message this session can emit: nothing crosses,
	// at any size, in either direction.
	p.ToGateway.Arm(Impairment{MaxOuterPacket: 1, OuterOverhead: 28})
	p.ToClient.Arm(Impairment{MaxOuterPacket: 1, OuterOverhead: 28})

	// The bound is INJECTED time, and the figure reported on failure is MEASURED
	// injected time. Both halves of that matter and neither was true before.
	//
	// The old wait was Settle(60 s of REAL time), which on this rig pours about
	// three and a half hours of virtual time into a session — past a dozen rekey
	// intervals on a path that carries nothing — and its message then reported
	// the CONSTANT `budget` as though it were an observation, so every failure
	// read "the client is established after 4m0s of injected time on a path that
	// carries NOTHING" no matter what had actually elapsed. That sentence is the
	// silent-refusal signature, so the test was accusing the protocol of the one
	// defect this package exists to find, on the strength of a hardcoded string.
	//
	// It was measured out: in 10 such failures under load the probe count was 0,
	// 1, 2 or 3 — always SHORT of the MaxLostProbes=4 that ends the session,
	// never at or past it — and 13 of 13 unloaded runs reached exactly 4 and tore
	// down. The teardown rule was never the problem. So the count is now printed
	// against the threshold that ends it, which is the one comparison that tells
	// "the budget has not been spent yet" apart from "the budget was spent and
	// nothing happened". Only the second is a protocol defect.
	budget := time.Duration(session.DefaultMaxLostProbes) * session.DefaultProbeMax * 3
	elapsed, err := p.SettleWithin(budget, 30*time.Second, 180*time.Second, func() bool {
		return p.Client.Loop.Session().State().Terminal()
	})
	if err != nil {
		s := p.Client.Loop.Session().Stats()
		t.Fatalf("the client is %s after %s of injected time on a path that carries NOTHING "+
			"(probes lost %d of the %d that end a session, wide lost %d, narrow lost %d; %v). "+
			"A dead path must still reach a teardown; the size-aware signal narrows the "+
			"verdict, it must not remove it.",
			p.Client.Loop.Session().State(), elapsed, s.ProbesLost, session.DefaultMaxLostProbes,
			s.WideProbesLost, s.NarrowProbesLost, err)
	}
	if !errors.Is(p.Client.Loop.Session().Err(), session.ErrPeerUnreachable) {
		t.Fatalf("the client failed with %v, want ErrPeerUnreachable", p.Client.Loop.Session().Err())
	}
	if p.Client.Loop.Session().PathNarrowed() {
		t.Fatal("a path that carries nothing was reported as NARROWED. The two verdicts want " +
			"opposite responses — narrowed means resize and carry on, unreachable means tear " +
			"down and fail closed — so confusing them is worse than having neither.")
	}
	if _, err := p.SettleWithin(30*time.Second, 2*time.Second, 30*time.Second, func() bool {
		return p.Client.Loop.Tunnel().Gate().State() != tun.StateCarrying
	}); err != nil {
		t.Fatalf("the gate is %s after an unreachable peer; the teardown must fail closed (%v)",
			p.Client.Loop.Tunnel().Gate().State(), err)
	}
	s := p.Client.Loop.Session().Stats()
	t.Logf("a dead path: probes lost %d (wide %d, narrow %d) in %s of injected time, state %s, "+
		"gate %s, narrowed=%v", s.ProbesLost, s.WideProbesLost, s.NarrowProbesLost, elapsed,
		p.Client.Loop.Session().State(), p.Client.Loop.Tunnel().Gate().State(),
		p.Client.Loop.Session().PathNarrowed())
}

// TestTheNarrowedPathTestHasTeeth is the control for the test above: the same
// shim, the same session, a cap ABOVE the plan floor's outer size. Every packet
// must then cross. Without this, the black hole above could be a shim that
// drops everything.
func TestTheNarrowedPathTestHasTeeth(t *testing.T) {
	t.Parallel()
	p := burstPair(t, PairConfig{})

	// The cap is derived from the plan floor, not written down: at the fleet
	// default of 1450 the floor is 1338, which over UDP/IPv4 is a 1366-byte
	// outer packet (it was 1168 and 1196 when this was written at 1280). Cap
	// the path exactly at it and nothing may be dropped.
	outerCap := p.Sizing.MessageSize + 28
	p.ToGateway.Arm(Impairment{MaxOuterPacket: outerCap, OuterOverhead: 28})

	sent := p.OfferInner(100, p.FullPayload())
	got := p.Collect(sent, 40*time.Second)
	st := p.ToGateway.Stats()
	if st.DroppedOversize != 0 {
		t.Fatalf("the shim dropped %d packets at a %d-byte cap for a %d-byte plan floor; the "+
			"cap is wrong or the session is emitting wider than it was pinned to",
			st.DroppedOversize, outerCap, p.Sizing.MessageSize)
	}
	if got != sent {
		t.Fatalf("delivered %d of %d at a cap the traffic fits; the shim is dropping for some "+
			"other reason and the black-hole result proves nothing (link %+v)", got, sent, st)
	}
	if st.MaxOuterSeen != outerCap {
		t.Fatalf("the largest outer packet offered was %d, want exactly %d — the session must be "+
			"filling the plan floor exactly, or the black-hole test's cap is not the boundary "+
			"it claims to be", st.MaxOuterSeen, outerCap)
	}

	// The teeth for the DETECTOR, not just for the shim: the same body, the same
	// wait, a path that carries everything. A verdict that fired here would be a
	// false positive, and a false "the path narrowed" is how a healthy session
	// gets resized down to nothing.
	probeMax := p.Client.Loop.Session().ProbeDraw().Max
	if gProbe := p.Gateway.Loop.Session().ProbeDraw().Max; gProbe > probeMax {
		probeMax = gProbe
	}
	maxLost := p.Client.Loop.Session().MaxLostProbes()
	if gLost := p.Gateway.Loop.Session().MaxLostProbes(); gLost > maxLost {
		maxLost = gLost
	}
	budget := time.Duration(maxLost) * probeMax * 2
	requirePairBudget(t, p, budget, exerciseProbe)
	elapsed, drove := driveAnsweredProbes(p, 60*time.Second, budget, wantWideProbes)

	cs := p.Client.Loop.Session().Stats()
	if !drove || cs.WideProbesSent < wantWideProbes {
		t.Fatalf("no wide probe was ever sent, so 'no narrowed verdict' is not evidence of "+
			"anything — the detector was never exercised: %d of the %d wide probes wanted, in "+
			"%s of injected time (pings sent %d, pongs received %d, probes lost %d, state %s)",
			cs.WideProbesSent, wantWideProbes, elapsed, cs.PingsSent, cs.PongsReceived,
			cs.ProbesLost, p.Client.Loop.Session().State())
	}
	if p.Client.Loop.Session().PathNarrowed() || p.Gateway.Loop.Session().PathNarrowed() {
		t.Fatalf("a path that carries every full-size message was reported as narrowed after %s "+
			"(client %v, gateway %v)", elapsed,
			p.Client.Loop.Session().PathNarrowed(), p.Gateway.Loop.Session().PathNarrowed())
	}
	if cs.WideProbesLost != 0 {
		t.Fatalf("%d wide probes were lost on an unimpaired path", cs.WideProbesLost)
	}
	if s := p.Client.Loop.Session().State(); s != session.StateEstablished {
		t.Fatalf("the client is %s on a path that carries everything (%v)", s,
			p.Client.Loop.Session().Err())
	}
	t.Logf("teeth: %d wide probes sent and %d lost on a path one byte wider than the plan floor; "+
		"no narrowed verdict", cs.WideProbesSent, cs.WideProbesLost)
}

// --- the negotiation ---------------------------------------------------------

// TestPathMTUNegotiationFloorsAtTheFleetMinimum is the netlab statement of the
// negotiated half of silent-refusal instance #3: the number a session whose two
// ends plan at the fleet default actually negotiates to, and the reason the
// fleet may raise its path_mtu to 1450.
//
// Each end reaches the wire carrying its own PLANNING path MTU in the handshake
// payload (EncodePathMTUNotice), and the initiator refuses loudly unless the
// two ends planned at one number. So the netlab rig — two real driver loops, a
// real gateway responder, a real shaper — negotiates on every handshake it
// completes, and this test holds the number the fleet default negotiates at:
//
//   - the rig plans at carrier.DefaultPathMTU, never the old 1280;
//   - that number is above the inner-IPv6 dead zone whose upper edge the floor
//     exists to clear, so the pair is PROMOTABLE (InnerIPv6 true);
//   - the session-level arithmetic the two ends actually ran agrees both made a
//     claim and picked the smaller of two equal claims — which is the fleet
//     minimum, never lower;
//   - the pair CARRIES a full-size flow, proving the negotiation produced a
//     working session and not a silent downgrade into the dead zone (a session
//     negotiated too far down still reports up — the one failure mode this test
//     exists to catch).
//
// The +28 is the UDP/IPv4 outer overhead: at the 1450 fleet default the plan
// floor is 1338, so a full-size message leaves as a 1366-byte outer packet,
// exactly the number TestTheNarrowedPathTestHasTeeth caps the path at.
func TestPathMTUNegotiationFloorsAtTheFleetMinimum(t *testing.T) {
	t.Parallel()
	p := burstPair(t, PairConfig{})

	if p.Sizing.PathMTU != carrier.DefaultPathMTU {
		t.Fatalf("the rig planned at %d, want carrier.DefaultPathMTU (%d); the negotiated "+
			"floor this test pins is the fleet default and the two have drifted",
			p.Sizing.PathMTU, carrier.DefaultPathMTU)
	}
	if p.Sizing.PathMTU < 1450 {
		t.Fatalf("the rig negotiated a planning path MTU of %d, below the %d-byte fleet "+
			"minimum; a lower floor is the old 1280 default, which drops the pair into the "+
			"inner-IPv6 dead zone", p.Sizing.PathMTU, 1450)
	}

	if !p.Sizing.InnerIPv6 {
		t.Fatalf("a pair negotiated at %d reports inner IPv6 as impossible; the %d-byte "+
			"negotiated floor is supposed to clear the dead zone, so a false InnerIPv6 means "+
			"the rig is planning somewhere the floor does not reach",
			p.Sizing.PathMTU, p.Sizing.PathMTU)
	}

	negotiated, both := session.NegotiatedPathMTU(p.Sizing.PathMTU, p.Sizing.PathMTU)
	if !both {
		t.Fatal("two ends that both planned at the fleet default did not make a claim; " +
			"negotiation cannot floor at anything if neither end stands behind a number")
	}
	if negotiated != p.Sizing.PathMTU {
		t.Fatalf("the negotiated path MTU is %d, want %d; NegotiatedPathMTU must pick the "+
			"smaller of two equal claims, and it picked something else", negotiated, p.Sizing.PathMTU)
	}
	if negotiated < 1450 {
		t.Fatalf("negotiation floored at %d, below the %d-byte fleet minimum", negotiated, 1450)
	}

	if p.Sizing.MessageSize != carrier.Floor(p.Sizing.PathMTU, p.Sizing.Classes...) {
		t.Fatalf("the rig's message size %d is not the plan floor at %d", p.Sizing.MessageSize,
			p.Sizing.PathMTU)
	}

	sent := p.OfferInner(3, p.FullPayload())
	if got := p.Collect(sent, 40*time.Second); got != sent {
		t.Fatalf("delivered %d of %d full-size packets after negotiating at %d; a pair that "+
			"negotiates down into the dead zone carries small traffic while full-size flows "+
			"black hole, so the carry is the proof the negotiation is a working session and "+
			"not a silent refusal", got, sent, negotiated)
	}
	t.Logf("negotiated at the %d-byte fleet minimum (plan floor %d, inner MTU %d, inner IPv6 %v) "+
		"and carried %d full-size packets", negotiated, p.Sizing.MessageSize, p.Sizing.InnerMTU,
		p.Sizing.InnerIPv6, sent)
}

// --- helpers ------------------------------------------------------------------

// wantWideProbes is how many answered wide probes make "no narrowed verdict" an
// observation rather than an accident. One would do for the letter of the
// assertion; four is the same number the detector needs to reach a verdict, so
// a run that gets this far has exercised the detector over its whole ladder
// rather than catching it before it started.
const wantWideProbes = 4

// driveAnsweredProbes advances the injected clock until the client has sent at
// least wantWide wide probes, all of them resolved, AND at least `injected` of
// injected time has passed. It reports the injected time it burned and whether
// it got there before `real` of REAL time ran out.
//
// It exists because the obvious loop
//
//	for elapsed := 0; elapsed < budget; elapsed += 50 * time.Millisecond {
//	    p.Clock.Advance(50 * time.Millisecond)
//	    time.Sleep(50 * time.Microsecond)
//	}
//
// is not a wait at all. It advances 160 SECONDS of injected time in about 160
// MILLISECONDS of real time and then reads a counter that the client's write
// goroutine has to move — and that goroutine only moves it when the scheduler
// gives it a turn. On a loaded machine it can miss the window completely, and
// the test then reports "the detector was never exercised" about a detector
// that was simply never given a turn. Measured on this package: the same binary
// on the same bytes failed 1 run in 5 alone, and 9 of the first 13 with six
// copies running at once.
//
// The clock is therefore driven against the loops' own progress instead of
// against a step count, in two gears:
//
//   - quiescent (no probe outstanding), 50 ms a step, which is 1/60th of the
//     shortest probe interval the draw can produce, so no probe slot is
//     stepped over;
//   - a probe outstanding, 1 ms a step, so the 20-second expiry of an in-flight
//     probe takes 20 000 steps to reach instead of 400. A test that outran an
//     answer still crossing the rig would count a live probe as LOST, which is
//     the same defect one layer up and would turn this fix into the next flake.
//
// Progress is never suspended, only slowed, so a genuinely dead path still
// reaches its probe expiries and still fails this test — that property is the
// reason the second gear is 1 ms and not zero.
func driveAnsweredProbes(p *Pair, realCap, injected time.Duration, wantWide uint64) (time.Duration, bool) {
	// Derive the virtual-time budget's step from the budget itself, not from a
	// constant, to keep the wake count near targetSteps and inside maxSpins=4096.
	// Previously this hardcoded 100 ms / 10 ms, which for a 160 s budget is still
	// ~1600 wakes, but for any other budget the wake count is whatever falls out.
	// The caller must have derived `injected` from the driver's live Probe
	// interval; the check below enforces the invariant for any direct caller.
	const targetSteps = 1500
	base := injected / targetSteps
	if base < time.Millisecond {
		base = time.Millisecond
	}
	if base > time.Second {
		base = time.Second
	}
	// Outstanding gear is an order of magnitude finer so a 20 s probe expiry
	// is not stepped over, but still coarse enough that a never-answered probe
	// costs ~2000 wakes rather than 20 000.
	outstandingStep := base / 10
	if outstandingStep < time.Millisecond {
		outstandingStep = time.Millisecond
	}
	if outstandingStep > 100*time.Millisecond {
		outstandingStep = 100 * time.Millisecond
	}
	start := p.Clock.Now()
	deadline := time.Now().Add(realCap)
	for time.Now().Before(deadline) {
		s := p.Client.Loop.Session().Stats()
		outstanding := s.PingsSent > s.PongsReceived+s.ProbesLost
		if !outstanding && p.Clock.Now().Sub(start) >= injected && s.WideProbesSent >= wantWide {
			return p.Clock.Now().Sub(start), true
		}
		step := oddStep(base)
		if outstanding {
			step = oddStep(outstandingStep)
		}
		p.Clock.Advance(step)
		time.Sleep(200 * time.Microsecond)
	}
	return p.Clock.Now().Sub(start), false
}

type nullSink struct{}

func (nullSink) SendData([]byte) error { return nil }

// mustV6 is a unique-local inner address, built from bytes like every other
// address in this tree so that no literal appears in the source.
func mustV6() netip.Addr {
	return netip.AddrFrom16([16]byte{0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
