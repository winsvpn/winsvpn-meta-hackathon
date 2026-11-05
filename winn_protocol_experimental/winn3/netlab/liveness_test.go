package netlab

import (
	"errors"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/session"
)

// The liveness detector, measured exactly rather than statistically.
//
// Pair proves a property survives the real three-goroutine pump. Duplex proves
// what the property IS: the delivery order is a permutation the caller writes
// down, so "the probe budget expired" is a fact about frames rather than a race
// with a scheduler. Both defects this file covers are decided by which messages
// arrive, not by how fast, so this is the rig that can state them.

// livenessDuplex builds the exact rig at the shipping probe schedule.
//
// patientGateway holds the GATEWAY's probe budget open so that the client's
// verdict can be observed on its own. It is a rig control and it is needed for a
// structural reason rather than a convenient one: an end whose inbound is dead
// fires both its silence timer AND its probe slot, while an end that is still
// hearing its peer fires only the silence timer, so the silent end always
// reaches its budget first. Without holding it open, every run would end in the
// gateway's teardown before the client's own decision could be read.
func livenessDuplex(t *testing.T, patientGateway bool) *Duplex {
	t.Helper()
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	cfg := DuplexConfig{TokenWindow: netlabWindow}
	cfg.Tweak = func(c *session.Config) {
		// The in-band rekey is pushed out of the way. These runs cover thousands
		// of seconds of injected time, and a ratchet that cannot complete because
		// one direction is dropped ends in CloseRekeyFailed — a real behaviour,
		// but a different one, and it would terminate the session before the
		// liveness verdict under test could be read.
		c.RekeyInterval = session.Draw{Min: 12 * time.Hour, Mean: 24 * time.Hour, Max: 48 * time.Hour}
		// Accept is set on the gateway's configuration and nowhere else.
		if patientGateway && c.Accept != nil {
			c.MaxLostProbes = 1000
		}
	}
	d, err := NewDuplex(kr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Handshake(400); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestSuppressedProbesDoNotTearDownAnEndThatIsStillHearingItsPeer is the fix
// for §4.3 of WINN3_NETWORK_REALISM_20260808.md, stated to the frame.
//
// The claim in §3 of WINN3_SESSION_DRIVER_20260808.md was that noise "cannot
// forge a PONG and cannot suppress one". The first clause is true. The second is
// not: the receive path is bounded, so noise at volume DISPLACES real messages,
// PINGs and PONGs included, and the legitimate probe budget then fires on an
// outage the attacker manufactured. That measured as the far end failing with
// ErrPeerUnreachable while the sprayed end sat established with 28,818
// unopenable messages and zero probes lost — the honest detector firing on a
// fabricated fact, which is a censorship capability priced in bandwidth.
//
// This rig produces the SAME frame-level condition with no flood at all, which
// is what makes it exact: every message the client sends is discarded, so its
// probes are never answered, while every message the gateway sends is delivered,
// so the client keeps hearing its peer. The client's probe budget is therefore
// spent on an outage that did not happen, and it must not tear down for it.
func TestSuppressedProbesDoNotTearDownAnEndThatIsStillHearingItsPeer(t *testing.T) {
	t.Parallel()
	d := livenessDuplex(t, true)

	budget := uint64(session.DefaultMaxLostProbes)
	payload := make([]byte, 64)

	// The gateway's traffic arrives in bursts separated by more than the probe
	// spacing, which is what a spray produces and what the rig has to reproduce.
	// Delivering EVERY round would be the wrong shape twice over: the client's
	// probe slot only fires after its inbound has gone quiet for a draw, and an
	// end that is continuously answering its peer's probes keeps resetting its
	// own silence timer, so a continuously-fed client never probes at all and the
	// condition under test never arises.
	const gap = 30

	var lost uint64
	for round := 0; round < 6000; round++ {
		// Everything the client sends is lost. This is what a spray at the
		// gateway's inbox does to it, and it is also what a one-way
		// desynchronisation does: the two are indistinguishable from here, which
		// is the whole difficulty.
		if _, err := d.Drain(d.Client); err != nil {
			t.Fatalf("client drain: %v", err)
		}
		_ = d.Gateway.Enqueue(payload)
		msgs, err := d.Drain(d.Gateway)
		if err != nil {
			t.Fatalf("gateway drain: %v", err)
		}
		if round%gap == 0 {
			// The burst that gets through. It is what proves to the client that
			// its peer is alive and reaching it, which is the fact that makes
			// "peer unreachable" false.
			for _, m := range msgs {
				if _, err := d.Client.Deliver(m); err != nil {
					t.Fatalf("client deliver: %v", err)
				}
			}
		}
		if lost = d.Client.Stats().ProbesLost; lost >= budget {
			break
		}
		d.Advance(time.Second)
	}

	if lost < budget {
		t.Fatalf("the client lost only %d probes against a budget of %d; the rig never reached "+
			"the condition and this test proves nothing", lost, budget)
	}
	if d.Client.State().Terminal() {
		t.Fatalf("the client is %s (%v) after losing %d probes WHILE RECEIVING %d authenticated "+
			"messages from its peer. That is the teardown an off-path attacker manufactures with "+
			"bandwidth, and closing it is the whole point of this change.",
			d.Client.State(), d.Client.Err(), lost, d.Client.Stats().MessagesReceived)
	}
	if got := d.Client.Stats().MessagesReceived; got == 0 {
		t.Fatal("the client received nothing, so \"it did not tear down\" is a statement about a " +
			"rig that carried nothing rather than about the detector")
	}
	// The damage must still be VISIBLE. Refusing the fabricated verdict must not
	// also hide the degradation: a policy layer reads a climbing probe-loss count
	// on an established session and answers it with a carrier change, which is
	// the response that actually helps against a flood at a known five-tuple.
	t.Logf("FIXED: the client lost %d probes and stayed %s while receiving %d authenticated "+
		"messages; the loss is still counted so a policy layer can still see it",
		lost, d.Client.State(), d.Client.Stats().MessagesReceived)
}

// TestAnEndThatHearsNothingStillReachesUnreachable is the teeth: the same rig,
// the same loop, the same budget, with the gateway's traffic dropped too.
//
// Without it the test above would be satisfied by a driver that had simply
// stopped tearing down, which would be a far worse defect than the one being
// fixed — a tunnel that never fails closed is traffic leaving in the clear.
func TestAnEndThatHearsNothingStillReachesUnreachable(t *testing.T) {
	t.Parallel()
	d := livenessDuplex(t, false)

	budget := uint64(session.DefaultMaxLostProbes)
	for round := 0; round < 6000; round++ {
		if _, err := d.Drain(d.Client); err != nil {
			t.Fatalf("client drain: %v", err)
		}
		if _, err := d.Drain(d.Gateway); err != nil {
			t.Fatalf("gateway drain: %v", err)
		}
		if d.Client.State().Terminal() {
			break
		}
		d.Advance(time.Second)
	}

	if !d.Client.State().Terminal() {
		t.Fatalf("the client is %s having lost %d probes with nothing arriving in either "+
			"direction; a genuinely unreachable peer must still be detected",
			d.Client.State(), d.Client.Stats().ProbesLost)
	}
	if !errors.Is(d.Client.Err(), session.ErrPeerUnreachable) {
		t.Fatalf("the client failed with %v, want ErrPeerUnreachable", d.Client.Err())
	}
	if got := d.Client.Stats().ProbesLost; got < budget {
		t.Fatalf("the client tore down having lost %d probes, below the %d-probe budget; the "+
			"teardown came from somewhere other than the liveness detector", got, budget)
	}
	if d.Client.PathNarrowed() {
		t.Fatal("a path that carries nothing was reported as narrowed")
	}
	t.Logf("teeth: with both directions dropped the client lost %d probes and failed with %v",
		d.Client.Stats().ProbesLost, d.Client.Err())
}

// TestAPerfectPumpAnswersEveryWideProbeAndRaisesNoVerdict is the false-positive
// control for the size-aware signal, at the exact rig.
//
// A detector that reported "the path narrowed" on a path that carries everything
// would be worse than no detector: the answer to the verdict is to shrink the
// session's message ceiling, and a false positive shrinks a healthy tunnel.
func TestAPerfectPumpAnswersEveryWideProbeAndRaisesNoVerdict(t *testing.T) {
	t.Parallel()
	d := livenessDuplex(t, false)

	for round := 0; round < 400; round++ {
		if _, err := d.Exchange(); err != nil {
			t.Fatalf("exchange: %v", err)
		}
		d.Advance(time.Second)
	}

	cs, gs := d.Client.Stats(), d.Gateway.Stats()
	if cs.WideProbesSent == 0 && gs.WideProbesSent == 0 {
		t.Fatalf("no wide probe was sent by either end in 400 rounds; \"no verdict\" is not "+
			"evidence about a detector that never ran (client pings %d, gateway pings %d)",
			cs.PingsSent, gs.PingsSent)
	}
	if cs.WideProbesLost != 0 || gs.WideProbesLost != 0 {
		t.Fatalf("wide probes were lost on a perfect pump: client %d, gateway %d. A full-size "+
			"probe must be ANSWERED full-size — a narrow answer would prove only the outbound "+
			"leg, and would leave a return path that cannot carry the answer undetected.",
			cs.WideProbesLost, gs.WideProbesLost)
	}
	if d.Client.PathNarrowed() || d.Gateway.PathNarrowed() {
		t.Fatalf("a path that carries everything was reported as narrowed (client %v, gateway %v)",
			d.Client.PathNarrowed(), d.Gateway.PathNarrowed())
	}
	if d.Client.State() != session.StateEstablished || d.Gateway.State() != session.StateEstablished {
		t.Fatalf("client %s, gateway %s after 400 rounds of a perfect pump",
			d.Client.State(), d.Gateway.State())
	}
	t.Logf("perfect pump: %d wide probes from the client and %d from the gateway, none lost",
		cs.WideProbesSent, gs.WideProbesSent)
}
