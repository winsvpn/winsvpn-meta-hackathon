package netlab

import (
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
)

// TestTheDuplexDefaultSizesAtTheShippingPlanFloor pins the exact rig to the
// same floor the real concurrency rig is built at, so the two cannot drift
// apart again.
//
// Until 2026-08-10 NewDuplex defaulted MaxMessageSize to a literal 1168 — the
// plan floor at a 1280-byte path — while Pair planned at carrier.DefaultPathMTU.
// The raise 1280 -> 1450 moved the floor to 1338, so Duplex was silently
// modelling a session sized for a path no host may plan at any more
// (driver.NewSizing refuses it). The two tests that use Duplex measure probe
// and reorder behaviour, which is size-independent, so nothing caught it: the
// same shape as every stale constant this package has chased.
//
// The first assertion is the drift guard: the default must DERIVE from the
// fleet constant, so a future raise moves Duplex with Pair. The second pins
// today's absolute number, matching driver/sizing_test.go's 1338 pin, so a
// change that quietly moves the value fails loudly instead of drifting.
func TestTheDuplexDefaultSizesAtTheShippingPlanFloor(t *testing.T) {
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDuplex(kr, DuplexConfig{})
	if err != nil {
		t.Fatal(err)
	}
	want := carrier.Floor(carrier.DefaultPathMTU, carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS)
	if d.MaxMessageSize != want {
		t.Fatalf("Duplex defaulted to %d bytes, but the shipping [UDP, TCP, TLS] plan floor at "+
			"carrier.DefaultPathMTU (%d) is %d; the exact rig and the Pair rig must be built at "+
			"the same size", d.MaxMessageSize, carrier.DefaultPathMTU, want)
	}
	if want != 1338 {
		t.Fatalf("the plan floor is %d, want 1338 at the current %d-byte fleet default; "+
			"this test and pump.go's comment must be re-measured together", want, carrier.DefaultPathMTU)
	}
}

// pumpLivenessDuplex builds the exact rig with every schedule a liveness run
// must not cross pushed out of the way, and the probe draw tightened so a
// liveness budget is reached in a few seconds of injected time rather than a
// few forty-second runs.
//
// It is liveness_test.go's livenessDuplex, with the probe draw shrunk. Rekey
// is pushed out for the same reason livenessDuplex does — a run that spends a
// probe budget in virtual time must not also trip a rekey. Both probe budgets
// are left at their defaults so that a genuinely stalled pump is exactly what
// the detecting end observes, and there is no patient end holding a budget
// open, because this test never lets the stall reach the bound.
func pumpLivenessDuplex(t *testing.T) *Duplex {
	t.Helper()
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	cfg := DuplexConfig{TokenWindow: netlabWindow}
	cfg.Tweak = func(c *session.Config) {
		c.RekeyInterval = session.Draw{Min: 12 * time.Hour, Mean: 24 * time.Hour, Max: 48 * time.Hour}
		c.Probe = session.Draw{Min: time.Second, Mean: 2 * time.Second, Max: 3 * time.Second}
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

// TestAStalledPumpIsDetectedAndRestartedWithinTheLivenessBound is the pump-rig
// test this lane owns. "Pump" is the caller driving one end of the Duplex, and
// a stalled pump is an end whose outbound is never drained.
//
// The GATEWAY's pump is stalled: the client's traffic is still delivered into
// it — so the PONGs its probes earn accumulate in the gateway's undrained
// outbox — but nothing the gateway has to say ever reaches the client. From
// the client's seat that is a peer whose return path has gone: its probes go
// unanswered, its lost count climbs toward the liveness budget, and the
// detector is watching a stalled pump.
//
// The half this test exists to prove is the RESTART, which the two liveness
// tests in liveness_test.go do not cover: if the stalled pump is restarted —
// its outbox drained and delivered — before the liveness budget is spent, the
// client must recover and stay established. Detection alone closes the tunnel
// only at the bound; a supervisor that restarts in time keeps the tunnel up,
// and that is the property a real host's pump supervisor is built on.
func TestAStalledPumpIsDetectedAndRestartedWithinTheLivenessBound(t *testing.T) {
	t.Parallel()
	d := pumpLivenessDuplex(t)

	maxLost := uint64(session.DefaultMaxLostProbes) // 4, both ends at default
	probeMax := 3 * time.Second                     // the Probe.Max drilled above
	bound := time.Duration(maxLost) * probeMax      // the liveness budget: lost probes x probe ceiling

	started := d.Clock.Now()

	var elapsed time.Duration
	var restarted bool
	var lostAtRestart uint64

	// Stall the gateway pump. The client keeps pumping INTO the gateway so its
	// probes are really answered-or-not rather than never sent, and the
	// gateway's PONGs accumulate in its outbox. The gateway's own outbound is
	// never drained, so nothing comes back to the client.
	for rounds := 0; rounds < 6000; rounds++ {
		c2g, err := d.Drain(d.Client)
		if err != nil {
			t.Fatalf("client drain: %v", err)
		}
		for _, m := range c2g {
			if _, err := d.Gateway.Deliver(m); err != nil {
				t.Fatalf("gateway deliver: %v", err)
			}
		}

		lost := d.Client.Stats().ProbesLost
		if !restarted && lost >= 1 {
			// Restart the stalled gateway pump before the bound is spent: drain
			// the accumulated outbox and deliver it to the client.
			g2c, err := d.Drain(d.Gateway)
			if err != nil {
				t.Fatalf("gateway drain: %v", err)
			}
			for _, m := range g2c {
				if _, err := d.Client.Deliver(m); err != nil {
					t.Fatalf("client deliver: %v", err)
				}
			}
			restarted = true
			lostAtRestart = lost
			elapsed = d.Clock.Now().Sub(started)
			break
		}
		d.Advance(time.Second)
	}

	if !restarted {
		t.Fatalf("the client never lost a probe while the gateway pump was stalled for 6000 s of " +
			"injected time; either the stall was not created or detection never ran, and the test " +
			"proves nothing")
	}

	// Detection real: the lost count moved, so the detector saw the stall.
	if lostAtRestart == 0 {
		t.Fatal("restarted with zero probes lost, so the restart is a statement about a pump that " +
			"never stalled rather than about the detector")
	}
	// Detection pending, not tripped: the restarted pump was ABLE to restart
	// within the bound, which requires the teardown not to have fired yet.
	if lostAtRestart >= maxLost {
		t.Fatalf("the client had already lost %d probes (budget %d) when the pump restarted; a "+
			"pump restarted AT or past the liveness bound is too late, and this test has not "+
			"proved 'within the bound'", lostAtRestart, maxLost)
	}
	if elapsed >= bound {
		t.Fatalf("the stalled pump was restarted after %s of injected time, at or past the %s "+
			"liveness budget (%d probes x %s); the restart was NOT within the bound",
			elapsed, bound, maxLost, probeMax)
	}
	if d.Client.State().Terminal() {
		t.Fatalf("the client is %s (%v) at restart after losing %d probes, before the bound was "+
			"spent; a stall it could have survived tore the tunnel down early",
			d.Client.State(), d.Client.Err(), lostAtRestart)
	}

	// Recovery is a fact, not an assumption: keep both pumps running and
	// require the session to stay established over continued traffic, and to
	// have actually heard its peer (messages received), so "recovered" is not
	// "a rig that carried nothing".
	for rounds := 0; rounds < 40 && d.Client.State() != session.StateEstablished; rounds++ {
		c2g, err := d.Drain(d.Client)
		if err != nil {
			t.Fatalf("recovery client drain: %v", err)
		}
		for _, m := range c2g {
			if _, err := d.Gateway.Deliver(m); err != nil {
				t.Fatalf("recovery gateway deliver: %v", err)
			}
		}
		g2c, err := d.Drain(d.Gateway)
		if err != nil {
			t.Fatalf("recovery gateway drain: %v", err)
		}
		for _, m := range g2c {
			if _, err := d.Client.Deliver(m); err != nil {
				t.Fatalf("recovery client deliver: %v", err)
			}
		}
		d.Advance(time.Second)
	}

	if d.Client.State() != session.StateEstablished {
		t.Fatalf("the client is %s (%v) after the stalled pump was restarted within %s; it lost "+
			"%d probes before the restart and did not recover, which is the failure this test "+
			"exists to catch", d.Client.State(), d.Client.Err(), elapsed, lostAtRestart)
	}
	if got := d.Client.Stats().MessagesReceived; got == 0 {
		t.Fatal("the client delivered nothing after the restart, so 'recovered' is a statement " +
			"about a rig that carried nothing rather than about the session")
	}
	t.Logf("stalled gateway pump detected at %d lost probes, restarted after %s (bound %s), "+
		"client recovered to %s having received %d messages",
		lostAtRestart, elapsed, bound, d.Client.State(), d.Client.Stats().MessagesReceived)
}
