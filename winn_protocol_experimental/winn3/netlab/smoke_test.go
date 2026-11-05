package netlab

import (
	"context"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
)

// TestTheRigCarriesBytesOnAPerfectLink is the rig's own sanity check. A perfect
// Link is loopback, so this must reproduce exactly what the driver lane already
// proved; if it does not, every impairment result in this package is measuring
// the rig rather than the protocol.
func TestTheRigCarriesBytesOnAPerfectLink(t *testing.T) {
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
	sent, got := p.SendInner(64, 64, 40*time.Second)
	if sent != 64 {
		t.Fatalf("offered %d of 64 packets to the host device", sent)
	}
	if got != sent {
		t.Fatalf("delivered %d of %d inner packets on a PERFECT link: client %+v, gateway %+v, "+
			"link c2g %+v, link g2c %+v, client tun %+v, gateway tun %+v",
			got, sent, p.Client.Loop.Stats(), p.Gateway.Loop.Stats(),
			p.ToGateway.Stats(), p.ToClient.Stats(),
			p.Client.Loop.Tunnel().Stats(), p.Gateway.Loop.Tunnel().Stats())
	}
}

// TestTheFakeClockFiresAnAlreadyDueTimerAtOnce pins the one property of this
// rig's clock that a real time.Timer has and a naive fake does not.
//
// time.NewTimer with a non-positive duration fires immediately. A fake that
// queued it instead would be more forgiving than the real thing, and the class
// of bug it hides is a loop that POLLS instead of waiting: every wake computes
// a deadline already in the past, builds a zero-length timer, and spins. The
// driver lane's mutation 20 survived its first run for exactly this reason, and
// the fix was in the fake rather than in the test.
//
// It is asserted here without any Advance at all, because "fires on the next
// advance" is precisely the broken behaviour and a rig that advances constantly
// cannot tell the two apart.
func TestTheFakeClockFiresAnAlreadyDueTimerAtOnce(t *testing.T) {
	t.Parallel()
	c := NewStepClock()
	for _, d := range []time.Duration{0, -time.Nanosecond, -time.Hour} {
		tm := c.NewTimer(d)
		select {
		case <-tm.C():
		default:
			t.Fatalf("a timer for %s did not fire without an Advance; a real time.Timer does, "+
				"and a fake that is more forgiving hides a loop that polls instead of waiting", d)
		}
		tm.Stop()
	}
	// And the other half: a future deadline must NOT fire early, or the fake
	// would pass the test above by firing everything.
	tm := c.NewTimer(time.Hour)
	select {
	case <-tm.C():
		t.Fatal("a timer for an hour ahead fired immediately")
	default:
	}
	c.Advance(time.Hour + time.Second)
	select {
	case <-tm.C():
	case <-time.After(time.Second):
		t.Fatal("a timer did not fire after its deadline passed")
	}
	tm.Stop()
}

// TestSmokeShipsTheVirtualRigHappyPath is what the delivered run command
// `go test ./winn3/netlab -run Smoke -count=1` actually matches.
//
// It exists because before it was written the filter matched NOTHING: neither
// existing test in this file contains "Smoke", so the deliverable command
// reported `ok [no tests to run]` — a green that never ran anything, which is
// the exact shape this package's catalogue exists to retract.
//
// It is the whole happy path in one Pair: a perfect link carries a full-size
// flow end to end, a carrier swap keeps the same epoch and keeps carrying, and
// the post-migration flow is lossless. Those are the properties rig.go, pump.go
// and link.go were shipped to provide, and each is asserted against a body,
// never against a name.
func TestSmokeShipsTheVirtualRigHappyPath(t *testing.T) {
	t.Parallel()
	p := burstPair(t, PairConfig{})

	sent, got := p.SendInner(64, p.FullPayload(), 40*time.Second)
	if sent != 64 {
		t.Fatalf("the client's host device accepted only %d of 64 packets on a perfect link", sent)
	}
	if got != sent {
		t.Fatalf("delivered %d of %d full-size packets on a perfect link; the rig itself is "+
			"not loopback", got, sent)
	}

	if err := p.MigrateTo(carrier.ClassTCP, p.Sizing.PathMTU); err != nil {
		t.Fatalf("the carrier swap was refused on a healthy session: %v", err)
	}
	if err := p.ProveCarrying(30 * time.Second); err != nil {
		t.Fatalf("the fresh carrier never carried the session after the swap: %v", err)
	}
	sent2, got2 := p.SendInner(40, p.FullPayload(), 30*time.Second)
	if sent2 != 40 {
		t.Fatalf("the client's host device accepted only %d of 40 packets after the swap", sent2)
	}
	if got2 != sent2 {
		t.Fatalf("delivered %d of %d full-size packets after the carrier swap; the migration "+
			"lost data on a healthy session", got2, sent2)
	}
	if p.Client.Loop.Session().Epoch() != p.Gateway.Loop.Session().Epoch() {
		t.Fatal("the two ends disagree about the epoch after the swap; the rig handed them " +
			"different sessions")
	}
}
