package netlab

import (
	"context"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/session"
)

// TestZZZRekeyHypothesis forces a rekey to fire during the unarmed data phase
// and asks whether it produces an Unopenable delta on the gateway — i.e. whether
// Collect's injected clock crossing the rekey interval is the scheduler-race
// root cause behind TestAPerfectLinkIsLoopback's ~1-in-84 flake.
func TestZZZRekeyHypothesis(t *testing.T) {
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	// Tiny rekey interval so a rekey fires inside the short data phase.
	p, err := NewPair(kr, PairConfig{
		TokenWindow: netlabWindow,
		SendQueue:   2048,
		Tweak: func(c *session.Config) {
			c.RekeyInterval = session.Draw{Min: 200 * time.Millisecond, Mean: 400 * time.Millisecond, Max: time.Second}
		},
	})
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
	if err := p.ProveCarrying(20 * time.Second); err != nil {
		t.Fatal(err)
	}
	base := p.Gateway.Loop.Session().Stats().Unopenable
	sent := p.OfferInner(400, p.FullPayload())
	got := p.Collect(sent, 40*time.Second)
	gw := p.Gateway.Loop.Session().Stats()
	cli := p.Client.Loop.Session().Stats()
	t.Logf("sent=%d got=%d base=%d now=%d delta=%d | gw.Rekeys=%d cli.Rekeys=%d | cli.HSm=%d",
		sent, got, base, gw.Unopenable, gw.Unopenable-base, gw.Rekeys, cli.Rekeys, cli.HandshakeMessagesSent)
	if gw.Unopenable != base {
		t.Fatalf("REKEY PRODUCES UNOPENABLE DELTA: delta=%d rekeys gw=%d cli=%d", gw.Unopenable-base, gw.Rekeys, cli.Rekeys)
	}
}
