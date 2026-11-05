package session

// Seat C parity probe: builds on the release tree and the lane tree. A response
// opens, then every later gateway datagram is lost forever. Records what
// HasAuthenticatedReply says at every step until the client is terminal, and
// the close verdict.

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestSeatCStickyReplyParity(t *testing.T) {
	for _, dual := range []bool{true, false} {
		edPriv, edPub, mlSeed, mlPub := dualKeys(t)
		p := newPair(t, func(cli, gw *Config) {
			quietConfig(cli)
			quietConfig(gw)
			if dual {
				gw.DualAuth = DualAuthConfig{Ed25519Private: edPriv, MLDSA65Seed: mlSeed}
				cli.DualAuth = DualAuthConfig{Expected: true, Ed25519Public: edPub, MLDSA65Public: mlPub}
			}
		})
		// Only the very first gateway datagram (the response) ever arrives.
		p.filterToCli = func(idx int, _ []byte) bool { return idx == 0 }
		p.run()
		start := p.clk.Now()
		falseAt := time.Duration(-1)
		steps := 0
		for !p.cli.State().Terminal() && steps < 200 {
			if !p.cli.HasAuthenticatedReply() && falseAt < 0 {
				falseAt = p.clk.Now().Sub(start)
			}
			dl := p.cli.NextDeadline()
			if !dl.After(p.clk.Now()) {
				dl = p.clk.Now().Add(time.Millisecond)
			}
			p.clk.Advance(dl.Sub(p.clk.Now()))
			p.run()
			steps++
		}
		t.Logf("dual=%v: terminal=%v after %v, reason=%s needCarrier=%v attempts=%d, HasAuthenticatedReply first false at %v (-1 = never), at end=%v",
			dual, p.cli.State().Terminal(), p.clk.Now().Sub(start), p.cli.LocalCloseReason(), p.cli.NeedsCarrierChange(),
			p.cli.Stats().HandshakeAttempts, falseAt, p.cli.HasAuthenticatedReply())
	}
}

// Same path, but one datagram of the superseded generation (its PQ_CT) arrives
// late, after the supersession. Lane tree only (reads GenerationsSuperseded).
//
// Seat C N-1, made an assertion in the lane: a connect that was answered, then
// superseded, then went unanswered, closes pq-failed with no carrier change
// and ErrPQFailed (the release tree's verdict for the same path), whether or
// not a stale datagram of the dead generation arrived, and HasAuthenticatedReply
// stays true.
func TestSeatCStaleDatagramFlipsTheCarrierVerdict(t *testing.T) {
	var verdicts []string
	for _, late := range []bool{false, true} {
		p := newPair(t, func(cli, gw *Config) {
			quietConfig(cli)
			quietConfig(gw)
		})
		var held []byte
		p.filterToCli = func(idx int, m []byte) bool {
			if idx == 1 {
				held = append([]byte(nil), m...)
			}
			return idx == 0
		}
		p.run()
		delivered := false
		for !p.cli.State().Terminal() {
			if late && !delivered && p.cli.Stats().GenerationsSuperseded > 0 {
				_, _ = p.cli.Deliver(held)
				delivered = true
			}
			dl := p.cli.NextDeadline()
			if !dl.After(p.clk.Now()) {
				dl = p.clk.Now().Add(time.Millisecond)
			}
			p.clk.Advance(dl.Sub(p.clk.Now()))
			p.run()
		}
		t.Logf("late stale PQ_CT=%v: reason=%s needCarrier=%v err=%v HasAuthenticatedReply=%v unopenable=%d",
			late, p.cli.LocalCloseReason(), p.cli.NeedsCarrierChange(), p.cli.Err(), p.cli.HasAuthenticatedReply(), p.cli.Stats().Unopenable)
		if late && !delivered {
			t.Fatal("fixture: no supersession happened, so the stale datagram was never delivered")
		}
		if p.cli.LocalCloseReason() != ClosePQFailed || p.cli.NeedsCarrierChange() || !errors.Is(p.cli.Err(), ErrPQFailed) {
			t.Fatalf("late=%v: reason %s, carrier change %v, err %v; want %s, false, ErrPQFailed",
				late, p.cli.LocalCloseReason(), p.cli.NeedsCarrierChange(), p.cli.Err(), ClosePQFailed)
		}
		if !p.cli.HasAuthenticatedReply() {
			t.Fatalf("late=%v: HasAuthenticatedReply false after an answered generation", late)
		}
		verdicts = append(verdicts, fmt.Sprintf("%s/%v/%v", p.cli.LocalCloseReason(), p.cli.NeedsCarrierChange(), p.cli.Err()))
	}
	if verdicts[0] != verdicts[1] {
		t.Fatalf("a stale datagram of the dead generation changed the verdict: %q vs %q", verdicts[0], verdicts[1])
	}
}
