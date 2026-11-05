package session

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// One lost REKEY_INIT used to end the session: the INIT was queued once and
// the initiator then waited out RekeyTimeout with its data plane shut. The
// resend lets the same rekey complete, on both ends, exactly once.
func TestLostRekeyInitIsResentAndTheRekeyCompletes(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.RekeyTimeout = 15 * time.Second
		gw.RekeyTimeout = 15 * time.Second
	})
	p.establish()
	cliEpoch, gwEpoch := p.cli.Epoch(), p.gw.Epoch()

	start := p.nToGw
	p.filterToGw = func(idx int, _ []byte) bool { return idx != start } // drop only the first INIT
	if err := p.cli.startRekey(p.clk.Now()); err != nil {
		t.Fatal(err)
	}
	p.run()
	if p.cli.State() != StateRekeying || p.gw.Epoch() != gwEpoch {
		t.Fatalf("precondition: INIT not lost (client %s, gateway epoch %d)", p.cli.State(), p.gw.Epoch())
	}
	for i := 0; i < 60 && p.cli.State() == StateRekeying; i++ {
		p.clk.Advance(250 * time.Millisecond)
		p.run()
	}
	if p.cli.State() != StateEstablished || p.gw.State() != StateEstablished {
		t.Fatalf("after the resend: client %s (err %v), gateway %s (err %v)",
			p.cli.State(), p.cli.Err(), p.gw.State(), p.gw.Err())
	}
	if p.cli.Epoch() != cliEpoch+1 || p.gw.Epoch() != gwEpoch+1 {
		t.Fatalf("epochs %d/%d, want one ratchet each from %d/%d",
			p.cli.Epoch(), p.gw.Epoch(), cliEpoch, gwEpoch)
	}
	if p.cli.Stats().Rekeys != 1 || p.gw.Stats().Rekeys != 1 {
		t.Fatalf("rekeys client %d gateway %d, want exactly 1 each", p.cli.Stats().Rekeys, p.gw.Stats().Rekeys)
	}
	if got := p.cli.Stats().RekeyInitResends; got == 0 {
		t.Fatal("the rekey completed without a resend; the test did not lose the INIT")
	}
	if !p.cli.NextDeadline().After(p.clk.Now()) {
		t.Fatal("an established session reports a past deadline after the resend")
	}

	// And the new epoch carries data both ways.
	p.resetDelivered()
	if err := p.cli.Enqueue([]byte("after the resent rekey")); err != nil {
		t.Fatal(err)
	}
	if err := p.gw.Enqueue([]byte("and back")); err != nil {
		t.Fatal(err)
	}
	p.run()
	if len(p.atGw) != 1 || !bytes.Equal(p.atGw[0], []byte("after the resent rekey")) {
		t.Fatalf("gateway received %q", p.atGw)
	}
	if len(p.atCli) != 1 || !bytes.Equal(p.atCli[0], []byte("and back")) {
		t.Fatalf("client received %q", p.atCli)
	}
}

// The resend schedule is jittered, bounded inside RekeyTimeout, and armed only
// while this end waits for an ACK. When every INIT is lost the timeout still
// decides, exactly as before.
func TestRekeyInitResendScheduleIsBoundedAndTheTimeoutStillDecides(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.RekeyTimeout = 15 * time.Second
	})
	p.establish()
	start := p.nToGw
	p.filterToGw = func(idx int, _ []byte) bool { return idx < start }
	began := p.clk.Now()
	if err := p.cli.startRekey(began); err != nil {
		t.Fatal(err)
	}
	first := p.cli.NextDeadline()
	if !first.After(began) || first.Sub(began) < rekeyResendBase/2 || first.Sub(began) > rekeyResendBase {
		t.Fatalf("first resend at %v after start, want within [%v, %v]",
			first.Sub(began), rekeyResendBase/2, rekeyResendBase)
	}
	for i := 0; i < 200 && !p.cli.State().Terminal(); i++ {
		p.clk.Advance(100 * time.Millisecond)
		p.run()
	}
	if !p.cli.State().Terminal() {
		t.Fatalf("client state is %s after the rekey timeout", p.cli.State())
	}
	if err := p.cli.Err(); !errors.Is(err, ErrRekeyFailed) {
		t.Fatalf("error is %v, want ErrRekeyFailed", err)
	}
	resends := p.cli.Stats().RekeyInitResends
	// 15 s with windows 0.75, 1.5, 3, then 4 s capped, each fired in its upper
	// half: the latest draws give 5 resends, the earliest 9.
	if resends < 5 || resends > 9 {
		t.Fatalf("%d resends inside a 15 s timeout, want 5..9", resends)
	}
}

// A duplicate REKEY_INIT that reaches the responder before it has sealed its
// ACK must not start a second ratchet.
func TestDuplicateRekeyInitBeforeTheAckIsIgnored(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
	})
	p.establish()
	gwEpoch := p.gw.Epoch()
	if err := p.cli.startRekey(p.clk.Now()); err != nil {
		t.Fatal(err)
	}
	value := p.cli.rekeyPriv.PublicKey().Bytes()
	now := p.clk.Now()
	for i := 0; i < 2; i++ {
		if _, err := p.gw.handleFrames(now, []core.Frame{{Type: core.FrameRekeyInit, Value: value}}, false); err != nil {
			t.Fatal(err)
		}
	}
	acks := 0
	for _, f := range p.gw.ctrl {
		if f.typ == core.FrameRekeyAck {
			acks++
		}
	}
	if acks != 1 {
		t.Fatalf("the responder queued %d ACKs for one INIT seen twice, want 1", acks)
	}
	p.run()
	if p.gw.Epoch() != gwEpoch+1 || p.gw.Stats().Rekeys != 1 {
		t.Fatalf("gateway epoch %d rekeys %d, want one ratchet", p.gw.Epoch(), p.gw.Stats().Rekeys)
	}
}
