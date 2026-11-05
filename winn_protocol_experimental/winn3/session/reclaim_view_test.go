package session

import (
	"bytes"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// TestRetireIfQuietIsAtomicWithReceive drives the commit directly: a snapshot
// taken, an authenticated receive, then RetireIfQuiet on the stale sequence must
// REFUSE; on the current sequence of a quiet session it must succeed and leave
// the session terminal. This is property 1 at the layer where the atomicity
// lives.
func TestRetireIfQuietIsAtomicWithReceive(t *testing.T) {
	p := newPair(t, nil)
	p.establish()

	stale := p.gw.ReclaimView().Seq

	if err := p.cli.Enqueue([]byte("live traffic")); err != nil {
		t.Fatal(err)
	}
	p.run()
	if got := p.gw.ReclaimView().Seq; got == stale {
		t.Fatalf("an authenticated receive did not move the sequence (%d)", got)
	}

	if p.gw.RetireIfQuiet(stale) {
		t.Fatal("RetireIfQuiet committed against a sequence a receive had already moved")
	}
	if p.gw.State().Terminal() {
		t.Fatal("the session was terminated on a refused retirement")
	}

	cur := p.gw.ReclaimView().Seq
	if !p.gw.RetireIfQuiet(cur) {
		t.Fatal("RetireIfQuiet refused the current sequence of a quiet session")
	}
	if !p.gw.State().Terminal() {
		t.Fatal("RetireIfQuiet did not leave the session terminal")
	}
	if p.gw.Err() == nil {
		t.Fatal("a retired session recorded no error")
	}
	if !p.gw.RetireIfQuiet(cur + 1) {
		t.Fatal("RetireIfQuiet did not report an already-terminal session reclaimable")
	}
}

// TestReInitiationResetsCurrentGeneration pins property 2: an ordinary rekey
// preserves the current-generation marker, and a fresh re-initiation resets it,
// leaving the new generation authenticated but not yet established (the state a
// reclaim policy must protect).
func TestReInitiationResetsCurrentGeneration(t *testing.T) {
	p := newPair(t, nil)
	p.establish()
	before := p.gw.ReclaimView()
	if !before.Established || before.CurGenAt.IsZero() {
		t.Fatal("the gateway is not established after the handshake")
	}

	p.clk.Advance(time.Second)
	if err := p.gw.startRekey(p.clk.Now()); err != nil {
		t.Fatalf("startRekey: %v", err)
	}
	p.run()
	afterRekey := p.gw.ReclaimView()
	if !afterRekey.Established {
		t.Fatal("the gateway is not established after a rekey")
	}
	if !afterRekey.CurGenAt.Equal(before.CurGenAt) {
		t.Fatalf("a rekey moved the current-generation marker from %v to %v", before.CurGenAt, afterRekey.CurGenAt)
	}

	p.clk.Advance(time.Second)
	ini := p.newInitiator(t)
	msg, err := ini.WriteInitiation(nil, core.PadAuto)
	if err != nil {
		t.Fatalf("WriteInitiation: %v", err)
	}
	if _, err := p.gw.Deliver(msg); err != nil {
		t.Fatalf("Deliver re-initiation: %v", err)
	}
	reinit := p.gw.ReclaimView()
	if !reinit.Authenticated {
		t.Fatal("the re-initiated generation lost its authenticated peer")
	}
	if reinit.Established {
		t.Fatal("the re-initiated generation is marked established before it completed")
	}
	// Compare against the sequence AFTER the rekey, not the original: the rekey
	// itself advanced the sequence, so a re-initiation that merely matched the
	// pre-rekey value would still be caught by comparing to the wrong baseline.
	if reinit.Seq == afterRekey.Seq {
		t.Fatal("a fresh re-initiation did not move the sequence past the post-rekey value")
	}
}

// TestFirstAuthenticationAdvancesSequence is Gap 1: a half-open that first
// rejected an admission-valid but crypto-invalid initiation is snapshotted at
// sequence S with no peer; a valid initiation then authenticates and installs
// the session, which must move the sequence so a retirement committed against S
// is refused before the generation has even established.
func TestFirstAuthenticationAdvancesSequence(t *testing.T) {
	p := newPair(t, nil)

	// An admission-valid, crypto-invalid initiation: correct admission key and
	// gateway id, wrong gateway static key, so ReadInitiation counts it
	// Unopenable without authenticating.
	wrongGw, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	wrongPub, err := core.NewPublicKey(wrongGw.Public())
	if err != nil {
		t.Fatal(err)
	}
	clk := p.clk
	foreign, err := core.NewInitiator(core.Config{
		Gateway: p.gp,
		Now:     func() time.Time { return clk.Now() },
	}, p.cliStatic, wrongPub)
	if err != nil {
		t.Fatal(err)
	}
	fmsg, err := foreign.WriteInitiation(nil, core.PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.gw.Deliver(fmsg); err != nil {
		t.Fatalf("Deliver foreign initiation: %v", err)
	}
	snap := p.gw.ReclaimView()
	if snap.Authenticated || snap.Established {
		t.Fatalf("the crypto-invalid initiation authenticated: %+v", snap)
	}
	if p.gw.Stats().Unopenable == 0 {
		t.Fatal("the crypto-invalid initiation was not counted Unopenable")
	}

	// A valid initiation now authenticates and installs the session.
	valid := p.newInitiator(t)
	vmsg, err := valid.WriteInitiation(nil, core.PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.gw.Deliver(vmsg); err != nil {
		t.Fatalf("Deliver valid initiation: %v", err)
	}
	after := p.gw.ReclaimView()
	if !after.Authenticated {
		t.Fatal("the valid initiation did not authenticate the peer")
	}
	if after.Established {
		t.Fatal("the responder established before the post-quantum ratchet completed")
	}
	if after.Seq == snap.Seq {
		t.Fatal("the first authenticated handshake did not advance the sequence")
	}

	// The stale retirement, committed against the pre-authentication snapshot,
	// must be refused; the authenticated, still-completing handshake survives.
	if p.gw.RetireIfQuiet(snap.Seq) {
		t.Fatal("a retirement committed against a pre-authentication snapshot killed the authenticated handshake")
	}
	if p.gw.State().Terminal() {
		t.Fatal("the authenticated handshake is terminal after a refused stale retirement")
	}
}

// buildConfirmedGateway establishes a gateway driver and drives one data message
// after establishment so its LastAuthRecv is strictly after its CurGenAt
// (confirmed usable). adv offsets the clock before establishment so callers can
// order two gateways' establishment instants.
func buildConfirmedGateway(t *testing.T, adv time.Duration) *pair {
	t.Helper()
	p := newPair(t, nil)
	if adv > 0 {
		p.clk.Advance(adv)
	}
	p.establish()
	p.clk.Advance(time.Second)
	if err := p.cli.Enqueue([]byte("confirming traffic")); err != nil {
		t.Fatal(err)
	}
	p.run()
	v := p.gw.ReclaimView()
	if !v.Established || !v.LastAuthRecv.After(v.CurGenAt) {
		t.Fatalf("gateway not confirmed usable after setup: %+v", v)
	}
	return p
}

// reinitiate completes a FRESH re-initiation of p's peer: a new client driver on
// the same static key handshakes with p.gw, which admits it as a re-initiation
// of the same peer and establishes a new generation. The old client is
// discarded, as a phone that re-handshakes from a new socket discards its old
// session. It runs entirely at p.clk's current instant.
func reinitiate(t *testing.T, p *pair) {
	t.Helper()
	cli, err := NewClient(Config{
		Core:          p.cli.cfg.Core,
		Static:        p.cliStatic,
		GatewayStatic: p.gwPub,
		Padding:       p.cli.cfg.Padding,
		Clock:         p.clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	p.cli = cli
	p.toGw, p.toCli = nil, nil
	p.establish()
}

// olderConfirmedGateway is a confirmed gateway whose generation established one
// second BEFORE a fresh pair's clock start, so it is the older session against
// a replacement established at that start. The replacement must establish at
// the clock's start instant for these tests: a pair whose clock advanced before
// its first handshake sees a stale retransmission that arms the responder's
// re-initiation rate gate (reinitCheckInterval) at that instant, and a
// re-initiation at the same instant would then be deferred, not admitted.
func olderConfirmedGateway(t *testing.T) *pair {
	t.Helper()
	p := newPair(t, nil)
	p.clk.Advance(-time.Second)
	p.establish()
	confirm(t, p, "the victim carries")
	return p
}

// confirm has p's client send one message that the gateway opens, after
// advancing the clock so the receive is strictly after the establishment.
func confirm(t *testing.T, p *pair, tag string) {
	t.Helper()
	p.clk.Advance(time.Second)
	if err := p.cli.Enqueue([]byte(tag)); err != nil {
		t.Fatal(err)
	}
	p.run()
}

// TestCurrentGenerationIDAdvancesOnlyOnANewGeneration pins curGenID (Round Q
// Turn 5, OI-Q2): fixed across authenticated receives and in-band rekeys, and
// advanced by every new generation, including one whose establishment has the
// same clock reading as the generation before it.
func TestCurrentGenerationIDAdvancesOnlyOnANewGeneration(t *testing.T) {
	p := newPair(t, nil)
	if v := p.gw.ReclaimView(); v.CurGenID != 0 || v.Established {
		t.Fatalf("before any establishment: %+v", v)
	}
	p.establish()
	g1 := p.gw.ReclaimView()
	if !g1.Established || g1.CurGenID == 0 {
		t.Fatalf("the first establishment did not start a generation: %+v", g1)
	}

	// A fresh re-initiation completed at the SAME clock reading as the first
	// establishment: curGenAt cannot tell the two generations apart, curGenID
	// must.
	reinitiate(t, p)
	g2 := p.gw.ReclaimView()
	if !g2.CurGenAt.Equal(g1.CurGenAt) {
		t.Fatalf("fixture: the held clock stamped %v and %v", g1.CurGenAt, g2.CurGenAt)
	}
	if !g2.Established || g2.CurGenID != g1.CurGenID+1 {
		t.Fatalf("a re-initiation at the same instant did not advance the generation by one: %d after %d", g2.CurGenID, g1.CurGenID)
	}

	confirm(t, p, "receive one")
	confirm(t, p, "receive two")
	if v := p.gw.ReclaimView(); v.CurGenID != g2.CurGenID || !v.CurGenAt.Equal(g2.CurGenAt) || !v.LastAuthRecv.After(v.CurGenAt) {
		t.Fatalf("authenticated receives moved the generation: %d at %v, want %d at %v", v.CurGenID, v.CurGenAt, g2.CurGenID, g2.CurGenAt)
	}

	p.clk.Advance(time.Second)
	if err := p.gw.startRekey(p.clk.Now()); err != nil {
		t.Fatalf("startRekey: %v", err)
	}
	p.run()
	if v := p.gw.ReclaimView(); v.State != StateEstablished || v.CurGenID != g2.CurGenID || !v.CurGenAt.Equal(g2.CurGenAt) {
		t.Fatalf("an in-band rekey moved the generation or did not complete: %+v", v)
	}
	confirm(t, p, "receive after the rekey")
	if v := p.gw.ReclaimView(); v.CurGenID != g2.CurGenID {
		t.Fatalf("a receive after the rekey moved the generation: %d, want %d", v.CurGenID, g2.CurGenID)
	}

	// A later re-initiation starts the next generation.
	p.clk.Advance(time.Second)
	reinitiate(t, p)
	g3 := p.gw.ReclaimView()
	if !g3.Established || g3.CurGenID != g2.CurGenID+1 || !g3.CurGenAt.After(g2.CurGenAt) {
		t.Fatalf("a later re-initiation did not start the next generation: %+v after %+v", g3, g2)
	}
	confirm(t, p, "receive on the newest generation")
	if v := p.gw.ReclaimView(); v.CurGenID != g3.CurGenID {
		t.Fatalf("a receive moved the newest generation: %d, want %d", v.CurGenID, g3.CurGenID)
	}
}

// TestCommitSupersedeAtomic is Gap 2 at the layer where atomicity lives: the
// two-driver commit terminates the victim only when both the victim's selected
// sequence and the replacement's current validity hold together under both
// locks. Each transition of either session between selection and commit refuses
// the commit and leaves both sessions untouched.
func TestCommitSupersedeAtomic(t *testing.T) {
	t.Run("valid replacement retires the older victim", func(t *testing.T) {
		victim := buildConfirmedGateway(t, 0)
		repl := buildConfirmedGateway(t, time.Second)
		vv := victim.gw.ReclaimView()
		rv := repl.gw.ReclaimView()
		if !vv.CurGenAt.Before(rv.CurGenAt) {
			t.Fatalf("fixture: victim not older (%v vs %v)", vv.CurGenAt, rv.CurGenAt)
		}
		if !CommitSupersede(victim.gw, repl.gw, vv.Seq, rv.CurGenID, rv.PeerStatic) {
			t.Fatal("a valid supersede was refused")
		}
		if !victim.gw.State().Terminal() {
			t.Fatal("the victim was not terminated")
		}
		if repl.gw.State().Terminal() {
			t.Fatal("the replacement was terminated")
		}
	})

	t.Run("replacement re-initiated after selection is refused", func(t *testing.T) {
		victim := buildConfirmedGateway(t, 0)
		repl := buildConfirmedGateway(t, time.Second)
		vv := victim.gw.ReclaimView()
		rv := repl.gw.ReclaimView()
		// The replacement accepts a fresh initiation: its current generation
		// resets, so it is no longer established.
		msg, err := repl.newInitiator(t).WriteInitiation(nil, core.PadAuto)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repl.gw.Deliver(msg); err != nil {
			t.Fatal(err)
		}
		if CommitSupersede(victim.gw, repl.gw, vv.Seq, rv.CurGenID, rv.PeerStatic) {
			t.Fatal("supersede committed against a re-initiated replacement")
		}
		if victim.gw.State().Terminal() {
			t.Fatal("the victim was terminated against an invalid replacement")
		}
	})

	t.Run("replacement terminated after selection is refused", func(t *testing.T) {
		victim := buildConfirmedGateway(t, 0)
		repl := buildConfirmedGateway(t, time.Second)
		vv := victim.gw.ReclaimView()
		rv := repl.gw.ReclaimView()
		if !repl.gw.RetireIfQuiet(rv.Seq) {
			t.Fatal("could not terminate the replacement for the test")
		}
		if CommitSupersede(victim.gw, repl.gw, vv.Seq, rv.CurGenID, rv.PeerStatic) {
			t.Fatal("supersede committed against a terminated replacement")
		}
		if victim.gw.State().Terminal() {
			t.Fatal("the victim was terminated against a terminated replacement")
		}
	})

	t.Run("established but unconfirmed replacement is refused", func(t *testing.T) {
		// The commit's own confirmation check, independent of selection: the
		// replacement established (the responder assembled its final flight) but
		// has opened nothing since, so its post-handshake keys are unproven.
		victim := buildConfirmedGateway(t, 0)
		repl := newPair(t, nil)
		repl.clk.Advance(time.Second)
		repl.establish()
		vv := victim.gw.ReclaimView()
		rv := repl.gw.ReclaimView()
		if !rv.Established || rv.LastAuthRecv.After(rv.CurGenAt) || !vv.CurGenAt.Before(rv.CurGenAt) {
			t.Fatalf("fixture: want a newer established replacement with nothing opened since: %+v", rv)
		}
		if CommitSupersede(victim.gw, repl.gw, vv.Seq, rv.CurGenID, rv.PeerStatic) {
			t.Fatal("supersede committed against a replacement whose post-handshake keys never opened anything")
		}
		if victim.gw.State().Terminal() {
			t.Fatal("the victim was terminated against an unconfirmed replacement")
		}
	})

	t.Run("replacement that received after selection still supersedes", func(t *testing.T) {
		// Round Q Turn 4, OI-Q4: a busy replacement's authenticated traffic moves
		// its sequence between selection and commit on every sweep. That changes
		// nothing about its validity, so it must not defer the supersede.
		victim := buildConfirmedGateway(t, 0)
		repl := buildConfirmedGateway(t, time.Second)
		vv := victim.gw.ReclaimView()
		rv := repl.gw.ReclaimView()
		repl.clk.Advance(time.Second)
		if err := repl.cli.Enqueue([]byte("replacement traffic after selection")); err != nil {
			t.Fatal(err)
		}
		repl.run()
		if repl.gw.ReclaimView().Seq == rv.Seq {
			t.Fatal("fixture: the replacement's receive did not move its sequence")
		}
		if !CommitSupersede(victim.gw, repl.gw, vv.Seq, rv.CurGenID, rv.PeerStatic) {
			t.Fatal("supersede was deferred by the replacement's own traffic")
		}
		if !victim.gw.State().Terminal() || repl.gw.State().Terminal() {
			t.Fatal("the wrong session ended")
		}
	})

	t.Run("replacement generation differs from selection is refused", func(t *testing.T) {
		// The replacement is revalidated by generation, not by sequence: a commit
		// against a generation other than the one selected refuses.
		victim := buildConfirmedGateway(t, 0)
		repl := buildConfirmedGateway(t, time.Second)
		vv := victim.gw.ReclaimView()
		rv := repl.gw.ReclaimView()
		if CommitSupersede(victim.gw, repl.gw, vv.Seq, rv.CurGenID+1, rv.PeerStatic) {
			t.Fatal("supersede committed against a replacement generation that was not selected")
		}
		if victim.gw.State().Terminal() {
			t.Fatal("the victim was terminated on a generation mismatch")
		}
	})

	t.Run("replacement re-established at the selected instant is refused", func(t *testing.T) {
		// Round Q Turn 5, OI-Q2. The replacement is selected with the clock held
		// at T, completes a fresh re-initiation still at T (so its curGenAt is
		// unchanged), and is confirmed after the clock advances. Peer, state,
		// confirmation and curGenAt all match the selection, but it is a
		// different generation, and the commit must refuse.
		victim := olderConfirmedGateway(t)
		repl := newPair(t, nil)
		repl.establish()
		vv := victim.gw.ReclaimView()
		rv := repl.gw.ReclaimView()
		reinitiate(t, repl)
		confirm(t, repl, "the new generation carries")
		cur := repl.gw.ReclaimView()
		if !cur.CurGenAt.Equal(rv.CurGenAt) || cur.CurGenID == rv.CurGenID ||
			!cur.LastAuthRecv.After(cur.CurGenAt) || cur.State != StateEstablished ||
			!bytes.Equal(cur.PeerStatic, rv.PeerStatic) {
			t.Fatalf("fixture: want a confirmed new generation at the selected instant: selected %+v, now %+v", rv, cur)
		}
		if CommitSupersede(victim.gw, repl.gw, vv.Seq, rv.CurGenID, rv.PeerStatic) {
			t.Fatal("supersede committed against a replacement generation other than the one selected")
		}
		if victim.gw.State().Terminal() {
			t.Fatal("the victim was terminated against a different replacement generation")
		}
		// Anti-vacuity: selected afresh, the new generation is a valid replacement.
		if !CommitSupersede(victim.gw, repl.gw, vv.Seq, cur.CurGenID, cur.PeerStatic) {
			t.Fatal("the confirmed new generation, selected afresh, was refused")
		}
	})

	t.Run("confirmed replacement re-established after the clock stepped back is refused", func(t *testing.T) {
		// The same gap with a CONFIRMED selection, as a supersede sweep would
		// select it: established at T, confirmed at T+1s and selected, then the
		// injected clock returns T, a re-initiation completes there, and the new
		// generation is confirmed after the clock advances again.
		victim := olderConfirmedGateway(t)
		repl := newPair(t, nil)
		repl.establish()
		confirm(t, repl, "the selected generation carries")
		vv := victim.gw.ReclaimView()
		rv := repl.gw.ReclaimView()
		if !rv.LastAuthRecv.After(rv.CurGenAt) {
			t.Fatal("fixture: the selected replacement is not confirmed")
		}
		repl.clk.Advance(-time.Second)
		reinitiate(t, repl)
		confirm(t, repl, "the new generation carries")
		cur := repl.gw.ReclaimView()
		if !cur.CurGenAt.Equal(rv.CurGenAt) || cur.CurGenID == rv.CurGenID || !cur.LastAuthRecv.After(cur.CurGenAt) {
			t.Fatalf("fixture: want a confirmed new generation at the selected instant: selected %+v, now %+v", rv, cur)
		}
		if CommitSupersede(victim.gw, repl.gw, vv.Seq, rv.CurGenID, rv.PeerStatic) {
			t.Fatal("supersede committed against a replacement generation other than the one selected")
		}
		if victim.gw.State().Terminal() {
			t.Fatal("the victim was terminated against a different replacement generation")
		}
	})

	t.Run("victim generation changed after selection is refused", func(t *testing.T) {
		victim := buildConfirmedGateway(t, 0)
		repl := buildConfirmedGateway(t, time.Second)
		vv := victim.gw.ReclaimView()
		rv := repl.gw.ReclaimView()
		// The victim accepts a fresh same-key initiation after selection: its
		// sequence moves and it must be reclassified, not retired on the stale
		// selected sequence.
		msg, err := victim.newInitiator(t).WriteInitiation(nil, core.PadAuto)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := victim.gw.Deliver(msg); err != nil {
			t.Fatal(err)
		}
		if CommitSupersede(victim.gw, repl.gw, vv.Seq, rv.CurGenID, rv.PeerStatic) {
			t.Fatal("supersede committed against a victim whose generation changed")
		}
		if victim.gw.State().Terminal() {
			t.Fatal("the re-initiated victim was terminated on its stale selected sequence")
		}
	})

	t.Run("wrong replacement peer is refused", func(t *testing.T) {
		victim := buildConfirmedGateway(t, 0)
		repl := buildConfirmedGateway(t, time.Second)
		vv := victim.gw.ReclaimView()
		rv := repl.gw.ReclaimView()
		if CommitSupersede(victim.gw, repl.gw, vv.Seq, rv.CurGenID, []byte("not-the-replacements-peer-key!!!")) {
			t.Fatal("supersede committed with a mismatched replacement peer")
		}
		if victim.gw.State().Terminal() {
			t.Fatal("the victim was terminated on a mismatched replacement peer")
		}
	})

	t.Run("victim not older than replacement is refused", func(t *testing.T) {
		older := buildConfirmedGateway(t, 0)
		newer := buildConfirmedGateway(t, time.Second)
		// Ask to retire the NEWER as if the older were its replacement: ordering
		// fails, so nothing is retired.
		nv := newer.gw.ReclaimView()
		ov := older.gw.ReclaimView()
		if CommitSupersede(newer.gw, older.gw, nv.Seq, ov.CurGenID, ov.PeerStatic) {
			t.Fatal("supersede committed with the victim newer than the replacement")
		}
		if newer.gw.State().Terminal() {
			t.Fatal("the newer session was retired against an older replacement")
		}
	})
}
