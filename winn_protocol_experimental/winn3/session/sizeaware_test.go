package session

import (
	"errors"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// The size-aware liveness signal, tested where its rules can be stated exactly.
//
// The rig in winn3/netlab proves these properties survive a real path. What it
// cannot do is put a finger on the one line each of them turns on, and each of
// these rules is one line that a later edit could plausibly "simplify" back into
// the defect it fixes.

// established drives a pair to Established and returns it.
func established(t *testing.T, tweak func(cli, gw *Config)) *pair {
	t.Helper()
	p := newPair(t, tweak)
	p.establish()
	return p
}

// TestAWideFrameIsSealedToTheCeilingAndNotToABucket is the mechanism.
//
// A probe that is padded by the ordinary shaper is a probe of an arbitrary size,
// and an arbitrary size answers an arbitrary question. The point of a wide probe
// is that it is EXACTLY as large as the traffic this session emits, so that "the
// probe crossed" and "my data crosses" are the same statement.
//
// The trap this pins is specific: shaper.target returns "no padding" for a
// minLen at or above the ceiling, so asking the shaper for a wide target would
// silently emit a nine-byte PING as a small message and turn the wide probe into
// a narrow one — a detector quietly measuring the wrong thing, which is the
// original defect wearing the fix's clothes.
func TestAWideFrameIsSealedToTheCeilingAndNotToABucket(t *testing.T) {
	t.Parallel()
	p := established(t, nil)

	p.cli.mu.Lock()
	if err := p.cli.queueProbe(p.clk.Now(), true); err != nil {
		p.cli.mu.Unlock()
		t.Fatal(err)
	}
	ceiling := p.cli.cfg.MaxMessageSize
	p.cli.mu.Unlock()

	msg, err := p.cli.Poll()
	if err != nil {
		t.Fatal(err)
	}
	if msg == nil {
		t.Fatal("a queued wide probe produced no message")
	}
	if len(msg) != ceiling {
		t.Fatalf("a wide probe was sealed to %d bytes, want exactly the %d-byte ceiling. A probe "+
			"smaller than the traffic it stands for cannot detect a path that carries small "+
			"messages and black holes large ones.", len(msg), ceiling)
	}
	if s := p.cli.Stats(); s.WideProbesSent != 1 {
		t.Fatalf("WideProbesSent is %d after one wide probe", s.WideProbesSent)
	}

	// And the narrow probe is NOT sealed to the ceiling, or the two classes would
	// be one class and the disambiguation would be a fiction.
	p.cli.mu.Lock()
	if err := p.cli.queueProbe(p.clk.Now(), false); err != nil {
		p.cli.mu.Unlock()
		t.Fatal(err)
	}
	p.cli.mu.Unlock()
	msg, err = p.cli.Poll()
	if err != nil {
		t.Fatal(err)
	}
	if msg == nil {
		t.Fatal("a queued narrow probe produced no message")
	}
	if len(msg) == ceiling {
		t.Fatalf("a narrow probe was also sealed to the %d-byte ceiling; the two size classes "+
			"are the same size and the detector cannot distinguish anything", ceiling)
	}
}

// TestAPongInheritsTheWidthOfThePingItAnswers is the return leg.
//
// A wide probe answered by a narrow PONG proves only that the OUTBOUND path
// carries a full-size message. A path narrowed on the return leg would then
// answer every wide probe from a path that cannot carry the answer, and the
// verdict would never fire on the direction that was actually broken.
func TestAPongInheritsTheWidthOfThePingItAnswers(t *testing.T) {
	t.Parallel()
	p := established(t, nil)

	ping := core.Frame{Type: core.FramePing, Value: make([]byte, pingTokenSize)}
	for _, wide := range []bool{true, false} {
		p.gw.mu.Lock()
		p.gw.ctrl = nil
		if _, err := p.gw.handleFrames(p.clk.Now(), []core.Frame{ping}, wide); err != nil {
			p.gw.mu.Unlock()
			t.Fatal(err)
		}
		queued := append([]pendingFrame(nil), p.gw.ctrl...)
		p.gw.mu.Unlock()

		if len(queued) != 1 || queued[0].typ != core.FramePong {
			t.Fatalf("a PING in a wide=%v message queued %d frames, want one PONG", wide, len(queued))
		}
		if queued[0].wide != wide {
			t.Fatalf("a PING that arrived in a wide=%v message was answered with a wide=%v PONG; "+
				"the answer must cross the same path at the same size or it proves only one leg",
				wide, queued[0].wide)
		}
	}
}

// TestAssembleNeverCoalescesAcrossTheWidthBoundary is the trap the netlab lane's
// own §3.3 warns about, one layer down.
//
// The session coalesces control frames until the message budget is spent. If a
// narrow probe were packed into a message some other frame had already made
// full-size, it would be black holed by exactly the path it exists to measure —
// and the detector would then read "small messages do not cross either", which
// is the wrong verdict reached by the fix's own machinery.
func TestAssembleNeverCoalescesAcrossTheWidthBoundary(t *testing.T) {
	t.Parallel()
	p := established(t, nil)

	p.cli.mu.Lock()
	ceiling := p.cli.cfg.MaxMessageSize
	tok := [pingTokenSize]byte{1}
	p.cli.ctrl = []pendingFrame{
		pongFrame(tok[:], false),
		pingFrame(tok, true),
		pongFrame(tok[:], false),
	}
	p.cli.mu.Unlock()

	var sizes []int
	for i := 0; i < 4; i++ {
		msg, err := p.cli.Poll()
		if err != nil {
			t.Fatal(err)
		}
		if msg == nil {
			break
		}
		sizes = append(sizes, len(msg))
	}
	if len(sizes) < 3 {
		t.Fatalf("three frames of alternating width produced %d messages (%v); they were "+
			"coalesced across the boundary and the narrow ones rode a full-size message",
			len(sizes), sizes)
	}
	if sizes[0] == ceiling {
		t.Fatalf("the first message is %d bytes; a narrow PONG was widened by the wide PING "+
			"queued behind it", sizes[0])
	}
	if sizes[1] != ceiling {
		t.Fatalf("the second message is %d bytes, want the %d-byte ceiling", sizes[1], ceiling)
	}
	if sizes[2] == ceiling {
		t.Fatalf("the third message is %d bytes; the narrow PONG behind the wide PING was "+
			"widened by it", sizes[2])
	}
}

// TestANarrowPongDoesNotClearAWideProbe is the single line the whole signal
// rests on.
//
// The old rule was "one answered probe proves the whole path, so every
// outstanding probe is resolved". That is what made a narrowed path invisible: a
// small PONG cleared a wide probe the path had in fact black holed, so the
// detector concluded the path was fine on evidence about a message the path was
// never asked to carry.
func TestANarrowPongDoesNotClearAWideProbe(t *testing.T) {
	t.Parallel()
	p := established(t, nil)
	d := p.cli
	now := p.clk.Now()

	d.mu.Lock()
	defer d.mu.Unlock()

	wideTok := [pingTokenSize]byte{1}
	narrowTok := [pingTokenSize]byte{2}
	d.inflight[wideTok] = probeState{at: now, wide: true}
	d.inflight[narrowTok] = probeState{at: now, wide: false}
	d.lost, d.lostWide = 2, 1

	// A NARROW answer resolves the narrow probe and nothing else.
	d.onPong(now, narrowTok[:])
	if _, still := d.inflight[wideTok]; !still {
		t.Fatal("a narrow PONG resolved an outstanding WIDE probe. That is the defect: it " +
			"concludes the path carries full-size messages from evidence about a small one.")
	}
	if _, gone := d.inflight[narrowTok]; gone {
		t.Fatal("a narrow PONG did not resolve its own probe")
	}
	if d.lostWide != 1 {
		t.Fatalf("the wide ladder was reset to %d by a narrow PONG", d.lostWide)
	}
	if d.lost != 1 {
		t.Fatalf("lost is %d after a narrow PONG resolved one of two ladders, want the wide "+
			"ladder's 1", d.lost)
	}
	if !d.narrowOKAt.Equal(now) {
		t.Fatal("a narrow PONG did not record that the narrow class is alive; without that " +
			"record the narrowed verdict has no disproof to stand on")
	}

	// A WIDE answer resolves everything, because a full-size round trip implies
	// every smaller one.
	d.narrowed = true
	d.onPong(now, wideTok[:])
	if len(d.inflight) != 0 {
		t.Fatalf("%d probes still outstanding after a wide PONG", len(d.inflight))
	}
	if d.lost != 0 || d.lostWide != 0 {
		t.Fatalf("a wide PONG left lost=%d lostWide=%d", d.lost, d.lostWide)
	}
	if d.narrowed {
		t.Fatal("the narrowed verdict survived a wide probe being answered end to end; it must " +
			"clear on positive evidence, or a path that recovered stays marked forever")
	}
}

// TestTheProbeLadderAlternatesOnlyOnceTheWideOneIsFailing pins the schedule.
//
// Always wide is what makes the default question the right one. Alternating from
// the start would halve the rate of the ladder that drives the DEAD-path
// verdict, and the documented 43.5 s detection cost for a burst loss beyond the
// token window would double — 17 seconds of extra dead tunnel for a user who
// already cannot reach anything.
func TestTheProbeLadderAlternatesOnlyOnceTheWideOneIsFailing(t *testing.T) {
	t.Parallel()
	p := established(t, nil)
	d := p.cli

	d.mu.Lock()
	defer d.mu.Unlock()

	d.lostWide = 0
	d.lastProbeWide = true
	if !d.nextProbeIsWide() {
		t.Fatal("a healthy session queued a NARROW probe; the default question must be whether " +
			"the path carries what this session actually sends")
	}
	d.lastProbeWide = false
	if !d.nextProbeIsWide() {
		t.Fatal("a healthy session queued a narrow probe after a narrow one")
	}

	d.lostWide = 1
	d.lastProbeWide = true
	if d.nextProbeIsWide() {
		t.Fatal("the wide ladder is failing and the next probe is wide again; without a narrow " +
			"probe there is no round-trip evidence that small messages DO cross, and a narrowed " +
			"path is indistinguishable from a dead one")
	}
	d.lastProbeWide = false
	if !d.nextProbeIsWide() {
		t.Fatal("the alternation stopped testing the wide class, so a path that recovered would " +
			"never be observed to have recovered")
	}
}

// TestTheUnreachableVerdictNeedsSilenceAsWellAsAnExpiredBudget is the fix for
// the off-path spray.
//
// The probe budget alone is a teardown primitive an attacker can manufacture:
// the receive path is bounded, so noise at volume displaces real messages and
// PONGs with them, and the honest detector then fires on a fabricated outage.
// Requiring that NOTHING AUTHENTICATED arrived meanwhile refuses the fabrication
// without weakening the real verdict, because a peer that has genuinely gone
// sends nothing.
func TestTheUnreachableVerdictNeedsSilenceAsWellAsAnExpiredBudget(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		heard bool
		want  bool // want a teardown
	}{
		{"nothing arrived: the peer really is unreachable", false, true},
		{"the peer is still reaching us: the outage is fabricated", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := established(t, nil)
			d := p.cli
			d.mu.Lock()
			now := p.clk.Now()
			// The factor of two is deliberate and it is NOT a boundary being
			// cleared quietly. This test's subject is the silence half of the
			// verdict, so every probe here must be unambiguously expired however
			// the expiry compares — the backdate exists to take the boundary OUT
			// of the question. It also cannot be tightened to exactly Probe.Max
			// as a way of testing the boundary here: that boundary is owned,
			// from both sides and one tick either way, by
			// TestAProbeIsLostTheInstantItHasBeenOutstandingForProbeMax in
			// probedeadline_test.go. A `2 *` in a backdate is normally how an
			// off-by-one hides; this one is checked, and the check is elsewhere.
			sent := now.Add(-2 * d.cfg.Probe.Max)
			for i := 0; i < d.cfg.MaxLostProbes; i++ {
				tok := [pingTokenSize]byte{byte(i + 1)}
				d.inflight[tok] = probeState{at: sent, wide: false}
			}
			// lastOpened is either older than the probes (silence) or newer than
			// them (the peer is reaching us). Nothing else differs.
			if tc.heard {
				d.lastOpened = now
			} else {
				d.lastOpened = sent.Add(-time.Second)
			}
			err := d.tickEstablished(now)
			state, lost := d.state, d.lost
			d.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if lost < d.cfg.MaxLostProbes {
				t.Fatalf("only %d probes expired; the case was not reached", lost)
			}
			gone := state != StateEstablished
			if gone != tc.want {
				t.Fatalf("state is %s after a full probe budget with heard=%v; want teardown=%v. "+
					"The two cases differ ONLY in whether the peer was still reaching us, which "+
					"is the one fact an off-path attacker cannot manufacture.",
					state, tc.heard, tc.want)
			}
		})
	}
}

// TestSetMaxMessageSizeHoldsBothInvariantsTheSinkAsksFor is the lever, and the
// two ways it can go wrong.
//
// carrier.MessageSizeSink states them: recompute the shaper, because a bucket
// above the new ceiling would round a small packet up past what the carrier can
// send; and refuse to shrink below what an already-queued frame needs, because
// that frame has nowhere to go and dropping it silently is the black hole one
// layer in — arriving, this time, by way of the fix for it.
func TestSetMaxMessageSizeHoldsBothInvariantsTheSinkAsksFor(t *testing.T) {
	t.Parallel()
	p := established(t, nil)
	d := p.cli

	d.mu.Lock()
	before := d.cfg.MaxMessageSize
	d.mu.Unlock()

	if err := d.SetMaxMessageSize(MessageFloor() - 1); err == nil {
		t.Fatal("a ceiling below the message floor was accepted; the session could not emit a " +
			"single cover packet at it")
	}
	if err := d.SetMaxMessageSize(core.MaxTransportPayload + 1); err == nil {
		t.Fatal("a ceiling above the encoding bound was accepted")
	}

	narrower := before - 200
	if err := d.SetMaxMessageSize(narrower); err != nil {
		t.Fatalf("SetMaxMessageSize(%d): %v", narrower, err)
	}

	// Invariant 1: NO padding target may exceed the new ceiling, for any message
	// the session could ever build. This is a sweep rather than a sample, and it
	// has to be: the ladder is a per-session random draw, so whether a stale
	// boundary above the new ceiling is ever REACHED depends on where the draw
	// put the boundaries below it. A single probe packet would leave a clamp that
	// keeps stale buckets passing on most seeds and failing on some — the worst
	// kind of test, and the exact reason a first mutation pass here survived.
	d.mu.Lock()
	shape := d.shape
	d.mu.Unlock()
	for minLen := MessageFloor(); minLen <= narrower; minLen++ {
		target, err := shape.target(minLen)
		if err != nil {
			t.Fatal(err)
		}
		if target != 0 && target > narrower {
			t.Fatalf("a message needing %d bytes is padded to %d against a %d-byte ceiling; the "+
				"ladder still holds a boundary above the ceiling, so the carrier refuses (or the "+
				"path black holes) every message that reaches it", minLen, target, narrower)
		}
	}

	// And on the wire: a one-byte inner packet must not produce a message wider
	// than the carrier can send.
	if err := d.Enqueue([]byte{1}); err != nil {
		t.Fatal(err)
	}
	msg, err := d.Poll()
	if err != nil {
		t.Fatal(err)
	}
	if msg == nil {
		t.Fatal("nothing was emitted for a queued inner packet")
	}
	if len(msg) > narrower {
		t.Fatalf("a one-byte packet was padded to %d bytes against a %d-byte ceiling; the "+
			"shaper's ladder was not clamped and every padded message is now oversize",
			len(msg), narrower)
	}
	// And the ladder still shapes: the ceiling is a boundary, so a message that
	// needs it is sealed to it rather than left unpadded.
	if err := d.Enqueue(make([]byte, InnerMTU(narrower))); err != nil {
		t.Fatal(err)
	}
	if msg, err = d.Poll(); err != nil || msg == nil {
		t.Fatalf("poll after a full-size packet at the new ceiling: %v", err)
	}
	if len(msg) != narrower {
		t.Fatalf("a full-size packet at the new ceiling produced a %d-byte message, want %d",
			len(msg), narrower)
	}

	// Invariant 2: a shrink an already-queued frame cannot survive is REFUSED.
	if err := d.Enqueue(make([]byte, InnerMTU(narrower))); err != nil {
		t.Fatal(err)
	}
	if err := d.SetMaxMessageSize(MessageFloor() + 8); err == nil {
		t.Fatal("a shrink below what a queued inner packet needs was accepted; that packet has " +
			"nowhere to go and dropping it silently is the failure this whole change is about")
	}
	// The refusal must not have half-applied.
	if err := d.Enqueue(make([]byte, InnerMTU(narrower))); err != nil {
		t.Fatalf("the refused shrink narrowed the session anyway: %v", err)
	}
}

// TestSetMaxMessageSizeIsRefusedOnATerminalSession keeps the lever from being a
// way to touch a session that is already gone.
func TestSetMaxMessageSizeIsRefusedOnATerminalSession(t *testing.T) {
	t.Parallel()
	p := established(t, nil)
	if err := p.cli.Close(); err != nil {
		t.Fatal(err)
	}
	p.run()
	if !p.cli.State().Terminal() {
		p.cli.mu.Lock()
		p.cli.terminate()
		p.cli.mu.Unlock()
	}
	if err := p.cli.SetMaxMessageSize(1000); !errors.Is(err, ErrClosed) {
		t.Fatalf("SetMaxMessageSize on a terminal session returned %v, want ErrClosed", err)
	}
}
