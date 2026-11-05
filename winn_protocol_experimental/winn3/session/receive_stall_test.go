package session

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// assertNoStaleDeadline pins the self-deadlock rule from tickEstablished: once
// the pair has quiesced, no Established driver may report a deadline in the
// past, because nothing would consume it and the caller's loop would spin.
func assertNoStaleDeadline(t *testing.T, p *pair) {
	t.Helper()
	now := p.clk.Now()
	for name, d := range map[string]*Driver{"client": p.cli, "gateway": p.gw} {
		if d.State() != StateEstablished {
			continue
		}
		if dl := d.NextDeadline(); !dl.IsZero() && dl.Before(now) {
			t.Fatalf("%s NextDeadline %v is %v in the past after quiescence", name, dl, now.Sub(dl))
		}
	}
}

// A contiguous loss of more than the client's token window strands its receive
// direction for good. The session must notice and tear down in seconds, not
// after MaxLostProbes x Probe.Max.
func TestReceiveStallPastTheWindowTearsDownInSeconds(t *testing.T) {
	p := newPair(t, nil)
	p.establish()
	pl := p.gw.cfg.maxPayload() - frameHeaderSize
	start := p.nToCli
	const gap = 1100 // > DefaultTokenWindow on the client
	p.filterToCli = func(idx int, _ []byte) bool { return idx < start || idx >= start+gap }
	for i := 0; i < gap+200; i++ {
		if err := p.gw.Enqueue(bytes.Repeat([]byte{byte(i)}, pl)); err != nil {
			p.run()
			_ = p.gw.Enqueue(bytes.Repeat([]byte{byte(i)}, pl))
		}
	}
	p.run()
	if p.cli.Stats().Unopenable == 0 {
		t.Fatal("setup: the gap did not strand the client's receive window")
	}
	stalledAt := p.clk.Now()
	for step := 0; step < 600; step++ {
		p.clk.Advance(100 * time.Millisecond)
		for i := 0; i < 4; i++ {
			_ = p.gw.Enqueue(bytes.Repeat([]byte{0x5a}, pl))
		}
		p.run()
		if p.cli.State().Terminal() || p.cli.State() == StateClosing {
			break
		}
		assertNoStaleDeadline(t, p)
	}
	took := p.clk.Now().Sub(stalledAt)
	if !(p.cli.State().Terminal() || p.cli.State() == StateClosing) {
		t.Fatalf("client still %s after %v of a stranded receive window", p.cli.State(), took)
	}
	if !errors.Is(p.cli.Err(), ErrPeerUnreachable) {
		t.Fatalf("client closed with %v, want ErrPeerUnreachable", p.cli.Err())
	}
	if took > 6*time.Second {
		t.Fatalf("stranded receive window took %v to tear down, want <= 6s", took)
	}
	t.Logf("stranded receive window torn down after %v", took)
}

// Garbage at the 5-tuple of a healthy, idle session must never tear it down:
// the peer keeps answering probes, so lastOpened keeps moving.
func TestUnopenableNoiseOnAHealthyIdleSessionDoesNotTearDown(t *testing.T) {
	p := newPair(t, nil)
	p.establish()
	junk := make([]byte, p.cli.cfg.MaxMessageSize)
	before := p.cli.Stats()
	for step := 0; step < 600; step++ {
		p.clk.Advance(100 * time.Millisecond)
		if _, err := rand.Read(junk); err != nil {
			t.Fatal(err)
		}
		if _, err := p.cli.Deliver(append([]byte(nil), junk...)); err != nil {
			t.Fatalf("junk delivery returned %v", err)
		}
		p.run()
		if p.cli.State() != StateEstablished || p.gw.State() != StateEstablished {
			t.Fatalf("noise tore the session down at step %d: cli=%s (%v) gw=%s (%v)",
				step, p.cli.State(), p.cli.Err(), p.gw.State(), p.gw.Err())
		}
		assertNoStaleDeadline(t, p)
	}
	after := p.cli.Stats()
	if after.Unopenable-before.Unopenable < 600 {
		t.Fatalf("setup: only %d junk messages counted unopenable", after.Unopenable-before.Unopenable)
	}
	// Bounded extra probing: at most one stall probe per stallProbeDraw.Min.
	if sent := after.PingsSent - before.PingsSent; sent > uint64(60*time.Second/stallProbeDraw.Min)+16 {
		t.Fatalf("noise drove %d probes in 60s, above the stallProbeDraw.Min bound", sent)
	}
}

// Neither an idle healthy tunnel nor a one-way upload to a healthy peer that
// only answers probes may be torn down, and neither may probe excessively.
func TestHealthyIdleAndOneWayUploadStayUp(t *testing.T) {
	for _, upload := range []bool{false, true} {
		p := newPair(t, nil)
		p.establish()
		pl := p.cli.cfg.maxPayload() - frameHeaderSize
		before := p.cli.Stats()
		for step := 0; step < 600; step++ {
			p.clk.Advance(100 * time.Millisecond)
			if upload {
				_ = p.cli.Enqueue(bytes.Repeat([]byte{0x44}, pl))
			}
			p.run()
			if p.cli.State() != StateEstablished || p.gw.State() != StateEstablished {
				t.Fatalf("upload=%v: torn down at step %d: cli=%s (%v)", upload, step, p.cli.State(), p.cli.Err())
			}
			assertNoStaleDeadline(t, p)
		}
		sent := p.cli.Stats().PingsSent - before.PingsSent
		st := p.cli.Stats()
		t.Logf("upload=%v probes in 60s: %d (msgs_sent=%d pongs=%d lost=%d gw_pings=%d)", upload, sent, st.MessagesSent-before.MessagesSent, st.PongsReceived-before.PongsReceived, st.ProbesLost-before.ProbesLost, p.gw.Stats().PingsSent)
		if sent > 60 {
			t.Fatalf("upload=%v: %d probes in 60s", upload, sent)
		}
	}
}

// An old unanswered probe followed by healthy traffic must not hold a later
// dead path open: lostSince remembers the oldest loss, so the dead-path verdict
// counts only probes lost since the last authenticated receive (silentLost).
func TestAnOldLostProbeDoesNotHoldALaterDeadPathOpen(t *testing.T) {
	p := newPair(t, nil)
	p.establish()
	pl := p.cli.cfg.maxPayload() - frameHeaderSize
	// Phase 1: idle until the client emits a probe; drop exactly the next R2I
	// message (its PONG), then start two-way traffic at once, so the probe
	// expires as lost WHILE authenticated data keeps arriving.
	before := p.cli.Stats().PingsSent
	for step := 0; step < 600 && p.cli.Stats().PingsSent == before; step++ {
		p.clk.Advance(100 * time.Millisecond)
		mark := p.nToCli
		p.filterToCli = func(idx int, _ []byte) bool { return idx < mark }
		p.drain()
		if p.cli.Stats().PingsSent != before {
			break
		}
		p.filterToCli = nil
		p.deliver()
	}
	if p.cli.Stats().PingsSent == before {
		t.Fatal("setup: the client never probed")
	}
	dropOne := p.nToCli
	p.filterToCli = func(idx int, _ []byte) bool { return idx != dropOne }
	p.deliver()
	for step := 0; step < 250; step++ {
		p.clk.Advance(100 * time.Millisecond)
		_ = p.cli.Enqueue(bytes.Repeat([]byte{0x11}, pl))
		_ = p.gw.Enqueue(bytes.Repeat([]byte{0x22}, pl))
		p.run()
	}
	t.Logf("after phase 2: probes_lost=%d state=%s", p.cli.Stats().ProbesLost, p.cli.State())
	if p.cli.State() != StateEstablished {
		t.Fatalf("setup: client %s after phase 2", p.cli.State())
	}
	// Phase 3: return path silent, client keeps sending. Only the ordinary
	// ladder applies here (no unopenable arrivals), so the bound is its own:
	// MaxLostProbes x Probe.Max plus the first probe spacing.
	start := p.nToCli
	p.filterToCli = func(idx int, _ []byte) bool { return idx < start }
	silentAt := p.clk.Now()
	for step := 0; step < 1200; step++ {
		p.clk.Advance(100 * time.Millisecond)
		_ = p.cli.Enqueue(bytes.Repeat([]byte{0x33}, pl))
		p.run()
		if p.cli.State().Terminal() || p.cli.State() == StateClosing {
			break
		}
	}
	took := p.clk.Now().Sub(silentAt)
	t.Logf("dead path after an old lost probe: client %s (%v) after %v", p.cli.State(), p.cli.Err(), took)
	if !(p.cli.State().Terminal() || p.cli.State() == StateClosing) || !errors.Is(p.cli.Err(), ErrPeerUnreachable) {
		t.Fatalf("a stale lostSince blocked teardown: client %s after %v of silence", p.cli.State(), took)
	}
	if took > 100*time.Second {
		t.Fatalf("dead path took %v, want <= 100s (MaxLostProbes x Probe.Max plus one spacing)", took)
	}
}

// During a stall an ordinary probe deadline must not add a probe between two
// stall draws: the stall schedule is exclusive.
func TestAnOrdinaryProbeDeadlineCannotInterleaveWithTheStallSchedule(t *testing.T) {
	p := newPair(t, nil)
	p.establish()
	pl := p.gw.cfg.maxPayload() - frameHeaderSize
	start := p.nToCli
	const gap = 1100
	p.filterToCli = func(idx int, _ []byte) bool { return idx < start || idx >= start+gap }
	for i := 0; i < gap+200; i++ {
		if err := p.gw.Enqueue(bytes.Repeat([]byte{byte(i)}, pl)); err != nil {
			p.run()
			_ = p.gw.Enqueue(bytes.Repeat([]byte{byte(i)}, pl))
		}
	}
	p.run()
	// Walk forward until the first stall probe has been emitted.
	before := p.cli.Stats().PingsSent
	for step := 0; step < 40 && p.cli.Stats().PingsSent == before; step++ {
		p.clk.Advance(50 * time.Millisecond)
		_ = p.gw.Enqueue(bytes.Repeat([]byte{0x5a}, pl))
		p.run()
	}
	if p.cli.Stats().PingsSent == before {
		t.Fatal("setup: the stall never emitted a probe")
	}
	p.cli.mu.Lock()
	if !p.cli.receiveStalled(p.clk.Now()) {
		p.cli.mu.Unlock()
		t.Fatal("setup: the client is not in a receive stall")
	}
	stallAt := p.cli.nextStallProbe
	now := p.clk.Now()
	// Force an ordinary probe to fall due 100 ms from now, inside the draw.
	p.cli.probeAt = now.Add(100 * time.Millisecond)
	p.cli.probeEvery = 0
	p.cli.mu.Unlock()
	emitted := p.cli.Stats().PingsSent
	for p.clk.Now().Add(10 * time.Millisecond).Before(stallAt) {
		p.clk.Advance(10 * time.Millisecond)
		p.run()
		if got := p.cli.Stats().PingsSent; got != emitted {
			t.Fatalf("a probe was emitted at +%v, before the stall draw at +%v",
				p.clk.Now().Sub(now), stallAt.Sub(now))
		}
	}
}
