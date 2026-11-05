package gateway

// handshake_replay_observability_test.go
//
// Lane ds_replay: prove or disprove replay resistance of the Winn3 v3
// handshake by MEASURING what a replayed initiation actually does to a
// gateway, rather than trusting a test name.
//
// Threat model: an on-path observer records everything. The observer captures
// a genuine initiation (and its reply) in passive transit. They do NOT hold the
// admission key, the gateway static key, or the client's ephemeral private key;
// their one capability is to emit the captured bytes again, at a time and from
// a source address they choose. For each replay we measure the three
// observables the brief asks about:
//
//   - a RESPONSE  -> Result.Reply != nil (the only field that becomes bytes)
//   - a STATE change -> gateway Stats() counters
//   - a RESOURCE ALLOCATION -> Table().Sessions() grows
//
// Scenarios:
//
//	S1  same gateway, immediate replay, two source addresses.
//	S2  a restart of the SAME gateway (same static key, admission key and
//	    gateway id; replay cache wiped) inside the freshness window.
//	S3a a second gateway sharing admission key + gateway id but a DIFFERENT
//	    static key (the normal fleet case).
//	S3b a second gateway sharing admission key + static key but a DIFFERENT
//	    gateway id — the exact case the gatewayID-bound tag claims to stop.
//	S4  the original gateway, replay after the acceptance window has elapsed.
//	S5  positive control: a genuinely fresh initiation must still emit a byte
//	    (so S1–S4 cannot pass just because the harness is broken-silent).
//
// The three controls required by the house rules are present:
//   - GREEN:   S5 must observe a real handshake (harness not broken).
//   - NEUTRAL: S3a, S3b (cross-gateway) and S4 (expired) are rejection-only
//     paths that never touch the positive branch.
//   - POSITIVE: S2 is the scenario that must be SEEN and measured; it is the
//     one place a captured initiation can still get any response, and the test
//     asserts its exact magnitude so it cannot silently widen or narrow.

import (
	"path/filepath"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// acceptanceSpan reproduces the freshness window arithmetic that core uses
// (Freshness.resolve) so this file's S4 timing is on the same numbers the
// responder computes internally, not a private constant of this test.
func acceptanceSpan() time.Duration {
	window := core.DefaultBucketWindow
	skew := core.DefaultMaxSkew
	spread := int((skew + window - 1) / window)
	return time.Duration(2*spread+1) * window
}

// replaySummary is one measurement row: what a given replay produced.
type replaySummary struct {
	scenario       string
	replyBytes     int
	kind           Kind
	sessionsBefore int
	sessionsAfter  int
	handshakesDel  int
	unauthDel      int
}

func (s replaySummary) String() string {
	return s.scenario +
		": reply=" + itoa(s.replyBytes) + "B kind=" + s.kind.String() +
		" sessions+" + itoa(s.sessionsAfter-s.sessionsBefore) +
		" handshakes+" + itoa(s.handshakesDel) +
		" unauth+" + itoa(s.unauthDel)
}

// replayGateway is a second, independent gateway front door. The first harness
// gateway (h.gw) shares this clock, so a replay made at "now" on both is a
// replay made at the same instant of the freshness lifetime.
type replayGateway struct {
	cleanup func()
	tbl     *Table
	stats   func() GatewayStats
	handle  func([]byte, []byte, time.Time) Result
}

func newFleetGate(t *testing.T, h *realHarness, gwStatic *core.StaticKey, gatewayID []byte) *replayGateway {
	t.Helper()
	cfg := core.Config{
		Gateway: core.GatewayParams{
			AdmissionKeys: [][]byte{h.admission},
			GatewayID:     []byte(gatewayID),
			TagSize:       core.DefaultTagSize,
		},
		Now: h.clock,
	}
	resp, err := core.NewResponder(cfg, gwStatic, func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("second responder: %v", err)
	}
	g, err := New(silentCfg(), testGatewayPathMTU, resp, h.binder())
	if err != nil {
		t.Fatalf("second gateway: %v", err)
	}
	t.Cleanup(g.Table().Close)
	return &replayGateway{
		cleanup: func() { g.Table().Close() },
		tbl:     g.Table(),
		stats:   g.Stats,
		handle:  g.Handle,
	}
}

// TestHandshakeReplayObservability is the whole measurement: capture one
// genuine initiation, then replay it into each scenario above and total the
// three observables per scenario.
func TestHandshakeReplayObservability(t *testing.T) {
	h := newRealHarness(t, silentCfg())
	srcVictim := []byte("on-path-observer-recorded-client")
	srcAttacker := []byte("attacker-chosen-source")

	// Capture the initiation. This first delivery through the front door is
	// both the positive control (S5) and the source of the recorded bytes.
	init := h.initiation(t)

	before := h.gw.Table().Sessions()
	first := h.gw.Handle(init, srcVictim, h.clock())
	if first.Kind != KindHandshake || first.Reply == nil {
		t.Fatalf("S5/GREEN control: a fresh authenticated initiation must emit a byte, got %s (%d reply B)",
			first.Kind, lenOrNil(first))
	}
	if first.Entry == nil {
		t.Fatal("S5/GREEN control: a fresh handshake produced no table entry (harness broken)")
	}
	if got := h.gw.Table().Sessions(); got != before+1 {
		t.Fatalf("S5/GREEN control: session count went %d -> %d after a single fresh handshake",
			before, got)
	}
	recorded := append([]byte(nil), init...)

	var rows []replaySummary

	// S1: same gateway, exact replay, from both the recorded source and a
	// different source. The replay cache is keyed on the body, not the address,
	// so both must be silent and neither may move session state.
	{
		shs0, suna0 := h.gw.Stats().Handshakes, h.gw.Stats().Unauthenticated
		deliver := []struct {
			name string
			src  []byte
		}{
			{"S1 same-source replay", srcVictim},
			{"S1 other-source replay", srcAttacker},
			{"S1 other-source replay #2", srcAttacker},
			{"S1 other-source replay #3", srcAttacker},
		}
		for _, d := range deliver {
			res := h.gw.Handle(recorded, d.src, h.clock())
			mustBeSilent(t, res, d.name)
		}
		rows = append(rows, replaySummary{
			scenario: "S1 same-gateway" + " x4", replyBytes: 0, kind: KindDropped,
			sessionsBefore: before + 1, sessionsAfter: h.gw.Table().Sessions(),
			handshakesDel: int(h.gw.Stats().Handshakes - shs0),
			unauthDel:     int(h.gw.Stats().Unauthenticated - suna0),
		})
		if h.gw.Table().Sessions() != before+1 {
			t.Fatal("S1: a replayed initiation changed the session count")
		}
	}

	// S2: the SAME static key, admission key and gateway id, but a FRESH
	// responder whose replay cache is empty — i.e. the gateway process restarted
	// inside the freshness window that already accepted the original. The
	// replay cache is per-process and does not survive a restart, so a captured
	// initiation the pre-restart process stamped can be accepted by the
	// post-restart process. This is the only path, in a correct deployment, on
	// which a replay gets any answer at all, and it is bounded by the freshness
	// window. Measure its exact magnitude.
	{
		g2 := newFleetGate(t, h, h.gwStatic, h.gwCfg.Gateway.GatewayID)
		s0 := g2.tbl.Sessions()
		res := g2.handle(recorded, srcAttacker, h.clock())
		rows = append(rows, replaySummary{
			scenario: "S2 restarted-responder same static/id/key", replyBytes: lenOrNil(res),
			kind:           res.Kind,
			sessionsBefore: s0, sessionsAfter: g2.tbl.Sessions(),
			handshakesDel: int(g2.stats().Handshakes - 0),
			unauthDel:     int(g2.stats().Unauthenticated - 0),
		})
		if res.Kind != KindHandshake || res.Reply == nil {
			t.Fatalf("S2: expected a response+allocation from a restarted responder within the window, got %s (%d B)",
				res.Kind, lenOrNil(res))
		}
		if g2.tbl.Sessions() != s0+1 {
			t.Fatalf("S2: the replayed initiation allocated %d sessions, want 1", g2.tbl.Sessions()-s0)
		}
		if g2.stats().Handshakes != 1 {
			t.Fatalf("S2: Handshakes counter is %d after one replayed acceptance, want 1", g2.stats().Handshakes)
		}
		g2.cleanup()
	}

	// S3a: a second gateway sharing admission key and gateway id but with a
	// DIFFERENT static key (the normal case — each fleet gateway has its own
	// secret). The initiation is sealed to the first gateway's static key, so
	// the static-key DH in handshake.go cannot unwrap it: decryption fails
	// before any response is possible. This is an independent replay-binding
	// layer that does not depend on the cache at all.
	{
		other, err := core.GenerateStaticKey()
		if err != nil {
			t.Fatalf("other static key: %v", err)
		}
		g3 := newFleetGate(t, h, other, h.gwCfg.Gateway.GatewayID)
		s0 := g3.tbl.Sessions()
		res := g3.handle(recorded, srcAttacker, h.clock())
		mustBeSilent(t, res, "S3a cross-gateway with a different static key")
		rows = append(rows, replaySummary{
			scenario: "S3a fresh-responder different static", replyBytes: 0, kind: res.Kind,
			sessionsBefore: s0, sessionsAfter: g3.tbl.Sessions(),
			handshakesDel: int(g3.stats().Handshakes),
			unauthDel:     int(g3.stats().Unauthenticated),
		})
		if g3.tbl.Sessions() != s0 {
			t.Fatalf("S3a: a cross-gateway replay with a different static key allocated sessions")
		}
		g3.cleanup()
	}

	// S3b: a second gateway sharing the admission key AND the same static key
	// but with a DIFFERENT gateway id. The gatewayID is an authenticated input
	// to the admission tag, so the replayed tag must fail at admission and the
	// gateway must stay silent.
	{
		g4 := newFleetGate(t, h, h.gwStatic, []byte("winn3-gateway-other-id"))
		s0 := g4.tbl.Sessions()
		res := g4.handle(recorded, srcAttacker, h.clock())
		mustBeSilent(t, res, "S3b cross-gateway with a different gateway id")
		rows = append(rows, replaySummary{
			scenario: "S3b fresh-responder different id", replyBytes: 0, kind: res.Kind,
			sessionsBefore: s0, sessionsAfter: g4.tbl.Sessions(),
			handshakesDel: int(g4.stats().Handshakes),
			unauthDel:     int(g4.stats().Unauthenticated),
		})
		if g4.tbl.Sessions() != s0 {
			t.Fatalf("S3b: a cross-gateway replay with a different gateway id allocated sessions")
		}
		g4.cleanup()
	}

	// S4: the original gateway again, once the acceptance window has elapsed.
	// The time bucket is now outside the skew span, so the tag no longer
	// verifies and it must be silent — the exact boundary the replay cache and
	// the acceptance window are coupled to close.
	{
		h.setNow(fixedNow.Add(acceptanceSpan() + 2*time.Second))
		res := h.gw.Handle(recorded, srcAttacker, h.clock())
		mustBeSilent(t, res, "S4 replay after the acceptance window")
		rows = append(rows, replaySummary{
			scenario: "S4 same-gateway after-window", replyBytes: 0, kind: res.Kind,
			sessionsBefore: before + 1, sessionsAfter: h.gw.Table().Sessions(),
			handshakesDel: 0, unauthDel: int(h.gw.Stats().Unauthenticated),
		})
		if h.gw.Table().Sessions() != before+1 {
			t.Fatal("S4: a replayed initiation after its window changed the session count")
		}
	}

	// The whole measured table goes into the log so the report is reproducible
	// from the test run alone.
	for _, r := range rows {
		t.Logf("MEASURED %s", r.String())
	}
}

func lenOrNil(res Result) int {
	if res.Reply == nil {
		return 0
	}
	return len(res.Reply)
}

// newFleetGateJournaled is newFleetGate with core.Config.ReplayJournal set, so
// the responder's handshake replay window is seeded from, and appends to, the
// persisted journal. It models the production wiring cmd/winn3-gateway performs
// from WINN3_REPLAY_JOURNAL.
func newFleetGateJournaled(t *testing.T, h *realHarness, gwStatic *core.StaticKey, gatewayID []byte, journal string) *replayGateway {
	t.Helper()
	cfg := core.Config{
		Gateway: core.GatewayParams{
			AdmissionKeys: [][]byte{h.admission},
			GatewayID:     []byte(gatewayID),
			TagSize:       core.DefaultTagSize,
		},
		Now:           h.clock,
		ReplayJournal: journal,
	}
	resp, err := core.NewResponder(cfg, gwStatic, func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("journaled responder: %v", err)
	}
	g, err := New(silentCfg(), testGatewayPathMTU, resp, h.binder())
	if err != nil {
		t.Fatalf("journaled gateway: %v", err)
	}
	t.Cleanup(g.Table().Close)
	return &replayGateway{
		cleanup: func() { g.Table().Close() },
		tbl:     g.Table(),
		stats:   g.Stats,
		handle:  g.Handle,
	}
}

// TestHandshakeReplayJournalKeepsRestartedGatewaySilent is the S2 scenario of
// TestHandshakeReplayObservability re-run with the persisted replay journal
// (F-02) enabled: capture a genuine initiation, then restart the SAME gateway
// (same static key, admission key and gateway id) against the SAME journal
// inside the freshness window. Without the journal this is the one measured
// place a captured initiation earns a fresh response (the old S2 assertion);
// with it, the restarted process must keep refusing it — silence, no reply,
// no session, no handshake counted.
func TestHandshakeReplayJournalKeepsRestartedGatewaySilent(t *testing.T) {
	h := newRealHarness(t, silentCfg())
	journal := filepath.Join(t.TempDir(), "replay.journal")
	srcVictim := []byte("on-path-observer-recorded-client")
	srcAttacker := []byte("attacker-chosen-source")

	g1 := newFleetGateJournaled(t, h, h.gwStatic, h.gwCfg.Gateway.GatewayID, journal)
	init := h.initiation(t)

	// Capture: the genuine initiation is answered once and journaled.
	first := g1.handle(init, srcVictim, h.clock())
	if first.Kind != KindHandshake || first.Reply == nil {
		t.Fatalf("GREEN control: a fresh authenticated initiation must emit a byte, got %s (%d reply B)",
			first.Kind, lenOrNil(first))
	}

	// Restart: a brand-new responder/gateway on the same journal. The captured
	// initiation must now be silent — this is the property the restart used to
	// violate.
	g2 := newFleetGateJournaled(t, h, h.gwStatic, h.gwCfg.Gateway.GatewayID, journal)
	s0 := g2.tbl.Sessions()
	res := g2.handle(init, srcAttacker, h.clock())
	mustBeSilent(t, res, "S2-journal restarted-responder same static/id/key")
	if got := g2.tbl.Sessions(); got != s0 {
		t.Fatalf("S2-journal: the replayed initiation allocated %d sessions, want 0", got-s0)
	}
	if got := g2.stats().Handshakes; got != 0 {
		t.Fatalf("S2-journal: the replayed initiation completed %d handshakes, want 0", got)
	}

	// And a genuinely FRESH initiation still earns an answer, so the journal
	// silence above is not a broken-silent gateway.
	fresh := h.initiation(t)
	freshRes := g2.handle(fresh, srcVictim, h.clock())
	if freshRes.Kind != KindHandshake || freshRes.Reply == nil {
		t.Fatalf("a fresh initiation after the journaled restart was not answered: %s (%d reply B)",
			freshRes.Kind, lenOrNil(freshRes))
	}

	g1.cleanup()
	g2.cleanup()
}
