package main

// replay_journal_health_test.go
//
// F-02: the persisted handshake replay journal's health must be
// operator-visible from this binary. A sticky persistence failure blocks that
// initiation and every later new handshake, while established sessions keep
// carrying. serve() folds the check into its statusInterval ticker and emits
// exactly one machine-readable line per state change:
//
//	winn3-gateway: replay-journal status=<ok|admission-blocked|load-refused>
//
// The JSON status independently exposes ready=false and
// replay_journal_status=admission-blocked. A lab run with no journal
// configured emits no health line and reports disabled; production serve
// refuses WINN3_GATEWAY_REPLAY_JOURNAL=0 and any absent or unusable path
// before listen. A journal that cannot be loaded refuses startup with the
// load-refused token.

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// TestReplayJournalStatusLineIsEmittedOncePerStateChange pins the
// state-change tracker: the ok line once, the admission-blocked line once
// when the sticky error first appears, and silence in between -- one line per
// transition, never a line per tick.
func TestReplayJournalStatusLineIsEmittedOncePerStateChange(t *testing.T) {
	var l replayJournalLog

	if got := l.report(replayJournalStatusOK); got != "winn3-gateway: replay-journal status=ok" {
		t.Fatalf("first report of a healthy journal = %q, want the ok line", got)
	}
	if got := l.report(replayJournalStatusOK); got != "" {
		t.Fatalf("a second report of the unchanged ok state = %q, want no line (one per state change)", got)
	}

	if got := l.report(replayJournalStatusAdmissionBlocked); got != "winn3-gateway: replay-journal status=admission-blocked" {
		t.Fatalf("first report of a failed journal = %q, want the admission-blocked line", got)
	}
	if got := l.report(replayJournalStatusAdmissionBlocked); got != "" {
		t.Fatalf("a sticky failure must be reported exactly once: got %q, want no line", got)
	}
}

// TestReplayJournalHealthyGatewayReportsOK goes through the real production
// wiring -- buildSessionConfig reading WINN3_REPLAY_JOURNAL -- and requires
// that a clean journaled responder renders as the ok line through the same
// gate serve() consults and is ready to admit new handshakes.
func TestReplayJournalHealthyGatewayReportsOK(t *testing.T) {
	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(dir, "replay.journal")
	t.Setenv("WINN3_REPLAY_JOURNAL", journal)

	srv, _ := newTestServer(t, 8)
	if srv.sessionCfg.Core.ReplayJournal != journal {
		t.Fatalf("buildSessionConfig did not wire the journal: Core.ReplayJournal = %q, want %q",
			srv.sessionCfg.Core.ReplayJournal, journal)
	}
	if srv.sessionCfg.Responder == nil || srv.sessionCfg.Responder.ReplayJournalError() != nil {
		t.Fatalf("a clean journal must report no error, got %v", srv.sessionCfg.Responder.ReplayJournalError())
	}
	var l replayJournalLog
	if got := srv.journalHealthLine(&l); got != "winn3-gateway: replay-journal status=ok" {
		t.Fatalf("a healthy journaled gateway rendered as %q, want the ok line", got)
	}
	if got := srv.journalHealthLine(&l); got != "" {
		t.Fatalf("the ok state was reported twice (%q); one line per state change", got)
	}
	status := srv.status()
	if !status.Ready || status.ReplayJournalStatus != replayJournalStatusOK {
		t.Fatalf("healthy journal readiness = ready %v status %q, want true/%q",
			status.Ready, status.ReplayJournalStatus, replayJournalStatusOK)
	}
}

// TestReplayJournalHealthIsSilentWithoutAJournal pins explicit opt-out
// posture: a gateway whose config carries no journal path must never emit
// the line and must identify the journal as disabled in status.
func TestReplayJournalHealthIsSilentWithoutAJournal(t *testing.T) {
	srv, _ := newTestServer(t, 8)
	var l replayJournalLog
	if got := srv.journalHealthLine(&l); got != "" {
		t.Fatalf("a journal-free gateway emitted %q; nothing may be logged", got)
	}
	status := srv.status()
	if !status.Ready || status.ReplayJournalStatus != replayJournalStatusDisabled {
		t.Fatalf("journal-free readiness = ready %v status %q, want true/%q",
			status.Ready, status.ReplayJournalStatus, replayJournalStatusDisabled)
	}
}

// TestReplayJournalFailureBlocksReadinessAndNewHandshakesButKeepsSessions
// drives the production UDP gateway and a real client loop. A pre-existing
// pending sidecar makes the next durable append fail without modifying core
// internals. The new handshake must receive no wire response, status must
// become unready, and the session established before the fault must still
// carry a reflected packet.
func TestReplayJournalFailureBlocksReadinessAndNewHandshakesButKeepsSessions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(dir, "replay.journal")
	t.Setenv("WINN3_REPLAY_JOURNAL", journal)

	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	sessionCfg, err := buildSessionConfig(serveOptions{
		staticPath: filepath.Join(dir, "static.key"),
		admission:  filepath.Join(dir, "admission.key"),
		gatewayID:  testGatewayID,
	})
	if err != nil {
		t.Fatal(err)
	}
	assign, err := parseAssignment(testGatewayInner, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	defer conn.Close()

	srv := &server{
		conn:        conn,
		sizing:      sizing,
		sessionCfg:  sessionCfg,
		assign:      assign,
		maxSessions: 8,
		peers:       make(map[netip.AddrPort]*peerSession),
	}
	readDone := make(chan error, 1)
	go func() { readDone <- srv.readLoop(ctx) }()
	defer func() {
		_ = conn.SetReadDeadline(time.Now())
		<-readDone
		srv.closeAll()
	}()

	gwAddr := conn.LocalAddr().(*net.UDPAddr)
	cli := startTestClient(t, ctx, testClientOpts{
		dir:           dir,
		gwAddr:        gwAddr,
		gatewayPublic: readTestKey(t, filepath.Join(dir, "static.pub")),
		admission:     readTestSecret(t, filepath.Join(dir, "admission.key")),
		sizing:        sizing,
		inner:         testClientInner,
	})
	waitFor(t, 40*time.Second, "the established client gate to carry", func() bool {
		return cli.loop.Tunnel().Gate().State() == tun.StateCarrying
	})

	before := srv.status()
	if !before.Ready || before.ReplayJournalStatus != replayJournalStatusOK {
		t.Fatalf("pre-fault readiness = ready %v status %q, want true/%q",
			before.Ready, before.ReplayJournalStatus, replayJournalStatusOK)
	}

	pending, err := os.OpenFile(journal+".pending", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatalf("installing the append-failure control: %v", err)
	}
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}

	blocked := capturedInitiation(t, dir, sessionCfg)
	newPeer, err := net.DialUDP("udp4", nil, gwAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer newPeer.Close()
	if _, err := newPeer.Write(blocked); err != nil {
		t.Fatal(err)
	}
	if got := readDatagramOrTimeout(t, newPeer, 2*time.Second); got != nil {
		t.Fatalf("journal-blocked initiation received %d response bytes; refusal must be wire-silent", len(got))
	}

	waitFor(t, 10*time.Second, "the sticky replay-journal error", func() bool {
		return srv.sessionCfg.Responder.ReplayJournalError() != nil
	})
	after := srv.status()
	if after.Ready || after.ReplayJournalStatus != replayJournalStatusAdmissionBlocked {
		t.Fatalf("post-fault readiness = ready %v status %q, want false/%q",
			after.Ready, after.ReplayJournalStatus, replayJournalStatusAdmissionBlocked)
	}
	encoded, err := json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"ready":false`)) ||
		!bytes.Contains(encoded, []byte(`"replay_journal_status":"admission-blocked"`)) {
		t.Fatalf("post-fault operator JSON does not expose fail-closed readiness: %s", encoded)
	}

	laterPeer, err := net.DialUDP("udp4", nil, gwAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer laterPeer.Close()
	if _, err := laterPeer.Write(capturedInitiation(t, dir, sessionCfg)); err != nil {
		t.Fatal(err)
	}
	if got := readDatagramOrTimeout(t, laterPeer, 2*time.Second); got != nil {
		t.Fatalf("initiation after sticky journal failure received %d response bytes; refusal must stay wire-silent", len(got))
	}

	var logState replayJournalLog
	if got := srv.journalHealthLine(&logState); got != "winn3-gateway: replay-journal status=admission-blocked" {
		t.Fatalf("post-fault health line = %q, want admission-blocked", got)
	}

	payload := []byte("established session survives replay-journal failure")
	cli.dev.offer(t, testIPv4(t, testClientInner, testGatewayInner, payload))
	reply := cli.dev.take(t, 10*time.Second)
	if !bytes.Equal(reply[20:], payload) {
		t.Fatalf("established-session payload after journal failure = %q, want %q", reply[20:], payload)
	}
}

// TestReplayJournalTornFileRefusesStartupWithLoadRefused pins the
// fail-closed load: a journal that is not a whole number of records must
// refuse the startup, naming the journal, so a torn journal can never
// silently weaken the replay window.
func TestReplayJournalTornFileRefusesStartupWithLoadRefused(t *testing.T) {
	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(dir, "replay.journal")
	if err := os.WriteFile(journal, []byte{0x01, 0x02, 0x03}, 0o640); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WINN3_REPLAY_JOURNAL", journal)

	_, err := buildSessionConfig(serveOptions{
		staticPath: filepath.Join(dir, "static.key"),
		admission:  filepath.Join(dir, "admission.key"),
		gatewayID:  testGatewayID,
	})
	if err == nil {
		t.Fatal("a torn journal was accepted; the load must refuse (fail-closed)")
	}
	if !strings.Contains(err.Error(), "replay journal") {
		t.Fatalf("the refusal does not name the journal, so an operator cannot tell what to fix: %v", err)
	}
}
