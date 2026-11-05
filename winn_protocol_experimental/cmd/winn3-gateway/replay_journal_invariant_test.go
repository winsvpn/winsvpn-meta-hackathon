package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

func writeEmptyReplayJournal(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "replay.journal")
	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRequireReplayJournalEnvRefusesExplicitDisable(t *testing.T) {
	t.Setenv("WINN3_GATEWAY_REPLAY_JOURNAL", "0")
	t.Setenv("WINN3_REPLAY_JOURNAL", writeEmptyReplayJournal(t, t.TempDir()))
	err := requireReplayJournalEnv()
	if err == nil || err.Error() != replayJournalDisableRefused {
		t.Fatalf("explicit disable error = %v, want %q", err, replayJournalDisableRefused)
	}
}

func TestRequireReplayJournalEnvRefusesMissingPath(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "replay.journal")
	t.Setenv("WINN3_REPLAY_JOURNAL", missing)
	err := requireReplayJournalEnv()
	if err == nil || !strings.Contains(err.Error(), replayJournalPathRequired) {
		t.Fatalf("missing path error = %v, want it to name %q", err, replayJournalPathRequired)
	}
	if _, statErr := os.Lstat(missing); !os.IsNotExist(statErr) {
		t.Fatalf("a missing journal was created (%v); that empty file is the restart replay bypass", statErr)
	}
}

func TestRequireReplayJournalEnvRefusesUnwritableJournal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file modes")
	}
	path := writeEmptyReplayJournal(t, t.TempDir())
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WINN3_REPLAY_JOURNAL", path)
	err := requireReplayJournalEnv()
	if err == nil || !strings.Contains(err.Error(), "not writable") {
		t.Fatalf("unwritable journal error = %v, want a not-writable refusal", err)
	}
}

func TestRequireReplayJournalEnvRefusesSymlinkJournal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix symlinks")
	}
	dir := t.TempDir()
	real := writeEmptyReplayJournal(t, dir)
	link := filepath.Join(dir, "replay.link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WINN3_REPLAY_JOURNAL", link)
	err := requireReplayJournalEnv()
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink journal error = %v, want a symbolic-link refusal", err)
	}
}

func TestRequireReplayJournalEnvRefusesUnsetProductionServe(t *testing.T) {
	t.Setenv("WINN3_GATEWAY_REPLAY_JOURNAL", "")
	t.Setenv("WINN3_REPLAY_JOURNAL", "")
	err := requireReplayJournalEnv()
	if err == nil || !strings.Contains(err.Error(), replayJournalPathRequired) {
		t.Fatalf("unset production replay journal must fail closed, got %v", err)
	}
}

func TestRunServeRefusesExplicitDisableBeforeListen(t *testing.T) {
	opts := operatorValueOptions(t)
	t.Setenv("WINN3_GATEWAY_REPLAY_JOURNAL", "0")
	err := runServe(opts, new(bytes.Buffer))
	if err == nil || !strings.Contains(err.Error(), replayJournalDisableRefused) {
		t.Fatalf("runServe explicit disable = %v, want %q", err, replayJournalDisableRefused)
	}
}

func TestRunServeRefusesMissingJournalBeforeCreatingIt(t *testing.T) {
	opts := operatorValueOptions(t)
	missing := filepath.Join(t.TempDir(), "replay.journal")
	t.Setenv("WINN3_REPLAY_JOURNAL", missing)
	err := runServe(opts, new(bytes.Buffer))
	if err == nil || !strings.Contains(err.Error(), replayJournalPathRequired) {
		t.Fatalf("runServe missing journal = %v, want it to name %q", err, replayJournalPathRequired)
	}
	if _, statErr := os.Lstat(missing); !os.IsNotExist(statErr) {
		t.Fatalf("runServe created %s (%v); a missing path must fail before Open can wipe the replay window", missing, statErr)
	}
}

func TestExplicitDisableRefusesNewHandshakesBeforeReady(t *testing.T) {
	t.Setenv("WINN3_GATEWAY_REPLAY_JOURNAL", "0")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srv, gwAddr := newTestServer(t, 8)
	ready, status := srv.replayJournalReadiness()
	if ready || status != replayJournalStatusLoadRefused {
		t.Fatalf("explicit disable readiness = ready %v status %q, want false/%q",
			ready, status, replayJournalStatusLoadRefused)
	}
	if srv.admitsNewHandshakes() {
		t.Fatal("explicit disable still admits new handshakes")
	}

	readDone := make(chan error, 1)
	go func() { readDone <- srv.readLoop(ctx) }()
	defer func() {
		_ = srv.conn.SetReadDeadline(time.Now())
		<-readDone
		srv.closeAll()
	}()

	peer, err := net.DialUDP("udp4", nil, gwAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if _, err := peer.Write(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	if got := readDatagramOrTimeout(t, peer, 2*time.Second); got != nil {
		t.Fatalf("explicit-disable initiation received %d response bytes; refusal must be wire-silent", len(got))
	}
}

func TestReplayJournalPathReplacementRefusesNewHandshakesAndKeepsSessions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix pathname identity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	journal := writeEmptyReplayJournal(t, dir)
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
		t.Fatalf("pre-replacement readiness = ready %v status %q, want true/%q",
			before.Ready, before.ReplayJournalStatus, replayJournalStatusOK)
	}
	if err := sessionCfg.Responder.ReplayJournalError(); err != nil {
		t.Fatalf("pre-replacement replay journal error = %v, want nil", err)
	}

	moved := journal + ".moved"
	if err := os.Rename(journal, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, journal); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 10*time.Second, "pathname replacement to block admission", func() bool {
		ready, status := srv.replayJournalReadiness()
		return !ready && status == replayJournalStatusAdmissionBlocked
	})
	after := srv.status()
	if after.Ready || after.ReplayJournalStatus != replayJournalStatusAdmissionBlocked {
		t.Fatalf("post-replacement readiness = ready %v status %q, want false/%q",
			after.Ready, after.ReplayJournalStatus, replayJournalStatusAdmissionBlocked)
	}
	encoded, err := json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"ready":false`)) ||
		!bytes.Contains(encoded, []byte(`"replay_journal_status":"admission-blocked"`)) {
		t.Fatalf("post-replacement operator JSON does not expose fail-closed readiness: %s", encoded)
	}

	newPeer, err := net.DialUDP("udp4", nil, gwAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer newPeer.Close()
	if _, err := newPeer.Write(capturedInitiation(t, dir, sessionCfg)); err != nil {
		t.Fatal(err)
	}
	if got := readDatagramOrTimeout(t, newPeer, 2*time.Second); got != nil {
		t.Fatalf("pathname-replaced initiation received %d response bytes; refusal must be wire-silent", len(got))
	}

	// The established-peer reinitiation seam remains blocked by the writer's
	// sticky descriptor check while the established session keeps carrying.
	// Because readiness found the replacement before this initiation, no
	// pending append record should be created.
	if err := cli.car.Send(ctx, capturedInitiation(t, dir, sessionCfg)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "known-peer reinitiation to reach durable replay append", func() bool {
		return sessionCfg.Responder.ReplayJournalError() != nil
	})
	journalErr := sessionCfg.Responder.ReplayJournalError()
	if journalErr == nil || !strings.Contains(journalErr.Error(), "replay journal") {
		t.Fatalf("known-peer replay journal error = %v, want pathname refusal", journalErr)
	}
	if _, err := os.Lstat(journal + ".pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pre-admission pathname refusal created a pending record: %v", err)
	}
	if err := cli.car.Send(ctx, capturedInitiation(t, dir, sessionCfg)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if got := sessionCfg.Responder.ReplayJournalError(); got == nil || got.Error() != journalErr.Error() {
		t.Fatalf("sticky replay journal error changed from %v to %v", journalErr, got)
	}
	if got := srv.status(); got.Sessions != 1 {
		t.Fatalf("known-peer reinitiation after pathname replacement changed sessions to %d, want 1", got.Sessions)
	}

	payload := []byte("established session survives journal pathname replacement")
	cli.dev.offer(t, testIPv4(t, testClientInner, testGatewayInner, payload))
	reply := cli.dev.take(t, 10*time.Second)
	if !bytes.Equal(reply[20:], payload) {
		t.Fatalf("established-session payload after pathname replacement = %q, want %q", reply[20:], payload)
	}
}

func TestDatagramAdmissionDoesNotInspectJournalPath(t *testing.T) {
	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	journal := writeEmptyReplayJournal(t, dir)
	t.Setenv("WINN3_REPLAY_JOURNAL", journal)
	cfg, err := buildSessionConfig(serveOptions{
		staticPath: filepath.Join(dir, "static.key"),
		admission:  filepath.Join(dir, "admission.key"),
		gatewayID:  testGatewayID,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := &server{sessionCfg: cfg}
	if err := os.Remove(journal); err != nil {
		t.Fatal(err)
	}
	if !srv.admitsNewHandshakes() {
		t.Fatal("in-memory packet gate inspected the removed journal pathname")
	}
	ready, status := srv.replayJournalReadiness()
	if ready || status != replayJournalStatusAdmissionBlocked {
		t.Fatalf("periodic readiness after removal = %v/%q, want false/%q",
			ready, status, replayJournalStatusAdmissionBlocked)
	}
	if srv.admitsNewHandshakes() {
		t.Fatal("periodic pathname monitor did not publish an in-memory admission block")
	}
}

func TestReplayJournalRestartStillRefusesTheCapturedInitiation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	journal := writeEmptyReplayJournal(t, dir)
	t.Setenv("WINN3_REPLAY_JOURNAL", journal)

	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	opts := serveOptions{
		staticPath: filepath.Join(dir, "static.key"),
		admission:  filepath.Join(dir, "admission.key"),
		gatewayID:  testGatewayID,
	}
	sessionCfg, err := buildSessionConfig(opts)
	if err != nil {
		t.Fatal(err)
	}
	assign, err := parseAssignment(testGatewayInner, "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	start := func(t *testing.T) (*server, *net.UDPAddr, context.CancelFunc, <-chan error) {
		t.Helper()
		cfg, err := buildSessionConfig(opts)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Skipf("cannot open a loopback datagram socket: %v", err)
		}
		srv := &server{
			conn:        conn,
			sizing:      sizing,
			sessionCfg:  cfg,
			assign:      assign,
			maxSessions: 8,
			peers:       make(map[netip.AddrPort]*peerSession),
		}
		ready, status := srv.replayJournalReadiness()
		if !ready || status != replayJournalStatusOK {
			t.Fatalf("restarted gateway readiness = ready %v status %q, want true/%q",
				ready, status, replayJournalStatusOK)
		}
		loopCtx, stop := context.WithCancel(ctx)
		readDone := make(chan error, 1)
		go func() { readDone <- srv.readLoop(loopCtx) }()
		return srv, conn.LocalAddr().(*net.UDPAddr), func() {
			stop()
			_ = conn.SetReadDeadline(time.Now())
			<-readDone
			srv.closeAll()
			_ = conn.Close()
		}, readDone
	}

	srv1, gwAddr, stop1, _ := start(t)
	initMsg := capturedInitiation(t, dir, sessionCfg)
	peer, err := net.DialUDP("udp4", nil, gwAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write(initMsg); err != nil {
		t.Fatal(err)
	}
	reply := readDatagram(t, peer, 10*time.Second)
	if len(reply) == 0 {
		t.Fatal("first-life initiation produced no reply; the harness never reached the handshake")
	}
	_ = peer.Close()
	stop1()
	_ = srv1

	srv2, gwAddr2, stop2, _ := start(t)
	defer stop2()
	replayPeer, err := net.DialUDP("udp4", nil, gwAddr2)
	if err != nil {
		t.Fatal(err)
	}
	defer replayPeer.Close()
	if _, err := replayPeer.Write(initMsg); err != nil {
		t.Fatal(err)
	}
	if got := readDatagramOrTimeout(t, replayPeer, 2*time.Second); got != nil {
		t.Fatalf("restart replay received %d response bytes; the journal must keep the capture refused", len(got))
	}
	if srv2.admitsNewHandshakes() == false {
		t.Fatal("a healthy restarted journal must still admit a distinct new handshake")
	}
}

func TestInspectLiveReplayJournalDetectsPathnameReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix pathname identity")
	}
	dir := t.TempDir()
	path := writeEmptyReplayJournal(t, dir)
	srv := &server{}
	if err := srv.verifyLiveReplayJournal(path); err != nil {
		t.Fatal(err)
	}
	moved := path + ".moved"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := srv.verifyLiveReplayJournal(path); err == nil {
		t.Fatal("pathname replacement was accepted; readiness must bind the live file identity")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(moved, path); err != nil {
		t.Fatal(err)
	}
	if err := srv.verifyLiveReplayJournal(path); err == nil {
		t.Fatal("identity failure was not sticky after the original path was restored")
	}
}

type generationReplayJournalMonitor struct {
	boundGeneration uint64
	pathGeneration  uint64
	broken          error
}

func (m *generationReplayJournalMonitor) ReplayJournalError() error { return m.broken }

func (m *generationReplayJournalMonitor) VerifyReplayJournalPath() error {
	if m.broken != nil {
		return m.broken
	}
	if m.pathGeneration != m.boundGeneration {
		m.broken = errors.New("unexpected replay-journal generation")
		return m.broken
	}
	return nil
}

func (m *generationReplayJournalMonitor) legitimateRewrite() {
	m.pathGeneration++
	m.boundGeneration = m.pathGeneration
}

func (m *generationReplayJournalMonitor) hostileReplacement() {
	m.pathGeneration++
}

func TestGatewayMonitorAcceptsWriterRebindButRejectsUncoordinatedReplacement(t *testing.T) {
	path := writeEmptyReplayJournal(t, t.TempDir())
	monitor := &generationReplayJournalMonitor{boundGeneration: 1, pathGeneration: 1}
	srv := &server{journalMonitor: monitor}
	srv.sessionCfg.Core.ReplayJournal = path

	if ready, status := srv.replayJournalReadiness(); !ready || status != replayJournalStatusOK {
		t.Fatalf("initial monitor readiness = %v/%q, want true/%q", ready, status, replayJournalStatusOK)
	}
	if !srv.admitsNewHandshakes() {
		t.Fatal("initial healthy monitor blocked admission")
	}

	monitor.legitimateRewrite()
	if ready, status := srv.replayJournalReadiness(); !ready || status != replayJournalStatusOK {
		t.Fatalf("writer-coordinated compaction readiness = %v/%q, want true/%q", ready, status, replayJournalStatusOK)
	}
	if srv.journalIdentBroken.Load() {
		t.Fatal("writer-coordinated compaction set the sticky gateway identity failure")
	}

	monitor.hostileReplacement()
	if ready, status := srv.replayJournalReadiness(); ready || status != replayJournalStatusAdmissionBlocked {
		t.Fatalf("hostile replacement readiness = %v/%q, want false/%q", ready, status, replayJournalStatusAdmissionBlocked)
	}
	if !srv.journalIdentBroken.Load() {
		t.Fatal("hostile replacement did not set the sticky gateway identity failure")
	}
	monitor.boundGeneration = monitor.pathGeneration
	monitor.broken = nil
	if ready, _ := srv.replayJournalReadiness(); ready {
		t.Fatal("gateway identity failure recovered after the path was restored")
	}
	if srv.admitsNewHandshakes() {
		t.Fatal("gateway admitted a new handshake after sticky hostile replacement")
	}
}
