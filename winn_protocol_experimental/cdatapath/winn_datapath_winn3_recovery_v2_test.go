//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
)

// Round A2 v2 on the C ABI: one coherent snapshot for every recovery decision
// and for status, and fail-fast for a tunnel that never establishes.

// manualRecoveringTunnel assembles a tunnel with no supervisor behind it and
// leaves it exactly where a supervisor would between rounds: round one ran
// (so its counters are not zero), ended, and was retired; round two is built
// and not yet published. The test publishes round two itself, through
// winn3TestHookAfterSnapshot, at the moment a torn read would be exposed.
func manualRecoveringTunnel(t *testing.T) (*winn3Tunnel, *winn3Round, *winn3Round) {
	t.Helper()
	silent, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no loopback socket: %v", err)
	}
	doc := baseConfig(t)
	doc["gateway_endpoint"] = silent.LocalAddr().String()
	cfg, err := decodeWinn3Config(encode(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	classes, err := carrierClasses(cfg.CarrierClasses)
	if err != nil {
		t.Fatal(err)
	}
	sizing, err := driver.NewSizing(cfg.PathMTU, classes...)
	if err != nil {
		t.Fatal(err)
	}
	assign, err := assignment(cfg)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := gatewayEndpoint(cfg.GatewayEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	tunnel := &winn3Tunnel{
		cancel: cancel,
		next:   make(chan struct{}),
		done:   make(chan struct{}),
		socket: conn,
	}
	r1, err := buildWinn3Round(ctx, tunnel, cfg, conn, remote, sizing, cfg.PathMTU, assign)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := buildWinn3Round(ctx, tunnel, cfg, conn, remote, sizing, cfg.PathMTU, assign)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		winn3TestHookAfterSnapshot = nil
		cancel()
		_ = r2.Close()
		_ = conn.Close()
		_ = silent.Close()
	})

	runCtx, stop := context.WithCancel(ctx)
	ran := make(chan error, 1)
	go func() { ran <- r1.Run(runCtx) }()
	deadline := time.Now().Add(10 * time.Second)
	for r1.loop.Stats().MessagesSent == 0 {
		if time.Now().After(deadline) {
			t.Fatal("round one sent nothing")
		}
		time.Sleep(5 * time.Millisecond)
	}
	stop()
	<-ran
	_ = r1.Close()
	if !tunnel.recovering.Load() || !r1.dev.isClosed() {
		t.Fatal("round one is not retired into recovery")
	}
	return tunnel, r1, r2
}

// publishAt makes the snapshot hook publish r2 the first time it runs, which
// is after a decision snapshot has been taken and before it is used.
func publishAt(tunnel *winn3Tunnel, r2 *winn3Round) *sync.Once {
	once := new(sync.Once)
	winn3TestHookAfterSnapshot = func() {
		once.Do(func() { tunnel.publish(r2) })
	}
	return once
}

// TestARetiredDeviceWriteIsAbsorbedAcrossAPublish: a host write that met round
// one's closed device is absorbed even though round two is published in the
// middle of the decision.
func TestARetiredDeviceWriteIsAbsorbedAcrossAPublish(t *testing.T) {
	tunnel, _, r2 := manualRecoveringTunnel(t)
	publishAt(tunnel, r2)
	packet := recoveryPacket("10.13.0.2", "10.13.0.1", "across a publish")
	if n := tunnel.writeInbound(packet); int(n) != len(packet) {
		t.Fatalf("a host write during recovery returned %d, want it absorbed (%d)", n, len(packet))
	}
	if tunnel.rounds.Load() != 2 {
		t.Fatal("the hook did not publish round two; the race was not forced")
	}
	if _, dev, _ := tunnel.round(); dev != r2.dev {
		t.Fatal("round two is not current after the forced publish")
	}
}

// TestARetiredDeviceReadMovesToTheSuccessorAcrossAPublish: the same boundary
// on a host read. It must wait on round two inside its timeout, not report the
// tunnel closed.
func TestARetiredDeviceReadMovesToTheSuccessorAcrossAPublish(t *testing.T) {
	tunnel, _, r2 := manualRecoveringTunnel(t)
	publishAt(tunnel, r2)
	buf := make([]byte, 2048)
	if _, err := tunnel.take(buf, 200); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a host read across the publish returned %v, want a timeout on round two", err)
	}
	if tunnel.rounds.Load() != 2 {
		t.Fatal("the hook did not publish round two; the race was not forced")
	}
}

// TestStatusNeverPublishesARetiredRoundAsCurrent: status taken while round one
// is retired, with round two published between the snapshot and its use, must
// not report round one's counters as the live round's.
func TestStatusNeverPublishesARetiredRoundAsCurrent(t *testing.T) {
	tunnel, r1, r2 := manualRecoveringTunnel(t)
	sent := r1.loop.Stats().MessagesSent
	publishAt(tunnel, r2)
	var st map[string]any
	if err := json.Unmarshal([]byte(tunnel.statusJSON()), &st); err != nil {
		t.Fatal(err)
	}
	if tunnel.rounds.Load() != 2 {
		t.Fatal("the hook did not publish round two; the race was not forced")
	}
	if st["winn3_messages_sent"] != float64(0) || st["winn3_may_carry"] != false {
		t.Fatalf("status exposed round one (messages_sent=%d) as current: %v", sent, st)
	}
	if st["winn3_lifecycle"] != driver.LifecycleRecovering {
		t.Fatalf("lifecycle is %v, want %q", st["winn3_lifecycle"], driver.LifecycleRecovering)
	}
	// And after the publish, round two is current but has proven nothing: the
	// tunnel is still recovering.
	if err := json.Unmarshal([]byte(tunnel.statusJSON()), &st); err != nil {
		t.Fatal(err)
	}
	if st["winn3_lifecycle"] != driver.LifecycleRecovering || st["winn3_rx_packets"] != float64(0) {
		t.Fatalf("an unproven successor published %v", st)
	}
}

// TestAnAppleTunnelThatNeverEstablishesIsBlockedAfterOneRound: fail-fast on the
// C ABI. One unanswered round, then a persistent blocked status with its cause
// and winn3_runtime_completed, with no packet submitted by the host.
func TestAnAppleTunnelThatNeverEstablishesIsBlockedAfterOneRound(t *testing.T) {
	winn3TestSessionTweak = func(c *session.Config) {
		c.Retry = session.Retry{Base: 50 * time.Millisecond, Cap: 100 * time.Millisecond, Attempts: 2}
	}
	defer func() { winn3TestSessionTweak = nil }()
	silent, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no loopback socket: %v", err)
	}
	defer silent.Close()
	local, err := net.DialUDP("udp4", nil, silent.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	file, err := local.File()
	if err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	_ = local.Close()

	doc := baseConfig(t)
	doc["gateway_endpoint"] = silent.LocalAddr().String()
	tunnel, err := openWinn3(encode(t, doc), fd)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer tunnel.close()
	var st map[string]any
	if err := json.Unmarshal([]byte(tunnel.statusJSON()), &st); err != nil {
		t.Fatal(err)
	}
	if st["winn3_lifecycle"] != driver.LifecycleConnecting {
		t.Fatalf("a fresh tunnel is %v, want connecting", st["winn3_lifecycle"])
	}
	select {
	case <-tunnel.done:
	case <-time.After(15 * time.Second):
		t.Fatalf("the supervisor was still running after %d rounds", tunnel.rounds.Load())
	}
	if n := tunnel.rounds.Load(); n != 1 {
		t.Fatalf("%d rounds for a tunnel that never established, want 1", n)
	}
	for range 2 {
		if err := json.Unmarshal([]byte(tunnel.statusJSON()), &st); err != nil {
			t.Fatal(err)
		}
		if st["winn3_lifecycle"] != driver.LifecycleBlocked ||
			st["winn3_lifecycle_cause"] != driver.LifecycleCauseNeverEstablished ||
			st["winn3_runtime_completed"] != true ||
			!strings.HasPrefix(st["carrier_error"].(string), driver.ErrReconnectNeverEstablished.Error()) {
			t.Fatalf("status after a never-established round: %v", st)
		}
	}
	if n := tunnel.socketCloses.Load(); n != 1 {
		t.Fatalf("socket closed %d times when the supervisor ended, want once", n)
	}
}
