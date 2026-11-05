package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// syncBuffer is an io.Writer the test can read while winn3Serve writes to it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) lastStatus(t *testing.T) winn3Status {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var last winn3Status
	sc := bufio.NewScanner(bytes.NewReader(s.b.Bytes()))
	for sc.Scan() {
		var st winn3Status
		if err := json.Unmarshal(sc.Bytes(), &st); err != nil {
			t.Fatalf("status line is not JSON: %v", err)
		}
		last = st
	}
	return last
}

// TestAHostStopTellsTheGateway is the SIGTERM path of the desktop engine.
//
// runWinn3 hands winn3Serve a context that SIGTERM cancels. Before this fix
// that context was Run's own, so a stop returned with the session still
// ESTABLISHED and nothing on the wire: the gateway kept the session, its
// -max-sessions slot and its probes toward the dead port until its liveness
// ladder gave up (L22b: 7 to 74 s of datagrams after each SIGTERM). A host stop
// must now reach the gateway as an ordinary CLOSE, well inside that ladder,
// and winn3Serve must still end the way a host has always seen it end.
func TestAHostStopTellsTheGateway(t *testing.T) {
	dir := t.TempDir()
	gatewayStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	clientStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	admission := bytes.Repeat([]byte{0x3c}, 32)
	write := func(name string, content []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	clientKeyPath := write("client.key", clientStatic.Bytes())
	gatewayKeyPath := write("gateway.key", gatewayStatic.Bytes())
	gatewayPubPath := write("gateway.pub", gatewayStatic.Public())
	admissionPath := write("admission.key", admission)

	sizing, err := driver.NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP, carrier.ClassTCP)
	if err != nil {
		t.Fatal(err)
	}
	clientHost, clientDevice := seamPair(t, sizing.InnerMTU)
	gatewayHost, gatewayDevice := seamPair(t, sizing.InnerMTU)
	_ = clientHost
	_ = gatewayHost
	clientProfile := profileFor(t, dir, "client.json", map[string]any{
		"role": clientRole, "static_path": clientKeyPath, "gateway_static_path": gatewayPubPath,
		"admission_path": admissionPath, "host_port": clientHost.port,
	})
	gatewayProfile := profileFor(t, dir, "gateway.json", map[string]any{
		"role": gatewayRole, "static_path": gatewayKeyPath, "admission_path": admissionPath,
		"host_port": gatewayHost.port,
	})
	clientSession, _, err := winn3BuildSession(clientProfile)
	if err != nil {
		t.Fatal(err)
	}
	gatewaySession, _, err := winn3BuildSession(gatewayProfile)
	if err != nil {
		t.Fatal(err)
	}
	toGateway, toClient, err := carrier.NewPipePair(carrier.PipeConfig{
		Class: carrier.ClassUDP, MaxMessageSize: sizing.MessageSize, PathMTU: sizing.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	routerAddr := mustAddr(t, "10.64.0.1")
	clientLoop, err := driver.NewClient(driver.Config{
		Session: clientSession, Sizing: sizing, Carrier: toGateway,
		Tun: &tun.Config{
			Assign: tun.Assignment{V4: mustAddr(t, "10.64.0.2"), RouterV4: routerAddr},
			Device: clientDevice, Clock: driver.SessionClock{Clock: driver.SystemClock{}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	gatewayLoop, err := driver.NewGateway(driver.Config{
		Session: gatewaySession, Sizing: sizing, Carrier: toClient,
		Tun: &tun.Config{
			Assign: tun.Assignment{V4: mustAddr(t, "10.64.0.3"), RouterV4: routerAddr},
			Device: gatewayDevice, Clock: driver.SessionClock{Clock: driver.SystemClock{}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	gwCtx, gwCancel := context.WithCancel(context.Background())
	defer gwCancel()
	go func() { _ = gatewayLoop.Run(gwCtx) }()

	hostCtx, hostStop := context.WithCancel(context.Background())
	defer hostStop()
	out := &syncBuffer{}
	served := make(chan error, 1)
	go func() { served <- winn3Serve(hostCtx, clientLoop, sizing, "", out) }()

	waitUntil(t, 15*time.Second, "the client's gate to open", func() bool {
		return clientLoop.Tunnel().Gate().State() == tun.StateCarrying
	})
	if gatewayLoop.Session().State() != session.StateEstablished {
		t.Fatalf("fixture: gateway is %s", gatewayLoop.Session().State())
	}

	stopped := time.Now()
	hostStop()
	waitUntil(t, 5*time.Second, "the gateway to hear the client's CLOSE", func() bool {
		return gatewayLoop.Session().PeerCloseReason() == session.CloseNormal
	})
	if took := time.Since(stopped); took > 3*time.Second {
		t.Fatalf("the gateway heard the CLOSE %s after the host stop", took)
	}

	var serveErr error
	select {
	case serveErr = <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("winn3Serve did not return after a host stop")
	}
	if !errors.Is(serveErr, context.Canceled) {
		t.Fatalf("winn3Serve returned %v after a host stop, want context.Canceled as before", serveErr)
	}
	final := out.lastStatus(t)
	if final.Event != "stopped" || final.PromotionReady || final.Refusal != context.Canceled.Error() {
		t.Fatalf("final status is event=%q promotion_ready=%v refusal=%q, want stopped, false, %q",
			final.Event, final.PromotionReady, final.Refusal, context.Canceled.Error())
	}
	if gate := clientLoop.Tunnel().Gate().State(); gate == tun.StateCarrying {
		t.Fatal("the client's gate is still carrying after a host stop")
	}
}
