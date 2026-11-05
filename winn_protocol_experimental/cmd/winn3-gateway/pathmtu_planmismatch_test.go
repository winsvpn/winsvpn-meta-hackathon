package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// TestAFullPlanClientAgainstTheDefaultUdpGatewayRefusesInsteadOfBlackHoling
// is the shipping plan-floor mismatch, driven through THIS binary's
// constructors, not through winn3/driver.NewSizing called from a test.
//
// cmd/winn3-gateway's -plan flag defaults to "udp" (see run). cmd/winn-datapath
// sizes whatever carrier_classes the served profile named, which the reference
// operator sets to udp,tcp,tls. Both resolve a missing path_mtu to
// carrier.DefaultPathMTU. PathMTUs therefore agree and the 7-byte PathMTU-only
// notice (EncodePathMTUNotice, winn3/gateway.New) cannot see the floor gap:
// the session establishes, small packets carry, and a full-size inner packet
// from the wider tun vanishes on the narrower one while both gates report
// carrying.
//
// newSession builds driver.NewGateway, whose responder emits
// EncodePathMTUFloorNotice. That suffix is what makes this loud. A regression
// that wired this binary onto winn3/gateway.New (7-byte notice) would make
// this test establish instead of refuse — the original black hole, and the
// driver-package sibling TestTwoLoopsAtTheSamePathMTUWithDifferentPlansRefuseInsteadOfBlackHoling
// would stay green because it never calls newSession.
func TestAFullPlanClientAgainstTheDefaultUdpGatewayRefusesInsteadOfBlackHoling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}

	// The flag default, through the function runServe actually calls.
	gwSizing, classes, err := buildServeSizing(serveOptions{
		plan:    "udp",
		pathMTU: carrier.DefaultPathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(classes) != 1 || classes[0] != carrier.ClassUDP {
		t.Fatalf("buildServeSizing(plan=udp) resolved %v, want [udp]", classes)
	}

	cliSizing, err := driver.NewSizing(
		carrier.DefaultPathMTU,
		carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS,
	)
	if err != nil {
		t.Fatal(err)
	}
	if gwSizing.PathMTU != cliSizing.PathMTU {
		t.Fatalf("harness: PathMTUs differ (%d vs %d); this test is about the same PathMTU",
			gwSizing.PathMTU, cliSizing.PathMTU)
	}
	if cliSizing.MessageSize >= gwSizing.MessageSize {
		t.Fatalf("harness: client floor %d is not below gateway udp-only floor %d",
			cliSizing.MessageSize, gwSizing.MessageSize)
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
		sizing:      gwSizing,
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

	cli, runErr := startTestClientCaptureRun(t, ctx, testClientOpts{
		dir:           dir,
		gwAddr:        conn.LocalAddr().(*net.UDPAddr),
		gatewayPublic: readTestKey(t, filepath.Join(dir, "static.pub")),
		admission:     readTestSecret(t, filepath.Join(dir, "admission.key")),
		sizing:        cliSizing,
		inner:         testClientInner,
	})

	select {
	case err := <-runErr:
		if err == nil {
			t.Fatal("the client loop ran to completion against the default -plan udp gateway " +
				"at the same path MTU; that session is the black hole")
		}
		if !errors.Is(err, driver.ErrSessionFailed) {
			t.Fatalf("Run returned %v, want ErrSessionFailed", err)
		}
		if !errors.Is(cli.loop.Session().Err(), session.ErrPathMTUMismatch) {
			t.Fatalf("the session failed with %v, want ErrPathMTUMismatch", cli.loop.Session().Err())
		}
		text := err.Error()
		for _, want := range []string{
			strconv.Itoa(cliSizing.MessageSize),
			strconv.Itoa(gwSizing.MessageSize),
			strconv.Itoa(carrier.DefaultPathMTU),
		} {
			if !strings.Contains(text, want) {
				t.Errorf("Run's error does not name %s:\n%s", want, text)
			}
		}
		if !strings.Contains(text, "cannot shrink") {
			t.Errorf("a wider gateway plan floor does not say this end cannot shrink the responder:\n%s", text)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the client did not refuse within 20s; if the gate is carrying this is the black hole")
	}
	if cli.loop.Carrying() {
		t.Error("the client reported carrying on a session it refused")
	}
}

// TestAUdpClientAgainstTheDefaultUdpGatewayAtTheFleetPathMTUStillCarries is
// the over-fire control: identical PathMTU AND identical plan, through the
// same constructors as the refusal above, must still establish and reflect
// an inner packet. A gateway that refused every client would make the
// refusal test green for the wrong reason.
func TestAUdpClientAgainstTheDefaultUdpGatewayAtTheFleetPathMTUStillCarries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	sizing, classes, err := buildServeSizing(serveOptions{
		plan:    "udp",
		pathMTU: carrier.DefaultPathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(classes) != 1 || classes[0] != carrier.ClassUDP {
		t.Fatalf("buildServeSizing(plan=udp) resolved %v, want [udp]", classes)
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

	cli := startTestClient(t, ctx, testClientOpts{
		dir:           dir,
		gwAddr:        conn.LocalAddr().(*net.UDPAddr),
		gatewayPublic: readTestKey(t, filepath.Join(dir, "static.pub")),
		admission:     readTestSecret(t, filepath.Join(dir, "admission.key")),
		sizing:        sizing,
		inner:         testClientInner,
	})
	waitFor(t, 40*time.Second, "the client gate to carry", func() bool {
		return cli.loop.Tunnel().Gate().State() == tun.StateCarrying
	})
	payload := []byte("default udp plan at the fleet path MTU still carries")
	cli.dev.offer(t, testIPv4(t, testClientInner, testGatewayInner, payload))
	back := cli.dev.take(t, 40*time.Second)
	if !bytes.Equal(back[20:], payload) {
		t.Fatalf("reflected payload is %q, want %q", back[20:], payload)
	}
	if err := cli.loop.Session().Err(); err != nil {
		t.Fatalf("an agreeing session recorded %v", err)
	}
}

// startTestClientCaptureRun is startTestClient except Run's error is returned
// rather than discarded. The refusal test has to see ErrSessionFailed; the
// harness that swallows it cannot tell a refusal from a hang.
func startTestClientCaptureRun(t *testing.T, ctx context.Context, o testClientOpts) (*testClient, <-chan error) {
	t.Helper()
	staticBytes, err := readKeyFile(filepath.Join(o.dir, "client.key"))
	if err != nil {
		t.Fatal(err)
	}
	staticKey, err := core.NewStaticKey(staticBytes)
	if err != nil {
		t.Fatal(err)
	}
	gatewayStatic, err := core.NewPublicKey(o.gatewayPublic)
	if err != nil {
		t.Fatal(err)
	}
	car, err := carrier.DialUDP(ctx, carrier.UDPConfig{
		Remote:         o.gwAddr,
		MaxMessageSize: o.sizing.MessageSize,
		PathMTU:        o.sizing.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	dev := newTestDevice(o.sizing.InnerMTU)
	tunCfg := tun.Config{
		Assign: tun.Assignment{V4: netip.MustParseAddr(o.inner)},
		Device: dev,
		Clock:  driver.SessionClock{Clock: driver.SystemClock{}},
	}
	loop, err := driver.NewClient(driver.Config{
		Session: session.Config{
			Core: core.Config{
				Gateway: core.GatewayParams{
					AdmissionKeys: [][]byte{o.admission},
					GatewayID:     []byte(testGatewayID),
				},
			},
			Static:        staticKey,
			GatewayStatic: gatewayStatic,
			Padding:       core.PadBucket,
		},
		Sizing:  o.sizing,
		Carrier: car,
		Tun:     &tunCfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	runErr := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runErr <- loop.Run(runCtx)
	}()
	t.Cleanup(func() {
		cancel()
		_ = loop.Close()
		_ = dev.Close()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
	return &testClient{loop: loop, dev: dev}, runErr
}
