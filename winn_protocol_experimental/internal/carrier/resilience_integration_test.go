package carrier

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/mobility"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

func TestRealCarrierSelfHealingH3ToH2(t *testing.T) {
	echoAddress, stopEcho := startUDPEcho(t)
	defer stopEcho()
	lab := generateCarrierLab(t)
	suite, err := tlsconfig.ParseSuite("x25519-mlkem768")
	if err != nil {
		t.Fatal(err)
	}
	deviceSigner, err := pqauth.LoadSigner(pqauth.MLDSA65, lab.DevicePQ65Seed)
	if err != nil {
		t.Fatal(err)
	}
	controllerSigner, err := pqauth.LoadSigner(pqauth.MLDSA87, lab.ControllerPQ87Seed)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := pqauth.LoadRegistry(lab.DeviceRegistry)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := pqauth.LoadVerifierSet(lab.ControllerPQPins)
	if err != nil {
		t.Fatal(err)
	}
	replay, _ := carrierauth.NewReplayCache(256)
	requestVerifier := &carrierauth.RequestVerifier{
		Registry: registry, Replay: replay, Suite: suite.Name, MaxSkew: time.Minute,
	}
	responseVerifier := &carrierauth.ResponseVerifier{
		Verifiers: pins, ControllerID: "lab-controller", Suite: suite.Name, MaxSkew: time.Minute,
	}

	h3PacketListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h3Template := "https://" + h3PacketListener.LocalAddr().String() +
		"/.well-known/masque/udp/{target_host}/{target_port}/"
	h3Handler, err := NewH3Server(
		h3Template, "winn.invalid:443", echoAddress, suite,
		requestVerifier, controllerSigner, "lab-controller",
	)
	if err != nil {
		t.Fatal(err)
	}
	h3TLS, err := tlsconfig.ServerForALPN(
		lab.ServerCert, lab.ServerKey, lab.CACert, suite, http3.NextProtoH3,
	)
	if err != nil {
		t.Fatal(err)
	}
	h3Service := &http3.Server{
		TLSConfig: h3TLS, Handler: h3Handler, EnableDatagrams: true,
		QUICConfig: &quic.Config{
			EnableDatagrams: true, Allow0RTT: false,
			InitialPacketSize: H3InitialPacketSize(
				h3Handler.MaxDatagram + envelopeHeaderSize,
			),
			HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 10 * time.Second,
		},
	}
	h3Done := make(chan error, 1)
	go func() { h3Done <- h3Service.Serve(h3PacketListener) }()

	h2Listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h2Handler, err := NewH2Server(
		"winn.invalid:443", echoAddress, suite,
		requestVerifier, controllerSigner, "lab-controller",
	)
	if err != nil {
		t.Fatal(err)
	}
	h2TLS, err := tlsconfig.ServerForALPN(
		lab.ServerCert, lab.ServerKey, lab.CACert, suite, http2.NextProtoTLS,
	)
	if err != nil {
		t.Fatal(err)
	}
	h2Service := &http.Server{Handler: h2Handler, TLSConfig: h2TLS}
	if err := http2.ConfigureServer(h2Service, &http2.Server{}); err != nil {
		t.Fatal(err)
	}
	h2Done := make(chan error, 1)
	go func() { h2Done <- h2Service.ServeTLS(h2Listener, "", "") }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = h2Service.Shutdown(ctx)
		select {
		case serveErr := <-h2Done:
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				t.Errorf("H2 server: %v", serveErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("H2 service did not stop")
		}
	}()

	clientH3TLS, err := tlsconfig.ClientForALPN(
		lab.DeviceCert, lab.DeviceKey, lab.CACert, "127.0.0.1", suite, http3.NextProtoH3,
	)
	if err != nil {
		t.Fatal(err)
	}
	clientH2TLS, err := tlsconfig.ClientForALPN(
		lab.DeviceCert, lab.DeviceKey, lab.CACert, "127.0.0.1", suite, http2.NextProtoTLS,
	)
	if err != nil {
		t.Fatal(err)
	}
	const sessionID = "ffeeddccbbaa99887766554433221100"
	h3Dialer, err := NewH3Dialer(
		h3Template, "winn.invalid:443", lab.DeviceID, sessionID,
		suite, clientH3TLS, deviceSigner, responseVerifier,
	)
	if err != nil {
		t.Fatal(err)
	}
	h2Dialer, err := NewH2Dialer(
		"https://"+h2Listener.Addr().String()+H2Path,
		"winn.invalid:443", lab.DeviceID, sessionID,
		suite, clientH2TLS, deviceSigner, responseVerifier,
	)
	if err != nil {
		t.Fatal(err)
	}
	managerConfig := DefaultManagerConfig()
	managerConfig.DialTimeout = 5 * time.Second
	managerConfig.RecoveryInitial = 10 * time.Millisecond
	managerConfig.RecoveryMaximum = 50 * time.Millisecond
	manager, err := NewManager(
		context.Background(), sessionID, 42,
		[]Candidate{
			{Path: mobility.Path{
				ID: "h3-node-a", Carrier: mobility.HTTP3,
				Endpoint: h3Template, Priority: 0,
			}, Dialer: h3Dialer},
			{Path: mobility.Path{
				ID: "h2-node-b", Carrier: mobility.HTTP2,
				Endpoint: h2Listener.Addr().String(), Priority: 10,
			}, Dialer: h2Dialer},
		},
		mobility.DefaultConfig(), managerConfig,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := manager.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if manager.Snapshot().ActivePath != "h3-node-a" {
		t.Fatal("H3 was not initially selected")
	}
	assertManagerEcho(t, manager, []byte("before-H3-failure"))

	if err := h3Service.Close(); err != nil {
		t.Fatal(err)
	}
	_ = h3Handler.Close()
	select {
	case serveErr := <-h3Done:
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) &&
			!errors.Is(serveErr, net.ErrClosed) {
			t.Fatalf("H3 server: %v", serveErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("H3 service did not stop")
	}
	readResult := make(chan error, 1)
	go func() {
		buffer := make([]byte, DefaultMaxDatagram)
		count, _, readErr := manager.ReadFrom(buffer)
		if readErr == nil && string(buffer[:count]) != "after-H3-failure" {
			readErr = errors.New("unexpected post-recovery payload")
		}
		readResult <- readErr
	}()
	waitForActivePath(t, manager, "h2-node-b", 5*time.Second)
	if _, err := manager.WriteTo([]byte("after-H3-failure"), nil); err != nil {
		t.Fatal(err)
	}
	select {
	case readErr := <-readResult:
		if readErr != nil {
			t.Fatal(readErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("read did not resume after H2 recovery")
	}
	snapshot := manager.Snapshot()
	if snapshot.SessionID != sessionID || snapshot.TunnelGeneration != 42 ||
		snapshot.ActivePath != "h2-node-b" {
		t.Fatalf("self-healing broke logical tunnel continuity: %+v", snapshot)
	}
}

func assertManagerEcho(t *testing.T, manager *Manager, payload []byte) {
	t.Helper()
	_ = manager.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := manager.WriteTo(payload, nil); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, DefaultMaxDatagram)
	count, _, err := manager.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:count]) != string(payload) {
		t.Fatalf("echo %q, want %q", buffer[:count], payload)
	}
	_ = manager.SetDeadline(time.Time{})
}

func waitForActivePath(t *testing.T, manager *Manager, expected string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if manager.Snapshot().ActivePath == expected {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("active path did not become %s: %+v", expected, manager.Snapshot())
}
