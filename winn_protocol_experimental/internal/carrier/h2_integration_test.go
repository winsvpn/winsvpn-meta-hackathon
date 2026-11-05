package carrier

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

func TestAuthenticatedH2FallbackEndToEnd(t *testing.T) {
	echoAddress, stopEcho := startUDPEcho(t)
	defer stopEcho()
	lab := generateCarrierLab(t)
	suite, err := tlsconfig.ParseSuite("x25519-mlkem768")
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := tlsconfig.ServerForALPN(
		lab.ServerCert, lab.ServerKey, lab.CACert, suite, http2.NextProtoTLS,
	)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := tlsconfig.ClientForALPN(
		lab.DeviceCert, lab.DeviceKey, lab.CACert, "127.0.0.1", suite, http2.NextProtoTLS,
	)
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
	replay, _ := carrierauth.NewReplayCache(128)
	requestVerifier := &carrierauth.RequestVerifier{
		Registry: registry, Replay: replay, Suite: suite.Name, MaxSkew: time.Minute,
	}
	handler, err := NewH2Server(
		"winn.invalid:443",
		echoAddress,
		suite,
		requestVerifier,
		controllerSigner,
		"lab-controller",
	)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler:           handler,
		TLSConfig:         serverTLS,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	if err := http2.ConfigureServer(server, &http2.Server{
		MaxConcurrentStreams: 64,
		IdleTimeout:          30 * time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.ServeTLS(listener, "", "")
	}()
	defer func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
		select {
		case serveErr := <-serverDone:
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				t.Errorf("H2 server: %v", serveErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("H2 server did not stop")
		}
	}()

	responseVerifier := &carrierauth.ResponseVerifier{
		Verifiers: pins, ControllerID: "lab-controller", Suite: suite.Name, MaxSkew: time.Minute,
	}
	dialer, err := NewH2Dialer(
		"https://"+listener.Addr().String()+H2Path,
		"winn.invalid:443",
		lab.DeviceID,
		"00112233445566778899aabbccddeeff",
		suite,
		clientTLS,
		deviceSigner,
		responseVerifier,
	)
	if err != nil {
		t.Fatal(err)
	}
	var customDialUsed atomic.Bool
	var networkDialer net.Dialer
	dialer.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		customDialUsed.Store(true)
		return networkDialer.DialContext(ctx, network, address)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := dialer.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !customDialUsed.Load() {
		t.Fatal("injected TCP underlay dialer was not used")
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payloads := [][]byte{
		[]byte("first-h2-fallback-datagram"),
		[]byte("second-h2-fallback-datagram"),
	}
	buffer := make([]byte, DefaultMaxDatagram)
	for _, payload := range payloads {
		if _, err := connection.WriteTo(payload, nil); err != nil {
			t.Fatal(err)
		}
		count, _, err := connection.ReadFrom(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if string(buffer[:count]) != string(payload) {
			t.Fatalf("echo %q, want %q", buffer[:count], payload)
		}
	}
}

func TestFrameBounds(t *testing.T) {
	if err := writeFrame(ioDiscard{}, nil, DefaultMaxDatagram); err != ErrDatagramTooLarge {
		t.Fatalf("empty datagram returned %v", err)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(data []byte) (int, error) { return len(data), nil }
