//go:build unix

package datapath

// The descriptor half of the carrier contract: a socket the HOST opened (and,
// on Android, protected) is adopted by the datapath and handed to the carrier,
// which uses it and opens nothing of its own.
//
// TestOpenWithCarrierCarriesRealDatagramsOverAMasqueCarrier is the one that
// matters for an audit: it is not a double. It stands up the real H3 CONNECT-UDP
// (MASQUE) server from internal/carrier, dials it with the real H3Dialer over a
// borrowed descriptor, and moves real datagrams end to end through
// WriteInbound/ReadOutbound.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/pki"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

// TestOpenWithCarrierHandsTheProtectedDescriptorToTheCarrier proves the wiring
// with a double: the exact socket the host handed over is the socket the
// carrier dialer received, and the engine's own socket-creation seam is never
// reached.
func TestOpenWithCarrierHandsTheProtectedDescriptorToTheCarrier(t *testing.T) {
	attempts := withSocketOpenerGuard(t)

	adopted := 0
	originalAdopt := descriptorAdopted
	descriptorAdopted = func() { adopted++ }
	t.Cleanup(func() { descriptorAdopted = originalAdopt })

	descriptor, local := borrowUDPDescriptor(t)
	dialer := &stubPacketCarrierDialer{}
	engine, err := OpenWithCarrier(
		context.Background(),
		carrierConfigBlob(CarrierHTTP3, "203.0.113.9:51820"),
		descriptor,
		dialer,
	)
	if err != nil {
		t.Fatalf("OpenWithCarrier with descriptor %d: %v", descriptor, err)
	}
	defer func() { _ = engine.Close() }()

	if adopted != 1 {
		t.Fatalf("descriptor adoption ran %d times, want 1", adopted)
	}
	if dialer.supplied == nil {
		t.Fatal("the carrier dialer was never given the adopted descriptor")
	}
	if got := dialer.supplied.LocalAddr().String(); got != local.String() {
		t.Fatalf(
			"carrier was given a socket bound to %s, want the host's %s",
			got, local,
		)
	}
	if dialer.ownedSockets.Load() != 0 {
		t.Fatalf(
			"carrier opened %d sockets of its own despite being supplied one",
			dialer.ownedSockets.Load(),
		)
	}
	if engine.Status().SocketOwnedByEngine {
		t.Fatal("socket_owned_by_engine is true for an adopted descriptor")
	}
	if got := attempts.Load(); got != 0 {
		t.Fatalf("%d socket-creation attempts with a supplied descriptor", got)
	}
}

// TestOpenWithCarrierRefusesAStreamDescriptorForAPacketCarrier keeps the two
// socket kinds from being confused: a UDP descriptor is not a TCP one.
func TestOpenWithCarrierRefusesAStreamDescriptorForAPacketCarrier(t *testing.T) {
	descriptor, _ := borrowUDPDescriptor(t)
	_, err := OpenWithCarrier(
		context.Background(),
		carrierConfigBlob(CarrierHTTP2, "203.0.113.9:51820"),
		descriptor,
		&stubStreamCarrierDialer{},
	)
	if err == nil {
		t.Fatal("a UDP descriptor was accepted for the HTTP/2 carrier")
	}
	if !strings.Contains(err.Error(), "not a TCP socket") {
		t.Fatalf("error = %v, want a refusal naming the wrong socket kind", err)
	}
}

// TestOpenWithCarrierCarriesRealDatagramsOverAMasqueCarrier is the end-to-end
// proof. No doubles: real PQ device authentication, real TLS 1.3 with the
// x25519-mlkem768 suite, a real QUIC handshake, a real RFC 9298 CONNECT-UDP
// session through internal/masque, and real datagrams in both directions —
// every byte of it over a UDP descriptor the host opened and handed over.
func TestOpenWithCarrierCarriesRealDatagramsOverAMasqueCarrier(t *testing.T) {
	attempts := withSocketOpenerGuard(t)

	echoAddress, stopEcho := startDatapathUDPEcho(t)
	defer stopEcho()

	lab, err := pki.GenerateLab(
		t.TempDir()+"/pki", "127.0.0.1", "android-lab-1", time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
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
	replay, err := carrierauth.NewReplayCache(128)
	if err != nil {
		t.Fatal(err)
	}

	packetListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetListener.Close()
	template := "https://" + packetListener.LocalAddr().String() +
		"/.well-known/masque/udp/{target_host}/{target_port}/"
	handler, err := carrier.NewH3Server(
		template, "winn.invalid:443", echoAddress, suite,
		&carrierauth.RequestVerifier{
			Registry: registry, Replay: replay,
			Suite: suite.Name, MaxSkew: time.Minute,
		},
		controllerSigner, "lab-controller",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	serverTLS, err := tlsconfig.ServerForALPN(
		lab.ServerCert, lab.ServerKey, lab.CACert, suite, http3.NextProtoH3,
	)
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		TLSConfig: serverTLS, Handler: handler, EnableDatagrams: true,
		QUICConfig: &quic.Config{
			EnableDatagrams: true, Allow0RTT: false,
			// The client and server must agree on the packet floor. It is what
			// makes the completed handshake proof that the path carries a
			// full-size Winn envelope in both directions, which is what the
			// HTTP/3 carrier reads instead of probing the path with datagrams.
			InitialPacketSize: carrier.H3InitialPacketSize(
				handler.MaxOuterDatagram,
			),
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       20 * time.Second,
		},
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(packetListener) }()
	defer func() {
		_ = server.Close()
		select {
		case serveErr := <-serverDone:
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) &&
				!errors.Is(serveErr, net.ErrClosed) {
				t.Errorf("H3 server: %v", serveErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("H3 server did not stop")
		}
	}()

	clientTLS, err := tlsconfig.ClientForALPN(
		lab.DeviceCert, lab.DeviceKey, lab.CACert,
		"127.0.0.1", suite, http3.NextProtoH3,
	)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := carrier.NewH3Dialer(
		template, "winn.invalid:443", lab.DeviceID,
		"0123456789abcdef0123456789abcdef", suite, clientTLS,
		deviceSigner, &carrierauth.ResponseVerifier{
			Verifiers: pins, ControllerID: "lab-controller",
			Suite: suite.Name, MaxSkew: time.Minute,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	// The descriptor the host opened. In production VpnService.protect(fd) has
	// already marked this kernel socket, and the mark survives the handoff.
	descriptor, local := borrowUDPDescriptor(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	engine, err := OpenWithCarrier(
		ctx,
		carrierConfigBlob(CarrierHTTP3, echoAddress),
		descriptor,
		dialer,
	)
	if err != nil {
		t.Fatalf("OpenWithCarrier over the real MASQUE carrier: %v", err)
	}
	defer func() { _ = engine.Close() }()

	status := engine.Status()
	if status.Carrier != CarrierHTTP3 {
		t.Fatalf("status carrier = %q, want %q", status.Carrier, CarrierHTTP3)
	}
	if status.SocketOwnedByEngine {
		t.Fatal("socket_owned_by_engine is true for an adopted descriptor")
	}
	if status.GatewaySenderFilter {
		t.Fatal("gateway_sender_filter is on for a carrier transport")
	}
	// The carrier's local address is the QUIC connection's local address, which
	// is the supplied socket's. This is the cross-layer proof that the bytes
	// really left over the descriptor the host handed us.
	if status.LocalEndpoint != local.String() {
		t.Fatalf(
			"carrier is bound to %s, want the host's protected socket %s",
			status.LocalEndpoint, local,
		)
	}

	payloads := [][]byte{
		[]byte("awg-outer-datagram-one-over-masque"),
		[]byte("awg-outer-datagram-two-over-masque"),
	}
	buffer := make([]byte, 2048)
	for _, payload := range payloads {
		if _, err := engine.WriteInbound(payload); err != nil {
			t.Fatalf("WriteInbound over the MASQUE carrier: %v", err)
		}
		count, err := engine.ReadOutboundTimeout(buffer, 10*time.Second)
		if err != nil {
			t.Fatalf("ReadOutbound over the MASQUE carrier: %v", err)
		}
		if string(buffer[:count]) != string(payload) {
			t.Fatalf("echo %q, want %q", buffer[:count], payload)
		}
	}

	final := engine.Status()
	if final.TxDatagrams != uint64(len(payloads)) {
		t.Fatalf("tx_datagrams = %d, want %d", final.TxDatagrams, len(payloads))
	}
	if final.RxDatagrams != uint64(len(payloads)) {
		t.Fatalf("rx_datagrams = %d, want %d", final.RxDatagrams, len(payloads))
	}
	if final.RxForeign != 0 {
		t.Fatalf("%d carrier datagrams were rejected as foreign", final.RxForeign)
	}
	if got := attempts.Load(); got != 0 {
		t.Fatalf("%d socket-creation attempts with a supplied descriptor", got)
	}
}

// TestOpenWithCarrierCarriesRealDatagramsOverAnHTTP2Carrier is the stream-socket
// twin of the MASQUE test. It exists because adoptStreamDescriptor and the
// SocketKindStream branch of installCarrierSocket are a different code path, and
// a path that has never moved a byte should not be reported as working.
func TestOpenWithCarrierCarriesRealDatagramsOverAnHTTP2Carrier(t *testing.T) {
	attempts := withSocketOpenerGuard(t)

	echoAddress, stopEcho := startDatapathUDPEcho(t)
	defer stopEcho()

	lab, err := pki.GenerateLab(
		t.TempDir()+"/pki", "127.0.0.1", "android-lab-1", time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
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
	replay, err := carrierauth.NewReplayCache(128)
	if err != nil {
		t.Fatal(err)
	}

	handler, err := carrier.NewH2Server(
		"winn.invalid:443", echoAddress, suite,
		&carrierauth.RequestVerifier{
			Registry: registry, Replay: replay,
			Suite: suite.Name, MaxSkew: time.Minute,
		},
		controllerSigner, "lab-controller",
	)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := tlsconfig.ServerForALPN(
		lab.ServerCert, lab.ServerKey, lab.CACert, suite, http2.NextProtoTLS,
	)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler: handler, TLSConfig: serverTLS,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.ServeTLS(listener, "", "") }()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		select {
		case serveErr := <-serverDone:
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				t.Errorf("H2 server: %v", serveErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("H2 server did not stop")
		}
	}()

	clientTLS, err := tlsconfig.ClientForALPN(
		lab.DeviceCert, lab.DeviceKey, lab.CACert,
		"127.0.0.1", suite, http2.NextProtoTLS,
	)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := carrier.NewH2Dialer(
		"https://"+listener.Addr().String()+carrier.H2Path,
		"winn.invalid:443", lab.DeviceID,
		"0123456789abcdef0123456789abcdef", suite, clientTLS,
		deviceSigner, &carrierauth.ResponseVerifier{
			Verifiers: pins, ControllerID: "lab-controller",
			Suite: suite.Name, MaxSkew: time.Minute,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	descriptor := borrowTCPDescriptor(t, listener.Addr().String())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	engine, err := OpenWithCarrier(
		ctx, carrierConfigBlob(CarrierHTTP2, echoAddress), descriptor, dialer,
	)
	if err != nil {
		t.Fatalf("OpenWithCarrier over the real HTTP/2 carrier: %v", err)
	}
	defer func() { _ = engine.Close() }()

	status := engine.Status()
	if status.Carrier != CarrierHTTP2 {
		t.Fatalf("status carrier = %q, want %q", status.Carrier, CarrierHTTP2)
	}
	if status.SocketOwnedByEngine {
		t.Fatal("socket_owned_by_engine is true for an adopted descriptor")
	}
	if status.GatewaySenderFilter {
		t.Fatal("gateway_sender_filter is on for a carrier transport")
	}
	// HTTP/2 has no address identity to compare — h2PacketConn reports a fixed
	// local name — so the proof that the host's descriptor is what carried the
	// session is that the carrier CONSUMED it. Without this the test would pass
	// just as happily on a socket the carrier opened for itself.
	if !dialer.TransportConn.Taken() {
		t.Fatal(
			"the HTTP/2 carrier never consumed the host's descriptor; it must " +
				"have opened its own TCP connection",
		)
	}

	payload := []byte("awg-outer-datagram-over-http2")
	if _, err := engine.WriteInbound(payload); err != nil {
		t.Fatalf("WriteInbound over the HTTP/2 carrier: %v", err)
	}
	buffer := make([]byte, 2048)
	count, err := engine.ReadOutboundTimeout(buffer, 10*time.Second)
	if err != nil {
		t.Fatalf("ReadOutbound over the HTTP/2 carrier: %v", err)
	}
	if string(buffer[:count]) != string(payload) {
		t.Fatalf("echo %q, want %q", buffer[:count], payload)
	}
	if got := attempts.Load(); got != 0 {
		t.Fatalf("%d socket-creation attempts with a supplied descriptor", got)
	}
}

// borrowTCPDescriptor produces a CONNECTED TCP descriptor that nothing in the
// test process owns, mirroring borrowUDPDescriptor. On Android this is the
// socket the host would connect and then hand to VpnService.protect.
func borrowTCPDescriptor(t *testing.T, address string) int {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("connect for descriptor: %v", err)
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		t.Fatalf("dialed %T, want *net.TCPConn", conn)
	}
	file, err := tcp.File()
	if err != nil {
		_ = conn.Close()
		t.Fatalf("duplicate descriptor: %v", err)
	}
	_ = conn.Close()
	descriptor, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		_ = file.Close()
		t.Fatalf("dup descriptor: %v", err)
	}
	syscall.CloseOnExec(descriptor)
	if err := file.Close(); err != nil {
		t.Fatalf("release intermediate descriptor: %v", err)
	}
	return descriptor
}

func startDatapathUDPEcho(t *testing.T) (string, func()) {
	t.Helper()
	connection, err := net.ListenUDP("udp", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 2048)
		for {
			count, peer, readErr := connection.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			_, _ = connection.WriteToUDP(buffer[:count], peer)
		}
	}()
	return connection.LocalAddr().String(), func() {
		_ = connection.Close()
		<-done
	}
}
