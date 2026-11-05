package carrier

// These tests are the load-bearing proof for the Android handoff.
//
// The claim being tested is not "the code compiles with a supplied socket". It
// is "the carrier moved real bytes over the socket the caller supplied, and
// created no socket of its own". Both halves are checked:
//
//   - listenUDPSocket and defaultStreamDialContext are the ONLY two places this
//     package opens a transport socket. Each test replaces them with recorders
//     that fail the test if they are ever reached.
//   - a real authenticated carrier is dialled against a real server, and a real
//     datagram is echoed back through it.
//
// The negative half is what matters: without it a carrier could quietly open
// its own unprotected socket and every functional assertion would still pass —
// on Android that is the difference between a tunnel and an infinite loop.

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/pki"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

const suppliedSocketSessionID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

type suppliedSocketRig struct {
	lab              pki.Paths
	suite            tlsconfig.Suite
	deviceSigner     *pqauth.Signer
	requestVerifier  *carrierauth.RequestVerifier
	responseVerifier *carrierauth.ResponseVerifier
	echoAddress      string
}

func newSuppliedSocketRig(t *testing.T) *suppliedSocketRig {
	t.Helper()
	echoAddress, stopEcho := startUDPEcho(t)
	t.Cleanup(stopEcho)
	lab := generateCarrierLab(t)
	suite, err := tlsconfig.ParseSuite("x25519-mlkem768")
	if err != nil {
		t.Fatal(err)
	}
	deviceSigner, err := pqauth.LoadSigner(pqauth.MLDSA65, lab.DevicePQ65Seed)
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
	return &suppliedSocketRig{
		lab:          lab,
		suite:        suite,
		deviceSigner: deviceSigner,
		requestVerifier: &carrierauth.RequestVerifier{
			Registry: registry, Replay: replay,
			Suite: suite.Name, MaxSkew: time.Minute,
		},
		responseVerifier: &carrierauth.ResponseVerifier{
			Verifiers: pins, ControllerID: "lab-controller",
			Suite: suite.Name, MaxSkew: time.Minute,
		},
		echoAddress: echoAddress,
	}
}

// controllerSigner is rebuilt per server so the rig holds no long-lived signer
// beyond the device one the dialers need.
func (rig *suppliedSocketRig) controllerSigner(t *testing.T) *pqauth.Signer {
	t.Helper()
	signer, err := pqauth.LoadSigner(pqauth.MLDSA87, rig.lab.ControllerPQ87Seed)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// refuseOwnUDPSocket makes any attempt by this package to open its own UDP
// socket fail the test. It returns a counter so a test can also assert zero.
func refuseOwnUDPSocket(t *testing.T) *atomic.Int32 {
	t.Helper()
	var attempts atomic.Int32
	previous := listenUDPSocket
	listenUDPSocket = func(network string, local *net.UDPAddr) (net.PacketConn, error) {
		attempts.Add(1)
		t.Errorf(
			"carrier opened its own UDP socket (%s %v) while a caller-supplied "+
				"socket was installed; on Android that socket is unprotected and "+
				"the tunnel loops",
			network, local,
		)
		return nil, errors.New("own-socket path is poisoned by the test")
	}
	t.Cleanup(func() { listenUDPSocket = previous })
	return &attempts
}

// refuseOwnTCPSocket is the HTTP/2 equivalent.
func refuseOwnTCPSocket(t *testing.T) *atomic.Int32 {
	t.Helper()
	var attempts atomic.Int32
	previous := defaultStreamDialContext
	defaultStreamDialContext = func(
		_ context.Context, network, address string,
	) (net.Conn, error) {
		attempts.Add(1)
		t.Errorf(
			"carrier opened its own TCP connection (%s %s) while a "+
				"caller-supplied socket was installed",
			network, address,
		)
		return nil, errors.New("own-socket path is poisoned by the test")
	}
	t.Cleanup(func() { defaultStreamDialContext = previous })
	return &attempts
}

// countingStreamConn records how many bytes really crossed the supplied TCP
// connection, so "it worked" cannot be satisfied by some other socket.
type countingStreamConn struct {
	net.Conn
	read    atomic.Uint64
	written atomic.Uint64
}

func (c *countingStreamConn) Read(buffer []byte) (int, error) {
	count, err := c.Conn.Read(buffer)
	if count > 0 {
		c.read.Add(uint64(count))
	}
	return count, err
}

func (c *countingStreamConn) Write(buffer []byte) (int, error) {
	count, err := c.Conn.Write(buffer)
	if count > 0 {
		c.written.Add(uint64(count))
	}
	return count, err
}

// TestH3CarrierRidesCallerSuppliedPacketSocket dials the real authenticated
// HTTP/3 CONNECT-UDP (MASQUE) carrier over a UDP socket the test opened, and
// proves the carrier opened none of its own.
func TestH3CarrierRidesCallerSuppliedPacketSocket(t *testing.T) {
	rig := newSuppliedSocketRig(t)

	packetListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetListener.Close()
	template := "https://" + packetListener.LocalAddr().String() +
		"/.well-known/masque/udp/{target_host}/{target_port}/"
	handler, err := NewH3Server(
		template, "winn.invalid:443", rig.echoAddress, rig.suite,
		rig.requestVerifier, rig.controllerSigner(t), "lab-controller",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	serverTLS, err := tlsconfig.ServerForALPN(
		rig.lab.ServerCert, rig.lab.ServerKey, rig.lab.CACert,
		rig.suite, http3.NextProtoH3,
	)
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		TLSConfig: serverTLS, Handler: handler, EnableDatagrams: true,
		QUICConfig: &quic.Config{
			EnableDatagrams: true, Allow0RTT: false,
			InitialPacketSize: H3InitialPacketSize(
				handler.MaxDatagram + envelopeHeaderSize,
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
		rig.lab.DeviceCert, rig.lab.DeviceKey, rig.lab.CACert,
		"127.0.0.1", rig.suite, http3.NextProtoH3,
	)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := NewH3Dialer(
		template, "winn.invalid:443", rig.lab.DeviceID,
		suppliedSocketSessionID, rig.suite, clientTLS,
		rig.deviceSigner, rig.responseVerifier,
	)
	if err != nil {
		t.Fatal(err)
	}

	// This is the socket a VpnService.protect(fd) would have marked.
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	protectedAddress := socket.LocalAddr().String()
	if err := dialer.UseSuppliedSocket(socket); err != nil {
		_ = socket.Close()
		t.Fatal(err)
	}
	if !dialer.HasSuppliedSocket() {
		t.Fatal("dialer does not report the supplied socket")
	}
	if dialer.SuppliedSocketKind() != SocketKindPacket {
		t.Fatalf("H3 asked for %q, want %q",
			dialer.SuppliedSocketKind(), SocketKindPacket)
	}

	attempts := refuseOwnUDPSocket(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	connection, err := dialer.Dial(ctx)
	if err != nil {
		t.Fatalf("dial H3 carrier over a caller-supplied socket: %v", err)
	}
	defer connection.Close()

	if local := connection.LocalAddr(); local == nil ||
		local.String() != protectedAddress {
		t.Fatalf(
			"carrier local address is %v, want the supplied socket %s",
			local, protectedAddress,
		)
	}
	if !dialer.TransportSocket.Taken() {
		t.Fatal("supplied socket was not consumed by the dial")
	}
	if got := attempts.Load(); got != 0 {
		t.Fatalf("carrier opened %d sockets of its own; want 0", got)
	}

	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("awg-outer-datagram-over-a-protected-socket")
	if _, err := connection.WriteTo(payload, nil); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, DefaultMaxDatagram)
	count, _, err := connection.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:count]) != string(payload) {
		t.Fatalf("echo %q, want %q", buffer[:count], payload)
	}

	// A second dial must fail closed rather than open a replacement socket the
	// host never protected.
	secondContext, cancelSecond := context.WithTimeout(
		context.Background(), 5*time.Second,
	)
	defer cancelSecond()
	if _, err := dialer.Dial(secondContext); !errors.Is(
		err, ErrSuppliedSocketConsumed,
	) {
		t.Fatalf("second dial returned %v, want ErrSuppliedSocketConsumed", err)
	}
	if got := attempts.Load(); got != 0 {
		t.Fatalf("re-dial opened %d sockets of its own; want 0", got)
	}
}

// TestH2CarrierRidesCallerSuppliedStreamSocket does the same for HTTP/2, whose
// transport is a TCP connection rather than a UDP socket.
func TestH2CarrierRidesCallerSuppliedStreamSocket(t *testing.T) {
	rig := newSuppliedSocketRig(t)

	handler, err := NewH2Server(
		"winn.invalid:443", rig.echoAddress, rig.suite,
		rig.requestVerifier, rig.controllerSigner(t), "lab-controller",
	)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := tlsconfig.ServerForALPN(
		rig.lab.ServerCert, rig.lab.ServerKey, rig.lab.CACert,
		rig.suite, http2.NextProtoTLS,
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
		rig.lab.DeviceCert, rig.lab.DeviceKey, rig.lab.CACert,
		"127.0.0.1", rig.suite, http2.NextProtoTLS,
	)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := NewH2Dialer(
		"https://"+listener.Addr().String()+H2Path,
		"winn.invalid:443", rig.lab.DeviceID, suppliedSocketSessionID,
		rig.suite, clientTLS, rig.deviceSigner, rig.responseVerifier,
	)
	if err != nil {
		t.Fatal(err)
	}

	// The host opens and protects the TCP connection, then hands it over.
	raw, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	supplied := &countingStreamConn{Conn: raw}
	if err := dialer.UseSuppliedSocket(supplied); err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	if dialer.SuppliedSocketKind() != SocketKindStream {
		t.Fatalf("H2 asked for %q, want %q",
			dialer.SuppliedSocketKind(), SocketKindStream)
	}

	attempts := refuseOwnTCPSocket(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	connection, err := dialer.Dial(ctx)
	if err != nil {
		t.Fatalf("dial H2 carrier over a caller-supplied socket: %v", err)
	}
	defer connection.Close()
	if got := attempts.Load(); got != 0 {
		t.Fatalf("carrier opened %d connections of its own; want 0", got)
	}
	if !dialer.TransportConn.Taken() {
		t.Fatal("supplied connection was not consumed by the dial")
	}

	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("awg-outer-datagram-over-a-protected-tcp-socket")
	if _, err := connection.WriteTo(payload, nil); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, DefaultMaxDatagram)
	count, _, err := connection.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:count]) != string(payload) {
		t.Fatalf("echo %q, want %q", buffer[:count], payload)
	}

	// Bytes really crossed the supplied connection, not merely "a" connection.
	if written := supplied.written.Load(); written == 0 {
		t.Fatal("no bytes were written to the caller-supplied TCP connection")
	}
	if read := supplied.read.Load(); read == 0 {
		t.Fatal("no bytes were read from the caller-supplied TCP connection")
	}
}

// TestSuppliedSocketFailsClosedRatherThanOpeningItsOwn covers the refusals that
// keep an unprotected socket from ever being substituted in.
func TestSuppliedSocketFailsClosedRatherThanOpeningItsOwn(t *testing.T) {
	t.Run("packet socket is single use", func(t *testing.T) {
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer socket.Close()
		supplied, err := NewSuppliedPacketSocket(socket)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := supplied.take(); err != nil {
			t.Fatal(err)
		}
		if _, err := supplied.take(); !errors.Is(err, ErrSuppliedSocketConsumed) {
			t.Fatalf("second take returned %v", err)
		}
	})

	t.Run("connected UDP socket is refused", func(t *testing.T) {
		peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		connected, err := net.Dial("udp4", peer.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer connected.Close()
		udp, ok := connected.(*net.UDPConn)
		if !ok {
			t.Fatalf("dialed %T, want *net.UDPConn", connected)
		}
		if _, err := NewSuppliedPacketSocket(udp); !errors.Is(
			err, ErrSuppliedSocketWrongKind,
		) {
			t.Fatalf("connected UDP socket accepted: %v", err)
		}
	})

	t.Run("H3 refuses a supplied socket beside a dial hook", func(t *testing.T) {
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer socket.Close()
		dialer := &H3Dialer{DialQUICPath: func(
			context.Context, string, *tls.Config, *quic.Config,
		) (*quic.Conn, *quic.Transport, error) {
			return nil, nil, errors.New("unreachable")
		}}
		if err := dialer.UseSuppliedSocket(socket); !errors.Is(
			err, ErrSuppliedSocketConflict,
		) {
			t.Fatalf("conflicting configuration accepted: %v", err)
		}
	})

	t.Run("H2 refuses a supplied socket beside a dial hook", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		dialer := &H2Dialer{DialContext: func(
			context.Context, string, string,
		) (net.Conn, error) {
			return nil, errors.New("unreachable")
		}}
		if err := dialer.UseSuppliedSocket(conn); !errors.Is(
			err, ErrSuppliedSocketConflict,
		) {
			t.Fatalf("conflicting configuration accepted: %v", err)
		}
	})

	t.Run("hostname endpoints are refused", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		supplied, err := NewSuppliedStreamSocket(conn)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := supplied.take("tcp", "gateway.example:443"); !errors.Is(
			err, ErrSuppliedSocketEndpoint,
		) {
			t.Fatalf("hostname endpoint accepted: %v", err)
		}
		if supplied.Taken() {
			t.Fatal("a refused take consumed the socket")
		}
	})

	t.Run("peer mismatch is refused", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		supplied, err := NewSuppliedStreamSocket(conn)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := supplied.take("tcp", "127.0.0.1:1"); !errors.Is(
			err, ErrSuppliedSocketPeer,
		) {
			t.Fatalf("mismatched peer accepted: %v", err)
		}
	})

	t.Run("an unused supplied socket is closed by Close", func(t *testing.T) {
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		supplied, err := NewSuppliedPacketSocket(socket)
		if err != nil {
			t.Fatal(err)
		}
		if err := supplied.Close(); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 1)
		if _, _, err := socket.ReadFrom(buffer); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("socket still open after Close: %v", err)
		}
		// Close after a take must not touch the socket the carrier now owns.
		second, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer second.Close()
		owned, err := NewSuppliedPacketSocket(second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owned.take(); err != nil {
			t.Fatal(err)
		}
		if err := owned.Close(); err != nil {
			t.Fatal(err)
		}
		if err := second.SetReadDeadline(time.Now()); err != nil {
			t.Fatalf("Close after take closed the carrier's socket: %v", err)
		}
	})
}
