package carrier

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/pki"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

func TestAuthenticatedH3ConnectUDPEndToEnd(t *testing.T) {
	if raceEnabled() {
		// quic-go v0.60.0 has an upstream data race (switchToNewPath vs
		// http3 ConnectionState) that -race flags on this exercise; the
		// library, not Winn, is the writer. Tracked upstream; do not hide
		// production -race runs behind a skip.
		t.Skip("upstream quic-go v0.60.0 race: switchToNewPath vs http3 ConnectionState")
	}
	echoAddress, stopEcho := startUDPEcho(t)
	defer stopEcho()

	lab := generateCarrierLab(t)
	suite, err := tlsconfig.ParseSuite("x25519-mlkem768")
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := tlsconfig.ServerAnonymousForALPN(
		lab.ServerCert, lab.ServerKey, suite, http3.NextProtoH3,
	)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := tlsconfig.ClientAnonymousForALPN(
		lab.CACert, "127.0.0.1", suite, http3.NextProtoH3,
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
	issuer, err := privacytoken.GenerateIssuerKey(3072)
	if err != nil {
		t.Fatal(err)
	}
	controllerPins, err := pqauth.LoadVerifierSet(lab.ControllerPQPins)
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
	requestVerifier := &carrierauth.RequestVerifier{
		Replay:  replay,
		Suite:   suite.Name,
		MaxSkew: time.Minute,
	}
	handler, err := NewH3Server(
		template,
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
	var backendDials atomic.Int32
	handler.DialBackend = func(
		_ context.Context,
		address *net.UDPAddr,
	) (*net.UDPConn, error) {
		backendDials.Add(1)
		return net.DialUDP("udp", nil, address)
	}
	redemptions, err := privacytoken.NewRedemptionCache(128)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	handler.PrivacyTokens = &PrivacyTokenVerifier{
		PublicKey:   &issuer.PublicKey,
		KeyID:       mustIssuerKeyID(t, &issuer.PublicKey),
		NotBefore:   now.Add(-time.Minute),
		NotAfter:    now.Add(time.Hour),
		Redemptions: redemptions,
		LabMode:     true,
	}
	defer handler.Close()
	server := &http3.Server{
		TLSConfig:       serverTLS,
		Handler:         handler,
		EnableDatagrams: true,
		QUICConfig: &quic.Config{
			EnableDatagrams: true,
			Allow0RTT:       false,
			InitialPacketSize: H3InitialPacketSize(
				handler.MaxDatagram + envelopeHeaderSize,
			),
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       20 * time.Second,
		},
	}
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.Serve(packetListener)
	}()
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

	responseVerifier := &carrierauth.ResponseVerifier{
		Verifiers:    controllerPins,
		ControllerID: "lab-controller",
		Suite:        suite.Name,
		MaxSkew:      time.Minute,
	}
	dialer, err := NewH3Dialer(
		template,
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
	dialer.AuthorizationMode = carrierauth.AuthModeAnonymousToken
	dialer.DeviceID = ""
	dialer.DeviceSigner = nil
	anonymousCredentials := &queuedAnonymousCredentialSource{
		credentials: []AnonymousCredential{
			newAnonymousCredential(t, issuer),
			newAnonymousCredential(t, issuer),
		},
	}
	dialer.AnonymousCredentials = anonymousCredentials
	var capacityChecks atomic.Int32
	dialer.confirmCapacity = func(
		confirmer DatagramCapacityConfirmer,
	) (int, error) {
		capacityChecks.Add(1)
		return confirmer.ConfirmDatagramCapacity()
	}
	var customDialUsed atomic.Bool
	dialer.DialQUICPath = func(ctx context.Context, address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, *quic.Transport, error) {
		customDialUsed.Store(true)
		return dialMigratableQUIC(ctx, address, tlsConfig, quicConfig)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	prepared, err := dialer.PrepareH3Path(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if !customDialUsed.Load() {
		t.Fatal("injected QUIC underlay dialer was not used")
	}
	if !prepared.Ready() {
		t.Fatal("prepared QUIC/TLS path is not live")
	}
	if replay.Len(time.Now()) != 0 {
		t.Fatal("H3 prewarm consumed click-time authentication")
	}
	if err := dialer.AuthenticatePreparedH3Path(ctx, prepared); err != nil {
		t.Fatal(err)
	}
	if !prepared.Authenticated() {
		t.Fatal("prepared H3 path lacks authenticated CONNECT proof")
	}
	if replay.Len(time.Now()) != 1 {
		t.Fatal("prepared H3 authentication was not recorded exactly once")
	}
	if calls := capacityChecks.Load(); calls != 0 {
		t.Fatalf(
			"preparatory authenticated CONNECT ran %d envelope capacity checks; want 0",
			calls,
		)
	}
	if calls := backendDials.Load(); calls != 0 {
		t.Fatalf(
			"authentication-only preparation allocated %d backend sockets; want 0",
			calls,
		)
	}
	connection, err := dialer.DialPrepared(ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if calls := capacityChecks.Load(); calls != 1 {
		t.Fatalf(
			"click DialPrepared ran %d envelope capacity checks; want 1", calls,
		)
	}
	if calls := backendDials.Load(); calls != 1 {
		t.Fatalf(
			"click-time data CONNECT allocated %d backend sockets; want 1",
			calls,
		)
	}
	if calls := anonymousCredentials.calls.Load(); calls != 2 {
		t.Fatalf(
			"preparatory and click CONNECT requests consumed %d anonymous credentials; want 2",
			calls,
		)
	}
	if prepared.Ready() {
		t.Fatal("consumed prepared path still reports ready")
	}
	credentialSource := &countingCredentialSource{}
	dialer.AuthorizationMode = carrierauth.AuthModeAnonymousToken
	dialer.AnonymousCredentials = credentialSource
	if _, err := dialer.DialPrepared(ctx, prepared); err == nil {
		t.Fatal("second click unexpectedly reused a prepared path")
	}
	if credentialSource.calls.Load() != 0 {
		t.Fatal("rejected second click consumed an anonymous credential")
	}
	defer connection.Close()
	migrator, ok := connection.(PathMigrator)
	if !ok {
		t.Fatal("HTTP/3 carrier does not expose in-place QUIC migration")
	}
	replacementSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	migrationContext, cancelMigration := context.WithTimeout(ctx, 8*time.Second)
	if err := migrator.MigratePath(migrationContext, replacementSocket); err != nil {
		cancelMigration()
		t.Fatalf("migrate live QUIC connection: %v", err)
	}
	cancelMigration()
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("authenticated-awg-datagram")
	if written, err := connection.WriteTo(payload, nil); err != nil {
		t.Fatal(err)
	} else if written != len(payload) {
		t.Fatalf("wrote %d bytes, want %d", written, len(payload))
	}
	buffer := make([]byte, DefaultMaxDatagram)
	read, _, err := connection.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:read]) != string(payload) {
		t.Fatalf("echo %q, want %q", buffer[:read], payload)
	}
	if replay.Len(time.Now()) != 2 {
		t.Fatal("prepared and click-time request nonces were not recorded")
	}

	// A second authenticated preparation must succeed even when its click-time
	// envelope capacity check is configured to model an underlay that cannot
	// carry a full-size envelope. DialPrepared must then run that check and
	// fail before returning.
	//
	// This is the same fail-closed property the MTU probe used to pin, moved to
	// the mechanism that replaced the probe. The old wording was "DialPrepared
	// invokes the prober exactly once and fails when it errors". Preparation
	// still must not run the check, the click still must, and a click-time
	// failure still must abort rather than hand back a carrier. What changed is
	// that the check no longer puts datagrams on the wire, so its failure can
	// no longer be induced by a censor who drops one datagram size class.
	noCapacityDialer := *dialer
	noCapacityDialer.SessionID = "11223344556677889900aabbccddeeff"
	noCapacityDialer.SequenceEpoch = "ffeeddccbbaa00998877665544332211"
	noCapacityDialer.AnonymousCredentials = &queuedAnonymousCredentialSource{
		credentials: []AnonymousCredential{
			newAnonymousCredential(t, issuer),
			newAnonymousCredential(t, issuer),
		},
	}
	tooSmall := errors.New("carrier underlay cannot carry a full-size envelope")
	var noCapacityChecks atomic.Int32
	noCapacityDialer.confirmCapacity = func(
		DatagramCapacityConfirmer,
	) (int, error) {
		noCapacityChecks.Add(1)
		return 0, tooSmall
	}
	noCapacityPrepared, err := noCapacityDialer.PrepareH3Path(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer noCapacityPrepared.Close()
	if err := noCapacityDialer.AuthenticatePreparedH3Path(
		ctx,
		noCapacityPrepared,
	); err != nil {
		t.Fatalf(
			"preparatory anonymous CONNECT required an envelope capacity check: %v",
			err,
		)
	}
	if calls := noCapacityChecks.Load(); calls != 0 {
		t.Fatalf(
			"preparatory authentication ran %d capacity checks; want 0", calls,
		)
	}
	if _, err := noCapacityDialer.DialPrepared(
		ctx,
		noCapacityPrepared,
	); !errors.Is(err, tooSmall) {
		t.Fatalf("click DialPrepared error = %v, want %v", err, tooSmall)
	}
	if calls := noCapacityChecks.Load(); calls != 1 {
		t.Fatalf(
			"click DialPrepared ran %d capacity checks; want 1", calls,
		)
	}
}

func TestH3ClientRejectsOversizeDatagram(t *testing.T) {
	connection := &memoryPacketConn{}
	limited, err := limitPacketConn(connection, 1200)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limited.WriteTo(make([]byte, 1201), nil); err != ErrDatagramTooLarge {
		t.Fatalf("oversize write returned %v", err)
	}
}

func TestCanceledH3AuthenticationConsumesNoCredential(t *testing.T) {
	source := &countingCredentialSource{}
	dialer := &H3Dialer{
		AuthorizationMode:    carrierauth.AuthModeAnonymousToken,
		AnonymousCredentials: source,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := dialer.newH3Authentication(
		ctx,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("newH3Authentication error = %v, want cancellation", err)
	}
	if calls := source.calls.Load(); calls != 0 {
		t.Fatalf("canceled authentication consumed %d credentials", calls)
	}
	if err := dialer.AuthenticatePreparedH3Path(
		ctx,
		nil,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf(
			"AuthenticatePreparedH3Path error = %v, want cancellation",
			err,
		)
	}
}

func TestAnonymousH3EntryPointsRejectStableTLSIdentity(t *testing.T) {
	template, err := uritemplate.New(
		"https://cover.example/.well-known/masque/udp/{target_host}/{target_port}/",
	)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &H3Dialer{
		Template:          template,
		PublicTarget:      "winn.invalid:443",
		AuthorizationMode: carrierauth.AuthModeAnonymousToken,
		TLSConfig: &tls.Config{
			Certificates:           []tls.Certificate{{}},
			SessionTicketsDisabled: true,
		},
		ResponseVerifier: &carrierauth.ResponseVerifier{},
	}
	ctx := context.Background()
	if _, err := dialer.PrepareH3Path(
		ctx,
	); err == nil || !strings.Contains(
		err.Error(),
		"stable client identity or resumption",
	) {
		t.Fatalf("PrepareH3Path anonymous-profile error = %v", err)
	}
	if _, err := dialer.Dial(
		ctx,
	); err == nil || !strings.Contains(
		err.Error(),
		"stable client identity or resumption",
	) {
		t.Fatalf("Dial anonymous-profile error = %v", err)
	}
	source := &countingCredentialSource{}
	dialer.AnonymousCredentials = source
	if _, err := dialer.newH3Authentication(
		ctx,
	); err == nil || !strings.Contains(
		err.Error(),
		"stable client identity or resumption",
	) {
		t.Fatalf("authentication anonymous-profile error = %v", err)
	}
	if calls := source.calls.Load(); calls != 0 {
		t.Fatalf("invalid anonymous profile consumed %d credentials", calls)
	}
}

func TestH3ClientDropsOversizeInboundDatagramWithoutTruncation(t *testing.T) {
	connection := &onePacketConn{packet: make([]byte, 1201)}
	limited, err := limitPacketConn(connection, 1200)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1500)
	if _, _, err := limited.ReadFrom(buffer); err != ErrDatagramTooLarge {
		t.Fatalf("oversize inbound packet returned %v", err)
	}
}

func startUDPEcho(t *testing.T) (string, func()) {
	t.Helper()
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, AbsoluteMaxDatagram+1)
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

func generateCarrierLab(t *testing.T) pki.Paths {
	t.Helper()
	paths, err := pki.GenerateLab(t.TempDir()+"/pki", "127.0.0.1", "android-lab-1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

type memoryPacketConn struct{}

type countingCredentialSource struct {
	calls atomic.Int32
}

type queuedAnonymousCredentialSource struct {
	mu          sync.Mutex
	calls       atomic.Int32
	credentials []AnonymousCredential
}

func (source *countingCredentialSource) NextAnonymousCredential() (
	AnonymousCredential,
	error,
) {
	source.calls.Add(1)
	return AnonymousCredential{}, errors.New("unexpected credential request")
}

func (source *queuedAnonymousCredentialSource) NextAnonymousCredential() (
	AnonymousCredential,
	error,
) {
	source.calls.Add(1)
	source.mu.Lock()
	defer source.mu.Unlock()
	if len(source.credentials) == 0 {
		return AnonymousCredential{}, errors.New(
			"anonymous credential queue exhausted",
		)
	}
	credential := source.credentials[0]
	source.credentials[0] = AnonymousCredential{}
	source.credentials = source.credentials[1:]
	return credential, nil
}

func newAnonymousCredential(
	t *testing.T,
	issuer *rsa.PrivateKey,
) AnonymousCredential {
	t.Helper()
	bundle := issuePrivacyToken(t, issuer)
	verified, err := privacytoken.Verify(
		bundle.PublicToken(),
		&issuer.PublicKey,
		mustIssuerKeyID(t, &issuer.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := bundle.Signer()
	if err != nil {
		t.Fatal(err)
	}
	return AnonymousCredential{
		Pseudonym: verified.Pseudonym,
		Signer:    signer,
		Token:     bundle.PublicToken(),
	}
}

func (*memoryPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (*memoryPacketConn) WriteTo(packet []byte, _ net.Addr) (int, error) {
	return len(packet), nil
}
func (*memoryPacketConn) Close() error                     { return nil }
func (*memoryPacketConn) LocalAddr() net.Addr              { return fixedAddr("memory") }
func (*memoryPacketConn) SetDeadline(time.Time) error      { return nil }
func (*memoryPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryPacketConn) SetWriteDeadline(time.Time) error { return nil }

type onePacketConn struct {
	packet []byte
}

func (c *onePacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	return copy(buffer, c.packet), fixedAddr("one"), nil
}
func (*onePacketConn) WriteTo(packet []byte, _ net.Addr) (int, error) {
	return len(packet), nil
}
func (*onePacketConn) Close() error                     { return nil }
func (*onePacketConn) LocalAddr() net.Addr              { return fixedAddr("one") }
func (*onePacketConn) SetDeadline(time.Time) error      { return nil }
func (*onePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*onePacketConn) SetWriteDeadline(time.Time) error { return nil }
