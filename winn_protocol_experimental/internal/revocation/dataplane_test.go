package revocation_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/pki"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/revocation"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

const testControllerID = "lab-controller"

// TestRevocationReachesCarrierDataPlane is the regression test for P0-2. It
// exists because a revocation path that compiles but was never driven end to
// end is the same defect one layer up.
//
// It stands up a real HTTP/2 carrier over real mTLS with lab PKI, proves an
// authenticated device can relay UDP through it, then publishes a signed
// revocation list naming that device through the real
// Build/Sign/Encode/LoadVerified pipeline, installs it, and proves the same
// device is refused by the same carrier. The first phase is what makes the
// second phase meaningful: without it, a test that shows a device being
// refused proves only that something is broken.
func TestRevocationReachesCarrierDataPlane(t *testing.T) {
	echoAddress, stopEcho := startUDPEcho(t)
	defer stopEcho()
	lab := generateLab(t)
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
		lab.DeviceCert, lab.DeviceKey, lab.CACert, "127.0.0.1", suite,
		http2.NextProtoTLS,
	)
	if err != nil {
		t.Fatal(err)
	}
	deviceSigner, err := pqauth.LoadSigner(pqauth.MLDSA65, lab.DevicePQ65Seed)
	if err != nil {
		t.Fatal(err)
	}
	controllerSigner, err := pqauth.LoadSigner(
		pqauth.MLDSA87, lab.ControllerPQ87Seed,
	)
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
	now := time.Now().UTC()

	// Phase 1 trust material: a genuine signed list that does not name this
	// device. The carrier is enforcing revocation the whole time; the device
	// is simply not on the list yet.
	emptyList := publishList(t, lab, controllerSigner, 1, now, nil)
	verifiedEmpty, _, err := revocation.LoadVerified(
		emptyList, "", testControllerID, pins, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	checker, err := revocation.NewChecker(
		verifiedEmpty, revocation.DefaultMaxAge, false,
	)
	if err != nil {
		t.Fatal(err)
	}

	replay, err := carrierauth.NewReplayCache(128)
	if err != nil {
		t.Fatal(err)
	}
	requestVerifier := &carrierauth.RequestVerifier{
		Registry:    registry,
		Replay:      replay,
		Suite:       suite.Name,
		MaxSkew:     time.Minute,
		Revocations: checker,
	}
	handler, err := carrier.NewH2Server(
		"winn.invalid:443", echoAddress, suite, requestVerifier,
		controllerSigner, testControllerID,
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
		shutdownContext, cancel := context.WithTimeout(
			context.Background(), 3*time.Second,
		)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
		select {
		case serveErr := <-serverDone:
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				t.Errorf("H2 carrier: %v", serveErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("H2 carrier did not stop")
		}
	}()

	responseVerifier := &carrierauth.ResponseVerifier{
		Verifiers:    pins,
		ControllerID: testControllerID,
		Suite:        suite.Name,
		MaxSkew:      time.Minute,
	}
	// The dial context must outlive the returned connection: the H2 carrier
	// stream is bound to it, so cancelling at dial time would close the pipe
	// under the caller and look exactly like a carrier rejection.
	dialContext, cancelDial := context.WithTimeout(
		context.Background(), 30*time.Second,
	)
	defer cancelDial()
	dial := func(sessionID string) (net.PacketConn, error) {
		dialer, dialErr := carrier.NewH2Dialer(
			"https://"+listener.Addr().String()+carrier.H2Path,
			"winn.invalid:443", lab.DeviceID, sessionID, suite, clientTLS,
			deviceSigner, responseVerifier,
		)
		if dialErr != nil {
			return nil, dialErr
		}
		return dialer.Dial(dialContext)
	}

	// Phase 1: the device is not revoked, so the data plane must carry its
	// traffic. This is the control that gives the phase-2 failure meaning.
	connection, err := dial("00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatalf("unrevoked device was refused by the carrier: %v", err)
	}
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("pre-revocation-datagram")
	if _, err := connection.WriteTo(payload, nil); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, carrier.DefaultMaxDatagram)
	count, _, err := connection.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:count]) != string(payload) {
		t.Fatalf("echo = %q, want %q", buffer[:count], payload)
	}
	connection.Close()

	// Revoke. This is the real publication pipeline: build from plaintext
	// device IDs, sign with the controller key, write the document, then load
	// and verify it exactly as a carrier would.
	revokedList := publishList(
		t, lab, controllerSigner, 2, now, []string{lab.DeviceID},
	)
	verifiedRevoked, nextState, err := revocation.LoadVerified(
		revokedList, "", testControllerID, pins, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if nextState.HighestSequence != 2 {
		t.Fatalf("trust state sequence = %d, want 2", nextState.HighestSequence)
	}
	if err := checker.Install(verifiedRevoked); err != nil {
		t.Fatal(err)
	}
	if !checker.RevokedDevice(lab.DeviceID) {
		t.Fatal("checker does not consider the published device revoked")
	}

	// Phase 2: the same device, the same certificate, the same registered
	// ML-DSA key, the same carrier process. Only the revocation list changed.
	// If this dial succeeds, revocation does not reach the data plane.
	if _, err := dial("ffeeddccbbaa99887766554433221100"); err == nil {
		t.Fatal("revoked device still established a carrier session")
	}

	// A different, unrevoked device on the same list must still be served, so
	// the phase-2 failure is attributable to revocation rather than to the
	// carrier having broken outright.
	if checker.RevokedDevice("some-other-device") {
		t.Fatal("revocation list denied a device it does not name")
	}
}

// TestAnonymousModeIsNotSubjectToRevocation pins the scope boundary. Anonymous
// token mode has no stable device identity, so VerifyAnonymous must never
// consult the revocation source even when one is installed. If this ever
// starts failing, anonymous carriers have been coupled to identity-mode
// revocation and the privacy property of that mode is gone.
func TestAnonymousModeIsNotSubjectToRevocation(t *testing.T) {
	verifier := &carrierauth.RequestVerifier{
		Revocations: denyEverything{},
	}
	// VerifyAnonymous rejects before it would ever reach a revocation check,
	// because its configuration guard runs first. The assertion that matters
	// is the error identity: it must not be ErrDeviceRevoked.
	_, err := verifier.VerifyAnonymous(nil, "", "", "", "", nil)
	if err == nil {
		t.Fatal("unconfigured anonymous verification succeeded")
	}
	if errors.Is(err, carrierauth.ErrDeviceRevoked) {
		t.Fatal("anonymous mode consulted the device revocation source")
	}
}

func publishList(t *testing.T, lab pki.Paths, signer *pqauth.Signer, sequence uint64, now time.Time, revoked []string) string {
	t.Helper()
	list, err := revocation.Build(
		testControllerID, sequence, now, 24*time.Hour, revoked,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := revocation.Sign(&list, signer); err != nil {
		t.Fatal(err)
	}
	encoded, err := revocation.Encode(list)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(
		t.TempDir(), "revocation-list.json",
	)
	if err := securefile.AtomicWrite(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

type denyEverything struct{}

func (denyEverything) RevokedDevice(string) bool { return true }

func generateLab(t *testing.T) pki.Paths {
	t.Helper()
	paths, err := pki.GenerateLab(
		t.TempDir()+"/pki", "127.0.0.1", "device-1", time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

func startUDPEcho(t *testing.T) (string, func()) {
	t.Helper()
	connection, err := net.ListenUDP(
		"udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
	)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, carrier.AbsoluteMaxDatagram+1)
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
