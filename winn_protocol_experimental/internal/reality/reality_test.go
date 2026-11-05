package reality_test

// These tests measure what a real prober and a real Winn client each get
// from a reality.Listen-wrapped listener, against fixtures built the same
// way cmd/winn-carrier-server builds its own: internal/pki.GenerateLab for
// the Winn side (server, device, ECH material - the same generator
// internal/echconfig's and internal/carrier's own integration tests use),
// plus a separately-issued cover certificate and a separately-issued "real
// third party" certificate, exactly mirroring the three distinct identities
// a real deployment has: the Winn leaf, the operator's own cover
// certificate, and a real site this deployment does not control.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/coverlisten"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/pki"
	"winsvpn.local/winnprotocol/internal/reality"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

const (
	privateServerName    = "gateway-reality-test.winn.invalid"
	coverServerName      = "www.example.com"
	thirdPartyServerName = "thirdparty.example.net"
	testTimeout          = 15 * time.Second
	thirdPartyBody       = "hello from the real third party, not from Winn"
)

// fixture is the three-identity setup every test in this file starts from.
type fixture struct {
	coverConfig *tls.Config // what coverlisten.Apply/Verify built - the listener configuration under test

	winnClientConfig *tls.Config // a genuine, fully-provisioned Winn client
	winnLeaf         *x509.Certificate

	coverLeaf *x509.Certificate

	thirdPartyListener net.Listener
	thirdPartyLeaf     *x509.Certificate
	thirdPartyCAPool   *x509.CertPool
}

func buildFixture(t *testing.T) *fixture {
	t.Helper()

	lab, err := pki.GenerateLab(
		filepath.Join(t.TempDir(), "pki"), privateServerName,
		"reality-test-device-1", time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("pki.GenerateLab: %v", err)
	}
	suite, err := tlsconfig.ParseSuite("x25519-mlkem768")
	if err != nil {
		t.Fatalf("ParseSuite: %v", err)
	}
	winnServerTLS, err := tlsconfig.ServerForALPN(
		lab.ServerCert, lab.ServerKey, lab.CACert, suite, "h2",
	)
	if err != nil {
		t.Fatalf("ServerForALPN: %v", err)
	}
	echKeys, err := echconfig.LoadServerKeys(lab.ECHServerKeys)
	if err != nil {
		t.Fatalf("LoadServerKeys: %v", err)
	}
	if err := echconfig.ConfigureServer(winnServerTLS, echKeys, true); err != nil {
		t.Fatalf("ConfigureServer: %v", err)
	}
	winnLeaf := parseCertFile(t, lab.ServerCert)

	clientTLS, err := tlsconfig.ClientForALPN(
		lab.DeviceCert, lab.DeviceKey, lab.CACert, privateServerName, suite, "h2",
	)
	if err != nil {
		t.Fatalf("ClientForALPN: %v", err)
	}
	configList, err := echconfig.LoadClientConfigList(lab.ECHConfigList)
	if err != nil {
		t.Fatalf("LoadClientConfigList: %v", err)
	}
	if err := echconfig.ConfigureClient(clientTLS, configList, true); err != nil {
		t.Fatalf("ConfigureClient: %v", err)
	}

	coverCA, coverCAKey := newCA(t, "Reality Test Cover Issuer")
	coverLeafCert := newLeaf(t, coverCA, coverCAKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: coverServerName},
		DNSNames:    []string{coverServerName},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	coverCertPath, coverKeyPath := writeCertAndKey(t, "cover", coverLeafCert)

	coverListener, err := coverlisten.Apply(coverlisten.Options{
		Winn:                      winnServerTLS,
		CoverALPN:                 []string{"h2", "http/1.1"},
		CoverCertPath:             coverCertPath,
		CoverKeyPath:              coverKeyPath,
		ECHKeys:                   echKeys,
		RequestsClientCertificate: true,
		Logf:                      t.Logf,
	})
	if err != nil {
		t.Fatalf("coverlisten.Apply: %v", err)
	}
	if err := coverlisten.Verify(coverListener.TLS); err != nil {
		t.Fatalf("coverlisten.Verify: %v", err)
	}

	thirdPartyCA, thirdPartyCAKey := newCA(t, "Reality Test Third Party Issuer")
	thirdPartyLeafCert := newLeaf(t, thirdPartyCA, thirdPartyCAKey, &x509.Certificate{
		Subject:  pkix.Name{CommonName: thirdPartyServerName},
		DNSNames: []string{thirdPartyServerName},
		// The IP SAN is a test-fixture concession, not a "real site" shape:
		// this fixture is reached over loopback, and Target.Validate's own
		// tests need a ServerName that verification can actually match. The
		// DNS name above is what TestListenUnauthenticatedProberReceivesThe...
		// cares about; InsecureSkipVerify there means this SAN is unused on
		// that path.
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	thirdPartyPool := x509.NewCertPool()
	thirdPartyPool.AddCert(thirdPartyCA)
	thirdPartyLeaf, err := x509.ParseCertificate(thirdPartyLeafCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse third party leaf: %v", err)
	}

	return &fixture{
		coverConfig:        coverListener.TLS,
		winnClientConfig:   clientTLS,
		winnLeaf:           winnLeaf,
		coverLeaf:          parseCertFile(t, coverCertPath),
		thirdPartyListener: startThirdPartyServer(t, thirdPartyLeafCert),
		thirdPartyLeaf:     thirdPartyLeaf,
		thirdPartyCAPool:   thirdPartyPool,
	}
}

// listenReality wraps a fresh loopback listener with the fixture's cover
// configuration and its third-party server as the relay target - exactly
// the shape cmd/winn-carrier-server builds when -reality-relay-target is
// set.
func listenReality(t *testing.T, f *fixture, onOutcome func(string)) net.Listener {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if onOutcome == nil {
		onOutcome = func(string) {}
	}
	wrapped, err := reality.Listen(inner, reality.Options{
		Cover: f.coverConfig,
		Target: reality.Target{
			Address:     f.thirdPartyListener.Addr().String(),
			DialTimeout: 3 * time.Second,
		},
		HandshakeTimeout: testTimeout,
		Logf:             t.Logf,
		OnOutcome:        onOutcome,
	})
	if err != nil {
		t.Fatalf("reality.Listen: %v", err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })
	return wrapped
}

// ---------------------------------------------------------------------------
// An authenticated client still connects.
// ---------------------------------------------------------------------------

func TestListenAuthenticatedClientStillConnects(t *testing.T) {
	f := buildFixture(t)
	var outcomes []string
	var mu sync.Mutex
	relayListener := listenReality(t, f, func(outcome string) {
		mu.Lock()
		outcomes = append(outcomes, outcome)
		mu.Unlock()
	})

	serverDone := make(chan error, 1)
	go func() {
		conn, err := relayListener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			serverDone <- fmt.Errorf("accepted connection is %T, not *tls.Conn", conn)
			return
		}
		// net/http's own conn.serve would call exactly this, on an
		// already-complete handshake, before ever reading a request. Prove
		// that really is Go's documented no-op in this setting, not just
		// assume it.
		if err := tlsConn.HandshakeContext(context.Background()); err != nil {
			serverDone <- fmt.Errorf("second HandshakeContext call: %w", err)
			return
		}
		if _, err := tlsConn.Write([]byte("ok")); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	clientConn, err := net.DialTimeout("tcp", relayListener.Addr().String(), testTimeout)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()
	_ = clientConn.SetDeadline(time.Now().Add(testTimeout))
	tlsClient := tls.Client(clientConn, f.winnClientConfig)
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("genuine Winn client handshake failed: %v", err)
	}
	state := tlsClient.ConnectionState()
	if !state.ECHAccepted {
		t.Fatal("expected ECH to be accepted for a genuine Winn client")
	}
	if len(state.PeerCertificates) == 0 || !state.PeerCertificates[0].Equal(f.winnLeaf) {
		t.Fatalf("expected the Winn leaf certificate, got %+v", state.PeerCertificates)
	}
	buffer := make([]byte, 2)
	if _, err := io.ReadFull(tlsClient, buffer); err != nil {
		t.Fatalf("read from server: %v", err)
	}
	if string(buffer) != "ok" {
		t.Fatalf("unexpected payload %q", buffer)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server side: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(outcomes) != 0 {
		t.Fatalf("expected no OnOutcome calls for a genuine Winn connection, got %v", outcomes)
	}
}

// ---------------------------------------------------------------------------
// An unauthenticated prober receives the relayed genuine handshake.
// ---------------------------------------------------------------------------

func TestListenUnauthenticatedProberReceivesTheRelayedGenuineHandshake(t *testing.T) {
	f := buildFixture(t)
	outcomeCh := make(chan string, 1)
	relayListener := listenReality(t, f, func(outcome string) {
		outcomeCh <- outcome
	})
	acceptedAnything := make(chan struct{}, 1)
	go func() {
		// A relayed connection must never reach Accept. If anything ever
		// does during this test, that is itself the failure - record it
		// rather than let it block forever.
		conn, err := relayListener.Accept()
		if err == nil {
			_ = conn.Close()
			acceptedAnything <- struct{}{}
		}
	}()

	// An ordinary prober - a plain TLS client, exactly what a censor's
	// generic active-probing tooling and a curious human both actually use
	// in practice, per the research this feature is built against (see
	// docs/handoff). It offers no ECH extension at all, so
	// internal/coverlisten's own classification cannot even attempt to find
	// a Winn client here - internal/tlsconfig.ApplyCoverProfile's own tests
	// (cover_test.go, clienthello_test.go) already prove that classification
	// decision in isolation; this test's job is to prove what THIS package
	// does once that decision comes back negative.
	proberConfig := &tls.Config{
		ServerName:         coverServerName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	conn, err := net.DialTimeout("tcp", relayListener.Addr().String(), testTimeout)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(testTimeout))
	tlsConn := tls.Client(conn, proberConfig)
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("prober handshake with the relayed connection failed: %v", err)
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("expected a certificate from the relay target")
	}
	got := state.PeerCertificates[0]
	if !got.Equal(f.thirdPartyLeaf) {
		t.Fatalf(
			"prober received a certificate for %q issued by %q; expected "+
				"the real third party's own certificate for %q issued by "+
				"%q - anything else means this deployment presented some "+
				"identity of its own to an unauthenticated peer",
			got.Subject, got.Issuer,
			f.thirdPartyLeaf.Subject, f.thirdPartyLeaf.Issuer,
		)
	}
	if got.Equal(f.coverLeaf) {
		t.Fatal("prober received the operator's own cover certificate instead of a relay")
	}
	if got.Equal(f.winnLeaf) {
		t.Fatal("prober received the Winn leaf certificate")
	}

	// The splice must keep working after the handshake too, not just forward
	// it: issue a real request and read the real target's real response back
	// over the same connection.
	request, err := http.NewRequest(http.MethodGet, "https://"+thirdPartyServerName+"/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if err := request.Write(tlsConn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(tlsConn), request)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != thirdPartyBody {
		t.Fatalf("unexpected body %q, want %q", body, thirdPartyBody)
	}

	select {
	case <-acceptedAnything:
		t.Fatal("a relayed connection was delivered to Accept")
	default:
	}

	// Close this end now: the relay target's response above was read to a
	// Content-Length boundary, which does not itself wait for the
	// connection to close, and the relay's own byte pump (server side)
	// needs both directions to finish - including this one - before it
	// reports an outcome. A real client that received "Connection: close"
	// would close its own side at this point too.
	_ = conn.Close()
	select {
	case outcome := <-outcomeCh:
		if outcome != reality.OutcomeRelayed {
			t.Fatalf("expected outcome %q, got %q", reality.OutcomeRelayed, outcome)
		}
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for OnOutcome")
	}
}

// ---------------------------------------------------------------------------
// A misconfigured target fails closed.
// ---------------------------------------------------------------------------

func TestTargetValidateFailsClosed(t *testing.T) {
	t.Run("empty address", func(t *testing.T) {
		if err := (reality.Target{}).Validate(context.Background()); err == nil {
			t.Fatal("expected Validate to refuse an empty address")
		}
	})

	t.Run("unreachable", func(t *testing.T) {
		probe, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		address := probe.Addr().String()
		_ = probe.Close() // freed; nothing should be listening for the dial below

		target := reality.Target{Address: address, DialTimeout: 2 * time.Second}
		if err := target.Validate(context.Background()); err == nil {
			t.Fatal("expected Validate to fail against an unreachable address")
		}
	})

	t.Run("accepts TCP but never speaks TLS", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer listener.Close()
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = conn.Write([]byte("not a TLS server\n"))
		}()
		target := reality.Target{Address: listener.Addr().String(), DialTimeout: 2 * time.Second}
		if err := target.Validate(context.Background()); err == nil {
			t.Fatal("expected Validate to fail against a listener that never speaks TLS")
		}
	})

	t.Run("certificate not verifiable by this process", func(t *testing.T) {
		f := buildFixture(t)
		// Deliberately no RootCAs override: the fixture's third party is
		// signed by a locally-generated test CA nothing trusts by default,
		// exactly like a self-signed or misissued certificate would be in
		// production.
		target := reality.Target{
			Address:     f.thirdPartyListener.Addr().String(),
			DialTimeout: 2 * time.Second,
		}
		if err := target.Validate(context.Background()); err == nil {
			t.Fatal("expected Validate to fail without a trust anchor for the target's issuer")
		}
	})

	t.Run("a real, verifiable target succeeds", func(t *testing.T) {
		f := buildFixture(t)
		target := reality.Target{
			Address:     f.thirdPartyListener.Addr().String(),
			DialTimeout: 2 * time.Second,
			RootCAs:     f.thirdPartyCAPool,
		}
		if err := target.Validate(context.Background()); err != nil {
			t.Fatalf("expected Validate to succeed against a real, verifiable target: %v", err)
		}
	})
}

func TestListenRefusesIncompleteConfiguration(t *testing.T) {
	f := buildFixture(t)

	newInner := func(t *testing.T) net.Listener {
		t.Helper()
		inner, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { _ = inner.Close() })
		return inner
	}

	t.Run("empty target", func(t *testing.T) {
		if _, err := reality.Listen(newInner(t), reality.Options{
			Cover: f.coverConfig,
		}); err == nil {
			t.Fatal("expected Listen to refuse an empty target")
		}
	})

	t.Run("nil cover configuration", func(t *testing.T) {
		if _, err := reality.Listen(newInner(t), reality.Options{
			Target: reality.Target{Address: f.thirdPartyListener.Addr().String()},
		}); err == nil {
			t.Fatal("expected Listen to refuse a nil Cover configuration")
		}
	})

	t.Run("nil inner listener", func(t *testing.T) {
		if _, err := reality.Listen(nil, reality.Options{
			Cover:  f.coverConfig,
			Target: reality.Target{Address: f.thirdPartyListener.Addr().String()},
		}); err == nil {
			t.Fatal("expected Listen to refuse a nil inner listener")
		}
	})
}

// ---------------------------------------------------------------------------
// Fixture plumbing.
// ---------------------------------------------------------------------------

func parseCertFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("no PEM block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate in %s: %v", path, err)
	}
	return cert
}

func newCA(t *testing.T, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CA cert: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return parsed, key
}

func newLeaf(
	t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey,
	template *x509.Certificate,
) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	template.SerialNumber = big.NewInt(time.Now().UnixNano())
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(24 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der, issuer.Raw}, PrivateKey: key}
}

// writeCertAndKey writes certificate an EC private key as PEM files, the
// shape tlsconfig.LoadCoverCertificate (via coverlisten.Apply) reads from
// disk.
func writeCertAndKey(t *testing.T, label string, certificate tls.Certificate) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	var chain []byte
	for _, der := range certificate.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	certPath = filepath.Join(dir, label+".crt")
	if err := os.WriteFile(certPath, chain, 0o600); err != nil {
		t.Fatalf("write %s certificate: %v", label, err)
	}
	ecKey, ok := certificate.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("%s private key is not ECDSA", label)
	}
	keyDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal %s key: %v", label, err)
	}
	keyPath = filepath.Join(dir, label+".key")
	if err := os.WriteFile(
		keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600,
	); err != nil {
		t.Fatalf("write %s key: %v", label, err)
	}
	return certPath, keyPath
}

// startThirdPartyServer runs a minimal, independent TLS+HTTP server standing
// in for "a real site this deployment does not control." It is deliberately
// not built from any Winn or coverlisten machinery.
func startThirdPartyServer(t *testing.T, leaf tls.Certificate) net.Listener {
	t.Helper()
	config := &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS12,
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen (third party fixture): %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				serveThirdPartyConnection(conn, config)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		wg.Wait()
	})
	return listener
}

func serveThirdPartyConnection(conn net.Conn, config *tls.Config) {
	tlsConn := tls.Server(conn, config)
	_ = tlsConn.SetDeadline(time.Now().Add(testTimeout))
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	reader := bufio.NewReader(tlsConn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		// A bare TLS-only probe (this file's "misconfigured target" cases,
		// and TestListenAuthenticatedClientStillConnects's Winn path, which
		// never reaches this server at all) sends no request; there is
		// nothing further to serve.
		return
	}
	_ = request.Body.Close()
	body := thirdPartyBody
	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: " + fmt.Sprint(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" + body
	_, _ = tlsConn.Write([]byte(response))
}

// ---------------------------------------------------------------------------
// A connection already committed to the Winn profile is never relayed.
// ---------------------------------------------------------------------------

// A peer that reaches the Winn profile (genuine ECH, private inner name) but
// then fails the handshake - here, no client certificate - has already been
// sent the Winn ServerHello. Relaying it afterwards would splice a dead Winn
// stream onto the third party and dial that party for nothing.
func TestListenDoesNotRelayAFailedWinnHandshake(t *testing.T) {
	f := buildFixture(t)
	spy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen spy target: %v", err)
	}
	t.Cleanup(func() { _ = spy.Close() })
	spyHits := make(chan struct{}, 4)
	go func() {
		for {
			conn, err := spy.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
			spyHits <- struct{}{}
		}
	}()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	outcomes := make(chan string, 4)
	wrapped, err := reality.Listen(inner, reality.Options{
		Cover:            f.coverConfig,
		Target:           reality.Target{Address: spy.Addr().String(), DialTimeout: 3 * time.Second},
		HandshakeTimeout: testTimeout,
		Logf:             t.Logf,
		OnOutcome:        func(outcome string) { outcomes <- outcome },
	})
	if err != nil {
		t.Fatalf("reality.Listen: %v", err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })

	noCert := f.winnClientConfig.Clone()
	noCert.Certificates = nil
	noCert.GetClientCertificate = nil
	conn, err := net.DialTimeout("tcp", wrapped.Addr().String(), testTimeout)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(testTimeout))
	client := tls.Client(conn, noCert)
	handshakeErr := client.Handshake()
	if handshakeErr == nil {
		// TLS 1.3: the client finishes before the server rejects the empty
		// certificate; the rejection arrives on the first read.
		var one [1]byte
		if _, readErr := client.Read(one[:]); readErr == nil {
			t.Fatal("a Winn client without a certificate was served")
		}
	} else if client.ConnectionState().ECHAccepted {
		t.Logf("handshake failed as expected: %v", handshakeErr)
	}
	// The server side has finished with the connection by the time the
	// client sees it end, so a relay dial (if any) has already happened.
	select {
	case <-spyHits:
		t.Fatal("the relay target was dialed for a connection committed to the Winn profile")
	case outcome := <-outcomes:
		t.Fatalf("unexpected relay outcome %q for a failed Winn handshake", outcome)
	case <-time.After(500 * time.Millisecond):
	}
}

// noHalfCloseListener hands out connections that, like the production
// wrappers under this listener (decoy's prefixConn, connlimit's countedConn),
// embed net.Conn as an interface and so do not expose CloseWrite.
type noHalfCloseListener struct{ net.Listener }

func (l noHalfCloseListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return struct{ net.Conn }{conn}, nil
}

// A relay that ran to completion is OutcomeRelayed even when the client side
// cannot half-close, which is the production shape; OutcomeRelayFailed is
// reserved for a target that could not be reached.
func TestListenCompletedRelayIsNotReportedAsFailedWithoutHalfClose(t *testing.T) {
	f := buildFixture(t)
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	outcomes := make(chan string, 1)
	wrapped, err := reality.Listen(noHalfCloseListener{inner}, reality.Options{
		Cover: f.coverConfig,
		Target: reality.Target{
			Address:     f.thirdPartyListener.Addr().String(),
			DialTimeout: 3 * time.Second,
		},
		HandshakeTimeout: testTimeout,
		Logf:             t.Logf,
		OnOutcome:        func(outcome string) { outcomes <- outcome },
	})
	if err != nil {
		t.Fatalf("reality.Listen: %v", err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })

	conn, err := net.DialTimeout("tcp", wrapped.Addr().String(), testTimeout)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(testTimeout))
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         coverServerName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("prober handshake: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://"+thirdPartyServerName+"/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if err := request.Write(tlsConn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(tlsConn), request)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	// The client deliberately stays open: the target closing is what ends
	// this relay.
	select {
	case outcome := <-outcomes:
		if outcome != reality.OutcomeRelayed {
			t.Fatalf("outcome = %q, want %q", outcome, reality.OutcomeRelayed)
		}
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for OnOutcome")
	}
}
