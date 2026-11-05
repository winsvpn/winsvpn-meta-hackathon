package tlsconfig_test

// Tests for the client trust anchor — the change that makes CDN-fronting
// expressible for the http2-stream carrier.
//
// The bar these are written to is the one the escalation lane set: not coverage
// of the happy path, but tests that can catch a value sourced from the wrong
// place. The specific class of error that matters here is a NIL POOL, because
// nil is overloaded in crypto/tls: it means "use the system store" on a
// tls.Config, and it is also what a Go function returns alongside an error. A
// refactor that let a failed private-CA load return (nil, nil) would widen the
// trust store to the whole public WebPKI, silently, on a carrier whose entire
// purpose is to be unblockable — and every happy-path test would still pass.
// TestPrivateCAFailureNeverYieldsTheSystemPool and
// TestNilRootPoolIsReachableOnlyThroughWebPKI exist for exactly that.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/pki"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

// ---------------------------------------------------------------------------
// The anchor is stated, never inferred
// ---------------------------------------------------------------------------

func TestZeroTrustAnchorIsRefused(t *testing.T) {
	t.Parallel()
	lab := newLab(t)
	_, err := tlsconfig.ClientAnonymousTrusted(
		tlsconfig.ClientTrust{RootCAPath: lab.paths.CACert},
		lab.serverName, mustSuite(t, protocol.SuiteX25519MLKEM768), "h2",
	)
	if !errors.Is(err, tlsconfig.ErrTrustAnchorUnknown) {
		t.Fatalf("the zero ClientTrust must be refused, not defaulted: %v", err)
	}
}

func TestMisspelledTrustAnchorIsRefused(t *testing.T) {
	t.Parallel()
	lab := newLab(t)
	for _, anchor := range []tlsconfig.TrustAnchor{
		"webpki ", "WebPKI", "public", "system", "private_ca",
	} {
		_, err := tlsconfig.ClientAnonymousTrusted(
			tlsconfig.ClientTrust{Anchor: anchor},
			lab.serverName, mustSuite(t, protocol.SuiteX25519MLKEM768), "h2",
		)
		if !errors.Is(err, tlsconfig.ErrTrustAnchorUnknown) {
			t.Fatalf("anchor %q must be refused, got %v", anchor, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Private CA: unchanged, and still mandatory when selected
// ---------------------------------------------------------------------------

func TestPrivateCAStillRequiresItsPEM(t *testing.T) {
	t.Parallel()
	lab := newLab(t)
	for _, path := range []string{"", "   "} {
		_, err := tlsconfig.ClientAnonymousTrusted(
			tlsconfig.ClientTrust{Anchor: tlsconfig.TrustPrivateCA, RootCAPath: path},
			lab.serverName, mustSuite(t, protocol.SuiteX25519MLKEM768), "h2",
		)
		if !errors.Is(err, tlsconfig.ErrTrustRootCARequired) {
			t.Fatalf("private-ca with path %q must be refused, got %v", path, err)
		}
	}
}

// TestPrivateCAFailureNeverYieldsTheSystemPool is the fail-closed assertion the
// brief asks for by name: a misconfiguration must refuse rather than silently
// fall back to an unverified peer.
//
// It is written against a path that CANNOT load — a directory, a missing file,
// and a file that is not PEM — rather than only the empty string, because the
// empty string is rejected by an earlier guard. It is the LOAD failure that
// could plausibly be refactored into a fallback.
func TestPrivateCAFailureNeverYieldsTheSystemPool(t *testing.T) {
	t.Parallel()
	lab := newLab(t)
	notPEM := filepath.Join(t.TempDir(), "not-a-pem.txt")
	if err := writeFile(notPEM, []byte("this is not a certificate\n")); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"missing file": filepath.Join(t.TempDir(), "absent.pem"),
		"a directory":  t.TempDir(),
		"not PEM":      notPEM,
	} {
		config, err := tlsconfig.ClientAnonymousTrusted(
			tlsconfig.ClientTrust{
				Anchor: tlsconfig.TrustPrivateCA, RootCAPath: path,
			},
			lab.serverName, mustSuite(t, protocol.SuiteX25519MLKEM768), "h2",
		)
		if err == nil {
			t.Fatalf("%s: a private CA that will not load must be an error, "+
				"got a usable config with RootCAs=%v", name, config.RootCAs)
		}
		if config != nil {
			t.Fatalf("%s: a failed load must return no config at all, "+
				"got RootCAs=%v InsecureSkipVerify=%v",
				name, config.RootCAs, config.InsecureSkipVerify)
		}
	}
}

func TestPrivateCAProducesAPoolAndNotTheSystemStore(t *testing.T) {
	t.Parallel()
	lab := newLab(t)
	config, err := tlsconfig.ClientAnonymousTrusted(
		tlsconfig.ClientTrust{
			Anchor: tlsconfig.TrustPrivateCA, RootCAPath: lab.paths.CACert,
		},
		lab.serverName, mustSuite(t, protocol.SuiteX25519MLKEM768), "h2",
	)
	if err != nil {
		t.Fatal(err)
	}
	if config.RootCAs == nil {
		t.Fatal("private-ca must install an explicit pool; nil is the system store")
	}
}

// TestExistingConstructorsAreUnchanged pins the default-off posture: every
// caller that predates ClientTrust must still get the private-CA behaviour,
// with an identical resulting configuration.
func TestExistingConstructorsAreUnchanged(t *testing.T) {
	t.Parallel()
	lab := newLab(t)
	suite := mustSuite(t, protocol.SuiteX25519MLKEM768)

	legacy, err := tlsconfig.ClientAnonymousForALPN(
		lab.paths.CACert, lab.serverName, suite, "h2",
	)
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := tlsconfig.ClientAnonymousTrusted(
		tlsconfig.ClientTrust{
			Anchor: tlsconfig.TrustPrivateCA, RootCAPath: lab.paths.CACert,
		},
		lab.serverName, suite, "h2",
	)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.RootCAs == nil || explicit.RootCAs == nil {
		t.Fatal("both constructors must install an explicit pool")
	}
	if !legacy.RootCAs.Equal(explicit.RootCAs) {
		t.Fatal("the legacy constructor no longer produces the private pool")
	}
	if legacy.ServerName != explicit.ServerName ||
		legacy.MinVersion != explicit.MinVersion ||
		legacy.MaxVersion != explicit.MaxVersion ||
		legacy.SessionTicketsDisabled != explicit.SessionTicketsDisabled ||
		legacy.Renegotiation != explicit.Renegotiation ||
		legacy.InsecureSkipVerify != explicit.InsecureSkipVerify ||
		len(legacy.Certificates) != len(explicit.Certificates) {
		t.Fatal("the legacy and explicit private-CA configurations diverged")
	}

	// The device-certificate constructor is the one the shipped identity-mode
	// carrier uses. It must still work and must still be private-CA.
	identity, err := tlsconfig.ClientForALPN(
		lab.paths.DeviceCert, lab.paths.DeviceKey, lab.paths.CACert,
		lab.serverName, suite, "h2",
	)
	if err != nil {
		t.Fatal(err)
	}
	if identity.RootCAs == nil {
		t.Fatal("ClientForALPN must remain private-CA")
	}
	if len(identity.Certificates) != 1 {
		t.Fatalf("ClientForALPN must still present the device certificate, got %d",
			len(identity.Certificates))
	}
}

// ---------------------------------------------------------------------------
// WebPKI: the fronted path, and the four things it refuses
// ---------------------------------------------------------------------------

func TestWebPKIUsesTheSystemStore(t *testing.T) {
	t.Parallel()
	config, err := tlsconfig.ClientAnonymousTrusted(
		tlsconfig.ClientTrust{Anchor: tlsconfig.TrustWebPKI},
		"cdn.example", mustSuite(t, protocol.SuiteX25519MLKEM768), "h2",
	)
	if err != nil {
		t.Fatal(err)
	}
	if config.RootCAs != nil {
		t.Fatal("webpki must leave RootCAs nil so crypto/tls uses the system store")
	}
	if config.InsecureSkipVerify {
		t.Fatal("webpki must still VERIFY the chain; it changes the anchor, " +
			"not whether verification happens")
	}
	if config.ServerName != "cdn.example" {
		t.Fatalf("the fronting domain must be verified against, got %q",
			config.ServerName)
	}
	if len(config.Certificates) != 0 {
		t.Fatal("the fronted path must present no client certificate")
	}
}

// TestWebPKIStillEnforcesTheKeyAgreement guards a real seam. The widened
// supported_groups offer is only safe because VerifyConnection refuses
// everything it advertises but does not want (see ClientCurvePreferences). A
// second construction path that forgot to install it would advertise seven
// groups and accept any of them, which is a downgrade, not a fingerprint
// question.
func TestWebPKIStillEnforcesTheKeyAgreement(t *testing.T) {
	t.Parallel()
	suite := mustSuite(t, protocol.SuiteX25519MLKEM768)
	config, err := tlsconfig.ClientAnonymousTrusted(
		tlsconfig.ClientTrust{Anchor: tlsconfig.TrustWebPKI},
		"cdn.example", suite, "h2",
	)
	if err != nil {
		t.Fatal(err)
	}
	if config.VerifyConnection == nil {
		t.Fatal("webpki dropped VerifyConnection; the widened group offer is " +
			"then unenforced")
	}
	if config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 {
		t.Fatal("webpki must stay TLS 1.3 only")
	}
	// A server that answered with a group this client advertises but does not
	// want must be refused by the installed callback.
	err = config.VerifyConnection(tls.ConnectionState{
		Version: tls.VersionTLS13, CurveID: tls.CurveP521,
	})
	if err == nil {
		t.Fatal("VerifyConnection accepted a group the suite does not name")
	}
	if err = config.VerifyConnection(tls.ConnectionState{
		Version: tls.VersionTLS13, CurveID: suite.Curve,
	}); err != nil {
		t.Fatalf("VerifyConnection refused the suite's own group: %v", err)
	}
}

func TestWebPKIRefusesAPrivateRootAsWell(t *testing.T) {
	t.Parallel()
	lab := newLab(t)
	_, err := tlsconfig.ClientAnonymousTrusted(
		tlsconfig.ClientTrust{
			Anchor: tlsconfig.TrustWebPKI, RootCAPath: lab.paths.CACert,
		},
		"cdn.example", mustSuite(t, protocol.SuiteX25519MLKEM768), "h2",
	)
	if !errors.Is(err, tlsconfig.ErrTrustRootCAConflict) {
		t.Fatalf("naming both anchors must be refused, not resolved: %v", err)
	}
}

func TestWebPKIRequiresTheFrontingDomain(t *testing.T) {
	t.Parallel()
	suite := mustSuite(t, protocol.SuiteX25519MLKEM768)
	for _, name := range []string{"", "  ", "."} {
		_, err := tlsconfig.ClientAnonymousTrusted(
			tlsconfig.ClientTrust{Anchor: tlsconfig.TrustWebPKI},
			name, suite, "h2",
		)
		if !errors.Is(err, tlsconfig.ErrTrustServerNameRequired) {
			t.Fatalf("webpki with server name %q must be refused: %v", name, err)
		}
	}
	// Not a domain. The IP literals are the ones that matter: a fronted
	// deployment verifying a public certificate for an address has put the
	// address back on the wire, which is the exposure the anchor exists to
	// remove. ":443" is included because NormalizeServerName leaves it intact.
	for _, name := range []string{
		"198.51.100.7", "[2001:db8::1]", "2001:db8::1", ":443",
		"localhost", "gateway", "cdn.example/path", "cdn..example",
	} {
		_, err := tlsconfig.ClientAnonymousTrusted(
			tlsconfig.ClientTrust{Anchor: tlsconfig.TrustWebPKI},
			name, suite, "h2",
		)
		if !errors.Is(err, tlsconfig.ErrTrustServerNameNotADomain) {
			t.Fatalf("webpki with server name %q must be refused as not a "+
				"domain: %v", name, err)
		}
	}
	// And a real fronting domain is accepted, with or without the trailing dot
	// and port NormalizeServerName strips.
	for _, name := range []string{
		"cdn.example.net", "cdn.example.net.", "cdn.example.net:443",
	} {
		config, err := tlsconfig.ClientAnonymousTrusted(
			tlsconfig.ClientTrust{Anchor: tlsconfig.TrustWebPKI},
			name, suite, "h2",
		)
		if err != nil {
			t.Fatalf("webpki refused the fronting domain %q: %v", name, err)
		}
		if config.RootCAs != nil {
			t.Fatalf("%q: webpki must use the system store", name)
		}
		if config.ServerName != "cdn.example.net" {
			t.Fatalf("%q: TLS server name = %q, want %q", name, config.ServerName, "cdn.example.net")
		}
	}
}

// TestWebPKIRefusesAStableDeviceCertificate is the coupling that makes the
// fronted path safe rather than merely possible: identity-mode authorization
// compares the signed claims against the mTLS certificate at the ORIGIN, which
// a TLS-terminating CDN never forwards, and a stable device certificate handed
// to a CDN is a persistent identifier for a circumvention user.
func TestWebPKIRefusesAStableDeviceCertificate(t *testing.T) {
	t.Parallel()
	lab := newLab(t)
	_, err := tlsconfig.ClientForALPN(
		lab.paths.DeviceCert, lab.paths.DeviceKey, "",
		"cdn.example", mustSuite(t, protocol.SuiteX25519MLKEM768), "h2",
	)
	// ClientForALPN is private-CA by construction, so it cannot even name
	// webpki; it must fail on the missing root rather than quietly widening.
	if !errors.Is(err, tlsconfig.ErrTrustRootCARequired) {
		t.Fatalf("the identity constructor must stay private-CA: %v", err)
	}

	// And the guard itself must refuse the combination for any caller that
	// assembles certificates of its own.
	pool, err := tlsconfig.TrustPoolForTest(
		tlsconfig.ClientTrust{Anchor: tlsconfig.TrustWebPKI}, true, "cdn.example",
	)
	if !errors.Is(err, tlsconfig.ErrTrustWebPKIWithClientCertificate) {
		t.Fatalf("webpki with a client certificate must be refused: %v", err)
	}
	if pool != nil {
		t.Fatal("a refused trust combination must return no pool")
	}
}

// TestNilRootPoolIsReachableOnlyThroughWebPKI is the counterpart to
// TestPrivateCAFailureNeverYieldsTheSystemPool, written from the other
// direction: it enumerates every anchor and asserts that a nil pool with a nil
// error happens for webpki and nowhere else.
func TestNilRootPoolIsReachableOnlyThroughWebPKI(t *testing.T) {
	t.Parallel()
	lab := newLab(t)
	for _, testCase := range []struct {
		name      string
		trust     tlsconfig.ClientTrust
		wantNil   bool
		wantError bool
	}{
		{"webpki", tlsconfig.ClientTrust{Anchor: tlsconfig.TrustWebPKI}, true, false},
		{"private-ca loaded", tlsconfig.ClientTrust{
			Anchor: tlsconfig.TrustPrivateCA, RootCAPath: lab.paths.CACert,
		}, false, false},
		{"private-ca missing", tlsconfig.ClientTrust{
			Anchor:     tlsconfig.TrustPrivateCA,
			RootCAPath: filepath.Join(t.TempDir(), "absent.pem"),
		}, true, true},
		{"private-ca unset", tlsconfig.ClientTrust{
			Anchor: tlsconfig.TrustPrivateCA,
		}, true, true},
		{"unset anchor", tlsconfig.ClientTrust{}, true, true},
	} {
		pool, err := tlsconfig.TrustPoolForTest(testCase.trust, false, "cdn.example")
		if gotError := err != nil; gotError != testCase.wantError {
			t.Fatalf("%s: error=%v, want error=%v", testCase.name, err,
				testCase.wantError)
		}
		if gotNil := pool == nil; gotNil != testCase.wantNil {
			t.Fatalf("%s: nil pool=%v, want %v", testCase.name, gotNil,
				testCase.wantNil)
		}
		// The load-bearing line: a nil pool WITHOUT an error is the system
		// store, and only webpki may reach it.
		if pool == nil && err == nil &&
			testCase.trust.Anchor != tlsconfig.TrustWebPKI {
			t.Fatalf("%s: anchor %q succeeded with the system store",
				testCase.name, testCase.trust.Anchor)
		}
	}
}

// ---------------------------------------------------------------------------
// The two anchors are genuinely different, proven over a real handshake
// ---------------------------------------------------------------------------

// TestWebPKIClientRefusesThePrivateGatewayLeaf performs a real TLS 1.3
// handshake against a listener holding a Winn-CA leaf.
//
// This is the assertion that "webpki" is not a synonym for "verify nothing".
// The two clients differ in EXACTLY ONE field — the trust anchor. Same suite,
// same ALPN, same server name, same listener. So a pass cannot be explained by
// a hostname mismatch or a suite disagreement, and the anchor is proven to be
// doing work rather than being a field nobody reads. It also pins the practical
// consequence for operators: pointing a fronted profile at an unfronted node
// fails closed at the handshake instead of connecting to an unverified peer.
func TestWebPKIClientRefusesThePrivateGatewayLeaf(t *testing.T) {
	t.Parallel()
	// A DOTTED name, because webpki refuses a bare label, and the point of the
	// test is that the anchor is the only difference between the two clients.
	const frontingName = "gateway.winn.invalid"
	paths, err := pki.GenerateLab(
		filepath.Join(t.TempDir(), "pki"), frontingName, "trust-anchor-device-1",
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	lab := &labFixture{paths: paths, serverName: frontingName}
	suite := mustSuite(t, protocol.SuiteX25519MLKEM768)

	serverConfig, err := tlsconfig.ServerAnonymousForALPN(
		lab.paths.ServerCert, lab.paths.ServerKey, suite, "h2",
	)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "localhost:0", serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				_ = conn.(*tls.Conn).Handshake()
				_ = conn.Close()
			}()
		}
	}()

	private, err := tlsconfig.ClientAnonymousTrusted(
		tlsconfig.ClientTrust{
			Anchor: tlsconfig.TrustPrivateCA, RootCAPath: lab.paths.CACert,
		},
		lab.serverName, suite, "h2",
	)
	if err != nil {
		t.Fatal(err)
	}
	if handshakeErr := handshake(t, listener.Addr().String(), private); handshakeErr != nil {
		t.Fatalf("private-ca client must accept the Winn leaf: %v", handshakeErr)
	}

	fronted, err := tlsconfig.ClientAnonymousTrusted(
		tlsconfig.ClientTrust{Anchor: tlsconfig.TrustWebPKI},
		lab.serverName, suite, "h2",
	)
	if err != nil {
		t.Fatal(err)
	}
	handshakeErr := handshake(t, listener.Addr().String(), fronted)
	if handshakeErr == nil {
		t.Fatal("webpki client accepted a private Winn leaf: the system store " +
			"is not being consulted, or verification was skipped")
	}
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	if !errors.As(handshakeErr, &unknown) && !errors.As(handshakeErr, &hostname) &&
		!errors.As(handshakeErr, &invalid) &&
		!strings.Contains(handshakeErr.Error(), "certificate") {
		t.Fatalf("webpki refused for the wrong reason: %v", handshakeErr)
	}
}

func handshake(t *testing.T, address string, config *tls.Config) error {
	t.Helper()
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, config)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	return nil
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

var _ = pki.Paths{}

func TestTrustedClientStillRequiresALPN(t *testing.T) {
	t.Parallel()
	lab := newLab(t)
	suite := mustSuite(t, protocol.SuiteX25519MLKEM768)
	for name, alpn := range map[string][]string{
		"none":  nil,
		"empty": {""},
	} {
		_, err := tlsconfig.ClientAnonymousTrusted(
			tlsconfig.ClientTrust{
				Anchor: tlsconfig.TrustPrivateCA, RootCAPath: lab.paths.CACert,
			},
			lab.serverName, suite, alpn...,
		)
		if err == nil {
			t.Fatalf("%s ALPN must be refused", name)
		}
	}
	// And ALPN is validated BEFORE the trust anchor is resolved, so a caller
	// with two mistakes learns about the one it can see in its own call.
	if _, err := tlsconfig.ClientAnonymousTrusted(
		tlsconfig.ClientTrust{}, "", suite,
	); err == nil {
		t.Fatal("an empty ALPN list must be refused before anything else")
	}
}

func TestIdentityClientRefusesUnreadableKeyMaterial(t *testing.T) {
	t.Parallel()
	lab := newLab(t)
	suite := mustSuite(t, protocol.SuiteX25519MLKEM768)
	absent := filepath.Join(t.TempDir(), "absent.pem")
	for name, testCase := range map[string]struct{ cert, key string }{
		"missing certificate": {absent, lab.paths.DeviceKey},
		"missing key":         {lab.paths.DeviceCert, absent},
		"mismatched pair":     {lab.paths.DeviceCert, lab.paths.CAKey},
	} {
		config, err := tlsconfig.ClientForALPN(
			testCase.cert, testCase.key, lab.paths.CACert,
			lab.serverName, suite, "h2",
		)
		if err == nil {
			t.Fatalf("%s must be refused", name)
		}
		if config != nil {
			t.Fatalf("%s returned a usable configuration", name)
		}
	}
}
