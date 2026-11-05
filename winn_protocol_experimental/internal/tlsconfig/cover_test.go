package tlsconfig

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// The cover profile exists so that a censor cannot confirm a Winn endpoint on
// one unauthenticated connection. These tests hold that line at the unit level:
// they assert the observable facts a prober would collect, not the shape of the
// configuration that produces them.

const (
	testECHVersion   = 0xfe0d
	testKEMX25519    = 0x0020
	testKDFHKDF256   = 0x0001
	testAEADAES128   = 0x0001
	testPublicName   = "cover.example"
	testPrivateName  = "private.example"
	testHandshakeTMO = 10 * time.Second
)

type coverHarness struct {
	address    string
	echList    []byte
	rootCAs    *x509.CertPool
	clientCert tls.Certificate
	stop       func()
}

func newCoverHarness(t *testing.T, private string, allowUnnamed bool, clientAuth tls.ClientAuthType) *coverHarness {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Cover Test CA With A Very Distinctive Name"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	newLeaf := func(template *x509.Certificate) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate leaf key: %v", err)
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatalf("create leaf: %v", err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	}

	serverCert := newLeaf(&x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{testPublicName, testPrivateName},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	clientCert := newLeaf(&x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	echKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ECH key: %v", err)
	}
	echConfig := buildTestECHConfig(t, echKey.PublicKey().Bytes())
	echList := binary.BigEndian.AppendUint16(nil, uint16(len(echConfig)))
	echList = append(echList, echConfig...)

	winn := &tls.Config{
		Certificates:           []tls.Certificate{serverCert},
		ClientAuth:             clientAuth,
		ClientCAs:              pool,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519MLKEM768},
		SessionTicketsDisabled: true,
		NextProtos:             []string{"h2"},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{
			{Config: echConfig, PrivateKey: echKey.Bytes(), SendAsRetry: true},
		},
	}
	if clientAuth == tls.NoClientCert {
		winn.ClientCAs = nil
	}
	cover, err := ApplyCoverProfile(winn, CoverProfile{
		PrivateServerName:       private,
		CoverALPN:               []string{"h2", "http/1.1"},
		AllowUnnamedWinnClients: allowUnnamed,
		// These cases measure certificate_authorities, the accepted version
		// set and the accepted group set. The served leaf is the subject of
		// TestCoverCertificateHidesTheIssuer and
		// TestCoverProfileRefusesToReuseTheWinnLeaf instead, so this harness
		// takes the lab escape hatch rather than standing up a second PKI.
		AllowWinnLeafAsCover: true,
	})
	if err != nil {
		t.Fatalf("ApplyCoverProfile: %v", err)
	}
	cover.EncryptedClientHelloKeys = winn.EncryptedClientHelloKeys

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
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
				tlsConn := tls.Server(conn, cover)
				_ = tlsConn.SetDeadline(time.Now().Add(testHandshakeTMO))
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				_, _ = tlsConn.Write([]byte("ok"))
				<-done
			}()
		}
	}()
	harness := &coverHarness{
		address: listener.Addr().String(), echList: echList,
		rootCAs: pool, clientCert: clientCert,
	}
	harness.stop = func() {
		close(done)
		_ = listener.Close()
		wg.Wait()
	}
	t.Cleanup(harness.stop)
	return harness
}

func buildTestECHConfig(t *testing.T, publicKey []byte) []byte {
	t.Helper()
	var contents []byte
	contents = append(contents, 1)
	contents = binary.BigEndian.AppendUint16(contents, testKEMX25519)
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(publicKey)))
	contents = append(contents, publicKey...)
	suites := binary.BigEndian.AppendUint16(nil, testKDFHKDF256)
	suites = binary.BigEndian.AppendUint16(suites, testAEADAES128)
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(suites)))
	contents = append(contents, suites...)
	contents = append(contents, 253, byte(len(testPublicName)))
	contents = append(contents, testPublicName...)
	contents = binary.BigEndian.AppendUint16(contents, 0)

	config := binary.BigEndian.AppendUint16(nil, testECHVersion)
	config = binary.BigEndian.AppendUint16(config, uint16(len(contents)))
	return append(config, contents...)
}

// probe records exactly what an unauthenticated peer learns.
type probeOutcome struct {
	handshakeErr  error
	acceptableCAs [][]byte
	state         tls.ConnectionState
	appErr        error
}

func (h *coverHarness) probe(t *testing.T, cfg *tls.Config) probeOutcome {
	t.Helper()
	var outcome probeOutcome
	cfg = cfg.Clone()
	cfg.RootCAs = h.rootCAs
	// Record certificate_authorities - the D4 measurement - while still
	// presenting whatever certificate the caller configured.
	offered := cfg.Certificates
	cfg.Certificates = nil
	cfg.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		outcome.acceptableCAs = append(outcome.acceptableCAs, cri.AcceptableCAs...)
		if len(offered) > 0 {
			return &offered[0], nil
		}
		return &tls.Certificate{}, nil
	}
	conn, err := net.DialTimeout("tcp", h.address, testHandshakeTMO)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(testHandshakeTMO))
	tlsConn := tls.Client(conn, cfg)
	if outcome.handshakeErr = tlsConn.Handshake(); outcome.handshakeErr != nil {
		return outcome
	}
	outcome.state = tlsConn.ConnectionState()
	// A TLS 1.3 client completes its handshake without waiting for the
	// server's verdict, so the terminal outcome only shows on the first read.
	buffer := make([]byte, 8)
	if _, err := tlsConn.Read(buffer); err != nil && !errors.Is(err, io.EOF) {
		outcome.appErr = err
	}
	return outcome
}

func ordinaryClient(serverName string, version uint16, curves []tls.CurveID) *tls.Config {
	return &tls.Config{
		ServerName:       serverName,
		MinVersion:       version,
		MaxVersion:       version,
		CurvePreferences: curves,
	}
}

// TestCoverProfileWithholdsClientCAFromProbers is the regression test for the
// worst of the five discriminators: an unauthenticated prober receiving the
// Winn CA's Distinguished Name in certificate_authorities.
func TestCoverProfileWithholdsClientCAFromProbers(t *testing.T) {
	harness := newCoverHarness(t, testPrivateName, false, tls.RequireAndVerifyClientCert)

	shapes := []struct {
		name string
		cfg  *tls.Config
	}{
		{"ordinary browser groups", ordinaryClient(testPublicName, tls.VersionTLS13,
			[]tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384})},
		{"tls 1.2 only", ordinaryClient(testPublicName, tls.VersionTLS12, nil)},
		{"hybrid group without ECH", ordinaryClient(testPublicName, tls.VersionTLS13,
			[]tls.CurveID{tls.X25519MLKEM768})},
		{"private name guessed, no ECH", ordinaryClient(testPrivateName, tls.VersionTLS13,
			[]tls.CurveID{tls.X25519MLKEM768})},
	}
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			outcome := harness.probe(t, shape.cfg)
			if outcome.handshakeErr != nil {
				t.Fatalf("prober was refused (%v); a refusal is itself a discriminator", outcome.handshakeErr)
			}
			if outcome.appErr != nil {
				t.Fatalf("prober was killed after the handshake (%v); that is a discriminator", outcome.appErr)
			}
			if len(outcome.acceptableCAs) != 0 {
				t.Fatalf("certificate_authorities leaked %d CA name(s) to an unauthenticated prober",
					len(outcome.acceptableCAs))
			}
		})
	}
}

// TestCoverProfileAcceptsOrdinaryTLSVersionsAndGroups covers discriminators one
// and two: the accepted version and group set must not itself be a fingerprint.
func TestCoverProfileAcceptsOrdinaryTLSVersionsAndGroups(t *testing.T) {
	harness := newCoverHarness(t, testPrivateName, false, tls.RequireAndVerifyClientCert)

	for _, testCase := range []struct {
		name    string
		version uint16
		curves  []tls.CurveID
	}{
		{"tls1.2", tls.VersionTLS12, nil},
		{"tls1.3 x25519", tls.VersionTLS13, []tls.CurveID{tls.X25519}},
		{"tls1.3 p256", tls.VersionTLS13, []tls.CurveID{tls.CurveP256}},
		{"tls1.3 p384", tls.VersionTLS13, []tls.CurveID{tls.CurveP384}},
		{"tls1.3 browser set", tls.VersionTLS13,
			[]tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			outcome := harness.probe(t, ordinaryClient(testPublicName, testCase.version, testCase.curves))
			if outcome.handshakeErr != nil {
				t.Fatalf("ordinary client refused: %v", outcome.handshakeErr)
			}
			if outcome.state.Version != testCase.version {
				t.Fatalf("negotiated version %x, want %x", outcome.state.Version, testCase.version)
			}
			if len(outcome.state.PeerCertificates) == 0 {
				t.Fatal("no server certificate delivered")
			}
		})
	}
}

// TestWinnClientReachesStrictProfile is the other half of the contract: the
// cover profile must not lock out the clients it exists to protect.
func TestWinnClientReachesStrictProfile(t *testing.T) {
	harness := newCoverHarness(t, testPrivateName, false, tls.RequireAndVerifyClientCert)

	cfg := &tls.Config{
		ServerName:                     testPrivateName,
		MinVersion:                     tls.VersionTLS13,
		MaxVersion:                     tls.VersionTLS13,
		CurvePreferences:               []tls.CurveID{tls.X25519MLKEM768},
		NextProtos:                     []string{"h2"},
		EncryptedClientHelloConfigList: harness.echList,
		Certificates:                   []tls.Certificate{harness.clientCert},
	}
	outcome := harness.probe(t, cfg)
	if outcome.handshakeErr != nil {
		t.Fatalf("genuine Winn client refused: %v", outcome.handshakeErr)
	}
	if outcome.appErr != nil {
		t.Fatalf("genuine Winn client killed after handshake: %v", outcome.appErr)
	}
	if !outcome.state.ECHAccepted {
		t.Fatal("ECH was not accepted for the Winn client")
	}
	if outcome.state.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("negotiated group %v, want the hybrid group", outcome.state.CurveID)
	}
	if outcome.state.NegotiatedProtocol != "h2" {
		t.Fatalf("negotiated ALPN %q, want h2", outcome.state.NegotiatedProtocol)
	}
	if len(outcome.acceptableCAs) == 0 {
		t.Fatal("the Winn profile should still drive client-certificate selection")
	}
}

// TestUnnamedWinnClientNeedsExplicitOptIn records the behaviour of deployments
// whose clients present no SNI at all - a certificate with only an IP address,
// for which RFC 6066 forbids SNI. Such a deployment cannot tier on the server
// name, and must say so rather than silently falling back.
func TestUnnamedWinnClientNeedsExplicitOptIn(t *testing.T) {
	echClient := func() *tls.Config {
		return &tls.Config{
			ServerName:                     "",
			MinVersion:                     tls.VersionTLS13,
			MaxVersion:                     tls.VersionTLS13,
			CurvePreferences:               []tls.CurveID{tls.X25519MLKEM768},
			NextProtos:                     []string{"h2"},
			Certificates:                   []tls.Certificate{},
			InsecureSkipVerify:             true,
			EncryptedClientHelloConfigList: nil,
		}
	}

	t.Run("without opt-in the strict profile is unreachable", func(t *testing.T) {
		harness := newCoverHarness(t, "", false, tls.RequireAndVerifyClientCert)
		cfg := echClient()
		cfg.EncryptedClientHelloConfigList = harness.echList
		cfg.Certificates = []tls.Certificate{harness.clientCert}
		outcome := harness.probe(t, cfg)
		if outcome.handshakeErr != nil {
			t.Fatalf("unexpected refusal: %v", outcome.handshakeErr)
		}
		if len(outcome.acceptableCAs) != 0 {
			t.Fatal("no CA name should be offered when tiering is not opted into")
		}
	})

	t.Run("with opt-in an ECH client reaches the strict profile", func(t *testing.T) {
		harness := newCoverHarness(t, "", true, tls.RequireAndVerifyClientCert)
		cfg := echClient()
		cfg.EncryptedClientHelloConfigList = harness.echList
		cfg.Certificates = []tls.Certificate{harness.clientCert}
		outcome := harness.probe(t, cfg)
		if outcome.handshakeErr != nil {
			t.Fatalf("genuine Winn client refused: %v", outcome.handshakeErr)
		}
		if !outcome.state.ECHAccepted {
			t.Fatal("ECH was not accepted")
		}
		if len(outcome.acceptableCAs) == 0 {
			t.Fatal("the Winn profile should drive client-certificate selection")
		}
	})

	t.Run("with opt-in a plain prober still gets the cover profile", func(t *testing.T) {
		harness := newCoverHarness(t, "", true, tls.RequireAndVerifyClientCert)
		outcome := harness.probe(t, ordinaryClient(testPublicName, tls.VersionTLS13,
			[]tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}))
		if outcome.handshakeErr != nil {
			t.Fatalf("prober refused: %v", outcome.handshakeErr)
		}
		if len(outcome.acceptableCAs) != 0 {
			t.Fatal("certificate_authorities leaked to a prober that offered no ECH")
		}
	})
}

// TestCoverCertificateHidesTheIssuer covers the half of the CA-identity leak
// that certificate_authorities does not. Winn clients pin the Winn CA, so the
// gateway's leaf is issued by it, and a leaf carries its issuer's DN in the
// clear to anyone who completes a handshake.
func TestCoverCertificateHidesTheIssuer(t *testing.T) {
	// A cover certificate an operator would supply: ordinary name, unrelated
	// issuer.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(77),
		Subject:      pkix.Name{CommonName: testPublicName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{testPublicName},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	coverCert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	winn := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
	}
	profile, err := ApplyCoverProfile(winn, CoverProfile{
		PrivateServerName: testPrivateName,
		CoverALPN:         []string{"h2"},
		Certificate:       coverCert,
	})
	if err != nil {
		t.Fatalf("ApplyCoverProfile: %v", err)
	}
	if len(profile.Certificates) != 1 {
		t.Fatalf("cover profile has %d certificates, want 1", len(profile.Certificates))
	}
	if profile.GetCertificate != nil {
		t.Fatal("cover profile must not fall back to the Winn certificate callback")
	}
	issuer, err := CertificateIssuerName(profile)
	if err != nil {
		t.Fatalf("CertificateIssuerName: %v", err)
	}
	if strings.Contains(strings.ToLower(issuer), "winn") {
		t.Fatalf("cover certificate issuer %q identifies the deployment", issuer)
	}
}

// TestCoverProfileRefusesToReuseTheWinnLeaf pins the gate rather than the
// mechanism. A cover profile that silently falls back to the Winn leaf is
// worse than no cover profile at all, because it reads as protection while
// still handing the issuer Distinguished Name to every prober - which is what
// a warning-only fallback produced for as long as it existed.
func TestCoverProfileRefusesToReuseTheWinnLeaf(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject:      pkix.Name{CommonName: testPrivateName},
		Issuer:       pkix.Name{CommonName: "Winn Protocol Experimental Lab CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{testPrivateName},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	winn := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
	}

	if _, err := ApplyCoverProfile(winn, CoverProfile{
		PrivateServerName: testPrivateName,
		CoverALPN:         []string{"h2"},
	}); err == nil {
		t.Fatal("built a cover profile with no cover certificate; " +
			"every prober would read the Winn CA off the leaf")
	}

	// The escape hatch still works, and has to be asked for by name.
	profile, err := ApplyCoverProfile(winn, CoverProfile{
		PrivateServerName:    testPrivateName,
		CoverALPN:            []string{"h2"},
		AllowWinnLeafAsCover: true,
	})
	if err != nil {
		t.Fatalf("explicit opt-in was refused: %v", err)
	}
	if len(profile.Certificates) == 0 {
		t.Fatal("opt-in produced no certificate")
	}
}

func TestLoadCoverCertificateRequiresBothHalves(t *testing.T) {
	if _, err := LoadCoverCertificate("", "key.pem"); err == nil {
		t.Fatal("accepted a cover certificate without a certificate path")
	}
	if _, err := LoadCoverCertificate("cert.pem", ""); err == nil {
		t.Fatal("accepted a cover certificate without a key path")
	}
}

func TestPrivateServerNameFromCertificate(t *testing.T) {
	withSAN := func(dns []string, ips []net.IP) *tls.Config {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("key: %v", err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(9),
			Subject:      pkix.Name{CommonName: "common"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			DNSNames:     dns,
			IPAddresses:  ips,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatalf("cert: %v", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}}}}
	}

	if name, err := PrivateServerNameFromCertificate(withSAN([]string{"a.example"}, nil)); err != nil || name != "a.example" {
		t.Fatalf("DNS SAN: got %q, %v", name, err)
	}
	// An IP-only certificate must report no name: RFC 6066 forbids IP
	// literals in SNI, so a client presents none and name tiering cannot work.
	name, err := PrivateServerNameFromCertificate(withSAN(nil, []net.IP{net.ParseIP("127.0.0.1")}))
	if err == nil {
		t.Fatalf("IP-only certificate returned name %q; want an error", name)
	}
}

func TestNormalizeServerName(t *testing.T) {
	for input, want := range map[string]string{
		"  Example.COM  ": "Example.COM",
		"example.com.":    "example.com",
		"example.com:443": "example.com",
		"":                "",
	} {
		if got := NormalizeServerName(input); got != want {
			t.Fatalf("NormalizeServerName(%q) = %q, want %q", input, got, want)
		}
	}
}
