package coverlisten_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/coverlisten"
	"winsvpn.local/winnprotocol/internal/echconfig"
)

// These tests measure what a prober collects on one unauthenticated
// connection, against a listener configuration built the way the commands
// build theirs. They are the "after" half of the before/after; the "before" is
// the same harness with the cover profile removed, which is what
// TestStrictProfileAloneIdentifiesTheDeployment records.

const (
	winnCAName  = "Winn Protocol Experimental Lab CA"
	coverCAName = "Example Trust Services R3"
	privateName = "gateway-7.winn.invalid"
	coverName   = "www.example.com"
	handshakeTO = 10 * time.Second
)

type pki struct {
	winnCAPool  *x509.CertPool
	serverCert  tls.Certificate
	clientCert  tls.Certificate
	coverCert   string
	coverKey    string
	coverIssuer string
}

func newPKI(t *testing.T) pki {
	t.Helper()
	dir := t.TempDir()

	newCA := func(name string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
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
		return parsed, key, der
	}

	newLeaf := func(
		issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey,
		template *x509.Certificate,
	) (tls.Certificate, []byte, *ecdsa.PrivateKey) {
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
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, der, key
	}

	winnCA, winnCAKey, _ := newCA(winnCAName)
	winnPool := x509.NewCertPool()
	winnPool.AddCert(winnCA)

	serverCert, _, _ := newLeaf(winnCA, winnCAKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: privateName},
		DNSNames:    []string{privateName},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	clientCert, _, _ := newLeaf(winnCA, winnCAKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "device-1"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	// A cover certificate the owner would realistically hold: an ordinary
	// server certificate for an ordinary name, from a CA that has nothing to
	// do with Winn.
	// Shaped like a real ACME leaf: subject is a Common Name and nothing else,
	// one plausible public name, no loopback SAN, ordinary validity, and the
	// issuing intermediate supplied alongside it.
	coverCA, coverCAKey, coverCADER := newCA(coverCAName)
	_, coverLeafDER, coverLeafKey := newLeaf(coverCA, coverCAKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: coverName},
		DNSNames:    []string{coverName},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})

	certPath := filepath.Join(dir, "cover.crt")
	keyPath := filepath.Join(dir, "cover.key")
	var chain []byte
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: coverLeafDER})...)
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: coverCADER})...)
	if err := os.WriteFile(certPath, chain, 0o600); err != nil {
		t.Fatalf("write cover certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(coverLeafKey)
	if err != nil {
		t.Fatalf("marshal cover key: %v", err)
	}
	if err := os.WriteFile(
		keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600,
	); err != nil {
		t.Fatalf("write cover key: %v", err)
	}

	return pki{
		winnCAPool: winnPool, serverCert: serverCert, clientCert: clientCert,
		coverCert: certPath, coverKey: keyPath, coverIssuer: coverCAName,
	}
}

// strictConfig mirrors what tlsconfig.ServerForALPN plus
// echconfig.ConfigureServer produce, which is what every command hands to
// coverlisten.Apply.
func strictConfig(t *testing.T, material pki, keys []tls.EncryptedClientHelloKey) *tls.Config {
	t.Helper()
	config := &tls.Config{
		Certificates:           []tls.Certificate{material.serverCert},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              material.winnCAPool,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519MLKEM768},
		SessionTicketsDisabled: true,
		Renegotiation:          tls.RenegotiateNever,
		NextProtos:             []string{"h2"},
	}
	if err := echconfig.ConfigureServer(config, keys, true); err != nil {
		t.Fatalf("ConfigureServer: %v", err)
	}
	return config
}

func echMaterial(t *testing.T) ([]byte, []tls.EncryptedClientHelloKey) {
	t.Helper()
	configList, keyFile, err := echconfig.Generate(coverName, 1)
	if err != nil {
		t.Fatalf("generate ECH: %v", err)
	}
	keys, err := echconfig.TLSKeys(keyFile)
	if err != nil {
		t.Fatalf("ECH server keys: %v", err)
	}
	return configList, keys
}

type observation struct {
	handshakeErr  error
	acceptableCAs []string
	version       uint16
	issuer        string
	echAccepted   bool
	curve         tls.CurveID
	alpn          string
}

// serve runs one listener with the given configuration and returns a prober.
func serve(t *testing.T, config *tls.Config) func(*testing.T, *tls.Config) observation {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
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
				server := tls.Server(conn, config)
				_ = server.SetDeadline(time.Now().Add(handshakeTO))
				if err := server.Handshake(); err != nil {
					return
				}
				_, _ = server.Write([]byte("ok"))
				<-done
			}()
		}
	}()
	t.Cleanup(func() {
		close(done)
		_ = listener.Close()
		wg.Wait()
	})

	address := listener.Addr().String()
	return func(t *testing.T, client *tls.Config) observation {
		t.Helper()
		var seen observation
		client = client.Clone()
		client.InsecureSkipVerify = true
		offered := client.Certificates
		client.Certificates = nil
		client.GetClientCertificate = func(
			request *tls.CertificateRequestInfo,
		) (*tls.Certificate, error) {
			// Every acceptable CA the server names is, by definition, what a
			// prober learns for free.
			for _, raw := range request.AcceptableCAs {
				var name pkix.RDNSequence
				if _, err := asn1.Unmarshal(raw, &name); err == nil {
					seen.acceptableCAs = append(seen.acceptableCAs, name.String())
					continue
				}
				seen.acceptableCAs = append(seen.acceptableCAs, string(raw))
			}
			if len(offered) > 0 {
				return &offered[0], nil
			}
			return &tls.Certificate{}, nil
		}
		conn, err := net.DialTimeout("tcp", address, handshakeTO)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(handshakeTO))
		tlsConn := tls.Client(conn, client)
		if seen.handshakeErr = tlsConn.Handshake(); seen.handshakeErr != nil {
			return seen
		}
		state := tlsConn.ConnectionState()
		seen.version = state.Version
		seen.echAccepted = state.ECHAccepted
		seen.curve = state.CurveID
		seen.alpn = state.NegotiatedProtocol
		if len(state.PeerCertificates) > 0 {
			seen.issuer = state.PeerCertificates[0].Issuer.String()
		}
		buffer := make([]byte, 8)
		if _, err := tlsConn.Read(buffer); err != nil && !errors.Is(err, io.EOF) {
			if seen.handshakeErr == nil {
				seen.handshakeErr = err
			}
		}
		return seen
	}
}

func ordinaryProber(version uint16, curves []tls.CurveID) *tls.Config {
	return &tls.Config{
		ServerName:       coverName,
		MinVersion:       version,
		MaxVersion:       version,
		CurvePreferences: curves,
		NextProtos:       []string{"h2", "http/1.1"},
	}
}

// TestStrictProfileAloneIdentifiesTheDeployment is the "before" measurement.
// It is the configuration winn-server and winn-token-issuer served until this
// change, and it exists so the "after" numbers below have something to be
// better than.
func TestStrictProfileAloneIdentifiesTheDeployment(t *testing.T) {
	material := newPKI(t)
	_, keys := echMaterial(t)
	probe := serve(t, strictConfig(t, material, keys))

	seen := probe(t, ordinaryProber(tls.VersionTLS13,
		[]tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}))

	// An ordinary client is refused outright, which is itself the signal.
	if seen.handshakeErr == nil {
		t.Fatal("expected the strict profile to refuse an ordinary client")
	}

	// And a prober willing to speak the Winn group is handed the CA name.
	seen = probe(t, ordinaryProber(tls.VersionTLS13,
		[]tls.CurveID{tls.X25519MLKEM768}))
	if len(seen.acceptableCAs) == 0 {
		t.Fatal("expected certificate_authorities to name the Winn CA")
	}
	var named bool
	for _, name := range seen.acceptableCAs {
		if strings.Contains(name, winnCAName) {
			named = true
		}
	}
	if !named {
		t.Fatalf("expected the Winn CA in %v", seen.acceptableCAs)
	}
	t.Logf("before: prober reads certificate_authorities = %v", seen.acceptableCAs)
}

// TestCoverListenerTellsAProberNothing is the "after" measurement, on the
// configuration coverlisten.Apply builds.
func TestCoverListenerTellsAProberNothing(t *testing.T) {
	material := newPKI(t)
	_, keys := echMaterial(t)
	winn := strictConfig(t, material, keys)

	listener, err := coverlisten.Apply(coverlisten.Options{
		Winn:                      winn,
		CoverALPN:                 []string{"h2", "http/1.1"},
		CoverCertPath:             material.coverCert,
		CoverKeyPath:              material.coverKey,
		ECHKeys:                   keys,
		RequestsClientCertificate: true,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !listener.CoverCertificate {
		t.Fatal("cover certificate was not recorded as supplied")
	}
	if listener.PrivateServerName != privateName {
		t.Fatalf("private server name %q, want %q", listener.PrivateServerName, privateName)
	}
	probe := serve(t, listener.TLS)

	for _, shape := range []struct {
		name    string
		version uint16
		curves  []tls.CurveID
	}{
		{"ordinary browser", tls.VersionTLS13,
			[]tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}},
		{"tls 1.2 only", tls.VersionTLS12, nil},
		{"hybrid group, no ECH", tls.VersionTLS13,
			[]tls.CurveID{tls.X25519MLKEM768}},
	} {
		t.Run(shape.name, func(t *testing.T) {
			seen := probe(t, ordinaryProber(shape.version, shape.curves))
			if seen.handshakeErr != nil {
				t.Fatalf("prober refused (%v); a refusal is itself a discriminator",
					seen.handshakeErr)
			}
			if len(seen.acceptableCAs) != 0 {
				t.Fatalf("certificate_authorities disclosed %v", seen.acceptableCAs)
			}
			if seen.version != shape.version {
				t.Fatalf("negotiated version %x, want %x", seen.version, shape.version)
			}
			if strings.Contains(strings.ToLower(seen.issuer), "winn") {
				t.Fatalf("served leaf issuer %q identifies the deployment", seen.issuer)
			}
			if !strings.Contains(seen.issuer, coverCAName) {
				t.Fatalf("served leaf issuer %q is not the cover CA", seen.issuer)
			}
			t.Logf("after: version=%x acceptable_cas=%d issuer=%q",
				seen.version, len(seen.acceptableCAs), seen.issuer)
		})
	}

	// The other half of the contract: the profile must not lock out the
	// clients it exists to protect.
	t.Run("genuine winn client still reaches the strict profile", func(t *testing.T) {
		client := &tls.Config{
			ServerName:                     privateName,
			MinVersion:                     tls.VersionTLS13,
			MaxVersion:                     tls.VersionTLS13,
			CurvePreferences:               []tls.CurveID{tls.X25519MLKEM768},
			NextProtos:                     []string{"h2"},
			Certificates:                   []tls.Certificate{material.clientCert},
			EncryptedClientHelloConfigList: echConfigListFor(t, listener.TLS),
		}
		seen := probe(t, client)
		if seen.handshakeErr != nil {
			t.Fatalf("genuine Winn client refused: %v", seen.handshakeErr)
		}
		if !seen.echAccepted {
			t.Fatal("ECH was not accepted for the Winn client")
		}
		if seen.curve != tls.X25519MLKEM768 {
			t.Fatalf("negotiated group %v, want the hybrid group", seen.curve)
		}
		if seen.alpn != "h2" {
			t.Fatalf("negotiated ALPN %q, want h2", seen.alpn)
		}
		if len(seen.acceptableCAs) == 0 {
			t.Fatal("the strict profile should still drive client-certificate selection")
		}
		if !strings.Contains(strings.ToLower(seen.issuer), "winn") {
			t.Fatalf("Winn client received leaf issued by %q, want the Winn CA", seen.issuer)
		}
	})
}

// TestApplyRefusesWithoutACoverCertificate is the gate. Its predecessor was a
// log.Printf.
func TestApplyRefusesWithoutACoverCertificate(t *testing.T) {
	material := newPKI(t)
	_, keys := echMaterial(t)

	_, err := coverlisten.Apply(coverlisten.Options{
		Winn:                      strictConfig(t, material, keys),
		CoverALPN:                 []string{"h2"},
		ECHKeys:                   keys,
		RequestsClientCertificate: true,
	})
	if err == nil {
		t.Fatal("built a listener with no cover certificate; every prober " +
			"would read the Winn CA off the served leaf")
	}
	if !errors.Is(err, coverlisten.ErrNoCoverCertificate) {
		t.Fatalf("error %v does not wrap ErrNoCoverCertificate", err)
	}
	// The message has to tell an operator what to generate, because the owner
	// is the only person who can generate it.
	for _, want := range []string{"-cover-cert", "-cover-key", winnCAName} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal message does not mention %q: %s", want, err)
		}
	}

	// The lab escape hatch works, and has to be asked for by name.
	built, err := coverlisten.Apply(coverlisten.Options{
		Winn:                      strictConfig(t, material, keys),
		CoverALPN:                 []string{"h2"},
		ECHKeys:                   keys,
		RequestsClientCertificate: true,
		AllowWinnLeafAsCover:      true,
	})
	if err != nil {
		t.Fatalf("explicit opt-in refused: %v", err)
	}
	if built.CoverCertificate {
		t.Fatal("opt-in must not report a cover certificate as supplied")
	}
	reused, err := coverlisten.ServesWinnLeaf(built.TLS, strictConfig(t, material, keys))
	if err != nil {
		t.Fatalf("ServesWinnLeaf: %v", err)
	}
	if !reused {
		t.Fatal("opt-in should serve the Winn leaf; that is what makes it insecure")
	}
}

// TestVerifyRejectsAStrictConfiguration is what makes the per-command Verify
// call at the point of serving worth making: handed the strict profile by
// mistake, it says so instead of serving it.
func TestVerifyRejectsAStrictConfiguration(t *testing.T) {
	material := newPKI(t)
	_, keys := echMaterial(t)
	if err := coverlisten.Verify(strictConfig(t, material, keys)); err == nil {
		t.Fatal("Verify accepted the strict profile as a cover listener")
	}
	if err := coverlisten.Verify(nil); err == nil {
		t.Fatal("Verify accepted a nil configuration")
	}

	listener, err := coverlisten.Apply(coverlisten.Options{
		Winn:                      strictConfig(t, material, keys),
		CoverALPN:                 []string{"h2"},
		CoverCertPath:             material.coverCert,
		CoverKeyPath:              material.coverKey,
		ECHKeys:                   keys,
		RequestsClientCertificate: true,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := coverlisten.Verify(listener.TLS); err != nil {
		t.Fatalf("Verify rejected its own output: %v", err)
	}

	// Each discriminator Verify names must actually be caught.
	for _, mutation := range []struct {
		name  string
		apply func(*tls.Config)
	}{
		{"requests a client certificate", func(c *tls.Config) {
			c.ClientAuth = tls.RequireAndVerifyClientCert
		}},
		{"refuses TLS 1.2", func(c *tls.Config) { c.MinVersion = tls.VersionTLS13 }},
		{"pins one named group", func(c *tls.Config) {
			c.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
		}},
		{"never issues a session ticket", func(c *tls.Config) {
			c.SessionTicketsDisabled = true
		}},
		{"makes ECH mandatory", func(c *tls.Config) {
			c.VerifyConnection = func(tls.ConnectionState) error { return nil }
		}},
		{"has no ECH keys", func(c *tls.Config) { c.EncryptedClientHelloKeys = nil }},
		{"carries a client CA pool", func(c *tls.Config) {
			c.ClientCAs = x509.NewCertPool()
		}},
		{"pins a cipher suite set", func(c *tls.Config) {
			c.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := listener.TLS.Clone()
			mutation.apply(mutated)
			if err := coverlisten.Verify(mutated); err == nil {
				t.Fatalf("Verify accepted a listener that %s", mutation.name)
			}
		})
	}
}

// TestApplyRefusesUnparseableWinnLeaf is the negative for parseWinnLeaf.
// Before the fail-closed change, garbage Winn leaf bytes made
// ReviewCoverCertificate skip the relational half (same-CA / shared-name)
// and Apply still returned a listener. Cover handshakes would work; genuine
// clients would fail at TLS, which on this product is indistinguishable
// from a censor.
func TestApplyRefusesUnparseableWinnLeaf(t *testing.T) {
	material := newPKI(t)
	_, keys := echMaterial(t)
	winn := strictConfig(t, material, keys)
	winn.Certificates[0].Certificate[0] = []byte("not-a-certificate")
	winn.Certificates[0].Leaf = nil

	_, err := coverlisten.Apply(coverlisten.Options{
		Winn:                      winn,
		CoverALPN:                 []string{"h2"},
		CoverCertPath:             material.coverCert,
		CoverKeyPath:              material.coverKey,
		ECHKeys:                   keys,
		RequestsClientCertificate: true,
	})
	if err == nil {
		t.Fatal("Apply accepted a Winn leaf that does not parse; relational " +
			"cover review would have been skipped and genuine clients would " +
			"fail the handshake")
	}
	if !strings.Contains(err.Error(), "parse Winn server certificate") {
		t.Fatalf("error %q does not name the parse failure", err)
	}
}

// echConfigListFor rebuilds the client-side ECH config list from the keys the
// listener holds, so the test does not depend on file layout.
func echConfigListFor(t *testing.T, config *tls.Config) []byte {
	t.Helper()
	if len(config.EncryptedClientHelloKeys) == 0 {
		t.Fatal("listener has no ECH keys")
	}
	var list []byte
	for _, key := range config.EncryptedClientHelloKeys {
		list = append(list, key.Config...)
	}
	prefixed := []byte{byte(len(list) >> 8), byte(len(list))}
	return append(prefixed, list...)
}
