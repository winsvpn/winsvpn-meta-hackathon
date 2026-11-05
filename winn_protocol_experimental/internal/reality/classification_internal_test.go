package reality

// White-box tests for classificationConfig, the one piece of behaviour this
// package adds to internal/coverlisten's own decision: turning its "fall
// back to the cover certificate" signal (nil, nil) into a forced handshake
// abort (errNotWinnClient) before anything reaches the wire.
//
// These deliberately do not re-prove that internal/tlsconfig.ApplyCoverProfile
// correctly requires both the ECH extension and a matching private server
// name - internal/tlsconfig/cover_test.go and clienthello_test.go already do
// that, over a real network handshake, in that package. Re-deriving the same
// proof here over a real ECH-encrypted ClientHello ran into a genuine
// subtlety in crypto/tls's own client-side ECH retry handling once the
// relay target (an ordinary, non-ECH server) is in the loop - a real thing
// to understand, but not this package's thing to understand: this package
// never inspects ECH itself, and its own correctness only depends on
// forwarding ApplyCoverProfile's decision faithfully. That is exactly what a
// direct, in-process call to the wrapped GetConfigForClient proves, without
// needing a real ECH-capable client at all.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

const (
	testPrivateServerName = "private.reality-classification-test.invalid"
	echExtensionCodePoint = 0xfe0d
)

func selfSignedTestCert(t *testing.T, commonName string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// buildTestCoverConfig builds a *tls.Config the same way coverlisten.Apply
// does internally (via tlsconfig.ApplyCoverProfile), without going through
// coverlisten's own certificate-plausibility gate, which is orthogonal to
// what this file tests. It returns both the cover configuration and the
// exact strict winn *tls.Config pointer ApplyCoverProfile was given, so a
// test can confirm classificationConfig hands out that same pointer
// unmodified rather than a copy.
func buildTestCoverConfig(t *testing.T) (cover, winn *tls.Config) {
	t.Helper()
	winnCert := selfSignedTestCert(t, testPrivateServerName)
	coverCert := selfSignedTestCert(t, "www.example-cover.invalid")
	winn = &tls.Config{
		Certificates: []tls.Certificate{winnCert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	cover, err := tlsconfig.ApplyCoverProfile(winn, tlsconfig.CoverProfile{
		PrivateServerName: testPrivateServerName,
		CoverALPN:         []string{"h2", "http/1.1"},
		Certificate:       &coverCert,
	})
	if err != nil {
		t.Fatalf("ApplyCoverProfile: %v", err)
	}
	return cover, winn
}

func TestClassificationConfigForwardsCoverDecisionFaithfully(t *testing.T) {
	cover, winn := buildTestCoverConfig(t)

	t.Run("no ECH extension at all is refused, not served the cover certificate", func(t *testing.T) {
		shim := newShimConn(nil)
		wrapped := classificationConfig(cover, shim)
		selected, err := wrapped.GetConfigForClient(&tls.ClientHelloInfo{
			ServerName: testPrivateServerName, // even the right name; extension is what's missing
		})
		if selected != nil {
			t.Fatalf("expected no configuration to be selected, got %v", selected)
		}
		if !errors.Is(err, errNotWinnClient) {
			t.Fatalf("expected errNotWinnClient, got %v", err)
		}
		if shim.live {
			t.Fatal("shim must not be committed live for a connection that will be relayed")
		}
	})

	t.Run("ECH extension present but the wrong private name is refused", func(t *testing.T) {
		shim := newShimConn(nil)
		wrapped := classificationConfig(cover, shim)
		selected, err := wrapped.GetConfigForClient(&tls.ClientHelloInfo{
			ServerName: "not-" + testPrivateServerName,
			Extensions: []uint16{echExtensionCodePoint},
		})
		if selected != nil {
			t.Fatalf("expected no configuration to be selected, got %v", selected)
		}
		if !errors.Is(err, errNotWinnClient) {
			t.Fatalf("expected errNotWinnClient, got %v", err)
		}
		if shim.live {
			t.Fatal("shim must not be committed live for a connection that will be relayed")
		}
	})

	t.Run("ECH extension present with the matching private name selects Winn and commits the shim live", func(t *testing.T) {
		shim := newShimConn(nil)
		wrapped := classificationConfig(cover, shim)
		// Since tiering requires an accepted ECH (internal/tlsconfig records
		// the outer hello's name and wants a different inner one), model the
		// two calls crypto/tls makes for a decrypted ECH connection: the
		// outer hello through GetEncryptedClientHelloKeys, then the inner one.
		conn, peer := net.Pipe()
		defer conn.Close()
		defer peer.Close()
		if _, err := wrapped.GetEncryptedClientHelloKeys(&tls.ClientHelloInfo{
			ServerName: "www.example.com",
			Conn:       conn,
		}); err != nil {
			t.Fatalf("GetEncryptedClientHelloKeys: %v", err)
		}
		selected, err := wrapped.GetConfigForClient(&tls.ClientHelloInfo{
			ServerName: testPrivateServerName,
			Extensions: []uint16{echExtensionCodePoint},
			Conn:       conn,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// ApplyCoverProfile documents that it hands out the strict
		// configuration it was given, unmodified - classificationConfig
		// must forward exactly that pointer, not a copy, so a future
		// regression that started cloning or rebuilding it is caught here
		// rather than only showing up as a subtle behavioural drift.
		if selected != winn {
			t.Fatal("expected the exact strict Winn *tls.Config pointer, got a different value")
		}
		if !shim.live {
			t.Fatal("expected the shim to have been committed live before returning")
		}
	})
}
