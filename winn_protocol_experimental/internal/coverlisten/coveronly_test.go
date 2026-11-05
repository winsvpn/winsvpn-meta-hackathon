package coverlisten_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/coverlisten"
)

// outerNameProber models a peer that does not hold the deployment's ECH key
// but knows the private server name. It offers an ECH extension under a key
// of its own, with the private name as the ECH config's public name, so the
// OUTER ClientHello carries the ECH code point and the private name in the
// clear. Go cannot decrypt the extension, processes the outer hello, and the
// profile selector sees exactly what a genuine inner hello would show it.
func outerNameProber(t *testing.T, outerName string) *tls.Config {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := key.PublicKey().Bytes()
	var contents []byte
	contents = append(contents, 9)
	contents = binary.BigEndian.AppendUint16(contents, 0x0020)
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(publicKey)))
	contents = append(contents, publicKey...)
	suites := binary.BigEndian.AppendUint16(nil, 0x0001)
	suites = binary.BigEndian.AppendUint16(suites, 0x0001)
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(suites)))
	contents = append(contents, suites...)
	contents = append(contents, 253, byte(len(outerName)))
	contents = append(contents, outerName...)
	contents = binary.BigEndian.AppendUint16(contents, 0)
	config := binary.BigEndian.AppendUint16(nil, 0xfe0d)
	config = binary.BigEndian.AppendUint16(config, uint16(len(contents)))
	config = append(config, contents...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(config)))
	list = append(list, config...)
	return &tls.Config{
		ServerName:                     "inner.example.net",
		MinVersion:                     tls.VersionTLS13,
		NextProtos:                     []string{"h2", "http/1.1"},
		EncryptedClientHelloConfigList: list,
	}
}

// leafSeenBy runs one handshake and returns the leaf the prober read, whether
// or not Go went on to accept it.
func leafSeenBy(t *testing.T, config *tls.Config, prober *tls.Config) *x509.Certificate {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		server := tls.Server(conn, config)
		_ = server.SetDeadline(time.Now().Add(handshakeTO))
		_ = server.Handshake()
	}()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), handshakeTO)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(handshakeTO))
	client := tls.Client(conn, prober)
	handshakeErr := client.Handshake()
	wg.Wait()
	if certs := client.ConnectionState().PeerCertificates; len(certs) > 0 {
		return certs[0]
	}
	var verification *tls.CertificateVerificationError
	if errors.As(handshakeErr, &verification) && len(verification.UnverifiedCertificates) > 0 {
		return verification.UnverifiedCertificates[0]
	}
	t.Fatalf("prober read no certificate (handshake: %v)", handshakeErr)
	return nil
}

func TestCoverOnlyListenerServesTheCoverLeafToAnOuterNameProber(t *testing.T) {
	material := newPKI(t)
	_, keys := echMaterial(t)
	winn := strictConfig(t, material, keys)
	winn.ClientAuth = tls.NoClientCert
	winn.ClientCAs = nil

	for _, shape := range []struct {
		name      string
		coverOnly bool
		wantWinn  bool
	}{
		// The record of why CoverOnly exists: with a selectable strict
		// profile, the outer-name prober used to be served the Winn leaf.
		// Tiering now requires an accepted ECH (tlsconfig, audit L08 F-5),
		// so even the selectable profile serves the cover leaf here.
		{"selectable strict profile", false, false},
		{"cover only", true, false},
	} {
		t.Run(shape.name, func(t *testing.T) {
			listener, err := coverlisten.Apply(coverlisten.Options{
				Winn:          winn,
				CoverALPN:     []string{"h2", "http/1.1"},
				CoverCertPath: material.coverCert,
				CoverKeyPath:  material.coverKey,
				ECHKeys:       keys,
				CoverOnly:     shape.coverOnly,
			})
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if shape.coverOnly && listener.PrivateServerName != "" {
				t.Fatalf("cover-only listener still records private name %q", listener.PrivateServerName)
			}
			if shape.coverOnly && listener.TLS.GetConfigForClient != nil {
				t.Fatal("cover-only listener still installs a profile selector")
			}
			leaf := leafSeenBy(t, listener.TLS, outerNameProber(t, privateName))
			issuer := leaf.Issuer.String()
			gotWinn := strings.Contains(issuer, winnCAName)
			if gotWinn != shape.wantWinn {
				t.Fatalf("outer-name prober was served a leaf issued by %q (winn=%v), want winn=%v",
					issuer, gotWinn, shape.wantWinn)
			}
			if !shape.wantWinn && !strings.Contains(issuer, coverCAName) {
				t.Fatalf("outer-name prober was served a leaf issued by %q, want the cover CA", issuer)
			}
		})
	}
}
