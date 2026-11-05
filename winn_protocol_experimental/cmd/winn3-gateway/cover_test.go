package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"winsvpn.local/winnprotocol/internal/echconfig"
)

// Lab cover material shaped like coverlisten's own tests: a Winn leaf under a
// private CA, and a separate DV-shaped cover certificate with its issuing
// intermediate, plus an ECH key file LoadServerKeys will accept.
const (
	labCoverName   = "www.example.com"
	labCoverIssuer = "Example Trust Services R3"
	labWinnName    = "gateway-7.winn.invalid"
	labWinnCAName  = "Winn Protocol Experimental Lab CA"
)

type labCover struct {
	certPath      string
	keyPath       string
	coverCertPath string
	coverKeyPath  string
	echKeysPath   string
}

func (c labCover) apply(opts *serveOptions) {
	opts.certPath = c.certPath
	opts.keyPath = c.keyPath
	opts.coverCertPath = c.coverCertPath
	opts.coverKeyPath = c.coverKeyPath
	opts.echKeysPath = c.echKeysPath
}

func writeLabCover(t *testing.T) labCover {
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
	newLeaf := func(issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, template *x509.Certificate) ([]byte, *ecdsa.PrivateKey) {
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
		return der, key
	}
	writeKey := func(path string, key *ecdsa.PrivateKey) {
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatalf("marshal key: %v", err)
		}
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			t.Fatalf("write key: %v", err)
		}
	}

	winnCA, winnCAKey, _ := newCA(labWinnCAName)
	winnDER, winnKey := newLeaf(winnCA, winnCAKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: labWinnName},
		DNSNames:    []string{labWinnName},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	certPath := filepath.Join(dir, "server.pem")
	keyPath := filepath.Join(dir, "server-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: winnDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	writeKey(keyPath, winnKey)

	coverCA, coverCAKey, coverCADER := newCA(labCoverIssuer)
	coverDER, coverKey := newLeaf(coverCA, coverCAKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: labCoverName},
		DNSNames:    []string{labCoverName},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	coverCertPath := filepath.Join(dir, "cover.crt")
	coverKeyPath := filepath.Join(dir, "cover.key")
	var chain []byte
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: coverDER})...)
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: coverCADER})...)
	if err := os.WriteFile(coverCertPath, chain, 0o644); err != nil {
		t.Fatal(err)
	}
	writeKey(coverKeyPath, coverKey)

	_, keyFile, err := echconfig.Generate(labCoverName, 1)
	if err != nil {
		t.Fatalf("echconfig.Generate: %v", err)
	}
	encoded, err := echconfig.EncodeKeyFile(keyFile)
	if err != nil {
		t.Fatalf("echconfig.EncodeKeyFile: %v", err)
	}
	echPath := filepath.Join(dir, "ech-server-keys.json")
	if err := os.WriteFile(echPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	return labCover{
		certPath:      certPath,
		keyPath:       keyPath,
		coverCertPath: coverCertPath,
		coverKeyPath:  coverKeyPath,
		echKeysPath:   echPath,
	}
}

func TestRequireCoverFlagsNamesEachMissingInput(t *testing.T) {
	base := writeLabCover(t)
	opts := serveOptions{
		certPath:      base.certPath,
		keyPath:       base.keyPath,
		echKeysPath:   base.echKeysPath,
		coverCertPath: base.coverCertPath,
		coverKeyPath:  base.coverKeyPath,
	}
	if err := requireCoverFlags(opts); err != nil {
		t.Fatalf("complete cover material was refused: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*serveOptions)
		want   string
	}{
		{"no cert", func(o *serveOptions) { o.certPath = "" }, "-cert"},
		{"whitespace cert", func(o *serveOptions) { o.certPath = "  " }, "-cert"},
		{"no key", func(o *serveOptions) { o.keyPath = "" }, "-key"},
		{"no ech-keys", func(o *serveOptions) { o.echKeysPath = "" }, "-ech-keys"},
		{"no cover-cert", func(o *serveOptions) { o.coverCertPath = "" }, "-cover-cert"},
		{"no cover-key", func(o *serveOptions) { o.coverKeyPath = "" }, "-cover-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := opts
			tc.mutate(&o)
			err := requireCoverFlags(o)
			if err == nil {
				t.Fatal("missing cover material was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not name %q", err, tc.want)
			}
		})
	}

	waived := opts
	waived.coverCertPath = ""
	waived.coverKeyPath = ""
	waived.allowWinnLeafAsCover = true
	if err := requireCoverFlags(waived); err != nil {
		t.Fatalf("-insecure-cover-reuses-winn-leaf still required a cover cert: %v", err)
	}
}

func TestCoverFlagsAreRequiredBeforeTheSocketIsBound(t *testing.T) {
	held, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()

	opts := operatorValueOptions(t)
	opts.listen = held.LocalAddr().String()
	opts.certPath = ""
	opts.keyPath = ""
	opts.echKeysPath = ""
	opts.coverCertPath = ""
	opts.coverKeyPath = ""

	err = runServe(opts, new(bytes.Buffer))
	if err == nil {
		t.Fatal("runServe started with no cover material")
	}
	if !strings.Contains(err.Error(), "-cert") {
		t.Fatalf("refusal does not name -cert: %v", err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "address already in use") ||
		strings.Contains(strings.ToLower(err.Error()), "bind") {
		t.Fatalf("the socket was reached before the cover-flag check: %v", err)
	}

	// Control: the same held address WITH cover material must be a bind
	// failure, or this test would pass against a function that always
	// returns "-cert is required".
	withCover := operatorValueOptions(t)
	withCover.listen = held.LocalAddr().String()
	bindErr := runServe(withCover, new(bytes.Buffer))
	if bindErr == nil {
		t.Fatal("two processes bound the same UDP port")
	}
	if strings.Contains(bindErr.Error(), "-cert") {
		t.Fatalf("control with cover material still names -cert: %v", bindErr)
	}
}

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) snapshot() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.b.Bytes()...)
}

func waitListening(t *testing.T, buf *safeBuffer, done <-chan error, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("runServe exited before listening: %v\nstatus:\n%s", err, buf.snapshot())
		default:
		}
		for _, line := range bytes.Split(buf.snapshot(), []byte("\n")) {
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			var st serveStatus
			if json.Unmarshal(line, &st) != nil {
				continue
			}
			if st.Event == "listening" && st.Listen != "" {
				return st.Listen
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no listening event within %s:\n%s", timeout, buf.snapshot())
	return ""
}

func startCoverGateway(t *testing.T) string {
	t.Helper()
	opts := operatorValueOptions(t)
	opts.runFor = 4 * time.Second
	buf := &safeBuffer{}
	done := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		done <- runServe(opts, buf)
	}()
	t.Cleanup(wg.Wait)
	return waitListening(t, buf, done, 5*time.Second)
}

func TestAProberCompletesCoverHTTPSAndIsServedTheDecoy(t *testing.T) {
	listen := startCoverGateway(t)

	var state tls.ConnectionState
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	var lastErr error
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := tls.DialWithDialer(dialer, "tcp", listen, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
			ServerName:         labCoverName,
		})
		if err != nil {
			lastErr = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		state = raw.ConnectionState()
		_ = raw.Close()
		lastErr = nil
		break
	}
	if lastErr != nil {
		t.Fatalf("TLS dial to cover TCP port: %v", lastErr)
	}
	if len(state.PeerCertificates) == 0 {
		t.Fatal("handshake produced no peer certificate")
	}
	issuer := state.PeerCertificates[0].Issuer.CommonName
	if issuer != labCoverIssuer {
		t.Fatalf("prober saw issuer %q, want the cover CA %q (a Winn CA name means the cover profile was not served)",
			issuer, labCoverIssuer)
	}
	if strings.Contains(issuer, "Winn") {
		t.Fatalf("cover handshake presented a Winn issuer: %q", issuer)
	}
	if got := state.PeerCertificates[0].DNSNames; len(got) != 1 || got[0] != labCoverName {
		t.Fatalf("cover leaf DNS names = %v, want [%s]", got, labCoverName)
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"http/1.1"},
				ServerName:         labCoverName,
			},
		},
	}
	resp, err := client.Get("https://" + listen + "/")
	if err != nil {
		t.Fatalf("GET / through cover HTTPS: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		t.Fatalf("read cover body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cover GET / status %d, want 200; body %q", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("cover Content-Type %q, want text/html", ct)
	}
	if !bytes.Contains(bytes.ToLower(body), []byte("<html")) {
		t.Fatalf("cover body is not HTML: %q", body[:min(len(body), 200)])
	}
}

func TestAProberCompletesCoverQUIC(t *testing.T) {
	listen := startCoverGateway(t)

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
		ServerName:         labCoverName,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var lastErr error
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := quic.DialAddr(ctx, listen, tlsConf, &quic.Config{
			HandshakeIdleTimeout: 2 * time.Second,
		})
		if err != nil {
			lastErr = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		state := conn.ConnectionState().TLS
		_ = conn.CloseWithError(0, "")
		if len(state.PeerCertificates) == 0 {
			t.Fatal("QUIC handshake produced no peer certificate")
		}
		issuer := state.PeerCertificates[0].Issuer.CommonName
		if issuer != labCoverIssuer {
			t.Fatalf("QUIC prober saw issuer %q, want %q", issuer, labCoverIssuer)
		}
		return
	}
	t.Fatalf("QUIC dial to cover UDP port: %v", lastErr)
}

func TestUnauthenticatedUDPStillGetsSilence(t *testing.T) {
	listen := startCoverGateway(t)

	raddr, err := net.ResolveUDPAddr("udp4", listen)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	junk := make([]byte, 1025) // one byte past MaxHandshakeMessage: a stranger, no session
	if _, err := client.Write(junk); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	if n > 0 {
		t.Fatalf("unauthenticated UDP got %d bytes back; v3 must stay silent: %q", n, buf[:n])
	}
	if err == nil {
		t.Fatal("unauthenticated UDP read succeeded with 0 bytes; want a deadline")
	}
	if !os.IsTimeout(err) && !strings.Contains(strings.ToLower(err.Error()), "timeout") &&
		!strings.Contains(err.Error(), "deadline") {
		t.Fatalf("unauthenticated UDP error is %v, want a read timeout", err)
	}
}
