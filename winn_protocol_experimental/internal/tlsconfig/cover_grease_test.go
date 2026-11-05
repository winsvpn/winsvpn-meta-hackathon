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
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// These tests run over a buffered in-memory pipe instead of the
// loopback harness in cover_test.go, so the GREASE shape can be
// exercised with a stock Go client: a wrong-key ECH config whose
// public_name is the private name puts the private name in the
// cleartext outer SNI with an undecryptable ECH extension, which is
// exactly what a crafted prober hello does.

type bufferedPipeConn struct {
	r   <-chan []byte
	w   chan<- []byte
	buf []byte
}

func (p *bufferedPipeConn) Read(b []byte) (int, error) {
	for len(p.buf) == 0 {
		chunk, ok := <-p.r
		if !ok {
			return 0, net.ErrClosed
		}
		p.buf = chunk
	}
	n := copy(b, p.buf)
	p.buf = p.buf[n:]
	return n, nil
}

func (p *bufferedPipeConn) Write(b []byte) (int, error) {
	p.w <- append([]byte(nil), b...)
	return len(b), nil
}

func (p *bufferedPipeConn) Close() error                     { return nil }
func (p *bufferedPipeConn) LocalAddr() net.Addr              { return pipeAddr{} }
func (p *bufferedPipeConn) RemoteAddr() net.Addr             { return pipeAddr{} }
func (p *bufferedPipeConn) SetDeadline(time.Time) error      { return nil }
func (p *bufferedPipeConn) SetReadDeadline(time.Time) error  { return nil }
func (p *bufferedPipeConn) SetWriteDeadline(time.Time) error { return nil }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

func bufferedPipe() (net.Conn, net.Conn) {
	ab := make(chan []byte, 256)
	ba := make(chan []byte, 256)
	return &bufferedPipeConn{r: ba, w: ab}, &bufferedPipeConn{r: ab, w: ba}
}

func echConfigForPublicName(t *testing.T, configID byte, pub []byte, publicName string) []byte {
	t.Helper()
	var contents []byte
	contents = append(contents, configID)
	contents = binary.BigEndian.AppendUint16(contents, testKEMX25519)
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(pub)))
	contents = append(contents, pub...)
	suites := binary.BigEndian.AppendUint16(nil, testKDFHKDF256)
	suites = binary.BigEndian.AppendUint16(suites, testAEADAES128)
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(suites)))
	contents = append(contents, suites...)
	contents = append(contents, 253, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = binary.BigEndian.AppendUint16(contents, 0)
	config := binary.BigEndian.AppendUint16(nil, testECHVersion)
	config = binary.BigEndian.AppendUint16(config, uint16(len(contents)))
	return append(config, contents...)
}

type greaseHarness struct {
	cover      *tls.Config
	pool       *x509.CertPool
	clientCert tls.Certificate
	echList    []byte
}

func newGreaseHarness(t *testing.T) *greaseHarness {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Distinctive Winn CA"},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	mkLeaf := func(cn string, usages []x509.ExtKeyUsage, dns []string) tls.Certificate {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			DNSNames: dns, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages,
		}, caCert, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: k}
	}
	serverCert := mkLeaf("server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		[]string{testPublicName, testPrivateName})
	clientCert := mkLeaf("device", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	echKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	echConfig := buildTestECHConfig(t, echKey.PublicKey().Bytes())
	echList := binary.BigEndian.AppendUint16(nil, uint16(len(echConfig)))
	echList = append(echList, echConfig...)
	winn := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: pool,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519MLKEM768},
		SessionTicketsDisabled: true, NextProtos: []string{"h2"},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{
			{Config: echConfig, PrivateKey: echKey.Bytes(), SendAsRetry: true},
		},
	}
	cover, err := ApplyCoverProfile(winn, CoverProfile{
		PrivateServerName:    testPrivateName,
		CoverALPN:            []string{"h2", "http/1.1"},
		AllowWinnLeafAsCover: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	cover.EncryptedClientHelloKeys = winn.EncryptedClientHelloKeys
	return &greaseHarness{cover: cover, pool: pool, clientCert: clientCert, echList: echList}
}

func (h *greaseHarness) handshake(t *testing.T, clientCfg *tls.Config, cas *int) (clientErr, serverErr error, state tls.ConnectionState) {
	t.Helper()
	c1, c2 := bufferedPipe()
	done := make(chan error, 1)
	go func() {
		s := tls.Server(c2, h.cover)
		done <- s.Handshake()
		s.Close()
	}()
	c := tls.Client(c1, clientCfg)
	clientErr = c.Handshake()
	go func() {
		buf := make([]byte, 1024)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	}()
	serverErr = <-done
	return clientErr, serverErr, c.ConnectionState()
}

// A prober that knows the private name and sends a GREASE /
// wrong-key ECH extension with it as the cleartext outer SNI must
// stay on the cover profile: ECH was not accepted, so no client
// certificate may be demanded and no CA name may leak.
func TestCoverProfileGreaseECHDoesNotTier(t *testing.T) {
	h := newGreaseHarness(t)
	atkKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	atkConfig := echConfigForPublicName(t, 99, atkKey.PublicKey().Bytes(), testPrivateName)
	atkList := binary.BigEndian.AppendUint16(nil, uint16(len(atkConfig)))
	atkList = append(atkList, atkConfig...)
	cas := 0
	clientCfg := &tls.Config{
		ServerName: testPrivateName, RootCAs: h.pool,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		CurvePreferences:               []tls.CurveID{tls.X25519MLKEM768},
		NextProtos:                     []string{"h2"},
		EncryptedClientHelloConfigList: atkList,
		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cas = len(cri.AcceptableCAs)
			return &tls.Certificate{}, nil
		},
	}
	_, serverErr, _ := h.handshake(t, clientCfg, &cas)
	if cas > 0 {
		t.Fatalf("grease ECH leaked %d CA name(s) to an unauthenticated prober", cas)
	}
	if serverErr != nil && strings.Contains(serverErr.Error(), "certificate") {
		t.Fatalf("grease ECH selected the strict profile (server demanded a client certificate): %v", serverErr)
	}
}

// The other half: a genuine client doing real ECH still tiers.
func TestCoverProfileGenuineECHStillTiersOverPipe(t *testing.T) {
	h := newGreaseHarness(t)
	cas := 0
	clientCfg := &tls.Config{
		ServerName: testPrivateName, RootCAs: h.pool,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		CurvePreferences:               []tls.CurveID{tls.X25519MLKEM768},
		NextProtos:                     []string{"h2"},
		EncryptedClientHelloConfigList: h.echList,
		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cas = len(cri.AcceptableCAs)
			return &h.clientCert, nil
		},
	}
	clientErr, serverErr, state := h.handshake(t, clientCfg, &cas)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("genuine ECH client broken: client=%v server=%v", clientErr, serverErr)
	}
	if !state.ECHAccepted || cas == 0 {
		t.Fatalf("genuine ECH client did not reach strict profile: accepted=%v cas=%d", state.ECHAccepted, cas)
	}
}

// assertGenuineECHTiers runs one real handshake from a genuine Winn ECH
// client and fails unless it reached the strict profile.
func (h *greaseHarness) assertGenuineECHTiers(t *testing.T, after string) {
	t.Helper()
	cas := 0
	clientCfg := &tls.Config{
		ServerName: testPrivateName, RootCAs: h.pool,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		CurvePreferences:               []tls.CurveID{tls.X25519MLKEM768},
		NextProtos:                     []string{"h2"},
		EncryptedClientHelloConfigList: h.echList,
		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cas = len(cri.AcceptableCAs)
			return &h.clientCert, nil
		},
	}
	clientErr, serverErr, state := h.handshake(t, clientCfg, &cas)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("genuine ECH client broken after %s: client=%v server=%v", after, clientErr, serverErr)
	}
	if !state.ECHAccepted || cas == 0 {
		t.Fatalf("genuine ECH client locked out of the strict profile after %s: accepted=%v cas=%d", after, state.ECHAccepted, cas)
	}
}

// Every ordinary browser that offers GREASE ECH to the cover name reaches
// GetConfigForClient with the cover SNI. Its outer-name record must be
// consumed there too, or the table fills after maxOuterECHNames visitors
// and every genuine Winn client falls to the cover profile until restart.
func TestCoverProfileCoverNameGreaseECHDoesNotFillOuterNames(t *testing.T) {
	h := newGreaseHarness(t)
	for i := 0; i < maxOuterECHNames+16; i++ {
		conn, _ := bufferedPipe()
		hello := &tls.ClientHelloInfo{
			Conn:       conn,
			ServerName: testPublicName,
			Extensions: []uint16{extensionEncryptedClientHello},
		}
		if _, err := h.cover.GetEncryptedClientHelloKeys(hello); err != nil {
			t.Fatal(err)
		}
		selected, err := h.cover.GetConfigForClient(hello)
		if err != nil || selected != nil {
			t.Fatalf("cover-name GREASE hello selected %v, %v; want the cover profile", selected, err)
		}
	}
	h.assertGenuineECHTiers(t, "cover-name GREASE ECH visitors")
}

// A hello whose ECH extension Go cannot parse, or whose decrypted inner
// hello Go cannot decode, is aborted after GetEncryptedClientHelloKeys and
// before GetConfigForClient (crypto/tls readClientHello and
// processECHClientHello). Such residue must age out instead of filling
// the table for good.
func TestCoverProfileAbortedECHHellosDoNotFillOuterNames(t *testing.T) {
	h := newGreaseHarness(t)
	for i := 0; i < maxOuterECHNames+16; i++ {
		conn, _ := bufferedPipe()
		hello := &tls.ClientHelloInfo{
			Conn:       conn,
			ServerName: testPublicName,
			Extensions: []uint16{extensionEncryptedClientHello},
		}
		if _, err := h.cover.GetEncryptedClientHelloKeys(hello); err != nil {
			t.Fatal(err)
		}
	}
	h.assertGenuineECHTiers(t, "aborted ECH hellos")
}

// The table never holds more than maxOuterECHNames records, evicts the
// oldest first, and a consumed or re-recorded connection is not evicted
// by its stale ring slot.
func TestOuterECHNamesEvictsOldestAndStaysBounded(t *testing.T) {
	var o outerECHNames
	conns := make([]net.Conn, maxOuterECHNames+5)
	for i := range conns {
		conns[i], _ = bufferedPipe()
	}
	for i := 0; i < maxOuterECHNames; i++ {
		o.record(conns[i], "outer")
	}
	// conns[1] is consumed and conns[2] recorded again before the wrap.
	if _, ok := o.consume(conns[1]); !ok {
		t.Fatal("live record not found")
	}
	o.record(conns[2], "again")
	for i := maxOuterECHNames; i < len(conns); i++ {
		o.record(conns[i], "outer")
	}
	if len(o.byConn) > maxOuterECHNames {
		t.Fatalf("table holds %d records, cap %d", len(o.byConn), maxOuterECHNames)
	}
	if _, ok := o.consume(conns[0]); ok {
		t.Fatal("oldest record survived the wrap")
	}
	if name, ok := o.consume(conns[2]); !ok || name != "again" {
		t.Fatalf("re-recorded connection evicted by its stale slot: %q %v", name, ok)
	}
	if _, ok := o.consume(conns[len(conns)-1]); !ok {
		t.Fatal("newest record missing")
	}
}
