package main

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"winsvpn.local/winnprotocol/internal/coverlisten"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/pki"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
)

const labTLSSuite = "x25519-mlkem768"

// TestTLSDialNoLongerHardRefusesTheClass is the cheap proof that class=tls is
// no longer a compile-time "cannot be dialled" regardless of profile fields.
// The files do not exist, so the dial must fail at tlsconfig / echconfig load,
// not at the old hard refuse.
func TestTLSDialNoLongerHardRefusesTheClass(t *testing.T) {
	profile, err := loadWinn3Profile(writeProfile(t, validTLSProfile()))
	if err != nil {
		t.Fatalf("valid tls profile refused at load: %v", err)
	}
	sizing, err := driver.NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS)
	if err != nil {
		t.Fatal(err)
	}
	admission := make([]byte, 32)
	_, err = winn3DialCarrier(context.Background(), profile, sizing, admission)
	if err == nil {
		t.Fatal("dialled with nonexistent TLS material")
	}
	if strings.Contains(err.Error(), "cannot be dialled") {
		t.Fatalf("class=tls is still hard-refused: %v", err)
	}
}

func TestAWebPKITLSProfileWithAClientCertIsTheTypedError(t *testing.T) {
	document := validTLSProfile()
	c := document["carrier"].(map[string]any)
	c["trust_anchor"] = "webpki"
	delete(c, "root_ca_path")
	c["server_name"] = "cdn.example"
	_, err := loadWinn3Profile(writeProfile(t, document))
	if err == nil {
		t.Fatal("accepted webpki plus a client certificate")
	}
	if !errors.Is(err, tlsconfig.ErrTrustWebPKIWithClientCertificate) {
		t.Fatalf("want ErrTrustWebPKIWithClientCertificate, got %v", err)
	}
}

func TestTheTLSLogLineCarriesNoPath(t *testing.T) {
	profile, err := loadWinn3Profile(writeProfile(t, validTLSProfile()))
	if err != nil {
		t.Fatal(err)
	}
	line := profile.describeForLog()
	for _, forbidden := range []string{
		"/nonexistent", "ca.pem", "ech.bin", "client.pem", "client.key",
		"winn.example", "198.51.100.7",
	} {
		if strings.Contains(line, forbidden) {
			t.Fatalf("the log line leaks %q: %s", forbidden, line)
		}
	}
	for _, required := range []string{
		"carrier=tls", "trust=private-ca", "ech_list=true", "client_cert=true",
	} {
		if !strings.Contains(line, required) {
			t.Fatalf("the log line omits %q: %s", required, line)
		}
	}
}

// TestTheTLSCarrierDialsThroughTlsconfig is the positive proof: a loopback
// TLS 1.3 listener built with internal/tlsconfig + mandatory ECH, a v3 host
// profile naming that material, and winn3DialCarrier returning ClassTLS.
// A DialTCP downgrade would be ClassTCP and this test would fail.
func TestTheTLSCarrierDialsThroughTlsconfig(t *testing.T) {
	paths, err := pki.GenerateLab(
		t.TempDir()+"/pki", "winn3-tls.example", "winn3-tls-1", time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("generate lab PKI: %v", err)
	}
	suite, err := tlsconfig.ParseSuite(labTLSSuite)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := tlsconfig.ServerForALPN(
		paths.ServerCert, paths.ServerKey, paths.CACert, suite, winn3TLSDefaultALPN,
	)
	if err != nil {
		t.Fatal(err)
	}
	echKeys, err := echconfig.LoadServerKeys(paths.ECHServerKeys)
	if err != nil {
		t.Fatal(err)
	}
	if err := echconfig.ConfigureServer(serverTLS, echKeys, true); err != nil {
		t.Fatal(err)
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
	}()

	document := validTLSProfile()
	carrierSpec := document["carrier"].(map[string]any)
	carrierSpec["endpoint"] = listener.Addr().String()
	carrierSpec["root_ca_path"] = paths.CACert
	carrierSpec["ech_config_list_path"] = paths.ECHConfigList
	carrierSpec["client_cert_path"] = paths.DeviceCert
	carrierSpec["client_key_path"] = paths.DeviceKey
	carrierSpec["server_name"] = "winn3-tls.example"
	carrierSpec["suite"] = labTLSSuite

	profile, err := loadWinn3Profile(writeProfile(t, document))
	if err != nil {
		t.Fatalf("tls profile refused: %v", err)
	}
	sizing, err := driver.NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS)
	if err != nil {
		t.Fatal(err)
	}
	admission := make([]byte, 32)
	for i := range admission {
		admission[i] = byte(i + 1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := winn3DialCarrier(ctx, profile, sizing, admission)
	if err != nil {
		t.Fatalf("winn3DialCarrier: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if got := conn.Class(); got != carrier.ClassTLS {
		t.Fatalf("stream class is %s, want %s (a TCP dial would be a silent downgrade)",
			got, carrier.ClassTLS)
	}
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not complete the handshake")
	}
}

// TestTheTLSDefaultALPNMatchesTheGatewayCoverWinnProfile pins the host-profile
// default to the ALPN cmd/winn3-gateway/cover.go puts on the Winn strict
// profile (http2.NextProtoTLS). A mismatch fails the handshake after ECH is
// accepted, which is how a dialable client still cannot reach the cover
// listener.
func TestTheTLSDefaultALPNMatchesTheGatewayCoverWinnProfile(t *testing.T) {
	if winn3TLSDefaultALPN != http2.NextProtoTLS {
		t.Fatalf("default ALPN is %q, gateway cover Winn profile offers %q",
			winn3TLSDefaultALPN, http2.NextProtoTLS)
	}
}

// TestTheTLSCarrierDialsACoverListener is the coordination with the cover
// listener: the same assembly cmd/winn3-gateway/cover.go uses
// (ServerAnonymousForALPN + h2 + coverlisten.Apply + mandatory ECH), a v3
// host profile naming that material, and winn3DialCarrier returning ClassTLS.
// A raw tls.Listen without a cover profile would still prove the client
// speaks TLS; this one proves it reaches the Winn profile behind the cover.
func TestTheTLSCarrierDialsACoverListener(t *testing.T) {
	const privateName = "winn3-tls.example"
	paths, err := pki.GenerateLab(
		t.TempDir()+"/cover-pki", privateName, "winn3-tls-1", time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("generate lab PKI: %v", err)
	}
	suite, err := tlsconfig.ParseSuite(labTLSSuite)
	if err != nil {
		t.Fatal(err)
	}
	winnTLS, err := tlsconfig.ServerAnonymousForALPN(
		paths.ServerCert, paths.ServerKey, suite, http2.NextProtoTLS,
	)
	if err != nil {
		t.Fatalf("strict Winn TLS: %v", err)
	}
	echKeys, err := echconfig.LoadServerKeys(paths.ECHServerKeys)
	if err != nil {
		t.Fatal(err)
	}
	if err := echconfig.ConfigureServer(winnTLS, echKeys, true); err != nil {
		t.Fatal(err)
	}
	built, err := coverlisten.Apply(coverlisten.Options{
		Winn:                      winnTLS,
		CoverALPN:                 []string{http2.NextProtoTLS, "http/1.1"},
		CoverServerName:           privateName,
		ECHKeys:                   echKeys,
		RequestsClientCertificate: false,
		AllowWinnLeafAsCover:      true,
	})
	if err != nil {
		t.Fatalf("coverlisten.Apply: %v", err)
	}
	if err := coverlisten.Verify(built.TLS); err != nil {
		t.Fatalf("cover listener is not probe resistant: %v", err)
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", built.TLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	negotiated := make(chan string, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			negotiated <- "not-tls"
			return
		}
		if hsErr := tlsConn.Handshake(); hsErr != nil {
			negotiated <- "handshake-err"
			return
		}
		negotiated <- tlsConn.ConnectionState().NegotiatedProtocol
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
	}()

	document := validTLSProfile()
	carrierSpec := document["carrier"].(map[string]any)
	carrierSpec["endpoint"] = listener.Addr().String()
	carrierSpec["root_ca_path"] = paths.CACert
	carrierSpec["ech_config_list_path"] = paths.ECHConfigList
	carrierSpec["client_cert_path"] = paths.DeviceCert
	carrierSpec["client_key_path"] = paths.DeviceKey
	carrierSpec["server_name"] = privateName
	carrierSpec["suite"] = labTLSSuite

	profile, err := loadWinn3Profile(writeProfile(t, document))
	if err != nil {
		t.Fatalf("tls profile refused: %v", err)
	}
	sizing, err := driver.NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS)
	if err != nil {
		t.Fatal(err)
	}
	admission := make([]byte, 32)
	for i := range admission {
		admission[i] = byte(i + 1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := winn3DialCarrier(ctx, profile, sizing, admission)
	if err != nil {
		t.Fatalf("winn3DialCarrier against coverlisten.Apply: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if got := conn.Class(); got != carrier.ClassTLS {
		t.Fatalf("stream class is %s, want %s (a TCP dial would be a silent downgrade)",
			got, carrier.ClassTLS)
	}
	select {
	case alpn := <-negotiated:
		if alpn != http2.NextProtoTLS {
			t.Fatalf("cover Winn profile negotiated ALPN %q, want %q",
				alpn, http2.NextProtoTLS)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cover listener did not complete the handshake")
	}
}
