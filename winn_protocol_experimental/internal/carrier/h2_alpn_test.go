package carrier

import (
	"crypto/tls"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

// newALPNProbeDialer builds a dialer exactly as the product does, through
// NewH2Dialer, so these tests break if the shipped constructor stops deciding
// the ALPN list. It never connects; only the configuration is under test.
//
// The caller-supplied TLS config deliberately requests http2.NextProtoTLS
// alone, matching what cmd/ passes. That makes the widening observable: if
// NewH2Dialer stopped adding the fallback, NextProtos would be the one-element
// list this helper handed it.
func newALPNProbeDialer(t *testing.T) *H2Dialer {
	t.Helper()

	lab := generateCarrierLab(t)
	suite, err := tlsconfig.ParseSuite("x25519-mlkem768")
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := tlsconfig.ClientForALPN(
		lab.DeviceCert, lab.DeviceKey, lab.CACert,
		"127.0.0.1", suite, http2.NextProtoTLS,
	)
	if err != nil {
		t.Fatal(err)
	}
	deviceSigner, err := pqauth.LoadSigner(pqauth.MLDSA65, lab.DevicePQ65Seed)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := pqauth.LoadVerifierSet(lab.ControllerPQPins)
	if err != nil {
		t.Fatal(err)
	}
	responseVerifier := &carrierauth.ResponseVerifier{
		Verifiers:    pins,
		ControllerID: "lab-controller",
		Suite:        suite.Name,
		MaxSkew:      time.Minute,
	}
	dialer, err := NewH2Dialer(
		"https://127.0.0.1:443"+H2Path,
		"winn.invalid:443",
		lab.DeviceID,
		"00112233445566778899aabbccddeeff",
		suite,
		clientTLS,
		deviceSigner,
		responseVerifier,
	)
	if err != nil {
		t.Fatal(err)
	}
	return dialer
}

// TestNewH2DialerOffersBrowserShapedALPN pins the ALPN list the shipped H2
// dialer builds.
//
// ALPN is sent in the clear in the outer ClientHello even under ECH, so the
// offer is visible to a passive observer. Every browser dialing TCP offers h2
// and http/1.1 together; this client offered h2 alone, which is a list no
// ordinary client produces and therefore a selector requiring no probing.
//
// The companion test is TestOuterALPNMatchesABrowserOverTCP in
// internal/tlsconfig, which captures a real first flight and asserts both
// protocols reach the wire in order. Two tests are needed because this package
// imports internal/tlsconfig, so the capture harness there cannot reach
// NewH2Dialer without an import cycle: that test proves the bytes, this one
// proves the shipped constructor produces them.
func TestNewH2DialerOffersBrowserShapedALPN(t *testing.T) {
	dialer := newALPNProbeDialer(t)

	want := []string{http2.NextProtoTLS, "http/1.1"}
	if !slices.Equal(dialer.TLSConfig.NextProtos, want) {
		t.Fatalf("NextProtos = %v, want %v; a single-protocol ALPN is a "+
			"discriminator no browser produces",
			dialer.TLSConfig.NextProtos, want)
	}
}

// TestNewH2DialerStillRequiresH2 is the other half, and the reason widening the
// offer is safe.
//
// Advertising http/1.1 must not make it reachable. The dialer's
// VerifyConnection calls ValidatePeerProfile with http2.NextProtoTLS and fails
// closed on anything else, so a server selecting the fallback is refused at the
// same handshake position as before. If this test ever fails, the offer has
// become a real protocol fallback and the H2 carrier can be downgraded off its
// own transport.
func TestNewH2DialerStillRequiresH2(t *testing.T) {
	dialer := newALPNProbeDialer(t)

	verify := dialer.TLSConfig.VerifyConnection
	if verify == nil {
		t.Fatal("no VerifyConnection installed; the ALPN requirement is unenforced")
	}
	for _, negotiated := range []string{"http/1.1", "h3", ""} {
		t.Run("rejects_"+negotiated, func(t *testing.T) {
			state := tls.ConnectionState{
				Version:            tls.VersionTLS13,
				NegotiatedProtocol: negotiated,
			}
			if err := verify(state); err == nil {
				t.Fatalf("negotiating %q was accepted; only h2 may be", negotiated)
			}
		})
	}
}
