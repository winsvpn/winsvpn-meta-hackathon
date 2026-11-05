package carrierhost

// Tests for the profile's trust anchor — the field that makes a CDN-fronted
// deployment expressible.
//
// The property that matters most is not that webpki works; it is that every way
// of half-configuring it is refused. A profile that reached the network with a
// public trust anchor AND a stable device certificate would hand a persistent
// device identifier to a fronting CDN and then be refused at the origin, and a
// profile that named webpki while keeping a private root would be a document
// whose author had not decided what it trusted.

import (
	"errors"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

// TestAbsentTrustAnchorMeansPrivateCA is the backward-compatibility guarantee:
// every profile written before this field existed keeps its exact behaviour.
func TestAbsentTrustAnchorMeansPrivateCA(t *testing.T) {
	profile, err := ParseProfile(encode(t, validProfile()))
	if err != nil {
		t.Fatal(err)
	}
	if profile.TrustAnchor != string(tlsconfig.TrustPrivateCA) {
		t.Fatalf("an absent trust_anchor resolved to %q", profile.TrustAnchor)
	}
	trust := profile.ClientTrust()
	if trust.Anchor != tlsconfig.TrustPrivateCA {
		t.Fatalf("ClientTrust anchor is %q", trust.Anchor)
	}
	if trust.RootCAPath != "/winn/ca.pem" {
		t.Fatalf("ClientTrust lost the root CA path: %q", trust.RootCAPath)
	}
}

func TestPrivateCAStillRequiresARootCAPath(t *testing.T) {
	profile := validProfile()
	profile.TrustAnchor = string(tlsconfig.TrustPrivateCA)
	profile.RootCAPath = ""
	_, err := ParseProfile(encode(t, profile))
	if err == nil || !strings.Contains(err.Error(), "root_ca_path") {
		t.Fatalf("private-ca without a root must be refused: %v", err)
	}
	// And the same with the field simply absent, which is the common case.
	profile.TrustAnchor = ""
	if _, err = ParseProfile(encode(t, profile)); err == nil ||
		!strings.Contains(err.Error(), "root_ca_path") {
		t.Fatalf("the default anchor must still require a root: %v", err)
	}
}

func TestUnknownTrustAnchorIsRefused(t *testing.T) {
	for _, anchor := range []string{"webpki ", "public", "system", "none"} {
		profile := validProfile()
		profile.TrustAnchor = anchor
		_, err := ParseProfile(encode(t, profile))
		if !errors.Is(err, tlsconfig.ErrTrustAnchorUnknown) {
			t.Fatalf("trust_anchor %q must be refused: %v", anchor, err)
		}
	}
}

// TestWebPKIRequiresAnonymousAuthorization is the coupling. Identity mode
// compares the signed claims against the mTLS certificate AT THE ORIGIN, and a
// TLS-terminating CDN is the mTLS peer, so the comparison has no input there.
func TestWebPKIRequiresAnonymousAuthorization(t *testing.T) {
	profile := validProfile()
	profile.TrustAnchor = string(tlsconfig.TrustWebPKI)
	profile.RootCAPath = ""
	profile.AuthorizationMode = carrierauth.AuthModeIdentity
	_, err := ParseProfile(encode(t, profile))
	if !errors.Is(err, tlsconfig.ErrTrustWebPKIWithClientCertificate) {
		t.Fatalf("webpki in identity mode must be refused: %v", err)
	}
}

// TestWebPKIRefusesAPrivateRootAsWell covers the shape a control plane could
// most plausibly produce by accident or by intent: flipping the anchor while
// the device-local root path stays where the host put it. The result is a
// refusal, not a widened trust store.
func TestWebPKIRefusesAPrivateRootAsWell(t *testing.T) {
	profile := validProfile()
	profile.TrustAnchor = string(tlsconfig.TrustWebPKI)
	// RootCAPath left as the host set it.
	_, err := ParseProfile(encode(t, profile))
	if !errors.Is(err, tlsconfig.ErrTrustRootCAConflict) {
		t.Fatalf("webpki alongside a private root must be refused: %v", err)
	}
}

// TestWebPKIReachesTheAnonymousRouteRefusal records exactly how far a fronted
// profile gets today.
//
// The trust anchor, the coupling and the TLS configuration are all in place and
// tested. What a fronted session still needs is an anonymous-token credential
// source in the profile format, which this host does not have — so a correctly
// formed fronted profile stops at ErrAnonymousRouteUnimplemented and not
// anywhere earlier. That is the honest state of the feature and this test is
// what will fail, loudly and in the right place, when the anonymous route
// lands.
func TestWebPKIReachesTheAnonymousRouteRefusal(t *testing.T) {
	profile := validProfile()
	profile.TrustAnchor = string(tlsconfig.TrustWebPKI)
	profile.RootCAPath = ""
	profile.AuthorizationMode = carrierauth.AuthModeAnonymousToken
	_, err := ParseProfile(encode(t, profile))
	if !errors.Is(err, ErrAnonymousRouteUnimplemented) {
		t.Fatalf("a well-formed fronted profile must stop at the anonymous "+
			"route and nowhere else, got: %v", err)
	}
}

func TestTrustAnchorAppearsInTheLogLineAndNamesNoPath(t *testing.T) {
	profile, err := ParseProfile(encode(t, validProfile()))
	if err != nil {
		t.Fatal(err)
	}
	line := profile.DescribeForLog()
	if !strings.Contains(line, "trust="+string(tlsconfig.TrustPrivateCA)) {
		t.Fatalf("the log line does not state the trust anchor: %s", line)
	}
	// The profile names private files; the log line must never carry one.
	for _, path := range []string{
		profile.RootCAPath, profile.ClientKeyPath, profile.DeviceSeedPath,
		profile.ControllerPinsPath, profile.ECHConfigListPath,
	} {
		if strings.Contains(line, path) {
			t.Fatalf("the log line leaked a credential path: %s", line)
		}
	}
}

func TestCarrierEndpointReadsTheCarriersOwnField(t *testing.T) {
	h3, err := ParseProfile(encode(t, validProfile()))
	if err != nil {
		t.Fatal(err)
	}
	if got := h3.CarrierEndpoint(); got != h3.MASQUETemplate {
		t.Fatalf("http3 endpoint is %q, want the MASQUE template", got)
	}

	raw := validProfile()
	raw.Carrier = CarrierHTTP2
	raw.MASQUETemplate = ""
	raw.H2URL = "https://carrier.invalid/winn/stream"
	h2, err := ParseProfile(encode(t, raw))
	if err != nil {
		t.Fatal(err)
	}
	if got := h2.CarrierEndpoint(); got != h2.H2URL {
		t.Fatalf("http2 endpoint is %q, want the H2 URL", got)
	}

	// An unset carrier has no endpoint rather than whichever field happens to
	// be populated, so a caller cannot get an endpoint for a carrier that was
	// never validated.
	if got := (Profile{H2URL: "https://x.invalid/"}).CarrierEndpoint(); got != "" {
		t.Fatalf("an unnamed carrier reported endpoint %q", got)
	}
}

// TestClientTrustOnARawProfileDefaultsToPrivateCA covers the accessor being
// called on a Profile that has not been through ParseProfile — which is how a
// caller assembling one in Go would reach it. The default must be the same on
// both routes or a hand-built profile would trust a different store than the
// same document loaded from disk.
func TestClientTrustOnARawProfileDefaultsToPrivateCA(t *testing.T) {
	raw := Profile{RootCAPath: "/winn/ca.pem"}
	trust := raw.ClientTrust()
	if trust.Anchor != tlsconfig.TrustPrivateCA {
		t.Fatalf("a raw profile resolved to anchor %q", trust.Anchor)
	}
	if trust.RootCAPath != "/winn/ca.pem" {
		t.Fatalf("a raw profile lost its root path: %q", trust.RootCAPath)
	}
	// And the log line must be safe to call on one too, since it is the first
	// thing a host prints and a panic there would kill the process before the
	// operator saw the real error.
	if line := raw.DescribeForLog(); !strings.Contains(line, "spa=off") ||
		!strings.Contains(line, "trust=private-ca") {
		t.Fatalf("raw profile log line is %q", line)
	}
}
