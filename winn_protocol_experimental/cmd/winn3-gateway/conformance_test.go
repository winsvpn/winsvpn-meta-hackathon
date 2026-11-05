package main

import (
	"os"
	"path/filepath"
	"testing"

	"winsvpn.local/winnprotocol/winn3/conform"
	"winsvpn.local/winnprotocol/winn3/core"
)

// The cross-host conformance adapter for THE GATEWAY THAT ANSWERS.
//
// This binary is the reference end. Every other host in the tree is trying to
// be admitted by it, and it is the only end that can refuse — in silence, with
// no response, no ICMP and no log line. So its derivation is not one opinion
// among five; it is the one the other four are measured against, and a defect
// here is invisible from every client in the fleet simultaneously.
//
// The adapter drives buildSessionConfig — the REAL function runServe calls —
// against conform.Reference(), through real files on disk, because the
// admission secret's encoding is a property of how the file is READ and a test
// that handed it bytes directly would not be testing that at all.

// winn3ConformanceOptions writes the reference operator's key material to disk
// and returns the serve options that name it.
//
// The admission file is written VERBATIM, trailing newline included, because
// `winn3-gateway -mode keygen` writes hex text with a newline and the
// "trim \r\n and stop" rule is what the suite is checking.
func winn3ConformanceOptions(t *testing.T, op conform.Operator) serveOptions {
	t.Helper()
	dir := t.TempDir()

	static, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	staticPath := filepath.Join(dir, "static.key")
	if err := os.WriteFile(staticPath, static.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	admissionPath := filepath.Join(dir, "admission.key")
	if err := os.WriteFile(admissionPath, []byte(op.AdmissionFile), 0o600); err != nil {
		t.Fatal(err)
	}

	return serveOptions{
		listen:     "127.0.0.1:0",
		staticPath: staticPath,
		admission:  admissionPath,
		gatewayID:  op.GatewayID,
		innerV4:    "10.64.0.1",
		plan:       "udp,tcp,tls",
		pathMTU:    op.PathMTU,
	}
}

// winn3ConformanceDerivation is what THIS host derives, through its own real
// code path.
func winn3ConformanceDerivation(t *testing.T, opts serveOptions) conform.Derivation {
	t.Helper()
	cfg, err := buildSessionConfig(opts)
	if err != nil {
		t.Fatalf("buildSessionConfig refused the reference operator configuration: %v", err)
	}
	// buildServeSizing, NOT driver.NewSizing. runServe calls this exact
	// function, so a gateway that ignored -path-mtu — or dropped a class out of
	// -plan — is caught here. Calling driver.NewSizing directly would make this
	// adapter agree with itself while runServe planned on something else, which
	// is precisely what the defect-3 mutation demonstrated on 2026-08-09 by
	// coming back MISSED.
	sizing, classes, err := buildServeSizing(opts)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(classes))
	for _, c := range classes {
		names = append(names, c.String())
	}
	return conform.FromCore(
		"cmd/winn3-gateway/main.go:buildSessionConfig+runServe (THE GATEWAY THAT ANSWERS)",
		cfg.Core.Gateway, sizing, names)
}

// TestGatewayConformsToTheCrossHostSuite is TIER A.
func TestGatewayConformsToTheCrossHostSuite(t *testing.T) {
	op := conform.Reference()
	want, err := conform.Expected(op)
	if err != nil {
		t.Fatal(err)
	}
	got := winn3ConformanceDerivation(t, winn3ConformanceOptions(t, op))
	want.MustMatch(t, got)
}

// TestGatewayAdmitsAnInitiationSealedFromTheReference is the property, not a
// proxy for it: a real initiation sealed under the reference admission profile
// must be READ by a responder built from what this binary derived.
//
// Hex equality would already have caught defect 1. This catches it in the
// currency the field failure was denominated in — "the gateway answered
// nothing" — and it would also catch a divergence in something the hex
// comparison does not cover, such as the tag length.
func TestGatewayAdmitsAnInitiationSealedFromTheReference(t *testing.T) {
	op := conform.Reference()
	client, err := conform.Expected(op)
	if err != nil {
		t.Fatal(err)
	}
	gateway := winn3ConformanceDerivation(t, winn3ConformanceOptions(t, op))
	if err := conform.AdmissionRoundTrip(client, gateway); err != nil {
		t.Fatal(err)
	}
}

// TestGatewayDoesNotDecodeTheAdmissionSecret is the negative control for the
// rule buildSessionConfig states in prose.
//
// It asserts the derived key IS the file's 64 hex characters and is NOT the 32
// bytes they encode. The comment above that line says decoding "cost a
// debugging cycle"; this is the test that makes the comment enforceable.
func TestGatewayDoesNotDecodeTheAdmissionSecret(t *testing.T) {
	op := conform.Reference()
	got := winn3ConformanceDerivation(t, winn3ConformanceOptions(t, op))
	if len(got.AdmissionKey) != 64 {
		t.Fatalf("the gateway keyed with %d bytes; the admission file holds 64 hex characters "+
			"and they ARE the secret. If this is 32, somebody added a hex.DecodeString and every "+
			"client in the fleet is now refused in silence.", len(got.AdmissionKey))
	}
	if string(got.AdmissionKey) != string(op.AdmissionSecret()) {
		t.Fatalf("the gateway's admission key is not the file's bytes:\n  got  %q\n  want %q",
			got.AdmissionKey, op.AdmissionSecret())
	}
}

// TestGatewayIDIsNotDecoded is the negative control for defect 1 at the one end
// that cannot be worked around.
func TestGatewayIDIsNotDecoded(t *testing.T) {
	op := conform.Reference()
	got := winn3ConformanceDerivation(t, winn3ConformanceOptions(t, op))
	if string(got.GatewayID) != op.GatewayID {
		t.Fatalf("the gateway derived gateway_id %q (%x) from the operator string %q. "+
			"Every client computes its tag over the operator string's raw bytes; a gateway "+
			"that derives anything else answers none of them.",
			got.GatewayID, got.GatewayID, op.GatewayID)
	}
	if len(got.GatewayID) != 8 {
		t.Fatalf("gateway_id is %d bytes, want 8 — %q base64-DECODES to 6, which is the "+
			"shape of defect 1", len(got.GatewayID), op.GatewayID)
	}
}

// TestGatewayPathMTUIsWhateverTheOperatorTyped is defect 3 at this end.
//
// The gateway's -path-mtu default is carrier.DefaultPathMTU and nothing
// negotiates it. This pins that the flag is honoured verbatim and that the
// default is the same number every client defaults to, which is the only thing
// standing between an operator and two ends with different plan floors.
// 1421 rather than the 1400 this walked until 2026-08-10: over the reference
// plan 1400 is inside the inner-IPv6 dead zone and driver.NewSizing refuses it,
// so it stopped being a path MTU an operator can type at all. 1421 is the exact
// value the zone ends at for [udp tcp tls] — 1280 + 29 bytes of v3 overhead +
// 112 for TLS over IPv6 — which keeps a case immediately below the fleet
// default and pins the boundary from the legal side.
func TestGatewayPathMTUIsWhateverTheOperatorTyped(t *testing.T) {
	for _, mtu := range []int{conform.DefaultPathMTU, 1421, 1500} {
		op := conform.Reference()
		op.PathMTU = mtu
		opts := winn3ConformanceOptions(t, op)
		got := winn3ConformanceDerivation(t, opts)
		if got.PathMTU != mtu {
			t.Errorf("-path-mtu %d produced a resolved path MTU of %d", mtu, got.PathMTU)
		}
		want, err := conform.Floor([]string{"udp", "tcp", "tls"}, mtu)
		if err != nil {
			t.Fatal(err)
		}
		if got.MessageSize != want.MessageSize || got.InnerMTU != want.InnerMTU {
			t.Errorf("at -path-mtu %d the gateway plans message_size=%d inner_mtu=%d; the "+
				"reference is %d/%d. A client on the other number sends messages this "+
				"gateway refuses in silence.",
				mtu, got.MessageSize, got.InnerMTU, want.MessageSize, want.InnerMTU)
		}
	}
}

// TestTheGatewayKeysWithTheOperatorValueUntrimmed pins the gateway's side of the
// whitespace divergence this suite found on 2026-08-09.
//
// buildSessionConfig uses strings.TrimSpace for the EMPTINESS CHECK and then
// keys with the value UNTRIMMED. Every INI-reading host trims instead —
// WinnV3Keys.from calls .trim(), linux/runner's parser Trim()s every value —
// so an operator value carrying one trailing space produces a 9-byte gateway id
// here and an 8-byte one on Android.
//
// Measured, not inferred:
//
//	cmd/winn3-gateway    77696e736777303120  (9 bytes)
//	apple/WinsTunnelCore 77696e736777303120  (9 bytes — agrees, because the
//	                                          descriptor's base64 hides the
//	                                          space from Swift's own trim)
//	android WinnV3Keys   77696e7367773031    (8 bytes — diverges)
//
// This test does not assert the divergence is acceptable. It pins what the
// AUTHORITY does, so that whoever unifies the rule has a fixed point to move
// from — and so that a change here is a decision rather than an accident.
//
// UPDATED 2026-08-09, and the update is the point of reading this comment. The
// divergence row it used to name — operator-value-whitespace-normalisation — is
// gone, closed by runServe REFUSING an edge-whitespace -gateway-id at the flag
// rather than by trimming it. So this test still passes and still means what it
// meant: buildSessionConfig keys with the operator's raw bytes, unchanged. What
// changed is that no such value can reach it through the real entry point any
// more. The adapter drives buildSessionConfig directly on purpose, so that the
// derivation the other four hosts are measured against is what the datagram
// path computes rather than what a start-up gate happened to allow. See the
// operator-value-whitespace-refused-at-the-flag pin in conform.RegressionPins,
// and cmd/winn3-gateway/operatorvalue_test.go for the refusal's own tests.
func TestTheGatewayKeysWithTheOperatorValueUntrimmed(t *testing.T) {
	op := conform.Reference()
	op.GatewayID = "winsgw01 " // one trailing space: a copy-paste, a heredoc
	got := winn3ConformanceDerivation(t, winn3ConformanceOptions(t, op))

	if string(got.GatewayID) != "winsgw01 " {
		t.Fatalf("the gateway keyed with %q (%x); it must key with the operator's value "+
			"UNTRIMMED, because that is the behaviour every host is currently measured "+
			"against. If the gateway now trims, the hosts that trim have been brought into "+
			"line and the operator-value-whitespace-normalisation row should be deleted — or "+
			"they have not, and this change just moved the divergence somewhere new.",
			got.GatewayID, got.GatewayID)
	}
	if len(got.GatewayID) != 9 {
		t.Fatalf("gateway_id is %d bytes, want 9", len(got.GatewayID))
	}

	// And the consequence, in the currency that matters: a client that trimmed
	// is not admitted by this gateway.
	trimmed := got
	trimmed.Host = "a host that trims the operator's gateway id (Android does)"
	trimmed.GatewayID = []byte("winsgw01")
	if err := conform.AdmissionRoundTrip(trimmed, got); err == nil {
		t.Fatal("a client that trimmed the trailing space was admitted by a gateway that " +
			"kept it. If that is now true the two ends normalise identically and this " +
			"divergence is closed.")
	}
}
