package main

// buildH2Listener is where -reality-relay-target's on/off behaviour is
// actually decided, so it is the right place for an executed proof of the
// two claims that flag's help text makes: "empty leaves every listener's
// behaviour byte-for-byte what it is today" (TestBuildH2ListenerOffIsANoOp)
// and "a non-empty target really routes through internal/reality, not just
// a config field that is thereafter ignored" (TestBuildH2ListenerOnWrapsWithReality).

import (
	"encoding/base64"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/gatewaymanifest"
	"winsvpn.local/winnprotocol/internal/observability"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/reality"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/internal/transparency"
)

func TestBuildH2ListenerOffIsANoOp(t *testing.T) {
	classified, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer classified.Close()

	metrics := observability.New()
	got, err := buildH2Listener(classified, nil, reality.Target{}, metrics)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != classified {
		t.Fatal(
			"expected the exact same listener back when -reality-relay-target " +
				"is empty, got a different value - the off case must be " +
				"'internal/reality is never called', not 'internal/reality is " +
				"called with an empty target', or this claim is not actually true",
		)
	}
}

func TestBuildH2ListenerOnWrapsWithReality(t *testing.T) {
	classified, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer classified.Close()

	metrics := observability.New()
	// Cover is deliberately nil: reality.Listen itself refuses that
	// (internal/reality's own tests cover the full accept/relay behaviour),
	// so seeing exactly that refusal here - rather than a silent success, or
	// some other error - is the proof that a non-empty target really does
	// reach internal/reality and does not, say, silently fall back to
	// returning classified unwrapped.
	_, err = buildH2Listener(
		classified, nil, reality.Target{Address: "127.0.0.1:1"}, metrics,
	)
	if err == nil {
		t.Fatal(
			"expected an error: a non-empty target with a nil Cover " +
				"configuration must reach reality.Listen's own refusal",
		)
	}
	if !strings.Contains(err.Error(), "cover") {
		t.Fatalf("expected reality.Listen's nil-Cover refusal, got: %v", err)
	}
}

// LoadVerifiedNodeV2 returns an advanced pin but does not persist it. The
// carrier must, or the retained state stays at its bootstrap sequence: the
// second rotation is then refused as a sequence gap and an older manifest
// stays replayable across restarts.
func TestManifestV2TrustStateCommitAllowsRotationAndRefusesRollback(t *testing.T) {
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	signer, pins := testCarrierV2Signer(t)
	defer signer.Destroy()
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest-v2.json")
	logPath := filepath.Join(dir, "transparency.jsonl")
	statePath := filepath.Join(dir, "trust-state-v2.json")

	publish := func(sequence uint64, previous string, at time.Time) string {
		t.Helper()
		manifest := testCarrierManifestV2(t, at, signer, sequence, previous)
		encoded, err := gatewaymanifest.EncodeV2(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := securefile.AtomicWrite(manifestPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		digest, err := gatewaymanifest.DigestV2(manifest)
		if err != nil {
			t.Fatal(err)
		}
		return digest
	}
	load := func(at time.Time) (gatewaymanifest.TrustStateV2, error) {
		_, _, _, next, err := gatewaymanifest.LoadVerifiedNodeV2(
			manifestPath, "entry-nyc", logPath, statePath, pins, at,
		)
		return next, err
	}

	firstDigest := publish(1, "", now)
	_, firstCheckpoint, err := transparency.Append(logPath, firstDigest, signer, pins, now)
	if err != nil {
		t.Fatal(err)
	}
	_, _, bootState, err := gatewaymanifest.BootstrapTrustStateV2(
		manifestPath, logPath, firstCheckpoint, pins, now.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := commitManifestV2TrustState(statePath, bootState); err != nil {
		t.Fatal(err)
	}

	secondDigest := publish(2, firstDigest, now.Add(time.Minute))
	if _, _, err := transparency.Append(logPath, secondDigest, signer, pins, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	second, err := load(now.Add(2 * time.Minute))
	if err != nil {
		t.Fatalf("rotation to sequence 2: %v", err)
	}
	// Control: without the commit (the old behaviour) sequence 3 is refused.
	thirdDigest := publish(3, secondDigest, now.Add(2*time.Minute))
	if _, _, err := transparency.Append(logPath, thirdDigest, signer, pins, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := load(now.Add(3 * time.Minute)); err == nil ||
		!strings.Contains(err.Error(), "gap") {
		t.Fatalf("uncommitted pin then sequence 3 = %v, want the sequence-gap refusal", err)
	}

	// With the commit, rollback to 1 is refused and 3 is accepted.
	if err := commitManifestV2TrustState(statePath, second); err != nil {
		t.Fatal(err)
	}
	persisted, err := gatewaymanifest.LoadTrustStateV2(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.HighestSequence != 2 || persisted.ManifestDigest != secondDigest {
		t.Fatalf("persisted pin = %d %s, want 2 %s",
			persisted.HighestSequence, persisted.ManifestDigest, secondDigest)
	}
	third, err := load(now.Add(3 * time.Minute))
	if err != nil {
		t.Fatalf("rotation to sequence 3 after commit: %v", err)
	}
	if err := commitManifestV2TrustState(statePath, third); err != nil {
		t.Fatal(err)
	}
	publish(1, "", now)
	if _, err := load(now.Add(3 * time.Minute)); err == nil ||
		!strings.Contains(err.Error(), "rollback") {
		t.Fatalf("replayed sequence 1 = %v, want the rollback refusal", err)
	}
}

func testCarrierV2Signer(t testing.TB) (*pqauth.Signer, *pqauth.VerifierSet) {
	t.Helper()
	seed := make([]byte, 32)
	for index := range seed {
		seed[index] = byte(0x21 + index)
	}
	signer, err := pqauth.NewSigner(pqauth.MLDSA65, seed)
	clear(seed)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := pqauth.NewVerifier(signer.Algorithm(), signer.PublicBytes())
	if err != nil {
		t.Fatal(err)
	}
	pins, err := pqauth.NewVerifierSet(verifier)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pins
}

func testCarrierManifestV2(
	t testing.TB, now time.Time, signer *pqauth.Signer,
	sequence uint64, previousDigest string,
) gatewaymanifest.ManifestV2 {
	t.Helper()
	echList, _, err := echconfig.Generate("cover.example", 1)
	if err != nil {
		t.Fatal(err)
	}
	manifest := gatewaymanifest.ManifestV2{
		Format:         gatewaymanifest.FormatV2,
		Sequence:       sequence,
		PreviousDigest: previousDigest,
		IssuedAt:       now.Format(time.RFC3339Nano),
		ExpiresAt:      now.Add(24 * time.Hour).Format(time.RFC3339Nano),
		ControllerID:   "controller-1",
		Suite:          "x25519-mlkem768",
		MinimumClient:  gatewaymanifest.MinimumClientV3,
		Capabilities:   gatewaymanifest.RequiredV2Capabilities(),
		Nodes: []gatewaymanifest.NodeV2{{
			ID:           "entry-nyc",
			OperatorID:   "vultr-entry",
			Provider:     "vultr",
			Roles:        []string{gatewaymanifest.RoleCarrier},
			Capabilities: []string{"candidate-isolated-verification"},
			Transports: []gatewaymanifest.TransportV2{{
				ID:                  "h3-primary",
				Type:                connectivity.CarrierHTTP3,
				Endpoint:            "https://gateway.example/.well-known/masque/udp/{target_host}/{target_port}/",
				ServerName:          "gateway.example",
				ECHConfigList:       base64.StdEncoding.EncodeToString(echList),
				ALPN:                []string{"h3"},
				PublicTarget:        "winn.invalid:443",
				Suite:               "x25519-mlkem768",
				AuthenticationModes: []string{gatewaymanifest.AuthIdentity},
				PublicAWGKey:        "nNOe1VBs+qdVjQGHgems9Xd3SO6gsrVl7+DM8y/EZAQ=",
				FixedBackend:        "127.0.0.1:51820",
				MinInnerDatagram:    1200,
				MaxInnerDatagram:    1350,
				Capabilities:        []string{"attempt-binding", "fixed-backend"},
			}},
		}},
	}
	if err := gatewaymanifest.SignV2(&manifest, signer); err != nil {
		t.Fatal(err)
	}
	return manifest
}
