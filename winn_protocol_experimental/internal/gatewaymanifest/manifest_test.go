package gatewaymanifest

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/internal/transparency"
)

func TestManifestSignVerifyDigestAndTamper(t *testing.T) {
	signer, pins := manifestTestKeys(t)
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	manifest := validManifest(t, now)
	if err := Sign(&manifest, signer); err != nil {
		t.Fatal(err)
	}
	if err := Verify(manifest, pins, now.Add(time.Minute), time.Minute); err != nil {
		t.Fatal(err)
	}
	digest, err := Digest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != 64 {
		t.Fatalf("digest length = %d", len(digest))
	}
	manifest.Nodes[0].ServerName = "attacker.invalid"
	if err := Verify(manifest, pins, now.Add(time.Minute), time.Minute); err == nil {
		t.Fatal("tampered manifest verified")
	}
}

func TestManifestFailClosedValidation(t *testing.T) {
	signer, pins := manifestTestKeys(t)
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"expired", func(m *Manifest) {
			m.IssuedAt = now.Add(-2 * time.Hour).Format(time.RFC3339Nano)
			m.ExpiresAt = now.Add(-time.Hour).Format(time.RFC3339Nano)
		}},
		{"missing-ech-capability", func(m *Manifest) {
			m.Capabilities = []string{"adaptive-inner-mtu", "happy-eyeballs-v2", "signed-gateway-manifest"}
		}},
		{"classical-suite", func(m *Manifest) { m.Suite = "x25519" }},
		{"open-ended-h2-url", func(m *Manifest) {
			m.Nodes[0].H2URL = "https://gateway.example/open-proxy"
		}},
		{"invalid-address-hint", func(m *Manifest) {
			m.Nodes[0].IPv6Hints = []string{"192.0.2.1"}
		}},
		{"malformed-ech", func(m *Manifest) {
			m.Nodes[0].ECHConfigList = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 16)))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := validManifest(t, now)
			test.mutate(&manifest)
			if err := Sign(&manifest, signer); err != nil {
				if test.name == "expired" {
					// An expired document is structurally signable.
					t.Fatal(err)
				}
				return
			}
			if err := Verify(manifest, pins, now, time.Minute); err == nil {
				t.Fatal("invalid manifest verified")
			}
		})
	}
}

func TestManifestNodeSelectionDoesNotAcceptUnknownNode(t *testing.T) {
	manifest := validManifest(t, time.Now().UTC())
	if _, err := manifest.Node("missing"); err == nil {
		t.Fatal("unknown node accepted")
	}
	node, err := manifest.Node("primary")
	if err != nil {
		t.Fatal(err)
	}
	if node.ServerName != "gateway.example" {
		t.Fatalf("selected node = %#v", node)
	}
}

func TestLoadVerifiedNodeRequiresPinnedTransparencyInclusion(t *testing.T) {
	signer, pins := manifestTestKeys(t)
	now := time.Now().UTC()
	manifest := validManifest(t, now)
	if err := Sign(&manifest, signer); err != nil {
		t.Fatal(err)
	}
	manifestData, err := Encode(manifest)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "manifest.json")
	logPath := filepath.Join(directory, "transparency.jsonl")
	checkpointPath := filepath.Join(directory, "checkpoint.json")
	if err := securefile.AtomicWrite(manifestPath, manifestData, 0o644); err != nil {
		t.Fatal(err)
	}
	digest, err := Digest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	_, checkpoint, err := transparency.Append(
		logPath, digest, signer, pins, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	checkpointData, _ := json.Marshal(checkpoint)
	if err := securefile.AtomicWrite(checkpointPath, checkpointData, 0o644); err != nil {
		t.Fatal(err)
	}
	_, node, gotDigest, gotCheckpoint, err := LoadVerifiedNode(
		manifestPath, "primary", logPath, checkpointPath, pins,
		now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if node.ID != "primary" || gotDigest != digest ||
		gotCheckpoint != checkpoint {
		t.Fatal("verified deployment did not preserve node, digest, and checkpoint")
	}
	checkpoint.Size++
	checkpointData, _ = json.Marshal(checkpoint)
	if err := securefile.AtomicWrite(checkpointPath, checkpointData, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := LoadVerifiedNode(
		manifestPath, "primary", logPath, checkpointPath, pins,
		now.Add(time.Minute),
	); err == nil {
		t.Fatal("mismatched externally retained checkpoint was accepted")
	}
}

func manifestTestKeys(t *testing.T) (*pqauth.Signer, *pqauth.VerifierSet) {
	t.Helper()
	seed := make([]byte, 32)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	signer, err := pqauth.NewSigner(pqauth.MLDSA65, seed)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := signer.PublicBytes()
	verifier, err := pqauth.NewVerifier(pqauth.MLDSA65, publicKey)
	clear(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := pqauth.NewVerifierSet(verifier)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pins
}

func TestManifestRejectsClockSkewAboveFrozenMaximum(t *testing.T) {
	signer, pins := manifestTestKeys(t)
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	manifest := validManifest(t, now)
	if err := Sign(&manifest, signer); err != nil {
		t.Fatal(err)
	}
	if err := Verify(manifest, pins, now, DefaultClockSkew+time.Nanosecond); err == nil {
		t.Fatal("v1 verifier accepted clock skew above frozen maximum")
	}
	if err := Verify(manifest, pins, now, -time.Nanosecond); err == nil {
		t.Fatal("v1 verifier accepted negative clock skew")
	}
}

func validManifest(t testing.TB, now time.Time) Manifest {
	t.Helper()
	echList, _, err := echconfig.Generate("cover.example", 1)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := RequiredCapabilities()
	return Manifest{
		Format:         Format,
		Sequence:       1,
		IssuedAt:       now.Format(time.RFC3339Nano),
		ExpiresAt:      now.Add(24 * time.Hour).Format(time.RFC3339Nano),
		ControllerID:   "controller-1",
		Suite:          "x25519-mlkem768",
		MinimumClient:  "winn/2.1",
		Capabilities:   capabilities,
		PreviousDigest: "",
		Nodes: []Node{{
			ID:                  "primary",
			MASQUETemplate:      "https://gateway.example/.well-known/masque/udp/{target_host}/{target_port}/",
			H2URL:               "https://gateway.example/winn/v2/udp-stream",
			ServerName:          "gateway.example",
			IPv4Hints:           []string{"192.0.2.1"},
			IPv6Hints:           []string{"2001:db8::1"},
			ECHConfigList:       base64.StdEncoding.EncodeToString(echList),
			MaxInnerDatagram:    1350,
			AuthenticationModes: []string{AuthIdentity, AuthAnonymousToken},
			Capabilities:        capabilities,
		}},
	}
}
