package linuxauto

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/directawg"
	"winsvpn.local/winnprotocol/internal/gatewaymanifest"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/internal/transparency"
)

func TestLoadVerifiedAutoDeploymentAndExplicitTrustCommit(
	t *testing.T,
) {
	now := time.Date(2026, 7, 24, 20, 0, 0, 0, time.UTC)
	signer, pins := runtimeDeploymentSigner(t)
	root := t.TempDir()
	manifestPath := filepath.Join(root, "manifest-v2.json")
	logPath := filepath.Join(root, "transparency.jsonl")
	statePath := filepath.Join(root, "trust-state-v2.json")
	profilePath := filepath.Join(root, "linux-profile.json")

	first := runtimeDeploymentManifest(t, now, signer)
	writeRuntimeManifest(t, manifestPath, first)
	firstDigest, err := gatewaymanifest.DigestV2(first)
	if err != nil {
		t.Fatal(err)
	}
	_, firstCheckpoint, err := transparency.Append(
		logPath, firstDigest, signer, pins, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, _, firstState, err :=
		gatewaymanifest.BootstrapTrustStateV2(
			manifestPath,
			logPath,
			firstCheckpoint,
			pins,
			now.Add(time.Second),
		)
	if err != nil {
		t.Fatal(err)
	}
	writeRuntimeTrustState(t, statePath, firstState)

	second := runtimeDeploymentManifest(
		t, now.Add(time.Minute), signer,
	)
	second.Sequence = 2
	second.PreviousDigest = firstDigest
	if err := gatewaymanifest.SignV2(&second, signer); err != nil {
		t.Fatal(err)
	}
	writeRuntimeManifest(t, manifestPath, second)
	secondDigest, err := gatewaymanifest.DigestV2(second)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := transparency.Append(
		logPath, secondDigest, signer, pins, now.Add(time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	profile := runtimeDeploymentProfile(
		now.Add(time.Minute), secondDigest,
	)
	if err := directawg.SignLinuxDeploymentProfile(
		&profile, signer,
	); err != nil {
		t.Fatal(err)
	}
	writeRuntimeJSON(t, profilePath, profile, 0o644)

	loaded, err := LoadVerifiedAutoDeployment(
		VerifiedAutoDeploymentConfig{
			ManifestPath:     manifestPath,
			NodeID:           "entry-auto",
			TransparencyLog:  logPath,
			TrustStatePath:   statePath,
			LinuxProfilePath: profilePath,
			ControllerPins:   pins,
			Now: func() time.Time {
				return now.Add(2 * time.Minute)
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ManifestDigest != secondDigest ||
		loaded.Node.ID != "entry-auto" ||
		loaded.LinuxInterface.MTU != 1280 ||
		loaded.LinuxVerification.DNSResolver != "10.66.0.53:53" ||
		loaded.NextTrustState.HighestSequence != 2 {
		t.Fatalf("loaded deployment = %#v", loaded)
	}
	before, err := gatewaymanifest.LoadTrustStateV2(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, firstState) {
		t.Fatal("loader advanced trust state before installation")
	}
	if err := loaded.CommitTrustState(); err != nil {
		t.Fatal(err)
	}
	after, err := gatewaymanifest.LoadTrustStateV2(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, loaded.NextTrustState) {
		t.Fatal("explicit trust-state commit did not persist next state")
	}
}

func TestLoadVerifiedAutoDeploymentRejectsProfileForOtherNode(
	t *testing.T,
) {
	now := time.Date(2026, 7, 24, 20, 0, 0, 0, time.UTC)
	signer, pins := runtimeDeploymentSigner(t)
	root := t.TempDir()
	manifestPath := filepath.Join(root, "manifest-v2.json")
	logPath := filepath.Join(root, "transparency.jsonl")
	statePath := filepath.Join(root, "trust-state-v2.json")
	profilePath := filepath.Join(root, "linux-profile.json")
	manifest := runtimeDeploymentManifest(t, now, signer)
	other := manifest.Nodes[0]
	other.Transports = append(
		[]gatewaymanifest.TransportV2(nil),
		manifest.Nodes[0].Transports...,
	)
	other.ID = "entry-other"
	other.Transports[0].ID = "direct-other"
	manifest.Nodes = append(manifest.Nodes, other)
	if err := gatewaymanifest.SignV2(&manifest, signer); err != nil {
		t.Fatal(err)
	}
	writeRuntimeManifest(t, manifestPath, manifest)
	digest, err := gatewaymanifest.DigestV2(manifest)
	if err != nil {
		t.Fatal(err)
	}
	_, checkpoint, err := transparency.Append(
		logPath, digest, signer, pins, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, _, state, err := gatewaymanifest.BootstrapTrustStateV2(
		manifestPath, logPath, checkpoint, pins, now.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	writeRuntimeTrustState(t, statePath, state)
	profile := runtimeDeploymentProfile(now, digest)
	profile.NodeID = "entry-other"
	profile.TransportID = "direct-other"
	if err := directawg.SignLinuxDeploymentProfile(
		&profile, signer,
	); err != nil {
		t.Fatal(err)
	}
	writeRuntimeJSON(t, profilePath, profile, 0o644)
	_, err = LoadVerifiedAutoDeployment(
		VerifiedAutoDeploymentConfig{
			ManifestPath:     manifestPath,
			NodeID:           "entry-auto",
			TransparencyLog:  logPath,
			TrustStatePath:   statePath,
			LinuxProfilePath: profilePath,
			ControllerPins:   pins,
			Now:              func() time.Time { return now.Add(time.Minute) },
		},
	)
	if err == nil || !strings.Contains(err.Error(), "different verified node") {
		t.Fatalf("cross-node profile error = %v", err)
	}
}

func runtimeDeploymentSigner(
	t testing.TB,
) (*pqauth.Signer, *pqauth.VerifierSet) {
	t.Helper()
	seed := make([]byte, 32)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	signer, err := pqauth.NewSigner(pqauth.MLDSA65, seed)
	clear(seed)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := signer.PublicBytes()
	verifier, err := pqauth.NewVerifier(
		signer.Algorithm(), publicKey,
	)
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

func runtimeDeploymentManifest(
	t testing.TB,
	now time.Time,
	signer *pqauth.Signer,
) gatewaymanifest.ManifestV2 {
	t.Helper()
	manifest := gatewaymanifest.ManifestV2{
		Format:        gatewaymanifest.FormatV2,
		Sequence:      1,
		IssuedAt:      now.Format(time.RFC3339Nano),
		ExpiresAt:     now.Add(24 * time.Hour).Format(time.RFC3339Nano),
		ControllerID:  "controller-auto",
		Suite:         "x25519-mlkem768",
		MinimumClient: gatewaymanifest.MinimumClientV3,
		Capabilities:  gatewaymanifest.RequiredV2Capabilities(),
		Nodes: []gatewaymanifest.NodeV2{{
			ID:           "entry-auto",
			OperatorID:   "operator-auto",
			Provider:     "vultr",
			Roles:        []string{gatewaymanifest.RoleCarrier},
			Capabilities: []string{"candidate-isolated-verification"},
			Transports: []gatewaymanifest.TransportV2{{
				ID:                  "direct-primary",
				Type:                connectivity.CarrierDirectAWG,
				Endpoint:            "192.0.2.10:51820",
				Suite:               "x25519-mlkem768",
				AuthenticationModes: []string{gatewaymanifest.AuthAWGPSK},
				PublicAWGKey:        runtimeDeploymentPublicKey(),
				MinInnerDatagram:    1200,
				MaxInnerDatagram:    1350,
				Capabilities: []string{
					"awg-handshake-readiness",
					"candidate-isolated-verification",
				},
			}},
		}},
	}
	if err := gatewaymanifest.SignV2(&manifest, signer); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func runtimeDeploymentPublicKey() string {
	return "nNOe1VBs+qdVjQGHgems9Xd3SO6gsrVl7+DM8y/EZAQ="
}

func runtimeDeploymentProfile(
	now time.Time,
	manifestDigest string,
) directawg.LinuxDeploymentProfile {
	return directawg.LinuxDeploymentProfile{
		Format:         directawg.LinuxDeploymentProfileFormat,
		ManifestDigest: manifestDigest,
		NodeID:         "entry-auto",
		TransportID:    "direct-primary",
		IssuedAt:       now.Format(time.RFC3339),
		ExpiresAt:      now.Add(12 * time.Hour).Format(time.RFC3339),
		Interface: directawg.LinuxInterfaceProfile{
			InnerAddressPool:    "10.66.0.0/24",
			AllowedIPs:          []string{"10.66.0.0/24"},
			VerificationRoutes:  []string{"10.66.0.0/24"},
			MTU:                 1280,
			ListenPortMin:       41100,
			ListenPortMax:       41200,
			PersistentKeepalive: 25,
			Obfuscation: directawg.AWGObfuscation{
				JC: 4, JMin: 12, JMax: 64,
				S1: 16, S2: 80, S3: 24, S4: 8,
				H1: 111111, H2: 222222,
				H3: 333333, H4: 444444,
			},
		},
		Probe: directawg.LinuxProbeProfile{
			DNSResolver:         "10.66.0.53:53",
			DNSQueryName:        "auto.invalid",
			ExpectedDNSAnswers:  []string{"10.66.0.9"},
			CanaryEndpoint:      "10.66.0.10:7007",
			TimeoutMilliseconds: 2000,
		},
	}
}

func writeRuntimeManifest(
	t testing.TB,
	path string,
	manifest gatewaymanifest.ManifestV2,
) {
	t.Helper()
	encoded, err := gatewaymanifest.EncodeV2(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.AtomicWrite(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeRuntimeTrustState(
	t testing.TB,
	path string,
	state gatewaymanifest.TrustStateV2,
) {
	t.Helper()
	encoded, err := gatewaymanifest.EncodeTrustStateV2(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.AtomicWrite(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeRuntimeJSON(
	t testing.TB,
	path string,
	value any,
	mode fs.FileMode,
) {
	t.Helper()
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if err := securefile.AtomicWrite(path, encoded, mode); err != nil {
		t.Fatal(err)
	}
}

func TestLoadLinuxDeploymentProfileRejectsUnknownAndExtraJSON(
	t *testing.T,
) {
	root := t.TempDir()
	path := filepath.Join(root, "profile.json")
	for _, payload := range [][]byte{
		[]byte(`{"unknown":true}`),
		[]byte(`{}` + "\n" + `{}`),
		bytes.Repeat([]byte("x"), (256<<10)+1),
	} {
		if err := securefile.AtomicWrite(path, payload, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := directawg.LoadLinuxDeploymentProfile(path); err == nil {
			t.Fatal("invalid Linux deployment profile loaded")
		}
	}
}
