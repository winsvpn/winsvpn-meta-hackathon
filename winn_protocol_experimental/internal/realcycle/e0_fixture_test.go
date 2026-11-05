package realcycle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/directawg"
	"winsvpn.local/winnprotocol/internal/gatewaymanifest"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/realtopology"
	"winsvpn.local/winnprotocol/internal/transparency"
)

func writeRealE0Bundle(t *testing.T, parent, name string) string {
	t.Helper()
	bundle := filepath.Join(parent, name)
	if err := os.Mkdir(bundle, 0o700); err != nil {
		t.Fatal(err)
	}
	files := realE0PublicDocuments(t)
	inventory := make([]realtopology.PublicFile, 0, len(realtopology.AllowedPublicBasenames))
	for _, basename := range realtopology.AllowedPublicBasenames {
		data := files[basename]
		if err := os.WriteFile(filepath.Join(bundle, basename), data, 0o644); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		inventory = append(inventory, realtopology.PublicFile{
			Name: basename, Size: int64(len(data)),
			SHA256: hex.EncodeToString(digest[:]),
		})
	}
	descriptor := realtopology.Descriptor{
		Schema: realtopology.Schema, TopologyID: "generated-four-node-fixture",
		Protocol: realtopology.ProtocolVersion, LiveReady: false,
		ExercisedNodes: []string{},
		Deployments: []realtopology.Deployment{
			{
				Role:         realtopology.RoleControl,
				InstanceUUID: "11111111-1111-4111-8111-111111111111",
				NodeID:       "controller-1", ServiceID: "service-controller-1",
				Provider: "provider-a", OperatorID: "operator-control",
			},
			{
				Role:         realtopology.RoleEntryPrimary,
				InstanceUUID: "22222222-2222-4222-8222-222222222222",
				NodeID:       "entry-primary-node", ServiceID: "entry-primary-service",
				Provider: "provider-a", OperatorID: "operator-entry",
			},
			{
				Role:         realtopology.RoleEntrySecondary,
				InstanceUUID: "33333333-3333-4333-8333-333333333333",
				NodeID:       "entry-secondary-node", ServiceID: "entry-secondary-service",
				Provider: "provider-a", OperatorID: "operator-entry",
			},
			{
				Role:         realtopology.RoleExit,
				InstanceUUID: "44444444-4444-4444-8444-444444444444",
				NodeID:       "exit-node", ServiceID: "exit-service",
				Provider: "provider-b", OperatorID: "operator-exit",
			},
		},
		Files: inventory,
	}
	data, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(
		filepath.Join(bundle, realtopology.DescriptorName), data, 0o644,
	); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func realE0PublicDocuments(t *testing.T) map[string][]byte {
	t.Helper()
	now := time.Date(2026, 7, 27, 20, 0, 0, 0, time.UTC)
	signer, err := pqauth.NewSigner(pqauth.MLDSA65, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	rawAWG := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	directNode := func(
		id, operator, provider, role, transportID, endpoint string,
	) gatewaymanifest.NodeV2 {
		return gatewaymanifest.NodeV2{
			ID: id, OperatorID: operator, Provider: provider,
			Roles: []string{gatewaymanifest.RoleCarrier, role},
			Transports: []gatewaymanifest.TransportV2{{
				ID: transportID, Type: connectivity.CarrierDirectAWG,
				Endpoint: endpoint, Suite: "x25519-mlkem768",
				AuthenticationModes: []string{gatewaymanifest.AuthAWGPSK},
				PublicAWGKey:        rawAWG, MinInnerDatagram: 1200,
				MaxInnerDatagram: 1350,
				Capabilities: []string{
					"awg-handshake-readiness",
					"candidate-isolated-verification",
				},
			}},
			Capabilities: []string{
				"active-probe-resistant",
				"candidate-isolated-verification",
			},
		}
	}
	manifest := gatewaymanifest.ManifestV2{
		Format: gatewaymanifest.FormatV2, Sequence: 1,
		IssuedAt:     now.Format(time.RFC3339Nano),
		ExpiresAt:    now.Add(24 * time.Hour).Format(time.RFC3339Nano),
		ControllerID: "controller-1", Suite: "x25519-mlkem768",
		MinimumClient: gatewaymanifest.MinimumClientV3,
		Capabilities:  gatewaymanifest.RequiredV2Capabilities(),
		Nodes: []gatewaymanifest.NodeV2{
			directNode(
				"entry-primary-node", "operator-entry", "provider-a",
				gatewaymanifest.RoleEntry, "entry-primary-service",
				"192.0.2.10:51820",
			),
			directNode(
				"entry-secondary-node", "operator-entry", "provider-a",
				gatewaymanifest.RoleEntry, "entry-secondary-service",
				"192.0.2.11:51820",
			),
			directNode(
				"exit-node", "operator-exit", "provider-b",
				gatewaymanifest.RoleExit, "exit-service",
				"192.0.2.12:51820",
			),
		},
	}
	if err := gatewaymanifest.SignV2(&manifest, signer); err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := gatewaymanifest.EncodeV2(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest, err := gatewaymanifest.DigestV2(manifest)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := pqauth.VerifierSetDocument(signer)
	if err != nil {
		t.Fatal(err)
	}
	pinsBytes, err := json.Marshal(pins)
	if err != nil {
		t.Fatal(err)
	}
	pinsBytes = append(pinsBytes, '\n')
	receipt, err := transparency.NewReceipt(1, manifestDigest, "", signer, now)
	if err != nil {
		t.Fatal(err)
	}
	receiptDigest, err := transparency.Digest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes = append(receiptBytes, '\n')
	trustBytes, err := gatewaymanifest.EncodeTrustStateV2(
		gatewaymanifest.TrustStateV2{
			Format:          gatewaymanifest.TrustStateFormatV2,
			HighestSequence: 1, ManifestDigest: manifestDigest,
			Checkpoint: transparency.Checkpoint{
				Size: 1, ReceiptDigest: receiptDigest,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	profile := directawg.LinuxDeploymentProfile{
		Format:         directawg.LinuxDeploymentProfileFormat,
		ManifestDigest: manifestDigest, NodeID: "entry-primary-node",
		TransportID: "entry-primary-service",
		IssuedAt:    now.Format(time.RFC3339),
		ExpiresAt:   now.Add(24 * time.Hour).Format(time.RFC3339),
		Interface: directawg.LinuxInterfaceProfile{
			InnerAddressPool:   "10.77.0.0/24",
			AllowedIPs:         []string{"0.0.0.0/0"},
			VerificationRoutes: []string{"10.66.0.0/24"},
			MTU:                1280, ListenPortMin: 40000, ListenPortMax: 40100,
			PersistentKeepalive: 25,
			Obfuscation: directawg.AWGObfuscation{
				JC: 4, JMin: 12, JMax: 64, S1: 16, S2: 80,
				S3: 24, S4: 8, H1: 101, H2: 202, H3: 303, H4: 404,
			},
		},
		Probe: directawg.LinuxProbeProfile{
			DNSResolver: "10.66.0.53:53", DNSQueryName: "canary.winn.invalid",
			ExpectedDNSAnswers: []string{"10.66.0.9"},
			CanaryEndpoint:     "10.66.0.9:7007", TimeoutMilliseconds: 3000,
		},
	}
	if err := directawg.SignLinuxDeploymentProfile(&profile, signer); err != nil {
		t.Fatal(err)
	}
	profileBytes, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	profileBytes = append(profileBytes, '\n')
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Winn generated test carrier root"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	certificateDER, err := x509.CreateCertificate(
		rand.Reader, template, template, private.Public(), private,
	)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER},
	)
	return map[string][]byte{
		"accepted-trust-state-v2.json": trustBytes,
		"carrier-root-ca.pem":          certificatePEM,
		"controller-pq-pins.json":      pinsBytes,
		"gateway-manifest-v2.json":     manifestBytes,
		"linux-profile.json":           profileBytes,
		"transparency.jsonl":           receiptBytes,
	}
}
