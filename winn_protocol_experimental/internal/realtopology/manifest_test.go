package realtopology

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
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/directawg"
	"winsvpn.local/winnprotocol/internal/gatewaymanifest"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/transparency"
)

func TestValidateBundle(t *testing.T) {
	bundle := writeValidBundle(t)
	result, err := ValidateBundle(bundle)
	if err != nil {
		t.Fatalf("ValidateBundle: %v", err)
	}
	if result.TopologyID != "generated-four-node-fixture" ||
		result.PublicFileCount != len(AllowedPublicBasenames) ||
		len(result.DescriptorSHA256) != 64 ||
		len(result.BundleSHA256) != 64 {
		t.Fatalf("unexpected result: %+v", result)
	}
	data, err := os.ReadFile(filepath.Join(bundle, DescriptorName))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if result.DescriptorSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf(
			"DescriptorSHA256 = %q, want file digest %q",
			result.DescriptorSHA256, hex.EncodeToString(sum[:]),
		)
	}
}

func TestValidateRetainedRoot(t *testing.T) {
	if _, err := ValidateRetainedRoot(nil); err == nil ||
		!strings.Contains(err.Error(), "retained bundle root is required") {
		t.Fatalf("nil root error = %v", err)
	}
	bundle := writeValidBundle(t)
	want, err := ValidateBundle(bundle)
	if err != nil {
		t.Fatalf("ValidateBundle: %v", err)
	}
	root, err := os.OpenRoot(bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	got, err := ValidateRetainedRoot(root)
	if err != nil {
		t.Fatalf("ValidateRetainedRoot: %v", err)
	}
	if got != want {
		t.Fatalf("ValidateRetainedRoot %+v != ValidateBundle %+v", got, want)
	}
}

func TestValidateBundleRejectsGarbageLinuxProfileSignature(t *testing.T) {
	bundle := writeValidBundle(t)
	path := filepath.Join(bundle, "linux-profile.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var profile directawg.LinuxDeploymentProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(profile.AuthSignature)
	if err != nil || len(raw) == 0 {
		t.Fatalf("fixture signature not strict Base64: %v len=%d", err, len(raw))
	}
	raw[0] ^= 1
	profile.AuthSignature = base64.StdEncoding.EncodeToString(raw)
	out, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	rebindFile(t, bundle, "linux-profile.json")
	_, err = ValidateBundle(bundle)
	if err == nil || !strings.Contains(err.Error(), "invalid Winn ML-DSA signature") {
		t.Fatalf("error = %v, want invalid Winn ML-DSA signature", err)
	}
}

func TestValidateBundleRejectsDescriptorDefects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Descriptor)
		want   string
	}{
		{
			name: "live ready",
			mutate: func(document *Descriptor) {
				document.LiveReady = true
			},
			want: "live_ready",
		},
		{
			name: "exercised node",
			mutate: func(document *Descriptor) {
				document.ExercisedNodes = []string{"entry-primary-node"}
			},
			want: "empty exercised_nodes",
		},
		{
			name: "missing deployment",
			mutate: func(document *Descriptor) {
				document.Deployments = document.Deployments[:3]
			},
			want: "exactly 4",
		},
		{
			name: "duplicate instance",
			mutate: func(document *Descriptor) {
				document.Deployments[2].InstanceUUID =
					document.Deployments[1].InstanceUUID
			},
			want: "UUIDs must be unique",
		},
		{
			name: "duplicate logical ID",
			mutate: func(document *Descriptor) {
				document.Deployments[2].ServiceID =
					document.Deployments[1].NodeID
			},
			want: "globally unique",
		},
		{
			name: "entry exit provider collision",
			mutate: func(document *Descriptor) {
				document.Deployments[1].Provider =
					document.Deployments[3].Provider
			},
			want: "provider and operator separation",
		},
		{
			name: "entry exit operator collision",
			mutate: func(document *Descriptor) {
				document.Deployments[2].OperatorID =
					document.Deployments[3].OperatorID
			},
			want: "provider and operator separation",
		},
		{
			name: "manifest deployment mismatch",
			mutate: func(document *Descriptor) {
				document.Deployments[1].NodeID = "unbound-entry-node"
			},
			want: "absent from manifest",
		},
		{
			name: "inventory order",
			mutate: func(document *Descriptor) {
				document.Files[0], document.Files[1] =
					document.Files[1], document.Files[0]
			},
			want: "file inventory row",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundle := writeValidBundle(t)
			document := readDescriptor(t, bundle)
			test.mutate(&document)
			writeDescriptor(t, bundle, document)
			_, err := ValidateBundle(bundle)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestValidateBundleRejectsUnknownDuplicateAndSecretFields(t *testing.T) {
	tests := []struct {
		name string
		edit func(string) string
		want string
	}{
		{
			name: "unknown",
			edit: func(data string) string {
				return strings.Replace(
					data, `"schema":`, `"unexpected":1,"schema":`, 1,
				)
			},
			want: "unknown field",
		},
		{
			name: "duplicate",
			edit: func(data string) string {
				return strings.Replace(
					data,
					`"schema":"`+Schema+`"`,
					`"schema":"`+Schema+`","schema":"`+Schema+`"`,
					1,
				)
			},
			want: "duplicate JSON field",
		},
		{
			name: "secret named",
			edit: func(data string) string {
				return strings.Replace(
					data, `"schema":`, `"private_key":"x","schema":`, 1,
				)
			},
			want: "secret-named JSON field",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundle := writeValidBundle(t)
			path := filepath.Join(bundle, DescriptorName)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(test.edit(string(data))), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err = ValidateBundle(bundle)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestSecretFieldInspectionAllowsPublicCredentialMetadata(t *testing.T) {
	if err := inspectJSONNames([]byte(
		`{"credential_domain":"public-scope","credential_key_id":"public-key-id"}`,
	)); err != nil {
		t.Fatalf("public credential metadata was rejected: %v", err)
	}
	for _, field := range []string{
		"private_key", "device_pq_seed", "provider_api_token", "psk",
	} {
		if err := inspectJSONNames([]byte(
			`{"` + field + `":"forbidden"}`,
		)); err == nil {
			t.Fatalf("secret field %q was accepted", field)
		}
	}
}

func TestInspectJSONNamesEnforcesNestingDepth(t *testing.T) {
	if err := inspectJSONNames(nestedJSONArray(MaxJSONDepth)); err != nil {
		t.Fatalf("depth %d was rejected: %v", MaxJSONDepth, err)
	}

	for _, depth := range []int{
		MaxJSONDepth + 1,
		MaxJSONDepth + 32,
		4096,
	} {
		err := inspectJSONNames(nestedJSONArray(depth))
		if err == nil || !strings.Contains(
			err.Error(), "JSON nesting exceeds limit",
		) {
			t.Fatalf(
				"depth %d error = %v, want nesting-limit rejection",
				depth,
				err,
			)
		}
	}
}

func FuzzInspectJSONNamesNestingDepth(f *testing.F) {
	for _, depth := range []int{
		0,
		1,
		MaxJSONDepth - 1,
		MaxJSONDepth,
		MaxJSONDepth + 1,
		64,
		4096,
	} {
		f.Add(depth)
	}
	f.Fuzz(func(t *testing.T, depth int) {
		if depth < 0 || depth > 4096 {
			t.Skip()
		}
		err := inspectJSONNames(nestedJSONArray(depth))
		if depth <= MaxJSONDepth {
			if err != nil {
				t.Fatalf("depth %d was rejected: %v", depth, err)
			}
			return
		}
		if err == nil || !strings.Contains(
			err.Error(), "JSON nesting exceeds limit",
		) {
			t.Fatalf(
				"depth %d error = %v, want nesting-limit rejection",
				depth,
				err,
			)
		}
	})
}

func nestedJSONArray(depth int) []byte {
	var document strings.Builder
	document.Grow(depth*2 + len("null"))
	document.WriteString(strings.Repeat("[", depth))
	document.WriteString("null")
	document.WriteString(strings.Repeat("]", depth))
	return []byte(document.String())
}

func TestValidateBundleRejectsFilesystemAndContentDefects(t *testing.T) {
	t.Run("extra file", func(t *testing.T) {
		bundle := writeValidBundle(t)
		if err := os.WriteFile(
			filepath.Join(bundle, "extra.json"), []byte("{}\n"), 0o644,
		); err != nil {
			t.Fatal(err)
		}
		_, err := ValidateBundle(bundle)
		if err == nil || !strings.Contains(err.Error(), "contains 8 entries") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		bundle := writeValidBundle(t)
		target := filepath.Join(bundle, AllowedPublicBasenames[0])
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(AllowedPublicBasenames[1], target); err != nil {
			t.Fatal(err)
		}
		_, err := ValidateBundle(bundle)
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		bundle := writeValidBundle(t)
		if err := os.Link(
			filepath.Join(bundle, AllowedPublicBasenames[0]),
			filepath.Join(t.TempDir(), "alias"),
		); err != nil {
			t.Skipf("hardlinks unavailable: %v", err)
		}
		_, err := ValidateBundle(bundle)
		if err == nil || !strings.Contains(err.Error(), "hardlinks") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("digest mismatch", func(t *testing.T) {
		bundle := writeValidBundle(t)
		path := filepath.Join(bundle, AllowedPublicBasenames[0])
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data[0] ^= 1
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err = ValidateBundle(bundle)
		if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("unsigned manifest metadata", func(t *testing.T) {
		bundle := writeValidBundle(t)
		manifestPath := filepath.Join(bundle, "gateway-manifest-v2.json")
		if err := os.WriteFile(
			manifestPath,
			[]byte(`{"format":"winn-gateway-manifest/v2"}`+"\n"),
			0o644,
		); err != nil {
			t.Fatal(err)
		}
		rebindFile(t, bundle, "gateway-manifest-v2.json")
		_, err := ValidateBundle(bundle)
		if err == nil || !strings.Contains(
			err.Error(), "validate gateway manifest",
		) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("secret field in public input", func(t *testing.T) {
		bundle := writeValidBundle(t)
		path := filepath.Join(bundle, "controller-pq-pins.json")
		if err := os.WriteFile(
			path, []byte(`{"private_key":"forbidden"}`+"\n"), 0o644,
		); err != nil {
			t.Fatal(err)
		}
		rebindFile(t, bundle, "controller-pq-pins.json")
		_, err := ValidateBundle(bundle)
		if err == nil || !strings.Contains(
			err.Error(), "secret-named JSON field",
		) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("schema-invalid public input", func(t *testing.T) {
		bundle := writeValidBundle(t)
		path := filepath.Join(bundle, "accepted-trust-state-v2.json")
		if err := os.WriteFile(
			path, []byte(`{"fixture":"not-a-trust-state"}`+"\n"), 0o644,
		); err != nil {
			t.Fatal(err)
		}
		rebindFile(t, bundle, "accepted-trust-state-v2.json")
		_, err := ValidateBundle(bundle)
		if err == nil || !strings.Contains(
			err.Error(), "validate accepted trust state",
		) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("private key PEM in public CA slot", func(t *testing.T) {
		bundle := writeValidBundle(t)
		path := filepath.Join(bundle, "carrier-root-ca.pem")
		data := pem.EncodeToMemory(&pem.Block{
			Type: "PRIVATE KEY", Bytes: []byte("forbidden"),
		})
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		rebindFile(t, bundle, "carrier-root-ca.pem")
		_, err := ValidateBundle(bundle)
		if err == nil || !strings.Contains(
			err.Error(), "not an unadorned certificate",
		) {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func writeValidBundle(t *testing.T) string {
	t.Helper()
	bundle := t.TempDir()
	files := validPublicDocuments(t)
	inventory := make([]PublicFile, 0, len(AllowedPublicBasenames))
	for _, name := range AllowedPublicBasenames {
		data := files[name]
		if err := os.WriteFile(filepath.Join(bundle, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		inventory = append(inventory, PublicFile{
			Name:   name,
			Size:   int64(len(data)),
			SHA256: hex.EncodeToString(digest[:]),
		})
	}
	document := Descriptor{
		Schema:         Schema,
		TopologyID:     "generated-four-node-fixture",
		Protocol:       ProtocolVersion,
		LiveReady:      false,
		ExercisedNodes: []string{},
		Deployments: []Deployment{
			{
				Role: RoleControl, InstanceUUID: "11111111-1111-4111-8111-111111111111",
				NodeID: "controller-1", ServiceID: "service-controller-1",
				Provider: "provider-a", OperatorID: "operator-control",
			},
			{
				Role: RoleEntryPrimary, InstanceUUID: "22222222-2222-4222-8222-222222222222",
				NodeID: "entry-primary-node", ServiceID: "entry-primary-service",
				Provider: "provider-a", OperatorID: "operator-entry",
			},
			{
				Role: RoleEntrySecondary, InstanceUUID: "33333333-3333-4333-8333-333333333333",
				NodeID: "entry-secondary-node", ServiceID: "entry-secondary-service",
				Provider: "provider-a", OperatorID: "operator-entry",
			},
			{
				Role: RoleExit, InstanceUUID: "44444444-4444-4444-8444-444444444444",
				NodeID: "exit-node", ServiceID: "exit-service",
				Provider: "provider-b", OperatorID: "operator-exit",
			},
		},
		Files: inventory,
	}
	writeDescriptor(t, bundle, document)
	return bundle
}

func validPublicDocuments(t *testing.T) map[string][]byte {
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
	receipt, err := transparency.NewReceipt(
		1, manifestDigest, "", signer, now,
	)
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
	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		&x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Winn generated test carrier root"},
			NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		},
		&x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Winn generated test carrier root"},
			NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		},
		private.Public(), private,
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

func readDescriptor(t *testing.T, bundle string) Descriptor {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(bundle, DescriptorName))
	if err != nil {
		t.Fatal(err)
	}
	var document Descriptor
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func writeDescriptor(t *testing.T, bundle string, document Descriptor) {
	t.Helper()
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(
		filepath.Join(bundle, DescriptorName), data, 0o644,
	); err != nil {
		t.Fatal(err)
	}
}

func rebindFile(t *testing.T, bundle, name string) {
	t.Helper()
	document := readDescriptor(t, bundle)
	data, err := os.ReadFile(filepath.Join(bundle, name))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	for index := range document.Files {
		if document.Files[index].Name == name {
			document.Files[index].Size = int64(len(data))
			document.Files[index].SHA256 = hex.EncodeToString(digest[:])
		}
	}
	writeDescriptor(t, bundle, document)
}
