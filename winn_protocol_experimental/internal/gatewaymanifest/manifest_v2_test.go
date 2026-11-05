package gatewaymanifest

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/privacytoken"
)

var (
	v2TokenOnce sync.Once
	v2TokenDER  [2][]byte
	v2TokenID   [2]string
	v2TokenErr  error
)

func TestManifestV2SignVerifyDigestAndTypedSelection(t *testing.T) {
	signer, pins := manifestTestKeys(t)
	now := time.Date(2026, 7, 23, 18, 0, 0, 0, time.UTC)
	manifest := validManifestV2(t, now)
	if err := SignV2(&manifest, signer); err != nil {
		t.Fatal(err)
	}
	if err := VerifyV2(
		manifest, pins, now.Add(time.Minute), time.Minute,
	); err != nil {
		t.Fatal(err)
	}
	digest, err := DigestV2(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != 64 {
		t.Fatalf("v2 manifest digest length = %d", len(digest))
	}
	node, err := manifest.Node("entry-nyc")
	if err != nil {
		t.Fatal(err)
	}
	transport, err := node.Transport("h3-primary")
	if err != nil {
		t.Fatal(err)
	}
	if transport.Type != connectivity.CarrierHTTP3 {
		t.Fatalf("selected transport = %#v", transport)
	}
	manifest.Nodes[0].Transports[0].FixedBackend = "attacker.invalid:53"
	if err := VerifyV2(
		manifest, pins, now.Add(time.Minute), time.Minute,
	); err == nil {
		t.Fatal("tampered v2 manifest verified")
	}
}

func TestManifestV2FailClosedTransportPolicies(t *testing.T) {
	signer, pins := manifestTestKeys(t)
	now := time.Date(2026, 7, 23, 18, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*ManifestV2)
	}{
		{"missing-ech", func(manifest *ManifestV2) {
			manifest.Nodes[0].Transports[1].ECHConfigList = ""
		}},
		{"wrong-minimum-client", func(manifest *ManifestV2) {
			manifest.MinimumClient = "winn/30"
		}},
		{"entry-exit-role-conflict", func(manifest *ManifestV2) {
			manifest.Nodes[0].Roles = []string{
				RoleCarrier, RoleEntry, RoleExit,
			}
		}},
		{"lab-production-role-conflict", func(manifest *ManifestV2) {
			manifest.Nodes[0].Roles = []string{RoleLab, RoleCarrier}
		}},
		{"masque-query", func(manifest *ManifestV2) {
			manifest.Nodes[0].Transports[1].Endpoint += "?leak=true"
		}},
		{"masque-fragment", func(manifest *ManifestV2) {
			manifest.Nodes[0].Transports[1].Endpoint += "#fragment"
		}},
		{"masque-userinfo", func(manifest *ManifestV2) {
			manifest.Nodes[0].Transports[1].Endpoint =
				"https://user@gateway.example/.well-known/masque/udp/{target_host}/{target_port}/"
		}},
		{"masque-placeholder-position", func(manifest *ManifestV2) {
			manifest.Nodes[0].Transports[1].Endpoint =
				"https://gateway.example/.well-known/masque/udp/fixed/{target_host}/?port={target_port}"
		}},
		{"malformed-ech", func(manifest *ManifestV2) {
			manifest.Nodes[0].Transports[1].ECHConfigList =
				base64.StdEncoding.EncodeToString(bytesOf(0x65, 16))
		}},
		{"classical-suite", func(manifest *ManifestV2) {
			manifest.Nodes[0].Transports[0].Suite = "x25519"
		}},
		{"strong-suite-weak-signature", func(manifest *ManifestV2) {
			manifest.Suite = "p384-mlkem1024"
			for nodeIndex := range manifest.Nodes {
				for transportIndex := range manifest.Nodes[nodeIndex].Transports {
					manifest.Nodes[nodeIndex].Transports[transportIndex].Suite =
						manifest.Suite
				}
			}
		}},
		{"anonymous-without-token-key", func(manifest *ManifestV2) {
			manifest.PrivacyTokenKeys = nil
		}},
		{"reality-without-policy", func(manifest *ManifestV2) {
			manifest.Nodes[0].Transports[2].RegionPolicy = "missing"
		}},
		{"reality-target-mismatch", func(manifest *ManifestV2) {
			manifest.Nodes[0].Transports[2].ServerName = "other.example"
		}},
		{"direct-with-tls-fields", func(manifest *ManifestV2) {
			manifest.Nodes[0].Transports[0].ServerName = "gateway.example"
		}},
		{"direct-with-hostname", func(manifest *ManifestV2) {
			manifest.Nodes[0].Transports[0].Endpoint = "gateway.example:51820"
		}},
		{"direct-with-carrier-auth", func(manifest *ManifestV2) {
			manifest.Nodes[0].Transports[0].AuthenticationModes =
				[]string{AuthIdentity}
		}},
		{"direct-with-fixed-backend", func(manifest *ManifestV2) {
			manifest.Nodes[0].Transports[0].FixedBackend =
				"127.0.0.1:51820"
		}},
		{"unbound-token-key", func(manifest *ManifestV2) {
			manifest.Nodes[0].Transports[1].TokenKeyID = "unknown"
		}},
		{"token-key-id-mismatch", func(manifest *ManifestV2) {
			manifest.PrivacyTokenKeys[0].ID = repeatByteHex(0xaa)
		}},
		{"global-transport-id-collision", func(manifest *ManifestV2) {
			duplicate := manifest.Nodes[0].Transports[1]
			manifest.Nodes = append(manifest.Nodes, NodeV2{
				ID:           "carrier-2",
				OperatorID:   "operator-2",
				Provider:     "upcloud",
				Roles:        []string{RoleCarrier},
				Transports:   []TransportV2{duplicate},
				Capabilities: []string{"candidate-isolated-verification"},
			})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := validManifestV2(t, now)
			test.mutate(&manifest)
			if err := SignV2(&manifest, signer); err == nil {
				if err := VerifyV2(
					manifest, pins, now, time.Minute,
				); err == nil {
					t.Fatal("invalid v2 manifest verified")
				}
			}
		})
	}
}

func TestManifestV2RejectsClockSkewAboveFrozenMaximum(t *testing.T) {
	signer, pins := manifestTestKeys(t)
	now := time.Date(2026, 7, 23, 18, 0, 0, 0, time.UTC)
	manifest := validManifestV2(t, now)
	if err := SignV2(&manifest, signer); err != nil {
		t.Fatal(err)
	}
	if err := VerifyV2(
		manifest, pins, now, DefaultClockSkew+time.Nanosecond,
	); err == nil {
		t.Fatal("v2 verifier accepted clock skew above frozen maximum")
	}
	if err := VerifyV2(manifest, pins, now, -time.Nanosecond); err == nil {
		t.Fatal("v2 verifier accepted negative clock skew")
	}
}

func TestManifestV2RejectsAmbiguousWebSocketURLs(t *testing.T) {
	signer, _ := manifestTestKeys(t)
	now := time.Date(2026, 7, 23, 18, 0, 0, 0, time.UTC)
	tests := []string{
		"wss://user@gateway.example/winn/v3/ws",
		"wss://gateway.example/winn/v3/ws#fragment",
		"wss://gateway.example/winn/v3/ws?query=true",
		"wss://gateway.example:70000/winn/v3/ws",
	}
	for _, endpoint := range tests {
		t.Run(endpoint, func(t *testing.T) {
			manifest := validManifestV2(t, now)
			websocket := manifest.Nodes[0].Transports[1]
			websocket.ID = "ws-primary"
			websocket.Type = connectivity.CarrierWebSocketTLS
			websocket.Endpoint = endpoint
			websocket.ALPN = []string{"h2"}
			websocket.SidecarConfigDigest = repeatByteHex(0x81)
			manifest.Nodes[0].Transports = append(
				manifest.Nodes[0].Transports, websocket,
			)
			if err := SignV2(&manifest, signer); err == nil {
				t.Fatal("ambiguous WebSocket URL was signed")
			}
		})
	}
}

func TestManifestV2EnforcesTwoHopSeparation(t *testing.T) {
	signer, pins := manifestTestKeys(t)
	now := time.Date(2026, 7, 23, 18, 0, 0, 0, time.UTC)
	manifest := validManifestV2(t, now)
	addPrivacyCircuit(t, &manifest)
	if err := SignV2(&manifest, signer); err != nil {
		t.Fatal(err)
	}
	if err := VerifyV2(
		manifest, pins, now.Add(time.Minute), time.Minute,
	); err != nil {
		t.Fatal(err)
	}
	circuit, err := manifest.Circuit("privacy-us-1")
	if err != nil || circuit.Mode != connectivity.ModeMaximumPrivacy {
		t.Fatalf("privacy circuit = %#v, %v", circuit, err)
	}

	tests := []struct {
		name   string
		mutate func(*ManifestV2)
	}{
		{"same-provider", func(current *ManifestV2) {
			current.Nodes[1].Provider = current.Nodes[0].Provider
		}},
		{"same-operator", func(current *ManifestV2) {
			current.Nodes[1].OperatorID = current.Nodes[0].OperatorID
		}},
		{"same-credential-domain", func(current *ManifestV2) {
			current.Circuits[0].Exit.CredentialDomain =
				current.Circuits[0].Entry.CredentialDomain
		}},
		{"same-credential-key", func(current *ManifestV2) {
			current.Circuits[0].Exit.CredentialKeyID =
				current.Circuits[0].Entry.CredentialKeyID
		}},
		{"transport-key-mismatch", func(current *ManifestV2) {
			current.Nodes[1].Transports[0].TokenKeyID =
				current.Circuits[0].Entry.CredentialKeyID
		}},
		{"identity-only-exit", func(current *ManifestV2) {
			current.Nodes[1].Transports[0].AuthenticationModes =
				[]string{AuthIdentity}
			current.Nodes[1].Transports[0].TokenKeyID = ""
		}},
		{"same-issuer-domain", func(current *ManifestV2) {
			current.PrivacyTokenKeys[1].IssuerDomain =
				current.PrivacyTokenKeys[0].IssuerDomain
		}},
		{"same-key-material", func(current *ManifestV2) {
			current.PrivacyTokenKeys[1].PublicKey =
				current.PrivacyTokenKeys[0].PublicKey
		}},
		{"privacy-mtu-above-cell", func(current *ManifestV2) {
			current.Nodes[1].Transports[0].MaxInnerDatagram = 961
		}},
		{"unbound-two-hop", func(current *ManifestV2) {
			current.Circuits = nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := validManifestV2(t, now)
			addPrivacyCircuit(t, &current)
			test.mutate(&current)
			if err := SignV2(&current, signer); err == nil {
				t.Fatal("invalid two-hop manifest signed")
			}
		})
	}
}

func TestManifestV2SignsCanonicalPrehashBeyond64KiB(t *testing.T) {
	signer, pins := manifestTestKeys(t)
	now := time.Date(2026, 7, 23, 18, 0, 0, 0, time.UTC)
	manifest := validManifestV2(t, now)
	template := manifest.Nodes[0].Transports[1]
	manifest.Nodes[0].Transports = make(
		[]TransportV2, MaxV2Transports,
	)
	for index := range manifest.Nodes[0].Transports {
		current := template
		current.ID = fmt.Sprintf("h3-%03d", index)
		manifest.Nodes[0].Transports[index] = current
	}
	if err := SignV2(&manifest, signer); err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeV2(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) <= 64<<10 {
		t.Fatalf("large manifest is only %d bytes", len(encoded))
	}
	if err := VerifyV2(manifest, pins, now, time.Minute); err != nil {
		t.Fatal(err)
	}
}

func TestManifestV2SignatureCannotUseV1Domain(t *testing.T) {
	signer, pins := manifestTestKeys(t)
	now := time.Date(2026, 7, 23, 18, 0, 0, 0, time.UTC)
	manifest := validManifestV2(t, now)
	if err := SignV2(&manifest, signer); err != nil {
		t.Fatal(err)
	}
	manifest.Format = Format
	if err := VerifyV2(manifest, pins, now, time.Minute); err == nil {
		t.Fatal("v2 verifier accepted v1 manifest format")
	}
}

func validManifestV2(t testing.TB, now time.Time) ManifestV2 {
	t.Helper()
	rawKey := base64.StdEncoding.EncodeToString(
		bytesOf(0x6b, 32),
	)
	echList, _, err := echconfig.Generate("cover.example", 1)
	if err != nil {
		t.Fatal(err)
	}
	ech := base64.StdEncoding.EncodeToString(echList)
	tokenDER, tokenID := v2TokenMaterial(t)
	tokenKey := PrivacyTokenKey{
		ID:           tokenID,
		Scope:        "carrier:winn.invalid:443",
		IssuerDomain: "issuer-entry",
		Algorithm:    "rsabssa-sha384-pss-randomized",
		PublicKey:    base64.StdEncoding.EncodeToString(tokenDER),
		NotBefore:    now.Format(time.RFC3339Nano),
		NotAfter:     now.Add(24 * time.Hour).Format(time.RFC3339Nano),
	}
	common := func() TransportV2 {
		return TransportV2{
			Suite:               "x25519-mlkem768",
			AuthenticationModes: []string{AuthIdentity, AuthAnonymousToken},
			TokenKeyID:          tokenKey.ID,
			PublicAWGKey:        rawKey,
			FixedBackend:        "127.0.0.1:51820",
			MinInnerDatagram:    1200,
			MaxInnerDatagram:    1350,
			Capabilities:        []string{"attempt-binding", "fixed-backend"},
		}
	}
	direct := common()
	direct.ID = "direct-primary"
	direct.Type = connectivity.CarrierDirectAWG
	direct.Endpoint = "192.0.2.10:51820"
	direct.AuthenticationModes = []string{AuthAWGPSK}
	direct.TokenKeyID = ""
	direct.FixedBackend = ""
	direct.Capabilities = []string{
		"awg-handshake-readiness",
		"candidate-isolated-verification",
	}

	h3 := common()
	h3.ID = "h3-primary"
	h3.Type = connectivity.CarrierHTTP3
	h3.Endpoint = "https://gateway.example/.well-known/masque/udp/{target_host}/{target_port}/"
	h3.ServerName = "gateway.example"
	h3.ECHConfigList = ech
	h3.ALPN = []string{"h3"}
	h3.PublicTarget = "winn.invalid:443"

	reality := common()
	reality.ID = "reality-primary"
	reality.Type = connectivity.CarrierRealityXHTTP
	reality.Endpoint = "192.0.2.10:443"
	reality.ServerName = "decoy.example"
	reality.ALPN = []string{"h2", "http/1.1"}
	reality.RegionPolicy = "global-default"
	reality.SidecarConfigDigest = repeatByteHex(0x44)

	return ManifestV2{
		Format:           FormatV2,
		Sequence:         1,
		IssuedAt:         now.Format(time.RFC3339Nano),
		ExpiresAt:        now.Add(24 * time.Hour).Format(time.RFC3339Nano),
		ControllerID:     "controller-1",
		Suite:            "x25519-mlkem768",
		MinimumClient:    MinimumClientV3,
		Capabilities:     RequiredV2Capabilities(),
		PrivacyTokenKeys: []PrivacyTokenKey{tokenKey},
		RegionalPolicies: []RegionalPolicyV2{{
			ID:        "global-default",
			Regions:   []string{"global"},
			NotBefore: now.Format(time.RFC3339Nano),
			NotAfter:  now.Add(24 * time.Hour).Format(time.RFC3339Nano),
			Targets: []CamouflageTargetV2{{
				ServerName: "decoy.example",
				Endpoint:   "192.0.2.10:443",
				ALPN:       []string{"h2", "http/1.1"},
			}},
		}},
		Nodes: []NodeV2{{
			ID:         "entry-nyc",
			OperatorID: "vultr-entry",
			Provider:   "vultr",
			Roles:      []string{RoleCarrier, RoleEntry},
			Transports: []TransportV2{direct, h3, reality},
			Capabilities: []string{
				"active-probe-resistant",
				"candidate-isolated-verification",
			},
		}},
	}
}

func v2TokenMaterial(t testing.TB) ([]byte, string) {
	return v2TokenMaterialAt(t, 0)
}

func v2TokenMaterialAt(t testing.TB, index int) ([]byte, string) {
	t.Helper()
	v2TokenOnce.Do(func() {
		for current := range v2TokenDER {
			privateKey, err := privacytoken.GenerateIssuerKey(3072)
			if err != nil {
				v2TokenErr = err
				return
			}
			v2TokenDER[current], v2TokenErr =
				x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
			if v2TokenErr != nil {
				return
			}
			v2TokenID[current], v2TokenErr =
				privacytoken.IssuerKeyID(&privateKey.PublicKey)
			if v2TokenErr != nil {
				return
			}
		}
	})
	if v2TokenErr != nil {
		t.Fatal(v2TokenErr)
	}
	return append([]byte(nil), v2TokenDER[index]...), v2TokenID[index]
}

func addPrivacyCircuit(t testing.TB, manifest *ManifestV2) {
	t.Helper()
	entry := manifest.Nodes[0].Transports[1]
	manifest.Nodes[0].Transports[1].AuthenticationModes =
		[]string{AuthIdentity}
	manifest.Nodes[0].Transports[1].TokenKeyID = ""
	manifest.PrivacyTokenKeys[0].Scope = "entry-blind-token"
	entry.ID = "privacy-entry"
	entry.Type = connectivity.CarrierPrivacyTwoHop
	entry.Endpoint = "https://entry.example/winn/v3/relay"
	entry.ServerName = "entry.example"
	entry.ALPN = []string{"h2"}
	entry.PublicTarget = ""
	entry.MinInnerDatagram = 576
	entry.MaxInnerDatagram = 960
	exit := entry
	exitDER, exitID := v2TokenMaterialAt(t, 1)
	exitKey := manifest.PrivacyTokenKeys[0]
	exitKey.ID = exitID
	exitKey.Scope = "exit-blind-token"
	exitKey.IssuerDomain = "issuer-exit"
	exitKey.PublicKey = base64.StdEncoding.EncodeToString(exitDER)
	manifest.PrivacyTokenKeys = append(
		manifest.PrivacyTokenKeys, exitKey,
	)
	exit.ID = "privacy-exit"
	exit.Endpoint = "https://exit.example/winn/v3/relay"
	exit.ServerName = "exit.example"
	exit.TokenKeyID = exitKey.ID
	manifest.Nodes[0].Transports = append(
		manifest.Nodes[0].Transports, entry,
	)
	manifest.Nodes = append(manifest.Nodes, NodeV2{
		ID:         "exit-chi",
		OperatorID: "upcloud-exit",
		Provider:   "upcloud",
		Roles:      []string{RoleCarrier, RoleExit},
		Transports: []TransportV2{exit},
		Capabilities: []string{
			"candidate-isolated-verification",
			"privacy-cell-relay",
		},
	})
	manifest.Circuits = []CircuitV2{{
		ID:   "privacy-us-1",
		Mode: connectivity.ModeMaximumPrivacy,
		Entry: HopV2{
			NodeID:           manifest.Nodes[0].ID,
			TransportID:      entry.ID,
			CredentialDomain: "entry-blind-token",
			CredentialKeyID:  entry.TokenKeyID,
		},
		Exit: HopV2{
			NodeID:           "exit-chi",
			TransportID:      exit.ID,
			CredentialDomain: "exit-blind-token",
			CredentialKeyID:  exit.TokenKeyID,
		},
	}}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func repeatByteHex(value byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, 64)
	for index := 0; index < len(result); index += 2 {
		result[index] = digits[value>>4]
		result[index+1] = digits[value&0x0f]
	}
	return string(result)
}
