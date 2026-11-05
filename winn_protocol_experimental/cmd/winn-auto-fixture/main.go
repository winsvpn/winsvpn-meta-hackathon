// Command winn-auto-fixture creates a private, short-lived production-shaped
// Linux Auto deployment for privileged acceptance testing. It signs a
// ManifestV2 and Linux profile, creates and bootstraps its transparency state,
// and initializes the real rotation/apply state through rotation.Coordinator.
// It is not a production controller or token issuer.
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/internal/awg"
	"winsvpn.local/winnprotocol/internal/bootstrap"
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/directawg"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/gatewaymanifest"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/rotation"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/internal/transparency"
)

const fixtureFormat = "winn-auto-private-fixture/v1"

type fixtureSummary struct {
	Format            string `json:"format"`
	ManifestPath      string `json:"manifest_path"`
	ManifestDigest    string `json:"manifest_digest"`
	TransparencyLog   string `json:"transparency_log"`
	TrustStatePath    string `json:"trust_state_path"`
	LinuxProfilePath  string `json:"linux_profile_path"`
	RotationStatePath string `json:"rotation_state_path"`
	AppliedPSKPath    string `json:"applied_psk_path"`
	ProtocolVersion   string `json:"protocol_version"`
}

func main() {
	if err := run(os.Args[1:], os.Stderr, os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(1)
	}
}

func run(args []string, errw io.Writer, outw io.Writer) error {
	fs := flag.NewFlagSet("winn-auto-fixture", flag.ContinueOnError)
	fs.SetOutput(errw)

	var outputDirectory string
	var controllerSeedPath string
	var controllerPinsPath string
	var controllerAlgorithm string
	var tokenPublicKeyPath string
	var echConfigPath string
	var pskPath string
	var controllerID string
	var deviceID string
	var nodeID string
	var operatorID string
	var provider string
	var directTransportID string
	var h3TransportID string
	var directEndpoint string
	var masqueTemplate string
	var serverName string
	var ipv4Hint string
	var fixedBackend string
	var gatewayPublicKey string
	var publicTarget string
	var issuerDomain string
	var innerAddressPool string
	var allowedIPs string
	var verificationRoutes string
	var mtu int
	var listenPortMin int
	var listenPortMax int
	var dnsResolver string
	var dnsQueryName string
	var expectedDNSAnswers string
	var canaryEndpoint string
	var lifetime time.Duration

	fs.StringVar(&outputDirectory, "out", "", "new private output directory")
	fs.StringVar(&controllerSeedPath, "controller-pq-seed", "", "controller ML-DSA seed")
	fs.StringVar(&controllerPinsPath, "controller-pq-pins", "", "controller verifier pins")
	fs.StringVar(
		&controllerAlgorithm,
		"controller-pq-algorithm",
		protocol.RequiredAuthAlgorithm(protocol.DefaultSuite),
		"controller ML-DSA algorithm required by the frozen suite",
	)
	fs.StringVar(&tokenPublicKeyPath, "privacy-token-public-key", "", "blind-token issuer public key PEM")
	fs.StringVar(&echConfigPath, "ech-config-list", "", "RFC 9849 client ECHConfigList")
	fs.StringVar(&pskPath, "psk-file", "", "base64-encoded 32-byte applied AWG PSK")
	fs.StringVar(&controllerID, "controller-id", "", "controller identity")
	fs.StringVar(&deviceID, "device-id", "", "client device identity")
	fs.StringVar(&nodeID, "node-id", "", "gateway node identity")
	fs.StringVar(&operatorID, "operator-id", "winn-private-lab", "gateway operator identity")
	fs.StringVar(&provider, "provider", "aicore-private-lab", "gateway provider label")
	fs.StringVar(&directTransportID, "direct-transport-id", "direct-primary", "direct AWG transport ID")
	fs.StringVar(&h3TransportID, "h3-transport-id", "h3-primary", "HTTP/3 transport ID")
	fs.StringVar(&directEndpoint, "direct-endpoint", "", "signed raw AWG IP-literal endpoint")
	fs.StringVar(&masqueTemplate, "masque-template", "", "signed RFC 9298 HTTPS URI template")
	fs.StringVar(&serverName, "server-name", "", "signed H3 server name")
	fs.StringVar(&ipv4Hint, "ipv4-hint", "", "signed H3 IPv4 address hint")
	fs.StringVar(&fixedBackend, "fixed-backend", "", "signed H3 fixed AWG backend")
	fs.StringVar(&gatewayPublicKey, "gateway-public-key", "", "base64 AWG peer public key")
	fs.StringVar(&publicTarget, "public-target", "winn.invalid:443", "logical CONNECT-UDP target")
	fs.StringVar(&issuerDomain, "issuer-domain", "winn-private-issuer", "signed blind-token issuer separation label")
	fs.StringVar(&innerAddressPool, "inner-address-pool", "", "signed client address pool")
	fs.StringVar(&allowedIPs, "allowed-ips", "", "comma-separated signed AWG allowed prefixes")
	fs.StringVar(&verificationRoutes, "verification-routes", "", "comma-separated signed probe prefixes")
	fs.IntVar(&mtu, "mtu", 1280, "signed inner AWG MTU")
	fs.IntVar(&listenPortMin, "listen-port-min", 61000, "signed client listen-port floor")
	fs.IntVar(&listenPortMax, "listen-port-max", 61100, "signed client listen-port ceiling")
	fs.StringVar(&dnsResolver, "dns-resolver", "", "signed protected DNS endpoint")
	fs.StringVar(&dnsQueryName, "dns-query-name", "winn-auto-e2e.invalid", "signed protected DNS query")
	fs.StringVar(&expectedDNSAnswers, "expected-dns-answers", "", "comma-separated signed DNS answers")
	fs.StringVar(&canaryEndpoint, "canary-endpoint", "", "signed tunnel canary endpoint")
	fs.DurationVar(&lifetime, "lifetime", 2*time.Hour, "fixture trust lifetime")
	if err := fs.Parse(args); err != nil {
		return err
	}

	for name, value := range map[string]string{
		"out":                      outputDirectory,
		"controller-pq-seed":       controllerSeedPath,
		"controller-pq-pins":       controllerPinsPath,
		"privacy-token-public-key": tokenPublicKeyPath,
		"ech-config-list":          echConfigPath,
		"psk-file":                 pskPath,
		"controller-id":            controllerID,
		"device-id":                deviceID,
		"node-id":                  nodeID,
		"direct-endpoint":          directEndpoint,
		"masque-template":          masqueTemplate,
		"server-name":              serverName,
		"ipv4-hint":                ipv4Hint,
		"fixed-backend":            fixedBackend,
		"gateway-public-key":       gatewayPublicKey,
		"inner-address-pool":       innerAddressPool,
		"allowed-ips":              allowedIPs,
		"verification-routes":      verificationRoutes,
		"dns-resolver":             dnsResolver,
		"expected-dns-answers":     expectedDNSAnswers,
		"canary-endpoint":          canaryEndpoint,
	} {
		if value == "" {
			return failf(errw, "%s is required", name)
		}
	}
	if lifetime <= 0 || lifetime > gatewaymanifest.MaxLifetime {
		return failf(errw, "lifetime must be within (0, %s]", gatewaymanifest.MaxLifetime)
	}
	if err := validateListenPortRange(listenPortMin, listenPortMax); err != nil {
		return failf(errw, "%s", err.Error())
	}
	// #nosec G115 -- both values were bounded to [1024, 65535] above.
	listenPortMinimum := uint16(listenPortMin)
	// #nosec G115 -- both values were bounded to [1024, 65535] above.
	listenPortMaximum := uint16(listenPortMax)
	if err := protocol.ValidatePeerPublicKey(gatewayPublicKey); err != nil {
		return failf(errw, "gateway-public-key: %v", err)
	}
	allowedIPList, err := splitList(allowedIPs)
	if err != nil {
		return failf(errw, "allowed-ips: %v", err)
	}
	verificationRouteList, err := splitList(verificationRoutes)
	if err != nil {
		return failf(errw, "verification-routes: %v", err)
	}
	expectedDNSAnswerList, err := splitList(expectedDNSAnswers)
	if err != nil {
		return failf(errw, "expected-dns-answers: %v", err)
	}
	if err := os.Mkdir(outputDirectory, 0o700); err != nil {
		return failf(errw, "create new fixture directory: %v", err)
	}

	signer, err := pqauth.LoadSigner(
		controllerAlgorithm, controllerSeedPath,
	)
	if err != nil {
		return failf(errw, "load controller signer: %v", err)
	}
	pins, err := pqauth.LoadVerifierSet(controllerPinsPath)
	if err != nil {
		return failf(errw, "load controller pins: %v", err)
	}
	if verifier, verifierErr := pins.Verifier(
		signer.Algorithm(), signer.KeyID(),
	); verifierErr != nil || verifier == nil {
		return failf(errw, "controller signer is not present in pins")
	}
	issuerPublicKey, err := privacytoken.LoadIssuerPublicKey(
		tokenPublicKeyPath,
	)
	if err != nil {
		return failf(errw, "load privacy-token issuer public key: %v", err)
	}
	issuerDER, err := x509.MarshalPKIXPublicKey(issuerPublicKey)
	if err != nil {
		return failf(errw, "marshal privacy-token issuer public key: %v", err)
	}
	defer clear(issuerDER)
	tokenKeyID, err := privacytoken.IssuerKeyID(issuerPublicKey)
	if err != nil {
		return failf(errw, "derive privacy-token key ID: %v", err)
	}
	echList, err := echconfig.LoadClientConfigList(echConfigPath)
	if err != nil {
		return failf(errw, "load ECH config list: %v", err)
	}
	defer clear(echList)
	psk, err := readBase64Secret(pskPath)
	if err != nil {
		return failf(errw, "load applied AWG PSK: %v", err)
	}
	defer clear(psk)

	now := time.Now().UTC()
	expiresAt := now.Add(lifetime)
	tokenKey := gatewaymanifest.PrivacyTokenKey{
		ID:           tokenKeyID,
		Scope:        "carrier:" + publicTarget,
		IssuerDomain: issuerDomain,
		Algorithm:    privacytoken.Algorithm,
		PublicKey:    base64.StdEncoding.EncodeToString(issuerDER),
		NotBefore:    now.Format(time.RFC3339Nano),
		NotAfter:     expiresAt.Format(time.RFC3339Nano),
	}
	direct := gatewaymanifest.TransportV2{
		ID:                  directTransportID,
		Type:                connectivity.CarrierDirectAWG,
		Endpoint:            directEndpoint,
		Suite:               protocol.DefaultSuite,
		AuthenticationModes: []string{gatewaymanifest.AuthAWGPSK},
		PublicAWGKey:        gatewayPublicKey,
		MinInnerDatagram:    1200,
		MaxInnerDatagram:    1350,
		Capabilities: []string{
			"awg-handshake-readiness",
			"candidate-isolated-verification",
		},
	}
	h3 := gatewaymanifest.TransportV2{
		ID:                  h3TransportID,
		Type:                connectivity.CarrierHTTP3,
		Endpoint:            masqueTemplate,
		ServerName:          serverName,
		IPv4Hints:           []string{ipv4Hint},
		ECHConfigList:       base64.StdEncoding.EncodeToString(echList),
		ALPN:                []string{"h3"},
		Suite:               protocol.DefaultSuite,
		AuthenticationModes: []string{gatewaymanifest.AuthAnonymousToken},
		TokenKeyID:          tokenKeyID,
		PublicTarget:        publicTarget,
		PublicAWGKey:        gatewayPublicKey,
		FixedBackend:        fixedBackend,
		MinInnerDatagram:    1200,
		MaxInnerDatagram:    1350,
		Capabilities: []string{
			"attempt-binding",
			"fixed-backend",
		},
	}
	manifest := gatewaymanifest.ManifestV2{
		Format:           gatewaymanifest.FormatV2,
		Sequence:         1,
		IssuedAt:         now.Format(time.RFC3339Nano),
		ExpiresAt:        expiresAt.Format(time.RFC3339Nano),
		ControllerID:     controllerID,
		Suite:            protocol.DefaultSuite,
		MinimumClient:    gatewaymanifest.MinimumClientV3,
		Capabilities:     gatewaymanifest.RequiredV2Capabilities(),
		PrivacyTokenKeys: []gatewaymanifest.PrivacyTokenKey{tokenKey},
		Nodes: []gatewaymanifest.NodeV2{{
			ID:         nodeID,
			OperatorID: operatorID,
			Provider:   provider,
			Roles:      []string{gatewaymanifest.RoleCarrier},
			Transports: []gatewaymanifest.TransportV2{direct, h3},
			Capabilities: []string{
				"candidate-isolated-verification",
			},
		}},
	}
	if err := gatewaymanifest.SignV2(&manifest, signer); err != nil {
		return failf(errw, "sign ManifestV2: %v", err)
	}
	manifestPath := filepath.Join(
		outputDirectory, "manifest-v2.json",
	)
	encodedManifest, err := encodeManifest(manifest)
	if err != nil {
		return failf(errw, "%s", err.Error())
	}
	if err := writeEncoded(
		manifestPath,
		encodedManifest,
		0o644,
	); err != nil {
		return failf(errw, "%s", err.Error())
	}
	manifestDigest, err := gatewaymanifest.DigestV2(manifest)
	if err != nil {
		return failf(errw, "digest ManifestV2: %v", err)
	}
	logPath := filepath.Join(outputDirectory, "transparency.jsonl")
	_, checkpoint, err := transparency.Append(
		logPath, manifestDigest, signer, pins, now,
	)
	if err != nil {
		return failf(errw, "append ManifestV2 transparency receipt: %v", err)
	}
	_, bootDigest, trustState, err :=
		gatewaymanifest.BootstrapTrustStateV2(
			manifestPath,
			logPath,
			checkpoint,
			pins,
			now.Add(time.Second),
		)
	if err != nil {
		return failf(errw, "bootstrap ManifestV2 trust state: %v", err)
	}
	if err := refuseBootstrapDigestMismatch(
		bootDigest, manifestDigest,
	); err != nil {
		return failf(errw, "%s", err.Error())
	}
	trustStatePath := filepath.Join(
		outputDirectory, "trust-state-v2.json",
	)
	trustEncoded, err := gatewaymanifest.EncodeTrustStateV2(
		trustState,
	)
	if err != nil {
		return failf(errw, "encode ManifestV2 trust state: %v", err)
	}
	if err := writeEncoded(trustStatePath, trustEncoded, 0o600); err != nil {
		return failf(errw, "%s", err.Error())
	}

	profile := directawg.LinuxDeploymentProfile{
		Format:         directawg.LinuxDeploymentProfileFormat,
		ManifestDigest: manifestDigest,
		NodeID:         nodeID,
		TransportID:    directTransportID,
		IssuedAt:       now.Format(time.RFC3339),
		ExpiresAt:      expiresAt.Format(time.RFC3339),
		Interface: directawg.LinuxInterfaceProfile{
			InnerAddressPool:    innerAddressPool,
			AllowedIPs:          allowedIPList,
			VerificationRoutes:  verificationRouteList,
			MTU:                 mtu,
			ListenPortMin:       listenPortMinimum,
			ListenPortMax:       listenPortMaximum,
			PersistentKeepalive: 25,
			Obfuscation: directawg.AWGObfuscation{
				JC: 4, JMin: 12, JMax: 64,
				S1: 16, S2: 80, S3: 24, S4: 8,
				H1: 111111, H2: 222222,
				H3: 333333, H4: 444444,
			},
		},
		Probe: directawg.LinuxProbeProfile{
			DNSResolver:         dnsResolver,
			DNSQueryName:        dnsQueryName,
			ExpectedDNSAnswers:  expectedDNSAnswerList,
			CanaryEndpoint:      canaryEndpoint,
			TimeoutMilliseconds: 2000,
		},
	}
	if err := directawg.SignLinuxDeploymentProfile(
		&profile, signer,
	); err != nil {
		return failf(errw, "sign Linux deployment profile: %v", err)
	}
	profilePath := filepath.Join(
		outputDirectory, "linux-profile.json",
	)
	if err := writeJSON(profilePath, profile, 0o644); err != nil {
		return failf(errw, "%s", err.Error())
	}

	rotationStatePath := filepath.Join(
		outputDirectory, "rotation.state",
	)
	appliedPSKPath := filepath.Join(
		outputDirectory, "current.psk",
	)
	coordinator, err := rotation.NewCoordinator(
		rotation.CoordinatorConfig{
			Applier:       awg.FileApplier{Path: appliedPSKPath},
			StatePath:     rotationStatePath,
			DeviceID:      deviceID,
			PeerPublicKey: gatewayPublicKey,
			Suite:         protocol.DefaultSuite,
			Now:           func() time.Time { return now },
		},
	)
	if err != nil {
		return failf(errw, "construct rotation coordinator: %v", err)
	}
	_, rotateErr := coordinator.Rotate(
		context.Background(),
		&fixtureRekeyClient{
			now:          now,
			expiresAt:    expiresAt,
			controllerID: controllerID,
			psk:          psk,
		},
	)
	closeErr := coordinator.Close(context.Background())
	if err := errors.Join(rotateErr, closeErr); err != nil {
		return failf(errw, "initialize applied rotation state: %v", err)
	}

	summary := fixtureSummary{
		Format:            fixtureFormat,
		ManifestPath:      manifestPath,
		ManifestDigest:    manifestDigest,
		TransparencyLog:   logPath,
		TrustStatePath:    trustStatePath,
		LinuxProfilePath:  profilePath,
		RotationStatePath: rotationStatePath,
		AppliedPSKPath:    appliedPSKPath,
		ProtocolVersion:   connectivity.Version,
	}
	if err := writeJSON(
		filepath.Join(outputDirectory, "fixture.json"),
		summary,
		0o600,
	); err != nil {
		return failf(errw, "%s", err.Error())
	}
	return printJSON(outw, summary)
}

type fixtureRekeyClient struct {
	now          time.Time
	expiresAt    time.Time
	controllerID string
	psk          []byte
}

func (client *fixtureRekeyClient) NewRequest(
	deviceID string,
	peerPublicKey string,
	currentGeneration uint64,
) (protocol.RekeyRequest, error) {
	return protocol.RekeyRequest{
		Version:           protocol.Version,
		Suite:             protocol.DefaultSuite,
		ControllerID:      client.controllerID,
		DeviceID:          deviceID,
		PeerPublicKey:     peerPublicKey,
		RequestID:         strings.Repeat("1", 32),
		Nonce:             strings.Repeat("2", 32),
		CurrentGeneration: currentGeneration,
		Capabilities: protocol.RequiredCapabilities(
			protocol.DefaultSuite,
		),
	}, nil
}

func (client *fixtureRekeyClient) Rekey(
	_ context.Context,
	request protocol.RekeyRequest,
) (bootstrap.Result, error) {
	psk := bytes.Clone(client.psk)
	generation := request.CurrentGeneration + 1
	return bootstrap.Result{
		Response: protocol.RekeyResponse{
			Version:       protocol.Version,
			Suite:         request.Suite,
			ControllerID:  request.ControllerID,
			DeviceID:      request.DeviceID,
			PeerPublicKey: request.PeerPublicKey,
			RequestID:     request.RequestID,
			Nonce:         request.Nonce,
			Generation:    generation,
			KeyID: protocol.KeyID(
				request.ControllerID,
				request.Suite,
				request.DeviceID,
				request.PeerPublicKey,
				generation,
				psk,
			),
			IssuedAt: client.now.Format(time.RFC3339Nano),
			ExpiresAt: client.expiresAt.Format(
				time.RFC3339Nano,
			),
		},
		PSK: psk,
	}, nil
}

func encodeManifest(
	manifest gatewaymanifest.ManifestV2,
) ([]byte, error) {
	encoded, err := gatewaymanifest.EncodeV2(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode ManifestV2: %w", err)
	}
	return encoded, nil
}

func readBase64Secret(path string) ([]byte, error) {
	data, err := securefile.ReadPrivateLimited(path, 256)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	decoded, err := base64.StdEncoding.Strict().DecodeString(
		strings.TrimSpace(string(data)),
	)
	if err != nil || len(decoded) != 32 {
		clear(decoded)
		return nil, errors.New(
			"secret must be one base64-encoded 32-byte value",
		)
	}
	return decoded, nil
}

func splitList(value string) ([]string, error) {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			return nil, errors.New(
				"comma-separated list contains an empty entry",
			)
		}
		result = append(result, trimmed)
	}
	return result, nil
}

func validateListenPortRange(listenPortMin, listenPortMax int) error {
	// Matches directawg.validateLinuxSignedConfig: at least two
	// non-privileged ports. The previous local check allowed [1,65535]
	// with min==max, which SignLinuxDeploymentProfile always refused.
	if listenPortMin < 1024 ||
		listenPortMax < listenPortMin ||
		listenPortMax > 65535 ||
		listenPortMax-listenPortMin < 1 {
		return errors.New("listen-port range is invalid")
	}
	return nil
}

func refuseBootstrapDigestMismatch(bootDigest, manifestDigest string) error {
	if bootDigest != manifestDigest {
		return fmt.Errorf(
			"bootstrap ManifestV2 trust state: digest mismatch got %s want %s",
			bootDigest,
			manifestDigest,
		)
	}
	return nil
}

func writeEncoded(path string, encoded []byte, mode os.FileMode) error {
	defer clear(encoded)
	if err := securefile.AtomicWrite(path, encoded, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func writeJSON(path string, value any, mode os.FileMode) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	return writeEncoded(path, append(encoded, '\n'), mode)
}

func printJSON(outw io.Writer, value any) error {
	encoder := json.NewEncoder(outw)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("print fixture summary: %w", err)
	}
	return nil
}

func failf(errw io.Writer, format string, arguments ...any) error {
	err := fmt.Errorf(format, arguments...)
	fmt.Fprintln(errw, err.Error())
	return err
}

var _ rotation.RekeyClient = (*fixtureRekeyClient)(nil)
