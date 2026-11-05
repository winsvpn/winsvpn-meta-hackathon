//go:build linux

// Command winn-acceptance drives Winn v3's real production connectivity
// stack (internal/connectivity's Auto-mode candidate racing over real
// internal/directawg candidates) through repeated connection attempts
// against a real gateway fleet, recording every attempt via
// internal/measurement, toward Phase 1's acceptance gate: 10,000 warm/cold
// attempts with p99 <= 3s over the declared network envelope.
//
// It must run as root inside a disposable, internet-routed network
// namespace (see scripts/aicore_real_gateway_e2e.sh for how that namespace
// and its NAT egress are set up) — never against a shared root namespace.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"math"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/directawg"
	"winsvpn.local/winnprotocol/internal/measurement"
	"winsvpn.local/winnprotocol/internal/securefile"
)

// sourceTreeDigest is injected by the acceptance build with:
// -ldflags "-X main.sourceTreeDigest=<sha256-of-the-exact-source-inputs>".
// Evidence runs fail closed if an untracked build omits it.
var sourceTreeDigest string

// gatewaySpec describes one real fleet node. All four currently share
// identical internal addressing (own address 10.203.1.1/30, client pool
// 10.203.1.16/28, DNS/canary responders on 10.203.1.1) — safe because each
// candidate's verification traffic lives in its own candidate-isolated
// route table, so only endpoint and public key need to differ per node.
type gatewaySpec struct {
	name      string
	region    string
	provider  string
	endpoint  string
	publicKey string
}

func defaultGateways() []gatewaySpec {
	return []gatewaySpec{
		{name: "winn-control-atl", region: "us-atl", provider: "vultr", endpoint: "<NODE_CONTROL_ATL>:51820", publicKey: "<REDACTED_WG_KEY>"},
		{name: "winn-entry-nyc", region: "us-nyc", provider: "vultr", endpoint: "<NODE_ENTRY_NYC>:51820", publicKey: "<REDACTED_WG_KEY>"},
		{name: "winn-entry-mia", region: "us-mia", provider: "vultr", endpoint: "<NODE_ENTRY_MIA>:51820", publicKey: "<REDACTED_WG_KEY>"},
		{name: "winn-exit-chi", region: "us-chi", provider: "upcloud", endpoint: "<NODE_EXIT_CHI>:51820", publicKey: "<REDACTED_WG_KEY>"},
	}
}

const (
	sharedDNSResolver    = "10.203.1.1:53"
	sharedCanaryEndpoint = "10.203.1.1:9999"
	sharedInnerPool      = "10.203.1.16/28"
	sharedTunnelRoute    = "10.203.1.0/24"
	readinessProfile     = "winn-acceptance-v1"
)

func main() {
	attempts := flag.Int("attempts", 10, "number of connection attempts to run")
	warmBatch := flag.Int("warm-batch", 5, "attempts per fresh (cold) readiness cycle; the rest reuse it (warm)")
	gatewayLimit := flag.Int("gateway-limit", 0, "diagnostic-only: race just the first N gateways instead of all four (0 = all)")
	gatewayID := flag.String("gateway-id", "", "diagnostic-only: use exactly this named gateway (mutually exclusive with gateway-limit)")
	clientPrivateKeyFile := flag.String("client-private-key-file", "", "path to base64 AWG client private key")
	pskFile := flag.String("psk-file", "", "path to base64 preshared key")
	tableName := flag.String("table-name", "winnacceptance", "nftables table name")
	underlayInterface := flag.String("underlay-interface", "", "protected underlay interface name (required)")
	underlayMarkHex := flag.String("underlay-mark", "9979", "hex firewall mark for the underlay")
	awgGoBinary := flag.String("awg-go-binary", "/opt/winn-lab/bin/amneziawg-go", "path to amneziawg-go")
	awgBinary := flag.String("awg-binary", "/opt/winn-lab/bin/awg", "path to awg")
	ipBinary := flag.String("ip-binary", "/usr/sbin/ip", "path to ip")
	nftBinary := flag.String("nft-binary", "/usr/sbin/nft", "path to nft")
	resolvectlBinary := flag.String("resolvectl-binary", "/usr/bin/resolvectl", "path to resolvectl")
	tempRoot := flag.String("temp-root", "", "private temp root for key files/nft batches (required)")
	logPath := flag.String("log-path", "", "measurement evidence log path (required)")
	logKeyPath := flag.String("log-key-path", "", "measurement HMAC key path, 32 raw bytes mode 0600 (required)")
	osVersion := flag.String("os-version", "Ubuntu 24.04 LTS", "platform OS version recorded in each attempt")
	device := flag.String("device", "AICORE", "device name recorded in each attempt")
	networkInterface := flag.String(
		"network-interface",
		"ethernet",
		"measured access interface: ethernet, wifi, cellular, loopback, or synthetic",
	)
	ipFamily := flag.String(
		"ip-family",
		"ipv4",
		"measured IP family: ipv4, ipv6, dual, or nat64",
	)
	natType := flag.String("nat", "", "measured NAT classification")
	impairment := flag.String(
		"impairment",
		"none",
		"declared, independently captured impairment profile",
	)
	rttMillis := flag.Float64(
		"rtt-ms",
		0,
		"measured pre-run round-trip latency in milliseconds",
	)
	lossFraction := flag.Float64(
		"loss-fraction",
		0,
		"measured or configured packet-loss fraction in [0,1]",
	)
	capacityMbps := flag.Float64(
		"capacity-mbps",
		0,
		"configured or measured access capacity in Mbit/s",
	)
	clientRegion := flag.String(
		"client-region",
		"aicore-lab",
		"client measurement region label",
	)
	onlineHold := flag.Duration(
		"online-hold",
		0,
		"lab-only: keep one successful production connection online for this duration (requires attempts=1, maximum 10m)",
	)
	flag.Parse()

	if *clientPrivateKeyFile == "" || *pskFile == "" || *underlayInterface == "" ||
		*tempRoot == "" || *logPath == "" || *logKeyPath == "" {
		fatalf("client-private-key-file, psk-file, underlay-interface, temp-root, log-path, and log-key-path are all required")
	}
	if *attempts <= 0 {
		fatalf("attempts must be positive")
	}
	if *warmBatch <= 0 {
		fatalf("warm-batch must be positive")
	}
	if *onlineHold < 0 || *onlineHold > 10*time.Minute {
		fatalf("online-hold must be between 0 and 10m")
	}
	if *onlineHold > 0 && *attempts != 1 {
		fatalf("online-hold requires attempts=1")
	}
	if *gatewayID != "" && *gatewayLimit != 0 {
		fatalf("gateway-id and gateway-limit are mutually exclusive")
	}
	if err := validateNetworkMetadata(
		*networkInterface,
		*ipFamily,
		*natType,
		*impairment,
		*rttMillis,
		*lossFraction,
		*capacityMbps,
		*clientRegion,
	); err != nil {
		fatalf("network metadata: %v", err)
	}
	if !lowerHexDigest(sourceTreeDigest) {
		fatalf("binary lacks a valid embedded source-tree digest")
	}
	executablePath, err := os.Executable()
	if err != nil {
		fatalf("resolve acceptance executable: %v", err)
	}
	artifactDigest, err := sha256File(executablePath)
	if err != nil {
		fatalf("hash acceptance executable: %v", err)
	}

	clientPrivateKey, err := readBase64File(*clientPrivateKeyFile)
	if err != nil {
		fatalf("read client private key: %v", err)
	}
	psk, err := readBase64File(*pskFile)
	if err != nil {
		fatalf("read psk: %v", err)
	}
	markValue, err := strconv.ParseUint(*underlayMarkHex, 16, 32)
	if err != nil {
		fatalf("parse underlay mark: %v", err)
	}
	underlayMark := uint32(markValue)

	dnsResolverAddr, err := netip.ParseAddrPort(sharedDNSResolver)
	if err != nil {
		fatalf("parse shared DNS resolver: %v", err)
	}
	innerPool, err := netip.ParsePrefix(sharedInnerPool)
	if err != nil {
		fatalf("parse shared inner pool: %v", err)
	}
	tunnelRoute, err := netip.ParsePrefix(sharedTunnelRoute)
	if err != nil {
		fatalf("parse shared tunnel route: %v", err)
	}

	// The fixed set of executables this harness may launch, taken from the
	// same operator-supplied flags the controller is configured with. Anything
	// else is refused at the exec call rather than trusted by convention.
	allowed, err := directawg.NewLinuxExecAllowList(
		*nftBinary, *resolvectlBinary, *awgGoBinary, *awgBinary, *ipBinary,
	)
	if err != nil {
		fatalf("executable allow-list: %v", err)
	}
	runner := &realCommandRunner{
		resolvectlBinary: *resolvectlBinary,
		allowed:          allowed,
	}

	verifier, err := directawg.NewLinuxProtectedVerifier(directawg.LinuxVerificationConfig{
		DNSResolver:        sharedDNSResolver,
		DNSQueryName:       "winn-acceptance-canary.invalid",
		ExpectedDNSAnswers: []netip.Addr{netip.MustParseAddr("203.0.113.99")},
		CanaryEndpoint:     sharedCanaryEndpoint,
		Timeout:            2 * time.Second,
	})
	if err != nil {
		fatalf("construct protected verifier: %v", err)
	}

	policyFactory, err := directawg.NewLinuxNftResolvedPolicyFactory(directawg.LinuxNftResolvedPolicyConfig{
		NftBinary:         *nftBinary,
		ResolvectlBinary:  *resolvectlBinary,
		TempRoot:          *tempRoot,
		TableName:         *tableName,
		UnderlayInterface: *underlayInterface,
		UnderlayMark:      underlayMark,
		DNSResolver:       dnsResolverAddr.Addr(),
		HealthInterval:    2 * time.Second,
		Runner:            runner,
	})
	if err != nil {
		fatalf("construct policy factory: %v", err)
	}

	controller, err := directawg.NewLinuxController(directawg.LinuxControllerConfig{
		AWGGoBinary: *awgGoBinary,
		AWGBinary:   *awgBinary,
		IPBinary:    *ipBinary,
		TempRoot:    *tempRoot,
		Signed: directawg.LinuxSignedInterfaceConfig{
			InnerAddressPool:    innerPool,
			AllowedIPs:          []netip.Prefix{tunnelRoute},
			VerificationRoutes:  []netip.Prefix{tunnelRoute},
			MTU:                 1280,
			ListenPortMin:       41100,
			ListenPortMax:       41200,
			PersistentKeepalive: 25,
			Obfuscation: directawg.AWGObfuscation{
				JC: 4, JMin: 12, JMax: 64,
				S1: 16, S2: 80, S3: 24, S4: 8,
				H1: 111111, H2: 222222, H3: 333333, H4: 444444,
			},
		},
		KeyProvider:   fixedKeyProvider{material: directawg.LinuxKeyMaterial{Generation: 1, PrivateKey: clientPrivateKey, PSK: psk}},
		Verifier:      verifier,
		PolicyFactory: policyFactory,
		Runner:        runner,
	})
	if err != nil {
		fatalf("construct controller: %v", err)
	}

	// A real protected dialer, not the LabMode-only generic UDPDialer:
	// found by chasing an "operation not permitted" write error back to
	// its root cause during this same session's testing. The generic
	// dialer is explicitly documented as unable to protect its own
	// socket from the kill switch it's racing against; this one binds to
	// the named underlay and applies the same mark the nftables policy
	// admits, exactly like a real platform route monitor would.
	protectedDialer, err := directawg.NewLinuxProtectedUDPDialer(directawg.LinuxProtectedUDPDialerConfig{
		InterfaceName: *underlayInterface,
		FirewallMark:  underlayMark,
	})
	if err != nil {
		fatalf("construct protected dialer: %v", err)
	}

	gateways := defaultGateways()
	if *gatewayID != "" {
		selected := make([]gatewaySpec, 0, 1)
		for _, gateway := range gateways {
			if gateway.name == *gatewayID {
				selected = append(selected, gateway)
				break
			}
		}
		if len(selected) != 1 {
			fatalf("gateway-id %q is unknown", *gatewayID)
		}
		gateways = selected
	} else if *gatewayLimit > 0 && *gatewayLimit < len(gateways) {
		gateways = gateways[:*gatewayLimit]
	}
	manifestDigest := effectiveManifestDigest(gateways)
	farFuture := time.Now().UTC().Add(24 * time.Hour)

	candidates := make([]connectivity.Candidate, 0, len(gateways))
	descriptors := make([]connectivity.CandidateDescriptor, 0, len(gateways))
	for _, gateway := range gateways {
		descriptor := connectivity.CandidateDescriptor{
			ID:        gateway.name,
			Carrier:   connectivity.CarrierDirectAWG,
			NodeID:    gateway.name,
			ExpiresAt: farFuture,
		}
		candidate, err := directawg.NewCandidate(directawg.Config{
			Descriptor:        descriptor,
			Endpoint:          gateway.endpoint,
			GatewayPublicKey:  gateway.publicKey,
			MinInnerDatagram:  1200,
			MaxInnerDatagram:  1350,
			IdleTimeout:       30 * time.Second,
			SocketBufferBytes: 4 << 20,
			Controller:        controller,
			Dialer:            protectedDialer,
		})
		if err != nil {
			fatalf("construct candidate %s: %v", gateway.name, err)
		}
		candidates = append(candidates, candidate)
		descriptors = append(descriptors, descriptor)
	}

	log, err := openOrCreateLog(*logPath, *logKeyPath)
	if err != nil {
		fatalf("open measurement log: %v", err)
	}
	defer func() {
		if err := log.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "measurement log close: %v\n", err)
		}
	}()

	var readiness connectivity.Readiness
	haveReadiness := false

	for attemptIndex := 1; attemptIndex <= *attempts; attemptIndex++ {
		now := time.Now().UTC()
		readinessClass := measurement.ReadinessWarm
		if !haveReadiness || !readiness.ExpiresAt.After(now.Add(2*time.Second)) ||
			(attemptIndex-1)%(*warmBatch) == 0 {
			readiness = connectivity.Readiness{
				Profile:           readinessProfile,
				Mode:              connectivity.ModeAuto,
				ManifestDigest:    manifestDigest,
				ManifestExpiresAt: farFuture,
				PSKGeneration:     1,
				PSKExpiresAt:      farFuture,
				UnusedCredentials: 8,
				PreparedAt:        now,
				ExpiresAt:         now.Add(connectivity.DefaultReadinessTTL),
				Candidates:        descriptors,
			}
			haveReadiness = true
			readinessClass = measurement.ReadinessCold
		}

		coordinator := connectivity.NewCoordinator()
		sessionID := randomHex32()
		result := coordinator.Connect(context.Background(), connectivity.ConnectRequest{
			Readiness:     readiness,
			Candidates:    candidates,
			SessionID:     sessionID,
			SequenceEpoch: uint64(attemptIndex),
			Deadline:      connectivity.DefaultDeadline,
		})
		var holdFailure error
		if result.State == connectivity.StateOnline && *onlineHold > 0 {
			fmt.Printf(
				"HOLD_ONLINE candidate=%s duration=%s\n",
				result.CandidateID,
				onlineHold.String(),
			)
			timer := time.NewTimer(*onlineHold)
			<-timer.C
			status := coordinator.Status()
			if status.State != connectivity.StateOnline {
				holdFailure = fmt.Errorf(
					"connection lost during online hold: state=%s failure=%s",
					status.State,
					status.Failure,
				)
			}
		}
		stopErr := coordinator.Stop()
		if stopErr != nil {
			fmt.Fprintf(
				os.Stderr,
				"attempt %d: coordinator stop: %v\n",
				attemptIndex,
				stopErr,
			)
		}
		if holdFailure != nil {
			fatalf("attempt %d: %v", attemptIndex, holdFailure)
		}
		if stopErr != nil {
			fatalf("attempt %d: teardown failed: %v", attemptIndex, stopErr)
		}

		candidateIDs := make([]string, 0, len(descriptors))
		for _, descriptor := range descriptors {
			candidateIDs = append(candidateIDs, descriptor.ID)
		}
		serverRegion := ""
		serverProvider := ""
		for _, gateway := range gateways {
			if gateway.name == result.CandidateID {
				serverRegion = gateway.region
				serverProvider = gateway.provider
				break
			}
		}

		attempt, err := measurement.FromConnectivityResult(result, measurement.AttemptMetadata{
			SourceDigest:   sourceTreeDigest,
			ArtifactDigest: artifactDigest,
			ManifestDigest: manifestDigest,
			Platform:       "linux",
			OSVersion:      *osVersion,
			Device:         *device,
			Readiness:      readinessClass,
			CandidateIDs:   candidateIDs,
			Network: measurement.NetworkProfile{
				Interface:      *networkInterface,
				IPFamily:       *ipFamily,
				NAT:            *natType,
				Impairment:     *impairment,
				RTTMillis:      *rttMillis,
				LossFraction:   *lossFraction,
				CapacityMbps:   *capacityMbps,
				ClientRegion:   *clientRegion,
				ServerRegion:   serverRegion,
				ServerProvider: serverProvider,
			},
		})
		if err != nil {
			fatalf("attempt %d: build measurement record: %v", attemptIndex, err)
		}
		if err := log.Append(attempt); err != nil {
			fatalf("attempt %d: append measurement record: %v", attemptIndex, err)
		}

		fmt.Printf(
			"attempt %d/%d readiness=%s outcome=%s candidate=%s failure=%s outcome_ms=%.1f\n",
			attemptIndex, *attempts, readinessClass, result.State,
			result.CandidateID, result.Failure,
			float64(result.Timings.Outcome.Microseconds())/1000,
		)
	}

	summary := log.Summary()
	fmt.Printf(
		"\nSUMMARY total=%d success=%d failure=%d p50=%s p95=%s p99=%s success_p99=%s\n",
		summary.Total, summary.Successes, summary.Failures,
		summary.OutcomeP50, summary.OutcomeP95, summary.OutcomeP99,
		summary.SuccessfulOutcomeP99,
	)
	for code, count := range summary.FailureCounts {
		fmt.Printf("  failure %s: %d\n", code, count)
	}
}

func openOrCreateLog(path, keyPath string) (*measurement.Log, error) {
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		key := make([]byte, sha256.Size)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate measurement key: %w", err)
		}
		if err := os.WriteFile(keyPath, key, 0o600); err != nil {
			clear(key)
			return nil, fmt.Errorf("write measurement key: %w", err)
		}
		clear(key)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return measurement.Create(path, keyPath)
	}
	return measurement.Open(path, keyPath)
}

// readBase64File reads a base64 key file through the shared private reader,
// which requires a real regular file with no group or other access and bounds
// the read. os.ReadFile did none of those things for a path holding key
// material.
func readBase64File(path string) ([]byte, error) {
	data, err := securefile.ReadPrivateLimited(path, 4<<10)
	if err != nil {
		return nil, err
	}
	decoded, decodeErr := base64.StdEncoding.DecodeString(
		strings.TrimSpace(string(data)),
	)
	clear(data)
	return decoded, decodeErr
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// sha256File hashes an evidence artifact through the shared checked reader.
//
// Two guarantees come from there, and both matter for a value that is sealed
// into evidence. TYPE: a symbolic link, a FIFO or a device node in that
// position is refused rather than followed, so the digest cannot describe
// something other than the file the manifest names. STABILITY: the read is
// bracketed by descriptor stats and performed twice, so an in-place rewrite
// landing mid-stream is refused instead of producing a digest of a
// half-old/half-new byte sequence the file never actually held. That second
// property is why this returns an error the caller must honour: the only
// argument here is os.Executable(), and a refusal means the running artifact
// changed underneath the run that is about to be attested.
func sha256File(path string) (string, error) {
	return securefile.SHA256Regular(path)
}

func lowerHexDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil &&
		len(decoded) == sha256.Size &&
		value == strings.ToLower(value)
}

func validateNetworkMetadata(
	networkInterface string,
	ipFamily string,
	natType string,
	impairment string,
	rttMillis float64,
	lossFraction float64,
	capacityMbps float64,
	clientRegion string,
) error {
	switch networkInterface {
	case "ethernet", "wifi", "cellular", "loopback", "synthetic":
	default:
		return errors.New("interface is invalid")
	}
	switch ipFamily {
	case "ipv4", "ipv6", "dual", "nat64":
	default:
		return errors.New("IP family is invalid")
	}
	if len(natType) > 64 || len(impairment) == 0 ||
		len(impairment) > 128 || len(clientRegion) == 0 ||
		len(clientRegion) > 128 {
		return errors.New("labels are invalid")
	}
	if math.IsNaN(rttMillis) || math.IsInf(rttMillis, 0) ||
		rttMillis < 0 || rttMillis > 60_000 ||
		math.IsNaN(lossFraction) || math.IsInf(lossFraction, 0) ||
		lossFraction < 0 || lossFraction > 1 ||
		math.IsNaN(capacityMbps) || math.IsInf(capacityMbps, 0) ||
		capacityMbps < 0 {
		return errors.New("numeric values are invalid")
	}
	return nil
}

func effectiveManifestDigest(gateways []gatewaySpec) string {
	var profile strings.Builder
	profile.WriteString("winn-acceptance-effective-manifest/v2\n")
	for _, gateway := range gateways {
		fmt.Fprintf(
			&profile,
			"%s|%s|%s|%s|%s\n",
			gateway.name,
			gateway.region,
			gateway.provider,
			gateway.endpoint,
			gateway.publicKey,
		)
	}
	fmt.Fprintf(
		&profile,
		"dns=%s|canary=%s|pool=%s|route=%s|readiness=%s\n",
		sharedDNSResolver,
		sharedCanaryEndpoint,
		sharedInnerPool,
		sharedTunnelRoute,
		readinessProfile,
	)
	return sha256Hex(profile.String())
}

func randomHex32() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buffer)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

type fixedKeyProvider struct {
	material directawg.LinuxKeyMaterial
}

func (provider fixedKeyProvider) KeyMaterial(
	_ context.Context, _ connectivity.Binding,
) (directawg.LinuxKeyMaterial, error) {
	privateKey := append([]byte(nil), provider.material.PrivateKey...)
	psk := append([]byte(nil), provider.material.PSK...)
	return directawg.LinuxKeyMaterial{
		Generation: provider.material.Generation,
		PrivateKey: privateKey,
		PSK:        psk,
	}, nil
}

// realCommandRunner executes every real command for real (nft, awg,
// amneziawg-go, ip) except resolvectl, which cannot be meaningfully
// exercised inside a network namespace whose systemd-resolved is the root
// namespace's own (see cmd/winn-aicore-directawg-e2e for the original
// finding) — it is intercepted and recorded instead.
type realCommandRunner struct {
	// allowed is the fixed set of executables this runner may launch.
	allowed          *directawg.LinuxExecAllowList
	resolvectlBinary string
	mu               sync.Mutex
	interceptedCalls []directawg.LinuxCommand
}

func (runner *realCommandRunner) Run(
	ctx context.Context, command directawg.LinuxCommand,
) (directawg.LinuxCommandResult, error) {
	if command.Path == runner.resolvectlBinary {
		runner.mu.Lock()
		runner.interceptedCalls = append(runner.interceptedCalls, command)
		runner.mu.Unlock()
		return directawg.LinuxCommandResult{}, nil
	}
	if err := runner.allowed.Require(command.Path); err != nil {
		return directawg.LinuxCommandResult{}, err
	}
	// #nosec G204 -- command.Path was just required to be a member of this
	// runner's fixed allow-list, built from the executables the operator named
	// on the command line and validated as absolute paths. Args are passed as
	// separate argv elements and never through a shell, so no argument can
	// introduce a second command. This is authorised lab tooling driving hosts
	// the operator controls. The list pins the path STRING, not the executable
	// object behind it: see LinuxExecAllowList for the exact scope, including
	// the exec boundaries it does not cover.
	process := exec.CommandContext(ctx, command.Path, command.Args...)
	var stdout, stderr strings.Builder
	process.Stdout = &stdout
	process.Stderr = &stderr
	err := process.Run()
	result := directawg.LinuxCommandResult{
		Stdout: []byte(stdout.String()),
		Stderr: []byte(stderr.String()),
	}
	if err != nil {
		return result, fmt.Errorf("%s %s: %w: %s", command.Path, strings.Join(command.Args, " "), err, stderr.String())
	}
	return result, nil
}

func (runner *realCommandRunner) Start(
	command directawg.LinuxCommand,
) (directawg.LinuxManagedProcess, error) {
	if err := runner.allowed.Require(command.Path); err != nil {
		return nil, err
	}
	// #nosec G204 -- command.Path was just required to be a member of this
	// runner's fixed allow-list, built from the executables the operator named
	// on the command line and validated as absolute paths. Args are passed as
	// separate argv elements and never through a shell, so no argument can
	// introduce a second command. This is authorised lab tooling driving hosts
	// the operator controls. The list pins the path STRING, not the executable
	// object behind it: see LinuxExecAllowList for the exact scope, including
	// the exec boundaries it does not cover.
	process := exec.Command(command.Path, command.Args...)
	if err := process.Start(); err != nil {
		return nil, err
	}
	managed := &realManagedProcess{process: process, exited: make(chan struct{})}
	go func() {
		err := process.Wait()
		managed.mu.Lock()
		managed.err = err
		managed.mu.Unlock()
		close(managed.exited)
	}()
	return managed, nil
}

type realManagedProcess struct {
	process  *exec.Cmd
	exited   chan struct{}
	mu       sync.Mutex
	err      error
	stopOnce sync.Once
	stopErr  error
}

func (process *realManagedProcess) Exited() <-chan struct{} { return process.exited }

func (process *realManagedProcess) Err() error {
	select {
	case <-process.exited:
	default:
		return nil
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.err
}

func (process *realManagedProcess) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	process.stopOnce.Do(func() {
		select {
		case <-process.exited:
			return
		default:
		}
		if err := process.process.Process.Signal(os.Interrupt); err != nil {
			_ = process.process.Process.Kill()
		}
		select {
		case <-process.exited:
		case <-ctx.Done():
			process.stopErr = ctx.Err()
			_ = process.process.Process.Kill()
			<-process.exited
		}
	})
	return process.stopErr
}
