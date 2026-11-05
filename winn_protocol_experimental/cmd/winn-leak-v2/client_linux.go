//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/directawg"
	"winsvpn.local/winnprotocol/internal/securefile"
)

// sourceTreeDigest is set by the acceptance build:
//
//	-ldflags "-X main.sourceTreeDigest=<sha256-of-exact-source-inputs>"
//
// The leak driver refuses an unstamped binary because its output is intended
// to be acceptance evidence, not an informal smoke test.
var sourceTreeDigest string

const crashAcknowledgement = "LEAVE_FAIL_CLOSED_STATE_FOR_EXTERNAL_RECOVERY"

type clientState struct {
	Version        string `json:"version"`
	At             string `json:"at"`
	RunID          string `json:"run_id"`
	Phase          string `json:"phase"`
	PID            int    `json:"pid"`
	Family         string `json:"family"`
	InterfaceName  string `json:"interface_name,omitempty"`
	NftTable       string `json:"nft_table"`
	SourceDigest   string `json:"source_digest"`
	ArtifactDigest string `json:"artifact_digest"`
	Failure        string `json:"failure,omitempty"`
}

type clientEvent struct {
	Sequence      uint64 `json:"sequence"`
	At            string `json:"at"`
	RunID         string `json:"run_id"`
	Phase         string `json:"phase"`
	InterfaceName string `json:"interface_name,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

type clientEventWriter struct {
	file     *os.File
	encoder  *json.Encoder
	runID    string
	sequence uint64
}

func newClientEventWriter(path, runID string) (*clientEventWriter, error) {
	file, err := openExclusivePrivateFile(path)
	if err != nil {
		return nil, err
	}
	return &clientEventWriter{
		file: file, encoder: json.NewEncoder(file), runID: runID,
	}, nil
}

func (writer *clientEventWriter) append(event clientEvent) error {
	writer.sequence++
	event.Sequence = writer.sequence
	event.At = time.Now().UTC().Format(time.RFC3339Nano)
	event.RunID = writer.runID
	if err := writer.encoder.Encode(event); err != nil {
		return err
	}
	return writer.file.Sync()
}

func (writer *clientEventWriter) close() error {
	return errors.Join(writer.file.Sync(), writer.file.Close())
}

type clientRuntime struct {
	runID          string
	family         string
	controlDir     string
	statePath      string
	tableName      string
	sourceDigest   string
	artifactDigest string
	interfaceName  string
	events         *clientEventWriter
}

func (runtime *clientRuntime) phase(phase, detail string) error {
	if err := runtime.events.append(clientEvent{
		Phase: phase, InterfaceName: runtime.interfaceName, Detail: detail,
	}); err != nil {
		return err
	}
	return writeReplaceJSON(runtime.statePath, clientState{
		Version:        "winn-leak-client/v2",
		At:             time.Now().UTC().Format(time.RFC3339Nano),
		RunID:          runtime.runID,
		Phase:          phase,
		PID:            os.Getpid(),
		Family:         runtime.family,
		InterfaceName:  runtime.interfaceName,
		NftTable:       runtime.tableName,
		SourceDigest:   runtime.sourceDigest,
		ArtifactDigest: runtime.artifactDigest,
		Failure: func() string {
			if phase == "failed" {
				return detail
			}
			return ""
		}(),
	})
}

type clientConfig struct {
	runID             string
	family            string
	controlDir        string
	statePath         string
	eventPath         string
	tempRoot          string
	gatewayEndpoint   string
	gatewayPublicKey  string
	clientKeyFile     string
	pskFile           string
	innerPool         netip.Prefix
	allowed           []netip.Prefix
	verification      []netip.Prefix
	dnsResolver       string
	dnsQueryName      string
	expectedDNSAnswer netip.Addr
	canaryEndpoint    string
	tableName         string
	underlayInterface string
	underlayMark      uint32
	awgGoBinary       string
	awgBinary         string
	ipBinary          string
	nftBinary         string
	resolvectlBinary  string
	commandTimeout    time.Duration
	crashAck          string
}

func runClient(args []string) (resultErr error) {
	config, err := parseClientConfig(args)
	if err != nil {
		return err
	}
	if !lowerHex(sourceTreeDigest, sha256.Size) {
		return errors.New("client binary lacks a valid embedded source-tree digest")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	artifactDigest, err := sha256File(executable)
	if err != nil {
		return err
	}
	events, err := newClientEventWriter(config.eventPath, config.runID)
	if err != nil {
		return fmt.Errorf("create client event log: %w", err)
	}
	runtime := &clientRuntime{
		runID: config.runID, family: config.family,
		controlDir: config.controlDir, statePath: config.statePath,
		tableName: config.tableName, sourceDigest: sourceTreeDigest,
		artifactDigest: artifactDigest, events: events,
	}
	defer func() {
		resultErr = errors.Join(resultErr, events.close())
	}()
	if err := runtime.phase("starting", ""); err != nil {
		return err
	}

	privateKey, err := readBase64Secret(config.clientKeyFile)
	if err != nil {
		_ = runtime.phase("failed", "read client key")
		return fmt.Errorf("read client key: %w", err)
	}
	defer clear(privateKey)
	psk, err := readBase64Secret(config.pskFile)
	if err != nil {
		_ = runtime.phase("failed", "read PSK")
		return fmt.Errorf("read PSK: %w", err)
	}
	defer clear(psk)

	// The fixed set of executables this harness may launch, taken from the
	// same operator-supplied flags the controller and policy factory are
	// configured with. Anything else is refused at the exec call.
	allowedExecutables, err := directawg.NewLinuxExecAllowList(
		config.awgGoBinary, config.awgBinary, config.ipBinary,
		config.nftBinary, config.resolvectlBinary,
	)
	if err != nil {
		_ = runtime.phase("failed", "executable allow-list")
		return fmt.Errorf("executable allow-list: %w", err)
	}
	runner := newRealLinuxRunner(allowedExecutables)
	resolver, _ := netip.ParseAddrPort(config.dnsResolver)
	verifier, err := directawg.NewLinuxProtectedVerifier(
		directawg.LinuxVerificationConfig{
			DNSResolver:        config.dnsResolver,
			DNSQueryName:       config.dnsQueryName,
			ExpectedDNSAnswers: []netip.Addr{config.expectedDNSAnswer},
			CanaryEndpoint:     config.canaryEndpoint,
			Timeout:            3 * time.Second,
		},
	)
	if err != nil {
		_ = runtime.phase("failed", "construct protected verifier")
		return err
	}
	factory, err := directawg.NewLinuxNftResolvedPolicyFactory(
		directawg.LinuxNftResolvedPolicyConfig{
			NftBinary: config.nftBinary, ResolvectlBinary: config.resolvectlBinary,
			TempRoot: config.tempRoot, TableName: config.tableName,
			UnderlayInterface: config.underlayInterface,
			UnderlayMark:      config.underlayMark, DNSResolver: resolver.Addr(),
			HealthInterval: 500 * time.Millisecond, Runner: runner,
		},
	)
	if err != nil {
		_ = runtime.phase("failed", "construct fail-closed policy")
		return fmt.Errorf("construct policy factory: %w", err)
	}
	controller, err := directawg.NewLinuxController(
		directawg.LinuxControllerConfig{
			AWGGoBinary: config.awgGoBinary, AWGBinary: config.awgBinary,
			IPBinary: config.ipBinary, TempRoot: config.tempRoot,
			Signed: directawg.LinuxSignedInterfaceConfig{
				InnerAddressPool:   config.innerPool,
				AllowedIPs:         slices.Clone(config.allowed),
				VerificationRoutes: slices.Clone(config.verification),
				MTU:                1280, ListenPortMin: 41400, ListenPortMax: 41463,
				PersistentKeepalive: 25,
				Obfuscation: directawg.AWGObfuscation{
					JC: 4, JMin: 12, JMax: 64,
					S1: 16, S2: 80, S3: 24, S4: 8,
					H1: 111111, H2: 222222, H3: 333333, H4: 444444,
				},
			},
			KeyProvider: fixedLeakKeyProvider{
				material: directawg.LinuxKeyMaterial{
					Generation: 1, PrivateKey: privateKey, PSK: psk,
				},
			},
			Verifier: verifier, PolicyFactory: factory, Runner: runner,
		},
	)
	if err != nil {
		_ = runtime.phase("failed", "construct Linux controller")
		return fmt.Errorf("construct Linux controller: %w", err)
	}
	dialer, err := directawg.NewLinuxProtectedUDPDialer(
		directawg.LinuxProtectedUDPDialerConfig{
			InterfaceName: config.underlayInterface,
			FirewallMark:  config.underlayMark,
		},
	)
	if err != nil {
		_ = runtime.phase("failed", "construct protected underlay dialer")
		return fmt.Errorf("construct protected dialer: %w", err)
	}
	descriptor := connectivity.CandidateDescriptor{
		ID: "leak-v2-direct", Carrier: connectivity.CarrierDirectAWG,
		NodeID: "leak-v2-gateway", ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	candidate, err := directawg.NewCandidate(directawg.Config{
		Descriptor: descriptor, Endpoint: config.gatewayEndpoint,
		GatewayPublicKey: config.gatewayPublicKey,
		MinInnerDatagram: 1200, MaxInnerDatagram: 1350,
		IdleTimeout: 30 * time.Second, SocketBufferBytes: 4 << 20,
		Controller: controller, Dialer: dialer,
	})
	if err != nil {
		_ = runtime.phase("failed", "construct direct-AWG candidate")
		return fmt.Errorf("construct direct-AWG candidate: %w", err)
	}
	binding := connectivity.Binding{
		AttemptID: randomHex(16), Profile: "leak-v2",
		Mode: connectivity.ModeAuto, ManifestDigest: randomHex(32),
		CandidateID: descriptor.ID, NodeID: descriptor.NodeID,
		SessionID: randomHex(16), PSKGeneration: 1, SequenceEpoch: 1,
		Nonce: randomHex(16), ExpiresAt: time.Now().UTC().Add(time.Hour),
	}

	beforeInterfaces, err := listWinnInterfaces()
	if err != nil {
		return err
	}
	signalContext, stopSignals := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP,
	)
	defer stopSignals()
	dialContext, cancelDial := context.WithTimeout(signalContext, 20*time.Second)
	connection, err := candidate.Dial(dialContext, binding)
	cancelDial()
	if err != nil {
		_ = runtime.phase("failed", "dial failed")
		releaseErr := releasePolicy(factory)
		return errors.Join(fmt.Errorf("dial production candidate: %w", err), releaseErr)
	}
	cleaned := false
	cleanup := func() error {
		if cleaned {
			return nil
		}
		cleaned = true
		closeErr := connection.Close()
		releaseErr := releasePolicy(factory)
		return errors.Join(closeErr, releaseErr)
	}
	defer func() {
		if !cleaned {
			resultErr = errors.Join(resultErr, cleanup())
		}
	}()
	afterInterfaces, err := listWinnInterfaces()
	if err != nil {
		return err
	}
	runtime.interfaceName, err = oneNewInterface(beforeInterfaces, afterInterfaces)
	if err != nil {
		return err
	}
	if err := runtime.phase("prepared", "kill switch active; no default route committed"); err != nil {
		return err
	}
	if err := waitBarrier(
		signalContext, connection.Health(), config, "continue-prepared",
	); err != nil {
		return err
	}

	verifyContext, cancelVerify := context.WithTimeout(
		signalContext, 12*time.Second,
	)
	err = connection.FreshAWGHandshake(verifyContext, binding)
	if err == nil {
		err = connection.VerifyProtectedDNS(verifyContext, binding)
	}
	if err == nil {
		err = connection.VerifyTunnelCanary(verifyContext, binding)
	}
	if err == nil {
		err = connection.VerifyBidirectional(verifyContext, binding)
	}
	cancelVerify()
	if err != nil {
		_ = runtime.phase("failed", "candidate verification failed")
		return fmt.Errorf("verify production candidate: %w", err)
	}
	if err := runtime.phase("verified", "protected DNS and tunnel canary verified"); err != nil {
		return err
	}
	if err := waitBarrier(
		signalContext, connection.Health(), config, "continue-verified",
	); err != nil {
		return err
	}

	commitContext, cancelCommit := context.WithTimeout(
		signalContext, 5*time.Second,
	)
	err = connection.Commit(commitContext, binding)
	cancelCommit()
	if err != nil {
		_ = runtime.phase("failed", "commit failed")
		return fmt.Errorf("commit production candidate: %w", err)
	}
	if err := verifyResolverCommit(
		signalContext, runner, config, runtime.interfaceName,
	); err != nil {
		_ = runtime.phase("failed", "resolver commit not observed")
		return err
	}
	if err := runtime.phase(
		"committed", "full route and real systemd-resolved ownership committed",
	); err != nil {
		return err
	}
	action, err := waitCommitted(signalContext, connection.Health(), config)
	if err != nil {
		_ = runtime.phase("failed", "health or control failure")
		return err
	}
	if action == "crash" {
		if config.crashAck != crashAcknowledgement {
			return errors.New("self-crash command requires the exact crash acknowledgement")
		}
		if err := runtime.phase(
			"crashing", "SIGKILL requested; external recovery now owns cleanup",
		); err != nil {
			return err
		}
		return syscall.Kill(os.Getpid(), syscall.SIGKILL)
	}
	if err := runtime.phase("stopping", "graceful stop requested"); err != nil {
		return err
	}
	if err := cleanup(); err != nil {
		_ = runtime.phase("failed", "graceful cleanup failed")
		return fmt.Errorf("graceful cleanup: %w", err)
	}
	if err := assertReleased(runner, config, runtime.interfaceName); err != nil {
		_ = runtime.phase("failed", "post-stop release invariant failed")
		return err
	}
	return runtime.phase("stopped", "interface, resolver, routes, and kill switch released")
}

func parseClientConfig(args []string) (clientConfig, error) {
	flags := flag.NewFlagSet("client", flag.ContinueOnError)
	var raw clientConfig
	runID := flags.String("run-id", "", "lowercase 32-hex run identifier")
	family := flags.String("family", "", "v4 or v6")
	controlDir := flags.String("control-dir", "", "existing absolute 0700 control directory")
	statePath := flags.String("state-file", "", "absolute replaceable state JSON path")
	eventPath := flags.String("event-log", "", "exclusive absolute JSONL event path")
	tempRoot := flags.String("temp-root", "", "existing absolute 0700 temporary root")
	gatewayEndpoint := flags.String("gateway-endpoint", "", "outer IP-literal gateway endpoint")
	gatewayPublicKey := flags.String("gateway-pubkey", "", "AWG gateway public key")
	clientKeyFile := flags.String("client-private-key-file", "", "absolute mode-0600 base64 key file")
	pskFile := flags.String("psk-file", "", "absolute mode-0600 base64 PSK file")
	innerPool := flags.String("inner-pool", "", "single-family private client pool")
	allowed := flags.String("allowed-ips", "", "comma-separated single-family allowed prefixes")
	verification := flags.String("verification-routes", "", "comma-separated signed probe prefixes")
	dnsResolver := flags.String("dns-resolver", "", "tunnel DNS IP-literal endpoint")
	dnsQueryName := flags.String("dns-query-name", "", "protected DNS canary name")
	expectedDNS := flags.String("expected-dns-answer", "", "signed expected DNS answer")
	canaryEndpoint := flags.String("canary-endpoint", "", "tunnel canary IP-literal endpoint")
	tableName := flags.String("table-name", "", "unique nftables table")
	underlayInterface := flags.String("underlay-interface", "", "physical underlay interface")
	underlayMark := flags.String("underlay-mark", "", "hex protected-socket mark")
	awgGoBinary := flags.String("awg-go-binary", "/opt/winn-lab/bin/amneziawg-go", "amneziawg-go path")
	awgBinary := flags.String("awg-binary", "/opt/winn-lab/bin/awg", "awg path")
	ipBinary := flags.String("ip-binary", "/usr/sbin/ip", "ip path")
	nftBinary := flags.String("nft-binary", "/usr/sbin/nft", "nft path")
	resolvectlBinary := flags.String("resolvectl-binary", "/usr/bin/resolvectl", "real resolvectl path")
	commandTimeout := flags.Duration("command-timeout", 2*time.Minute, "maximum wait at each lifecycle barrier")
	crashAck := flags.String("crash-ack", "", "exact acknowledgement required for crash-now")
	if err := flags.Parse(args); err != nil {
		return raw, err
	}
	raw = clientConfig{
		runID: *runID, family: *family, controlDir: *controlDir,
		statePath: *statePath, eventPath: *eventPath, tempRoot: *tempRoot,
		gatewayEndpoint: *gatewayEndpoint, gatewayPublicKey: *gatewayPublicKey,
		clientKeyFile: *clientKeyFile, pskFile: *pskFile,
		dnsResolver: *dnsResolver, dnsQueryName: *dnsQueryName,
		canaryEndpoint: *canaryEndpoint, tableName: *tableName,
		underlayInterface: *underlayInterface,
		awgGoBinary:       *awgGoBinary, awgBinary: *awgBinary,
		ipBinary: *ipBinary, nftBinary: *nftBinary,
		resolvectlBinary: *resolvectlBinary, commandTimeout: *commandTimeout,
		crashAck: *crashAck,
	}
	if !lowerHex(raw.runID, 16) || (raw.family != "v4" && raw.family != "v6") {
		return raw, errors.New("client run-id must be lowercase 32-hex and family must be v4 or v6")
	}
	for name, path := range map[string]string{
		"control-dir": raw.controlDir, "state-file": raw.statePath,
		"event-log": raw.eventPath, "temp-root": raw.tempRoot,
		"client-private-key-file": raw.clientKeyFile, "psk-file": raw.pskFile,
	} {
		if !filepath.IsAbs(path) {
			return raw, fmt.Errorf("%s must be absolute", name)
		}
	}
	if err := requirePrivateDirectory(raw.controlDir); err != nil {
		return raw, fmt.Errorf("control directory: %w", err)
	}
	if err := requirePrivateDirectory(raw.tempRoot); err != nil {
		return raw, fmt.Errorf("temporary root: %w", err)
	}
	for _, path := range []string{raw.clientKeyFile, raw.pskFile} {
		if err := requirePrivateFile(path); err != nil {
			return raw, err
		}
	}
	pool, err := netip.ParsePrefix(*innerPool)
	if err != nil {
		return raw, fmt.Errorf("parse inner pool: %w", err)
	}
	raw.innerPool = pool
	raw.allowed, err = parsePrefixes(*allowed)
	if err != nil {
		return raw, fmt.Errorf("parse allowed IPs: %w", err)
	}
	raw.verification, err = parsePrefixes(*verification)
	if err != nil {
		return raw, fmt.Errorf("parse verification routes: %w", err)
	}
	resolver, err := netip.ParseAddrPort(raw.dnsResolver)
	if err != nil {
		return raw, fmt.Errorf("parse DNS resolver: %w", err)
	}
	answer, err := netip.ParseAddr(*expectedDNS)
	if err != nil {
		return raw, fmt.Errorf("parse expected DNS answer: %w", err)
	}
	raw.expectedDNSAnswer = answer
	canary, err := netip.ParseAddrPort(raw.canaryEndpoint)
	if err != nil {
		return raw, fmt.Errorf("parse canary endpoint: %w", err)
	}
	isV4 := raw.family == "v4"
	if pool.Addr().Is4() != isV4 || resolver.Addr().Is4() != isV4 ||
		answer.Is4() != isV4 || canary.Addr().Is4() != isV4 {
		return raw, errors.New("client family, inner pool, resolver, answer, and canary differ")
	}
	for _, prefix := range append(slices.Clone(raw.allowed), raw.verification...) {
		if prefix.Addr().Is4() != isV4 {
			return raw, errors.New("client allowed/verification prefix family differs")
		}
	}
	if isV4 && !slices.Contains(raw.allowed, netip.MustParsePrefix("0.0.0.0/0")) {
		return raw, errors.New("v4 leak acceptance requires an exact 0.0.0.0/0 full-tunnel route")
	}
	if !isV4 && !slices.Contains(raw.allowed, netip.MustParsePrefix("::/0")) {
		return raw, errors.New("v6 leak acceptance requires an exact ::/0 full-tunnel route")
	}
	mark, err := strconv.ParseUint(*underlayMark, 16, 32)
	if err != nil || mark == 0 {
		return raw, errors.New("client underlay mark must be nonzero hex")
	}
	raw.underlayMark = uint32(mark)
	if raw.commandTimeout < 10*time.Second || raw.commandTimeout > 15*time.Minute {
		return raw, errors.New("client command-timeout must be between 10s and 15m")
	}
	if raw.gatewayEndpoint == "" || raw.gatewayPublicKey == "" ||
		raw.dnsQueryName == "" || raw.tableName == "" ||
		raw.underlayInterface == "" {
		return raw, errors.New("client gateway, DNS, table, and underlay fields are required")
	}
	return raw, nil
}

func waitBarrier(
	ctx context.Context,
	health <-chan error,
	config clientConfig,
	command string,
) error {
	action, err := waitForControl(ctx, health, config, command)
	if err != nil {
		return err
	}
	if action == "crash" {
		if config.crashAck != crashAcknowledgement {
			return errors.New("self-crash command requires the exact crash acknowledgement")
		}
		return syscall.Kill(os.Getpid(), syscall.SIGKILL)
	}
	if action != command {
		return fmt.Errorf("unexpected control action %q", action)
	}
	return nil
}

func waitCommitted(
	ctx context.Context,
	health <-chan error,
	config clientConfig,
) (string, error) {
	return waitForControl(ctx, health, config, "stop")
}

func waitForControl(
	ctx context.Context,
	health <-chan error,
	config clientConfig,
	expected string,
) (string, error) {
	timer := time.NewTimer(config.commandTimeout)
	defer timer.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return "stop", nil
		case err, ok := <-health:
			if !ok || err == nil {
				return "", errors.New("candidate health stream ended")
			}
			return "", fmt.Errorf("candidate health failed: %w", err)
		case <-timer.C:
			return "", fmt.Errorf("timed out waiting for %s", expected)
		case <-ticker.C:
			for _, action := range []string{"crash-now", expected} {
				path := filepath.Join(config.controlDir, action)
				info, err := os.Lstat(path)
				if os.IsNotExist(err) {
					continue
				}
				if err != nil {
					return "", err
				}
				if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
					info.Size() != 0 {
					return "", fmt.Errorf("control command %s is not an empty regular file", action)
				}
				if action == "crash-now" {
					return "crash", nil
				}
				return action, nil
			}
		}
	}
}

func verifyResolverCommit(
	ctx context.Context,
	runner *realLinuxRunner,
	config clientConfig,
	interfaceName string,
) error {
	checkContext, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	result, err := runner.Run(checkContext, directawg.LinuxCommand{
		Path: config.resolvectlBinary,
		Args: []string{"status", interfaceName},
	})
	if err != nil {
		return fmt.Errorf("read committed resolver state: %w", err)
	}
	output := string(result.Stdout)
	resolver, _ := netip.ParseAddrPort(config.dnsResolver)
	if !strings.Contains(output, resolver.Addr().String()) ||
		!strings.Contains(output, "~.") {
		return errors.New("real resolver state omitted the tunnel DNS server or ~. route")
	}
	return nil
}

func releasePolicy(factory *directawg.LinuxNftResolvedPolicyFactory) error {
	context, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return factory.Release(context)
}

func assertReleased(
	runner *realLinuxRunner,
	config clientConfig,
	interfaceName string,
) error {
	context, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := os.Stat(filepath.Join("/sys/class/net", interfaceName)); !os.IsNotExist(err) {
		if err == nil {
			return errors.New("candidate interface remains after graceful stop")
		}
		return err
	}
	if _, err := runner.Run(context, directawg.LinuxCommand{
		Path: config.nftBinary,
		Args: []string{"list", "table", "inet", config.tableName},
	}); err == nil {
		return errors.New("kill-switch table remains after explicit graceful release")
	}
	return nil
}

type fixedLeakKeyProvider struct {
	material directawg.LinuxKeyMaterial
}

func (provider fixedLeakKeyProvider) KeyMaterial(
	_ context.Context,
	_ connectivity.Binding,
) (directawg.LinuxKeyMaterial, error) {
	return directawg.LinuxKeyMaterial{
		Generation: provider.material.Generation,
		PrivateKey: slices.Clone(provider.material.PrivateKey),
		PSK:        slices.Clone(provider.material.PSK),
	}, nil
}

// readBase64Secret reads a client key or PSK through the shared private
// reader, which requires a real regular file with no group or other access and
// bounds the read. os.ReadFile did none of those things for a path holding key
// material, and this is the most sensitive read in the harness.
func readBase64Secret(path string) ([]byte, error) {
	data, err := securefile.ReadPrivateLimited(path, 4<<10)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	clear(data)
	if err != nil {
		return nil, err
	}
	if len(decoded) != 32 {
		clear(decoded)
		return nil, errors.New("secret must decode to exactly 32 bytes")
	}
	return decoded, nil
}

func requirePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return errors.New("path must be a real directory inaccessible to group/other")
	}
	return nil
}

func requirePrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return errors.New("secret path must be a regular file inaccessible to group/other")
	}
	return nil
}

func parsePrefixes(value string) ([]netip.Prefix, error) {
	parts := strings.Split(value, ",")
	if len(parts) == 0 || len(parts) > 64 {
		return nil, errors.New("prefix count is invalid")
	}
	result := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil || prefix != prefix.Masked() {
			return nil, fmt.Errorf("invalid canonical prefix %q", part)
		}
		if slices.Contains(result, prefix) {
			return nil, fmt.Errorf("duplicated prefix %q", part)
		}
		result = append(result, prefix)
	}
	return result, nil
}

func listWinnInterfaces() ([]string, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}
	var result []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "winn") {
			result = append(result, entry.Name())
		}
	}
	slices.Sort(result)
	return result, nil
}

func oneNewInterface(before, after []string) (string, error) {
	var added []string
	for _, current := range after {
		if !slices.Contains(before, current) {
			added = append(added, current)
		}
	}
	if len(added) != 1 {
		return "", fmt.Errorf("expected one new Winn interface, found %d", len(added))
	}
	return added[0], nil
}

func randomHex(size int) string {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}
	return hex.EncodeToString(data)
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

func writeReplaceJSON(path string, value any) error {
	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, ".winn-leak-state-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := os.Chmod(tempName, 0o600); err != nil {
		_ = temp.Close()
		return err
	}
	encoder := json.NewEncoder(temp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		return err
	}
	// #nosec G304 -- `directory` is filepath.Dir of the caller's state-file
	// path, and this open happens only AFTER os.CreateTemp and os.Rename have
	// both succeeded inside it, so it is known to exist and to be a directory.
	// It is opened solely to fsync the rename for durability: no content is
	// read from it, nothing is written through it, and the handle is closed
	// immediately. There is no path here that could disclose a file's
	// contents.
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
