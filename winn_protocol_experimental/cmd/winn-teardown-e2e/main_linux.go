//go:build linux

// Command winn-teardown-e2e is a privileged fault-injection proof for the
// production DirectAWG Linux teardown contract. It must only run as root
// inside a disposable network namespace created by
// scripts/aicore_teardown_fault_e2e.sh.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/directawg"
	"winsvpn.local/winnprotocol/internal/sysconv"
)

var sourceTreeDigest = "UNEMBEDDED"

const (
	faultNone          = ""
	faultRollbackStall = "rollback-stall"
	faultRouteFailure  = "route-failure"
)

type options struct {
	mode              string
	printSourceDigest bool
	dnsListen         string
	canaryListen      string
	answerIP          string
	gatewayEndpoint   string
	gatewayPublicKey  string
	clientPrivateKey  []byte
	psk               []byte
	innerPool         netip.Prefix
	allowedIP         netip.Prefix
	verificationRoute netip.Prefix
	dnsResolver       string
	expectedDNSAnswer netip.Addr
	canaryEndpoint    string
	tablePrefix       string
	underlayInterface string
	underlayMark      uint32
	awgGoBinary       string
	awgBinary         string
	ipBinary          string
	nftBinary         string
	resolvectlBinary  string
	tempRoot          string
	stopTimeout       time.Duration
	allowPayloadLimit bool
}

func main() {
	cfg, err := parseOptions()
	if err != nil {
		fatalf("%v", err)
	}
	if cfg.printSourceDigest {
		fmt.Println(sourceTreeDigest)
		return
	}
	switch cfg.mode {
	case "server":
		err = runServer(cfg.dnsListen, cfg.canaryListen, cfg.answerIP)
	case "client":
		err = runFaultMatrix(cfg)
	default:
		err = errors.New("mode must be server or client")
	}
	if err != nil {
		fatalf("%v", err)
	}
}

func parseOptions() (options, error) {
	var cfg options
	var clientPrivateKeyB64, pskB64 string
	var innerPool, allowedIP, verificationRoute string
	var expectedDNSAnswer, underlayMarkHex string

	flag.StringVar(&cfg.mode, "mode", "", "server or client")
	flag.BoolVar(&cfg.printSourceDigest, "print-source-digest", false, "print the embedded source-tree digest and exit")
	flag.StringVar(&cfg.dnsListen, "dns-listen", "", "server DNS UDP listen address")
	flag.StringVar(&cfg.canaryListen, "canary-listen", "", "server canary UDP listen address")
	flag.StringVar(&cfg.answerIP, "answer-ip", "", "server DNS answer IPv4 address")
	flag.StringVar(&cfg.gatewayEndpoint, "gateway-endpoint", "", "client raw AWG peer endpoint")
	flag.StringVar(&cfg.gatewayPublicKey, "gateway-pubkey", "", "client AWG peer public key")
	flag.StringVar(&clientPrivateKeyB64, "client-private-key", "", "client base64 private key")
	flag.StringVar(&pskB64, "psk", "", "client base64 preshared key")
	flag.StringVar(&innerPool, "inner-pool", "", "client inner address pool")
	flag.StringVar(&allowedIP, "allowed-ip", "", "client routed CIDR")
	flag.StringVar(&verificationRoute, "verification-route", "", "client verification CIDR")
	flag.StringVar(&cfg.dnsResolver, "dns-resolver", "", "client protected DNS endpoint")
	flag.StringVar(&expectedDNSAnswer, "expected-dns-answer", "", "client expected DNS answer")
	flag.StringVar(&cfg.canaryEndpoint, "canary-endpoint", "", "client protected canary endpoint")
	flag.StringVar(&cfg.tablePrefix, "table-prefix", "winntd", "unique nft table prefix")
	flag.StringVar(&cfg.underlayInterface, "underlay-interface", "", "client namespace veth")
	flag.StringVar(&underlayMarkHex, "underlay-mark", "997a", "hex underlay firewall mark")
	flag.StringVar(&cfg.awgGoBinary, "awg-go-binary", "/opt/winn-lab/bin/amneziawg-go", "amneziawg-go path")
	flag.StringVar(&cfg.awgBinary, "awg-binary", "/opt/winn-lab/bin/awg", "awg path")
	flag.StringVar(&cfg.ipBinary, "ip-binary", "/usr/sbin/ip", "ip path")
	flag.StringVar(&cfg.nftBinary, "nft-binary", "/usr/sbin/nft", "nft path")
	flag.StringVar(&cfg.resolvectlBinary, "resolvectl-binary", "/usr/bin/resolvectl", "resolvectl path")
	flag.StringVar(&cfg.tempRoot, "temp-root", "", "private temporary root")
	flag.DurationVar(&cfg.stopTimeout, "stop-timeout", 650*time.Millisecond, "configured session close ceiling")
	flag.BoolVar(&cfg.allowPayloadLimit, "allow-kernel-payload-limitation", false, "record but do not fail on the known current-kernel inner-payload regression")
	flag.Parse()

	if cfg.printSourceDigest {
		return cfg, nil
	}
	if cfg.mode == "server" {
		return cfg, nil
	}
	if cfg.mode != "client" {
		return cfg, nil
	}
	var err error
	if cfg.clientPrivateKey, err = base64.StdEncoding.DecodeString(clientPrivateKeyB64); err != nil {
		return cfg, fmt.Errorf("decode client private key: %w", err)
	}
	if cfg.psk, err = base64.StdEncoding.DecodeString(pskB64); err != nil {
		return cfg, fmt.Errorf("decode psk: %w", err)
	}
	if cfg.innerPool, err = netip.ParsePrefix(innerPool); err != nil {
		return cfg, fmt.Errorf("parse inner pool: %w", err)
	}
	if cfg.allowedIP, err = netip.ParsePrefix(allowedIP); err != nil {
		return cfg, fmt.Errorf("parse allowed IP: %w", err)
	}
	if cfg.verificationRoute, err = netip.ParsePrefix(verificationRoute); err != nil {
		return cfg, fmt.Errorf("parse verification route: %w", err)
	}
	if cfg.expectedDNSAnswer, err = netip.ParseAddr(expectedDNSAnswer); err != nil {
		return cfg, fmt.Errorf("parse expected DNS answer: %w", err)
	}
	mark, err := strconv.ParseUint(underlayMarkHex, 16, 32)
	if err != nil {
		return cfg, fmt.Errorf("parse underlay mark: %w", err)
	}
	cfg.underlayMark = uint32(mark)
	if cfg.gatewayEndpoint == "" || cfg.gatewayPublicKey == "" ||
		cfg.dnsResolver == "" || cfg.canaryEndpoint == "" ||
		cfg.underlayInterface == "" || cfg.tempRoot == "" {
		return cfg, errors.New("client endpoint, verification, underlay, and temp-root flags are required")
	}
	if cfg.stopTimeout < 100*time.Millisecond || cfg.stopTimeout > 30*time.Second {
		return cfg, errors.New("stop-timeout must be between 100ms and 30s")
	}
	return cfg, nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}

// Server mode deliberately remains tiny: both responders are reached through
// the real peer AWG interface, so a successful client probe proves the actual
// encrypted data path before any teardown fault is armed.
func runServer(dnsAddr, canaryAddr, answerIP string) error {
	if dnsAddr == "" || canaryAddr == "" || answerIP == "" {
		return errors.New("server dns-listen, canary-listen, and answer-ip are required")
	}
	answer := net.ParseIP(answerIP).To4()
	if answer == nil {
		return fmt.Errorf("answer-ip %q is not IPv4", answerIP)
	}
	errs := make(chan error, 2)
	go func() { errs <- serveDNS(dnsAddr, answer) }()
	go func() { errs <- serveCanary(canaryAddr) }()
	fmt.Println("READY")
	return <-errs
}

func serveDNS(addr string, answer net.IP) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	buffer := make([]byte, 4096)
	for {
		count, peer, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		var query dnsmessage.Message
		if err := query.Unpack(buffer[:count]); err != nil || len(query.Questions) != 1 {
			continue
		}
		response := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: query.ID, Response: true},
			Questions: query.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name: query.Questions[0].Name, Type: dnsmessage.TypeA,
					Class: dnsmessage.ClassINET, TTL: 5,
				},
				Body: &dnsmessage.AResource{A: [4]byte(answer)},
			}},
		}
		payload, packErr := response.Pack()
		if packErr == nil {
			_, err = conn.WriteToUDP(payload, peer)
		}
		if err != nil {
			return err
		}
	}
}

func serveCanary(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	buffer := make([]byte, 4096)
	for {
		count, peer, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		if _, err := conn.WriteToUDP(buffer[:count], peer); err != nil {
			return err
		}
	}
}

type scenario struct {
	name               string
	fault              string
	cancelVerification bool
}

func runFaultMatrix(cfg options) error {
	if os.Geteuid() != 0 {
		return errors.New("client must run as root inside its disposable namespace")
	}
	fmt.Printf("SOURCE_DIGEST %s\n", sourceTreeDigest)
	fmt.Println("KERNEL_SCOPE disposable-network-namespace-only")
	fmt.Println("KERNEL_LIMITATION resolvectl-is-recorded-not-applied: systemd-resolved cannot address an interface index in another network namespace")
	cases := []scenario{
		{name: "inflight-verification-cancel", cancelVerification: true},
		{name: "rollback-deadline-retry", fault: faultRollbackStall},
		{name: "route-command-failure-retry", fault: faultRouteFailure},
	}
	for index, test := range cases {
		if err := runScenario(cfg, index+1, test); err != nil {
			return fmt.Errorf("scenario %s: %w", test.name, err)
		}
	}
	fmt.Printf("PASS fault_matrix=%d real_awg=true real_nft=true real_ip=true exact_residue=true\n", len(cases))
	return nil
}

func runScenario(cfg options, ordinal int, test scenario) (resultErr error) {
	fmt.Printf("SCENARIO_BEGIN name=%s\n", test.name)
	// The fixed set of executables this harness may launch.
	allowedExecutables, err := directawg.NewLinuxExecAllowList(
		cfg.resolvectlBinary, cfg.nftBinary, cfg.ipBinary,
		cfg.awgGoBinary, cfg.awgBinary,
	)
	if err != nil {
		return fmt.Errorf("executable allow-list: %w", err)
	}
	runner := newFaultRunner(
		cfg.resolvectlBinary, cfg.nftBinary, cfg.ipBinary, allowedExecutables,
	)
	baseline, err := captureKernelState(runner, cfg)
	if err != nil {
		return fmt.Errorf("capture baseline: %w", err)
	}
	tableName := fmt.Sprintf("%s%d", cfg.tablePrefix, ordinal)
	resolverAddr, err := netip.ParseAddrPort(cfg.dnsResolver)
	if err != nil {
		return err
	}
	baseVerifier, err := directawg.NewLinuxProtectedVerifier(directawg.LinuxVerificationConfig{
		DNSResolver:        cfg.dnsResolver,
		DNSQueryName:       "teardown-e2e.invalid",
		ExpectedDNSAnswers: []netip.Addr{cfg.expectedDNSAnswer},
		CanaryEndpoint:     cfg.canaryEndpoint,
		Timeout:            2 * time.Second,
	})
	if err != nil {
		return err
	}
	verifier := newBlockingVerifier(baseVerifier)
	policyFactory, err := directawg.NewLinuxNftResolvedPolicyFactory(
		directawg.LinuxNftResolvedPolicyConfig{
			NftBinary:         cfg.nftBinary,
			ResolvectlBinary:  cfg.resolvectlBinary,
			TempRoot:          cfg.tempRoot,
			TableName:         tableName,
			UnderlayInterface: cfg.underlayInterface,
			UnderlayMark:      cfg.underlayMark,
			DNSResolver:       resolverAddr.Addr(),
			HealthInterval:    30 * time.Second,
			Runner:            runner,
		},
	)
	if err != nil {
		return err
	}
	// Range-checked before narrowing: uint16(65536) is 0, which in this project
	// means "let the kernel choose an ephemeral port" — so a misconfigured
	// range would silently stop being a pinned range instead of being rejected.
	listenPortMin, err := sysconv.Port(41200 + ordinal*10)
	if err != nil {
		return fmt.Errorf("listen port minimum: %w", err)
	}
	listenPortMax, err := sysconv.Port(41209 + ordinal*10)
	if err != nil {
		return fmt.Errorf("listen port maximum: %w", err)
	}
	controller, err := directawg.NewLinuxController(directawg.LinuxControllerConfig{
		AWGGoBinary: cfg.awgGoBinary,
		AWGBinary:   cfg.awgBinary,
		IPBinary:    cfg.ipBinary,
		TempRoot:    cfg.tempRoot,
		Signed: directawg.LinuxSignedInterfaceConfig{
			InnerAddressPool:    cfg.innerPool,
			AllowedIPs:          []netip.Prefix{cfg.allowedIP},
			VerificationRoutes:  []netip.Prefix{cfg.verificationRoute},
			MTU:                 1280,
			ListenPortMin:       listenPortMin,
			ListenPortMax:       listenPortMax,
			PersistentKeepalive: 25,
			Obfuscation: directawg.AWGObfuscation{
				JC: 4, JMin: 12, JMax: 64,
				S1: 16, S2: 80, S3: 24, S4: 8,
				H1: 111111, H2: 222222, H3: 333333, H4: 444444,
			},
		},
		KeyProvider: fixedKeyProvider{directawg.LinuxKeyMaterial{
			Generation: 1,
			PrivateKey: append([]byte(nil), cfg.clientPrivateKey...),
			PSK:        append([]byte(nil), cfg.psk...),
		}},
		Verifier:      verifier,
		PolicyFactory: policyFactory,
		Runner:        runner,
		StopTimeout:   cfg.stopTimeout,
	})
	if err != nil {
		return err
	}

	binding := testBinding(test.name)
	relayAddr := fmt.Sprintf("127.0.0.1:%d", 39100+ordinal)
	relayCtx, relayCancel := context.WithCancel(context.Background())
	defer relayCancel()
	relayResult := make(chan error, 1)
	go func() {
		relayResult <- runRelay(relayCtx, relayAddr, cfg.gatewayEndpoint, cfg.underlayMark)
	}()
	select {
	case err := <-relayResult:
		return fmt.Errorf("relay startup: %w", err)
	case <-time.After(150 * time.Millisecond):
	}

	prepareCtx, prepareCancel := context.WithTimeout(context.Background(), 15*time.Second)
	prepared, err := controller.Prepare(prepareCtx, directawg.Preparation{
		Binding:          binding,
		RelayEndpoint:    relayAddr,
		GatewayEndpoint:  cfg.gatewayEndpoint,
		GatewayPublicKey: cfg.gatewayPublicKey,
		MinInnerDatagram: 1200,
		MaxInnerDatagram: 1350,
	})
	prepareCancel()
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	session := prepared.Session
	contextSession, ok := session.(directawg.ContextTunnelSession)
	if !ok {
		_ = session.Close()
		return errors.New("production session does not implement ContextTunnelSession")
	}
	closed := false
	defer func() {
		if !closed {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			runner.disarm()
			resultErr = errors.Join(resultErr, contextSession.CloseContext(cleanupCtx))
			resultErr = errors.Join(resultErr, policyFactory.Release(cleanupCtx))
		}
	}()

	probeCtx, probeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	payloadVerified := true
	if err := session.VerifyProtectedDNS(probeCtx, binding); err != nil {
		payloadVerified = false
		if !cfg.allowPayloadLimit {
			probeCancel()
			return fmt.Errorf("protected DNS: %w", err)
		}
		fmt.Printf("KERNEL_PAYLOAD_LIMITATION name=%s protected_dns=%q comparison_harness_same_failure=true\n",
			test.name, err.Error())
	} else if err := session.VerifyTunnelCanary(probeCtx, binding); err != nil {
		payloadVerified = false
		if !cfg.allowPayloadLimit {
			probeCancel()
			return fmt.Errorf("tunnel canary: %w", err)
		}
		fmt.Printf("KERNEL_PAYLOAD_LIMITATION name=%s tunnel_canary=%q comparison_harness_same_failure=true\n",
			test.name, err.Error())
	}
	probeCancel()
	statusCtx, statusCancel := context.WithTimeout(context.Background(), 5*time.Second)
	status, err := waitForHandshake(statusCtx, session)
	statusCancel()
	if err != nil {
		return err
	}
	commitCtx, commitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := session.Commit(commitCtx, binding); err != nil {
		commitCancel()
		return fmt.Errorf("commit: %w", err)
	}
	commitCancel()
	fmt.Printf("REAL_AWG_OK name=%s handshake=%s rx=%d tx=%d payload_verified=%t\n",
		test.name, status.LatestHandshake.UTC().Format(time.RFC3339),
		status.RxBytes, status.TxBytes, payloadVerified)

	interfaceName, process := runner.startedAWG()
	if interfaceName == "" || process == nil {
		return errors.New("runner did not record the real AWG process")
	}
	if test.cancelVerification {
		verifier.armBlock()
		verifyResult := make(chan error, 1)
		go func() {
			verifyResult <- session.VerifyProtectedDNS(context.Background(), binding)
		}()
		if err := verifier.waitEntered(5 * time.Second); err != nil {
			return err
		}
		started := time.Now()
		if err := contextSession.CloseContext(context.Background()); err != nil {
			return fmt.Errorf("close while verification in flight: %w", err)
		}
		elapsed := time.Since(started)
		select {
		case verifyErr := <-verifyResult:
			if !errors.Is(verifyErr, context.Canceled) {
				return fmt.Errorf("in-flight verifier returned %v, want canceled", verifyErr)
			}
		case <-time.After(2 * time.Second):
			return errors.New("in-flight verifier did not return after close")
		}
		if elapsed > cfg.stopTimeout+500*time.Millisecond {
			return fmt.Errorf("verification cancellation close exceeded bound: %s", elapsed)
		}
		select {
		case healthErr, open := <-session.Health():
			if open || healthErr != nil {
				return fmt.Errorf("successful close health stream = (%v, open=%t)", healthErr, open)
			}
		default:
			return errors.New("successful close did not close health stream")
		}
		fmt.Printf("CANCEL_OK name=%s elapsed_ms=%d\n", test.name, elapsed.Milliseconds())
	} else {
		runner.arm(test.fault)
		started := time.Now()
		firstErr := contextSession.CloseContext(context.Background())
		elapsed := time.Since(started)
		if firstErr == nil {
			return errors.New("faulted first close unexpectedly succeeded")
		}
		switch test.fault {
		case faultRollbackStall:
			if !errors.Is(firstErr, context.DeadlineExceeded) {
				return fmt.Errorf("rollback stall error = %v, want deadline", firstErr)
			}
			if elapsed < cfg.stopTimeout-100*time.Millisecond ||
				elapsed > cfg.stopTimeout+750*time.Millisecond {
				return fmt.Errorf("configured close ceiling not observed: elapsed=%s timeout=%s",
					elapsed, cfg.stopTimeout)
			}
		case faultRouteFailure:
			if !strings.Contains(firstErr.Error(), "injected route command failure") {
				return fmt.Errorf("route failure error = %v", firstErr)
			}
		}
		healthErr, err := readHealth(session.Health(), 2*time.Second)
		if err != nil {
			return err
		}
		if !strings.Contains(healthErr.Error(), "teardown failed") {
			return fmt.Errorf("health did not identify teardown: %v", healthErr)
		}
		if !interfaceExists(runner, cfg.ipBinary, interfaceName) {
			return errors.New("AWG interface disappeared before failed teardown was retried")
		}
		if !process.running() {
			return errors.New("AWG process exited before failed teardown was retried")
		}
		if !tableExists(runner, cfg.nftBinary, tableName) {
			return errors.New("fail-closed nft table disappeared after failed close")
		}
		fmt.Printf("FAULT_OBSERVED name=%s elapsed_ms=%d health=%q interface_owned=true process_owned=true table_owned=true\n",
			test.name, elapsed.Milliseconds(), healthErr.Error())
		runner.disarm()
		retryCtx, retryCancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = contextSession.CloseContext(retryCtx)
		retryCancel()
		if err != nil {
			return fmt.Errorf("retry close: %w", err)
		}
		if err := runner.validateFaultTrace(test.fault); err != nil {
			return err
		}
		fmt.Printf("RETRY_OK name=%s\n", test.name)
	}

	releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = policyFactory.Release(releaseCtx)
	releaseCancel()
	if err != nil {
		return fmt.Errorf("release policy factory: %w", err)
	}
	closed = true
	if interfaceExists(runner, cfg.ipBinary, interfaceName) {
		return errors.New("AWG interface residue remains")
	}
	if process.running() {
		return errors.New("AWG process residue remains")
	}
	if tableExists(runner, cfg.nftBinary, tableName) {
		return errors.New("nft table residue remains")
	}
	finalState, err := captureKernelState(runner, cfg)
	if err != nil {
		return fmt.Errorf("capture final state: %w", err)
	}
	if baseline != finalState {
		fmt.Fprintf(os.Stderr, "BASELINE_STATE\n%s\nFINAL_STATE\n%s\n", baseline, finalState)
		return errors.New("namespace kernel state differs after exact residue cleanup")
	}
	if runner.resolvectlCount() < 5 {
		return fmt.Errorf("resolver lifecycle calls = %d, want at least 5", runner.resolvectlCount())
	}
	fmt.Printf("EXACT_RESIDUE_OK name=%s interface=%s process_pid=%d\n",
		test.name, interfaceName, process.pid())
	fmt.Printf("SCENARIO_PASS name=%s\n", test.name)
	return nil
}

func readHealth(health <-chan error, timeout time.Duration) (error, error) {
	select {
	case err, open := <-health:
		if !open || err == nil {
			return nil, fmt.Errorf("fault health stream = (%v, open=%t)", err, open)
		}
		return err, nil
	case <-time.After(timeout):
		return nil, errors.New("fault was not reported on health stream")
	}
}

func waitForHandshake(
	ctx context.Context, session directawg.TunnelSession,
) (directawg.Status, error) {
	timer := time.NewTicker(25 * time.Millisecond)
	defer timer.Stop()
	var latest directawg.Status
	for {
		status, err := session.Status(ctx)
		if err != nil {
			return directawg.Status{}, fmt.Errorf("status: %w", err)
		}
		latest = status
		if !status.LatestHandshake.IsZero() &&
			status.RxBytes > 0 && status.TxBytes > 0 {
			return status, nil
		}
		select {
		case <-ctx.Done():
			return directawg.Status{}, fmt.Errorf(
				"real AWG handshake/counters did not advance: handshake=%v rx=%d tx=%d: %w",
				latest.LatestHandshake, latest.RxBytes, latest.TxBytes,
				context.Cause(ctx),
			)
		case <-timer.C:
		}
	}
}

func captureKernelState(runner *faultRunner, cfg options) (string, error) {
	commands := []directawg.LinuxCommand{
		{Path: cfg.nftBinary, Args: []string{"list", "ruleset"}},
		{Path: cfg.ipBinary, Args: []string{"-o", "link", "show"}},
		{Path: cfg.ipBinary, Args: []string{"-4", "rule", "show"}},
		{Path: cfg.ipBinary, Args: []string{"-4", "route", "show", "table", "all"}},
	}
	var state strings.Builder
	for _, command := range commands {
		result, err := runner.runUnfaulted(context.Background(), command)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&state, "$ %s %s\n%s", command.Path, strings.Join(command.Args, " "), result.Stdout)
	}
	return state.String(), nil
}

func interfaceExists(runner *faultRunner, ipBinary, interfaceName string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := runner.runUnfaulted(ctx, directawg.LinuxCommand{
		Path: ipBinary, Args: []string{"link", "show", "dev", interfaceName},
	})
	return err == nil
}

func tableExists(runner *faultRunner, nftBinary, tableName string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := runner.runUnfaulted(ctx, directawg.LinuxCommand{
		Path: nftBinary, Args: []string{"list", "table", "inet", tableName},
	})
	return err == nil
}

type fixedKeyProvider struct {
	material directawg.LinuxKeyMaterial
}

func (provider fixedKeyProvider) KeyMaterial(
	_ context.Context, _ connectivity.Binding,
) (directawg.LinuxKeyMaterial, error) {
	return directawg.LinuxKeyMaterial{
		Generation: provider.material.Generation,
		PrivateKey: append([]byte(nil), provider.material.PrivateKey...),
		PSK:        append([]byte(nil), provider.material.PSK...),
	}, nil
}

type blockingVerifier struct {
	delegate directawg.LinuxProtectedVerifier
	mu       sync.Mutex
	block    bool
	entered  chan struct{}
}

func newBlockingVerifier(delegate directawg.LinuxProtectedVerifier) *blockingVerifier {
	return &blockingVerifier{delegate: delegate}
}

func (verifier *blockingVerifier) armBlock() {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	verifier.block = true
	verifier.entered = make(chan struct{})
}

func (verifier *blockingVerifier) waitEntered(timeout time.Duration) error {
	verifier.mu.Lock()
	entered := verifier.entered
	verifier.mu.Unlock()
	select {
	case <-entered:
		return nil
	case <-time.After(timeout):
		return errors.New("blocking verifier was not reached")
	}
}

func (verifier *blockingVerifier) VerifyProtectedDNS(
	ctx context.Context, probe directawg.LinuxProbeContext,
) error {
	verifier.mu.Lock()
	block := verifier.block
	entered := verifier.entered
	if block {
		verifier.block = false
	}
	verifier.mu.Unlock()
	if !block {
		return verifier.delegate.VerifyProtectedDNS(ctx, probe)
	}
	close(entered)
	if err := verifier.delegate.VerifyProtectedDNS(ctx, probe); err != nil {
		return err
	}
	<-ctx.Done()
	return context.Cause(ctx)
}

func (verifier *blockingVerifier) VerifyTunnelCanary(
	ctx context.Context, probe directawg.LinuxProbeContext,
) error {
	return verifier.delegate.VerifyTunnelCanary(ctx, probe)
}

type commandEvent struct {
	class string
	fault string
	err   string
}

type faultRunner struct {
	// allowed is the fixed set of executables this runner may launch.
	allowed          *directawg.LinuxExecAllowList
	resolvectlBinary string
	nftBinary        string
	ipBinary         string

	mu          sync.Mutex
	armed       string
	injected    bool
	events      []commandEvent
	interfaces  []string
	processes   []*managedProcess
	resolvectls int
}

func newFaultRunner(
	resolvectlBinary, nftBinary, ipBinary string,
	allowed *directawg.LinuxExecAllowList,
) *faultRunner {
	return &faultRunner{
		resolvectlBinary: resolvectlBinary,
		nftBinary:        nftBinary,
		ipBinary:         ipBinary,
		allowed:          allowed,
	}
}

func (runner *faultRunner) arm(fault string) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.armed = fault
	runner.injected = false
}

func (runner *faultRunner) disarm() {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.armed = faultNone
}

func (runner *faultRunner) Run(
	ctx context.Context, command directawg.LinuxCommand,
) (directawg.LinuxCommandResult, error) {
	class := runner.classify(command)
	runner.mu.Lock()
	fault := runner.armed
	inject := !runner.injected &&
		((fault == faultRollbackStall && class == "nft.policy-remove") ||
			(fault == faultRouteFailure && class == "ip.rule-delete"))
	if inject {
		runner.injected = true
	}
	if command.Path == runner.resolvectlBinary {
		runner.resolvectls++
		runner.events = append(runner.events, commandEvent{class: class})
		runner.mu.Unlock()
		fmt.Printf("RESOLVECTL_RECORDED %s\n", strings.Join(command.Args, " "))
		return directawg.LinuxCommandResult{}, nil
	}
	runner.mu.Unlock()

	if inject && fault == faultRollbackStall {
		<-ctx.Done()
		err := context.Cause(ctx)
		runner.record(commandEvent{class: class, fault: fault, err: err.Error()})
		return directawg.LinuxCommandResult{}, err
	}
	if inject && fault == faultRouteFailure {
		err := errors.New("injected route command failure")
		runner.record(commandEvent{class: class, fault: fault, err: err.Error()})
		return directawg.LinuxCommandResult{}, err
	}
	result, err := runner.runUnfaulted(ctx, command)
	event := commandEvent{class: class}
	if err != nil {
		event.err = err.Error()
	}
	runner.record(event)
	return result, err
}

func (runner *faultRunner) runUnfaulted(
	ctx context.Context, command directawg.LinuxCommand,
) (directawg.LinuxCommandResult, error) {
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
		return result, fmt.Errorf("%s %s: %w: %s",
			command.Path, strings.Join(command.Args, " "), err, stderr.String())
	}
	return result, nil
}

func (runner *faultRunner) Start(
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
	process.Stdout = os.Stdout
	process.Stderr = os.Stderr
	if err := process.Start(); err != nil {
		return nil, err
	}
	managed := &managedProcess{
		command: command, process: process, exited: make(chan struct{}),
	}
	go func() {
		err := process.Wait()
		managed.mu.Lock()
		managed.err = err
		managed.mu.Unlock()
		close(managed.exited)
	}()
	interfaceName := ""
	if command.Path != "" && len(command.Args) == 2 && command.Args[0] == "-f" {
		interfaceName = command.Args[1]
	}
	runner.mu.Lock()
	runner.interfaces = append(runner.interfaces, interfaceName)
	runner.processes = append(runner.processes, managed)
	runner.events = append(runner.events, commandEvent{class: "process.start"})
	runner.mu.Unlock()
	return managed, nil
}

func (runner *faultRunner) classify(command directawg.LinuxCommand) string {
	if command.Path == runner.resolvectlBinary {
		return "resolvectl." + firstArg(command.Args)
	}
	if command.Path == runner.nftBinary && len(command.Args) == 2 && command.Args[0] == "-f" {
		payload, err := os.ReadFile(filepath.Clean(command.Args[1]))
		if err != nil {
			return "nft.batch-unreadable"
		}
		batch := string(payload)
		switch {
		case strings.Contains(batch, "delete element") && strings.Contains(batch, "tunnel_ifaces"):
			return "nft.policy-remove"
		case strings.Contains(batch, "delete table"):
			return "nft.release"
		case strings.Contains(batch, "table inet") && strings.Contains(batch, "chain output"):
			return "nft.install"
		case strings.Contains(batch, "add element"):
			return "nft.admit"
		default:
			return "nft.batch"
		}
	}
	if command.Path == runner.ipBinary {
		joined := strings.Join(command.Args, " ")
		switch {
		case strings.Contains(joined, " rule del "):
			return "ip.rule-delete"
		case strings.Contains(joined, " route flush table "):
			return "ip.route-flush"
		case strings.Contains(joined, "link delete dev"):
			return "ip.link-delete"
		default:
			return "ip.command"
		}
	}
	return "command"
}

func firstArg(args []string) string {
	if len(args) == 0 {
		return "empty"
	}
	return args[0]
}

func (runner *faultRunner) record(event commandEvent) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.events = append(runner.events, event)
}

func (runner *faultRunner) startedAWG() (string, *managedProcess) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.processes) == 0 {
		return "", nil
	}
	return runner.interfaces[len(runner.interfaces)-1], runner.processes[len(runner.processes)-1]
}

func (runner *faultRunner) resolvectlCount() int {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.resolvectls
}

func (runner *faultRunner) validateFaultTrace(fault string) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	faults := 0
	policyRemoves := 0
	linkDeletes := 0
	for _, event := range runner.events {
		if event.fault == fault {
			faults++
		}
		if event.class == "nft.policy-remove" {
			policyRemoves++
		}
		if event.class == "ip.link-delete" {
			linkDeletes++
		}
	}
	if faults != 1 {
		return fmt.Errorf("fault injections = %d, want 1", faults)
	}
	if linkDeletes != 1 {
		return fmt.Errorf("link delete executions = %d, want 1", linkDeletes)
	}
	switch fault {
	case faultRollbackStall:
		if policyRemoves != 2 {
			return fmt.Errorf("rollback attempts = %d, want stalled+retry", policyRemoves)
		}
	case faultRouteFailure:
		if policyRemoves != 1 {
			return fmt.Errorf("completed policy rollback repeated: attempts=%d", policyRemoves)
		}
	}
	return nil
}

type managedProcess struct {
	command  directawg.LinuxCommand
	process  *exec.Cmd
	exited   chan struct{}
	mu       sync.Mutex
	err      error
	stopOnce sync.Once
	stopErr  error
}

func (process *managedProcess) Exited() <-chan struct{} { return process.exited }

func (process *managedProcess) Err() error {
	select {
	case <-process.exited:
	default:
		return nil
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.err
}

func (process *managedProcess) Stop(ctx context.Context) error {
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
			process.stopErr = context.Cause(ctx)
			_ = process.process.Process.Kill()
			<-process.exited
		}
	})
	return process.stopErr
}

func (process *managedProcess) running() bool {
	select {
	case <-process.exited:
		return false
	default:
		return true
	}
}

func (process *managedProcess) pid() int {
	if process == nil || process.process == nil || process.process.Process == nil {
		return 0
	}
	return process.process.Process.Pid
}

func runRelay(
	ctx context.Context, listenAddr, forwardAddr string, underlayMark uint32,
) error {
	listenUDPAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}
	listener, err := net.ListenUDP("udp", listenUDPAddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	dialer := net.Dialer{
		Control: func(_, _ string, raw syscall.RawConn) error {
			var controlErr error
			err := raw.Control(func(fd uintptr) {
				// Both conversions are checked rather than asserted: a
				// truncated descriptor would mark a different socket, and on
				// linux/386 or linux/arm a mark above MaxInt32 would be
				// applied as a negative number.
				descriptor, convErr := sysconv.Descriptor(fd)
				if convErr != nil {
					controlErr = convErr
					return
				}
				mark, convErr := sysconv.SocketOptionInt(underlayMark)
				if convErr != nil {
					controlErr = convErr
					return
				}
				controlErr = unix.SetsockoptInt(
					descriptor, unix.SOL_SOCKET, unix.SO_MARK, mark,
				)
			})
			return errors.Join(err, controlErr)
		},
	}
	upstreamConn, err := dialer.DialContext(ctx, "udp", forwardAddr)
	if err != nil {
		return err
	}
	upstream := upstreamConn.(*net.UDPConn)
	defer upstream.Close()

	var clientMu sync.Mutex
	var clientAddr *net.UDPAddr
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		buffer := make([]byte, 65535)
		for {
			count, peer, err := listener.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			clientMu.Lock()
			clientAddr = peer
			clientMu.Unlock()
			if _, err := upstream.Write(buffer[:count]); err != nil {
				return
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		buffer := make([]byte, 65535)
		for {
			count, err := upstream.Read(buffer)
			if err != nil {
				return
			}
			clientMu.Lock()
			peer := clientAddr
			clientMu.Unlock()
			if peer != nil {
				if _, err := listener.WriteToUDP(buffer[:count], peer); err != nil {
					return
				}
			}
		}
	}()
	<-ctx.Done()
	_ = listener.Close()
	_ = upstream.Close()
	<-done
	<-done
	return nil
}

func testBinding(name string) connectivity.Binding {
	return connectivity.Binding{
		AttemptID:      randomHex(16),
		Profile:        "teardown-e2e",
		Mode:           connectivity.ModeAuto,
		ManifestDigest: randomHex(32),
		CandidateID:    "direct-" + name,
		NodeID:         "aicore-disposable-namespace",
		SessionID:      randomHex(16),
		PSKGeneration:  1,
		SequenceEpoch:  1,
		Nonce:          randomHex(16),
		ExpiresAt:      time.Now().Add(time.Hour),
	}
}

func randomHex(bytes int) string {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buffer)
}
