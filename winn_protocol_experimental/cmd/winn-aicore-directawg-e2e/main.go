//go:build linux

// Command winn-aicore-directawg-e2e is a privileged, namespace-isolated
// integration test for the real Linux direct-AWG controller and nftables
// policy factory in internal/directawg. It is not part of the normal go test
// suite: it must run as root inside a disposable network namespace created by
// scripts/aicore_directawg_policy_e2e.sh, never against a shared root
// namespace. Linux-only (unix.SO_MARK and friends do not exist elsewhere) —
// cross-compile with GOOS=linux GOARCH=amd64 from any other platform.
//
// Mode "server" runs a bare DNS+canary UDP responder used as the tunnel-only
// verification target. Mode "client" drives the real production controller
// and policy factory against a real awg/amneziawg-go/nft/ip toolchain.
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

func main() {
	mode := flag.String("mode", "", "server or client")
	dnsAddr := flag.String("dns-listen", "", "server: UDP address for the DNS responder")
	canaryAddr := flag.String("canary-listen", "", "server: UDP address for the canary responder")
	answerIP := flag.String("answer-ip", "", "server: IPv4 address to answer every DNS query with")

	relayListenPort := flag.Int("relay-listen-port", 39001, "client: loopback port for the internal AWG relay")
	gatewayEndpoint := flag.String("gateway-endpoint", "", "client: outer veth endpoint of the raw AWG peer")
	gatewayPublicKey := flag.String("gateway-pubkey", "", "client: base64 public key of the raw AWG peer")
	clientPrivateKeyB64 := flag.String("client-private-key", "", "client: base64 private key")
	pskB64 := flag.String("psk", "", "client: base64 preshared key")
	innerPool := flag.String("inner-pool", "", "client: private CIDR pool for the inner AWG address")
	allowedIP := flag.String("allowed-ip", "", "client: CIDR routed through the tunnel")
	verificationRoute := flag.String("verification-route", "", "client: CIDR the DNS/canary probes must stay within")
	listenPortMin := flag.Int("listen-port-min", 0, "client: inclusive lower AWG listen port")
	listenPortMax := flag.Int("listen-port-max", 0, "client: inclusive upper AWG listen port")
	dnsResolver := flag.String("dns-resolver", "", "client: server-side DNS responder address, reached through the tunnel")
	dnsQueryName := flag.String("dns-query-name", "aicore-e2e-canary.invalid", "client: DNS query name")
	expectedDNSAnswer := flag.String("expected-dns-answer", "", "client: expected DNS answer IPv4 address")
	canaryEndpoint := flag.String("canary-endpoint", "", "client: server-side canary responder address, reached through the tunnel")
	tableName := flag.String("table-name", "winnaicoree2e", "client: nftables table name")
	underlayInterface := flag.String("underlay-interface", "", "client: veth interface name used as the protected underlay")
	underlayMarkHex := flag.String("underlay-mark", "1234", "client: hex firewall mark for the underlay")
	awgGoBinary := flag.String("awg-go-binary", "/opt/winn-lab/bin/amneziawg-go", "path to amneziawg-go")
	awgBinary := flag.String("awg-binary", "/opt/winn-lab/bin/awg", "path to awg")
	ipBinary := flag.String("ip-binary", "/usr/sbin/ip", "path to ip")
	nftBinary := flag.String("nft-binary", "/usr/sbin/nft", "path to nft")
	resolvectlBinary := flag.String("resolvectl-binary", "/usr/bin/resolvectl", "path to resolvectl")
	tempRoot := flag.String("temp-root", "", "private temporary root for key files and nft batches")
	holdSeconds := flag.Int("hold-seconds", 2, "client: seconds to hold the committed tunnel before teardown")
	flag.Parse()

	switch *mode {
	case "server":
		if err := runServer(*dnsAddr, *canaryAddr, *answerIP); err != nil {
			fmt.Fprintln(os.Stderr, "server:", err)
			os.Exit(1)
		}
	case "client":
		cfg := clientConfig{
			relayListenPort:   *relayListenPort,
			gatewayEndpoint:   *gatewayEndpoint,
			gatewayPublicKey:  *gatewayPublicKey,
			innerPool:         *innerPool,
			allowedIP:         *allowedIP,
			verificationRoute: *verificationRoute,
			listenPortMin:     *listenPortMin,
			listenPortMax:     *listenPortMax,
			dnsResolver:       *dnsResolver,
			dnsQueryName:      *dnsQueryName,
			expectedDNSAnswer: *expectedDNSAnswer,
			canaryEndpoint:    *canaryEndpoint,
			tableName:         *tableName,
			underlayInterface: *underlayInterface,
			awgGoBinary:       *awgGoBinary,
			awgBinary:         *awgBinary,
			ipBinary:          *ipBinary,
			nftBinary:         *nftBinary,
			resolvectlBinary:  *resolvectlBinary,
			tempRoot:          *tempRoot,
			holdSeconds:       *holdSeconds,
		}
		var err error
		cfg.clientPrivateKey, err = base64.StdEncoding.DecodeString(*clientPrivateKeyB64)
		if err != nil {
			fatalf("decode client private key: %v", err)
		}
		cfg.psk, err = base64.StdEncoding.DecodeString(*pskB64)
		if err != nil {
			fatalf("decode psk: %v", err)
		}
		markValue, err := strconv.ParseUint(*underlayMarkHex, 16, 32)
		if err != nil {
			fatalf("parse underlay mark: %v", err)
		}
		cfg.underlayMark = uint32(markValue)
		if err := runClient(cfg); err != nil {
			fatalf("client: %v", err)
		}
	default:
		fatalf("mode must be server or client")
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// ---------------------------------------------------------------------------
// server mode: bare DNS + canary responders
// ---------------------------------------------------------------------------

func runServer(dnsAddr, canaryAddr, answerIP string) error {
	if dnsAddr == "" || canaryAddr == "" || answerIP == "" {
		return errors.New("dns-listen, canary-listen, and answer-ip are required")
	}
	answer := net.ParseIP(answerIP).To4()
	if answer == nil {
		return fmt.Errorf("answer-ip %q is not a valid IPv4 address", answerIP)
	}
	var group sync.WaitGroup
	errs := make(chan error, 2)
	group.Add(2)
	go func() {
		defer group.Done()
		errs <- serveDNS(dnsAddr, answer)
	}()
	go func() {
		defer group.Done()
		errs <- serveCanary(canaryAddr)
	}()
	fmt.Println("READY")
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
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
		fmt.Fprintf(os.Stderr, "DNS_RESPONDER_GOT bytes=%d from=%s\n", count, peer)
		var query dnsmessage.Message
		if err := query.Unpack(buffer[:count]); err != nil {
			fmt.Fprintf(os.Stderr, "DNS_RESPONDER_UNPACK_ERR %v\n", err)
			continue
		}
		if len(query.Questions) != 1 {
			fmt.Fprintf(os.Stderr, "DNS_RESPONDER_BAD_QUESTIONS count=%d\n", len(query.Questions))
			continue
		}
		response := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:       query.ID,
				Response: true,
			},
			Questions: query.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name:  query.Questions[0].Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   5,
				},
				Body: &dnsmessage.AResource{A: [4]byte(answer)},
			}},
		}
		payload, err := response.Pack()
		if err != nil {
			continue
		}
		written, writeErr := conn.WriteToUDP(payload, peer)
		fmt.Fprintf(os.Stderr, "DNS_RESPONDER_REPLIED bytes=%d to=%s err=%v\n", written, peer, writeErr)
		if writeErr != nil {
			return writeErr
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

// runRelay is a minimal single-peer loopback UDP relay standing in for the
// separately-dialed, protected remote socket that production's candidate
// layer would normally provide. Its upstream (internet-facing) socket is
// SO_MARK'd with the same underlay mark the nftables policy admits: without
// this, the relay's own outbound packets are just as unmarked as any other
// process's and get dropped by the same fail-closed OUTPUT policy meant to
// gate only the legitimate AWG daemon traffic — production's real protected
// dialer would carry the equivalent marking itself. It returns immediately
// with an error if binding/dialing fails, and otherwise blocks until ctx is
// cancelled.
func runRelay(ctx context.Context, listenAddr, forwardAddr string, underlayMark uint32) error {
	listenUDPAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("resolve relay listen address: %w", err)
	}
	listener, err := net.ListenUDP("udp", listenUDPAddr)
	if err != nil {
		return fmt.Errorf("bind relay listener: %w", err)
	}
	dialer := net.Dialer{
		Control: func(_, _ string, raw syscall.RawConn) error {
			var controlErr error
			err := raw.Control(func(fd uintptr) {
				// Both conversions are checked rather than asserted: a
				// truncated descriptor would mark a different socket, and on
				// linux/386 or linux/arm a mark above MaxInt32 would be applied
				// as a negative number.
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
				readBack, readErr := unix.GetsockoptInt(descriptor, unix.SOL_SOCKET, unix.SO_MARK)
				fmt.Fprintf(os.Stderr, "RELAY_MARK_DEBUG fd=%d set_err=%v mark_readback=%#x readback_err=%v\n", fd, controlErr, readBack, readErr)
			})
			if err != nil {
				return err
			}
			return controlErr
		},
	}
	upstreamConn, err := dialer.DialContext(ctx, "udp", forwardAddr)
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("dial relay upstream: %w", err)
	}
	fmt.Fprintf(os.Stderr, "RELAY_DEBUG local=%s remote=%s forwardAddr=%s\n", upstreamConn.LocalAddr(), upstreamConn.RemoteAddr(), forwardAddr)
	upstream, ok := upstreamConn.(*net.UDPConn)
	if !ok {
		_ = listener.Close()
		_ = upstreamConn.Close()
		return errors.New("relay upstream dial did not return a UDP socket")
	}
	var clientMu sync.Mutex
	var clientAddr *net.UDPAddr
	go func() {
		buffer := make([]byte, 2048)
		for {
			count, addr, err := listener.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			clientMu.Lock()
			clientAddr = addr
			clientMu.Unlock()
			written, writeErr := upstream.Write(buffer[:count])
			fmt.Fprintf(os.Stderr, "RELAY_FORWARD_DEBUG from=%s bytes=%d written=%d err=%v\n", addr, count, written, writeErr)
		}
	}()
	go func() {
		buffer := make([]byte, 2048)
		for {
			count, err := upstream.Read(buffer)
			if err != nil {
				fmt.Fprintf(os.Stderr, "RELAY_REVERSE_DEBUG read_err=%v\n", err)
				return
			}
			clientMu.Lock()
			target := clientAddr
			clientMu.Unlock()
			var written int
			var writeErr error
			if target != nil {
				written, writeErr = listener.WriteToUDP(buffer[:count], target)
			}
			fmt.Fprintf(os.Stderr, "RELAY_REVERSE_DEBUG bytes=%d target=%v written=%d err=%v\n", count, target, written, writeErr)
		}
	}()
	<-ctx.Done()
	_ = listener.Close()
	_ = upstream.Close()
	return nil
}

// ---------------------------------------------------------------------------
// client mode: the real production controller and policy factory
// ---------------------------------------------------------------------------

type clientConfig struct {
	relayListenPort   int
	gatewayEndpoint   string
	gatewayPublicKey  string
	clientPrivateKey  []byte
	psk               []byte
	innerPool         string
	allowedIP         string
	verificationRoute string
	listenPortMin     int
	listenPortMax     int
	dnsResolver       string
	dnsQueryName      string
	expectedDNSAnswer string
	canaryEndpoint    string
	tableName         string
	underlayInterface string
	underlayMark      uint32
	awgGoBinary       string
	awgBinary         string
	ipBinary          string
	nftBinary         string
	resolvectlBinary  string
	tempRoot          string
	holdSeconds       int
}

func runClient(cfg clientConfig) error {
	pool, err := netip.ParsePrefix(cfg.innerPool)
	if err != nil {
		return fmt.Errorf("parse inner pool: %w", err)
	}
	allowed, err := netip.ParsePrefix(cfg.allowedIP)
	if err != nil {
		return fmt.Errorf("parse allowed IP: %w", err)
	}
	verification, err := netip.ParsePrefix(cfg.verificationRoute)
	if err != nil {
		return fmt.Errorf("parse verification route: %w", err)
	}
	resolverAddr, err := netip.ParseAddrPort(cfg.dnsResolver)
	if err != nil {
		return fmt.Errorf("parse dns resolver: %w", err)
	}
	expectedAnswer, err := netip.ParseAddr(cfg.expectedDNSAnswer)
	if err != nil {
		return fmt.Errorf("parse expected dns answer: %w", err)
	}

	// The fixed set of executables this harness may launch. See the identical
	// construction in cmd/winn-acceptance.
	allowedExecutables, err := directawg.NewLinuxExecAllowList(
		cfg.nftBinary, cfg.resolvectlBinary,
		cfg.awgGoBinary, cfg.awgBinary, cfg.ipBinary,
	)
	if err != nil {
		return fmt.Errorf("executable allow-list: %w", err)
	}
	runner := &realCommandRunner{
		resolvectlBinary: cfg.resolvectlBinary,
		allowed:          allowedExecutables,
	}

	verifier, err := directawg.NewLinuxProtectedVerifier(directawg.LinuxVerificationConfig{
		DNSResolver:        cfg.dnsResolver,
		DNSQueryName:       cfg.dnsQueryName,
		ExpectedDNSAnswers: []netip.Addr{expectedAnswer},
		CanaryEndpoint:     cfg.canaryEndpoint,
		Timeout:            2 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("construct protected verifier: %w", err)
	}

	policyFactory, err := directawg.NewLinuxNftResolvedPolicyFactory(directawg.LinuxNftResolvedPolicyConfig{
		NftBinary:         cfg.nftBinary,
		ResolvectlBinary:  cfg.resolvectlBinary,
		TempRoot:          cfg.tempRoot,
		TableName:         cfg.tableName,
		UnderlayInterface: cfg.underlayInterface,
		UnderlayMark:      cfg.underlayMark,
		DNSResolver:       resolverAddr.Addr(),
		HealthInterval:    2 * time.Second,
		Runner:            runner,
	})
	if err != nil {
		return fmt.Errorf("construct policy factory: %w", err)
	}

	// Range-checked before narrowing: uint16(65536) is 0, which in this project
	// means "let the kernel choose an ephemeral port" — so a misconfigured
	// range would silently stop being a pinned range instead of being rejected.
	listenPortMin, err := sysconv.Port(cfg.listenPortMin)
	if err != nil {
		return fmt.Errorf("listen port minimum: %w", err)
	}
	listenPortMax, err := sysconv.Port(cfg.listenPortMax)
	if err != nil {
		return fmt.Errorf("listen port maximum: %w", err)
	}
	controller, err := directawg.NewLinuxController(directawg.LinuxControllerConfig{
		AWGGoBinary: cfg.awgGoBinary,
		AWGBinary:   cfg.awgBinary,
		IPBinary:    cfg.ipBinary,
		TempRoot:    cfg.tempRoot,
		Signed: directawg.LinuxSignedInterfaceConfig{
			InnerAddressPool:   pool,
			AllowedIPs:         []netip.Prefix{allowed},
			VerificationRoutes: []netip.Prefix{verification},
			MTU:                1280,
			ListenPortMin:      listenPortMin,
			ListenPortMax:      listenPortMax,
			// Nonzero on purpose: this used to make the daemon eagerly
			// initiate a handshake before Prepare's zero-baseline check ran
			// (a real race, fixed by applying keepalive only after that
			// check passes — see enablePersistentKeepalive). Left nonzero
			// here specifically to re-verify that fix against a real daemon.
			PersistentKeepalive: 25,
			Obfuscation: directawg.AWGObfuscation{
				JC: 4, JMin: 12, JMax: 64,
				S1: 16, S2: 80, S3: 24, S4: 8,
				H1: 111111, H2: 222222, H3: 333333, H4: 444444,
			},
		},
		KeyProvider:   fixedKeyProvider{material: directawg.LinuxKeyMaterial{Generation: 1, PrivateKey: cfg.clientPrivateKey, PSK: cfg.psk}},
		Verifier:      verifier,
		PolicyFactory: policyFactory,
		Runner:        runner,
	})
	if err != nil {
		return fmt.Errorf("construct controller: %w", err)
	}

	binding := connectivity.Binding{
		AttemptID:      randomHex32(),
		Profile:        "aicore-e2e",
		Mode:           connectivity.ModeAuto,
		ManifestDigest: randomHex64(),
		CandidateID:    "direct-primary",
		NodeID:         "aicore-e2e-node",
		SessionID:      randomHex32(),
		PSKGeneration:  1,
		SequenceEpoch:  1,
		Nonce:          randomHex32(),
		ExpiresAt:      time.Now().Add(time.Hour),
	}
	// The real controller sets the AWG peer's wire-level "endpoint" to
	// RelayEndpoint, not GatewayEndpoint (confirmed by reading
	// linux_controller_common.go's configureAWG directly) — production
	// expects a loopback relay standing in for a separately-dialed,
	// protected remote socket. This test provides that relay itself so the
	// AWG interface can actually reach the real server veth address.
	relayListenAddr := fmt.Sprintf("127.0.0.1:%d", cfg.relayListenPort)
	relayCtx, relayCancel := context.WithCancel(context.Background())
	defer relayCancel()
	relayReady := make(chan error, 1)
	go func() {
		relayReady <- runRelay(relayCtx, relayListenAddr, cfg.gatewayEndpoint, cfg.underlayMark)
	}()
	select {
	case err := <-relayReady:
		if err != nil {
			return fmt.Errorf("start relay: %w", err)
		}
	case <-time.After(200 * time.Millisecond):
	}
	fmt.Printf("RELAY_READY %s -> %s\n", relayListenAddr, cfg.gatewayEndpoint)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	prepared, err := controller.Prepare(ctx, directawg.Preparation{
		Binding:          binding,
		RelayEndpoint:    relayListenAddr,
		GatewayEndpoint:  cfg.gatewayEndpoint,
		GatewayPublicKey: cfg.gatewayPublicKey,
		MinInnerDatagram: 1200,
		MaxInnerDatagram: 1350,
	})
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	session := prepared.Session
	fmt.Printf("PREPARE_OK local_source=%s baseline_handshake_zero=%v baseline_rx=%d baseline_tx=%d\n",
		prepared.LocalSourceEndpoint, prepared.Baseline.LatestHandshake.IsZero(),
		prepared.Baseline.RxBytes, prepared.Baseline.TxBytes)

	teardownOnFailure := true
	defer func() {
		if teardownOnFailure {
			if err := session.Close(); err != nil {
				fmt.Fprintln(os.Stderr, "cleanup close error:", err)
			}
		}
	}()

	verifyCtx, verifyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer verifyCancel()
	if err := session.VerifyProtectedDNS(verifyCtx, binding); err != nil {
		dumpDiagnostics(runner, cfg)
		return fmt.Errorf("VerifyProtectedDNS: %w", err)
	}
	fmt.Println("VERIFY_DNS_OK")
	if err := session.VerifyTunnelCanary(verifyCtx, binding); err != nil {
		dumpDiagnostics(runner, cfg)
		return fmt.Errorf("VerifyTunnelCanary: %w", err)
	}
	fmt.Println("VERIFY_CANARY_OK")

	status, err := session.Status(verifyCtx)
	if err != nil {
		return fmt.Errorf("status: %w", err)
	}
	if status.LatestHandshake.IsZero() || status.RxBytes == 0 || status.TxBytes == 0 {
		return fmt.Errorf("status did not advance: handshake_zero=%v rx=%d tx=%d",
			status.LatestHandshake.IsZero(), status.RxBytes, status.TxBytes)
	}
	fmt.Printf("STATUS_OK handshake=%s rx=%d tx=%d\n", status.LatestHandshake.Format(time.RFC3339), status.RxBytes, status.TxBytes)

	commitCtx, commitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer commitCancel()
	if err := session.Commit(commitCtx, binding); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	fmt.Println("COMMIT_OK")

	select {
	case err, ok := <-session.Health():
		return fmt.Errorf("unexpected health signal immediately after commit: err=%v ok=%v", err, ok)
	case <-time.After(time.Duration(cfg.holdSeconds) * time.Second):
	}
	fmt.Println("HEALTH_STABLE_OK")

	teardownOnFailure = false
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer closeCancel()
	_ = closeCtx
	if err := session.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	fmt.Println("CLOSE_OK")
	return nil
}

// dumpDiagnostics prints live nftables/route/interface/AWG state to stderr
// right before the caller tears everything down, so a verification failure
// is actually debuggable instead of just "it timed out."
func dumpDiagnostics(runner *realCommandRunner, cfg clientConfig) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dump := func(label string, path string, args ...string) {
		fmt.Fprintf(os.Stderr, "=== DIAGNOSTIC: %s ===\n", label)
		result, err := runner.Run(ctx, directawg.LinuxCommand{Path: path, Args: args})
		if err != nil {
			fmt.Fprintf(os.Stderr, "(command error: %v)\n", err)
		}
		fmt.Fprintln(os.Stderr, string(result.Stdout))
	}
	dump("nft ruleset", cfg.nftBinary, "list", "ruleset")
	dump("ip link", cfg.ipBinary, "-o", "link", "show")
	dump("ip route (main)", cfg.ipBinary, "route", "show")
	dump("ip route (all tables)", cfg.ipBinary, "route", "show", "table", "all")
	dump("ip rule", cfg.ipBinary, "rule", "show")
	dump("awg show", cfg.awgBinary, "show")
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
// amneziawg-go, ip) except resolvectl, which is intercepted and recorded.
// resolvectl cannot be meaningfully exercised inside an isolated network
// namespace: systemd-resolved runs in the root namespace and cannot resolve
// an interface index that only exists in a different network namespace
// (confirmed empirically: "Failed to get link data ... Unknown object" with
// zero effect on the root namespace's own DNS state). Real resolvectl
// behavior against a genuine interface is deferred to the first real cloud
// node, where testing directly against the primary interface is safe.
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
		fmt.Printf("INTERCEPTED_RESOLVECTL %s\n", strings.Join(command.Args, " "))
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
	process.Stdout = os.Stdout
	process.Stderr = os.Stderr
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

func randomHex32() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buffer)
}

func randomHex64() string {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buffer)
}
