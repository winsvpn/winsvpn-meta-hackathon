//go:build linux

// Command winn-h3-e2e proves the production Linux Winn H3 candidate as one
// vertical slice. It must run inside a disposable client network namespace:
//
//	fixed-IP SO_BINDTODEVICE+SO_MARK protected QUIC underlay
//	  -> TLS 1.3 X25519+ML-KEM-768 with mandatory accepted ECH
//	  -> ML-DSA-authenticated RFC 9298 CONNECT-UDP
//	  -> fresh inner AmneziaWG session
//	  -> protected DNS and tunnel canary
//	  -> route/DNS commit and bounded teardown.
//
// The companion script creates the disposable namespaces and the production
// carrier server. This command never creates a generic UDP substitute for H3.
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
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/dns/dnsmessage"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/directawg"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/h3candidate"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/preparation"
	"winsvpn.local/winnprotocol/internal/sysconv"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

// Set only by the evidence build:
//
//	-ldflags "-X main.sourceDigest=<sha256 source-manifest digest>"
var sourceDigest = "unset"

const (
	protocolVersion = connectivity.Version
	connectBudget   = 3 * time.Second
)

func main() {
	printDigest := flag.Bool(
		"print-source-digest", false,
		"print the source digest embedded by the evidence build",
	)
	mode := flag.String("mode", "", "server or client")

	dnsListen := flag.String(
		"dns-listen", "", "server: protected DNS responder address",
	)
	canaryListen := flag.String(
		"canary-listen", "", "server: tunnel canary responder address",
	)
	answerIP := flag.String(
		"answer-ip", "", "server: IPv4 answer for every DNS query",
	)

	serverName := flag.String(
		"server-name", "", "client: authenticated carrier DNS name",
	)
	remoteEndpoint := flag.String(
		"remote-endpoint", "", "client: fixed carrier IP-literal endpoint",
	)
	masqueTemplate := flag.String(
		"masque-template", "", "client: authenticated RFC 9298 URI template",
	)
	publicTarget := flag.String(
		"public-target", "winn.invalid:443",
		"client: fixed logical CONNECT-UDP target",
	)
	deviceID := flag.String(
		"device-id", "", "client: mTLS and ML-DSA device identity",
	)
	controllerID := flag.String(
		"controller-id", "", "client: expected ML-DSA controller identity",
	)
	deviceCert := flag.String(
		"device-cert", "", "client: device certificate PEM",
	)
	deviceKey := flag.String(
		"device-key", "", "client: device private key PEM",
	)
	rootCA := flag.String(
		"root-ca", "", "client: carrier root CA PEM",
	)
	devicePQSeed := flag.String(
		"device-pq-seed", "", "client: device ML-DSA-65 seed",
	)
	controllerPins := flag.String(
		"controller-pq-pins", "", "client: trusted controller ML-DSA pins",
	)
	echConfigList := flag.String(
		"ech-config-list", "", "client: RFC 9849 ECHConfigList",
	)

	gatewayEndpoint := flag.String(
		"gateway-endpoint", "", "client: fixed signed inner AWG backend",
	)
	gatewayPublicKey := flag.String(
		"gateway-pubkey", "", "client: signed AWG gateway public key",
	)
	clientPrivateKeyB64 := flag.String(
		"client-private-key", "", "client: base64 AWG private key",
	)
	pskB64 := flag.String(
		"psk", "", "client: base64 AWG preshared key",
	)
	innerPool := flag.String(
		"inner-pool", "", "client: signed inner address pool",
	)
	allowedIP := flag.String(
		"allowed-ip", "", "client: signed AWG allowed prefix",
	)
	verificationRoute := flag.String(
		"verification-route", "", "client: signed probe prefix",
	)
	listenPortMin := flag.Int(
		"listen-port-min", 0, "client: lower candidate AWG listen port",
	)
	listenPortMax := flag.Int(
		"listen-port-max", 0, "client: upper candidate AWG listen port",
	)
	dnsResolver := flag.String(
		"dns-resolver", "", "client: tunnel-only DNS endpoint",
	)
	dnsQueryName := flag.String(
		"dns-query-name", "winn-h3-e2e.invalid",
		"client: protected DNS query name",
	)
	expectedDNSAnswer := flag.String(
		"expected-dns-answer", "", "client: signed expected DNS answer",
	)
	canaryEndpoint := flag.String(
		"canary-endpoint", "", "client: tunnel-only canary endpoint",
	)

	clientNamespace := flag.String(
		"client-namespace", "",
		"client: disposable namespace name used by the mark authorizer",
	)
	tableName := flag.String(
		"table-name", "", "client: candidate-scoped nftables table",
	)
	underlayInterface := flag.String(
		"underlay-interface", "", "client: physical underlay interface",
	)
	directMarkHex := flag.String(
		"direct-underlay-mark", "", "client: DirectAWG mark in hexadecimal",
	)
	h3MarkHex := flag.String(
		"h3-underlay-mark", "", "client: dedicated H3 mark in hexadecimal",
	)
	awgGoBinary := flag.String(
		"awg-go-binary", directawg.DefaultLinuxAWGGoBinary,
		"path to amneziawg-go",
	)
	awgBinary := flag.String(
		"awg-binary", directawg.DefaultLinuxAWGBinary, "path to awg",
	)
	ipBinary := flag.String(
		"ip-binary", directawg.DefaultLinuxIPBinary, "path to ip",
	)
	nftBinary := flag.String(
		"nft-binary", directawg.DefaultLinuxNftBinary, "path to nft",
	)
	resolvectlBinary := flag.String(
		"resolvectl-binary", directawg.DefaultLinuxResolvectlBinary,
		"path to resolvectl",
	)
	tempRoot := flag.String(
		"temp-root", "", "private temporary root for candidate state",
	)
	hold := flag.Duration(
		"hold", 250*time.Millisecond,
		"duration to observe health after commit",
	)
	flag.Parse()

	if *printDigest {
		fmt.Println(sourceDigest)
		return
	}

	switch *mode {
	case "server":
		if err := runResponderServer(
			*dnsListen, *canaryListen, *answerIP,
		); err != nil {
			fatalf("server: %v", err)
		}
	case "client":
		privateKey, err := decodeSecret(
			"client private key", *clientPrivateKeyB64,
		)
		if err != nil {
			fatalf("%v", err)
		}
		defer clear(privateKey)
		psk, err := decodeSecret("preshared key", *pskB64)
		if err != nil {
			fatalf("%v", err)
		}
		defer clear(psk)
		directMark, err := parseMark(*directMarkHex)
		if err != nil {
			fatalf("direct underlay mark: %v", err)
		}
		h3Mark, err := parseMark(*h3MarkHex)
		if err != nil {
			fatalf("H3 underlay mark: %v", err)
		}
		cfg := clientConfig{
			serverName:         *serverName,
			remoteEndpoint:     *remoteEndpoint,
			masqueTemplate:     *masqueTemplate,
			publicTarget:       *publicTarget,
			deviceID:           *deviceID,
			controllerID:       *controllerID,
			deviceCert:         *deviceCert,
			deviceKey:          *deviceKey,
			rootCA:             *rootCA,
			devicePQSeed:       *devicePQSeed,
			controllerPins:     *controllerPins,
			echConfigList:      *echConfigList,
			gatewayEndpoint:    *gatewayEndpoint,
			gatewayPublicKey:   *gatewayPublicKey,
			clientPrivateKey:   privateKey,
			psk:                psk,
			innerPool:          *innerPool,
			allowedIP:          *allowedIP,
			verificationRoute:  *verificationRoute,
			listenPortMin:      *listenPortMin,
			listenPortMax:      *listenPortMax,
			dnsResolver:        *dnsResolver,
			dnsQueryName:       *dnsQueryName,
			expectedDNSAnswer:  *expectedDNSAnswer,
			canaryEndpoint:     *canaryEndpoint,
			clientNamespace:    *clientNamespace,
			tableName:          *tableName,
			underlayInterface:  *underlayInterface,
			directUnderlayMark: directMark,
			h3UnderlayMark:     h3Mark,
			awgGoBinary:        *awgGoBinary,
			awgBinary:          *awgBinary,
			ipBinary:           *ipBinary,
			nftBinary:          *nftBinary,
			resolvectlBinary:   *resolvectlBinary,
			tempRoot:           *tempRoot,
			hold:               *hold,
		}
		if err := runClient(cfg); err != nil {
			fatalf("client: %v", err)
		}
	default:
		fatalf("mode must be server or client")
	}
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}

func decodeSecret(name, encoded string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		clear(decoded)
		return nil, fmt.Errorf("%s must be one base64-encoded 32-byte value", name)
	}
	return decoded, nil
}

func parseMark(encoded string) (uint32, error) {
	value, err := strconv.ParseUint(encoded, 16, 32)
	if err != nil || value == 0 {
		return 0, errors.New("mark must be nonzero hexadecimal")
	}
	return uint32(value), nil
}

// ---------------------------------------------------------------------------
// Server-side tunnel-only DNS and canary responders.
// ---------------------------------------------------------------------------

func runResponderServer(dnsAddress, canaryAddress, answerText string) error {
	if dnsAddress == "" || canaryAddress == "" || answerText == "" {
		return errors.New(
			"dns-listen, canary-listen, and answer-ip are required",
		)
	}
	answer := net.ParseIP(answerText).To4()
	if answer == nil {
		return errors.New("answer-ip must be an IPv4 literal")
	}
	dns, err := net.ListenUDP(
		"udp4", mustResolveUDP(dnsAddress),
	)
	if err != nil {
		return fmt.Errorf("listen protected DNS: %w", err)
	}
	canary, err := net.ListenUDP(
		"udp4", mustResolveUDP(canaryAddress),
	)
	if err != nil {
		_ = dns.Close()
		return fmt.Errorf("listen tunnel canary: %w", err)
	}
	defer dns.Close()
	defer canary.Close()
	fmt.Println("READY")

	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- serveDNS(dns, answer) }()
	go func() { errorsChannel <- serveCanary(canary) }()
	return <-errorsChannel
}

func mustResolveUDP(address string) *net.UDPAddr {
	resolved, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		fatalf("resolve UDP address %q: %v", address, err)
	}
	return resolved
}

func serveDNS(connection *net.UDPConn, answer net.IP) error {
	buffer := make([]byte, 4096)
	for {
		count, peer, err := connection.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		var query dnsmessage.Message
		if err := query.Unpack(buffer[:count]); err != nil ||
			len(query.Questions) != 1 {
			continue
		}
		response := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID: query.ID, Response: true,
			},
			Questions: query.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name: query.Questions[0].Name,
					Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
					TTL: 5,
				},
				Body: &dnsmessage.AResource{
					A: [4]byte(answer),
				},
			}},
		}
		payload, err := response.Pack()
		if err != nil {
			continue
		}
		if _, err := connection.WriteToUDP(payload, peer); err != nil {
			return err
		}
		fmt.Printf("DNS_RESPONSE peer=%s bytes=%d\n", peer, len(payload))
	}
}

func serveCanary(connection *net.UDPConn) error {
	buffer := make([]byte, 4096)
	for {
		count, peer, err := connection.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		if _, err := connection.WriteToUDP(buffer[:count], peer); err != nil {
			return err
		}
		fmt.Printf("CANARY_RESPONSE peer=%s bytes=%d\n", peer, count)
	}
}

// ---------------------------------------------------------------------------
// Client: production H3 candidate and real Linux DirectAWG controller.
// ---------------------------------------------------------------------------

type clientConfig struct {
	serverName       string
	remoteEndpoint   string
	masqueTemplate   string
	publicTarget     string
	deviceID         string
	controllerID     string
	deviceCert       string
	deviceKey        string
	rootCA           string
	devicePQSeed     string
	controllerPins   string
	echConfigList    string
	gatewayEndpoint  string
	gatewayPublicKey string

	clientPrivateKey []byte
	psk              []byte

	innerPool         string
	allowedIP         string
	verificationRoute string
	listenPortMin     int
	listenPortMax     int
	dnsResolver       string
	dnsQueryName      string
	expectedDNSAnswer string
	canaryEndpoint    string

	clientNamespace    string
	tableName          string
	underlayInterface  string
	directUnderlayMark uint32
	h3UnderlayMark     uint32
	awgGoBinary        string
	awgBinary          string
	ipBinary           string
	nftBinary          string
	resolvectlBinary   string
	tempRoot           string
	hold               time.Duration
}

func runClient(cfg clientConfig) (resultErr error) {
	pool, err := netip.ParsePrefix(cfg.innerPool)
	if err != nil {
		return fmt.Errorf("parse inner pool: %w", err)
	}
	allowed, err := netip.ParsePrefix(cfg.allowedIP)
	if err != nil {
		return fmt.Errorf("parse allowed prefix: %w", err)
	}
	verification, err := netip.ParsePrefix(cfg.verificationRoute)
	if err != nil {
		return fmt.Errorf("parse verification prefix: %w", err)
	}
	resolver, err := netip.ParseAddrPort(cfg.dnsResolver)
	if err != nil {
		return fmt.Errorf("parse protected DNS endpoint: %w", err)
	}
	expectedAnswer, err := netip.ParseAddr(cfg.expectedDNSAnswer)
	if err != nil {
		return fmt.Errorf("parse expected DNS answer: %w", err)
	}
	if cfg.clientNamespace == "" {
		return errors.New("client namespace is required")
	}
	if cfg.directUnderlayMark == cfg.h3UnderlayMark {
		return errors.New("DirectAWG and H3 require distinct underlay marks")
	}

	// The fixed set of executables this harness may launch.
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
	verifier, err := directawg.NewLinuxProtectedVerifier(
		directawg.LinuxVerificationConfig{
			DNSResolver:        cfg.dnsResolver,
			DNSQueryName:       cfg.dnsQueryName,
			ExpectedDNSAnswers: []netip.Addr{expectedAnswer},
			CanaryEndpoint:     cfg.canaryEndpoint,
			Timeout:            2 * time.Second,
		},
	)
	if err != nil {
		return fmt.Errorf("construct protected verifier: %w", err)
	}
	policyFactory, err := directawg.NewLinuxNftResolvedPolicyFactory(
		directawg.LinuxNftResolvedPolicyConfig{
			NftBinary:         cfg.nftBinary,
			ResolvectlBinary:  cfg.resolvectlBinary,
			TempRoot:          cfg.tempRoot,
			TableName:         cfg.tableName,
			UnderlayInterface: cfg.underlayInterface,
			UnderlayMark:      cfg.directUnderlayMark,
			DNSResolver:       resolver.Addr(),
			HealthInterval:    500 * time.Millisecond,
			Runner:            runner,
		},
	)
	if err != nil {
		return fmt.Errorf("construct policy factory: %w", err)
	}

	expiresAt := time.Now().UTC().Add(10 * time.Minute)
	anchor, err := policyFactory.PrepareUnderlayPolicyAnchor(
		context.Background(),
		directawg.LinuxUnderlayPolicyAnchorSpec{
			TableFamily:           "inet",
			TableName:             cfg.tableName,
			OutputChain:           "output",
			UnderlayInterface:     cfg.underlayInterface,
			DirectAWGUnderlayMark: cfg.directUnderlayMark,
			ExpiresAt:             expiresAt,
		},
	)
	if err != nil {
		return fmt.Errorf("prepare cold-H3 policy anchor: %w", err)
	}
	fmt.Println("COLD_POLICY_ANCHOR_OK")

	var authorization preparation.UnderlayMarkAuthorizationLease
	var connection connectivity.CandidateConnection
	var warmResource h3candidate.PreparedResource
	defer func() {
		cleanupContext, cancelCleanup := context.WithTimeout(
			context.Background(), 12*time.Second,
		)
		defer cancelCleanup()
		var cleanupError error
		if connection != nil {
			cleanupError = errors.Join(
				cleanupError, connection.Close(),
			)
			connection = nil
		}
		if warmResource != nil {
			cleanupError = errors.Join(
				cleanupError,
				warmResource.Close(cleanupContext),
			)
			warmResource = nil
		}
		if authorization.Resource != nil {
			cleanupError = errors.Join(
				cleanupError,
				authorization.Resource.Close(cleanupContext),
			)
		}
		if anchor.Resource != nil {
			cleanupError = errors.Join(
				cleanupError, anchor.Resource.Close(cleanupContext),
			)
		}
		cleanupError = errors.Join(
			cleanupError, policyFactory.Release(cleanupContext),
		)
		if cleanupError != nil {
			resultErr = errors.Join(
				resultErr,
				fmt.Errorf("bounded H3 teardown: %w", cleanupError),
			)
		} else {
			fmt.Println("BOUNDED_TEARDOWN_OK")
		}
	}()

	authorizer, err := preparation.NewLinuxUnderlayMarkAuthorizer(
		preparation.LinuxUnderlayMarkAuthorizerConfig{
			NftBinary:                 cfg.nftBinary,
			IPBinary:                  cfg.ipBinary,
			NetworkNamespace:          cfg.clientNamespace,
			AllowRootNetworkNamespace: false,
			TableFamily:               anchor.TableFamily,
			TableName:                 anchor.TableName,
			OutputChain:               anchor.OutputChain,
			UnderlayInterface:         anchor.UnderlayInterface,
			DirectAWGUnderlayMark:     anchor.DirectAWGUnderlayMark,
			FirewallMark:              cfg.h3UnderlayMark,
			CommandTimeout:            3 * time.Second,
			CleanupRetryInterval:      50 * time.Millisecond,
		},
	)
	if err != nil {
		return fmt.Errorf("construct H3 mark authorizer: %w", err)
	}
	authorization, err = authorizer.AuthorizeUnderlayMark(
		context.Background(),
		preparation.UnderlayMarkAuthorizationRequest{
			CandidateID:      "h3-primary",
			NodeID:           "aicore-h3-node",
			Carrier:          connectivity.CarrierHTTP3,
			ManifestDigest:   carrierauth.LabManifestDigest,
			ManifestSequence: 1,
			SignedEndpoint:   cfg.masqueTemplate,
			ExpiresAt:        expiresAt,
		},
	)
	if err != nil {
		return fmt.Errorf("authorize dedicated H3 underlay mark: %w", err)
	}
	fmt.Printf(
		"H3_MARK_AUTHORIZED interface=%s mark=%#x\n",
		authorization.InterfaceName, authorization.FirewallMark,
	)

	suite, err := tlsconfig.ParseSuite("x25519-mlkem768")
	if err != nil {
		return err
	}
	clientTLS, err := tlsconfig.ClientForALPN(
		cfg.deviceCert, cfg.deviceKey, cfg.rootCA,
		cfg.serverName, suite, http3.NextProtoH3,
	)
	if err != nil {
		return fmt.Errorf("construct strict client TLS: %w", err)
	}
	echList, err := echconfig.LoadClientConfigList(cfg.echConfigList)
	if err != nil {
		return fmt.Errorf("load ECH config list: %w", err)
	}
	defer clear(echList)
	if err := echconfig.ConfigureClient(clientTLS, echList, true); err != nil {
		return fmt.Errorf("require ECH: %w", err)
	}
	deviceSigner, err := pqauth.LoadSigner(
		pqauth.MLDSA65, cfg.devicePQSeed,
	)
	if err != nil {
		return fmt.Errorf("load device ML-DSA signer: %w", err)
	}
	controllerVerifiers, err := pqauth.LoadVerifierSet(
		cfg.controllerPins,
	)
	if err != nil {
		return fmt.Errorf("load controller ML-DSA pins: %w", err)
	}
	responseVerifier := &carrierauth.ResponseVerifier{
		Verifiers:    controllerVerifiers,
		ControllerID: cfg.controllerID,
		Suite:        suite.Name,
		MaxSkew:      time.Minute,
	}
	h3Dialer, err := carrier.NewH3Dialer(
		cfg.masqueTemplate,
		cfg.publicTarget,
		cfg.deviceID,
		randomHex(16),
		suite,
		clientTLS,
		deviceSigner,
		responseVerifier,
	)
	if err != nil {
		return fmt.Errorf("construct authenticated H3 dialer: %w", err)
	}
	h3Dialer.MaxDatagram = 1350
	h3Dialer.MaxOuterDatagram =
		1350 + carrier.CarrierEnvelopeOverhead
	h3Dialer.AuthorizationMode = carrierauth.AuthModeIdentity

	underlay, err := h3candidate.NewLinuxProtectedUnderlayFactory(
		h3candidate.LinuxProtectedUnderlayConfig{
			InterfaceName:    authorization.InterfaceName,
			FirewallMark:     authorization.FirewallMark,
			ServerName:       cfg.serverName,
			RemoteEndpoint:   cfg.remoteEndpoint,
			SessionExpiresAt: expiresAt,
			HealthInterval:   500 * time.Millisecond,
		},
	)
	if err != nil {
		return fmt.Errorf("construct fixed-IP protected H3 underlay: %w", err)
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
	controller, err := directawg.NewLinuxController(
		directawg.LinuxControllerConfig{
			AWGGoBinary: cfg.awgGoBinary,
			AWGBinary:   cfg.awgBinary,
			IPBinary:    cfg.ipBinary,
			TempRoot:    cfg.tempRoot,
			Signed: directawg.LinuxSignedInterfaceConfig{
				InnerAddressPool:    pool,
				AllowedIPs:          []netip.Prefix{allowed},
				VerificationRoutes:  []netip.Prefix{verification},
				MTU:                 1280,
				ListenPortMin:       listenPortMin,
				ListenPortMax:       listenPortMax,
				PersistentKeepalive: 25,
				Obfuscation: directawg.AWGObfuscation{
					JC: 4, JMin: 12, JMax: 64,
					S1: 16, S2: 80, S3: 24, S4: 8,
					H1: 111111, H2: 222222,
					H3: 333333, H4: 444444,
				},
			},
			KeyProvider: fixedKeyProvider{
				material: directawg.LinuxKeyMaterial{
					Generation: 1,
					PrivateKey: cfg.clientPrivateKey,
					PSK:        cfg.psk,
				},
			},
			Verifier:      verifier,
			PolicyFactory: policyFactory,
			Runner:        runner,
			StopTimeout:   3 * time.Second,
		},
	)
	if err != nil {
		return fmt.Errorf("construct real DirectAWG controller: %w", err)
	}
	innerController, err := h3candidate.NewLinuxAWGOverH3Controller(
		h3candidate.LinuxAWGOverH3Config{
			Controller:        controller,
			GatewayEndpoint:   cfg.gatewayEndpoint,
			GatewayPublicKey:  cfg.gatewayPublicKey,
			LocalRelayAddress: "127.0.0.1:0",
			MinInnerDatagram:  1200,
			MaxInnerDatagram:  1350,
			PollInterval:      10 * time.Millisecond,
			RelayBatchSize:    16,
			SocketBufferBytes: 0,
		},
	)
	if err != nil {
		return fmt.Errorf("construct production H3-to-AWG adapter: %w", err)
	}
	descriptor := connectivity.CandidateDescriptor{
		ID:        "h3-primary",
		Carrier:   connectivity.CarrierHTTP3,
		NodeID:    "aicore-h3-node",
		ExpiresAt: expiresAt,
	}
	preparationStarted := time.Now()
	warm, err := h3candidate.PrepareWarm(
		context.Background(),
		h3candidate.Config{
			Descriptor:       descriptor,
			SessionExpiresAt: expiresAt,
			Dialer:           h3Dialer,
			Underlay:         underlay,
			Tunnel:           innerController,
			Verifier:         h3candidate.NewLinuxCandidateVerifierAdapter(),
			Transactions:     h3candidate.NewLinuxRouteDNSTransactionFactory(),
			TeardownTimeout:  5 * time.Second,
		},
		time.Minute,
	)
	if err != nil {
		return fmt.Errorf(
			"prepare live authenticated production H3 candidate: %w", err,
		)
	}
	candidate := warm.Candidate
	warmResource = warm.Resource
	fmt.Printf(
		"LIVE_H3_PREPARED elapsed=%s warm_until=%s "+
			"auth_mode=%s authenticated_connect_probe=true "+
			"preparation_auth_requests=1\n",
		time.Since(preparationStarted),
		warm.WarmUntil.Format(time.RFC3339Nano),
		h3Dialer.AuthorizationMode,
	)
	binding := connectivity.Binding{
		AttemptID:      randomHex(16),
		Profile:        "aicore-h3-e2e",
		Mode:           connectivity.ModeAuto,
		ManifestDigest: carrierauth.LabManifestDigest,
		CandidateID:    descriptor.ID,
		NodeID:         descriptor.NodeID,
		SessionID:      randomHex(16),
		PSKGeneration:  1,
		SequenceEpoch:  1,
		Nonce:          randomHex(16),
		// Production bindingFor caps the click binding at the prepared
		// generation's readiness expiry. This standalone vertical driver
		// bypasses preparation.Manager, so apply the authenticated-warm
		// expiry explicitly rather than overclaiming the descriptor lifetime.
		ExpiresAt: warm.WarmUntil,
	}

	fmt.Printf(
		"PREPARED protocol_version=%s suite=%s ech=required "+
			"zero_rtt=false auth=%s h3_fixed_ip=true live_h3=true\n",
		protocolVersion, suite.Name, deviceSigner.Algorithm(),
	)
	connectContext, cancelConnect := context.WithTimeout(
		context.Background(), connectBudget,
	)
	defer cancelConnect()
	started := time.Now()
	connection, err = candidate.Dial(connectContext, binding)
	if err != nil {
		return fmt.Errorf(
			"dial production H3 candidate after %s: %w",
			time.Since(started), err,
		)
	}
	dialElapsed := time.Since(started)
	fmt.Printf("H3_AWG_DIAL_OK elapsed=%s\n", dialElapsed)

	type probeResult struct {
		name string
		err  error
	}
	probes := make(chan probeResult, 2)
	go func() {
		probes <- probeResult{
			name: "protected_dns",
			err: connection.VerifyProtectedDNS(
				connectContext, binding,
			),
		}
	}()
	go func() {
		probes <- probeResult{
			name: "tunnel_canary",
			err: connection.VerifyTunnelCanary(
				connectContext, binding,
			),
		}
	}()
	if err := connection.FreshAWGHandshake(
		connectContext, binding,
	); err != nil {
		return fmt.Errorf("fresh inner AWG handshake: %w", err)
	}
	fmt.Println("FRESH_AWG_HANDSHAKE_OK")
	if err := connection.VerifyBidirectional(
		connectContext, binding,
	); err != nil {
		return fmt.Errorf("inner AWG bidirectional counters: %w", err)
	}
	fmt.Println("AWG_COUNTERS_BIDIRECTIONAL_OK")
	for range 2 {
		result := <-probes
		if result.err != nil {
			return fmt.Errorf("%s: %w", result.name, result.err)
		}
		fmt.Printf("%s_OK\n", strings.ToUpper(result.name))
	}
	if err := connection.Commit(connectContext, binding); err != nil {
		return fmt.Errorf("commit H3 route/DNS transaction: %w", err)
	}
	elapsed := time.Since(started)
	if elapsed > connectBudget {
		return fmt.Errorf(
			"connect budget exceeded: elapsed=%s budget=%s",
			elapsed, connectBudget,
		)
	}
	fmt.Printf(
		"ONLINE elapsed=%s budget=%s protocol_version=%s "+
			"tls13=true hybrid_kex=x25519+ml-kem-768 ech_accepted=true "+
			"zero_rtt=false connect_udp_authenticated=true "+
			"inner_awg_fresh=true protected_dns=true canary=true\n",
		elapsed, connectBudget, protocolVersion,
	)
	if cfg.hold > 0 {
		select {
		case healthErr, ok := <-connection.Health():
			return fmt.Errorf(
				"candidate health failed before hold completed: %v (open=%v)",
				healthErr, ok,
			)
		case <-time.After(cfg.hold):
		}
	}
	fmt.Println("HEALTH_STABLE_OK")
	return nil
}

type fixedKeyProvider struct {
	material directawg.LinuxKeyMaterial
}

func (provider fixedKeyProvider) KeyMaterial(
	_ context.Context,
	binding connectivity.Binding,
) (directawg.LinuxKeyMaterial, error) {
	if binding.PSKGeneration != provider.material.Generation {
		return directawg.LinuxKeyMaterial{},
			errors.New("binding PSK generation differs from key material")
	}
	return directawg.LinuxKeyMaterial{
		Generation: provider.material.Generation,
		PrivateKey: append(
			[]byte(nil), provider.material.PrivateKey...,
		),
		PSK: append([]byte(nil), provider.material.PSK...),
	}, nil
}

// systemd-resolved in the root namespace cannot configure an interface index
// that exists only inside the disposable client namespace. We therefore
// record only the resolver staging calls. Protected DNS verification itself is
// real: its socket is bound to the fresh AWG interface, marked for that
// candidate's route table, and receives a strict DNS answer through inner AWG.
type realCommandRunner struct {
	// allowed is the fixed set of executables this runner may launch.
	allowed          *directawg.LinuxExecAllowList
	resolvectlBinary string
	mu               sync.Mutex
	resolverCalls    []directawg.LinuxCommand
}

func (runner *realCommandRunner) Run(
	ctx context.Context,
	command directawg.LinuxCommand,
) (directawg.LinuxCommandResult, error) {
	if command.Path == runner.resolvectlBinary {
		runner.mu.Lock()
		runner.resolverCalls = append(
			runner.resolverCalls, command,
		)
		runner.mu.Unlock()
		fmt.Printf(
			"NAMESPACE_RESOLVECTL_RECORDED %s\n",
			strings.Join(command.Args, " "),
		)
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
	var stdout strings.Builder
	var stderr strings.Builder
	process.Stdout = &stdout
	process.Stderr = &stderr
	err := process.Run()
	result := directawg.LinuxCommandResult{
		Stdout: []byte(stdout.String()),
		Stderr: []byte(stderr.String()),
	}
	if err != nil {
		return result, fmt.Errorf(
			"%s %s: %w: %s",
			command.Path, strings.Join(command.Args, " "),
			err, stderr.String(),
		)
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
	managed := &realManagedProcess{
		process: process,
		exited:  make(chan struct{}),
	}
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

func (process *realManagedProcess) Exited() <-chan struct{} {
	return process.exited
}

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
			process.stopErr = context.Cause(ctx)
			_ = process.process.Process.Kill()
			<-process.exited
		}
	})
	return process.stopErr
}

func randomHex(bytes int) string {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buffer)
}
