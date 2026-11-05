//go:build linux

// Command winn-auto-e2e is the privileged production-reference join for
// Winn v3 Linux Auto mode. It loads only signed ManifestV2/profile facts,
// real rotation state, and an encrypted anonymous-token vault; performs all
// DirectAWG and live H3 preparation before the click; then drives the exact
// three-second autoconnect boundary.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"

	"winsvpn.local/winnprotocol/internal/autoconnect"
	"winsvpn.local/winnprotocol/internal/awg"
	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/directawg"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/gatewaymanifest"
	"winsvpn.local/winnprotocol/internal/h3candidate"
	"winsvpn.local/winnprotocol/internal/linuxauto"
	"winsvpn.local/winnprotocol/internal/measurement"
	"winsvpn.local/winnprotocol/internal/mobility"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/preparation"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/rotation"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/internal/state"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

var sourceDigest = "unset"

const maxMeasuredBatchAttempts = 4000

type stringList []string

func (values *stringList) String() string {
	return strings.Join(*values, ",")
}

func (values *stringList) Set(value string) error {
	if value == "" {
		return errors.New("path cannot be empty")
	}
	*values = append(*values, value)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() (resultErr error) {
	printDigest := flag.Bool(
		"print-source-digest", false,
		"print the source digest embedded by the evidence build",
	)
	manifestPath := flag.String(
		"manifest-v2", "", "signed ManifestV2 JSON",
	)
	nodeID := flag.String("node-id", "", "verified gateway node")
	transparencyLog := flag.String(
		"transparency-log", "", "append-only manifest receipt log",
	)
	trustStatePath := flag.String(
		"trust-state-v2", "", "retained ManifestV2 trust state",
	)
	linuxProfilePath := flag.String(
		"linux-profile", "", "signed Linux deployment profile",
	)
	controllerPinsPath := flag.String(
		"controller-pq-pins", "", "controller ML-DSA pins",
	)
	directTransportID := flag.String(
		"direct-transport-id", "direct-primary",
		"selected signed DirectAWG transport",
	)
	h3TransportID := flag.String(
		"h3-transport-id", "h3-primary",
		"selected signed HTTP/3 transport",
	)
	// Auto legitimately prefers DirectAWG, so ordinary runs select it on
	// essentially every attempt and leave the HTTP/3 carrier — the entire
	// reason the stealth path exists — unexercised under load. This withholds
	// a carrier from preparation so a cell can produce targeted evidence for
	// the other. It restricts which candidates the harness prepares; it never
	// widens Mode policy, and Auto already allows HTTP/3.
	forceCarrier := flag.String(
		"force-carrier", "",
		"restrict preparation to one carrier for targeted evidence: "+
			"empty (both), http3, or direct-awg",
	)
	deviceID := flag.String(
		"device-id", "", "rotation and carrier device identity",
	)
	devicePQSeedPath := flag.String(
		"device-pq-seed", "", "device ML-DSA seed",
	)
	rootCAPath := flag.String(
		"root-ca", "", "carrier TLS trust root",
	)
	clientPrivateKeyPath := flag.String(
		"client-private-key-file", "",
		"base64-encoded AWG private key",
	)
	rotationStatePath := flag.String(
		"rotation-state", "", "real hybrid-PSK rotation state",
	)
	appliedPSKPath := flag.String(
		"applied-psk", "", "rotation-applied PSK file",
	)
	vaultPath := flag.String(
		"credential-vault", "", "encrypted anonymous-token vault",
	)
	vaultKeyPath := flag.String(
		"credential-vault-key", "", "raw 32-byte vault key",
	)
	bundleDirectory := flag.String(
		"privacy-token-bundle-dir", "",
		"private directory containing blind-token JSON bundles",
	)
	var bundlePaths stringList
	flag.Var(
		&bundlePaths,
		"privacy-token-bundle",
		"blind-token bundle to import; repeat for each credential",
	)
	clientNamespace := flag.String(
		"client-namespace", "",
		"disposable client namespace used by the mark authorizer",
	)
	tableName := flag.String(
		"table-name", "", "candidate-scoped nftables table",
	)
	underlayInterface := flag.String(
		"underlay-interface", "", "protected physical underlay",
	)
	directMarkText := flag.String(
		"direct-underlay-mark", "", "DirectAWG mark in hexadecimal",
	)
	h3MarkText := flag.String(
		"h3-underlay-mark", "", "dedicated H3 mark in hexadecimal",
	)
	awgGoBinary := flag.String(
		"awg-go-binary", directawg.DefaultLinuxAWGGoBinary,
		"path to amneziawg-go",
	)
	awgBinary := flag.String(
		"awg-binary", directawg.DefaultLinuxAWGBinary,
		"path to awg",
	)
	ipBinary := flag.String(
		"ip-binary", directawg.DefaultLinuxIPBinary,
		"path to ip",
	)
	nftBinary := flag.String(
		"nft-binary", directawg.DefaultLinuxNftBinary,
		"path to nft",
	)
	resolvectlBinary := flag.String(
		"resolvectl-binary",
		directawg.DefaultLinuxResolvectlBinary,
		"path to resolvectl",
	)
	tempRoot := flag.String(
		"temp-root", "", "private temporary root",
	)
	hold := flag.Duration(
		"hold", 250*time.Millisecond,
		"post-Online health observation",
	)
	directInitialOuterDrop := flag.Duration(
		"direct-initial-outer-drop",
		0,
		"diagnostic only: discard initial DirectAWG outer writes",
	)
	directClickDelay := flag.Duration(
		"direct-click-delay",
		0,
		"diagnostic only: delay the warm click-time DirectAWG dial",
	)
	attemptCount := flag.Int(
		"attempts", 1,
		"independent single-use Auto generations in this evidence batch",
	)
	readinessText := flag.String(
		"readiness", string(measurement.ReadinessWarm),
		"measurement boundary: warm or cold",
	)
	measurementLogPath := flag.String(
		"measurement-log", "", "HMAC-chained attempt evidence log",
	)
	measurementKeyPath := flag.String(
		"measurement-key", "", "raw 32-byte measurement HMAC key",
	)
	osVersion := flag.String(
		"os-version", "Ubuntu 24.04 LTS",
		"platform OS version recorded in evidence",
	)
	device := flag.String(
		"device", "AICORE",
		"physical or virtual device recorded in evidence",
	)
	networkInterface := flag.String(
		"network-interface", "ethernet",
		"measured interface: ethernet, wifi, cellular, loopback, synthetic",
	)
	ipFamily := flag.String(
		"ip-family", "ipv4",
		"measured IP family: ipv4, ipv6, dual, or nat64",
	)
	natType := flag.String(
		"nat", "none", "declared NAT classification",
	)
	impairment := flag.String(
		"impairment", "baseline",
		"frozen impairment profile identifier",
	)
	rttMillis := flag.Float64(
		"rtt-ms", 0, "declared measured/configured RTT in milliseconds",
	)
	lossFraction := flag.Float64(
		"loss-fraction", 0,
		"declared measured/configured loss fraction in [0,1]",
	)
	capacityMbps := flag.Float64(
		"capacity-mbps", 0,
		"declared measured/configured capacity in Mbit/s",
	)
	clientRegion := flag.String(
		"client-region", "aicore-lab",
		"client region label",
	)
	serverRegion := flag.String(
		"server-region", "aicore-lab",
		"server region label",
	)
	serverProvider := flag.String(
		"server-provider", "private-lab",
		"server provider label",
	)
	flag.Parse()

	if *printDigest {
		fmt.Println(sourceDigest)
		return nil
	}
	for name, value := range map[string]string{
		"manifest-v2":             *manifestPath,
		"node-id":                 *nodeID,
		"transparency-log":        *transparencyLog,
		"trust-state-v2":          *trustStatePath,
		"linux-profile":           *linuxProfilePath,
		"controller-pq-pins":      *controllerPinsPath,
		"device-id":               *deviceID,
		"device-pq-seed":          *devicePQSeedPath,
		"root-ca":                 *rootCAPath,
		"client-private-key-file": *clientPrivateKeyPath,
		"rotation-state":          *rotationStatePath,
		"applied-psk":             *appliedPSKPath,
		"credential-vault":        *vaultPath,
		"credential-vault-key":    *vaultKeyPath,
		"client-namespace":        *clientNamespace,
		"table-name":              *tableName,
		"underlay-interface":      *underlayInterface,
		"direct-underlay-mark":    *directMarkText,
		"h3-underlay-mark":        *h3MarkText,
		"temp-root":               *tempRoot,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if !lowerHexDigest(sourceDigest) {
		return errors.New(
			"binary lacks a valid embedded source-tree digest",
		)
	}
	if *hold < 0 || *hold > 10*time.Minute {
		return errors.New("hold must be between zero and ten minutes")
	}
	if *directInitialOuterDrop < 0 ||
		*directInitialOuterDrop > 2*time.Second {
		return errors.New(
			"direct initial outer discard must be within [0,2s]",
		)
	}
	if *directClickDelay < 0 || *directClickDelay > 2*time.Second {
		return errors.New(
			"direct click delay must be within [0,2s]",
		)
	}
	if *attemptCount < 1 || *attemptCount > maxMeasuredBatchAttempts {
		return fmt.Errorf(
			"attempts must be within [1,%d]",
			maxMeasuredBatchAttempts,
		)
	}
	if *hold > 0 && *attemptCount != 1 {
		return errors.New("hold requires exactly one attempt")
	}
	readinessClass, err := parseReadinessClass(*readinessText)
	if err != nil {
		return err
	}
	if *directClickDelay > 0 &&
		readinessClass != measurement.ReadinessWarm {
		return errors.New(
			"diagnostic DirectAWG click delay requires warm readiness",
		)
	}
	if (*measurementLogPath == "") != (*measurementKeyPath == "") {
		return errors.New(
			"measurement-log and measurement-key must be provided together",
		)
	}
	if *measurementLogPath == "" {
		return errors.New(
			"measurement-log and measurement-key are required",
		)
	}
	network := measurement.NetworkProfile{
		Interface:      *networkInterface,
		IPFamily:       *ipFamily,
		NAT:            *natType,
		Impairment:     *impairment,
		RTTMillis:      *rttMillis,
		LossFraction:   *lossFraction,
		CapacityMbps:   *capacityMbps,
		ClientRegion:   *clientRegion,
		ServerRegion:   *serverRegion,
		ServerProvider: *serverProvider,
	}
	if err := validateMeasurementMetadata(
		*osVersion, *device, network,
	); err != nil {
		return err
	}
	collectedBundles, err := collectBundlePaths(
		bundlePaths, *bundleDirectory,
	)
	if err != nil {
		return err
	}
	bundlePaths = collectedBundles
	directMark, err := parseMark(*directMarkText)
	if err != nil {
		return fmt.Errorf("direct underlay mark: %w", err)
	}
	h3Mark, err := parseMark(*h3MarkText)
	if err != nil {
		return fmt.Errorf("H3 underlay mark: %w", err)
	}
	if directMark == h3Mark {
		return errors.New("DirectAWG and H3 marks must be distinct")
	}
	pins, err := pqauth.LoadVerifierSet(*controllerPinsPath)
	if err != nil {
		return fmt.Errorf("load controller pins: %w", err)
	}
	deployment, err := linuxauto.LoadVerifiedAutoDeployment(
		linuxauto.VerifiedAutoDeploymentConfig{
			ManifestPath:     *manifestPath,
			NodeID:           *nodeID,
			TransparencyLog:  *transparencyLog,
			TrustStatePath:   *trustStatePath,
			LinuxProfilePath: *linuxProfilePath,
			ControllerPins:   pins,
		},
	)
	if err != nil {
		return err
	}
	directTransport, err := deployment.Node.Transport(
		*directTransportID,
	)
	if err != nil {
		return err
	}
	h3Transport, err := deployment.Node.Transport(*h3TransportID)
	if err != nil {
		return err
	}
	if directTransport.Type != connectivity.CarrierDirectAWG ||
		h3Transport.Type != connectivity.CarrierHTTP3 ||
		directTransport.PublicAWGKey != h3Transport.PublicAWGKey {
		return errors.New(
			"selected Auto transports are not one DirectAWG/H3 peer",
		)
	}
	if h3Transport.PublicTarget == "" ||
		h3Transport.FixedBackend == "" {
		return errors.New(
			"signed H3 transport lacks public target or fixed backend",
		)
	}
	tokenKey, err := manifestTokenKey(
		deployment.Manifest, h3Transport.TokenKeyID,
	)
	if err != nil {
		return err
	}

	privateKey, err := readBase64Secret(*clientPrivateKeyPath)
	if err != nil {
		return fmt.Errorf("load AWG private key: %w", err)
	}
	defer clear(privateKey)
	rotationCoordinator, err := rotation.NewCoordinator(
		rotation.CoordinatorConfig{
			Applier:       awg.FileApplier{Path: *appliedPSKPath},
			StatePath:     *rotationStatePath,
			DeviceID:      *deviceID,
			PeerPublicKey: directTransport.PublicAWGKey,
			Suite:         deployment.Manifest.Suite,
		},
	)
	if err != nil {
		return fmt.Errorf("construct rotation coordinator: %w", err)
	}
	defer func() {
		cleanupContext, cancel := context.WithTimeout(
			context.Background(), 5*time.Second,
		)
		defer cancel()
		resultErr = errors.Join(
			resultErr, rotationCoordinator.Close(cleanupContext),
		)
	}()
	pskSource, err := preparation.NewRotationHybridPSKSnapshotSource(
		preparation.RotationHybridPSKSnapshotSourceConfig{
			Coordinator:   rotationCoordinator,
			Suite:         deployment.Manifest.Suite,
			DeviceID:      *deviceID,
			PeerPublicKey: directTransport.PublicAWGKey,
		},
	)
	if err != nil {
		return err
	}
	pskPool, err := preparation.NewProductionHybridPSKPool(
		preparation.ProductionHybridPSKPoolConfig{
			Source:        pskSource,
			Suite:         deployment.Manifest.Suite,
			DeviceID:      *deviceID,
			PeerPublicKey: directTransport.PublicAWGKey,
		},
	)
	if err != nil {
		return err
	}
	keyProvider, err := linuxauto.NewRotationKeyProvider(
		linuxauto.RotationKeyProviderConfig{
			Coordinator:   rotationCoordinator,
			ControllerID:  deployment.Manifest.ControllerID,
			Suite:         deployment.Manifest.Suite,
			DeviceID:      *deviceID,
			PeerPublicKey: directTransport.PublicAWGKey,
			PrivateKey:    privateKey,
		},
	)
	if err != nil {
		return err
	}
	defer keyProvider.Close()

	vault, err := state.OpenCredentialVault(
		state.CredentialVaultConfig{
			Path:    *vaultPath,
			KeyPath: *vaultKeyPath,
		},
	)
	if err != nil {
		return fmt.Errorf("open credential vault: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, vault.Close())
	}()
	if len(bundlePaths) > 0 {
		imports := make(
			[]state.CredentialImport, 0, len(bundlePaths),
		)
		class := state.CredentialClassBinding{
			TokenKeyID:      tokenKey.ID,
			Scope:           tokenKey.Scope,
			IssuerDomain:    tokenKey.IssuerDomain,
			IssuerPublicKey: tokenKey.PublicKey,
			NotBefore:       tokenKey.NotBefore,
			NotAfter:        tokenKey.NotAfter,
		}
		for _, path := range bundlePaths {
			bundle, loadErr := privacytoken.LoadBundle(path)
			if loadErr != nil {
				return fmt.Errorf(
					"load privacy-token bundle %s: %w",
					path, loadErr,
				)
			}
			imports = append(imports, state.CredentialImport{
				Class: class, Bundle: bundle,
			})
		}
		if err := vault.Add(context.Background(), imports); err != nil {
			return fmt.Errorf("import credential inventory: %w", err)
		}
	}
	vaultAdapter, err :=
		preparation.NewEncryptedAnonymousCredentialVault(vault)
	if err != nil {
		return err
	}
	credentialPool, err :=
		preparation.NewProductionAnonymousCredentialPool(
			preparation.ProductionAnonymousCredentialPoolConfig{
				Vault: vaultAdapter,
			},
		)
	if err != nil {
		return err
	}

	resolver, err := netip.ParseAddrPort(
		deployment.LinuxVerification.DNSResolver,
	)
	if err != nil {
		return fmt.Errorf("signed DNS resolver: %w", err)
	}
	// The fixed set of executables this harness may launch.
	allowedExecutables, err := directawg.NewLinuxExecAllowList(
		*nftBinary, *resolvectlBinary, *awgGoBinary, *awgBinary, *ipBinary,
	)
	if err != nil {
		return fmt.Errorf("executable allow-list: %w", err)
	}
	runner := &realCommandRunner{
		resolvectlBinary: *resolvectlBinary,
		allowed:          allowedExecutables,
	}
	protectedVerifier, err :=
		directawg.NewLinuxProtectedVerifier(
			deployment.LinuxVerification,
		)
	if err != nil {
		return fmt.Errorf("construct protected verifier: %w", err)
	}
	policyFactory, err :=
		directawg.NewLinuxNftResolvedPolicyFactory(
			directawg.LinuxNftResolvedPolicyConfig{
				NftBinary:         *nftBinary,
				ResolvectlBinary:  *resolvectlBinary,
				TempRoot:          *tempRoot,
				TableName:         *tableName,
				UnderlayInterface: *underlayInterface,
				UnderlayMark:      directMark,
				DNSResolver:       resolver.Addr(),
				HealthInterval:    500 * time.Millisecond,
				Runner:            runner,
			},
		)
	if err != nil {
		return fmt.Errorf("construct fail-closed policy: %w", err)
	}
	defer func() {
		cleanupContext, cancel := context.WithTimeout(
			context.Background(), 8*time.Second,
		)
		defer cancel()
		resultErr = errors.Join(
			resultErr, policyFactory.Release(cleanupContext),
		)
	}()
	policyAnchor, err :=
		preparation.NewLinuxUnderlayPolicyAnchorLeaser(
			preparation.LinuxUnderlayPolicyAnchorLeaserConfig{
				Factory:               policyFactory,
				TableName:             *tableName,
				UnderlayInterface:     *underlayInterface,
				DirectAWGUnderlayMark: directMark,
			},
		)
	if err != nil {
		return err
	}
	underlayAuthorizer, err :=
		preparation.NewLinuxUnderlayMarkAuthorizer(
			preparation.LinuxUnderlayMarkAuthorizerConfig{
				NftBinary:             *nftBinary,
				IPBinary:              *ipBinary,
				NetworkNamespace:      *clientNamespace,
				TableFamily:           "inet",
				TableName:             *tableName,
				OutputChain:           "output",
				UnderlayInterface:     *underlayInterface,
				DirectAWGUnderlayMark: directMark,
				FirewallMark:          h3Mark,
				CommandTimeout:        3 * time.Second,
				CleanupRetryInterval:  50 * time.Millisecond,
			},
		)
	if err != nil {
		return err
	}
	controller, err := directawg.NewLinuxController(
		directawg.LinuxControllerConfig{
			AWGGoBinary:   *awgGoBinary,
			AWGBinary:     *awgBinary,
			IPBinary:      *ipBinary,
			TempRoot:      *tempRoot,
			Signed:        deployment.LinuxInterface,
			KeyProvider:   keyProvider,
			Verifier:      protectedVerifier,
			PolicyFactory: policyFactory,
			Runner:        runner,
			StopTimeout:   3 * time.Second,
		},
	)
	if err != nil {
		return fmt.Errorf("construct Linux AWG controller: %w", err)
	}
	controllerFactory := func(
		_ context.Context,
		input preparation.DirectAWGPreparationInput,
	) (directawg.TunnelController, error) {
		if input.GatewayPublicKey != directTransport.PublicAWGKey {
			return nil, errors.New(
				"DirectAWG controller peer differs from signed selection",
			)
		}
		return controller, nil
	}
	var directDropState *initialOuterDropState
	var directDialerFactory linuxauto.DirectRemoteDialerFactory
	if *directInitialOuterDrop > 0 {
		directDropState = &initialOuterDropState{}
		directDialerFactory = func(
			authorization preparation.UnderlayMarkAuthorization,
		) (directawg.RemoteDialer, error) {
			protected, dialerErr :=
				directawg.NewLinuxProtectedUDPDialer(
					directawg.LinuxProtectedUDPDialerConfig{
						InterfaceName: authorization.InterfaceName,
						FirewallMark:  authorization.FirewallMark,
					},
				)
			if dialerErr != nil {
				return nil, dialerErr
			}
			return initialOuterDropDialer{
				next:     protected,
				duration: *directInitialOuterDrop,
				state:    directDropState,
			}, nil
		}
	}
	directProbe, err := linuxauto.NewLiveDirectProbe(
		linuxauto.LiveDirectProbeConfig{
			ControllerFactory: controllerFactory,
			DialerFactory:     directDialerFactory,
			PollInterval:      10 * time.Millisecond,
			EvidenceLifetime:  30 * time.Second,
		},
	)
	if err != nil {
		return err
	}
	var directClickDelayState *delayedDirectDialState
	var builderDialerFactory linuxauto.DirectRemoteDialerFactory
	if *directClickDelay > 0 {
		directClickDelayState = &delayedDirectDialState{}
		builderDialerFactory = func(
			authorization preparation.UnderlayMarkAuthorization,
		) (directawg.RemoteDialer, error) {
			protected, dialerErr :=
				directawg.NewLinuxProtectedUDPDialer(
					directawg.LinuxProtectedUDPDialerConfig{
						InterfaceName: authorization.InterfaceName,
						FirewallMark:  authorization.FirewallMark,
					},
				)
			if dialerErr != nil {
				return nil, dialerErr
			}
			return delayedDirectDialer{
				next:  protected,
				delay: *directClickDelay,
				state: directClickDelayState,
			}, nil
		}
	}
	directBuilder, err := linuxauto.NewDirectBuilder(
		linuxauto.DirectBuilderConfig{
			ControllerFactory: controllerFactory,
			Probe:             directProbe,
			DialerFactory:     builderDialerFactory,
			PollInterval:      10 * time.Millisecond,
			MaxProbeAge:       30 * time.Second,
		},
	)
	if err != nil {
		return err
	}

	deviceSigner, err := pqauth.LoadSigner(
		pqauth.MLDSA65, *devicePQSeedPath,
	)
	if err != nil {
		return fmt.Errorf("load device signer: %w", err)
	}
	defer deviceSigner.Destroy()
	suite, err := tlsconfig.ParseSuite(
		deployment.Manifest.Suite,
	)
	if err != nil {
		return err
	}
	h3Builder, err := linuxauto.NewH3Builder(
		linuxauto.H3BuilderConfig{
			DialerFactory: func(
				_ context.Context,
				input preparation.H3PreparationInput,
			) (*carrier.H3Dialer, error) {
				if input.CredentialScope !=
					"carrier:"+input.PublicTarget {
					return nil, errors.New(
						"signed carrier target differs from credential scope",
					)
				}
				clientTLS, tlsErr :=
					tlsconfig.ClientAnonymousForALPN(
						*rootCAPath,
						input.ServerName,
						suite,
						http3.NextProtoH3,
					)
				if tlsErr != nil {
					return nil, tlsErr
				}
				if tlsErr = echconfig.ConfigureClient(
					clientTLS, input.ECHConfigList, true,
				); tlsErr != nil {
					return nil, tlsErr
				}
				responseVerifier :=
					&carrierauth.ResponseVerifier{
						Verifiers:    pins,
						ControllerID: input.ControllerID,
						Suite:        input.Suite,
						MaxSkew:      time.Minute,
					}
				sessionID, sessionErr :=
					mobility.NewSessionID()
				if sessionErr != nil {
					return nil, sessionErr
				}
				return carrier.NewH3Dialer(
					input.EndpointTemplate,
					input.PublicTarget,
					*deviceID,
					sessionID,
					suite,
					clientTLS,
					deviceSigner,
					responseVerifier,
				)
			},
			TunnelFactory: func(
				_ context.Context,
				input preparation.H3PreparationInput,
			) (h3candidate.TunnelController, error) {
				return h3candidate.NewLinuxAWGOverH3Controller(
					h3candidate.LinuxAWGOverH3Config{
						Controller:        controller,
						GatewayEndpoint:   input.FixedBackend,
						GatewayPublicKey:  input.GatewayPublicKey,
						LocalRelayAddress: "127.0.0.1:0",
						MinInnerDatagram:  input.MinInnerDatagram,
						MaxInnerDatagram:  input.MaxInnerDatagram,
						PollInterval:      10 * time.Millisecond,
						RelayBatchSize:    16,
					},
				)
			},
			Verifier:        h3candidate.NewLinuxCandidateVerifierAdapter(),
			Transactions:    h3candidate.NewLinuxRouteDNSTransactionFactory(),
			WarmAge:         time.Minute,
			HealthInterval:  500 * time.Millisecond,
			TeardownTimeout: 5 * time.Second,
		},
	)
	if err != nil {
		return err
	}
	assembler, err := preparation.NewVerifiedPreparationAssembler(
		preparation.VerifiedPreparationAssemblerConfig{
			Deployments: []preparation.VerifiedDeploymentV2{
				deployment.Deployment,
			},
			PSKPool:        pskPool,
			CredentialPool: credentialPool,
			PolicyAnchor:   policyAnchor,
			Underlay:       underlayAuthorizer,
			DirectAWG:      directBuilder,
			H3:             h3Builder,
			Policy:         preparation.Phase1AutoPolicy,
			MaxParallel:    2,
			CloseTimeout:   8 * time.Second,
		},
	)
	if err != nil {
		return err
	}
	autoRuntime, err := linuxauto.NewAutoRuntime(
		assembler,
		linuxauto.AutoRuntimeConfig{
			Deadline: connectivity.DefaultDeadline,
		},
	)
	if err != nil {
		return err
	}

	executablePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve production Auto executable: %w", err)
	}
	artifactDigest, err := sha256File(executablePath)
	if err != nil {
		return fmt.Errorf("hash production Auto executable: %w", err)
	}
	evidenceLog, err := openOrCreateMeasurementLog(
		*measurementLogPath, *measurementKeyPath,
	)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, evidenceLog.Close())
	}()

	assemblyCandidateIDs := []string{
		*directTransportID,
		*h3TransportID,
	}
	assemblyRequiredCarriers := []connectivity.Carrier{
		connectivity.CarrierDirectAWG,
		connectivity.CarrierHTTP3,
	}
	assemblyRequiredWarmCarriers := []connectivity.Carrier{
		connectivity.CarrierHTTP3,
	}
	switch *forceCarrier {
	case "":
	case "http3":
		assemblyCandidateIDs = []string{*h3TransportID}
		assemblyRequiredCarriers = []connectivity.Carrier{
			connectivity.CarrierHTTP3,
		}
	case "direct-awg":
		assemblyCandidateIDs = []string{*directTransportID}
		assemblyRequiredCarriers = []connectivity.Carrier{
			connectivity.CarrierDirectAWG,
		}
		assemblyRequiredWarmCarriers = nil
	default:
		return errors.New(
			"force-carrier must be empty, http3, or direct-awg",
		)
	}
	assemblyRequest := preparation.VerifiedAssemblyRequest{
		Profile:                  "phase1-auto",
		Mode:                     connectivity.ModeAuto,
		CandidateIDs:             assemblyCandidateIDs,
		MinimumUnusedCredentials: preparation.Phase1MinimumUnusedCredentials,
		ReadinessTTL:             connectivity.DefaultReadinessTTL,
		RequiredCarriers:         assemblyRequiredCarriers,
		RequiredWarmCarriers:     assemblyRequiredWarmCarriers,
	}
	candidateIDs := slices.Clone(assemblyRequest.CandidateIDs)
	baseMetadata := measurement.AttemptMetadata{
		SourceDigest:   sourceDigest,
		ArtifactDigest: artifactDigest,
		ManifestDigest: deployment.ManifestDigest,
		Platform:       "linux",
		OSVersion:      *osVersion,
		Device:         *device,
		Readiness:      readinessClass,
		CandidateIDs:   candidateIDs,
		Network:        network,
	}
	appendOperationFailure := func(
		startedAt time.Time,
		failure connectivity.FailureCode,
	) error {
		record, recordErr := measurement.FromOperationFailure(
			connectivity.ModeAuto,
			failure,
			startedAt.UTC(),
			time.Now().UTC(),
			baseMetadata,
		)
		if recordErr != nil {
			return recordErr
		}
		return evidenceLog.Append(record)
	}
	for attemptIndex := 1; attemptIndex <= *attemptCount; attemptIndex++ {
		operationStarted := time.Now()
		directDropsBefore := 0
		if directDropState != nil {
			directDropsBefore = directDropState.count()
		}
		var evidenceStartedAt time.Time
		preparationContext := context.Background()
		cancelOperation := func() {}
		if readinessClass == measurement.ReadinessCold {
			evidenceStartedAt = operationStarted.UTC()
			preparationContext, cancelOperation = context.WithDeadline(
				context.Background(),
				operationStarted.Add(connectivity.MaxDeadline),
			)
		}

		preparationStarted := time.Now()
		var attempt *autoconnect.Attempt
		var prepareErr error
		if readinessClass == measurement.ReadinessCold {
			attempt, prepareErr = autoRuntime.PrepareCold(
				preparationContext, assemblyRequest,
			)
		} else {
			attempt, prepareErr = autoRuntime.Prepare(
				preparationContext, assemblyRequest,
			)
		}
		preparationElapsed := time.Since(preparationStarted)
		if prepareErr != nil {
			failure := connectivity.FailureNotReady
			if errors.Is(prepareErr, context.DeadlineExceeded) ||
				errors.Is(context.Cause(preparationContext),
					context.DeadlineExceeded) {
				failure = connectivity.FailureConnectDeadlineExceeded
			}
			recordErr := appendOperationFailure(
				operationStarted, failure,
			)
			cancelOperation()
			if recordErr != nil {
				return errors.Join(
					fmt.Errorf(
						"attempt %d/%d record production Auto prepare "+
							"failure after %s",
						attemptIndex, *attemptCount, preparationElapsed,
					),
					recordErr,
				)
			}
			fmt.Printf(
				"AUTO_FAILED attempt=%d/%d readiness=%s elapsed=%s "+
					"phase=prepare state=%s failure=%s protocol_version=%s\n",
				attemptIndex,
				*attemptCount,
				readinessClass,
				time.Since(operationStarted),
				connectivity.StateFailed,
				failure,
				connectivity.Version,
			)
			continue
		}
		directDrops := 0
		if directDropState != nil {
			directDrops = directDropState.count() - directDropsBefore
			if directDrops <= 0 {
				cancelOperation()
				return fmt.Errorf(
					"attempt %d/%d diagnostic DirectAWG discard "+
						"did not intercept an outer packet",
					attemptIndex,
					*attemptCount,
				)
			}
		}
		fmt.Printf(
			"AUTO_PREPARED attempt=%d/%d readiness=%s elapsed=%s "+
				"protocol_version=%s manifest=%s direct=%s h3=%s "+
				"anonymous_vault=true rotation_psk=true live_h3=true "+
				"direct_outer_dropped=%d\n",
			attemptIndex,
			*attemptCount,
			readinessClass,
			preparationElapsed,
			connectivity.Version,
			deployment.ManifestDigest,
			*directTransportID,
			*h3TransportID,
			directDrops,
		)
		if commitErr := deployment.CommitTrustState(); commitErr != nil {
			closeContext, cancelClose := context.WithTimeout(
				context.Background(), 12*time.Second,
			)
			closeErr := attempt.Close(closeContext)
			cancelClose()
			recordErr := appendOperationFailure(
				operationStarted,
				connectivity.FailureManifestInvalid,
			)
			cancelOperation()
			return errors.Join(commitErr, closeErr, recordErr)
		}

		clickStarted := time.Now()
		result, connectErr := attempt.Connect(preparationContext)
		clickElapsed := time.Since(clickStarted)
		if connectErr != nil {
			closeContext, cancelClose := context.WithTimeout(
				context.Background(), 12*time.Second,
			)
			closeErr := attempt.Close(closeContext)
			cancelClose()
			failure := connectivity.FailureNotReady
			if errors.Is(connectErr, context.DeadlineExceeded) ||
				errors.Is(context.Cause(preparationContext),
					context.DeadlineExceeded) {
				failure = connectivity.FailureConnectDeadlineExceeded
			}
			if closeErr != nil {
				failure = connectivity.FailureTeardownFailed
			}
			recordErr := appendOperationFailure(
				operationStarted, failure,
			)
			cancelOperation()
			if recordErr != nil || closeErr != nil {
				return errors.Join(
					fmt.Errorf(
						"attempt %d/%d production Auto connect could not "+
							"produce a safe complete denominator after %s",
						attemptIndex, *attemptCount, clickElapsed,
					),
					closeErr,
					recordErr,
				)
			}
			fmt.Printf(
				"AUTO_FAILED attempt=%d/%d readiness=%s elapsed=%s "+
					"click_elapsed=%s phase=connect state=%s failure=%s "+
					"protocol_version=%s\n",
				attemptIndex,
				*attemptCount,
				readinessClass,
				time.Since(operationStarted),
				clickElapsed,
				connectivity.StateFailed,
				failure,
				connectivity.Version,
			)
			fmt.Printf(
				"AUTO_BOUNDED_TEARDOWN_OK attempt=%d/%d\n",
				attemptIndex, *attemptCount,
			)
			continue
		}
		if directClickDelayState != nil {
			if directClickDelayState.count() <= 0 ||
				result.Carrier != connectivity.CarrierHTTP3 {
				closeContext, cancelClose := context.WithTimeout(
					context.Background(), 12*time.Second,
				)
				closeErr := attempt.Close(closeContext)
				cancelClose()
				cancelOperation()
				return errors.Join(
					errors.New(
						"diagnostic warm race did not select H3 "+
							"against delayed DirectAWG",
					),
					closeErr,
				)
			}
			fmt.Printf(
				"AUTO_H3_FORCED attempt=%d/%d direct_click_delay=%s\n",
				attemptIndex,
				*attemptCount,
				*directClickDelay,
			)
		}

		var healthErr error
		var healthStatus connectivity.Result
		if *hold > 0 {
			timer := time.NewTimer(*hold)
			<-timer.C
			status := attempt.Status()
			if !status.Success() {
				healthStatus = status
				healthErr = fmt.Errorf(
					"production Auto health failed during hold: %+v",
					status,
				)
			} else {
				fmt.Printf(
					"AUTO_HEALTH_HOLD_OK attempt=%d/%d "+
						"duration=%s candidate=%s carrier=%s\n",
					attemptIndex,
					*attemptCount,
					*hold,
					status.CandidateID,
					status.Carrier,
				)
			}
		}
		closeContext, cancelClose := context.WithTimeout(
			context.Background(), 12*time.Second,
		)
		closeErr := attempt.Close(closeContext)
		cancelClose()
		cancelOperation()

		evidenceResult := result
		if healthErr != nil {
			if !healthStatus.Success() &&
				!healthStatus.StartedAt.IsZero() &&
				!healthStatus.FinishedAt.IsZero() {
				evidenceResult = healthStatus
			} else {
				evidenceResult.State = connectivity.StateFailed
				evidenceResult.Failure =
					connectivity.FailurePostCommitHealth
				evidenceResult.FinishedAt = time.Now().UTC()
				evidenceResult.Timings.Outcome =
					evidenceResult.FinishedAt.Sub(
						evidenceResult.StartedAt,
					)
			}
		}
		if closeErr != nil {
			evidenceResult.State = connectivity.StateFailed
			evidenceResult.Failure = connectivity.FailureTeardownFailed
			evidenceResult.FinishedAt = time.Now().UTC()
			evidenceResult.Timings.Outcome =
				evidenceResult.FinishedAt.Sub(
					evidenceResult.StartedAt,
				)
		}
		metadata := baseMetadata
		metadata.EvidenceStartedAt = evidenceStartedAt
		record, recordErr := measurement.FromConnectivityResult(
			evidenceResult,
			metadata,
		)
		if recordErr != nil {
			return errors.Join(recordErr, healthErr, closeErr)
		}
		if appendErr := evidenceLog.Append(record); appendErr != nil {
			return errors.Join(appendErr, healthErr, closeErr)
		}
		if closeErr != nil {
			return errors.Join(healthErr, closeErr)
		}

		scoredElapsed := time.Duration(record.Timeline.OutcomeMicros) *
			time.Microsecond
		if evidenceResult.Success() &&
			evidenceResult.Predicates.Verified() &&
			scoredElapsed <= connectivity.MaxDeadline {
			fmt.Printf(
				"AUTO_ONLINE attempt=%d/%d readiness=%s elapsed=%s "+
					"click_elapsed=%s budget=%s protocol_version=%s "+
					"candidate=%s carrier=%s fresh_awg=true "+
					"bidirectional=true protected_dns=true canary=true\n",
				attemptIndex,
				*attemptCount,
				readinessClass,
				scoredElapsed,
				clickElapsed,
				connectivity.MaxDeadline,
				connectivity.Version,
				evidenceResult.CandidateID,
				evidenceResult.Carrier,
			)
		} else {
			fmt.Printf(
				"AUTO_FAILED attempt=%d/%d readiness=%s elapsed=%s "+
					"click_elapsed=%s state=%s failure=%s candidate=%s\n",
				attemptIndex,
				*attemptCount,
				readinessClass,
				scoredElapsed,
				clickElapsed,
				evidenceResult.State,
				evidenceResult.Failure,
				evidenceResult.CandidateID,
			)
		}
		fmt.Printf(
			"AUTO_BOUNDED_TEARDOWN_OK attempt=%d/%d\n",
			attemptIndex, *attemptCount,
		)
	}
	summary := evidenceLog.Summary()
	fmt.Printf(
		"AUTO_BATCH_SUMMARY requested=%d readiness=%s "+
			"log_total=%d log_success=%d log_failure=%d "+
			"p50=%s p95=%s p99=%s\n",
		*attemptCount,
		readinessClass,
		summary.Total,
		summary.Successes,
		summary.Failures,
		summary.OutcomeP50,
		summary.OutcomeP95,
		summary.OutcomeP99,
	)
	return nil
}

func parseReadinessClass(value string) (measurement.ReadinessClass, error) {
	switch measurement.ReadinessClass(value) {
	case measurement.ReadinessWarm:
		return measurement.ReadinessWarm, nil
	case measurement.ReadinessCold:
		return measurement.ReadinessCold, nil
	default:
		return "", errors.New("readiness must be warm or cold")
	}
}

type initialOuterDropState struct {
	mu      sync.Mutex
	dropped int
}

func (state *initialOuterDropState) count() int {
	if state == nil {
		return 0
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.dropped
}

type initialOuterDropDialer struct {
	next     directawg.RemoteDialer
	duration time.Duration
	state    *initialOuterDropState
}

func (dialer initialOuterDropDialer) Dial(
	ctx context.Context,
	endpoint string,
) (net.PacketConn, error) {
	connection, err := dialer.next.Dial(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	return &initialOuterDropPacketConn{
		PacketConn: connection,
		duration:   dialer.duration,
		state:      dialer.state,
	}, nil
}

type initialOuterDropPacketConn struct {
	net.PacketConn
	duration time.Duration
	state    *initialOuterDropState

	mu        sync.Mutex
	startedAt time.Time
}

func (connection *initialOuterDropPacketConn) WriteTo(
	packet []byte,
	address net.Addr,
) (int, error) {
	if connection.state == nil {
		return 0, errors.New("initial outer discard state is missing")
	}
	connection.mu.Lock()
	now := time.Now()
	if connection.startedAt.IsZero() {
		connection.startedAt = now
	}
	drop := now.Before(
		connection.startedAt.Add(connection.duration),
	)
	connection.mu.Unlock()
	if drop {
		connection.state.mu.Lock()
		connection.state.dropped++
		connection.state.mu.Unlock()
	}
	if drop {
		return len(packet), nil
	}
	if address == nil {
		if writer, ok := connection.PacketConn.(interface {
			Write([]byte) (int, error)
		}); ok {
			return writer.Write(packet)
		}
	}
	return connection.PacketConn.WriteTo(packet, address)
}

type delayedDirectDialState struct {
	mu     sync.Mutex
	starts int
}

func (state *delayedDirectDialState) count() int {
	if state == nil {
		return 0
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.starts
}

type delayedDirectDialer struct {
	next  directawg.RemoteDialer
	delay time.Duration
	state *delayedDirectDialState
}

func (dialer delayedDirectDialer) Dial(
	ctx context.Context,
	endpoint string,
) (net.PacketConn, error) {
	if dialer.state == nil {
		return nil, errors.New("delayed DirectAWG dial state is missing")
	}
	dialer.state.mu.Lock()
	dialer.state.starts++
	dialer.state.mu.Unlock()
	timer := time.NewTimer(dialer.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-timer.C:
		return dialer.next.Dial(ctx, endpoint)
	}
}

func collectBundlePaths(
	explicit []string,
	directory string,
) ([]string, error) {
	paths := slices.Clone(explicit)
	if directory != "" {
		info, err := os.Lstat(directory)
		if err != nil {
			return nil, fmt.Errorf(
				"inspect privacy-token bundle directory: %w", err,
			)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New(
				"privacy-token bundle directory is not a real directory",
			)
		}
		entries, err := os.ReadDir(directory)
		if err != nil {
			return nil, fmt.Errorf(
				"read privacy-token bundle directory: %w", err,
			)
		}
		for _, entry := range entries {
			if entry.IsDir() ||
				!strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			entryInfo, err := entry.Info()
			if err != nil {
				return nil, fmt.Errorf(
					"inspect privacy-token bundle %s: %w",
					entry.Name(), err,
				)
			}
			if !entryInfo.Mode().IsRegular() {
				return nil, fmt.Errorf(
					"privacy-token bundle %s is not a regular file",
					entry.Name(),
				)
			}
			paths = append(paths, filepath.Join(directory, entry.Name()))
		}
	}
	slices.Sort(paths)
	unique := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		cleaned := filepath.Clean(path)
		if _, duplicate := seen[cleaned]; duplicate {
			return nil, fmt.Errorf(
				"privacy-token bundle path is duplicated: %s", cleaned,
			)
		}
		seen[cleaned] = struct{}{}
		unique = append(unique, cleaned)
	}
	return unique, nil
}

func validateMeasurementMetadata(
	osVersion string,
	device string,
	network measurement.NetworkProfile,
) error {
	if osVersion == "" || len(osVersion) > 128 ||
		device == "" || len(device) > 128 {
		return errors.New(
			"measurement OS version and device are required",
		)
	}
	switch network.Interface {
	case "ethernet", "wifi", "cellular", "loopback", "synthetic":
	default:
		return errors.New("measurement network interface is invalid")
	}
	switch network.IPFamily {
	case "ipv4", "ipv6", "dual", "nat64":
	default:
		return errors.New("measurement IP family is invalid")
	}
	for _, value := range []float64{
		network.RTTMillis,
		network.LossFraction,
		network.CapacityMbps,
	} {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return errors.New(
				"measurement network values must be finite",
			)
		}
	}
	if network.RTTMillis < 0 || network.RTTMillis > 60_000 ||
		network.LossFraction < 0 || network.LossFraction > 1 ||
		network.CapacityMbps < 0 {
		return errors.New("measurement network values are invalid")
	}
	return nil
}

func openOrCreateMeasurementLog(
	path string,
	keyPath string,
) (*measurement.Log, error) {
	_, logErr := os.Lstat(path)
	_, keyErr := os.Lstat(keyPath)
	logExists := logErr == nil
	keyExists := keyErr == nil
	if logErr != nil && !errors.Is(logErr, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect measurement log: %w", logErr)
	}
	if keyErr != nil && !errors.Is(keyErr, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect measurement key: %w", keyErr)
	}
	if logExists && !keyExists {
		return nil, errors.New(
			"existing measurement log lacks its HMAC key",
		)
	}
	if !keyExists {
		key := make([]byte, sha256.Size)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate measurement key: %w", err)
		}
		defer clear(key)
		if err := securefile.AtomicWrite(keyPath, key, 0o600); err != nil {
			return nil, fmt.Errorf("write measurement key: %w", err)
		}
	}
	if logExists {
		log, err := measurement.Open(path, keyPath)
		if err != nil {
			return nil, fmt.Errorf("open measurement log: %w", err)
		}
		return log, nil
	}
	log, err := measurement.Create(path, keyPath)
	if err != nil {
		return nil, fmt.Errorf("create measurement log: %w", err)
	}
	return log, nil
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

func manifestTokenKey(
	manifest gatewaymanifest.ManifestV2,
	id string,
) (gatewaymanifest.PrivacyTokenKey, error) {
	for _, key := range manifest.PrivacyTokenKeys {
		if key.ID == id {
			return key, nil
		}
	}
	return gatewaymanifest.PrivacyTokenKey{},
		errors.New("selected H3 privacy-token key is absent")
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

func parseMark(text string) (uint32, error) {
	value, err := strconv.ParseUint(text, 16, 32)
	if err != nil || value == 0 {
		return 0, errors.New("mark must be nonzero hexadecimal")
	}
	return uint32(value), nil
}

func lowerHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, current := range value {
		if (current < '0' || current > '9') &&
			(current < 'a' || current > 'f') {
			return false
		}
	}
	return true
}

// systemd-resolved in the root namespace cannot configure a link index that
// exists only inside the disposable client namespace. The runner records only
// resolver staging calls; the signed DNS probe itself remains a real marked
// socket through the candidate AWG interface.
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
			command.Path,
			strings.Join(command.Args, " "),
			err,
			stderr.String(),
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

var _ directawg.LinuxCommandRunner = (*realCommandRunner)(nil)
