package directawg

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
)

const (
	DefaultLinuxAWGGoBinary = "/opt/winn-lab/bin/amneziawg-go"
	DefaultLinuxAWGBinary   = "/opt/winn-lab/bin/awg"
	DefaultLinuxIPBinary    = "/usr/sbin/ip"

	defaultLinuxStartupPoll = 10 * time.Millisecond
	defaultLinuxStopTimeout = 3 * time.Second
)

var ErrLinuxControllerUnsupported = errors.New(
	"direct AWG Linux tunnel controller is unsupported on this platform",
)

type LinuxKeyMaterial struct {
	Generation uint64
	PrivateKey []byte
	PSK        []byte
}

// LinuxKeyMaterialProvider returns uniquely owned key buffers. Prepare clears
// both buffers immediately after writing private mode-0600 files. Providers
// must bind the returned material to Binding.PSKGeneration.
type LinuxKeyMaterialProvider interface {
	KeyMaterial(context.Context, connectivity.Binding) (LinuxKeyMaterial, error)
}

type AWGObfuscation struct {
	JC   uint16
	JMin uint16
	JMax uint16
	S1   uint16
	S2   uint16
	S3   uint16
	S4   uint16
	H1   uint32
	H2   uint32
	H3   uint32
	H4   uint32
}

// LinuxSignedInterfaceConfig contains values copied from a verified signed
// deployment configuration. A caller must not populate it from unsigned local
// flags in production. ListenPortMin and ListenPortMax define an inclusive
// non-privileged lease range; each concurrent candidate receives a distinct
// port derived from its identity, with deterministic collision probing.
type LinuxSignedInterfaceConfig struct {
	InnerAddressPool    netip.Prefix
	AllowedIPs          []netip.Prefix
	VerificationRoutes  []netip.Prefix
	MTU                 int
	ListenPortMin       uint16
	ListenPortMax       uint16
	PersistentKeepalive uint16
	Obfuscation         AWGObfuscation
}

type LinuxProbeContext struct {
	Binding            connectivity.Binding
	InterfaceName      string
	InnerAddress       netip.Prefix
	FirewallMark       uint32
	VerificationRoutes []netip.Prefix
}

// LinuxProtectedVerifier must bind all sockets to InterfaceName and
// FirewallMark. It must never fall back to the host resolver or an unmarked
// socket.
type LinuxProtectedVerifier interface {
	VerifyProtectedDNS(context.Context, LinuxProbeContext) error
	VerifyTunnelCanary(context.Context, LinuxProbeContext) error
}

type LinuxPolicySpec struct {
	Binding       connectivity.Binding
	InterfaceName string
	InnerAddress  netip.Prefix
	RouteTable    uint32
	FirewallMark  uint32
}

// LinuxPolicyFactory prepares candidate-specific DNS and kill-switch state.
// Prepare must leave the kill switch engaged. Commit may release it only after
// the route transaction is active. Rollback must synchronously engage or
// preserve it before restoring DNS. Prepare implementations must also undo
// their own partial side effects before returning an error.
//
// UnderlayMark returns the fixed mark this factory admits into its shared
// nftables underlay-bypass rule. The controller must apply this exact mark to
// the AWG daemon's own socket (via "awg set <if> fwmark <mark>"): it is a
// factory-wide constant shared by every candidate's daemon process, distinct
// from each candidate's own per-attempt LinuxPolicySpec.FirewallMark used for
// probe-routing table selection. Without this, the daemon's re-encapsulated
// UDP traffic carries no mark, never matches "meta mark @underlay_marks", and
// is silently dropped by the fail-closed OUTPUT policy once it is installed.
type LinuxPolicyFactory interface {
	Prepare(context.Context, LinuxPolicySpec) (LinuxPolicyTransaction, error)
	UnderlayMark() uint32
}

type LinuxPolicyTransaction interface {
	Commit(context.Context) error
	Rollback(context.Context) error
	Health() <-chan error
}

type LinuxCommand struct {
	Path string
	Args []string
}

type LinuxCommandResult struct {
	Stdout []byte
	Stderr []byte
}

type LinuxManagedProcess interface {
	Exited() <-chan struct{}
	Err() error
	Stop(context.Context) error
}

type LinuxCommandRunner interface {
	Run(context.Context, LinuxCommand) (LinuxCommandResult, error)
	Start(LinuxCommand) (LinuxManagedProcess, error)
}

type LinuxControllerConfig struct {
	AWGGoBinary string
	AWGBinary   string
	IPBinary    string
	TempRoot    string

	Signed        LinuxSignedInterfaceConfig
	KeyProvider   LinuxKeyMaterialProvider
	Verifier      LinuxProtectedVerifier
	PolicyFactory LinuxPolicyFactory
	Runner        LinuxCommandRunner

	StartupPollInterval time.Duration
	StopTimeout         time.Duration

	// ListenPortAvailable is an optional test seam. Production uses a real
	// dual-stack UDP bind probe so a signed port that is already owned by an
	// unrelated or recently active socket is skipped before AWG setup.
	ListenPortAvailable func(uint16) bool
}

type linuxController struct {
	config LinuxControllerConfig

	portMu      sync.Mutex
	leasedPorts map[uint16]struct{}

	addressMu       sync.Mutex
	leasedAddresses map[netip.Addr]struct{}
}

// newLinuxController is platform-neutral so the command lifecycle can be
// tested with a fake runner. NewLinuxController is build-tag gated.
func newLinuxController(config LinuxControllerConfig) (*linuxController, error) {
	if config.AWGGoBinary == "" {
		config.AWGGoBinary = DefaultLinuxAWGGoBinary
	}
	if config.AWGBinary == "" {
		config.AWGBinary = DefaultLinuxAWGBinary
	}
	if config.IPBinary == "" {
		config.IPBinary = DefaultLinuxIPBinary
	}
	for name, path := range map[string]string{
		"amneziawg-go": config.AWGGoBinary,
		"awg":          config.AWGBinary,
		"ip":           config.IPBinary,
	} {
		if err := validateLinuxExecutable(path); err != nil {
			return nil, fmt.Errorf("%s executable: %w", name, err)
		}
	}
	if config.TempRoot != "" {
		if !filepath.IsAbs(config.TempRoot) {
			return nil, errors.New("linux AWG temporary root must be absolute")
		}
		info, err := os.Lstat(config.TempRoot)
		if err != nil {
			return nil, fmt.Errorf("inspect Linux AWG temporary root: %w", err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New(
				"linux AWG temporary root must be a real directory",
			)
		}
	}
	if config.KeyProvider == nil || config.Verifier == nil ||
		config.PolicyFactory == nil {
		return nil, errors.New(
			"linux AWG key provider, verifier, and policy factory are required",
		)
	}
	if err := validateLinuxSignedConfig(config.Signed); err != nil {
		return nil, err
	}
	config.Signed.AllowedIPs = slices.Clone(config.Signed.AllowedIPs)
	config.Signed.VerificationRoutes = slices.Clone(
		config.Signed.VerificationRoutes,
	)
	if config.Runner == nil {
		config.Runner = newExecLinuxRunner()
	}
	if config.StartupPollInterval == 0 {
		config.StartupPollInterval = defaultLinuxStartupPoll
	}
	if config.StartupPollInterval < time.Millisecond ||
		config.StartupPollInterval > 250*time.Millisecond {
		return nil, errors.New("linux AWG startup poll interval is invalid")
	}
	if config.StopTimeout == 0 {
		config.StopTimeout = defaultLinuxStopTimeout
	}
	if config.StopTimeout < 100*time.Millisecond ||
		config.StopTimeout > 30*time.Second {
		return nil, errors.New("linux AWG stop timeout is invalid")
	}
	if config.ListenPortAvailable == nil {
		config.ListenPortAvailable = linuxListenPortAvailable
	}
	return &linuxController{
		config:          config,
		leasedPorts:     make(map[uint16]struct{}),
		leasedAddresses: make(map[netip.Addr]struct{}),
	}, nil
}

func (controller *linuxController) Prepare(
	ctx context.Context,
	preparation Preparation,
) (_ PreparedTunnel, resultErr error) {
	if ctx == nil {
		return PreparedTunnel{}, errors.New(
			"linux AWG prepare context is required",
		)
	}
	now := time.Now().UTC()
	if err := preparation.Binding.Validate(now); err != nil {
		return PreparedTunnel{}, fmt.Errorf("linux AWG binding: %w", err)
	}
	if err := validateLoopbackEndpoint(preparation.RelayEndpoint); err != nil {
		return PreparedTunnel{}, fmt.Errorf("linux AWG relay endpoint: %w", err)
	}
	if err := validateIPLiteralEndpoint(
		preparation.GatewayEndpoint, false,
	); err != nil {
		return PreparedTunnel{}, fmt.Errorf("linux AWG gateway endpoint: %w", err)
	}
	if err := validatePublicKey(preparation.GatewayPublicKey); err != nil {
		return PreparedTunnel{}, err
	}
	if controller.config.Signed.MTU < preparation.MinInnerDatagram ||
		controller.config.Signed.MTU > preparation.MaxInnerDatagram {
		return PreparedTunnel{}, errors.New(
			"linux AWG signed MTU differs from candidate limits",
		)
	}

	material, err := controller.config.KeyProvider.KeyMaterial(
		ctx, preparation.Binding,
	)
	if err != nil {
		return PreparedTunnel{}, fmt.Errorf(
			"obtain Linux AWG key material: %w", err,
		)
	}
	defer clearLinuxKeyMaterial(&material)
	if material.Generation != preparation.Binding.PSKGeneration {
		return PreparedTunnel{}, errors.New(
			"linux AWG key material generation mismatch",
		)
	}
	if len(material.PrivateKey) != 32 || len(material.PSK) != 32 {
		return PreparedTunnel{}, errors.New(
			"linux AWG private key and PSK must be exactly 32 bytes",
		)
	}
	if linuxKeyIsZero(material.PrivateKey) ||
		linuxKeyIsZero(material.PSK) {
		return PreparedTunnel{}, errors.New(
			"linux AWG private key and PSK must be nonzero",
		)
	}
	pskDigest := sha256.Sum256(material.PSK)

	identity := deriveLinuxCandidateIdentity(
		preparation.Binding, controller.config.Signed.InnerAddressPool,
	)
	innerAddress, releaseInnerAddress, err :=
		controller.reserveInnerAddress(identity)
	if err != nil {
		return PreparedTunnel{}, err
	}
	identity.InnerAddress = innerAddress
	innerAddressOwned := true
	defer func() {
		if innerAddressOwned {
			releaseInnerAddress()
		}
	}()
	listenPort, releaseListenPort, err := controller.reserveListenPort(
		identity,
	)
	if err != nil {
		return PreparedTunnel{}, err
	}
	listenPortOwned := true
	defer func() {
		if listenPortOwned {
			releaseListenPort()
		}
	}()
	secretDir, err := os.MkdirTemp(
		controller.config.TempRoot, "winn-directawg-*",
	)
	if err != nil {
		return PreparedTunnel{}, fmt.Errorf(
			"create Linux AWG secret directory: %w", err,
		)
	}
	// #nosec G302 -- this is a directory; 0700 is the intended private mode.
	if err := os.Chmod(secretDir, 0o700); err != nil {
		_ = removeLinuxSecretFiles(secretDir)
		return PreparedTunnel{}, fmt.Errorf(
			"secure Linux AWG secret directory: %w", err,
		)
	}
	privatePath := filepath.Join(secretDir, "private-key")
	pskPath := filepath.Join(secretDir, "preshared-key")
	removeSecrets := func() error {
		return removeLinuxSecretFiles(
			privatePath, pskPath, secretDir,
		)
	}
	secretsPending := true
	defer func() {
		if !secretsPending {
			return
		}
		if err := removeSecrets(); err != nil {
			resultErr = errors.Join(
				resultErr,
				fmt.Errorf("remove Linux AWG secret files: %w", err),
			)
		}
	}()
	if err := writeLinuxKeyFile(privatePath, material.PrivateKey); err != nil {
		return PreparedTunnel{}, err
	}
	if err := writeLinuxKeyFile(pskPath, material.PSK); err != nil {
		return PreparedTunnel{}, err
	}
	clearLinuxKeyMaterial(&material)

	process, err := controller.config.Runner.Start(LinuxCommand{
		Path: controller.config.AWGGoBinary,
		Args: []string{"-f", identity.InterfaceName},
	})
	if err != nil {
		return PreparedTunnel{}, fmt.Errorf(
			"start Linux amneziawg-go: %w", err,
		)
	}
	cleanupProcess := true
	cleanup := func() error {
		cleanupContext, cancel := context.WithTimeout(
			context.Background(), controller.config.StopTimeout,
		)
		defer cancel()
		_, linkError := controller.config.Runner.Run(
			cleanupContext,
			LinuxCommand{
				Path: controller.config.IPBinary,
				Args: []string{
					"link", "delete", "dev", identity.InterfaceName,
				},
			},
		)
		processError := process.Stop(cleanupContext)
		return errors.Join(linkError, processError)
	}
	defer func() {
		if cleanupProcess {
			if err := cleanup(); err != nil {
				resultErr = errors.Join(
					resultErr,
					fmt.Errorf("clean up Linux AWG process: %w", err),
				)
			}
		}
	}()
	if err := controller.waitForInterface(
		ctx, process, identity.InterfaceName,
	); err != nil {
		return PreparedTunnel{}, err
	}
	if err := controller.configureAWG(
		ctx,
		identity.InterfaceName,
		listenPort,
		controller.config.PolicyFactory.UnderlayMark(),
		preparation,
		privatePath,
		pskPath,
	); err != nil {
		return PreparedTunnel{}, err
	}
	if err := removeSecrets(); err != nil {
		return PreparedTunnel{}, fmt.Errorf(
			"remove Linux AWG secret files: %w", err,
		)
	}
	secretsPending = false
	if err := controller.verifyListenPort(
		ctx, identity.InterfaceName, listenPort,
	); err != nil {
		return PreparedTunnel{}, err
	}

	statusSource, err := NewCLIStatusSource(
		controller.config.AWGBinary,
		identity.InterfaceName,
		preparation.GatewayPublicKey,
	)
	if err != nil {
		return PreparedTunnel{}, err
	}
	statusSource.run = controller.runStatusCommand
	baseline, err := statusSource.Status(ctx)
	if err != nil {
		return PreparedTunnel{}, fmt.Errorf(
			"read Linux AWG baseline status: %w", err,
		)
	}
	if !baseline.LatestHandshake.IsZero() ||
		baseline.RxBytes != 0 || baseline.TxBytes != 0 {
		return PreparedTunnel{}, errors.New(
			"linux AWG interface did not start with a zero peer baseline",
		)
	}
	// Capture the fresh-peer baseline before activating the link. An IPv6
	// address starts duplicate-address detection when the link comes up. With
	// ::/0 assigned to the peer, that kernel-generated multicast packet can
	// legitimately trigger the first handshake and counters before a
	// post-activation status read. The down interface is still fully
	// configured, so its peer identity, endpoint, and zero counters remain
	// observable without creating network traffic.
	if err := controller.configureLink(
		ctx, identity.InterfaceName, identity.InnerAddress,
	); err != nil {
		return PreparedTunnel{}, err
	}
	if err := controller.enablePersistentKeepalive(
		ctx, identity.InterfaceName, preparation.GatewayPublicKey,
	); err != nil {
		return PreparedTunnel{}, err
	}

	route, err := newLinuxRouteTransaction(
		ctx,
		controller.config.Runner,
		controller.config.IPBinary,
		identity,
		controller.config.Signed.AllowedIPs,
		controller.config.StopTimeout,
	)
	if err != nil {
		return PreparedTunnel{}, err
	}
	cleanupRoute := true
	defer func() {
		if cleanupRoute {
			cleanupContext, cancel := context.WithTimeout(
				context.Background(), controller.config.StopTimeout,
			)
			defer cancel()
			if err := route.Rollback(cleanupContext); err != nil {
				resultErr = errors.Join(
					resultErr,
					fmt.Errorf("roll back Linux AWG routes: %w", err),
				)
			}
		}
	}()
	policy, err := controller.config.PolicyFactory.Prepare(
		ctx,
		LinuxPolicySpec{
			Binding:       preparation.Binding,
			InterfaceName: identity.InterfaceName,
			InnerAddress:  identity.InnerAddress,
			RouteTable:    identity.RouteTable,
			FirewallMark:  identity.FirewallMark,
		},
	)
	if err != nil {
		return PreparedTunnel{}, fmt.Errorf(
			"prepare Linux AWG DNS/kill-switch policy: %w", err,
		)
	}
	if policy == nil || policy.Health() == nil {
		if policy != nil {
			cleanupContext, cancel := context.WithTimeout(
				context.Background(), controller.config.StopTimeout,
			)
			defer cancel()
			if err := policy.Rollback(cleanupContext); err != nil {
				return PreparedTunnel{}, errors.Join(
					errors.New(
						"linux AWG policy transaction or health stream is missing",
					),
					fmt.Errorf(
						"roll back Linux AWG DNS/kill-switch policy: %w",
						err,
					),
				)
			}
		}
		return PreparedTunnel{}, errors.New(
			"linux AWG policy transaction or health stream is missing",
		)
	}

	session := newLinuxTunnelSession(linuxTunnelSessionConfig{
		binding:  preparation.Binding,
		status:   statusSource,
		verifier: controller.config.Verifier,
		probe: LinuxProbeContext{
			Binding:       preparation.Binding,
			InterfaceName: identity.InterfaceName,
			InnerAddress:  identity.InnerAddress,
			FirewallMark:  identity.FirewallMark,
			VerificationRoutes: slices.Clone(
				controller.config.Signed.VerificationRoutes,
			),
		},
		route:         route,
		policy:        policy,
		process:       process,
		runner:        controller.config.Runner,
		ipBinary:      controller.config.IPBinary,
		interfaceName: identity.InterfaceName,
		stopTimeout:   controller.config.StopTimeout,
		refreshHandshake: func(refreshContext context.Context) error {
			return controller.refreshAWGHandshake(
				refreshContext,
				preparation,
				identity.InterfaceName,
				pskDigest,
			)
		},
		releasePort:    releaseListenPort,
		releaseAddress: releaseInnerAddress,
	})
	cleanupRoute = false
	cleanupProcess = false
	listenPortOwned = false
	innerAddressOwned = false
	relayHost, _, _ := net.SplitHostPort(preparation.RelayEndpoint)
	return PreparedTunnel{
		Session:  session,
		Baseline: baseline,
		LocalSourceEndpoint: net.JoinHostPort(
			relayHost,
			strconv.Itoa(int(listenPort)),
		),
	}, nil
}

func (controller *linuxController) waitForInterface(
	ctx context.Context,
	process LinuxManagedProcess,
	interfaceName string,
) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-process.Exited():
			return fmt.Errorf(
				"interface readiness: %w",
				linuxProcessExitError(process),
			)
		case <-timer.C:
			if _, err := controller.config.Runner.Run(
				ctx,
				LinuxCommand{
					Path: controller.config.IPBinary,
					Args: []string{
						"link", "show", "dev", interfaceName,
					},
				},
			); err == nil {
				return nil
			}
			timer.Reset(controller.config.StartupPollInterval)
		}
	}
}

func (controller *linuxController) configureAWG(
	ctx context.Context,
	interfaceName string,
	listenPort uint16,
	firewallMark uint32,
	preparation Preparation,
	privatePath string,
	pskPath string,
) error {
	obfuscation := controller.config.Signed.Obfuscation
	_, err := controller.config.Runner.Run(
		ctx,
		LinuxCommand{
			Path: controller.config.AWGBinary,
			Args: []string{
				"set", interfaceName,
				"private-key", privatePath,
				"listen-port", strconv.Itoa(
					int(listenPort),
				),
				"fwmark", fmt.Sprintf("0x%x", firewallMark),
				"jc", strconv.Itoa(int(obfuscation.JC)),
				"jmin", strconv.Itoa(int(obfuscation.JMin)),
				"jmax", strconv.Itoa(int(obfuscation.JMax)),
				"s1", strconv.Itoa(int(obfuscation.S1)),
				"s2", strconv.Itoa(int(obfuscation.S2)),
				"s3", strconv.Itoa(int(obfuscation.S3)),
				"s4", strconv.Itoa(int(obfuscation.S4)),
				"h1", strconv.FormatUint(uint64(obfuscation.H1), 10),
				"h2", strconv.FormatUint(uint64(obfuscation.H2), 10),
				"h3", strconv.FormatUint(uint64(obfuscation.H3), 10),
				"h4", strconv.FormatUint(uint64(obfuscation.H4), 10),
			},
		},
	)
	if err != nil {
		return fmt.Errorf("configure Linux AWG interface: %w", err)
	}
	allowed := make([]string, 0, len(controller.config.Signed.AllowedIPs))
	for _, prefix := range controller.config.Signed.AllowedIPs {
		allowed = append(allowed, prefix.String())
	}
	// persistent-keepalive is deliberately not set here: with a valid peer
	// and endpoint already configured, a nonzero keepalive can make the
	// daemon eagerly initiate a handshake as soon as the interface comes up,
	// before the caller's post-configureLink zero-baseline check runs. Over
	// a very low-latency path that handshake can complete within the same
	// few milliseconds, which would make the zero-baseline check fail even
	// though nothing is actually wrong. enablePersistentKeepalive applies it
	// afterward, once the zero baseline has already been observed.
	peerArgs := []string{
		"set", interfaceName,
		"peer", preparation.GatewayPublicKey,
		"preshared-key", pskPath,
		"endpoint", preparation.RelayEndpoint,
		"allowed-ips", strings.Join(allowed, ","),
	}
	if _, err := controller.config.Runner.Run(
		ctx,
		LinuxCommand{Path: controller.config.AWGBinary, Args: peerArgs},
	); err != nil {
		return fmt.Errorf("configure Linux AWG peer: %w", err)
	}
	return nil
}

// enablePersistentKeepalive applies the signed keepalive interval to the
// already-configured peer. Callers must invoke this only after observing a
// zero baseline: see the comment in configureAWG for why keepalive cannot be
// set at initial peer configuration time.
func (controller *linuxController) enablePersistentKeepalive(
	ctx context.Context,
	interfaceName string,
	gatewayPublicKey string,
) error {
	if controller.config.Signed.PersistentKeepalive == 0 {
		return nil
	}
	if _, err := controller.config.Runner.Run(
		ctx,
		LinuxCommand{
			Path: controller.config.AWGBinary,
			Args: []string{
				"set", interfaceName,
				"peer", gatewayPublicKey,
				"persistent-keepalive",
				strconv.Itoa(int(controller.config.Signed.PersistentKeepalive)),
			},
		},
	); err != nil {
		return fmt.Errorf("enable Linux AWG persistent keepalive: %w", err)
	}
	return nil
}

// refreshAWGHandshake replaces only the exact existing peer so amneziawg-go
// starts it with a fresh initial-handshake timer. It reacquires and checks the
// same PSK generation, exposes the PSK only through a private short-lived file,
// and does not create a second interface, socket, process, or route.
func (controller *linuxController) refreshAWGHandshake(
	ctx context.Context,
	preparation Preparation,
	interfaceName string,
	expectedPSKDigest [sha256.Size]byte,
) (resultErr error) {
	if ctx == nil {
		return errors.New("linux AWG handshake refresh context is required")
	}
	if err := preparation.Binding.Validate(time.Now().UTC()); err != nil {
		return fmt.Errorf("refresh Linux AWG binding: %w", err)
	}
	material, err := controller.config.KeyProvider.KeyMaterial(
		ctx, preparation.Binding,
	)
	if err != nil {
		return fmt.Errorf("reacquire Linux AWG key material: %w", err)
	}
	defer clearLinuxKeyMaterial(&material)
	if material.Generation != preparation.Binding.PSKGeneration ||
		len(material.PrivateKey) != 32 ||
		len(material.PSK) != 32 ||
		linuxKeyIsZero(material.PrivateKey) ||
		linuxKeyIsZero(material.PSK) ||
		sha256.Sum256(material.PSK) != expectedPSKDigest {
		return errors.New(
			"refreshed Linux AWG key material differs from the prepared peer",
		)
	}

	secretDir, err := os.MkdirTemp(
		controller.config.TempRoot, "winn-directawg-refresh-*",
	)
	if err != nil {
		return fmt.Errorf("create Linux AWG refresh secret directory: %w", err)
	}
	// #nosec G302 -- this is a directory; 0700 is the intended private mode.
	if err := os.Chmod(secretDir, 0o700); err != nil {
		_ = removeLinuxSecretFiles(secretDir)
		return fmt.Errorf("secure Linux AWG refresh secret directory: %w", err)
	}
	pskPath := filepath.Join(secretDir, "preshared-key")
	removeSecrets := func() error {
		return removeLinuxSecretFiles(pskPath, secretDir)
	}
	defer func() {
		if cleanupErr := removeSecrets(); cleanupErr != nil {
			resultErr = errors.Join(
				resultErr,
				fmt.Errorf(
					"remove Linux AWG refresh secret files: %w",
					cleanupErr,
				),
			)
		}
	}()
	if err := writeLinuxKeyFile(pskPath, material.PSK); err != nil {
		return err
	}
	clearLinuxKeyMaterial(&material)

	if _, err := controller.config.Runner.Run(
		ctx,
		LinuxCommand{
			Path: controller.config.AWGBinary,
			Args: []string{
				"set", interfaceName,
				"peer", preparation.GatewayPublicKey,
				"remove",
			},
		},
	); err != nil {
		return fmt.Errorf("remove stale Linux AWG peer for refresh: %w", err)
	}
	allowed := make(
		[]string, 0, len(controller.config.Signed.AllowedIPs),
	)
	for _, prefix := range controller.config.Signed.AllowedIPs {
		allowed = append(allowed, prefix.String())
	}
	peerArgs := []string{
		"set", interfaceName,
		"peer", preparation.GatewayPublicKey,
		"preshared-key", pskPath,
		"endpoint", preparation.RelayEndpoint,
		"allowed-ips", strings.Join(allowed, ","),
	}
	if keepalive := controller.config.Signed.PersistentKeepalive; keepalive > 0 {
		peerArgs = append(
			peerArgs,
			"persistent-keepalive",
			strconv.Itoa(int(keepalive)),
		)
	}
	if _, err := controller.config.Runner.Run(
		ctx,
		LinuxCommand{
			Path: controller.config.AWGBinary,
			Args: peerArgs,
		},
	); err != nil {
		return fmt.Errorf("re-add exact Linux AWG peer for refresh: %w", err)
	}
	return nil
}

func (controller *linuxController) verifyListenPort(
	ctx context.Context,
	interfaceName string,
	expected uint16,
) error {
	result, err := controller.config.Runner.Run(
		ctx,
		LinuxCommand{
			Path: controller.config.AWGBinary,
			Args: []string{
				"show", interfaceName, "listen-port",
			},
		},
	)
	if err != nil {
		return fmt.Errorf("verify Linux AWG listen port: %w", err)
	}
	text := strings.TrimSpace(string(result.Stdout))
	port, err := strconv.ParseUint(text, 10, 16)
	if err != nil || uint16(port) != expected {
		return errors.New(
			"linux AWG actual listen port differs from its candidate lease",
		)
	}
	return nil
}

func (controller *linuxController) configureLink(
	ctx context.Context,
	interfaceName string,
	innerAddress netip.Prefix,
) error {
	commands := [][]string{
		{
			familyFlag(innerAddress.Addr()),
			"address", "add", innerAddress.String(),
			"dev", interfaceName,
		},
		{
			"link", "set", "dev", interfaceName,
			"mtu", strconv.Itoa(controller.config.Signed.MTU),
		},
		{"link", "set", "dev", interfaceName, "up"},
	}
	for _, args := range commands {
		if _, err := controller.config.Runner.Run(
			ctx,
			LinuxCommand{Path: controller.config.IPBinary, Args: args},
		); err != nil {
			return fmt.Errorf("configure Linux AWG link: %w", err)
		}
	}
	return nil
}

func (controller *linuxController) runStatusCommand(
	ctx context.Context,
	path string,
	args ...string,
) ([]byte, error) {
	result, err := controller.config.Runner.Run(
		ctx,
		LinuxCommand{Path: path, Args: append([]string(nil), args...)},
	)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), result.Stdout...), nil
}

type linuxCandidateIdentity struct {
	InterfaceName  string
	InnerAddress   netip.Prefix
	RouteTable     uint32
	FirewallMark   uint32
	VerifyPriority uint32
	CommitPriority uint32
	PortSeed       uint16
}

func deriveLinuxCandidateIdentity(
	binding connectivity.Binding,
	pool netip.Prefix,
) linuxCandidateIdentity {
	sum := sha256.Sum256([]byte(
		"winn-directawg-linux/v1\x00" +
			binding.AttemptID + "\x00" +
			binding.CandidateID + "\x00" +
			strconv.FormatUint(binding.PSKGeneration, 10),
	))
	interfaceName := "winn" + fmt.Sprintf("%x", sum[:5])
	address := candidateAddress(pool, sum)
	table := uint32(10_000) +
		binary.BigEndian.Uint32(sum[8:12])%1_000_000
	mark := binary.BigEndian.Uint32(sum[12:16])
	if mark == 0 {
		mark = 1
	}
	return linuxCandidateIdentity{
		InterfaceName: interfaceName,
		InnerAddress:  address,
		RouteTable:    table,
		FirewallMark:  mark,
		VerifyPriority: 7000 +
			uint32(binary.BigEndian.Uint16(sum[16:18]))%6000,
		CommitPriority: 1000 +
			uint32(binary.BigEndian.Uint16(sum[18:20]))%6000,
		PortSeed: binary.BigEndian.Uint16(sum[20:22]),
	}
}

func (controller *linuxController) reserveListenPort(
	identity linuxCandidateIdentity,
) (uint16, func(), error) {
	minimum := uint32(controller.config.Signed.ListenPortMin)
	maximum := uint32(controller.config.Signed.ListenPortMax)
	count := maximum - minimum + 1
	start := uint32(identity.PortSeed) % count

	controller.portMu.Lock()
	defer controller.portMu.Unlock()
	for offset := uint32(0); offset < count; offset++ {
		// #nosec G115 -- ListenPortMin/Max are uint16 and validated
		// Min<Max above; minimum+(start+offset)%count is always <= maximum.
		port := uint16(minimum + (start+offset)%count)
		if _, leased := controller.leasedPorts[port]; leased {
			continue
		}
		if !controller.config.ListenPortAvailable(port) {
			continue
		}
		controller.leasedPorts[port] = struct{}{}
		var once sync.Once
		release := func() {
			once.Do(func() {
				controller.portMu.Lock()
				delete(controller.leasedPorts, port)
				controller.portMu.Unlock()
			})
		}
		return port, release, nil
	}
	return 0, nil, errors.New(
		"linux AWG signed listen-port range has no available port",
	)
}

func linuxListenPortAvailable(port uint16) bool {
	ipv4, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.IPv4zero, Port: int(port)},
	)
	if err != nil {
		return false
	}
	if err := ipv4.Close(); err != nil {
		return false
	}
	ipv6, err := net.ListenUDP(
		"udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: int(port)},
	)
	if err != nil {
		return false
	}
	return ipv6.Close() == nil
}

func (controller *linuxController) reserveInnerAddress(
	identity linuxCandidateIdentity,
) (netip.Prefix, func(), error) {
	pool := controller.config.Signed.InnerAddressPool
	start := identity.InnerAddress.Addr()
	current := start

	controller.addressMu.Lock()
	defer controller.addressMu.Unlock()
	for {
		if _, leased := controller.leasedAddresses[current]; !leased {
			controller.leasedAddresses[current] = struct{}{}
			var once sync.Once
			release := func() {
				once.Do(func() {
					controller.addressMu.Lock()
					delete(controller.leasedAddresses, current)
					controller.addressMu.Unlock()
				})
			}
			return netip.PrefixFrom(current, current.BitLen()),
				release, nil
		}
		current = nextCandidateAddress(pool, current)
		if current == start {
			return netip.Prefix{}, nil, errors.New(
				"linux AWG signed inner-address pool is exhausted",
			)
		}
	}
}

func nextCandidateAddress(pool netip.Prefix, current netip.Addr) netip.Addr {
	next := current.Next()
	if !next.IsValid() || !pool.Contains(next) ||
		(next.Is4() && next == lastAddress(pool)) {
		next = pool.Masked().Addr().Next()
	}
	return next
}

func candidateAddress(
	pool netip.Prefix,
	sum [sha256.Size]byte,
) netip.Prefix {
	masked := pool.Masked()
	address := masked.Addr()
	bitLength := address.BitLen()
	hostBits := bitLength - masked.Bits()
	var raw []byte
	if address.Is4() {
		value := address.As4()
		raw = value[:]
	} else {
		value := address.As16()
		raw = value[:]
	}
	for bit := 0; bit < hostBits; bit++ {
		sourceByte := sum[20+(bit/8)%12]
		sourceBit := (sourceByte >> uint(7-bit%8)) & 1
		targetBit := bitLength - hostBits + bit
		byteIndex := targetBit / 8
		mask := byte(1 << uint(7-targetBit%8))
		if sourceBit == 1 {
			raw[byteIndex] |= mask
		} else {
			raw[byteIndex] &^= mask
		}
	}
	derived, _ := netip.AddrFromSlice(raw)
	derived = derived.Unmap()
	if derived == masked.Addr() {
		derived = derived.Next()
	}
	if derived.Is4() && derived == lastAddress(masked) {
		derived = derived.Prev()
	}
	return netip.PrefixFrom(derived, derived.BitLen())
}

func lastAddress(prefix netip.Prefix) netip.Addr {
	address := prefix.Masked().Addr()
	var raw []byte
	if address.Is4() {
		value := address.As4()
		raw = value[:]
	} else {
		value := address.As16()
		raw = value[:]
	}
	for bit := prefix.Bits(); bit < address.BitLen(); bit++ {
		raw[bit/8] |= byte(1 << uint(7-bit%8))
	}
	last, _ := netip.AddrFromSlice(raw)
	return last.Unmap()
}

func validateLinuxSignedConfig(config LinuxSignedInterfaceConfig) error {
	pool := config.InnerAddressPool
	if !pool.IsValid() || pool != pool.Masked() ||
		!pool.Addr().IsPrivate() ||
		pool.Bits() > pool.Addr().BitLen()-2 {
		return errors.New(
			"linux AWG inner address pool must be a private canonical subnet",
		)
	}
	if config.MTU < 576 || config.MTU > 1500 {
		return errors.New("linux AWG signed MTU is invalid")
	}
	if pool.Addr().Is6() && config.MTU < 1280 {
		return errors.New("linux AWG IPv6 MTU must be at least 1280")
	}
	if config.ListenPortMin < 1024 ||
		config.ListenPortMax < config.ListenPortMin ||
		config.ListenPortMax-config.ListenPortMin < 1 {
		return errors.New(
			"linux AWG signed listen-port range must contain at least two non-privileged ports",
		)
	}
	if config.PersistentKeepalive > 600 {
		return errors.New("linux AWG persistent keepalive is invalid")
	}
	if err := validateAWGObfuscation(config.Obfuscation); err != nil {
		return err
	}
	if int(config.Obfuscation.JMax) >= config.MTU {
		return errors.New(
			"linux AWG maximum junk packet must be below interface MTU",
		)
	}
	allowed, err := validateLinuxPrefixes(
		config.AllowedIPs, pool.Addr(), "allowed IP",
	)
	if err != nil {
		return err
	}
	verification, err := validateLinuxPrefixes(
		config.VerificationRoutes, pool.Addr(), "verification route",
	)
	if err != nil {
		return err
	}
	for _, probe := range verification {
		covered := false
		for _, current := range allowed {
			if current.Bits() <= probe.Bits() &&
				current.Contains(probe.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			return errors.New(
				"linux AWG verification route is outside allowed IPs",
			)
		}
	}
	return nil
}

func validateLinuxPrefixes(
	prefixes []netip.Prefix,
	family netip.Addr,
	name string,
) ([]netip.Prefix, error) {
	if len(prefixes) == 0 || len(prefixes) > 64 {
		return nil, fmt.Errorf("linux AWG %s count is invalid", name)
	}
	result := slices.Clone(prefixes)
	slices.SortFunc(result, func(first, second netip.Prefix) int {
		return first.Addr().Compare(second.Addr())
	})
	for index, prefix := range result {
		if !prefix.IsValid() || prefix != prefix.Masked() ||
			prefix.Addr().Is4() != family.Is4() {
			return nil, fmt.Errorf("linux AWG %s is invalid", name)
		}
		if index > 0 && prefix == result[index-1] {
			return nil, fmt.Errorf("linux AWG %s is duplicated", name)
		}
	}
	return result, nil
}

func validateAWGObfuscation(config AWGObfuscation) error {
	if config.JC == 0 || config.JC > 128 ||
		config.JMin > config.JMax || config.JMax > 1280 ||
		config.S1 > 1280 || config.S2 > 1280 ||
		config.S3 > 1280 || config.S4 > 1280 {
		return errors.New("linux AWG junk schedule is invalid")
	}
	headers := []uint32{config.H1, config.H2, config.H3, config.H4}
	seen := make(map[uint32]struct{}, len(headers))
	for _, header := range headers {
		if header == 0 {
			return errors.New("linux AWG obfuscation headers must be nonzero")
		}
		if _, duplicate := seen[header]; duplicate {
			return errors.New("linux AWG obfuscation headers must be distinct")
		}
		seen[header] = struct{}{}
	}
	return nil
}

// validateLinuxExecutable is a SHAPE check on a configured binary path, and it
// is deliberately nothing more.
//
// It answers "is this an absolute path that currently names a regular file with
// an execute bit" — a configuration-error check, so a typo or a directory is
// reported at startup instead of as a confusing exec failure later. It uses
// os.Stat, which FOLLOWS symbolic links, and that is intentional: operators
// legitimately point these at /usr/bin/ip and similar, which are links on many
// distributions.
//
// It is NOT an identity or content pin, and nothing in this package treats it
// as one. It cannot tell that the file changed between this call and exec, and
// LinuxExecAllowList does not close that gap either — that list pins path
// strings, not executable objects. See its type comment for the exact scope of
// what is and is not enforced, including the two exec boundaries (execLinuxRunner
// and runBoundedStatusCommand) that this shape check is the only gate on.
func validateLinuxExecutable(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("path must be absolute")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("path must name a regular executable file")
	}
	return nil
}

func writeLinuxKeyFile(path string, raw []byte) error {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(raw))+1)
	base64.StdEncoding.Encode(encoded[:len(encoded)-1], raw)
	encoded[len(encoded)-1] = '\n'
	defer clear(encoded)
	// #nosec G304 -- path is code-constructed via filepath.Join inside a
	// freshly created 0700 temporary directory, not derived from untrusted
	// input.
	file, err := os.OpenFile(
		path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600,
	)
	if err != nil {
		return fmt.Errorf("create Linux AWG key file: %w", err)
	}
	_, writeErr := file.Write(encoded)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.Join(writeErr, syncErr, closeErr)
	}
	return nil
}

func clearLinuxKeyMaterial(material *LinuxKeyMaterial) {
	if material == nil {
		return
	}
	clear(material.PrivateKey)
	clear(material.PSK)
	material.PrivateKey = nil
	material.PSK = nil
	material.Generation = 0
}

func linuxKeyIsZero(key []byte) bool {
	var combined byte
	for _, value := range key {
		combined |= value
	}
	return combined == 0
}

func removeLinuxSecretFiles(paths ...string) error {
	var removeError error
	for _, path := range paths {
		if err := os.Remove(path); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			removeError = errors.Join(removeError, err)
		}
	}
	return removeError
}

func familyFlag(address netip.Addr) string {
	if address.Is4() {
		return "-4"
	}
	return "-6"
}
