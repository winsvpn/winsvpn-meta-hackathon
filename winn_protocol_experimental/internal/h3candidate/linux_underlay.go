package h3candidate

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"winsvpn.local/winnprotocol/internal/connectivity"
)

const (
	defaultLinuxUnderlayHealthInterval = time.Second
	minLinuxUnderlayHealthInterval     = 100 * time.Millisecond
	maxLinuxUnderlayHealthInterval     = 30 * time.Second
)

var ErrLinuxAdaptersUnsupported = errors.New(
	"linux H3 adapters are unsupported on this platform",
)

// LinuxProtectedUnderlayConfig contains trusted local routing state plus one
// signed manifest address hint. RemoteEndpoint must be an IP literal so opening
// the QUIC underlay never invokes the host resolver. ServerName is the public
// TLS name in the verified transport.
type LinuxProtectedUnderlayConfig struct {
	InterfaceName  string
	FirewallMark   uint32
	ServerName     string
	RemoteEndpoint string
	// SessionExpiresAt is the trusted lifetime of a committed path. It must
	// not be replaced by the short click-work Binding expiry.
	SessionExpiresAt time.Time
	HealthInterval   time.Duration
}

type linuxProtectedPacketOpener interface {
	Open(
		context.Context,
		string,
		string,
		uint32,
	) (net.PacketConn, error)
	Protect(net.PacketConn, string, uint32) error
}

type linuxInterfaceInspector interface {
	Check(string) error
}

type linuxQUICPathDialer func(
	context.Context,
	net.PacketConn,
	*net.UDPAddr,
	*tls.Config,
	*quic.Config,
) (*quic.Conn, *quic.Transport, error)

type linuxProtectedUnderlayFactory struct {
	config    LinuxProtectedUnderlayConfig
	remote    netip.AddrPort
	opener    linuxProtectedPacketOpener
	inspector linuxInterfaceInspector
	dialQUIC  linuxQUICPathDialer
	now       func() time.Time
}

// newLinuxProtectedUnderlayFactory stays platform-neutral for lifecycle tests.
// The exported constructor is build-tag gated and supplies real Linux socket
// protection.
func newLinuxProtectedUnderlayFactory(
	config LinuxProtectedUnderlayConfig,
	opener linuxProtectedPacketOpener,
	inspector linuxInterfaceInspector,
	dialQUIC linuxQUICPathDialer,
	now func() time.Time,
) (*linuxProtectedUnderlayFactory, error) {
	if err := validateLinuxInterfaceAndMark(
		config.InterfaceName, config.FirewallMark,
	); err != nil {
		return nil, err
	}
	if !validTLSServerName(config.ServerName) {
		return nil, errors.New("linux H3 server name is invalid")
	}
	remote, err := netip.ParseAddrPort(config.RemoteEndpoint)
	if err != nil || !remote.Addr().IsValid() ||
		remote.Addr().IsUnspecified() ||
		remote.Addr().IsMulticast() ||
		remote.Port() == 0 {
		return nil, errors.New(
			"linux H3 remote endpoint must be a usable IP literal and port",
		)
	}
	if config.HealthInterval == 0 {
		config.HealthInterval = defaultLinuxUnderlayHealthInterval
	}
	if config.HealthInterval < minLinuxUnderlayHealthInterval ||
		config.HealthInterval > maxLinuxUnderlayHealthInterval {
		return nil, errors.New("linux H3 health interval is invalid")
	}
	if now == nil {
		now = time.Now
	}
	config.SessionExpiresAt = config.SessionExpiresAt.UTC()
	if config.SessionExpiresAt.IsZero() {
		return nil, errors.New("linux H3 session lifetime is required")
	}
	if !config.SessionExpiresAt.After(now().UTC()) {
		return nil, errors.New("linux H3 session lifetime is expired")
	}
	if opener == nil || inspector == nil || dialQUIC == nil {
		return nil, errors.New(
			"linux H3 socket opener, interface inspector, and QUIC dialer are required",
		)
	}
	return &linuxProtectedUnderlayFactory{
		config:    config,
		remote:    remote,
		opener:    opener,
		inspector: inspector,
		dialQUIC:  dialQUIC,
		now:       now,
	}, nil
}

func (factory *linuxProtectedUnderlayFactory) Open(
	ctx context.Context,
	binding connectivity.Binding,
) (ProtectedUnderlay, error) {
	prepared, err := factory.Prepare(
		ctx,
		factory.config.SessionExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	if err := prepared.Claim(binding); err != nil {
		_ = prepared.Close(context.Background())
		return nil, err
	}
	return prepared, nil
}

func (factory *linuxProtectedUnderlayFactory) Prepare(
	ctx context.Context,
	expiresAt time.Time,
) (PreparedProtectedUnderlay, error) {
	if ctx == nil {
		return nil, errors.New("linux H3 underlay context is required")
	}
	now := factory.now().UTC()
	expiresAt = expiresAt.UTC()
	if !expiresAt.After(now) {
		return nil, errors.New("linux H3 underlay preparation is expired")
	}
	if err := factory.inspector.Check(factory.config.InterfaceName); err != nil {
		return nil, fmt.Errorf("linux H3 underlay is unavailable: %w", err)
	}
	lifetime, cancel := context.WithCancel(context.WithoutCancel(ctx))
	underlay := &linuxProtectedUnderlay{
		factory:   factory,
		expiresAt: expiresAt,
		lifetime:  lifetime,
		cancel:    cancel,
		health:    make(chan error, 1),
		closed:    make(chan struct{}),
	}
	go underlay.monitor()
	return underlay, nil
}

type linuxProtectedUnderlay struct {
	factory   *linuxProtectedUnderlayFactory
	binding   connectivity.Binding
	expiresAt time.Time
	lifetime  context.Context
	cancel    context.CancelFunc

	mu      sync.Mutex
	dialed  bool
	claimed bool

	health     chan error
	healthOnce sync.Once
	closeOnce  sync.Once
	closed     chan struct{}
}

func (underlay *linuxProtectedUnderlay) Claim(
	binding connectivity.Binding,
) error {
	if underlay == nil {
		return ErrClosed
	}
	now := underlay.factory.now().UTC()
	if err := binding.Validate(now); err != nil {
		return fmt.Errorf("claim prepared Linux H3 underlay: %w", err)
	}
	if binding.ExpiresAt.After(underlay.expiresAt) {
		return errors.New(
			"click-time binding outlives prepared Linux H3 underlay",
		)
	}
	if err := underlay.available(); err != nil {
		return err
	}
	underlay.mu.Lock()
	defer underlay.mu.Unlock()
	if underlay.claimed {
		return errors.New("prepared Linux H3 underlay is already claimed")
	}
	underlay.binding = binding
	underlay.claimed = true
	return nil
}

func (underlay *linuxProtectedUnderlay) DialQUICPath(
	ctx context.Context,
	address string,
	tlsConfig *tls.Config,
	quicConfig *quic.Config,
) (*quic.Conn, *quic.Transport, error) {
	if ctx == nil {
		return nil, nil, errors.New("linux H3 QUIC dial context is required")
	}
	if err := underlay.available(); err != nil {
		return nil, nil, err
	}
	if err := underlay.validateRequestedPath(address, tlsConfig, quicConfig); err != nil {
		return nil, nil, err
	}
	underlay.mu.Lock()
	if underlay.dialed {
		underlay.mu.Unlock()
		return nil, nil, errors.New(
			"linux H3 underlay permits exactly one initial QUIC path",
		)
	}
	underlay.dialed = true
	underlay.mu.Unlock()

	network := "udp4"
	local := "0.0.0.0:0"
	if underlay.factory.remote.Addr().Is6() {
		network = "udp6"
		local = "[::]:0"
	}
	socket, err := underlay.factory.opener.Open(
		ctx,
		network,
		underlay.factory.config.InterfaceName,
		underlay.factory.config.FirewallMark,
	)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"open protected Linux H3 socket on %s: %w", local, err,
		)
	}
	remote := net.UDPAddrFromAddrPort(underlay.factory.remote)
	connection, transport, err := underlay.factory.dialQUIC(
		ctx, socket, remote, tlsConfig, quicConfig,
	)
	if err != nil {
		_ = socket.Close()
		return nil, nil, err
	}
	if connection == nil || transport == nil {
		if transport != nil {
			_ = transport.Close()
		}
		_ = socket.Close()
		if connection != nil {
			_ = connection.CloseWithError(0, "invalid protected underlay")
		}
		return nil, nil, errors.New(
			"protected Linux H3 dial returned an incomplete QUIC path",
		)
	}
	// carrier.H3Dialer owns the connection, transport, and the transport's
	// application-supplied PacketConn after success.
	return connection, transport, nil
}

func (underlay *linuxProtectedUnderlay) ProtectMigrationSocket(
	ctx context.Context,
	binding connectivity.Binding,
	socket net.PacketConn,
) error {
	if ctx == nil {
		return errors.New("linux H3 migration context is required")
	}
	underlay.mu.Lock()
	claimed := underlay.claimed
	expected := underlay.binding
	underlay.mu.Unlock()
	if !claimed || !equalBinding(expected, binding) {
		return ErrBindingMismatch
	}
	if err := underlay.available(); err != nil {
		return err
	}
	if nilInterface(socket) {
		return errors.New("linux H3 migration socket is required")
	}
	if err := underlay.factory.opener.Protect(
		socket,
		underlay.factory.config.InterfaceName,
		underlay.factory.config.FirewallMark,
	); err != nil {
		return fmt.Errorf("protect Linux H3 migration socket: %w", err)
	}
	return nil
}

func (underlay *linuxProtectedUnderlay) Health() <-chan error {
	return underlay.health
}

func (underlay *linuxProtectedUnderlay) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	underlay.closeOnce.Do(func() {
		underlay.cancel()
	})
	select {
	case <-underlay.closed:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (underlay *linuxProtectedUnderlay) available() error {
	select {
	case <-underlay.closed:
		return ErrClosed
	default:
	}
	now := underlay.factory.now().UTC()
	if !underlay.expiresAt.After(now) {
		return errors.New("linux H3 underlay preparation expired")
	}
	return nil
}

func (underlay *linuxProtectedUnderlay) validateRequestedPath(
	address string,
	tlsConfig *tls.Config,
	quicConfig *quic.Config,
) error {
	host, port, err := splitServerAddress(address)
	if err != nil ||
		!strings.EqualFold(host, underlay.factory.config.ServerName) ||
		port != underlay.factory.remote.Port() {
		return errors.New(
			"linux H3 requested authority differs from the signed fixed path",
		)
	}
	if tlsConfig == nil ||
		!strings.EqualFold(
			strings.TrimSuffix(tlsConfig.ServerName, "."),
			underlay.factory.config.ServerName,
		) ||
		tlsConfig.MinVersion != tls.VersionTLS13 ||
		tlsConfig.MaxVersion != tls.VersionTLS13 {
		return errors.New("linux H3 TLS path is not strict TLS 1.3")
	}
	if quicConfig == nil || quicConfig.Allow0RTT {
		return errors.New("linux H3 QUIC path is missing or permits 0-RTT")
	}
	return nil
}

func (underlay *linuxProtectedUnderlay) monitor() {
	defer close(underlay.closed)
	ticker := time.NewTicker(underlay.factory.config.HealthInterval)
	defer ticker.Stop()
	expiry := time.NewTimer(
		max(time.Duration(0),
			underlay.expiresAt.Sub(underlay.factory.now().UTC())),
	)
	defer expiry.Stop()
	for {
		select {
		case <-underlay.lifetime.Done():
			underlay.healthOnce.Do(func() { close(underlay.health) })
			return
		case <-expiry.C:
			underlay.publishHealth(
				errors.New("linux H3 underlay preparation expired"),
			)
			return
		case <-ticker.C:
			if err := underlay.factory.inspector.Check(
				underlay.factory.config.InterfaceName,
			); err != nil {
				underlay.publishHealth(fmt.Errorf(
					"linux H3 underlay interface failed: %w", err,
				))
				return
			}
		}
	}
}

func (underlay *linuxProtectedUnderlay) publishHealth(err error) {
	underlay.healthOnce.Do(func() {
		underlay.health <- err
		close(underlay.health)
	})
}

func splitServerAddress(address string) (string, uint16, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		if strings.Contains(address, ":") {
			return "", 0, err
		}
		host = address
		portText = "443"
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	port, err := net.LookupPort("tcp", portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("server authority port is invalid")
	}
	return host, uint16(port), nil
}

func validTLSServerName(value string) bool {
	if len(value) == 0 || len(value) > 253 ||
		value != strings.ToLower(value) ||
		strings.HasSuffix(value, ".") ||
		net.ParseIP(value) != nil {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, current := range label {
			if (current < 'a' || current > 'z') &&
				(current < '0' || current > '9') &&
				current != '-' {
				return false
			}
		}
	}
	return true
}

func validateLinuxInterfaceAndMark(
	interfaceName string,
	firewallMark uint32,
) error {
	if interfaceName == "" || len(interfaceName) > 15 ||
		firewallMark == 0 {
		return errors.New("linux H3 underlay interface or mark is invalid")
	}
	for _, current := range interfaceName {
		if (current < 'a' || current > 'z') &&
			(current < 'A' || current > 'Z') &&
			(current < '0' || current > '9') &&
			current != '_' && current != '-' && current != '.' {
			return errors.New("linux H3 underlay interface name is invalid")
		}
	}
	return nil
}
