// Package directawg adapts a real, raw AmneziaWG/WireGuard UDP path to the
// Winn v3 candidate contract. Authentication comes from the AWG handshake
// against the signed manifest key and current PSK generation; Winn does not add
// a second, bespoke UDP authentication protocol.
package directawg

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/connectivity"
)

const (
	defaultPollInterval = 10 * time.Millisecond
	maxClockSkew        = time.Second
)

var initialHandshakeHedgeOffsets = [...]time.Duration{
	700 * time.Millisecond,
	1100 * time.Millisecond,
	1500 * time.Millisecond,
	1900 * time.Millisecond,
}

// Status is the authoritative per-peer state reported by the AWG
// implementation. Byte counters are monotonically increasing for the lifetime
// of one prepared candidate interface.
type Status struct {
	PeerPublicKey   string
	PeerEndpoint    string
	LatestHandshake time.Time
	RxBytes         uint64
	TxBytes         uint64
}

// Preparation is passed to a platform tunnel controller after the raw remote
// socket and loopback relay are ready. RelayEndpoint is the endpoint that the
// candidate-isolated AWG interface must use for this attempt.
type Preparation struct {
	Binding          connectivity.Binding
	RelayEndpoint    string
	GatewayEndpoint  string
	GatewayPublicKey string
	MinInnerDatagram int
	MaxInnerDatagram int
}

// PreparedTunnel contains a baseline captured before the controller activates
// the candidate endpoint or current PSK generation. This prevents old handshake
// and traffic counters from satisfying a new connection attempt.
type PreparedTunnel struct {
	Session             TunnelSession
	Baseline            Status
	LocalSourceEndpoint string
}

// TunnelController prepares one candidate-isolated AWG interface. A successful
// Prepare must not tie the returned session lifetime to ctx: the coordinator
// cancels its candidate race context after selecting the winner.
type TunnelController interface {
	Prepare(context.Context, Preparation) (PreparedTunnel, error)
}

// TunnelSession must keep DNS and canary verification inside this exact
// candidate tunnel. Its methods may be called concurrently. Close must be
// idempotent and synchronous: before it returns, it must remove any routes and
// resolver state installed by Commit while preserving or engaging the platform
// kill switch. Close must remain safe when Commit is cancelled concurrently.
// Health must return one stable, non-nil channel that publishes at most one
// terminal error and then closes.
type TunnelSession interface {
	Status(context.Context) (Status, error)
	VerifyProtectedDNS(context.Context, connectivity.Binding) error
	VerifyTunnelCanary(context.Context, connectivity.Binding) error
	Commit(context.Context, connectivity.Binding) error
	Health() <-chan error
	Close() error
}

// ContextTunnelSession is implemented by production sessions whose teardown is
// bounded by both a caller context and the session's configured stop timeout.
// Close remains for API compatibility and delegates to CloseContext.
type ContextTunnelSession interface {
	TunnelSession
	CloseContext(context.Context) error
}

// HandshakeRefresher is an optional production capability. It atomically
// refreshes the exact existing peer under the same immutable binding and PSK
// generation so a lost initial handshake does not wait for AWG's five-second
// engine limiter. It must not create a second interface or session.
type HandshakeRefresher interface {
	RefreshAWGHandshake(context.Context, connectivity.Binding) error
}

// RemoteDialer opens the raw UDP path to a manifest endpoint.
type RemoteDialer interface {
	Dial(context.Context, string) (net.PacketConn, error)
}

type Config struct {
	Descriptor        connectivity.CandidateDescriptor
	Endpoint          string
	GatewayPublicKey  string
	LocalRelayAddress string
	MinInnerDatagram  int
	MaxInnerDatagram  int
	IdleTimeout       time.Duration
	SocketBufferBytes int
	PollInterval      time.Duration
	Controller        TunnelController
	Dialer            RemoteDialer
	// LabMode permits the generic UDPDialer, which cannot protect its socket
	// from a platform VPN route or kill switch. Production must inject a
	// platform-protected RemoteDialer.
	LabMode bool
	Now     func() time.Time
}

type Candidate struct {
	config Config
}

func NewCandidate(config Config) (*Candidate, error) {
	now := time.Now
	if config.Now != nil {
		now = config.Now
	}
	if err := config.Descriptor.Validate(now().UTC()); err != nil {
		return nil, fmt.Errorf("direct AWG descriptor: %w", err)
	}
	if config.Descriptor.Carrier != connectivity.CarrierDirectAWG {
		return nil, errors.New("direct AWG candidate has the wrong carrier")
	}
	if err := validateIPLiteralEndpoint(config.Endpoint, false); err != nil {
		return nil, fmt.Errorf("direct AWG endpoint: %w", err)
	}
	if err := validatePublicKey(config.GatewayPublicKey); err != nil {
		return nil, err
	}
	if config.MinInnerDatagram < 576 ||
		config.MaxInnerDatagram < config.MinInnerDatagram ||
		config.MaxInnerDatagram > carrier.AbsoluteMaxDatagram {
		return nil, errors.New("direct AWG inner datagram range is invalid")
	}
	if config.IdleTimeout < 0 {
		return nil, errors.New("direct AWG idle timeout is invalid")
	}
	if config.SocketBufferBytes < 0 ||
		config.SocketBufferBytes > carrier.MaxRelaySocketBufferBytes {
		return nil, errors.New("direct AWG socket buffer size is invalid")
	}
	if config.PollInterval < 0 || config.PollInterval > 250*time.Millisecond {
		return nil, errors.New("direct AWG polling interval is invalid")
	}
	if config.Controller == nil {
		return nil, errors.New("direct AWG tunnel controller is required")
	}
	if config.LocalRelayAddress == "" {
		config.LocalRelayAddress = "127.0.0.1:0"
	}
	if err := validateLoopbackEndpoint(config.LocalRelayAddress); err != nil {
		return nil, fmt.Errorf("direct AWG loopback relay: %w", err)
	}
	if config.Dialer == nil && !config.LabMode {
		return nil, errors.New(
			"production direct AWG requires a protected underlay dialer",
		)
	}
	if config.Dialer == nil {
		config.Dialer = UDPDialer{}
	}
	if !config.LabMode && genericUDPDialer(config.Dialer) {
		return nil, errors.New(
			"generic UDP dialer is permitted only in direct AWG lab mode",
		)
	}
	if config.PollInterval == 0 {
		config.PollInterval = defaultPollInterval
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Candidate{config: config}, nil
}

func (candidate *Candidate) Descriptor() connectivity.CandidateDescriptor {
	return candidate.config.Descriptor
}

func (candidate *Candidate) Dial(
	ctx context.Context,
	binding connectivity.Binding,
) (connectivity.CandidateConnection, error) {
	if ctx == nil {
		return nil, errors.New("direct AWG dial context is required")
	}
	startedAt := candidate.config.Now().UTC()
	if err := binding.Validate(startedAt); err != nil {
		return nil, fmt.Errorf("direct AWG binding: %w", err)
	}
	if binding.CandidateID != candidate.config.Descriptor.ID ||
		binding.NodeID != candidate.config.Descriptor.NodeID {
		return nil, errors.New("direct AWG binding does not match candidate")
	}

	remote, err := candidate.config.Dialer.Dial(ctx, candidate.config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("dial direct AWG UDP path: %w", err)
	}
	local, err := listenLoopback(candidate.config.LocalRelayAddress)
	if err != nil {
		_ = remote.Close()
		return nil, fmt.Errorf("listen for local AWG packets: %w", err)
	}

	prepared, err := candidate.config.Controller.Prepare(ctx, Preparation{
		Binding:          binding,
		RelayEndpoint:    local.LocalAddr().String(),
		GatewayEndpoint:  candidate.config.Endpoint,
		GatewayPublicKey: candidate.config.GatewayPublicKey,
		MinInnerDatagram: candidate.config.MinInnerDatagram,
		MaxInnerDatagram: candidate.config.MaxInnerDatagram,
	})
	if err != nil {
		_ = local.Close()
		_ = remote.Close()
		return nil, fmt.Errorf("prepare direct AWG tunnel: %w", err)
	}
	if prepared.Session == nil {
		_ = local.Close()
		_ = remote.Close()
		return nil, errors.New("direct AWG controller returned no session")
	}
	if prepared.Session.Health() == nil {
		_ = prepared.Session.Close()
		_ = local.Close()
		_ = remote.Close()
		return nil, errors.New(
			"direct AWG controller returned no session health stream",
		)
	}
	if err := validateLoopbackEndpoint(
		prepared.LocalSourceEndpoint,
	); err != nil {
		_ = prepared.Session.Close()
		_ = local.Close()
		_ = remote.Close()
		return nil, fmt.Errorf("direct AWG local source: %w", err)
	}
	expectedLocalPeer, err := net.ResolveUDPAddr(
		"udp", prepared.LocalSourceEndpoint,
	)
	if err != nil || expectedLocalPeer.Port == 0 {
		_ = prepared.Session.Close()
		_ = local.Close()
		_ = remote.Close()
		if err != nil {
			return nil, fmt.Errorf(
				"resolve direct AWG local source: %w", err,
			)
		}
		return nil, errors.New("direct AWG local source port is zero")
	}
	if err := validateStatus(
		prepared.Baseline,
		candidate.config.GatewayPublicKey,
		local.LocalAddr().String(),
		candidate.config.Now().UTC(),
		true,
	); err != nil {
		_ = prepared.Session.Close()
		_ = local.Close()
		_ = remote.Close()
		return nil, fmt.Errorf("direct AWG baseline: %w", err)
	}
	if !candidate.config.LabMode &&
		(!prepared.Baseline.LatestHandshake.IsZero() ||
			prepared.Baseline.RxBytes != 0 ||
			prepared.Baseline.TxBytes != 0) {
		_ = prepared.Session.Close()
		_ = local.Close()
		_ = remote.Close()
		return nil, errors.New(
			"production direct AWG requires a fresh isolated peer baseline",
		)
	}
	lifetime, cancel := context.WithCancel(context.Background())
	connection := &Connection{
		binding:          binding,
		startedAt:        startedAt,
		handshakeReadyAt: candidate.config.Now().UTC(),
		pollInterval:     candidate.config.PollInterval,
		now:              candidate.config.Now,
		session:          prepared.Session,
		baseline:         prepared.Baseline,
		expectedKey:      candidate.config.GatewayPublicKey,
		expectedEndpoint: local.LocalAddr().String(),
		local:            local,
		remote:           remote,
		cancel:           cancel,
		relayDone:        make(chan struct{}),
		health:           make(chan error, 1),
		healthWatchDone:  make(chan struct{}),
	}
	go connection.runRelay(lifetime, carrier.RelayConfig{
		MaxDatagram:       candidate.config.MaxInnerDatagram,
		IdleTimeout:       candidate.config.IdleTimeout,
		ExpectedLocalPeer: expectedLocalPeer,
		SocketBufferBytes: candidate.config.SocketBufferBytes,
	})
	go connection.watchSessionHealth(lifetime)
	return connection, nil
}

type Connection struct {
	binding          connectivity.Binding
	startedAt        time.Time
	handshakeReadyAt time.Time
	pollInterval     time.Duration
	now              func() time.Time
	session          TunnelSession
	baseline         Status
	expectedKey      string
	expectedEndpoint string
	local            *net.UDPConn
	remote           net.PacketConn
	cancel           context.CancelFunc

	relayDone chan struct{}
	relayMu   sync.RWMutex
	relayErr  error

	health          chan error
	healthOnce      sync.Once
	healthWatchDone chan struct{}

	handshakeMu sync.Mutex

	closeOnce   sync.Once
	closeStart  sync.Once
	closeMu     sync.Mutex
	closeErr    error
	fullyClosed bool
}

func (connection *Connection) FreshAWGHandshake(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	if err := connection.checkBinding(binding); err != nil {
		return err
	}
	connection.handshakeMu.Lock()
	defer connection.handshakeMu.Unlock()
	nextHedge := 0
	return connection.poll(ctx, func(status Status) (bool, error) {
		if status.LatestHandshake.IsZero() {
			return connection.maybeRefreshInitialHandshake(
				ctx, binding, &nextHedge,
			)
		}
		floor := connection.startedAt.Truncate(time.Second)
		if status.LatestHandshake.Before(floor) {
			return connection.maybeRefreshInitialHandshake(
				ctx, binding, &nextHedge,
			)
		}
		if connection.baseline.LatestHandshake.IsZero() {
			return true, nil
		}
		return status.LatestHandshake.After(
			connection.baseline.LatestHandshake,
		), nil
	})
}

func (connection *Connection) maybeRefreshInitialHandshake(
	ctx context.Context,
	binding connectivity.Binding,
	nextHedge *int,
) (bool, error) {
	if nextHedge == nil || *nextHedge >= len(initialHandshakeHedgeOffsets) {
		return false, nil
	}
	if connection.now().UTC().Before(
		connection.handshakeReadyAt.Add(
			initialHandshakeHedgeOffsets[*nextHedge],
		),
	) {
		return false, nil
	}
	refresher, ok := connection.session.(HandshakeRefresher)
	if !ok {
		*nextHedge = len(initialHandshakeHedgeOffsets)
		return false, nil
	}
	if err := refresher.RefreshAWGHandshake(ctx, binding); err != nil {
		return false, fmt.Errorf(
			"refresh exact AWG peer after missing initial handshake: %w",
			err,
		)
	}
	(*nextHedge)++
	return false, nil
}

func (connection *Connection) VerifyBidirectional(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	if err := connection.checkBinding(binding); err != nil {
		return err
	}
	return connection.poll(ctx, func(status Status) (bool, error) {
		if status.RxBytes < connection.baseline.RxBytes ||
			status.TxBytes < connection.baseline.TxBytes {
			return false, errors.New("direct AWG counters regressed")
		}
		return status.RxBytes > connection.baseline.RxBytes &&
			status.TxBytes > connection.baseline.TxBytes, nil
	})
}

func (connection *Connection) VerifyProtectedDNS(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	if err := connection.checkBinding(binding); err != nil {
		return err
	}
	if err := connection.ensureRelay(); err != nil {
		return err
	}
	return connection.session.VerifyProtectedDNS(ctx, binding)
}

func (connection *Connection) VerifyTunnelCanary(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	if err := connection.checkBinding(binding); err != nil {
		return err
	}
	if err := connection.ensureRelay(); err != nil {
		return err
	}
	return connection.session.VerifyTunnelCanary(ctx, binding)
}

func (connection *Connection) Commit(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	if err := connection.checkBinding(binding); err != nil {
		return err
	}
	if err := connection.ensureRelay(); err != nil {
		return err
	}
	if err := connection.ensureHealth(); err != nil {
		return err
	}
	if err := connection.session.Commit(ctx, binding); err != nil {
		return err
	}
	if err := connection.ensureRelay(); err != nil {
		return err
	}
	return connection.ensureHealth()
}

func (connection *Connection) Health() <-chan error {
	return connection.health
}

func (connection *Connection) Close() error {
	connection.closeOnce.Do(func() {
		_ = connection.retryClose()
	})
	connection.closeMu.Lock()
	defer connection.closeMu.Unlock()
	return connection.closeErr
}

// RetryClose resumes a failed staged Linux teardown. Close remains idempotent
// for ordinary callers; the coordinator uses this explicit recovery hook only
// when a later owner must compensate for an interrupted rollback.
func (connection *Connection) RetryClose() error {
	return connection.retryClose()
}

func (connection *Connection) retryClose() error {
	connection.closeStart.Do(func() {
		connection.cancel()
	})
	connection.closeMu.Lock()
	defer connection.closeMu.Unlock()
	if connection.fullyClosed {
		return connection.closeErr
	}

	var sessionErr error
	if connection.session != nil {
		// The Linux session owns retryable staged teardown. Re-enter it after
		// a transient failure instead of caching the first wrapper error.
		sessionErr = connection.session.Close()
	}
	<-connection.relayDone
	// Relay failure is an operational health signal, not evidence that the
	// route/DNS/interface rollback failed. Returning it from Close would make
	// the coordinator permanently poison reconnect after a routine outage.
	connection.closeErr = sessionErr
	<-connection.healthWatchDone
	connection.healthOnce.Do(func() {
		close(connection.health)
	})
	connection.fullyClosed = sessionErr == nil
	return connection.closeErr
}

func (connection *Connection) runRelay(
	ctx context.Context,
	config carrier.RelayConfig,
) {
	err := carrier.RelayLocalUDP(ctx, connection.local, connection.remote, config)
	connection.relayMu.Lock()
	connection.relayErr = err
	connection.relayMu.Unlock()
	close(connection.relayDone)
	if ctx.Err() != nil {
		return
	}
	if err == nil {
		err = errors.New("direct AWG relay stopped")
	}
	connection.fail(fmt.Errorf("direct AWG relay stopped: %w", err))
}

func (connection *Connection) watchSessionHealth(ctx context.Context) {
	defer close(connection.healthWatchDone)
	select {
	case <-ctx.Done():
		return
	case err, ok := <-connection.session.Health():
		if ctx.Err() != nil {
			return
		}
		if !ok || err == nil {
			err = errors.New("direct AWG tunnel health stream terminated")
		}
		connection.fail(err)
	}
}

func (connection *Connection) fail(err error) {
	if err == nil {
		return
	}
	published := false
	connection.healthOnce.Do(func() {
		connection.health <- err
		close(connection.health)
		published = true
	})
	if published {
		go func() {
			_ = connection.Close()
		}()
	}
}

func (connection *Connection) ensureHealth() error {
	select {
	case err, ok := <-connection.health:
		if !ok || err == nil {
			return errors.New("direct AWG connection health was lost")
		}
		return fmt.Errorf("direct AWG connection health was lost: %w", err)
	default:
		return nil
	}
}

func (connection *Connection) poll(
	ctx context.Context,
	accept func(Status) (bool, error),
) error {
	if ctx == nil {
		return errors.New("direct AWG verification context is required")
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-connection.relayDone:
			return connection.ensureRelay()
		case <-timer.C:
			status, err := connection.session.Status(ctx)
			if err != nil {
				return err
			}
			now := connection.now().UTC()
			if err := validateStatus(
				status,
				connection.expectedKey,
				connection.expectedEndpoint,
				now,
				false,
			); err != nil {
				return err
			}
			accepted, err := accept(status)
			if err != nil {
				return err
			}
			if accepted {
				return nil
			}
			timer.Reset(connection.pollInterval)
		}
	}
}

func (connection *Connection) ensureRelay() error {
	select {
	case <-connection.relayDone:
		connection.relayMu.RLock()
		err := connection.relayErr
		connection.relayMu.RUnlock()
		if err == nil {
			return errors.New("direct AWG relay stopped")
		}
		return fmt.Errorf("direct AWG relay stopped: %w", err)
	default:
		return nil
	}
}

func (connection *Connection) checkBinding(
	binding connectivity.Binding,
) error {
	if binding != connection.binding {
		return errors.New("direct AWG verification binding mismatch")
	}
	if err := connection.ensureRelay(); err != nil {
		return err
	}
	return connection.ensureHealth()
}

func validateStatus(
	status Status,
	expectedKey string,
	expectedEndpoint string,
	now time.Time,
	baseline bool,
) error {
	if status.PeerPublicKey != expectedKey {
		return errors.New("direct AWG status reports the wrong peer key")
	}
	if status.PeerEndpoint != expectedEndpoint {
		return errors.New("direct AWG status reports the wrong peer endpoint")
	}
	if status.LatestHandshake.IsZero() {
		return nil
	}
	if status.LatestHandshake.Location() != time.UTC {
		return errors.New("direct AWG handshake time must be UTC")
	}
	if status.LatestHandshake.After(now.Add(maxClockSkew)) {
		if baseline {
			return errors.New("direct AWG baseline handshake is in the future")
		}
		return errors.New("direct AWG handshake is in the future")
	}
	return nil
}

func listenLoopback(address string) (*net.UDPConn, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	network := "udp6"
	if ip.To4() != nil {
		network = "udp4"
	}
	return net.ListenUDP(network, &net.UDPAddr{IP: ip, Port: port})
}

func validateLoopbackEndpoint(endpoint string) error {
	if err := validateIPLiteralEndpoint(endpoint, true); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(endpoint)
	if !net.ParseIP(host).IsLoopback() {
		return errors.New("relay endpoint is not loopback")
	}
	return nil
}

func validateIPLiteralEndpoint(endpoint string, allowZeroPort bool) error {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" || net.ParseIP(host) == nil {
		return errors.New("endpoint must use an IP literal")
	}
	port, err := strconv.Atoi(portText)
	minimum := 1
	if allowZeroPort {
		minimum = 0
	}
	if err != nil || port < minimum || port > 65535 {
		return errors.New("endpoint port is invalid")
	}
	return nil
}

func validatePublicKey(value string) error {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 32 {
		clear(decoded)
		return errors.New("direct AWG public key must encode 32 bytes")
	}
	var nonzero byte
	for _, current := range decoded {
		nonzero |= current
	}
	clear(decoded)
	if nonzero == 0 {
		return errors.New("direct AWG public key must not be all zero")
	}
	return nil
}

func genericUDPDialer(dialer RemoteDialer) bool {
	switch dialer.(type) {
	case UDPDialer, *UDPDialer:
		return true
	default:
		return false
	}
}
