package h3candidate

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
	"winsvpn.local/winnprotocol/internal/directawg"
	"winsvpn.local/winnprotocol/internal/wcf3"
)

const (
	defaultLinuxAWGPollInterval = 10 * time.Millisecond
	maxLinuxAWGClockSkew        = time.Second
)

// LinuxAWGOverH3Config adapts the real DirectAWG Linux controller to an
// authenticated H3 CONNECT-UDP PacketConn. GatewayEndpoint is the signed fixed
// AWG backend and must be an IP literal. The local relay is candidate-isolated.
type LinuxAWGOverH3Config struct {
	Controller        directawg.TunnelController
	GatewayEndpoint   string
	GatewayPublicKey  string
	LocalRelayAddress string
	MinInnerDatagram  int
	MaxInnerDatagram  int
	IdleTimeout       time.Duration
	PollInterval      time.Duration
	RelayBatchSize    int
	SocketBufferBytes int
	Now               func() time.Time
}

type linuxAWGOverH3Controller struct {
	config LinuxAWGOverH3Config
}

// NewLinuxAWGOverH3Controller constructs the real inner-AWG adapter. Its
// controller should normally come from directawg.NewLinuxController.
func NewLinuxAWGOverH3Controller(
	config LinuxAWGOverH3Config,
) (TunnelController, error) {
	if nilInterface(config.Controller) {
		return nil, errors.New(
			"linux AWG-over-H3 requires a DirectAWG tunnel controller",
		)
	}
	if err := validateIPLiteralEndpoint(
		config.GatewayEndpoint, false,
	); err != nil {
		return nil, fmt.Errorf("linux H3 fixed AWG backend: %w", err)
	}
	if err := validateAWGPublicKey(config.GatewayPublicKey); err != nil {
		return nil, err
	}
	if config.LocalRelayAddress == "" {
		config.LocalRelayAddress = "127.0.0.1:0"
	}
	if err := validateLoopbackEndpoint(config.LocalRelayAddress, true); err != nil {
		return nil, fmt.Errorf("linux H3 local relay: %w", err)
	}
	if config.MinInnerDatagram < 576 ||
		config.MaxInnerDatagram < config.MinInnerDatagram ||
		config.MaxInnerDatagram > carrier.AbsoluteMaxDatagram {
		return nil, errors.New("linux H3 inner datagram range is invalid")
	}
	if config.IdleTimeout < 0 {
		return nil, errors.New("linux H3 relay idle timeout is invalid")
	}
	if config.PollInterval == 0 {
		config.PollInterval = defaultLinuxAWGPollInterval
	}
	if config.PollInterval < time.Millisecond ||
		config.PollInterval > 250*time.Millisecond {
		return nil, errors.New("linux H3 AWG status poll interval is invalid")
	}
	if config.RelayBatchSize < 0 ||
		config.RelayBatchSize > carrier.MaxRelayBatchSize {
		return nil, errors.New("linux H3 relay batch size is invalid")
	}
	if config.SocketBufferBytes < 0 ||
		config.SocketBufferBytes > carrier.MaxRelaySocketBufferBytes {
		return nil, errors.New("linux H3 relay socket buffer size is invalid")
	}
	if config.SocketBufferBytes != 0 {
		return nil, errors.New(
			"linux H3 carrier relay does not expose raw socket buffers",
		)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &linuxAWGOverH3Controller{config: config}, nil
}

func (controller *linuxAWGOverH3Controller) Start(
	ctx context.Context,
	carrierPath net.PacketConn,
	binding connectivity.Binding,
	frameContext wcf3.Context,
) (_ TunnelSession, resultErr error) {
	if ctx == nil {
		return nil, errors.New("linux AWG-over-H3 context is required")
	}
	if nilInterface(carrierPath) {
		return nil, errors.New("linux AWG-over-H3 carrier path is required")
	}
	now := controller.config.Now().UTC()
	if err := validateAdapterContext(binding, frameContext, now); err != nil {
		return nil, err
	}
	local, err := listenLoopbackUDP(controller.config.LocalRelayAddress)
	if err != nil {
		return nil, fmt.Errorf("listen for Linux H3 AWG packets: %w", err)
	}
	localOwned := true
	defer func() {
		if localOwned {
			resultErr = errors.Join(resultErr, normalizeClosedError(local.Close()))
		}
	}()

	prepared, err := controller.config.Controller.Prepare(
		ctx,
		directawg.Preparation{
			Binding:          binding,
			RelayEndpoint:    local.LocalAddr().String(),
			GatewayEndpoint:  controller.config.GatewayEndpoint,
			GatewayPublicKey: controller.config.GatewayPublicKey,
			MinInnerDatagram: controller.config.MinInnerDatagram,
			MaxInnerDatagram: controller.config.MaxInnerDatagram,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("prepare Linux inner AWG over H3: %w", err)
	}
	if nilInterface(prepared.Session) {
		return nil, errors.New(
			"linux DirectAWG controller returned no inner session",
		)
	}
	contextualSession, ok := prepared.Session.(directawg.ContextTunnelSession)
	if !ok || nilInterface(contextualSession) {
		_ = prepared.Session.Close()
		return nil, errors.New(
			"linux H3 requires a context-bounded DirectAWG session",
		)
	}
	sessionOwned := true
	defer func() {
		if sessionOwned {
			resultErr = errors.Join(
				resultErr,
				contextualSession.CloseContext(context.Background()),
			)
		}
	}()
	if contextualSession.Health() == nil {
		return nil, errors.New(
			"linux DirectAWG controller returned no health stream",
		)
	}
	expectedPeer, err := resolveExpectedAWGPeer(
		prepared.LocalSourceEndpoint, local.LocalAddr(),
	)
	if err != nil {
		return nil, err
	}
	if err := validateLinuxAWGStatus(
		prepared.Baseline,
		controller.config.GatewayPublicKey,
		local.LocalAddr().String(),
		now,
		true,
	); err != nil {
		return nil, fmt.Errorf("linux H3 inner AWG baseline: %w", err)
	}
	if !prepared.Baseline.LatestHandshake.IsZero() ||
		prepared.Baseline.RxBytes != 0 ||
		prepared.Baseline.TxBytes != 0 {
		return nil, errors.New(
			"linux H3 inner AWG requires a fresh zero peer baseline",
		)
	}

	relayContext, cancelRelay := context.WithCancel(ctx)
	session := &linuxAWGOverH3Session{
		binding:          binding,
		frameContext:     frameContext,
		direct:           contextualSession,
		baseline:         prepared.Baseline,
		expectedKey:      controller.config.GatewayPublicKey,
		expectedEndpoint: local.LocalAddr().String(),
		startedAt:        now,
		pollInterval:     controller.config.PollInterval,
		now:              controller.config.Now,
		local:            local,
		carrierPath:      carrierPath,
		cancelRelay:      cancelRelay,
		relayDone:        make(chan struct{}),
		closing:          make(chan struct{}),
		closeGate:        make(chan struct{}, 1),
		health:           make(chan error, 1),
	}
	session.closeGate <- struct{}{}
	go session.runRelay(relayContext, carrier.RelayConfig{
		MaxDatagram:       controller.config.MaxInnerDatagram,
		IdleTimeout:       controller.config.IdleTimeout,
		ExpectedLocalPeer: expectedPeer,
		BatchSize:         controller.config.RelayBatchSize,
		SocketBufferBytes: controller.config.SocketBufferBytes,
	})
	go session.monitor()
	localOwned = false
	sessionOwned = false
	return session, nil
}

type linuxAWGOverH3Session struct {
	binding      connectivity.Binding
	frameContext wcf3.Context
	direct       directawg.ContextTunnelSession
	baseline     directawg.Status

	expectedKey      string
	expectedEndpoint string
	startedAt        time.Time
	pollInterval     time.Duration
	now              func() time.Time

	local       *net.UDPConn
	carrierPath net.PacketConn
	cancelRelay context.CancelFunc
	relayDone   chan struct{}
	closing     chan struct{}

	mu          sync.RWMutex
	relayErr    error
	terminalErr error

	health     chan error
	healthOnce sync.Once
	closeStart sync.Once
	closeGate  chan struct{}

	relayStopped bool
	directClosed bool
	fullyClosed  bool
	closeErr     error
}

var _ TunnelSession = (*linuxAWGOverH3Session)(nil)

func (session *linuxAWGOverH3Session) FreshAWGHandshake(
	ctx context.Context,
	binding connectivity.Binding,
	frameContext wcf3.Context,
) error {
	if err := session.check(ctx, binding, frameContext); err != nil {
		return err
	}
	return session.poll(ctx, func(status directawg.Status) (bool, error) {
		if status.LatestHandshake.IsZero() {
			return false, nil
		}
		floor := session.startedAt.Truncate(time.Second)
		if status.LatestHandshake.Before(floor) {
			return false, nil
		}
		if session.baseline.LatestHandshake.IsZero() {
			return true, nil
		}
		return status.LatestHandshake.After(
			session.baseline.LatestHandshake,
		), nil
	})
}

func (session *linuxAWGOverH3Session) VerifyBidirectional(
	ctx context.Context,
	binding connectivity.Binding,
	frameContext wcf3.Context,
) error {
	if err := session.check(ctx, binding, frameContext); err != nil {
		return err
	}
	return session.poll(ctx, func(status directawg.Status) (bool, error) {
		if status.RxBytes < session.baseline.RxBytes ||
			status.TxBytes < session.baseline.TxBytes {
			return false, errors.New("linux H3 AWG counters regressed")
		}
		return status.RxBytes > session.baseline.RxBytes &&
			status.TxBytes > session.baseline.TxBytes, nil
	})
}

func (session *linuxAWGOverH3Session) Health() <-chan error {
	return session.health
}

func (session *linuxAWGOverH3Session) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	session.closeStart.Do(func() {
		close(session.closing)
		session.cancelRelay()
		_ = session.local.SetDeadline(time.Now())
		_ = session.carrierPath.SetDeadline(time.Now())
	})
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-session.closeGate:
	}
	defer func() { session.closeGate <- struct{}{} }()
	if session.fullyClosed {
		return session.closeErr
	}
	if !session.relayStopped {
		if err := waitChannel(ctx, session.relayDone); err != nil {
			return err
		}
		// A relay outage is already delivered on Health. It is not a
		// route/DNS teardown failure and must not poison reconnect after the
		// inner Direct-AWG session rolls back successfully.
		session.relayStopped = true
	}
	if !session.directClosed {
		if err := session.direct.CloseContext(ctx); err != nil {
			return err
		}
		session.directClosed = true
	}
	session.fullyClosed = true
	session.healthOnce.Do(func() { close(session.health) })
	return session.closeErr
}

func (session *linuxAWGOverH3Session) runRelay(
	ctx context.Context,
	config carrier.RelayConfig,
) {
	// RelayLocalUDP closes this view, not the H3 carrier itself. Candidate
	// cleanup owns carrierPath and closes it only after Session.Close returns.
	view := nonClosingPacketConn{PacketConn: session.carrierPath}
	err := carrier.RelayLocalUDP(ctx, session.local, view, config)
	session.mu.Lock()
	session.relayErr = err
	session.mu.Unlock()
	close(session.relayDone)
}

func (session *linuxAWGOverH3Session) monitor() {
	select {
	case <-session.closing:
		return
	case <-session.relayDone:
		session.mu.RLock()
		err := session.relayErr
		session.mu.RUnlock()
		if err == nil {
			err = errors.New("linux H3 AWG relay stopped")
		}
		session.publishHealth(fmt.Errorf(
			"linux H3 AWG relay failed: %w", err,
		))
	case err, ok := <-session.direct.Health():
		if !ok || err == nil {
			err = errors.New(
				"linux DirectAWG session health stream terminated",
			)
		}
		session.publishHealth(fmt.Errorf(
			"linux H3 inner AWG failed: %w", err,
		))
	}
}

func (session *linuxAWGOverH3Session) publishHealth(err error) {
	session.mu.Lock()
	session.terminalErr = err
	session.mu.Unlock()
	session.healthOnce.Do(func() {
		session.health <- err
		close(session.health)
	})
}

func (session *linuxAWGOverH3Session) check(
	ctx context.Context,
	binding connectivity.Binding,
	frameContext wcf3.Context,
) error {
	if ctx == nil {
		return errors.New("linux H3 AWG operation context is required")
	}
	if err := validateExpectedAdapterContext(
		session.binding, session.frameContext,
		binding, frameContext, session.now().UTC(),
	); err != nil {
		return err
	}
	select {
	case <-session.closing:
		return ErrClosed
	default:
	}
	session.mu.RLock()
	terminal := session.terminalErr
	session.mu.RUnlock()
	if terminal != nil {
		return fmt.Errorf("linux H3 AWG health failed: %w", terminal)
	}
	return nil
}

func (session *linuxAWGOverH3Session) poll(
	ctx context.Context,
	accept func(directawg.Status) (bool, error),
) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-session.closing:
			return ErrClosed
		case <-session.relayDone:
			return session.relayFailure()
		case <-timer.C:
			status, err := session.direct.Status(ctx)
			if err != nil {
				return err
			}
			if err := validateLinuxAWGStatus(
				status,
				session.expectedKey,
				session.expectedEndpoint,
				session.now().UTC(),
				false,
			); err != nil {
				return err
			}
			ok, err := accept(status)
			if err != nil {
				return err
			}
			if ok {
				return nil
			}
			timer.Reset(session.pollInterval)
		}
	}
}

func (session *linuxAWGOverH3Session) relayFailure() error {
	session.mu.RLock()
	err := session.relayErr
	session.mu.RUnlock()
	if err == nil {
		return errors.New("linux H3 AWG relay stopped")
	}
	return fmt.Errorf("linux H3 AWG relay stopped: %w", err)
}

func (session *linuxAWGOverH3Session) verifyProtectedDNS(
	ctx context.Context,
	binding connectivity.Binding,
	frameContext wcf3.Context,
) error {
	if err := session.check(ctx, binding, frameContext); err != nil {
		return err
	}
	if err := session.direct.VerifyProtectedDNS(ctx, binding); err != nil {
		return err
	}
	return session.check(ctx, binding, frameContext)
}

func (session *linuxAWGOverH3Session) verifyTunnelCanary(
	ctx context.Context,
	binding connectivity.Binding,
	frameContext wcf3.Context,
) error {
	if err := session.check(ctx, binding, frameContext); err != nil {
		return err
	}
	if err := session.direct.VerifyTunnelCanary(ctx, binding); err != nil {
		return err
	}
	return session.check(ctx, binding, frameContext)
}

func (session *linuxAWGOverH3Session) commitRouteDNS(
	ctx context.Context,
	binding connectivity.Binding,
	frameContext wcf3.Context,
) error {
	if err := session.check(ctx, binding, frameContext); err != nil {
		return err
	}
	if err := session.direct.Commit(ctx, binding); err != nil {
		return err
	}
	return session.check(ctx, binding, frameContext)
}

func (session *linuxAWGOverH3Session) rollbackRouteDNS(
	ctx context.Context,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// directawg.TunnelSession.Close is idempotent and synchronously engages
	// the kill switch before restoring resolver state and removing routes.
	return session.direct.CloseContext(ctx)
}

// LinuxCandidateVerifierAdapter delegates DNS and canary predicates to the
// exact DirectAWG Linux session behind this H3 candidate.
type LinuxCandidateVerifierAdapter struct{}

func NewLinuxCandidateVerifierAdapter() CandidateVerifier {
	return LinuxCandidateVerifierAdapter{}
}

func (LinuxCandidateVerifierAdapter) VerifyProtectedDNS(
	ctx context.Context,
	session TunnelSession,
	binding connectivity.Binding,
	frameContext wcf3.Context,
) error {
	adapted, ok := session.(*linuxAWGOverH3Session)
	if !ok || adapted == nil {
		return errors.New(
			"linux H3 DNS verifier requires its AWG-over-H3 session",
		)
	}
	return adapted.verifyProtectedDNS(ctx, binding, frameContext)
}

func (LinuxCandidateVerifierAdapter) VerifyTunnelCanary(
	ctx context.Context,
	session TunnelSession,
	binding connectivity.Binding,
	frameContext wcf3.Context,
) error {
	adapted, ok := session.(*linuxAWGOverH3Session)
	if !ok || adapted == nil {
		return errors.New(
			"linux H3 canary verifier requires its AWG-over-H3 session",
		)
	}
	return adapted.verifyTunnelCanary(ctx, binding, frameContext)
}

// LinuxRouteDNSTransactionFactory exposes the DirectAWG Linux session's staged
// route, resolver, and kill-switch transaction through the H3 candidate
// contract.
type LinuxRouteDNSTransactionFactory struct{}

func NewLinuxRouteDNSTransactionFactory() TransactionFactory {
	return LinuxRouteDNSTransactionFactory{}
}

func (LinuxRouteDNSTransactionFactory) Prepare(
	ctx context.Context,
	session TunnelSession,
	binding connectivity.Binding,
	frameContext wcf3.Context,
) (RouteDNSTransaction, error) {
	if ctx == nil {
		return nil, errors.New(
			"linux H3 route/DNS prepare context is required",
		)
	}
	adapted, ok := session.(*linuxAWGOverH3Session)
	if !ok || adapted == nil {
		return nil, errors.New(
			"linux H3 route/DNS transaction requires its AWG-over-H3 session",
		)
	}
	if err := adapted.check(ctx, binding, frameContext); err != nil {
		return nil, err
	}
	return &linuxRouteDNSTransaction{
		session:      adapted,
		binding:      binding,
		frameContext: frameContext,
	}, nil
}

type linuxRouteDNSTransaction struct {
	session      *linuxAWGOverH3Session
	binding      connectivity.Binding
	frameContext wcf3.Context

	mu         sync.Mutex
	committed  bool
	rolledBack bool
}

func (transaction *linuxRouteDNSTransaction) Commit(
	ctx context.Context,
	binding connectivity.Binding,
	frameContext wcf3.Context,
) error {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.rolledBack {
		return errors.New("linux H3 route/DNS transaction was rolled back")
	}
	if !equalBinding(transaction.binding, binding) ||
		transaction.frameContext != frameContext {
		return ErrBindingMismatch
	}
	if transaction.committed {
		return nil
	}
	if err := transaction.session.commitRouteDNS(
		ctx, binding, frameContext,
	); err != nil {
		return err
	}
	transaction.committed = true
	return nil
}

func (transaction *linuxRouteDNSTransaction) Rollback(
	ctx context.Context,
) error {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.rolledBack {
		return nil
	}
	err := transaction.session.rollbackRouteDNS(ctx)
	if err == nil {
		transaction.rolledBack = true
	}
	return err
}

type nonClosingPacketConn struct {
	net.PacketConn
}

func (nonClosingPacketConn) Close() error {
	return nil
}

func validateAdapterContext(
	binding connectivity.Binding,
	frameContext wcf3.Context,
	now time.Time,
) error {
	if err := binding.Validate(now); err != nil {
		return fmt.Errorf("linux H3 adapter binding: %w", err)
	}
	derived, err := wcf3.ContextFromBinding(binding, now)
	if err != nil || derived != frameContext {
		return ErrBindingMismatch
	}
	return nil
}

func validateExpectedAdapterContext(
	expectedBinding connectivity.Binding,
	expectedFrame wcf3.Context,
	binding connectivity.Binding,
	frameContext wcf3.Context,
	now time.Time,
) error {
	if err := validateAdapterContext(binding, frameContext, now); err != nil {
		return err
	}
	if !equalBinding(expectedBinding, binding) ||
		expectedFrame != frameContext {
		return ErrBindingMismatch
	}
	return nil
}

func validateLinuxAWGStatus(
	status directawg.Status,
	expectedKey string,
	expectedEndpoint string,
	now time.Time,
	baseline bool,
) error {
	if status.PeerPublicKey != expectedKey {
		return errors.New("linux H3 AWG status reports the wrong peer key")
	}
	if status.PeerEndpoint != expectedEndpoint {
		return errors.New("linux H3 AWG status reports the wrong relay endpoint")
	}
	if status.LatestHandshake.IsZero() {
		return nil
	}
	if status.LatestHandshake.Location() != time.UTC ||
		status.LatestHandshake.After(now.Add(maxLinuxAWGClockSkew)) {
		if baseline {
			return errors.New("linux H3 AWG baseline handshake is invalid")
		}
		return errors.New("linux H3 AWG handshake time is invalid")
	}
	return nil
}

func resolveExpectedAWGPeer(
	endpoint string,
	relayAddress net.Addr,
) (*net.UDPAddr, error) {
	if err := validateLoopbackEndpoint(endpoint, false); err != nil {
		return nil, fmt.Errorf("linux H3 AWG local source: %w", err)
	}
	expected, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil || expected.Port == 0 {
		return nil, errors.New("linux H3 AWG local source is invalid")
	}
	relay, ok := relayAddress.(*net.UDPAddr)
	if !ok || relay == nil || !expected.IP.Equal(relay.IP) {
		return nil, errors.New(
			"linux H3 AWG source and relay address families differ",
		)
	}
	return expected, nil
}

func listenLoopbackUDP(address string) (*net.UDPConn, error) {
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

func validateLoopbackEndpoint(endpoint string, allowZero bool) error {
	if err := validateIPLiteralEndpoint(endpoint, allowZero); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(endpoint)
	if !net.ParseIP(host).IsLoopback() {
		return errors.New("endpoint is not loopback")
	}
	return nil
}

func validateIPLiteralEndpoint(endpoint string, allowZero bool) error {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" || net.ParseIP(host) == nil {
		return errors.New("endpoint must use an IP literal")
	}
	port, err := strconv.Atoi(portText)
	minimum := 1
	if allowZero {
		minimum = 0
	}
	if err != nil || port < minimum || port > 65535 {
		return errors.New("endpoint port is invalid")
	}
	return nil
}

func validateAWGPublicKey(value string) error {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 32 {
		clear(decoded)
		return errors.New("linux H3 AWG public key must encode 32 bytes")
	}
	var nonzero byte
	for _, current := range decoded {
		nonzero |= current
	}
	clear(decoded)
	if nonzero == 0 {
		return errors.New("linux H3 AWG public key must be nonzero")
	}
	return nil
}

func waitChannel(ctx context.Context, channel <-chan struct{}) error {
	select {
	case <-channel:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}
