package h3candidate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/wcf3"
)

type connectionConfig struct {
	descriptor       connectivity.CandidateDescriptor
	binding          connectivity.Binding
	sessionExpiresAt time.Time
	frameContext     wcf3.Context
	carrierPath      net.PacketConn
	underlay         ProtectedUnderlay
	underlayHealth   <-chan error
	session          TunnelSession
	sessionHealth    <-chan error
	verifier         CandidateVerifier
	transaction      RouteDNSTransaction
	lifetimeContext  context.Context
	cancelLifetime   context.CancelFunc
	now              func() time.Time
	teardownTimeout  time.Duration
}

type connection struct {
	descriptor       connectivity.CandidateDescriptor
	binding          connectivity.Binding
	sessionExpiresAt time.Time
	frameContext     wcf3.Context
	carrierPath      net.PacketConn
	underlay         ProtectedUnderlay
	underlayHealth   <-chan error
	session          TunnelSession
	sessionHealth    <-chan error
	verifier         CandidateVerifier
	transaction      RouteDNSTransaction
	now              func() time.Time
	teardownTimeout  time.Duration

	lifetimeContext context.Context
	cancelLifetime  context.CancelFunc

	mu         sync.Mutex
	operations sync.WaitGroup
	closed     bool
	committed  bool

	commitMu    sync.Mutex
	closeOnce   sync.Once
	closeStart  sync.Once
	closeMu     sync.Mutex
	closeErr    error
	fullyClosed bool

	health     chan error
	healthOnce sync.Once
}

type MigratableConnection interface {
	connectivity.CandidateConnection
	MigratePath(
		context.Context,
		connectivity.Binding,
		net.PacketConn,
	) error
}

var (
	_ connectivity.CandidateConnection = (*connection)(nil)
	_ MigratableConnection             = (*connection)(nil)
)

func newConnection(config connectionConfig) *connection {
	result := &connection{
		descriptor:       config.descriptor,
		binding:          config.binding,
		sessionExpiresAt: config.sessionExpiresAt,
		frameContext:     config.frameContext,
		carrierPath:      config.carrierPath,
		underlay:         config.underlay,
		underlayHealth:   config.underlayHealth,
		session:          config.session,
		sessionHealth:    config.sessionHealth,
		verifier:         config.verifier,
		transaction:      config.transaction,
		now:              config.now,
		lifetimeContext:  config.lifetimeContext,
		cancelLifetime:   config.cancelLifetime,
		teardownTimeout:  config.teardownTimeout,
		health:           make(chan error, 1),
	}
	go result.monitorHealth()
	return result
}

func (connection *connection) FreshAWGHandshake(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	operationContext, done, err := connection.beginOperation(ctx, binding)
	if err != nil {
		return err
	}
	defer done()
	return connection.session.FreshAWGHandshake(
		operationContext,
		connection.binding,
		connection.frameContext,
	)
}

func (connection *connection) VerifyBidirectional(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	operationContext, done, err := connection.beginOperation(ctx, binding)
	if err != nil {
		return err
	}
	defer done()
	return connection.session.VerifyBidirectional(
		operationContext,
		connection.binding,
		connection.frameContext,
	)
}

func (connection *connection) VerifyProtectedDNS(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	operationContext, done, err := connection.beginOperation(ctx, binding)
	if err != nil {
		return err
	}
	defer done()
	return connection.verifier.VerifyProtectedDNS(
		operationContext,
		connection.session,
		connection.binding,
		connection.frameContext,
	)
}

func (connection *connection) VerifyTunnelCanary(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	operationContext, done, err := connection.beginOperation(ctx, binding)
	if err != nil {
		return err
	}
	defer done()
	return connection.verifier.VerifyTunnelCanary(
		operationContext,
		connection.session,
		connection.binding,
		connection.frameContext,
	)
}

func (connection *connection) Commit(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	operationContext, done, err := connection.beginOperation(ctx, binding)
	if err != nil {
		return err
	}
	defer done()

	connection.commitMu.Lock()
	defer connection.commitMu.Unlock()
	connection.mu.Lock()
	if connection.closed {
		connection.mu.Unlock()
		return ErrClosed
	}
	if connection.committed {
		connection.mu.Unlock()
		return nil
	}
	connection.mu.Unlock()

	if err := connection.transaction.Commit(
		operationContext,
		connection.binding,
		connection.frameContext,
	); err != nil {
		return err
	}
	connection.mu.Lock()
	if connection.closed {
		connection.mu.Unlock()
		return ErrClosed
	}
	connection.committed = true
	connection.mu.Unlock()
	return nil
}

func (connection *connection) Health() <-chan error {
	return connection.health
}

// MigratePath preserves the authenticated H3 CONNECT-UDP stream. Production
// requires the same underlay lease to protect the replacement socket before it
// reaches carrier.PathMigrator. The adapter consumes and closes socket on any
// failure.
func (connection *connection) MigratePath(
	ctx context.Context,
	binding connectivity.Binding,
	socket net.PacketConn,
) error {
	if nilInterface(socket) {
		return errors.New("H3 migration socket is required")
	}
	operationContext, done, err := connection.beginOperation(ctx, binding)
	if err != nil {
		_ = socket.Close()
		return err
	}
	defer done()
	if nilInterface(connection.underlay) {
		_ = socket.Close()
		return errors.New("H3 migration requires protected underlay")
	}
	if err := connection.underlay.ProtectMigrationSocket(
		operationContext, connection.binding, socket,
	); err != nil {
		_ = socket.Close()
		return fmt.Errorf("protect H3 migration socket: %w", err)
	}
	migrator, ok := connection.carrierPath.(carrier.PathMigrator)
	if !ok {
		_ = socket.Close()
		return errors.New("H3 carrier path does not support QUIC migration")
	}
	if err := migrator.MigratePath(operationContext, socket); err != nil {
		return err
	}
	return nil
}

func (connection *connection) Close() error {
	connection.closeOnce.Do(func() {
		_ = connection.retryClose()
	})
	connection.closeMu.Lock()
	defer connection.closeMu.Unlock()
	return connection.closeErr
}

// RetryClose resumes a failed H3 rollback without weakening Close's
// idempotence for ordinary callers.
func (connection *connection) RetryClose() error {
	return connection.retryClose()
}

func (connection *connection) retryClose() error {
	connection.closeStart.Do(func() {
		connection.mu.Lock()
		connection.closed = true
		connection.mu.Unlock()
		connection.cancelLifetime()
	})
	connection.closeMu.Lock()
	defer connection.closeMu.Unlock()
	if connection.fullyClosed {
		return connection.closeErr
	}

	// Cancel first, then close the packet carrier before waiting for active
	// operations. A QUIC read can otherwise retain its stream while
	// operations.Wait blocks the very Close that would wake it.
	var carrierWakeErr error
	if !nilInterface(connection.carrierPath) {
		carrierWakeErr = normalizeClosedError(
			connection.carrierPath.Close(),
		)
	}
	operationsErr := waitGroupWithTimeout(
		&connection.operations, connection.teardownTimeout,
	)

	connection.commitMu.Lock()
	connection.closeErr = cleanupWithTimeout(
		connection.teardownTimeout,
		connection.transaction,
		connection.session,
		nil,
		connection.underlay,
	)
	connection.commitMu.Unlock()
	connection.closeErr = errors.Join(
		carrierWakeErr, operationsErr, connection.closeErr,
	)
	terminal := error(ErrClosed)
	if connection.closeErr != nil {
		terminal = errors.Join(ErrClosed, connection.closeErr)
	}
	connection.publishHealth(terminal)
	connection.fullyClosed = connection.closeErr == nil
	return connection.closeErr
}

func waitGroupWithTimeout(
	group *sync.WaitGroup,
	timeout time.Duration,
) error {
	done := make(chan struct{})
	go func() {
		group.Wait()
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return errors.New(
			"H3 candidate operations exceeded teardown timeout",
		)
	}
}

func cleanupWithTimeout(
	timeout time.Duration,
	transaction RouteDNSTransaction,
	session TunnelSession,
	carrierPath net.PacketConn,
	underlay ProtectedUnderlay,
) error {
	teardownContext, cancelTeardown := context.WithTimeout(
		context.Background(), timeout,
	)
	defer cancelTeardown()

	var rollbackErr error
	if !nilInterface(transaction) {
		rollbackErr = transaction.Rollback(teardownContext)
	}
	var sessionErr error
	if !nilInterface(session) {
		sessionErr = session.Close(teardownContext)
	}
	var carrierErr error
	if !nilInterface(carrierPath) {
		carrierErr = normalizeClosedError(carrierPath.Close())
	}
	var underlayErr error
	if !nilInterface(underlay) {
		underlayErr = underlay.Close(teardownContext)
	}
	return errors.Join(
		rollbackErr,
		sessionErr,
		carrierErr,
		underlayErr,
	)
}

func (connection *connection) beginOperation(
	ctx context.Context,
	binding connectivity.Binding,
) (context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, errors.New("H3 candidate operation context is required")
	}
	connection.mu.Lock()
	if connection.closed {
		connection.mu.Unlock()
		return nil, nil, ErrClosed
	}
	committed := connection.committed
	if err := connection.validateBinding(binding, committed); err != nil {
		connection.mu.Unlock()
		return nil, nil, err
	}
	connection.operations.Add(1)
	connection.mu.Unlock()

	operationContext, cancel := context.WithCancel(ctx)
	stopLifetimeBridge := context.AfterFunc(
		connection.lifetimeContext, cancel,
	)
	done := func() {
		stopLifetimeBridge()
		cancel()
		connection.operations.Done()
	}
	return operationContext, done, nil
}

func (connection *connection) validateBinding(
	binding connectivity.Binding,
	committed bool,
) error {
	now := connection.now().UTC()
	if !equalBinding(connection.binding, binding) {
		return ErrBindingMismatch
	}
	if !connection.sessionExpiresAt.After(now) {
		return ErrSessionExpired
	}
	if !committed {
		if err := binding.Validate(now); err != nil {
			return fmt.Errorf("H3 candidate operation binding: %w", err)
		}
	}
	frameContext, err := wcf3.ContextFromBinding(binding, now)
	if committed && !binding.ExpiresAt.After(now) {
		frameContext = connection.frameContext
		err = nil
	}
	if err != nil || frameContext != connection.frameContext {
		return ErrBindingMismatch
	}
	return nil
}

func (connection *connection) monitorHealth() {
	duration := time.Until(connection.sessionExpiresAt)
	if connection.now != nil {
		duration = connection.sessionExpiresAt.Sub(
			connection.now().UTC(),
		)
	}
	if duration < 0 {
		duration = 0
	}
	expiry := time.NewTimer(duration)
	defer expiry.Stop()

	var terminal error
	select {
	case <-connection.lifetimeContext.Done():
		return
	case value, ok := <-connection.sessionHealth:
		terminal = healthTerminal(
			"AWG tunnel session", value, ok,
		)
	case value, ok := <-connection.underlayHealth:
		terminal = healthTerminal(
			"protected H3 underlay", value, ok,
		)
	case <-expiry.C:
		terminal = ErrSessionExpired
	}
	connection.publishHealth(terminal)
	_ = connection.Close()
}

func (connection *connection) publishHealth(err error) {
	if err == nil {
		err = errors.New("H3 candidate health failed without reason")
	}
	connection.healthOnce.Do(func() {
		connection.health <- err
		close(connection.health)
	})
}

func healthTerminal(source string, err error, ok bool) error {
	if !ok {
		return fmt.Errorf("%s health channel closed", source)
	}
	if err == nil {
		return fmt.Errorf("%s health failed without reason", source)
	}
	return fmt.Errorf("%s health failed: %w", source, err)
}

func normalizeClosedError(err error) error {
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func equalBinding(left, right connectivity.Binding) bool {
	return left.AttemptID == right.AttemptID &&
		left.Profile == right.Profile &&
		left.Mode == right.Mode &&
		left.ManifestDigest == right.ManifestDigest &&
		left.CandidateID == right.CandidateID &&
		left.NodeID == right.NodeID &&
		left.SessionID == right.SessionID &&
		left.PSKGeneration == right.PSKGeneration &&
		left.SequenceEpoch == right.SequenceEpoch &&
		left.Nonce == right.Nonce &&
		left.ExpiresAt.Equal(right.ExpiresAt)
}
