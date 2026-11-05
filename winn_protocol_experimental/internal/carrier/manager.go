package carrier

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"winsvpn.local/winnprotocol/internal/mobility"
	"winsvpn.local/winnprotocol/internal/observability"
)

type Dialer interface {
	Dial(context.Context) (net.PacketConn, error)
}

type Candidate struct {
	Path   mobility.Path
	Dialer Dialer
}

type ManagerConfig struct {
	DialTimeout        time.Duration
	RecoveryInitial    time.Duration
	RecoveryMaximum    time.Duration
	HandoffRedundancy  time.Duration
	RedundantDatagrams int
	CoverIntervalMin   time.Duration
	CoverIntervalMax   time.Duration
	CoverDatagramSize  int
	Metrics            *observability.Registry
}

func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		DialTimeout:        10 * time.Second,
		RecoveryInitial:    100 * time.Millisecond,
		RecoveryMaximum:    5 * time.Second,
		RedundantDatagrams: 64,
	}
}

type activeCarrier struct {
	pathID string
	conn   net.PacketConn
	cancel context.CancelFunc
}

// Manager is a fail-closed, self-healing PacketConn. It never creates a raw
// network bypass. Reads and writes resume only after another configured carrier
// has completed its authenticated handshake.
type Manager struct {
	ctx    context.Context
	cancel context.CancelFunc
	engine *mobility.Engine
	config ManagerConfig

	candidates        map[string]Candidate
	connectMu         sync.Mutex
	activeMu          sync.RWMutex
	active            *activeCarrier
	previous          *activeCarrier
	previousUntil     time.Time
	previousRemaining int
	sendSequence      atomic.Uint64

	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time

	closeOnce sync.Once
}

func NewManager(parent context.Context, sessionID string, tunnelGeneration uint64, candidates []Candidate, mobilityConfig mobility.Config, config ManagerConfig) (*Manager, error) {
	if parent == nil {
		return nil, errors.New("manager parent context is required")
	}
	if config.DialTimeout <= 0 || config.RecoveryInitial <= 0 ||
		config.RecoveryMaximum < config.RecoveryInitial {
		return nil, errors.New("invalid carrier recovery configuration")
	}
	if config.HandoffRedundancy < 0 || config.HandoffRedundancy > time.Second ||
		config.RedundantDatagrams < 0 || config.RedundantDatagrams > 128 {
		return nil, errors.New("handoff redundancy must be bounded to one second and 128 datagrams")
	}
	coverEnabled := config.CoverIntervalMin != 0 ||
		config.CoverIntervalMax != 0 || config.CoverDatagramSize != 0
	if coverEnabled &&
		(config.CoverIntervalMin < 500*time.Millisecond ||
			config.CoverIntervalMax < config.CoverIntervalMin ||
			config.CoverIntervalMax > time.Minute ||
			config.CoverDatagramSize < envelopeHeaderSize ||
			config.CoverDatagramSize > AbsoluteMaxCarrierEnvelope) {
		return nil, errors.New("cover traffic schedule or datagram size is invalid")
	}
	paths := make([]mobility.Path, 0, len(candidates))
	index := make(map[string]Candidate, len(candidates))
	for _, candidate := range candidates {
		if candidate.Dialer == nil {
			return nil, fmt.Errorf("path %q has no dialer", candidate.Path.ID)
		}
		if _, duplicate := index[candidate.Path.ID]; duplicate {
			return nil, fmt.Errorf("duplicate carrier path %q", candidate.Path.ID)
		}
		index[candidate.Path.ID] = candidate
		paths = append(paths, candidate.Path)
	}
	engine, err := mobility.New(sessionID, tunnelGeneration, paths, mobilityConfig)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	manager := &Manager{
		ctx:        ctx,
		cancel:     cancel,
		engine:     engine,
		config:     config,
		candidates: index,
	}
	if coverEnabled {
		go manager.coverLoop()
	}
	return manager, nil
}

func (m *Manager) Connect(ctx context.Context) error {
	_, err := m.ensureActive(ctx)
	return err
}

func (m *Manager) ReadFrom(buffer []byte) (int, net.Addr, error) {
	ctx, cancel := m.operationContext(true)
	defer cancel()
	for {
		active, err := m.ensureActive(ctx)
		if err != nil {
			return 0, nil, err
		}
		if deadline := m.deadline(true); !deadline.IsZero() {
			_ = active.conn.SetReadDeadline(deadline)
		}
		count, _, err := active.conn.ReadFrom(buffer)
		if err == nil {
			return count, fixedAddr(active.pathID), nil
		}
		m.invalidate(active, err)
		if ctx.Err() != nil {
			return 0, nil, deadlineError(ctx)
		}
	}
}

func (m *Manager) WriteTo(packet []byte, _ net.Addr) (int, error) {
	ctx, cancel := m.operationContext(false)
	defer cancel()
	for attempts := 0; ; attempts++ {
		active, err := m.ensureActive(ctx)
		if err != nil {
			return 0, err
		}
		if deadline := m.deadline(false); !deadline.IsZero() {
			_ = active.conn.SetWriteDeadline(deadline)
		}
		count, err := m.writeActive(active, packet)
		if err == nil {
			return count, nil
		}
		m.invalidate(active, err)
		if count > 0 || attempts >= 1 {
			return count, err
		}
		if ctx.Err() != nil {
			return 0, deadlineError(ctx)
		}
	}
}

// MigrateActivePath validates and switches an established HTTP/3 QUIC
// connection to a caller-provided socket without changing the Winn session or
// carrier stream. The active PathMigrator consumes socket on every outcome.
func (m *Manager) MigrateActivePath(ctx context.Context, socket net.PacketConn) error {
	if ctx == nil || socket == nil {
		return errors.New("migration context and socket are required")
	}
	active := m.current()
	if active == nil {
		return errors.New("no active carrier is available for migration")
	}
	migrator, ok := active.conn.(PathMigrator)
	if !ok {
		return errors.New("active carrier does not support in-place QUIC migration")
	}
	started := time.Now()
	if err := migrator.MigratePath(ctx, socket); err != nil {
		m.inc("carrier_quic_migration_failed")
		return err
	}
	m.inc("carrier_quic_migrated")
	m.observe("carrier_quic_migration", time.Since(started))
	return nil
}

func (m *Manager) EffectiveMTU() int {
	active := m.current()
	if active == nil {
		return 0
	}
	if aware, ok := active.conn.(MTUAware); ok {
		return aware.EffectiveMTU()
	}
	return 0
}

// Switch performs make-before-break replacement. A failed probe leaves the old
// authenticated carrier active.
func (m *Manager) Switch(ctx context.Context, pathID string) error {
	candidate, ok := m.candidates[pathID]
	if !ok {
		return fmt.Errorf("unknown carrier path %q", pathID)
	}
	if ctx == nil {
		return errors.New("switch context is required")
	}
	if err := m.engine.BeginProbe(); err != nil {
		return err
	}
	started := time.Now()
	replacement, err := m.dial(ctx, candidate)
	if err != nil {
		_ = m.engine.Observe(mobility.Observation{
			PathID: pathID, Success: false, Loss: 1, At: time.Now(),
		})
		m.inc("carrier_probe_failed")
		return err
	}
	now := time.Now()
	if err := m.engine.Observe(mobility.Observation{
		PathID: pathID, Success: true, RTT: now.Sub(started), At: now,
	}); err != nil {
		_ = replacement.conn.Close()
		replacement.cancel()
		return err
	}
	if err := m.engine.Activate(pathID, now); err != nil {
		_ = replacement.conn.Close()
		replacement.cancel()
		return err
	}
	m.swap(replacement)
	m.inc("carrier_path_switched")
	m.observe("carrier_switch", now.Sub(started))
	return nil
}

func (m *Manager) Snapshot() mobility.Snapshot {
	return m.engine.Snapshot(time.Now())
}

func (m *Manager) LocalAddr() net.Addr {
	return fixedAddr("winn-session:" + m.Snapshot().SessionID)
}

func (m *Manager) SetDeadline(deadline time.Time) error {
	m.deadlineMu.Lock()
	m.readDeadline = deadline
	m.writeDeadline = deadline
	m.deadlineMu.Unlock()
	if active := m.current(); active != nil {
		return active.conn.SetDeadline(deadline)
	}
	return nil
}

func (m *Manager) SetReadDeadline(deadline time.Time) error {
	m.deadlineMu.Lock()
	m.readDeadline = deadline
	m.deadlineMu.Unlock()
	if active := m.current(); active != nil {
		return active.conn.SetReadDeadline(deadline)
	}
	return nil
}

func (m *Manager) SetWriteDeadline(deadline time.Time) error {
	m.deadlineMu.Lock()
	m.writeDeadline = deadline
	m.deadlineMu.Unlock()
	if active := m.current(); active != nil {
		return active.conn.SetWriteDeadline(deadline)
	}
	return nil
}

func (m *Manager) Close() error {
	var closeError error
	m.closeOnce.Do(func() {
		m.cancel()
		m.engine.Close()
		m.activeMu.Lock()
		active := m.active
		previous := m.previous
		m.active = nil
		m.previous = nil
		m.activeMu.Unlock()
		if active != nil {
			active.cancel()
			closeError = active.conn.Close()
		}
		if previous != nil && previous != active {
			previous.cancel()
			closeError = errors.Join(closeError, previous.conn.Close())
		}
	})
	return closeError
}

func (m *Manager) ensureActive(ctx context.Context) (*activeCarrier, error) {
	if active := m.current(); active != nil {
		return active, nil
	}
	m.connectMu.Lock()
	defer m.connectMu.Unlock()
	if active := m.current(); active != nil {
		return active, nil
	}
	if m.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if ctx == nil {
		ctx = m.ctx
	}
	if err := m.engine.BeginProbe(); err != nil {
		return nil, err
	}
	delay := m.config.RecoveryInitial
	recoveryStarted := time.Now()
	for {
		attempted := make(map[string]bool, len(m.candidates))
		for len(attempted) < len(m.candidates) {
			path, err := m.engine.Select(time.Now())
			if err != nil {
				break
			}
			if attempted[path.ID] {
				break
			}
			attempted[path.ID] = true
			candidate := m.candidates[path.ID]
			started := time.Now()
			active, dialErr := m.dial(ctx, candidate)
			now := time.Now()
			if dialErr != nil {
				_ = m.engine.Observe(mobility.Observation{
					PathID: path.ID, Success: false, Loss: 1, At: now,
				})
				m.inc("carrier_dial_failed")
				continue
			}
			if err := m.engine.Observe(mobility.Observation{
				PathID: path.ID, Success: true, RTT: now.Sub(started), At: now,
			}); err != nil {
				_ = active.conn.Close()
				active.cancel()
				return nil, err
			}
			if err := m.engine.Activate(path.ID, now); err != nil {
				_ = active.conn.Close()
				active.cancel()
				return nil, err
			}
			m.swap(active)
			m.inc("carrier_recovered")
			m.observe("carrier_recovery", now.Sub(recoveryStarted))
			return active, nil
		}
		wait := delay + secureJitter(delay/2)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, deadlineError(ctx)
		case <-m.ctx.Done():
			timer.Stop()
			return nil, net.ErrClosed
		case <-timer.C:
		}
		if delay < m.config.RecoveryMaximum/2 {
			delay *= 2
		} else {
			delay = m.config.RecoveryMaximum
		}
	}
}

func (m *Manager) dial(ctx context.Context, candidate Candidate) (*activeCarrier, error) {
	dialContext, cancel := context.WithCancel(m.ctx)
	stopCallerCancellation := context.AfterFunc(ctx, cancel)
	timer := time.AfterFunc(m.config.DialTimeout, cancel)
	connection, err := candidate.Dialer.Dial(dialContext)
	if err != nil {
		timer.Stop()
		stopCallerCancellation()
		cancel()
		return nil, err
	}
	timerStopped := timer.Stop()
	callerStopped := stopCallerCancellation()
	if (!timerStopped && dialContext.Err() != nil) ||
		(!callerStopped && ctx.Err() != nil) {
		_ = connection.Close()
		cancel()
		return nil, context.DeadlineExceeded
	}
	return &activeCarrier{pathID: candidate.Path.ID, conn: connection, cancel: cancel}, nil
}

func (m *Manager) swap(replacement *activeCarrier) {
	m.activeMu.Lock()
	previous := m.active
	stalePrevious := m.previous
	m.active = replacement
	m.previous = nil
	m.previousUntil = time.Time{}
	m.previousRemaining = 0
	if previous != nil && previous != replacement &&
		m.config.HandoffRedundancy > 0 &&
		m.config.RedundantDatagrams > 0 {
		m.previous = previous
		m.previousUntil = time.Now().Add(m.config.HandoffRedundancy)
		m.previousRemaining = m.config.RedundantDatagrams
	}
	retained := m.previous
	m.activeMu.Unlock()
	if stalePrevious != nil && stalePrevious != previous &&
		stalePrevious != replacement {
		stalePrevious.cancel()
		_ = stalePrevious.conn.Close()
	}
	if previous != nil && previous != replacement && retained != previous {
		previous.cancel()
		_ = previous.conn.Close()
	}
	if retained != nil {
		go m.expirePrevious(retained, m.config.HandoffRedundancy)
	}
}

func (m *Manager) invalidate(failed *activeCarrier, _ error) {
	m.activeMu.Lock()
	if m.active != failed {
		m.activeMu.Unlock()
		return
	}
	m.active = nil
	previous := m.previous
	m.previous = nil
	m.previousRemaining = 0
	m.activeMu.Unlock()
	failed.cancel()
	_ = failed.conn.Close()
	if previous != nil {
		previous.cancel()
		_ = previous.conn.Close()
	}
	_ = m.engine.Fail(failed.pathID, time.Now())
	m.inc("carrier_active_failed")
}

func (m *Manager) writeActive(active *activeCarrier, packet []byte) (int, error) {
	sequence := m.sendSequence.Add(1)
	writer, sequenced := active.conn.(SequencedWriter)
	if !sequenced {
		return active.conn.WriteTo(packet, nil)
	}
	count, err := writer.WriteSequenced(packet, nil, sequence)
	if err != nil {
		return count, err
	}
	previous := m.redundancyTarget(active)
	if previous == nil {
		return count, nil
	}
	previousWriter, ok := previous.conn.(SequencedWriter)
	if !ok {
		m.retirePrevious(previous)
		return count, nil
	}
	if _, duplicateErr := previousWriter.WriteSequenced(
		packet, nil, sequence,
	); duplicateErr != nil {
		m.retirePrevious(previous)
		m.inc("carrier_handoff_duplicate_failed")
	} else {
		m.inc("carrier_handoff_datagram_duplicated")
	}
	return count, nil
}

func (m *Manager) redundancyTarget(active *activeCarrier) *activeCarrier {
	var expired *activeCarrier
	m.activeMu.Lock()
	if m.active == active && m.previous != nil {
		if time.Now().Before(m.previousUntil) && m.previousRemaining > 0 {
			m.previousRemaining--
			previous := m.previous
			m.activeMu.Unlock()
			return previous
		}
		expired = m.previous
		m.previous = nil
		m.previousRemaining = 0
	}
	m.activeMu.Unlock()
	if expired != nil {
		go closeCarrier(expired)
	}
	return nil
}

func (m *Manager) retirePrevious(previous *activeCarrier) {
	m.activeMu.Lock()
	if m.previous == previous {
		m.previous = nil
		m.previousRemaining = 0
	}
	m.activeMu.Unlock()
	closeCarrier(previous)
}

func (m *Manager) expirePrevious(previous *activeCarrier, after time.Duration) {
	timer := time.NewTimer(after)
	defer timer.Stop()
	select {
	case <-timer.C:
		m.retirePrevious(previous)
	case <-m.ctx.Done():
	}
}

func closeCarrier(carrier *activeCarrier) {
	if carrier == nil {
		return
	}
	carrier.cancel()
	_ = carrier.conn.Close()
}

func (m *Manager) coverLoop() {
	for {
		span := m.config.CoverIntervalMax - m.config.CoverIntervalMin
		delay := m.config.CoverIntervalMin + secureJitter(span)
		timer := time.NewTimer(delay)
		select {
		case <-m.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		active := m.current()
		if active == nil {
			continue
		}
		sender, ok := active.conn.(CoverTrafficSender)
		if !ok {
			continue
		}
		if err := sender.SendCover(m.config.CoverDatagramSize); err != nil {
			m.inc("carrier_cover_failed")
		} else {
			m.inc("carrier_cover_sent")
		}
	}
}

func (m *Manager) current() *activeCarrier {
	m.activeMu.RLock()
	active := m.active
	m.activeMu.RUnlock()
	return active
}

func (m *Manager) deadline(read bool) time.Time {
	m.deadlineMu.Lock()
	defer m.deadlineMu.Unlock()
	if read {
		return m.readDeadline
	}
	return m.writeDeadline
}

func (m *Manager) operationContext(read bool) (context.Context, context.CancelFunc) {
	deadline := m.deadline(read)
	if deadline.IsZero() {
		return context.WithCancel(m.ctx)
	}
	return context.WithDeadline(m.ctx, deadline)
}

func (m *Manager) inc(event string) {
	if m.config.Metrics != nil {
		m.config.Metrics.Inc(event)
	}
}

func (m *Manager) observe(operation string, duration time.Duration) {
	if m.config.Metrics != nil {
		m.config.Metrics.ObserveDuration(operation, duration)
	}
}

func secureJitter(maximum time.Duration) time.Duration {
	if maximum <= 0 {
		return 0
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(maximum)))
	if err != nil {
		return 0
	}
	return time.Duration(value.Int64())
}

func deadlineError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return os.ErrDeadlineExceeded
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return net.ErrClosed
}
