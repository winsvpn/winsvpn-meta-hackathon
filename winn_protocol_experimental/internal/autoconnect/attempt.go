// Package autoconnect joins one immutable background-prepared generation to
// Winn's click-time connectivity coordinator.
//
// An Attempt is deliberately single-use. Anonymous H3 credentials and prepared
// carrier state are generation-scoped, so silently reusing them for a later
// user click would weaken replay and readiness guarantees.
package autoconnect

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/mobility"
	"winsvpn.local/winnprotocol/internal/preparation"
)

var ErrAttemptClosed = errors.New("auto connection attempt is closed")

// PreparedGeneration is satisfied by preparation.Manager and
// preparation.PreparedAssembly. Acquire must be non-blocking: all carrier,
// credential, and policy work belongs to background preparation.
type PreparedGeneration interface {
	Acquire() (*preparation.Lease, error)
	Close(context.Context) error
}

// IdentitySource returns a fresh logical Winn session and nonzero replay epoch
// for the click-time Binding. Production callers may inject a durable epoch
// source; it must honor ctx. The default uses independent cryptographic
// randomness.
type IdentitySource func(
	context.Context,
) (sessionID string, sequenceEpoch uint64, err error)

type Config struct {
	Generation PreparedGeneration
	Deadline   time.Duration
	Identity   IdentitySource
}

// Attempt owns one coordinator and retains the preparation lease from click
// until the selected tunnel has been synchronously stopped.
type Attempt struct {
	generation  PreparedGeneration
	deadline    time.Duration
	identity    IdentitySource
	coordinator *connectivity.Coordinator

	mu         sync.Mutex
	started    bool
	closed     bool
	done       chan struct{}
	result     connectivity.Result
	connectErr error
	lease      *preparation.Lease

	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

func New(config Config) (*Attempt, error) {
	if config.Generation == nil {
		return nil, errors.New("prepared Auto generation is required")
	}
	if config.Deadline == 0 {
		config.Deadline = connectivity.DefaultDeadline
	}
	if config.Deadline < 0 || config.Deadline > connectivity.MaxDeadline {
		return nil, fmt.Errorf(
			"auto connection deadline must be within (0, %s]",
			connectivity.MaxDeadline,
		)
	}
	if config.Identity == nil {
		config.Identity = randomIdentity
	}
	return &Attempt{
		generation:  config.Generation,
		deadline:    config.Deadline,
		identity:    config.Identity,
		coordinator: connectivity.NewCoordinator(),
		done:        make(chan struct{}),
		closeDone:   make(chan struct{}),
	}, nil
}

// Connect consumes this attempt. Equivalent concurrent callers coalesce onto
// the same result; no caller can trigger a second credential or carrier use.
// The deadline begins before the preparation lease and binding are read.
func (attempt *Attempt) Connect(ctx context.Context) (
	connectivity.Result,
	error,
) {
	if attempt == nil {
		return connectivity.Result{}, ErrAttemptClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}

	attempt.mu.Lock()
	if attempt.closed {
		attempt.mu.Unlock()
		return connectivity.Result{}, ErrAttemptClosed
	}
	if attempt.started {
		done := attempt.done
		attempt.mu.Unlock()
		select {
		case <-ctx.Done():
			return connectivity.Result{}, context.Cause(ctx)
		case <-done:
			attempt.mu.Lock()
			result, err := attempt.result, attempt.connectErr
			attempt.mu.Unlock()
			return result, err
		}
	}
	attempt.started = true
	attempt.mu.Unlock()

	result, lease, err := attempt.connect(ctx)

	attempt.mu.Lock()
	if err == nil && result.Success() && !attempt.closed {
		attempt.lease = lease
		lease = nil
	}
	attempt.result = result
	attempt.connectErr = err
	close(attempt.done)
	attempt.mu.Unlock()
	if lease != nil {
		lease.Release()
	}
	return result, err
}

func (attempt *Attempt) connect(ctx context.Context) (
	connectivity.Result,
	*preparation.Lease,
	error,
) {
	clickDeadline := time.Now().Add(attempt.deadline)
	clickContext, cancel := context.WithDeadline(ctx, clickDeadline)
	defer cancel()
	if cause := context.Cause(clickContext); cause != nil {
		return connectivity.Result{}, nil, cause
	}
	effectiveDeadline, ok := clickContext.Deadline()
	if !ok {
		return connectivity.Result{}, nil,
			errors.New("auto connection context lacks a deadline")
	}

	lease, err := attempt.generation.Acquire()
	if err != nil {
		return connectivity.Result{}, nil,
			fmt.Errorf("acquire prepared Auto generation: %w", err)
	}
	sessionID, sequenceEpoch, err := attempt.identity(clickContext)
	if err != nil {
		lease.Release()
		return connectivity.Result{}, nil,
			fmt.Errorf("create Auto connection identity: %w", err)
	}
	// A caller may intentionally begin the hard budget before this click
	// (for example, a true-cold acceptance attempt that includes verified
	// preparation). Bind the candidate to the earliest effective deadline;
	// never advertise a fresh click budget that the parent context cannot
	// honor.
	remaining := time.Until(effectiveDeadline)
	if remaining <= 0 {
		lease.Release()
		return connectivity.Result{}, nil, context.DeadlineExceeded
	}
	request, err := lease.ConnectRequest(
		sessionID, sequenceEpoch, remaining,
	)
	if err != nil {
		lease.Release()
		return connectivity.Result{}, nil,
			fmt.Errorf("snapshot prepared Auto generation: %w", err)
	}
	result := attempt.coordinator.Connect(clickContext, request)
	return result, lease, nil
}

// Status reports the coordinator's current authoritative state.
func (attempt *Attempt) Status() connectivity.Result {
	if attempt == nil || attempt.coordinator == nil {
		return connectivity.Result{State: connectivity.StateStopped}
	}
	return attempt.coordinator.Status()
}

// Close is retryable by callers whose context expires. Cleanup continues in
// the background exactly once: stop the selected tunnel, release the click-time
// lease, then retire all background-prepared resources.
func (attempt *Attempt) Close(ctx context.Context) error {
	if attempt == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	attempt.closeOnce.Do(func() {
		attempt.mu.Lock()
		attempt.closed = true
		started := attempt.started
		attempt.mu.Unlock()
		go attempt.close(started)
	})
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-attempt.closeDone:
		return attempt.closeErr
	}
}

func (attempt *Attempt) close(started bool) {
	var closeErr error
	if started {
		closeErr = errors.Join(closeErr, attempt.coordinator.Stop())
		<-attempt.done
	}
	attempt.mu.Lock()
	lease := attempt.lease
	attempt.lease = nil
	attempt.mu.Unlock()
	if lease != nil {
		lease.Release()
	}
	closeErr = errors.Join(
		closeErr,
		attempt.generation.Close(context.Background()),
	)
	attempt.closeErr = closeErr
	close(attempt.closeDone)
}

func randomIdentity(ctx context.Context) (string, uint64, error) {
	if cause := context.Cause(ctx); cause != nil {
		return "", 0, cause
	}
	sessionID, err := mobility.NewSessionID()
	if err != nil {
		return "", 0, err
	}
	var encoded [8]byte
	if _, err := rand.Read(encoded[:]); err != nil {
		return "", 0, err
	}
	if cause := context.Cause(ctx); cause != nil {
		return "", 0, cause
	}
	epoch := binary.BigEndian.Uint64(encoded[:])
	if epoch == 0 {
		epoch = 1
	}
	return sessionID, epoch, nil
}
