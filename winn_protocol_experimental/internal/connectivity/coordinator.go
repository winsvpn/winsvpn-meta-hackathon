package connectivity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const (
	candidateCleanupGrace           = 500 * time.Millisecond
	candidateRecoveryInitialBackoff = 10 * time.Millisecond
	candidateRecoveryMaxBackoff     = time.Second
)

// Candidate is a prepared, authenticated carrier option. Descriptor must be
// immutable and non-blocking. Dial returns after the encrypted carrier path is
// available, while the real AWG handshake is verified separately.
type Candidate interface {
	Descriptor() CandidateDescriptor
	Dial(context.Context, Binding) (CandidateConnection, error)
}

// CandidateConnection is safe for concurrent method calls. Close is
// idempotent, permanently fences route installation, and wins over an
// in-flight Commit: a Commit returning after Close must not restore routes or
// connectivity. Implementors must bind every verification exchange to the
// supplied Binding, honor context cancellation, and keep lifetime independent
// from the Dial context after Dial succeeds. Health is non-blocking and returns
// one stable, non-nil channel for the connection lifetime. It stays open while
// healthy and then publishes one terminal error and closes. A close without an
// error is also treated as fail-closed health loss.
type CandidateConnection interface {
	FreshAWGHandshake(context.Context, Binding) error
	VerifyBidirectional(context.Context, Binding) error
	VerifyProtectedDNS(context.Context, Binding) error
	VerifyTunnelCanary(context.Context, Binding) error
	Commit(context.Context, Binding) error
	Health() <-chan error
	Close() error
}

type ConnectRequest struct {
	Readiness     Readiness
	Candidates    []Candidate
	SessionID     string
	SequenceEpoch uint64
	Deadline      time.Duration
	// AttemptID and Nonce are either both empty (ordinary warm/background
	// preparation) or both preallocated at the beginning of a true-cold user
	// operation. A reserved pair lets cold preparation and the coordinator use
	// one exact immutable Binding without extending the hard deadline.
	AttemptID        string
	Nonce            string
	ReservedBindings []Binding
}

type attempt struct {
	fingerprint string
	generation  uint64
	cancel      context.CancelCauseFunc
	done        chan struct{}
	result      Result
}

type Coordinator struct {
	mu              sync.Mutex
	state           State
	current         *attempt
	active          CandidateConnection
	activeResult    Result
	generation      uint64
	watchers        map[uint64]chan Event
	nextWatcher     uint64
	now             func() time.Time
	stopDone        chan struct{}
	stopOnce        sync.Once
	stopErr         error
	stopRequested   chan struct{}
	stopRequestOnce sync.Once
	validationGate  chan struct{}
	healthDone      chan struct{}
	healthErr       error
	poisoned        bool
}

func NewCoordinator() *Coordinator {
	return &Coordinator{
		state:          StateCold,
		watchers:       make(map[uint64]chan Event),
		now:            time.Now,
		stopDone:       make(chan struct{}),
		stopRequested:  make(chan struct{}),
		validationGate: make(chan struct{}, 1),
	}
}

func (coordinator *Coordinator) Status() Result {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.state == StateStopping ||
		coordinator.state == StateStopped {
		result := coordinator.activeResult
		if coordinator.current != nil {
			result = coordinator.current.result
		}
		result.State = coordinator.state
		if coordinator.state == StateStopped {
			result.Failure = FailureStoppedByUser
		}
		return result
	}
	if coordinator.current != nil {
		return coordinator.current.result
	}
	result := coordinator.activeResult
	if result.State == "" {
		result.State = coordinator.state
	}
	return result
}

// WatchEvents returns a bounded event stream and an idempotent unsubscribe
// function. Status remains authoritative if a slow watcher misses an event.
func (coordinator *Coordinator) WatchEvents() (<-chan Event, func()) {
	coordinator.mu.Lock()
	id := coordinator.nextWatcher
	coordinator.nextWatcher++
	channel := make(chan Event, 32)
	coordinator.watchers[id] = channel
	coordinator.mu.Unlock()
	var once sync.Once
	return channel, func() {
		once.Do(func() {
			coordinator.mu.Lock()
			if existing, ok := coordinator.watchers[id]; ok {
				delete(coordinator.watchers, id)
				close(existing)
			}
			coordinator.mu.Unlock()
		})
	}
}

func (coordinator *Coordinator) Connect(
	ctx context.Context,
	request ConnectRequest,
) Result {
	if ctx == nil {
		ctx = context.Background()
	}
	started := coordinator.now().UTC()
	request = cloneConnectRequest(request)
	fingerprint := preliminaryRequestFingerprint(request)
	attemptID, nonce := request.AttemptID, request.Nonce
	if attemptID == "" && nonce == "" {
		var identityErr error
		attemptID, nonce, identityErr = newAttemptIdentity()
		if identityErr != nil {
			attemptID = fallbackAttemptID(started)
			return failedResult(
				attemptID, request.Readiness, fingerprint, started,
				coordinator.now().UTC(), FailureNotReady,
			)
		}
	} else if !sessionPattern.MatchString(attemptID) ||
		!sessionPattern.MatchString(nonce) {
		return failedResult(
			fallbackAttemptID(started),
			request.Readiness,
			fingerprint,
			started,
			coordinator.now().UTC(),
			FailureNotReady,
		)
	}
	deadline := request.Deadline
	if deadline == 0 {
		deadline = DefaultDeadline
	}
	if deadline < 0 || deadline > MaxDeadline {
		return failedResult(
			attemptID, request.Readiness, fingerprint, started,
			coordinator.now().UTC(),
			FailureNotReady,
		)
	}
	hardDeadline := started.Add(deadline)
	deadlineContext, cancelDeadline := context.WithDeadline(
		ctx, hardDeadline,
	)
	defer cancelDeadline()
	cleanupReserve := candidateCleanupGrace
	if quarterDeadline := deadline / 4; cleanupReserve > quarterDeadline {
		cleanupReserve = quarterDeadline
	}
	workContext, cancelWork := context.WithDeadline(
		deadlineContext,
		hardDeadline.Add(-cleanupReserve),
	)
	defer cancelWork()

	validationHeld := false
	releaseValidation := func() {
		if validationHeld {
			<-coordinator.validationGate
			validationHeld = false
		}
	}
	defer releaseValidation()
	select {
	case coordinator.validationGate <- struct{}{}:
		validationHeld = true
	case <-coordinator.stopRequested:
		return failedResult(
			attemptID, request.Readiness, fingerprint, started,
			coordinator.now().UTC(), FailureStoppedByUser,
		)
	case <-workContext.Done():
		return failedResult(
			attemptID, request.Readiness, fingerprint, started,
			coordinator.now().UTC(), contextFailure(workContext),
		)
	}

	coordinator.mu.Lock()
	for coordinator.state != StateOnline &&
		coordinator.healthDone != nil {
		teardownDone := coordinator.healthDone
		coordinator.mu.Unlock()
		select {
		case <-teardownDone:
		case <-coordinator.stopRequested:
			return failedResult(
				attemptID, request.Readiness, fingerprint, started,
				coordinator.now().UTC(), FailureStoppedByUser,
			)
		case <-workContext.Done():
			return failedResult(
				attemptID, request.Readiness, fingerprint, started,
				coordinator.now().UTC(), contextFailure(workContext),
			)
		}
		coordinator.mu.Lock()
	}
	stopping := coordinator.state == StateStopping ||
		coordinator.state == StateStopped
	poisoned := coordinator.poisoned
	coordinator.mu.Unlock()
	if stopping {
		return failedResult(
			attemptID, request.Readiness, fingerprint, started,
			coordinator.now().UTC(), FailureStoppedByUser,
		)
	}
	if poisoned {
		return failedResult(
			attemptID, request.Readiness, fingerprint, started,
			coordinator.now().UTC(), FailureTeardownFailed,
		)
	}

	type validationResult struct {
		candidates []validatedCandidate
		err        error
	}
	validation := make(chan validationResult, 1)
	go func() {
		candidates, validationErr := validateRequest(
			request,
			started,
			contextDeadline(workContext),
		)
		validation <- validationResult{
			candidates: candidates,
			err:        validationErr,
		}
	}()
	var validated []validatedCandidate
	var err error
	select {
	case <-coordinator.stopRequested:
		return failedResult(
			attemptID, request.Readiness, fingerprint, started,
			coordinator.now().UTC(), FailureStoppedByUser,
		)
	case <-workContext.Done():
		// Descriptor is deliberately specified as non-blocking. If a
		// candidate violates that contract, fail this Coordinator closed so
		// retries cannot accumulate permanently blocked validation goroutines.
		coordinator.markPoisoned()
		return failedResult(
			attemptID, request.Readiness, fingerprint, started,
			coordinator.now().UTC(),
			contextFailure(workContext),
		)
	case result := <-validation:
		validated = result.candidates
		err = result.err
	}
	if err != nil {
		code := FailureNotReady
		if errors.Is(err, errModePolicy) {
			code = FailureModePolicyViolation
		}
		if workContext.Err() != nil {
			code = contextFailure(workContext)
		}
		return failedResult(
			attemptID, request.Readiness, fingerprint, started,
			coordinator.now().UTC(), code,
		)
	}
	validatedFingerprint, err := requestFingerprint(request, validated)
	if err != nil {
		return failedResult(
			attemptID, request.Readiness, fingerprint, started,
			coordinator.now().UTC(),
			FailureNotReady,
		)
	}
	fingerprint = validatedFingerprint
	if workContext.Err() != nil {
		return failedResult(
			attemptID, request.Readiness, fingerprint, started,
			coordinator.now().UTC(), contextFailure(workContext),
		)
	}
	attemptContext, cancelAttempt := context.WithCancelCause(workContext)

	coordinator.mu.Lock()
	for coordinator.state != StateOnline &&
		coordinator.healthDone != nil {
		teardownDone := coordinator.healthDone
		coordinator.mu.Unlock()
		select {
		case <-teardownDone:
		case <-coordinator.stopRequested:
			cancelAttempt(errStopped)
			return failedResult(
				attemptID, request.Readiness, fingerprint, started,
				coordinator.now().UTC(), FailureStoppedByUser,
			)
		case <-workContext.Done():
			cancelAttempt(nil)
			return failedResult(
				attemptID, request.Readiness, fingerprint, started,
				coordinator.now().UTC(), contextFailure(workContext),
			)
		}
		coordinator.mu.Lock()
	}
	if coordinator.state == StateStopping ||
		coordinator.state == StateStopped {
		coordinator.mu.Unlock()
		cancelAttempt(errStopped)
		return failedResult(
			attemptID, request.Readiness, fingerprint, started,
			coordinator.now().UTC(), FailureStoppedByUser,
		)
	}
	if coordinator.poisoned {
		coordinator.mu.Unlock()
		cancelAttempt(nil)
		return failedResult(
			attemptID, request.Readiness, fingerprint, started,
			coordinator.now().UTC(), FailureTeardownFailed,
		)
	}
	if coordinator.current != nil {
		current := coordinator.current
		if current.fingerprint != fingerprint {
			coordinator.mu.Unlock()
			cancelAttempt(nil)
			return failedResult(
				attemptID, request.Readiness, fingerprint, started,
				coordinator.now().UTC(), FailureConnectInProgress,
			)
		}
		done := current.done
		coordinator.mu.Unlock()
		releaseValidation()
		cancelAttempt(nil)
		select {
		case <-done:
			return current.result
		case <-deadlineContext.Done():
			return failedResult(
				attemptID, request.Readiness, fingerprint, started,
				coordinator.now().UTC(), contextFailure(deadlineContext),
			)
		}
	}
	if coordinator.state == StateOnline &&
		coordinator.activeResult.TrustFingerprint == fingerprint {
		result := coordinator.activeResult
		coordinator.mu.Unlock()
		releaseValidation()
		cancelAttempt(nil)
		return result
	}

	staleActive := coordinator.active
	staleHealthDone := coordinator.healthDone
	coordinator.active = nil
	coordinator.activeResult = Result{}
	coordinator.generation++
	current := &attempt{
		fingerprint: fingerprint,
		generation:  coordinator.generation,
		cancel:      cancelAttempt,
		done:        make(chan struct{}),
		result: Result{
			AttemptID:        attemptID,
			TrustFingerprint: fingerprint,
			Profile:          request.Readiness.Profile,
			Mode:             request.Readiness.Mode,
			State:            StateConnecting,
			StartedAt:        started,
		},
	}
	coordinator.current = current
	coordinator.state = StateConnecting
	coordinator.emitLocked(Event{
		AttemptID: attemptID,
		Timestamp: started,
		State:     StateConnecting,
		Mode:      request.Readiness.Mode,
	})
	coordinator.mu.Unlock()
	releaseValidation()

	var connection CandidateConnection
	var descriptor CandidateDescriptor
	var predicates Predicates
	var timings Timings
	var failure FailureCode
	if staleActive != nil {
		cleanupContext, cancelCleanup := candidateCleanupContext(
			hardDeadline,
		)
		if err := closeCandidateWithinContext(
			cleanupContext,
			staleActive,
		); err != nil {
			failure = FailureTeardownFailed
		}
		if staleHealthDone != nil &&
			waitChannelWithinContext(
				cleanupContext,
				staleHealthDone,
			) != nil {
			failure = FailureTeardownFailed
		}
		cancelCleanup()
	}
	if failure == FailureNone && attemptContext.Err() == nil {
		connection, descriptor, predicates, timings, failure = coordinator.race(
			attemptContext, request, validated, attemptID, nonce, started,
			hardDeadline,
		)
	} else if failure == FailureNone {
		failure = contextFailure(attemptContext)
	}
	result := coordinator.finishAttempt(
		current, request, connection, descriptor, predicates, timings, failure,
		hardDeadline,
	)
	cancelAttempt(nil)
	return result
}

// Stop is terminal for one Coordinator. It invalidates the current generation,
// cancels candidate work, closes the active tunnel, waits for candidate
// teardown, and cannot be undone by a late Connect completion.
func (coordinator *Coordinator) Stop() error {
	coordinator.mu.Lock()
	switch coordinator.state {
	case StateStopped:
		err := coordinator.stopErr
		coordinator.mu.Unlock()
		return err
	case StateStopping:
		done := coordinator.stopDone
		coordinator.mu.Unlock()
		<-done
		coordinator.mu.Lock()
		err := coordinator.stopErr
		coordinator.mu.Unlock()
		return err
	}
	coordinator.state = StateStopping
	coordinator.stopRequestOnce.Do(func() {
		close(coordinator.stopRequested)
	})
	coordinator.generation++
	now := coordinator.now().UTC()
	current := coordinator.current
	if current != nil {
		current.cancel(errStopped)
	}
	active := coordinator.active
	healthDone := coordinator.healthDone
	coordinator.active = nil
	coordinator.activeResult = Result{}
	attemptID := ""
	mode := Mode("")
	if current != nil {
		attemptID = current.result.AttemptID
		mode = current.result.Mode
	}
	coordinator.emitLocked(Event{
		AttemptID: attemptID,
		Timestamp: now,
		State:     StateStopping,
		Mode:      mode,
		Reason:    FailureStoppedByUser,
	})
	coordinator.mu.Unlock()

	cleanupContext, cancelCleanup := context.WithTimeout(
		context.Background(),
		candidateCleanupGrace,
	)
	defer cancelCleanup()
	var teardownErr error
	if active != nil {
		teardownErr = errors.Join(
			teardownErr,
			closeCandidateWithinContext(cleanupContext, active),
		)
	}
	if current != nil {
		if waitChannelWithinContext(cleanupContext, current.done) != nil {
			teardownErr = errors.Join(
				teardownErr,
				errors.New("candidate attempt exceeded cleanup grace"),
			)
		} else if current.result.Failure == FailureTeardownFailed {
			teardownErr = errors.Join(
				teardownErr,
				errors.New("candidate teardown failed"),
			)
		}
	}
	if healthDone != nil {
		teardownErr = errors.Join(
			teardownErr,
			waitChannelWithinContext(cleanupContext, healthDone),
		)
	}

	coordinator.mu.Lock()
	teardownErr = errors.Join(teardownErr, coordinator.healthErr)
	lateActive := coordinator.active
	coordinator.active = nil
	coordinator.activeResult = Result{}
	coordinator.mu.Unlock()
	if lateActive != nil {
		teardownErr = errors.Join(
			teardownErr,
			closeCandidateWithinContext(cleanupContext, lateActive),
		)
	}
	coordinator.mu.Lock()
	coordinator.state = StateStopped
	coordinator.stopErr = teardownErr
	reason := FailureStoppedByUser
	if teardownErr != nil {
		reason = FailureTeardownFailed
	}
	coordinator.emitLocked(Event{
		AttemptID: attemptID,
		Timestamp: coordinator.now().UTC(),
		State:     StateStopped,
		Mode:      mode,
		Reason:    reason,
	})
	coordinator.mu.Unlock()
	coordinator.stopOnce.Do(func() { close(coordinator.stopDone) })
	return teardownErr
}

type validatedCandidate struct {
	candidate  Candidate
	descriptor CandidateDescriptor
}

type candidateReady struct {
	connection CandidateConnection
	descriptor CandidateDescriptor
	predicates Predicates
	timings    Timings
	failure    FailureCode
}

func (coordinator *Coordinator) race(
	ctx context.Context,
	request ConnectRequest,
	candidates []validatedCandidate,
	attemptID string,
	nonce string,
	started time.Time,
	hardDeadline time.Time,
) (
	CandidateConnection,
	CandidateDescriptor,
	Predicates,
	Timings,
	FailureCode,
) {
	raceContext, cancelRace := context.WithCancel(ctx)
	results := make(chan candidateReady)
	abandon := make(chan struct{})
	var abandonOnce sync.Once
	abandonAll := func() {
		abandonOnce.Do(func() { close(abandon) })
	}
	defer abandonAll()
	for _, validated := range candidates {
		validated := validated
		go func() {
			ready := verifyCandidate(
				raceContext,
				abandon,
				request,
				attemptID,
				nonce,
				validated,
				started,
				coordinator.now,
				hardDeadline,
			)
			select {
			case results <- ready:
			case <-abandon:
				// The bounded drain has ended. A late successful candidate
				// owns its connection and must still attempt cleanup.
				if ready.connection != nil {
					_ = retryCandidateWithGrace(ready.connection)
				}
			}
		}()
	}

	outstanding := len(candidates)
	var winner candidateReady
	var bestFailure FailureCode
	var bestTimings Timings
	for outstanding > 0 && winner.connection == nil {
		select {
		case <-ctx.Done():
			cancelRace()
			cleanupContext, cancelCleanup := candidateCleanupContext(
				hardDeadline,
			)
			cleanupErr := drainAndCloseWithinContext(
				cleanupContext,
				results,
				outstanding,
			)
			cancelCleanup()
			if cleanupErr != nil {
				return nil, CandidateDescriptor{}, Predicates{}, Timings{},
					FailureTeardownFailed
			}
			return nil, CandidateDescriptor{}, Predicates{}, Timings{},
				contextFailure(ctx)
		case ready := <-results:
			outstanding--
			if ready.failure != FailureNone {
				preferred := preferFailure(bestFailure, ready.failure)
				if preferred != bestFailure {
					bestTimings = ready.timings
				}
				bestFailure = preferred
				continue
			}
			winner = ready
		}
	}
	cancelRace()
	if winner.connection == nil {
		cleanupContext, cancelCleanup := candidateCleanupContext(
			hardDeadline,
		)
		if drainAndCloseWithinContext(
			cleanupContext,
			results,
			outstanding,
		) != nil {
			cancelCleanup()
			return nil, CandidateDescriptor{}, Predicates{}, Timings{},
				FailureTeardownFailed
		}
		cancelCleanup()
	} else {
		// Every incomplete verifier and every late candidate result already
		// has an exact persistent teardown owner behind abandon. Signal those
		// owners immediately, but do not discard the verified winner merely
		// because an isolated, never-committed loser needs longer than the
		// user-visible cleanup reserve. Commit remains the winner's final
		// non-blocking liveness gate.
		abandonAll()
	}

	closeWinner := func() error {
		winnerCleanup, cancelWinnerCleanup := candidateCleanupContext(
			hardDeadline,
		)
		defer cancelWinnerCleanup()
		return closeCandidateWithinContext(
			winnerCleanup,
			winner.connection,
		)
	}

	if winner.connection == nil {
		if ctx.Err() != nil {
			return nil, CandidateDescriptor{}, Predicates{}, Timings{},
				contextFailure(ctx)
		}
		if bestFailure == FailureNone {
			bestFailure = FailureNoReachableCandidate
		}
		return nil, CandidateDescriptor{}, Predicates{},
			bestTimings, bestFailure
	}
	if ctx.Err() != nil {
		if closeWinner() != nil {
			return nil, CandidateDescriptor{}, Predicates{},
				winner.timings,
				FailureTeardownFailed
		}
		return nil, CandidateDescriptor{}, Predicates{}, winner.timings,
			contextFailure(ctx)
	}
	binding := bindingFor(
		request, attemptID, nonce, winner.descriptor,
		contextDeadline(ctx),
	)
	if err := binding.Validate(coordinator.now().UTC()); err != nil {
		if closeWinner() != nil {
			return nil, CandidateDescriptor{}, Predicates{},
				winner.timings,
				FailureTeardownFailed
		}
		return nil, CandidateDescriptor{}, Predicates{}, winner.timings,
			FailureCredentialsExhausted
	}
	commitErr, commitResponsive := commitCandidate(
		ctx,
		winner.connection,
		binding,
	)
	if commitErr != nil {
		winner.timings.Commit = elapsedSince(
			started,
			coordinator.now().UTC(),
		)
		if closeWinner() != nil {
			return nil, CandidateDescriptor{}, Predicates{},
				winner.timings,
				FailureTeardownFailed
		}
		if !commitResponsive {
			return nil, CandidateDescriptor{}, Predicates{},
				winner.timings,
				FailureTeardownFailed
		}
		if ctx.Err() != nil {
			return nil, CandidateDescriptor{}, Predicates{},
				winner.timings,
				contextFailure(ctx)
		}
		return nil, CandidateDescriptor{}, Predicates{}, winner.timings,
			FailureCommitFailed
	}
	winner.timings.Commit = elapsedSince(
		started,
		coordinator.now().UTC(),
	)
	if ctx.Err() != nil {
		if closeWinner() != nil {
			return nil, CandidateDescriptor{}, Predicates{},
				winner.timings,
				FailureTeardownFailed
		}
		return nil, CandidateDescriptor{}, Predicates{}, winner.timings,
			contextFailure(ctx)
	}
	return winner.connection, winner.descriptor, winner.predicates,
		winner.timings, FailureNone
}

func verifyCandidate(
	ctx context.Context,
	abandon <-chan struct{},
	request ConnectRequest,
	attemptID string,
	nonce string,
	validated validatedCandidate,
	started time.Time,
	now func() time.Time,
	hardDeadline time.Time,
) candidateReady {
	binding := bindingFor(
		request, attemptID, nonce, validated.descriptor,
		contextDeadline(ctx),
	)
	connection, err := validated.candidate.Dial(ctx, binding)
	timings := Timings{Dial: elapsedSince(started, now().UTC())}
	if err != nil {
		return candidateReady{
			descriptor: validated.descriptor,
			timings:    timings,
			failure:    predicateFailure(ctx, FailureNoReachableCandidate),
		}
	}
	if nilCandidateConnection(connection) {
		return candidateReady{
			descriptor: validated.descriptor,
			timings:    timings,
			failure:    FailureNoReachableCandidate,
		}
	}

	var teardownClaimed atomic.Bool
	teardownDone := make(chan struct{})
	var teardownErr error
	runTeardown := func(
		cleanupContext context.Context,
		retry bool,
	) error {
		if teardownClaimed.CompareAndSwap(false, true) {
			if retry {
				teardownErr = retryCandidateWithGrace(connection)
			} else {
				teardownErr = closeCandidateWithinContext(
					cleanupContext,
					connection,
				)
			}
			close(teardownDone)
			return teardownErr
		}
		select {
		case <-teardownDone:
			return teardownErr
		case <-cleanupContext.Done():
			return errors.New(
				"candidate teardown owner exceeded cleanup grace",
			)
		}
	}
	ownershipDone := make(chan struct{})
	defer close(ownershipDone)
	go func() {
		select {
		case <-ownershipDone:
			return
		case <-abandon:
			// Recheck ownership after abandonment wins a simultaneous
			// select. A completed verifier owns its returned result; an
			// incomplete verifier transfers teardown ownership here.
			select {
			case <-ownershipDone:
				return
			default:
			}
			cleanupContext, cancelCleanup := context.WithTimeout(
				context.WithoutCancel(ctx),
				candidateCleanupGrace,
			)
			defer cancelCleanup()
			_ = runTeardown(cleanupContext, true)
		}
	}()

	probeContext, cancelProbes := context.WithCancel(ctx)
	type verification struct {
		kind   string
		err    error
		timing time.Duration
	}
	speculative := make(chan verification, 2)
	probesDone := make(chan struct{}, 2)
	go func() {
		defer func() { probesDone <- struct{}{} }()
		speculative <- verification{
			kind: "dns",
			err: connection.VerifyProtectedDNS(
				probeContext, binding,
			),
			timing: elapsedSince(started, now().UTC()),
		}
	}()
	go func() {
		defer func() { probesDone <- struct{}{} }()
		speculative <- verification{
			kind: "canary",
			err: connection.VerifyTunnelCanary(
				probeContext, binding,
			),
			timing: elapsedSince(started, now().UTC()),
		}
	}()
	closeOnFailure := func(code FailureCode) candidateReady {
		cancelProbes()
		cleanupContext, cancelCleanup := candidateCleanupContext(
			hardDeadline,
		)
		closeErr := runTeardown(cleanupContext, false)
		for range 2 {
			select {
			case <-probesDone:
			case <-cleanupContext.Done():
				closeErr = errors.Join(
					closeErr,
					errors.New("candidate probes ignored cancellation"),
				)
			}
		}
		cancelCleanup()
		if closeErr != nil {
			code = FailureTeardownFailed
		} else {
			code = predicateFailure(ctx, code)
		}
		return candidateReady{
			descriptor: validated.descriptor,
			timings:    timings,
			failure:    code,
		}
	}

	if err := connection.FreshAWGHandshake(ctx, binding); err != nil {
		timings.Handshake = elapsedSince(started, now().UTC())
		return closeOnFailure(FailureHandshakeFailed)
	}
	timings.Handshake = elapsedSince(started, now().UTC())
	predicates := Predicates{FreshAWGHandshake: true}
	if err := connection.VerifyBidirectional(ctx, binding); err != nil {
		timings.Bidirectional = elapsedSince(started, now().UTC())
		return closeOnFailure(FailureBidirectionalFailed)
	}
	timings.Bidirectional = elapsedSince(started, now().UTC())
	predicates.Bidirectional = true
	for range 2 {
		select {
		case <-ctx.Done():
			return closeOnFailure(contextFailure(ctx))
		case result := <-speculative:
			if result.kind == "dns" {
				timings.DNS = result.timing
			} else {
				timings.Canary = result.timing
			}
			if result.err != nil {
				if result.kind == "dns" {
					return closeOnFailure(
						FailureDNSVerificationFailed,
					)
				}
				return closeOnFailure(FailureCanaryFailed)
			}
			if result.kind == "dns" {
				predicates.ProtectedDNS = true
			} else {
				predicates.TunnelCanary = true
			}
		}
	}
	cancelProbes()
	for range 2 {
		<-probesDone
	}
	if !predicates.Verified() {
		failure := FailureNoReachableCandidate
		if closeCandidateWithGrace(connection) != nil {
			failure = FailureTeardownFailed
		}
		return candidateReady{
			descriptor: validated.descriptor,
			timings:    timings,
			failure:    failure,
		}
	}
	return candidateReady{
		connection: connection,
		descriptor: validated.descriptor,
		predicates: predicates,
		timings:    timings,
	}
}

func nilCandidateConnection(connection CandidateConnection) bool {
	if connection == nil {
		return true
	}
	value := reflect.ValueOf(connection)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (coordinator *Coordinator) finishAttempt(
	current *attempt,
	request ConnectRequest,
	connection CandidateConnection,
	descriptor CandidateDescriptor,
	predicates Predicates,
	timings Timings,
	failure FailureCode,
	hardDeadline time.Time,
) Result {
	finished := coordinator.now().UTC()
	result := current.result
	result.FinishedAt = finished
	result.Predicates = predicates
	timings.Outcome = elapsedSince(result.StartedAt, finished)
	result.Timings = timings
	result.Failure = failure
	cleanupContext, cancelCleanup := candidateCleanupContext(
		hardDeadline,
	)
	defer cancelCleanup()

	validGeneration := func() bool {
		return coordinator.current == current &&
			coordinator.generation == current.generation &&
			coordinator.state != StateStopping &&
			coordinator.state != StateStopped &&
			!coordinator.poisoned
	}
	finishInvalid := func() Result {
		result.State = StateFailed
		coordinator.mu.Lock()
		if coordinator.poisoned &&
			coordinator.state != StateStopping &&
			coordinator.state != StateStopped {
			result.Failure = FailureTeardownFailed
		} else {
			result.Failure = FailureStoppedByUser
		}
		current.result = result
		coordinator.mu.Unlock()
		if connection != nil {
			if closeCandidateWithinContext(
				cleanupContext,
				connection,
			) != nil {
				result.Failure = FailureTeardownFailed
			}
		}
		coordinator.mu.Lock()
		if result.Failure == FailureTeardownFailed {
			coordinator.poisoned = true
		}
		current.result = result
		if coordinator.current == current {
			coordinator.current = nil
		}
		coordinator.mu.Unlock()
		close(current.done)
		return result
	}

	coordinator.mu.Lock()
	if !validGeneration() {
		coordinator.mu.Unlock()
		return finishInvalid()
	}
	coordinator.mu.Unlock()

	var health <-chan error
	if failure == FailureNone && connection != nil {
		var healthErr error
		health, healthErr = healthChannelWithinContext(
			cleanupContext,
			connection,
		)
		if healthErr != nil {
			failure = FailureTeardownFailed
			result.Failure = failure
		} else if health == nil {
			failure = FailurePostCommitHealth
			result.Failure = failure
		} else {
			select {
			case <-health:
				failure = FailurePostCommitHealth
				result.Failure = failure
			default:
			}
		}
	}

	coordinator.mu.Lock()
	if !validGeneration() {
		coordinator.mu.Unlock()
		return finishInvalid()
	}
	if failure == FailureNone && connection != nil && health != nil &&
		coordinator.healthDone == nil {
		result.State = StateOnline
		result.CandidateID = descriptor.ID
		result.Carrier = descriptor.Carrier
		coordinator.active = connection
		coordinator.activeResult = result
		coordinator.state = StateOnline
		current.result = result
		coordinator.current = nil
		healthGeneration := coordinator.generation
		healthDone := make(chan struct{})
		coordinator.healthDone = healthDone
		coordinator.emitLocked(Event{
			AttemptID:   result.AttemptID,
			Timestamp:   finished,
			State:       result.State,
			Mode:        request.Readiness.Mode,
			CandidateID: result.CandidateID,
		})
		coordinator.mu.Unlock()
		close(current.done)
		go coordinator.monitorHealth(
			connection,
			health,
			healthGeneration,
			result,
			healthDone,
		)
		return result
	}
	if failure == FailureNone && coordinator.healthDone != nil {
		failure = FailureTeardownFailed
		result.Failure = failure
	}

	// Keep current registered until teardown finishes. Stop and competing
	// Connect calls must observe and wait on this exact connection owner.
	result.State = StateFailed
	result.Failure = failure
	coordinator.state = StateFailed
	current.result = result
	coordinator.mu.Unlock()

	if connection != nil {
		if closeCandidateWithinContext(
			cleanupContext,
			connection,
		) != nil {
			result.Failure = FailureTeardownFailed
		}
	}
	coordinator.mu.Lock()
	if result.Failure == FailureTeardownFailed {
		coordinator.poisoned = true
	}
	current.result = result
	if coordinator.current == current {
		coordinator.current = nil
	}
	coordinator.emitLocked(Event{
		AttemptID:   result.AttemptID,
		Timestamp:   finished,
		State:       result.State,
		Mode:        request.Readiness.Mode,
		CandidateID: result.CandidateID,
		Reason:      result.Failure,
	})
	coordinator.mu.Unlock()
	close(current.done)
	return result
}

func (coordinator *Coordinator) monitorHealth(
	connection CandidateConnection,
	health <-chan error,
	generation uint64,
	online Result,
	done chan struct{},
) {
	defer close(done)
	<-health

	coordinator.mu.Lock()
	if coordinator.state != StateOnline ||
		coordinator.active != connection ||
		coordinator.generation != generation {
		if coordinator.healthDone == done {
			coordinator.healthDone = nil
		}
		coordinator.mu.Unlock()
		return
	}
	coordinator.active = nil
	failed := online
	failed.State = StateFailed
	failed.FinishedAt = coordinator.now().UTC()
	failed.Failure = FailurePostCommitHealth
	failed.Timings.Outcome = elapsedSince(
		failed.StartedAt,
		failed.FinishedAt,
	)
	coordinator.activeResult = failed
	coordinator.state = StateFailed
	coordinator.emitLocked(Event{
		AttemptID:   failed.AttemptID,
		Timestamp:   failed.FinishedAt,
		State:       StateFailed,
		Mode:        failed.Mode,
		CandidateID: failed.CandidateID,
		Reason:      failed.Failure,
	})
	coordinator.mu.Unlock()

	if err := closeCandidateWithGrace(connection); err != nil {
		coordinator.mu.Lock()
		coordinator.poisoned = true
		coordinator.healthErr = errors.Join(
			coordinator.healthErr,
			err,
		)
		if coordinator.state == StateFailed &&
			coordinator.generation == generation &&
			coordinator.activeResult.AttemptID == failed.AttemptID {
			failed.Failure = FailureTeardownFailed
			coordinator.activeResult = failed
			coordinator.emitLocked(Event{
				AttemptID:   failed.AttemptID,
				Timestamp:   coordinator.now().UTC(),
				State:       StateFailed,
				Mode:        failed.Mode,
				CandidateID: failed.CandidateID,
				Reason:      FailureTeardownFailed,
			})
		}
		coordinator.mu.Unlock()
	}
	coordinator.mu.Lock()
	if coordinator.healthDone == done {
		coordinator.healthDone = nil
	}
	coordinator.mu.Unlock()
}

func bindingFor(
	request ConnectRequest,
	attemptID string,
	nonce string,
	descriptor CandidateDescriptor,
	connectDeadline time.Time,
) Binding {
	for _, reserved := range request.ReservedBindings {
		if reserved.CandidateID == descriptor.ID {
			return reserved
		}
	}
	expiresAt := minimumTime(
		request.Readiness.ExpiresAt,
		request.Readiness.ManifestExpiresAt,
		request.Readiness.PSKExpiresAt,
		descriptor.ExpiresAt,
	)
	if !connectDeadline.IsZero() && connectDeadline.Before(expiresAt) {
		expiresAt = connectDeadline
	}
	return Binding{
		AttemptID:      attemptID,
		Profile:        request.Readiness.Profile,
		Mode:           request.Readiness.Mode,
		ManifestDigest: request.Readiness.ManifestDigest,
		CandidateID:    descriptor.ID,
		NodeID:         descriptor.NodeID,
		SessionID:      request.SessionID,
		PSKGeneration:  request.Readiness.PSKGeneration,
		SequenceEpoch:  request.SequenceEpoch,
		Nonce:          nonce,
		ExpiresAt:      expiresAt,
	}
}

func contextDeadline(ctx context.Context) time.Time {
	if ctx == nil {
		return time.Time{}
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return time.Time{}
	}
	return deadline.UTC()
}

func minimumTime(values ...time.Time) time.Time {
	result := values[0]
	for _, value := range values[1:] {
		if value.Before(result) {
			result = value
		}
	}
	return result
}

func validateRequest(
	request ConnectRequest,
	now time.Time,
	bindingDeadline time.Time,
) ([]validatedCandidate, error) {
	if err := request.Readiness.Validate(now); err != nil {
		return nil, err
	}
	if !sessionPattern.MatchString(request.SessionID) ||
		request.SequenceEpoch == 0 {
		return nil, errors.New(
			"connection session and sequence epoch are required",
		)
	}
	if len(request.Candidates) != len(request.Readiness.Candidates) ||
		len(request.Candidates) == 0 ||
		len(request.Candidates) > MaxCandidates {
		return nil, errors.New(
			"connection candidates do not match readiness",
		)
	}
	ready := make(
		map[string]CandidateDescriptor,
		len(request.Readiness.Candidates),
	)
	for _, descriptor := range request.Readiness.Candidates {
		ready[descriptor.ID] = descriptor
	}
	if len(request.ReservedBindings) == 0 &&
		(request.AttemptID != "" || request.Nonce != "") {
		return nil, errors.New(
			"reserved cold attempt lacks exact candidate bindings",
		)
	}
	if len(request.ReservedBindings) != 0 {
		if len(request.ReservedBindings) != len(request.Readiness.Candidates) ||
			!sessionPattern.MatchString(request.AttemptID) ||
			!sessionPattern.MatchString(request.Nonce) {
			return nil, errors.New(
				"reserved cold bindings are incomplete",
			)
		}
		reserved := make(
			map[string]Binding,
			len(request.ReservedBindings),
		)
		for _, binding := range request.ReservedBindings {
			descriptor, ok := ready[binding.CandidateID]
			if !ok {
				return nil, errors.New(
					"reserved cold binding candidate is not ready",
				)
			}
			if _, duplicate := reserved[binding.CandidateID]; duplicate {
				return nil, errors.New(
					"reserved cold binding candidate is duplicated",
				)
			}
			if err := binding.Validate(now); err != nil {
				return nil, fmt.Errorf(
					"reserved cold binding: %w", err,
				)
			}
			if binding.AttemptID != request.AttemptID ||
				binding.Profile != request.Readiness.Profile ||
				binding.Mode != request.Readiness.Mode ||
				binding.ManifestDigest !=
					request.Readiness.ManifestDigest ||
				binding.NodeID != descriptor.NodeID ||
				binding.SessionID != request.SessionID ||
				binding.PSKGeneration !=
					request.Readiness.PSKGeneration ||
				binding.SequenceEpoch != request.SequenceEpoch ||
				binding.Nonce != request.Nonce ||
				binding.ExpiresAt.After(
					request.Readiness.ExpiresAt,
				) ||
				binding.ExpiresAt.After(
					request.Readiness.ManifestExpiresAt,
				) ||
				binding.ExpiresAt.After(
					request.Readiness.PSKExpiresAt,
				) ||
				binding.ExpiresAt.After(descriptor.ExpiresAt) ||
				(!bindingDeadline.IsZero() &&
					binding.ExpiresAt.After(bindingDeadline)) {
				return nil, errors.New(
					"reserved cold binding differs from readiness",
				)
			}
			reserved[binding.CandidateID] = binding
		}
	}
	seen := make(map[string]struct{}, len(request.Candidates))
	validated := make([]validatedCandidate, 0, len(request.Candidates))
	for _, candidate := range request.Candidates {
		if candidate == nil {
			return nil, errors.New("connection candidate is nil")
		}
		descriptor := candidate.Descriptor()
		if err := descriptor.Validate(now); err != nil {
			return nil, err
		}
		if !request.Readiness.Mode.Allows(descriptor.Carrier) {
			return nil, fmt.Errorf(
				"%w: carrier %q", errModePolicy, descriptor.Carrier,
			)
		}
		expected, ok := ready[descriptor.ID]
		if !ok || expected != descriptor {
			return nil, errors.New(
				"connection candidate differs from readiness",
			)
		}
		if _, duplicate := seen[descriptor.ID]; duplicate {
			return nil, errors.New(
				"connection candidate is duplicated",
			)
		}
		seen[descriptor.ID] = struct{}{}
		validated = append(validated, validatedCandidate{
			candidate:  candidate,
			descriptor: descriptor,
		})
	}
	return validated, nil
}

func cloneConnectRequest(request ConnectRequest) ConnectRequest {
	request.Readiness.Candidates = slices.Clone(
		request.Readiness.Candidates,
	)
	request.Readiness.Blockers = slices.Clone(request.Readiness.Blockers)
	request.Candidates = slices.Clone(request.Candidates)
	request.ReservedBindings = slices.Clone(request.ReservedBindings)
	return request
}

func requestFingerprint(
	request ConnectRequest,
	validated []validatedCandidate,
) (string, error) {
	readiness := request.Readiness
	readiness.Candidates = slices.Clone(readiness.Candidates)
	slices.SortFunc(
		readiness.Candidates,
		func(first, second CandidateDescriptor) int {
			return compareDescriptors(first, second)
		},
	)
	descriptors := make(
		[]CandidateDescriptor, 0, len(validated),
	)
	for _, candidate := range validated {
		descriptors = append(descriptors, candidate.descriptor)
	}
	slices.SortFunc(descriptors, compareDescriptors)
	document := struct {
		Version       string
		Readiness     Readiness
		Descriptors   []CandidateDescriptor
		SessionID     string
		SequenceEpoch uint64
		DeadlineNanos int64
		AttemptID     string
		Nonce         string
		Bindings      []Binding
	}{
		Version:       Version,
		Readiness:     readiness,
		Descriptors:   descriptors,
		SessionID:     request.SessionID,
		SequenceEpoch: request.SequenceEpoch,
		DeadlineNanos: int64(effectiveDeadline(request.Deadline)),
		AttemptID:     request.AttemptID,
		Nonce:         request.Nonce,
		Bindings:      slices.Clone(request.ReservedBindings),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func preliminaryRequestFingerprint(request ConnectRequest) string {
	document := struct {
		Version       string
		Readiness     Readiness
		SessionID     string
		SequenceEpoch uint64
		DeadlineNanos int64
		AttemptID     string
		Nonce         string
		Bindings      []Binding
	}{
		Version:       Version,
		Readiness:     request.Readiness,
		SessionID:     request.SessionID,
		SequenceEpoch: request.SequenceEpoch,
		DeadlineNanos: int64(effectiveDeadline(request.Deadline)),
		AttemptID:     request.AttemptID,
		Nonce:         request.Nonce,
		Bindings:      slices.Clone(request.ReservedBindings),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		encoded = []byte(Version + ":unencodable-request")
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func effectiveDeadline(value time.Duration) time.Duration {
	if value == 0 {
		return DefaultDeadline
	}
	return value
}

func compareDescriptors(first, second CandidateDescriptor) int {
	if first.ID < second.ID {
		return -1
	}
	if first.ID > second.ID {
		return 1
	}
	if first.NodeID < second.NodeID {
		return -1
	}
	if first.NodeID > second.NodeID {
		return 1
	}
	if first.Carrier < second.Carrier {
		return -1
	}
	if first.Carrier > second.Carrier {
		return 1
	}
	return first.ExpiresAt.Compare(second.ExpiresAt)
}

func failedResult(
	attemptID string,
	readiness Readiness,
	fingerprint string,
	started time.Time,
	finished time.Time,
	code FailureCode,
) Result {
	return Result{
		AttemptID:        attemptID,
		TrustFingerprint: fingerprint,
		Profile:          readiness.Profile,
		Mode:             readiness.Mode,
		State:            StateFailed,
		StartedAt:        started,
		FinishedAt:       finished,
		Timings: Timings{
			Outcome: elapsedSince(started, finished),
		},
		Failure: code,
	}
}

func elapsedSince(started, current time.Time) time.Duration {
	elapsed := current.Sub(started)
	if elapsed < 0 {
		return 0
	}
	return elapsed
}

func (coordinator *Coordinator) emitLocked(event Event) {
	for _, watcher := range coordinator.watchers {
		select {
		case watcher <- event:
		default:
		}
	}
}

// attemptEntropy is crypto/rand.Read. Tests replace it to prove a CSPRNG
// failure is FailureNotReady, not FailureNoReachableCandidate (which would
// look like the path was censored).
var attemptEntropy = rand.Read

func newAttemptIdentity() (string, string, error) {
	var random [32]byte
	if _, err := attemptEntropy(random[:]); err != nil {
		return "", "", err
	}
	attemptID := hex.EncodeToString(random[:16])
	nonce := hex.EncodeToString(random[16:])
	return attemptID, nonce, nil
}

var fallbackAttemptSequence atomic.Uint64

func fallbackAttemptID(started time.Time) string {
	sequence := fallbackAttemptSequence.Add(1)
	encoded := fmt.Sprintf(
		"winn-attempt-fallback:%d:%d",
		started.UnixNano(),
		sequence,
	)
	digest := sha256.Sum256([]byte(encoded))
	return hex.EncodeToString(digest[:16])
}

func predicateFailure(
	ctx context.Context,
	fallback FailureCode,
) FailureCode {
	if ctx.Err() != nil {
		return contextFailure(ctx)
	}
	return fallback
}

func contextFailure(ctx context.Context) FailureCode {
	if errors.Is(context.Cause(ctx), errStopped) ||
		errors.Is(context.Cause(ctx), context.Canceled) {
		return FailureStoppedByUser
	}
	return FailureConnectDeadlineExceeded
}

func preferFailure(current, candidate FailureCode) FailureCode {
	priority := map[FailureCode]int{
		FailureNoReachableCandidate:  1,
		FailureHandshakeFailed:       2,
		FailureBidirectionalFailed:   3,
		FailureDNSVerificationFailed: 4,
		FailureCanaryFailed:          5,
		FailureCredentialsExhausted:  6,
		FailureCommitFailed:          7,
		FailureTeardownFailed:        8,
	}
	if priority[candidate] > priority[current] {
		return candidate
	}
	return current
}

func drainAndCloseWithinContext(
	cleanupContext context.Context,
	results <-chan candidateReady,
	remaining int,
) error {
	var closeErr error
	closeResults := make(chan error, remaining)
	received := 0
	pendingCloses := 0
	for received < remaining || pendingCloses > 0 {
		select {
		case ready := <-results:
			received++
			if ready.failure == FailureTeardownFailed {
				closeErr = errors.Join(
					closeErr,
					errors.New("candidate reported teardown failure"),
				)
			}
			if ready.connection != nil {
				pendingCloses++
				go func(connection CandidateConnection) {
					closeResults <- recoverCandidateTeardown(connection)
				}(ready.connection)
			}
		case err := <-closeResults:
			pendingCloses--
			closeErr = errors.Join(closeErr, err)
		case <-cleanupContext.Done():
			return errors.Join(
				closeErr,
				errors.New("candidate teardown exceeded cleanup grace"),
			)
		}
	}
	return closeErr
}

func commitCandidate(
	ctx context.Context,
	connection CandidateConnection,
	binding Binding,
) (error, bool) {
	done := make(chan error)
	abandon := make(chan struct{})
	go func() {
		err := connection.Commit(ctx, binding)
		select {
		case done <- err:
		case <-abandon:
			// Commit owns the connection until it returns. If cancellation
			// won, compensate again after any late route mutation so no
			// successful late Commit is left without a teardown owner.
			_ = retryCandidateWithGrace(connection)
		}
	}()
	select {
	case err := <-done:
		return err, true
	case <-ctx.Done():
		close(abandon)
		return ctx.Err(), false
	}
}

func closeCandidateWithGrace(connection CandidateConnection) error {
	cleanupContext, cancel := context.WithTimeout(
		context.Background(),
		candidateCleanupGrace,
	)
	defer cancel()
	return closeCandidateWithinContext(cleanupContext, connection)
}

type candidateTeardownRetrier interface {
	RetryClose() error
}

func retryCandidateWithGrace(connection CandidateConnection) error {
	cleanupContext, cancel := context.WithTimeout(
		context.Background(),
		candidateCleanupGrace,
	)
	defer cancel()
	return closeCandidateWithinContext(cleanupContext, connection)
}

func candidateCleanupContext(
	hardDeadline time.Time,
) (context.Context, context.CancelFunc) {
	cleanupDeadline := time.Now().Add(candidateCleanupGrace)
	if !hardDeadline.IsZero() && hardDeadline.Before(cleanupDeadline) {
		cleanupDeadline = hardDeadline
	}
	return context.WithDeadline(context.Background(), cleanupDeadline)
}

func closeCandidateWithinContext(
	ctx context.Context,
	connection CandidateConnection,
) error {
	if nilCandidateConnection(connection) {
		return nil
	}
	return candidateCloseMethodWithinContext(
		ctx,
		func() error {
			return recoverCandidateTeardown(connection)
		},
	)
}

func recoverCandidateTeardown(connection CandidateConnection) error {
	retrier, retryable := connection.(candidateTeardownRetrier)
	if !retryable {
		return connection.Close()
	}
	backoff := candidateRecoveryInitialBackoff
	for {
		if err := retrier.RetryClose(); err == nil {
			return nil
		}
		// The production Direct-AWG and H3 wrappers retain staged teardown
		// state. This goroutine is the resource owner and deliberately
		// survives its caller's bounded wait, retrying at a capped rate until
		// rollback is proven complete. Poison blocks new attempts while that
		// owner is recovering, so retries cannot multiply candidate state.
		timer := time.NewTimer(backoff)
		<-timer.C
		if backoff < candidateRecoveryMaxBackoff {
			backoff *= 2
			if backoff > candidateRecoveryMaxBackoff {
				backoff = candidateRecoveryMaxBackoff
			}
		}
	}
}

func candidateCloseMethodWithinContext(
	ctx context.Context,
	closeMethod func() error,
) error {
	done := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		done <- closeMethod()
	}()
	// Establish an owning teardown goroutine before considering an already
	// expired cleanup context. The owner remains responsible even if this
	// caller must return before Close completes.
	<-started
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return errors.New("candidate Close exceeded cleanup grace")
	}
}

func waitChannelWithinContext(
	ctx context.Context,
	done <-chan struct{},
) error {
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return errors.New("candidate operation exceeded cleanup grace")
	}
}

func healthChannelWithinContext(
	ctx context.Context,
	connection CandidateConnection,
) (<-chan error, error) {
	type healthResult struct {
		channel <-chan error
	}
	result := make(chan healthResult, 1)
	go func() {
		result <- healthResult{channel: connection.Health()}
	}()
	select {
	case ready := <-result:
		return ready.channel, nil
	case <-ctx.Done():
		return nil, errors.New("candidate Health exceeded cleanup grace")
	}
}

func (coordinator *Coordinator) markPoisoned() {
	coordinator.mu.Lock()
	coordinator.poisoned = true
	coordinator.mu.Unlock()
}

var (
	errModePolicy = errors.New("mode policy violation")
	errStopped    = errors.New("connection stopped by user")
)
