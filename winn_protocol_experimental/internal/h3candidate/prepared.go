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
	"winsvpn.local/winnprotocol/internal/mobility"
)

const (
	MaxPreparedH3Age             = 10 * time.Minute
	preparedH3QUICPathRaceWidth  = 2
	preparedH3QUICPathHedgeDelay = 50 * time.Millisecond
	preparedH3LoserCleanupLimit  = 250 * time.Millisecond
)

// PreparedResource owns a live, authenticated H3 preparation until the
// enclosing preparation generation retires it.
type PreparedResource interface {
	Close(context.Context) error
}

// WarmPreparation is a genuine live H3 result: TLS/QUIC completed, ECH and the
// strict hybrid peer profile were accepted by the configured TLS verifier, one
// signed authentication-only CONNECT response passed controller-signature
// verification without allocating a backend relay, and the same HTTP/3
// connection remains unused by the later click binding. On a slow path, the
// delayed hedge performs the same proof with its own unlinkable one-time
// credential; the first fully authenticated path wins and every other path is
// closed. The click data path still performs the full envelope MTU probe before
// returning.
type WarmPreparation struct {
	Candidate       *Candidate
	ProbeFreshUntil time.Time
	WarmUntil       time.Time
	Resource        PreparedResource
}

// preparedLifetimes separates the two lifetimes that prepared H3 work must not
// conflate.
//
// warmUntil answers "how long may this unused prepared path still be claimed?"
// That is a freshness question, so it carries the preparation-age term.
//
// The committed lifetime answers "how long may the resulting tunnel live?"
// That is a trust question. SPECIFICATION.md requires it to be the earliest
// trusted expiry over the descriptor, manifest, PSK generation, anonymous
// credential lease, and underlay authorization — all of which are already
// folded into sessionExpiresAt by the caller. Reducing it by the preparation
// age would terminate healthy committed sessions at an unrelated boundary.
func preparedLifetimes(
	current time.Time,
	warmAge time.Duration,
	descriptorExpiresAt time.Time,
	sessionExpiresAt time.Time,
) (warmUntil time.Time, committed time.Time) {
	warmUntil = current.Add(warmAge)
	if descriptorExpiresAt.Before(warmUntil) {
		warmUntil = descriptorExpiresAt.UTC()
	}
	if sessionExpiresAt.Before(warmUntil) {
		warmUntil = sessionExpiresAt
	}
	return warmUntil, sessionExpiresAt
}

// PrepareWarm performs carrier work before click time. The dialer's current
// session and sequence epoch identify only the preparation probe. Candidate
// Dial replaces both with the immutable click-time Binding and consumes the
// next anonymous credential on the already-live HTTP/3 connection.
func PrepareWarm(
	ctx context.Context,
	config Config,
	warmAge time.Duration,
) (WarmPreparation, error) {
	if ctx == nil {
		return WarmPreparation{},
			errors.New("warm H3 preparation context is required")
	}
	if cause := context.Cause(ctx); cause != nil {
		return WarmPreparation{}, cause
	}
	if warmAge <= 0 || warmAge > MaxPreparedH3Age {
		return WarmPreparation{}, errors.New(
			"warm H3 preparation lifetime is invalid",
		)
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	current := now().UTC()
	if err := config.Descriptor.Validate(current); err != nil {
		return WarmPreparation{},
			fmt.Errorf("warm H3 descriptor: %w", err)
	}
	// A zero session lifetime is rejected rather than defaulted. Substituting
	// the descriptor expiry here is the fail-back pattern that let a committed
	// H3 session inherit the short candidate-work deadline; the caller must
	// state the trusted lifetime explicitly.
	sessionExpiresAt := config.SessionExpiresAt.UTC()
	if sessionExpiresAt.IsZero() {
		return WarmPreparation{}, errors.New(
			"warm H3 session lifetime is required",
		)
	}
	if !sessionExpiresAt.After(current) ||
		sessionExpiresAt.After(config.Descriptor.ExpiresAt) {
		return WarmPreparation{}, errors.New(
			"warm H3 session lifetime exceeds trusted descriptor",
		)
	}
	if config.Descriptor.Carrier != connectivity.CarrierHTTP3 {
		return WarmPreparation{}, errors.New(
			"warm H3 descriptor carrier is not HTTP/3",
		)
	}
	warmFactory, ok := config.Underlay.(WarmProtectedUnderlayFactory)
	if !ok || nilInterface(warmFactory) {
		return WarmPreparation{}, errors.New(
			"warm H3 preparation requires a preparable protected underlay",
		)
	}
	if nilInterface(config.Tunnel) ||
		nilInterface(config.Verifier) ||
		nilInterface(config.Transactions) {
		return WarmPreparation{}, errors.New(
			"warm H3 tunnel, verifier, and transaction controller are required",
		)
	}
	snapshot, err := snapshotProductionDialer(config.Dialer)
	if err != nil {
		return WarmPreparation{}, err
	}
	warmUntil, committedSessionExpiresAt := preparedLifetimes(
		current, warmAge, config.Descriptor.ExpiresAt, sessionExpiresAt,
	)
	if !warmUntil.After(current) {
		return WarmPreparation{}, errors.New(
			"warm H3 preparation has no positive trust lifetime",
		)
	}
	raceTasks := make(
		[]func(context.Context) (*preparedH3Attempt, error),
		0,
		preparedH3QUICPathRaceWidth,
	)
	laneAttempts := make(
		[]*preparedH3Attempt,
		preparedH3QUICPathRaceWidth,
	)
	for range preparedH3QUICPathRaceWidth {
		attempt := &preparedH3Attempt{}
		laneAttempts[len(raceTasks)] = attempt
		raceTasks = append(
			raceTasks,
			func(raceContext context.Context) (
				*preparedH3Attempt,
				error,
			) {
				underlay, prepareErr := warmFactory.Prepare(
					raceContext,
					warmUntil,
				)
				if underlayErr := attempt.SetUnderlay(
					raceContext,
					underlay,
				); underlayErr != nil {
					return attempt, underlayErr
				}
				if prepareErr != nil {
					return attempt, fmt.Errorf(
						"prepare protected H3 underlay: %w",
						prepareErr,
					)
				}
				dialer := snapshot
				dialer.TLSConfig = snapshot.TLSConfig.Clone()
				if snapshot.QUICConfig != nil {
					dialer.QUICConfig = snapshot.QUICConfig.Clone()
				}
				dialer.DialQUIC = nil
				dialer.DialQUICPath = underlay.DialQUICPath
				path, pathErr := dialer.PrepareH3Path(raceContext)
				if setPathErr := attempt.SetPath(path); setPathErr != nil {
					return attempt, setPathErr
				}
				if pathErr != nil {
					return attempt, pathErr
				}
				if identityErr := assignFreshPreparationIdentity(
					&dialer,
				); identityErr != nil {
					return attempt, identityErr
				}
				if authErr := dialer.AuthenticatePreparedH3Path(
					raceContext,
					path,
				); authErr != nil {
					return attempt, authErr
				}
				if !path.Ready() || !path.Authenticated() {
					return attempt, errors.New(
						"prepared H3 path lacks live authenticated evidence",
					)
				}
				return attempt, nil
			},
		)
	}
	winner, err := firstSuccessfulHedgedRace(
		ctx,
		preparedH3QUICPathHedgeDelay,
		preparedH3LoserCleanupLimit,
		raceTasks,
		func(
			cleanupContext context.Context,
			attempt *preparedH3Attempt,
		) error {
			return attempt.Close(cleanupContext)
		},
		func(
			cleanupContext context.Context,
			index int,
		) error {
			return laneAttempts[index].Close(cleanupContext)
		},
	)
	if err != nil {
		return WarmPreparation{}, fmt.Errorf(
			"race protected H3 QUIC paths: %w",
			err,
		)
	}
	underlay, path, err := winner.Resources()
	if err != nil {
		return WarmPreparation{}, err
	}
	resource := &warmPreparedResource{
		path:     path,
		underlay: underlay,
	}
	fail := func(cause error) (WarmPreparation, error) {
		cleanupContext, cancelCleanup := context.WithTimeout(
			context.Background(),
			preparedH3LoserCleanupLimit,
		)
		closeErr := resource.Close(cleanupContext)
		cancelCleanup()
		return WarmPreparation{}, errors.Join(
			cause,
			closeErr,
		)
	}

	if !path.Ready() || !path.Authenticated() {
		return fail(errors.New(
			"prepared H3 path lacks live authenticated evidence",
		))
	}

	preparedUnderlay := &singlePreparedUnderlayFactory{
		underlay: underlay,
	}
	dial := func(
		clickContext context.Context,
		binding connectivity.Binding,
		_ ProtectedUnderlay,
	) (net.PacketConn, error) {
		dialer := snapshot
		dialer.SessionID = binding.SessionID
		dialer.ManifestDigest = binding.ManifestDigest
		dialer.SequenceEpoch = fmt.Sprintf(
			"%032x", binding.SequenceEpoch,
		)
		dialer.DialQUIC = nil
		dialer.DialQUICPath = nil
		return dialer.DialPrepared(clickContext, path)
	}
	candidate, err := newCandidate(
		config.Descriptor,
		dial,
		preparedUnderlay,
		config.Tunnel,
		config.Verifier,
		config.Transactions,
		now,
		config.TeardownTimeout,
	)
	if err != nil {
		return fail(err)
	}
	candidate.sessionExpiresAt = committedSessionExpiresAt
	return WarmPreparation{
		Candidate:       candidate,
		ProbeFreshUntil: warmUntil,
		WarmUntil:       warmUntil,
		Resource:        resource,
	}, nil
}

func assignFreshPreparationIdentity(dialer *carrier.H3Dialer) error {
	if dialer == nil {
		return errors.New("preparation lane H3 dialer is required")
	}
	sessionID, err := mobility.NewSessionID()
	if err != nil {
		return fmt.Errorf("create preparation lane session: %w", err)
	}
	sequenceEpoch, err := mobility.NewSessionID()
	if err != nil {
		return fmt.Errorf("create preparation lane sequence epoch: %w", err)
	}
	dialer.SessionID = sessionID
	dialer.SequenceEpoch = sequenceEpoch
	return nil
}

type singlePreparedUnderlayFactory struct {
	mu       sync.Mutex
	underlay PreparedProtectedUnderlay
	claimed  bool
}

func (factory *singlePreparedUnderlayFactory) Open(
	ctx context.Context,
	binding connectivity.Binding,
) (ProtectedUnderlay, error) {
	if ctx == nil {
		return nil, errors.New("prepared H3 click context is required")
	}
	if cause := context.Cause(ctx); cause != nil {
		return nil, cause
	}
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if factory.claimed || nilInterface(factory.underlay) {
		return nil, errors.New(
			"prepared H3 underlay is already consumed",
		)
	}
	if err := factory.underlay.Claim(binding); err != nil {
		return nil, err
	}
	factory.claimed = true
	return factory.underlay, nil
}

type warmPreparedResource struct {
	path     *carrier.PreparedH3Path
	underlay PreparedProtectedUnderlay
	pathOnce sync.Once
	pathErr  error
}

type preparedH3Attempt struct {
	mu       sync.Mutex
	path     *carrier.PreparedH3Path
	underlay PreparedProtectedUnderlay
	closed   bool
	closeErr error
}

func (attempt *preparedH3Attempt) SetUnderlay(
	ctx context.Context,
	underlay PreparedProtectedUnderlay,
) error {
	if attempt == nil {
		if !nilInterface(underlay) {
			return underlay.Close(ctx)
		}
		return errors.New("prepared H3 attempt is nil")
	}
	attempt.mu.Lock()
	if !attempt.closed {
		attempt.underlay = underlay
		attempt.mu.Unlock()
		return nil
	}
	attempt.mu.Unlock()
	if !nilInterface(underlay) {
		return underlay.Close(ctx)
	}
	return errors.New("prepared H3 attempt was already closed")
}

func (attempt *preparedH3Attempt) SetPath(
	path *carrier.PreparedH3Path,
) error {
	if attempt == nil {
		if path != nil {
			return path.Close()
		}
		return errors.New("prepared H3 attempt is nil")
	}
	attempt.mu.Lock()
	if !attempt.closed {
		attempt.path = path
		attempt.mu.Unlock()
		return nil
	}
	attempt.mu.Unlock()
	if path != nil {
		return path.Close()
	}
	return errors.New("prepared H3 attempt was already closed")
}

func (attempt *preparedH3Attempt) Resources() (
	PreparedProtectedUnderlay,
	*carrier.PreparedH3Path,
	error,
) {
	if attempt == nil {
		return nil, nil, errors.New("prepared H3 attempt is nil")
	}
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if attempt.closed || nilInterface(attempt.underlay) ||
		attempt.path == nil {
		return nil, nil, errors.New(
			"prepared H3 winner no longer owns complete resources",
		)
	}
	return attempt.underlay, attempt.path, nil
}

func (attempt *preparedH3Attempt) Close(ctx context.Context) error {
	if attempt == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	attempt.mu.Lock()
	if attempt.closed {
		err := attempt.closeErr
		attempt.mu.Unlock()
		return err
	}
	attempt.closed = true
	path := attempt.path
	underlay := attempt.underlay
	attempt.path = nil
	attempt.underlay = nil
	attempt.mu.Unlock()

	var closeErr error
	if path != nil {
		closeErr = path.Close()
	}
	if !nilInterface(underlay) {
		closeErr = errors.Join(closeErr, underlay.Close(ctx))
	}
	attempt.mu.Lock()
	attempt.closeErr = errors.Join(attempt.closeErr, closeErr)
	closeErr = attempt.closeErr
	attempt.mu.Unlock()
	return closeErr
}

type raceResult[T any] struct {
	index int
	value T
	err   error
}

func firstSuccessfulHedgedRace[T any](
	ctx context.Context,
	hedgeDelay time.Duration,
	cleanupLimit time.Duration,
	tasks []func(context.Context) (T, error),
	cleanup func(context.Context, T) error,
	abortTasks ...func(context.Context, int) error,
) (T, error) {
	var zero T
	if ctx == nil {
		return zero, errors.New("race context is required")
	}
	if len(tasks) < 2 || cleanup == nil || len(abortTasks) > 1 ||
		hedgeDelay <= 0 || cleanupLimit <= 0 {
		return zero, errors.New(
			"race requires at least two tasks, positive bounds, and cleanup",
		)
	}
	if cause := context.Cause(ctx); cause != nil {
		return zero, cause
	}
	for _, task := range tasks {
		if task == nil {
			return zero, errors.New("race task is nil")
		}
	}
	var abortTask func(context.Context, int) error
	if len(abortTasks) == 1 {
		abortTask = abortTasks[0]
		if abortTask == nil {
			return zero, errors.New("race abort task is nil")
		}
	}

	raceContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan raceResult[T], len(tasks))
	launch := func(index int) {
		task := tasks[index]
		go func() {
			value, err := task(raceContext)
			results <- raceResult[T]{
				index: index,
				value: value,
				err:   err,
			}
		}()
	}

	var (
		winner          T
		winnerFound     bool
		taskErrors      []error
		cleanupValues   []T
		launched        = 1
		completed       int
		stopLaunching   bool
		cleanupDeadline time.Time
		cleanupTimer    *time.Timer
		cleanupDone     <-chan time.Time
		drainTimedOut   bool
		abortError      error
	)
	startCleanupWindow := func() {
		if cleanupTimer != nil {
			return
		}
		cleanupDeadline = time.Now().Add(cleanupLimit)
		cleanupTimer = time.NewTimer(cleanupLimit)
		cleanupDone = cleanupTimer.C
	}
	defer func() {
		if cleanupTimer != nil {
			cleanupTimer.Stop()
		}
	}()
	launch(0)
	hedgeTimer := time.NewTimer(hedgeDelay)
	defer hedgeTimer.Stop()
	hedgeChannel := hedgeTimer.C
	stopHedgeTimer := func() {
		if !hedgeTimer.Stop() {
			select {
			case <-hedgeTimer.C:
			default:
			}
		}
		hedgeChannel = nil
	}
	armNextHedge := func() {
		stopHedgeTimer()
		if launched < len(tasks) && !winnerFound {
			hedgeTimer.Reset(hedgeDelay)
			hedgeChannel = hedgeTimer.C
		}
	}
	parentDone := ctx.Done()
drain:
	for completed < launched ||
		(!winnerFound && !stopLaunching && launched < len(tasks)) {
		select {
		case <-parentDone:
			stopLaunching = true
			cancel()
			stopHedgeTimer()
			startCleanupWindow()
			if abortTask != nil {
				indexes := make([]int, launched)
				for index := range launched {
					indexes[index] = index
				}
				abortError = errors.Join(
					abortError,
					abortRaceTasksBeforeDeadline(
						ctx,
						cleanupDeadline,
						abortTask,
						indexes,
					),
				)
			}
			parentDone = nil
		case result := <-results:
			completed++
			if cause := context.Cause(ctx); cause != nil {
				stopLaunching = true
				cancel()
				stopHedgeTimer()
				if result.err == nil {
					result.err = cause
				}
			}
			if result.err == nil && !winnerFound {
				winner = result.value
				winnerFound = true
				cancel()
				stopHedgeTimer()
				startCleanupWindow()
				if abortTask != nil {
					indexes := make([]int, 0, launched-1)
					for index := range launched {
						if index != result.index {
							indexes = append(indexes, index)
						}
					}
					abortError = errors.Join(
						abortError,
						abortRaceTasksBeforeDeadline(
							ctx,
							cleanupDeadline,
							abortTask,
							indexes,
						),
					)
				}
				continue
			}
			if result.err != nil {
				taskErrors = append(taskErrors, fmt.Errorf(
					"race task %d: %w",
					result.index,
					result.err,
				))
			}
			cleanupValues = append(cleanupValues, result.value)
			if !winnerFound && !stopLaunching &&
				completed == launched &&
				launched < len(tasks) {
				stopHedgeTimer()
				launch(launched)
				launched++
				armNextHedge()
			}
		case <-hedgeChannel:
			if context.Cause(ctx) != nil {
				stopLaunching = true
				cancel()
				stopHedgeTimer()
				continue
			}
			launch(launched)
			launched++
			armNextHedge()
		case <-cleanupDone:
			drainTimedOut = true
			stopLaunching = true
			cancel()
			stopHedgeTimer()
			break drain
		}
	}

	if cause := context.Cause(ctx); cause != nil && winnerFound {
		taskErrors = append(taskErrors, cause)
		cleanupValues = append(cleanupValues, winner)
		winner = zero
		winnerFound = false
	}
	if drainTimedOut {
		persistentCleanupContext := context.WithoutCancel(ctx)
		known := cleanupValues
		if winnerFound {
			known = append(known, winner)
		}
		for _, value := range known {
			go func(value T) {
				_ = cleanup(persistentCleanupContext, value)
			}(value)
		}
		pending := launched - completed
		if pending > 0 {
			go func() {
				for range pending {
					result := <-results
					go func(value T) {
						_ = cleanup(persistentCleanupContext, value)
					}(result.value)
				}
			}()
		}
		return zero, errors.Join(
			errors.New("race task drain exceeded cleanup limit"),
			context.DeadlineExceeded,
			context.Cause(ctx),
		)
	}
	if cleanupTimer == nil {
		startCleanupWindow()
	}
	cleanupContext, cancelCleanup := context.WithDeadline(
		context.WithoutCancel(ctx),
		cleanupDeadline,
	)
	defer cancelCleanup()
	cleanupError := abortError
	for _, value := range cleanupValues {
		cleanupError = errors.Join(
			cleanupError,
			cleanupRaceValueWithinContext(
				cleanupContext,
				cleanup,
				value,
			),
		)
	}
	if cleanupError != nil {
		if winnerFound {
			cleanupError = errors.Join(
				cleanupError,
				cleanupRaceValueWithinContext(
					cleanupContext,
					cleanup,
					winner,
				),
			)
		}
		return zero, fmt.Errorf(
			"race loser cleanup failed: %w",
			cleanupError,
		)
	}
	if winnerFound {
		return winner, nil
	}
	return zero, errors.Join(
		errors.New("all raced tasks failed"),
		context.Cause(ctx),
		errors.Join(taskErrors...),
	)
}

func abortRaceTasksBeforeDeadline(
	parent context.Context,
	deadline time.Time,
	abort func(context.Context, int) error,
	indexes []int,
) error {
	if abort == nil || len(indexes) == 0 {
		return nil
	}
	ctx, cancel := context.WithDeadline(
		context.WithoutCancel(parent),
		deadline,
	)
	defer cancel()
	var abortError error
	for _, index := range indexes {
		result := make(chan error, 1)
		go func(index int) {
			result <- abort(ctx, index)
		}(index)
		select {
		case err := <-result:
			abortError = errors.Join(abortError, err)
		case <-ctx.Done():
			return errors.Join(abortError, context.Cause(ctx))
		}
	}
	return abortError
}

func cleanupRaceValueWithinContext[T any](
	ctx context.Context,
	cleanup func(context.Context, T) error,
	value T,
) error {
	result := make(chan error, 1)
	go func() {
		result <- cleanup(ctx, value)
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (resource *warmPreparedResource) Close(ctx context.Context) error {
	if resource == nil {
		return nil
	}
	resource.pathOnce.Do(func() {
		resource.pathErr = resource.path.Close()
	})
	var underlayErr error
	if !nilInterface(resource.underlay) {
		underlayErr = resource.underlay.Close(ctx)
	}
	return errors.Join(resource.pathErr, underlayErr)
}
