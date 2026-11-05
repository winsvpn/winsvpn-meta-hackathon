package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeBehavior is what one scripted cycle does.
//
// Advance is the monotonic time the cycle consumes. It is the mechanism that
// makes every duration test in this package deterministic: no test waits for
// real time to pass, so none of them can pass or fail by scheduler luck.
type fakeBehavior struct {
	Outcome    CycleOutcome
	ExitStatus int
	Advance    time.Duration

	StdoutTail  []byte
	StderrTail  []byte
	StdoutBytes int64
	StderrBytes int64
	Truncated   bool

	Resources ResourceSample
	Cleanup   *CycleContainmentCleanup

	// Err makes RunCycle fail to produce a result at all, which is a
	// different thing from a cycle that ran and failed.
	Err error

	// MissingCleanup is used only by the fail-closed controller test. Normal
	// fake cycles always emit the explicit non-applicable cleanup shape.
	MissingCleanup bool

	// BlockUntilContextDone makes the cycle hang until its context is
	// cancelled, then report a timeout. Combined with a short real
	// CycleTimeout this exercises the deadline without a sleep: the fake
	// returns exactly when the deadline fires, however slow the machine.
	BlockUntilContextDone bool

	// Before runs at the top of the cycle, so a test can mutate state --
	// drift the snapshot, fill the disk -- at a precise point in the loop.
	Before func(sequence int64)
}

// fakeRunner is the injected CycleRunner used by every controller test.
//
// The injection is what makes a hang, a resource blow-up, a mid-loop source
// drift and an exact-nanosecond duration boundary reachable at all. None of
// them can be provoked against the real runner without a lab and a week.
type fakeRunner struct {
	mu        sync.Mutex
	clock     *fakeClock
	script    []fakeBehavior
	fallback  fakeBehavior
	requests  []CycleRequest
	callCount int64
	// concurrent is set if two calls ever overlap. The controller promises
	// one at a time; a test that merely assumed it would not notice a
	// regression.
	inFlight   int
	concurrent bool
}

func newFakeRunner(clock *fakeClock, script ...fakeBehavior) *fakeRunner {
	return &fakeRunner{
		clock:  clock,
		script: script,
		fallback: fakeBehavior{
			Outcome: OutcomeSucceeded,
			Advance: time.Hour,
		},
	}
}

func (r *fakeRunner) RunCycle(
	ctx context.Context, request CycleRequest,
) (CycleResult, error) {
	r.mu.Lock()
	r.inFlight++
	if r.inFlight > 1 {
		r.concurrent = true
	}
	index := int(r.callCount)
	r.callCount++
	r.requests = append(r.requests, request)
	behavior := r.fallback
	if index < len(r.script) {
		behavior = r.script[index]
	}
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		r.inFlight--
		r.mu.Unlock()
	}()

	if behavior.Before != nil {
		behavior.Before(request.Sequence)
	}
	if behavior.BlockUntilContextDone {
		<-ctx.Done()
		r.clock.Advance(behavior.Advance)
		return CycleResult{
			Outcome:            OutcomeTimedOut,
			ExitStatus:         -1,
			ContainmentCleanup: nonApplicableContainmentCleanup(),
		}, nil
	}
	r.clock.Advance(behavior.Advance)
	if behavior.Err != nil {
		return CycleResult{}, behavior.Err
	}
	outcome := behavior.Outcome
	if outcome == "" {
		outcome = OutcomeSucceeded
	}
	stdoutBytes := behavior.StdoutBytes
	if stdoutBytes < int64(len(behavior.StdoutTail)) {
		stdoutBytes = int64(len(behavior.StdoutTail))
	}
	stderrBytes := behavior.StderrBytes
	if stderrBytes < int64(len(behavior.StderrTail)) {
		stderrBytes = int64(len(behavior.StderrTail))
	}
	result := CycleResult{
		Outcome:     outcome,
		ExitStatus:  behavior.ExitStatus,
		StdoutTail:  behavior.StdoutTail,
		StderrTail:  behavior.StderrTail,
		StdoutBytes: stdoutBytes,
		StderrBytes: stderrBytes,
		Truncated:   behavior.Truncated || stdoutBytes > int64(len(behavior.StdoutTail)),
		Resources:   behavior.Resources,
	}
	if !behavior.MissingCleanup {
		if behavior.Cleanup != nil {
			result.ContainmentCleanup = *behavior.Cleanup
		} else {
			result.ContainmentCleanup = nonApplicableContainmentCleanup()
		}
	}
	return result, nil
}

func (r *fakeRunner) Calls() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.callCount
}

func (r *fakeRunner) Requests() []CycleRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]CycleRequest, len(r.requests))
	copy(out, r.requests)
	return out
}

func (r *fakeRunner) SawConcurrency() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.concurrent
}

// TestSerialisingRunnerDetectsOverlap proves the one-at-a-time wrapper reports
// a violation instead of quietly serialising around it.
//
// A mutex-based wrapper would make this test pass by making the second caller
// wait, which is precisely the failure mode being excluded: the controller bug
// would then be invisible.
func TestSerialisingRunnerDetectsOverlap(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var announceOnce sync.Once
	blocking := runnerFunc(func(
		context.Context, CycleRequest,
	) (CycleResult, error) {
		// Only the FIRST call blocks. Later calls return at once, so the
		// reusability assertion at the end of this test is not itself
		// waiting on a channel nobody will close.
		first := false
		announceOnce.Do(func() {
			first = true
			close(entered)
		})
		if first {
			<-release
		}
		return CycleResult{
			Outcome:            OutcomeSucceeded,
			ContainmentCleanup: nonApplicableContainmentCleanup(),
		}, nil
	})
	wrapped := newSerialisingRunner(blocking)
	request := CycleRequest{
		Sequence:         1,
		Readiness:        ReadinessWarm,
		Timeout:          time.Minute,
		OutputLimit:      1024,
		WorkingDirectory: "/tmp",
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = wrapped.RunCycle(context.Background(), request)
	}()
	<-entered

	_, err := wrapped.RunCycle(context.Background(), request)
	if !errors.Is(err, errRunnerReentered) {
		t.Fatalf("second concurrent call returned %v, want errRunnerReentered", err)
	}
	close(release)
	<-done

	// And after the first call finishes the wrapper is usable again: a
	// wrapper that latched would stop the soak on its first cycle.
	if _, err := wrapped.RunCycle(context.Background(), request); err != nil {
		t.Fatalf("sequential call after release failed: %v", err)
	}
}

type runnerFunc func(context.Context, CycleRequest) (CycleResult, error)

func (f runnerFunc) RunCycle(
	ctx context.Context, request CycleRequest,
) (CycleResult, error) {
	return f(ctx, request)
}
