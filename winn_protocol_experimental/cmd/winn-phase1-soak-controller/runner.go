package main

import (
	"context"
	"errors"
	"time"
)

// Readiness is the warm/cold schedule axis the accepted runner already
// understands. The controller does not invent a third value; scripts/
// aicore_phase1_auto_matrix.sh rejects anything that is not warm or cold, and
// a controller that could emit a third would be building a request the runner
// is guaranteed to refuse.
type Readiness string

const (
	// ReadinessWarm reuses whatever state the previous cycle left behind.
	ReadinessWarm Readiness = "warm"
	// ReadinessCold is preceded by a settle interval so the cycle starts
	// from a quiescent host.
	ReadinessCold Readiness = "cold"
)

func (r Readiness) valid() bool {
	return r == ReadinessWarm || r == ReadinessCold
}

// CycleRequest is everything the controller hands one invocation of the
// accepted runner. It is a value, not a pointer, and it carries no channels or
// callbacks: a request must be fully recordable in a receipt, and anything a
// receipt cannot hold is a side channel the evidence would not show.
type CycleRequest struct {
	// Sequence is 1-based and increases by exactly one per attempt. It is
	// the conservation anchor for the whole receipt log.
	Sequence int64

	Readiness Readiness

	// Timeout is an ABSOLUTE per-cycle bound, not a per-read idle timeout.
	// A runner that is producing output steadily but will never finish is
	// exactly the hang this controller exists to survive.
	Timeout time.Duration

	// OutputLimit bounds the bytes retained from each of stdout and stderr.
	// Beyond it, bytes are counted and discarded. There is no mode in which
	// this is unbounded.
	OutputLimit int64

	// Environment is the COMPLETE environment for the child, constructed
	// explicitly. The controller's own environment is never inherited and
	// never merged in; see config.go for why that is a hard rule rather
	// than a default.
	Environment []string

	// WorkingDirectory is the immutable snapshot root the cycle runs from.
	WorkingDirectory string
}

// CycleOutcome is a closed set. "Other" does not exist, because an outcome the
// controller cannot name is one the conservation check cannot count, and a
// conservation check with an escape hatch conserves nothing.
type CycleOutcome string

const (
	OutcomeSucceeded CycleOutcome = "succeeded"
	OutcomeFailed    CycleOutcome = "failed"
	OutcomeTimedOut  CycleOutcome = "timed_out"
	OutcomeCancelled CycleOutcome = "cancelled"
)

func (o CycleOutcome) valid() bool {
	switch o {
	case OutcomeSucceeded, OutcomeFailed, OutcomeTimedOut, OutcomeCancelled:
		return true
	}
	return false
}

// CycleResult is what one invocation produced.
//
// ExitStatus is the process's REAL exit status. Nothing in this program pipes
// a child through grep, head, or tee to obtain it: a pipeline reports the exit
// status of its last stage, so a failing runner behind a pipe reports success,
// and a soak built on that would record a week of green cycles that never ran.
type CycleResult struct {
	Outcome CycleOutcome

	// ExitStatus is meaningful when Outcome is Succeeded or Failed. For a
	// timeout or a cancellation it is -1: the process was killed rather
	// than having exited on its own terms, and reporting a signal-derived
	// number as an exit status would invent an answer the runner never
	// gave.
	ExitStatus int

	// StdoutTail and StderrTail hold at most OutputLimit bytes each.
	StdoutTail []byte
	StderrTail []byte

	// StdoutBytes and StderrBytes are the TOTAL bytes produced, including
	// those discarded past the limit. Keeping the true count is the point:
	// a runner that emitted four gigabytes and a runner that emitted four
	// kilobytes must not look identical in the evidence.
	StdoutBytes int64
	StderrBytes int64
	Truncated   bool

	Resources ResourceSample
	// ContainmentCleanup is attached only after the containment lifecycle's
	// Finish operation succeeds. Its closed shape distinguishes verified
	// Linux cgroup removal from an explicitly non-applicable platform.
	ContainmentCleanup CycleContainmentCleanup

	// StartedElapsed and EndedElapsed are monotonic offsets from the soak's
	// origin, not wall timestamps.
	StartedElapsed time.Duration
	EndedElapsed   time.Duration
}

// CycleRunner is the injected command contract.
//
// Implementations must be safe to call from one goroutine at a time and must
// not be called concurrently by this controller; the one-at-a-time property is
// the controller's responsibility and is asserted, not assumed, by
// serialisingRunner below.
//
// A returned error means the controller could not obtain a result at all --
// the binary was missing, the fork failed. It does NOT mean the cycle failed;
// a cycle that ran and exited non-zero returns a CycleResult with
// OutcomeFailed and a nil error. Collapsing those two would make a missing
// runner indistinguishable from a runner that ran and said no.
type CycleRunner interface {
	RunCycle(ctx context.Context, request CycleRequest) (CycleResult, error)
}

var errRunnerReentered = errors.New(
	"the cycle runner was entered while a cycle was already in flight",
)

// serialisingRunner enforces the one-at-a-time rule by detecting a violation
// rather than by serialising around it.
//
// A mutex would make an overlapping call correct-looking: the second caller
// would simply wait, and a controller bug that scheduled two cycles at once
// would be invisible forever. Failing loudly is the whole value.
type serialisingRunner struct {
	inner CycleRunner
	inUse chan struct{}
}

func newSerialisingRunner(inner CycleRunner) *serialisingRunner {
	return &serialisingRunner{inner: inner, inUse: make(chan struct{}, 1)}
}

func (r *serialisingRunner) RunCycle(
	ctx context.Context, request CycleRequest,
) (CycleResult, error) {
	select {
	case r.inUse <- struct{}{}:
	default:
		return CycleResult{}, errRunnerReentered
	}
	defer func() { <-r.inUse }()
	return r.inner.RunCycle(ctx, request)
}

func (q CycleRequest) validate() error {
	switch {
	case q.Sequence < 1:
		return errors.New("cycle sequence must be positive")
	case !q.Readiness.valid():
		return errors.New("cycle readiness must be warm or cold")
	case q.Timeout <= 0:
		return errors.New("cycle timeout must be positive")
	case q.OutputLimit <= 0:
		return errors.New("cycle output limit must be positive")
	case q.WorkingDirectory == "":
		return errors.New("cycle working directory must be set")
	}
	return nil
}
