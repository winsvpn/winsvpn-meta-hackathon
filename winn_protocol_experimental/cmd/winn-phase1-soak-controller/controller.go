package main

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Controller drives the soak.
//
// It owns scheduling, provenance, resumption, bounds and evidence. It owns no
// measurement semantics whatsoever: what a cycle means, what it measures and
// whether the numbers are any good is entirely the accepted runner's business,
// and this type deliberately cannot inspect or reinterpret them.
type Controller struct {
	config     Config
	clock      Clock
	runner     CycleRunner
	receipts   *ReceiptLog
	checkpoint *CheckpointStore
	lock       *InstanceLock
	frozen     Provenance
	terminal   *TerminalState
	emit       *emitter
	evidence   string

	// reverify recomputes the snapshot digest before each cycle. It is a
	// field so a test can drive drift without needing to mutate a real tree
	// mid-loop, which on a read-only mount is not possible at all.
	reverify func() (Provenance, error)

	// freeSpace reports free bytes on the evidence filesystem.
	freeSpace func() (int64, error)

	// carried is the monotonic time this soak had already served before this
	// process started. It comes from the checkpoint and is added to, never
	// replaced. This single field is the no-duration-reset guarantee.
	carried time.Duration

	resumeCount int64
	wallAtStart string
}

// Summary is the final, deliberately non-promotional report.
type Summary struct {
	Schema string `json:"schema"`
	RunID  string `json:"run_id"`

	// Promotable is always false and is a field rather than a comment so
	// that a summary file found on its own, months later, still says so.
	Promotable bool `json:"promotable"`
	// NonPromotionNotice is likewise carried in the artifact. It is written
	// by summaryNotice and cannot be configured away.
	NonPromotionNotice string `json:"non_promotion_notice"`

	TerminalReason TerminalReason `json:"terminal_reason"`
	TerminalDetail string         `json:"terminal_detail"`

	RequestedDurationNanos time.Duration `json:"requested_duration_nanos"`
	ServedDurationNanos    time.Duration `json:"served_duration_nanos"`
	DurationServed         bool          `json:"duration_served"`
	OvershootNanos         time.Duration `json:"overshoot_nanos"`

	CyclesAttempted int64 `json:"cycles_attempted"`
	CyclesSucceeded int64 `json:"cycles_succeeded"`
	CyclesFailed    int64 `json:"cycles_failed"`
	CyclesTimedOut  int64 `json:"cycles_timed_out"`
	CyclesCancelled int64 `json:"cycles_cancelled"`
	ConservationOK  bool  `json:"conservation_ok"`

	ResumeCount          int64  `json:"resume_count"`
	FirstFailureSequence int64  `json:"first_failure_sequence"`
	FinalReceiptDigest   string `json:"final_receipt_digest"`
	FinalCheckpoint      string `json:"final_checkpoint_content_address"`

	Provenance Provenance `json:"provenance"`

	// EnvironmentNames lists the child environment's KEYS. No value from
	// that environment appears anywhere in this struct.
	EnvironmentNames []string `json:"child_environment_names"`
}

const summarySchema = "winn-phase1-soak-summary/v1"

// summaryNotice is the non-promotion statement carried inside every summary.
//
// It is a constant, not a template, and nothing in this program can suppress or
// parameterise it.
const summaryNotice = "NOT PROMOTABLE, AND NOT THE PRODUCTION AUTO SOAK. " +
	"This is a harness run. The production Phase 1 Auto soak requires the " +
	"real multi-gateway topology, a real seven-day execution on it, and a " +
	"controller-side finalization performed off the producing host over " +
	"retrieved evidence. None of those is performed here: this controller " +
	"signs nothing, seals no terminal audit checkpoint, and creates no " +
	"anchor artifact. No result in this file may be cited as a passed gate."

// Run executes the soak.
//
// The loop is intentionally flat and its exit conditions are all in one place.
// A seven-day loop with termination logic scattered across helpers is a loop
// whose stopping behaviour nobody can check by reading it.
func (c *Controller) Run(ctx context.Context) (Summary, error) {
	if c.terminal == nil {
		c.terminal = &TerminalState{}
	}
	total := c.config.Duration

	for {
		served := c.served()
		if served >= total {
			if err := c.saveTerminalCheckpoint(); err != nil {
				c.terminal.Claim(ReasonEvidenceFault, fmt.Sprintf(
					"cannot latch terminal duration checkpoint: %v", err,
				))
			} else {
				c.terminal.Claim(ReasonDurationServed, fmt.Sprintf(
					"served %s of a requested %s", served, total,
				))
			}
			break
		}
		if err := ctx.Err(); err != nil {
			c.terminal.Claim(ReasonContextDone, err.Error())
			break
		}

		// The free-space gate runs BEFORE the cycle, not after. Finding out
		// afterwards that the disk was full means the cycle's own evidence
		// is the thing that could not be written.
		free, err := c.freeSpace()
		if err != nil {
			c.terminal.Claim(ReasonEvidenceFault, fmt.Sprintf(
				"cannot measure free space on the evidence filesystem: %v", err,
			))
			break
		}
		if free < c.config.MinFreeBytes {
			c.terminal.Claim(ReasonFreeSpaceFloor, fmt.Sprintf(
				"%s free is below the %s floor",
				formatBytes(free), formatBytes(c.config.MinFreeBytes),
			))
			break
		}

		current, err := c.reverify()
		if err != nil {
			c.terminal.Claim(ReasonSourceDrift, fmt.Sprintf(
				"snapshot could not be re-verified: %v", err,
			))
			break
		}
		if kind, detail := detectDrift(c.frozen, current); kind != driftNone {
			c.terminal.Claim(ReasonSourceDrift, fmt.Sprintf(
				"%s: %s", kind, detail,
			))
			break
		}

		sequence := c.receipts.Count() + 1
		readiness := c.config.readinessFor(sequence)
		if readiness == ReadinessCold && c.config.ColdSettle > 0 {
			if err := c.clock.Sleep(ctx, c.config.ColdSettle); err != nil {
				c.terminal.Claim(ReasonContextDone, err.Error())
				break
			}
		}

		request := CycleRequest{
			Sequence:         sequence,
			Readiness:        readiness,
			Timeout:          c.config.CycleTimeout,
			OutputLimit:      c.config.MaxCycleOutputBytes,
			Environment:      c.config.cycleEnvironment(sequence, readiness, c.lock.Nonce()),
			WorkingDirectory: c.frozen.SnapshotRoot,
		}
		if err := request.validate(); err != nil {
			c.terminal.Claim(ReasonRunnerFault, err.Error())
			break
		}

		startedElapsed := c.served()
		// The absolute per-cycle deadline is applied HERE as well as inside
		// the production runner. Two independent applications of the same
		// bound, because they fail differently: the runner's own deadline is
		// what turns a hung child into a SIGTERM and then a SIGKILL, and this
		// one is what guarantees the CONTRACT holds for any implementation of
		// CycleRunner, including one that forgot.
		//
		// What neither of them can do is preempt a runner that ignores its
		// context outright. Go cannot interrupt a goroutine, so a runner that
		// never returns hangs this loop, and the honest backstop for that is
		// the outer systemd RuntimeMaxSec that -print-systemd-command emits.
		// That limitation is stated rather than defended against with a
		// mechanism that would abandon a live child process on a shared host.
		cycleCtx, cancelCycle := context.WithTimeout(ctx, request.Timeout)
		result, runErr := c.runner.RunCycle(cycleCtx, request)
		cancelCycle()
		endedElapsed := c.served()
		if runErr != nil {
			// The runner could not produce a result at all. This is not a
			// failed cycle and must not be counted as one: a missing binary
			// and a runner that ran and said no are different findings, and
			// a conservation total that merged them would be arithmetic
			// over two different things.
			c.terminal.Claim(ReasonRunnerFault, runErr.Error())
			break
		}
		if !result.Outcome.valid() {
			c.terminal.Claim(ReasonRunnerFault, fmt.Sprintf(
				"the cycle runner returned an unnameable outcome %q",
				result.Outcome,
			))
			break
		}
		if err := validateContainmentCleanup(result.ContainmentCleanup); err != nil {
			c.terminal.Claim(ReasonRunnerFault, fmt.Sprintf(
				"the cycle runner returned invalid containment cleanup: %v",
				err,
			))
			break
		}
		result.StartedElapsed = startedElapsed
		result.EndedElapsed = endedElapsed

		broken := c.config.Bounds.check(
			result.Resources, result.StdoutBytes, result.StderrBytes,
		)

		digest, err := c.recordCycle(request, result, broken, current)
		if err != nil {
			c.terminal.Claim(ReasonEvidenceFault, err.Error())
			break
		}
		if err := c.saveCheckpoint(digest); err != nil {
			c.terminal.Claim(ReasonEvidenceFault, err.Error())
			break
		}

		c.emit.Printf(
			"SOAK_CYCLE seq=%d readiness=%s outcome=%s exit=%d "+
				"served=%s of %s stdout=%d stderr=%d truncated=%t",
			request.Sequence, request.Readiness, result.Outcome,
			result.ExitStatus, c.served(), total,
			result.StdoutBytes, result.StderrBytes, result.Truncated,
		)

		switch {
		case len(broken) > 0:
			c.terminal.Claim(ReasonResourceBound, fmt.Sprintf(
				"cycle %d exceeded %s: observed %d against a limit of %d",
				request.Sequence, broken[0].Bound,
				broken[0].Observed, broken[0].Limit,
			))
		case result.Outcome == OutcomeTimedOut:
			c.terminal.Claim(ReasonCycleTimedOut, fmt.Sprintf(
				"cycle %d did not finish within %s",
				request.Sequence, c.config.CycleTimeout,
			))
		case result.Outcome == OutcomeFailed:
			c.terminal.Claim(ReasonCycleFailed, fmt.Sprintf(
				"cycle %d exited %d", request.Sequence, result.ExitStatus,
			))
		case result.Outcome == OutcomeCancelled:
			c.terminal.Claim(ReasonContextDone, fmt.Sprintf(
				"cycle %d was cancelled", request.Sequence,
			))
		}
		if c.terminal.Claimed() {
			break
		}

		if c.config.Cadence > 0 {
			if err := c.clock.Sleep(ctx, c.config.Cadence); err != nil {
				c.terminal.Claim(ReasonContextDone, err.Error())
				break
			}
		}
	}
	return c.summarise(), nil
}

// served is the total monotonic time this soak has served, across every
// process that has run it.
//
// carried comes from the checkpoint; MonotonicElapsed is this process's own
// segment. The sum is what the loop compares against the total, and it is the
// only quantity that does. There is no path in this program that recomputes
// elapsed time from wall timestamps.
func (c *Controller) served() time.Duration {
	return c.carried + c.clock.MonotonicElapsed()
}

func (c *Controller) recordCycle(
	request CycleRequest,
	result CycleResult,
	broken []ExceededBound,
	current Provenance,
) (string, error) {
	receipt := Receipt{
		RunID:                   c.config.RunID,
		InstanceNonce:           c.lock.Nonce(),
		PredecessorNonce:        c.lock.Predecessor(),
		ResumeCount:             c.resumeCount,
		Readiness:               request.Readiness,
		Outcome:                 result.Outcome,
		ExitStatus:              result.ExitStatus,
		StartedElapsedNanos:     int64(result.StartedElapsed),
		EndedElapsedNanos:       int64(result.EndedElapsed),
		AccumulatedElapsedNanos: int64(c.served()),
		WallAt:                  rfc3339(c.clock.WallNow()),
		StdoutBytes:             result.StdoutBytes,
		StderrBytes:             result.StderrBytes,
		Truncated:               result.Truncated,
		StdoutTail:              result.StdoutTail,
		StderrTail:              result.StderrTail,
		Resources:               result.Resources,
		ContainmentCleanup:      result.ContainmentCleanup,
		ExceededBounds:          broken,
		SnapshotDigest:          current.SnapshotDigest,
	}
	digest, err := c.receipts.Append(receipt)
	if err != nil {
		return "", err
	}
	if result.Outcome != OutcomeSucceeded || len(broken) > 0 {
		failure := FirstFailure{
			RunID:          c.config.RunID,
			Sequence:       c.receipts.Count(),
			Outcome:        result.Outcome,
			ExitStatus:     result.ExitStatus,
			Readiness:      request.Readiness,
			WallAt:         receipt.WallAt,
			ElapsedNanos:   int64(c.served()),
			ReceiptDigest:  digest,
			StdoutTail:     result.StdoutTail,
			StderrTail:     result.StderrTail,
			ExceededBounds: broken,
		}
		err := recordFirstFailureDirectory(c.receipts.directory, failure)
		switch {
		case err == nil:
		case errors.Is(err, errFirstFailureAlreadyRecorded):
			existing, loadErr := loadFirstFailureDirectory(
				c.receipts.directory, c.config.RunID,
			)
			if loadErr != nil {
				return "", loadErr
			}
			if validateErr := validateFirstFailure(
				c.receipts.ReplayState(), existing,
			); validateErr != nil {
				return "", validateErr
			}
		default:
			return "", err
		}
	}
	return digest, nil
}

func (c *Controller) saveCheckpoint(receiptDigest string) error {
	if receiptDigest != c.receipts.Head() {
		return fmt.Errorf(
			"receipt append returned %s but replay head is %s",
			receiptDigest, c.receipts.Head(),
		)
	}
	return c.saveCheckpointState(false, "")
}

func (c *Controller) saveTerminalCheckpoint() error {
	return c.saveCheckpointState(true, ReasonDurationServed)
}

func (c *Controller) saveCheckpointState(
	terminal bool, terminalReason TerminalReason,
) error {
	totals := c.receipts.Totals()
	replay := c.receipts.ReplayState()
	_, err := c.checkpoint.Save(Checkpoint{
		RunID:                   c.config.RunID,
		InstanceNonce:           c.lock.Nonce(),
		PredecessorNonce:        c.lock.Predecessor(),
		Provenance:              c.frozen,
		TotalDurationNanos:      int64(c.config.Duration),
		AccumulatedElapsedNanos: int64(c.served()),
		CyclesAttempted:         totals.Attempted,
		CyclesSucceeded:         totals.Succeeded,
		CyclesFailed:            totals.Failed,
		CyclesTimedOut:          totals.TimedOut,
		CyclesCancelled:         totals.Cancelled,
		LastReceiptDigest:       c.receipts.Head(),
		FirstFailureRecorded:    replay.HasFailure,
		Terminal:                terminal,
		TerminalReason:          terminalReason,
		WallAtStart:             c.wallAtStart,
		WallAtCheckpoint:        rfc3339(c.clock.WallNow()),
		ResumeCount:             c.resumeCount,
	})
	return err
}

func (c *Controller) summarise() Summary {
	reason, detail := c.terminal.Reason()
	totals := c.receipts.Totals()
	served := c.served()
	overshoot := time.Duration(0)
	if served > c.config.Duration {
		overshoot = served - c.config.Duration
	}
	address := ""
	if stored, addr, err := c.checkpoint.Load(); err == nil {
		address = addr
		_ = stored
	}
	firstFailureSequence := int64(0)
	if replay := c.receipts.ReplayState(); replay.HasFailure {
		firstFailureSequence = replay.FirstFailure.Sequence
	}
	return Summary{
		Schema:                 summarySchema,
		RunID:                  c.config.RunID,
		Promotable:             false,
		NonPromotionNotice:     summaryNotice,
		TerminalReason:         reason,
		TerminalDetail:         detail,
		RequestedDurationNanos: c.config.Duration,
		ServedDurationNanos:    served,
		DurationServed:         served >= c.config.Duration,
		OvershootNanos:         overshoot,
		CyclesAttempted:        totals.Attempted,
		CyclesSucceeded:        totals.Succeeded,
		CyclesFailed:           totals.Failed,
		CyclesTimedOut:         totals.TimedOut,
		CyclesCancelled:        totals.Cancelled,
		ConservationOK:         totals.conservationError() == nil,
		ResumeCount:            c.resumeCount,
		FirstFailureSequence:   firstFailureSequence,
		FinalReceiptDigest:     c.receipts.Head(),
		FinalCheckpoint:        address,
		Provenance:             c.frozen,
		EnvironmentNames:       EnvironmentNames(c.config.ChildEnvironment),
	}
}
