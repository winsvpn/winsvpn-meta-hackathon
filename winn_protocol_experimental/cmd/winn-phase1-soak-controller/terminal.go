package main

import "sync"

// TerminalReason names why a soak stopped. The set is closed.
type TerminalReason string

const (
	ReasonDurationServed   TerminalReason = "duration_served"
	ReasonSignal           TerminalReason = "signal"
	ReasonContextDone      TerminalReason = "context_done"
	ReasonCycleFailed      TerminalReason = "cycle_failed"
	ReasonCycleTimedOut    TerminalReason = "cycle_timed_out"
	ReasonFreeSpaceFloor   TerminalReason = "free_space_floor"
	ReasonResourceBound    TerminalReason = "resource_bound_exceeded"
	ReasonSourceDrift      TerminalReason = "source_drift"
	ReasonRunnerFault      TerminalReason = "runner_fault"
	ReasonEvidenceFault    TerminalReason = "evidence_fault"
	ReasonPreflightRefusal TerminalReason = "preflight_refusal"
)

// TerminalState records the FIRST reason a soak stopped and refuses every
// later one.
//
// First-terminal-wins is the property that makes a post-mortem readable. A
// SIGTERM arriving one millisecond after a cycle failed does not turn a failure
// into an orderly shutdown, and a second SIGTERM from an impatient operator does
// not overwrite the first. Both of those are races that happen constantly in a
// seven-day run, and a last-writer-wins field would report whichever one lost.
//
// Claim returns whether the caller won, so a caller can tell the difference
// between "I stopped this run" and "I noticed it was already stopping".
type TerminalState struct {
	mu     sync.Mutex
	won    bool
	reason TerminalReason
	detail string
}

func (t *TerminalState) Claim(reason TerminalReason, detail string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.won {
		return false
	}
	t.won = true
	t.reason = reason
	t.detail = detail
	return true
}

// Claimed reports whether any reason has been recorded.
func (t *TerminalState) Claimed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.won
}

func (t *TerminalState) Reason() (TerminalReason, string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.reason, t.detail
}
