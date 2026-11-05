package main

import (
	"errors"
	"fmt"
)

// killScope names what a signal will reach.
type killScope string

const (
	// scopeProcessGroup signals the child and every descendant it started.
	// Only ever chosen when the child is confirmed to be the LEADER of its
	// own group, which means the group contains nothing this controller did
	// not cause to exist.
	scopeProcessGroup killScope = "process_group"
	// scopeSingleProcess signals exactly one pid. Chosen when the child is
	// not its own group leader, because the group it is in then also
	// contains this controller and whatever started it.
	scopeSingleProcess killScope = "single_process"
)

// killPlan is the fully resolved argument to kill(2).
//
// Target is the literal first argument: a positive pid signals one process, a
// negative value signals the process group with that absolute value. Nothing
// else computes that argument; there is exactly one place in this program where
// a signal target is decided, and this is it.
type killPlan struct {
	Target int
	Scope  killScope
	PID    int
}

var (
	errKillNoOwnedChild = errors.New(
		"refusing to signal: no child is owned by this controller",
	)
	errKillGroupUnknown = errors.New(
		"refusing to signal: the child's process group could not be read",
	)
)

// planKill decides what a cleanup is allowed to signal.
//
// This function is the reason a shared host survives this controller. On a box
// that also runs the carrier, the gateway, and whatever else the project has
// deployed, three specific arguments to kill(2) are catastrophic and two of
// them are easy to produce by accident:
//
//	kill(-1, ...)  signals EVERY process the caller may signal. As root that
//	               is the entire machine. It is produced by negating a pid of
//	               1, or by negating a pgid that was never read successfully
//	               and left at its zero value minus one.
//	kill(0, ...)   signals the CALLER'S OWN process group -- this controller,
//	               its parent shell, and its siblings. It is produced by
//	               negating a zero pgid.
//	kill(-N, ...)  where N is not the child's own group leader signals every
//	               member of whatever group the child happened to land in.
//	               Produced whenever Setpgid silently failed.
//
// Each is refused by construction below, and each has a test that fails if the
// corresponding guard is removed.
//
// pgidErr carries whatever Getpgid returned. A failure there is a refusal, not
// a fallback: not knowing which group a process is in is precisely the state in
// which guessing is unaffordable.
func planKill(childPID, observedPGID int, pgidErr error) (killPlan, error) {
	// A pid of 0 is "my own group", 1 is init, and anything negative is
	// already a group specifier. None of the three can be a child this
	// controller forked, so none of them may reach kill(2) from here.
	if childPID <= 1 {
		return killPlan{}, fmt.Errorf(
			"%w (candidate pid %d is not a forkable child pid)",
			errKillNoOwnedChild, childPID,
		)
	}
	if pgidErr != nil {
		return killPlan{}, fmt.Errorf("%w: %w", errKillGroupUnknown, pgidErr)
	}
	if observedPGID <= 1 {
		return killPlan{}, fmt.Errorf(
			"%w (reported group %d is not a real process group)",
			errKillGroupUnknown, observedPGID,
		)
	}
	if observedPGID != childPID {
		// Setpgid did not take effect, so this child shares a group with
		// the controller. Signalling that group would take the controller
		// down with it and, on a host where the controller was started
		// from an operator's shell, the shell too. One pid only.
		return killPlan{
			Target: childPID,
			Scope:  scopeSingleProcess,
			PID:    childPID,
		}, nil
	}
	target := -childPID
	// Belt and braces on the two values that must never be produced. This
	// is unreachable given the guards above; it stays because the cost of
	// being wrong here is the whole machine, and because a later edit to the
	// conditions above would be caught by it.
	if target >= -1 {
		return killPlan{}, fmt.Errorf(
			"%w (computed target %d would broadcast)",
			errKillNoOwnedChild, target,
		)
	}
	return killPlan{
		Target: target,
		Scope:  scopeProcessGroup,
		PID:    childPID,
	}, nil
}
