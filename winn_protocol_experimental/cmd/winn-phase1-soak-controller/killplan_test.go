package main

import (
	"errors"
	"syscall"
	"testing"
)

// TestPlanKillNeverBroadcasts is the test that protects the shared host.
//
// Every case names a value that reaches kill(2) as a catastrophe if the
// corresponding guard in planKill is removed. Each is checked for the exact
// target, not merely for "an error occurred": a test that only asserted err !=
// nil would pass if planKill returned an error for an unrelated reason and
// would keep passing after the guard it names had been deleted.
func TestPlanKillNeverBroadcasts(t *testing.T) {
	tests := []struct {
		name        string
		childPID    int
		observed    int
		pgidErr     error
		wantTarget  int
		wantScope   killScope
		wantRefusal error
	}{
		{
			name:       "own group leader is signalled as a group",
			childPID:   4242,
			observed:   4242,
			wantTarget: -4242,
			wantScope:  scopeProcessGroup,
		},
		{
			name:       "not the group leader falls back to one pid",
			childPID:   4242,
			observed:   17,
			wantTarget: 4242,
			wantScope:  scopeSingleProcess,
		},
		{
			// Negating a pid of 1 produces kill(-1), which as root signals
			// every process on the machine.
			name:        "pid 1 is refused",
			childPID:    1,
			observed:    1,
			wantRefusal: errKillNoOwnedChild,
		},
		{
			// Negating a zero pid produces kill(0), which signals the
			// CONTROLLER'S OWN process group.
			name:        "pid 0 is refused",
			childPID:    0,
			observed:    0,
			wantRefusal: errKillNoOwnedChild,
		},
		{
			name:        "negative pid is refused",
			childPID:    -9,
			observed:    -9,
			wantRefusal: errKillNoOwnedChild,
		},
		{
			// Not knowing which group a process is in is the state in which
			// guessing is unaffordable.
			name:        "an unreadable process group is refused",
			childPID:    4242,
			observed:    0,
			pgidErr:     syscall.ESRCH,
			wantRefusal: errKillGroupUnknown,
		},
		{
			// Getpgid succeeded but reported a group that cannot be a real
			// one. Trusting it and negating produces kill(0) or kill(-1).
			name:        "a zero group with no error is still refused",
			childPID:    4242,
			observed:    0,
			wantRefusal: errKillGroupUnknown,
		},
		{
			name:        "group 1 is refused",
			childPID:    4242,
			observed:    1,
			wantRefusal: errKillGroupUnknown,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := planKill(test.childPID, test.observed, test.pgidErr)
			if test.wantRefusal != nil {
				if !errors.Is(err, test.wantRefusal) {
					t.Fatalf("planKill returned (%+v, %v), want a %v refusal",
						plan, err, test.wantRefusal)
				}
				if plan.Target != 0 {
					t.Fatalf("a refused plan carries target %d; a caller that "+
						"ignored the error would signal it", plan.Target)
				}
				return
			}
			if err != nil {
				t.Fatalf("planKill refused a legitimate child: %v", err)
			}
			if plan.Target != test.wantTarget {
				t.Fatalf("target %d, want %d", plan.Target, test.wantTarget)
			}
			if plan.Scope != test.wantScope {
				t.Fatalf("scope %q, want %q", plan.Scope, test.wantScope)
			}
			if plan.PID != test.childPID {
				t.Fatalf("plan records pid %d, want %d", plan.PID, test.childPID)
			}
		})
	}
}

// TestPlanKillNeverProducesADangerousTargetOverAWideRange sweeps the whole
// dangerous neighbourhood rather than sampling it.
//
// The three values that must never leave this function are -1, 0 and 1: the
// first is the machine-wide broadcast, the second is the caller's own group,
// and the third is init. A sweep is used because the guards are inequalities,
// and an off-by-one in an inequality is exactly the mistake a handful of
// hand-picked cases misses.
func TestPlanKillNeverProducesADangerousTargetOverAWideRange(t *testing.T) {
	for pid := -8; pid <= 8; pid++ {
		for observed := -8; observed <= 8; observed++ {
			for _, pgidErr := range []error{nil, syscall.EPERM} {
				plan, err := planKill(pid, observed, pgidErr)
				if err != nil {
					continue
				}
				switch plan.Target {
				case -1, 0, 1:
					t.Fatalf("planKill(%d, %d, %v) returned target %d, "+
						"which broadcasts or signals init",
						pid, observed, pgidErr, plan.Target)
				}
				if pid <= 1 {
					t.Fatalf("planKill accepted pid %d, which cannot be an "+
						"owned child", pid)
				}
				if pgidErr != nil {
					t.Fatalf("planKill accepted a plan despite Getpgid "+
						"failing with %v", pgidErr)
				}
			}
		}
	}
}

// TestPlanKillGroupScopeRequiresLeadership states the property in one line so
// a reader does not have to infer it from the table above.
//
// A group signal is only ever chosen when the child IS the group leader, which
// means the group was created by Setpgid for this child and contains nothing
// the controller did not cause to exist. Any other group might contain an
// unrelated service that was already running on the host.
func TestPlanKillGroupScopeRequiresLeadership(t *testing.T) {
	for _, observed := range []int{2, 3, 100, 999, 5000} {
		const childPID = 4242
		plan, err := planKill(childPID, observed, nil)
		if err != nil {
			t.Fatalf("planKill(%d, %d): %v", childPID, observed, err)
		}
		if observed == childPID {
			continue
		}
		if plan.Scope == scopeProcessGroup {
			t.Fatalf("planKill chose a group signal for a child that is not "+
				"its group leader (pid %d, group %d); the group may contain "+
				"unrelated services", childPID, observed)
		}
		if plan.Target != childPID {
			t.Fatalf("single-process target %d, want %d", plan.Target, childPID)
		}
	}
}
