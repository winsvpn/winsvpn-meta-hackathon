package main

import (
	"os"
	"strings"
	"testing"
)

// TestGatherProvenanceConsultsTheMountProbe closes a gap that mutation testing
// found.
//
// TestUnionFilesystemIsRefused checks the POLICY -- which filesystem names are
// refused. It says nothing about whether gatherProvenance ever asks. Deleting
// the refusal from gatherProvenance left that test green on an APFS host,
// because no test could present a union mount to the real code path. This one
// swaps the probe and drives the real function.
func TestGatherProvenanceConsultsTheMountProbe(t *testing.T) {
	cfg := provenanceConfig(t)

	original := mountProber
	t.Cleanup(func() { mountProber = original })

	// Control: a plain read-only ext4 is accepted, so each refusal below is
	// attributable to the fact being changed.
	mountProber = func(*os.File) (mountFacts, error) {
		return mountFacts{
			FilesystemType: "ext4", ReadOnly: true, Available: true,
			FreeBytes: 1 << 40, TotalBytes: 1 << 41,
		}, nil
	}
	if _, err := gatherProvenance(cfg); err != nil {
		t.Fatalf("a read-only ext4 snapshot was refused: %v", err)
	}

	tests := []struct {
		name  string
		facts mountFacts
		want  string
	}{
		{
			name: "overlay",
			facts: mountFacts{
				FilesystemType: "overlay", ReadOnly: true, Available: true,
			},
			want: "union mount",
		},
		{
			name: "aufs",
			facts: mountFacts{
				FilesystemType: "aufs", ReadOnly: true, Available: true,
			},
			want: "union mount",
		},
		{
			name: "fuse",
			facts: mountFacts{
				FilesystemType: "fuse", ReadOnly: true, Available: true,
			},
			want: "interposing userspace layer",
		},
		{
			name: "unavailable probe",
			facts: mountFacts{
				Available: false,
			},
			want: "cannot report the filesystem",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mountProber = func(*os.File) (mountFacts, error) {
				return test.facts, nil
			}
			_, err := gatherProvenance(cfg)
			if err == nil {
				t.Fatalf("gatherProvenance accepted a %s snapshot", test.name)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("refusal was %v, want one containing %q",
					err, test.want)
			}
		})
	}

	// A union mount is refused even WITH the writable opt-out. The opt-out
	// relaxes immutability, not attributability, and conflating the two
	// would let -allow-writable-snapshot silently re-admit overlayfs.
	t.Run("the writable opt-out does not re-admit a union mount", func(t *testing.T) {
		permissive := cfg
		permissive.AllowWritableSnapshot = true
		mountProber = func(*os.File) (mountFacts, error) {
			return mountFacts{
				FilesystemType: "overlay", ReadOnly: false, Available: true,
			}, nil
		}
		_, err := gatherProvenance(permissive)
		if err == nil {
			t.Fatal("-allow-writable-snapshot re-admitted an overlay mount")
		}
		if !strings.Contains(err.Error(), "union mount") {
			t.Fatalf("refusal was %v, want the union-mount one", err)
		}
	})
}

// TestEvaluateSnapshotMountPolicy checks the decision in isolation, including
// the read-only gate's interaction with the opt-out.
func TestEvaluateSnapshotMountPolicy(t *testing.T) {
	readOnlyExt4 := mountFacts{
		FilesystemType: "ext4", ReadOnly: true, Available: true,
	}
	writableExt4 := mountFacts{
		FilesystemType: "ext4", ReadOnly: false, Available: true,
	}
	if err := evaluateSnapshotMount("/snap", readOnlyExt4, false); err != nil {
		t.Errorf("read-only ext4 was refused: %v", err)
	}
	if err := evaluateSnapshotMount("/snap", writableExt4, false); err == nil {
		t.Error("a writable mount was accepted without the opt-out")
	}
	if err := evaluateSnapshotMount("/snap", writableExt4, true); err != nil {
		t.Errorf("the opt-out did not admit a writable ext4: %v", err)
	}
}

// TestConservationErrorDetectsUnbalancedTotals verifies the guard rail
// directly.
//
// Mutation testing showed that removing this check breaks no other test,
// because everywhere it is called the totals are recomputed from a closed
// outcome set and therefore always balance. The comment on the function now
// says exactly that. This test exercises it on input the program cannot
// currently produce, so the guard rail is verified rather than merely present.
func TestConservationErrorDetectsUnbalancedTotals(t *testing.T) {
	balanced := receiptTotals{
		Attempted: 10, Succeeded: 6, Failed: 2, TimedOut: 1, Cancelled: 1,
	}
	if err := balanced.conservationError(); err != nil {
		t.Fatalf("balanced totals were rejected: %v", err)
	}
	for _, unbalanced := range []receiptTotals{
		{Attempted: 10, Succeeded: 6, Failed: 2, TimedOut: 1},
		{Attempted: 10, Succeeded: 11},
		{Attempted: 0, Succeeded: 1},
	} {
		if err := unbalanced.conservationError(); err == nil {
			t.Errorf("totals %+v were accepted", unbalanced)
		}
	}
}

// TestCheckpointConservationErrorDetectsUnbalancedCounters is the load-bearing
// half: a checkpoint's counters are read back from disk and CAN be edited, so
// this check does detect something the program cannot otherwise see.
func TestCheckpointConservationErrorDetectsUnbalancedCounters(t *testing.T) {
	sound := Checkpoint{
		TotalDurationNanos:      int64(DefaultDuration),
		AccumulatedElapsedNanos: 1,
		CyclesAttempted:         5,
		CyclesSucceeded:         3,
		CyclesFailed:            1,
		CyclesTimedOut:          1,
		LastReceiptDigest:       repeatHex(64),
	}
	if err := sound.conservationError(); err != nil {
		t.Fatalf("a sound checkpoint was rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*Checkpoint)
	}{
		{"counters do not sum", func(c *Checkpoint) { c.CyclesAttempted = 9 }},
		{"negative elapsed", func(c *Checkpoint) { c.AccumulatedElapsedNanos = -1 }},
		{"zero duration", func(c *Checkpoint) { c.TotalDurationNanos = 0 }},
		{"negative duration", func(c *Checkpoint) { c.TotalDurationNanos = -1 }},
		{"negative attempted", func(c *Checkpoint) { c.CyclesAttempted = -1 }},
		{"negative resume count", func(c *Checkpoint) { c.ResumeCount = -1 }},
		{"malformed receipt digest", func(c *Checkpoint) {
			c.LastReceiptDigest = "not-a-digest"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			broken := sound
			test.mutate(&broken)
			if err := broken.conservationError(); err == nil {
				t.Fatalf("%s was accepted", test.name)
			}
		})
	}
}
