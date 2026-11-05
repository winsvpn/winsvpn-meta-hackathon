package main

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func storedCheckpoint(cfg Config, provenance Provenance) Checkpoint {
	return Checkpoint{
		Schema:                  checkpointSchema,
		RunID:                   cfg.RunID,
		InstanceNonce:           "aabbccddaabbccddaabbccddaabbccdd",
		Provenance:              provenance,
		TotalDurationNanos:      int64(cfg.Duration),
		AccumulatedElapsedNanos: int64(72 * time.Hour),
		CyclesAttempted:         3,
		CyclesSucceeded:         3,
		LastReceiptDigest:       strings.Repeat("f", 64),
		WallAtStart:             rfc3339(testOrigin),
		WallAtCheckpoint:        rfc3339(testOrigin.Add(72 * time.Hour)),
		ResumeCount:             0,
	}
}

func replayForCheckpoint(checkpoint Checkpoint) ReceiptReplayState {
	return ReceiptReplayState{
		Count: checkpoint.CyclesAttempted,
		Head:  checkpoint.LastReceiptDigest,
		Totals: receiptTotals{
			Attempted: checkpoint.CyclesAttempted,
			Succeeded: checkpoint.CyclesSucceeded,
			Failed:    checkpoint.CyclesFailed,
			TimedOut:  checkpoint.CyclesTimedOut,
			Cancelled: checkpoint.CyclesCancelled,
		},
		HasFailure:           checkpoint.FirstFailureRecorded,
		LastInstanceNonce:    checkpoint.InstanceNonce,
		LastPredecessorNonce: checkpoint.PredecessorNonce,
		LastResumeCount:      checkpoint.ResumeCount,
	}
}

// TestResumeRefusedOnClockRollback is the fail-closed clock case.
func TestResumeRefusedOnClockRollback(t *testing.T) {
	cfg := testConfig(t, t.TempDir())
	provenance := testProvenance()
	stored := storedCheckpoint(cfg, provenance)
	checkpointTime := testOrigin.Add(72 * time.Hour)

	// One nanosecond before the checkpoint is already a rollback.
	refusal := evaluateResume(
		stored, provenance, checkpointTime.Add(-time.Nanosecond),
		cfg.Duration, cfg.RunID,
	)
	if refusal == nil {
		t.Fatal("a wall clock one nanosecond behind the checkpoint was accepted")
	}
	if refusal.Reason != "clock_rollback" {
		t.Fatalf("refusal reason %q, want clock_rollback", refusal.Reason)
	}

	// Exactly at the checkpoint is not a rollback: a host whose clock has
	// not moved must still be able to resume, and refusing equality would
	// make a fast restart impossible.
	if refusal := evaluateResume(
		stored, provenance, checkpointTime, cfg.Duration, cfg.RunID,
	); refusal != nil {
		t.Fatalf("equality was refused as a rollback: %s", refusal.Detail)
	}
	// And forward is fine.
	if refusal := evaluateResume(
		stored, provenance, checkpointTime.Add(time.Hour),
		cfg.Duration, cfg.RunID,
	); refusal != nil {
		t.Fatalf("a forward clock was refused: %s", refusal.Detail)
	}
}

// TestResumeRefusedOnSourceDrift covers every pin independently.
//
// Each subtest changes exactly one field and asserts the SPECIFIC reason. A
// test that only asserted "a refusal happened" would keep passing if the drift
// detector collapsed to a single always-true comparison.
func TestResumeRefusedOnSourceDrift(t *testing.T) {
	cfg := testConfig(t, t.TempDir())
	base := testProvenance()
	stored := storedCheckpoint(cfg, base)
	wallNow := testOrigin.Add(80 * time.Hour)

	tests := []struct {
		name   string
		mutate func(*Provenance)
		want   driftKind
	}{
		{
			name:   "runner replaced",
			mutate: func(p *Provenance) { p.RunnerDigest = "11" + repeatHex(62) },
			want:   driftRunner,
		},
		{
			name:   "verifier replaced",
			mutate: func(p *Provenance) { p.VerifierDigest = "22" + repeatHex(62) },
			want:   driftVerifier,
		},
		{
			name:   "manifest replaced",
			mutate: func(p *Provenance) { p.ManifestDigest = "33" + repeatHex(62) },
			want:   driftManifest,
		},
		{
			name:   "source digest repinned",
			mutate: func(p *Provenance) { p.SourceDigest = "44" + repeatHex(62) },
			want:   driftSourcePin,
		},
		{
			name: "controller or child environment changed",
			mutate: func(p *Provenance) {
				p.ConfigurationDigest = "66" + repeatHex(62)
			},
			want: driftConfig,
		},
		{
			name:   "snapshot tree changed",
			mutate: func(p *Provenance) { p.SnapshotDigest = "55" + repeatHex(62) },
			want:   driftSnapshot,
		},
		{
			// A tree whose digest matches but whose file count does not is
			// a walk that stopped early. Treating it as unchanged would let
			// an unreadable snapshot resume as a healthy one.
			name:   "snapshot file count changed",
			mutate: func(p *Provenance) { p.SnapshotFileCount = 1 },
			want:   driftSnapshot,
		},
		{
			name:   "runner path repointed",
			mutate: func(p *Provenance) { p.RunnerPath = "/tmp/other-runner.sh" },
			want:   driftPaths,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := base
			test.mutate(&current)
			refusal := evaluateResume(
				stored, current, wallNow, cfg.Duration, cfg.RunID,
			)
			if refusal == nil {
				t.Fatal("drift was accepted")
			}
			if refusal.Reason != string(test.want) {
				t.Fatalf("refusal reason %q, want %q",
					refusal.Reason, test.want)
			}
		})
	}

	// Control: the unmodified provenance resumes. Without it, a detector
	// that refused everything would pass every case above.
	if refusal := evaluateResume(
		stored, base, wallNow, cfg.Duration, cfg.RunID,
	); refusal != nil {
		t.Fatalf("undrifted provenance was refused: %s", refusal.Detail)
	}
}

// TestResumeRefusedOnChangedDuration is the other half of the no-reset
// guarantee: the total may not be redeclared between processes.
func TestResumeRefusedOnChangedDuration(t *testing.T) {
	cfg := testConfig(t, t.TempDir())
	provenance := testProvenance()
	stored := storedCheckpoint(cfg, provenance)
	wallNow := testOrigin.Add(80 * time.Hour)

	refusal := evaluateResume(
		stored, provenance, wallNow, 336*time.Hour, cfg.RunID,
	)
	if refusal == nil || refusal.Reason != "duration_changed" {
		t.Fatalf("a redeclared duration produced %+v, want duration_changed",
			refusal)
	}
	refusal = evaluateResume(
		stored, provenance, wallNow, cfg.Duration, "a-different-run",
	)
	if refusal == nil || refusal.Reason != "run_id_mismatch" {
		t.Fatalf("a foreign run ID produced %+v, want run_id_mismatch", refusal)
	}
}

// TestPlanResumeCarriesElapsedTimeForward states the guarantee numerically.
func TestPlanResumeCarriesElapsedTimeForward(t *testing.T) {
	cfg := testConfig(t, t.TempDir())
	provenance := testProvenance()
	stored := storedCheckpoint(cfg, provenance)

	plan, err := planResume(
		stored, true, replayForCheckpoint(stored), FirstFailureFileState{},
		provenance,
		testOrigin.Add(80*time.Hour), cfg,
	)
	if err != nil {
		t.Fatalf("planResume: %v", err)
	}
	if plan.Carried != 72*time.Hour {
		t.Fatalf("carried %s, want 72h; zero would mean the duration clock "+
			"was reset on resume", plan.Carried)
	}
	if plan.ResumeCount != 1 {
		t.Errorf("resume count %d, want 1", plan.ResumeCount)
	}
	if plan.WallAtStart != stored.WallAtStart {
		t.Errorf("wall-at-start %q, want the original %q",
			plan.WallAtStart, stored.WallAtStart)
	}

	// A fresh run carries nothing and counts no resume.
	fresh, err := planResume(
		Checkpoint{}, false, ReceiptReplayState{Head: genesisDigest},
		FirstFailureFileState{}, provenance, testOrigin, cfg,
	)
	if err != nil {
		t.Fatalf("planResume for a fresh run: %v", err)
	}
	if fresh.Carried != 0 || fresh.ResumeCount != 0 {
		t.Errorf("fresh run carried %s over %d resumes, want 0 and 0",
			fresh.Carried, fresh.ResumeCount)
	}
}

// TestPlanResumeRefusesDisagreeingState covers the two ways the checkpoint and
// the receipt log can contradict each other.
func TestPlanResumeRefusesDisagreeingState(t *testing.T) {
	cfg := testConfig(t, t.TempDir())
	provenance := testProvenance()
	stored := storedCheckpoint(cfg, provenance)
	wallNow := testOrigin.Add(80 * time.Hour)

	if _, err := planResume(
		stored, true, ReceiptReplayState{
			Count: 5, Head: stored.LastReceiptDigest,
		}, FirstFailureFileState{}, provenance, wallNow, cfg,
	); err == nil {
		t.Fatal("a checkpoint claiming 3 cycles resumed against a log of 5")
	}
	if _, err := planResume(
		Checkpoint{}, false, ReceiptReplayState{
			Count: 3, Head: stored.LastReceiptDigest,
		}, FirstFailureFileState{}, provenance, wallNow, cfg,
	); err == nil {
		t.Fatal("a receipt log with no checkpoint at all was accepted")
	}
}

func TestPlanResumeBindsEveryAuthenticatedEvidenceField(t *testing.T) {
	cfg := testConfig(t, t.TempDir())
	provenance := testProvenance()
	stored := storedCheckpoint(cfg, provenance)
	base := replayForCheckpoint(stored)
	wallNow := testOrigin.Add(80 * time.Hour)

	tests := []struct {
		name   string
		mutate func(*ReceiptReplayState)
	}{
		{"head", func(r *ReceiptReplayState) {
			r.Head = strings.Repeat("a", 64)
		}},
		{"attempted", func(r *ReceiptReplayState) { r.Totals.Attempted++ }},
		{"succeeded", func(r *ReceiptReplayState) { r.Totals.Succeeded-- }},
		{"failed", func(r *ReceiptReplayState) { r.Totals.Failed++ }},
		{"timed_out", func(r *ReceiptReplayState) { r.Totals.TimedOut++ }},
		{"cancelled", func(r *ReceiptReplayState) { r.Totals.Cancelled++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			replay := base
			test.mutate(&replay)
			if _, err := planResume(
				stored, true, replay, FirstFailureFileState{},
				provenance, wallNow, cfg,
			); err == nil {
				t.Fatalf("resume accepted mutated %s", test.name)
			}
		})
	}
}

func TestPlanResumeRejectsTerminalRunID(t *testing.T) {
	cfg := testConfig(t, t.TempDir())
	provenance := testProvenance()
	stored := storedCheckpoint(cfg, provenance)
	stored.Terminal = true
	stored.TerminalReason = ReasonDurationServed
	stored.AccumulatedElapsedNanos = stored.TotalDurationNanos
	_, err := planResume(
		stored, true, replayForCheckpoint(stored),
		FirstFailureFileState{}, provenance,
		testOrigin.Add(DefaultDuration), cfg,
	)
	if err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Fatalf("terminal checkpoint resumed: %v", err)
	}
}

// TestCheckpointAuthenticationIsRequired proves a tampered or unauthenticated
// checkpoint is refused rather than repaired.
func TestCheckpointAuthenticationIsRequired(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "state")
	store, err := OpenCheckpointStore(stateRoot)
	if err != nil {
		t.Fatalf("open checkpoint store: %v", err)
	}
	cfg := testConfig(t, t.TempDir())
	original := storedCheckpoint(cfg, testProvenance())
	address, err := store.Save(original)
	if err != nil {
		t.Fatalf("save checkpoint: %v", err)
	}
	loaded, loadedAddress, err := store.Load()
	if err != nil {
		t.Fatalf("load checkpoint: %v", err)
	}
	if loadedAddress != address {
		t.Fatalf("content address %s on load, %s on save", loadedAddress, address)
	}
	if loaded.AccumulatedElapsedNanos != original.AccumulatedElapsedNanos {
		t.Fatalf("round trip lost the accumulated elapsed time")
	}

	path := filepath.Join(stateRoot, "checkpoint.json")

	t.Run("modified body is refused", func(t *testing.T) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read checkpoint: %v", err)
		}
		var envelope checkpointEnvelope
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatalf("decode envelope: %v", err)
		}
		// Halve the accumulated elapsed time -- the exact edit that would
		// make a soak serve its duration twice.
		var body Checkpoint
		if err := json.Unmarshal(envelope.Body, &body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		body.AccumulatedElapsedNanos /= 2
		modified, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode modified body: %v", err)
		}
		envelope.Body = modified
		tampered, err := json.Marshal(envelope)
		if err != nil {
			t.Fatalf("encode tampered envelope: %v", err)
		}
		if err := os.WriteFile(path, tampered, 0o600); err != nil {
			t.Fatalf("write tampered checkpoint: %v", err)
		}
		if _, _, err := store.Load(); err == nil {
			t.Fatal("a body that no longer matches its content address loaded")
		} else if !strings.Contains(err.Error(), "content address") {
			t.Fatalf("refusal was %v, want a content-address mismatch", err)
		}
	})

	t.Run("foreign key is refused", func(t *testing.T) {
		if _, err := store.Save(original); err != nil {
			t.Fatalf("restore checkpoint: %v", err)
		}
		foreign := *store
		foreign.key = make([]byte, resumeKeyBytes)
		if _, err := rand.Read(foreign.key); err != nil {
			t.Fatalf("mint a foreign key: %v", err)
		}
		if _, _, err := foreign.Load(); err == nil {
			t.Fatal("a checkpoint authenticated under one key loaded under another")
		}
		// Control: the real key still works, so the refusal above was the
		// MAC and not some unrelated decode failure.
		if _, _, err := store.Load(); err != nil {
			t.Fatalf("the genuine key stopped working: %v", err)
		}
	})

	t.Run("inconsistent counters are refused", func(t *testing.T) {
		broken := original
		broken.CyclesAttempted = 9
		if _, err := store.Save(broken); err == nil {
			t.Fatal("a checkpoint whose counters do not add up was saved")
		}
	})
}

// TestDuplicateControllerIsRefused covers the exact lock and the nonce lineage.
func TestDuplicateControllerIsRefused(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "state")

	first, err := AcquireInstanceLock(stateRoot)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if first.Nonce() == "" {
		t.Fatal("the first instance minted no nonce")
	}
	if first.Predecessor() != "" {
		t.Errorf("the first instance has predecessor %q, want none",
			first.Predecessor())
	}

	// A second controller in the same process. flock is per-open-file-
	// description, so a second open of the same path is a genuinely
	// different holder and this is a real test of exclusion.
	if _, err := AcquireInstanceLock(stateRoot); err == nil {
		t.Fatal("a second controller acquired the lock while the first held it")
	}

	if err := first.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}

	second, err := AcquireInstanceLock(stateRoot)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	defer func() { _ = second.Release() }()

	if second.Nonce() == first.Nonce() {
		t.Fatal("the second instance reused the first instance's nonce; two " +
			"runs would then be indistinguishable in the evidence")
	}
	if second.Predecessor() != first.Nonce() {
		t.Fatalf("the second instance names %q as its predecessor, want %q",
			second.Predecessor(), first.Nonce())
	}
}

// TestTerminalStateFirstWins is the signal-race test.
//
// It is deterministic by construction: every goroutine calls Claim with its own
// distinct reason, and the assertion is that EXACTLY ONE call returns true and
// that the stored reason is that winner's. Which goroutine wins is a genuine
// race and is deliberately not asserted -- asserting it would be asserting a
// scheduling order, which is how a concurrency test becomes luck-dependent.
func TestTerminalStateFirstWins(t *testing.T) {
	const claimants = 64
	for attempt := 0; attempt < 200; attempt++ {
		state := &TerminalState{}
		start := make(chan struct{})
		var wg sync.WaitGroup
		winners := make([]bool, claimants)
		reasons := make([]TerminalReason, claimants)
		for index := 0; index < claimants; index++ {
			wg.Add(1)
			reasons[index] = TerminalReason(
				"reason-" + itoa(int64(index)),
			)
			go func(i int) {
				defer wg.Done()
				<-start
				winners[i] = state.Claim(reasons[i], "detail-"+itoa(int64(i)))
			}(index)
		}
		close(start)
		wg.Wait()

		won := -1
		for index, isWinner := range winners {
			if !isWinner {
				continue
			}
			if won != -1 {
				t.Fatalf("two claimants both won: %d and %d", won, index)
			}
			won = index
		}
		if won == -1 {
			t.Fatal("no claimant won, so no terminal reason was recorded")
		}
		reason, detail := state.Reason()
		if reason != reasons[won] {
			t.Fatalf("stored reason %q, want the winner's %q",
				reason, reasons[won])
		}
		if detail != "detail-"+itoa(int64(won)) {
			t.Fatalf("stored detail %q does not match the winner's", detail)
		}
	}
}

// TestSignalDoesNotOverwriteAnEarlierFailure is the ordering the race test
// cannot express: a SIGTERM arriving after a cycle already failed must not
// relabel the run as an orderly shutdown.
func TestSignalDoesNotOverwriteAnEarlierFailure(t *testing.T) {
	state := &TerminalState{}
	if !state.Claim(ReasonCycleFailed, "cycle 3 exited 42") {
		t.Fatal("the first claim did not win")
	}
	if state.Claim(ReasonSignal, "received terminated") {
		t.Fatal("a later signal claim won over an earlier failure")
	}
	if state.Claim(ReasonSignal, "received terminated again") {
		t.Fatal("a second signal claim won")
	}
	reason, detail := state.Reason()
	if reason != ReasonCycleFailed {
		t.Fatalf("terminal reason is %q, want %q", reason, ReasonCycleFailed)
	}
	if detail != "cycle 3 exited 42" {
		t.Fatalf("terminal detail is %q, want the failure's", detail)
	}
}
