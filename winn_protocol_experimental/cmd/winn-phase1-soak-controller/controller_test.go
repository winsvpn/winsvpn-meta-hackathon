package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// readReceiptLines returns the raw bytes of each receipt line.
func readReceiptLines(t *testing.T, evidenceRoot string) [][]byte {
	t.Helper()
	path := filepath.Join(evidenceRoot, "cycle-receipts.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read receipt log: %v", err)
	}
	var lines [][]byte
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if line == "" {
			continue
		}
		lines = append(lines, []byte(line))
	}
	return lines
}

// readReceipts decodes the whole receipt log from disk.
//
// From disk, not from the in-memory ReceiptLog: the log is the artifact an
// auditor reads, and a test that asserted on the writer's own counters would
// verify the counters agree with themselves.
func readReceipts(t *testing.T, evidenceRoot string) []Receipt {
	t.Helper()
	path := filepath.Join(evidenceRoot, "cycle-receipts.jsonl")
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("open receipt log: %v", err)
	}
	defer func() { _ = file.Close() }()
	var receipts []Receipt
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64<<10), maximumReceiptScannerBytes)
	for scanner.Scan() {
		var receipt Receipt
		if err := json.Unmarshal(scanner.Bytes(), &receipt); err != nil {
			t.Fatalf("decode receipt: %v", err)
		}
		receipts = append(receipts, receipt)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read receipt log: %v", err)
	}
	return receipts
}

// TestSoakServesFullDurationAndStops is the success case.
//
// Seven cycles of twenty-four hours each land on exactly the requested one
// hundred and sixty-eight, and the loop stops there rather than starting an
// eighth.
func TestSoakServesFullDurationAndStops(t *testing.T) {
	root := t.TempDir()
	clock := newFakeClock(testOrigin)
	runner := newFakeRunner(clock)
	runner.fallback = fakeBehavior{Outcome: OutcomeSucceeded, Advance: 24 * time.Hour}

	h := newHarness(t, root, runner, clock, func(cfg *Config) {
		cfg.Cadence = 0
		cfg.ColdSettle = 0
	})
	defer h.close()

	summary, err := h.controller().Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned an error: %v", err)
	}

	if runner.Calls() != 7 {
		t.Errorf("ran %d cycles, want exactly 7", runner.Calls())
	}
	if runner.SawConcurrency() {
		t.Error("two cycles overlapped; the runner must be entered one at a time")
	}
	if summary.TerminalReason != ReasonDurationServed {
		t.Errorf("terminal reason %q, want %q",
			summary.TerminalReason, ReasonDurationServed)
	}
	if !summary.DurationServed {
		t.Error("summary says the duration was not served")
	}
	if summary.ServedDurationNanos != DefaultDuration {
		t.Errorf("served %s, want exactly %s",
			summary.ServedDurationNanos, DefaultDuration)
	}
	if summary.OvershootNanos != 0 {
		t.Errorf("overshoot %s, want 0", summary.OvershootNanos)
	}
	if summary.CyclesAttempted != 7 || summary.CyclesSucceeded != 7 {
		t.Errorf("attempted %d succeeded %d, want 7 and 7",
			summary.CyclesAttempted, summary.CyclesSucceeded)
	}
	if !summary.ConservationOK {
		t.Error("conservation check failed on a clean run")
	}
	if summary.Promotable {
		t.Fatal("the summary claims to be promotable")
	}
	terminalCheckpoint, _, err := h.checkpoint.Load()
	if err != nil {
		t.Fatalf("load terminal checkpoint: %v", err)
	}
	if !terminalCheckpoint.Terminal ||
		terminalCheckpoint.TerminalReason != ReasonDurationServed {
		t.Fatalf("duration completion was not terminally latched: %+v",
			terminalCheckpoint)
	}
	if _, err := planResume(
		terminalCheckpoint, true, h.receipts.ReplayState(),
		FirstFailureFileState{}, h.currentProvenance,
		clock.WallNow(), h.config,
	); err == nil {
		t.Fatal("same run ID resumed after terminal duration checkpoint")
	}
	if !strings.Contains(summary.NonPromotionNotice, "NOT PROMOTABLE") ||
		!strings.Contains(summary.NonPromotionNotice, "not the production") &&
			!strings.Contains(summary.NonPromotionNotice, "NOT THE PRODUCTION") {
		t.Errorf("non-promotion notice does not say so: %q",
			summary.NonPromotionNotice)
	}

	receipts := readReceipts(t, h.config.EvidenceRoot)
	if len(receipts) != 7 {
		t.Fatalf("wrote %d receipts, want 7", len(receipts))
	}
	// The chain is recomputed from the RAW LINES, not from the decoded
	// structs. A struct round-trip would re-encode with this program's
	// current field order, so a chain verified that way would verify the
	// encoder against itself rather than the bytes an auditor will hash.
	lines := readReceiptLines(t, h.config.EvidenceRoot)
	previous := genesisDigest
	for index, receipt := range receipts {
		want := int64(index + 1)
		if receipt.Sequence != want {
			t.Errorf("receipt %d has sequence %d", index, receipt.Sequence)
		}
		if receipt.PreviousDigest != previous {
			t.Errorf("receipt %d chains to %s, but receipt %d hashes to %s",
				want, receipt.PreviousDigest, want-1, previous)
		}
		if receipt.Attempted != want {
			t.Errorf("receipt %d records %d attempts", want, receipt.Attempted)
		}
		sum := sha256.Sum256(lines[index])
		previous = hex.EncodeToString(sum[:])
	}

	// Independent replay: a second reader over the same file must agree.
	// This is the check that would catch a writer whose in-memory chain and
	// on-disk bytes had diverged.
	replayDirectory, err := openSecureDirectory(h.config.EvidenceRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replayDirectory.Close() }()
	replay := &ReceiptLog{
		path: filepath.Join(h.config.EvidenceRoot, "cycle-receipts.jsonl"),
		base: "cycle-receipts.jsonl", directory: replayDirectory,
		lastHash: genesisDigest,
	}
	if err := replay.replay(h.config.RunID); err != nil {
		t.Fatalf("independent replay rejected the log: %v", err)
	}
	if replay.Count() != 7 {
		t.Errorf("replay counted %d receipts, want 7", replay.Count())
	}

	// Warm/cold schedule: -cold-every=4 makes cycles 4 the cold ones.
	requests := runner.Requests()
	for _, request := range requests {
		want := ReadinessWarm
		if request.Sequence%4 == 0 {
			want = ReadinessCold
		}
		if request.Readiness != want {
			t.Errorf("cycle %d readiness %q, want %q",
				request.Sequence, request.Readiness, want)
		}
	}
	// A schedule that produced only warm cycles would satisfy every
	// assertion above if -cold-every were ignored, so the mix is asserted.
	cold := 0
	for _, request := range requests {
		if request.Readiness == ReadinessCold {
			cold++
		}
	}
	if cold != 1 {
		t.Errorf("saw %d cold cycles among 7 at -cold-every=4, want 1", cold)
	}
}

// TestDurationBoundaryExactly168Hours pins the stop predicate at the boundary.
//
// This test and the two beside it exist as a set. Any single one of them can be
// satisfied by the wrong comparison; together they admit exactly one.
func TestDurationBoundaryExactly168Hours(t *testing.T) {
	root := t.TempDir()
	clock := newFakeClock(testOrigin)
	runner := newFakeRunner(clock)
	runner.fallback = fakeBehavior{Outcome: OutcomeSucceeded, Advance: 24 * time.Hour}

	h := newHarness(t, root, runner, clock, func(cfg *Config) {
		cfg.Cadence = 0
		cfg.ColdSettle = 0
	})
	defer h.close()

	summary, err := h.controller().Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := clock.MonotonicElapsed(); got != DefaultDuration {
		t.Fatalf("clock reached %s, want exactly %s", got, DefaultDuration)
	}
	if runner.Calls() != 7 {
		t.Fatalf("ran %d cycles at exactly the boundary, want 7; an eighth "+
			"means the stop predicate accepts elapsed == total",
			runner.Calls())
	}
	if summary.OvershootNanos != 0 {
		t.Errorf("overshoot %v at the exact boundary, want 0",
			summary.OvershootNanos)
	}
	if !summary.DurationServed {
		t.Error("exactly the requested duration must count as served")
	}
}

// TestDurationBoundaryOneNanosecondShort proves the loop does NOT stop early.
//
// Without this, a predicate that stopped at total-1ns would pass the exact and
// the over-boundary tests and quietly cut every soak short.
func TestDurationBoundaryOneNanosecondShort(t *testing.T) {
	root := t.TempDir()
	clock := newFakeClock(testOrigin)
	// Six cycles of 24h, then one that lands one nanosecond short.
	script := make([]fakeBehavior, 0, 8)
	for i := 0; i < 6; i++ {
		script = append(script, fakeBehavior{
			Outcome: OutcomeSucceeded, Advance: 24 * time.Hour,
		})
	}
	script = append(script, fakeBehavior{
		Outcome: OutcomeSucceeded, Advance: 24*time.Hour - 1,
	})
	runner := newFakeRunner(clock, script...)
	runner.fallback = fakeBehavior{Outcome: OutcomeSucceeded, Advance: time.Nanosecond}

	h := newHarness(t, root, runner, clock, func(cfg *Config) {
		cfg.Cadence = 0
		cfg.ColdSettle = 0
	})
	defer h.close()

	summary, err := h.controller().Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if runner.Calls() != 8 {
		t.Fatalf("ran %d cycles, want 8: at total-1ns the loop must run "+
			"another cycle", runner.Calls())
	}
	if summary.ServedDurationNanos != DefaultDuration {
		t.Errorf("served %v, want %v", summary.ServedDurationNanos, DefaultDuration)
	}
}

// TestDurationBoundaryOneNanosecondOver proves the overshoot is recorded rather
// than rounded away, and that no further cycle starts.
func TestDurationBoundaryOneNanosecondOver(t *testing.T) {
	root := t.TempDir()
	clock := newFakeClock(testOrigin)
	script := make([]fakeBehavior, 0, 7)
	for i := 0; i < 6; i++ {
		script = append(script, fakeBehavior{
			Outcome: OutcomeSucceeded, Advance: 24 * time.Hour,
		})
	}
	script = append(script, fakeBehavior{
		Outcome: OutcomeSucceeded, Advance: 24*time.Hour + 1,
	})
	runner := newFakeRunner(clock, script...)
	runner.fallback = fakeBehavior{Outcome: OutcomeSucceeded, Advance: time.Hour}

	h := newHarness(t, root, runner, clock, func(cfg *Config) {
		cfg.Cadence = 0
		cfg.ColdSettle = 0
	})
	defer h.close()

	summary, err := h.controller().Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if runner.Calls() != 7 {
		t.Fatalf("ran %d cycles past the boundary, want 7", runner.Calls())
	}
	if summary.ServedDurationNanos != DefaultDuration+1 {
		t.Errorf("served %v, want %v", summary.ServedDurationNanos, DefaultDuration+1)
	}
	if summary.OvershootNanos != 1 {
		t.Errorf("overshoot %v, want exactly 1ns", summary.OvershootNanos)
	}
	if !summary.DurationServed {
		t.Error("a run past the boundary must count as served")
	}
}

// TestCycleFailureStopsAndPreservesFirstFailure covers the failure case and the
// first-failure guarantee together, because the guarantee is only meaningful
// once a second failure has had a chance to overwrite the first.
func TestCycleFailureStopsAndPreservesFirstFailure(t *testing.T) {
	root := t.TempDir()
	clock := newFakeClock(testOrigin)
	runner := newFakeRunner(clock,
		fakeBehavior{Outcome: OutcomeSucceeded, Advance: time.Hour},
		fakeBehavior{
			Outcome: OutcomeFailed, ExitStatus: 42, Advance: time.Hour,
			StderrTail: []byte("first failure: batch aborted"),
		},
	)
	h := newHarness(t, root, runner, clock, func(cfg *Config) {
		cfg.Cadence = 0
		cfg.ColdSettle = 0
	})
	defer h.close()

	summary, err := h.controller().Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if runner.Calls() != 2 {
		t.Fatalf("ran %d cycles, want 2: the loop must stop on a failure",
			runner.Calls())
	}
	if summary.TerminalReason != ReasonCycleFailed {
		t.Errorf("terminal reason %q, want %q",
			summary.TerminalReason, ReasonCycleFailed)
	}
	if summary.CyclesFailed != 1 || summary.CyclesSucceeded != 1 ||
		summary.CyclesAttempted != 2 {
		t.Errorf("totals attempted=%d succeeded=%d failed=%d, want 2/1/1",
			summary.CyclesAttempted, summary.CyclesSucceeded,
			summary.CyclesFailed)
	}
	if !summary.ConservationOK {
		t.Error("conservation failed")
	}
	if summary.FirstFailureSequence != 2 {
		t.Errorf("summary first failure=%d, want 2",
			summary.FirstFailureSequence)
	}

	failure := readFirstFailure(t, h.config.EvidenceRoot)
	if failure.Sequence != 2 {
		t.Errorf("first failure records sequence %d, want 2", failure.Sequence)
	}
	if failure.ExitStatus != 42 {
		t.Errorf("first failure records exit %d, want 42", failure.ExitStatus)
	}
	if !strings.Contains(string(failure.StderrTail), "first failure") {
		t.Errorf("first failure lost the runner's own output: %q",
			failure.StderrTail)
	}
}

// TestFirstFailureSurvivesLaterFailures is the mutation-sensitive half.
//
// Two failures are recorded in sequence with different exit statuses. If
// RecordFirstFailure used create-or-truncate instead of O_EXCL, this test sees
// the SECOND status and fails. The preceding test would not: it never produces
// a second failure.
func TestFirstFailureSurvivesLaterFailures(t *testing.T) {
	evidence := t.TempDir()
	first := FirstFailure{
		RunID: "r", Sequence: 3, Outcome: OutcomeFailed, ExitStatus: 7,
		StderrTail: []byte("the diagnostic one"),
	}
	second := FirstFailure{
		RunID: "r", Sequence: 400, Outcome: OutcomeFailed, ExitStatus: 99,
		StderrTail: []byte("four hundred cycles of wreckage later"),
	}
	if err := RecordFirstFailure(evidence, first); err != nil {
		t.Fatalf("record first failure: %v", err)
	}
	err := RecordFirstFailure(evidence, second)
	if !errors.Is(err, errFirstFailureAlreadyRecorded) {
		t.Fatalf("second RecordFirstFailure returned %v, want "+
			"errFirstFailureAlreadyRecorded", err)
	}
	stored := readFirstFailure(t, evidence)
	if stored.Sequence != 3 || stored.ExitStatus != 7 {
		t.Fatalf("stored failure is sequence %d exit %d; the first failure "+
			"was overwritten", stored.Sequence, stored.ExitStatus)
	}
	if !strings.Contains(string(stored.StderrTail), "diagnostic") {
		t.Errorf("stored tail is %q, want the first failure's",
			stored.StderrTail)
	}
}

func readFirstFailure(t *testing.T, evidenceRoot string) FirstFailure {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(evidenceRoot, "first-failure.json"))
	if err != nil {
		t.Fatalf("read first failure record: %v", err)
	}
	var failure FirstFailure
	if err := json.Unmarshal(raw, &failure); err != nil {
		t.Fatalf("decode first failure record: %v", err)
	}
	return failure
}

// TestHangIsBoundedByTheCycleTimeout drives a runner that blocks until its
// context is cancelled.
//
// The determinism argument: the fake returns the instant the deadline fires and
// not before, so there is no schedule on which it could return early and make
// the test pass without the deadline having been applied. The 80ms is a real
// duration, but nothing races it.
func TestHangIsBoundedByTheCycleTimeout(t *testing.T) {
	root := t.TempDir()
	clock := newFakeClock(testOrigin)
	runner := newFakeRunner(clock, fakeBehavior{
		BlockUntilContextDone: true,
		Advance:               time.Hour,
	})
	h := newHarness(t, root, runner, clock, func(cfg *Config) {
		cfg.Cadence = 0
		cfg.ColdSettle = 0
		cfg.CycleTimeout = 80 * time.Millisecond
	})
	defer h.close()

	started := time.Now()
	summary, err := h.controller().Run(context.Background())
	waited := time.Since(started)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if waited < 80*time.Millisecond {
		t.Fatalf("the hung cycle returned after %s, sooner than the %s "+
			"deadline; the deadline was not what released it",
			waited, 80*time.Millisecond)
	}
	if runner.Calls() != 1 {
		t.Fatalf("ran %d cycles, want 1", runner.Calls())
	}
	if summary.TerminalReason != ReasonCycleTimedOut {
		t.Errorf("terminal reason %q, want %q",
			summary.TerminalReason, ReasonCycleTimedOut)
	}
	if summary.CyclesTimedOut != 1 {
		t.Errorf("timed-out count %d, want 1", summary.CyclesTimedOut)
	}
	if !summary.ConservationOK {
		t.Error("conservation failed after a timeout")
	}
	failure := readFirstFailure(t, h.config.EvidenceRoot)
	if failure.Outcome != OutcomeTimedOut {
		t.Errorf("first failure records outcome %q, want %q",
			failure.Outcome, OutcomeTimedOut)
	}
}

// TestCrashAndResumeDoesNotRestartTheClock is the core resumption guarantee.
func TestCrashAndResumeDoesNotRestartTheClock(t *testing.T) {
	root := t.TempDir()

	// First process: three cycles of 24h, then a "crash" -- the process
	// simply stops, exactly as a SIGKILL would leave it, with the receipt
	// log and checkpoint on disk and nothing else.
	firstClock := newFakeClock(testOrigin)
	firstRunner := newFakeRunner(firstClock,
		fakeBehavior{Outcome: OutcomeSucceeded, Advance: 24 * time.Hour},
		fakeBehavior{Outcome: OutcomeSucceeded, Advance: 24 * time.Hour},
		fakeBehavior{Outcome: OutcomeSucceeded, Advance: 24 * time.Hour},
		fakeBehavior{Err: errors.New("simulated crash: the host went away")},
	)
	firstHarness := newHarness(t, root, firstRunner, firstClock, func(cfg *Config) {
		cfg.Cadence = 0
		cfg.ColdSettle = 0
	})
	firstSummary, err := firstHarness.controller().Run(context.Background())
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	firstHarness.close()

	if firstSummary.CyclesAttempted != 3 {
		t.Fatalf("first run attempted %d cycles, want 3",
			firstSummary.CyclesAttempted)
	}
	if firstSummary.ServedDurationNanos != 72*time.Hour {
		t.Fatalf("first run served %s, want 72h",
			firstSummary.ServedDurationNanos)
	}

	// Second process: a brand new monotonic clock reading zero, exactly as a
	// restarted process has. The wall clock has moved forward by a day of
	// downtime, which must NOT be credited as soak time.
	secondClock := newFakeClock(testOrigin.Add(96 * time.Hour))
	secondRunner := newFakeRunner(secondClock)
	secondRunner.fallback = fakeBehavior{
		Outcome: OutcomeSucceeded, Advance: 24 * time.Hour,
	}
	secondHarness := newHarness(t, root, secondRunner, secondClock, func(cfg *Config) {
		cfg.Cadence = 0
		cfg.ColdSettle = 0
	})
	defer secondHarness.close()

	secondSummary, err := secondHarness.controller().Run(context.Background())
	if err != nil {
		t.Fatalf("resumed run: %v", err)
	}

	// Four more cycles, not seven. Seven would mean the resumed run
	// restarted the 168h clock from zero.
	if secondRunner.Calls() != 4 {
		t.Fatalf("resumed run ran %d cycles, want 4; %d means the duration "+
			"clock was reset on resume", secondRunner.Calls(), 7)
	}
	if secondSummary.ResumeCount != 1 {
		t.Errorf("resume count %d, want 1", secondSummary.ResumeCount)
	}
	if secondSummary.ServedDurationNanos != DefaultDuration {
		t.Errorf("resumed run served %s, want %s",
			secondSummary.ServedDurationNanos, DefaultDuration)
	}
	if secondSummary.CyclesAttempted != 7 {
		t.Errorf("total attempted across both processes is %d, want 7",
			secondSummary.CyclesAttempted)
	}
	if secondSummary.TerminalReason != ReasonDurationServed {
		t.Errorf("terminal reason %q, want %q",
			secondSummary.TerminalReason, ReasonDurationServed)
	}

	// The receipt log spans both processes with one unbroken sequence, and
	// the two instance nonces differ: the evidence shows a resume happened.
	receipts := readReceipts(t, secondHarness.config.EvidenceRoot)
	if len(receipts) != 7 {
		t.Fatalf("%d receipts across both processes, want 7", len(receipts))
	}
	if receipts[2].InstanceNonce == receipts[3].InstanceNonce {
		t.Error("the resumed process reused the previous instance nonce; a " +
			"resume would then be indistinguishable from an uninterrupted run")
	}
	if receipts[3].PredecessorNonce != receipts[2].InstanceNonce {
		t.Errorf("the resumed process's predecessor nonce %q does not name "+
			"the previous instance %q",
			receipts[3].PredecessorNonce, receipts[2].InstanceNonce)
	}
	// Accumulated elapsed must be monotonically non-decreasing across the
	// resume boundary. A reset would show as a drop.
	for index := 1; index < len(receipts); index++ {
		if receipts[index].AccumulatedElapsedNanos <
			receipts[index-1].AccumulatedElapsedNanos {
			t.Fatalf("accumulated elapsed dropped from %d to %d at receipt %d",
				receipts[index-1].AccumulatedElapsedNanos,
				receipts[index].AccumulatedElapsedNanos, index+1)
		}
	}
}

// TestFreeSpaceFloorStopsBeforeTheCycle proves the gate runs before a cycle
// rather than after it.
func TestFreeSpaceFloorStopsBeforeTheCycle(t *testing.T) {
	root := t.TempDir()
	clock := newFakeClock(testOrigin)
	runner := newFakeRunner(clock)
	h := newHarness(t, root, runner, clock, func(cfg *Config) {
		cfg.Cadence = 0
		cfg.ColdSettle = 0
	})
	defer h.close()
	h.freeBytes = h.config.MinFreeBytes - 1

	summary, err := h.controller().Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if runner.Calls() != 0 {
		t.Fatalf("ran %d cycles below the free-space floor, want 0",
			runner.Calls())
	}
	if summary.TerminalReason != ReasonFreeSpaceFloor {
		t.Errorf("terminal reason %q, want %q",
			summary.TerminalReason, ReasonFreeSpaceFloor)
	}

	// And exactly at the floor it proceeds: a gate that refused at equality
	// would stop every soak one byte early and this test would not notice.
	h2 := newHarness(t, t.TempDir(), newFakeRunner(clock), clock,
		func(cfg *Config) {
			cfg.Cadence = 0
			cfg.ColdSettle = 0
			cfg.Duration = time.Hour
		})
	defer h2.close()
	h2.freeBytes = h2.config.MinFreeBytes
	h2.runner.fallback = fakeBehavior{Outcome: OutcomeSucceeded, Advance: time.Hour}
	summary2, err := h2.controller().Run(context.Background())
	if err != nil {
		t.Fatalf("Run at exactly the floor: %v", err)
	}
	if summary2.TerminalReason != ReasonDurationServed {
		t.Errorf("at exactly the floor the soak stopped with %q",
			summary2.TerminalReason)
	}
}

// TestResourceBoundStopsTheSoak proves an exceeded ceiling is terminal and is
// recorded on the receipt.
func TestResourceBoundStopsTheSoak(t *testing.T) {
	root := t.TempDir()
	clock := newFakeClock(testOrigin)
	runner := newFakeRunner(clock, fakeBehavior{
		Outcome: OutcomeSucceeded,
		Advance: time.Hour,
		Resources: ResourceSample{
			Available:   true,
			MaxRSSBytes: 5 << 30,
		},
	})
	h := newHarness(t, root, runner, clock, func(cfg *Config) {
		cfg.Cadence = 0
		cfg.ColdSettle = 0
		cfg.Bounds.MaxRSSBytes = 4 << 30
	})
	defer h.close()

	summary, err := h.controller().Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if runner.Calls() != 1 {
		t.Fatalf("ran %d cycles, want 1", runner.Calls())
	}
	if summary.TerminalReason != ReasonResourceBound {
		t.Errorf("terminal reason %q, want %q",
			summary.TerminalReason, ReasonResourceBound)
	}
	receipts := readReceipts(t, h.config.EvidenceRoot)
	if len(receipts) != 1 {
		t.Fatalf("%d receipts, want 1", len(receipts))
	}
	if len(receipts[0].ExceededBounds) != 1 ||
		receipts[0].ExceededBounds[0].Bound != "max_rss_bytes" {
		t.Fatalf("receipt records exceeded bounds %+v, want one max_rss_bytes",
			receipts[0].ExceededBounds)
	}
	if receipts[0].ExceededBounds[0].Observed != 5<<30 {
		t.Errorf("recorded observation %d, want %d",
			receipts[0].ExceededBounds[0].Observed, int64(5)<<30)
	}
	// A cycle that succeeded but broke a bound is still a failure worth
	// preserving: the first-failure record must exist.
	failure := readFirstFailure(t, h.config.EvidenceRoot)
	if len(failure.ExceededBounds) != 1 {
		t.Errorf("first failure omitted the exceeded bound: %+v", failure)
	}
}

// TestUnmeasuredResourcesNeverTripABound guards the inverse mistake.
//
// A sample that could not be taken must not be reported as a violation, or
// every cycle on a host without /proc would stop the soak for a measurement
// nobody made.
func TestUnmeasuredResourcesNeverTripABound(t *testing.T) {
	bounds := ResourceBounds{
		MaxRSSBytes:    1,
		MaxThreads:     1,
		MaxOpenFiles:   1,
		MaxOutputBytes: 1 << 30,
	}
	unmeasured := ResourceSample{
		Available:     false,
		ProcSampled:   false,
		MaxRSSBytes:   1 << 40,
		PeakThreads:   1 << 20,
		PeakOpenFiles: 1 << 20,
	}
	if broken := bounds.check(unmeasured, 0, 0); len(broken) != 0 {
		t.Fatalf("unmeasured sample reported violations %+v", broken)
	}
	measured := unmeasured
	measured.Available = true
	measured.ProcSampled = true
	broken := bounds.check(measured, 0, 0)
	if len(broken) != 3 {
		t.Fatalf("measured sample reported %d violations, want 3: %+v",
			len(broken), broken)
	}
}

// TestSourceDriftMidLoopStopsTheSoak drifts the snapshot between cycles.
func TestSourceDriftMidLoopStopsTheSoak(t *testing.T) {
	root := t.TempDir()
	clock := newFakeClock(testOrigin)
	var h *harness
	runner := newFakeRunner(clock,
		fakeBehavior{Outcome: OutcomeSucceeded, Advance: time.Hour},
		fakeBehavior{
			Outcome: OutcomeSucceeded, Advance: time.Hour,
			Before: func(int64) {
				// Replace the runner binary underneath the soak. This is
				// the specific drift that means a different program
				// produced the later cycles.
				h.currentProvenance.RunnerDigest = "ff" + repeatHex(62)
			},
		},
	)
	h = newHarness(t, root, runner, clock, func(cfg *Config) {
		cfg.Cadence = 0
		cfg.ColdSettle = 0
	})
	defer h.close()

	summary, err := h.controller().Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Cycle 2 ran with the drift already applied; the loop re-verifies at
	// the TOP of a cycle, so the drift is caught before cycle 3 starts.
	if runner.Calls() != 2 {
		t.Fatalf("ran %d cycles, want 2", runner.Calls())
	}
	if summary.TerminalReason != ReasonSourceDrift {
		t.Fatalf("terminal reason %q, want %q",
			summary.TerminalReason, ReasonSourceDrift)
	}
	if !strings.Contains(summary.TerminalDetail, string(driftRunner)) {
		t.Errorf("terminal detail %q does not name the runner drift",
			summary.TerminalDetail)
	}
}

// TestBoundedOutputIsRecordedNotRetained proves the retained tail is capped
// while the true byte count survives.
func TestBoundedOutputIsRecordedNotRetained(t *testing.T) {
	root := t.TempDir()
	clock := newFakeClock(testOrigin)
	const produced = 64 << 20
	runner := newFakeRunner(clock, fakeBehavior{
		Outcome:     OutcomeSucceeded,
		Advance:     time.Hour,
		StdoutTail:  []byte(strings.Repeat("A", 4096)),
		StdoutBytes: produced,
		StderrTail:  []byte(strings.Repeat("B", 4096)),
		StderrBytes: produced,
	})
	h := newHarness(t, root, runner, clock, func(cfg *Config) {
		cfg.Cadence = 0
		cfg.ColdSettle = 0
		cfg.Duration = time.Hour
		cfg.MaxCycleOutputBytes = 4096
		cfg.Bounds.MaxOutputBytes = 1 << 40
	})
	defer h.close()

	if _, err := h.controller().Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	receipts := readReceipts(t, h.config.EvidenceRoot)
	if len(receipts) != 1 {
		t.Fatalf("%d receipts, want 1", len(receipts))
	}
	receipt := receipts[0]
	if receipt.StdoutBytes != produced || receipt.StderrBytes != produced {
		t.Errorf("recorded %d/%d bytes, want %d/%d: the TRUE volume must "+
			"survive truncation", receipt.StdoutBytes, receipt.StderrBytes,
			produced, produced)
	}
	if len(receipt.StdoutTail) != 4096 || len(receipt.StderrTail) != 4096 {
		t.Errorf("retained %d/%d bytes, want 4096/4096",
			len(receipt.StdoutTail), len(receipt.StderrTail))
	}
	if !receipt.Truncated {
		t.Error("receipt does not record that the output was truncated")
	}

	// The receipt log itself stayed small. A log that grew with the child's
	// output would be the unbounded stdout this bound exists to prevent.
	info, err := os.Stat(filepath.Join(
		h.config.EvidenceRoot, "cycle-receipts.jsonl",
	))
	if err != nil {
		t.Fatalf("stat receipt log: %v", err)
	}
	if info.Size() > 64<<10 {
		t.Errorf("one receipt occupies %d bytes for a cycle that produced "+
			"%d bytes of output", info.Size(), produced)
	}
}

// TestNoSecretReachesTheChildOrTheEvidence is the leakage test.
//
// It asserts two things that must both hold, because either alone can pass for
// the wrong reason: the secret's VALUE appears nowhere, and the child
// environment is exactly what was configured. Without the second, a controller
// that wrote no evidence at all would pass.
func TestNoSecretReachesTheChildOrTheEvidence(t *testing.T) {
	const secret = "hunter2-this-value-must-never-be-written"
	root := t.TempDir()
	clock := newFakeClock(testOrigin)
	runner := newFakeRunner(clock)
	runner.fallback = fakeBehavior{Outcome: OutcomeSucceeded, Advance: time.Hour}

	h := newHarness(t, root, runner, clock, func(cfg *Config) {
		cfg.Cadence = 0
		cfg.ColdSettle = 0
		cfg.Duration = 3 * time.Hour
		cfg.ChildEnvironment = []string{
			"MATRIX_ID=phase1-auto-v1",
			"PATH=/usr/bin:/bin",
			"POSTGRES_PASSWORD=" + secret,
		}
	})
	defer h.close()

	// The CONTROLLER's own environment carries a different secret. Nothing
	// from it may reach the child.
	t.Setenv("WINN_SOAK_TEST_CONTROLLER_SECRET", "controller-only-"+secret)

	summary, err := h.controller().Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if summary.CyclesAttempted != 3 {
		t.Fatalf("attempted %d cycles, want 3; a run that did nothing would "+
			"leak nothing and prove nothing", summary.CyclesAttempted)
	}

	// The child environment is exactly the configured entries plus the four
	// reserved ones. Not os.Environ() plus anything.
	for _, request := range runner.Requests() {
		if len(request.Environment) != 3+len(reservedChildVariables) {
			t.Fatalf("child environment has %d entries, want %d: the "+
				"controller's own environment must not be inherited",
				len(request.Environment), 3+len(reservedChildVariables))
		}
		for _, entry := range request.Environment {
			if strings.Contains(entry, "CONTROLLER_SECRET") {
				t.Fatalf("the controller's own environment reached the child: %q",
					entry)
			}
		}
	}

	// Positive control: the KEY is recorded, so the absence of the VALUE
	// below is not the absence of any record at all.
	found := false
	for _, name := range summary.EnvironmentNames {
		if name == "POSTGRES_PASSWORD" {
			found = true
		}
		if strings.Contains(name, secret) {
			t.Fatalf("a value leaked into the recorded environment names: %q", name)
		}
	}
	if !found {
		t.Fatal("the environment name was not recorded at all, so the " +
			"value-absence check below would pass vacuously")
	}

	// The value appears in no file this controller wrote.
	for _, directory := range []string{h.config.StateRoot, h.config.EvidenceRoot} {
		walkErr := filepath.WalkDir(directory, func(
			path string, entry fs.DirEntry, err error,
		) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			contents, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if strings.Contains(string(contents), secret) {
				t.Errorf("the secret value appears in %s", path)
			}
			if strings.Contains(string(contents), "CONTROLLER_SECRET") {
				t.Errorf("a controller environment name appears in %s", path)
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walk %s: %v", directory, walkErr)
		}
	}

	// And in the summary as encoded for the operator.
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("encode summary: %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Error("the secret value appears in the summary")
	}
}

// TestRunnerFaultIsNotCountedAsAFailedCycle keeps the conservation totals
// honest about what they count.
func TestRunnerFaultIsNotCountedAsAFailedCycle(t *testing.T) {
	root := t.TempDir()
	clock := newFakeClock(testOrigin)
	runner := newFakeRunner(clock,
		fakeBehavior{Outcome: OutcomeSucceeded, Advance: time.Hour},
		fakeBehavior{Err: errors.New("fork/exec: no such file or directory")},
	)
	h := newHarness(t, root, runner, clock, func(cfg *Config) {
		cfg.Cadence = 0
		cfg.ColdSettle = 0
	})
	defer h.close()

	summary, err := h.controller().Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if summary.TerminalReason != ReasonRunnerFault {
		t.Errorf("terminal reason %q, want %q",
			summary.TerminalReason, ReasonRunnerFault)
	}
	if summary.CyclesAttempted != 1 {
		t.Errorf("attempted %d, want 1: a runner that never ran is not an "+
			"attempt", summary.CyclesAttempted)
	}
	if summary.CyclesFailed != 0 {
		t.Errorf("failed %d, want 0", summary.CyclesFailed)
	}
	if !summary.ConservationOK {
		t.Error("conservation failed")
	}
}

// TestCadenceIsHonoured asserts the configured interval was actually requested.
func TestCadenceIsHonoured(t *testing.T) {
	root := t.TempDir()
	clock := newFakeClock(testOrigin)
	runner := newFakeRunner(clock)
	runner.fallback = fakeBehavior{Outcome: OutcomeSucceeded, Advance: 0}

	h := newHarness(t, root, runner, clock, func(cfg *Config) {
		cfg.Duration = 4 * time.Hour
		cfg.Cadence = time.Hour
		cfg.ColdSettle = 30 * time.Minute
		cfg.ColdEvery = 2
	})
	defer h.close()

	if _, err := h.controller().Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	sleeps := clock.Sleeps()
	if len(sleeps) == 0 {
		t.Fatal("the controller never waited; -cadence had no effect")
	}
	cadences, settles := 0, 0
	for _, slept := range sleeps {
		switch slept {
		case time.Hour:
			cadences++
		case 30 * time.Minute:
			settles++
		default:
			t.Errorf("unexpected wait of %s", slept)
		}
	}
	if cadences == 0 {
		t.Error("no cadence wait was requested")
	}
	if settles == 0 {
		t.Error("no cold-settle wait was requested despite -cold-every=2")
	}
}

// TestContextCancellationStopsTheLoop covers orderly shutdown.
func TestContextCancellationStopsTheLoop(t *testing.T) {
	root := t.TempDir()
	clock := newFakeClock(testOrigin)
	ctx, cancel := context.WithCancel(context.Background())
	runner := newFakeRunner(clock,
		fakeBehavior{
			Outcome: OutcomeSucceeded, Advance: time.Hour,
			Before: func(int64) { cancel() },
		},
	)
	h := newHarness(t, root, runner, clock, func(cfg *Config) {
		cfg.Cadence = 0
		cfg.ColdSettle = 0
	})
	defer h.close()
	defer cancel()

	summary, err := h.controller().Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if runner.Calls() != 1 {
		t.Fatalf("ran %d cycles after cancellation, want 1", runner.Calls())
	}
	if summary.TerminalReason != ReasonContextDone {
		t.Errorf("terminal reason %q, want %q",
			summary.TerminalReason, ReasonContextDone)
	}
}
