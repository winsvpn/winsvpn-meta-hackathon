package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const receiptTestNonce = "0123456789abcdef0123456789abcdef"

func validTestReceipt(runID string, outcome CycleOutcome) Receipt {
	exitStatus := 0
	if outcome == OutcomeTimedOut || outcome == OutcomeCancelled {
		exitStatus = -1
	} else if outcome == OutcomeFailed {
		exitStatus = 1
	}
	return Receipt{
		RunID:              runID,
		InstanceNonce:      receiptTestNonce,
		Readiness:          ReadinessWarm,
		Outcome:            outcome,
		ExitStatus:         exitStatus,
		WallAt:             rfc3339(testOrigin),
		SnapshotDigest:     strings.Repeat("a", 64),
		ContainmentCleanup: nonApplicableContainmentCleanup(),
	}
}

func appendReceipts(t *testing.T, log *ReceiptLog, outcomes ...CycleOutcome) {
	t.Helper()
	for _, outcome := range outcomes {
		if _, err := log.Append(validTestReceipt("tamper-test", outcome)); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
}

// TestReceiptLogReplayRejectsTampering.
//
// Each subtest performs one specific edit to the file and asserts the replay
// refuses it with the reason that edit should produce. Asserting only "replay
// returned an error" would let a replay that rejected every log pass all of
// them, so a clean control is run first in every case.
func TestReceiptLogReplayRejectsTampering(t *testing.T) {
	const runID = "tamper-test"

	build := func(t *testing.T) string {
		t.Helper()
		evidence := t.TempDir()
		log, err := OpenReceiptLog(evidence, runID)
		if err != nil {
			t.Fatalf("open receipt log: %v", err)
		}
		appendReceipts(t, log,
			OutcomeSucceeded, OutcomeSucceeded, OutcomeFailed,
			OutcomeSucceeded, OutcomeTimedOut,
		)
		if err := log.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		// Control: the untouched log replays.
		reopened, err := OpenReceiptLog(evidence, runID)
		if err != nil {
			t.Fatalf("the untouched log was refused: %v", err)
		}
		if reopened.Count() != 5 {
			t.Fatalf("replayed %d receipts, want 5", reopened.Count())
		}
		totals := reopened.Totals()
		if totals.Attempted != 5 || totals.Succeeded != 3 ||
			totals.Failed != 1 || totals.TimedOut != 1 {
			t.Fatalf("replayed totals %+v", totals)
		}
		if err := totals.conservationError(); err != nil {
			t.Fatalf("conservation failed on a clean log: %v", err)
		}
		_ = reopened.Close()
		return evidence
	}

	lines := func(t *testing.T, evidence string) []string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(evidence, "cycle-receipts.jsonl"))
		if err != nil {
			t.Fatalf("read log: %v", err)
		}
		return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	}

	rewrite := func(t *testing.T, evidence string, contents []string) {
		t.Helper()
		body := strings.Join(contents, "\n")
		if body != "" {
			body += "\n"
		}
		if err := os.WriteFile(
			filepath.Join(evidence, "cycle-receipts.jsonl"),
			[]byte(body), 0o600,
		); err != nil {
			t.Fatalf("rewrite log: %v", err)
		}
	}

	tests := []struct {
		name   string
		mutate func(t *testing.T, evidence string)
		want   string
	}{
		{
			name: "a middle receipt removed",
			mutate: func(t *testing.T, evidence string) {
				current := lines(t, evidence)
				rewrite(t, evidence, append(current[:2], current[3:]...))
			},
			want: "jumps from sequence",
		},
		{
			name: "a receipt duplicated",
			mutate: func(t *testing.T, evidence string) {
				current := lines(t, evidence)
				doubled := append([]string{}, current[:3]...)
				doubled = append(doubled, current[2])
				doubled = append(doubled, current[3:]...)
				rewrite(t, evidence, doubled)
			},
			want: "jumps from sequence",
		},
		{
			name: "the tail truncated",
			mutate: func(t *testing.T, evidence string) {
				current := lines(t, evidence)
				rewrite(t, evidence, current[:3])
			},
			// Truncation of the TAIL is not detectable from the log alone:
			// the remaining prefix is a perfectly valid shorter log. It is
			// caught by the checkpoint, which records how many cycles ran,
			// and planResume refuses the disagreement. This case asserts the
			// prefix still replays, so the comment above is not describing a
			// detection that does not exist.
			want: "",
		},
		{
			name: "an outcome relabelled",
			mutate: func(t *testing.T, evidence string) {
				current := lines(t, evidence)
				var receipt Receipt
				if err := json.Unmarshal([]byte(current[2]), &receipt); err != nil {
					t.Fatalf("decode: %v", err)
				}
				receipt.Outcome = OutcomeSucceeded
				encoded, err := json.Marshal(receipt)
				if err != nil {
					t.Fatalf("encode: %v", err)
				}
				current[2] = string(encoded)
				rewrite(t, evidence, current)
			},
			// The semantic validator now catches the impossible
			// succeeded/nonzero-exit pairing even before conservation.
			want: "successful receipt has a nonzero exit status",
		},
		{
			// This case isolates the CHAIN check, which the relabelling
			// case above does not reach. WallAt affects neither the outcome
			// nor any running total, so receipt 3 stays internally
			// consistent and only its bytes change -- which is exactly what
			// receipt 4's PreviousDigest commits to.
			name: "a non-accounting field edited",
			mutate: func(t *testing.T, evidence string) {
				current := lines(t, evidence)
				var receipt Receipt
				if err := json.Unmarshal([]byte(current[2]), &receipt); err != nil {
					t.Fatalf("decode: %v", err)
				}
				receipt.WallAt = "2026-01-01T00:00:00Z"
				encoded, err := json.Marshal(receipt)
				if err != nil {
					t.Fatalf("encode: %v", err)
				}
				current[2] = string(encoded)
				rewrite(t, evidence, current)
			},
			want: "chains to",
		},
		{
			name: "a running total edited",
			mutate: func(t *testing.T, evidence string) {
				current := lines(t, evidence)
				var receipt Receipt
				if err := json.Unmarshal(
					[]byte(current[len(current)-1]), &receipt,
				); err != nil {
					t.Fatalf("decode: %v", err)
				}
				receipt.Succeeded = 99
				encoded, err := json.Marshal(receipt)
				if err != nil {
					t.Fatalf("encode: %v", err)
				}
				current[len(current)-1] = string(encoded)
				rewrite(t, evidence, current)
			},
			want: "running totals that disagree",
		},
		{
			name: "a blank line inserted",
			mutate: func(t *testing.T, evidence string) {
				current := lines(t, evidence)
				spaced := append([]string{}, current[:2]...)
				spaced = append(spaced, "")
				spaced = append(spaced, current[2:]...)
				rewrite(t, evidence, spaced)
			},
			want: "blank line",
		},
		{
			name: "a foreign run's receipt spliced in",
			mutate: func(t *testing.T, evidence string) {
				current := lines(t, evidence)
				var receipt Receipt
				if err := json.Unmarshal([]byte(current[1]), &receipt); err != nil {
					t.Fatalf("decode: %v", err)
				}
				receipt.RunID = "some-other-run"
				encoded, err := json.Marshal(receipt)
				if err != nil {
					t.Fatalf("encode: %v", err)
				}
				current[1] = string(encoded)
				rewrite(t, evidence, current)
			},
			want: "belongs to run",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := build(t)
			test.mutate(t, evidence)
			log, err := OpenReceiptLog(evidence, runID)
			if log != nil {
				_ = log.Close()
			}
			if test.want == "" {
				if err != nil {
					t.Fatalf("replay refused a case documented as "+
						"undetectable from the log alone: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("%s was accepted by the replay", test.name)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("refusal was %q, want one containing %q",
					err.Error(), test.want)
			}
		})
	}
}

// TestTailTruncationIsCaughtByTheCheckpoint states the compensating control for
// the one case the log alone cannot detect.
func TestTailTruncationIsCaughtByTheCheckpoint(t *testing.T) {
	cfg := testConfig(t, t.TempDir())
	provenance := testProvenance()
	stored := storedCheckpoint(cfg, provenance)
	stored.CyclesAttempted = 5
	stored.CyclesSucceeded = 5
	stored.AccumulatedElapsedNanos = int64(72 * time.Hour)

	// The log has been truncated to three receipts while the checkpoint
	// still records five.
	_, err := planResume(
		stored, true, ReceiptReplayState{
			Count: 3, Head: stored.LastReceiptDigest,
		}, FirstFailureFileState{}, provenance,
		testOrigin.Add(80*time.Hour), cfg,
	)
	if err == nil {
		t.Fatal("a truncated receipt log resumed against a checkpoint that " +
			"records more cycles")
	}
	if !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("refusal was %v, want one naming the disagreement", err)
	}
	// Control: agreement resumes.
	if _, err := planResume(
		stored, true, replayForCheckpoint(stored),
		FirstFailureFileState{}, provenance,
		testOrigin.Add(80*time.Hour), cfg,
	); err != nil {
		t.Fatalf("an agreeing pair was refused: %v", err)
	}
}

// TestReceiptLogOwnsItsSequenceAndTotals proves a caller cannot dictate them.
//
// If Append honoured caller-supplied sequence numbers, the conservation check
// would be checking the caller's arithmetic rather than what happened.
func TestReceiptLogOwnsItsSequenceAndTotals(t *testing.T) {
	evidence := t.TempDir()
	log, err := OpenReceiptLog(evidence, "ownership")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = log.Close() }()

	receipt := validTestReceipt("ownership", OutcomeSucceeded)
	receipt.Sequence = 9999
	receipt.Attempted = 12345
	receipt.Succeeded = 999
	receipt.PreviousDigest = "not the real predecessor"
	if _, err := log.Append(receipt); err != nil {
		t.Fatalf("append: %v", err)
	}
	stored := readReceipts(t, evidence)
	if len(stored) != 1 {
		t.Fatalf("%d receipts, want 1", len(stored))
	}
	if stored[0].Sequence != 1 {
		t.Errorf("stored sequence %d, want 1", stored[0].Sequence)
	}
	if stored[0].Attempted != 1 || stored[0].Succeeded != 1 {
		t.Errorf("stored totals attempted=%d succeeded=%d, want 1 and 1",
			stored[0].Attempted, stored[0].Succeeded)
	}
	if stored[0].PreviousDigest != genesisDigest {
		t.Errorf("stored predecessor %q, want the genesis digest",
			stored[0].PreviousDigest)
	}
}

func TestReceiptAtConfiguredMaximumReplays(t *testing.T) {
	root := t.TempDir()
	log, err := OpenReceiptLog(root, "maximum-tail")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	tail := make([]byte, maximumCycleTailBytes)
	for index := range tail {
		tail[index] = byte(index)
	}
	maximumReceipt := validTestReceipt("maximum-tail", OutcomeSucceeded)
	maximumReceipt.StdoutTail = tail
	maximumReceipt.StderrTail = tail
	maximumReceipt.StdoutBytes = int64(len(tail))
	maximumReceipt.StderrBytes = int64(len(tail))
	if _, err := log.Append(maximumReceipt); err != nil {
		t.Fatalf("append configured maximum: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	info, err := os.Stat(filepath.Join(root, "cycle-receipts.jsonl"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() > int64(maximumReceiptScannerBytes) {
		t.Fatalf("encoded line is %d bytes, scanner bound is %d",
			info.Size(), maximumReceiptScannerBytes)
	}
	replayed, err := OpenReceiptLog(root, "maximum-tail")
	if err != nil {
		t.Fatalf("replay configured maximum: %v", err)
	}
	defer func() { _ = replayed.Close() }()
	if replayed.Count() != 1 {
		t.Fatalf("replayed %d receipts, want 1", replayed.Count())
	}
}

func TestFirstFailureFileIsBoundToTheFailingReceipt(t *testing.T) {
	root := t.TempDir()
	log, err := OpenReceiptLog(root, "first-bind")
	if err != nil {
		t.Fatal(err)
	}
	failingReceipt := validTestReceipt("first-bind", OutcomeFailed)
	failingReceipt.Readiness = ReadinessCold
	failingReceipt.ExitStatus = 17
	failingReceipt.StdoutTail = []byte("out")
	failingReceipt.StderrTail = []byte("err")
	failingReceipt.StdoutBytes = 3
	failingReceipt.StderrBytes = 3
	failingReceipt.ExceededBounds = []ExceededBound{}
	digest, err := log.Append(failingReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := RecordFirstFailure(root, FirstFailure{
		RunID:         "first-bind",
		Sequence:      1,
		Outcome:       OutcomeFailed,
		ExitStatus:    17,
		Readiness:     ReadinessCold,
		WallAt:        failingReceipt.WallAt,
		ElapsedNanos:  failingReceipt.AccumulatedElapsedNanos,
		ReceiptDigest: digest,
		StdoutTail:    []byte("out"),
		StderrTail:    []byte("err"),
	}); err != nil {
		t.Fatal(err)
	}
	file, err := LoadFirstFailure(root, "first-bind")
	if err != nil {
		t.Fatal(err)
	}
	replay := log.ReplayState()
	if err := validateFirstFailure(replay, file); err != nil {
		t.Fatalf("matching first failure refused: %v", err)
	}

	tampered := file
	tampered.Failure.ExitStatus = 99
	if err := validateFirstFailure(replay, tampered); err == nil {
		t.Fatal("tampered first-failure duplicate was accepted")
	}
	if err := validateFirstFailure(
		replay, FirstFailureFileState{},
	); err == nil {
		t.Fatal("missing first-failure file was accepted")
	}
	if err := validateFirstFailure(
		ReceiptReplayState{Head: genesisDigest}, file,
	); err == nil {
		t.Fatal("stale first-failure file with a clean log was accepted")
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestReceiptLogRefusesAnUnnameableOutcome keeps the conservation set closed.
func TestReceiptLogRefusesAnUnnameableOutcome(t *testing.T) {
	evidence := t.TempDir()
	log, err := OpenReceiptLog(evidence, "closed-set")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = log.Close() }()
	if _, err := log.Append(Receipt{
		RunID:   "closed-set",
		Outcome: CycleOutcome("something-else"),
	}); err == nil {
		t.Fatal("an outcome outside the closed set was recorded")
	}
	if readReceipts(t, evidence) != nil {
		t.Error("the refused receipt was written anyway")
	}
}
