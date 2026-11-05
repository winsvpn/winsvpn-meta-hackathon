package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	receiptSchema = "winn-phase1-soak-cycle-receipt/v2"
	// genesisDigest is the predecessor of the first receipt. Sixty-four
	// zeroes rather than an empty string, so that a truncated log cannot be
	// made to look like a fresh one by deleting every line.
	genesisDigest = "0000000000000000000000000000000000000000000000000000000000000000"
	// maximumCycleTailBytes is the largest configured tail retained from EACH
	// output stream. The replay ceiling below is derived from this same value,
	// so Append can never create a valid receipt that replay refuses.
	maximumCycleTailBytes = 1 << 20
	// JSON encodes []byte as base64. Four bytes are emitted per three input
	// bytes, rounded up. Both stdout and stderr may reach the configured max.
	maximumEncodedTailBytes = 4 * ((maximumCycleTailBytes + 2) / 3)
	// Every non-tail field must fit in this separately enforced allowance.
	// It is deliberately generous but finite; the actual metadata encoding is
	// checked before every append.
	maximumReceiptMetadataBytes = 64 << 10
	// maximumReceiptLine is therefore a mathematical upper bound, not a value
	// chosen independently from the writer.
	maximumReceiptLine = maximumReceiptMetadataBytes +
		2*maximumEncodedTailBytes
	// Scanner must also accommodate the newline delimiter after a maximum
	// sized JSON line.
	maximumReceiptScannerBytes = maximumReceiptLine + 1
	// maximumReceipts bounds the whole log. Seven days at the shortest
	// sensible cadence cannot approach this; it exists so a corrupt file
	// cannot make verification allocate without limit.
	maximumReceipts = 1_000_000
	// maximumRecordedCgroupEventsBytes mirrors Phase A's descriptor-read
	// bound. Receipt replay must accept the exact raw kernel bytes Phase A
	// preserves, but never a payload Phase A itself could not have read.
	maximumRecordedCgroupEventsBytes = 4 << 10
)

var noncePattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

var receiptJSONMembers = []string{
	"schema", "run_id", "sequence", "previous_digest", "instance_nonce",
	"predecessor_nonce", "resume_count", "readiness", "outcome",
	"exit_status", "started_elapsed_nanos", "ended_elapsed_nanos",
	"accumulated_elapsed_nanos", "wall_at", "stdout_bytes", "stderr_bytes",
	"truncated", "stdout_tail", "stderr_tail", "resources",
	"containment_cleanup", "exceeded_bounds", "running_attempted", "running_succeeded",
	"running_failed", "running_timed_out", "running_cancelled",
	"snapshot_digest",
}

// Receipt is one cycle, as recorded.
//
// Every field is always emitted -- no omitempty anywhere in this struct. An
// omitted field changes the bytes, and the bytes are what the next receipt's
// PreviousDigest commits to; a field that disappears when it happens to be
// empty makes the chain depend on the values rather than only on the content.
type Receipt struct {
	Schema           string `json:"schema"`
	RunID            string `json:"run_id"`
	Sequence         int64  `json:"sequence"`
	PreviousDigest   string `json:"previous_digest"`
	InstanceNonce    string `json:"instance_nonce"`
	PredecessorNonce string `json:"predecessor_nonce"`
	ResumeCount      int64  `json:"resume_count"`

	Readiness Readiness    `json:"readiness"`
	Outcome   CycleOutcome `json:"outcome"`
	// ExitStatus is the runner's own exit status, or -1 where the process
	// was killed rather than having exited. See CycleResult.
	ExitStatus int `json:"exit_status"`

	StartedElapsedNanos int64 `json:"started_elapsed_nanos"`
	EndedElapsedNanos   int64 `json:"ended_elapsed_nanos"`
	// AccumulatedElapsedNanos is the soak-wide monotonic total after this
	// cycle, across every resume. A reader can therefore confirm the
	// duration was served without trusting the summary.
	AccumulatedElapsedNanos int64  `json:"accumulated_elapsed_nanos"`
	WallAt                  string `json:"wall_at"`

	StdoutBytes int64 `json:"stdout_bytes"`
	StderrBytes int64 `json:"stderr_bytes"`
	Truncated   bool  `json:"truncated"`
	// StdoutTail and StderrTail are bounded excerpts, base64 in JSON.
	StdoutTail []byte `json:"stdout_tail"`
	StderrTail []byte `json:"stderr_tail"`

	Resources          ResourceSample          `json:"resources"`
	ContainmentCleanup CycleContainmentCleanup `json:"containment_cleanup"`
	ExceededBounds     []ExceededBound         `json:"exceeded_bounds"`

	// RunningTotals let a reader check conservation at every line rather
	// than only at the end. A log whose last line balances but whose
	// seventeenth does not has been edited.
	Attempted int64 `json:"running_attempted"`
	Succeeded int64 `json:"running_succeeded"`
	Failed    int64 `json:"running_failed"`
	TimedOut  int64 `json:"running_timed_out"`
	Cancelled int64 `json:"running_cancelled"`

	// SnapshotDigest is re-verified before every cycle and recorded here, so
	// the tree each individual cycle ran against is attributable rather than
	// inferred from a single check at startup.
	SnapshotDigest string `json:"snapshot_digest"`
}

// ReceiptLog is an append-only JSONL log.
//
// Append-only is enforced by the open mode and by never seeking: the file is
// opened O_APPEND, so every write lands at the end regardless of what any other
// writer is doing, and nothing in this type truncates, rewrites, or removes a
// line.
type ReceiptLog struct {
	path           string
	base           string
	directory      *secureDirectory
	file           *os.File
	lastHash       string
	count          int64
	totals         receiptTotals
	first          receiptFailureState
	haveFirst      bool
	lastReceipt    *Receipt
	replayIdentity fileIdentity
	hadReplayFile  bool
}

type receiptFailureState struct {
	Sequence       int64
	Outcome        CycleOutcome
	ExitStatus     int
	Readiness      Readiness
	WallAt         string
	ElapsedNanos   int64
	ReceiptDigest  string
	StdoutTail     []byte
	StderrTail     []byte
	ExceededBounds []ExceededBound
}

type ReceiptReplayState struct {
	Count                int64
	Head                 string
	Totals               receiptTotals
	FirstFailure         receiptFailureState
	HasFailure           bool
	LastInstanceNonce    string
	LastPredecessorNonce string
	LastResumeCount      int64
}

type receiptTotals struct {
	Attempted int64
	Succeeded int64
	Failed    int64
	TimedOut  int64
	Cancelled int64
}

// conservationError reports totals that do not add up.
//
// Honest scope, because mutation testing showed the first version of this
// comment claimed more than the code does. Removing this check entirely leaves
// every test in this package passing, and that is not a hole in the tests: the
// totals it inspects are RECOMPUTED here from a closed set of outcomes, so
// within this program they cannot fail to balance. It is a structural assertion
// against a future edit that adds a fifth outcome and forgets to count it, not
// a detector of tampering.
//
// What actually catches an edited log is the comparison in replay between each
// receipt's RECORDED running totals and the recomputed ones, and what catches a
// truncated log is Checkpoint.conservationError together with the
// checkpoint-versus-log count comparison in planResume. Those are the load-
// bearing checks; this one is a guard rail.
func (t receiptTotals) conservationError() error {
	sum := t.Succeeded + t.Failed + t.TimedOut + t.Cancelled
	if sum != t.Attempted {
		return fmt.Errorf(
			"receipt conservation failed: %d attempted but the outcome "+
				"counts sum to %d", t.Attempted, sum,
		)
	}
	return nil
}

// OpenReceiptLog opens the log and replays it to recover the chain head.
//
// Replaying rather than trusting the checkpoint is deliberate. The checkpoint
// says where the controller thinks it was; the log says what was actually
// written. Where they disagree the log wins, and the disagreement is reported.
func OpenReceiptLog(directory, runID string) (*ReceiptLog, error) {
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, "cycle-receipts.jsonl")
	secure, err := openSecureDirectory(directory)
	if err != nil {
		return nil, err
	}
	log := &ReceiptLog{
		path: path, base: "cycle-receipts.jsonl",
		directory: secure, lastHash: genesisDigest,
	}
	if err := log.replay(runID); err != nil {
		_ = secure.Close()
		return nil, err
	}
	created := !log.hadReplayFile
	flags := os.O_APPEND | os.O_CREATE | os.O_WRONLY
	if created {
		flags |= os.O_EXCL
	}
	file, err := secure.Open(log.base, flags, 0o600)
	if err != nil {
		_ = secure.Close()
		return nil, fmt.Errorf("open receipt log: %w", err)
	}
	if created {
		if err := syncFileOperation(file); err != nil {
			_ = file.Close()
			_ = secure.Close()
			return nil, fmt.Errorf("sync new receipt log: %w", err)
		}
		if err := secure.Sync(); err != nil {
			_ = file.Close()
			_ = secure.Close()
			return nil, err
		}
	}
	openedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat opened receipt log: %w", err)
	}
	openedIdentity, err := identityFromInfo(openedInfo)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("identify opened receipt log: %w", err)
	}
	if log.hadReplayFile && openedIdentity != log.replayIdentity {
		_ = file.Close()
		return nil, errors.New(
			"receipt log changed identity between replay and append custody",
		)
	}
	log.file = file
	return log, nil
}

func (l *ReceiptLog) replay(runID string) error {
	// #nosec G304 -- see OpenReceiptLog.
	file, err := l.directory.Open(l.base, os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open receipt log for replay: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat receipt log %s: %w", l.path, err)
	}
	identity, err := identityFromInfo(info)
	if err != nil {
		return fmt.Errorf("identify receipt log %s: %w", l.path, err)
	}
	l.replayIdentity = identity
	l.hadReplayFile = true
	if info.Size() > 0 {
		var final [1]byte
		if _, err := file.ReadAt(final[:], info.Size()-1); err != nil {
			return fmt.Errorf("read receipt log terminator: %w", err)
		}
		if final[0] != '\n' {
			return fmt.Errorf(
				"receipt log %s is not newline-terminated", l.path,
			)
		}
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64<<10), maximumReceiptScannerBytes)
	expected := int64(1)
	previous := genesisDigest
	var totals receiptTotals
	var previousReceipt *Receipt
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			return fmt.Errorf(
				"receipt log %s contains a blank line at position %d",
				l.path, expected,
			)
		}
		if expected > maximumReceipts {
			return fmt.Errorf(
				"receipt log %s exceeds the %d receipt bound",
				l.path, maximumReceipts,
			)
		}
		var receipt Receipt
		if err := decodeExactJSONObject(line, receiptJSONMembers, &receipt); err != nil {
			return fmt.Errorf(
				"receipt %d in %s is not decodable: %w", expected, l.path, err,
			)
		}
		switch {
		case receipt.Schema != receiptSchema:
			return fmt.Errorf(
				"receipt %d has schema %q, expected %q",
				expected, receipt.Schema, receiptSchema,
			)
		case receipt.RunID != runID:
			return fmt.Errorf(
				"receipt %d belongs to run %q, this invocation is run %q",
				expected, receipt.RunID, runID,
			)
		case receipt.Sequence != expected:
			// Gaps and repeats are both fatal. A gap means a cycle ran and
			// was not recorded; a repeat means two writers. Neither can be
			// reconciled by a reader afterwards.
			return fmt.Errorf(
				"receipt log %s jumps from sequence %d to %d",
				l.path, expected-1, receipt.Sequence,
			)
		case receipt.PreviousDigest != previous:
			return fmt.Errorf(
				"receipt %d chains to %s, but receipt %d hashes to %s",
				receipt.Sequence, receipt.PreviousDigest,
				expected-1, previous,
			)
		}
		if err := validateReceiptSemantics(receipt, previousReceipt); err != nil {
			return fmt.Errorf("receipt %d semantics: %w", expected, err)
		}
		totals.Attempted++
		switch receipt.Outcome {
		case OutcomeSucceeded:
			totals.Succeeded++
		case OutcomeFailed:
			totals.Failed++
		case OutcomeTimedOut:
			totals.TimedOut++
		case OutcomeCancelled:
			totals.Cancelled++
		default:
			return fmt.Errorf(
				"receipt %d has an unnameable outcome %q",
				receipt.Sequence, receipt.Outcome,
			)
		}
		if totals.Attempted != receipt.Attempted ||
			totals.Succeeded != receipt.Succeeded ||
			totals.Failed != receipt.Failed ||
			totals.TimedOut != receipt.TimedOut ||
			totals.Cancelled != receipt.Cancelled {
			return fmt.Errorf(
				"receipt %d records running totals that disagree with the "+
					"lines before it", receipt.Sequence,
			)
		}
		if err := totals.conservationError(); err != nil {
			return fmt.Errorf("at receipt %d: %w", receipt.Sequence, err)
		}
		sum := sha256.Sum256(line)
		previous = hex.EncodeToString(sum[:])
		if !l.haveFirst &&
			(receipt.Outcome != OutcomeSucceeded ||
				len(receipt.ExceededBounds) > 0) {
			l.first = failureStateFromReceipt(receipt, previous)
			l.haveFirst = true
		}
		expected++
		copyOfReceipt := receipt
		previousReceipt = &copyOfReceipt
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read receipt log %s: %w", l.path, err)
	}
	l.lastHash = previous
	l.count = expected - 1
	l.totals = totals
	l.lastReceipt = previousReceipt
	return nil
}

func validateReceiptSemantics(receipt Receipt, previous *Receipt) error {
	switch {
	case !noncePattern.MatchString(receipt.InstanceNonce):
		return errors.New("instance nonce is not 32 lowercase hexadecimal characters")
	case receipt.PredecessorNonce != "" &&
		!noncePattern.MatchString(receipt.PredecessorNonce):
		return errors.New("predecessor nonce is malformed")
	case receipt.ResumeCount < 0:
		return errors.New("resume count is negative")
	case !receipt.Readiness.valid():
		return fmt.Errorf("readiness %q is invalid", receipt.Readiness)
	case !receipt.Outcome.valid():
		return fmt.Errorf("outcome %q is invalid", receipt.Outcome)
	case receipt.Outcome == OutcomeSucceeded && receipt.ExitStatus != 0:
		return errors.New("successful receipt has a nonzero exit status")
	case receipt.Outcome == OutcomeFailed && receipt.ExitStatus == 0:
		return errors.New("failed receipt has a zero exit status")
	case (receipt.Outcome == OutcomeTimedOut ||
		receipt.Outcome == OutcomeCancelled) && receipt.ExitStatus != -1:
		return errors.New("timed-out/cancelled receipt must use exit status -1")
	case receipt.StartedElapsedNanos < 0 ||
		receipt.EndedElapsedNanos < receipt.StartedElapsedNanos ||
		receipt.AccumulatedElapsedNanos < receipt.EndedElapsedNanos:
		return errors.New("monotonic elapsed fields are negative or out of order")
	case receipt.StdoutBytes < int64(len(receipt.StdoutTail)) ||
		receipt.StderrBytes < int64(len(receipt.StderrTail)):
		return errors.New("output byte count is smaller than its retained tail")
	case receipt.Truncated !=
		(receipt.StdoutBytes > int64(len(receipt.StdoutTail)) ||
			receipt.StderrBytes > int64(len(receipt.StderrTail))):
		return errors.New("truncated flag disagrees with output counts and tails")
	case !digestPattern.MatchString(receipt.SnapshotDigest):
		return errors.New("snapshot digest is malformed")
	}
	if _, err := time.Parse(time.RFC3339Nano, receipt.WallAt); err != nil {
		return fmt.Errorf("wall_at is not RFC3339Nano: %w", err)
	}
	if err := validateResourceSemantics(
		receipt.Resources, receipt.ExceededBounds,
	); err != nil {
		return err
	}
	if err := validateContainmentCleanup(receipt.ContainmentCleanup); err != nil {
		return fmt.Errorf("containment cleanup: %w", err)
	}
	if previous == nil {
		if receipt.ResumeCount != 0 {
			return errors.New(
				"first receipt must have resume_count 0",
			)
		}
		return nil
	}
	switch {
	case receipt.AccumulatedElapsedNanos < previous.AccumulatedElapsedNanos:
		return errors.New("accumulated elapsed time moved backwards")
	case receipt.ResumeCount == previous.ResumeCount:
		if receipt.InstanceNonce != previous.InstanceNonce ||
			receipt.PredecessorNonce != previous.PredecessorNonce {
			return errors.New("nonce lineage changed without a resume")
		}
	case receipt.ResumeCount == previous.ResumeCount+1:
		if receipt.InstanceNonce == previous.InstanceNonce {
			return errors.New("resumed instance reused the prior nonce")
		}
		if receipt.PredecessorNonce != previous.InstanceNonce {
			return errors.New("resumed instance does not name the prior nonce")
		}
	default:
		return errors.New("resume count skipped or moved backwards")
	}
	return nil
}

func validateContainmentCleanup(cleanup CycleContainmentCleanup) error {
	switch cleanup.Schema {
	case linuxCgroupV2CleanupSchema:
		switch {
		case cleanup.ChildCgroupInode == 0:
			//lint:ignore ST1005 Linux is a proper noun.
			return errors.New("Linux cleanup has a zero child cgroup inode")
		case !cleanup.ChildRemoved:
			//lint:ignore ST1005 Linux is a proper noun.
			return errors.New("Linux cleanup does not prove child removal")
		}
		if err := validateTerminalCgroupEvents(
			cleanup.FinalCgroupEvents,
		); err != nil {
			return err
		}
	case nonApplicableCleanupSchema:
		if cleanup.ChildCgroupInode != 0 ||
			cleanup.FinalCgroupEvents != "" ||
			cleanup.ChildRemoved {
			return errors.New(
				"non-applicable cleanup carries mixed Linux evidence",
			)
		}
	default:
		if cleanup.Schema == "" {
			return errors.New("containment cleanup evidence is missing")
		}
		return fmt.Errorf(
			"containment cleanup schema %q is unknown", cleanup.Schema,
		)
	}
	return nil
}

func validateTerminalCgroupEvents(raw string) error {
	encoded := []byte(raw)
	if len(encoded) == 0 {
		return errors.New("cgroup.events is empty")
	}
	if len(encoded) > maximumRecordedCgroupEventsBytes {
		return errors.New("cgroup.events exceeds the 4 KiB bound")
	}
	if encoded[len(encoded)-1] != '\n' || !utf8.Valid(encoded) {
		return errors.New("cgroup.events is malformed or unterminated")
	}
	found := 0
	populated := false
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || line != fields[0]+" "+fields[1] {
			return fmt.Errorf("malformed cgroup.events line %q", line)
		}
		if fields[0] != "populated" {
			continue
		}
		found++
		switch fields[1] {
		case "0":
			populated = false
		case "1":
			populated = true
		default:
			return fmt.Errorf("invalid populated value %q", fields[1])
		}
	}
	if found != 1 {
		return fmt.Errorf(
			"cgroup.events contains %d populated lines, expected exactly one",
			found,
		)
	}
	if populated {
		return errors.New("cgroup.events is not terminal: populated is 1")
	}
	return nil
}

func validateResourceSemantics(
	sample ResourceSample, exceeded []ExceededBound,
) error {
	values := []int64{
		sample.MaxRSSBytes, sample.UserCPUNanos, sample.SystemCPUNanos,
		sample.PeakThreads, sample.PeakOpenFiles, sample.PeakVmRSSBytes,
		sample.SampleCount,
	}
	for _, value := range values {
		if value < 0 {
			return errors.New("resource sample contains a negative value")
		}
	}
	if !sample.ProcSampled &&
		(sample.PeakThreads != 0 || sample.PeakOpenFiles != 0 ||
			sample.PeakVmRSSBytes != 0 || sample.SampleCount != 0) {
		return errors.New("unmeasured proc sample carries measured values")
	}
	seen := make(map[string]struct{})
	for _, bound := range exceeded {
		if bound.Bound == "" || bound.Observed <= bound.Limit || bound.Limit <= 0 {
			return errors.New("exceeded bound is empty or does not exceed its limit")
		}
		if _, exists := seen[bound.Bound]; exists {
			return fmt.Errorf("exceeded bound %q is duplicated", bound.Bound)
		}
		seen[bound.Bound] = struct{}{}
	}
	return nil
}

func (l *ReceiptLog) Count() int64          { return l.count }
func (l *ReceiptLog) Head() string          { return l.lastHash }
func (l *ReceiptLog) Totals() receiptTotals { return l.totals }
func (l *ReceiptLog) ReplayState() ReceiptReplayState {
	return ReceiptReplayState{
		Count:        l.count,
		Head:         l.lastHash,
		Totals:       l.totals,
		FirstFailure: l.first,
		HasFailure:   l.haveFirst,
		LastInstanceNonce: func() string {
			if l.lastReceipt == nil {
				return ""
			}
			return l.lastReceipt.InstanceNonce
		}(),
		LastPredecessorNonce: func() string {
			if l.lastReceipt == nil {
				return ""
			}
			return l.lastReceipt.PredecessorNonce
		}(),
		LastResumeCount: func() int64 {
			if l.lastReceipt == nil {
				return 0
			}
			return l.lastReceipt.ResumeCount
		}(),
	}
}

// Append writes one receipt and advances the chain.
//
// The caller supplies everything except Sequence, PreviousDigest and the
// running totals, which this method owns. Letting the caller set them would
// make the conservation check a check on the caller's arithmetic rather than on
// what happened.
func (l *ReceiptLog) Append(receipt Receipt) (string, error) {
	if err := l.directory.VerifyPath(); err != nil {
		return "", fmt.Errorf("receipt directory continuity: %w", err)
	}
	info, err := l.file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat receipt append descriptor: %w", err)
	}
	identity, err := identityFromInfo(info)
	if err != nil {
		return "", fmt.Errorf("identify receipt append descriptor: %w", err)
	}
	if identity.nlink != 1 {
		return "", fmt.Errorf(
			"receipt append descriptor has %d hard links", identity.nlink,
		)
	}
	if !receipt.Outcome.valid() {
		return "", fmt.Errorf("refusing to record outcome %q", receipt.Outcome)
	}
	if l.count >= maximumReceipts {
		return "", fmt.Errorf(
			"refusing to append receipt %d beyond the %d receipt bound",
			l.count+1, maximumReceipts,
		)
	}
	receipt.Schema = receiptSchema
	receipt.Sequence = l.count + 1
	receipt.PreviousDigest = l.lastHash

	totals := l.totals
	totals.Attempted++
	switch receipt.Outcome {
	case OutcomeSucceeded:
		totals.Succeeded++
	case OutcomeFailed:
		totals.Failed++
	case OutcomeTimedOut:
		totals.TimedOut++
	case OutcomeCancelled:
		totals.Cancelled++
	}
	if err := totals.conservationError(); err != nil {
		return "", err
	}
	receipt.Attempted = totals.Attempted
	receipt.Succeeded = totals.Succeeded
	receipt.Failed = totals.Failed
	receipt.TimedOut = totals.TimedOut
	receipt.Cancelled = totals.Cancelled
	if receipt.ExceededBounds == nil {
		receipt.ExceededBounds = []ExceededBound{}
	}
	if receipt.StdoutTail == nil {
		receipt.StdoutTail = []byte{}
	}
	if receipt.StderrTail == nil {
		receipt.StderrTail = []byte{}
	}
	if len(receipt.StdoutTail) > maximumCycleTailBytes ||
		len(receipt.StderrTail) > maximumCycleTailBytes {
		return "", fmt.Errorf(
			"receipt %d tails are %d/%d bytes; each is limited to %d",
			receipt.Sequence, len(receipt.StdoutTail), len(receipt.StderrTail),
			maximumCycleTailBytes,
		)
	}

	metadataOnly := receipt
	metadataOnly.StdoutTail = []byte{}
	metadataOnly.StderrTail = []byte{}
	metadata, err := json.Marshal(metadataOnly)
	if err != nil {
		return "", fmt.Errorf(
			"encode receipt %d metadata: %w", receipt.Sequence, err,
		)
	}
	if len(metadata) > maximumReceiptMetadataBytes {
		return "", fmt.Errorf(
			"receipt %d metadata is %d bytes, above the %d byte bound",
			receipt.Sequence, len(metadata), maximumReceiptMetadataBytes,
		)
	}

	encoded, err := json.Marshal(receipt)
	if err != nil {
		return "", fmt.Errorf("encode receipt %d: %w", receipt.Sequence, err)
	}
	if len(encoded) > maximumReceiptLine {
		return "", fmt.Errorf(
			"receipt %d encoded to %d bytes, above replay's %d byte bound",
			receipt.Sequence, len(encoded), maximumReceiptLine,
		)
	}
	if err := validateReceiptSemantics(receipt, l.lastReceipt); err != nil {
		return "", fmt.Errorf("refusing receipt %d: %w", receipt.Sequence, err)
	}
	if err := writeAllOperation(l.file, append(encoded, '\n')); err != nil {
		return "", fmt.Errorf("append receipt %d: %w", receipt.Sequence, err)
	}
	if err := syncFileOperation(l.file); err != nil {
		// A receipt that is not durable is not a receipt. Failing here
		// stops the soak, which is correct: continuing would produce cycles
		// whose evidence may not survive the crash it is meant to survive.
		return "", fmt.Errorf("sync receipt %d: %w", receipt.Sequence, err)
	}
	sum := sha256.Sum256(encoded)
	digest := hex.EncodeToString(sum[:])
	l.lastHash = digest
	l.count = receipt.Sequence
	l.totals = totals
	copyOfReceipt := receipt
	l.lastReceipt = &copyOfReceipt
	if !l.haveFirst &&
		(receipt.Outcome != OutcomeSucceeded ||
			len(receipt.ExceededBounds) > 0) {
		l.first = failureStateFromReceipt(receipt, digest)
		l.haveFirst = true
	}
	return digest, nil
}

func failureStateFromReceipt(
	receipt Receipt, digest string,
) receiptFailureState {
	return receiptFailureState{
		Sequence:       receipt.Sequence,
		Outcome:        receipt.Outcome,
		ExitStatus:     receipt.ExitStatus,
		Readiness:      receipt.Readiness,
		WallAt:         receipt.WallAt,
		ElapsedNanos:   receipt.AccumulatedElapsedNanos,
		ReceiptDigest:  digest,
		StdoutTail:     append([]byte(nil), receipt.StdoutTail...),
		StderrTail:     append([]byte(nil), receipt.StderrTail...),
		ExceededBounds: append([]ExceededBound(nil), receipt.ExceededBounds...),
	}
}

func (l *ReceiptLog) Close() error {
	if l == nil {
		return nil
	}
	var findings []error
	if l.file != nil {
		file := l.file
		l.file = nil
		if err := file.Close(); err != nil {
			findings = append(findings, fmt.Errorf("close receipt log: %w", err))
		}
	}
	if l.directory != nil {
		directory := l.directory
		l.directory = nil
		if err := directory.Close(); err != nil {
			findings = append(findings, err)
		}
	}
	return errors.Join(findings...)
}

// FirstFailure is the preserved record of the first cycle that did not succeed.
type FirstFailure struct {
	Schema         string          `json:"schema"`
	RunID          string          `json:"run_id"`
	Sequence       int64           `json:"sequence"`
	Outcome        CycleOutcome    `json:"outcome"`
	ExitStatus     int             `json:"exit_status"`
	Readiness      Readiness       `json:"readiness"`
	WallAt         string          `json:"wall_at"`
	ElapsedNanos   int64           `json:"elapsed_nanos"`
	ReceiptDigest  string          `json:"receipt_digest"`
	StdoutTail     []byte          `json:"stdout_tail"`
	StderrTail     []byte          `json:"stderr_tail"`
	ExceededBounds []ExceededBound `json:"exceeded_bounds"`
}

const firstFailureSchema = "winn-phase1-soak-first-failure/v1"

var errFirstFailureAlreadyRecorded = errors.New(
	"a first failure is already recorded",
)

type FirstFailureFileState struct {
	Present bool
	Failure FirstFailure
}

var firstFailureJSONMembers = []string{
	"schema", "run_id", "sequence", "outcome", "exit_status", "readiness",
	"wall_at", "elapsed_nanos", "receipt_digest", "stdout_tail",
	"stderr_tail", "exceeded_bounds",
}

func LoadFirstFailure(directory, runID string) (FirstFailureFileState, error) {
	secure, err := openSecureDirectory(directory)
	if err != nil {
		return FirstFailureFileState{}, err
	}
	defer func() { _ = secure.Close() }()
	return loadFirstFailureDirectory(secure, runID)
}

func loadFirstFailureDirectory(
	directory *secureDirectory, runID string,
) (FirstFailureFileState, error) {
	file, err := directory.Open("first-failure.json", os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return FirstFailureFileState{}, nil
	}
	if err != nil {
		return FirstFailureFileState{}, fmt.Errorf("open first failure: %w", err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maximumReceiptLine+1))
	closeErr := file.Close()
	if readErr != nil {
		return FirstFailureFileState{}, fmt.Errorf("read first failure: %w", readErr)
	}
	if closeErr != nil {
		return FirstFailureFileState{}, fmt.Errorf("close first failure: %w", closeErr)
	}
	if len(raw) > maximumReceiptLine {
		return FirstFailureFileState{}, fmt.Errorf(
			"first failure file is %d bytes, above %d",
			len(raw), maximumReceiptLine,
		)
	}
	var failure FirstFailure
	if err := decodeExactJSONObject(
		raw, firstFailureJSONMembers, &failure,
	); err != nil {
		return FirstFailureFileState{}, fmt.Errorf(
			"decode first failure: %w", err,
		)
	}
	if failure.Schema != firstFailureSchema {
		return FirstFailureFileState{}, fmt.Errorf(
			"first failure schema is %q, expected %q",
			failure.Schema, firstFailureSchema,
		)
	}
	if failure.RunID != runID {
		return FirstFailureFileState{}, fmt.Errorf(
			"first failure belongs to run %q, expected %q",
			failure.RunID, runID,
		)
	}
	if failure.Sequence < 1 || !failure.Outcome.valid() ||
		(failure.Outcome == OutcomeSucceeded &&
			len(failure.ExceededBounds) == 0) || !failure.Readiness.valid() ||
		failure.ElapsedNanos < 0 ||
		!digestPattern.MatchString(failure.ReceiptDigest) {
		return FirstFailureFileState{}, errors.New(
			"first failure carries invalid sequence/outcome/readiness/elapsed/digest semantics",
		)
	}
	if _, err := time.Parse(time.RFC3339Nano, failure.WallAt); err != nil {
		return FirstFailureFileState{}, fmt.Errorf(
			"first failure wall_at is invalid: %w", err,
		)
	}
	return FirstFailureFileState{Present: true, Failure: failure}, nil
}

func validateFirstFailure(
	replay ReceiptReplayState, file FirstFailureFileState,
) error {
	if replay.HasFailure != file.Present {
		return fmt.Errorf(
			"first-failure state disagrees: receipt replay has_failure=%t, "+
				"file_present=%t", replay.HasFailure, file.Present,
		)
	}
	if !replay.HasFailure {
		return nil
	}
	want := replay.FirstFailure
	got := file.Failure
	if got.Sequence != want.Sequence ||
		got.Outcome != want.Outcome ||
		got.ExitStatus != want.ExitStatus ||
		got.Readiness != want.Readiness ||
		got.WallAt != want.WallAt ||
		got.ElapsedNanos != want.ElapsedNanos ||
		got.ReceiptDigest != want.ReceiptDigest ||
		!bytes.Equal(got.StdoutTail, want.StdoutTail) ||
		!bytes.Equal(got.StderrTail, want.StderrTail) ||
		!equalExceededBounds(got.ExceededBounds, want.ExceededBounds) {
		return fmt.Errorf(
			"first-failure file does not reproduce receipt %d (%s)",
			want.Sequence, want.ReceiptDigest,
		)
	}
	return nil
}

func equalExceededBounds(a, b []ExceededBound) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

// RecordFirstFailure writes the first failure exactly once.
//
// O_EXCL is the mechanism, not a check-then-write. A "does the file exist"
// test followed by a write has a window in which a second failure arriving
// close behind the first overwrites it, and the whole point of this file is
// that the FIRST failure is the diagnostic one: by cycle four hundred the host
// is in whatever state failure three hundred and ninety-nine left it, and the
// tail of that cycle explains nothing.
//
// Later failures are not lost -- every one of them is in the receipt log. Only
// this singled-out copy is immutable.
func RecordFirstFailure(directory string, failure FirstFailure) error {
	if err := ensurePrivateDirectory(directory); err != nil {
		return err
	}
	secure, err := openSecureDirectory(directory)
	if err != nil {
		return err
	}
	defer func() { _ = secure.Close() }()
	return recordFirstFailureDirectory(secure, failure)
}

func recordFirstFailureDirectory(
	directory *secureDirectory, failure FirstFailure,
) error {
	failure.Schema = firstFailureSchema
	if failure.ExceededBounds == nil {
		failure.ExceededBounds = []ExceededBound{}
	}
	encoded, err := json.MarshalIndent(failure, "", "  ")
	if err != nil {
		return fmt.Errorf("encode first failure: %w", err)
	}
	file, err := directory.Open(
		"first-failure.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600,
	)
	if errors.Is(err, os.ErrExist) {
		return errFirstFailureAlreadyRecorded
	}
	if err != nil {
		return fmt.Errorf("create first failure record: %w", err)
	}
	if err := writeAllOperation(file, append(encoded, '\n')); err != nil {
		_ = file.Close()
		return fmt.Errorf("write first failure record: %w", err)
	}
	if err := syncFileOperation(file); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync first failure record: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close first failure record: %w", err)
	}
	if err := directory.Sync(); err != nil {
		return err
	}
	return directory.VerifyPath()
}

func rfc3339(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}
