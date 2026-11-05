package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	checkpointSchema = "winn-phase1-soak-checkpoint/v1"
	// checkpointMACDomain separates this MAC from every other use of the
	// same key. There is only one use today; the domain is present so that
	// adding a second one later cannot produce a value that verifies as a
	// checkpoint.
	checkpointMACDomain = "winn-phase1-soak-controller/checkpoint/v1\x00"
	resumeKeyBytes      = 32
)

// Checkpoint is the resumable state of one soak.
//
// AccumulatedElapsed is the field that matters most. It is monotonic time this
// soak has ACTUALLY SERVED, carried across process restarts. A resumed run adds
// its own fresh monotonic segment to this value; it never restarts from zero.
// That is the whole of the no-duration-reset guarantee, and it is a property of
// this one field being read and added to rather than of any check performed
// afterwards.
type Checkpoint struct {
	Schema           string     `json:"schema"`
	RunID            string     `json:"run_id"`
	InstanceNonce    string     `json:"instance_nonce"`
	PredecessorNonce string     `json:"predecessor_nonce"`
	Provenance       Provenance `json:"provenance"`

	TotalDurationNanos      int64 `json:"total_duration_nanos"`
	AccumulatedElapsedNanos int64 `json:"accumulated_elapsed_nanos"`

	CyclesAttempted int64 `json:"cycles_attempted"`
	CyclesSucceeded int64 `json:"cycles_succeeded"`
	CyclesFailed    int64 `json:"cycles_failed"`
	CyclesTimedOut  int64 `json:"cycles_timed_out"`
	CyclesCancelled int64 `json:"cycles_cancelled"`

	LastReceiptDigest    string `json:"last_receipt_digest"`
	FirstFailureRecorded bool   `json:"first_failure_recorded"`
	// Terminal is latched only after the requested monotonic duration has
	// been served and the final checkpoint is durable. A terminal run ID may
	// never be resumed.
	Terminal       bool           `json:"terminal"`
	TerminalReason TerminalReason `json:"terminal_reason"`

	// WallAtStart and WallAtCheckpoint are RFC3339 with nanoseconds. They
	// are NOT used to compute elapsed time. WallAtCheckpoint exists so a
	// resume can refuse when the operator's clock has moved backwards,
	// which is a signal that something is wrong with the host rather than
	// a quantity to subtract.
	WallAtStart      string `json:"wall_at_start"`
	WallAtCheckpoint string `json:"wall_at_checkpoint"`

	ResumeCount int64 `json:"resume_count"`
}

// conservationError reports a checkpoint whose counters do not add up.
//
// A checkpoint that fails this is refused rather than repaired. The counters
// are the only record of how many cycles ran; a controller that "fixed" them
// would be choosing what the evidence says.
func (c Checkpoint) conservationError() error {
	for _, count := range []struct {
		name  string
		value int64
	}{
		{"attempted", c.CyclesAttempted},
		{"succeeded", c.CyclesSucceeded},
		{"failed", c.CyclesFailed},
		{"timed_out", c.CyclesTimedOut},
		{"cancelled", c.CyclesCancelled},
		{"resume_count", c.ResumeCount},
	} {
		if count.value < 0 {
			return fmt.Errorf(
				"checkpoint %s count is negative", count.name,
			)
		}
	}
	sum := c.CyclesSucceeded + c.CyclesFailed +
		c.CyclesTimedOut + c.CyclesCancelled
	if sum != c.CyclesAttempted {
		return fmt.Errorf(
			"checkpoint conservation failed: %d attempted but "+
				"%d succeeded + %d failed + %d timed out + %d cancelled = %d",
			c.CyclesAttempted, c.CyclesSucceeded, c.CyclesFailed,
			c.CyclesTimedOut, c.CyclesCancelled, sum,
		)
	}
	if c.AccumulatedElapsedNanos < 0 {
		return errors.New("checkpoint accumulated elapsed time is negative")
	}
	if c.TotalDurationNanos <= 0 {
		return errors.New("checkpoint total duration is not positive")
	}
	if c.CyclesAttempted > 0 && !digestPattern.MatchString(c.LastReceiptDigest) {
		return errors.New("checkpoint last receipt digest is malformed")
	}
	if c.CyclesAttempted == 0 && c.LastReceiptDigest != genesisDigest {
		return errors.New(
			"zero-cycle checkpoint must name the genesis receipt digest",
		)
	}
	if c.FirstFailureRecorded && c.CyclesAttempted == 0 {
		return errors.New(
			"zero-cycle checkpoint cannot claim a first failure",
		)
	}
	if c.Terminal {
		if c.TerminalReason != ReasonDurationServed {
			return fmt.Errorf(
				"terminal checkpoint reason is %q, expected %q",
				c.TerminalReason, ReasonDurationServed,
			)
		}
		if c.AccumulatedElapsedNanos < c.TotalDurationNanos {
			return errors.New(
				"terminal checkpoint claims duration served before its total",
			)
		}
	} else if c.TerminalReason != "" {
		return errors.New("non-terminal checkpoint carries a terminal reason")
	}
	return nil
}

type checkpointEnvelope struct {
	Schema string `json:"schema"`
	// Body is kept as raw bytes so verification re-hashes exactly what was
	// written. Re-marshalling a decoded struct would hash this program's
	// current encoding of the value rather than the bytes on disk, and any
	// future field reordering would then silently invalidate every stored
	// checkpoint -- or worse, validate a modified one.
	Body           json.RawMessage `json:"body"`
	ContentAddress string          `json:"content_address"`
	MAC            string          `json:"mac"`
}

var checkpointEnvelopeJSONMembers = []string{
	"schema", "body", "content_address", "mac",
}

var checkpointJSONMembers = []string{
	"schema", "run_id", "instance_nonce", "predecessor_nonce", "provenance",
	"total_duration_nanos", "accumulated_elapsed_nanos", "cycles_attempted",
	"cycles_succeeded", "cycles_failed", "cycles_timed_out",
	"cycles_cancelled", "last_receipt_digest", "first_failure_recorded",
	"terminal", "terminal_reason", "wall_at_start", "wall_at_checkpoint",
	"resume_count",
}

// CheckpointStore reads and writes the authenticated checkpoint.
//
// What the MAC establishes, exactly: that this file was written by something
// holding the run-local resume key, which lives at 0600 in the controller's own
// state directory. It stops an unprivileged process on the host from handing
// this controller a forged resume state.
//
// What it does NOT establish: anything at all against the identity that runs
// the controller. On a host where the runner executes as root, root reads the
// key. This is deliberately not an evidence-signing key, it is not a finalizer
// seed, and no artifact it touches is promotable. The custody separation this
// project enforces -- that no signing or finalizing secret exists on the
// producing host -- is unaffected by it, and preflightCustody refuses to start
// if any such secret is found.
type CheckpointStore struct {
	path      string
	base      string
	directory *secureDirectory
	key       []byte
}

// OpenCheckpointStore loads or creates the run-local resume key.
func OpenCheckpointStore(stateRoot string) (*CheckpointStore, error) {
	if err := ensurePrivateDirectory(stateRoot); err != nil {
		return nil, err
	}
	directory, err := openSecureDirectory(stateRoot)
	if err != nil {
		return nil, err
	}
	failed := func(err error) (*CheckpointStore, error) {
		_ = directory.Close()
		return nil, err
	}
	keyPath := filepath.Join(stateRoot, "resume.key")
	// #nosec G304 -- stateRoot is a configuration value, base name constant.
	var key []byte
	keyFile, err := directory.Open("resume.key", os.O_RDONLY, 0)
	switch {
	case err == nil:
		key, err = io.ReadAll(io.LimitReader(keyFile, resumeKeyBytes+1))
		closeErr := keyFile.Close()
		if err != nil {
			return failed(fmt.Errorf("read resume key: %w", err))
		}
		if closeErr != nil {
			return failed(fmt.Errorf("close resume key: %w", closeErr))
		}
		if len(key) != resumeKeyBytes {
			return failed(fmt.Errorf(
				"resume key %s is %d bytes, expected %d",
				keyPath, len(key), resumeKeyBytes,
			))
		}
		info, statErr := os.Lstat(keyPath)
		if statErr != nil {
			return failed(fmt.Errorf("stat resume key: %w", statErr))
		}
		if info.Mode().Perm()&0o077 != 0 {
			return failed(fmt.Errorf(
				"resume key %s is readable beyond its owner (mode %04o)",
				keyPath, info.Mode().Perm(),
			))
		}
	case errors.Is(err, os.ErrNotExist):
		key = make([]byte, resumeKeyBytes)
		if _, err := rand.Read(key); err != nil {
			return failed(fmt.Errorf("mint resume key: %w", err))
		}
		if err := atomicWriteDirectory(
			directory, "resume.key", key, 0o600,
		); err != nil {
			return failed(err)
		}
	default:
		return failed(fmt.Errorf("read resume key: %w", err))
	}
	return &CheckpointStore{
		path: filepath.Join(stateRoot, "checkpoint.json"), base: "checkpoint.json",
		directory: directory, key: key,
	}, nil
}

func (s *CheckpointStore) Close() error {
	if s == nil || s.directory == nil {
		return nil
	}
	directory := s.directory
	s.directory = nil
	return directory.Close()
}

func (s *CheckpointStore) authenticator(contentAddress string) []byte {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(checkpointMACDomain))
	mac.Write([]byte(contentAddress))
	return mac.Sum(nil)
}

// Save writes the checkpoint atomically.
func (s *CheckpointStore) Save(checkpoint Checkpoint) (string, error) {
	if err := s.directory.VerifyPath(); err != nil {
		return "", fmt.Errorf("checkpoint directory continuity: %w", err)
	}
	checkpoint.Schema = checkpointSchema
	if err := checkpoint.conservationError(); err != nil {
		return "", fmt.Errorf("refusing to save an inconsistent checkpoint: %w", err)
	}
	body, err := json.Marshal(checkpoint)
	if err != nil {
		return "", fmt.Errorf("encode checkpoint: %w", err)
	}
	sum := sha256.Sum256(body)
	address := hex.EncodeToString(sum[:])
	envelope := checkpointEnvelope{
		Schema:         checkpointSchema,
		Body:           body,
		ContentAddress: address,
		MAC:            hex.EncodeToString(s.authenticator(address)),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("encode checkpoint envelope: %w", err)
	}
	if err := atomicWriteDirectory(s.directory, s.base, encoded, 0o600); err != nil {
		return "", err
	}
	return address, nil
}

var (
	errNoCheckpoint          = errors.New("no checkpoint exists")
	errCheckpointUnauthentic = errors.New(
		"checkpoint failed authentication; refusing to resume from it",
	)
	errCheckpointMisaddressed = errors.New(
		"checkpoint content address does not match its body",
	)
)

// Load returns the stored checkpoint, or an error.
//
// Every failure below is terminal. There is no repair path, no fallback to an
// older copy, and no "resume anyway" flag: a soak that cannot prove where it
// left off has to start a new run under a new run ID, because the alternative
// is a seven-day claim assembled from a state nobody can vouch for.
func (s *CheckpointStore) Load() (Checkpoint, string, error) {
	if err := s.directory.VerifyPath(); err != nil {
		return Checkpoint{}, "", fmt.Errorf("checkpoint directory continuity: %w", err)
	}
	file, err := s.directory.Open(s.base, os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return Checkpoint{}, "", errNoCheckpoint
	}
	if err != nil {
		return Checkpoint{}, "", fmt.Errorf("open checkpoint: %w", err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maximumReceiptLine+1))
	closeErr := file.Close()
	if readErr != nil {
		return Checkpoint{}, "", fmt.Errorf("read checkpoint: %w", readErr)
	}
	if closeErr != nil {
		return Checkpoint{}, "", fmt.Errorf("close checkpoint: %w", closeErr)
	}
	if len(raw) > maximumReceiptLine {
		return Checkpoint{}, "", errors.New("checkpoint exceeds bounded size")
	}
	var envelope checkpointEnvelope
	if err := decodeExactJSONObject(
		raw, checkpointEnvelopeJSONMembers, &envelope,
	); err != nil {
		return Checkpoint{}, "", fmt.Errorf("decode checkpoint envelope: %w", err)
	}
	if envelope.Schema != checkpointSchema {
		return Checkpoint{}, "", fmt.Errorf(
			"checkpoint schema is %q, expected %q",
			envelope.Schema, checkpointSchema,
		)
	}
	sum := sha256.Sum256(envelope.Body)
	address := hex.EncodeToString(sum[:])
	if address != envelope.ContentAddress {
		return Checkpoint{}, "", fmt.Errorf(
			"%w: body hashes to %s, envelope claims %s",
			errCheckpointMisaddressed, address, envelope.ContentAddress,
		)
	}
	presented, err := hex.DecodeString(envelope.MAC)
	if err != nil {
		return Checkpoint{}, "", fmt.Errorf("%w: malformed MAC", errCheckpointUnauthentic)
	}
	// The content address is verified BEFORE the MAC is checked, and the MAC
	// is computed over the address rather than over the body. Both orderings
	// matter: authenticating the body directly would let a mismatched
	// address through, and authenticating an unverified address would let a
	// modified body through under a stale address.
	if !hmac.Equal(presented, s.authenticator(address)) {
		return Checkpoint{}, "", errCheckpointUnauthentic
	}
	var checkpoint Checkpoint
	if err := decodeExactJSONObject(
		envelope.Body, checkpointJSONMembers, &checkpoint,
	); err != nil {
		return Checkpoint{}, "", fmt.Errorf("decode checkpoint body: %w", err)
	}
	if checkpoint.Schema != checkpointSchema {
		return Checkpoint{}, "", fmt.Errorf(
			"checkpoint body schema is %q, expected %q",
			checkpoint.Schema, checkpointSchema,
		)
	}
	if err := checkpoint.conservationError(); err != nil {
		return Checkpoint{}, "", err
	}
	if !noncePattern.MatchString(checkpoint.InstanceNonce) ||
		(checkpoint.PredecessorNonce != "" &&
			!noncePattern.MatchString(checkpoint.PredecessorNonce)) {
		return Checkpoint{}, "", errors.New("checkpoint nonce lineage is malformed")
	}
	for _, wall := range []struct {
		name, value string
	}{
		{"wall_at_start", checkpoint.WallAtStart},
		{"wall_at_checkpoint", checkpoint.WallAtCheckpoint},
	} {
		if _, err := time.Parse(time.RFC3339Nano, wall.value); err != nil {
			return Checkpoint{}, "", fmt.Errorf(
				"checkpoint %s is not RFC3339Nano: %w", wall.name, err,
			)
		}
	}
	return checkpoint, address, nil
}

// resumeRefusal names why a resume was refused, for the receipt.
type resumeRefusal struct {
	Reason string
	Detail string
}

// evaluateResume decides whether a stored checkpoint may be resumed from.
//
// It is a pure function of the checkpoint, the freshly gathered provenance, the
// current wall clock and the frozen configuration. Being pure is what lets the
// clock-rollback and source-drift tests drive it directly instead of staging a
// filesystem and hoping the right branch was reached.
func evaluateResume(
	stored Checkpoint,
	current Provenance,
	wallNow time.Time,
	configuredTotal time.Duration,
	configuredRunID string,
) *resumeRefusal {
	if stored.RunID != configuredRunID {
		return &resumeRefusal{
			Reason: "run_id_mismatch",
			Detail: fmt.Sprintf(
				"checkpoint belongs to run %q, this invocation is run %q",
				stored.RunID, configuredRunID,
			),
		}
	}
	if stored.TotalDurationNanos != int64(configuredTotal) {
		// Refusing this is the second half of the no-reset guarantee. A
		// resume that accepted a different total could serve 168h of
		// accumulated time against a freshly declared 336h total, or the
		// reverse, and the summary would report a duration nobody ran.
		return &resumeRefusal{
			Reason: "duration_changed",
			Detail: fmt.Sprintf(
				"checkpoint froze a total of %s, this invocation declares %s",
				time.Duration(stored.TotalDurationNanos), configuredTotal,
			),
		}
	}
	stampedAt, err := time.Parse(time.RFC3339Nano, stored.WallAtCheckpoint)
	if err != nil {
		return &resumeRefusal{
			Reason: "unparsable_checkpoint_time",
			Detail: fmt.Sprintf(
				"checkpoint wall time %q is not RFC3339: %v",
				stored.WallAtCheckpoint, err,
			),
		}
	}
	if wallNow.Before(stampedAt) {
		return &resumeRefusal{
			Reason: "clock_rollback",
			Detail: fmt.Sprintf(
				"%v: the host clock reads %s, which is %s before the "+
					"checkpoint written at %s",
				errClockRollback,
				wallNow.UTC().Format(time.RFC3339Nano),
				stampedAt.Sub(wallNow),
				stampedAt.UTC().Format(time.RFC3339Nano),
			),
		}
	}
	if kind, detail := detectDrift(stored.Provenance, current); kind != driftNone {
		return &resumeRefusal{
			Reason: string(kind),
			Detail: detail,
		}
	}
	return nil
}

// ResumePlan is the decision to continue an interrupted soak.
type ResumePlan struct {
	// Carried is the monotonic time the soak had already served. The
	// resumed run ADDS its own elapsed time to this. It is never zeroed for
	// a resume, and evaluateResume has already refused any change to the
	// total duration it is measured against.
	Carried     time.Duration
	ResumeCount int64
	WallAtStart string
}

// planResume turns a stored checkpoint and a replayed receipt log into the
// state a resumed controller starts from, or refuses.
//
// It is a pure function so the fail-closed conditions can be driven directly.
// Reaching them through a staged filesystem would mean a test that "passes"
// whenever any error occurs, including one from the staging itself -- which is
// how a fail-closed test comes to pass without ever reaching the branch it
// names.
func planResume(
	stored Checkpoint,
	haveCheckpoint bool,
	replay ReceiptReplayState,
	firstFailure FirstFailureFileState,
	current Provenance,
	wallNow time.Time,
	cfg Config,
) (ResumePlan, error) {
	if err := validateFirstFailure(replay, firstFailure); err != nil {
		return ResumePlan{}, err
	}
	if !haveCheckpoint {
		if replay.Count != 0 {
			return ResumePlan{}, fmt.Errorf(
				"the receipt log already holds %d cycles but no checkpoint "+
					"exists; refusing to append to a run whose state cannot "+
					"be authenticated", replay.Count,
			)
		}
		return ResumePlan{
			Carried:     0,
			ResumeCount: 0,
			WallAtStart: rfc3339(wallNow),
		}, nil
	}
	if refusal := evaluateResume(
		stored, current, wallNow, cfg.Duration, cfg.RunID,
	); refusal != nil {
		return ResumePlan{}, fmt.Errorf(
			"refusing to resume (%s): %s", refusal.Reason, refusal.Detail,
		)
	}
	if stored.CyclesAttempted != replay.Count {
		return ResumePlan{}, fmt.Errorf(
			"the checkpoint records %d cycles but the receipt log holds %d; "+
				"the two disagree about what happened and neither may be "+
				"preferred silently",
			stored.CyclesAttempted, replay.Count,
		)
	}
	if replay.Count > 0 &&
		(stored.InstanceNonce != replay.LastInstanceNonce ||
			stored.PredecessorNonce != replay.LastPredecessorNonce ||
			stored.ResumeCount != replay.LastResumeCount) {
		return ResumePlan{}, errors.New(
			"checkpoint nonce/resume lineage disagrees with the receipt head",
		)
	}
	if stored.LastReceiptDigest != replay.Head {
		return ResumePlan{}, fmt.Errorf(
			"checkpoint receipt head is %s, replayed head is %s",
			stored.LastReceiptDigest, replay.Head,
		)
	}
	storedTotals := receiptTotals{
		Attempted: stored.CyclesAttempted,
		Succeeded: stored.CyclesSucceeded,
		Failed:    stored.CyclesFailed,
		TimedOut:  stored.CyclesTimedOut,
		Cancelled: stored.CyclesCancelled,
	}
	if storedTotals != replay.Totals {
		return ResumePlan{}, fmt.Errorf(
			"checkpoint outcome totals disagree with replayed receipt totals",
		)
	}
	if stored.FirstFailureRecorded != replay.HasFailure {
		return ResumePlan{}, fmt.Errorf(
			"checkpoint first-failure flag is %t, replay has_failure=%t",
			stored.FirstFailureRecorded, replay.HasFailure,
		)
	}
	if stored.Terminal {
		return ResumePlan{}, fmt.Errorf(
			"run %q is terminal (%s); refusing to resume a completed run ID",
			stored.RunID, stored.TerminalReason,
		)
	}
	return ResumePlan{
		Carried:     time.Duration(stored.AccumulatedElapsedNanos),
		ResumeCount: stored.ResumeCount + 1,
		WallAtStart: stored.WallAtStart,
	}, nil
}
