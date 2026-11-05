// Package measurement stores tamper-evident, append-only Winn v3 experiment
// results. Both successes and failures are retained so score calculations
// cannot silently discard inconvenient outcomes.
package measurement

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/securefile"
)

const (
	Format         = "winn-measurement-hmac-sha256/v1"
	AnchorFormat   = "winn-measurement-anchor-hmac-sha256/v1"
	recordDomain   = "winn-measurement-record/v1\x00"
	anchorDomain   = "winn-measurement-anchor/v1\x00"
	maxRecordBytes = 256 << 10
	maxAnchorBytes = 4096
	maxCandidates  = connectivity.MaxCandidates
)

type ReadinessClass string

const (
	ReadinessWarm ReadinessClass = "warm"
	ReadinessCold ReadinessClass = "cold"
)

type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
)

type NetworkProfile struct {
	Interface      string  `json:"interface"`
	IPFamily       string  `json:"ip_family"`
	NAT            string  `json:"nat,omitempty"`
	Impairment     string  `json:"impairment,omitempty"`
	RTTMillis      float64 `json:"rtt_millis"`
	LossFraction   float64 `json:"loss_fraction"`
	CapacityMbps   float64 `json:"capacity_mbps,omitempty"`
	ClientRegion   string  `json:"client_region,omitempty"`
	ServerRegion   string  `json:"server_region,omitempty"`
	ServerProvider string  `json:"server_provider,omitempty"`
}

// Timeline values are microseconds elapsed from the start of the attempt.
// DNS and canary may complete before the AWG handshake due candidate-isolated
// pipelining, but CommitMicros must be the final successful predicate.
type Timeline struct {
	DialMicros          int64 `json:"dial_micros,omitempty"`
	HandshakeMicros     int64 `json:"handshake_micros,omitempty"`
	BidirectionalMicros int64 `json:"bidirectional_micros,omitempty"`
	DNSMicros           int64 `json:"dns_micros,omitempty"`
	CanaryMicros        int64 `json:"canary_micros,omitempty"`
	CommitMicros        int64 `json:"commit_micros,omitempty"`
	OutcomeMicros       int64 `json:"outcome_micros"`
}

type Metrics struct {
	ThroughputMbps      float64 `json:"throughput_mbps,omitempty"`
	BaselineMbps        float64 `json:"baseline_mbps,omitempty"`
	CPUPercent          float64 `json:"cpu_percent,omitempty"`
	PeakMemoryBytes     uint64  `json:"peak_memory_bytes,omitempty"`
	EnergyMilliwattHour float64 `json:"energy_milliwatt_hour,omitempty"`
	CoverBytes          uint64  `json:"cover_bytes,omitempty"`
	UserBytes           uint64  `json:"user_bytes,omitempty"`
	ReconnectMicros     int64   `json:"reconnect_micros,omitempty"`
}

type Attempt struct {
	AttemptID         string                   `json:"attempt_id"`
	SourceDigest      string                   `json:"source_digest"`
	ArtifactDigest    string                   `json:"artifact_digest"`
	ProtocolVersion   string                   `json:"protocol_version"`
	ManifestDigest    string                   `json:"manifest_digest"`
	TrustFingerprint  string                   `json:"trust_fingerprint"`
	Platform          string                   `json:"platform"`
	OSVersion         string                   `json:"os_version"`
	Device            string                   `json:"device"`
	Mode              connectivity.Mode        `json:"mode"`
	Readiness         ReadinessClass           `json:"readiness"`
	CandidateIDs      []string                 `json:"candidate_ids"`
	SelectedCandidate string                   `json:"selected_candidate,omitempty"`
	Network           NetworkProfile           `json:"network"`
	StartedAt         string                   `json:"started_at"`
	FinishedAt        string                   `json:"finished_at"`
	Outcome           Outcome                  `json:"outcome"`
	Failure           connectivity.FailureCode `json:"failure_code,omitempty"`
	Timeline          Timeline                 `json:"timeline"`
	Metrics           Metrics                  `json:"metrics"`
}

type entry struct {
	Format         string  `json:"format"`
	Sequence       uint64  `json:"sequence"`
	RecordedAt     string  `json:"recorded_at"`
	Attempt        Attempt `json:"attempt"`
	PreviousMAC    string  `json:"previous_mac"`
	Authentication string  `json:"authentication"`
}

type unsignedEntry struct {
	Format      string  `json:"format"`
	Sequence    uint64  `json:"sequence"`
	RecordedAt  string  `json:"recorded_at"`
	Attempt     Attempt `json:"attempt"`
	PreviousMAC string  `json:"previous_mac"`
}

type anchor struct {
	Format         string `json:"format"`
	Sequence       uint64 `json:"sequence"`
	LastMAC        string `json:"last_mac"`
	Authentication string `json:"authentication"`
}

type unsignedAnchor struct {
	Format   string `json:"format"`
	Sequence uint64 `json:"sequence"`
	LastMAC  string `json:"last_mac"`
}

type Log struct {
	mu          sync.Mutex
	file        *os.File
	lock        *fileLock
	anchorPath  string
	key         [32]byte
	sequence    uint64
	lastMAC     [32]byte
	previousMAC [32]byte
	attempts    []Attempt
	attemptIDs  map[string]struct{}
	now         func() time.Time
	closed      bool
	poisoned    error
}

type Summary struct {
	Total                int
	Successes            int
	Failures             int
	OutcomeP50           time.Duration
	OutcomeP95           time.Duration
	OutcomeP99           time.Duration
	SuccessfulOutcomeP99 time.Duration
	FailureCounts        map[connectivity.FailureCode]int
}

// Create initializes a new evidence log and its separately authenticated
// high-water anchor. It never opens or truncates an existing target.
func Create(path, keyPath string) (*Log, error) {
	return open(path, keyPath, true, false)
}

// Open requires an existing evidence log and matching high-water anchor. It
// never creates either file.
func Open(path, keyPath string) (*Log, error) {
	return open(path, keyPath, false, true)
}

func open(
	path string,
	keyPath string,
	create bool,
	reconcileAnchor bool,
) (*Log, error) {
	keyData, err := securefile.ReadPrivateLimited(keyPath, 1024)
	if err != nil {
		return nil, fmt.Errorf("read measurement key: %w", err)
	}
	defer clear(keyData)
	if len(keyData) != sha256.Size {
		return nil, fmt.Errorf(
			"measurement key length is %d, want %d",
			len(keyData), sha256.Size,
		)
	}
	if err := securefile.EnsurePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if !create {
		preflight, preflightErr := os.Lstat(path)
		if preflightErr != nil {
			return nil, preflightErr
		}
		if !preflight.Mode().IsRegular() {
			return nil, errors.New(
				"measurement log path is not a regular file",
			)
		}
	}
	lock, err := acquireFileLock(path + ".lock")
	if err != nil {
		return nil, fmt.Errorf("lock measurement log: %w", err)
	}
	fail := func(current error) (*Log, error) {
		_ = lock.release()
		return nil, current
	}
	existing, err := os.Lstat(path)
	if create {
		if err == nil {
			return fail(errors.New("measurement log already exists"))
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fail(err)
		}
	} else {
		if err != nil {
			return fail(err)
		}
		if !existing.Mode().IsRegular() {
			return fail(errors.New(
				"measurement log path is not a regular file",
			))
		}
	}
	if err == nil && !existing.Mode().IsRegular() {
		return fail(errors.New(
			"measurement log path is not a regular file",
		))
	}
	flags := os.O_RDWR | os.O_APPEND
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	// #nosec G304 -- the administrator-selected path has a validated private
	// parent and any existing target was checked immediately above.
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return fail(fmt.Errorf("open measurement log: %w", err))
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() ||
		(!create && existing != nil && !os.SameFile(existing, opened)) {
		_ = file.Close()
		return fail(errors.New(
			"measurement log target changed or is not regular",
		))
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fail(fmt.Errorf("secure measurement log: %w", err))
	}
	log := &Log{
		file:       file,
		lock:       lock,
		anchorPath: path + ".anchor",
		attemptIDs: make(map[string]struct{}),
		now:        time.Now,
	}
	copy(log.key[:], keyData)
	if create {
		if _, anchorErr := os.Lstat(log.anchorPath); anchorErr == nil {
			_ = file.Close()
			_ = lock.release()
			clear(log.key[:])
			return nil, errors.New(
				"measurement anchor already exists",
			)
		} else if !errors.Is(anchorErr, os.ErrNotExist) {
			_ = file.Close()
			_ = lock.release()
			clear(log.key[:])
			return nil, anchorErr
		}
		if err := log.writeAnchor(0, [sha256.Size]byte{}); err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			_ = lock.release()
			clear(log.key[:])
			return nil, err
		}
		return log, nil
	}
	if err := log.verifyExisting(); err != nil {
		_ = file.Close()
		_ = lock.release()
		clear(log.key[:])
		return nil, err
	}
	if err := log.verifyAnchor(reconcileAnchor); err != nil {
		_ = file.Close()
		_ = lock.release()
		clear(log.key[:])
		return nil, err
	}
	return log, nil
}

func Verify(path, keyPath string) error {
	log, err := open(path, keyPath, false, false)
	if err != nil {
		return err
	}
	return log.Close()
}

func (log *Log) Append(attempt Attempt) error {
	log.mu.Lock()
	defer log.mu.Unlock()
	if log.closed {
		return errors.New("measurement log is closed")
	}
	if log.poisoned != nil {
		return fmt.Errorf(
			"measurement log is poisoned after ambiguous write: %w",
			log.poisoned,
		)
	}
	if err := ValidateAttempt(attempt); err != nil {
		return err
	}
	if _, duplicate := log.attemptIDs[attempt.AttemptID]; duplicate {
		return errors.New("measurement attempt ID is duplicated")
	}
	next := entry{
		Format:      Format,
		Sequence:    log.sequence + 1,
		RecordedAt:  log.now().UTC().Format(time.RFC3339Nano),
		Attempt:     cloneAttempt(attempt),
		PreviousMAC: hex.EncodeToString(log.lastMAC[:]),
	}
	mac, err := log.authenticate(next)
	if err != nil {
		return err
	}
	next.Authentication = hex.EncodeToString(mac[:])
	encoded, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if len(encoded)+1 > maxRecordBytes {
		return errors.New("measurement record exceeds size limit")
	}
	encoded = append(encoded, '\n')
	written, err := log.file.Write(encoded)
	if err != nil {
		return log.poison(
			fmt.Errorf("append measurement record: %w", err),
		)
	}
	if written != len(encoded) {
		return log.poison(io.ErrShortWrite)
	}
	if err := log.file.Sync(); err != nil {
		return log.poison(
			fmt.Errorf("sync measurement record: %w", err),
		)
	}
	if err := log.writeAnchor(next.Sequence, mac); err != nil {
		return log.poison(err)
	}
	log.sequence = next.Sequence
	log.lastMAC = mac
	log.attempts = append(log.attempts, cloneAttempt(attempt))
	log.attemptIDs[attempt.AttemptID] = struct{}{}
	return nil
}

func (log *Log) Attempts() []Attempt {
	log.mu.Lock()
	defer log.mu.Unlock()
	attempts := make([]Attempt, len(log.attempts))
	for index, attempt := range log.attempts {
		attempts[index] = cloneAttempt(attempt)
	}
	return attempts
}

func (log *Log) Summary() Summary {
	return Summarize(log.Attempts())
}

func (log *Log) Close() error {
	log.mu.Lock()
	defer log.mu.Unlock()
	if log.closed {
		return nil
	}
	log.closed = true
	clear(log.key[:])
	fileErr := log.file.Close()
	var lockErr error
	if log.lock != nil {
		lockErr = log.lock.release()
		log.lock = nil
	}
	return errors.Join(fileErr, lockErr)
}

func ValidateAttempt(attempt Attempt) error {
	if !lowerHex(attempt.AttemptID, 32) {
		return errors.New("measurement attempt ID must be 32 lowercase hex characters")
	}
	for name, digest := range map[string]string{
		"source":            attempt.SourceDigest,
		"artifact":          attempt.ArtifactDigest,
		"manifest":          attempt.ManifestDigest,
		"trust fingerprint": attempt.TrustFingerprint,
	} {
		if !lowerHex(digest, 64) {
			return fmt.Errorf("%s digest must be 64 lowercase hex characters", name)
		}
	}
	if attempt.ProtocolVersion != connectivity.Version {
		return fmt.Errorf("protocol version must be %q", connectivity.Version)
	}
	switch attempt.Platform {
	case "linux", "macos", "android", "ios", "windows":
	default:
		return errors.New("measurement platform is unsupported")
	}
	if attempt.OSVersion == "" || len(attempt.OSVersion) > 128 ||
		attempt.Device == "" || len(attempt.Device) > 128 {
		return errors.New("measurement OS version and device are required")
	}
	if !connectivity.ValidMode(attempt.Mode) {
		return errors.New("measurement mode is invalid")
	}
	if attempt.Readiness != ReadinessWarm && attempt.Readiness != ReadinessCold {
		return errors.New("measurement readiness class is invalid")
	}
	if err := validateCandidates(attempt); err != nil {
		return err
	}
	started, err := parseUTC(attempt.StartedAt)
	if err != nil {
		return fmt.Errorf("measurement started_at: %w", err)
	}
	finished, err := parseUTC(attempt.FinishedAt)
	if err != nil {
		return fmt.Errorf("measurement finished_at: %w", err)
	}
	if finished.Before(started) || finished.Sub(started) > 24*time.Hour {
		return errors.New("measurement attempt lifetime is invalid")
	}
	elapsedMicros := finished.Sub(started).Microseconds()
	if attempt.Timeline.OutcomeMicros < 0 {
		return errors.New("measurement outcome timeline is invalid")
	}
	timelineDelta := attempt.Timeline.OutcomeMicros - elapsedMicros
	if timelineDelta < 0 {
		timelineDelta = -timelineDelta
	}
	if timelineDelta > 1000 {
		return errors.New("measurement outcome timeline is invalid")
	}
	if err := validateTimeline(attempt); err != nil {
		return err
	}
	if err := validateNetwork(attempt.Network); err != nil {
		return err
	}
	if err := validateMetrics(attempt.Metrics); err != nil {
		return err
	}
	switch attempt.Outcome {
	case OutcomeSuccess:
		if attempt.Failure != connectivity.FailureNone ||
			attempt.SelectedCandidate == "" {
			return errors.New("successful measurement has failure or no winner")
		}
	case OutcomeFailure:
		if !connectivity.ValidFailureCode(attempt.Failure) {
			return errors.New("failed measurement requires a valid failure")
		}
		if attempt.SelectedCandidate != "" &&
			!failureMayFollowSelection(attempt.Failure) {
			return errors.New(
				"failed measurement has an impossible selected candidate",
			)
		}
	default:
		return errors.New("measurement outcome is invalid")
	}
	return nil
}

func failureMayFollowSelection(code connectivity.FailureCode) bool {
	switch code {
	case connectivity.FailureCommitFailed,
		connectivity.FailureNetworkChanged,
		connectivity.FailurePostCommitHealth,
		connectivity.FailureStoppedByUser,
		connectivity.FailureTeardownFailed:
		return true
	default:
		return false
	}
}

func Summarize(attempts []Attempt) Summary {
	summary := Summary{
		Total:         len(attempts),
		FailureCounts: make(map[connectivity.FailureCode]int),
	}
	all := make([]int64, 0, len(attempts))
	successful := make([]int64, 0, len(attempts))
	for _, attempt := range attempts {
		all = append(all, attempt.Timeline.OutcomeMicros)
		if attempt.Outcome == OutcomeSuccess {
			summary.Successes++
			successful = append(successful, attempt.Timeline.OutcomeMicros)
		} else {
			summary.Failures++
			summary.FailureCounts[attempt.Failure]++
		}
	}
	slices.Sort(all)
	slices.Sort(successful)
	summary.OutcomeP50 = percentile(all, 0.50)
	summary.OutcomeP95 = percentile(all, 0.95)
	summary.OutcomeP99 = percentile(all, 0.99)
	summary.SuccessfulOutcomeP99 = percentile(successful, 0.99)
	return summary
}

func (log *Log) verifyExisting() error {
	if _, err := log.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek measurement log: %w", err)
	}
	scanner := bufio.NewScanner(log.file)
	scanner.Buffer(make([]byte, 4096), maxRecordBytes)
	var expectedSequence uint64 = 1
	var previousMAC [sha256.Size]byte
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		var current entry
		if err := decoder.Decode(&current); err != nil {
			return fmt.Errorf("verify measurement line %d: %w", lineNumber, err)
		}
		if err := requireEOF(decoder); err != nil {
			return fmt.Errorf("verify measurement line %d: %w", lineNumber, err)
		}
		if current.Format != Format || current.Sequence != expectedSequence {
			return fmt.Errorf(
				"verify measurement line %d: format or sequence mismatch",
				lineNumber,
			)
		}
		if _, err := parseUTC(current.RecordedAt); err != nil {
			return fmt.Errorf(
				"verify measurement line %d: invalid recorded_at",
				lineNumber,
			)
		}
		if err := ValidateAttempt(current.Attempt); err != nil {
			return fmt.Errorf(
				"verify measurement line %d: %w",
				lineNumber, err,
			)
		}
		if _, duplicate := log.attemptIDs[current.Attempt.AttemptID]; duplicate {
			return fmt.Errorf(
				"verify measurement line %d: duplicate attempt ID",
				lineNumber,
			)
		}
		decodedPrevious, err := hex.DecodeString(current.PreviousMAC)
		if err != nil || len(decodedPrevious) != sha256.Size ||
			subtle.ConstantTimeCompare(decodedPrevious, previousMAC[:]) != 1 {
			return fmt.Errorf(
				"verify measurement line %d: previous MAC mismatch",
				lineNumber,
			)
		}
		decodedMAC, err := hex.DecodeString(current.Authentication)
		if err != nil || len(decodedMAC) != sha256.Size {
			return fmt.Errorf(
				"verify measurement line %d: invalid authentication",
				lineNumber,
			)
		}
		expectedMAC, err := log.authenticate(current)
		if err != nil {
			return fmt.Errorf("verify measurement line %d: %w", lineNumber, err)
		}
		if subtle.ConstantTimeCompare(decodedMAC, expectedMAC[:]) != 1 {
			return fmt.Errorf(
				"verify measurement line %d: authentication failed",
				lineNumber,
			)
		}
		log.previousMAC = previousMAC
		previousMAC = expectedMAC
		expectedSequence++
		log.attempts = append(log.attempts, cloneAttempt(current.Attempt))
		log.attemptIDs[current.Attempt.AttemptID] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read measurement log: %w", err)
	}
	log.sequence = expectedSequence - 1
	log.lastMAC = previousMAC
	if _, err := log.file.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek measurement log end: %w", err)
	}
	return nil
}

func (log *Log) verifyAnchor(reconcile bool) error {
	data, err := securefile.ReadPrivateLimited(
		log.anchorPath, maxAnchorBytes,
	)
	if err != nil {
		return fmt.Errorf("read measurement anchor: %w", err)
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var current anchor
	if err := decoder.Decode(&current); err != nil {
		return fmt.Errorf("decode measurement anchor: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return fmt.Errorf("decode measurement anchor: %w", err)
	}
	if current.Format != AnchorFormat {
		return errors.New("measurement anchor format is invalid")
	}
	decodedLast, err := hex.DecodeString(current.LastMAC)
	if err != nil || len(decodedLast) != sha256.Size {
		return errors.New("measurement anchor MAC is invalid")
	}
	decodedAuth, err := hex.DecodeString(current.Authentication)
	if err != nil || len(decodedAuth) != sha256.Size {
		return errors.New("measurement anchor authentication is invalid")
	}
	expected, err := log.authenticateAnchor(current)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(decodedAuth, expected[:]) != 1 {
		return errors.New("measurement anchor authentication failed")
	}
	if current.Sequence == log.sequence &&
		subtle.ConstantTimeCompare(decodedLast, log.lastMAC[:]) == 1 {
		return nil
	}
	if reconcile &&
		current.Sequence < ^uint64(0) &&
		current.Sequence+1 == log.sequence &&
		subtle.ConstantTimeCompare(decodedLast, log.previousMAC[:]) == 1 {
		if err := log.writeAnchor(log.sequence, log.lastMAC); err != nil {
			return fmt.Errorf(
				"reconcile measurement anchor after committed record: %w",
				err,
			)
		}
		return nil
	}
	if current.Sequence != log.sequence {
		return errors.New(
			"measurement anchor sequence does not match evidence log",
		)
	}
	return errors.New(
		"measurement anchor MAC does not match evidence log",
	)
}

func (log *Log) writeAnchor(
	sequence uint64,
	lastMAC [sha256.Size]byte,
) error {
	current := anchor{
		Format:   AnchorFormat,
		Sequence: sequence,
		LastMAC:  hex.EncodeToString(lastMAC[:]),
	}
	authentication, err := log.authenticateAnchor(current)
	if err != nil {
		return err
	}
	current.Authentication = hex.EncodeToString(authentication[:])
	encoded, err := json.Marshal(current)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxAnchorBytes {
		return errors.New("measurement anchor exceeds size limit")
	}
	if err := securefile.AtomicWrite(
		log.anchorPath, encoded, 0o600,
	); err != nil {
		return fmt.Errorf("write measurement anchor: %w", err)
	}
	return nil
}

func (log *Log) authenticateAnchor(
	current anchor,
) ([sha256.Size]byte, error) {
	unsigned := unsignedAnchor{
		Format:   current.Format,
		Sequence: current.Sequence,
		LastMAC:  current.LastMAC,
	}
	encoded, err := json.Marshal(unsigned)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	mac := hmac.New(sha256.New, log.key[:])
	_, _ = mac.Write([]byte(anchorDomain))
	_, _ = mac.Write(encoded)
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result, nil
}

func (log *Log) poison(err error) error {
	if log.poisoned == nil {
		log.poisoned = err
	}
	return err
}

func (log *Log) authenticate(current entry) ([sha256.Size]byte, error) {
	unsigned := unsignedEntry{
		Format:      current.Format,
		Sequence:    current.Sequence,
		RecordedAt:  current.RecordedAt,
		Attempt:     current.Attempt,
		PreviousMAC: current.PreviousMAC,
	}
	encoded, err := json.Marshal(unsigned)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	mac := hmac.New(sha256.New, log.key[:])
	_, _ = mac.Write([]byte(recordDomain))
	_, _ = mac.Write(encoded)
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result, nil
}

func validateCandidates(attempt Attempt) error {
	if len(attempt.CandidateIDs) == 0 ||
		len(attempt.CandidateIDs) > maxCandidates {
		return errors.New("measurement candidate count is invalid")
	}
	seen := make(map[string]struct{}, len(attempt.CandidateIDs))
	for _, candidate := range attempt.CandidateIDs {
		if candidate == "" || len(candidate) > 128 {
			return errors.New("measurement candidate ID is invalid")
		}
		if _, duplicate := seen[candidate]; duplicate {
			return errors.New("measurement candidate ID is duplicated")
		}
		seen[candidate] = struct{}{}
	}
	if attempt.SelectedCandidate != "" {
		if _, ok := seen[attempt.SelectedCandidate]; !ok {
			return errors.New("selected candidate is not in the candidate set")
		}
	}
	return nil
}

func validateTimeline(attempt Attempt) error {
	values := []int64{
		attempt.Timeline.DialMicros,
		attempt.Timeline.HandshakeMicros,
		attempt.Timeline.BidirectionalMicros,
		attempt.Timeline.DNSMicros,
		attempt.Timeline.CanaryMicros,
		attempt.Timeline.CommitMicros,
	}
	for _, value := range values {
		if value < 0 || value > attempt.Timeline.OutcomeMicros {
			return errors.New("measurement predicate timeline is invalid")
		}
	}
	if attempt.Outcome == OutcomeSuccess {
		for _, value := range values {
			if value == 0 {
				return errors.New("successful measurement lacks a predicate time")
			}
		}
		maximum := slices.Max(values[:len(values)-1])
		if attempt.Timeline.CommitMicros < maximum {
			return errors.New("measurement commit precedes a predicate")
		}
	}
	return nil
}

func validateNetwork(network NetworkProfile) error {
	switch network.Interface {
	case "ethernet", "wifi", "cellular", "loopback", "synthetic":
	default:
		return errors.New("measurement network interface is invalid")
	}
	switch network.IPFamily {
	case "ipv4", "ipv6", "dual", "nat64":
	default:
		return errors.New("measurement IP family is invalid")
	}
	if invalidFloat(network.RTTMillis) || network.RTTMillis < 0 ||
		network.RTTMillis > 60_000 ||
		invalidFloat(network.LossFraction) || network.LossFraction < 0 ||
		network.LossFraction > 1 ||
		invalidFloat(network.CapacityMbps) || network.CapacityMbps < 0 {
		return errors.New("measurement network metrics are invalid")
	}
	return nil
}

func validateMetrics(metrics Metrics) error {
	values := []float64{
		metrics.ThroughputMbps,
		metrics.BaselineMbps,
		metrics.CPUPercent,
		metrics.EnergyMilliwattHour,
	}
	for _, value := range values {
		if invalidFloat(value) || value < 0 {
			return errors.New("measurement metric is invalid")
		}
	}
	if metrics.CPUPercent > 100_000 || metrics.ReconnectMicros < 0 {
		return errors.New("measurement CPU or reconnect metric is invalid")
	}
	return nil
}

func percentile(sorted []int64, quantile float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	index := int(math.Ceil(quantile*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return time.Duration(sorted[index]) * time.Microsecond
}

func cloneAttempt(attempt Attempt) Attempt {
	attempt.CandidateIDs = slices.Clone(attempt.CandidateIDs)
	return attempt
}

func parseUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC {
		return time.Time{}, errors.New("timestamp must be RFC3339Nano UTC")
	}
	return parsed, nil
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && value == hex.EncodeToString(decoded)
}

func invalidFloat(value float64) bool {
	return math.IsNaN(value) || math.IsInf(value, 0)
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("extra JSON value")
	}
	return err
}
