package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// DefaultDuration is exactly seven days. It is spelled as hours rather than as
// 7*24 so that the number appearing in a receipt, in the systemd command and in
// this constant is visibly the same number.
const DefaultDuration = 168 * time.Hour

// maximumDuration is a sanity ceiling, not a policy. A typo that asks for
// 168000h should be refused at the flag rather than discovered on day eight.
const maximumDuration = 90 * 24 * time.Hour

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// Config is the frozen configuration of one soak.
type Config struct {
	RunID string

	StateRoot    string
	SnapshotRoot string
	EvidenceRoot string

	RunnerPath             string
	ExpectedRunnerSHA256   string
	VerifierPath           string
	ExpectedVerifierSHA256 string
	ManifestPath           string
	ExpectedManifestSHA256 string
	ExpectedSourceDigest   string

	Duration     time.Duration
	Cadence      time.Duration
	CycleTimeout time.Duration
	// ColdEvery makes every Nth cycle cold. Zero means every cycle is warm.
	// One means every cycle is cold.
	ColdEvery  int64
	ColdSettle time.Duration

	MinFreeBytes        int64
	MaxLogBytes         int64
	MaxLogFiles         int
	MaxCycleOutputBytes int64
	MaxControllerOutput int64
	Bounds              ResourceBounds

	AllowWritableSnapshot bool
	KillGrace             time.Duration
	SampleInterval        time.Duration
	ProcRoot              string
	CgroupRoot            string

	// ChildEnvironment is the COMPLETE environment handed to every cycle.
	// It is built from -env-file plus the controller's own per-cycle
	// variables, and never from os.Environ().
	ChildEnvironment []string
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Validate refuses a configuration that cannot produce trustworthy evidence.
//
// Several of these are refusals of a value that would "work": an unbounded
// memory ceiling, a zero free-space floor, an inherited environment. Each one
// would let the soak run and would remove a property the soak exists to
// demonstrate, which is the worse outcome of the two.
func (c Config) Validate() error {
	if !identifierPattern.MatchString(c.RunID) {
		return fmt.Errorf(
			"run ID %q must be 1-64 characters of [A-Za-z0-9_.-] beginning "+
				"alphanumerically; it names directories and receipt fields",
			c.RunID,
		)
	}
	for _, pin := range []struct {
		label string
		value string
	}{
		{"-runner-sha256", c.ExpectedRunnerSHA256},
		{"-verifier-sha256", c.ExpectedVerifierSHA256},
		{"-manifest-sha256", c.ExpectedManifestSHA256},
		{"-source-digest", c.ExpectedSourceDigest},
	} {
		if !digestPattern.MatchString(pin.value) {
			return fmt.Errorf(
				"%s must be 64 lowercase hexadecimal characters, got %q",
				pin.label, pin.value,
			)
		}
	}
	for _, path := range []struct {
		label string
		value string
	}{
		{"-state-root", c.StateRoot},
		{"-snapshot-root", c.SnapshotRoot},
		{"-evidence-root", c.EvidenceRoot},
		{"-runner", c.RunnerPath},
		{"-verifier", c.VerifierPath},
		{"-manifest", c.ManifestPath},
	} {
		if !filepath.IsAbs(path.value) {
			return fmt.Errorf(
				"%s must be an absolute path, got %q", path.label, path.value,
			)
		}
	}
	// Isolation. A state root inside the snapshot would be written to by the
	// controller and then re-digested as part of the "immutable" tree, which
	// fails the snapshot check on the controller's own bookkeeping; an
	// evidence root inside the snapshot does the same. Refusing is clearer
	// than excluding, because an exclusion list is a thing to get wrong.
	for _, pair := range []struct {
		labelA, a, labelB, b string
	}{
		{"-state-root", c.StateRoot, "-snapshot-root", c.SnapshotRoot},
		{"-evidence-root", c.EvidenceRoot, "-snapshot-root", c.SnapshotRoot},
		{"-state-root", c.StateRoot, "-evidence-root", c.EvidenceRoot},
	} {
		if err := requireDisjoint(
			pair.labelA, pair.a, pair.labelB, pair.b,
		); err != nil {
			return err
		}
	}
	switch {
	case c.Duration <= 0:
		return errors.New("-duration must be positive")
	case c.Duration > maximumDuration:
		return fmt.Errorf(
			"-duration %s exceeds the %s ceiling", c.Duration, maximumDuration,
		)
	case c.CycleTimeout <= 0:
		return errors.New("-cycle-timeout must be positive")
	case c.CycleTimeout > c.Duration:
		return fmt.Errorf(
			"-cycle-timeout %s exceeds the whole -duration %s; one cycle "+
				"could then outlast the soak", c.CycleTimeout, c.Duration,
		)
	case c.Cadence < 0:
		return errors.New("-cadence cannot be negative")
	case c.ColdEvery < 0:
		return errors.New("-cold-every cannot be negative")
	case c.ColdSettle < 0:
		return errors.New("-cold-settle cannot be negative")
	case c.KillGrace <= 0:
		return errors.New("-kill-grace must be positive")
	case c.SampleInterval <= 0:
		return errors.New("-sample-interval must be positive")
	case c.MinFreeBytes <= 0:
		return errors.New(
			"-min-free-bytes must be positive; a zero floor is not a gate",
		)
	case c.MaxLogBytes <= 0:
		return errors.New("-max-log-bytes must be positive")
	case c.MaxLogFiles < 1:
		return errors.New("-max-log-files must be at least one")
	case c.MaxCycleOutputBytes <= 0:
		return errors.New(
			"-max-cycle-output-bytes must be positive; there is no unbounded mode",
		)
	case c.MaxCycleOutputBytes > maximumCycleTailBytes:
		return fmt.Errorf(
			"-max-cycle-output-bytes %d exceeds the append/replay-safe "+
				"ceiling of %d", c.MaxCycleOutputBytes, maximumCycleTailBytes,
		)
	case c.MaxControllerOutput <= 0:
		return errors.New("-max-controller-output-bytes must be positive")
	case c.Bounds.MaxRSSBytes <= 0:
		return errors.New(
			"-max-rss-bytes must be positive; a soak with no memory ceiling " +
				"cannot demonstrate that memory stayed bounded",
		)
	case !filepath.IsAbs(c.ProcRoot):
		return fmt.Errorf("-proc-root must be absolute, got %q", c.ProcRoot)
	case !filepath.IsAbs(c.CgroupRoot):
		return fmt.Errorf("-cgroup-root must be absolute, got %q", c.CgroupRoot)
	}
	// The log budget has to fit inside the free-space floor with room to
	// spare, or the rotation ceiling and the disk gate contradict each other:
	// the gate would stop the soak for space the logs are entitled to use.
	budget := saturatingMultiply(c.MaxLogBytes, int64(c.MaxLogFiles))
	if budget >= c.MinFreeBytes {
		return fmt.Errorf(
			"the log budget (%s over %d files) is not smaller than "+
				"-min-free-bytes (%s); the rotation ceiling and the disk "+
				"gate would contradict each other",
			formatBytes(c.MaxLogBytes), c.MaxLogFiles,
			formatBytes(c.MinFreeBytes),
		)
	}
	if len(c.ChildEnvironment) == 0 {
		return errors.New(
			"the child environment is empty; the accepted runner is " +
				"configured entirely through its environment, so an empty " +
				"one means nothing was loaded",
		)
	}
	return nil
}

// reservedChildVariables are set by the controller for every cycle. An env file
// may not define them: a file that could would let an operator pin READINESS to
// warm and silently disable the cold half of the schedule while the receipts
// went on claiming a mixed one.
var reservedChildVariables = []string{
	"READINESS",
	"WINN_SOAK_RUN_ID",
	"WINN_SOAK_CYCLE_SEQUENCE",
	"WINN_SOAK_INSTANCE_NONCE",
}

var envLinePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// LoadChildEnvironment reads the complete child environment from a file.
//
// A file rather than repeated -env flags, and this is not a style preference:
// command-line arguments are world-readable in /proc on Linux, so every value
// passed that way is visible to any local user for the lifetime of a seven-day
// process. The file is required to be 0600.
//
// os.Environ() is never consulted. The controller's own environment may carry
// anything the operator's shell had -- credentials, agent sockets, tokens -- and
// a runner that inherited them would be a seven-day exfiltration surface for
// values nobody decided to expose.
func LoadChildEnvironment(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat env file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf(
			"env file %s is readable beyond its owner (mode %04o); it "+
				"carries the runner's configuration",
			path, info.Mode().Perm(),
		)
	}
	if info.Size() > 1<<20 {
		return nil, fmt.Errorf("env file %s is larger than 1 MiB", path)
	}
	// #nosec G304 -- the path is an operator-supplied configuration file;
	// its mode and size have just been checked.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open env file: %w", err)
	}
	defer func() { _ = file.Close() }()

	seen := make(map[string]bool)
	var entries []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 4096), 1<<16)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !envLinePattern.MatchString(line) {
			return nil, fmt.Errorf(
				"env file %s line %d is not NAME=VALUE", path, lineNumber,
			)
		}
		name, _, _ := strings.Cut(line, "=")
		for _, reserved := range reservedChildVariables {
			if name == reserved {
				return nil, fmt.Errorf(
					"env file %s line %d defines %s, which the controller "+
						"sets per cycle", path, lineNumber, name,
				)
			}
		}
		if seen[name] {
			return nil, fmt.Errorf(
				"env file %s defines %s more than once; which one would "+
					"reach the runner depends on the reader",
				path, name,
			)
		}
		seen[name] = true
		entries = append(entries, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read env file %s: %w", path, err)
	}
	if findings := checkCustodySeparation(entries, nil); len(findings) > 0 {
		return nil, fmt.Errorf(
			"env file %s defines %s, which must never exist on the "+
				"producing host", path, findings[0].Detail,
		)
	}
	sort.Strings(entries)
	return entries, nil
}

// EnvironmentNames returns only the NAMES from an environment, for the receipt.
//
// Values are never recorded, never logged, and never printed. There is no flag
// that turns that off.
func EnvironmentNames(environment []string) []string {
	names := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// cycleEnvironment builds the complete environment for one cycle.
func (c Config) cycleEnvironment(
	sequence int64, readiness Readiness, nonce string,
) []string {
	environment := make([]string, 0, len(c.ChildEnvironment)+4)
	environment = append(environment, c.ChildEnvironment...)
	environment = append(environment,
		"READINESS="+string(readiness),
		"WINN_SOAK_RUN_ID="+c.RunID,
		fmt.Sprintf("WINN_SOAK_CYCLE_SEQUENCE=%d", sequence),
		"WINN_SOAK_INSTANCE_NONCE="+nonce,
	)
	return environment
}

// configurationDigest commits to every controller option and to the exact
// child environment without emitting any environment value. The digest is
// intentionally one-way evidence, not an authentication tag; checkpoint
// authentication separately prevents an unprivileged local process from
// replacing the committed value.
func configurationDigest(c Config) (string, error) {
	environment := append([]string(nil), c.ChildEnvironment...)
	sort.Strings(environment)
	canonical := struct {
		RunID                     string        `json:"run_id"`
		StateRoot                 string        `json:"state_root"`
		SnapshotRoot              string        `json:"snapshot_root"`
		EvidenceRoot              string        `json:"evidence_root"`
		RunnerPath                string        `json:"runner_path"`
		ExpectedRunnerSHA256      string        `json:"expected_runner_sha256"`
		VerifierPath              string        `json:"verifier_path"`
		ExpectedVerifierSHA256    string        `json:"expected_verifier_sha256"`
		ManifestPath              string        `json:"manifest_path"`
		ExpectedManifestSHA256    string        `json:"expected_manifest_sha256"`
		ExpectedSourceDigest      string        `json:"expected_source_digest"`
		Duration                  time.Duration `json:"duration_nanos"`
		Cadence                   time.Duration `json:"cadence_nanos"`
		CycleTimeout              time.Duration `json:"cycle_timeout_nanos"`
		ColdEvery                 int64         `json:"cold_every"`
		ColdSettle                time.Duration `json:"cold_settle_nanos"`
		MinFreeBytes              int64         `json:"min_free_bytes"`
		MaxLogBytes               int64         `json:"max_log_bytes"`
		MaxLogFiles               int           `json:"max_log_files"`
		MaxCycleOutputBytes       int64         `json:"max_cycle_output_bytes"`
		MaxControllerOutput       int64         `json:"max_controller_output_bytes"`
		MaxRSSBytes               int64         `json:"max_rss_bytes"`
		MaxThreads                int64         `json:"max_threads"`
		MaxOpenFiles              int64         `json:"max_open_files"`
		MaxBoundOutputBytes       int64         `json:"max_bound_output_bytes"`
		AllowWritableSnapshot     bool          `json:"allow_writable_snapshot"`
		KillGrace                 time.Duration `json:"kill_grace_nanos"`
		SampleInterval            time.Duration `json:"sample_interval_nanos"`
		ProcRoot                  string        `json:"proc_root"`
		CgroupRoot                string        `json:"cgroup_root"`
		CanonicalChildEnvironment []string      `json:"canonical_child_environment"`
	}{
		RunID: c.RunID, StateRoot: c.StateRoot,
		SnapshotRoot: c.SnapshotRoot, EvidenceRoot: c.EvidenceRoot,
		RunnerPath: c.RunnerPath, ExpectedRunnerSHA256: c.ExpectedRunnerSHA256,
		VerifierPath:           c.VerifierPath,
		ExpectedVerifierSHA256: c.ExpectedVerifierSHA256,
		ManifestPath:           c.ManifestPath,
		ExpectedManifestSHA256: c.ExpectedManifestSHA256,
		ExpectedSourceDigest:   c.ExpectedSourceDigest,
		Duration:               c.Duration, Cadence: c.Cadence,
		CycleTimeout: c.CycleTimeout, ColdEvery: c.ColdEvery,
		ColdSettle: c.ColdSettle, MinFreeBytes: c.MinFreeBytes,
		MaxLogBytes: c.MaxLogBytes, MaxLogFiles: c.MaxLogFiles,
		MaxCycleOutputBytes:   c.MaxCycleOutputBytes,
		MaxControllerOutput:   c.MaxControllerOutput,
		MaxRSSBytes:           c.Bounds.MaxRSSBytes,
		MaxThreads:            c.Bounds.MaxThreads,
		MaxOpenFiles:          c.Bounds.MaxOpenFiles,
		MaxBoundOutputBytes:   c.Bounds.MaxOutputBytes,
		AllowWritableSnapshot: c.AllowWritableSnapshot,
		KillGrace:             c.KillGrace, SampleInterval: c.SampleInterval,
		ProcRoot: c.ProcRoot, CgroupRoot: c.CgroupRoot,
		CanonicalChildEnvironment: environment,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("encode canonical controller configuration: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// readinessFor decides warm or cold for a sequence number.
//
// ColdEvery of zero means never cold; one means always cold; N means every Nth.
// The modulus is against the 1-based sequence so that -cold-every=1 is every
// cycle and -cold-every=4 makes cycles 4, 8, 12 cold, which is what an operator
// reading the flag expects.
func (c Config) readinessFor(sequence int64) Readiness {
	if c.ColdEvery <= 0 {
		return ReadinessWarm
	}
	if sequence%c.ColdEvery == 0 {
		return ReadinessCold
	}
	return ReadinessWarm
}
