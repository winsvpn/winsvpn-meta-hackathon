package main

import (
	"bytes"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBoundedBufferKeepsATailAndCountsEverything.
func TestBoundedBufferKeepsATailAndCountsEverything(t *testing.T) {
	buffer := newBoundedBuffer(10)
	// One write that fits, one that straddles the limit, one entirely past.
	for _, chunk := range []string{"12345", "6789ABCDEF", strings.Repeat("Z", 1000)} {
		n, err := buffer.Write([]byte(chunk))
		if err != nil {
			t.Fatalf("bounded write returned an error: %v", err)
		}
		if n != len(chunk) {
			t.Fatalf("bounded write reported %d of %d bytes; a short write "+
				"would change how the child behaves", n, len(chunk))
		}
	}
	if got := string(buffer.Bytes()); got != strings.Repeat("Z", 10) {
		t.Errorf("retained %q, want the final ten bytes", got)
	}
	if want := int64(5 + 10 + 1000); buffer.Total() != want {
		t.Errorf("counted %d bytes, want %d", buffer.Total(), want)
	}
	if !buffer.Truncated() {
		t.Error("truncation was not reported")
	}

	// Exactly at the limit is not truncation.
	exact := newBoundedBuffer(4)
	if _, err := exact.Write([]byte("abcd")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if exact.Truncated() {
		t.Error("a write of exactly the limit was reported as truncated")
	}
	if _, err := exact.Write([]byte("e")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !exact.Truncated() {
		t.Error("one byte past the limit was not reported as truncated")
	}
}

// TestRotatingLogRespectsItsBudget writes far more than the budget and then
// measures what is actually on disk.
//
// Measuring the disk rather than trusting the rotation logic is the point: a
// rotation that renamed files without ever deleting one would satisfy every
// invariant the writer could check about itself.
func TestRotatingLogRespectsItsBudget(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "logs")
	const perFile = 4096
	const files = 3
	log, err := newRotatingLog(directory, "cycle.log", perFile, files)
	if err != nil {
		t.Fatalf("create rotating log: %v", err)
	}
	defer func() { _ = log.Close() }()

	chunk := bytes.Repeat([]byte("x"), 512)
	// Two hundred times the budget.
	for written := 0; written < perFile*files*200; written += len(chunk) {
		if _, err := log.Write(chunk); err != nil {
			t.Fatalf("write to rotating log: %v", err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	var total int64
	count := 0
	walkErr := filepath.WalkDir(directory, func(
		path string, entry fs.DirEntry, err error,
	) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		count++
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk log directory: %v", walkErr)
	}
	if count > files {
		t.Errorf("%d log files on disk, want at most %d", count, files)
	}
	budget := int64(perFile * files)
	if total > budget {
		t.Errorf("%d bytes on disk, above the %d byte ceiling", total, budget)
	}
	if total == 0 {
		t.Fatal("nothing was written at all, so the ceiling check is vacuous")
	}
}

// TestRotatingLogSingleFileStillRotates covers the maxFiles=1 corner, where the
// only way to honour a budget is to discard.
func TestRotatingLogSingleFileStillRotates(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "logs")
	log, err := newRotatingLog(directory, "cycle.log", 1024, 1)
	if err != nil {
		t.Fatalf("create rotating log: %v", err)
	}
	defer func() { _ = log.Close() }()
	chunk := bytes.Repeat([]byte("y"), 256)
	for i := 0; i < 100; i++ {
		if _, err := log.Write(chunk); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	info, err := os.Stat(filepath.Join(directory, "cycle.log"))
	if err != nil {
		t.Fatalf("stat log: %v", err)
	}
	if info.Size() > 1024 {
		t.Errorf("single log grew to %d bytes against a 1024 byte budget",
			info.Size())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read log directory: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("%d files in a single-file log directory", len(entries))
	}
}

func TestRotatingLogSplitsOneOversizedWriteAtExactBoundaries(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "logs")
	log, err := newRotatingLog(directory, "cycle.log", 100, 3)
	if err != nil {
		t.Fatalf("create rotating log: %v", err)
	}
	payload := bytes.Repeat([]byte("z"), 1_037)
	n, err := log.Write(payload)
	if err != nil {
		t.Fatalf("oversized write: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("wrote %d of %d bytes", n, len(payload))
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read logs: %v", err)
	}
	var total int64
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > 100 {
			t.Fatalf("%s is %d bytes, above exact 100-byte file bound",
				entry.Name(), info.Size())
		}
		total += info.Size()
	}
	if total > 300 {
		t.Fatalf("retained %d bytes, above exact 300-byte aggregate bound", total)
	}
}

func TestRotatingLogRefusesPreexistingBudgetViolations(t *testing.T) {
	for _, test := range []struct {
		name string
		file string
		size int
	}{
		{"oversized current", "cycle.log", 101},
		{"stale file beyond retention", "cycle.log.3", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.WriteFile(
				filepath.Join(directory, test.file),
				bytes.Repeat([]byte("x"), test.size), 0o600,
			); err != nil {
				t.Fatal(err)
			}
			if _, err := newRotatingLog(
				directory, "cycle.log", 100, 3,
			); err == nil {
				t.Fatalf("accepted existing violating file %s", test.file)
			}
		})
	}
}

// TestEmitterStopsAtItsBudget.
func TestEmitterStopsAtItsBudget(t *testing.T) {
	var sink bytes.Buffer
	e := newEmitter(&sink, 200)
	for i := 0; i < 10_000; i++ {
		e.Printf("cycle %d produced a line of controller commentary", i)
	}
	if sink.Len() > 400 {
		t.Errorf("the emitter wrote %d bytes against a 200 byte budget",
			sink.Len())
	}
	if sink.Len() == 0 {
		t.Fatal("the emitter wrote nothing, so the budget check is vacuous")
	}
	if !strings.Contains(sink.String(), "output budget reached") {
		t.Error("the emitter stopped without saying why")
	}
	// The first line survived: a budget that dropped everything would also
	// satisfy the size assertion above.
	if !strings.Contains(sink.String(), "cycle 0") {
		t.Error("the emitter discarded its first line")
	}
}

// TestLogBudgetMustFitInsideTheFreeSpaceFloor proves the two bounds are checked
// against each other rather than configured independently.
func TestLogBudgetMustFitInsideTheFreeSpaceFloor(t *testing.T) {
	cfg := testConfig(t, t.TempDir())
	cfg.MaxLogBytes = 1 << 30
	cfg.MaxLogFiles = 16
	cfg.MinFreeBytes = 1 << 30
	err := cfg.Validate()
	if err == nil {
		t.Fatal("a log budget larger than the free-space floor was accepted")
	}
	if !strings.Contains(err.Error(), "contradict") {
		t.Fatalf("refusal was %v, want one naming the contradiction", err)
	}
}

// TestConfigRefusesUnboundedAndInheritedSettings covers the refusals that would
// otherwise "work".
func TestConfigRefusesUnboundedAndInheritedSettings(t *testing.T) {
	base := testConfig(t, t.TempDir())
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name:   "no memory ceiling",
			mutate: func(c *Config) { c.Bounds.MaxRSSBytes = 0 },
			want:   "-max-rss-bytes",
		},
		{
			name:   "no free space floor",
			mutate: func(c *Config) { c.MinFreeBytes = 0 },
			want:   "-min-free-bytes",
		},
		{
			name:   "no output ceiling",
			mutate: func(c *Config) { c.MaxCycleOutputBytes = 0 },
			want:   "-max-cycle-output-bytes",
		},
		{
			name:   "empty child environment",
			mutate: func(c *Config) { c.ChildEnvironment = nil },
			want:   "child environment is empty",
		},
		{
			name:   "cycle timeout longer than the whole soak",
			mutate: func(c *Config) { c.CycleTimeout = c.Duration + time.Hour },
			want:   "-cycle-timeout",
		},
		{
			name:   "state root inside the snapshot",
			mutate: func(c *Config) { c.StateRoot = c.SnapshotRoot + "/state" },
			want:   "inside",
		},
		{
			name:   "evidence root inside the snapshot",
			mutate: func(c *Config) { c.EvidenceRoot = c.SnapshotRoot + "/evidence" },
			want:   "inside",
		},
		{
			name:   "relative path",
			mutate: func(c *Config) { c.StateRoot = "relative/state" },
			want:   "absolute path",
		},
		{
			name:   "short digest pin",
			mutate: func(c *Config) { c.ExpectedRunnerSHA256 = "abc" },
			want:   "-runner-sha256",
		},
		{
			name:   "uppercase digest pin",
			mutate: func(c *Config) { c.ExpectedSourceDigest = strings.ToUpper("ee" + repeatHex(62)) },
			want:   "-source-digest",
		},
		{
			name:   "run ID with a path separator",
			mutate: func(c *Config) { c.RunID = "../escape" },
			want:   "run ID",
		},
		{
			name:   "duration above the ceiling",
			mutate: func(c *Config) { c.Duration = maximumDuration + time.Hour },
			want:   "-duration",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := base
			test.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("%s was accepted", test.name)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("refusal was %q, want one containing %q",
					err.Error(), test.want)
			}
		})
	}
	// Control: the unmutated configuration is accepted, so the cases above
	// are refusals of what they name rather than of the baseline.
	if err := base.Validate(); err != nil {
		t.Fatalf("the baseline configuration is itself refused: %v", err)
	}
}

// TestLoadChildEnvironmentRefusesLeakyAndAmbiguousFiles.
func TestLoadChildEnvironmentRefusesLeakyAndAmbiguousFiles(t *testing.T) {
	write := func(t *testing.T, contents string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "soak.env")
		if err := os.WriteFile(path, []byte(contents), mode); err != nil {
			t.Fatalf("write env file: %v", err)
		}
		return path
	}

	good := write(t, "# a comment\n\nMATRIX_ID=phase1\nPATH=/usr/bin\n", 0o600)
	loaded, err := LoadChildEnvironment(good)
	if err != nil {
		t.Fatalf("a well-formed env file was refused: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loaded %d entries, want 2: %v", len(loaded), loaded)
	}

	tests := []struct {
		name     string
		contents string
		mode     os.FileMode
		want     string
	}{
		{
			name:     "world readable",
			contents: "MATRIX_ID=phase1\n",
			mode:     0o644,
			want:     "readable beyond its owner",
		},
		{
			name:     "reserved variable",
			contents: "READINESS=warm\n",
			mode:     0o600,
			want:     "the controller sets per cycle",
		},
		{
			name:     "duplicate name",
			contents: "MATRIX_ID=a\nMATRIX_ID=b\n",
			mode:     0o600,
			want:     "more than once",
		},
		{
			name:     "not NAME=VALUE",
			contents: "just some text\n",
			mode:     0o600,
			want:     "not NAME=VALUE",
		},
		{
			name:     "finalizer seed",
			contents: "WINN_FINALIZER_SEED=deadbeef\n",
			mode:     0o600,
			want:     "must never exist on the producing host",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := write(t, test.contents, test.mode)
			_, err := LoadChildEnvironment(path)
			if err == nil {
				t.Fatalf("%s was accepted", test.name)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("refusal was %q, want one containing %q",
					err.Error(), test.want)
			}
			if strings.Contains(err.Error(), "deadbeef") {
				t.Fatalf("the refusal quotes a value: %v", err)
			}
		})
	}
}

// TestEnvironmentNamesNeverCarryValues.
func TestEnvironmentNamesNeverCarryValues(t *testing.T) {
	names := EnvironmentNames([]string{
		"B=second-secret",
		"A=first-secret",
		"malformed-entry-without-equals",
	})
	if len(names) != 2 {
		t.Fatalf("returned %d names, want 2: %v", len(names), names)
	}
	if names[0] != "A" || names[1] != "B" {
		t.Errorf("names are %v, want a sorted [A B]", names)
	}
	for _, name := range names {
		if strings.Contains(name, "secret") {
			t.Errorf("a value leaked into the name list: %q", name)
		}
	}
}

// TestCycleEnvironmentIsExactlyWhatWasConfigured.
func TestCycleEnvironmentIsExactlyWhatWasConfigured(t *testing.T) {
	cfg := testConfig(t, t.TempDir())
	environment := cfg.cycleEnvironment(7, ReadinessCold, "nonce-value")
	if len(environment) != len(cfg.ChildEnvironment)+len(reservedChildVariables) {
		t.Fatalf("built %d entries from %d configured plus %d reserved",
			len(environment), len(cfg.ChildEnvironment),
			len(reservedChildVariables))
	}
	joined := strings.Join(environment, "\n")
	for _, want := range []string{
		"READINESS=cold",
		"WINN_SOAK_CYCLE_SEQUENCE=7",
		"WINN_SOAK_INSTANCE_NONCE=nonce-value",
		"WINN_SOAK_RUN_ID=" + cfg.RunID,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("cycle environment omits %q", want)
		}
	}
}

// TestReadinessSchedule pins the warm/cold cadence at its boundaries.
func TestReadinessSchedule(t *testing.T) {
	cases := []struct {
		coldEvery int64
		sequence  int64
		want      Readiness
	}{
		{0, 1, ReadinessWarm},
		{0, 1000, ReadinessWarm},
		{1, 1, ReadinessCold},
		{1, 2, ReadinessCold},
		{4, 1, ReadinessWarm},
		{4, 3, ReadinessWarm},
		{4, 4, ReadinessCold},
		{4, 5, ReadinessWarm},
		{4, 8, ReadinessCold},
	}
	for _, test := range cases {
		cfg := Config{ColdEvery: test.coldEvery}
		if got := cfg.readinessFor(test.sequence); got != test.want {
			t.Errorf("cold-every=%d sequence=%d gave %q, want %q",
				test.coldEvery, test.sequence, got, test.want)
		}
	}
}

// TestSaturatingMultiplyDoesNotWrap guards the 32-bit build.
//
// On linux/386 an unchecked multiplication of block count by block size
// overflows silently, and a free-space gate computed from a wrapped negative
// would pass on a full disk.
func TestSaturatingMultiplyDoesNotWrap(t *testing.T) {
	if got := saturatingMultiply(1<<62, 8); got <= 0 {
		t.Errorf("saturatingMultiply wrapped to %d", got)
	}
	if got := saturatingMultiply(4, 1024); got != 4096 {
		t.Errorf("ordinary multiplication gave %d, want 4096", got)
	}
	for _, pair := range [][2]int64{{0, 5}, {5, 0}, {-1, 5}, {5, -1}} {
		if got := saturatingMultiply(pair[0], pair[1]); got != 0 {
			t.Errorf("saturatingMultiply(%d, %d) = %d, want 0",
				pair[0], pair[1], got)
		}
	}
}

func TestBoundedUint64ToInt64RejectsOverflow(t *testing.T) {
	if got, err := boundedUint64ToInt64(math.MaxInt64, "test counter"); err != nil ||
		got != math.MaxInt64 {
		t.Fatalf("maximum signed counter = %d, %v", got, err)
	}
	if _, err := boundedUint64ToInt64(
		uint64(math.MaxInt64)+1, "test counter",
	); err == nil {
		t.Fatal("overflowing filesystem counter was accepted")
	}
}
