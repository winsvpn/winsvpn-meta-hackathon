package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testOrigin is a fixed wall time so that every receipt in these tests is
// byte-reproducible.
var testOrigin = time.Date(2026, 7, 27, 0, 0, 0, 0, time.UTC)

// harness is a controller wired entirely to fakes, plus the real state and
// evidence directories on disk.
//
// The filesystem is real on purpose. The append-only receipt log, the O_EXCL
// first-failure record, the flock and the atomic checkpoint replacement are all
// properties of real files; a fake filesystem would test a model of them.
type harness struct {
	t          *testing.T
	config     Config
	clock      *fakeClock
	runner     *fakeRunner
	lock       *InstanceLock
	receipts   *ReceiptLog
	checkpoint *CheckpointStore
	frozen     Provenance
	emitted    *os.File

	// freeBytes is what the injected free-space probe reports.
	freeBytes int64
	// currentProvenance is what the injected re-verification reports. A test
	// mutates it to drift the source mid-loop.
	currentProvenance Provenance
	// reverifyErr makes re-verification fail outright.
	reverifyErr error
}

func testProvenance() Provenance {
	return Provenance{
		SnapshotRoot:        "/snapshot",
		SnapshotDigest:      "aa" + repeatHex(62),
		SnapshotFileCount:   42,
		SnapshotFsType:      "ext4",
		SnapshotReadOnly:    true,
		RunnerPath:          "/opt/winn-lab/aicore_phase1_auto_matrix.sh",
		RunnerDigest:        "bb" + repeatHex(62),
		VerifierPath:        "/opt/winn-lab/bin/winn-phase1-matrix-verify",
		VerifierDigest:      "cc" + repeatHex(62),
		ManifestPath:        "/opt/winn-lab/bin/winn-auto-e2e.source.sha256",
		ManifestDigest:      "dd" + repeatHex(62),
		SourceDigest:        "ee" + repeatHex(62),
		ConfigurationDigest: "ff" + repeatHex(62),
	}
}

func repeatHex(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = '0'
	}
	return string(out)
}

// testConfig produces a configuration that Validate accepts, with directories
// under the test's own temporary root.
func testConfig(t *testing.T, root string) Config {
	t.Helper()
	cfg := Config{
		RunID:                  "soak-test",
		StateRoot:              filepath.Join(root, "state"),
		SnapshotRoot:           filepath.Join(root, "snapshot"),
		EvidenceRoot:           filepath.Join(root, "evidence"),
		RunnerPath:             filepath.Join(root, "bin", "runner.sh"),
		ExpectedRunnerSHA256:   "bb" + repeatHex(62),
		VerifierPath:           filepath.Join(root, "bin", "verifier"),
		ExpectedVerifierSHA256: "cc" + repeatHex(62),
		ManifestPath:           filepath.Join(root, "bin", "manifest.sha256"),
		ExpectedManifestSHA256: "dd" + repeatHex(62),
		ExpectedSourceDigest:   "ee" + repeatHex(62),
		Duration:               DefaultDuration,
		Cadence:                time.Minute,
		CycleTimeout:           30 * time.Minute,
		ColdEvery:              4,
		ColdSettle:             time.Minute,
		MinFreeBytes:           8 << 30,
		MaxLogBytes:            1 << 20,
		MaxLogFiles:            4,
		MaxCycleOutputBytes:    4096,
		MaxControllerOutput:    1 << 20,
		Bounds: ResourceBounds{
			MaxRSSBytes:    4 << 30,
			MaxThreads:     4096,
			MaxOpenFiles:   4096,
			MaxOutputBytes: 4096,
		},
		KillGrace:        30 * time.Second,
		SampleInterval:   5 * time.Second,
		ProcRoot:         "/proc",
		CgroupRoot:       "/sys/fs/cgroup",
		ChildEnvironment: []string{"PATH=/usr/bin:/bin", "MATRIX_ID=phase1-auto-v1"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("test configuration is itself invalid: %v", err)
	}
	return cfg
}

// newHarness builds a controller over real directories and fake everything
// else. reuse=true keeps whatever a previous harness left behind, which is how
// the crash-and-resume test hands one run's state to the next.
func newHarness(
	t *testing.T, root string, runner *fakeRunner, clock *fakeClock,
	mutate func(*Config),
) *harness {
	t.Helper()
	cfg := testConfig(t, root)
	if mutate != nil {
		mutate(&cfg)
		if err := cfg.Validate(); err != nil {
			t.Fatalf("mutated test configuration is invalid: %v", err)
		}
	}
	h := &harness{
		t:                 t,
		config:            cfg,
		clock:             clock,
		runner:            runner,
		frozen:            testProvenance(),
		currentProvenance: testProvenance(),
		freeBytes:         64 << 30,
	}
	return h
}

// controller assembles the Controller, applying the resume plan exactly as
// soak() does. Sharing that path is what makes the resume tests test the
// program rather than a parallel implementation written for the test.
func (h *harness) controller() *Controller {
	t := h.t
	t.Helper()

	lock, err := AcquireInstanceLock(h.config.StateRoot)
	if err != nil {
		t.Fatalf("acquire instance lock: %v", err)
	}
	h.lock = lock

	store, err := OpenCheckpointStore(h.config.StateRoot)
	if err != nil {
		t.Fatalf("open checkpoint store: %v", err)
	}
	h.checkpoint = store

	receipts, err := OpenReceiptLog(h.config.EvidenceRoot, h.config.RunID)
	if err != nil {
		t.Fatalf("open receipt log: %v", err)
	}
	h.receipts = receipts

	stored, _, loadErr := store.Load()
	haveCheckpoint := loadErr == nil
	if loadErr != nil && loadErr != errNoCheckpoint {
		t.Fatalf("load checkpoint: %v", loadErr)
	}
	firstFailure, err := LoadFirstFailure(
		h.config.EvidenceRoot, h.config.RunID,
	)
	if err != nil {
		t.Fatalf("load first failure: %v", err)
	}
	plan, err := planResume(
		stored, haveCheckpoint, receipts.ReplayState(), firstFailure,
		h.currentProvenance, h.clock.WallNow(), h.config,
	)
	if err != nil {
		t.Fatalf("plan resume: %v", err)
	}

	sink, err := os.CreateTemp(t.TempDir(), "controller-output-*")
	if err != nil {
		t.Fatalf("create emitter sink: %v", err)
	}
	h.emitted = sink

	return &Controller{
		config:     h.config,
		clock:      h.clock,
		runner:     newSerialisingRunner(h.runner),
		receipts:   receipts,
		checkpoint: store,
		lock:       lock,
		frozen:     h.frozen,
		terminal:   &TerminalState{},
		emit:       newEmitter(sink, h.config.MaxControllerOutput),
		evidence:   h.config.EvidenceRoot,
		reverify: func() (Provenance, error) {
			if h.reverifyErr != nil {
				return Provenance{}, h.reverifyErr
			}
			return h.currentProvenance, nil
		},
		freeSpace: func() (int64, error) {
			return h.freeBytes, nil
		},
		carried:     plan.Carried,
		resumeCount: plan.ResumeCount,
		wallAtStart: plan.WallAtStart,
	}
}

func (h *harness) close() {
	if h.receipts != nil {
		_ = h.receipts.Close()
	}
	if h.lock != nil {
		_ = h.lock.Release()
	}
	if h.emitted != nil {
		_ = h.emitted.Close()
	}
}
