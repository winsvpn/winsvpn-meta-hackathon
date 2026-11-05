package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// stageSnapshot builds a small tree and returns its root.
func stageSnapshot(t *testing.T) string {
	t.Helper()
	// t.TempDir() on macOS hands back a /var symlink; the snapshot gates
	// refuse a symlinked path component by design, so the root is resolved
	// here rather than the gate being weakened to accommodate the test.
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temporary directory: %v", err)
	}
	root := filepath.Join(base, "snapshot")
	if err := os.MkdirAll(filepath.Join(root, "scripts"), 0o700); err != nil {
		t.Fatalf("stage snapshot: %v", err)
	}
	files := map[string]string{
		"scripts/aicore_phase1_auto_matrix.sh": "#!/bin/sh\nexit 0\n",
		"go.mod":                               "module winsvpn.local/winnprotocol\n",
	}
	for name, contents := range files {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return root
}

func writePinned(t *testing.T, path, contents string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	sum := sha256.Sum256([]byte(contents))
	return hex.EncodeToString(sum[:])
}

// provenanceConfig builds a Config whose pins all match real files on disk.
func provenanceConfig(t *testing.T) Config {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temporary directory: %v", err)
	}
	snapshot := stageSnapshot(t)
	cfg := Config{
		RunID:                "provenance-test",
		StateRoot:            filepath.Join(base, "state"),
		SnapshotRoot:         snapshot,
		EvidenceRoot:         filepath.Join(base, "evidence"),
		RunnerPath:           filepath.Join(base, "bin", "runner.sh"),
		VerifierPath:         filepath.Join(base, "bin", "verifier"),
		ManifestPath:         filepath.Join(base, "bin", "manifest.sha256"),
		ExpectedSourceDigest: "ee" + repeatHex(62),
		Duration:             DefaultDuration,
		Cadence:              time.Minute,
		CycleTimeout:         30 * time.Minute,
		ColdEvery:            4,
		MinFreeBytes:         1 << 20,
		MaxLogBytes:          1 << 10,
		MaxLogFiles:          4,
		MaxCycleOutputBytes:  4096,
		MaxControllerOutput:  1 << 20,
		Bounds:               ResourceBounds{MaxRSSBytes: 1 << 30},
		KillGrace:            time.Second,
		SampleInterval:       time.Second,
		ProcRoot:             "/proc",
		CgroupRoot:           "/sys/fs/cgroup",
		ChildEnvironment:     []string{"PATH=/usr/bin"},
		// The staged snapshot is an ordinary writable directory, which the
		// gate refuses by default. The test opts in explicitly so that the
		// refusal it is exercising is the one it names, rather than the
		// read-only gate firing first for every case.
		AllowWritableSnapshot: true,
	}
	cfg.ExpectedRunnerSHA256 = writePinned(t, cfg.RunnerPath, "#!/bin/sh\nexit 0\n")
	cfg.ExpectedVerifierSHA256 = writePinned(t, cfg.VerifierPath, "verifier bytes")
	cfg.ExpectedManifestSHA256 = writePinned(t, cfg.ManifestPath, "manifest bytes")
	return cfg
}

// TestGatherProvenancePinsAndRefuses covers the happy path and every pin.
func TestGatherProvenancePinsAndRefuses(t *testing.T) {
	cfg := provenanceConfig(t)

	provenance, err := gatherProvenance(cfg)
	if err != nil {
		t.Fatalf("gatherProvenance on a clean tree: %v", err)
	}
	if provenance.SnapshotFileCount != 2 {
		t.Errorf("counted %d files, want 2", provenance.SnapshotFileCount)
	}
	if provenance.RunnerDigest != cfg.ExpectedRunnerSHA256 {
		t.Errorf("runner digest %q, want %q",
			provenance.RunnerDigest, cfg.ExpectedRunnerSHA256)
	}

	// Repeating the gather over an unchanged tree must give the identical
	// digest. A tree digest that varied between walks would make every
	// drift check fire on the second cycle.
	again, err := gatherProvenance(cfg)
	if err != nil {
		t.Fatalf("second gatherProvenance: %v", err)
	}
	if again.SnapshotDigest != provenance.SnapshotDigest {
		t.Fatalf("the snapshot digest is not stable: %s then %s",
			provenance.SnapshotDigest, again.SnapshotDigest)
	}

	t.Run("a changed pin is refused", func(t *testing.T) {
		drifted := cfg
		drifted.ExpectedRunnerSHA256 = "00" + repeatHex(62)
		if _, err := gatherProvenance(drifted); err == nil {
			t.Fatal("a runner whose digest does not match its pin was accepted")
		} else if !strings.Contains(err.Error(), "runner digest mismatch") {
			t.Fatalf("refusal was %v, want a runner digest mismatch", err)
		}
	})

	t.Run("a changed file changes the tree digest", func(t *testing.T) {
		path := filepath.Join(cfg.SnapshotRoot, "go.mod")
		if err := os.WriteFile(path, []byte("module other\n"), 0o600); err != nil {
			t.Fatalf("modify snapshot: %v", err)
		}
		modified, err := gatherProvenance(cfg)
		if err != nil {
			t.Fatalf("gatherProvenance after modification: %v", err)
		}
		if modified.SnapshotDigest == provenance.SnapshotDigest {
			t.Fatal("changing a file inside the snapshot did not change its " +
				"digest; the immutability re-verification would detect nothing")
		}
		kind, _ := detectDrift(provenance, modified)
		if kind != driftSnapshot {
			t.Fatalf("detectDrift reported %q, want %q", kind, driftSnapshot)
		}
	})
}

// TestQuarantinedTreeIsRefused covers the marker files.
func TestQuarantinedTreeIsRefused(t *testing.T) {
	for _, marker := range quarantineMarkers {
		t.Run(marker, func(t *testing.T) {
			cfg := provenanceConfig(t)
			// Control first: the tree is accepted before the marker exists,
			// so the refusal below is attributable to the marker and not to
			// some unrelated property of the staged tree.
			if _, err := gatherProvenance(cfg); err != nil {
				t.Fatalf("the tree was already refused before the marker: %v", err)
			}
			path := filepath.Join(cfg.SnapshotRoot, marker)
			if err := os.WriteFile(path, []byte("set aside\n"), 0o600); err != nil {
				t.Fatalf("write marker: %v", err)
			}
			_, err := gatherProvenance(cfg)
			if err == nil {
				t.Fatalf("a tree carrying %s was accepted", marker)
			}
			if !errors.Is(err, errQuarantined) {
				t.Fatalf("refusal was %v, want a quarantine refusal", err)
			}
		})
	}
}

// TestQuarantineMarkerOneLevelDownIsRefused covers a marker written by the
// accepted runner into one of its own matrix roots.
func TestQuarantineMarkerOneLevelDownIsRefused(t *testing.T) {
	cfg := provenanceConfig(t)
	nested := filepath.Join(cfg.SnapshotRoot, "matrices")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatalf("create nested directory: %v", err)
	}
	if _, err := gatherProvenance(cfg); err != nil {
		t.Fatalf("the tree was refused before the marker existed: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(nested, "INVALID"), []byte("reason=x\n"), 0o600,
	); err != nil {
		t.Fatalf("write nested marker: %v", err)
	}
	if _, err := gatherProvenance(cfg); !errors.Is(err, errQuarantined) {
		t.Fatalf("a nested INVALID marker produced %v, want a quarantine refusal",
			err)
	}
}

// TestUnionFilesystemIsRefused exercises the refusal predicate directly.
//
// Mounting an overlayfs inside a unit test would need root and a kernel
// feature, so the syscall-facing half of this is genuinely not covered here:
// probeMount's magic-number reading is exercised only by running on a real
// filesystem. The DECISION taken on its answer is what is tested, and the gap
// is named rather than implied away.
func TestUnionFilesystemIsRefused(t *testing.T) {
	for _, name := range []string{"overlay", "overlay2", "aufs", "ecryptfs", "fuse"} {
		facts := mountFacts{FilesystemType: name, Available: true}
		reason, refuse := facts.refusalReason()
		if !refuse {
			t.Errorf("%s was accepted as a snapshot filesystem", name)
		}
		if !strings.Contains(reason, name) {
			t.Errorf("refusal for %s does not name it: %q", name, reason)
		}
	}
	for _, name := range []string{"ext4", "xfs", "btrfs", "apfs", "squashfs"} {
		facts := mountFacts{FilesystemType: name, Available: true}
		if _, refuse := facts.refusalReason(); refuse {
			t.Errorf("%s was refused, but only union and interposing "+
				"filesystems should be", name)
		}
	}
	// An unavailable probe never refuses on filesystem grounds;
	// gatherProvenance refuses it separately, for the explicit reason that
	// the gate cannot be enforced at all.
	if _, refuse := (mountFacts{Available: false}).refusalReason(); refuse {
		t.Error("an unavailable probe produced a filesystem refusal")
	}
}

// TestWritableSnapshotIsRefusedByDefault proves the opt-out is required.
func TestWritableSnapshotIsRefusedByDefault(t *testing.T) {
	cfg := provenanceConfig(t)
	cfg.AllowWritableSnapshot = false
	_, err := gatherProvenance(cfg)
	if err == nil {
		t.Fatal("a writable snapshot mount was accepted without the opt-out")
	}
	if !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("refusal was %v, want one naming the read-only requirement", err)
	}
}

// TestSymlinkedPathComponentIsRefused proves a redirectable path is refused
// rather than resolved.
func TestSymlinkedPathComponentIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need elevation on Windows")
	}
	cfg := provenanceConfig(t)
	base := filepath.Dir(cfg.SnapshotRoot)
	link := filepath.Join(base, "snapshot-link")
	if err := os.Symlink(cfg.SnapshotRoot, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	cfg.SnapshotRoot = link
	_, err := gatherProvenance(cfg)
	if err == nil {
		t.Fatal("a symlinked snapshot root was accepted; the tree it names " +
			"can be redirected after it has been pinned")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("refusal was %v, want one naming the symbolic link", err)
	}
}

// TestNonRegularFileInSnapshotIsRefused proves the manifest refuses rather than
// skips.
//
// A walk that skipped a fifo would hash identically before and after one was
// added, so the immutability re-verification would not see it appear.
func TestNonRegularFileInSnapshotIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need elevation on Windows")
	}
	cfg := provenanceConfig(t)
	before, err := gatherProvenance(cfg)
	if err != nil {
		t.Fatalf("clean tree was refused: %v", err)
	}
	link := filepath.Join(cfg.SnapshotRoot, "sneaky")
	if err := os.Symlink("/etc/passwd", link); err != nil {
		t.Fatalf("create symlink inside the snapshot: %v", err)
	}
	after, err := gatherProvenance(cfg)
	if err == nil {
		t.Fatalf("a snapshot containing a symlink was accepted with digest %s "+
			"(was %s)", after.SnapshotDigest, before.SnapshotDigest)
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("refusal was %v, want one naming the non-regular file", err)
	}
}

// TestEmptySnapshotIsRefused closes the digest-collision-with-nothing hole.
func TestEmptySnapshotIsRefused(t *testing.T) {
	cfg := provenanceConfig(t)
	for _, name := range []string{"go.mod", "scripts/aicore_phase1_auto_matrix.sh"} {
		if err := os.Remove(filepath.Join(cfg.SnapshotRoot, name)); err != nil {
			t.Fatalf("empty the snapshot: %v", err)
		}
	}
	_, err := gatherProvenance(cfg)
	if err == nil {
		t.Fatal("an empty snapshot was accepted; it digests identically " +
			"whether it is empty or unreadable")
	}
	if !strings.Contains(err.Error(), "no regular files") {
		t.Fatalf("refusal was %v, want one naming the empty tree", err)
	}
}

// TestCustodySeparationFindsSeedsAndNeverQuotesThem.
func TestCustodySeparationFindsSeedsAndNeverQuotesThem(t *testing.T) {
	const value = "0123456789abcdef-the-actual-secret"
	environment := []string{
		"PATH=/usr/bin",
		"WINN_FINALIZER_SEED=" + value,
		"PROJECT_SIGNING_KEY=" + value,
	}
	findings := checkCustodySeparation(environment, nil)
	if len(findings) != 2 {
		t.Fatalf("found %d custody problems, want 2: %+v", len(findings), findings)
	}
	for _, finding := range findings {
		if strings.Contains(finding.Detail, value) {
			t.Fatalf("a custody finding quotes the secret value: %q",
				finding.Detail)
		}
	}
	if len(checkCustodySeparation([]string{"PATH=/usr/bin"}, nil)) != 0 {
		t.Fatal("a clean environment produced a finding")
	}

	directory := t.TempDir()
	if len(checkCustodySeparation(nil, []string{directory})) != 0 {
		t.Fatal("an empty directory produced a finding")
	}
	seed := filepath.Join(directory, "finalizer.seed")
	if err := os.WriteFile(seed, []byte(value), 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	findings = checkCustodySeparation(nil, []string{directory})
	if len(findings) != 1 {
		t.Fatalf("a finalizer seed on disk produced %d findings", len(findings))
	}
	if strings.Contains(findings[0].Detail, value) {
		t.Fatalf("the file finding quotes the seed: %q", findings[0].Detail)
	}
}

func TestConfigurationDigestBindsExactEnvironmentAndRuntimeOptions(t *testing.T) {
	cfg := provenanceConfig(t)
	cfg.ChildEnvironment = []string{
		"PATH=/usr/bin:/bin",
		"MATRIX_ID=phase1",
		"LOW_ENTROPY_VALUE=do-not-print-me",
	}
	baseline, err := configurationDigest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	reordered := cfg
	reordered.ChildEnvironment = []string{
		"LOW_ENTROPY_VALUE=do-not-print-me",
		"PATH=/usr/bin:/bin",
		"MATRIX_ID=phase1",
	}
	reorderedDigest, err := configurationDigest(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if reorderedDigest != baseline {
		t.Fatal("environment ordering changed the canonical digest")
	}

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"environment value", func(c *Config) {
			c.ChildEnvironment[2] = "LOW_ENTROPY_VALUE=different"
		}},
		{"cadence", func(c *Config) { c.Cadence++ }},
		{"kill grace", func(c *Config) { c.KillGrace++ }},
		{"sample interval", func(c *Config) { c.SampleInterval++ }},
		{"proc root", func(c *Config) { c.ProcRoot = "/alternate-proc" }},
		{"controller output", func(c *Config) { c.MaxControllerOutput++ }},
		{"resource bound", func(c *Config) { c.Bounds.MaxThreads++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modified := cfg
			modified.ChildEnvironment = append(
				[]string(nil), cfg.ChildEnvironment...,
			)
			test.mutate(&modified)
			got, err := configurationDigest(modified)
			if err != nil {
				t.Fatal(err)
			}
			if got == baseline {
				t.Fatalf("%s did not change configuration digest", test.name)
			}
			kind, detail := detectDrift(
				Provenance{ConfigurationDigest: baseline},
				Provenance{ConfigurationDigest: got},
			)
			if kind != driftConfig {
				t.Fatalf("drift kind=%q, want %q", kind, driftConfig)
			}
			if strings.Contains(detail, "do-not-print-me") ||
				strings.Contains(detail, "different") {
				t.Fatalf("configuration drift leaked an environment value: %q",
					detail)
			}
		})
	}
}

// TestPreflightRefusesWhenCustodySeparationIsBroken proves the check is wired
// into the gate rather than merely available.
func TestPreflightRefusesWhenCustodySeparationIsBroken(t *testing.T) {
	cfg := provenanceConfig(t)
	if _, err := preflight(cfg, []string{"PATH=/usr/bin"}); err != nil {
		t.Fatalf("preflight refused a clean host: %v", err)
	}
	_, err := preflight(cfg, []string{
		"PATH=/usr/bin", "WINN_FINALIZER_SEED=deadbeef",
	})
	if err == nil {
		t.Fatal("preflight accepted a host holding a finalizer seed")
	}
	if !strings.Contains(err.Error(), "custody separation") {
		t.Fatalf("refusal was %v, want one naming custody separation", err)
	}
	if strings.Contains(err.Error(), "deadbeef") {
		t.Fatalf("the refusal quotes the seed value: %v", err)
	}
}

// TestRequireDisjointDoesNotConfusePrefixesWithNesting.
func TestRequireDisjointDoesNotConfusePrefixesWithNesting(t *testing.T) {
	if err := requireDisjoint("a", "/srv/soak-state", "b", "/srv/soak-evidence"); err != nil {
		t.Errorf("sibling directories sharing a name prefix were refused: %v", err)
	}
	if err := requireDisjoint("a", "/srv/soak", "b", "/srv/soak/state"); err == nil {
		t.Error("a nested directory was accepted as disjoint")
	}
	if err := requireDisjoint("a", "/srv/soak/state", "b", "/srv/soak"); err == nil {
		t.Error("nesting was accepted in the other direction")
	}
	if err := requireDisjoint("a", "/srv/soak", "b", "/srv/soak"); err == nil {
		t.Error("identical directories were accepted as disjoint")
	}
}
