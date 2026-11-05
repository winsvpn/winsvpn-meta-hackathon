// The controller-side finalization script, exercised end to end against real
// binaries and real files.
//
// The properties under test are ordering properties, and ordering is where this
// step is fragile: sealing is create-once, so a run that publishes the
// checkpoint and then fails has spent something it cannot spend again. If the
// script checked its output paths after sealing, a single interrupted run would
// wedge the evidence permanently — the checkpoint would exist, the archive
// would exist, and no retry could ever complete.
package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/auditcheckpoint"
)

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found at %s: %v", root, err)
	}
	return root
}

// buildBinary compiles one of this module's commands so the script under test
// runs against the real thing rather than a stub.
func buildBinary(t *testing.T, moduleRoot, pkg, output string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), output)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(
		ctx, "go", "build", "-o", path, "./cmd/"+pkg,
	)
	command.Dir = moduleRoot
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, out)
	}
	return path
}

type finalizeFixture struct {
	script    string
	auditBin  string
	verifyBin string
	evidence  string
	seed      string
	runID     string
	producer  string
}

func newFinalizeFixture(t *testing.T) *finalizeFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell script")
	}
	root := moduleRoot(t)
	directory, seedPath := newSealedEvidence(t)
	// The smoke's evidence needs the carrier files the conservation report
	// reconciles; this test exercises the script's ordering and publication,
	// so the verifier stage is pointed at a stub. Everything the CHECKPOINT
	// depends on is real: real audit log, real manifest, real winn-audit.
	verifyStub := filepath.Join(t.TempDir(), "verify-stub")
	if err := os.WriteFile(
		verifyStub, []byte("#!/bin/sh\nexit 0\n"), 0o755, // #nosec G302
	); err != nil {
		t.Fatal(err)
	}
	return &finalizeFixture{
		script:    filepath.Join(root, "scripts", "finalize_audit_checkpoint.sh"),
		auditBin:  buildBinary(t, root, "winn-audit", "winn-audit"),
		verifyBin: verifyStub,
		evidence:  directory,
		seed:      seedPath,
		runID:     bindingRunID,
		producer:  bindingProducer,
	}
}

func (f *finalizeFixture) run(t *testing.T) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/sh", f.script,
		f.auditBin, f.verifyBin, f.evidence, f.runID, f.producer, f.seed,
	)
	out, err := command.CombinedOutput()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return exitError.ExitCode(), string(out)
		}
		t.Fatalf("run finalizer: %v\n%s", err, out)
	}
	return 0, string(out)
}

func (f *finalizeFixture) checkpointPath() string {
	return filepath.Join(f.evidence, auditcheckpoint.FileName)
}

func (f *finalizeFixture) archivePath() string {
	return f.evidence + ".closed.tar.gz"
}

func TestFinalizeScriptClosesAndPublishes(t *testing.T) {
	fixture := newFinalizeFixture(t)
	exit, out := fixture.run(t)
	if exit != 0 {
		t.Fatalf("finalization failed:\n%s", out)
	}
	// One artifact, no pin sidecar: the digest is reported on stdout and bound
	// by whatever records it. Two files published by two link() calls were the
	// non-atomic step this design removed.
	for _, expected := range []string{
		fixture.checkpointPath(),
		fixture.archivePath(),
	} {
		if _, err := os.Lstat(expected); err != nil {
			t.Fatalf("finalization did not publish %s: %v", expected, err)
		}
	}
	if !strings.Contains(out, "CLOSED_ARCHIVE_SHA256=") {
		t.Fatalf("finalization printed no closed-archive digest:\n%s", out)
	}
	if _, err := os.Lstat(fixture.archivePath() + ".sha256"); !os.IsNotExist(err) {
		t.Fatal(
			"a pin sidecar was published; publication must be one atomic " +
				"artifact, not two independent links",
		)
	}
	// No temporary files survive a successful run.
	entries, err := os.ReadDir(filepath.Dir(fixture.evidence))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".winn-closed-") {
			t.Fatalf("a temporary archive survived: %s", entry.Name())
		}
	}
}

// TestFinalizeScriptRefusesAForeignIncumbentArchive is the fail-closed rule at
// the publication end.
//
// It replaces an earlier test that required the destination to be refused
// BEFORE the checkpoint was sealed. That ordering is no longer possible, and no
// longer needed. Not possible, because deciding whether an incumbent archive is
// this run's own requires rebuilding it, which requires the checkpoint to exist.
// Not needed, because sealing is create-once with exact-match resume: a second
// attempt over the same evidence reproduces the same checkpoint and costs
// nothing, so reaching the conflict a step later spends nothing that cannot be
// spent again.
//
// What must still hold is that a DIFFERENT artifact at the destination is never
// reconciled, and nothing claims success.
func TestFinalizeScriptRefusesAForeignIncumbentArchive(t *testing.T) {
	fixture := newFinalizeFixture(t)
	if err := os.WriteFile(
		fixture.archivePath(), []byte("a previous run's archive\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	exit, out := fixture.run(t)
	if exit == 0 {
		t.Fatalf("finalization reconciled a foreign incumbent archive:\n%s", out)
	}
	if !strings.Contains(out, "different archive") {
		t.Fatalf("refusal has the wrong shape:\n%s", out)
	}
	content, err := os.ReadFile(fixture.archivePath()) // #nosec G304 -- temp
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "a previous run's archive\n" {
		t.Fatal("the incumbent archive was overwritten")
	}
}

// TestFinalizeScriptResumesAnIdenticalIncumbentArchive is the other half: an
// interrupted run that already published its artifact must be able to finish.
func TestFinalizeScriptResumesAnIdenticalIncumbentArchive(t *testing.T) {
	fixture := newFinalizeFixture(t)
	if exit, out := fixture.run(t); exit != 0 {
		t.Fatalf("the first run must succeed:\n%s", out)
	}
	before, err := os.ReadFile(fixture.archivePath()) // #nosec G304 -- temp
	if err != nil {
		t.Fatal(err)
	}
	exit, out := fixture.run(t)
	if exit != 0 {
		t.Fatalf(
			"a re-run over an already-published artifact failed (%s); an "+
				"interrupted finalization would be unrecoverable", out,
		)
	}
	after, err := os.ReadFile(fixture.archivePath()) // #nosec G304 -- temp
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the re-run republished a different artifact")
	}
}

// TestFinalizeScriptRefusesMalformedEvidenceBeforeSealing covers the same rule
// for the input side: evidence whose manifest does not describe it must be
// rejected before anything attests to it.
func TestFinalizeScriptRefusesMalformedEvidenceBeforeSealing(t *testing.T) {
	fixture := newFinalizeFixture(t)
	if err := os.WriteFile(
		filepath.Join(fixture.evidence, auditcheckpoint.EnvironmentName),
		[]byte("source_digest="+bindingProducer+"\ntampered=yes\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	exit, out := fixture.run(t)
	if exit == 0 {
		t.Fatalf("finalization closed evidence its manifest disowns:\n%s", out)
	}
	if !strings.Contains(out, "base manifest does not match") {
		t.Fatalf("refusal has the wrong shape:\n%s", out)
	}
	if _, err := os.Lstat(fixture.checkpointPath()); !os.IsNotExist(err) {
		t.Fatal("a checkpoint was sealed over evidence that failed preflight")
	}
}

// TestFinalizeScriptIsRetrySafeAfterACrash is the recovery property.
//
// The checkpoint is create-once by design, so a run that published it and then
// died is exactly the state a naive "refuse if a checkpoint exists" rule would
// make unrecoverable. The retry must verify the existing checkpoint against the
// same external bindings and carry on.
func TestFinalizeScriptIsRetrySafeAfterACrash(t *testing.T) {
	fixture := newFinalizeFixture(t)

	// Simulate the crash: the checkpoint was published, nothing else was.
	if err := seal(
		fixture.evidence, bindingLogName, "evidence-manifest.sha256",
		fixture.runID, fixture.producer, fixture.seed,
	); err != nil {
		t.Fatalf("stage the interrupted run: %v", err)
	}
	before, err := os.ReadFile(fixture.checkpointPath()) // #nosec G304 -- temp
	if err != nil {
		t.Fatal(err)
	}

	exit, out := fixture.run(t)
	if exit != 0 {
		t.Fatalf(
			"a retry after an interrupted run could not complete; the "+
				"create-once checkpoint would have wedged the evidence "+
				"permanently:\n%s", out,
		)
	}
	if !strings.Contains(out, "already exists; verifying it before resuming") {
		t.Fatalf("the retry did not resume from the existing checkpoint:\n%s", out)
	}
	after, err := os.ReadFile(fixture.checkpointPath()) // #nosec G304 -- temp
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the retry rewrote the checkpoint the first run published")
	}
	if _, err := os.Lstat(fixture.archivePath()); err != nil {
		t.Fatalf("the retry did not publish the closed archive: %v", err)
	}
}

// TestFinalizeScriptRefusesAForeignCheckpointOnRetry is the limit of the resume
// rule: resuming is allowed only when the existing checkpoint is the one this
// run would have made. A checkpoint naming a different run must not be adopted.
func TestFinalizeScriptRefusesAForeignCheckpointOnRetry(t *testing.T) {
	fixture := newFinalizeFixture(t)
	if err := seal(
		fixture.evidence, bindingLogName, "evidence-manifest.sha256",
		"a-completely-different-run", fixture.producer, fixture.seed,
	); err != nil {
		t.Fatalf("stage the foreign checkpoint: %v", err)
	}
	exit, out := fixture.run(t)
	if exit == 0 {
		t.Fatalf("finalization adopted another run's checkpoint:\n%s", out)
	}
	if !strings.Contains(out, "run identity mismatch") {
		t.Fatalf("refusal has the wrong shape:\n%s", out)
	}
	if _, err := os.Lstat(fixture.archivePath()); !os.IsNotExist(err) {
		t.Fatal("an archive was published over a foreign checkpoint")
	}
}
