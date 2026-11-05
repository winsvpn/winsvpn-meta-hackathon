// AUDIT-CLOSE, producer-side state machine — asserted against the real shell
// scripts and the real files they leave on disk.
//
// The gap these tests exist to close is specific. Marking pre-checkpoint
// evidence "non-promotional" inside a file named COMPLETE, or inside
// batches/<key>.done, protects nothing: a consumer that predates the checkpoint
// ignores the unknown key and reads the familiar filename as completion.
// Safety has to be the default, which means the pre-checkpoint state must not
// produce a file that LOOKS finished in the first place.
//
// So these tests do not ask a Go function for its opinion. They run the actual
// orchestration and then look at the filesystem.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProducerRunLeavesNoCompletionArtifacts runs the real conservation-smoke
// wrapper to a successful finish with stub binaries, then inspects the run root
// it produced.
//
// A cooperative run must leave: evidence, and an explicit closed-pending state.
// It must NOT leave: a checkpoint, a conservation verdict, or anything a
// downstream consumer would read as a finished, promotable artifact.
func TestProducerRunLeavesNoCompletionArtifacts(t *testing.T) {
	environment := ncWrapperEnvironment(t)
	fixture := ncNewWrapperFixture(t,
		ncCooperativeSmokeStub, "exit 0\n", "exit 0\n")
	exit, out := ncRunCommand(t, environment, "/bin/sh", fixture.arguments()...)
	if exit != 0 {
		t.Fatalf("a cooperative producer run must succeed:\n%s", out)
	}

	// The producing host really did produce evidence.
	evidence := filepath.Join(fixture.runRoot, "evidence")
	if info, err := os.Stat(evidence); err != nil || !info.IsDir() {
		t.Fatalf("the run produced no evidence directory: %v", err)
	}

	// And really did not close it.
	for _, forbidden := range []string{
		"evidence/audit-checkpoint.json",
		"COMPLETE",
		"DONE",
		"result.done",
	} {
		if _, err := os.Lstat(
			filepath.Join(fixture.runRoot, forbidden),
		); !os.IsNotExist(err) {
			t.Fatalf(
				"a producer-side run created %s; a consumer that predates the "+
					"checkpoint would read it as finished evidence", forbidden,
			)
		}
	}
	if err := filepath.WalkDir(fixture.runRoot, func(
		path string, entry os.DirEntry, err error,
	) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".done") || name == "COMPLETE" {
			t.Fatalf(
				"a producer-side run created a completion-shaped artifact: %s",
				path,
			)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(
		out, "AUDIT_CHECKPOINT_STATE=closed-pending-controller-finalization",
	) {
		t.Fatalf("the run did not declare itself unclosed:\n%s", out)
	}
}

// TestMatrixDriverRefusesToAnchorPreCheckpointEvidence runs the real matrix
// driver and proves it produces nothing at all when asked to anchor.
//
// Anchoring is the one irreversible step: it commits two independent external
// providers to an archive. Doing that to evidence whose trail has never been
// closed would produce a durable, externally witnessed attestation to something
// nobody had checked, and no later flag could retract it.
func TestMatrixDriverRefusesToAnchorPreCheckpointEvidence(t *testing.T) {
	moduleRoot := ncModuleRoot(t)
	script := filepath.Join(moduleRoot, "scripts", "aicore_phase1_auto_matrix.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("matrix driver missing: %v", err)
	}
	stubs := t.TempDir()
	// Both stubs record every invocation. The point of the assertion below is
	// not merely that the run failed — a run that died on any of the fifteen
	// unstubbed executables it would otherwise validate would also fail, and a
	// test that could not tell those apart would prove nothing. These witnesses
	// prove the refusal happened BEFORE any work was attempted.
	auditWitness := filepath.Join(stubs, "audit-invoked")
	harnessWitness := filepath.Join(stubs, "harness-invoked")
	auditStub := filepath.Join(stubs, "winn-audit")
	ncWriteStub(t, auditStub, ": > "+auditWitness+"\nexit 0\n")
	harness := filepath.Join(stubs, "harness.sh")
	ncWriteStub(t, harness, ": > "+harnessWitness+"\nexit 0\n")

	matrixRoot := filepath.Join(t.TempDir(), "matrix")
	// Nothing else is supplied: no source digest, no engine digest, no stubs
	// for the fifteen executables the driver would otherwise validate. The
	// refusal must fire without any of them, because a run that is not
	// permitted to proceed should be told that, not told which prerequisite it
	// happens to be missing today.
	environment := append(ncWrapperEnvironmentOrHost(t),
		"MATRIX_ID=audit-close-anchor-refusal",
		"MATRIX_ROOT="+matrixRoot,
		"ANCHOR_MODE=dual-provider-v1",
		"AUDIT_BIN="+auditStub,
		"HARNESS="+harness,
	)
	exit, out := ncRunCommand(t, environment, "/bin/sh", script)
	if exit == 0 {
		t.Fatalf(
			"the matrix driver anchored pre-checkpoint evidence:\n%s", out,
		)
	}

	// The exact refusal, not "some error happened". This is what distinguishes
	// the policy refusal under test from an unrelated missing dependency.
	for _, phrase := range []string{
		"AUDIT-CLOSE",
		"dual-provider anchoring must run on the controller",
		"finalize_audit_checkpoint.sh",
		"not promotable",
	} {
		if !strings.Contains(out, phrase) {
			t.Fatalf(
				"the driver failed, but not with the AUDIT-CLOSE refusal "+
					"(missing %q). A failure for an unrelated reason would "+
					"make this test vacuous:\n%s", phrase, out,
			)
		}
	}

	// And it refused before doing anything: no dependency validation, no leak
	// scan, no batch.
	for name, witness := range map[string]string{
		"winn-audit":        auditWitness,
		"the batch harness": harnessWitness,
	} {
		if _, err := os.Lstat(witness); !os.IsNotExist(err) {
			t.Fatalf(
				"%s was invoked before the AUDIT-CLOSE refusal; the policy "+
					"check is not running early enough to be a refusal rather "+
					"than a late abort", name,
			)
		}
	}

	// Nothing that looks like progress, let alone completion, may survive.
	for _, forbidden := range []string{
		"COMPLETE",
		"PRODUCER_CLOSED_PENDING",
		"anchors",
		"batches",
		"evidence",
	} {
		if _, err := os.Lstat(
			filepath.Join(matrixRoot, forbidden),
		); !os.IsNotExist(err) {
			t.Fatalf("the refused run left %s behind", forbidden)
		}
	}
	if _, err := os.Lstat(matrixRoot); !os.IsNotExist(err) {
		t.Fatal("the refused run created a matrix root")
	}
}

// ncWrapperEnvironmentOrHost returns an environment safe to append matrix
// variables to: ncWrapperEnvironment returns nil when the host already has
// sha256sum, which would discard the inherited PATH.
func ncWrapperEnvironmentOrHost(t *testing.T) []string {
	t.Helper()
	if environment := ncWrapperEnvironment(t); environment != nil {
		return environment
	}
	return os.Environ()
}

// TestOrchestrationNeverWritesTerminalNames is a source-level invariant over
// the real scripts, and it exists because the filesystem tests above can only
// observe the code paths a stubbed run happens to reach.
//
// The rule it pins: no producer-side script may write batches/<key>.done, a
// COMPLETE marker, or the ordinary <evidence>.tar.gz archive. Those names are
// the controller's vocabulary, reserved for evidence that has actually been
// closed. A regression that reintroduces any of them fails here even if no
// stubbed run reaches that line.
func TestOrchestrationNeverWritesTerminalNames(t *testing.T) {
	moduleRoot := ncModuleRoot(t)
	for _, name := range []string{
		"aicore_phase1_auto_matrix.sh",
		"aicore_auto_e2e.sh",
		"aicore_conservation_smoke.sh",
	} {
		t.Run(name, func(t *testing.T) {
			content, err := os.ReadFile( // #nosec G304 -- repository script
				filepath.Join(moduleRoot, "scripts", name),
			)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{
				`.done"`,
				`/COMPLETE"`,
				`COMPLETE.tmp`,
				`{EVIDENCE_DIR}.tar.gz`,
				`$evidence_directory.tar.gz`,
			} {
				for index, line := range strings.Split(string(content), "\n") {
					if strings.HasPrefix(strings.TrimSpace(line), "#") {
						continue
					}
					if strings.Contains(line, forbidden) {
						t.Fatalf(
							"%s:%d writes the controller's terminal vocabulary "+
								"%q on the producing host:\n\t%s",
							name, index+1, forbidden, strings.TrimSpace(line),
						)
					}
				}
			}
		})
	}
}
