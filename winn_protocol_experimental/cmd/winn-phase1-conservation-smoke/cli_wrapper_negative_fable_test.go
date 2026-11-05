// Codex negative controls that only exist at the process boundary:
//
//   - wrong/missing artifact (binary) digest and wrong/missing source digest
//     through the real CLI flags of a freshly built smoke binary, including
//     the unstamped-build refusal and nonzero-exit propagation from the smoke
//     itself;
//   - wrapper nonzero-exit-status propagation through the REAL
//     scripts/aicore_conservation_smoke.sh executed with stub binaries,
//     without editing the script (the Opus lane owns it): a failing smoke, a
//     failing audit-chain verifier (F6), and a failing conservation verifier
//     must each surface as a nonzero wrapper exit with the right attribution,
//     and the F6 audit step must run BEFORE the conservation report.
//
// The loopback backend trick used throughout: a UDP dial to 127.0.0.1:9
// always succeeds, so requireUnreachable fails fast. Reaching THAT error
// proves every gate ordered before it admitted the run; never reaching it
// proves a gate refused first. This keeps every subtest seconds-fast instead
// of driving a full QUIC smoke.
package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ncStampedSourceDigest is the 64-lower-hex source digest baked into the
// stamped test build via the same -ldflags mechanism the release script uses.
var ncStampedSourceDigest = strings.Repeat("ad", 32)

func ncModuleRoot(t *testing.T) string {
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

func ncGoBuildSmoke(t *testing.T, moduleRoot, output, stamp string) {
	t.Helper()
	arguments := []string{"build", "-trimpath"}
	if stamp != "" {
		arguments = append(arguments, "-ldflags", "-X main.sourceDigest="+stamp)
	}
	arguments = append(
		arguments, "-o", output, "./cmd/winn-phase1-conservation-smoke",
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", arguments...)
	command.Dir = moduleRoot
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
}

// ncRunCommand runs a process and returns its exit code and combined output.
// Only genuine start failures are fatal; a nonzero exit is a result.
func ncRunCommand(
	t *testing.T,
	environment []string,
	name string,
	arguments ...string,
) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, name, arguments...)
	if environment != nil {
		command.Env = environment
	}
	out, err := command.CombinedOutput()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return exitError.ExitCode(), string(out)
		}
		t.Fatalf("%s failed to run at all: %v\n%s", name, err, out)
	}
	return 0, string(out)
}

func TestNegativeControlSmokeCLIDigestGates(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the smoke binary; skipped in -short")
	}
	moduleRoot := ncModuleRoot(t)
	binaries := t.TempDir()
	stamped := filepath.Join(binaries, "smoke-stamped")
	unstamped := filepath.Join(binaries, "smoke-unstamped")
	ncGoBuildSmoke(t, moduleRoot, stamped, ncStampedSourceDigest)
	ncGoBuildSmoke(t, moduleRoot, unstamped, "")
	stampedDigest, err := sha256File(stamped)
	if err != nil {
		t.Fatal(err)
	}
	unstampedDigest, err := sha256File(unstamped)
	if err != nil {
		t.Fatal(err)
	}
	const reachableBackend = "127.0.0.1:9"

	newDirectories := func(t *testing.T) (string, string) {
		base := t.TempDir()
		return filepath.Join(base, "evidence"), filepath.Join(base, "work")
	}
	requireNoEvidence := func(t *testing.T, evidence string) {
		t.Helper()
		if _, statErr := os.Stat(evidence); !os.IsNotExist(statErr) {
			t.Fatal("evidence directory exists after a refused run")
		}
	}

	t.Run("WrongBinaryDigestRefusedWithExitOne", func(t *testing.T) {
		evidence, work := newDirectories(t)
		exit, out := ncRunCommand(t, nil, stamped,
			"-evidence-dir", evidence, "-work-dir", work,
			"-unroutable-backend", reachableBackend,
			"-expected-binary-sha256", strings.Repeat("0", 64),
			"-expected-source-digest", ncStampedSourceDigest,
		)
		if exit != 1 {
			t.Fatalf("exit=%d on a wrong binary digest, want 1\n%s", exit, out)
		}
		if !strings.Contains(out, "runner expected") ||
			!strings.Contains(out, "CONSERVATION_SMOKE_FAIL") {
			t.Fatalf("refusal output has the wrong shape:\n%s", out)
		}
		requireNoEvidence(t, evidence)
	})

	t.Run("MissingBinaryDigestRefused", func(t *testing.T) {
		evidence, work := newDirectories(t)
		exit, out := ncRunCommand(t, nil, stamped,
			"-evidence-dir", evidence, "-work-dir", work,
			"-unroutable-backend", reachableBackend,
			"-expected-source-digest", ncStampedSourceDigest,
		)
		if exit == 0 {
			t.Fatalf("smoke ran with no expected binary digest\n%s", out)
		}
		if strings.Contains(out, "reachable on this host") {
			t.Fatalf(
				"REGRESSION to pre-F4 behavior: execution passed the "+
					"binding gate without a binary digest\n%s", out,
			)
		}
		if !strings.Contains(out, "-expected-binary-sha256 is required") {
			t.Fatalf("missing-binary-digest refusal has the wrong shape:\n%s", out)
		}
		requireNoEvidence(t, evidence)
	})

	t.Run("WrongSourceDigestRefused", func(t *testing.T) {
		evidence, work := newDirectories(t)
		exit, out := ncRunCommand(t, nil, stamped,
			"-evidence-dir", evidence, "-work-dir", work,
			"-unroutable-backend", reachableBackend,
			"-expected-binary-sha256", stampedDigest,
			"-expected-source-digest", strings.Repeat("0", 64),
		)
		if exit == 0 {
			t.Fatalf("a wrong expected source digest was accepted\n%s", out)
		}
		if !strings.Contains(out, "built from source manifest") {
			t.Fatalf("wrong-source-digest refusal has the wrong shape:\n%s", out)
		}
		requireNoEvidence(t, evidence)
	})

	t.Run("MissingSourceDigestRefused", func(t *testing.T) {
		evidence, work := newDirectories(t)
		exit, out := ncRunCommand(t, nil, stamped,
			"-evidence-dir", evidence, "-work-dir", work,
			"-unroutable-backend", reachableBackend,
			"-expected-binary-sha256", stampedDigest,
		)
		if exit == 0 {
			t.Fatalf("smoke ran with no expected source digest\n%s", out)
		}
		if strings.Contains(out, "reachable on this host") {
			t.Fatalf(
				"F7 regression: execution passed the binding gate without "+
					"an expected source digest\n%s", out,
			)
		}
		if !strings.Contains(out, "-expected-source-digest is required") {
			t.Fatalf("missing-source-digest refusal has the wrong shape:\n%s", out)
		}
		requireNoEvidence(t, evidence)
	})

	t.Run("UnstampedBuildRefused", func(t *testing.T) {
		evidence, work := newDirectories(t)
		exit, out := ncRunCommand(t, nil, unstamped,
			"-evidence-dir", evidence, "-work-dir", work,
			"-unroutable-backend", reachableBackend,
			"-expected-binary-sha256", unstampedDigest,
			"-expected-source-digest", ncStampedSourceDigest,
		)
		if exit == 0 {
			t.Fatalf("an UNSTAMPED plain `go build` binary produced a run\n%s", out)
		}
		if !strings.Contains(out, "not stamped") {
			t.Fatalf("unstamped-build refusal has the wrong shape:\n%s", out)
		}
		requireNoEvidence(t, evidence)
	})

	t.Run("FullBindingAdmitsToTheBackendGate", func(t *testing.T) {
		// Positive ordering control: correct binary digest, correct source
		// digest — the next voice must be the backend-reachability
		// precondition, proving the binding gates admitted the run.
		evidence, work := newDirectories(t)
		exit, out := ncRunCommand(t, nil, stamped,
			"-evidence-dir", evidence, "-work-dir", work,
			"-unroutable-backend", reachableBackend,
			"-expected-binary-sha256", stampedDigest,
			"-expected-source-digest", ncStampedSourceDigest,
		)
		if exit == 0 {
			t.Fatalf("a loopback backend was accepted as unroutable\n%s", out)
		}
		if !strings.Contains(out, "reachable on this host") {
			t.Fatalf(
				"expected the backend gate to speak after full binding:\n%s", out,
			)
		}
		requireNoEvidence(t, evidence)
	})
}

// --- wrapper nonzero-exit propagation ----------------------------------------

func ncWriteStub(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// ncWrapperEnvironment returns an environment where sha256sum resolves, using
// a shasum shim only if the host lacks the real tool.
func ncWrapperEnvironment(t *testing.T) []string {
	t.Helper()
	if _, err := exec.LookPath("sha256sum"); err == nil {
		return nil
	}
	shimDirectory := t.TempDir()
	ncWriteStub(t, filepath.Join(shimDirectory, "sha256sum"),
		`exec shasum -a 256 "$@"`+"\n")
	environment := os.Environ()
	for index, entry := range environment {
		if strings.HasPrefix(entry, "PATH=") {
			environment[index] = "PATH=" + shimDirectory + ":" +
				strings.TrimPrefix(entry, "PATH=")
			return environment
		}
	}
	return append(environment, "PATH="+shimDirectory)
}

// ncWrapperFixture is one ready-to-run wrapper invocation: stub smoke, stub
// conservation verifier, stub audit verifier, a stub source manifest, and the
// digests the wrapper's own gates recompute.
type ncWrapperFixture struct {
	script         string
	smoke          string
	verify         string
	auditVerify    string
	manifest       string
	smokeDigest    string
	manifestDigest string
	runRoot        string
	verifyMarker   string
}

// ncCooperativeSmokeStub behaves the way the wrapper expects a succeeding
// smoke to: it finds its -evidence-dir/-work-dir arguments, creates the
// audit key where the wrapper's F6 step looks for it, and writes an empty
// sealed trail.
// The two winn-audit stages the wrapper runs are told apart by their mode flag,
// so each can be failed on its own and each negative control proves the stage it
// names actually fired.
const ncAuditStubRejectingChainOnly = `for argument in "$@"; do
	if [ "$argument" = -detect-finalizer-leaks ]; then
		exit 0
	fi
done
echo audit-stub-rejects-chain >&2
exit 9
`

const ncAuditStubRejectingLeakScanOnly = `for argument in "$@"; do
	if [ "$argument" = -detect-finalizer-leaks ]; then
		echo audit-stub-found-a-leak >&2
		exit 9
	fi
done
exit 0
`

const ncCooperativeSmokeStub = `evidence=""
work=""
while [ "$#" -gt 0 ]; do
	case "$1" in
	-evidence-dir) evidence="$2"; shift ;;
	-work-dir) work="$2"; shift ;;
	esac
	shift
done
mkdir -p "$evidence" "$work/pki"
: > "$work/pki/audit.key"
: > "$evidence/carrier-audit.jsonl"
exit 0
`

func ncNewWrapperFixture(
	t *testing.T,
	smokeBody, verifyBody, auditBody string,
) *ncWrapperFixture {
	t.Helper()
	stubs := t.TempDir()
	fixture := &ncWrapperFixture{
		script: filepath.Join(
			ncModuleRoot(t), "scripts", "aicore_conservation_smoke.sh",
		),
		smoke:        filepath.Join(stubs, "smoke-stub"),
		verify:       filepath.Join(stubs, "verify-stub"),
		auditVerify:  filepath.Join(stubs, "audit-stub"),
		manifest:     filepath.Join(stubs, "smoke.source.sha256"),
		runRoot:      filepath.Join(t.TempDir(), "run"),
		verifyMarker: filepath.Join(stubs, "verify-ran"),
	}
	if _, err := os.Stat(fixture.script); err != nil {
		t.Fatalf("wrapper script missing: %v", err)
	}
	ncWriteStub(t, fixture.smoke, smokeBody)
	ncWriteStub(t, fixture.verify,
		": > "+fixture.verifyMarker+"\n"+verifyBody)
	ncWriteStub(t, fixture.auditVerify, auditBody)
	if err := os.WriteFile(
		fixture.manifest, []byte("nc source manifest fixture\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	var err error
	if fixture.smokeDigest, err = sha256File(fixture.smoke); err != nil {
		t.Fatal(err)
	}
	if fixture.manifestDigest, err = sha256File(fixture.manifest); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *ncWrapperFixture) arguments() []string {
	return []string{
		fixture.script, fixture.smoke, fixture.verify, fixture.auditVerify,
		fixture.runRoot, fixture.smokeDigest, fixture.manifest,
		fixture.manifestDigest,
	}
}

// The wrapper is the Opus lane's file; these tests only EXECUTE it, with stub
// binaries, to prove that a nonzero exit from any stage propagates instead of
// being laundered into success, and that the F6 audit-chain step gates the
// conservation report.
func TestNegativeControlWrapperExitStatusPropagation(t *testing.T) {
	environment := ncWrapperEnvironment(t)

	t.Run("SmokeFailurePropagates", func(t *testing.T) {
		fixture := ncNewWrapperFixture(t,
			"echo smoke-stub-fired >&2\nexit 7\n", "exit 0\n", "exit 0\n")
		exit, out := ncRunCommand(t, environment,
			"/bin/sh", fixture.arguments()...)
		if exit == 0 {
			t.Fatalf("wrapper exited 0 over a smoke that exited 7\n%s", out)
		}
		if !strings.Contains(out, "conservation smoke failed") {
			t.Fatalf("wrapper did not attribute the failure to the smoke:\n%s", out)
		}
	})

	t.Run("AuditChainFailureStopsTheRun", func(t *testing.T) {
		// F6: a failing HMAC/chain verification must stop the run. The stub
		// distinguishes the two winn-audit stages, because the wrapper now runs
		// the finalizer-leak scan before the writer and the chain verification
		// after it, and a stub that failed both would prove only that the
		// earlier one fired.
		fixture := ncNewWrapperFixture(t,
			ncCooperativeSmokeStub, "exit 0\n", ncAuditStubRejectingChainOnly)
		exit, out := ncRunCommand(t, environment,
			"/bin/sh", fixture.arguments()...)
		if exit == 0 {
			t.Fatalf("wrapper exited 0 over a rejected audit chain\n%s", out)
		}
		if !strings.Contains(out, "audit verifier rejected the sealed carrier trail") {
			t.Fatalf(
				"wrapper did not attribute the failure to the audit "+
					"verifier:\n%s", out,
			)
		}
	})

	t.Run("FinalizerLeakOnTheWriterHostStopsTheRun", func(t *testing.T) {
		// AUDIT-CLOSE: the leak scan runs BEFORE the smoke, so a producing host
		// carrying finalizer material never gets to write a trail at all.
		fixture := ncNewWrapperFixture(t,
			ncCooperativeSmokeStub, "exit 0\n", ncAuditStubRejectingLeakScanOnly)
		exit, out := ncRunCommand(t, environment,
			"/bin/sh", fixture.arguments()...)
		if exit == 0 {
			t.Fatalf("wrapper exited 0 over a leaking host\n%s", out)
		}
		if !strings.Contains(
			out, "finalizer material was found on the audit writer's host",
		) {
			t.Fatalf("wrapper did not attribute the failure to the scan:\n%s", out)
		}
		if strings.Contains(out, "forcing every carrier abort reason") {
			t.Fatal(
				"the smoke ran despite finalizer material being present; the " +
					"trail it wrote could have been closed by the party it audits",
			)
		}
	})

	// AUDIT-CLOSE state machine, producer side.
	//
	// The wrapper no longer runs the conservation verifier at all. It cannot:
	// acceptance now requires the terminal checkpoint, and the checkpoint cannot
	// be created on this host without handing the audit writer the credential
	// that constrains it. A cooperative run therefore ends CLOSED-PENDING, and
	// this test exists to make sure nobody quietly restores a producer-side
	// verification that would read as an acceptance.
	t.Run("ProducerSideRunEndsClosedPendingAndNeverVerifies", func(t *testing.T) {
		fixture := ncNewWrapperFixture(t,
			ncCooperativeSmokeStub, "exit 0\n", "exit 0\n")
		exit, out := ncRunCommand(t, environment,
			"/bin/sh", fixture.arguments()...)
		if exit != 0 {
			t.Fatalf("a cooperative producer-side run must succeed:\n%s", out)
		}
		if _, err := os.Stat(fixture.verifyMarker); !os.IsNotExist(err) {
			t.Fatal(
				"the conservation verifier ran on the producing host; its " +
					"verdict would be an acceptance of evidence whose trail " +
					"was never closed",
			)
		}
		if !strings.Contains(
			out, "AUDIT_CHECKPOINT_STATE=closed-pending-controller-finalization",
		) {
			t.Fatalf(
				"producer-side evidence did not declare itself unclosed:\n%s",
				out,
			)
		}
		if strings.Contains(out, "MATRIX_VERIFY_CARRIER_CONSERVATION_OK") {
			t.Fatalf(
				"producer-side output claims a conservation verdict:\n%s", out,
			)
		}
	})

	t.Run("WrongReviewedArtifactDigestRefused", func(t *testing.T) {
		fixture := ncNewWrapperFixture(t,
			ncCooperativeSmokeStub, "exit 0\n", "exit 0\n")
		fixture.smokeDigest = strings.Repeat("0", 64)
		exit, out := ncRunCommand(t, environment,
			"/bin/sh", fixture.arguments()...)
		if exit == 0 {
			t.Fatalf("wrapper accepted a binary that fails the reviewed digest\n%s", out)
		}
		if !strings.Contains(out, "deployer expected") {
			t.Fatalf("artifact digest refusal has the wrong shape:\n%s", out)
		}
		if _, err := os.Stat(fixture.runRoot); !os.IsNotExist(err) {
			t.Fatal("run root was created despite the digest refusal")
		}
	})

	t.Run("WrongSourceManifestDigestRefused", func(t *testing.T) {
		fixture := ncNewWrapperFixture(t,
			ncCooperativeSmokeStub, "exit 0\n", "exit 0\n")
		fixture.manifestDigest = strings.Repeat("1", 64)
		exit, out := ncRunCommand(t, environment,
			"/bin/sh", fixture.arguments()...)
		if exit == 0 {
			t.Fatalf("wrapper accepted a source manifest that fails its digest\n%s", out)
		}
		if !strings.Contains(out, "deployer expected") {
			t.Fatalf("source manifest refusal has the wrong shape:\n%s", out)
		}
		if _, err := os.Stat(fixture.runRoot); !os.IsNotExist(err) {
			t.Fatal("run root was created despite the manifest refusal")
		}
	})

	t.Run("MissingSourceManifestRefused", func(t *testing.T) {
		fixture := ncNewWrapperFixture(t,
			ncCooperativeSmokeStub, "exit 0\n", "exit 0\n")
		fixture.manifest = fixture.manifest + ".does-not-exist"
		exit, out := ncRunCommand(t, environment,
			"/bin/sh", fixture.arguments()...)
		if exit == 0 {
			t.Fatalf("wrapper ran without the deployed source manifest\n%s", out)
		}
		if !strings.Contains(out, "not a regular file") {
			t.Fatalf("missing-manifest refusal has the wrong shape:\n%s", out)
		}
	})

	t.Run("MalformedExpectedDigestRefused", func(t *testing.T) {
		fixture := ncNewWrapperFixture(t,
			ncCooperativeSmokeStub, "exit 0\n", "exit 0\n")
		fixture.smokeDigest = "abc123"
		exit, out := ncRunCommand(t, environment,
			"/bin/sh", fixture.arguments()...)
		if exit == 0 {
			t.Fatalf("wrapper accepted a malformed expected digest\n%s", out)
		}
		if !strings.Contains(out, "not 64 lower-hex") {
			t.Fatalf("malformed-digest refusal has the wrong shape:\n%s", out)
		}
	})

	t.Run("MissingArgumentsAreAUsageError", func(t *testing.T) {
		// The pre-F4 wrapper accepted three arguments and treated every
		// digest as optional; the hardened contract must refuse anything but
		// the full seven, so a caller cannot simply omit a binding.
		fixture := ncNewWrapperFixture(t,
			ncCooperativeSmokeStub, "exit 0\n", "exit 0\n")
		exit, out := ncRunCommand(t, environment,
			"/bin/sh", fixture.script, fixture.smoke, fixture.verify,
			fixture.runRoot,
		)
		if exit == 0 {
			t.Fatalf("wrapper ran with the bindings omitted\n%s", out)
		}
		if exit != 64 || !strings.Contains(out, "usage:") {
			t.Fatalf("expected the EX_USAGE refusal, got exit=%d:\n%s", exit, out)
		}
	})
}
