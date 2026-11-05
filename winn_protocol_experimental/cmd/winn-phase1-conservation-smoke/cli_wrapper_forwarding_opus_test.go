// Opus defense-in-depth controls for the wrapper's digest FORWARDING, as
// opposed to the wrapper's own digest COMPARISON.
//
// scripts/aicore_conservation_smoke.sh checks two things itself — that the
// smoke binary on disk hashes to the digest the deployer reviewed, and that the
// deployed .source.sha256 manifest hashes to the digest the deployer stated —
// and then hands both expectations to the smoke, which re-checks them against
// its own executable and its own ldflags-stamped source digest. The second
// layer is only an independent layer if the wrapper forwards the DEPLOYER's
// stated values. If it forwarded the values it recomputed itself, the smoke
// would be comparing the wrapper's arithmetic against its own, and the whole
// inner check would collapse into a tautology the moment the wrapper's outer
// comparison regressed. The two are indistinguishable in a healthy run,
// precisely because the outer comparison forces them equal, so no test that
// exercises a healthy wrapper can tell them apart.
//
// These tests therefore SIMULATE the regression Fable's finding was about:
// they take the real script, neuter its two comparison gates in a temp copy —
// the exact "what if that earlier check ever regressed" scenario — and then
// require that a deployer/actual mismatch is still refused. Under a correct
// wrapper the deployer's value reaches the smoke unchanged and the mismatch is
// caught; under a forwarding regression the smoke would receive the wrapper's
// own recomputed value, agree with itself, and admit a run the deployer never
// authorized.
//
// This is deliberately NOT the "a wrong digest is rejected" case. That is
// already covered, twice over: TestNegativeControlSmokeCLIDigestGates drives
// the smoke's flags directly, and TestNegativeControlWrapperExitStatusPropagation's
// Wrong*DigestRefused subtests prove the wrapper's own comparison refuses. Both
// of those stay green under the forwarding bug these tests exist to catch.
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

// The two comparison gates in the real wrapper, quoted exactly. Each must
// appear exactly once; if the script is refactored so these no longer match,
// the bypass silently would not happen and these tests would prove nothing, so
// a miss is a hard failure rather than a skip.
const (
	fwdBinaryGate = `if [ "$smoke_sha256" != "$expected_smoke_sha256" ]; then`
	fwdSourceGate = `if [ "$source_digest" != "$expected_source_digest" ]; then`
)

// Sentinel expectations: well formed 64 lower-hex (the wrapper's format gate is
// NOT bypassed and still requires that), and never equal to any real digest.
var (
	fwdSentinelBinaryDigest = strings.Repeat("be", 32)
	fwdSentinelSourceDigest = strings.Repeat("5d", 32)
)

// fwdBypassedWrapper writes a copy of the REAL wrapper whose two self-checks
// are short-circuited, standing in for a future regression that weakens or
// deletes them. Nothing else about the script is altered: argument handling,
// the 64-lower-hex format gate, the ordering of the stages and — the point of
// the exercise — the flags handed to the smoke are the production ones.
func fwdBypassedWrapper(t *testing.T) string {
	t.Helper()
	original := filepath.Join(
		ncModuleRoot(t), "scripts", "aicore_conservation_smoke.sh",
	)
	body, err := os.ReadFile(original)
	if err != nil {
		t.Fatalf("read wrapper: %v", err)
	}
	text := string(body)
	for _, gate := range []string{fwdBinaryGate, fwdSourceGate} {
		if count := strings.Count(text, gate); count != 1 {
			t.Fatalf(
				"expected exactly one occurrence of the wrapper gate %q, "+
					"found %d: the script was refactored and this test can no "+
					"longer simulate the comparison regressing", gate, count,
			)
		}
		text = strings.Replace(text, gate, "if false; then", 1)
	}
	bypassed := filepath.Join(t.TempDir(), "aicore_conservation_smoke_bypassed.sh")
	if err := os.WriteFile(bypassed, []byte(text), 0o755); err != nil {
		t.Fatal(err)
	}
	return bypassed
}

// fwdRunBounded is ncRunCommand with a tight deadline. Every assertion below
// is satisfied by a refusal that happens in milliseconds; the deadline only
// exists so that the FAILING direction — a smoke that was wrongly admitted and
// starts driving a full QUIC run — reports a failure instead of hanging.
func fwdRunBounded(
	t *testing.T,
	environment []string,
	name string,
	arguments ...string,
) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
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

// fwdRecordedFlag returns the value the smoke process actually received for a
// flag, from the argv the recording stub wrote out.
func fwdRecordedFlag(t *testing.T, recorded []string, flag string) string {
	t.Helper()
	for index, argument := range recorded {
		if argument == flag {
			if index+1 >= len(recorded) {
				t.Fatalf("%s was passed with no value: %q", flag, recorded)
			}
			return recorded[index+1]
		}
	}
	t.Fatalf("the smoke was never given %s at all: %q", flag, recorded)
	return ""
}

// TestWrapperForwardsDeployerExpectationsNotItsOwnRecomputation is the direct
// statement of the property.
//
// With the wrapper's own comparison bypassed, the deployer's stated digests and
// the digests the wrapper recomputes are free to differ, and the test makes
// them differ. It then reads the argv the smoke was actually invoked with.
//
// A regression fails this test if and only if line ~133/134 of the wrapper
// passes anything other than the deployer-supplied $expected_smoke_sha256 /
// $expected_source_digest — most plausibly the wrapper's own $smoke_sha256 /
// $source_digest, which is what the script did before Fable's finding. In a
// healthy run those are equal and no existing test can see the difference;
// here they are provably not equal, so the substitution is visible.
func TestWrapperForwardsDeployerExpectationsNotItsOwnRecomputation(t *testing.T) {
	environment := ncWrapperEnvironment(t)
	recordedPath := filepath.Join(t.TempDir(), "smoke-argv")
	fixture := ncNewWrapperFixture(t,
		"printf '%s\\n' \"$@\" >"+recordedPath+"\n"+ncCooperativeSmokeStub,
		"exit 0\n", "exit 0\n")

	// What the wrapper would recompute for itself, kept for the inequality
	// assertions below.
	recomputedBinaryDigest := fixture.smokeDigest
	recomputedSourceDigest := fixture.manifestDigest

	// What the deployer states. Deliberately not what is on disk; only the
	// bypassed comparison lets these through.
	fixture.script = fwdBypassedWrapper(t)
	fixture.smokeDigest = fwdSentinelBinaryDigest
	fixture.manifestDigest = fwdSentinelSourceDigest

	exit, out := fwdRunBounded(t, environment, "/bin/sh", fixture.arguments()...)
	if exit != 0 {
		t.Fatalf(
			"the bypassed wrapper did not reach the smoke (exit=%d), so this "+
				"test proved nothing about forwarding:\n%s", exit, out,
		)
	}
	body, err := os.ReadFile(recordedPath)
	if err != nil {
		t.Fatalf("the smoke stub recorded no argv: %v", err)
	}
	recorded := strings.Split(strings.TrimRight(string(body), "\n"), "\n")

	binarySeen := fwdRecordedFlag(t, recorded, "-expected-binary-sha256")
	sourceSeen := fwdRecordedFlag(t, recorded, "-expected-source-digest")

	if binarySeen == recomputedBinaryDigest {
		t.Fatalf(
			"REGRESSION: the wrapper handed the smoke its OWN recomputed "+
				"binary digest %s instead of the deployer's %s. The smoke's "+
				"selfDigest check is then comparing the wrapper's arithmetic "+
				"with its own and can never disagree with it",
			recomputedBinaryDigest, fwdSentinelBinaryDigest,
		)
	}
	if binarySeen != fwdSentinelBinaryDigest {
		t.Fatalf(
			"the smoke received -expected-binary-sha256 %q, want the "+
				"deployer-supplied %q", binarySeen, fwdSentinelBinaryDigest,
		)
	}
	if sourceSeen == recomputedSourceDigest {
		t.Fatalf(
			"REGRESSION: the wrapper handed the smoke its OWN recomputed "+
				"source-manifest digest %s instead of the deployer's %s. The "+
				"smoke's requireBinding source check is then a tautology",
			recomputedSourceDigest, fwdSentinelSourceDigest,
		)
	}
	if sourceSeen != fwdSentinelSourceDigest {
		t.Fatalf(
			"the smoke received -expected-source-digest %q, want the "+
				"deployer-supplied %q", sourceSeen, fwdSentinelSourceDigest,
		)
	}
}

// TestWrapperBypassedGatesAreStillCaughtBySmokeSelfBinding is the same property
// proved end to end through the REAL smoke binary rather than through argv.
//
// The fixture is built so that the wrapper's recomputed source digest is
// exactly the digest the smoke was stamped with — i.e. the manifest on disk
// genuinely is the one this build came from — while the DEPLOYER states a
// different digest. That separation is what makes the test discriminating:
//
//   - forwarding the deployer's value (correct): requireBinding sees an
//     expectation that disagrees with its stamp and refuses before any
//     directory is created, so the smoke independently catches what the
//     bypassed wrapper let through;
//   - forwarding the wrapper's recomputed value (the regression): the smoke
//     receives exactly its own stamp, agrees with itself, and is admitted —
//     the second layer has stopped existing.
//
// Existing coverage cannot see this. Every current test either lets the
// wrapper's own comparison do the refusing, or invokes the smoke's flags
// directly with no wrapper in between.
func TestWrapperBypassedGatesAreStillCaughtBySmokeSelfBinding(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the smoke binary; skipped in -short")
	}
	environment := ncWrapperEnvironment(t)
	moduleRoot := ncModuleRoot(t)

	fixture := ncNewWrapperFixture(t, "exit 0\n", "exit 0\n", "exit 0\n")

	// Stamp the real binary with the digest of the manifest that is actually on
	// disk, so the only disagreement in play is the deployer's stated value.
	realSmoke := filepath.Join(t.TempDir(), "smoke-stamped-to-manifest")
	ncGoBuildSmoke(t, moduleRoot, realSmoke, fixture.manifestDigest)
	realDigest, err := sha256File(realSmoke)
	if err != nil {
		t.Fatal(err)
	}

	fixture.script = fwdBypassedWrapper(t)
	fixture.smoke = realSmoke
	fixture.smokeDigest = realDigest                 // correct: isolates the source check
	fixture.manifestDigest = fwdSentinelSourceDigest // what the deployer states

	exit, out := fwdRunBounded(t, environment, "/bin/sh", fixture.arguments()...)
	if exit == 0 {
		t.Fatalf(
			"REGRESSION: with the wrapper's own comparison bypassed, a run "+
				"the deployer never authorized completed. The smoke's "+
				"requireBinding did not see the deployer's expectation, so "+
				"the second layer of the binding is not independent:\n%s", out,
		)
	}
	if !strings.Contains(out, fwdSentinelSourceDigest) {
		t.Fatalf(
			"REGRESSION: the smoke's refusal never mentions the deployer's "+
				"stated digest %s, so that value did not reach it:\n%s",
			fwdSentinelSourceDigest, out,
		)
	}
	if !strings.Contains(out, "built from source manifest") {
		t.Fatalf(
			"expected the smoke's own requireBinding refusal, got:\n%s", out,
		)
	}
	if !strings.Contains(out, "conservation smoke failed") {
		t.Fatalf(
			"the wrapper did not attribute the refusal to the smoke:\n%s", out,
		)
	}
	if _, err := os.Stat(filepath.Join(fixture.runRoot, "evidence")); !os.IsNotExist(err) {
		t.Fatal("evidence was created despite the smoke refusing to bind")
	}
}
