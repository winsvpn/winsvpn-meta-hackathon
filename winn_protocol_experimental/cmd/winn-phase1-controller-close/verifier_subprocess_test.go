// The real-subprocess contract for the controller's verifier wiring.
//
// This exists because the bug it guards against was invisible to unit stubs. A
// fake Verifier records that VerifyMatrix was called; it cannot notice that the
// real invocation omits an argument the real binary hard-requires. The failure
// mode was a guaranteed refusal for a plumbing reason, which on a console is
// indistinguishable from a genuine trust failure — the worst kind of bug to
// have in a gate, because it looks exactly like the gate working.
//
// So these tests run the actual winn-phase1-matrix-verify binary.
package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/auditcheckpoint"
	"winsvpn.local/winnprotocol/internal/securefile"
)

func buildVerifier(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "winn-phase1-matrix-verify")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build",
		"-o", output, "./cmd/winn-phase1-matrix-verify")
	command.Dir = root
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build the verifier: %v\n%s", err, out)
	}
	return output
}

// TestRealVerifierReceivesTheFinalizerPin proves the argument actually reaches
// the binary, by observing how the binary's own refusal changes with it.
//
// The fixture's matrix root is not a complete formal matrix, so the run fails
// either way — but WHY it fails is the whole point. Without the pin the binary
// refuses for the missing pin, naming AUDIT-CLOSE; with the pin it gets past
// that gate and fails on something else. A wiring that never passed the flag
// would produce the first message on every real run forever.
func TestRealVerifierReceivesTheFinalizerPin(t *testing.T) {
	verifier := buildVerifier(t)
	fixture := newMatrixFixture(t, fixtureOptions{})
	// Close one batch so a checkpoint exists for the verifier to reach.
	seedKeyID, err := auditcheckpoint.KeyIDFromSeedFile(fixture.seed)
	if err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(fixture.root, "evidence",
		"auto-e2e-"+fixtureMatrixID+"-"+fixture.keys[0])

	run := func(pin string) string {
		arguments := []string{
			"-carrier-conservation-report", evidence,
			"-audit-run-id", fixtureMatrixID + "-" + fixture.keys[0],
			"-audit-producer-digest", fixtureSource,
		}
		if pin != "" {
			arguments = append(arguments, "-audit-finalizer-key-id", pin)
		}
		out, _ := exec.Command(verifier, arguments...).CombinedOutput()
		return string(out)
	}

	withoutPin := run("")
	if !strings.Contains(withoutPin, "AUDIT-CLOSE") ||
		!strings.Contains(withoutPin, "finalizer key is pinned") {
		t.Fatalf(
			"the real binary did not refuse an unpinned run as expected:\n%s",
			withoutPin,
		)
	}
	withPin := run(seedKeyID)
	if strings.Contains(withPin, "finalizer key is pinned") {
		t.Fatalf(
			"supplying -audit-finalizer-key-id did not change the binary's "+
				"verdict; the flag is not reaching it:\n%s", withPin,
		)
	}
	withWrongPin := run(strings.Repeat("f", 64))
	if strings.Contains(withWrongPin, "finalizer key is pinned") {
		t.Fatalf("a wrong pin was treated as a missing pin:\n%s", withWrongPin)
	}
}

// TestBinaryVerifierSuppliesEveryRequiredFlag inspects the exact argument
// vector the controller's production wiring builds, so a dropped flag fails
// here rather than on a live matrix.
func TestBinaryVerifierSuppliesEveryRequiredFlag(t *testing.T) {
	recorder := filepath.Join(t.TempDir(), "record-args")
	captured := filepath.Join(t.TempDir(), "arguments.txt")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + captured + "\nexit 0\n"
	if err := os.WriteFile(recorder, []byte(script), 0o755); err != nil { // #nosec G302
		t.Fatal(err)
	}
	verifier := &binaryVerifier{
		binary:            recorder,
		finalizerKeyID:    strings.Repeat("a", 64),
		matrixRoot:        "/matrix",
		profiles:          "/profiles.json",
		expectedSource:    strings.Repeat("b", 64),
		expectedAWGEngine: strings.Repeat("c", 64),
		providerOneID:     "provider-one",
		providerOnePK:     "/one.pub",
		providerTwoID:     "provider-two",
		providerTwoPK:     "/two.pub",
	}
	verifier.UseFrozenTrust(newFrozenTrustForTest(t))
	if err := verifier.VerifyMatrix(candidateCompleteName); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(captured) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	arguments := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	for _, required := range []string{
		"-audit-finalizer-key-id",
		strings.Repeat("a", 64),
		"-complete-record-name",
		candidateCompleteName,
		"-audit-producer-digest",
		"-anchor-provider-one-id",
		"-anchor-provider-two-id",
	} {
		found := false
		for _, argument := range arguments {
			if argument == required {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf(
				"the real verifier invocation omits %q; a run through this "+
					"path would fail closed for a plumbing reason, which is "+
					"indistinguishable from a genuine trust failure.\nGot: %v",
				required, arguments,
			)
		}
	}
}

// newFrozenTrustForTest builds a complete frozen trust set backed by real
// anonymous snapshots, so tests exercise the production path rather than the
// removed pathname fallback.
func newFrozenTrustForTest(t *testing.T) frozenTrust {
	t.Helper()
	one := []byte("PROVIDER ONE KEY\n")
	two := []byte("PROVIDER TWO KEY\n")
	hosts := []byte("host ssh-ed25519 AAAA\n")
	snapshot := func(content []byte) *os.File {
		file, err := securefile.AnonymousSnapshot(content)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = file.Close() })
		return file
	}
	return frozenTrust{
		providerOneKey:  one,
		providerTwoKey:  two,
		knownHosts:      hosts,
		providerOneFile: snapshot(one),
		providerTwoFile: snapshot(two),
		knownHostsFile:  snapshot(hosts),
	}
}

// TestBinaryVerifierFailsClosedWithoutFrozenTrust covers the fallback that used
// to be here.
//
// VerifyMatrix previously reverted to the operator's mutable -anchor-provider-*
// pathnames whenever the frozen snapshots were absent. That is the one
// situation in which reverting is least acceptable: the anchors are already
// irreversible by the time the matrix is verified, so a run whose trust
// adoption was skipped verified the finished evidence against whatever those
// names pointed at by then — and reported PASS. A fallback that produces a
// SUCCESSFUL verification is invisible exactly when it matters.
//
// The recorder exits 0, so if the fallback ever returns this test sees a nil
// error rather than an absence of evidence.
func TestBinaryVerifierFailsClosedWithoutFrozenTrust(t *testing.T) {
	recorder := filepath.Join(t.TempDir(), "record-args")
	captured := filepath.Join(t.TempDir(), "arguments.txt")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + captured + "\nexit 0\n"
	if err := os.WriteFile(recorder, []byte(script), 0o755); err != nil { // #nosec G302
		t.Fatal(err)
	}
	base := func() *binaryVerifier {
		return &binaryVerifier{
			binary:         recorder,
			finalizerKeyID: strings.Repeat("a", 64),
			matrixRoot:     "/matrix",
			profiles:       "/profiles.json",
			providerOnePK:  "/one.pub",
			providerTwoPK:  "/two.pub",
		}
	}
	complete := newFrozenTrustForTest(t)

	for _, test := range []struct {
		name  string
		build func() frozenTrust
	}{
		{"no_trust_at_all", func() frozenTrust { return frozenTrust{} }},
		{"first_provider_missing", func() frozenTrust {
			partial := complete
			partial.providerOneFile = nil
			return partial
		}},
		{"second_provider_missing", func() frozenTrust {
			partial := complete
			partial.providerTwoFile = nil
			return partial
		}},
		{"known_hosts_missing", func() frozenTrust {
			partial := complete
			partial.knownHostsFile = nil
			return partial
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_ = os.Remove(captured)
			verifier := base()
			verifier.UseFrozenTrust(test.build())
			err := verifier.VerifyMatrix(candidateCompleteName)
			if err == nil {
				t.Fatal(
					"the matrix was verified without a complete frozen trust " +
						"set; the run would report PASS over evidence checked " +
						"against pathnames that may have been replaced after " +
						"the anchors became irreversible",
				)
			}
			if !strings.Contains(err.Error(), "frozen trust set") {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
			// And the child must never have been started: refusing after
			// invoking the verifier would still have verified something.
			if _, statErr := os.Stat(captured); statErr == nil {
				t.Fatal(
					"the verifier subprocess ran despite the incomplete " +
						"frozen trust set",
				)
			}
		})
	}
}

// TestCandidateVerificationIsLabelledNonPromotional proves the transcript
// itself carries the distinction. A transcript travels; internal state does not.
func TestCandidateVerificationIsLabelledNonPromotional(t *testing.T) {
	verifier := buildVerifier(t)
	out, _ := exec.Command(verifier,
		"-matrix-root", t.TempDir(),
		"-profiles", "/nonexistent.json",
		"-expected-source-digest", strings.Repeat("a", 64),
		"-expected-awg-engine-digest", strings.Repeat("b", 64),
		"-complete-record-name", candidateCompleteName,
	).CombinedOutput()
	// This run cannot pass; what matters is that the binary accepts the flag
	// rather than rejecting it as unknown, which is what would silently break
	// the controller's candidate pass.
	if strings.Contains(string(out), "flag provided but not defined") {
		t.Fatalf(
			"the verifier does not accept -complete-record-name:\n%s", out,
		)
	}
}
