// The post-gate trust-swap window.
//
// verifyLastReversibleGate validates the frozen trust set, and then the anchor
// step runs. Everything in between used to resolve PATHNAMES:
// pinAnchorRunner handed anchors/provider-one.ed25519.pub to the anchor
// subprocess, verifyIncumbent reopened it, and binaryVerifier passed it again.
// A swap landing in that window reached the irreversible provider signatures
// under a trust set CONTROLLER_START never authorised, and the disagreement
// surfaced only afterwards.
//
// A hash-before-invoke check does not close this. The subprocess is handed a
// name and opens it itself, so checking the file's contents beforehand tells
// you what the file was, not what the child will read. The fix is that no
// pathname is resolved after the freeze at all: descriptors are opened once and
// the child is given /dev/fd names backed by them.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/phase1anchor"
	"winsvpn.local/winnprotocol/internal/securefile"
)

// TestAnchorRunnerRefusesWithoutFrozenTrust proves the runner cannot fall back
// to pathnames if the adoption step is ever skipped.
func TestAnchorRunnerRefusesWithoutFrozenTrust(t *testing.T) {
	runner := &pinAnchorRunner{binary: "/nonexistent"}
	_, err := runner.Anchor("000000-genesis", []byte("{}"), "", "")
	if err == nil {
		t.Fatal("the anchor runner ran without a frozen trust set")
	}
	if !strings.Contains(err.Error(), "frozen trust set") &&
		!strings.Contains(err.Error(), "anchor 000000-genesis") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// --- anonymous snapshots ---------------------------------------------------

// TestSequentialAnchorsAllReceiveTheKeys covers descriptor reuse. A snapshot
// read to EOF once yields nothing on the next read, so without a rewind the
// genesis anchor would receive the keys and every batch after it would receive
// empty files — surfacing as an unrelated SSH failure partway through an
// irreversible chain.
func TestSequentialAnchorsAllReceiveTheKeys(t *testing.T) {
	keyBytes := []byte("PROVIDER ONE KEY\n")
	snapshot, err := securefile.AnonymousSnapshot(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	hostBytes := []byte("host ssh-ed25519 AAAA\n")
	hosts, err := securefile.AnonymousSnapshot(hostBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer hosts.Close()
	twoBytes := []byte("PROVIDER TWO KEY\n")
	two, err := securefile.AnonymousSnapshot(twoBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer two.Close()

	frozen := frozenTrust{
		providerOneKey: keyBytes, providerTwoKey: twoBytes,
		knownHosts:      hostBytes,
		providerOneFile: snapshot, providerTwoFile: two, knownHostsFile: hosts,
	}

	// One call per anchor in a real run: genesis, batches, seal.
	for round := 0; round < 6; round++ {
		files, err := frozen.extraFiles()
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		content, err := io.ReadAll(files[0])
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != string(keyBytes) {
			t.Fatalf(
				"round %d handed the child %q instead of the key; a "+
					"descriptor reused without rewinding is empty after the "+
					"first anchor", round, content,
			)
		}
	}
}

// TestSnapshotsAreBuiltFromVerifiedBytesNotAReRead pins the ordering that makes
// the snapshot meaningful. It is built from trustView's in-memory bytes — the
// ones already checked against the signed start record — so a swap landing
// before the snapshot is caught by that earlier verification, and a swap
// landing after it has no name to act on.
func TestSnapshotsAreBuiltFromVerifiedBytesNotAReRead(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	controller := fixture.controller()
	if err := controller.loadTrustInputs(); err != nil {
		t.Fatal(err)
	}
	if err := controller.freezeAnchorRoot(); err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), controller.trust.providerOneKey...)

	// Corrupt the frozen file, then take the snapshot. The snapshot must carry
	// the verified in-memory bytes, not what the path now holds.
	if err := os.WriteFile(
		controller.trust.frozenProviderOneKey,
		[]byte("CORRUPTED ON DISK\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := controller.snapshotFrozenTrust(); err != nil {
		t.Fatal(err)
	}
	defer controller.trust.close()

	if err := securefile.RewindSnapshot(
		controller.trust.providerOneFile, original,
	); err != nil {
		t.Fatalf(
			"the snapshot does not hold the verified bytes (%v); it was built "+
				"from a re-read of the path instead", err,
		)
	}
}

// --- the real subprocess seam ---------------------------------------------

// TestChildProcessesConsumeTheSnapshotBytesNotTheNamedFiles observes the trust
// material at the point it is ACTUALLY consumed, in a real child process.
//
// It replaces a test that recorded anchor REQUEST bytes and accepted any Run
// error — which proved nothing about what a provider saw, and could pass for a
// completely unrelated reason. Here a real fake anchor-pin reads the argv paths
// it is handed and writes back what it found, so the assertion is on bytes the
// child actually read.
func TestChildProcessesConsumeTheSnapshotBytesNotTheNamedFiles(t *testing.T) {
	directory := t.TempDir()
	report := filepath.Join(directory, "child-report.txt")

	// A stand-in for winn-phase1-anchor-pin: reads the two provider-key paths
	// and the known-hosts path it is given, and appends what it read.
	fakePin := filepath.Join(directory, "fake-anchor-pin")
	if err := os.WriteFile(fakePin, []byte(
		"#!/bin/sh\n"+
			"one=''; two=''; hosts=''\n"+
			"while [ \"$#\" -gt 0 ]; do\n"+
			"  case \"$1\" in\n"+
			"    -provider-one-public-key) one=$2 ;;\n"+
			"    -provider-two-public-key) two=$2 ;;\n"+
			"    -known-hosts) hosts=$2 ;;\n"+
			"  esac\n"+
			"  shift\n"+
			"done\n"+
			"{\n"+
			"  printf 'ONE:'; cat \"$one\"\n"+
			"  printf 'TWO:'; cat \"$two\"\n"+
			"  printf 'HOSTS:'; cat \"$hosts\"\n"+
			"} >> "+report+"\n"+
			"exit 1\n",
	), 0o755); err != nil { // #nosec G302
		t.Fatal(err)
	}

	fixture := newMatrixFixture(t, fixtureOptions{})
	controller := fixture.controller()
	runner := &pinAnchorRunner{
		binary:        fakePin,
		pendingRoot:   filepath.Join(fixture.root, "anchors", "pending"),
		committedRoot: filepath.Join(fixture.root, "anchors", "committed"),
		sshBinary:     "/bin/true",
		sshKey:        filepath.Join(directory, "key"),
		timeout:       "5s",
		providerOneID: "provider-one",
		providerOne:   "192.0.2.1",
		providerTwoID: "provider-two",
		providerTwo:   "192.0.2.2",
	}
	controller.Anchor = runner

	// All THREE trust inputs are captured and asserted. An earlier version
	// checked only provider one and the known hosts, so a bug that handed
	// provider one's bytes to both key arguments would have passed.
	//
	// The fixture generates distinct keys per provider, so the two assertions
	// cannot be satisfied by the same bytes — interchangeable placeholders
	// would have made the second assertion decorative.
	originalOne, err := os.ReadFile(fixture.keyOne) // #nosec G304 -- temp
	if err != nil {
		t.Fatal(err)
	}
	originalTwo, err := os.ReadFile(fixture.keyTwo) // #nosec G304 -- temp
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(originalOne)) ==
		strings.TrimSpace(string(originalTwo)) {
		t.Fatal(
			"the fixture gave both providers identical key bytes; one key " +
				"could then satisfy both assertions below",
		)
	}
	originalHosts, err := os.ReadFile(fixture.hosts) // #nosec G304 -- temp
	if err != nil {
		t.Fatal(err)
	}

	// After the gate, mutate every named frozen file IN PLACE.
	controller.mutateAfterGate = func() {
		for _, name := range []string{
			"provider-one.ed25519.pub",
			"provider-two.ed25519.pub",
			"known_hosts",
		} {
			path := filepath.Join(fixture.root, "anchors", name)
			writable, err := os.OpenFile(path, os.O_WRONLY, 0o600)
			if err != nil {
				t.Error(err)
				continue
			}
			if _, err := writable.WriteAt([]byte("SWAPPEDSWAPPED!!"), 0); err != nil {
				t.Error(err)
			}
			if err := writable.Close(); err != nil {
				t.Error(err)
			}
		}
	}

	// The fake exits non-zero, so the run fails — but only AFTER the child has
	// read and reported the trust material, which is what is being asserted.
	_ = controller.Run()

	observed, err := os.ReadFile(report) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("the child was never invoked, so nothing was observed: %v", err)
	}
	if !strings.Contains(string(observed), "ONE:") {
		t.Fatalf("the child reported nothing usable:\n%s", observed)
	}
	if strings.Contains(string(observed), "SWAPPED") {
		t.Fatalf(
			"the child read bytes mutated in place after the gate:\n%s",
			observed,
		)
	}
	if !strings.Contains(string(observed), strings.TrimSpace(string(originalOne))) {
		t.Fatalf(
			"the child did not read the original first provider key:\n%s",
			observed,
		)
	}
	if !strings.Contains(string(observed), strings.TrimSpace(string(originalTwo))) {
		t.Fatalf(
			"the child did not read the original SECOND provider key; the two "+
				"keys are distinct, so this cannot be satisfied by the "+
				"first:\n%s", observed,
		)
	}
	// And each key must appear under its own marker, so a wiring bug that
	// passed one key for both arguments is caught rather than averaged out.
	oneLine := "ONE:" + strings.TrimSpace(string(originalOne))
	twoLine := "TWO:" + strings.TrimSpace(string(originalTwo))
	if !strings.Contains(string(observed), oneLine) {
		t.Fatalf("provider one's key did not arrive as ONE:\n%s", observed)
	}
	if !strings.Contains(string(observed), twoLine) {
		t.Fatalf("provider two's key did not arrive as TWO:\n%s", observed)
	}
	if !strings.Contains(
		string(observed), strings.TrimSpace(string(originalHosts)),
	) {
		t.Fatalf(
			"the child did not read the original known hosts:\n%s", observed,
		)
	}
}

// TestSequentialChildrenAllReceiveTheSnapshotBytes proves the descriptors are
// rewound between anchors, observed in real children rather than in memory.
func TestSequentialChildrenAllReceiveTheSnapshotBytes(t *testing.T) {
	directory := t.TempDir()
	report := filepath.Join(directory, "sequential-report.txt")
	fakePin := filepath.Join(directory, "fake-anchor-pin")
	if err := os.WriteFile(fakePin, []byte(
		"#!/bin/sh\n"+
			"one=''\n"+
			"while [ \"$#\" -gt 0 ]; do\n"+
			"  case \"$1\" in -provider-one-public-key) one=$2 ;; esac\n"+
			"  shift\n"+
			"done\n"+
			"{ printf 'CALL['; cat \"$one\" | tr -d '\\n'; printf ']\\n'; } >> "+report+"\n"+
			"exit 1\n",
	), 0o755); err != nil { // #nosec G302
		t.Fatal(err)
	}

	keyBytes := []byte("PROVIDER ONE KEY\n")
	one, err := securefile.AnonymousSnapshot(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close()
	twoBytes := []byte("PROVIDER TWO KEY\n")
	two, err := securefile.AnonymousSnapshot(twoBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer two.Close()
	hostBytes := []byte("host ssh-ed25519 AAAA\n")
	hosts, err := securefile.AnonymousSnapshot(hostBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer hosts.Close()

	runner := &pinAnchorRunner{
		binary:        fakePin,
		pendingRoot:   filepath.Join(directory, "pending"),
		committedRoot: filepath.Join(directory, "committed"),
		sshBinary:     "/bin/true",
		timeout:       "5s",
		providerOneID: "provider-one",
		providerOne:   "192.0.2.1",
		providerTwoID: "provider-two",
		providerTwo:   "192.0.2.2",
	}
	runner.UseFrozenTrust(frozenTrust{
		providerOneKey: keyBytes, providerTwoKey: twoBytes,
		knownHosts:      hostBytes,
		providerOneFile: one, providerTwoFile: two, knownHostsFile: hosts,
	})
	if err := os.MkdirAll(runner.pendingRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(runner.committedRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	request := phase1anchor.Request{
		Schema: phase1anchor.RequestSchema, Kind: phase1anchor.KindGenesis,
		MatrixID: "m", SourceDigest: strings.Repeat("1", 64),
		AutoArtifactDigest: strings.Repeat("2", 64),
		ProfileDigest:      strings.Repeat("3", 64),
		ScheduleDigest:     strings.Repeat("4", 64),
		ExpectedBatchCount: 1, Ordinal: 0,
	}
	encoded, err := request.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	// Four sequential anchors, as a real run performs.
	for round := 0; round < 4; round++ {
		_, _ = runner.Anchor(
			fmt.Sprintf("%06d-slot", round), encoded,
			phase1anchor.ZeroDigest, phase1anchor.ZeroDigest,
		)
	}

	observed, err := os.ReadFile(report) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("no child was invoked: %v", err)
	}
	expected := "CALL[" + strings.TrimSpace(string(keyBytes)) + "]"
	calls := strings.Count(string(observed), expected)
	empty := strings.Count(string(observed), "CALL[]")
	if empty > 0 {
		t.Fatalf(
			"%d child invocations received an EMPTY provider key; a snapshot "+
				"reused without rewinding is exhausted after the first "+
				"anchor:\n%s", empty, observed,
		)
	}
	if calls < 4 {
		t.Fatalf(
			"only %d of the sequential invocations received the key:\n%s",
			calls, observed,
		)
	}
}
