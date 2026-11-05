// Nested descriptor inheritance, proved rather than assumed.
//
// The controller hands this process an anonymous snapshot of known_hosts. This
// process then execs ssh, which must READ that file. Descriptor inheritance
// does not cross an exec boundary on its own: Go's exec closes every
// non-standard descriptor in a child unless ExtraFiles names it, so an ssh
// grandchild would never see the controller's fd — it would try to open the
// pathname it was given, and /dev/fd/5 in a process that does not hold fd 5
// fails outright.
//
// So the chain is explicit at each hop, and this file proves the second hop
// with a real grandchild process rather than trusting the arrangement.
package main

import (
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/phase1anchor"
	"winsvpn.local/winnprotocol/internal/securefile"
)

// TestGrandchildCannotSeeADescriptorThatWasNotPassed is the control that makes
// the test above meaningful: without ExtraFiles the descriptor is NOT
// inherited, so the arrangement is doing real work rather than describing
// something that would happen anyway.
func TestGrandchildCannotSeeADescriptorThatWasNotPassed(t *testing.T) {
	content := []byte("provider-one ssh-ed25519 AAAAC3NzaC1lZDI1NTE5\n")
	snapshot, err := securefile.AnonymousSnapshot(content)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()

	grandchild := filepath.Join(t.TempDir(), "fake-ssh")
	if err := os.WriteFile(grandchild, []byte(
		"#!/bin/sh\ncat /dev/fd/3 2>&1\n",
	), 0o755); err != nil { // #nosec G302
		t.Fatal(err)
	}
	command := exec.Command(grandchild)
	// Deliberately no ExtraFiles.
	output, _ := command.CombinedOutput()
	if strings.Contains(string(output), string(content)) {
		t.Fatal(
			"a descriptor that was never passed was still readable in the " +
				"child; the inheritance test above proves nothing",
		)
	}
}

// TestSnapshotSurvivesRepeatedGrandchildren covers the two providers one run
// contacts in sequence: the snapshot is rewound before each, so the second ssh
// receives the same bytes as the first rather than an empty file.
func TestSnapshotSurvivesRepeatedGrandchildren(t *testing.T) {
	content := []byte("provider ssh-ed25519 AAAAC3NzaC1lZDI1NTE5\n")
	snapshot, err := securefile.AnonymousSnapshot(content)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()

	grandchild := filepath.Join(t.TempDir(), "fake-ssh")
	if err := os.WriteFile(grandchild, []byte(
		"#!/bin/sh\ncat /dev/fd/3\n",
	), 0o755); err != nil { // #nosec G302
		t.Fatal(err)
	}
	for round := 0; round < 4; round++ {
		if err := securefile.RewindSnapshot(snapshot, content); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		command := exec.Command(grandchild)
		command.ExtraFiles = []*os.File{snapshot}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("round %d failed: %v\n%s", round, err, output)
		}
		if string(output) != string(content) {
			t.Fatalf(
				"round %d read %q; without a rewind every ssh after the first "+
					"receives an empty known-hosts file, which surfaces as an "+
					"unverifiable host key partway through the chain",
				round, output,
			)
		}
	}
}

// TestRealPinProviderHandsSSHTheInheritedSnapshot exercises the ACTUAL
// production wiring.
//
// The earlier version of this test built its own exec.Command with its own
// ExtraFiles and its own hardcoded /dev/fd/3 argument. That demonstrates that
// os/exec can pass descriptors — which was never in doubt — and says nothing
// about whether pinProvider passes them, or what path it names. If pinProvider
// stopped setting ExtraFiles tomorrow, or named a different descriptor, that
// test would still have passed.
//
// This one calls the real pinProvider. The fake ssh PARSES the argv it is
// actually given, finds UserKnownHostsFile itself rather than assuming a value,
// and reports both the path it was told to use and the bytes it read there.
func TestRealPinProviderHandsSSHTheInheritedSnapshot(t *testing.T) {
	directory := t.TempDir()
	report := filepath.Join(directory, "ssh-report.txt")

	// Parses the real argv. If pinProvider ever names a different descriptor,
	// or stops passing one, this reports what it actually saw rather than
	// silently succeeding.
	fakeSSH := filepath.Join(directory, "fake-ssh")
	if err := os.WriteFile(fakeSSH, []byte(
		"#!/bin/sh\n"+
			"hosts=''\n"+
			"while [ \"$#\" -gt 0 ]; do\n"+
			"  case \"$1\" in\n"+
			"    UserKnownHostsFile=*) hosts=\"${1#UserKnownHostsFile=}\" ;;\n"+
			"  esac\n"+
			"  shift\n"+
			"done\n"+
			"{\n"+
			"  printf 'PATH[%s]\\n' \"$hosts\"\n"+
			"  printf 'BYTES['\n"+
			"  cat \"$hosts\" 2>&1 | tr -d '\\n'\n"+
			"  printf ']\\n'\n"+
			"} >> "+report+"\n"+
			"cat >/dev/null\n"+
			"echo 'ANCHOR_REJECT: fake provider'>&2\n"+
			"exit 1\n",
	), 0o755); err != nil { // #nosec G302
		t.Fatal(err)
	}

	hostBytes := []byte("provider-one ssh-ed25519 AAAAC3NzaC1lZDI1NTE5FAKE\n")
	snapshot, err := securefile.AnonymousSnapshot(hostBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()

	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = private
	request := phase1anchor.Request{
		Schema:             phase1anchor.RequestSchema,
		Kind:               phase1anchor.KindGenesis,
		MatrixID:           "phase1-auto-v1",
		SourceDigest:       strings.Repeat("1", 64),
		AutoArtifactDigest: strings.Repeat("2", 64),
		ProfileDigest:      strings.Repeat("3", 64),
		ScheduleDigest:     strings.Repeat("4", 64),
		ExpectedBatchCount: 1,
		Ordinal:            0,
	}
	canonical, err := request.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(directory, "pending")
	if err := os.MkdirAll(pending, 0o700); err != nil {
		t.Fatal(err)
	}
	sshKey := filepath.Join(directory, "anchor.key")
	if err := os.WriteFile(sshKey, []byte("fake key\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The real function. It is expected to fail — the fake provider rejects —
	// but only after ssh has been invoked with the real argument vector. The
	// timeout is generous so a loaded host's spawn latency cannot turn the
	// kill before the report write into a false "never invoked ssh".
	_ = pinProvider(
		request, canonical, pending, fakeSSH, sshKey,
		snapshot, hostBytes, 15*time.Second,
		provider{
			id:             "provider-one",
			host:           "192.0.2.1",
			public:         public,
			previousDigest: phase1anchor.ZeroDigest,
			receiptName:    "provider-one.receipt.json",
		},
	)

	if err := waitForFile(t, report, 15*time.Second); err != nil {
		t.Fatalf("the real pinProvider never invoked ssh: %v", err)
	}
	observed, err := os.ReadFile(report) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("the real pinProvider never invoked ssh: %v", err)
	}
	// The argv assertion: pinProvider must name an inherited descriptor, not a
	// filesystem path.
	if !strings.Contains(string(observed), "PATH[/dev/fd/3]") {
		t.Fatalf(
			"pinProvider did not point ssh at the inherited descriptor; it "+
				"passed:\n%s", observed,
		)
	}
	// And that descriptor must actually carry the snapshot's bytes.
	want := "BYTES[" + strings.TrimSpace(string(hostBytes)) + "]"
	if !strings.Contains(string(observed), want) {
		t.Fatalf(
			"ssh read the wrong bytes from the inherited descriptor:\n%s\n"+
				"want %s", observed, want,
		)
	}
}

// TestRealPinProviderFailsIfTheDescriptorIsNotPassed is the negative control
// that makes the test above load-bearing: pointed at a descriptor number this
// process does not pass, the read must fail rather than silently succeed.
func TestRealPinProviderFailsIfTheDescriptorIsNotPassed(t *testing.T) {
	directory := t.TempDir()
	report := filepath.Join(directory, "wrong-fd-report.txt")
	fakeSSH := filepath.Join(directory, "fake-ssh")
	// Deliberately reads fd 4, which pinProvider does not pass (it passes only
	// one ExtraFile, which becomes fd 3).
	if err := os.WriteFile(fakeSSH, []byte(
		"#!/bin/sh\n"+
			"{ printf 'WRONGFD['; cat /dev/fd/4 2>&1 | tr -d '\\n'; printf ']\\n'; } >> "+
			report+"\n"+
			"cat >/dev/null\n"+
			"echo 'ANCHOR_REJECT: fake provider'>&2\n"+
			"exit 1\n",
	), 0o755); err != nil { // #nosec G302
		t.Fatal(err)
	}

	hostBytes := []byte("provider-one ssh-ed25519 AAAAC3NzaC1lZDI1NTE5FAKE\n")
	snapshot, err := securefile.AnonymousSnapshot(hostBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	request := phase1anchor.Request{
		Schema:             phase1anchor.RequestSchema,
		Kind:               phase1anchor.KindGenesis,
		MatrixID:           "phase1-auto-v1",
		SourceDigest:       strings.Repeat("1", 64),
		AutoArtifactDigest: strings.Repeat("2", 64),
		ProfileDigest:      strings.Repeat("3", 64),
		ScheduleDigest:     strings.Repeat("4", 64),
		ExpectedBatchCount: 1,
		Ordinal:            0,
	}
	canonical, err := request.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(directory, "pending")
	if err := os.MkdirAll(pending, 0o700); err != nil {
		t.Fatal(err)
	}
	sshKey := filepath.Join(directory, "anchor.key")
	if err := os.WriteFile(sshKey, []byte("fake key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The timeout is generous so a loaded host's spawn latency cannot kill
	// the fake ssh before it writes its report, and the report is waited for
	// rather than read once, because the child's exit and its directory
	// entries can be observed out of order under load.
	_ = pinProvider(
		request, canonical, pending, fakeSSH, sshKey,
		snapshot, hostBytes, 10*time.Second,
		provider{
			id: "provider-one", host: "192.0.2.1", public: public,
			previousDigest: phase1anchor.ZeroDigest,
			receiptName:    "provider-one.receipt.json",
		},
	)
	if err := waitForFile(t, report, 15*time.Second); err != nil {
		t.Fatalf("the fake ssh never ran: %v", err)
	}
	observed, err := os.ReadFile(report) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("the fake ssh never ran: %v", err)
	}
	if strings.Contains(string(observed), strings.TrimSpace(string(hostBytes))) {
		t.Fatalf(
			"a descriptor number pinProvider does not pass still yielded the "+
				"snapshot bytes; descriptor inheritance is wider than the "+
				"wiring intends:\n%s", observed,
		)
	}
}
