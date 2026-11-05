//go:build unix

package main

import (
	"crypto/ed25519"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/phase1anchor"
	"winsvpn.local/winnprotocol/internal/securefile"
)

// Unique sleep argv so a leftover process is attributable to this test, not
// to some other lane. Foreground pipeline (no '&'): macOS /bin/sh puts
// background jobs in their own group, which would make a process-group kill
// miss them and look like a production leak of a pattern the pin tool's ssh
// child does not use.
const hungSSHSleepArg = "3471"

// TestPinProviderTimeoutReturnsAndKillsHungGrandchild is the load-bearing
// control for configurePinnedSSH. A fake ssh whose pipeline descendant keeps
// stdout open used to keep pinProvider blocked after CommandContext fired —
// measured 1m52s against a 10s timeout on
// TestRealPinProviderFailsIfTheDescriptorIsNotPassed.
//
// The 25s outer bound is why this test can go red. If pinProvider never
// returns, we fail here instead of hanging the suite. The per-provider
// timeout is deliberately generous (8s) so a loaded CI host's spawn latency
// cannot kill the fake ssh before it has touched `started`, and the started
// and leak observations below are polls with deadlines rather than single
// shots, so slow scheduling cannot masquerade as a production kill failure.
func TestPinProviderTimeoutReturnsAndKillsHungGrandchild(t *testing.T) {
	directory := t.TempDir()
	started := filepath.Join(directory, "started")
	fakeSSH := filepath.Join(directory, "fake-ssh")
	if err := os.WriteFile(fakeSSH, []byte(
		"#!/bin/sh\n"+
			"touch '"+started+"'\n"+
			"sleep "+hungSSHSleepArg+" | cat\n",
	), 0o755); err != nil { // #nosec G302
		t.Fatal(err)
	}

	hostBytes := []byte("192.0.2.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5FAKE\n")
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

	const timeout = 8 * time.Second
	done := make(chan error, 1)
	go func() {
		done <- pinProvider(
			request, canonical, pending, fakeSSH, sshKey,
			snapshot, hostBytes, timeout,
			provider{
				id:             "provider-one",
				host:           "192.0.2.1",
				public:         public,
				previousDigest: phase1anchor.ZeroDigest,
				receiptName:    "provider-one.receipt.json",
			},
		)
	}()

	var returned error
	select {
	case returned = <-done:
	case <-time.After(25 * time.Second):
		t.Fatal(
			"pinProvider still blocked 25s after an 8s per-provider timeout; " +
				"CommandContext is not bounding Output() when ssh descendants " +
				"keep stdout open",
		)
	}

	if err := waitForFile(t, started, 15*time.Second); err != nil {
		t.Fatalf("fake ssh never started: %v (pinProvider err %v)", err, returned)
	}
	var temporary temporaryError
	if !errors.As(returned, &temporary) {
		t.Fatalf("timeout must be temporary (exit 75), got %v", returned)
	}

	if leaked := hungSleepPIDsByDeadline(t, 10*time.Second); len(leaked) > 0 {
		t.Fatalf(
			"sleep %s still running 10s after the timeout kill; leaked pids %v",
			hungSSHSleepArg, leaked,
		)
	}
}

func hungSleepPIDs(t *testing.T) []string {
	t.Helper()
	command := exec.Command("ps", "-ax", "-o", "pid=", "-o", "args=")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("ps: %v", err)
	}
	want := "sleep " + hungSSHSleepArg
	var pids []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid, args, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		args = strings.TrimSpace(args)
		if args == want || strings.HasSuffix(args, "/"+want) || strings.HasPrefix(args, want+" ") {
			pids = append(pids, pid)
		}
	}
	return pids
}

// waitForFile polls until path exists or the deadline passes, and returns the
// error from the final Stat when it never appeared. The fake ssh writes its
// report as its final act before exiting, and on a loaded host the child's
// exit can be observed before its directory entries are visible here, so a
// single Stat right after pinProvider returns is a spawn-latency race.
func waitForFile(t *testing.T, path string, deadline time.Duration) error {
	t.Helper()
	limit := time.Now().Add(deadline)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(limit) {
			_, err := os.Stat(path)
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// hungSleepPIDsByDeadline polls ps until no descendant of this test's fake
// ssh remains, or the deadline passes, returning the leftovers. A single ps
// immediately after pinProvider returns races the SIGKILL delivery on a
// loaded host; the claim worth making is "gone within the deadline", not
// "gone at this instant".
func hungSleepPIDsByDeadline(t *testing.T, deadline time.Duration) []string {
	t.Helper()
	limit := time.Now().Add(deadline)
	var last []string
	for {
		last = hungSleepPIDs(t)
		if len(last) == 0 {
			return nil
		}
		if time.Now().After(limit) {
			return last
		}
		time.Sleep(100 * time.Millisecond)
	}
}
