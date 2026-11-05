//go:build unix

package main

import (
	"net/netip"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestValidateCandidatesAcceptsGatewaySrflxAndMDNS(t *testing.T) {
	t.Parallel()
	cfg := config{
		family: "v4", expected: netip.MustParseAddr("198.51.100.9"),
		allowedHosts: map[netip.Addr]struct{}{},
		forbidden: map[netip.Addr]struct{}{
			netip.MustParseAddr("192.0.2.10"): {},
		},
	}
	result := browserResult{
		GatheringState: "complete",
		Candidates: []iceCandidate{
			{Candidate: "candidate:1 1 udp 1 host-id.local 5000 typ host"},
			{
				Candidate:      "candidate:2 1 udp 1 198.51.100.9 6000 typ srflx raddr 0.0.0.0 rport 0",
				RelatedAddress: "0.0.0.0",
			},
		},
	}
	if err := validateCandidates(cfg, result); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCandidatesRejectsForbiddenAndUnexpectedSrflx(t *testing.T) {
	t.Parallel()
	base := config{
		family: "v4", expected: netip.MustParseAddr("198.51.100.9"),
		allowedHosts: map[netip.Addr]struct{}{},
		forbidden: map[netip.Addr]struct{}{
			netip.MustParseAddr("192.0.2.10"): {},
		},
	}
	for name, candidate := range map[string]iceCandidate{
		"forbidden host": {
			Candidate: "candidate:1 1 udp 1 192.0.2.10 5000 typ host",
		},
		"wrong egress": {
			Candidate: "candidate:1 1 udp 1 203.0.113.7 5000 typ srflx",
		},
	} {
		t.Run(name, func(t *testing.T) {
			result := browserResult{
				GatheringState: "complete",
				Candidates:     []iceCandidate{candidate},
			}
			if err := validateCandidates(base, result); err == nil {
				t.Fatal("unsafe candidate accepted")
			}
		})
	}
}

func TestValidateCandidatesRequiresExpectedSrflx(t *testing.T) {
	t.Parallel()
	cfg := config{
		family: "v6", expected: netip.MustParseAddr("2001:db8::9"),
		allowedHosts: map[netip.Addr]struct{}{},
		forbidden: map[netip.Addr]struct{}{
			netip.MustParseAddr("2001:db8:1::10"): {},
		},
	}
	result := browserResult{
		GatheringState: "complete",
		Candidates: []iceCandidate{{
			Candidate: "candidate:1 1 udp 1 host-id.local 5000 typ host",
		}},
	}
	if err := validateCandidates(cfg, result); err == nil {
		t.Fatal("missing server-reflexive candidate accepted")
	}
}

func TestValidateCandidatesRejectsUnsafeRedactedRelatedEndpoint(t *testing.T) {
	t.Parallel()
	cfg := config{
		family: "v4", expected: netip.MustParseAddr("198.51.100.9"),
		allowedHosts: map[netip.Addr]struct{}{},
		forbidden:    map[netip.Addr]struct{}{},
	}
	for name, candidate := range map[string]iceCandidate{
		"nonzero port": {
			Candidate:      "candidate:1 1 udp 1 198.51.100.9 6000 typ srflx",
			RelatedAddress: "0.0.0.0",
			RelatedPort:    1234,
		},
		"wrong family": {
			Candidate:      "candidate:1 1 udp 1 198.51.100.9 6000 typ srflx",
			RelatedAddress: "::",
		},
		"host candidate": {
			Candidate:      "candidate:1 1 udp 1 10.0.0.2 6000 typ host",
			RelatedAddress: "0.0.0.0",
		},
	} {
		t.Run(name, func(t *testing.T) {
			result := browserResult{
				GatheringState: "complete",
				Candidates:     []iceCandidate{candidate},
			}
			if err := validateCandidates(cfg, result); err == nil {
				t.Fatal("unsafe redacted related endpoint accepted")
			}
		})
	}
}

func TestFillCandidateFields(t *testing.T) {
	t.Parallel()
	candidate := iceCandidate{
		Candidate: "candidate:abc 1 UDP 123 198.51.100.9 4567 typ srflx raddr 10.0.0.2 rport 1234",
	}
	fillCandidateFields(&candidate)
	if candidate.Address != "198.51.100.9" || candidate.Port != 4567 ||
		candidate.Protocol != "udp" || candidate.Type != "srflx" ||
		candidate.RelatedAddress != "10.0.0.2" ||
		candidate.RelatedPort != 1234 {
		t.Fatalf("unexpected parse: %+v", candidate)
	}
}

func TestParseConfigRequiresForbiddenAddresses(t *testing.T) {
	t.Parallel()
	_, err := parseConfig([]string{
		"-run-id=00112233445566778899aabbccddeeff",
		"-family=v4",
		"-browser=/usr/bin/chromium",
		"-stun-server=198.51.100.2:3478",
		"-expected-egress=198.51.100.9",
		"-output=/tmp/evidence.json",
	})
	if err == nil {
		t.Fatal("empty forbidden address set accepted")
	}
}

func TestChromiumProcessStopKillsExactProcessGroup(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "sleep 30 & wait")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	pgid, err := syscall.Getpgid(command.Process.Pid)
	if err != nil || pgid != command.Process.Pid {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("dedicated group: pgid=%d err=%v", pgid, err)
	}
	process := &chromiumProcess{
		command: command, pgid: pgid, done: make(chan struct{}),
	}
	go func() {
		err := command.Wait()
		process.mu.Lock()
		process.err = err
		process.mu.Unlock()
		close(process.done)
	}()
	time.Sleep(25 * time.Millisecond)
	if err := process.stop(); err != nil {
		t.Fatal(err)
	}
	if process.groupAlive() {
		t.Fatal("dedicated process group survived cleanup")
	}
}

func TestLoopbackWebSocketHost(t *testing.T) {
	for _, host := range []string{
		"localhost", "127.0.0.1", "127.23.45.67", "::1",
	} {
		if !loopbackWebSocketHost(host) {
			t.Errorf("loopbackWebSocketHost(%q) = false", host)
		}
	}
	for _, host := range []string{
		"", "0.0.0.0", "::", "192.168.1.1", "example.com",
	} {
		if loopbackWebSocketHost(host) {
			t.Errorf("loopbackWebSocketHost(%q) = true", host)
		}
	}
}

func TestDevToolsListURLIncludesTrustedPort(t *testing.T) {
	if got, want := devToolsListURL(43123),
		"http://127.0.0.1:43123/json/list"; got != want {
		t.Fatalf("devToolsListURL() = %q, want %q", got, want)
	}
}

func TestWaitProcessGroupGoneAllowsNaturalChildExit(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "sleep 0.05 &")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	pgid, err := syscall.Getpgid(command.Process.Pid)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	if !waitProcessGroupGone(pgid, time.Second) {
		_ = terminateExactGroup(pgid)
		t.Fatal("naturally exiting child process group remained")
	}
}

func TestWaitProcessGroupGoneDoesNotHideResidue(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "sleep 30 &")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	pgid, err := syscall.Getpgid(command.Process.Pid)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	if waitProcessGroupGone(pgid, 20*time.Millisecond) {
		t.Fatal("persistent child process group was treated as gone")
	}
	if err := terminateExactGroup(pgid); err != nil {
		t.Fatal(err)
	}
}
