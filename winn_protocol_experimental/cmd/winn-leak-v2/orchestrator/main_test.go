//go:build unix

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
)

func TestDeriveRunIDIsBoundToFamilyAndScenario(t *testing.T) {
	t.Parallel()
	seed := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	values := []string{
		deriveRunID(seed, "v4", "graceful"),
		deriveRunID(seed, "v4", "outage"),
		deriveRunID(seed, "v4", "crash"),
		deriveRunID(seed, "v6", "graceful"),
		deriveRunID(seed, "v6", "outage"),
		deriveRunID(seed, "v6", "crash"),
	}
	for index, value := range values {
		if !lowerHex(value, 16) {
			t.Fatalf("run ID %d is invalid: %q", index, value)
		}
		for other := 0; other < index; other++ {
			if values[other] == value {
				t.Fatalf("run ID collision at %d and %d", index, other)
			}
		}
	}
}

func TestOrderedSubsequence(t *testing.T) {
	t.Parallel()
	phases := []string{"starting", "prepared", "verified", "committed", "stopping", "stopped"}
	if !orderedSubsequence(phases, phases) {
		t.Fatal("exact order rejected")
	}
	if !orderedSubsequence(phases, []string{"prepared", "committed", "stopped"}) {
		t.Fatal("valid subsequence rejected")
	}
	if orderedSubsequence(phases, []string{"committed", "prepared"}) {
		t.Fatal("out-of-order sequence accepted")
	}
}

func TestCredentialModeCanExecute(t *testing.T) {
	credential := &syscall.Credential{
		Uid: 1001, Gid: 1002, Groups: []uint32{1003},
	}
	tests := []struct {
		name     string
		mode     os.FileMode
		ownerUID uint32
		ownerGID uint32
		want     bool
	}{
		{name: "owner", mode: 0o100, ownerUID: 1001, ownerGID: 2000, want: true},
		{name: "primary group", mode: 0o010, ownerUID: 2000, ownerGID: 1002, want: true},
		{name: "supplementary group", mode: 0o010, ownerUID: 2000, ownerGID: 1003, want: true},
		{name: "other", mode: 0o001, ownerUID: 2000, ownerGID: 2001, want: true},
		{name: "denied", mode: 0o700, ownerUID: 2000, ownerGID: 2001, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := credentialModeCanExecute(
				test.mode, test.ownerUID, test.ownerGID, credential,
			); got != test.want {
				t.Fatalf("credentialModeCanExecute() = %v, want %v", got, test.want)
			}
		})
	}
	if credentialModeCanExecute(0o111, 0, 0, nil) {
		t.Fatal("nil credential was permitted")
	}
	if credentialModeCanExecute(
		0o111, 0, 0, &syscall.Credential{Uid: 0},
	) {
		t.Fatal("root credential was permitted")
	}
}

func TestValidateClientArgsRejectsControlledFlags(t *testing.T) {
	t.Parallel()
	for _, argument := range []string{
		"-run-id=abc", "-family=v4", "-control-dir=/tmp/x",
		"-state-file=/tmp/x", "-event-log=/tmp/x", "-temp-root=/tmp/x",
		"-command-timeout=1h", "-crash-ack=yes",
	} {
		if err := validateClientArgs([]string{argument}); err == nil {
			t.Fatalf("controlled argument %q accepted", argument)
		}
	}
	if err := validateClientArgs([]string{"-gateway-endpoint=192.0.2.1:443"}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateConfigRequiresExactFamilyPair(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.Families = append(cfg.Families, cfg.Families[0])
	if err := validateConfig(cfg); err == nil {
		t.Fatal("duplicate/extra family accepted")
	}
	cfg = validConfig()
	cfg.ObserverIdentity = cfg.GatewayIdentity
	if err := validateConfig(cfg); err == nil {
		t.Fatal("co-located identity accepted")
	}
}

func TestSortedFamilyConfigs(t *testing.T) {
	t.Parallel()
	values := []familyConfig{{Family: "v6"}, {Family: "v4"}}
	got := sortedFamilyConfigs(values)
	if !slices.EqualFunc(got, []familyConfig{{Family: "v4"}, {Family: "v6"}},
		func(left, right familyConfig) bool { return left.Family == right.Family }) {
		t.Fatalf("unexpected order: %+v", got)
	}
}

func TestExactStateBarrierUsesRunFamilyAndPID(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.Mkdir("control", 0o700); err != nil {
		t.Fatal(err)
	}
	eventFile, err := root.OpenFile(
		"suite-events.jsonl",
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	driver := &suite{
		config: config{PhaseTimeoutSecond: 15},
		events: &eventWriter{
			file: eventFile, encoder: json.NewEncoder(eventFile),
		},
	}
	scenario := &scenarioRuntime{
		suite: driver, root: root, directory: directory,
		runID:  "00112233445566778899aabbccddeeff",
		family: familyConfig{Family: "v4"}, scenario: "graceful",
		process: &managedProcess{
			command: &exec.Cmd{Process: current},
			done:    make(chan struct{}),
		},
	}
	state, err := json.Marshal(clientState{
		Version: "winn-leak-client/v2", RunID: scenario.runID,
		Family: "v4", Phase: "prepared", PID: os.Getpid(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("state.json", state, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := scenario.waitState("prepared"); err != nil {
		t.Fatal(err)
	}
	if err := scenario.barrier("continue-prepared"); err != nil {
		t.Fatal(err)
	}
	info, err := root.Stat(filepath.Join("control", "continue-prepared"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("barrier size/mode=%d/%#o", info.Size(), info.Mode().Perm())
	}
	if err := scenario.barrier("continue-prepared"); !os.IsExist(err) {
		t.Fatalf("duplicate barrier error=%v", err)
	}
	if err := driver.events.close(); err != nil {
		t.Fatal(err)
	}
}

func validConfig() config {
	common := config{
		Version:      configVersion,
		RunSeed:      "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		EvidenceRoot: "/private/evidence", ClientBinary: "/opt/winn/client",
		WebRTCBinary: "/opt/winn/webrtc", BrowserBinary: "/opt/chrome/chrome",
		WebRTCUser:  "winn-webrtc",
		GatewayHook: "/opt/winn/gateway-hook", ObserverHook: "/opt/winn/observer-hook",
		ProbeHook: "/opt/winn/probe-hook", RecoveryHook: "/opt/winn/recovery-hook",
		GatewayIdentity:    "provider-a/account-a/gateway",
		ObserverIdentity:   "provider-b/account-b/observer",
		PhaseTimeoutSecond: 60, HookTimeoutSecond: 30,
	}
	common.Families = []familyConfig{
		{
			Family: "v4", ClientArgs: []string{"-gateway-endpoint=192.0.2.1:443"},
			STUNServer: "198.51.100.2:3478", ExpectedEgress: "198.51.100.9",
			ForbiddenAddresses: []string{"192.0.2.10"},
		},
		{
			Family: "v6", ClientArgs: []string{"-gateway-endpoint=[2001:db8::1]:443"},
			STUNServer: "[2001:db8::2]:3478", ExpectedEgress: "2001:db8::9",
			ForbiddenAddresses: []string{"2001:db8:1::10"},
		},
	}
	return common
}
