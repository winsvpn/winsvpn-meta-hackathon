//go:build linux

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAdmittedCommandExecutesOwnedDescriptorWithEmptyEnvironment(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	output, err := runAdmittedCommand(
		context.Background(), file, nil, executable,
		[]string{"-test.run=TestAdmittedCommandHelper", "--", "emit"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseAdmittedResult(output); err != nil {
		t.Fatalf("helper result did not replay: %v", err)
	}
}

func TestAdmittedCapabilityPathsPassAcceptedE3SafetyChecks(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	launcher, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = launcher.Close() }()
	contractPath := privateTestDirectory(t)
	statePath := privateTestDirectory(t)
	if err := os.WriteFile(
		filepath.Join(contractPath, "contract.json"), []byte("{}"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	contractDir := openTestSecureDirectory(t, contractPath)
	stateDir := openTestSecureDirectory(t, statePath)
	output, err := runAdmittedCommand(
		context.Background(), launcher,
		[]*os.File{contractDir.file, stateDir.file}, executable,
		[]string{
			"-test.run=TestAdmittedCommandHelper", "--", "e3-paths",
			"/proc/self/fd/4/contract.json", "/proc/self/fd/5/.",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseAdmittedResult(output); err != nil {
		t.Fatalf("E3-compatible capability helper result: %v", err)
	}
}

func TestAdmittedCommandTimeoutKillsOwnedGroup(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := runAdmittedCommand(
		ctx, file, nil, executable,
		[]string{"-test.run=TestAdmittedCommandHelper", "--", "sleep"},
	); err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("timeout did not fail closed: %v", err)
	}
}

func TestAdmittedCommandHelper(t *testing.T) {
	if len(os.Args) < 2 {
		return
	}
	mode := os.Args[len(os.Args)-1]
	if len(os.Args) >= 4 && os.Args[len(os.Args)-3] == "e3-paths" {
		mode = "e3-paths"
		contractPath := os.Args[len(os.Args)-2]
		statePath := os.Args[len(os.Args)-1]
		info, err := os.Lstat(contractPath)
		if err != nil || !info.Mode().IsRegular() {
			os.Exit(3)
		}
		contract, err := os.ReadFile(contractPath)
		if err != nil || string(contract) != "{}" {
			os.Exit(4)
		}
		fd, err := unix.Open(
			statePath,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		if err != nil {
			os.Exit(5)
		}
		_ = unix.Close(fd)
	}
	switch mode {
	case "sleep":
		time.Sleep(time.Minute)
		os.Exit(0)
	case "emit":
		fallthrough
	case "e3-paths":
		result := validAdmittedReceipt().Result
		data, err := json.Marshal(result)
		if err != nil {
			os.Exit(2)
		}
		_, _ = os.Stdout.Write(append(data, '\n'))
		os.Exit(0)
	}
}
