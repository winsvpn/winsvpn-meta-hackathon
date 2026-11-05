//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

func TestOfflineAdapterDescriptorContractEndToEnd(t *testing.T) {
	directory := t.TempDir()
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	runnerFD, err := unix.MemfdCreate(
		"adapter-test",
		unix.MFD_ALLOW_SEALING|unix.MFD_CLOEXEC|unix.MFD_EXEC,
	)
	if err != nil {
		t.Fatal(err)
	}
	runner := os.NewFile(uintptr(runnerFD), "adapter-test")
	defer runner.Close()
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(runner, hash), source); err != nil {
		t.Fatal(err)
	}
	if err := runner.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := runner.Chmod(0o500); err != nil {
		t.Fatal(err)
	}
	const seals = unix.F_SEAL_WRITE | unix.F_SEAL_SHRINK |
		unix.F_SEAL_GROW | unix.F_SEAL_EXEC | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(runner.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	binding, encoded := testBindingWithRunnerDigest(
		t, hex.EncodeToString(hash.Sum(nil)),
	)
	bindingPath := filepath.Join(directory, "fd4-binding")
	if err := os.WriteFile(bindingPath, encoded, 0o400); err != nil {
		t.Fatal(err)
	}
	_, intentBytes, err := realcycle.NewControllerCycleIntent(encoded)
	if err != nil {
		t.Fatal(err)
	}
	intentPath := filepath.Join(directory, "fd5-intent")
	if err := os.WriteFile(intentPath, intentBytes, 0o400); err != nil {
		t.Fatal(err)
	}
	intentFile, err := os.Open(intentPath)
	if err != nil {
		t.Fatal(err)
	}
	bindingFile, err := os.Open(bindingPath)
	if err != nil {
		t.Fatal(err)
	}

	command := exec.Command(
		"/proc/self/fd/3",
		"-test.run=^TestDescriptorContractHelper$",
		"--",
		"--descriptor-contract-helper",
	)
	command.Args[0] = "sealed-adapter-test"
	command.Env = testEnvironment(binding)
	command.ExtraFiles = []*os.File{runner, bindingFile, intentFile}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("helper failed: %v stderr=%q", err, stderr.String())
	}
	var status preflightOutput
	if err := json.NewDecoder(&stdout).Decode(&status); err != nil {
		t.Fatalf("decode helper output: %v output=%q", err, stdout.String())
	}
	if status.ControllerBindingDigest != binding.ObjectDigest ||
		status.MatrixExecuted || status.Authority {
		t.Fatalf("unsafe helper output: %+v", status)
	}
}

func TestSealedRunnerRejectsMutationAndMissingSeal(t *testing.T) {
	fd, err := unix.MemfdCreate(
		"adapter-seal-test",
		unix.MFD_ALLOW_SEALING|unix.MFD_CLOEXEC|unix.MFD_EXEC,
	)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "adapter-seal-test")
	defer file.Close()
	if _, err := file.Write([]byte("sealed")); err != nil {
		t.Fatal(err)
	}
	if err := file.Chmod(0o500); err != nil {
		t.Fatal(err)
	}
	if err := requireRunnerSeals(file); err == nil {
		t.Fatal("unsealed runner unexpectedly accepted")
	}
	const seals = unix.F_SEAL_WRITE | unix.F_SEAL_SHRINK |
		unix.F_SEAL_GROW | unix.F_SEAL_EXEC | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		t.Fatal(err)
	}
	if err := requireRunnerSeals(file); err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("x"), 0); err == nil {
		t.Fatal("write to sealed runner unexpectedly succeeded")
	}
	if err := file.Truncate(1); err == nil {
		t.Fatal("truncate sealed runner unexpectedly succeeded")
	}
	if err := file.Truncate(128); err == nil {
		t.Fatal("grow sealed runner unexpectedly succeeded")
	}
	if err := file.Chmod(0o400); err == nil {
		t.Fatal("chmod sealed runner unexpectedly succeeded")
	}
}

func TestDescriptorContractHelper(t *testing.T) {
	if len(os.Args) == 0 ||
		os.Args[len(os.Args)-1] != "--descriptor-contract-helper" {
		return
	}
	runner := os.NewFile(3, "winn-sealed-runner")
	binding := os.NewFile(inheritedBindingFD, "winn-e3-binding")
	intent := os.NewFile(inheritedIntentFD, "winn-e3-intent")
	if runner == nil || binding == nil || intent == nil {
		t.Fatal("descriptors 3, 4, and 5 are unavailable")
	}
	if err := runInherited(
		runner, binding, intent, os.Environ(), os.Stdout,
	); err != nil {
		t.Fatal(err)
	}
}
