//go:build !unix

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"testing"
)

func TestUnsupportedPlatformRefusalIsExact(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	if status := runUnsupportedPlatform(&stderr); status != 1 {
		t.Fatalf("unsupported-platform status = %d, want 1", status)
	}
	const want = "winn-webrtc-v2 requires a Unix platform\n"
	if got := stderr.String(); got != want {
		t.Fatalf("unsupported-platform stderr = %q, want %q", got, want)
	}
}

func TestUnsupportedPlatformCommandSubprocess(t *testing.T) {
	if os.Getenv("WINN_WEBRTC_UNSUPPORTED_HELPER") == "1" {
		os.Exit(runUnsupportedPlatform(os.Stderr))
	}
	command := exec.Command(os.Args[0], "-test.run=^TestUnsupportedPlatformCommandSubprocess$")
	command.Env = append(os.Environ(), "WINN_WEBRTC_UNSUPPORTED_HELPER=1")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 1 {
		t.Fatalf("unsupported subprocess error = %v, want exit status 1", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("unsupported subprocess wrote stdout %q", stdout.String())
	}
	const want = "winn-webrtc-v2 requires a Unix platform\n"
	if got := stderr.String(); got != want {
		t.Fatalf("unsupported subprocess stderr = %q, want %q", got, want)
	}
}
