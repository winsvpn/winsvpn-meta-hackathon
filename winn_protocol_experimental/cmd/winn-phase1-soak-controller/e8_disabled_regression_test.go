package main

import (
	"os"
	"strings"
	"testing"
)

func TestIncompleteE8ModeIsNotExposedByProductionCLI(t *testing.T) {
	runCLI := func(t *testing.T, arguments ...string) (int, string) {
		t.Helper()
		stdout, err := os.CreateTemp(t.TempDir(), "stdout")
		if err != nil {
			t.Fatal(err)
		}
		defer stdout.Close()
		stderr, err := os.CreateTemp(t.TempDir(), "stderr")
		if err != nil {
			t.Fatal(err)
		}
		defer stderr.Close()

		status := run(arguments, stdout, stderr, os.Environ())
		if _, err := stderr.Seek(0, 0); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(stderr.Name())
		if err != nil {
			t.Fatal(err)
		}
		return status, string(data)
	}

	const historicalMode = "-admitted-e8-r4-local-sealed-rehearsal"
	status, diagnostic := runCLI(t, historicalMode)
	if status != exitUsage {
		t.Fatalf("historical incomplete E8 mode exited %d, want usage refusal %d",
			status, exitUsage)
	}
	if !strings.Contains(diagnostic, "flag provided but not defined") ||
		!strings.Contains(diagnostic, historicalMode) {
		t.Fatalf("historical incomplete E8 mode was not rejected as unknown: %q",
			diagnostic)
	}

	status, help := runCLI(t, "-h")
	if status != exitUsage {
		t.Fatalf("help exited %d, want usage status %d", status, exitUsage)
	}
	if strings.Contains(strings.ToLower(help), "e8") ||
		strings.Contains(help, historicalMode) {
		t.Fatalf("production help unexpectedly exposes an E8 surface: %q", help)
	}
}
