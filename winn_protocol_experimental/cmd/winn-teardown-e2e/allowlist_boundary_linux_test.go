//go:build linux

// The allow-list denial at THIS harness's own exec boundary.
//
// LinuxExecAllowList is tested directly in internal/directawg. What cannot be
// tested there is whether each harness actually consults it, in BOTH Run and
// Start, before reaching os/exec — and that is the property the control
// depends on, because the list is per-runner and enforced only where a runner
// calls it. A runner that forgot one of the two methods would leave a hole the
// package-level tests cannot see.
//
// A refusal here must therefore come back with nothing executed. The command
// used is a real, ordinary binary that is simply not in this runner's
// configured set, so an acceptance would genuinely run something.
package main

import (
	"context"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/directawg"
)

func TestHarnessRunnerRefusesUnconfiguredExecutable(t *testing.T) {
	allowed, err := directawg.NewLinuxExecAllowList("/usr/sbin/nft", "/usr/bin/resolvectl", "/usr/bin/amneziawg-go",
		"/usr/bin/awg", "/usr/bin/ip")
	if err != nil {
		t.Fatal(err)
	}
	runner := newFaultRunner(
		"/usr/bin/resolvectl", "/usr/sbin/nft", "/usr/bin/ip", allowed,
	)
	forbidden := directawg.LinuxCommand{
		Path: "/bin/sh",
		Args: []string{"-c", "exit 0"},
	}

	t.Run("Run", func(t *testing.T) {
		if _, err := runner.Run(context.Background(), forbidden); err == nil ||
			!strings.Contains(err.Error(), "refusing to execute") {
			t.Fatalf(
				"Run accepted an unconfigured executable (err = %v); the "+
					"allow-list is not consulted at this exec boundary", err,
			)
		}
	})
	t.Run("Start", func(t *testing.T) {
		process, err := runner.Start(forbidden)
		if err == nil || !strings.Contains(err.Error(), "refusing to execute") {
			t.Fatalf(
				"Start accepted an unconfigured executable (err = %v); Run "+
					"and Start are two separate exec boundaries and both must "+
					"consult the list", err,
			)
		}
		if process != nil {
			t.Fatal("a refused Start returned a managed process")
		}
	})

	// Positive control. A runner that refused everything would satisfy both
	// assertions above while enforcing nothing meaningful.
	t.Run("configured_executable_is_not_refused_by_the_list", func(t *testing.T) {
		if err := allowed.Require("/usr/bin/ip"); err != nil {
			t.Fatalf("the configured executable was refused: %v", err)
		}
	})
}
