//go:build unix && !linux

package main

import (
	"errors"
	"os/exec"
)

type nonLinuxCycleContainment struct{}

func prepareCycleContainment(
	_, _ string, _ int64, required bool,
) (cycleContainment, error) {
	if required {
		return nil, errors.New(
			"formal cycle containment requires Linux cgroup v2; refusing fallback",
		)
	}
	return nonLinuxCycleContainment{}, nil
}

func (nonLinuxCycleContainment) Configure(*exec.Cmd) error { return nil }
func (nonLinuxCycleContainment) Sample(string) (
	int64, int64, int64, bool, error,
) {
	return 0, 0, 0, false, nil
}
func (nonLinuxCycleContainment) TerminateAll() error { return nil }
func (nonLinuxCycleContainment) KillAll() error      { return nil }
func (nonLinuxCycleContainment) Finish() (CycleContainmentCleanup, error) {
	return nonApplicableContainmentCleanup(), nil
}
