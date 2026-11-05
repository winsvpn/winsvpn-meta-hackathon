//go:build unix

package main

import "os/exec"

type cycleContainment interface {
	Configure(*exec.Cmd) error
	Sample(procRoot string) (
		threads, openFiles, rssBytes int64, supported bool, err error,
	)
	TerminateAll() error
	KillAll() error
	Finish() (CycleContainmentCleanup, error)
}

var cycleContainmentPreparer = prepareCycleContainment
