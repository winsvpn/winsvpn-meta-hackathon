//go:build unix

package main

import "syscall"

//lint:ignore U1000 used by the Linux process-group runner.
var admittedKillGroup = func(pid int) error {
	return syscall.Kill(-pid, syscall.SIGKILL)
}
