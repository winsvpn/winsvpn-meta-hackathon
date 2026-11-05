//go:build unix

package main

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

// sshChildWaitDelay is how long Output/Wait may block on leftover pipes after
// the ssh leader has exited. Zero (the Go default) waits for EOF forever.
const sshChildWaitDelay = time.Second

// configurePinnedSSH makes the per-provider timeout actually bound pinProvider.
//
// CommandContext alone sends SIGKILL to the ssh leader. A helper or a shell
// pipeline that keeps stdout open leaves Cmd.Wait stuck in awaitGoroutines
// after that leader is gone. Measured 2026-08-13: TestRealPinProviderFailsIfTheDescriptorIsNotPassed
// ran 1m52s against a 10s context timeout, with Output blocked on a live stdout
// copy and no ANCHOR_PIN line emitted.
//
// WaitDelay is the I/O unstick. The process-group kill is so descendants do not
// leak. The group is signalled only when the child is confirmed to be the
// leader of its own group — kill(-N) on a shared group would reach this pin
// tool and its siblings (see cmd/winn-phase1-soak-controller/killplan.go).
func configurePinnedSSH(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = sshChildWaitDelay
	command.Cancel = func() error {
		return killPinnedSSH(command.Process)
	}
}

func killPinnedSSH(proc *os.Process) error {
	if proc == nil || proc.Pid <= 1 {
		return os.ErrProcessDone
	}
	pgid, err := syscall.Getpgid(proc.Pid)
	if err != nil {
		return proc.Kill()
	}
	if pgid != proc.Pid {
		return proc.Kill()
	}
	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil {
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	return nil
}
