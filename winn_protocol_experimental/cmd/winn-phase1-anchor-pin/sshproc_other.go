//go:build !unix

package main

import (
	"os/exec"
	"time"
)

const sshChildWaitDelay = time.Second

// configurePinnedSSH on non-unix cannot create a process group. WaitDelay still
// stops Output from blocking forever after the leader is killed.
func configurePinnedSSH(command *exec.Cmd) {
	command.WaitDelay = sshChildWaitDelay
}
