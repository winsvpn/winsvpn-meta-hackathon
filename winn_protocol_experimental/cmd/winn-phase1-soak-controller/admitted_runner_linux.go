//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func runAdmittedCommand(
	ctx context.Context,
	launcher *os.File,
	capabilities []*os.File,
	displayPath string,
	arguments []string,
) ([]byte, error) {
	// #nosec G204 -- the executable is the fixed descriptor path for the
	// provenance-validated launcher supplied as ExtraFiles[0]; no shell or
	// argument-derived executable path is involved.
	cmd := exec.Command("/proc/self/fd/3", arguments...)
	cmd.Args[0] = displayPath
	cmd.ExtraFiles = append([]*os.File{launcher}, capabilities...)
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout := newBoundedBuffer(admittedMaximumObjectBytes)
	stderr := newBoundedBuffer(64 << 10)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-waited:
	case <-ctx.Done():
		_ = admittedKillGroup(cmd.Process.Pid)
		waitErr = <-waited
		waitErr = errors.Join(ctx.Err(), waitErr)
	}
	if waitErr != nil {
		return nil, fmt.Errorf(
			"admitted launcher failed: %w; stderr=%q",
			waitErr, string(stderr.Bytes()),
		)
	}
	if stdout.Truncated() || stdout.Total() == 0 {
		return nil, errors.New("admitted launcher output is empty or truncated")
	}
	return stdout.Bytes(), nil
}
