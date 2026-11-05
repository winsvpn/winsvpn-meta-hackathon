//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	"winsvpn.local/winnprotocol/internal/directawg"
)

// realLinuxRunner deliberately executes resolvectl rather than intercepting
// it. The v2 client must run in a disposable VM/container with its own real
// systemd-resolved instance; the older namespace harness is rejected because
// its root-namespace resolver cannot see the candidate link.
type realLinuxRunner struct {
	// allowed is the fixed set of executables this runner may launch.
	allowed *directawg.LinuxExecAllowList
}

func newRealLinuxRunner(
	allowed *directawg.LinuxExecAllowList,
) *realLinuxRunner {
	return &realLinuxRunner{allowed: allowed}
}

func (runner *realLinuxRunner) Run(
	ctx context.Context,
	command directawg.LinuxCommand,
) (directawg.LinuxCommandResult, error) {
	if err := runner.allowed.Require(command.Path); err != nil {
		return directawg.LinuxCommandResult{}, err
	}
	// #nosec G204 -- command.Path was just required to be a member of this
	// runner's fixed allow-list, built from the executables the operator named
	// on the command line and validated as absolute paths. Args are passed as
	// separate argv elements and never through a shell, so no argument can
	// introduce a second command. This is authorised lab tooling driving hosts
	// the operator controls. The list pins the path STRING, not the executable
	// object behind it: see LinuxExecAllowList for the exact scope, including
	// the exec boundaries it does not cover.
	process := exec.CommandContext(ctx, command.Path, command.Args...)
	var stdout, stderr strings.Builder
	process.Stdout = &stdout
	process.Stderr = &stderr
	err := process.Run()
	result := directawg.LinuxCommandResult{
		Stdout: []byte(stdout.String()), Stderr: []byte(stderr.String()),
	}
	if err != nil {
		return result, fmt.Errorf(
			"%s %s: %w: %s",
			command.Path, strings.Join(command.Args, " "), err, stderr.String(),
		)
	}
	return result, nil
}

func (runner *realLinuxRunner) Start(
	command directawg.LinuxCommand,
) (directawg.LinuxManagedProcess, error) {
	if err := runner.allowed.Require(command.Path); err != nil {
		return nil, err
	}
	// #nosec G204 -- command.Path was just required to be a member of this
	// runner's fixed allow-list, built from the executables the operator named
	// on the command line and validated as absolute paths. Args are passed as
	// separate argv elements and never through a shell, so no argument can
	// introduce a second command. This is authorised lab tooling driving hosts
	// the operator controls. The list pins the path STRING, not the executable
	// object behind it: see LinuxExecAllowList for the exact scope, including
	// the exec boundaries it does not cover.
	process := exec.Command(command.Path, command.Args...)
	process.Stdout = os.Stdout
	process.Stderr = os.Stderr
	if err := process.Start(); err != nil {
		return nil, err
	}
	managed := &realLeakProcess{
		process: process, exited: make(chan struct{}),
	}
	go func() {
		err := process.Wait()
		managed.mu.Lock()
		managed.err = err
		managed.mu.Unlock()
		close(managed.exited)
	}()
	return managed, nil
}

type realLeakProcess struct {
	process  *exec.Cmd
	exited   chan struct{}
	mu       sync.Mutex
	err      error
	stopOnce sync.Once
	stopErr  error
}

func (process *realLeakProcess) Exited() <-chan struct{} { return process.exited }

func (process *realLeakProcess) Err() error {
	select {
	case <-process.exited:
	default:
		return nil
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.err
}

func (process *realLeakProcess) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	process.stopOnce.Do(func() {
		select {
		case <-process.exited:
			return
		default:
		}
		signalError := process.process.Process.Signal(os.Interrupt)
		if signalError != nil {
			_ = process.process.Process.Kill()
		}
		select {
		case <-process.exited:
		case <-ctx.Done():
			process.stopErr = errors.Join(signalError, context.Cause(ctx))
			_ = process.process.Process.Kill()
			<-process.exited
		}
	})
	return process.stopErr
}
