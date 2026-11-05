package directawg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

type execLinuxRunner struct{}

func newExecLinuxRunner() LinuxCommandRunner {
	return execLinuxRunner{}
}

func (execLinuxRunner) Run(
	ctx context.Context,
	command LinuxCommand,
) (LinuxCommandResult, error) {
	if ctx == nil {
		return LinuxCommandResult{}, errors.New(
			"linux command context is required",
		)
	}
	if err := validateLinuxCommand(command); err != nil {
		return LinuxCommandResult{}, err
	}
	// #nosec G204 -- no shell is involved; validateLinuxCommand above
	// requires command.Path to be an absolute regular executable file.
	process := exec.CommandContext(ctx, command.Path, command.Args...)
	var stdout boundedBuffer
	var stderr boundedBuffer
	stdout.limit = maxCLIOutput
	stderr.limit = 64 << 10
	process.Stdout = &stdout
	process.Stderr = &stderr
	err := process.Run()
	result := LinuxCommandResult{
		Stdout: append([]byte(nil), stdout.Bytes()...),
		Stderr: append([]byte(nil), stderr.Bytes()...),
	}
	if stdout.exceeded || stderr.exceeded {
		return result, errors.New("linux command output exceeds limit")
	}
	if err != nil {
		return result, fmt.Errorf("linux command failed: %w", err)
	}
	return result, nil
}

func (execLinuxRunner) Start(
	command LinuxCommand,
) (LinuxManagedProcess, error) {
	if err := validateLinuxCommand(command); err != nil {
		return nil, err
	}
	// #nosec G204 -- no shell is involved; validateLinuxCommand above
	// requires command.Path to be an absolute regular executable file.
	process := exec.Command(command.Path, command.Args...)
	process.Stdin = nil
	process.Stdout = io.Discard
	process.Stderr = io.Discard
	if err := process.Start(); err != nil {
		return nil, err
	}
	managed := &execLinuxProcess{
		process: process,
		exited:  make(chan struct{}),
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

type execLinuxProcess struct {
	process  *exec.Cmd
	exited   chan struct{}
	mu       sync.Mutex
	err      error
	stopOnce sync.Once
	stopErr  error
}

func (process *execLinuxProcess) Exited() <-chan struct{} {
	return process.exited
}

func (process *execLinuxProcess) Err() error {
	select {
	case <-process.exited:
	default:
		return nil
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.err
}

func (process *execLinuxProcess) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	process.stopOnce.Do(func() {
		select {
		case <-process.exited:
			return
		default:
		}
		if err := process.process.Process.Signal(os.Interrupt); err != nil {
			_ = process.process.Process.Kill()
		}
		select {
		case <-process.exited:
		case <-ctx.Done():
			killErr := process.process.Process.Kill()
			<-process.exited
			// The caller's deadline caused escalation, but the required
			// postcondition is now proven: the process exited. Caching the
			// expired context here would make every retry report failure and
			// prevent the Linux session from releasing its leases.
			if killErr != nil &&
				!errors.Is(killErr, os.ErrProcessDone) {
				process.stopErr = fmt.Errorf(
					"kill Linux process after stop deadline: %w",
					killErr,
				)
			}
		}
	})
	return process.stopErr
}

func validateLinuxCommand(command LinuxCommand) error {
	if err := validateLinuxExecutable(command.Path); err != nil {
		return err
	}
	for _, argument := range command.Args {
		if stringsContainsNUL(argument) {
			return errors.New("linux command argument contains NUL")
		}
	}
	return nil
}

func stringsContainsNUL(value string) bool {
	for index := range len(value) {
		if value[index] == 0 {
			return true
		}
	}
	return false
}
