//go:build linux

package preparation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
)

type execLinuxUnderlayRunner struct {
	// allowed is the fixed set of executables this runner may launch: exactly
	// the nft and ip paths newDefaultLinuxUnderlayRunner was configured with
	// and verified to be real executables. validateLinuxUnderlayCommand checks
	// that a command path is absolute and well-formed, which is a different
	// question from whether it is one of the two binaries this runner exists to
	// drive.
	allowed map[string]struct{}
}

func newDefaultLinuxUnderlayRunner(
	nftBinary string,
	ipBinary string,
) (LinuxUnderlayCommandRunner, error) {
	for name, path := range map[string]string{
		"nft": nftBinary,
		"ip":  ipBinary,
	} {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf(
				"inspect Linux underlay %s executable: %w",
				name, err,
			)
		}
		if !info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o111 == 0 {
			return nil, fmt.Errorf(
				"linux underlay %s path is not a real executable",
				name,
			)
		}
	}
	return execLinuxUnderlayRunner{
		allowed: map[string]struct{}{
			nftBinary: {}, ipBinary: {},
		},
	}, nil
}

func (runner execLinuxUnderlayRunner) Run(
	ctx context.Context,
	command LinuxUnderlayCommand,
) (LinuxUnderlayCommandResult, error) {
	if ctx == nil {
		return LinuxUnderlayCommandResult{},
			errors.New("linux underlay command context is required")
	}
	if err := validateLinuxUnderlayCommand(command); err != nil {
		return LinuxUnderlayCommandResult{}, err
	}
	if _, ok := runner.allowed[command.Path]; !ok {
		return LinuxUnderlayCommandResult{}, fmt.Errorf(
			"refusing to execute %q: this underlay runner drives only the "+
				"configured nft and ip binaries", command.Path,
		)
	}
	// #nosec G204 -- command.Path was just required to be one of the exact two
	// executables this runner was constructed with, both of which were checked
	// at construction to be real, non-symlink, executable regular files. Args
	// are separate argv elements, are rejected if they contain NUL, and never
	// pass through a shell. This is authorised host-preparation tooling.
	process := exec.CommandContext(ctx, command.Path, command.Args...)
	var stdout linuxUnderlayBoundedBuffer
	var stderr linuxUnderlayBoundedBuffer
	process.Stdout = &stdout
	process.Stderr = &stderr
	err := process.Run()
	result := LinuxUnderlayCommandResult{
		Stdout: append([]byte(nil), stdout.data...),
		Stderr: append([]byte(nil), stderr.data...),
	}
	if stdout.exceeded || stderr.exceeded {
		clear(result.Stdout)
		clear(result.Stderr)
		return LinuxUnderlayCommandResult{},
			errors.New("linux underlay command output exceeds limit")
	}
	if err != nil {
		return result, fmt.Errorf("linux underlay command failed: %w", err)
	}
	return result, nil
}

type linuxUnderlayBoundedBuffer struct {
	mu       sync.Mutex
	data     []byte
	exceeded bool
}

func (buffer *linuxUnderlayBoundedBuffer) Write(
	value []byte,
) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	if len(buffer.data)+len(value) > maxLinuxUnderlayCommandOutput {
		buffer.exceeded = true
		remaining := maxLinuxUnderlayCommandOutput - len(buffer.data)
		if remaining > 0 {
			buffer.data = append(buffer.data, value[:remaining]...)
		}
		return len(value), nil
	}
	buffer.data = append(buffer.data, value...)
	return len(value), nil
}
