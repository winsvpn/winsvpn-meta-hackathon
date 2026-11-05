//go:build !unix

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"time"
)

// execRunner does not exist off unix.
//
// The fields are declared so the rest of the program compiles unchanged, and
// RunCycle refuses rather than degrading: a soak controller that could not put
// its child in its own process group would have no safe way to clean one up,
// and running anyway on a best-effort basis is how a shared host loses an
// unrelated service.
type execRunner struct {
	runnerPath     string
	runnerFile     *os.File
	procRoot       string
	cgroupRoot     string
	sampleInterval time.Duration
	childLog       io.Writer
	killGrace      time.Duration
}

var errExecRunnerUnsupported = errors.New(
	"the process-group-scoped cycle runner requires a unix platform",
)

func (r *execRunner) RunCycle(context.Context, CycleRequest) (CycleResult, error) {
	return CycleResult{}, errExecRunnerUnsupported
}
