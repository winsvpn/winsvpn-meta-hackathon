//go:build unix

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	execHelperModeVariable = "WINN_EXEC_RUNNER_TEST_MODE"
	execHelperPIDFile      = "WINN_EXEC_RUNNER_TEST_PID_FILE"
)

func TestExecRunnerHelperProcess(t *testing.T) {
	mode := os.Getenv(execHelperModeVariable)
	if mode == "" {
		return
	}
	switch mode {
	case "graceful":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM)
		<-signals
		os.Exit(0)
	case "ignore":
		signal.Ignore(syscall.SIGTERM)
		for {
			time.Sleep(time.Hour)
		}
	case "descendants":
		executable, err := os.Executable()
		if err != nil {
			os.Exit(91)
		}
		child := exec.Command(executable,
			"-test.run=^TestExecRunnerHelperProcess$")
		child.Env = append(os.Environ(), execHelperModeVariable+"=ignore")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(92)
		}
		if err := os.WriteFile(
			os.Getenv(execHelperPIDFile),
			[]byte(strconv.Itoa(child.Process.Pid)+"\n"), 0o600,
		); err != nil {
			os.Exit(93)
		}
		signal.Ignore(syscall.SIGTERM)
		for {
			time.Sleep(time.Hour)
		}
	default:
		os.Exit(94)
	}
}

func execHelperFixture(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test executable: %v", err)
	}
	return executableFixture(t,
		"exec "+shellQuote(executable)+" -test.run=^TestExecRunnerHelperProcess$")
}

func executableFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runner.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatalf("write runner fixture: %v", err)
	}
	return path
}

func execRequest(path string, timeout time.Duration) CycleRequest {
	return CycleRequest{
		Sequence:    1,
		Readiness:   ReadinessWarm,
		Timeout:     timeout,
		OutputLimit: 4096,
		Environment: []string{
			"PATH=/usr/bin:/bin",
			"GORACE=atexit_sleep_ms=0",
		},
		WorkingDirectory: filepath.Dir(path),
	}
}

func execTestRunner(t *testing.T, path string, grace time.Duration) *execRunner {
	t.Helper()
	log, err := newRotatingLog(t.TempDir(), "cycle.log", 1<<20, 2)
	if err != nil {
		t.Fatalf("open child log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return &execRunner{
		runnerPath:     path,
		procRoot:       "/proc",
		sampleInterval: time.Millisecond,
		childLog:       log,
		killGrace:      grace,
	}
}

func TestExecRunnerQuickExitUsesRealWaitPath(t *testing.T) {
	path := executableFixture(t,
		"printf 'hello\\n'; printf 'problem\\n' >&2; exit 0")
	runner := execTestRunner(t, path, 50*time.Millisecond)
	result, err := runner.RunCycle(
		// Process startup under a full -race ./... run can be delayed by
		// several seconds even though the child exits immediately. This test
		// exercises the real wait path, not the one-second timeout boundary.
		context.Background(), execRequest(path, 10*time.Second),
	)
	if err != nil {
		t.Fatalf("RunCycle: %v", err)
	}
	if result.Outcome != OutcomeSucceeded || result.ExitStatus != 0 {
		t.Fatalf("outcome=%s exit=%d", result.Outcome, result.ExitStatus)
	}
	if string(result.StdoutTail) != "hello\n" ||
		string(result.StderrTail) != "problem\n" {
		t.Fatalf("tails stdout=%q stderr=%q",
			result.StdoutTail, result.StderrTail)
	}
}

func TestExecRunnerGracefulTermDoesNotPayFullGrace(t *testing.T) {
	path := execHelperFixture(t)
	const grace = 2 * time.Second
	const timeout = 2 * time.Second
	runner := execTestRunner(t, path, grace)
	request := execRequest(path, timeout)
	request.Environment = append(
		request.Environment, execHelperModeVariable+"=graceful",
	)
	started := time.Now()
	result, err := runner.RunCycle(
		context.Background(), request,
	)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("RunCycle: %v", err)
	}
	if result.Outcome != OutcomeTimedOut {
		t.Fatalf("outcome=%s, want timed_out", result.Outcome)
	}
	if elapsed >= timeout+grace/2 {
		t.Fatalf("graceful child took %s; it paid the %s kill grace", elapsed, grace)
	}
}

func TestExecRunnerTermIgnoringChildIsKilledAndReaped(t *testing.T) {
	path := execHelperFixture(t)
	const grace = 80 * time.Millisecond
	const timeout = 2 * time.Second
	runner := execTestRunner(t, path, grace)
	request := execRequest(path, timeout)
	request.Environment = append(
		request.Environment, execHelperModeVariable+"=ignore",
	)
	started := time.Now()
	result, err := runner.RunCycle(
		context.Background(), request,
	)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("RunCycle: %v", err)
	}
	if result.Outcome != OutcomeTimedOut || result.ExitStatus != -1 {
		t.Fatalf("outcome=%s exit=%d", result.Outcome, result.ExitStatus)
	}
	if elapsed < grace {
		t.Fatalf("TERM-ignoring child returned in %s before %s grace", elapsed, grace)
	}
	if elapsed > timeout+time.Second {
		t.Fatalf("TERM-ignoring child was not bounded: %s", elapsed)
	}
}

func TestExecRunnerKillsOwnedDescendants(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "descendant.pid")
	path := execHelperFixture(t)
	runner := execTestRunner(t, path, 60*time.Millisecond)
	// Leave enough startup budget for the helper to create its descendant and
	// PID receipt when every package is running under the race detector.
	request := execRequest(path, 10*time.Second)
	request.Environment = append(request.Environment,
		execHelperModeVariable+"=descendants",
		execHelperPIDFile+"="+pidFile,
	)
	result, err := runner.RunCycle(
		context.Background(), request,
	)
	if err != nil {
		t.Fatalf("RunCycle: %v", err)
	}
	if result.Outcome != OutcomeTimedOut {
		t.Fatalf("outcome=%s, want timed_out", result.Outcome)
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read descendant pid: %v (stdout=%q stderr=%q)",
			err, result.StdoutTail, result.StderrTail)
	}
	pid64, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil {
		t.Fatalf("parse descendant pid: %v", err)
	}
	pid := int(pid64)
	deadline := time.Now().Add(time.Second)
	for {
		err = syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("descendant %d remains after group cleanup (kill(0)=%v)",
				pid, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestExecRunnerGetpgidFailureUsesOwnedPIDAndSurfacesIt(t *testing.T) {
	path := execHelperFixture(t)
	runner := execTestRunner(t, path, 300*time.Millisecond)
	runner.getpgid = func(int) (int, error) {
		return 0, syscall.EPERM
	}
	const timeout = 2 * time.Second
	request := execRequest(path, timeout)
	request.Environment = append(
		request.Environment, execHelperModeVariable+"=graceful",
	)
	started := time.Now()
	_, err := runner.RunCycle(
		context.Background(), request,
	)
	if err == nil || !strings.Contains(err.Error(), "process group") {
		t.Fatalf("degraded Getpgid fallback was not surfaced: %v", err)
	}
	if elapsed := time.Since(started); elapsed >= timeout+time.Second {
		t.Fatalf("owned-PID fallback took %s", elapsed)
	}
}

func TestExecRunnerGroupSignalFailureFallsBackAndSurfacesIt(t *testing.T) {
	path := execHelperFixture(t)
	runner := execTestRunner(t, path, 300*time.Millisecond)
	// A non-EPERM group-signal failure (a genuinely surprising kernel error)
	// must both fall back to the direct pid and be surfaced: descendants may
	// have survived the failed group signal. EPERM has its own test below
	// because on macOS killpg reports EPERM for a zombie-only group, which is
	// the normal "child already exited" case, not a degraded fallback.
	runner.kill = func(target int, signal syscall.Signal) error {
		if target < -1 {
			return syscall.EINVAL
		}
		return syscall.Kill(target, signal)
	}
	request := execRequest(path, 2*time.Second)
	request.Environment = append(
		request.Environment, execHelperModeVariable+"=graceful",
	)
	_, err := runner.RunCycle(
		context.Background(), request,
	)
	if err == nil || !strings.Contains(err.Error(), "process group") {
		t.Fatalf("degraded group-signal fallback was not surfaced: %v", err)
	}
}

func TestExecRunnerGroupSignalEPERMSignalsTheOwnedPIDDirectly(t *testing.T) {
	// macOS killpg returns EPERM when the only group member left is a zombie
	// (a zombie is not a "receiving process"). That is the child-exited race
	// the SIGTERM/SIGKILL path hits intermittently, and it is NOT a degraded
	// fallback: the owned pid is still reserved, so the direct-pid signal is
	// the complete and correct action and must not be surfaced as an error.
	path := execHelperFixture(t)
	runner := execTestRunner(t, path, 300*time.Millisecond)
	runner.kill = func(target int, signal syscall.Signal) error {
		if target < -1 {
			return syscall.EPERM
		}
		return syscall.Kill(target, signal)
	}
	request := execRequest(path, 2*time.Second)
	request.Environment = append(
		request.Environment, execHelperModeVariable+"=graceful",
	)
	result, err := runner.RunCycle(
		context.Background(), request,
	)
	if err != nil {
		t.Fatalf("an EPERM group kill must resolve through the direct pid: %v", err)
	}
	if result.Outcome != OutcomeTimedOut {
		t.Fatalf("outcome=%s, want timed_out", result.Outcome)
	}
}

type phaseBTestContainment struct {
	configureErr error
	sampleErr    error
	finishErr    error
	finishResult *CycleContainmentCleanup
	finishCalls  int
}

func (c *phaseBTestContainment) Configure(*exec.Cmd) error {
	return c.configureErr
}

func (c *phaseBTestContainment) Sample(string) (
	int64, int64, int64, bool, error,
) {
	return 0, 0, 0, false, c.sampleErr
}

func (*phaseBTestContainment) TerminateAll() error { return nil }
func (*phaseBTestContainment) KillAll() error      { return nil }
func (c *phaseBTestContainment) Finish() (CycleContainmentCleanup, error) {
	c.finishCalls++
	if c.finishErr != nil {
		return CycleContainmentCleanup{}, c.finishErr
	}
	if c.finishResult != nil {
		return *c.finishResult, nil
	}
	return nonApplicableContainmentCleanup(), nil
}

func installPhaseBContainment(
	t *testing.T, containment cycleContainment,
) {
	t.Helper()
	old := cycleContainmentPreparer
	cycleContainmentPreparer = func(
		_, _ string, _ int64, _ bool,
	) (cycleContainment, error) {
		return containment, nil
	}
	t.Cleanup(func() { cycleContainmentPreparer = old })
}

func TestExecRunnerFinishesExactlyOnceOnEveryPostPreparePath(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		configure   error
		sample      error
		cancel      bool
		timeout     time.Duration
		alter       func(*execRunner)
		wantErr     bool
		wantOutcome CycleOutcome
	}{
		{
			name: "configure fault", body: "exit 0",
			configure: errors.New("injected configure fault"), wantErr: true,
		},
		{
			name: "stdout pipe fault", body: "exit 0", wantErr: true,
			alter: func(r *execRunner) {
				r.command = func(path string) *exec.Cmd {
					command := exec.Command(path)
					command.Stdout = io.Discard
					return command
				}
			},
		},
		{
			name: "stderr pipe fault", body: "exit 0", wantErr: true,
			alter: func(r *execRunner) {
				r.command = func(path string) *exec.Cmd {
					command := exec.Command(path)
					command.Stderr = io.Discard
					return command
				}
			},
		},
		{
			name: "start fault", body: "exit 0", wantErr: true,
			alter: func(r *execRunner) {
				r.runnerPath = filepath.Join(t.TempDir(), "absent-runner")
			},
		},
		{
			// This case proves the exactly-once Finish path, not a one-second
			// process-start deadline. Full-tree parallel load can delay fork
			// and exec without changing the runner behavior under test. Keep
			// the actual timeout boundary covered by the dedicated case below.
			name: "normal", body: "printf success", timeout: 10 * time.Second,
			wantOutcome: OutcomeSucceeded,
		},
		{
			name: "timeout", body: "sleep 10", timeout: 20 * time.Millisecond,
			wantOutcome: OutcomeTimedOut,
		},
		{
			name: "cancel", body: "sleep 10", cancel: true,
			timeout: time.Second, wantOutcome: OutcomeCancelled,
		},
		{
			name: "sampling fault", body: "sleep 0.05", timeout: time.Second,
			sample: errors.New("injected sample fault"), wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := executableFixture(t, test.body)
			containment := &phaseBTestContainment{
				configureErr: test.configure,
				sampleErr:    test.sample,
			}
			installPhaseBContainment(t, containment)
			runner := execTestRunner(t, path, 10*time.Millisecond)
			if test.alter != nil {
				test.alter(runner)
			}
			timeout := test.timeout
			if timeout == 0 {
				timeout = time.Second
			}
			request := execRequest(path, timeout)
			ctx := context.Background()
			if test.cancel {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			result, err := runner.RunCycle(ctx, request)
			if containment.finishCalls != 1 {
				t.Fatalf("Finish called %d times, want exactly once",
					containment.finishCalls)
			}
			if test.wantErr {
				if err == nil {
					t.Fatal("runner fault returned nil error")
				}
				if !reflect.DeepEqual(result, CycleResult{}) {
					t.Fatalf("runner fault returned partial result %+v", result)
				}
				return
			}
			if err != nil {
				t.Fatalf("successful result path failed: %v", err)
			}
			if result.Outcome != test.wantOutcome {
				t.Fatalf("outcome %q, want %q", result.Outcome, test.wantOutcome)
			}
			if result.ContainmentCleanup != nonApplicableContainmentCleanup() {
				t.Fatalf("cleanup evidence was not attached after Finish: %+v",
					result.ContainmentCleanup)
			}
		})
	}
}

func TestExecRunnerFinishFailureReturnsExactZeroResult(t *testing.T) {
	path := executableFixture(t, "printf should-not-survive")
	containment := &phaseBTestContainment{
		finishErr: errors.New("injected finish fault"),
	}
	installPhaseBContainment(t, containment)
	runner := execTestRunner(t, path, 10*time.Millisecond)
	result, err := runner.RunCycle(
		context.Background(), execRequest(path, time.Second),
	)
	if err == nil || !strings.Contains(err.Error(), "injected finish fault") {
		t.Fatalf("Finish failure was not returned: %v", err)
	}
	if containment.finishCalls != 1 {
		t.Fatalf("Finish called %d times, want exactly once", containment.finishCalls)
	}
	if !reflect.DeepEqual(result, CycleResult{}) {
		t.Fatalf("Finish failure leaked partial result/evidence: %+v", result)
	}
}

func TestExecRunnerMissingFinishEvidenceReturnsExactZeroResult(t *testing.T) {
	path := executableFixture(t, "printf should-not-survive")
	missing := CycleContainmentCleanup{}
	containment := &phaseBTestContainment{finishResult: &missing}
	installPhaseBContainment(t, containment)
	runner := execTestRunner(t, path, 10*time.Millisecond)
	result, err := runner.RunCycle(
		context.Background(), execRequest(path, time.Second),
	)
	if err == nil || !strings.Contains(err.Error(), "cleanup evidence is missing") {
		t.Fatalf("missing Finish evidence was not refused: %v", err)
	}
	if containment.finishCalls != 1 {
		t.Fatalf("Finish called %d times, want exactly once", containment.finishCalls)
	}
	if !reflect.DeepEqual(result, CycleResult{}) {
		t.Fatalf("missing Finish evidence leaked result: %+v", result)
	}
}

func TestExecRunnerAcceptsExactMultilineKernelCleanupEvidence(t *testing.T) {
	path := executableFixture(t, "exit 0")
	cleanup := CycleContainmentCleanup{
		Schema:            linuxCgroupV2CleanupSchema,
		ChildCgroupInode:  9981,
		FinalCgroupEvents: "populated 0\nfrozen 0\n",
		ChildRemoved:      true,
	}
	containment := &phaseBTestContainment{finishResult: &cleanup}
	installPhaseBContainment(t, containment)
	runner := execTestRunner(t, path, 10*time.Millisecond)
	result, err := runner.RunCycle(
		context.Background(), execRequest(path, time.Second),
	)
	if err != nil {
		t.Fatalf("multiline kernel cleanup was refused: %v", err)
	}
	if containment.finishCalls != 1 {
		t.Fatalf("Finish called %d times, want exactly once", containment.finishCalls)
	}
	if result.ContainmentCleanup != cleanup {
		t.Fatalf("exact kernel cleanup bytes were not preserved: %+v",
			result.ContainmentCleanup)
	}
}
