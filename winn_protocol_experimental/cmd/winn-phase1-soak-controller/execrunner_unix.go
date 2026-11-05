//go:build unix

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
)

const rusageMaxRSSUnit int64 = rusageMaxRSSScale

type execRunner struct {
	runnerPath     string
	runnerFile     *os.File
	procRoot       string
	cgroupRoot     string
	sampleInterval time.Duration
	childLog       io.Writer
	killGrace      time.Duration

	// Test seams for rare syscall failures. Nil means the real syscall.
	getpgid func(int) (int, error)
	kill    func(int, syscall.Signal) error
	command func(string) *exec.Cmd
}

type ownedSignalTarget struct {
	plan          killPlan
	resolutionErr error
}

type childCopyResult struct {
	stream string
	err    error
}

type resourceObservation struct {
	sample  ResourceSample
	escaped bool
	err     error
}

// RunCycle owns fork, signal and reap for one accepted runner invocation.
//
// There is deliberately no concurrent Cmd.Wait goroutine. This function is the
// only wait4 caller and the only signal sender. A final WNOHANG observation and
// a following group signal therefore cannot race another goroutine reaping the
// leader and releasing its PID for reuse.
func (r *execRunner) RunCycle(
	ctx context.Context, request CycleRequest,
) (result CycleResult, runErr error) {
	if err := request.validate(); err != nil {
		return CycleResult{}, err
	}
	cycleCtx, cancelCycle := context.WithTimeout(ctx, request.Timeout)
	defer cancelCycle()

	executable := r.runnerPath
	if r.runnerFile != nil {
		if runtime.GOOS != "linux" {
			return CycleResult{}, errors.New(
				"exact verified-inode runner execution requires Linux " +
					"/proc/self/fd inheritance; refusing pathname fallback",
			)
		}
		executable = "/proc/self/fd/3"
	}
	// #nosec G204 -- executable is either the provenance-pinned path or the
	// inherited descriptor path for the exact descriptor pinned by soak().
	command := func(name string) *exec.Cmd { return exec.Command(name) }
	if r.command != nil {
		command = r.command
	}
	cmd := command(executable)
	if r.runnerFile != nil {
		cmd.Args[0] = r.runnerPath
		cmd.ExtraFiles = []*os.File{r.runnerFile}
	}
	cmd.Dir = request.WorkingDirectory
	cmd.Env = request.Environment
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	containment, err := cycleContainmentPreparer(
		r.cgroupRoot, r.procRoot, request.Sequence, r.runnerFile != nil,
	)
	if err != nil {
		return CycleResult{}, fmt.Errorf("prepare cycle containment: %w", err)
	}
	defer func() {
		cleanup, finishErr := containment.Finish()
		if finishErr == nil {
			finishErr = validateContainmentCleanup(cleanup)
		}
		if finishErr != nil {
			result = CycleResult{}
			runErr = errors.Join(
				runErr,
				fmt.Errorf("finish cycle containment: %w", finishErr),
			)
			return
		}
		if runErr != nil {
			result = CycleResult{}
			return
		}
		result.ContainmentCleanup = cleanup
	}()
	if err := containment.Configure(cmd); err != nil {
		return CycleResult{}, fmt.Errorf("configure cycle containment: %w", err)
	}

	stdoutTail := newBoundedBuffer(request.OutputLimit)
	stderrTail := newBoundedBuffer(request.OutputLimit)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return CycleResult{}, fmt.Errorf("open cycle stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdout.Close()
		return CycleResult{}, fmt.Errorf("open cycle stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		return CycleResult{}, fmt.Errorf(
			"start cycle %d (%s): %w", request.Sequence, r.runnerPath, err,
		)
	}

	pid := cmd.Process.Pid
	target := r.resolveSignalTarget(pid)
	copied := make(chan childCopyResult, 2)
	go copyChildStream(copied, "stdout", stdout,
		io.MultiWriter(stdoutTail, r.childLog))
	go copyChildStream(copied, "stderr", stderr,
		io.MultiWriter(stderrTail, r.childLog))

	sampled := make(chan resourceObservation, 1)
	stopSampling := make(chan struct{})
	go func() {
		sampled <- r.sampleUntil(stopSampling, target, containment)
	}()

	var waitStatus syscall.WaitStatus
	var usage syscall.Rusage
	waitNoHang := func() (bool, error) {
		for {
			got, waitErr := syscall.Wait4(
				pid, &waitStatus, syscall.WNOHANG, &usage,
			)
			if errors.Is(waitErr, syscall.EINTR) {
				continue
			}
			if waitErr != nil {
				return false, waitErr
			}
			switch got {
			case 0:
				return false, nil
			case pid:
				return true, nil
			default:
				return false, fmt.Errorf(
					"wait4 returned pid %d for owned child %d", got, pid,
				)
			}
		}
	}

	poll := time.NewTicker(5 * time.Millisecond)
	defer poll.Stop()
	reaped := false
	timedOrCancelled := false
	var waitErr error
	var cleanupErr error

normalWait:
	for {
		reaped, waitErr = waitNoHang()
		if waitErr != nil || reaped {
			break
		}
		select {
		case <-cycleCtx.Done():
			timedOrCancelled = true
			break normalWait
		case <-poll.C:
		}
	}

	if !reaped && waitErr == nil && timedOrCancelled {
		cleanupErr = errors.Join(
			containment.TerminateAll(),
			r.signalOwned(cmd.Process, target, syscall.SIGTERM),
		)
		grace := time.NewTimer(r.killGrace)
	termWait:
		for {
			reaped, waitErr = waitNoHang()
			if waitErr != nil || reaped {
				stopTimer(grace)
				break
			}
			select {
			case <-poll.C:
			case <-grace.C:
				// Reap first if the process exited. Otherwise PID reservation
				// remains in force through this same-goroutine group signal.
				reaped, waitErr = waitNoHang()
				if waitErr != nil || reaped {
					break termWait
				}
				cleanupErr = errors.Join(cleanupErr,
					containment.KillAll(),
					r.signalOwned(cmd.Process, target, syscall.SIGKILL))
				break termWait
			}
		}
	}

	if !reaped && waitErr == nil {
		reapDeadline := time.NewTimer(r.killGrace)
	reapWait:
		for {
			reaped, waitErr = waitNoHang()
			if waitErr != nil || reaped {
				stopTimer(reapDeadline)
				break
			}
			select {
			case <-poll.C:
			case <-reapDeadline.C:
				waitErr = fmt.Errorf(
					"child did not reap within %s after SIGKILL", r.killGrace,
				)
				break reapWait
			}
		}
	}

	// wait4, not Cmd.Wait, reaped the child.
	_ = cmd.Process.Release()
	close(stopSampling)
	observation := <-sampled
	sample := observation.sample
	if reaped {
		sample.Available = true
		leaderRSS := saturatingMultiply(
			int64(usage.Maxrss), rusageMaxRSSUnit)
		if leaderRSS > sample.MaxRSSBytes {
			sample.MaxRSSBytes = leaderRSS
		}
		sample.UserCPUNanos = timevalNanos(usage.Utime)
		sample.SystemCPUNanos = timevalNanos(usage.Stime)
	}

	copyErrors := drainChildCopies(
		copied, stdout, stderr, maxDuration(r.killGrace, time.Second),
	)
	result = CycleResult{
		StdoutTail: stdoutTail.Bytes(), StderrTail: stderrTail.Bytes(),
		StdoutBytes: stdoutTail.Total(), StderrBytes: stderrTail.Total(),
		Truncated: stdoutTail.Truncated() || stderrTail.Truncated(),
		Resources: sample,
	}
	if err := escapedContainmentError(observation.escaped); err != nil {
		return result, err
	}
	if observation.err != nil {
		return result, observation.err
	}
	if waitErr != nil {
		return result, fmt.Errorf(
			"cycle %d could not be reaped safely: %w",
			request.Sequence, waitErr,
		)
	}
	switch {
	case errors.Is(cycleCtx.Err(), context.DeadlineExceeded) &&
		!errors.Is(ctx.Err(), context.Canceled):
		result.Outcome = OutcomeTimedOut
		result.ExitStatus = -1
	case ctx.Err() != nil:
		result.Outcome = OutcomeCancelled
		result.ExitStatus = -1
	case waitStatus.Exited() && waitStatus.ExitStatus() == 0:
		result.Outcome = OutcomeSucceeded
		result.ExitStatus = 0
	default:
		result.Outcome = OutcomeFailed
		if waitStatus.Exited() {
			result.ExitStatus = waitStatus.ExitStatus()
		} else {
			result.ExitStatus = -1
		}
	}
	if len(copyErrors) > 0 {
		return result, fmt.Errorf(
			"cycle %d output capture failed: %w",
			request.Sequence, errors.Join(copyErrors...),
		)
	}
	if cleanupErr != nil {
		return result, fmt.Errorf(
			"cycle %d cleanup required a degraded fallback: %w",
			request.Sequence, cleanupErr,
		)
	}
	return result, nil
}

func escapedContainmentError(escaped bool) error {
	if !escaped {
		return nil
	}
	return errors.New(
		"a descendant escaped the owned process group; cgroup-v2 " +
			"containment is required before this cycle can be accepted",
	)
}

func copyChildStream(
	done chan<- childCopyResult, stream string, source io.Reader, sink io.Writer,
) {
	_, err := io.Copy(sink, source)
	done <- childCopyResult{stream: stream, err: err}
}

func drainChildCopies(
	done <-chan childCopyResult,
	stdout, stderr io.Closer,
	limit time.Duration,
) []error {
	timer := time.NewTimer(limit)
	defer stopTimer(timer)
	var findings []error
	for remaining := 2; remaining > 0; {
		select {
		case result := <-done:
			remaining--
			if result.err != nil {
				findings = append(findings,
					fmt.Errorf("%s capture: %w", result.stream, result.err))
			}
		case <-timer.C:
			_ = stdout.Close()
			_ = stderr.Close()
			findings = append(findings, errors.New(
				"owned child output pipes did not close within the drain bound"))
			for remaining > 0 {
				<-done
				remaining--
			}
		}
	}
	_ = stdout.Close()
	_ = stderr.Close()
	return findings
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func (r *execRunner) resolveSignalTarget(pid int) ownedSignalTarget {
	getpgid := r.getpgid
	if getpgid == nil {
		getpgid = syscall.Getpgid
	}
	observed, pgidErr := getpgid(pid)
	plan, err := planKill(pid, observed, pgidErr)
	if err == nil {
		return ownedSignalTarget{plan: plan}
	}
	return ownedSignalTarget{
		plan: killPlan{
			Target: pid,
			Scope:  scopeSingleProcess,
			PID:    pid,
		},
		resolutionErr: err,
	}
}

func (r *execRunner) signalOwned(
	process *os.Process, target ownedSignalTarget, signal syscall.Signal,
) error {
	if target.plan.Scope == scopeSingleProcess {
		err := process.Signal(signal)
		if errors.Is(err, os.ErrProcessDone) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("signal owned pid %d with %s: %w",
				target.plan.PID, signal, err)
		}
		return target.resolutionErr
	}

	kill := r.kill
	if kill == nil {
		kill = syscall.Kill
	}
	err := kill(target.plan.Target, signal)
	switch {
	case err == nil || errors.Is(err, syscall.ESRCH):
		return nil
	case errors.Is(err, syscall.EPERM):
		// EPERM on the group signal is "the group has no process we may
		// signal", which this loop legitimately produces when the child has
		// exited and is a zombie: on macOS killpg reports EPERM for a group
		// whose only member is a zombie, because a zombie is not a receiving
		// process. The child's pid is still reserved (this goroutine is the
		// only reaper), so signalling the direct pid is the complete and
		// correct action, not a degraded fallback worth surfacing.
	default:
		// The group signal failed for a reason other than "nobody is
		// there". Fall back to the direct pid so cleanup still proceeds,
		// and surface the group failure: descendants may have survived it.
		fallbackErr := process.Signal(signal)
		if errors.Is(fallbackErr, os.ErrProcessDone) {
			fallbackErr = nil
		}
		return errors.Join(
			fmt.Errorf("signal owned process group %d with %s: %w",
				target.plan.Target, signal, err),
			fallbackErr,
		)
	}
	fallbackErr := process.Signal(signal)
	if fallbackErr == nil || errors.Is(fallbackErr, os.ErrProcessDone) {
		return nil
	}
	return fmt.Errorf("signal owned pid %d with %s: %w",
		target.plan.PID, signal, fallbackErr)
}

func (r *execRunner) sampleUntil(
	stop <-chan struct{}, target ownedSignalTarget,
	containment cycleContainment,
) resourceObservation {
	var sample ResourceSample
	var escaped bool
	var sampleErr error
	interval := r.sampleInterval
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	sampleOnce := func() {
		threads, openFiles, rss, cgroupSupported, cgroupErr :=
			containment.Sample(r.procRoot)
		if cgroupErr != nil {
			sampleErr = errors.Join(sampleErr,
				fmt.Errorf("sample per-cycle cgroup: %w", cgroupErr))
			return
		}
		if cgroupErr == nil && cgroupSupported {
			if threads != 0 || openFiles != 0 || rss != 0 {
				sample.merge(threads, openFiles, rss)
			}
			return
		}
		if r.runnerFile != nil {
			sampleErr = errors.Join(sampleErr, errors.New(
				"formal cycle cgroup accounting is unavailable"))
			return
		}
		if target.plan.Scope != scopeProcessGroup {
			return
		}
		if found, supported := detectEscapedDescendant(
			r.procRoot, target.plan.PID, target.plan.PID,
		); supported && found {
			escaped = true
		}
		groupThreads, groupOpenFiles, groupRSS, supported := procGroupSample(
			r.procRoot, target.plan.PID,
		)
		if !supported {
			return
		}
		if groupThreads != 0 || groupOpenFiles != 0 || groupRSS != 0 {
			sample.merge(groupThreads, groupOpenFiles, groupRSS)
		}
	}
	sampleOnce()
	for {
		select {
		case <-stop:
			return resourceObservation{
				sample: sample, escaped: escaped, err: sampleErr,
			}
		case <-ticker.C:
			sampleOnce()
		}
	}
}

func timevalNanos(t syscall.Timeval) int64 {
	return saturatingMultiply(int64(t.Sec), int64(time.Second)) +
		int64(t.Usec)*int64(time.Microsecond)
}
