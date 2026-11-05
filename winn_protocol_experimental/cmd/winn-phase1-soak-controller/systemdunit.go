package main

// systemdunit.go generates a command. It does not run one.
//
// This file deliberately imports NOTHING that can start a process -- no
// os/exec, no syscall, no os. A test parses the file's own import list and
// fails if that ever changes. That is a stronger guarantee than a code review
// note, and it is the point: deciding when a seven-day unit starts on a shared
// host is an operator's decision, and a program that could make it would
// eventually make it by accident.

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SystemdUnitRequest is what the printed command would launch.
type SystemdUnitRequest struct {
	UnitName        string
	ControllerPath  string
	Config          Config
	EnvFile         string
	MemoryMax       string
	CPUQuota        string
	TasksMax        int64
	WorkingRoot     string
	RuntimeMaxExtra time.Duration
}

// SystemdCommand builds the argv of a systemd-run invocation.
//
// It returns a slice rather than a string so the caller cannot be tempted to
// hand it to a shell: there is no quoting to get wrong because there is no
// shell. ShellQuoted below exists only for display.
func SystemdCommand(request SystemdUnitRequest) []string {
	cfg := request.Config
	// RuntimeMaxSec is the outer backstop. It is the soak duration plus a
	// margin, never exactly the duration: a unit killed at exactly the
	// deadline would be killed in the middle of writing the final summary,
	// and the run would then lack the one artifact that says how it ended.
	runtimeMax := cfg.Duration + request.RuntimeMaxExtra

	argv := []string{
		"systemd-run",
		"--unit=" + request.UnitName,
		"--description=Winn Phase 1 soak controller (harness; not promotable)",
		"--collect",
		"--property=Type=exec",
		// The controller must NOT be restarted automatically. A restart
		// that reran the resume path unattended would repeatedly re-enter
		// whatever fail-closed condition stopped it, burning the receipt
		// log and obscuring the first failure.
		"--property=Restart=no",
		// KillMode=control-group so that a unit stop reaches the cycle's
		// descendants. This is systemd's own group teardown of the unit's
		// own cgroup; it is not, and must not be confused with, the
		// controller signalling a pid. See killplan.go.
		"--property=KillMode=control-group",
		"--property=KillSignal=SIGTERM",
		fmt.Sprintf("--property=TimeoutStopSec=%d",
			int64((cfg.KillGrace+30*time.Second)/time.Second)),
		fmt.Sprintf("--property=RuntimeMaxSec=%d",
			int64(runtimeMax/time.Second)),
		"--property=PrivateTmp=yes",
		"--property=NoNewPrivileges=yes",
		"--property=Delegate=yes",
		// Keep the controller out of the delegated unit root. Cgroup v2
		// refuses enabling domain controllers on a populated cgroup, so
		// per-cycle cgroups must be siblings of this controller subgroup.
		"--property=DelegateSubgroup=" + controllerDelegationSubgroup,
		"--property=ProtectSystem=strict",
		// The accepted AICORE snapshot may live below /root. It remains
		// read-only; hiding it entirely would fail before provenance.
		"--property=ProtectHome=read-only",
		"--property=ReadWritePaths=" + cfg.StateRoot + " " + cfg.EvidenceRoot,
		"--property=ReadOnlyPaths=" + cfg.SnapshotRoot,
	}
	if request.MemoryMax != "" {
		argv = append(argv, "--property=MemoryMax="+request.MemoryMax)
	}
	if request.CPUQuota != "" {
		argv = append(argv, "--property=CPUQuota="+request.CPUQuota)
	}
	if request.TasksMax > 0 {
		argv = append(argv, "--property=TasksMax="+
			strconv.FormatInt(request.TasksMax, 10))
	}
	if request.WorkingRoot != "" {
		argv = append(argv, "--property=WorkingDirectory="+request.WorkingRoot)
	}
	argv = append(argv,
		"--",
		request.ControllerPath,
		"-run",
		"-run-id="+cfg.RunID,
		"-state-root="+cfg.StateRoot,
		"-snapshot-root="+cfg.SnapshotRoot,
		"-evidence-root="+cfg.EvidenceRoot,
		"-runner="+cfg.RunnerPath,
		"-runner-sha256="+cfg.ExpectedRunnerSHA256,
		"-verifier="+cfg.VerifierPath,
		"-verifier-sha256="+cfg.ExpectedVerifierSHA256,
		"-manifest="+cfg.ManifestPath,
		"-manifest-sha256="+cfg.ExpectedManifestSHA256,
		"-source-digest="+cfg.ExpectedSourceDigest,
		"-env-file="+request.EnvFile,
		"-duration="+cfg.Duration.String(),
		"-cadence="+cfg.Cadence.String(),
		"-cycle-timeout="+cfg.CycleTimeout.String(),
		"-cold-every="+strconv.FormatInt(cfg.ColdEvery, 10),
		"-cold-settle="+cfg.ColdSettle.String(),
		"-min-free-bytes="+strconv.FormatInt(cfg.MinFreeBytes, 10),
		"-max-log-bytes="+strconv.FormatInt(cfg.MaxLogBytes, 10),
		"-max-log-files="+strconv.Itoa(cfg.MaxLogFiles),
		"-max-cycle-output-bytes="+
			strconv.FormatInt(cfg.MaxCycleOutputBytes, 10),
		"-max-controller-output-bytes="+
			strconv.FormatInt(cfg.MaxControllerOutput, 10),
		"-max-rss-bytes="+strconv.FormatInt(cfg.Bounds.MaxRSSBytes, 10),
		"-max-threads="+strconv.FormatInt(cfg.Bounds.MaxThreads, 10),
		"-max-open-files="+strconv.FormatInt(cfg.Bounds.MaxOpenFiles, 10),
		"-kill-grace="+cfg.KillGrace.String(),
		"-sample-interval="+cfg.SampleInterval.String(),
		"-proc-root="+cfg.ProcRoot,
		"-cgroup-root="+cfg.CgroupRoot,
	)
	if cfg.AllowWritableSnapshot {
		argv = append(argv, "-allow-writable-snapshot")
	}
	return argv
}

// shellQuote renders one argument for display.
//
// Single quotes with the embedded-quote escape, because that form has no
// interpolation at all: no $, no backtick, no backslash escape has any meaning
// inside it. A display helper that produced something a shell would expand
// would turn a copied line into a different command than the one shown.
func shellQuote(argument string) string {
	if argument == "" {
		return "''"
	}
	safe := true
	for _, r := range argument {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.' || r == '/' ||
			r == ':' || r == '=' || r == ',' || r == '+' || r == '@':
		default:
			safe = false
		}
		if !safe {
			break
		}
	}
	if safe {
		return argument
	}
	return "'" + strings.ReplaceAll(argument, "'", `'\''`) + "'"
}

// ShellQuoted renders the argv for a human to read or paste.
func ShellQuoted(argv []string) string {
	parts := make([]string, len(argv))
	for i, argument := range argv {
		parts[i] = shellQuote(argument)
	}
	return strings.Join(parts, " ")
}
