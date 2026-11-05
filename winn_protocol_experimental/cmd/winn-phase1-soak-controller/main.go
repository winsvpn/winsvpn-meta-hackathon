package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// Exit statuses. They are distinct because an operator's automation needs to
// tell "the soak refused to start" from "the soak ran and a cycle failed"
// without parsing prose.
const (
	exitOK               = 0
	exitUsage            = 64
	exitPreflightRefusal = 65
	exitSoakStopped      = 66
	exitInternal         = 70
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Environ()))
}

type modes struct {
	preflight       bool
	dryRun          bool
	soak            bool
	printSystemd    bool
	admitted        bool
	e5Plan          bool
	e6Handoff       bool
	e7Authorization bool
}

func run(arguments []string, stdout, stderr *os.File, environment []string) int {
	set := flag.NewFlagSet("winn-phase1-soak-controller", flag.ContinueOnError)
	set.SetOutput(stderr)

	var mode modes
	var cfg Config
	var envFile string
	var unitName string
	var controllerPath string
	var memoryMax string
	var cpuQuota string
	var tasksMax int64
	var admittedCfg AdmittedConfig
	var e5PlanRoot string
	var e6HandoffRoot string
	var e6ReceiptRoot string
	var e7AuthorizationRoot string
	var e7ReceiptRoot string

	set.BoolVar(&mode.preflight, "preflight", false,
		"run every gate, report, and run no cycles")
	set.BoolVar(&mode.dryRun, "dry-run", false,
		"preflight plus the projected schedule; run no cycles")
	set.BoolVar(&mode.soak, "run", false,
		"run the soak")
	set.BoolVar(&mode.printSystemd, "print-systemd-command", false,
		"print the systemd-run invocation; this program never executes it")
	set.BoolVar(&mode.admitted, "admitted-e3-preflight", false,
		"run one Linux-only, nonauthorizing E3 admitted preflight")
	set.BoolVar(&mode.e5Plan, "admitted-e5-four-node-plan", false,
		"freeze one Linux-only, nonauthorizing E5 four-node execution plan")
	set.BoolVar(&mode.e6Handoff, "admitted-e6-sealed-handoff", false,
		"verify and freeze one Linux-only, nonauthorizing E6 sealed handoff")
	set.BoolVar(
		&mode.e7Authorization, "admitted-e7-execution-authorization", false,
		"verify and freeze one Linux-only, nonauthorizing E7 explicit authority input",
	)

	set.StringVar(&cfg.RunID, "run-id", "", "run identifier")
	set.StringVar(&cfg.StateRoot, "state-root", "",
		"controller state directory (lock, nonce, resume key, checkpoint)")
	set.StringVar(&cfg.SnapshotRoot, "snapshot-root", "",
		"fresh, immutable, isolated snapshot the cycles run from")
	set.StringVar(&cfg.EvidenceRoot, "evidence-root", "",
		"receipt log, first-failure record, rotated cycle logs, summary")
	set.StringVar(&cfg.RunnerPath, "runner", "",
		"the accepted Phase 1 runner")
	set.StringVar(&cfg.ExpectedRunnerSHA256, "runner-sha256", "",
		"pinned SHA-256 of the runner")
	set.StringVar(&cfg.VerifierPath, "verifier", "",
		"the evidence verifier")
	set.StringVar(&cfg.ExpectedVerifierSHA256, "verifier-sha256", "",
		"pinned SHA-256 of the verifier")
	set.StringVar(&cfg.ManifestPath, "manifest", "",
		"the source manifest")
	set.StringVar(&cfg.ExpectedManifestSHA256, "manifest-sha256", "",
		"pinned SHA-256 of the source manifest")
	set.StringVar(&cfg.ExpectedSourceDigest, "source-digest", "",
		"the expected embedded source digest")
	set.StringVar(&envFile, "env-file", "",
		"0600 file of NAME=VALUE lines: the COMPLETE child environment")

	set.DurationVar(&cfg.Duration, "duration", DefaultDuration,
		"total soak duration, measured monotonically")
	set.DurationVar(&cfg.Cadence, "cadence", time.Minute,
		"minimum interval between the end of one cycle and the next")
	set.DurationVar(&cfg.CycleTimeout, "cycle-timeout", 30*time.Minute,
		"absolute per-cycle timeout")
	set.Int64Var(&cfg.ColdEvery, "cold-every", 4,
		"every Nth cycle is cold; 0 means every cycle is warm")
	set.DurationVar(&cfg.ColdSettle, "cold-settle", 2*time.Minute,
		"settle interval before a cold cycle")

	set.Int64Var(&cfg.MinFreeBytes, "min-free-bytes", 8<<30,
		"refuse to start a cycle below this much free space")
	set.Int64Var(&cfg.MaxLogBytes, "max-log-bytes", 64<<20,
		"bytes per rotated cycle log file")
	set.IntVar(&cfg.MaxLogFiles, "max-log-files", 8,
		"rotated cycle log files retained")
	set.Int64Var(&cfg.MaxCycleOutputBytes, "max-cycle-output-bytes", 1<<20,
		"bytes of stdout and of stderr retained per cycle")
	set.Int64Var(&cfg.MaxControllerOutput, "max-controller-output-bytes",
		16<<20, "bytes of the controller's own output")
	set.Int64Var(&cfg.Bounds.MaxRSSBytes, "max-rss-bytes", 4<<30,
		"per-cycle peak resident set ceiling")
	set.Int64Var(&cfg.Bounds.MaxThreads, "max-threads", 4096,
		"per-cycle thread ceiling; 0 disables the check")
	set.Int64Var(&cfg.Bounds.MaxOpenFiles, "max-open-files", 4096,
		"per-cycle open descriptor ceiling; 0 disables the check")

	set.BoolVar(&cfg.AllowWritableSnapshot, "allow-writable-snapshot", false,
		"accept a writable snapshot mount (detection-only immutability)")
	set.DurationVar(&cfg.KillGrace, "kill-grace", 30*time.Second,
		"grace between SIGTERM and SIGKILL for an owned cycle")
	set.DurationVar(&cfg.SampleInterval, "sample-interval", 5*time.Second,
		"how often a live cycle is sampled for resource metrics")
	set.StringVar(&cfg.ProcRoot, "proc-root", "/proc",
		"procfs mount point used for per-cycle resource sampling")
	set.StringVar(&cfg.CgroupRoot, "cgroup-root", "/sys/fs/cgroup",
		"cgroup-v2 mount used for atomic per-cycle containment on Linux")

	set.StringVar(&unitName, "unit-name", "winn-phase1-soak",
		"systemd unit name for -print-systemd-command")
	set.StringVar(&controllerPath, "controller-path", "",
		"absolute path to this binary for -print-systemd-command")
	set.StringVar(&memoryMax, "systemd-memory-max", "8G",
		"MemoryMax for -print-systemd-command")
	set.StringVar(&cpuQuota, "systemd-cpu-quota", "200%",
		"CPUQuota for -print-systemd-command")
	set.Int64Var(&tasksMax, "systemd-tasks-max", 8192,
		"TasksMax for -print-systemd-command")

	set.StringVar(&admittedCfg.AdmissionPath, "admission", "",
		"immutable E2 admission directory for admitted preflight")
	set.StringVar(&admittedCfg.TrustPath, "trust", "",
		"accepted public trust bundle for admitted preflight")
	set.StringVar(&admittedCfg.TopologyPath, "topology", "",
		"accepted E0 topology bundle for admitted preflight")
	set.StringVar(&admittedCfg.LauncherPath, "admitted-launcher", "",
		"exact E3 admitted launcher executable")
	set.StringVar(&admittedCfg.LauncherSHA256, "admitted-launcher-sha256", "",
		"pinned SHA-256 of the E3 admitted launcher")
	set.StringVar(&admittedCfg.AdapterPath, "admitted-adapter", "",
		"exact E3 admitted adapter executable")
	set.StringVar(&admittedCfg.AdapterSHA256, "admitted-adapter-sha256", "",
		"pinned SHA-256 of the E3 admitted adapter")
	set.StringVar(&admittedCfg.Profile, "admitted-profile", "",
		"public admitted profile identifier")
	set.StringVar(&admittedCfg.MatrixRelativePath, "matrix-relative-path", "",
		"snapshot-relative matrix path (the matrix is not executed)")
	set.StringVar(&admittedCfg.MatrixSHA256, "matrix-sha256", "",
		"pinned SHA-256 of the nonexecuted matrix")
	set.StringVar(&admittedCfg.SnapshotSHA256, "snapshot-sha256", "",
		"pinned snapshot tree digest")
	set.Uint64Var(&admittedCfg.SnapshotFileCount, "snapshot-file-count", 0,
		"pinned snapshot regular-file count")
	set.StringVar(&admittedCfg.ConfigurationSHA256, "configuration-sha256", "",
		"pinned public controller configuration digest")
	set.DurationVar(&admittedCfg.Timeout, "admitted-timeout", 30*time.Second,
		"absolute E3 admitted launcher timeout")
	set.StringVar(&e5PlanRoot, "e5-plan-root", "",
		"existing empty private directory for the nonauthorizing E5 plan")
	set.StringVar(&e6HandoffRoot, "e6-handoff-input-root", "",
		"exact two-file signed E6 handoff input directory")
	set.StringVar(&e6ReceiptRoot, "e6-receipt-root", "",
		"existing empty private directory for the nonauthorizing E6 receipt")
	set.StringVar(
		&e7AuthorizationRoot, "e7-authorization-input-root", "",
		"exact two-file signed E7 execution authorization input directory",
	)
	set.StringVar(&e7ReceiptRoot, "e7-receipt-root", "",
		"existing empty private directory for the nonauthorizing E7 receipt")

	if err := set.Parse(arguments); err != nil {
		return exitUsage
	}
	selected := 0
	for _, on := range []bool{
		mode.preflight, mode.dryRun, mode.soak, mode.printSystemd, mode.admitted,
		mode.e5Plan, mode.e6Handoff, mode.e7Authorization,
	} {
		if on {
			selected++
		}
	}
	if selected != 1 {
		fmt.Fprintln(stderr,
			"exactly one of -preflight, -dry-run, -run, "+
				"-print-systemd-command, -admitted-e3-preflight, "+
				"-admitted-e5-four-node-plan, "+
				"-admitted-e6-sealed-handoff, "+
				"-admitted-e7-execution-authorization is required")
		return exitUsage
	}
	cfg.Bounds.MaxOutputBytes = cfg.MaxCycleOutputBytes

	if mode.admitted || mode.e5Plan || mode.e6Handoff ||
		mode.e7Authorization {
		admittedCfg.RunID = cfg.RunID
		admittedCfg.StateRoot = cfg.StateRoot
		admittedCfg.EvidenceRoot = cfg.EvidenceRoot
		admittedCfg.SnapshotRoot = cfg.SnapshotRoot
		admittedCfg.ManifestPath = cfg.ManifestPath
		admittedCfg.VerifierPath = cfg.VerifierPath
		admittedCfg.SourceSHA256 = cfg.ExpectedSourceDigest
		admittedCfg.ManifestSHA256 = cfg.ExpectedManifestSHA256
		admittedCfg.VerifierSHA256 = cfg.ExpectedVerifierSHA256
		if mode.e5Plan {
			summary, err := runAdmittedE5Plan(
				context.Background(), admittedCfg, e5PlanRoot,
			)
			if err != nil {
				fmt.Fprintf(stderr, "REFUSED: %v\n", err)
				return exitPreflightRefusal
			}
			encoded, err := e5PlanSummaryJSON(summary)
			if err != nil {
				fmt.Fprintf(stderr, "internal: %v\n", err)
				return exitInternal
			}
			fmt.Fprintln(stdout, string(encoded))
			return exitOK
		}
		if mode.e6Handoff {
			summary, err := runAdmittedE6Handoff(
				context.Background(), admittedCfg, e5PlanRoot,
				e6HandoffRoot, e6ReceiptRoot,
			)
			if err != nil {
				fmt.Fprintf(stderr, "REFUSED: %v\n", err)
				return exitPreflightRefusal
			}
			encoded, err := e6SummaryJSON(summary)
			if err != nil {
				fmt.Fprintf(stderr, "internal: %v\n", err)
				return exitInternal
			}
			fmt.Fprintln(stdout, string(encoded))
			return exitOK
		}
		if mode.e7Authorization {
			summary, err := runAdmittedE7Authorization(
				context.Background(), admittedCfg, e6ReceiptRoot,
				e7AuthorizationRoot, e7ReceiptRoot,
			)
			if err != nil {
				fmt.Fprintf(stderr, "REFUSED: %v\n", err)
				return exitPreflightRefusal
			}
			encoded, err := e7SummaryJSON(summary)
			if err != nil {
				fmt.Fprintf(stderr, "internal: %v\n", err)
				return exitInternal
			}
			fmt.Fprintln(stdout, string(encoded))
			return exitOK
		}
		summary, err := runAdmittedPreflight(context.Background(), admittedCfg)
		if err != nil {
			fmt.Fprintf(stderr, "REFUSED: %v\n", err)
			return exitPreflightRefusal
		}
		encoded, err := admittedSummaryJSON(summary)
		if err != nil {
			fmt.Fprintf(stderr, "internal: %v\n", err)
			return exitInternal
		}
		fmt.Fprintln(stdout, string(encoded))
		return exitOK
	}

	if envFile != "" {
		loaded, err := LoadChildEnvironment(envFile)
		if err != nil {
			fmt.Fprintf(stderr, "REFUSED: %v\n", err)
			return exitPreflightRefusal
		}
		cfg.ChildEnvironment = loaded
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "REFUSED: %v\n", err)
		return exitPreflightRefusal
	}
	if !mode.printSystemd {
		if err := refuseAdmittedRootsForLegacy(
			cfg.StateRoot, cfg.EvidenceRoot,
		); err != nil {
			fmt.Fprintf(stderr, "REFUSED: %v\n", err)
			return exitPreflightRefusal
		}
	}

	if mode.printSystemd {
		if controllerPath == "" {
			controllerPath = "/opt/winn-lab/bin/winn-phase1-soak-controller"
		}
		argv := SystemdCommand(SystemdUnitRequest{
			UnitName:        unitName,
			ControllerPath:  controllerPath,
			Config:          cfg,
			EnvFile:         envFile,
			MemoryMax:       memoryMax,
			CPUQuota:        cpuQuota,
			TasksMax:        tasksMax,
			WorkingRoot:     cfg.SnapshotRoot,
			RuntimeMaxExtra: time.Hour,
		})
		fmt.Fprintln(stdout,
			"# Generated, NOT executed. This program never invokes "+
				"systemctl or systemd-run.")
		fmt.Fprintln(stdout, ShellQuoted(argv))
		return exitOK
	}

	report, err := preflight(cfg, environment)
	if err != nil {
		fmt.Fprintf(stderr, "REFUSED: %v\n", err)
		return exitPreflightRefusal
	}
	if mode.preflight || mode.dryRun {
		encoded, encodeErr := json.MarshalIndent(report, "", "  ")
		if encodeErr != nil {
			fmt.Fprintf(stderr, "internal: %v\n", encodeErr)
			return exitInternal
		}
		fmt.Fprintln(stdout, string(encoded))
		if mode.dryRun {
			for _, line := range projectSchedule(cfg) {
				fmt.Fprintln(stdout, line)
			}
		}
		return exitOK
	}

	summary, err := soak(cfg, report.Provenance, stdout, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "REFUSED: %v\n", err)
		return exitPreflightRefusal
	}
	encoded, encodeErr := json.MarshalIndent(summary, "", "  ")
	if encodeErr != nil {
		fmt.Fprintf(stderr, "internal: %v\n", encodeErr)
		return exitInternal
	}
	fmt.Fprintln(stdout, string(encoded))
	fmt.Fprintln(stdout, summaryNotice)
	if summary.TerminalReason != ReasonDurationServed {
		return exitSoakStopped
	}
	return exitOK
}

// PreflightReport is what every mode computes before doing anything.
type PreflightReport struct {
	Schema             string           `json:"schema"`
	RunID              string           `json:"run_id"`
	Promotable         bool             `json:"promotable"`
	NonPromotionNotice string           `json:"non_promotion_notice"`
	Provenance         Provenance       `json:"provenance"`
	CustodyFindings    []CustodyFinding `json:"custody_findings"`
	FreeBytes          int64            `json:"evidence_free_bytes"`
	MinFreeBytes       int64            `json:"min_free_bytes"`
	LogBudgetBytes     int64            `json:"log_budget_bytes"`
	DurationNanos      time.Duration    `json:"duration_nanos"`
	EnvironmentNames   []string         `json:"child_environment_names"`
}

const preflightSchema = "winn-phase1-soak-preflight/v1"

// preflight runs every gate that can be evaluated without starting a cycle.
//
// The custody check runs LAST among the refusals but is reported first in the
// struct, because it is the one an operator most needs to see: a finalizer or
// signing secret on the producing host invalidates the whole custody
// separation this project is built on, and no amount of correct scheduling
// compensates for it.
func preflight(cfg Config, environment []string) (PreflightReport, error) {
	provenance, err := gatherProvenance(cfg)
	if err != nil {
		return PreflightReport{}, err
	}
	findings := checkCustodySeparation(environment, []string{
		cfg.StateRoot,
		cfg.EvidenceRoot,
		cfg.SnapshotRoot,
		filepath.Dir(cfg.RunnerPath),
		filepath.Dir(cfg.VerifierPath),
	})
	if len(findings) > 0 {
		return PreflightReport{}, fmt.Errorf(
			"custody separation is broken: %s. No finalizer or signing "+
				"secret may exist on the producing host; a checkpoint or "+
				"anchor created where the evidence writer could read the "+
				"key constrains nobody",
			findings[0].Detail,
		)
	}
	if err := ensurePrivateDirectory(cfg.EvidenceRoot); err != nil {
		return PreflightReport{}, err
	}
	if err := ensurePrivateDirectory(cfg.StateRoot); err != nil {
		return PreflightReport{}, err
	}
	facts, err := probeMount(cfg.EvidenceRoot)
	if err != nil {
		return PreflightReport{}, err
	}
	if !facts.Available {
		return PreflightReport{}, errors.New(
			"this platform cannot report free space on the evidence " +
				"filesystem, so the minimum-free-space gate cannot be enforced",
		)
	}
	if facts.FreeBytes < cfg.MinFreeBytes {
		return PreflightReport{}, fmt.Errorf(
			"evidence filesystem has %s free, below the %s floor",
			formatBytes(facts.FreeBytes), formatBytes(cfg.MinFreeBytes),
		)
	}
	return PreflightReport{
		Schema:             preflightSchema,
		RunID:              cfg.RunID,
		Promotable:         false,
		NonPromotionNotice: summaryNotice,
		Provenance:         provenance,
		CustodyFindings:    []CustodyFinding{},
		FreeBytes:          facts.FreeBytes,
		MinFreeBytes:       cfg.MinFreeBytes,
		LogBudgetBytes: saturatingMultiply(
			cfg.MaxLogBytes, int64(cfg.MaxLogFiles),
		),
		DurationNanos:    cfg.Duration,
		EnvironmentNames: EnvironmentNames(cfg.ChildEnvironment),
	}, nil
}

// projectSchedule renders the warm/cold plan without running anything.
//
// It walks the same Config.readinessFor the loop uses. A projection computed by
// a second, parallel implementation would be a description of a program that
// does not exist -- which is the specific way dry-run output becomes a lie.
func projectSchedule(cfg Config) []string {
	const preview = 24
	lines := []string{
		"# projected schedule (first cycles; no cycle is executed)",
	}
	for sequence := int64(1); sequence <= preview; sequence++ {
		lines = append(lines, fmt.Sprintf(
			"cycle %3d readiness=%s cadence=%s timeout=%s",
			sequence, cfg.readinessFor(sequence),
			cfg.Cadence, cfg.CycleTimeout,
		))
	}
	lines = append(lines, fmt.Sprintf(
		"# total duration %s, measured monotonically; a resumed run adds "+
			"to the elapsed time it had already served rather than "+
			"restarting it", cfg.Duration,
	))
	return lines
}

// soak wires the real components together and runs the loop.
func soak(
	cfg Config, provenance Provenance, stdout, stderr *os.File,
) (Summary, error) {
	lock, err := AcquireInstanceLock(cfg.StateRoot)
	if err != nil {
		return Summary{}, err
	}
	defer func() { _ = lock.Release() }()

	runnerFile, runnerDigest, err := openAndDigestPinnedFile(cfg.RunnerPath)
	if err != nil {
		return Summary{}, fmt.Errorf("open exact runner descriptor: %w", err)
	}
	defer func() { _ = runnerFile.Close() }()
	if runnerDigest != provenance.RunnerDigest ||
		runnerDigest != cfg.ExpectedRunnerSHA256 {
		return Summary{}, fmt.Errorf(
			"runner changed before descriptor custody: got %s, expected %s",
			runnerDigest, provenance.RunnerDigest,
		)
	}
	sealedRunnerPath, sealedRunnerFile, cleanupRunner, err := sealRunnerCopy(
		cfg.StateRoot, runnerFile, runnerDigest,
	)
	if err != nil {
		return Summary{}, err
	}
	defer cleanupRunner()
	defer func() { _ = sealedRunnerFile.Close() }()

	store, err := OpenCheckpointStore(cfg.StateRoot)
	if err != nil {
		return Summary{}, err
	}
	defer func() { _ = store.Close() }()
	receipts, err := OpenReceiptLog(cfg.EvidenceRoot, cfg.RunID)
	if err != nil {
		return Summary{}, err
	}
	defer func() { _ = receipts.Close() }()

	clock := newRealClock()
	stored, _, err := store.Load()
	haveCheckpoint := err == nil
	if err != nil && !errors.Is(err, errNoCheckpoint) {
		return Summary{}, err
	}
	firstFailure, err := loadFirstFailureDirectory(
		receipts.directory, cfg.RunID,
	)
	if err != nil {
		return Summary{}, err
	}
	plan, err := planResume(
		stored, haveCheckpoint, receipts.ReplayState(), firstFailure,
		provenance, clock.WallNow(), cfg,
	)
	if err != nil {
		return Summary{}, err
	}
	if haveCheckpoint {
		if lock.Predecessor() != stored.InstanceNonce {
			return Summary{}, fmt.Errorf(
				"instance nonce lineage mismatch: lock predecessor %q, "+
					"checkpoint instance %q",
				lock.Predecessor(), stored.InstanceNonce,
			)
		}
		if lock.Nonce() == stored.InstanceNonce {
			return Summary{}, errors.New(
				"new controller instance reused the checkpoint nonce",
			)
		}
	}

	childLog, err := newRotatingLog(
		filepath.Join(cfg.EvidenceRoot, "cycle-logs"),
		"cycle.log", cfg.MaxLogBytes, cfg.MaxLogFiles,
	)
	if err != nil {
		return Summary{}, err
	}
	defer func() { _ = childLog.Close() }()

	terminal := &TerminalState{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	go func() {
		for received := range signals {
			// First-terminal-wins. A second signal, or a signal that
			// arrives just after a cycle already failed, does not change
			// the recorded reason.
			terminal.Claim(ReasonSignal, "received "+received.String())
			cancel()
		}
	}()

	controller := &Controller{
		config: cfg,
		clock:  clock,
		runner: newSerialisingRunner(&execRunner{
			runnerPath:     sealedRunnerPath,
			runnerFile:     sealedRunnerFile,
			procRoot:       cfg.ProcRoot,
			cgroupRoot:     cfg.CgroupRoot,
			sampleInterval: cfg.SampleInterval,
			childLog:       childLog,
			killGrace:      cfg.KillGrace,
		}),
		receipts:   receipts,
		checkpoint: store,
		lock:       lock,
		frozen:     provenance,
		terminal:   terminal,
		emit:       newEmitter(stdout, cfg.MaxControllerOutput),
		evidence:   cfg.EvidenceRoot,
		reverify: func() (Provenance, error) {
			return gatherProvenance(cfg)
		},
		freeSpace: func() (int64, error) {
			return receipts.directory.FreeBytes()
		},
		carried:     plan.Carried,
		resumeCount: plan.ResumeCount,
		wallAtStart: plan.WallAtStart,
	}
	summary, err := controller.Run(ctx)
	if err != nil {
		return Summary{}, err
	}
	encoded, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return Summary{}, err
	}
	if err := atomicWriteDirectory(
		receipts.directory, "soak-summary-"+cfg.RunID+".json",
		append(encoded, '\n'), 0o600,
	); err != nil {
		return Summary{}, fmt.Errorf("write soak summary: %w", err)
	}
	return summary, nil
}
