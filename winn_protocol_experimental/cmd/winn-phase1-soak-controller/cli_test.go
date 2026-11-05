package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captured runs the CLI with real files for stdout and stderr and returns both.
//
// Real *os.File rather than a buffer because run's signature takes *os.File:
// the production path writes to os.Stdout, and a test that exercised a
// different signature would be testing a different program.
func captured(t *testing.T, arguments []string, environment []string) (
	status int, stdout, stderr string,
) {
	t.Helper()
	directory := t.TempDir()
	outFile, err := os.Create(filepath.Join(directory, "stdout"))
	if err != nil {
		t.Fatalf("create stdout: %v", err)
	}
	errFile, err := os.Create(filepath.Join(directory, "stderr"))
	if err != nil {
		t.Fatalf("create stderr: %v", err)
	}
	status = run(arguments, outFile, errFile, environment)
	_ = outFile.Close()
	_ = errFile.Close()
	outBytes, err := os.ReadFile(filepath.Join(directory, "stdout"))
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	errBytes, err := os.ReadFile(filepath.Join(directory, "stderr"))
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return status, string(outBytes), string(errBytes)
}

// cliArguments builds a complete, valid argument list against staged files.
func cliArguments(t *testing.T, mode string) ([]string, Config, string) {
	t.Helper()
	cfg := provenanceConfig(t)
	envFile := filepath.Join(filepath.Dir(cfg.RunnerPath), "soak.env")
	if err := os.WriteFile(
		envFile, []byte("MATRIX_ID=phase1-auto-v1\nPATH=/usr/bin:/bin\n"), 0o600,
	); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	arguments := []string{
		mode,
		"-run-id=" + cfg.RunID,
		"-state-root=" + cfg.StateRoot,
		"-snapshot-root=" + cfg.SnapshotRoot,
		"-evidence-root=" + cfg.EvidenceRoot,
		"-runner=" + cfg.RunnerPath,
		"-runner-sha256=" + cfg.ExpectedRunnerSHA256,
		"-verifier=" + cfg.VerifierPath,
		"-verifier-sha256=" + cfg.ExpectedVerifierSHA256,
		"-manifest=" + cfg.ManifestPath,
		"-manifest-sha256=" + cfg.ExpectedManifestSHA256,
		"-source-digest=" + cfg.ExpectedSourceDigest,
		"-env-file=" + envFile,
		"-allow-writable-snapshot",
		"-min-free-bytes=1048576",
		"-max-log-bytes=65536",
		"-max-log-files=4",
	}
	return arguments, cfg, envFile
}

// TestPreflightRunsNoCyclesAndReportsNonPromotable.
func TestPreflightRunsNoCyclesAndReportsNonPromotable(t *testing.T) {
	arguments, cfg, _ := cliArguments(t, "-preflight")
	status, stdout, stderr := captured(t, arguments, []string{"PATH=/usr/bin"})
	if status != exitOK {
		t.Fatalf("preflight exited %d: %s", status, stderr)
	}
	var report PreflightReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("preflight output is not a report: %v\n%s", err, stdout)
	}
	if report.Promotable {
		t.Error("the preflight report claims to be promotable")
	}
	if !strings.Contains(report.NonPromotionNotice, "NOT PROMOTABLE") {
		t.Error("the preflight report omits the non-promotion notice")
	}
	if report.Provenance.RunnerDigest != cfg.ExpectedRunnerSHA256 {
		t.Errorf("report pins runner %q, want %q",
			report.Provenance.RunnerDigest, cfg.ExpectedRunnerSHA256)
	}
	if len(report.EnvironmentNames) != 2 {
		t.Errorf("report lists %d environment names, want 2: %v",
			len(report.EnvironmentNames), report.EnvironmentNames)
	}
	// No cycle artifacts exist: preflight runs nothing.
	if _, err := os.Stat(filepath.Join(
		cfg.EvidenceRoot, "cycle-receipts.jsonl",
	)); !os.IsNotExist(err) {
		t.Errorf("preflight wrote a receipt log (stat error %v)", err)
	}
}

// TestPreflightRefusesABrokenPin proves the gate is real.
func TestPreflightRefusesABrokenPin(t *testing.T) {
	arguments, _, _ := cliArguments(t, "-preflight")
	for index, argument := range arguments {
		if strings.HasPrefix(argument, "-runner-sha256=") {
			arguments[index] = "-runner-sha256=" + "00" + repeatHex(62)
		}
	}
	status, stdout, stderr := captured(t, arguments, []string{"PATH=/usr/bin"})
	if status != exitPreflightRefusal {
		t.Fatalf("exited %d, want %d\nstdout: %s\nstderr: %s",
			status, exitPreflightRefusal, stdout, stderr)
	}
	if !strings.Contains(stderr, "runner digest mismatch") {
		t.Errorf("stderr does not name the mismatch: %s", stderr)
	}
	if stdout != "" {
		t.Errorf("a refused preflight wrote to stdout: %s", stdout)
	}
}

// TestDryRunProjectsTheScheduleWithoutRunningIt.
func TestDryRunProjectsTheScheduleWithoutRunningIt(t *testing.T) {
	arguments, cfg, _ := cliArguments(t, "-dry-run")
	arguments = append(arguments, "-cold-every=3")
	status, stdout, stderr := captured(t, arguments, []string{"PATH=/usr/bin"})
	if status != exitOK {
		t.Fatalf("dry run exited %d: %s", status, stderr)
	}
	if !strings.Contains(stdout, "no cycle is executed") {
		t.Error("the dry run does not say that nothing was executed")
	}
	warm := strings.Count(stdout, "readiness=warm")
	cold := strings.Count(stdout, "readiness=cold")
	if cold == 0 {
		t.Error("the projected schedule contains no cold cycles at -cold-every=3")
	}
	if warm == 0 {
		t.Error("the projected schedule contains no warm cycles")
	}
	// At -cold-every=3 over 24 projected cycles: 8 cold, 16 warm. A
	// projection computed by a second implementation would drift from this.
	if cold != 8 || warm != 16 {
		t.Errorf("projected %d cold and %d warm cycles, want 8 and 16",
			cold, warm)
	}
	if _, err := os.Stat(filepath.Join(
		cfg.EvidenceRoot, "cycle-receipts.jsonl",
	)); !os.IsNotExist(err) {
		t.Errorf("the dry run wrote a receipt log (stat error %v)", err)
	}
}

// TestPrintSystemdCommandOnlyPrints.
func TestPrintSystemdCommandOnlyPrints(t *testing.T) {
	arguments, cfg, envFile := cliArguments(t, "-print-systemd-command")
	arguments = append(arguments,
		"-controller-path=/opt/winn-lab/bin/winn-phase1-soak-controller",
	)
	status, stdout, stderr := captured(t, arguments, []string{"PATH=/usr/bin"})
	if status != exitOK {
		t.Fatalf("exited %d: %s", status, stderr)
	}
	if !strings.Contains(stdout, "NOT executed") {
		t.Error("the printed command does not say it was not executed")
	}
	if !strings.Contains(stdout, "systemd-run") {
		t.Error("no systemd-run command was printed")
	}
	if !strings.Contains(stdout, "-env-file="+envFile) {
		t.Error("the printed command omits the env file")
	}
	if !strings.Contains(stdout, "ReadOnlyPaths="+cfg.SnapshotRoot) {
		t.Error("the printed command does not mount the snapshot read-only")
	}
	// Nothing was created: the printing mode touches no state at all.
	if _, err := os.Stat(cfg.StateRoot); !os.IsNotExist(err) {
		t.Errorf("printing the command created the state root (stat error %v)", err)
	}
}

// TestExactlyOneModeIsRequired.
func TestExactlyOneModeIsRequired(t *testing.T) {
	base, _, _ := cliArguments(t, "-preflight")
	both := append([]string{"-dry-run"}, base...)
	status, _, stderr := captured(t, both, []string{"PATH=/usr/bin"})
	if status != exitUsage {
		t.Errorf("two modes exited %d, want %d", status, exitUsage)
	}
	if !strings.Contains(stderr, "exactly one of") {
		t.Errorf("stderr does not explain: %s", stderr)
	}

	none := append([]string{}, base[1:]...)
	status, _, stderr = captured(t, none, []string{"PATH=/usr/bin"})
	if status != exitUsage {
		t.Errorf("no mode exited %d, want %d", status, exitUsage)
	}
	if !strings.Contains(stderr, "exactly one of") {
		t.Errorf("stderr does not explain: %s", stderr)
	}
}

// TestCLIRefusesWhenTheHostHoldsAFinalizerSeed is the custody gate at the CLI
// boundary, with the environment supplied explicitly.
func TestCLIRefusesWhenTheHostHoldsAFinalizerSeed(t *testing.T) {
	arguments, _, _ := cliArguments(t, "-preflight")
	status, stdout, stderr := captured(t, arguments, []string{
		"PATH=/usr/bin",
		"WINN_FINALIZER_SEED=0011223344556677",
	})
	if status != exitPreflightRefusal {
		t.Fatalf("exited %d, want %d\n%s", status, exitPreflightRefusal, stderr)
	}
	if !strings.Contains(stderr, "custody separation") {
		t.Errorf("stderr does not name custody separation: %s", stderr)
	}
	if strings.Contains(stderr, "0011223344556677") ||
		strings.Contains(stdout, "0011223344556677") {
		t.Error("the seed value was echoed")
	}
}

// TestDefaultDurationIsExactlySevenDays.
//
// A test on a constant looks trivial and is not: 168h is the number the whole
// deliverable is specified around, and an edit to it would otherwise be caught
// by nothing.
func TestDefaultDurationIsExactlySevenDays(t *testing.T) {
	if DefaultDuration != 168*3600*1e9 {
		t.Fatalf("DefaultDuration is %v, want 168h", DefaultDuration)
	}
	if DefaultDuration.Hours() != 168 {
		t.Fatalf("DefaultDuration is %v hours, want 168", DefaultDuration.Hours())
	}
	if DefaultDuration.String() != "168h0m0s" {
		t.Fatalf("DefaultDuration renders as %q", DefaultDuration.String())
	}
}
