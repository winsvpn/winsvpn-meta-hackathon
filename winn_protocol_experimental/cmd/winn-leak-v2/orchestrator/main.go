//go:build unix

// Command winn-leak-orchestrator-v2 runs the acceptance lifecycle matrix.
//
// It is intentionally an external driver: the production client remains
// unaware of test sequencing, while provider-specific gateway, observer,
// probe, and crash-recovery operations are isolated behind exact executable
// hooks. Hooks are invoked directly without a shell and every executable and
// output is hashed into private evidence.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	configVersion       = "winn-leak-acceptance-config/v2"
	resultVersion       = "winn-leak-acceptance-result/v2"
	crashAcknowledgment = "LEAVE_FAIL_CLOSED_STATE_FOR_EXTERNAL_RECOVERY"
)

type config struct {
	Version            string         `json:"version"`
	RunSeed            string         `json:"run_seed"`
	EvidenceRoot       string         `json:"evidence_root"`
	ClientBinary       string         `json:"client_binary"`
	WebRTCBinary       string         `json:"webrtc_binary"`
	BrowserBinary      string         `json:"browser_binary"`
	WebRTCUser         string         `json:"webrtc_user"`
	GatewayHook        string         `json:"gateway_hook"`
	ObserverHook       string         `json:"observer_hook"`
	ProbeHook          string         `json:"probe_hook"`
	RecoveryHook       string         `json:"recovery_hook"`
	GatewayIdentity    string         `json:"gateway_identity"`
	ObserverIdentity   string         `json:"observer_identity"`
	PhaseTimeoutSecond int            `json:"phase_timeout_seconds"`
	HookTimeoutSecond  int            `json:"hook_timeout_seconds"`
	Families           []familyConfig `json:"families"`
}

type familyConfig struct {
	Family               string   `json:"family"`
	ClientArgs           []string `json:"client_args"`
	STUNServer           string   `json:"stun_server"`
	ExpectedEgress       string   `json:"expected_egress"`
	AllowedHostAddresses []string `json:"allowed_host_addresses"`
	ForbiddenAddresses   []string `json:"forbidden_addresses"`
}

type clientState struct {
	Version string `json:"version"`
	RunID   string `json:"run_id"`
	Phase   string `json:"phase"`
	PID     int    `json:"pid"`
	Family  string `json:"family"`
}

type clientEvent struct {
	Sequence uint64 `json:"sequence"`
	RunID    string `json:"run_id"`
	Phase    string `json:"phase"`
}

type suiteEvent struct {
	Sequence uint64 `json:"sequence"`
	At       string `json:"at"`
	RunID    string `json:"run_id,omitempty"`
	Family   string `json:"family,omitempty"`
	Scenario string `json:"scenario,omitempty"`
	Kind     string `json:"kind"`
	Detail   string `json:"detail,omitempty"`
}

type scenarioResult struct {
	RunID       string `json:"run_id"`
	Family      string `json:"family"`
	Scenario    string `json:"scenario"`
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
	Passed      bool   `json:"passed"`
	Failure     string `json:"failure,omitempty"`
}

type suiteResult struct {
	Version        string            `json:"version"`
	BatchID        string            `json:"batch_id"`
	StartedAt      string            `json:"started_at"`
	CompletedAt    string            `json:"completed_at"`
	ConfigSHA256   string            `json:"config_sha256"`
	ArtifactHashes map[string]string `json:"artifact_hashes"`
	EvidenceHashes map[string]string `json:"evidence_hashes"`
	GatewayID      string            `json:"gateway_identity"`
	ObserverID     string            `json:"observer_identity"`
	WebRTCUser     string            `json:"webrtc_user"`
	Scenarios      []scenarioResult  `json:"scenarios"`
	Passed         bool              `json:"passed"`
	Failure        string            `json:"failure,omitempty"`
}

type eventWriter struct {
	file     *os.File
	encoder  *json.Encoder
	sequence uint64
}

func (writer *eventWriter) append(event suiteEvent) error {
	writer.sequence++
	event.Sequence = writer.sequence
	event.At = time.Now().UTC().Format(time.RFC3339Nano)
	if err := writer.encoder.Encode(event); err != nil {
		return err
	}
	return writer.file.Sync()
}

func (writer *eventWriter) close() error {
	return errors.Join(writer.file.Sync(), writer.file.Close())
}

type suite struct {
	config           config
	configDigest     string
	batchID          string
	batchDir         string
	root             *os.Root
	events           *eventWriter
	artifacts        map[string]string
	webRTCCredential *syscall.Credential
	hookSequence     uint64
}

func main() {
	flags := flag.NewFlagSet("winn-leak-orchestrator-v2", flag.ContinueOnError)
	configPath := flags.String("config", "", "absolute private acceptance JSON config")
	if err := flags.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if flags.NArg() != 0 || *configPath == "" {
		fmt.Fprintln(os.Stderr, "usage: winn-leak-orchestrator-v2 -config=/absolute/private/config.json")
		os.Exit(2)
	}
	cfg, digest, err := readConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	driver, err := newSuite(cfg, digest)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	result := driver.run()
	if !result.Passed {
		fmt.Fprintln(os.Stderr, result.Failure)
		os.Exit(1)
	}
	fmt.Printf("PASS batch_id=%s evidence=%s\n", result.BatchID, driver.batchDir)
}

func readConfig(path string) (config, string, error) {
	var result config
	if err := requireAbsoluteClean(path, "config"); err != nil {
		return result, "", err
	}
	file, info, err := openSecureRegular(path)
	if err != nil {
		return result, "", err
	}
	defer file.Close()
	if info.Mode().Perm()&0o077 != 0 {
		return result, "", errors.New("acceptance config must deny group and other access")
	}
	data, err := io.ReadAll(io.LimitReader(file, 1<<20))
	if err != nil {
		return result, "", err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, "", fmt.Errorf("decode config: %w", err)
	}
	if err := validateConfig(result); err != nil {
		return result, "", err
	}
	digest := sha256.Sum256(data)
	return result, hex.EncodeToString(digest[:]), nil
}

func validateConfig(cfg config) error {
	if cfg.Version != configVersion || !lowerHex(cfg.RunSeed, 32) {
		return errors.New("config version or lowercase 64-hex run seed is invalid")
	}
	for name, path := range map[string]string{
		"evidence_root":  cfg.EvidenceRoot,
		"client_binary":  cfg.ClientBinary,
		"webrtc_binary":  cfg.WebRTCBinary,
		"browser_binary": cfg.BrowserBinary,
		"gateway_hook":   cfg.GatewayHook,
		"observer_hook":  cfg.ObserverHook,
		"probe_hook":     cfg.ProbeHook,
		"recovery_hook":  cfg.RecoveryHook,
	} {
		if err := requireAbsoluteClean(path, name); err != nil {
			return err
		}
	}
	if cfg.GatewayIdentity == "" || cfg.ObserverIdentity == "" ||
		cfg.GatewayIdentity == cfg.ObserverIdentity {
		return errors.New("gateway and independent observer identities must be nonempty and different")
	}
	if strings.TrimSpace(cfg.WebRTCUser) == "" {
		return errors.New("a dedicated non-root webrtc_user is required")
	}
	if cfg.PhaseTimeoutSecond < 15 || cfg.PhaseTimeoutSecond > 900 ||
		cfg.HookTimeoutSecond < 5 || cfg.HookTimeoutSecond > 300 {
		return errors.New("phase timeout must be 15..900s and hook timeout 5..300s")
	}
	if len(cfg.Families) != 2 {
		return errors.New("exactly one v4 and one v6 family configuration are required")
	}
	seen := map[string]bool{}
	for _, family := range cfg.Families {
		if family.Family != "v4" && family.Family != "v6" {
			return errors.New("family must be v4 or v6")
		}
		if seen[family.Family] {
			return fmt.Errorf("duplicate %s family", family.Family)
		}
		seen[family.Family] = true
		if err := validateClientArgs(family.ClientArgs); err != nil {
			return fmt.Errorf("%s client args: %w", family.Family, err)
		}
		stun, err := netip.ParseAddrPort(family.STUNServer)
		if err != nil || stun.Port() == 0 {
			return fmt.Errorf("%s STUN server is invalid", family.Family)
		}
		egress, err := netip.ParseAddr(family.ExpectedEgress)
		if err != nil || egress.IsUnspecified() {
			return fmt.Errorf("%s expected egress is invalid", family.Family)
		}
		isV4 := family.Family == "v4"
		if stun.Addr().Is4() != isV4 || egress.Is4() != isV4 {
			return fmt.Errorf("%s STUN/egress family mismatch", family.Family)
		}
		if len(family.ForbiddenAddresses) == 0 {
			return fmt.Errorf("%s requires pre-tunnel forbidden addresses", family.Family)
		}
		if err := validateAddressLists(family); err != nil {
			return err
		}
	}
	return nil
}

func validateAddressLists(family familyConfig) error {
	allowed := map[netip.Addr]bool{}
	for _, raw := range family.AllowedHostAddresses {
		address, err := netip.ParseAddr(raw)
		if err != nil || address.IsUnspecified() {
			return fmt.Errorf("%s allowed address %q is invalid", family.Family, raw)
		}
		allowed[address.Unmap()] = true
	}
	for _, raw := range family.ForbiddenAddresses {
		address, err := netip.ParseAddr(raw)
		if err != nil || address.IsUnspecified() {
			return fmt.Errorf("%s forbidden address %q is invalid", family.Family, raw)
		}
		if allowed[address.Unmap()] {
			return fmt.Errorf("%s address %s is allowed and forbidden", family.Family, address)
		}
	}
	return nil
}

func validateClientArgs(args []string) error {
	if len(args) == 0 {
		return errors.New("client_args cannot be empty")
	}
	controlled := []string{
		"-run-id", "-family", "-control-dir", "-state-file", "-event-log",
		"-temp-root", "-command-timeout", "-crash-ack",
	}
	for _, argument := range args {
		if !strings.HasPrefix(argument, "-") ||
			strings.ContainsAny(argument, "\x00\r\n") {
			return fmt.Errorf("unsafe client argument %q", argument)
		}
		for _, prefix := range controlled {
			doublePrefix := "-" + prefix
			if argument == prefix || strings.HasPrefix(argument, prefix+"=") ||
				argument == doublePrefix ||
				strings.HasPrefix(argument, doublePrefix+"=") {
				return fmt.Errorf("orchestrator-controlled argument %q is forbidden", argument)
			}
		}
	}
	return nil
}

func newSuite(cfg config, configDigest string) (*suite, error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return nil, errors.New("orchestrator must run as root inside the disposable Linux client")
	}
	credential, err := credentialForUser(cfg.WebRTCUser)
	if err != nil {
		return nil, err
	}
	rootInfo, err := os.Lstat(cfg.EvidenceRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect evidence root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() ||
		rootInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("evidence root must be a private real directory")
	}
	seed, _ := hex.DecodeString(cfg.RunSeed)
	batchDigest := sha256.Sum256(append([]byte("winn-leak-batch/v2\x00"), seed...))
	batchID := hex.EncodeToString(batchDigest[:16])
	evidenceRoot, err := os.OpenRoot(cfg.EvidenceRoot)
	if err != nil {
		return nil, err
	}
	batchName := "batch-" + batchID
	if err := evidenceRoot.Mkdir(batchName, 0o700); err != nil {
		_ = evidenceRoot.Close()
		return nil, fmt.Errorf("create exclusive batch evidence directory: %w", err)
	}
	batchRoot, err := evidenceRoot.OpenRoot(batchName)
	_ = evidenceRoot.Close()
	if err != nil {
		return nil, err
	}
	eventFile, err := batchRoot.OpenFile(
		"suite-events.jsonl",
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		_ = batchRoot.Close()
		return nil, err
	}
	driver := &suite{
		config: cfg, configDigest: configDigest, batchID: batchID,
		batchDir: filepath.Join(cfg.EvidenceRoot, batchName),
		root:     batchRoot,
		events: &eventWriter{
			file: eventFile, encoder: json.NewEncoder(eventFile),
		},
		artifacts:        make(map[string]string),
		webRTCCredential: credential,
	}
	if err := driver.hashArtifacts(); err != nil {
		_ = driver.events.close()
		_ = driver.root.Close()
		return nil, err
	}
	return driver, nil
}

func (suite *suite) hashArtifacts() error {
	paths := []string{
		suite.config.ClientBinary, suite.config.WebRTCBinary,
		suite.config.BrowserBinary, suite.config.GatewayHook,
		suite.config.ObserverHook, suite.config.ProbeHook,
		suite.config.RecoveryHook,
	}
	for _, path := range paths {
		info, err := requireExecutable(path)
		if err != nil {
			return fmt.Errorf("artifact %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("artifact %s is not regular", path)
		}
		if path == suite.config.WebRTCBinary ||
			path == suite.config.BrowserBinary {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || !credentialModeCanExecute(
				info.Mode(),
				uint32(stat.Uid),
				uint32(stat.Gid),
				suite.webRTCCredential,
			) {
				return fmt.Errorf(
					"artifact %s is not executable by webrtc_user",
					path,
				)
			}
			if !credentialCanOpenParents(
				path, suite.webRTCCredential,
			) {
				return fmt.Errorf(
					"artifact %s has an ancestor not readable/traversable by webrtc_user",
					path,
				)
			}
		}
		digest, err := sha256File(path)
		if err != nil {
			return fmt.Errorf("hash %s: %w", path, err)
		}
		suite.artifacts[path] = digest
	}
	hooks := []string{
		suite.config.GatewayHook, suite.config.ObserverHook,
		suite.config.ProbeHook, suite.config.RecoveryHook,
	}
	for index, left := range hooks {
		for _, right := range hooks[index+1:] {
			if left == right {
				return errors.New("gateway, observer, probe, and recovery hooks must be distinct artifacts")
			}
		}
	}
	return nil
}

func (suite *suite) run() suiteResult {
	started := time.Now().UTC().Format(time.RFC3339Nano)
	result := suiteResult{
		Version: resultVersion, BatchID: suite.batchID, StartedAt: started,
		ConfigSHA256: suite.configDigest, ArtifactHashes: suite.artifacts,
		GatewayID:  suite.config.GatewayIdentity,
		ObserverID: suite.config.ObserverIdentity,
		WebRTCUser: suite.config.WebRTCUser,
	}
	runErr := suite.events.append(suiteEvent{Kind: "suite_started", Detail: suite.batchID})
	if runErr == nil {
		for _, family := range suite.config.Families {
			for _, scenario := range []string{"graceful", "outage", "crash"} {
				scenarioResult := suite.runScenario(family, scenario)
				result.Scenarios = append(result.Scenarios, scenarioResult)
				if !scenarioResult.Passed {
					runErr = errors.New(scenarioResult.Failure)
					break
				}
			}
			if runErr != nil {
				break
			}
		}
	}
	result.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if runErr != nil {
		result.Failure = runErr.Error()
	} else {
		result.Passed = len(result.Scenarios) == 6
		if !result.Passed {
			result.Failure = "the exact six-scenario v4/v6 matrix did not complete"
		}
	}
	runErr = errors.Join(runErr, suite.events.append(suiteEvent{
		Kind: "suite_completed", Detail: fmt.Sprintf("passed=%t", result.Passed),
	}))
	if runErr != nil {
		result.Passed = false
		result.Failure = runErr.Error()
	}
	closeErr := suite.events.close()
	if closeErr != nil {
		result.Passed = false
		result.Failure = errors.Join(errors.New(result.Failure), closeErr).Error()
	}
	evidenceHashes, hashErr := hashEvidenceTree(suite.batchDir)
	if hashErr != nil {
		result.Passed = false
		result.Failure = errors.Join(errors.New(result.Failure), hashErr).Error()
	} else {
		result.EvidenceHashes = evidenceHashes
	}
	if err := suite.writeJSON("suite-result.json", result); err != nil {
		result.Passed = false
		result.Failure = errors.Join(errors.New(result.Failure), err).Error()
		fmt.Fprintln(os.Stderr, "write suite result:", err)
	}
	_ = suite.root.Close()
	return result
}

func hashEvidenceTree(root string) (map[string]string, error) {
	hashes := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative == "." || entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("evidence contains a symlink: %s", relative)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("evidence is not a regular file: %s", relative)
		}
		digest, err := sha256File(path)
		if err != nil {
			return err
		}
		hashes[relative] = digest
		return nil
	})
	return hashes, err
}

type scenarioRuntime struct {
	suite            *suite
	family           familyConfig
	scenario         string
	runID            string
	directory        string
	root             *os.Root
	process          *managedProcess
	observerMayExist bool
	gatewayMayExist  bool
	gatewayOut       bool
	recovered        bool
}

func (suite *suite) runScenario(
	family familyConfig,
	scenario string,
) (result scenarioResult) {
	runID := deriveRunID(suite.config.RunSeed, family.Family, scenario)
	result = scenarioResult{
		RunID: runID, Family: family.Family, Scenario: scenario,
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	finish := func(err error) scenarioResult {
		result.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err != nil {
			result.Failure = err.Error()
		} else {
			result.Passed = true
		}
		return result
	}
	name := family.Family + "-" + scenario + "-" + runID[:12]
	if err := suite.root.Mkdir(name, 0o700); err != nil {
		return finish(err)
	}
	root, err := suite.root.OpenRoot(name)
	if err != nil {
		return finish(err)
	}
	runtime := &scenarioRuntime{
		suite: suite, family: family, scenario: scenario,
		runID: runID, directory: filepath.Join(suite.batchDir, name), root: root,
	}
	defer root.Close()
	if err := suite.events.append(suiteEvent{
		RunID: runID, Family: family.Family, Scenario: scenario,
		Kind: "scenario_started",
	}); err != nil {
		return finish(err)
	}

	runErr := runtime.execute()
	if runErr != nil {
		cleanupErr := runtime.rollback()
		runErr = errors.Join(runErr, cleanupErr)
	}
	endErr := suite.events.append(suiteEvent{
		RunID: runID, Family: family.Family, Scenario: scenario,
		Kind: "scenario_completed", Detail: fmt.Sprintf("passed=%t", runErr == nil),
	})
	return finish(errors.Join(runErr, endErr))
}

func (runtime *scenarioRuntime) execute() error {
	for _, directory := range []string{"control", "temp"} {
		if err := runtime.root.Mkdir(directory, 0o700); err != nil {
			return err
		}
	}
	runtime.observerMayExist = true
	if err := runtime.hook("observer", "start"); err != nil {
		return err
	}
	if err := runtime.hook("observer", "status"); err != nil {
		return err
	}
	runtime.gatewayMayExist = true
	if err := runtime.hook("gateway", "start"); err != nil {
		return err
	}
	if err := runtime.hook("gateway", "status"); err != nil {
		return err
	}
	process, err := runtime.startClient()
	if err != nil {
		return err
	}
	runtime.process = process
	if err := runtime.phase("prepared"); err != nil {
		return err
	}
	if err := runtime.barrier("continue-prepared"); err != nil {
		return err
	}
	if err := runtime.phase("verified"); err != nil {
		return err
	}
	if err := runtime.barrier("continue-verified"); err != nil {
		return err
	}
	if err := runtime.phase("committed"); err != nil {
		return err
	}
	if err := runtime.runWebRTC(); err != nil {
		return err
	}
	if err := runtime.hook("observer", "assert-committed"); err != nil {
		return err
	}

	switch runtime.scenario {
	case "outage":
		if err := runtime.hook("gateway", "outage"); err != nil {
			return err
		}
		runtime.gatewayOut = true
		if err := runtime.assertLivePhase("outage-fail-closed"); err != nil {
			return err
		}
		if err := runtime.hook("gateway", "recover"); err != nil {
			return err
		}
		runtime.gatewayOut = false
		if err := runtime.hook("gateway", "status"); err != nil {
			return err
		}
		if err := runtime.assertLivePhase("recovered"); err != nil {
			return err
		}
		return runtime.gracefulStop()
	case "crash":
		if err := runtime.barrier("crash-now"); err != nil {
			return err
		}
		if err := runtime.process.waitForSignal(
			time.Duration(runtime.suite.config.PhaseTimeoutSecond)*time.Second,
			syscall.SIGKILL,
		); err != nil {
			return err
		}
		if err := runtime.waitState("crashing"); err != nil {
			return err
		}
		if err := runtime.hook("probe", "crashed-fail-closed"); err != nil {
			return err
		}
		if err := runtime.hook("observer", "assert-crashed-fail-closed"); err != nil {
			return err
		}
		if err := runtime.hook("recovery", "recover-crash"); err != nil {
			return err
		}
		runtime.recovered = true
		if processGroupAlive(runtime.process.pgid) {
			return errors.New("crash recovery left the exact client process group alive")
		}
		if err := runtime.stopRemoteRoles(); err != nil {
			return err
		}
		if err := runtime.residue(); err != nil {
			return err
		}
		return runtime.validateClientEvents([]string{
			"starting", "prepared", "verified", "committed", "crashing",
		})
	default:
		return runtime.gracefulStop()
	}
}

func (runtime *scenarioRuntime) phase(phase string) error {
	if err := runtime.waitState(phase); err != nil {
		return err
	}
	if err := runtime.hook("probe", phase); err != nil {
		return err
	}
	return runtime.hook("observer", "assert-"+phase)
}

func (runtime *scenarioRuntime) assertLivePhase(phase string) error {
	if exited, err := runtime.process.exited(); exited {
		return fmt.Errorf("client exited during %s: %w", phase, err)
	}
	if err := runtime.waitState("committed"); err != nil {
		return err
	}
	if err := runtime.hook("probe", phase); err != nil {
		return err
	}
	return runtime.hook("observer", "assert-"+phase)
}

func (runtime *scenarioRuntime) gracefulStop() error {
	if err := runtime.barrier("stop"); err != nil {
		return err
	}
	if err := runtime.process.waitForSuccess(
		time.Duration(runtime.suite.config.PhaseTimeoutSecond) * time.Second,
	); err != nil {
		return err
	}
	if err := runtime.waitState("stopped"); err != nil {
		return err
	}
	if err := runtime.hook("probe", "stopped"); err != nil {
		return err
	}
	if err := runtime.hook("observer", "assert-stopped"); err != nil {
		return err
	}
	if err := runtime.stopRemoteRoles(); err != nil {
		return err
	}
	if err := runtime.residue(); err != nil {
		return err
	}
	return runtime.validateClientEvents([]string{
		"starting", "prepared", "verified", "committed", "stopping", "stopped",
	})
}

func (runtime *scenarioRuntime) startClient() (*managedProcess, error) {
	args := []string{
		runtime.suite.config.ClientBinary,
		"client",
		"-run-id=" + runtime.runID,
		"-family=" + runtime.family.Family,
		"-control-dir=" + filepath.Join(runtime.directory, "control"),
		"-state-file=" + filepath.Join(runtime.directory, "state.json"),
		"-event-log=" + filepath.Join(runtime.directory, "client-events.jsonl"),
		"-temp-root=" + filepath.Join(runtime.directory, "temp"),
		fmt.Sprintf("-command-timeout=%ds", runtime.suite.config.PhaseTimeoutSecond),
	}
	if runtime.scenario == "crash" {
		args = append(args, "-crash-ack="+crashAcknowledgment)
	}
	args = append(args, runtime.family.ClientArgs...)
	stdout, err := runtime.root.OpenFile(
		"client.stdout.log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600,
	)
	if err != nil {
		return nil, err
	}
	stderr, err := runtime.root.OpenFile(
		"client.stderr.log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600,
	)
	if err != nil {
		_ = stdout.Close()
		return nil, err
	}
	command := &exec.Cmd{
		Path: runtime.suite.config.ClientBinary, Args: args,
		Dir: runtime.directory, Stdout: stdout, Stderr: stderr,
		SysProcAttr: &syscall.SysProcAttr{Setpgid: true},
	}
	if err := command.Start(); err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, err
	}
	pgid, err := syscall.Getpgid(command.Process.Pid)
	if err != nil || pgid != command.Process.Pid {
		_ = terminateProcessGroup(command.Process.Pid)
		_ = command.Process.Kill()
		waitErr := command.Wait()
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, errors.Join(
			errors.New("client did not own an exact process group"),
			err, waitErr,
		)
	}
	process := &managedProcess{
		command: command, stdout: stdout, stderr: stderr,
		pgid: pgid, done: make(chan struct{}),
	}
	go process.wait()
	return process, nil
}

func (runtime *scenarioRuntime) waitState(phase string) error {
	timeout := time.Duration(runtime.suite.config.PhaseTimeoutSecond) * time.Second
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := runtime.root.ReadFile("state.json")
		if err == nil {
			var state clientState
			if json.Unmarshal(data, &state) == nil &&
				state.Version == "winn-leak-client/v2" &&
				state.RunID == runtime.runID &&
				state.Family == runtime.family.Family &&
				state.Phase == phase {
				if runtime.process == nil || state.PID != runtime.process.command.Process.Pid {
					return errors.New("client state PID did not match the launched process")
				}
				return runtime.suite.events.append(suiteEvent{
					RunID: runtime.runID, Family: runtime.family.Family,
					Scenario: runtime.scenario, Kind: "client_phase", Detail: phase,
				})
			}
		}
		if runtime.process != nil {
			if exited, exitErr := runtime.process.exited(); exited {
				return fmt.Errorf("client exited before phase %s: %w", phase, exitErr)
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for client phase %s", phase)
}

func (runtime *scenarioRuntime) barrier(name string) error {
	control, err := runtime.root.OpenRoot("control")
	if err != nil {
		return err
	}
	defer control.Close()
	file, err := control.OpenFile(
		name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600,
	)
	if err != nil {
		return err
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		return err
	}
	directory, err := control.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func (runtime *scenarioRuntime) runWebRTC() error {
	work, err := os.MkdirTemp("/tmp", "winn-webrtc-orchestrator-*")
	if err != nil {
		return err
	}
	workCleaned := false
	cleanupWork := func() error {
		if workCleaned {
			return nil
		}
		workCleaned = true
		removeErr := os.RemoveAll(work)
		if _, statErr := os.Lstat(work); !os.IsNotExist(statErr) {
			if statErr == nil {
				removeErr = errors.Join(removeErr, errors.New("WebRTC work directory residue remained"))
			} else {
				removeErr = errors.Join(removeErr, statErr)
			}
		}
		return removeErr
	}
	defer cleanupWork()
	if err := prepareCredentialDirectory(work, runtime.suite.webRTCCredential); err != nil {
		return errors.Join(err, cleanupWork())
	}
	for _, name := range []string{"home", "tmp", "runtime"} {
		path := filepath.Join(work, name)
		// #nosec G301 -- these are private directories for the unprivileged browser.
		if err := os.Mkdir(path, 0o700); err != nil {
			return errors.Join(err, cleanupWork())
		}
		if err := os.Chown(
			path,
			int(runtime.suite.webRTCCredential.Uid),
			int(runtime.suite.webRTCCredential.Gid),
		); err != nil {
			return errors.Join(err, cleanupWork())
		}
	}
	output := filepath.Join(work, "webrtc.json")
	timeout := time.Duration(runtime.suite.config.PhaseTimeoutSecond) * time.Second
	if timeout > time.Minute {
		timeout = time.Minute
	}
	args := []string{
		runtime.suite.config.WebRTCBinary,
		"-run-id=" + runtime.runID,
		"-family=" + runtime.family.Family,
		"-browser=" + runtime.suite.config.BrowserBinary,
		"-stun-server=" + runtime.family.STUNServer,
		"-expected-egress=" + runtime.family.ExpectedEgress,
		"-allowed-host-addresses=" + strings.Join(runtime.family.AllowedHostAddresses, ","),
		"-forbidden-addresses=" + strings.Join(runtime.family.ForbiddenAddresses, ","),
		"-output=" + output,
		"-timeout=" + timeout.String(),
	}
	if err := runtime.runLoggedCommand(
		"webrtc", runtime.suite.config.WebRTCBinary, args,
		timeout+10*time.Second,
		runtime.suite.webRTCCredential,
		[]string{
			"HOME=" + filepath.Join(work, "home"),
			"TMPDIR=" + filepath.Join(work, "tmp"),
			"XDG_RUNTIME_DIR=" + filepath.Join(work, "runtime"),
			"PATH=/usr/bin:/bin",
			"LANG=C.UTF-8",
			"USER=" + runtime.suite.config.WebRTCUser,
		},
		work,
	); err != nil {
		return errors.Join(err, cleanupWork())
	}
	workRoot, err := os.OpenRoot(work)
	if err != nil {
		return errors.Join(err, cleanupWork())
	}
	data, readErr := workRoot.ReadFile("webrtc.json")
	closeErr := workRoot.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return errors.Join(err, cleanupWork())
	}
	evidenceFile, err := runtime.root.OpenFile(
		"webrtc.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600,
	)
	if err != nil {
		return errors.Join(err, cleanupWork())
	}
	copyErr := func() error {
		_, err := evidenceFile.Write(data)
		return errors.Join(err, evidenceFile.Sync(), evidenceFile.Close())
	}()
	if copyErr != nil {
		return errors.Join(copyErr, cleanupWork())
	}
	if err := cleanupWork(); err != nil {
		return err
	}
	data, err = runtime.root.ReadFile("webrtc.json")
	if err != nil {
		return err
	}
	var result struct {
		Version          string `json:"version"`
		RunID            string `json:"run_id"`
		Family           string `json:"family"`
		EffectiveUID     int    `json:"effective_uid"`
		ProcessGroupGone bool   `json:"process_group_gone"`
		ProfileRemoved   bool   `json:"profile_removed"`
		Passed           bool   `json:"passed"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	if result.Version != "winn-webrtc-evidence/v2" ||
		result.RunID != runtime.runID ||
		result.Family != runtime.family.Family ||
		result.EffectiveUID == 0 ||
		!result.ProcessGroupGone ||
		!result.ProfileRemoved ||
		!result.Passed {
		return errors.New("WebRTC runner did not emit matching passing evidence")
	}
	return nil
}

func (runtime *scenarioRuntime) hook(role, action string) error {
	path := map[string]string{
		"gateway":  runtime.suite.config.GatewayHook,
		"observer": runtime.suite.config.ObserverHook,
		"probe":    runtime.suite.config.ProbeHook,
		"recovery": runtime.suite.config.RecoveryHook,
	}[role]
	if path == "" {
		return fmt.Errorf("unknown hook role %q", role)
	}
	args := []string{
		path, action, runtime.runID, runtime.family.Family,
		runtime.scenario, runtime.directory,
	}
	return runtime.runLoggedCommand(
		role+"-"+action, path, args,
		time.Duration(runtime.suite.config.HookTimeoutSecond)*time.Second,
		nil,
		nil,
		runtime.directory,
	)
}

func (runtime *scenarioRuntime) runLoggedCommand(
	label string,
	path string,
	args []string,
	timeout time.Duration,
	credential *syscall.Credential,
	environment []string,
	workingDirectory string,
) error {
	runtime.suite.hookSequence++
	prefix := fmt.Sprintf("%03d-%s", runtime.suite.hookSequence, label)
	stdout, err := runtime.root.OpenFile(
		prefix+".stdout.log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600,
	)
	if err != nil {
		return err
	}
	stderr, err := runtime.root.OpenFile(
		prefix+".stderr.log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600,
	)
	if err != nil {
		_ = stdout.Close()
		return err
	}
	command := &exec.Cmd{
		Path: path, Args: args, Dir: workingDirectory,
		Stdout: stdout, Stderr: stderr,
		Env: environment,
		SysProcAttr: &syscall.SysProcAttr{
			Setpgid: true, Credential: credential,
		},
	}
	startErr := command.Start()
	var runErr error
	if startErr != nil {
		runErr = startErr
	} else {
		pgid, groupErr := syscall.Getpgid(command.Process.Pid)
		if groupErr != nil || pgid != command.Process.Pid {
			_ = terminateProcessGroup(command.Process.Pid)
			_ = command.Process.Kill()
			waitErr := command.Wait()
			runErr = errors.Join(
				errors.New("command did not own an exact process group"),
				groupErr, waitErr,
			)
		} else {
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			timer := time.NewTimer(timeout)
			select {
			case runErr = <-done:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			case <-timer.C:
				killErr := terminateProcessGroup(pgid)
				waitErr := <-done
				runErr = errors.Join(
					fmt.Errorf("%s exceeded %s", label, timeout),
					killErr, waitErr,
				)
			}
			if processGroupAlive(pgid) {
				residueErr := terminateProcessGroup(pgid)
				runErr = errors.Join(
					runErr, residueErr,
					fmt.Errorf("%s left process-group residue", label),
				)
			}
		}
	}
	closeErr := errors.Join(stdout.Sync(), stderr.Sync(), stdout.Close(), stderr.Close())
	if runErr != nil {
		return errors.Join(fmt.Errorf("%s failed: %w", label, runErr), closeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	return runtime.suite.events.append(suiteEvent{
		RunID: runtime.runID, Family: runtime.family.Family,
		Scenario: runtime.scenario, Kind: "command_passed", Detail: label,
	})
}

func processGroupAlive(pgid int) bool {
	err := syscall.Kill(-pgid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func terminateProcessGroup(pgid int) error {
	if pgid <= 1 {
		return errors.New("refusing to signal an unsafe process group")
	}
	var result error
	if processGroupAlive(pgid) {
		if err := syscall.Kill(-pgid, syscall.SIGTERM); !errors.Is(err, syscall.ESRCH) {
			result = errors.Join(result, err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for processGroupAlive(pgid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if processGroupAlive(pgid) {
		if err := syscall.Kill(-pgid, syscall.SIGKILL); !errors.Is(err, syscall.ESRCH) {
			result = errors.Join(result, err)
		}
	}
	deadline = time.Now().Add(time.Second)
	for processGroupAlive(pgid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if processGroupAlive(pgid) {
		result = errors.Join(result, errors.New("process group remained after SIGKILL"))
	}
	return result
}

func (runtime *scenarioRuntime) stopRemoteRoles() error {
	var result error
	if runtime.gatewayMayExist {
		err := runtime.hook("gateway", "stop")
		result = errors.Join(result, err)
		if err == nil {
			runtime.gatewayMayExist = false
			runtime.gatewayOut = false
		}
	}
	if runtime.observerMayExist {
		err := runtime.hook("observer", "stop")
		result = errors.Join(result, err)
		if err == nil {
			runtime.observerMayExist = false
		}
	}
	return result
}

func (runtime *scenarioRuntime) residue() error {
	return errors.Join(
		runtime.hook("recovery", "residue"),
		runtime.hook("probe", "residue"),
		runtime.hook("gateway", "residue"),
		runtime.hook("observer", "residue"),
	)
}

func (runtime *scenarioRuntime) rollback() error {
	var result error
	if runtime.process != nil {
		if exited, _ := runtime.process.exited(); !exited {
			result = errors.Join(result, runtime.process.terminate())
		}
	}
	if runtime.gatewayOut {
		result = errors.Join(result, runtime.hook("gateway", "recover"))
		runtime.gatewayOut = false
	}
	if !runtime.recovered {
		result = errors.Join(result, runtime.hook("recovery", "cleanup"))
		runtime.recovered = true
	}
	result = errors.Join(result, runtime.stopRemoteRoles())
	result = errors.Join(result, runtime.residue())
	return result
}

func (runtime *scenarioRuntime) validateClientEvents(required []string) error {
	file, err := runtime.root.Open("client-events.jsonl")
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var phases []string
	var lastSequence uint64
	for scanner.Scan() {
		var event clientEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return err
		}
		if event.RunID != runtime.runID || event.Sequence != lastSequence+1 {
			return errors.New("client event run binding or sequence is invalid")
		}
		lastSequence = event.Sequence
		phases = append(phases, event.Phase)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if !orderedSubsequence(phases, required) {
		return fmt.Errorf("client phases %v omitted required order %v", phases, required)
	}
	return nil
}

type managedProcess struct {
	command  *exec.Cmd
	stdout   *os.File
	stderr   *os.File
	pgid     int
	done     chan struct{}
	mu       sync.Mutex
	err      error
	stopOnce sync.Once
	stopErr  error
}

func (process *managedProcess) wait() {
	err := process.command.Wait()
	closeErr := errors.Join(
		process.stdout.Sync(), process.stderr.Sync(),
		process.stdout.Close(), process.stderr.Close(),
	)
	process.mu.Lock()
	process.err = errors.Join(err, closeErr)
	process.mu.Unlock()
	close(process.done)
}

func (process *managedProcess) exited() (bool, error) {
	select {
	case <-process.done:
		process.mu.Lock()
		defer process.mu.Unlock()
		return true, process.err
	default:
		return false, nil
	}
}

func (process *managedProcess) waitForSuccess(timeout time.Duration) error {
	select {
	case <-process.done:
		process.mu.Lock()
		defer process.mu.Unlock()
		if process.err != nil {
			return fmt.Errorf("client did not exit successfully: %w", process.err)
		}
		if processGroupAlive(process.pgid) {
			cleanupErr := terminateProcessGroup(process.pgid)
			return errors.Join(
				errors.New("graceful client exit left process-group residue"),
				cleanupErr,
			)
		}
		return nil
	case <-time.After(timeout):
		return errors.New("timed out waiting for client success")
	}
}

func (process *managedProcess) waitForSignal(
	timeout time.Duration,
	expected syscall.Signal,
) error {
	select {
	case <-process.done:
	case <-time.After(timeout):
		return fmt.Errorf("timed out waiting for client signal %s", expected)
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	var exitErr *exec.ExitError
	if !errors.As(process.err, &exitErr) {
		return fmt.Errorf("client crash was not an exit error: %w", process.err)
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != expected {
		return fmt.Errorf("client exited without exact %s: %w", expected, process.err)
	}
	return nil
}

func (process *managedProcess) terminate() error {
	process.stopOnce.Do(func() {
		if exited, _ := process.exited(); exited {
			return
		}
		signalErr := syscall.Kill(-process.pgid, syscall.SIGTERM)
		select {
		case <-process.done:
			process.stopErr = signalErr
		case <-time.After(5 * time.Second):
			killErr := syscall.Kill(-process.pgid, syscall.SIGKILL)
			<-process.done
			process.stopErr = errors.Join(signalErr, killErr)
		}
		if processGroupAlive(process.pgid) {
			process.stopErr = errors.Join(
				process.stopErr, terminateProcessGroup(process.pgid),
			)
		}
	})
	return process.stopErr
}

func (suite *suite) writeJSON(name string, value any) error {
	file, err := suite.root.OpenFile(
		name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600,
	)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	writeErr := encoder.Encode(value)
	return errors.Join(writeErr, file.Sync(), file.Close())
}

func deriveRunID(seed, family, scenario string) string {
	digest := sha256.Sum256([]byte(
		"winn-leak-scenario/v2\x00" + seed + "\x00" + family + "\x00" + scenario,
	))
	return hex.EncodeToString(digest[:16])
}

func orderedSubsequence(got, required []string) bool {
	index := 0
	for _, value := range got {
		if index < len(required) && value == required[index] {
			index++
		}
	}
	return index == len(required)
}

func credentialForUser(name string) (*syscall.Credential, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("look up WebRTC user %q: %w", name, err)
	}
	uidValue, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uidValue == 0 {
		return nil, errors.New("webrtc_user must resolve to a non-root numeric UID")
	}
	gidValue, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return nil, errors.New("webrtc_user has an invalid primary GID")
	}
	groupStrings, err := account.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("resolve WebRTC supplementary groups: %w", err)
	}
	groups := make([]uint32, 0, len(groupStrings))
	for _, value := range groupStrings {
		group, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, errors.New("webrtc_user has an invalid supplementary GID")
		}
		groups = append(groups, uint32(group))
	}
	return &syscall.Credential{
		Uid: uint32(uidValue), Gid: uint32(gidValue), Groups: groups,
	}, nil
}

func credentialModeCanExecute(
	mode os.FileMode,
	ownerUID uint32,
	ownerGID uint32,
	credential *syscall.Credential,
) bool {
	return credentialPermissionBits(
		mode, ownerUID, ownerGID, credential,
	)&0o1 != 0
}

func credentialPermissionBits(
	mode os.FileMode,
	ownerUID uint32,
	ownerGID uint32,
	credential *syscall.Credential,
) os.FileMode {
	if credential == nil || credential.Uid == 0 {
		return 0
	}
	permissions := mode.Perm()
	if credential.Uid == ownerUID {
		return permissions >> 6 & 0o7
	}
	if credential.Gid == ownerGID || slices.Contains(
		credential.Groups, ownerGID,
	) {
		return permissions >> 3 & 0o7
	}
	return permissions & 0o7
}

func credentialCanOpenParents(
	path string,
	credential *syscall.Credential,
) bool {
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || credentialPermissionBits(
			info.Mode(),
			uint32(stat.Uid),
			uint32(stat.Gid),
			credential,
		)&0o5 != 0o5 {
			return false
		}
		if directory == string(filepath.Separator) {
			return true
		}
	}
}

func prepareCredentialDirectory(
	path string,
	credential *syscall.Credential,
) error {
	if credential == nil || credential.Uid == 0 {
		return errors.New("invalid unprivileged browser credential")
	}
	// #nosec G302 -- a private directory requires its owner execute bit.
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	return os.Chown(path, int(credential.Uid), int(credential.Gid))
}

func requireExecutable(path string) (os.FileInfo, error) {
	file, info, err := openSecureRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if info.Mode().Perm()&0o111 == 0 {
		return nil, errors.New("file is not executable")
	}
	return info, nil
}

func sha256File(path string) (string, error) {
	file, _, err := openSecureRegular(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func openSecureRegular(path string) (*os.File, os.FileInfo, error) {
	if err := requireAbsoluteClean(path, "file"); err != nil {
		return nil, nil, err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, nil, err
	}
	if err := requireAbsoluteClean(resolved, "resolved file"); err != nil {
		return nil, nil, err
	}
	path = resolved
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, nil, err
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return nil, nil, errors.New("file parent must be a real directory")
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, nil, err
	}
	file, openErr := root.Open(filepath.Base(path))
	closeErr := root.Close()
	if openErr != nil {
		return nil, nil, openErr
	}
	if closeErr != nil {
		_ = file.Close()
		return nil, nil, closeErr
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, errors.New("file is not regular")
	}
	return file, info, nil
}

func requireAbsoluteClean(path, name string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s must be an absolute clean path", name)
	}
	return nil
}

func lowerHex(value string, bytes int) bool {
	if len(value) != bytes*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes
}

func sortedFamilyConfigs(value []familyConfig) []familyConfig {
	result := slices.Clone(value)
	slices.SortFunc(result, func(left, right familyConfig) int {
		return strings.Compare(left.Family, right.Family)
	})
	return result
}
