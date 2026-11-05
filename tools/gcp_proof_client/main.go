// Command winsvpn-gcp-proof-client is a dedicated, non-consumer release
// executable for the three-VM GCP proof. It never links into the Flutter app.
// It is the sole local orchestrator: every role is queried separately, and
// only exact real evidence is accepted before any action data is emitted.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	identityContract       = "winsvpn-gcp-proof-client-identity-v1"
	remoteContract         = "winsvpn-gcp-proof-remote-action-v4"
	requestContract        = "winsvpn-gcp-proof-remote-action-request-v4"
	winn3StatusContract    = "winsvpn-gcp-proof-winn3-status-v2"
	attemptJournalContract = "winsvpn-gcp-proof-protocol-attempts-v1"
	attemptAckContract     = "winsvpn-gcp-proof-protocol-attempt-ack-v1"
	transactionContract    = "winsvpn-gcp-proof-transaction-v4"
	remoteHelper           = "/usr/local/libexec/winsvpn-gcp-proof-remote"
	remoteSudo             = "/usr/bin/sudo"
	remoteSchemaVersion    = 4
	winn3StatusVersion     = 2
	maxRemoteOutput        = 4 * 1024 * 1024
	commandTimeout         = 120 * time.Second
	maxActionNanoseconds   = uint64(commandTimeout / time.Nanosecond)
	phaseObserveBefore     = "observe-before"
	phaseExercise          = "exercise"
	phaseObserveAfter      = "observe-after"
	phaseMutate            = "mutate"
	describeFormat         = "json(id,name)"
	realWinn3Interface     = "winn3gw0"
	realAWGInterface       = "awg0"
)

// These values are set only by tools/build_gcp_proof_client.py. A binary with
// any unset value refuses both identity and action modes.
var (
	releaseValue        = "UNSET"
	sharedRevision      = "UNSET"
	sourceSHA256        = "UNSET"
	buildContractSHA256 = "UNSET"
	toolchainVersion    = "UNSET"
	targetValue         = "UNSET"
	buildIdentity       = "UNSET"
	// The reviewed builder must set this with
	// -X=main.expectedAttemptBrokerSHA256=<lowercase-sha256>.
	expectedAttemptBrokerSHA256 = "UNSET"
)

var (
	projectPattern      = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	instancePattern     = regexp.MustCompile(`^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)
	zonePattern         = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]+-[a-z]$`)
	idPattern           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$`)
	fleetPattern        = regexp.MustCompile(`^[a-f0-9]{12}$`)
	shaPattern          = regexp.MustCompile(`^[a-f0-9]{64}$`)
	releasePattern      = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\+[0-9]+$`)
	sharedPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	interfacePattern    = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,64}$`)
	utcPattern          = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$`)
	instanceIDPattern   = regexp.MustCompile(`^[1-9][0-9]{0,31}$`)
	bootIDPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	processNoncePattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	awgKeyPattern       = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
	xrayUserPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@:-]{0,127}$`)
	commPattern         = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,16}$`)
)

var syntheticInterfaces = map[string]bool{
	"winn3": true,
	"xray0": true,
}

var actionNames = []string{
	"route-decision",
	"connect-primary",
	"connect-cover-awg",
	"connect-cover-xray",
	"inject-awg-block",
	"probe-awg-block",
	"restore-awg",
	"inject-winn3-block",
	"probe-winn3-block",
	"withdraw-cover",
	"probe-cover-withdrawn",
	"restore-cover",
	"restore-winn3",
	"teardown-check",
}

var actionOperations = map[string]string{
	"route-decision":        "query-signed-route-decision",
	"connect-primary":       "exercise-winn3-client",
	"connect-cover-awg":     "exercise-awg-client",
	"connect-cover-xray":    "exercise-xray-client",
	"inject-awg-block":      "block-cover-awg",
	"probe-awg-block":       "exercise-cover-fallback",
	"restore-awg":           "restore-cover-awg",
	"inject-winn3-block":    "block-winn3",
	"probe-winn3-block":     "exercise-winn3-fallback",
	"withdraw-cover":        "withdraw-cover-route",
	"probe-cover-withdrawn": "exercise-downgrade-refusal",
	"restore-cover":         "restore-cover-route",
	"restore-winn3":         "restore-winn3",
	"teardown-check":        "inspect-proof-scope",
}

var mutatingActions = map[string]bool{
	"inject-awg-block":   true,
	"restore-awg":        true,
	"inject-winn3-block": true,
	"withdraw-cover":     true,
	"restore-cover":      true,
	"restore-winn3":      true,
}

type options struct {
	action, project, gcloudBin, fleetID  string
	controlInstance, controlZone         string
	winn3Instance, winn3Zone             string
	coverInstance, coverZone             string
	runID, sessionID, correlationID      string
	credentialKind, credentialPath       string
	credentialAccount, credentialProject string
}

type observationStep struct {
	instance, zone, role, phase string
}

type commandResult struct {
	stdout, stderr []byte
	exitCode       int
}

type commandRunner interface {
	run(ctx context.Context, argv []string) (commandResult, error)
}

type subprocessRunner struct{}

func (subprocessRunner) run(ctx context.Context, argv []string) (commandResult, error) {
	if len(argv) == 0 {
		return commandResult{}, errors.New("empty command argv")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = nil
	stdout, err := cmd.Output()
	if err == nil {
		return commandResult{stdout: stdout, exitCode: 0}, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return commandResult{
			stdout:   stdout,
			stderr:   append([]byte(nil), exitErr.Stderr...),
			exitCode: exitErr.ExitCode(),
		}, nil
	}
	return commandResult{}, err
}

type gcloudGuard interface {
	run(context.Context, commandRunner, []string) (commandResult, error)
	verifyUnchanged() error
	bindIdentity(gcloudIdentityInput) error
}

var loadGcloudGuard = func(path string) (gcloudGuard, error) {
	return verifyGcloudCustody(path)
}

var newChallenge = func() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", errors.New("proof challenge generation failed")
	}
	return hex.EncodeToString(buf), nil
}

func verifyGcloudVersion(ctx context.Context, runner commandRunner, guard gcloudGuard) error {
	result, err := guard.run(ctx, runner, []string{"version", "--format=json"})
	if err != nil || result.exitCode != 0 || len(bytes.TrimSpace(result.stderr)) != 0 || len(result.stdout) > 65536 {
		return errors.New("Google Cloud CLI version probe failed")
	}
	var payload map[string]any
	if err := strictDecode(result.stdout, &payload); err != nil {
		return errors.New("Google Cloud CLI version output is invalid")
	}
	if observed, ok := payload["Google Cloud SDK"].(string); !ok || observed != reviewedGcloudVersion {
		return fmt.Errorf("Google Cloud CLI version mismatch: expected %q", reviewedGcloudVersion)
	}
	return nil
}

type compiledIdentity struct {
	SchemaVersion       int    `json:"schema_version"`
	Contract            string `json:"contract"`
	Release             string `json:"release"`
	SharedRevision      string `json:"shared_revision"`
	SourceSHA256        string `json:"source_sha256"`
	BuildContractSHA256 string `json:"build_contract_sha256"`
	ToolchainVersion    string `json:"toolchain_version"`
	Target              string `json:"target"`
	BuildIdentity       string `json:"build_identity"`
}

type remoteEnvelope struct {
	SchemaVersion int             `json:"schema_version"`
	Contract      string          `json:"contract"`
	Action        string          `json:"action"`
	Phase         string          `json:"phase"`
	Project       string          `json:"project"`
	Instance      string          `json:"instance"`
	InstanceID    string          `json:"instance_id"`
	BootID        string          `json:"boot_id"`
	Role          string          `json:"role"`
	RunID         string          `json:"run_id"`
	SessionID     string          `json:"session_id"`
	CorrelationID string          `json:"correlation_id"`
	Operation     string          `json:"operation"`
	EffectKind    string          `json:"effect_kind"`
	Challenge     string          `json:"challenge"`
	RequestSHA256 string          `json:"request_sha256"`
	HelperHashes  json.RawMessage `json:"helper_hashes"`
	StartedUTC    string          `json:"started_utc"`
	EndedUTC      string          `json:"ended_utc"`
	StateSHA256   string          `json:"state_sha256"`
	Evidence      json.RawMessage `json:"evidence"`
	Transaction   json.RawMessage `json:"transaction"`
	Data          json.RawMessage `json:"data"`
	EffectSHA256  string          `json:"effect_sha256"`
}

type remoteEvidence struct {
	StartedMonotonicNS     uint64               `json:"started_monotonic_ns"`
	EndedMonotonicNS       uint64               `json:"ended_monotonic_ns"`
	Services               serviceEvidence      `json:"services"`
	ProcessIdentity        processIdentity      `json:"process_identity"`
	InstanceID             string               `json:"instance_id"`
	BootID                 string               `json:"boot_id"`
	Role                   string               `json:"role"`
	Instance               string               `json:"instance"`
	ClientBuildIdentity    string               `json:"client_build_identity"`
	Challenge              string               `json:"challenge"`
	RequestSHA256          string               `json:"request_sha256"`
	Winn3Status            *winn3Status         `json:"winn3_status"`
	InterfaceCounters      map[string]netCount  `json:"interface_counters"`
	AWGPeers               []awgPeer            `json:"awg_peers"`
	XrayStats              *xrayUserStats       `json:"xray_stats"`
	AttemptAcknowledgments []protocolAttemptAck `json:"attempt_acknowledgements"`
	AttemptJournalBefore   *attemptJournal      `json:"attempt_journal_before"`
	AttemptJournalAfterAWG *attemptJournal      `json:"attempt_journal_after_awg"`
	AttemptJournalAfter    *attemptJournal      `json:"attempt_journal_after"`
}

type processIdentity struct {
	PID            uint64 `json:"pid"`
	ExeSHA256      string `json:"exe_sha256"`
	StarttimeTicks uint64 `json:"starttime_ticks"`
	Comm           string `json:"comm"`
}

type serviceEvidence struct {
	Units     map[string]serviceUnitEvidence `json:"units"`
	Binaries  map[string]string              `json:"binaries"`
	Forbidden forbiddenServiceEvidence       `json:"forbidden"`
}

type serviceUnitEvidence struct {
	ActiveState      string `json:"active_state"`
	FragmentPath     string `json:"fragment_path"`
	FragmentSHA256   string `json:"fragment_sha256"`
	MainPID          uint64 `json:"main_pid"`
	ExecutableSHA256 string `json:"executable_sha256"`
}

type forbiddenServiceEvidence struct {
	Units    map[string]forbiddenUnitEvidence   `json:"units"`
	Binaries map[string]forbiddenBinaryEvidence `json:"binaries"`
}

type forbiddenUnitEvidence struct {
	LoadState string `json:"load_state"`
}

type forbiddenBinaryEvidence struct {
	Absent bool `json:"absent"`
}

type netCount struct {
	RX uint64 `json:"rx"`
	TX uint64 `json:"tx"`
}

type awgPeer struct {
	PublicKey           string `json:"public_key"`
	LatestHandshakeUnix uint64 `json:"latest_handshake_unix"`
	RX                  uint64 `json:"rx"`
	TX                  uint64 `json:"tx"`
}

type xrayUserStats struct {
	User     string `json:"user"`
	Uplink   uint64 `json:"uplink"`
	Downlink uint64 `json:"downlink"`
}

type winn3Status struct {
	SchemaVersion         int    `json:"schema_version"`
	Contract              string `json:"contract"`
	Event                 string `json:"event"`
	Ready                 bool   `json:"ready"`
	Forward               bool   `json:"forward"`
	ProcessID             uint64 `json:"process_id"`
	ProcessNonce          string `json:"process_nonce"`
	BootID                string `json:"boot_id"`
	ProcessStartTicks     uint64 `json:"process_start_ticks"`
	ProcessStartedUTC     string `json:"process_started_utc"`
	ObservedUTC           string `json:"observed_utc"`
	ObservedMonotonicNS   uint64 `json:"observed_monotonic_ns"`
	Sequence              uint64 `json:"sequence"`
	InnerPacketsDelivered uint64 `json:"inner_packets_delivered"`
	Reflected             uint64 `json:"reflected"`
	RXDeviceWrites        uint64 `json:"rx_device_writes"`
}

type attemptJournal struct {
	Contract      string         `json:"contract"`
	Events        []attemptEvent `json:"events"`
	SchemaVersion int            `json:"schema_version"`
}

type attemptEvent struct {
	Action        string `json:"action"`
	CorrelationID string `json:"correlation_id"`
	MonotonicNS   uint64 `json:"monotonic_ns"`
	Node          string `json:"node"`
	Phase         string `json:"phase"`
	Protocol      string `json:"protocol"`
	Result        string `json:"result"`
	SessionID     string `json:"session_id"`
	UTC           string `json:"utc"`
}

type protocolAttemptAck struct {
	Action        string `json:"action"`
	Contract      string `json:"contract"`
	CorrelationID string `json:"correlation_id"`
	Node          string `json:"node"`
	Protocol      string `json:"protocol"`
	SessionID     string `json:"session_id"`
	State         string `json:"state"`
}

type transactionRecord struct {
	Contract       string          `json:"contract"`
	Nonce          string          `json:"nonce"`
	Kind           string          `json:"kind"`
	Protocol       string          `json:"protocol"`
	ResponseSHA256 string          `json:"response_sha256"`
	Response       json.RawMessage `json:"response"`
}

type proofAttempt struct {
	Protocol string `json:"protocol"`
	Node     string `json:"node"`
	Result   string `json:"result"`
}

type statusDelta struct {
	InnerPacketsDelivered uint64 `json:"inner_packets_delivered"`
	RXDeviceWrites        uint64 `json:"rx_device_writes"`
}

type validatedObservation struct {
	step        observationStep
	envelope    remoteEnvelope
	evidence    remoteEvidence
	helpers     map[string]string
	transaction transactionRecord
	started     time.Time
	ended       time.Time
}

type fleetIDs struct {
	control, winn3, cover string
}

func main() {
	if err := runCLI(os.Args[1:], subprocessRunner{}, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func runCLI(argv []string, runner commandRunner, output io.Writer) error {
	identity, err := currentIdentity()
	if err != nil {
		return err
	}
	if len(argv) == 1 && argv[0] == "--winsvpn-proof-identity" {
		return writeJSON(output, identity)
	}
	opts, err := parseActionArgs(argv)
	if err != nil {
		return err
	}
	guard, err := loadGcloudGuard(opts.gcloudBin)
	if err != nil {
		return err
	}
	if err := guard.bindIdentity(gcloudIdentityInput{
		kind: opts.credentialKind, path: opts.credentialPath,
		expectedAccount: opts.credentialAccount, expectedProject: opts.credentialProject,
	}); err != nil {
		return err
	}
	versionCtx, versionCancel := context.WithTimeout(context.Background(), commandTimeout)
	if err := verifyGcloudVersion(versionCtx, runner, guard); err != nil {
		versionCancel()
		return err
	}
	versionCancel()
	challenge, err := newChallenge()
	if err != nil {
		return err
	}
	if !shaPattern.MatchString(challenge) {
		return errors.New("proof challenge is invalid")
	}
	ids, err := describeFleetIDs(runner, guard, opts)
	if err != nil {
		return err
	}
	plan := observationPlan(opts)
	if len(plan) == 0 {
		return errors.New("proof observation plan is empty")
	}
	seen := map[string]struct{}{}
	observations := make([]validatedObservation, 0, len(plan))
	for _, step := range plan {
		key := step.role + "/" + step.phase
		if _, found := seen[key]; found {
			return errors.New("duplicate role observation is forbidden")
		}
		seen[key] = struct{}{}
		requestSHA, err := requestDigest(opts, identity, step, challenge)
		if err != nil {
			return err
		}
		body, err := runRemoteStep(runner, guard, opts, identity, step, challenge, requestSHA)
		if err != nil {
			return err
		}
		obs, err := validateRoleObservation(body, opts, identity, step, challenge, requestSHA, ids)
		if err != nil {
			return err
		}
		observations = append(observations, obs)
	}
	if err := validateObservationSequence(opts, observations, ids, challenge); err != nil {
		return err
	}
	data, err := assembleActionData(opts, observations, ids, challenge)
	if err != nil {
		return err
	}
	if err := validateProofClosure(opts, observations); err != nil {
		return err
	}
	return writeJSON(output, data)
}

func currentIdentity() (compiledIdentity, error) {
	if _, err := reviewedAttemptBrokerIdentity(); err != nil {
		return compiledIdentity{}, err
	}
	value := compiledIdentity{
		SchemaVersion:       1,
		Contract:            identityContract,
		Release:             releaseValue,
		SharedRevision:      sharedRevision,
		SourceSHA256:        sourceSHA256,
		BuildContractSHA256: buildContractSHA256,
		ToolchainVersion:    toolchainVersion,
		Target:              targetValue,
		BuildIdentity:       buildIdentity,
	}
	if !releasePattern.MatchString(value.Release) ||
		!sharedPattern.MatchString(value.SharedRevision) ||
		!shaPattern.MatchString(value.SourceSHA256) ||
		!shaPattern.MatchString(value.BuildContractSHA256) ||
		!regexp.MustCompile(`^go[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(value.ToolchainVersion) ||
		value.Target != "linux/amd64" ||
		!shaPattern.MatchString(value.BuildIdentity) {
		return compiledIdentity{}, errors.New("proof executable has no valid release build identity")
	}
	return value, nil
}

func reviewedAttemptBrokerIdentity() (string, error) {
	if !shaPattern.MatchString(expectedAttemptBrokerSHA256) ||
		expectedAttemptBrokerSHA256 == strings.Repeat("0", 64) {
		return "", errors.New("proof executable has no reviewed attempt-broker identity")
	}
	return expectedAttemptBrokerSHA256, nil
}

var actionArgNames = []string{
	"--winsvpn-proof-action",
	"--project",
	"--gcloud-bin",
	"--fleet-id",
	"--control-instance",
	"--control-zone",
	"--winn3-data-instance",
	"--winn3-data-zone",
	"--cover-data-instance",
	"--cover-data-zone",
	"--run-id",
	"--session-id",
	"--correlation-id",
}

var credentialArgNames = []string{
	"--credential-kind",
	"--credential-path",
	"--credential-account",
	"--credential-project",
}

func parseActionArgs(argv []string) (options, error) {
	required := len(actionArgNames) * 2
	extra := len(credentialArgNames) * 2
	if len(argv) != required && len(argv) != required+extra {
		return options{}, errors.New("proof action argv has missing or extra tokens")
	}
	values := make(map[string]string, len(actionArgNames))
	for index, name := range actionArgNames {
		position := index * 2
		if argv[position] != name || argv[position+1] == "" {
			return options{}, fmt.Errorf("proof action argv must use the fixed position for %s", name)
		}
		values[name] = argv[position+1]
	}
	o := options{
		action: values["--winsvpn-proof-action"], project: values["--project"],
		gcloudBin: values["--gcloud-bin"], fleetID: values["--fleet-id"],
		controlInstance: values["--control-instance"], controlZone: values["--control-zone"],
		winn3Instance: values["--winn3-data-instance"], winn3Zone: values["--winn3-data-zone"],
		coverInstance: values["--cover-data-instance"], coverZone: values["--cover-data-zone"],
		runID: values["--run-id"], sessionID: values["--session-id"],
		correlationID: values["--correlation-id"],
	}
	if _, found := actionOperations[o.action]; !found {
		return options{}, errors.New("proof action is unsupported")
	}
	if !projectPattern.MatchString(o.project) || !fleetPattern.MatchString(o.fleetID) {
		return options{}, errors.New("proof project or fleet id is invalid")
	}
	if !validGcloudPath(o.gcloudBin) {
		return options{}, errors.New("proof gcloud executable path is invalid")
	}
	for _, item := range []struct{ name, value string }{
		{"control instance", o.controlInstance}, {"Winn3 instance", o.winn3Instance},
		{"cover instance", o.coverInstance},
	} {
		if !instancePattern.MatchString(item.value) {
			return options{}, fmt.Errorf("proof %s is invalid", item.name)
		}
	}
	if o.controlInstance == o.winn3Instance || o.controlInstance == o.coverInstance || o.winn3Instance == o.coverInstance {
		return options{}, errors.New("proof instance identities must be distinct")
	}
	for _, item := range []struct{ name, value string }{
		{"control zone", o.controlZone}, {"Winn3 zone", o.winn3Zone}, {"cover zone", o.coverZone},
	} {
		if !zonePattern.MatchString(item.value) {
			return options{}, fmt.Errorf("proof %s is invalid", item.name)
		}
	}
	for _, item := range []struct{ name, value string }{
		{"run id", o.runID}, {"session id", o.sessionID}, {"correlation id", o.correlationID},
	} {
		if !idPattern.MatchString(item.value) {
			return options{}, fmt.Errorf("proof %s is invalid", item.name)
		}
	}
	if len(argv) == required {
		return o, nil
	}
	for index, name := range credentialArgNames {
		position := required + index*2
		if argv[position] != name || argv[position+1] == "" {
			return options{}, fmt.Errorf("proof action argv must use the fixed position for %s", name)
		}
	}
	o.credentialKind = argv[required+1]
	o.credentialPath = argv[required+3]
	o.credentialAccount = argv[required+5]
	o.credentialProject = argv[required+7]
	if o.credentialProject != o.project {
		return options{}, errors.New("proof credential project does not match the bound project")
	}
	if strings.ContainsAny(o.credentialPath, "\\\x00\r\n\t") || strings.Contains(o.credentialPath, "..") ||
		!strings.HasPrefix(o.credentialPath, "/") {
		return options{}, errors.New("proof credential path is invalid")
	}
	return o, nil
}

func validGcloudPath(value string) bool {
	if value == "" || strings.ContainsAny(value, "\\\x00\r\n\t ;&|$`(){}[]*?!<>") || strings.Contains(value, "..") {
		return false
	}
	parts := strings.Split(value, "/")
	base := parts[len(parts)-1]
	return base == "gcloud" || base == "gcloud.cmd"
}

func observationPlan(o options) []observationStep {
	control := observationStep{instance: o.controlInstance, zone: o.controlZone, role: "control"}
	winn3 := observationStep{instance: o.winn3Instance, zone: o.winn3Zone, role: "data-winn3"}
	cover := observationStep{instance: o.coverInstance, zone: o.coverZone, role: "data-cover"}
	with := func(step observationStep, phase string) observationStep {
		step.phase = phase
		return step
	}
	switch o.action {
	case "route-decision", "teardown-check":
		return []observationStep{with(control, phaseExercise)}
	case "connect-primary":
		return []observationStep{with(winn3, phaseObserveBefore), with(control, phaseExercise), with(winn3, phaseObserveAfter)}
	case "connect-cover-awg", "connect-cover-xray", "probe-awg-block":
		return []observationStep{with(cover, phaseObserveBefore), with(control, phaseExercise), with(cover, phaseObserveAfter)}
	case "inject-awg-block", "restore-awg":
		return []observationStep{with(cover, phaseMutate)}
	case "inject-winn3-block", "restore-winn3":
		return []observationStep{with(winn3, phaseMutate)}
	case "withdraw-cover", "restore-cover":
		return []observationStep{with(control, phaseMutate)}
	case "probe-winn3-block", "probe-cover-withdrawn":
		return []observationStep{
			with(winn3, phaseObserveBefore), with(cover, phaseObserveBefore),
			with(control, phaseExercise),
			with(winn3, phaseObserveAfter), with(cover, phaseObserveAfter),
		}
	default:
		return nil
	}
}

func describeFleetIDs(runner commandRunner, guard gcloudGuard, o options) (fleetIDs, error) {
	var ids fleetIDs
	for _, item := range []struct {
		role, instance, zone string
		dst                  *string
	}{
		{"control", o.controlInstance, o.controlZone, &ids.control},
		{"data-winn3", o.winn3Instance, o.winn3Zone, &ids.winn3},
		{"data-cover", o.coverInstance, o.coverZone, &ids.cover},
	} {
		id, err := describeInstanceID(runner, guard, o, item.instance, item.zone)
		if err != nil {
			return fleetIDs{}, err
		}
		*item.dst = id
	}
	if ids.control == ids.winn3 || ids.control == ids.cover || ids.winn3 == ids.cover {
		return fleetIDs{}, errors.New("proof instance numeric ids must be distinct")
	}
	return ids, nil
}

func describeInstanceID(runner commandRunner, guard gcloudGuard, o options, instance, zone string) (string, error) {
	command := []string{
		"compute", "instances", "describe", instance,
		"--zone=" + zone,
		"--quiet",
		"--project=" + o.project,
		"--format=" + describeFormat,
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	result, err := guard.run(ctx, runner, command)
	if err != nil {
		return "", fmt.Errorf("proof instance describe failed: %w", err)
	}
	if result.exitCode != 0 || len(bytes.TrimSpace(result.stderr)) != 0 {
		return "", errors.New("proof instance describe exited unexpectedly")
	}
	fields, err := decodeExactObject(result.stdout, []string{"id", "name"}, nil)
	if err != nil {
		return "", errors.New("proof instance describe output is invalid")
	}
	var name string
	if err := strictDecode(fields["name"], &name); err != nil || name != instance {
		return "", errors.New("proof instance describe name mismatch")
	}
	var id string
	if err := strictDecode(fields["id"], &id); err != nil || !instanceIDPattern.MatchString(id) {
		return "", errors.New("proof instance numeric id is missing or malformed")
	}
	return id, nil
}

func requestDigest(o options, identity compiledIdentity, step observationStep, challenge string) (string, error) {
	core := map[string]any{
		"action": stepAction(o), "challenge": challenge, "client_build_identity": identity.BuildIdentity,
		"contract": requestContract, "correlation_id": o.correlationID, "fleet_id": o.fleetID,
		"instance": step.instance, "phase": step.phase, "project": o.project, "role": step.role,
		"run_id": o.runID, "schema_version": remoteSchemaVersion, "session_id": o.sessionID,
	}
	encoded, err := canonicalJSON(core, true)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func stepAction(o options) string {
	return o.action
}

func runRemoteStep(
	runner commandRunner,
	guard gcloudGuard,
	o options,
	identity compiledIdentity,
	step observationStep,
	challenge, requestSHA string,
) ([]byte, error) {
	remoteCommand := strings.Join([]string{
		remoteSudo,
		"--non-interactive",
		remoteHelper,
		"--schema-version=" + strconv.Itoa(remoteSchemaVersion),
		"--action=" + o.action,
		"--phase=" + step.phase,
		"--project=" + o.project,
		"--instance=" + step.instance,
		"--role=" + step.role,
		"--fleet-id=" + o.fleetID,
		"--run-id=" + o.runID,
		"--session-id=" + o.sessionID,
		"--correlation-id=" + o.correlationID,
		"--client-build-identity=" + identity.BuildIdentity,
		"--challenge=" + challenge,
		"--request-hash=" + requestSHA,
	}, " ")
	command := []string{
		"compute", "ssh", step.instance,
		"--zone=" + step.zone,
		"--quiet",
		"--project=" + o.project,
		"--command=" + remoteCommand,
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	result, err := guard.run(ctx, runner, command)
	if err != nil {
		return nil, fmt.Errorf("proof remote action execution failed: %w", err)
	}
	if result.exitCode != 0 {
		return nil, fmt.Errorf("proof remote action exited %d", result.exitCode)
	}
	if len(bytes.TrimSpace(result.stderr)) != 0 {
		return nil, errors.New("proof remote action wrote unexpected stderr")
	}
	if len(result.stdout) == 0 || len(result.stdout) > maxRemoteOutput {
		return nil, errors.New("proof remote action output size is invalid")
	}
	return result.stdout, nil
}

func instanceIDForRole(ids fleetIDs, role string) string {
	switch role {
	case "control":
		return ids.control
	case "data-winn3":
		return ids.winn3
	case "data-cover":
		return ids.cover
	default:
		return ""
	}
}

func decodeRemoteEnvelope(data []byte) (remoteEnvelope, error) {
	var value remoteEnvelope
	if _, err := decodeExactObject(data, []string{
		"schema_version", "contract", "action", "phase", "project", "instance", "instance_id",
		"boot_id", "role", "run_id", "session_id", "correlation_id", "operation", "effect_kind",
		"challenge", "request_sha256", "helper_hashes", "started_utc", "ended_utc", "state_sha256",
		"evidence", "transaction", "data", "effect_sha256",
	}, &value); err != nil {
		return remoteEnvelope{}, fmt.Errorf("remote action envelope is invalid: %w", err)
	}
	if err := rejectForbiddenEvidenceKeys(data); err != nil {
		return remoteEnvelope{}, err
	}
	return value, nil
}

func strictDecode(data []byte, target any) error {
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are forbidden")
		}
		return err
	}
	return nil
}

func decodeExactObject(data []byte, expected []string, target any) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := strictDecode(data, &fields); err != nil {
		return nil, err
	}
	if !exactRawKeys(fields, expected) {
		return nil, errors.New("JSON object keys mismatch")
	}
	if target != nil {
		if err := strictDecode(data, target); err != nil {
			return nil, err
		}
	}
	return fields, nil
}

func exactRawKeys(value map[string]json.RawMessage, expected []string) bool {
	if value == nil || len(value) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, found := value[key]; !found {
			return false
		}
	}
	return true
}

func rejectForbiddenEvidenceKeys(data []byte) error {
	var value any
	if err := strictDecode(data, &value); err != nil {
		return err
	}
	forbidden := map[string]bool{
		"pass": true, "passed": true, "ok": true, "success": true,
		"verdict": true, "acceptance": true,
	}
	var walk func(any) error
	walk = func(raw any) error {
		switch item := raw.(type) {
		case map[string]any:
			for key, child := range item {
				if forbidden[strings.ToLower(key)] {
					return fmt.Errorf("forbidden proof assertion key %q", key)
				}
				if err := walk(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range item {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(value)
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, isDelim := token.(json.Delim)
		if !isDelim {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				if _, found := seen[key]; found {
					return fmt.Errorf("duplicate JSON key %q is forbidden", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return errors.New("JSON object is not closed")
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return errors.New("JSON array is not closed")
			}
		default:
			return errors.New("unexpected JSON closing delimiter")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are forbidden")
		}
		return err
	}
	return nil
}

func expectedEffectKind(phase string) string {
	if phase == phaseMutate {
		return "remote_mutation"
	}
	return "observation"
}

func validateRemoteEnvelope(value remoteEnvelope, o options, identity compiledIdentity, step observationStep, challenge, requestSHA, instanceID string) error {
	if value.SchemaVersion != remoteSchemaVersion || value.Contract != remoteContract ||
		value.Action != o.action || value.Phase != step.phase || value.Project != o.project ||
		value.Instance != step.instance || value.InstanceID != instanceID ||
		!instanceIDPattern.MatchString(value.InstanceID) || !bootIDPattern.MatchString(value.BootID) ||
		value.Role != step.role || value.RunID != o.runID || value.SessionID != o.sessionID ||
		value.CorrelationID != o.correlationID || value.Operation != actionOperations[o.action] ||
		value.EffectKind != expectedEffectKind(step.phase) || value.Challenge != challenge ||
		value.RequestSHA256 != requestSHA || !shaPattern.MatchString(value.StateSHA256) ||
		!shaPattern.MatchString(value.EffectSHA256) || value.Challenge != challenge {
		return errors.New("remote action envelope identity or effect contract mismatch")
	}
	if value.Contract == "winsvpn-gcp-proof-remote-action-test-v1" || value.SchemaVersion == 1 {
		return errors.New("synthetic or stale remote action contract is forbidden")
	}
	started, err := parseUTC(value.StartedUTC)
	if err != nil {
		return fmt.Errorf("remote action start is invalid: %w", err)
	}
	ended, err := parseUTC(value.EndedUTC)
	if err != nil || !ended.After(started) || ended.Sub(started) > commandTimeout {
		return errors.New("remote action time window is invalid")
	}
	stateDigest, err := canonicalJSONDigest(value.Evidence)
	if err != nil || stateDigest != value.StateSHA256 {
		return errors.New("remote action state digest mismatch")
	}
	digest, err := remoteEffectDigest(value)
	if err != nil || digest != value.EffectSHA256 {
		return errors.New("remote action effect digest mismatch")
	}
	_ = identity
	return nil
}

func remoteEffectDigest(value remoteEnvelope) (string, error) {
	var data any
	if err := strictDecode(value.Data, &data); err != nil {
		return "", err
	}
	var evidence any
	if err := strictDecode(value.Evidence, &evidence); err != nil {
		return "", err
	}
	var helpers any
	if err := strictDecode(value.HelperHashes, &helpers); err != nil {
		return "", err
	}
	var transaction any
	if err := strictDecode(value.Transaction, &transaction); err != nil {
		return "", err
	}
	core := map[string]any{
		"action": value.Action, "boot_id": value.BootID, "challenge": value.Challenge,
		"contract": value.Contract, "correlation_id": value.CorrelationID, "data": data,
		"effect_kind": value.EffectKind, "ended_utc": value.EndedUTC, "evidence": evidence,
		"helper_hashes": helpers, "instance": value.Instance, "instance_id": value.InstanceID,
		"operation": value.Operation, "phase": value.Phase, "project": value.Project,
		"request_sha256": value.RequestSHA256, "role": value.Role, "run_id": value.RunID,
		"schema_version": value.SchemaVersion, "session_id": value.SessionID,
		"started_utc": value.StartedUTC, "state_sha256": value.StateSHA256,
		"transaction": transaction,
	}
	encoded, err := canonicalJSON(core, false)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func canonicalJSONDigest(raw []byte) (string, error) {
	var value any
	if err := strictDecode(raw, &value); err != nil {
		return "", err
	}
	encoded, err := canonicalJSON(value, true)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func canonicalJSON(value any, newline bool) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	encoded := bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	var canonical bytes.Buffer
	for _, current := range string(encoded) {
		if current < 0x7f {
			canonical.WriteByte(byte(current))
			continue
		}
		if current <= 0xffff {
			fmt.Fprintf(&canonical, `\u%04x`, current)
			continue
		}
		high, low := utf16.EncodeRune(current)
		fmt.Fprintf(&canonical, `\u%04x\u%04x`, high, low)
	}
	if newline {
		canonical.WriteByte('\n')
	}
	return canonical.Bytes(), nil
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func validateRoleObservation(
	raw []byte,
	o options,
	identity compiledIdentity,
	step observationStep,
	challenge, requestSHA string,
	ids fleetIDs,
) (validatedObservation, error) {
	instanceID := instanceIDForRole(ids, step.role)
	envelope, err := decodeRemoteEnvelope(raw)
	if err != nil {
		return validatedObservation{}, err
	}
	if err := validateRemoteEnvelope(envelope, o, identity, step, challenge, requestSHA, instanceID); err != nil {
		return validatedObservation{}, err
	}
	helpers, err := validateHelperHashes(envelope.HelperHashes, o, step)
	if err != nil {
		return validatedObservation{}, err
	}
	transaction, err := validateTransaction(envelope.Transaction, envelope.EffectKind, challenge, o, step)
	if err != nil {
		return validatedObservation{}, err
	}
	evidence, err := validateRemoteEvidence(envelope.Evidence, o, identity, step, challenge, requestSHA, instanceID, envelope.BootID)
	if err != nil {
		return validatedObservation{}, err
	}
	if step.phase == phaseObserveBefore || step.phase == phaseObserveAfter {
		if !isJSONNull(envelope.Data) {
			return validatedObservation{}, errors.New("observe phase must not carry action data")
		}
	}
	started, _ := parseUTC(envelope.StartedUTC)
	ended, _ := parseUTC(envelope.EndedUTC)
	return validatedObservation{
		step: step, envelope: envelope, evidence: evidence, helpers: helpers,
		transaction: transaction, started: started, ended: ended,
	}, nil
}

func validateHelperHashes(raw json.RawMessage, o options, step observationStep) (map[string]string, error) {
	expected := []string{"remote"}
	requireAttemptBroker := step.role == "control" && step.phase == phaseExercise && isAttemptAckAction(o.action)
	if requireAttemptBroker {
		expected = []string{"attempt_broker", "remote"}
	}
	fields, err := decodeExactObject(raw, expected, nil)
	if err != nil {
		return nil, errors.New("helper hash evidence is missing or malformed")
	}
	values := map[string]string{}
	for _, key := range expected {
		var digest string
		if err := strictDecode(fields[key], &digest); err != nil || !shaPattern.MatchString(digest) {
			return nil, errors.New("helper hash evidence is missing or malformed")
		}
		values[key] = digest
	}
	if values["remote"] == strings.Repeat("0", 64) {
		return nil, errors.New("helper hash evidence is missing or malformed")
	}
	if requireAttemptBroker {
		reviewed, err := reviewedAttemptBrokerIdentity()
		if err != nil || values["attempt_broker"] == strings.Repeat("0", 64) || values["attempt_broker"] != reviewed {
			return nil, errors.New("attempt-broker helper identity does not match the reviewed boundary")
		}
	}
	return values, nil
}

func validateTransaction(raw json.RawMessage, effectKind, challenge string, o options, step observationStep) (transactionRecord, error) {
	var value transactionRecord
	if _, err := decodeExactObject(raw, []string{
		"contract", "nonce", "kind", "protocol", "response_sha256", "response",
	}, &value); err != nil {
		return transactionRecord{}, errors.New("exact transaction response is invalid")
	}
	if value.Contract != transactionContract || value.Nonce != challenge ||
		value.Kind != effectKind || !shaPattern.MatchString(value.ResponseSHA256) ||
		len(bytes.TrimSpace(value.Response)) == 0 || isJSONNull(value.Response) {
		return transactionRecord{}, errors.New("exact transaction response is invalid")
	}
	digest, err := canonicalJSONDigest(value.Response)
	if err != nil || digest != value.ResponseSHA256 {
		return transactionRecord{}, errors.New("exact transaction response digest mismatch")
	}
	if err := expectedTransactionProtocol(value.Protocol, o, step); err != nil {
		return transactionRecord{}, err
	}
	return value, nil
}

func expectedTransactionProtocol(protocol string, o options, step observationStep) error {
	want := ""
	switch {
	case step.role == "data-winn3":
		want = "winn3"
	case step.role == "data-cover" && o.action == "connect-cover-awg":
		want = "awg"
	case step.role == "data-cover" && o.action == "connect-cover-xray":
		want = "xray"
	case step.role == "data-cover" && (o.action == "probe-awg-block" || o.action == "inject-awg-block" || o.action == "restore-awg"):
		want = "awg-xray-fallback"
	case step.role == "data-cover":
		want = "cover"
	case o.action == "probe-awg-block" && step.phase == phaseExercise:
		want = "awg-xray-fallback"
	case o.action == "connect-cover-awg":
		want = "awg"
	case o.action == "connect-cover-xray":
		want = "xray"
	case o.action == "teardown-check":
		want = "scope"
	case o.action == "withdraw-cover" || o.action == "restore-cover" || o.action == "probe-cover-withdrawn":
		want = "cover"
	default:
		want = "winn3"
	}
	if protocol != want {
		return errors.New("exact transaction response protocol mismatch")
	}
	return nil
}

func validateRemoteEvidence(
	raw json.RawMessage,
	o options,
	identity compiledIdentity,
	step observationStep,
	challenge, requestSHA, instanceID, bootID string,
) (remoteEvidence, error) {
	if err := validateEvidenceShape(raw, o, step); err != nil {
		return remoteEvidence{}, fmt.Errorf("remote action evidence shape is invalid: %w", err)
	}
	var value remoteEvidence
	if err := strictDecode(raw, &value); err != nil {
		return remoteEvidence{}, fmt.Errorf("remote action evidence is invalid: %w", err)
	}
	if value.StartedMonotonicNS == 0 || value.EndedMonotonicNS <= value.StartedMonotonicNS ||
		value.EndedMonotonicNS-value.StartedMonotonicNS > maxActionNanoseconds {
		return remoteEvidence{}, errors.New("remote action monotonic interval is invalid")
	}
	if value.Role != step.role || value.Instance != step.instance ||
		value.ClientBuildIdentity != identity.BuildIdentity || value.Challenge != challenge ||
		value.RequestSHA256 != requestSHA || value.InstanceID != instanceID ||
		value.BootID != bootID || !instanceIDPattern.MatchString(value.InstanceID) ||
		!bootIDPattern.MatchString(value.BootID) {
		return remoteEvidence{}, errors.New("remote action evidence identity mismatch")
	}
	if err := validateProcessIdentity(value.ProcessIdentity); err != nil {
		return remoteEvidence{}, err
	}
	if err := validateServiceEvidence(value.Services, step.role); err != nil {
		return remoteEvidence{}, err
	}
	if err := bindProcessToServices(value.ProcessIdentity, value.Services, step.role); err != nil {
		return remoteEvidence{}, err
	}
	if err := validateRoleSpecificEvidence(value, o, step); err != nil {
		return remoteEvidence{}, err
	}
	return value, nil
}

func validateEvidenceShape(raw json.RawMessage, o options, step observationStep) error {
	fields, err := decodeExactObject(raw, []string{
		"started_monotonic_ns", "ended_monotonic_ns", "services", "process_identity",
		"instance_id", "boot_id", "role", "instance", "client_build_identity", "challenge",
		"request_sha256", "winn3_status", "interface_counters", "awg_peers", "xray_stats",
		"attempt_acknowledgements", "attempt_journal_before", "attempt_journal_after_awg",
		"attempt_journal_after",
	}, nil)
	if err != nil {
		return err
	}
	if _, err := decodeExactObject(fields["process_identity"], []string{
		"pid", "exe_sha256", "starttime_ticks", "comm",
	}, nil); err != nil {
		return err
	}
	serviceFields, err := decodeExactObject(fields["services"], []string{"units", "binaries", "forbidden"}, nil)
	if err != nil {
		return err
	}
	var units map[string]json.RawMessage
	if err := strictDecode(serviceFields["units"], &units); err != nil || units == nil {
		return errors.New("service units must be an object")
	}
	for _, rawUnit := range units {
		if _, err := decodeExactObject(rawUnit, []string{
			"active_state", "fragment_path", "fragment_sha256", "main_pid", "executable_sha256",
		}, nil); err != nil {
			return err
		}
	}
	forbiddenFields, err := decodeExactObject(serviceFields["forbidden"], []string{"units", "binaries"}, nil)
	if err != nil {
		return err
	}
	var forbiddenUnits map[string]json.RawMessage
	if err := strictDecode(forbiddenFields["units"], &forbiddenUnits); err != nil || forbiddenUnits == nil {
		return errors.New("forbidden units must be an object")
	}
	for _, item := range forbiddenUnits {
		if _, err := decodeExactObject(item, []string{"load_state"}, nil); err != nil {
			return err
		}
	}
	var forbiddenBinaries map[string]json.RawMessage
	if err := strictDecode(forbiddenFields["binaries"], &forbiddenBinaries); err != nil || forbiddenBinaries == nil {
		return errors.New("forbidden binaries must be an object")
	}
	for _, item := range forbiddenBinaries {
		if _, err := decodeExactObject(item, []string{"absent"}, nil); err != nil {
			return err
		}
	}
	if !isJSONNull(fields["winn3_status"]) {
		if _, err := decodeExactObject(fields["winn3_status"], []string{
			"schema_version", "contract", "event", "ready", "forward", "process_id",
			"process_nonce", "boot_id", "process_start_ticks", "process_started_utc",
			"observed_utc", "observed_monotonic_ns", "sequence",
			"inner_packets_delivered", "reflected", "rx_device_writes",
		}, nil); err != nil {
			return err
		}
	}
	if !isJSONNull(fields["interface_counters"]) {
		var counters map[string]json.RawMessage
		if err := strictDecode(fields["interface_counters"], &counters); err != nil || counters == nil {
			return errors.New("interface counters must be an object")
		}
		for name, item := range counters {
			if syntheticInterfaces[name] {
				return errors.New("synthetic interface evidence is forbidden")
			}
			if _, err := decodeExactObject(item, []string{"rx", "tx"}, nil); err != nil {
				return err
			}
		}
	}
	if !isJSONNull(fields["awg_peers"]) {
		var peers []json.RawMessage
		if err := strictDecode(fields["awg_peers"], &peers); err != nil || peers == nil {
			return errors.New("AWG peers must be an array")
		}
		for _, item := range peers {
			if _, err := decodeExactObject(item, []string{
				"public_key", "latest_handshake_unix", "rx", "tx",
			}, nil); err != nil {
				return err
			}
		}
	}
	if !isJSONNull(fields["xray_stats"]) {
		if _, err := decodeExactObject(fields["xray_stats"], []string{"user", "uplink", "downlink"}, nil); err != nil {
			return err
		}
	}
	var acknowledgements []json.RawMessage
	if err := strictDecode(fields["attempt_acknowledgements"], &acknowledgements); err != nil || acknowledgements == nil {
		return errors.New("attempt acknowledgements must be an array")
	}
	for _, item := range acknowledgements {
		if _, err := decodeExactObject(item, []string{
			"action", "contract", "correlation_id", "node", "protocol", "session_id", "state",
		}, nil); err != nil {
			return err
		}
	}
	for _, key := range []string{"attempt_journal_before", "attempt_journal_after_awg", "attempt_journal_after"} {
		if !isJSONNull(fields[key]) {
			if err := validateJournalShape(fields[key]); err != nil {
				return err
			}
		}
	}
	_ = o
	_ = step
	return nil
}

func validateJournalShape(raw json.RawMessage) error {
	journalFields, err := decodeExactObject(raw, []string{"contract", "events", "schema_version"}, nil)
	if err != nil {
		return err
	}
	var events []json.RawMessage
	if err := strictDecode(journalFields["events"], &events); err != nil || events == nil {
		return errors.New("attempt journal events must be an array")
	}
	for _, event := range events {
		if _, err := decodeExactObject(event, []string{
			"action", "correlation_id", "monotonic_ns", "node", "phase", "protocol", "result", "session_id", "utc",
		}, nil); err != nil {
			return err
		}
	}
	return nil
}

func validateProcessIdentity(value processIdentity) error {
	if value.PID == 0 || !shaPattern.MatchString(value.ExeSHA256) || value.StarttimeTicks == 0 ||
		!commPattern.MatchString(value.Comm) {
		return errors.New("process identity is missing or malformed")
	}
	return nil
}

func bindProcessToServices(process processIdentity, services serviceEvidence, role string) error {
	unitName := map[string]string{
		"control":    "wins-hub.service",
		"data-winn3": "winn3-gateway.service",
		"data-cover": "xray.service",
	}[role]
	unit, found := services.Units[unitName]
	if !found || unit.MainPID != process.PID || unit.ExecutableSHA256 != process.ExeSHA256 {
		return errors.New("process identity is not bound to the role service")
	}
	return nil
}

func validateServiceEvidence(value serviceEvidence, role string) error {
	expectedUnits := map[string][]string{
		"control":    {"wins-hub.service"},
		"data-winn3": {"winn3-gateway.service"},
		"data-cover": {"xray.service", "docker.service"},
	}[role]
	expectedBinaries := map[string][]string{
		"control":    {},
		"data-winn3": {"/usr/local/libexec/winn/winn3-gateway"},
		"data-cover": {"/usr/local/bin/xray"},
	}[role]
	if !exactTypedKeys(value.Units, expectedUnits) || !exactTypedKeys(value.Binaries, expectedBinaries) ||
		value.Forbidden.Units == nil || value.Forbidden.Binaries == nil {
		return errors.New("service evidence role inventory mismatch")
	}
	for name, unit := range value.Units {
		if unit.ActiveState != "active" || unit.MainPID == 0 || !strings.HasPrefix(unit.FragmentPath, "/") ||
			!shaPattern.MatchString(unit.FragmentSHA256) || !shaPattern.MatchString(unit.ExecutableSHA256) {
			return fmt.Errorf("service evidence is incomplete for %s", name)
		}
	}
	for path, digest := range value.Binaries {
		if !strings.HasPrefix(path, "/") || !shaPattern.MatchString(digest) {
			return errors.New("service binary evidence is invalid")
		}
	}
	expectedForbiddenUnits := []string{}
	expectedForbiddenBinaries := []string{}
	if role == "data-winn3" {
		expectedForbiddenUnits = []string{"xray.service", "docker.service", "docker.socket"}
		expectedForbiddenBinaries = []string{
			"/usr/local/bin/xray", "/usr/bin/xray", "/usr/bin/docker", "/usr/local/bin/docker",
			"/snap/bin/docker", "/usr/bin/dockerd", "/usr/local/bin/dockerd",
		}
	}
	if !exactTypedKeys(value.Forbidden.Units, expectedForbiddenUnits) ||
		!exactTypedKeys(value.Forbidden.Binaries, expectedForbiddenBinaries) {
		return errors.New("forbidden component evidence inventory mismatch")
	}
	for _, item := range value.Forbidden.Units {
		if item.LoadState != "not-found" {
			return errors.New("forbidden service is present on data-winn3")
		}
	}
	for _, item := range value.Forbidden.Binaries {
		if !item.Absent {
			return errors.New("forbidden binary is present on data-winn3")
		}
	}
	return nil
}

func validateRoleSpecificEvidence(value remoteEvidence, o options, step observationStep) error {
	needsWinn3 := step.role == "data-winn3" && (step.phase == phaseObserveBefore || step.phase == phaseObserveAfter)
	needsCover := step.role == "data-cover" && (step.phase == phaseObserveBefore || step.phase == phaseObserveAfter)
	needBefore, needMid, needAfter := journalPresence(o, step)
	if (value.Winn3Status != nil) != needsWinn3 {
		if value.Winn3Status != nil && step.role != "data-winn3" {
			return errors.New("cross-role evidence is forbidden")
		}
		if needsWinn3 {
			return errors.New("Winn3 status v2 evidence is missing")
		}
		if value.Winn3Status != nil {
			return errors.New("unexpected Winn3 status evidence")
		}
	}
	if needsWinn3 {
		if err := validateWinn3StatusV2(*value.Winn3Status, value.ProcessIdentity, value.BootID); err != nil {
			return err
		}
		if value.InterfaceCounters == nil || !exactTypedKeys(value.InterfaceCounters, []string{realWinn3Interface}) {
			return errors.New("Winn3 interface counter evidence is missing")
		}
		for name := range value.InterfaceCounters {
			if syntheticInterfaces[name] || name != realWinn3Interface || !interfacePattern.MatchString(name) {
				return errors.New("synthetic interface evidence is forbidden")
			}
		}
	} else if value.InterfaceCounters != nil {
		return errors.New("unexpected interface counter evidence")
	}
	if (value.AWGPeers != nil) != needsCover || (value.XrayStats != nil) != needsCover {
		if (value.AWGPeers != nil || value.XrayStats != nil) && step.role != "data-cover" {
			return errors.New("cross-role evidence is forbidden")
		}
		if needsCover {
			return errors.New("cover AWG or Xray evidence is missing")
		}
	}
	if needsCover {
		if err := validateAWGPeers(value.AWGPeers); err != nil {
			return err
		}
		if err := validateXrayStats(*value.XrayStats); err != nil {
			return err
		}
	}
	if step.role == "control" && (value.Winn3Status != nil || value.AWGPeers != nil || value.XrayStats != nil || value.InterfaceCounters != nil) {
		return errors.New("cross-role evidence is forbidden")
	}
	if step.role == "data-winn3" && (value.AWGPeers != nil || value.XrayStats != nil) {
		return errors.New("cross-role evidence is forbidden")
	}
	if step.role == "data-cover" && value.Winn3Status != nil {
		return errors.New("cross-role evidence is forbidden")
	}
	needsAcks := step.role == "control" && step.phase == phaseExercise && isAttemptAckAction(o.action)
	if !needsAcks && len(value.AttemptAcknowledgments) != 0 {
		return errors.New("unexpected protocol attempt acknowledgement")
	}
	if (value.AttemptJournalBefore != nil) != needBefore ||
		(value.AttemptJournalAfterAWG != nil) != needMid ||
		(value.AttemptJournalAfter != nil) != needAfter {
		return errors.New("protocol attempt journal presence mismatch")
	}
	if needBefore {
		if err := validateAttemptJournal(*value.AttemptJournalBefore); err != nil {
			return err
		}
	}
	if needMid {
		if err := validateAttemptJournal(*value.AttemptJournalAfterAWG); err != nil {
			return err
		}
	}
	if needAfter {
		if err := validateAttemptJournal(*value.AttemptJournalAfter); err != nil {
			return err
		}
	}
	return nil
}

func isAttemptAckAction(action string) bool {
	switch action {
	case "connect-primary", "connect-cover-awg", "connect-cover-xray",
		"probe-awg-block", "probe-winn3-block", "probe-cover-withdrawn":
		return true
	default:
		return false
	}
}

func journalPresence(o options, step observationStep) (needBefore, needMid, needAfter bool) {
	if step.role != "control" || step.phase != phaseExercise {
		return false, false, false
	}
	switch o.action {
	case "probe-awg-block", "probe-winn3-block":
		return true, true, true
	case "connect-primary", "connect-cover-awg", "connect-cover-xray", "probe-cover-withdrawn":
		return true, false, true
	default:
		return false, false, false
	}
}

func validateWinn3StatusV2(value winn3Status, process processIdentity, bootID string) error {
	if value.SchemaVersion != winn3StatusVersion || value.Contract != winn3StatusContract ||
		value.Event != "posture" || !value.Ready || !value.Forward || value.ProcessID == 0 ||
		value.ProcessID != process.PID || !processNoncePattern.MatchString(value.ProcessNonce) ||
		value.BootID != bootID || !bootIDPattern.MatchString(value.BootID) ||
		value.ProcessStartTicks == 0 || value.ProcessStartTicks != process.StarttimeTicks ||
		value.ObservedMonotonicNS == 0 || value.Sequence == 0 {
		return errors.New("Winn3 status v2 evidence is invalid")
	}
	if value.Contract == "winsvpn-gcp-proof-winn3-status-v1" || value.SchemaVersion == 1 {
		return errors.New("synthetic or stale Winn3 status is forbidden")
	}
	started, err := parseUTC(value.ProcessStartedUTC)
	if err != nil {
		return errors.New("Winn3 status v2 process start is invalid")
	}
	observed, err := parseUTC(value.ObservedUTC)
	if err != nil || !observed.After(started) {
		return errors.New("Winn3 status v2 observation time is invalid")
	}
	if value.Reflected > 0 && value.InnerPacketsDelivered == 0 {
		return errors.New("Winn3 status evidence is invalid or reflection-only")
	}
	return nil
}

func validateAWGPeers(peers []awgPeer) error {
	if len(peers) == 0 {
		return errors.New("AWG peer evidence is missing")
	}
	seen := map[string]struct{}{}
	for _, peer := range peers {
		if !awgKeyPattern.MatchString(peer.PublicKey) {
			return errors.New("AWG peer evidence is malformed")
		}
		if _, found := seen[peer.PublicKey]; found {
			return errors.New("duplicate protocol evidence is forbidden")
		}
		seen[peer.PublicKey] = struct{}{}
	}
	return nil
}

func validateXrayStats(value xrayUserStats) error {
	if !xrayUserPattern.MatchString(value.User) || strings.Contains(value.User, ">>>") ||
		strings.EqualFold(value.User, "inbound") {
		return errors.New("Xray StatsService exact-user evidence is missing or malformed")
	}
	return nil
}

func validateAttemptJournal(value attemptJournal) error {
	if value.SchemaVersion != 1 || value.Contract != attemptJournalContract || value.Events == nil {
		return errors.New("protocol attempt journal contract is invalid")
	}
	var lastMonotonic uint64
	var lastUTC time.Time
	for index, event := range value.Events {
		stamp, err := parseUTC(event.UTC)
		if err != nil || event.MonotonicNS == 0 || !instancePattern.MatchString(event.Node) ||
			event.Action == "" || event.CorrelationID == "" || event.Phase == "" ||
			event.Protocol == "" || event.Result == "" || event.SessionID == "" {
			return errors.New("protocol attempt journal event is invalid")
		}
		if index > 0 && (event.MonotonicNS <= lastMonotonic || !stamp.After(lastUTC)) {
			return errors.New("protocol attempt journal ordering is invalid")
		}
		lastMonotonic = event.MonotonicNS
		lastUTC = stamp
	}
	return nil
}

func exactTypedKeys[T any](value map[string]T, expected []string) bool {
	if value == nil || len(value) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, found := value[key]; !found {
			return false
		}
	}
	return true
}

func observationByRolePhase(values []validatedObservation, role, phase string) (validatedObservation, bool) {
	for _, item := range values {
		if item.step.role == role && item.step.phase == phase {
			return item, true
		}
	}
	return validatedObservation{}, false
}

func validateObservationSequence(o options, values []validatedObservation, ids fleetIDs, challenge string) error {
	if len(values) == 0 {
		return errors.New("proof observation plan is empty")
	}
	var lastEnd time.Time
	var lastMono uint64
	seenDigests := map[string]struct{}{}
	seenTransactions := map[string]struct{}{}
	firstStart := values[0].started
	for index, item := range values {
		if item.envelope.Challenge != challenge || item.evidence.Challenge != challenge ||
			item.transaction.Nonce != challenge {
			return errors.New("proof challenge mismatch")
		}
		wantID := instanceIDForRole(ids, item.step.role)
		if item.envelope.InstanceID != wantID || item.evidence.InstanceID != wantID {
			return errors.New("instance numeric id mismatch")
		}
		if _, found := seenDigests[item.envelope.StateSHA256]; found {
			return errors.New("duplicate protocol evidence is forbidden")
		}
		seenDigests[item.envelope.StateSHA256] = struct{}{}
		if _, found := seenTransactions[item.transaction.ResponseSHA256]; found {
			return errors.New("duplicate protocol evidence is forbidden")
		}
		seenTransactions[item.transaction.ResponseSHA256] = struct{}{}
		if index > 0 {
			if !item.started.After(lastEnd) || item.evidence.StartedMonotonicNS <= lastMono {
				return errors.New("observation sequence is stale or unordered")
			}
		}
		lastEnd = item.ended
		lastMono = item.evidence.EndedMonotonicNS
	}
	if values[len(values)-1].ended.Sub(firstStart) > commandTimeout {
		return errors.New("remote action time window is invalid")
	}
	if err := rejectUnstableInstanceIdentity(values); err != nil {
		return err
	}
	_ = o
	return nil
}

func rejectUnstableInstanceIdentity(values []validatedObservation) error {
	type identity struct {
		boot, remote, broker, pid, exe, ticks, comm string
	}
	first := map[string]identity{}
	for _, item := range values {
		current := identity{
			boot: item.evidence.BootID, remote: item.helpers["remote"],
			broker: item.helpers["attempt_broker"],
			pid:    strconv.FormatUint(item.evidence.ProcessIdentity.PID, 10),
			exe:    item.evidence.ProcessIdentity.ExeSHA256,
			ticks:  strconv.FormatUint(item.evidence.ProcessIdentity.StarttimeTicks, 10),
			comm:   item.evidence.ProcessIdentity.Comm,
		}
		previous, found := first[item.step.role]
		if !found {
			first[item.step.role] = current
			continue
		}
		if previous != current {
			return errors.New("instance boot, process, or helper identity is stale")
		}
	}
	return nil
}

func validateProofClosure(o options, values []validatedObservation) error {
	requireAttemptBroker := isAttemptAckAction(o.action)
	reviewed := ""
	if requireAttemptBroker {
		var err error
		reviewed, err = reviewedAttemptBrokerIdentity()
		if err != nil {
			return errors.New("proof closure is not bound to the reviewed attempt-broker identity")
		}
	}
	observedBroker := 0
	for _, item := range values {
		digest, found := item.helpers["attempt_broker"]
		if !found {
			continue
		}
		if !requireAttemptBroker {
			return errors.New("proof closure contains an unexpected attempt-broker identity")
		}
		observedBroker++
		if item.step.role != "control" || item.step.phase != phaseExercise ||
			digest != reviewed || digest == strings.Repeat("0", 64) {
			return errors.New("proof closure is not bound to the reviewed attempt-broker identity")
		}
	}
	if requireAttemptBroker && observedBroker != 1 {
		return errors.New("proof closure is not bound to the reviewed attempt-broker identity")
	}
	return nil
}

func assembleActionData(o options, values []validatedObservation, ids fleetIDs, challenge string) (any, error) {
	switch o.action {
	case "route-decision":
		return assembleRouteDecision(o, values)
	case "connect-primary":
		return assembleConnectPrimary(o, values, challenge)
	case "connect-cover-awg":
		return assembleConnectCoverAWG(o, values)
	case "connect-cover-xray":
		return assembleConnectCoverXray(o, values)
	case "inject-awg-block":
		return assembleControlState(values, "negative-awg-block", "protocol", "awg", "blocked")
	case "probe-awg-block":
		return assembleAWGFirstFallback(o, values)
	case "restore-awg":
		return assembleControlState(values, "negative-awg-block", "protocol", "awg", "restored")
	case "inject-winn3-block":
		return assembleControlState(values, "negative-winn3-block", "protocol", "winn3", "blocked")
	case "probe-winn3-block":
		return assembleWinn3Block(o, values)
	case "withdraw-cover":
		return assembleControlState(values, "negative-cover-withdrawn", "node", o.coverInstance, "withdrawn")
	case "probe-cover-withdrawn":
		return assembleCoverWithdrawn(o, values)
	case "restore-cover":
		return assembleControlState(values, "negative-cover-withdrawn", "node", o.coverInstance, "restored")
	case "restore-winn3":
		return assembleControlState(values, "negative-winn3-block", "protocol", "winn3", "restored")
	case "teardown-check":
		exercise, ok := observationByRolePhase(values, "control", phaseExercise)
		if !ok {
			return nil, errors.New("teardown observation is missing")
		}
		var data map[string]any
		if _, err := decodeExactObject(exercise.envelope.Data, []string{
			"expected_resources", "observed_resources", "unexpected_targets", "foreign_resource_ids",
			"credential_files_read", "production_resources_touched",
		}, &data); err != nil {
			return nil, errors.New("teardown data shape is invalid")
		}
		if err := validateTeardownData(o, data); err != nil {
			return nil, err
		}
		return data, nil
	default:
		return nil, errors.New("unsupported action data")
	}
}

func assembleRouteDecision(o options, values []validatedObservation) (any, error) {
	exercise, ok := observationByRolePhase(values, "control", phaseExercise)
	if !ok {
		return nil, errors.New("route decision observation is missing")
	}
	var data struct {
		ServedCarrier    string `json:"served_carrier"`
		DescriptorNode   string `json:"descriptor_node"`
		SelectedNode     string `json:"selected_node"`
		DescriptorSHA256 string `json:"descriptor_sha256"`
		SignatureState   string `json:"signature_state"`
		CanaryState      string `json:"canary_state"`
	}
	if _, err := decodeExactObject(exercise.envelope.Data, []string{
		"served_carrier", "descriptor_node", "selected_node", "descriptor_sha256", "signature_state", "canary_state",
	}, &data); err != nil ||
		data.ServedCarrier != "winn3" || data.DescriptorNode != o.winn3Instance || data.SelectedNode != o.winn3Instance ||
		data.SignatureState != "verified" || data.CanaryState != "reachable" || !shaPattern.MatchString(data.DescriptorSHA256) {
		return nil, errors.New("route decision did not prove signed Winn3 node binding")
	}
	return data, nil
}

func assembleConnectPrimary(o options, values []validatedObservation, challenge string) (any, error) {
	before, okBefore := observationByRolePhase(values, "data-winn3", phaseObserveBefore)
	after, okAfter := observationByRolePhase(values, "data-winn3", phaseObserveAfter)
	exercise, okExercise := observationByRolePhase(values, "control", phaseExercise)
	if !okBefore || !okAfter || !okExercise || before.evidence.Winn3Status == nil || after.evidence.Winn3Status == nil {
		return nil, errors.New("primary connection did not prove Winn3 carried traffic")
	}
	if before.evidence.Winn3Status.ProcessNonce != after.evidence.Winn3Status.ProcessNonce ||
		before.evidence.Winn3Status.BootID != after.evidence.Winn3Status.BootID ||
		before.evidence.Winn3Status.ProcessStartTicks != after.evidence.Winn3Status.ProcessStartTicks ||
		before.evidence.Winn3Status.ProcessStartedUTC != after.evidence.Winn3Status.ProcessStartedUTC ||
		before.evidence.Winn3Status.ProcessID != after.evidence.Winn3Status.ProcessID ||
		after.evidence.Winn3Status.ObservedMonotonicNS <= before.evidence.Winn3Status.ObservedMonotonicNS ||
		after.evidence.Winn3Status.Sequence <= before.evidence.Winn3Status.Sequence {
		return nil, errors.New("Winn3 status v2 nonce/start/sequence delta is invalid")
	}
	beforeObserved, _ := parseUTC(before.evidence.Winn3Status.ObservedUTC)
	afterObserved, _ := parseUTC(after.evidence.Winn3Status.ObservedUTC)
	if !afterObserved.After(beforeObserved) || afterObserved.Before(exercise.started) || afterObserved.After(after.ended) {
		return nil, errors.New("Winn3 status v2 observation is stale")
	}
	if after.evidence.Winn3Status.InnerPacketsDelivered <= before.evidence.Winn3Status.InnerPacketsDelivered ||
		after.evidence.Winn3Status.RXDeviceWrites <= before.evidence.Winn3Status.RXDeviceWrites {
		return nil, errors.New("stale positive Winn3 status was accepted")
	}
	delivered := after.evidence.Winn3Status.InnerPacketsDelivered - before.evidence.Winn3Status.InnerPacketsDelivered
	writes := after.evidence.Winn3Status.RXDeviceWrites - before.evidence.Winn3Status.RXDeviceWrites
	rx, tx, ok := positiveCounterDelta(before.evidence.InterfaceCounters, after.evidence.InterfaceCounters, realWinn3Interface)
	if !ok || delivered == 0 || writes == 0 || delivered > writes || rx < writes {
		return nil, errors.New("primary status and interface evidence are not cross-bound")
	}
	if err := validateAcknowledgements(exercise.evidence.AttemptAcknowledgments, o, []proofAttempt{{"winn3", o.winn3Instance, "connected"}}); err != nil {
		return nil, err
	}
	if _, err := reconstructAttemptAppend(exercise.evidence.AttemptJournalBefore, exercise.evidence.AttemptJournalAfter, []expectedAttemptStep{
		{"winn3", "started", "pending", o.winn3Instance},
		{"winn3", "finished", "connected", o.winn3Instance},
	}, o, exercise); err != nil {
		return nil, err
	}
	if exercise.transaction.Nonce != challenge || exercise.transaction.Protocol != "winn3" {
		return nil, errors.New("exact transaction response is invalid")
	}
	reconstructed := map[string]any{
		"attempts": []proofAttempt{{Protocol: "winn3", Node: o.winn3Instance, Result: "connected"}},
		"bytes_rx": rx, "bytes_tx": tx, "interface": realWinn3Interface,
		"status_delta": statusDelta{InnerPacketsDelivered: delivered, RXDeviceWrites: writes},
	}
	helperData := map[string]any{
		"attempts": []proofAttempt{{Protocol: "winn3", Node: o.winn3Instance, Result: "connected"}},
	}
	if err := requireHelperDataMatch(exercise.envelope.Data, helperData); err != nil {
		return nil, err
	}
	return reconstructed, nil
}

func assembleConnectCoverAWG(o options, values []validatedObservation) (any, error) {
	before, okBefore := observationByRolePhase(values, "data-cover", phaseObserveBefore)
	after, okAfter := observationByRolePhase(values, "data-cover", phaseObserveAfter)
	exercise, okExercise := observationByRolePhase(values, "control", phaseExercise)
	if !okBefore || !okAfter || !okExercise || o.coverInstance == o.winn3Instance {
		return nil, errors.New("cover AWG connection evidence is invalid")
	}
	if _, err := reconstructAttemptAppend(exercise.evidence.AttemptJournalBefore, exercise.evidence.AttemptJournalAfter, []expectedAttemptStep{
		{"awg", "started", "pending", o.coverInstance},
		{"awg", "finished", "connected", o.coverInstance},
	}, o, exercise); err != nil {
		return nil, err
	}
	if err := validateAcknowledgements(exercise.evidence.AttemptAcknowledgments, o, []proofAttempt{{"awg", o.coverInstance, "connected"}}); err != nil {
		return nil, err
	}
	handshake, err := requireAWGPeerDelta(before.evidence.AWGPeers, after.evidence.AWGPeers, exercise.started, exercise.ended, true)
	if err != nil {
		return nil, err
	}
	reconstructed := map[string]any{
		"protocol": "awg", "node": o.coverInstance, "result": "connected",
		"latest_handshake_utc": handshake,
	}
	helperData := map[string]any{"protocol": "awg", "node": o.coverInstance, "result": "connected"}
	if err := requireHelperDataMatch(exercise.envelope.Data, helperData); err != nil {
		return nil, err
	}
	return reconstructed, nil
}

func assembleConnectCoverXray(o options, values []validatedObservation) (any, error) {
	before, okBefore := observationByRolePhase(values, "data-cover", phaseObserveBefore)
	after, okAfter := observationByRolePhase(values, "data-cover", phaseObserveAfter)
	exercise, okExercise := observationByRolePhase(values, "control", phaseExercise)
	if !okBefore || !okAfter || !okExercise || o.coverInstance == o.winn3Instance ||
		before.evidence.XrayStats == nil || after.evidence.XrayStats == nil {
		return nil, errors.New("cover Xray connection evidence is invalid")
	}
	if _, err := reconstructAttemptAppend(exercise.evidence.AttemptJournalBefore, exercise.evidence.AttemptJournalAfter, []expectedAttemptStep{
		{"xray", "started", "pending", o.coverInstance},
		{"xray", "finished", "connected", o.coverInstance},
	}, o, exercise); err != nil {
		return nil, err
	}
	if err := validateAcknowledgements(exercise.evidence.AttemptAcknowledgments, o, []proofAttempt{{"xray", o.coverInstance, "connected"}}); err != nil {
		return nil, err
	}
	if before.evidence.XrayStats.User != after.evidence.XrayStats.User ||
		after.evidence.XrayStats.Uplink <= before.evidence.XrayStats.Uplink ||
		after.evidence.XrayStats.Downlink <= before.evidence.XrayStats.Downlink {
		return nil, errors.New("cover Xray connection evidence is invalid")
	}
	reconstructed := map[string]any{"protocol": "xray", "node": o.coverInstance, "result": "connected"}
	if err := requireHelperDataMatch(exercise.envelope.Data, reconstructed); err != nil {
		return nil, err
	}
	return reconstructed, nil
}

func assembleControlState(values []validatedObservation, controlID, identityKey, identityValue, state string) (any, error) {
	if len(values) != 1 || values[0].step.phase != phaseMutate {
		return nil, errors.New("negative-control state data is invalid")
	}
	return validateControlStateData(values[0].envelope.Data, controlID, identityKey, identityValue, state)
}

func assembleAWGFirstFallback(o options, values []validatedObservation) (any, error) {
	before, okBefore := observationByRolePhase(values, "data-cover", phaseObserveBefore)
	after, okAfter := observationByRolePhase(values, "data-cover", phaseObserveAfter)
	exercise, okExercise := observationByRolePhase(values, "control", phaseExercise)
	if !okBefore || !okAfter || !okExercise || o.coverInstance == o.winn3Instance ||
		exercise.evidence.AttemptJournalBefore == nil || exercise.evidence.AttemptJournalAfterAWG == nil ||
		exercise.evidence.AttemptJournalAfter == nil {
		return nil, errors.New("AWG negative control did not prove Xray fallback")
	}
	beforeEvents := exercise.evidence.AttemptJournalBefore.Events
	afterAWGEvents := exercise.evidence.AttemptJournalAfterAWG.Events
	afterEvents := exercise.evidence.AttemptJournalAfter.Events
	if len(afterAWGEvents) != len(beforeEvents)+2 || len(afterEvents) != len(afterAWGEvents)+2 ||
		!attemptEventsEqual(afterAWGEvents[:len(beforeEvents)], beforeEvents) ||
		!attemptEventsEqual(afterEvents[:len(afterAWGEvents)], afterAWGEvents) {
		return nil, errors.New("protocol attempt journal did not append atomically")
	}
	observed := append(append([]attemptEvent{}, afterAWGEvents[len(beforeEvents):]...), afterEvents[len(afterAWGEvents):]...)
	expected := []struct{ protocol, phase, result string }{
		{"awg", "started", "pending"},
		{"awg", "finished", "failed"},
		{"xray", "started", "pending"},
		{"xray", "finished", "connected"},
	}
	lastMonotonic := exercise.evidence.StartedMonotonicNS
	lastUTC := exercise.started
	for index, event := range observed {
		stamp, err := parseUTC(event.UTC)
		if err != nil || event.Action != o.action || event.CorrelationID != o.correlationID ||
			event.SessionID != o.sessionID || event.Node != o.coverInstance || event.Protocol != expected[index].protocol ||
			event.Phase != expected[index].phase || event.Result != expected[index].result ||
			event.MonotonicNS <= lastMonotonic || event.MonotonicNS >= exercise.evidence.EndedMonotonicNS ||
			!stamp.After(lastUTC) || !stamp.Before(exercise.ended) {
			return nil, errors.New("AWG-first fallback attempt ordering is invalid")
		}
		lastMonotonic, lastUTC = event.MonotonicNS, stamp
	}
	awgStarted, _ := parseUTC(observed[0].UTC)
	awgEnded, _ := parseUTC(observed[1].UTC)
	if _, err := requireAWGPeerDelta(before.evidence.AWGPeers, after.evidence.AWGPeers, awgStarted, awgEnded, false); err != nil {
		return nil, err
	}
	if before.evidence.XrayStats == nil || after.evidence.XrayStats == nil ||
		before.evidence.XrayStats.User != after.evidence.XrayStats.User ||
		after.evidence.XrayStats.Downlink <= before.evidence.XrayStats.Downlink ||
		after.evidence.XrayStats.Uplink <= before.evidence.XrayStats.Uplink {
		return nil, errors.New("Xray fallback counters are not reconstructable")
	}
	rx := after.evidence.XrayStats.Downlink - before.evidence.XrayStats.Downlink
	tx := after.evidence.XrayStats.Uplink - before.evidence.XrayStats.Uplink
	if err := validateAcknowledgements(exercise.evidence.AttemptAcknowledgments, o, []proofAttempt{
		{"awg", o.coverInstance, "blocked"}, {"xray", o.coverInstance, "connected"},
	}); err != nil {
		return nil, err
	}
	reconstructed := map[string]any{
		"control_id": "negative-awg-block",
		"attempts": []proofAttempt{
			{Protocol: "awg", Node: o.coverInstance, Result: "blocked"},
			{Protocol: "xray", Node: o.coverInstance, Result: "connected"},
		},
		"attempt_events": observed, "awg_interface": realAWGInterface,
		"xray_bytes_rx": rx, "xray_bytes_tx": tx,
	}
	helperData := map[string]any{
		"control_id": "negative-awg-block",
		"attempts": []proofAttempt{
			{Protocol: "awg", Node: o.coverInstance, Result: "blocked"},
			{Protocol: "xray", Node: o.coverInstance, Result: "connected"},
		},
		"attempt_events": observed,
	}
	if err := requireHelperDataMatch(exercise.envelope.Data, helperData); err != nil {
		return nil, err
	}
	return reconstructed, nil
}

func assembleWinn3Block(o options, values []validatedObservation) (any, error) {
	winn3Before, okWB := observationByRolePhase(values, "data-winn3", phaseObserveBefore)
	winn3After, okWA := observationByRolePhase(values, "data-winn3", phaseObserveAfter)
	coverBefore, okCB := observationByRolePhase(values, "data-cover", phaseObserveBefore)
	coverAfter, okCA := observationByRolePhase(values, "data-cover", phaseObserveAfter)
	exercise, okE := observationByRolePhase(values, "control", phaseExercise)
	if !okWB || !okWA || !okCB || !okCA || !okE || o.coverInstance == o.winn3Instance ||
		winn3Before.evidence.Winn3Status == nil || winn3After.evidence.Winn3Status == nil ||
		exercise.evidence.AttemptJournalBefore == nil || exercise.evidence.AttemptJournalAfterAWG == nil ||
		exercise.evidence.AttemptJournalAfter == nil {
		return nil, errors.New("Winn3 negative control did not prove AWG cover fallback")
	}
	if winn3After.evidence.Winn3Status.InnerPacketsDelivered != winn3Before.evidence.Winn3Status.InnerPacketsDelivered ||
		winn3After.evidence.Winn3Status.RXDeviceWrites != winn3Before.evidence.Winn3Status.RXDeviceWrites ||
		winn3Before.evidence.InterfaceCounters[realWinn3Interface] != winn3After.evidence.InterfaceCounters[realWinn3Interface] {
		return nil, errors.New("Winn3 negative control did not prove AWG cover fallback")
	}
	winn3Events, err := reconstructAttemptAppend(exercise.evidence.AttemptJournalBefore, exercise.evidence.AttemptJournalAfterAWG, []expectedAttemptStep{
		{"winn3", "started", "pending", o.winn3Instance},
		{"winn3", "finished", "failed", o.winn3Instance},
	}, o, exercise)
	if err != nil {
		return nil, err
	}
	awgEvents, err := reconstructAttemptAppend(exercise.evidence.AttemptJournalAfterAWG, exercise.evidence.AttemptJournalAfter, []expectedAttemptStep{
		{"awg", "started", "pending", o.coverInstance},
		{"awg", "finished", "connected", o.coverInstance},
	}, o, exercise)
	if err != nil {
		return nil, err
	}
	winn3Ended, err := parseUTC(winn3Events[len(winn3Events)-1].UTC)
	if err != nil {
		return nil, errors.New("Winn3-first fallback attempt order is invalid")
	}
	awgStarted, err := parseUTC(awgEvents[0].UTC)
	if err != nil || winn3Events[len(winn3Events)-1].MonotonicNS >= awgEvents[0].MonotonicNS ||
		!winn3Ended.Before(awgStarted) {
		return nil, errors.New("Winn3-first fallback attempt order is invalid")
	}
	awgEnded, err := parseUTC(awgEvents[len(awgEvents)-1].UTC)
	if err != nil {
		return nil, errors.New("Winn3 negative control did not prove AWG cover fallback")
	}
	if _, err := requireAWGPeerDelta(coverBefore.evidence.AWGPeers, coverAfter.evidence.AWGPeers, awgStarted, awgEnded, true); err != nil {
		return nil, err
	}
	observed := append(append([]attemptEvent{}, winn3Events...), awgEvents...)
	if err := validateAcknowledgements(exercise.evidence.AttemptAcknowledgments, o, []proofAttempt{
		{"winn3", o.winn3Instance, "blocked"}, {"awg", o.coverInstance, "connected"},
	}); err != nil {
		return nil, err
	}
	reconstructed := map[string]any{
		"control_id": "negative-winn3-block",
		"attempts": []proofAttempt{
			{Protocol: "winn3", Node: o.winn3Instance, Result: "blocked"},
			{Protocol: "awg", Node: o.coverInstance, Result: "connected"},
		},
		"attempt_events": observed,
	}
	if err := requireHelperDataMatch(exercise.envelope.Data, reconstructed); err != nil {
		return nil, err
	}
	return reconstructed, nil
}

func assembleCoverWithdrawn(o options, values []validatedObservation) (any, error) {
	winn3Before, okWB := observationByRolePhase(values, "data-winn3", phaseObserveBefore)
	winn3After, okWA := observationByRolePhase(values, "data-winn3", phaseObserveAfter)
	coverBefore, okCB := observationByRolePhase(values, "data-cover", phaseObserveBefore)
	coverAfter, okCA := observationByRolePhase(values, "data-cover", phaseObserveAfter)
	exercise, okE := observationByRolePhase(values, "control", phaseExercise)
	if !okWB || !okWA || !okCB || !okCA || !okE || o.coverInstance == o.winn3Instance ||
		exercise.evidence.AttemptJournalBefore == nil || exercise.evidence.AttemptJournalAfterAWG != nil ||
		exercise.evidence.AttemptJournalAfter == nil {
		return nil, errors.New("cover withdrawal did not prove fail-closed downgrade refusal")
	}
	if winn3Before.evidence.Winn3Status == nil || winn3After.evidence.Winn3Status == nil ||
		winn3After.evidence.Winn3Status.InnerPacketsDelivered != winn3Before.evidence.Winn3Status.InnerPacketsDelivered ||
		winn3After.evidence.Winn3Status.RXDeviceWrites != winn3Before.evidence.Winn3Status.RXDeviceWrites {
		return nil, errors.New("cover withdrawal did not prove fail-closed downgrade refusal")
	}
	if err := requireUnchangedAWGPeers(coverBefore.evidence.AWGPeers, coverAfter.evidence.AWGPeers); err != nil {
		return nil, err
	}
	if coverBefore.evidence.XrayStats == nil || coverAfter.evidence.XrayStats == nil ||
		*coverBefore.evidence.XrayStats != *coverAfter.evidence.XrayStats {
		return nil, errors.New("cover withdrawal did not prove fail-closed downgrade refusal")
	}
	beforeEvents := exercise.evidence.AttemptJournalBefore.Events
	afterEvents := exercise.evidence.AttemptJournalAfter.Events
	if len(afterEvents) != len(beforeEvents)+2 || !attemptEventsEqual(afterEvents[:len(beforeEvents)], beforeEvents) {
		return nil, errors.New("protocol attempt journal did not append atomically")
	}
	observed := append([]attemptEvent{}, afterEvents[len(beforeEvents):]...)
	expected := []struct{ phase, result string }{{"started", "pending"}, {"finished", "failed"}}
	lastMonotonic := exercise.evidence.StartedMonotonicNS
	lastUTC := exercise.started
	for index, event := range observed {
		stamp, err := parseUTC(event.UTC)
		if err != nil || event.Action != o.action || event.CorrelationID != o.correlationID ||
			event.SessionID != o.sessionID || event.Node != o.winn3Instance || event.Protocol != "winn3" ||
			event.Phase != expected[index].phase || event.Result != expected[index].result ||
			event.MonotonicNS <= lastMonotonic || event.MonotonicNS >= exercise.evidence.EndedMonotonicNS ||
			!stamp.After(lastUTC) || !stamp.Before(exercise.ended) {
			return nil, errors.New("cover withdrawal attempt evidence is invalid")
		}
		lastMonotonic, lastUTC = event.MonotonicNS, stamp
	}
	if err := validateAcknowledgements(exercise.evidence.AttemptAcknowledgments, o, []proofAttempt{
		{"winn3", o.winn3Instance, "blocked"},
	}); err != nil {
		return nil, err
	}
	reconstructed := map[string]any{
		"control_id":     "negative-cover-withdrawn",
		"attempts":       []proofAttempt{{Protocol: "winn3", Node: o.winn3Instance, Result: "blocked"}},
		"attempt_events": observed, "refusal_code": "same_node_downgrade_refused",
		"same_node_downgrade_attempts": uint64(0),
	}
	if err := requireHelperDataMatch(exercise.envelope.Data, reconstructed); err != nil {
		return nil, err
	}
	return reconstructed, nil
}

func requireHelperDataMatch(raw json.RawMessage, reconstructed any) error {
	got, err := canonicalJSONDigest(raw)
	if err != nil {
		return errors.New("remote action data is invalid")
	}
	encoded, err := json.Marshal(reconstructed)
	if err != nil {
		return err
	}
	want, err := canonicalJSONDigest(encoded)
	if err != nil || got != want {
		return errors.New("helper action data does not match reconstructed evidence")
	}
	return nil
}

type expectedAttemptStep struct {
	protocol, phase, result, node string
}

func reconstructAttemptAppend(
	before, after *attemptJournal,
	expected []expectedAttemptStep,
	o options,
	exercise validatedObservation,
) ([]attemptEvent, error) {
	if before == nil || after == nil {
		return nil, errors.New("timestamped protocol attempts are absent")
	}
	beforeEvents := before.Events
	afterEvents := after.Events
	if len(afterEvents) != len(beforeEvents)+len(expected) ||
		!attemptEventsEqual(afterEvents[:len(beforeEvents)], beforeEvents) {
		return nil, errors.New("protocol attempt journal did not append atomically")
	}
	observed := append([]attemptEvent{}, afterEvents[len(beforeEvents):]...)
	lastMonotonic := exercise.evidence.StartedMonotonicNS
	lastUTC := exercise.started
	for index, event := range observed {
		stamp, err := parseUTC(event.UTC)
		want := expected[index]
		if err != nil || event.Action != o.action || event.CorrelationID != o.correlationID ||
			event.SessionID != o.sessionID || event.Node != want.node ||
			event.Protocol != want.protocol || event.Phase != want.phase ||
			event.Result != want.result || event.MonotonicNS <= lastMonotonic ||
			event.MonotonicNS >= exercise.evidence.EndedMonotonicNS ||
			!stamp.After(lastUTC) || !stamp.Before(exercise.ended) {
			return nil, errors.New("protocol attempt journal reconstruction is invalid")
		}
		lastMonotonic, lastUTC = event.MonotonicNS, stamp
	}
	return observed, nil
}

func validateControlStateData(raw json.RawMessage, controlID, identityKey, identityValue, state string) (map[string]any, error) {
	var data map[string]any
	if _, err := decodeExactObject(raw, []string{"control_id", identityKey, "state"}, &data); err != nil ||
		data["control_id"] != controlID || data[identityKey] != identityValue || data["state"] != state {
		return nil, errors.New("negative-control state data is invalid")
	}
	return data, nil
}

func validateAcknowledgements(values []protocolAttemptAck, o options, expected []proofAttempt) error {
	if len(values) != len(expected) {
		return errors.New("protocol attempt acknowledgement count mismatch")
	}
	for index, value := range values {
		if value.Action != o.action || value.Contract != attemptAckContract || value.CorrelationID != o.correlationID ||
			value.Node != expected[index].Node || value.Protocol != expected[index].Protocol ||
			value.SessionID != o.sessionID || value.State != "completed" {
			return errors.New("protocol attempt acknowledgement identity mismatch")
		}
	}
	return nil
}

func attemptEventsEqual(actual, expected []attemptEvent) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func positiveCounterDelta(before, after map[string]netCount, name string) (uint64, uint64, bool) {
	left, foundBefore := before[name]
	right, foundAfter := after[name]
	if !foundBefore || !foundAfter || right.RX < left.RX || right.TX < left.TX {
		return 0, 0, false
	}
	rx, tx := right.RX-left.RX, right.TX-left.TX
	return rx, tx, rx > 0 && tx > 0
}

func requireAWGPeerDelta(before, after []awgPeer, started, ended time.Time, requireIncrease bool) (string, error) {
	if err := validateAWGPeers(before); err != nil {
		return "", err
	}
	if err := validateAWGPeers(after); err != nil {
		return "", err
	}
	beforeByKey := map[string]awgPeer{}
	for _, peer := range before {
		beforeByKey[peer.PublicKey] = peer
	}
	var handshakeUTC string
	matched := false
	for _, peer := range after {
		previous, found := beforeByKey[peer.PublicKey]
		if !found || peer.RX < previous.RX || peer.TX < previous.TX {
			return "", errors.New("AWG attempt interface evidence is absent or regressed")
		}
		stamp := time.Unix(int64(peer.LatestHandshakeUnix), 0).UTC()
		inWindow := peer.LatestHandshakeUnix > 0 && !stamp.Before(started) && !stamp.After(ended)
		if requireIncrease {
			if peer.RX == previous.RX || peer.TX == previous.TX || !inWindow {
				continue
			}
			handshakeUTC = stamp.Format("2006-01-02T15:04:05Z")
			matched = true
			continue
		}
		if inWindow {
			return "", errors.New("AWG failure is contradicted by an in-window handshake")
		}
		matched = true
	}
	if !matched || (requireIncrease && handshakeUTC == "") {
		if requireIncrease {
			return "", errors.New("cover AWG handshake or interface evidence is invalid")
		}
		return "", errors.New("AWG attempt interface evidence is absent or regressed")
	}
	return handshakeUTC, nil
}

func requireUnchangedAWGPeers(before, after []awgPeer) error {
	if len(before) != len(after) {
		return errors.New("cover withdrawal did not prove fail-closed downgrade refusal")
	}
	afterByKey := map[string]awgPeer{}
	for _, peer := range after {
		afterByKey[peer.PublicKey] = peer
	}
	for _, peer := range before {
		got, found := afterByKey[peer.PublicKey]
		if !found || got != peer {
			return errors.New("cover withdrawal did not prove fail-closed downgrade refusal")
		}
	}
	return nil
}

func validateTeardownData(o options, data map[string]any) error {
	if !exactKeys(data, []string{"expected_resources", "observed_resources", "unexpected_targets", "foreign_resource_ids", "credential_files_read", "production_resources_touched"}) {
		return errors.New("teardown data keys mismatch")
	}
	expected := resourceIdentity(o)
	for _, key := range []string{"expected_resources", "observed_resources"} {
		encoded, err := json.Marshal(data[key])
		if err != nil {
			return errors.New("teardown resource identity is malformed")
		}
		var actual map[string]any
		if err := strictDecode(encoded, &actual); err != nil || !resourceIdentityEqual(actual, expected) {
			return errors.New("teardown resource identity mismatch")
		}
	}
	for _, key := range []string{"unexpected_targets", "foreign_resource_ids", "credential_files_read", "production_resources_touched"} {
		values, ok := data[key].([]any)
		if !ok || len(values) != 0 {
			return fmt.Errorf("teardown %s must be empty", key)
		}
	}
	return nil
}

func resourceIdentity(o options) map[string][]string {
	subnets := []string{
		"pf-" + o.fleetID + "-sn-control",
		"pf-" + o.fleetID + "-sn-data-winn3",
		"pf-" + o.fleetID + "-sn-data-cover",
	}
	firewalls := []string{
		"pf-" + o.fleetID + "-admin-ssh", "pf-" + o.fleetID + "-control-http",
		"pf-" + o.fleetID + "-winn3-in", "pf-" + o.fleetID + "-cover-in",
	}
	sort.Strings(firewalls)
	return map[string][]string{
		"instances": {o.controlInstance, o.winn3Instance, o.coverInstance},
		"network":   {"pf-" + o.fleetID + "-net"},
		"subnets":   subnets,
		"firewalls": firewalls,
	}
}

func resourceIdentityEqual(actual map[string]any, expected map[string][]string) bool {
	if !exactKeys(actual, []string{"instances", "network", "subnets", "firewalls"}) {
		return false
	}
	for key, wanted := range expected {
		if key == "network" {
			if actual[key] != wanted[0] {
				return false
			}
			continue
		}
		raw, ok := actual[key].([]any)
		if !ok || len(raw) != len(wanted) {
			return false
		}
		for index := range wanted {
			if raw[index] != wanted[index] {
				return false
			}
		}
	}
	return true
}

func regionOf(zone string) string {
	index := strings.LastIndex(zone, "-")
	return zone[:index]
}

func exactKeys(value map[string]any, expected []string) bool {
	if len(value) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, found := value[key]; !found {
			return false
		}
	}
	return true
}

func parseUTC(value string) (time.Time, error) {
	if !utcPattern.MatchString(value) {
		return time.Time{}, errors.New("timestamp must use canonical UTC Z form")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC {
		return time.Time{}, errors.New("timestamp is not canonical UTC")
	}
	return parsed, nil
}

func writeJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
