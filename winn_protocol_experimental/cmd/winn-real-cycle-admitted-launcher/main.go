// Command winn-real-cycle-admitted-launcher is the only E3 write/exec
// boundary. It validates E2, publishes a pending intent durably, and launches
// only the preflight adapter. It has no matrix or run mode.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

const (
	bindingFileName = "controller-binding.json"
	intentFileName  = "controller-intent.json"
	resultFileName  = "adapter-preflight-result.json"
	adapterSchema   = "winn-real-cycle-admitted-adapter-preflight/v2"
	maxResultBytes  = 256 << 10
)

type durableRuntime interface {
	PublishExclusive(string, []byte) (*os.File, error)
	SpawnPreflight(
		*os.File, *os.File, []string,
	) ([]byte, error)
	Close() error
}

type adapterResult struct {
	Schema                   string `json:"schema"`
	Status                   string `json:"status"`
	Mode                     string `json:"mode"`
	CycleID                  string `json:"cycle_id"`
	AttemptID                string `json:"attempt_id"`
	TopologyID               string `json:"topology_id"`
	ControllerBindingDigest  string `json:"controller_binding_digest"`
	ControllerIntentDigest   string `json:"controller_intent_digest"`
	AdmissionBundleSHA256    string `json:"admission_bundle_sha256"`
	DispatchAuthorized       bool   `json:"dispatch_authorized"`
	ExternalTopologyExecuted bool   `json:"external_topology_executed"`
	MatrixExecuted           bool   `json:"matrix_executed"`
	ProviderAccess           bool   `json:"provider_access"`
	CredentialAccess         bool   `json:"credential_access"`
	Mutation                 string `json:"mutation"`
	Authority                bool   `json:"authority"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func run(arguments []string, output io.Writer) error {
	return runWith(
		arguments,
		output,
		realcycle.LoadControllerBindingInput,
		realcycle.ValidateAdmission,
		newProductionRuntime,
	)
}

func runWith(
	arguments []string,
	output io.Writer,
	loadInput func(string) (realcycle.ControllerBindingInput, error),
	validateAdmission func(string, string, string) (realcycle.AdmissionResult, error),
	newRuntime func(string, string, string, time.Duration) (durableRuntime, error),
) (returnErr error) {
	flags := flag.NewFlagSet(
		"winn-real-cycle-admitted-launcher", flag.ContinueOnError,
	)
	flags.SetOutput(io.Discard)
	var admissionPath, trustPath, topologyPath, contractPath string
	var stateDirectory, adapterPath, mode string
	var timeout time.Duration
	flags.StringVar(&admissionPath, "admission", "", "immutable E2 admission directory")
	flags.StringVar(&trustPath, "trust", "", "accepted public trust bundle")
	flags.StringVar(&topologyPath, "topology", "", "accepted E0 topology bundle")
	flags.StringVar(&contractPath, "controller-contract", "", "canonical E3 contract")
	flags.StringVar(&stateDirectory, "state-dir", "", "existing private empty E3 state directory")
	flags.StringVar(&adapterPath, "adapter", "", "exact admitted adapter executable")
	flags.StringVar(&mode, "mode", "preflight", "only preflight is supported")
	flags.DurationVar(&timeout, "timeout", 30*time.Second, "bounded adapter deadline")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if mode != "preflight" {
		return errors.New("execution is unsupported; mode must be preflight")
	}
	if contractPath == "" || stateDirectory == "" || adapterPath == "" {
		return errors.New("controller-contract, state-dir, and adapter are required")
	}
	if timeout <= 0 || timeout > 5*time.Minute {
		return errors.New("timeout must be positive and at most five minutes")
	}

	// E2 and the controller contract are validated before the write/exec
	// runtime is opened. Failure above or here therefore has zero side effects.
	input, err := loadInput(contractPath)
	if err != nil {
		return err
	}
	admission, err := validateAdmission(admissionPath, trustPath, topologyPath)
	if err != nil {
		return err
	}
	binding, bindingBytes, err := realcycle.NewControllerCycleBinding(
		admission, input,
	)
	if err != nil {
		return err
	}
	intent, intentBytes, err := realcycle.NewControllerCycleIntent(bindingBytes)
	if err != nil {
		return err
	}

	runtimeBoundary, err := newRuntime(
		stateDirectory, adapterPath, binding.RunnerSHA256, timeout,
	)
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, runtimeBoundary.Close())
	}()

	bindingFile, err := runtimeBoundary.PublishExclusive(
		bindingFileName, bindingBytes,
	)
	if err != nil {
		return fmt.Errorf("publish controller binding: %w", err)
	}
	intentFile, err := runtimeBoundary.PublishExclusive(
		intentFileName, intentBytes,
	)
	if err != nil {
		return errors.Join(
			fmt.Errorf("publish pending intent: %w", err),
			bindingFile.Close(),
		)
	}

	resultBytes, err := runtimeBoundary.SpawnPreflight(
		bindingFile, intentFile, controllerEnvironment(binding),
	)
	closeErr := errors.Join(bindingFile.Close(), intentFile.Close())
	if err != nil {
		return errors.Join(
			fmt.Errorf("admitted preflight adapter: %w", err),
			closeErr,
		)
	}
	if closeErr != nil {
		return fmt.Errorf("close parent binding/intent handles: %w", closeErr)
	}
	if err := validateAdapterResult(resultBytes, binding, intent); err != nil {
		return err
	}
	resultFile, err := runtimeBoundary.PublishExclusive(
		resultFileName, resultBytes,
	)
	if err != nil {
		return fmt.Errorf("publish adapter preflight result: %w", err)
	}
	if err := resultFile.Close(); err != nil {
		return fmt.Errorf("close adapter preflight result: %w", err)
	}
	_, err = output.Write(resultBytes)
	return err
}

func controllerEnvironment(
	binding realcycle.ControllerCycleBinding,
) []string {
	return []string{
		"READINESS=" + binding.Readiness,
		"WINN_SOAK_ADAPTER_MODE=preflight",
		"WINN_SOAK_CYCLE_SEQUENCE=" + strconv.FormatUint(binding.Sequence, 10),
		"WINN_SOAK_INSTANCE_NONCE=" + binding.InstanceNonce,
		"WINN_SOAK_MATRIX_RELATIVE_PATH=" + binding.MatrixRelativePath,
		"WINN_SOAK_MATRIX_SHA256=" + binding.MatrixSHA256,
		"WINN_SOAK_PROFILE=" + binding.Profile,
		"WINN_SOAK_RUN_ID=" + binding.SoakRunID,
	}
}

func validateAdapterResult(
	data []byte,
	binding realcycle.ControllerCycleBinding,
	intent realcycle.ControllerCycleIntent,
) error {
	if len(data) == 0 || len(data) > maxResultBytes ||
		data[len(data)-1] != '\n' ||
		bytes.Count(data, []byte{'\n'}) != 1 {
		return errors.New("adapter result framing is invalid")
	}
	var result adapterResult
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return fmt.Errorf("decode adapter result: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("adapter result contains trailing data")
	}
	canonical, err := json.Marshal(result)
	if err != nil || !bytes.Equal(append(canonical, '\n'), data) {
		return errors.New("adapter result is not canonical")
	}
	if result.Schema != adapterSchema ||
		result.Status != "controller-binding-valid-nonauthorizing" ||
		result.Mode != "preflight" ||
		result.CycleID != binding.CycleID ||
		result.AttemptID != binding.AttemptID ||
		result.TopologyID != binding.TopologyID ||
		result.ControllerBindingDigest != binding.ObjectDigest ||
		result.ControllerIntentDigest != intent.ObjectDigest ||
		result.AdmissionBundleSHA256 != binding.AdmissionBundleSHA256 ||
		result.DispatchAuthorized || result.ExternalTopologyExecuted ||
		result.MatrixExecuted || result.ProviderAccess ||
		result.CredentialAccess || result.Mutation != "none" ||
		result.Authority {
		return errors.New("adapter result does not exactly match binding")
	}
	return nil
}
