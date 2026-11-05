// Command winn-real-cycle-admitted-adapter consumes one canonical E3 binding
// from inherited descriptor 4 and validates the exact controller environment.
// It is deliberately preflight-only and never invokes the matrix.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"runtime"
	"strconv"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

const (
	outputSchema       = "winn-real-cycle-admitted-adapter-preflight/v2"
	maxBindingBytes    = 256 << 10
	maxRunnerBytes     = 128 << 20
	inheritedBindingFD = uintptr(4)
	inheritedIntentFD  = uintptr(5)
)

var exactEnvironmentNames = []string{
	"READINESS",
	"WINN_SOAK_ADAPTER_MODE",
	"WINN_SOAK_CYCLE_SEQUENCE",
	"WINN_SOAK_INSTANCE_NONCE",
	"WINN_SOAK_MATRIX_RELATIVE_PATH",
	"WINN_SOAK_MATRIX_SHA256",
	"WINN_SOAK_PROFILE",
	"WINN_SOAK_RUN_ID",
}

var afterFirstBindingRead = func() {}

type preflightOutput struct {
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
	runner := os.NewFile(3, "winn-sealed-runner")
	binding := os.NewFile(inheritedBindingFD, "winn-e3-binding")
	intent := os.NewFile(inheritedIntentFD, "winn-e3-intent")
	if runner == nil || binding == nil || intent == nil {
		fmt.Fprintln(
			os.Stderr,
			"FAIL: inherited descriptors 3 runner, 4 binding, and 5 intent are required",
		)
		os.Exit(1)
	}
	if err := runInherited(
		runner, binding, intent, os.Environ(), os.Stdout,
	); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func runInherited(
	runnerFile, bindingFile, intentFile *os.File,
	environ []string,
	output io.Writer,
) error {
	status, validationErr := evaluateInherited(
		runnerFile, bindingFile, intentFile, environ,
	)
	closeErr := errors.Join(
		closeFile(runnerFile),
		closeFile(bindingFile),
		closeFile(intentFile),
	)
	if validationErr != nil || closeErr != nil {
		return errors.Join(validationErr, closeErr)
	}
	return writeStatus(output, status)
}

func evaluateInherited(
	runnerFile, bindingFile, intentFile *os.File,
	environ []string,
) (preflightOutput, error) {
	data, err := readStableBindingFile(bindingFile)
	if err != nil {
		return preflightOutput{}, err
	}
	status, binding, err := evaluate(data, environ)
	if err != nil {
		return preflightOutput{}, err
	}
	intentBytes, err := readStableIntentFile(intentFile)
	if err != nil {
		return preflightOutput{}, err
	}
	intent, err := realcycle.ParseControllerCycleIntent(intentBytes)
	if err != nil {
		return preflightOutput{}, err
	}
	bindingSHA := sha256.Sum256(data)
	if intent.ControllerBindingDigest != binding.ObjectDigest ||
		intent.ControllerBindingSHA256 != fmt.Sprintf("%x", bindingSHA[:]) ||
		intent.AdmissionBundleSHA256 != binding.AdmissionBundleSHA256 ||
		intent.CycleID != binding.CycleID ||
		intent.AttemptID != binding.AttemptID ||
		intent.SoakRunID != binding.SoakRunID ||
		intent.Sequence != binding.Sequence ||
		intent.InstanceNonce != binding.InstanceNonce {
		return preflightOutput{}, errors.New(
			"pending intent does not exactly bind descriptor 4",
		)
	}
	status.ControllerIntentDigest = intent.ObjectDigest
	if err := validateRunnerDescriptor(runnerFile, binding); err != nil {
		return preflightOutput{}, err
	}
	return status, nil
}

func closeFile(file *os.File) error {
	if file == nil {
		return nil
	}
	return file.Close()
}

func run(bindingReader io.Reader, environ []string, output io.Writer) error {
	if bindingReader == nil {
		return errors.New("binding reader is required")
	}
	data, err := io.ReadAll(io.LimitReader(bindingReader, maxBindingBytes+1))
	if err != nil {
		return fmt.Errorf("read binding descriptor: %w", err)
	}
	if len(data) == 0 || len(data) > maxBindingBytes {
		return errors.New("binding descriptor size is invalid")
	}
	status, _, err := evaluate(data, environ)
	if err != nil {
		return err
	}
	return writeStatus(output, status)
}

func evaluate(
	data []byte,
	environ []string,
) (preflightOutput, realcycle.ControllerCycleBinding, error) {
	binding, err := realcycle.ParseControllerCycleBinding(data)
	if err != nil {
		return preflightOutput{}, realcycle.ControllerCycleBinding{}, err
	}
	environment, err := parseExactEnvironment(environ)
	if err != nil {
		return preflightOutput{}, realcycle.ControllerCycleBinding{}, err
	}
	if environment["WINN_SOAK_ADAPTER_MODE"] != "preflight" {
		return preflightOutput{}, realcycle.ControllerCycleBinding{},
			errors.New("execution is unsupported; adapter mode must be preflight")
	}
	sequence, err := strconv.ParseUint(
		environment["WINN_SOAK_CYCLE_SEQUENCE"], 10, 64,
	)
	if err != nil || sequence != binding.Sequence ||
		environment["READINESS"] != binding.Readiness ||
		environment["WINN_SOAK_INSTANCE_NONCE"] != binding.InstanceNonce ||
		environment["WINN_SOAK_MATRIX_RELATIVE_PATH"] != binding.MatrixRelativePath ||
		environment["WINN_SOAK_MATRIX_SHA256"] != binding.MatrixSHA256 ||
		environment["WINN_SOAK_PROFILE"] != binding.Profile ||
		environment["WINN_SOAK_RUN_ID"] != binding.SoakRunID {
		return preflightOutput{}, realcycle.ControllerCycleBinding{},
			errors.New("controller environment does not match E3 binding")
	}
	status := preflightOutput{
		Schema:                   outputSchema,
		Status:                   "controller-binding-valid-nonauthorizing",
		Mode:                     "preflight",
		CycleID:                  binding.CycleID,
		AttemptID:                binding.AttemptID,
		TopologyID:               binding.TopologyID,
		ControllerBindingDigest:  binding.ObjectDigest,
		AdmissionBundleSHA256:    binding.AdmissionBundleSHA256,
		DispatchAuthorized:       false,
		ExternalTopologyExecuted: false,
		MatrixExecuted:           false,
		ProviderAccess:           false,
		CredentialAccess:         false,
		Mutation:                 "none",
		Authority:                false,
	}
	return status, binding, nil
}

func writeStatus(output io.Writer, status preflightOutput) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(status)
}

func readStableBindingFile(file *os.File) ([]byte, error) {
	return readStableFile(file, "binding", maxBindingBytes)
}

func readStableIntentFile(file *os.File) ([]byte, error) {
	return readStableFile(file, "intent", maxBindingBytes)
}

func readStableFile(
	file *os.File,
	label string,
	maximum int64,
) ([]byte, error) {
	if file == nil {
		return nil, fmt.Errorf("inherited %s descriptor is unavailable", label)
	}
	before, err := file.Stat()
	if err != nil || !safeDescriptorInfo(before, 0o400, maximum) {
		return nil, errors.New(
			"inherited " + label +
				" descriptor is not a safe bounded regular file",
		)
	}
	offset, err := file.Seek(0, io.SeekCurrent)
	if err != nil || offset != 0 {
		return nil, errors.New(
			label + " descriptor initial offset must be exactly zero",
		)
	}
	first, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(first) == 0 || int64(len(first)) > maximum ||
		int64(len(first)) != before.Size() {
		return nil, errors.New(
			label + " descriptor read is incomplete or oversized",
		)
	}
	if label == "binding" {
		afterFirstBindingRead()
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, errors.New(label + " descriptor cannot be rewound")
	}
	second, err := io.ReadAll(io.LimitReader(file, maximum+1))
	after, statErr := file.Stat()
	firstHash, secondHash := sha256.Sum256(first), sha256.Sum256(second)
	if err != nil || statErr != nil || !sameDescriptorInfo(before, after) ||
		!bytes.Equal(first, second) || firstHash != secondHash {
		return nil, errors.New(
			label + " descriptor changed during custody replay",
		)
	}
	return first, nil
}

func validateRunnerDescriptor(
	file *os.File,
	binding realcycle.ControllerCycleBinding,
) error {
	if runtime.GOOS != "linux" {
		return errors.New(
			"exact admitted runner descriptor identity requires Linux /proc",
		)
	}
	if file == nil {
		return errors.New("inherited runner descriptor 3 is unavailable")
	}
	before, err := file.Stat()
	if err != nil || !safeRunnerDescriptorInfo(before) {
		return errors.New("inherited runner descriptor is unsafe")
	}
	if err := requireRunnerSeals(file); err != nil {
		return err
	}
	executed, err := os.Stat("/proc/self/exe")
	if err != nil || !os.SameFile(before, executed) {
		return errors.New("descriptor 3 is not the executing runner identity")
	}
	offset, err := file.Seek(0, io.SeekCurrent)
	if err != nil || offset != 0 {
		return errors.New("runner descriptor initial offset must be exactly zero")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return errors.New("runner descriptor cannot be rewound")
	}
	firstHash := sha256.New()
	firstCopied, err := io.Copy(
		firstHash, io.LimitReader(file, maxRunnerBytes+1),
	)
	middle, middleErr := file.Stat()
	if _, seekErr := file.Seek(0, io.SeekStart); seekErr != nil {
		return errors.New("runner descriptor cannot be replayed")
	}
	secondHash := sha256.New()
	secondCopied, secondErr := io.Copy(
		secondHash, io.LimitReader(file, maxRunnerBytes+1),
	)
	after, statErr := file.Stat()
	firstDigest := fmt.Sprintf("%x", firstHash.Sum(nil))
	secondDigest := fmt.Sprintf("%x", secondHash.Sum(nil))
	if err != nil || secondErr != nil ||
		middleErr != nil || statErr != nil ||
		firstCopied != before.Size() || secondCopied != before.Size() ||
		!sameDescriptorInfo(before, middle) ||
		!sameDescriptorInfo(before, after) ||
		firstDigest != secondDigest ||
		firstDigest != binding.RunnerSHA256 {
		return errors.New("executing runner descriptor digest or identity mismatch")
	}
	return nil
}

func safeRunnerDescriptorInfo(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() &&
		info.Mode().Perm() == 0o500 &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 &&
		info.Size() > 0 && info.Size() <= maxRunnerBytes &&
		descriptorLinkCount(info) == 0 &&
		descriptorOwnerMatches(info)
}

func safeDescriptorInfo(
	info os.FileInfo,
	permission os.FileMode,
	maximum int64,
) bool {
	return info != nil && info.Mode().IsRegular() &&
		info.Mode().Perm() == permission &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 &&
		info.Size() > 0 && info.Size() <= maximum &&
		descriptorLinkCount(info) == 1 &&
		descriptorOwnerMatches(info)
}

func sameDescriptorInfo(before, after os.FileInfo) bool {
	return before != nil && after != nil &&
		os.SameFile(before, after) &&
		before.Mode() == after.Mode() &&
		before.Size() == after.Size() &&
		before.ModTime().Equal(after.ModTime()) &&
		descriptorLinkCount(before) == descriptorLinkCount(after)
}

func descriptorLinkCount(info os.FileInfo) uint64 {
	if info == nil {
		return 0
	}
	value := reflect.ValueOf(info.Sys())
	if !value.IsValid() {
		return 0
	}
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return 0
	}
	field := value.FieldByName("Nlink")
	if !field.IsValid() {
		return 0
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16,
		reflect.Uint32, reflect.Uint64:
		return field.Uint()
	default:
		return 0
	}
}

func descriptorOwnerMatches(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	value := reflect.ValueOf(info.Sys())
	if !value.IsValid() {
		return false
	}
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return false
	}
	field := value.FieldByName("Uid")
	if !field.IsValid() {
		return false
	}
	var uid uint64
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16,
		reflect.Uint32, reflect.Uint64:
		uid = field.Uint()
	default:
		return false
	}
	// #nosec G115 -- POSIX effective user identifiers are nonnegative uid_t
	// values returned through Go's host int.
	return uid == uint64(os.Geteuid())
}

func parseExactEnvironment(environ []string) (map[string]string, error) {
	values := make(map[string]string, len(environ))
	for _, entry := range environ {
		for index := 0; index < len(entry); index++ {
			if entry[index] != '=' {
				continue
			}
			name, value := entry[:index], entry[index+1:]
			if name == "" {
				return nil, errors.New("environment contains an empty name")
			}
			if _, exists := values[name]; exists {
				return nil, errors.New("environment contains a duplicate name")
			}
			values[name] = value
			break
		}
	}
	if len(values) != len(exactEnvironmentNames) {
		return nil, errors.New("controller environment cardinality is not exact")
	}
	for _, name := range exactEnvironmentNames {
		if _, ok := values[name]; !ok {
			return nil, errors.New("controller environment name set is not exact")
		}
	}
	return values, nil
}
