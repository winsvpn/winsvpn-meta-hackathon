package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

type fakeRuntime struct {
	directory   string
	failPublish int
	failName    string
	failStage   string
	publishes   []string
	durable     map[string]bool
	issued      []*os.File
	spawns      int
	result      []byte
	spawnErr    error
	closed      bool
	closeErr    error
}

var durablePublicationStages = []string{
	"create-temp",
	"write",
	"fsync-temp",
	"close-temp",
	"rename-noreplace",
	"fsync-parent",
	"reopen",
	"identity-and-byte-replay",
}

func (runtime *fakeRuntime) PublishExclusive(
	name string,
	data []byte,
) (*os.File, error) {
	runtime.publishes = append(runtime.publishes, name)
	if runtime.failPublish == len(runtime.publishes) {
		return nil, errors.New("injected publication failure")
	}
	if runtime.durable[name] {
		return nil, errors.New("orphan or existing final refused")
	}
	for _, stage := range durablePublicationStages {
		if runtime.failName == name && runtime.failStage == stage {
			return nil, errors.New("injected " + stage + " failure")
		}
	}
	path := filepath.Join(runtime.directory, name)
	if err := os.WriteFile(path, data, 0o400); err != nil {
		return nil, err
	}
	runtime.durable[name] = true
	file, err := os.Open(path)
	if err == nil {
		runtime.issued = append(runtime.issued, file)
	}
	return file, err
}

func (runtime *fakeRuntime) SpawnPreflight(
	binding, intent *os.File,
	environment []string,
) ([]byte, error) {
	runtime.spawns++
	if !runtime.durable[bindingFileName] ||
		!runtime.durable[intentFileName] ||
		binding == nil || intent == nil ||
		len(environment) != 8 {
		return nil, errors.New("spawn occurred before durable prerequisites")
	}
	return bytes.Clone(runtime.result), runtime.spawnErr
}

func (runtime *fakeRuntime) Close() error {
	runtime.closed = true
	return runtime.closeErr
}

func TestLauncherPublishesIntentBeforeSinglePreflightSpawn(t *testing.T) {
	admission, input := launcherInputs()
	binding, _, err := realcycle.NewControllerCycleBinding(admission, input)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{
		directory: t.TempDir(),
		durable:   make(map[string]bool),
		result:    adapterResultBytes(t, binding),
	}
	var output bytes.Buffer
	if err := runWith(
		launcherArguments(),
		&output,
		func(string) (realcycle.ControllerBindingInput, error) {
			return input, nil
		},
		func(string, string, string) (realcycle.AdmissionResult, error) {
			return admission, nil
		},
		func(string, string, string, time.Duration) (durableRuntime, error) {
			return runtime, nil
		},
	); err != nil {
		t.Fatal(err)
	}
	if runtime.spawns != 1 || !runtime.closed {
		t.Fatalf("runtime lifecycle mismatch: spawns=%d closed=%v", runtime.spawns, runtime.closed)
	}
	expected := []string{bindingFileName, intentFileName, resultFileName}
	if strings.Join(runtime.publishes, ",") != strings.Join(expected, ",") {
		t.Fatalf("publication order = %v", runtime.publishes)
	}
	if !bytes.Equal(output.Bytes(), runtime.result) {
		t.Fatal("launcher output differs from durable result")
	}
	for index, file := range runtime.issued {
		if _, err := file.Stat(); err == nil {
			t.Fatalf("parent handle %d remains open", index)
		}
	}
}

func TestLauncherNeverSpawnsBeforeDurableIntent(t *testing.T) {
	for _, failure := range []int{1, 2} {
		t.Run(string(rune('0'+failure)), func(t *testing.T) {
			admission, input := launcherInputs()
			runtime := &fakeRuntime{
				directory:   t.TempDir(),
				failPublish: failure,
				durable:     make(map[string]bool),
			}
			err := runWith(
				launcherArguments(),
				&bytes.Buffer{},
				func(string) (realcycle.ControllerBindingInput, error) {
					return input, nil
				},
				func(string, string, string) (realcycle.AdmissionResult, error) {
					return admission, nil
				},
				func(string, string, string, time.Duration) (durableRuntime, error) {
					return runtime, nil
				},
			)
			if err == nil || runtime.spawns != 0 {
				t.Fatalf("failure=%d err=%v spawns=%d", failure, err, runtime.spawns)
			}
		})
	}
}

func TestLauncherPublicationPhaseFailuresNeverSpawnBeforeIntentDurable(
	t *testing.T,
) {
	for _, name := range []string{bindingFileName, intentFileName} {
		for _, stage := range durablePublicationStages {
			t.Run(name+"/"+stage, func(t *testing.T) {
				admission, input := launcherInputs()
				runtime := &fakeRuntime{
					directory: t.TempDir(),
					failName:  name,
					failStage: stage,
					durable:   make(map[string]bool),
				}
				err := runWith(
					launcherArguments(),
					&bytes.Buffer{},
					func(string) (realcycle.ControllerBindingInput, error) {
						return input, nil
					},
					func(string, string, string) (realcycle.AdmissionResult, error) {
						return admission, nil
					},
					func(string, string, string, time.Duration) (durableRuntime, error) {
						return runtime, nil
					},
				)
				if err == nil || runtime.spawns != 0 {
					t.Fatalf(
						"name=%s stage=%s err=%v spawns=%d",
						name, stage, err, runtime.spawns,
					)
				}
			})
		}
	}
}

func TestLauncherRefusesOrphanIntentWithoutSpawn(t *testing.T) {
	admission, input := launcherInputs()
	runtime := &fakeRuntime{
		directory: t.TempDir(),
		durable: map[string]bool{
			intentFileName: true,
		},
	}
	err := runWith(
		launcherArguments(),
		&bytes.Buffer{},
		func(string) (realcycle.ControllerBindingInput, error) {
			return input, nil
		},
		func(string, string, string) (realcycle.AdmissionResult, error) {
			return admission, nil
		},
		func(string, string, string, time.Duration) (durableRuntime, error) {
			return runtime, nil
		},
	)
	if err == nil || runtime.spawns != 0 {
		t.Fatalf("orphan intent was not refused: err=%v spawns=%d", err, runtime.spawns)
	}
}

func TestLauncherE2FailureHasNoRuntimeOrSpawn(t *testing.T) {
	factoryCalls := 0
	err := runWith(
		launcherArguments(),
		&bytes.Buffer{},
		func(string) (realcycle.ControllerBindingInput, error) {
			return realcycle.ControllerBindingInput{}, errors.New("bad E2 contract")
		},
		func(string, string, string) (realcycle.AdmissionResult, error) {
			t.Fatal("admission should not follow invalid contract")
			return realcycle.AdmissionResult{}, nil
		},
		func(string, string, string, time.Duration) (durableRuntime, error) {
			factoryCalls++
			return nil, nil
		},
	)
	if err == nil || factoryCalls != 0 {
		t.Fatalf("E2 failure opened runtime: err=%v calls=%d", err, factoryCalls)
	}
}

func TestLauncherRejectsResultAndPublicationFailure(t *testing.T) {
	for _, test := range []struct {
		name        string
		mutate      func(*fakeRuntime)
		wantPublish int
	}{
		{
			name: "invalid-result",
			mutate: func(runtime *fakeRuntime) {
				runtime.result = []byte("{}\n")
			},
			wantPublish: 2,
		},
		{
			name: "result-publication",
			mutate: func(runtime *fakeRuntime) {
				runtime.failPublish = 3
			},
			wantPublish: 3,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			admission, input := launcherInputs()
			binding, _, err := realcycle.NewControllerCycleBinding(admission, input)
			if err != nil {
				t.Fatal(err)
			}
			runtime := &fakeRuntime{
				directory: t.TempDir(),
				durable:   make(map[string]bool),
				result:    adapterResultBytes(t, binding),
			}
			test.mutate(runtime)
			var output bytes.Buffer
			err = runWith(
				launcherArguments(),
				&output,
				func(string) (realcycle.ControllerBindingInput, error) {
					return input, nil
				},
				func(string, string, string) (realcycle.AdmissionResult, error) {
					return admission, nil
				},
				func(string, string, string, time.Duration) (durableRuntime, error) {
					return runtime, nil
				},
			)
			if err == nil || runtime.spawns != 1 ||
				len(runtime.publishes) != test.wantPublish ||
				output.Len() != 0 {
				t.Fatalf(
					"err=%v spawns=%d publishes=%v output=%q",
					err, runtime.spawns, runtime.publishes, output.String(),
				)
			}
		})
	}
}

func TestLauncherRejectsRunMode(t *testing.T) {
	arguments := launcherArguments()
	arguments = append(arguments, "--mode=run")
	if err := runWith(
		arguments,
		&bytes.Buffer{},
		nil, nil, nil,
	); err == nil {
		t.Fatal("run mode unexpectedly accepted")
	}
}

func TestLauncherRejectsCanonicalMismatchedAdapterResult(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*adapterResult)
	}{
		{"dispatch-authorized", func(result *adapterResult) { result.DispatchAuthorized = true }},
		{"authority", func(result *adapterResult) { result.Authority = true }},
		{"matrix-executed", func(result *adapterResult) { result.MatrixExecuted = true }},
		{"external-topology", func(result *adapterResult) { result.ExternalTopologyExecuted = true }},
		{"provider-access", func(result *adapterResult) { result.ProviderAccess = true }},
		{"credential-access", func(result *adapterResult) { result.CredentialAccess = true }},
		{"wrong-status", func(result *adapterResult) { result.Status = "ok" }},
		{"wrong-mode", func(result *adapterResult) { result.Mode = "run" }},
		{"wrong-mutation", func(result *adapterResult) { result.Mutation = "changed" }},
		{"wrong-schema", func(result *adapterResult) { result.Schema = "nope" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			admission, input := launcherInputs()
			binding, _, err := realcycle.NewControllerCycleBinding(admission, input)
			if err != nil {
				t.Fatal(err)
			}
			good := adapterResultBytes(t, binding)
			var parsed adapterResult
			if err := json.Unmarshal(bytes.TrimSpace(good), &parsed); err != nil {
				t.Fatal(err)
			}
			test.mutate(&parsed)
			bad, err := json.Marshal(parsed)
			if err != nil {
				t.Fatal(err)
			}
			bad = append(bad, '\n')
			runtime := &fakeRuntime{
				directory: t.TempDir(),
				durable:   make(map[string]bool),
				result:    bad,
			}
			var output bytes.Buffer
			err = runWith(
				launcherArguments(),
				&output,
				func(string) (realcycle.ControllerBindingInput, error) {
					return input, nil
				},
				func(string, string, string) (realcycle.AdmissionResult, error) {
					return admission, nil
				},
				func(string, string, string, time.Duration) (durableRuntime, error) {
					return runtime, nil
				},
			)
			if err == nil || runtime.spawns != 1 ||
				len(runtime.publishes) != 2 || output.Len() != 0 {
				t.Fatalf(
					"err=%v spawns=%d publishes=%v output=%q",
					err, runtime.spawns, runtime.publishes, output.String(),
				)
			}
			if !strings.Contains(err.Error(), "does not exactly match binding") {
				t.Fatalf("wrong error: %v", err)
			}
		})
	}
}

func TestRunFailsClosedOnUnreadableContract(t *testing.T) {
	var output bytes.Buffer
	err := run(launcherArguments(), &output)
	if err == nil || output.Len() != 0 {
		t.Fatalf("err=%v output=%q", err, output.String())
	}
}

func TestLauncherJoinsRuntimeCloseFailure(t *testing.T) {
	admission, input := launcherInputs()
	binding, _, err := realcycle.NewControllerCycleBinding(admission, input)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{
		directory: t.TempDir(),
		durable:   make(map[string]bool),
		result:    adapterResultBytes(t, binding),
		closeErr:  errors.New("injected runtime close failure"),
	}
	err = runWith(
		launcherArguments(),
		&bytes.Buffer{},
		func(string) (realcycle.ControllerBindingInput, error) {
			return input, nil
		},
		func(string, string, string) (realcycle.AdmissionResult, error) {
			return admission, nil
		},
		func(string, string, string, time.Duration) (durableRuntime, error) {
			return runtime, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "runtime close failure") {
		t.Fatalf("runtime close error was lost: %v", err)
	}
}

func launcherArguments() []string {
	return []string{
		"--admission=/e2",
		"--trust=/trust",
		"--topology=/topology",
		"--controller-contract=/contract",
		"--state-dir=/state",
		"--adapter=/adapter",
		"--mode=preflight",
	}
}

func launcherInputs() (
	realcycle.AdmissionResult,
	realcycle.ControllerBindingInput,
) {
	digest := strings.Repeat("a", 64)
	return realcycle.AdmissionResult{
			CycleID: "cycle-1", AttemptID: "attempt-1",
			TopologyID: "topology-1", BindingDigest: digest,
			Nonce:         "00112233445566778899aabbccddeeff",
			CounterDomain: "counter-1", AcceptedCounter: 1,
			ExpectedTransport:       realcycle.TransportDirect,
			AdmissionBundleSHA256:   digest,
			RuntimeCollectionDigest: digest,
			ReservationObjectDigest: digest,
			StartNotBefore:          "2030-01-01T10:08:00Z",
			StartDeadline:           "2030-01-01T10:10:00Z",
			FinishDeadline:          "2030-01-01T10:20:00Z",
		}, realcycle.ControllerBindingInput{
			SoakRunID: "soak-run-1", Sequence: 1,
			InstanceNonce: "ffeeddccbbaa99887766554433221100",
			Readiness:     "warm", Profile: "direct-primary",
			RunnerSHA256:       digest,
			MatrixRelativePath: "scripts/aicore_phase1_auto_matrix.sh",
			MatrixSHA256:       digest, SnapshotSHA256: digest,
			SnapshotFileCount: 102, SourceSHA256: digest,
			ManifestSHA256: digest, VerifierSHA256: digest,
			ConfigurationSHA256: digest,
			ChildEnvironmentNames: []string{
				"READINESS",
				"WINN_SOAK_ADAPTER_MODE",
				"WINN_SOAK_CYCLE_SEQUENCE",
				"WINN_SOAK_INSTANCE_NONCE",
				"WINN_SOAK_MATRIX_RELATIVE_PATH",
				"WINN_SOAK_MATRIX_SHA256",
				"WINN_SOAK_PROFILE",
				"WINN_SOAK_RUN_ID",
			},
		}
}

func adapterResultBytes(
	t *testing.T,
	binding realcycle.ControllerCycleBinding,
) []byte {
	t.Helper()
	bindingBytes, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	bindingBytes = append(bindingBytes, '\n')
	intent, _, err := realcycle.NewControllerCycleIntent(bindingBytes)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(adapterResult{
		Schema: adapterSchema, Status: "controller-binding-valid-nonauthorizing",
		Mode: "preflight", CycleID: binding.CycleID,
		AttemptID: binding.AttemptID, TopologyID: binding.TopologyID,
		ControllerBindingDigest: binding.ObjectDigest,
		ControllerIntentDigest:  intent.ObjectDigest,
		AdmissionBundleSHA256:   binding.AdmissionBundleSHA256,
		Mutation:                "none",
	})
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}
