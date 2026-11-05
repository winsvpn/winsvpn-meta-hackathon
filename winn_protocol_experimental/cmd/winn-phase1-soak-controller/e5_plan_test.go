package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

func testE5Admission(t *testing.T) realcycle.AdmissionResult {
	t.Helper()
	value := testAdmissionResult()
	value.ExercisedNodeCount = e5PlanNodeCount
	for index, role := range e5RequiredRoles {
		nodeID := "node-" + strings.ReplaceAll(role, "-", "_")
		deployment := realcycle.DeploymentBinding{
			Role: role, InstanceUUID: "instance-" + role,
			NodeID: nodeID, ServiceID: "service-" + role,
			Provider: "offline-provider", OperatorID: "operator-" + role,
		}
		runtime := realcycle.RuntimeAttestation{
			Schema:             realcycle.RuntimeSchema,
			CycleBindingDigest: value.BindingDigest,
			Role:               role, InstanceUUID: deployment.InstanceUUID,
			NodeID: nodeID, ServiceID: deployment.ServiceID,
			Provider: deployment.Provider, OperatorID: deployment.OperatorID,
			BootID: "boot-" + role, ProcessID: uint64(100 + index),
			ProcessStartTicks: uint64(1000 + index),
			ExecutableSHA256:  strings.Repeat("a", 64),
			ConfigSHA256:      strings.Repeat("b", 64),
			CertificateSHA256: strings.Repeat("c", 64),
			Endpoint:          "127.0.0.1:4" + string(rune('0'+index)),
			Status:            "running", ObservedAt: "2026-07-28T00:00:30Z",
			CounterDomain:   value.CounterDomain,
			ObservedCounter: value.AcceptedCounter + uint64(index) + 1,
			KeyID:           "runtime-key-" + role, Signature: "test-signature",
		}
		digest, err := realcycle.RuntimeAttestationObjectDigest(runtime)
		if err != nil {
			t.Fatal(err)
		}
		value.ExercisedNodes[index] = nodeID
		value.Deployments[index] = deployment
		value.RuntimeAttestations[index] = runtime
		value.RuntimeObjectDigests[index] = digest
	}
	value.LastObservedCounter = value.AcceptedCounter + e5PlanNodeCount
	return value
}

func TestBuildE5PlanRequiresExactFourNodeProjection(t *testing.T) {
	admission := testE5Admission(t)
	digest := strings.Repeat("c", 64)
	receipt := validAdmittedReceipt()
	receipt.ObjectDigest = digest
	receipt.AdmissionBundleSHA256 = admission.AdmissionBundleSHA256
	receipt.AdmissionBindingDigest = admission.BindingDigest
	receipt.RuntimeCollectionDigest = admission.RuntimeCollectionDigest
	receipt.ReservationObjectDigest = admission.ReservationObjectDigest
	receipt.Result.CycleID = admission.CycleID
	receipt.Result.AttemptID = admission.AttemptID
	receipt.Result.TopologyID = admission.TopologyID
	plan, encoded, err := buildE5Plan(
		minimallyShapedAdmittedConfig(t), strings.Repeat("d", 64),
		admission, receipt, 1, strings.Repeat("e", 64),
		strings.Repeat("f", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseE5Plan(encoded); err != nil {
		t.Fatal(err)
	}
	if plan.ExercisedNodeCount != 4 ||
		plan.ExercisedNodeOrder != admission.ExercisedNodes ||
		plan.Nodes[0].Role != "control" ||
		plan.Nodes[3].Role != "exit" ||
		plan.DispatchAuthorized || plan.ExternalTopologyExecuted ||
		plan.ProviderAccess || plan.CredentialAccess || plan.NetworkAccess ||
		plan.LiveNodesContacted || plan.SpendAuthorized ||
		plan.HandoffReady || plan.Authority {
		t.Fatalf("unsafe or incomplete E5 plan: %+v", plan)
	}
	for _, mutate := range []func(*realcycle.AdmissionResult){
		func(value *realcycle.AdmissionResult) { value.ExercisedNodeCount = 3 },
		func(value *realcycle.AdmissionResult) {
			value.ExercisedNodes[2] = "other"
		},
		func(value *realcycle.AdmissionResult) {
			value.Deployments[1].Role = "exit"
		},
		func(value *realcycle.AdmissionResult) {
			value.RuntimeAttestations[0].NodeID = "other"
		},
		func(value *realcycle.AdmissionResult) {
			value.RuntimeObjectDigests[3] = strings.Repeat("0", 64)
		},
	} {
		changed := admission
		mutate(&changed)
		if _, _, err := buildE5Plan(
			minimallyShapedAdmittedConfig(t), strings.Repeat("d", 64),
			changed, receipt, 1, strings.Repeat("e", 64),
			strings.Repeat("f", 64),
		); err == nil {
			t.Fatal("invalid four-node projection was accepted")
		}
	}
	permuted := admission
	permuted.ExercisedNodes = [4]string{
		admission.ExercisedNodes[3], admission.ExercisedNodes[1],
		admission.ExercisedNodes[0], admission.ExercisedNodes[2],
	}
	permutedPlan, _, err := buildE5Plan(
		minimallyShapedAdmittedConfig(t), strings.Repeat("d", 64),
		permuted, receipt, 1, strings.Repeat("e", 64),
		strings.Repeat("f", 64),
	)
	if err != nil || permutedPlan.ExercisedNodeOrder != permuted.ExercisedNodes {
		t.Fatalf("exact four-node set permutation was not preserved: %v", err)
	}
}

func TestE5PlanParserRejectsAuthorityAndDigestDrift(t *testing.T) {
	admission := testE5Admission(t)
	receipt := validAdmittedReceipt()
	receipt.ObjectDigest = strings.Repeat("c", 64)
	receipt.AdmissionBundleSHA256 = admission.AdmissionBundleSHA256
	receipt.AdmissionBindingDigest = admission.BindingDigest
	receipt.RuntimeCollectionDigest = admission.RuntimeCollectionDigest
	receipt.ReservationObjectDigest = admission.ReservationObjectDigest
	receipt.Result.CycleID = admission.CycleID
	receipt.Result.AttemptID = admission.AttemptID
	receipt.Result.TopologyID = admission.TopologyID
	plan, _, err := buildE5Plan(
		minimallyShapedAdmittedConfig(t), strings.Repeat("d", 64),
		admission, receipt, 1, strings.Repeat("e", 64),
		strings.Repeat("f", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*e5FourNodePlan){
		func(value *e5FourNodePlan) { value.DispatchAuthorized = true },
		func(value *e5FourNodePlan) { value.NetworkAccess = true },
		func(value *e5FourNodePlan) { value.HandoffReady = true },
		func(value *e5FourNodePlan) { value.Authority = true },
		func(value *e5FourNodePlan) { value.Nodes[1].RuntimeObservedCounter++ },
		func(value *e5FourNodePlan) { value.RequiredFutureGates[0] = "missing" },
	} {
		changed := plan
		mutate(&changed)
		encoded, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseE5Plan(encoded); err == nil {
			t.Fatal("mutated E5 plan was accepted")
		}
	}
}

func TestE5PlanReplaysE4WithoutMutatingIt(t *testing.T) {
	oldPlatform := admittedPlatform
	oldVerify := verifyAdmittedInputsOperation
	oldValidate := validateAdmittedAdmission
	oldLaunch := runAdmittedLauncherOperation
	oldPublish := publishE5PlanOperation
	admittedPlatform = "linux"
	verifyAdmittedInputsOperation = func(AdmittedConfig) error { return nil }
	admission := testE5Admission(t)
	validateAdmittedAdmission = func(
		string, string, string,
	) (realcycle.AdmissionResult, error) {
		return admission, nil
	}
	runAdmittedLauncherOperation = func(
		_ context.Context, _ AdmittedConfig, request admittedLaunchRequest,
	) ([]byte, error) {
		contract, err := readTestContract(request)
		if err != nil {
			return nil, err
		}
		input, err := realcycle.ParseControllerBindingInput(contract)
		if err != nil {
			return nil, err
		}
		return writeMockAdmittedArtifacts(
			request.StateDirectory, admission, input,
		)
	}
	publishE5PlanOperation = func(
		directory *secureDirectory, encoded []byte, expected e5FourNodePlan,
	) error {
		path := filepath.Join(directory.path, e5PlanFile)
		if err := os.WriteFile(path, encoded, 0o400); err != nil {
			return err
		}
		replayed, raw, err := readE5Plan(directory)
		if err != nil {
			return err
		}
		if replayed != expected || string(raw) != string(encoded) {
			return errors.New("injected E5 replay mismatch")
		}
		return directory.Sync()
	}
	t.Cleanup(func() {
		admittedPlatform = oldPlatform
		verifyAdmittedInputsOperation = oldVerify
		validateAdmittedAdmission = oldValidate
		runAdmittedLauncherOperation = oldLaunch
		publishE5PlanOperation = oldPublish
	})

	cfg := minimallyShapedAdmittedConfig(t)
	if _, err := runAdmittedPreflight(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	stateBefore, _, err := treeDigest(cfg.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	evidenceBefore, _, err := treeDigest(cfg.EvidenceRoot)
	if err != nil {
		t.Fatal(err)
	}
	planRoot := privateTestDirectory(t)
	summary, err := runAdmittedE5Plan(
		context.Background(), cfg, planRoot,
	)
	if err != nil {
		t.Fatal(err)
	}
	stateAfter, _, _ := treeDigest(cfg.StateRoot)
	evidenceAfter, _, _ := treeDigest(cfg.EvidenceRoot)
	if stateAfter != stateBefore || evidenceAfter != evidenceBefore {
		t.Fatal("E5 planning mutated E4 state or evidence")
	}
	if summary.ExercisedNodeCount != 4 ||
		summary.DispatchAuthorized || summary.ExternalTopologyExecuted ||
		summary.ProviderAccess || summary.CredentialAccess ||
		summary.NetworkAccess || summary.LiveNodesContacted ||
		summary.SpendAuthorized || summary.HandoffReady || summary.Authority {
		t.Fatalf("unsafe E5 summary: %+v", summary)
	}
	info, err := os.Stat(filepath.Join(planRoot, e5PlanFile))
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("E5 plan mode is not 0400: %v %+v", err, info)
	}
	if _, err := runAdmittedE5Plan(
		context.Background(), cfg, planRoot,
	); err == nil {
		t.Fatal("E5 plan root reuse was accepted")
	}
}

func TestE5RefusesUnsupportedPlatformBeforePlanMutation(t *testing.T) {
	oldPlatform := admittedPlatform
	admittedPlatform = "darwin"
	t.Cleanup(func() { admittedPlatform = oldPlatform })
	root := privateTestDirectory(t)
	if _, err := runAdmittedE5Plan(
		context.Background(), minimallyShapedAdmittedConfig(t), root,
	); err == nil || !strings.Contains(err.Error(), "Linux-only") {
		t.Fatalf("unsupported platform was not refused: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unsupported platform mutated plan root: %v %v", err, entries)
	}
}

func TestE5RefusesChangedAdmissionBeforePublication(t *testing.T) {
	oldPlatform := admittedPlatform
	oldVerify := verifyAdmittedInputsOperation
	oldValidate := validateAdmittedAdmission
	admittedPlatform = "linux"
	verifyAdmittedInputsOperation = func(AdmittedConfig) error { return nil }
	admission := testE5Admission(t)
	calls := 0
	validateAdmittedAdmission = func(
		string, string, string,
	) (realcycle.AdmissionResult, error) {
		calls++
		if calls == 2 {
			admission.AcceptedCounter++
		}
		return admission, nil
	}
	t.Cleanup(func() {
		admittedPlatform = oldPlatform
		verifyAdmittedInputsOperation = oldVerify
		validateAdmittedAdmission = oldValidate
	})

	cfg := minimallyShapedAdmittedConfig(t)
	for _, root := range []string{cfg.StateRoot, cfg.EvidenceRoot} {
		if err := os.WriteFile(
			filepath.Join(root, admittedModeFile), []byte("{}"), 0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	planRoot := privateTestDirectory(t)
	if _, err := runAdmittedE5Plan(
		context.Background(), cfg, planRoot,
	); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed E2 admission was not refused: %v", err)
	}
	entries, err := os.ReadDir(planRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("changed admission mutated plan root: %v %v", err, entries)
	}
}
