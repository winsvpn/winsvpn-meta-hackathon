//go:build linux && winn_incomplete_e8

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

type e8AuthenticatedRoots struct {
	e6Root    string
	e7Root    string
	grantRoot string
	e7Bytes   []byte
}

func prepareE8AuthenticatedRoots(
	t *testing.T,
	fixture *e8AdmissionFixture,
	planRoot, workerPath, workerSHA string,
) e8AuthenticatedRoots {
	t.Helper()
	planDirectory, err := openAdmittedPrivateDirectory(planRoot)
	if err != nil {
		t.Fatal(err)
	}
	plan, planBytes, err := readE5Plan(planDirectory)
	if closeErr := planDirectory.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	admission, err := realcycle.ValidateAdmission(
		fixture.directory, fixture.trustPath, fixture.topology,
	)
	if err != nil {
		t.Fatal(err)
	}
	dispatchPublic, dispatchPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	supervisorPublic, supervisorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture.private["dispatch-e8-real"] = dispatchPrivate
	fixture.private["supervisor-e8-real"] = supervisorPrivate
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	testExecutableFile, testExecutableSHA, err :=
		openAndDigestPinnedFile(testExecutable)
	if err != nil {
		t.Fatal(err)
	}
	if err := testExecutableFile.Close(); err != nil {
		t.Fatal(err)
	}
	configRoot := privateTestDirectory(t)
	configPath := filepath.Join(configRoot, "e8-supervisor.json")
	configBytes := []byte("{\"mode\":\"local-rehearsal-only\"}\n")
	if err := os.WriteFile(configPath, configBytes, 0o400); err != nil {
		t.Fatal(err)
	}
	expected := realcycle.HandoffExpectation{
		RunID: plan.RunID, CycleID: plan.CycleID,
		AttemptID: plan.AttemptID, TopologyID: plan.TopologyID,
		PlanSHA256:              admittedRawSHA(planBytes),
		PlanObjectDigest:        plan.ObjectDigest,
		TrustSHA256:             admission.TrustSHA256,
		AdmissionBindingDigest:  plan.AdmissionBindingDigest,
		AdmissionBundleSHA256:   plan.AdmissionBundleSHA256,
		RuntimeCollectionDigest: plan.RuntimeCollectionDigest,
		ReservationObjectDigest: plan.ReservationObjectDigest,
		AdmissionNonce:          plan.AdmissionNonce, CounterDomain: plan.CounterDomain,
		AcceptedCounter:     plan.AcceptedCounter,
		LastObservedCounter: admission.LastObservedCounter,
		ExpectedTransport:   plan.ExpectedTransport,
		StartNotBefore:      plan.StartNotBefore, StartDeadline: plan.StartDeadline,
		FinishDeadline: plan.FinishDeadline,
	}
	extension := realcycle.HandoffRoleExtension{
		Schema:              realcycle.HandoffRoleExtensionSchema,
		State:               "public-key-extension-only",
		PlanSHA256:          expected.PlanSHA256,
		PlanObjectDigest:    expected.PlanObjectDigest,
		AcceptedTrustSHA256: expected.TrustSHA256,
		Keys: [2]realcycle.HandoffRoleKey{
			{
				KeyID:     "dispatch-e8-real",
				Role:      realcycle.KeyRoleDispatchAuthorizer,
				PublicKey: base64.StdEncoding.EncodeToString(dispatchPublic),
			},
			{
				KeyID:     "supervisor-e8-real",
				Role:      realcycle.KeyRoleExecutionSupervisor,
				PublicKey: base64.StdEncoding.EncodeToString(supervisorPublic),
			},
		},
		ControllerKeyID: "controller",
	}
	extension.Signature = fixture.sign(
		t, "controller",
		"winn-real-cycle-handoff-role-extension-signature/v1",
		extension,
	)
	authorization := realcycle.AuthorizationCommitment{
		Schema: realcycle.AuthorizationCommitmentSchema,
		State:  "sealed-pending-activation",
		Scope:  "execute-one-four-node-cycle",
		RunID:  expected.RunID, CycleID: expected.CycleID,
		AttemptID: expected.AttemptID, TopologyID: expected.TopologyID,
		PlanSHA256:               expected.PlanSHA256,
		PlanObjectDigest:         expected.PlanObjectDigest,
		AdmissionBindingDigest:   expected.AdmissionBindingDigest,
		AdmissionBundleSHA256:    expected.AdmissionBundleSHA256,
		RuntimeCollectionDigest:  expected.RuntimeCollectionDigest,
		ReservationObjectDigest:  expected.ReservationObjectDigest,
		AdmissionNonce:           expected.AdmissionNonce,
		CounterDomain:            expected.CounterDomain,
		MinimumActivationCounter: expected.LastObservedCounter + 1,
		ValidNotBefore:           expected.StartNotBefore,
		ValidNotAfter:            expected.StartDeadline,
		MaxRuntimeAgeSeconds:     300, MaxExecutionSeconds: 600,
		OneTimeNonce:    stringsRepeat("b", 32),
		AuthorizerKeyID: "dispatch-e8-real",
	}
	authorization.Signature = fixture.sign(
		t, "dispatch-e8-real",
		"winn-real-cycle-authorization-commitment-signature/v1",
		authorization,
	)
	supervisor := realcycle.SupervisorCommitment{
		Schema: realcycle.SupervisorCommitmentSchema,
		State:  "sealed-pending-activation",
		RunID:  expected.RunID, CycleID: expected.CycleID,
		AttemptID: expected.AttemptID, TopologyID: expected.TopologyID,
		PlanSHA256:                 expected.PlanSHA256,
		PlanObjectDigest:           expected.PlanObjectDigest,
		ExpectedTransport:          expected.ExpectedTransport,
		SupervisorExecutablePath:   testExecutable,
		SupervisorExecutableSHA256: testExecutableSHA,
		SupervisorConfigPath:       configPath,
		SupervisorConfigSHA256:     admittedRawSHA(configBytes),
		MaxExecutionSeconds:        600, OneTimeNonce: authorization.OneTimeNonce,
		SupervisorKeyID: "supervisor-e8-real",
	}
	supervisor.Signature = fixture.sign(
		t, "supervisor-e8-real",
		"winn-real-cycle-supervisor-commitment-signature/v1",
		supervisor,
	)
	handoff, err := realcycle.VerifySealedHandoffObjects(
		fixture.trustPath, expected, authorization, extension, supervisor,
	)
	if err != nil {
		t.Fatal(err)
	}
	e6, e6Bytes, err := buildE6Receipt(plan, expected.PlanSHA256, handoff)
	if err != nil {
		t.Fatal(err)
	}
	e6Root := privateTestDirectory(t)
	e6Directory, err := openAdmittedPrivateDirectory(e6Root)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishE6Receipt(
		e6Directory, e6Bytes, e6, fixture.trustPath, handoff,
	); err != nil {
		t.Fatal(err)
	}
	if err := e6Directory.Close(); err != nil {
		t.Fatal(err)
	}
	e7Expected := e7Expectation(e6, admittedRawSHA(e6Bytes))
	decision := realcycle.ExecutionAuthorization{
		Schema:     realcycle.ExecutionAuthorizationSchema,
		State:      "explicit-authority-input-only",
		Scope:      "one-provider-neutral-supervisor-execution",
		DecisionID: "decision-e8-production-unconsumed",
		RunID:      e7Expected.RunID, CycleID: e7Expected.CycleID,
		AttemptID: e7Expected.AttemptID, TopologyID: e7Expected.TopologyID,
		PlanSHA256:                 e7Expected.PlanSHA256,
		PlanObjectDigest:           e7Expected.PlanObjectDigest,
		TrustSHA256:                e7Expected.TrustSHA256,
		E6ReceiptSHA256:            e7Expected.E6ReceiptSHA256,
		E6ReceiptObjectDigest:      e7Expected.E6ReceiptObjectDigest,
		HandoffCollectionDigest:    e7Expected.HandoffCollectionDigest,
		OneTimeNonce:               e7Expected.OneTimeNonce,
		ActivationCounter:          e7Expected.MinimumActivationCounter,
		ValidNotBefore:             e7Expected.ValidNotBefore,
		ValidNotAfter:              e7Expected.ValidNotAfter,
		MaxExecutionSeconds:        e7Expected.MaxExecutionSeconds,
		SupervisorExecutablePath:   e7Expected.SupervisorExecutablePath,
		SupervisorExecutableSHA256: e7Expected.SupervisorExecutableSHA256,
		SupervisorConfigPath:       e7Expected.SupervisorConfigPath,
		SupervisorConfigSHA256:     e7Expected.SupervisorConfigSHA256,
		AuthorizerKeyID:            "dispatch-e8-real",
	}
	decision.Signature = fixture.sign(
		t, "dispatch-e8-real",
		"winn-real-cycle-explicit-execution-authorization-signature/v1",
		decision,
	)
	decisionBytes := append(e8FixtureBytes(t, decision), '\n')
	decisionObject, err := admittedDigest(
		"winn-real-cycle-explicit-execution-authorization-object/v1",
		decision,
	)
	if err != nil {
		t.Fatal(err)
	}
	acceptance := realcycle.SupervisorAuthorizationAcceptance{
		Schema:                realcycle.SupervisorAuthorizationAcceptanceSchema,
		State:                 "accepted-for-future-atomic-consumption",
		DecisionSHA256:        admittedRawSHA(decisionBytes),
		DecisionObjectDigest:  decisionObject,
		E6ReceiptSHA256:       e7Expected.E6ReceiptSHA256,
		E6ReceiptObjectDigest: e7Expected.E6ReceiptObjectDigest,
		RunID:                 e7Expected.RunID, CycleID: e7Expected.CycleID,
		AttemptID: e7Expected.AttemptID, TopologyID: e7Expected.TopologyID,
		OneTimeNonce:               e7Expected.OneTimeNonce,
		ActivationCounter:          e7Expected.MinimumActivationCounter,
		SupervisorExecutablePath:   e7Expected.SupervisorExecutablePath,
		SupervisorExecutableSHA256: e7Expected.SupervisorExecutableSHA256,
		SupervisorConfigPath:       e7Expected.SupervisorConfigPath,
		SupervisorConfigSHA256:     e7Expected.SupervisorConfigSHA256,
		SupervisorKeyID:            "supervisor-e8-real",
	}
	acceptance.Signature = fixture.sign(
		t, "supervisor-e8-real",
		"winn-real-cycle-supervisor-authorization-acceptance-signature/v1",
		acceptance,
	)
	authorizationResult, err := realcycle.VerifyExecutionAuthorizationObjects(
		e7Expected, decision, acceptance,
	)
	if err != nil {
		t.Fatal(err)
	}
	e7, e7Bytes, err := buildE7Receipt(
		e6, admittedRawSHA(e6Bytes), decision, acceptance, authorizationResult,
	)
	if err != nil {
		t.Fatal(err)
	}
	e7Root := privateTestDirectory(t)
	e7Directory, err := openAdmittedPrivateDirectory(e7Root)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishE7Receipt(
		e7Directory, e7Bytes, e7, e7Expected, authorizationResult,
	); err != nil {
		t.Fatal(err)
	}
	if err := e7Directory.Close(); err != nil {
		t.Fatal(err)
	}
	grant := e8RehearsalGrant{
		Schema: e8GrantSchema, State: e8GrantState, Scope: e8GrantScope,
		GrantID: "grant-e8-real", RunID: plan.RunID, CycleID: plan.CycleID,
		AttemptID: plan.AttemptID, TopologyID: plan.TopologyID,
		PlanSHA256: e6.PlanSHA256, PlanObjectDigest: plan.ObjectDigest,
		E6ReceiptSHA256:       admittedRawSHA(e6Bytes),
		E6ReceiptObjectDigest: e6.ObjectDigest,
		E7ReceiptSHA256:       admittedRawSHA(e7Bytes),
		E7ReceiptObjectDigest: e7.ObjectDigest,
		WorkerPath:            workerPath, WorkerSHA256: workerSHA,
		SandboxPolicy:       e8SandboxPolicy,
		SandboxPolicyDigest: e8SandboxPolicyDigest(),
		RehearsalNonce:      stringsRepeat("c", 32), MaxRehearsalSeconds: 20,
		AuthorizerKeyID: "dispatch-e8-real",
	}
	grant.Signature = fixture.sign(
		t, "dispatch-e8-real", e8GrantDomain, e8GrantUnsignedOf(grant),
	)
	grantBytes := e8FixtureBytes(t, grant)
	grantObject, err := admittedDigest(e8GrantObject, grant)
	if err != nil {
		t.Fatal(err)
	}
	grantAcceptance := e8RehearsalAcceptance{
		Schema: e8AcceptanceSchema, State: "accepted-for-local-rehearsal-only",
		GrantSHA256:           admittedRawSHA(grantBytes),
		GrantObjectDigest:     grantObject,
		E6ReceiptSHA256:       admittedRawSHA(e6Bytes),
		E6ReceiptObjectDigest: e6.ObjectDigest,
		E7ReceiptSHA256:       admittedRawSHA(e7Bytes),
		E7ReceiptObjectDigest: e7.ObjectDigest,
		RunID:                 plan.RunID, CycleID: plan.CycleID,
		AttemptID: plan.AttemptID, TopologyID: plan.TopologyID,
		WorkerPath: workerPath, WorkerSHA256: workerSHA,
		SandboxPolicyDigest:        e8SandboxPolicyDigest(),
		RehearsalNonce:             grant.RehearsalNonce,
		SupervisorExecutablePath:   e6.SupervisorExecutablePath,
		SupervisorExecutableSHA256: e6.SupervisorExecutableSHA256,
		SupervisorKeyID:            "supervisor-e8-real",
	}
	grantAcceptance.Signature = fixture.sign(
		t, "supervisor-e8-real", e8AcceptanceDomain,
		e8AcceptanceUnsignedOf(grantAcceptance),
	)
	grantRoot := privateTestDirectory(t)
	for name, value := range map[string]any{
		e8GrantFile: grant, e8AcceptanceFile: grantAcceptance,
	} {
		if err := os.WriteFile(
			filepath.Join(grantRoot, name), e8FixtureBytes(t, value), 0o400,
		); err != nil {
			t.Fatal(err)
		}
	}
	return e8AuthenticatedRoots{
		e6Root: e6Root, e7Root: e7Root, grantRoot: grantRoot,
		e7Bytes: e7Bytes,
	}
}

func buildE8FixtureBinary(
	t *testing.T, moduleRoot, output, packagePath string, static bool,
) string {
	t.Helper()
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(
		goBinary,
		"build", "-o", output, packagePath,
	)
	if packagePath == "./cmd/winn-local-sealed-node" {
		command.Args = append(
			command.Args[:1],
			append(
				[]string{"build", "-tags", "winn_incomplete_e8"},
				command.Args[2:]...,
			)...,
		)
	}
	command.Dir = moduleRoot
	command.Env = append(
		os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off",
	)
	if static {
		command.Env = append(command.Env, "CGO_ENABLED=0")
	}
	if data, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", packagePath, err, data)
	}
	if err := os.Chmod(output, 0o500); err != nil {
		t.Fatal(err)
	}
	file, digest, err := openAndDigestPinnedFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return digest
}

func newE8RealConfig(
	t *testing.T, fixture *e8AdmissionFixture,
	workerPath, workerSHA string,
) (AdmittedConfig, string, string) {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate E8 integration source")
	}
	moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	binaryRoot := privateTestDirectory(t)
	launcherPath := filepath.Join(binaryRoot, "e8-launcher")
	adapterPath := filepath.Join(binaryRoot, "e8-adapter")
	launcherSHA := buildE8FixtureBinary(
		t, moduleRoot, launcherPath,
		"./cmd/winn-real-cycle-admitted-launcher", true,
	)
	adapterSHA := buildE8FixtureBinary(
		t, moduleRoot, adapterPath,
		"./cmd/winn-real-cycle-admitted-adapter", true,
	)
	stateRoot := privateTestDirectory(t)
	evidenceRoot := privateTestDirectory(t)
	snapshotRoot := privateTestDirectory(t)
	matrixBytes := []byte("#!/bin/sh\nexit 99\n")
	matrixPath := filepath.Join(snapshotRoot, "matrix.sh")
	if err := os.WriteFile(matrixPath, matrixBytes, 0o400); err != nil {
		t.Fatal(err)
	}
	snapshotSHA, snapshotCount, err := treeDigest(snapshotRoot)
	if err != nil {
		t.Fatal(err)
	}
	inputRoot := privateTestDirectory(t)
	manifestPath := filepath.Join(inputRoot, "manifest.json")
	verifierPath := filepath.Join(inputRoot, "verifier.json")
	manifestBytes := []byte("{\"e8\":\"manifest\"}\n")
	verifierBytes := []byte("{\"e8\":\"verifier\"}\n")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(verifierPath, verifierBytes, 0o400); err != nil {
		t.Fatal(err)
	}
	return AdmittedConfig{
		RunID: "run-e8-real", StateRoot: stateRoot,
		EvidenceRoot: evidenceRoot, SnapshotRoot: snapshotRoot,
		AdmissionPath: fixture.directory, TrustPath: fixture.trustPath,
		TopologyPath: fixture.topology,
		LauncherPath: launcherPath, LauncherSHA256: launcherSHA,
		AdapterPath: adapterPath, AdapterSHA256: adapterSHA,
		ManifestPath: manifestPath, ManifestSHA256: admittedRawSHA(manifestBytes),
		VerifierPath: verifierPath, VerifierSHA256: admittedRawSHA(verifierBytes),
		Profile: "e8-real", MatrixRelativePath: "matrix.sh",
		MatrixSHA256:   admittedRawSHA(matrixBytes),
		SnapshotSHA256: snapshotSHA, SnapshotFileCount: uint64(snapshotCount),
		SourceSHA256:        admittedRawSHA([]byte("e8-r2-source")),
		ConfigurationSHA256: admittedRawSHA([]byte("e8-r2-configuration")),
		Timeout:             20 * time.Second,
	}, workerPath, workerSHA
}

func buildE8RetainedWorker(t *testing.T) (string, string) {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate E8 integration source")
	}
	moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	binaryRoot := privateTestDirectory(t)
	workerPath := filepath.Join(binaryRoot, "e8-worker")
	workerSHA := buildE8FixtureBinary(
		t, moduleRoot, workerPath, "./cmd/winn-local-sealed-node", true,
	)
	return workerPath, workerSHA
}

func TestE8FullAuthenticatedE2ThroughDurableReceiptLeavesE7Unconsumed(
	t *testing.T,
) {
	workerPath, workerSHA := buildE8RetainedWorker(t)
	prepared, err := prepareLocalFourNode(
		context.Background(), workerPath, workerSHA,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = prepared.Close() })
	fixture := newE8AdmissionFixtureForWorkers(
		t, &prepared.identities, workerSHA,
	)
	cfg, workerPath, workerSHA := newE8RealConfig(
		t, fixture, workerPath, workerSHA,
	)
	firstE3, err := runAdmittedPreflight(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if firstE3.Sequence != 1 || firstE3.MatrixExecuted ||
		firstE3.HandoffReady || firstE3.Authority {
		t.Fatalf("unsafe first E3 result: %+v", firstE3)
	}
	planRoot := privateTestDirectory(t)
	planSummary, err := runAdmittedE5Plan(
		context.Background(), cfg, planRoot,
	)
	if err != nil {
		t.Fatal(err)
	}
	if planSummary.E4LastReceiptDigest != firstE3.ReceiptDigest ||
		planSummary.ExercisedNodeCount != 4 {
		t.Fatalf("E5 did not bind first E3: %+v", planSummary)
	}
	planDirectory, err := openAdmittedPrivateDirectory(planRoot)
	if err != nil {
		t.Fatal(err)
	}
	sealedPlan, _, err := readE5Plan(planDirectory)
	if closeErr := planDirectory.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := validateE8PreparedPlan(
		sealedPlan, prepared, workerPath, workerSHA,
	); err != nil {
		t.Fatalf("real sealed E5 identity edge failed: %v", err)
	}
	mutations := map[string]func(*e5FourNodePlan){
		"zero-pid": func(plan *e5FourNodePlan) {
			plan.Nodes[0].ProcessID = 0
		},
		"mismatched-start": func(plan *e5FourNodePlan) {
			plan.Nodes[0].ProcessStartTicks++
		},
		"synthetic-pid-substitution": func(plan *e5FourNodePlan) {
			plan.Nodes[0].ProcessID += 100000
		},
		"cross-node-pid-swap": func(plan *e5FourNodePlan) {
			plan.Nodes[0].ProcessID, plan.Nodes[1].ProcessID =
				plan.Nodes[1].ProcessID, plan.Nodes[0].ProcessID
		},
		"executable-substitution": func(plan *e5FourNodePlan) {
			plan.Nodes[0].ExecutableSHA256 = strings.Repeat("f", 64)
		},
	}
	for name, mutate := range mutations {
		t.Run("reject-"+name, func(t *testing.T) {
			mutated := sealedPlan
			mutate(&mutated)
			for index := range mutated.Nodes {
				digest, digestErr := realcycle.RuntimeAttestationObjectDigest(
					mutated.Nodes[index].runtimeAttestation(),
				)
				if digestErr != nil {
					t.Fatal(digestErr)
				}
				mutated.Nodes[index].RuntimeObjectDigest = digest
			}
			if mutated.Nodes[0].ProcessID != 0 {
				resealed, _, resealErr := encodeE5Plan(mutated)
				if resealErr != nil {
					t.Fatalf("mutation was not independently resealable: %v", resealErr)
				}
				mutated = resealed
			}
			if err := validateE8PreparedPlan(
				mutated, prepared, workerPath, workerSHA,
			); err == nil {
				t.Fatal("mutated/resealed E5 process identity was accepted")
			}
		})
	}
	roots := prepareE8AuthenticatedRoots(
		t, fixture, planRoot, workerPath, workerSHA,
	)
	e7Path := filepath.Join(roots.e7Root, e7ReceiptFile)
	e7Before, err := os.ReadFile(e7Path)
	if err != nil || string(e7Before) != string(roots.e7Bytes) {
		t.Fatal("E7 input was not exact before rehearsal")
	}
	outputRoot := privateTestDirectory(t)
	// Model a hard stop inside E3 after the next contract/attempt and nonce
	// became durable but before a complete receipt was appended.
	partialSequence := fmt.Sprintf("%020d", firstE3.Sequence+1)
	if err := os.WriteFile(
		filepath.Join(cfg.StateRoot, admittedContractsDirectory, partialSequence+".json"),
		[]byte("{\"partial\":true}"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	partialAttempt := filepath.Join(
		cfg.StateRoot, admittedAttemptsDirectory, partialSequence,
	)
	if err := os.Mkdir(partialAttempt, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(partialAttempt, "controller-intent.json"),
		[]byte("{\"partial\":true}"), 0o400,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(cfg.StateRoot, admittedNonceFile),
		[]byte(strings.Repeat("f", 32)), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	oldCrashBoundary := e8CrashBoundaryOperation
	for _, crashStage := range []string{
		"after-e3-durable",
		"after-children-complete",
		"after-receipt-publication",
	} {
		crashed := false
		e8CrashBoundaryOperation = func(stage string) error {
			if stage == crashStage && !crashed {
				crashed = true
				return errors.New("injected hard-stop boundary at " + stage)
			}
			return nil
		}
		if _, err := runAdmittedE8Rehearsal(
			context.Background(), cfg, planRoot, roots.e6Root, roots.e7Root,
			roots.grantRoot, outputRoot, workerPath, workerSHA,
			prepared,
		); err == nil || !crashed {
			t.Fatalf(
				"E8 hard-stop boundary %s was not exercised: %v",
				crashStage, err,
			)
		}
	}
	e8CrashBoundaryOperation = oldCrashBoundary
	defer func() { e8CrashBoundaryOperation = oldCrashBoundary }()
	summary, err := runAdmittedE8Rehearsal(
		context.Background(), cfg, planRoot, roots.e6Root, roots.e7Root,
		roots.grantRoot, outputRoot, workerPath, workerSHA,
		prepared,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.RehearsalComplete || summary.NodeCount != 4 ||
		summary.ProviderAccess || summary.CredentialAccess ||
		summary.NetworkAccess || summary.LiveNodesContacted ||
		summary.SpendAuthorized || summary.Authority {
		t.Fatalf("unsafe E8 summary: %+v", summary)
	}
	e7After, err := os.ReadFile(e7Path)
	if err != nil || string(e7After) != string(e7Before) {
		t.Fatal("E8 changed or consumed production E7 evidence")
	}
	output, err := openAdmittedPrivateDirectory(outputRoot)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := output.ReadDir()
	if err != nil || len(entries) != 1 || entries[0].Name() != e8ReceiptFile {
		t.Fatalf("E8 output topology is not exact: %v %v", err, entries)
	}
	receiptFile, err := openAdmittedPrivateFileMode(
		output, e8ReceiptFile, os.O_RDONLY, 0, 0o400,
	)
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes, err := readBoundedE6File(receiptFile)
	if closeErr := receiptFile.Close(); err == nil {
		err = closeErr
	}
	if closeErr := output.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	var receipt e8Receipt
	if err := decodeStrictObject(receiptBytes, &receipt); err != nil {
		t.Fatal(err)
	}
	if err := validateE8Receipt(receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.E3Sequence != 2 || receipt.ProductionE7Consumed ||
		receipt.ExplicitAuthorityConsumed || receipt.Authority ||
		!receipt.SandboxEnforced {
		t.Fatalf("unsafe durable E8 receipt: %+v", receipt)
	}
	recovered, err := runAdmittedE8Rehearsal(
		context.Background(), cfg, planRoot, roots.e6Root, roots.e7Root,
		roots.grantRoot, outputRoot, workerPath, workerSHA,
		prepared,
	)
	if err != nil || recovered != summary {
		t.Fatalf("E8 committed retry was not idempotent: %+v %v", recovered, err)
	}
	log, err := openAdmittedReceiptLog(cfg.EvidenceRoot, cfg.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if log.count != 2 {
		t.Fatalf("E8 idempotent retry advanced E3 to %d receipts", log.count)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestE8SupervisorIdentityRejectsSameBytesAtDifferentInode(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, digest, err := openAndDigestPinnedFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	root := privateTestDirectory(t)
	copyPath := filepath.Join(root, "same-bytes-different-inode")
	if err := os.WriteFile(copyPath, data, 0o500); err != nil {
		t.Fatal(err)
	}
	if identity, err := verifyE8SupervisorIdentity(e6VerificationReceipt{
		SupervisorExecutablePath:   copyPath,
		SupervisorExecutableSHA256: digest,
	}); err == nil {
		if identity != nil {
			_ = identity.Close()
		}
		t.Fatal("E8 accepted mutable-path equivalence without inode equality")
	}
}
