//go:build linux

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

func TestE7DurableAuthorizationReceiptEndToEndAndNonauthorizing(
	t *testing.T,
) {
	dispatchPublic, dispatchPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	supervisorPublic, supervisorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identityRoot := physicalE6TestDirectory(t)
	executablePath := filepath.Join(identityRoot, "supervisor")
	configPath := filepath.Join(identityRoot, "supervisor.json")
	executableBytes := []byte("E7 supervisor executable\n")
	configBytes := []byte("{\"mode\":\"e7\"}\n")
	if err := os.WriteFile(executablePath, executableBytes, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configBytes, 0o400); err != nil {
		t.Fatal(err)
	}
	expected := realcycle.ExecutionAuthorizationExpectation{
		RunID: "run-e7", CycleID: "cycle-e7",
		AttemptID: "attempt-e7", TopologyID: "topology-e7",
		PlanSHA256:                 strings.Repeat("1", 64),
		PlanObjectDigest:           strings.Repeat("2", 64),
		TrustSHA256:                strings.Repeat("3", 64),
		E6ReceiptSHA256:            strings.Repeat("4", 64),
		E6ReceiptObjectDigest:      strings.Repeat("5", 64),
		HandoffCollectionDigest:    strings.Repeat("6", 64),
		OneTimeNonce:               strings.Repeat("a", 32),
		MinimumActivationCounter:   108,
		LastObservedCounter:        107,
		ValidNotBefore:             "2030-01-01T10:08:00Z",
		ValidNotAfter:              "2030-01-01T10:10:00Z",
		MaxExecutionSeconds:        600,
		SupervisorExecutablePath:   executablePath,
		SupervisorExecutableSHA256: admittedRawSHA(executableBytes),
		SupervisorConfigPath:       configPath,
		SupervisorConfigSHA256:     admittedRawSHA(configBytes),
		RoleKeys: [2]realcycle.HandoffRoleKey{
			{
				KeyID: "dispatch-e7", Role: realcycle.KeyRoleDispatchAuthorizer,
				PublicKey: base64.StdEncoding.EncodeToString(dispatchPublic),
			},
			{
				KeyID: "supervisor-e7", Role: realcycle.KeyRoleExecutionSupervisor,
				PublicKey: base64.StdEncoding.EncodeToString(supervisorPublic),
			},
		},
	}
	decision := realcycle.ExecutionAuthorization{
		Schema:     realcycle.ExecutionAuthorizationSchema,
		State:      "explicit-authority-input-only",
		Scope:      "one-provider-neutral-supervisor-execution",
		DecisionID: "decision-e7",
		RunID:      expected.RunID, CycleID: expected.CycleID,
		AttemptID: expected.AttemptID, TopologyID: expected.TopologyID,
		PlanSHA256:                 expected.PlanSHA256,
		PlanObjectDigest:           expected.PlanObjectDigest,
		TrustSHA256:                expected.TrustSHA256,
		E6ReceiptSHA256:            expected.E6ReceiptSHA256,
		E6ReceiptObjectDigest:      expected.E6ReceiptObjectDigest,
		HandoffCollectionDigest:    expected.HandoffCollectionDigest,
		OneTimeNonce:               expected.OneTimeNonce,
		ActivationCounter:          expected.MinimumActivationCounter,
		ValidNotBefore:             expected.ValidNotBefore,
		ValidNotAfter:              expected.ValidNotAfter,
		MaxExecutionSeconds:        expected.MaxExecutionSeconds,
		SupervisorExecutablePath:   expected.SupervisorExecutablePath,
		SupervisorExecutableSHA256: expected.SupervisorExecutableSHA256,
		SupervisorConfigPath:       expected.SupervisorConfigPath,
		SupervisorConfigSHA256:     expected.SupervisorConfigSHA256,
		AuthorizerKeyID:            expected.RoleKeys[0].KeyID,
	}
	decision.Signature = signE6Fixture(
		t, dispatchPrivate,
		"winn-real-cycle-explicit-execution-authorization-signature/v1",
		decision,
	)
	decisionBytes, err := json.Marshal(decision)
	if err != nil {
		t.Fatal(err)
	}
	decisionBytes = append(decisionBytes, '\n')
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
		E6ReceiptSHA256:       expected.E6ReceiptSHA256,
		E6ReceiptObjectDigest: expected.E6ReceiptObjectDigest,
		RunID:                 expected.RunID, CycleID: expected.CycleID,
		AttemptID: expected.AttemptID, TopologyID: expected.TopologyID,
		OneTimeNonce:               expected.OneTimeNonce,
		ActivationCounter:          expected.MinimumActivationCounter,
		SupervisorExecutablePath:   expected.SupervisorExecutablePath,
		SupervisorExecutableSHA256: expected.SupervisorExecutableSHA256,
		SupervisorConfigPath:       expected.SupervisorConfigPath,
		SupervisorConfigSHA256:     expected.SupervisorConfigSHA256,
		SupervisorKeyID:            expected.RoleKeys[1].KeyID,
	}
	acceptance.Signature = signE6Fixture(
		t, supervisorPrivate,
		"winn-real-cycle-supervisor-authorization-acceptance-signature/v1",
		acceptance,
	)
	result, err := realcycle.VerifyExecutionAuthorizationObjects(
		expected, decision, acceptance,
	)
	if err != nil {
		t.Fatal(err)
	}
	e6 := e6VerificationReceipt{
		ObjectDigest: expected.E6ReceiptObjectDigest,
	}
	receipt, encoded, err := buildE7Receipt(
		e6, expected.E6ReceiptSHA256, decision, acceptance, result,
	)
	if err != nil {
		t.Fatal(err)
	}
	root := privateTestDirectory(t)
	directory, err := openAdmittedPrivateDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := publishE7Receipt(
		directory, encoded, receipt, expected, result,
	); err != nil {
		t.Fatal(err)
	}
	replayed, authenticated, raw, err := readAuthenticatedE7Receipt(
		directory, expected,
	)
	if err != nil || replayed != receipt || authenticated != result ||
		string(raw) != string(encoded) {
		t.Fatalf("E7 durable authenticated replay failed: %v", err)
	}
	if replayed.SecureTimeObserved ||
		replayed.ActivationCounterReserved ||
		replayed.LiveRuntimeRechecked ||
		replayed.CredentialHandleReleased ||
		replayed.ExplicitAuthorityConsumed ||
		replayed.SupervisorExecuted || replayed.DispatchAuthorized ||
		replayed.ExternalTopologyExecuted || replayed.ProviderAccess ||
		replayed.CredentialAccess || replayed.NetworkAccess ||
		replayed.LiveNodesContacted || replayed.SpendAuthorized ||
		replayed.HandoffReady || replayed.Authority {
		t.Fatalf("E7 granted authority: %+v", replayed)
	}
	tampered := receipt
	tampered.ExecutionAuthorization.Signature =
		base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	_, tamperedBytes, err := encodeE7Receipt(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseE7ReceiptStructure(tamperedBytes); err != nil {
		t.Fatalf("tampered receipt should remain structurally exact: %v", err)
	}
	tamperedValue, err := parseE7ReceiptStructure(tamperedBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyE7ReceiptProjection(
		tamperedValue, expected,
	); err == nil {
		t.Fatal("E7 accepted re-digested invalid authority signature")
	}
	outerDrift := receipt
	outerDrift.E6ReceiptSHA256 = strings.Repeat("f", 64)
	outerDrift.E6ReceiptObjectDigest = strings.Repeat("e", 64)
	_, outerDriftBytes, err := encodeE7Receipt(outerDrift)
	if err != nil {
		t.Fatal(err)
	}
	outerDriftValue, err := parseE7ReceiptStructure(outerDriftBytes)
	if err != nil {
		t.Fatalf("outer E6 mutant should remain structurally exact: %v", err)
	}
	if _, err := verifyE7ReceiptProjection(
		outerDriftValue, expected,
	); err == nil {
		t.Fatal("E7 accepted re-digested incoherent outer E6 tuple")
	}

	for name, inject := range map[string]func() func(){
		"write": func() func() {
			old := writeAllOperation
			writeAllOperation = func(io.Writer, []byte) error {
				return io.ErrShortWrite
			}
			return func() { writeAllOperation = old }
		},
		"file sync": func() func() {
			old := syncFileOperation
			syncFileOperation = func(*os.File) error {
				return errors.New("injected E7 file sync refusal")
			}
			return func() { syncFileOperation = old }
		},
		"temporary close": func() func() {
			old := closeE7TemporaryOperation
			closeE7TemporaryOperation = func(*os.File) error {
				return errors.New("injected E7 close refusal")
			}
			return func() { closeE7TemporaryOperation = old }
		},
		"rename": func() func() {
			old := renameE7NoReplaceOperation
			renameE7NoReplaceOperation = func(
				*secureDirectory, string,
			) error {
				return errors.New("injected E7 rename refusal")
			}
			return func() { renameE7NoReplaceOperation = old }
		},
	} {
		t.Run(name, func(t *testing.T) {
			failureRoot := privateTestDirectory(t)
			failureDirectory, err := openAdmittedPrivateDirectory(failureRoot)
			if err != nil {
				t.Fatal(err)
			}
			defer failureDirectory.Close()
			restore := inject()
			defer restore()
			if err := publishE7Receipt(
				failureDirectory, encoded, receipt, expected, result,
			); err == nil {
				t.Fatal("injected E7 pre-rename failure was accepted")
			}
			entries, err := failureDirectory.ReadDir()
			if err != nil || len(entries) != 0 {
				t.Fatalf("E7 pre-rename failure left artifacts: %v %v", err, entries)
			}
		})
	}

	t.Run("parent sync indeterminate", func(t *testing.T) {
		failureRoot := privateTestDirectory(t)
		failureDirectory, err := openAdmittedPrivateDirectory(failureRoot)
		if err != nil {
			t.Fatal(err)
		}
		defer failureDirectory.Close()
		old := syncE7DirectoryOperation
		syncE7DirectoryOperation = func(*secureDirectory) error {
			return errors.New("injected E7 directory sync refusal")
		}
		defer func() { syncE7DirectoryOperation = old }()
		err = publishE7Receipt(
			failureDirectory, encoded, receipt, expected, result,
		)
		var publication *e6PublicationError
		if !errors.As(err, &publication) ||
			!publication.FinalReceiptMayExist ||
			publication.DirectorySynced ||
			publication.ReceiptAuthenticated ||
			publication.Stage != "E7-parent-directory-fsync" {
			t.Fatalf("E7 directory sync failure was not indeterminate: %v", err)
		}
	})

	t.Run("authenticated readback indeterminate", func(t *testing.T) {
		failureRoot := privateTestDirectory(t)
		failureDirectory, err := openAdmittedPrivateDirectory(failureRoot)
		if err != nil {
			t.Fatal(err)
		}
		defer failureDirectory.Close()
		old := readAuthenticatedE7ReceiptOperation
		readAuthenticatedE7ReceiptOperation = func(
			*secureDirectory,
			realcycle.ExecutionAuthorizationExpectation,
		) (
			e7VerificationReceipt,
			realcycle.ExecutionAuthorizationResult,
			[]byte,
			error,
		) {
			return e7VerificationReceipt{},
				realcycle.ExecutionAuthorizationResult{}, nil,
				errors.New("injected E7 readback refusal")
		}
		defer func() { readAuthenticatedE7ReceiptOperation = old }()
		err = publishE7Receipt(
			failureDirectory, encoded, receipt, expected, result,
		)
		var publication *e6PublicationError
		if !errors.As(err, &publication) ||
			!publication.FinalReceiptMayExist ||
			!publication.DirectorySynced ||
			publication.ReceiptAuthenticated ||
			publication.Stage != "E7-durable-authenticated-readback" {
			t.Fatalf("E7 readback failure was not indeterminate: %v", err)
		}
	})

	t.Run("directory identity indeterminate", func(t *testing.T) {
		failureRoot := privateTestDirectory(t)
		failureDirectory, err := openAdmittedPrivateDirectory(failureRoot)
		if err != nil {
			t.Fatal(err)
		}
		defer failureDirectory.Close()
		old := verifyE7DirectoryOperation
		verifyE7DirectoryOperation = func(*secureDirectory) error {
			return errors.New("injected E7 directory identity refusal")
		}
		defer func() { verifyE7DirectoryOperation = old }()
		err = publishE7Receipt(
			failureDirectory, encoded, receipt, expected, result,
		)
		var publication *e6PublicationError
		if !errors.As(err, &publication) ||
			!publication.FinalReceiptMayExist ||
			!publication.DirectorySynced ||
			!publication.ReceiptAuthenticated ||
			publication.Stage != "E7-postpublication-directory-identity" {
			t.Fatalf("E7 directory identity failure was not indeterminate: %v", err)
		}
	})

	t.Run("no replace", func(t *testing.T) {
		failureRoot := privateTestDirectory(t)
		if err := os.WriteFile(
			filepath.Join(failureRoot, e7ReceiptFile),
			[]byte("existing"), 0o400,
		); err != nil {
			t.Fatal(err)
		}
		failureDirectory, err := openAdmittedPrivateDirectory(failureRoot)
		if err != nil {
			t.Fatal(err)
		}
		defer failureDirectory.Close()
		if err := publishE7Receipt(
			failureDirectory, encoded, receipt, expected, result,
		); err == nil {
			t.Fatal("E7 replaced an existing final receipt")
		}
		data, err := os.ReadFile(filepath.Join(failureRoot, e7ReceiptFile))
		if err != nil || string(data) != "existing" {
			t.Fatal("E7 changed an existing final receipt")
		}
	})
}

func TestRunE7AuthenticatesDurableE6AndFinalReplay(t *testing.T) {
	newKey := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return public, private
	}
	controllerPublic, controllerPrivate := newKey()
	dispatchPublic, dispatchPrivate := newKey()
	supervisorPublic, supervisorPrivate := newKey()
	trust := realcycle.TrustBundle{
		Schema:       realcycle.TrustSchema,
		AcceptanceID: "accepted-e7-run",
		AcceptedAt:   "2030-01-01T09:00:00Z",
		ExpiresAt:    "2030-01-01T11:00:00Z",
		Keys: []realcycle.TrustKey{{
			KeyID:     "controller-e7-run",
			Role:      realcycle.KeyRoleController,
			PublicKey: base64.StdEncoding.EncodeToString(controllerPublic),
		}},
	}
	trustBytes, err := json.Marshal(trust)
	if err != nil {
		t.Fatal(err)
	}
	trustBytes = append(trustBytes, '\n')
	trustRoot := privateTestDirectory(t)
	trustPath := filepath.Join(trustRoot, "trust.json")
	if err := os.WriteFile(trustPath, trustBytes, 0o400); err != nil {
		t.Fatal(err)
	}
	identityRoot := physicalE6TestDirectory(t)
	executablePath := filepath.Join(identityRoot, "supervisor")
	configPath := filepath.Join(identityRoot, "supervisor.json")
	executableBytes := []byte("E7 run supervisor executable\n")
	configBytes := []byte("{\"mode\":\"e7-run\"}\n")
	if err := os.WriteFile(executablePath, executableBytes, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configBytes, 0o400); err != nil {
		t.Fatal(err)
	}
	handoffExpected := realcycle.HandoffExpectation{
		RunID: "run-e7-real", CycleID: "cycle-e7-real",
		AttemptID: "attempt-e7-real", TopologyID: "topology-e7-real",
		PlanSHA256:              strings.Repeat("1", 64),
		PlanObjectDigest:        strings.Repeat("2", 64),
		TrustSHA256:             admittedRawSHA(trustBytes),
		AdmissionBindingDigest:  strings.Repeat("3", 64),
		AdmissionBundleSHA256:   strings.Repeat("4", 64),
		RuntimeCollectionDigest: strings.Repeat("5", 64),
		ReservationObjectDigest: strings.Repeat("6", 64),
		AdmissionNonce:          strings.Repeat("a", 32),
		CounterDomain:           "counter-e7-real",
		AcceptedCounter:         100, LastObservedCounter: 107,
		ExpectedTransport: realcycle.TransportH3,
		StartNotBefore:    "2030-01-01T10:08:00Z",
		StartDeadline:     "2030-01-01T10:10:00Z",
		FinishDeadline:    "2030-01-01T10:20:00Z",
	}
	extension := realcycle.HandoffRoleExtension{
		Schema:              realcycle.HandoffRoleExtensionSchema,
		State:               "public-key-extension-only",
		PlanSHA256:          handoffExpected.PlanSHA256,
		PlanObjectDigest:    handoffExpected.PlanObjectDigest,
		AcceptedTrustSHA256: handoffExpected.TrustSHA256,
		Keys: [2]realcycle.HandoffRoleKey{
			{
				KeyID:     "dispatch-e7-run",
				Role:      realcycle.KeyRoleDispatchAuthorizer,
				PublicKey: base64.StdEncoding.EncodeToString(dispatchPublic),
			},
			{
				KeyID:     "supervisor-e7-run",
				Role:      realcycle.KeyRoleExecutionSupervisor,
				PublicKey: base64.StdEncoding.EncodeToString(supervisorPublic),
			},
		},
		ControllerKeyID: "controller-e7-run",
	}
	extension.Signature = signE6Fixture(
		t, controllerPrivate,
		"winn-real-cycle-handoff-role-extension-signature/v1",
		extension,
	)
	authorization := realcycle.AuthorizationCommitment{
		Schema: realcycle.AuthorizationCommitmentSchema,
		State:  "sealed-pending-activation",
		Scope:  "execute-one-four-node-cycle",
		RunID:  handoffExpected.RunID, CycleID: handoffExpected.CycleID,
		AttemptID:                handoffExpected.AttemptID,
		TopologyID:               handoffExpected.TopologyID,
		PlanSHA256:               handoffExpected.PlanSHA256,
		PlanObjectDigest:         handoffExpected.PlanObjectDigest,
		AdmissionBindingDigest:   handoffExpected.AdmissionBindingDigest,
		AdmissionBundleSHA256:    handoffExpected.AdmissionBundleSHA256,
		RuntimeCollectionDigest:  handoffExpected.RuntimeCollectionDigest,
		ReservationObjectDigest:  handoffExpected.ReservationObjectDigest,
		AdmissionNonce:           handoffExpected.AdmissionNonce,
		CounterDomain:            handoffExpected.CounterDomain,
		MinimumActivationCounter: 108,
		ValidNotBefore:           handoffExpected.StartNotBefore,
		ValidNotAfter:            handoffExpected.StartDeadline,
		MaxRuntimeAgeSeconds:     300, MaxExecutionSeconds: 600,
		OneTimeNonce:    strings.Repeat("b", 32),
		AuthorizerKeyID: "dispatch-e7-run",
	}
	authorization.Signature = signE6Fixture(
		t, dispatchPrivate,
		"winn-real-cycle-authorization-commitment-signature/v1",
		authorization,
	)
	supervisor := realcycle.SupervisorCommitment{
		Schema: realcycle.SupervisorCommitmentSchema,
		State:  "sealed-pending-activation",
		RunID:  handoffExpected.RunID, CycleID: handoffExpected.CycleID,
		AttemptID:                  handoffExpected.AttemptID,
		TopologyID:                 handoffExpected.TopologyID,
		PlanSHA256:                 handoffExpected.PlanSHA256,
		PlanObjectDigest:           handoffExpected.PlanObjectDigest,
		ExpectedTransport:          handoffExpected.ExpectedTransport,
		SupervisorExecutablePath:   executablePath,
		SupervisorExecutableSHA256: admittedRawSHA(executableBytes),
		SupervisorConfigPath:       configPath,
		SupervisorConfigSHA256:     admittedRawSHA(configBytes),
		MaxExecutionSeconds:        600, OneTimeNonce: strings.Repeat("b", 32),
		SupervisorKeyID: "supervisor-e7-run",
	}
	supervisor.Signature = signE6Fixture(
		t, supervisorPrivate,
		"winn-real-cycle-supervisor-commitment-signature/v1",
		supervisor,
	)
	handoffResult, err := realcycle.VerifySealedHandoffObjects(
		trustPath, handoffExpected, authorization, extension, supervisor,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan := e5FourNodePlan{
		RunID: handoffExpected.RunID, CycleID: handoffExpected.CycleID,
		AttemptID:               handoffExpected.AttemptID,
		TopologyID:              handoffExpected.TopologyID,
		ObjectDigest:            handoffExpected.PlanObjectDigest,
		AdmissionBindingDigest:  handoffExpected.AdmissionBindingDigest,
		AdmissionBundleSHA256:   handoffExpected.AdmissionBundleSHA256,
		RuntimeCollectionDigest: handoffExpected.RuntimeCollectionDigest,
		ReservationObjectDigest: handoffExpected.ReservationObjectDigest,
		AdmissionNonce:          handoffExpected.AdmissionNonce,
		CounterDomain:           handoffExpected.CounterDomain,
		AcceptedCounter:         handoffExpected.AcceptedCounter,
		ExpectedTransport:       handoffExpected.ExpectedTransport,
		StartNotBefore:          handoffExpected.StartNotBefore,
		StartDeadline:           handoffExpected.StartDeadline,
		FinishDeadline:          handoffExpected.FinishDeadline,
	}
	e6, e6Bytes, err := buildE6Receipt(
		plan, handoffExpected.PlanSHA256, handoffResult,
	)
	if err != nil {
		t.Fatal(err)
	}
	e6Root := privateTestDirectory(t)
	e6Directory, err := openAdmittedPrivateDirectory(e6Root)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishE6Receipt(
		e6Directory, e6Bytes, e6, trustPath, handoffResult,
	); err != nil {
		t.Fatal(err)
	}
	if err := e6Directory.Close(); err != nil {
		t.Fatal(err)
	}
	expected := e7Expectation(e6, admittedRawSHA(e6Bytes))
	decision := realcycle.ExecutionAuthorization{
		Schema:     realcycle.ExecutionAuthorizationSchema,
		State:      "explicit-authority-input-only",
		Scope:      "one-provider-neutral-supervisor-execution",
		DecisionID: "decision-e7-real",
		RunID:      expected.RunID, CycleID: expected.CycleID,
		AttemptID: expected.AttemptID, TopologyID: expected.TopologyID,
		PlanSHA256:                 expected.PlanSHA256,
		PlanObjectDigest:           expected.PlanObjectDigest,
		TrustSHA256:                expected.TrustSHA256,
		E6ReceiptSHA256:            expected.E6ReceiptSHA256,
		E6ReceiptObjectDigest:      expected.E6ReceiptObjectDigest,
		HandoffCollectionDigest:    expected.HandoffCollectionDigest,
		OneTimeNonce:               expected.OneTimeNonce,
		ActivationCounter:          expected.MinimumActivationCounter,
		ValidNotBefore:             expected.ValidNotBefore,
		ValidNotAfter:              expected.ValidNotAfter,
		MaxExecutionSeconds:        expected.MaxExecutionSeconds,
		SupervisorExecutablePath:   expected.SupervisorExecutablePath,
		SupervisorExecutableSHA256: expected.SupervisorExecutableSHA256,
		SupervisorConfigPath:       expected.SupervisorConfigPath,
		SupervisorConfigSHA256:     expected.SupervisorConfigSHA256,
		AuthorizerKeyID:            "dispatch-e7-run",
	}
	decision.Signature = signE6Fixture(
		t, dispatchPrivate,
		"winn-real-cycle-explicit-execution-authorization-signature/v1",
		decision,
	)
	decisionBytes, err := json.Marshal(decision)
	if err != nil {
		t.Fatal(err)
	}
	decisionBytes = append(decisionBytes, '\n')
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
		E6ReceiptSHA256:       expected.E6ReceiptSHA256,
		E6ReceiptObjectDigest: expected.E6ReceiptObjectDigest,
		RunID:                 expected.RunID, CycleID: expected.CycleID,
		AttemptID: expected.AttemptID, TopologyID: expected.TopologyID,
		OneTimeNonce:               expected.OneTimeNonce,
		ActivationCounter:          expected.MinimumActivationCounter,
		SupervisorExecutablePath:   expected.SupervisorExecutablePath,
		SupervisorExecutableSHA256: expected.SupervisorExecutableSHA256,
		SupervisorConfigPath:       expected.SupervisorConfigPath,
		SupervisorConfigSHA256:     expected.SupervisorConfigSHA256,
		SupervisorKeyID:            "supervisor-e7-run",
	}
	acceptance.Signature = signE6Fixture(
		t, supervisorPrivate,
		"winn-real-cycle-supervisor-authorization-acceptance-signature/v1",
		acceptance,
	)
	inputRoot := privateTestDirectory(t)
	for name, value := range map[string]any{
		realcycle.ExecutionAuthorizationFile:            decision,
		realcycle.SupervisorAuthorizationAcceptanceFile: acceptance,
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, '\n')
		if err := os.WriteFile(filepath.Join(inputRoot, name), encoded, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	cfg := minimallyShapedAdmittedConfig(t)
	cfg.RunID = expected.RunID
	cfg.TrustPath = trustPath
	outputRoot := privateTestDirectory(t)
	summary, err := runAdmittedE7Authorization(
		t.Context(), cfg, e6Root, inputRoot, outputRoot,
	)
	if err != nil {
		t.Fatal(err)
	}
	if summary.DecisionID != decision.DecisionID ||
		summary.DispatchAuthorized || summary.ProviderAccess ||
		summary.CredentialAccess || summary.NetworkAccess ||
		summary.LiveNodesContacted || summary.SpendAuthorized ||
		summary.HandoffReady || summary.Authority {
		t.Fatalf("unsafe E7 run summary: %+v", summary)
	}

	oldRead := readE7SourceE6ReceiptOperation
	readCount := 0
	readE7SourceE6ReceiptOperation = func(
		directory *secureDirectory, trustPath string,
	) (
		e6VerificationReceipt, realcycle.SealedHandoffResult, []byte, error,
	) {
		readCount++
		if readCount == 3 {
			return e6VerificationReceipt{}, realcycle.SealedHandoffResult{},
				nil, errors.New("injected final E6 replay refusal")
		}
		return readAuthenticatedE6Receipt(directory, trustPath)
	}
	defer func() { readE7SourceE6ReceiptOperation = oldRead }()
	indeterminateRoot := privateTestDirectory(t)
	_, err = runAdmittedE7Authorization(
		t.Context(), cfg, e6Root, inputRoot, indeterminateRoot,
	)
	var publication *e6PublicationError
	if !errors.As(err, &publication) ||
		publication.Stage != "E7-postpublication-E6-authenticated-replay" ||
		!publication.FinalReceiptMayExist ||
		!publication.DirectorySynced ||
		!publication.ReceiptAuthenticated {
		t.Fatalf("final E6 replay failure was not indeterminate: %v", err)
	}
	if _, err := os.Stat(
		filepath.Join(indeterminateRoot, e7ReceiptFile),
	); err != nil {
		t.Fatalf("indeterminate E7 run lost durable receipt: %v", err)
	}
}
