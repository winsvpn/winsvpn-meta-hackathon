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

func physicalE6TestDirectory(t *testing.T) string {
	t.Helper()
	base := "/private/tmp"
	if info, err := os.Stat(base); err != nil || !info.IsDir() {
		base = "/tmp"
	}
	root, err := os.MkdirTemp(base, "winn-e6-command-test.")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

func signE6Fixture(
	t *testing.T, private ed25519.PrivateKey, domain string, value any,
) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	message := append(append([]byte(domain), 0), encoded...)
	return base64.StdEncoding.EncodeToString(ed25519.Sign(private, message))
}

func testEncodedE6Receipt(t *testing.T) (
	e6VerificationReceipt, []byte,
) {
	t.Helper()
	admission := testE5Admission(t)
	plan := e5FourNodePlan{
		RunID: "run-e6", CycleID: admission.CycleID,
		AttemptID: admission.AttemptID, TopologyID: admission.TopologyID,
		ObjectDigest:            strings.Repeat("a", 64),
		AdmissionBindingDigest:  admission.BindingDigest,
		AdmissionBundleSHA256:   admission.AdmissionBundleSHA256,
		RuntimeCollectionDigest: admission.RuntimeCollectionDigest,
		ReservationObjectDigest: admission.ReservationObjectDigest,
		AdmissionNonce:          admission.Nonce, CounterDomain: admission.CounterDomain,
		AcceptedCounter:   admission.AcceptedCounter,
		ExpectedTransport: admission.ExpectedTransport,
		StartNotBefore:    admission.StartNotBefore,
		StartDeadline:     admission.StartDeadline,
		FinishDeadline:    admission.FinishDeadline,
	}
	value, encoded, err := buildE6Receipt(
		plan, strings.Repeat("b", 64), testE6Result(admission, plan),
	)
	if err != nil {
		t.Fatal(err)
	}
	return value, encoded
}

func TestPublishE6ReceiptFailureBoundaries(t *testing.T) {
	value, encoded := testEncodedE6Receipt(t)
	for name, inject := range map[string]func() func(){
		"write": func() func() {
			old := writeAllOperation
			writeAllOperation = func(io.Writer, []byte) error {
				return io.ErrShortWrite
			}
			return func() { writeAllOperation = old }
		},
		"sync": func() func() {
			old := syncFileOperation
			syncFileOperation = func(*os.File) error {
				return errors.New("injected sync refusal")
			}
			return func() { syncFileOperation = old }
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := privateTestDirectory(t)
			directory, err := openAdmittedPrivateDirectory(root)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			restore := inject()
			defer restore()
			if err := publishE6Receipt(
				directory, encoded, value, "/missing/trust",
				realcycle.SealedHandoffResult{},
			); err == nil {
				t.Fatal("injected publication failure was accepted")
			}
			entries, err := directory.ReadDir()
			if err != nil || len(entries) != 0 {
				t.Fatalf("failed E6 publication left artifacts: %v %v", err, entries)
			}
		})
	}

	t.Run("no replace", func(t *testing.T) {
		root := privateTestDirectory(t)
		if err := os.WriteFile(
			filepath.Join(root, e6ReceiptFile), []byte("existing"), 0o400,
		); err != nil {
			t.Fatal(err)
		}
		directory, err := openAdmittedPrivateDirectory(root)
		if err != nil {
			t.Fatal(err)
		}
		defer directory.Close()
		if err := publishE6Receipt(
			directory, encoded, value, "/missing/trust",
			realcycle.SealedHandoffResult{},
		); err == nil {
			t.Fatal("E6 publication replaced an existing final")
		}
		data, err := os.ReadFile(filepath.Join(root, e6ReceiptFile))
		if err != nil || string(data) != "existing" {
			t.Fatal("existing E6 receipt was changed")
		}
	})

	t.Run("temporary close", func(t *testing.T) {
		root := privateTestDirectory(t)
		directory, err := openAdmittedPrivateDirectory(root)
		if err != nil {
			t.Fatal(err)
		}
		defer directory.Close()
		old := closeE6TemporaryOperation
		closeE6TemporaryOperation = func(*os.File) error {
			return errors.New("injected close refusal")
		}
		defer func() { closeE6TemporaryOperation = old }()
		if err := publishE6Receipt(
			directory, encoded, value, "/missing/trust",
			realcycle.SealedHandoffResult{},
		); err == nil {
			t.Fatal("temporary close failure was accepted")
		}
		entries, err := directory.ReadDir()
		if err != nil || len(entries) != 0 {
			t.Fatalf("close failure left artifacts: %v %v", err, entries)
		}
	})

	t.Run("rename", func(t *testing.T) {
		root := privateTestDirectory(t)
		directory, err := openAdmittedPrivateDirectory(root)
		if err != nil {
			t.Fatal(err)
		}
		defer directory.Close()
		old := renameE6NoReplaceOperation
		renameE6NoReplaceOperation = func(*secureDirectory, string) error {
			return errors.New("injected rename refusal")
		}
		defer func() { renameE6NoReplaceOperation = old }()
		if err := publishE6Receipt(
			directory, encoded, value, "/missing/trust",
			realcycle.SealedHandoffResult{},
		); err == nil {
			t.Fatal("rename failure was accepted")
		}
		entries, err := directory.ReadDir()
		if err != nil || len(entries) != 0 {
			t.Fatalf("rename failure left artifacts: %v %v", err, entries)
		}
	})

	t.Run("parent sync is indeterminate", func(t *testing.T) {
		root := privateTestDirectory(t)
		directory, err := openAdmittedPrivateDirectory(root)
		if err != nil {
			t.Fatal(err)
		}
		defer directory.Close()
		old := syncE6DirectoryOperation
		syncE6DirectoryOperation = func(*secureDirectory) error {
			return errors.New("injected directory sync refusal")
		}
		defer func() { syncE6DirectoryOperation = old }()
		err = publishE6Receipt(
			directory, encoded, value, "/missing/trust",
			realcycle.SealedHandoffResult{},
		)
		var publication *e6PublicationError
		if !errors.As(err, &publication) ||
			!publication.FinalReceiptMayExist ||
			publication.DirectorySynced ||
			publication.ReceiptAuthenticated ||
			publication.Stage != "parent-directory-fsync" {
			t.Fatalf("directory sync failure was not indeterminate: %v", err)
		}
		if _, err := os.Stat(filepath.Join(root, e6ReceiptFile)); err != nil {
			t.Fatalf("renamed receipt missing after indeterminate sync: %v", err)
		}
	})

	t.Run("durable readback is indeterminate", func(t *testing.T) {
		root := privateTestDirectory(t)
		directory, err := openAdmittedPrivateDirectory(root)
		if err != nil {
			t.Fatal(err)
		}
		defer directory.Close()
		old := readAuthenticatedE6ReceiptOperation
		readAuthenticatedE6ReceiptOperation = func(
			*secureDirectory, string,
		) (
			e6VerificationReceipt, realcycle.SealedHandoffResult, []byte, error,
		) {
			return e6VerificationReceipt{}, realcycle.SealedHandoffResult{},
				nil, errors.New("injected readback refusal")
		}
		defer func() { readAuthenticatedE6ReceiptOperation = old }()
		err = publishE6Receipt(
			directory, encoded, value, "/missing/trust",
			realcycle.SealedHandoffResult{},
		)
		var publication *e6PublicationError
		if !errors.As(err, &publication) ||
			!publication.FinalReceiptMayExist ||
			!publication.DirectorySynced ||
			publication.ReceiptAuthenticated ||
			publication.Stage != "durable-authenticated-readback" {
			t.Fatalf("readback failure was not indeterminate: %v", err)
		}
		if _, err := os.Stat(filepath.Join(root, e6ReceiptFile)); err != nil {
			t.Fatalf("durable receipt missing after readback refusal: %v", err)
		}
	})
}

func TestPublishE6ReceiptAuthenticatesDurableBytesEndToEnd(t *testing.T) {
	newKey := func(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
		t.Helper()
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return public, private
	}
	controllerPublic, controllerPrivate := newKey(t)
	dispatchPublic, dispatchPrivate := newKey(t)
	supervisorPublic, supervisorPrivate := newKey(t)
	trust := realcycle.TrustBundle{
		Schema: realcycle.TrustSchema, AcceptanceID: "accepted-e6-e2e",
		AcceptedAt: "2030-01-01T09:00:00Z",
		ExpiresAt:  "2030-01-01T11:00:00Z",
		Keys: []realcycle.TrustKey{{
			KeyID: "controller-e6-e2e", Role: realcycle.KeyRoleController,
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
	executableBytes := []byte("sealed supervisor executable\n")
	configBytes := []byte("{\"mode\":\"sealed\"}\n")
	if err := os.WriteFile(executablePath, executableBytes, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configBytes, 0o400); err != nil {
		t.Fatal(err)
	}
	expected := realcycle.HandoffExpectation{
		RunID: "run-e6-e2e", CycleID: "cycle-e6-e2e",
		AttemptID: "attempt-e6-e2e", TopologyID: "topology-e6-e2e",
		PlanSHA256:              strings.Repeat("1", 64),
		PlanObjectDigest:        strings.Repeat("2", 64),
		TrustSHA256:             admittedRawSHA(trustBytes),
		AdmissionBindingDigest:  strings.Repeat("3", 64),
		AdmissionBundleSHA256:   strings.Repeat("4", 64),
		RuntimeCollectionDigest: strings.Repeat("5", 64),
		ReservationObjectDigest: strings.Repeat("6", 64),
		AdmissionNonce:          strings.Repeat("a", 32),
		CounterDomain:           "counter-e6-e2e",
		AcceptedCounter:         100, LastObservedCounter: 107,
		ExpectedTransport: realcycle.TransportH3,
		StartNotBefore:    "2030-01-01T10:08:00Z",
		StartDeadline:     "2030-01-01T10:10:00Z",
		FinishDeadline:    "2030-01-01T10:20:00Z",
	}
	extension := realcycle.HandoffRoleExtension{
		Schema:     realcycle.HandoffRoleExtensionSchema,
		State:      "public-key-extension-only",
		PlanSHA256: expected.PlanSHA256, PlanObjectDigest: expected.PlanObjectDigest,
		AcceptedTrustSHA256: expected.TrustSHA256,
		Keys: [2]realcycle.HandoffRoleKey{
			{
				KeyID:     "dispatch-e6-e2e",
				Role:      realcycle.KeyRoleDispatchAuthorizer,
				PublicKey: base64.StdEncoding.EncodeToString(dispatchPublic),
			},
			{
				KeyID:     "supervisor-e6-e2e",
				Role:      realcycle.KeyRoleExecutionSupervisor,
				PublicKey: base64.StdEncoding.EncodeToString(supervisorPublic),
			},
		},
		ControllerKeyID: "controller-e6-e2e",
	}
	extension.Signature = signE6Fixture(
		t, controllerPrivate,
		"winn-real-cycle-handoff-role-extension-signature/v1",
		extension,
	)
	authorization := realcycle.AuthorizationCommitment{
		Schema: realcycle.AuthorizationCommitmentSchema,
		State:  "sealed-pending-activation", Scope: "execute-one-four-node-cycle",
		RunID: expected.RunID, CycleID: expected.CycleID,
		AttemptID: expected.AttemptID, TopologyID: expected.TopologyID,
		PlanSHA256: expected.PlanSHA256, PlanObjectDigest: expected.PlanObjectDigest,
		AdmissionBindingDigest:  expected.AdmissionBindingDigest,
		AdmissionBundleSHA256:   expected.AdmissionBundleSHA256,
		RuntimeCollectionDigest: expected.RuntimeCollectionDigest,
		ReservationObjectDigest: expected.ReservationObjectDigest,
		AdmissionNonce:          expected.AdmissionNonce,
		CounterDomain:           expected.CounterDomain, MinimumActivationCounter: 108,
		ValidNotBefore: expected.StartNotBefore, ValidNotAfter: expected.StartDeadline,
		MaxRuntimeAgeSeconds: 300, MaxExecutionSeconds: 600,
		OneTimeNonce:    strings.Repeat("b", 32),
		AuthorizerKeyID: "dispatch-e6-e2e",
	}
	authorization.Signature = signE6Fixture(
		t, dispatchPrivate,
		"winn-real-cycle-authorization-commitment-signature/v1",
		authorization,
	)
	supervisor := realcycle.SupervisorCommitment{
		Schema: realcycle.SupervisorCommitmentSchema,
		State:  "sealed-pending-activation",
		RunID:  expected.RunID, CycleID: expected.CycleID,
		AttemptID: expected.AttemptID, TopologyID: expected.TopologyID,
		PlanSHA256: expected.PlanSHA256, PlanObjectDigest: expected.PlanObjectDigest,
		ExpectedTransport:          expected.ExpectedTransport,
		SupervisorExecutablePath:   executablePath,
		SupervisorExecutableSHA256: admittedRawSHA(executableBytes),
		SupervisorConfigPath:       configPath,
		SupervisorConfigSHA256:     admittedRawSHA(configBytes),
		MaxExecutionSeconds:        600, OneTimeNonce: strings.Repeat("b", 32),
		SupervisorKeyID: "supervisor-e6-e2e",
	}
	supervisor.Signature = signE6Fixture(
		t, supervisorPrivate,
		"winn-real-cycle-supervisor-commitment-signature/v1",
		supervisor,
	)
	handoffRoot := privateTestDirectory(t)
	for name, value := range map[string]any{
		realcycle.AuthorizationCommitmentFile: authorization,
		realcycle.HandoffRoleExtensionFile:    extension,
		realcycle.SupervisorCommitmentFile:    supervisor,
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, '\n')
		if err := os.WriteFile(filepath.Join(handoffRoot, name), encoded, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	result, err := realcycle.ValidateSealedHandoff(
		handoffRoot, trustPath, expected,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan := e5FourNodePlan{
		RunID: expected.RunID, CycleID: expected.CycleID,
		AttemptID: expected.AttemptID, TopologyID: expected.TopologyID,
		ObjectDigest:            expected.PlanObjectDigest,
		AdmissionBindingDigest:  expected.AdmissionBindingDigest,
		AdmissionBundleSHA256:   expected.AdmissionBundleSHA256,
		RuntimeCollectionDigest: expected.RuntimeCollectionDigest,
		ReservationObjectDigest: expected.ReservationObjectDigest,
		AdmissionNonce:          expected.AdmissionNonce, CounterDomain: expected.CounterDomain,
		AcceptedCounter:   expected.AcceptedCounter,
		ExpectedTransport: expected.ExpectedTransport,
		StartNotBefore:    expected.StartNotBefore, StartDeadline: expected.StartDeadline,
		FinishDeadline: expected.FinishDeadline,
	}
	receipt, encoded, err := buildE6Receipt(plan, expected.PlanSHA256, result)
	if err != nil {
		t.Fatal(err)
	}
	receiptRoot := privateTestDirectory(t)
	directory, err := openAdmittedPrivateDirectory(receiptRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := publishE6Receipt(
		directory, encoded, receipt, trustPath, result,
	); err != nil {
		t.Fatal(err)
	}
	replayed, authenticated, raw, err := readAuthenticatedE6Receipt(
		directory, trustPath,
	)
	if err != nil || replayed != receipt || authenticated != result ||
		string(raw) != string(encoded) {
		t.Fatalf("durable authenticated receipt mismatch: %v", err)
	}
	tampered := receipt
	tampered.AuthorizationSignature = base64.StdEncoding.EncodeToString(
		make([]byte, ed25519.SignatureSize),
	)
	_, tamperedBytes, err := encodeE6Receipt(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseE6ReceiptStructure(tamperedBytes); err != nil {
		t.Fatalf("tampered receipt should remain structurally valid: %v", err)
	}
	if _, _, err := parseAuthenticatedE6Receipt(
		tamperedBytes, trustPath,
	); err == nil {
		t.Fatal("cryptographically invalid durable receipt authenticated")
	}
}
