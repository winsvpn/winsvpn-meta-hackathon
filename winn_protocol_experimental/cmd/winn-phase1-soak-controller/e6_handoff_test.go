package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

func testE6Result(
	admission realcycle.AdmissionResult, plan e5FourNodePlan,
) realcycle.SealedHandoffResult {
	signature := base64.StdEncoding.EncodeToString(make([]byte, 64))
	firstKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	secondBytes := make([]byte, 32)
	secondBytes[0] = 1
	secondKey := base64.StdEncoding.EncodeToString(secondBytes)
	return realcycle.SealedHandoffResult{
		TrustSHA256:         strings.Repeat("9", 64),
		AcceptedCounter:     admission.AcceptedCounter,
		LastObservedCounter: admission.LastObservedCounter,
		ExpectedTransport:   plan.ExpectedTransport,
		StartNotBefore:      plan.StartNotBefore, StartDeadline: plan.StartDeadline,
		FinishDeadline:               plan.FinishDeadline,
		AuthorizationSHA256:          strings.Repeat("1", 64),
		AuthorizationObjectDigest:    strings.Repeat("2", 64),
		RoleExtensionSHA256:          strings.Repeat("8", 64),
		RoleExtensionObjectDigest:    strings.Repeat("9", 64),
		RoleExtensionControllerKeyID: "controller-key",
		RoleExtensionSignature:       signature,
		RoleExtensionKeys: [2]realcycle.HandoffRoleKey{
			{KeyID: "dispatch-key", Role: realcycle.KeyRoleDispatchAuthorizer,
				PublicKey: firstKey},
			{KeyID: "supervisor-key", Role: realcycle.KeyRoleExecutionSupervisor,
				PublicKey: secondKey},
		},
		AuthorizationKeyID: "dispatch-key", AuthorizationSignature: signature,
		SupervisorSHA256:       strings.Repeat("3", 64),
		SupervisorObjectDigest: strings.Repeat("4", 64),
		SupervisorKeyID:        "supervisor-key", SupervisorSignature: signature,
		CollectionDigest:         strings.Repeat("5", 64),
		MinimumActivationCounter: admission.LastObservedCounter + 1,
		ValidNotBefore:           plan.StartNotBefore, ValidNotAfter: plan.StartDeadline,
		MaxRuntimeAgeSeconds: 300, MaxExecutionSeconds: 60,
		OneTimeNonce:               strings.Repeat("a", 32),
		SupervisorExecutablePath:   "/opt/winn/bin/winn-execution-supervisor",
		SupervisorExecutableSHA256: strings.Repeat("6", 64),
		SupervisorConfigPath:       "/etc/winn/execution-supervisor.json",
		SupervisorConfigSHA256:     strings.Repeat("7", 64),
	}
}

func TestE6ReceiptRemainsPendingAndNonauthorizing(t *testing.T) {
	admission := testE5Admission(t)
	receipt := validAdmittedReceipt()
	receipt.ObjectDigest = strings.Repeat("c", 64)
	receipt.AdmissionBundleSHA256 = admission.AdmissionBundleSHA256
	receipt.AdmissionBindingDigest = admission.BindingDigest
	receipt.RuntimeCollectionDigest = admission.RuntimeCollectionDigest
	receipt.ReservationObjectDigest = admission.ReservationObjectDigest
	receipt.Result.CycleID, receipt.Result.AttemptID =
		admission.CycleID, admission.AttemptID
	receipt.Result.TopologyID = admission.TopologyID
	plan, planBytes, err := buildE5Plan(
		minimallyShapedAdmittedConfig(t), strings.Repeat("d", 64),
		admission, receipt, 1, strings.Repeat("e", 64),
		strings.Repeat("f", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	changedDeadline := plan
	changedDeadline.StartDeadline = changedDeadline.FinishDeadline
	if err := validateE6PlanAdmission(
		changedDeadline, admission, plan.RunID,
	); err == nil {
		t.Fatal("E5 StartDeadline drift from E2 admission was accepted")
	}
	result := testE6Result(admission, plan)
	value, encoded, err := buildE6Receipt(
		plan, admittedRawSHA(planBytes), result,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseE6ReceiptStructure(encoded); err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseAuthenticatedE6Receipt(
		encoded, filepath.Join(t.TempDir(), "missing-trust.json"),
	); err == nil {
		t.Fatal("structurally valid fake-signature receipt authenticated")
	}
	if value.VerificationState != "sealed-inputs-verified-pending-activation" ||
		value.ActivationObserved || value.SecureTimeObserved ||
		value.ActivationCounterReserved || value.LiveRuntimeRechecked ||
		value.CredentialHandleReleased || value.SupervisorExecuted ||
		value.DispatchAuthorized || value.ExternalTopologyExecuted ||
		value.ProviderAccess || value.CredentialAccess || value.NetworkAccess ||
		value.LiveNodesContacted || value.SpendAuthorized ||
		value.HandoffReady || value.Authority {
		t.Fatalf("unsafe E6 receipt: %+v", value)
	}
	changed := value
	changed.DispatchAuthorized = true
	if bad, err := json.Marshal(changed); err != nil {
		t.Fatal(err)
	} else if _, err := parseE6ReceiptStructure(bad); err == nil {
		t.Fatal("authorizing E6 receipt was accepted")
	}
	for name, seconds := range map[string]uint64{
		"above policy cap": realcycle.MaximumExecutionSeconds + 1,
		"max uint64":       math.MaxUint64,
		"duration overflow": uint64(
			math.MaxInt64/int64(time.Second),
		) + 1,
	} {
		t.Run(name, func(t *testing.T) {
			changed := value
			changed.MaxExecutionSeconds = seconds
			if bad, err := json.Marshal(changed); err != nil {
				t.Fatal(err)
			} else if _, err := parseE6ReceiptStructure(bad); err == nil {
				t.Fatal("overflowing E6 execution duration was accepted")
			}
		})
	}
}

func TestE6ReplaysE5AndAdmissionBeforePublication(t *testing.T) {
	oldPlatform := admittedPlatform
	oldVerify := verifyAdmittedInputsOperation
	oldValidate := validateAdmittedAdmission
	oldHandoff := validateSealedHandoffOperation
	oldReplay := replaySealedHandoffOperation
	oldPublish := publishE6ReceiptOperation
	admittedPlatform = "linux"
	verifyAdmittedInputsOperation = func(AdmittedConfig) error { return nil }
	admission := testE5Admission(t)
	validateAdmittedAdmission = func(
		string, string, string,
	) (realcycle.AdmissionResult, error) {
		return admission, nil
	}
	validateSealedHandoffOperation = func(
		_ string, _ string, expected realcycle.HandoffExpectation,
	) (realcycle.SealedHandoffResult, error) {
		if expected.AdmissionBindingDigest != admission.BindingDigest {
			return realcycle.SealedHandoffResult{}, errors.New("bad expectation")
		}
		return testE6Result(admission, e5FourNodePlan{
			ExpectedTransport: admission.ExpectedTransport,
			StartNotBefore:    admission.StartNotBefore,
			StartDeadline:     admission.StartDeadline,
			FinishDeadline:    admission.FinishDeadline,
		}), nil
	}
	replaySealedHandoffOperation = func(
		_ string, _ realcycle.HandoffExpectation,
		_ realcycle.AuthorizationCommitment,
		_ realcycle.HandoffRoleExtension,
		_ realcycle.SupervisorCommitment,
	) (realcycle.SealedHandoffResult, error) {
		return testE6Result(admission, e5FourNodePlan{
			ExpectedTransport: admission.ExpectedTransport,
			StartNotBefore:    admission.StartNotBefore,
			StartDeadline:     admission.StartDeadline,
			FinishDeadline:    admission.FinishDeadline,
		}), nil
	}
	publishE6ReceiptOperation = func(
		directory *secureDirectory,
		encoded []byte,
		expected e6VerificationReceipt,
		_ string,
		_ realcycle.SealedHandoffResult,
	) error {
		if err := os.WriteFile(
			filepath.Join(directory.path, e6ReceiptFile), encoded, 0o400,
		); err != nil {
			return err
		}
		replayed, raw, err := readE6ReceiptStructure(directory)
		if err != nil || replayed != expected || string(raw) != string(encoded) {
			return errors.New("injected E6 replay mismatch")
		}
		return directory.Sync()
	}
	t.Cleanup(func() {
		admittedPlatform = oldPlatform
		verifyAdmittedInputsOperation = oldVerify
		validateAdmittedAdmission = oldValidate
		validateSealedHandoffOperation = oldHandoff
		replaySealedHandoffOperation = oldReplay
		publishE6ReceiptOperation = oldPublish
	})

	cfg := minimallyShapedAdmittedConfig(t)
	e4 := validAdmittedReceipt()
	e4.ObjectDigest = strings.Repeat("c", 64)
	e4.AdmissionBundleSHA256 = admission.AdmissionBundleSHA256
	e4.AdmissionBindingDigest = admission.BindingDigest
	e4.RuntimeCollectionDigest = admission.RuntimeCollectionDigest
	e4.ReservationObjectDigest = admission.ReservationObjectDigest
	e4.Result.CycleID, e4.Result.AttemptID = admission.CycleID, admission.AttemptID
	e4.Result.TopologyID = admission.TopologyID
	plan, encoded, err := buildE5Plan(
		cfg, strings.Repeat("d", 64), admission, e4, 1,
		strings.Repeat("e", 64), strings.Repeat("f", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	planRoot := privateTestDirectory(t)
	if err := os.WriteFile(
		filepath.Join(planRoot, e5PlanFile), encoded, 0o400,
	); err != nil {
		t.Fatal(err)
	}
	handoffRoot := privateTestDirectory(t)
	receiptRoot := privateTestDirectory(t)
	summary, err := runAdmittedE6Handoff(
		context.Background(), cfg, planRoot, handoffRoot, receiptRoot,
	)
	if err != nil {
		t.Fatal(err)
	}
	if summary.PlanSHA256 != admittedRawSHA(encoded) ||
		summary.VerificationState !=
			"sealed-inputs-verified-pending-activation" ||
		summary.DispatchAuthorized || summary.ExternalTopologyExecuted ||
		summary.ProviderAccess || summary.CredentialAccess ||
		summary.NetworkAccess || summary.LiveNodesContacted ||
		summary.SpendAuthorized || summary.HandoffReady || summary.Authority {
		t.Fatalf("unsafe E6 summary for plan %+v: %+v", plan, summary)
	}
	replayCalls := 0
	replaySealedHandoffOperation = func(
		string, realcycle.HandoffExpectation,
		realcycle.AuthorizationCommitment,
		realcycle.HandoffRoleExtension,
		realcycle.SupervisorCommitment,
	) (realcycle.SealedHandoffResult, error) {
		replayCalls++
		if replayCalls == 1 {
			return testE6Result(admission, e5FourNodePlan{
				ExpectedTransport: admission.ExpectedTransport,
				StartNotBefore:    admission.StartNotBefore,
				StartDeadline:     admission.StartDeadline,
				FinishDeadline:    admission.FinishDeadline,
			}), nil
		}
		return realcycle.SealedHandoffResult{},
			errors.New("injected postpublication replay refusal")
	}
	postReplayRoot := privateTestDirectory(t)
	if _, err := runAdmittedE6Handoff(
		context.Background(), cfg, planRoot, handoffRoot, postReplayRoot,
	); err == nil {
		t.Fatal("postpublication replay failure was accepted")
	} else {
		var publication *e6PublicationError
		if !errors.As(err, &publication) ||
			publication.Stage != "postpublication-cryptographic-replay" ||
			!publication.FinalReceiptMayExist ||
			!publication.DirectorySynced ||
			!publication.ReceiptAuthenticated {
			t.Fatalf("postpublication refusal was not indeterminate: %v", err)
		}
	}
	if _, err := os.Stat(filepath.Join(postReplayRoot, e6ReceiptFile)); err != nil {
		t.Fatalf("postpublication refusal lost durable receipt: %v", err)
	}
	replaySealedHandoffOperation = func(
		string, realcycle.HandoffExpectation,
		realcycle.AuthorizationCommitment,
		realcycle.HandoffRoleExtension,
		realcycle.SupervisorCommitment,
	) (realcycle.SealedHandoffResult, error) {
		return realcycle.SealedHandoffResult{},
			errors.New("injected supervisor identity drift")
	}
	driftReceiptRoot := privateTestDirectory(t)
	if _, err := runAdmittedE6Handoff(
		context.Background(), cfg, planRoot, handoffRoot, driftReceiptRoot,
	); err == nil {
		t.Fatal("prepublication supervisor identity drift was accepted")
	}
	if entries, err := os.ReadDir(driftReceiptRoot); err != nil || len(entries) != 0 {
		t.Fatalf("prepublication drift left a receipt: %v %v", err, entries)
	}
	if _, err := runAdmittedE6Handoff(
		context.Background(), cfg, planRoot, handoffRoot, receiptRoot,
	); err == nil {
		t.Fatal("E6 receipt root reuse was accepted")
	}
}
