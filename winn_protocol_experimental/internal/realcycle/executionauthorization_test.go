package realcycle

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type executionAuthorizationFixture struct {
	expected   ExecutionAuthorizationExpectation
	decision   ExecutionAuthorization
	acceptance SupervisorAuthorizationAcceptance
	keys       map[string]ed25519.PrivateKey
}

func newExecutionAuthorizationFixture(
	t *testing.T,
) executionAuthorizationFixture {
	t.Helper()
	handoff := newHandoffFixture(t)
	identityRoot := physicalTempDir(t)
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
	expected := ExecutionAuthorizationExpectation{
		RunID: handoff.expected.RunID, CycleID: handoff.expected.CycleID,
		AttemptID:                  handoff.expected.AttemptID,
		TopologyID:                 handoff.expected.TopologyID,
		PlanSHA256:                 handoff.expected.PlanSHA256,
		PlanObjectDigest:           handoff.expected.PlanObjectDigest,
		TrustSHA256:                strings.Repeat("7", 64),
		E6ReceiptSHA256:            strings.Repeat("8", 64),
		E6ReceiptObjectDigest:      strings.Repeat("9", 64),
		HandoffCollectionDigest:    strings.Repeat("a", 64),
		OneTimeNonce:               strings.Repeat("b", 32),
		MinimumActivationCounter:   108,
		LastObservedCounter:        107,
		ValidNotBefore:             "2030-01-01T10:08:00Z",
		ValidNotAfter:              "2030-01-01T10:10:00Z",
		MaxExecutionSeconds:        600,
		SupervisorExecutablePath:   executablePath,
		SupervisorExecutableSHA256: rawSHA(executableBytes),
		SupervisorConfigPath:       configPath,
		SupervisorConfigSHA256:     rawSHA(configBytes),
		RoleKeys:                   handoff.extension.Keys,
	}
	value := executionAuthorizationFixture{
		expected: expected, keys: handoff.keys,
		decision: ExecutionAuthorization{
			Schema:     ExecutionAuthorizationSchema,
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
			AuthorizerKeyID:            handoff.extension.Keys[0].KeyID,
		},
	}
	value.seal(t)
	return value
}

func (f *executionAuthorizationFixture) seal(t *testing.T) {
	t.Helper()
	sign := func(keyID, domain string, value any) string {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		message := append(append([]byte(domain), 0), encoded...)
		return base64.StdEncoding.EncodeToString(
			ed25519.Sign(f.keys[keyID], message),
		)
	}
	f.decision.Signature = sign(
		f.decision.AuthorizerKeyID,
		executionAuthorizationSignatureDomain,
		executionAuthorizationUnsignedOf(f.decision),
	)
	decisionBytes := mustCanonical(t, f.decision)
	decisionObject, err := digestObject(
		executionAuthorizationObjectDomain, f.decision,
	)
	if err != nil {
		t.Fatal(err)
	}
	f.acceptance = SupervisorAuthorizationAcceptance{
		Schema:                SupervisorAuthorizationAcceptanceSchema,
		State:                 "accepted-for-future-atomic-consumption",
		DecisionSHA256:        rawSHA(decisionBytes),
		DecisionObjectDigest:  decisionObject,
		E6ReceiptSHA256:       f.expected.E6ReceiptSHA256,
		E6ReceiptObjectDigest: f.expected.E6ReceiptObjectDigest,
		RunID:                 f.expected.RunID, CycleID: f.expected.CycleID,
		AttemptID: f.expected.AttemptID, TopologyID: f.expected.TopologyID,
		OneTimeNonce:               f.expected.OneTimeNonce,
		ActivationCounter:          f.expected.MinimumActivationCounter,
		SupervisorExecutablePath:   f.expected.SupervisorExecutablePath,
		SupervisorExecutableSHA256: f.expected.SupervisorExecutableSHA256,
		SupervisorConfigPath:       f.expected.SupervisorConfigPath,
		SupervisorConfigSHA256:     f.expected.SupervisorConfigSHA256,
		SupervisorKeyID:            f.expected.RoleKeys[1].KeyID,
	}
	f.acceptance.Signature = sign(
		f.acceptance.SupervisorKeyID,
		supervisorAuthorizationAcceptanceSignatureDomain,
		supervisorAuthorizationAcceptanceUnsignedOf(f.acceptance),
	)
}

func TestExecutionAuthorizationExactAndNonauthorizing(t *testing.T) {
	fixture := newExecutionAuthorizationFixture(t)
	root := t.TempDir()
	writePrivate(
		t, filepath.Join(root, ExecutionAuthorizationFile),
		mustCanonical(t, fixture.decision),
	)
	writePrivate(
		t, filepath.Join(root, SupervisorAuthorizationAcceptanceFile),
		mustCanonical(t, fixture.acceptance),
	)
	result, err := ValidateExecutionAuthorization(root, fixture.expected)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := VerifyExecutionAuthorizationObjects(
		fixture.expected, fixture.decision, fixture.acceptance,
	)
	if err != nil || replayed != result ||
		result.ActivationCounter != fixture.expected.MinimumActivationCounter {
		t.Fatalf("E7 replay mismatch: %v %+v", err, replayed)
	}
}

func TestExecutionAuthorizationRejectsDriftAndRoleConfusion(t *testing.T) {
	for name, mutate := range map[string]func(*executionAuthorizationFixture){
		"receipt drift": func(f *executionAuthorizationFixture) {
			f.decision.E6ReceiptSHA256 = strings.Repeat("f", 64)
		},
		"counter drift": func(f *executionAuthorizationFixture) {
			f.decision.ActivationCounter++
		},
		"execution duration above policy cap": func(f *executionAuthorizationFixture) {
			f.expected.MaxExecutionSeconds = MaximumExecutionSeconds + 1
			f.decision.MaxExecutionSeconds = f.expected.MaxExecutionSeconds
		},
		"execution duration max uint64": func(f *executionAuthorizationFixture) {
			f.expected.MaxExecutionSeconds = math.MaxUint64
			f.decision.MaxExecutionSeconds = f.expected.MaxExecutionSeconds
		},
		"execution duration arithmetic overflow": func(
			f *executionAuthorizationFixture,
		) {
			f.expected.MaxExecutionSeconds =
				uint64(math.MaxInt64/int64(time.Second)) + 1
			f.decision.MaxExecutionSeconds = f.expected.MaxExecutionSeconds
		},
		"wrong authorizer role": func(f *executionAuthorizationFixture) {
			f.decision.AuthorizerKeyID = f.expected.RoleKeys[1].KeyID
		},
		"supervisor path drift": func(f *executionAuthorizationFixture) {
			f.decision.SupervisorConfigPath += ".other"
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newExecutionAuthorizationFixture(t)
			mutate(&fixture)
			fixture.seal(t)
			if _, err := VerifyExecutionAuthorizationObjects(
				fixture.expected, fixture.decision, fixture.acceptance,
			); err == nil {
				t.Fatal("invalid E7 authorization input was accepted")
			}
		})
	}
}
