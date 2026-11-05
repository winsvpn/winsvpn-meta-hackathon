package realcycle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type handoffFixture struct {
	trust         TrustBundle
	keys          map[string]ed25519.PrivateKey
	expected      HandoffExpectation
	authorization AuthorizationCommitment
	extension     HandoffRoleExtension
	supervisor    SupervisorCommitment
}

func physicalTempDir(t *testing.T) string {
	t.Helper()
	base := "/private/tmp"
	if info, err := os.Stat(base); err != nil || !info.IsDir() {
		return t.TempDir()
	}
	root, err := os.MkdirTemp(base, "winn-e6-test.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

func newHandoffFixture(t *testing.T) handoffFixture {
	t.Helper()
	keys := make(map[string]ed25519.PrivateKey)
	newKey := func(id, role string) TrustKey {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[id] = private
		return TrustKey{
			KeyID: id, Role: role,
			PublicKey: base64.StdEncoding.EncodeToString(public),
		}
	}
	expected := HandoffExpectation{
		RunID: "run-e6", CycleID: "cycle-e6", AttemptID: "attempt-e6",
		TopologyID: "topology-e6", PlanSHA256: strings.Repeat("1", 64),
		PlanObjectDigest:        strings.Repeat("2", 64),
		AdmissionBindingDigest:  strings.Repeat("3", 64),
		AdmissionBundleSHA256:   strings.Repeat("4", 64),
		RuntimeCollectionDigest: strings.Repeat("5", 64),
		ReservationObjectDigest: strings.Repeat("6", 64),
		AdmissionNonce:          strings.Repeat("a", 32),
		CounterDomain:           "counter-e6", AcceptedCounter: 100,
		LastObservedCounter: 107,
		ExpectedTransport:   TransportH3,
		StartNotBefore:      "2030-01-01T10:08:00Z",
		StartDeadline:       "2030-01-01T10:10:00Z",
		FinishDeadline:      "2030-01-01T10:20:00Z",
	}
	value := handoffFixture{
		keys: keys, expected: expected,
		trust: TrustBundle{
			Schema: TrustSchema, AcceptanceID: "accepted-e6-root",
			AcceptedAt: "2030-01-01T09:00:00Z",
			ExpiresAt:  "2030-01-01T11:00:00Z",
			Keys: []TrustKey{
				newKey("controller-key", KeyRoleController),
			},
		},
	}
	dispatchKey := newKey("dispatch-key", KeyRoleDispatchAuthorizer)
	supervisorKey := newKey("supervisor-key", KeyRoleExecutionSupervisor)
	value.expected.TrustSHA256 = rawSHA(mustCanonical(t, value.trust))
	value.extension = HandoffRoleExtension{
		Schema: HandoffRoleExtensionSchema, State: "public-key-extension-only",
		PlanSHA256:          expected.PlanSHA256,
		PlanObjectDigest:    expected.PlanObjectDigest,
		AcceptedTrustSHA256: value.expected.TrustSHA256,
		Keys: [2]HandoffRoleKey{
			{KeyID: dispatchKey.KeyID, Role: dispatchKey.Role,
				PublicKey: dispatchKey.PublicKey},
			{KeyID: supervisorKey.KeyID, Role: supervisorKey.Role,
				PublicKey: supervisorKey.PublicKey},
		},
		ControllerKeyID: "controller-key",
	}
	value.authorization = AuthorizationCommitment{
		Schema: AuthorizationCommitmentSchema,
		State:  "sealed-pending-activation",
		Scope:  "execute-one-four-node-cycle",
		RunID:  expected.RunID, CycleID: expected.CycleID,
		AttemptID: expected.AttemptID, TopologyID: expected.TopologyID,
		PlanSHA256:              expected.PlanSHA256,
		PlanObjectDigest:        expected.PlanObjectDigest,
		AdmissionBindingDigest:  expected.AdmissionBindingDigest,
		AdmissionBundleSHA256:   expected.AdmissionBundleSHA256,
		RuntimeCollectionDigest: expected.RuntimeCollectionDigest,
		ReservationObjectDigest: expected.ReservationObjectDigest,
		AdmissionNonce:          expected.AdmissionNonce,
		CounterDomain:           expected.CounterDomain, MinimumActivationCounter: 108,
		ValidNotBefore:       expected.StartNotBefore,
		ValidNotAfter:        expected.StartDeadline,
		MaxRuntimeAgeSeconds: 300, MaxExecutionSeconds: 600,
		OneTimeNonce:    strings.Repeat("b", 32),
		AuthorizerKeyID: "dispatch-key",
	}
	value.supervisor = SupervisorCommitment{
		Schema: SupervisorCommitmentSchema,
		State:  "sealed-pending-activation",
		RunID:  expected.RunID, CycleID: expected.CycleID,
		AttemptID: expected.AttemptID, TopologyID: expected.TopologyID,
		PlanSHA256:                 expected.PlanSHA256,
		PlanObjectDigest:           expected.PlanObjectDigest,
		ExpectedTransport:          expected.ExpectedTransport,
		SupervisorExecutablePath:   "/opt/winn/bin/winn-execution-supervisor",
		SupervisorExecutableSHA256: strings.Repeat("7", 64),
		SupervisorConfigPath:       "/etc/winn/execution-supervisor.json",
		SupervisorConfigSHA256:     strings.Repeat("8", 64),
		MaxExecutionSeconds:        600, OneTimeNonce: strings.Repeat("b", 32),
		SupervisorKeyID: "supervisor-key",
	}
	value.seal(t)
	return value
}

func (f *handoffFixture) seal(t *testing.T) {
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
	f.authorization.Signature = sign(
		f.authorization.AuthorizerKeyID, authorizationSignatureDomain,
		authorizationUnsignedOf(f.authorization),
	)
	f.extension.Signature = sign(
		f.extension.ControllerKeyID, handoffRoleExtensionSignatureDomain,
		handoffRoleExtensionUnsignedOf(f.extension),
	)
	f.supervisor.Signature = sign(
		f.supervisor.SupervisorKeyID, supervisorSignatureDomain,
		supervisorUnsignedOf(f.supervisor),
	)
}

func TestValidateSealedHandoffExactAndNonauthorizing(t *testing.T) {
	fixture := newHandoffFixture(t)
	identityRoot := physicalTempDir(t)
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
	fixture.supervisor.SupervisorExecutablePath = executablePath
	fixture.supervisor.SupervisorExecutableSHA256 = rawSHA(executableBytes)
	fixture.supervisor.SupervisorConfigPath = configPath
	fixture.supervisor.SupervisorConfigSHA256 = rawSHA(configBytes)
	fixture.seal(t)
	root := t.TempDir()
	trustPath := filepath.Join(t.TempDir(), "trust.json")
	writePrivate(t, trustPath, mustCanonical(t, fixture.trust))
	writePrivate(t, filepath.Join(root, AuthorizationCommitmentFile),
		mustCanonical(t, fixture.authorization))
	writePrivate(t, filepath.Join(root, HandoffRoleExtensionFile),
		mustCanonical(t, fixture.extension))
	writePrivate(t, filepath.Join(root, SupervisorCommitmentFile),
		mustCanonical(t, fixture.supervisor))

	result, err := ValidateSealedHandoff(root, trustPath, fixture.expected)
	if err != nil {
		t.Fatal(err)
	}
	if result.MinimumActivationCounter != 108 ||
		result.MaxExecutionSeconds != 600 ||
		result.OneTimeNonce != strings.Repeat("b", 32) ||
		!hex64Pattern.MatchString(result.CollectionDigest) {
		t.Fatalf("unexpected sealed handoff result: %+v", result)
	}
	replayed, err := VerifySealedHandoffObjects(
		trustPath, fixture.expected, fixture.authorization,
		fixture.extension, fixture.supervisor,
	)
	if err != nil || replayed != result {
		t.Fatalf("durable projection replay failed: %v %+v", err, replayed)
	}
	if err := os.Chmod(configPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		configPath, []byte("{\"mode\":\"drifted\"}\n"), 0o400,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(configPath, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateSealedHandoff(
		root, trustPath, fixture.expected,
	); err == nil {
		t.Fatal("supervisor content drift was accepted")
	}
}

func TestValidateSealedHandoffRejectsDriftRoleConfusionAndExtraFile(t *testing.T) {
	for name, mutate := range map[string]func(*handoffFixture){
		"plan drift": func(f *handoffFixture) {
			f.authorization.PlanSHA256 = strings.Repeat("9", 64)
		},
		"counter not advanced": func(f *handoffFixture) {
			f.authorization.MinimumActivationCounter = f.expected.AcceptedCounter
		},
		"nonce mismatch": func(f *handoffFixture) {
			f.supervisor.OneTimeNonce = strings.Repeat("c", 32)
		},
		"wrong signature role": func(f *handoffFixture) {
			f.authorization.AuthorizerKeyID = "supervisor-key"
		},
		"window exceeds admission": func(f *handoffFixture) {
			f.authorization.ValidNotAfter = "2030-01-01T10:21:00Z"
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newHandoffFixture(t)
			mutate(&fixture)
			fixture.seal(t)
			trustBytes := mustCanonical(t, fixture.trust)
			_, index, err := parseTrust(trustBytes)
			if err != nil {
				t.Fatal(err)
			}
			_, err = validateSealedHandoffValues(
				fixture.authorization, fixture.extension, fixture.supervisor,
				fixture.trust, index, fixture.expected,
				trustBytes,
				mustCanonical(t, fixture.authorization),
				mustCanonical(t, fixture.extension),
				mustCanonical(t, fixture.supervisor),
			)
			if err == nil {
				t.Fatal("invalid sealed handoff was accepted")
			}
		})
	}

	fixture := newHandoffFixture(t)
	root := t.TempDir()
	trustPath := filepath.Join(t.TempDir(), "trust.json")
	writePrivate(t, trustPath, mustCanonical(t, fixture.trust))
	writePrivate(t, filepath.Join(root, AuthorizationCommitmentFile),
		mustCanonical(t, fixture.authorization))
	writePrivate(t, filepath.Join(root, HandoffRoleExtensionFile),
		mustCanonical(t, fixture.extension))
	writePrivate(t, filepath.Join(root, SupervisorCommitmentFile),
		mustCanonical(t, fixture.supervisor))
	if err := os.WriteFile(filepath.Join(root, "extra.json"), []byte("{}\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateSealedHandoff(
		root, trustPath, fixture.expected,
	); err == nil {
		t.Fatal("extra handoff file was accepted")
	}
}

func TestSealedHandoffRejectsSignatureRoleAndPathBypasses(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*handoffFixture)
		mutatePost func(*handoffFixture)
	}{
		{"same public key across roles", func(f *handoffFixture) {
			f.extension.Keys[1].PublicKey = f.extension.Keys[0].PublicKey
		}, nil},
		{"role key reuses accepted controller key", func(f *handoffFixture) {
			f.extension.Keys[0].PublicKey = f.trust.Keys[0].PublicKey
		}, nil},
		{"dirty executable path", func(f *handoffFixture) {
			f.supervisor.SupervisorExecutablePath = "/opt/winn/../winn/supervisor"
		}, nil},
		{"root config path", func(f *handoffFixture) {
			f.supervisor.SupervisorConfigPath = "/"
		}, nil},
		{"corrupt authorization signature", nil, func(f *handoffFixture) {
			f.authorization.Signature =
				base64.StdEncoding.EncodeToString(make([]byte, 64))
		}},
		{"corrupt supervisor signature", nil, func(f *handoffFixture) {
			f.supervisor.Signature =
				base64.StdEncoding.EncodeToString(make([]byte, 64))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHandoffFixture(t)
			if test.mutate != nil {
				test.mutate(&fixture)
				fixture.seal(t)
			}
			if test.mutatePost != nil {
				test.mutatePost(&fixture)
			}
			trustBytes := mustCanonical(t, fixture.trust)
			_, index, err := parseTrust(trustBytes)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := validateSealedHandoffValues(
				fixture.authorization, fixture.extension, fixture.supervisor,
				fixture.trust, index, fixture.expected, trustBytes,
				mustCanonical(t, fixture.authorization),
				mustCanonical(t, fixture.extension),
				mustCanonical(t, fixture.supervisor),
			); err == nil {
				t.Fatal("sealed handoff bypass was accepted")
			}
		})
	}
}

func TestValidateSealedHandoffRejectsSymlinkSupervisor(t *testing.T) {
	fixture := newHandoffFixture(t)
	identityRoot := physicalTempDir(t)
	target := filepath.Join(identityRoot, "real-supervisor")
	link := filepath.Join(identityRoot, "supervisor-link")
	data := []byte("sealed supervisor executable\n")
	if err := os.WriteFile(target, data, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(identityRoot, "supervisor.json")
	configData := []byte("{\"mode\":\"sealed\"}\n")
	if err := os.WriteFile(config, configData, 0o400); err != nil {
		t.Fatal(err)
	}
	fixture.supervisor.SupervisorExecutablePath = link
	fixture.supervisor.SupervisorExecutableSHA256 = rawSHA(data)
	fixture.supervisor.SupervisorConfigPath = config
	fixture.supervisor.SupervisorConfigSHA256 = rawSHA(configData)
	fixture.seal(t)
	root := t.TempDir()
	trustPath := filepath.Join(t.TempDir(), "trust.json")
	writePrivate(t, trustPath, mustCanonical(t, fixture.trust))
	writePrivate(t, filepath.Join(root, AuthorizationCommitmentFile),
		mustCanonical(t, fixture.authorization))
	writePrivate(t, filepath.Join(root, HandoffRoleExtensionFile),
		mustCanonical(t, fixture.extension))
	writePrivate(t, filepath.Join(root, SupervisorCommitmentFile),
		mustCanonical(t, fixture.supervisor))
	if _, err := ValidateSealedHandoff(
		root, trustPath, fixture.expected,
	); err == nil {
		t.Fatal("symlink supervisor executable was accepted")
	}
}

func TestNoSymlinkDescriptorWalkRejectsAncestorSymlink(t *testing.T) {
	root := physicalTempDir(t)
	realParent := filepath.Join(root, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(realParent, "supervisor")
	if err := os.WriteFile(target, []byte("supervisor\n"), 0o500); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(realParent, alias); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readNoSymlinkRegular(
		filepath.Join(alias, "supervisor"), 1024,
	); err == nil {
		t.Fatal("ancestor-symlink supervisor path was accepted")
	}
	if data, _, err := readNoSymlinkRegular(target, 1024); err != nil ||
		string(data) != "supervisor\n" {
		t.Fatalf("descriptor walk rejected exact physical file: %v %q", err, data)
	}
}
