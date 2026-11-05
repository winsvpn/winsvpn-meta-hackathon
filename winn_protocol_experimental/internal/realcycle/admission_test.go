package realcycle

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type admissionFixture struct {
	t           *testing.T
	directory   string
	trustPath   string
	topology    string
	trust       TrustBundle
	private     map[string]ed25519.PrivateKey
	intent      AdmissionIntent
	runtime     RuntimeSet
	reservation CredentialReservation
	readiness   ReadinessEnvelope
}

func TestValidateAdmissionDirectAndH3(t *testing.T) {
	for _, transport := range []string{TransportDirect, TransportH3} {
		t.Run(transport, func(t *testing.T) {
			fixture := newAdmissionFixture(t, transport)
			got, err := ValidateAdmission(
				fixture.directory, fixture.trustPath, fixture.topology,
			)
			if err != nil {
				t.Fatal(err)
			}
			wantReserved := 0
			if transport == TransportH3 {
				wantReserved = 1
			}
			if got.CycleID != fixture.intent.CycleID ||
				got.AttemptID != fixture.intent.AttemptID ||
				got.TopologyID != fixture.intent.TopologyID ||
				got.BindingDigest != fixture.intent.BindingDigest ||
				got.RuntimeCount != 4 ||
				got.ExercisedNodeCount != len(fixture.intent.ExercisedNodes) ||
				got.ReservedTokenCount != wantReserved ||
				got.LastObservedCounter != fixture.readiness.AcceptedCounter ||
				got.TrustSHA256 != fixture.intent.TrustSHA256 ||
				!validDigest(got.AdmissionBundleSHA256) ||
				got.RuntimeCollectionDigest != fixture.runtime.CollectionDigest ||
				got.StartNotBefore != fixture.intent.StartNotBefore ||
				got.StartDeadline != fixture.intent.StartDeadline ||
				got.FinishDeadline != fixture.intent.FinishDeadline {
				t.Fatalf("unexpected result: %+v", got)
			}
			for index := range fixture.intent.ExercisedNodes {
				if got.ExercisedNodes[index] != fixture.intent.ExercisedNodes[index] {
					t.Fatalf("unexpected exercised node projection: %+v", got)
				}
			}
			for index := range fixture.intent.Deployments {
				expectedDeployment := fixture.intent.Deployments[index]
				expectedRuntime := fixture.runtime.Attestations[index]
				expectedDigest, err := RuntimeAttestationObjectDigest(
					expectedRuntime,
				)
				if err != nil {
					t.Fatal(err)
				}
				if got.Deployments[index] != expectedDeployment ||
					got.RuntimeAttestations[index] != expectedRuntime ||
					got.RuntimeObjectDigests[index] != expectedDigest {
					t.Fatalf(
						"unexpected E5 admission projection at %d: %+v",
						index, got,
					)
				}
			}
		})
	}
}

func TestValidateAdmissionRejectsContractAndCausalityMutations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*admissionFixture)
	}{
		{"dispatch-authorized", func(f *admissionFixture) {
			f.readiness.DispatchAuthorized = true
		}},
		{"mutation", func(f *admissionFixture) {
			f.readiness.Mutation = "reserve"
		}},
		{"readiness-before-reservation", func(f *admissionFixture) {
			f.readiness.AcceptedAt = f.reservation.CommittedAt
		}},
		{"runtime-not-strict", func(f *admissionFixture) {
			f.runtime.Attestations[2].ObservedCounter =
				f.runtime.Attestations[1].ObservedCounter
		}},
		{"direct-token", func(f *admissionFixture) {
			f.intent.ExpectedTransport = TransportDirect
		}},
		{"consumed-count-smuggling", func(f *admissionFixture) {
			data, err := marshalCanonical(f.reservation)
			if err != nil {
				f.t.Fatal(err)
			}
			data = []byte(strings.Replace(
				string(data), `"reserved_count":1`,
				`"reserved_count":1,"consumed_count":0`, 1,
			))
			writePrivate(f.t, filepath.Join(f.directory, ReservationFile), data)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAdmissionFixture(t, TransportH3)
			test.mutate(fixture)
			if test.name != "consumed-count-smuggling" {
				fixture.seal()
			}
			if _, err := ValidateAdmission(
				fixture.directory, fixture.trustPath, fixture.topology,
			); err == nil {
				t.Fatal("mutated admission unexpectedly validated")
			}
		})
	}
}

func TestValidateAdmissionRejectsRuntimeReservationAndEnvelopeReordering(t *testing.T) {
	fixture := newAdmissionFixture(t, TransportH3)
	fixture.reservation.RuntimeCollectionDigest = strings.Repeat("0", 64)
	fixture.sealReservationAndReadiness()
	if _, err := ValidateAdmission(
		fixture.directory, fixture.trustPath, fixture.topology,
	); err == nil {
		t.Fatal("reservation detached from runtime unexpectedly validated")
	}
}

func TestValidateAdmissionRejectsUnixNanoWraparoundTimestamps(t *testing.T) {
	const upperWrap = "2614-07-23T09:35:33.709551616Z"
	const lowerWrap = "1445-06-13T10:26:26.290448384Z"
	tests := []struct {
		name   string
		mutate func(*admissionFixture)
	}{
		{"trust-upper", func(f *admissionFixture) {
			f.trust.ExpiresAt = upperWrap
			f.writeTrustAndReseal()
		}},
		{"runtime-upper", func(f *admissionFixture) {
			f.runtime.Attestations[0].ObservedAt = upperWrap
			f.seal()
		}},
		{"runtime-lower", func(f *admissionFixture) {
			f.runtime.Attestations[0].ObservedAt = lowerWrap
			f.seal()
		}},
		{"reservation-upper", func(f *admissionFixture) {
			f.reservation.PreparedAt = upperWrap
			f.seal()
		}},
		{"readiness-upper", func(f *admissionFixture) {
			f.readiness.AcceptedAt = upperWrap
			f.seal()
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAdmissionFixture(t, TransportH3)
			test.mutate(fixture)
			if _, err := ValidateAdmission(
				fixture.directory, fixture.trustPath, fixture.topology,
			); err == nil {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestValidateAdmissionRetainedByteReplay(t *testing.T) {
	t.Run("admission-same-inode-rewrite", func(t *testing.T) {
		fixture := newAdmissionFixture(t, TransportH3)
		path := filepath.Join(fixture.directory, ReadinessFile)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		originalHook := beforeAdmissionFinalReplay
		beforeAdmissionFinalReplay = func() {
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data[10] ^= 1
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
				t.Fatal(err)
			}
			beforeAdmissionFinalReplay = originalHook
		}
		t.Cleanup(func() { beforeAdmissionFinalReplay = originalHook })
		if _, err := ValidateAdmission(
			fixture.directory, fixture.trustPath, fixture.topology,
		); err == nil || !strings.Contains(err.Error(), "changed") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("trust-same-inode-rewrite", func(t *testing.T) {
		fixture := newAdmissionFixture(t, TransportDirect)
		info, err := os.Stat(fixture.trustPath)
		if err != nil {
			t.Fatal(err)
		}
		originalHook := beforeAdmissionFinalReplay
		beforeAdmissionFinalReplay = func() {
			if err := os.Chmod(fixture.trustPath, 0o600); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(fixture.trustPath)
			if err != nil {
				t.Fatal(err)
			}
			data[10] ^= 1
			if err := os.WriteFile(fixture.trustPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(
				fixture.trustPath, info.ModTime(), info.ModTime(),
			); err != nil {
				t.Fatal(err)
			}
			beforeAdmissionFinalReplay = originalHook
		}
		t.Cleanup(func() { beforeAdmissionFinalReplay = originalHook })
		if _, err := ValidateAdmission(
			fixture.directory, fixture.trustPath, fixture.topology,
		); err == nil || !strings.Contains(err.Error(), "trust bundle") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("E0-same-inode-rewrite", func(t *testing.T) {
		fixture := newAdmissionFixture(t, TransportDirect)
		path := filepath.Join(fixture.topology, "gateway-manifest-v2.json")
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		originalHook := beforeAdmissionFinalReplay
		beforeAdmissionFinalReplay = func() {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data[10] ^= 1
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
				t.Fatal(err)
			}
			beforeAdmissionFinalReplay = originalHook
		}
		t.Cleanup(func() { beforeAdmissionFinalReplay = originalHook })
		if _, err := ValidateAdmission(
			fixture.directory, fixture.trustPath, fixture.topology,
		); err == nil || !strings.Contains(err.Error(), "E0") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestAdmissionProductionFilesHaveNoExecutionNetworkOrWrites(t *testing.T) {
	files := []string{
		"admission.go",
		filepath.Join("..", "..", "cmd", "winn-real-cycle-admission", "main.go"),
	}
	for _, path := range files {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range parsed.Imports {
			name := strings.Trim(imported.Path.Value, `"`)
			if name == "net" || strings.HasPrefix(name, "net/") ||
				name == "os/exec" || strings.Contains(name, "provider") ||
				strings.Contains(name, "cloud") {
				t.Fatalf("%s imports forbidden package %q", path, name)
			}
		}
		forbidden := map[string]bool{
			"WriteFile": true, "Create": true, "CreateTemp": true,
			"Mkdir": true, "MkdirAll": true, "OpenFile": true,
			"Rename": true, "Remove": true, "RemoveAll": true,
			"Chmod": true, "Chtimes": true, "Truncate": true,
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := selector.X.(*ast.Ident)
			if ok && ident.Name == "os" && forbidden[selector.Sel.Name] {
				t.Errorf("%s calls forbidden os.%s", path, selector.Sel.Name)
			}
			return true
		})
	}
}

func newAdmissionFixture(t *testing.T, transport string) *admissionFixture {
	t.Helper()
	root := t.TempDir()
	fixture := &admissionFixture{
		t: t, directory: filepath.Join(root, "admission"),
		trustPath: filepath.Join(root, "accepted-trust.json"),
		topology:  writeRealE0Bundle(t, root, "e0"),
		private:   make(map[string]ed25519.PrivateKey),
	}
	if err := os.Mkdir(fixture.directory, 0o700); err != nil {
		t.Fatal(err)
	}
	e0, err := consumeE0(fixture.topology)
	if err != nil {
		t.Fatal(err)
	}
	defer e0.close()
	keys := []TrustKey{
		fixture.newKey("controller", KeyRoleController, ""),
		fixture.newKey("lease", KeyRoleLease, ""),
	}
	for _, deployment := range e0.descriptor.Deployments {
		keys = append(keys, fixture.newKey(
			"runtime-"+deployment.Role, KeyRoleRuntime, deployment.NodeID,
		))
	}
	fixture.trust = TrustBundle{
		Schema: TrustSchema, AcceptanceID: "accepted-e2-root",
		AcceptedAt: "2030-01-01T09:00:00Z",
		ExpiresAt:  "2030-01-01T12:00:00Z", Keys: keys,
	}
	writeCanonical(t, fixture.trustPath, fixture.trust)
	trustBytes, err := os.ReadFile(fixture.trustPath)
	if err != nil {
		t.Fatal(err)
	}
	deployments := make([]DeploymentBinding, len(e0.descriptor.Deployments))
	for index, row := range e0.descriptor.Deployments {
		deployments[index] = DeploymentBinding{
			Role: row.Role, InstanceUUID: row.InstanceUUID,
			NodeID: row.NodeID, ServiceID: row.ServiceID,
			Provider: row.Provider, OperatorID: row.OperatorID,
		}
	}
	fixture.intent = AdmissionIntent{
		Schema: AdmissionIntentSchema, CycleID: "cycle-e2-0001",
		AttemptID: "attempt-e2-0001", TopologyID: e0.result.TopologyID,
		DescriptorSHA256: e0.result.DescriptorSHA256,
		BundleSHA256:     e0.result.BundleSHA256,
		TrustSHA256:      fileSHA256(trustBytes),
		Nonce:            strings.Repeat("a", 32), AcceptedAt: "2030-01-01T10:00:00Z",
		CounterDomain: "counter-domain-e2", AcceptedCounter: 100,
		ExpectedTransport: transport,
		ExercisedNodes:    []string{deployments[1].NodeID},
		Deployments:       deployments,
		StartNotBefore:    "2030-01-01T10:08:00Z",
		StartDeadline:     "2030-01-01T10:10:00Z",
		FinishDeadline:    "2030-01-01T10:20:00Z",
		ControllerKeyID:   "controller",
	}
	fixture.runtime = RuntimeSet{
		Schema: RuntimeSetSchema, ControllerKeyID: "controller",
	}
	for index, deployment := range deployments {
		fixture.runtime.Attestations = append(
			fixture.runtime.Attestations,
			RuntimeAttestation{
				Schema: RuntimeSchema, Role: deployment.Role,
				InstanceUUID: deployment.InstanceUUID, NodeID: deployment.NodeID,
				ServiceID: deployment.ServiceID, Provider: deployment.Provider,
				OperatorID: deployment.OperatorID,
				BootID: "10000000-0000-4000-8000-00000000000" +
					string(rune('1'+index)),
				ProcessID:         uint64(2000 + index),
				ProcessStartTicks: uint64(3000 + index),
				ExecutableSHA256:  strings.Repeat(string(rune('1'+index)), 64),
				ConfigSHA256:      strings.Repeat(string(rune('5'+index)), 64),
				CertificateSHA256: strings.Repeat(
					[]string{"9", "a", "b", "c"}[index], 64,
				),
				Endpoint: "192.0.2." + string(rune('1'+index)) + ":443",
				Status:   "running",
				ObservedAt: "2030-01-01T10:0" +
					string(rune('1'+index)) + ":00Z",
				CounterDomain:   fixture.intent.CounterDomain,
				ObservedCounter: uint64(101 + index),
				KeyID:           "runtime-" + deployment.Role,
			},
		)
	}
	fixture.reservation = CredentialReservation{
		Schema:  CredentialReservationSchema,
		LeaseID: "lease-e2-0001", ReservationID: "reservation-e2-0001",
		AttemptID: fixture.intent.AttemptID, State: "committed",
		PreparedAt:    "2030-01-01T10:05:00Z",
		CounterDomain: fixture.intent.CounterDomain, PreparedCounter: 105,
		CommittedAt: "2030-01-01T10:06:00Z", CommittedCounter: 106,
		ExpiresAt:     "2030-01-01T11:00:00Z",
		PSKGeneration: 7, PSKKeyID: "psk-generation-7",
		PeerPublicKey:       base64.StdEncoding.EncodeToString(make([]byte, 32)),
		VaultRevisionBefore: 10, VaultRevisionAfter: 11,
		PublisherKeyID: "lease",
	}
	if transport == TransportH3 {
		deployment := deployments[1]
		row := TokenReservation{
			CandidateID: "h3-primary", NodeID: deployment.NodeID,
			ServiceID: deployment.ServiceID, Transport: TransportH3,
			TokenKeyID: "token-key-1", Scope: "carrier",
			IssuerDomain: "issuer.example", ReservedCount: 1,
		}
		row.CommitmentSHA256 = fixture.tokenCommitment(row)
		fixture.reservation.TokenClasses = []TokenReservation{row}
	}
	fixture.readiness = ReadinessEnvelope{
		Schema:        ReadinessEnvelopeSchema,
		AcceptedAt:    "2030-01-01T10:07:00Z",
		CounterDomain: fixture.intent.CounterDomain, AcceptedCounter: 107,
		StartNotBefore: fixture.intent.StartNotBefore,
		StartDeadline:  fixture.intent.StartDeadline,
		FinishDeadline: fixture.intent.FinishDeadline,
		ContractValid:  true, DispatchAuthorized: false, Mutation: "none",
		ControllerKeyID: "controller",
	}
	fixture.seal()
	return fixture
}

func (f *admissionFixture) newKey(id, role, node string) TrustKey {
	f.t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	f.private[id] = private
	return TrustKey{
		KeyID: id, Role: role, NodeID: node,
		PublicKey: base64.StdEncoding.EncodeToString(public),
	}
}

func (f *admissionFixture) sign(keyID, domain string, value any) string {
	f.t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		f.t.Fatal(err)
	}
	message := append(append([]byte(domain), 0), encoded...)
	return base64.StdEncoding.EncodeToString(
		ed25519.Sign(f.private[keyID], message),
	)
}

func (f *admissionFixture) tokenCommitment(row TokenReservation) string {
	f.t.Helper()
	value := struct {
		CandidateID   string `json:"candidate_id"`
		NodeID        string `json:"node_id"`
		ServiceID     string `json:"service_id"`
		Transport     string `json:"transport"`
		TokenKeyID    string `json:"token_key_id"`
		Scope         string `json:"scope"`
		IssuerDomain  string `json:"issuer_domain"`
		ReservedCount uint64 `json:"reserved_count"`
	}{
		row.CandidateID, row.NodeID, row.ServiceID, row.Transport,
		row.TokenKeyID, row.Scope, row.IssuerDomain, row.ReservedCount,
	}
	digest, err := digestObject(reservationCommitmentDomain, value)
	if err != nil {
		f.t.Fatal(err)
	}
	return digest
}

func (f *admissionFixture) seal() {
	f.t.Helper()
	binding, err := digestObject(
		admissionBindingDomain, admissionIntentCoreOf(f.intent),
	)
	if err != nil {
		f.t.Fatal(err)
	}
	f.intent.BindingDigest = binding
	f.intent.Signature = f.sign(
		f.intent.ControllerKeyID, admissionIntentSignatureDomain,
		admissionIntentUnsignedOf(f.intent),
	)
	f.runtime.CycleBindingDigest = binding
	runtimeDigests := make([]string, len(f.runtime.Attestations))
	for index := range f.runtime.Attestations {
		row := &f.runtime.Attestations[index]
		row.CycleBindingDigest = binding
		row.Signature = f.sign(
			row.KeyID, runtimeSignatureDomain, runtimeUnsignedOf(*row),
		)
		runtimeDigests[index], err = digestObject(runtimeObjectDomain, *row)
		if err != nil {
			f.t.Fatal(err)
		}
	}
	f.runtime.CollectionDigest, err = digestObject(
		runtimeCollectionDomain, runtimeDigests,
	)
	if err != nil {
		f.t.Fatal(err)
	}
	f.runtime.Signature = f.sign(
		f.runtime.ControllerKeyID, runtimeSetSignatureDomain,
		runtimeSetUnsigned{
			Schema:             f.runtime.Schema,
			CycleBindingDigest: f.runtime.CycleBindingDigest,
			Attestations:       slices.Clone(f.runtime.Attestations),
			CollectionDigest:   f.runtime.CollectionDigest,
			ControllerKeyID:    f.runtime.ControllerKeyID,
		},
	)
	f.sealReservationAndReadiness()
}

func (f *admissionFixture) writeTrustAndReseal() {
	f.t.Helper()
	writeCanonical(f.t, f.trustPath, f.trust)
	data, err := os.ReadFile(f.trustPath)
	if err != nil {
		f.t.Fatal(err)
	}
	f.intent.TrustSHA256 = fileSHA256(data)
	f.seal()
}

func (f *admissionFixture) sealReservationAndReadiness() {
	f.t.Helper()
	f.reservation.CycleBindingDigest = f.intent.BindingDigest
	if f.reservation.RuntimeCollectionDigest == "" {
		f.reservation.RuntimeCollectionDigest = f.runtime.CollectionDigest
	}
	f.reservation.Signature = f.sign(
		f.reservation.PublisherKeyID, reservationSignatureDomain,
		reservationUnsignedOf(f.reservation),
	)
	reservationDigest, err := digestObject(
		reservationObjectDomain, f.reservation,
	)
	if err != nil {
		f.t.Fatal(err)
	}
	intentBytes := mustCanonical(f.t, f.intent)
	runtimeBytes := mustCanonical(f.t, f.runtime)
	reservationBytes := mustCanonical(f.t, f.reservation)
	f.readiness.CycleBindingDigest = f.intent.BindingDigest
	f.readiness.IntentSHA256 = fileSHA256(intentBytes)
	f.readiness.RuntimeSHA256 = fileSHA256(runtimeBytes)
	f.readiness.RuntimeCollectionDigest = f.runtime.CollectionDigest
	f.readiness.ReservationSHA256 = fileSHA256(reservationBytes)
	f.readiness.ReservationObjectDigest = reservationDigest
	f.readiness.Signature = f.sign(
		f.readiness.ControllerKeyID, readinessSignatureDomain,
		readinessUnsignedOf(f.readiness),
	)
	writePrivate(
		f.t, filepath.Join(f.directory, AdmissionIntentFile), intentBytes,
	)
	writePrivate(f.t, filepath.Join(f.directory, RuntimeFile), runtimeBytes)
	writePrivate(
		f.t, filepath.Join(f.directory, ReservationFile), reservationBytes,
	)
	writeCanonical(
		f.t, filepath.Join(f.directory, ReadinessFile), f.readiness,
	)
}

func TestAdmissionFileOrderIsCanonical(t *testing.T) {
	if !slices.IsSorted(admissionFiles) {
		t.Fatalf("admission files are not sorted: %v", admissionFiles)
	}
	joined := strings.Join(admissionFiles, "\n")
	sum := sha256.Sum256([]byte(joined))
	if len(hex.EncodeToString(sum[:])) != 64 {
		t.Fatal("unexpected digest width")
	}
}
