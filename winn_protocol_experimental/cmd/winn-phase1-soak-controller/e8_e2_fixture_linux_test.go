//go:build linux && winn_incomplete_e8

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/directawg"
	"winsvpn.local/winnprotocol/internal/gatewaymanifest"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/realcycle"
	"winsvpn.local/winnprotocol/internal/realtopology"
	"winsvpn.local/winnprotocol/internal/transparency"
)

const (
	e8AdmissionBindingDomain = "winn-real-cycle-admission-binding/v1"
	e8AdmissionSignature     = "winn-real-cycle-admission-intent-signature/v1"
	e8RuntimeObject          = "winn-real-runtime-attestation-object/v1"
	e8RuntimeSignature       = "winn-real-runtime-attestation-signature/v1"
	e8RuntimeCollection      = "winn-real-runtime-attestation-collection/v1"
	e8RuntimeSetSignature    = "winn-real-runtime-attestation-set-signature/v1"
	e8ReservationObject      = "winn-real-credential-reservation-object/v1"
	e8ReservationSignature   = "winn-real-credential-reservation-signature/v1"
	e8ReadinessSignature     = "winn-real-cycle-readiness-envelope-signature/v1"
)

type e8AdmissionFixture struct {
	directory string
	trustPath string
	topology  string
	trust     realcycle.TrustBundle
	private   map[string]ed25519.PrivateKey
	intent    realcycle.AdmissionIntent
	runtime   realcycle.RuntimeSet
	reserve   realcycle.CredentialReservation
	readiness realcycle.ReadinessEnvelope
}

type e8AdmissionIntentCore struct {
	Schema            string                        `json:"schema"`
	CycleID           string                        `json:"cycle_id"`
	AttemptID         string                        `json:"attempt_id"`
	TopologyID        string                        `json:"topology_id"`
	DescriptorSHA256  string                        `json:"descriptor_sha256"`
	BundleSHA256      string                        `json:"bundle_sha256"`
	TrustSHA256       string                        `json:"trust_sha256"`
	Nonce             string                        `json:"nonce"`
	AcceptedAt        string                        `json:"accepted_at"`
	CounterDomain     string                        `json:"counter_domain"`
	AcceptedCounter   uint64                        `json:"accepted_counter"`
	ExpectedTransport string                        `json:"expected_transport"`
	ExercisedNodes    []string                      `json:"exercised_nodes"`
	Deployments       []realcycle.DeploymentBinding `json:"deployments"`
	StartNotBefore    string                        `json:"start_not_before"`
	StartDeadline     string                        `json:"start_deadline"`
	FinishDeadline    string                        `json:"finish_deadline"`
}

type e8AdmissionIntentUnsigned struct {
	e8AdmissionIntentCore
	BindingDigest   string `json:"binding_digest"`
	ControllerKeyID string `json:"controller_key_id"`
}

type e8RuntimeUnsigned struct {
	Schema             string `json:"schema"`
	CycleBindingDigest string `json:"cycle_binding_digest"`
	Role               string `json:"role"`
	InstanceUUID       string `json:"instance_uuid"`
	NodeID             string `json:"node_id"`
	ServiceID          string `json:"service_id"`
	Provider           string `json:"provider"`
	OperatorID         string `json:"operator_id"`
	BootID             string `json:"boot_id"`
	ProcessID          uint64 `json:"process_id"`
	ProcessStartTicks  uint64 `json:"process_start_ticks"`
	ExecutableSHA256   string `json:"executable_sha256"`
	ConfigSHA256       string `json:"config_sha256"`
	CertificateSHA256  string `json:"certificate_sha256"`
	Endpoint           string `json:"endpoint"`
	Status             string `json:"status"`
	ObservedAt         string `json:"observed_at"`
	CounterDomain      string `json:"counter_domain"`
	ObservedCounter    uint64 `json:"observed_counter"`
	KeyID              string `json:"key_id"`
}

type e8RuntimeSetUnsigned struct {
	Schema             string                         `json:"schema"`
	CycleBindingDigest string                         `json:"cycle_binding_digest"`
	Attestations       []realcycle.RuntimeAttestation `json:"attestations"`
	CollectionDigest   string                         `json:"collection_digest"`
	ControllerKeyID    string                         `json:"controller_key_id"`
}

type e8ReservationUnsigned struct {
	Schema                  string                       `json:"schema"`
	CycleBindingDigest      string                       `json:"cycle_binding_digest"`
	RuntimeCollectionDigest string                       `json:"runtime_collection_digest"`
	LeaseID                 string                       `json:"lease_id"`
	ReservationID           string                       `json:"reservation_id"`
	AttemptID               string                       `json:"attempt_id"`
	State                   string                       `json:"state"`
	PreparedAt              string                       `json:"prepared_at"`
	CounterDomain           string                       `json:"counter_domain"`
	PreparedCounter         uint64                       `json:"prepared_counter"`
	CommittedAt             string                       `json:"committed_at"`
	CommittedCounter        uint64                       `json:"committed_counter"`
	ExpiresAt               string                       `json:"expires_at"`
	PSKGeneration           uint64                       `json:"psk_generation"`
	PSKKeyID                string                       `json:"psk_key_id"`
	PeerPublicKey           string                       `json:"peer_public_key"`
	VaultRevisionBefore     uint64                       `json:"vault_revision_before"`
	VaultRevisionAfter      uint64                       `json:"vault_revision_after"`
	TokenClasses            []realcycle.TokenReservation `json:"token_classes"`
	PublisherKeyID          string                       `json:"publisher_key_id"`
}

type e8ReadinessUnsigned struct {
	Schema                  string `json:"schema"`
	CycleBindingDigest      string `json:"cycle_binding_digest"`
	IntentSHA256            string `json:"intent_sha256"`
	RuntimeSHA256           string `json:"runtime_sha256"`
	RuntimeCollectionDigest string `json:"runtime_collection_digest"`
	ReservationSHA256       string `json:"reservation_sha256"`
	ReservationObjectDigest string `json:"reservation_object_digest"`
	AcceptedAt              string `json:"accepted_at"`
	CounterDomain           string `json:"counter_domain"`
	AcceptedCounter         uint64 `json:"accepted_counter"`
	StartNotBefore          string `json:"start_not_before"`
	StartDeadline           string `json:"start_deadline"`
	FinishDeadline          string `json:"finish_deadline"`
	ContractValid           bool   `json:"contract_valid"`
	DispatchAuthorized      bool   `json:"dispatch_authorized"`
	Mutation                string `json:"mutation"`
	ControllerKeyID         string `json:"controller_key_id"`
}

func e8FixtureDigest(domain string, value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(encoded)
	return hex.EncodeToString(hash.Sum(nil))
}

func e8FixtureBytes(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func e8WritePrivate(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
}

func (fixture *e8AdmissionFixture) sign(
	t *testing.T, keyID, domain string, value any,
) string {
	t.Helper()
	message := append(append([]byte(domain), 0), e8FixtureBytes(t, value)...)
	return base64.StdEncoding.EncodeToString(
		ed25519.Sign(fixture.private[keyID], message),
	)
}

func (fixture *e8AdmissionFixture) newKey(
	t *testing.T, id, role, node string,
) realcycle.TrustKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture.private[id] = private
	return realcycle.TrustKey{
		KeyID: id, Role: role, NodeID: node,
		PublicKey: base64.StdEncoding.EncodeToString(public),
	}
}

func newE8AdmissionFixture(t *testing.T) *e8AdmissionFixture {
	return newE8AdmissionFixtureForWorkers(t, nil, "")
}

func newE8AdmissionFixtureForWorkers(
	t *testing.T,
	identities *[e5PlanNodeCount]e8PreparedIdentity,
	workerSHA string,
) *e8AdmissionFixture {
	t.Helper()
	root := t.TempDir()
	fixture := &e8AdmissionFixture{
		directory: filepath.Join(root, "admission"),
		trustPath: filepath.Join(root, "accepted-trust.json"),
		topology:  filepath.Join(root, "topology"),
		private:   make(map[string]ed25519.PrivateKey),
	}
	if err := os.Mkdir(fixture.directory, 0o700); err != nil {
		t.Fatal(err)
	}
	writeE8TopologyBundle(t, fixture.topology)
	topology, err := realtopology.ValidateBundle(fixture.topology)
	if err != nil {
		t.Fatal(err)
	}
	descriptorBytes, err := os.ReadFile(
		filepath.Join(fixture.topology, realtopology.DescriptorName),
	)
	if err != nil {
		t.Fatal(err)
	}
	var descriptor realtopology.Descriptor
	if err := json.Unmarshal(descriptorBytes, &descriptor); err != nil {
		t.Fatal(err)
	}
	keys := []realcycle.TrustKey{
		fixture.newKey(t, "controller", realcycle.KeyRoleController, ""),
		fixture.newKey(t, "lease", realcycle.KeyRoleLease, ""),
	}
	for _, deployment := range descriptor.Deployments {
		keys = append(keys, fixture.newKey(
			t, "runtime-"+deployment.Role,
			realcycle.KeyRoleRuntime, deployment.NodeID,
		))
	}
	fixture.trust = realcycle.TrustBundle{
		Schema: realcycle.TrustSchema, AcceptanceID: "accepted-e2-root",
		AcceptedAt: "2030-01-01T09:00:00Z",
		ExpiresAt:  "2030-01-01T12:00:00Z", Keys: keys,
	}
	trustBytes := append(e8FixtureBytes(t, fixture.trust), '\n')
	e8WritePrivate(t, fixture.trustPath, trustBytes)
	deployments := make([]realcycle.DeploymentBinding, len(descriptor.Deployments))
	for index, row := range descriptor.Deployments {
		deployments[index] = realcycle.DeploymentBinding{
			Role: row.Role, InstanceUUID: row.InstanceUUID,
			NodeID: row.NodeID, ServiceID: row.ServiceID,
			Provider: row.Provider, OperatorID: row.OperatorID,
		}
	}
	fixture.intent = realcycle.AdmissionIntent{
		Schema:  realcycle.AdmissionIntentSchema,
		CycleID: "cycle-e8-real", AttemptID: "attempt-e8-real",
		TopologyID:       topology.TopologyID,
		DescriptorSHA256: topology.DescriptorSHA256,
		BundleSHA256:     topology.BundleSHA256,
		TrustSHA256:      admittedRawSHA(trustBytes),
		Nonce:            stringsRepeat("a", 32), AcceptedAt: "2030-01-01T10:00:00Z",
		CounterDomain: "counter-domain-e8", AcceptedCounter: 100,
		ExpectedTransport: realcycle.TransportDirect,
		ExercisedNodes: []string{
			deployments[0].NodeID, deployments[1].NodeID,
			deployments[2].NodeID, deployments[3].NodeID,
		},
		Deployments:     deployments,
		StartNotBefore:  "2030-01-01T10:08:00Z",
		StartDeadline:   "2030-01-01T10:10:00Z",
		FinishDeadline:  "2030-01-01T10:20:00Z",
		ControllerKeyID: "controller",
	}
	fixture.runtime = realcycle.RuntimeSet{
		Schema: realcycle.RuntimeSetSchema, ControllerKeyID: "controller",
	}
	for index, deployment := range deployments {
		fixture.runtime.Attestations = append(
			fixture.runtime.Attestations,
			realcycle.RuntimeAttestation{
				Schema: realcycle.RuntimeSchema, Role: deployment.Role,
				InstanceUUID: deployment.InstanceUUID, NodeID: deployment.NodeID,
				ServiceID: deployment.ServiceID, Provider: deployment.Provider,
				OperatorID: deployment.OperatorID,
				BootID: "10000000-0000-4000-8000-00000000000" +
					string(rune('1'+index)),
				ProcessID:         uint64(2000 + index),
				ProcessStartTicks: uint64(3000 + index),
				ExecutableSHA256:  stringsRepeat(string(rune('1'+index)), 64),
				ConfigSHA256:      stringsRepeat(string(rune('5'+index)), 64),
				CertificateSHA256: stringsRepeat(
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
	fixture.reserve = realcycle.CredentialReservation{
		Schema:  realcycle.CredentialReservationSchema,
		LeaseID: "lease-e8", ReservationID: "reservation-e8",
		AttemptID: fixture.intent.AttemptID, State: "committed",
		PreparedAt:    "2030-01-01T10:05:00Z",
		CounterDomain: fixture.intent.CounterDomain, PreparedCounter: 105,
		CommittedAt: "2030-01-01T10:06:00Z", CommittedCounter: 106,
		ExpiresAt: "2030-01-01T11:00:00Z", PSKGeneration: 7,
		PSKKeyID:            "psk-generation-7",
		PeerPublicKey:       base64.StdEncoding.EncodeToString(make([]byte, 32)),
		VaultRevisionBefore: 10, VaultRevisionAfter: 11,
		PublisherKeyID: "lease",
	}
	fixture.readiness = realcycle.ReadinessEnvelope{
		Schema:        realcycle.ReadinessEnvelopeSchema,
		AcceptedAt:    "2030-01-01T10:07:00Z",
		CounterDomain: fixture.intent.CounterDomain, AcceptedCounter: 107,
		StartNotBefore: fixture.intent.StartNotBefore,
		StartDeadline:  fixture.intent.StartDeadline,
		FinishDeadline: fixture.intent.FinishDeadline,
		ContractValid:  true, DispatchAuthorized: false, Mutation: "none",
		ControllerKeyID: "controller",
	}
	if identities != nil {
		if !digestPattern.MatchString(workerSHA) {
			t.Fatal("prepared fixture worker digest is malformed")
		}
		for index := range fixture.runtime.Attestations {
			identity := identities[index]
			if identity.Schema != e8PreparedIdentitySchema ||
				identity.WorkerSHA256 != workerSHA ||
				identity.ProcessID == 0 || identity.ProcessStartTicks == 0 {
				t.Fatalf("prepared fixture identity %d is invalid", index)
			}
			fixture.runtime.Attestations[index].ProcessID = identity.ProcessID
			fixture.runtime.Attestations[index].ProcessStartTicks =
				identity.ProcessStartTicks
			fixture.runtime.Attestations[index].ExecutableSHA256 = workerSHA
		}
	}
	fixture.seal(t)
	return fixture
}

func stringsRepeat(value string, count int) string {
	result := make([]byte, 0, len(value)*count)
	for range count {
		result = append(result, value...)
	}
	return string(result)
}

func (fixture *e8AdmissionFixture) seal(t *testing.T) {
	t.Helper()
	core := e8AdmissionIntentCore{
		Schema: fixture.intent.Schema, CycleID: fixture.intent.CycleID,
		AttemptID: fixture.intent.AttemptID, TopologyID: fixture.intent.TopologyID,
		DescriptorSHA256: fixture.intent.DescriptorSHA256,
		BundleSHA256:     fixture.intent.BundleSHA256,
		TrustSHA256:      fixture.intent.TrustSHA256, Nonce: fixture.intent.Nonce,
		AcceptedAt:        fixture.intent.AcceptedAt,
		CounterDomain:     fixture.intent.CounterDomain,
		AcceptedCounter:   fixture.intent.AcceptedCounter,
		ExpectedTransport: fixture.intent.ExpectedTransport,
		ExercisedNodes:    slices.Clone(fixture.intent.ExercisedNodes),
		Deployments:       slices.Clone(fixture.intent.Deployments),
		StartNotBefore:    fixture.intent.StartNotBefore,
		StartDeadline:     fixture.intent.StartDeadline,
		FinishDeadline:    fixture.intent.FinishDeadline,
	}
	fixture.intent.BindingDigest = e8FixtureDigest(e8AdmissionBindingDomain, core)
	fixture.intent.Signature = fixture.sign(
		t, "controller", e8AdmissionSignature, e8AdmissionIntentUnsigned{
			e8AdmissionIntentCore: core,
			BindingDigest:         fixture.intent.BindingDigest,
			ControllerKeyID:       fixture.intent.ControllerKeyID,
		},
	)
	fixture.runtime.CycleBindingDigest = fixture.intent.BindingDigest
	runtimeDigests := make([]string, len(fixture.runtime.Attestations))
	for index := range fixture.runtime.Attestations {
		row := &fixture.runtime.Attestations[index]
		row.CycleBindingDigest = fixture.intent.BindingDigest
		unsigned := e8RuntimeUnsigned{
			Schema: row.Schema, CycleBindingDigest: row.CycleBindingDigest,
			Role: row.Role, InstanceUUID: row.InstanceUUID, NodeID: row.NodeID,
			ServiceID: row.ServiceID, Provider: row.Provider,
			OperatorID: row.OperatorID, BootID: row.BootID,
			ProcessID: row.ProcessID, ProcessStartTicks: row.ProcessStartTicks,
			ExecutableSHA256:  row.ExecutableSHA256,
			ConfigSHA256:      row.ConfigSHA256,
			CertificateSHA256: row.CertificateSHA256, Endpoint: row.Endpoint,
			Status: row.Status, ObservedAt: row.ObservedAt,
			CounterDomain:   row.CounterDomain,
			ObservedCounter: row.ObservedCounter, KeyID: row.KeyID,
		}
		row.Signature = fixture.sign(t, row.KeyID, e8RuntimeSignature, unsigned)
		runtimeDigests[index] = e8FixtureDigest(e8RuntimeObject, *row)
	}
	fixture.runtime.CollectionDigest =
		e8FixtureDigest(e8RuntimeCollection, runtimeDigests)
	fixture.runtime.Signature = fixture.sign(
		t, "controller", e8RuntimeSetSignature, e8RuntimeSetUnsigned{
			Schema:             fixture.runtime.Schema,
			CycleBindingDigest: fixture.runtime.CycleBindingDigest,
			Attestations:       slices.Clone(fixture.runtime.Attestations),
			CollectionDigest:   fixture.runtime.CollectionDigest,
			ControllerKeyID:    fixture.runtime.ControllerKeyID,
		},
	)
	fixture.reserve.CycleBindingDigest = fixture.intent.BindingDigest
	fixture.reserve.RuntimeCollectionDigest = fixture.runtime.CollectionDigest
	fixture.reserve.Signature = fixture.sign(
		t, "lease", e8ReservationSignature, e8ReservationUnsigned{
			Schema:                  fixture.reserve.Schema,
			CycleBindingDigest:      fixture.reserve.CycleBindingDigest,
			RuntimeCollectionDigest: fixture.reserve.RuntimeCollectionDigest,
			LeaseID:                 fixture.reserve.LeaseID,
			ReservationID:           fixture.reserve.ReservationID,
			AttemptID:               fixture.reserve.AttemptID, State: fixture.reserve.State,
			PreparedAt:          fixture.reserve.PreparedAt,
			CounterDomain:       fixture.reserve.CounterDomain,
			PreparedCounter:     fixture.reserve.PreparedCounter,
			CommittedAt:         fixture.reserve.CommittedAt,
			CommittedCounter:    fixture.reserve.CommittedCounter,
			ExpiresAt:           fixture.reserve.ExpiresAt,
			PSKGeneration:       fixture.reserve.PSKGeneration,
			PSKKeyID:            fixture.reserve.PSKKeyID,
			PeerPublicKey:       fixture.reserve.PeerPublicKey,
			VaultRevisionBefore: fixture.reserve.VaultRevisionBefore,
			VaultRevisionAfter:  fixture.reserve.VaultRevisionAfter,
			TokenClasses:        slices.Clone(fixture.reserve.TokenClasses),
			PublisherKeyID:      fixture.reserve.PublisherKeyID,
		},
	)
	intentBytes := append(e8FixtureBytes(t, fixture.intent), '\n')
	runtimeBytes := append(e8FixtureBytes(t, fixture.runtime), '\n')
	reserveBytes := append(e8FixtureBytes(t, fixture.reserve), '\n')
	fixture.readiness.CycleBindingDigest = fixture.intent.BindingDigest
	fixture.readiness.IntentSHA256 = admittedRawSHA(intentBytes)
	fixture.readiness.RuntimeSHA256 = admittedRawSHA(runtimeBytes)
	fixture.readiness.RuntimeCollectionDigest = fixture.runtime.CollectionDigest
	fixture.readiness.ReservationSHA256 = admittedRawSHA(reserveBytes)
	fixture.readiness.ReservationObjectDigest =
		e8FixtureDigest(e8ReservationObject, fixture.reserve)
	fixture.readiness.Signature = fixture.sign(
		t, "controller", e8ReadinessSignature, e8ReadinessUnsigned{
			Schema:                  fixture.readiness.Schema,
			CycleBindingDigest:      fixture.readiness.CycleBindingDigest,
			IntentSHA256:            fixture.readiness.IntentSHA256,
			RuntimeSHA256:           fixture.readiness.RuntimeSHA256,
			RuntimeCollectionDigest: fixture.readiness.RuntimeCollectionDigest,
			ReservationSHA256:       fixture.readiness.ReservationSHA256,
			ReservationObjectDigest: fixture.readiness.ReservationObjectDigest,
			AcceptedAt:              fixture.readiness.AcceptedAt,
			CounterDomain:           fixture.readiness.CounterDomain,
			AcceptedCounter:         fixture.readiness.AcceptedCounter,
			StartNotBefore:          fixture.readiness.StartNotBefore,
			StartDeadline:           fixture.readiness.StartDeadline,
			FinishDeadline:          fixture.readiness.FinishDeadline,
			ContractValid:           fixture.readiness.ContractValid,
			DispatchAuthorized:      fixture.readiness.DispatchAuthorized,
			Mutation:                fixture.readiness.Mutation,
			ControllerKeyID:         fixture.readiness.ControllerKeyID,
		},
	)
	e8WritePrivate(t, filepath.Join(
		fixture.directory, realcycle.AdmissionIntentFile,
	), intentBytes)
	e8WritePrivate(t, filepath.Join(
		fixture.directory, realcycle.RuntimeFile,
	), runtimeBytes)
	e8WritePrivate(t, filepath.Join(
		fixture.directory, realcycle.ReservationFile,
	), reserveBytes)
	e8WritePrivate(t, filepath.Join(
		fixture.directory, realcycle.ReadinessFile,
	), append(e8FixtureBytes(t, fixture.readiness), '\n'))
}

func writeE8TopologyBundle(t *testing.T, bundle string) {
	t.Helper()
	if err := os.Mkdir(bundle, 0o700); err != nil {
		t.Fatal(err)
	}
	files := e8TopologyPublicDocuments(t)
	inventory := make(
		[]realtopology.PublicFile, 0, len(realtopology.AllowedPublicBasenames),
	)
	for _, basename := range realtopology.AllowedPublicBasenames {
		data := files[basename]
		if err := os.WriteFile(filepath.Join(bundle, basename), data, 0o444); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		inventory = append(inventory, realtopology.PublicFile{
			Name: basename, Size: int64(len(data)),
			SHA256: hex.EncodeToString(digest[:]),
		})
	}
	descriptor := realtopology.Descriptor{
		Schema:     realtopology.Schema,
		TopologyID: "generated-four-node-e8-fixture",
		Protocol:   realtopology.ProtocolVersion, LiveReady: false,
		ExercisedNodes: []string{},
		Deployments: []realtopology.Deployment{
			{
				Role:         realtopology.RoleControl,
				InstanceUUID: "11111111-1111-4111-8111-111111111111",
				NodeID:       "controller-1", ServiceID: "service-controller-1",
				Provider: "provider-a", OperatorID: "operator-control",
			},
			{
				Role:         realtopology.RoleEntryPrimary,
				InstanceUUID: "22222222-2222-4222-8222-222222222222",
				NodeID:       "entry-primary-node",
				ServiceID:    "entry-primary-service",
				Provider:     "provider-a", OperatorID: "operator-entry",
			},
			{
				Role:         realtopology.RoleEntrySecondary,
				InstanceUUID: "33333333-3333-4333-8333-333333333333",
				NodeID:       "entry-secondary-node",
				ServiceID:    "entry-secondary-service",
				Provider:     "provider-a", OperatorID: "operator-entry",
			},
			{
				Role:         realtopology.RoleExit,
				InstanceUUID: "44444444-4444-4444-8444-444444444444",
				NodeID:       "exit-node", ServiceID: "exit-service",
				Provider: "provider-b", OperatorID: "operator-exit",
			},
		},
		Files: inventory,
	}
	data := append(e8FixtureBytes(t, descriptor), '\n')
	if err := os.WriteFile(
		filepath.Join(bundle, realtopology.DescriptorName), data, 0o444,
	); err != nil {
		t.Fatal(err)
	}
}

func e8TopologyPublicDocuments(t *testing.T) map[string][]byte {
	t.Helper()
	now := time.Date(2026, 7, 27, 20, 0, 0, 0, time.UTC)
	signer, err := pqauth.NewSigner(
		pqauth.MLDSA65, bytes.Repeat([]byte{0x31}, 32),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	rawAWG := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	directNode := func(
		id, operator, provider, role, transportID, endpoint string,
	) gatewaymanifest.NodeV2 {
		return gatewaymanifest.NodeV2{
			ID: id, OperatorID: operator, Provider: provider,
			Roles: []string{gatewaymanifest.RoleCarrier, role},
			Transports: []gatewaymanifest.TransportV2{{
				ID: transportID, Type: connectivity.CarrierDirectAWG,
				Endpoint: endpoint, Suite: "x25519-mlkem768",
				AuthenticationModes: []string{gatewaymanifest.AuthAWGPSK},
				PublicAWGKey:        rawAWG, MinInnerDatagram: 1200,
				MaxInnerDatagram: 1350,
				Capabilities: []string{
					"awg-handshake-readiness",
					"candidate-isolated-verification",
				},
			}},
			Capabilities: []string{
				"active-probe-resistant",
				"candidate-isolated-verification",
			},
		}
	}
	manifest := gatewaymanifest.ManifestV2{
		Format: gatewaymanifest.FormatV2, Sequence: 1,
		IssuedAt:     now.Format(time.RFC3339Nano),
		ExpiresAt:    now.Add(24 * time.Hour).Format(time.RFC3339Nano),
		ControllerID: "controller-1", Suite: "x25519-mlkem768",
		MinimumClient: gatewaymanifest.MinimumClientV3,
		Capabilities:  gatewaymanifest.RequiredV2Capabilities(),
		Nodes: []gatewaymanifest.NodeV2{
			directNode(
				"entry-primary-node", "operator-entry", "provider-a",
				gatewaymanifest.RoleEntry, "entry-primary-service",
				"192.0.2.10:51820",
			),
			directNode(
				"entry-secondary-node", "operator-entry", "provider-a",
				gatewaymanifest.RoleEntry, "entry-secondary-service",
				"192.0.2.11:51820",
			),
			directNode(
				"exit-node", "operator-exit", "provider-b",
				gatewaymanifest.RoleExit, "exit-service", "192.0.2.12:51820",
			),
		},
	}
	if err := gatewaymanifest.SignV2(&manifest, signer); err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := gatewaymanifest.EncodeV2(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest, err := gatewaymanifest.DigestV2(manifest)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := pqauth.VerifierSetDocument(signer)
	if err != nil {
		t.Fatal(err)
	}
	pinsBytes := append(e8FixtureBytes(t, pins), '\n')
	receipt, err := transparency.NewReceipt(1, manifestDigest, "", signer, now)
	if err != nil {
		t.Fatal(err)
	}
	receiptDigest, err := transparency.Digest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes := append(e8FixtureBytes(t, receipt), '\n')
	trustBytes, err := gatewaymanifest.EncodeTrustStateV2(
		gatewaymanifest.TrustStateV2{
			Format:          gatewaymanifest.TrustStateFormatV2,
			HighestSequence: 1, ManifestDigest: manifestDigest,
			Checkpoint: transparency.Checkpoint{
				Size: 1, ReceiptDigest: receiptDigest,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	profile := directawg.LinuxDeploymentProfile{
		Format:         directawg.LinuxDeploymentProfileFormat,
		ManifestDigest: manifestDigest, NodeID: "entry-primary-node",
		TransportID: "entry-primary-service",
		IssuedAt:    now.Format(time.RFC3339),
		ExpiresAt:   now.Add(24 * time.Hour).Format(time.RFC3339),
		Interface: directawg.LinuxInterfaceProfile{
			InnerAddressPool:   "10.77.0.0/24",
			AllowedIPs:         []string{"0.0.0.0/0"},
			VerificationRoutes: []string{"10.66.0.0/24"},
			MTU:                1280, ListenPortMin: 40000, ListenPortMax: 40100,
			PersistentKeepalive: 25,
			Obfuscation: directawg.AWGObfuscation{
				JC: 4, JMin: 12, JMax: 64, S1: 16, S2: 80,
				S3: 24, S4: 8, H1: 101, H2: 202, H3: 303, H4: 404,
			},
		},
		Probe: directawg.LinuxProbeProfile{
			DNSResolver:        "10.66.0.53:53",
			DNSQueryName:       "canary.winn.invalid",
			ExpectedDNSAnswers: []string{"10.66.0.9"},
			CanaryEndpoint:     "10.66.0.9:7007", TimeoutMilliseconds: 3000,
		},
	}
	if err := directawg.SignLinuxDeploymentProfile(&profile, signer); err != nil {
		t.Fatal(err)
	}
	profileBytes := append(e8FixtureBytes(t, profile), '\n')
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Winn generated E8 carrier root"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	certificateDER, err := x509.CreateCertificate(
		rand.Reader, template, template, private.Public(), private,
	)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER},
	)
	return map[string][]byte{
		"accepted-trust-state-v2.json": trustBytes,
		"carrier-root-ca.pem":          certificatePEM,
		"controller-pq-pins.json":      pinsBytes,
		"gateway-manifest-v2.json":     manifestBytes,
		"linux-profile.json":           profileBytes,
		"transparency.jsonl":           receiptBytes,
	}
}

func TestE8FixturePassesRealE2Validation(t *testing.T) {
	fixture := newE8AdmissionFixture(t)
	result, err := realcycle.ValidateAdmission(
		fixture.directory, fixture.trustPath, fixture.topology,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.CycleID != fixture.intent.CycleID ||
		result.AttemptID != fixture.intent.AttemptID ||
		result.TopologyID != fixture.intent.TopologyID ||
		result.RuntimeCount != 4 || result.ExercisedNodeCount != 4 {
		t.Fatalf("unsafe or incomplete E2 result: %+v", result)
	}
}
