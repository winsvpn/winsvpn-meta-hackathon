package preparation

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/rotation"
)

func TestProductionHybridPSKPoolValidatesPinsAndZerosSnapshot(
	t *testing.T,
) {
	harness := newProductionPSKPoolHarness(t)
	lease, err := harness.pool.AcquireCurrentHybridPSK(
		context.Background(), harness.request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if lease.Generation != harness.generation ||
		!lease.ExpiresAt.Equal(harness.expiresAt) ||
		lease.PSKs == nil ||
		lease.Resource == nil {
		t.Fatalf("hybrid PSK pool lease changed: %#v", lease)
	}
	harness.source.mu.Lock()
	cleared := isAllZero(harness.source.lastPSK)
	harness.source.mu.Unlock()
	if !cleared {
		t.Fatal("adapter retained source-owned raw PSK bytes")
	}

	const references = 64
	resources := make([]Resource, references)
	for index := range references {
		sublease, err := lease.PSKs.AcquireHybridPSK(
			context.Background(), harness.generation,
		)
		if err != nil {
			t.Fatal(err)
		}
		resources[index] = sublease.Resource
	}
	if _, err := lease.PSKs.AcquireHybridPSK(
		context.Background(), harness.generation+1,
	); err == nil {
		t.Fatal("unpinned PSK generation was leased")
	}
	if err := lease.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if harness.source.closed.Load() != 0 {
		t.Fatal("root close revoked active generation references")
	}
	var group sync.WaitGroup
	group.Add(len(resources))
	for _, resource := range resources {
		go func(current Resource) {
			defer group.Done()
			if err := current.Close(context.Background()); err != nil {
				t.Error(err)
			}
		}(resource)
	}
	group.Wait()
	if harness.source.closed.Load() != 1 {
		t.Fatalf(
			"pinned source close count = %d; want 1",
			harness.source.closed.Load(),
		)
	}
}

func TestProductionHybridPSKPoolRejectsAlteredOrStaleState(
	t *testing.T,
) {
	tests := []struct {
		name   string
		mutate func(*productionPSKPoolHarness)
	}{
		{
			name: "manifest binding altered",
			mutate: func(h *productionPSKPoolHarness) {
				h.source.requestMutator = func(
					request *HybridPSKPoolRequest,
				) {
					request.ManifestDigest = strings.Repeat("f", 64)
				}
			},
		},
		{
			name: "stale observation",
			mutate: func(h *productionPSKPoolHarness) {
				h.source.observedOffset =
					-maximumPoolObservationAge - time.Nanosecond
			},
		},
		{
			name: "rotation has pending request",
			mutate: func(h *productionPSKPoolHarness) {
				h.source.pending = true
			},
		},
		{
			name: "key ID altered",
			mutate: func(h *productionPSKPoolHarness) {
				h.source.keyIDOverride = strings.Repeat("0", 64)
			},
		},
		{
			name: "generation altered",
			mutate: func(h *productionPSKPoolHarness) {
				h.source.generationOffset = 1
			},
		},
		{
			name: "all-zero key",
			mutate: func(h *productionPSKPoolHarness) {
				h.source.zeroPSK = true
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newProductionPSKPoolHarness(t)
			test.mutate(harness)
			if _, err := harness.pool.AcquireCurrentHybridPSK(
				context.Background(), harness.request,
			); err == nil {
				t.Fatal("invalid pinned PSK snapshot was accepted")
			}
			if harness.source.closed.Load() != 1 {
				t.Fatalf(
					"invalid source close count = %d; want 1",
					harness.source.closed.Load(),
				)
			}
			harness.source.mu.Lock()
			cleared := isAllZero(harness.source.lastPSK)
			harness.source.mu.Unlock()
			if !cleared {
				t.Fatal("rejected raw PSK was not cleared")
			}
		})
	}
}

func TestProductionHybridPSKPoolHonorsCancellationAfterPin(
	t *testing.T,
) {
	harness := newProductionPSKPoolHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	harness.source.afterPin = cancel
	if _, err := harness.pool.AcquireCurrentHybridPSK(
		ctx, harness.request,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-pin cancellation error = %v", err)
	}
	if harness.source.closed.Load() != 1 {
		t.Fatalf(
			"cancelled source close count = %d; want 1",
			harness.source.closed.Load(),
		)
	}
	harness.source.mu.Lock()
	cleared := isAllZero(harness.source.lastPSK)
	harness.source.mu.Unlock()
	if !cleared {
		t.Fatal("cancelled raw PSK was not cleared")
	}
}

func TestProductionAnonymousCredentialPoolValidatesAndScopesTokens(
	t *testing.T,
) {
	harness := newProductionCredentialPoolHarness(t, 1)
	lease, err := harness.pool.AcquireAnonymousCredentialInventory(
		context.Background(), harness.request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if lease.UnusedCredentials != 12 ||
		len(lease.ClassInventories) != 1 ||
		len(lease.Requirements) != 1 ||
		lease.Credentials == nil ||
		lease.Resource == nil {
		t.Fatalf("credential pool lease changed: %#v", lease)
	}
	requirement := harness.request.Requirements[0]
	sublease, err := lease.Credentials.AcquireAnonymousCredentials(
		context.Background(),
		credentialSubleaseRequest(requirement, lease.ExpiresAt),
	)
	if err != nil {
		t.Fatal(err)
	}
	if sublease.Count != MinimumReservedCredentialsPerH3 ||
		sublease.Source == nil ||
		sublease.Resource == nil {
		t.Fatalf("credential sublease changed: %#v", sublease)
	}
	seen := make(map[string]struct{})
	for range MinimumReservedCredentialsPerH3 {
		credential, err := sublease.Source.NextAnonymousCredential()
		if err != nil {
			t.Fatal(err)
		}
		verified, err := privacytoken.Verify(
			credential.Token,
			harness.issuer,
			requirement.TokenKeyID,
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, duplicate := seen[verified.TokenID]; duplicate {
			t.Fatal("credential source returned a duplicate token")
		}
		seen[verified.TokenID] = struct{}{}
	}
	if _, err := sublease.Source.NextAnonymousCredential(); err == nil {
		t.Fatal("credential source exceeded its exact reservation")
	}
	if _, err := lease.Credentials.AcquireAnonymousCredentials(
		context.Background(),
		credentialSubleaseRequest(requirement, lease.ExpiresAt),
	); err == nil {
		t.Fatal("candidate reservation was acquired twice")
	}
	if err := sublease.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lease.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if harness.vault.rootClosed.Load() != 1 ||
		harness.vault.candidateClosed.Load() != 1 {
		t.Fatalf(
			"vault cleanup root=%d candidate=%d",
			harness.vault.rootClosed.Load(),
			harness.vault.candidateClosed.Load(),
		)
	}
}

func TestProductionAnonymousCredentialPoolRejectsReplayAcrossCandidates(
	t *testing.T,
) {
	harness := newProductionCredentialPoolHarness(t, 2)
	harness.vault.duplicateAcrossCandidates = true
	lease, err := harness.pool.AcquireAnonymousCredentialInventory(
		context.Background(), harness.request,
	)
	if err != nil {
		t.Fatal(err)
	}
	first, err := lease.Credentials.AcquireAnonymousCredentials(
		context.Background(),
		credentialSubleaseRequest(
			harness.request.Requirements[0], lease.ExpiresAt,
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := lease.Credentials.AcquireAnonymousCredentials(
		context.Background(),
		credentialSubleaseRequest(
			harness.request.Requirements[1], lease.ExpiresAt,
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Source.NextAnonymousCredential(); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Source.NextAnonymousCredential(); err == nil {
		t.Fatal("cross-candidate credential replay was accepted")
	}
	if err := first.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := second.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lease.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestProductionAnonymousCredentialPoolScopesLifetimeAndExpiry(
	t *testing.T,
) {
	t.Run("closed pool", func(t *testing.T) {
		harness := newProductionCredentialPoolHarness(t, 1)
		lease, err := harness.pool.AcquireAnonymousCredentialInventory(
			context.Background(), harness.request,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := lease.Resource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := lease.Credentials.AcquireAnonymousCredentials(
			context.Background(),
			credentialSubleaseRequest(
				harness.request.Requirements[0],
				lease.ExpiresAt,
			),
		); err == nil {
			t.Fatal("closed credential pool issued a sublease")
		}
	})

	t.Run("expired pool and source", func(t *testing.T) {
		harness := newProductionCredentialPoolHarness(t, 1)
		lease, err := harness.pool.AcquireAnonymousCredentialInventory(
			context.Background(), harness.request,
		)
		if err != nil {
			t.Fatal(err)
		}
		requirement := harness.request.Requirements[0]
		sublease, err := lease.Credentials.AcquireAnonymousCredentials(
			context.Background(),
			credentialSubleaseRequest(requirement, lease.ExpiresAt),
		)
		if err != nil {
			t.Fatal(err)
		}
		harness.clock.Set(lease.ExpiresAt)
		if _, err := sublease.Source.NextAnonymousCredential(); err == nil {
			t.Fatal("expired credential source issued a credential")
		}
		if err := sublease.Resource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := lease.Resource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestProductionAnonymousCredentialPoolHonorsCancellationAfterReserve(
	t *testing.T,
) {
	harness := newProductionCredentialPoolHarness(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	harness.vault.afterReserve = cancel
	if _, err := harness.pool.AcquireAnonymousCredentialInventory(
		ctx, harness.request,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-reservation cancellation error = %v", err)
	}
	if harness.vault.rootClosed.Load() != 1 ||
		harness.vault.candidateClosed.Load() != 1 {
		t.Fatalf(
			"cancelled vault cleanup root=%d candidate=%d",
			harness.vault.rootClosed.Load(),
			harness.vault.candidateClosed.Load(),
		)
	}
}

func TestProductionAnonymousCredentialPoolRejectsFalseEvidence(
	t *testing.T,
) {
	tests := []struct {
		name   string
		mutate func(*productionCredentialPoolHarness)
	}{
		{
			name: "vault is not durable",
			mutate: func(h *productionCredentialPoolHarness) {
				h.vault.durable = false
			},
		},
		{
			name: "reservation binding altered",
			mutate: func(h *productionCredentialPoolHarness) {
				h.vault.alterRequirement = true
			},
		},
		{
			name: "class inventory below floor",
			mutate: func(h *productionCredentialPoolHarness) {
				h.vault.unused = 7
			},
		},
		{
			name: "stale observation",
			mutate: func(h *productionCredentialPoolHarness) {
				h.vault.observedOffset =
					-maximumPoolObservationAge - time.Nanosecond
			},
		},
		{
			name: "candidate reservation omitted",
			mutate: func(h *productionCredentialPoolHarness) {
				h.vault.omitCandidate = true
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newProductionCredentialPoolHarness(t, 1)
			test.mutate(harness)
			if _, err := harness.pool.
				AcquireAnonymousCredentialInventory(
					context.Background(), harness.request,
				); err == nil {
				t.Fatal("false credential evidence was accepted")
			}
			if harness.vault.rootClosed.Load() != 1 {
				t.Fatalf(
					"rejected vault root closes = %d; want 1",
					harness.vault.rootClosed.Load(),
				)
			}
		})
	}
}

func TestProductionAnonymousCredentialSourceRejectsAlteredProof(
	t *testing.T,
) {
	harness := newProductionCredentialPoolHarness(t, 1)
	harness.vault.alterPseudonym = true
	lease, err := harness.pool.AcquireAnonymousCredentialInventory(
		context.Background(), harness.request,
	)
	if err != nil {
		t.Fatal(err)
	}
	requirement := harness.request.Requirements[0]
	sublease, err := lease.Credentials.AcquireAnonymousCredentials(
		context.Background(),
		credentialSubleaseRequest(requirement, lease.ExpiresAt),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sublease.Source.NextAnonymousCredential(); err == nil {
		t.Fatal("altered credential pseudonym was accepted")
	}
	if harness.vault.lastIssuedSigner == nil ||
		!harness.vault.lastIssuedSigner.Destroyed() {
		t.Fatal("rejected credential signer was not destroyed")
	}
	if err := sublease.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lease.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestProductionCredentialPoolConcurrentReserveConsumeCleanup(
	t *testing.T,
) {
	const candidates = 8
	harness := newProductionCredentialPoolHarness(t, candidates)
	lease, err := harness.pool.AcquireAnonymousCredentialInventory(
		context.Background(), harness.request,
	)
	if err != nil {
		t.Fatal(err)
	}
	failures := make(chan error, candidates)
	var group sync.WaitGroup
	group.Add(candidates)
	for _, requirement := range harness.request.Requirements {
		go func(current AnonymousCredentialRequirement) {
			defer group.Done()
			sublease, err := lease.Credentials.
				AcquireAnonymousCredentials(
					context.Background(),
					credentialSubleaseRequest(
						current, lease.ExpiresAt,
					),
				)
			if err != nil {
				failures <- err
				return
			}
			for range current.Count {
				if _, err := sublease.Source.
					NextAnonymousCredential(); err != nil {
					failures <- err
				}
			}
			if err := sublease.Resource.Close(
				context.Background(),
			); err != nil {
				failures <- err
			}
		}(requirement)
	}
	group.Wait()
	if err := lease.Resource.Close(context.Background()); err != nil {
		failures <- err
	}
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	if harness.vault.candidateClosed.Load() != candidates ||
		harness.vault.rootClosed.Load() != 1 {
		t.Fatalf(
			"concurrent vault cleanup candidate=%d root=%d",
			harness.vault.candidateClosed.Load(),
			harness.vault.rootClosed.Load(),
		)
	}
}

type productionPSKPoolHarness struct {
	now        time.Time
	generation uint64
	expiresAt  time.Time
	request    HybridPSKPoolRequest
	source     *testPinnedHybridPSKSource
	pool       *ProductionHybridPSKPool
	clock      *productionPoolTestClock
}

func newProductionPSKPoolHarness(
	t testing.TB,
) *productionPSKPoolHarness {
	t.Helper()
	now := productionNow()
	clock := &productionPoolTestClock{current: now}
	generation := uint64(19)
	expiresAt := now.Add(time.Hour)
	peerPublicKey := base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{0x45}, 32),
	)
	request := HybridPSKPoolRequest{
		Profile:           "auto-production",
		ControllerID:      "controller-production",
		ManifestDigest:    strings.Repeat("a", 64),
		ManifestSequence:  7,
		ManifestExpiresAt: now.Add(2 * time.Hour),
	}
	source := &testPinnedHybridPSKSource{
		now:           now,
		suite:         protocol.DefaultSuite,
		deviceID:      "device-production",
		peerPublicKey: peerPublicKey,
		generation:    generation,
		expiresAt:     expiresAt,
	}
	pool, err := NewProductionHybridPSKPool(
		ProductionHybridPSKPoolConfig{
			Source:        source,
			Suite:         source.suite,
			DeviceID:      source.deviceID,
			PeerPublicKey: source.peerPublicKey,
			Now:           clock.Now,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return &productionPSKPoolHarness{
		now:        now,
		generation: generation,
		expiresAt:  expiresAt,
		request:    request,
		source:     source,
		pool:       pool,
		clock:      clock,
	}
}

type testPinnedHybridPSKSource struct {
	mu sync.Mutex

	now              time.Time
	suite            string
	deviceID         string
	peerPublicKey    string
	generation       uint64
	expiresAt        time.Time
	requestMutator   func(*HybridPSKPoolRequest)
	observedOffset   time.Duration
	generationOffset uint64
	keyIDOverride    string
	pending          bool
	zeroPSK          bool
	afterPin         func()
	lastPSK          []byte
	closed           atomic.Int64
}

func (source *testPinnedHybridPSKSource) PinCurrentHybridPSK(
	_ context.Context,
	request HybridPSKPoolRequest,
) (PinnedHybridPSKSnapshot, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	psk := bytes.Repeat([]byte{0x5a}, 32)
	if source.zeroPSK {
		clear(psk)
	}
	source.lastPSK = psk
	generation := source.generation + source.generationOffset
	keyID := protocol.KeyID(
		request.ControllerID,
		source.suite,
		source.deviceID,
		source.peerPublicKey,
		source.generation,
		psk,
	)
	if source.keyIDOverride != "" {
		keyID = source.keyIDOverride
	}
	state := rotation.ClientState{
		Version:       1,
		ControllerID:  request.ControllerID,
		Suite:         source.suite,
		DeviceID:      source.deviceID,
		PeerPublicKey: source.peerPublicKey,
		Generation:    generation,
		KeyID:         keyID,
		ExpiresAt: source.expiresAt.Format(
			time.RFC3339Nano,
		),
	}
	if source.pending {
		state.Pending = &protocol.RekeyRequest{}
	}
	binding := request
	if source.requestMutator != nil {
		source.requestMutator(&binding)
	}
	if source.afterPin != nil {
		source.afterPin()
	}
	return PinnedHybridPSKSnapshot{
		Request:    binding,
		ObservedAt: source.now.Add(source.observedOffset),
		State:      state,
		PSK:        psk,
		Resource: &productionTestResource{
			count: &source.closed,
		},
	}, nil
}

type productionCredentialPoolHarness struct {
	now     time.Time
	issuer  *rsa.PublicKey
	request AnonymousCredentialPoolRequest
	vault   *testAtomicCredentialVault
	pool    *ProductionAnonymousCredentialPool
	clock   *productionPoolTestClock
}

func newProductionCredentialPoolHarness(
	t testing.TB,
	candidateCount int,
) *productionCredentialPoolHarness {
	t.Helper()
	now := productionNow()
	clock := &productionPoolTestClock{current: now}
	issuer := productionCredentialIssuer(t)
	keyID, err := privacytoken.IssuerKeyID(&issuer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&issuer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	requirements := make(
		[]AnonymousCredentialRequirement, candidateCount,
	)
	for index := range candidateCount {
		requirements[index] = AnonymousCredentialRequirement{
			CandidateID:     "h3-pool-" + fmt.Sprint(index),
			NodeID:          "gateway-production",
			TokenKeyID:      keyID,
			CredentialScope: "carrier-anonymous",
			IssuerDomain:    "issuer-independent",
			IssuerPublicKey: base64.StdEncoding.EncodeToString(
				publicDER,
			),
			NotBefore: now.Add(-time.Minute).Format(
				time.RFC3339Nano,
			),
			NotAfter: now.Add(2 * time.Hour).Format(
				time.RFC3339Nano,
			),
			Count: MinimumReservedCredentialsPerH3,
		}
	}
	clear(publicDER)
	request := AnonymousCredentialPoolRequest{
		Profile:                  "auto-production",
		ControllerID:             "controller-production",
		ManifestDigest:           strings.Repeat("b", 64),
		ManifestSequence:         7,
		ExpiresAt:                now.Add(time.Hour),
		MinimumUnusedCredentials: Phase1MinimumUnusedCredentials,
		Requirements:             requirements,
	}
	vault := &testAtomicCredentialVault{
		now:     now,
		issuer:  issuer,
		durable: true,
		unused:  12,
	}
	pool, err := NewProductionAnonymousCredentialPool(
		ProductionAnonymousCredentialPoolConfig{
			Vault: vault,
			Now:   clock.Now,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return &productionCredentialPoolHarness{
		now:     now,
		issuer:  &issuer.PublicKey,
		request: request,
		vault:   vault,
		pool:    pool,
		clock:   clock,
	}
}

var (
	productionCredentialIssuerOnce sync.Once
	productionCredentialIssuerKey  *rsa.PrivateKey
	productionCredentialIssuerErr  error
)

func productionCredentialIssuer(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	productionCredentialIssuerOnce.Do(func() {
		productionCredentialIssuerKey,
			productionCredentialIssuerErr =
			privacytoken.GenerateIssuerKey(3072)
	})
	if productionCredentialIssuerErr != nil {
		t.Fatal(productionCredentialIssuerErr)
	}
	return productionCredentialIssuerKey
}

type testAtomicCredentialVault struct {
	now     time.Time
	issuer  *rsa.PrivateKey
	durable bool
	unused  int

	observedOffset            time.Duration
	alterRequirement          bool
	omitCandidate             bool
	alterPseudonym            bool
	duplicateAcrossCandidates bool
	afterReserve              func()

	rootClosed       atomic.Int64
	candidateClosed  atomic.Int64
	lastIssuedSigner *pqauth.Signer
}

func (vault *testAtomicCredentialVault) ReserveAnonymousCredentials(
	_ context.Context,
	request AnonymousCredentialPoolRequest,
) (PinnedAnonymousCredentialReservation, error) {
	requirements := cloneCredentialRequirements(request.Requirements)
	responseRequest := request
	responseRequest.Requirements =
		cloneCredentialRequirements(request.Requirements)
	if vault.alterRequirement && len(responseRequest.Requirements) != 0 {
		responseRequest.Requirements[0].Count++
	}
	candidates := make(
		[]PinnedAnonymousCandidateReservation, 0, len(requirements),
	)
	if !vault.omitCandidate {
		for _, requirement := range requirements {
			credentials := make(
				[]carrier.AnonymousCredential, requirement.Count,
			)
			for index := range credentials {
				credentials[index] = issuePoolCredential(
					vault.issuer,
				)
				if vault.lastIssuedSigner == nil {
					vault.lastIssuedSigner =
						credentials[index].Signer
				}
			}
			if vault.alterPseudonym && len(credentials) != 0 {
				credentials[0].Pseudonym = "anon-altered"
			}
			queue := &testCredentialQueue{
				credentials: credentials,
			}
			candidates = append(
				candidates,
				PinnedAnonymousCandidateReservation{
					Requirement: requirement,
					Source:      queue,
					Resource: &testCredentialQueueResource{
						queue: queue,
						count: &vault.candidateClosed,
					},
				},
			)
		}
	}
	if vault.duplicateAcrossCandidates && len(candidates) > 1 {
		first := candidates[0].Source.(*testCredentialQueue)
		second := candidates[1].Source.(*testCredentialQueue)
		second.credentials[0] = first.credentials[0]
	}
	var inventories []AnonymousCredentialClassInventory
	if len(requirements) != 0 {
		inventories = []AnonymousCredentialClassInventory{{
			TokenKeyID:        requirements[0].TokenKeyID,
			CredentialScope:   requirements[0].CredentialScope,
			IssuerDomain:      requirements[0].IssuerDomain,
			UnusedCredentials: vault.unused,
		}}
	}
	reservation := PinnedAnonymousCredentialReservation{
		Request:           responseRequest,
		ObservedAt:        vault.now.Add(vault.observedOffset),
		ExpiresAt:         request.ExpiresAt,
		UnusedCredentials: vault.unused,
		ClassInventories:  inventories,
		Candidates:        candidates,
		Durable:           vault.durable,
		Resource: &productionTestResource{
			count: &vault.rootClosed,
		},
	}
	if vault.afterReserve != nil {
		vault.afterReserve()
	}
	return reservation, nil
}

func issuePoolCredential(
	issuer *rsa.PrivateKey,
) carrier.AnonymousCredential {
	request, state, err := privacytoken.BeginIssue(
		&issuer.PublicKey, pqauth.MLDSA65,
	)
	if err != nil {
		panic(err)
	}
	response, err := privacytoken.BlindSign(request, issuer)
	if err != nil {
		panic(err)
	}
	bundle, err := state.Finalize(response)
	if err != nil {
		panic(err)
	}
	signer, err := bundle.Signer()
	if err != nil {
		panic(err)
	}
	keyID, err := privacytoken.IssuerKeyID(&issuer.PublicKey)
	if err != nil {
		panic(err)
	}
	verified, err := privacytoken.Verify(
		bundle.PublicToken(), &issuer.PublicKey, keyID,
	)
	if err != nil {
		panic(err)
	}
	return carrier.AnonymousCredential{
		Pseudonym: verified.Pseudonym,
		Signer:    signer,
		Token:     bundle.PublicToken(),
	}
}

type testCredentialQueue struct {
	mu          sync.Mutex
	credentials []carrier.AnonymousCredential
	next        int
}

type testCredentialQueueResource struct {
	once  sync.Once
	queue *testCredentialQueue
	count *atomic.Int64
}

func (resource *testCredentialQueueResource) Close(
	_ context.Context,
) error {
	resource.once.Do(func() {
		resource.queue.mu.Lock()
		for index := range resource.queue.credentials {
			resource.queue.credentials[index].Destroy()
		}
		resource.queue.mu.Unlock()
		resource.count.Add(1)
	})
	return nil
}

func (queue *testCredentialQueue) NextAnonymousCredential() (
	carrier.AnonymousCredential,
	error,
) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.next >= len(queue.credentials) {
		return carrier.AnonymousCredential{},
			errors.New("test credential queue exhausted")
	}
	result := queue.credentials[queue.next]
	queue.next++
	return result, nil
}

func credentialSubleaseRequest(
	requirement AnonymousCredentialRequirement,
	expiresAt time.Time,
) AnonymousCredentialRequest {
	return AnonymousCredentialRequest{
		CandidateID:       requirement.CandidateID,
		NodeID:            requirement.NodeID,
		TokenKeyID:        requirement.TokenKeyID,
		CredentialScope:   requirement.CredentialScope,
		IssuerDomain:      requirement.IssuerDomain,
		ExpiresAt:         expiresAt,
		MinimumCredential: requirement.Count,
	}
}

type productionPoolTestClock struct {
	mu      sync.Mutex
	current time.Time
}

func (clock *productionPoolTestClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.current
}

func (clock *productionPoolTestClock) Set(current time.Time) {
	clock.mu.Lock()
	clock.current = current
	clock.mu.Unlock()
}

var (
	_ HybridPSKSnapshotSource           = (*testPinnedHybridPSKSource)(nil)
	_ AtomicAnonymousCredentialVault    = (*testAtomicCredentialVault)(nil)
	_ carrier.AnonymousCredentialSource = (*testCredentialQueue)(nil)
)
