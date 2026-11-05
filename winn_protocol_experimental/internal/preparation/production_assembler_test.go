package preparation

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
)

func TestVerifiedPreparationAssemblerDerivesAndOwnsExactProductionFacts(
	t *testing.T,
) {
	harness := newProductionAssemblerHarness(t)
	assembly, err := harness.assembler.Assemble(
		context.Background(), harness.request(),
	)
	if err != nil {
		t.Fatal(err)
	}
	assembledRequest := assembly.Request()
	if assembledRequest.ManifestDigest != harness.digest ||
		!assembledRequest.ManifestExpiresAt.Equal(
			harness.now.Add(2*time.Hour),
		) ||
		assembledRequest.PSKGeneration != 19 ||
		!assembledRequest.PSKExpiresAt.Equal(harness.pskExpiry) ||
		assembledRequest.UnusedCredentials != 12 ||
		assembledRequest.MinimumUnusedCredentials !=
			Phase1MinimumUnusedCredentials ||
		len(assembledRequest.Candidates) != 2 {
		t.Fatalf("assembled request changed: %#v", assembledRequest)
	}
	for _, descriptor := range assembledRequest.Candidates {
		if !descriptor.ExpiresAt.Equal(harness.pskExpiry) {
			t.Fatalf(
				"candidate %q expiry = %v; want %v",
				descriptor.ID,
				descriptor.ExpiresAt,
				harness.pskExpiry,
			)
		}
	}
	pskRequests := harness.pskPool.snapshot()
	if len(pskRequests) != 1 {
		t.Fatalf("PSK pool requests = %d; want 1", len(pskRequests))
	}
	pskRequest := pskRequests[0]
	if pskRequest.Profile != "auto-production" ||
		pskRequest.ControllerID != "controller-production" ||
		pskRequest.ManifestDigest != harness.digest ||
		pskRequest.ManifestSequence != 7 ||
		!pskRequest.ManifestExpiresAt.Equal(harness.now.Add(2*time.Hour)) {
		t.Fatalf("PSK pool request changed: %#v", pskRequest)
	}
	inventoryRequests := harness.credentialPool.snapshot()
	if len(inventoryRequests) != 1 {
		t.Fatalf(
			"credential pool requests = %d; want 1",
			len(inventoryRequests),
		)
	}
	inventoryRequest := inventoryRequests[0]
	wantRequirement := AnonymousCredentialRequirement{
		CandidateID:     "h3-primary",
		NodeID:          "gateway-production",
		TokenKeyID:      harness.tokenKey.ID,
		CredentialScope: harness.tokenKey.Scope,
		IssuerDomain:    harness.tokenKey.IssuerDomain,
		IssuerPublicKey: harness.tokenKey.PublicKey,
		NotBefore:       harness.tokenKey.NotBefore,
		NotAfter:        harness.tokenKey.NotAfter,
		Count:           MinimumReservedCredentialsPerH3,
	}
	if inventoryRequest.Profile != "auto-production" ||
		inventoryRequest.ControllerID != "controller-production" ||
		inventoryRequest.ManifestDigest != harness.digest ||
		inventoryRequest.ManifestSequence != 7 ||
		!inventoryRequest.ExpiresAt.Equal(harness.pskExpiry) ||
		inventoryRequest.MinimumUnusedCredentials !=
			Phase1MinimumUnusedCredentials ||
		!reflect.DeepEqual(
			inventoryRequest.Requirements,
			[]AnonymousCredentialRequirement{wantRequirement},
		) {
		t.Fatalf(
			"credential inventory request changed: %#v",
			inventoryRequest,
		)
	}

	lease, err := assembly.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := lease.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if readiness := snapshot.Readiness(); readiness.UnusedCredentials != 12 {
		t.Fatalf(
			"readiness unused credentials = %d; want 12",
			readiness.UnusedCredentials,
		)
	}
	closeResult := make(chan error, 1)
	go func() {
		closeResult <- assembly.Close(context.Background())
	}()
	select {
	case err := <-closeResult:
		t.Fatalf("assembly closed while click-time lease was active: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	lease.Release()
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("assembly did not close after lease release")
	}
	if got := harness.closeLog.snapshot(); !slices.Equal(
		got,
		[]string{
			"h3-builder",
			"underlay-h3-primary",
			"policy-anchor-h3-primary",
			"credential-h3-primary",
			"psk-generation-19",
			"direct-builder",
			"underlay-direct-primary",
			"psk-generation-19",
			"credential-pool",
			"psk-pool",
		},
	) {
		t.Fatalf("assembled cleanup order = %v", got)
	}
}

func TestVerifiedPreparationAssemblerRequiresEightUnusedPerClass(
	t *testing.T,
) {
	t.Run("requested floor below eight", func(t *testing.T) {
		harness := newProductionAssemblerHarness(t)
		request := harness.request()
		request.MinimumUnusedCredentials =
			Phase1MinimumUnusedCredentials - 1
		if _, err := harness.assembler.Assemble(
			context.Background(), request,
		); err == nil {
			t.Fatal("readiness floor below eight was accepted")
		}
		if harness.pskPool.acquired.Load() != 0 ||
			harness.credentialPool.acquired.Load() != 0 {
			t.Fatal("invalid floor reached production pools")
		}
	})

	t.Run("one eligible class below eight", func(t *testing.T) {
		harness := newProductionAssemblerHarness(t)
		harness.credentialPool.classUnused = 7
		harness.credentialPool.unused = 7
		if _, err := harness.assembler.Assemble(
			context.Background(), harness.request(),
		); err == nil {
			t.Fatal("credential class below eight was accepted")
		}
		if harness.direct.snapshot() != nil ||
			harness.h3.snapshot() != nil {
			t.Fatal("insufficient inventory reached a platform builder")
		}
		harness.requirePoolBalance(t, 1)
	})
}

func TestCredentialInventoryFloorCoversEveryEligibleClass(t *testing.T) {
	requirements := []AnonymousCredentialRequirement{
		{
			CandidateID:     "h3-a",
			NodeID:          "gateway-a",
			TokenKeyID:      "token-a",
			CredentialScope: "scope-a",
			IssuerDomain:    "issuer-a",
			IssuerPublicKey: "public-a",
			NotBefore:       "before-a",
			NotAfter:        "after-a",
			Count:           MinimumReservedCredentialsPerH3,
		},
		{
			CandidateID:     "h3-b",
			NodeID:          "gateway-b",
			TokenKeyID:      "token-b",
			CredentialScope: "scope-b",
			IssuerDomain:    "issuer-b",
			IssuerPublicKey: "public-b",
			NotBefore:       "before-b",
			NotAfter:        "after-b",
			Count:           MinimumReservedCredentialsPerH3,
		},
	}
	inventories := []AnonymousCredentialClassInventory{
		{
			TokenKeyID:        "token-a",
			CredentialScope:   "scope-a",
			IssuerDomain:      "issuer-a",
			UnusedCredentials: 12,
		},
		{
			TokenKeyID:        "token-b",
			CredentialScope:   "scope-b",
			IssuerDomain:      "issuer-b",
			UnusedCredentials: 7,
		},
	}
	if validCredentialClassInventories(
		inventories,
		requirements,
		Phase1MinimumUnusedCredentials,
		7,
	) {
		t.Fatal("one class below eight satisfied readiness")
	}
	inventories[1].UnusedCredentials = 9
	if !validCredentialClassInventories(
		inventories,
		requirements,
		Phase1MinimumUnusedCredentials,
		9,
	) {
		t.Fatal("all eligible classes above eight failed readiness")
	}
}

func TestVerifiedPreparationAssemblerFailsClosedOnStaleOrAlteredPools(
	t *testing.T,
) {
	tests := []struct {
		name   string
		mutate func(*productionAssemblerHarness)
	}{
		{
			name: "stale PSK observation",
			mutate: func(h *productionAssemblerHarness) {
				h.pskPool.observedOffset =
					-maximumPoolObservationAge - time.Nanosecond
			},
		},
		{
			name: "PSK manifest digest altered",
			mutate: func(h *productionAssemblerHarness) {
				h.pskPool.digestOverride =
					"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			},
		},
		{
			name: "credential requirements altered",
			mutate: func(h *productionAssemblerHarness) {
				h.credentialPool.alterRequirement = true
			},
		},
		{
			name: "credential class omitted",
			mutate: func(h *productionAssemblerHarness) {
				h.credentialPool.omitClasses = true
			},
		},
		{
			name: "readiness count is not class floor",
			mutate: func(h *productionAssemblerHarness) {
				h.credentialPool.classUnused = 11
				h.credentialPool.unused = 12
			},
		},
		{
			name: "stale credential observation",
			mutate: func(h *productionAssemblerHarness) {
				h.credentialPool.observedOffset =
					-maximumPoolObservationAge - time.Nanosecond
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newProductionAssemblerHarness(t)
			test.mutate(harness)
			if _, err := harness.assembler.Assemble(
				context.Background(), harness.request(),
			); err == nil {
				t.Fatal("stale or altered pool facts were accepted")
			}
			if len(harness.direct.snapshot()) != 0 ||
				len(harness.h3.snapshot()) != 0 {
				t.Fatal("invalid pool facts reached a platform builder")
			}
			if harness.pskPool.acquired.Load() !=
				harness.pskPool.closed.Load() ||
				harness.credentialPool.acquired.Load() !=
					harness.credentialPool.closed.Load() {
				t.Fatalf(
					"pool ownership leaked PSK=%d/%d credential=%d/%d",
					harness.pskPool.acquired.Load(),
					harness.pskPool.closed.Load(),
					harness.credentialPool.acquired.Load(),
					harness.credentialPool.closed.Load(),
				)
			}
		})
	}
}

func TestVerifiedPreparationAssemblerRollsBackParallelFailure(t *testing.T) {
	harness := newProductionAssemblerHarness(t)
	harness.h3.err = errors.New("H3 preparation failed")
	if _, err := harness.assembler.Assemble(
		context.Background(), harness.request(),
	); err == nil {
		t.Fatal("parallel preparation failure was accepted")
	}
	harness.requirePoolBalance(t, 1)
	if harness.psks.acquired.Load() != harness.psks.closed.Load() ||
		harness.credentials.acquired.Load() !=
			harness.credentials.closed.Load() ||
		harness.policyAnchor.acquired.Load() !=
			harness.policyAnchor.closed.Load() ||
		harness.underlay.acquired.Load() != harness.underlay.closed.Load() {
		t.Fatalf(
			"candidate rollback leaked PSK=%d/%d credential=%d/%d anchor=%d/%d underlay=%d/%d",
			harness.psks.acquired.Load(),
			harness.psks.closed.Load(),
			harness.credentials.acquired.Load(),
			harness.credentials.closed.Load(),
			harness.policyAnchor.acquired.Load(),
			harness.policyAnchor.closed.Load(),
			harness.underlay.acquired.Load(),
			harness.underlay.closed.Load(),
		)
	}
}

func TestVerifiedPreparationAssemblerReportsPinnedPoolCleanupErrors(
	t *testing.T,
) {
	harness := newProductionAssemblerHarness(t)
	pskCloseFailure := errors.New("PSK pool cleanup failed")
	credentialCloseFailure := errors.New(
		"credential pool cleanup failed",
	)
	harness.pskPool.resourceErr = pskCloseFailure
	harness.credentialPool.resourceErr = credentialCloseFailure
	assembly, err := harness.assembler.Assemble(
		context.Background(), harness.request(),
	)
	if err != nil {
		t.Fatal(err)
	}
	err = assembly.Close(context.Background())
	if !errors.Is(err, pskCloseFailure) ||
		!errors.Is(err, credentialCloseFailure) {
		t.Fatalf("assembly cleanup error = %v", err)
	}
	harness.requirePoolBalance(t, 1)
}

func TestVerifiedPreparationAssemblerConcurrentOwnership(t *testing.T) {
	harness := newProductionAssemblerHarness(t)
	const workers = 32
	failures := make(chan error, workers)
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			assembly, err := harness.assembler.Assemble(
				context.Background(), harness.request(),
			)
			if err != nil {
				failures <- err
				return
			}
			if err := assembly.Close(context.Background()); err != nil {
				failures <- err
			}
		}()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	harness.requirePoolBalance(t, workers)
	if harness.psks.acquired.Load() != workers*2 ||
		harness.psks.closed.Load() != workers*2 ||
		harness.credentials.acquired.Load() != workers ||
		harness.credentials.closed.Load() != workers ||
		harness.policyAnchor.acquired.Load() != workers ||
		harness.policyAnchor.closed.Load() != workers ||
		harness.underlay.acquired.Load() != workers*2 ||
		harness.underlay.closed.Load() != workers*2 {
		t.Fatalf(
			"candidate ownership PSK=%d/%d credential=%d/%d anchor=%d/%d underlay=%d/%d",
			harness.psks.acquired.Load(),
			harness.psks.closed.Load(),
			harness.credentials.acquired.Load(),
			harness.credentials.closed.Load(),
			harness.policyAnchor.acquired.Load(),
			harness.policyAnchor.closed.Load(),
			harness.underlay.acquired.Load(),
			harness.underlay.closed.Load(),
		)
	}
}

type productionAssemblerHarness struct {
	*productionHarness
	pskPool        *fakeProductionPSKPool
	credentialPool *fakeProductionCredentialPool
	assembler      *VerifiedPreparationAssembler
}

func newProductionAssemblerHarness(
	t testing.TB,
) *productionAssemblerHarness {
	t.Helper()
	production := newProductionHarness(t)
	harness := &productionAssemblerHarness{
		productionHarness: production,
	}
	harness.pskPool = &fakeProductionPSKPool{
		now:       harness.now,
		expiresAt: harness.pskExpiry,
		psks:      harness.psks,
		closeLog:  harness.closeLog,
	}
	harness.credentialPool = &fakeProductionCredentialPool{
		now:         harness.now,
		unused:      12,
		classUnused: 12,
		credentials: harness.credentials,
		closeLog:    harness.closeLog,
	}
	var err error
	harness.assembler, err = NewVerifiedPreparationAssembler(
		VerifiedPreparationAssemblerConfig{
			Deployments:    []VerifiedDeploymentV2{harness.deployment},
			PSKPool:        harness.pskPool,
			CredentialPool: harness.credentialPool,
			PolicyAnchor:   harness.policyAnchor,
			Underlay:       harness.underlay,
			DirectAWG:      harness.direct,
			H3:             harness.h3,
			Policy:         Phase1AutoPolicy,
			Now:            func() time.Time { return harness.now },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return harness
}

func (harness *productionAssemblerHarness) request() VerifiedAssemblyRequest {
	return VerifiedAssemblyRequest{
		Profile: "auto-production",
		Mode:    connectivity.ModeAuto,
		CandidateIDs: []string{
			"direct-primary",
			"h3-primary",
		},
		MinimumUnusedCredentials: Phase1MinimumUnusedCredentials,
		ReadinessTTL:             connectivity.DefaultReadinessTTL,
		RequiredCarriers: []connectivity.Carrier{
			connectivity.CarrierDirectAWG,
			connectivity.CarrierHTTP3,
		},
		RequiredWarmCarriers: []connectivity.Carrier{
			connectivity.CarrierHTTP3,
		},
	}
}

func (harness *productionAssemblerHarness) requirePoolBalance(
	t testing.TB,
	expected int64,
) {
	t.Helper()
	if harness.pskPool.acquired.Load() != expected ||
		harness.pskPool.closed.Load() != expected ||
		harness.credentialPool.acquired.Load() != expected ||
		harness.credentialPool.closed.Load() != expected {
		t.Fatalf(
			"pool ownership PSK=%d/%d credential=%d/%d; want %d",
			harness.pskPool.acquired.Load(),
			harness.pskPool.closed.Load(),
			harness.credentialPool.acquired.Load(),
			harness.credentialPool.closed.Load(),
			expected,
		)
	}
}

type fakeProductionPSKPool struct {
	mu             sync.Mutex
	requests       []HybridPSKPoolRequest
	now            time.Time
	expiresAt      time.Time
	psks           HybridPSKLeaser
	closeLog       *productionCloseLog
	observedOffset time.Duration
	digestOverride string
	expiryOffset   time.Duration
	err            error
	resourceErr    error
	acquired       atomic.Int64
	closed         atomic.Int64
}

func (pool *fakeProductionPSKPool) AcquireCurrentHybridPSK(
	_ context.Context,
	request HybridPSKPoolRequest,
) (HybridPSKPoolLease, error) {
	pool.mu.Lock()
	pool.requests = append(pool.requests, request)
	pool.mu.Unlock()
	pool.acquired.Add(1)
	digest := request.ManifestDigest
	if pool.digestOverride != "" {
		digest = pool.digestOverride
	}
	return HybridPSKPoolLease{
		Profile:           request.Profile,
		ControllerID:      request.ControllerID,
		ManifestDigest:    digest,
		ManifestSequence:  request.ManifestSequence,
		ManifestExpiresAt: request.ManifestExpiresAt,
		ObservedAt:        pool.now.Add(pool.observedOffset),
		Generation:        19,
		ExpiresAt:         pool.expiresAt.Add(pool.expiryOffset),
		PSKs:              pool.psks,
		Resource: &productionTestResource{
			name:  "psk-pool",
			log:   pool.closeLog,
			err:   pool.resourceErr,
			count: &pool.closed,
		},
	}, pool.err
}

func (pool *fakeProductionPSKPool) snapshot() []HybridPSKPoolRequest {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return slices.Clone(pool.requests)
}

type fakeProductionCredentialPool struct {
	mu               sync.Mutex
	requests         []AnonymousCredentialPoolRequest
	now              time.Time
	unused           int
	classUnused      int
	credentials      AnonymousCredentialLeaser
	closeLog         *productionCloseLog
	observedOffset   time.Duration
	expiryOffset     time.Duration
	alterRequirement bool
	omitClasses      bool
	err              error
	resourceErr      error
	acquired         atomic.Int64
	closed           atomic.Int64
}

func (pool *fakeProductionCredentialPool) AcquireAnonymousCredentialInventory(
	_ context.Context,
	request AnonymousCredentialPoolRequest,
) (AnonymousCredentialPoolLease, error) {
	request.Requirements = slices.Clone(request.Requirements)
	pool.mu.Lock()
	pool.requests = append(pool.requests, request)
	pool.mu.Unlock()
	pool.acquired.Add(1)
	requirements := slices.Clone(request.Requirements)
	if pool.alterRequirement && len(requirements) != 0 {
		requirements[0].Count++
	}
	var inventories []AnonymousCredentialClassInventory
	if !pool.omitClasses {
		seen := make(map[string]struct{})
		for _, requirement := range request.Requirements {
			key := fmt.Sprintf(
				"%s\x00%s\x00%s",
				requirement.TokenKeyID,
				requirement.CredentialScope,
				requirement.IssuerDomain,
			)
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			inventories = append(
				inventories,
				AnonymousCredentialClassInventory{
					TokenKeyID:        requirement.TokenKeyID,
					CredentialScope:   requirement.CredentialScope,
					IssuerDomain:      requirement.IssuerDomain,
					UnusedCredentials: pool.classUnused,
				},
			)
		}
	}
	return AnonymousCredentialPoolLease{
		Profile:                  request.Profile,
		ControllerID:             request.ControllerID,
		ManifestDigest:           request.ManifestDigest,
		ManifestSequence:         request.ManifestSequence,
		ObservedAt:               pool.now.Add(pool.observedOffset),
		ExpiresAt:                request.ExpiresAt.Add(pool.expiryOffset),
		MinimumUnusedCredentials: request.MinimumUnusedCredentials,
		UnusedCredentials:        pool.unused,
		Requirements:             requirements,
		ClassInventories:         inventories,
		Credentials:              pool.credentials,
		Resource: &productionTestResource{
			name:  "credential-pool",
			log:   pool.closeLog,
			err:   pool.resourceErr,
			count: &pool.closed,
		},
	}, pool.err
}

func (pool *fakeProductionCredentialPool) snapshot() []AnonymousCredentialPoolRequest {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	result := make(
		[]AnonymousCredentialPoolRequest, len(pool.requests),
	)
	for index, request := range pool.requests {
		request.Requirements = slices.Clone(request.Requirements)
		result[index] = request
	}
	return result
}

var (
	_ HybridPSKPool           = (*fakeProductionPSKPool)(nil)
	_ AnonymousCredentialPool = (*fakeProductionCredentialPool)(nil)
)
