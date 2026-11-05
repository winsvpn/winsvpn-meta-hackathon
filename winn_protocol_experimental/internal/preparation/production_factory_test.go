package preparation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/gatewaymanifest"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
)

func TestBindVerifiedDeploymentV2SnapshotsExactManifestFacts(t *testing.T) {
	now := productionNow()
	manifest, node, digest, _, _ := productionManifest(t, now)
	deployment, err := BindVerifiedDeploymentV2(manifest, node, digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BindVerifiedDeploymentV2(
		manifest, node, strings.Repeat("0", 64),
	); err == nil {
		t.Fatal("wrong verified manifest digest was accepted")
	}
	altered := node
	altered.Transports = slices.Clone(node.Transports)
	altered.Transports[0].Endpoint = "192.0.2.200:51820"
	if _, err := BindVerifiedDeploymentV2(
		manifest, altered, digest,
	); err == nil {
		t.Fatal("node differing from signed manifest was accepted")
	}

	manifest.Nodes[0].Transports[0].Endpoint = "192.0.2.201:51820"
	node.Transports[0].Endpoint = "192.0.2.202:51820"
	stored := deployment.transports["direct-primary"].transport
	if stored.Endpoint != "192.0.2.10:51820" {
		t.Fatalf("deployment snapshot was mutated: %#v", stored)
	}
}

func TestProductionFactoryMapsVerifiedDirectAWGFacts(t *testing.T) {
	harness := newProductionHarness(t)
	prepared, err := harness.factory.PrepareCandidate(
		context.Background(),
		harness.directContext(),
	)
	if err != nil {
		t.Fatal(err)
	}
	inputs := harness.direct.snapshot()
	if len(inputs) != 1 {
		t.Fatalf("direct builder inputs = %d; want 1", len(inputs))
	}
	input := inputs[0]
	transport := harness.transport("direct-primary")
	underlayRequests := harness.underlay.snapshot()
	if input.Context != harness.directContext() ||
		input.ManifestSequence != 7 ||
		input.ControllerID != "controller-production" ||
		input.Suite != transport.Suite ||
		input.Endpoint != transport.Endpoint ||
		input.GatewayPublicKey != transport.PublicAWGKey ||
		input.MinInnerDatagram != transport.MinInnerDatagram ||
		input.MaxInnerDatagram != transport.MaxInnerDatagram ||
		!slices.Equal(input.Capabilities, transport.Capabilities) ||
		input.UnderlayMark.AuthorizationID != "underlay-direct-primary" ||
		input.UnderlayMark.InterfaceName != "eth0" ||
		input.UnderlayMark.FirewallMark != 0x9101 ||
		!input.UnderlayMark.ExpiresAt.Equal(
			harness.directContext().Descriptor.ExpiresAt,
		) {
		t.Fatalf("direct input mapping changed: %#v", input)
	}
	if len(underlayRequests) != 1 ||
		underlayRequests[0].SignedEndpoint != transport.Endpoint ||
		underlayRequests[0].ManifestDigest != harness.digest ||
		underlayRequests[0].ManifestSequence != 7 {
		t.Fatalf("direct underlay authorization changed: %#v", underlayRequests)
	}
	if calls := harness.credentials.callCount(); calls != 0 {
		t.Fatalf("direct preparation acquired %d anonymous credentials", calls)
	}
	if calls := len(harness.policyAnchor.snapshot()); calls != 0 {
		t.Fatalf("direct preparation acquired %d policy anchors", calls)
	}
	if err := prepared.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := prepared.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := harness.closeLog.snapshot(); !slices.Equal(
		got,
		[]string{
			"direct-builder",
			"underlay-direct-primary",
			"psk-generation-19",
		},
	) {
		t.Fatalf("direct cleanup order = %v", got)
	}
}

func TestProductionFactoryMapsVerifiedH3AndCredentialFacts(t *testing.T) {
	harness := newProductionHarness(t)
	prepared, err := harness.factory.PrepareCandidate(
		context.Background(),
		harness.h3Context(),
	)
	if err != nil {
		t.Fatal(err)
	}
	inputs := harness.h3.snapshot()
	if len(inputs) != 1 {
		t.Fatalf("H3 builder inputs = %d; want 1", len(inputs))
	}
	input := inputs[0]
	transport := harness.transport("h3-primary")
	requests := harness.credentials.snapshot()
	anchorRequests := harness.policyAnchor.snapshot()
	underlayRequests := harness.underlay.snapshot()
	if len(requests) != 1 {
		t.Fatalf("credential requests = %d; want 1", len(requests))
	}
	request := requests[0]
	if input.Context != harness.h3Context() ||
		input.ManifestSequence != 7 ||
		input.ControllerID != "controller-production" ||
		input.Suite != transport.Suite ||
		input.EndpointTemplate != transport.Endpoint ||
		input.ServerName != transport.ServerName ||
		!slices.Equal(input.IPv4Hints, transport.IPv4Hints) ||
		!slices.Equal(input.IPv6Hints, transport.IPv6Hints) ||
		!bytes.Equal(input.ECHConfigList, harness.ech) ||
		!slices.Equal(input.ALPN, []string{"h3"}) ||
		input.PublicTarget != "winn.invalid:443" ||
		input.FixedBackend != transport.FixedBackend ||
		input.GatewayPublicKey != transport.PublicAWGKey ||
		input.MinInnerDatagram != transport.MinInnerDatagram ||
		input.MaxInnerDatagram != transport.MaxInnerDatagram ||
		input.AuthorizationMode != gatewaymanifest.AuthAnonymousToken ||
		input.TokenKeyID != transport.TokenKeyID ||
		input.CredentialScope != harness.tokenKey.Scope ||
		input.IssuerDomain != harness.tokenKey.IssuerDomain ||
		input.ReservedCredentials != MinimumReservedCredentialsPerH3 ||
		input.AnonymousCredentials == nil ||
		input.UnderlayMark.AuthorizationID != "underlay-h3-primary" ||
		input.UnderlayMark.InterfaceName != "eth0" ||
		input.UnderlayMark.FirewallMark != 0x9101 ||
		!input.UnderlayMark.ExpiresAt.Equal(
			harness.h3Context().Descriptor.ExpiresAt,
		) {
		t.Fatalf("H3 input mapping changed: %#v", input)
	}
	if len(underlayRequests) != 1 ||
		underlayRequests[0].SignedEndpoint != transport.Endpoint ||
		underlayRequests[0].ManifestDigest != harness.digest ||
		underlayRequests[0].ManifestSequence != 7 {
		t.Fatalf("H3 underlay authorization changed: %#v", underlayRequests)
	}
	if len(anchorRequests) != 1 ||
		anchorRequests[0].CandidateID != "h3-primary" ||
		anchorRequests[0].NodeID != "gateway-production" ||
		anchorRequests[0].Carrier != connectivity.CarrierHTTP3 ||
		anchorRequests[0].ManifestDigest != harness.digest ||
		anchorRequests[0].ManifestSequence != 7 ||
		anchorRequests[0].SignedEndpoint != transport.Endpoint ||
		!anchorRequests[0].ExpiresAt.Equal(
			harness.h3Context().Descriptor.ExpiresAt,
		) {
		t.Fatalf("H3 policy anchor request changed: %#v", anchorRequests)
	}
	if request.CandidateID != "h3-primary" ||
		request.NodeID != "gateway-production" ||
		request.TokenKeyID != harness.tokenKey.ID ||
		request.CredentialScope != harness.tokenKey.Scope ||
		request.IssuerDomain != harness.tokenKey.IssuerDomain ||
		request.MinimumCredential != MinimumReservedCredentialsPerH3 ||
		!request.ExpiresAt.Equal(harness.h3Context().Descriptor.ExpiresAt) {
		t.Fatalf("credential reservation mapping changed: %#v", request)
	}
	if !prepared.Warm {
		t.Fatal("H3 builder warm evidence was lost")
	}
	if err := prepared.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := harness.closeLog.snapshot(); !slices.Equal(
		got,
		[]string{
			"h3-builder",
			"underlay-h3-primary",
			"policy-anchor-h3-primary",
			"credential-h3-primary",
			"psk-generation-19",
		},
	) {
		t.Fatalf("H3 cleanup order = %v", got)
	}
}

func TestProductionFactoryDirectWaitsForConcurrentH3PolicyAnchor(
	t *testing.T,
) {
	harness := newProductionHarness(t)
	factory, err := NewProductionFactory(ProductionFactoryConfig{
		Deployments:           []VerifiedDeploymentV2{harness.deployment},
		PSKs:                  harness.psks,
		Credentials:           harness.credentials,
		PolicyAnchor:          harness.policyAnchor,
		Underlay:              harness.underlay,
		DirectAWG:             harness.direct,
		H3:                    harness.h3,
		WaitForH3PolicyAnchor: true,
		Now:                   func() time.Time { return harness.now },
	})
	if err != nil {
		t.Fatal(err)
	}

	directResult := make(chan PreparedCandidate, 1)
	directErrors := make(chan error, 1)
	go func() {
		prepared, prepareErr := factory.PrepareCandidate(
			context.Background(), harness.directContext(),
		)
		directResult <- prepared
		directErrors <- prepareErr
	}()
	deadline := time.Now().Add(time.Second)
	for harness.psks.acquired.Load() == 0 &&
		time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if harness.psks.acquired.Load() == 0 {
		t.Fatal("direct preparation did not reach the policy barrier")
	}
	if harness.underlay.acquired.Load() != 0 ||
		len(harness.direct.snapshot()) != 0 {
		t.Fatal(
			"direct authorization crossed the barrier before the H3 anchor",
		)
	}

	h3Prepared, err := factory.PrepareCandidate(
		context.Background(), harness.h3Context(),
	)
	if err != nil {
		t.Fatal(err)
	}
	var directPrepared PreparedCandidate
	select {
	case directPrepared = <-directResult:
		if err := <-directErrors; err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("direct preparation did not resume after the H3 anchor")
	}
	if len(harness.policyAnchor.snapshot()) != 1 ||
		harness.underlay.acquired.Load() != 2 ||
		len(harness.direct.snapshot()) != 1 {
		t.Fatal("concurrent policy-anchor barrier ownership is incomplete")
	}
	if err := directPrepared.Resource.Close(
		context.Background(),
	); err != nil {
		t.Fatal(err)
	}
	if err := h3Prepared.Resource.Close(
		context.Background(),
	); err != nil {
		t.Fatal(err)
	}
}

func TestProductionFactoryFailClosedContextAndLeaseValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*productionHarness, *CandidateContext)
	}{
		{
			name: "unknown transport",
			mutate: func(_ *productionHarness, current *CandidateContext) {
				current.Descriptor.ID = "unknown"
			},
		},
		{
			name: "wrong node",
			mutate: func(_ *productionHarness, current *CandidateContext) {
				current.Descriptor.NodeID = "attacker-node"
			},
		},
		{
			name: "wrong carrier",
			mutate: func(_ *productionHarness, current *CandidateContext) {
				current.Descriptor.Carrier = connectivity.CarrierHTTP2
			},
		},
		{
			name: "wrong digest",
			mutate: func(_ *productionHarness, current *CandidateContext) {
				current.ManifestDigest = strings.Repeat("f", 64)
			},
		},
		{
			name: "wrong manifest expiry",
			mutate: func(_ *productionHarness, current *CandidateContext) {
				current.ManifestExpiresAt =
					current.ManifestExpiresAt.Add(-time.Second)
			},
		},
		{
			name: "PSK generation mismatch",
			mutate: func(h *productionHarness, _ *CandidateContext) {
				h.psks.generationOffset = 1
			},
		},
		{
			name: "PSK expiry mismatch",
			mutate: func(h *productionHarness, _ *CandidateContext) {
				h.psks.expiryOffset = time.Second
			},
		},
		{
			name: "credential token mismatch",
			mutate: func(h *productionHarness, _ *CandidateContext) {
				h.credentials.tokenKeyOverride = strings.Repeat("e", 64)
			},
		},
		{
			name: "credential inventory below floor",
			mutate: func(h *productionHarness, _ *CandidateContext) {
				h.credentials.count = 1
			},
		},
		{
			name: "policy anchor candidate mismatch",
			mutate: func(h *productionHarness, _ *CandidateContext) {
				h.policyAnchor.candidateOverride = "attacker-candidate"
			},
		},
		{
			name: "policy anchor expiry mismatch",
			mutate: func(h *productionHarness, _ *CandidateContext) {
				h.policyAnchor.expiryOffset = time.Second
			},
		},
		{
			name: "policy anchor interface mismatch",
			mutate: func(h *productionHarness, _ *CandidateContext) {
				h.policyAnchor.interfaceOverride = "eth1"
			},
		},
		{
			name: "policy and H3 marks collide",
			mutate: func(h *productionHarness, _ *CandidateContext) {
				h.policyAnchor.directMark = 0x9101
			},
		},
		{
			name: "underlay candidate mismatch",
			mutate: func(h *productionHarness, _ *CandidateContext) {
				h.underlay.candidateOverride = "attacker-candidate"
			},
		},
		{
			name: "underlay expiry mismatch",
			mutate: func(h *productionHarness, _ *CandidateContext) {
				h.underlay.expiryOffset = time.Second
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newProductionHarness(t)
			current := harness.h3Context()
			test.mutate(harness, &current)
			if _, err := harness.factory.PrepareCandidate(
				context.Background(), current,
			); err == nil {
				t.Fatal("invalid production preparation unexpectedly passed")
			}
			// Every lease returned before a later validation failure is owned
			// and must be released.
			if harness.psks.acquired.Load() != harness.psks.closed.Load() {
				t.Fatalf(
					"PSK leases acquired=%d closed=%d",
					harness.psks.acquired.Load(),
					harness.psks.closed.Load(),
				)
			}
			if harness.credentials.acquired.Load() !=
				harness.credentials.closed.Load() {
				t.Fatalf(
					"credential leases acquired=%d closed=%d",
					harness.credentials.acquired.Load(),
					harness.credentials.closed.Load(),
				)
			}
			if harness.policyAnchor.acquired.Load() !=
				harness.policyAnchor.closed.Load() {
				t.Fatalf(
					"policy anchor leases acquired=%d closed=%d",
					harness.policyAnchor.acquired.Load(),
					harness.policyAnchor.closed.Load(),
				)
			}
			if harness.underlay.acquired.Load() !=
				harness.underlay.closed.Load() {
				t.Fatalf(
					"underlay leases acquired=%d closed=%d",
					harness.underlay.acquired.Load(),
					harness.underlay.closed.Load(),
				)
			}
		})
	}
}

func TestProductionFactoryRejectsAlteredSignedH3PolicyBeforeBuilder(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*verifiedTransportV2)
	}{
		{
			name: "anonymous mode removed",
			mutate: func(current *verifiedTransportV2) {
				current.transport.AuthenticationModes =
					[]string{gatewaymanifest.AuthIdentity}
			},
		},
		{
			name: "token key removed",
			mutate: func(current *verifiedTransportV2) {
				current.transport.TokenKeyID = ""
				current.tokenKey = nil
			},
		},
		{
			name: "classical or alternate suite",
			mutate: func(current *verifiedTransportV2) {
				current.transport.Suite = "p256-mlkem768"
			},
		},
		{
			name: "ECH removed",
			mutate: func(current *verifiedTransportV2) {
				current.transport.ECHConfigList = ""
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newProductionHarness(t)
			facts := harness.deployment.transports["h3-primary"]
			test.mutate(&facts)
			harness.deployment.transports["h3-primary"] = facts
			factory, err := harness.newFactory()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := factory.PrepareCandidate(
				context.Background(), harness.h3Context(),
			); err == nil {
				t.Fatal("altered H3 policy reached the builder")
			}
			if calls := len(harness.h3.snapshot()); calls != 0 {
				t.Fatalf("H3 builder called %d times", calls)
			}
		})
	}
}

func TestProductionFactoryFailureCleansAllOwnershipInReverse(t *testing.T) {
	harness := newProductionHarness(t)
	buildFailure := errors.New("H3 builder failed")
	builderCloseFailure := errors.New("builder cleanup failed")
	underlayCloseFailure := errors.New("underlay cleanup failed")
	anchorCloseFailure := errors.New("policy anchor cleanup failed")
	credentialCloseFailure := errors.New("credential cleanup failed")
	pskCloseFailure := errors.New("PSK cleanup failed")
	harness.h3.err = buildFailure
	harness.h3.resourceErr = builderCloseFailure
	harness.underlay.resourceErr = underlayCloseFailure
	harness.policyAnchor.resourceErr = anchorCloseFailure
	harness.credentials.resourceErr = credentialCloseFailure
	harness.psks.resourceErr = pskCloseFailure

	_, err := harness.factory.PrepareCandidate(
		context.Background(), harness.h3Context(),
	)
	for _, expected := range []error{
		buildFailure,
		builderCloseFailure,
		underlayCloseFailure,
		anchorCloseFailure,
		credentialCloseFailure,
		pskCloseFailure,
	} {
		if !errors.Is(err, expected) {
			t.Fatalf("preparation error %v does not include %v", err, expected)
		}
	}
	if got := harness.closeLog.snapshot(); !slices.Equal(
		got,
		[]string{
			"h3-builder",
			"underlay-h3-primary",
			"policy-anchor-h3-primary",
			"credential-h3-primary",
			"psk-generation-19",
		},
	) {
		t.Fatalf("failure cleanup order = %v", got)
	}
}

func TestProductionFactoryManagerLeaseDefersResourceCleanup(t *testing.T) {
	harness := newProductionHarness(t)
	manager, err := NewPhase1AutoManager(Config{
		Factory: harness.factory,
		Now:     func() time.Time { return harness.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := harness.managerRequest()
	if err := manager.Prepare(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	lease, err := manager.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	closeResult := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(
			context.Background(), 2*time.Second,
		)
		defer cancel()
		closeResult <- manager.Close(ctx)
	}()
	select {
	case err := <-closeResult:
		t.Fatalf("manager closed while lease was active: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if got := harness.closeLog.snapshot(); len(got) != 0 {
		t.Fatalf("resources closed before lease release: %v", got)
	}
	lease.Release()
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("manager did not close after lease release")
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
		},
	) {
		t.Fatalf("manager retirement cleanup order = %v", got)
	}
}

func TestProductionFactoryConcurrentPreparationAndCleanup(t *testing.T) {
	harness := newProductionHarness(t)
	const workers = 64
	var group sync.WaitGroup
	group.Add(workers)
	failures := make(chan error, workers)
	for index := range workers {
		go func() {
			defer group.Done()
			current := harness.directContext()
			if index%2 != 0 {
				current = harness.h3Context()
			}
			prepared, err := harness.factory.PrepareCandidate(
				context.Background(), current,
			)
			if err != nil {
				failures <- err
				return
			}
			var closes sync.WaitGroup
			closes.Add(2)
			for range 2 {
				go func() {
					defer closes.Done()
					if err := prepared.Resource.Close(
						context.Background(),
					); err != nil {
						failures <- err
					}
				}()
			}
			closes.Wait()
		}()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	if harness.psks.acquired.Load() != workers ||
		harness.psks.closed.Load() != workers {
		t.Fatalf(
			"PSK lease ownership acquired=%d closed=%d",
			harness.psks.acquired.Load(),
			harness.psks.closed.Load(),
		)
	}
	if harness.credentials.acquired.Load() != workers/2 ||
		harness.credentials.closed.Load() != workers/2 {
		t.Fatalf(
			"credential ownership acquired=%d closed=%d",
			harness.credentials.acquired.Load(),
			harness.credentials.closed.Load(),
		)
	}
	if harness.policyAnchor.acquired.Load() != workers/2 ||
		harness.policyAnchor.closed.Load() != workers/2 {
		t.Fatalf(
			"policy anchor ownership acquired=%d closed=%d",
			harness.policyAnchor.acquired.Load(),
			harness.policyAnchor.closed.Load(),
		)
	}
	if harness.underlay.acquired.Load() != workers ||
		harness.underlay.closed.Load() != workers {
		t.Fatalf(
			"underlay ownership acquired=%d closed=%d",
			harness.underlay.acquired.Load(),
			harness.underlay.closed.Load(),
		)
	}
}

type productionHarness struct {
	now          time.Time
	manifest     gatewaymanifest.ManifestV2
	deployment   VerifiedDeploymentV2
	digest       string
	ech          []byte
	tokenKey     gatewaymanifest.PrivacyTokenKey
	pskExpiry    time.Time
	closeLog     *productionCloseLog
	psks         *fakeHybridPSKLeaser
	credentials  *fakeCredentialLeaser
	policyAnchor *fakePolicyAnchorLeaser
	underlay     *fakeUnderlayAuthorizationLeaser
	direct       *fakeDirectPreparationBuilder
	h3           *fakeH3PreparationBuilder
	factory      *ProductionFactory
}

func newProductionHarness(t testing.TB) *productionHarness {
	t.Helper()
	now := productionNow()
	manifest, node, digest, ech, tokenKey := productionManifest(t, now)
	deployment, err := BindVerifiedDeploymentV2(manifest, node, digest)
	if err != nil {
		t.Fatal(err)
	}
	closeLog := &productionCloseLog{}
	pskExpiry := now.Add(time.Hour)
	harness := &productionHarness{
		now:        now,
		manifest:   manifest,
		deployment: deployment,
		digest:     digest,
		ech:        ech,
		tokenKey:   tokenKey,
		pskExpiry:  pskExpiry,
		closeLog:   closeLog,
	}
	harness.psks = &fakeHybridPSKLeaser{
		expiresAt: pskExpiry,
		closeLog:  closeLog,
	}
	harness.credentials = &fakeCredentialLeaser{
		count:    MinimumReservedCredentialsPerH3,
		closeLog: closeLog,
	}
	harness.policyAnchor = &fakePolicyAnchorLeaser{
		closeLog: closeLog,
	}
	harness.underlay = &fakeUnderlayAuthorizationLeaser{
		closeLog: closeLog,
	}
	harness.direct = &fakeDirectPreparationBuilder{
		now:      now,
		closeLog: closeLog,
	}
	harness.h3 = &fakeH3PreparationBuilder{
		now:      now,
		closeLog: closeLog,
	}
	harness.factory, err = harness.newFactory()
	if err != nil {
		t.Fatal(err)
	}
	return harness
}

func (harness *productionHarness) newFactory() (*ProductionFactory, error) {
	return NewProductionFactory(ProductionFactoryConfig{
		Deployments:  []VerifiedDeploymentV2{harness.deployment},
		PSKs:         harness.psks,
		Credentials:  harness.credentials,
		PolicyAnchor: harness.policyAnchor,
		Underlay:     harness.underlay,
		DirectAWG:    harness.direct,
		H3:           harness.h3,
		Now:          func() time.Time { return harness.now },
	})
}

func (harness *productionHarness) context(
	id string,
	carrierType connectivity.Carrier,
) CandidateContext {
	return CandidateContext{
		Profile:           "auto-production",
		Mode:              connectivity.ModeAuto,
		ManifestDigest:    harness.digest,
		ManifestExpiresAt: harness.now.Add(2 * time.Hour),
		PSKGeneration:     19,
		PSKExpiresAt:      harness.pskExpiry,
		Descriptor: connectivity.CandidateDescriptor{
			ID:        id,
			Carrier:   carrierType,
			NodeID:    "gateway-production",
			ExpiresAt: harness.now.Add(30 * time.Minute),
		},
	}
}

func (harness *productionHarness) directContext() CandidateContext {
	return harness.context(
		"direct-primary", connectivity.CarrierDirectAWG,
	)
}

func (harness *productionHarness) h3Context() CandidateContext {
	return harness.context("h3-primary", connectivity.CarrierHTTP3)
}

func (harness *productionHarness) transport(
	id string,
) gatewaymanifest.TransportV2 {
	return harness.deployment.transports[id].transport
}

func (harness *productionHarness) managerRequest() Request {
	direct := harness.directContext()
	h3 := harness.h3Context()
	return Request{
		Profile:                  direct.Profile,
		Mode:                     direct.Mode,
		ManifestDigest:           direct.ManifestDigest,
		ManifestExpiresAt:        direct.ManifestExpiresAt,
		PSKGeneration:            direct.PSKGeneration,
		PSKExpiresAt:             direct.PSKExpiresAt,
		UnusedCredentials:        Phase1MinimumUnusedCredentials,
		MinimumUnusedCredentials: Phase1MinimumUnusedCredentials,
		ReadinessTTL:             connectivity.DefaultReadinessTTL,
		Candidates: []connectivity.CandidateDescriptor{
			direct.Descriptor,
			h3.Descriptor,
		},
		RequiredCarriers: []connectivity.Carrier{
			connectivity.CarrierDirectAWG,
			connectivity.CarrierHTTP3,
		},
		RequiredWarmCarriers: []connectivity.Carrier{
			connectivity.CarrierHTTP3,
		},
	}
}

func productionNow() time.Time {
	return time.Date(2026, 7, 24, 5, 0, 0, 0, time.UTC)
}

var (
	productionTokenOnce sync.Once
	productionTokenDER  []byte
	productionTokenID   string
	productionTokenErr  error
)

func productionManifest(
	t testing.TB,
	now time.Time,
) (
	gatewaymanifest.ManifestV2,
	gatewaymanifest.NodeV2,
	string,
	[]byte,
	gatewaymanifest.PrivacyTokenKey,
) {
	t.Helper()
	productionTokenOnce.Do(func() {
		privateKey, err := privacytoken.GenerateIssuerKey(3072)
		if err != nil {
			productionTokenErr = err
			return
		}
		productionTokenDER, productionTokenErr =
			x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if productionTokenErr != nil {
			return
		}
		productionTokenID, productionTokenErr =
			privacytoken.IssuerKeyID(&privateKey.PublicKey)
	})
	if productionTokenErr != nil {
		t.Fatal(productionTokenErr)
	}
	ech, _, err := echconfig.Generate("cover.example", 1)
	if err != nil {
		t.Fatal(err)
	}
	rawAWGKey := base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{0x6b}, 32),
	)
	tokenKey := gatewaymanifest.PrivacyTokenKey{
		ID:           productionTokenID,
		Scope:        "carrier:winn.invalid:443",
		IssuerDomain: "issuer-independent",
		Algorithm:    privacytoken.Algorithm,
		PublicKey:    base64.StdEncoding.EncodeToString(productionTokenDER),
		NotBefore:    now.Add(-time.Minute).Format(time.RFC3339Nano),
		NotAfter:     now.Add(90 * time.Minute).Format(time.RFC3339Nano),
	}
	direct := gatewaymanifest.TransportV2{
		ID:                  "direct-primary",
		Type:                connectivity.CarrierDirectAWG,
		Endpoint:            "192.0.2.10:51820",
		Suite:               "x25519-mlkem768",
		AuthenticationModes: []string{gatewaymanifest.AuthAWGPSK},
		PublicAWGKey:        rawAWGKey,
		MinInnerDatagram:    1200,
		MaxInnerDatagram:    1350,
		Capabilities: []string{
			"awg-handshake-readiness",
			"candidate-isolated-verification",
		},
	}
	h3 := gatewaymanifest.TransportV2{
		ID:         "h3-primary",
		Type:       connectivity.CarrierHTTP3,
		Endpoint:   "https://gateway.example/.well-known/masque/udp/{target_host}/{target_port}/",
		ServerName: "gateway.example",
		IPv4Hints:  []string{"192.0.2.10"},
		IPv6Hints:  []string{"2001:db8::10"},
		ECHConfigList: base64.StdEncoding.EncodeToString(
			ech,
		),
		ALPN:  []string{"h3"},
		Suite: "x25519-mlkem768",
		AuthenticationModes: []string{
			gatewaymanifest.AuthIdentity,
			gatewaymanifest.AuthAnonymousToken,
		},
		TokenKeyID:       tokenKey.ID,
		PublicTarget:     "winn.invalid:443",
		PublicAWGKey:     rawAWGKey,
		FixedBackend:     "127.0.0.1:51820",
		MinInnerDatagram: 1200,
		MaxInnerDatagram: 1350,
		Capabilities:     []string{"attempt-binding", "fixed-backend"},
	}
	node := gatewaymanifest.NodeV2{
		ID:         "gateway-production",
		OperatorID: "operator-independent",
		Provider:   "provider-independent",
		Roles:      []string{gatewaymanifest.RoleCarrier},
		Transports: []gatewaymanifest.TransportV2{direct, h3},
		Capabilities: []string{
			"active-probe-resistant",
			"candidate-isolated-verification",
		},
	}
	manifest := gatewaymanifest.ManifestV2{
		Format:           gatewaymanifest.FormatV2,
		Sequence:         7,
		IssuedAt:         now.Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt:        now.Add(2 * time.Hour).Format(time.RFC3339Nano),
		ControllerID:     "controller-production",
		Suite:            "x25519-mlkem768",
		MinimumClient:    gatewaymanifest.MinimumClientV3,
		Capabilities:     gatewaymanifest.RequiredV2Capabilities(),
		Nodes:            []gatewaymanifest.NodeV2{node},
		PrivacyTokenKeys: []gatewaymanifest.PrivacyTokenKey{tokenKey},
	}
	seed := bytes.Repeat([]byte{0x42}, 32)
	signer, err := pqauth.NewSigner(pqauth.MLDSA65, seed)
	clear(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := gatewaymanifest.SignV2(&manifest, signer); err != nil {
		t.Fatal(err)
	}
	node, err = manifest.Node(node.ID)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := gatewaymanifest.DigestV2(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return manifest, node, digest, slices.Clone(ech), tokenKey
}

type productionCloseLog struct {
	mu      sync.Mutex
	entries []string
}

func (log *productionCloseLog) add(name string) {
	log.mu.Lock()
	log.entries = append(log.entries, name)
	log.mu.Unlock()
}

func (log *productionCloseLog) snapshot() []string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return slices.Clone(log.entries)
}

type productionTestResource struct {
	name  string
	log   *productionCloseLog
	err   error
	count *atomic.Int64
	once  sync.Once
}

func (resource *productionTestResource) Close(context.Context) error {
	resource.once.Do(func() {
		if resource.log != nil {
			resource.log.add(resource.name)
		}
		if resource.count != nil {
			resource.count.Add(1)
		}
	})
	return resource.err
}

type productionTestCandidate struct {
	descriptor connectivity.CandidateDescriptor
}

func (candidate *productionTestCandidate) Descriptor() connectivity.CandidateDescriptor {
	return candidate.descriptor
}

func (*productionTestCandidate) Dial(
	context.Context,
	connectivity.Binding,
) (connectivity.CandidateConnection, error) {
	return nil, errors.New("test candidate is dormant")
}

type fakeHybridPSKLeaser struct {
	expiresAt        time.Time
	closeLog         *productionCloseLog
	generationOffset uint64
	expiryOffset     time.Duration
	resourceErr      error
	acquired         atomic.Int64
	closed           atomic.Int64
}

func (leaser *fakeHybridPSKLeaser) AcquireHybridPSK(
	_ context.Context,
	generation uint64,
) (HybridPSKLease, error) {
	leaser.acquired.Add(1)
	name := fmt.Sprintf("psk-generation-%d", generation)
	return HybridPSKLease{
		Generation: generation + leaser.generationOffset,
		ExpiresAt:  leaser.expiresAt.Add(leaser.expiryOffset),
		Resource: &productionTestResource{
			name:  name,
			log:   leaser.closeLog,
			err:   leaser.resourceErr,
			count: &leaser.closed,
		},
	}, nil
}

type fakeCredentialSource struct{}

func (*fakeCredentialSource) NextAnonymousCredential() (
	carrier.AnonymousCredential,
	error,
) {
	return carrier.AnonymousCredential{}, errors.New(
		"test credential must not be consumed by mapping",
	)
}

type fakeCredentialLeaser struct {
	mu               sync.Mutex
	requests         []AnonymousCredentialRequest
	count            int
	closeLog         *productionCloseLog
	tokenKeyOverride string
	resourceErr      error
	acquired         atomic.Int64
	closed           atomic.Int64
}

func (leaser *fakeCredentialLeaser) AcquireAnonymousCredentials(
	_ context.Context,
	request AnonymousCredentialRequest,
) (AnonymousCredentialLease, error) {
	leaser.mu.Lock()
	leaser.requests = append(leaser.requests, request)
	leaser.mu.Unlock()
	leaser.acquired.Add(1)
	tokenKeyID := request.TokenKeyID
	if leaser.tokenKeyOverride != "" {
		tokenKeyID = leaser.tokenKeyOverride
	}
	return AnonymousCredentialLease{
		CandidateID:     request.CandidateID,
		NodeID:          request.NodeID,
		TokenKeyID:      tokenKeyID,
		CredentialScope: request.CredentialScope,
		IssuerDomain:    request.IssuerDomain,
		ExpiresAt:       request.ExpiresAt,
		Count:           leaser.count,
		Source:          &fakeCredentialSource{},
		Resource: &productionTestResource{
			name:  "credential-" + request.CandidateID,
			log:   leaser.closeLog,
			err:   leaser.resourceErr,
			count: &leaser.closed,
		},
	}, nil
}

func (leaser *fakeCredentialLeaser) snapshot() []AnonymousCredentialRequest {
	leaser.mu.Lock()
	defer leaser.mu.Unlock()
	return slices.Clone(leaser.requests)
}

func (leaser *fakeCredentialLeaser) callCount() int {
	return len(leaser.snapshot())
}

type fakePolicyAnchorLeaser struct {
	mu                sync.Mutex
	requests          []UnderlayPolicyAnchorRequest
	closeLog          *productionCloseLog
	candidateOverride string
	expiryOffset      time.Duration
	interfaceOverride string
	directMark        uint32
	resourceErr       error
	err               error
	acquired          atomic.Int64
	closed            atomic.Int64
}

func (leaser *fakePolicyAnchorLeaser) AcquireUnderlayPolicyAnchor(
	_ context.Context,
	request UnderlayPolicyAnchorRequest,
) (UnderlayPolicyAnchorLease, error) {
	leaser.mu.Lock()
	leaser.requests = append(leaser.requests, request)
	leaser.mu.Unlock()
	leaser.acquired.Add(1)
	candidateID := request.CandidateID
	if leaser.candidateOverride != "" {
		candidateID = leaser.candidateOverride
	}
	interfaceName := "eth0"
	if leaser.interfaceOverride != "" {
		interfaceName = leaser.interfaceOverride
	}
	directMark := leaser.directMark
	if directMark == 0 {
		directMark = 0x9001
	}
	return UnderlayPolicyAnchorLease{
		CandidateID:           candidateID,
		NodeID:                request.NodeID,
		Carrier:               request.Carrier,
		ManifestDigest:        request.ManifestDigest,
		ManifestSequence:      request.ManifestSequence,
		SignedEndpoint:        request.SignedEndpoint,
		AnchorID:              "policy-anchor-" + request.CandidateID,
		TableFamily:           "inet",
		TableName:             "winn_lock",
		OutputChain:           "output",
		InterfaceName:         interfaceName,
		DirectAWGFirewallMark: directMark,
		ExpiresAt:             request.ExpiresAt.Add(leaser.expiryOffset),
		Resource: &productionTestResource{
			name:  "policy-anchor-" + request.CandidateID,
			log:   leaser.closeLog,
			err:   leaser.resourceErr,
			count: &leaser.closed,
		},
	}, leaser.err
}

func (leaser *fakePolicyAnchorLeaser) snapshot() []UnderlayPolicyAnchorRequest {
	leaser.mu.Lock()
	defer leaser.mu.Unlock()
	return slices.Clone(leaser.requests)
}

type fakeUnderlayAuthorizationLeaser struct {
	mu                sync.Mutex
	requests          []UnderlayMarkAuthorizationRequest
	closeLog          *productionCloseLog
	candidateOverride string
	expiryOffset      time.Duration
	resourceErr       error
	err               error
	acquired          atomic.Int64
	closed            atomic.Int64
}

func (leaser *fakeUnderlayAuthorizationLeaser) AuthorizeUnderlayMark(
	_ context.Context,
	request UnderlayMarkAuthorizationRequest,
) (UnderlayMarkAuthorizationLease, error) {
	leaser.mu.Lock()
	leaser.requests = append(leaser.requests, request)
	leaser.mu.Unlock()
	leaser.acquired.Add(1)
	candidateID := request.CandidateID
	if leaser.candidateOverride != "" {
		candidateID = leaser.candidateOverride
	}
	return UnderlayMarkAuthorizationLease{
		CandidateID:      candidateID,
		NodeID:           request.NodeID,
		Carrier:          request.Carrier,
		ManifestDigest:   request.ManifestDigest,
		ManifestSequence: request.ManifestSequence,
		SignedEndpoint:   request.SignedEndpoint,
		AuthorizationID:  "underlay-" + request.CandidateID,
		InterfaceName:    "eth0",
		FirewallMark:     0x9101,
		ExpiresAt:        request.ExpiresAt.Add(leaser.expiryOffset),
		Resource: &productionTestResource{
			name:  "underlay-" + request.CandidateID,
			log:   leaser.closeLog,
			err:   leaser.resourceErr,
			count: &leaser.closed,
		},
	}, leaser.err
}

func (leaser *fakeUnderlayAuthorizationLeaser) snapshot() []UnderlayMarkAuthorizationRequest {
	leaser.mu.Lock()
	defer leaser.mu.Unlock()
	return slices.Clone(leaser.requests)
}

type fakeDirectPreparationBuilder struct {
	mu          sync.Mutex
	inputs      []DirectAWGPreparationInput
	now         time.Time
	closeLog    *productionCloseLog
	err         error
	resourceErr error
}

func (builder *fakeDirectPreparationBuilder) PrepareDirectAWG(
	_ context.Context,
	input DirectAWGPreparationInput,
) (CandidateBuild, error) {
	builder.mu.Lock()
	builder.inputs = append(builder.inputs, input)
	builder.mu.Unlock()
	return CandidateBuild{
		Candidate: &productionTestCandidate{
			descriptor: input.Context.Descriptor,
		},
		ProbeFreshUntil: builder.now.Add(20 * time.Minute),
		Resource: &productionTestResource{
			name: "direct-builder",
			log:  builder.closeLog,
			err:  builder.resourceErr,
		},
	}, builder.err
}

func (builder *fakeDirectPreparationBuilder) snapshot() []DirectAWGPreparationInput {
	builder.mu.Lock()
	defer builder.mu.Unlock()
	return slices.Clone(builder.inputs)
}

type fakeH3PreparationBuilder struct {
	mu          sync.Mutex
	inputs      []H3PreparationInput
	now         time.Time
	closeLog    *productionCloseLog
	err         error
	resourceErr error
}

func (builder *fakeH3PreparationBuilder) PrepareH3(
	_ context.Context,
	input H3PreparationInput,
) (CandidateBuild, error) {
	input.IPv4Hints = slices.Clone(input.IPv4Hints)
	input.IPv6Hints = slices.Clone(input.IPv6Hints)
	input.ECHConfigList = slices.Clone(input.ECHConfigList)
	input.ALPN = slices.Clone(input.ALPN)
	input.Capabilities = slices.Clone(input.Capabilities)
	builder.mu.Lock()
	builder.inputs = append(builder.inputs, input)
	builder.mu.Unlock()
	return CandidateBuild{
		Candidate: &productionTestCandidate{
			descriptor: input.Context.Descriptor,
		},
		ProbeFreshUntil: builder.now.Add(20 * time.Minute),
		Warm:            true,
		WarmUntil:       builder.now.Add(8 * time.Minute),
		Resource: &productionTestResource{
			name: "h3-builder",
			log:  builder.closeLog,
			err:  builder.resourceErr,
		},
	}, builder.err
}

func (builder *fakeH3PreparationBuilder) snapshot() []H3PreparationInput {
	builder.mu.Lock()
	defer builder.mu.Unlock()
	return slices.Clone(builder.inputs)
}

var (
	_ HybridPSKLeaser                 = (*fakeHybridPSKLeaser)(nil)
	_ AnonymousCredentialLeaser       = (*fakeCredentialLeaser)(nil)
	_ UnderlayPolicyAnchorLeaser      = (*fakePolicyAnchorLeaser)(nil)
	_ UnderlayMarkAuthorizationLeaser = (*fakeUnderlayAuthorizationLeaser)(nil)
	_ DirectAWGPreparationBuilder     = (*fakeDirectPreparationBuilder)(nil)
	_ H3PreparationBuilder            = (*fakeH3PreparationBuilder)(nil)
	_ connectivity.Candidate          = (*productionTestCandidate)(nil)
)
