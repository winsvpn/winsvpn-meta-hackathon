package main

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	fixtureContractPin = "1111111111111111111111111111111111111111111111111111111111111111"
	fixtureSourcePin   = "2222222222222222222222222222222222222222222222222222222222222222"
	fixtureVerifierPin = "9999999999999999999999999999999999999999999999999999999999999999"
)

type fixtureSet struct {
	manifest Manifest
	attempt  AttemptEvidence
	topology TopologyEvidence
}

func canonicalFixture(t *testing.T) fixtureSet {
	t.Helper()
	pins := Pins{
		ContractSHA256:              fixtureContractPin,
		SourceSHA256:                fixtureSourcePin,
		HostArtifactSHA256:          repeatedDigest('3'),
		ProviderArtifactSHA256:      repeatedDigest('4'),
		AWGArtifactSHA256:           repeatedDigest('5'),
		AWGConfigSHA256:             repeatedDigest('c'),
		ExpectedAWGPeerSHA256:       repeatedDigest('e'),
		AWGEngineInstanceNonce:      "deadbeef-cafe-4bad-8dad-feedfacecafe",
		AWGEngineGeneration:         13,
		WinningPathGeneration:       15,
		WinningInterfaceTokenSHA256: repeatedDigest('d'),
		ReflectorArtifactSHA256:     repeatedDigest('6'),
		ReflectorConfigSHA256:       repeatedDigest('7'),
		DNSConfigSHA256:             repeatedDigest('8'),
		VerifierSHA256:              fixtureVerifierPin,
	}
	binding := Binding{
		RunID:                           "01234567-89ab-4def-8123-456789abcdef",
		AttemptNonce:                    "11111111-2222-4333-8444-555555555555",
		PathID:                          "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		WCF3SessionID:                   "12345678-1234-4234-8234-123456789abc",
		WCF3BindingID:                   "abcdefab-cdef-4abc-8def-abcdefabcdef",
		PSKGeneration:                   7,
		SequenceEpoch:                   9,
		CanarySequence:                  11,
		RequestedAtMonotonicNanoseconds: 1_000_000_000,
		AWGConfigSHA256:                 pins.AWGConfigSHA256,
		ExpectedAWGPeerSHA256:           pins.ExpectedAWGPeerSHA256,
		AWGEngineInstanceNonce:          pins.AWGEngineInstanceNonce,
		AWGEngineGeneration:             pins.AWGEngineGeneration,
		WinningPathGeneration:           pins.WinningPathGeneration,
		WinningInterfaceTokenSHA256:     pins.WinningInterfaceTokenSHA256,
	}
	binding.BindingSHA256 = bindingDigest(binding)
	topology := TopologyEvidence{
		Schema:                          topologySchema,
		ProtocolVersion:                 protocolVersion,
		MeasurementScope:                measurementScope,
		RunID:                           binding.RunID,
		AWGArtifactSHA256:               pins.AWGArtifactSHA256,
		AWGConfigSHA256:                 pins.AWGConfigSHA256,
		ExpectedAWGPeerSHA256:           pins.ExpectedAWGPeerSHA256,
		AWGEngineInstanceNonce:          pins.AWGEngineInstanceNonce,
		AWGEngineGeneration:             pins.AWGEngineGeneration,
		WinningPathGeneration:           pins.WinningPathGeneration,
		WinningInterfaceTokenSHA256:     pins.WinningInterfaceTokenSHA256,
		ReflectorArtifactSHA256:         pins.ReflectorArtifactSHA256,
		ReflectorConfigSHA256:           pins.ReflectorConfigSHA256,
		DNSConfigSHA256:                 pins.DNSConfigSHA256,
		DNSDirectPreTunnel:              "blocked",
		DNSDirectPostTeardown:           "blocked",
		ReflectorDirectPreTunnel:        "blocked",
		ReflectorDirectPostTeardown:     "blocked",
		ReflectorAcceptedIngress:        "awg-inner-only",
		OuterPlaintextDNSObserved:       false,
		OuterPlaintextReflectorObserved: false,
		FirewallSnapshotSHA256:          repeatedDigest('a'),
		RouteSnapshotSHA256:             repeatedDigest('b'),
		OuterCaptureSHA256:              repeatedDigest('c'),
		ObserverReceiptSHA256:           repeatedDigest('d'),
	}
	topologyBytes := mustCanonical(t, topology)
	topologySHA256 := digest(topologyBytes)
	sampleIdentity := AWGSampleIdentity{
		PeerPublicKeySHA256:         pins.ExpectedAWGPeerSHA256,
		ConfigSHA256:                pins.AWGConfigSHA256,
		EngineInstanceNonce:         pins.AWGEngineInstanceNonce,
		EngineGeneration:            pins.AWGEngineGeneration,
		PathGeneration:              pins.WinningPathGeneration,
		WinningInterfaceTokenSHA256: pins.WinningInterfaceTokenSHA256,
	}
	attempt := AttemptEvidence{
		Schema:                              attemptSchema,
		ProtocolVersion:                     protocolVersion,
		MeasurementScope:                    measurementScope,
		RunID:                               binding.RunID,
		AttemptNonce:                        binding.AttemptNonce,
		Mode:                                "maximum-privacy",
		Radio:                               "wifi",
		Readiness:                           "cold",
		T0Source:                            t0Source,
		ConnectButtonT0MonotonicNanoseconds: 1_000_000_000,
		Binding:                             binding,
		Predicates: Predicates{
			FreshAWGHandshake: Predicate{
				Observed:               true,
				AtMonotonicNanoseconds: 2_000_000_000,
				BindingSHA256:          binding.BindingSHA256,
			},
			AuthenticatedBidirectionalBytes: Predicate{
				Observed:               true,
				AtMonotonicNanoseconds: 2_500_000_000,
				BindingSHA256:          binding.BindingSHA256,
			},
			ProtectedDNS: Predicate{
				Observed:               true,
				AtMonotonicNanoseconds: 3_000_000_000,
				BindingSHA256:          binding.BindingSHA256,
			},
			AuthenticatedReflector: Predicate{
				Observed:               true,
				AtMonotonicNanoseconds: 3_500_000_000,
				BindingSHA256:          binding.BindingSHA256,
			},
		},
		AWG: AWGProof{
			BaselineSampleAtMonotonicNanoseconds:      1_100_000_000,
			HandshakePostSampleAtMonotonicNanoseconds: 2_000_000_000,
			CounterPostSampleAtMonotonicNanoseconds:   2_500_000_000,
			BaselineIdentity:                          sampleIdentity,
			HandshakePostIdentity:                     sampleIdentity,
			CounterPostIdentity:                       sampleIdentity,
			BaselineLatestHandshakeUnixMilliseconds:   1_900_000_000_000,
			PostLatestHandshakeUnixMilliseconds:       1_900_000_000_001,
			BaselineAuthenticatedTxBytes:              100,
			PostAuthenticatedTxBytes:                  356,
			BaselineAuthenticatedRxBytes:              200,
			PostAuthenticatedRxBytes:                  712,
			AuthenticatedOutboundDeltaBytes:           256,
			AuthenticatedInboundDeltaBytes:            512,
			PSKGeneration:                             binding.PSKGeneration,
			BindingSHA256:                             binding.BindingSHA256,
			Fresh:                                     true,
		},
		DNS: DNSProof{
			Attempted:                      true,
			Observed:                       true,
			RequestAtMonotonicNanoseconds:  2_600_000_000,
			ResponseAtMonotonicNanoseconds: 3_000_000_000,
			QueryNonceSHA256:               repeatedDigest('f'),
			ResponsePayloadSHA256:          repeatedDigest('a'),
			ConfigSHA256:                   pins.DNSConfigSHA256,
			TopologySHA256:                 topologySHA256,
			BindingSHA256:                  binding.BindingSHA256,
			CacheBypassed:                  true,
			TunnelOnly:                     true,
		},
		Reflector: ReflectorProof{
			Attempted:                              true,
			Observed:                               true,
			RequestSentAtMonotonicNanoseconds:      3_100_000_000,
			ResponseObservedAtMonotonicNanoseconds: 3_500_000_000,
			CanarySequence:                         binding.CanarySequence,
			ArtifactSHA256:                         pins.ReflectorArtifactSHA256,
			ConfigSHA256:                           pins.ReflectorConfigSHA256,
			TopologySHA256:                         topologySHA256,
			BindingSHA256:                          binding.BindingSHA256,
			Authenticated:                          true,
			TunnelOnly:                             true,
		},
		Terminal: Terminal{
			State:                          "succeeded",
			FailureCode:                    "none",
			TerminalAtMonotonicNanoseconds: 4_000_000_000,
			TDataMonotonicNanoseconds:      4_000_000_000,
			TUIMonotonicNanoseconds:        4_000_000_000,
			DeadlineFailureReportingBudgetNanoseconds: 0,
			CleanupState:                  "not-required",
			CleanupAtMonotonicNanoseconds: 0,
			CleanupBudgetNanoseconds:      maxCleanupNanoseconds,
		},
		CleanHost: CleanHost{
			Admitted:           true,
			DeviceThermalState: "nominal",
			LowPowerMode:       "off",
			OtherVPNActive:     false,
			HostStressActive:   false,
			ObservationSHA256:  repeatedDigest('b'),
		},
		Pins: pins,
	}
	attemptBytes := mustCanonical(t, attempt)
	manifest := Manifest{
		Schema:                      manifestSchema,
		ProtocolVersion:             protocolVersion,
		MeasurementScope:            measurementScope,
		ContractSHA256:              pins.ContractSHA256,
		SourceSHA256:                pins.SourceSHA256,
		HostArtifactSHA256:          pins.HostArtifactSHA256,
		ProviderArtifactSHA256:      pins.ProviderArtifactSHA256,
		AWGArtifactSHA256:           pins.AWGArtifactSHA256,
		AWGConfigSHA256:             pins.AWGConfigSHA256,
		ExpectedAWGPeerSHA256:       pins.ExpectedAWGPeerSHA256,
		AWGEngineInstanceNonce:      pins.AWGEngineInstanceNonce,
		AWGEngineGeneration:         pins.AWGEngineGeneration,
		WinningPathGeneration:       pins.WinningPathGeneration,
		WinningInterfaceTokenSHA256: pins.WinningInterfaceTokenSHA256,
		ReflectorArtifactSHA256:     pins.ReflectorArtifactSHA256,
		ReflectorConfigSHA256:       pins.ReflectorConfigSHA256,
		DNSConfigSHA256:             pins.DNSConfigSHA256,
		VerifierSHA256:              pins.VerifierSHA256,
		EvidencePath:                "evidence/attempt.json",
		EvidenceSHA256:              digest(attemptBytes),
		TopologyPath:                "proof/topology.json",
		TopologySHA256:              topologySHA256,
	}
	return fixtureSet{
		manifest: manifest,
		attempt:  attempt,
		topology: topology,
	}
}

func TestCanonicalFixtureAtExactBoundaryConforms(t *testing.T) {
	root := writeFixture(t, canonicalFixture(t))
	result, err := verifyFixture(
		root,
		fixtureContractPin,
		fixtureSourcePin,
		fixtureVerifierPin,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Attempt.Terminal.TDataMonotonicNanoseconds != 4_000_000_000 ||
		result.Attempt.Terminal.TUIMonotonicNanoseconds != 4_000_000_000 {
		t.Fatal("fixture does not exercise the exact three-second boundary")
	}
}

func TestCanonicalCheckedInFixtures(t *testing.T) {
	root := filepath.Join("testdata", "canonical")
	if _, err := verifyFixture(
		root,
		fixtureContractPin,
		fixtureSourcePin,
		fixtureVerifierPin,
	); err != nil {
		t.Fatal(err)
	}
	fixture := canonicalFixture(t)
	for relative, want := range map[string][]byte{
		"manifest.json":         mustCanonical(t, fixture.manifest),
		"evidence/attempt.json": mustCanonical(t, fixture.attempt),
		"proof/topology.json":   mustCanonical(t, fixture.topology),
	} {
		got, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s is not the canonical generated fixture", relative)
		}
	}
}

func TestRelocatedRootConforms(t *testing.T) {
	fixture := canonicalFixture(t)
	first := writeFixture(t, fixture)
	second := filepath.Join(t.TempDir(), "unrelated", "location")
	if err := os.MkdirAll(filepath.Join(second, "evidence"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(second, "proof"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{
		"manifest.json",
		"evidence/attempt.json",
		"proof/topology.json",
	} {
		content, err := os.ReadFile(filepath.Join(first, relative))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(second, relative),
			content,
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := verifyFixture(
		second,
		fixtureContractPin,
		fixtureSourcePin,
		fixtureVerifierPin,
	); err != nil {
		t.Fatal(err)
	}
}

func TestSemanticMutationsFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fixtureSet)
	}{
		{"TdataPlusOne", func(f *fixtureSet) {
			f.attempt.Terminal.TDataMonotonicNanoseconds++
		}},
		{"TUIPlusOne", func(f *fixtureSet) {
			f.attempt.Terminal.TUIMonotonicNanoseconds++
		}},
		{"T0ChangedBeforeBinding", func(f *fixtureSet) {
			f.attempt.Binding.RequestedAtMonotonicNanoseconds++
		}},
		{"BindingDigestChanged", func(f *fixtureSet) {
			f.attempt.Binding.BindingSHA256 = repeatedDigest('c')
		}},
		{"StaleHandshake", func(f *fixtureSet) {
			f.attempt.AWG.PostLatestHandshakeUnixMilliseconds =
				f.attempt.AWG.BaselineLatestHandshakeUnixMilliseconds
		}},
		{"HandshakeSamplePredicateMismatch", func(f *fixtureSet) {
			f.attempt.AWG.HandshakePostSampleAtMonotonicNanoseconds++
		}},
		{"CounterSamplePredicateMismatch", func(f *fixtureSet) {
			f.attempt.AWG.CounterPostSampleAtMonotonicNanoseconds++
		}},
		{"CounterRollback", func(f *fixtureSet) {
			f.attempt.AWG.PostAuthenticatedTxBytes = 99
		}},
		{"CounterDeltaMismatch", func(f *fixtureSet) {
			f.attempt.AWG.AuthenticatedInboundDeltaBytes++
		}},
		{"BaselinePeerPrecommitDrift", func(f *fixtureSet) {
			f.attempt.AWG.BaselineIdentity.PeerPublicKeySHA256 =
				repeatedDigest('a')
		}},
		{"HandshakeConfigPrecommitDrift", func(f *fixtureSet) {
			f.attempt.AWG.HandshakePostIdentity.ConfigSHA256 =
				repeatedDigest('a')
		}},
		{"CounterEngineNoncePrecommitDrift", func(f *fixtureSet) {
			f.attempt.AWG.CounterPostIdentity.EngineInstanceNonce =
				"facefeed-cafe-4bad-8dad-deadbeefcafe"
		}},
		{"BaselineEngineGenerationDrift", func(f *fixtureSet) {
			f.attempt.AWG.BaselineIdentity.EngineGeneration++
		}},
		{"CounterPathGenerationDrift", func(f *fixtureSet) {
			f.attempt.AWG.CounterPostIdentity.PathGeneration++
		}},
		{"HandshakeInterfaceTokenDrift", func(f *fixtureSet) {
			f.attempt.AWG.HandshakePostIdentity.WinningInterfaceTokenSHA256 =
				repeatedDigest('a')
		}},
		{"BindingAWGConfigDrift", func(f *fixtureSet) {
			f.attempt.Binding.AWGConfigSHA256 = repeatedDigest('a')
			f.attempt.Binding.BindingSHA256 = bindingDigest(f.attempt.Binding)
			rebindPredicates(&f.attempt)
		}},
		{"TopologyEngineGenerationDrift", func(f *fixtureSet) {
			f.topology.AWGEngineGeneration++
		}},
		{"DNSCacheNotBypassed", func(f *fixtureSet) {
			f.attempt.DNS.CacheBypassed = false
		}},
		{"DNSNotTunnelOnly", func(f *fixtureSet) {
			f.attempt.DNS.TunnelOnly = false
		}},
		{"DNSConfigDrift", func(f *fixtureSet) {
			f.attempt.DNS.ConfigSHA256 = repeatedDigest('c')
		}},
		{"DNSRequestBeforeTunnelBytes", func(f *fixtureSet) {
			f.attempt.DNS.RequestAtMonotonicNanoseconds =
				f.attempt.Predicates.AuthenticatedBidirectionalBytes.
					AtMonotonicNanoseconds - 1
		}},
		{"ReflectorNotAuthenticated", func(f *fixtureSet) {
			f.attempt.Reflector.Authenticated = false
		}},
		{"ReflectorNotTunnelOnly", func(f *fixtureSet) {
			f.attempt.Reflector.TunnelOnly = false
		}},
		{"ReflectorConfigDrift", func(f *fixtureSet) {
			f.attempt.Reflector.ConfigSHA256 = repeatedDigest('c')
		}},
		{"ReflectorRequestBeforeDNS", func(f *fixtureSet) {
			f.attempt.Reflector.RequestSentAtMonotonicNanoseconds =
				f.attempt.Predicates.ProtectedDNS.AtMonotonicNanoseconds - 1
		}},
		{"DNSUnattemptedWithRequest", func(f *fixtureSet) {
			f.attempt.DNS.Attempted = false
			f.attempt.DNS.Observed = false
			f.attempt.Predicates.ProtectedDNS.Observed = false
			f.attempt.Predicates.ProtectedDNS.AtMonotonicNanoseconds = 0
			f.attempt.DNS.ResponseAtMonotonicNanoseconds = 0
		}},
		{"ReflectorUnobservedAuthenticated", func(f *fixtureSet) {
			f.attempt.Reflector.Observed = false
			f.attempt.Reflector.Authenticated = true
			f.attempt.Predicates.AuthenticatedReflector.Observed = false
			f.attempt.Predicates.AuthenticatedReflector.AtMonotonicNanoseconds = 0
			f.attempt.Reflector.ResponseObservedAtMonotonicNanoseconds = 0
		}},
		{"LateReflectorCallback", func(f *fixtureSet) {
			f.attempt.Terminal.TerminalAtMonotonicNanoseconds =
				f.attempt.Reflector.ResponseObservedAtMonotonicNanoseconds - 1
		}},
		{"NonV4RunID", func(f *fixtureSet) {
			f.attempt.RunID = "01234567-89ab-1def-8123-456789abcdef"
			f.attempt.Binding.RunID = f.attempt.RunID
			f.topology.RunID = f.attempt.RunID
			f.attempt.Binding.BindingSHA256 = bindingDigest(f.attempt.Binding)
			rebindPredicates(&f.attempt)
		}},
		{"WrongUUIDVariant", func(f *fixtureSet) {
			f.attempt.AttemptNonce = "11111111-2222-4333-7444-555555555555"
			f.attempt.Binding.AttemptNonce = f.attempt.AttemptNonce
			f.attempt.Binding.BindingSHA256 = bindingDigest(f.attempt.Binding)
			rebindPredicates(&f.attempt)
		}},
		{"DuplicateBindingUUID", func(f *fixtureSet) {
			f.attempt.Binding.PathID = f.attempt.Binding.AttemptNonce
			f.attempt.Binding.BindingSHA256 = bindingDigest(f.attempt.Binding)
			rebindPredicates(&f.attempt)
		}},
		{"SuccessCleanupMutation", func(f *fixtureSet) {
			f.attempt.Terminal.CleanupState = "complete"
		}},
		{"SourcePinDrift", func(f *fixtureSet) {
			f.attempt.Pins.SourceSHA256 = repeatedDigest('c')
		}},
		{"CleanHostRejected", func(f *fixtureSet) {
			f.attempt.CleanHost.HostStressActive = true
		}},
		{"T0DeadlineOverflow", func(f *fixtureSet) {
			f.attempt.ConnectButtonT0MonotonicNanoseconds =
				math.MaxUint64 - deadlineNanoseconds + 1
			f.attempt.Binding.RequestedAtMonotonicNanoseconds =
				f.attempt.ConnectButtonT0MonotonicNanoseconds
			f.attempt.Binding.BindingSHA256 =
				bindingDigest(f.attempt.Binding)
			rebindPredicates(&f.attempt)
		}},
		{"DirectDNSReachability", func(f *fixtureSet) {
			f.topology.DNSDirectPreTunnel = "reachable"
		}},
		{"DirectReflectorReachability", func(f *fixtureSet) {
			f.topology.ReflectorDirectPostTeardown = "reachable"
		}},
		{"OuterPlaintextDNS", func(f *fixtureSet) {
			f.topology.OuterPlaintextDNSObserved = true
		}},
		{"OuterPlaintextReflector", func(f *fixtureSet) {
			f.topology.OuterPlaintextReflectorObserved = true
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := canonicalFixture(t)
			test.mutate(&fixture)
			root := writeFixture(t, fixture)
			if _, err := verifyFixture(
				root,
				fixtureContractPin,
				fixtureSourcePin,
				fixtureVerifierPin,
			); err == nil {
				t.Fatal("mutation was accepted")
			}
		})
	}
}

func TestOrdinaryFailureRequiresBoundedCleanupAndSameDeadlineUI(t *testing.T) {
	fixture := failedDNSFixture(t)
	root := writeFixture(t, fixture)
	if _, err := verifyFixture(
		root,
		fixtureContractPin,
		fixtureSourcePin,
		fixtureVerifierPin,
	); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*fixtureSet)
	}{
		{"NoCleanup", func(f *fixtureSet) {
			f.attempt.Terminal.CleanupState = "not-required"
		}},
		{"CleanupLate", func(f *fixtureSet) {
			f.attempt.Terminal.CleanupAtMonotonicNanoseconds++
		}},
		{"FailureUIPlusOne", func(f *fixtureSet) {
			f.attempt.Terminal.TUIMonotonicNanoseconds++
		}},
		{"WrongFailureCode", func(f *fixtureSet) {
			f.attempt.Terminal.FailureCode = "none"
		}},
		{"MismatchedPredicateFailureCode", func(f *fixtureSet) {
			f.attempt.Terminal.FailureCode = "reflector-failed"
		}},
		{"LateDNSRequestCallback", func(f *fixtureSet) {
			f.attempt.DNS.RequestAtMonotonicNanoseconds =
				f.attempt.Terminal.TerminalAtMonotonicNanoseconds + 1
		}},
		{"UnobservedDNSHasResponse", func(f *fixtureSet) {
			f.attempt.DNS.ResponseAtMonotonicNanoseconds =
				f.attempt.DNS.RequestAtMonotonicNanoseconds
		}},
		{"UnattemptedDNSHasFlags", func(f *fixtureSet) {
			f.attempt.DNS.Attempted = false
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := failedDNSFixture(t)
			test.mutate(&mutated)
			root := writeFixture(t, mutated)
			if _, err := verifyFixture(
				root,
				fixtureContractPin,
				fixtureSourcePin,
				fixtureVerifierPin,
			); err == nil {
				t.Fatal("failure mutation was accepted")
			}
		})
	}
}

func TestDeadlineFailureUsesSeparateBoundedReportingWindow(t *testing.T) {
	fixture := deadlineExceededFixture(t)
	root := writeFixture(t, fixture)
	if _, err := verifyFixture(
		root,
		fixtureContractPin,
		fixtureSourcePin,
		fixtureVerifierPin,
	); err != nil {
		t.Fatal(err)
	}

	for _, terminalAt := range []uint64{
		4_000_000_001,
		4_025_000_000,
		4_050_000_000,
	} {
		accepted := deadlineExceededFixture(t)
		accepted.attempt.Terminal.TerminalAtMonotonicNanoseconds = terminalAt
		accepted.attempt.Terminal.TUIMonotonicNanoseconds = 4_050_000_000
		accepted.attempt.Terminal.CleanupAtMonotonicNanoseconds =
			terminalAt + maxCleanupNanoseconds
		root := writeFixture(t, accepted)
		if _, err := verifyFixture(
			root,
			fixtureContractPin,
			fixtureSourcePin,
			fixtureVerifierPin,
		); err != nil {
			t.Fatalf("honest bounded timer wake %d rejected: %v", terminalAt, err)
		}
	}

	for _, test := range []struct {
		name   string
		mutate func(*fixtureSet)
	}{
		{"DecisionAtDeadline", func(f *fixtureSet) {
			f.attempt.Terminal.TerminalAtMonotonicNanoseconds--
		}},
		{"DecisionAfterReportingWindow", func(f *fixtureSet) {
			f.attempt.Terminal.TerminalAtMonotonicNanoseconds =
				4_050_000_001
			f.attempt.Terminal.TUIMonotonicNanoseconds =
				4_050_000_001
			f.attempt.Terminal.CleanupAtMonotonicNanoseconds =
				4_300_000_001
		}},
		{"UIAtDeadline", func(f *fixtureSet) {
			f.attempt.Terminal.TUIMonotonicNanoseconds = 4_000_000_000
		}},
		{"UIAfterReportingWindow", func(f *fixtureSet) {
			f.attempt.Terminal.TUIMonotonicNanoseconds++
		}},
		{"ReportingBudgetZero", func(f *fixtureSet) {
			f.attempt.Terminal.DeadlineFailureReportingBudgetNanoseconds = 0
		}},
		{"ReportingBudgetExtended", func(f *fixtureSet) {
			f.attempt.Terminal.DeadlineFailureReportingBudgetNanoseconds++
		}},
		{"CleanupAfterIndependentWindow", func(f *fixtureSet) {
			f.attempt.Terminal.CleanupAtMonotonicNanoseconds++
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := deadlineExceededFixture(t)
			test.mutate(&mutated)
			root := writeFixture(t, mutated)
			if _, err := verifyFixture(
				root,
				fixtureContractPin,
				fixtureSourcePin,
				fixtureVerifierPin,
			); err == nil {
				t.Fatal("deadline-failure timing mutation was accepted")
			}
		})
	}
}

func TestDeadlineFailureDecisionOverflowFailsClosed(t *testing.T) {
	attempt := deadlineExceededFixture(t).attempt
	attempt.ConnectButtonT0MonotonicNanoseconds =
		math.MaxUint64 - deadlineNanoseconds
	attempt.Terminal.TerminalAtMonotonicNanoseconds = math.MaxUint64
	attempt.Terminal.TUIMonotonicNanoseconds = math.MaxUint64
	if err := validateTerminal(attempt, math.MaxUint64); err == nil {
		t.Fatal("deadline-plus-one overflow was accepted")
	}
}

func TestNonDeadlineFailureCannotBorrowReportingWindow(t *testing.T) {
	for _, mutate := range []func(*fixtureSet){
		func(f *fixtureSet) {
			f.attempt.Terminal.DeadlineFailureReportingBudgetNanoseconds =
				maxDeadlineFailureReportingNanoseconds
		},
		func(f *fixtureSet) {
			f.attempt.Terminal.TerminalAtMonotonicNanoseconds =
				4_000_000_001
			f.attempt.Terminal.TUIMonotonicNanoseconds =
				4_000_000_001
			f.attempt.Terminal.CleanupAtMonotonicNanoseconds =
				4_100_000_001
		},
	} {
		fixture := failedDNSFixture(t)
		mutate(&fixture)
		root := writeFixture(t, fixture)
		if _, err := verifyFixture(
			root,
			fixtureContractPin,
			fixtureSourcePin,
			fixtureVerifierPin,
		); err == nil {
			t.Fatal("ordinary failure borrowed the deadline reporting window")
		}
	}
}

func TestEvidencePersistenceFailureRequiresCompletedProtectedFlow(t *testing.T) {
	fixture := canonicalFixture(t)
	fixture.attempt.Terminal.State = "failed"
	fixture.attempt.Terminal.FailureCode = "evidence-persistence-failed"
	fixture.attempt.Terminal.CleanupState = "complete"
	fixture.attempt.Terminal.CleanupAtMonotonicNanoseconds = 4_200_000_000
	root := writeFixture(t, fixture)
	if _, err := verifyFixture(
		root,
		fixtureContractPin,
		fixtureSourcePin,
		fixtureVerifierPin,
	); err != nil {
		t.Fatal(err)
	}

	mutated := canonicalFixture(t)
	mutated.attempt.Terminal = fixture.attempt.Terminal
	mutated.attempt.Predicates.AuthenticatedReflector.Observed = false
	mutated.attempt.Predicates.AuthenticatedReflector.AtMonotonicNanoseconds = 0
	mutated.attempt.Reflector.Observed = false
	mutated.attempt.Reflector.ResponseObservedAtMonotonicNanoseconds = 0
	mutated.attempt.Reflector.Authenticated = false
	root = writeFixture(t, mutated)
	if _, err := verifyFixture(
		root,
		fixtureContractPin,
		fixtureSourcePin,
		fixtureVerifierPin,
	); err == nil {
		t.Fatal("persistence failure without completed flow was accepted")
	}
}

func TestEveryEventClassIsBoundedByTerminalTime(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*AttemptEvidence, uint64)
	}{
		{"Predicate", func(a *AttemptEvidence, late uint64) {
			a.Predicates.FreshAWGHandshake.AtMonotonicNanoseconds = late
		}},
		{"AWGBaseline", func(a *AttemptEvidence, late uint64) {
			a.AWG.BaselineSampleAtMonotonicNanoseconds = late
		}},
		{"AWGHandshakePost", func(a *AttemptEvidence, late uint64) {
			a.AWG.HandshakePostSampleAtMonotonicNanoseconds = late
		}},
		{"AWGCounterPost", func(a *AttemptEvidence, late uint64) {
			a.AWG.CounterPostSampleAtMonotonicNanoseconds = late
		}},
		{"DNSRequest", func(a *AttemptEvidence, late uint64) {
			a.DNS.RequestAtMonotonicNanoseconds = late
		}},
		{"DNSResponse", func(a *AttemptEvidence, late uint64) {
			a.DNS.ResponseAtMonotonicNanoseconds = late
		}},
		{"ReflectorRequest", func(a *AttemptEvidence, late uint64) {
			a.Reflector.RequestSentAtMonotonicNanoseconds = late
		}},
		{"ReflectorResponse", func(a *AttemptEvidence, late uint64) {
			a.Reflector.ResponseObservedAtMonotonicNanoseconds = late
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			attempt := canonicalFixture(t).attempt
			terminal := attempt.Terminal.TerminalAtMonotonicNanoseconds
			test.mutate(&attempt, terminal+1)
			if err := validateNoLateEvents(attempt, terminal); err == nil {
				t.Fatal("late event was accepted")
			}
		})
	}
}

func TestAttemptedAndUnobservedProofStatesAreCanonical(t *testing.T) {
	deadline := uint64(4_000_000_000)

	dnsUnattempted := canonicalFixture(t).attempt
	dnsUnattempted.DNS.Attempted = false
	dnsUnattempted.DNS.Observed = false
	dnsUnattempted.DNS.RequestAtMonotonicNanoseconds = 0
	dnsUnattempted.DNS.ResponseAtMonotonicNanoseconds = 0
	dnsUnattempted.DNS.CacheBypassed = false
	dnsUnattempted.DNS.TunnelOnly = false
	dnsUnattempted.Predicates.ProtectedDNS.Observed = false
	dnsUnattempted.Predicates.ProtectedDNS.AtMonotonicNanoseconds = 0
	if err := validateDNS(
		dnsUnattempted,
		dnsUnattempted.DNS.TopologySHA256,
		deadline,
	); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*AttemptEvidence){
		func(a *AttemptEvidence) { a.DNS.RequestAtMonotonicNanoseconds = 1 },
		func(a *AttemptEvidence) { a.DNS.ResponseAtMonotonicNanoseconds = 1 },
		func(a *AttemptEvidence) { a.DNS.CacheBypassed = true },
		func(a *AttemptEvidence) { a.DNS.TunnelOnly = true },
	} {
		candidate := dnsUnattempted
		mutate(&candidate)
		if err := validateDNS(
			candidate,
			candidate.DNS.TopologySHA256,
			deadline,
		); err == nil {
			t.Fatal("noncanonical unattempted DNS state was accepted")
		}
	}

	reflectorUnattempted := failedDNSFixture(t).attempt
	if err := validateReflector(
		reflectorUnattempted,
		reflectorUnattempted.Reflector.TopologySHA256,
		deadline,
	); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*AttemptEvidence){
		func(a *AttemptEvidence) {
			a.Reflector.RequestSentAtMonotonicNanoseconds = 1
		},
		func(a *AttemptEvidence) {
			a.Reflector.ResponseObservedAtMonotonicNanoseconds = 1
		},
		func(a *AttemptEvidence) { a.Reflector.Authenticated = true },
		func(a *AttemptEvidence) { a.Reflector.TunnelOnly = true },
	} {
		candidate := reflectorUnattempted
		mutate(&candidate)
		if err := validateReflector(
			candidate,
			candidate.Reflector.TopologySHA256,
			deadline,
		); err == nil {
			t.Fatal("noncanonical unattempted reflector state was accepted")
		}
	}

	reflectorAttempted := failedReflectorFixture(t).attempt
	if err := validateReflector(
		reflectorAttempted,
		reflectorAttempted.Reflector.TopologySHA256,
		deadline,
	); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*AttemptEvidence){
		func(a *AttemptEvidence) {
			a.Reflector.RequestSentAtMonotonicNanoseconds = 0
		},
		func(a *AttemptEvidence) {
			a.Reflector.ResponseObservedAtMonotonicNanoseconds = 1
		},
		func(a *AttemptEvidence) { a.Reflector.Authenticated = true },
		func(a *AttemptEvidence) { a.Reflector.TunnelOnly = false },
	} {
		candidate := reflectorAttempted
		mutate(&candidate)
		if err := validateReflector(
			candidate,
			candidate.Reflector.TopologySHA256,
			deadline,
		); err == nil {
			t.Fatal("noncanonical attempted reflector state was accepted")
		}
	}
}

func TestStrictJSONMutationsReject(t *testing.T) {
	canonical := mustCanonical(t, canonicalFixture(t).manifest)
	mutations := map[string][]byte{
		"Unknown": bytes.Replace(
			canonical,
			[]byte(`{"schema":`),
			[]byte(`{"secret":"redacted","schema":`),
			1,
		),
		"ForbiddenRequestTag": bytes.Replace(
			canonical,
			[]byte(`{"schema":`),
			[]byte(`{"requestTag":"forbidden","schema":`),
			1,
		),
		"ForbiddenChallenge": bytes.Replace(
			canonical,
			[]byte(`{"schema":`),
			[]byte(`{"challenge":"forbidden","schema":`),
			1,
		),
		"ForbiddenAddress": bytes.Replace(
			canonical,
			[]byte(`{"schema":`),
			[]byte(`{"clientAddress":"192.0.2.1","schema":`),
			1,
		),
		"ForbiddenAppleID": bytes.Replace(
			canonical,
			[]byte(`{"schema":`),
			[]byte(`{"appleID":"owner@example.invalid","schema":`),
			1,
		),
		"Missing": bytes.Replace(
			canonical,
			[]byte(`"protocolVersion":"winn/3",`),
			nil,
			1,
		),
		"Duplicate": bytes.Replace(
			canonical,
			[]byte(`{"schema":"`),
			[]byte(`{"schema":"winn-stageb-physical-manifest/1","schema":"`),
			1,
		),
		"CaseVariant": bytes.Replace(
			canonical,
			[]byte(`"schema":`),
			[]byte(`"Schema":`),
			1,
		),
		"Null": bytes.Replace(
			canonical,
			[]byte(`"protocolVersion":"winn/3"`),
			[]byte(`"protocolVersion":null`),
			1,
		),
		"TrailingJSON": append(
			append([]byte(nil), canonical...),
			[]byte("{}\n")...,
		),
		"Whitespace": append([]byte(" "), canonical...),
	}
	for name, content := range mutations {
		t.Run(name, func(t *testing.T) {
			var manifest Manifest
			if err := decodeCanonicalJSON(content, &manifest); err == nil {
				t.Fatal("strict JSON mutation was accepted")
			}
		})
	}
}

func TestLocalConformanceReceiptCannotSubstitute(t *testing.T) {
	fixture := canonicalFixture(t)
	root := writeFixture(t, fixture)
	local := []byte(
		`{"schema":"winn-stageb-local-receipt/1",` +
			`"measurementScope":"local-conformance-only"}` + "\n",
	)
	evidencePath := filepath.Join(root, fixture.manifest.EvidencePath)
	if err := os.WriteFile(evidencePath, local, 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.manifest.EvidenceSHA256 = digest(local)
	writeCanonicalFile(t, filepath.Join(root, "manifest.json"), fixture.manifest)
	if _, err := verifyFixture(
		root,
		fixtureContractPin,
		fixtureSourcePin,
		fixtureVerifierPin,
	); err == nil {
		t.Fatal("local-conformance receipt was accepted")
	}
}

func TestManifestPinsAndEvidenceDigestsFailClosed(t *testing.T) {
	for _, test := range []struct {
		name                     string
		expectedManifest         string
		expectedContract         string
		expectedSource           string
		expectedVerify           string
		mutate                   func(*fixtureSet)
		mutateManifestAfterWrite func(*Manifest)
	}{
		{
			name:             "ExpectedManifest",
			expectedManifest: repeatedDigest('a'),
			expectedContract: fixtureContractPin,
			expectedSource:   fixtureSourcePin,
			expectedVerify:   fixtureVerifierPin,
		},
		{
			name:             "ExpectedContract",
			expectedContract: repeatedDigest('a'),
			expectedSource:   fixtureSourcePin,
			expectedVerify:   fixtureVerifierPin,
		},
		{
			name:             "ExpectedSource",
			expectedContract: fixtureContractPin,
			expectedSource:   repeatedDigest('a'),
			expectedVerify:   fixtureVerifierPin,
		},
		{
			name:             "ExpectedVerifier",
			expectedContract: fixtureContractPin,
			expectedSource:   fixtureSourcePin,
			expectedVerify:   repeatedDigest('a'),
		},
		{
			name:             "ManifestContractDrift",
			expectedContract: fixtureContractPin,
			expectedSource:   fixtureSourcePin,
			expectedVerify:   fixtureVerifierPin,
			mutateManifestAfterWrite: func(manifest *Manifest) {
				manifest.ContractSHA256 = repeatedDigest('a')
			},
		},
		{
			name:             "EvidenceDigest",
			expectedContract: fixtureContractPin,
			expectedSource:   fixtureSourcePin,
			expectedVerify:   fixtureVerifierPin,
			mutateManifestAfterWrite: func(manifest *Manifest) {
				manifest.EvidenceSHA256 = repeatedDigest('a')
			},
		},
		{
			name:             "TopologyDigest",
			expectedContract: fixtureContractPin,
			expectedSource:   fixtureSourcePin,
			expectedVerify:   fixtureVerifierPin,
			mutateManifestAfterWrite: func(manifest *Manifest) {
				manifest.TopologySHA256 = repeatedDigest('a')
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := canonicalFixture(t)
			if test.mutate != nil {
				test.mutate(&fixture)
			}
			root := writeFixture(t, fixture)
			if test.mutateManifestAfterWrite != nil {
				test.mutateManifestAfterWrite(&fixture.manifest)
				writeCanonicalFile(
					t,
					filepath.Join(root, "manifest.json"),
					fixture.manifest,
				)
			}
			manifestPath := filepath.Join(root, "manifest.json")
			manifestBytes, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			expectedManifest := test.expectedManifest
			if expectedManifest == "" {
				expectedManifest = digest(manifestBytes)
			}
			if _, err := Verify(
				manifestPath,
				expectedManifest,
				test.expectedContract,
				test.expectedSource,
				test.expectedVerify,
			); err == nil {
				t.Fatal("pin mutation was accepted")
			}
		})
	}
}

func TestManifestBytesArePinnedBeforeParsing(t *testing.T) {
	root := writeFixture(t, canonicalFixture(t))
	manifestPath := filepath.Join(root, "manifest.json")
	original, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		manifestPath,
		append([]byte(" "), original...),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	_, err = Verify(
		manifestPath,
		digest(original),
		fixtureContractPin,
		fixtureSourcePin,
		fixtureVerifierPin,
	)
	if err == nil ||
		!strings.Contains(err.Error(), "manifest bytes do not match independent pin") {
		t.Fatalf("manifest was parsed before external digest refusal: %v", err)
	}
}

func TestRootRelativePathAndFileTypeRefusal(t *testing.T) {
	t.Run("ManifestTraversal", func(t *testing.T) {
		root := writeFixture(t, canonicalFixture(t))
		manifestBytes, err := os.ReadFile(filepath.Join(root, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(
			root+"/evidence/../manifest.json",
			digest(manifestBytes),
			fixtureContractPin,
			fixtureSourcePin,
			fixtureVerifierPin,
		); err == nil {
			t.Fatal("noncanonical manifest traversal was accepted")
		}
	})

	for name, path := range map[string]string{
		"Absolute":  "/tmp/attempt.json",
		"Escape":    "../attempt.json",
		"Dot":       "./attempt.json",
		"Backslash": `evidence\attempt.json`,
		"IPAddress": "192.0.2.1",
		"Hostname":  "evidence.example/attempt.json",
		"Alternate": "evidence/other.json",
	} {
		t.Run(name, func(t *testing.T) {
			fixture := canonicalFixture(t)
			root := writeFixture(t, fixture)
			fixture.manifest.EvidencePath = path
			writeCanonicalFile(
				t,
				filepath.Join(root, "manifest.json"),
				fixture.manifest,
			)
			if _, err := verifyFixture(
				root,
				fixtureContractPin,
				fixtureSourcePin,
				fixtureVerifierPin,
			); err == nil {
				t.Fatal("unsafe path was accepted")
			}
		})
	}

	t.Run("Symlink", func(t *testing.T) {
		fixture := canonicalFixture(t)
		root := writeFixture(t, fixture)
		target := filepath.Join(root, "actual-attempt.json")
		if err := os.Rename(
			filepath.Join(root, fixture.manifest.EvidencePath),
			target,
		); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(
			"../actual-attempt.json",
			filepath.Join(root, fixture.manifest.EvidencePath),
		); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyFixture(
			root,
			fixtureContractPin,
			fixtureSourcePin,
			fixtureVerifierPin,
		); err == nil {
			t.Fatal("symlink evidence was accepted")
		}
	})

	t.Run("IntermediateDirectorySymlink", func(t *testing.T) {
		fixture := canonicalFixture(t)
		root := writeFixture(t, fixture)
		actual := filepath.Join(root, "actual-evidence")
		if err := os.Rename(filepath.Join(root, "evidence"), actual); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(
			"actual-evidence",
			filepath.Join(root, "evidence"),
		); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyFixture(
			root,
			fixtureContractPin,
			fixtureSourcePin,
			fixtureVerifierPin,
		); err == nil {
			t.Fatal("intermediate directory symlink was accepted")
		}
	})

	t.Run("RootSymlink", func(t *testing.T) {
		fixture := canonicalFixture(t)
		root := writeFixture(t, fixture)
		parent := t.TempDir()
		linkedRoot := filepath.Join(parent, "linked-root")
		if err := os.Symlink(root, linkedRoot); err != nil {
			t.Fatal(err)
		}
		manifestBytes, err := os.ReadFile(filepath.Join(root, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(
			filepath.Join(linkedRoot, "manifest.json"),
			digest(manifestBytes),
			fixtureContractPin,
			fixtureSourcePin,
			fixtureVerifierPin,
		); err == nil {
			t.Fatal("symlink evidence root was accepted")
		}
	})

	t.Run("OpenedFileSwap", func(t *testing.T) {
		fixture := canonicalFixture(t)
		root := writeFixture(t, fixture)
		manifestPath := filepath.Join(root, "manifest.json")
		manifestBytes, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		swapped := false
		_, err = verifyWithHooks(
			manifestPath,
			digest(manifestBytes),
			fixtureContractPin,
			fixtureSourcePin,
			fixtureVerifierPin,
			verificationHooks{
				afterOpen: func(name string) {
					if swapped || name != "evidence/attempt.json" {
						return
					}
					swapped = true
					path := filepath.Join(root, name)
					original := path + ".opened"
					if renameErr := os.Rename(path, original); renameErr != nil {
						t.Fatal(renameErr)
					}
					content, readErr := os.ReadFile(original)
					if readErr != nil {
						t.Fatal(readErr)
					}
					if writeErr := os.WriteFile(path, content, 0o600); writeErr != nil {
						t.Fatal(writeErr)
					}
				},
			},
		)
		if err == nil || !swapped {
			t.Fatal("opened evidence file replacement was accepted")
		}
	})

	t.Run("OpenedDirectorySwap", func(t *testing.T) {
		fixture := canonicalFixture(t)
		root := writeFixture(t, fixture)
		manifestPath := filepath.Join(root, "manifest.json")
		manifestBytes, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		swapped := false
		_, err = verifyWithHooks(
			manifestPath,
			digest(manifestBytes),
			fixtureContractPin,
			fixtureSourcePin,
			fixtureVerifierPin,
			verificationHooks{
				afterOpen: func(name string) {
					if swapped || name != "evidence/attempt.json" {
						return
					}
					swapped = true
					directory := filepath.Join(root, "evidence")
					openedDirectory := filepath.Join(root, "evidence.opened")
					if renameErr := os.Rename(
						directory,
						openedDirectory,
					); renameErr != nil {
						t.Fatal(renameErr)
					}
					if mkdirErr := os.Mkdir(directory, 0o700); mkdirErr != nil {
						t.Fatal(mkdirErr)
					}
				},
			},
		)
		if err == nil || !swapped {
			t.Fatal("opened evidence directory replacement was accepted")
		}
	})
}

func TestCanonicalFixtureDigestsAreStable(t *testing.T) {
	fixture := canonicalFixture(t)
	got := []string{
		digest(mustCanonical(t, fixture.manifest)),
		digest(mustCanonical(t, fixture.attempt)),
		digest(mustCanonical(t, fixture.topology)),
		fixture.attempt.Binding.BindingSHA256,
	}
	want := []string{
		"b79a4ba2d360992b74286ac925aaeb4480e71d708b3f279a36efaae07e2c6df7",
		"05223cc232b7ae142dc9cd1c63b91489aca9d3d388c50854fae8748abe1a8a99",
		"4e14d0a0ed5070be17e4f21be4e80fe0630f14b1989102d466f161d6652acba9",
		"d6a1581559db4fb1589eb070fda72b8df62b0d55279e87c88eb6072b73a0e812",
	}
	for index := range want {
		if got[index] != want[index] {
			t.Errorf(
				"digest[%d]=%s; replace fixture pin %s",
				index,
				got[index],
				want[index],
			)
		}
	}
}

func failedDNSFixture(t *testing.T) fixtureSet {
	t.Helper()
	fixture := canonicalFixture(t)
	fixture.attempt.Predicates.ProtectedDNS.Observed = false
	fixture.attempt.Predicates.ProtectedDNS.AtMonotonicNanoseconds = 0
	fixture.attempt.Predicates.AuthenticatedReflector.Observed = false
	fixture.attempt.Predicates.AuthenticatedReflector.AtMonotonicNanoseconds = 0
	fixture.attempt.DNS.Observed = false
	fixture.attempt.DNS.ResponseAtMonotonicNanoseconds = 0
	fixture.attempt.Reflector.Attempted = false
	fixture.attempt.Reflector.Observed = false
	fixture.attempt.Reflector.RequestSentAtMonotonicNanoseconds = 0
	fixture.attempt.Reflector.ResponseObservedAtMonotonicNanoseconds = 0
	fixture.attempt.Reflector.Authenticated = false
	fixture.attempt.Reflector.TunnelOnly = false
	fixture.attempt.Terminal = Terminal{
		State:                          "failed",
		FailureCode:                    "protected-dns-failed",
		TerminalAtMonotonicNanoseconds: 3_900_000_000,
		TDataMonotonicNanoseconds:      0,
		TUIMonotonicNanoseconds:        4_000_000_000,
		DeadlineFailureReportingBudgetNanoseconds: 0,
		CleanupState:                  "complete",
		CleanupAtMonotonicNanoseconds: 4_150_000_000,
		CleanupBudgetNanoseconds:      maxCleanupNanoseconds,
	}
	return fixture
}

func failedReflectorFixture(t *testing.T) fixtureSet {
	t.Helper()
	fixture := canonicalFixture(t)
	fixture.attempt.Predicates.AuthenticatedReflector.Observed = false
	fixture.attempt.Predicates.AuthenticatedReflector.AtMonotonicNanoseconds = 0
	fixture.attempt.Reflector.Observed = false
	fixture.attempt.Reflector.ResponseObservedAtMonotonicNanoseconds = 0
	fixture.attempt.Reflector.Authenticated = false
	fixture.attempt.Terminal = Terminal{
		State:                          "failed",
		FailureCode:                    "reflector-failed",
		TerminalAtMonotonicNanoseconds: 3_900_000_000,
		TDataMonotonicNanoseconds:      0,
		TUIMonotonicNanoseconds:        4_000_000_000,
		DeadlineFailureReportingBudgetNanoseconds: 0,
		CleanupState:                  "complete",
		CleanupAtMonotonicNanoseconds: 4_150_000_000,
		CleanupBudgetNanoseconds:      maxCleanupNanoseconds,
	}
	return fixture
}

func deadlineExceededFixture(t *testing.T) fixtureSet {
	t.Helper()
	fixture := failedDNSFixture(t)
	fixture.attempt.Terminal = Terminal{
		State:                          "failed",
		FailureCode:                    "deadline-exceeded",
		TerminalAtMonotonicNanoseconds: 4_000_000_001,
		TDataMonotonicNanoseconds:      0,
		TUIMonotonicNanoseconds:        4_050_000_000,
		DeadlineFailureReportingBudgetNanoseconds: maxDeadlineFailureReportingNanoseconds,
		CleanupState:                  "complete",
		CleanupAtMonotonicNanoseconds: 4_250_000_001,
		CleanupBudgetNanoseconds:      maxCleanupNanoseconds,
	}
	return fixture
}

func writeFixture(t *testing.T, fixture fixtureSet) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "evidence"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "proof"), 0o700); err != nil {
		t.Fatal(err)
	}
	topologyBytes := mustCanonical(t, fixture.topology)
	fixture.manifest.TopologySHA256 = digest(topologyBytes)
	fixture.attempt.DNS.TopologySHA256 = fixture.manifest.TopologySHA256
	fixture.attempt.Reflector.TopologySHA256 = fixture.manifest.TopologySHA256
	attemptBytes := mustCanonical(t, fixture.attempt)
	fixture.manifest.EvidenceSHA256 = digest(attemptBytes)
	writeBytes(t, filepath.Join(root, fixture.manifest.TopologyPath), topologyBytes)
	writeBytes(t, filepath.Join(root, fixture.manifest.EvidencePath), attemptBytes)
	writeCanonicalFile(t, filepath.Join(root, "manifest.json"), fixture.manifest)
	return root
}

func verifyFixture(
	root string,
	expectedContract string,
	expectedSource string,
	expectedVerifier string,
) (Result, error) {
	manifestPath := filepath.Join(root, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return Result{}, err
	}
	return Verify(
		manifestPath,
		digest(manifestBytes),
		expectedContract,
		expectedSource,
		expectedVerifier,
	)
}

func writeCanonicalFile(t *testing.T, path string, value any) {
	t.Helper()
	writeBytes(t, path, mustCanonical(t, value))
}

func writeBytes(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustCanonical(t *testing.T, value any) []byte {
	t.Helper()
	content, err := MarshalCanonical(value)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func repeatedDigest(character byte) string {
	return strings.Repeat(string(character), 64)
}

func rebindPredicates(attempt *AttemptEvidence) {
	binding := attempt.Binding.BindingSHA256
	attempt.Predicates.FreshAWGHandshake.BindingSHA256 = binding
	attempt.Predicates.AuthenticatedBidirectionalBytes.BindingSHA256 = binding
	attempt.Predicates.ProtectedDNS.BindingSHA256 = binding
	attempt.Predicates.AuthenticatedReflector.BindingSHA256 = binding
	attempt.AWG.BindingSHA256 = binding
	attempt.DNS.BindingSHA256 = binding
	attempt.Reflector.BindingSHA256 = binding
}

func TestEmitCanonicalFixtureForMaintainers(t *testing.T) {
	if os.Getenv("WINN_EMIT_STAGEB_PHYSICAL_FIXTURE") != "1" {
		t.Skip("maintainer-only fixture emission")
	}
	fixture := canonicalFixture(t)
	for name, value := range map[string]any{
		"manifest.json":         fixture.manifest,
		"evidence/attempt.json": fixture.attempt,
		"proof/topology.json":   fixture.topology,
	} {
		content, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s=%s", name, content)
	}
}
