package connectivity

import (
	"strings"
	"testing"
)

// This test is the both-directions proof for the config-issuance gate. It
// asserts the negative (an old client is refused a winn/3 config) and the
// positive (a winn/3-capable client is eligible) in the same run, and it is
// wired to be run against a mutation by fin_ios_gate_mutate_20260811.py: the
// fail-open mutant (Winn3ConfigEligible made to return nil for everyone) must
// trip the v1-refusal assertion below. A green here therefore cannot come from
// a gate that always says yes.

// oldClients are the configs that predate winn/3 and must be refused. v1 is
// the AmneziaWG generation before winn/3 existed; v2 is the rekey-only client
// that can ask for a key but cannot carry a winn/3 session. Both would silently
// fail against a v3 gateway (which answers no unauthenticated datagram), so an
// issuer that handed either a winn/3 config would produce the indistinguishable-
// from-censorship failure this gate exists to prevent.
func oldClients() []ClientCapability {
	return []ClientCapability{
		{ProtocolVersion: "winn/1", NegotiationReady: true},
		{ProtocolVersion: "winn/2", NegotiationReady: true},
		// An even older client sends neither a version nor the boolean: the
		// zero value. It must also be refused.
		{ProtocolVersion: "", NegotiationReady: false},
	}
}

// TestOldClientNeverReceivesWinn3Config is the negative direction: every
// pre-winn/3 client is refused at issuance.
func TestOldClientNeverReceivesWinn3Config(t *testing.T) {
	for _, cap := range oldClients() {
		if err := Winn3ConfigEligible(cap); err == nil {
			t.Fatalf(
				"Winn3ConfigEligible(version=%q ready=%t) = nil, want refusal: "+
					"an old client must never be handed a winn/3 config",
				cap.ProtocolVersion, cap.NegotiationReady,
			)
		}
	}
	err := Winn3ConfigEligible(oldClients()[0])
	if !strings.Contains(err.Error(), "winn/3") {
		t.Fatalf("refusal error does not name the winn/3 contract: %v", err)
	}
}

// TestWinn3CapableClientIsEligible is the positive direction: a client that
// declares exactly Version and can actually negotiate is eligible.
func TestWinn3CapableClientIsEligible(t *testing.T) {
	cap := ClientCapability{ProtocolVersion: Version, NegotiationReady: true}
	if err := Winn3ConfigEligible(cap); err != nil {
		t.Fatalf(
			"Winn3ConfigEligible(version=%q ready=true) = %v, want nil",
			cap.ProtocolVersion, err,
		)
	}
}

// TestWinn3ButNotNegotiationReadyIsRefused is the second fail-closed direction:
// a client that declares winn/3 but cannot carry a session is no more eligible
// than a v1 client — it would equally be handed a config it could never
// complete. This is the property clientbinding reports as
// `safe_to_advertise_protocol`.
func TestWinn3ButNotNegotiationReadyIsRefused(t *testing.T) {
	cap := ClientCapability{ProtocolVersion: Version, NegotiationReady: false}
	err := Winn3ConfigEligible(cap)
	if err == nil {
		t.Fatal(
			"Winn3ConfigEligible(version=winn/3 ready=false) = nil, want refusal: " +
				"advertising winn/3 without the ability to negotiate must not issue a config",
		)
	}
	if !strings.Contains(err.Error(), "negotiat") {
		t.Fatalf("not-ready refusal does not name the reason: %v", err)
	}
}
