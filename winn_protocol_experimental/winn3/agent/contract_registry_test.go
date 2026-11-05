package agent

import (
	"errors"
	"testing"
)

// registry is the production ContractRegistry under test. Instances are cheap
// and independent, so each test builds its own and never shares one across
// assertions.
func registry() *ContractRegistry {
	return NewContractRegistry()
}

func conn(params ...Param) *Action {
	return &Action{Kind: ActionConnect, Params: params, Policy: PolicyRef{Name: "default", Version: 3}}
}

func rot(params ...Param) *Action {
	return &Action{Kind: ActionRotateKey, Params: params, Policy: PolicyRef{Name: "default", Version: 3}}
}

// TestRegistry_ValidConnectPasses asserts the happy path: a connect carrying
// both production-required params (gateway_id and host) must be accepted. This
// is the only connect through the production registry that must clear the gate.
func TestRegistry_ValidConnectPasses(t *testing.T) {
	a := conn(
		Param{Name: "gateway_id", Value: "spain-madrid"},
		Param{Name: "host", Value: "spain-madrid:443"},
	)
	if err := registry().Validate(a); err != nil {
		t.Fatalf("valid connect was rejected: %v", err)
	}
}

// TestRegistry_ConnectMissingGatewayIDRejected asserts the negative half of the
// connect contract: dropping gateway_id must fail, reported as ErrMalformed,
// even though host is present. A registry that accepts this has no connect
// gate at all.
func TestRegistry_ConnectMissingGatewayIDRejected(t *testing.T) {
	a := conn(
		Param{Name: "host", Value: "spain-madrid:443"},
	)
	err := registry().Validate(a)
	if err == nil {
		t.Fatal("connect missing gateway_id was accepted; expected ErrMalformed")
	}
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("connect missing gateway_id produced %v, want ErrMalformed", err)
	}
}

// TestRegistry_RotateKeyMissingKeyIDRejected asserts the negative half of the
// rotate_key contract: dropping key_id must fail, reported as ErrMalformed,
// even though algorithm is present.
func TestRegistry_RotateKeyMissingKeyIDRejected(t *testing.T) {
	a := rot(
		Param{Name: "algorithm", Value: "x25519"},
	)
	err := registry().Validate(a)
	if err == nil {
		t.Fatal("rotate_key missing key_id was accepted; expected ErrMalformed")
	}
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("rotate_key missing key_id produced %v, want ErrMalformed", err)
	}
}

// TestRegistry_RotateKeyMissingAlgorithmRejected asserts the second required
// param of rotate_key is enforced independently of key_id.
func TestRegistry_RotateKeyMissingAlgorithmRejected(t *testing.T) {
	a := rot(
		Param{Name: "key_id", Value: "k-7"},
	)
	err := registry().Validate(a)
	if err == nil {
		t.Fatal("rotate_key missing algorithm was accepted; expected ErrMalformed")
	}
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("rotate_key missing algorithm produced %v, want ErrMalformed", err)
	}
}

// TestRegistry_ConnectUnexpectedParamRejected asserts the negative half of the
// connect Allowed set. A connect carrying an unexpected param must be rejected
// as ErrMalformed, so the Allowed list is real and the Required params above
// are not merely being ignored.
func TestRegistry_ConnectUnexpectedParamRejected(t *testing.T) {
	a := conn(
		Param{Name: "gateway_id", Value: "spain-madrid"},
		Param{Name: "host", Value: "spain-madrid:443"},
		Param{Name: "injected", Value: "x"},
	)
	err := registry().Validate(a)
	if err == nil {
		t.Fatal("connect with an unexpected param was accepted; expected ErrMalformed")
	}
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("connect with unexpected param produced %v, want ErrMalformed", err)
	}
}

// TestRegistry_UnknownKindStillDenied guards the interaction between the
// registry and the closed kind set: a well-formed action of an unknown kind is
// denied as ErrUnknownKind, not silently admitted or mislabelled ErrMalformed.
func TestRegistry_UnknownKindStillDenied(t *testing.T) {
	a := &Action{Kind: ActionKind("erase_all_billing"), Params: nil, Policy: PolicyRef{Name: "default", Version: 3}}
	err := registry().Validate(a)
	if err == nil {
		t.Fatal("unknown kind was accepted; expected ErrUnknownKind")
	}
	if !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("unknown kind produced %v, want ErrUnknownKind", err)
	}
}

// TestRegistry_FailureClassesStayDistinct guards the sentinels under the
// registry path: if ErrUnknownKind and ErrMalformed ever collapse, the two
// negative controls above cannot distinguish a denied action from a rejected
// one.
func TestRegistry_FailureClassesStayDistinct(t *testing.T) {
	if ErrUnknownKind == ErrMalformed {
		t.Fatal("ErrUnknownKind and ErrMalformed are the same value")
	}
}
