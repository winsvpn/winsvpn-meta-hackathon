package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func prodConnect(gateway, host string) *Action {
	return &Action{
		Kind: ActionConnect,
		Params: []Param{
			{Name: "gateway_id", Value: gateway},
			{Name: "host", Value: host},
		},
		Policy: PolicyRef{Name: "default", Version: 3},
	}
}

func prodRotate(keyID, algo, principal string) *Action {
	params := []Param{
		{Name: "key_id", Value: keyID},
		{Name: "algorithm", Value: algo},
	}
	if principal != "" {
		params = append(params, Param{Name: "principal", Value: principal})
	}
	return &Action{
		Kind:   ActionRotateKey,
		Params: params,
		Policy: PolicyRef{Name: "default", Version: 3},
	}
}

func prodReport(params ...Param) *Action {
	return &Action{
		Kind:   ActionReport,
		Params: params,
		Policy: PolicyRef{Name: "default", Version: 3},
	}
}

// TestDenyGateway_MissingGatewayIDDenied is the fail-closed bound: a connect
// with no gateway_id must be denied, not allowed. Before this guard, DenyGateway
// returned Allow whenever the banned name was absent, including when the
// param itself was absent.
func TestDenyGateway_MissingGatewayIDDenied(t *testing.T) {
	rule := DenyGateway("banned-gateway")
	act := &Action{
		Kind:   ActionConnect,
		Params: []Param{{Name: "host", Value: "gx10:443"}},
		Policy: PolicyRef{Name: "default", Version: 3},
	}
	if got := rule(context.Background(), act); got != Deny {
		t.Fatalf("missing gateway_id decision = %v, want %v", got, Deny)
	}
}

// TestDenyGateway_EmptyGatewayIDDenied denies a present but empty gateway_id.
func TestDenyGateway_EmptyGatewayIDDenied(t *testing.T) {
	rule := DenyGateway("banned-gateway")
	act := connectAction("")
	if got := rule(context.Background(), act); got != Deny {
		t.Fatalf("empty gateway_id decision = %v, want %v", got, Deny)
	}
}

// TestDenyGateway_NilActionDenied denies nil rather than panicking or allowing.
func TestDenyGateway_NilActionDenied(t *testing.T) {
	rule := DenyGateway("banned-gateway")
	if got := rule(context.Background(), nil); got != Deny {
		t.Fatalf("nil action decision = %v, want %v", got, Deny)
	}
}

// TestDenyGateway_NoParamsDenied is the no-param form of missing gateway_id.
func TestDenyGateway_NoParamsDenied(t *testing.T) {
	rule := DenyGateway()
	act := &Action{Kind: ActionConnect, Policy: PolicyRef{Name: "default", Version: 3}}
	if got := rule(context.Background(), act); got != Deny {
		t.Fatalf("no-params connect decision = %v, want %v", got, Deny)
	}
}

// TestAllowRule_NilActionDenied pins that the positive bound still refuses nil.
func TestAllowRule_NilActionDenied(t *testing.T) {
	if got := AllowRule()(context.Background(), nil); got != Deny {
		t.Fatalf("AllowRule nil decision = %v, want %v", got, Deny)
	}
}

// TestRequirePrincipal_OwnerAllowed is the positive bound of the rotate_key
// ownership rule.
func TestRequirePrincipal_OwnerAllowed(t *testing.T) {
	rule := RequirePrincipal("owner")
	act := prodRotate("k-7", "x25519", "owner")
	if got := rule(context.Background(), act); got != Allow {
		t.Fatalf("owner principal decision = %v, want %v", got, Allow)
	}
}

// TestRequirePrincipal_NonOwnerDenied is the deny path: a non-owner must not
// rotate keys.
func TestRequirePrincipal_NonOwnerDenied(t *testing.T) {
	rule := RequirePrincipal("owner")
	act := prodRotate("k-7", "x25519", "attacker")
	if got := rule(context.Background(), act); got != Deny {
		t.Fatalf("non-owner principal decision = %v, want %v", got, Deny)
	}
}

// TestRequirePrincipal_MissingDenied denies rotate_key with no principal.
func TestRequirePrincipal_MissingDenied(t *testing.T) {
	rule := RequirePrincipal("owner")
	act := prodRotate("k-7", "x25519", "")
	if got := rule(context.Background(), act); got != Deny {
		t.Fatalf("missing principal decision = %v, want %v", got, Deny)
	}
}

// TestRequirePrincipal_EmptyOwnerDenied: a rule constructed with an empty
// owner must deny even when the action carries principal "".
func TestRequirePrincipal_EmptyOwnerDenied(t *testing.T) {
	rule := RequirePrincipal("")
	act := prodRotate("k-7", "x25519", "")
	act.Params = append(act.Params, Param{Name: "principal", Value: ""})
	if got := rule(context.Background(), act); got != Deny {
		t.Fatalf("empty owner decision = %v, want %v", got, Deny)
	}
}

// TestRequirePrincipal_ConflictingDuplicatesDenied: first-match-wins would
// allow owner followed by attacker. Any non-owner value must deny.
func TestRequirePrincipal_ConflictingDuplicatesDenied(t *testing.T) {
	rule := RequirePrincipal("owner")
	act := &Action{
		Kind: ActionRotateKey,
		Params: []Param{
			{Name: "key_id", Value: "k-7"},
			{Name: "algorithm", Value: "x25519"},
			{Name: "principal", Value: "owner"},
			{Name: "principal", Value: "attacker"},
		},
		Policy: PolicyRef{Name: "default", Version: 3},
	}
	if got := rule(context.Background(), act); got != Deny {
		t.Fatalf("conflicting principal decision = %v, want %v", got, Deny)
	}
}

// TestRequirePrincipal_NilActionDenied denies nil rather than panicking.
func TestRequirePrincipal_NilActionDenied(t *testing.T) {
	if got := RequirePrincipal("owner")(context.Background(), nil); got != Deny {
		t.Fatalf("nil action decision = %v, want %v", got, Deny)
	}
}

// TestRegister_NilRuleRejected is the Register error path with no existing test.
func TestRegister_NilRuleRejected(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.Register(ActionConnect, nil); err == nil {
		t.Fatal("registering a nil rule did not fail")
	}
}

// TestRegister_NilEngineRejected refuses a nil or zero engine rather than
// panicking on map assign.
func TestRegister_NilEngineRejected(t *testing.T) {
	var e *PolicyEngine
	if err := e.Register(ActionConnect, AllowRule()); err == nil {
		t.Fatal("nil engine Register did not fail")
	}
	z := &PolicyEngine{}
	if err := z.Register(ActionConnect, AllowRule()); err == nil {
		t.Fatal("zero engine Register did not fail")
	}
}

// TestEvaluate_NilEngineDenied denies on a nil engine rather than panicking.
func TestEvaluate_NilEngineDenied(t *testing.T) {
	var e *PolicyEngine
	if got := e.Evaluate(context.Background(), connectAction("gx10")); got != Deny {
		t.Fatalf("nil engine decision = %v, want %v", got, Deny)
	}
}

// TestRegistry_ReportTakesNoParams is the fail-closed bound for ActionReport:
// extra params, including a frozen-fleet register smuggle, must be ErrMalformed.
func TestRegistry_ReportTakesNoParams(t *testing.T) {
	reg := NewContractRegistry()
	cases := []*Action{
		prodReport(Param{Name: "note", Value: "x"}),
		prodReport(Param{Name: "register", Value: "spain-madrid"}),
		prodReport(Param{Name: "ssh_host", Value: "kansas"}),
	}
	for i, a := range cases {
		err := reg.Validate(a)
		if err == nil {
			t.Fatalf("case %d report with params was accepted; expected ErrMalformed", i)
		}
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("case %d produced %v, want ErrMalformed", i, err)
		}
	}
	if err := reg.Validate(prodReport()); err != nil {
		t.Fatalf("empty report was rejected: %v", err)
	}
}

// TestRegistry_ConnectRegisterParamRejected: a production-valid-looking
// connect that also carries register must be schema-rejected, so the
// frozen-fleet collision cannot ride on connect.
func TestRegistry_ConnectRegisterParamRejected(t *testing.T) {
	reg := NewContractRegistry()
	a := prodConnect("gx10", "gx10:443")
	a.Params = append(a.Params, Param{Name: "register", Value: "spain-madrid"})
	err := reg.Validate(a)
	if err == nil {
		t.Fatal("connect with register param was accepted; expected ErrMalformed")
	}
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("connect with register produced %v, want ErrMalformed", err)
	}
}

// TestRegistry_RotateKeyPrincipalAdmitted: principal is allowed on rotate_key
// so RequirePrincipal can run after the schema gate. Unexpected names still fail.
func TestRegistry_RotateKeyPrincipalAdmitted(t *testing.T) {
	reg := NewContractRegistry()
	if err := reg.Validate(prodRotate("k-7", "x25519", "owner")); err != nil {
		t.Fatalf("rotate_key with principal was rejected: %v", err)
	}
	if err := reg.Validate(prodRotate("k-7", "x25519", "")); err != nil {
		t.Fatalf("rotate_key without principal was rejected: %v", err)
	}
	bad := prodRotate("k-7", "x25519", "owner")
	bad.Params = append(bad.Params, Param{Name: "injected", Value: "x"})
	if err := reg.Validate(bad); err == nil {
		t.Fatal("rotate_key with unexpected param was accepted")
	} else if !errors.Is(err, ErrMalformed) {
		t.Fatalf("unexpected param produced %v, want ErrMalformed", err)
	}
}

// TestRegistry_DuplicateParamRejected: duplicate names make param order
// meaningful, which the schema forbids.
func TestRegistry_DuplicateParamRejected(t *testing.T) {
	reg := NewContractRegistry()
	a := prodConnect("gx10", "gx10:443")
	a.Params = append(a.Params, Param{Name: "gateway_id", Value: "other"})
	err := reg.Validate(a)
	if err == nil {
		t.Fatal("duplicate gateway_id was accepted; expected ErrMalformed")
	}
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("duplicate param produced %v, want ErrMalformed", err)
	}
	if !strings.Contains(err.Error(), "duplicate param") {
		t.Fatalf("error %q does not name duplicate param", err.Error())
	}
}

// TestRegistry_EmptyPolicyNameRejected: a missing or empty policy name is
// malformed. The derived JSON Schema marks policy.name required; Validate
// must enforce the same, not only the JSON Schema helper.
func TestRegistry_EmptyPolicyNameRejected(t *testing.T) {
	reg := NewContractRegistry()
	a := prodConnect("gx10", "gx10:443")
	a.Policy.Name = ""
	err := reg.Validate(a)
	if err == nil {
		t.Fatal("empty policy name was accepted; expected ErrMalformed")
	}
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("empty policy name produced %v, want ErrMalformed", err)
	}
}

// TestDecodeAndValidate_UnknownJSONKeyRejected enforces additionalProperties
// false on the Go decoder. json.Unmarshal would drop the key and pass.
func TestDecodeAndValidate_UnknownJSONKeyRejected(t *testing.T) {
	reg := NewContractRegistry()
	raw := []byte(`{"kind":"connect","params":[{"name":"gateway_id","value":"gx10"},{"name":"host","value":"gx10:443"}],"policy":{"name":"default","version":3},"surprise":true}`)
	_, err := reg.DecodeAndValidate(raw)
	if err == nil {
		t.Fatal("unknown JSON key was accepted; expected ErrMalformed")
	}
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("unknown JSON key produced %v, want ErrMalformed", err)
	}
}

// TestDecodeAndValidate_TrailingDataRejected refuses a second JSON value.
func TestDecodeAndValidate_TrailingDataRejected(t *testing.T) {
	reg := NewContractRegistry()
	raw := []byte(`{"kind":"report","policy":{"name":"default","version":3}}{"kind":"connect"}`)
	_, err := reg.DecodeAndValidate(raw)
	if err == nil {
		t.Fatal("trailing JSON value was accepted; expected ErrMalformed")
	}
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("trailing data produced %v, want ErrMalformed", err)
	}
}

// TestDecodeAndValidate_UndecodableIsMalformed pins the decode-failure class.
func TestDecodeAndValidate_UndecodableIsMalformed(t *testing.T) {
	reg := NewContractRegistry()
	_, err := reg.DecodeAndValidate([]byte(`{`))
	if err == nil {
		t.Fatal("truncated JSON was accepted")
	}
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("truncated JSON produced %v, want ErrMalformed", err)
	}
}

// TestAdmit_InvalidConnectDeniedWithAllowRule: even with AllowRule registered,
// a connect missing host must not be admitted. This is the composition that
// Evaluate alone does not provide.
func TestAdmit_InvalidConnectDeniedWithAllowRule(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.Register(ActionConnect, AllowRule()); err != nil {
		t.Fatalf("register: %v", err)
	}
	reg := NewContractRegistry()
	incomplete := &Action{
		Kind:   ActionConnect,
		Params: []Param{{Name: "gateway_id", Value: "gx10"}},
		Policy: PolicyRef{Name: "default", Version: 3},
	}
	// Evaluate alone would Allow this (AllowRule, kind registered).
	if got := e.Evaluate(context.Background(), incomplete); got != Allow {
		t.Fatalf("setup: Evaluate without schema = %v, want Allow (documents the gap Admit closes)", got)
	}
	dec, err := reg.Admit(context.Background(), e, incomplete)
	if err == nil {
		t.Fatal("Admit accepted connect missing host")
	}
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("Admit error = %v, want ErrMalformed", err)
	}
	if dec != Deny {
		t.Fatalf("Admit decision = %v, want Deny (fail closed even if error ignored)", dec)
	}
}

// TestAdmit_ValidConnectAllowedAndBannedDenied is the production connect path
// through Admit: schema-complete, then DenyGateway.
func TestAdmit_ValidConnectAllowedAndBannedDenied(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.Register(ActionConnect, DenyGateway("banned-gateway")); err != nil {
		t.Fatalf("register: %v", err)
	}
	reg := NewContractRegistry()
	ok, err := reg.Admit(context.Background(), e, prodConnect("gx10", "gx10:443"))
	if err != nil {
		t.Fatalf("Admit allowed gateway: %v", err)
	}
	if ok != Allow {
		t.Fatalf("Admit allowed gateway decision = %v, want Allow", ok)
	}
	denied, err := reg.Admit(context.Background(), e, prodConnect("banned-gateway", "banned-gateway:443"))
	if err != nil {
		t.Fatalf("Admit banned gateway unexpected error: %v", err)
	}
	if denied != Deny {
		t.Fatalf("Admit banned gateway decision = %v, want Deny", denied)
	}
}

// TestAdmit_RotateKeyOwnerPath: production schema plus RequirePrincipal.
func TestAdmit_RotateKeyOwnerPath(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.Register(ActionRotateKey, DenyRotateKeyUnlessOwner("owner")); err != nil {
		t.Fatalf("register: %v", err)
	}
	reg := NewContractRegistry()
	allow, err := reg.Admit(context.Background(), e, prodRotate("k-7", "x25519", "owner"))
	if err != nil {
		t.Fatalf("owner rotate Admit: %v", err)
	}
	if allow != Allow {
		t.Fatalf("owner rotate decision = %v, want Allow", allow)
	}
	deny, err := reg.Admit(context.Background(), e, prodRotate("k-7", "x25519", "attacker"))
	if err != nil {
		t.Fatalf("attacker rotate Admit error: %v", err)
	}
	if deny != Deny {
		t.Fatalf("attacker rotate decision = %v, want Deny", deny)
	}
	missing, err := reg.Admit(context.Background(), e, prodRotate("k-7", "x25519", ""))
	if err != nil {
		t.Fatalf("missing principal should be schema-valid: %v", err)
	}
	if missing != Deny {
		t.Fatalf("missing principal decision = %v, want Deny", missing)
	}
}

// TestAdmit_NilArgsDenied returns Deny and an error for nil registry or engine.
func TestAdmit_NilArgsDenied(t *testing.T) {
	e := NewPolicyEngine()
	reg := NewContractRegistry()
	a := prodReport()
	var nilReg *ContractRegistry
	dec, err := nilReg.Admit(context.Background(), e, a)
	if err == nil || dec != Deny {
		t.Fatalf("nil registry Admit = (%v, %v), want (Deny, error)", dec, err)
	}
	dec, err = reg.Admit(context.Background(), nil, a)
	if err == nil || dec != Deny {
		t.Fatalf("nil engine Admit = (%v, %v), want (Deny, error)", dec, err)
	}
}

// TestEvaluateValidated_NilSchemaDenied.
func TestEvaluateValidated_NilSchemaDenied(t *testing.T) {
	e := NewPolicyEngine()
	dec, err := e.EvaluateValidated(context.Background(), nil, prodReport())
	if err == nil || dec != Deny {
		t.Fatalf("nil schema EvaluateValidated = (%v, %v), want (Deny, error)", dec, err)
	}
}

// TestIsKnown_ProductionContracts pins the production kind set on the schema.
func TestIsKnown_ProductionContracts(t *testing.T) {
	s := NewSchema(productionContracts)
	for _, k := range []ActionKind{ActionConnect, ActionRotateKey, ActionReport} {
		if !s.IsKnown(k) {
			t.Fatalf("IsKnown(%q)=false, want true", k)
		}
	}
	if s.IsKnown(ActionKind("wipe_disk")) {
		t.Fatal("IsKnown(wipe_disk)=true, want false")
	}
	var nilS *ActionSchema
	if nilS.IsKnown(ActionConnect) {
		t.Fatal("nil schema IsKnown=true, want false")
	}
}

// TestValidate_ValidKindWithoutContractTakesNoParams: a kind in the closed
// set but missing from the schema map is admitted only with zero params.
func TestValidate_ValidKindWithoutContractTakesNoParams(t *testing.T) {
	s := NewSchema(map[ActionKind]ParamContract{
		ActionConnect: {Required: []string{"host"}, Allowed: []string{"host"}},
	})
	emptyReport := &Action{Kind: ActionReport, Policy: PolicyRef{Name: "default", Version: 3}}
	if err := s.Validate(emptyReport); err != nil {
		t.Fatalf("empty report without contract was rejected: %v", err)
	}
	withParam := &Action{
		Kind:   ActionReport,
		Params: []Param{{Name: "note", Value: "x"}},
		Policy: PolicyRef{Name: "default", Version: 3},
	}
	err := s.Validate(withParam)
	if err == nil {
		t.Fatal("report with params and no contract was accepted")
	}
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

// TestDecodeAndValidate_ProductionConnectRoundTrip is the happy path through
// the strict decoder, so a green here is not only the negative controls.
func TestDecodeAndValidate_ProductionConnectRoundTrip(t *testing.T) {
	reg := NewContractRegistry()
	raw, err := json.Marshal(prodConnect("gx10", "gx10:443"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := reg.DecodeAndValidate(raw)
	if err != nil {
		t.Fatalf("DecodeAndValidate: %v", err)
	}
	if got.Kind != ActionConnect {
		t.Fatalf("kind = %q, want connect", got.Kind)
	}
}
