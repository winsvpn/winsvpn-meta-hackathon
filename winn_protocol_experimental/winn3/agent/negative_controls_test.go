package agent

import (
	"errors"
	"testing"
)

// TestNegative_UnknownKindNotInValidKinds is the negative control for the
// closed kind set. An Action whose Kind is not a member of validKinds must be
// rejected with ErrUnknownKind before any param check. This mirrors
// TestControl_UnknownKindMustBeDenied but exercises the production registry
// and the IsValidKind gate directly.
func TestNegative_UnknownKindNotInValidKinds(t *testing.T) {
	// Kind not in validKinds (closed set: connect, rotate_key, report).
	const bogus ActionKind = "erase_all_billing"
	if IsValidKind(bogus) {
		t.Fatalf("IsValidKind(%q)=true, want false (closed set is %v)", bogus, validKinds)
	}
	a := &Action{
		Kind:   bogus,
		Params: []Param{},
		Policy: PolicyRef{Name: "default", Version: 3},
	}
	// Via ActionSchema directly.
	s := NewSchema(map[ActionKind]ParamContract{
		ActionConnect: {Required: []string{"host"}, Allowed: []string{"host"}},
		ActionRotateKey: {},
		ActionReport:    {},
	})
	if err := s.Validate(a); !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("Validate unknown kind = %v, want ErrUnknownKind", err)
	}
	if _, err := s.DecodeAndValidate([]byte(`{"kind":"erase_all_billing","params":[],"policy":{"name":"default","version":3}}`)); !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("DecodeAndValidate unknown kind = %v, want ErrUnknownKind", err)
	}
	// Via production registry as well.
	reg := NewContractRegistry()
	if err := reg.Validate(a); !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("registry Validate unknown kind = %v, want ErrUnknownKind", err)
	}
}

// TestNegative_EmptyParamNameRejected is the negative control for param name
// presence. Any Action carrying a Param whose Name is the empty string must be
// rejected with ErrMalformed regardless of kind or contract. Before the fix,
// kinds with empty Allowed (report, rotate_key) accepted such params.
func TestNegative_EmptyParamNameRejected(t *testing.T) {
	cases := []struct {
		name string
		act  *Action
		raw  string
	}{
		{
			name: "report_empty_name",
			act:  &Action{Kind: ActionReport, Params: []Param{{Name: "", Value: "x"}}, Policy: PolicyRef{Name: "default", Version: 3}},
			raw:  `{"kind":"report","params":[{"name":"","value":"x"}],"policy":{"name":"default","version":3}}`,
		},
		{
			name: "rotate_key_empty_name",
			act:  &Action{Kind: ActionRotateKey, Params: []Param{{Name: "", Value: "y"}}, Policy: PolicyRef{Name: "default", Version: 3}},
			raw:  `{"kind":"rotate_key","params":[{"name":"","value":"y"}],"policy":{"name":"default","version":3}}`,
		},
		{
			name: "connect_single_empty_name",
			act:  &Action{Kind: ActionConnect, Params: []Param{{Name: "", Value: "z"}}, Policy: PolicyRef{Name: "default", Version: 3}},
			raw:  `{"kind":"connect","params":[{"name":"","value":"z"}],"policy":{"name":"default","version":3}}`,
		},
		{
			name: "connect_host_plus_empty_name",
			act:  &Action{Kind: ActionConnect, Params: []Param{{Name: "host", Value: "spain-madrid:443"}, {Name: "", Value: "evil"}}, Policy: PolicyRef{Name: "default", Version: 3}},
			raw:  `{"kind":"connect","params":[{"name":"host","value":"spain-madrid:443"},{"name":"","value":"evil"}],"policy":{"name":"default","version":3}}`,
		},
	}
	s := NewSchema(map[ActionKind]ParamContract{
		ActionConnect:   {Required: []string{"host"}, Allowed: []string{"host"}},
		ActionRotateKey: {},
		ActionReport:    {},
	})
	reg := NewContractRegistry()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := s.Validate(c.act); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Validate empty Name (%s) = %v, want ErrMalformed", c.name, err)
			}
			if _, err := s.DecodeAndValidate([]byte(c.raw)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("DecodeAndValidate empty Name (%s) = %v, want ErrMalformed", c.raw, err)
			}
			// production registry must also reject empty names for its own
			// kinds; use the act's kind against production contracts.
			if err := reg.Validate(c.act); !errors.Is(err, ErrMalformed) {
				// For connect cases the production contract also enforces
				// required/allowed, but empty-name must be the reason when
				// the schema is otherwise valid. For the "report" case the
				// old code returned nil, so this is the mutation catch.
				t.Fatalf("registry Validate empty Name (%s) = %v, want ErrMalformed", c.name, err)
			}
		})
	}
}

// TestNegative_EmptyNamePrecedesRequired ensures the empty-name check is not
// masked by a missing-required diagnostic. An action that is missing a required
// param AND carries an empty name must still be reported as ErrMalformed due
// to the empty name, not swallowed.
func TestNegative_EmptyNamePrecedesRequired(t *testing.T) {
	s := NewSchema(map[ActionKind]ParamContract{
		ActionConnect: {Required: []string{"host"}, Allowed: []string{"host"}},
	})
	// Only param is nameless, so Required host is also missing. Empty-name
	// must win.
	a := &Action{Kind: ActionConnect, Params: []Param{{Name: "", Value: "x"}}, Policy: PolicyRef{Name: "default", Version: 3}}
	err := s.Validate(a)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("empty-name+missing-required = %v, want ErrMalformed", err)
	}
	if err.Error() != "agent: action schema violation: param name empty" {
		// Pin the exact message so a future change that reorders checks is visible.
		t.Logf("note: error message is %q (expected param name empty)", err.Error())
	}
}
