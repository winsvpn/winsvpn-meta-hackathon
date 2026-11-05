package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func validEnvironment() []string {
	return []string{
		"READINESS=warm",
		"WINN_SOAK_CYCLE_SEQUENCE=1",
		"WINN_SOAK_FIXTURE=success-v1",
		"WINN_SOAK_INSTANCE_NONCE=0123456789abcdef0123456789abcdef",
		"WINN_SOAK_RUN_ID=micro-soak-1",
	}
}

func TestValidateEnvironmentAcceptsExactContract(t *testing.T) {
	values, err := validateEnvironment(validEnvironment())
	if err != nil {
		t.Fatalf("valid environment refused: %v", err)
	}
	if values["READINESS"] != "warm" {
		t.Fatalf("readiness = %q, want warm", values["READINESS"])
	}
}

func TestValidateEnvironmentAcceptsColdAndLaterSequence(t *testing.T) {
	environment := validEnvironment()
	environment[0] = "READINESS=cold"
	environment[1] = "WINN_SOAK_CYCLE_SEQUENCE=42"
	if _, err := validateEnvironment(environment); err != nil {
		t.Fatalf("cold environment refused: %v", err)
	}
}

func TestValidateEnvironmentRejectsContractDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]string) []string
	}{
		{
			name: "unknown variable",
			mutate: func(environment []string) []string {
				return append(environment, "PATH=/usr/bin")
			},
		},
		{
			name: "missing variable",
			mutate: func(environment []string) []string {
				return environment[1:]
			},
		},
		{
			name: "duplicate variable",
			mutate: func(environment []string) []string {
				return append(environment, environment[0])
			},
		},
		{
			name: "bad readiness",
			mutate: func(environment []string) []string {
				environment[0] = "READINESS=lukewarm"
				return environment
			},
		},
		{
			name: "zero sequence",
			mutate: func(environment []string) []string {
				environment[1] = "WINN_SOAK_CYCLE_SEQUENCE=0"
				return environment
			},
		},
		{
			name: "noncanonical sequence",
			mutate: func(environment []string) []string {
				environment[1] = "WINN_SOAK_CYCLE_SEQUENCE=01"
				return environment
			},
		},
		{
			name: "bad fixture version",
			mutate: func(environment []string) []string {
				environment[2] = "WINN_SOAK_FIXTURE=success-v2"
				return environment
			},
		},
		{
			name: "bad nonce",
			mutate: func(environment []string) []string {
				environment[3] = "WINN_SOAK_INSTANCE_NONCE=ABC"
				return environment
			},
		},
		{
			name: "bad run id",
			mutate: func(environment []string) []string {
				environment[4] = "WINN_SOAK_RUN_ID=has/slash"
				return environment
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := append([]string(nil), validEnvironment()...)
			_, err := validateEnvironment(test.mutate(environment))
			if err == nil {
				t.Fatal("invalid environment accepted")
			}
			if strings.Contains(err.Error(), "0123456789abcdef") {
				t.Fatalf("error leaked a nonce value: %v", err)
			}
		})
	}
}

func TestChildInvocationIsExact(t *testing.T) {
	if !isChildInvocation([]string{"/proc/self/exe", "--child"}) {
		t.Fatal("exact child invocation was not recognized")
	}
	for _, arguments := range [][]string{
		nil,
		{"/proc/self/exe"},
		{"/proc/self/exe", "--child", "extra"},
		{"/proc/self/exe", "--other"},
	} {
		if isChildInvocation(arguments) {
			t.Fatalf("non-child invocation was accepted: %q", arguments)
		}
	}
}

func TestRunFixtureUsesOneChildAndEmitsExactResult(t *testing.T) {
	childCalls := 0
	var output bytes.Buffer
	err := runFixture(
		validEnvironment(),
		func() error {
			childCalls++
			return nil
		},
		&output,
	)
	if err != nil {
		t.Fatalf("run fixture: %v", err)
	}
	if childCalls != 1 {
		t.Fatalf("child calls = %d, want 1", childCalls)
	}
	var result fixtureResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	want := fixtureResult{
		Schema:    "winn-phase1-soak-success-fixture/v1",
		RunID:     "micro-soak-1",
		Sequence:  1,
		Readiness: "warm",
		ChildExit: 0,
	}
	if result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
	if output.String()[output.Len()-1] != '\n' {
		t.Fatal("output is not newline terminated")
	}
}

func TestRunFixtureFailsClosedOnChildError(t *testing.T) {
	var output bytes.Buffer
	err := runFixture(
		validEnvironment(),
		func() error { return errors.New("synthetic failure") },
		&output,
	)
	if err == nil || !strings.Contains(err.Error(), "self child failed") {
		t.Fatalf("child error = %v, want self child failure", err)
	}
	if output.Len() != 0 {
		t.Fatalf("child failure emitted output: %q", output.String())
	}
}
