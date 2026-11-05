// Command winn-real-cycle-preflight validates the E1 public evidence contract.
// It has no execution mode and grants no cloud, credential, or runtime
// authority.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

const outputSchema = "winn-real-cycle-preflight/v1"

type preflightOutput struct {
	Schema               string `json:"schema"`
	Status               string `json:"status"`
	Mode                 string `json:"mode"`
	CycleID              string `json:"cycle_id"`
	AttemptID            string `json:"attempt_id"`
	TopologyID           string `json:"topology_id"`
	BindingDigest        string `json:"binding_digest"`
	EvidenceBundleSHA256 string `json:"evidence_bundle_sha256"`
	RuntimeCount         int    `json:"runtime_count"`
	TerminalCount        int    `json:"terminal_count"`
	LiveReady            bool   `json:"live_ready"`
	CloudValidation      bool   `json:"cloud_validation"`
	TrustAcceptance      bool   `json:"trust_acceptance"`
	CredentialAuthority  bool   `json:"credential_authority"`
	TerminalAuthority    bool   `json:"terminal_authority"`
	ExecutionAuthority   bool   `json:"execution_authority"`
	ReplayReservation    bool   `json:"replay_reservation"`
	ProviderAccess       bool   `json:"provider_access"`
	CredentialAccess     bool   `json:"credential_access"`
	Mutation             string `json:"mutation"`
	Authority            bool   `json:"authority"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func run(arguments []string, output io.Writer) error {
	return runWithValidator(
		arguments, output, realcycle.ValidateBundle,
	)
}

func runWithValidator(
	arguments []string,
	output io.Writer,
	validate func(string, string, string) (realcycle.Result, error),
) error {
	flags := flag.NewFlagSet(
		"winn-real-cycle-preflight", flag.ContinueOnError,
	)
	flags.SetOutput(io.Discard)
	var evidence string
	var trust string
	var topology string
	var mode string
	flags.StringVar(
		&evidence, "evidence", "", "immutable E1 evidence directory",
	)
	flags.StringVar(
		&trust, "trust", "", "separately accepted public trust bundle",
	)
	flags.StringVar(
		&topology, "topology", "", "exact accepted E0 topology bundle",
	)
	flags.StringVar(&mode, "mode", "preflight", "only preflight is supported")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if mode != "preflight" {
		return errors.New(
			"real-cycle execution is unsupported; mode must be preflight",
		)
	}
	result, err := validate(evidence, trust, topology)
	if err != nil {
		return err
	}
	status := preflightOutput{
		Schema:               outputSchema,
		Status:               "evidence-contract-valid-nonauthorizing",
		Mode:                 "preflight",
		CycleID:              result.CycleID,
		AttemptID:            result.AttemptID,
		TopologyID:           result.TopologyID,
		BindingDigest:        result.BindingDigest,
		EvidenceBundleSHA256: result.EvidenceBundleSHA256,
		RuntimeCount:         result.RuntimeCount,
		TerminalCount:        result.TerminalCount,
		LiveReady:            false,
		CloudValidation:      false,
		TrustAcceptance:      false,
		CredentialAuthority:  false,
		TerminalAuthority:    false,
		ExecutionAuthority:   false,
		ReplayReservation:    false,
		ProviderAccess:       false,
		CredentialAccess:     false,
		Mutation:             "none",
		Authority:            false,
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(status)
}
