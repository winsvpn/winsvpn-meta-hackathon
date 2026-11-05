// Command winn-real-cycle-admission validates the offline E2 admission
// contract. It has no execution mode and grants no runtime, provider,
// credential, reservation, or mutation authority.
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

const outputSchema = "winn-real-cycle-admission-preflight/v1"

type admissionOutput struct {
	Schema                  string `json:"schema"`
	Status                  string `json:"status"`
	Mode                    string `json:"mode"`
	CycleID                 string `json:"cycle_id"`
	AttemptID               string `json:"attempt_id"`
	TopologyID              string `json:"topology_id"`
	BindingDigest           string `json:"binding_digest"`
	AdmissionBundleSHA256   string `json:"admission_bundle_sha256"`
	RuntimeCollectionDigest string `json:"runtime_collection_digest"`
	ReservationObjectDigest string `json:"reservation_object_digest"`
	RuntimeCount            int    `json:"runtime_count"`
	ReservedTokenCount      int    `json:"reserved_token_count"`
	StartNotBefore          string `json:"start_not_before"`
	StartDeadline           string `json:"start_deadline"`
	FinishDeadline          string `json:"finish_deadline"`
	LiveReady               bool   `json:"live_ready"`
	DispatchAuthorized      bool   `json:"dispatch_authorized"`
	RuntimeAuthority        bool   `json:"runtime_authority"`
	ProviderAccess          bool   `json:"provider_access"`
	CredentialAccess        bool   `json:"credential_access"`
	ReservationMutation     bool   `json:"reservation_mutation"`
	ExecutionAuthority      bool   `json:"execution_authority"`
	CanonicalPublication    bool   `json:"canonical_publication"`
	Mutation                string `json:"mutation"`
	Authority               bool   `json:"authority"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func run(arguments []string, output io.Writer) error {
	return runWithValidator(
		arguments, output, realcycle.ValidateAdmission,
	)
}

func runWithValidator(
	arguments []string,
	output io.Writer,
	validate func(string, string, string) (realcycle.AdmissionResult, error),
) error {
	flags := flag.NewFlagSet(
		"winn-real-cycle-admission", flag.ContinueOnError,
	)
	flags.SetOutput(io.Discard)
	var admission, trust, topology, mode string
	flags.StringVar(
		&admission, "admission", "", "immutable E2 admission directory",
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
		return errors.New("execution is unsupported; preflight must equal preflight")
	}
	result, err := validate(admission, trust, topology)
	if err != nil {
		return err
	}
	status := admissionOutput{
		Schema:  outputSchema,
		Status:  "admission-contract-valid-nonauthorizing",
		Mode:    "preflight",
		CycleID: result.CycleID, AttemptID: result.AttemptID,
		TopologyID: result.TopologyID, BindingDigest: result.BindingDigest,
		AdmissionBundleSHA256:   result.AdmissionBundleSHA256,
		RuntimeCollectionDigest: result.RuntimeCollectionDigest,
		ReservationObjectDigest: result.ReservationObjectDigest,
		RuntimeCount:            result.RuntimeCount,
		ReservedTokenCount:      result.ReservedTokenCount,
		StartNotBefore:          result.StartNotBefore,
		StartDeadline:           result.StartDeadline, FinishDeadline: result.FinishDeadline,
		LiveReady: false, DispatchAuthorized: false,
		RuntimeAuthority: false, ProviderAccess: false,
		CredentialAccess: false, ReservationMutation: false,
		ExecutionAuthority: false, CanonicalPublication: false,
		Mutation: "none", Authority: false,
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(status)
}
