// Command winn-real-topology-verify performs the E0 structural-only external
// topology preflight. It cannot run a topology and grants no runtime authority.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"winsvpn.local/winnprotocol/internal/realtopology"
)

type preflightOutput struct {
	Schema              string `json:"schema"`
	Status              string `json:"status"`
	Mode                string `json:"mode"`
	TopologyID          string `json:"topology_id"`
	DescriptorSHA256    string `json:"descriptor_sha256"`
	BundleSHA256        string `json:"bundle_sha256"`
	PublicFileCount     int    `json:"public_file_count"`
	LiveReady           bool   `json:"live_ready"`
	ExercisedNodeCount  int    `json:"exercised_node_count"`
	SignatureValidation bool   `json:"signature_validation"`
	TrustValidation     bool   `json:"trust_validation"`
	RuntimeValidation   bool   `json:"runtime_validation"`
	Mutation            string `json:"mutation"`
	Authority           bool   `json:"authority"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func run(arguments []string, output io.Writer) error {
	return runWithValidator(
		arguments, output, realtopology.ValidateBundle,
	)
}

func runWithValidator(
	arguments []string,
	output io.Writer,
	validate func(string) (realtopology.Result, error),
) error {
	if output == nil {
		return errors.New("output writer is required")
	}
	flags := flag.NewFlagSet("winn-real-topology-verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var bundle string
	var mode string
	flags.StringVar(&bundle, "bundle", "", "public external topology bundle")
	flags.StringVar(&mode, "mode", "preflight", "only preflight is supported")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if mode != "preflight" {
		return errors.New(
			"external topology execution is unsupported; mode must be preflight",
		)
	}
	result, err := validate(bundle)
	if err != nil {
		return err
	}
	encoded := preflightOutput{
		Schema:              realtopology.PreflightStatusSchema,
		Status:              "structurally-valid-nonauthorizing",
		Mode:                "preflight",
		TopologyID:          result.TopologyID,
		DescriptorSHA256:    result.DescriptorSHA256,
		BundleSHA256:        result.BundleSHA256,
		PublicFileCount:     result.PublicFileCount,
		LiveReady:           false,
		ExercisedNodeCount:  0,
		SignatureValidation: false,
		TrustValidation:     false,
		RuntimeValidation:   false,
		Mutation:            "none",
		Authority:           false,
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(encoded)
}
