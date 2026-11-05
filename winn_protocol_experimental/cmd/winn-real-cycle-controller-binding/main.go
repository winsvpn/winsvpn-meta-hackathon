// Command winn-real-cycle-controller-binding validates E2 and emits one
// canonical, nonauthorizing E3 controller-cycle binding. It has no run mode.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func run(arguments []string, output io.Writer) error {
	return runWith(
		arguments,
		output,
		realcycle.LoadControllerBindingInput,
		realcycle.ValidateAdmission,
	)
}

func runWith(
	arguments []string,
	output io.Writer,
	loadInput func(string) (realcycle.ControllerBindingInput, error),
	validateAdmission func(
		string, string, string,
	) (realcycle.AdmissionResult, error),
) error {
	flags := flag.NewFlagSet(
		"winn-real-cycle-controller-binding", flag.ContinueOnError,
	)
	flags.SetOutput(io.Discard)
	var admissionPath, trustPath, topologyPath, contractPath, mode string
	flags.StringVar(&admissionPath, "admission", "", "immutable E2 admission directory")
	flags.StringVar(&trustPath, "trust", "", "separately accepted public trust bundle")
	flags.StringVar(&topologyPath, "topology", "", "exact accepted E0 topology bundle")
	flags.StringVar(
		&contractPath, "controller-contract", "",
		"canonical public controller contract JSON",
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
	if contractPath == "" {
		return errors.New("controller-contract is required")
	}
	input, err := loadInput(contractPath)
	if err != nil {
		return err
	}
	admission, err := validateAdmission(
		admissionPath, trustPath, topologyPath,
	)
	if err != nil {
		return err
	}
	_, bindingBytes, err := realcycle.NewControllerCycleBinding(admission, input)
	if err != nil {
		return err
	}
	written, err := output.Write(bindingBytes)
	if err != nil {
		return err
	}
	if written != len(bindingBytes) {
		return errors.New("short write of controller cycle binding")
	}
	return nil
}
