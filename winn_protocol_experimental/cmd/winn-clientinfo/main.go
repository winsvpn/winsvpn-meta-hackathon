// Command winn-clientinfo exposes package clientbinding as a single-shot,
// line-oriented JSON subprocess.
//
// It exists because that is the shape Win's VPN already ships Go engines in:
// windows/awg_engine builds to winsvpn_awg_engine.exe, and tools/build_xray_
// engine.sh cross-compiles a Go binary that Android stages into jniLibs and
// runs from nativeLibraryDir. Both are plain Go executables with CGO_ENABLED=0
// off the Apple targets, which is exactly why they cross-compile to every
// architecture from one host with no C toolchain.
//
// Every subcommand writes one JSON value to stdout (object, array, or string)
// and nothing else. Operational errors and unknown subcommands write
// {"error": "..."} and exit 1. validate-* writes {"valid": true} and exits 0
// when the input is valid, or {"valid": false, "error": "..."} and exits 1
// when it is not. A caller that only inspects the process exit code therefore
// cannot mistake an invalid document for a successful validation. A failed
// write to stdout is itself an error (exit 1), never a silent success.
//
// This binary reports and validates. It cannot connect: no platform tunnel
// provider exists for Winn v3 outside Linux, and "backend" reports that.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"winsvpn.local/winnprotocol/clientbinding"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: winn-clientinfo <backend|versions|suites|modes|capabilities|auth-algorithm|carriers|validate-readiness|validate-binding|validate-device-id|validate-peer-key>")
	}
	argument := ""
	if len(os.Args) > 2 {
		argument = os.Args[2]
	}

	switch os.Args[1] {
	case "backend":
		emit(clientbinding.TunnelBackendJSON())
	case "versions":
		emitValue(map[string]any{
			"binding":                clientbinding.FacadeVersion(),
			"protocol_version":       clientbinding.ProtocolVersion(),
			"rekey_protocol_version": clientbinding.RekeyProtocolVersion(),
			"tunnel_supported":       clientbinding.TunnelSupported(),
		})
	case "suites":
		emit(clientbinding.SupportedSuitesJSON())
	case "modes":
		emit(clientbinding.SupportedModesJSON())
	case "capabilities":
		encoded, err := clientbinding.CapabilitiesJSON(argument)
		emitResult(encoded, err)
	case "auth-algorithm":
		algorithm, err := clientbinding.RequiredAuthAlgorithm(argument)
		emitResult(fmt.Sprintf("%q", algorithm), err)
	case "carriers":
		encoded, err := clientbinding.CarriersForModeJSON(argument)
		emitResult(encoded, err)
	case "validate-readiness":
		emitCheck(clientbinding.ValidateReadinessJSON(readInput(argument)))
	case "validate-binding":
		emitCheck(clientbinding.ValidateBindingJSON(readInput(argument)))
	case "validate-device-id":
		emitCheck(clientbinding.ValidateDeviceID(argument))
	case "validate-peer-key":
		emitCheck(clientbinding.ValidatePeerPublicKey(argument))
	default:
		fail("unknown subcommand " + os.Args[1])
	}
}

// readInput treats "-" as stdin so a caller never has to put a readiness
// document on a command line where it would land in process listings.
// os.Stdin is required because windows-amd64 is a first-class build target
// of tools/build_winn_protocol_engine.sh and /dev/stdin does not exist there.
func readInput(argument string) string {
	if argument != "-" {
		return argument
	}
	document, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail(err.Error())
	}
	return string(document)
}

func emit(document string) {
	writeStdout(document, 0)
}

func emitValue(value any) {
	emitValueWithStatus(value, 0)
}

func emitValueWithStatus(value any, code int) {
	encoded, err := json.Marshal(value)
	if err != nil {
		fail(err.Error())
	}
	writeStdout(string(encoded), code)
}

func emitResult(document string, err error) {
	if err != nil {
		fail(err.Error())
	}
	emit(document)
}

func emitCheck(err error) {
	if err != nil {
		emitValueWithStatus(map[string]any{"valid": false, "error": err.Error()}, 1)
	}
	emitValue(map[string]any{"valid": true})
}

func writeStdout(document string, code int) {
	if _, err := fmt.Fprintln(os.Stdout, document); err != nil {
		os.Exit(1)
	}
	os.Exit(code)
}

func fail(message string) {
	encoded, err := json.Marshal(map[string]string{"error": message})
	if err != nil {
		_, _ = fmt.Fprintln(os.Stdout, `{"error":"encode failed"}`)
		os.Exit(1)
	}
	if _, err := fmt.Fprintln(os.Stdout, string(encoded)); err != nil {
		os.Exit(1)
	}
	os.Exit(1)
}
