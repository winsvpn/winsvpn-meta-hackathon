//go:build !linux && !darwin

package main

import (
	"fmt"
	"os"
)

// probeMount reports that this platform cannot answer.
//
// It deliberately does not return an error. An unsupported platform is not a
// probe failure, and the distinction matters downstream: config.go refuses to
// start a soak where the free-space gate cannot be evaluated, and it refuses
// with "this platform cannot enforce the gate" rather than with a syscall
// error that suggests a transient problem worth retrying.
func probeMount(string) (mountFacts, error) {
	return mountFacts{Available: false}, nil
}

// probeMountDescriptor fails closed on platforms without an fd-bound
// filesystem probe. Falling back to the pathname would reintroduce the
// replacement race this controller is designed to exclude.
func probeMountDescriptor(*os.File) (mountFacts, error) {
	return mountFacts{}, fmt.Errorf(
		"this platform cannot inspect snapshot mounts through a held descriptor",
	)
}
