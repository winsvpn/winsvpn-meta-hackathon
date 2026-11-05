//go:build !unix

package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestExecRunnerNonUnixRefusesCycle(t *testing.T) {
	t.Parallel()
	result, err := (&execRunner{}).RunCycle(context.Background(), CycleRequest{})
	if !errors.Is(err, errExecRunnerUnsupported) {
		t.Fatalf("RunCycle error = %v, want %v", err, errExecRunnerUnsupported)
	}
	if !reflect.DeepEqual(result, CycleResult{}) {
		t.Fatalf("RunCycle returned nonzero result on unsupported platform: %#v", result)
	}
}

func TestAdmittedKillGroupNonUnixRefuses(t *testing.T) {
	t.Parallel()
	if err := admittedKillGroup(1); err == nil {
		t.Fatal("admitted process-group kill reported success on unsupported platform")
	}
}
