//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublishE5PlanIsExclusiveDurableAndMode0400(t *testing.T) {
	admission := testE5Admission(t)
	receipt := validAdmittedReceipt()
	receipt.ObjectDigest = strings.Repeat("c", 64)
	receipt.AdmissionBundleSHA256 = admission.AdmissionBundleSHA256
	receipt.AdmissionBindingDigest = admission.BindingDigest
	receipt.RuntimeCollectionDigest = admission.RuntimeCollectionDigest
	receipt.ReservationObjectDigest = admission.ReservationObjectDigest
	receipt.Result.CycleID = admission.CycleID
	receipt.Result.AttemptID = admission.AttemptID
	receipt.Result.TopologyID = admission.TopologyID
	plan, encoded, err := buildE5Plan(
		minimallyShapedAdmittedConfig(t), strings.Repeat("d", 64),
		admission, receipt, 1, strings.Repeat("e", 64),
		strings.Repeat("f", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	root := privateTestDirectory(t)
	directory, err := openAdmittedPrivateDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()
	if err := publishE5Plan(directory, encoded, plan); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, e5PlanFile))
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("wrong published mode: %v %+v", err, info)
	}
	before, err := os.ReadFile(filepath.Join(root, e5PlanFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := publishE5Plan(directory, encoded, plan); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second publication did not refuse replacement: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(root, e5PlanFile))
	if err != nil || string(after) != string(before) {
		t.Fatal("failed second publication changed committed bytes")
	}
}
