//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"winsvpn.local/winnprotocol/internal/measurement"
)

func TestParseReadinessClassIsExact(t *testing.T) {
	for _, value := range []string{"", "Warm", "synthetic-cold"} {
		if _, err := parseReadinessClass(value); err == nil {
			t.Fatalf("readiness %q was accepted", value)
		}
	}
	for _, value := range []measurement.ReadinessClass{
		measurement.ReadinessWarm,
		measurement.ReadinessCold,
	} {
		got, err := parseReadinessClass(string(value))
		if err != nil || got != value {
			t.Fatalf(
				"readiness %q = %q, %v", value, got, err,
			)
		}
	}
}

func TestCollectBundlePathsSortsAndRejectsAliases(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"token-2.json", "token-1.json"} {
		if err := os.WriteFile(
			filepath.Join(directory, name), []byte("{}"), 0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(directory, "ignored.txt"), []byte("ignored"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	paths, err := collectBundlePaths(nil, directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 ||
		filepath.Base(paths[0]) != "token-1.json" ||
		filepath.Base(paths[1]) != "token-2.json" {
		t.Fatalf("collected bundle paths = %#v", paths)
	}
	if _, err := collectBundlePaths(
		[]string{paths[0]}, directory,
	); err == nil {
		t.Fatal("duplicate explicit/directory bundle was accepted")
	}
	link := filepath.Join(t.TempDir(), "bundles")
	if err := os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}
	if _, err := collectBundlePaths(nil, link); err == nil {
		t.Fatal("symlink bundle directory was accepted")
	}
}

func TestValidateMeasurementMetadataRejectsUnfrozenValues(t *testing.T) {
	valid := measurement.NetworkProfile{
		Interface:      "ethernet",
		IPFamily:       "ipv4",
		NAT:            "none",
		Impairment:     "baseline",
		RTTMillis:      20,
		LossFraction:   0.001,
		CapacityMbps:   1000,
		ClientRegion:   "aicore-lab",
		ServerRegion:   "aicore-lab",
		ServerProvider: "private-lab",
	}
	if err := validateMeasurementMetadata(
		"Ubuntu 24.04 LTS", "AICORE", valid,
	); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.IPFamily = "auto"
	if err := validateMeasurementMetadata(
		"Ubuntu 24.04 LTS", "AICORE", invalid,
	); err == nil {
		t.Fatal("invalid IP family was accepted")
	}
	invalid = valid
	invalid.LossFraction = 1.01
	if err := validateMeasurementMetadata(
		"Ubuntu 24.04 LTS", "AICORE", invalid,
	); err == nil {
		t.Fatal("invalid loss fraction was accepted")
	}
}
