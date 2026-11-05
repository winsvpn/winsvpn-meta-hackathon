package main

import (
	"os"
	"path/filepath"
	"testing"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/conform"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
)

// The cross-host conformance adapter for the LAB RIG.
//
// The rig is not a gateway and admits everything, but it is the responder half
// of every in-tree end-to-end proof — so a rig that derived different admission
// inputs from the others would make those proofs pass while the shipping pair
// failed, which is worse than having no proof at all. It is included for
// exactly that reason and for no other.

func labrigConformanceDerivation(t *testing.T, op conform.Operator) conform.Derivation {
	t.Helper()
	dir := t.TempDir()

	static, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	staticPath := filepath.Join(dir, "static.key")
	if err := os.WriteFile(staticPath, static.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	admissionPath := filepath.Join(dir, "admission.key")
	if err := os.WriteFile(admissionPath, []byte(op.AdmissionFile), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := buildGatewaySession(gatewayOptions{
		staticPath: staticPath,
		admission:  admissionPath,
		gatewayID:  op.GatewayID,
	})
	if err != nil {
		t.Fatalf("buildGatewaySession refused the reference operator configuration: %v", err)
	}

	// The rig sizes itself at carrier.DefaultPathMTU over UDP alone and takes
	// no flag for either — main.go:201. That is a FIXED plan, so this adapter
	// reports what the rig really uses rather than what the reference asks for,
	// and the assertions below compare the halves that are comparable.
	sizing, err := driver.NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	return conform.FromCore(
		"cmd/winn3-labrig/main.go:buildGatewaySession (the in-tree responder half)",
		cfg.Core.Gateway, sizing, []string{"udp"})
}

// TestLabrigDerivesTheSameAdmissionInputsAsEveryOtherHost.
//
// Only the admission half is compared: the rig's plan and path MTU are
// hardcoded, so comparing the sizing would fail for a reason that is a design
// choice rather than a defect. Comparing the admission inputs is the part that
// has to be identical, because it is the part that decides whether the rig
// answers.
func TestLabrigDerivesTheSameAdmissionInputsAsEveryOtherHost(t *testing.T) {
	op := conform.Reference()
	want, err := conform.Expected(op)
	if err != nil {
		t.Fatal(err)
	}
	got := labrigConformanceDerivation(t, op)

	if string(got.GatewayID) != string(want.GatewayID) {
		t.Errorf("gateway_id: rig has %q (%x), the reference has %q (%x)",
			got.GatewayID, got.GatewayID, want.GatewayID, want.GatewayID)
	}
	if string(got.AdmissionKey) != string(want.AdmissionKey) {
		t.Errorf("admission key: rig has %d bytes, the reference has %d. The rig reads the "+
			"same file the gateway does and must key with the same bytes, or every in-tree "+
			"end-to-end proof passes against a responder the shipping client could not reach.",
			len(got.AdmissionKey), len(want.AdmissionKey))
	}
	if got.TagSize != want.TagSize {
		t.Errorf("tag size: rig has %d, the reference has %d", got.TagSize, want.TagSize)
	}
	if err := conform.AdmissionRoundTrip(want, got); err != nil {
		t.Error(err)
	}
}

// TestTheRigsFixedSizingIsStillFixedAndStillTheDefault.
//
// The rig takes no -path-mtu and no -plan. That is fine while its number is the
// same default every other host lands on; it stops being fine the moment either
// moves. Pinned so that a change to carrier.DefaultPathMTU does not quietly
// leave the rig sizing against a value nothing else uses.
func TestTheRigsFixedSizingIsStillFixedAndStillTheDefault(t *testing.T) {
	got := labrigConformanceDerivation(t, conform.Reference())
	if got.PathMTU != conform.DefaultPathMTU {
		t.Fatalf("the rig sizes at path MTU %d and the tree's default is %d",
			got.PathMTU, conform.DefaultPathMTU)
	}
	want, err := conform.Floor([]string{"udp"}, conform.DefaultPathMTU)
	if err != nil {
		t.Fatal(err)
	}
	if got.MessageSize != want.MessageSize || got.InnerMTU != want.InnerMTU {
		t.Fatalf("the rig plans %d/%d; udp at the default path MTU is %d/%d",
			got.MessageSize, got.InnerMTU, want.MessageSize, want.InnerMTU)
	}
	t.Logf("MEASURED rig sizing PathMTU=%d MessageSize=%d InnerMTU=%d",
		got.PathMTU, got.MessageSize, got.InnerMTU)
}
