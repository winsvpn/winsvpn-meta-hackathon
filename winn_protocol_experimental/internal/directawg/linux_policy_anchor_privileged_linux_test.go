//go:build linux

package directawg

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestPrivilegedLinuxUnderlayPolicyAnchorLifecycle(t *testing.T) {
	if os.Getenv("WINN_PRIVILEGED_ANCHOR_E2E") != "1" {
		t.Skip("set WINN_PRIVILEGED_ANCHOR_E2E=1 inside a disposable network namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("privileged anchor E2E requires root in a disposable namespace")
	}
	tableName := os.Getenv("WINN_ANCHOR_E2E_TABLE")
	if !validNftIdentifier(tableName) {
		t.Fatalf("invalid or missing WINN_ANCHOR_E2E_TABLE %q", tableName)
	}
	runNft := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(
			context.Background(), 3*time.Second,
		)
		defer cancel()
		return exec.CommandContext(
			ctx, DefaultLinuxNftBinary, args...,
		).CombinedOutput()
	}
	if _, err := runNft(
		"list", "table", "inet", tableName,
	); err == nil {
		t.Fatalf("refusing to reuse nft table %s", tableName)
	}
	defer func() {
		_, _ = runNft("delete", "table", "inet", tableName)
	}()

	factory, err := NewLinuxNftResolvedPolicyFactory(
		LinuxNftResolvedPolicyConfig{
			NftBinary:         DefaultLinuxNftBinary,
			ResolvectlBinary:  DefaultLinuxResolvectlBinary,
			TempRoot:          t.TempDir(),
			TableName:         tableName,
			UnderlayInterface: "lo",
			UnderlayMark:      0x9a71,
			DNSResolver:       netip.MustParseAddr("192.0.2.53"),
			HealthInterval:    30 * time.Second,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.PrepareUnderlayPolicyAnchor(
		context.Background(),
		LinuxUnderlayPolicyAnchorSpec{
			TableFamily:           "inet",
			TableName:             tableName,
			OutputChain:           "output",
			UnderlayInterface:     "lo",
			DirectAWGUnderlayMark: 0x9a71,
			ExpiresAt:             time.Now().Add(30 * time.Second),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "chain",
			args: []string{"list", "chain", "inet", tableName, "output"},
			want: []string{
				"policy drop",
				"meta mark @underlay_marks",
				"oifname @underlay_ifaces",
			},
		},
		{
			name: "candidate-set",
			args: []string{
				"list", "set", "inet", tableName, "tunnel_ifaces",
			},
			want: []string{"type ifname"},
		},
		{
			name: "interface",
			args: []string{
				"list", "set", "inet", tableName, "underlay_ifaces",
			},
			want: []string{`"lo"`},
		},
		{
			name: "mark",
			args: []string{
				"list", "set", "inet", tableName, "underlay_marks",
			},
			want: []string{"0x00009a71"},
		},
	} {
		output, err := runNft(check.args...)
		if err != nil {
			t.Fatalf("%s readback: %v: %s", check.name, err, output)
		}
		for _, wanted := range check.want {
			if !strings.Contains(string(output), wanted) {
				t.Fatalf(
					"%s readback lacks %q:\n%s",
					check.name, wanted, output,
				)
			}
		}
	}
	if err := lease.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, setName := range []string{
		"underlay_ifaces", "underlay_marks",
	} {
		output, err := runNft(
			"list", "set", "inet", tableName, setName,
		)
		if err != nil {
			t.Fatalf("post-close %s: %v: %s", setName, err, output)
		}
		if strings.Contains(string(output), `"lo"`) ||
			strings.Contains(string(output), "0x00009a71") {
			t.Fatalf("post-close %s retains anchor:\n%s", setName, output)
		}
	}
	if err := factory.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if output, err := runNft(
		"list", "table", "inet", tableName,
	); err == nil {
		t.Fatalf("released table remains:\n%s", output)
	}
	fmt.Printf(
		"ANCHOR_E2E_PASS table=%s interface=lo mark=0x00009a71 residue=none\n",
		tableName,
	)
}
