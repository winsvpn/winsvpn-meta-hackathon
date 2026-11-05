package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/anchorfixture"
	"winsvpn.local/winnprotocol/internal/phase1anchor"
)

// TestPinToolRefusesIPv4MappedDuplicateHosts is the negative control for host
// distinctness. String inequality is not enough: 127.0.0.1 and
// ::ffff:127.0.0.1 are one machine, and two "providers" on one machine are
// not two anchors.
func TestPinToolRefusesIPv4MappedDuplicateHosts(t *testing.T) {
	bin := anchorfixture.BuildPinTool(t)
	workspace := t.TempDir()
	dummy := filepath.Join(workspace, "dummy")
	if err := os.WriteFile(dummy, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(workspace, "pending")
	command := exec.Command( // #nosec G204 -- binary this test just built
		bin,
		"-pending-directory", pending,
		"-request", dummy,
		"-ssh-key", dummy,
		"-known-hosts", dummy,
		"-provider-one-id", "provider-one",
		"-provider-one-host", "127.0.0.1",
		"-provider-one-public-key", dummy,
		"-provider-one-previous-receipt", phase1anchor.ZeroDigest,
		"-provider-two-id", "provider-two",
		"-provider-two-host", "::ffff:127.0.0.1",
		"-provider-two-public-key", dummy,
		"-provider-two-previous-receipt", phase1anchor.ZeroDigest,
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf(
			"accepted IPv4 and IPv4-mapped IPv6 as distinct providers:\n%s",
			output,
		)
	}
	if !strings.Contains(string(output), "distinct dual-provider") {
		t.Fatalf("refused for the wrong reason: %v\n%s", err, output)
	}
}

func TestParsedHostsRejectIPv4MappedAlias(t *testing.T) {
	if parsedHostsAreDistinct("127.0.0.1", "::ffff:127.0.0.1") {
		t.Fatal("IPv4-mapped address treated as a second provider")
	}
	if parsedHostsAreDistinct("127.0.0.1", "127.0.0.1") {
		t.Fatal("identical IPv4 strings treated as distinct")
	}
	if !parsedHostsAreDistinct("127.0.0.1", "127.0.0.2") {
		t.Fatal("two distinct IPv4 addresses rejected")
	}
	if parsedHostsAreDistinct("", "127.0.0.1") {
		t.Fatal("empty host accepted")
	}
	if parsedHostsAreDistinct("not-an-ip", "127.0.0.1") {
		t.Fatal("unparseable host accepted")
	}
}
