package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/securefile"
)

func TestSplitListAcceptsSingleAndMultiple(t *testing.T) {
	got, err := splitList("10.228.0.0/23")
	if err != nil {
		t.Fatalf("single prefix refused: %v", err)
	}
	if len(got) != 1 || got[0] != "10.228.0.0/23" {
		t.Fatalf("single prefix = %#v", got)
	}
	got, err = splitList("10.228.0.0/23, 10.228.2.0/24")
	if err != nil {
		t.Fatalf("two prefixes refused: %v", err)
	}
	if len(got) != 2 || got[0] != "10.228.0.0/23" || got[1] != "10.228.2.0/24" {
		t.Fatalf("two prefixes = %#v", got)
	}
}

func TestSplitListRefusesEmptyEntries(t *testing.T) {
	for _, value := range []string{",", "10.228.0.0/23,", ",10.228.0.0/23", "10.228.0.0/23,,10.228.2.0/24", "  "} {
		got, err := splitList(value)
		if err == nil {
			t.Fatalf("empty-entry list %q was accepted as %#v", value, got)
		}
		if !strings.Contains(err.Error(), "empty entry") {
			t.Fatalf("empty-entry list %q error %q does not name empty entry", value, err)
		}
	}
}

func TestReadBase64SecretAccepts32Bytes(t *testing.T) {
	path := writePrivateSecret(t, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x03}, 32)))
	got, err := readBase64Secret(path)
	if err != nil {
		t.Fatalf("valid 32-byte secret refused: %v", err)
	}
	defer clear(got)
	if len(got) != 32 {
		t.Fatalf("decoded length %d, want 32", len(got))
	}
	for _, b := range got {
		if b != 0x03 {
			t.Fatal("decoded secret bytes do not match the written value")
		}
	}
}

func TestReadBase64SecretRefusesWrongLength(t *testing.T) {
	path := writePrivateSecret(t, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x03}, 31)))
	got, err := readBase64Secret(path)
	clear(got)
	if err == nil {
		t.Fatal("31-byte secret was accepted")
	}
	if !strings.Contains(err.Error(), "32-byte") {
		t.Fatalf("wrong-length error %q does not name 32-byte", err)
	}
}

func TestReadBase64SecretRefusesInvalidBase64(t *testing.T) {
	path := writePrivateSecret(t, "not-valid-base64!!!")
	got, err := readBase64Secret(path)
	clear(got)
	if err == nil {
		t.Fatal("invalid base64 was accepted")
	}
}

func TestValidateListenPortRangeMatchesLinuxProfile(t *testing.T) {
	if err := validateListenPortRange(61000, 61100); err != nil {
		t.Fatalf("default range refused: %v", err)
	}
	if err := validateListenPortRange(1024, 1025); err != nil {
		t.Fatalf("minimum legal two-port range refused: %v", err)
	}
	for _, tc := range []struct {
		min, max int
		name     string
	}{
		{1, 2, "privileged floor"},
		{61000, 61000, "single port"},
		{61100, 61000, "max below min"},
		{1024, 70000, "max above 65535"},
		{0, 1025, "zero floor"},
	} {
		if err := validateListenPortRange(tc.min, tc.max); err == nil {
			t.Fatalf("%s range [%d, %d] was accepted", tc.name, tc.min, tc.max)
		}
	}
}

func TestRefuseBootstrapDigestMismatchNamesBothDigests(t *testing.T) {
	if err := refuseBootstrapDigestMismatch("abc", "abc"); err != nil {
		t.Fatalf("matching digests refused: %v", err)
	}
	err := refuseBootstrapDigestMismatch("deadbeef", "cafebabe")
	if err == nil {
		t.Fatal("mismatched digests were accepted")
	}
	text := err.Error()
	if !strings.Contains(text, "digest mismatch") {
		t.Fatalf("error %q does not say digest mismatch", text)
	}
	if !strings.Contains(text, "deadbeef") || !strings.Contains(text, "cafebabe") {
		t.Fatalf("error %q does not name both digests", text)
	}
	if strings.Contains(text, "<nil>") {
		t.Fatalf("error %q still collapses to <nil>", text)
	}
}

func TestRunRefusesMissingRequiredFlag(t *testing.T) {
	err := run(nil, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("empty argv was accepted")
	}
	if !strings.Contains(err.Error(), "is required") {
		t.Fatalf("empty argv error %q does not name a required flag", err)
	}
}

func TestRunRefusesEmptyAllowedIPsEntry(t *testing.T) {
	args := validFlagArgs(t, t.TempDir())
	replaceFlag(args, "-allowed-ips", "10.228.0.0/23,")
	err := run(args, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("trailing-comma allowed-ips was accepted")
	}
	if !strings.Contains(err.Error(), "allowed-ips") {
		t.Fatalf("error %q does not name allowed-ips", err)
	}
	if !strings.Contains(err.Error(), "empty entry") {
		t.Fatalf("error %q does not name empty entry", err)
	}
}

func TestRunRefusesPrivilegedListenPort(t *testing.T) {
	args := validFlagArgs(t, t.TempDir())
	args = append(args, "-listen-port-min", "1", "-listen-port-max", "2")
	err := run(args, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("privileged listen-port range was accepted")
	}
	if !strings.Contains(err.Error(), "listen-port") {
		t.Fatalf("error %q does not name listen-port", err)
	}
}

func TestRunRefusesZeroLifetime(t *testing.T) {
	args := validFlagArgs(t, t.TempDir())
	args = append(args, "-lifetime", "0")
	err := run(args, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("zero lifetime was accepted")
	}
	if !strings.Contains(err.Error(), "lifetime") {
		t.Fatalf("error %q does not name lifetime", err)
	}
}

func TestRunRefusesHelpAsSuccessNotCrash(t *testing.T) {
	err := run([]string{"-h"}, io.Discard, io.Discard)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help error = %v, want flag.ErrHelp", err)
	}
}

func TestRunBuildsPrivateFixture(t *testing.T) {
	root := t.TempDir()
	materials := writeFixtureMaterials(t, root)
	out := filepath.Join(root, "fixture-out")
	args := validFlagArgs(t, out)
	replaceFlag(args, "-controller-pq-seed", materials.seedPath)
	replaceFlag(args, "-controller-pq-pins", materials.pinsPath)
	replaceFlag(args, "-privacy-token-public-key", materials.tokenPath)
	replaceFlag(args, "-ech-config-list", materials.echPath)
	replaceFlag(args, "-psk-file", materials.pskPath)

	var stdout bytes.Buffer
	if err := run(args, io.Discard, &stdout); err != nil {
		t.Fatalf("valid fixture run refused: %v", err)
	}

	var summary fixtureSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("stdout is not fixture JSON: %v", err)
	}
	if summary.Format != fixtureFormat {
		t.Fatalf("format %q, want %q", summary.Format, fixtureFormat)
	}
	if summary.ProtocolVersion != "winn/3" {
		t.Fatalf("protocol_version %q, want winn/3", summary.ProtocolVersion)
	}
	if summary.ManifestDigest == "" || len(summary.ManifestDigest) != 64 {
		t.Fatalf("manifest_digest length %d, want 64 hex chars", len(summary.ManifestDigest))
	}
	for _, path := range []string{
		summary.ManifestPath,
		summary.TransparencyLog,
		summary.TrustStatePath,
		summary.LinuxProfilePath,
		summary.RotationStatePath,
		summary.AppliedPSKPath,
		filepath.Join(out, "fixture.json"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("expected output missing %s: %v", filepath.Base(path), err)
		}
		if info.Size() == 0 {
			t.Fatalf("expected output empty: %s", filepath.Base(path))
		}
	}
	dirInfo, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm()&0o077 != 0 {
		t.Fatalf("fixture directory mode %04o allows group/other access", dirInfo.Mode().Perm())
	}
}

func writePrivateSecret(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := securefile.AtomicWrite(path, []byte(contents+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func validGatewayPublicKey() string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x03}, 32))
}

func validFlagArgs(t *testing.T, out string) []string {
	t.Helper()
	dummy := filepath.Join(t.TempDir(), "missing")
	return []string{
		"-out", out,
		"-controller-pq-seed", dummy,
		"-controller-pq-pins", dummy,
		"-privacy-token-public-key", dummy,
		"-ech-config-list", dummy,
		"-psk-file", dummy,
		"-controller-id", "controller-auto",
		"-device-id", "device-auto",
		"-node-id", "node-auto",
		"-direct-endpoint", "192.0.2.10:51820",
		"-masque-template", "https://carrier.winn.test:42443/.well-known/masque/udp/{target_host}/{target_port}/",
		"-server-name", "carrier.winn.test",
		"-ipv4-hint", "192.0.2.10",
		"-fixed-backend", "192.0.2.10:51820",
		"-gateway-public-key", validGatewayPublicKey(),
		"-inner-address-pool", "10.228.1.0/24",
		"-allowed-ips", "10.228.0.0/23",
		"-verification-routes", "10.228.0.0/24",
		"-dns-resolver", "10.228.0.2:5500",
		"-expected-dns-answers", "203.0.113.228",
		"-canary-endpoint", "10.228.0.2:5501",
	}
}

func replaceFlag(args []string, name, value string) {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == name {
			args[i+1] = value
			return
		}
	}
	panic("flag not present: " + name)
}

type fixtureMaterials struct {
	seedPath  string
	pinsPath  string
	tokenPath string
	echPath   string
	pskPath   string
}

func writeFixtureMaterials(t *testing.T, root string) fixtureMaterials {
	t.Helper()
	seed := bytes.Repeat([]byte{0x31}, 32)
	signer, err := pqauth.NewSigner(pqauth.MLDSA65, seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.AtomicWrite(
		filepath.Join(root, "controller.seed"), seed, 0o600,
	); err != nil {
		t.Fatal(err)
	}
	clear(seed)

	document, err := pqauth.VerifierSetDocument(signer)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.AtomicWrite(
		filepath.Join(root, "controller-pins.json"), pins, 0o644,
	); err != nil {
		t.Fatal(err)
	}

	issuer, err := privacytoken.GenerateIssuerKey(3072)
	if err != nil {
		t.Fatal(err)
	}
	_, publicPEM, err := privacytoken.MarshalIssuerKeys(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.AtomicWrite(
		filepath.Join(root, "token.pub"), publicPEM, 0o644,
	); err != nil {
		t.Fatal(err)
	}

	echList, _, err := echconfig.Generate("carrier.winn.test", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.AtomicWrite(
		filepath.Join(root, "ech.bin"), echList, 0o644,
	); err != nil {
		t.Fatal(err)
	}

	psk := bytes.Repeat([]byte{0x05}, 32)
	encodedPSK := []byte(base64.StdEncoding.EncodeToString(psk) + "\n")
	clear(psk)
	if err := securefile.AtomicWrite(
		filepath.Join(root, "current.psk"), encodedPSK, 0o600,
	); err != nil {
		t.Fatal(err)
	}

	return fixtureMaterials{
		seedPath:  filepath.Join(root, "controller.seed"),
		pinsPath:  filepath.Join(root, "controller-pins.json"),
		tokenPath: filepath.Join(root, "token.pub"),
		echPath:   filepath.Join(root, "ech.bin"),
		pskPath:   filepath.Join(root, "current.psk"),
	}
}
