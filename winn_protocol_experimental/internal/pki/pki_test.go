package pki_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/pki"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
)

func TestGenerateLabRejectsInvalidDeviceID(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	tooLong := strings.Repeat("a", 65)
	for _, deviceID := range []string{
		"",
		"has space",
		"-leading-dash",
		".leading-dot",
		"id/slash",
		tooLong,
	} {
		out := filepath.Join(t.TempDir(), "must-not-exist")
		_, err := pki.GenerateLab(out, "localhost", deviceID, now)
		if err == nil {
			t.Errorf("deviceID %q was accepted; want invalid device ID", deviceID)
			continue
		}
		if !strings.Contains(err.Error(), "invalid device ID") {
			t.Errorf("deviceID %q error %q does not name invalid device ID", deviceID, err)
		}
		if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("deviceID %q: GenerateLab returned %v but created %s; the local ValidDeviceID gate is gone and a later checker ran after writing keys",
				deviceID, err, out)
		}
	}
}

func TestGenerateLabRejectsEmptyServerName(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	out := filepath.Join(t.TempDir(), "must-not-exist")
	_, err := pki.GenerateLab(out, "", "android-lab-1", now)
	if err == nil {
		t.Fatal("empty server name was accepted")
	}
	if !strings.Contains(err.Error(), "server name is required") {
		t.Fatalf("error %q does not name the empty server name", err)
	}
	if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("empty server name: GenerateLab returned %v but created %s", err, out)
	}
}

func TestGenerateLabRejectsNonEmptyOutputDirectory(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	marker := filepath.Join(dir, "already-there")
	if err := os.WriteFile(marker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := pki.GenerateLab(dir, "localhost", "android-lab-1", now)
	if err == nil {
		t.Fatal("non-empty output directory was accepted")
	}
	if !strings.Contains(err.Error(), "is not empty") {
		t.Fatalf("error %q does not name the non-empty directory", err)
	}
}

func TestGenerateLabHappyPathLabBundle(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	out := filepath.Join(t.TempDir(), "pki")
	const deviceID = "a..b"
	const serverName = "localhost"
	paths, err := pki.GenerateLab(out, serverName, deviceID, now)
	if err != nil {
		t.Fatal(err)
	}
	if paths.DeviceID != deviceID || paths.ServerName != serverName || paths.OutputDir != out {
		t.Fatalf("Paths identity fields: DeviceID=%q ServerName=%q OutputDir=%q",
			paths.DeviceID, paths.ServerName, paths.OutputDir)
	}

	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatal("output path is not a directory")
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("output dir perm %04o, want 0700", info.Mode().Perm())
	}

	private := map[string]string{
		"ca-key.pem":                   paths.CAKey,
		"server-key.pem":               paths.ServerKey,
		"device-key.pem":               paths.DeviceKey,
		"state.key":                    paths.StateKey,
		"audit.key":                    paths.AuditKey,
		"controller-mldsa65.seed":      paths.ControllerPQ65Seed,
		"controller-mldsa87.seed":      paths.ControllerPQ87Seed,
		"device-mldsa65.seed":          paths.DevicePQ65Seed,
		"device-mldsa87.seed":          paths.DevicePQ87Seed,
		"ech-server-keys.json":         paths.ECHServerKeys,
		"privacy-token-issuer-key.pem": paths.PrivacyTokenPrivate,
	}
	public := map[string]string{
		"ca.pem":                          paths.CACert,
		"server.pem":                      paths.ServerCert,
		"device.pem":                      paths.DeviceCert,
		"controller-mldsa65.pub":          paths.ControllerPQ65Public,
		"controller-mldsa87.pub":          paths.ControllerPQ87Public,
		"controller-pq-pins.json":         paths.ControllerPQPins,
		"device-mldsa65.pub":              paths.DevicePQ65Public,
		"device-mldsa87.pub":              paths.DevicePQ87Public,
		"device-pq-registry.json":         paths.DeviceRegistry,
		"ech-config-list.bin":             paths.ECHConfigList,
		"privacy-token-issuer-public.pem": paths.PrivacyTokenPublic,
	}
	for name, path := range private {
		assertPerm(t, path, 0o600)
		want := filepath.Join(out, name)
		if path != want {
			t.Errorf("%s path %q, want %q", name, path, want)
		}
	}
	for name, path := range public {
		assertPerm(t, path, 0o644)
		want := filepath.Join(out, name)
		if path != want {
			t.Errorf("%s path %q, want %q", name, path, want)
		}
	}

	ca := parseCert(t, paths.CACert)
	server := parseCert(t, paths.ServerCert)
	device := parseCert(t, paths.DeviceCert)
	if ca.Subject.CommonName != "Winn Protocol Experimental Lab CA" {
		t.Errorf("CA CN %q is not the lab CA name", ca.Subject.CommonName)
	}
	if !ca.IsCA || !ca.MaxPathLenZero || ca.MaxPathLen != 0 {
		t.Errorf("CA IsCA=%v MaxPathLenZero=%v MaxPathLen=%d", ca.IsCA, ca.MaxPathLenZero, ca.MaxPathLen)
	}
	if ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA is missing KeyUsageCertSign")
	}
	if server.Subject.CommonName != "Winn Protocol Experimental Controller" {
		t.Errorf("server CN %q", server.Subject.CommonName)
	}
	if len(server.DNSNames) != 1 || server.DNSNames[0] != serverName {
		t.Errorf("server DNSNames %v, want [%s]", server.DNSNames, serverName)
	}
	if len(server.IPAddresses) != 0 {
		t.Errorf("server IPAddresses %v, want none for a DNS name", server.IPAddresses)
	}
	if !hasExtKeyUsage(server, x509.ExtKeyUsageServerAuth) {
		t.Error("server cert missing ExtKeyUsageServerAuth")
	}
	if !hasExtKeyUsage(device, x509.ExtKeyUsageClientAuth) {
		t.Error("device cert missing ExtKeyUsageClientAuth")
	}
	if len(device.URIs) != 1 || device.URIs[0].String() != "spiffe://winn.local/device/"+deviceID {
		t.Errorf("device URI SAN %v, want spiffe://winn.local/device/%s", device.URIs, deviceID)
	}

	wantNotBefore := now.Add(-5 * time.Minute)
	if !ca.NotBefore.Equal(wantNotBefore) || !server.NotBefore.Equal(wantNotBefore) || !device.NotBefore.Equal(wantNotBefore) {
		t.Errorf("NotBefore ca=%s server=%s device=%s want %s", ca.NotBefore, server.NotBefore, device.NotBefore, wantNotBefore)
	}
	if !ca.NotAfter.Equal(now.AddDate(10, 0, 0)) {
		t.Errorf("CA NotAfter %s, want 10 years from now", ca.NotAfter)
	}
	if !server.NotAfter.Equal(now.AddDate(1, 0, 0)) || !device.NotAfter.Equal(now.AddDate(1, 0, 0)) {
		t.Errorf("leaf NotAfter server=%s device=%s, want 1 year from now", server.NotAfter, device.NotAfter)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := server.Verify(x509.VerifyOptions{
		Roots: roots, DNSName: serverName, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("server cert does not verify against lab CA: %v", err)
	}
	if _, err := device.Verify(x509.VerifyOptions{
		Roots: roots, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("device cert does not verify against lab CA: %v", err)
	}

	caKey := parseECKey(t, paths.CAKey)
	serverKey := parseECKey(t, paths.ServerKey)
	deviceKey := parseECKey(t, paths.DeviceKey)
	if caKey.Curve != elliptic.P384() || serverKey.Curve != elliptic.P384() || deviceKey.Curve != elliptic.P384() {
		t.Error("expected P-384 for CA, server, and device keys")
	}
	if !publicKeyMatches(ca, caKey) || !publicKeyMatches(server, serverKey) || !publicKeyMatches(device, deviceKey) {
		t.Error("a private key does not match its certificate public key")
	}

	assertLen(t, paths.StateKey, 32)
	assertLen(t, paths.AuditKey, 32)
	assertLen(t, paths.ControllerPQ65Seed, 32)
	assertLen(t, paths.ControllerPQ87Seed, 32)
	assertLen(t, paths.DevicePQ65Seed, 32)
	assertLen(t, paths.DevicePQ87Seed, 32)

	assertPQPair(t, pqauth.MLDSA65, paths.DevicePQ65Seed, paths.DevicePQ65Public)
	assertPQPair(t, pqauth.MLDSA87, paths.DevicePQ87Seed, paths.DevicePQ87Public)
	assertPQPair(t, pqauth.MLDSA65, paths.ControllerPQ65Seed, paths.ControllerPQ65Public)
	assertPQPair(t, pqauth.MLDSA87, paths.ControllerPQ87Seed, paths.ControllerPQ87Public)

	if _, err := pqauth.LoadRegistry(paths.DeviceRegistry); err != nil {
		t.Errorf("LoadRegistry: %v", err)
	}
	if _, err := pqauth.LoadVerifierSet(paths.ControllerPQPins); err != nil {
		t.Errorf("LoadVerifierSet: %v", err)
	}

	list, err := os.ReadFile(paths.ECHConfigList)
	if err != nil {
		t.Fatal(err)
	}
	if err := echconfig.ValidateConfigList(list); err != nil {
		t.Errorf("ECH config list: %v", err)
	}
	if !bytes.Contains(list, []byte("public.winn.invalid")) {
		t.Error("ECH config list does not contain the lab public name public.winn.invalid")
	}
	if _, err := echconfig.LoadServerKeys(paths.ECHServerKeys); err != nil {
		t.Errorf("LoadServerKeys: %v", err)
	}

	tokenKey, err := privacytoken.LoadIssuerPrivateKey(paths.PrivacyTokenPrivate)
	if err != nil {
		t.Errorf("LoadIssuerPrivateKey: %v", err)
	} else if tokenKey.N.BitLen() != 3072 {
		t.Errorf("privacy token RSA bit length %d, want 3072", tokenKey.N.BitLen())
	}
	if _, err := privacytoken.LoadIssuerPublicKey(paths.PrivacyTokenPublic); err != nil {
		t.Errorf("LoadIssuerPublicKey: %v", err)
	}

	_, err = pki.GenerateLab(out, serverName, deviceID, now)
	if err == nil {
		t.Fatal("second GenerateLab on the same directory was accepted")
	}
	if !strings.Contains(err.Error(), "is not empty") {
		t.Fatalf("second GenerateLab error %q does not name the non-empty directory", err)
	}
}

func TestGenerateLabIPAddressGetsIPAddressSAN(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	out := filepath.Join(t.TempDir(), "pki")
	paths, err := pki.GenerateLab(out, "127.0.0.1", "ip-device-1", now)
	if err != nil {
		t.Fatal(err)
	}
	server := parseCert(t, paths.ServerCert)
	if len(server.DNSNames) != 0 {
		t.Errorf("IP server DNSNames %v, want none", server.DNSNames)
	}
	if len(server.IPAddresses) != 1 || !server.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IP server IPAddresses %v, want 127.0.0.1", server.IPAddresses)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parseCert(t, paths.CACert))
	if _, err := server.Verify(x509.VerifyOptions{
		Roots: roots, DNSName: "127.0.0.1", CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("IP server cert does not verify: %v", err)
	}
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Errorf("stat %s: %v", filepath.Base(path), err)
		return
	}
	if info.Mode().Perm() != want {
		t.Errorf("%s perm %04o, want %04o", filepath.Base(path), info.Mode().Perm(), want)
	}
}

func assertLen(t *testing.T, path string, want int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Errorf("read %s: %v", filepath.Base(path), err)
		return
	}
	n := len(data)
	clear(data)
	if n != want {
		t.Errorf("%s length %d, want %d", filepath.Base(path), n, want)
	}
}

func parseCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cert %s: %v", filepath.Base(path), err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("%s is not a single CERTIFICATE PEM", filepath.Base(path))
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert %s: %v", filepath.Base(path), err)
	}
	return cert
}

func parseECKey(t *testing.T, path string) *ecdsa.PrivateKey {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key %s: %v", filepath.Base(path), err)
	}
	defer clear(data)
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("%s is not a single PRIVATE KEY PEM", filepath.Base(path))
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse key %s: %v", filepath.Base(path), err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("%s is not an ECDSA private key", filepath.Base(path))
	}
	return key
}

func publicKeyMatches(cert *x509.Certificate, key *ecdsa.PrivateKey) bool {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	return pub.Equal(&key.PublicKey)
}

func hasExtKeyUsage(cert *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, usage := range cert.ExtKeyUsage {
		if usage == want {
			return true
		}
	}
	return false
}

func assertPQPair(t *testing.T, algorithm, seedPath, publicPath string) {
	t.Helper()
	signer, err := pqauth.LoadSigner(algorithm, seedPath)
	if err != nil {
		t.Errorf("LoadSigner %s: %v", algorithm, err)
		return
	}
	defer signer.Destroy()
	verifier, err := pqauth.LoadVerifier(algorithm, publicPath)
	if err != nil {
		t.Errorf("LoadVerifier %s: %v", algorithm, err)
		return
	}
	if !bytes.Equal(signer.PublicBytes(), verifier.PublicBytes()) {
		t.Errorf("%s seed and public key do not form a pair", algorithm)
	}
}
