package main

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeRegistry(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "peers.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func registryKey(fill byte) ([]byte, string) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = fill
	}
	return raw, base64.StdEncoding.EncodeToString(raw)
}

func TestPeerRegistryAuthorizesOnlyTheMappedStaticKey(t *testing.T) {
	key, encoded := registryKey(0x31)
	path := writeRegistry(t, `{"version":1,"peers":[{"static_public":"`+encoded+`","inner_v4":"10.10.0.2","not_after":4102444800}]}`)
	registry, err := newPeerRegistry(path, netip.MustParsePrefix("10.10.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.authorize(key); err != nil {
		t.Fatalf("mapped key refused: %v", err)
	}
	other, _ := registryKey(0x32)
	if err := registry.authorize(other); !errors.Is(err, errPeerNotAuthorized) {
		t.Fatalf("unmapped key error = %v, want %v", err, errPeerNotAuthorized)
	}
	if got, ok := registry.innerForPeer(key); !ok || got.String() != "10.10.0.2" {
		t.Fatalf("innerForPeer = %v, %v", got, ok)
	}
}

func TestPeerRegistryReloadMakesAtomicReplacementVisible(t *testing.T) {
	first, firstEncoded := registryKey(0x41)
	second, secondEncoded := registryKey(0x42)
	path := writeRegistry(t, `{"version":1,"peers":[{"static_public":"`+firstEncoded+`","inner_v4":"10.10.0.2","not_after":4102444800}]}`)
	registry, err := newPeerRegistry(path, netip.MustParsePrefix("10.10.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(filepath.Dir(path), "replacement.json")
	if err := os.WriteFile(replacement, []byte(`{"version":1,"peers":[{"static_public":"`+secondEncoded+`","inner_v4":"10.10.0.3","not_after":4102444800}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := registry.authorize(second); err != nil {
		t.Fatalf("replacement key refused: %v", err)
	}
	if err := registry.authorize(first); !errors.Is(err, errPeerNotAuthorized) {
		t.Fatalf("retired key error = %v", err)
	}
}

// authorize must not re-parse an unchanged registry on every handshake:
// it is the AcceptFunc of every admission-passing initiation, so a full
// parse there is unauthenticated work an admission-key holder can repeat
// at will. An in-place rewrite with the identical size, mode and mtime is
// stat-identical, so the published snapshot keeps answering; only a real
// replacement (the hub's atomic rename, covered above) is re-parsed.
func TestPeerRegistryAuthorizeDoesNotReparseAnUnchangedFile(t *testing.T) {
	key, encoded := registryKey(0x45)
	body := `{"version":1,"peers":[{"static_public":"` + encoded + `","inner_v4":"10.10.0.2","not_after":4102444800}]}`
	path := writeRegistry(t, body)
	registry, err := newPeerRegistry(path, netip.MustParsePrefix("10.10.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	garbage := []byte(body)
	for i := range garbage {
		garbage[i] = 'x'
	}
	if err := os.WriteFile(path, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := registry.authorize(key); err != nil {
		t.Fatalf("authorize re-parsed a stat-identical file: %v", err)
	}
	// A changed mtime means the file changed: the garbage must now be
	// parsed, fail, and refuse every peer (fail closed).
	later := info.ModTime().Add(2 * time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	if err := registry.authorize(key); err == nil {
		t.Fatal("authorize accepted a peer from a changed, unparsable registry")
	}
}

func TestPeerRegistryExpiredBindingSelfRevokes(t *testing.T) {
	key, encoded := registryKey(0x43)
	path := writeRegistry(t, `{"version":1,"peers":[{"static_public":"`+encoded+`","inner_v4":"10.10.0.2","not_after":1}]}`)
	registry, err := newPeerRegistry(path, netip.MustParsePrefix("10.10.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.authorize(key); !errors.Is(err, errPeerNotAuthorized) {
		t.Fatalf("expired key error = %v, want %v", err, errPeerNotAuthorized)
	}
}

func TestPeerRegistryRequiresExplicitExpirySemantics(t *testing.T) {
	_, encoded := registryKey(0x44)
	path := writeRegistry(t, `{"version":1,"peers":[{"static_public":"`+encoded+`","inner_v4":"10.10.0.2"}]}`)
	if _, err := newPeerRegistry(path, netip.MustParsePrefix("10.10.0.0/24")); err == nil {
		t.Fatal("accepted a binding with missing not_after")
	}
}

func TestPeerRegistryRejectsDuplicateKeysAndAddresses(t *testing.T) {
	_, keyA := registryKey(0x51)
	_, keyB := registryKey(0x52)
	cases := []string{
		`{"version":1,"peers":[{"static_public":"` + keyA + `","inner_v4":"10.10.0.2","not_after":4102444800},{"static_public":"` + keyA + `","inner_v4":"10.10.0.3","not_after":4102444800}]}`,
		`{"version":1,"peers":[{"static_public":"` + keyA + `","inner_v4":"10.10.0.2","not_after":4102444800},{"static_public":"` + keyB + `","inner_v4":"10.10.0.2","not_after":4102444800}]}`,
	}
	for _, body := range cases {
		if _, err := newPeerRegistry(writeRegistry(t, body), netip.MustParsePrefix("10.10.0.0/24")); err == nil {
			t.Fatalf("accepted ambiguous registry %s", body)
		}
	}
}

func TestPeerRegistryRejectsAddressesOutsideUsablePool(t *testing.T) {
	_, key := registryKey(0x61)
	for _, address := range []string{"10.9.0.2", "10.10.0.0", "10.10.0.255", "10.10.0.02"} {
		body := `{"version":1,"peers":[{"static_public":"` + key + `","inner_v4":"` + address + `","not_after":4102444800}]}`
		if _, err := newPeerRegistry(writeRegistry(t, body), netip.MustParsePrefix("10.10.0.0/24")); err == nil {
			t.Fatalf("accepted unusable address %s", address)
		}
	}
}

func TestPeerRegistryRejectsTheGatewayAddress(t *testing.T) {
	_, key := registryKey(0x62)
	body := `{"version":1,"peers":[{"static_public":"` + key + `","inner_v4":"10.10.0.1","not_after":4102444800}]}`
	if _, err := newPeerRegistry(
		writeRegistry(t, body), netip.MustParsePrefix("10.10.0.0/24"), netip.MustParseAddr("10.10.0.1"),
	); err == nil {
		t.Fatal("accepted the gateway's own address as a client binding")
	}
}

func TestForwardDeviceWithRegistryFailsClosedWithoutAuthenticatedPeer(t *testing.T) {
	_, encoded := registryKey(0x71)
	path := writeRegistry(t, `{"version":1,"peers":[{"static_public":"`+encoded+`","inner_v4":"10.10.0.2","not_after":4102444800}]}`)
	registry, err := newPeerRegistry(path, netip.MustParsePrefix("10.10.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	writer := &fakeInnerWriter{}
	dev := newGatewayForwardDevice(writer, newForwardTable(), 1400, registry)
	dev.bind(fakeLoop())
	if _, err := dev.WritePacket(ipv4Packet(t, "10.10.0.2", "8.8.8.8")); !errors.Is(err, errGatewayPeerUnauthorized) {
		t.Fatalf("unauthenticated loop error = %v", err)
	}
	if len(writer.written) != 0 {
		t.Fatal("unauthenticated packet reached the kernel writer")
	}
}

func TestForwardDeviceRejectsAuthenticatedPeerUsingAnotherIssuedAddress(t *testing.T) {
	key, encoded := registryKey(0x72)
	path := writeRegistry(t, `{"version":1,"peers":[{"static_public":"`+encoded+`","inner_v4":"10.10.0.2","not_after":4102444800}]}`)
	registry, err := newPeerRegistry(path, netip.MustParsePrefix("10.10.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	dev := newGatewayForwardDevice(&fakeInnerWriter{}, newForwardTable(), 1400, registry)
	if _, err := dev.validatePeerSource(key, netip.MustParseAddr("10.10.0.3")); !errors.Is(err, errGatewayInnerSourceMismatch) {
		t.Fatalf("wrong issued address error = %v, want %v", err, errGatewayInnerSourceMismatch)
	}
	if _, err := dev.validatePeerSource(key, netip.MustParseAddr("10.10.0.2")); err != nil {
		t.Fatalf("correct key/address binding refused: %v", err)
	}
}

func TestForwardDeviceRejectsUnknownAuthenticatedPeer(t *testing.T) {
	_, encoded := registryKey(0x73)
	unknown, _ := registryKey(0x74)
	path := writeRegistry(t, `{"version":1,"peers":[{"static_public":"`+encoded+`","inner_v4":"10.10.0.2","not_after":4102444800}]}`)
	registry, err := newPeerRegistry(path, netip.MustParsePrefix("10.10.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	dev := newGatewayForwardDevice(&fakeInnerWriter{}, newForwardTable(), 1400, registry)
	if _, err := dev.validatePeerSource(unknown, netip.MustParseAddr("10.10.0.2")); !errors.Is(err, errGatewayPeerUnauthorized) {
		t.Fatalf("unknown peer error = %v, want %v", err, errGatewayPeerUnauthorized)
	}
}
