package echconfig_test

import (
	"bytes"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/pki"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

func TestValidateConfigListRejectsGarbageAndAcceptsGenerated(t *testing.T) {
	if err := echconfig.ValidateConfigList(nil); err == nil {
		t.Fatal("ValidateConfigList(nil) succeeded")
	}
	if err := echconfig.ValidateConfigList([]byte{}); err == nil {
		t.Fatal("ValidateConfigList empty succeeded")
	}
	if err := echconfig.ValidateConfigList([]byte{0x00, 0x01, 0xff}); err == nil {
		t.Fatal("ValidateConfigList truncated succeeded")
	}
	list, _, err := echconfig.Generate("cover.example", 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := echconfig.ValidateConfigList(list); err != nil {
		t.Fatalf("generated list rejected: %v", err)
	}
}

func TestLoadClientConfigListRoundTripAndRejectsTruncated(t *testing.T) {
	list, _, err := echconfig.Generate("cover.example", 4)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ech-config-list.bin")
	if err := os.WriteFile(path, list, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := echconfig.LoadClientConfigList(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded, list) {
		t.Fatalf("loaded %d bytes, want %d", len(loaded), len(list))
	}
	if err := os.WriteFile(path, []byte{0x00, 0x01}, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := echconfig.LoadClientConfigList(path); err == nil {
		t.Fatal("truncated config list loaded")
	}
	if _, err := echconfig.LoadClientConfigList(filepath.Join(t.TempDir(), "missing.bin")); err == nil {
		t.Fatal("missing config list loaded")
	}
}

func TestLoadServerKeysRoundTripAndRejectsExtraJSON(t *testing.T) {
	_, keys, err := echconfig.Generate("cover.example", 5)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := echconfig.EncodeKeyFile(keys)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ech-server-keys.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := echconfig.LoadServerKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d keys, want 1", len(loaded))
	}
	extra := append(append([]byte{}, encoded...), []byte("{\"x\":1}\n")...)
	if err := os.WriteFile(path, extra, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := echconfig.LoadServerKeys(path); err == nil {
		t.Fatal("extra JSON accepted")
	}
}

func TestTLSKeysRejectsEmptyWrongFormatAndTooMany(t *testing.T) {
	if _, err := echconfig.TLSKeys(echconfig.KeyFile{}); err == nil {
		t.Fatal("empty key file accepted")
	}
	bogus := echconfig.KeyFile{
		Format: "not-winn-ech-key-set/v1",
		Keys:   []echconfig.KeyEntry{{Config: "YQ==", PrivateKey: "YQ=="}},
	}
	if _, err := echconfig.TLSKeys(bogus); err == nil {
		t.Fatal("wrong format accepted")
	}
	_, keys, err := echconfig.Generate("cover.example", 6)
	if err != nil {
		t.Fatal(err)
	}
	tooMany := keys
	tooMany.Keys = make([]echconfig.KeyEntry, 9)
	for i := range tooMany.Keys {
		tooMany.Keys[i] = keys.Keys[0]
	}
	if _, err := echconfig.TLSKeys(tooMany); err == nil {
		t.Fatal("9 keys accepted")
	}
}

func TestGenerateRejectsInvalidPublicName(t *testing.T) {
	for _, name := range []string{"", ".", "-bad.example", "bad-.example", "a..b.example"} {
		if _, _, err := echconfig.Generate(name, 1); err == nil {
			t.Fatalf("Generate(%q) succeeded", name)
		}
	}
}

func TestConfigureRequiredFalseDoesNotInstallAndRejectsMaterial(t *testing.T) {
	client := &tls.Config{}
	if err := echconfig.ConfigureClient(client, nil, false); err != nil {
		t.Fatal(err)
	}
	if len(client.EncryptedClientHelloConfigList) != 0 {
		t.Fatal("disabled client still received a config list")
	}
	list, keysFile, err := echconfig.Generate("cover.example", 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := echconfig.ConfigureClient(client, list, false); err == nil {
		t.Fatal("client accepted ECH material while disabled")
	}
	keys, err := echconfig.TLSKeys(keysFile)
	if err != nil {
		t.Fatal(err)
	}
	server := &tls.Config{}
	if err := echconfig.ConfigureServer(server, nil, false); err != nil {
		t.Fatal(err)
	}
	if len(server.EncryptedClientHelloKeys) != 0 {
		t.Fatal("disabled server still received keys")
	}
	if err := echconfig.ConfigureServer(server, keys, false); err == nil {
		t.Fatal("server accepted ECH keys while disabled")
	}
	if err := echconfig.ConfigureClient(nil, list, true); err == nil {
		t.Fatal("ConfigureClient(nil) succeeded")
	}
	if err := echconfig.ConfigureServer(nil, keys, true); err == nil {
		t.Fatal("ConfigureServer(nil) succeeded")
	}
	if err := echconfig.ConfigureServerCover(nil, keys); err == nil {
		t.Fatal("ConfigureServerCover(nil) succeeded")
	}
	if err := echconfig.ConfigureServerCover(&tls.Config{}, nil); err == nil {
		t.Fatal("ConfigureServerCover empty keys succeeded")
	}
}

func TestConfigureServerCoverAcceptsECHAndNonECH(t *testing.T) {
	directory := t.TempDir()
	paths, err := pki.GenerateLab(
		filepath.Join(directory, "pki"), "localhost", "ech-cover-1", time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	configList, keyFile, err := echconfig.Generate("public.winn.invalid", 11)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := echconfig.TLSKeys(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	suite, err := tlsconfig.ParseSuite("x25519-mlkem768")
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, err := tlsconfig.ServerForALPN(
		paths.ServerCert, paths.ServerKey, paths.CACert, suite, "h2",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := echconfig.ConfigureServerCover(serverConfig, keys); err != nil {
		t.Fatal(err)
	}
	echClient, err := tlsconfig.ClientForALPN(
		paths.DeviceCert, paths.DeviceKey, paths.CACert, "localhost", suite, "h2",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := echconfig.ConfigureClient(echClient, configList, true); err != nil {
		t.Fatal(err)
	}
	clientState, serverState, clientErr, serverErr := handshake(t, echClient, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("cover ECH handshake: client=%v server=%v", clientErr, serverErr)
	}
	if !clientState.ECHAccepted || !serverState.ECHAccepted {
		t.Fatalf("cover did not accept ECH: client=%v server=%v", clientState.ECHAccepted, serverState.ECHAccepted)
	}

	plainClient, err := tlsconfig.ClientForALPN(
		paths.DeviceCert, paths.DeviceKey, paths.CACert, "localhost", suite, "h2",
	)
	if err != nil {
		t.Fatal(err)
	}
	plainCS, plainSS, plainClientErr, plainServerErr := handshake(t, plainClient, serverConfig)
	if plainClientErr != nil || plainServerErr != nil {
		t.Fatalf("cover non-ECH handshake: client=%v server=%v", plainClientErr, plainServerErr)
	}
	if plainCS.ECHAccepted || plainSS.ECHAccepted {
		t.Fatal("cover treated a non-ECH client as ECH-accepted")
	}
}
