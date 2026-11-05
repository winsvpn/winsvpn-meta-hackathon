package echconfig_test

import (
	"crypto/tls"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/pki"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

func TestRequiredECHHandshakeSucceedsAndRejectsDowngrade(t *testing.T) {
	directory := t.TempDir()
	paths, err := pki.GenerateLab(
		filepath.Join(directory, "pki"), "localhost", "ech-device-1", time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	configList, keyFile, err := echconfig.Generate("public.winn.invalid", 7)
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
	if err := echconfig.ConfigureServer(serverConfig, keys, true); err != nil {
		t.Fatal(err)
	}
	clientConfig, err := tlsconfig.ClientForALPN(
		paths.DeviceCert, paths.DeviceKey, paths.CACert, "localhost", suite, "h2",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := echconfig.ConfigureClient(clientConfig, configList, true); err != nil {
		t.Fatal(err)
	}
	clientState, serverState, clientErr, serverErr := handshake(t, clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("ECH handshake: client=%v server=%v", clientErr, serverErr)
	}
	if !clientState.ECHAccepted || !serverState.ECHAccepted {
		t.Fatalf("ECH not accepted: client=%v server=%v", clientState.ECHAccepted, serverState.ECHAccepted)
	}

	downgraded, err := tlsconfig.ClientForALPN(
		paths.DeviceCert, paths.DeviceKey, paths.CACert, "localhost", suite, "h2",
	)
	if err != nil {
		t.Fatal(err)
	}
	_, _, downgradedErr, rejectedErr := handshake(t, downgraded, serverConfig)
	if rejectedErr == nil {
		t.Fatalf("server accepted a client that omitted required ECH (client=%v)", downgradedErr)
	}
	if !strings.Contains(rejectedErr.Error(), "Encrypted Client Hello") {
		t.Fatalf("server error is not ECH rejection: %v", rejectedErr)
	}
}

func TestGenerateProducesStrictConfigList(t *testing.T) {
	list, keys, err := echconfig.Generate("cover.example", 9)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) < 64 {
		t.Fatalf("ECHConfigList length = %d", len(list))
	}
	if _, err := echconfig.PublicConfigListBase64(list); err != nil {
		t.Fatal(err)
	}
	keys.Keys[0].Config = "not-base64"
	if _, err := echconfig.TLSKeys(keys); err == nil {
		t.Fatal("invalid ECH key file accepted")
	}
}

func TestTLSKeysRejectsPrivateKeyFromAnotherConfig(t *testing.T) {
	_, first, err := echconfig.Generate("cover.example", 9)
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := echconfig.Generate("cover.example", 10)
	if err != nil {
		t.Fatal(err)
	}
	first.Keys[0].PrivateKey = second.Keys[0].PrivateKey
	if _, err := echconfig.TLSKeys(first); err == nil {
		t.Fatal("ECH config accepted a mismatched private key")
	}
}

func handshake(t *testing.T, clientConfig, serverConfig *tls.Config) (
	tls.ConnectionState, tls.ConnectionState, error, error,
) {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	client := tls.Client(clientSide, clientConfig.Clone())
	server := tls.Server(serverSide, serverConfig.Clone())
	deadline := time.Now().Add(5 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Handshake() }()
	clientErr := client.Handshake()
	// After a required-ECH rejection, the server still has a TLS alert to
	// write. net.Pipe is unbuffered, so if the client has already returned
	// from Handshake and is not reading, the server blocks until SetDeadline.
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		buf := make([]byte, 512)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
		}
	}()
	serverErr := <-serverDone
	clientState := client.ConnectionState()
	serverState := server.ConnectionState()
	_ = clientSide.Close()
	_ = serverSide.Close()
	<-drainDone
	return clientState, serverState, clientErr, serverErr
}
