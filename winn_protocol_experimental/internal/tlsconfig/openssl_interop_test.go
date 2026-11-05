package tlsconfig_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/pki"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

func TestOpenSSLInteroperatesWithEveryStrictHybridTLSGroup(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		if os.Getenv("WINN_RELEASE_GATE") == "1" {
			t.Fatal("release gate requires OpenSSL 3.5 or newer")
		}
		t.Skip("OpenSSL is unavailable")
	}
	version, versionErr := exec.Command(openssl, "version").CombinedOutput()
	if versionErr != nil || !opensslAtLeast35(string(version)) {
		if os.Getenv("WINN_RELEASE_GATE") == "1" {
			t.Fatalf("release gate requires OpenSSL 3.5 or newer: %s", version)
		}
		t.Skipf("OpenSSL 3.5 or newer is unavailable: %s", version)
	}
	groups, err := exec.Command(openssl, "list", "-tls-groups").CombinedOutput()
	if err != nil || !strings.Contains(string(groups), "X25519MLKEM768") {
		if os.Getenv("WINN_RELEASE_GATE") == "1" {
			t.Fatalf("release OpenSSL lacks standardized hybrid ML-KEM groups: %s", groups)
		}
		t.Skip("OpenSSL does not expose standardized hybrid ML-KEM TLS groups")
	}
	paths, err := pki.GenerateLab(filepath.Join(t.TempDir(), "pki"), "localhost", "openssl-device-1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, suiteName := range protocol.SupportedSuites() {
		t.Run(suiteName, func(t *testing.T) {
			suite, err := tlsconfig.ParseSuite(suiteName)
			if err != nil {
				t.Fatal(err)
			}
			configuration, err := tlsconfig.Server(paths.ServerCert, paths.ServerKey, paths.CACert, suite)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			serverResult := make(chan error, 1)
			go func() {
				connection, err := listener.Accept()
				if err != nil {
					serverResult <- err
					return
				}
				tlsConnection := tls.Server(connection, configuration)
				defer tlsConnection.Close()
				if err := tlsConnection.Handshake(); err != nil {
					serverResult <- err
					return
				}
				state := tlsConnection.ConnectionState()
				if state.Version != tls.VersionTLS13 || state.CurveID != suite.Curve ||
					state.NegotiatedProtocol != "http/1.1" {
					serverResult <- fmt.Errorf(
						"OpenSSL negotiated version=%x group=%s ALPN=%q",
						state.Version,
						state.CurveID,
						state.NegotiatedProtocol,
					)
					return
				}
				serverResult <- nil
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(
				ctx,
				openssl,
				"s_client",
				"-connect", listener.Addr().String(),
				"-tls1_3",
				"-groups", suite.Curve.String(),
				"-alpn", "http/1.1",
				"-cert", paths.DeviceCert,
				"-key", paths.DeviceKey,
				"-CAfile", paths.CACert,
				"-verify_hostname", "localhost",
				"-quiet",
			)
			command.Stdin = strings.NewReader("")
			output, commandErr := command.CombinedOutput()
			serverErr := <-serverResult
			if commandErr != nil {
				t.Fatalf("OpenSSL hybrid handshake failed: %v\n%s", commandErr, output)
			}
			if serverErr != nil {
				t.Fatal(serverErr)
			}
		})
	}
}

func opensslAtLeast35(version string) bool {
	var major, minor int
	_, err := fmt.Sscanf(version, "OpenSSL %d.%d", &major, &minor)
	return err == nil && (major > 3 || major == 3 && minor >= 5)
}
