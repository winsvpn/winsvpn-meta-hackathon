package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/winn3/agent"
)

// TestE3EnrollmentChain is the lane E3 driver:
//
//  1. data plane registers (D4: POST /api/v1/nodes/register)
//  2. controller mints AWG keys (POST /v2/rekeys, x25519-mlkem768, 24h TTL)
//  3. hub serves a descriptor whose payload.node names the node
//
// Hop 2 starts the controller in-process (same stack as cmd/winn-server).
// Hops 1 and 3 need the Python hub extracted from the control-plane
// installer. That process is not startable from this Go module: it is a
// FastAPI app with SQLite, bootstrap grants, and an admin token. Kansas
// and Spain are frozen (winn3/agent.FrozenFleetAllowlist). When no
// loopback hub is opted in, those hops skip with the sourced contract.
func TestE3EnrollmentChain(t *testing.T) {
	t.Run("1_d4_register", testD4RegisterOrSkip)
	t.Run("2_controller_mint", testControllerMintHop)
	t.Run("3_hub_descriptor", testHubDescriptorOrSkip)
}

func testControllerMintHop(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{
		"-suite", protocol.DefaultSuite,
		"-ttl", "24h",
		"-emit", "-",
	}, &buf); err != nil {
		t.Fatalf("controller mint hop failed: %v", err)
	}
	var res result
	if err := json.Unmarshal(buf.Bytes(), &res); err != nil {
		t.Fatalf("decode mint result: %v\n%s", err, buf.String())
	}
	if res.Suite != protocol.DefaultSuite {
		t.Errorf("suite = %q, want %s", res.Suite, protocol.DefaultSuite)
	}
	if res.LifetimeTTL != (24*time.Hour).String() || !res.LifetimeMatches {
		t.Errorf("TTL %s (match=%v), want 24h", res.LifetimeTTL, res.LifetimeMatches)
	}
	if !res.DescriptorNamesNode {
		t.Error("RekeyResponse does not name the registering device")
	}
	if !res.PSKAppliedBoth || res.PSKSize != 32 {
		t.Errorf("minted PSK not applied on both sides (size=%d both=%v)", res.PSKSize, res.PSKAppliedBoth)
	}
	if res.Generation != 1 {
		t.Errorf("generation = %d, want 1", res.Generation)
	}
}

func testD4RegisterOrSkip(t *testing.T) {
	skipHubHop(t, "D4 POST "+hubRegisterPath)
}

func testHubDescriptorOrSkip(t *testing.T) {
	skipHubHop(t, "POST "+hubVerifyPath+" vpn_config.winn3_descriptor")
}

func skipHubHop(t *testing.T, hop string) {
	t.Helper()
	base := strings.TrimSpace(os.Getenv("WINN3_E3_HUB_BASE"))
	if base == "" {
		t.Skip(hubContractDocumentation(
			hop + ": WINN3_E3_HUB_BASE unset. Python hub is not started from this module " +
				"(FastAPI heredoc in server/wins_control_plane_setup_ONETOUCH.sh; needs SQLite, " +
				"bootstrap grant, X-Admin-Token). Loopback 9443/8000 are not a hub. " +
				"Kansas/Spain are frozen: this test never POSTs /api/v1/nodes/register at them.",
		))
	}
	parsed, err := url.Parse(base)
	if err != nil {
		t.Fatalf("WINN3_E3_HUB_BASE is not a URL: %v", err)
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		t.Fatalf("WINN3_E3_HUB_BASE host %q is not a loopback IP; refusing non-local hub (frozen fleet)", host)
	}
	slug := strings.TrimSpace(os.Getenv("WINN3_E3_NODE_SLUG"))
	for _, frozen := range agent.FrozenFleetAllowlist {
		if slug == frozen {
			t.Fatalf("WINN3_E3_NODE_SLUG %q is on FrozenFleetAllowlist; refusing", slug)
		}
	}
	token := strings.TrimSpace(os.Getenv("WINN3_E3_NODE_TOKEN"))
	if slug == "" || token == "" {
		t.Skip(hubContractDocumentation(
			hop + ": loopback hub origin is set but WINN3_E3_NODE_SLUG / WINN3_E3_NODE_TOKEN " +
				"are unset. Tokens are not guessed and are never logged.",
		))
	}
	t.Skip(hubContractDocumentation(
		hop + ": loopback hub origin and lab token are set, but this probe still skips the " +
			"live POST. A live register against even a lab hub can DELETE colliding rows on " +
			"older hub copies (audit/hub_main_patched.py still runs DELETE FROM nodes on " +
			"endpoint/public_key/ssh_host collision). Drive hops 1 and 3 from the hub's own " +
			"server/test_winn3_descriptor_hub.py once D4 lands v3 enablement. Hop 2 ran.",
	))
}

// TestE3ContractPins fails if the sourced path strings or Go protocol
// constants drift. Hub strings are grepped from the installers; controller
// strings are imported from protocol and cmd/winn-server.
func TestE3ContractPins(t *testing.T) {
	if protocol.RekeyPath != "/v2/rekeys" {
		t.Errorf("protocol.RekeyPath = %q", protocol.RekeyPath)
	}
	if protocol.DefaultSuite != "x25519-mlkem768" {
		t.Errorf("protocol.DefaultSuite = %q", protocol.DefaultSuite)
	}
	if protocol.MediaType != "application/vnd.winn.rekey+json" {
		t.Errorf("protocol.MediaType = %q", protocol.MediaType)
	}
	if protocol.Version != "winn/2" {
		t.Errorf("protocol.Version = %q (controller rekey wire version)", protocol.Version)
	}

	root := winsVPNRoot(t)
	serverMain, err := os.ReadFile(filepath.Join(root, "winn_protocol_experimental", "cmd", "winn-server", "main.go"))
	if err != nil {
		t.Fatalf("read winn-server: %v", err)
	}
	if !bytes.Contains(serverMain, []byte(`"key-ttl", 24*time.Hour`)) &&
		!bytes.Contains(serverMain, []byte("key-ttl\", 24*time.Hour")) {
		if !bytes.Contains(serverMain, []byte(`flag.DurationVar(&ttl, "key-ttl", 24*time.Hour`)) {
			t.Error("cmd/winn-server no longer defaults -key-ttl to 24h")
		}
	}
	if !bytes.Contains(serverMain, []byte(`"listen", "127.0.0.1:9443"`)) &&
		!bytes.Contains(serverMain, []byte(`flag.StringVar(&listenAddress, "listen", "127.0.0.1:9443"`)) {
		t.Error("cmd/winn-server no longer defaults -listen to 127.0.0.1:9443")
	}

	controlPlane := filepath.Join(root, "server", "wins_control_plane_setup_ONETOUCH.sh")
	body, err := os.ReadFile(controlPlane)
	if err != nil {
		t.Skipf("control-plane installer not at %s: %v", controlPlane, err)
	}
	needles := []string{
		`@app.post("/api/v1/nodes/register")`,
		`@app.post("/api/v1/nodes/bootstrap")`,
		`@app.post("/admin/nodes/winn3")`,
		`@app.post("/admin/nodes/winn3/descriptor")`,
		`@app.post("/verify")`,
		`"winn3_descriptor": served_winn3_descriptor`,
		`protocol_version and protocol_params_json are DELIBERATELY absent`,
		`descriptor_payload_b64`,
		`descriptor_sig_b64`,
		`WINN3_DESCRIPTOR_CLIENT_CAPABILITY = "supports_winn3_descriptor"`,
	}
	for _, needle := range needles {
		if !bytes.Contains(body, []byte(needle)) {
			t.Errorf("control-plane installer missing %q", needle)
		}
	}

	dataPlane := filepath.Join(root, "server", "wins_data_plane_setup_ONETOUCH.sh")
	dpBody, err := os.ReadFile(dataPlane)
	if err != nil {
		t.Skipf("data-plane installer not at %s: %v", dataPlane, err)
	}
	dpNeedles := []string{
		`HUB_REGISTER_URL="${HUB_REGISTER_URL:-${HUB_API_BASE}/api/v1/nodes/register}"`,
		`payload="$(WINS_REGISTER_NODE_TOKEN="${NODE_TOKEN}" WINS_REGISTER_XRAY_UUID="${XRAY_UUID}" jq -n \`,
		`slug: $slug,`,
		`public_key: $public_key,`,
		`secret_token: $ENV.WINS_REGISTER_NODE_TOKEN,`,
		`xray_uuid: $ENV.WINS_REGISTER_XRAY_UUID,`,
	}
	for _, needle := range dpNeedles {
		if !bytes.Contains(dpBody, []byte(needle)) {
			t.Errorf("data-plane installer missing %q", needle)
		}
	}
	if bytes.Contains(dpBody, []byte(`--arg secret_token`)) || bytes.Contains(dpBody, []byte(`--arg xray_uuid`)) {
		t.Error("data-plane installer must not place node token or Xray UUID on the jq command line")
	}

	var frozenKansas, frozenSpain bool
	for _, id := range agent.FrozenFleetAllowlist {
		if id == "kansas" {
			frozenKansas = true
		}
		if id == "spain-madrid" {
			frozenSpain = true
		}
	}
	if !frozenKansas || !frozenSpain {
		t.Fatal("FrozenFleetAllowlist no longer names kansas and spain-madrid")
	}
}

func TestE3SkipReasonDocumentsEndpoints(t *testing.T) {
	doc := hubContractDocumentation("unit")
	need := []string{
		hubRegisterPath,
		hubBootstrapPath,
		hubAdminWinn3Path,
		hubAdminDescriptorPath,
		hubVerifyPath,
		protocol.RekeyPath,
		protocol.DefaultSuite,
		controllerKeyTTLFlag,
		controllerRekeyMediaType(),
		"secret_token",
		"payload.node",
		"supports_winn3_descriptor",
	}
	for _, s := range need {
		if !strings.Contains(doc, s) {
			t.Errorf("skip contract missing %q", s)
		}
	}
}

func winsVPNRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}
