package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"winsvpn.local/awgcarryclient/peer"
)

// The end-to-end tests run the real client code against a real userspace
// AmneziaWG responder (peer package: the same engine, in this process) with
// a DNS responder inside the tunnel at the node's inner router address, over
// loopback UDP, with a non-default obfuscation profile.

var e2eProfile = map[string]any{
	"Jc": 3, "Jmin": 40, "Jmax": 70, "S1": 21, "S2": 37, "S3": 16, "S4": 0,
	"H1": 1234567, "H2": 2345678, "H3": 3456789, "H4": 4567890,
}

func profileLinesOf(t *testing.T, profile map[string]any) []string {
	t.Helper()
	raw, _ := json.Marshal(profile)
	lines, err := profileLines(raw)
	if err != nil {
		t.Fatal(err)
	}
	return lines
}

type fixture struct {
	node   peer.Keypair
	canary peer.Keypair
	peer   *peer.Peer
}

func startFixture(t *testing.T, profile map[string]any, silent bool) *fixture {
	t.Helper()
	node, err := peer.NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	canary, err := peer.NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	p, err := peer.Start(peer.Config{
		PrivateKey:      node.Private,
		ClientPublicKey: canary.Public,
		ClientAddress:   netip.MustParseAddr("10.8.255.1"),
		InnerAddress:    netip.MustParseAddr("10.8.1.1"),
		DNSPort:         53,
		Profile:         profileLinesOf(t, profile),
		Name:            "hub.example.test",
		Address:         netip.MustParseAddr("192.0.2.7"),
		Silent:          silent,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return &fixture{node: node, canary: canary, peer: p}
}

func (f *fixture) request(t *testing.T, timeout int) *Request {
	t.Helper()
	raw := validRequest()
	raw["private_key"] = f.canary.Private
	raw["peer_public_key"] = f.node.Public
	raw["endpoint"] = fmt.Sprintf("127.0.0.1:%d", f.peer.Port)
	raw["obfuscation"] = e2eProfile
	raw["timeout_seconds"] = timeout
	req, _, err := parseRequest(encode(t, raw), "udp")
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestE2EACorrectProfileCarriesADecryptedDNSReply(t *testing.T) {
	f := startFixture(t, e2eProfile, false)
	req := f.request(t, 20)
	result := probe(context.Background(), req)
	if result.Status != statusCarried || !result.Handshake {
		t.Fatalf("status %s handshake %v detail %q", result.Status, result.Handshake, result.Detail)
	}
	if !f.peer.Handshook() || f.peer.Queries() < 1 {
		t.Fatalf("the responder saw no handshake (%v) or no query (%d)", f.peer.Handshook(), f.peer.Queries())
	}
	// The reply is the responder's answer to this question: id, QR, one
	// question echoed, one A record with the fixture address.
	if len(result.Reply) != len(req.DNSQuery)+16 || result.Reply[0] != req.DNSQuery[0] || result.Reply[1] != req.DNSQuery[1] {
		t.Fatalf("reply %x", result.Reply)
	}
	if string(result.Reply[12:len(req.DNSQuery)]) != string(req.DNSQuery[12:]) {
		t.Fatal("the question was not echoed")
	}
	if !strings.HasSuffix(hex.EncodeToString(result.Reply), hex.EncodeToString([]byte{192, 0, 2, 7})) {
		t.Fatalf("no fixture address in %x", result.Reply)
	}
	if result.Elapsed > 10*time.Second {
		t.Fatalf("took %v", result.Elapsed)
	}
}

func TestE2EAWrongProfileNeverHandshakes(t *testing.T) {
	for name, change := range map[string]func(map[string]any){
		"H1 differs": func(p map[string]any) { p["H1"] = 7654321 },
		"S1 differs": func(p map[string]any) { p["S1"] = 22 },
		"S2 differs": func(p map[string]any) { p["S2"] = 36 },
		"H2 differs": func(p map[string]any) { p["H2"] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			nodeProfile := map[string]any{}
			for k, v := range e2eProfile {
				nodeProfile[k] = v
			}
			change(nodeProfile)
			f := startFixture(t, nodeProfile, false)
			req := f.request(t, 4)
			result := probe(context.Background(), req)
			if result.Status != statusNoReply || result.Handshake || len(result.Reply) != 0 {
				t.Fatalf("status %s handshake %v reply %x detail %q", result.Status, result.Handshake, result.Reply, result.Detail)
			}
			if f.peer.Handshook() || f.peer.Queries() != 0 {
				t.Fatal("the responder handshook with a mismatched profile")
			}
			if result.Elapsed < 4*time.Second || result.Elapsed > 8*time.Second {
				t.Fatalf("the deadline was not honoured: %v", result.Elapsed)
			}
		})
	}
}

func TestE2EAWrongKeyNeverHandshakes(t *testing.T) {
	f := startFixture(t, e2eProfile, false)
	other, err := peer.NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	req := f.request(t, 4)
	for name, mutate := range map[string]func(){
		"another canary key": func() { req.privateKeyHex = mustHex(other.Private) },
		"another node key":   func() { req.peerPublicHex = mustHex(other.Public) },
	} {
		t.Run(name, func(t *testing.T) {
			req = f.request(t, 4)
			mutate()
			result := probe(context.Background(), req)
			if result.Status != statusNoReply || result.Handshake || len(result.Reply) != 0 {
				t.Fatalf("status %s handshake %v detail %q", result.Status, result.Handshake, result.Detail)
			}
			if f.peer.Handshook() {
				t.Fatal("the responder handshook with a wrong key")
			}
		})
	}
}

func TestE2EASilentPeerIsNoReplyWithinTheDeadline(t *testing.T) {
	// Nobody listens here: a bound, never-read UDP socket.
	silent, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	f := startFixture(t, e2eProfile, false)
	req := f.request(t, 3)
	req.EndpointPort = uint16(silent.LocalAddr().(*net.UDPAddr).Port)
	started := time.Now()
	result := probe(context.Background(), req)
	if result.Status != statusNoReply || result.Handshake || len(result.Reply) != 0 {
		t.Fatalf("status %s handshake %v detail %q", result.Status, result.Handshake, result.Detail)
	}
	if elapsed := time.Since(started); elapsed < 3*time.Second || elapsed > 7*time.Second {
		t.Fatalf("deadline not honoured: %v", elapsed)
	}
}

func TestE2EAHandshakeWithoutADNSAnswerIsNoReply(t *testing.T) {
	f := startFixture(t, e2eProfile, true)
	req := f.request(t, 3)
	result := probe(context.Background(), req)
	if result.Status != statusNoReply || len(result.Reply) != 0 {
		t.Fatalf("status %s reply %x", result.Status, result.Reply)
	}
	if !result.Handshake || !f.peer.Handshook() || f.peer.Queries() == 0 {
		t.Fatalf("the handshake should complete and the query arrive: handshake %v peer %v queries %d",
			result.Handshake, f.peer.Handshook(), f.peer.Queries())
	}
}

func TestE2EAnUnresolvableEndpointIsRefusedQuickly(t *testing.T) {
	f := startFixture(t, e2eProfile, false)
	req := f.request(t, 10)
	req.EndpointHost = "no-such-host.invalid"
	started := time.Now()
	result := probe(context.Background(), req)
	if result.Status != statusEndpointUnusable || len(result.Reply) != 0 {
		t.Fatalf("status %s detail %q", result.Status, result.Detail)
	}
	if time.Since(started) > 10*time.Second {
		t.Fatal("resolution did not respect the deadline")
	}
}

// A served profile the engine refuses to configure (a special junk chain
// it cannot parse, or overlapping header ranges) is a refusal, not a no_reply:
// nothing was sent, so nothing about the node may be concluded.
func TestE2EAnEngineRejectedProfileIsARefusalNotANoReply(t *testing.T) {
	f := startFixture(t, e2eProfile, false)
	for name, change := range map[string]func(map[string]any){
		"I1 without its closing >":  func(p map[string]any) { p["I1"] = "<" },
		"overlapping header ranges": func(p map[string]any) { p["H1"] = "100-200"; p["H2"] = "150-250" },
	} {
		t.Run(name, func(t *testing.T) {
			profile := map[string]any{}
			for k, v := range e2eProfile {
				profile[k] = v
			}
			change(profile)
			raw := validRequest()
			raw["private_key"] = f.canary.Private
			raw["peer_public_key"] = f.node.Public
			raw["endpoint"] = fmt.Sprintf("127.0.0.1:%d", f.peer.Port)
			raw["obfuscation"] = profile
			raw["timeout_seconds"] = 10
			req, _, err := parseRequest(encode(t, raw), "udp")
			if err != nil {
				t.Fatalf("the client's own parser should pass this to the engine: %v", err)
			}
			result := probe(context.Background(), req)
			if result.Status != statusRefused || result.Handshake || len(result.Reply) != 0 {
				t.Fatalf("status %s handshake %v detail %q", result.Status, result.Handshake, result.Detail)
			}
			if result.Detail != "device configuration rejected" {
				t.Fatalf("the refusal reason is not fixed: %q", result.Detail)
			}
			if result.Elapsed > 2*time.Second {
				t.Fatalf("a refused configuration waited %v", result.Elapsed)
			}
			var out bytes.Buffer
			serve(context.Background(), bytes.NewReader(append(encode(t, raw), '\n')), &out, "udp", probe)
			replies := decodeReplies(t, out.Bytes())
			if len(replies) != 1 || replies[0]["id"] != float64(7) {
				t.Fatalf("replies %v", replies)
			}
			if _, present := replies[0]["dns_reply_hex"]; present {
				t.Fatalf("an engine refusal became a verdict: %v", replies[0])
			}
		})
	}
	if f.peer.Handshook() || f.peer.Queries() != 0 {
		t.Fatal("a refused configuration reached the node")
	}
}

func mustHex(b64 string) string {
	value, err := keyHex(b64)
	if err != nil {
		panic(err)
	}
	return value
}

// The real binary, built from this package with the toolchain that built
// the tests, driven over pipes exactly as CarryClientProcess drives it.

var (
	builtOnce sync.Once
	builtPath string
	builtErr  error
)

func builtClient(t *testing.T) string {
	t.Helper()
	builtOnce.Do(func() {
		dir, err := os.MkdirTemp("", "awg-carry-client-bin-")
		if err != nil {
			builtErr = err
			return
		}
		builtPath = filepath.Join(dir, "wins-awg-carry-client")
		goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
		cmd := exec.Command(goBinary, "build", "-trimpath", "-o", builtPath, ".")
		cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOFLAGS=-mod=mod")
		if out, err := cmd.CombinedOutput(); err != nil {
			builtErr = fmt.Errorf("build: %v: %s", err, out)
		}
	})
	if builtErr != nil {
		t.Fatal(builtErr)
	}
	return builtPath
}

func TestE2ETheBuiltBinarySpeaksTheContractOverPipes(t *testing.T) {
	binary := builtClient(t)
	f := startFixture(t, e2eProfile, false)
	cmd := exec.Command(binary, "--transport", "udp")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LANG=C"}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { stdin.Close(); cmd.Wait() }()
	reader := bufio.NewReader(stdout)

	raw := validRequest()
	raw["private_key"] = f.canary.Private
	raw["peer_public_key"] = f.node.Public
	raw["endpoint"] = fmt.Sprintf("127.0.0.1:%d", f.peer.Port)
	raw["obfuscation"] = e2eProfile
	raw["timeout_seconds"] = 20
	raw["id"] = 41
	line := encode(t, raw)
	if _, err := stdin.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	var reply map[string]any
	answer, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(answer), &reply); err != nil {
		t.Fatalf("reply not JSON: %q", answer)
	}
	if reply["id"] != float64(41) || reply["slug"] != "lab-1" || reply["transport"] != "udp" {
		t.Fatalf("echo wrong: %v", reply)
	}
	replyHex, _ := reply["dns_reply_hex"].(string)
	if len(replyHex) == 0 || !strings.HasSuffix(replyHex, "c0000207") {
		t.Fatalf("no carried reply: %v", reply)
	}
	if strings.Contains(answer, f.canary.Private) {
		t.Fatal("the reply carries the private key")
	}
	// A second request on the same process, a refused one, then a third
	// that must still be probed: the process keeps no state and keeps going.
	bad := validRequest()
	bad["id"] = 42
	bad["transport"] = "stealth"
	stdin.Write(append(encode(t, bad), '\n'))
	answer, _ = reader.ReadString('\n')
	reply = nil
	json.Unmarshal([]byte(answer), &reply)
	if reply["id"] != float64(42) || reply["dns_reply_hex"] != nil || !strings.Contains(fmt.Sprint(reply["error"]), "refused") {
		t.Fatalf("refusal wrong: %v", reply)
	}
	raw["id"] = 43
	raw["timeout_seconds"] = 20
	stdin.Write(append(encode(t, raw), '\n'))
	answer, _ = reader.ReadString('\n')
	reply = nil
	json.Unmarshal([]byte(answer), &reply)
	if reply["id"] != float64(43) || !strings.HasSuffix(fmt.Sprint(reply["dns_reply_hex"]), "c0000207") {
		t.Fatalf("third probe wrong: %v", reply)
	}
	if f.peer.Queries() < 2 {
		t.Fatalf("queries %d", f.peer.Queries())
	}
}

func TestTheBinaryRefusesAMissingOrUnknownTransport(t *testing.T) {
	binary := builtClient(t)
	for _, args := range [][]string{{}, {"--transport", "tcp"}, {"--transport", "udp", "extra"}} {
		cmd := exec.Command(binary, args...)
		cmd.Stdin = strings.NewReader("")
		if err := cmd.Run(); err == nil {
			t.Fatalf("%v accepted", args)
		}
	}
	cmd := exec.Command(binary, "--transport", "stealth_tls")
	cmd.Stdin = strings.NewReader("")
	if err := cmd.Run(); err != nil {
		t.Fatalf("a valid transport with empty input exited %v", err)
	}
}

// TestMain removes the binary the pipe tests built, once every test ran.
func TestMain(m *testing.M) {
	code := m.Run()
	if builtPath != "" {
		os.RemoveAll(filepath.Dir(builtPath))
	}
	os.Exit(code)
}
