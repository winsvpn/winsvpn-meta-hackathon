package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/datapath"
	"winsvpn.local/winnprotocol/datapath/duplex"
)

// buildBinary compiles the real subprocess entry point. Driving the compiled
// binary, rather than calling run() in process, is the point: it proves that a
// host launching this the way Android launches libxray.so gets a working
// datapath over a pipe.
func buildBinary(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go tool not on PATH: %v", err)
	}
	name := "winn-datapath"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	output := filepath.Join(t.TempDir(), name)
	command := exec.Command("go", "build", "-o", output, ".")
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build winn-datapath: %v\n%s", err, combined)
	}
	return output
}

func newGateway(t *testing.T) *net.UDPConn {
	t.Helper()
	gateway, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), Port: 0,
	})
	if err != nil {
		t.Fatalf("listen gateway: %v", err)
	}
	t.Cleanup(func() { _ = gateway.Close() })
	return gateway
}

func TestPrintContractReportsThisBuild(t *testing.T) {
	binary := buildBinary(t)
	output, err := exec.Command(binary, "-print-contract").Output()
	if err != nil {
		t.Fatalf("-print-contract: %v", err)
	}
	var banner Contract
	if err := json.Unmarshal(bytes.TrimSpace(output), &banner); err != nil {
		t.Fatalf("decode contract banner %q: %v", output, err)
	}
	if banner.Contract != datapath.ContractVersion ||
		banner.Wire != duplex.WireVersion {
		t.Fatalf("banner = %+v", banner)
	}
	if banner.GOOS != runtime.GOOS || banner.GOARCH != runtime.GOARCH {
		t.Fatalf("banner target = %s/%s, want %s/%s",
			banner.GOOS, banner.GOARCH, runtime.GOOS, runtime.GOARCH)
	}
	// The banner has to carry the normative wire numbers: a host uses it to
	// refuse a mismatched engine before it sends a single frame.
	if banner.FrameMagic != "0x334E4E57" || banner.FrameVersion != 1 ||
		banner.FrameHeaderSize != 16 || banner.MaxFramePayload != 65535 {
		t.Fatalf("banner wire constants = %+v", banner)
	}
	if !strings.Contains(banner.PayloadSemantics, "AmneziaWG outer") {
		t.Fatalf("banner does not state the payload semantics: %q",
			banner.PayloadSemantics)
	}
	// The machine-readable list, which is what a host actually probes. Both
	// classes, spelled exactly, because the host compares whole strings.
	if len(banner.Payloads) != 2 ||
		banner.Payloads[0] != "awg-datagram" || banner.Payloads[1] != "ip-packet" {
		t.Fatalf("banner payloads = %v, want [awg-datagram ip-packet]",
			banner.Payloads)
	}
	// The prose says "not raw IP packets" in its first clause. A host that
	// matched the prose instead of the list would read that as support. This
	// asserts the two fields are genuinely different things, which is the whole
	// reason the list was added.
	if strings.Contains(banner.PayloadSemantics, "not raw IP packets") &&
		!strings.Contains(string(output), `"payloads"`) {
		t.Fatal("the banner carries the prose but not the machine-readable list")
	}
}

// TestTheBannerSurvivesTheHostProbe reproduces WinnV3Host.engineSupportsV3
// character for character against the banner this build actually emits.
//
// Reproduced rather than approximated: the Kotlin does not parse JSON — it
// finds the literal key, takes the first bracketed run after it, splits on
// commas and compares whole trimmed strings. A change to this banner that a
// Go decoder still accepts can silently stop satisfying that scan, and the
// consequence is a host that refuses every v3 session with NO_V3_ENGINE while
// the engine standing next to it can carry one.
func TestTheBannerSurvivesTheHostProbe(t *testing.T) {
	binary := buildBinary(t)
	output, err := exec.Command(binary, "-print-contract").Output()
	if err != nil {
		t.Fatalf("-print-contract: %v", err)
	}
	if !kotlinEngineSupportsV3(string(output)) {
		t.Fatalf("WinnV3Host.engineSupportsV3 would refuse this banner: %s", output)
	}

	// The banner the host was written against, quoted from WinnV3HostTest. It
	// must still be refused, or the probe is matching prose.
	shipping := `{"contract":"1","wire":"winn-datapath-duplex/1",` +
		`"payload_semantics":"inbound and outbound frames carry AmneziaWG ` +
		`outer datagrams, not raw IP packets","goos":"android"}`
	if kotlinEngineSupportsV3(shipping) {
		t.Fatal("the probe accepts the pre-seam banner; it is matching prose")
	}
	for _, refuse := range []string{
		``,
		`not json at all`,
		`{"payloads":[]}`,
		`{"payloads":["awg-datagram"]}`,
		`{"payloads":["ip-packet-experimental"]}`,
		`{"payloads":["ip-packet"`,
	} {
		if kotlinEngineSupportsV3(refuse) {
			t.Errorf("the probe accepts %q", refuse)
		}
	}
}

// kotlinEngineSupportsV3 is WinnV3Host.engineSupportsV3, transcribed.
func kotlinEngineSupportsV3(banner string) bool {
	at := strings.Index(banner, `"payloads"`)
	if at < 0 {
		return false
	}
	open := strings.Index(banner[at:], "[")
	if open < 0 {
		return false
	}
	open += at
	closeAt := strings.Index(banner[open:], "]")
	if closeAt < 0 {
		return false
	}
	closeAt += open
	for _, entry := range strings.Split(banner[open+1:closeAt], ",") {
		if strings.Trim(strings.TrimSpace(entry), `"`) == "ip-packet" {
			return true
		}
	}
	return false
}

// TestSubprocessStdioCarriesDatagramsBothWays is the full Android/Windows shape
// end to end: launch the binary, speak frames over its pipes, and watch real
// UDP datagrams reach and return from a loopback gateway.
func TestSubprocessStdioCarriesDatagramsBothWays(t *testing.T) {
	binary := buildBinary(t)
	gateway := newGateway(t)

	command := exec.Command(binary, "-transport", "stdio")
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = command.Wait()
		if stderr.Len() > 0 {
			t.Logf("winn-datapath stderr: %s", stderr.String())
		}
	})

	reader := duplex.NewReader(stdout, true)
	writer := duplex.NewWriter(stdin)

	expect := func(want duplex.Opcode) []byte {
		t.Helper()
		opcode, payload, err := reader.Read()
		if err != nil {
			t.Fatalf("expecting %s: %v (stderr: %s)", want, err, stderr.String())
		}
		if opcode != want {
			t.Fatalf("got %s (%q), want %s", opcode, payload, want)
		}
		return append([]byte(nil), payload...)
	}

	// There is no banner frame; the host speaks first.
	// allow_own_socket is correct here and only here: this is a desktop-shaped
	// launch with no protected descriptor. On Android the service must pass one.
	config := []byte(`{"contract":"` + datapath.ContractVersion +
		`","payload":"` + datapath.PayloadAWGDatagram +
		`","carrier":"` + datapath.CarrierDirectAWG +
		`","gateway_endpoint":"` + gateway.LocalAddr().String() +
		`","session_id":"subprocess-stdio","allow_own_socket":true}`)
	if err := writer.Write(duplex.OpCreate, config); err != nil {
		t.Fatalf("write open: %v", err)
	}
	var ready datapath.Status
	if err := json.Unmarshal(expect(duplex.OpCreateAck), &ready); err != nil {
		t.Fatalf("decode ready: %v", err)
	}
	if !ready.SocketOwnedByEngine {
		t.Fatal("engine did not report owning the socket it opened")
	}

	payload := []byte("subprocess-stdio-host-to-gateway")
	if err := writer.Write(duplex.OpInbound, payload); err != nil {
		t.Fatalf("write inbound: %v", err)
	}
	buffer := make([]byte, 2048)
	_ = gateway.SetReadDeadline(time.Now().Add(20 * time.Second))
	count, from, err := gateway.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("gateway read: %v (stderr: %s)", err, stderr.String())
	}
	if !bytes.Equal(buffer[:count], payload) {
		t.Fatalf("gateway got %q, want %q", buffer[:count], payload)
	}

	reply := []byte("subprocess-stdio-gateway-to-host")
	if _, err := gateway.WriteToUDP(reply, from); err != nil {
		t.Fatalf("gateway write: %v", err)
	}
	if got := expect(duplex.OpOutbound); !bytes.Equal(got, reply) {
		t.Fatalf("outbound frame = %q, want %q", got, reply)
	}

	// CloseAck is empty by the normative framing, so the counters have to be
	// asked for before the close.
	if err := writer.Write(duplex.OpStatusRequest, nil); err != nil {
		t.Fatalf("write status request: %v", err)
	}
	var final datapath.Status
	if err := json.Unmarshal(expect(duplex.OpStatusResponse), &final); err != nil {
		t.Fatalf("decode final status: %v", err)
	}
	if final.TxDatagrams != 1 || final.RxDatagrams != 1 {
		t.Fatalf("final counters tx=%d rx=%d, want 1/1",
			final.TxDatagrams, final.RxDatagrams)
	}
	if err := writer.Write(duplex.OpClose, nil); err != nil {
		t.Fatalf("write close: %v", err)
	}
	if payload := expect(duplex.OpCloseAck); len(payload) != 0 {
		t.Fatalf("close-ack carried %d bytes, must be empty", len(payload))
	}
	if _, _, err := reader.Read(); err != io.EOF {
		t.Fatalf("stream did not end after Close: %v", err)
	}
}

// TestSubprocessRefusesToOpenItsOwnSocketByDefault is the Android guard at the
// process boundary: without allow_own_socket and without a descriptor, the
// engine must refuse rather than create an unprotected socket.
func TestSubprocessRefusesToOpenItsOwnSocketByDefault(t *testing.T) {
	binary := buildBinary(t)
	gateway := newGateway(t)

	command := exec.Command(binary, "-transport", "stdio")
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = command.Wait()
	})

	reader := duplex.NewReader(stdout, true)
	writer := duplex.NewWriter(stdin)
	config := []byte(`{"contract":"` + datapath.ContractVersion +
		`","payload":"` + datapath.PayloadAWGDatagram +
		`","carrier":"` + datapath.CarrierDirectAWG +
		`","gateway_endpoint":"` + gateway.LocalAddr().String() + `"}`)
	if err := writer.Write(duplex.OpCreate, config); err != nil {
		t.Fatalf("write open: %v", err)
	}
	opcode, message, err := reader.Read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if opcode != duplex.OpError {
		t.Fatalf("got %s, want an error frame", opcode)
	}
	if !bytes.Contains(message, []byte("VpnService.protect")) {
		t.Fatalf("refusal %q does not name the Android requirement", message)
	}
}

func TestArgumentValidation(t *testing.T) {
	cases := [][]string{
		{"-transport", "carrier-pigeon"},
		{"-transport", "unix"},                    // missing -control
		{"-transport", "stdio", "-receive-fd"},    // not possible on a pipe
		{"-transport", "stdio", "-control", "/x"}, // control is unix-only
		{"unexpected-positional"},
	}
	for _, arguments := range cases {
		if err := run(context.Background(), arguments); err == nil {
			t.Fatalf("run(%v) was accepted", arguments)
		}
	}
}
