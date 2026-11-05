//go:build unix

package clientbinding

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/datapath/duplex"
	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
)

// The relay-subprocess backend, proven against itself.
//
// Two REAL winn-datapath subprocesses — a client driven through Connect, a
// gateway driven directly by this test — are joined by two real loopback UDP
// sockets handed over as descriptors, exactly as a host hands a protected
// socket to its engine. Inner IP packets cross one to the other inside the
// winn/3 ciphertext, and the digests are compared. No interface, no route and
// no utun/utun device on this machine is touched: this is the loopback rig the
// project has proven safe.

// buildEngine compiles the real relay subprocess entry point, so the proof
// exercises the shipping binary rather than an in-process stand-in.
func buildEngine(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go tool not on PATH: %v", err)
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test source")
	}
	moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), ".."))
	name := "winn-datapath"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	output := filepath.Join(t.TempDir(), name)
	command := exec.Command("go", "build", "-o", output, "./cmd/winn-datapath")
	command.Dir = moduleRoot
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build winn-datapath: %v\n%s", err, combined)
	}
	return output
}

// loopbackSocket binds 127.0.0.1 on an ephemeral port. Loopback explicitly,
// never a wildcard: a wildcard bind would expose this test on every interface.
func loopbackSocket(t *testing.T) (*net.UDPConn, *net.UDPAddr) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("loopback socket has no UDP address")
	}
	return conn, addr
}

// handOverDup returns a stable descriptor the engine may inherit as fd 3.
func handOverDup(t *testing.T, conn *net.UDPConn) int {
	t.Helper()
	file, err := conn.File()
	if err != nil {
		t.Fatalf("cannot take a descriptor from the loopback socket: %v", err)
	}
	fd, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	_ = file.Close()
	return fd
}

// testKeyring writes real key files and two key documents sharing them, so the
// engines run over the actual document path rather than a hand-built struct.
type testKeyring struct {
	clientPath  string
	gatewayPath string
}

func newTestKeyring(t *testing.T) testKeyring {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, content []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	clientStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	gatewayStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	admission := write("admission.key",
		[]byte("clientbinding-e2e-admission-secret-0123456789"))
	clientKey := write("client.key", clientStatic.Bytes())
	gatewayKey := write("gateway.key", gatewayStatic.Bytes())
	gatewayPub := write("gateway.pub", gatewayStatic.Public())

	writeJSON := func(name string, doc map[string]any) {
		encoded, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		write(name, encoded)
	}

	writeJSON("client.json", map[string]any{
		"version":                "winn3-keys/1",
		"role":                   "client",
		"gateway_id":             "clientbinding-e2e",
		"static_path":            clientKey,
		"gateway_static_path":    gatewayPub,
		"admission_path":         admission,
		"outer_socket_exclusion": "loopback test: no posture is installed by this test",
	})
	writeJSON("gateway.json", map[string]any{
		"version":        "winn3-keys/1",
		"role":           "gateway",
		"gateway_id":     "clientbinding-e2e",
		"static_path":    gatewayKey,
		"admission_path": admission,
	})
	return testKeyring{
		clientPath:  filepath.Join(dir, "client.json"),
		gatewayPath: filepath.Join(dir, "gateway.json"),
	}
}

// planFloor returns the plan-floor sizing the create documents must pin inner
// messages to.
func planFloor(t *testing.T) driver.Sizing {
	t.Helper()
	sizing, err := driver.NewSizing(1500,
		carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS)
	if err != nil {
		t.Fatal(err)
	}
	return sizing
}

// frameGatewayDriver is the host half of the gateway engine's frame channel.
type frameGatewayDriver struct {
	writer   *duplex.Writer
	frames   chan duplexFrame
	closeAck chan struct{}
	done     chan struct{}
	stdin    io.WriteCloser
	stderr   *strings.Builder
	cmd      *exec.Cmd
}

func (g *frameGatewayDriver) route(stdout io.Reader) {
	reader := duplex.NewReader(stdout, true)
	defer close(g.done)
	for {
		opcode, payload, err := reader.Read()
		if err != nil {
			return
		}
		switch opcode {
		case duplex.OpCloseAck:
			select {
			case g.closeAck <- struct{}{}:
			default:
			}
		default:
			cp := make([]byte, len(payload))
			copy(cp, payload)
			select {
			case g.frames <- duplexFrame{opcode: opcode, payload: cp}:
			default:
			}
		}
	}
}

func startGateway(t *testing.T, binary, keysPath string, fd int) *frameGatewayDriver {
	t.Helper()
	gateway := &frameGatewayDriver{
		frames:   make(chan duplexFrame, 512),
		closeAck: make(chan struct{}, 1),
		done:     make(chan struct{}),
		stderr:   &strings.Builder{},
	}
	file := os.NewFile(uintptr(fd), "gateway-socket")
	command := exec.Command(binary, "-transport", "stdio",
		"-winn3", "-winn3-keys", keysPath, "-udp-fd", "3")
	command.ExtraFiles = []*os.File{file}
	command.Stderr = gateway.stderr
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	gateway.cmd = command
	gateway.stdin = stdin
	gateway.writer = duplex.NewWriter(stdin)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	go gateway.route(stdout)
	t.Cleanup(func() {
		_ = gateway.writer.Write(duplex.OpClose, nil)
		select {
		case <-gateway.closeAck:
		case <-time.After(10 * time.Second):
		}
		_ = stdin.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	return gateway
}

func (g *frameGatewayDriver) create(t *testing.T, doc []byte) {
	t.Helper()
	if err := g.writer.Write(duplex.OpCreate, doc); err != nil {
		t.Fatalf("gateway create: %v (stderr: %s)", err, g.stderr)
	}
}

func (g *frameGatewayDriver) expectCreateAck(t *testing.T) {
	t.Helper()
	deadline := time.After(35 * time.Second)
	for {
		select {
		case f := <-g.frames:
			if f.opcode == duplex.OpCreateAck {
				return
			}
			if f.opcode == duplex.OpError {
				t.Fatalf("gateway refused create: %s (stderr: %s)", f.payload, g.stderr)
			}
		case <-deadline:
			t.Fatalf("no gateway CreateAck within 35s (stderr: %s)", g.stderr)
		}
	}
}

// ipv4UDP builds a minimal, checksum-valid IPv4/UDP packet with the given
// source and destination addresses. The inner-IP validator insists on a valid
// header checksum and on the assigned source/destination.
func ipv4UDP(src, dst [4]byte, payload []byte) []byte {
	total := 20 + 8 + len(payload)
	buf := make([]byte, total)
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(total))
	binary.BigEndian.PutUint16(buf[6:8], 0x4000) // DF
	buf[8] = 64                                  // TTL
	buf[9] = 17                                  // UDP
	copy(buf[12:16], src[:])
	copy(buf[16:20], dst[:])
	binary.BigEndian.PutUint16(buf[20:22], 12345)
	binary.BigEndian.PutUint16(buf[22:24], 53)
	binary.BigEndian.PutUint16(buf[24:26], uint16(8+len(payload)))
	copy(buf[28:], payload)
	binary.BigEndian.PutUint16(buf[10:12], checksum(buf[:20]))
	return buf
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// TestRelayBackendReportIsTruthfulWhenPresent proves the positive half of the
// capability report: once an engine is available, TunnelSupported is true, the
// carrier backends list names the relay, and safe_to_advertise_protocol stays
// false because the platform device and preparation assembler are still
// missing. The two listed-missing facts keep the report honest.
func TestRelayBackendReportIsTruthfulWhenPresent(t *testing.T) {
	binary := buildEngine(t)
	t.Setenv(engineEnv, binary)
	if !TunnelSupported() {
		t.Fatal("with an engine configured, TunnelSupported must be true")
	}
	var report struct {
		TunnelSupported bool     `json:"tunnel_supported"`
		Advertise       bool     `json:"safe_to_advertise_protocol"`
		Carriers        []string `json:"carrier_backends_available"`
		Missing         []string `json:"missing_for_tunnel"`
	}
	if err := json.Unmarshal([]byte(TunnelBackendJSON()), &report); err != nil {
		t.Fatalf("TunnelBackendJSON is not valid JSON: %v", err)
	}
	if !report.TunnelSupported {
		t.Fatal("the report claims no tunnel support with an engine configured")
	}
	if len(report.Carriers) == 0 {
		t.Fatal("the report must name the relay carrier backend once it is present")
	}
	if report.Advertise {
		t.Fatal("safe_to_advertise_protocol must stay false until the platform " +
			"device and preparation assembler are verified: advertising a " +
			"negotiation you cannot deliver is the silent downgrade")
	}
	foundDevice, foundPrep := false, false
	for _, missing := range report.Missing {
		if strings.Contains(missing, "platform tunnel provider") {
			foundDevice = true
		}
		if strings.Contains(missing, "preparation assembler") {
			foundPrep = true
		}
	}
	if !foundDevice || !foundPrep {
		t.Fatalf("the report must keep listing the two still-missing pieces: %v",
			report.Missing)
	}
}

// TestRelayConnectDisconnectRoundTrip proves Connect, a real carry, and
// Disconnect through the binding against a real gateway engine, over loopback,
// without a system VPN.
func TestRelayConnectDisconnectRoundTrip(t *testing.T) {
	binary := buildEngine(t)
	t.Setenv(engineEnv, binary)
	ring := newTestKeyring(t)
	sizing := planFloor(t)

	clientSock, clientAddr := loopbackSocket(t)
	gatewaySock, gatewayAddr := loopbackSocket(t)

	gateway := startGateway(t, binary, ring.gatewayPath, handOverDup(t, gatewaySock))

	clientCreate := map[string]any{
		"payload":          "ip-packet",
		"gateway_endpoint": gatewayAddr.String(),
		"inner_address":    "10.8.1.3",
		"inner_next_hop":   "10.8.1.1",
		"inner_mtu":        sizing.InnerMTU,
		"path_mtu":         1500,
		"carrier_classes":  []string{"udp", "tcp", "tls"},
		"session_id":       "clientbinding-e2e",
		"allow_own_socket": false,
		"owns_tun":         false,
	}
	gatewayCreate := map[string]any{
		"payload":          "ip-packet",
		"gateway_endpoint": clientAddr.String(),
		"inner_address":    "10.8.1.1",
		"inner_next_hop":   "10.8.1.3",
		"inner_mtu":        sizing.InnerMTU,
		"path_mtu":         1500,
		"carrier_classes":  []string{"udp", "tcp", "tls"},
		"session_id":       "clientbinding-e2e",
		"allow_own_socket": false,
		"owns_tun":         false,
	}

	// The client's inner socket is handed to Connect, which hands it to the
	// engine as fd 3, and the gateway's to the gateway engine the same way.
	clientFD := handOverDup(t, clientSock)
	config, err := json.Marshal(map[string]any{
		"keys":             ring.clientPath,
		"engine_socket_fd": clientFD,
		"create":           clientCreate,
	})
	if err != nil {
		t.Fatal(err)
	}

	status, err := Connect(string(config))
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	t.Cleanup(func() { _ = Disconnect() })

	var ack struct {
		SessionID   string `json:"session_id"`
		InnerMTU    int    `json:"inner_mtu"`
		MessageSize int    `json:"message_size"`
		Refusal     string `json:"refusal,omitempty"`
	}
	if err := json.Unmarshal([]byte(status), &ack); err != nil {
		t.Fatalf("CreateAck is not JSON: %v\n%s", err, status)
	}
	if ack.SessionID != "clientbinding-e2e" {
		t.Fatalf("CreateAck session_id = %q", ack.SessionID)
	}
	if ack.InnerMTU != sizing.InnerMTU || ack.MessageSize != sizing.MessageSize {
		t.Fatalf("CreateAck plan floor %d/%d, want %d/%d",
			ack.InnerMTU, ack.MessageSize, sizing.InnerMTU, sizing.MessageSize)
	}

	// The far end must also have built its tunnel before it will clear the
	// client's handshake and carry a packet.
	gateway.create(t, mustJSONBytes(t, gatewayCreate))
	gateway.expectCreateAck(t)

	// Deliver one inner packet off our assigned address to the gateway's
	// assigned address. Offered repeatedly while the handshake completes,
	// because a packet offered before the gate opens is dropped fail-closed.
	needle := []byte("clientbinding round-trip payload")
	packet := ipv4UDP(
		[4]byte{10, 8, 1, 3}, [4]byte{10, 8, 1, 1}, needle)
	for attempt := 0; attempt < 60; attempt++ {
		if err := SendPacket(string(packet)); err != nil {
			t.Fatalf("SendPacket: %v", err)
		}
		deadline := time.Now().Add(2 * time.Second)
		if gotOne(t, gateway, needle, deadline) {
			break
		}
		if attempt == 59 {
			t.Fatalf("no packet reached the gateway after %d attempts", attempt+1)
		}
	}

	// Status must reflect the live session the whole time.
	if status := Status(); !strings.Contains(status, "clientbinding-e2e") {
		t.Fatalf("Status() does not reference the live session: %s", status)
	}

	// Disconnect must report a clean teardown for the live session.
	if err := Disconnect(); err != nil {
		t.Fatalf("Disconnect returned an error for a live session: %v", err)
	}
	// ... and a condition once it is down.
	if err := Disconnect(); !errors.Is(err, ErrNoActiveSession) {
		t.Fatalf("Disconnect after teardown = %v, want ErrNoActiveSession", err)
	}
}

func gotOne(t *testing.T, gateway *frameGatewayDriver, needle []byte, deadline time.Time) bool {
	for time.Now().Before(deadline) {
		select {
		case f := <-gateway.frames:
			if f.opcode == duplex.OpOutbound &&
				strings.Contains(string(f.payload), string(needle)) {
				return true
			}
			if f.opcode == duplex.OpError {
				t.Fatalf("gateway reported an error: %s", f.payload)
			}
		case <-time.After(100 * time.Millisecond):
		}
	}
	return false
}

func mustJSONBytes(t *testing.T, v any) []byte {
	t.Helper()
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// TestBindingTakesOwnershipAndAdoptsSuppliedDescriptor proves the two halves of
// the descriptor contract in one loopback rig, and either half alone is not
// evidence of the other.
//
//  1. Ownership, closed in Close. A descriptor supplied as engine_socket_fd
//     becomes the BINDING's the moment Connect accepts it: Disconnect (Close)
//     must release it. A sibling descriptor never handed over must stay open
//     throughout, which is the negative control that stops an always-closed
//     lie: the test only reports the handed fd as closed because it can also
//     prove the control fd stays open.
//
//  2. Adoption, never creation. The create document sets allow_own_socket
//     false, so the engine has no seat that may open its own socket — decoding
//     refuses a create without a descriptor when allow_own_socket is false, so
//     Connect reaching CreateAck is already that proof. On top of it, whatever
//     reaches a raw peer must arrive from the handed socket's bound port: if
//     the socket-creation seam were ever reached the engine would dial a fresh
//     :0 socket and the source port would differ, and this fails.
func TestBindingTakesOwnershipAndAdoptsSuppliedDescriptor(t *testing.T) {
	binary := buildEngine(t)
	t.Setenv(engineEnv, binary)
	ring := newTestKeyring(t)
	sizing := planFloor(t)

	// A raw peer that only receives. It does not need to speak winn/3: whatever
	// the client engine emits out its adopted socket identifies the SOURCE
	// socket, which is the fact under test, not the handshake state.
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen peer socket: %v", err)
	}
	defer func() { _ = peer.Close() }()
	peerAddr, ok := peer.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("peer socket has no UDP address")
	}

	// The handed socket: the descriptor given to the binding, and the only
	// socket the client engine is permitted to use.
	handed, handedAddr := loopbackSocket(t)
	handedFD := handOverDup(t, handed)

	// A control descriptor never handed over. It must survive the whole test,
	// proving the open/closed detection is real rather than an all-closed lie.
	control, _ := loopbackSocket(t)
	controlFile, err := control.File()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = controlFile.Close() }()
	controlFD := int(controlFile.Fd())

	if !fdOpen(handedFD) {
		t.Fatalf("handed fd %d must be open before Connect", handedFD)
	}
	if !fdOpen(controlFD) {
		t.Fatalf("control fd %d must be open before Connect", controlFD)
	}

	config, err := json.Marshal(map[string]any{
		"keys":             ring.clientPath,
		"engine_socket_fd": handedFD,
		"create": map[string]any{
			"payload":          "ip-packet",
			"gateway_endpoint": peerAddr.String(),
			"inner_address":    "10.8.1.3",
			"inner_next_hop":   "10.8.1.1",
			"inner_mtu":        sizing.InnerMTU,
			"path_mtu":         1500,
			"carrier_classes":  []string{"udp", "tcp", "tls"},
			"session_id":       "clientbinding-ownership",
			"allow_own_socket": false,
			"owns_tun":         false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Connect succeeding with allow_own_socket=false is the first half of the
	// adoption proof: without a descriptor the engine has no seat and is refused
	// outright, so reaching CreateAck means fd 3 was handed over and adopted.
	if _, err := Connect(string(config)); err != nil {
		t.Fatalf("Connect with a supplied descriptor must succeed: %v", err)
	}
	t.Cleanup(func() { _ = Disconnect() })

	// Second half: whatever leaves the client must leave from the handed
	// socket's port, never from a socket the engine opened for itself.
	_ = peer.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 4096)
	for {
		_, from, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("no datagram reached the peer from the handed socket: %v", err)
		}
		if from.Port != handedAddr.Port {
			t.Fatalf("socket-creation seam reached: datagram arrived from %s, "+
				"want the handed socket %s", from, handedAddr)
		}
		break
	}

	// Ownership: Close must release the descriptor the binding accepted.
	if err := Disconnect(); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if fdOpen(handedFD) {
		t.Fatalf("supplied fd %d is still open after Close; the binding leaked "+
			"the descriptor it took ownership of", handedFD)
	}
	if !fdOpen(controlFD) {
		t.Fatalf("control fd %d closed unexpectedly; the detection cannot "+
			"distinguish open from closed", controlFD)
	}
}

// fdOpen reports whether the descriptor is currently open, without consuming
// it: dup succeeds on an open descriptor and returns EBADF on a closed one.
// The duplicate is discarded immediately. This is portable across unix targets,
// where syscall exposes no public Fcntl.
func fdOpen(fd int) bool {
	dup, err := syscall.Dup(fd)
	if err != nil {
		return false
	}
	_ = syscall.Close(dup)
	return true
}

// TestConnectHonorsExplicitEngineAndReturnsPromptlyOnSubprocessExit. The
// config's "engine" override is the engine Connect checks and spawns, with
// $WINS_WINN3_ENGINE unset; an engine that exits before CreateAck, or after
// refusing Create, ends Connect promptly instead of waiting out the connect
// and close budgets (35 s + 10 s) on a dead child.
func TestConnectHonorsExplicitEngineAndReturnsPromptlyOnSubprocessExit(t *testing.T) {
	binary := buildEngine(t)
	t.Setenv(engineEnv, "")
	ring := newTestKeyring(t)
	sizing := planFloor(t)
	create := func(id string, ownSocket bool) map[string]any {
		return map[string]any{
			"payload":          "ip-packet",
			"gateway_endpoint": "127.0.0.1:51820",
			"inner_address":    "10.8.1.3",
			"inner_next_hop":   "10.8.1.1",
			"inner_mtu":        sizing.InnerMTU,
			"path_mtu":         1500,
			"carrier_classes":  []string{"udp", "tcp", "tls"},
			"session_id":       id,
			"allow_own_socket": ownSocket,
			"owns_tun":         false,
		}
	}

	// 1. Explicit engine, environment unset, key file missing: the engine
	// starts and exits before CreateAck.
	missingKeys := mustJSONBytes(t, map[string]any{
		"engine": binary,
		"keys":   filepath.Join(t.TempDir(), "missing-keys.json"),
		"create": create("clientbinding-missing-keys", true),
	})
	start := time.Now()
	_, err := Connect(string(missingKeys))
	if err == nil || errors.Is(err, ErrEngineUnavailable) {
		t.Fatalf("Connect with an explicit engine and missing keys = %v, want the engine's exit", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Connect on an early engine exit took %s, want a prompt return", elapsed)
	}

	// 2. A refused Create must not stall teardown for the close budget.
	refused := mustJSONBytes(t, map[string]any{
		"engine": binary,
		"keys":   ring.clientPath,
		"create": create("clientbinding-refused", false),
	})
	start = time.Now()
	_, err = Connect(string(refused))
	if err == nil || !strings.Contains(err.Error(), "engine refused create") {
		t.Fatalf("Connect on a refused create = %v, want an engine refusal", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Connect on a refused create took %s, want a prompt teardown", elapsed)
	}
}
