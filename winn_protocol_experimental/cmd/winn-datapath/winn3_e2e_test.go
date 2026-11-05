package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// An end-to-end proof of THIS package's wiring.
//
// winn3/driver already proves the loop carries packets; that is its lane's
// result and repeating it here would prove nothing new. What is unproven until
// this test runs is the part this lane wrote: that a JSON host profile turns
// into a working session configuration, that the loopback device is a usable
// tun.Device in both directions, and — the one that matters — that the status
// document a desktop host reads goes to promotion_ready ONLY after an inner
// packet has been validated and written to the host device, and not merely when
// the session says DATA may flow.
//
// The two halves are joined by a carrier.Pipe pair rather than a socket,
// because this test is about the seams above the carrier and a real socket
// would add a flake without adding a proof.

func TestTheStatusDocumentPromotesOnlyAfterAnInnerPacketArrives(t *testing.T) {
	dir := t.TempDir()

	gatewayStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	clientStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	admission := make([]byte, 32)
	for i := range admission {
		admission[i] = byte(i*7 + 3)
	}
	write := func(name string, content []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	clientKeyPath := write("client.key", clientStatic.Bytes())
	gatewayKeyPath := write("gateway.key", gatewayStatic.Bytes())
	gatewayPubPath := write("gateway.pub", gatewayStatic.Public())
	admissionPath := write("admission.key", admission)

	// carrier.DefaultPathMTU rather than the literal 1280 this read until
	// 2026-08-10: this rig has no opinion about the path, and 1280 over a
	// [udp,tcp] plan is inside the inner-IPv6 dead zone driver.NewSizing now
	// refuses. It must be the same number profileFor writes into both
	// documents, or the loops are sized against a profile that says otherwise.
	sizing, err := driver.NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP, carrier.ClassTCP)
	if err != nil {
		t.Fatal(err)
	}

	// Each half gets a host-side loopback socket first, exactly as a desktop
	// host binds its seam before starting the engine, and the engine's device is
	// then pinned to that port.
	clientHost, clientDevice := seamPair(t, sizing.InnerMTU)
	gatewayHost, gatewayDevice := seamPair(t, sizing.InnerMTU)

	clientProfile := profileFor(t, dir, "client.json", map[string]any{
		"role":                clientRole,
		"static_path":         clientKeyPath,
		"gateway_static_path": gatewayPubPath,
		"admission_path":      admissionPath,
		"host_port":           clientHost.port,
	})
	gatewayProfile := profileFor(t, dir, "gateway.json", map[string]any{
		"role":           gatewayRole,
		"static_path":    gatewayKeyPath,
		"admission_path": admissionPath,
		"host_port":      gatewayHost.port,
	})

	clientSession, _, err := winn3BuildSession(clientProfile)
	if err != nil {
		t.Fatalf("build client session from its profile: %v", err)
	}
	gatewaySession, _, err := winn3BuildSession(gatewayProfile)
	if err != nil {
		t.Fatalf("build gateway session from its profile: %v", err)
	}

	toGateway, toClient, err := carrier.NewPipePair(carrier.PipeConfig{
		Class:          carrier.ClassUDP,
		MaxMessageSize: sizing.MessageSize,
		PathMTU:        sizing.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}

	clientAddr := mustAddr(t, "10.64.0.2")
	gatewayAddr := mustAddr(t, "10.64.0.3")
	routerAddr := mustAddr(t, "10.64.0.1")

	clientTun := tun.Config{
		Assign:    tun.Assignment{V4: clientAddr, RouterV4: routerAddr},
		Device:    clientDevice,
		Clock:     driver.SessionClock{Clock: driver.SystemClock{}},
		ICMPBurst: 4,
	}
	gatewayTun := tun.Config{
		Assign:    tun.Assignment{V4: gatewayAddr, RouterV4: routerAddr},
		Device:    gatewayDevice,
		Clock:     driver.SessionClock{Clock: driver.SystemClock{}},
		ICMPBurst: 4,
	}

	clientLoop, err := driver.NewClient(driver.Config{
		Session: clientSession, Sizing: sizing, Carrier: toGateway,
		Tun: &clientTun,
	})
	if err != nil {
		t.Fatal(err)
	}
	gatewayLoop, err := driver.NewGateway(driver.Config{
		Session: gatewaySession, Sizing: sizing, Carrier: toClient,
		Tun: &gatewayTun,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientDone := make(chan error, 1)
	gatewayDone := make(chan error, 1)
	go func() { clientDone <- clientLoop.Run(ctx) }()
	go func() { gatewayDone <- gatewayLoop.Run(ctx) }()

	const exclusion = "fwmark 0x1f4 lookup 51820"
	statusOf := func(loop *driver.Loop) winn3Status {
		return winn3StatusFrom("posture", loop, sizing, exclusion)
	}

	// THE HALF THAT MATTERS. Wait for the gate to open — the session says DATA
	// may flow — and require that the status document still refuses to promote,
	// because nothing has reached the host device yet.
	waitUntil(t, 15*time.Second, "the client's gate to open", func() bool {
		return statusOf(clientLoop).GateState == tun.StateCarrying.String()
	})
	beforeTraffic := statusOf(clientLoop)
	if beforeTraffic.RxPackets != 0 {
		t.Fatalf("the fixture delivered %d packets before the test sent any",
			beforeTraffic.RxPackets)
	}
	if beforeTraffic.PromotionReady {
		t.Fatal("the status document promoted on a carrying gate with zero " +
			"delivered inner packets: the gate is being read as the whole " +
			"proof, which is the exact error the tun contract's RxOffered / " +
			"RxPackets distinction exists to prevent")
	}
	if beforeTraffic.Posture != winn3PostureBootstrap {
		t.Fatalf("posture is %q before any traffic", beforeTraffic.Posture)
	}

	// Now put a real inner packet through, host to host, and have the far side
	// answer. Only the ANSWER can promote the client, because only an inbound
	// packet increments RxPackets.
	payload := []byte("winn3 desktop staged posture")
	clientHost.send(t, ipv4Packet(clientAddr.As4(), gatewayAddr.As4(), payload))

	arrived := gatewayHost.recv(t, 15*time.Second)
	if string(payloadOf(arrived)) != string(payload) {
		t.Fatalf("the gateway host received a different payload: %q",
			payloadOf(arrived))
	}
	gatewayHost.send(t, ipv4Packet(gatewayAddr.As4(), clientAddr.As4(), payload))

	waitUntil(t, 15*time.Second, "the client to promote", func() bool {
		return statusOf(clientLoop).PromotionReady
	})
	promoted := statusOf(clientLoop)
	if promoted.RxPackets == 0 {
		t.Fatal("promoted with no delivered packets")
	}
	if promoted.Posture != winn3PostureFull {
		t.Fatalf("promotion_ready is true but posture is %q", promoted.Posture)
	}
	if promoted.InnerMTU != sizing.InnerMTU {
		t.Fatalf("status inner_mtu %d, sizing %d",
			promoted.InnerMTU, sizing.InnerMTU)
	}
	if promoted.OuterSocketExclusion != exclusion {
		t.Fatalf("the exclusion the host declared was not echoed: %q",
			promoted.OuterSocketExclusion)
	}

	// The document a host actually reads is the encoded one, so encode it.
	encoded, err := json.Marshal(promoted)
	if err != nil {
		t.Fatal(err)
	}
	var decoded winn3Status
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.PromotionReady || decoded.Posture != winn3PostureFull {
		t.Fatalf("the encoded status does not carry the promotion: %s", encoded)
	}

	// Teardown latches the gate, and the teardown document must narrow.
	cancel()
	clientDevice.Close()
	gatewayDevice.Close()
	<-clientDone
	<-gatewayDone
	after := winn3StatusFrom("stopped", clientLoop, sizing, exclusion)
	if after.PromotionReady {
		t.Fatal("a stopped loop still reports promotion_ready")
	}
}

// TestTheLoopbackSeamRefusesAForeignSender.
//
// A loopback port is writable by any local process. An unpinned seam would let
// one inject inner packets into somebody else's tunnel, so the device counts
// and drops anything that did not come from the port the host declared.
func TestTheLoopbackSeamRefusesAForeignSender(t *testing.T) {
	host, device := seamPair(t, 1200)
	defer func() { _ = device.Close() }()

	intruder, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), Port: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = intruder.Close() }()

	engine := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: device.LocalPort()}
	if _, err := intruder.WriteToUDP([]byte("injected"), engine); err != nil {
		t.Fatal(err)
	}
	host.send(t, []byte("legitimate"))

	buf := make([]byte, 2048)
	if err := device.conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := device.ReadPacket(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "legitimate" {
		t.Fatalf("the device delivered %q; a foreign datagram got through",
			buf[:n])
	}
	if device.ForeignDatagrams() != 1 {
		t.Fatalf("foreign datagrams counted %d, want 1",
			device.ForeignDatagrams())
	}
}

// --- fixture -----------------------------------------------------------------

const (
	clientRole  = winn3RoleClient
	gatewayRole = winn3RoleGateway
)

// seamHost is the host's half of a loopback seam: the socket a desktop host
// binds before it starts the engine.
type seamHost struct {
	conn *net.UDPConn
	port int
	peer *net.UDPAddr
}

func seamPair(t *testing.T, mtu int) (*seamHost, *winn3LoopbackDevice) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), Port: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("loopback socket has no UDP address")
	}
	device, err := newWinn3LoopbackDevice(local.Port, mtu)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })
	return &seamHost{
		conn: conn,
		port: local.Port,
		peer: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: device.LocalPort()},
	}, device
}

func (h *seamHost) send(t *testing.T, packet []byte) {
	t.Helper()
	if _, err := h.conn.WriteToUDP(packet, h.peer); err != nil {
		t.Fatal(err)
	}
}

func (h *seamHost) recv(t *testing.T, within time.Duration) []byte {
	t.Helper()
	if err := h.conn.SetReadDeadline(time.Now().Add(within)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, err := h.conn.Read(buf)
	if err != nil {
		t.Fatalf("nothing reached the far host within %s: %v", within, err)
	}
	return buf[:n]
}

// profileFor writes a v3 host profile and loads it through the real parser, so
// that this fixture exercises the shipping document path rather than building a
// struct the parser would have refused.
func profileFor(
	t *testing.T, dir, name string, fields map[string]any,
) winn3Profile {
	t.Helper()
	document := map[string]any{
		"version": winn3ProfileVersion,
		"role":    fields["role"],
		"plan":    []string{"udp", "tcp"},
		// The same number the sizing above is built at, and the fleet default
		// for the same reason: a literal 1280 here is inside the inner-IPv6
		// dead zone over this plan. Moved 2026-08-10 with the fleet default.
		"path_mtu":   carrier.DefaultPathMTU,
		"gateway_id": "winn3-desktop-e2e",
		"carrier": map[string]any{
			"class":    "udp",
			"endpoint": "198.51.100.7:51820",
		},
		"inner": map[string]any{
			"v4":        "10.64.0.2",
			"router_v4": "10.64.0.1",
		},
		"keys": map[string]any{
			"static_path":    fields["static_path"],
			"admission_path": fields["admission_path"],
		},
		"device": map[string]any{
			"kind":      winn3DeviceLoopbackUDP,
			"host_port": fields["host_port"],
		},
		"allow_own_socket":       true,
		"outer_socket_exclusion": "fwmark 0x1f4 lookup 51820",
	}
	if gatewayKey, ok := fields["gateway_static_path"]; ok {
		document["keys"].(map[string]any)["gateway_static_path"] = gatewayKey
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	profile, err := loadWinn3Profile(path)
	if err != nil {
		t.Fatalf("the fixture profile %s was refused: %v", name, err)
	}
	return profile
}

func waitUntil(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", within, what)
}

func mustAddr(t *testing.T, text string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(text)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

// ipv4Packet builds one UDP-over-IPv4 packet with a correct header checksum.
func ipv4Packet(src, dst [4]byte, payload []byte) []byte {
	const headerLen = 20
	const udpLen = 8
	total := headerLen + udpLen + len(payload)
	packet := make([]byte, total)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(total)) //nolint:gosec // bounded by the fixture
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:headerLen]))

	udp := packet[headerLen:]
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], 40001)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen+len(payload))) //nolint:gosec // bounded by the fixture
	copy(udp[udpLen:], payload)
	return packet
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum) //nolint:gosec // one's complement of a folded sum
}

func payloadOf(packet []byte) []byte {
	if len(packet) < 28 {
		return nil
	}
	return packet[28:]
}
