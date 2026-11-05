//go:build unix

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/datapath/duplex"
	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// The end-to-end proof of the frame seam.
//
// TWO HOSTS, each driving a real winn3FrameServer over a real duplex frame
// channel, joined by two real loopback datagram sockets handed over as
// descriptors exactly as VpnService.protect + SCM_RIGHTS hands one over. Inner
// IP packets go in as Inbound frames and come out of the far side as Outbound
// frames, and the digests are compared across a rekey and a carrier migration.
//
// LOOPBACK ONLY. Both sockets bind 127.0.0.1 explicitly. Nothing here listens on
// a routable interface, opens a utun device or touches this machine's routing
// table: a dozen sibling lanes depend on its connectivity.
//
// What this proves that winn3/driver's own end-to-end test does not: that the
// bytes crossing THIS package's frame channel are inner IP packets, that the
// create document's plan turns into the floor rather than the dialled carrier's
// ceiling, and that the status document a host reads its promotion gate off goes
// true only after an inner packet has been validated and delivered.

// TestTwoFrameHostsCarryPacketsAcrossARekeyAndAMigration is the whole seam.
//
// that is the point.
//
//nolint:gocyclo // one linear scenario; splitting it would hide the ordering
func TestTwoFrameHostsCarryPacketsAcrossARekeyAndAMigration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	ring := newFrameKeyring(t)

	// The plan is three classes and the floor is computed over all of them, so
	// the tunnel is sized for the tls leg it may escalate to and not for the udp
	// leg it dialled. That is the 84-byte rule, exercised rather than asserted.
	const pathMTU = 1500
	sizing, err := driver.NewSizing(pathMTU, mustClasses(t, "udp", "tcp", "tls")...)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("plan floor: message_size=%d inner_mtu=%d (a dialled udp/ipv4 carrier would have been %d)",
		sizing.MessageSize, sizing.InnerMTU,
		carrier.InnerMTU(carrier.MaxMessageSizeFor(carrier.ClassUDP, carrier.FamilyIPv4, pathMTU)))

	clientSock, clientAddr := loopbackSocket(t)
	gatewaySock, gatewayAddr := loopbackSocket(t)

	client := startFrameEngine(t, ctx, ring.clientKeys, handOver(t, clientSock))
	gateway := startFrameEngine(t, ctx, ring.gatewayKeys, handOver(t, gatewaySock))

	// Each side's "gateway_endpoint" is its PEER. On the gateway engine that is
	// the client, because the field names the far end of the carrier and the
	// lab's responding half has no gateway of its own.
	client.create(t, frameCreate(gatewayAddr, "10.8.1.3", "10.8.1.1", sizing, pathMTU))
	gateway.create(t, frameCreate(clientAddr, "10.8.1.1", "10.8.1.3", sizing, pathMTU))

	// The CreateAck must already publish the floor, because a host that has not
	// yet set its interface MTU reads it from here.
	ack := client.ack(t)
	if ack.InnerMTU != sizing.InnerMTU || ack.MessageSize != sizing.MessageSize {
		t.Fatalf("CreateAck published inner_mtu=%d message_size=%d, want %d/%d",
			ack.InnerMTU, ack.MessageSize, sizing.InnerMTU, sizing.MessageSize)
	}
	if ack.PromotionReady {
		t.Fatal("the tunnel offered promotion before a single packet had arrived")
	}
	if ack.SessionID != "e2e" {
		t.Fatalf("CreateAck session_id = %q", ack.SessionID)
	}
	_ = gateway.ack(t)

	// --- 1. a full-size inner packet, both ways ---------------------------------

	full := make([]byte, sizing.InnerMTU-28)
	for i := range full {
		full[i] = byte(i * 31)
	}
	wantDigest := digestOf(full)

	// The handshake needs a few round trips; the first packets may be offered
	// while the gate is still closed and are dropped fail-closed by design. So
	// the send is retried rather than assumed, which is also what a host does.
	got := carryPacket(t, client, gateway, ipv4Packet(
		[4]byte{10, 8, 1, 3}, [4]byte{10, 8, 1, 1}, full), 45*time.Second)
	if d := digestOf(payloadOf(got)); d != wantDigest {
		t.Fatalf("full-size packet arrived with digest %s, want %s", d, wantDigest)
	}
	if len(got) != sizing.InnerMTU {
		t.Fatalf("full-size packet arrived as %d bytes, want the %d-byte floor inner MTU",
			len(got), sizing.InnerMTU)
	}

	reply := []byte("winn3 frame seam reply")
	back := carryPacket(t, gateway, client, ipv4Packet(
		[4]byte{10, 8, 1, 1}, [4]byte{10, 8, 1, 3}, reply), 20*time.Second)
	if d := digestOf(payloadOf(back)); d != digestOf(reply) {
		t.Fatal("the reply digest does not match")
	}

	// --- 2. the promotion gate ---------------------------------------------------

	status := client.status(t)
	if !status.PromotionReady {
		t.Fatalf("a delivered inner packet did not open the promotion gate: %+v", status)
	}
	if status.GateState != tun.StateCarrying.String() {
		t.Fatalf("gate_state = %q, want %q", status.GateState, tun.StateCarrying)
	}
	if status.RxPackets == 0 {
		t.Fatal("promotion_ready is true with rx_packets at zero")
	}
	if status.Posture != winn3PostureFull {
		t.Fatalf("posture = %q, want %q", status.Posture, winn3PostureFull)
	}
	// rx_offered is published NEXT TO rx_packets and never instead of it: the
	// Android parser refuses a document that reports arrivals without
	// deliveries, so a status missing rx_packets would refuse a working tunnel.
	if status.RxOffered < status.RxPackets {
		t.Fatalf("rx_offered %d is below rx_packets %d", status.RxOffered, status.RxPackets)
	}

	// --- 3. a rekey, with traffic across the ratchet -------------------------------

	// rekey_after_messages is 8 in the client's key document, so a handful of
	// packets crosses the volume trigger. The knob can only tighten; see
	// TestTheRekeyKnobOnlyTightens.
	startEpoch := client.loop(t).Session().Epoch()
	for i := range 24 {
		client.inboundPacket(t, ipv4Packet(
			[4]byte{10, 8, 1, 3}, [4]byte{10, 8, 1, 1},
			[]byte(fmt.Sprintf("volume %d", i))))
		time.Sleep(20 * time.Millisecond)
	}
	waitUntil(t, 45*time.Second, "a completed rekey at both ends", func() bool {
		return client.loop(t).Session().Stats().Rekeys > 0 &&
			gateway.loop(t).Session().Stats().Rekeys > 0
	})
	if epoch := client.loop(t).Session().Epoch(); epoch == startEpoch {
		t.Fatalf("the client epoch is still %d after a rekey", epoch)
	}
	gateway.drain()

	acrossRatchet := []byte("carried across the ratchet")
	got = carryPacket(t, client, gateway, ipv4Packet(
		[4]byte{10, 8, 1, 3}, [4]byte{10, 8, 1, 1}, acrossRatchet), 30*time.Second)
	if d := digestOf(payloadOf(got)); d != digestOf(acrossRatchet) {
		t.Fatal("nothing survived the ratchet with a matching digest")
	}
	t.Logf("across the ratchet: client rekeys=%d epoch=%d",
		client.loop(t).Session().Stats().Rekeys, client.loop(t).Session().Epoch())

	// --- 4. a carrier migration ----------------------------------------------------

	// Both ends move to a fresh pair of loopback sockets, exactly as
	// winn3/driver's own end-to-end test does. The message size handed to the
	// replacement carrier is the PLAN FLOOR again and not the new socket's own
	// ceiling, which is what Loop.Migrate asserts.
	newClientSock, newClientAddr := loopbackSocket(t)
	newGatewaySock, newGatewayAddr := loopbackSocket(t)

	clientCarrier := newLoopbackCarrier(t, newClientSock, newGatewayAddr, sizing)
	gatewayCarrier := newLoopbackCarrier(t, newGatewaySock, newClientAddr, sizing)

	oldClient := client.loop(t).Carrier()
	oldGateway := gateway.loop(t).Carrier()
	if _, err := gateway.loop(t).Migrate(gatewayCarrier); err != nil {
		t.Fatalf("the gateway refused to migrate: %v", err)
	}
	if _, err := client.loop(t).Migrate(clientCarrier); err != nil {
		t.Fatalf("the client refused to migrate: %v", err)
	}
	_ = oldClient.Close()
	_ = oldGateway.Close()
	gateway.drain()

	afterMigration := []byte("carried after the carrier moved")
	got = carryPacket(t, client, gateway, ipv4Packet(
		[4]byte{10, 8, 1, 3}, [4]byte{10, 8, 1, 1}, afterMigration), 30*time.Second)
	if d := digestOf(payloadOf(got)); d != digestOf(afterMigration) {
		t.Fatal("nothing survived the migration with a matching digest")
	}
	if m := client.loop(t).Stats().Migrations; m != 1 {
		t.Fatalf("client migrations = %d, want 1", m)
	}

	// A full-size packet AFTER the migration is the one that a tunnel sized to
	// the dialled carrier black-holes. It is the last thing checked because it
	// is the failure the floor exists to prevent.
	got = carryPacket(t, client, gateway, ipv4Packet(
		[4]byte{10, 8, 1, 3}, [4]byte{10, 8, 1, 1}, full), 30*time.Second)
	if d := digestOf(payloadOf(got)); d != wantDigest {
		t.Fatal("the full-size packet did not survive the migration")
	}

	// --- 5. an orderly close --------------------------------------------------------

	final := client.status(t)
	t.Logf("client final: %+v", final)
	client.close(t)
	gateway.close(t)
}

// TestAFrameSessionRefusesRatherThanRelaying is the fail-closed property.
//
// A create this mode cannot honour produces an Error frame and NO tunnel. What
// it must never produce is an AmneziaWG relay, because a session the gateway
// negotiated as winn/3 running as classical AWG with nobody told is the silent
// downgrade found in the Apple providers.
func TestAFrameSessionRefusesRatherThanRelaying(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ring := newFrameKeyring(t)
	sock, addr := loopbackSocket(t)
	engine := startFrameEngine(t, ctx, ring.clientKeys, handOver(t, sock))

	sizing, err := driver.NewSizing(1500, mustClasses(t, "udp", "tcp", "tls")...)
	if err != nil {
		t.Fatal(err)
	}
	document := frameCreate(addr, "10.8.1.3", "10.8.1.1", sizing, 1500)
	var decoded map[string]any
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded["payload"] = "awg-datagram"
	relay, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}

	engine.send(t, duplex.OpCreate, relay)
	refusal := engine.errorFrame(t, 10*time.Second)
	if refusal == "" {
		t.Fatal("an awg-datagram create produced no Error frame")
	}
	t.Logf("refusal: %s", refusal)
	if engine.server.currentLoop() != nil {
		t.Fatal("a refused create left a tunnel behind")
	}

	// And the channel is still usable: a refusal is not a session failure, so
	// the correct document that follows it works.
	engine.create(t, document)
	if ack := engine.ack(t); ack.InnerMTU != sizing.InnerMTU {
		t.Fatalf("the retry after a refusal did not build: %+v", ack)
	}
	engine.close(t)
}

// TestASecondCreateIsRefused. One session carries exactly one tunnel; a second
// create that replaced the first would leave the host pumping into a device the
// engine had dropped.
func TestASecondCreateIsRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ring := newFrameKeyring(t)
	sock, addr := loopbackSocket(t)
	engine := startFrameEngine(t, ctx, ring.clientKeys, handOver(t, sock))

	sizing, err := driver.NewSizing(1500, mustClasses(t, "udp", "tcp", "tls")...)
	if err != nil {
		t.Fatal(err)
	}
	document := frameCreate(addr, "10.8.1.3", "10.8.1.1", sizing, 1500)
	engine.create(t, document)
	_ = engine.ack(t)

	first := engine.server.currentLoop()
	engine.send(t, duplex.OpCreate, document)
	if refusal := engine.errorFrame(t, 10*time.Second); refusal == "" {
		t.Fatal("a second create was not refused")
	}
	if engine.server.currentLoop() != first {
		t.Fatal("a second create replaced the live tunnel")
	}
	engine.close(t)
}

// TestAnInboundPacketBeforeCreateIsRefused. Without this the device would be
// nil and the engine would panic on the first frame a confused host sent.
func TestAnInboundPacketBeforeCreateIsRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ring := newFrameKeyring(t)
	engine := startFrameEngine(t, ctx, ring.clientKeys, -1)
	engine.send(t, duplex.OpInbound, []byte{0x45, 0x00})
	if refusal := engine.errorFrame(t, 10*time.Second); refusal == "" {
		t.Fatal("an inbound packet before create was not refused")
	}

	// And StatusRequest before create is answered rather than refused, with the
	// bootstrap posture: a host must be able to ask, and the answer must never
	// be one that widens anything.
	engine.send(t, duplex.OpStatusRequest, nil)
	status := engine.statusFrame(t, 10*time.Second)
	if status.PromotionReady || status.Posture != winn3PostureBootstrap {
		t.Fatalf("a pre-create status was not the bootstrap posture: %+v", status)
	}
	engine.close(t)
}

// --- fixture -------------------------------------------------------------------

type frameKeyring struct {
	clientKeys  winn3Keys
	gatewayKeys winn3Keys

	// The document paths, for the subprocess proof, which passes -winn3-keys on
	// argv rather than holding a parsed struct.
	clientPath  string
	gatewayPath string
}

// newFrameKeyring writes real key files and loads them through the SHIPPING
// parser, so the fixture exercises the document path a host uses rather than a
// struct the parser would have refused.
func newFrameKeyring(t *testing.T) frameKeyring {
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
	admission := write("admission.key", []byte("winn3-frame-e2e-admission-secret-0123456789"))

	paths := map[string]string{}
	load := func(name string, document map[string]any) winn3Keys {
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		keys, err := loadWinn3Keys(path)
		if err != nil {
			t.Fatal(err)
		}
		paths[name] = path
		return keys
	}

	ring := frameKeyring{
		clientKeys: load("client.json", map[string]any{
			"version":             winn3KeysVersion,
			"role":                winn3RoleClient,
			"gateway_id":          "winn3-frame-e2e",
			"static_path":         write("client.key", clientStatic.Bytes()),
			"gateway_static_path": write("gateway.pub", gatewayStatic.Public()),
			"admission_path":      admission,
			// Low enough that the volume trigger fires inside a test rather than
			// after 2^28 messages. Only ever downward; see the field's doc.
			"rekey_after_messages": 8,
		}),
		gatewayKeys: load("gateway.json", map[string]any{
			"version":        winn3KeysVersion,
			"role":           winn3RoleGateway,
			"gateway_id":     "winn3-frame-e2e",
			"static_path":    write("gateway.key", gatewayStatic.Bytes()),
			"admission_path": admission,
		}),
	}
	ring.clientPath = paths["client.json"]
	ring.gatewayPath = paths["gateway.json"]
	return ring
}

// frameCreate builds a create document that satisfies the floor rule.
func frameCreate(
	peer *net.UDPAddr, inner, nextHop string, sizing driver.Sizing, pathMTU int,
) []byte {
	document := map[string]any{
		"payload":          "ip-packet",
		"gateway_endpoint": peer.String(),
		"inner_address":    inner,
		"inner_next_hop":   nextHop,
		"inner_mtu":        sizing.InnerMTU,
		"path_mtu":         pathMTU,
		"carrier_classes":  []string{"udp", "tcp", "tls"},
		"session_id":       "e2e",
		"allow_own_socket": false,
		"owns_tun":         false,
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return encoded
}

// loopbackSocket binds 127.0.0.1 on an ephemeral port. Loopback explicitly and
// never a wildcard: a wildcard bind would put this test on every interface this
// machine has.
func loopbackSocket(t *testing.T) (*net.UDPConn, *net.UDPAddr) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), Port: 0,
	})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("loopback socket has no UDP address")
	}
	return conn, addr
}

// handOver turns a bound socket into a bare descriptor, which is what
// VpnService.protect + SCM_RIGHTS delivers to the engine.
//
// The dup is taken from the *os.File conn.File() returns and the file is then
// closed, so exactly one descriptor is left for the engine to own: the engine
// wraps it with os.NewFile and net.FilePacketConn, which dups again and closes
// the original. A test that passed file.Fd() directly would double-close.
func handOver(t *testing.T, conn *net.UDPConn) int {
	t.Helper()
	file, err := conn.File()
	if err != nil {
		t.Fatalf("cannot take a descriptor from the loopback socket: %v", err)
	}
	descriptor, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	_ = file.Close()
	_ = conn.Close()
	return descriptor
}

// newLoopbackCarrier wraps a bound socket at the PLAN FLOOR.
func newLoopbackCarrier(
	t *testing.T, conn *net.UDPConn, peer *net.UDPAddr, sizing driver.Sizing,
) carrier.Conn {
	t.Helper()
	c, err := carrier.NewUDP(carrier.UDPConfig{
		Conn: conn, Peer: peer, OwnsConn: true,
		MaxMessageSize: sizing.MessageSize, PathMTU: sizing.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// frameEngine is one engine plus the host half of its frame channel.
type frameEngine struct {
	server *winn3FrameServer
	stream net.Conn
	writer *duplex.Writer

	acks     chan winn3Status
	statuses chan winn3Status
	errs     chan string
	inbound  chan []byte
	closeAck chan struct{}

	served   chan error
	stopOnce sync.Once
}

// startFrameEngine runs one winn3FrameServer over an in-memory stream pair.
//
// net.Pipe rather than a socketpair because the frame channel's transport is not
// what is under test here — the payload semantics are — and a synchronous pipe
// makes an accidental deadlock in the pump visible immediately instead of hiding
// it behind a kernel buffer.
func startFrameEngine(
	t *testing.T, ctx context.Context, keys winn3Keys, descriptor int,
) *frameEngine {
	t.Helper()
	hostSide, engineSide := net.Pipe()
	engine := &frameEngine{
		server:   newWinn3FrameServer(keys, descriptor, engineSide),
		stream:   hostSide,
		writer:   duplex.NewWriter(hostSide),
		acks:     make(chan winn3Status, 8),
		statuses: make(chan winn3Status, 64),
		errs:     make(chan string, 64),
		inbound:  make(chan []byte, 512),
		closeAck: make(chan struct{}, 1),
		served:   make(chan error, 1),
	}

	go func() {
		err := engine.server.serve(ctx, engineSide)
		engine.server.shutdown()
		_ = engineSide.Close()
		engine.served <- err
	}()
	go engine.readFrames()

	t.Cleanup(func() { engine.stop() })
	return engine
}

// readFrames is the host's dedicated reader. true: a host accepts
// engine-to-host opcodes.
func (e *frameEngine) readFrames() {
	reader := duplex.NewReader(e.stream, true)
	for {
		opcode, payload, err := reader.Read()
		if err != nil {
			return
		}
		switch opcode {
		case duplex.OpCreateAck, duplex.OpStatusResponse:
			var status winn3Status
			if json.Unmarshal(payload, &status) != nil {
				continue
			}
			sink := e.statuses
			if opcode == duplex.OpCreateAck {
				sink = e.acks
			}
			select {
			case sink <- status:
			default:
			}
		case duplex.OpOutbound:
			select {
			case e.inbound <- append([]byte(nil), payload...):
			default:
			}
		case duplex.OpError:
			select {
			case e.errs <- string(payload):
			default:
			}
		case duplex.OpCloseAck:
			select {
			case e.closeAck <- struct{}{}:
			default:
			}
		}
	}
}

func (e *frameEngine) send(t *testing.T, opcode duplex.Opcode, payload []byte) {
	t.Helper()
	if err := e.writer.Write(opcode, payload); err != nil {
		t.Fatalf("write %s frame: %v", opcode, err)
	}
}

func (e *frameEngine) create(t *testing.T, document []byte) {
	t.Helper()
	e.send(t, duplex.OpCreate, document)
}

func (e *frameEngine) inboundPacket(t *testing.T, packet []byte) {
	t.Helper()
	e.send(t, duplex.OpInbound, packet)
}

func (e *frameEngine) ack(t *testing.T) winn3Status {
	t.Helper()
	select {
	case status := <-e.acks:
		return status
	case refusal := <-e.errs:
		t.Fatalf("create was refused: %s", refusal)
	case <-time.After(30 * time.Second):
		t.Fatal("no CreateAck within 30s")
	}
	return winn3Status{}
}

func (e *frameEngine) status(t *testing.T) winn3Status {
	t.Helper()
	e.send(t, duplex.OpStatusRequest, nil)
	return e.statusFrame(t, 15*time.Second)
}

func (e *frameEngine) statusFrame(t *testing.T, within time.Duration) winn3Status {
	t.Helper()
	select {
	case status := <-e.statuses:
		return status
	case <-time.After(within):
		t.Fatalf("no StatusResponse within %s", within)
	}
	return winn3Status{}
}

func (e *frameEngine) errorFrame(t *testing.T, within time.Duration) string {
	t.Helper()
	select {
	case refusal := <-e.errs:
		return refusal
	case <-time.After(within):
		return ""
	}
}

func (e *frameEngine) loop(t *testing.T) *driver.Loop {
	t.Helper()
	loop := e.server.currentLoop()
	if loop == nil {
		t.Fatal("no tunnel")
	}
	return loop
}

// drain empties whatever is already queued, so a later assertion is about the
// packet it sent and not about one still in flight from an earlier step.
func (e *frameEngine) drain() {
	for {
		select {
		case <-e.inbound:
		default:
			return
		}
	}
}

func (e *frameEngine) close(t *testing.T) {
	t.Helper()
	e.send(t, duplex.OpClose, nil)
	select {
	case <-e.closeAck:
	case <-time.After(15 * time.Second):
		t.Fatal("no CloseAck within 15s")
	}
	select {
	case err := <-e.served:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("serve returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not return after CloseAck")
	}
}

func (e *frameEngine) stop() {
	e.stopOnce.Do(func() {
		_ = e.stream.Close()
		e.server.shutdown()
	})
}

// carryPacket offers one inner packet and waits for it at the far side,
// retrying while the handshake completes.
//
// Retried rather than assumed because a packet offered before the gate opens is
// DROPPED FAIL-CLOSED by design: the tun layer refuses to move an inner packet
// until the session says DATA may flow, and a test that treated that as a
// failure would be asserting the opposite of the property.
func carryPacket(
	t *testing.T, from, to *frameEngine, packet []byte, within time.Duration,
) []byte {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		from.inboundPacket(t, packet)
		select {
		case got := <-to.inbound:
			return got
		case <-time.After(400 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing reached the far host within %s (gate=%q)",
				within, from.status(t).GateState)
		}
	}
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// TestTheHandedOverDescriptorIsCheckedNotTrusted.
//
// A host that sends the wrong descriptor — a stream socket, a pipe, a closed
// number — must be told, not have the engine build a carrier over something that
// cannot carry datagrams. The failure mode of trusting it is a tunnel that
// establishes nothing and reports no reason.
func TestTheHandedOverDescriptorIsCheckedNotTrusted(t *testing.T) {
	ring := newFrameKeyring(t)

	sizing, err := driver.NewSizing(1500, mustClasses(t, "udp", "tcp", "tls")...)
	if err != nil {
		t.Fatal(err)
	}
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51820}
	document := frameCreate(peer, "10.8.1.3", "10.8.1.1", sizing, 1500)

	// A TCP listener's descriptor. It is a real, open, valid socket, which is
	// what makes it the interesting wrong answer.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot open a loopback stream socket: %v", err)
	}
	defer func() { _ = listener.Close() }()
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		t.Fatal("not a TCP listener")
	}
	file, err := tcpListener.File()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()

	server := newWinn3FrameServer(ring.clientKeys, descriptor, io.Discard)
	err = server.open(t.Context(), document)
	if err == nil {
		server.shutdown()
		t.Fatal("a stream socket was accepted as the outer carrier")
	}
	if !strings.Contains(err.Error(), "descriptor handed over") {
		t.Fatalf("refusal %v does not name the descriptor", err)
	}

	// A number that is not a descriptor at all.
	server = newWinn3FrameServer(ring.clientKeys, 1<<20, io.Discard)
	if err := server.open(t.Context(), document); err == nil {
		server.shutdown()
		t.Fatal("a bogus descriptor number was accepted")
	}
}

// TestTheEngineDialsOnlyWhenTheHostSaysItMay is the desktop half of the socket
// rule, exercised against a real loopback socket.
func TestTheEngineDialsOnlyWhenTheHostSaysItMay(t *testing.T) {
	ring := newFrameKeyring(t)
	sizing, err := driver.NewSizing(1500, mustClasses(t, "udp", "tcp", "tls")...)
	if err != nil {
		t.Fatal(err)
	}
	_, peer := loopbackSocket(t)

	var document map[string]any
	if err := json.Unmarshal(
		frameCreate(peer, "10.8.1.3", "10.8.1.1", sizing, 1500), &document,
	); err != nil {
		t.Fatal(err)
	}
	document["allow_own_socket"] = true
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	// The key document declares no exclusion, so this must be refused even
	// though nothing about the socket itself is wrong.
	server := newWinn3FrameServer(ring.clientKeys, -1, io.Discard)
	if err := server.open(t.Context(), encoded); err == nil {
		server.shutdown()
		t.Fatal("the engine opened its own socket with no exclusion declared")
	}

	// With an exclusion declared it dials, and the tunnel builds.
	declared := ring.clientKeys
	declared.OuterSocketExclusion = "fwmark 0x51820 lookup main"
	server = newWinn3FrameServer(declared, -1, io.Discard)
	if err := server.open(t.Context(), encoded); err != nil {
		t.Fatalf("a declared exclusion did not permit an own socket: %v", err)
	}
	defer server.shutdown()
	if server.currentLoop() == nil {
		t.Fatal("no tunnel was built")
	}
	// And the exclusion the host declared is echoed next to the counters, so
	// the claim is auditable rather than merely made.
	var status winn3Status
	if err := json.Unmarshal([]byte(server.statusJSON("posture")), &status); err != nil {
		t.Fatal(err)
	}
	if status.OuterSocketExclusion != declared.OuterSocketExclusion {
		t.Fatalf("the status does not echo the exclusion: %+v", status)
	}
}

// TestPromotionIsGatedOnDeliveriesAndNotOnArrivals.
//
// This is the substitution a sibling lane caught in this protocol today, made
// behavioural rather than structural. RxOffered counts payloads HANDED to the
// tun layer and RxPackets counts inner packets it VALIDATED and delivered to the
// host device. A gate built on the first promotes a tunnel on a packet the
// inner-IP validator rejected — one addressed to somebody else, from a martian
// source, or of a family this tunnel was never assigned.
//
// So this drives the two counters APART on purpose: every packet the client
// sends is addressed to an inner address the gateway does not own, so the
// gateway's validator refuses all of them. Its gate reaches carrying and its
// rx_offered climbs, and promotion_ready must stay FALSE the whole time.
//
// A mutant that reads RxOffered here passes every other test in this package,
// because in the ordinary case the two counters are equal.
func TestPromotionIsGatedOnDeliveriesAndNotOnArrivals(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ring := newFrameKeyring(t)
	sizing, err := driver.NewSizing(1500, mustClasses(t, "udp", "tcp", "tls")...)
	if err != nil {
		t.Fatal(err)
	}

	clientSock, clientAddr := loopbackSocket(t)
	gatewaySock, gatewayAddr := loopbackSocket(t)
	client := startFrameEngine(t, ctx, ring.clientKeys, handOver(t, clientSock))
	gateway := startFrameEngine(t, ctx, ring.gatewayKeys, handOver(t, gatewaySock))

	client.create(t, frameCreate(gatewayAddr, "10.8.1.3", "10.8.1.1", sizing, 1500))
	gateway.create(t, frameCreate(clientAddr, "10.8.1.1", "10.8.1.3", sizing, 1500))
	_ = client.ack(t)
	_ = gateway.ack(t)

	// 10.9.9.9 is not the gateway's inner address, so every one of these is an
	// arrival the validator refuses.
	misdirected := ipv4Packet(
		[4]byte{10, 8, 1, 3}, [4]byte{10, 9, 9, 9}, []byte("addressed to nobody"))
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		client.inboundPacket(t, misdirected)
		time.Sleep(50 * time.Millisecond)
		stats := gateway.loop(t).Tunnel().Stats()
		if stats.RxOffered > 0 {
			break
		}
	}

	stats := gateway.loop(t).Tunnel().Stats()
	if stats.RxOffered == 0 {
		t.Skip("no payload was offered to the gateway's tun layer; the two " +
			"counters were never driven apart, so this proves nothing")
	}
	if stats.RxPackets != 0 {
		t.Fatalf("the gateway DELIVERED %d packets addressed to 10.9.9.9; the "+
			"inner-IP validator is not refusing them and this test cannot "+
			"distinguish the counters", stats.RxPackets)
	}

	status := gateway.status(t)
	if status.RxOffered == 0 {
		t.Fatal("the status document does not publish rx_offered")
	}
	if status.RxPackets != 0 {
		t.Fatalf("the status reports rx_packets=%d with none delivered", status.RxPackets)
	}
	if status.PromotionReady {
		t.Fatalf("PROMOTION WAS OFFERED ON AN ARRIVAL, NOT A DELIVERY: "+
			"rx_offered=%d rx_packets=%d gate=%q",
			status.RxOffered, status.RxPackets, status.GateState)
	}
	if status.Posture != winn3PostureBootstrap {
		t.Fatalf("posture = %q with nothing delivered", status.Posture)
	}
	t.Logf("counters driven apart: rx_offered=%d rx_packets=%d dropped_invalid=%d gate=%q",
		status.RxOffered, status.RxPackets, stats.RxDroppedInvalid, status.GateState)
}

// TestTheCarrierIsBuiltAtThePlanFloorAndNotItsOwnCeiling.
//
// carrier.NewUDP defaults MaxMessageSize to the ceiling for the RESOLVED FAMILY
// at the path MTU — 1452 for UDP over IPv4 at 1500 — when it is handed zero.
// The plan floor over udp+tcp+tls at the same path MTU is 1388. Handing the
// carrier its own ceiling is inert while the session is separately pinned, which
// is precisely why it would survive every other test here: it removes a guard
// without removing a behaviour, and the behaviour comes back the moment anything
// sizes a message from the carrier instead of from the plan.
func TestTheCarrierIsBuiltAtThePlanFloorAndNotItsOwnCeiling(t *testing.T) {
	ring := newFrameKeyring(t)
	sizing, err := driver.NewSizing(1500, mustClasses(t, "udp", "tcp", "tls")...)
	if err != nil {
		t.Fatal(err)
	}
	sock, addr := loopbackSocket(t)

	server := newWinn3FrameServer(ring.clientKeys, handOver(t, sock), io.Discard)
	if err := server.open(t.Context(),
		frameCreate(addr, "10.8.1.3", "10.8.1.1", sizing, 1500)); err != nil {
		t.Fatal(err)
	}
	defer server.shutdown()

	built := server.currentLoop().Carrier()
	if got := built.MaxMessageSize(); got != sizing.MessageSize {
		t.Fatalf("the carrier was built at %d and the plan floor is %d: "+
			"a carrier sized to the class it dialled is the 84-byte black hole",
			got, sizing.MessageSize)
	}
	// And the number is genuinely below what this class alone would allow, so
	// the assertion above is not accidentally true.
	own := carrier.MaxMessageSizeFor(carrier.ClassUDP, carrier.FamilyIPv4, sizing.PathMTU)
	if own <= sizing.MessageSize {
		t.Fatalf("this plan's floor %d is not below the dialled class's own "+
			"ceiling %d; the test has stopped testing anything",
			sizing.MessageSize, own)
	}
}
