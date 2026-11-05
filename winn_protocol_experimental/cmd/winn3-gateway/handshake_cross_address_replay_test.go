package main

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
)

// TestACapturedInitiationReplayedFromASecondAddressIsSilent is the §4.3
// property the library already pins and this binary does not.
//
// winn3/gateway.Handle uses one core.Responder for the process. Its replay
// cache is keyed on the initiation body, not the source address, so
// TestHandshakeReplayObservability S1 requires silence from both the recorded
// source and an attacker-chosen source.
//
// This binary does not call Gateway.Handle. server.sessionFor indexes
// server.peers by netip.AddrPort and newSession calls driver.NewGateway, which
// builds a fresh core.Responder (empty replay cache) per address. A captured
// initiation replayed from a second UDP source is therefore a first sighting
// at a new Responder: ReadInitiation succeeds, WriteResponse runs, and
// Pipe.Send writes a handshake reply to the attacker. That is a gateway
// detector. A v3 gateway that answers a replayed initiation is a gateway a
// censor can find by sending it one.
//
// Three controls, all on the same captured bytes:
//
//   - GREEN: the first delivery from source A must elicit a reply. If this
//     fails, the harness never reached the handshake and everything below
//     would pass for the wrong reason.
//   - SAME-SOURCE: replaying those bytes from A must stay silent. That is the
//     per-Responder cache doing its job, and it must keep working even if the
//     cross-address path is broken.
//   - OTHER-SOURCE: replaying those bytes from B must stay silent AND must
//     not construct a second session. That is the property this binary is
//     missing.
func TestACapturedInitiationReplayedFromASecondAddressIsSilent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	sessionCfg, err := buildSessionConfig(serveOptions{
		staticPath: filepath.Join(dir, "static.key"),
		admission:  filepath.Join(dir, "admission.key"),
		gatewayID:  testGatewayID,
	})
	if err != nil {
		t.Fatal(err)
	}
	assign, err := parseAssignment(testGatewayInner, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	defer conn.Close()

	srv := &server{
		conn:        conn,
		sizing:      sizing,
		sessionCfg:  sessionCfg,
		assign:      assign,
		maxSessions: 8,
		peers:       make(map[netip.AddrPort]*peerSession),
	}
	readDone := make(chan error, 1)
	go func() { readDone <- srv.readLoop(ctx) }()
	defer func() {
		_ = conn.SetReadDeadline(time.Now())
		<-readDone
		srv.closeAll()
	}()

	initMsg := capturedInitiation(t, dir, sessionCfg)
	gwAddr := conn.LocalAddr().(*net.UDPAddr)

	srcA, err := net.DialUDP("udp4", nil, gwAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer srcA.Close()
	if _, err := srcA.Write(initMsg); err != nil {
		t.Fatal(err)
	}

	// GREEN: a fresh authenticated initiation must emit a byte.
	reply := readDatagram(t, srcA, 10*time.Second)
	if len(reply) == 0 {
		t.Fatal("GREEN control: a fresh authenticated initiation produced no reply; the harness never reached the handshake")
	}
	waitFor(t, 10*time.Second, "the gateway to hold the first session", func() bool {
		st := srv.status()
		return st.Sessions == 1 && st.Built == 1
	})
	afterFirst := srv.status()
	if afterFirst.Sessions != 1 || afterFirst.Built != 1 {
		t.Fatalf("GREEN control: after one initiation, sessions=%d built=%d, want 1/1",
			afterFirst.Sessions, afterFirst.Built)
	}

	// SAME-SOURCE: the per-Responder replay cache must refuse the copy.
	if _, err := srcA.Write(initMsg); err != nil {
		t.Fatal(err)
	}
	if got := readDatagramOrTimeout(t, srcA, 2*time.Second); got != nil {
		t.Fatalf("SAME-SOURCE replay: the gateway answered %d bytes; a replayed initiation must be silent", len(got))
	}
	same := srv.status()
	if same.Sessions != 1 || same.Built != 1 {
		t.Fatalf("SAME-SOURCE replay constructed a new session: sessions %d -> %d, built %d -> %d",
			afterFirst.Sessions, same.Sessions, afterFirst.Built, same.Built)
	}

	// OTHER-SOURCE: the process-wide property. A second AddrPort must not
	// get its own empty replay cache.
	srcB, err := net.DialUDP("udp4", nil, gwAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer srcB.Close()
	if _, err := srcB.Write(initMsg); err != nil {
		t.Fatal(err)
	}
	if got := readDatagramOrTimeout(t, srcB, 3*time.Second); got != nil {
		t.Fatalf("OTHER-SOURCE replay: the gateway answered %d bytes to a captured initiation from a second UDP source. "+
			"cmd/winn3-gateway builds a fresh core.Responder per AddrPort (driver.NewGateway), so the replay cache is partitioned by source address. "+
			"winn3/gateway.Handle does not: TestHandshakeReplayObservability S1 requires silence from an attacker-chosen source. "+
			"A reply here is a gateway detector", len(got))
	}
	after := srv.status()
	if after.Sessions != 1 || after.Built != 1 {
		t.Fatalf("OTHER-SOURCE replay allocated a second session: sessions %d -> %d, built %d -> %d. "+
			"The replay cache is per-Responder and this binary constructs one Responder per AddrPort",
			afterFirst.Sessions, after.Sessions, afterFirst.Built, after.Built)
	}
}

// TestAFreshInitiationFromASecondAddressIsStillAdmitted is the other half of
// the property above, and the reason the fix for it is what it is.
//
// The obvious way to make a replayed initiation silent from a second address is
// to key admission on the source address — "I have already served this client,
// ignore it elsewhere". That would be a bug wearing a fix's clothes. Clients
// roam: a phone moves from Wi-Fi to cellular, a CGNAT rebinds a UDP port, a
// laptop wakes on a new network. Every one of those re-initiates from an
// address the gateway has never seen, and a gateway that answered such a client
// with silence would be broken for exactly the mobile users this protocol
// exists to serve — and broken invisibly, because silence is also what a censor
// looks like.
//
// So the two requirements are:
//
//   - a BIT-IDENTICAL replay from any address is silent (the test above)
//   - a FRESH initiation from any address is answered (this test)
//
// They do not conflict, and the reason they do not is that core's replay cache
// is keyed on SHA-256 of the recovered initiation body, which carries a
// per-handshake ephemeral public key. Two initiations from the same client
// static key differ in that ephemeral, so they hash differently. "Already seen"
// therefore means "these exact bytes", never "this client" and never "this
// address".
//
// This test would fail against any address-keyed or client-keyed
// implementation, which is precisely why it is here.
func TestAFreshInitiationFromASecondAddressIsStillAdmitted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	sessionCfg, err := buildSessionConfig(serveOptions{
		staticPath: filepath.Join(dir, "static.key"),
		admission:  filepath.Join(dir, "admission.key"),
		gatewayID:  testGatewayID,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The shared responder is the fix under test. Without it each address gets
	// its own replay cache and the sibling test above fails; with it, this test
	// is what proves the sharing did not cost a roaming client its session.
	if sessionCfg.Responder == nil {
		t.Fatal("buildSessionConfig returned no shared responder; the cross-address replay cache is partitioned again")
	}
	assign, err := parseAssignment(testGatewayInner, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	defer conn.Close()

	srv := &server{
		conn:        conn,
		sizing:      sizing,
		sessionCfg:  sessionCfg,
		assign:      assign,
		maxSessions: 8,
		peers:       make(map[netip.AddrPort]*peerSession),
	}
	readDone := make(chan error, 1)
	go func() { readDone <- srv.readLoop(ctx) }()
	defer func() {
		_ = conn.SetReadDeadline(time.Now())
		<-readDone
		srv.closeAll()
	}()

	gwAddr := conn.LocalAddr().(*net.UDPAddr)

	// Two initiations from the SAME client static key, drawn separately, so
	// they differ only in the per-handshake ephemeral — which is exactly what a
	// roam looks like on the wire.
	first := capturedInitiation(t, dir, sessionCfg)
	second := capturedInitiation(t, dir, sessionCfg)
	if bytes.Equal(first, second) {
		t.Fatal("two separately drawn initiations are byte-identical; the ephemeral is not fresh and this test proves nothing")
	}

	srcA, err := net.DialUDP("udp4", nil, gwAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer srcA.Close()
	if _, err := srcA.Write(first); err != nil {
		t.Fatal(err)
	}
	if reply := readDatagram(t, srcA, 10*time.Second); len(reply) == 0 {
		t.Fatal("the first initiation produced no reply")
	}
	waitFor(t, 10*time.Second, "the gateway to hold the first session", func() bool {
		st := srv.status()
		return st.Sessions == 1 && st.Built == 1
	})

	// The roam: a different socket, therefore a different AddrPort, carrying a
	// DIFFERENT initiation from the same client.
	srcB, err := net.DialUDP("udp4", nil, gwAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer srcB.Close()
	if _, err := srcB.Write(second); err != nil {
		t.Fatal(err)
	}
	reply := readDatagramOrTimeout(t, srcB, 10*time.Second)
	if len(reply) == 0 {
		t.Fatal("ROAM: a FRESH initiation from a second address got silence. The replay defence has been " +
			"keyed on something other than the initiation body — an address or a client identity — and every " +
			"roaming client is now refused in a way indistinguishable from a censored path")
	}
	waitFor(t, 10*time.Second, "the roamed client to get its own session", func() bool {
		st := srv.status()
		return st.Sessions == 2 && st.Built == 2
	})
	st := srv.status()
	if st.Sessions != 2 || st.Built != 2 {
		t.Fatalf("after a legitimate roam: sessions=%d built=%d, want 2/2", st.Sessions, st.Built)
	}
	// And the roam must not have been counted as an attack.
	if st.Replays != 0 {
		t.Fatalf("replayed_initiations = %d after a legitimate roam, want 0: a fresh initiation "+
			"was misread as a replay", st.Replays)
	}
}

// TestNoConstructionPathReachesASessionWithoutTheSharedResponder closes the
// CLASS rather than the instance.
//
// The two tests above prove this binary behaves correctly today. Neither would
// notice a future edit that reintroduced an unshared config on some path they
// do not exercise — and such an edit fails nothing visible: the gateway serves
// every legitimate client perfectly and is merely findable by anyone holding
// one captured initiation. Silent, remote, permanent. That is the worst shape a
// defect can have in this product, so the invariant is asserted directly at
// each of the three gates that enforce it.
func TestNoConstructionPathReachesASessionWithoutTheSharedResponder(t *testing.T) {
	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	opts := serveOptions{
		staticPath: filepath.Join(dir, "static.key"),
		admission:  filepath.Join(dir, "admission.key"),
		gatewayID:  testGatewayID,
	}

	// GATE 1: the constructor every path in this package uses always installs
	// one. If this regresses, every other gate below is load-bearing.
	good, err := buildSessionConfig(opts)
	if err != nil {
		t.Fatal(err)
	}
	if good.Responder == nil {
		t.Fatal("buildSessionConfig returned a config with no shared handshake responder; " +
			"every peer address would get its own empty replay cache and a captured " +
			"initiation replayed from a second address would be answered")
	}

	// GATE 2: preflight refuses to START a gateway on an unshared config, so
	// the failure is a startup error an operator sees rather than a silent
	// posture change.
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	assign, err := parseAssignment(testGatewayInner, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	unshared := good
	unshared.Responder = nil
	if err := preflightSession(sizing, unshared, assign); err == nil {
		t.Fatal("preflightSession accepted a config with no shared handshake responder; " +
			"a gateway built from it is a remote detector and must not start")
	}

	// GATE 3: and even if something bypassed preflight, the per-peer
	// constructor itself refuses rather than silently falling back to
	// driver.NewGateway's own private core.Responder.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	defer conn.Close()
	srv := &server{
		conn:        conn,
		sizing:      sizing,
		sessionCfg:  unshared,
		assign:      assign,
		maxSessions: 8,
		peers:       make(map[netip.AddrPort]*peerSession),
	}
	ps, err := srv.newSession(context.Background(), netip.MustParseAddrPort("127.0.0.1:41111"))
	if err == nil {
		if ps != nil {
			ps.close()
		}
		t.Fatal("newSession built a session from a config with no shared handshake responder; " +
			"that session holds a private replay cache and the cross-address replay defence is gone")
	}
	if srv.built.Load() != 0 {
		t.Fatalf("built = %d after a refused session; the refusal must happen before anything is counted",
			srv.built.Load())
	}
}

func capturedInitiation(t *testing.T, dir string, gwCfg session.Config) []byte {
	t.Helper()
	cliStatic, err := core.NewStaticKey(readTestKey(t, filepath.Join(dir, "client.key")))
	if err != nil {
		t.Fatal(err)
	}
	gwPub, err := core.NewPublicKey(readTestKey(t, filepath.Join(dir, "static.pub")))
	if err != nil {
		t.Fatal(err)
	}
	ini, err := core.NewInitiator(core.Config{
		Gateway: core.GatewayParams{
			AdmissionKeys: [][]byte{readTestSecret(t, filepath.Join(dir, "admission.key"))},
			GatewayID:     gwCfg.Core.Gateway.GatewayID,
		},
	}, cliStatic, gwPub)
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	msg, err := ini.WriteInitiation(nil, core.PadAuto)
	if err != nil {
		t.Fatalf("WriteInitiation: %v", err)
	}
	if !couldBeInitiation(len(msg)) {
		t.Fatalf("the captured initiation is %d bytes, which this binary would refuse as a stranger before any crypto", len(msg))
	}
	return msg
}

func readDatagram(t *testing.T, c *net.UDPConn, budget time.Duration) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(budget))
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("waiting for a handshake reply: %v", err)
	}
	if n == 0 {
		t.Fatal("read a zero-length datagram; that is not a handshake reply")
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out
}

func readDatagramOrTimeout(t *testing.T, c *net.UDPConn, budget time.Duration) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(budget))
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil
		}
		t.Fatalf("replay read: %v", err)
	}
	if n == 0 {
		return nil
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out
}
