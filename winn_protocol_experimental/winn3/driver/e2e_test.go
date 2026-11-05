package driver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
)

// planClasses is the migration plan every end-to-end test is built at: a session
// that may escalate from a datagram carrier to a stream carrier, which is the
// §4.2 answer to a censor who drops UDP wholesale.
func planClasses() []carrier.Class {
	return []carrier.Class{carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS}
}

func planSizing(t *testing.T) Sizing {
	t.Helper()
	s, err := NewSizing(carrier.DefaultPathMTU, planClasses()...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// rekeySoon makes the volume trigger fire inside a test rather than after four
// gigabytes. The TIME trigger is left alone: it is a jittered draw and forcing
// it would mean either sleeping for minutes or replacing the draw, and this test
// is about the loop carrying traffic across a ratchet, not about the schedule.
func rekeySoon(n uint64) func(*session.Config) {
	return func(c *session.Config) { c.RekeyAfterMessages = n }
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// TestLoopbackTunnelCarriesBytes is the deliverable: the first time this
// protocol carries a byte end to end.
//
// One client loop and one gateway loop, each with its own inner-IP layer and its
// own host device, joined by a pair of queue-backed carriers. It drives a real
// X25519 handshake, a real ML-KEM-768 ratchet and real ChaCha20-Poly1305
// transport messages, then:
//
//	inner packets both ways, digests compared
//	a rekey, with traffic across the ratchet
//	a carrier migration from a datagram class to a stream class
//	an orderly teardown that the peer observes as CloseNormal
//
// The two ends are modelled as two ENDPOINTS rather than as a client and a
// forwarding gateway. winn3/tun is the client-side validator — "source is ours
// going out, destination is ours coming in" — and the gateway-side mirror
// validator does not exist yet (item 3 of that lane's §9). Endpoint to endpoint
// is what the two validators compose into today, and it exercises every seam
// this loop owns.
func TestLoopbackTunnelCarriesBytes(t *testing.T) {
	// The step clock makes the session's schedule deterministic, but the loop
	// goroutines are still real: a rekey convergence or a CLOSE waits for an
	// actual message exchange to flow through the carriers, and on a shared
	// machine that exchange is starved by other processes, not by the session.
	// The deadline is therefore generous (the test normally completes in ~1s and
	// only spends the budget when the machine is under load), so a scheduler
	// delay can never be what separates a flake from a pass.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)

	// Both loops share one manually advanced clock. Its Now is never advanced
	// here — the handshake, the volume-triggered rekey and the CLOSE are all
	// message-driven, so nothing in this test needs virtual time to move. What
	// the injection buys is determinism: none of the session's real timers exists
	// on the critical path, so a scheduler-delayed timer can never be the thing
	// that separates a flake from a pass. Every deadline stays in the future,
	// which is also why the write loop's maxSpins guard cannot trip: the loops
	// are woken by real wake signals and ctx cancellation, never by a clock that
	// refuses to move.
	clk := newStepClock()

	// The carriers. NewPipePair is the gateway demultiplexer's seam, used here
	// as a loopback with no socket at all.
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{
		Class:   carrier.ClassUDP,
		PathMTU: carrier.DefaultPathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}

	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar, clock: clk,
		local: clientAddr(), router: gatewayAddr(),
		tweak: rekeySoon(64),
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, clock: clk,
		local: gatewayAddr(), router: clientAddr(),
		tweak: rekeySoon(64),
	})
	defer cli.stop()
	defer gw.stop()

	cli.start(ctx)
	gw.start(ctx)

	// 1. The handshake and the post-quantum ratchet.
	cli.waitState(session.StateEstablished, 15*time.Second)
	gw.waitState(session.StateEstablished, 15*time.Second)

	// The gate is applied by the goroutine that reached the state, so it is open
	// by the time a host can observe "established" — see
	// TestTheGateIsOpenByTheTimeAHostCanUseIt, which is where the remaining
	// instruction-width window is measured. Loop.Carrying() is the accessor a
	// host should wait on; this waits on it for the same reason.
	waitFor(t, 5*time.Second, "the gate to open behind the established session", func() bool {
		return cli.loop.Carrying() && cli.loop.Tunnel().Gate().State() == tunCarrying()
	})

	// 2. Inner packets, client to gateway, digests compared.
	sent := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		payload := []byte(fmt.Sprintf("winn3 client to gateway packet %d", i))
		sent = append(sent, digest(payload))
		cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), payload))
	}
	for i, want := range sent {
		got := gw.dev.take(t, 10*time.Second)
		if d := digest(payloadOf(got)); d != want {
			t.Fatalf("packet %d arrived with digest %s, want %s", i, d, want)
		}
	}

	// 3. Inner packets, gateway to client.
	back := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		payload := []byte(fmt.Sprintf("winn3 gateway to client packet %d", i))
		back = append(back, digest(payload))
		gw.dev.offer(t, ipv4Packet(gatewayAddr(), clientAddr(), payload))
	}
	for i, want := range back {
		got := cli.dev.take(t, 10*time.Second)
		if d := digest(payloadOf(got)); d != want {
			t.Fatalf("return packet %d arrived with digest %s, want %s", i, d, want)
		}
	}

	// 4. A rekey, with traffic across it.
	//
	// The rekey schedule is deliberately DETERMINISTIC, because every phase after
	// this one must run in a rekey-free window or it inherits the two flakes this
	// test used to have. RekeyAfterMessages = 64 fires exactly once here: the
	// eighty crossing packets amount to roughly a hundred sent messages, so the
	// first boundary is crossed mid-crossing and the second (at 128) is never
	// reached. The result is one clean ratchet whose drops are accounted for
	// below, and then a ~40-message window after it in which the migration, the
	// post-migration burst and the CLOSE can run without a ratchet interrupting
	// the delivery their assertions depend on.
	//
	// The accounting is where the two refusal policies become visible: a packet
	// offered while the session is REKEYING is DROPPED by the tun gate rather
	// than queued, so
	//
	//	offered = delivered + dropped at the gate + lost in flight across a cut
	//
	// and the third term is bounded by reorder depth. A test that demanded every
	// packet arrive would be asserting something the design deliberately does not
	// promise; a test that demanded nothing would not notice a tunnel that stopped
	// carrying at the first ratchet.
	startEpoch := cli.loop.Session().Epoch()
	gateDroppedBefore := cli.loop.Tunnel().Stats().TxDroppedClosed

	// Eighty inner packets. If the volume trigger failed to fire mid-crossing
	// the wait below would time out loudly — a schedule miscalibration is a
	// deterministic red, not an intermittent one.
	const crossing = 80
	crossed := make(map[string]bool, crossing)
	for i := 0; i < crossing; i++ {
		payload := make([]byte, 600)
		copy(payload, fmt.Sprintf("winn3 packet across the ratchet %02d", i))
		crossed[digest(payload)] = true
		cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), payload))
		time.Sleep(2 * time.Millisecond)
	}

	arrived := map[string]bool{}
	gateDropped := func() uint64 {
		return cli.loop.Tunnel().Stats().TxDroppedClosed - gateDroppedBefore
	}
	deadline := time.Now().Add(20 * time.Second)
	for uint64(len(arrived))+gateDropped() < crossing && time.Now().Before(deadline) {
		select {
		case p := <-gw.dev.out:
			arrived[digest(payloadOf(p))] = true
		case <-time.After(100 * time.Millisecond):
		}
	}

	// A COMPLETED ratchet at both ends, at the same epoch, is the precondition
	// every later phase depends on. "Rekeys > 0" alone was the original flake: a
	// ratchet could still be in flight — one end even an epoch ahead — when the
	// migration and the burst started, and a packet offered across a live ratchet
	// is dropped fail-closed by design. Requiring both sessions to be established
	// again with EQUAL epochs converges the ratchet before the migration moves the
	// carrier underneath it, and is what makes the CLOSE openable at the peer.
	// The step clock makes the rekey schedule deterministic, but the ratchet
	// itself completes only when the RekeyInit/RekeyAck exchange actually flows
	// through the carriers, and that is real-time. Under a heavily loaded shared
	// machine (other lanes compiling, swap pressure) the two messages can be
	// starved for far longer than 15s, which is the measured flake this wait
	// closes. The budget is generous and bounded by the test's own ctx; the wait
	// returns the instant both ends converge, so a pass is as fast as ever and
	// the budget exists only to give a guaranteed-but-starved exchange room.
	rekeyConverged := func() bool {
		return cli.loop.Session().Stats().Rekeys > 0 &&
			gw.loop.Session().Stats().Rekeys > 0 &&
			cli.loop.Session().State() == session.StateEstablished &&
			gw.loop.Session().State() == session.StateEstablished &&
			cli.loop.Session().Epoch() == gw.loop.Session().Epoch()
	}
	waitFor(t, 45*time.Second, "a completed rekey at both ends, converged on one epoch", func() bool {
		if rekeyConverged() {
			return true
		}
		if cli.loop.Session().Err() != nil || gw.loop.Session().Err() != nil {
			t.Logf("rekey convergence aborted: cliRekeys=%d gwRekeys=%d cliState=%s gwState=%s cliEpoch=%d gwEpoch=%d cliErr=%v gwErr=%v",
				cli.loop.Session().Stats().Rekeys, gw.loop.Session().Stats().Rekeys,
				cli.loop.Session().State(), gw.loop.Session().State(),
				cli.loop.Session().Epoch(), gw.loop.Session().Epoch(),
				cli.loop.Session().Err(), gw.loop.Session().Err())
		}
		return false
	})
	if got := cli.loop.Session().Epoch(); got <= startEpoch {
		t.Fatalf("client epoch is %d after a rekey, was %d", got, startEpoch)
	}
	if len(arrived) == 0 {
		t.Fatal("no packet arrived across the rekey; the tunnel stopped carrying at the first ratchet")
	}
	for d := range arrived {
		if !crossed[d] {
			t.Fatalf("a packet arrived with digest %s that was never sent", d)
		}
	}
	accounted := uint64(len(arrived)) + gateDropped()
	if accounted+2 < crossing {
		t.Fatalf("%d of %d packets are unaccounted for: %d delivered, %d dropped at the gate",
			crossing-accounted, crossing, len(arrived), gateDropped())
	}
	t.Logf("across the ratchet: %d delivered, %d dropped fail-closed at the gate, %d rekeys",
		len(arrived), gateDropped(), cli.loop.Session().Stats().Rekeys)

	// 5. A carrier migration, datagram class to stream class, with no
	// re-handshake. Quiesce first so nothing is in flight across the move.
	drainDevice(gw.dev)
	drainDevice(cli.dev)

	cliTLS, gwTLS, err := carrier.NewPipePair(carrier.PipeConfig{
		Class:   carrier.ClassTLS,
		PathMTU: carrier.DefaultPathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	epoch := cli.loop.Session().Epoch()
	for _, m := range []struct {
		name string
		e    *endpoint
		to   carrier.Conn
	}{{"gateway", gw, gwTLS}, {"client", cli, cliTLS}} {
		mig, err := m.e.loop.Migrate(m.to)
		if err != nil {
			t.Fatalf("%s migration: %v", m.name, err)
		}
		if mig.Narrows {
			t.Fatalf("%s migration narrows: session %d, carrier %d — the floor was not pinned",
				m.name, mig.SessionSize, mig.CarrierSize)
		}
	}
	if got := cli.loop.Session().Epoch(); got != epoch {
		t.Fatalf("epoch changed from %d to %d across a migration; the session did not survive it", epoch, got)
	}
	if got := cli.loop.Session().State(); got != session.StateEstablished {
		t.Fatalf("client session is %s after a migration, want established", got)
	}

	// Prove the migrated carrier is live before relying on it. Migrate returns
	// the moment the carrier pointer has been swapped, but the reader goroutine
	// only re-arms on the destination carrier when it observes the generation
	// change, and on a loaded machine that is not instant. The netlab rig makes
	// this same liveness an observed fact (Pair.ProveCarrying); here it is one
	// probe round trip: offer, then take. Only after it lands does the burst
	// below claim anything, so the first take is no longer racing the re-arm.
	probe := []byte("winn3 migration liveness probe")
	probeWant := digest(probe)
	cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), probe))
	if d := digest(payloadOf(gw.dev.take(t, 20*time.Second))); d != probeWant {
		t.Fatalf("migrated carrier delivered a probe with digest %s, want %s", d, probeWant)
	}

	// 6. Traffic over the new carrier, digests compared.
	after := make([]string, 0, 6)
	for i := 0; i < 6; i++ {
		payload := []byte(fmt.Sprintf("winn3 packet after the migration %d", i))
		after = append(after, digest(payload))
		cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), payload))
	}
	gateDroppedBeforeBurst := cli.loop.Tunnel().Stats().TxDroppedClosed
	for i, want := range after {
		got := gw.dev.take(t, 20*time.Second)
		if d := digest(payloadOf(got)); d != want {
			t.Fatalf("post-migration packet %d arrived with digest %s, want %s", i, d, want)
		}
	}
	// The negative half of the determinism claim. None of the post-migration
	// burst may be dropped fail-closed at the gate: the schedule above puts this
	// phase far from the next rekey boundary, so a nonzero delta here means a
	// ratchet leaked into the rekey-free window and this file turns red
	// deterministically instead of every now and then. Together with the
	// convergence wait this converts "no 10s/15s flake" from a hope into a
	// measured property with a named failure.
	if dropped := cli.loop.Tunnel().Stats().TxDroppedClosed - gateDroppedBeforeBurst; dropped != 0 {
		t.Fatalf("%d of the post-migration burst was dropped fail-closed at the gate; "+
			"a ratchet leaked into the rekey-free window", dropped)
	}
	if cliTLS.Stats().Sent == 0 {
		t.Fatal("nothing was sent on the destination carrier; the swap did not take")
	}
	if got := cli.loop.Stats().Migrations; got != 1 {
		t.Fatalf("loop counted %d migrations, want 1", got)
	}

	// 7. Teardown. The CLOSE rides an ordinary message, so the peer learns from
	// the frame rather than from a socket closing.
	if err := cli.loop.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cli.waitRun(30 * time.Second); err != nil {
		t.Fatalf("client Run returned %v, want a clean close", err)
	}
	if got := cli.loop.Session().State(); got != session.StateClosed {
		t.Fatalf("client session is %s after Close, want closed", got)
	}
	if got := cli.loop.Tunnel().Gate().State().String(); got != "down" {
		t.Fatalf("client gate is %q after Run returned, want down", got)
	}
	waitFor(t, 30*time.Second, "the gateway to observe the peer's CLOSE", func() bool {
		return gw.loop.Session().State().Terminal()
	})
	if got := gw.loop.Session().PeerCloseReason(); got != session.CloseNormal {
		t.Fatalf("gateway saw close reason %v, want CloseNormal", got)
	}
	if err := gw.waitRun(30 * time.Second); err != nil {
		t.Fatalf("gateway Run returned %v, want a clean close", err)
	}

	// 8. Nothing was dropped at the seams the loop owns.
	for _, e := range []*endpoint{cli, gw} {
		st := e.loop.Stats()
		if st.InnerRejected != 0 || st.InnerNoTun != 0 {
			t.Fatalf("loop rejected %d inner packets and had %d with no tun",
				st.InnerRejected, st.InnerNoTun)
		}
		// A clean loopback run, migration included, must move no failure
		// counter at all. RecvFailed is the one worth stating: a MIGRATION is
		// not a read failure, and a loop that counted the swap as one would put
		// a spike in the health counters at exactly the moment an operator is
		// trying to diagnose a failover.
		if st.RecvFailed != 0 || st.SendFailed != 0 {
			t.Fatalf("a clean run recorded %d read failures and %d send failures",
				st.RecvFailed, st.SendFailed)
		}
		ts := e.loop.Tunnel().Stats()
		if ts.TxDroppedInvalid != 0 || ts.RxDroppedInvalid != 0 {
			t.Fatalf("tun rejected packets as invalid: tx %d rx %d",
				ts.TxDroppedInvalid, ts.RxDroppedInvalid)
		}
	}
	t.Logf("client %+v", cli.loop.Stats())
	t.Logf("gateway %+v", gw.loop.Stats())
}

func drainDevice(d *fakeDevice) {
	for {
		select {
		case <-d.out:
		case <-time.After(150 * time.Millisecond):
			return
		}
	}
}

// TestLoopbackUDPTunnelCarriesBytes runs the same pump over two real datagram
// sockets, so that the proof does not rest on a queue standing in for a network.
//
// Both sockets bind the LOOPBACK address explicitly. Nothing here listens on a
// routable interface, creates a utun device or starts a tunnel on this machine:
// every sibling lane depends on this machine's connectivity.
func TestLoopbackUDPTunnelCarriesBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)

	loopback := net.IPv4(127, 0, 0, 1)
	gwConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback, Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	defer gwConn.Close()
	cliConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback, Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	defer cliConn.Close()

	gwAddr := gwConn.LocalAddr().(*net.UDPAddr)
	cliAddr := cliConn.LocalAddr().(*net.UDPAddr)

	cliCar, err := carrier.NewUDP(carrier.UDPConfig{
		Conn: cliConn, Peer: gwAddr,
		MaxMessageSize: sz.MessageSize, PathMTU: sz.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	gwCar, err := carrier.NewUDP(carrier.UDPConfig{
		Conn: gwConn, Peer: cliAddr,
		MaxMessageSize: sz.MessageSize, PathMTU: sz.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}

	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar, local: clientAddr(), router: gatewayAddr(),
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, local: gatewayAddr(), router: clientAddr(),
	})
	defer cli.stop()
	defer gw.stop()

	cli.start(ctx)
	gw.start(ctx)

	cli.waitState(session.StateEstablished, 20*time.Second)
	gw.waitState(session.StateEstablished, 20*time.Second)

	// A full-size inner packet, which is the one that a mis-sized session black
	// holes and a correctly sized one carries.
	full := make([]byte, sz.InnerMTU-20)
	for i := range full {
		full[i] = byte(i * 31)
	}
	want := digest(full)
	cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), full))
	got := gw.dev.take(t, 15*time.Second)
	if d := digest(payloadOf(got)); d != want {
		t.Fatalf("full-size packet arrived with digest %s, want %s", d, want)
	}
	if len(got) != sz.InnerMTU {
		t.Fatalf("full-size packet arrived as %d bytes, want the %d-byte inner MTU", len(got), sz.InnerMTU)
	}

	reply := []byte("winn3 loopback udp reply")
	gw.dev.offer(t, ipv4Packet(gatewayAddr(), clientAddr(), reply))
	back := cli.dev.take(t, 15*time.Second)
	if d := digest(payloadOf(back)); d != digest(reply) {
		t.Fatal("reply digest does not match")
	}

	if err := cli.loop.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cli.waitRun(15 * time.Second); err != nil {
		t.Fatalf("client Run returned %v", err)
	}
	waitFor(t, 15*time.Second, "the gateway to observe the CLOSE", func() bool {
		return gw.loop.Session().State().Terminal()
	})
	cancel()
	_ = gw.waitRun(15 * time.Second)
}

// TestTheGateIsOpenByTheTimeAHostCanUseIt is defect 6 of
// WINN3_NETWORK_REALISM_20260808.md §9.2, fixed and pinned.
//
// The gate used to open one WAKE after the session reported established: the
// message that completes the handshake is opened on the reader goroutine, and
// only the writer synced the gate, so a host that waited for
// Session().State() == established and then wrote lost the whole burst. Measured
// under -race -count=2: 64 of 64 offered packets counted as TxDroppedClosed on a
// perfectly healthy tunnel.
//
// Two things now answer it, and both are asserted here because they cover
// different callers:
//
//  1. The reader syncs the gate on the goroutine that reached the state, so the
//     window collapses from a scheduler round trip to a few instructions. A host
//     that spins on State() may still lose a packet or two to the remaining
//     window — but not the burst, which is the difference between "the first
//     connection is slow" and "the first connection does not happen".
//  2. Loop.Carrying() is the honest answer to "may I write yet", and a host that
//     waits on it loses nothing at all, with no race left to lose it to.
func TestTheGateIsOpenByTheTimeAHostCanUseIt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{
		Class:   carrier.ClassUDP,
		PathMTU: carrier.DefaultPathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	slow := &slowSend{Conn: cliCar}
	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: slow, local: clientAddr(), router: gatewayAddr(),
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, local: gatewayAddr(), router: clientAddr(),
	})
	defer cli.stop()
	defer gw.stop()

	// Before anything runs there is no tunnel, and Carrying() must say so. An
	// accessor that answered "yes" here would be worse than no accessor: a host
	// that trusts it writes its first burst into a closed gate and loses it,
	// which is the very failure it exists to prevent.
	if cli.loop.Carrying() {
		t.Fatal("Carrying() reports an open gate on a loop that has not been started")
	}

	cli.start(ctx)
	gw.start(ctx)

	// Make the write loop BUSY at the instant the session establishes, which is
	// the condition the original 64-of-64 measurement was taken under and the only
	// condition in which "one wake late" is a measurable quantity rather than a
	// scheduling coin flip.
	//
	// Two hundred inner packets are pushed straight into the session before it
	// establishes — bypassing the gate, which is closed, and which is the point —
	// and the carrier's Send is slowed. writeLoop drains BEFORE it syncs the gate,
	// so when only the writer owned the gate there was a long, deterministic
	// window in which the session read `established` and the gate was shut.
	for i := 0; i < 200; i++ {
		if err := cli.loop.Session().Enqueue(make([]byte, 64)); err != nil {
			break
		}
	}
	slow.enable()

	// A host that does the obvious thing: spin on the session state, then write
	// at once. Nothing waits for the gate.
	deadline := time.Now().Add(20 * time.Second)
	for cli.loop.Session().State() != session.StateEstablished {
		if time.Now().After(deadline) {
			t.Fatalf("the client never established (state %s)", cli.loop.Session().State())
		}
	}

	const burst = 64
	for i := 0; i < burst; i++ {
		cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), []byte{byte(i)}))
	}
	waitFor(t, 10*time.Second, "the tun layer to account for the burst", func() bool {
		s := cli.loop.Tunnel().Stats()
		return s.TxPackets+s.TxDroppedClosed+s.TxDroppedSink >= burst
	})
	dropped := cli.loop.Tunnel().Stats().TxDroppedClosed
	if dropped > burst/8 {
		t.Fatalf("%d of %d packets written the instant the session read `established` were "+
			"dropped by a closed gate. The gate must be applied by the goroutine that reached "+
			"the state, not one wake later; before that fix this was 64 of 64.", dropped, burst)
	}
	t.Logf("a host that spins on State() and writes immediately lost %d of %d packets "+
		"(64 of 64 before the fix)", dropped, burst)

	// And the contract: a host that waits for Carrying() loses nothing.
	if !cli.loop.Carrying() {
		waitFor(t, 5*time.Second, "Carrying() to report the open gate", cli.loop.Carrying)
	}
	before := cli.loop.Tunnel().Stats().TxDroppedClosed
	for i := 0; i < burst; i++ {
		cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), []byte{byte(i)}))
	}
	waitFor(t, 10*time.Second, "the second burst to be accounted for", func() bool {
		s := cli.loop.Tunnel().Stats()
		return s.TxPackets+s.TxDroppedClosed+s.TxDroppedSink >= 2*burst
	})
	if after := cli.loop.Tunnel().Stats().TxDroppedClosed; after != before {
		t.Fatalf("%d packets were dropped by a closed gate AFTER Carrying() reported true; "+
			"the accessor is not the contract it claims to be", after-before)
	}

	// A loop with no tun layer has no physical gate, so its projected session
	// state is the gate. Before establishment it must fail closed just like
	// SendInner.
	nogw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, local: gatewayAddr(), router: clientAddr(), noTun: true,
	})
	if nogw.loop.Carrying() {
		t.Fatal("an unstarted no-tun loop reports Carrying() true")
	}
}

// slowSend is a carrier whose Send can be made slow on demand.
//
// It exists for one test and for one reason: "the gate opened one wake late" is
// a statement about a window, and a window with nothing in it is not measurable.
// Slowing the writer puts something in it.
type slowSend struct {
	carrier.Conn
	on atomic.Bool
}

func (s *slowSend) enable() { s.on.Store(true) }

func (s *slowSend) Send(ctx context.Context, msg []byte) error {
	if s.on.Load() {
		time.Sleep(2 * time.Millisecond)
	}
	return s.Conn.Send(ctx, msg)
}
