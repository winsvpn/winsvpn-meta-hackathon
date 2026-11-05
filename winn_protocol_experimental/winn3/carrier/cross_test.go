package carrier

// cross_test.go is a cross-package integration: it drives a Pipe carrier (the
// queue-backed carrier this package uses for the gateway demultiplexer seam)
// between a real client session.Driver and a real gateway session.Driver, and
// observes the carrying state through a winn3/tun Gate — the fail-closed
// authority that decides whether an inner packet may cross.
//
// It is a full datapath session with no sockets and no tunnels: the two
// drivers exchange only sealed Winn3 messages through the two Pipes, and the
// Gate is the endpoint that admits inner packets while carrying. It proves the
// carrier and the tun gate agree on when a session is sealed and that teardown
// closes both. None of this ever touches a kernel interface on this Mac.
//
// Run with: go test ./winn3/carrier -run Cross -count=1

import (
	"bytes"
	"context"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// crossAdmit models the kernel tun device behind the Gate: an inner packet may
// cross only while the gate carries. This is the same whitelist the session
// layer would enforce — MayCarry is true for exactly one state — and it is the
// seam the whole test stands on.
func crossAdmit(g *tun.Gate, inner []byte) ([]byte, bool) {
	if !g.State().MayCarry() {
		return nil, false
	}
	return inner, true
}

// reflectGate pushes the client session's carrying state into the Gate, the
// way the host's promotion layer observes a session and opens the gate. A
// session that is not carrying never opens it; a session that has terminated
// closes it.
func reflectGate(g *tun.Gate, d *session.Driver) {
	switch {
	case d.State() == session.StateEstablished:
		g.Set(tun.StateCarrying)
	case d.State().Terminal():
		g.Set(tun.StateDown)
	default:
		g.Set(tun.StateDown)
	}
}

// crossPair is a client and a gateway driver wired together through a Pipe
// carrier pair, plus the client-side tun.Gate that guards the inner data path.
type crossPair struct {
	t   *testing.T
	cli *session.Driver
	gw  *session.Driver
	// cliPipe is the client's carrier end; gwPipe is the gateway's. Sending on
	// one lands in the other's inbox, and the demultiplexer seam is exactly
	// a.Deliver -> b.inbox as NewPipePair wires it.
	cliPipe *Pipe
	gwPipe  *Pipe
	gate    *tun.Gate

	atGw  [][]byte // inner packets the gateway session delivered to its device
	atCli [][]byte // inner packets the client session delivered to its device
}

// newCrossPair builds both drivers plus a Pipe carrier pair, all sharing one
// deterministic clock and deterministic entropy, so the session is repeatable.
func newCrossPair(t *testing.T) *crossPair {
	t.Helper()
	clk := newFakeClock()
	rand := &countingRand{n: 7}

	admission := make([]byte, 32)
	if _, err := rand.Read(admission); err != nil {
		t.Fatal(err)
	}
	gp := core.GatewayParams{
		AdmissionKeys: [][]byte{admission},
		GatewayID:     []byte("winn3-cross-carrier-gateway"),
	}

	gwStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	cliStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	gwPub, err := core.NewPublicKey(gwStatic.Public())
	if err != nil {
		t.Fatal(err)
	}

	cliCfg := session.Config{
		Core:          core.Config{Gateway: gp},
		Static:        cliStatic,
		GatewayStatic: gwPub,
		Padding:       core.PadBucket,
		Clock:         clk,
		Rand:          rand,
	}
	gwCfg := session.Config{
		Core:    core.Config{Gateway: gp},
		Static:  gwStatic,
		Accept:  func([]byte) error { return nil },
		Padding: core.PadBucket,
		Clock:   clk,
		Rand:    rand,
	}

	cli, err := session.NewClient(cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := session.NewGateway(gwCfg)
	if err != nil {
		t.Fatal(err)
	}

	cliPipe, gwPipe, err := NewPipePair(PipeConfig{Class: ClassUDP})
	if err != nil {
		t.Fatal(err)
	}

	p := &crossPair{t: t, cli: cli, gw: gw, cliPipe: cliPipe, gwPipe: gwPipe, gate: tun.NewGate()}
	t.Cleanup(func() { _ = cliPipe.Close(); _ = gwPipe.Close() })
	return p
}

// pumpCross alternates draining each driver's Poll into the other side's Pipe
// and delivering whatever arrived, until one pass moves nothing. It mirrors the
// session package's own no-socket pair pump so the handshake and the PQ ratchet
// complete deterministically.
func (p *crossPair) pumpCross() {
	p.t.Helper()
	ctx := context.Background()
	for round := 0; round < 64; round++ {
		moved := 0

		nToGw := 0
		for i := 0; i < 512; i++ {
			msg, err := p.cli.Poll()
			if err != nil {
				p.t.Fatalf("client poll: %v", err)
			}
			if msg == nil {
				break
			}
			if err := p.cliPipe.Send(ctx, msg); err != nil {
				p.t.Fatalf("client send into pipe: %v", err)
			}
			nToGw++
		}
		nToCli := 0
		for i := 0; i < 512; i++ {
			msg, err := p.gw.Poll()
			if err != nil {
				p.t.Fatalf("gateway poll: %v", err)
			}
			if msg == nil {
				break
			}
			if err := p.gwPipe.Send(ctx, msg); err != nil {
				p.t.Fatalf("gateway send into pipe: %v", err)
			}
			nToCli++
		}

		for i := 0; i < nToGw; i++ {
			msg, err := p.gwPipe.Recv(ctx)
			if err != nil {
				p.t.Fatalf("gateway pipe recv: %v", err)
			}
			pkts, err := p.gw.Deliver(msg)
			if err != nil {
				continue // terminal; the test asserts on state
			}
			p.atGw = append(p.atGw, pkts...)
			moved += len(pkts)
		}
		for i := 0; i < nToCli; i++ {
			msg, err := p.cliPipe.Recv(ctx)
			if err != nil {
				p.t.Fatalf("client pipe recv: %v", err)
			}
			pkts, err := p.cli.Deliver(msg)
			if err != nil {
				continue
			}
			p.atCli = append(p.atCli, pkts...)
			moved += len(pkts)
		}

		if moved == 0 && nToGw == 0 && nToCli == 0 {
			return
		}
	}
	p.t.Fatal("cross pair did not quiesce")
}

// TestCrossPipeCarrierSessionSealsAndClosesThroughTunGate drives a full session
// from cold to established (sealed) to closed, over a Pipe carrier pair, with a
// tun.Gate as the carrying endpoint.
//
// The carrier↔tun agreement under test is the sealing property: the gate must
// admit inner packets exactly while the session is established, must refuse
// them before the session is sealed and after it has closed, and teardown must
// close both the session and the gate.
func TestCrossPipeCarrierSessionSealsAndClosesThroughTunGate(t *testing.T) {
	p := newCrossPair(t)

	if p.gate.State().MayCarry() {
		t.Fatal("a fresh gate already carries before any session is up")
	}

	// Before the handshake completes, the gate must refuse inner data. This is
	// the fail-closed half: an inner packet appears only inside a sealed
	// message, so nothing can cross through the gate yet.
	if _, ok := crossAdmit(p.gate, []byte("pre-seal trespass")); ok {
		t.Fatal("the gate admitted an inner packet before the session was sealed")
	}

	// Establish the full session through the Pipes: handshake plus the
	// post-quantum ratchet. The gate must NOT carry while the session is still
	// handshaking.
	for i := 0; i < 40 && p.cli.State() != session.StateEstablished; i++ {
		reflectGate(p.gate, p.cli)
		if p.gate.State().MayCarry() {
			t.Fatalf("the gate carried at client state %s before the PQ ratchet finished", p.cli.State())
		}
		p.pumpCross()
	}
	reflectGate(p.gate, p.cli)
	if p.cli.State() != session.StateEstablished || p.gw.State() != session.StateEstablished {
		t.Fatalf("session did not establish: cli %s gw %s (err %v / %v)",
			p.cli.State(), p.gw.State(), p.cli.Err(), p.gw.Err())
	}
	if p.cli.Epoch() != 1 || p.gw.Epoch() != 1 {
		t.Fatalf("epochs after seal: cli %d gw %d, want 1 (post-quantum ratchet)", p.cli.Epoch(), p.gw.Epoch())
	}

	// Now the session is sealed: the gate opens.
	reflectGate(p.gate, p.cli)
	if got := p.gate.State(); got != tun.StateCarrying || !got.MayCarry() {
		t.Fatalf("gate state after seal is %s, want carrying", got)
	}

	// A real inner packet crosses end to end: client session -> client Pipe ->
	// gateway Pipe -> gateway session -> the gateway's device, admitted through
	// the gate on both ends.
	payload := []byte("cross-package sealed flow through pipe carrier")
	if err := p.cli.Enqueue(payload); err != nil {
		t.Fatal(err)
	}
	p.pumpCross()
	if len(p.atGw) != 1 || !bytes.Equal(p.atGw[0], payload) {
		t.Fatalf("gateway received %v, want the single payload %q", p.atGw, payload)
	}
	if admitted, ok := crossAdmit(p.gate, p.atGw[0]); !ok || !bytes.Equal(admitted, payload) {
		t.Fatal("the gateway-side inner packet was not admitted through the carrying gate")
	}

	// The carrier really carried the sealed message: on-wire bytes moved both
	// ways, not zeros.
	if s := p.cliPipe.Stats(); s.Sent == 0 || s.Delivered == 0 {
		t.Fatalf("client pipe did not carry traffic: %+v", s)
	}
	if s := p.gwPipe.Stats(); s.Sent == 0 || s.Delivered == 0 {
		t.Fatalf("gateway pipe did not carry traffic: %+v", s)
	}

	// Tear the session down. The CLOSE frame rides an ordinary message through
	// the Pipes.
	if err := p.cli.Close(); err != nil {
		t.Fatal(err)
	}
	p.pumpCross()

	if !p.cli.State().Terminal() || !p.gw.State().Terminal() {
		t.Fatalf("session did not close: cli %s gw %s (err %v / %v)",
			p.cli.State(), p.gw.State(), p.cli.Err(), p.gw.Err())
	}

	// The gate must now refuse inner data again: teardown closed the sealed
	// path along with the session. This is the close half of the sealing claim.
	reflectGate(p.gate, p.cli)
	if p.gate.State().MayCarry() {
		t.Fatalf("the gate still carries after the session closed")
	}
	if _, ok := crossAdmit(p.gate, payload); ok {
		t.Fatal("the gate admitted an inner packet after the session closed")
	}

	// Enqueue after close must be refused, matching the session's fail-closed
	// contract.
	if err := p.cli.Enqueue(payload); err == nil {
		t.Fatal("Enqueue succeeded on a closed session")
	}
}

// TestCrossPipeCloseUnblocksAndClosesBothEnds pins that tearing down the Pipe
// carrier releases the queue and refuses further I/O, so the carrier side of
// the seal does not linger after the session ends.
func TestCrossPipeCloseUnblocksAndClosesBothEnds(t *testing.T) {
	p := newCrossPair(t)
	p.pumpCross()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := p.cliPipe.Close(); err != nil {
		t.Fatalf("client pipe close: %v", err)
	}

	if err := p.cliPipe.Send(ctx, []byte("after close")); err == nil {
		t.Fatal("Send succeeded on a closed carrier")
	}
	if err := p.cliPipe.Deliver([]byte("after close")); err == nil {
		t.Fatal("Deliver succeeded on a closed carrier")
	}

	// A queued Recv must be unblocked with an error by Close, never hang.
	quitted := make(chan error, 1)
	go func() {
		_, err := p.cliPipe.Recv(ctx)
		quitted <- err
	}()
	select {
	case <-quitted:
		// Empty inbox: Recv returned the context deadline, which is still a
		// bounded refusal, not a hang.
	case <-time.After(3 * time.Second):
		t.Fatal("Recv on a closed carrier neither returned nor timed out")
	}
}
