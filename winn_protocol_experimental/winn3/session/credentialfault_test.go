package session

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// A wrong key must not be reported as censorship.
//
// Measured on 2026-08-09, before the fix: a wrong gateway static key, a
// mismatched admission secret, a divergent gateway id, a gateway refusing
// admission and a total block all produced the identical client outcome —
// ErrCarrierExhausted, "handshake attempts exhausted on this carrier",
// NeedsCarrierChange() true. Five causes, one message, and the two diagnoses
// lead an operator in opposite directions.
//
// These tests build their own driver pair rather than using the package's
// shared one, so that a change to the shared rig cannot quietly change what
// they exercise.

// faultRig is a client and a gateway with a link this file can break in
// specific ways. It is deliberately small: nothing here needs reordering,
// duplication or padding control.
type faultRig struct {
	t   *testing.T
	clk *testClock
	cli *Driver
	gw  *Driver

	dropToGw  bool
	dropToCli bool
}

func newFaultRig(t *testing.T, tweak func(cli, gw *Config)) *faultRig {
	t.Helper()
	clk := newClock()

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
	admission := make([]byte, 32)
	if _, err := rand.Read(admission); err != nil {
		t.Fatal(err)
	}
	gp := core.GatewayParams{
		AdmissionKeys: [][]byte{admission},
		GatewayID:     []byte("winn3-credential-fault-test"),
	}

	cliCfg := Config{
		Core:          core.Config{Gateway: gp},
		Static:        cliStatic,
		GatewayStatic: gwPub,
		Padding:       core.PadBucket,
		Clock:         clk,
		Retry:         Retry{Base: time.Second, Cap: 4 * time.Second, Attempts: 5, FreshAfter: 2},
	}
	gwCfg := Config{
		Core:    core.Config{Gateway: gp},
		Static:  gwStatic,
		Accept:  func([]byte) error { return nil },
		Padding: core.PadBucket,
		Clock:   clk,
	}
	if tweak != nil {
		tweak(&cliCfg, &gwCfg)
	}

	cli, err := NewClient(cliCfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	gw, err := NewGateway(gwCfg)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	return &faultRig{t: t, clk: clk, cli: cli, gw: gw}
}

// step moves one round of traffic in both directions, honouring the drops.
func (r *faultRig) step() {
	r.t.Helper()
	var toGw, toCli [][]byte
	for i := 0; i < 64; i++ {
		msg, err := r.cli.Poll()
		if err != nil || msg == nil {
			break
		}
		if !r.dropToGw {
			toGw = append(toGw, msg)
		}
	}
	for i := 0; i < 64; i++ {
		msg, err := r.gw.Poll()
		if err != nil || msg == nil {
			break
		}
		if !r.dropToCli {
			toCli = append(toCli, msg)
		}
	}
	for _, m := range toGw {
		_, _ = r.gw.Deliver(m)
	}
	for _, m := range toCli {
		_, _ = r.cli.Deliver(m)
	}
}

// runUntilClientGivesUp drives the clock until the client is terminal.
func (r *faultRig) runUntilClientGivesUp() {
	r.t.Helper()
	for i := 0; i < 200; i++ {
		if r.cli.State().Terminal() {
			return
		}
		r.step()
		r.clk.Advance(10 * time.Second)
	}
	r.t.Fatalf("the client never gave up; state %s", r.cli.State())
}

func (r *faultRig) runUntilGatewayGivesUp() {
	r.t.Helper()
	for i := 0; i < 200; i++ {
		if r.gw.State().Terminal() {
			return
		}
		r.step()
		r.clk.Advance(10 * time.Second)
	}
	r.t.Fatalf("the gateway never gave up; state %s", r.gw.State())
}

// wrongGatewayStatic points the client at a static key no gateway holds.
func wrongGatewayStatic(t *testing.T) func(cli, gw *Config) {
	t.Helper()
	return func(cli, gw *Config) {
		other, err := core.GenerateStaticKey()
		if err != nil {
			t.Fatal(err)
		}
		pub, err := core.NewPublicKey(other.Public())
		if err != nil {
			t.Fatal(err)
		}
		cli.GatewayStatic = pub
	}
}

// TestACredentialFaultReachesTheGatewayAndIsNamedThere is the operator-facing
// half, and the half where the discrimination is real.
//
// A wrong client-side credential still puts datagrams on the gateway's doorstep.
// The gateway cannot open any of them, opens no session, and eventually drops
// the half-open state. Before the fix that was ErrPeerUnreachable — "peer did
// not answer liveness probes" — for a peer that was demonstrably answering.
func TestACredentialFaultReachesTheGatewayAndIsNamedThere(t *testing.T) {
	r := newFaultRig(t, wrongGatewayStatic(t))
	r.runUntilGatewayGivesUp()

	unopenable := r.gw.Stats().Unopenable
	if unopenable == 0 {
		t.Fatal("the gateway saw no unopenable datagrams; the fault is not being " +
			"reproduced and everything below would pass for the wrong reason")
	}

	err := r.gw.Err()
	if !errors.Is(err, ErrHandshakeUnauthenticated) {
		t.Fatalf("gateway error is %v, want ErrHandshakeUnauthenticated", err)
	}
	if errors.Is(err, ErrPeerUnreachable) {
		t.Fatal("a peer that delivered datagrams was reported as unreachable")
	}

	// Stats.Unopenable had no reader outside a test. This is the reader: the
	// number must be IN the message, and it must be the measured one.
	if !strings.Contains(err.Error(), itoa(unopenable)) {
		t.Fatalf("the error does not carry the measured Unopenable=%d: %q",
			unopenable, err.Error())
	}
	var f *HandshakeFailure
	if !errors.As(err, &f) {
		t.Fatalf("the error is not a *HandshakeFailure: %T", err)
	}
	if f.Unopenable != unopenable {
		t.Fatalf("HandshakeFailure.Unopenable is %d, Stats says %d", f.Unopenable, unopenable)
	}
	if f.Initiator {
		t.Fatal("the gateway's failure claims to be an initiator's")
	}
	t.Logf("MEASURED gateway verdict: Unopenable=%d err=%v", unopenable, err)
}

// TestAGatewayThatHeardNothingIsStillUnreachable is the control for the test
// above. Without it, "always report ErrHandshakeUnauthenticated" would pass.
func TestAGatewayThatHeardNothingIsStillUnreachable(t *testing.T) {
	r := newFaultRig(t, nil)
	r.dropToGw = true
	r.runUntilGatewayGivesUp()

	if got := r.gw.Stats().Unopenable; got != 0 {
		t.Fatalf("Unopenable is %d on a gateway nothing reached", got)
	}
	err := r.gw.Err()
	if !errors.Is(err, ErrPeerUnreachable) {
		t.Fatalf("gateway error is %v, want ErrPeerUnreachable", err)
	}
	if errors.Is(err, ErrHandshakeUnauthenticated) {
		t.Fatal("a gateway that heard nothing reported a credential fault")
	}
}

// TestAClientAnsweredWithGarbageDoesNotDemandACarrierChange is the client-side
// half.
//
// A client that receives datagrams it cannot open — an injecting censor, a
// captive portal, a middlebox rewriting the payload, a client that reached a
// different gateway — must not be told "this carrier is exhausted, change
// class". Something is answering; changing class cannot help.
func TestAClientAnsweredWithGarbageDoesNotDemandACarrierChange(t *testing.T) {
	r := newFaultRig(t, nil)
	r.dropToCli = true // the real gateway's answers never arrive

	noise := make([]byte, 1200)
	for i := 0; i < 200 && !r.cli.State().Terminal(); i++ {
		r.step()
		for j := 0; j < 3; j++ {
			if _, err := rand.Read(noise); err != nil {
				t.Fatal(err)
			}
			// Deliver must stay silent about this: it returns no error and no
			// packets, exactly as it does for any unopenable message.
			pkts, err := r.cli.Deliver(noise)
			if err != nil && !errors.Is(err, ErrClosed) {
				t.Fatalf("Deliver turned an unopenable message into an error: %v", err)
			}
			if len(pkts) != 0 {
				t.Fatal("Deliver returned packets from an unopenable message")
			}
		}
		r.clk.Advance(10 * time.Second)
	}
	if !r.cli.State().Terminal() {
		t.Fatalf("the client never gave up; state %s", r.cli.State())
	}

	unopenable := r.cli.Stats().Unopenable
	if unopenable == 0 {
		t.Fatal("the client opened everything it was sent; the injection is not " +
			"being reproduced")
	}

	err := r.cli.Err()
	if !errors.Is(err, ErrHandshakeUnauthenticated) {
		t.Fatalf("client error is %v, want ErrHandshakeUnauthenticated", err)
	}
	if errors.Is(err, ErrCarrierExhausted) {
		t.Fatal("a peer that is answering was reported as an exhausted carrier")
	}
	if r.cli.NeedsCarrierChange() {
		t.Fatal("the driver demanded a carrier-class change for a peer that is " +
			"answering: changing class cannot help and this is the signal that " +
			"sends an operator hunting for a censor")
	}
	if !r.cli.NeedsNewSession() {
		t.Error("a failed handshake did not ask for a new session")
	}
	if !strings.Contains(err.Error(), itoa(unopenable)) {
		t.Fatalf("the error does not carry the measured Unopenable=%d: %q",
			unopenable, err.Error())
	}
	t.Logf("MEASURED client verdict: Unopenable=%d needCarrier=%v err=%v",
		unopenable, r.cli.NeedsCarrierChange(), err)
}

// TestASilentPathStillDemandsACarrierChange is the control that keeps the fix
// from becoming an outage of its own.
//
// The measured failure ErrCarrierExhausted answers is 24 retries into a
// wholesale UDP block. That behaviour must survive: total silence still sets
// NeedsCarrierChange and still answers to ErrCarrierExhausted, because a censor
// blocking UDP is what it is for.
//
// What must ALSO be true is that the message stops asserting censorship, since
// a gateway that refused these credentials produces byte-identical silence.
func TestASilentPathStillDemandsACarrierChange(t *testing.T) {
	r := newFaultRig(t, nil)
	r.dropToGw = true
	r.runUntilClientGivesUp()

	if got := r.cli.Stats().Unopenable; got != 0 {
		t.Fatalf("Unopenable is %d on a path that delivered nothing", got)
	}
	err := r.cli.Err()
	if !errors.Is(err, ErrCarrierExhausted) {
		t.Fatalf("client error is %v, want ErrCarrierExhausted", err)
	}
	if errors.Is(err, ErrHandshakeUnauthenticated) {
		t.Fatal("a silent path was reported as a credential fault")
	}
	if !r.cli.NeedsCarrierChange() {
		t.Fatal("a silent path no longer demands a carrier-class change; the " +
			"24-retries-into-a-UDP-block answer has been lost")
	}
	// The honest half: the client cannot tell a block from a refusal, so it
	// must not imply it can.
	text := err.Error()
	for _, want := range []string{"gateway static key", "admission secret", "gateway id"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the message does not mention %q, so a reader is still sent "+
				"hunting for a censor: %q", want, text)
		}
	}
}

// TestEveryCredentialFaultIsSilentToTheClient records the uncomfortable part,
// so that nobody later writes a client-side check that cannot work.
//
// A v3 gateway answers nothing it cannot authenticate. That is correct and is
// not up for negotiation, and its consequence is that on the CLIENT all four
// credential faults are indistinguishable from a block. This test pins that
// consequence: silence toward the peer is preserved in every case, and the
// client's Unopenable stays at zero.
//
// If a future change makes any of these answer, this test fails — which is the
// point. It would mean the gateway had become a probe oracle.
func TestEveryCredentialFaultIsSilentToTheClient(t *testing.T) {
	cases := []struct {
		name  string
		tweak func(cli, gw *Config)
	}{
		{"wrong gateway static", wrongGatewayStatic(t)},
		{"mismatched admission secret", func(cli, gw *Config) {
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}
			cli.Core.Gateway.AdmissionKeys = [][]byte{key}
		}},
		{"divergent gateway id", func(cli, gw *Config) {
			cli.Core.Gateway.GatewayID = []byte("winn3-credential-fault-OTHER")
		}},
		{"gateway refuses admission", func(cli, gw *Config) {
			gw.Accept = func([]byte) error { return errors.New("not admitted") }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newFaultRig(t, tc.tweak)
			r.runUntilClientGivesUp()

			if got := r.gw.Stats().Unopenable; got == 0 {
				t.Fatalf("the gateway saw no unopenable datagrams, so this case " +
					"is not the fault it is named after")
			}
			if got := r.cli.Stats().Unopenable; got != 0 {
				t.Fatalf("the client received %d datagrams it could not open; the "+
					"gateway answered something it had not authenticated, which is "+
					"a probe oracle", got)
			}
			if got := r.cli.Stats().MessagesReceived; got != 0 {
				t.Fatalf("the client opened %d messages from a gateway that "+
					"refused it", got)
			}
			if !errors.Is(r.cli.Err(), ErrCarrierExhausted) {
				t.Fatalf("client error is %v, want ErrCarrierExhausted: a credential "+
					"fault IS silent here and must be reported as the silence it is",
					r.cli.Err())
			}
			// And the gateway names it, which is where the fault is diagnosable.
			r.runUntilGatewayGivesUp()
			if !errors.Is(r.gw.Err(), ErrHandshakeUnauthenticated) {
				t.Fatalf("gateway error is %v, want ErrHandshakeUnauthenticated",
					r.gw.Err())
			}
		})
	}
}

// itoa avoids importing strconv for one call in one file's assertions.
func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
