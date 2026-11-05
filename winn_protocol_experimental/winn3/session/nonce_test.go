package session

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// The nonce-reuse contract. core.Session derives its AEAD nonce as
// (epoch salt || send counter) and the counter advances inside Seal; a reuse can
// therefore only be introduced by the CALLER, which is this driver. No test
// inside the core can catch it. These are that test.

// tokenWitness records the demux token of every transport message a driver
// emits, alongside the full message, so a repeat can be classified.
type tokenWitness struct {
	t      *testing.T
	tokens map[string][]byte
	n      int
}

func newTokenWitness(t *testing.T) *tokenWitness {
	return &tokenWitness{t: t, tokens: make(map[string][]byte)}
}

// observe classifies one emitted message.
//
// A repeated token is one of two things and they are not equally bad. If the
// bodies are identical it is a retransmission of already-sealed bytes: the same
// nonce over the same plaintext, which is what a retransmission is and is safe.
// If the bodies differ it is a re-seal at a spent counter, which is a
// catastrophic nonce reuse. This driver should produce neither, so both are
// reported.
func (w *tokenWitness) observe(msg []byte) (dupIdentical, dupDiffering int) {
	if len(msg) < core.DemuxTokenSize {
		return 0, 0
	}
	w.n++
	key := hex.EncodeToString(msg[:core.DemuxTokenSize])
	prev, seen := w.tokens[key]
	if !seen {
		w.tokens[key] = append([]byte(nil), msg...)
		return 0, 0
	}
	if bytes.Equal(prev, msg) {
		return 1, 0
	}
	return 0, 1
}

// TestNonceWitnessHasTeeth checks the detector before it is trusted, the same
// way the metronome and clamping detectors in this package are checked. A guard
// that cannot fail turns an unverified claim into a verified-looking one.
func TestNonceWitnessHasTeeth(t *testing.T) {
	w := newTokenWitness(t)
	token := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	a := append(append([]byte(nil), token...), []byte("ciphertext one")...)
	b := append(append([]byte(nil), token...), []byte("ciphertext two")...)

	if same, diff := w.observe(a); same != 0 || diff != 0 {
		t.Fatalf("a first sighting was reported as a duplicate (%d,%d)", same, diff)
	}
	if same, diff := w.observe(a); same != 1 || diff != 0 {
		t.Errorf("an identical retransmission was classified (%d,%d), want (1,0)", same, diff)
	}
	if same, diff := w.observe(b); same != 0 || diff != 1 {
		t.Errorf("a re-seal at a spent counter was classified (%d,%d), want (0,1); the witness has no teeth", same, diff)
	}
}

// TestNoDemuxTokenIsEverReused is the contract test.
//
// It drives a session through every path that could plausibly rewind a counter —
// the post-quantum ratchet, repeated rekeys, a stalled and retransmitted
// handshake, data queued across a ratchet, cover traffic, keepalive probes and a
// simulated carrier switch — and requires that no demux token is ever emitted
// twice. The token is PRF(demux key, counter), so a repeat means a repeated
// (epoch, counter) pair, which means a repeated nonce.
func TestNoDemuxTokenIsEverReused(t *testing.T) {
	w := newTokenWitness(t)
	var identical, differing int

	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		// Ratchet constantly, so the counter resets as often as possible.
		cli.RekeyAfterMessages = 3
		gw.RekeyAfterMessages = 5
		cli.RekeyInterval = Draw{Min: time.Second, Mean: 2 * time.Second, Max: 5 * time.Second}
		gw.RekeyInterval = Draw{Min: time.Second, Mean: 3 * time.Second, Max: 6 * time.Second}
		cli.Silence = Draw{Min: time.Second, Mean: 2 * time.Second, Max: 4 * time.Second}
		gw.Silence = Draw{Min: time.Second, Mean: 2 * time.Second, Max: 4 * time.Second}
	})

	// Watch both directions, including the handshake phase.
	p.filterToGw = func(_ int, msg []byte) bool {
		a, b := w.observe(msg)
		identical += a
		differing += b
		return true
	}
	p.filterToCli = func(_ int, msg []byte) bool {
		a, b := w.observe(msg)
		identical += a
		differing += b
		return true
	}

	p.establish()

	// 700 rounds of 500 ms, plus 2 s on every eleventh, is 478 s of virtual time.
	// The rekey draw above is exactly what this test exercises — it ratchets as
	// often as it can, on purpose — so it is declared. The probe schedule is not
	// exercised, and the budget has to stay under it or a probe joins the token
	// stream on a machine-load coin toss.
	const rounds, roundStep, pauseEvery, pause = 700, 500 * time.Millisecond, 11, 2 * time.Second
	requireQuietBudget(t, p.cli, rounds*roundStep+(rounds/pauseEvery+1)*pause, exercisesRekey)

	for round := 0; round < rounds; round++ {
		for i := 0; i < 3; i++ {
			if err := p.cli.Enqueue([]byte("payload")); err != nil && round == 0 {
				t.Fatal(err)
			}
			if err := p.gw.Enqueue(make([]byte, 200+i)); err != nil && round == 0 {
				t.Fatal(err)
			}
		}
		if round%7 == 0 {
			_ = p.cli.EmitCover()
		}
		// A carrier switch is invisible to the driver by construction, but the
		// counter must stay monotone across one, so the run pauses and resumes
		// the way a migration would.
		if round%pauseEvery == 0 {
			p.clk.Advance(pause)
		}
		p.clk.Advance(roundStep)
		p.run()
		if p.cli.State().Terminal() || p.gw.State().Terminal() {
			t.Fatalf("session died at round %d: %s/%s (%v/%v)",
				round, p.cli.State(), p.gw.State(), p.cli.Err(), p.gw.Err())
		}
	}

	if differing != 0 {
		t.Fatalf("NONCE REUSE: %d messages were sealed at an already-spent counter with different plaintext", differing)
	}
	if identical != 0 {
		t.Errorf("%d transport messages were emitted twice byte-for-byte; the driver should never re-emit a sealed message", identical)
	}
	if w.n < 1500 {
		t.Fatalf("only %d messages were observed; this test measured too little", w.n)
	}
	if p.cli.Stats().Rekeys < 5 || p.gw.Stats().Rekeys < 5 {
		t.Fatalf("only %d/%d rekeys; the counter barely reset",
			p.cli.Stats().Rekeys, p.gw.Stats().Rekeys)
	}
	if p.cli.Epoch() != p.gw.Epoch() {
		t.Errorf("epochs diverged after %d rekeys: %d vs %d", p.cli.Stats().Rekeys, p.cli.Epoch(), p.gw.Epoch())
	}
}

// TestHandshakeRetransmissionDoesNotReseal covers the one path that deliberately
// re-emits bytes.
//
// A retransmitted initiation MUST be byte-identical — the core says so, because a
// differing retransmission is a second handshake burning a second slot of gateway
// state. Byte-identical is also the safe choice for nonces: it replays bytes that
// were sealed once, rather than sealing new bytes at an old counter.
func TestHandshakeRetransmissionDoesNotReseal(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		cli.Retry = Retry{Base: time.Second, Cap: 2 * time.Second, Attempts: 4, FreshAfter: 9}
	})
	p.filterToGw = func(int, []byte) bool { return false }

	var sent [][]byte
	for i := 0; i < 20 && !p.cli.State().Terminal(); i++ {
		for {
			msg, err := p.cli.Poll()
			if err != nil {
				t.Fatal(err)
			}
			if msg == nil {
				break
			}
			sent = append(sent, msg)
		}
		// Step to the client's own next fire rather than a fixed 5 s, which
		// would jump past connectBy (CT-1 D4) before the ladder had fired.
		if dl := p.cli.NextDeadline(); dl.After(p.clk.Now()) {
			p.clk.Advance(dl.Sub(p.clk.Now()))
		}
	}
	if len(sent) < 3 {
		t.Fatalf("only %d initiations were emitted", len(sent))
	}
	for i := 1; i < len(sent); i++ {
		if !bytes.Equal(sent[0], sent[i]) {
			t.Fatalf("retransmission %d differs from the original; it was re-sealed, not replayed", i)
		}
	}
}

// TestNoExportedPathHandsOutTheSealer is the structural half of the contract.
//
// The whole argument that a nonce cannot be reused rests on there being exactly
// one way to seal — Poll, under the driver mutex. An exported accessor returning
// the core session would create a second sender interface and quietly overturn
// that, which is precisely the failure the independent review named as the one
// thing that would change its verdict. Reflection pins it so the mistake fails a
// test rather than depending on a reviewer noticing.
func TestNoExportedPathHandsOutTheSealer(t *testing.T) {
	forbidden := map[reflect.Type]string{
		reflect.TypeOf((*core.Session)(nil)):     "*core.Session",
		reflect.TypeOf((*core.Initiator)(nil)):   "*core.Initiator",
		reflect.TypeOf((*core.Responder)(nil)):   "*core.Responder",
		reflect.TypeOf((*core.PQEphemeral)(nil)): "*core.PQEphemeral",
	}
	dt := reflect.TypeOf(&Driver{})
	if dt.NumMethod() == 0 {
		t.Fatal("no exported methods were inspected; this guard has no teeth")
	}
	for i := 0; i < dt.NumMethod(); i++ {
		m := dt.Method(i)
		for j := 0; j < m.Type.NumOut(); j++ {
			if name, bad := forbidden[m.Type.Out(j)]; bad {
				t.Errorf("Driver.%s returns %s; a second sender interface can reuse a nonce", m.Name, name)
			}
		}
	}
	// The same for the package's constructors, which must hand back a Driver and
	// nothing that can seal on its own.
	for _, fn := range []any{NewClient, NewGateway} {
		ft := reflect.TypeOf(fn)
		for j := 0; j < ft.NumOut(); j++ {
			if name, bad := forbidden[ft.Out(j)]; bad {
				t.Errorf("a constructor returns %s", name)
			}
		}
	}
}

// --- MTU arithmetic ---------------------------------------------------------

// TestDefaultMessageSizeFitsTheCarrierItClaims: the earlier value of this
// constant was 1280 with a comment claiming that made a message unfragmentable
// at the IPv6 minimum MTU. It was one layer off — MaxMessageSize bounds the
// MESSAGE, and the carrier then wraps it — so a full-size message became a
// 1328-byte UDP/IPv6 packet, 48 bytes over the floor the comment invoked.
func TestDefaultMessageSizeFitsTheCarrierItClaims(t *testing.T) {
	if outer := DefaultMaxMessageSize + CarrierOverheadUDPIPv6; outer > IPv6MinimumLinkMTU {
		t.Errorf("a full-size message is a %d-byte UDP/IPv6 packet, %d over the %d-byte floor",
			outer, outer-IPv6MinimumLinkMTU, IPv6MinimumLinkMTU)
	}
	if outer := DefaultMaxMessageSize + CarrierOverheadUDPIPv4; outer > IPv6MinimumLinkMTU {
		t.Errorf("a full-size message is a %d-byte UDP/IPv4 packet, over the %d-byte floor", outer, IPv6MinimumLinkMTU)
	}
	// The post-quantum blobs must still ride in one message at the default, or
	// the handshake stops being one round trip for no reason.
	budget := DefaultMaxMessageSize - core.TransportOverhead() - frameHeaderSize
	if n := len(chunkBlob(core.FramePQEK, make([]byte, core.PQEncapsulationKeySize), budget)); n != 1 {
		t.Errorf("the encapsulation key needs %d chunks at the default message size", n)
	}
	if n := len(chunkBlob(core.FramePQCT, make([]byte, core.PQCiphertextSize), budget)); n != 1 {
		t.Errorf("the ciphertext needs %d chunks at the default message size", n)
	}
	// And a handshake message still fits.
	if core.MaxHandshakeMessage > DefaultMaxMessageSize {
		t.Errorf("a handshake message may be %d bytes, past the %d-byte default", core.MaxHandshakeMessage, DefaultMaxMessageSize)
	}
}

func TestMTUDerivations(t *testing.T) {
	cases := []struct {
		path, overhead, wantMsg, wantInner int
	}{
		{1500, CarrierOverheadUDPIPv6, 1452, 1423},
		{1500, CarrierOverheadUDPIPv4, 1472, 1443},
		{1400, CarrierOverheadUDPIPv6, 1352, 1323},
		{1280, CarrierOverheadUDPIPv6, 1232, 1203},
	}
	for _, c := range cases {
		gotMsg := MaxMessageSizeForPath(c.path, c.overhead)
		if gotMsg != c.wantMsg {
			t.Errorf("MaxMessageSizeForPath(%d,%d) = %d, want %d", c.path, c.overhead, gotMsg, c.wantMsg)
		}
		if got := InnerMTU(gotMsg); got != c.wantInner {
			t.Errorf("InnerMTU(%d) = %d, want %d", gotMsg, got, c.wantInner)
		}
		if gotMsg+c.overhead > c.path {
			t.Errorf("a full message on a %d-byte path is a %d-byte packet", c.path, gotMsg+c.overhead)
		}
	}

	// Degenerate inputs must clamp rather than produce an unusable session.
	if got := MaxMessageSizeForPath(10, 48); got != MessageFloor() {
		t.Errorf("a tiny path gave %d, want the %d-byte floor", got, MessageFloor())
	}
	if got := MaxMessageSizeForPath(1<<20, 0); got != core.MaxTransportPayload {
		t.Errorf("a huge path gave %d, want the %d encoding limit", got, core.MaxTransportPayload)
	}
	if got := InnerMTU(0); got != 0 {
		t.Errorf("InnerMTU(0) = %d, want 0", got)
	}

	// A value produced by the helper must be accepted by the config.
	if _, err := NewGateway(Config{
		Core:           core.Config{Gateway: gatewayParams(t)},
		Static:         mustStatic(t),
		Accept:         func([]byte) error { return nil },
		MaxMessageSize: MaxMessageSizeForPath(1500, CarrierOverheadUDPIPv6),
	}); err != nil {
		t.Errorf("a derived message size was rejected: %v", err)
	}
}

// TestInnerIPv6NeedsAWiderPath states the consequence the default invites people
// to get wrong: at a 1280-byte outer path no tunnel can carry inner IPv6,
// because RFC 8200 requires the inner link to offer 1280 and the tunnel's own
// header does not fit in the difference.
func TestInnerIPv6NeedsAWiderPath(t *testing.T) {
	if InnerMTU(DefaultMaxMessageSize) >= 1280 {
		t.Fatal("the default now carries inner IPv6; the documented caveat is stale")
	}
	for _, overhead := range []int{CarrierOverheadUDPIPv6, CarrierOverheadUDPIPv4} {
		need := MinPathMTUForInnerIPv6(overhead)
		if got := InnerMTU(MaxMessageSizeForPath(need, overhead)); got < 1280 {
			t.Errorf("at the stated minimum path %d the inner MTU is %d, below the 1280 RFC 8200 requires", need, got)
		}
		if got := InnerMTU(MaxMessageSizeForPath(need-1, overhead)); got >= 1280 {
			t.Errorf("the stated minimum path %d is one byte too generous", need)
		}
	}
	if got := MinPathMTUForInnerIPv6(CarrierOverheadUDPIPv6); got != 1357 {
		t.Errorf("MinPathMTUForInnerIPv6(UDP/IPv6) = %d, want 1357", got)
	}
	if got := MinPathMTUForInnerIPv6(CarrierOverheadUDPIPv4); got != 1337 {
		t.Errorf("MinPathMTUForInnerIPv6(UDP/IPv4) = %d, want 1337", got)
	}
}

func mustStatic(t *testing.T) *core.StaticKey {
	t.Helper()
	k, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}
