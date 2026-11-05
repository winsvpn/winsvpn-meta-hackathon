package session

// CT-1 D6 tests that need the D6 API (Amendment 3): the Karn floor and the
// draw index directly (T19, T20), and the hold of early datagrams (T21: a full
// hold, the batch path, clearing, and the drain order). The D5-compatible half
// is ct1_d6_test.go.

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// TestCT1RetryFloorIsKarnBackoff is T19's floor: f(k) = max(b, min(b*2^k,
// floorCap)) for k consecutive unanswered pre-session fires, floorCap =
// min(MaxRTTPrior, Cap/Attempts); the base is the measured RTT once there is
// one (and a measured RTT above the cap is not clamped); a session in hand
// means the base alone, whatever k.
func TestCT1RetryFloorIsKarnBackoff(t *testing.T) {
	cases := []struct {
		retry Retry
		hsRTT time.Duration
		limit time.Duration
	}{
		{Retry{}, 0, time.Second},
		{Retry{RTTPrior: 30 * time.Millisecond}, 0, time.Second},
		{Retry{RTTPrior: time.Second}, 0, time.Second},
		{Retry{Base: 100 * time.Millisecond, Cap: 2 * time.Second, Attempts: 5, RTTPrior: 300 * time.Millisecond}, 0, 400 * time.Millisecond},
		{Retry{Base: 5 * time.Millisecond, Cap: 10 * time.Millisecond, Attempts: 40}, 0, 250 * time.Microsecond},
		{Retry{}, 30 * time.Millisecond, time.Second},
		{Retry{}, 1500 * time.Millisecond, time.Second},
	}
	for _, c := range cases {
		r := c.retry.orDefault()
		if got := r.floorCap(); got != c.limit {
			t.Fatalf("%+v: floorCap %v, want %v", c.retry, got, c.limit)
		}
		d := &Driver{cfg: Config{Retry: r}, hsRTT: c.hsRTT}
		base := c.hsRTT
		if base == 0 {
			base = r.RTTPrior
		}
		for k := 0; k <= 10; k++ {
			d.preFires = k
			want := base
			for i := 0; i < k && want < c.limit; i++ {
				want *= 2
			}
			want = max(base, min(want, c.limit))
			got := d.retryFloor()
			if got != want {
				t.Fatalf("%+v hsRTT %v: f(%d) = %v, want %v", c.retry, c.hsRTT, k, got, want)
			}
			if got > max(base, c.limit) {
				t.Fatalf("f(%d) = %v above both the base and floorCap %v", k, got, c.limit)
			}
		}
	}
}

// TestCT1PreSessionBackoffResetsWhenAResponseOpens is the reset half of T19
// and T20: after a pre-session fire, preFires and drawIdx are 1; when the
// response opens both are 0 (attempt is not); a generation superseded after
// that starts its pre-session phase at f(0), the measured RTT.
func TestCT1PreSessionBackoffResetsWhenAResponseOpens(t *testing.T) {
	p, _, _ := ct1DualPair(t, 1360, true)
	first, err := p.cli.Poll()
	if err != nil || first == nil {
		t.Fatalf("no initiation: %v", err)
	}
	// The first initiation is lost; the ladder fires a fresh one.
	p.clk.Advance(p.cli.NextDeadline().Sub(p.clk.Now()))
	init2, err := p.cli.Poll()
	if err != nil || init2 == nil {
		t.Fatalf("no fresh initiation at the fire: %v", err)
	}
	if p.cli.preFires != 1 || p.cli.drawIdx != 1 || p.cli.attempt != 1 {
		t.Fatalf("after one pre-session fire: preFires %d drawIdx %d attempt %d, want 1 1 1", p.cli.preFires, p.cli.drawIdx, p.cli.attempt)
	}
	if got, want := p.cli.retryFloor(), 2*DefaultRTTPrior; got != want {
		t.Fatalf("the floor after one unanswered fire is %v, want %v", got, want)
	}
	p.clk.Advance(10 * time.Millisecond)
	if _, err := p.gw.Deliver(init2); err != nil {
		t.Fatal(err)
	}
	resp := ct1GwDrain(t, p.gw)
	p.clk.Advance(10 * time.Millisecond)
	if _, err := p.cli.Deliver(resp[0]); err != nil || p.cli.sess == nil {
		t.Fatalf("the response did not open: %v", err)
	}
	if p.cli.preFires != 0 || p.cli.drawIdx != 0 || p.cli.attempt != 1 {
		t.Fatalf("after the response: preFires %d drawIdx %d attempt %d, want 0 0 1", p.cli.preFires, p.cli.drawIdx, p.cli.attempt)
	}
	hsRTT := p.cli.hsRTT
	// The PQ_EK is answered, and the whole flight is lost: the fire supersedes.
	for _, m := range drainCli(t, p) {
		if _, err := p.gw.Deliver(m); err != nil {
			t.Fatal(err)
		}
	}
	ct1GwDrain(t, p.gw)
	p.clk.Advance(p.cli.NextDeadline().Sub(p.clk.Now()))
	now := p.clk.Now()
	if m, err := p.cli.Poll(); err != nil || m == nil || p.cli.Stats().GenerationsSuperseded != 1 {
		t.Fatalf("no supersession at the fire: %v", err)
	}
	if p.cli.preFires != 0 || p.cli.retryFloor() != hsRTT {
		t.Fatalf("the superseding generation's pre-session floor: preFires %d floor %v, want 0 and the measured %v", p.cli.preFires, p.cli.retryFloor(), hsRTT)
	}
	if g := p.cli.NextDeadline().Sub(now); g < hsRTT || g >= hsRTT+ct1Window(p.cli.drawIdx) {
		t.Fatalf("the new generation's first fire %v ahead, want in [%v, %v)", g, hsRTT, hsRTT+ct1Window(p.cli.drawIdx))
	}
}

func drainCli(t *testing.T, p *pair) [][]byte {
	t.Helper()
	var out [][]byte
	for i := 0; i < 64; i++ {
		m, err := p.cli.Poll()
		if err != nil {
			t.Fatal(err)
		}
		if m == nil {
			return out
		}
		out = append(out, append([]byte(nil), m...))
	}
	t.Fatal("client did not quiesce")
	return nil
}

// ct1HeldFlight is a dual-auth pair whose client holds a session with its PQ
// ciphertext outstanding, and the gateway's whole flight for it, undelivered:
// flight[0] the PQ_CT (epoch 0), then the Ed25519 frame and the ML-DSA-65
// chunks (epoch 1).
func ct1HeldFlight(t *testing.T, size int) (*pair, [][]byte) {
	t.Helper()
	p, _, _ := ct1DualPair(t, size, true)
	var flight [][]byte
	p.filterToCli = func(idx int, m []byte) bool {
		if idx == 0 {
			return true
		}
		flight = append(flight, append([]byte(nil), m...))
		return false
	}
	p.run()
	p.filterToCli = nil
	if p.cli.sess == nil || p.cli.pqEph == nil || len(flight) < 3 {
		t.Fatalf("fixture: session %v, %d flight datagram(s)", p.cli.sess != nil, len(flight))
	}
	return p, flight
}

// TestCT1FullHoldCostsOneGeneration is T21's full-hold case: eight noise
// datagrams arrive between the PQ_EK and the PQ_CT and fill the hold; the
// honest attestation, reordered ahead of the PQ_CT, is refused (HoldRefused
// counts every one of them, and each is counted Unopenable); the PQ_CT
// ratchets and the noise fails its one retry. The connect carries with
// exactly one generation added. An injector can at worst cost a supersession.
func TestCT1FullHoldCostsOneGeneration(t *testing.T) {
	p, flight := ct1HeldFlight(t, 1360)
	for i := 0; i < holdMax; i++ {
		noise := make([]byte, 200+100*i)
		if _, err := rand.Read(noise); err != nil {
			t.Fatal(err)
		}
		if _, err := p.cli.Deliver(noise); err != nil {
			t.Fatal(err)
		}
	}
	if len(p.cli.hold) != holdMax || p.cli.Stats().Unopenable != 0 {
		t.Fatalf("fixture: hold %d, unopenable %d", len(p.cli.hold), p.cli.Stats().Unopenable)
	}
	honest := flight[1:]
	for _, m := range honest {
		if _, err := p.cli.Deliver(m); err != nil {
			t.Fatal(err)
		}
	}
	st := p.cli.Stats()
	if st.HoldRefused != uint64(len(honest)) || st.Unopenable != uint64(len(honest)) {
		t.Fatalf("HoldRefused %d Unopenable %d, want %d each (the honest datagrams)", st.HoldRefused, st.Unopenable, len(honest))
	}
	if _, err := p.cli.Deliver(flight[0]); err != nil {
		t.Fatal(err)
	}
	st = p.cli.Stats()
	if len(p.cli.hold) != 0 || st.HoldOpened != 0 || st.Unopenable != uint64(len(honest)+holdMax) {
		t.Fatalf("after the ratchet: hold %d, opened %d, unopenable %d", len(p.cli.hold), st.HoldOpened, st.Unopenable)
	}
	if p.cli.State() != StateInitiating || p.cli.DualAuthVerified() {
		t.Fatalf("the attestation cannot have arrived: %s", p.cli.State())
	}
	for i := 0; i < 20 && p.cli.State() != StateEstablished; i++ {
		p.clk.Advance(p.cli.NextDeadline().Sub(p.clk.Now()))
		p.run()
	}
	st = p.cli.Stats()
	if p.cli.State() != StateEstablished || !p.cli.DualAuthVerified() || st.GenerationsSuperseded != 1 || st.HandshakeAttempts != 2 {
		t.Fatalf("%s verified %v superseded %d attempts %d; want established, verified, 1, 2", p.cli.State(), p.cli.DualAuthVerified(), st.GenerationsSuperseded, st.HandshakeAttempts)
	}
	inner := make([]byte, 40)
	inner[0] = 0x45
	if err := p.gw.Enqueue(inner); err != nil {
		t.Fatal(err)
	}
	p.run()
	if len(p.atCli) == 0 {
		t.Fatal("not carrying after the extra generation")
	}
}

// TestCT1HoldDrainsOnEitherPath is T21's batch-path case (and the scalar one
// beside it): the gateway's attestation and a DATA message, all epoch 1,
// arrive ahead of the epoch-0 PQ_CT. They are held, drained once the PQ_CT's
// own handling has returned, and the connect establishes with the
// attestation verified and the early DATA delivered, with no supersession and
// nothing counted Unopenable.
func TestCT1HoldDrainsOnEitherPath(t *testing.T) {
	for _, path := range ct1Paths {
		for _, size := range ct1Sizes {
			t.Run(fmt.Sprintf("%s/size=%d", path, size), func(t *testing.T) {
				p, flight := ct1HeldFlight(t, size)
				// The gateway is established: its first DATA is epoch 1 too.
				data := ct1Seal(t, p.gw.sess, ct1DataFrame())
				early := append(append([][]byte{}, flight[1:]...), data)
				msgs := append(append([][]byte{}, early...), flight[0])
				pkts := ct1DeliverVia(t, p.cli, path, msgs...)
				st := p.cli.Stats()
				if p.cli.State() != StateEstablished || !p.cli.DualAuthVerified() {
					t.Fatalf("%s verified %v", p.cli.State(), p.cli.DualAuthVerified())
				}
				if st.HoldOpened != uint64(len(early)) || st.HoldRefused != 0 || st.Unopenable != 0 || st.GenerationsSuperseded != 0 {
					t.Fatalf("opened %d refused %d unopenable %d superseded %d; want %d 0 0 0", st.HoldOpened, st.HoldRefused, st.Unopenable, st.GenerationsSuperseded, len(early))
				}
				if len(pkts) != 1 || len(p.cli.hold) != 0 {
					t.Fatalf("%d packet(s) delivered, hold %d; want the early DATA and an empty hold", len(pkts), len(p.cli.hold))
				}
			})
		}
	}
}

// TestCT1HoldIsEmptyAfterSupersessionTerminateAndEstablish is T21's clearing
// case, in the spirit of wipe_lifecycle_test.go: datagrams held when the
// generation is superseded, when the session terminates, and (without dual
// auth, noise held) when it establishes are gone and their bytes zeroed, and
// each is counted Unopenable once.
func TestCT1HoldIsEmptyAfterSupersessionTerminateAndEstablish(t *testing.T) {
	zeroed := func(t *testing.T, held [][]byte) {
		t.Helper()
		for _, m := range held {
			for _, b := range m {
				if b != 0 {
					t.Fatal("a discarded held datagram was not wiped")
				}
			}
		}
	}
	t.Run("supersession", func(t *testing.T) {
		p, flight := ct1HeldFlight(t, 1360)
		for _, m := range flight[1:3] {
			p.cli.Deliver(m)
		}
		held := append([][]byte{}, p.cli.hold...)
		if len(held) != 2 {
			t.Fatalf("fixture: %d held", len(held))
		}
		p.clk.Advance(p.cli.NextDeadline().Sub(p.clk.Now()))
		if m, err := p.cli.Poll(); err != nil || m == nil || p.cli.Stats().GenerationsSuperseded != 1 {
			t.Fatalf("no supersession: %v", err)
		}
		if len(p.cli.hold) != 0 || p.cli.Stats().Unopenable != 2 {
			t.Fatalf("after supersession: hold %d, unopenable %d", len(p.cli.hold), p.cli.Stats().Unopenable)
		}
		zeroed(t, held)
	})
	t.Run("terminate", func(t *testing.T) {
		p, flight := ct1HeldFlight(t, 1360)
		for _, m := range flight[1:3] {
			p.cli.Deliver(m)
		}
		held := append([][]byte{}, p.cli.hold...)
		if err := p.cli.Close(); err != nil {
			t.Fatal(err)
		}
		ct1PollAll(t, p.cli)
		if !p.cli.State().Terminal() || len(p.cli.hold) != 0 {
			t.Fatalf("after terminate: %s, hold %d", p.cli.State(), len(p.cli.hold))
		}
		zeroed(t, held)
	})
	t.Run("establish", func(t *testing.T) {
		p, _, _ := ct1DualPair(t, 1360, false)
		var flight [][]byte
		p.filterToCli = func(idx int, m []byte) bool {
			if idx == 0 {
				return true
			}
			flight = append(flight, append([]byte(nil), m...))
			return false
		}
		p.run()
		noise := make([]byte, 300)
		rand.Read(noise)
		p.cli.Deliver(noise)
		held := append([][]byte{}, p.cli.hold...)
		if len(held) != 1 {
			t.Fatalf("fixture: %d held", len(held))
		}
		p.cli.Deliver(flight[0])
		if p.cli.State() != StateEstablished || len(p.cli.hold) != 0 || p.cli.Stats().Unopenable != 1 {
			t.Fatalf("after establish: %s, hold %d, unopenable %d", p.cli.State(), len(p.cli.hold), p.cli.Stats().Unopenable)
		}
		zeroed(t, held)
	})
}

// TestCT1HoldDrainsAfterTheRatchetDatagramIsHandled pins the drain order (Q5
// item 3; kills the "drain inside onPQCT" mutant). A test-only gateway seals
// its PQ_CT together with a CLOSE in one epoch-0 message; the attestation,
// epoch 1, is held ahead of it. The whole of that message is handled first:
// the CLOSE ends the session, so the held attestation is discarded unopened,
// never verified, and the peer's close reason is the one it sent.
func TestCT1HoldDrainsAfterTheRatchetDatagramIsHandled(t *testing.T) {
	p, _, _ := ct1DualPair(t, 1360, true)
	m, _ := p.cli.Poll()
	p.gw.Deliver(m)
	resp := ct1GwDrain(t, p.gw)
	p.cli.Deliver(resp[0])
	for _, k := range drainCli(t, p) {
		p.gw.Deliver(k)
	}
	var fs []core.Frame
	for _, f := range p.gw.ctrl {
		if f.typ == core.FramePQCT {
			fs = append(fs, core.Frame{Type: f.typ, Value: f.value})
		}
	}
	if len(fs) == 0 || p.gw.Epoch() != 0 {
		t.Fatal("fixture: the gateway holds no PQ_CT to send")
	}
	crafted := ct1Seal(t, p.gw.sess, append(fs, core.Frame{Type: core.FrameClose, Value: []byte{byte(CloseNormal)}})...)
	flight := ct1GwDrain(t, p.gw) // its own PQ_CT (never delivered), then the attestation under epoch 1
	for _, f := range flight[1:] {
		p.cli.Deliver(f)
	}
	if len(p.cli.hold) != len(flight)-1 {
		t.Fatalf("fixture: %d held, want %d", len(p.cli.hold), len(flight)-1)
	}
	p.cli.Deliver(crafted)
	if !p.cli.State().Terminal() || p.cli.DualAuthVerified() || p.cli.Stats().HoldOpened != 0 {
		t.Fatalf("%s verified %v opened %d: the hold drained before the ratchet's own datagram was handled", p.cli.State(), p.cli.DualAuthVerified(), p.cli.Stats().HoldOpened)
	}
	if got := p.cli.PeerCloseReason(); got != CloseNormal {
		t.Fatalf("peer close reason %s, want %s", got, CloseNormal)
	}
}
