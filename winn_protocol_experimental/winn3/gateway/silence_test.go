package gateway

import (
	"crypto/rand"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// silentCfg turns the admission meter off, so that these tests reach core's
// admission check every time and measure the protocol's silence rather than the
// rate limiter's. The rate limiter has its own tests.
func silentCfg() Config {
	return Config{
		InitialWindow:  16,
		MaxWindow:      64,
		MinWindow:      16,
		MaxSessions:    32,
		AdmissionRate:  -1,
		AdmissionBurst: -1,
		SourceRate:     -1,
		SourceBurst:    -1,
		allowUnmetered: true,
	}
}

// mustBeSilent is the single assertion this whole file exists to make.
func mustBeSilent(t *testing.T, res Result, what string) {
	t.Helper()
	if res.Reply != nil {
		t.Fatalf("%s: the gateway answered %d bytes. A gateway that answers an "+
			"unauthenticated datagram is a gateway a censor can find by sending it one.",
			what, len(res.Reply))
	}
	if res.Kind != KindDropped {
		t.Fatalf("%s: Kind is %s, want dropped", what, res.Kind)
	}
	if res.Entry != nil || res.Plaintext != nil {
		t.Fatalf("%s: a rejected datagram produced an entry or a plaintext", what)
	}
}

// TestEveryRejectionPathAnswersNothing walks every way a datagram can be
// refused and demands the identical nothing from all of them.
//
// The list is the point. §4.3 of the design says the only way to make a Winn3
// gateway emit a byte is a fresh initiation that authenticates under that
// gateway's admission key; this enumerates the alternatives and checks each one
// individually, including the two that are easy to forget — a replayed
// initiation, which would otherwise turn one captured packet into a permanent
// gateway detector, and a replayed transport message.
func TestEveryRejectionPathAnswersNothing(t *testing.T) {
	h := newRealHarness(t, silentCfg())
	c := h.newClient(t, 1, 8)
	src := []byte("peer-A")

	before := h.gw.Table().Sessions()

	t.Run("empty and short", func(t *testing.T) {
		for n := 0; n <= core.TransportOverhead(); n++ {
			buf := make([]byte, n)
			rand.Read(buf)
			mustBeSilent(t, h.gw.Handle(buf, src, h.clock()), "a random datagram of length "+itoa(n))
		}
	})

	t.Run("noise at every plausible length", func(t *testing.T) {
		for n := core.TransportOverhead(); n <= core.MaxHandshakeMessage+64; n += 37 {
			buf := make([]byte, n)
			rand.Read(buf)
			mustBeSilent(t, h.gw.Handle(buf, src, h.clock()), "noise of length "+itoa(n))
		}
	})

	t.Run("replayed initiation", func(t *testing.T) {
		// c.initMsg already authenticated once, against the responder directly.
		mustBeSilent(t, h.gw.Handle(c.initMsg, src, h.clock()), "a replayed initiation")
		mustBeSilent(t, h.gw.Handle(c.initMsg, src, h.clock()), "the same replayed initiation again")
	})

	t.Run("corrupted initiation", func(t *testing.T) {
		for i := 0; i < len(c.initMsg); i += 11 {
			bad := append([]byte(nil), c.initMsg...)
			bad[i] ^= 0x80
			mustBeSilent(t, h.gw.Handle(bad, src, h.clock()), "an initiation with byte "+itoa(i)+" flipped")
		}
	})

	t.Run("initiation from outside the skew window", func(t *testing.T) {
		fresh := h.initiation(t)
		h.setNow(fixedNow.Add(10 * time.Minute))
		mustBeSilent(t, h.gw.Handle(fresh, src, h.clock()), "an initiation whose bucket has expired")
		h.setNow(fixedNow)
	})

	t.Run("replayed transport message", func(t *testing.T) {
		res := h.gw.Handle(c.msgs[0], src, h.clock())
		if res.Kind != KindTransport {
			t.Fatalf("the genuine transport message did not open: %s", res.Kind)
		}
		if res.Reply != nil {
			t.Fatal("a transport message produced a reply; transport is never answered at this layer")
		}
		for i := 0; i < 4; i++ {
			mustBeSilent(t, h.gw.Handle(c.msgs[0], src, h.clock()), "a replayed transport message")
		}
	})

	t.Run("corrupted transport message", func(t *testing.T) {
		bad := append([]byte(nil), c.msgs[1]...)
		bad[len(bad)-1] ^= 0x01
		mustBeSilent(t, h.gw.Handle(bad, src, h.clock()), "a transport message with a flipped tag byte")
		// And the genuine one still opens afterwards.
		if res := h.gw.Handle(c.msgs[1], src, h.clock()); res.Kind != KindTransport {
			t.Fatal("the genuine message was invalidated by a corrupted copy of it")
		}
	})

	t.Run("transport message for a session that has gone", func(t *testing.T) {
		h.gw.Table().Remove(c.entry)
		mustBeSilent(t, h.gw.Handle(c.msgs[2], src, h.clock()), "a message for an evicted session")
	})

	if got := h.gw.Table().Sessions(); got != before-1 {
		t.Fatalf("the session count moved from %d to %d across a file full of rejections "+
			"(one deliberate removal aside)", before, got)
	}
}

// TestACapturedInitiationIsSilentAtEveryInstantOfItsAcceptanceWindow.
//
// core pins the freshness/replay-cache handover at the crypto layer; this pins
// that the gateway inherits it without a gap. The freshness window and the
// replay-cache lifetime coincide at (2*spread+1)*window, so a captured
// initiation is refused by the cache while its tag still verifies and by the
// tag once it does not — and at no instant in between is it both forgotten and
// still valid. If those two formulas ever drift apart, the gap is a window in
// which a censor's recorded packet becomes a working gateway detector again.
func TestACapturedInitiationIsSilentAtEveryInstantOfItsAcceptanceWindow(t *testing.T) {
	h := newRealHarness(t, silentCfg())

	window := core.DefaultBucketWindow
	spread := int((core.DefaultMaxSkew + window - 1) / window)
	span := time.Duration(2*spread+1) * window

	captured := h.initiation(t)

	// A gateway whose clock is maximally behind accepts it at the very start of
	// the acceptance window, which stamps the replay cache as early as it can
	// possibly be stamped: the worst case for the coupling.
	earliest := fixedNow.Add(-time.Duration(spread) * window)
	h.setNow(earliest)
	first := h.gw.Handle(captured, []byte("peer"), h.clock())
	if first.Kind != KindHandshake || first.Reply == nil {
		t.Fatalf("the maximally-early acceptance must succeed, got %s", first.Kind)
	}
	sessions := h.gw.Table().Sessions()

	expiry := earliest.Add(span)
	for at := earliest; at.Before(expiry.Add(2 * window)); at = at.Add(window / 4) {
		h.setNow(at)
		res := h.gw.Handle(captured, []byte("peer"), h.clock())
		mustBeSilent(t, res, "a captured initiation replayed at +"+at.Sub(earliest).String())
		if got := h.gw.Table().Sessions(); got != sessions {
			t.Fatalf("a replayed initiation created a session at +%s", at.Sub(earliest))
		}
	}
}

// TestAFullTableAnswersNothing. Capacity is a rejection like any other: the
// client that cannot be served sees exactly what a probe sees, so a censor
// cannot tell a busy gateway from an absent one.
func TestAFullTableAnswersNothing(t *testing.T) {
	cfg := silentCfg()
	cfg.MaxSessions = 1
	cfg.DisableEvictOnAdmit = true
	h := newRealHarness(t, cfg)

	if res := h.gw.Handle(h.initiation(t), []byte("peer-1"), h.clock()); res.Kind != KindHandshake {
		t.Fatalf("the first client was not admitted: %s", res.Kind)
	}
	for i := 0; i < 5; i++ {
		mustBeSilent(t, h.gw.Handle(h.initiation(t), []byte("peer-2"), h.clock()), "an initiation to a full gateway")
	}
	if got := h.gw.Stats().Refused; got != 5 {
		t.Fatalf("Refused is %d, want 5", got)
	}
	if got := h.gw.Table().Sessions(); got != 1 {
		t.Fatalf("%d sessions on a table capped at 1", got)
	}
}

// TestABrokenBinderAnswersNothing. The binder is the seam to core; if it fails,
// the gateway has a session it cannot route to. It must then say nothing at all
// rather than complete a handshake it cannot honour.
func TestABrokenBinderAnswersNothing(t *testing.T) {
	h := newRealHarness(t, silentCfg())
	broken, err := New(silentCfg(), testGatewayPathMTU, h.resp, refusingBinder())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(broken.Table().Close)

	mustBeSilent(t, broken.Handle(h.initiation(t), []byte("peer"), h.clock()), "an initiation a broken binder could not complete")
	if got := broken.Table().Sessions(); got != 0 {
		t.Fatalf("%d sessions were created despite the binder failing", got)
	}
	if got := broken.Stats().Refused; got != 1 {
		t.Fatalf("Refused is %d, want 1", got)
	}
}

// TestThrottlingIsSilentToo. The rate limiter is a rejection path like any
// other and must be indistinguishable from the rest.
func TestThrottlingIsSilentToo(t *testing.T) {
	cfg := silentCfg()
	cfg.AdmissionRate = 1
	cfg.AdmissionBurst = 1
	h := newRealHarness(t, cfg)

	if res := h.gw.Handle(h.initiation(t), []byte("peer"), h.clock()); res.Kind != KindHandshake {
		t.Fatalf("the first initiation, which is inside the burst, was not admitted: %s", res.Kind)
	}
	for i := 0; i < 10; i++ {
		mustBeSilent(t, h.gw.Handle(h.initiation(t), []byte("peer"), h.clock()), "a throttled initiation")
	}
	if got := h.gw.Stats().Throttled; got != 10 {
		t.Fatalf("Throttled is %d, want 10", got)
	}
	// The budget refills with time, so throttling is a delay and not a
	// permanent refusal.
	h.setNow(fixedNow.Add(5 * time.Second))
	if res := h.gw.Handle(h.initiation(t), []byte("peer"), h.clock()); res.Kind != KindHandshake {
		t.Fatalf("the budget did not refill: %s", res.Kind)
	}
}

// TestOnlyAFreshAuthenticatedInitiationEmitsAByte states the positive form of
// the invariant, so that the tests above cannot pass by the gateway being
// broken and silent about everything.
func TestOnlyAFreshAuthenticatedInitiationEmitsAByte(t *testing.T) {
	h := newRealHarness(t, silentCfg())
	res := h.gw.Handle(h.initiation(t), []byte("peer"), h.clock())
	if res.Kind != KindHandshake || len(res.Reply) == 0 {
		t.Fatalf("a fresh authenticated initiation produced %s with %d reply bytes", res.Kind, len(res.Reply))
	}
	if res.Entry == nil {
		t.Fatal("an accepted handshake produced no table entry")
	}
	if h.gw.Stats().Handshakes != 1 {
		t.Fatalf("Handshakes is %d, want 1", h.gw.Stats().Handshakes)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
