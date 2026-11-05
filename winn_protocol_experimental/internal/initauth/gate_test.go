package initauth

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_780_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// transportDatagram is the measured steady-state shape: 32 bytes with the H4
// word at offset 0 (S4 = 0, so a transport datagram carries no prefix). It is
// what a flow sends after its handshake, and it is deliberately NOT
// initiation-shaped, so it can only be admitted by an existing grant.
func transportDatagram() []byte {
	d := make([]byte, 32)
	binary.LittleEndian.PutUint32(d[:4], 44)
	_, _ = rand.Read(d[8:])
	return d
}

// junkDatagram is one of the Jc datagrams AmneziaWG emits before the handshake:
// random bytes of a random size in [Jmin, Jmax]. The measured fleet profile
// produced 27 and 16 bytes on a real handset.
func junkDatagram(size int) []byte {
	d := make([]byte, size)
	_, _ = rand.Read(d)
	return d
}

func newTestGate(t *testing.T, clock *fakeClock, mode Mode, limits Limits, keys ...[]byte) *Gate {
	t.Helper()
	if len(keys) == 0 {
		keys = [][]byte{testKey(t, 0xa1)}
	}
	g, err := NewGate(Config{
		Keys:    keys,
		Profile: fleetProfile,
		Limits:  limits,
		Mode:    mode,
		Now:     clock.Now,
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	return g
}

func sealedInitiation(t *testing.T, key []byte, at time.Time) []byte {
	t.Helper()
	d := makeInitiation(t, fleetProfile)
	if err := Seal(d, key, fleetProfile, at, Options{}); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return d
}

func TestGateAdmitsAnAuthenticatedInitiationAndThenTheWholeFlowBehindIt(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	g := newTestGate(t, clock, ModeRequire, Limits{}, key)
	client := netip.MustParseAddrPort("203.0.113.9:41234")

	// The junk that precedes the handshake is dropped, which is exactly what
	// amneziawg-go would have done with it.
	if outcome, admit := g.Consider(client, junkDatagram(27)); outcome != OutcomeNoGrant || admit {
		t.Fatalf("junk before the handshake: outcome=%s admit=%v", outcome, admit)
	}

	init := sealedInitiation(t, key, clock.Now())
	if outcome, admit := g.Consider(client, init); outcome != OutcomeAuthenticated || !admit {
		t.Fatalf("sealed initiation: outcome=%s admit=%v", outcome, admit)
	}

	for i := 0; i < 5; i++ {
		clock.Advance(25 * time.Second)
		if outcome, admit := g.Consider(client, transportDatagram()); outcome != OutcomeEstablished || !admit {
			t.Fatalf("transport datagram %d: outcome=%s admit=%v", i, outcome, admit)
		}
	}

	snap := g.Snapshot()
	if snap.Counters.Authenticated != 1 || snap.Counters.Established != 5 || snap.Counters.NoGrant != 1 {
		t.Fatalf("counters: %+v", snap.Counters)
	}
	if snap.Grants != 1 {
		t.Fatalf("grants = %d, want 1", snap.Grants)
	}
}

// This is the headline property. SPA_DECISION_20260806.md §3 called the CGNAT
// exposure information-theoretic for a firewall gate: authorisation is granted
// to an address shared by thousands of subscribers of a state-linked carrier,
// so an investigator with a SIM on that carrier is inside the grant without
// holding the key, for the whole sliding 30-minute window.
//
// Here the authenticator and the traffic it authorises leave the same socket,
// so the grant names the NAT mapping rather than the egress address, and the
// neighbour is simply not in it. There is no window to race.
func TestACoResidentCGNATNeighbourSharingTheEgressAddressIsNotAdmitted(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	g := newTestGate(t, clock, ModeRequire, Limits{}, key)

	// One carrier egress address; two subscribers, two NAT mappings.
	realUser := netip.MustParseAddrPort("198.51.100.7:52001")
	investigator := netip.MustParseAddrPort("198.51.100.7:52002")

	if outcome, admit := g.Consider(realUser, sealedInitiation(t, key, clock.Now())); outcome != OutcomeAuthenticated || !admit {
		t.Fatalf("real user: outcome=%s admit=%v", outcome, admit)
	}

	// The neighbour probes hard for the whole grace window while the real
	// user's session is live and continuously refreshing the grant.
	for i := 0; i < 50; i++ {
		clock.Advance(2 * time.Second)
		if _, admit := g.Consider(realUser, transportDatagram()); !admit {
			t.Fatalf("the real user's own traffic stopped being admitted at step %d", i)
		}
		if outcome, admit := g.Consider(investigator, transportDatagram()); admit {
			t.Fatalf("co-resident neighbour admitted at step %d: outcome=%s", i, outcome)
		}
		if outcome, admit := g.Consider(investigator, junkDatagram(30)); admit {
			t.Fatalf("co-resident neighbour's junk admitted at step %d: outcome=%s", i, outcome)
		}
	}

	// And an unsealed initiation from the neighbour gets them nowhere either.
	unsealed := makeInitiation(t, fleetProfile)
	if outcome, admit := g.Consider(investigator, unsealed); outcome != OutcomeUnauthenticated || admit {
		t.Fatalf("neighbour's unsealed initiation: outcome=%s admit=%v", outcome, admit)
	}
}

func TestACapturedInitiationReplayedFromAnotherSocketIsRefused(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	g := newTestGate(t, clock, ModeRequire, Limits{}, key)

	victim := netip.MustParseAddrPort("198.51.100.7:52001")
	attacker := netip.MustParseAddrPort("198.51.100.7:52002")

	init := sealedInitiation(t, key, clock.Now())
	if outcome, _ := g.Consider(victim, init); outcome != OutcomeAuthenticated {
		t.Fatalf("victim: outcome=%s", outcome)
	}

	// The attacker captured those exact bytes off the wire and replays them.
	// They verify — the tag is valid — and are refused anyway.
	if outcome, admit := g.Consider(attacker, init); outcome != OutcomeReplay || admit {
		t.Fatalf("replay from a second socket: outcome=%s admit=%v", outcome, admit)
	}
	// Still refused a minute later, inside the skew window.
	clock.Advance(30 * time.Second)
	if outcome, admit := g.Consider(attacker, init); outcome != OutcomeReplay || admit {
		t.Fatalf("replay after 30s: outcome=%s admit=%v", outcome, admit)
	}
}

// A retransmitted initiation inside a live flow must NOT be treated as a
// replay. AmneziaWG retransmits its handshake, and a censor degrading the link
// is enough to make that the normal case rather than the exception.
func TestARetransmittedInitiationInsideALiveFlowIsStillAdmitted(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	g := newTestGate(t, clock, ModeRequire, Limits{}, key)
	client := netip.MustParseAddrPort("203.0.113.9:41234")

	init := sealedInitiation(t, key, clock.Now())
	if outcome, _ := g.Consider(client, init); outcome != OutcomeAuthenticated {
		t.Fatalf("first initiation: outcome=%s", outcome)
	}
	clock.Advance(5 * time.Second)
	if outcome, admit := g.Consider(client, init); outcome != OutcomeEstablished || !admit {
		t.Fatalf("retransmission on the same 4-tuple: outcome=%s admit=%v", outcome, admit)
	}
}

// The drop-resilience property, which fwknop-style SPA does not have: the
// assessment recorded "no knock retry. One datagram, 50 ms settle, dial." Here
// every AmneziaWG handshake retry is a fresh initiation with a fresh
// authenticator, so a censor who drops the first N costs the client latency and
// nothing else.
func TestADroppingCensorOnlyCostsLatencyBecauseEveryRetryReauthenticates(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	g := newTestGate(t, clock, ModeRequire, Limits{}, key)
	client := netip.MustParseAddrPort("203.0.113.9:41234")

	// 23 initiations are dropped on the path and never reach the gate at all —
	// the measured censor drew 24 retries out of the client.
	for i := 0; i < 23; i++ {
		_ = sealedInitiation(t, key, clock.Now())
		clock.Advance(5 * time.Second)
	}
	// The 24th gets through. Its bucket is 115 seconds past the first one's,
	// which is well outside a 60-second skew window — so this also proves the
	// authenticator is recomputed per attempt rather than cached.
	if outcome, admit := g.Consider(client, sealedInitiation(t, key, clock.Now())); outcome != OutcomeAuthenticated || !admit {
		t.Fatalf("the surviving retry: outcome=%s admit=%v", outcome, admit)
	}
}

func TestObserveModeAdmitsEverythingAndStillCountsWhatEnforcingWouldHaveDropped(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	g := newTestGate(t, clock, ModeObserve, Limits{}, key)
	client := netip.MustParseAddrPort("203.0.113.9:41234")
	stranger := netip.MustParseAddrPort("203.0.113.10:5000")

	if _, admit := g.Consider(client, sealedInitiation(t, key, clock.Now())); !admit {
		t.Fatal("a sealed initiation must be admitted in observe mode")
	}
	for i := 0; i < 7; i++ {
		if outcome, admit := g.Consider(stranger, makeInitiation(t, fleetProfile)); !admit || outcome != OutcomeUnauthenticated {
			t.Fatalf("observe mode must admit an unauthenticated initiation: outcome=%s admit=%v", outcome, admit)
		}
	}
	if outcome, admit := g.Consider(stranger, junkDatagram(20)); !admit || outcome != OutcomeNoGrant {
		t.Fatalf("observe mode must admit junk: outcome=%s admit=%v", outcome, admit)
	}

	snap := g.Snapshot()
	if snap.Counters.AdmittedWhileObserving != 8 {
		t.Fatalf("AdmittedWhileObserving = %d, want 8 — this is the number that answers 'what would enforcing cost me'", snap.Counters.AdmittedWhileObserving)
	}
	if snap.Counters.Unauthenticated != 7 || snap.Counters.NoGrant != 1 || snap.Counters.Authenticated != 1 {
		t.Fatalf("counters: %+v", snap.Counters)
	}
	if snap.Mode != ModeObserve {
		t.Fatalf("mode = %s", snap.Mode)
	}
}

func TestTheGateSelfDemotesWhenNothingIsAdmittedForTheWholeWindow(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	var demoted string
	g, err := NewGate(Config{
		Keys:     [][]byte{key},
		Profile:  fleetProfile,
		Mode:     ModeRequire,
		Now:      clock.Now,
		Limits:   Limits{MinRejectedBeforeDemote: 20, DemoteAfter: time.Minute, RateCapacity: 1_000_000, RatePerMinute: 60_000_000},
		OnDemote: func(why string) { demoted = why },
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	stranger := netip.MustParseAddrPort("203.0.113.10:5000")

	// Nineteen rejections, and more than the window has elapsed: the count
	// threshold has not been crossed, so nothing happens.
	for i := 0; i < 19; i++ {
		g.Consider(stranger, makeInitiation(t, fleetProfile))
	}
	clock.Advance(2 * time.Minute)
	if g.Mode() != ModeRequire {
		t.Fatal("demoted on the window alone, before the count threshold")
	}

	g.Consider(stranger, makeInitiation(t, fleetProfile))
	if g.Mode() != ModeObserve {
		t.Fatal("both thresholds were crossed and the gate did not demote")
	}
	snap := g.Snapshot()
	if snap.Counters.Demotions != 1 || snap.DemoteWhy == "" || snap.DemotedAt.IsZero() {
		t.Fatalf("demotion not recorded: %+v", snap)
	}
	if demoted == "" {
		t.Fatal("OnDemote was not called")
	}
	// And after demoting it admits, which is the entire point: the failure mode
	// is "stop gating", never "stop admitting".
	if _, admit := g.Consider(stranger, makeInitiation(t, fleetProfile)); !admit {
		t.Fatal("a demoted gate must admit")
	}
}

// The false-positive guard, and it is load-bearing. Without it a single source
// gets a remote kill switch on the gate: rate limiting and rejection are normal
// under load, and a busy CGNAT egress can produce thousands of rejections in a
// burst that resolves itself.
func TestAFloodThatResolvesInsideTheWindowDoesNotDemoteTheGate(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	g := newTestGate(t, clock, ModeRequire, Limits{
		MinRejectedBeforeDemote: 20,
		DemoteAfter:             time.Minute,
		RateCapacity:            1_000_000,
		RatePerMinute:           60_000_000,
	}, key)
	stranger := netip.MustParseAddrPort("203.0.113.10:5000")

	// Twice the count threshold, all inside the window.
	for i := 0; i < 40; i++ {
		clock.Advance(time.Second)
		g.Consider(stranger, makeInitiation(t, fleetProfile))
	}
	if g.Mode() != ModeRequire {
		t.Fatal("a burst inside the window demoted the gate; this is the remote kill switch the pairing exists to prevent")
	}
	if g.Snapshot().Counters.Demotions != 0 {
		t.Fatal("demotion counted")
	}
}

func TestOneAdmittedInitiationResetsTheDemotionStreak(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	g := newTestGate(t, clock, ModeRequire, Limits{
		MinRejectedBeforeDemote: 20,
		DemoteAfter:             time.Minute,
		RateCapacity:            1_000_000,
		RatePerMinute:           60_000_000,
	}, key)
	stranger := netip.MustParseAddrPort("203.0.113.10:5000")
	realUser := netip.MustParseAddrPort("203.0.113.11:6000")

	for i := 0; i < 19; i++ {
		g.Consider(stranger, makeInitiation(t, fleetProfile))
	}
	clock.Advance(2 * time.Minute)

	// One real client gets in. That proves the gate is not locked out, so both
	// the counter and the window origin must reset.
	if outcome, _ := g.Consider(realUser, sealedInitiation(t, key, clock.Now())); outcome != OutcomeAuthenticated {
		t.Fatalf("real user: outcome=%s", outcome)
	}

	for i := 0; i < 19; i++ {
		g.Consider(stranger, makeInitiation(t, fleetProfile))
	}
	if g.Mode() != ModeRequire {
		t.Fatal("the streak was not reset by an accepted initiation")
	}
}

func TestRateLimitingRunsBeforeVerificationSoAFloodCannotBecomeCPUExhaustion(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	g := newTestGate(t, clock, ModeRequire, Limits{RateCapacity: 3, RatePerMinute: 60}, key)
	flood := netip.MustParseAddrPort("203.0.113.10:5000")

	var verified, limited int
	for i := 0; i < 10; i++ {
		outcome, admit := g.Consider(flood, makeInitiation(t, fleetProfile))
		if admit {
			t.Fatal("an unauthenticated initiation was admitted")
		}
		switch outcome {
		case OutcomeUnauthenticated:
			verified++
		case OutcomeRateLimited:
			limited++
		default:
			t.Fatalf("unexpected outcome %s", outcome)
		}
	}
	if verified != 3 {
		t.Fatalf("%d datagrams reached verification, want exactly the burst capacity of 3", verified)
	}
	if limited != 7 {
		t.Fatalf("%d datagrams were refused before verification, want 7", limited)
	}

	// A real client behind a DIFFERENT mapping is untouched by the flood,
	// because the bucket is per source address and this one is fresh.
	clean := netip.MustParseAddrPort("203.0.113.12:7000")
	if outcome, admit := g.Consider(clean, sealedInitiation(t, key, clock.Now())); outcome != OutcomeAuthenticated || !admit {
		t.Fatalf("clean client: outcome=%s admit=%v", outcome, admit)
	}

	// And the bucket refills.
	clock.Advance(time.Minute)
	if outcome, _ := g.Consider(flood, makeInitiation(t, fleetProfile)); outcome != OutcomeUnauthenticated {
		t.Fatalf("after refill: outcome=%s", outcome)
	}
}

// The deliberate inversion of ../ratelimit's semantics.
// SPA_DECISION_20260806.md §6 showed that refusing a NEW source when the table
// is full is a silent lockout an attacker holds open indefinitely by
// re-touching forged addresses. This gate evicts instead.
func TestATableFullOfForgedSourcesShedsRatherThanLockingOutANewOne(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	g := newTestGate(t, clock, ModeRequire, Limits{RateMaxSources: 8, RateCapacity: 4, RatePerMinute: 60}, key)

	// Fill and overflow the limiter table with forged sources.
	for i := 0; i < 400; i++ {
		src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i % 256)}), uint16(1024+i))
		g.Consider(src, makeInitiation(t, fleetProfile))
	}
	if shed := g.Snapshot().Counters.RateSourcesShed; shed == 0 {
		t.Fatal("the limiter never shed, so this test did not exercise the path it exists for")
	}

	// A real client arriving now must still be admitted. Under
	// ../ratelimit's refuse-when-full behaviour this is the datagram that would
	// have been dropped, silently, for the duration of the flood plus the idle
	// window.
	real := netip.MustParseAddrPort("203.0.113.55:41234")
	if outcome, admit := g.Consider(real, sealedInitiation(t, key, clock.Now())); outcome != OutcomeAuthenticated || !admit {
		t.Fatalf("a real client was locked out by a table full of forged sources: outcome=%s admit=%v", outcome, admit)
	}
}

func TestAGrantExpiresAfterGraceAndSlidesForwardOnItsOwnTraffic(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	g := newTestGate(t, clock, ModeRequire, Limits{Grace: 30 * time.Second}, key)
	client := netip.MustParseAddrPort("203.0.113.9:41234")

	if outcome, _ := g.Consider(client, sealedInitiation(t, key, clock.Now())); outcome != OutcomeAuthenticated {
		t.Fatalf("initiation: outcome=%s", outcome)
	}
	// A live session keeps the grant alive indefinitely on its own keepalives.
	for i := 0; i < 20; i++ {
		clock.Advance(25 * time.Second)
		if outcome, admit := g.Consider(client, transportDatagram()); outcome != OutcomeEstablished || !admit {
			t.Fatalf("keepalive %d: outcome=%s admit=%v", i, outcome, admit)
		}
	}
	// Silence past the grace window forgets it.
	clock.Advance(31 * time.Second)
	if outcome, admit := g.Consider(client, transportDatagram()); outcome != OutcomeNoGrant || admit {
		t.Fatalf("after grace: outcome=%s admit=%v", outcome, admit)
	}
}

func TestTheSameClientOnADualStackListenerIsOneGrantNotTwo(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	g := newTestGate(t, clock, ModeRequire, Limits{}, key)

	v4 := netip.MustParseAddrPort("203.0.113.9:41234")
	mapped := netip.MustParseAddrPort("[::ffff:203.0.113.9]:41234")

	if outcome, _ := g.Consider(v4, sealedInitiation(t, key, clock.Now())); outcome != OutcomeAuthenticated {
		t.Fatalf("outcome=%s", outcome)
	}
	if outcome, admit := g.Consider(mapped, transportDatagram()); outcome != OutcomeEstablished || !admit {
		t.Fatalf("the 4-in-6 form of the same client was not recognised: outcome=%s admit=%v", outcome, admit)
	}
	if got := g.Snapshot().Grants; got != 1 {
		t.Fatalf("grants = %d, want 1", got)
	}
}

func TestNewGateRefusesAConfigurationItCannotHonourRatherThanDegrading(t *testing.T) {
	if _, err := NewGate(Config{Keys: [][]byte{testKey(t, 1)}, Profile: Profile{S1: 0, H1Start: 1, H1End: 1}}); err == nil {
		t.Fatal("a profile with no room was accepted")
	}
	if _, err := NewGate(Config{Keys: nil, Profile: fleetProfile}); err == nil {
		t.Fatal("a gate with no keys was accepted")
	}
	if _, err := NewGate(Config{Keys: [][]byte{[]byte("short")}, Profile: fleetProfile}); err == nil {
		t.Fatal("a short key was accepted")
	}
	if _, err := NewGate(Config{
		Keys:    [][]byte{testKey(t, 1)},
		Profile: fleetProfile,
		Options: Options{BucketWindow: time.Second, MaxSkew: 24 * time.Hour},
	}); err == nil {
		t.Fatal("a skew wide enough to make verification expensive was accepted")
	}
}

// The end-to-end filter over real sockets, including the property that decides
// whether an active prober learns anything: the gate must never write a byte
// back, on any path, for any reason.
func TestWrapPacketConnDeliversOnlyAdmittedDatagramsAndNeverWritesBack(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	g := newTestGate(t, clock, ModeRequire, Limits{}, key)

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer server.Close()
	gated := g.WrapPacketConn(server)

	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer client.Close()

	target := server.LocalAddr()

	// A prober's traffic first: junk, a wrong-sized datagram, and an
	// initiation-shaped one with a forged prefix.
	for _, probe := range [][]byte{
		junkDatagram(27),
		junkDatagram(1200),
		makeInitiation(t, fleetProfile),
		transportDatagram(),
	} {
		if _, err := client.WriteTo(probe, target); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	// Then a real client's sealed initiation, from the same socket.
	sealed := sealedInitiation(t, key, clock.Now())
	if _, err := client.WriteTo(sealed, target); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 2048)
	if err := gated.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	n, from, err := gated.ReadFrom(buf)
	if err != nil {
		t.Fatalf("the gated conn delivered nothing; the four probes should have been consumed and the fifth delivered: %v", err)
	}
	if n != len(sealed) {
		t.Fatalf("delivered %d bytes, want the %d-byte sealed initiation", n, len(sealed))
	}
	if string(buf[:n]) != string(sealed) {
		t.Fatal("the delivered datagram was modified in transit; the wrapper must be byte-transparent")
	}
	if from == nil {
		t.Fatal("no source address")
	}

	// Nothing at all came back to the client, from any of the five datagrams.
	if err := client.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if n, _, err := client.ReadFrom(buf); err == nil {
		t.Fatalf("the gate answered a prober with %d bytes; every rejection path must be silent", n)
	}

	snap := g.Snapshot()
	if snap.Counters.Authenticated != 1 {
		t.Fatalf("counters: %+v", snap.Counters)
	}
	if snap.Counters.NoGrant != 3 || snap.Counters.Unauthenticated != 1 {
		t.Fatalf("counters: %+v", snap.Counters)
	}
}

// One scenario walking the whole adversary the threat model names: drop, delay,
// replay, and active probing, against a gate in enforcing mode.
func TestTheGateHoldsAgainstAnAdversaryWhoDropsDelaysReplaysAndProbes(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	g := newTestGate(t, clock, ModeRequire, Limits{}, key)

	user := netip.MustParseAddrPort("198.51.100.7:52001")
	adversary := netip.MustParseAddrPort("198.51.100.7:52002")

	// DROP: the first two initiations never arrive.
	first := sealedInitiation(t, key, clock.Now())
	clock.Advance(5 * time.Second)
	second := sealedInitiation(t, key, clock.Now())
	clock.Advance(5 * time.Second)
	_ = first
	_ = second

	// DELAY: the third arrives 45 seconds late, inside the 60-second skew.
	third := sealedInitiation(t, key, clock.Now())
	clock.Advance(45 * time.Second)
	if outcome, admit := g.Consider(user, third); outcome != OutcomeAuthenticated || !admit {
		t.Fatalf("a delayed initiation inside the skew window: outcome=%s admit=%v", outcome, admit)
	}

	// REPLAY: the adversary, behind the same CGNAT egress, replays the one that
	// worked, from their own mapping, while it is still inside the skew window.
	if outcome, admit := g.Consider(adversary, third); outcome != OutcomeReplay || admit {
		t.Fatalf("replay: outcome=%s admit=%v", outcome, admit)
	}

	// DELAY past the window: the first one, held back and released 115 seconds
	// after it was sealed, is refused on freshness alone — it would be refused
	// even if the replay cache had been emptied, because its bucket is gone.
	// Note the tolerance is bucket-granular, so a 60-second skew over 10-second
	// buckets admits up to 6 buckets in each direction; 115 s is 11.
	clock.Advance(60 * time.Second)
	if outcome, admit := g.Consider(adversary, first); outcome != OutcomeUnauthenticated || admit {
		t.Fatalf("an initiation held past the skew window: outcome=%s admit=%v", outcome, admit)
	}

	// PROBE: 200 crafted, correctly-shaped, correctly-sized initiations with
	// forged prefixes, plus scan traffic of every other shape.
	for i := 0; i < 200; i++ {
		if _, admit := g.Consider(adversary, makeInitiation(t, fleetProfile)); admit {
			t.Fatalf("a forged initiation was admitted at attempt %d", i)
		}
		if _, admit := g.Consider(adversary, junkDatagram(1+i%1400)); admit {
			t.Fatalf("scan traffic was admitted at attempt %d", i)
		}
	}

	// Through all of it the real user's session is untouched.
	clock.Advance(25 * time.Second)
	if outcome, admit := g.Consider(user, transportDatagram()); outcome != OutcomeEstablished || !admit {
		t.Fatalf("the real session was disturbed by the adversary: outcome=%s admit=%v", outcome, admit)
	}
}

// The grant and replay tables carry the same fail-open posture as the limiter,
// and for the same reason: refusing a real client is worse than admitting one
// datagram to a state machine that authenticates on its own account. These two
// tests exist because the posture is only real if the exhaustion path is
// exercised, and an untested fail-open is just an assumption.
func TestAFullGrantTableShedsRatherThanRefusingANewFlow(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	g := newTestGate(t, clock, ModeRequire, Limits{MaxGrants: 8}, key)

	for i := 0; i < 200; i++ {
		src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i % 251)}), uint16(1024+i))
		if outcome, admit := g.Consider(src, sealedInitiation(t, key, clock.Now())); outcome != OutcomeAuthenticated || !admit {
			t.Fatalf("flow %d was refused while the grant table was under pressure: outcome=%s", i, outcome)
		}
	}
	snap := g.Snapshot()
	if snap.Counters.GrantsShed == 0 {
		t.Fatal("the grant table never shed, so this test did not exercise the path it exists for")
	}
	if snap.Grants > 8 {
		t.Fatalf("grants = %d, past the cap of 8", snap.Grants)
	}
}

func TestAFullReplayTableShedsAndTheGateKeepsAdmitting(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	g := newTestGate(t, clock, ModeRequire, Limits{MaxReplayEntries: 8}, key)
	client := netip.MustParseAddrPort("203.0.113.9:41234")

	for i := 0; i < 200; i++ {
		// A fresh 4-tuple each time, so every datagram takes the verification
		// path rather than the grant short-circuit.
		src := netip.AddrPortFrom(client.Addr(), uint16(20000+i))
		if outcome, admit := g.Consider(src, sealedInitiation(t, key, clock.Now())); outcome != OutcomeAuthenticated || !admit {
			t.Fatalf("initiation %d refused under replay-table pressure: outcome=%s", i, outcome)
		}
	}
	snap := g.Snapshot()
	if snap.Counters.ReplayShed == 0 {
		t.Fatal("the replay table never shed")
	}
	if snap.ReplayCache > 8 {
		t.Fatalf("replay cache = %d, past the cap of 8", snap.ReplayCache)
	}
}

func TestExpiredGrantsAndReplayEntriesArePrunedRatherThanAccumulating(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	g := newTestGate(t, clock, ModeRequire, Limits{Grace: 30 * time.Second}, key)

	for i := 0; i < 40; i++ {
		src := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.9"), uint16(20000+i))
		if outcome, _ := g.Consider(src, sealedInitiation(t, key, clock.Now())); outcome != OutcomeAuthenticated {
			t.Fatalf("initiation %d: outcome=%s", i, outcome)
		}
	}
	if got := g.Snapshot().Grants; got != 40 {
		t.Fatalf("grants = %d, want 40", got)
	}

	// Everything above is now stale. The next verification prunes it.
	clock.Advance(10 * time.Minute)
	fresh := netip.MustParseAddrPort("203.0.113.9:30000")
	if outcome, _ := g.Consider(fresh, sealedInitiation(t, key, clock.Now())); outcome != OutcomeAuthenticated {
		t.Fatalf("fresh initiation: outcome=%s", outcome)
	}
	snap := g.Snapshot()
	if snap.Grants != 1 {
		t.Fatalf("grants = %d after pruning, want 1", snap.Grants)
	}
	if snap.ReplayCache != 1 {
		t.Fatalf("replay cache = %d after pruning, want 1", snap.ReplayCache)
	}
	if snap.Counters.GrantsShed != 0 || snap.Counters.ReplayShed != 0 {
		t.Fatalf("pruning should not have needed to shed: %+v", snap.Counters)
	}
}

func TestModeAndOutcomeNamesAreStableBecauseOperatorsReadThem(t *testing.T) {
	if ModeObserve.String() != "observe" || ModeRequire.String() != "require" || Mode(9).String() != "unknown" {
		t.Fatal("mode names changed")
	}
	want := map[Outcome]string{
		OutcomeEstablished:     "established",
		OutcomeAuthenticated:   "authenticated",
		OutcomeUnauthenticated: "unauthenticated",
		OutcomeReplay:          "replay",
		OutcomeRateLimited:     "rate_limited",
		OutcomeNoGrant:         "no_grant",
	}
	for outcome, name := range want {
		if outcome.String() != name {
			t.Fatalf("%d.String() = %q, want %q", outcome, outcome.String(), name)
		}
	}
	if Outcome(9).String() != "unknown" {
		t.Fatal("unknown outcome name changed")
	}
	if !OutcomeEstablished.Admits() || !OutcomeAuthenticated.Admits() {
		t.Fatal("an admitting outcome stopped admitting")
	}
	for _, o := range []Outcome{OutcomeUnauthenticated, OutcomeReplay, OutcomeRateLimited, OutcomeNoGrant} {
		if o.Admits() {
			t.Fatalf("%s must not admit", o)
		}
	}
}

func TestOnOutcomeSeesEveryDecisionIncludingTheOnesTheModeOverrides(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	var seen []Outcome
	var admits []bool
	g, err := NewGate(Config{
		Keys:    [][]byte{key},
		Profile: fleetProfile,
		Mode:    ModeObserve,
		Now:     clock.Now,
		OnOutcome: func(_ netip.AddrPort, o Outcome, admitted bool) {
			seen = append(seen, o)
			admits = append(admits, admitted)
		},
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	src := netip.MustParseAddrPort("203.0.113.9:41234")
	g.Consider(src, junkDatagram(27))
	g.Consider(src, makeInitiation(t, fleetProfile))
	g.Consider(src, sealedInitiation(t, key, clock.Now()))

	if len(seen) != 3 {
		t.Fatalf("OnOutcome fired %d times, want 3", len(seen))
	}
	if seen[0] != OutcomeNoGrant || seen[1] != OutcomeUnauthenticated || seen[2] != OutcomeAuthenticated {
		t.Fatalf("outcomes = %v", seen)
	}
	for i, a := range admits {
		if !a {
			t.Fatalf("observe mode reported decision %d as not admitted", i)
		}
	}
}

// The window must start at the first rejection of the streak. A gate that sat
// idle (no traffic at all) for longer than DemoteAfter must not demote on the
// first burst that crosses the count; it demotes only once rejections have
// continued, unbroken, for the whole window.
func TestABurstAfterAnIdlePeriodDoesNotDemoteTheGate(t *testing.T) {
	clock := newFakeClock()
	key := testKey(t, 0xa1)
	g := newTestGate(t, clock, ModeRequire, Limits{
		MinRejectedBeforeDemote: 20,
		DemoteAfter:             time.Minute,
		RateCapacity:            1_000_000,
		RatePerMinute:           60_000_000,
	}, key)
	stranger := netip.MustParseAddrPort("203.0.113.10:5000")

	clock.Advance(10 * time.Minute)
	for i := 0; i < 40; i++ {
		clock.Advance(500 * time.Millisecond)
		g.Consider(stranger, makeInitiation(t, fleetProfile))
	}
	if g.Mode() != ModeRequire {
		t.Fatal("a 20s burst after an idle period demoted the gate; the window must run from the first rejection")
	}

	// The guard itself still works: the same streak continuing past the
	// window demotes.
	clock.Advance(time.Minute)
	g.Consider(stranger, makeInitiation(t, fleetProfile))
	if g.Mode() != ModeObserve {
		t.Fatal("an unbroken streak longer than the window did not demote")
	}
}
