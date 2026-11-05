package tun

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
)

// TestConfigRefusesWhatWouldSilentlyBreak. Every one of these produces a tunnel
// that starts and then drops traffic for a reason nobody can see from Yangon.
// Refusing at construction turns each into a message.
func TestConfigRefusesWhatWouldSilentlyBreak(t *testing.T) {
	base := func() Config {
		return Config{
			Assign:                  fixtureAssign(),
			Device:                  &fakeDevice{mtu: fixtureInnerMTU},
			Sink:                    &fakeSink{},
			Clock:                   newFakeClock(),
			CarrierFloorMessageSize: fixtureCarrierFloor,
		}
	}
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no device", func(c *Config) { c.Device = nil }},
		{"no sink", func(c *Config) { c.Sink = nil }},
		{"no clock", func(c *Config) { c.Clock = nil }},
		{"no addresses assigned", func(c *Config) { c.Assign = Assignment{} }},
		{"loopback assigned", func(c *Config) { c.Assign = Assignment{V4: v4a(127, 0, 0, 1)} }},
		{"multicast assigned", func(c *Config) { c.Assign = Assignment{V4: v4a(239, 1, 2, 3)} }},
		{"ipv4-mapped assigned as ipv6", func(c *Config) {
			c.Assign = Assignment{V4: fixtureAssign().V4, V6: mappedV6(10, 64, 0, 2)}
		}},
		{"router equals the assigned address", func(c *Config) {
			a := fixtureAssign()
			a.RouterV4 = a.V4
			c.Assign = a
		}},
		{"router without an assignment", func(c *Config) {
			c.Assign = Assignment{V4: fixtureAssign().V4, RouterV6: ulaV6(1)}
		}},
		{"carrier floor below the overhead", func(c *Config) { c.CarrierFloorMessageSize = 20 }},
		{"carrier floor below the ipv4 floor", func(c *Config) { c.CarrierFloorMessageSize = 400 }},
		{"device mtu larger than the tunnel can carry", func(c *Config) {
			c.Device = &fakeDevice{mtu: fixtureInnerMTU + 1}
		}},
		{"device mtu zero", func(c *Config) { c.Device = &fakeDevice{mtu: 0} }},
		{"device mtu below the ipv4 floor", func(c *Config) { c.Device = &fakeDevice{mtu: 500} }},
		{"device mtu below the ipv6 minimum with ipv6 assigned", func(c *Config) {
			c.Device = &fakeDevice{mtu: 1000}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mutate(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("New accepted a configuration that would fail silently at run time")
			} else if !errors.Is(err, ErrConfig) {
				t.Fatalf("error is %v, want ErrConfig", err)
			}
		})
	}

	// And the baseline is accepted, so the table is not passing because New
	// rejects everything.
	tn, err := New(base())
	if err != nil {
		t.Fatalf("New rejected a valid configuration: %v", err)
	}
	if tn.InnerMTU() != fixtureInnerMTU || tn.DeviceMTU() != fixtureInnerMTU {
		t.Fatalf("inner MTU %d, device MTU %d", tn.InnerMTU(), tn.DeviceMTU())
	}
	if tn.Gate().State() != StateDown {
		t.Fatal("a new tunnel is not closed")
	}
}

// TestCarrierFloorNotTheCarrierInUse is the failover trap, written down as a
// test.
//
// A session may migrate from a UDP carrier to a TLS-over-TCP carrier without
// re-handshaking — that is the design's answer to a censor who blocks UDP
// wholesale. The two carriers do not have the same maximum message size, and
// the inner MTU is fixed in the host's interface configuration at start. Size
// it to the carrier that happened to be dialled and the first failover black
// holes every full-size flow: the tunnel stays "up", small packets keep
// working, and large transfers stall — the worst possible failure to diagnose
// remotely.
func TestCarrierFloorNotTheCarrierInUse(t *testing.T) {
	const udpCarrier = 1452 // what a UDP carrier on a 1500-byte path offers
	const tlsCarrier = 1380 // what the TLS-over-TCP fallback offers

	floor := tlsCarrier
	if udpCarrier < floor {
		floor = udpCarrier
	}
	tn, err := New(Config{
		Assign:                  fixtureAssign(),
		Device:                  &fakeDevice{mtu: InnerMTU(floor)},
		Sink:                    &fakeSink{},
		Clock:                   newFakeClock(),
		CarrierFloorMessageSize: floor,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := CarrierMessageFor(tn.InnerMTU()); got > tlsCarrier {
		t.Fatalf("a full inner packet needs %d carrier bytes; the narrowest carrier offers %d", got, tlsCarrier)
	}
	if got := CarrierMessageFor(tn.InnerMTU()); got > udpCarrier {
		t.Fatalf("a full inner packet needs %d carrier bytes; the UDP carrier offers %d", got, udpCarrier)
	}
}

// TestCounterSemantics pins WHERE each count is taken.
//
// This is the class of bug a sibling lane found today in another package: a
// counter that incremented on the host read rather than on arrival, which would
// have torn down a working tunnel on a slow host. The names here say which side
// of the layer they belong to, and this test makes the distinction fail if it
// is ever collapsed: five reads, three of which cross, must produce five and
// three and not five and five.
func TestCounterSemantics(t *testing.T) {
	f := newFixture(t).carrying()

	f.dev.queue(
		goodV4(100),
		v4cfg{src: peerV4(), dst: peerV4(), payload: 100}.build(), // foreign source
		goodV4(200),
		[]byte{0x45, 0x00}, // truncated
		goodV6(150),
	)
	_ = f.tun.PumpOutbound(context.Background())

	st := f.tun.Stats()
	if st.DeviceReads != 5 {
		t.Fatalf("DeviceReads=%d, want 5 — this counts what the host handed us", st.DeviceReads)
	}
	if st.TxPackets != 3 {
		t.Fatalf("TxPackets=%d, want 3 — this counts what the session accepted", st.TxPackets)
	}
	if st.TxDroppedInvalid != 2 {
		t.Fatalf("TxDroppedInvalid=%d, want 2", st.TxDroppedInvalid)
	}
	if st.DeviceReads == st.TxPackets {
		t.Fatal("DeviceReads and TxPackets are the same number; one of them is counting in the wrong place")
	}
	wantBytes := uint64(100 + IPv4HeaderMin + 200 + IPv4HeaderMin + 150 + IPv6HeaderLen)
	if st.TxBytes != wantBytes {
		t.Fatalf("TxBytes=%d, want %d", st.TxBytes, wantBytes)
	}

	// The same distinction on the receive side: RxOffered counts arrivals,
	// RxPackets counts deliveries.
	_ = f.tun.Inbound(arrivingV4(100))
	_ = f.tun.Inbound(v4cfg{src: peerV4(), dst: peerV4(), payload: 100}.build())
	st = f.tun.Stats()
	if st.RxOffered != 2 || st.RxPackets != 1 || st.RxDroppedInvalid != 1 {
		t.Fatalf("offered=%d delivered=%d dropped=%d, want 2, 1 and 1", st.RxOffered, st.RxPackets, st.RxDroppedInvalid)
	}
}

// TestSinkRefusalIsNotCountedAsSent. A session that refuses a packet — because
// it is rekeying, because its counter is exhausted, because its queue is full —
// has not sent it, and a counter that says otherwise makes a stalled tunnel
// look healthy.
func TestSinkRefusalIsNotCountedAsSent(t *testing.T) {
	f := newFixture(t).carrying()
	sentinel := errors.New("session refused")
	f.sink.mu.Lock()
	f.sink.err = sentinel
	f.sink.mu.Unlock()

	if err := f.tun.Outbound(goodV4(100)); !errors.Is(err, sentinel) {
		t.Fatalf("%v, want the session's own error", err)
	}
	st := f.tun.Stats()
	if st.TxPackets != 0 || st.TxBytes != 0 || st.TxDroppedSink != 1 {
		t.Fatalf("counters: %+v", st)
	}
}

func TestDeviceWriteFailuresAreCounted(t *testing.T) {
	f := newFixture(t).carrying()
	boom := errors.New("device gone")
	f.dev.mu.Lock()
	f.dev.writeErr = boom
	f.dev.mu.Unlock()

	if err := f.tun.Inbound(arrivingV4(100)); !errors.Is(err, ErrDeviceWrite) {
		t.Fatalf("%v, want ErrDeviceWrite", err)
	}
	if st := f.tun.Stats(); st.RxDroppedDevice != 1 || st.RxPackets != 0 {
		t.Fatalf("counters: %+v", st)
	}

	// A short write is a failure too. Counting it as a delivery would report a
	// packet the host received half of.
	g := newFixture(t).carrying()
	g.dev.mu.Lock()
	g.dev.shortBy = 1
	g.dev.mu.Unlock()
	if err := g.tun.Inbound(arrivingV4(100)); !errors.Is(err, ErrDeviceWrite) {
		t.Fatalf("short write: %v, want ErrDeviceWrite", err)
	}
	if st := g.tun.Stats(); st.RxPackets != 0 {
		t.Fatalf("a short write was counted as a delivery: %+v", st)
	}
}

// TestPumpSurvivesBadPackets. A tunnel that dies because one application
// emitted one malformed packet is a tunnel a hostile network can kill by
// injecting one.
func TestPumpSurvivesBadPackets(t *testing.T) {
	f := newFixture(t).carrying()
	f.dev.queue(
		[]byte{0xff},
		v4cfg{src: peerV4(), dst: peerV4(), payload: 10}.build(),
		goodV4(4000), // oversize
		goodV4(64),   // and the loop is still alive
	)
	err := f.tun.PumpOutbound(context.Background())
	if !errors.Is(err, errNoMoreReads) {
		t.Fatalf("pump ended with %v, want the device's own end-of-queue error", err)
	}
	if f.sink.count() != 1 {
		t.Fatalf("session saw %d packets, want the single valid one", f.sink.count())
	}
	if st := f.tun.Stats(); st.DeviceReads != 4 {
		t.Fatalf("DeviceReads=%d, want 4", st.DeviceReads)
	}
}

func TestPumpStopsWhenTheContextIsCancelled(t *testing.T) {
	f := newFixture(t).carrying()
	f.dev.queue(goodV4(64))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.tun.PumpOutbound(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v, want context.Canceled", err)
	}
	if f.tun.Stats().DeviceReads != 0 {
		t.Fatal("the pump read from the device after its context was cancelled")
	}
}

// TestPumpBufferIsReused makes the FrameSink aliasing contract observable
// rather than a footnote in a doc comment.
//
// The pump reads into one buffer for the life of the tunnel, and hands the sink
// a slice of it. A sink that retains the slice will find it rewritten by the
// next packet. That is a documented obligation, and a documented obligation
// nobody can see is one somebody will violate — so this test demonstrates the
// aliasing directly, and the two lanes can point at it.
func TestPumpBufferIsReused(t *testing.T) {
	f := newFixture(t).carrying()
	first := goodV4(100)
	second := v4cfg{src: fixtureAssign().V4, dst: v4a(203, 0, 113, 9), payload: 400}.build()
	f.dev.queue(first, second)
	_ = f.tun.PumpOutbound(context.Background())

	aliases := f.sink.allAliases()
	if len(aliases) != 2 {
		t.Fatalf("sink saw %d packets, want 2", len(aliases))
	}
	// The slice handed over for the first packet now holds the second packet's
	// bytes, because both are windows onto the same buffer.
	if !bytes.Equal(aliases[0], second[:len(aliases[0])]) {
		t.Fatal("the pump did not reuse its buffer; the aliasing contract in FrameSink.SendData is describing something that is not true")
	}
	// And the copies the sink took are intact, which is what a correct sink does.
	copies := f.sink.all()
	if !bytes.Equal(copies[0], first) {
		t.Fatal("a sink that copies immediately does not see the reuse")
	}
}

func TestPumpIgnoresEmptyReads(t *testing.T) {
	f := newFixture(t).carrying()
	f.dev.queue(nil, goodV4(64))
	_ = f.tun.PumpOutbound(context.Background())
	if f.sink.count() != 1 {
		t.Fatalf("sink saw %d packets, want 1", f.sink.count())
	}
	if st := f.tun.Stats(); st.DeviceReads != 2 || st.TxDroppedInvalid != 0 {
		t.Fatalf("counters: %+v", st)
	}
}

// TestSetStateDelegatesToTheGate makes sure the convenience method is the same
// authority and not a second one.
func TestSetStateDelegatesToTheGate(t *testing.T) {
	f := newFixture(t)
	f.tun.SetState(StateCarrying)
	if f.gate.State() != StateCarrying {
		t.Fatal("SetState and Gate() are not the same authority")
	}
	if f.gate.Generation() != 1 {
		t.Fatalf("generation=%d, want 1", f.gate.Generation())
	}
	f.tun.SetState(StateCarrying)
	if f.gate.Generation() != 1 {
		t.Fatal("a no-op transition bumped the generation")
	}
	f.tun.SetState(StateDown)
	if f.gate.Generation() != 2 {
		t.Fatalf("generation=%d, want 2", f.gate.Generation())
	}
}

// TestTheStateVocabularyIsExactlyThis pins the SIX STRINGS THEMSELVES.
//
// ===========================================================================
// WHAT THIS REPLACED, AND WHY THE REPLACEMENT IS NOT PEDANTRY
// ===========================================================================
//
// Until 2026-08-09 this was `TestStateStrings`, and it asserted two things:
// `s.String() != ""` for every state, and `State(200).String() == "invalid"`.
// Both are true of an infinity of vocabularies. Renaming `carrying` to
// anything non-empty left it green.
//
// The name is not a diagnostic. cmd/winn-datapath publishes it as `gate_state`
// and five host call sites across four platforms decide whether to promote a
// tunnel by comparing against their own copy of it. A rename here that nothing
// catches gives every host an unrecognised name, every mayCarry() answer
// false, and a tunnel that handshakes, rekeys, moves bytes and never carries
// the user's traffic — silently, and indistinguishably from the censor.
//
// So the strings are written out, once, by hand, in the test. That duplication
// is deliberate: a test that derived the expectation from String() would agree
// with any rename. winn3/conform's TestTheGateStateVocabularyIsTheSameOnEveryHost
// holds the other end of the same seam, against the hosts' own source.
func TestTheStateVocabularyIsExactlyThis(t *testing.T) {
	want := []struct {
		state State
		name  string
	}{
		{StateDown, "down"},
		{StateHandshaking, "handshaking"},
		{StateEpoch0, "epoch0"},
		{StateCarrying, "carrying"},
		{StateRekeying, "rekeying"},
		{StateClosed, "closed"},
	}
	for _, c := range want {
		if got := c.state.String(); got != c.name {
			t.Errorf("State(%d).String() = %q, want %q.\n"+
				"  This string CROSSES THE ENGINE→HOST BOUNDARY as `gate_state`. Five host "+
				"call sites compare against their own copy of it:\n"+
				"    android/app/src/main/kotlin/org/winsvpn/app/WinnV3StagedStart.kt\n"+
				"    android/devicecheck/app/src/main/kotlin/org/winsvpn/app/WinnV3StagedStart.kt\n"+
				"    windows/runner/winn3_posture.h            (kCarryingGate)\n"+
				"    apple/WinsTunnelCore/WinsWinn3HostContract.swift (carryingState)\n"+
				"    linux/runner/linux_winn3_host.cc          (via winn3_posture.h)\n"+
				"  Renaming it here without renaming it in all five gives every host an "+
				"unrecognised name, mayCarry() false, and a tunnel that never promotes while "+
				"reporting no error anywhere.",
				uint8(c.state), got, c.name)
		}
	}

	// EXACTLY ONE of them carries, and it is the one the hosts compare against.
	carrying := []string{}
	for _, c := range want {
		if c.state.MayCarry() {
			carrying = append(carrying, c.name)
		}
	}
	if len(carrying) != 1 || carrying[0] != "carrying" {
		t.Errorf("the states that carry are %v, want exactly [carrying]", carrying)
	}

	// The names are DISTINCT. Two states sharing a name makes the seam
	// ambiguous in the direction that matters: a host would parse one wire name
	// into whichever state its own list happened to reach first.
	seen := map[string]State{}
	for _, c := range want {
		if prior, dup := seen[c.name]; dup {
			t.Errorf("State(%d) and State(%d) are both named %q",
				uint8(prior), uint8(c.state), c.name)
		}
		seen[c.name] = c.state
	}

	// And none of them is the sentinel. If a real state were ever named
	// "invalid", a host could not tell a state it recognised from a value that
	// was never a state.
	if _, clash := seen[InvalidStateName]; clash {
		t.Errorf("a declared state is named %q, which is the sentinel String() gives a "+
			"value that is NOT a state", InvalidStateName)
	}
}

// TestEveryNamedStateIsDeclaredAndEveryDeclaredStateIsNamed walks all 256 byte
// values.
//
// It closes the gap between the switch in String() and the slice in
// DeclaredStates(): a state added to one and not the other is a state that
// either has a name nothing can parse, or a parse nothing can produce. Both
// halves are asserted, because only one of them is visible from either side.
func TestEveryNamedStateIsDeclaredAndEveryDeclaredStateIsNamed(t *testing.T) {
	declared := map[State]bool{}
	for _, s := range DeclaredStates() {
		if declared[s] {
			t.Errorf("DeclaredStates lists State(%d) twice", uint8(s))
		}
		declared[s] = true
	}

	for i := 0; i < 256; i++ {
		s := State(uint8(i))
		named := s.String() != InvalidStateName
		if named && !declared[s] {
			t.Errorf("State(%d) is named %q but is not in DeclaredStates().\n"+
				"  ParseState walks DeclaredStates, so this name can be EMITTED and never "+
				"PARSED — the engine would publish a gate_state no host, and not even Go, "+
				"can turn back into a state.", i, s.String())
		}
		if declared[s] && !named {
			t.Errorf("State(%d) is in DeclaredStates() but String() calls it %q.\n"+
				"  It would be published as the sentinel, and ParseState refuses the "+
				"sentinel, so the state could never round-trip.", i, InvalidStateName)
		}
	}

	if len(declared) != 6 {
		t.Errorf("DeclaredStates() has %d entries, want 6. If a state was added on purpose, "+
			"every host's vocabulary has to grow with it — see "+
			"winn3/conform.TestTheGateStateVocabularyIsTheSameOnEveryHost, which will name "+
			"the ones that did not.", len(declared))
	}
}

// TestEveryEmittedNameParsesBackToItsOwnState is the seam in the direction the
// HOSTS read it.
//
// Every host receives a NAME and has to arrive at a decision. This is that
// mapping, asserted as a mapping rather than as "a string came out".
func TestEveryEmittedNameParsesBackToItsOwnState(t *testing.T) {
	for _, s := range DeclaredStates() {
		got, ok := ParseState(s.String())
		if !ok {
			t.Errorf("ParseState(%q) refused a name String() emits. The engine would "+
				"publish a gate_state its own parser rejects.", s.String())
			continue
		}
		if got != s {
			t.Errorf("ParseState(%q) = State(%d), want State(%d) — the round trip lands on "+
				"a DIFFERENT state, so a host reading this name acts on the wrong one",
				s.String(), uint8(got), uint8(s))
		}
		if got.MayCarry() != s.MayCarry() {
			t.Errorf("ParseState(%q).MayCarry() = %v, want %v",
				s.String(), got.MayCarry(), s.MayCarry())
		}
	}
}

// TestAnUnknownGateStateNameFailsClosed is the assertion `State(200) ==
// "invalid"` was standing in for and did not make.
//
// The old line proved an undeclared VALUE gets a name. The question that
// actually decides whether a user's traffic moves is the other one: what
// happens to an unrecognised NAME. The answer must be "not carrying", by
// refusal and not by a default, because the moment a parser defaults it fails
// OPEN on the next name either side of the seam adds.
func TestAnUnknownGateStateNameFailsClosed(t *testing.T) {
	unknown := []string{
		"",
		"invalid",       // the sentinel is NOT a state
		"established",   // winn3/session's vocabulary, a plausible confusion
		"Carrying",      // case matters; a host normalises before it asks
		" carrying",     // so does whitespace
		"carrying ",     //
		"carry",         // a prefix is not a match
		"carrying_full", // nor is the name a prefix of something else
		"conveying",     // what a rename would look like from the host side
		"up",            //
		"\x00carrying",  //
	}
	for _, name := range unknown {
		got, ok := ParseState(name)
		if ok {
			t.Errorf("ParseState(%q) accepted a name that is not in the vocabulary", name)
		}
		if got.MayCarry() {
			t.Errorf("ParseState(%q) failed OPEN: it refused the name and still returned a "+
				"state that CARRIES (State(%d)).\n"+
				"  A refusal that lands on StateCarrying is worse than no parser: it moves "+
				"the user's traffic on a name nothing recognised.", name, uint8(got))
		}
		if got != StateDown {
			t.Errorf("ParseState(%q) returned State(%d) on refusal, want StateDown. The zero "+
				"value is the one every uninitialised Gate already reads as, so a caller "+
				"that ignores ok still ends up closed.", name, uint8(got))
		}
	}

	// And the undeclared-VALUE half the old assertion did make, kept and
	// widened: EVERY byte value that is not a declared state is the sentinel,
	// not just 200.
	declared := map[State]bool{}
	for _, s := range DeclaredStates() {
		declared[s] = true
	}
	for i := 0; i < 256; i++ {
		s := State(uint8(i))
		if declared[s] {
			continue
		}
		if s.String() != InvalidStateName {
			t.Errorf("State(%d).String() = %q; an undeclared state must not be given a "+
				"plausible-looking name", i, s.String())
		}
		if s.MayCarry() {
			t.Errorf("State(%d) is undeclared and CARRIES", i)
		}
	}
}

// TestAssignmentValidationCoversBothFamilies exercises the assignment checks
// directly, including the ones New cannot reach because an earlier check fires
// first.
func TestAssignmentValidationCoversBothFamilies(t *testing.T) {
	cases := []struct {
		name string
		a    Assignment
	}{
		{"empty", Assignment{}},
		{"ipv6 in the v4 slot", Assignment{V4: ulaV6(2)}},
		{"ipv4 in the v6 slot", Assignment{V6: v4a(10, 64, 0, 2)}},
		{"mapped v6", Assignment{V6: mappedV6(10, 64, 0, 2)}},
		{"compat v6", Assignment{V6: compatV6(2)}},
		{"unspecified v4", Assignment{V4: netip.AddrFrom4([4]byte{})}},
		{"router v4 is v6", Assignment{V4: v4a(10, 64, 0, 2), RouterV4: ulaV6(1)}},
		{"router v6 is mapped", Assignment{V6: ulaV6(2), RouterV6: mappedV6(10, 64, 0, 1)}},
		{"router v6 without v6", Assignment{V4: v4a(10, 64, 0, 2), RouterV6: ulaV6(1)}},
		{"router v4 without v4", Assignment{V6: ulaV6(2), RouterV4: v4a(10, 64, 0, 1)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.a.validate(); err == nil {
				t.Fatal("validate accepted an unusable assignment")
			}
		})
	}
	good := fixtureAssign()
	if err := good.validate(); err != nil {
		t.Fatalf("validate rejected the fixture: %v", err)
	}
	if !good.hasV4() || !good.hasV6() {
		t.Fatal("the fixture should carry both families")
	}
}

// TestRateLimiterFirstCallIsAllowed covers the bucket's cold start, where an
// uninitialised last-seen time would otherwise compute a nonsense elapsed
// interval from the zero Time.
func TestRateLimiterFirstCallIsAllowed(t *testing.T) {
	tb := newTokenBucket(1, 1)
	c := newFakeClock()
	if !tb.allow(c.Now()) {
		t.Fatal("the first call was refused")
	}
	if tb.allow(c.Now()) {
		t.Fatal("the bucket refilled without time passing")
	}
	c.advance(2_000_000_000) // two seconds, in nanoseconds
	if !tb.allow(c.Now()) {
		t.Fatal("the bucket did not refill")
	}
	if tb.allow(c.Now()) {
		t.Fatal("the bucket refilled past its burst")
	}
}
