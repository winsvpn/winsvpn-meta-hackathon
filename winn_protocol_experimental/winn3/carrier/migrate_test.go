package carrier

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
)

// stickyClock is a session.Clock that never advances, so no session timer fires
// and the handshake and migration are driven purely by message exchange.
type stickyClock struct {
	t time.Time
}

func (c *stickyClock) Now() time.Time { return c.t }

// sizedPipe is a Conn with a chosen class and ceiling, for migration tests.
func sizedPipe(t *testing.T, class Class, size int) *Pipe {
	t.Helper()
	p, err := NewPipe(PipeConfig{Class: class, MaxMessageSize: size, PathMTU: 1500})
	if err != nil {
		t.Fatalf("pipe %s/%d: %v", class, size, err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// TestMigrationToAWiderCarrierChangesNothing.
//
// A destination that can carry more than the session emits is not a problem to
// solve. Widening would buy payload at the cost of a message-size discontinuity
// at exactly the instant a session moves between transports — which is a
// correlator linking the flow before the move to the flow after it, on a design
// whose §5.4 wants that move to be unlinkable.
func TestMigrationToAWiderCarrierChangesNothing(t *testing.T) {
	t.Parallel()
	from := sizedPipe(t, ClassTLS, 1168)
	to := sizedPipe(t, ClassUDP, 1252)
	sink := &sizeSink{}

	m, err := Migrate(sink, from, to, 1168)
	if err != nil {
		t.Fatalf("widening migration failed: %v", err)
	}
	if m.Narrows || m.SizeApplied || m.Remedy != RemedyNone {
		t.Fatalf("a widening migration did something: %+v", m)
	}
	if len(sink.got) != 0 {
		t.Fatalf("the session was told a new size on a widening migration: %v", sink.got)
	}
	if m.From != ClassTLS || m.To != ClassUDP {
		t.Fatalf("classes are %s -> %s", m.From, m.To)
	}
	// Equal is also "wide enough".
	if m, err := Migrate(sink, from, sizedPipe(t, ClassUDP, 1168), 1168); err != nil || m.Narrows {
		t.Fatalf("an equal-size migration was treated as narrowing: %+v %v", m, err)
	}
}

// TestNarrowingMigrationTellsTheSession is the black-hole fix.
//
// UDP over IPv4 at a 1280-byte path carries 1252 bytes of message; TLS over IPv6
// carries 1168. A session built for the first and moved to the second is 84
// bytes over on every full-size packet, and the symptom is a tunnel that reports
// "up" while every large transfer stalls.
func TestNarrowingMigrationTellsTheSession(t *testing.T) {
	t.Parallel()
	from := sizedPipe(t, ClassUDP, 1252)
	to := sizedPipe(t, ClassTLS, 1168)
	sink := &sizeSink{}

	m, err := Migrate(sink, from, to, 1252)
	if err != nil {
		t.Fatalf("narrowing migration failed: %v", err)
	}
	if !m.Narrows {
		t.Fatal("the narrowing was not detected")
	}
	if !m.SizeApplied {
		t.Fatal("the session was not told")
	}
	if len(sink.got) != 1 || sink.got[0] != 1168 {
		t.Fatalf("the session was told %v, want [1168]", sink.got)
	}
	if m.Remedy != RemedyNone {
		t.Fatalf("a completed migration proposed remedy %s", m.Remedy)
	}
}

// TestNarrowingMigrationIsRefusedWhenTheSessionCannotBeTold.
//
// A caller without a mutable session cannot apply the narrower ceiling.
// Refusing is actionable — the caller can tear down and re-handshake at the
// smaller size — and completing is not, because nothing downstream would ever
// report the black hole. The refusal names which remedy applies rather than
// choosing it.
func TestNarrowingMigrationIsRefusedWhenTheSessionCannotBeTold(t *testing.T) {
	t.Parallel()
	from := sizedPipe(t, ClassUDP, 1252)
	to := sizedPipe(t, ClassTLS, 1168)

	m, err := Migrate(nil, from, to, 1252)
	if !errors.Is(err, ErrMigrationWouldBlackHole) {
		t.Fatalf("got %v, want ErrMigrationWouldBlackHole", err)
	}
	if m.Remedy != RemedyTellSession {
		t.Fatalf("remedy is %s, want tell-session", m.Remedy)
	}
	if m.SizeApplied {
		t.Fatal("a refused migration reported the size applied")
	}
	if m.CarrierSize != 1168 || m.SessionSize != 1252 {
		t.Fatalf("the refusal reports the wrong numbers: %+v", m)
	}
}

// TestNarrowingMigrationIsRefusedWhenTheSessionSaysNo.
//
// A session that cannot narrow — because a queued frame already needs the wider
// size — must not be forced. The remedy changes, because the caller's options
// change: telling it is no longer available and a re-handshake is.
func TestNarrowingMigrationIsRefusedWhenTheSessionSaysNo(t *testing.T) {
	t.Parallel()
	from := sizedPipe(t, ClassUDP, 1252)
	to := sizedPipe(t, ClassTLS, 1168)
	refusal := errors.New("a queued frame needs 1200 bytes")
	sink := &sizeSink{refuse: refusal}

	m, err := Migrate(sink, from, to, 1252)
	if !errors.Is(err, ErrMigrationWouldBlackHole) {
		t.Fatalf("got %v, want ErrMigrationWouldBlackHole", err)
	}
	if m.Remedy != RemedyRehandshake {
		t.Fatalf("remedy is %s, want rehandshake", m.Remedy)
	}
	if got := err.Error(); got == "" || !contains(got, refusal.Error()) {
		t.Fatalf("the refusal does not carry the session's reason: %q", got)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// TestMigrateRefusals.
func TestMigrateRefusals(t *testing.T) {
	t.Parallel()
	to := sizedPipe(t, ClassTLS, 1168)
	if _, err := Migrate(nil, nil, nil, 1168); !errors.Is(err, ErrConfig) {
		t.Fatalf("a nil destination returned %v", err)
	}
	if _, err := Migrate(nil, nil, to, session.MessageFloor()-1); !errors.Is(err, ErrConfig) {
		t.Fatalf("a session size below the floor returned %v", err)
	}
	if _, err := Migrate(nil, nil, nil, session.MessageFloor()-1); !errors.Is(err, ErrConfig) ||
		!contains(err.Error(), "session size") {
		t.Fatalf("two invalid inputs returned %v, want the session-size refusal first", err)
	}
	// A nil source is legal: the first carrier a session ever gets has no
	// predecessor, and refusing that would make the initial attach a special
	// case with its own untested path.
	if m, err := Migrate(nil, nil, to, 1168); err != nil || m.From != ClassUnknown {
		t.Fatalf("a first attach was refused: %+v %v", m, err)
	}
}

// TestFloorLevelMigrationFromTheOldCarrierIsRejectedOrUpgraded is the doc.go
// failover trap asserted through migrate.go's own branching.
//
// The trap: a session sized to the carrier it DIALED — the floor of the old
// carrier, computed before the plan knew it would migrate — and then moved onto
// a transport that floor never covered. At the IPv6 minimum path a UDP carrier
// over IPv4 carries 1252 bytes of message and a TLS carrier over IPv6 carries
// 1168: a session built for the first and moved to the second is 84 bytes over
// on every full-size packet.
//
// doc.go §5 names the only two legal resolutions and forbids the silent one:
// either shrink the session explicitly (upgraded, via the sink) or, when the
// session cannot be told, refuse. A completion that neither told the session nor
// refused is the black hole the tunnel reports as "up". So the one thing a
// floor-level migration from the old carrier may never do is complete silently.
func TestFloorLevelMigrationFromTheOldCarrierIsRejectedOrUpgraded(t *testing.T) {
	t.Parallel()
	const mtu = session.IPv6MinimumLinkMTU
	oldCarrierSize := MaxMessageSizeFor(ClassUDP, FamilyIPv4, mtu) // 1252
	tlsIPv6Size := MaxMessageSizeFor(ClassTLS, FamilyIPv6, mtu)    // 1168
	if got := oldCarrierSize - tlsIPv6Size; got != 84 {
		t.Fatalf("fixture: the 84-byte TLS/IPv6-vs-UDP/IPv4 gap is now %d; the doc's trap arithmetic is stale", got)
	}
	to := sizedPipe(t, ClassTLS, tlsIPv6Size)

	// Rejected: no sink, so the session cannot be told the narrower ceiling,
	// and the migration must refuse rather than complete.
	mRej, err := Migrate(nil, sizedPipe(t, ClassUDP, oldCarrierSize), to, oldCarrierSize)
	if !errors.Is(err, ErrMigrationWouldBlackHole) {
		t.Fatalf("floor-level migration without a sink must be rejected, got %v", err)
	}
	if !mRej.Narrows {
		t.Fatal("the narrowing was not reported on the refused migration")
	}
	if mRej.Remedy != RemedyTellSession {
		t.Fatalf("rejected floor migration remedy = %s, want tell-session", mRej.Remedy)
	}
	if mRej.SizeApplied {
		t.Fatal("a refused migration reported the size applied")
	}

	// Upgraded: with a sink, the session must actually be told the ceiling, so
	// the move narrows and applies rather than silently black-holing.
	sink := &sizeSink{}
	mUp, err := Migrate(sink, sizedPipe(t, ClassUDP, oldCarrierSize), to, oldCarrierSize)
	if err != nil {
		t.Fatalf("floor-level migration with a sink failed: %v", err)
	}
	if !mUp.Narrows || !mUp.SizeApplied {
		t.Fatalf("the session was not narrowed on the upgraded migration: %+v", mUp)
	}
	if len(sink.got) != 1 || sink.got[0] != tlsIPv6Size {
		t.Fatalf("the session was told %v, want [%d]", sink.got, tlsIPv6Size)
	}
	if mUp.Remedy != RemedyNone {
		t.Fatalf("an upgraded floor migration proposed remedy %s", mUp.Remedy)
	}
}

// TestMigrationAtThePinnedFloorNeverNarrows is the primary path.
//
// Build the session at Floor over the whole plan and every migration the plan
// allows is a no-op at the size layer. The test walks every ordered pair of
// classes and requires that none of them narrows — which is the property that
// makes "pin the floor" a rule rather than a suggestion.
func TestMigrationAtThePinnedFloorNeverNarrows(t *testing.T) {
	t.Parallel()
	plan := []Class{ClassUDP, ClassTCP, ClassTLS}
	const mtu = 1280
	floor := Floor(mtu, plan...)

	for _, from := range plan {
		for _, to := range plan {
			for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
				// The carrier reports what it can carry on this family; the
				// session was built at the floor across all of them.
				carrierSize := MaxMessageSizeFor(to, family, mtu)
				dst := sizedPipe(t, to, floor)
				if carrierSize < floor {
					t.Fatalf("%s/%s carries %d, below the plan floor %d",
						to, family, carrierSize, floor)
				}
				m, err := Migrate(nil, sizedPipe(t, from, floor), dst, floor)
				if err != nil {
					t.Fatalf("%s -> %s/%s at the floor: %v", from, to, family, err)
				}
				if m.Narrows {
					t.Fatalf("%s -> %s/%s narrowed at the pinned floor", from, to, family)
				}
			}
		}
	}
}

// TestPlanFloorNeverUnderSizesTheManagedCarriers is the floor invariant, and the
// one this lane exists to hold.
//
// NewPlanFloor is the primary sizing API: a caller builds the session at
// pf.MessageSize and the tun device at pf.InnerMTU and is promised that no
// migration the plan allows can black hole. That promise is exactly the
// "a floor never under-sizes after migration" property from the
// carrierfloor/pathmtu1450 thread: the floor must be small enough to fit EVERY
// carrier the plan may reach, or that carrier's failover silently drops every
// full-size flow while the tunnel still reports "up".
//
// It is asserted two ways so the two halves cannot drift:
//
//   - the capacity inequality directly: for every class in the plan and both
//     address families, the carrier's MaxMessageSize on the path must be >= the
//     floor, and
//   - through the migration seam itself: build every carrier at the floor and
//     walk every ordered pair, requiring that none of them narrows.
//
// It is run across the fleet default (DefaultPathMTU, now 1450), the IPv6
// minimum, a value on the old dead-zone edge, and a wide path, plus the empty
// plan whose conservative reading is the whole point of "we do not yet know".
func TestPlanFloorNeverUnderSizesTheManagedCarriers(t *testing.T) {
	t.Parallel()
	plans := map[string][]Class{
		"full":  {ClassUDP, ClassTCP, ClassTLS},
		"udp":   {ClassUDP},
		"empty": nil,
	}
	for _, mtu := range []int{session.MessageFloor(), 1420, DefaultPathMTU, 1500} {
		effective := func(classes []Class) []Class {
			if len(classes) == 0 {
				return []Class{ClassUnknown}
			}
			return classes
		}
		for name, plan := range plans {
			plan := plan
			pf := NewPlanFloor(mtu, plan...)

			// The two numbers this package produces for one plan must agree.
			if pf.MessageSize != Floor(mtu, plan...) {
				t.Fatalf("mtu %d plan %-5s: NewPlanFloor.MessageSize %d != Floor %d",
					mtu, name, pf.MessageSize, Floor(mtu, plan...))
			}
			if pf.InnerMTU != InnerMTU(pf.MessageSize) {
				t.Fatalf("mtu %d plan %-5s: InnerMTU %d != InnerMTU(MessageSize) %d",
					mtu, name, pf.InnerMTU, InnerMTU(pf.MessageSize))
			}

			// 1. The capacity inequality: the floor must never exceed what any
			//    carrier the plan allows can carry, on either family.
			for _, class := range effective(plan) {
				for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
					if cap := MaxMessageSizeFor(class, family, mtu); cap < pf.MessageSize {
						t.Fatalf("mtu %d plan %-5s: floor %d EXCEEDS %s/%s capacity %d — a failover to it black holes",
							mtu, name, pf.MessageSize, class, family, cap)
					}
				}
			}

			// 2. Through the seam: build every carrier at the floor and walk
			//    every ordered pair. None may narrow, and none may be refused.
			//    ClassUnknown is a planning answer, not a carrier a pipe can
			//    stand in for, so the empty plan is walked over the concrete
			//    carriers the conservative floor must stay safe across.
			concrete := effective(plan)
			if name == "empty" {
				concrete = []Class{ClassUDP, ClassTCP, ClassTLS}
			}
			for _, from := range concrete {
				for _, to := range concrete {
					m, err := Migrate(nil,
						sizedPipe(t, from, pf.MessageSize),
						sizedPipe(t, to, pf.MessageSize),
						pf.MessageSize)
					if err != nil {
						t.Fatalf("mtu %d plan %-5s %s->%s at floor %d: %v",
							mtu, name, from, to, pf.MessageSize, err)
					}
					if m.Narrows {
						t.Fatalf("mtu %d plan %-5s %s->%s narrowed at the plan floor %d",
							mtu, name, from, to, pf.MessageSize)
					}
				}
			}
		}
	}
}

// TestMigrationCarriesALiveSessionsBytes is the end-to-end shape.
//
// The point of §5.4 is that a session survives the move. This does not run a
// real handshake — that is the session lane's suite — but it does check the
// thing this package is responsible for: that the same opaque message goes out
// over one carrier, then the other, with no state carried between them and no
// re-framing.
func TestMigrationCarriesALiveSessionsBytes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	floor := Floor(1280, ClassUDP, ClassTLS)

	udpA, udpB, err := NewPipePair(PipeConfig{Class: ClassUDP, MaxMessageSize: floor})
	if err != nil {
		t.Fatalf("udp pair: %v", err)
	}
	tlsA, tlsB, err := NewPipePair(PipeConfig{Class: ClassTLS, MaxMessageSize: floor})
	if err != nil {
		t.Fatalf("tls pair: %v", err)
	}
	defer func() {
		_ = udpA.Close()
		_ = udpB.Close()
		_ = tlsA.Close()
		_ = tlsB.Close()
	}()

	msg := message(floor, 7)
	if err := udpA.Send(ctx, msg); err != nil {
		t.Fatalf("send over udp: %v", err)
	}
	if got, err := udpB.Recv(ctx); err != nil || string(got) != string(msg) {
		t.Fatalf("udp leg: %v", err)
	}

	m, err := Migrate(nil, udpA, tlsA, floor)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if m.Narrows {
		t.Fatal("the pinned floor still narrowed")
	}
	if err := tlsA.Send(ctx, msg); err != nil {
		t.Fatalf("send over tls: %v", err)
	}
	if got, err := tlsB.Recv(ctx); err != nil || string(got) != string(msg) {
		t.Fatalf("tls leg: %v", err)
	}
	if s := tlsA.Stats(); s.Sent != 1 {
		t.Fatalf("the new carrier's counters are not its own: %+v", s)
	}
	if s := udpA.Stats(); s.Sent != 1 {
		t.Fatalf("the old carrier's counters moved after the migration: %+v", s)
	}
}

// TestRemedyStrings keeps status output readable.
func TestRemedyStrings(t *testing.T) {
	t.Parallel()
	for r, want := range map[Remedy]string{
		RemedyNone: "none", RemedyTellSession: "tell-session",
		RemedyRehandshake: "rehandshake", Remedy(9): "none",
	} {
		if got := r.String(); got != want {
			t.Errorf("Remedy(%d).String() = %q, want %q", r, got, want)
		}
	}
}

// TestDriverSatisfiesTheSink pins the live seam at compile time.
func TestDriverSatisfiesTheSink(t *testing.T) {
	t.Parallel()
	var sink MessageSizeSink = &sizeSink{}
	if err := sink.SetMaxMessageSize(1168); err != nil {
		t.Fatalf("sink: %v", err)
	}
	var _ MessageSizeSink = (*session.Driver)(nil)
}

// liveSess is a real *session.Driver wired to a carrier that can be swapped
// underneath it, matching how winn3/driver's Loop migrates a live session.
//
// It exists because every other migration test here stands a fake sizeSink in
// for the session. That asserts the branching in Migrate but never the claim
// that a REAL session survives the move. This rig drives an actual handshake to
// Established over one carrier, then swaps a second carrier in through
// carrier.Migrate — with the session itself as the MessageSizeSink — and proves
// the session's cryptographic state (epoch, keys) is untouched and it still
// carries full-size traffic on the new carrier.
type liveSess struct {
	d *session.Driver

	mu  sync.Mutex
	cur Conn

	inner chan []byte
}

func (l *liveSess) current() Conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.cur
}

// swap replaces the carrier and unblocks any Recv parked on the old one by
// closing it. It returns the old carrier so a caller can also release it.
func (l *liveSess) swap(c Conn) Conn {
	l.mu.Lock()
	old := l.cur
	l.cur = c
	l.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return old
}

// pumpLive connects a session to its carrier: one goroutine pulls inbound
// messages from the current carrier into the session and collects the inner
// packets it yields, another drains the session's outbox onto the current
// carrier. Both re-read l.current() every iteration so that a swap mid-flight is
// picked up without any handshake between pump and caller.
func pumpLive(ctx context.Context, l *liveSess) {
	go func() {
		for {
			if ctx.Err() != nil {
				return
			}
			c := l.current()
			if c == nil {
				select {
				case <-ctx.Done():
					return
				case <-time.After(200 * time.Microsecond):
				}
				continue
			}
			msg, err := c.Recv(ctx)
			if err != nil {
				// Closing the old carrier during a swap surfaces here as an
				// error; the next iteration reads the new carrier.
				continue
			}
			pkts, _ := l.d.Deliver(msg)
			for _, p := range pkts {
				select {
				case l.inner <- p:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() {
		for {
			if ctx.Err() != nil {
				return
			}
			c := l.current()
			if c == nil {
				select {
				case <-ctx.Done():
					return
				case <-time.After(200 * time.Microsecond):
				}
				continue
			}
			msg, err := l.d.Poll()
			if err != nil {
				return
			}
			if msg == nil {
				select {
				case <-ctx.Done():
					return
				case <-time.After(200 * time.Microsecond):
				}
				continue
			}
			if err := c.Send(ctx, msg); err != nil && ctx.Err() == nil {
				// A send into a carrier that was just closed during a swap is
				// not the session failing; keep going and pick up the new
				// carrier on the next iteration.
				continue
			}
		}
	}()
}

// establishLive runs a real client/gateway pair to Established and returns the
// two wired rigs. Both sides are sized at sessionSize, wide enough that a
// destination one carrier class narrower forces a genuine narrowing migration.
func establishLive(t *testing.T, sessionSize int) (*liveSess, *liveSess) {
	t.Helper()

	clk := &stickyClock{t: time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)}

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
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	gp := core.GatewayParams{AdmissionKeys: [][]byte{key}, GatewayID: []byte("migrate-live")}

	cliCar, gwCar, err := NewPipePair(PipeConfig{Class: ClassUDP, MaxMessageSize: sessionSize, PathMTU: 1500})
	if err != nil {
		t.Fatal(err)
	}

	mkCli := func() *session.Driver {
		d, err := session.NewClient(session.Config{
			Core:           core.Config{Gateway: gp},
			Static:         cliStatic,
			GatewayStatic:  gwPub,
			Padding:        core.PadBucket,
			Clock:          clk,
			MaxMessageSize: sessionSize,
		})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	mkGw := func() *session.Driver {
		d, err := session.NewGateway(session.Config{
			Core:           core.Config{Gateway: gp},
			Static:         gwStatic,
			Accept:         func([]byte) error { return nil },
			Padding:        core.PadBucket,
			Clock:          clk,
			MaxMessageSize: sessionSize,
		})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}

	cliLS := &liveSess{d: mkCli(), cur: cliCar, inner: make(chan []byte, 256)}
	gwLS := &liveSess{d: mkGw(), cur: gwCar, inner: make(chan []byte, 256)}
	return cliLS, gwLS
}

// waitEstablished blocks until both real sessions report Established.
func waitEstablished(t *testing.T, cli, gw *session.Driver) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if cli.State() == session.StateEstablished && gw.State() == session.StateEstablished {
			return
		}
		if cli.Err() != nil || gw.Err() != nil {
			t.Fatalf("terminal during handshake: cli=%v gw=%v", cli.Err(), gw.Err())
		}
		if time.Now().After(deadline) {
			t.Fatalf("never established: cli=%s gw=%s", cli.State(), gw.State())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// carry asserts that an inner packet of want bytes crosses from the client
// session to the gateway session's inner sink within the deadline.
func carry(t *testing.T, deadline time.Duration, cli *liveSess, gw *liveSess, want int, what string) {
	t.Helper()
	full := make([]byte, want)
	for i := range full {
		full[i] = byte(i)
	}
	if err := cli.d.Enqueue(full); err != nil {
		t.Fatalf("enqueue %s: %v", what, err)
	}
	select {
	case got := <-gw.inner:
		if len(got) != want {
			t.Fatalf("%s: inner packet arrived as %d bytes, want %d", what, len(got), want)
		}
	case <-time.After(deadline):
		t.Fatalf("%s: the inner packet never crossed; the live session stopped carrying", what)
	}
}

// TestLiveSessionSurvivesACarrierMigrationBoundary is the migration/floor test
// with a REAL session, not a fake sink.
//
// Every other pass through Migrate in this file stands a sizeSink in for the
// session and never proves the "live carrier preserves session state" clause of
// the doc comment. This one does: it drives an actual X25519 handshake and
// ML-KEM-768 ratchet to Established over a UDP carrier, carries a full-size
// packet, migrates to a narrower TLS carrier with the *session.Driver itself as
// the MessageSizeSink, and requires that:
//
//   - the migration is a genuine narrowing whose new ceiling was applied to the
//     live session (Narrows and SizeApplied), exactly the doc's failover trap,
//   - the session's epoch — the measure that a migration re-handshaked, which
//     §5.4 forbids — is unchanged at both ends, and
//   - a full-size packet at the NEW ceiling still crosses end to end on the new
//     carrier, so the session outlived the move rather than merely reporting it.
func TestLiveSessionSurvivesACarrierMigrationBoundary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// sessionSize is the UDP-over-IPv4 ceiling at the doc's trap, and the
	// destination TLS carrier is one class narrower, so the migration MUST
	// narrow and shrink the live session.
	oldSize := MaxMessageSizeFor(ClassUDP, FamilyIPv4, 1280) // 1252
	newSize := MaxMessageSizeFor(ClassTLS, FamilyIPv6, 1280) // 1168
	if oldSize <= newSize {
		t.Fatalf("fixture: UDP/IPv4 %d must be wider than TLS/IPv6 %d for a narrowing migration",
			oldSize, newSize)
	}

	cliLS, gwLS := establishLive(t, oldSize)
	pumpLive(ctx, cliLS)
	pumpLive(ctx, gwLS)
	if cliLS.d.Err() != nil || gwLS.d.Err() != nil {
		t.Fatalf("sessions failed before the migration: cli=%v gw=%v", cliLS.d.Err(), gwLS.d.Err())
	}
	waitEstablished(t, cliLS.d, gwLS.d)
	if cliLS.d.Epoch() != gwLS.d.Epoch() {
		t.Fatalf("fixture: client and gateway are on different epochs %d != %d",
			cliLS.d.Epoch(), gwLS.d.Epoch())
	}

	// The session is genuinely live before the move: a full-size inner packet at
	// the OLD ceiling crosses the first carrier.
	carry(t, 5*time.Second, cliLS, gwLS, session.InnerMTU(oldSize), "pre-migration UDP")

	// Quiesce so nothing is mid-flight across the swap.
	for i := 0; i < len(cliLS.inner); i++ {
		<-cliLS.inner
	}
	for i := 0; i < len(gwLS.inner); i++ {
		<-gwLS.inner
	}

	// A second pair of carriers, one class narrower, for the migration target.
	cliTLS, gwTLS, err := NewPipePair(PipeConfig{Class: ClassTLS, MaxMessageSize: newSize, PathMTU: 1500})
	if err != nil {
		t.Fatal(err)
	}

	// The migration boundary: both live sessions move onto the narrower carrier,
	// each through carrier.Migrate with the REAL session as the sink.
	epochBefore := cliLS.d.Epoch()
	mCli, err := Migrate(cliLS.d, cliLS.current(), cliTLS, oldSize)
	if err != nil {
		t.Fatalf("client migration: %v", err)
	}
	mGw, err := Migrate(gwLS.d, gwLS.current(), gwTLS, oldSize)
	if err != nil {
		t.Fatalf("gateway migration: %v", err)
	}

	// The narrowing must be applied to the live sessions, never merely detected.
	for _, m := range []Migration{mCli, mGw} {
		if !m.Narrows || !m.SizeApplied {
			t.Fatalf("migration did not narrow and apply to the live session: %+v", m)
		}
		if m.CarrierSize != newSize {
			t.Fatalf("the live session was told ceiling %d, want %d", m.CarrierSize, newSize)
		}
		if m.Remedy != RemedyNone {
			t.Fatalf("a completed live migration proposed remedy %s", m.Remedy)
		}
	}

	// Swap the pumps onto the new carriers.
	cliLS.swap(cliTLS)
	gwLS.swap(gwTLS)

	// Session state is preserved: the epochs are unchanged from before the move
	// (a re-handshake, which §5.4 forbids on migration, would advance them), and
	// both ends are still Established and healthy.
	if got := cliLS.d.Epoch(); got != epochBefore {
		t.Fatalf("client epoch changed from %d to %d across the migration; the session "+
			"re-handshaked instead of surviving the move", epochBefore, got)
	}
	if got := cliLS.d.State(); got != session.StateEstablished {
		t.Fatalf("client session is %s after migration, want established", got)
	}
	if cliLS.d.Err() != nil || gwLS.d.Err() != nil {
		t.Fatalf("session failed across the migration: cli=%v gw=%v", cliLS.d.Err(), gwLS.d.Err())
	}

	// The NEGATIVE half, which a positive-only test cannot see, asserted FIRST
	// so it stays deterministic: the narrowing must have actually taken hold in
	// the live session, not merely been recorded. A packet at the OLD ceiling —
	// which the new carrier can no longer carry — must now be refused at
	// Enqueue. A session whose ceiling was never reset (or was reset to the
	// wrong, wider number) happily accepts it, which is the black hole waiting
	// for the first full-size flow after a failover. session.Enqueue refuses on
	// size alone, before anything touches the carrier, so a wrong-ceiling
	// mutation is caught here instantly rather than by anything probabilistic on
	// the wire.
	if err := cliLS.d.Enqueue(make([]byte, session.InnerMTU(oldSize))); err == nil {
		t.Fatalf("the live session still accepts a %d-byte inner packet after the ceiling "+
			"narrowed to %d; the migration recorded the shrink without applying it, and the "+
			"first full-size post-failover flow will black hole", session.InnerMTU(oldSize), newSize)
	}

	// And it still carries: a full-size inner packet at the NEW (narrowed)
	// ceiling crosses end to end on the new carrier, so the same live session
	// goes on moving traffic over the destination transport.
	carry(t, 5*time.Second, cliLS, gwLS, session.InnerMTU(newSize), "post-migration TLS")

	if cliTLS.Stats().Sent == 0 {
		t.Fatal("nothing was sent on the destination carrier; the swap did not take")
	}
}

// TestRebindToANewSocketCarriesTheLiveSession is the rebind case.
//
// §5.4 makes migration a pointer assignment precisely because the session holds
// no socket, and the migration a mobile, renumbering network actually requires
// is usually not a carrier-class change at all: the class stays UDP, the ceiling
// is unchanged, and only the SOCKET is new. That is the shape this test drives.
// A real handshake is brought to Established over one loopback datagram socket,
// a full-size packet is carried, and then both live sessions are pointed at a
// genuinely distinct second datagram socket through carrier.Migrate, with the
// real *session.Driver as the sink.
//
// Rebind is the cheap end of migration. The size layer must do nothing — a
// same-class, same-ceiling swap that also re-shaped would hand an on-path
// observer the very correlator §5.4 wants to avoid — so the only thing at stake
// is whether the session itself outlives the swap. The test pinches the three
// measures that would catch a session dropped at the move:
//
//   - the epoch, unchanged at both ends (a re-handshake, which §5.4 forbids on a
//     move, would advance it),
//   - the old socket's counters, frozen once the swap is done (a live session
//     still flushing its old carrier would keep them moving), and
//   - carriage: a full-size inner packet at the SAME ceiling still crosses end
//     to end on the new socket, and the new socket actually sent something.
func TestRebindToANewSocketCarriesTheLiveSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The loopback sockets this test uses bind IPv6, so the concrete ceiling is
	// the IPv6 UDP one at the IPv6-minimum path floor (1232). Rebind is
	// same-class, so the ceiling does not change across the move.
	sessionSize := MaxMessageSizeFor(ClassUDP, FamilyIPv6, 1280) // 1232
	if sessionSize != 1232 {
		t.Fatalf("fixture: UDP/IPv6 ceiling at 1280 is %d, want 1232", sessionSize)
	}

	// Two pairs of real loopback datagram sockets. The second is the rebound
	// socket: a genuinely different local endpoint, same class, same ceiling.
	// OwnsConn is set so that a liveSess.swap of the old carrier actually closes
	// its kernel socket and unblocks a Recv parked on it — the pumpLive contract
	// is that a swapped-out carrier surfaces as an error and the pump moves on.
	cliOld, gwOld, cliOldSock, gwOldSock := udpPair(t, func(c *UDPConfig) {
		c.MaxMessageSize = sessionSize
		c.PathMTU = 1280
		c.OwnsConn = true
	})
	cliNew, gwNew, cliNewSock, gwNewSock := udpPair(t, func(c *UDPConfig) {
		c.MaxMessageSize = sessionSize
		c.PathMTU = 1280
		c.OwnsConn = true
	})
	defer func() {
		_ = cliOld.Close()
		_ = gwOld.Close()
		_ = cliNew.Close()
		_ = gwNew.Close()
	}()
	_ = gwOldSock
	_ = gwNewSock

	// A rebind is only a rebind if the destination is a different endpoint. If
	// the "new" socket is the old one, this test would silently exercise nothing.
	if sameUDPAddr(cliOldSock.LocalAddr().(*net.UDPAddr), cliNewSock.LocalAddr().(*net.UDPAddr)) {
		t.Fatalf("fixture: the rebound client socket is the same endpoint %s, not a new socket",
			cliOldSock.LocalAddr())
	}

	// Bring a real session to Established over the FIRST socket pair.
	clk := &stickyClock{t: time.Date(2026, 8, 11, 13, 0, 0, 0, time.UTC)}
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
	gp := core.GatewayParams{AdmissionKeys: [][]byte{admission}, GatewayID: []byte("migrate-rebind")}

	mkCli := func() *session.Driver {
		d, err := session.NewClient(session.Config{
			Core:           core.Config{Gateway: gp},
			Static:         cliStatic,
			GatewayStatic:  gwPub,
			Padding:        core.PadBucket,
			Clock:          clk,
			MaxMessageSize: sessionSize,
		})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	mkGw := func() *session.Driver {
		d, err := session.NewGateway(session.Config{
			Core:           core.Config{Gateway: gp},
			Static:         gwStatic,
			Accept:         func([]byte) error { return nil },
			Padding:        core.PadBucket,
			Clock:          clk,
			MaxMessageSize: sessionSize,
		})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}

	cliLS := &liveSess{d: mkCli(), cur: cliOld, inner: make(chan []byte, 256)}
	gwLS := &liveSess{d: mkGw(), cur: gwOld, inner: make(chan []byte, 256)}
	pumpLive(ctx, cliLS)
	pumpLive(ctx, gwLS)
	waitEstablished(t, cliLS.d, gwLS.d)
	if cliLS.d.Epoch() != gwLS.d.Epoch() {
		t.Fatalf("fixture: ends on different epochs %d != %d", cliLS.d.Epoch(), gwLS.d.Epoch())
	}

	// The session is genuinely live on the first socket before the move.
	carry(t, 5*time.Second, cliLS, gwLS, session.InnerMTU(sessionSize), "pre-rebind UDP")

	// Quiesce so nothing is mid-flight across the swap.
	for i := 0; i < len(cliLS.inner); i++ {
		<-cliLS.inner
	}
	for i := 0; i < len(gwLS.inner); i++ {
		<-gwLS.inner
	}

	// The rebind: point both live sessions at the new socket through Migrate,
	// the real session as the sink.
	epochBefore := cliLS.d.Epoch()
	mCli, err := Migrate(cliLS.d, cliLS.current(), cliNew, sessionSize)
	if err != nil {
		t.Fatalf("client rebind: %v", err)
	}
	mGw, err := Migrate(gwLS.d, gwLS.current(), gwNew, sessionSize)
	if err != nil {
		t.Fatalf("gateway rebind: %v", err)
	}

	// A same-class, same-ceiling swap must do nothing at the size layer: no
	// narrowing, nothing told, no remedy. Re-shaping on a rebind is what hands
	// an observer the move.
	for _, m := range []Migration{mCli, mGw} {
		if m.Narrows || m.SizeApplied || m.Remedy != RemedyNone {
			t.Fatalf("a same-size rebind reshaped the size layer: %+v", m)
		}
		if m.To != ClassUDP {
			t.Fatalf("rebind moved to class %s, want udp", m.To)
		}
		if m.CarrierSize != sessionSize {
			t.Fatalf("rebind destination ceiling %d, want %d", m.CarrierSize, sessionSize)
		}
	}

	// Swap the pumps onto the new sockets BEFORE any counter is frozen, so the
	// old sockets can no longer be touched by either pump after this point.
	cliLS.swap(cliNew)
	gwLS.swap(gwNew)

	// Freeze the old sockets' counters as the negative-control baseline. Nothing
	// reads or writes them once the swap has taken, so they must not move.
	oldCliSent := cliOld.Stats().Sent
	oldGwDelivered := gwOld.Stats().Delivered

	// Session state is preserved: the epoch is unchanged from before the move (a
	// re-handshake, which §5.4 forbids, would advance it), both ends are still
	// Established, and neither reports an error.
	if got := cliLS.d.Epoch(); got != epochBefore {
		t.Fatalf("client epoch changed from %d to %d across the rebind; the session "+
			"re-handshaked instead of surviving the move", epochBefore, got)
	}
	if got := cliLS.d.State(); got != session.StateEstablished {
		t.Fatalf("client session is %s after the rebind, want established", got)
	}
	if cliLS.d.Err() != nil || gwLS.d.Err() != nil {
		t.Fatalf("session failed across the rebind: cli=%v gw=%v", cliLS.d.Err(), gwLS.d.Err())
	}

	// The session still carries, at the SAME ceiling, on the NEW socket. This is
	// the positive half: the move took and the session is still live on it.
	carry(t, 5*time.Second, cliLS, gwLS, session.InnerMTU(sessionSize), "post-rebind new socket")

	// The NEGATIVE half, which a positive-only test cannot see: neither end of
	// the OLD socket carried the swapped traffic. A live session that kept
	// flushing its old carrier would have moved these counters.
	if got := cliOld.Stats().Sent; got != oldCliSent {
		t.Fatalf("the old client socket kept sending after the rebind (%d -> %d); the "+
			"session is still flushing its old carrier", oldCliSent, got)
	}
	if got := gwOld.Stats().Delivered; got != oldGwDelivered {
		t.Fatalf("the old gateway socket kept delivering after the rebind (%d -> %d)",
			oldGwDelivered, got)
	}
	if cliNew.Stats().Sent == 0 {
		t.Fatal("nothing was sent on the rebound socket; the swap did not take")
	}
}

// TestMigrateTableFreshAndAlreadyMigrated is the table form of the two
// migration shapes a caller actually reaches: a session being attached to its
// first carrier (fresh, from == nil) and a live session being moved off one
// carrier onto another (already-migrated, from != nil).
//
// The two rows are kept in one table so neither path silently drifts from the
// other. The discriminating assertion is m.From: the fresh path has no
// predecessor class and must report ClassUnknown, while the already-migrated
// path must report the carrier it actually left. Both rows use a destination
// wide enough for the session, so neither is a narrowing migration; a row that
// narrowed (or told the session a new size for no reason) would be exercising
// the wrong shape entirely.
func TestMigrateTableFreshAndAlreadyMigrated(t *testing.T) {
	t.Parallel()

	wideUDP := sizedPipe(t, ClassUDP, 1252)
	wideTLS := sizedPipe(t, ClassTLS, 1252)

	cases := []struct {
		name     string
		from     Conn
		to       Conn
		session  int
		wantFrom Class
	}{
		{
			name:     "fresh document, first attach to its first carrier",
			from:     nil,
			to:       wideUDP,
			session:  session.MessageFloor(),
			wantFrom: ClassUnknown,
		},
		{
			name:     "already-migrated document, moved off a real carrier",
			from:     wideUDP,
			to:       wideTLS,
			session:  1252,
			wantFrom: ClassUDP,
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			m, err := Migrate(nil, c.from, c.to, c.session)
			if err != nil {
				t.Fatalf("migration failed: %v", err)
			}
			if m.From != c.wantFrom {
				t.Fatalf("from = %s, want %s (the two paths must report their own origin)",
					m.From, c.wantFrom)
			}
			if m.To != c.to.Class() {
				t.Fatalf("to = %s, want %s", m.To, c.to.Class())
			}
			if m.Narrows {
				t.Fatalf("%s: a wide-enough destination narrowed: %+v", c.name, m)
			}
			if m.SizeApplied || m.Remedy != RemedyNone {
				t.Fatalf("%s: the size layer did unnecessary work: %+v", c.name, m)
			}
			if c.from != nil && m.SessionSize != c.session {
				t.Fatalf("%s: session size reported %d, want %d", c.name, m.SessionSize, c.session)
			}
		})
	}
}
