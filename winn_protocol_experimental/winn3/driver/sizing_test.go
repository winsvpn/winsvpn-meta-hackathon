package driver

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// TestFloorIsTheNarrowestNotTheDialledCarrier is the 84-byte trap, stated as an
// exact number so the test cannot pass vacuously.
//
// A session sized to the UDP/IPv4 carrier it dialled emits up to 1252 bytes. The
// floor across the classes it may escalate to is 1168. The difference is 84
// bytes on every full-size packet after the first migration: the tunnel reports
// up, small packets keep working, and large transfers stall.
func TestFloorIsTheNarrowestNotTheDialledCarrier(t *testing.T) {
	const path = carrier.DefaultPathMTU

	dialled := carrier.MaxMessageSizeFor(carrier.ClassUDP, carrier.FamilyIPv4, path)
	sz, err := NewSizing(path, carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS)
	if err != nil {
		t.Fatal(err)
	}

	// The two absolute numbers moved with the fleet default on 2026-08-10
	// (1280 -> 1450); the GAP did not, and the gap is what this test is about.
	// It is the difference between the widest class the plan may reach
	// (TLS/IPv6, 112 bytes) and the one actually dialled (UDP/IPv4, 28), so it
	// is 84 at every path MTU and would only change if an overhead did.
	if dialled != 1422 {
		t.Fatalf("a dialled UDP/IPv4 carrier at a %d-byte path carries %d, want 1422", path, dialled)
	}
	if sz.MessageSize != 1338 {
		t.Fatalf("the plan floor is %d, want 1338", sz.MessageSize)
	}
	if gap := dialled - sz.MessageSize; gap != 84 {
		t.Fatalf("the gap between the dialled carrier and the plan floor is %d bytes, want 84", gap)
	}
	if want := session.InnerMTU(sz.MessageSize); sz.InnerMTU != want {
		t.Fatalf("inner MTU is %d, want %d", sz.InnerMTU, want)
	}
	if want := tun.InnerMTU(sz.MessageSize); sz.InnerMTU != want {
		t.Fatalf("inner MTU is %d, but the tun layer derives %d from the same size", sz.InnerMTU, want)
	}
}

// TestSizingRefusesAnUnplannedPlan holds the two refusals that make the floor
// mean something. An empty plan and an unknown class both make carrier.Floor
// charge the worst case, which is SAFE but silent, and a host that forgot to
// name its plan has a bug that a silently conservative number hides until the
// first migration.
func TestSizingRefusesAnUnplannedPlan(t *testing.T) {
	for _, tc := range []struct {
		name    string
		classes []carrier.Class
	}{
		{"empty", nil},
		{"unknown", []carrier.Class{carrier.ClassUDP, carrier.ClassUnknown}},
		{"duplicate", []carrier.Class{carrier.ClassUDP, carrier.ClassUDP}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewSizing(carrier.DefaultPathMTU, tc.classes...); !errors.Is(err, ErrConfig) {
				t.Fatalf("NewSizing accepted a %s plan (err %v)", tc.name, err)
			}
		})
	}
	if _, err := NewSizing(700, carrier.ClassTLS); !errors.Is(err, ErrConfig) {
		t.Fatalf("NewSizing accepted a path MTU that cannot carry the IPv4 floor (err %v)", err)
	}
}

// TestSizingWidensWithTheRealPath checks that the floor is not a constant. A
// real path is usually 1500 and leaving 220 bytes per packet on the floor is a
// real cost on a metered mobile connection.
func TestSizingWidensWithTheRealPath(t *testing.T) {
	// 1421 rather than 1280: since 2026-08-10 the band below it is the dead
	// zone and NewSizing refuses it outright, so the narrowest path this plan
	// can be BUILT at is the boundary itself. See TestSizingRefusesTheDeadZone.
	narrow, err := NewSizing(1421, planClasses()...)
	if err != nil {
		t.Fatal(err)
	}
	wide, err := NewSizing(1500, planClasses()...)
	if err != nil {
		t.Fatal(err)
	}
	if wide.MessageSize <= narrow.MessageSize {
		t.Fatalf("a 1500-byte path yields %d, no better than a %d-byte path's %d",
			wide.MessageSize, narrow.PathMTU, narrow.MessageSize)
	}
	// The refusal boundary and the InnerIPv6 predicate must be the SAME edge.
	// If they ever drift apart, one of them is wrong and the dead zone either
	// reopens or grows a band of falsely-refused working configurations.
	if !narrow.InnerIPv6 {
		t.Fatalf("the narrowest path NewSizing will build (%d) does not carry inner IPv6; "+
			"the refusal boundary and the InnerIPv6 predicate have drifted apart",
			narrow.PathMTU)
	}
	if narrow.InnerMTU != tun.IPv6MinLinkMTU {
		t.Fatalf("the inner MTU at the refusal boundary is %d, want exactly %d — the "+
			"boundary is defined as the path where the inner link reaches RFC 8200's floor",
			narrow.InnerMTU, tun.IPv6MinLinkMTU)
	}
	if narrow.MinPathMTUForInnerIPv6 != narrow.PathMTU {
		t.Fatalf("the plan reports %d as the path it needs for inner IPv6, but it was built "+
			"at %d", narrow.MinPathMTUForInnerIPv6, narrow.PathMTU)
	}
}

// TestSizingRefusesTheDeadZone is the refusal added on 2026-08-10 alongside the
// fleet default raise.
//
// 1280..1420 is a 141-value band where a session RESOLVES, BOOTSTRAPS AND
// CARRIES and can never promote, because the inner interface MTU it implies is
// below the floor RFC 8200 requires of a link carrying IPv6 and ipv6_add_dev()
// returns -EINVAL. Raising the default merely AVOIDS the band; this makes it
// unreachable.
//
// The band is PLAN-AWARE, and the udp-only rows are why that matters: a
// udp-only plan crosses at 1357, so a flat 1421 would refuse configurations
// that work. A refusal firing on a working configuration is a worse outage than
// the defect it closes.
func TestSizingRefusesTheDeadZone(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mtu     int
		classes []carrier.Class
		refused bool
	}{
		{"the shipping plan, low edge", 1280, planClasses(), true},
		{"the shipping plan, high edge", 1420, planClasses(), true},
		{"the shipping plan, boundary", 1421, planClasses(), false},
		{"the shipping plan, fleet default", carrier.DefaultPathMTU, planClasses(), false},
		{"the shipping plan, measured path", 1500, planClasses(), false},

		// A narrower plan carries inner IPv6 sooner, so its dead zone ends
		// sooner. These four rows are the over-fire control for the refusal.
		{"udp only, low edge", 1280, []carrier.Class{carrier.ClassUDP}, true},
		{"udp only, below its own boundary", 1356, []carrier.Class{carrier.ClassUDP}, true},
		{"udp only, at its own boundary", 1357, []carrier.Class{carrier.ClassUDP}, false},
		{"udp only, inside the WIDE plan's dead zone", 1400, []carrier.Class{carrier.ClassUDP}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sz, err := NewSizing(tc.mtu, tc.classes...)
			switch {
			case tc.refused && err == nil:
				t.Fatalf("NewSizing(%d, %v) was accepted; it yields an inner MTU of %d, "+
					"below %d, so the session could never promote",
					tc.mtu, tc.classes, sz.InnerMTU, tun.IPv6MinLinkMTU)
			case !tc.refused && err != nil:
				t.Fatalf("NewSizing(%d, %v) was refused: %v", tc.mtu, tc.classes, err)
			case tc.refused:
				if !errors.Is(err, ErrPathMTUDeadZone) {
					t.Fatalf("the refusal is %v, want ErrPathMTUDeadZone", err)
				}
				// Wrapped in ErrConfig too, so every caller that already
				// handles a bad configuration keeps handling this one.
				if !errors.Is(err, ErrConfig) {
					t.Fatalf("the refusal is %v, want it to wrap ErrConfig as well", err)
				}
				// Loud: an operator must get the number to change, not just a
				// complaint about the one they used.
				if !strings.Contains(err.Error(), strconv.Itoa(tc.mtu)) {
					t.Errorf("the refusal does not name the configured %d: %v", tc.mtu, err)
				}
			case !tc.refused:
				if !sz.InnerIPv6 {
					t.Fatalf("NewSizing(%d, %v) was accepted but reports no inner IPv6; "+
						"the refusal and the predicate disagree", tc.mtu, tc.classes)
				}
			}
		})
	}
}

// TestLoopRefusesASizeItDidNotPin is the structural half. A caller that could
// set the session's message size could put the 84 bytes back, so the field must
// be refused rather than trusted.
func TestLoopRefusesASizeItDidNotPin(t *testing.T) {
	kr := newKeyring(t)
	sz := planSizing(t)
	pipe, _, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}

	base := func() Config {
		return Config{
			Session: session.Config{
				Core:          coreConfigFor(kr),
				Static:        kr.cliStatic,
				GatewayStatic: kr.gwPublic,
			},
			Sizing:  sz,
			Carrier: pipe,
		}
	}

	// The dialled carrier's own ceiling, which is the mistake this refuses.
	cfg := base()
	cfg.Session.MaxMessageSize = carrier.MaxMessageSizeFor(
		carrier.ClassUDP, carrier.FamilyIPv4, carrier.DefaultPathMTU)
	if _, err := NewClient(cfg); !errors.Is(err, ErrSizeNotPinned) {
		t.Fatalf("the loop accepted a caller-supplied message size (err %v)", err)
	}

	// Even the correct number is refused, because a caller that may pass the
	// right one may pass the wrong one, and the check would then be a comment.
	cfg = base()
	cfg.Session.MaxMessageSize = sz.MessageSize
	if _, err := NewClient(cfg); !errors.Is(err, ErrSizeNotPinned) {
		t.Fatalf("the loop accepted a caller-supplied message size that happened to be right (err %v)", err)
	}

	// The tun's floor is the same number and is refused the same way.
	dev := newDevice(sz.InnerMTU)
	cfg = base()
	cfg.Tun = &tun.Config{
		Assign:                  tun.Assignment{V4: clientAddr(), RouterV4: gatewayAddr()},
		Device:                  dev,
		Clock:                   SessionClock{Clock: SystemClock{}},
		CarrierFloorMessageSize: 1252,
	}
	if _, err := NewClient(cfg); !errors.Is(err, ErrSizeNotPinned) {
		t.Fatalf("the loop accepted a caller-supplied tun carrier floor (err %v)", err)
	}

	// And a host may not supply its own sink either: the sink is how a packet
	// reaches the session, and a second one is a second way in.
	cfg = base()
	cfg.Tun = &tun.Config{
		Assign: tun.Assignment{V4: clientAddr(), RouterV4: gatewayAddr()},
		Device: dev,
		Clock:  SessionClock{Clock: SystemClock{}},
		Sink:   frameSink{},
	}
	if _, err := NewClient(cfg); !errors.Is(err, ErrConfig) {
		t.Fatalf("the loop accepted a caller-supplied frame sink (err %v)", err)
	}
}

// TestLoopRefusesACarrierOutsideThePlan is the other half of the same property,
// and it is the one that closes the trap at RUN time rather than at build time.
//
// A floor is a promise about the classes it was computed over and about no
// others. Escalating onto a class the plan never named is exactly how a session
// ends up wider than the carrier underneath it.
func TestLoopRefusesACarrierOutsideThePlan(t *testing.T) {
	kr := newKeyring(t)
	sz, err := NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP, carrier.ClassTCP)
	if err != nil {
		t.Fatal(err)
	}
	udp, _, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	tls, _, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassTLS})
	if err != nil {
		t.Fatal(err)
	}

	// Dialling outside the plan is refused at construction.
	cfg := Config{
		Session: session.Config{
			Core: coreConfigFor(kr), Static: kr.cliStatic, GatewayStatic: kr.gwPublic,
		},
		Sizing: sz, Carrier: tls,
	}
	if _, err := NewClient(cfg); !errors.Is(err, ErrConfig) {
		t.Fatalf("the loop dialled a carrier class the plan does not name (err %v)", err)
	}

	// Migrating outside the plan is refused at run time.
	cfg.Carrier = udp
	l, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Migrate(tls); !errors.Is(err, ErrConfig) {
		t.Fatalf("the loop migrated onto a class the plan does not name (err %v)", err)
	}
	if got := l.Carrier(); got != carrier.Conn(udp) {
		t.Fatal("a refused migration changed the carrier anyway")
	}
}

// TestLoopRefusesACarrierNarrowerThanTheFloor catches the configuration where
// the plan is right and the carrier was built with the wrong ceiling.
func TestLoopRefusesACarrierNarrowerThanTheFloor(t *testing.T) {
	kr := newKeyring(t)
	sz := planSizing(t)
	narrow, err := carrier.NewPipe(carrier.PipeConfig{
		Class: carrier.ClassUDP, MaxMessageSize: sz.MessageSize - 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Session: session.Config{
			Core: coreConfigFor(kr), Static: kr.cliStatic, GatewayStatic: kr.gwPublic,
		},
		Sizing: sz, Carrier: narrow,
	}
	if _, err := NewClient(cfg); !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("the loop accepted a carrier narrower than the plan floor (err %v)", err)
	}
}

// TestMigrationAtThePinnedFloorNeverNarrows walks every ordered pair of classes
// in the plan and requires that no move needs the session to be told anything.
//
// This is why session.Driver.SetMaxMessageSize — which does not exist yet — is
// not on the critical path for a working tunnel: pin the floor over the whole
// plan and every migration the plan allows is a no-op for sizing.
func TestMigrationAtThePinnedFloorNeverNarrows(t *testing.T) {
	sz := planSizing(t)
	for _, from := range sz.Classes {
		for _, to := range sz.Classes {
			a, err := carrier.NewPipe(carrier.PipeConfig{Class: from, PathMTU: sz.PathMTU})
			if err != nil {
				t.Fatal(err)
			}
			b, err := carrier.NewPipe(carrier.PipeConfig{Class: to, PathMTU: sz.PathMTU})
			if err != nil {
				t.Fatal(err)
			}
			m, err := carrier.Migrate(nil, a, b, sz.MessageSize)
			if err != nil {
				t.Fatalf("%s -> %s at the pinned floor: %v", from, to, err)
			}
			if m.Narrows {
				t.Fatalf("%s -> %s narrows at the pinned floor: session %d, carrier %d",
					from, to, m.SessionSize, m.CarrierSize)
			}
		}
	}
}

// TestConstructionRefusalsAreDiagnostic covers the configurations that would
// otherwise fail at run time as silence. A tunnel that starts and then drops
// everything is much harder to diagnose from Yangon than a start that says why.
func TestConstructionRefusalsAreDiagnostic(t *testing.T) {
	kr := newKeyring(t)
	sz := planSizing(t)
	pipe, _, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewSizing(0, carrier.ClassUDP); !errors.Is(err, ErrConfig) {
		t.Fatalf("NewSizing accepted a zero path MTU (err %v)", err)
	}

	// No sizing at all: the loop must not fall back to a default, because the
	// only default available is the one that is right for a single carrier
	// family.
	if _, err := NewClient(Config{Carrier: pipe}); !errors.Is(err, ErrConfig) {
		t.Fatalf("the loop accepted a configuration with no sizing (err %v)", err)
	}
	if _, err := NewClient(Config{Sizing: sz}); !errors.Is(err, ErrConfig) {
		t.Fatalf("the loop accepted a configuration with no carrier (err %v)", err)
	}

	// The session layer's own refusals reach the caller unchanged rather than
	// being re-worded here.
	if _, err := NewClient(Config{
		Sizing: sz, Carrier: pipe,
		Session: session.Config{Core: coreConfigFor(kr), GatewayStatic: kr.gwPublic},
	}); err == nil {
		t.Fatal("the loop built a client with no static key")
	}

	// And the tun layer's: an assignment the packet validator would reject is a
	// tunnel that drops all of its own traffic.
	dev := newDevice(sz.InnerMTU)
	_, err = NewClient(Config{
		Sizing: sz, Carrier: pipe,
		Session: session.Config{
			Core: coreConfigFor(kr), Static: kr.cliStatic, GatewayStatic: kr.gwPublic,
		},
		Tun: &tun.Config{
			Assign: tun.Assignment{V4: v4a(127, 0, 0, 1)},
			Device: dev,
			Clock:  SessionClock{Clock: SystemClock{}},
		},
	})
	if !errors.Is(err, tun.ErrConfig) {
		t.Fatalf("the loop built a tunnel on a loopback inner address (err %v)", err)
	}
}

// TestANarrowingMigrationTellsTheSessionRatherThanBlackHoling is the black-hole
// answer, reached through the loop.
//
// It USED to be a refusal, and the refusal was the right answer only while
// *session.Driver could not be told: completing would have been unactionable,
// because nothing downstream would ever have reported the black hole — the
// tunnel reads "up", small packets work, and large transfers stall.
//
// session.Driver now implements carrier.MessageSizeSink, so the third rung of
// carrier/migrate.go's ladder is reachable: the session is told the destination
// carrier's ceiling and the migration completes SAFELY. The properties that
// matter are that the size was actually applied, that the report says so, and
// that the session's own ceiling moved — which is observed the way this file
// observes it everywhere else, through Enqueue's boundary rather than through an
// accessor that does not exist.
func TestANarrowingMigrationTellsTheSessionRatherThanBlackHoling(t *testing.T) {
	kr := newKeyring(t)
	sz := planSizing(t)
	wide, _, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	// Inside the plan by class, but built with a ceiling below the floor: the
	// path MTU was measured after the fact and came back smaller.
	narrow, err := carrier.NewPipe(carrier.PipeConfig{
		Class: carrier.ClassTLS, MaxMessageSize: sz.MessageSize - 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewClient(Config{
		Sizing: sz, Carrier: wide,
		Session: session.Config{
			Core: coreConfigFor(kr), Static: kr.cliStatic, GatewayStatic: kr.gwPublic,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Nothing is enqueued first, deliberately: a queued full-size packet is the
	// case the OTHER test covers, and it is a refusal rather than this one.
	m, err := l.Migrate(narrow)
	if err != nil {
		t.Fatalf("a narrowing migration onto a carrier the plan names returned %v, "+
			"want a completed migration with the size applied", err)
	}
	if !m.Narrows {
		t.Fatal("the migration report does not say it narrows")
	}
	if !m.SizeApplied {
		t.Fatal("the migration completed without telling the session the new ceiling")
	}
	if m.Remedy != carrier.RemedyNone {
		t.Fatalf("the remedy is %s, want none: the session was told", m.Remedy)
	}
	if m.CarrierSize != sz.MessageSize-1 {
		t.Fatalf("the report says the destination carries %d, want %d", m.CarrierSize, sz.MessageSize-1)
	}
	if got := l.Carrier(); got != carrier.Conn(narrow) {
		t.Fatal("a completed migration did not swap the carrier")
	}
	if got := l.Stats().Migrations; got != 1 {
		t.Fatalf("a completed migration was counted %d times, want 1", got)
	}
	// And the session's ceiling really moved: a packet that fitted the plan
	// floor's inner MTU no longer fits, and one sized for the destination does.
	// Enqueue's boundary is the only externally observable evidence there is —
	// session.Driver exposes no accessor for MaxMessageSize, by design.
	if err := l.Session().Enqueue(make([]byte, session.InnerMTU(sz.MessageSize))); err == nil {
		t.Fatal("the session still accepts a packet sized for the OLD ceiling, " +
			"so the migration black holed it after all")
	}
	if err := l.Session().Enqueue(make([]byte, session.InnerMTU(sz.MessageSize-1))); err != nil {
		t.Fatalf("the session refuses a packet sized for the NEW ceiling: %v", err)
	}
}

// TestANarrowingMigrationIsStillRefusedWhenTheSessionCannotTakeIt is the other
// half, and it is the one that keeps the refusal alive.
//
// A session that has already queued an inner packet too large for the
// destination cannot be narrowed: that packet has nowhere to go, and dropping it
// silently is the black hole one layer in. SetMaxMessageSize refuses, Migrate
// converts the refusal into RemedyRehandshake, and the carrier is NOT swapped —
// so a caller that ignores the error is not left on a carrier its session
// overflows.
func TestANarrowingMigrationIsStillRefusedWhenTheSessionCannotTakeIt(t *testing.T) {
	kr := newKeyring(t)
	sz := planSizing(t)
	wide, _, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	narrow, err := carrier.NewPipe(carrier.PipeConfig{
		Class: carrier.ClassTLS, MaxMessageSize: session.MessageFloor() + 16,
	})
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewClient(Config{
		Sizing: sz, Carrier: wide,
		Session: session.Config{
			Core: coreConfigFor(kr), Static: kr.cliStatic, GatewayStatic: kr.gwPublic,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// A full-size inner packet is queued and cannot be re-sized.
	if err := l.Session().Enqueue(make([]byte, session.InnerMTU(sz.MessageSize))); err != nil {
		t.Fatalf("enqueue at the plan floor: %v", err)
	}

	m, err := l.Migrate(narrow)
	if !errors.Is(err, carrier.ErrMigrationWouldBlackHole) {
		t.Fatalf("a migration the session could not accept returned %v, want the black-hole refusal", err)
	}
	if m.Remedy != carrier.RemedyRehandshake {
		t.Fatalf("the remedy is %s, want rehandshake", m.Remedy)
	}
	if m.SizeApplied {
		t.Fatal("the report claims the size was applied and the session refused it")
	}
	if got := l.Carrier(); got != carrier.Conn(wide) {
		t.Fatal("a refused migration swapped the carrier anyway")
	}
	if got := l.Stats().Migrations; got != 0 {
		t.Fatalf("a refused migration was counted: %d", got)
	}
}

// TestTheSessionIsBuiltAtExactlyThePlanFloor observes the ceiling the session
// ACTUALLY has, rather than the one the loop meant to give it.
//
// Nothing else can. session.Driver exposes no accessor for MaxMessageSize, so a
// loop that pinned the wrong number would look correct everywhere except on the
// wire — and the symptom, once padding pushed a message past a narrower
// carrier's ceiling after a migration, would be "large downloads stall",
// reported from a country where nobody can attach a debugger.
//
// Enqueue's own boundary is the instrument: it refuses an inner packet larger
// than InnerMTU(MaxMessageSize), so one accepted packet at exactly the plan
// floor's inner MTU and one refused packet at one byte more pin the ceiling
// exactly, from outside the package.
func TestTheSessionIsBuiltAtExactlyThePlanFloor(t *testing.T) {
	kr := newKeyring(t)
	sz := planSizing(t)
	pipe, _, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	// The dialled carrier is deliberately WIDER than the plan floor, which is the
	// ordinary case and the one that hides the mistake.
	if pipe.MaxMessageSize() <= sz.MessageSize {
		t.Fatalf("the fixture's carrier carries %d, not more than the %d-byte floor; "+
			"this test cannot distinguish the two", pipe.MaxMessageSize(), sz.MessageSize)
	}

	l, err := NewClient(Config{
		Sizing: sz, Carrier: pipe,
		Session: session.Config{
			Core: coreConfigFor(kr), Static: kr.cliStatic, GatewayStatic: kr.gwPublic,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := l.Session().Enqueue(make([]byte, sz.InnerMTU)); err != nil {
		t.Fatalf("the session refused a packet at the plan floor's inner MTU (%d): %v",
			sz.InnerMTU, err)
	}
	err = l.Session().Enqueue(make([]byte, sz.InnerMTU+1))
	if err == nil {
		t.Fatalf("the session accepted a %d-byte inner packet; its ceiling is above the "+
			"%d-byte plan floor, so a migration to the narrowest class in the plan will "+
			"black hole full-size flows", sz.InnerMTU+1, sz.MessageSize)
	}
	if !errors.Is(err, session.ErrInnerTooLarge) {
		t.Fatalf("the session refused an oversize packet with %v, want ErrInnerTooLarge", err)
	}
}
