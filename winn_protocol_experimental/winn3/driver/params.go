package driver

import (
	"errors"
	"fmt"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// Errors. Every one is local: nothing in this package is ever turned into an
// observable response to a peer, for the same reason none of the three packages
// below it does.
var (
	// ErrConfig is an invalid loop configuration.
	ErrConfig = errors.New("winn3/driver: invalid configuration")

	// ErrSizeNotPinned is returned when a caller sets session.Config's
	// MaxMessageSize itself. The loop pins it to the plan floor and a caller who
	// could override that could reintroduce the 84-byte black hole the floor
	// exists to close.
	ErrSizeNotPinned = errors.New(
		"winn3/driver: the loop pins the message size; leave Session.MaxMessageSize zero")

	// ErrSizeMismatch is returned when a supplied tun or carrier was not built
	// at the plan floor.
	ErrSizeMismatch = errors.New("winn3/driver: component was not sized to the plan floor")

	// ErrClosed is reserved. Close always returns nil (it is a request, not a
	// wait, and it is idempotent). After Close, SendInner returns
	// tun.ErrNotCarrying because the session is no longer Established, and Run
	// returns once the CLOSE has been handed to the carrier. Nothing in this
	// package currently returns ErrClosed; do not errors.Is(err, ErrClosed)
	// expecting Close or Run to produce it.
	ErrClosed = errors.New("winn3/driver: loop is closed")

	// ErrSessionFailed is returned by Run when the session terminated in a
	// failed state; the wrapped cause is the session's own.
	ErrSessionFailed = errors.New("winn3/driver: session failed")

	// ErrPathMTUDeadZone is a path MTU that would build a session which
	// resolves, bootstraps, carries — and can never promote.
	//
	// It is returned WRAPPED IN ErrConfig, so every caller that already handles
	// a bad configuration keeps handling this one; the separate sentinel is for
	// a caller that wants to say something specific to an operator, because the
	// remedy is specific and is not "check your config".
	ErrPathMTUDeadZone = errors.New("winn3/driver: path MTU is inside the inner-IPv6 dead zone")
)

func errWrap(base error, format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{base}, args...)...)
}

// Clock is the loop's time source AND its wait primitive.
//
// It is deliberately WIDER than session.Clock and tun.Clock, which are Now()
// only. Those two are narrow because a timer inside them would put the timing
// policy in two layers at once, and the measured failure this protocol replaces
// — a 25.000-second zero-jitter keepalive — was exactly a timer in the wrong
// layer. This package is the layer that owns the wait, so this is the right
// layer for the only timer in v3.
//
// A session.Clock is not automatically a driver.Clock. That is intentional: a
// host that supplies one must think about the second method rather than have it
// appear by accident.
type Clock interface {
	// Now reports the current time. It must agree with the session's clock.
	Now() time.Time

	// NewTimer returns a timer that fires once after d. The caller always calls
	// Stop, exactly once, whether or not the timer fired.
	NewTimer(d time.Duration) Timer
}

// Timer is one pending wake-up.
type Timer interface {
	C() <-chan time.Time
	Stop()
}

// SystemClock is the production Clock.
type SystemClock struct{}

// Now reads the wall clock.
func (SystemClock) Now() time.Time { return time.Now() }

// NewTimer returns a real timer.
func (SystemClock) NewTimer(d time.Duration) Timer { return &systemTimer{t: time.NewTimer(d)} }

type systemTimer struct{ t *time.Timer }

func (s *systemTimer) C() <-chan time.Time { return s.t.C }
func (s *systemTimer) Stop()               { s.t.Stop() }

// SessionClock adapts a driver.Clock to the Now()-only interface the session
// and tun layers take, so that one host configures one clock rather than three.
type SessionClock struct{ Clock Clock }

// Now implements session.Clock and tun.Clock.
func (s SessionClock) Now() time.Time { return s.Clock.Now() }

// --- sizing ------------------------------------------------------------------

// Sizing is the one place in a v3 host where the message size is decided.
//
// The number that matters is MessageSize, and the whole of its content is that
// it is computed over every class the session may escalate TO rather than the
// class it dialled. The carrier lane measured the gap: Floor(1280, UDP, TCP,
// TLS) is 1168 against 1252 for a dialled UDP/IPv4 carrier — 84 bytes that
// black hole every full-size flow on the first migration while the tunnel still
// reports up, small packets keep working, and the report comes from a country
// where nobody can attach a debugger.
type Sizing struct {
	// PathMTU is the planning path MTU the floor was computed at.
	PathMTU int

	// Classes is the migration plan, in the order a host intends to try it.
	Classes []carrier.Class

	// MessageSize is carrier.Floor(PathMTU, Classes...). The session is built
	// with it and no migration inside the plan can narrow below it.
	MessageSize int

	// InnerMTU is the tun device MTU MessageSize implies.
	InnerMTU int

	// InnerIPv6 reports whether the tunnel can carry inner IPv6 at this floor.
	// False is common and is not a defect: at a 1280-byte outer path inner IPv6
	// is impossible for any tunnel.
	InnerIPv6 bool

	// MinPathMTUForInnerIPv6 is the outer path MTU the plan needs before
	// inner IPv6 is possible: the maximum of each class's requirement, which
	// is the class with the most overhead (TLS in a full plan, 1421). A
	// udp-only plan is lower (1357). carrier.PlanFloor's "narrowest class"
	// comment means this same number — the class that leaves the least
	// inner MTU — not UDP.
	MinPathMTUForInnerIPv6 int
}

// NewSizing computes the plan floor.
//
// It refuses an empty plan and refuses carrier.ClassUnknown rather than
// charging them the conservative overhead silently. carrier.Floor is safe with
// neither — it charges the worst case — but a host that forgot to name its plan
// has a bug that a silently conservative number would hide until the first
// migration.
func NewSizing(pathMTU int, classes ...carrier.Class) (Sizing, error) {
	if len(classes) == 0 {
		return Sizing{}, errWrap(ErrConfig,
			"a migration plan must name the carrier classes the session may escalate to")
	}
	seen := make(map[carrier.Class]bool, len(classes))
	for i, c := range classes {
		if c == carrier.ClassUnknown {
			return Sizing{}, errWrap(ErrConfig, "plan entry %d is an unknown carrier class", i)
		}
		if seen[c] {
			return Sizing{}, errWrap(ErrConfig, "plan names %s twice", c)
		}
		seen[c] = true
	}
	if pathMTU <= 0 {
		return Sizing{}, errWrap(ErrConfig, "path MTU %d must be positive", pathMTU)
	}

	pf := carrier.NewPlanFloor(pathMTU, classes...)
	s := Sizing{
		PathMTU:                pathMTU,
		Classes:                append([]carrier.Class(nil), classes...),
		MessageSize:            pf.MessageSize,
		InnerMTU:               pf.InnerMTU,
		InnerIPv6:              pf.InnerIPv6,
		MinPathMTUForInnerIPv6: pf.MinPathMTUForInnerIPv6,
	}
	if s.InnerMTU < tun.MinInnerMTUv4 {
		return Sizing{}, errWrap(ErrConfig,
			"a path MTU of %d over this plan yields an inner MTU of %d, below the %d-byte IPv4 floor",
			pathMTU, s.InnerMTU, tun.MinInnerMTUv4)
	}
	if pathMTU < s.MinPathMTUForInnerIPv6 {
		return Sizing{}, deadZone(s)
	}
	return s, nil
}

// deadZone refuses the 141-value band where a session works and is still
// useless. ADDED 2026-08-10, with the fleet default raise it is the other half
// of.
//
// ===========================================================================
// WHAT THE BAND IS
// ===========================================================================
//
// Between the low edge — RFC 8200's 1280, below which nothing carries IPv6
// anywhere — and MinPathMTUForInnerIPv6, a session RESOLVES, BOOTSTRAPS AND
// CARRIES, and can never promote. The inner interface MTU the plan floor
// implies falls below 1280, and the kernel will not put IPv6 on a link that
// narrow: ipv6_add_dev() returns -EINVAL. That is the KERNEL's refusal, not one
// platform's, and desktop Linux has it exactly as Android does.
//
// For the shipping plan the band is 1280..1420 and the threshold is 1421 =
// 1280 + 29 bytes of v3 overhead + 112 for TLS over IPv6, the widest class a
// full plan may reach.
//
// ===========================================================================
// WHY IT IS PLAN-AWARE AND NOT THE CONSTANT 1421
// ===========================================================================
//
// 1421 is the threshold for the WIDEST plan. A udp-only plan crosses at 1357,
// and between 1357 and 1420 such a plan carries inner IPv6 perfectly well. A
// flat 1421 would refuse those configurations, and a refusal that fires on a
// working configuration is a worse outage than the defect it closes — the same
// rule that kept the mismatch refusal narrow. Sizing.MinPathMTUForInnerIPv6 is
// the maximum of each class's requirement (the most-overhead class the plan
// may migrate TO), so this band is exactly the dead zone and never a byte wider.
//
// ===========================================================================
// WHY REFUSE RATHER THAN CLAMP
// ===========================================================================
//
// Clamping — "take the minimum" — is what this replaces. Silently moving a
// session to the smaller of two numbers converts a loud refusal into a quiet
// downgrade INTO this band, which is the defect wearing the fix's clothes. The
// operator gets a number to change instead.
func deadZone(s Sizing) error {
	return fmt.Errorf("%w: %w: a path MTU of %d over the plan %v yields an inner MTU of %d, "+
		"below the %d-byte floor RFC 8200 requires of any link carrying IPv6. The session "+
		"would resolve, bootstrap and CARRY, and could never promote: the kernel refuses the "+
		"interface outright (ipv6_add_dev() returns -EINVAL), on desktop Linux exactly as on "+
		"Android. This plan needs %d. Either raise the path MTU to at least that — the fleet "+
		"default is %d — or narrow the plan, which lowers the bar because the threshold is set "+
		"by the widest class the session may migrate to",
		ErrConfig, ErrPathMTUDeadZone, s.PathMTU, s.Classes, s.InnerMTU,
		tun.IPv6MinLinkMTU, s.MinPathMTUForInnerIPv6, carrier.DefaultPathMTU)
}

// Allows reports whether the plan permits migrating to class.
func (s Sizing) Allows(class carrier.Class) bool {
	for _, c := range s.Classes {
		if c == class {
			return true
		}
	}
	return false
}

// TunConfig fills in the two sizing fields of a tun.Config, so that a host
// cannot size the tun device to the carrier it dialled.
//
// It sets CarrierFloorMessageSize only. Everything else in a tun.Config —
// the assignment, the device, the clock — is the host's, and this package has
// no business inventing any of it.
func (s Sizing) TunConfig(cfg tun.Config) tun.Config {
	cfg.CarrierFloorMessageSize = s.MessageSize
	return cfg
}

// --- state mapping -----------------------------------------------------------

// tunStateFor maps a session state onto the one bit the tun layer needs.
//
// It is §5.1 of WINN3_TUN_LAYER_20260808.md in code. The mapping is
// many-to-one on the closed side on purpose: the tun layer needs one bit — carry
// or do not — and every extra distinction it is allowed to make is a chance to
// make the wrong one.
//
// Written as a whitelist of exactly one carrying case. A blacklist is the shape
// that fails OPEN when somebody adds a session state and forgets a case, and
// TestOnlyEstablishedCarries walks all 256 values of session.State to prove it
// stayed that way.
func tunStateFor(s session.State) tun.State {
	switch s {
	case session.StateEstablished:
		return tun.StateCarrying
	case session.StateInitiating:
		return tun.StateHandshaking
	case session.StateRekeying:
		return tun.StateRekeying
	case session.StateClosing:
		return tun.StateClosed
	default:
		// StateClosed, StateFailed, the zero value and every value that is not a
		// state at all.
		return tun.StateDown
	}
}
