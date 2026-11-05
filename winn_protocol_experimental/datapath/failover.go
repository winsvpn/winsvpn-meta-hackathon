package datapath

// Multi-carrier failover, reachable from a shipping path.
//
// # What was missing, precisely
//
// internal/carrier/manager.go already implements multi-candidate failover:
// ensureActive dials candidates in turn, with backoff and a mobility engine to
// order them, and Manager is itself a net.PacketConn, so a caller that holds
// one has a transport that survives the loss of any single carrier. It was
// constructed in exactly one place — cmd/winn-carrier-client, a lab client —
// and no shipping datapath path reached it.
//
// Meanwhile this package built exactly one carrier and refused every other:
// Open's `config.Carrier != CarrierDirectAWG` guard, and openWithCarrier's
// suppliedSocketCarriers lookup. Both return as soon as the pump starts, so a
// carrier that stopped carrying was a session that sat there.
//
// escalation.go supplied the missing decision — a verdict, and an ordered plan
// naming v3's own carriers — and deliberately stopped short of acting on it.
// This file is the joint: it takes that same validated plan and builds the
// Manager over it, so the plan is not only a recommendation a host may read but
// an order the datapath can follow where it is safe to do so.
//
// # Why this is a separate constructor and not a flag on Open
//
// The opt-in IS the constructor call. Open and OpenWithCarrier are untouched,
// so every existing host keeps its exact behaviour, and a node that has not
// been changed to call OpenConfigWithFailover emits a status document with no
// new key and dials no carrier it did not dial before. That is the same
// default-off posture escalation.go holds, obtained without a mode flag whose
// absence would have to be interpreted.
//
// # The socket rule decides where this may run, and it is not negotiable
//
// carrier.go's rule is that the HOST opens the transport socket and protects it
// (VpnService.protect on Android) before the datapath may touch it. A Manager
// dials its successor itself, whenever the active carrier fails, at a moment no
// host chose. On a platform where the socket must be protected, that is a
// socket the host never protected — and outer traffic on an unprotected socket
// routes back into the tunnel, which is the failure this package exists to
// prevent.
//
// A caller-supplied descriptor cannot rescue it either, and the reason is worth
// stating because it looks like it should. A supplied-socket dialer is
// single-use by design (internal/carrier/supplied_socket.go,
// ErrSuppliedSocketConsumed: it "refuses rather than opening an unprotected
// replacement"). So a Manager built over supplied-socket dialers would get one
// dial per candidate and, after that, an ensureActive loop that can never
// succeed and never stops trying. Refusing the combination outright is better
// than a fallback that works once and then spins.
//
// So this path requires allow_own_socket and no descriptor: the desktop and
// Linux shape, where the outer traffic is excluded by route. That is Linux,
// Windows and macOS — three of five platforms, and per
// WINN3_UDP_BLOCK_SURVIVABILITY_20260808.md §4 exactly the three that need no
// host work at all. Android and iOS keep the verdict-only model escalation.go
// built for them, and ErrFailoverSuppliedSocket says so by name.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/mobility"
)

var (
	// ErrFailoverPlanRequired is returned when no escalation plan is
	// configured. The plan is not an optional ordering hint here: it is the
	// only thing that says which carrier is tried after which, and it carries
	// the refusals that stop the sequence from being decoration —
	// ErrEscalationPlanAllUDP above all, without which a caller could hand this
	// function direct-awg followed by http3-connect-udp and get a failover that
	// the same one-line censor rule kills twice.
	ErrFailoverPlanRequired = errors.New(
		"winn datapath failover requires a carrier_escalation plan: it is the " +
			"order the carriers are tried in, and its validation is what " +
			"refuses a plan with no UDP-surviving successor",
	)

	// ErrFailoverObserveRequired is returned when the escalation mode is not
	// EscalationObserve.
	//
	// This path ACTS on the verdict, so the verdict must be computed — off mode
	// returns the zero policy and AssessEscalation reports nothing at all, so a
	// failover engine in off mode would carry a supervisor that could never
	// conclude anything and would degrade silently to dial-failure-only
	// failover while the caller believed it had more.
	//
	// It is also the diagnosability requirement. Observe mode is what publishes
	// carrier_escalation in Status, and a node that switches carriers on a
	// verdict it does not publish leaves nobody able to say afterwards why it
	// moved. Requiring the two together is what makes the switch reviewable.
	ErrFailoverObserveRequired = errors.New(
		"winn datapath failover requires carrier_escalation mode " +
			string(EscalationObserve) + ": the failover acts on the verdict, " +
			"so the verdict must be computed and published",
	)

	// ErrFailoverSuppliedSocket is returned when a descriptor is supplied.
	// See the socket rule in this file's header.
	ErrFailoverSuppliedSocket = errors.New(
		"winn datapath failover cannot use a caller-supplied descriptor: a " +
			"supplied-socket dialer is single-use, so the successor carrier " +
			"would have to open a socket of its own, which on a platform that " +
			"requires a protected socket routes the outer traffic back into " +
			"the tunnel; use the verdict from AssessEscalation instead and let " +
			"the host reopen",
	)

	// ErrFailoverCandidateMissing is returned when a plan entry has no
	// candidate. A plan whose successor cannot be built is a plan that will
	// discover at the worst moment that it has nowhere to go.
	ErrFailoverCandidateMissing = errors.New(
		"winn datapath failover has no candidate for a carrier the escalation " +
			"plan names",
	)

	// ErrFailoverCandidateUnplanned is returned for a candidate the plan does
	// not name. Silently ignoring it would mean a caller believed a carrier was
	// in the rotation when it was not; silently appending it would mean a
	// carrier entered the rotation without passing the plan's validation.
	ErrFailoverCandidateUnplanned = errors.New(
		"winn datapath failover was given a candidate the escalation plan does " +
			"not name",
	)

	// ErrFailoverCandidateDialer is returned for a candidate with no dialer,
	// or for a direct-awg candidate that was given one. direct-awg is built by
	// this package from the gateway endpoint; every other carrier needs an
	// internal/carrier dialer the caller constructed.
	ErrFailoverCandidateDialer = errors.New(
		"winn datapath failover candidate has the wrong dialer for its carrier",
	)
)

// planPriorityStep is the mobility priority spacing between consecutive
// escalation-plan entries.
//
// mobility.Engine.score adds Path.Priority to a cost in which lower wins, and
// the other terms are RTT in milliseconds (weight 1), loss (weight 400) and
// consecutive failures (weight 2000, the FailurePenalty). Choosing 1000 places
// the plan order exactly where it belongs between those two:
//
//   - A healthy plan head keeps its place. Even a 500 ms round trip scores 500,
//     which still beats the successor's 1000, so the datapath does not wander
//     onto a fallback carrier because the primary got slow. Escalation is for a
//     carrier that has stopped working, not one that is merely worse.
//   - One hard failure demotes past the next entry. A failed dial or a dead
//     socket adds 2000, which is more than the step, so the successor is tried
//     next rather than the failed carrier being retried forever.
//
// Every candidate starts unobserved and unobserved paths all take the same
// FailurePenalty/2, so on the very first connect the ordering is the plan's
// order and nothing else.
const planPriorityStep = 1000.0

// CarrierCandidate is one entry of the escalation plan, made buildable.
type CarrierCandidate struct {
	// Carrier is the carrier name, which must appear in the escalation plan.
	Carrier string

	// Endpoint is what this candidate connects to — a MASQUE URI template or
	// an absolute HTTPS URL for the envelope carriers. It is recorded on the
	// mobility path for diagnostics and is required to be non-empty by
	// mobility.New. For CarrierDirectAWG it is ignored and the configuration's
	// gateway endpoint is used, because that is the only endpoint direct-awg
	// has.
	Endpoint string

	// Dialer builds the carrier. It is required for the envelope carriers and
	// must be nil for CarrierDirectAWG, which this package builds itself.
	//
	// It must NOT already hold a supplied socket. openWithFailover checks, for
	// the same reason openWithCarrier does: a dialer that arrived pre-loaded
	// makes it unprovable which socket the carrier used.
	Dialer carrier.SuppliedSocketDialer
}

// OpenConfigWithFailover creates an engine whose transport is a
// carrier.Manager built over the configuration's escalation plan.
//
// ctx bounds the FIRST connect only. The Manager's own lifetime is tied to the
// engine, not to ctx, and that distinction is load-bearing: a caller that
// passed a dial-scoped context and had it govern the Manager would find the
// whole transport torn down the moment its connect deadline elapsed, some
// seconds after a perfectly good session had been established. Engine.Close
// closes the Manager, which cancels it.
func OpenConfigWithFailover(
	ctx context.Context,
	config Config,
	candidates []CarrierCandidate,
) (*Engine, error) {
	if ctx == nil {
		return nil, errors.New("winn datapath failover dial context is required")
	}
	normalized, err := config.normalize()
	if err != nil {
		return nil, err
	}
	return openWithFailover(ctx, normalized, candidates)
}

// OpenWithFailover is OpenConfigWithFailover for a JSON configuration blob.
func OpenWithFailover(
	ctx context.Context,
	configJSON []byte,
	candidates []CarrierCandidate,
) (*Engine, error) {
	if ctx == nil {
		return nil, errors.New("winn datapath failover dial context is required")
	}
	config, err := ParseConfig(configJSON)
	if err != nil {
		return nil, err
	}
	return openWithFailover(ctx, config, candidates)
}

func openWithFailover(
	ctx context.Context,
	config Config,
	candidates []CarrierCandidate,
) (*Engine, error) {
	// The socket rule, checked before anything is built or dialed.
	if !config.AllowOwnSocket {
		return nil, ErrOwnSocketRefused
	}
	plan := config.Escalation.Plan
	if len(plan) == 0 {
		return nil, ErrFailoverPlanRequired
	}
	if config.Escalation.Mode != EscalationObserve {
		return nil, fmt.Errorf("%w (mode is %q)",
			ErrFailoverObserveRequired, config.Escalation.Mode)
	}
	gateway, err := net.ResolveUDPAddr("udp", config.GatewayEndpoint)
	if err != nil {
		return nil, fmt.Errorf("winn datapath gateway endpoint: %w", err)
	}

	ordered, directDialers, err := planCandidates(plan, candidates, gateway)
	if err != nil {
		return nil, err
	}

	managerConfig := carrier.DefaultManagerConfig()
	// Cover traffic on the failover path is the same DEVICE-LOCAL schedule the
	// single-carrier path uses (see the cover constants in engine.go): the
	// interval distribution lives in this module, not in a served key, so a
	// controller cannot widen it and re-expose the keepalive metronome. The
	// Manager owns the loop here because the Manager, not the engine, knows
	// which carrier is currently active and therefore which one can pad.
	if anyEnvelopeCarrier(ordered) {
		managerConfig.CoverIntervalMin = coverIntervalMin
		managerConfig.CoverIntervalMax = coverIntervalMax
		managerConfig.CoverDatagramSize = coverDatagramSize
	}

	// context.Background rather than ctx: see the doc comment on
	// OpenConfigWithFailover. Engine.Close closes the Manager, which cancels it.
	manager, err := carrier.NewManager(
		context.Background(), failoverSessionID(config), 1, ordered,
		mobility.DefaultConfig(), managerConfig,
	)
	if err != nil {
		return nil, fmt.Errorf("winn datapath failover manager: %w", err)
	}

	engine := newEngine(config, gateway, manager, true)
	// The Manager reports a synthetic peer for every carrier, so the engine's
	// gateway-sender filter cannot run here — exactly as on the single-carrier
	// path. The check is not lost: for an envelope carrier the authenticated
	// Winn envelope is the stronger replacement, and for the direct-awg leg
	// directUDPConn applies the same address filter at the socket, which is
	// where the address is actually known.
	engine.filterGatewaySender = false
	// Wired after newEngine and before any dial, so the direct legs report
	// their drops into the same counter Status already publishes rather than
	// into a second one nobody reads. Nothing dials before Connect below, so
	// there is no window in which a conn could exist without its sink.
	for _, dialer := range directDialers {
		dialer.foreignSink = &engine.counters.foreignSender
	}

	if err := manager.Connect(ctx); err != nil {
		_ = manager.Close()
		return nil, fmt.Errorf(
			"winn datapath failover: no carrier in the plan became ready: %w",
			err,
		)
	}
	go engine.pump()
	engine.supervise(manager)
	return engine, nil
}

// supervise starts the goroutine that turns the escalation verdict into an
// actual carrier switch.
//
// # Why the Manager alone is not enough, which is the whole reason this exists
//
// carrier.Manager fails over on an ERROR: ensureActive moves to the next
// candidate when a dial fails, and ReadFrom/WriteTo invalidate the active
// carrier when the socket returns one. That covers a refused connection, a
// reset, a dead TLS session.
//
// It does not cover the defect that was measured. Scenario B is a censor
// dropping UDP: the socket opens, every write succeeds, and the read simply
// never returns anything. There is no error anywhere for the Manager to see, so
// a Manager built over [direct-awg, http2-stream] would activate direct-awg and
// sit on it forever, exactly as the single-carrier path did. Multi-candidate
// dialing and surviving a censor are different problems, and only the first of
// them was already solved.
//
// escalation.go supplies what is missing — a verdict computed from datagram
// counts and clocks, which is precisely the evidence available when there is no
// error — and deliberately stopped at producing it. This is the other half:
// VerdictBlocked, on a plan with a successor, becomes Manager.Switch.
//
// # Why switching is safe HERE and was not safe there
//
// escalation.go declines to switch because on three of five platforms the
// replacement socket must be opened and protected by the host. That reasoning
// is unchanged and is why openWithFailover refuses anything but the
// allow_own_socket shape. On that shape the datapath already opens its own
// sockets — Open does it today under the same flag — so a switch opens nothing
// the host was not already trusting it to open.
//
// Manager.Switch is make-before-break: it dials the replacement and keeps the
// old carrier active if the probe fails, so a bad successor costs a dial rather
// than the session.
func (engine *Engine) supervise(manager *Manager) {
	engine.superviseWg.Add(1)
	go engine.superviseLoop(manager)
}

// Manager is the multi-carrier transport this package drives. It is an alias so
// the failover surface can be read without following it into internal/carrier,
// and so tests can substitute one.
type Manager = carrier.Manager

func (engine *Engine) superviseLoop(manager *Manager) {
	defer engine.superviseWg.Done()
	ticker := time.NewTicker(escalationReviewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-engine.closed:
			return
		case <-ticker.C:
		}
		assessment, assessed := engine.AssessEscalation()
		if !assessed || assessment.Verdict != VerdictBlocked {
			// Healthy, stalled and pending all leave the carrier alone.
			//
			// Stalled is deliberately NOT acted on, and that is not an
			// oversight. A stalled carrier WAS carrying traffic, so the network
			// that is now quiet may be a handover, a suspend or a radio gap,
			// and the recommended response to a blocked carrier — tear down the
			// transport and build another — is the wrong response to a tunnel
			// that is about to come back. escalation.go keeps the two verdicts
			// distinct for exactly this decision; acting on both would have
			// made the distinction pointless.
			continue
		}
		if assessment.Recommended == "" {
			// The plan has no successor after the carrier in use. Nothing to
			// do, and saying so once per interval in a counter nobody reads is
			// better than switching to something the plan did not name.
			continue
		}
		switchCtx, cancel := context.WithTimeout(
			context.Background(), escalationSwitchTimeout,
		)
		err := manager.Switch(switchCtx, assessment.Recommended)
		cancel()
		if err != nil {
			// Make-before-break: the old carrier is still active. Try again on
			// the next tick rather than tearing down a session for a successor
			// that would not dial.
			continue
		}
		// Only after the Manager has actually activated the successor, so a
		// failed probe never renames the carrier a host is reading about.
		engine.rebindEscalation(assessment.Recommended)
	}
}

const (
	// escalationReviewInterval is how often the verdict is recomputed.
	//
	// It is deliberately much shorter than DefaultBlockAfter (nine seconds):
	// the budget decides WHEN a carrier is blocked, and this only decides how
	// long after that the datapath notices. One second adds at most one second
	// to a nine-second diagnosis, and the evaluation is a few atomic loads and
	// a clock read against a policy that is usually not even active.
	escalationReviewInterval = time.Second

	// escalationSwitchTimeout bounds one make-before-break switch. It matches
	// carrier.DefaultManagerConfig's DialTimeout, because a switch IS a dial
	// and a shorter bound here would cancel dials the Manager considers still
	// in progress.
	escalationSwitchTimeout = 10 * time.Second
)

// planCandidates puts the candidates in the plan's order and refuses every
// mismatch between the two.
//
// The plan and the candidate list must describe the same set exactly. Neither
// direction is tolerated: a plan entry with no candidate is a successor that
// cannot be built, and a candidate the plan does not name is a carrier that
// would enter the rotation without having passed the plan's validation — the
// UDP-survival check included.
func planCandidates(
	plan []string, candidates []CarrierCandidate, gateway *net.UDPAddr,
) ([]carrier.Candidate, []*directUDPDialer, error) {
	byCarrier := make(map[string]CarrierCandidate, len(candidates))
	for _, candidate := range candidates {
		if _, duplicate := byCarrier[candidate.Carrier]; duplicate {
			return nil, nil, fmt.Errorf(
				"winn datapath failover names carrier %q twice",
				candidate.Carrier,
			)
		}
		byCarrier[candidate.Carrier] = candidate
	}
	for _, candidate := range candidates {
		if !containsString(plan, candidate.Carrier) {
			return nil, nil, fmt.Errorf("%w (%q; plan is %v)",
				ErrFailoverCandidateUnplanned, candidate.Carrier, plan)
		}
	}

	ordered := make([]carrier.Candidate, 0, len(plan))
	directDialers := make([]*directUDPDialer, 0, 1)
	for index, name := range plan {
		candidate, present := byCarrier[name]
		if !present {
			return nil, nil, fmt.Errorf("%w (%q)",
				ErrFailoverCandidateMissing, name)
		}
		path := mobility.Path{
			ID:       name,
			Endpoint: candidate.Endpoint,
			Priority: float64(index) * planPriorityStep,
		}
		var dialer carrier.Dialer
		switch name {
		case CarrierDirectAWG:
			if candidate.Dialer != nil {
				return nil, nil, fmt.Errorf(
					"%w: %s is built from the gateway endpoint and must not "+
						"be given a dialer",
					ErrFailoverCandidateDialer, CarrierDirectAWG,
				)
			}
			path.Carrier = mobility.DirectUDP
			path.Endpoint = gateway.String()
			direct := &directUDPDialer{gateway: gateway}
			directDialers = append(directDialers, direct)
			dialer = direct
		case CarrierHTTP3, CarrierHTTP2:
			if candidate.Dialer == nil {
				return nil, nil, fmt.Errorf(
					"%w: %s needs an internal/carrier dialer",
					ErrFailoverCandidateDialer, name,
				)
			}
			if candidate.Dialer.HasSuppliedSocket() {
				return nil, nil, ErrFailoverSuppliedSocket
			}
			if required := suppliedSocketCarriers[name]; //nolint:staticcheck
			candidate.Dialer.SuppliedSocketKind() != required {
				return nil, nil, fmt.Errorf(
					"%w: carrier %q needs a %q socket, the dialer takes %q",
					ErrCarrierDialerMismatch, name, required,
					candidate.Dialer.SuppliedSocketKind(),
				)
			}
			if name == CarrierHTTP3 {
				path.Carrier = mobility.HTTP3
			} else {
				path.Carrier = mobility.HTTP2
			}
			if path.Endpoint == "" {
				return nil, nil, fmt.Errorf(
					"winn datapath failover candidate %q needs an endpoint",
					name,
				)
			}
			dialer = candidate.Dialer
		default:
			// Unreachable: normalizeEscalationPlan already refused every
			// carrier without a dialer in this build. Returning rather than
			// falling through keeps that true if that function changes.
			return nil, nil, fmt.Errorf("%w (%q)",
				ErrEscalationPlanUnusable, name)
		}
		ordered = append(ordered, carrier.Candidate{Path: path, Dialer: dialer})
	}
	return ordered, directDialers, nil
}

func anyEnvelopeCarrier(candidates []carrier.Candidate) bool {
	for _, candidate := range candidates {
		if candidate.Path.Carrier != mobility.DirectUDP {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// failoverSessionID returns a session ID the mobility engine accepts.
//
// Config.SessionID is opaque and up to 128 bytes, whereas mobility requires 32
// lowercase hex characters. Where the configured value happens to satisfy that,
// it is used so the mobility snapshot correlates with the datapath's status;
// otherwise one is generated. Either way the value never reaches the wire — it
// is mobility bookkeeping and Manager.LocalAddr, not a carrier claim, which is
// signed with the dialer's own session ID from the carrier profile.
// sessionIDGenerator is the single seam through which this file obtains a
// session ID, following the same pattern and for the same reason as
// socketOpener in engine.go: the failure path below is unreachable in
// production, and an untested failure path in a security-adjacent module is
// indistinguishable from a wrong one.
var sessionIDGenerator = mobility.NewSessionID

func failoverSessionID(config Config) string {
	if mobility.ValidSessionID(config.SessionID) {
		return config.SessionID
	}
	generated, err := sessionIDGenerator()
	if err != nil {
		// crypto/rand failing is not a condition this package can paper over,
		// but mobility.New will reject the empty string with a clear message
		// and that is a better failure than a fabricated constant that would
		// make two sessions look like one.
		return ""
	}
	return generated
}

// ---------------------------------------------------------------------------
// The direct-awg leg
// ---------------------------------------------------------------------------

// directUDPDialer makes direct-awg a Manager candidate.
//
// It exists so the plan head of the MEASURED scenario can be the carrier that
// was actually measured. WINN3_OVER_THE_STEALTH_LEG_MEASURED_AND_THE_FOUR_
// REFUSALS_20260807.md §3 scenario B is v3 on direct-awg under a drop-UDP rule;
// a failover path that could not start there would only ever be exercised from
// a carrier the defect was not measured on.
//
// It opens its own socket, which is why openWithFailover requires
// allow_own_socket before anything here is constructed.
type directUDPDialer struct {
	gateway *net.UDPAddr

	// foreignSink counts datagrams dropped because they came from somewhere
	// other than the gateway. It is the engine's own foreignSender counter,
	// assigned by openWithFailover after the engine exists and before any dial,
	// so Status keeps reporting one number for that event rather than two.
	foreignSink *atomic.Uint64
}

func (dialer *directUDPDialer) Dial(ctx context.Context) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	network := "udp4"
	if dialer.gateway.IP.To4() == nil {
		network = "udp6"
	}
	conn, err := socketOpener(network, ":0")
	if err != nil {
		return nil, fmt.Errorf("winn datapath open UDP socket: %w", err)
	}
	return &directUDPConn{
		PacketConn:  conn,
		gateway:     dialer.gateway,
		foreignSink: dialer.foreignSink,
	}, nil
}

// SuppliedSocketKind reports what a host would have to hand over if this leg
// were ever driven from a protected descriptor. It is here only so the type
// satisfies the same interface the envelope dialers do; openWithFailover never
// supplies a socket.
func (dialer *directUDPDialer) SuppliedSocketKind() carrier.SocketKind {
	return carrier.SocketKindPacket
}

// HasSuppliedSocket is always false: this dialer opens its own socket, which
// is the only shape openWithFailover permits at all.
func (dialer *directUDPDialer) HasSuppliedSocket() bool { return false }

// directUDPConn adapts a UDP socket to the shape Manager drives.
//
// Two adaptations, and both are load-bearing:
//
//   - Manager calls WriteTo with a NIL address, because an envelope carrier has
//     exactly one destination and does not need one. A plain UDPConn returns an
//     error for a nil address, so this binds the gateway.
//   - The engine's gateway-sender filter is off on the failover path, because
//     the Manager reports a synthetic peer. The filter is not dropped: it is
//     applied HERE, at the one place on this path where the real sender address
//     is known. An off-path sender injecting bytes the host would hand to its
//     AWG engine is exactly what it stops, and the counter it feeds is the same
//     one Status already publishes.
type directUDPConn struct {
	net.PacketConn
	gateway     *net.UDPAddr
	foreignSink *atomic.Uint64
}

func (conn *directUDPConn) WriteTo(packet []byte, _ net.Addr) (int, error) {
	return conn.PacketConn.WriteTo(packet, conn.gateway)
}

func (conn *directUDPConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	for {
		count, sender, err := conn.PacketConn.ReadFrom(buffer)
		if err != nil {
			return count, sender, err
		}
		if !sameUDPEndpoint(sender, conn.gateway) {
			if conn.foreignSink != nil {
				conn.foreignSink.Add(1)
			}
			clear(buffer[:count])
			continue
		}
		return count, conn.gateway, nil
	}
}

// sameUDPEndpoint compares a received sender against the gateway.
//
// net.IP.Equal rather than == so that a v4-mapped v6 address compares equal to
// its v4 form, which is what a dual-stack socket reports and what would
// otherwise make every datagram from a correctly configured gateway look
// foreign.
func sameUDPEndpoint(sender net.Addr, gateway *net.UDPAddr) bool {
	if sender == nil || gateway == nil {
		return false
	}
	address, ok := sender.(*net.UDPAddr)
	if !ok {
		return false
	}
	return address.Port == gateway.Port && address.IP.Equal(gateway.IP)
}
