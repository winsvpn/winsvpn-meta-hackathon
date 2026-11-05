package session

// CT-1 handshake-phase loss recovery (ruling fable_ruling_ct1_handshake_recovery_20261001,
// Amendment 1: design D4, client-driven fresh-generation recovery, and D3).
//
// This file is the fail-first half: the timed-link runner and T2, T3, T7, T8
// and T9. It uses only the release tree's API (the counters D4 adds are read
// by name through reflection), so it can be dropped onto an unmodified copy and
// shown red there. ct1_common_test.go holds the other design-neutral tests and
// also builds on the release tree; ct1_d4_test.go needs the D4 API.

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/dualsign"
)

// --- a timed link over the real driver pair -----------------------------------

var (
	ct1RTTs  = []time.Duration{30 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond, 300 * time.Millisecond, 600 * time.Millisecond}
	ct1Sizes = []int{1360, 1168}
)

// ct1Runs is the seeded run count per cell (the ruling's 40). -short keeps the
// matrix and cuts the repetitions, for the race detector.
func ct1Runs() int {
	if testing.Short() {
		return 8
	}
	return 40
}

// ct1Kind is what a datagram is, read from the sender's observable state
// across the Poll that produced it, never from its index: an index shifts
// whenever the client's pre-session ladder outruns the RTT, and a loss scripted
// by index then hits the wrong datagram.
type ct1Kind int

const (
	ct1Initiation ct1Kind = iota // client: no session yet
	ct1PQEK                      // client: a PQ_EK message of a live generation
	ct1Response                  // gateway: a handshake response
	ct1PQCT                      // gateway: the PQ_CT (its ratchet ran during this Poll)
	ct1Probe                     // gateway: a message carrying a PING the gateway timed itself
	ct1Other                     // everything else: attestation, data, control
)

// ct1Dgram describes one datagram to a loss script. For the gateway, gen is
// the handshake generation (1 for the first response and everything after it,
// 2 after the second response, ...), and pos its place in that generation's
// flight: 0 the response, 1 the PQ_CT, 2 onward the datagrams that followed the
// PQ_CT in the same flight (the Ed25519 frame, then the ML-DSA-65 chunks), -1
// anything else. For the client, pos 0 is an initiation and 1 onward the PQ_EK
// chunks of one flight.
type ct1Dgram struct {
	kind  ct1Kind
	gen   int
	pos   int
	epoch uint32
	msg   []byte
}

type ct1Opts struct {
	rtt  time.Duration
	size int
	dual bool
	seed int
	// prior is the client's Retry.RTTPrior (D5): the cell's RTT in MEASURED
	// mode, zero in FIRST-CONTACT mode (the engine default applies).
	prior time.Duration
	// drop decides, per direction, whether a datagram is lost. nil loses
	// nothing.
	dropCli func(d ct1Dgram) bool
	dropGw  func(d ct1Dgram) bool
	// dup delivers every datagram that is not lost twice; delayGw adds a
	// per-datagram delay to the gateway's datagrams, which reorders them.
	dup     bool
	delayGw func(d ct1Dgram) time.Duration
	// untilTerminal keeps the run going after carrying would have stopped it,
	// until the client is terminal or the horizon passes.
	untilTerminal bool
	horizon       time.Duration
	// minRun keeps a run going after carrying until at least this much time
	// has passed, so a late datagram is still delivered and observed.
	minRun time.Duration
	// gwTimers leaves the gateway's production liveness timers armed (the
	// T10 real-timer variant); tail keeps a terminal run going that much
	// longer so the gateway's later transmissions are observed.
	gwTimers bool
	tail     time.Duration
}

type ct1Send struct {
	at      time.Duration
	idx     int
	dropped bool
	ct1Dgram
	// For gateway sends: the gateway's own counter deltas across the Poll
	// that produced it, and the client's handshake attempts and liveness at
	// that instant (the T10 real-timer variant classifies by these).
	hsDelta, pqDelta, pingDelta uint64
	cliAttempts                 uint64
	cliDone                     bool
	// gwReason is the gateway's local close reason after that Poll.
	gwReason CloseReason
	// deliveredAt is when a gateway send was delivered to the client (the
	// first copy, under dup), or -1 if it never was within the run.
	deliveredAt time.Duration
}

// ct1CliRecv is one datagram delivered to the client: when, whether it opened
// (MessagesReceived moved), the client's NextDeadline right after it, and the
// client's handshake attempts at that instant (its generation).
type ct1CliRecv struct {
	at       time.Duration
	opened   bool
	deadline time.Duration
	attempts uint64
	// held: the datagram went into the client's hold; gwIdx its gwSends index.
	held  bool
	gwIdx int
}

type ct1Recv struct {
	at time.Duration
	// opened: the message authenticated at the gateway, as an initiation it
	// admitted or a transport message under its current keys (its generation
	// sequence moved).
	opened bool
}

// ct1Fire is one fire of the client's retry ladder: when, the attempt index
// its draw was armed with, and whether it superseded a generation.
type ct1Fire struct {
	at         time.Duration
	index      int
	superseded bool
	// drawIndex is the full-jitter window index this fire's draw was taken
	// at (the driver's drawIdx where the tree has one, else the attempt
	// index, which is what an older tree draws at).
	drawIndex int
}

// ct1DriverInt reads an unexported int field of the driver by name, for
// trees that may not have it (ok false then).
func ct1DriverInt(d *Driver, name string) (int, bool) {
	f := reflect.ValueOf(d).Elem().FieldByName(name)
	if !f.IsValid() {
		return 0, false
	}
	return int(f.Int()), true
}

// ct1HoldLen is the length of the client's hold, or 0 on a tree without one.
func ct1HoldLen(d *Driver) int {
	f := reflect.ValueOf(d).Elem().FieldByName("hold")
	if !f.IsValid() {
		return 0
	}
	return f.Len()
}

type ct1Result struct {
	established  time.Duration
	carrying     time.Duration
	failed       error
	closedAt     time.Duration
	firstSendAt  time.Duration
	cliReason    CloseReason
	cliState     State
	needCarrier  bool
	hsAttempts   uint64
	superseded   uint64
	freshAt      []time.Duration // when each fresh initiation after the first left
	sessionAt    time.Duration   // when the client first held a session
	fires        []ct1Fire
	closePhase   int // the client's phase when it began to close: 0 pre-session, 1 PQ, 2 attestation
	maxPhase     int // the furthest phase any generation of the run reached
	dualVerified bool
	cliSends     []ct1Send
	gwSends      []ct1Send
	gwRecvs      []ct1Recv
	cliRecvs     []ct1CliRecv
	gw           *Driver
	cli          *Driver
	size         int
}

type ct1Msg struct {
	at   time.Time
	toGw bool
	msg  []byte
	// gwIdx is the index in gwSends of a gateway-to-client message.
	gwIdx int
}

// ct1StatOr0 reads a Stats counter by name; a counter the tree does not have
// reads as zero, so the runner also runs on the release tree.
func ct1StatOr0(s Stats, name string) uint64 {
	v := reflect.ValueOf(s).FieldByName(name)
	switch {
	case !v.IsValid():
		return 0
	case v.CanInt():
		return uint64(v.Int())
	}
	return v.Uint()
}

// ct1Phase is the client's handshake phase: 0 no session (pre-session), 1 the
// PQ ciphertext outstanding, 2 the attestation outstanding (or done).
func ct1Phase(d *Driver) int {
	switch {
	case d.sess == nil:
		return 0
	case d.pqEph != nil:
		return 1
	}
	return 2
}

// ct1ExpectedReason is the close reason a run that ran out must give: the
// reason of the phase it ran out in (D4 step 4), except that a connect that
// was answered and then ran out with no session (its fresh generation
// unanswered) closes with the furthest phase it reached (Seat C N-1).
func ct1ExpectedReason(r ct1Result) CloseReason {
	if r.closePhase == 0 && r.sessionAt >= 0 {
		return ct1PhaseReason(max(r.maxPhase, 1))
	}
	return ct1PhaseReason(r.closePhase)
}

// ct1PhaseReason is the close reason a connect that ran out in a phase must
// give (D4 step 4).
func ct1PhaseReason(phase int) CloseReason {
	switch phase {
	case 0:
		return CloseProtocolError
	case 1:
		return ClosePQFailed
	}
	return CloseDualAuthFailed
}

// ct1PreSessionFires counts ladder fires before the client first held a
// session: the unchanged pre-session ladder (copies, and a fresh initiation
// when its draws outrun the RTT). Under D4's one ladder they come out of the
// same Retry.Attempts.
func ct1PreSessionFires(r ct1Result) int {
	n := 0
	for _, f := range r.fires {
		if r.sessionAt < 0 || f.at < r.sessionAt {
			n++
		}
	}
	return n
}

// ct1LadderSpent reports a run that could not recover n losses because the
// pre-session ladder had already spent the fires recovery needs: with p
// pre-session fires, a connect has Attempts - 1 - p fires left that can
// supersede (the Attempts-th closes). Such a run must fail closed, in the phase
// it ran out in, by connectBy; ct1FailedClosed checks that.
func ct1LadderSpent(r ct1Result, n int) bool {
	return r.failed != nil && ct1PreSessionFires(r) > Retry{}.orDefault().Attempts-1-n
}

func ct1FailedClosed(t *testing.T, run int, r ct1Result) {
	t.Helper()
	if !r.cliState.Terminal() && r.cliState != StateClosing {
		t.Fatalf("run %d: client %s after its ladder ran out", run, r.cliState)
	}
	if r.cliReason != ct1ExpectedReason(r) {
		t.Fatalf("run %d: close reason %s in phase %d, want %s", run, r.cliReason, r.closePhase, ct1ExpectedReason(r))
	}
	if connectBy := r.firstSendAt + handshakeBudget(Retry{}.orDefault()); r.closedAt > connectBy {
		t.Fatalf("run %d: closed at %v, after connectBy %v", run, r.closedAt, connectBy)
	}
}

// The two prior modes of Amendment 2 (A2.5). MEASURED: the host supplied the
// last measured handshake RTT to this gateway as Retry.RTTPrior, here the
// cell's RTT. FIRST-CONTACT: RTTPrior zero, so the engine default (400 ms)
// is the pre-session floor.
type ct1Mode struct {
	name     string
	measured bool
}

var ct1Modes = []ct1Mode{{"measured", true}, {"first-contact", false}}

// ct1FirstContactPrior is DefaultRTTPrior, restated so this file still builds
// on trees that predate it.
const ct1FirstContactPrior = 400 * time.Millisecond

// prior is the Retry.RTTPrior a run in this mode sets (zero: leave the default).
func (m ct1Mode) prior(rtt time.Duration) time.Duration {
	if m.measured {
		return rtt
	}
	return 0
}

// floor is the first pre-session retry floor a run in this mode has (D5).
// Amendment 3 removed the FIRST-CONTACT exemption: every ruled bound is
// asserted in every cell in both modes.
func (m ct1Mode) floor(rtt time.Duration) time.Duration {
	if m.measured {
		return rtt
	}
	return ct1FirstContactPrior
}

// ct1SetPrior sets Retry.RTTPrior by name, so this file still builds on a tree
// without the field; there it sets nothing and the run is that tree's
// behaviour (which is how the fail-first runs show the D4 tree red).
func ct1SetPrior(r *Retry, prior time.Duration) {
	f := reflect.ValueOf(r).Elem().FieldByName("RTTPrior")
	if f.IsValid() && f.CanSet() {
		f.SetInt(int64(prior))
	}
}

// ct1Run drives one connect over a link with a fixed one-way delay of rtt/2 and
// scripted loss, from the first initiation to the client delivering the
// gateway's reply to its first inner packet ("carrying"). Every random draw in
// both drivers comes from a seeded stream, so a cell is reproducible.
func ct1Run(t *testing.T, o ct1Opts) ct1Result {
	t.Helper()
	return ct1RunWith(t, o, nil)
}

// ct1RunWith is ct1Run with a final adjustment of both configs.
func ct1RunWith(t *testing.T, o ct1Opts, tweak func(cli, gw *Config)) ct1Result {
	t.Helper()
	var edPriv, mlSeed []byte
	var edPub, mlPub []byte
	if o.dual {
		ep, epub, ms, mp := dualKeys(t)
		edPriv, edPub, mlSeed, mlPub = ep, epub, ms, mp
	}
	p := newPair(t, func(cli, gw *Config) {
		cli.MaxMessageSize, gw.MaxMessageSize = o.size, o.size
		cli.Rand = newDetRand(fmt.Sprintf("ct1-cli-%d-%d-%d", o.seed, o.size, o.rtt))
		gw.Rand = newDetRand(fmt.Sprintf("ct1-gw-%d-%d-%d", o.seed, o.size, o.rtt))
		// The gateway's own timers are pushed past the horizon so that every
		// gateway transmission in the trace is an answer; the client keeps the
		// production retry ladder, which is what is under test. The T10
		// real-timer variant keeps the gateway's production timers instead.
		if !o.gwTimers {
			quietConfig(gw)
			gw.Silence = Draw{Min: quietHorizon, Mean: 2 * quietHorizon, Max: 3 * quietHorizon}
		}
		if o.dual {
			gw.DualAuth = DualAuthConfig{Ed25519Private: edPriv, MLDSA65Seed: mlSeed}
			cli.DualAuth = DualAuthConfig{Expected: true, Ed25519Public: edPub, MLDSA65Public: mlPub}
		}
		if o.prior > 0 {
			ct1SetPrior(&cli.Retry, o.prior)
		}
		if tweak != nil {
			tweak(cli, gw)
		}
	})
	horizon := o.horizon
	if horizon == 0 {
		horizon = 40 * time.Second
	}
	owd := o.rtt / 2
	start := p.clk.Now()
	since := func() time.Duration { return p.clk.Now().Sub(start) }
	var q []ct1Msg
	var r ct1Result
	r.gw, r.cli = p.gw, p.cli
	r.size = o.size
	r.sessionAt = -1
	inner := make([]byte, 84)
	inner[0] = 0x45
	if err := p.cli.Enqueue(inner); err != nil {
		t.Fatal(err)
	}
	replied := false
	nCli, nGw, gwGen := 0, 0, 0
	for step := 0; step < 200000; step++ {
		now := p.clk.Now()
		if since() > horizon {
			break
		}
		cliPos := 0
		for {
			att := p.cli.Stats().HandshakeAttempts
			a0, sup0 := p.cli.attempt, ct1StatOr0(p.cli.Stats(), "GenerationsSuperseded")
			d0, ok := ct1DriverInt(p.cli, "drawIdx")
			if !ok {
				d0 = a0
			}
			phase, live := ct1Phase(p.cli), !p.cli.State().Terminal() && p.cli.State() != StateClosing
			m, err := p.cli.Poll()
			if err != nil {
				t.Fatalf("client poll: %v", err)
			}
			if live && (p.cli.State().Terminal() || p.cli.State() == StateClosing) {
				r.closePhase = phase
			}
			if p.cli.sess != nil {
				r.maxPhase = max(r.maxPhase, ct1Phase(p.cli))
			}
			authed, st := p.cli.sess != nil, p.cli.State()
			if p.cli.attempt > a0 {
				r.fires = append(r.fires, ct1Fire{at: since(), index: a0, drawIndex: d0,
					superseded: ct1StatOr0(p.cli.Stats(), "GenerationsSuperseded") > sup0})
			}
			if p.cli.Stats().HandshakeAttempts > att {
				r.freshAt = append(r.freshAt, since())
			}
			if m == nil {
				break
			}
			if nCli == 0 {
				r.firstSendAt = since()
			}
			d := ct1Dgram{kind: ct1Other, pos: -1, epoch: p.cli.Epoch(), msg: append([]byte(nil), m...)}
			switch {
			case !authed:
				d.kind, d.pos = ct1Initiation, 0
			case st == StateInitiating:
				cliPos++
				d.kind, d.pos = ct1PQEK, cliPos
			}
			drop := o.dropCli != nil && o.dropCli(d)
			r.cliSends = append(r.cliSends, ct1Send{at: since(), idx: nCli, dropped: drop, ct1Dgram: d})
			if !drop {
				q = append(q, ct1Msg{at: now.Add(owd), toGw: true, msg: d.msg})
				if o.dup {
					q = append(q, ct1Msg{at: now.Add(owd), toGw: true, msg: d.msg})
				}
			}
			nCli++
		}
		gwPos := -1
		for {
			e0, hs0, ps0, pp0 := p.gw.Epoch(), p.gw.Stats().HandshakeMessagesSent, p.gw.Stats().PingsSent, p.gw.pingPending
			pq0 := p.gw.Stats().PQChunksSent
			m, err := p.gw.Poll()
			if err != nil {
				t.Fatalf("gateway poll: %v", err)
			}
			if m == nil {
				break
			}
			e1, hs1, ps1, pp1 := p.gw.Epoch(), p.gw.Stats().HandshakeMessagesSent, p.gw.Stats().PingsSent, p.gw.pingPending
			pq1 := p.gw.Stats().PQChunksSent
			d := ct1Dgram{kind: ct1Other, pos: -1, epoch: e1, msg: append([]byte(nil), m...)}
			switch {
			case hs1 > hs0:
				gwGen++
				d.kind, d.pos = ct1Response, 0
			case e0 == 0 && e1 >= 1:
				d.kind, d.pos, d.epoch = ct1PQCT, 1, 0
				gwPos = 1
			case !pp1 && (pp0 || ps1 > ps0):
				d.kind = ct1Probe
			case gwPos >= 1:
				gwPos++
				d.pos = gwPos
			}
			d.gen = gwGen
			drop := o.dropGw != nil && o.dropGw(d)
			cs := p.cli.State()
			r.gwSends = append(r.gwSends, ct1Send{at: since(), idx: nGw, dropped: drop, ct1Dgram: d,
				hsDelta: hs1 - hs0, pqDelta: pq1 - pq0, pingDelta: ps1 - ps0,
				cliAttempts: p.cli.Stats().HandshakeAttempts, cliDone: cs.Terminal() || cs == StateClosing,
				gwReason: p.gw.LocalCloseReason(), deliveredAt: -1})
			if !drop {
				extra := time.Duration(0)
				if o.delayGw != nil {
					extra = o.delayGw(d)
				}
				q = append(q, ct1Msg{at: now.Add(owd + extra), toGw: false, msg: d.msg, gwIdx: nGw})
				if o.dup {
					q = append(q, ct1Msg{at: now.Add(owd + extra), toGw: false, msg: d.msg, gwIdx: nGw})
				}
			}
			nGw++
		}
		if r.established == 0 && p.cli.State() == StateEstablished {
			r.established = since()
		}
		if r.carrying != 0 && !o.untilTerminal && since() >= o.minRun {
			break
		}
		if p.cli.State().Terminal() {
			if r.closedAt == 0 {
				r.closedAt = since()
			}
			if since() >= r.closedAt+o.tail {
				break
			}
		}
		next := time.Time{}
		for _, m := range q {
			if next.IsZero() || m.at.Before(next) {
				next = m.at
			}
		}
		for _, d := range []time.Time{p.cli.NextDeadline(), p.gw.NextDeadline()} {
			if !d.IsZero() && d.After(now) && (next.IsZero() || d.Before(next)) {
				next = d
			}
		}
		if next.IsZero() {
			break
		}
		if next.After(now) {
			p.clk.Advance(next.Sub(now))
		}
		now = p.clk.Now()
		sort.SliceStable(q, func(i, j int) bool { return q[i].at.Before(q[j].at) })
		var keep []ct1Msg
		for _, m := range q {
			if m.at.After(now) {
				keep = append(keep, m)
				continue
			}
			if m.toGw {
				before := p.gw.genSeq
				pkts, _ := p.gw.Deliver(m.msg)
				r.gwRecvs = append(r.gwRecvs, ct1Recv{at: since(), opened: p.gw.genSeq != before})
				if len(pkts) > 0 && !replied {
					replied = true
					_ = p.gw.Enqueue(inner)
				}
			} else {
				recv0 := p.cli.Stats().MessagesReceived
				if s := &r.gwSends[m.gwIdx]; s.deliveredAt < 0 {
					s.deliveredAt = since()
				}
				hold0 := ct1HoldLen(p.cli)
				pkts, _ := p.cli.Deliver(m.msg)
				rv := ct1CliRecv{at: since(), opened: p.cli.Stats().MessagesReceived > recv0, attempts: p.cli.Stats().HandshakeAttempts,
					held: ct1HoldLen(p.cli) > hold0, gwIdx: m.gwIdx}
				if dl := p.cli.NextDeadline(); !dl.IsZero() {
					rv.deadline = dl.Sub(start)
				}
				r.cliRecvs = append(r.cliRecvs, rv)
				if r.sessionAt < 0 && p.cli.sess != nil {
					r.sessionAt = since()
				}
				if p.cli.sess != nil && !p.cli.State().Terminal() {
					r.maxPhase = max(r.maxPhase, ct1Phase(p.cli))
				}
				if len(pkts) > 0 && r.carrying == 0 {
					r.carrying = since()
				}
			}
		}
		q = keep
	}
	st := p.cli.Stats()
	r.hsAttempts = st.HandshakeAttempts
	r.superseded = ct1StatOr0(st, "GenerationsSuperseded")
	r.cliState = p.cli.State()
	r.cliReason = p.cli.LocalCloseReason()
	r.needCarrier = p.cli.NeedsCarrierChange()
	r.dualVerified = p.cli.DualAuthVerified()
	if r.cliState.Terminal() && r.closedAt == 0 {
		r.closedAt = since()
	}
	if r.carrying == 0 {
		r.failed = fmt.Errorf("no carrying by %v: client %s reason %s err %v", since(), r.cliState, r.cliReason, p.cli.Err())
	}
	return r
}

func ct1P95(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[int(0.95*float64(len(s)-1))]
}

func ct1Mean(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	var sum time.Duration
	for _, d := range ds {
		sum += d
	}
	return sum / time.Duration(len(ds))
}

// ct1Healthy measures the healthy carrying mean of one cell in one prior mode.
func ct1Healthy(t *testing.T, size int, rtt time.Duration, dual bool, prior time.Duration) time.Duration {
	t.Helper()
	var c []time.Duration
	for i := 0; i < ct1Runs(); i++ {
		r := ct1Run(t, ct1Opts{rtt: rtt, size: size, dual: dual, seed: 1000 + i, prior: prior})
		if r.failed != nil {
			t.Fatalf("healthy run %d (size %d rtt %v dual %v) failed: %v", i, size, rtt, dual, r.failed)
		}
		c = append(c, r.carrying)
	}
	return ct1Mean(c)
}

// ct1Window is the full-jitter window the default ladder draws from at an
// attempt index (500 ms doubling, 8 s cap).
func ct1Window(index int) time.Duration {
	r := Retry{}.orDefault()
	w := r.Base
	for i := 0; i < index; i++ {
		w = min(2*w, r.Cap)
	}
	return w
}

// ct1RetryWindows is the sum of the first n windows of the default ladder: the
// latest the n-th pre-session retry can leave.
func ct1RetryWindows(n int) time.Duration {
	total := time.Duration(0)
	for i := 0; i < n; i++ {
		total += ct1Window(i)
	}
	return total
}

// ct1GenerationsBound is the A1.5 bound for the generations a run added: per
// supersession, the measured-RTT floor plus the draw window that fire was armed
// with plus the two round trips of the fresh generation. The ruling writes the
// window as 500 ms, which is the window only when no pre-session retry fired
// before the response; the single per-connect ladder (D4 step 4) makes it the
// window of the attempt index actually reached, and that is what is used.
//
// The floor of a post-response fire is the measured RTT plus the flight
// allowance (one full-size datagram at 256 kbit/s, Seat C N-2), so that is the
// floor term here.
func ct1GenerationsBound(r ct1Result, rtt time.Duration) time.Duration {
	b := time.Duration(0)
	for _, f := range r.fires {
		if f.superseded {
			b += rtt + ct1FlightAllowance(r.size) + ct1Window(f.index) + 2*rtt
		}
	}
	return b
}

// ct1FlightAllowance restates the driver's flightAllowance for a plan floor.
func ct1FlightAllowance(size int) time.Duration {
	return time.Duration(int64(size) * 8 * int64(time.Second) / 256_000)
}

// ct1PreSessionFresh counts fresh initiations sent before the client first
// held a session: the unchanged pre-session ladder, not a loss recovery.
func ct1PreSessionFresh(r ct1Result) int {
	n := 0
	for _, f := range r.freshAt {
		if r.sessionAt < 0 || f < r.sessionAt {
			n++
		}
	}
	return n
}

// ct1DropFirst loses the first gateway datagram at flight position pos (in the
// first generation that has one), and nothing else.
func ct1DropFirst(pos int) func(ct1Dgram) bool {
	return ct1DropFirstWhere(func(d ct1Dgram) bool { return d.pos == pos })
}

// ct1DropFirstWhere loses the first datagram that satisfies match.
func ct1DropFirstWhere(match func(ct1Dgram) bool) func(ct1Dgram) bool {
	done := false
	return func(d ct1Dgram) bool {
		if done || !match(d) {
			return false
		}
		done = true
		return true
	}
}

// ct1DropAll combines loss scripts; a datagram is lost when any script loses
// it. Every script sees every datagram, so each keeps its own "first" state.
func ct1DropAll(fs ...func(ct1Dgram) bool) func(ct1Dgram) bool {
	return func(d ct1Dgram) bool {
		lost := false
		for _, f := range fs {
			if f(d) {
				lost = true
			}
		}
		return lost
	}
}

func ct1Dropped(sends []ct1Send) bool {
	for _, s := range sends {
		if s.dropped {
			return true
		}
	}
	return false
}

// ct1GatewayHandshakeDatagrams is how many datagrams the gateway's
// handshake-phase flight holds: the response, the PQ ciphertext, and with dual
// auth the Ed25519 frame and the three ML-DSA-65 chunks.
func ct1GatewayHandshakeDatagrams(dual bool) int {
	if dual {
		return 6
	}
	return 2
}

// ct1GatewayAnswersOnly is T10's guard, applied in every recovery run: each
// gateway transmission leaves at the instant a client message that
// authenticated or opened reached the gateway, so within one RTT of it, and the
// gateway sends nothing it timed itself.
func ct1GatewayAnswersOnly(t *testing.T, run int, r ct1Result) {
	t.Helper()
	openedAt := map[time.Duration]bool{}
	for _, rv := range r.gwRecvs {
		if rv.opened {
			openedAt[rv.at] = true
		}
	}
	for _, s := range r.gwSends {
		if s.kind == ct1Probe {
			t.Fatalf("run %d: the gateway sent a probe it timed itself at %v", run, s.at)
		}
		if !openedAt[s.at] {
			t.Fatalf("run %d: gateway datagram %d (kind %d) at %v answers no authenticated client message", run, s.idx, s.kind, s.at)
		}
	}
}

// ct1GenerationsAdded asserts A1.5's "n generations added" for a run: exactly
// n supersessions, no other fresh initiation after the first session, and
// carrying within the per-generation bound.
func ct1GenerationsAdded(t *testing.T, run int, r ct1Result, n int, healthy, rtt, slack time.Duration) {
	t.Helper()
	if r.superseded != uint64(n) {
		t.Fatalf("run %d: %d generation(s) superseded, want %d", run, r.superseded, n)
	}
	if want := uint64(1 + ct1PreSessionFresh(r) + n); r.hsAttempts != want {
		t.Fatalf("run %d: %d handshake attempts, want %d (1 + %d pre-session fresh + %d superseded)", run, r.hsAttempts, want, ct1PreSessionFresh(r), n)
	}
	// The baseline is the healthy mean, or this run's own healthy finish
	// (first session plus the PQ and data round trips) when the unchanged
	// pre-session ladder already delayed the first session with no loss.
	base := max(healthy, r.sessionAt+2*rtt) + slack
	if bound := base + ct1GenerationsBound(r, rtt); r.carrying > bound {
		t.Fatalf("run %d: carrying at %v, past the baseline %v plus the bound of %d added generation(s) (%v)", run, r.carrying, base, n, bound)
	}
}

// --- T2: a lost gateway handshake datagram costs one generation ---------------

// TestCT1LostGatewayHandshakeDatagramRecovers is T2, re-tiered by Amendments 2
// and 3. For every gateway handshake-phase datagram k (0 the response, 1 the
// PQ ciphertext, 2 the Ed25519 frame, 3 to 5 the ML-DSA-65 chunks), at both
// plan floors and five RTTs, with and without dual auth, in both prior modes:
// every run reaches carrying (a run whose ladder was spent is a failure, not a
// skip) and every gateway transmission is an answer (T10).
//
//   - k = 1 to 5 add exactly one generation, within the index-aware bound in
//     every run, and the cell p95 is within the restated ruled bound (A3.3
//     Q3) healthy + RTT + allowance + window(0) + 2 RTT, in every cell
//     including FIRST-CONTACT at 600 ms.
//   - k = 0: exactly one fresh initiation (HandshakeAttempts == 2), no
//     supersession, and carrying within healthy + floor + window(0) in every
//     run of every cell.
func TestCT1LostGatewayHandshakeDatagramRecovers(t *testing.T) {
	for _, mode := range ct1Modes {
		for _, dual := range []bool{true, false} {
			for _, size := range ct1Sizes {
				for _, rtt := range ct1RTTs {
					healthy := ct1Healthy(t, size, rtt, dual, mode.prior(rtt))
					for k := 0; k < ct1GatewayHandshakeDatagrams(dual); k++ {
						t.Run(fmt.Sprintf("%s/dual=%v/size=%d/rtt=%v/gw=%d", mode.name, dual, size, rtt, k), func(t *testing.T) {
							ct1LostGatewayDatagram(t, mode, dual, size, rtt, k, healthy)
						})
					}
				}
			}
		}
	}
}

func ct1LostGatewayDatagram(t *testing.T, mode ct1Mode, dual bool, size int, rtt time.Duration, k int, healthy time.Duration) {
	t.Helper()
	var carry []time.Duration
	for i := 0; i < ct1Runs(); i++ {
		r := ct1Run(t, ct1Opts{rtt: rtt, size: size, dual: dual, seed: i, prior: mode.prior(rtt), dropGw: ct1DropFirst(k)})
		if r.failed != nil {
			t.Fatalf("run %d: %v (pre-session fires %d)", i, r.failed, ct1PreSessionFires(r))
		}
		if !ct1Dropped(r.gwSends) {
			t.Fatalf("run %d: the scripted loss of gateway datagram %d never happened", i, k)
		}
		if dual && !r.dualVerified {
			t.Fatalf("run %d: carrying without a verified attestation", i)
		}
		ct1GatewayAnswersOnly(t, i, r)
		switch {
		case k >= 1:
			ct1GenerationsAdded(t, i, r, 1, healthy, rtt, 0)
		default:
			if r.hsAttempts != 2 || r.superseded != 0 {
				t.Fatalf("run %d: a lost response cost %d handshake attempts and %d supersessions, want 2 and 0", i, r.hsAttempts, r.superseded)
			}
			if bound := healthy + mode.floor(rtt) + ct1Window(0); r.carrying > bound {
				t.Fatalf("run %d: carrying at %v, past healthy %v + floor %v + window(0) = %v", i, r.carrying, healthy, mode.floor(rtt), bound)
			}
		}
		carry = append(carry, r.carrying)
	}
	if k >= 1 {
		if p95, bound := ct1P95(carry), healthy+rtt+ct1FlightAllowance(size)+ct1Window(0)+2*rtt; p95 > bound {
			t.Fatalf("p95 carrying %v exceeds the ruled bound %v (healthy %v + RTT + allowance + window(0) + 2 RTT)", p95, bound, healthy)
		}
	}
	// Measurement only: every bound above is asserted.
	t.Logf("p95 carrying %v (healthy mean %v)", ct1P95(carry), healthy)
}

// --- T3: a lost response with dual auth recovers through a fresh generation ---

// TestCT1LostResponseWithDualAuthAttestsTheReplacement is T3: the fresh
// initiation reaches admitReinitiation, and the replacement generation must
// still present a verifiable attestation (D3: the signer is not destroyed).
func TestCT1LostResponseWithDualAuthAttestsTheReplacement(t *testing.T) {
	for _, mode := range ct1Modes {
		for _, size := range ct1Sizes {
			for _, rtt := range ct1RTTs {
				ct1LostResponseAttests(t, mode, size, rtt)
			}
		}
	}
}

func ct1LostResponseAttests(t *testing.T, mode ct1Mode, size int, rtt time.Duration) {
	t.Run(fmt.Sprintf("%s/size=%d/rtt=%v", mode.name, size, rtt), func(t *testing.T) {
		for i := 0; i < ct1Runs(); i++ {
			r := ct1Run(t, ct1Opts{rtt: rtt, size: size, dual: true, seed: 500 + i, prior: mode.prior(rtt), dropGw: ct1DropFirst(0)})
			if r.failed != nil {
				t.Fatalf("run %d: %v", i, r.failed)
			}
			if !ct1Dropped(r.gwSends) {
				t.Fatalf("run %d: no response was lost", i)
			}
			if !r.dualVerified {
				t.Fatalf("run %d: the replacement generation established without a verified attestation", i)
			}
			if r.hsAttempts < 2 {
				t.Fatalf("run %d: %d handshake attempts; the lost response was not recovered by a fresh initiation", i, r.hsAttempts)
			}
		}
	})
}

// --- T7: one ladder, one deadline --------------------------------------------

// TestCT1OneLadderOneDeadline is T7. Across every phase and every generation a
// connect fires its retry ladder Retry.Attempts times in total and ends no
// later than connectBy (the first initiation plus handshakeBudget), with the
// reason of the phase it ran out in: the response lost once, the PQ_CT once,
// then every ML-DSA-65 chunk forever (CloseDualAuthFailed); every PQ_CT lost
// (ClosePQFailed); every response lost (CloseProtocolError, carrier change).
func TestCT1OneLadderOneDeadline(t *testing.T) {
	retry := Retry{}.orDefault()
	cases := []struct {
		name   string
		dual   []bool
		drop   func() func(ct1Dgram) bool
		reason CloseReason
	}{
		{"response-once-pqct-once-ml-forever", []bool{true}, func() func(ct1Dgram) bool {
			return ct1DropAll(ct1DropFirst(0), ct1DropFirst(1), func(d ct1Dgram) bool { return d.pos >= 3 })
		}, CloseDualAuthFailed},
		{"every-pqct", []bool{true, false}, func() func(ct1Dgram) bool {
			return func(d ct1Dgram) bool { return d.kind == ct1PQCT }
		}, ClosePQFailed},
		{"every-response", []bool{true, false}, func() func(ct1Dgram) bool {
			return func(d ct1Dgram) bool { return d.kind == ct1Response }
		}, CloseProtocolError},
	}
	for _, mode := range ct1Modes {
		for _, c := range cases {
			for _, dual := range c.dual {
				for _, size := range ct1Sizes {
					for _, rtt := range ct1RTTs {
						ct1OneLadderCell(t, mode, retry, c.name, c.reason, c.drop, dual, size, rtt)
					}
				}
			}
		}
	}
}

func ct1OneLadderCell(t *testing.T, mode ct1Mode, retry Retry, name string, reason CloseReason, drop func() func(ct1Dgram) bool, dual bool, size int, rtt time.Duration) {
	c := struct {
		name   string
		drop   func() func(ct1Dgram) bool
		reason CloseReason
	}{name, drop, reason}
	t.Run(fmt.Sprintf("%s/%s/dual=%v/size=%d/rtt=%v", mode.name, c.name, dual, size, rtt), func(t *testing.T) {
		inPhase := 0
		defer func() {
			t.Logf("%d/%d runs closed with %s; the rest ran out a phase earlier", inPhase, ct1Runs(), c.reason)
			if inPhase == 0 {
				t.Errorf("no run reached the scenario's phase (%s)", c.reason)
			}
		}()
		for i := 0; i < ct1Runs(); i++ {
			r := ct1Run(t, ct1Opts{rtt: rtt, size: size, dual: dual, seed: 800 + i, prior: mode.prior(rtt), untilTerminal: true, dropGw: c.drop()})
			if !r.cliState.Terminal() || r.carrying != 0 {
				t.Fatalf("run %d: client %s, carrying %v; want a closed connect", i, r.cliState, r.carrying)
			}
			if len(r.fires) != retry.Attempts {
				t.Fatalf("run %d: %d ladder fires, want exactly Retry.Attempts = %d", i, len(r.fires), retry.Attempts)
			}
			// The scenario's own phase is where the ladder normally runs
			// out; when the unchanged pre-session ladder spent extra fires
			// it runs out a phase earlier, and the reason must follow the
			// phase it actually ran out in.
			if r.cliReason != ct1ExpectedReason(r) {
				t.Fatalf("run %d: close reason %s in phase %d, want %s", i, r.cliReason, r.closePhase, ct1ExpectedReason(r))
			}
			if r.cliReason == c.reason {
				inPhase++
			}
			if connectBy := r.firstSendAt + handshakeBudget(retry); r.closedAt > connectBy {
				t.Fatalf("run %d: closed at %v, after connectBy %v", i, r.closedAt, connectBy)
			}
			if c.reason == CloseProtocolError && !r.needCarrier {
				t.Fatalf("run %d: a connect no response reached did not ask for a carrier change", i)
			}
			ct1GatewayAnswersOnly(t, i, r)
		}
	})
}

// --- T14 and T15: the floor keeps healthy connects to one initiation --------

// ct1HealthyOneKey checks one healthy run: one PQ_EK message set, no
// supersession, and returns the run.
func ct1HealthyOneKey(t *testing.T, run int, r ct1Result, size int) {
	t.Helper()
	if r.failed != nil {
		t.Fatalf("run %d: %v", run, r.failed)
	}
	keys := 0
	for _, s := range r.cliSends {
		if s.kind == ct1PQEK {
			keys++
		}
	}
	if want := len(chunkBlob(core.FramePQEK, make([]byte, core.PQEncapsulationKeySize), size-core.TransportOverhead()-frameHeaderSize)); keys != want {
		t.Fatalf("run %d: %d PQ_EK message(s), want one set of %d", run, keys, want)
	}
	if r.superseded != 0 {
		t.Fatalf("run %d: a healthy connect superseded %d generation(s)", run, r.superseded)
	}
}

// TestCT1MeasuredPriorFloorsTheFirstContact is T14 (it subsumes Amendment 1's
// T8, which was the 300 and 600 ms cells of it): with the host's measured RTT
// as the prior, a healthy connect at every RTT including 600 ms sends one
// initiation and one PQ_EK set, and no ladder fire precedes the response (the
// Amendment 2 confirmation question: a pre-session fire cannot precede the
// response on a path whose RTT is at or below the prior).
func TestCT1MeasuredPriorFloorsTheFirstContact(t *testing.T) {
	for _, dual := range []bool{true, false} {
		for _, size := range ct1Sizes {
			for _, rtt := range ct1RTTs {
				t.Run(fmt.Sprintf("dual=%v/size=%d/rtt=%v", dual, size, rtt), func(t *testing.T) {
					for i := 0; i < ct1Runs(); i++ {
						r := ct1Run(t, ct1Opts{rtt: rtt, size: size, dual: dual, seed: 900 + i, prior: rtt})
						ct1HealthyOneKey(t, i, r, size)
						if r.hsAttempts != 1 {
							t.Fatalf("run %d: %d handshake attempts on a healthy connect, want 1", i, r.hsAttempts)
						}
						if pf := ct1PreSessionFires(r); pf != 0 {
							t.Fatalf("run %d: %d ladder fire(s) before the response on a path at the prior", i, pf)
						}
					}
				})
			}
		}
	}
}

// TestCT1DefaultPriorFloorsTheFirstContact is T15: with no measurement (the
// 400 ms default prior), a healthy connect at RTT <= 300 ms behaves as T14; at
// 600 ms every run carries with at most one extra fresh initiation
// (HandshakeAttempts <= 2: the Karn floor puts a second pre-session fire after
// the first one's response for any RTT below 800 ms, A3.3 Q1), no
// supersession, within healthy + 400 ms + window(0). Every bound is asserted
// (A3.3 TESTS item 2).
func TestCT1DefaultPriorFloorsTheFirstContact(t *testing.T) {
	for _, dual := range []bool{true, false} {
		for _, size := range ct1Sizes {
			for _, rtt := range ct1RTTs {
				t.Run(fmt.Sprintf("dual=%v/size=%d/rtt=%v", dual, size, rtt), func(t *testing.T) {
					healthy := 3 * rtt
					for i := 0; i < ct1Runs(); i++ {
						r := ct1Run(t, ct1Opts{rtt: rtt, size: size, dual: dual, seed: 950 + i})
						ct1HealthyOneKey(t, i, r, size)
						if rtt <= 300*time.Millisecond {
							if r.hsAttempts != 1 || ct1PreSessionFires(r) != 0 {
								t.Fatalf("run %d: %d attempts, %d pre-session fires; want 1 and 0", i, r.hsAttempts, ct1PreSessionFires(r))
							}
							continue
						}
						if r.hsAttempts > 2 {
							t.Fatalf("run %d: %d handshake attempts at first contact on a %v path, want at most 2", i, r.hsAttempts, rtt)
						}
						if bound := healthy + ct1FirstContactPrior + ct1Window(0); r.carrying > bound {
							t.Fatalf("run %d: carrying at %v, past healthy %v + 400 ms + window(0) = %v", i, r.carrying, healthy, bound)
						}
					}
				})
			}
		}
	}
}

// --- T9: reorder and duplicate attestation frames ----------------------------

// ct1Attestation is a dual-auth pair whose client holds the ciphertext and
// none of the attestation (every attestation datagram of the flight was lost),
// with the two genuine signatures over the client's transcript as frames.
type ct1Attestation struct {
	p  *pair
	ed core.Frame
	ml []core.Frame
}

func newCT1Attestation(t *testing.T, size int) *ct1Attestation {
	t.Helper()
	edPriv, edPub, mlSeed, mlPub := dualKeys(t)
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.MaxMessageSize, gw.MaxMessageSize = size, size
		gw.DualAuth = DualAuthConfig{Ed25519Private: edPriv, MLDSA65Seed: mlSeed}
		cli.DualAuth = DualAuthConfig{Expected: true, Ed25519Public: edPub, MLDSA65Public: mlPub}
	})
	p.filterToCli = func(idx int, _ []byte) bool { return idx < 2 }
	p.run()
	p.filterToCli = nil
	if p.cli.State() != StateInitiating || p.cli.sess == nil || !p.cli.sess.PQRatcheted() || p.cli.dualDone {
		t.Fatalf("fixture: client %s, ratcheted %v", p.cli.State(), p.cli.sess != nil && p.cli.sess.PQRatcheted())
	}
	h := p.cli.sess.TranscriptHash()
	edSig, err := dualsign.SignEd25519(edPriv, h[:])
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pqauth.NewSigner(pqauth.MLDSA65, mlSeed)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	mlSig, err := dualsign.SignMLDSA65(signer, h[:])
	if err != nil {
		t.Fatal(err)
	}
	a := &ct1Attestation{p: p, ed: core.Frame{Type: core.FrameDualAuthED, Value: edSig}}
	for _, c := range chunkBlob(core.FrameDualAuthML, mlSig, p.cli.cfg.maxPayload()-frameHeaderSize) {
		a.ml = append(a.ml, core.Frame{Type: c.typ, Value: c.value})
	}
	return a
}

func (a *ct1Attestation) feed(t *testing.T, fs ...core.Frame) {
	t.Helper()
	if _, err := a.p.cli.handleFrames(a.p.clk.Now(), fs, false); err != nil {
		t.Fatal(err)
	}
}

// TestCT1AttestationReorderAndDuplicate is T9.
func TestCT1AttestationReorderAndDuplicate(t *testing.T) {
	for _, size := range ct1Sizes {
		t.Run(fmt.Sprintf("size=%d/ml-before-ed", size), func(t *testing.T) {
			a := newCT1Attestation(t, size)
			a.feed(t, a.ml...)
			if a.p.cli.State() != StateInitiating || a.p.cli.Err() != nil {
				t.Fatalf("a complete ML-DSA-65 half before the Ed25519 half: %s %v", a.p.cli.State(), a.p.cli.Err())
			}
			a.feed(t, a.ml[0]) // a chunk of the held half again
			a.feed(t, a.ed)
			if a.p.cli.State() != StateEstablished || !a.p.cli.DualAuthVerified() || a.p.cli.Err() != nil {
				t.Fatalf("the late Ed25519 half: %s verified=%v err %v", a.p.cli.State(), a.p.cli.DualAuthVerified(), a.p.cli.Err())
			}
		})
		t.Run(fmt.Sprintf("size=%d/ed-twice-equal-and-ml-after-completion", size), func(t *testing.T) {
			a := newCT1Attestation(t, size)
			a.feed(t, a.ed, a.ed)
			if a.p.cli.Err() != nil {
				t.Fatalf("an equal duplicate Ed25519 frame was refused: %v", a.p.cli.Err())
			}
			a.feed(t, a.ml...)
			a.feed(t, a.ml[len(a.ml)-1])
			if a.p.cli.State() != StateEstablished || !a.p.cli.DualAuthVerified() || a.p.cli.Err() != nil {
				t.Fatalf("after duplicates: %s verified=%v err %v", a.p.cli.State(), a.p.cli.DualAuthVerified(), a.p.cli.Err())
			}
		})
		t.Run(fmt.Sprintf("size=%d/different-ed-before-completion", size), func(t *testing.T) {
			a := newCT1Attestation(t, size)
			other := append([]byte(nil), a.ed.Value...)
			other[0] ^= 0xff
			a.feed(t, a.ed, core.Frame{Type: core.FrameDualAuthED, Value: other})
			if err := a.p.cli.Err(); !errors.Is(err, ErrProtocol) {
				t.Fatalf("a different Ed25519 value before completion: err %v, want ErrProtocol", err)
			}
		})
		t.Run(fmt.Sprintf("size=%d/wrong-ed-with-correct-ml", size), func(t *testing.T) {
			a := newCT1Attestation(t, size)
			wrong := append([]byte(nil), a.ed.Value...)
			wrong[len(wrong)-1] ^= 0x01
			a.feed(t, core.Frame{Type: core.FrameDualAuthED, Value: wrong})
			a.feed(t, a.ml...)
			if err := a.p.cli.Err(); !errors.Is(err, ErrDualAuthFailed) {
				t.Fatalf("a wrong Ed25519 signature: err %v, want ErrDualAuthFailed", err)
			}
			if a.p.cli.LocalCloseReason() != CloseDualAuthFailed {
				t.Fatalf("close reason %s, want %s", a.p.cli.LocalCloseReason(), CloseDualAuthFailed)
			}
			if got := ct1StatOr0(a.p.cli.Stats(), "GenerationsSuperseded"); got != 0 || a.p.cli.Stats().HandshakeAttempts != 1 {
				t.Fatalf("an invalid signature pair started a new generation (superseded %d)", got)
			}
		})
	}
}
