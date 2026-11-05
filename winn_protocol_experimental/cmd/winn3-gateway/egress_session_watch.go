package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// errRoutingUnaccountable is the close reason while a policy rule or route
// selects on mark or TOS.
var errRoutingUnaccountable = errors.New("policy routing selects on mark or TOS")

// egressLog receives the per-client guard's and the egress watch's log lines.
// It is os.Stderr; a variable only so a test can read the lines without
// swapping os.Stderr under running sessions.
var egressLog io.Writer = os.Stderr

// ESTABLISHED SESSIONS (Round CM3 Turn 3, GPT-6 Sol OI-CM3-1; lane L80).
//
// clientEgressGuard runs when a client is first admitted and when a
// token-demux session is rebound. A route can narrow after that without the
// client's address changing: an operator adds `mtu 1400`, a rule starts
// matching, a device MTU drops. Linux routes each send on an unconnected UDP
// socket afresh, so the next full-size reply takes the narrow route, and with
// the listener's default IP_PMTUDISC_WANT the kernel fragments it locally and
// the send reports success (measured: TestEgressNetnsKernelFragmentsAfterARouteNarrows).
// Nothing on the send path can see it.
//
// No per-packet check: the gateway is about one core bound, and a route lookup
// per send is a netlink round trip. Instead the kernel says when something that
// can change a reply's route has changed (startRouteWatch: links, IPv4
// addresses, routes, rules, nexthops), and this watcher re-asks the per-client
// question for every live UDP session:
//
//   - on a change notification, at most once per egressSweepMinGap (a burst
//     of notifications costs one sweep; one that arrives inside the gap is
//     swept on the next one-second tick);
//   - and every egressRecheckInterval regardless, the backstop for a
//     notification the kernel dropped (ENOBUFS also forces a sweep) or a watch
//     that could not start.
//
// Exposure after a route narrows, with the watch running: the notification's
// latency, plus up to egressSweepMinGap or one tick (one second) of pacing,
// plus the sweep itself. The sweep is one rule and route dump and then one
// lookup per live session, in order. Each answer (a route, a device, a whole
// dump through NLMSG_DONE) is bounded by netlinkAnswerBound (250 ms); a
// question is two answers (route then device, or the rule dump then the
// route dump) and is asked at most netlinkAttempts (3) times, so a stalled
// kernel costs at most 1.5 s per question and then fails CLOSED (Round CM3 Turn 6):
// the dump makes routing unaccountable and closes every session, a session's
// lookup closes that session. The healthy cost is measured
// (BenchmarkMeasureClientEgress). There is no hard wall-clock bound a gateway
// can promise while the kernel does not answer; the longest sweep seen is
// published as egress_sweep_max_us (Round CM3 Turn 4, Sol). Without the watch:
// egressRecheckInterval plus one tick, plus the sweep.
//
// UNACCOUNTABLE ROUTING (Round CM3 Turn 4, Sol OI-CM3-1). Before the
// per-session lookups, each sweep dumps the IPv4 policy rules and routes. A
// rule selecting on fwmark or tos, or a route keyed on tos, means a netfilter
// OUTPUT mark or TOS rewrite could move replies after any lookup
// (egress_route_netlink.go, routingSelector): every session is closed and
// every new client refused while one exists (egress_routing_unaccountable),
// and startup refuses (checkRoutingAccountable). Rule changes are rtnetlink
// notifications, so this is on the same event path. A dump that is not known
// to be complete (Round CM3 Turn 6: NLM_F_DUMP_INTR, an error inside it,
// truncation, no NLMSG_DONE in time) counts the same as a selector.
//
// The notification socket (egress_watch_linux.go) parses nothing: any
// datagram, a truncated one included, and a lost-notification ENOBUFS only
// request a sweep, and the sweep asks the kernel afresh. Nothing it receives
// can make a verdict cleaner.
//
// A session whose replies no longer fit is CLOSED, counted in
// egress_mtu_closed and logged without the address. Why terminal and not
// narrowed: the planning path MTU is agreed at the handshake and nothing in the
// protocol lowers it for the client; session.Driver.SetMaxMessageSize could
// shrink this end's messages, but an inner packet is carried whole in one frame
// and the shared tunnel device's MTU is fixed by the plan, so every full-size
// inner packet would then be dropped at this end: the same silent stall in a
// new place. Closing uses the ordinary authenticated CLOSE (driver.Loop.Close),
// which the client turns into a reconnect; the reconnect meets the admission
// guard, which refuses it while the route stays narrow (egress_mtu_refused), and
// admits it again once the route widens. Teardown is staged exactly as for a
// revoked peer: close requested, then the loop context cancelled, then the
// slot released, each after revokedCloseDeadline.
const egressSweepMinGap = 250 * time.Millisecond

// egressRecheckInterval and egressWatchTick are variables only so a test can
// shorten the backstop; production never changes them.
var (
	egressRecheckInterval = 10 * time.Second
	egressWatchTick       = time.Second
)

// egressCloseState is one session's teardown state. Only the egress watch
// goroutine reads or writes it.
type egressCloseState struct {
	stage     int // revokeUndecided, revokeCloseRequested, revokeStopped, revokeReleased
	decidedAt time.Time
	// closeRequest overrides driver.Loop.Close. Tests only.
	closeRequest func() error
}

// runEgressWatch is the egress watch goroutine. changed may be nil (no
// notification source); the backstop sweep still runs. tick paces the loop.
func (s *server) runEgressWatch(ctx context.Context, changed <-chan struct{}, tick <-chan time.Time) {
	closing := make(map[*peerSession]struct{})
	var last time.Time
	pending := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-changed:
			pending = true
		case now := <-tick:
			if now.Sub(last) >= egressRecheckInterval {
				pending = true
			}
			s.advanceEgressTeardown(now, closing)
		}
		if pending && time.Since(last) >= egressSweepMinGap {
			now := time.Now()
			s.sweepEgress(now, closing)
			last, pending = now, false
		}
	}
}

// sweepEgress re-runs the per-client guard for every live UDP session and
// starts closing the ones whose replies no longer fit.
func (s *server) sweepEgress(now time.Time, closing map[*peerSession]struct{}) int {
	if s.egressGuard == nil {
		return 0
	}
	start := time.Now()
	defer func() {
		us := uint64(time.Since(start).Microseconds())
		for {
			old := s.egressSweepMaxUS.Load()
			if us <= old || s.egressSweepMaxUS.CompareAndSwap(old, us) {
				return
			}
		}
	}()
	// Round CM3 Turn 4: first, can the replies' route be accounted for at all?
	sel, err := detectRoutingSelectors()
	unaccountable := false
	var why string
	switch {
	case err == nil && len(sel) > 0:
		unaccountable, why = true, describeSelectors(sel)
	case err != nil && !platformUnsupported(err):
		// Round CM3 Turn 6: a dump that was refused, interrupted, overrun,
		// truncated, late or otherwise incomplete, after its retries, fails
		// closed. (Turn 5 kept the previous verdict on a timeout, so an
		// incomplete dump could let a clean verdict stand.)
		unaccountable, why = true, fmt.Sprintf("the policy rules and routes could not be listed completely: %v", err)
	}
	was := s.egressUnaccountable.Swap(unaccountable)
	if unaccountable != was {
		if unaccountable {
			fmt.Fprintf(egressLog, "winn3-gateway: egress routing UNACCOUNTABLE (%s): closing every session and "+
				"refusing new clients until it is gone (Round CM3); see egress_routing_unaccountable\n", why)
		} else {
			fmt.Fprintln(egressLog, "winn3-gateway: egress routing accountable again: admitting clients")
		}
	}
	s.mu.Lock()
	live := make([]*peerSession, 0, len(s.peers))
	seen := make(map[*peerSession]bool, len(s.peers))
	for _, ps := range s.peers {
		if !seen[ps] {
			seen[ps] = true
			live = append(live, ps)
		}
	}
	s.mu.Unlock()
	closed := 0
	for _, ps := range live {
		if ps.loop == nil || ps.runReturned() {
			continue
		}
		if _, already := closing[ps]; already {
			continue
		}
		var r egressRoute
		ok := false
		if unaccountable {
			r.Err = errRoutingUnaccountable
		} else {
			r, ok = s.egressGuard.check(ps.remoteAddrPort())
		}
		if ok {
			continue
		}
		closed++
		s.egressClosed.Add(1)
		if c := s.egressClosedLogs.Add(1); c <= maxRefusalLogs {
			if errors.Is(r.Err, errRoutingUnaccountable) {
				fmt.Fprintf(egressLog, "winn3-gateway: closing a session: policy routing selects on mark or TOS, so "+
					"its replies' route cannot be accounted for (Round CM3); see egress_mtu_closed\n")
			} else if r.Err != nil {
				fmt.Fprintf(egressLog, "winn3-gateway: closing a session: the kernel refused the route lookup for "+
					"its reply flow (%v) (Round CM3); see egress_mtu_closed\n", r.Err)
			} else {
				fmt.Fprintf(egressLog, "winn3-gateway: closing a session whose replies the kernel now routes "+
					"through %s (mtu %d, route mtu %d, table %d): the plan's %d-byte IPv4 datagrams would "+
					"leave fragmented (Round CM3); see egress_mtu_closed\n",
					r.Device, r.MTU, r.RouteMTU, r.Table, s.egressGuard.datagram)
			}
			if c == maxRefusalLogs {
				fmt.Fprintf(egressLog, "winn3-gateway: further egress closes will not be logged; see egress_mtu_closed\n")
			}
		}
		closing[ps] = struct{}{}
		st := &ps.egressClose
		st.decidedAt = now
		var err error
		if st.closeRequest != nil {
			err = st.closeRequest()
		} else {
			err = ps.loop.Close()
		}
		if err != nil {
			// The orderly CLOSE could not be queued: cancel the loop now.
			if ps.stop != nil {
				ps.stop()
			}
			st.stage = revokeStopped
			continue
		}
		st.stage = revokeCloseRequested
	}
	return closed
}

// advanceEgressTeardown moves each closing session to its next bounded stage
// once the current one has outlived revokedCloseDeadline without Run
// returning, and forgets sessions whose Run has returned.
func (s *server) advanceEgressTeardown(now time.Time, closing map[*peerSession]struct{}) {
	for ps := range closing {
		if ps.runReturned() {
			delete(closing, ps)
			continue
		}
		st := &ps.egressClose
		if now.Sub(st.decidedAt) < revokedCloseDeadline {
			continue
		}
		switch st.stage {
		case revokeCloseRequested:
			if ps.stop != nil {
				ps.stop()
			}
			st.stage, st.decidedAt = revokeStopped, now
		case revokeStopped:
			s.releasePeer(ps.remoteAddrPort(), ps)
			st.stage, st.decidedAt = revokeReleased, now
			delete(closing, ps)
		default:
			delete(closing, ps)
		}
	}
}

// startEgressWatch starts the notification source and the watch goroutine
// for serve. It logs one line saying which kind of watch is running.
func (s *server) startEgressWatch(ctx context.Context) (stop func()) {
	if s.egressGuard == nil {
		return func() {}
	}
	changed, stopWatch, err := startRouteWatch()
	if err != nil {
		fmt.Fprintf(os.Stderr, "winn3-gateway: WARNING: route-change watch not running (%v); established sessions' "+
			"egress is rechecked every %v only\n", err, egressRecheckInterval)
		changed, stopWatch = nil, func() {}
	} else {
		fmt.Fprintf(os.Stderr, "winn3-gateway: egress watch on: established sessions are rechecked on every "+
			"route, rule, address or link change and every %v\n", egressRecheckInterval)
	}
	ticker := time.NewTicker(egressWatchTick)
	done := make(chan struct{})
	watchCtx, cancel := context.WithCancel(ctx)
	go func() {
		defer close(done)
		s.runEgressWatch(watchCtx, changed, ticker.C)
	}()
	return func() {
		cancel()
		<-done
		ticker.Stop()
		stopWatch()
	}
}
