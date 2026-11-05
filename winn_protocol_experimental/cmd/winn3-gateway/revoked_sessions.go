package main

import (
	"fmt"
	"os"
	"time"

	"winsvpn.local/winnprotocol/winn3/session"
)

// Ending sessions whose peer has left the authorization registry.
//
// # The defect this closes
//
// The registry is checked at every handshake and on every forwarded packet,
// but nothing ever ended an ESTABLISHED session whose peer it stopped
// authorizing. Such a session keeps opening liveness traffic and, before
// resolverDevice consulted the registry, kept getting DNS answers, so the
// client's gate read carrying and its A3 lifecycle read connected while every
// transit packet was refused (France, 2026-09-23: 2,370 refusals in six
// minutes while the phone claimed SECURED; UK the same day: 15,106).
//
// Ending the session with the ordinary authenticated CLOSE (driver.Loop.Close)
// hands the client a round end, which its supervisor turns into recovering
// and, when re-admission is refused, blocked. No new wire value is involved.
//
// # What the grace is, precisely
//
// A session is closed after revokedSessionGrace of CONSECUTIVE unauthorized
// sweep observations. The sweep runs on the serve ticker (statusInterval), so:
//
//   - the interval starts at the first sweep that observes the peer
//     unauthorized, not at the moment the hub replaced the registry file, and
//     the registry's own freshness contract (registryFreshness) sits between
//     those two moments;
//   - it is a sequence of observations, not proof of continuous absence
//     between them: a registry that is withdrawn and restored between two
//     sweeps is never observed;
//   - ticker scheduling can delay the close past the nominal grace. The grace
//     is a floor, not a deadline.
//
// Any authorized observation resets the interval. A session that is not
// ESTABLISHED or REKEYING is skipped WITHOUT resetting it, so a peer cannot
// restart its own grace by driving a state change such as an in-band rekey.
//
// The grace governs session TEARDOWN only. It grants no forwarding and no DNS
// authority: gatewayForwardDevice and resolverDevice apply the registry
// independently on every packet, under the registry's freshness contract.
//
// # The decision boundary
//
// When the interval is due, the sweep revalidates the registry freshly
// (forceRefreshDue, then a lookup that must stat the file) before committing.
// A restoration that the final validation sees cancels the close. A
// restoration that lands after the decision does not un-close the session;
// the client's next handshake is admitted by the restored registry, so the
// cost is one reconnect.
//
// # A close that does not take
//
// Loop.Close only REQUESTS an orderly teardown. If the request fails it is
// retried on the next sweep, up to revokedCloseRetries; after that, and also
// when a successful request has not ended Run within revokedCloseDeadline, the
// sweep falls back to local teardown in two bounded stages: first ps.stop,
// which cancels the loop context so Run returns and releasePeer runs on the Run
// goroutine as usual; then, if Run still has not returned after another
// revokedCloseDeadline, releasePeer directly, which frees the demux slot and
// the forwarding-table address without waiting on the Run goroutine.

// revokedSessionGrace is the consecutive-observation interval described above.
const revokedSessionGrace = 10 * time.Second

// revokedCloseDeadline bounds each teardown stage after a committed close.
const revokedCloseDeadline = 5 * time.Second

// revokedCloseRetries is how many failed close requests precede local teardown.
const revokedCloseRetries = 3

// revokeState is one session's sweep state. Only closeRevokedSessions, on the
// serve ticker goroutine, reads or writes it.
type revokeState struct {
	// unauthorizedSince is the first unauthorized observation of the current
	// interval, or zero.
	unauthorizedSince time.Time
	// decidedAt is when the current teardown stage began, or zero before the
	// close decision is committed.
	decidedAt time.Time
	// stage: 0 not decided, 1 close requested, 2 context cancelled, 3 released.
	stage int
	// failures counts failed close requests.
	failures int
	// closeRequest overrides driver.Loop.Close. Tests only; nil in production.
	closeRequest func() error
}

const (
	revokeUndecided = iota
	revokeCloseRequested
	revokeStopped
	revokeReleased
)

func (ps *peerSession) runReturned() bool {
	if ps.done == nil {
		return false
	}
	select {
	case <-ps.done:
		return true
	default:
		return false
	}
}

func (ps *peerSession) requestRevokedClose() error {
	if ps.revoke.closeRequest != nil {
		return ps.revoke.closeRequest()
	}
	return ps.loop.Close()
}

// revokedSweepResult counts what one sweep did, for the log line and tests.
type revokedSweepResult struct {
	closeRequested int
	closeFailed    int
	stopped        int
	released       int
}

func (s *server) peerAuthorized(peer []byte) bool {
	_, ok := s.peerRegistry.innerForPeer(peer)
	return ok
}

// closeRevokedSessions applies the policy above to every session. It runs on
// the serve ticker only.
func (s *server) closeRevokedSessions(now time.Time) revokedSweepResult {
	var res revokedSweepResult
	if s.peerRegistry == nil {
		return res
	}
	s.mu.Lock()
	all := make([]*peerSession, 0, len(s.peers)+len(s.tcpPeers))
	seen := make(map[*peerSession]bool, len(s.peers)+len(s.tcpPeers))
	for _, ps := range s.peers {
		if !seen[ps] {
			seen[ps] = true
			all = append(all, ps)
		}
	}
	for ps := range s.tcpPeers {
		if !seen[ps] {
			seen[ps] = true
			all = append(all, ps)
		}
	}
	s.mu.Unlock()
	for _, ps := range all {
		if ps.loop == nil || ps.runReturned() {
			continue
		}
		st := &ps.revoke
		if st.stage != revokeUndecided {
			s.advanceRevokedTeardown(ps, now, &res)
			continue
		}
		sess := ps.loop.Session()
		if sess == nil {
			continue
		}
		if state := sess.State(); state != session.StateEstablished && state != session.StateRekeying {
			continue
		}
		peer := sess.PeerStatic()
		if s.peerAuthorized(peer) {
			st.unauthorizedSince = time.Time{}
			st.failures = 0
			continue
		}
		if st.unauthorizedSince.IsZero() {
			st.unauthorizedSince = now
			continue
		}
		if now.Sub(st.unauthorizedSince) < revokedSessionGrace {
			continue
		}
		// Due. Revalidate freshly before committing, so a cached negative
		// snapshot cannot close a peer the hub has already restored.
		s.peerRegistry.forceRefreshDue()
		if s.peerAuthorized(peer) {
			st.unauthorizedSince = time.Time{}
			st.failures = 0
			continue
		}
		if err := ps.requestRevokedClose(); err != nil {
			st.failures++
			res.closeFailed++
			if st.failures < revokedCloseRetries {
				continue
			}
			s.stopRevokedSession(ps, now, &res)
			continue
		}
		st.stage = revokeCloseRequested
		st.decidedAt = now
		res.closeRequested++
	}
	if res != (revokedSweepResult{}) {
		fmt.Fprintf(os.Stderr,
			"winn3-gateway: revoked-peer sweep: close requested %d, close failed %d, "+
				"context cancelled %d, released %d (grace %v of consecutive unauthorized observations)\n",
			res.closeRequested, res.closeFailed, res.stopped, res.released, revokedSessionGrace)
	}
	return res
}

func (s *server) stopRevokedSession(ps *peerSession, now time.Time, res *revokedSweepResult) {
	if ps.stop != nil {
		ps.stop()
	}
	ps.revoke.stage = revokeStopped
	ps.revoke.decidedAt = now
	res.stopped++
}

// advanceRevokedTeardown moves a committed close to its next bounded stage if
// the current one has outlived revokedCloseDeadline without Run returning.
func (s *server) advanceRevokedTeardown(ps *peerSession, now time.Time, res *revokedSweepResult) {
	st := &ps.revoke
	if now.Sub(st.decidedAt) < revokedCloseDeadline {
		return
	}
	switch st.stage {
	case revokeCloseRequested:
		s.stopRevokedSession(ps, now, res)
	case revokeStopped:
		if ps.pipe == nil {
			s.releaseTCPPeer(ps)
		} else {
			s.releasePeer(ps.remoteAddrPort(), ps)
		}
		st.stage = revokeReleased
		st.decidedAt = now
		res.released++
	}
}
