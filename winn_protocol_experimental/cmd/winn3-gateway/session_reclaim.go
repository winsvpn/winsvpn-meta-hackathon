package main

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"time"

	"winsvpn.local/winnprotocol/winn3/session"
)

// Reclaiming -max-sessions slots from sessions that are dead or superseded.
//
// # The defect this closes
//
// This binary demultiplexes on the peer's UDP address, and a slot was freed
// only when a session's Loop.Run returned. A client that leaves without a CLOSE
// (a crash, SIGTERM of the desktop engine, a phone moving to another network
// and handshaking again from a new source port) therefore kept its slot until
// the gateway's own liveness ladder gave up on it: MaxLostProbes unanswered
// probes, 50 to 80 s at the defaults. Measured in lane L22b with
// -max-sessions 8 and one client every 2.3 s: 22 of the first 60 clients got
// total silence, which from the client is indistinguishable from UDP loss.
//
// # The two rules
//
// Reclaim under pressure (both modes, in sessionFor, only when the table is
// full). A slot is taken back from, in order:
//
//  1. a session that is terminal or closing, or that never authenticated an
//     initiation although something was delivered to it (it can only time out);
//  2. a session established in its current generation on which nothing
//     authenticated has opened for reclaimQuietProbeLifetimes probe ceilings
//     (40 s at the default 20 s ceiling), the one silent longest first.
//
// "Silent for 40 s" is an EARLIER timeout under pressure, not a proof the peer
// is dead: a live but quiet session can cross it. That is the trade a full
// table forces, and it is bounded to the case where the alternative is refusing
// a new client outright. An authenticated generation that is still completing
// its handshake is never in class 2 (its curGenAt is zero, so Established is
// false), and it is not in class 1 either (it has an authenticated peer), so a
// re-initiation in flight is protected.
//
// Supersede (forward mode only, on the serve ticker). In -forward mode the
// gateway enforces ONE ACTIVE SESSION PER CLIENT STATIC KEY: the hub binds a
// key to one inner IPv4 address, and forwardTable.learn hands that address to
// the newest session of the key on its first uplink packet, so an older session
// of the same key can carry nothing back to its client. Such an older session
// is retired once the newer one is CONFIRMED USABLE: it has established its
// current generation, it has opened at least one authenticated message AFTER
// that establishment (so its post-handshake keys are known to work end to end,
// not merely assembled), and it owns the key's inner address in the forwarding
// table. This policy keys on the static identity only; it does not separate two
// independently identified devices, which carry distinct keys and distinct
// inner addresses and never supersede each other.
//
// # Atomicity
//
// Selection reads each session through one coherent snapshot (ReclaimView, taken
// under the driver lock). Under-pressure reclaim commits with RetireIfQuiet,
// which re-checks the snapshot's sequence under that same lock and ends the
// session only if it has not moved, so an authenticated receive, a first
// authenticated handshake, or a fresh re-initiation between selection and commit
// refuses the retirement. Supersede commits with session.CommitSupersede, which
// holds BOTH the victim's and the replacement's driver locks across the whole
// decision: the replacement's current validity (same peer, same generation as
// selected, established, confirmed usable; its traffic does not matter) and the
// victim's selected sequence and ordering are checked, and the victim is
// terminated, with neither session able to transition in between. The commit
// also requires the replacement to still hold its own slot in s.peers.
// Removal from the table and the driver teardown therefore cannot race a receive
// or a re-initiation on either session.
//
// # Bounded accounting
//
// A retired session is removed from s.peers at once, so a new client can take
// the freed slot immediately, but its pipe, loop, device and goroutines live on
// until Loop.Run returns and its inbox lives until releasePeer closes the pipe.
// Those are tracked in s.retiring and bounded by retirementAllowance: reclaim
// refuses (and the new client is refused, as before) rather than let the retiring
// population grow without limit, and the installer memory bill carries
// retirementAllowance sessions at their fixed-plus-inbox cost. releasePeer frees
// a reservation only after the resources are closed, under a completion-ownership
// contract (see releasePeer); closeAll drains s.retiring and reports any teardown
// that did not complete, so a session removed from s.peers is never orphaned.

// reclaimQuietProbeLifetimes is how many probe ceilings (session Probe.Max) of
// authenticated silence make an established session reclaimable under pressure.
// Two, because one ceiling can pass on a healthy path when a single PONG is
// lost.
const reclaimQuietProbeLifetimes = 2

// retirementAllowance bounds how many removed-but-not-yet-torn-down sessions may
// exist at once. It is small because teardown is prompt (RetireIfQuiet has
// already wiped the session's keys, windows and queues; only the pipe, loop,
// device and goroutines remain until Loop.Run returns), and it is billed as
// that many extra sessions in the installer memory formula and Round K test.
const retirementAllowance = 4

// slotView pairs a coherent driver snapshot with the table identity needed to
// commit a retirement against it.
type slotView struct {
	ps   *peerSession
	addr netip.AddrPort
	tcp  bool
	view session.ReclaimView
}

func viewOfSlot(addr netip.AddrPort, ps *peerSession) (slotView, bool) {
	if ps == nil || ps.loop == nil {
		return slotView{}, false
	}
	d := ps.loop.Session()
	if d == nil {
		return slotView{}, false
	}
	return slotView{ps: ps, addr: addr, tcp: ps.pipe == nil, view: d.ReclaimView()}, true
}

// totalSlotsLocked includes sessions under construction so UDP and TCP share
// one ceiling, even while both ingress paths are building sessions.
func (s *server) totalSlotsLocked() int {
	return len(s.peers) + len(s.tcpPeers) + s.building
}

func (s *server) holdsSlotLocked(v slotView) bool {
	if v.tcp {
		_, ok := s.tcpPeers[v.ps]
		return ok
	}
	return s.peers[v.addr] == v.ps
}

func (s *server) deleteSlotLocked(v slotView) {
	if v.tcp {
		delete(s.tcpPeers, v.ps)
	} else {
		delete(s.peers, v.addr)
	}
}

// slotViews snapshots the table under s.mu and reads each session's coherent
// view after releasing it, so the read loop's known() is never held behind a
// walk of every session's lock.
func (s *server) slotViews() []slotView {
	type entry struct {
		addr netip.AddrPort
		ps   *peerSession
	}
	s.mu.Lock()
	entries := make([]entry, 0, len(s.peers)+len(s.tcpPeers))
	for addr, ps := range s.peers {
		entries = append(entries, entry{addr, ps})
	}
	for ps := range s.tcpPeers {
		entries = append(entries, entry{ps.remoteAddrPort(), ps})
	}
	s.mu.Unlock()
	views := make([]slotView, 0, len(entries))
	for _, e := range entries {
		if v, ok := viewOfSlot(e.addr, e.ps); ok {
			views = append(views, v)
		}
	}
	return views
}

type reclaimClass int

const (
	notReclaimable reclaimClass = iota
	reclaimQuiet                // established this generation, silent past the threshold
	reclaimFailed               // terminal, closing, or unauthenticated half-open
)

func classifySlot(v session.ReclaimView, now time.Time) reclaimClass {
	switch {
	case v.State.Terminal() || v.State == session.StateClosing:
		return reclaimFailed
	case !v.Established:
		// This generation has not established. A session with no authenticated
		// peer that has already been handed something it could not open can only
		// wait out its handshake budget, so it is reclaimable. One with an
		// authenticated peer is a key holder completing a handshake (a first
		// handshake or a fresh re-initiation) and is protected. One with nothing
		// delivered yet may be a real client's initiation still in the inbox.
		if !v.Authenticated && v.Unopenable > 0 {
			return reclaimFailed
		}
		return notReclaimable
	default:
		last := quietSince(v)
		if v.ProbeMax > 0 && now.Sub(last) >= reclaimQuietProbeLifetimes*v.ProbeMax {
			return reclaimQuiet
		}
		return notReclaimable
	}
}

// quietSince is the instant a reclaim measures silence from: the last
// authenticated receive, or this generation's establishment if nothing has
// opened since.
func quietSince(v session.ReclaimView) time.Time {
	if v.LastAuthRecv.After(v.CurGenAt) {
		return v.LastAuthRecv
	}
	return v.CurGenAt
}

// pickReclaimVictim applies the pressure rule: any failed session first, then
// the established session that has been silent longest past the threshold.
func pickReclaimVictim(views []slotView, now time.Time) (slotView, bool) {
	var best slotView
	bestClass := notReclaimable
	for _, v := range views {
		c := classifySlot(v.view, now)
		if c == notReclaimable {
			continue
		}
		if c > bestClass || (c == bestClass && c == reclaimQuiet && quietSince(v.view).Before(quietSince(best.view))) {
			best, bestClass = v, c
		}
	}
	return best, bestClass != notReclaimable
}

// confirmedUsable reports whether a session's current generation has proven its
// post-handshake keys work end to end: it is established and it has opened an
// authenticated message strictly AFTER establishing. The responder counts as
// established when the post-quantum ciphertext is ASSEMBLED, before the client
// is known to hold it, so establishment alone is not proof a replacement can
// carry the client's traffic.
func confirmedUsable(v session.ReclaimView) bool {
	return v.Established && v.LastAuthRecv.After(v.CurGenAt)
}

// supersedePair is one supersede decision: old is the older session to retire,
// newer is the replacement whose validity is the precondition. Both the old
// eligibility and the new validity are RE-checked at the commit point, so this
// pair is a proposal, never a decision.
type supersedePair struct {
	old   slotView
	newer slotView
}

// supersedePairs proposes retirements under the one-active-session-per-key
// policy: for every client static key whose NEWEST established session is
// confirmed usable and owns forwarding, each strictly older established session
// of that key is paired with that newer session. The newer session's identity
// and generation travel in the pair so the commit can revalidate it: selecting
// A because B is a valid replacement is meaningless if B stops being one before
// A is retired.
func supersedePairs(views []slotView, ownsForwarding func(v slotView) bool) []supersedePair {
	newest := make(map[string]slotView)
	for _, v := range views {
		if len(v.view.PeerStatic) == 0 || !v.view.Established {
			continue
		}
		if v.view.State != session.StateEstablished && v.view.State != session.StateRekeying {
			continue
		}
		k := string(v.view.PeerStatic)
		if cur, ok := newest[k]; !ok || v.view.CurGenAt.After(cur.view.CurGenAt) {
			newest[k] = v
		}
	}
	var out []supersedePair
	for _, v := range views {
		if len(v.view.PeerStatic) == 0 || !v.view.Established {
			continue
		}
		n, ok := newest[string(v.view.PeerStatic)]
		if !ok || n.ps == v.ps || !v.view.CurGenAt.Before(n.view.CurGenAt) {
			continue
		}
		if !confirmedUsable(n.view) || !ownsForwarding(n) {
			continue
		}
		out = append(out, supersedePair{old: v, newer: n})
	}
	return out
}

// retireSlot commits a retirement atomically. It refuses, doing nothing, when
// the session no longer holds v.addr (a rebind or releasePeer got there first),
// when the retiring population is already at its bound, or when the driver's
// sequence has moved since the snapshot (an authenticated receive or a fresh
// re-initiation between selection and here). On success the session is removed
// from s.peers, its slot is free, it is tracked in s.retiring, and its context
// is cancelled so Loop.Run returns and releasePeer tears it down.
func (s *server) retireSlot(v slotView) bool {
	s.mu.Lock()
	ok := s.retireLocked(v)
	s.mu.Unlock()
	if ok {
		// The session is wiped and out of the table. Cancel its context so Run
		// returns promptly; releasePeer runs on the Run goroutine and, only
		// after it has closed the loop, pipe and device, frees the retirement
		// reservation. stop() does not wait, so the read loop is never blocked
		// on teardown.
		v.ps.stop()
	}
	return ok
}

// retireLocked is the atomic commit body; the caller holds s.mu. It refuses,
// doing nothing, when the session no longer holds v.addr (a rebind or
// releasePeer got there first), when the retirement reservation is already at
// its bound, or when the driver's sequence has moved since the snapshot (an
// authenticated receive, a first authenticated handshake, or a fresh
// re-initiation between selection and here). On success the session is removed
// from s.peers and RESERVED in s.retiring; the reservation is held until
// releasePeer confirms the loop, pipe and device are closed.
func (s *server) retireLocked(v slotView) bool {
	if !s.holdsSlotLocked(v) {
		return false
	}
	if _, already := s.retiring[v.ps]; !already && len(s.retiring) >= retirementAllowance {
		return false
	}
	// RetireIfQuiet re-checks the snapshot's sequence under the driver lock and
	// ends the session only if nothing has moved. The driver lock is always
	// taken after s.mu here and in status(), never the other way.
	if !v.ps.loop.Session().RetireIfQuiet(v.view.Seq) {
		return false
	}
	s.deleteSlotLocked(v)
	if s.retiring == nil {
		s.retiring = make(map[*peerSession]struct{})
	}
	s.retiring[v.ps] = struct{}{}
	return true
}

// retireSupersededOld commits one supersede proposal. The whole decision is
// synchronized: it holds s.mu (covering the forwarding-ownership check and the
// table bookkeeping) and, inside session.CommitSupersede, both drivers' locks
// (covering the replacement's validity and the victim's eligibility and the
// victim's termination). So the replacement cannot re-initiate, terminate or
// receive, the victim cannot re-initiate or receive, and forwarding ownership
// cannot be read stale, in the window between the check and the irreversible
// termination.
//
// The victim is retired against its SELECTED sequence, not a refreshed one: if
// the victim changed at all since selection (a fresh same-key initiation, a
// receive, an establishment) its genSeq has moved and the commit is refused
// rather than terminating a session that must be reclassified.
func (s *server) retireSupersededOld(pair supersedePair, owns func(slotView) bool) bool {
	s.mu.Lock()
	if !s.holdsSlotLocked(pair.old) {
		s.mu.Unlock()
		return false
	}
	// The replacement must still hold its own slot. releasePeer removes a
	// session from s.peers BEFORE it closes that session's loop and device, and
	// the forwarding entry is forgotten only on device close, so in that window
	// a live driver and a true ownership check can belong to a replacement that
	// is already leaving (Round Q Turn 4, OI-Q2).
	if !s.holdsSlotLocked(pair.newer) {
		s.mu.Unlock()
		return false
	}
	if _, already := s.retiring[pair.old.ps]; !already && len(s.retiring) >= retirementAllowance {
		s.mu.Unlock()
		return false
	}
	// Forwarding ownership of the replacement, read fresh under s.mu (the
	// forwarding table takes its own lock, always after s.mu, never before).
	if !owns(pair.newer) {
		s.mu.Unlock()
		return false
	}
	// The atomic cross-driver commit: replacement still valid AND victim still
	// eligible at its selected sequence, then terminate the victim, all under
	// both drivers' locks.
	if !session.CommitSupersede(
		pair.old.ps.loop.Session(), pair.newer.ps.loop.Session(),
		pair.old.view.Seq, pair.newer.view.CurGenID, pair.newer.view.PeerStatic,
	) {
		s.mu.Unlock()
		return false
	}
	s.deleteSlotLocked(pair.old)
	if s.retiring == nil {
		s.retiring = make(map[*peerSession]struct{})
	}
	s.retiring[pair.old.ps] = struct{}{}
	s.mu.Unlock()
	pair.old.ps.stop()
	return true
}

// reclaimSlot is sessionFor's pressure path. It reports whether the table now
// has room.
func (s *server) reclaimSlot(now time.Time) bool {
	views := s.slotViews()
	victim, ok := pickReclaimVictim(views, now)
	if ok && s.retireSlot(victim) {
		s.reclaimed.Add(1)
		if c := s.reclaimLogs.Add(1); c <= maxRefusalLogs {
			fmt.Fprintf(os.Stderr, "winn3-gateway: session table full; reclaimed a %s session "+
				"(state %s, quiet %s) for a new admissible initiation\n",
				reclaimClassName(classifySlot(victim.view, now)), victim.view.State,
				now.Sub(quietSince(victim.view)).Round(time.Second))
		}
	}
	s.mu.Lock()
	room := s.totalSlotsLocked() < s.maxSessions
	s.mu.Unlock()
	return room
}

// reclaimSupersededSessions is the ticker half. It runs only with -forward,
// where the one-active-session-per-key policy holds. Ownership is read from the
// registry and the forwarding table: a key's newest session supersedes only
// once it owns that key's inner address, so the downlink has moved.
func (s *server) reclaimSupersededSessions() int {
	if !s.forward || s.peerRegistry == nil || s.table == nil {
		return 0
	}
	return s.supersedeOnce(func(v slotView) bool {
		inner, ok := s.peerRegistry.innerForPeer(v.view.PeerStatic)
		if !ok {
			return false
		}
		loop, ok := s.table.lookup(inner)
		return ok && loop == v.ps.loop
	})
}

// supersedeOnce retires every session superseded under the given
// forwarding-ownership predicate. It is the body of reclaimSupersededSessions,
// separated so a test can supply ownership directly on a host where the Linux
// forwarding device does not run.
//
// Each proposal is committed by retireSupersededOld, which re-reads forwarding
// ownership under s.mu and revalidates the replacement and the victim inside
// session.CommitSupersede under both drivers' locks, so a replacement that
// re-initiated, terminated, or lost forwarding between selection and the commit
// does not cause the old, possibly still-working session to be retired.
func (s *server) supersedeOnce(owns func(slotView) bool) int {
	n := 0
	for _, pair := range supersedePairs(s.slotViews(), owns) {
		if s.retireSupersededOld(pair, owns) {
			n++
		}
	}
	if n > 0 {
		s.superseded.Add(uint64(n))
		if c := s.reclaimLogs.Add(1); c <= maxRefusalLogs {
			fmt.Fprintf(os.Stderr, "winn3-gateway: retired %d session(s) superseded by a newer "+
				"confirmed session of the same client key\n", n)
		}
	}
	return n
}

// awaitRetiring closes and waits out every session still in s.retiring. It is
// called from closeAll so a retired session is never orphaned by shutdown. It
// reports how many teardowns completed and how many timed out, so a caller can
// tell a proven drain from an abandoned wait rather than assuming success.
func (s *server) awaitRetiring() (drained, timedOut int) {
	s.mu.Lock()
	pending := make([]*peerSession, 0, len(s.retiring))
	for ps := range s.retiring {
		pending = append(pending, ps)
	}
	s.mu.Unlock()
	for _, ps := range pending {
		if ps.stop != nil {
			ps.stop()
		}
		if ps.done == nil {
			timedOut++
			continue
		}
		select {
		case <-ps.done:
			drained++
		case <-time.After(2 * time.Second):
			timedOut++
		}
	}
	return drained, timedOut
}

// Per-key session cap.
//
// Every rule above frees a slot only from a session that is dead, half-open,
// silent for two probe ceilings, or superseded by a CONFIRMED newer session of
// the same key. None of them bounds how many slots one enrolled key may hold
// at once: a client that completes a handshake from a fresh source port, never
// sends an uplink packet (so no session of its key ever owns forwarding and
// supersede never fires) and answers the gateway's liveness probes (so no
// session is ever quiet) holds that slot for as long as it likes, and 64 such
// handshakes from one free-tier device hold every slot of a node. Every other
// client of that node is then refused in silence, which under this threat
// model reads as censorship. winn3/gateway's table has carried
// DefaultMaxSessionsPerClient = 4 for exactly this reason; this binary did not
// use that table and had no equivalent.
//
// maxSessionsPerKey is enforced twice. At ADMISSION, the registry's accept
// callback (peerRegistry.admit, run inside core.ReadInitiation under the
// handshaking driver's lock) refuses the handshake outright when the key
// already holds the cap, so the refused initiation never becomes an
// authenticated session: it stays a half-open the pressure rule reclaims at
// once (classifySlot, reclaimFailed). On the serve TICKER, enforcePerKeyCap
// rebuilds the per-key count from the table and retires, oldest first, any
// surplus that slipped in between two rebuilds. The count map is guarded by
// keyMu alone and is never read or written while s.mu or a driver lock is
// held, so the accept callback (which runs under a driver lock) cannot form a
// lock cycle with CommitSupersede (s.mu, then two driver locks).
//
// Four is winn3/gateway's number and is comfortably above what a real client
// needs: a phone that re-handshakes from a new port while its old session
// lingers holds two, and the old one is superseded or reclaimed within seconds.
const maxSessionsPerKey = 4

// keyMayOpenSession is the accept-time half of the cap. It runs inside the
// handshaking driver's lock, so it takes keyMu and nothing else. The count it
// reads is the ticker's last rebuild plus every acceptance since, so a burst of
// handshakes inside one tick is bounded too; a retransmitted initiation of one
// session counts again until the next rebuild, which is why the cap is four and
// not one.
func (s *server) keyMayOpenSession(peer []byte) bool {
	if len(peer) != 32 {
		return false
	}
	var k [32]byte
	copy(k[:], peer)
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if s.keySessions[k] >= maxSessionsPerKey {
		return false
	}
	if s.keySessions == nil {
		s.keySessions = make(map[[32]byte]int)
	}
	s.keySessions[k]++
	return true
}

// enforcePerKeyCap is the ticker half: it rebuilds the per-key count from the
// live table and retires, oldest admission first, every session a key holds
// beyond maxSessionsPerKey. It reads each session through slotViews (driver
// locks taken one at a time, outside s.mu) and publishes the count under keyMu
// only. It returns how many sessions it retired.
func (s *server) enforcePerKeyCap() int {
	views := s.slotViews()
	byKey := make(map[[32]byte][]slotView)
	for _, v := range views {
		if len(v.view.PeerStatic) != 32 {
			continue
		}
		var k [32]byte
		copy(k[:], v.view.PeerStatic)
		byKey[k] = append(byKey[k], v)
	}
	counts := make(map[[32]byte]int, len(byKey))
	retired := 0
	for k, group := range byKey {
		counts[k] = len(group)
		if len(group) <= maxSessionsPerKey {
			continue
		}
		sort.SliceStable(group, func(i, j int) bool {
			return group[i].ps.admittedAt.Before(group[j].ps.admittedAt)
		})
		for _, v := range group[:len(group)-maxSessionsPerKey] {
			if s.retireSurplus(v) {
				retired++
				counts[k]--
			}
		}
	}
	s.keyMu.Lock()
	s.keySessions = counts
	s.keyMu.Unlock()
	if retired > 0 {
		s.reclaimed.Add(uint64(retired))
		if c := s.reclaimLogs.Add(1); c <= maxRefusalLogs {
			fmt.Fprintf(os.Stderr, "winn3-gateway: retired %d session(s) held beyond the %d-per-key cap\n",
				retired, maxSessionsPerKey)
		}
	}
	return retired
}

// retireSurplus removes one over-cap session from the table and cancels its
// loop, without a CLOSE, under the same retirement reservation every other
// retirement uses. It refuses when the session no longer holds its slot or the
// reservation is at its bound; the next tick tries again. The teardown is the
// one stopRevokedSession and advanceEgressTeardown already use: Loop.Run
// returns on the cancelled context and releasePeer frees the reservation after
// the loop, pipe and device are closed.
func (s *server) retireSurplus(v slotView) bool {
	s.mu.Lock()
	if !s.holdsSlotLocked(v) {
		s.mu.Unlock()
		return false
	}
	if _, already := s.retiring[v.ps]; !already && len(s.retiring) >= retirementAllowance {
		s.mu.Unlock()
		return false
	}
	s.deleteSlotLocked(v)
	if s.retiring == nil {
		s.retiring = make(map[*peerSession]struct{})
	}
	s.retiring[v.ps] = struct{}{}
	s.mu.Unlock()
	if v.ps.stop != nil {
		v.ps.stop()
	}
	return true
}

func reclaimClassName(c reclaimClass) string {
	switch c {
	case reclaimFailed:
		return "failed"
	case reclaimQuiet:
		return "silent"
	}
	return "live"
}
