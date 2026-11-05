package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// This file is the gateway's OWN forwarding table -- the mechanism
// driver.Config.Tun's doc names ("a gateway-side session whose inner side is
// the gateway's own forwarding table") and that nothing before 2026-08-12
// actually built. See driver.Loop.SendInner's doc for the full argument for
// why winn3/tun cannot be that mechanism: its address validator is written,
// on purpose, to make an endpoint "structurally incapable of acting as a
// router for anyone else's traffic" (winn3/tun/doc.go), which is exactly
// backwards from what a gateway that must hand an arbitrary internet reply
// back to the correct one of many peers needs.
//
// The shape here is the plainest one that is still correct: a NAT gateway's
// forwarding table is normally keyed by (protocol, inner addr:port, outer
// addr:port); this one is keyed by inner ADDRESS ALONE, because a whole
// session -- not a single flow -- is what a client's traffic must return to,
// and because nothing in this design assigns more than one inner address per
// session. If the control plane ever assigns two clients the same inner
// address (a provisioning error entirely outside this file's authority: see
// -forward-cidr's flag help) the two sessions cannot both be routed to
// correctly and the table says so via Collisions rather than silently
// misdelivering one session's replies into the other's tunnel forever.
//
// # Platform split
//
// This file is portable and carries no build tag: forwardTable,
// gatewayForwardDevice and the small ipv4SourceDestination parser below do no
// I/O and need no kernel interface, so they are exercised directly by
// forward_test.go on any OS. Only the shared kernel descriptor itself
// (sharedGatewayTun, forward_linux.go / forward_other.go) is platform-specific,
// and gatewayForwardDevice reaches it through the innerWriter interface below
// rather than through the concrete type, which is what makes that possible.

// innerWriter is the write half of the shared kernel device, seen from a
// per-session gatewayForwardDevice.
//
// Narrow on purpose: a per-session device only ever WRITES to the shared
// descriptor (the forward direction, client -> internet). It never reads
// from it -- see gatewayForwardDevice.ReadPacket's doc for why that half is
// permanently idle here, and forward_linux.go's sharedGatewayTun.run for
// where the return direction actually lives. *sharedGatewayTun satisfies
// this on every platform, including the refusal stub on non-Linux, so a
// caller that somehow reaches it after ignoring newSharedGatewayTun's error
// gets a device error rather than a nil-pointer panic. The interface is also
// what lets forward_test.go exercise gatewayForwardDevice with a fake writer
// and no real TUN device at all.
type innerWriter interface {
	write(pkt []byte) (int, error)
}

// closableDevice is tun.Device plus the lifecycle method every device
// backend THIS BINARY builds actually has, even though tun.Device itself
// declares none -- its own doc explains that omission is about winn3/tun
// staying neutral across hosts that own a device's lifecycle differently, not
// a claim that no host ever needs one. Both backends here do: *reflector
// (reflect.go, unmodified) and *gatewayForwardDevice below.
type closableDevice interface {
	tun.Device
	Close() error
}

var (
	_ closableDevice = (*reflector)(nil)
	_ closableDevice = (*gatewayForwardDevice)(nil)
)

// forwardTable is the address -> session index. One instance is shared by
// every session the gateway process is currently serving in -forward mode.
//
// # Eviction
//
// There is no TTL and no idle sweep in this type. An address stays mapped
// until forget runs for the *driver.Loop that currently owns it, or learn
// confirms that the registry no longer authorizes that owner for the address.
// forget is called from gatewayForwardDevice.Close, which runs when the owning session
// is torn down. server.releasePeer is what tears a session down when its
// Loop.Run returns, so a dead session cannot keep an inner address (the
// 2026-08-12 measurement: collisions 1, forgotten 0, 10.64.0.2 still held
// by phase A's session object) after the session itself has ended.
//
// A mapping is not dropped just because the session has gone quiet: liveness
// is the session layer's job (DefaultMaxLostProbes x DefaultProbeMax after
// the silence timer). Once that layer terminates the session, Run returns,
// releasePeer Closes the device, forget runs.
//
// # Collisions
//
// learn refuses to replace an owner still authorized for the address. Such
// collisions increment Collisions, but the first loop keeps the mapping. Same-loop
// relearn is not a collision. This is a security boundary: replacing the owner
// would route the first client's replies into the second client's authenticated
// session.
type forwardTable struct {
	registry *peerRegistry
	// isolation is the OI-5 uplink destination rule (forward_isolation.go),
	// set once in main beside registry, before any session exists, and nil in
	// tests that build a bare table. WritePacket reads it without a lock.
	isolation *forwardIsolation
	mu        sync.Mutex
	byAddr    map[netip.Addr]*driver.Loop

	// peers caches, per address, the peer static key of the loop learn
	// installed there, so lookup (once per downlink packet) does not take that
	// session's Driver lock through PeerStatic. It is safe to cache because a
	// Driver's peer key never changes once set: admitReinitiation refuses an
	// initiation from any other key, and learn runs only for an established,
	// registry-validated session (WritePacket). lookup uses an entry only
	// while it names the loop byAddr still holds, and falls back to
	// PeerStatic otherwise.
	peers map[netip.Addr]cachedPeer

	learned         uint64
	forgotten       uint64
	collisions      uint64
	freeDroppedUp   atomic.Uint64
	freeDroppedDown atomic.Uint64

	// refused counts forward-direction refusals by class; see
	// forwardRefusal. They replace the per-packet log lines that used to
	// name the peer key and addresses.
	refused [forwardRefusalClasses]uint64
}

// forwardRefusal is one class of forward-direction refusal. WritePacket
// counts every occurrence on the shared forwardTable and describes each class
// at most once per session, so operators keep the failure rate (status
// forward.table) and a first sighting per session (stderr) without the
// journal holding one line per packet.
//
// The lines carry no peer key, inner address or destination. The key maps to
// an account in the hub registry, the registry binds each key to one inner
// address, and together with the destination one such line per packet was a
// record of which account reached which internet address. Measured on the
// fleet 2026-09-24 (lane L25): 13,333 such lines in one node's syslog.
type forwardRefusal uint8

const (
	refusalPeerUnauthorized forwardRefusal = iota
	refusalSourceMismatch
	refusalSourceChanged
	refusalSourceOwned
	refusalWriteFailed
	// refusalIntraSubnet is OI-5's class: the packet's destination is one this
	// gateway does not forward (forwardIsolation's doc lists them), or the
	// packet is not IPv4 at all.
	refusalIntraSubnet
	forwardRefusalClasses
)

// countRefusal records one refusal of class c and returns the running total
// for that class.
func (t *forwardTable) countRefusal(c forwardRefusal) uint64 {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.refused[c]++
	return t.refused[c]
}

func newForwardTable() *forwardTable {
	return &forwardTable{byAddr: make(map[netip.Addr]*driver.Loop), peers: make(map[netip.Addr]cachedPeer)}
}

// cachedPeer is one forwardTable.peers entry.
type cachedPeer struct {
	loop *driver.Loop
	peer []byte
}

// learn records that addr's traffic belongs to loop. It returns false for an
// invalid claim or when another loop still owns addr under registry authority.
// Close removes dead owners; learn also evicts owners whose registry authority
// for addr has ended, without allowing a live authorized owner's displacement.
func (t *forwardTable) learn(addr netip.Addr, loop *driver.Loop) bool {
	if !addr.IsValid() || loop == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if existing, ok := t.byAddr[addr]; ok && existing != loop {
		if t.registry == nil || existing == nil || existing.Session() == nil || loop.Session() == nil {
			t.collisions++
			return false
		}
		samePeer := bytes.Equal(existing.Session().PeerStatic(), loop.Session().PeerStatic())
		if !samePeer {
			currentAddr, authorized := t.registry.innerForPeer(existing.Session().PeerStatic())
			if authorized && currentAddr == addr {
				t.collisions++
				return false
			}
		}
		delete(t.byAddr, addr)
		delete(t.peers, addr)
		t.forgotten++
	}
	t.byAddr[addr] = loop
	if sess := loop.Session(); sess != nil {
		if peer := sess.PeerStatic(); len(peer) > 0 {
			t.peers[addr] = cachedPeer{loop: loop, peer: bytes.Clone(peer)}
		}
	}
	t.learned++
	return true
}

// forget removes addr's mapping, but ONLY if it still points at loop.
//
// The guard is the whole reason this is not a bare delete: a session closing
// out runs concurrently with every other session's traffic, and without the
// guard a session that is shutting down could evict a mapping a NEWER
// session already relearned for the same address after a legitimate
// reconnect -- turning an orderly close into the same misdelivery
// Collisions exists to flag, except silent, because nothing would count it.
func (t *forwardTable) forget(addr netip.Addr, loop *driver.Loop) {
	t.mu.Lock()
	if t.byAddr[addr] == loop {
		delete(t.byAddr, addr)
		delete(t.peers, addr)
		t.forgotten++
	}
	t.mu.Unlock()
}

// lookup returns the session currently authorized for addr, if any. Registry
// checks run without the table lock, since a refresh can read from disk.
func (t *forwardTable) lookup(addr netip.Addr) (*driver.Loop, bool) {
	return t.lookupPacket(addr, 0)
}

// lookupPacket applies downlink policing before encryption or enqueueing.
func (t *forwardTable) lookupPacket(addr netip.Addr, n int) (*driver.Loop, bool) {
	loop, ok, _ := t.lookupPacketDecision(addr, n)
	return loop, ok
}

// lookupPacketDecision is lookupPacket with a third result that tells a
// bandwidth refusal from an unknown or unauthorized destination, so the
// dispatcher can count a cap drop as one and not as the other.
func (t *forwardTable) lookupPacketDecision(addr netip.Addr, n int) (*driver.Loop, bool, bool) {
	t.mu.Lock()
	loop, ok := t.byAddr[addr]
	cached, hit := t.peers[addr]
	t.mu.Unlock()
	if !ok || loop == nil {
		return nil, false, false
	}
	if t.registry != nil {
		sess := loop.Session()
		if sess == nil {
			return nil, false, false
		}
		var peer []byte
		if hit && cached.loop == loop {
			peer = cached.peer
		} else {
			peer = sess.PeerStatic()
		}
		binding, allowed := t.registry.policyForPeer(peer)
		if !allowed || binding.addr != addr {
			return nil, false, false
		}
		if n > 0 && !binding.bandwidth.allow(n, true) {
			t.freeDroppedDown.Add(1)
			return nil, false, true
		}
	}
	return loop, true, false
}

// forwardTableStats is a snapshot for the status document.
type forwardTableStats struct {
	Size       int    `json:"size"`
	Learned    uint64 `json:"learned"`
	Forgotten  uint64 `json:"forgotten"`
	Collisions uint64 `json:"collisions"`

	// Forward-direction refusals by class (forwardRefusal). The first two
	// are validatePeerSource's: the session's peer is not in the registry,
	// or the packet's inner source is not the one the registry binds to it.
	// SourceOwned is WritePacket's share of Collisions. IntraSubnet is OI-5's
	// destination refusal (forwardIsolation) plus non-IPv4 packets.
	PeerUnauthorized uint64 `json:"peer_unauthorized"`
	SourceMismatch   uint64 `json:"source_mismatch"`
	SourceChanged    uint64 `json:"source_changed"`
	SourceOwned      uint64 `json:"source_owned"`
	WriteFailed      uint64 `json:"write_failed"`
	FreeDroppedUp    uint64 `json:"free_dropped_up"`
	FreeDroppedDown  uint64 `json:"free_dropped_down"`
	IntraSubnet      uint64 `json:"intra_subnet"`
}

// gatewayForwardStatus is the -forward-specific half of serveStatus,
// combining the shared device's own counters (forward_linux.go /
// forward_other.go) with this table's. It is nil in serveStatus unless
// -forward is set; see serveStatus.Forward's doc for how to read it.
type gatewayForwardStatus struct {
	Device sharedGatewayTunStats `json:"device"`
	Table  forwardTableStats     `json:"table"`
}

func (t *forwardTable) Stats() forwardTableStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	return forwardTableStats{
		Size:       len(t.byAddr),
		Learned:    t.learned,
		Forgotten:  t.forgotten,
		Collisions: t.collisions,

		PeerUnauthorized: t.refused[refusalPeerUnauthorized],
		SourceMismatch:   t.refused[refusalSourceMismatch],
		SourceChanged:    t.refused[refusalSourceChanged],
		SourceOwned:      t.refused[refusalSourceOwned],
		WriteFailed:      t.refused[refusalWriteFailed],
		FreeDroppedUp:    t.freeDroppedUp.Load(),
		FreeDroppedDown:  t.freeDroppedDown.Load(),
		IntraSubnet:      t.refused[refusalIntraSubnet],
	}
}

// ipv4SourceDestination extracts an IPv4 packet's source and destination
// addresses, bounds-checked and nothing more.
//
// It exists so the same two lines are not duplicated between the forward
// direction (gatewayForwardDevice.WritePacket, which trusts an ALREADY
// winn3/tun-validated packet) and the return direction
// (sharedGatewayTun.run, which trusts NOTHING -- it reads raw bytes straight
// off the kernel). It is deliberately not a full parser: winn3/tun's own
// parsePacket already is the strict one, and ip.go's comment on why a
// lenient parser is a parsing differential is the reason this one makes no
// claim beyond "these are the address-field bytes of what looks like an
// IPv4 header". Nothing downstream treats that claim as validation --
// forgetting/looking up in forwardTable is the only thing malformed input
// here can ever cause, never a delivery, because a lookup that misses is a
// drop by construction (see sharedGatewayTun.run).
//
// reflect.go's reflector parses the same two fields inline rather than
// calling this. That is a small, deliberate duplication instead of a new
// dependency edge from the untouched, separately-pinned reflector path onto
// this one; see this file's own package doc.
func ipv4SourceDestination(pkt []byte) (src, dst netip.Addr, ok bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, netip.Addr{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || ihl > len(pkt) {
		return netip.Addr{}, netip.Addr{}, false
	}
	src = netip.AddrFrom4([4]byte(pkt[12:16]))
	dst = netip.AddrFrom4([4]byte(pkt[16:20]))
	return src, dst, true
}

// errGatewayForwardDeviceClosed is ReadPacket's unblocking error, matching
// the shape errReflectorClosed already establishes in reflect.go.
var errGatewayForwardDeviceClosed = errors.New("gateway forward device closed")

var (
	errGatewayForwardDeviceUnbound = errors.New("gateway forward device has no bound session")
	errGatewayInnerSourceChanged   = errors.New("gateway session changed its claimed inner source")
	errGatewayInnerSourceOwned     = errors.New("gateway inner source is owned by another live session")
	errGatewayPeerUnauthorized     = errors.New("gateway session peer is not in the authorization registry")
	errGatewayInnerSourceMismatch  = errors.New("gateway inner source does not match the authenticated peer")
	errGatewayDestinationRefused   = errors.New("gateway does not forward to that destination")
	errGatewayForwardNotIPv4       = errors.New("gateway forwards IPv4 only")
)

// gatewayForwardDevice is the per-session tun.Device that backs the FORWARD
// direction (client -> internet) when -forward is enabled. It replaces the
// reflector for that one direction only; the return direction is not a
// tun.Device operation at all -- see ReadPacket below and
// driver.Loop.SendInner.
//
// # The forward direction
//
// WritePacket is called by winn3/tun's Tunnel.deliver, which validates
// FIRST, always (tun.go: "the ONLY place in this package that writes to the
// host device, and it validates first"). By the time this method runs, pkt
// has already passed winn3/tun/ip.go's inbound rule with AcceptTransit set:
// martian source and destination are refused. AcceptTransit does not bind the
// source address to the session, so this layer must: the first authenticated
// packet claims one address, later packets from this session must use that
// address, and another live session cannot replace its table entry. Only after
// those checks is pkt handed, byte for byte, to the kernel. From there the
// kernel's own routing and NAT -- configured by the install script, never by
// this process -- carry it exactly as they would for any other host the TUN
// interface puts on that route.
//
// # The return direction
//
// ReadPacket never returns anything. PumpOutbound (winn3/tun/tun.go) would
// call winn3/tun's Outbound validator on whatever it read, which requires the
// packet's SOURCE to equal this session's single fixed "ours" address
// (ip.go: "the source must be exactly an assigned address") -- correct for a
// point-to-point tunnel, and never true of a real reply, which is sourced
// from whatever the client's original packet was addressed to. So this
// device's read side is permanently idle by design, and the return path
// runs entirely outside it: sharedGatewayTun.run reads the shared kernel
// descriptor directly, looks up the destination address in the SAME
// forwardTable this method writes to, and calls the owning session's
// Loop.SendInner, bypassing tun.Tunnel for that direction alone.
type gatewayForwardDevice struct {
	shared innerWriter
	table  *forwardTable
	mtu    int

	mu       sync.Mutex
	loop     *driver.Loop
	owned    netip.Addr
	registry *peerRegistry
	// described has bit c set once refusal class c was logged for this
	// session. Guarded by mu.
	described uint8

	// peerLoop and peer cache the bound session's peer static key for
	// WritePacket's per-packet authorization, so it does not take the
	// session's Driver lock through PeerStatic on every uplink packet. Safe
	// because a Driver's key never changes once set (admitReinitiation refuses
	// any other key) and a Loop's session never changes; the entry is used
	// only while peerLoop is the bound loop, and an empty key is never cached.
	// Guarded by mu.
	peerLoop *driver.Loop
	peer     []byte

	// pending counts this session's packets queued on the shared device and
	// not yet written. It moves only under -forward-async-write;
	// see forward_async.go and Close.
	pending atomic.Int64

	closeOnce sync.Once
	done      chan struct{}
}

// validatePeerSource returns the peer's registry binding after checking that
// the authenticated peer holds src. Its error is one of two fixed sentinels,
// which is what lets WritePacket print it; see forwardRefusal.
func (d *gatewayForwardDevice) validatePeerSource(peer []byte, src netip.Addr) (peerBinding, error) {
	if d.registry == nil {
		return peerBinding{}, nil
	}
	binding, allowed := d.registry.policyForPeer(peer)
	if !allowed {
		return peerBinding{}, errGatewayPeerUnauthorized
	}
	if src != binding.addr {
		return peerBinding{}, errGatewayInnerSourceMismatch
	}
	return binding, nil
}

// authorizesSource reports whether the registry currently authorizes this
// device's bound, authenticated session peer for the inner source src. It is
// the resolver's authorization check (see newResolverDevice), and it is the
// same predicate WritePacket applies: identity comes from the session, never
// from the packet.
func (d *gatewayForwardDevice) authorizesSource(src netip.Addr) bool {
	d.mu.Lock()
	loop := d.loop
	d.mu.Unlock()
	if loop == nil || d.registry == nil {
		return false
	}
	sess := loop.Session()
	if sess == nil {
		return false
	}
	_, err := d.validatePeerSource(sess.PeerStatic(), src)
	return err == nil
}

// allowSourcePacket covers the in-process UDP resolver, which bypasses the
// forward writer. Admission comes from the bound authenticated peer.
func (d *gatewayForwardDevice) allowSourcePacket(src netip.Addr, n int, down bool) bool {
	d.mu.Lock()
	loop := d.loop
	d.mu.Unlock()
	if loop == nil || d.registry == nil || loop.Session() == nil {
		return false
	}
	binding, ok := d.registry.policyForPeer(loop.Session().PeerStatic())
	if !ok || binding.addr != src {
		return false
	}
	if !binding.bandwidth.allow(n, down) {
		if down {
			d.table.freeDroppedDown.Add(1)
		} else {
			d.table.freeDroppedUp.Add(1)
		}
		return false
	}
	return true
}

// newGatewayForwardDevice builds a device with no session bound yet. See
// bind for why binding is a second step.
func newGatewayForwardDevice(shared innerWriter, table *forwardTable, mtu int, registries ...*peerRegistry) *gatewayForwardDevice {
	var registry *peerRegistry
	if len(registries) > 0 {
		registry = registries[0]
	}
	return &gatewayForwardDevice{shared: shared, table: table, mtu: mtu, registry: registry, done: make(chan struct{})}
}

// bind attaches the session this device belongs to.
//
// It is separate from construction because of an ordering constraint in
// newSession: the Device must exist before driver.NewGateway can build the
// *driver.Loop that owns it, so the Loop this device needs to learn addresses
// against cannot be known at construction time. bind is called once, by
// newSession, strictly before that session's Loop.Run goroutine starts --
// which is strictly before anything could call WritePacket -- so the mutex
// below is a defensive belt over an already-safe sequential ordering, not
// something a caller needs to race against.
func (d *gatewayForwardDevice) bind(loop *driver.Loop) {
	d.mu.Lock()
	d.loop = loop
	d.mu.Unlock()
}

// firstRefusalLocked reports whether refusal class c has not yet been
// described for this session, and marks it described. d.mu must be held.
func (d *gatewayForwardDevice) firstRefusalLocked(c forwardRefusal) bool {
	bit := uint8(1) << c
	if d.described&bit != 0 {
		return false
	}
	d.described |= bit
	return true
}

// WritePacket implements the forward direction. See the type doc.
//
// Its refusal diagnostics name the class and the running count only; see
// forwardRefusal for why they carry no key, inner address or destination.
func (d *gatewayForwardDevice) WritePacket(pkt []byte) (int, error) {
	src, _, ok := ipv4SourceDestination(pkt)
	if !ok {
		// OI-5: refused, never handed to the kernel. The tun validator stops
		// the family upstream (winn3/tun/ip.go familyAllowed); this consumer
		// does not depend on that. Counted with the destination refusals.
		d.mu.Lock()
		first := d.firstRefusalLocked(refusalIntraSubnet)
		d.mu.Unlock()
		if total := d.table.countRefusal(refusalIntraSubnet); first {
			fmt.Fprintf(os.Stderr, "winn3-gateway: forward refused a non-IPv4 packet len=%d "+
				"(first for this session; %d since start, see forward.table.intra_subnet)\n", len(pkt), total)
		}
		return 0, errGatewayForwardNotIPv4
	} else {
		d.mu.Lock()
		loop := d.loop
		if loop == nil {
			d.mu.Unlock()
			fmt.Fprintf(os.Stderr, "winn3-gateway: forward unbound loop\n")
			return 0, errGatewayForwardDeviceUnbound
		}
		var bandwidth *peerBandwidth
		if d.registry != nil {
			sess := loop.Session()
			if sess == nil {
				d.mu.Unlock()
				fmt.Fprintf(os.Stderr, "winn3-gateway: forward sess is nil\n")
				return 0, errGatewayPeerUnauthorized
			}
			peer := d.peer
			if d.peerLoop != loop || len(peer) == 0 {
				peer = sess.PeerStatic()
				if len(peer) > 0 {
					d.peerLoop, d.peer = loop, bytes.Clone(peer)
				}
			}
			if binding, err := d.validatePeerSource(peer, src); err != nil {
				class, counter := refusalPeerUnauthorized, "peer_unauthorized"
				if errors.Is(err, errGatewayInnerSourceMismatch) {
					class, counter = refusalSourceMismatch, "source_mismatch"
				}
				first := d.firstRefusalLocked(class)
				d.mu.Unlock()
				if total := d.table.countRefusal(class); first {
					fmt.Fprintf(os.Stderr, "winn3-gateway: forward validatePeerSource failed: err=%v "+
						"(first for this session; %d since start, see forward.table.%s)\n", err, total, counter)
				}
				return 0, err
			} else {
				bandwidth = binding.bandwidth
			}
		}
		if d.owned.IsValid() && d.owned != src {
			first := d.firstRefusalLocked(refusalSourceChanged)
			d.mu.Unlock()
			if total := d.table.countRefusal(refusalSourceChanged); first {
				fmt.Fprintf(os.Stderr, "winn3-gateway: forward source changed "+
					"(first for this session; %d since start, see forward.table.source_changed)\n", total)
			}
			return 0, errGatewayInnerSourceChanged
		}
		if !d.owned.IsValid() {
			if !d.table.learn(src, loop) {
				first := d.firstRefusalLocked(refusalSourceOwned)
				d.mu.Unlock()
				if total := d.table.countRefusal(refusalSourceOwned); first {
					fmt.Fprintf(os.Stderr, "winn3-gateway: forward table.learn failed: inner source already owned "+
						"(first for this session; %d since start, see forward.table.source_owned)\n", total)
				}
				return 0, errGatewayInnerSourceOwned
			}
			d.owned = src
		}
		// OI-5: the destination rule runs after every source check, so the
		// source counters keep their meaning and intra_subnet counts only
		// packets whose source was accepted. It reads the packet's own
		// address words (the parse above proved the header). See
		// forwardIsolation.
		if iso := d.table.isolation; iso != nil && iso.refuses(ipv4SourceDestinationUint32(pkt)) {
			first := d.firstRefusalLocked(refusalIntraSubnet)
			d.mu.Unlock()
			if total := d.table.countRefusal(refusalIntraSubnet); first {
				fmt.Fprintf(os.Stderr, "winn3-gateway: forward destination refused "+
					"(first for this session; %d since start, see forward.table.intra_subnet)\n", total)
			}
			return 0, errGatewayDestinationRefused
		}
		d.mu.Unlock()
		if !bandwidth.allow(len(pkt), false) {
			d.table.freeDroppedUp.Add(1)
			return len(pkt), nil
		}
	}
	var n int
	var err error
	if tw, ok := d.shared.(trackedWriter); ok && tw.asyncWrites() {
		n, err = tw.writeTracked(&d.pending, pkt)
	} else {
		n, err = d.shared.write(pkt)
	}
	if err != nil {
		d.mu.Lock()
		first := d.firstRefusalLocked(refusalWriteFailed)
		d.mu.Unlock()
		// The error text is not logged: innerWriter.write returns an
		// unrestricted error, which may name the packet's addresses. The
		// caller still receives err unchanged (OI-U2, Round U).
		if total := d.table.countRefusal(refusalWriteFailed); first {
			fmt.Fprintf(os.Stderr,
				"winn3-gateway: shared.write failed: n=%d "+
					"(first for this session; %d since start, see forward.table.write_failed)\n",
				n, total)
		}
	}
	return n, err
}

// asyncCloseWait bounds how long Close waits for this session's queued
// packets. A writer only ever waits on write(2) to a TUN descriptor, which does
// not block, so the bound is a backstop against a wedged kernel, not a budget
// the normal path spends.
const asyncCloseWait = 2 * time.Second

// awaitQueuedWrites returns once every packet this session queued under
// -forward-async-write has been written, or after asyncCloseWait.
// With the flag off nothing is ever pending and it returns at once.
func (d *gatewayForwardDevice) awaitQueuedWrites() {
	if d.pending.Load() == 0 {
		return
	}
	deadline := time.Now().Add(asyncCloseWait)
	for d.pending.Load() != 0 {
		if time.Now().After(deadline) {
			fmt.Fprintf(os.Stderr, "winn3-gateway: forward device closed with %d queued packet(s) still "+
				"unwritten after %v (see forward.device.async_written)\n", d.pending.Load(), asyncCloseWait)
			return
		}
		time.Sleep(100 * time.Microsecond)
	}
}

// ReadPacket blocks until Close, and never produces a packet. See the type
// doc for why the return direction does not go through this method.
func (d *gatewayForwardDevice) ReadPacket([]byte) (int, error) {
	<-d.done
	return 0, errGatewayForwardDeviceClosed
}

// MTU reports the plan floor's inner MTU, matching what sharedGatewayTun was
// asked to configure on the real interface (and verified against the
// kernel's own answer at construction; see forward_linux.go).
func (d *gatewayForwardDevice) MTU() int { return d.mtu }

// Close forgets the sole address this session claimed, so a later session can
// claim it after this owner is gone without inheriting stale return routing.
// It does NOT close the shared kernel device: that
// descriptor outlives every individual session and is owned by the
// top-level server, exactly as the reflector's per-session Close never
// touches anything wider than its own inbox. Under -forward-async-write it
// first waits for this session's queued packets (awaitQueuedWrites), so that
// once it returns nothing more of this session reaches the kernel.
func (d *gatewayForwardDevice) Close() error {
	d.closeOnce.Do(func() {
		d.awaitQueuedWrites()
		d.mu.Lock()
		loop := d.loop
		owned := d.owned
		d.mu.Unlock()
		if loop != nil && owned.IsValid() {
			d.table.forget(owned, loop)
		}
		close(d.done)
	})
	return nil
}
