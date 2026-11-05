//go:build !linux

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
)

// These tests run supersede through the REAL -forward ownership path on a host
// without the Linux kernel device: every session gets a real
// gatewayForwardDevice bound to one real forwardTable (with the registry, as
// runServe wires it) and a real peerRegistry, and ownership is read by the
// production predicate, reclaimSupersededSessions. The only part missing is the
// kernel TUN behind sharedGatewayTun: on this build its write refuses, AFTER
// WritePacket has already validated the source against the registry and
// learned it into the table, so ownership moves exactly as in production and
// nothing is forwarded. On Linux the same path needs a real /dev/net/tun (and
// so root), which this lane may not create; the build tag keeps the nil shared
// device away from the Linux write, which would dereference it.

const forwardEgressDst = "198.51.100.77"

// newForwardReclaimRig is newReclaimRig in -forward mode, with the client key
// registered at testClientInner. It serves only the read loop, never the
// serve ticker, so the test decides when reclaimSupersededSessions runs.
func newForwardReclaimRig(t *testing.T, ctx context.Context) *reclaimRig {
	t.Helper()
	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	clientPub := readTestKey(t, filepath.Join(dir, "client.pub"))
	body := fmt.Sprintf(`{"version":1,"peers":[{"static_public":%q,"inner_v4":%q,"not_after":0}]}`,
		base64.StdEncoding.EncodeToString(clientPub), testClientInner)
	registry, err := newPeerRegistry(writeRegistry(t, body), netip.MustParsePrefix("10.64.0.0/24"),
		netip.MustParseAddr(testGatewayInner))
	if err != nil {
		t.Fatal(err)
	}
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	sessionCfg, err := buildSessionConfig(serveOptions{
		staticPath: filepath.Join(dir, "static.key"),
		admission:  filepath.Join(dir, "admission.key"),
		gatewayID:  testGatewayID,
	}, registry)
	if err != nil {
		t.Fatal(err)
	}
	// Fast gateway probes, so an idle session is confirmed by its client's PONG
	// promptly (an event the test waits on, not a deadline), and a ladder that
	// never gives up, so only supersede can end the older session.
	sessionCfg.Probe = session.Draw{Min: 50 * time.Millisecond, Mean: 100 * time.Millisecond, Max: 300 * time.Millisecond}
	sessionCfg.MaxLostProbes = 1000
	assign, err := parseAssignment(testGatewayInner, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	table := newForwardTable()
	table.registry = registry
	srv := &server{
		conn:          conn,
		sizing:        sizing,
		sessionCfg:    sessionCfg,
		assign:        assign,
		maxSessions:   8,
		peers:         make(map[netip.AddrPort]*peerSession),
		acceptTransit: true,
		forward:       true,
		table:         table,
		peerRegistry:  registry,
	}
	gwAddr := conn.LocalAddr().(*net.UDPAddr)
	readDone := make(chan error, 1)
	go func() { readDone <- srv.readLoop(ctx) }()
	t.Cleanup(func() {
		_ = conn.Close()
		<-readDone
		srv.closeAll()
	})
	return &reclaimRig{
		srv:    srv,
		gwAddr: gwAddr,
		opts: testClientOpts{
			dir: dir, gwAddr: gwAddr,
			gatewayPublic: readTestKey(t, filepath.Join(dir, "static.pub")),
			admission:     readTestSecret(t, filepath.Join(dir, "admission.key")),
			sizing:        sizing, inner: testClientInner,
		},
	}
}

// uplink sends one egress packet from cli; on the gateway it opens under the
// session's keys and reaches that session's gatewayForwardDevice, which learns
// testClientInner for it.
func uplink(t *testing.T, cli *testClient, tag string) {
	t.Helper()
	cli.dev.offer(t, testIPv4(t, testClientInner, forwardEgressDst, []byte(tag)))
}

func forwardOwner(r *reclaimRig) *driver.Loop {
	loop, _ := r.srv.table.lookup(netip.MustParseAddr(testClientInner))
	return loop
}

// TestForwardModeSupersedeFollowsRealForwardingOwnership: through the real
// device, table and registry, the newer same-key session supersedes the older
// one only once its own uplink has moved the key's address to it, and not
// while the replacement has left s.peers with its device (so its forwarding
// entry) still up, which is the Round Q Turn 4 OI-Q2 window on the real path.
func TestForwardModeSupersedeFollowsRealForwardingOwnership(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*supersedeSafety)
	defer cancel()
	r := newForwardReclaimRig(t, ctx)

	a := startTestClient(t, ctx, r.opts)
	waitFor(t, supersedeSafety, "the older client to carry", func() bool { return carrying(a) })
	older := r.onlySession(t)
	uplink(t, a, "a-egress")
	waitFor(t, supersedeSafety, "the older session to own the key's address", func() bool {
		return forwardOwner(r) == older.loop
	})

	b := startTestClient(t, ctx, r.opts)
	waitFor(t, supersedeSafety, "the newer client to carry", func() bool { return carrying(b) })
	var newer *peerSession
	waitFor(t, supersedeSafety, "the gateway to hold the newer established session", func() bool {
		for _, v := range r.srv.slotViews() {
			if v.ps != older && v.view.Established {
				newer = v.ps
				return true
			}
		}
		return false
	})

	// Newer established but its client has sent no uplink: the address still
	// belongs to the older session, so nothing is superseded.
	if n := r.srv.reclaimSupersededSessions(); n != 0 {
		t.Fatalf("supersede retired %d sessions before the replacement took the address", n)
	}
	if !r.inPeers(older) {
		t.Fatal("the older session left the table before the replacement took the address")
	}

	// Confirmed but not owning: the rig's gateway probes fast, and the newer
	// client's PONG opens under the newer session's post-handshake keys, so the
	// newer session becomes confirmed usable without any uplink, and the address
	// stays with the older session. Only the ownership check can refuse here.
	waitFor(t, supersedeSafety, "the newer session to be confirmed usable", func() bool {
		v, ok := viewOfSlot(newer.remoteAddrPort(), newer)
		return ok && confirmedUsable(v.view)
	})
	if forwardOwner(r) != older.loop {
		t.Fatal("fixture: the key's address moved without an uplink from the newer client")
	}
	if n := r.srv.reclaimSupersededSessions(); n != 0 {
		t.Fatalf("supersede retired %d sessions for a confirmed replacement that does not own the address", n)
	}
	if !r.inPeers(older) || older.loop.Session().State().Terminal() {
		t.Fatal("the older session did not survive while it still owned the address")
	}

	// The newer client's first proper uplink moves the address.
	uplink(t, b, "b-egress")
	waitFor(t, supersedeSafety, "the newer session to own the key's address", func() bool {
		return forwardOwner(r) == newer.loop
	})
	waitFor(t, supersedeSafety, "the newer session to be confirmed usable", func() bool {
		v, ok := viewOfSlot(newer.remoteAddrPort(), newer)
		return ok && confirmedUsable(v.view)
	})

	// OI-Q2 on the real path: the replacement leaves s.peers (releasePeer's
	// first step) while its driver and forwarding device stay up, so the real
	// predicate still reports it as the owner.
	newerAddr := newer.remoteAddrPort()
	r.srv.mu.Lock()
	delete(r.srv.peers, newerAddr)
	r.srv.mu.Unlock()
	if forwardOwner(r) != newer.loop {
		t.Fatal("fixture: the detached replacement no longer owns the address")
	}
	// The table walk can no longer see the detached replacement, so drive the
	// commit on the {older, newer} pair directly, with the real predicate.
	views := append(r.srv.slotViews(), mustView(t, newerAddr, newer))
	realOwns := func(v slotView) bool {
		inner, ok := r.srv.peerRegistry.innerForPeer(v.view.PeerStatic)
		if !ok {
			return false
		}
		loop, ok := r.srv.table.lookup(inner)
		return ok && loop == v.ps.loop
	}
	pairs := supersedePairs(views, realOwns)
	if len(pairs) != 1 || pairs[0].old.ps != older || pairs[0].newer.ps != newer {
		t.Fatalf("selection did not propose {older,newer} under real ownership: %d pairs", len(pairs))
	}
	if r.srv.retireSupersededOld(pairs[0], realOwns) {
		t.Fatal("the older session was retired against a replacement that no longer holds a slot")
	}
	if !r.inPeers(older) || older.loop.Session().State().Terminal() {
		t.Fatal("the older session did not survive the refused supersede")
	}

	// Restored to the table, the real ticker body supersedes the older session.
	r.srv.mu.Lock()
	r.srv.peers[newerAddr] = newer
	r.srv.mu.Unlock()
	killSilently(a)
	n, _ := sweepJustified(t, older, r.srv.reclaimSupersededSessions)
	if n != 1 {
		t.Fatalf("supersede retired %d sessions, want 1", n)
	}
	if r.inPeers(older) {
		t.Fatal("the superseded session is still in the table")
	}
	waitFor(t, supersedeSafety, "the superseded session to end", func() bool {
		return older.loop.Session().State().Terminal()
	})
	if forwardOwner(r) != newer.loop {
		t.Fatal("the replacement lost the key's address when the older session was retired")
	}
}

func mustView(t *testing.T, addr netip.AddrPort, ps *peerSession) slotView {
	t.Helper()
	v, ok := viewOfSlot(addr, ps)
	if !ok {
		t.Fatal("could not snapshot a session")
	}
	return v
}
