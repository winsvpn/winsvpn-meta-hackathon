package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"time"
)

// forwardIsolation is the uplink destination rule of PQ OI-5 (gateway client
// isolation, unanimous 2026-10-10; exact code 2026-10-11). A client packet may
// leave this gateway towards the internet and nowhere else. Before OI-5,
// gatewayForwardDevice.WritePacket parsed the destination and discarded it,
// so the only thing between one client and another client, the gateway's own
// WAN address, or a private network behind the host was the installer's
// firewall. The firewall stays (it is the backstop for any path that bypasses
// WritePacket); this is the process's own refusal, which costs nothing on the
// wire and runs before the packet reaches the kernel.
//
// # What is refused
//
//  1. Any destination inside the client pool (-forward-cidr) other than this
//     gateway's own inner address (-inner-v4). The inner address is the one
//     pool address a client is meant to reach: the resolver, the promotion
//     probe's echo and the speedtest ingest all live there, and the
//     installer's WINN3GW-INPUT chain admits exactly those. The pool's
//     network and directed-broadcast addresses are inside the pool and are
//     refused by the same containment test; the registry already refuses to
//     BIND them (peer_registry.go), this refuses to SEND to them.
//  2. dst == src, checked first, so it holds even when both name the inner
//     address. With a registry the source is a pool address and rule 1
//     already covers it; without one (tests) this is the only pool rule.
//  3. RFC 1918 (10/8, 172.16/12, 192.168/16) and RFC 6598 shared space
//     (100.64/10): the host's own private networks, and awg0's VPN_CIDR.
//  4. Every IPv4 address configured on a local interface other than the
//     inner address, the WAN address first of all. This closes the NAT
//     hairpin into the gateway's own sockets (its winn3 listener, sshd and
//     anything else bound to the WAN address).
//
// Link-local (169.254/16, the cloud metadata block), loopback, multicast,
// unspecified, 0/8 and 240/4 are refused before WritePacket runs, by the tun
// inbound rule (winn3/tun/ip.go martianReason via inbound), so they are not
// duplicated here. Anything that is not IPv4 is refused by WritePacket itself.
//
// # Cost
//
// The check runs once per uplink packet, after the source checks, on the
// packet's own address words (ipv4SourceDestinationUint32). It is a handful
// of 32-bit compares against values computed once at construction, plus a
// scan of the local address set, which is read with one atomic load and no
// lock. It allocates nothing. Measured in forward_isolation_bench_test.go
// (numbers in the round's position paper).
//
// # The local address set
//
// The set is every IPv4 address net.InterfaceAddrs reports except the inner
// address. It is read at construction and then replaced whole by
// runLocalRefresh every isolationLocalRefresh. A WAN address that changes
// (DHCP renewal, a floating address moved onto this host) is refused from
// the next refresh on; during that window the installer's INPUT drop for the
// tunnel interface (`-i IFACE -j DROP` behind the WINN3GW-INPUT jump) is the
// rule that stops it. A refresh that fails keeps the last good set in force
// and is reported once.
type forwardIsolation struct {
	inner    uint32
	poolNet  uint32
	poolMask uint32

	// local is the set of local IPv4 addresses other than inner, as a
	// pointer to an immutable slice: the hot path loads the pointer and
	// scans; refreshLocal builds a new slice and stores a new pointer.
	local atomic.Pointer[[]uint32]

	// lister is net.InterfaceAddrs in production. Tests substitute a fake
	// so the set, and a WAN address change, are exact.
	lister func() ([]net.Addr, error)

	// warned is set by runLocalRefresh after its first reported failure, so
	// a host whose netlink is broken produces one line, not one per tick.
	warned atomic.Bool
}

// isolationLocalRefresh is how often the local address set is rebuilt. It
// matches the peer registry's freshness interval (registryFreshness): one
// netlink dump per second is nothing, and it bounds the window named in the
// type doc.
const isolationLocalRefresh = time.Second

// isolationPrivateNets are the RFC 1918 and RFC 6598 blocks, as (network,
// mask) pairs in host byte order so the hot path is one AND and one compare
// per entry.
var isolationPrivateNets = [...]struct{ net, mask uint32 }{
	{0x0A000000, 0xFF000000}, // 10.0.0.0/8
	{0xAC100000, 0xFFF00000}, // 172.16.0.0/12
	{0xC0A80000, 0xFFFF0000}, // 192.168.0.0/16
	{0x64400000, 0xFFC00000}, // 100.64.0.0/10
}

var errIsolationNotIPv4 = errors.New("forward isolation needs an IPv4 pool and inner address")

// newForwardIsolation builds the rule for pool (-forward-cidr, already
// validated by parseForwardCIDR) and inner (-inner-v4). It reads the local
// address set once; a failure there is returned, since a gateway that cannot
// enumerate its own addresses cannot promise rule 4.
func newForwardIsolation(pool netip.Prefix, inner netip.Addr) (*forwardIsolation, error) {
	return newForwardIsolationWith(pool, inner, net.InterfaceAddrs)
}

// newForwardIsolationWith is newForwardIsolation with the address lister
// injected.
func newForwardIsolationWith(pool netip.Prefix, inner netip.Addr, lister func() ([]net.Addr, error)) (*forwardIsolation, error) {
	if !pool.IsValid() || !pool.Addr().Is4() || !inner.Is4() {
		return nil, errIsolationNotIPv4
	}
	masked := pool.Masked()
	network := masked.Addr().As4()
	var mask uint32
	if bits := masked.Bits(); bits > 0 {
		mask = ^uint32(0) << uint(32-bits)
	}
	in := inner.As4()
	p := &forwardIsolation{
		inner:    binary.BigEndian.Uint32(in[:]),
		poolNet:  binary.BigEndian.Uint32(network[:]),
		poolMask: mask,
		lister:   lister,
	}
	if err := p.refreshLocal(); err != nil {
		return nil, fmt.Errorf("reading this host's interface addresses: %w", err)
	}
	return p, nil
}

// refuses reports whether an uplink packet from src to dst must not be
// forwarded. Both are the packet's own address words as
// ipv4SourceDestinationUint32 reads them (10.0.0.0 is 0x0A000000), so the
// hot path converts nothing. No allocation, no lock.
func (p *forwardIsolation) refuses(src, dst uint32) bool {
	if dst == src {
		return true
	}
	if dst == p.inner {
		return false
	}
	if dst&p.poolMask == p.poolNet {
		return true
	}
	for i := range isolationPrivateNets {
		if dst&isolationPrivateNets[i].mask == isolationPrivateNets[i].net {
			return true
		}
	}
	if local := p.local.Load(); local != nil {
		for _, a := range *local {
			if a == dst {
				return true
			}
		}
	}
	return false
}

// ipv4SourceDestinationUint32 returns the source and destination address
// fields of pkt as the words refuses compares. Call it only after
// ipv4SourceDestination has returned ok for the same packet (so the header
// is at least 20 bytes and the version nibble is 4); it is two loads, where
// converting the netip.Addr pair back to words costs a measured 1.5 ns per
// packet.
func ipv4SourceDestinationUint32(pkt []byte) (src, dst uint32) {
	return binary.BigEndian.Uint32(pkt[12:16]), binary.BigEndian.Uint32(pkt[16:20])
}

// refreshLocal rebuilds the local address set from the lister and publishes
// it. On error the previous set stays published.
func (p *forwardIsolation) refreshLocal() error {
	addrs, err := p.lister()
	if err != nil {
		return err
	}
	set := make([]uint32, 0, len(addrs))
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		v := binary.BigEndian.Uint32(ip4)
		if v == p.inner {
			continue
		}
		set = append(set, v)
	}
	p.local.Store(&set)
	return nil
}

// localAddrs returns the published local address set, for status and tests.
func (p *forwardIsolation) localAddrs() []netip.Addr {
	local := p.local.Load()
	if local == nil {
		return nil
	}
	out := make([]netip.Addr, 0, len(*local))
	for _, v := range *local {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		out = append(out, netip.AddrFrom4(b))
	}
	return out
}

// runLocalRefresh rebuilds the local address set every interval until ctx
// ends. It is the only writer of the set after construction.
func (p *forwardIsolation) runLocalRefresh(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.refreshLocal(); err != nil && !p.warned.Swap(true) {
				fmt.Fprintf(os.Stderr, "winn3-gateway: forward isolation: refreshing this host's interface "+
					"addresses failed: %v (the last good set stays in force; see forward.table.intra_subnet)\n", err)
			}
		}
	}
}
