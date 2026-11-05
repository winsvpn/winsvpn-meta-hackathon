package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"winsvpn.local/winnprotocol/winn3/tun"
)

// The loopback inner-packet seam.
//
// One inner IP packet per UDP datagram over 127.0.0.1. The host owns the real
// tun interface — Wintun on Windows, /dev/net/tun on a Linux host that would
// rather not pass a descriptor — and relays.
//
// # Why a cleartext leg over loopback is not a leak
//
// The containment is STRUCTURAL rather than a policy anybody has to enforce: a
// socket bound to 127.0.0.1 has no route off the device. This tree already
// rests on that argument three times — Android's WinnAwgLoopbackSeam,
// internal/carrier.RelayLocalUDP, and the Xray transport's RemoteAwgHost
// loopback pin — and BindLinuxWinnSeam is the fourth. This is the fifth and it
// is deliberately the same shape rather than a new one.
//
// What is different from the winn/1 seam, and worth saying once because getting
// it backwards is how cleartext reaches a gateway: the winn/1 seam carries
// AmneziaWG OUTER DATAGRAMS, already encrypted by AWG, and the engine only
// forwards them. This seam carries RAW INNER IP PACKETS, and the engine is what
// encrypts them. A host that wires this seam to a winn/1 engine forwards
// cleartext to the gateway; a host that wires the winn/1 seam to this engine
// double-encrypts and the gateway drops everything. The device kind in the
// profile is what keeps them apart, and neither engine accepts the other's.
//
// # Why the peer is pinned
//
// The socket accepts datagrams from exactly one address: the loopback port the
// host bound before starting this process. Any other source is counted and
// dropped rather than delivered. A local unprivileged process cannot otherwise
// be stopped from writing to a loopback port, and an unpinned seam would let
// one inject inner packets into somebody else's tunnel.

// winn3LoopbackDevice is a tun.Device backed by a pinned loopback UDP socket.
type winn3LoopbackDevice struct {
	conn *net.UDPConn
	peer netip.AddrPort
	mtu  int

	// foreign counts datagrams refused because they came from somewhere other
	// than the host's seam port.
	foreign atomic.Uint64
}

// winn3LoopbackMaxDatagram bounds one read. It is generously above any inner
// MTU this protocol can plan for; the tun layer refuses an oversize packet
// itself and counts it, which is where that decision belongs.
const winn3LoopbackMaxDatagram = 65535

// newWinn3LoopbackDevice binds the engine's half of the seam.
//
// It binds 127.0.0.1 on an ephemeral port and never any other address: binding
// a wildcard would put an inner-packet injection point on every interface the
// machine has, including the one the tunnel is trying to protect.
func newWinn3LoopbackDevice(hostPort, mtu int) (*winn3LoopbackDevice, error) {
	if hostPort <= 0 || hostPort > 65535 {
		return nil, fmt.Errorf("loopback seam: host port %d is not usable", hostPort)
	}
	if mtu <= 0 {
		return nil, fmt.Errorf("loopback seam: mtu %d is not usable", mtu)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 0,
	})
	if err != nil {
		return nil, fmt.Errorf("bind loopback seam: %w", err)
	}
	return &winn3LoopbackDevice{
		conn: conn,
		peer: netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			//nolint:gosec // bounded by the check above
			uint16(hostPort),
		),
		mtu: mtu,
	}, nil
}

// LocalPort is the ephemeral port the host must send inner packets to.
func (d *winn3LoopbackDevice) LocalPort() int {
	addr, ok := d.conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return 0
	}
	return addr.Port
}

// ForeignDatagrams is how many datagrams were refused for coming from the wrong
// place. It is published rather than only counted because a nonzero value means
// something on this machine is writing to the seam, which is worth seeing.
func (d *winn3LoopbackDevice) ForeignDatagrams() uint64 { return d.foreign.Load() }

// ReadPacket blocks until one inner IP packet arrives from the pinned peer.
func (d *winn3LoopbackDevice) ReadPacket(buf []byte) (int, error) {
	for {
		n, from, err := d.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return 0, err
		}
		if from != d.peer {
			d.foreign.Add(1)
			continue
		}
		if n == 0 {
			// A zero-length datagram is not an inner packet. Skipping it here
			// keeps the tun layer's invalid counter meaning "a packet that
			// failed validation" rather than "the host sent nothing".
			continue
		}
		return n, nil
	}
}

// WritePacket delivers one inner IP packet back to the host's seam.
func (d *winn3LoopbackDevice) WritePacket(pkt []byte) (int, error) {
	n, err := d.conn.WriteToUDPAddrPort(pkt, d.peer)
	if err != nil {
		return n, fmt.Errorf("%w: %s", tun.ErrDeviceWrite, err)
	}
	return n, nil
}

// MTU reports the inner MTU the host is required to have configured.
//
// The loopback seam has no interface of its own to read, so this returns the
// plan floor the engine computed — which is the number §4.2 obliges the host to
// set on the real interface. It is therefore an assertion about the host, not a
// measurement of it, and that is the honest weakness of this backend and the
// reason the tun-fd backend is preferred wherever a descriptor can be passed.
func (d *winn3LoopbackDevice) MTU() int { return d.mtu }

// Close releases the socket. Closing it is what unblocks a parked ReadPacket.
func (d *winn3LoopbackDevice) Close() error {
	err := d.conn.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

var _ tun.Device = (*winn3LoopbackDevice)(nil)
