package main

import (
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
)

// The two pumps, kept portable on purpose.
//
// This is the code that actually moves packets, so it is the code most worth
// testing -- and it is meaningless to review it if it can only be compiled for
// a platform the reviewer does not have. The Wintun adapter is reached through
// the tiny tunSide interface below, which main_windows.go implements over
// wintun.Session and relay_test.go implements over a channel. The pumps
// themselves, including every decision about whether a packet may move, are the
// same code in both cases.

// tunSide is the adapter, reduced to the three operations a relay needs.
type tunSide interface {
	// receivePacket returns the next inner packet the host stack wants to send,
	// together with a function that releases it back to the ring. The release
	// function is never nil when err is nil and must be called exactly once.
	//
	// errTunAgain means "nothing is ready, wait"; any other error is fatal and
	// unwinds the pump.
	receivePacket() (packet []byte, release func(), err error)

	// waitReadable blocks until receivePacket may succeed again.
	waitReadable() error

	// sendPacket delivers one inner packet to the host stack. errTunRingFull is
	// a droppable condition -- the host is not draining -- and any other error
	// is fatal.
	sendPacket(packet []byte) error
}

// seamReadBuffer bounds one datagram read. Generously above any inner MTU the
// protocol can plan for; oversize is classified and counted rather than
// truncated, because a truncated IP packet is undetectable corruption at the
// next layer. It lives here rather than beside the Wintun code because the
// pumps are what use it.
const seamReadBuffer = 65535

var (
	errTunAgain    = errors.New("winn3 relay: no packet ready")
	errTunRingFull = errors.New("winn3 relay: send ring is full")
	errTunClosed   = errors.New("winn3 relay: the adapter is closed")
)

// counters are published on shutdown. Silence that is never explained is how a
// datapath defect survives a field report, so every drop has a name and the
// names are kept distinct: "the host sent something absurd" and "the tunnel is
// dropping traffic" are different problems, and one counter would conflate
// them.
type counters struct {
	tunToSeam    atomic.Uint64
	seamToTun    atomic.Uint64
	dropInvalid  atomic.Uint64
	dropOversize atomic.Uint64
	dropRingFull atomic.Uint64
	foreign      atomic.Uint64
}

// pumpTunToSeam moves inner IP packets from the adapter to the engine.
//
// This is the direction that gets ENCRYPTED below: everything leaving here is
// cleartext, crosses one loopback hop, and is sealed by winn3/core inside
// winn-datapath before it touches the network. If this pump is ever wired to a
// winn/1 engine instead, that cleartext reaches the gateway unencrypted -- see
// the header of main_windows.go.
func pumpTunToSeam(
	tun tunSide, seam *net.UDPConn, peer netip.AddrPort,
	mtu int, stats *counters, shutdown func(),
) {
	defer shutdown()
	for {
		packet, release, err := tun.receivePacket()
		switch {
		case err == nil:
			if problem := classifyInnerPacket(packet, mtu); problem != nil {
				countRefusal(stats, problem)
			} else if _, err := seam.WriteToUDPAddrPort(packet, peer); err != nil {
				// The seam is loopback, so a write failure means the engine's
				// socket is gone -- there is nothing beneath us to encrypt.
				// Stopping is the fail-closed answer: carrying on would leave
				// an adapter up that silently carries nothing, which is the
				// exact failure this project has already been bitten by.
				release()
				return
			} else {
				stats.tunToSeam.Add(1)
			}
			release()
		case errors.Is(err, errTunAgain):
			if err := tun.waitReadable(); err != nil {
				return
			}
		default:
			return
		}
	}
}

// pumpSeamToTun moves inner IP packets from the engine to the adapter.
//
// Everything arriving here has already been decrypted and validated by
// winn3/tun's inbound validator. The checks below are this relay's own, because
// the seam is a loopback socket and this side of it is the injection point a
// local unprivileged process would aim at.
func pumpSeamToTun(
	tun tunSide, seam *net.UDPConn, peer netip.AddrPort,
	mtu int, stats *counters, shutdown func(),
) {
	defer shutdown()
	buffer := make([]byte, seamReadBuffer)
	for {
		n, from, err := seam.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		if from != peer {
			// THE PEER PIN. A loopback port is writable by any process on the
			// machine; without this, a local unprivileged process could inject
			// inner packets into somebody else's tunnel. Counted rather than
			// only dropped, because a nonzero value means something on this
			// machine is writing to the seam and that is worth seeing.
			stats.foreign.Add(1)
			continue
		}
		packet := buffer[:n]
		if problem := classifyInnerPacket(packet, mtu); problem != nil {
			countRefusal(stats, problem)
			continue
		}
		if err := tun.sendPacket(packet); err != nil {
			if errors.Is(err, errTunRingFull) {
				// The host stack is not draining. Dropping is what a real link
				// does; counting it is what keeps the silence explained.
				stats.dropRingFull.Add(1)
				continue
			}
			return
		}
		stats.seamToTun.Add(1)
	}
}

func countRefusal(stats *counters, problem error) {
	if errors.Is(problem, errPacketOversize) {
		stats.dropOversize.Add(1)
		return
	}
	stats.dropInvalid.Add(1)
}
