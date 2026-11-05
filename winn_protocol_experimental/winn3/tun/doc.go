// Package tun is Winn Protocol v3's inner-IP layer: the piece that turns an
// established session into an actual tunnel.
//
// It has exactly two jobs and refuses to grow a third.
//
//  1. Move inner IP packets between a host tun device and the frame-level
//     session driver, validating every packet in both directions against the
//     inner address the gateway assigned.
//  2. Be the fail-closed authority. If the session is not carrying — not yet
//     handshaken, still in epoch 0 under StrictPQ, mid-rekey, closing, or torn
//     down — no inner packet moves in either direction, and nothing is written
//     to the host at all.
//
// # What this package is not allowed to do
//
// No sockets. No file descriptors. No syscalls. No clock it was not handed.
// The core enforces the same rule on itself with a source-level guard, and
// TestPackageOpensNothing here is the stricter version of it: it parses every
// non-test file with go/parser and checks the import set against an allowlist,
// so an aliased import (`import n "net"`) cannot slip past a substring grep.
//
// The reason is portability, not purity. Winn v3 ships on five platforms whose
// tun devices agree about almost nothing: utun sockets with a 4-byte address
// family prefix on Darwin, /dev/net/tun with an optional PI header on Linux,
// a WinTun ring buffer on Windows, a file descriptor handed down by
// VpnService on Android, a NEPacketTunnelFlow object on iOS. Every one of
// those differences is somebody else's problem if this package only ever sees
// a Device interface.
//
// # The address rule, stated once
//
// A tunnel that forwards a packet whose source address it never assigned is a
// deanonymisation bug, not a routing quirk. The user in Myanmar whose handset
// emits one packet sourced from its carrier-assigned address, through a tunnel
// that shrugged and forwarded it, has been identified — by the tunnel that was
// supposed to be protecting them.
//
// So Assignment holds addresses, never prefixes. Outbound, the source must be
// exactly an assigned address. Inbound, the destination must be exactly an
// assigned address, which is also what makes this endpoint structurally
// incapable of acting as a router for anyone else's traffic.
//
// # MTU, in one line
//
// One inner packet of L bytes becomes one DATA frame in one transport message
// of L + Overhead() bytes on the wire, where Overhead() is
// core.TransportOverhead() + FrameOverhead = 26 + 3 = 29. Everything in mtu.go
// is that identity rearranged. See the handoff document for the worked
// arithmetic per carrier and the reason the inner MTU is pinned to the
// *smallest* carrier the session may migrate to rather than the one it dialled.
//
// # Fragmentation
//
// This package never fragments an inner packet and never reassembles one.
// An oversize packet is dropped and, if a next hop is known and the rate
// budget allows, a PMTU signal is synthesised *inward* — written to the host's
// own tun device, addressed to the host's own inner address. It never becomes
// a DATA frame and it never reaches the wire. Inner fragmentation would emit a
// two-packet burst with a near-fixed size ratio, which is a length and timing
// signature; it would put reassembly state on the gateway, which is a
// denial-of-service surface; and fragments are widely dropped by exactly the
// middleboxes this protocol exists to get past.
package tun
