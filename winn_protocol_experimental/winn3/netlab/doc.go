// Package netlab is the impairment rig: the first hostile network Winn Protocol
// v3 has met.
//
// Every proof under winn3/ before this package was written on loopback. Loopback
// never reorders, never drops, never renumbers a source address and never
// fragments, so every property the design leans on — the force-advance rule that
// buys reordering tolerance, the liveness-based desynchronisation detector, the
// demux-token index that is supposed to survive a NAT rebind, the IPv6 floor
// refusal, and the plan floor that exists to stop an 84-byte black hole on the
// first migration — was unproven against the conditions it was designed for.
//
// # What this package is
//
// A userspace impairment shim, not a netns rig. The choice is deliberate and it
// is not a compromise:
//
//   - The properties under test are all decided ABOVE the socket. The force-
//     advance rule is arithmetic on a counter; the desync detector is a probe
//     budget; the path-MTU refusal is a comparison at construction. A kernel
//     netem qdisc would impair the same messages this shim impairs, and would
//     additionally make every result non-deterministic and unavailable on this
//     platform.
//   - The one thing a netns rig has that this does not is a real IP stack, and
//     the one property that needs one — actual in-network fragmentation — is a
//     property v3 refuses to have (winn3/tun §2.5 drops rather than fragments),
//     so a rig that could produce it would be testing a path that cannot be
//     reached.
//   - Determinism is the whole point. A reorder tolerance measured as "usually
//     around 128" is not a measurement. Link places a message at an EXACT
//     displacement, so the break point is a number rather than a distribution.
//
// Nothing here opens a socket. Link sits between two carrier.Pipe instances,
// which is the same seam winn3/gateway's demultiplexer plugs into, so the
// messages crossing it are the real sealed messages a real carrier would carry.
//
// # The two rigs
//
// Pair is the end-to-end rig: two driver.Loop instances, each with its own tun
// layer and host device, joined by two Links — one per direction. It runs the
// real three-goroutine pump, so it proves that a property survives the actual
// concurrency, and it is the rig that can black-hole a tunnel while the tunnel
// still reports "up".
//
// Duplex is the exact rig: two session.Driver instances pumped by hand with no
// goroutines at all and an explicitly ordered delivery list. It is what turns
// "tolerates about half a window" into "tolerates exactly 127 and fails at 128".
//
// # The standard this package is held to
//
// A rig that reports everything passing on its first run has most likely
// impaired nothing. Every impairment in this package is therefore proved by
// showing the SAME test failing with the impairment cranked past tolerance —
// see teeth_test.go, which is the file to read first if a later reader doubts
// any number in the handoff document.
//
// # What this package must never do
//
// It opens no socket, binds no address, starts no tunnel and creates no tun
// device. Every "network" here is a queue in this process.
package netlab
