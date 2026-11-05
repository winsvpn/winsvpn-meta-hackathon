// Package driver is the loop that joins winn3/session, winn3/tun and
// winn3/carrier into a working Winn Protocol v3 tunnel.
//
// Four packages were built to a high standard and none of them calls another.
// That is not an oversight in any of them — it is the consequence of three
// deliberate refusals, each of which is correct in its own layer:
//
//   - winn3/session holds no socket and no timer, because a session that owns a
//     socket cannot have the socket swapped underneath it, and a timing policy
//     that lives in two layers will disagree with itself.
//   - winn3/tun holds no socket, no timer and no goroutine, because a packet
//     loop that outlives a teardown is the fail-closed property leaking out the
//     side.
//   - winn3/carrier holds no policy, because the escalation decision already
//     exists in datapath/escalation.go and two opinions disagree exactly when
//     disagreement is expensive.
//
// Somebody has to own the wait, the goroutines and the wiring. This package is
// that owner, and it is the only place in v3 where a timer, a goroutine and a
// socket-shaped thing meet. It decides no carrier-class escalation and no
// failover successor. Sizing refusals, the Established-only SendInner check,
// and tunStateFor are local fail-closed checks, not a second escalation opinion.
//
// # The pump
//
//	host device ──▶ tun.Outbound ──▶ [gate] ──▶ session.Enqueue ──▶ carrier.Send
//	host device ◀── tun.Inbound  ◀── [gate] ◀── session.Deliver ◀── carrier.Recv
//
// Three goroutines. They share the carrier pointer, the tun gate (under
// gateMu), and the counters. Closing the gate is monotone (l.down): two
// callers cannot reopen a latched gate.
//
//   - the DEVICE pump runs tun.PumpOutbound, which reads the host device,
//     validates the inner packet and hands it to the frame sink. Run starts
//     it and does not wait for it; a ReadPacket error ends the pump and is
//     discarded (there is no loop-level counter for that exit);
//   - the WRITER drains session.Poll into carrier.Send and owns the wait — it
//     is the only goroutine that reads session.NextDeadline;
//   - the READER drains carrier.Recv into session.Deliver and writes the inner
//     packets it yields to tun.Inbound. It also calls syncGate on the
//     goroutine that reaches Established, because waiting a wake for the
//     writer lost a 64-packet burst (see readLoop). The writer still syncs
//     the gate on every pass.
//
// # The two refusal policies, preserved
//
// session.Driver.Enqueue BUFFERS during the handshake and during a rekey,
// bounded by Config.SendQueue. tun's gate DROPS in every state but carrying.
// The difference is deliberate and this package preserves both rather than
// flattening either. Which applies when:
//
//   - While the loop is running, the gate is the outer valve and it closes
//     first, so in the ordinary case nothing reaches the buffer at all and the
//     buffering policy is never exercised from the tun side.
//   - The gate is not instantaneous. It is closed by the writer goroutine after
//     the state change it is reacting to, so a packet read from the device in
//     that window does reach Enqueue and is buffered. That is safe: the session
//     assembles a message only when data may flow, so a buffered packet cannot
//     be emitted under the wrong epoch — it is delayed by one ratchet round
//     trip, which is exactly what the session lane sized SendQueue for.
//   - Teardown is airtight rather than eventual. Once the session reaches a
//     terminal state, or Close is called, the gate is LATCHED down: gateState
//     never computes a carrying state again, and Gate.Set is a drain barrier,
//     so when it returns no packet is still on its way to the session or to the
//     device. That is the property users' safety rests on, and it is the one
//     that is not left to a race.
//
// Nobody should "fix" one layer to match the other. The gate is the outer
// valve; the queue is the inner buffer.
//
// # The message size is pinned to the plan floor
//
// This is the trap the carrier lane measured, and the reason this package
// builds the session rather than accepting one:
//
//	Floor(1280, UDP, TCP, TLS) = 1168     against 1252 for a dialled UDP/IPv4
//	carrier — 84 bytes that black hole every full-size flow on the FIRST
//	migration, while the tunnel still reads "up".
//
// So Config.Session.MaxMessageSize must be zero and NewClient/NewGateway refuse
// it otherwise. The size comes from Sizing, which is carrier.Floor over every
// class the session may escalate TO, never the class it dialled, and never
// session.DefaultMaxMessageSize — which is right for exactly one carrier family
// and is banned here by TestDriverNeverNamesTheDefaultMessageSize.
//
// # No policy is decided here
//
// session.NeedsCarrierChange() reports. datapath/escalation.go and
// datapath/failover.go decide. carrier.Migrate moves. This package supplies
// Observe, which is carrier.Observe over the live carrier PLUS the loop's
// own carErr when the Conn has no fatal() (Pipe has none; UDP and Stream
// do). A host that reads only Conn.fatal() misses a dead Pipe. The
// driver/dpbridge subpackage is the naming adapter from a carrier.Signal to
// the committed datapath.LinkObservation and EscalationPolicy.Evaluate. The
// verdict rules are not restated anywhere in this tree.
//
// The bridge is a SUBPACKAGE and not a file here on purpose. winn3/ is
// standalone: nothing under it may depend on datapath/, or the standalone
// protocol reacquires the dependency graph the ruling removed.
// TestDriverIsStandalone parses this package's own imports and fails on
// datapath, internal/carrier, Xray or AmneziaWG. A host that already runs the
// datapath imports the bridge; a host that does not, does not, and neither pays
// for the other.
package driver
