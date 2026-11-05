// Package session is the frame-level session driver for standalone Winn v3.
//
// The core package (winn3/core) does the cryptography: it turns key material
// into handshake messages and transport messages and back. It contains no
// policy at all — no timer, no socket, no retry schedule, no padding decision.
// Its author's summary was "crypto done, policy engine not". This package is
// the policy engine.
//
// # What it owns
//
//   - the session state machine: initiating, established, rekeying, closing
//   - frame multiplexing inside the transport AEAD: DATA, PAD, PING/PONG,
//     PQ_EK/PQ_CT, REKEY_INIT/REKEY_ACK, CLOSE
//   - the silence timer that replaces the measured 25.000-second zero-jitter
//     keepalive
//   - the padding policy: per-session bucket draws, or a carrier-supplied mimic
//   - the post-quantum ratchet and the in-band rekey ratchet, driven as frames
//   - detection of, and the response to, burst loss beyond the token window
//
// # What it deliberately does not own
//
// No sockets. No timers. No goroutines. The driver is a pure function of
// (queued inner packets, arriving messages, the clock) onto (outgoing messages,
// delivered inner packets, state). The caller owns the carrier and the wait.
//
// This is not fastidiousness. The measured failure this protocol replaces —
// UDP blocked wholesale, 24 retries, 100% loss — is only fixable if a carrier
// can be swapped underneath a live session, and a session that owns a socket
// cannot be. And a timing policy that lives in two layers is a timing policy
// that will disagree with itself; the 25.000-second metronome was exactly a
// timer in the wrong layer. TestSessionHasNoTimersOrSockets greps this
// package's own source to hold the line, the same way the core does.
//
// # The caller's loop
//
//	for {
//	    // 1. drain everything the driver wants on the wire
//	    for {
//	        msg, err := d.Poll()
//	        if err != nil { ... }
//	        if msg == nil { break }
//	        carrier.Send(ctx, msg)
//	    }
//	    if d.State().Terminal() { break }
//
//	    // 2. block until a message arrives or the driver's next deadline,
//	    //    whichever comes first. The driver never wakes itself.
//	    select {
//	    case msg := <-fromCarrier:
//	        inner, err := d.Deliver(msg)
//	        if err != nil { ... } // ErrClosed, ErrPathMTUMismatch, local WriteResponse failure
//	        if d.State().Terminal() { break } // protocol errors close without returning err
//	        for _, p := range inner { tun.Write(p) }
//	    case <-until(d.NextDeadline()):
//	    }
//	}
//
// Enqueue, Poll and Deliver are safe to call concurrently.
//
// # Nothing periodic and nothing distinctive
//
// Three separate mechanisms in this package exist only to keep the wire free of
// a clock an observer can lock onto, and each is held by a test that is fed a
// metronome and required to object:
//
//   - Keepalives ride a SILENCE timer. It measures time since the last packet
//     THIS side sent and fires only if that exceeds a threshold, so an active
//     flow never emits one. The threshold is redrawn after every fire from a
//     truncated exponential, sampled by inverse CDF so that there is no
//     probability atom at the truncation bounds. Clamping a draw to [min,max]
//     would put a point mass at exactly min and exactly max — a fixed value
//     recurring fleet-wide, which is the same failure class as the metronome,
//     only sparser. See jitter.go.
//   - Rekey is in band, as REKEY_INIT/REKEY_ACK frames inside the current
//     epoch's transport AEAD. There is no recurring handshake packet. The time
//     trigger for it is drawn from the same truncated exponential, never fixed.
//   - The post-quantum ratchet is in band too, as PQ_EK/PQ_CT frames, so the
//     characteristic 1184/1088-byte ML-KEM pair never appears as a packet size.
//
// # Burst loss beyond the token window
//
// §6.10 of the design records an acknowledged regression: an implicit counter
// cannot recover from a burst loss larger than the receiver's forward window.
// This package's answer is stated in full in the handoff document and
// summarised here because a reader of the code deserves it in the code:
//
//	The answer is TEARDOWN AND RE-HANDSHAKE. It is not recovery and it is not
//	a rekey, and neither of those is available.
//
//	Recovery is not available because any "here is my counter" message would
//	have to be recognisable to a receiver that by construction cannot open
//	anything from that sender, so it would have to be a new plaintext-
//	distinguishable message class — which is failure F1, the exact thing the
//	format exists to remove.
//
//	Rekey is not available because REKEY_INIT travels inside the current
//	epoch's AEAD, and the desynchronised receiver cannot open it. Rekey is
//	unavailable precisely when it would be needed. The reverse direction
//	cannot rescue it either: whichever end sends REKEY_INIT, the ACK has to
//	come back through the dead direction.
//
// So the driver detects the condition and tears the session down. Detection is
// liveness-based, never error-based: a run of unopenable messages is NOT the
// signal, because injected noise produces exactly that and would hand an
// off-path attacker a teardown primitive. The signal is unanswered PING probes
// while the peer is expected to be alive.
//
// One thing does make the teardown cheaper, and it is why CLOSE carries a
// reason. Desynchronisation is per direction. The end that detects it usually
// still has a working outbound direction, so it sends a best-effort
// CLOSE(CloseDesynchronised) before terminating. The peer opens it and tears
// down at once instead of waiting out its own probe budget. If the outbound
// direction is dead too the CLOSE is simply never received and the peer falls
// back to its own budget. No new packet class is involved: CLOSE is an
// ordinary frame in an ordinary message, so a session dying looks exactly like
// a session working.
package session
