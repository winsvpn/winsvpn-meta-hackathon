// Package carrier moves Winn3 messages between two endpoints.
//
// It is the last layer under winn3/session. The core produces byte strings, the
// session decides when they are produced, the tun layer decides what goes in
// them, and this package puts them on a socket and takes them off again. It
// holds no keys of the session, parses nothing it carries, and makes no policy
// decision about which transport to use.
//
// # The contract
//
// §4.2 of the standalone design fixes the interface at four methods:
//
//	Send(ctx, msg) error
//	Recv(ctx) ([]byte, error)
//	MaxMessageSize() int
//	Close() error
//
// Carrier is exactly that. Conn adds the three things a live migration and a
// policy layer need — Class, SetMaxMessageSize and Stats — and every carrier
// here implements it.
//
// # Why a TCP carrier is not optional
//
// The measured failure this package exists to answer is one iptables line:
// `-p udp -j DROP`. Against v3 as committed it produced 24 retries and 100 %
// loss, because the datapath had one transport. Blocking UDP wholesale is the
// cheapest move a censor has, and a protocol that dies to it has no censorship
// story at all. So a stream carrier ships alongside the datagram one, and it is
// built here rather than borrowed: neither AmneziaWG nor Xray appears in this
// package's import graph, and reaching for either would be the downgrade the
// standalone ruling exists to prevent.
//
// # The stream rule, and why the length is encrypted
//
// A datagram carrier preserves message boundaries for free. A stream carrier
// has to restore them, and the obvious way — write the length in front of the
// message — hands a censor the one thing the message format was built to
// remove. A two-byte cleartext length at a fixed offset in every record is a
// readable segmentation oracle: it lets an observer walk the stream record by
// record, count messages, measure the length distribution and confirm the
// protocol without holding any key. It is failure F1 rebuilt one layer down.
//
// §4.2 is therefore normative and this package obeys it verbatim:
//
//	A stream carrier MUST NOT write a cleartext length prefix. It MUST encrypt
//	each length under a separate key and nonce sequence derived from the
//	session — AEAD(k_len, n_i, uint16 len), 2 bytes of plaintext and 18 on the
//	wire — so that the record boundary is not readable and cannot be used to
//	segment the stream.
//
// See length.go for the key schedule, and §2 of the handoff for the one place
// this implementation had to depart from the literal wording of the rule: the
// first record on a stream carries the handshake initiation, so at that instant
// there is no session to derive from, and the key comes from the gateway
// admission secret both ends already hold.
//
// # Fingerprint discipline
//
// The two measured tells in the stack this replaces were a fleet-wide constant
// at a fixed offset in every initiation, and a keepalive at exactly 25.000
// seconds with zero jitter. Both are classes, not instances, and a carrier is a
// comfortable place to reintroduce either by accident. Four rules hold the line,
// each with a test that is fed a violation and required to object:
//
//   - One Write per message. The sealed length and the message go out in a
//     single write on a single buffer. Writing them separately would put an
//     18-byte TCP segment in front of every message, fleet-wide — a constant
//     expressed as a segment size instead of as bytes.
//   - Nothing is ever written unbidden. These carriers have no ticker, no
//     keepalive and no probe of their own; keepalives are PING frames inside
//     ordinary messages and belong to the session. A byte leaves a carrier only
//     because Send was called.
//   - The per-connection salt rides the first Send rather than the accept. A
//     gateway that wrote 16 bytes on accept would answer an unauthenticated TCP
//     connection, which is the probe oracle §4.3 spends the whole design
//     closing. Deferring it also keeps the first segment variable-length,
//     because the initiation it shares a write with is padded by a uniform draw.
//   - Reconnect delay is exponential with full jitter and a hard attempt cap
//     (§4.2). A fixed reconnect interval is the 25.000-second metronome wearing
//     a different hat, and the failure the session lane caught in its own
//     silence timer — a clamped exponential parking ~28 % of a fleet on exactly
//     5.000 s — is available here too. Backoff.Delay draws uniformly on the open
//     interval and TestBackoffHasNoAtomAtTheCap proves the atom is absent by
//     running the clamping implementation and requiring the detector to object.
//
// # Sizing, and the trap
//
// MaxMessageSize bounds the Winn3 message; the carrier then wraps it, and it is
// the wrapped packet that has to fit the path. This package never uses
// session.DefaultMaxMessageSize — that constant is correct for UDP over IPv6 and
// for nothing else, and a stream carrier is off by 64 bytes. Every size here
// comes from session.MaxMessageSizeForPath with an overhead this package
// derives from the carrier class and the resolved address family.
//
// The trap the tun lane named: size the session to the carrier it dialled and
// the first UDP→TLS failover silently black holes every full-size flow while the
// tunnel still reports "up". Small packets work, large transfers stall, and the
// report comes from a country where nobody can attach a debugger. Floor is the
// answer — the narrowest MaxMessageSize across every class the session may
// migrate to, across both address families — and it is the number the driver and
// the tun device should both be built with. Migrating then needs no size change
// at all, which is a second win: a message-size distribution that shifts at the
// instant of a migration links the flow before it to the flow after it.
//
// SetMaxMessageSize exists for when the floor could not be known in advance.
// It refuses a size below the session floor or above the path ceiling.
// Widening inside that range is allowed, and on a stream it raises the
// receive ceiling, because a peer already authorised to send the larger size
// must still be able to (TestWideningRaisesTheReceiveCeiling). Migrate does
// not widen the session: a destination that can carry more than the session
// emits is left alone, so the size distribution does not jump at the moment
// of the move. Migrate refuses outright to move a session onto a narrower
// carrier it cannot tell.
//
// # No policy
//
// Choosing the next carrier class is not done here. Observe reports what the
// driver says (NeedsCarrierChange) and what the carrier has seen, and returns
// both without a recommendation. datapath/escalation.go computes the verdict and
// datapath/failover.go acts on it; duplicating either would give the fleet two
// disagreeing opinions about when to move.
//
// # The caller's loop
//
//	c, err := carrier.DialUDP(ctx, carrier.UDPConfig{
//	    Remote:         gw,
//	    MaxMessageSize: carrier.Floor(pathMTU, carrier.ClassUDP, carrier.ClassTLS),
//	})
//	...
//	for {
//	    for {
//	        msg, err := d.Poll()
//	        if err != nil || msg == nil { break }
//	        if err := c.Send(ctx, msg); err != nil { ... }
//	    }
//	    if sig := carrier.Observe(d, c); sig.NeedsChange { /* ask the policy layer */ }
//	    msg, err := c.Recv(ctx)
//	    ...
//	}
package carrier
