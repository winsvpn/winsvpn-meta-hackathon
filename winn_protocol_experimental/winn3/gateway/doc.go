// Package gateway is the server-side dispatch for standalone Winn Protocol v3:
// the structure that lets one gateway serve many clients.
//
// # The problem this package exists to solve
//
// A Winn3 transport message is
//
//	DemuxToken(8) || AEAD( frames || padding )
//
// and that is the whole header. There is no session index, no counter, no type
// byte, no length and no version, because every one of those is a constant a
// censor can fingerprint. The consequence lands here: an arriving datagram
// carries nothing that names the session it belongs to. The gateway cannot read
// a session id off the wire, so it must precompute a forward window of expected
// demux tokens for every session and look the arriving token up.
//
// That single fact drives every decision below.
//
// # Four properties, held deliberately
//
// 1. An unauthenticated datagram costs approximately nothing. The hot path for
// a datagram nobody can authenticate is one shard-local map lookup, a load of a
// counter, and a drop: no allocation, no key material touched, no per-source
// state created, no asymmetric operation, no reply. The expensive path — the
// handshake admission check, which un-whitens the body and computes an HMAC —
// is reached only after that lookup misses, and is metered by a fixed-size
// work budget (see guard.go) so that a flood cannot buy more of the gateway's
// CPU than the operator has decided to sell. Nothing an unauthenticated peer
// sends allocates a byte of long-lived memory.
//
// 2. Precomputation is bought with proof of key possession, never with
// assertions. A registered session does not get its full token window; it gets
// InitialWindow tokens and earns the rest by opening messages that actually
// authenticate. The gateway's memory therefore tracks demonstrated use rather
// than claimed sessions, which is what closes the “can an attacker force
// unbounded precomputation” question at this layer — the crypto layer having
// already been checked and found bounded.
//
// 3. Silence on every rejection path. Every rejection in this package returns
// an error to the *caller* and nothing at all to the *peer*. Dispatch has no
// return channel by construction: Handle returns a reply only for a fresh
// initiation that authenticated under the gateway's admission key, and every
// other path returns a nil reply. There is no cookie, no error datagram, no
// distinguishable close. A cookie reply is a probe oracle by construction, and
// without the replay refusal a captured initiation would be a permanent gateway
// detector.
//
// 4. Degradation is a decision. Memory is finite and the token window is the
// bill (see the arithmetic in the handoff document). This package carries an
// explicit token budget. When it is reached, windows stop growing; when
// sessions are exhausted, the idlest are evicted; when there is nothing left to
// give, a new session is refused — silently, like everything else. It does not
// grow without limit and it does not crash.
//
// # What this package does not do
//
// It holds no socket and no timer. Time arrives as a parameter, so the tests
// are deterministic and there is no sleep anywhere in them. The carrier owns
// the socket; the session driver owns the frame policy; this package owns
// dispatch, admission metering, the token index, and eviction.
//
// # The seam to core, and the memory it used to cost
//
// core.Session kept its own private receive window and did its own token lookup
// inside Open, so a gateway that indexes tokens globally held the window twice:
// once in core's private per-session map and once in the global index. That
// doubled the §6.9 memory bill. The seam is now closed from both ends.
//
// core.Session.RecvDemuxKey lets a KeyedSource compute exactly the tokens Open
// would have recognised, which makes the production Binder one line (see
// gateway.go). core.Session.OpenAt takes the counter this package's index has
// already resolved, which is the OpenerAt interface in token.go — and once the
// session is driven that way its own copy of the window is dead weight, so the
// core.Config that built it may set core.CallerOwnsTokenWindow and never build
// it. Measured, at ten thousand sessions with a 256-token gateway window: 479
// MiB before, 127 MiB after.
//
// Three things about that are worth knowing before changing any of it.
//
// The choice belongs to whoever writes the core.Config, not to this package.
// The table drives any Opener that implements OpenerAt through OpenAt, whatever
// window its session was configured with, so the two cannot disagree in the
// direction that hurts: a caller-owned session is never asked to look up a token
// it no longer has. The opposite mismatch — a caller-owned session reaching this
// table as a plain Opener — fails every packet of that session in silence, and
// Entry.OpenerAt exists so that it can be seen from outside.
//
// Anti-replay did NOT move out of core, deliberately, and must not be
// reimplemented here. What was expensive was the map from token to counter, not
// the filter, which is one byte per counter; a filter living in a table that
// does concurrent registration, eviction and rekey re-basing stops existing the
// first time that code has a bug. The 1024-wide filter core keeps is wider than
// any window this package runs, so this package's window remains the binding
// constraint, exactly as before.
//
// The counter this package hands to OpenAt is a hint about where to look and
// never a claim about authenticity. It is not checked here, and the token is not
// re-derived from it and compared, because that would make a non-AEAD equality
// test part of an accept decision — the named non-goal in core/doc.go.
package gateway
