package core

import "io"

// This file is the seam an external demultiplexer needs, and deliberately
// nothing more than that.
//
// The problem it solves is stated in docs/handoff/WINN3_GATEWAY_TABLE_20260808.md
// §2.1 and §7. A gateway that terminates many thousands of sessions cannot
// afford to search every session for every arriving datagram, so it builds ONE
// index from token to session. But core.Session also precomputes the same
// tokens privately, and neither side can see the other's copy, so at ten
// thousand sessions the forward window is held twice: 479 MiB measured, where
// 117 MiB would do. Half of that bill is a duplicate of the other half.
//
// The two methods here remove the duplicate. RecvDemuxKey lets the index
// compute the same token sequence the session would have recognised; OpenAt
// lets the session be driven by that index instead of by its own copy, so the
// copy can be switched off with CallerOwnsTokenWindow.
//
// # What did NOT move, and will not
//
// Only the LOOKUP moves out. The replay filter stays in the session.
//
// The §7 sketch proposed that "the caller then owns replay", and that is the
// one thing here that departs from it. The reason is that a replay filter which
// lives in the caller is a replay filter that does not exist as soon as one
// caller has one bug — and the caller in question is a table doing concurrent
// registration, eviction and rekey re-basing, which is precisely where its own
// handoff records finding a lifetime race (§8, bug 1). Anti-replay is a
// property of the session's key material, so it belongs with the key material.
//
// This costs nothing worth having. What made core's window expensive was the
// map from token to counter — measured at 37.5 to 51.8 bytes per token — not
// the filter, which is one byte per counter. Keeping the filter and dropping
// the map keeps the guarantee and still collects essentially all of the saving.
//
// It also cannot break the caller. The retained filter is sized at
// DefaultTokenWindow (1024) while a gateway index runs at 256 or below, so the
// caller's window is still the binding constraint and
// TestTheGatewayWindowIsTheBindingConstraint keeps meaning what it meant.

// RecvDemuxKey returns a COPY of the receive-direction demux key for the
// current epoch, together with the epoch that key belongs to.
//
// It exists so that an in-process index can precompute exactly the tokens Open
// would have recognised:
//
//	token(counter) = HMAC-SHA256(key, "winn3 demux v1" || be64(counter))[:8]
//
// The epoch is returned with the key and is not decoration. Every ratchet
// installs a fresh demux key and restarts the counter at zero, so a token
// sequence is only meaningful for the epoch it was derived in; an index that
// does not re-base at a ratchet will drop every subsequent packet. Read the
// pair, and treat a change in the epoch as "discard and rebuild".
//
// # This key MUST NOT leave the process
//
// It is not an AEAD key and it decrypts nothing. What it does is name packets:
// anyone holding it can recognise every datagram of this session's receive
// direction on the wire, for the life of the epoch. That is the exact
// unlinkability the demux construction exists to provide, so a copy of this key
// in a log, a metrics label, a crash dump or a control-plane message is a
// session-linking oracle handed to whoever reads it.
//
// It is returned by value so that the caller may zero its own copy, and so that
// no caller can reach into the session's.
//
// This is an accessor, not a capability: it authenticates nothing, and holding
// it does not let anyone open, forge or replay a message. See OpenAt for what
// does decide those questions.
func (s *Session) RecvDemuxKey() (key [KeySize]byte, epoch uint32) {
	// Acquire order is sendMu -> recvMu -> chainMu, so recvMu then chainMu is
	// legal. Both are needed: the key and the epoch it belongs to must be read
	// across a ratchet as one value, or an index can be rebuilt with an old key
	// under a new epoch number and silently drop everything.
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	if s.wiped {
		return
	}
	return s.recvDemux, s.epoch
}

// HoldsToken reports whether token is in the receive window and unconsumed.
func (s *Session) HoldsToken(token []byte) bool {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	if s.wiped || s.recvWindow == nil || !s.recvWindow.indexed() {
		return false
	}
	_, ok := s.recvWindow.lookup(token)
	return ok
}

// OpenAt decrypts one transport message whose counter an external index has
// already resolved.
//
// It is Open with the lookup supplied from outside. Everything else — the
// nonce, the AEAD, the inner length check, the replay consumption, the byte
// accounting — is the identical code path, because both call
// openCounterLocked.
//
// # What the counter is
//
// The counter is a HINT ABOUT WHERE TO LOOK. It is never a claim that the
// message is genuine, and this method extends the caller no trust whatsoever on
// that question:
//
//   - It selects the nonce (salt || be64(counter)). If it is not the counter
//     the sender actually used, the AEAD fails. That is the whole check.
//   - The token as it arrived is the AAD, unmodified and unverified against the
//     counter. It is NOT re-derived and compared, for two reasons. It would add
//     an HMAC to the hot path and prove nothing the AEAD is not already
//     proving; and making a non-AEAD equality test part of an accept decision is
//     exactly the shape doc.go's non-goal forbids — the acceptance of a message
//     must rest on the AEAD alone, so that deleting everything around it leaves
//     the core as sound as it was.
//   - It is bounded by this session's own window before it is used at all, so a
//     caller cannot name an arbitrary point in the counter space.
//
// A caller passing an attacker-chosen counter therefore gains exactly one
// thing: a failed open. It cannot decrypt anything, it cannot cause a message
// to be attributed to a counter that did not produce it, and — because a
// message that fails to open consumes nothing — it cannot burn a counter slot
// that a genuine message is still going to need.
//
// # Replay
//
// The session's own filter decides, not the caller's. A counter outside the
// window, or one already consumed by a message that opened, is refused here
// even if the caller offers it a thousand times. Handing this method a
// deliberately broken index that re-offers consumed counters forever does not
// produce a single duplicate delivery.
//
// # Nonces
//
// OpenAt never seals, so it cannot create a (key, nonce) pair; nonce reuse is a
// property of the send side and is pinned by
// TestNonceIsNeverReusedAcrossEpochs. What a caller-supplied counter COULD have
// broken is the receive-side counterpart of that invariant, and this method
// holds it: at most one message is ever accepted per (key, nonce) pair, because
// the counter is consumed on success and every later message naming it is
// refused. Two distinct ciphertexts are never both accepted under one nonce.
//
// # Errors
//
// A counter outside the window, a counter already consumed, and a counter this
// session has never reached all return ErrUnauthenticated — the same error, for
// the same reason Open gives one error for an unknown token, a replay and
// noise. The caller must not be able to build an oracle out of the distinction,
// and in any case nothing is ever written back.
//
// It works on any session. With the default configuration the session still
// holds its own index and OpenAt simply bypasses the lookup, which is what
// makes the two paths differentially testable against each other. With
// CallerOwnsTokenWindow the index is gone and OpenAt is the only way in.
func (s *Session) OpenAt(msg []byte, counter uint64) ([]byte, error) {
	if len(msg) < TransportOverhead() {
		return nil, ErrShortMessage
	}

	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	if s.wiped || s.recvAEAD == nil || s.recvWindow == nil {
		return nil, ErrWiped
	}

	if !s.recvWindow.holds(counter) {
		return nil, ErrUnauthenticated
	}

	return s.openCounterLocked(msg, counter)
}

// OpenAtInto decrypts one transport message using an externally supplied counter
// into caller-owned storage dst without allocating memory.
func (s *Session) OpenAtInto(dst, msg []byte, counter uint64) ([]byte, error) {
	if len(msg) < TransportOverhead() {
		return nil, ErrShortMessage
	}

	if cap(dst) < len(msg)-DemuxTokenSize-AEADTagSize {
		return nil, io.ErrShortBuffer
	}

	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	if s.wiped || s.recvAEAD == nil || s.recvWindow == nil {
		return nil, ErrWiped
	}

	if !s.recvWindow.holds(counter) {
		return nil, ErrUnauthenticated
	}

	return s.openIntoCounterLocked(dst, msg, counter, false)
}
