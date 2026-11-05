package session

import (
	"encoding/binary"

	"winsvpn.local/winnprotocol/winn3/core"
)

// frameHeaderSize mirrors the core's TLV header: type(1) || len(2 BE).
//
// The core keeps it unexported, so this package carries its own copy and
// TestFrameHeaderSizeMatchesCore proves the copy is right by encoding an empty
// frame and measuring it. A silently wrong constant here would not break
// anything visibly; it would just make every message a few bytes off its padding
// target, which is a length-shaping bug that no functional test would notice.
const frameHeaderSize = 3

// chunkOffsetSize is the two-byte big-endian offset that prefixes the value of
// every PQ_EK and PQ_CT frame.
//
// It is required, not decorative. The transport tolerates reordering by design
// (that is what the token window is for), so a receiver that concatenated chunk
// values in arrival order would assemble a 1184-byte ML-KEM key out of order and
// then fail decapsulation with no idea why. An explicit offset makes reassembly
// reorder-safe and duplicate-safe, which in turn makes retransmitting the whole
// blob a legal, idempotent recovery step.
const chunkOffsetSize = 2

// CloseReason is the one-byte body of a CLOSE frame.
//
// Reasons never leave the transport AEAD, so they disclose nothing to an
// observer. They exist because the peer can act on them: a CloseDesynchronised
// tells the far end to stop waiting out its own liveness budget and re-handshake
// now, which halves the outage from a burst loss beyond the token window.
type CloseReason uint8

const (
	// CloseNormal is an orderly application shutdown. It is the only reason
	// that does not call for a new session.
	CloseNormal CloseReason = iota + 1

	// CloseDesynchronised means burst loss beyond the receive token window: the
	// sender can no longer be placed and the direction is unrecoverable.
	CloseDesynchronised

	// CloseRekeyFailed means an in-band rekey exchange did not complete.
	CloseRekeyFailed

	// ClosePQFailed means the post-quantum ratchet did not complete.
	ClosePQFailed

	// CloseCounterExhausted means the hard message ceiling was reached.
	CloseCounterExhausted

	// CloseProtocolError means the peer sent something this state machine
	// cannot accept.
	CloseProtocolError

	// CloseDualAuthFailed means the dual-signature session attestation did not
	// arrive or did not verify (docs/DUAL_SIGNATURE_SPEC.md). Fail closed: a
	// client that required the attestation closes rather than proceed on one
	// signature family. Appended LAST so it never renumbers a wire reason.
	CloseDualAuthFailed

	// CloseRekeyUnconfirmed means this end committed to the rekeyed epoch by
	// sealing the REKEY_ACK, and the peer never confirmed the new epoch inside
	// the RekeyTimeout bound (a dropped ACK, or a censor holding it). The
	// peer's CLOSE under the old epoch is unopenable to it, so this is the
	// local fail-loud half of F-03. Appended LAST so it never renumbers a
	// wire reason.
	CloseRekeyUnconfirmed
)

func (c CloseReason) String() string {
	switch c {
	case CloseNormal:
		return "normal"
	case CloseDesynchronised:
		return "desynchronised"
	case CloseRekeyFailed:
		return "rekey-failed"
	case ClosePQFailed:
		return "pq-failed"
	case CloseDualAuthFailed:
		return "dual-auth-failed"
	case CloseRekeyUnconfirmed:
		return "rekey-unconfirmed"
	case CloseCounterExhausted:
		return "counter-exhausted"
	case CloseProtocolError:
		return "protocol-error"
	}
	return "unknown"
}

// NeedsNewSession reports whether this reason means the peer should re-handshake
// rather than give up.
func (c CloseReason) NeedsNewSession() bool { return c != CloseNormal }

// pendingFrame is one frame waiting for a message to ride in.
//
// after runs once the frame has been sealed into a message, and only then. It
// is how a ratchet is made to happen at exactly the right point in the stream:
// the PQ_CT sender and the REKEY_ACK sender must ratchet AFTER their last
// message under the old epoch is on the wire, never before, or the message they
// just built becomes unopenable by the peer.
// wide is the size-aware liveness signal's only wire-visible mechanism: a frame
// marked wide forces the message carrying it to be sealed to the session's full
// message ceiling instead of to a padding bucket. See Driver.tickEstablished.
type pendingFrame struct {
	typ   core.FrameType
	value []byte
	after func() error
	wide  bool
}

// encodedSize is what this frame costs inside a message.
func (p pendingFrame) encodedSize() int { return frameHeaderSize + len(p.value) }

// chunkBlob splits a large value into PQ frames that each fit one message.
//
// Chunk payloads are equal-sized rather than greedily packed. Equal sizing means
// the chunk count depends only on the blob length and the carrier's message
// size, so a peer cannot infer anything from the split, and a retransmission
// produces byte-identical chunks.
func chunkBlob(t core.FrameType, blob []byte, maxValue int) []pendingFrame {
	per := maxValue - chunkOffsetSize
	if per < 1 {
		per = 1
	}
	var out []pendingFrame
	for off := 0; off < len(blob); off += per {
		end := off + per
		if end > len(blob) {
			end = len(blob)
		}
		v := make([]byte, chunkOffsetSize+(end-off))
		binary.BigEndian.PutUint16(v[:chunkOffsetSize], uint16(off))
		copy(v[chunkOffsetSize:], blob[off:end])
		out = append(out, pendingFrame{typ: t, value: v})
	}
	return out
}

// blobRx reassembles a chunked PQ blob.
//
// Coverage is tracked per byte rather than per chunk so that a duplicate or
// overlapping chunk is idempotent instead of an error. That is what lets the
// sender retransmit the entire blob on a timeout without the receiver having to
// know whether it is a retransmission — which matters, because the sender cannot
// tell which chunk was lost and the receiver cannot tell the sender.
type blobRx struct {
	buf     []byte
	covered []bool
	n       int
}

func newBlobRx(total int) *blobRx {
	return &blobRx{buf: make([]byte, total), covered: make([]bool, total)}
}

// accept folds one chunk in and reports whether the blob is now complete.
//
// A malformed chunk is a protocol error, not a silent drop: it arrived inside
// the transport AEAD, so it came from the peer and nothing else. Being lenient
// here would create a parsing differential between implementations, and a
// parsing differential is a fingerprint.
func (b *blobRx) accept(value []byte) (bool, error) {
	if len(value) < chunkOffsetSize+1 {
		return false, wrap(ErrProtocol, "pq chunk is %d bytes, needs an offset and at least one byte", len(value))
	}
	off := int(binary.BigEndian.Uint16(value[:chunkOffsetSize]))
	data := value[chunkOffsetSize:]
	if off+len(data) > len(b.buf) {
		return false, wrap(ErrProtocol, "pq chunk at %d runs %d bytes past the %d-byte blob", off, off+len(data)-len(b.buf), len(b.buf))
	}
	copy(b.buf[off:], data)
	for i := off; i < off+len(data); i++ {
		if !b.covered[i] {
			b.covered[i] = true
			b.n++
		}
	}
	return b.n == len(b.buf), nil
}

func (b *blobRx) complete() bool { return b.n == len(b.buf) }
func (b *blobRx) bytes() []byte  { return b.buf }

// closeFrame builds a CLOSE frame value.
func closeFrame(reason CloseReason) pendingFrame {
	return pendingFrame{typ: core.FrameClose, value: []byte{byte(reason)}}
}

// padFrame is a cover frame with no content. Padding inside the AEAD is what
// core.Session.Seal already does with a target length, so this exists only so
// that a message emitted purely as cover carries an explicit, parseable frame
// rather than an empty payload that a reader would have to guess about.
func padFrame() pendingFrame {
	return pendingFrame{typ: core.FramePad, value: nil}
}

// pingFrame builds a liveness probe. wide asks for it to ride a full-size
// message, which is what makes the probe able to detect a path that carries
// small messages and black holes large ones.
func pingFrame(token [pingTokenSize]byte, wide bool) pendingFrame {
	v := make([]byte, pingTokenSize)
	copy(v, token[:])
	return pendingFrame{typ: core.FramePing, value: v, wide: wide}
}

// pongFrame answers a probe. wide is inherited from the message the PING
// arrived in, so that a wide probe proves BOTH directions carry a full-size
// message rather than only the outbound one.
func pongFrame(token []byte, wide bool) pendingFrame {
	v := make([]byte, len(token))
	copy(v, token)
	return pendingFrame{typ: core.FramePong, value: v, wide: wide}
}
