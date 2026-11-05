package core

import (
	"encoding/binary"
	"io"
)

// Frames are the contents of a transport message's plaintext.
//
// A type byte and a length are perfectly acceptable HERE, unlike anywhere on
// the wire, because everything in this file lives inside the transport AEAD. To
// an observer a keepalive, a rekey and a 1400-byte download are the same
// object, differing only in total length — which the driver's padding policy
// shapes.
//
// This codec is deliberately minimal. The frame DRIVER — the loop that decides
// when to emit a PING, when to ratchet, and how much to pad — is not in this
// package and is the first item on the outstanding list in the design document.

// FrameType identifies a frame. Zero is reserved and invalid so that a
// zero-filled buffer never parses as a valid frame stream.
type FrameType uint8

const (
	_ FrameType = iota // 0: reserved, never valid

	// FrameData carries one inner IP packet.
	FrameData

	// FramePad is filler. It is never delivered upward. It exists so that a
	// message can be emitted with no real content at all, which is what a
	// cover packet is.
	FramePad

	// FramePing and FramePong are liveness, NAT-binding maintenance and RTT
	// sampling.
	//
	// They are frames rather than dedicated packets on purpose. The measured
	// failure they replace is a 25.000-second zero-jitter keepalive: a
	// periodogram spike that identifies the protocol from timing alone, with no
	// packet inspection at all. A PING that rides inside an ordinary transport
	// message, padded by the same policy as data, leaves no keepalive-sized
	// packet to count.
	//
	// The driver's obligations, which this codec cannot enforce: fire on a
	// SILENCE timer measured from the last packet sent, not on a schedule, so
	// an active flow never emits one; and redraw the threshold from a truncated
	// exponential after every fire, because a memoryless distribution is the
	// one an observer learns least from.
	FramePing
	FramePong

	// FramePQEK and FramePQCT carry the ML-KEM-768 ratchet (Session.MixPQ).
	FramePQEK
	FramePQCT

	// FrameRekeyInit and FrameRekeyAck carry fresh X25519 ephemerals for the
	// in-band epoch ratchet (Session.Rekey).
	FrameRekeyInit
	FrameRekeyAck

	// FrameClose is orderly teardown. It is an ordinary frame in an ordinary
	// message, so a closing session does not look different from a busy one.
	FrameClose

	// FrameDualAuthED and FrameDualAuthML carry the dual-signature session
	// attestation (docs/DUAL_SIGNATURE_SPEC.md). ED is the 64-byte Ed25519
	// signature; ML is the 3309-byte ML-DSA-65 signature, chunked like PQ
	// blobs. Appended AFTER FrameClose so every pre-existing frame keeps its
	// wire number. Only ever emitted to clients that announced the dual-auth
	// capability in the handshake flags; any other receiver treats them as a
	// protocol error, fail-closed.
	FrameDualAuthED
	FrameDualAuthML
)

// frameHeaderSize is type(1) || length(2 BE).
const frameHeaderSize = 3

// MaxFrameValue is what the length field can express.
const MaxFrameValue = 65535

// Frame is one decoded frame. Value aliases the buffer it was parsed from.
type Frame struct {
	Type  FrameType
	Value []byte
}

// AppendFrame encodes one frame onto dst.
func AppendFrame(dst []byte, t FrameType, value []byte) ([]byte, error) {
	if t == 0 {
		return nil, errWrap(ErrConfig, "frame type 0 is reserved")
	}
	if len(value) > MaxFrameValue {
		return nil, errWrap(ErrPayloadTooLarge, "frame value is %d bytes, limit %d", len(value), MaxFrameValue)
	}
	var hdr [frameHeaderSize]byte
	hdr[0] = byte(t)
	binary.BigEndian.PutUint16(hdr[1:], uint16(len(value)))
	dst = append(dst, hdr[:]...)
	dst = append(dst, value...)
	return dst, nil
}

// ParseFrames decodes a complete frame stream.
//
// It is strict: a trailing partial frame, a zero type, or a length that runs
// past the buffer is an error and the whole message is discarded. Leniency here
// would be a parsing differential between implementations, and a parsing
// differential is a fingerprint.
func ParseFrames(b []byte) ([]Frame, error) {
	return parseFrames(nil, b, true)
}

// ParseFramesInto decodes into caller-owned frame slots without allocating.
// An insufficient frame capacity returns io.ErrShortBuffer, with no frames.
func ParseFramesInto(dst []Frame, b []byte) ([]Frame, error) {
	return parseFrames(dst[:0], b, false)
}

func parseFrames(out []Frame, b []byte, allocate bool) ([]Frame, error) {
	for len(b) > 0 {
		if len(b) < frameHeaderSize {
			return nil, errWrap(ErrDecrypt, "trailing %d bytes are not a frame header", len(b))
		}
		t := FrameType(b[0])
		if t == 0 {
			return nil, errWrap(ErrDecrypt, "frame type 0 is reserved")
		}
		n := int(binary.BigEndian.Uint16(b[1:frameHeaderSize]))
		if frameHeaderSize+n > len(b) {
			return nil, errWrap(ErrDecrypt, "frame claims %d bytes but only %d remain", n, len(b)-frameHeaderSize)
		}
		if !allocate && len(out) == cap(out) {
			return nil, io.ErrShortBuffer
		}
		out = append(out, Frame{Type: t, Value: b[frameHeaderSize : frameHeaderSize+n : frameHeaderSize+n]})
		b = b[frameHeaderSize+n:]
	}
	return out, nil
}
