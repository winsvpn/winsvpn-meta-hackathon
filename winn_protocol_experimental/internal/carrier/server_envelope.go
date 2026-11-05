package carrier

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultSequenceWindow = 4096
	defaultSessionLimit   = 100000
)

type sessionWindow struct {
	highest uint64
	seen    map[uint64]struct{}
	updated time.Time
}

// SessionDeduplicator suppresses encrypted AWG duplicates created during a
// bounded two-carrier handoff. The AWG replay window remains a second layer of
// defense; this cache prevents needless backend work before packets reach it.
type SessionDeduplicator struct {
	mu       sync.Mutex
	max      int
	window   uint64
	sessions map[string]*sessionWindow
}

func NewSessionDeduplicator(maxSessions, sequenceWindow int) (*SessionDeduplicator, error) {
	if maxSessions < 1 || maxSessions > 1_000_000 ||
		sequenceWindow < 64 || sequenceWindow > 1_000_000 {
		return nil, errors.New("carrier deduplication limits are invalid")
	}
	return &SessionDeduplicator{
		max: maxSessions, window: uint64(sequenceWindow),
		sessions: make(map[string]*sessionWindow),
	}, nil
}

func (d *SessionDeduplicator) Accept(sessionID string, sequence uint64, now time.Time) bool {
	if d == nil || sessionID == "" || sequence == 0 {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	state := d.sessions[sessionID]
	if state == nil {
		if len(d.sessions) >= d.max {
			var oldestID string
			var oldest time.Time
			for id, candidate := range d.sessions {
				if oldestID == "" || candidate.updated.Before(oldest) {
					oldestID, oldest = id, candidate.updated
				}
			}
			delete(d.sessions, oldestID)
		}
		state = &sessionWindow{seen: make(map[uint64]struct{})}
		d.sessions[sessionID] = state
	}
	state.updated = now
	if sequence+d.window <= state.highest {
		return false
	}
	if _, duplicate := state.seen[sequence]; duplicate {
		return false
	}
	state.seen[sequence] = struct{}{}
	if sequence > state.highest {
		state.highest = sequence
	}
	floor := uint64(0)
	if state.highest > d.window {
		floor = state.highest - d.window
	}
	for value := range state.seen {
		if value <= floor {
			delete(state.seen, value)
		}
	}
	return true
}

type synchronizedFrameWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (writer *synchronizedFrameWriter) WriteEnvelope(encoded []byte, maximum int) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if err := writeFrame(writer.writer, encoded, maximum); err != nil {
		return err
	}
	if flusher, ok := writer.writer.(interface{ Flush() }); ok {
		flusher.Flush()
	}
	return nil
}

func h2EnvelopesToUDP(reader io.Reader, writer *synchronizedFrameWriter, backend *net.UDPConn, sessionID string, maxInner, maxOuter int, deduplicator *SessionDeduplicator) error {
	buffer := make([]byte, maxOuter)
	for {
		count, err := readFrameInto(reader, buffer, maxOuter)
		if err != nil {
			return err
		}
		frame, err := decodeEnvelope(buffer[:count], maxInner)
		clear(buffer[:count])
		if err != nil {
			return err
		}
		switch frame.kind {
		case envelopeData:
			if deduplicator != nil && !deduplicator.Accept(sessionID, frame.sequence, time.Now().UTC()) {
				continue
			}
			if _, err := backend.Write(frame.payload); err != nil {
				return err
			}
		case envelopeProbe:
			ack, err := encodeEnvelope(envelopeProbeAck, frame.sequence, nil, count)
			if err != nil {
				return err
			}
			err = writer.WriteEnvelope(ack, maxOuter)
			clear(ack)
			if err != nil {
				return err
			}
		case envelopeCover:
			continue
		default:
			return errors.New("client sent an invalid carrier control envelope")
		}
	}
}

func udpToH2Envelopes(writer *synchronizedFrameWriter, backend *net.UDPConn, maxInner, maxOuter int, sequence *atomic.Uint64, privacyPadding bool) error {
	buffer := make([]byte, maxInner+1)
	for {
		count, err := backend.Read(buffer)
		if err != nil {
			return err
		}
		if count > maxInner {
			clear(buffer[:count])
			return ErrDatagramTooLarge
		}
		outerSize := envelopeHeaderSize + count
		if privacyPadding {
			outerSize = privacyBucket(outerSize, maxOuter)
		}
		encoded, err := encodeEnvelope(envelopeData, sequence.Add(1), buffer[:count], outerSize)
		clear(buffer[:count])
		if err != nil {
			return err
		}
		err = writer.WriteEnvelope(encoded, maxOuter)
		clear(encoded)
		if err != nil {
			return err
		}
	}
}

// privacyBucket pads a server-to-client datagram the same way the client pads
// in the other direction. It shares paddedSize with the client, including the
// pad-to-maximum fall-through, so neither direction can be the one that still
// carries true lengths.
func privacyBucket(minimum, maximum int) int {
	return paddedSize(minimum, defaultPaddingBuckets(), maximum)
}
