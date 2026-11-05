package driver

import (
	"errors"

	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// frameSink is the seam between winn3/tun and winn3/session, and it is three
// lines because of a claim that turned out to be one word wrong.
//
// Both sibling lanes recorded that *session.Driver satisfies tun.FrameSink
// "with no adapter at all":
//
//	tun:      type FrameSink interface { SendData(pkt []byte) error }
//	session:  func (d *Driver) Enqueue(inner []byte) error
//
// The SIGNATURES are identical — one []byte in, one error out, and Enqueue
// copies the packet, which discharges FrameSink's no-retain obligation. The
// METHOD NAMES are not, and in Go a method set is names as well as signatures,
// so *session.Driver does not implement tun.FrameSink and never did. Neither
// lane could have caught it: neither package may import the other, so neither
// could write the assertion that would have failed to compile.
//
// TestDriverDoesNotSatisfyFrameSinkWithoutAnAdapter checks BOTH halves by
// reflection — that the names differ today, and that the signatures match — so
// if the session lane ever renames or adds the method this file is deleted
// under a failing test rather than left behind as a wrapper nobody remembers.
//
// The wake is the second reason this type exists rather than a bare method
// value. A packet that reaches the send queue and does not wake the writer waits
// for the session's next deadline, which on an established idle session is a
// silence draw of up to forty-five seconds. That is a tunnel that appears to
// work and delivers the first packet of every new connection a minute late.
type frameSink struct {
	sess *session.Driver
	wake func()
}

// SendData implements tun.FrameSink.
//
// It does not swallow Enqueue's error. ErrQueueFull and ErrInnerTooLarge are
// counted by the tun layer as TxDroppedSink, which is the evidence a host needs
// to tell "the session refused it" from "the gate was closed" — two very
// different diagnoses that a merged counter would make indistinguishable.
func (s frameSink) SendData(pkt []byte) error {
	if err := s.sess.Enqueue(pkt); err != nil {
		if errors.Is(err, session.ErrState) {
			return tun.ErrNotCarrying
		}
		return err
	}
	s.wake()
	return nil
}

// SendDataBatch implements tun.BatchFrameSink.
func (s frameSink) SendDataBatch(pkts [][]byte) (int, error) {
	n, err := s.sess.EnqueueBatch(pkts)
	if n > 0 {
		s.wake()
	}
	if err != nil && errors.Is(err, session.ErrState) {
		return n, tun.ErrNotCarrying
	}
	return n, err
}

// The adapter must satisfy the interfaces it exists for. If this assertion ever
// becomes redundant it is because *session.Driver grew SendData, which the
// reflection test reports.
var _ tun.FrameSink = frameSink{}
var _ tun.BatchFrameSink = frameSink{}

// The loop reads the session through the same three-method view the carrier
// package does, so that the escalation signal cannot silently narrow.
var _ carrierReporter = (*session.Driver)(nil)

// carrierReporter mirrors carrier.Reporter without importing it into the type
// of anything exported here.
type carrierReporter interface {
	NeedsCarrierChange() bool
	NeedsNewSession() bool
	State() session.State
	PathNarrowed() bool
}
