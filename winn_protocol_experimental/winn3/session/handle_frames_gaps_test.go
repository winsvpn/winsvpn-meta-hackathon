package session

import (
	"testing"

	"winsvpn.local/winnprotocol/winn3/core"
)

// TestHandleFramesGapsAdversarialValues is the value-layer table
// TestMalformedControlFramesCloseTheSession is not. That test covers short
// and long PING/PONG/CLOSE and a short REKEY_INIT. It does not cover an
// empty PING (ParseFrames accepts it), a CLOSE reason of 0, or the
// REKEY_ACK / REKEY_INIT asymmetry: a malformed ACK is ignored unless a
// rekey is pending, while a malformed INIT is always a protocol error
// because NewPublicKey runs before the state check.
func TestHandleFramesGapsAdversarialValues(t *testing.T) {
	cases := []struct {
		name      string
		frame     core.Frame
		wantClose bool
	}{
		{"empty ping token", core.Frame{Type: core.FramePing, Value: nil}, true},
		{"empty ping token empty slice", core.Frame{Type: core.FramePing, Value: []byte{}}, true},
		{"ping token one byte short of 8", core.Frame{Type: core.FramePing, Value: make([]byte, pingTokenSize-1)}, true},
		{"empty rekey init", core.Frame{Type: core.FrameRekeyInit, Value: nil}, true},
		{"rekey init 31 bytes", core.Frame{Type: core.FrameRekeyInit, Value: make([]byte, 31)}, true},
		{"rekey init 33 bytes", core.Frame{Type: core.FrameRekeyInit, Value: make([]byte, 33)}, true},
		// After establish, rekeyPend is false, so onRekeyAck returns nil
		// before NewPublicKey. A stray malformed ACK must not tear the
		// session down; a change that started closing here would be a
		// mixed-version fingerprint against this build.
		{"empty rekey ack while not rekeying is ignored", core.Frame{Type: core.FrameRekeyAck, Value: nil}, false},
		{"short rekey ack while not rekeying is ignored", core.Frame{Type: core.FrameRekeyAck, Value: []byte{1, 2, 3}}, false},
		{"close reason 0 is still a one-byte CLOSE", core.Frame{Type: core.FrameClose, Value: []byte{0}}, true},
		{"close reason 255 is still a one-byte CLOSE", core.Frame{Type: core.FrameClose, Value: []byte{255}}, true},
		{"empty pad is cover", core.Frame{Type: core.FramePad, Value: nil}, false},
		{"unknown type is ignored", core.Frame{Type: core.FrameType(200), Value: []byte("later")}, false},
		{"well-formed ping is answered, not closed", core.Frame{Type: core.FramePing, Value: make([]byte, pingTokenSize)}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
			p.establish()
			if _, err := p.gw.handleFrames(p.clk.Now(), []core.Frame{tc.frame}, false); err != nil {
				t.Fatalf("handleFrames returned %v (it must close via beginClose, not a returned error)", err)
			}
			closed := p.gw.State() != StateEstablished
			if closed != tc.wantClose {
				t.Fatalf("state=%s closed=%v, want closed=%v", p.gw.State(), closed, tc.wantClose)
			}
		})
	}
}

// TestHandleFramesCloseReasonZeroIsRecorded pins that a one-byte CLOSE
// whose reason is 0 is not a parse failure: the session terminates and
// peerReason is 0 ("unknown"). Collapsing reason 0 into CloseProtocolError
// would be a behaviour change, not a bugfix, and must be deliberate.
func TestHandleFramesCloseReasonZeroIsRecorded(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	p.establish()
	if _, err := p.gw.handleFrames(p.clk.Now(), []core.Frame{{Type: core.FrameClose, Value: []byte{0}}}, false); err != nil {
		t.Fatal(err)
	}
	if p.gw.PeerCloseReason() != 0 {
		t.Fatalf("PeerCloseReason=%d, want 0", p.gw.PeerCloseReason())
	}
	// terminate() lands in StateClosed. beginClose(CloseProtocolError) would
	// land in StateClosing. Treating reason 0 as malformed would take the
	// latter path and this would fail.
	if p.gw.State() != StateClosed {
		t.Fatalf("state=%s, want closed", p.gw.State())
	}
}

// TestHandleFramesEmptyDataIsDelivered pins that an empty FrameData is a
// zero-length inner packet at this layer, not a protocol error. tun.parsePacket
// refuses it later. Closing here would drop a mixed-version peer that emitted
// an empty data frame as cover-shaped padding.
func TestHandleFramesEmptyDataIsDelivered(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) { quietConfig(cli); quietConfig(gw) })
	p.establish()
	out, err := p.gw.handleFrames(p.clk.Now(), []core.Frame{{Type: core.FrameData, Value: nil}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || len(out[0]) != 0 {
		t.Fatalf("delivered %v, want one empty packet", out)
	}
	if p.gw.State() != StateEstablished {
		t.Fatalf("empty data tore the session down: %s", p.gw.State())
	}
}
