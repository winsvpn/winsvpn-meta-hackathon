package session

import (
	"errors"
	"testing"
	"time"
)

// TestAnAbandonedHandshakeGetsNoLateDatagram: a peer that sends a valid
// initiation, receives the response and then says nothing must hear nothing
// more from the gateway. The gateway drops the half-open session when its
// handshake budget expires, and before this it did so with a CLOSE: one
// datagram at a constant 23.5 s after the response, which L22b measured 7 of 7
// times and which an on-path observer can provoke without any key.
func TestAnAbandonedHandshakeGetsNoLateDatagram(t *testing.T) {
	p := newPair(t, nil)
	p.drain()   // the client's initiation
	p.deliver() // the gateway reads it
	sent := 0
	for {
		msg, err := p.gw.Poll()
		if err != nil {
			t.Fatal(err)
		}
		if msg == nil {
			break
		}
		sent++
	}
	if sent != 1 {
		t.Fatalf("the gateway emitted %d messages for one initiation, want the one response", sent)
	}
	if p.gw.State() != StateInitiating || p.gw.Epoch() != 0 {
		t.Fatalf("fixture: gateway is %s at epoch %d, want initiating at epoch 0", p.gw.State(), p.gw.Epoch())
	}

	// The client is gone. Walk the gateway's clock well past its budget.
	late := 0
	for i := 0; i < 60 && !p.gw.State().Terminal(); i++ {
		p.clk.Advance(time.Second)
		for {
			msg, err := p.gw.Poll()
			if err != nil {
				t.Fatal(err)
			}
			if msg == nil {
				break
			}
			late++
		}
	}
	if !p.gw.State().Terminal() {
		t.Fatalf("the gateway held the half-open session forever; state %s", p.gw.State())
	}
	if late != 0 {
		t.Fatalf("the gateway sent %d datagram(s) to a peer that abandoned the handshake", late)
	}
	if got := p.gw.LocalCloseReason(); got != ClosePQFailed {
		t.Errorf("close reason is %s, want %s", got, ClosePQFailed)
	}
	if err := p.gw.Err(); !errors.Is(err, ErrPQFailed) {
		t.Errorf("error is %v, want ErrPQFailed", err)
	}
}
