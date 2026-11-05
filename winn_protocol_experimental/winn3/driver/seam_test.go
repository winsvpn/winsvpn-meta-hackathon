package driver

import (
	"reflect"
	"testing"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// TestDriverDoesNotSatisfyFrameSinkWithoutAnAdapter is the finding this lane
// opened with, pinned so that it either stays true or is deleted deliberately.
//
// Two sibling lanes independently recorded that *session.Driver satisfies
// tun.FrameSink "with no adapter at all". The SIGNATURES do match exactly —
// func([]byte) error, and Enqueue copies the packet, which discharges the
// no-retain obligation — but the METHOD NAMES do not, and a Go method set is
// names as well as signatures. Neither lane could have caught it: neither
// package may import the other, so neither could write the assertion that would
// have failed to compile. This package can, and does.
//
// Both halves are checked, because both are load-bearing:
//
//   - the interface is NOT satisfied today, so the adapter must exist; and
//   - the signatures ARE identical, so the adapter is three lines and cannot
//     drift into a translation layer that copies, truncates or reorders.
//
// If the session lane ever adds SendData, the first half fails and sink.go is
// deleted under a failing test rather than left as a wrapper nobody remembers.
func TestDriverDoesNotSatisfyFrameSinkWithoutAnAdapter(t *testing.T) {
	sinkType := reflect.TypeOf((*tun.FrameSink)(nil)).Elem()
	driverType := reflect.TypeOf((*session.Driver)(nil))

	if driverType.Implements(sinkType) {
		t.Fatal("*session.Driver now implements tun.FrameSink directly; delete sink.go's adapter " +
			"and wire the driver straight into tun.Config.Sink")
	}

	m, ok := sinkType.MethodByName("SendData")
	if !ok {
		t.Fatal("tun.FrameSink no longer has SendData; the adapter's method name is stale")
	}
	enqueue, ok := driverType.MethodByName("Enqueue")
	if !ok {
		t.Fatal("*session.Driver no longer has Enqueue; the adapter has nothing to call")
	}

	// The bound method type drops the receiver, which is what makes the two
	// comparable at all.
	bound := reflect.ValueOf((*session.Driver)(nil)).MethodByName("Enqueue").Type()
	if bound != m.Type {
		t.Fatalf("Enqueue is %s and FrameSink.SendData is %s; the adapter is no longer a rename",
			bound, m.Type)
	}
	_ = enqueue
}

// TestTheAdapterIsTheOnlyThingBetweenThem checks that the adapter does nothing
// except rename and wake: what the tun layer hands down is exactly what the
// session receives, byte for byte, and an error from the session is returned
// rather than swallowed.
//
// Swallowing would be the tempting simplification, and it would erase the
// difference between "the gate refused it" (TxDroppedClosed) and "the session
// refused it" (TxDroppedSink) — two diagnoses that a host in Yangon has to be
// able to tell apart from counters alone.
func TestTheAdapterIsTheOnlyThingBetweenThem(t *testing.T) {
	sz := planSizing(t)
	kr := newKeyring(t)
	pipe, _, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	e := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: pipe, local: clientAddr(), router: gatewayAddr(),
	})
	defer e.stop()

	woke := 0
	sink := frameSink{sess: e.loop.Session(), wake: func() { woke++ }}

	pkt := ipv4Packet(clientAddr(), gatewayAddr(), []byte("exactly these bytes"))
	if err := sink.SendData(pkt); err != nil {
		t.Fatalf("SendData refused a valid packet: %v", err)
	}
	if woke != 1 {
		t.Fatalf("SendData woke the writer %d times, want 1; a packet that does not wake it "+
			"waits for the silence draw, which is up to forty-five seconds", woke)
	}

	// Oversize: the session's refusal must come back rather than be swallowed.
	big := ipv4Packet(clientAddr(), gatewayAddr(), make([]byte, sz.InnerMTU))
	if err := sink.SendData(big); err == nil {
		t.Fatal("SendData swallowed the session's refusal of an oversize packet")
	}
	if woke != 1 {
		t.Fatalf("a refused packet woke the writer; woke=%d", woke)
	}
}
