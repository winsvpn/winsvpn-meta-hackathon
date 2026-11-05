package main

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
)

// TestTCPIngressStopsCaptureAfterClassificationAndRetiresRejectedDriver. The
// admitted stream reads through the classification capture for its whole
// life; the capture must stop once the first flight is classified, or every
// uplink byte of the session stays in memory until the connection closes.
// A classified driver that admission then rejects must be retired (its
// session state and dual-auth key copies wiped), not dropped live.
func TestTCPIngressStopsCaptureAfterClassificationAndRetiresRejectedDriver(t *testing.T) {
	r := newReclaimRig(t, 1, nil)
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP, carrier.ClassTCP)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot open a TCP loopback listener: %v", err)
	}
	ingress := newTCPIngress(listener, r.opts.admission, r.srv.sessionCfg, sizing)
	ingress.setAdmissionGate(func() bool { return true })
	defer ingress.Close()

	raw, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	client, err := carrier.NewStream(carrier.StreamConfig{
		Conn: raw, Secret: r.opts.admission, Role: carrier.RoleClient,
		MaxMessageSize: sizing.MessageSize, PathMTU: sizing.PathMTU, TCPFirstFlight: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Send(ctx, capturedInitiation(t, r.opts.dir, r.srv.sessionCfg)); err != nil {
		t.Fatal(err)
	}
	var accepted *tcpAccepted
	select {
	case accepted = <-ingress.accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the TCP initiation was not classified")
	}

	// Uplink after classification, read by the admitted stream through the
	// capture wrapper exactly as the session loop reads it.
	const extra = 8
	payload := bytes.Repeat([]byte{0x5a}, sizing.MessageSize)
	for i := 0; i < extra; i++ {
		if err := client.Send(ctx, payload); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < extra; i++ {
		if _, err := accepted.stream.Recv(ctx); err != nil {
			t.Fatalf("Recv %d: %v", i, err)
		}
	}
	if accepted.driver.State().Terminal() {
		t.Fatal("the classified driver was terminal before admission decided")
	}

	// The admission rejection path (session cap or startPeerSession failure).
	go accepted.fallback()
	var cover net.Conn
	select {
	case cover = <-ingress.cover:
	case <-time.After(5 * time.Second):
		t.Fatal("the rejected stream was not handed to the cover")
	}
	defer cover.Close()
	replay, ok := cover.(*tcpReplayConn)
	if !ok {
		t.Fatalf("cover got %T, want *tcpReplayConn", cover)
	}
	// The cover replay is the capture: at most one first-flight record
	// (readTCPFirstFlight's own bound), never the session's later uplink.
	firstFlightMax := sizing.MessageSize + carrier.SaltSize + carrier.LengthRecordOverhead + 256 + 5
	if got := replay.prefix.Len(); got == 0 || got > firstFlightMax {
		t.Fatalf("the capture holds %d bytes, want the first flight only (1..%d): post-classification uplink was retained",
			got, firstFlightMax)
	}
	if !accepted.driver.State().Terminal() {
		t.Fatalf("the rejected driver is %s, want terminal (retired and wiped)", accepted.driver.State())
	}
}
