package main

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
)

func TestSessionDeliveryIsolatesFullPeerAndPreservesFIFO(t *testing.T) {
	s := &server{}
	newPeer := func() *peerSession {
		t.Helper()
		p, err := carrier.NewPipe(carrier.PipeConfig{Class: carrier.ClassUDP, Depth: 2})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.Close() })
		return &peerSession{pipe: p}
	}
	full, other := newPeer(), newPeer()
	from := netip.AddrPort{}
	s.deliverSessionDatagram(full, from, []byte("first"))
	s.deliverSessionDatagram(full, from, []byte("second"))
	s.deliverSessionDatagram(full, from, []byte("dropped"))
	payload := []byte("other")
	s.deliverSessionDatagram(other, from, payload)
	payload[0] = 'X'
	if st := full.pipe.Stats(); st.Delivered != 2 || st.DeliveredBytes != 11 || st.RecvErrors != 1 {
		t.Fatalf("full peer counters: %+v", st)
	}
	if st := other.pipe.Stats(); st.Delivered != 1 || st.DeliveredBytes != 5 || st.RecvErrors != 0 {
		t.Fatalf("other peer counters: %+v", st)
	}
	if got := s.refusedLogs.Load(); got != 0 {
		t.Fatalf("queue saturation counted as logged refusal: %d", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	recv := func(ps *peerSession, want string) {
		t.Helper()
		got, err := ps.pipe.Recv(ctx)
		if err != nil || !bytes.Equal(got, []byte(want)) {
			t.Fatalf("recv = %q, %v; want %q", got, err, want)
		}
	}
	recv(other, "other")
	recv(full, "first")
	s.deliverSessionDatagram(full, from, []byte("refill"))
	recv(full, "second")
	recv(full, "refill")
	if st := full.pipe.Stats(); st.Delivered != 3 || st.RecvErrors != 1 {
		t.Fatalf("refill counters: %+v", st)
	}
}
