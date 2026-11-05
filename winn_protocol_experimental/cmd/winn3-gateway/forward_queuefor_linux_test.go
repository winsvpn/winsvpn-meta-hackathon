//go:build linux

package main

import (
	"encoding/binary"
	"math/rand"
	"os"
	"testing"
)

// flowPacket builds an IPv4 TCP or UDP packet of a flow with a chosen IP ID,
// TTL, length and payload byte, so that everything varies except the flow.
func flowPacket(proto byte, src, dst [4]byte, sport, dport uint16, id uint16, ttl byte, payload int, fill byte) []byte {
	p := make([]byte, 20+8+payload)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:], id)
	p[8], p[9] = ttl, proto
	copy(p[12:], src[:])
	copy(p[16:], dst[:])
	binary.BigEndian.PutUint16(p[20:], sport)
	binary.BigEndian.PutUint16(p[22:], dport)
	for i := 28; i < len(p); i++ {
		p[i] = fill
	}
	return p
}

// TestQueueForIsStablePerUnfragmentedFlow establishes (forward_linux.go
// queueFor) that every unfragmented packet of a TCP or UDP flow maps to the
// same queue whatever its IP ID, TTL, length or payload: the queue count is
// fixed at startup and the hash reads only the source and the ports.
func TestQueueForIsStablePerUnfragmentedFlow(t *testing.T) {
	s := &sharedGatewayTun{files: make([]*os.File, 4)}
	rng := rand.New(rand.NewSource(1))
	for flow := 0; flow < 2000; flow++ {
		proto := byte(6)
		if flow%2 == 1 {
			proto = 17
		}
		src := [4]byte{10, 64, 0, byte(rng.Intn(256))}
		dst := [4]byte{byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}
		sport, dport := uint16(rng.Intn(65536)), uint16(rng.Intn(65536))
		want := s.queueFor(flowPacket(proto, src, dst, sport, dport, 1, 64, 0, 0))
		for k := 0; k < 20; k++ {
			pkt := flowPacket(proto, src, dst, sport, dport, uint16(rng.Intn(65536)), byte(rng.Intn(256)), rng.Intn(1300), byte(rng.Intn(256)))
			if got := s.queueFor(pkt); got != want {
				t.Fatalf("flow %d (proto %d): packet mapped to queue %d, first packet to %d", flow, proto, got, want)
			}
		}
	}
}

// TestQueueForCanSplitAFragmentedFlow documents why fragments take the
// barrier path: a non-first fragment carries payload where the ports would be,
// so queueFor can place it on another queue than the rest of its flow.
func TestQueueForCanSplitAFragmentedFlow(t *testing.T) {
	s := &sharedGatewayTun{files: make([]*os.File, 4)}
	src, dst := [4]byte{10, 64, 0, 2}, [4]byte{93, 184, 216, 34}
	flowQ := s.queueFor(flowPacket(17, src, dst, 40000, 443, 7, 64, 100, 0))
	split := false
	for fill := 0; fill < 256 && !split; fill++ {
		frag := flowPacket(17, src, dst, 0, 0, 7, 64, 100, byte(fill))
		// A non-first fragment: offset 1480 and bytes 20..23 are payload.
		frag[6], frag[7] = 0x00, 0xb9
		for i := 20; i < 28; i++ {
			frag[i] = byte(fill)
		}
		if s.queueFor(frag) != flowQ {
			split = true
		}
	}
	if !split {
		t.Fatal("no payload placed a fragment on another queue; the barrier's premise would be false")
	}
}
