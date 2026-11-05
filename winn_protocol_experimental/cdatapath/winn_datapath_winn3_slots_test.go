//go:build darwin

package main

import (
	"bytes"
	"testing"
	"time"
)

func TestScalarQueueSlotReadPacket(t *testing.T) {
	d := newABIDevice(1280)
	d.depth = 2
	first := ipv4Packet(t, "192.0.2.1", "192.0.2.2", 32)
	second := ipv4Packet(t, "192.0.2.1", "192.0.2.2", 40)
	for _, packet := range [][]byte{first, second} {
		if n, err := d.offer(packet); err != nil || n != len(packet) {
			t.Fatalf("offer = %d, %v", n, err)
		}
	}
	backing := d.outbound
	buf := make([]byte, len(second))
	n, err := d.ReadPacket(buf)
	if err != nil || n != len(first) || !bytes.Equal(buf[:n], first) {
		t.Fatalf("first read = %d, %v, %x", n, err, buf[:n])
	}
	if backing[0] != nil || len(d.outbound) != 1 || !bytes.Equal(d.outbound[0], second) {
		t.Fatal("retired slot must be nil and second packet must remain queued")
	}
	// ReadPacket keeps its existing truncate-and-dequeue contract.
	n, err = d.ReadPacket(buf[:8])
	if err == nil || n != 8 || !bytes.Equal(buf[:n], second[:8]) {
		t.Fatalf("short read = %d, %v, %x", n, err, buf[:n])
	}
	if backing[1] != nil || len(d.outbound) != 0 || d.droppedOutbound.Load() != 0 {
		t.Fatal("second retired slot must be nil without counting a queue drop")
	}
}

func TestScalarQueueSlotTake(t *testing.T) {
	d := newABIDevice(1280)
	d.depth = 2
	first := ipv4Packet(t, "192.0.2.1", "192.0.2.2", 32)
	second := ipv4Packet(t, "192.0.2.1", "192.0.2.2", 40)
	for _, packet := range [][]byte{first, second} {
		if n, err := d.WritePacket(packet); err != nil || n != len(packet) {
			t.Fatalf("WritePacket = %d, %v", n, err)
		}
	}
	backing := d.inbound
	buf := make([]byte, len(second))
	if n, err := d.take(buf[:8], time.Second); n != 0 || err != errWinn3TooLarge {
		t.Fatalf("short take = %d, %v", n, err)
	}
	if len(d.inbound) != 2 || !bytes.Equal(backing[0], first) || !bytes.Equal(backing[1], second) {
		t.Fatal("short destination must retain both queue slots and their order")
	}
	for i, packet := range [][]byte{first, second} {
		n, err := d.take(buf, time.Second)
		if err != nil || n != len(packet) || !bytes.Equal(buf[:n], packet) {
			t.Fatalf("take %d = %d, %v, %x", i, n, err, buf[:n])
		}
		if backing[i] != nil || len(d.inbound) != 1-i {
			t.Fatalf("take %d did not clear exactly its retired slot", i)
		}
		if i == 0 && !bytes.Equal(d.inbound[0], second) {
			t.Fatal("remaining packet changed after first take")
		}
	}
	if d.droppedInbound.Load() != 0 {
		t.Fatal("successful takes must not increment the drop counter")
	}
}

func TestScalarQueueSlotEviction(t *testing.T) {
	for _, inbound := range []bool{false, true} {
		name := "offer"
		if inbound {
			name = "WritePacket"
		}
		t.Run(name, func(t *testing.T) {
			d := newABIDevice(1280)
			d.depth = 1
			write := d.offer
			queue := &d.outbound
			if inbound {
				write = d.WritePacket
				queue = &d.inbound
			}
			first := ipv4Packet(t, "192.0.2.1", "192.0.2.2", 32)
			second := ipv4Packet(t, "192.0.2.1", "192.0.2.2", 40)
			if n, err := write(first); err != nil || n != len(first) {
				t.Fatalf("first write = %d, %v", n, err)
			}
			backing := *queue
			if n, err := write(second); err != nil || n != len(second) {
				t.Fatalf("second write = %d, %v", n, err)
			}
			if backing[0] != nil || len(*queue) != 1 || !bytes.Equal((*queue)[0], second) {
				t.Fatal("eviction must clear the old slot and retain the newest packet")
			}
			second[len(second)-1] ^= 1
			if bytes.Equal((*queue)[0], second) {
				t.Fatal("queued packet must remain independent of the caller's buffer")
			}
			wantInbound, wantOutbound := uint64(0), uint64(1)
			if inbound {
				wantInbound, wantOutbound = 1, 0
			}
			if d.droppedInbound.Load() != wantInbound || d.droppedOutbound.Load() != wantOutbound {
				t.Fatal("eviction must increment only the matching queue's drop counter once")
			}
		})
	}
}
