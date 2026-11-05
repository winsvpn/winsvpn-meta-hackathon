package driver

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
)

func TestReceiveStorageLazySlotsAndReuse(t *testing.T) {
	const capacity = 1402
	msgs, slots := newReceiveBatchStorage(capacity)
	if len(msgs) != session.MaxBatchSize || len(slots) != len(msgs) {
		t.Fatal("batch slot count changed")
	}
	for i := range msgs {
		if len(msgs[i].Payload) != capacity || slots[i].Scratch != nil || slots[i].Packets != nil {
			t.Fatalf("slot %d: wire buffer missing or unused receive backing allocated", i)
		}
		msgs[i].N = 40
	}
	prepareReceiveBatchSlots(msgs, slots, 0, capacity)
	prepareReceiveBatchSlots(msgs, slots, 2, capacity)
	for i := 0; i < 2; i++ {
		if len(slots[i].Scratch) != capacity || cap(slots[i].Packets) != capacity/3 || len(slots[i].Message) != 40 {
			t.Fatalf("slot %d: returned storage not prepared at carrier ceiling", i)
		}
	}
	if &slots[0].Scratch[0] == &slots[1].Scratch[0] || &slots[0].Scratch[0] == &msgs[0].Payload[0] {
		t.Fatal("distinct input/plaintext slots alias")
	}
	view0, view1 := slots[0].Packets[:1], slots[1].Packets[:1]
	if &view0[0] == &view1[0] {
		t.Fatal("packet-list slots alias")
	}
	backing0, backing1 := &slots[0].Scratch[0], &slots[1].Scratch[0]
	for i := 2; i < len(slots); i++ {
		if slots[i].Scratch != nil || slots[i].Packets != nil {
			t.Fatalf("unused slot %d allocated", i)
		}
	}
	prepareReceiveBatchSlots(msgs, slots, 1, capacity)
	prepareReceiveBatchSlots(msgs, slots, 3, capacity)
	if &slots[0].Scratch[0] != backing0 || &slots[1].Scratch[0] != backing1 || slots[2].Scratch == nil {
		t.Fatal("previous slots not reused or newly used slot not initialized")
	}
	if allocs := testing.AllocsPerRun(5, func() {
		prepareReceiveBatchSlots(msgs, slots, 3, capacity)
	}); allocs != 0 {
		t.Fatalf("warmed preparation allocated %v times", allocs)
	}
}

func TestReceiveStorageCapacityReset(t *testing.T) {
	for _, capacity := range []int{1402, 1200, 65535, 1402} {
		msgs, slots := newReceiveBatchStorage(capacity)
		want := min(session.MaxBatchSize, max(1, (2*1024*1024)/(10*capacity)))
		if len(msgs) != want || len(slots) != want {
			t.Fatalf("capacity %d: slot budget changed", capacity)
		}
		for i := range slots {
			if slots[i].Scratch != nil || slots[i].Packets != nil || cap(msgs[i].Payload) != capacity {
				t.Fatalf("capacity %d: reset retained old storage", capacity)
			}
		}
		msgs[0].N = 20
		prepareReceiveBatchSlots(msgs, slots, 1, capacity)
		if cap(slots[0].Scratch) != capacity || cap(slots[0].Packets) != capacity/3 {
			t.Fatalf("capacity %d: used slot has wrong new ceiling", capacity)
		}
	}
}

// Embedding Conn hides Pipe's batch extension while retaining its in-memory IO.
type receiveStorageScalarCarrier struct {
	carrier.Conn
	mu      sync.Mutex
	first   *byte
	reads   int
	changed bool
}

func (c *receiveStorageScalarCarrier) RecvInto(ctx context.Context, dst []byte) ([]byte, error) {
	c.mu.Lock()
	if len(dst) != 65535 {
		c.changed = true
	} else if c.first == nil {
		c.first = &dst[0]
	} else if c.first != &dst[0] {
		c.changed = true
	}
	c.reads++
	c.mu.Unlock()
	msg, err := c.Conn.Recv(ctx)
	if err != nil {
		return nil, err
	}
	return dst[:copy(dst, msg)], nil
}

func TestReceiveStorageValidInMemoryDeliveryAndClose(t *testing.T) {
	for _, scalar := range []bool{false, true} {
		name := "batch"
		if scalar {
			name = "scalar-into"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			left, right, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP, PathMTU: carrier.DefaultPathMTU})
			if err != nil {
				t.Fatal(err)
			}
			defer left.Close()
			defer right.Close()
			var leftCarrier carrier.Conn = left
			var scalarCarrier *receiveStorageScalarCarrier
			if scalar {
				scalarCarrier = &receiveStorageScalarCarrier{Conn: left}
				leftCarrier = scalarCarrier
			}
			sz, kr, clk := planSizing(t), newKeyring(t), newStepClock()
			cli := newClientEndpoint(t, kr, endpointOpts{sizing: sz, carrier: leftCarrier, clock: clk, local: clientAddr(), router: gatewayAddr()})
			gw := newGatewayEndpoint(t, kr, endpointOpts{sizing: sz, carrier: right, clock: clk, local: gatewayAddr(), router: clientAddr()})
			defer cli.stop()
			defer gw.stop()
			cli.start(ctx)
			gw.start(ctx)
			waitFor(t, 5*time.Second, "both gates carrying", func() bool { return cli.loop.Carrying() && gw.loop.Carrying() })
			for i := byte(1); i <= 2; i++ {
				request := ipv4Packet(clientAddr(), gatewayAddr(), []byte{i, 2, 3, 4})
				cli.dev.offer(t, request)
				if got := gw.dev.take(t, 2*time.Second); !bytes.Equal(got, request) {
					t.Fatal("batch delivery changed bytes or order")
				}
				response := ipv4Packet(gatewayAddr(), clientAddr(), []byte{4, 3, 2, i})
				gw.dev.offer(t, response)
				if got := cli.dev.take(t, 2*time.Second); !bytes.Equal(got, response) {
					t.Fatal("return delivery changed bytes or order")
				}
			}
			if err := cli.loop.Close(); err != nil {
				t.Fatal(err)
			}
			if err := cli.waitRun(3 * time.Second); err != nil {
				t.Fatal(err)
			}
			if err := gw.waitRun(3 * time.Second); err != nil {
				t.Fatal(err)
			}
			if cli.loop.Carrying() || gw.loop.Carrying() || gw.loop.Session().PeerCloseReason() != session.CloseNormal {
				t.Fatal("close control failed to latch gates down or reach peer")
			}
			if scalarCarrier != nil {
				scalarCarrier.mu.Lock()
				defer scalarCarrier.mu.Unlock()
				if scalarCarrier.reads < 2 || scalarCarrier.changed {
					t.Fatal("scalar scratch size or reuse changed")
				}
			}
		})
	}
}
