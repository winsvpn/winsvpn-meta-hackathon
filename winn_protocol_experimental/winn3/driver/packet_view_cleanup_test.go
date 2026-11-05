package driver

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
)

func TestPacketViewCleanupAfterConsumersAndShortBatch(t *testing.T) {
	cli, gw := packetViewPair(t)
	msgs, slots := newReceiveBatchStorage(1402)
	packets := [][]byte{
		ipv4Packet(clientAddr(), gatewayAddr(), []byte{1}),
		ipv4Packet(clientAddr(), gatewayAddr(), []byte{2}),
		ipv4Packet(clientAddr(), gatewayAddr(), []byte{3}),
		ipv4Packet(clientAddr(), gatewayAddr(), []byte{4}),
	}
	messages := [][]byte{packetViewMessage(t, cli.loop.sess, packets[:3]...), packetViewMessage(t, cli.loop.sess, packets[3])}
	for i, m := range messages {
		msgs[i].N = copy(msgs[i].Payload, m)
	}
	prepareReceiveBatchSlots(msgs, slots, 2, 1402)
	views0, views1 := slots[0].Packets[:cap(slots[0].Packets)], slots[1].Packets[:cap(slots[1].Packets)]
	gw.dev.block.Store(true)
	finished := make(chan error, 1)
	go func() { finished <- gw.loop.deliverReceiveBatch(slots[:2]) }()
	select {
	case <-gw.dev.writing:
	case <-time.After(2 * time.Second):
		t.Fatal("consumer did not start")
	}
	if len(slots[0].Packets) != 3 || !bytes.Equal(slots[0].Packets[0], packets[0]) {
		t.Fatal("views missing before synchronous consumer returned")
	}
	close(gw.dev.release)
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("delivery did not finish")
	}
	for _, want := range packets {
		if got := gw.dev.take(t, time.Second); !bytes.Equal(got, want) {
			t.Fatal("consumer bytes or order changed")
		}
	}
	assertPacketViewsCleared(t, slots[:2], views0, views1)
	backing := &slots[0].Scratch[0]
	msgs[0].N = copy(msgs[0].Payload, packetViewMessage(t, cli.loop.sess, packets[0]))
	prepareReceiveBatchSlots(msgs, slots, 1, 1402)
	if err := gw.loop.deliverReceiveBatch(slots[:1]); err != nil {
		t.Fatal(err)
	}
	if got := gw.dev.take(t, time.Second); !bytes.Equal(got, packets[0]) {
		t.Fatal("short batch changed payload")
	}
	assertPacketViewsCleared(t, slots[:2], views0, views1)
	if &slots[0].Scratch[0] != backing || cap(slots[0].Packets) != len(views0) {
		t.Fatal("cleanup discarded reusable storage")
	}
}

func TestPacketViewCleanupControlPrefixAndTerminalReturn(t *testing.T) {
	cli, gw := packetViewPair(t)
	before := ipv4Packet(clientAddr(), gatewayAddr(), []byte{1})
	after := ipv4Packet(clientAddr(), gatewayAddr(), []byte{2})
	first := packetViewMessage(t, cli.loop.sess, before)
	unused := packetViewMessage(t, cli.loop.sess, after)
	if err := cli.loop.sess.Close(); err != nil {
		t.Fatal(err)
	}
	closeMsg, err := cli.loop.sess.Poll()
	if err != nil || len(closeMsg) == 0 {
		t.Fatalf("normal CLOSE output: %v", err)
	}
	msgs, slots := newReceiveBatchStorage(1402)
	for i, msg := range [][]byte{first, closeMsg, unused} {
		msgs[i].N = copy(msgs[i].Payload, msg)
	}
	prepareReceiveBatchSlots(msgs, slots, 3, 1402)
	views := make([][][]byte, 3)
	for i := range views {
		views[i] = slots[i].Packets[:cap(slots[i].Packets)]
	}
	if err := gw.loop.deliverReceiveBatch(slots[:3]); !errors.Is(err, session.ErrClosed) {
		t.Fatalf("terminal suffix return = %v, want ErrClosed", err)
	}
	if got := gw.dev.take(t, time.Second); !bytes.Equal(got, before) {
		t.Fatal("data prefix changed")
	}
	if len(gw.dev.out) != 0 || gw.loop.Carrying() || gw.loop.sess.PeerCloseReason() != session.CloseNormal {
		t.Fatal("normal CLOSE did not stop suffix delivery and close gate")
	}
	assertPacketViewsCleared(t, slots[:3], views...)
	// A terminal session returns before inspecting inputs. Owned synthetic views
	// verify that the cleanup also covers that early return and the entire suffix.
	for i := 0; i < 3; i++ {
		slots[i].Packets = append(slots[i].Packets, []byte{byte(i + 1)})
	}
	if err := gw.loop.deliverReceiveBatch(slots[:3]); !errors.Is(err, session.ErrClosed) {
		t.Fatal("terminal session did not return ErrClosed")
	}
	assertPacketViewsCleared(t, slots[:3], views...)
}

func assertPacketViewsCleared(t *testing.T, slots []session.ReceiveSlot, backings ...[][]byte) {
	t.Helper()
	for i, backing := range backings {
		if len(slots[i].Packets) != 0 {
			t.Fatalf("slot %d still exposes packet views", i)
		}
		for j, view := range backing {
			if view != nil {
				t.Fatalf("slot %d view %d retained a reference", i, j)
			}
		}
	}
}

func packetViewMessage(t *testing.T, d *session.Driver, packets ...[]byte) []byte {
	t.Helper()
	for _, p := range packets {
		if err := d.Enqueue(p); err != nil {
			t.Fatal(err)
		}
	}
	m, err := d.Poll()
	if err != nil || len(m) == 0 {
		t.Fatalf("valid DATA output: %v", err)
	}
	return m
}

func packetViewPair(t *testing.T) (*endpoint, *endpoint) {
	t.Helper()
	left, right, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP, PathMTU: carrier.DefaultPathMTU})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	sz, kr, clk := planSizing(t), newKeyring(t), newStepClock()
	cli := newClientEndpoint(t, kr, endpointOpts{sizing: sz, carrier: left, clock: clk, local: clientAddr(), router: gatewayAddr()})
	gw := newGatewayEndpoint(t, kr, endpointOpts{sizing: sz, carrier: right, clock: clk, local: gatewayAddr(), router: clientAddr()})
	t.Cleanup(cli.stop)
	t.Cleanup(gw.stop)
	for step := 0; step < 20; step++ {
		for _, pair := range [][2]*Loop{{cli.loop, gw.loop}, {gw.loop, cli.loop}} {
			msg, err := pair[0].sess.Poll()
			if err != nil {
				t.Fatal(err)
			}
			if len(msg) != 0 {
				if _, err := pair[1].sess.Deliver(msg); err != nil {
					t.Fatal(err)
				}
			}
			pair[0].syncGate()
			pair[1].syncGate()
		}
		if cli.loop.Carrying() && gw.loop.Carrying() {
			return cli, gw
		}
	}
	t.Fatal("valid fixture handshake did not establish")
	return nil, nil
}
