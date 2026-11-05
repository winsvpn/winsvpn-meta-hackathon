package session

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func queueTestPayload(d *Driver, value byte) []byte {
	return bytes.Repeat([]byte{value}, d.cfg.maxPayload()-frameHeaderSize)
}

func queueTestReceive(t *testing.T, peer *Driver, msg []byte, value byte) {
	t.Helper()
	packets, err := peer.Deliver(msg)
	if err != nil || len(packets) != 1 || !bytes.Equal(packets[0], queueTestPayload(peer, value)) {
		t.Fatalf("packet %d: count=%d err=%v", value, len(packets), err)
	}
}

func TestDataQueueBatchRetiresOnlyConsumedPrefix(t *testing.T) {
	p := stage5Pair(t)
	p.cli.cfg.SendQueue = 8
	for i := byte(1); i <= 8; i++ {
		if err := p.cli.Enqueue(queueTestPayload(p.cli, i)); err != nil {
			t.Fatal(err)
		}
	}
	storage := p.cli.data[:cap(p.cli.data)]
	consumed := append([][]byte(nil), p.cli.data[:2]...)
	output := stage5Output(p.cli, 2)
	if n, err := p.cli.PollBatchInto(output); err != nil || n != 2 {
		t.Fatalf("poll: n=%d err=%v", n, err)
	}
	if len(p.cli.data) != 6 || &p.cli.data[0] != &storage[2] {
		t.Fatal("batch drain moved the unconsumed backlog")
	}
	for i := range consumed {
		if storage[i] != nil || !bytes.Equal(consumed[i], make([]byte, len(consumed[i]))) {
			t.Fatal("consumed packet storage was not cleared")
		}
		queueTestReceive(t, p.gw, output[i], byte(i+1))
	}
	first, counter := &p.cli.data[0], p.cli.sess.SendCounter()
	short := stage5Output(p.cli, 1)
	short[0] = make([]byte, 1)
	if n, err := p.cli.PollBatchInto(short); n != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short poll: n=%d err=%v", n, err)
	}
	if len(p.cli.data) != 6 || &p.cli.data[0] != first || p.cli.sess.SendCounter() != counter {
		t.Fatal("short output changed live queue or nonce")
	}
	extra := [][]byte{queueTestPayload(p.cli, 9), queueTestPayload(p.cli, 10), queueTestPayload(p.cli, 11)}
	if n, err := p.cli.EnqueueBatch(extra); n != 2 || !errors.Is(err, ErrQueueFull) {
		t.Fatalf("partial bounded enqueue: n=%d err=%v", n, err)
	}
	for i := byte(3); i <= 10; i++ {
		msg, err := p.cli.Poll()
		if err != nil || len(msg) == 0 {
			t.Fatalf("poll %d: %v", i, err)
		}
		queueTestReceive(t, p.gw, msg, i)
	}
}

func TestDataQueueEmptyDrainReusesStorage(t *testing.T) {
	for _, batched := range []bool{false, true} {
		name := "scalar"
		if batched {
			name = "batch"
		}
		t.Run(name, func(t *testing.T) {
			p := stage5Pair(t)
			for i := byte(1); i <= 4; i++ {
				if err := p.cli.Enqueue(queueTestPayload(p.cli, i)); err != nil {
					t.Fatal(err)
				}
			}
			storage := p.cli.data[:cap(p.cli.data)]
			base := &storage[0]
			if batched {
				output := stage5Output(p.cli, 4)
				if n, err := p.cli.PollBatchInto(output); err != nil || n != 4 {
					t.Fatalf("n=%d err=%v", n, err)
				}
				for i := range output {
					queueTestReceive(t, p.gw, output[i], byte(i+1))
				}
			} else {
				for i := byte(1); i <= 4; i++ {
					msg, err := p.cli.Poll()
					if err != nil {
						t.Fatal(err)
					}
					queueTestReceive(t, p.gw, msg, i)
				}
			}
			if len(p.cli.data) != 0 || cap(p.cli.data) < 4 || &p.cli.data[:cap(p.cli.data)][0] != base {
				t.Fatal("empty FIFO lost its reusable backing storage")
			}
			for _, slot := range storage {
				if slot != nil {
					t.Fatal("empty FIFO retained a packet reference")
				}
			}
			for i := 0; i < 4; i++ {
				if err := p.cli.Enqueue(queueTestPayload(p.cli, byte(i+5))); err != nil {
					t.Fatal(err)
				}
			}
			if &p.cli.data[0] != base {
				t.Fatal("refill allocated despite reusable empty storage")
			}
		})
	}
}

func TestDataQueueCompactionPreservesPartialErrorAndOrder(t *testing.T) {
	p := stage5Pair(t)
	p.cli.cfg.SendQueue = 8
	if len(p.cli.data) != 0 {
		t.Fatal("compaction fixture requires an empty queue")
	}
	// Keep the fixture independent of implementation-specific slice growth.
	p.cli.dataBase = make([][]byte, 0, 8)
	p.cli.data = p.cli.dataBase
	for i := byte(1); i <= 8; i++ {
		if err := p.cli.Enqueue(queueTestPayload(p.cli, i)); err != nil {
			t.Fatal(err)
		}
	}
	storage := p.cli.data[:cap(p.cli.data)]
	for i := byte(1); i <= 6; i++ {
		msg, err := p.cli.Poll()
		if err != nil {
			t.Fatal(err)
		}
		queueTestReceive(t, p.gw, msg, i)
	}
	inputs := [][]byte{queueTestPayload(p.cli, 9), make([]byte, p.cli.cfg.maxPayload()+1)}
	if n, err := p.cli.EnqueueBatch(inputs); n != 1 || !errors.Is(err, ErrInnerTooLarge) {
		t.Fatalf("partial invalid enqueue: n=%d err=%v", n, err)
	}
	if len(p.cli.data) != 3 || &p.cli.data[0] != &storage[0] {
		t.Fatal("retired prefix was not reused when most storage was free")
	}
	for _, slot := range storage[3:] {
		if slot != nil {
			t.Fatal("compaction retained duplicate packet references")
		}
	}
	for i := byte(7); i <= 9; i++ {
		msg, err := p.cli.Poll()
		if err != nil {
			t.Fatal(err)
		}
		queueTestReceive(t, p.gw, msg, i)
	}
}

func TestDataQueueHeadSurvivesRekeyAndCloseClearsReferences(t *testing.T) {
	p := stage5Pair(t)
	for i := byte(1); i <= 6; i++ {
		if err := p.cli.Enqueue(queueTestPayload(p.cli, i)); err != nil {
			t.Fatal(err)
		}
	}
	msg, err := p.cli.Poll()
	if err != nil {
		t.Fatal(err)
	}
	queueTestReceive(t, p.gw, msg, 1)
	p.resetDelivered()
	if err := p.cli.startRekey(p.clk.Now()); err != nil {
		t.Fatal(err)
	}
	p.run()
	if len(p.atGw) != 5 {
		t.Fatalf("rekey delivered %d packets", len(p.atGw))
	}
	for i, packet := range p.atGw {
		if !bytes.Equal(packet, queueTestPayload(p.cli, byte(i+2))) {
			t.Fatal("rekey changed FIFO order")
		}
	}
	for i := 0; i < 3; i++ {
		if err := p.cli.Enqueue(queueTestPayload(p.cli, 9)); err != nil {
			t.Fatal(err)
		}
	}
	storage := p.cli.data[:cap(p.cli.data)]
	packets := append([][]byte(nil), p.cli.data...)
	before := p.cli.Stats().DataFramesDropped
	if err := p.cli.Close(); err != nil {
		t.Fatal(err)
	}
	if p.cli.data != nil || p.cli.Stats().DataFramesDropped-before != 3 {
		t.Fatal("close queue accounting changed")
	}
	for _, slot := range storage {
		if slot != nil {
			t.Fatal("close retained a packet reference")
		}
	}
	for _, packet := range packets {
		if !bytes.Equal(packet, make([]byte, len(packet))) {
			t.Fatal("close did not wipe queued payload")
		}
	}
	if _, err := p.cli.Poll(); err != nil {
		t.Fatal(err)
	}
	if !p.cli.State().Terminal() || p.cli.Stats().DataFramesDropped-before != 3 {
		t.Fatal("terminal transition double-counted queue drops")
	}
}

func TestDataQueueReinitiationDiscardsAndWipesOldPackets(t *testing.T) {
	p := stage5Pair(t)
	if err := p.gw.Enqueue(queueTestPayload(p.gw, 7)); err != nil {
		t.Fatal(err)
	}
	storage := p.gw.data[:cap(p.gw.data)]
	packet := p.gw.data[0]
	fresh, err := NewClient(p.cli.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fresh.mu.Lock(); fresh.terminate(); fresh.mu.Unlock() })
	initiation, err := fresh.Poll()
	if err != nil || len(initiation) == 0 {
		t.Fatalf("initiation: %v", err)
	}
	if _, err := p.gw.Deliver(initiation); err != nil {
		t.Fatal(err)
	}
	if p.gw.data != nil {
		t.Fatal("replacement session retained old queue")
	}
	for _, slot := range storage {
		if slot != nil {
			t.Fatal("replacement retained old packet reference")
		}
	}
	if !bytes.Equal(packet, make([]byte, len(packet))) {
		t.Fatal("replacement did not wipe old packet")
	}
	runResponder(t, fresh, p.gw)
	if fresh.State() != StateEstablished || p.gw.State() != StateEstablished {
		t.Fatal("replacement handshake did not establish")
	}
}
