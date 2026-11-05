package session

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"testing"

	"winsvpn.local/winnprotocol/winn3/core"
)

func stage5Pair(t *testing.T) *pair {
	p := newPair(t, func(a, z *Config) { a.Padding = core.PadNone; z.Padding = core.PadNone })
	p.establish()
	t.Cleanup(func() {
		p.cli.mu.Lock()
		p.cli.terminate()
		p.cli.mu.Unlock()
		p.gw.mu.Lock()
		p.gw.terminate()
		p.gw.mu.Unlock()
	})
	return p
}

func stage5Output(d *Driver, n int) [][]byte {
	x := make([][]byte, n)
	for i := range x {
		x[i] = make([]byte, 0, d.cfg.MaxMessageSize)
	}
	return x
}

func stage5Input(msgs ...[]byte) []ReceiveSlot {
	x := make([]ReceiveSlot, len(msgs))
	for i, msg := range msgs {
		x[i] = ReceiveSlot{Message: msg, Scratch: bytes.Repeat([]byte{0xa5}, len(msg)), Packets: make([][]byte, 0, len(msg)/frameHeaderSize)}
	}
	return x
}

func stage5Message(t *testing.T, d *Driver, typ core.FrameType, data []byte) []byte {
	t.Helper()
	f, err := core.AppendFrame(nil, typ, data)
	if err != nil {
		t.Fatal(err)
	}
	m, err := d.sess.Seal(f, 0)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestStage5DriverBatchDataOrderAccountingAndAliases(t *testing.T) {
	p := stage5Pair(t)
	beforeTx, beforeRx := p.cli.Stats(), p.gw.Stats()
	const count = 16
	for i := 0; i < count; i++ {
		if err := p.cli.Enqueue(bytes.Repeat([]byte{byte(i)}, p.cli.cfg.maxPayload()-frameHeaderSize)); err != nil {
			t.Fatal(err)
		}
	}
	out := stage5Output(p.cli, count)
	backing := make([]*byte, count)
	for i := range out {
		backing[i] = &out[i][:cap(out[i])][0]
	}
	n, err := p.cli.PollBatchInto(out)
	if err != nil || n != count {
		t.Fatalf("poll %d: %v", n, err)
	}
	var size uint64
	for i := range out {
		if &out[i][0] != backing[i] {
			t.Fatal("output slot lost its backing storage")
		}
		size += uint64(len(out[i]))
	}
	in := stage5Input(out...)
	n, err = p.gw.DeliverBatch(in)
	if err != nil || n != count {
		t.Fatalf("deliver %d: %v", n, err)
	}
	for i := range in {
		if len(in[i].Packets) != 1 || !bytes.Equal(in[i].Packets[0], bytes.Repeat([]byte{byte(i)}, p.cli.cfg.maxPayload()-frameHeaderSize)) {
			t.Fatalf("packet order %d", i)
		}
		if &in[i].Packets[0][0] != &in[i].Scratch[2+frameHeaderSize] {
			t.Fatal("packet was allocated instead of borrowing scratch")
		}
		if cap(in[i].Packets[0]) != len(in[i].Packets[0]) {
			t.Fatal("packet exposes adjacent frame capacity")
		}
	}
	a, z := p.cli.Stats(), p.gw.Stats()
	if a.BytesSent-beforeTx.BytesSent != size || z.BytesReceived-beforeRx.BytesReceived != size || a.DataFramesSent-beforeTx.DataFramesSent != count || z.DataFramesReceived-beforeRx.DataFramesReceived != count {
		t.Fatal("batch accounting differs from wire bytes")
	}
	if p.cli.batch.pool == nil || p.gw.batch.pool == nil {
		t.Fatal("batch worker pool absent")
	}
}

func TestStage5DriverDataCloseDataBoundaryAndWipe(t *testing.T) {
	p := stage5Pair(t)
	in := stage5Input(stage5Message(t, p.cli, core.FrameData, []byte("before")), stage5Message(t, p.cli, core.FrameClose, []byte{byte(CloseNormal)}), stage5Message(t, p.cli, core.FrameData, []byte("after")))
	before := p.gw.Stats()
	n, err := p.gw.DeliverBatch(in)
	if err != nil || n != 1 || p.gw.State() != StateEstablished || string(in[0].Packets[0]) != "before" {
		t.Fatalf("DATA prefix %d: %v state %s", n, err, p.gw.State())
	}
	if p.gw.Stats().MessagesReceived-before.MessagesReceived != 1 {
		t.Fatal("unreturned control committed early")
	}
	n, err = p.gw.DeliverBatch(in[1:])
	if err != nil || n != 1 || p.gw.State() != StateClosed {
		t.Fatalf("CLOSE boundary %d: %v", n, err)
	}
	if len(in[2].Packets) != 0 || !bytes.Equal(in[2].Scratch, make([]byte, len(in[2].Scratch))) {
		t.Fatal("canceled post-close plaintext retained")
	}
	if string(in[0].Packets[0]) != "before" {
		t.Fatal("close erased already returned packet view")
	}
	if p.gw.Stats().MessagesReceived-before.MessagesReceived != 2 {
		t.Fatal("post-close ticket committed")
	}
	if p.gw.batch.frames != nil || p.gw.batch.assembly[0] != nil {
		t.Fatal("terminate retained batch storage")
	}
	if _, err := p.gw.sess.Open(in[2].Message); err != core.ErrWiped {
		t.Fatal("session not wiped", err)
	}
	if _, err := p.gw.DeliverBatch(in[2:]); err != ErrClosed {
		t.Fatal(err)
	}
}

func TestStage5DriverBatchNoiseAndDuplicateBoundaries(t *testing.T) {
	p := stage5Pair(t)
	real := stage5Message(t, p.cli, core.FrameData, []byte("real"))
	bad := bytes.Clone(real)
	bad[len(bad)-1] ^= 1
	in := stage5Input(bad, real, bytes.Clone(real))
	before := p.gw.Stats()
	n, err := p.gw.DeliverBatch(in)
	if err != nil || n != 1 || len(in[0].Packets) != 0 {
		t.Fatalf("corrupt boundary %d %v", n, err)
	}
	n, err = p.gw.DeliverBatch(in[1:])
	if err != nil || n != 1 || string(in[1].Packets[0]) != "real" {
		t.Fatalf("genuine boundary %d %v", n, err)
	}
	n, err = p.gw.DeliverBatch(in[2:])
	if err != nil || n != 1 || len(in[2].Packets) != 0 {
		t.Fatalf("duplicate boundary %d %v", n, err)
	}
	after := p.gw.Stats()
	if after.Unopenable-before.Unopenable != 2 || after.MessagesReceived-before.MessagesReceived != 1 || after.BytesReceived-before.BytesReceived != uint64(len(real)) {
		t.Fatal("duplicate/corrupt accounting")
	}
}

func TestStage5DriverBatchShortBuffersDoNotConsume(t *testing.T) {
	p := stage5Pair(t)
	if err := p.cli.Enqueue([]byte("queued")); err != nil {
		t.Fatal(err)
	}
	before := p.cli.sess.SendCounter()
	out := stage5Output(p.cli, 2)
	out[1] = make([]byte, 1)
	if n, err := p.cli.PollBatchInto(out); n != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short poll %d: %v", n, err)
	}
	if p.cli.sess.SendCounter() != before || len(p.cli.data) != 1 {
		t.Fatal("short output consumed queue or nonce")
	}
	msg := stage5Message(t, p.cli, core.FrameData, []byte("real"))
	in := stage5Input(msg)
	in[0].Packets = nil
	if n, err := p.gw.DeliverBatch(in); n != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short refs %d: %v", n, err)
	}
	in = stage5Input(msg)
	if n, err := p.gw.DeliverBatch(in); n != 1 || err != nil || len(in[0].Packets) != 1 {
		t.Fatalf("retry %d: %v", n, err)
	}
}

func TestStage5DriverBatchRekeyACKOldEpochAndNewProbe(t *testing.T) {
	p := stage5Pair(t)
	epoch := p.cli.Epoch()
	if err := p.cli.startRekey(p.clk.Now()); err != nil {
		t.Fatal(err)
	}
	init := stage5Output(p.cli, 4)
	n, err := p.cli.PollBatchInto(init)
	if err != nil || n != 1 {
		t.Fatalf("init %d: %v", n, err)
	}
	if n, err := p.gw.DeliverBatch(stage5Input(init[0])); n != 1 || err != nil {
		t.Fatalf("init delivery %d: %v", n, err)
	}
	ack := stage5Output(p.gw, 4)
	n, err = p.gw.PollBatchInto(ack)
	if err != nil || n != 1 || p.gw.Epoch() != epoch+1 || p.cli.Epoch() != epoch {
		t.Fatalf("ack %d: %v", n, err)
	}
	if n, err := p.cli.DeliverBatch(stage5Input(ack[0])); n != 1 || err != nil || p.cli.Epoch() != epoch+1 {
		t.Fatalf("ACK was not sealed with old epoch: %d %v", n, err)
	}
	probe := stage5Output(p.cli, 4)
	n, err = p.cli.PollBatchInto(probe)
	if err != nil || n == 0 {
		t.Fatalf("new probe %d: %v", n, err)
	}
	for i := 0; i < n; i++ {
		if _, err := p.gw.DeliverBatch(stage5Input(probe[i])); err != nil {
			t.Fatal(err)
		}
	}
	if p.gw.DataPlaneState() != StateEstablished {
		t.Fatal("new-epoch probe did not release ACK confirmation hold")
	}
}

func TestStage5DriverBatchVolumeBoundary(t *testing.T) {
	p := stage5Pair(t)
	p.cli.cfg.RekeyAfterMessages = p.cli.sess.SendCounter() + 2
	for i := 0; i < 5; i++ {
		if err := p.cli.Enqueue(make([]byte, p.cli.cfg.maxPayload()-frameHeaderSize)); err != nil {
			t.Fatal(err)
		}
	}
	out := stage5Output(p.cli, 8)
	n, err := p.cli.PollBatchInto(out)
	if err != nil || n != 3 || p.cli.State() != StateRekeying {
		t.Fatalf("volume cut n=%d state=%s err=%v", n, p.cli.State(), err)
	}
	if len(p.cli.data) != 3 {
		t.Fatal("data crossed rekey volume barrier")
	}
}

func TestStage5DriverBatchReceiveNoHotAllocation(t *testing.T) {
	p := stage5Pair(t)
	p.cli.cfg.RekeyAfterBytes = ^uint64(0)
	p.cli.cfg.RekeyAfterMessages = ^uint64(0)
	payload, err := core.AppendFrame(nil, core.FrameData, bytes.Repeat([]byte{5}, 1200))
	if err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, 1500)
	in := stage5Input(msg)
	allocs := testing.AllocsPerRun(50, func() {
		m, err := p.cli.sess.SealInto(msg, payload, 0)
		if err != nil {
			panic(err)
		}
		in[0].Message = m
		if n, err := p.gw.DeliverBatch(in); err != nil || n != 1 {
			panic("batch failed")
		}
	})
	if allocs != 0 {
		t.Fatalf("receive hot path allocated %.2f times", allocs)
	}
	runtime.KeepAlive(in)
}
