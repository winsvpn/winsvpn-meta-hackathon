package session

import (
	"bytes"
	"errors"
	"testing"

	"winsvpn.local/winnprotocol/winn3/core"
)

func assertAssemblyCleared(t *testing.T, d *Driver) {
	t.Helper()
	for i, buf := range d.batch.assembly {
		for j, value := range buf {
			if value != 0 {
				t.Fatalf("assembly slot %d retained plaintext at %d", i, j)
			}
		}
	}
}

func TestAssemblyCleanupLargeThenSmallBatch(t *testing.T) {
	p := stage5Pair(t)
	var backing [MaxBatchSize]*byte
	for round, count := range []int{MaxBatchSize, 1, 3} {
		want := make([][]byte, count)
		for i := range want {
			want[i] = bytes.Repeat([]byte{byte(round*MaxBatchSize + i + 1)}, p.cli.cfg.maxPayload()-frameHeaderSize)
			if err := p.cli.Enqueue(want[i]); err != nil {
				t.Fatal(err)
			}
		}
		out := stage5Output(p.cli, count)
		if n, err := p.cli.PollBatchInto(out); err != nil || n != count {
			t.Fatalf("round %d poll %d: %v", round, n, err)
		}
		assertAssemblyCleared(t, p.cli)
		for i, buf := range p.cli.batch.assembly {
			if round == 0 {
				backing[i] = &buf[0]
			} else if &buf[0] != backing[i] {
				t.Fatalf("assembly backing changed at %d", i)
			}
		}
		in := stage5Input(out...)
		if n, err := p.gw.DeliverBatch(in); err != nil || n != count {
			t.Fatalf("round %d deliver %d: %v", round, n, err)
		}
		for i := range in {
			if len(in[i].Packets) != 1 || !bytes.Equal(in[i].Packets[0], want[i]) {
				t.Fatalf("round %d packet %d changed", round, i)
			}
		}
	}
}

func TestAssemblyCleanupAfterClosedPool(t *testing.T) {
	p := stage5Pair(t)
	p.cli.batchLocked().pool.Close()
	for i := 0; i < 3; i++ {
		if err := p.cli.Enqueue(bytes.Repeat([]byte{byte(i + 1)}, p.cli.cfg.maxPayload()-frameHeaderSize)); err != nil {
			t.Fatal(err)
		}
	}
	before := p.cli.sess.SendCounter()
	if n, err := p.cli.PollBatchInto(stage5Output(p.cli, 3)); n != 0 || !errors.Is(err, core.ErrPoolClosed) {
		t.Fatalf("closed pool poll %d: %v", n, err)
	}
	assertAssemblyCleared(t, p.cli)
	if p.cli.sess.SendCounter() != before || len(p.cli.data) != 3 {
		t.Fatal("failed seal changed nonce or queue ownership")
	}
}
