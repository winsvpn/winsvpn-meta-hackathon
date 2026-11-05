package session

import (
	"testing"
)

func TestClientBatchHandshakeRepro(t *testing.T) {
	p := newPair(t, nil)
	cliSlots := make([][]byte, 4)
	for i := range cliSlots {
		cliSlots[i] = make([]byte, 1402)
	}
	n, err := p.cli.PollBatchInto(cliSlots)
	t.Logf("client initial PollBatchInto: n=%d, err=%v", n, err)
	if n != 1 || err != nil {
		t.Fatalf("expected 1 initiation message, got n=%d, err=%v", n, err)
	}

	gwIn := []ReceiveSlot{{
		Message: cliSlots[0],
		Scratch: make([]byte, 1402),
		Packets: make([][]byte, 0, 1402/3),
	}}
	done, err := p.gw.DeliverBatch(gwIn)
	t.Logf("gw DeliverBatch: done=%d, err=%v", done, err)
	if done != 1 || err != nil {
		t.Fatalf("expected gw DeliverBatch done=1, err=%v", err)
	}

	gwSlots := make([][]byte, 4)
	for i := range gwSlots {
		gwSlots[i] = make([]byte, 1402)
	}
	nGw, err := p.gw.PollBatchInto(gwSlots)
	t.Logf("gw PollBatchInto: n=%d, err=%v", nGw, err)
	if nGw != 1 || err != nil {
		t.Fatalf("expected gw PollBatchInto n=1, err=%v (got n=%d)", err, nGw)
	}

	cliIn := []ReceiveSlot{{
		Message: gwSlots[0],
		Scratch: make([]byte, 1402),
		Packets: make([][]byte, 0, 1402/3),
	}}
	doneCli, err := p.cli.DeliverBatch(cliIn)
	t.Logf("client DeliverBatch: done=%d, err=%v", doneCli, err)
	if doneCli != 1 || err != nil {
		t.Fatalf("expected client DeliverBatch done=1, err=%v (got done=%d)", err, doneCli)
	}

	n2, err := p.cli.PollBatchInto(cliSlots)
	t.Logf("client second PollBatchInto: n=%d, err=%v, len(cliSlots[0])=%d, cap(cliSlots[0])=%d, ctrl_len=%d",
		n2, err, len(cliSlots[0]), cap(cliSlots[0]), len(p.cli.ctrl))
	if n2 != 1 {
		t.Fatalf("expected client second PollBatchInto n=1, got n=%d, err=%v", n2, err)
	}
}
