package netlab

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestZZZTeethRepro is a temporary reproduction harness owned by
// gen_winn3_teeth_flake. It must be deleted before that lane reports DONE.
// It loads the scheduler the way a loaded machine does (the only regime in
// which the ~1-in-84 Unopenable delta in TestAPerfectLinkIsLoopback has
// reproduced) and, when a delta is observed, captures BOTH ends' full session
// stats so the mechanism can be named rather than assumed.
func TestZZZTeethRepro(t *testing.T) {
	var delta, retrans, rekeyed, other, lost uint64
	run := func() {
		kr, err := NewKeyring()
		if err != nil {
			t.Errorf("keyring: %v", err)
			return
		}
		p, err := NewPair(kr, PairConfig{TokenWindow: netlabWindow, SendQueue: 2048})
		if err != nil {
			t.Errorf("pair: %v", err)
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		p.Start(ctx)
		defer p.Stop()
		if err := p.Handshake(20 * time.Second); err != nil {
			t.Errorf("handshake: %v", err)
			return
		}
		if err := p.ProveCarrying(20 * time.Second); err != nil {
			t.Errorf("prove: %v", err)
			return
		}
		base := p.Gateway.Loop.Session().Stats().Unopenable
		sent := p.OfferInner(400, p.FullPayload())
		got := p.Collect(sent, 40*time.Second)
		gw := p.Gateway.Loop.Session().Stats()
		cli := p.Client.Loop.Session().Stats()
		if gw.Unopenable != base {
			atomic.AddUint64(&delta, 1)
			switch {
			case cli.HandshakeMessagesSent > 1:
				atomic.AddUint64(&retrans, 1)
			case gw.Rekeys > 0 || cli.Rekeys > 0:
				atomic.AddUint64(&rekeyed, 1)
			default:
				atomic.AddUint64(&other, 1)
			}
			t.Logf("CAPTURE got=%d sent=%d base=%d now=%d delta=%d | cli HSsent=%d HSatt=%d rekey=%d | gw rekey=%d Delivered=%d MsgRecv=%d DataDrop=%d PQrecv=%d | link.Held=%d SessSent=%d SessRecv=%d",
				got, sent, base, gw.Unopenable, gw.Unopenable-base,
				cli.HandshakeMessagesSent, cli.HandshakeAttempts, cli.Rekeys,
				gw.Rekeys, gw.DataFramesReceived, gw.MessagesReceived, gw.DataFramesDropped,
				gw.PQChunksReceived, p.ToGateway.Stats().Held,
				cli.MessagesSent, cli.MessagesReceived)
			t.Logf("  gw=%+v", gw)
			t.Logf("  cli=%+v", cli)
		}
		if got != sent {
			atomic.AddUint64(&lost, 1)
			t.Logf("LOSS got=%d sent=%d link=%+v", got, sent, p.ToGateway.Stats())
		}
	}

	const batch = 8
	for round := 0; round < 12; round++ {
		var wg sync.WaitGroup
		for i := 0; i < batch; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				run()
			}()
		}
		wg.Wait()
	}
	t.Logf("RESULT total=%d delta=%d (retrans=%d rekeyed=%d other=%d) lost=%d", batch*12, delta, retrans, rekeyed, other, lost)
}
