package driver

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// refuseThenBlockCarrier answers its first armed batch with `firstAccept`
// messages accepted (0 is an outright refusal, a positive count less than the
// batch is a short result), then blocks every later send until its context is
// cancelled: a carrier that honours cancellation but never becomes writable.
type refuseThenBlockCarrier struct {
	*throttleCarrier
	firstAccept int
	refusedOnce atomic.Bool
	blocked     atomic.Uint64
}

func (c *refuseThenBlockCarrier) SendBatch(ctx context.Context, msgs []carrier.BatchMsg) (int, error) {
	if !c.armed.Load() {
		return c.inner.SendBatch(ctx, msgs)
	}
	if c.refusedOnce.CompareAndSwap(false, true) {
		n := c.firstAccept
		if n >= len(msgs) {
			n = len(msgs) - 1
		}
		if n > 0 {
			if _, err := c.inner.SendBatch(ctx, msgs[:n]); err != nil {
				return 0, err
			}
		}
		return n, nil
	}
	c.blocked.Add(1)
	<-ctx.Done()
	return 0, ctx.Err()
}

func (c *refuseThenBlockCarrier) Send(ctx context.Context, msg []byte) error {
	if !c.armed.Load() {
		return c.inner.Send(ctx, msg)
	}
	c.blocked.Add(1)
	<-ctx.Done()
	return ctx.Err()
}

// A retry that blocks until cancelled must not hold the write loop past the
// retention budget: the loop fails with ErrSessionFailed and abandons the
// retained bytes into SendFailed exactly once.
func TestARetryThatBlocksUntilCancelledFailsWithinTheRetentionBudget(t *testing.T) {
	runRetentionCase(t, 0, false)
}

// A positive short initial result must enter retention too: its unsent suffix
// may not be re-presented under the unbounded carrier context.
func TestAPositiveShortBatchThenABlockedRetryFailsWithinTheRetentionBudget(t *testing.T) {
	runRetentionCase(t, 1, false)
}

// Cancelling the loop while ciphertext is retained abandons it into SendFailed.
func TestCancellingTheLoopWithRetainedCiphertextCountsIt(t *testing.T) {
	runRetentionCase(t, 0, true)
}

func runRetentionCase(t *testing.T, firstAccept int, cancelEarly bool) {
	t.Helper()
	krGw, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	krCli, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := core.NewPublicKey(krGw.Public())
	if err != nil {
		t.Fatal(err)
	}
	admission := make([]byte, 32)
	for i := range admission {
		admission[i] = byte(i*7 + 1)
	}
	params := core.GatewayParams{AdmissionKeys: [][]byte{admission}, GatewayID: []byte("winn3-retention")}
	sz, err := NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	cliDev := newFloodDevice(sz.InnerMTU, 1<<12)
	gwDev := newFloodDevice(sz.InnerMTU, 1<<12)
	cliCar, gwCarUDP := loopbackUDPPair(t)
	gwCar := &refuseThenBlockCarrier{throttleCarrier: newThrottle(gwCarUDP), firstAccept: firstAccept}

	cliLoop, err := NewClient(Config{
		Session: session.Config{Core: core.Config{Gateway: params}, Static: krCli, GatewayStatic: pub, Padding: core.PadBucket},
		Sizing:  sz, Carrier: cliCar,
		Tun: &tun.Config{Assign: tun.Assignment{V4: clientAddr(), RouterV4: gatewayAddr()}, Device: cliDev},
	})
	if err != nil {
		t.Fatal(err)
	}
	gwLoop, err := NewGateway(Config{
		Session: session.Config{Core: core.Config{Gateway: params}, Static: krGw, Accept: func([]byte) error { return nil }, Padding: core.PadBucket},
		Sizing:  sz, Carrier: gwCar,
		Tun: &tun.Config{Assign: tun.Assignment{V4: gatewayAddr(), RouterV4: clientAddr()}, Device: gwDev},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer cliLoop.Close()
	defer gwLoop.Close()
	go func() { _ = cliLoop.Run(ctx) }()
	gwDone := make(chan error, 1)
	go func() { gwDone <- gwLoop.Run(ctx) }()

	deadline := time.Now().Add(10 * time.Second)
	for !cliLoop.Carrying() || !gwLoop.Carrying() {
		if time.Now().After(deadline) {
			t.Fatal("tunnel did not reach carrying state")
		}
		time.Sleep(time.Millisecond)
	}

	pkt := ipv4Packet(gatewayAddr(), clientAddr(), make([]byte, sz.InnerMTU-28))
	gwCar.armed.Store(true)
	armedAt := time.Now()
	for i := 0; i < 64; i++ {
		gwDev.offer(pkt)
	}

	if cancelEarly {
		time.Sleep(300 * time.Millisecond)
		cancel()
		select {
		case <-gwDone:
		case <-time.After(5 * time.Second):
			t.Fatal("the gateway loop did not stop after cancellation")
		}
		st := gwLoop.Stats()
		if st.SendFailed == 0 {
			t.Fatalf("cancellation with retained ciphertext left it unaccounted: SendFailed=%d SendRefused=%d", st.SendFailed, st.SendRefused)
		}
		if again := gwLoop.Stats().SendFailed; again != st.SendFailed {
			t.Fatalf("SendFailed moved after the loop stopped: %d then %d", st.SendFailed, again)
		}
		t.Logf("cancelled with retained ciphertext: SendFailed=%d SendRefused=%d", st.SendFailed, st.SendRefused)
		return
	}
	select {
	case runErr := <-gwDone:
		took := time.Since(armedAt)
		if !errors.Is(runErr, ErrSessionFailed) {
			t.Fatalf("gateway loop ended with %v, want an error wrapping ErrSessionFailed", runErr)
		}
		if took > carrierStallLimit+2*time.Second {
			t.Fatalf("a blocking retry held the loop %v, past the %v budget", took, carrierStallLimit)
		}
		st := gwLoop.Stats()
		if st.SendFailed == 0 || st.SendRefused == 0 {
			t.Fatalf("abandoned retained bytes were not accounted: SendFailed=%d SendRefused=%d", st.SendFailed, st.SendRefused)
		}
		t.Logf("failed after %v: SendFailed=%d SendRefused=%d blocked=%d", took, st.SendFailed, st.SendRefused, gwCar.blocked.Load())
	case <-time.After(carrierStallLimit + 5*time.Second):
		t.Fatalf("a retry that blocks until cancelled held the write loop past %v", carrierStallLimit+5*time.Second)
	}
}
