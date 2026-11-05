package driver

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
)

// scriptedBatch answers SendBatch from a script of accepted counts; every call
// is a presentation.
type scriptedBatch struct {
	script []int
	calls  int
}

func (s *scriptedBatch) SendBatch(_ context.Context, msgs []carrier.BatchMsg) (int, error) {
	n := s.script[s.calls]
	s.calls++
	if n > len(msgs) {
		n = len(msgs)
	}
	return n, nil
}

func (s *scriptedBatch) RecvBatch(context.Context, []carrier.BatchMsg) (int, error) { return 0, nil }
func (s *scriptedBatch) Send(context.Context, []byte) error                         { return nil }
func (s *scriptedBatch) Recv(context.Context) ([]byte, error)                       { return nil, errors.New("unused") }
func (s *scriptedBatch) MaxMessageSize() int                                        { return 1402 }
func (s *scriptedBatch) Close() error                                               { return nil }

// Refusals are counted when each carrier call returns: three retained messages
// answered (1, nil) then (2, nil) are two refused presentations, not zero.
func TestIntermediatePartialBatchesCountEveryRefusedPresentation(t *testing.T) {
	l := &Loop{clock: SystemClock{}}
	l.txPending = [][]byte{{1}, {2}, {3}}
	l.txStallSince = time.Now()
	bc := &scriptedBatch{script: []int{1, 2}}
	if sent, err := l.flushPendingBatch(context.Background(), bc); sent != 1 || err != nil {
		t.Fatalf("first presentation: sent=%d err=%v", sent, err)
	}
	if got := l.c.sendRefused.Load(); got != 2 {
		t.Fatalf("after (1, nil) of 3: SendRefused=%d, want 2", got)
	}
	if len(l.txPending) != 2 {
		t.Fatalf("after (1, nil) of 3: %d retained, want 2", len(l.txPending))
	}
	if sent, err := l.flushPendingBatch(context.Background(), bc); sent != 2 || err != nil {
		t.Fatalf("second presentation: sent=%d err=%v", sent, err)
	}
	if got := l.c.sendRefused.Load(); got != 2 {
		t.Fatalf("after (2, nil) of 2: SendRefused=%d, want 2", got)
	}
	if len(l.txPending) != 0 || bc.calls != 2 {
		t.Fatalf("retained=%d calls=%d, want 0 and 2 (one presentation per attempt)", len(l.txPending), bc.calls)
	}
}

// scalarMTU is a non-batch carrier whose every send is a path-MTU refusal.
type scalarMTU struct{ sends atomic.Int64 }

func (s *scalarMTU) Send(context.Context, []byte) error {
	s.sends.Add(1)
	return carrier.ErrPathMTUReduced
}
func (s *scalarMTU) Recv(context.Context) ([]byte, error) { return nil, errors.New("unused") }
func (s *scalarMTU) MaxMessageSize() int                  { return 1402 }
func (s *scalarMTU) Close() error                         { return nil }
func (s *scalarMTU) Class() carrier.Class                 { return carrier.ClassUDP }
func (s *scalarMTU) SetMaxMessageSize(int) error          { return nil }
func (s *scalarMTU) Stats() carrier.Stats                 { return carrier.Stats{} }

// A retained scalar retry refused for path MTU is a refused presentation, and
// its bytes are abandoned exactly once.
func TestAScalarRetryRefusedForPathMTUIsCountedAndAbandonedOnce(t *testing.T) {
	c := &scalarMTU{}
	l := &Loop{clock: SystemClock{}, car: c, carGen: 7}
	l.txPending = [][]byte{{1}, {2}}
	l.txPendingGen = 7
	l.txStallSince = time.Now()
	_, err := l.drain(context.Background())
	if !errors.Is(err, carrier.ErrPathMTUReduced) {
		t.Fatalf("drain returned %v, want ErrPathMTUReduced", err)
	}
	if got := l.c.sendRefused.Load(); got != 1 {
		t.Fatalf("SendRefused=%d, want 1 (one refused presentation)", got)
	}
	if got := l.c.sendFailed.Load(); got != 2 {
		t.Fatalf("SendFailed=%d, want 2 (both retained messages abandoned)", got)
	}
	l.abandonRetained()
	if got := l.c.sendFailed.Load(); got != 2 {
		t.Fatalf("abandonment was counted twice: SendFailed=%d", got)
	}
}

// Cancelling the loop while ciphertext is retained accounts for it exactly once.
func TestCancellationWithRetainedCiphertextAbandonsItExactlyOnce(t *testing.T) {
	l := &Loop{clock: SystemClock{}}
	l.txPending = [][]byte{{1}, {2}, {3}}
	l.txStallSince = time.Now()
	l.abandonRetained()
	l.abandonRetained()
	if got := l.c.sendFailed.Load(); got != 3 {
		t.Fatalf("SendFailed=%d, want 3", got)
	}
	if len(l.txPending) != 0 || !l.txStallSince.IsZero() {
		t.Fatal("abandonment did not clear the retention state")
	}
}
