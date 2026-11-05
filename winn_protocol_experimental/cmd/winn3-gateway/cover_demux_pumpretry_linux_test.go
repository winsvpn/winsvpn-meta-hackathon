//go:build linux

package main

// MatchingErrorRetries on the receive pumps. A pump that recovers from a read
// fault and reads again after a matching errno (ECONNREFUSED here) has
// undertaken a matching-error retry; DemuxReadFaults counts the fault
// separately. Closure, a cancellation that prevents the retry, and a
// non-matching fault add no matching retry.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"winsvpn.local/winnprotocol/winn3/carrier"
)

func waitCounter(t *testing.T, what string, read func() uint64, want uint64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for read() < want {
		if time.Now().After(deadline) {
			t.Fatalf("%s reached %d, want %d", what, read(), want)
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(30 * time.Millisecond) // and it must not overshoot
	if got := read(); got != want {
		t.Fatalf("%s is %d, want exactly %d", what, got, want)
	}
}

func statusNumbers(t *testing.T, s *splitUDP) map[string]json.Number {
	t.Helper()
	b, err := json.Marshal(serveStatus{Event: "posture",
		UdpSendErrors: buildUDPSendErrorStatus(s.v3, carrier.SendErrorOptions{IPv4: true})})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		UdpSendErrors map[string]any `json:"udp_send_errors"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]json.Number{}
	for k, v := range doc.UdpSendErrors {
		if n, ok := v.(json.Number); ok {
			out[k] = n
		}
	}
	return out
}

func wantStatus(t *testing.T, got map[string]json.Number, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got[k].String() != v {
			t.Errorf("status %s = %q, want %s", k, got[k].String(), v)
		}
	}
}

// deliverHealthy proves the pump is still receiving after a recovery.
func deliverHealthy(t *testing.T, s *splitUDP, healthy *net.UDPConn, gw *net.UDPAddr) {
	t.Helper()
	if _, err := healthy.WriteToUDP([]byte("healthy!"), gw); err != nil {
		t.Fatal(err)
	}
	readFromSplit(t, s, 1, 2*time.Second)
}

// TestScalarPumpCountsEachRetryAfterECONNREFUSED: the scalar pump (the path a
// 32-bit build or a failed RawBatchConn takes) receives ECONNREFUSED from
// ReadMsgUDPAddrPort after another peer's port unreachable, recovers, and reads
// again. Each such retry is one matching-error retry and one read fault. RED on
// v3, which counted the fault only.
func TestScalarPumpCountsEachRetryAfterECONNREFUSED(t *testing.T) {
	real := newLoopbackUDP(t)
	setRawRecvErrOn(t, real)
	split := newSplitUDPWith(real, demuxDatagramMin, splitTestOptions{noBatch: true})
	defer split.stop()
	if split.batch != nil || split.errq == nil {
		t.Fatal("the scalar pump with an error queue was not selected")
	}
	healthy := newLoopbackUDP(t)
	gone := closedLoopbackAddr(t)
	gw := real.LocalAddr().(*net.UDPAddr)
	before := split.errq.Stats()

	const rounds = 3
	for i := 1; i <= rounds; i++ {
		// A plain send, outside the scalar helpers, so no send-side counter moves.
		if _, err := split.real.WriteToUDPAddrPort([]byte("to a departed client"), gone); err != nil {
			t.Fatalf("round %d: send to the closed port: %v", i, err)
		}
		waitCounter(t, "demux read faults", split.readFaults.Load, uint64(i))
		waitCounter(t, "matching error retries",
			func() uint64 { return split.errq.Stats().MatchingErrorRetries - before.MatchingErrorRetries }, uint64(i))
		deliverHealthy(t, split, healthy, gw)
	}
	st := split.errq.Stats()
	t.Logf("after %d scalar recoveries: read faults=%d stats=%+v", rounds, split.readFaults.Load(), st)
	if st.ScalarRefused != before.ScalarRefused || st.TransmitRefused != before.TransmitRefused {
		t.Fatalf("a send-side counter moved during receive recovery: %+v", st)
	}
	wantStatus(t, statusNumbers(t, split), map[string]string{
		"matching_error_retries": "3",
		"demux_read_faults":      "3",
		"error_queue_drained":    "3",
		"scalar_refused":         "0",
	})
}

// TestBatchPumpCountsTheRetryAfterInternalExhaustion: ReadBatchFrom returns
// the matching errno once its own AsyncErrorRetries budget is spent (see the
// carrier's TestReadBatchFromExhaustsItsBudgetThenReturnsTheErrno). The batch
// pump then recovers and reads again: that outer retry must count too. The
// wrapper stands in for the exhausted helper's return. RED on v3.
func TestBatchPumpCountsTheRetryAfterInternalExhaustion(t *testing.T) {
	real := newLoopbackUDP(t)
	setRawRecvErrOn(t, real)
	calls := 0
	split := newSplitUDPWith(real, demuxDatagramMin, splitTestOptions{
		wrapBatchRead: func(read func([]carrier.BatchMsg) (int, error)) func([]carrier.BatchMsg) (int, error) {
			return func(m []carrier.BatchMsg) (int, error) {
				calls++ // the pump goroutine is the only caller
				if calls == 1 {
					return 0, unix.ECONNREFUSED
				}
				return read(m)
			}
		},
	})
	defer split.stop()
	if split.batch == nil {
		t.Fatal("the batch pump was not selected")
	}
	healthy := newLoopbackUDP(t)
	gw := real.LocalAddr().(*net.UDPAddr)

	waitCounter(t, "demux read faults", split.readFaults.Load, 1)
	waitCounter(t, "matching error retries", func() uint64 { return split.errq.Stats().MatchingErrorRetries }, 1)
	deliverHealthy(t, split, healthy, gw)
	t.Logf("after one exhausted batch receive: read faults=%d stats=%+v", split.readFaults.Load(), split.errq.Stats())
	wantStatus(t, statusNumbers(t, split), map[string]string{
		"matching_error_retries": "1",
		"demux_read_faults":      "1",
		"scalar_refused":         "0",
	})
}

// TestPumpRecoveryCountsNoRetryWhenNoneIsUndertaken covers the exclusions
// directly on recoverRead: closure, a stopped split, a cancellation during the
// backoff, and a non-matching fault add no matching-error retry. A non-matching
// fault that is retried still counts as a read fault.
func TestPumpRecoveryCountsNoRetryWhenNoneIsUndertaken(t *testing.T) {
	real := newLoopbackUDP(t)
	split := newSplitUDP(real, demuxDatagramMin)
	defer split.stop()
	retries := func() uint64 { return split.errq.Stats().MatchingErrorRetries }

	var f demuxReadFaults
	if split.recoverRead(&f, net.ErrClosed) {
		t.Fatal("closure must not be retried")
	}
	if split.recoverRead(&f, unix.EBADF) {
		t.Fatal("a descriptor failure must not be retried")
	}
	if !split.recoverRead(&f, errors.New("raw-read udp4: not pollable")) {
		t.Fatal("a non-matching recoverable fault must be retried")
	}
	if split.readFaults.Load() != 1 || retries() != 0 {
		t.Fatalf("non-matching fault: read faults %d (want 1), matching retries %d (want 0)", split.readFaults.Load(), retries())
	}
	if !split.recoverRead(&f, unix.ECONNREFUSED) {
		t.Fatal("a matching fault must be retried")
	}
	if split.readFaults.Load() != 2 || retries() != 1 {
		t.Fatalf("matching fault: read faults %d (want 2), matching retries %d (want 1)", split.readFaults.Load(), retries())
	}

	// Cancellation during the backoff prevents the retry: no matching retry.
	stopping := newSplitUDP(newLoopbackUDP(t), demuxDatagramMin)
	g := demuxReadFaults{since: time.Now(), backoff: time.Hour}
	done := make(chan bool)
	go func() { done <- stopping.recoverRead(&g, unix.ECONNREFUSED) }()
	time.Sleep(20 * time.Millisecond)
	stopping.stop()
	if <-done {
		t.Fatal("a cancelled backoff must not report a retry")
	}
	if got := stopping.errq.Stats().MatchingErrorRetries; got != 0 {
		t.Fatalf("a cancelled retry was counted: matching retries %d", got)
	}
	// A split already stopping refuses at once, counting nothing.
	if stopping.recoverRead(&g, unix.ECONNREFUSED) || stopping.errq.Stats().MatchingErrorRetries != 0 {
		t.Fatal("a stopped split counted or retried")
	}
}
