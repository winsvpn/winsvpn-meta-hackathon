package masque

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func newDeadlineTestConn() *Conn {
	ctx, cancel := context.WithCancel(context.Background())
	return &Conn{
		readCtx:       ctx,
		readCtxCancel: cancel,
	}
}

func cleanupDeadlineTestConn(conn *Conn) {
	conn.deadlineMx.Lock()
	conn.deadlineGeneration++
	if conn.readDeadlineTimer != nil {
		conn.readDeadlineTimer.Stop()
		conn.readDeadlineTimer = nil
	}
	conn.readCtxCancel()
	conn.deadlineMx.Unlock()
}

func waitForReadContextCancellation(t *testing.T, conn *Conn, timeout time.Duration) {
	t.Helper()
	conn.deadlineMx.Lock()
	readContext := conn.readCtx
	conn.deadlineMx.Unlock()

	select {
	case <-readContext.Done():
	case <-time.After(timeout):
		t.Fatal("read context did not observe the deadline")
	}
}

func currentReadContext(t *testing.T, conn *Conn) context.Context {
	t.Helper()
	conn.deadlineMx.Lock()
	defer conn.deadlineMx.Unlock()
	return conn.readCtx
}

func TestClearExpiredReadDeadlineReturnsAndRenewsContext(t *testing.T) {
	conn := newDeadlineTestConn()
	t.Cleanup(func() { cleanupDeadlineTestConn(conn) })

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond)); err != nil {
		t.Fatalf("set initial deadline: %v", err)
	}
	waitForReadContextCancellation(t, conn, time.Second)

	clearDone := make(chan error, 1)
	go func() {
		clearDone <- conn.SetReadDeadline(time.Time{})
	}()
	select {
	case err := <-clearDone:
		if err != nil {
			t.Fatalf("clear deadline: %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("clearing an expired AfterFunc deadline deadlocked")
	}

	if err := currentReadContext(t, conn).Err(); err != nil {
		t.Fatalf("clearing deadline left read context canceled: %v", err)
	}
}

func TestFutureReadDeadlineAfterExpiryRenewsAndExpires(t *testing.T) {
	conn := newDeadlineTestConn()
	t.Cleanup(func() { cleanupDeadlineTestConn(conn) })

	if err := conn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("set expired deadline: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("set future deadline: %v", err)
	}
	if err := currentReadContext(t, conn).Err(); err != nil {
		t.Fatalf("future deadline did not renew read context: %v", err)
	}
	waitForReadContextCancellation(t, conn, time.Second)
}

func TestStaleReadDeadlineCallbackCannotCancelReplacement(t *testing.T) {
	conn := newDeadlineTestConn()
	t.Cleanup(func() { cleanupDeadlineTestConn(conn) })

	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	conn.deadlineCallbackStarted = func() {
		close(callbackStarted)
		<-releaseCallback
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond)); err != nil {
		t.Fatalf("set short deadline: %v", err)
	}
	select {
	case <-callbackStarted:
	case <-time.After(time.Second):
		t.Fatal("old deadline callback did not start")
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("replace deadline: %v", err)
	}
	close(releaseCallback)

	readContext := currentReadContext(t, conn)
	select {
	case <-readContext.Done():
		t.Fatal("stale deadline callback canceled replacement context")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestDeadlineSettersRejectClosedConnection(t *testing.T) {
	conn := newDeadlineTestConn()
	conn.closed.Store(true)
	t.Cleanup(func() { cleanupDeadlineTestConn(conn) })

	for name, setDeadline := range map[string]func(time.Time) error{
		"combined": conn.SetDeadline,
		"read":     conn.SetReadDeadline,
		"write":    conn.SetWriteDeadline,
	} {
		t.Run(name, func(t *testing.T) {
			if err := setDeadline(time.Now().Add(time.Second)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("deadline error = %v, want net.ErrClosed", err)
			}
		})
	}
}

func TestConcurrentCloseOwnsUnderlyingResourcesOnce(t *testing.T) {
	stream := &closeCountingStream{}
	var ownedCloseCalls atomic.Int32
	conn := newProxiedConn(
		stream,
		masqueAddr{"local"},
		masqueAddr{"remote"},
		func() error {
			ownedCloseCalls.Add(1)
			return nil
		},
	)

	const callers = 16
	var waitGroup sync.WaitGroup
	results := make(chan error, callers)
	for range callers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			results <- conn.Close()
		}()
	}
	waitGroup.Wait()
	close(results)

	successes := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Close error = %v, want nil or net.ErrClosed", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful Close calls = %d, want 1", successes)
	}
	if got := ownedCloseCalls.Load(); got != 1 {
		t.Fatalf("owned connection close calls = %d, want 1", got)
	}
	if got := stream.cancelReadCalls.Load(); got != 1 {
		t.Fatalf("CancelRead calls = %d, want 1", got)
	}
	if got := stream.cancelWriteCalls.Load(); got != 1 {
		if got != 2 {
			t.Fatalf("CancelWrite calls = %d, want 1 or 2", got)
		}
	}
	if got := stream.closeCalls.Load(); got != 0 {
		t.Fatalf("stream close calls = %d, want 0", got)
	}
}

type closeCountingStream struct {
	closeCalls       atomic.Int32
	cancelReadCalls  atomic.Int32
	cancelWriteCalls atomic.Int32
}

func (*closeCountingStream) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (*closeCountingStream) Write(packet []byte) (int, error) {
	return len(packet), nil
}

func (s *closeCountingStream) Close() error {
	s.closeCalls.Add(1)
	return nil
}

func (*closeCountingStream) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, io.EOF
}

func (*closeCountingStream) SendDatagram([]byte) error {
	return nil
}

func (*closeCountingStream) StreamID() quic.StreamID {
	return 0
}

func (s *closeCountingStream) CancelRead(quic.StreamErrorCode) {
	s.cancelReadCalls.Add(1)
}

func (s *closeCountingStream) CancelWrite(quic.StreamErrorCode) {
	s.cancelWriteCalls.Add(1)
}
