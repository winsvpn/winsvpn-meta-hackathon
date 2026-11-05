package carrier

import (
	"context"
	"net"
	"testing"
	"time"
)

// The portable RecvBatch loop keeps reading after its first accepted datagram
// for as long as datagrams keep arriving. Refused ones (foreign source, or
// over the ceiling from the peer's own address) must spend that drain budget
// too; otherwise an injected stream withholds the accepted prefix and grows
// one deferred deadline restore per refused datagram.
func TestUDPBatchDrainCountsRefusedDatagrams(t *testing.T) {
	saved := kernelBatchEnabled
	kernelBatchEnabled = false
	t.Cleanup(func() { kernelBatchEnabled = saved })

	// The system clock: the drain deadline is relative to Now, and the fake
	// clock's fixed instant would expire every drain read before it starts.
	_, b, aConn, bConn := udpPair(t, func(c *UDPConfig) {
		c.Clock = nil
		c.MaxMessageSize = 600
		c.PathMTU = 1280
	})
	foreign := loopbackUDP(t)
	dst := bConn.LocalAddr().(*net.UDPAddr)
	send := func(conn *net.UDPConn, n int, fill byte) {
		t.Helper()
		if _, err := conn.WriteToUDP(message(n, fill), dst); err != nil {
			t.Fatalf("raw write: %v", err)
		}
	}
	send(aConn, 100, 1)
	for i := 0; i < 5; i++ {
		send(foreign, 100, 9)
	}
	for i := 0; i < 5; i++ {
		send(aConn, 1200, 8)
	}
	send(aConn, 200, 2)
	// Loopback queues synchronously; the pause only guards a slow scheduler.
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msgs := make([]BatchMsg, 2)
	for i := range msgs {
		msgs[i].Payload = make([]byte, b.MaxMessageSize())
	}
	n, err := b.RecvBatch(ctx, msgs)
	if err != nil || n != 1 || msgs[0].N != 100 {
		t.Fatalf("first batch returned (%d, %v) with length %d, want (1, nil) and 100", n, err, msgs[0].N)
	}
	if st := b.Stats(); st.Foreign != 1 || st.RecvErrors != 0 || st.Delivered != 1 {
		t.Fatalf("a two-slot batch read past its drain budget: foreign=%d receive_errors=%d delivered=%d, want 1, 0, 1",
			st.Foreign, st.RecvErrors, st.Delivered)
	}

	// The socket deadline was handed back: the next call still waits for and
	// finds the legal datagram behind the remaining refused ones.
	n, err = b.RecvBatch(ctx, msgs)
	if err != nil || n != 1 || msgs[0].N != 200 {
		t.Fatalf("second batch returned (%d, %v) with length %d, want (1, nil) and 200", n, err, msgs[0].N)
	}
	if st := b.Stats(); st.Foreign != 5 || st.RecvErrors != 5 || st.Delivered != 2 {
		t.Fatalf("after both batches: foreign=%d receive_errors=%d delivered=%d, want 5, 5, 2",
			st.Foreign, st.RecvErrors, st.Delivered)
	}
}
