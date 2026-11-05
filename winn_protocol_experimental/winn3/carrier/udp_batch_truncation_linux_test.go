//go:build linux

package carrier

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

// A batch iovec is only as wide as the negotiated message ceiling. An
// oversize datagram must be discarded even when recvmmsg copies exactly that
// many bytes and reports the excess only through MSG_TRUNC.
func TestUDPBatchRejectsTruncatedOversizeDatagram(t *testing.T) {
	_, b, aConn, bConn := udpPair(t, func(c *UDPConfig) {
		c.MaxMessageSize = 600
		c.PathMTU = 1280
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dst := bConn.LocalAddr().(*net.UDPAddr)
	if _, err := aConn.WriteToUDP(bytes.Repeat([]byte{1}, 1200), dst); err != nil {
		t.Fatal(err)
	}
	msgs := []BatchMsg{{Payload: make([]byte, b.MaxMessageSize())}}
	n, err := b.RecvBatch(ctx, msgs)
	if err != nil || n != 0 {
		t.Fatalf("oversize batch datagram returned (%d, %v), want (0, nil)", n, err)
	}
	if st := b.Stats(); st.Delivered != 0 || st.RecvErrors != 1 {
		t.Fatalf("oversize datagram stats: delivered=%d receive_errors=%d, want 0 and 1",
			st.Delivered, st.RecvErrors)
	}
	want := bytes.Repeat([]byte{2}, 500)
	if _, err := aConn.WriteToUDP(want, dst); err != nil {
		t.Fatal(err)
	}
	n, err = b.RecvBatch(ctx, msgs)
	if err != nil || n != 1 || !bytes.Equal(msgs[0].Payload[:msgs[0].N], want) {
		t.Fatalf("following legal datagram returned (%d, %v), length=%d", n, err, msgs[0].N)
	}
}
