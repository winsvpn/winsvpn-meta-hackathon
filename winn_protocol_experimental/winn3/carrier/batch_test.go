package carrier

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

type mockBatchCarrier struct {
	sent     [][]byte
	received [][]byte
}

func (m *mockBatchCarrier) Send(ctx context.Context, msg []byte) error {
	m.sent = append(m.sent, append([]byte(nil), msg...))
	return nil
}

func (m *mockBatchCarrier) Recv(ctx context.Context) ([]byte, error) {
	if len(m.received) == 0 {
		return nil, ErrClosed
	}
	res := m.received[0]
	m.received = m.received[1:]
	return res, nil
}

func (m *mockBatchCarrier) MaxMessageSize() int { return 1500 }
func (m *mockBatchCarrier) Close() error        { return nil }

func (m *mockBatchCarrier) RecvBatch(ctx context.Context, msgs []BatchMsg) (int, error) {
	n := 0
	for i := range msgs {
		if len(m.received) == 0 {
			break
		}
		data := m.received[0]
		m.received = m.received[1:]
		copy(msgs[i].Payload, data)
		msgs[i].N = len(data)
		msgs[i].Addr = netip.MustParseAddrPort("127.0.0.1:9999")
		n++
	}
	if n == 0 && len(msgs) > 0 {
		return 0, ErrClosed
	}
	return n, nil
}

func (m *mockBatchCarrier) SendBatch(ctx context.Context, msgs []BatchMsg) (int, error) {
	n := 0
	for _, msg := range msgs {
		m.sent = append(m.sent, append([]byte(nil), msg.Payload[:msg.N]...))
		n++
	}
	return n, nil
}

func TestBatchCarrierInterface(t *testing.T) {
	carrier := &mockBatchCarrier{
		received: [][]byte{
			[]byte("packet1"),
			[]byte("packet2"),
			[]byte("packet3"),
		},
	}

	msgs := make([]BatchMsg, 5)
	for i := range msgs {
		msgs[i].Payload = make([]byte, 1500)
	}

	ctx := context.Background()
	n, err := carrier.RecvBatch(ctx, msgs)
	if err != nil {
		t.Fatalf("RecvBatch failed: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 packets, got %d", n)
	}
	if string(msgs[0].Payload[:msgs[0].N]) != "packet1" {
		t.Fatalf("packet 0 payload mismatch: %s", msgs[0].Payload[:msgs[0].N])
	}
	if string(msgs[2].Payload[:msgs[2].N]) != "packet3" {
		t.Fatalf("packet 2 payload mismatch: %s", msgs[2].Payload[:msgs[2].N])
	}

	// Test SendBatch
	sendMsgs := []BatchMsg{
		{Payload: []byte("out1"), N: 4},
		{Payload: []byte("out2"), N: 4},
	}
	sentN, err := carrier.SendBatch(ctx, sendMsgs)
	if err != nil {
		t.Fatalf("SendBatch failed: %v", err)
	}
	if sentN != 2 {
		t.Fatalf("expected 2 packets sent, got %d", sentN)
	}
	if len(carrier.sent) != 2 {
		t.Fatalf("expected 2 sent entries, got %d", len(carrier.sent))
	}
}

func TestBatchFallback(t *testing.T) {
	// Standard non-batch Carrier
	baseCarrier := &mockBatchCarrier{
		received: [][]byte{
			[]byte("fb1"),
			[]byte("fb2"),
		},
	}
	// Wrap as plain Carrier
	var plain Carrier = struct{ Carrier }{baseCarrier}

	msgs := make([]BatchMsg, 2)
	for i := range msgs {
		msgs[i].Payload = make([]byte, 1500)
	}

	ctx := context.Background()
	n, err := RecvBatchFallback(ctx, plain, msgs)
	if err != nil {
		t.Fatalf("RecvBatchFallback failed: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 packets, got %d", n)
	}
	if string(msgs[0].Payload[:msgs[0].N]) != "fb1" {
		t.Fatalf("mismatch: %s", msgs[0].Payload[:msgs[0].N])
	}

	outMsgs := []BatchMsg{
		{Payload: []byte("sentfb1"), N: 7},
	}
	sentN, err := SendBatchFallback(ctx, plain, outMsgs)
	if err != nil {
		t.Fatalf("SendBatchFallback failed: %v", err)
	}
	if sentN != 1 {
		t.Fatalf("expected 1 sent, got %d", sentN)
	}
}

func TestUDPBatchRoundTrip(t *testing.T) {
	t.Parallel()
	a, b, _, _ := udpPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	count := 8
	sendMsgs := make([]BatchMsg, count)
	for i := 0; i < count; i++ {
		payload := []byte(fmt.Sprintf("winn3-batch-datagram-%d", i))
		sendMsgs[i] = BatchMsg{
			Payload: payload,
			N:       len(payload),
		}
	}

	sentN, err := a.SendBatch(ctx, sendMsgs)
	if err != nil {
		t.Fatalf("SendBatch failed: %v", err)
	}
	if sentN != count {
		t.Fatalf("expected %d sent, got %d", count, sentN)
	}

	recvMsgs := make([]BatchMsg, count)
	for i := range recvMsgs {
		recvMsgs[i].Payload = make([]byte, 1500)
	}

	totalRecv := 0
	for totalRecv < count {
		n, err := b.RecvBatch(ctx, recvMsgs[totalRecv:])
		if err != nil {
			t.Fatalf("RecvBatch failed after %d packets: %v", totalRecv, err)
		}
		totalRecv += n
	}

	for i := 0; i < count; i++ {
		expected := fmt.Sprintf("winn3-batch-datagram-%d", i)
		got := string(recvMsgs[i].Payload[:recvMsgs[i].N])
		if got != expected {
			t.Fatalf("packet %d mismatch: expected %s, got %s", i, expected, got)
		}
	}
}

func BenchmarkUDPBatchRoundTrip(b *testing.B) {
	a, bCar, _, _ := udpPair(b)
	ctx := context.Background()

	const batchSize = 16
	sendMsgs := make([]BatchMsg, batchSize)
	recvMsgs := make([]BatchMsg, batchSize)
	for i := range sendMsgs {
		p := make([]byte, 1400)
		sendMsgs[i] = BatchMsg{Payload: p, N: len(p)}
		recvMsgs[i] = BatchMsg{Payload: make([]byte, 1500)}
	}

	b.SetBytes(int64(batchSize * 1400))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if _, err := a.SendBatch(ctx, sendMsgs); err != nil {
			b.Fatalf("SendBatch: %v", err)
		}
		total := 0
		for total < batchSize {
			n, err := bCar.RecvBatch(ctx, recvMsgs[total:])
			if err != nil {
				b.Fatalf("RecvBatch: %v", err)
			}
			total += n
		}
	}
}

func BenchmarkUDPSingleRoundTrip(b *testing.B) {
	a, bCar, _, _ := udpPair(b)
	ctx := context.Background()

	payload := make([]byte, 1400)
	recvBuf := make([]byte, 65535)

	b.SetBytes(1400)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if err := a.Send(ctx, payload); err != nil {
			b.Fatalf("Send: %v", err)
		}
		if _, err := bCar.RecvInto(ctx, recvBuf); err != nil {
			b.Fatalf("RecvInto: %v", err)
		}
	}
}


