package carrier

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestPipeCloseBeforeDeliveryAdmission(t *testing.T) {
	for _, retries := range []int{0, 3} {
		t.Run(fmt.Sprintf("retries_%d", retries), func(t *testing.T) {
			preparing := make(chan struct{})
			resume := make(chan struct{})
			p, err := NewPipe(PipeConfig{Class: ClassUDP, Seq: func([]byte) uint64 {
				close(preparing)
				<-resume
				return 1
			}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = p.Close() })
			result := make(chan error, 1)
			go func() { result <- p.DeliverWithRetry([]byte("message"), retries) }()
			<-preparing
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			close(resume)
			if err := <-result; !errors.Is(err, ErrClosed) {
				t.Fatalf("delivery after close = %v, want ErrClosed", err)
			}
			if len(p.inbox) != 0 {
				t.Fatal("closed pipe retained a queued buffer")
			}
			if s := p.Stats(); s.Delivered != 0 || s.DeliveredBytes != 0 || s.RecvErrors != 0 {
				t.Fatalf("closed delivery changed counters: %+v", s)
			}
			if p.flowSeen {
				t.Fatal("closed delivery changed flow observations")
			}
		})
	}
}

func TestPipeCloseDrainsAcceptedDeliveries(t *testing.T) {
	p, err := NewPipe(PipeConfig{Class: ClassUDP, Depth: 2})
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range []string{"first", "second"} {
		if err := p.DeliverWithRetry([]byte(msg), 3); err != nil {
			t.Fatal(err)
		}
	}
	before := p.Stats()
	if before.Delivered != 2 || before.DeliveredBytes != 11 {
		t.Fatalf("arrival counters = %+v", before)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if len(p.inbox) != 0 {
		t.Fatal("close did not drain accepted messages")
	}
	if after := p.Stats(); after != before {
		t.Fatalf("close changed arrival counters: before %+v, after %+v", before, after)
	}
	if _, err := p.Recv(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("receive after close = %v, want ErrClosed", err)
	}
}
