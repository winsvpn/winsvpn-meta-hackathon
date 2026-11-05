package session

import "testing"

// The send-queue census is the deepest the queue has been, and draining does
// not lower it.
func TestDataQueueHighWaterIsTheDeepestBacklog(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
	})
	p.establish()
	for i := 0; i < 5; i++ {
		if err := p.cli.Enqueue([]byte{0x45, byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if got := p.cli.Stats().DataQueueHighWater; got != 5 {
		t.Fatalf("high water after 5 enqueues = %d, want 5", got)
	}
	p.run()
	if n, err := p.cli.EnqueueBatch([][]byte{{0x45, 9}, {0x45, 10}}); err != nil || n != 2 {
		t.Fatalf("EnqueueBatch = %d, %v", n, err)
	}
	if got := p.cli.Stats().DataQueueHighWater; got != 5 {
		t.Fatalf("high water after a drain and 2 more = %d, want 5", got)
	}
	p.run()
	if len(p.atGw) != 7 {
		t.Fatalf("gateway received %d packets, want 7", len(p.atGw))
	}
}

// A batch the queue takes only in part still raises the high-water mark: the
// census runs on every return, not only when the whole batch fits.
func TestDataQueueHighWaterIncludesPartialBatch(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.SendQueue = 4
	})
	p.establish()
	n, err := p.cli.EnqueueBatch([][]byte{{1}, {2}, {3}, {4}, {5}})
	if n != 4 || err != ErrQueueFull {
		t.Fatalf("EnqueueBatch = %d, %v; want 4, ErrQueueFull", n, err)
	}
	if got := p.cli.Stats().DataQueueHighWater; got != 4 {
		t.Fatalf("high water = %d, want 4", got)
	}
}

// DataQueueDepth is the backlog standing when Stats is read, not the deepest
// it ever was: it rises with Enqueue and falls to zero once the queue has
// been sealed, while DataQueueHighWater keeps the peak.
func TestDataQueueDepthIsTheBacklogNow(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
	})
	p.establish()
	for i := 0; i < 3; i++ {
		if err := p.cli.Enqueue([]byte{0x45, byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if st := p.cli.Stats(); st.DataQueueDepth != 3 || st.DataQueueHighWater != 3 {
		t.Fatalf("after 3 enqueues: depth %d high water %d, want 3 and 3", st.DataQueueDepth, st.DataQueueHighWater)
	}
	p.run()
	if st := p.cli.Stats(); st.DataQueueDepth != 0 || st.DataQueueHighWater != 3 {
		t.Fatalf("after the drain: depth %d high water %d, want 0 and 3", st.DataQueueDepth, st.DataQueueHighWater)
	}
	if len(p.atGw) != 3 {
		t.Fatalf("gateway received %d packets, want 3", len(p.atGw))
	}
}
