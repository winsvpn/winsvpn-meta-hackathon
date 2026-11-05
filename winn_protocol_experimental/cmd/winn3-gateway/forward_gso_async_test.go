package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// gsoRecorder is the kernel side of one queue: plain writes are recorded as
// they are, GSO frames are segmented the way Linux would, so got is the
// packet sequence the forward path would see.
type gsoRecorder struct {
	t        *testing.T
	mu       sync.Mutex
	got      [][]byte
	frames   int
	refuse   bool
	holdOnce chan struct{}
	entered  chan struct{} // closed once the held write has begun
}

func (r *gsoRecorder) write(_ int, pkt []byte) (int, error) {
	if h := r.holdOnce; h != nil {
		r.holdOnce = nil // only the writer goroutine calls write here
		close(r.entered)
		<-h
	}
	r.mu.Lock()
	r.got = append(r.got, append([]byte(nil), pkt...))
	r.mu.Unlock()
	return len(pkt), nil
}

func (r *gsoRecorder) writeGSO(_ int, frame []byte) (int, error) {
	if r.refuse {
		return 0, errors.New("EINVAL")
	}
	segs := kernelSegment(r.t, frame)
	r.mu.Lock()
	r.got = append(r.got, segs...)
	r.frames++
	r.mu.Unlock()
	return len(frame), nil
}

// runCoalescing queues a marker that the writer holds in write(2), then the
// rest, then releases the marker, so the writer finds everything queued at
// once and coalesces what it can.
func runCoalescing(t *testing.T, refuse bool) (*gsoRecorder, *tunWriteQueues, [][]byte) {
	t.Helper()
	r := &gsoRecorder{t: t, refuse: refuse, holdOnce: make(chan struct{}), entered: make(chan struct{})}
	hold := r.holdOnce
	w := newTunWriteQueues(1, 256, 1600, r.write, nil)
	w.gap = time.Hour // every submit is handed off, none written inline
	w.enableGSO(r.writeGSO)

	ts := []byte{1, 1, 8, 10, 0, 0, 0, 7, 0, 0, 0, 9}
	marker := gsoTestSegment(1, 1, tcpFlagACK, nil, nil) // pure ACK: never merged
	bulk := gsoTestRun(16, 1321, 700, ts)
	other := gsoTestRun(3, 1321, 1321, nil)
	for _, p := range other {
		p[20] ^= 0x10 // another source port, so another flow
		binary.BigEndian.PutUint16(p[36:38], 0)
		sum := onesSum(p[12:20], 0) + 6 + uint32(len(p)-20)
		binary.BigEndian.PutUint16(p[36:38], ^foldChecksum(onesSum(p[20:], sum)))
	}
	want := [][]byte{marker}
	want = append(want, bulk...)
	want = append(want, marker)
	want = append(want, other...)

	var pending atomic.Int64
	for i, p := range want {
		if _, err := w.submit(0, &pending, p); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			// Wait until the writer is inside write(2) with the marker, so
			// it has finished collecting its first run and the rest queue
			// up behind it.
			select {
			case <-r.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("writer never took the marker")
			}
		}
	}
	close(hold)
	drained(t, &pending)
	w.close()
	return r, w, want
}

// Queued runs leave as one GSO frame each, everything else alone, and the
// kernel's segmentation gives back the submitted packets in submission order.
func TestAsyncTunWriteCoalescesQueuedRunsInOrder(t *testing.T) {
	r, w, want := runCoalescing(t, false)
	if len(r.got) != len(want) {
		t.Fatalf("kernel saw %d packets, want %d", len(r.got), len(want))
	}
	for i := range want {
		if !bytes.Equal(r.got[i], want[i]) {
			t.Fatalf("packet %d differs from the one submitted", i)
		}
	}
	st := w.stats()
	if r.frames != 2 || st.GSOFrames != 2 || st.GSOSegments != 19 {
		t.Fatalf("frames %d stats %+v: want 2 frames carrying 16+3 segments", r.frames, st)
	}
	if st.Written != uint64(len(want)) || st.Failed != 0 {
		t.Fatalf("stats %+v: want %d written, 0 failed", st, len(want))
	}
}

// A frame the kernel refuses is written again one packet at a time, in order,
// so -tun-gso never loses what a plain writer would have delivered.
func TestAsyncTunWriteRefusedGSOFrameFallsBackPerPacket(t *testing.T) {
	r, w, want := runCoalescing(t, true)
	if len(r.got) != len(want) {
		t.Fatalf("kernel saw %d packets, want %d", len(r.got), len(want))
	}
	for i := range want {
		if !bytes.Equal(r.got[i], want[i]) {
			t.Fatalf("packet %d differs from the one submitted", i)
		}
	}
	if st := w.stats(); st.GSOFrames != 0 || st.Written != uint64(len(want)) || st.Failed != 0 {
		t.Fatalf("stats %+v: want no frames and every packet written alone", st)
	}
}
