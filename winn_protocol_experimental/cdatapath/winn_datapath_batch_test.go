//go:build darwin && winn3_batch_test

package main

import (
	"bytes"
	"runtime"
	"sync"
	"testing"
	"time"
	"unsafe"
)

func batchIP(version, tag byte) []byte {
	n := 20
	if version == 6 {
		n = 40
	}
	p := make([]byte, n)
	p[0] = version << 4
	p[n-1] = tag
	return p
}

func registerBatchDevice(t *testing.T) (int64, *abiDevice) {
	t.Helper()
	d := newABIDevice(1500)
	h := nextHandle.Add(1)
	winn3Mu.Lock()
	winn3Registry[h] = &winn3Tunnel{dev: d}
	winn3Mu.Unlock()
	t.Cleanup(func() {
		winn3Mu.Lock()
		delete(winn3Registry, h)
		winn3Mu.Unlock()
		d.close()
	})
	return h, d
}

func TestBatchEnqueueValidatesEntireArrayAndCopies(t *testing.T) {
	h, d := registerBatchDevice(t)
	b := newNativeBatch(32, 64)
	for i := range b.packets {
		b.setPacket(i, batchIP(4, byte(i)))
	}
	b.packets[31].family = 30 // AF_INET6 on Darwin, contradicts version 4.
	if n := b.enqueue(h, 32, 24); n != errArgument {
		t.Fatalf("invalid tail = %d", n)
	}
	if len(d.outbound) != 0 || d.droppedOutbound.Load() != 0 {
		t.Fatal("invalid batch had side effects")
	}
	b.setPacket(31, batchIP(6, 31))
	if n := b.enqueue(h, 32, 24); n != 32 {
		t.Fatalf("enqueue = %d", n)
	}
	for i := range b.packets {
		clear(b.bytes(i))
	}
	b.free()
	runtime.GC()
	buf := make([]byte, 64)
	for i := 0; i < 32; i++ {
		n, err := d.ReadPacket(buf)
		version := byte(4)
		if i == 31 {
			version = 6
		}
		if err != nil || !bytes.Equal(buf[:n], batchIP(version, byte(i))) {
			t.Fatalf("copy/order %d: %x %v", i, buf[:n], err)
		}
	}
}

func TestBatchBadDescriptorsHaveNoSideEffects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*nativeBatch)
	}{
		{"nil-data", func(b *nativeBatch) { b.packets[1].data = nil }},
		{"zero-length", func(b *nativeBatch) { b.packets[1].length = 0 }},
		{"length-over-capacity", func(b *nativeBatch) { b.packets[1].length = 65 }},
		{"zero-capacity", func(b *nativeBatch) { b.packets[1].capacity = 0 }},
		{"huge-capacity", func(b *nativeBatch) { b.packets[1].capacity = 65536 }},
		{"reserved", func(b *nativeBatch) { b.packets[1].reserved = 1 }},
		{"bad-family", func(b *nativeBatch) { b.packets[1].family = 99 }},
		{"bad-version", func(b *nativeBatch) { b.bytes(1)[0] = 0x70 }},
		{"short-header", func(b *nativeBatch) { b.packets[1].length = 19 }},
		{"descriptor-alias", func(b *nativeBatch) { b.packets[1].data = b.raw }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, d := registerBatchDevice(t)
			b := newNativeBatch(2, 64)
			defer b.free()
			b.setPacket(0, batchIP(4, 1))
			b.setPacket(1, batchIP(4, 2))
			tc.mutate(b)
			if n := b.enqueue(h, 2, 24); n != errArgument {
				t.Fatalf("got %d", n)
			}
			if len(d.outbound) != 0 {
				t.Fatal("prefix was enqueued before tail validation")
			}
		})
	}
}

func TestBatchEnvelopeLimits(t *testing.T) {
	h, _ := registerBatchDevice(t)
	b := newNativeBatch(1, 64)
	defer b.free()
	b.setPacket(0, batchIP(4, 1))
	for _, tc := range [][2]int{{-1, 24}, {33, 24}, {1, 0}, {1, 23}, {1, 32}} {
		if n := b.enqueue(h, tc[0], tc[1]); n != errArgument {
			t.Fatalf("%v = %d", tc, n)
		}
	}
	if n := b.enqueue(h, 0, 24); n != 0 {
		t.Fatalf("empty = %d", n)
	}
	if n := b.enqueue(-1, 1, 24); n != errHandle {
		t.Fatalf("unknown = %d", n)
	}
	original := b.raw
	b.raw = unsafe.Add(original, 1)
	if n := b.enqueue(h, 1, 24); n != errArgument {
		t.Fatalf("unaligned = %d", n)
	}
	b.raw = nil
	if n := b.enqueue(h, 1, 24); n != errArgument {
		t.Fatalf("nil = %d", n)
	}
	b.raw = original
}

func TestBatchPressurePreservesDropOldest(t *testing.T) {
	h, d := registerBatchDevice(t)
	d.depth = 3
	b := newNativeBatch(4, 64)
	defer b.free()
	for i := range b.packets {
		b.setPacket(i, batchIP(4, byte(i)))
	}
	if n := b.enqueue(h, 4, 24); n != 4 {
		t.Fatalf("enqueue = %d", n)
	}
	if d.droppedOutbound.Load() != 1 || len(d.outbound) != 3 {
		t.Fatal("queue policy changed")
	}
	for i, p := range d.outbound {
		if p[19] != byte(i+1) {
			t.Fatal("wrong eviction/order")
		}
	}
}

func TestBatchDequeuePrefixAndShortBufferRetry(t *testing.T) {
	h, d := registerBatchDevice(t)
	d.WritePacket(batchIP(4, 1))
	d.WritePacket(batchIP(6, 2))
	d.WritePacket(batchIP(4, 3))
	b := newNativeBatch(3, 64)
	defer b.free()
	b.packets[1].capacity = 20
	for i := range b.packets {
		for j := range b.bytes(i) {
			b.bytes(i)[j] = 0xa5
		}
	}
	if n := b.dequeue(h, 3, 24, 1); n != 1 {
		t.Fatalf("prefix = %d", n)
	}
	if b.packets[0].length != 20 || b.packets[0].family != 2 || b.packets[1].length != 0 || b.packets[2].family != 0 {
		t.Fatal("metadata changed outside prefix")
	}
	if b.bytes(1)[0] != 0xa5 || b.bytes(2)[0] != 0xa5 || len(d.inbound) != 2 {
		t.Fatal("suffix/queue mutated")
	}
	short := newNativeBatch(1, 20)
	defer short.free()
	if n := short.dequeue(h, 1, 24, 1); n != errTooLarge || len(d.inbound) != 2 {
		t.Fatalf("short retry = %d", n)
	}
	out := newNativeBatch(3, 64)
	defer out.free()
	if n := out.dequeue(h, 3, 24, 1); n != 2 {
		t.Fatalf("retry = %d", n)
	}
	if out.packets[0].family != 30 || out.packets[1].family != 2 {
		t.Fatal("mixed family lost")
	}
	if !bytes.Equal(out.bytes(0)[:40], batchIP(6, 2)) || !bytes.Equal(out.bytes(1)[:20], batchIP(4, 3)) {
		t.Fatal("wrong packet bytes")
	}
}

func TestBatchDequeueRejectsTailBeforeConsumption(t *testing.T) {
	for _, alias := range []bool{false, true} {
		h, d := registerBatchDevice(t)
		d.WritePacket(batchIP(4, 1))
		b := newNativeBatch(2, 64)
		if alias {
			b.packets[1].data = b.packets[0].data
		} else {
			b.packets[1].family = 2
		}
		if n := b.dequeue(h, 2, 24, 1); n != errArgument {
			t.Fatalf("invalid output = %d", n)
		}
		if len(d.inbound) != 1 || b.packets[0].length != 0 || b.bytes(0)[0] != 0 {
			t.Fatal("invalid tail consumed/wrote prefix")
		}
		b.free()
	}
}

func TestBatchDequeueTimeoutAndClose(t *testing.T) {
	h, d := registerBatchDevice(t)
	b := newNativeBatch(1, 64)
	defer b.free()
	start := time.Now()
	if n := b.dequeue(h, 1, 24, 15); n != errTimeout {
		t.Fatalf("timeout = %d", n)
	}
	if elapsed := time.Since(start); elapsed < 10*time.Millisecond || elapsed > time.Second {
		t.Fatalf("deadline %v", elapsed)
	}
	done := make(chan int, 1)
	go func() { done <- b.dequeue(h, 1, 24, 0) }()
	time.Sleep(10 * time.Millisecond)
	d.close()
	select {
	case n := <-done:
		if n != errClosed {
			t.Fatalf("close = %d", n)
		}
	case <-time.After(time.Second):
		t.Fatal("close failed to wake reader")
	}
	b.setPacket(0, batchIP(4, 1))
	if n := b.enqueue(h, 1, 24); n != errClosed {
		t.Fatalf("enqueue after close = %d", n)
	}
}

func TestBatchConcurrentProducersAndClose(t *testing.T) {
	h, d := registerBatchDevice(t)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := newNativeBatch(32, 64)
			defer b.free()
			for i := range b.packets {
				b.setPacket(i, batchIP(4, byte(i)))
			}
			for i := 0; i < 100; i++ {
				n := b.enqueue(h, 32, 24)
				if n != 32 && n != errClosed {
					t.Errorf("race result %d", n)
					return
				}
			}
		}()
	}
	time.Sleep(time.Millisecond)
	d.close()
	wg.Wait()
	if len(d.outbound) != 0 {
		t.Fatal("enqueue resurrected closed queue")
	}
}

func TestBatchPublicCloseRetiresHandleWhileReadWaits(t *testing.T) {
	fd, peer, file := loopbackPair(t)
	defer peer.Close()
	defer file.Close()
	tunnel, err := openWinn3(encode(t, baseConfig(t)), fd)
	if err != nil {
		t.Fatal(err)
	}
	h := nextHandle.Add(1)
	winn3Mu.Lock()
	winn3Registry[h] = tunnel
	winn3Mu.Unlock()
	defer nativeClose(h)
	b := newNativeBatch(1, 64)
	defer b.free()
	done := make(chan int, 1)
	go func() { done <- b.dequeue(h, 1, 24, 0) }()
	time.Sleep(10 * time.Millisecond)
	nativeClose(h)
	select {
	case n := <-done:
		if n != errClosed && n != errHandle {
			t.Fatalf("close result %d", n)
		}
	case <-time.After(time.Second):
		t.Fatal("public close stranded reader")
	}
	if n := b.dequeue(h, 1, 24, 1); n != errHandle {
		t.Fatalf("retired handle = %d", n)
	}
}
