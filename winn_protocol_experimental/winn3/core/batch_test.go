package core

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"
)

func batchPair(t testing.TB, window int) (*Session, *Session, *CryptoPool) {
	t.Helper()
	a, err := newSession(RoleInitiator, chain{}, window)
	if err != nil {
		t.Fatal(err)
	}
	z, err := newSession(RoleResponder, chain{}, window)
	if err != nil {
		t.Fatal(err)
	}
	p := NewCryptoPool()
	t.Cleanup(func() { p.Close(); a.Wipe(); z.Wipe() })
	return a, z, p
}

func batchInputs(msgs ...[]byte) []OpenSlot {
	x := make([]OpenSlot, len(msgs))
	for i, m := range msgs {
		x[i] = OpenSlot{Msg: m, Dst: make([]byte, len(m))}
	}
	return x
}

type reorderedAEAD struct {
	cipher.AEAD
	second    chan struct{}
	mu        sync.Mutex
	completed []uint64
}

func (a *reorderedAEAD) Seal(dst, nonce, plain, aad []byte) []byte {
	c := binary.BigEndian.Uint64(nonce[nonceSaltSize:])
	if c == 0 {
		<-a.second
	}
	out := a.AEAD.Seal(dst, nonce, plain, aad)
	a.mu.Lock()
	a.completed = append(a.completed, c)
	a.mu.Unlock()
	if c == 1 {
		close(a.second)
	}
	return out
}

func TestStage5BatchNonceAndOrderedOutput(t *testing.T) {
	old := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(old)
	a, z, p := batchPair(t, DefaultTokenWindow)
	legacy, err := newSession(RoleInitiator, chain{}, DefaultTokenWindow)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Wipe()
	wrapped := &reorderedAEAD{AEAD: a.sendAEAD, second: make(chan struct{})}
	a.sendAEAD = wrapped
	var slots [MaxBatchSize]SealSlot
	for i := range slots {
		slots[i] = SealSlot{Dst: make([]byte, 180), Payload: bytes.Repeat([]byte{byte(i)}, 80), PadTo: 160}
	}
	if err := a.SealBatchInto(p, slots[:]); err != nil {
		t.Fatal(err)
	}
	if wrapped.completed[0] == 0 {
		t.Fatal("test failed to force out-of-order completion")
	}
	seen := make(map[string]bool)
	for i := range slots {
		want, err := legacy.Seal(slots[i].Payload, slots[i].PadTo)
		if err != nil || !bytes.Equal(want, slots[i].Dst) {
			t.Fatalf("slot %d differs from sequential nonce order: %v", i, err)
		}
		token := string(slots[i].Dst[:DemuxTokenSize])
		if seen[token] {
			t.Fatal("nonce token reused")
		}
		seen[token] = true
		got, err := z.Open(slots[i].Dst)
		if err != nil || !bytes.Equal(got, slots[i].Payload) {
			t.Fatalf("slot %d: %v", i, err)
		}
	}
	if a.SendCounter() != MaxBatchSize || a.SentBytes() != MaxBatchSize*160 || z.RecvdBytes() != a.SentBytes() {
		t.Fatal("unstable ordered byte accounting")
	}
	for i := range p.jobs {
		if p.jobs[i].aead != nil || p.jobs[i].nonce != [AEADNonceSize]byte{} {
			t.Fatal("worker retained an epoch reference")
		}
	}
}

func TestStage5BatchValidationAtomicAndCounterCeiling(t *testing.T) {
	a, _, p := batchPair(t, 8)
	x := []SealSlot{{Dst: make([]byte, 100), Payload: []byte("a")}, {Dst: make([]byte, 1), Payload: []byte("b")}}
	if err := a.SealBatchInto(p, x); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal(err)
	}
	if a.SendCounter() != 0 || a.SentBytes() != 0 {
		t.Fatal("partial validation consumed nonce/bytes")
	}
	x[1].Dst = make([]byte, 100)
	a.sendCounter = RejectAfterMessages - 1
	if err := a.SealBatchInto(p, x); err != ErrCounterExhausted {
		t.Fatal(err)
	}
	if a.sendCounter != RejectAfterMessages-1 || a.sentBytes != 0 {
		t.Fatal("failed ceiling check reserved counters")
	}
	if err := a.SealBatchInto(p, x[:1]); err != nil {
		t.Fatal(err)
	}
	if a.sendCounter != RejectAfterMessages {
		t.Fatal("last permitted nonce not reserved")
	}
	if err := a.SealBatchInto(p, make([]SealSlot, 65)); err != ErrBatchSize {
		t.Fatal(err)
	}
	p.Close()
	if err := a.SealBatchInto(p, x[:1]); err != ErrPoolClosed {
		t.Fatal(err)
	}
}

func TestStage5BatchCorruptGenuineAndPendingDuplicate(t *testing.T) {
	for _, corruptFirst := range []bool{true, false} {
		t.Run(fmt.Sprint(corruptFirst), func(t *testing.T) {
			a, z, p := batchPair(t, 8)
			msg, err := a.Seal([]byte("authentic"), 100)
			if err != nil {
				t.Fatal(err)
			}
			bad := bytes.Clone(msg)
			bad[len(bad)-1] ^= 1
			x := batchInputs(msg, msg, bad)
			if corruptFirst {
				x = batchInputs(bad, msg, msg)
			}
			if err := z.SpeculateOpenBatch(p, x); err != nil {
				t.Fatal(err)
			}
			if z.RecvdBytes() != 0 {
				t.Fatal("speculation accounted bytes")
			}
			accepted := 0
			for i := range x {
				out, err := z.CommitOpen(&x[i])
				if err == nil {
					accepted++
					if string(out) != "authentic" {
						t.Fatal("corrupted plaintext")
					}
				}
				if corruptFirst && i == 0 && err != ErrDecrypt {
					t.Fatal("corrupt pending ticket did not fail AEAD", err)
				}
				if _, err := z.CommitOpen(&x[i]); err == nil {
					t.Fatal("ticket committed twice")
				}
			}
			if accepted != 1 || z.RecvdBytes() != uint64(len(msg)) {
				t.Fatalf("accepted %d times, bytes %d", accepted, z.RecvdBytes())
			}
		})
	}
}

func TestStage5BatchWindowRefillAndPreview(t *testing.T) {
	a, z, p := batchPair(t, 8)
	x := make([]OpenSlot, MaxBatchSize)
	for i := range x {
		msg, err := a.Seal([]byte{byte(i)}, 0)
		if err != nil {
			t.Fatal(err)
		}
		x[i] = OpenSlot{Msg: msg, Dst: make([]byte, len(msg))}
	}
	if err := z.SpeculateOpenBatch(p, x); err != nil {
		t.Fatal(err)
	}
	if x[8].resolved {
		t.Fatal("test did not exceed initial lookup window")
	}
	for i := range x {
		before := z.RecvdBytes()
		preview, err := z.PreviewOpen(&x[i])
		if err != nil || !bytes.Equal(preview, []byte{byte(i)}) {
			t.Fatalf("preview %d: %v", i, err)
		}
		if z.RecvdBytes() != before {
			t.Fatal("preview consumed accounting")
		}
		plain, err := z.CommitOpen(&x[i])
		if err != nil || !bytes.Equal(plain, preview) {
			t.Fatalf("refilled slot %d: %v", i, err)
		}
	}
	if z.RecvdBytes() != a.SentBytes() {
		t.Fatal("refill accounting differs")
	}
}

func TestStage5BatchEpochRetryAndWipeCancellation(t *testing.T) {
	a, z, p := batchPair(t, 8)
	old, _ := a.Seal([]byte("old"), 0)
	late, _ := a.Seal([]byte("late old"), 0)
	secret := bytes.Repeat([]byte{7}, 32)
	if err := a.Rekey(secret); err != nil {
		t.Fatal(err)
	}
	fresh, _ := a.Seal([]byte("new"), 0)
	x := batchInputs(old, fresh, late)
	if err := z.SpeculateOpenBatch(p, x); err != nil {
		t.Fatal(err)
	}
	if _, err := z.CommitOpen(&x[0]); err != nil {
		t.Fatal(err)
	}
	if err := z.Rekey(secret); err != nil {
		t.Fatal(err)
	}
	out, err := z.CommitOpen(&x[1])
	if err != nil || string(out) != "new" {
		t.Fatal("speculative new-epoch failure was not retried", err)
	}
	if _, err := z.CommitOpen(&x[2]); err == nil {
		t.Fatal("old epoch plaintext committed after cut")
	}
	fresh, _ = a.Seal([]byte("cancel"), 0)
	x = batchInputs(fresh)
	if err := z.SpeculateOpenBatch(p, x); err != nil {
		t.Fatal(err)
	}
	before := z.RecvdBytes()
	z.Wipe()
	if _, err := z.CommitOpen(&x[0]); err != ErrWiped {
		t.Fatal(err)
	}
	if z.RecvdBytes() != before || z.recvAEAD != nil || z.recvWindow != nil {
		t.Fatal("canceled ticket changed wiped state")
	}
}

type blockedBatchAEAD struct {
	cipher.AEAD
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (a *blockedBatchAEAD) pause() { a.once.Do(func() { close(a.entered); <-a.release }) }
func (a *blockedBatchAEAD) Seal(dst, nonce, plain, aad []byte) []byte {
	a.pause()
	return a.AEAD.Seal(dst, nonce, plain, aad)
}
func (a *blockedBatchAEAD) Open(dst, nonce, msg, aad []byte) ([]byte, error) {
	a.pause()
	return a.AEAD.Open(dst, nonce, msg, aad)
}

func TestStage5BatchJoinBeforeRekeyWipeAndPoolClose(t *testing.T) {
	for _, operation := range []string{"send-rekey", "recv-wipe", "pool-close"} {
		t.Run(operation, func(t *testing.T) {
			a, z, p := batchPair(t, 8)
			block := &blockedBatchAEAD{entered: make(chan struct{}), release: make(chan struct{})}
			workDone := make(chan error, 1)
			if operation == "recv-wipe" {
				msg, _ := a.Seal([]byte("pending"), 0)
				block.AEAD = z.recvAEAD
				z.recvAEAD = block
				x := batchInputs(msg)
				go func() { workDone <- z.SpeculateOpenBatch(p, x) }()
			} else {
				block.AEAD = a.sendAEAD
				a.sendAEAD = block
				x := []SealSlot{{Dst: make([]byte, 100), Payload: []byte("pending")}}
				go func() { workDone <- a.SealBatchInto(p, x) }()
			}
			select {
			case <-block.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("worker did not start")
			}
			barrierDone := make(chan error, 1)
			go func() {
				switch operation {
				case "send-rekey":
					barrierDone <- a.Rekey(bytes.Repeat([]byte{9}, 32))
				case "recv-wipe":
					z.Wipe()
					barrierDone <- nil
				case "pool-close":
					p.Close()
					barrierDone <- nil
				}
			}()
			select {
			case err := <-barrierDone:
				t.Fatalf("barrier passed live worker: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			close(block.release)
			select {
			case err := <-workDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("worker join deadlocked")
			}
			select {
			case err := <-barrierDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("barrier deadlocked")
			}
			for i := range p.jobs {
				if p.jobs[i].aead != nil {
					t.Fatal("old AEAD retained")
				}
			}
		})
	}
}

func BenchmarkStage5BatchRoundTrip(b *testing.B) {
	for _, count := range []int{1, 8, 32} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			a, z, p := batchPair(b, DefaultTokenWindow)
			seal := make([]SealSlot, count)
			open := make([]OpenSlot, count)
			for i := range seal {
				seal[i] = SealSlot{Dst: make([]byte, 1500), Payload: make([]byte, 1200)}
				open[i].Dst = make([]byte, 1500)
			}
			b.ReportAllocs()
			b.SetBytes(int64(count * 1200))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := a.SealBatchInto(p, seal); err != nil {
					b.Fatal(err)
				}
				for j := range open {
					open[j].Msg = seal[j].Dst
				}
				if err := z.SpeculateOpenBatch(p, open); err != nil {
					b.Fatal(err)
				}
				for j := range open {
					if _, err := z.CommitOpen(&open[j]); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
