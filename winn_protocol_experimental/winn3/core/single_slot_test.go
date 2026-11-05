package core

import (
	"bytes"
	"crypto/cipher"
	"runtime"
	"sync"
	"testing"
)

func assertPoolJobsCleared(t *testing.T, p *CryptoPool) {
	t.Helper()
	for _, j := range p.jobs {
		if j.aead != nil || j.nonce != [AEADNonceSize]byte{} || j.dst != nil || j.src != nil || j.aad != nil || j.plain != nil || j.err != nil {
			t.Fatal("completed batch retained job state")
		}
	}
}

type singleSlotLockAEAD struct {
	cipher.AEAD
	t         *testing.T
	pool      *CryptoPool
	sessionMu *sync.Mutex
}

func (a *singleSlotLockAEAD) checkLocks() {
	a.t.Helper()
	if a.pool.mu.TryLock() {
		a.pool.mu.Unlock()
		a.t.Fatal("single job ran without pool lock")
	}
	if a.sessionMu.TryLock() {
		a.sessionMu.Unlock()
		a.t.Fatal("single job ran without session lock")
	}
	if a.pool.queue != nil || a.pool.count != 0 {
		a.t.Fatal("single job started workers")
	}
}
func (a *singleSlotLockAEAD) Seal(dst, nonce, plain, aad []byte) []byte {
	a.checkLocks()
	return a.AEAD.Seal(dst, nonce, plain, aad)
}
func (a *singleSlotLockAEAD) Open(dst, nonce, msg, aad []byte) ([]byte, error) {
	a.checkLocks()
	return a.AEAD.Open(dst, nonce, msg, aad)
}

func TestSingleSlotWorkerlessRoundTripAndCleanup(t *testing.T) {
	a, z, p := batchPair(t, 8)
	if p.queue != nil || p.count != 0 {
		t.Fatal("constructor started workers")
	}
	scalar, err := newSession(RoleInitiator, chain{}, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer scalar.Wipe()
	a.sendAEAD = &singleSlotLockAEAD{AEAD: a.sendAEAD, t: t, pool: p, sessionMu: &a.sendMu}
	z.recvAEAD = &singleSlotLockAEAD{AEAD: z.recvAEAD, t: t, pool: p, sessionMu: &z.recvMu}
	payload := []byte("ordinary single slot")
	slots := []SealSlot{{Dst: make([]byte, 100), Payload: payload, PadTo: 100}}
	if err := a.SealBatchInto(p, slots); err != nil {
		t.Fatal(err)
	}
	expected, err := scalar.Seal(payload, 100)
	if err != nil || !bytes.Equal(slots[0].Dst, expected) {
		t.Fatalf("scalar bytes differ: %v", err)
	}
	assertPoolJobsCleared(t, p)
	opened := batchInputs(slots[0].Dst)
	if err := z.SpeculateOpenBatch(p, opened); err != nil {
		t.Fatal(err)
	}
	assertPoolJobsCleared(t, p)
	if z.RecvdBytes() != 0 {
		t.Fatal("speculation accounted bytes")
	}
	got, err := z.CommitOpen(&opened[0])
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("round trip: %v", err)
	}
	if a.SendCounter() != 1 || a.SentBytes() != 100 || z.RecvdBytes() != 100 {
		t.Fatal("single-slot accounting differs")
	}
	if p.queue != nil || p.count != 0 {
		t.Fatal("single-slot round trip started workers")
	}
}

func TestSingleSlotLaterParallelResize(t *testing.T) {
	old := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(old)
	a, z, p := batchPair(t, 8)
	send := func(n int) {
		t.Helper()
		slots := make([]SealSlot, n)
		for i := range slots {
			slots[i] = SealSlot{Dst: make([]byte, 100), Payload: []byte{byte(i)}}
		}
		if err := a.SealBatchInto(p, slots); err != nil {
			t.Fatal(err)
		}
		for i := range slots {
			if got, err := z.Open(slots[i].Dst); err != nil || !bytes.Equal(got, slots[i].Payload) {
				t.Fatalf("parallel output: %v", err)
			}
		}
		assertPoolJobsCleared(t, p)
	}
	send(1)
	if p.count != 0 || p.queue != nil {
		t.Fatal("initial single slot created workers")
	}
	send(2)
	if p.count != 2 || p.queue == nil {
		t.Fatal("parallel path did not start workers")
	}
	runtime.GOMAXPROCS(1)
	send(1)
	if p.count != 2 {
		t.Fatal("single slot unexpectedly resized idle workers")
	}
	send(2)
	if p.count != 1 {
		t.Fatal("parallel batch did not honor reduced GOMAXPROCS")
	}
	runtime.GOMAXPROCS(3)
	send(2)
	if p.count != 3 {
		t.Fatal("parallel batch did not honor increased GOMAXPROCS")
	}
}

func TestSingleSlotEmptyAndFreshClose(t *testing.T) {
	a, z, p := batchPair(t, 8)
	if err := a.SealBatchInto(p, nil); err != nil {
		t.Fatal(err)
	}
	if err := z.SpeculateOpenBatch(p, nil); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.runLocked(0)
	p.mu.Unlock()
	if p.count != 0 || p.queue != nil {
		t.Fatal("empty work started workers")
	}
	p.Close()
	p.Close()
	var absent *CryptoPool
	absent.Close()
	if !p.closed || p.queue != nil || p.count != 0 {
		t.Fatal("fresh close retained pool state")
	}
	if err := a.SealBatchInto(p, nil); err != nil {
		t.Fatal("empty closed batch contract changed", err)
	}
	if err := z.SpeculateOpenBatch(p, nil); err != nil {
		t.Fatal("empty closed batch contract changed", err)
	}
	if err := a.SealBatchInto(p, []SealSlot{{Dst: make([]byte, 100), Payload: []byte("ordinary")}}); err != ErrPoolClosed {
		t.Fatal(err)
	}
	msg, err := a.Seal([]byte("ordinary"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := z.SpeculateOpenBatch(p, batchInputs(msg)); err != ErrPoolClosed {
		t.Fatal(err)
	}
	assertPoolJobsCleared(t, p)
}

func TestSingleSlotUsesResolvedJobCount(t *testing.T) {
	a, z, p := batchPair(t, 1)
	first, err := a.Seal([]byte("first"), 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.Seal([]byte("second"), 0)
	if err != nil {
		t.Fatal(err)
	}
	future := batchInputs(second)
	if err := z.SpeculateOpenBatch(p, future); err != nil {
		t.Fatal(err)
	}
	if future[0].resolved || p.queue != nil || p.count != 0 {
		t.Fatal("zero resolved jobs started workers")
	}
	slots := batchInputs(first, second)
	if err := z.SpeculateOpenBatch(p, slots); err != nil {
		t.Fatal(err)
	}
	if !slots[0].resolved || slots[1].resolved || p.queue != nil || p.count != 0 {
		t.Fatal("one resolved job did not use inline path")
	}
	for i, want := range []string{"first", "second"} {
		got, err := z.CommitOpen(&slots[i])
		if err != nil || string(got) != want {
			t.Fatalf("ordered refill: %v", err)
		}
	}
	if z.RecvdBytes() != a.SentBytes() {
		t.Fatal("ordered refill byte accounting differs")
	}
	assertPoolJobsCleared(t, p)
}
