package core

import "testing"

// TestTokenWindowCountsLateAndMissingAuthenticatedCounters: a counter consumed
// after a higher one is one reordering and fills one hole; a counter never
// consumed below the highest one is one loss.
func TestTokenWindowCountsLateAndMissingAuthenticatedCounters(t *testing.T) {
	var key [KeySize]byte
	for _, w := range []*tokenWindow{newTokenWindow(&key, 64), newCounterWindow(64)} {
		for _, c := range []uint64{0, 1, 3, 2, 4, 9, 5, 40, 41} {
			w.consume(c)
		}
		// Late: 2 after 3, 5 after 9. Missing: 6, 7, 8 and 10 to 39.
		if w.reordered != 2 {
			t.Fatalf("indexed=%v: reordered %d, want 2", w.indexed(), w.reordered)
		}
		if w.lost != 33 {
			t.Fatalf("indexed=%v: lost %d, want 33", w.indexed(), w.lost)
		}
	}
}

// TestTokenWindowCountsLossBeforeTheFirstCounter: a window whose first opened
// message is counter 3 lost 0, 1 and 2.
func TestTokenWindowCountsLossBeforeTheFirstCounter(t *testing.T) {
	w := newCounterWindow(64)
	w.consume(3)
	if w.reordered != 0 || w.lost != 3 {
		t.Fatalf("reordered %d lost %d, want 0 and 3", w.reordered, w.lost)
	}
}

// TestRecvFlowSurvivesAnEpochInstall: the counts of a retired window are
// carried, not lost with the window.
func TestRecvFlowSurvivesAnEpochInstall(t *testing.T) {
	s := &Session{role: RoleInitiator, windowSize: 64}
	if err := s.installEpoch(0); err != nil {
		t.Fatal(err)
	}
	for _, c := range []uint64{0, 2, 1, 5} {
		s.recvWindow.consume(c)
	}
	if err := s.installEpoch(1); err != nil {
		t.Fatal(err)
	}
	for _, c := range []uint64{1, 0} {
		s.recvWindow.consume(c)
	}
	reordered, lost := s.RecvFlow()
	if reordered != 2 || lost != 2 {
		t.Fatalf("RecvFlow reordered %d lost %d, want 2 (one per epoch) and 2 (3 and 4 of epoch 0)", reordered, lost)
	}
}

// TestRecvFlowCountsOnlySuccessfulOpens (Astra T2): the counts move only
// when a message authenticates and is consumed, on the scalar Open path and
// on the batch speculate and commit path alike. A forgery and a replay leave
// both counts as they were; a late authentic message moves one count from
// lost to reordered.
func TestRecvFlowCountsOnlySuccessfulOpens(t *testing.T) {
	for _, batch := range []bool{false, true} {
		a, z, pool := batchPair(t, 64)
		var msgs [][]byte
		for i := 0; i < 4; i++ {
			m, err := a.Seal([]byte{byte(i)}, 0)
			if err != nil {
				t.Fatal(err)
			}
			msgs = append(msgs, m)
		}
		open := func(m []byte) error {
			if !batch {
				_, err := z.Open(m)
				return err
			}
			slots := batchInputs(m)
			if err := z.SpeculateOpenBatch(pool, slots); err != nil {
				return err
			}
			_, err := z.CommitOpen(&slots[0])
			return err
		}
		want := func(step string, reordered, lost uint64) {
			t.Helper()
			if r, l := z.RecvFlow(); r != reordered || l != lost {
				t.Fatalf("batch=%v %s: reordered %d lost %d, want %d and %d", batch, step, r, l, reordered, lost)
			}
		}
		for _, i := range []int{0, 2} {
			if err := open(msgs[i]); err != nil {
				t.Fatal(err)
			}
		}
		want("0 then 2", 0, 1)
		bad := append([]byte(nil), msgs[1]...)
		bad[len(bad)-1] ^= 1
		if err := open(bad); err == nil {
			t.Fatalf("batch=%v: a forged message opened", batch)
		}
		want("forgery of 1", 0, 1)
		if err := open(msgs[1]); err != nil {
			t.Fatalf("batch=%v: late authentic message: %v", batch, err)
		}
		want("late 1", 1, 0)
		if err := open(msgs[1]); err == nil {
			t.Fatalf("batch=%v: a replay opened", batch)
		}
		want("replay of 1", 1, 0)
		if err := open(msgs[3]); err != nil {
			t.Fatalf("batch=%v: ordered suffix: %v", batch, err)
		}
		want("3", 1, 0)
	}
}
