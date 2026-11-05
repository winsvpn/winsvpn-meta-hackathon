package carrier

import (
	"testing"
	"time"
)

// TestSessionDeduplicatorSlidesPast4096 pins the H2/H3 silent-continue path
// in server_envelope.go: defaultSequenceWindow is 4096, Accept() false is
// `continue` (the datagram is dropped with no error to the peer), and that
// combination is the same shape as the Spain "4096 datagrams then silence"
// cliff if the window were a hard cap rather than a sliding one.
//
// There was no test of SessionDeduplicator at all. This one requires the
// shipping window to admit monotonically increasing sequences past 4096, and
// still reject a sequence that has fallen behind it.
func TestSessionDeduplicatorSlidesPast4096(t *testing.T) {
	if defaultSequenceWindow != 4096 {
		t.Fatalf("defaultSequenceWindow=%d, want 4096 (the silent-drop window H2/H3 construct with NewSessionDeduplicator)", defaultSequenceWindow)
	}
	d, err := NewSessionDeduplicator(defaultSessionLimit, defaultSequenceWindow)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	const past = 4096 + 500
	for seq := uint64(1); seq <= past; seq++ {
		if !d.Accept("session-a", seq, now) {
			t.Fatalf("Accept(%d)=false; a sliding window of %d must admit monotonic sequences past 4096 (a hard cap would die here)", seq, defaultSequenceWindow)
		}
	}
	if d.Accept("session-a", past, now) {
		t.Fatal("duplicate of the last accepted sequence was admitted")
	}
	behind := uint64(past) - uint64(defaultSequenceWindow)
	if d.Accept("session-a", behind, now) {
		t.Fatalf("Accept(%d)=true; sequence+window <= highest must drop a datagram that has fallen behind the window", behind)
	}
}

func TestSessionDeduplicatorRejectsZeroAndEmpty(t *testing.T) {
	d, err := NewSessionDeduplicator(8, 64)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	if d.Accept("", 1, now) {
		t.Fatal("empty session ID was admitted")
	}
	if d.Accept("session-a", 0, now) {
		t.Fatal("sequence 0 was admitted; encodeEnvelope also refuses it, so a zero would be a silent drop on the relay path")
	}
	if d.Accept("session-a", 1, now) != true {
		t.Fatal("first positive sequence was refused")
	}
}
