package session

import (
	"bytes"
	"errors"
	"testing"

	"winsvpn.local/winnprotocol/winn3/core"
)

func TestBlobReassemblyIsReorderSafe(t *testing.T) {
	blob := make([]byte, 300)
	for i := range blob {
		blob[i] = byte(i)
	}
	chunks := chunkBlob(core.FramePQEK, blob, 66)
	if len(chunks) < 4 {
		t.Fatalf("expected several chunks, got %d", len(chunks))
	}

	// Reverse order. The transport tolerates reorder by design, so a receiver
	// that concatenated in arrival order would assemble a scrambled ML-KEM key
	// and fail decapsulation with no idea why.
	rx := newBlobRx(len(blob))
	for i := len(chunks) - 1; i >= 0; i-- {
		done, err := rx.accept(chunks[i].value)
		if err != nil {
			t.Fatal(err)
		}
		if done != (i == 0) {
			t.Fatalf("chunk %d reported done=%v", i, done)
		}
	}
	if !bytes.Equal(rx.bytes(), blob) {
		t.Error("reassembled blob differs from the original")
	}
}

// TestBlobReassemblyIsIdempotent is what makes retransmitting a whole blob a
// legal recovery step: the sender cannot tell which chunk was lost and the
// receiver cannot tell the sender, so the sender resends everything and the
// receiver must not care.
func TestBlobReassemblyIsIdempotent(t *testing.T) {
	blob := []byte("0123456789abcdef")
	chunks := chunkBlob(core.FramePQCT, blob, 6)
	rx := newBlobRx(len(blob))

	// Every chunk three times, interleaved.
	for pass := 0; pass < 3; pass++ {
		for i, c := range chunks {
			done, err := rx.accept(c.value)
			if err != nil {
				t.Fatalf("pass %d chunk %d: %v", pass, i, err)
			}
			if done && !(pass == 0 && i == len(chunks)-1) && !rx.complete() {
				t.Fatalf("pass %d chunk %d reported done on an incomplete blob", pass, i)
			}
		}
	}
	if !rx.complete() {
		t.Fatal("blob never completed")
	}
	if !bytes.Equal(rx.bytes(), blob) {
		t.Error("duplicate chunks corrupted the blob")
	}
}

// TestBlobReassemblyRejectsMalformedChunks: a chunk arrives inside the transport
// AEAD, so it came from the peer and nothing else. Leniency here would be a
// parsing differential between implementations, and a parsing differential is a
// fingerprint.
func TestBlobReassemblyRejectsMalformedChunks(t *testing.T) {
	cases := []struct {
		name  string
		value []byte
	}{
		{"empty", nil},
		{"offset only", []byte{0, 0}},
		{"one byte", []byte{0}},
		{"runs past the end", []byte{0, 30, 1, 2, 3}},
		{"offset past the end", []byte{0xff, 0xff, 1}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rx := newBlobRx(32)
			done, err := rx.accept(c.value)
			if err == nil {
				t.Fatalf("accepted %v", c.value)
			}
			if !errors.Is(err, ErrProtocol) {
				t.Errorf("error is %v, want ErrProtocol", err)
			}
			if done {
				t.Error("a malformed chunk reported completion")
			}
		})
	}
}

func TestChunkBlobHandlesADegenerateBudget(t *testing.T) {
	// A budget at or below the offset size cannot carry anything; the splitter
	// must still make progress rather than loop.
	for _, budget := range []int{0, 1, 2, 3} {
		chunks := chunkBlob(core.FramePQEK, []byte("abcd"), budget)
		if len(chunks) == 0 {
			t.Fatalf("budget %d produced no chunks", budget)
		}
		rx := newBlobRx(4)
		var done bool
		for _, c := range chunks {
			var err error
			done, err = rx.accept(c.value)
			if err != nil {
				t.Fatalf("budget %d: %v", budget, err)
			}
		}
		if !done {
			t.Errorf("budget %d never completed the blob", budget)
		}
	}
	if n := len(chunkBlob(core.FramePQEK, nil, 64)); n != 0 {
		t.Errorf("an empty blob produced %d chunks", n)
	}
}

func TestPingAndPongFramesCopyTheirTokens(t *testing.T) {
	tok := [pingTokenSize]byte{9, 8, 7, 6, 5, 4, 3, 2}
	f := pingFrame(tok, false)
	if !bytes.Equal(f.value, tok[:]) {
		t.Fatalf("ping value is %v", f.value)
	}
	f.value[0] = 0
	if tok[0] != 9 {
		t.Error("pingFrame aliased the caller's token")
	}

	src := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	g := pongFrame(src, false)
	src[0] = 0
	if g.value[0] != 1 {
		t.Error("pongFrame aliased the caller's buffer")
	}
	if f.encodedSize() != frameHeaderSize+pingTokenSize {
		t.Errorf("encodedSize is %d", f.encodedSize())
	}
	if padFrame().encodedSize() != frameHeaderSize {
		t.Error("an empty pad frame is not header-sized")
	}
}
