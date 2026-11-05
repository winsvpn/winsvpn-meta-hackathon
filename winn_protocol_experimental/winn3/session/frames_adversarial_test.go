package session

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"winsvpn.local/winnprotocol/winn3/core"
)

func chunkValue(off uint16, data []byte) []byte {
	v := make([]byte, chunkOffsetSize+len(data))
	binary.BigEndian.PutUint16(v[:chunkOffsetSize], off)
	copy(v[chunkOffsetSize:], data)
	return v
}

// TestBlobRxAcceptFenceposts pins the arithmetic in blobRx.accept. A chunk
// arrives inside the transport AEAD, so a panic or an over-write past buf is
// a session DoS / memory corruption on a peer-supplied offset.
func TestBlobRxAcceptFenceposts(t *testing.T) {
	cases := []struct {
		name    string
		total   int
		value   []byte
		wantErr bool
		wantN   int
		done    bool
	}{
		{"empty", 32, nil, true, 0, false},
		{"offset only", 32, []byte{0, 0}, true, 0, false},
		{"one byte", 32, []byte{0}, true, 0, false},
		{"exact fill of a 4-byte blob", 4, chunkValue(0, []byte("abcd")), false, 4, true},
		{"exact fill at the tail", 8, chunkValue(6, []byte("xy")), false, 2, false},
		{"one byte past the tail", 8, chunkValue(6, []byte("xyz")), true, 0, false},
		{"offset equal to the blob length", 8, chunkValue(8, []byte{1}), true, 0, false},
		{"offset 0xFFFF against a small blob", 32, chunkValue(0xFFFF, []byte{1}), true, 0, false},
		{"offset 0xFFFF empty-data is already too short", 32, []byte{0xff, 0xff}, true, 0, false},
		{"single byte at offset 0", 8, chunkValue(0, []byte{'A'}), false, 1, false},
		{"single byte at last index", 8, chunkValue(7, []byte{'Z'}), false, 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rx := newBlobRx(tc.total)
			done, err := rx.accept(tc.value)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("accepted %v", tc.value)
				}
				if !errors.Is(err, ErrProtocol) {
					t.Fatalf("error is %v, want ErrProtocol", err)
				}
				if done {
					t.Fatal("a malformed chunk reported completion")
				}
				if rx.n != 0 {
					t.Fatalf("a rejected chunk covered %d bytes", rx.n)
				}
				return
			}
			if err != nil {
				t.Fatalf("rejected a well-formed chunk: %v", err)
			}
			if done != tc.done {
				t.Fatalf("done=%v, want %v", done, tc.done)
			}
			if rx.n != tc.wantN {
				t.Fatalf("covered %d bytes, want %d", rx.n, tc.wantN)
			}
		})
	}
}

// TestBlobRxOverlappingChunksAreIdempotentAndComplete pins per-byte coverage:
// two overlapping chunks that together cover the blob must complete once,
// and a third overlapping copy must not change the bytes.
func TestBlobRxOverlappingChunksAreIdempotentAndComplete(t *testing.T) {
	blob := []byte("01234567")
	rx := newBlobRx(len(blob))
	if done, err := rx.accept(chunkValue(0, blob[:6])); err != nil || done {
		t.Fatalf("first: done=%v err=%v", done, err)
	}
	done, err := rx.accept(chunkValue(4, blob[4:]))
	if err != nil {
		t.Fatal(err)
	}
	if !done {
		t.Fatal("overlapping tail did not complete the blob")
	}
	if !bytes.Equal(rx.bytes(), blob) {
		t.Fatalf("got %q, want %q", rx.bytes(), blob)
	}
	done, err = rx.accept(chunkValue(0, blob))
	if err != nil || !done {
		t.Fatalf("full-blob retry: done=%v err=%v", done, err)
	}
	if !bytes.Equal(rx.bytes(), blob) {
		t.Fatal("a duplicate overlapping chunk mutated the blob")
	}
}

// TestNewBlobRxZeroIsAlreadyComplete documents the current behaviour of an
// empty reassembly target. Production callers pass PQEncapsulationKeySize
// (1184) or PQCiphertextSize (1088), never 0. complete() is n == len(buf),
// so a zero-length target is complete before any chunk. That must not
// silently become a panic on make([]byte, 0), and it must not start
// accepting chunks that write past a zero buffer.
func TestNewBlobRxZeroIsAlreadyComplete(t *testing.T) {
	rx := newBlobRx(0)
	if !rx.complete() {
		t.Fatal("a zero-length blob was not complete at construction")
	}
	done, err := rx.accept(chunkValue(0, []byte{1}))
	if err == nil || done {
		t.Fatalf("a chunk against a zero-length blob: done=%v err=%v", done, err)
	}
}

// TestChunkBlobPQSizesReassemble pins that the only production blob sizes
// survive split/reassemble at a tight budget. Offsets are uint16; these
// sizes (1184, 1088) sit far below 65535, so the truncation that would
// hit a >65535 blob is not reachable on this path.
func TestChunkBlobPQSizesReassemble(t *testing.T) {
	for _, total := range []int{core.PQEncapsulationKeySize, core.PQCiphertextSize} {
		blob := make([]byte, total)
		for i := range blob {
			blob[i] = byte(i)
		}
		chunks := chunkBlob(core.FramePQEK, blob, 64)
		if len(chunks) < 2 {
			t.Fatalf("size %d produced %d chunks", total, len(chunks))
		}
		rx := newBlobRx(total)
		var done bool
		for i, c := range chunks {
			var err error
			done, err = rx.accept(c.value)
			if err != nil {
				t.Fatalf("size %d chunk %d: %v", total, i, err)
			}
		}
		if !done || !bytes.Equal(rx.bytes(), blob) {
			t.Fatalf("size %d did not reassemble", total)
		}
	}
}
