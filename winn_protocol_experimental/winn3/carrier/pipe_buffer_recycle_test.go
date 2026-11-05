package carrier

import (
	"bytes"
	"fmt"
	"testing"
)

func TestPacketBufferRecyclePipeOwnedStorage(t *testing.T) {
	for _, size := range []int{32, 2048, 2064} {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			bp := getPipeBuf(size)
			storage := (*bp)[:cap(*bp)]
			for i := range storage {
				storage[i] = 0x5a
			}
			recyclePipeBuf(bp)
			if !bytes.Equal(storage, make([]byte, len(storage))) {
				t.Fatal("recycled owned storage was not cleared")
			}
			next := getPipeBuf(32)
			defer recyclePipeBuf(next)
			if cap(*next) != 2048 {
				t.Fatalf("small-slab pool supplied capacity %d, want 2048", cap(*next))
			}
		})
	}
}

func TestPacketBufferRecyclePipeUnpooledSmallStorage(t *testing.T) {
	storage := bytes.Repeat([]byte{0x5a}, 32)
	recyclePipeBuf(&storage)
	if !bytes.Equal(storage, make([]byte, len(storage))) {
		t.Fatal("unpooled owned storage was not cleared")
	}
}
