package carrier

import "testing"

func TestResourcePipeSlabCapacity(t *testing.T) {
	for _, size := range []int{1, PipeBufferSlabBytes, PipeBufferSlabBytes + 1} {
		b := getPipeBuf(size)
		if len(*b) != size || cap(*b) != max(PipeBufferSlabBytes, size) {
			t.Fatal("reported slab differs from allocator")
		}
		recyclePipeBuf(b)
	}
}
