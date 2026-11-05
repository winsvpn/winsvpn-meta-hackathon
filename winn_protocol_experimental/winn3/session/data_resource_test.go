package session

import "testing"

func TestResourceSendSlabCapacity(t *testing.T) {
	var d Driver
	for _, size := range []int{1, DataBufferSlabBytes, DataBufferSlabBytes + 1} {
		b := d.getDataBuf(size)
		if len(b) != size || cap(b) != max(DataBufferSlabBytes, size) {
			t.Fatal("reported slab differs from allocator")
		}
		d.recycleDataBuf(b)
	}
}
