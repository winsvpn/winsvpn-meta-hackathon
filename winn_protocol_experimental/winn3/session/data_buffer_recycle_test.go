package session

import (
	"bytes"
	"fmt"
	"testing"
)

func TestPacketBufferRecycleSessionOwnedStorage(t *testing.T) {
	var d Driver
	for _, size := range []int{32, dataBufSize, dataBufSize + 16} {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			storage := d.getDataBuf(size)
			for i := range storage {
				storage[i] = 0x5a
			}
			d.recycleDataBuf(storage)
			if !bytes.Equal(storage, make([]byte, len(storage))) {
				t.Fatal("recycled owned plaintext was not cleared")
			}
		})
	}
}
