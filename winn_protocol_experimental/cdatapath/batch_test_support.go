//go:build darwin && winn3_batch_test

package main

/*
#include <stdlib.h>
#include "winn_packet_batch.h"
extern int WinsWinn3EnqueuePackets(long long, void *, int, int);
extern int WinsWinn3DequeuePackets(long long, void *, int, int, int);
extern char *WinnTunnelClose(long long);
static int batch_enqueue(long long h, void *p, int n, int s) {
  return WinsWinn3EnqueuePackets(h, p, n, s);
}
static int batch_dequeue(long long h, void *p, int n, int s, int ms) {
  return WinsWinn3DequeuePackets(h, p, n, s, ms);
}
*/
import "C"

import "unsafe"

// Test-only helpers use C allocations and a real Go -> C -> exported Go call.
// No Go pointer is stored in descriptors or survives a foreign call.
type nativeBatch struct {
	raw         unsafe.Pointer
	packets     []C.WinsWinn3PacketDescriptor
	allocations []unsafe.Pointer
}

func newNativeBatch(count, capacity int) *nativeBatch {
	b := &nativeBatch{raw: C.calloc(C.size_t(count), C.size_t(C.WINS_WINN3_PACKET_STRIDE))}
	b.packets = unsafe.Slice((*C.WinsWinn3PacketDescriptor)(b.raw), count)
	for i := range b.packets {
		p := C.calloc(1, C.size_t(capacity))
		b.allocations = append(b.allocations, p)
		b.packets[i].data = p
		b.packets[i].capacity = C.uint32_t(capacity)
	}
	return b
}
func (b *nativeBatch) free() {
	for _, p := range b.allocations {
		C.free(p)
	}
	C.free(b.raw)
}
func (b *nativeBatch) bytes(i int) []byte {
	return unsafe.Slice((*byte)(b.allocations[i]), int(b.packets[i].capacity))
}
func (b *nativeBatch) setPacket(i int, packet []byte) {
	copy(b.bytes(i), packet)
	b.packets[i].length = C.uint32_t(len(packet))
	b.packets[i].family = C.uint32_t(batchPacketFamily(packet))
}
func (b *nativeBatch) enqueue(handle int64, count, stride int) int {
	return int(C.batch_enqueue(C.longlong(handle), b.raw, C.int(count), C.int(stride)))
}
func (b *nativeBatch) dequeue(handle int64, count, stride, timeout int) int {
	return int(C.batch_dequeue(C.longlong(handle), b.raw, C.int(count), C.int(stride), C.int(timeout)))
}
func nativeClose(handle int64) { WinnTunnelFreeString(C.WinnTunnelClose(C.longlong(handle))) }
