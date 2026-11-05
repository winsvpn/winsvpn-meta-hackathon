//go:build darwin

package main

/*
#ifndef WINS_WINN3_PACKET_BATCH_H
#define WINS_WINN3_PACKET_BATCH_H
#include <stddef.h>
#include <stdint.h>

// Apple 64-bit ABI. All integers are in host byte order.
#define WINS_WINN3_BATCH_MAX 32
#define WINS_WINN3_PACKET_STRIDE 24
#define WINS_WINN3_PACKET_MAX 65535

typedef struct WinsWinn3PacketDescriptor {
  void *data;
  uint32_t length;
  uint32_t capacity;
  uint32_t family;
  uint32_t reserved;
} WinsWinn3PacketDescriptor;

#if defined(__cplusplus)
static_assert(sizeof(WinsWinn3PacketDescriptor) == 24, "packet descriptor stride");
static_assert(offsetof(WinsWinn3PacketDescriptor, length) == 8, "packet length offset");
#else
_Static_assert(sizeof(WinsWinn3PacketDescriptor) == 24, "packet descriptor stride");
_Static_assert(offsetof(WinsWinn3PacketDescriptor, length) == 8, "packet length offset");
#endif
#endif

#include <sys/socket.h>
*/
import "C"

import (
	"time"
	"unsafe"
)

const winn3BatchMax = 32

// A descriptor references caller memory only during the foreign call. The
// queues contain independent Go byte copies, never descriptors or C pointers.
func batchDescriptors(raw unsafe.Pointer, count, stride int, enqueue bool) ([]C.WinsWinn3PacketDescriptor, int) {
	if count < 0 || count > winn3BatchMax || stride != C.WINS_WINN3_PACKET_STRIDE {
		return nil, errArgument
	}
	if count == 0 {
		return nil, 0
	}
	if raw == nil || uintptr(raw)%unsafe.Alignof(C.WinsWinn3PacketDescriptor{}) != 0 {
		return nil, errArgument
	}
	start := uintptr(raw)
	end := start + uintptr(count*stride)
	if end < start {
		return nil, errArgument
	}
	desc := unsafe.Slice((*C.WinsWinn3PacketDescriptor)(raw), count)
	// Check the entire batch before any queue, counter, or caller output changes.
	for i := range desc {
		p := &desc[i]
		if p.data == nil || p.reserved != 0 || p.capacity == 0 || p.capacity > C.WINS_WINN3_PACKET_MAX {
			return nil, errArgument
		}
		lo := uintptr(p.data)
		hi := lo + uintptr(p.capacity)
		if hi < lo || (lo < end && start < hi) {
			return nil, errArgument
		}
		if enqueue {
			if p.length == 0 || p.length > p.capacity {
				return nil, errArgument
			}
			packet := unsafe.Slice((*byte)(p.data), int(p.length))
			if batchPacketFamily(packet) != uint32(p.family) || p.family == 0 {
				return nil, errArgument
			}
		} else {
			if p.length != 0 || p.family != 0 {
				return nil, errArgument
			}
			for j := 0; j < i; j++ {
				other := uintptr(desc[j].data)
				if lo < other+uintptr(desc[j].capacity) && other < hi {
					return nil, errArgument
				}
			}
		}
	}
	return desc, 0
}

// IP policy remains in tun. This boundary checks only the minimum header and
// the family/version agreement needed to interpret NEPacketTunnelFlow arrays.
func batchPacketFamily(packet []byte) uint32 {
	if len(packet) >= 20 && packet[0]>>4 == 4 {
		return uint32(C.AF_INET)
	}
	if len(packet) >= 40 && packet[0]>>4 == 6 {
		return uint32(C.AF_INET6)
	}
	return 0
}

// WinsWinn3EnqueuePackets accepts a validated batch atomically relative to
// close and other queue operations. The existing drop-oldest queue policy is
// preserved: a full queue still accepts every new packet and counts eviction.
//
//export WinsWinn3EnqueuePackets
func WinsWinn3EnqueuePackets(handle C.longlong, descriptors unsafe.Pointer, count C.int, stride C.int) C.int {
	desc, code := batchDescriptors(descriptors, int(count), int(stride), true)
	if code != 0 {
		return C.int(code)
	}
	t := lookupWinn3(int64(handle))
	if t == nil {
		return errHandle
	}
	_, d, _ := t.round()
	d.mu.Lock()
	defer d.mu.Unlock()
	if t.closed.Load() || d.closed {
		if d.closed && t.recoveryAbsorbs(d) {
			// A retired round's device during recovery: dropped and counted,
			// never reported as a closed tunnel. See winn3WriteInbound.
			t.droppedRecovering.Add(uint64(len(desc)))
			return count
		}
		return errClosed
	}
	for _, p := range desc {
		packet := unsafe.Slice((*byte)(p.data), int(p.length))
		cp := append([]byte(nil), packet...)
		if len(d.outbound) >= d.depth {
			d.outbound[0] = nil
			d.outbound = d.outbound[1:]
			d.droppedOutbound.Add(1)
		}
		d.outbound = append(d.outbound, cp)
	}
	if len(desc) > 0 {
		d.notEmpty.Broadcast()
	}
	return count
}

// WinsWinn3DequeuePackets waits only for the first packet and then copies the
// available prefix. A short destination leaves that packet queued. A positive
// prefix wins over a later error; all suffix descriptors and bytes stay intact.
//
//export WinsWinn3DequeuePackets
func WinsWinn3DequeuePackets(handle C.longlong, descriptors unsafe.Pointer, count C.int, stride C.int, timeoutMS C.int) C.int {
	desc, code := batchDescriptors(descriptors, int(count), int(stride), false)
	if code != 0 {
		return C.int(code)
	}
	t := lookupWinn3(int64(handle))
	if t == nil {
		return errHandle
	}
	deadline := time.Time{}
	if timeoutMS > 0 {
		deadline = time.Now().Add(time.Duration(timeoutMS) * time.Millisecond)
	}
	for {
		_, d, next := t.round()
		n := dequeueWinn3(t, d, desc, deadline)
		// A retired round's device during recovery: wait for the successor
		// inside the same timeout rather than report the tunnel closed.
		if n != errClosed || !d.isClosed() || !t.recoveryAbsorbs(d) {
			return n
		}
		if !awaitRound(next, deadline) {
			return errTimeout
		}
	}
}

// dequeueWinn3 is WinsWinn3DequeuePackets against one round's device.
func dequeueWinn3(t *winn3Tunnel, d *abiDevice, desc []C.WinsWinn3PacketDescriptor, deadline time.Time) C.int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if t.closed.Load() || d.closed {
		return errClosed
	}
	if len(desc) == 0 {
		return 0
	}
	for len(d.inbound) == 0 && !d.closed && !t.closed.Load() {
		if deadline.IsZero() {
			d.notEmpty.Wait()
			continue
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errTimeout
		}
		// Locking in the callback prevents a timeout wakeup from being lost
		// between scheduling the timer and entering Cond.Wait.
		timer := time.AfterFunc(remaining, func() {
			d.mu.Lock()
			d.notEmpty.Broadcast()
			d.mu.Unlock()
		})
		d.notEmpty.Wait()
		timer.Stop()
	}
	if t.closed.Load() || d.closed {
		return errClosed
	}
	n := 0
	for n < len(desc) && len(d.inbound) > 0 {
		packet := d.inbound[0]
		family := batchPacketFamily(packet)
		if family == 0 {
			if n == 0 {
				return errArgument
			}
			break
		}
		if len(packet) > int(desc[n].capacity) {
			if n == 0 {
				return errTooLarge
			}
			break
		}
		copy(unsafe.Slice((*byte)(desc[n].data), int(desc[n].capacity)), packet)
		desc[n].length = C.uint32_t(len(packet))
		desc[n].family = C.uint32_t(family)
		d.inbound[0] = nil
		d.inbound = d.inbound[1:]
		n++
	}
	if n > 0 {
		d.notFull.Broadcast()
	}
	return C.int(n)
}
