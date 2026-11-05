// Bulk tun reader for the Android uplink burst drain.
//
// One JNI call drains up to maxPackets packets the kernel already holds,
// replacing one Os.read JVM transition per packet. At the 1373-byte inner MTU
// the uplink runs about 68,000 packets per second at 750 Mbps, and each
// Os.read paid a JNI transition plus libcore wrapper overhead on top of the
// syscall itself; this moves the loop into native code and keeps the syscall.
//
// Return conventions mirror WinnV3AndroidTunDevice.readNonBlocking so the
// caller keeps one contract:
//   >= 0  packets filled into the slab
//   -1    queue empty or interrupted before the first packet (retryable)
//   -2    end of stream
//   -3    a packet exceeded packetCapacity (slotBytes is packetCapacity + 1,
//         so a full-slot read proves oversize exactly as the Kotlin loop did)
//   -4    unrecoverable read error or invalid direct buffers
//
// EINTR and EAGAIN stop the drain so retirement can be observed, and
// returns the packets already staged, which is what lets one poll wake carry
// a whole burst.
#include <jni.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "winn_tun_write_run.h"

extern "C" JNIEXPORT jint JNICALL
Java_org_winsvpn_app_WinnV3TunBulkRead_readBatch(
    JNIEnv* env, jclass /*clazz*/, jint fd,
    jobject slabObj, jobject lengthsObj, jint maxPackets, jint slotBytes) {
    if (maxPackets <= 0 || slotBytes <= 1 || slabObj == nullptr ||
        lengthsObj == nullptr) return -4;
    const size_t slots = static_cast<size_t>(maxPackets);
    const size_t width = static_cast<size_t>(slotBytes);
    if (slots > SIZE_MAX / width || slots > SIZE_MAX / sizeof(int32_t)) return -4;
    // Both Kotlin arguments are ByteBuffers, so JNI capacities are bytes.
    const jlong slabCapacity = env->GetDirectBufferCapacity(slabObj);
    const jlong lengthsCapacity = env->GetDirectBufferCapacity(lengthsObj);
    if (slabCapacity < static_cast<jlong>(slots * width) ||
        lengthsCapacity < static_cast<jlong>(slots * sizeof(int32_t))) return -4;
    uint8_t* slab = static_cast<uint8_t*>(env->GetDirectBufferAddress(slabObj));
    uint8_t* lengths = static_cast<uint8_t*>(env->GetDirectBufferAddress(lengthsObj));
    if (slab == nullptr || lengths == nullptr) return -4;

    // Each checked slot includes the packetCapacity + 1 oversize sentinel.
    // Only successful packet lengths are published to the caller.
    int count = 0;
    for (int i = 0; i < maxPackets; i++) {
        for (;;) {
            uint8_t* slot = slab + static_cast<size_t>(i) * width;
            ssize_t n = read(fd, slot, width);
            if (n > 0) {
                if (n > slotBytes - 1) {
                    return -3;
                }
                const int32_t length = static_cast<int32_t>(n);
                // ByteBuffer slices need not provide int32_t alignment.
                memcpy(lengths + static_cast<size_t>(i) * sizeof(length),
                       &length, sizeof(length));
                count++;
                break;
            }
            if (n == 0) {
                return count > 0 ? count : -2;
            }
            if (errno == EINTR) return count > 0 ? count : -1;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return count > 0 ? count : -1;
            }
            return -4;
        }
    }
    return count;
}

// Bulk tun writer for the downlink: packets [start, end) of one
// WinnV3PacketBatch in one JNI call instead of one Os.write JVM transition per
// packet. The syscall per packet stays; what goes is the JNI entry, the
// libcore wrapper, the FileDescriptor field read and the two lifetime
// monitors that each Os.write paid. lanes > 1 spreads the run over native
// writer threads by inner flow (see winn_tun_write_run.h).
//
//   bytes    the batch's byte slab
//   offsets  payload offset of each packet, indexed by batch position
//   lengths  payload length of each packet, indexed by batch position
//   done     one flag per packet of the run, done[i] for packet start + i;
//            written packets are marked, and marked packets are skipped, so a
//            call after a full device resumes exactly where the run stopped
//
// Returns how many packets of the run are done (0 .. end - start), or -errno
// of a device fault. Fewer than end - start with no fault means the device
// was full or a write was interrupted: the caller waits for POLLOUT outside
// this call and calls again. Nothing in this call waits or retries.
// start == end returns 0, which is how Kotlin probes that the symbol exists.
//
// The run's bytes are copied out of the Java array before any write, so no
// Java array is pinned while the kernel runs the receive path and worker
// threads never touch the Java heap. The copy is one memcpy of the run's
// span, at most the 512 KiB batch slab.
namespace {
pthread_mutex_t gWriteMu = PTHREAD_MUTEX_INITIALIZER;
uint8_t* gWriteScratch = nullptr;
size_t gWriteScratchCap = 0;
}  // namespace

extern "C" JNIEXPORT jint JNICALL
Java_org_winsvpn_app_WinnV3TunBulkWrite_writeBatch(
    JNIEnv* env, jobject /*thiz*/, jint fd, jbyteArray bytes,
    jintArray offsets, jintArray lengths, jint start, jint end, jint lanes,
    jbyteArray done) {
    if (start < 0 || end < start) return -EINVAL;
    const jint count = end - start;
    if (count == 0) return 0;
    if (count > winn_tun::kMaxRunPackets || fd < 0 || bytes == nullptr ||
        offsets == nullptr || lengths == nullptr || done == nullptr) {
        return -EINVAL;
    }
    if (env->GetArrayLength(offsets) < end || env->GetArrayLength(lengths) < end ||
        env->GetArrayLength(done) < count) {
        return -EINVAL;
    }
    int32_t packetOffsets[winn_tun::kMaxRunPackets];
    int32_t packetLengths[winn_tun::kMaxRunPackets];
    uint8_t doneFlags[winn_tun::kMaxRunPackets];
    env->GetIntArrayRegion(offsets, start, count, reinterpret_cast<jint*>(packetOffsets));
    env->GetIntArrayRegion(lengths, start, count, reinterpret_cast<jint*>(packetLengths));
    env->GetByteArrayRegion(done, 0, count, reinterpret_cast<jbyte*>(doneFlags));
    if (env->ExceptionCheck()) return -EINVAL;
    const jsize byteLength = env->GetArrayLength(bytes);
    int32_t lo = byteLength;
    int32_t hi = 0;
    for (jint i = 0; i < count; i++) {
        const int32_t offset = packetOffsets[i];
        const int32_t length = packetLengths[i];
        if (offset < 0 || length <= 0 || offset > byteLength - length) return -EINVAL;
        if (offset < lo) lo = offset;
        if (offset + length > hi) hi = offset + length;
    }
    for (jint i = 0; i < count; i++) packetOffsets[i] -= lo;
    const size_t span = static_cast<size_t>(hi - lo);

    pthread_mutex_lock(&gWriteMu);
    if (span > gWriteScratchCap) {
        uint8_t* grown = static_cast<uint8_t*>(realloc(gWriteScratch, span));
        if (grown == nullptr) {
            pthread_mutex_unlock(&gWriteMu);
            return -ENOMEM;
        }
        gWriteScratch = grown;
        gWriteScratchCap = span;
    }
    env->GetByteArrayRegion(bytes, lo, static_cast<jsize>(span),
                            reinterpret_cast<jbyte*>(gWriteScratch));
    if (env->ExceptionCheck()) {
        pthread_mutex_unlock(&gWriteMu);
        return -EINVAL;
    }
    const winn_tun::Run run{fd, gWriteScratch, span, packetOffsets, packetLengths,
                            count, doneFlags, winn_tun::SystemWrite};
    const int32_t result = winn_tun::WriteRunLanes(run, lanes);
    pthread_mutex_unlock(&gWriteMu);
    env->SetByteArrayRegion(done, 0, count, reinterpret_cast<const jbyte*>(doneFlags));
    return result;
}
