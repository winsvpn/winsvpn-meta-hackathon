package org.winsvpn.app

import java.nio.ByteBuffer

/**
 * Native bulk tun reader (libwinn_tun_bulk.so). One JNI call drains up to
 * [readBatch]'s maxPackets packets the kernel already holds, replacing one
 * Os.read JVM transition per packet at the uplink's ~68,000 packets per second.
 *
 * [available] is false when the library is absent, and every caller must fall
 * back to the per-packet Kotlin loop: test doubles, hosts without the staged
 * library, and variants without this jniLib stay correct and slower rather
 * than broken.
 *
 * Return conventions mirror WinnV3AndroidTunDevice.readNonBlocking so the
 * burst reader keeps one contract:
 *  - greater than or equal to 0: packets filled into the slab
 *  - -1: queue empty or drain interrupted before the first packet (retryable terminator)
 *  - -2: end of stream
 *  - -3: a packet exceeded the slot's packetCapacity
 *  - -4: unrecoverable read error (the caller raises IOException)
 */
internal object WinnV3TunBulkRead {
    const val KERNEL_EMPTY = -1
    const val END_OF_STREAM = -2
    const val OVERSIZE = -3
    const val READ_FAILED = -4

    val available: Boolean = try {
        Runtime.getRuntime().loadLibrary("winn_tun_bulk")
        true
    } catch (_: UnsatisfiedLinkError) {
        false
    } catch (_: SecurityException) {
        false
    }

    external fun readBatch(
        fd: Int,
        slab: ByteBuffer,
        lengths: ByteBuffer,
        maxPackets: Int,
        slotBytes: Int,
    ): Int
}
