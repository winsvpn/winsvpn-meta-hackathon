package org.winsvpn.app

import java.io.IOException

/**
 * Native bulk tun writer (libwinn_tun_bulk.so, the library [WinnV3TunBulkRead]
 * loads). One JNI call writes a run of downlink packets from one
 * [WinnV3PacketBatch], one write(2) each, replacing one Os.write JVM
 * transition per packet on the outbound pump.
 *
 * [available] is false when the library is absent or predates this symbol;
 * the seam then keeps the per-packet Kotlin path, exactly as it does today.
 *
 * RUNTIME SWITCH. The writer is used only when it is also switched on for the
 * device ([WinnV3AndroidTunDevice.establish]'s nativeBatchWrite), which the
 * service sets in debug builds when [SWITCH_FILE] exists in the app's files
 * directory. Off by default and always off in release builds, so one debug
 * APK measures both arms: create the file and reconnect for the native arm,
 * delete it and reconnect for the Kotlin arm.
 *
 * Return conventions of [writeBatch]:
 *  - 0 .. end - start: how many packets of the run are done. Fewer than the
 *    run means the device is full (EAGAIN) or a signal interrupted a write
 *    (EINTR): wait for POLLOUT and call again with the same [writeBatch] done
 *    flags, which skip what already went out
 *  - less than 0: -errno of a device fault
 * The native call does finite work only: it never retries, polls or sleeps,
 * so the caller holds the tun I/O lease for the call alone and waits with the
 * lease dropped.
 */
internal object WinnV3TunBulkWrite {
    /**
     * Writer lanes. 1 writes every run in order on the outbound pump thread
     * (arm A). More than 1 splits a run of at least 24 packets by inner flow
     * across native writer threads, so the kernel receive work a tun write
     * carries runs on several cores; per-flow order holds (arm B is 4). The
     * value moves only on an S26 A/B that shows the pump thread saturated in
     * kernel time and no rise in loaded p50, p99 or jitter.
     */
    const val LANES = 1

    /**
     * One JNI call writes at most this many packets. It bounds the work done
     * under one lifetime lease and how many packets can still reach a device
     * that a rebind has just retired: the seam re-checks the live device
     * between runs, as the per-packet loop re-checked it between packets. 32
     * at one lane; lanes need longer runs to be worth a worker wake.
     */
    val MAX_PACKETS_PER_CALL: Int = if (LANES > 1) 128 else 32

    /** The debug-build switch file, relative to Context.getFilesDir(). */
    const val SWITCH_FILE = "winn3_native_tun_write"

    val available: Boolean = try {
        Runtime.getRuntime().loadLibrary("winn_tun_bulk")
        writeBatch(-1, ByteArray(0), IntArray(0), IntArray(0), 0, 0, 1, ByteArray(0)) == 0
    } catch (_: UnsatisfiedLinkError) {
        false
    } catch (_: SecurityException) {
        false
    }

    /**
     * Calls [attempt] until all [count] packets of a run are done. Between
     * calls that stopped on a full device it runs [awaitWritable], which on
     * the real device is the lifetime-checked POLLOUT wait, so a retired
     * device ends the loop with that wait's IOException. A negative result is
     * a device fault, thrown as [fault] builds it; a result above [count] is
     * a broken writer and is thrown too, never retried.
     */
    inline fun drive(
        count: Int,
        attempt: () -> Int,
        awaitWritable: () -> Unit,
        fault: (Int) -> IOException,
    ) {
        while (true) {
            val done = attempt()
            when {
                done == count -> return
                done in 0 until count -> awaitWritable()
                done < 0 -> throw fault(-done)
                else -> throw IOException("Winn tun bulk write reported $done of $count packets")
            }
        }
    }

    external fun writeBatch(
        fd: Int,
        bytes: ByteArray,
        offsets: IntArray,
        lengths: IntArray,
        start: Int,
        end: Int,
        lanes: Int,
        done: ByteArray,
    ): Int
}
