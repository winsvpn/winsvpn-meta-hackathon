package org.winsvpn.app

import java.io.File

/** User and kernel CPU time of one thread, in clock ticks (USER_HZ). */
internal data class WinnV3ThreadTicks(val user: Long, val kernel: Long)

/**
 * Per-thread CPU time of this process's own threads, read from procfs.
 *
 * The phone's pump threads have never been profiled. Two numbers per thread
 * answer the question the tun-writer arms turn on: is the downlink pump busy,
 * and is it busy in the kernel (the tun write runs the inner IP and TCP
 * receive path on the writing thread) or in user space (JNI, copies, Kotlin)?
 * Read at the health watchdog's 10 s cadence, never on the packet path.
 *
 * Telemetry only. Every failure reads as absent, never as zero, so a host
 * without procfs (a plain-JVM unit test) or a thread that has not started
 * cannot be mistaken for an idle one.
 */
internal object WinnV3ThreadStat {
    /** The calling thread's kernel thread id, or -1 where procfs is absent. */
    fun currentThreadId(): Int = try {
        // /proc/thread-self links to /proc/<pid>/task/<tid> (Linux 3.17+).
        File("/proc/thread-self").canonicalFile.name.toInt()
    } catch (_: Exception) {
        -1
    }

    /** CPU ticks of thread [tid] of this process, or null. */
    fun cpuTicks(tid: Int): WinnV3ThreadTicks? {
        if (tid <= 0) return null
        val line = try {
            File("/proc/self/task/$tid/stat").readText()
        } catch (_: Exception) {
            return null
        }
        return parse(line)
    }

    /**
     * Parses one /proc/.../stat line. The command name sits in parentheses
     * and may itself hold spaces and parentheses, so fields are counted from
     * the LAST ')': state is field 3, utime field 14 and stime field 15.
     */
    fun parse(stat: String): WinnV3ThreadTicks? {
        val close = stat.lastIndexOf(')')
        if (close < 0 || close + 2 > stat.length) return null
        val fields = stat.substring(close + 2).trim().split(' ')
        if (fields.size < 13) return null
        val user = fields[11].toLongOrNull() ?: return null
        val kernel = fields[12].toLongOrNull() ?: return null
        if (user < 0 || kernel < 0) return null
        return WinnV3ThreadTicks(user, kernel)
    }
}
