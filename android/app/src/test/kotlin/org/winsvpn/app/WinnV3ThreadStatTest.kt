package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Per-thread CPU time for the pump census: parsing, and absence never reading as zero. */
class WinnV3ThreadStatTest {

    @Test
    fun `utime and stime are counted from the last parenthesis`() {
        // A command name may hold spaces and parentheses; field 14 is utime
        // and field 15 stime counting the pid as field 1.
        val line = "4242 (Calc-WinnV3 (x) y) S 1 2 3 0 -1 4194624 10 0 0 0 1234 5678 0 0 10 -10 40 0 99\n"
        assertEquals(WinnV3ThreadTicks(user = 1234, kernel = 5678), WinnV3ThreadStat.parse(line))
    }

    @Test
    fun `a malformed line reads as absent`() {
        assertNull(WinnV3ThreadStat.parse(""))
        assertNull(WinnV3ThreadStat.parse("4242 (truncated"))
        assertNull(WinnV3ThreadStat.parse("4242 (short) S 1 2 3"))
        assertNull(WinnV3ThreadStat.parse("4242 (x) S 1 2 3 0 -1 0 0 0 0 0 nan 5 0"))
        assertNull(WinnV3ThreadStat.parse("4242 (x) S 1 2 3 0 -1 0 0 0 0 0 -3 5 0"))
    }

    @Test
    fun `an unknown thread or a host without procfs reads as absent`() {
        assertNull(WinnV3ThreadStat.cpuTicks(-1))
        assertNull(WinnV3ThreadStat.cpuTicks(0))
        val tid = WinnV3ThreadStat.currentThreadId()
        if (File("/proc/thread-self").exists()) {
            assertTrue("a Linux host resolves its own thread id", tid > 0)
            val ticks = WinnV3ThreadStat.cpuTicks(tid)
            assertTrue(ticks != null && ticks.user >= 0 && ticks.kernel >= 0)
        } else {
            assertEquals(-1, tid)
        }
    }

    @Test
    fun `the perf line carries thread ticks only when present`() {
        val census = WinnV3PumpCensus(
            downlinkPackets = 1, downlinkWrites = 1, downlinkWriteNanos = 1,
            downlinkWriteMaxNanos = 1, uplinkPackets = 0, uplinkWrites = 0,
            uplinkWriteNanos = 0, uplinkWriteMaxNanos = 0,
            downlinkThreadTicks = WinnV3ThreadTicks(user = 120, kernel = 830),
            readerThreadTicks = WinnV3ThreadTicks(user = 7, kernel = 9),
        )
        val line = WinnV3PerfLine.format(
            census, """{"rekey_init_resends":2}""", statusAgeMs = 0, monotonicNanos = 5,
        )
        assertEquals(
            "datapath perf mono_ns=5 status_age_ms=0 " +
                "dl_pkts=1 dl_writes=1 dl_write_ns=1 dl_write_max_ns=1 " +
                "ul_pkts=0 ul_writes=0 ul_write_ns=0 ul_write_max_ns=0 " +
                "dl_utime_ticks=120 dl_stime_ticks=830 rd_utime_ticks=7 rd_stime_ticks=9 " +
                "rekey_init_resends=2",
            line,
        )
    }
}
