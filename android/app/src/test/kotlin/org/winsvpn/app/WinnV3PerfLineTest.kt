package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

/** The debug perf line copies listed integer counters only, in a fixed order. */
class WinnV3PerfLineTest {

    @Test
    fun `the perf line carries counts only, in a fixed order`() {
        val census = WinnV3PumpCensus(
            downlinkPackets = 10, downlinkWrites = 2, downlinkWriteNanos = 3000,
            downlinkWriteMaxNanos = 2000, uplinkPackets = 4, uplinkWrites = 1,
            uplinkWriteNanos = 500, uplinkWriteMaxNanos = 500,
            nativeWritePackets = 6, seamDrops = 1,
        )
        val status = """{"event":"posture","session_id":"abc","refusal":"203.0.113.9 refused",""" +
            """"host_queue_high_water":77,"rx_packets":5,"plan":["udp"],"unknown_key":9,""" +
            """"dropped_to_host":3}"""
        val line = WinnV3PerfLine.format(census, status, statusAgeMs = 12, monotonicNanos = 987654321)
        assertEquals(
            "datapath perf mono_ns=987654321 status_age_ms=12 " +
                "dl_pkts=10 dl_writes=2 dl_write_ns=3000 dl_write_max_ns=2000 dl_native_pkts=6 " +
                "ul_pkts=4 ul_writes=1 ul_write_ns=500 ul_write_max_ns=500 ul_seam_drops=1 " +
                "rx_packets=5 host_queue_high_water=77 dropped_to_host=3",
            line,
        )
        assertFalse("free text from the engine never reaches the line", line.contains("refused"))
        assertFalse(line.contains("abc"))
        assertNull(Regex("unknown_key").find(line))
    }

    @Test
    fun `the receive order and send queue counters ride the line after the census keys`() {
        val census = WinnV3PumpCensus(
            downlinkPackets = 1, downlinkWrites = 1, downlinkWriteNanos = 1,
            downlinkWriteMaxNanos = 1, uplinkPackets = 0, uplinkWrites = 0,
            uplinkWriteNanos = 0, uplinkWriteMaxNanos = 0,
        )
        val status = """{"send_queue_depth":41,"outer_lost":9,"unopenable":2,""" +
            """"outer_reordered":17,"send_queue_high_water":3153}"""
        val line = WinnV3PerfLine.format(census, status, statusAgeMs = 0, monotonicNanos = 7)
        assertEquals(
            "datapath perf mono_ns=7 status_age_ms=0 " +
                "dl_pkts=1 dl_writes=1 dl_write_ns=1 dl_write_max_ns=1 " +
                "ul_pkts=0 ul_writes=0 ul_write_ns=0 ul_write_max_ns=0 " +
                "send_queue_high_water=3153 unopenable=2 outer_reordered=17 outer_lost=9 send_queue_depth=41",
            line,
        )
    }

    @Test
    fun `a missing status and an uncounted seam are marked, not reported as zero`() {
        val census = WinnV3PumpCensus(
            downlinkPackets = 0, downlinkWrites = 0, downlinkWriteNanos = 0,
            downlinkWriteMaxNanos = 0, uplinkPackets = 0, uplinkWrites = 0,
            uplinkWriteNanos = 0, uplinkWriteMaxNanos = 0,
        )
        val line = WinnV3PerfLine.format(census, "", statusAgeMs = -5, monotonicNanos = 1)
        assertEquals(
            "datapath perf mono_ns=1 status_age_ms=-1 " +
                "dl_pkts=0 dl_writes=0 dl_write_ns=0 dl_write_max_ns=0 " +
                "ul_pkts=0 ul_writes=0 ul_write_ns=0 ul_write_max_ns=0",
            line,
        )
    }
}
