package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Round A3, lane L6: the promotion gate and the status parser against the
 * lifecycle a supervised Winn v3 engine publishes (Round A2).
 *
 * Every test here uses only the parser and the gate, so the file compiles
 * against the host as it was before the lifecycle was read, and runs RED there.
 * The documents are the frame mode's own shapes (`winn3_status.go`): a proven
 * round's counters beside a lifecycle that is not `connected` must never be
 * called proven, because the lifecycle can only subtract.
 */
class WinnV3LifecycleGateTest {

    private fun proven(lifecycle: String?): String {
        val tail = if (lifecycle == null) "" else ""","lifecycle":"$lifecycle""""
        return """{"event":"posture","posture":"promoted","promotion_ready":true,""" +
            """"gate_state":"carrying","rx_packets":9,"rx_offered":9$tail}"""
    }

    @Test
    fun `a proven round with lifecycle connected is proven`() {
        assertTrue(WinnV3PromotionGate.isProven(WinnV3EngineStatus.parse(proven("connected"))))
    }

    @Test
    fun `a document with no lifecycle keeps the two-clause rule`() {
        assertTrue(WinnV3PromotionGate.isProven(WinnV3EngineStatus.parse(proven(null))))
    }

    @Test
    fun `no lifecycle but connected is ever proven, whatever the counters say`() {
        for (state in listOf("recovering", "blocked", "stopped", "connecting", "a-state-nobody-defined")) {
            assertFalse(
                "lifecycle $state beside a carrying gate and delivered packets must not be proven",
                WinnV3PromotionGate.isProven(WinnV3EngineStatus.parse(proven(state))),
            )
        }
    }

    @Test
    fun `the recovering document the frame mode publishes is refused with its reason`() {
        // winn3_frame.go statusJSON while recovering: no round is described,
        // so the gate reads closed and nothing is delivered; posture is hold.
        val status = WinnV3EngineStatus.parse(
            """{"event":"posture","posture":"hold","promotion_ready":false,""" +
                """"gate_state":"closed","rx_packets":0,"rx_offered":0,"lifecycle":"recovering"}""",
        )
        assertFalse(WinnV3PromotionGate.isProven(status))
        assertEquals(
            "gate is closed, not carrying",
            WinnV3PromotionGate.whyNotProven(status),
        )
    }

    @Test
    fun `a duplicated lifecycle is refused rather than guessed`() {
        try {
            WinnV3EngineStatus.parse(
                """{"gate_state":"carrying","rx_packets":1,""" +
                    """"lifecycle":"connected","lifecycle":"recovering"}""",
            )
            fail("a document naming its lifecycle twice must be refused")
        } catch (_: WinnV3StartRefusal) {
        }
    }

    @Test
    fun `a lifecycle that is not a JSON string is refused`() {
        for (value in listOf("1", "true", "null", "{}")) {
            try {
                WinnV3EngineStatus.parse(
                    """{"gate_state":"carrying","rx_packets":1,"lifecycle":$value}""",
                )
                fail("lifecycle:$value must be refused")
            } catch (_: WinnV3StartRefusal) {
            }
        }
    }
}
