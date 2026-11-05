package org.winsvpn.app

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The promotion gate and the staged start.
 *
 * The gate is two clauses ANDed, and the tests below take each clause away in
 * turn — that is the mutation guard, by hand: an implementation that dropped
 * either condition, or that read `rx_offered` where it should read
 * `rx_packets`, goes red here.
 */
class WinnV3StagedStartTest {

    @Test
    fun engineRefusalIsTerminalInsteadOfTimingOutAsConnectivity() {
        val status = WinnV3EngineStatus.parse(
            """{"gate_state":"closed","rx_packets":0,"rx_offered":0,"refusal":"admission rejected"}"""
        )
        assertEquals("admission rejected", status.refusal)
    }

    private val gateway = WinnV3Route("203.0.113.9", 32)

    private fun bootstrap(mtu: Int = 1443) =
        WinnV3Posture.bootstrap("10.8.1.3", mtu, "10.8.1.1", gateway)

    private fun promoted(mtu: Int = 1443) = WinnV3Posture.promotion(
        innerAddress = "10.8.1.3",
        innerMtu = mtu,
        routes = listOf(WinnV3Route("0.0.0.0", 0)),
        dnsServers = listOf("10.8.1.53"),
        innerNextHop = "10.8.1.1",
        outerTransportExclusion = gateway,
        ipv6SinkAddress = "fd00:d951:0001::1",
    )

    // --- the gate ---------------------------------------------------------------

    @Test
    fun `proven requires BOTH carrying and a delivered packet`() {
        assertTrue(WinnV3PromotionGate.isProven(status("carrying", rxPackets = 1)))
        // Carrying, nothing delivered.
        assertFalse(WinnV3PromotionGate.isProven(status("carrying", rxPackets = 0)))
        // A packet delivered while not carrying cannot happen, but the gate must
        // not be the thing that assumes it.
        assertFalse(WinnV3PromotionGate.isProven(status("rekeying", rxPackets = 9)))
        assertFalse(WinnV3PromotionGate.isProven(status("handshaking", rxPackets = 9)))
        assertFalse(WinnV3PromotionGate.isProven(status("down", rxPackets = 9)))
        assertFalse(WinnV3PromotionGate.isProven(status("closed", rxPackets = 9)))
        assertFalse(WinnV3PromotionGate.isProven(status("epoch0", rxPackets = 9)))
    }

    @Test
    fun `RxOffered is never a substitute for RxPackets`() {
        // Ten packets ARRIVED and none was DELIVERED — every one rejected by the
        // inner-IP validator. This must not promote.
        val s = WinnV3EngineStatus(WinnV3GateState.CARRYING, rxPackets = 0, rxOffered = 10)
        assertFalse(WinnV3PromotionGate.isProven(s))
        assertTrue(WinnV3PromotionGate.whyNotProven(s)!!.contains("arrivals"))
    }

    @Test
    fun `an unknown gate state is not carrying`() {
        assertNull(WinnV3GateState.fromWire("established"))
        assertNull(WinnV3GateState.fromWire(null))
        assertFalse(WinnV3PromotionGate.isProven(status("something-new", rxPackets = 5)))
    }

    @Test
    fun `exactly one gate state may carry`() {
        val carrying = WinnV3GateState.entries.filter { it.mayCarry() }
        assertEquals(listOf(WinnV3GateState.CARRYING), carrying)
    }

    @Test
    fun `whyNotProven separates a dead gateway from an incomplete handshake`() {
        assertTrue(WinnV3PromotionGate.whyNotProven(status("handshaking", 0))!!.contains("not carrying"))
        assertTrue(WinnV3PromotionGate.whyNotProven(status("carrying", 0))!!.contains("RxPackets"))
        assertNull(WinnV3PromotionGate.whyNotProven(status("carrying", 1)))
    }

    // --- status parsing ----------------------------------------------------------

    @Test
    fun `parse reads the three fields the gate needs`() {
        val s = WinnV3EngineStatus.parse(
            """{"gate_state":"carrying","rx_offered":12,"rx_packets":11,"tx_packets":40}"""
        )
        assertEquals(WinnV3GateState.CARRYING, s.gateState)
        assertEquals(11L, s.rxPackets)
        assertEquals(12L, s.rxOffered)
    }

    @Test
    fun `parse refuses a document that reports arrivals without deliveries`() {
        val e = try {
            WinnV3EngineStatus.parse("""{"gate_state":"carrying","rx_offered":12}""")
            throw AssertionError("expected a refusal")
        } catch (e: WinnV3StartRefusal) {
            e
        }
        assertTrue(e.message!!.contains("rx_packets"))
        assertTrue(e.message!!.contains("ARRIVALS"))
    }

    @Test
    fun `parse tolerates a document with neither counter and reports zero`() {
        val s = WinnV3EngineStatus.parse("""{"gate_state":"handshaking"}""")
        assertEquals(0L, s.rxPackets)
        assertEquals(0L, s.rxOffered)
        assertFalse(WinnV3PromotionGate.isProven(s))
    }

    @Test
    fun `parse survives whitespace and a missing gate state`() {
        val s = WinnV3EngineStatus.parse("""{ "rx_packets" :  7 , "rx_offered" : 7 }""")
        assertEquals(7L, s.rxPackets)
        assertNull(s.gateState)
        assertFalse(WinnV3PromotionGate.isProven(s))
    }

    @Test
    fun `parse adversarial table refuses nested keys and other hostile shapes`() {
        data class Row(
            val name: String,
            val input: String,
            val wantThrow: Boolean = false,
            val wantProven: Boolean = false,
            val wantGate: WinnV3GateState? = null,
            val wantRx: Long = 0L,
        )
        val honest =
            """{"gate_state":"carrying","rx_packets":11,"rx_offered":12}"""
        val rows = listOf(
            Row("honest carrying document", honest, wantProven = true,
                wantGate = WinnV3GateState.CARRYING, wantRx = 11L),
            Row("honest handshaking document",
                """{"gate_state":"handshaking","rx_packets":0,"rx_offered":0}""",
                wantGate = WinnV3GateState.HANDSHAKING),
            Row(
                "nested keys are not top-level",
                """{"extra":{"gate_state":"carrying","rx_packets":1,"rx_offered":1}}""",
            ),
            Row(
                "nested ready beside top-level zeros stays unproven",
                """{"gate_state":"handshaking","rx_packets":0,"extra":{"gate_state":"carrying","rx_packets":9}}""",
                wantGate = WinnV3GateState.HANDSHAKING,
            ),
            Row(
                "garbage with key-shaped text is not a JSON object",
                """gate_state":"carrying","rx_packets":1""",
                wantThrow = true,
            ),
            Row(
                "event value that spells gate_state is not the key",
                """{"event":"gate_state","gate_state":"handshaking","rx_packets":0}""",
                wantGate = WinnV3GateState.HANDSHAKING,
            ),
            Row(
                "rx_packets scientific notation is not an integer",
                """{"gate_state":"carrying","rx_packets":1e2}""",
                wantThrow = true,
            ),
            Row(
                "rx_packets fractional is not an integer",
                """{"gate_state":"carrying","rx_packets":1.5}""",
                wantThrow = true,
            ),
            Row(
                "rx_packets negative is not a delivery count",
                """{"gate_state":"carrying","rx_packets":-1}""",
                wantThrow = true,
            ),
            Row(
                "duplicate rx_packets is untrustworthy",
                """{"gate_state":"carrying","rx_packets":0,"rx_packets":1}""",
                wantThrow = true,
            ),
            Row(
                "document larger than MAX_STATUS_BYTES",
                "x".repeat(WinnV3EngineStatus.MAX_STATUS_BYTES + 1),
                wantThrow = true,
            ),
            Row(
                "empty document is not proven and does not throw",
                "",
            ),
            Row(
                "whitespace only is not proven and does not throw",
                "  \n\t",
            ),
            Row(
                "honest carrying with trailing newline still proven",
                honest + "\n",
                wantProven = true,
                wantGate = WinnV3GateState.CARRYING,
                wantRx = 11L,
            ),
            Row(
                "concatenated second object that would prove is untrustworthy",
                """{"event":"posture"}{"gate_state":"carrying","rx_packets":1}""",
                wantThrow = true,
            ),
            Row(
                "leading non-object then a proven object is untrustworthy",
                """true{"gate_state":"carrying","rx_packets":1}""",
                wantThrow = true,
            ),
            Row(
                "trailing garbage after a proven object is an under-read",
                honest + " true",
                wantThrow = true,
            ),
            Row(
                "JSON array is not a status object",
                """[{"gate_state":"carrying","rx_packets":1}]""",
                wantThrow = true,
            ),
            Row(
                "gate_state as a number is not a state name",
                """{"gate_state":1,"rx_packets":1}""",
                wantThrow = true,
            ),
            Row(
                "rx_packets leading zeros are not an integer",
                """{"gate_state":"carrying","rx_packets":01}""",
                wantThrow = true,
            ),
            Row(
                "rx_packets zero is a legal parse and is not proven",
                """{"gate_state":"carrying","rx_packets":0}""",
                wantGate = WinnV3GateState.CARRYING,
            ),
            Row(
                "UTF-8 BOM is not a JSON object",
                "\uFEFF" + honest,
                wantThrow = true,
            ),
            Row(
                "duplicate gate_state is untrustworthy",
                """{"gate_state":"handshaking","gate_state":"carrying","rx_packets":1}""",
                wantThrow = true,
            ),
            Row(
                "trailing comma is not a single JSON object",
                """{"gate_state":"carrying","rx_packets":11,}""",
                wantThrow = true,
            ),
            Row(
                "JSON \\r in gate_state is a CR, not the letter r",
                """{"gate_state":"ca\rrying","rx_packets":1}""",
                wantRx = 1L,
            ),
            Row(
                "unknown JSON escape is not a string",
                """{"gate_state":"\carrying","rx_packets":1}""",
                wantThrow = true,
            ),
            Row(
                "padded carrying is not the wire name",
                """{"gate_state":" carrying","rx_packets":1}""",
                wantRx = 1L,
            ),
            Row(
                "uppercase CARRYING is not the wire name",
                """{"gate_state":"CARRYING","rx_packets":1}""",
                wantRx = 1L,
            ),
            Row(
                "JSON unicode c is the carrying gate",
                "{\"gate_state\":\"\\u0063arrying\",\"rx_packets\":1}",
                wantProven = true,
                wantGate = WinnV3GateState.CARRYING,
                wantRx = 1L,
            ),
            Row(
                "duplicate event is untrustworthy",
                """{"event":"posture","event":"carrying","gate_state":"handshaking","rx_packets":0}""",
                wantThrow = true,
            ),
        )
        for (row in rows) {
            try {
                val got = WinnV3EngineStatus.parse(row.input)
                if (row.wantThrow) {
                    throw AssertionError("${row.name}: hostile input was accepted: $got")
                }
                assertEquals(row.name, row.wantGate, got.gateState)
                assertEquals(row.name, row.wantRx, got.rxPackets)
                assertEquals(row.name, row.wantProven, WinnV3PromotionGate.isProven(got))
            } catch (e: WinnV3StartRefusal) {
                if (!row.wantThrow) {
                    throw AssertionError("${row.name}: accepted row refused: ${e.message}")
                }
            }
        }
    }

    // --- the staged start --------------------------------------------------------

    @Test
    fun `a start that sees a delivered packet promotes exactly once`() {
        val installed = mutableListOf<WinnV3Stage>()
        var polls = 0
        val outcome = start(
            install = { installed += it.stage },
            readStatus = {
                polls++
                if (polls < 3) statusJson("carrying", 0) else statusJson("carrying", 1)
            },
        ).start()

        assertTrue(outcome is WinnV3StagedStart.Outcome.Promoted)
        assertEquals(listOf(WinnV3Stage.BOOTSTRAP, WinnV3Stage.PROMOTED), installed)
        assertEquals(1L, (outcome as WinnV3StagedStart.Outcome.Promoted).rxPacketsAtPromotion)
    }

    @Test
    fun `a start that never sees a delivered packet refuses and tears down`() {
        val installed = mutableListOf<WinnV3Stage>()
        var toreDown = false
        val outcome = start(
            install = { installed += it.stage },
            readStatus = { statusJson("carrying", 0) },
            tearDown = { toreDown = true },
        ).start()

        // §4.3 rule 2: the host is put back and the promotion never happens.
        assertTrue(outcome is WinnV3StagedStart.Outcome.RefusedNotProven)
        assertEquals(listOf(WinnV3Stage.BOOTSTRAP), installed)
        assertTrue(toreDown)
        assertTrue((outcome as WinnV3StagedStart.Outcome.RefusedNotProven).reason.contains("RxPackets"))
    }

    @Test
    fun `a handshake that never completes refuses rather than widening`() {
        val installed = mutableListOf<WinnV3Stage>()
        val outcome = start(
            install = { installed += it.stage },
            readStatus = { statusJson("handshaking", 0) },
        ).start()
        assertTrue(outcome is WinnV3StagedStart.Outcome.RefusedNotProven)
        assertFalse(installed.contains(WinnV3Stage.PROMOTED))
    }

    @Test
    fun `an untrustworthy status tears down instead of waiting`() {
        var toreDown = false
        val started = start(
            readStatus = { """{"gate_state":"carrying","rx_offered":5}""" },
            tearDown = { toreDown = true },
        )
        try {
            started.start()
            throw AssertionError("expected a refusal")
        } catch (e: WinnV3StartRefusal) {
            assertTrue(e.message!!.contains("rx_packets"))
        }
        assertTrue(toreDown)
    }

    @Test
    fun `an explicit engine refusal tears down immediately`() {
        var toreDown = false
        val started = start(
            readStatus = {
                """{"gate_state":"closed","rx_packets":0,"rx_offered":0,"refusal":"admission rejected"}"""
            },
            tearDown = { toreDown = true },
        )
        try {
            started.start()
            throw AssertionError("expected the engine refusal to propagate")
        } catch (e: WinnV3StartRefusal) {
            assertTrue(e.message!!.contains("admission rejected"))
        }
        assertTrue(toreDown)
    }

    @Test
    fun `a bootstrap that cannot be installed is never followed by a promotion`() {
        val installed = mutableListOf<WinnV3Stage>()
        val started = start(
            install = {
                installed += it.stage
                if (it.stage == WinnV3Stage.BOOTSTRAP) {
                    throw WinnV3PostureRefusal("the platform rejected the narrow bootstrap")
                }
            },
        )
        try {
            started.start()
            throw AssertionError("expected the refusal to propagate")
        } catch (e: WinnV3PostureRefusal) {
            assertTrue(e.message!!.contains("narrow bootstrap"))
        }
        // §4.3 rule 1: never fall back to installing the full tunnel.
        assertEquals(listOf(WinnV3Stage.BOOTSTRAP), installed)
    }

    @Test
    fun `the two postures must be the two postures`() {
        val e = try {
            WinnV3StagedStart(
                bootstrap = promoted(), promoted = promoted(), proofDeadlineMs = 1,
                pollIntervalMs = 1, install = {}, readStatus = { "" }, tearDown = {},
                nowMs = { 0 }, sleepMs = {},
            )
            throw AssertionError("expected a refusal")
        } catch (e: WinnV3StartRefusal) {
            e
        }
        assertTrue(e.message!!.contains("not BOOTSTRAP"))
    }

    @Test
    fun `a promotion that changes the interface MTU is refused at construction`() {
        // bootstrap 1443 vs promoted 1359: two DIFFERENT, both-legal MTUs (>= RFC
        // 8200's 1280 floor). Not 1203 any more — since 2026-08-10 the promotion
        // posture refuses a sink on a sub-1280 link, so a sub-floor MTU would be
        // rejected by the posture before WinnV3StagedStart could see the MISM
        // it exists to check. The refusal under test here is the MTU change at
        // promotion, not the sink floor, so both MTUs stay above it.
        val e = try {
            WinnV3StagedStart(
                bootstrap = bootstrap(1443), promoted = promoted(1359), proofDeadlineMs = 1,
                pollIntervalMs = 1, install = {}, readStatus = { "" }, tearDown = {},
                nowMs = { 0 }, sleepMs = {},
            )
            throw AssertionError("expected a refusal")
        } catch (e: WinnV3StartRefusal) {
            e
        }
        assertTrue(e.message!!.contains("black holes"))
    }

    @Test
    fun `the deadline is honoured against the injected clock`() {
        var t = 0L
        var polls = 0
        val outcome = WinnV3StagedStart(
            bootstrap = bootstrap(), promoted = promoted(),
            proofDeadlineMs = 1_000L, pollIntervalMs = 250L,
            install = {}, readStatus = { polls++; statusJson("handshaking", 0) },
            tearDown = {}, nowMs = { t }, sleepMs = { t += it },
        ).start()
        assertTrue(outcome is WinnV3StagedStart.Outcome.RefusedNotProven)
        assertEquals(4, polls)
    }

    @Test
    fun `a superseded start cannot install bootstrap`() {
        val installed = mutableListOf<WinnV3Stage>()
        var toreDown = false
        val started = start(
            install = { installed += it.stage },
            tearDown = { toreDown = true },
            isStillOwner = { false },
        )
        try {
            started.start()
            throw AssertionError("expected a superseded refusal")
        } catch (e: WinnV3StartRefusal) {
            assertTrue(e.message!!.contains("before bootstrap"))
        }
        assertTrue(installed.isEmpty())
        assertTrue(toreDown)
    }

    @Test
    fun `a superseded start cannot promote after proof`() {
        val installed = mutableListOf<WinnV3Stage>()
        var owner = true
        var toreDown = false
        val started = start(
            install = { installed += it.stage },
            readStatus = {
                owner = false
                statusJson("carrying", 1)
            },
            tearDown = { toreDown = true },
            isStillOwner = { owner },
        )
        try {
            started.start()
            throw AssertionError("expected a superseded refusal")
        } catch (e: WinnV3StartRefusal) {
            assertTrue(e.message!!.contains("before promotion"))
        }
        assertEquals(listOf(WinnV3Stage.BOOTSTRAP), installed)
        assertTrue(toreDown)
    }

    @Test
    fun `ownership lost during final bridge inspection cannot promote`() {
        val installed = mutableListOf<WinnV3Stage>()
        var owner = true
        var inspections = 0
        var toreDown = false
        val started = start(
            install = { installed += it.stage },
            inspectBridge = {
                inspections++
                if (inspections == 2) owner = false
                WinnV3BridgeSnapshot(running = true, failure = null)
            },
            tearDown = { toreDown = true },
            isStillOwner = { owner },
        )
        try {
            started.start()
            throw AssertionError("expected a superseded refusal")
        } catch (e: WinnV3StartRefusal) {
            assertTrue(e.message!!.contains("final bridge inspection"))
        }
        assertEquals(listOf(WinnV3Stage.BOOTSTRAP), installed)
        assertTrue(toreDown)
    }

    @Test
    fun `atomic promotion callback can reject a superseded install`() {
        val installed = mutableListOf<WinnV3Stage>()
        var toreDown = false
        val started = start(
            install = { installed += it.stage },
            promoteIfStillOwner = { false },
            tearDown = { toreDown = true },
        )
        try {
            started.start()
            throw AssertionError("expected an atomic promotion refusal")
        } catch (e: WinnV3StartRefusal) {
            assertTrue(e.message!!.contains("superseded during promotion"))
        }
        assertEquals(listOf(WinnV3Stage.BOOTSTRAP), installed)
        assertTrue(toreDown)
    }

    @Test
    fun `atomic bootstrap callback can reject a superseded install`() {
        val installed = mutableListOf<WinnV3Stage>()
        var toreDown = false
        val started = start(
            install = { installed += it.stage },
            installBootstrapIfStillOwner = { false },
            tearDown = { toreDown = true },
        )
        try {
            started.start()
            throw AssertionError("expected an atomic bootstrap refusal")
        } catch (e: WinnV3StartRefusal) {
            assertTrue(e.message!!.contains("superseded during bootstrap"))
            assertEquals(WinnV3NativeVerdict.UNKNOWN_TERMINAL, e.verdict)
        }
        assertTrue(installed.isEmpty())
        assertTrue(toreDown)
    }

    // --- the self-starting promotion probe ---------------------------------------

    @Test
    fun `the probe fires only while carrying with nothing delivered, bounded by attempts`() {
        var probes = 0
        var polls = 0
        val outcome = start(
            proofDeadlineMs = 12_000L,
            pollIntervalMs = 100L,
            probeIntervalMs = 500L,
            probe = { probes++ },
            readStatus = {
                polls++
                // Handshake for the first three polls; carrying with nothing
                // delivered for the rest of the window.
                if (polls < 3) statusJson("handshaking", 0) else statusJson("carrying", 0)
            },
        ).start()

        assertTrue(outcome is WinnV3StagedStart.Outcome.RefusedNotProven)
        // Nothing was delivered, so the bounded probe fired exactly its cap --
        // and never while the gate was still handshaking.
        assertEquals(WinnV3PromotionProbe.MAX_PROBE_ATTEMPTS, probes)
    }

    @Test
    fun `the probe stops once a packet has been delivered`() {
        var probes = 0
        var polls = 0
        val outcome = start(
            proofDeadlineMs = 12_000L,
            pollIntervalMs = 100L,
            probeIntervalMs = 300L,
            probe = { probes++ },
            readStatus = {
                polls++
                if (polls < 6) statusJson("carrying", 0) else statusJson("carrying", 1)
            },
        ).start()

        assertTrue(outcome is WinnV3StagedStart.Outcome.Promoted)
        // Probes fired at t=0 and t=300ms; delivery at poll 6 (t=500ms)
        // promoted before the t=600ms slot.
        assertEquals(2, probes)
    }

    @Test
    fun `the probe respects its interval`() {
        var probes = 0
        var polls = 0
        val outcome = start(
            proofDeadlineMs = 12_000L,
            pollIntervalMs = 100L,
            probeIntervalMs = 1_000L,
            probe = { probes++ },
            readStatus = {
                polls++
                if (polls < 25) statusJson("carrying", 0) else statusJson("carrying", 1)
            },
        ).start()

        assertTrue(outcome is WinnV3StagedStart.Outcome.Promoted)
        // t=0, t=1000, t=2000; the delivery at t=2400 promoted before t=3000.
        assertEquals(3, probes)
    }

    @Test
    fun `a throwing probe counts as an attempt and never aborts the start`() {
        var attempts = 0
        var polls = 0
        val outcome = start(
            proofDeadlineMs = 12_000L,
            pollIntervalMs = 100L,
            probeIntervalMs = 300L,
            probe = {
                attempts++
                throw IllegalStateException("the platform refused the injection")
            },
            readStatus = {
                polls++
                if (polls < 6) statusJson("carrying", 0) else statusJson("carrying", 1)
            },
        ).start()

        assertTrue(outcome is WinnV3StagedStart.Outcome.Promoted)
        assertEquals(2, attempts)
    }

    @Test
    fun `a handshake that never carries is never probed`() {
        var probes = 0
        val outcome = start(
            proofDeadlineMs = 12_000L,
            pollIntervalMs = 100L,
            probe = { probes++ },
            readStatus = { statusJson("handshaking", 0) },
        ).start()

        assertTrue(outcome is WinnV3StagedStart.Outcome.RefusedNotProven)
        assertEquals(0, probes)
    }

    // --- native v3 verdict ------------------------------------------------------

    @Test
    fun `a successful promotion publishes connected and does not authorize AWG or Xray`() {
        val outcome = start(
            readStatus = { statusJson("carrying", 1) },
        ).start()
        assertTrue(outcome is WinnV3StagedStart.Outcome.Promoted)
        val promoted = outcome as WinnV3StagedStart.Outcome.Promoted
        assertEquals(WinnV3NativeVerdict.CONNECTED, promoted.verdict)
        assertEquals(-1L, promoted.verdict.awgXrayAuthorizationToken(41L))
    }

    @Test
    fun `inspectBridge runs on every staged poll`() {
        var inspections = 0
        var polls = 0
        val outcome = start(
            inspectBridge = {
                inspections++
                WinnV3BridgeSnapshot(running = true, failure = null)
            },
            readStatus = {
                polls++
                if (polls < 3) statusJson("carrying", 0) else statusJson("carrying", 1)
            },
        ).start()
        assertTrue(outcome is WinnV3StagedStart.Outcome.Promoted)
        assertEquals(polls + 1, inspections)
    }

    @Test
    fun `a dead bridge during poll is unknown_terminal and never waits out the deadline`() {
        var toreDown = false
        var polls = 0
        val outcome = start(
            inspectBridge = {
                WinnV3BridgeSnapshot(running = false, failure = "Winn v3 outbound pump stopped")
            },
            readStatus = {
                polls++
                statusJson("carrying", 0)
            },
            tearDown = { toreDown = true },
        ).start()
        assertTrue(outcome is WinnV3StagedStart.Outcome.RefusedNotProven)
        val refused = outcome as WinnV3StagedStart.Outcome.RefusedNotProven
        assertEquals(WinnV3NativeVerdict.UNKNOWN_TERMINAL, refused.verdict)
        assertEquals(-1L, refused.verdict.awgXrayAuthorizationToken(7L))
        assertTrue(toreDown)
        assertEquals(0, polls)
    }

    @Test
    fun `typed OS network pump failure authorizes ordinary cover without waiting the deadline`() {
        var toreDown = false
        var polls = 0
        for (failure in WinnV3OrdinaryNetworkFailureClass.entries) {
            toreDown = false
            polls = 0
            val outcome = start(
                inspectBridge = {
                    WinnV3BridgeSnapshot(
                        running = false,
                        failure = "Winn v3 outbound pump stopped: TypedErrnoFailure",
                        ordinaryNetworkFailure = failure,
                        ordinaryNetworkPosixErrno = failure.posixErrno,
                        cause = object : IOException("ENETUNREACH: network is unreachable") {
                            @JvmField val errno: Int = failure.posixErrno
                        },
                    )
                },
                readStatus = {
                    polls++
                    statusJson("carrying", 0)
                },
                tearDown = { toreDown = true },
            ).start()
            val refused = outcome as WinnV3StagedStart.Outcome.RefusedNotProven
            assertEquals(failure.name, WinnV3NativeVerdict.ORDINARY_CONNECTIVITY, refused.verdict)
            assertEquals(failure.name, 41L, refused.verdict.awgXrayAuthorizationToken(41L))
            assertFalse(failure.name, refused.verdict.securityRefusal)
            assertTrue(failure.name, toreDown)
            assertEquals(failure.name, 0, polls)
        }
    }

    @Test
    fun `hostile pump-collapse shapes never authorize ordinary cover`() {
        data class Row(
            val name: String,
            val snapshot: WinnV3BridgeSnapshot,
        )
        val rows = listOf(
            Row(
                "class-name only",
                WinnV3BridgeSnapshot(
                    running = false,
                    failure = "Winn v3 outbound pump stopped: IOException",
                ),
            ),
            Row(
                "ENETUNREACH text without errno",
                WinnV3BridgeSnapshot(
                    running = false,
                    failure = "ENETUNREACH: network is unreachable",
                    cause = IOException("ENETUNREACH: network is unreachable"),
                ),
            ),
            Row(
                "timeout exception",
                WinnV3BridgeSnapshot(
                    running = false,
                    failure = "Winn v3 outbound pump stopped: SocketTimeoutException",
                    cause = java.net.SocketTimeoutException("timed out"),
                ),
            ),
            Row(
                "Darwin ENETUNREACH is not Android",
                WinnV3BridgeSnapshot(
                    running = false,
                    failure = "Winn v3 outbound pump stopped: TypedErrnoFailure",
                    ordinaryNetworkPosixErrno = 51,
                    cause = object : IOException("ENETUNREACH: network is unreachable") {
                        @JvmField val errno: Int = 51
                    },
                ),
            ),
            Row(
                "ETIMEDOUT is not ordinary",
                WinnV3BridgeSnapshot(
                    running = false,
                    failure = "Winn v3 outbound pump stopped: TypedErrnoFailure",
                    ordinaryNetworkPosixErrno = 110,
                    cause = object : IOException("ETIMEDOUT") {
                        @JvmField val errno: Int = 110
                    },
                ),
            ),
            Row(
                "ECONNREFUSED is not ordinary",
                WinnV3BridgeSnapshot(
                    running = false,
                    failure = "Winn v3 outbound pump stopped: TypedErrnoFailure",
                    ordinaryNetworkPosixErrno = 111,
                    cause = object : IOException("ECONNREFUSED") {
                        @JvmField val errno: Int = 111
                    },
                ),
            ),
        )
        for (row in rows) {
            val outcome = start(inspectBridge = { row.snapshot }).start()
            val refused = outcome as WinnV3StagedStart.Outcome.RefusedNotProven
            assertEquals(row.name, WinnV3NativeVerdict.UNKNOWN_TERMINAL, refused.verdict)
            assertEquals(row.name, -1L, refused.verdict.awgXrayAuthorizationToken(99L))
            assertTrue(row.name, refused.verdict.securityRefusal)
        }
    }

    @Test
    fun `ordinary-looking text from a dead bridge remains unknown terminal`() {
        val outcome = start(
            inspectBridge = {
                WinnV3BridgeSnapshot(
                    running = false,
                    failure = "ENETUNREACH: network is unreachable",
                )
            },
        ).start()
        assertTrue(outcome is WinnV3StagedStart.Outcome.RefusedNotProven)
        val refused = outcome as WinnV3StagedStart.Outcome.RefusedNotProven
        assertEquals(WinnV3NativeVerdict.UNKNOWN_TERMINAL, refused.verdict)
        assertEquals(-1L, refused.verdict.awgXrayAuthorizationToken(99L))
    }

    @Test
    fun `wrong static key on the bridge is terminal_security without an AWG token`() {
        val outcome = start(
            inspectBridge = {
                WinnV3BridgeSnapshot(
                    running = false,
                    failure = "wrong static key for this gateway",
                )
            },
        ).start()
        val refused = outcome as WinnV3StagedStart.Outcome.RefusedNotProven
        assertEquals(WinnV3NativeVerdict.TERMINAL_SECURITY, refused.verdict)
        assertEquals(-1L, refused.verdict.awgXrayAuthorizationToken(5L))
    }

    @Test
    fun `security on a typed pump failure still wins and publishes no token`() {
        val outcome = start(
            inspectBridge = {
                WinnV3BridgeSnapshot(
                    running = false,
                    failure = "wrong static key for this gateway",
                    ordinaryNetworkFailure = WinnV3OrdinaryNetworkFailureClass.NETWORK_UNREACHABLE,
                    ordinaryNetworkPosixErrno = 101,
                    cause = object : IOException("ENETUNREACH: network is unreachable") {
                        @JvmField val errno: Int = 101
                    },
                )
            },
        ).start()
        val refused = outcome as WinnV3StagedStart.Outcome.RefusedNotProven
        assertEquals(WinnV3NativeVerdict.TERMINAL_SECURITY, refused.verdict)
        assertEquals(-1L, refused.verdict.awgXrayAuthorizationToken(5L))
    }

    @Test
    fun `a live bridge proof timeout emits unknown_terminal with no token`() {
        val outcome = start(
            readStatus = { statusJson("carrying", 0) },
        ).start()
        assertTrue(outcome is WinnV3StagedStart.Outcome.RefusedNotProven)
        val refused = outcome as WinnV3StagedStart.Outcome.RefusedNotProven
        assertEquals(WinnV3NativeVerdict.UNKNOWN_TERMINAL, refused.verdict)
        assertEquals(-1L, refused.verdict.awgXrayAuthorizationToken(41L))
    }

    @Test
    fun `an explicit engine refusal carries terminal_security`() {
        val started = start(
            readStatus = {
                """{"gate_state":"closed","rx_packets":0,"rx_offered":0,"refusal":"admission rejected"}"""
            },
        )
        try {
            started.start()
            throw AssertionError("expected the engine refusal to propagate")
        } catch (e: WinnV3StartRefusal) {
            assertEquals(WinnV3NativeVerdict.TERMINAL_SECURITY, e.verdict)
            assertEquals(-1L, e.verdict.awgXrayAuthorizationToken(3L))
        }
    }

    @Test
    fun `an untrustworthy status is unknown_terminal not connectivity`() {
        val started = start(
            readStatus = { """{"gate_state":"carrying","rx_offered":5}""" },
        )
        try {
            started.start()
            throw AssertionError("expected a refusal")
        } catch (e: WinnV3StartRefusal) {
            assertEquals(WinnV3NativeVerdict.UNKNOWN_TERMINAL, e.verdict)
            assertEquals(-1L, e.verdict.awgXrayAuthorizationToken(8L))
        }
    }

    @Test
    fun `ordinary probe errno cannot authorize after cancel`() {
        var owner = true
        val outcome = try {
            start(
                inspectBridge = {
                    owner = false
                    WinnV3BridgeSnapshot(
                        running = true,
                        failure = null,
                        ordinaryNetworkPosixErrno = 101,
                    )
                },
                readStatus = { statusJson("carrying", 0) },
                isStillOwner = { owner },
            ).start()
        } catch (e: WinnV3StartRefusal) {
            assertEquals(WinnV3NativeVerdict.UNKNOWN_TERMINAL, e.verdict)
            assertEquals(-1L, e.verdict.awgXrayAuthorizationToken(41L))
            return
        }
        val refused = outcome as WinnV3StagedStart.Outcome.RefusedNotProven
        assertEquals(WinnV3NativeVerdict.UNKNOWN_TERMINAL, refused.verdict)
        assertEquals(-1L, refused.verdict.awgXrayAuthorizationToken(41L))
    }

    @Test
    fun `protected-socket capture consumes numeric send errno and always closes`() {
        val live = mutableSetOf<Int>()
        val result = WinnV3ProtectedSocketErrno.capture(
            open = {
                live.add(4)
                4
            },
            protect = { true },
            send = {
                throw object : IOException("sendto failed: Network is unreachable") {
                    @JvmField val errno: Int = 101
                }
            },
            close = { live.remove(it) },
        )
        assertTrue(result.protected)
        assertTrue(result.closed)
        assertFalse(result.protectionFailed)
        assertTrue(live.isEmpty())
        assertEquals(101, result.posixErrno)
        assertEquals(
            WinnV3OrdinaryNetworkFailureClass.NETWORK_UNREACHABLE,
            WinnV3OrdinaryNetworkEvidence.classify(posixErrno = result.posixErrno),
        )
    }

    @Test
    fun `protected-socket capture refuses protection failure without sending`() {
        val live = mutableSetOf<Int>()
        var sent = false
        val result = WinnV3ProtectedSocketErrno.capture(
            open = {
                live.add(8)
                8
            },
            protect = { false },
            send = {
                sent = true
                throw object : IOException("ENETUNREACH") {
                    @JvmField val errno: Int = 101
                }
            },
            close = { live.remove(it) },
        )
        assertTrue(result.protectionFailed)
        assertTrue(result.closed)
        assertFalse(result.protected)
        assertFalse(sent)
        assertTrue(live.isEmpty())
        assertNull(result.posixErrno)
        assertNull(
            WinnV3OrdinaryNetworkEvidence.classify(
                posixErrno = result.posixErrno,
                cause = result.cause,
            ),
        )
    }

    @Test
    fun `protected-socket capture never authorizes SocketException or class-name ErrnoException`() {
        class ErrnoException(message: String) : IOException(message)
        data class Row(val name: String, val error: Throwable)
        val rows = listOf(
            Row(
                "DatagramChannel SocketException",
                java.net.SocketException("sendto failed: ENETUNREACH (Network is unreachable)"),
            ),
            Row("class-name ErrnoException", ErrnoException("errno 101 ENETUNREACH")),
            Row("timeout", java.net.SocketTimeoutException("ETIMEDOUT")),
            Row(
                "Darwin ENETUNREACH",
                object : IOException("ENETUNREACH") {
                    @JvmField val errno: Int = 51
                },
            ),
            Row(
                "ECONNREFUSED",
                object : IOException("ECONNREFUSED") {
                    @JvmField val errno: Int = 111
                },
            ),
        )
        for (row in rows) {
            val live = mutableSetOf<Int>()
            val result = WinnV3ProtectedSocketErrno.capture(
                open = {
                    live.add(2)
                    2
                },
                protect = { true },
                send = { throw row.error },
                close = { live.remove(it) },
            )
            assertTrue(row.name, result.closed)
            assertTrue(row.name, live.isEmpty())
            val classified = WinnV3OrdinaryNetworkEvidence.classify(
                posixErrno = result.posixErrno,
                cause = result.cause,
            )
            assertNull(row.name, classified)
            assertEquals(
                row.name,
                WinnV3NativeVerdict.UNKNOWN_TERMINAL,
                WinnV3NativeVerdictClassifier.fromEvidence(
                    cause = result.cause,
                    ordinaryNetworkPosixErrno = result.posixErrno,
                ),
            )
        }
    }

    @Test
    fun `protected-socket capture source never parses prose`() {
        var dir: java.io.File? = java.io.File(System.getProperty("user.dir") ?: ".").absoluteFile
        var source: String? = null
        while (dir != null) {
            val candidate = java.io.File(
                dir,
                "android/app/src/main/kotlin/org/winsvpn/app/WinnV3StagedStart.kt",
            )
            if (candidate.isFile) {
                source = candidate.readText()
                break
            }
            val here = java.io.File(dir, "app/src/main/kotlin/org/winsvpn/app/WinnV3StagedStart.kt")
            if (here.isFile) {
                source = here.readText()
                break
            }
            dir = dir.parentFile
        }
        val text = source ?: throw AssertionError("could not locate WinnV3StagedStart.kt")
        val capture = text.substringAfter("internal object WinnV3ProtectedSocketErrno")
            .substringBefore("internal data class WinnV3BridgeSnapshot")
        assertTrue(capture.contains("typedErrno(thrown)"))
        assertFalse(capture.contains(".message"))
        assertFalse(capture.contains("simpleName"))
        assertFalse(capture.contains("\"enetunreach\""))
        assertTrue(text.contains("fun typedPosixErrno"))
        assertTrue(text.contains("Never [Throwable.message]"))
    }

    @Test
    fun `literal and escaped critical members cannot occur twice in either order`() {
        val values = mapOf(
            "gate_state" to "\"carrying\"",
            "rx_packets" to "1",
            "rx_offered" to "1",
            "refusal" to "\"blocked\"",
            "event" to "\"ready\"",
            "promotion_ready" to "true",
            "lifecycle" to "\"carrying\"",
            "lifecycle_cause" to "\"blocked\"",
        )
        for ((key, value) in values) {
            val escaped = "\\u%04x".format(key.first().code) + key.drop(1)
            for ((first, second) in listOf(key to escaped, escaped to key)) {
                val json = "{\"$first\":$value,\"$second\":$value}"
                try {
                    WinnV3EngineStatus.parse(json)
                    throw AssertionError("duplicate $key accepted: $json")
                } catch (error: WinnV3StartRefusal) {
                    assertTrue(error.message!!.contains("duplicate JSON member $key"))
                }
            }
        }
    }

    @Test
    fun `escaped lifecycle names and values preserve refusal semantics`() {
        val literal = WinnV3EngineStatus.parse(
            """{"lifecycle":"blocked","lifecycle_cause":"admission rejected"}"""
        )
        val escaped = WinnV3EngineStatus.parse(
            """{"lifec\u0079cle":"b\u006cocked","lifecycle_ca\u0075se":"admission rejected"}"""
        )
        assertEquals(literal, escaped)
        assertFalse(WinnV3PromotionGate.isProven(escaped))
    }

    @Test
    fun `escaped unknown nested keys and string values do not supply top level proof`() {
        val status = WinnV3EngineStatus.parse(
            """{"gate_state":"handshaking","rx_packets":0,"unkn\u006fwn":{"gate_state":"carrying","rx_packets":5},"note":"\"gate_state\":\"carrying\"","array":[true,false,null,1.25e2]}"""
        )
        assertEquals(WinnV3GateState.HANDSHAKING, status.gateState)
        assertEquals(0L, status.rxPackets)
        assertFalse(WinnV3PromotionGate.isProven(status))
    }

    @Test
    fun `malformed grammar and non ASCII digits are terminal refusals`() {
        val documents = listOf(
            """{"gate_state":"carrying" "rx_packets":1}""",
            """{"gate_state":"carrying","rx_packets":1,}""",
            """{"gate_state":"carrying","rx_packets":01}""",
            """{"gate_state":"carrying","rx_packets":1,"nested":[true,]}""",
            """{"gate_state":"carrying","rx_packets":1,"nested":{"x":}}""",
            """{"gate_state":"carrying","rx_packets":1,"x":NaN}""",
            """{"gate_state":"carrying","rx_packets":1,"x":"\q"}""",
            """{"gate_state":"carrying","rx_packets":١}""",
            """{"gate_state":"carrying","rx_packets":1,"x":"\u００４１"}""",
            "{\"gate_state\":\"carrying\",\"rx_packets\":1,\u00a0\"x\":true}",
            """{"gate_state":"carrying","rx_packets":1} trailing""",
        )
        for (json in documents) {
            try {
                WinnV3EngineStatus.parse(json)
                throw AssertionError("malformed document accepted: $json")
            } catch (_: WinnV3StartRefusal) {
            }
        }
    }

    @Test
    fun `status wait time is part of the poll tick`() {
        var now = 0L
        val sleeps = mutableListOf<Long>()
        val outcome = WinnV3StagedStart(
            bootstrap = bootstrap(), promoted = promoted(),
            proofDeadlineMs = 1_000L, pollIntervalMs = 250L,
            install = {}, readStatus = { now += 100L; statusJson("handshaking", 0) },
            tearDown = {}, isStillOwner = { true },
            nowMs = { now }, sleepMs = { sleeps += it; now += it },
        ).start()
        assertTrue(outcome is WinnV3StagedStart.Outcome.RefusedNotProven)
        assertEquals(4, (outcome as WinnV3StagedStart.Outcome.RefusedNotProven).pollCount)
        assertEquals(listOf(150L, 150L, 150L, 150L), sleeps)
        assertEquals(1_000L, now)
    }

    @Test
    fun `proof arriving at or after the deadline never promotes`() {
        for (elapsed in listOf(1_000L, 1_001L)) {
            var now = 0L
            var promotions = 0
            val outcome = WinnV3StagedStart(
                bootstrap = bootstrap(), promoted = promoted(),
                proofDeadlineMs = 1_000L, pollIntervalMs = 250L,
                install = { if (it.stage == WinnV3Stage.PROMOTED) promotions++ },
                readStatus = { now += elapsed; statusJson("carrying", 1) },
                tearDown = {}, isStillOwner = { true },
                nowMs = { now }, sleepMs = { now += it },
            ).start()
            assertTrue(outcome is WinnV3StagedStart.Outcome.RefusedNotProven)
            assertEquals(0, promotions)
        }
    }

    private fun status(gate: String, rxPackets: Long) =
        WinnV3EngineStatus(WinnV3GateState.fromWire(gate), rxPackets, rxPackets)

    private fun statusJson(gate: String, rxPackets: Long) =
        """{"gate_state":"$gate","rx_packets":$rxPackets,"rx_offered":$rxPackets}"""

    private fun start(
        proofDeadlineMs: Long = 2_000L,
        pollIntervalMs: Long = 100L,
        probeIntervalMs: Long = WinnV3PromotionProbe.PROBE_INTERVAL_MS,
        install: (WinnV3Posture) -> Unit = {},
        installBootstrapIfStillOwner: ((WinnV3Posture) -> Boolean)? = null,
        promoteIfStillOwner: ((WinnV3Posture) -> Boolean)? = null,
        readStatus: () -> String = { statusJson("carrying", 1) },
        tearDown: () -> Unit = {},
        isStillOwner: () -> Boolean = { true },
        probe: (() -> Unit)? = null,
        inspectBridge: () -> WinnV3BridgeSnapshot = {
            WinnV3BridgeSnapshot(running = true, failure = null)
        },
    ): WinnV3StagedStart {
        var t = 0L
        return WinnV3StagedStart(
            bootstrap = bootstrap(),
            promoted = promoted(),
            proofDeadlineMs = proofDeadlineMs,
            pollIntervalMs = pollIntervalMs,
            install = install,
            installBootstrapIfStillOwner = installBootstrapIfStillOwner,
            promoteIfStillOwner = promoteIfStillOwner,
            readStatus = readStatus,
            inspectBridge = inspectBridge,
            tearDown = tearDown,
            isStillOwner = isStillOwner,
            probe = probe,
            probeIntervalMs = probeIntervalMs,
            nowMs = { t },
            sleepMs = { t += it },
        )
    }
}
