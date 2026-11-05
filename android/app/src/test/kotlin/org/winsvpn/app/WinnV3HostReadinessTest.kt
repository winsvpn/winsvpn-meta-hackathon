package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Round A3: the native bridge half of the Android lifecycle contract.
 *
 * `test/fixtures/winn3_host_lifecycle_readiness.json` lists a session's life
 * (connected, recovering, a later recovery, engine-reported blocked, the hold
 * after teardown, the host ceiling, an end with no blocked report, a hold the
 * platform could not refresh, a release forced by the disguise, a legacy
 * engine). Each step is applied to [WinnV3HostLifecycleBoard] exactly as the
 * service applies it, and the claim and lifecycle keys MainActivity puts in
 * `getTunnelReadiness` ([VpnTunnelService.readinessClaimFields]) must equal the
 * fixture's. The Dart status consumer is tested against the same maps in
 * `test/winn3_host_lifecycle_contract_test.dart`.
 */
class WinnV3HostReadinessTest {

    @Test
    fun `every step of the fixture is what the native bridge publishes`() {
        val fixture = Json.parse(fixtureText()) as Map<*, *>
        val steps = fixture["android"] as List<*>
        assertTrue("the fixture was not read; this guard would be vacuous", steps.size >= 10)
        val board = WinnV3HostLifecycleBoard()
        var owner = -1
        var watch = WinnV3LifecycleWatch()
        var now = 0L
        var revision = 1_000_000L
        for (raw in steps) {
            val step = raw as Map<*, *>
            val name = step["step"] as String
            val op = step["op"] as Map<*, *>
            (op["begin"] as? Long)?.let {
                owner = it.toInt()
                board.begin(owner)
                watch = WinnV3LifecycleWatch()
            }
            // A status document through the post-promotion loop's own step.
            (op["engine"] as? String)?.let { lifecycle ->
                now += 1_000L
                val binding = WinnV3LifecycleBinding(watch, owner)
                val observation = WinnV3PostPromotionStep.judge(
                    binding,
                    """{"gate_state":"carrying","rx_packets":5,"lifecycle":"$lifecycle"}""",
                    now,
                )
                val published = WinnV3PostPromotionStep.publish(board, binding, true, observation)
                assertTrue("$name: the owning session's publication was refused", published != WinnV3HostLifecycleBoard.Publication.REJECTED)
            }
            (op["publish"] as? String)?.let { verdict ->
                val observer = (op["observer"] as? String)?.let { WinnV3LifecycleObserver.valueOf(it) }
                revision += 1
                val published = board.publish(
                    owner,
                    WinnV3LifecycleWatch.Observation(
                        WinnV3LifecycleWatch.Verdict.valueOf(verdict),
                        observer,
                        op["cause"] as? String,
                        revision,
                    ),
                )
                assertTrue("$name: the owning session's publication was refused", published != WinnV3HostLifecycleBoard.Publication.REJECTED)
            }
            if (op["hold"] == true) board.holdCapture(held = true, limitation = null)
            // A revocation or destruction releasing the established hold.
            (op["os_release"] as? String)?.let { cause ->
                val limitation = WinnV3CaptureCustody().releaseLimitationFor(WinnV3TeardownCause.valueOf(cause))!!
                board.releaseHeldCapture(limitation)
                board.clear()
            }
            (op["hold_limitation"] as? String)?.let { board.holdCapture(held = true, limitation = it) }
            (op["release"] as? String)?.let { board.holdCapture(held = false, limitation = it) }
            // A non-holding end of the service (its PROCESS_DESTROY pass).
            if (op["end"] == true) board.clear()
            // The owner's Disconnect.
            if (op["acknowledge"] == true) board.acknowledgeReleaseNotice()

            val composite = (step["composite"] as List<*>).map { it as Boolean }
            val actual = VpnTunnelService.readinessClaimFields(
                serviceActive = composite[0],
                engineReady = composite[1],
                interfaceOpen = composite[2],
                lifecycle = board.snapshot(),
            )
            val expected = (step["readiness"] as Map<*, *>).mapKeys { it.key as String }
            assertEquals("$name: getTunnelReadiness claim and lifecycle keys", expected, actual)
            assertEquals(
                "$name: isTunnelHealthy agrees with `active`",
                expected["active"],
                VpnTunnelService.tunnelHealthyFor(composite[0], composite[1], composite[2], board.snapshot()),
            )
            val claimsConnectedNotification = VpnTunnelService.tunnelForegroundFor(
                composite[0], composite[1], composite[2], board.snapshot().state,
            ) == VpnTunnelService.TunnelForegroundState.CONNECTED
            assertEquals("$name: the notification claims connected exactly when readiness does", expected["active"], claimsConnectedNotification)
        }
    }

    @Test
    fun `the lifecycle keys never collide with the start verdict or the cover token`() {
        val keys = WinnV3HostLifecycleBoard.Snapshot(
            state = WinnV3Lifecycle.BLOCKED,
            observer = WinnV3LifecycleObserver.ENGINE,
            cause = "terminal",
            captureHeld = true,
            limitation = "x",
        ).readinessFields().keys
        for (historical in listOf(
            "winn3_verdict",
            "winn3_start_state",
            "winn3_security_refusal",
            "winn3_awg_xray_authorization_token",
            "winn3_start_token",
        )) {
            assertTrue("$historical must stay the start verdict's own key", historical !in keys)
        }
    }

    private fun fixtureText(): String {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            val candidate = File(dir, "test/fixtures/winn3_host_lifecycle_readiness.json")
            if (candidate.isFile) return candidate.readText()
            dir = dir.parentFile
        }
        throw AssertionError("could not locate test/fixtures/winn3_host_lifecycle_readiness.json")
    }

    /** Enough JSON for the fixture: objects, arrays, strings, integers, booleans, null. */
    private object Json {
        fun parse(text: String): Any? {
            val reader = Reader(text)
            val value = reader.value()
            reader.skip()
            check(reader.at == text.length) { "trailing data at ${reader.at}" }
            return value
        }

        private class Reader(val s: String) {
            var at = 0

            fun skip() {
                while (at < s.length && s[at].isWhitespace()) at++
            }

            fun value(): Any? {
                skip()
                return when (val c = s[at]) {
                    '{' -> obj()
                    '[' -> arr()
                    '"' -> str()
                    't' -> literal("true", true)
                    'f' -> literal("false", false)
                    'n' -> literal("null", null)
                    else -> if (c == '-' || c.isDigit()) num() else error("unexpected '$c' at $at")
                }
            }

            private fun literal(word: String, v: Any?): Any? {
                check(s.startsWith(word, at)) { "bad literal at $at" }
                at += word.length
                return v
            }

            private fun num(): Long {
                val start = at
                if (s[at] == '-') at++
                while (at < s.length && s[at].isDigit()) at++
                return s.substring(start, at).toLong()
            }

            private fun str(): String {
                at++
                val out = StringBuilder()
                while (s[at] != '"') {
                    if (s[at] == '\\') {
                        at++
                        out.append(
                            when (s[at]) {
                                'n' -> '\n'
                                't' -> '\t'
                                else -> s[at]
                            },
                        )
                    } else {
                        out.append(s[at])
                    }
                    at++
                }
                at++
                return out.toString()
            }

            private fun arr(): List<Any?> {
                at++
                val out = mutableListOf<Any?>()
                skip()
                if (s[at] == ']') {
                    at++
                    return out
                }
                while (true) {
                    out += value()
                    skip()
                    if (s[at] == ',') {
                        at++
                        continue
                    }
                    check(s[at] == ']') { "expected ] at $at" }
                    at++
                    return out
                }
            }

            private fun obj(): Map<String, Any?> {
                at++
                val out = linkedMapOf<String, Any?>()
                skip()
                if (s[at] == '}') {
                    at++
                    return out
                }
                while (true) {
                    skip()
                    val key = str()
                    skip()
                    check(s[at] == ':') { "expected : at $at" }
                    at++
                    out[key] = value()
                    skip()
                    if (s[at] == ',') {
                        at++
                        continue
                    }
                    check(s[at] == '}') { "expected } at $at" }
                    at++
                    return out
                }
            }
        }
    }
}
