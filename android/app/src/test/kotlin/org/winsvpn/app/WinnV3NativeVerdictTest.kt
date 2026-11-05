package org.winsvpn.app

import java.io.File
import java.io.IOException
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The typed native v3 verdict, its generation binding, and the AWG/Xray
 * authorization token. The token is present only for a positively ordinary
 * network failure; every security or unknown case must leave it absent.
 *
 * Raw exception text, including ENETUNREACH and timeout strings, is never
 * authorization. Winn v3 stays primary; Winn v1 AWG then Xray cover is
 * minted only for authenticated/typed connectivity failure classes.
 */
class WinnV3NativeVerdictTest {

    @Test
    fun `MethodChannel identities accept only exact positive integral values`() {
        assertEquals(7L, WinnV3MethodIdentity.exactPositiveLong(7))
        assertEquals(8L, WinnV3MethodIdentity.exactPositiveLong(8L))
        assertNull(WinnV3MethodIdentity.exactPositiveLong(0))
        assertNull(WinnV3MethodIdentity.exactPositiveLong(-1L))
        assertNull(WinnV3MethodIdentity.exactPositiveLong(41.9))
        assertNull(WinnV3MethodIdentity.exactPositiveLong(41.0f))
        assertNull(WinnV3MethodIdentity.exactPositiveLong("41"))
        assertNull(WinnV3MethodIdentity.exactPositiveLong(true))
        assertNull(WinnV3MethodIdentity.exactPositiveLong(null))
    }

    @Test
    fun `v3 config detection requires an identity pair even when both are absent`() {
        assertTrue(WinnV3MethodIdentity.configRequestsV3("[winn]\nprotocol = 3\n"))
        assertTrue(WinnV3MethodIdentity.configRequestsV3("[WINN]\ncarrier = WINN3\n"))
        assertFalse(WinnV3MethodIdentity.configRequestsV3("[winn]\nprotocol = 1\n"))
        assertFalse(WinnV3MethodIdentity.configRequestsV3("[other]\nprotocol = 3\n"))
        assertFalse(WinnV3MethodIdentity.configRequestsV3("[winn]\n; protocol = 3\n"))
    }

    @Test
    fun `the wire vocabulary is exactly the four typed values`() {
        assertEquals(
            listOf(
                "ordinary_connectivity",
                "terminal_security",
                "unknown_terminal",
                "connected",
            ),
            WinnV3NativeVerdict.entries.map { it.wire },
        )
        assertFalse(
            WinnV3NativeVerdict.entries.any { it.wire == "connectivity_failed" },
        )
        assertFalse(
            WinnV3NativeVerdict.entries.any { it.wire == "security_refused" },
        )
        assertFalse(
            WinnV3NativeVerdict.entries.any { it.wire == "promoted" },
        )
    }

    @Test
    fun `AWG Xray authorization token is present only for ordinary connectivity`() {
        val generation = 41L
        val rows = listOf(
            "wrong static key" to WinnV3NativeVerdict.TERMINAL_SECURITY,
            "mismatched admission secret" to WinnV3NativeVerdict.TERMINAL_SECURITY,
            "divergent gateway id" to WinnV3NativeVerdict.TERMINAL_SECURITY,
            "admission rejected" to WinnV3NativeVerdict.TERMINAL_SECURITY,
            "replay cache silence" to WinnV3NativeVerdict.TERMINAL_SECURITY,
            "malformed proof" to WinnV3NativeVerdict.TERMINAL_SECURITY,
            "stale ack" to WinnV3NativeVerdict.TERMINAL_SECURITY,
            "Winn v3 outbound pump stopped" to WinnV3NativeVerdict.UNKNOWN_TERMINAL,
            "unknown engine error" to WinnV3NativeVerdict.UNKNOWN_TERMINAL,
        )
        for ((error, want) in rows) {
            val got = WinnV3NativeVerdictClassifier.fromEvidence(error = error)
            assertEquals(error, want, got)
            val published = WinnV3NativeVerdictPublisher.apply(
                generation,
                9L,
                generation,
                9L,
                got,
            )!!
            assertEquals(error, -1L, published.awgXrayAuthorizationToken)
            assertTrue(error, published.securityRefusal)
            assertFalse(error, published.state == "connectivity_failed")
        }

        val ordinary = WinnV3NativeVerdictClassifier.fromEvidence(
            error = "ENETUNREACH: network is unreachable",
            ordinaryNetworkPosixErrno = 101,
        )
        assertEquals(WinnV3NativeVerdict.ORDINARY_CONNECTIVITY, ordinary)
        val published = WinnV3NativeVerdictPublisher.apply(
            generation,
            9L,
            generation,
            9L,
            ordinary,
        )!!
        assertEquals(generation, published.awgXrayAuthorizationToken)
        assertFalse(published.securityRefusal)
        assertEquals("ordinary_connectivity", published.state)
    }

    @Test
    fun `a stale generation cannot publish an AWG Xray token`() {
        val published = WinnV3NativeVerdictPublisher.apply(
            currentToken = 7L,
            currentGeneration = 2L,
            startToken = 8L,
            startGeneration = 2L,
            verdict = WinnV3NativeVerdict.ORDINARY_CONNECTIVITY,
        )
        assertNull(published)
    }

    @Test
    fun `an equal token with a stale transition generation cannot publish`() {
        val published = WinnV3NativeVerdictPublisher.apply(
            currentToken = 7L,
            currentGeneration = 2L,
            startToken = 7L,
            startGeneration = 1L,
            verdict = WinnV3NativeVerdict.ORDINARY_CONNECTIVITY,
        )
        assertNull(published)
    }

    @Test
    fun `timeout without positive network evidence is unknown_terminal`() {
        val got = WinnV3NativeVerdictClassifier.fromEvidence(
            timedOut = true,
            error = "gate is carrying but RxPackets is 0",
        )
        assertEquals(WinnV3NativeVerdict.UNKNOWN_TERMINAL, got)
        assertEquals(-1L, got.awgXrayAuthorizationToken(11L))
    }

    @Test
    fun `mixed security evidence wins over ordinary unreachability`() {
        val got = WinnV3NativeVerdictClassifier.fromEvidence(
            error = "ENETUNREACH after admission secret mismatch",
            positiveOrdinaryUnreachability = true,
        )
        assertEquals(WinnV3NativeVerdict.TERMINAL_SECURITY, got)
        assertEquals(-1L, got.awgXrayAuthorizationToken(2L))
    }

    @Test
    fun `connected never authorizes AWG or Xray`() {
        val published = WinnV3NativeVerdictPublisher.apply(
            currentToken = 1L,
            currentGeneration = 4L,
            startToken = 1L,
            startGeneration = 4L,
            verdict = WinnV3NativeVerdict.CONNECTED,
        )!!
        assertEquals("connected", published.state)
        assertEquals(-1L, published.awgXrayAuthorizationToken)
        assertFalse(published.securityRefusal)
    }

    @Test
    fun `engine status refusal is terminal_security`() {
        val got = WinnV3NativeVerdictClassifier.fromEvidence(
            statusRefusal = "admission rejected",
        )
        assertEquals(WinnV3NativeVerdict.TERMINAL_SECURITY, got)
    }

    @Test
    fun `malformed status is unknown_terminal`() {
        val got = WinnV3NativeVerdictClassifier.fromEvidence(
            untrustworthyStatus = "status document is not a single JSON object",
        )
        assertEquals(WinnV3NativeVerdict.UNKNOWN_TERMINAL, got)
        assertEquals(-1L, got.awgXrayAuthorizationToken(4L))
    }

    @Test
    fun `raw ENETUNREACH and timeout strings never authorize AWG or Xray`() {
        val generation = 41L
        val rows = listOf(
            "ENETUNREACH",
            "ENETUNREACH: network is unreachable",
            "network is unreachable",
            "network unreachable",
            "EHOSTUNREACH",
            "no route to host",
            "host is unreachable",
            "ENETDOWN",
            "EHOSTDOWN",
            "errno 101",
            "errno 113",
            "os error 101",
            "os error 113",
            "timeout",
            "timed out",
            "Connection timed out",
            "ETIMEDOUT",
            "socket timeout",
            "handshake timeout",
        )
        for (error in rows) {
            val got = WinnV3NativeVerdictClassifier.fromEvidence(error = error)
            assertEquals(error, WinnV3NativeVerdict.UNKNOWN_TERMINAL, got)
            assertEquals(error, -1L, got.awgXrayAuthorizationToken(generation))
            assertTrue(error, got.securityRefusal)
        }
    }

    @Test
    fun `handshake attempts exhausted with nothing arrived at all is unknown_terminal and not terminal_security`() {
        val goHandshakeExhaustedError = "handshake attempts exhausted on this carrier: 5 attempts, " +
            "5 handshake messages sent, nothing arrived at all. A blocked path and a gateway that " +
            "refused these credentials are indistinguishable from here, because a v3 gateway answers " +
            "neither: so check the gateway static key, the admission secret and the gateway id " +
            "before treating this as censorship"
        val got = WinnV3NativeVerdictClassifier.fromEvidence(error = goHandshakeExhaustedError)
        assertEquals(WinnV3NativeVerdict.UNKNOWN_TERMINAL, got)
    }

    @Test
    fun `exception objects carrying only ordinary-looking text never authorize`() {
        val rows = listOf<Throwable>(
            IOException("ENETUNREACH: network is unreachable"),
            ConnectException("Network is unreachable"),
            SocketTimeoutException("timed out"),
            UnknownHostException("timeout while resolving"),
            Exception("errno 101"),
            RuntimeException("os error 113"),
        )
        for (thrown in rows) {
            val label = thrown.javaClass.simpleName + ": " + thrown.message
            val got = WinnV3NativeVerdictClassifier.fromEvidence(
                error = thrown.message,
                cause = thrown,
            )
            assertEquals(label, WinnV3NativeVerdict.UNKNOWN_TERMINAL, got)
            assertEquals(label, -1L, got.awgXrayAuthorizationToken(7L))
        }
    }

    @Test
    fun `unauthorized POSIX numbers never authorize even with ENETUNREACH text`() {
        val rows = listOf(
            51, // Darwin ENETUNREACH; not an Android/Linux allowlist member
            50,
            64,
            65,
            110, // ETIMEDOUT
            111, // ECONNREFUSED
            0,
            -1,
        )
        for (errno in rows) {
            val got = WinnV3NativeVerdictClassifier.fromEvidence(
                error = "ENETUNREACH: network is unreachable",
                ordinaryNetworkPosixErrno = errno,
                cause = TypedErrnoFailure(errno, "ETIMEDOUT: timed out"),
            )
            assertEquals("errno $errno", WinnV3NativeVerdict.UNKNOWN_TERMINAL, got)
            assertEquals("errno $errno", -1L, got.awgXrayAuthorizationToken(3L))
        }
    }

    @Test
    fun `typed Android Linux POSIX classes authorize AWG then Xray cover`() {
        val generation = 41L
        for (failure in WinnV3OrdinaryNetworkFailureClass.entries) {
            val got = WinnV3NativeVerdictClassifier.fromEvidence(
                error = "ignored ENETUNREACH text",
                ordinaryNetworkFailure = failure,
            )
            assertEquals(failure.name, WinnV3NativeVerdict.ORDINARY_CONNECTIVITY, got)
            val published = WinnV3NativeVerdictPublisher.apply(
                generation, 9L, generation, 9L, got,
            )!!
            assertEquals(failure.name, generation, published.awgXrayAuthorizationToken)
            assertFalse(failure.name, published.securityRefusal)
            assertEquals(failure.name, "ordinary_connectivity", published.state)
        }
    }

    @Test
    fun `typed Android Linux POSIX errnos authorize AWG then Xray cover`() {
        val generation = 12L
        val errnos = listOf(100, 101, 112, 113)
        assertEquals(
            errnos,
            WinnV3OrdinaryNetworkFailureClass.entries.map { it.posixErrno },
        )
        for (errno in errnos) {
            val got = WinnV3NativeVerdictClassifier.fromEvidence(
                error = "gate is carrying but RxPackets is 0",
                ordinaryNetworkPosixErrno = errno,
            )
            assertEquals("errno $errno", WinnV3NativeVerdict.ORDINARY_CONNECTIVITY, got)
            assertEquals("errno $errno", generation, got.awgXrayAuthorizationToken(generation))
            assertFalse("errno $errno", got.securityRefusal)
        }
    }

    @Test
    fun `NoRouteToHostException without structured errno does not authorize`() {
        val got = WinnV3NativeVerdictClassifier.fromEvidence(
            cause = NoRouteToHostException("ENETUNREACH: network is unreachable"),
        )
        assertEquals(WinnV3NativeVerdict.UNKNOWN_TERMINAL, got)
        assertEquals(-1L, got.awgXrayAuthorizationToken(8L))
        assertNull(
            WinnV3OrdinaryNetworkEvidence.classifyThrowable(
                NoRouteToHostException("timeout"),
            ),
        )
    }

    @Test
    fun `SocketException prose and ErrnoException class names never authorize`() {
        class ErrnoException(message: String) : Exception(message)
        val rows = listOf<Throwable>(
            java.net.SocketException("sendto failed: ENETUNREACH (Network is unreachable)"),
            ErrnoException("errno 101 ENETUNREACH"),
            SocketTimeoutException("ETIMEDOUT"),
        )
        for (thrown in rows) {
            val label = thrown.javaClass.simpleName + ": " + thrown.message
            val got = WinnV3NativeVerdictClassifier.fromEvidence(
                error = thrown.message,
                cause = thrown,
            )
            assertEquals(label, WinnV3NativeVerdict.UNKNOWN_TERMINAL, got)
            assertEquals(label, -1L, got.awgXrayAuthorizationToken(7L))
            assertNull(label, WinnV3OrdinaryNetworkEvidence.classifyThrowable(thrown))
            assertNull(label, WinnV3OrdinaryNetworkEvidence.typedPosixErrno(thrown))
        }
    }

    @Test
    fun `production capture numeric errno authorizes ordinary cover before the deadline`() {
        val captured = WinnV3ProtectedSocketErrno.capture(
            open = { 1 },
            protect = { true },
            send = {
                throw object : Exception("sendto failed: Network is unreachable") {
                    @JvmField val errno: Int = 101
                }
            },
            close = {},
        )
        assertEquals(101, captured.posixErrno)
        val outcome = stagedStart(
            inspectBridge = {
                WinnV3BridgeSnapshot(
                    running = true,
                    failure = null,
                    ordinaryNetworkPosixErrno = captured.posixErrno,
                    cause = captured.cause,
                )
            },
            readStatus = { """{"gate_state":"carrying","rx_packets":0,"rx_offered":0}""" },
        ).start()
        val refused = outcome as WinnV3StagedStart.Outcome.RefusedNotProven
        assertEquals(WinnV3NativeVerdict.ORDINARY_CONNECTIVITY, refused.verdict)
        assertEquals(41L, refused.verdict.awgXrayAuthorizationToken(41L))
        assertFalse(refused.verdict.securityRefusal)
    }

    @Test
    fun `a throwable whose typed errno is allowlisted authorizes despite its message`() {
        val cause = TypedErrnoFailure(101, "ENETUNREACH: network is unreachable")
        val got = WinnV3NativeVerdictClassifier.fromEvidence(cause = cause)
        assertEquals(WinnV3NativeVerdict.ORDINARY_CONNECTIVITY, got)
        assertEquals(5L, got.awgXrayAuthorizationToken(5L))
        assertEquals(
            WinnV3OrdinaryNetworkFailureClass.NETWORK_UNREACHABLE,
            WinnV3OrdinaryNetworkEvidence.classifyThrowable(cause),
        )
    }

    @Test
    fun `typed ordinary evidence nested in the cause chain still authorizes`() {
        val nested = IOException(
            "wrapper",
            TypedErrnoFailure(113, "timeout while sending"),
        )
        val got = WinnV3NativeVerdictClassifier.fromEvidence(cause = nested)
        assertEquals(WinnV3NativeVerdict.ORDINARY_CONNECTIVITY, got)
        assertEquals(
            WinnV3OrdinaryNetworkFailureClass.HOST_UNREACHABLE,
            WinnV3OrdinaryNetworkEvidence.classifyThrowable(nested),
        )
    }

    @Test
    fun `authenticated ordinary unreachability flag never authorizes`() {
        val got = WinnV3NativeVerdictClassifier.fromEvidence(
            timedOut = true,
            positiveOrdinaryUnreachability = true,
        )
        assertEquals(WinnV3NativeVerdict.UNKNOWN_TERMINAL, got)
        assertEquals(-1L, got.awgXrayAuthorizationToken(41L))
    }

    @Test
    fun `timeout wins over a typed errno and publishes no token`() {
        val got = WinnV3NativeVerdictClassifier.fromEvidence(
            timedOut = true,
            ordinaryNetworkPosixErrno = 101,
        )
        assertEquals(WinnV3NativeVerdict.UNKNOWN_TERMINAL, got)
        assertEquals(-1L, got.awgXrayAuthorizationToken(12L))
    }

    @Test
    fun `typed ordinary pump evidence on a stopped bridge authorizes AWG then Xray cover`() {
        val generation = 99L
        for (failure in WinnV3OrdinaryNetworkFailureClass.entries) {
            val got = WinnV3NativeVerdictClassifier.fromEvidence(
                bridgeRunning = false,
                bridgeFailure = "Winn v3 outbound pump stopped: TypedErrnoFailure",
                ordinaryNetworkPosixErrno = failure.posixErrno,
                ordinaryNetworkFailure = failure,
                cause = TypedErrnoFailure(failure.posixErrno, "ENETUNREACH: network is unreachable"),
            )
            assertEquals(failure.name, WinnV3NativeVerdict.ORDINARY_CONNECTIVITY, got)
            assertEquals(failure.name, generation, got.awgXrayAuthorizationToken(generation))
            assertFalse(failure.name, got.securityRefusal)
        }
    }

    @Test
    fun `class-name pump collapse on a dead bridge remains unknown_terminal`() {
        val got = WinnV3NativeVerdictClassifier.fromEvidence(
            bridgeRunning = false,
            bridgeFailure = "Winn v3 outbound pump stopped: IOException",
            cause = IOException("ENETUNREACH: network is unreachable"),
        )
        assertEquals(WinnV3NativeVerdict.UNKNOWN_TERMINAL, got)
        assertEquals(-1L, got.awgXrayAuthorizationToken(99L))
    }

    @Test
    fun `mixed security still wins over a typed errno`() {
        val got = WinnV3NativeVerdictClassifier.fromEvidence(
            error = "wrong static key",
            ordinaryNetworkPosixErrno = 101,
            cause = NoRouteToHostException("network is unreachable"),
        )
        assertEquals(WinnV3NativeVerdict.TERMINAL_SECURITY, got)
        assertEquals(-1L, got.awgXrayAuthorizationToken(2L))
    }

    @Test
    fun `a live-bridge structured errno before the deadline authorizes ordinary cover`() {
        val outcome = stagedStart(
            inspectBridge = {
                WinnV3BridgeSnapshot(
                    running = true,
                    failure = null,
                    ordinaryNetworkPosixErrno = 101,
                )
            },
            readStatus = { """{"gate_state":"carrying","rx_packets":0,"rx_offered":0}""" },
        ).start()
        assertTrue(outcome is WinnV3StagedStart.Outcome.RefusedNotProven)
        val refused = outcome as WinnV3StagedStart.Outcome.RefusedNotProven
        assertEquals(WinnV3NativeVerdict.ORDINARY_CONNECTIVITY, refused.verdict)
        assertEquals(41L, refused.verdict.awgXrayAuthorizationToken(41L))
        assertFalse(refused.verdict.securityRefusal)
    }

    @Test
    fun `a stopped-bridge typed pump errno before the deadline authorizes ordinary cover`() {
        val outcome = stagedStart(
            inspectBridge = {
                WinnV3BridgeSnapshot(
                    running = false,
                    failure = "Winn v3 outbound pump stopped: TypedErrnoFailure",
                    ordinaryNetworkFailure = WinnV3OrdinaryNetworkFailureClass.NETWORK_UNREACHABLE,
                    ordinaryNetworkPosixErrno = 101,
                    cause = TypedErrnoFailure(101, "ENETUNREACH: network is unreachable"),
                )
            },
            readStatus = { """{"gate_state":"carrying","rx_packets":0,"rx_offered":0}""" },
        ).start()
        assertTrue(outcome is WinnV3StagedStart.Outcome.RefusedNotProven)
        val refused = outcome as WinnV3StagedStart.Outcome.RefusedNotProven
        assertEquals(WinnV3NativeVerdict.ORDINARY_CONNECTIVITY, refused.verdict)
        assertEquals(41L, refused.verdict.awgXrayAuthorizationToken(41L))
        assertFalse(refused.verdict.securityRefusal)
    }

    @Test
    fun `a live bridge proof timeout is unknown_terminal with no token`() {
        val outcome = stagedStart(
            inspectBridge = {
                WinnV3BridgeSnapshot(running = true, failure = null)
            },
            readStatus = { """{"gate_state":"carrying","rx_packets":0,"rx_offered":0}""" },
        ).start()
        assertTrue(outcome is WinnV3StagedStart.Outcome.RefusedNotProven)
        val refused = outcome as WinnV3StagedStart.Outcome.RefusedNotProven
        assertEquals(WinnV3NativeVerdict.UNKNOWN_TERMINAL, refused.verdict)
        assertEquals(-1L, refused.verdict.awgXrayAuthorizationToken(41L))
    }

    @Test
    fun `classifier source never substring-matches ordinary unreachability`() {
        val source = readStagedStartSource()
        assertFalse(source.contains("looksLikeOrdinaryUnreachability"))
        assertFalse(source.contains("ORDINARY_UNREACH_NEEDLES"))
        assertTrue(source.contains("WinnV3OrdinaryNetworkEvidence"))
        assertTrue(source.contains("WinnV3OrdinaryNetworkFailureClass"))
        assertTrue(source.contains("WinnV3ProtectedSocketErrno"))
        val classifier = source.substringAfter("internal object WinnV3NativeVerdictClassifier")
            .substringBefore("internal data class WinnV3EngineStatus")
        assertFalse(classifier.contains("\"enetunreach\""))
        assertFalse(classifier.contains("\"network is unreachable\""))
        assertFalse(classifier.contains("\"errno 101\""))
        assertFalse(
            classifier.contains("Even typed ENETUNREACH attached to a dead bridge"),
        )
        assertTrue(classifier.contains("WinnV3OrdinaryNetworkEvidence.classify"))
        val capture = source.substringAfter("internal object WinnV3ProtectedSocketErrno")
            .substringBefore("internal data class WinnV3BridgeSnapshot")
        assertFalse(capture.contains(".message"))
        assertTrue(capture.contains("typedErrno(thrown)"))
    }

    @Test
    fun `AWG then Xray grant is one-use, TTL bound, and order locked`() {
        WinnV3AwgXrayGrantStore.clear()
        assertTrue(
            WinnV3AwgXrayGrantStore.arm(
                startToken = 9L,
                startGeneration = 3L,
                selectionGeneration = "0123456789abcdef",
                failedV3Node = "v3-node",
                nowMs = 1_000L,
            ),
        )
        assertFalse(
            WinnV3AwgXrayGrantStore.consume(
                startToken = 9L,
                startGeneration = 3L,
                selectionGeneration = "0123456789abcdef",
                failedV3Node = "v3-node",
                exactV1Target = "v1-cover",
                requestedLeg = WinnV3CoverLeg.XRAY,
                nowMs = 1_001L,
            ),
        )
        assertTrue(
            WinnV3AwgXrayGrantStore.arm(
                startToken = 9L,
                startGeneration = 3L,
                selectionGeneration = "0123456789abcdef",
                failedV3Node = "v3-node",
                nowMs = 1_000L,
            ),
        )
        assertTrue(
            WinnV3AwgXrayGrantStore.consume(
                startToken = 9L,
                startGeneration = 3L,
                selectionGeneration = "0123456789abcdef",
                failedV3Node = "v3-node",
                exactV1Target = "v1-cover",
                requestedLeg = WinnV3CoverLeg.AWG,
                nowMs = 1_001L,
            ),
        )
        assertFalse(
            WinnV3AwgXrayGrantStore.consume(
                startToken = 9L,
                startGeneration = 3L,
                selectionGeneration = "0123456789abcdef",
                failedV3Node = "v3-node",
                exactV1Target = "other-node",
                requestedLeg = WinnV3CoverLeg.XRAY,
                nowMs = 1_002L,
            ),
        )
        assertTrue(
            WinnV3AwgXrayGrantStore.arm(
                startToken = 9L,
                startGeneration = 3L,
                selectionGeneration = "0123456789abcdef",
                failedV3Node = "v3-node",
                nowMs = 1_000L,
            ),
        )
        assertTrue(
            WinnV3AwgXrayGrantStore.consume(
                startToken = 9L,
                startGeneration = 3L,
                selectionGeneration = "0123456789abcdef",
                failedV3Node = "v3-node",
                exactV1Target = "v1-cover",
                requestedLeg = WinnV3CoverLeg.AWG,
                nowMs = 1_010L,
            ),
        )
        assertTrue(
            WinnV3AwgXrayGrantStore.consume(
                startToken = 9L,
                startGeneration = 3L,
                selectionGeneration = "0123456789abcdef",
                failedV3Node = "v3-node",
                exactV1Target = "v1-cover",
                requestedLeg = WinnV3CoverLeg.XRAY,
                nowMs = 1_011L,
            ),
        )
        assertFalse(
            WinnV3AwgXrayGrantStore.consume(
                startToken = 9L,
                startGeneration = 3L,
                selectionGeneration = "0123456789abcdef",
                failedV3Node = "v3-node",
                exactV1Target = "v1-cover",
                requestedLeg = WinnV3CoverLeg.XRAY,
                nowMs = 1_012L,
            ),
        )
    }

    @Test
    fun `hostile MethodChannel identities are refused`() {
        assertNull(WinnV3MethodIdentity.exactPositiveLong(true))
        assertNull(WinnV3MethodIdentity.exactPositiveLong("9"))
        assertNull(WinnV3MethodIdentity.exactPositiveLong(9.5))
        assertNull(WinnV3MethodIdentity.exactPositiveLong(0L))
        assertNull(WinnV3MethodIdentity.exactPositiveLong(-1L))
        assertNull(WinnV3MethodIdentity.exactPositiveLong(null))
        assertEquals(9L, WinnV3MethodIdentity.exactPositiveLong(9L))
        assertNull(WinnV3MethodIdentity.exactSelectionGeneration(true))
        assertNull(WinnV3MethodIdentity.exactSelectionGeneration(12))
        assertNull(WinnV3MethodIdentity.exactSelectionGeneration("short"))
        assertNull(WinnV3MethodIdentity.exactNodeSlug("auto"))
        assertNull(WinnV3MethodIdentity.exactNodeSlug(true))
        assertNull(WinnV3MethodIdentity.exactNodeSlug(1))
    }

    private class TypedErrnoFailure(
        val errno: Int,
        message: String,
    ) : Exception(message)

    private val gateway = WinnV3Route("203.0.113.9", 32)

    private fun stagedStart(
        inspectBridge: () -> WinnV3BridgeSnapshot,
        readStatus: () -> String,
    ): WinnV3StagedStart {
        var t = 0L
        return WinnV3StagedStart(
            bootstrap = WinnV3Posture.bootstrap("10.8.1.3", 1443, "10.8.1.1", gateway),
            promoted = WinnV3Posture.promotion(
                innerAddress = "10.8.1.3",
                innerMtu = 1443,
                routes = listOf(WinnV3Route("0.0.0.0", 0)),
                dnsServers = listOf("10.8.1.53"),
                innerNextHop = "10.8.1.1",
                outerTransportExclusion = gateway,
                ipv6SinkAddress = "fd00:d951:0001::1",
            ),
            proofDeadlineMs = 2_000L,
            pollIntervalMs = 100L,
            install = {},
            readStatus = readStatus,
            inspectBridge = inspectBridge,
            tearDown = {},
            nowMs = { t },
            sleepMs = { t += it },
        )
    }

    private fun readStagedStartSource(): String {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            val candidate = File(
                dir,
                "android/app/src/main/kotlin/org/winsvpn/app/WinnV3StagedStart.kt",
            )
            if (candidate.isFile) return candidate.readText()
            val here = File(dir, "app/src/main/kotlin/org/winsvpn/app/WinnV3StagedStart.kt")
            if (here.isFile) return here.readText()
            dir = dir.parentFile
        }
        throw AssertionError("could not locate WinnV3StagedStart.kt")
    }
}
