package org.winsvpn.app

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class AwgSocketProtectionTest {
    @Test
    fun `a refused protect rolls back and cannot continue startup`() {
        val attempted = mutableListOf<Int>()
        var rollbacks = 0
        var startupContinued = false

        val failure = try {
            AwgSocketProtection.protectOrRollback(
                sockets = { listOf(AwgSocket("IPv4", 41)) },
                protect = { fd ->
                    attempted += fd
                    false
                },
                rollback = { rollbacks++ },
            )
            startupContinued = true
            null
        } catch (failure: IOException) {
            failure
        }

        assertNotNull("a false protect result must refuse startup", failure)
        assertTrue(failure!!.message!!.contains("refused"))
        assertFalse("startup must not continue past failed protection", startupContinued)
        assertEquals(listOf(41), attempted)
        assertEquals("the published native engine must be rolled back once", 1, rollbacks)
    }

    @Test
    fun `successful protection allows startup to continue without rollback`() {
        val attempted = mutableListOf<Int>()
        var rollbacks = 0
        var startupContinued = false

        AwgSocketProtection.protectOrRollback(
            sockets = {
                listOf(
                    AwgSocket("IPv4", 41),
                    AwgSocket("IPv6", 42),
                )
            },
            protect = { fd ->
                attempted += fd
                true
            },
            rollback = { rollbacks++ },
        )
        startupContinued = true

        assertTrue(startupContinued)
        assertEquals(listOf(41, 42), attempted)
        assertEquals(0, rollbacks)
    }

    @Test
    fun `an unavailable address family is skipped while an available socket is protected`() {
        val attempted = mutableListOf<Int>()
        val unavailable = mutableListOf<String>()

        AwgSocketProtection.protectOrRollback(
            sockets = {
                listOf(
                    AwgSocket("IPv4", 41),
                    AwgSocket("IPv6", -1),
                )
            },
            protect = { fd ->
                attempted += fd
                true
            },
            rollback = { throw AssertionError("successful protection must not roll back") },
            onUnavailable = { label -> unavailable += label },
        )

        assertEquals(listOf(41), attempted)
        assertEquals(listOf("IPv6"), unavailable)
    }

    @Test
    fun `an exception from protect is wrapped rolled back and cannot continue`() {
        val platformFailure = SecurityException("VPN permission was revoked")
        var rollbacks = 0
        var startupContinued = false

        val failure = try {
            AwgSocketProtection.protectOrRollback(
                sockets = { listOf(AwgSocket("IPv4", 41)) },
                protect = { throw platformFailure },
                rollback = { rollbacks++ },
            )
            startupContinued = true
            null
        } catch (failure: IOException) {
            failure
        }

        assertNotNull(failure)
        assertSame(platformFailure, failure!!.cause)
        assertFalse(startupContinued)
        assertEquals(1, rollbacks)
    }

    @Test
    fun `when all carrier sockets are unavailable startup fails and rolls back`() {
        var rollbacks = 0
        var startupContinued = false

        val failure = try {
            AwgSocketProtection.protectOrRollback(
                sockets = {
                    listOf(
                        AwgSocket("IPv4", -1),
                        AwgSocket("IPv6", -1),
                    )
                },
                protect = { true },
                rollback = { rollbacks++ },
            )
            startupContinued = true
            null
        } catch (failure: IOException) {
            failure
        }

        assertNotNull("all sockets unavailable must fail", failure)
        assertTrue(failure!!.message!!.contains("No AmneziaWG carrier socket was available to protect"))
        assertFalse(startupContinued)
        assertEquals(1, rollbacks)
    }
}
