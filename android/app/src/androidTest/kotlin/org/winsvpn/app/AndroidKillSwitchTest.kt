package org.winsvpn.app

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * On-device proof that [AndroidKillSwitch] blocks cleartext egress while the VPN
 * is claimed up. Runs against the physical Motorola (ZY22GTV6Z3) under
 * `connectedDebugAndroidTest` for `org.winsvpn.app.debug`.
 *
 * The mechanism under test is [AndroidKillSwitch.establishBlockingInterface]:
 * it brings up a `VpnService` tun that captures the whole route table (IPv4
 * default + the IPv6 fail-closed sink) with no engine draining it, so every
 * packet that would otherwise egress on the physical interface is absorbed by
 * the tun and dropped. That is the "VPN claimed up, nothing egressing" posture
 * -- the tunnel looks established to the OS while actually blocking.
 *
 * It is scored as a real differential, not an assertion on state:
 *   - CONTROL GREEN (no mutation): cleartext egress works before the block.
 *   - the blocking interface is established and holds a tun descriptor.
 *   - POSITIVE / PROOF: while the interface is up, cleartext egress is blocked.
 *   - CONTROL RECOVERY: after teardown, cleartext egress works again.
 * No single positive assertion here could pass if the block were a no-op: the
 * blocked window is asserted by the NEGATIVE (egress must FAIL while up), which
 * is exactly the shape this codebase's own catalogue says survives when it is
 * omitted.
 *
 * Environmental preconditions, asserted fail-closed with a readable message:
 * `org.winsvpn.app.debug` must already be the prepared VPN package
 * (ACTIVATE_VPN appop `allow`, then DevVpnPrepareActivity) and the phone must
 * have real cleartext connectivity for the two WORK controls to be meaningful.
 */
@RunWith(AndroidJUnit4::class)
class AndroidKillSwitchTest {

    private val ctx: Context = ApplicationProvider.getApplicationContext<Context>() ?: error("no app context")
    private val tag = "WinsKSInstrumented"

    private companion object {
        /** The cleartext probe target: a public resolver reached as a raw IP literal. */
        const val PROBE_IP = "8.8.8.8"
        const val PROBE_PORT = 53
        const val ESTABLISH_TIMEOUT_MS = 12_000L
        const val EGRESS_TIMEOUT_MS = 4_000
    }

    @Test
    fun blockingInterface_stopsCleartextEgress_andTeardownRestoresIt() {
        // Fail-closed precondition: must already be the prepared VPN package.
        val consent = VpnService.prepare(ctx)
        assertNull(
            "org.winsvpn.app.debug is not the prepared VPN package; grant the " +
                "ACTIVATE_VPN appop then run DevVpnPrepareActivity before connectedDebugAndroidTest. " +
                "prepare() returned: $consent",
            consent,
        )

        try {
            // CONTROL GREEN: the probe reaches the network with no block in place.
            assertEgress(exactly = true, phase = "pre-block control")

            // Bring up the kill switch's blocking interface via a real VpnService.
            val started = ctx.startService(
                Intent(ctx, KillSwitchBlockService::class.java)
                    .setAction(KillSwitchBlockService.ACTION_ARM_BLOCK),
            )
            assertNotNull("must be able to start the kill-switch test service", started)

            // The VPN is now claimed up: the interface returned a real tun fd.
            assertTrue(
                "blocking interface must come up within ${ESTABLISH_TIMEOUT_MS}ms; error=" +
                    KillSwitchBlockService.lastError,
                awaitEstablished(),
            )
            assertNull(
                "blocking interface arm reported an error: ${KillSwitchBlockService.lastError}",
                KillSwitchBlockService.lastError,
            )
            assertNotNull(
                "establishBlockingInterface must return a real tun descriptor (VPN claimed up)",
                KillSwitchBlockService.lastEstablishment,
            )

            // PROOF (the negative): with the tun capturing the routes, cleartext
            // must NOT egress. If this probe succeeds the block is a no-op and
            // the kill switch is not blocking.
            assertEgress(exactly = false, phase = "while blocking interface up")
        } finally {
            // Tear down unconditionally so the owner's phone is left online.
            tearDown()
        }

        // CONTROL RECOVERY: after teardown the same probe egresses again.
        assertEgress(exactly = true, phase = "after teardown")
    }

    private fun tearDown() {
        try {
            ctx.stopService(Intent(ctx, KillSwitchBlockService::class.java))
        } catch (_: Exception) {
        }
        // stopService destroys the service, whose onDestroy closes the tun (the
        // framework also revokes the VpnService, restoring the device routes).
        KillSwitchBlockService.releaseMemoryPfd()
    }

    private fun awaitEstablished(): Boolean {
        val deadline = System.currentTimeMillis() + ESTABLISH_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            if (KillSwitchBlockService.lastEstablishment != null) return true
            if (KillSwitchBlockService.lastError != null) return true
            Thread.sleep(100)
        }
        return KillSwitchBlockService.lastEstablishment != null ||
            KillSwitchBlockService.lastError != null
    }

    /** Asserts cleartext egress either works ([exactly]=true) or is blocked (false). */
    private fun assertEgress(exactly: Boolean, phase: String) {
        val works = cleartextEgressWorks()
        Log.i(tag, "$phase: cleartext egress works=$works (expected=$exactly)")
        if (exactly) {
            assertTrue(
                "$phase: expected cleartext egress to WORK but it did not reach " +
                    "$PROBE_IP:$PROBE_PORT",
                works,
            )
        } else {
            assertFalse(
                "$phase: expected cleartext egress to be BLOCKED but a packet reached " +
                    "$PROBE_IP:$PROBE_PORT while the blocking interface was up",
                works,
            )
        }
    }

    /**
     * A cleartext UDP/DNS probe to [PROBE_IP]:[PROBE_PORT] using a raw socket and
     * an IP literal (no hostname resolution, so nothing but the routed packet can
     * cause a failure or success). Returns true only when a reply arrives.
     */
    private fun cleartextEgressWorks(): Boolean {
        return try {
            DatagramSocket().use { socket ->
                socket.soTimeout = EGRESS_TIMEOUT_MS
                val query = dnsQuery()
                val target = InetAddress.getByName(PROBE_IP)
                socket.send(DatagramPacket(query, query.size, InetSocketAddress(target, PROBE_PORT)))
                val reply = DatagramPacket(ByteArray(1500), 1500)
                socket.receive(reply)
                reply.length > 0 && (reply.data[0].toInt() and 0xFF) == (query[0].toInt() and 0xFF)
            }
        } catch (_: Exception) {
            false
        }
    }

    /** Builds a minimal one-question DNS query for `dns.google` with a random ID. */
    private fun dnsQuery(): ByteArray {
        val name = "dns.google"
        val out = java.io.ByteArrayOutputStream()
        val id = (System.nanoTime().toInt() and 0xFFFF)
        // header
        out.write((id ushr 8) and 0xFF); out.write(id and 0xFF)
        out.write(0x01); out.write(0x00) // flags: RD
        out.write(0x00); out.write(0x01) // QDCOUNT
        out.write(0x00); out.write(0x00) // ANCOUNT
        out.write(0x00); out.write(0x00) // NSCOUNT
        out.write(0x00); out.write(0x00) // ARCOUNT
        // question: labels
        for (label in name.split(".")) {
            out.write(label.length)
            for (c in label) out.write(c.code)
        }
        out.write(0x00)
        out.write(0x00); out.write(0x01) // QTYPE A
        out.write(0x00); out.write(0x01) // QCLASS IN
        return out.toByteArray()
    }
}
