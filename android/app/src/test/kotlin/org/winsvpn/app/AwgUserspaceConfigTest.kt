package org.winsvpn.app

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class AwgUserspaceConfigTest {

    private val privateKey = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
    private val publicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    private val privateHex = "c809f3e5317e9575c9b5ed78b638b7ce530dabe85ddab614220241801ddf0669"
    private val publicHex = "0000000000000000000000000000000000000000000000000000000000000000"

    private val dartShapedQuick = """
        [Interface]
        PrivateKey = $privateKey
        Address = 10.8.1.3/32
        MTU = 1280
        DNS = 10.8.1.1
        Jc = 2
        Jmin = 10
        Jmax = 50
        S1 = 16
        S2 = 80
        S3 = 16
        S4 = 0
        H1 = 11
        H2 = 22
        H3 = 33
        H4 = 44

        [Peer]
        PublicKey = $publicKey
        Endpoint = 127.0.0.1:1
        AllowedIPs = 0.0.0.0/0, ::/0
        PersistentKeepalive = 25
    """.trimIndent()

    @Test
    fun dartShapedIniBecomesOfficialUserspace() {
        val userspace = AwgUserspaceConfig.fromQuick(dartShapedQuick)
        assertEquals(
            """
            private_key=$privateHex
            jc=2
            jmin=10
            jmax=50
            s1=16
            s2=80
            s3=16
            h1=11
            h2=22
            h3=33
            h4=44
            replace_peers=true
            public_key=$publicHex
            endpoint=127.0.0.1:1
            allowed_ip=0.0.0.0/0
            allowed_ip=::/0
            persistent_keepalive_interval=25
            """.trimIndent() + "\n",
            userspace,
        )
        assertFalse(userspace.contains("s4="))
        assertFalse(userspace.contains("Address"))
        assertFalse(userspace.contains("10.8.1.3"))
    }

    @Test
    fun alreadyUserspaceDocumentsPassThrough() {
        val uapi = "private_key=$privateHex\npublic_key=$publicHex\n"
        assertEquals(uapi, AwgUserspaceConfig.fromQuick(uapi))
        assertEquals(uapi, AwgUserspaceConfig.peerUpdateFromQuick(uapi))
    }

    @Test
    fun livePeerUpdateOmitsInterfaceAndReplacePeers() {
        val update = AwgUserspaceConfig.peerUpdateFromQuick(dartShapedQuick)
        assertFalse(update.contains("private_key="))
        assertFalse(update.contains("replace_peers="))
        assertTrue(update.startsWith("public_key=$publicHex\n"))
        assertTrue(update.contains("endpoint=127.0.0.1:1\n"))
    }

    @Test
    fun unknownInterfaceKeyIsRefused() {
        try {
            AwgUserspaceConfig.fromQuick(
                dartShapedQuick.replace("MTU = 1280", "MTU = 1280\nNotARealKey = 1"),
            )
            fail("unknown Interface keys must fail closed")
        } catch (error: IOException) {
            assertTrue(error.message!!.contains("unknown [Interface] attribute notarealkey"))
        }
    }

    @Test
    fun extraSectionsAreRefused() {
        try {
            AwgUserspaceConfig.fromQuick("$dartShapedQuick\n[xray]\nenabled = true\n")
            fail("leftover non-AWG sections must fail closed")
        } catch (error: IOException) {
            assertTrue(error.message!!.contains("unsupported section"))
        }
    }

    @Test
    fun parseErrorsNeverEchoKeyMaterial() {
        val needle = privateKey.take(16).lowercase()
        val inputs = listOf(
            "PrivateKey = $privateKey\n$dartShapedQuick",
            dartShapedQuick.replace("PrivateKey = $privateKey", "PrivateKey $privateKey"),
            "[Interface $privateKey\n$dartShapedQuick",
            "[$privateKey]\n$dartShapedQuick",
        )
        for (input in inputs) {
            try {
                AwgUserspaceConfig.fromQuick(input)
                fail("must refuse: $input")
            } catch (e: IOException) {
                assertFalse(e.message!!, e.message!!.lowercase().contains(needle))
            }
        }
    }

    @Test
    fun officialBoolKeysBecomeUapiOneOrZero() {
        val userspace = AwgUserspaceConfig.fromQuick(
            """
            [Interface]
            PrivateKey = $privateKey
            RandomTrailers = on
            DisableCookies = off
            [Peer]
            PublicKey = $publicKey
            AllowedIPs = 0.0.0.0/0
            """.trimIndent(),
        )
        assertTrue(userspace.contains("random_trailers=1\n"))
        assertTrue(userspace.contains("disable_cookies=0\n"))
    }

    @Test
    fun headerProtectionKeyIsHex() {
        val userspace = AwgUserspaceConfig.fromQuick(
            """
            [Interface]
            PrivateKey = $privateKey
            HeaderProtectionKey = $publicKey
            [Peer]
            PublicKey = $publicKey
            AllowedIPs = 0.0.0.0/0
            """.trimIndent(),
        )
        assertTrue(userspace.contains("header_protection_key=$publicHex\n"))
    }

    @Test
    fun refusesHostnameEndpointBeforeNativeConversion() {
        try {
            AwgUserspaceConfig.fromQuick(
                """
                [Interface]
                PrivateKey = $privateKey
                [Peer]
                PublicKey = $publicKey
                Endpoint = carrier.example:9210
                AllowedIPs = 0.0.0.0/0
                """.trimIndent(),
            )
            fail("a hostname must be pinned before establish")
        } catch (error: IOException) {
            assertTrue(error.message!!.contains("must be a numeric address"))
        }
    }

    @Test
    fun preservesBracketedIpv6Endpoint() {
        val userspace = AwgUserspaceConfig.fromQuick(
            """
            [Interface]
            PrivateKey = $privateKey
            [Peer]
            PublicKey = $publicKey
            Endpoint = [2001:db8::1]:51820
            AllowedIPs = 0.0.0.0/0
            """.trimIndent(),
        )
        assertTrue(userspace.contains("endpoint=[2001:db8::1]:51820\n"))
    }

    @Test
    fun numericEndpointIsPreservedOnRepeatedInvocations() {
        val first = AwgUserspaceConfig.fromQuick(
            """
            [Interface]
            PrivateKey = $privateKey
            [Peer]
            PublicKey = $publicKey
            Endpoint = 192.168.4.36:9210
            AllowedIPs = 0.0.0.0/0
            """.trimIndent(),
        )
        val second = AwgUserspaceConfig.fromQuick(
            """
            [Interface]
            PrivateKey = $privateKey
            [Peer]
            PublicKey = $publicKey
            Endpoint = 192.168.4.36:9210
            AllowedIPs = 0.0.0.0/0
            """.trimIndent(),
        )
        assertTrue(first.contains("endpoint=192.168.4.36:9210\n"))
        assertEquals(first, second)
    }
}
