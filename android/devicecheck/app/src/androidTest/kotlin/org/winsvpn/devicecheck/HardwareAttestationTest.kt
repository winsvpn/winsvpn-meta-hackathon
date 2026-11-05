package org.winsvpn.devicecheck

import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Arrays

/**
 * On-device hardware key attestation checks, run by connectedCheck against the
 * real phone (ZY22GTV6Z3).
 *
 * The point of the release-keystore-family signing in this module is that the
 * installed devicecheck APK is signed with the same family of key as the
 * release app, so that Android Key Attestation -- which binds an attestation
 * certificate to the signing certificate of the app that requested it -- yields
 * an attestation chain anchored to that signing family instead of to the
 * ephemeral Android debug key. These tests prove the attestation pipeline runs
 * on-device (a real attestation certificate is produced) and that it genuinely
 * binds to this app's installed signing certificate.
 */
@RunWith(AndroidJUnit4::class)
class HardwareAttestationTest {

    private val keystore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    // Android Key Attestation certificate extension OID.
    private val attestationOid = "1.3.6.1.4.1.11129.2.1.17"

    @Test
    fun attestationChain_IsProducedForAttestationRequestedKey() {
        val alias = newAlias()
        try {
            generateAttestedKey(alias, byteArrayOf(0x01, 0x02, 0x03))
            val chain = keystore.getCertificateChain(alias)
            assertNotNull("attestation certificate chain must not be null", chain)
            assertTrue("attestation certificate chain must not be empty", chain!!.isNotEmpty())
        } finally {
            delete(alias)
        }
    }

    @Test
    fun leafCarriesAndroidKeyAttestationExtension() {
        val alias = newAlias()
        try {
            generateAttestedKey(alias, byteArrayOf(0x11, 0x22))
            val leaf = attestationCertificate(alias)
            val ext = leaf.getExtensionValue(attestationOid) as? ByteArray
            assertNotNull(
                "leaf certificate must carry the Android key-attestation extension",
                ext,
            )
            assertTrue("attestation extension must carry data", ext!!.isNotEmpty())
        } finally {
            delete(alias)
        }
    }

    @Test
    fun attestationChallenge_EchoesRequestedBytes() {
        val alias = newAlias()
        try {
            val challenge = ByteArray(32) { it.toByte() }
            generateAttestedKey(alias, challenge)
            val leaf = attestationCertificate(alias)
            val ext = leaf.getExtensionValue(attestationOid) as? ByteArray
                ?: throw AssertionError("no attestation extension")
            val inside = extensionOctets(ext)
            val roundTripped = readAttestationChallenge(inside)
            assertTrue(
                "attestation challenge must round-trip from the Keystore",
                Arrays.equals(challenge, roundTripped),
            )
        } finally {
            delete(alias)
        }
    }

    @Test
    fun attestation_BindsToInstalledAppSigningCertificate() {
        val alias = newAlias()
        try {
            generateAttestedKey(alias, byteArrayOf(0x42))
            val ext = attestationCertificate(alias).getExtensionValue(attestationOid) as? ByteArray
                ?: throw AssertionError("no attestation extension")
            val inside = extensionOctets(ext)
            val signer = installedSignerSha256()
            assertTrue(
                "attestation must embed this app's signing-cert digest (release-keystore family)",
                containsSubsequence(inside, signer),
            )
        } finally {
            delete(alias)
        }
    }

    // --- helpers ---

    private fun newAlias(): String = "attest-test-" + System.nanoTime()

    private fun generateAttestedKey(alias: String, challenge: ByteArray) {
        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .build()
        gen.initialize(spec)
        gen.generateKeyPair()
    }

    private fun attestationCertificate(alias: String): X509Certificate {
        val chain = keystore.getCertificateChain(alias) as? Array<*>
            ?: throw AssertionError("attestation certificate chain is null")
        assertTrue("attestation chain must not be empty", chain.isNotEmpty())
        val leaf = chain.firstOrNull() ?: fail("attestation chain has no leaf")
        assertTrue("leaf is not an X509 certificate", leaf is X509Certificate)
        @Suppress("UNCHECKED_CAST")
        return leaf as X509Certificate
    }

    private fun installedSignerSha256(): ByteArray {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        val pm = ctx.packageManager
        val md = MessageDigest.getInstance("SHA-256")
        val certs: ByteArray? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            info.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNATURES)
                .signatures?.firstOrNull()?.toByteArray()
        }
        val c = certs ?: throw AssertionError("could not read installed signing certificate")
        return md.digest(c)
    }

    // Returns the DER-encoded content inside the extension's outer OCTET STRING.
    private fun extensionOctets(v: ByteArray): ByteArray {
        val t = readTlv(v, 0)
        return v.copyOfRange(t.contentStart, t.end)
    }

    // The first member of the attestation cert is [0] EXPLICIT OCTET STRING.
    private fun readAttestationChallenge(b: ByteArray): ByteArray {
        val seq = readTlv(b, 0)
        val tag0 = readTlv(b, seq.contentStart)
        val value = readTlv(b, tag0.contentStart)
        return b.copyOfRange(value.contentStart, value.end)
    }

    private class Tlv(val tag: Int, val contentStart: Int, val end: Int)

    private fun readTlv(b: ByteArray, p: Int): Tlv {
        val tag = b[p].toInt() and 0xFF
        var q = p + 1
        var len = b[q].toInt() and 0xFF
        var lenBytes = 1
        if ((len and 0x80) != 0) {
            val n = len and 0x7F
            var l = 0
            for (i in 0 until n) {
                l = (l shl 8) or (b[q + 1 + i].toInt() and 0xFF)
            }
            len = l
            lenBytes = 1 + n
        }
        val contentStart = q + lenBytes
        return Tlv(tag, contentStart, contentStart + len)
    }

    private fun containsSubsequence(hay: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty()) return true
        if (needle.size > hay.size) return false
        outer@ for (i in 0..hay.size - needle.size) {
            for (j in needle.indices) {
                if (hay[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }

    private fun delete(alias: String) {
        try {
            keystore.deleteEntry(alias)
        } catch (_: Exception) {
            // best effort
        }
    }
}
