package org.winsvpn.devicecheck

import android.app.Instrumentation
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import java.security.MessageDigest

/**
 * On-device app-identity / signing gate for the Winn test variants.
 *
 * Run it from the host with:
 *
 *   adb -s ZY22GTV6Z3 shell am instrument -w -r \
 *       org.winsvpn.devicecheck/org.winsvpn.devicecheck.AppIdSigningCheck
 *
 * The manifest pins android:targetPackage to org.winsvpn.app.debug, so this
 * instrumentation is injected into that process and getTargetContext() is the
 * package it verifies. Reading ANOTHER package's signature from a normal app is
 * restricted since API 28, so this check is deliberately self-targeted: it only
 * asserts signing facts it is permitted to read, and FAILS CLOSED (never passes)
 * if the signature cannot be read.
 *
 * Two gates, each reported as a boolean in the result bundle:
 *   app_id_ok        true iff the target id is org.winsvpn.app.debug or
 *                    org.winsvpn.app.test.
 *   no_release_key   true iff the target's signing certificate SHA-256 is NOT
 *                    the release key 542ea1881a4807643e071d4ee6f961f1cf5045412394943b8ad9896fd7e7adcb.
 *                    Unreadable/absent signature -> false (fail closed).
 */
class AppIdSigningCheck : Instrumentation() {

    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        start()
    }

    override fun onStart() {
        val results = Bundle()
        val target = try { targetContext.packageName } catch (_: Exception) { "UNKNOWN" }

        results.putString(KEY_DEVICE_MODEL, android.os.Build.MODEL)
        results.putString(KEY_DEVICE_SERIAL_HINT, deviceSerial)
        results.putString(KEY_TARGET, target)
        results.putString(KEY_RELEASE_KEY, RELEASE_KEY_SHA256)

        val appIdOk = target == APP_DEBUG_ID || target == APP_TEST_ID
        results.putBoolean(APP_ID_OK, appIdOk)

        val certSha256 = readOwnCertSha256(target)
        results.putString(KEY_CERT, certSha256 ?: "UNREADABLE")
        val noReleaseKey = certSha256 != null && !certSha256.equals(RELEASE_KEY_SHA256, ignoreCase = true)
        results.putBoolean(NO_RELEASE_KEY, noReleaseKey)

        try {
            val pm = targetContext.packageManager
            val pkgs = pm.getInstalledPackages(0).mapNotNull { it.packageName }
                .filter { it.startsWith("org.winsvpn.") || it.startsWith("com.winsvpn.") }
            results.putString(KEY_ENUMERATED, pkgs.joinToString(","))
        } catch (_: Exception) {
            results.putString(KEY_ENUMERATED, "UNREADABLE")
        }

        finish(android.app.Activity.RESULT_OK, results)
    }

    private fun readOwnCertSha256(pkg: String): String? {
        val pm = targetContext.packageManager
        val certBytes: ByteArray? = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
                val signing = info.signingInfo
                if (signing != null) {
                    val certs = if (signing.hasMultipleSigners()) signing.apkContentsSigners else signing.signingCertificateHistory
                    certs?.firstOrNull()?.toByteArray()
                } else null
            } else {
                @Suppress("DEPRECATION")
                val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES)
                info.signatures?.firstOrNull()?.toByteArray()
            }
        } catch (_: Exception) { null } ?: try {
            @Suppress("DEPRECATION")
            val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES)
            info.signatures?.firstOrNull()?.toByteArray()
        } catch (_: Exception) { null }

        if (certBytes == null) return null
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(certBytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    private val deviceSerial: String
        get() = try { android.os.Build.getSerial() } catch (_: Exception) { android.os.Build.UNKNOWN }

    companion object {
        const val APP_DEBUG_ID = "org.winsvpn.app.debug"
        const val APP_TEST_ID = "org.winsvpn.app.test"
        const val RELEASE_KEY_SHA256 = "542ea1881a4807643e071d4ee6f961f1cf5045412394943b8ad9896fd7e7adcb"
        const val APP_ID_OK = "app_id_ok"
        const val NO_RELEASE_KEY = "no_release_key"
        const val KEY_DEVICE_MODEL = "device_model"
        const val KEY_DEVICE_SERIAL_HINT = "device_serial"
        const val KEY_TARGET = "target_pkg"
        const val KEY_RELEASE_KEY = "release_key_sha256"
        const val KEY_CERT = "cert_sha256"
        const val KEY_ENUMERATED = "enumerated"
    }
}
