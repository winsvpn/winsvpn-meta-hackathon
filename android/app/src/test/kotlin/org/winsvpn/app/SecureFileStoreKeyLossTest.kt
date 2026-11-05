package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Only a provably permanent key loss may delete the secure-files alias. The
 * classification is pure; the call site is pinned by source contract because
 * Android Keystore cannot run on the JVM.
 */
class SecureFileStoreKeyLossTest {
    @Test
    fun `the corrupted-key code is the platform's`() {
        assertEquals(
            android.security.KeyStoreException.ERROR_KEY_CORRUPTED,
            SecureFileStore.PLATFORM_KEY_CORRUPTED,
        )
    }

    @Test
    fun `only a causeless or corrupted-key loss is permanent`() {
        // engineGetKey converts KEY_PERMANENTLY_INVALIDATED without a cause.
        assertTrue(SecureFileStore.keyLossIsPermanent(hasCause = false, platformErrorCode = null))
        assertTrue(
            SecureFileStore.keyLossIsPermanent(
                hasCause = true,
                platformErrorCode = android.security.KeyStoreException.ERROR_KEY_CORRUPTED,
            ),
        )
        // A lost Keystore daemon: KeyStore2 throws SYSTEM_ERROR.
        assertFalse(
            SecureFileStore.keyLossIsPermanent(
                hasCause = true,
                platformErrorCode = android.security.KeyStoreException.ERROR_INTERNAL_SYSTEM_ERROR,
            ),
        )
        for (code in listOf(
            android.security.KeyStoreException.ERROR_KEYSTORE_FAILURE,
            android.security.KeyStoreException.ERROR_KEYSTORE_UNINITIALIZED,
            android.security.KeyStoreException.ERROR_USER_AUTHENTICATION_REQUIRED,
            android.security.KeyStoreException.ERROR_PERMISSION_DENIED,
            android.security.KeyStoreException.ERROR_OTHER,
        )) {
            assertFalse("code $code", SecureFileStore.keyLossIsPermanent(hasCause = true, platformErrorCode = code))
        }
        // Below API 33 the code is not public: a cause alone keeps the alias.
        assertFalse(SecureFileStore.keyLossIsPermanent(hasCause = true, platformErrorCode = null))
    }

    @Test
    fun `the alias is deleted only after the classification`() {
        val source = sourceFile("SecureFileStore.kt").readText()
        val catchStart = source.indexOf("} catch (e: java.security.UnrecoverableKeyException) {")
        assertTrue(catchStart >= 0)
        val guard = source.indexOf(
            "if (!keyLossIsPermanent(e.cause != null, platformErrorCodeOf(e.cause))) throw e",
            catchStart,
        )
        val delete = source.indexOf("keyStore.deleteEntry(keyAlias)", catchStart)
        assertTrue(guard in catchStart until delete)
        assertEquals(
            1,
            Regex("""catch \(e: java\.security\.UnrecoverableKeyException\)""").findAll(source).count(),
        )
    }

    private fun sourceFile(name: String): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            val candidate = File(dir, "android/app/src/main/kotlin/org/winsvpn/app/$name")
            if (candidate.isFile) return candidate
            val here = File(dir, "app/src/main/kotlin/org/winsvpn/app/$name")
            if (here.isFile) return here
            dir = dir.parentFile
        }
        throw AssertionError("could not locate $name")
    }
}
