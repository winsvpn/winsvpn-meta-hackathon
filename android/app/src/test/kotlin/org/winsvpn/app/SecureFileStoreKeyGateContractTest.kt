package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Source contract (Android Keystore cannot run on the JVM): whether the
 * secure-files key exists is decided by KeyStore.getKey, never by
 * containsAlias. On Keystore 2, containsAlias answers false for any Keystore
 * error, and the generation path would then replace the existing key. The
 * containsAlias ban covers getOrCreateKey only: the account reset path may
 * ask containsAlias, because it deletes the alias and then checks it is gone.
 */
class SecureFileStoreKeyGateContractTest {
    @Test
    fun `the key generator is reached only when getKey reports no key`() {
        val source = sourceFile("SecureFileStore.kt").readText()
        val start = source.indexOf("private fun getOrCreateKey()")
        assertTrue("getOrCreateKey must exist", start >= 0)
        // The member ends at the first closing brace at class-member indentation.
        val end = source.indexOf("\n    }\n", start)
        assertTrue("getOrCreateKey must end inside the class", end > start)
        val body = source.substring(start, end)
        assertFalse("containsAlias must not gate key generation", body.contains("containsAlias("))
        assertEquals(1, Regex("""keyStore\.getKey\(keyAlias, null\)""").findAll(body).count())
        val lookup = body.indexOf("keyStore.getKey(keyAlias, null)")
        val presentCheck = body.indexOf("if (stored != null)")
        val generator = body.indexOf("KeyGenerator.getInstance(")
        assertTrue(lookup in 0 until presentCheck)
        assertTrue(presentCheck in 0 until generator)
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
