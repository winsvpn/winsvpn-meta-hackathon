package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * FINAL4 Turn 3 (app-speed lane, pre-existing at 705bedd): SecureFileStore
 * opened the reset directories with OsConstants.O_DIRECTORY, which is not in
 * the public API stubs, so the app did not compile. The replacement keeps the
 * refusal of a non-directory with public API only.
 */
class SecureFileStoreDirectorySyncContractTest {

    @Test
    fun `every android system member the app names is public API`() {
        val loader = javaClass.classLoader
        val constants = Class.forName("android.system.OsConstants", false, loader)
        val os = Class.forName("android.system.Os", false, loader)
        fun names(type: Class<*>): Set<String> =
            (type.fields.map { it.name } + type.methods.map { it.name }).toSet()
        val publicConstants = names(constants)
        val publicOs = names(os)
        val missing = sortedSetOf<String>()
        var seen = 0
        for (file in mainSources()) {
            val text = file.readText()
            for (match in Regex("\\bOsConstants\\.([A-Za-z_][A-Za-z0-9_]*)").findAll(text)) {
                seen++
                if (match.groupValues[1] !in publicConstants) {
                    missing += "${file.name}: OsConstants.${match.groupValues[1]}"
                }
            }
            for (match in Regex("(?<![A-Za-z0-9_.])Os\\.([a-z][A-Za-z0-9]*)\\(").findAll(text)) {
                seen++
                if (match.groupValues[1] !in publicOs) {
                    missing += "${file.name}: Os.${match.groupValues[1]}"
                }
            }
        }
        assertTrue("no android.system reference was found", seen > 0)
        assertEquals(emptySet<String>(), missing)
    }

    @Test
    fun `the reset directory sync refuses anything but a directory`() {
        val body = source("SecureFileStore.kt")
            .substringAfter("private fun syncResetDirectory(path: Path) {")
            .substringBefore("private fun eraseForAccountReset(")
        assertFalse(body.contains("O_DIRECTORY"))
        val open = body.substringAfter("Os.open(").substringBefore("try {")
        for (flag in listOf("O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK", "O_NOCTTY", "O_CLOEXEC")) {
            assertTrue(flag, open.contains("OsConstants.$flag"))
        }
        val check = "if (!OsConstants.S_ISDIR(Os.fstat(fd).st_mode)) {\n" +
            "                throw ErrnoException(\"open\", OsConstants.ENOTDIR)\n" +
            "            }"
        assertEquals(1, body.split(check).size - 1)
        assertTrue(body.indexOf(check) < body.indexOf("Os.fsync(fd)"))
        assertTrue(
            body.substringAfter("Os.fsync(fd)").trimStart()
                .startsWith("} finally {\n            Os.close(fd)"),
        )
    }

    private fun mainSources(): List<File> =
        appSources().listFiles { file -> file.extension == "kt" }!!.sortedBy { it.name }

    private fun source(name: String): String = File(appSources(), name).readText()

    private fun appSources(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (prefix in listOf("android/app/src/main/kotlin", "app/src/main/kotlin", "src/main/kotlin")) {
                val candidate = File(dir, "$prefix/org/winsvpn/app")
                if (File(candidate, "SecureFileStore.kt").isFile) return candidate
            }
            dir = dir.parentFile
        }
        throw AssertionError("could not locate the app sources")
    }
}
