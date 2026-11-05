package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Source contract for release logcat: no warning or error log call may print
 * an exception message unless that text sits in a `BuildConfig.DEBUG` branch
 * of the same call, and no direct `Log` call may hand Log a throwable outside
 * a debug build. Exception messages from java.net, the resolver and the
 * engines name addresses, ports, hosts and config lines, and framework
 * notification errors name the product's channel id.
 */
class ReleaseLogMessageGuardTest {
    private val callStart = Regex(
        """\b(?:android\.util\.)?Log\.(?:w|e|wtf)\s*\(|""" +
            """\b(?:logWarning|logError|logWarn|resolverWarning|resolverError)\s*\(|""" +
            """\.on(?:Warning|Error)\s*\(""",
    )

    /** `$e` or `${e}` in a template prints the throwable's toString, message included. */
    private val throwableText = Regex("""\$(?:\{\s*)?(?:e|error|ex|throwable|cause)\b(?!\s*\.)""")

    private val trailingThrowable = Regex(""",\s*(e|error|ex|t|throwable|cause|it)\s*,?\s*\)\s*$""")

    @Test
    fun `no release warning or error line prints an exception message`() {
        val violations = mutableListOf<String>()
        val files = sourceDir().listFiles { f -> f.name.endsWith(".kt") }!!.sortedBy { it.name }
        assertTrue("no Kotlin sources found", files.size > 10)
        var calls = 0
        for (file in files) {
            val text = file.readText()
            for (match in callStart.findAll(text)) {
                val before = text.substring(maxOf(0, match.range.first - 12), match.range.first)
                if ("fun " in before) continue
                var i = match.range.last + 1
                var depth = 1
                while (depth > 0 && i < text.length) {
                    when (text[i]) {
                        '(' -> depth++
                        ')' -> depth--
                    }
                    i++
                }
                calls++
                val call = text.substring(match.range.first, i)
                val line = text.substring(0, match.range.first).count { it == '\n' } + 1
                if ((".message" in call || ".localizedMessage" in call || throwableText.containsMatchIn(call)) &&
                    "BuildConfig.DEBUG" !in call
                ) {
                    violations += "${file.name}:$line message"
                }
                // Log prints a throwable's message and trace: a direct call may
                // pass one only in a debug build.
                val guardedBefore = "if (BuildConfig.DEBUG" in
                    text.substring(maxOf(0, match.range.first - 160), match.range.first)
                if (match.value.trimStart().let { it.startsWith("Log.") || it.startsWith("android.util.Log.") } &&
                    trailingThrowable.containsMatchIn(call) &&
                    "BuildConfig.DEBUG" !in call && !guardedBefore
                ) {
                    violations += "${file.name}:$line throwable"
                }
            }
        }
        assertTrue("the scan matched too few calls to be meaningful ($calls)", calls > 50)
        assertTrue("release log calls print exception messages: $violations", violations.isEmpty())
    }

    private fun sourceDir(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            val candidate = File(dir, "android/app/src/main/kotlin/org/winsvpn/app")
            if (candidate.isDirectory) return candidate
            val here = File(dir, "app/src/main/kotlin/org/winsvpn/app")
            if (here.isDirectory) return here
            dir = dir.parentFile
        }
        throw AssertionError("could not locate the app's Kotlin sources")
    }
}
