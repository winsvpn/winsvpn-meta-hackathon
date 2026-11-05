package org.winsvpn.app.wear

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phone state must reach the screen in the order the phone sent it.
 *
 * Every PATH_STATE message is checked against the selected phone node, which
 * is a suspending capability lookup. Run as one coroutine per message, two
 * lookups can finish out of order, so CONNECTED can be applied before the
 * CONNECTING sent ahead of it and the watch shows the older state. The check
 * belongs on the flow itself, where elements are processed one at a time.
 */
class PhoneLinkOrderContractTest {

    @Test
    fun `the selected-node check keeps phone state in arrival order`() {
        val messages = source("wear_os/app/src/main/kotlin/org/winsvpn/app/wear/PhoneLink.kt")
            .substringAfter("private fun messageSnapshots()")
            .substringBefore("private fun dataSnapshots()")
        assertFalse(Regex("""\blaunch\s*\{""").containsMatchIn(messages))
        val listener = messages.substringBefore("awaitClose")
        assertTrue(listener.contains("trySend(snapshot.copy(sourceNodeId = event.sourceNodeId))"))
        val check = messages.substringAfter(".filter { snapshot ->", missingDelimiterValue = "")
        assertTrue(
            check.contains("PairingMatcher.matchesSelectedNode(snapshot.sourceNodeId, phoneNodeId())"),
        )
    }

    @Test
    fun `a burst during a node lookup drops the oldest queued state, not the newest`() {
        // callbackFlow's default buffer suspends when full, so trySend fails and
        // the newest state is the one lost; the screen keeps the last state.
        val messages = source("wear_os/app/src/main/kotlin/org/winsvpn/app/wear/PhoneLink.kt")
            .substringAfter("private fun messageSnapshots()")
            .substringBefore("private fun dataSnapshots()")
        val flow = messages.substringAfter("awaitClose", missingDelimiterValue = "")
        val buffer = "}.buffer(capacity = 64, onBufferOverflow = BufferOverflow.DROP_OLDEST).filter { snapshot ->"
        assertTrue(flow.contains(buffer))
    }

    private fun source(relative: String): String {
        var directory: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (directory != null) {
            val file = File(directory, relative)
            if (file.isFile) return file.readText()
            directory = directory.parentFile
        }
        throw AssertionError("could not locate $relative")
    }
}
