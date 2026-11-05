package org.winsvpn.app.wear

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * One state request per resume. startPolling() asks the phone on its first
 * loop iteration, so an extra refresh() in onResume() sends a second
 * requestState message (and wakes the phone service a second time).
 */
class WatchResumeRequestContractTest {

    @Test
    fun `onResume leaves the first state request to startPolling`() {
        val onResume = source("wear_os/app/src/main/kotlin/org/winsvpn/app/wear/MainActivity.kt")
            .substringAfter("override fun onResume() {")
            .substringBefore("override fun onPause() {")
        assertTrue(onResume.contains("viewModel.startPolling()"))
        assertEquals(0, Regex("""viewModel\.refresh\(\)""").findAll(onResume).count())
    }

    @Test
    fun `the poll loop requests state before its first delay`() {
        val poll = source("wear_os/app/src/main/kotlin/org/winsvpn/app/wear/WatchViewModel.kt")
            .substringAfter("fun startPolling() {")
            .substringBefore("fun stopPolling() {")
        val loop = poll.indexOf("while (isActive) {")
        val refresh = poll.indexOf("refresh()", loop)
        val delay = poll.indexOf("delay(", loop)
        assertTrue(loop >= 0)
        assertTrue(refresh in loop until delay)
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
