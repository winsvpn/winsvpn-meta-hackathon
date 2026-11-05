package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The in-app upload test reports what the far end accepted, over the time it
 * took to accept it (tunnel-speed round, 2026-10-09). On the Canada runs the
 * old accounting counted bytes the moment a 16 MB socket buffer took them and
 * capped the window at 8 s, so it reported 742 to 790 Mbit/s while the
 * gateway took in 28k to 32k datagrams per second, about 300 to 340 Mbit/s.
 * These pins keep each half of the fix in the source.
 */
class SpeedTestUploadAccountingContractTest {

    private val activity = source("MainActivity.kt")

    private val upload: String = activity
        .substringAfter("val speedTestSocketFactory = object : javax.net.SocketFactory() {")
        .substringBefore("name = \"Calc-Native-Upload-Test\"")

    private val body: String = upload
        .substringAfter("override fun writeTo(sink: BufferedSink) {")
        .substringBefore("val requestBuilder = Request.Builder()")

    @Test
    fun `the upload sections are found`() {
        assertTrue("upload section", upload.length > 1000)
        assertTrue("request body section", body.contains("sink.write(buffer, 0, writable)"))
    }

    @Test
    fun `bytes written into the sink are not yet confirmed`() {
        assertFalse(body.contains("confirmed.addAndGet"))
        assertTrue(body.contains("requestBytes += writable.toLong()"))
    }

    @Test
    fun `a flush failure fails the stream instead of being swallowed`() {
        assertFalse(body.contains("catch (_: Exception)"))
        assertTrue(body.contains("sink.flush()\n                                bodyCompleted = true"))
    }

    @Test
    fun `only a completed 2xx request confirms its bytes`() {
        val gate = upload.substringAfter("val response = call.execute()").substringBefore("} catch (e: Exception) {")
        assertTrue(gate.contains("val successful = response.code in 200..299 && bodyCompleted"))
        val confirmedAt = gate.indexOf("confirmed.addAndGet(requestBytes)")
        assertTrue("confirmed only inside the success branch", confirmedAt > gate.indexOf("if (successful) {"))
        assertTrue(gate.contains("failedStreams.incrementAndGet()"))
        val failure = upload.substringAfter("} catch (e: Exception) {").substringBefore("} finally {")
        assertTrue("an exception fails the stream", failure.contains("failedStreams.incrementAndGet()"))
    }

    @Test
    fun `the window runs to the last completion and is not capped`() {
        assertTrue(upload.contains("finishedAt.updateAndGet { previous -> maxOf(previous, completedAt) }"))
        assertTrue(upload.contains("val elapsedNanos = activeNanos\n"))
        assertFalse(upload.contains("minOf(activeNanos, TimeUnit.MILLISECONDS.toNanos(durationMs))"))
    }

    @Test
    fun `a run with an unfinished or failed stream reports no figure`() {
        assertTrue(upload.contains("val allFinished = done.await(durationMs + 15_000L, TimeUnit.MILLISECONDS)"))
        val verdict = upload.substringAfter("runOnUiThread {").substringBefore("result.success(mapOf(")
        assertTrue(verdict.contains("!allFinished || failedStreams.get() != 0L ||"))
        assertTrue(verdict.contains("result.success(null)"))
    }

    @Test
    fun `each upload socket asks for 512 KiB of send buffer`() {
        val factory = upload.substringBefore("override fun createSocket(): java.net.Socket")
        val requests = Regex("""socket\.sendBufferSize = ([0-9 *]+)""").findAll(factory).map { it.groupValues[1].trim() }.toList()
        assertEquals(listOf("512 * 1024"), requests)
    }

    @Test
    fun `the tunnel ingest window is not capped at the write window`() {
        val ingest = activity.substringAfter("val total = receivedBytes.sum()").substringBefore("val mbps = total.toDouble()")
        assertTrue(ingest.contains("(System.nanoTime() - startNanos).coerceAtLeast(1L)"))
        assertFalse(ingest.contains("coerceAtMost(windowNanos)"))
    }

    private fun source(name: String): String {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (prefix in listOf("android/app/src/main/kotlin", "app/src/main/kotlin")) {
                val file = File(dir, "$prefix/org/winsvpn/app/$name")
                if (file.isFile) return file.readText()
            }
            dir = dir.parentFile
        }
        throw AssertionError("could not locate $name")
    }
}
