package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class WatchSnapshotHealthTest {
    @Test
    fun cachedConnectionExpiresWhenNativeTunnelFails() {
        assertEquals("disconnected", WatchSnapshotHealth.status("connected", false) { false })
        assertEquals("permissionRequired", WatchSnapshotHealth.status("connected", false) { true })
    }

    @Test
    fun healthyConnectionAndDartTransitionsArePreserved() {
        assertEquals("connected", WatchSnapshotHealth.status("connected", true) {
            throw AssertionError("healthy tunnel does not need a permission query")
        })
        for (status in listOf("connecting", "disconnecting", "disconnected", "failed", "permissionRequired")) {
            assertEquals(status, WatchSnapshotHealth.status(status, false) {
                throw AssertionError("Dart transition should stay intact")
            })
        }
    }

    @Test
    fun cachedUpdatedAtAdvancesToReplyTimeWithoutMovingBackwards() {
        // Published 2.5 s after load_at, replayed from the cache 67.5 s later.
        assertEquals(1_790_480_070_000L, WatchSnapshotHealth.updatedAt(1_790_480_002_500L, 1_790_480_070_000L))
        // A phone clock set back never moves the stamp earlier.
        assertEquals(1_790_480_002_500L, WatchSnapshotHealth.updatedAt(1_790_480_002_500L, 1_790_480_001_000L))
    }

    @Test
    fun cachedReplyIsRestampedRatherThanReturnedVerbatim() {
        val cachedPath = source("WatchBridge.kt")
            .substringAfter("fun snapshotJson(context: Context): String {")
            .substringBefore("val nativeStatus = when {")
        assertTrue(cachedPath.contains("WatchSnapshotHealth.updatedAt("))
        assertFalse(cachedPath.contains("return cached"))
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
