package org.winsvpn.app

import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecureStorageOperationQueueTest {
    @Test
    fun timedOutEarlierWriteCannotOvertakeALaterAcknowledgedWrite() {
        val firstStarted = CountDownLatch(1)
        val releaseFirst = CountDownLatch(1)
        val bothFinished = CountDownLatch(2)
        val order = Collections.synchronizedList(mutableListOf<String>())
        try {
            SecureStorageOperationQueue.execute {
                firstStarted.countDown()
                releaseFirst.await()
                order.add("old")
                bothFinished.countDown()
            }
            assertTrue(firstStarted.await(2, TimeUnit.SECONDS))
            SecureStorageOperationQueue.execute {
                order.add("new")
                bothFinished.countDown()
            }
            assertFalse(bothFinished.await(100, TimeUnit.MILLISECONDS))
        } finally {
            releaseFirst.countDown()
        }
        assertTrue(bothFinished.await(2, TimeUnit.SECONDS))
        assertEquals(listOf("old", "new"), order)
    }
}
