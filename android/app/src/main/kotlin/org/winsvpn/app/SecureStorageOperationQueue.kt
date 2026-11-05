package org.winsvpn.app

import java.util.concurrent.Executors

/** Keeps timed-out secure operations in dispatch order until they really finish. */
internal object SecureStorageOperationQueue {
    private val executor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "Calc-Secure-Storage").apply { isDaemon = true }
    }

    fun execute(operation: () -> Unit) {
        executor.execute(operation)
    }
}
