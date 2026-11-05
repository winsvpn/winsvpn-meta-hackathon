package org.winsvpn.app

import java.io.IOException

/** One AmneziaWG transport socket exposed by the native engine. */
internal data class AwgSocket(
    val label: String,
    val fd: Int,
)

/**
 * Protects every available AmneziaWG transport socket or rolls the engine back.
 *
 * The native engine must already be running before it exposes these descriptors.
 * That makes rollback part of the protection gate: returning with any available
 * socket unprotected would let the tunnel route its own carrier traffic back into
 * its TUN.
 */
internal object AwgSocketProtection {
    @Throws(IOException::class)
    fun protectOrRollback(
        sockets: () -> Iterable<AwgSocket>,
        protect: (Int) -> Boolean,
        rollback: () -> Unit,
        onUnavailable: (String) -> Unit = {},
    ) {
        try {
            var protectedCount = 0
            for (socket in sockets()) {
                if (socket.fd < 0) {
                    onUnavailable(socket.label)
                    continue
                }

                val protected = try {
                    protect(socket.fd)
                } catch (failure: Exception) {
                    throw IOException(
                        "VpnService.protect() failed for the AmneziaWG ${socket.label} socket",
                        failure,
                    )
                }
                if (!protected) {
                    throw IOException(
                        "VpnService.protect() refused the AmneziaWG ${socket.label} socket; " +
                            "refusing to keep an unprotected engine running.",
                    )
                }
                tuneSocketBuffers(socket.fd)
                protectedCount++
            }
            if (protectedCount == 0) {
                throw IOException(
                    "No AmneziaWG carrier socket was available to protect; " +
                        "refusing to keep an unprotected engine running.",
                )
            }
        } catch (failure: Exception) {
            try {
                rollback()
            } catch (rollbackFailure: Exception) {
                failure.addSuppressed(rollbackFailure)
            }
            throw failure
        }
    }

    private const val SOCKET_BUFFER_FLOOR_BYTES = 8 * 1024 * 1024 // 8 MiB

    private fun tuneSocketBuffers(fdInt: Int) {
        try {
            android.os.ParcelFileDescriptor.fromFd(fdInt).use { duplicate ->
                val fd = duplicate.fileDescriptor
                android.system.Os.setsockoptInt(
                    fd,
                    android.system.OsConstants.SOL_SOCKET,
                    android.system.OsConstants.SO_RCVBUF,
                    SOCKET_BUFFER_FLOOR_BYTES,
                )
                android.system.Os.setsockoptInt(
                    fd,
                    android.system.OsConstants.SOL_SOCKET,
                    android.system.OsConstants.SO_SNDBUF,
                    SOCKET_BUFFER_FLOOR_BYTES,
                )
            }
        } catch (_: Throwable) {
            // Socket buffer tuning remains advisory.
        }
    }
}
