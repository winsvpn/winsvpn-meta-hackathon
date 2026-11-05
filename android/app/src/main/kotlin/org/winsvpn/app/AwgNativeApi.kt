package org.winsvpn.app

import org.amnezia.awg.GoBackend

/**
 * Serializes every handle operation of the bundled AmneziaWG JNI engine.
 *
 * The engine keeps its tunnels in one process-wide Go map with no lock
 * (tools/amneziawg_android_official_jni/api-android.go: `tunnelHandles`).
 * awgTurnOn inserts and awgTurnOff deletes while awgGetConfig is read from the
 * readiness executor and the health watchdog, and Go aborts the whole process
 * on a concurrent map read and write. One JVM monitor here is a leaf lock: the
 * native side never calls back into the app while it is held.
 */
internal object AwgNativeApi {
    @Synchronized
    fun awgTurnOn(name: String, tunFd: Int, settings: String, directory: String): Int =
        GoBackend.awgTurnOn(name, tunFd, settings, directory)

    @Synchronized
    fun awgTurnOff(handle: Int) = GoBackend.awgTurnOff(handle)

    @Synchronized
    fun awgGetSocketV4(handle: Int): Int = GoBackend.awgGetSocketV4(handle)

    @Synchronized
    fun awgGetSocketV6(handle: Int): Int = GoBackend.awgGetSocketV6(handle)

    @Synchronized
    fun awgGetConfig(handle: Int): String? = GoBackend.awgGetConfig(handle)

    @Synchronized
    fun awgUpdateTunnelPeers(handle: Int, settings: String): Int =
        GoBackend.awgUpdateTunnelPeers(handle, settings)
}
