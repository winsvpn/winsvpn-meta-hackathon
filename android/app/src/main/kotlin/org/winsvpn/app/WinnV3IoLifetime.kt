package org.winsvpn.app

import java.io.Closeable
import java.io.IOException

/** One owner, retained through each finite operation without operation callbacks. */
internal class WinnV3IoLifetime(private val owner: Closeable) {
    private val monitor = Any()
    private var retired = false
    private var active = 0
    private var closeClaimed = false

    fun begin() {
        synchronized(monitor) {
            if (retired) throw IOException("Winn tun device is closed")
            check(active < Int.MAX_VALUE)
            active += 1
        }
    }

    fun end() {
        val close = synchronized(monitor) {
            check(active > 0)
            active -= 1
            claimClose()
        }
        if (close) closeOwner()
    }

    fun retire() {
        val close = synchronized(monitor) {
            retired = true
            claimClose()
        }
        if (close) closeOwner()
    }

    private fun claimClose(): Boolean {
        if (!retired || active != 0 || closeClaimed) return false
        closeClaimed = true
        return true
    }

    private fun closeOwner() {
        try { owner.close() } catch (_: IOException) { }
    }
}
