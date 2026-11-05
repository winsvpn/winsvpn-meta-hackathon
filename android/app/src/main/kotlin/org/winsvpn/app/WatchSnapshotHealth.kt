package org.winsvpn.app

/** A cached connected claim must remain backed by native tunnel health. */
internal object WatchSnapshotHealth {
    fun status(
        cachedStatus: String,
        nativeHealthy: Boolean,
        needsPermission: () -> Boolean,
    ): String {
        if (cachedStatus != "connected" || nativeHealthy) return cachedStatus
        return if (needsPermission()) "permissionRequired" else "disconnected"
    }

    /**
     * The `updatedAt` a cached snapshot carries when it is sent again: the
     * reply time, so the watch's skew-free load age, (updatedAt - load_at)
     * plus its own time since arrival, includes the time the snapshot sat
     * cached on this phone. Never earlier than the stamp it replaces, so a
     * phone clock set back cannot make a figure look younger.
     */
    fun updatedAt(cachedUpdatedAt: Long, nowEpochMs: Long): Long =
        maxOf(cachedUpdatedAt, nowEpochMs)
}
