package org.winsvpn.app

/**
 * Context-free decision logic for the Android kill switch.
 *
 * Android has no application-callable API that installs a system-wide block
 * rule of its own the way Linux's WINSVPN_KS chain does. The only OS-level
 * kill switch is always-on VPN combined with "Block connections without VPN"
 * (lockdown), which lives in Settings and is programmatically reachable only
 * through hidden/system VpnManager methods (see [AndroidKillSwitch]). This
 * file decides, from the *observed* OS state, whether that OS guarantee is in
 * force and whether the app must hold a blocking interface of its own.
 *
 * Every function is pure so a unit test can enumerate the whole input space
 * and so a code path that silently widens the guarantee costs a red test.
 * The policy's spine is fail-closed: any state that cannot be read, or any
 * always-on arrangement that is not conclusively OUR app with lockdown on, is
 * treated as "the OS will not block for us", and the teardown then holds a
 * blocking interface instead.
 *
 * ## What the "OS guarantee" means, precisely
 *
 * `BlockConnectionsState.OUR_APP_ACTIVE` is the ONLY state in which Android
 * blocks every other UID while OUR tunnel is down: always-on is set to our
 * package and lockdown is on. Two states look close and are not:
 *
 *  - `LOCKDOWN_OTHER_APP`: some other VPN is always-on with lockdown. The OS
 *    blocks while THAT app's tunnel is down. While that app's tunnel is up and
 *    ours is down, traffic flows in the clear, so this state must NOT be
 *    treated as a guarantee for our tunnel-down window.
 *  - always-on unset or lockdown off: nothing blocks.
 *
 * ## What the caller does with the decision
 *
 * `mustHoldBlockingInterface` is consulted at tunnel teardown. When it returns
 * true the service keeps (or, if none is running, re-establishes) a VpnService
 * interface with the full route set and no engine draining it, so every packet
 * that would otherwise leave on the physical interface is absorbed by the tun
 * and dropped. That is the `VpnService.Builder` half of the kill switch, and
 * it is the only half that works on devices where always-on cannot be set
 * (below API 24) or where the hidden VpnManager path failed.
 */
object KillSwitchPolicy {

    /**
     * The first API level with `android.net.VpnManager` and the always-on /
     * lockdown facilities behind it. Below this the only user-facing route is
     * the deep link into Settings, and the app's blocking interface is the
     * entire kill switch.
     */
    const val MIN_ALWAYS_ON_API = 24

    /**
     * The state of the system's always-on/block-connections facility for the
     * current user, classified from the raw observed values.
     */
    enum class BlockConnectionsState {
        /** Below [MIN_ALWAYS_ON_API]: no programmatic facility exists. */
        UNAVAILABLE,

        /** Always-on is OUR package and lockdown is on. The OS blocks every
         *  non-VPN UID while OUR tunnel is down. */
        OUR_APP_ACTIVE,

        /** Always-on names another package with lockdown on. The OS blocks
         *  only while THAT app's tunnel is down, so it is no guarantee for
         *  our tunnel-down window. */
        LOCKDOWN_OTHER_APP,

        /** Always-on unset, or lockdown off, or (fail-closed) unreadable. */
        NOT_ARMED,
    }

    /**
     * Classify the raw OS state. `alwaysOnPackage == null` and
     * `lockdownEnabled == false` both mean "no guarantee". A failed read is
     * surfaced by the caller as those same values and therefore classifies as
     * [BlockConnectionsState.NOT_ARMED], which is the fail-closed direction.
     */
    fun blockConnectionsState(
        apiLevel: Int,
        alwaysOnPackage: String?,
        lockdownEnabled: Boolean,
        ourPackage: String,
    ): BlockConnectionsState {
        if (apiLevel < MIN_ALWAYS_ON_API) return BlockConnectionsState.UNAVAILABLE
        if (!lockdownEnabled) return BlockConnectionsState.NOT_ARMED
        return if (alwaysOnPackage == ourPackage) {
            BlockConnectionsState.OUR_APP_ACTIVE
        } else if (alwaysOnPackage != null) {
            BlockConnectionsState.LOCKDOWN_OTHER_APP
        } else {
            BlockConnectionsState.NOT_ARMED
        }
    }

    /**
     * True only when the OS is guaranteed to block every non-VPN UID while our
     * tunnel is down. This is the single boolean the rest of the policy leans
     * on, and by construction it is true in exactly one state.
     */
    fun osGuaranteesBlockedWhileDown(
        apiLevel: Int,
        alwaysOnPackage: String?,
        lockdownEnabled: Boolean,
        ourPackage: String,
    ): Boolean {
        return blockConnectionsState(apiLevel, alwaysOnPackage, lockdownEnabled, ourPackage) ==
            BlockConnectionsState.OUR_APP_ACTIVE
    }

    /**
     * Whether the tunnel teardown must leave a blocking interface in place.
     *
     * False whenever the kill switch is not armed (the user accepted a plain
     * tunnel with a leak-on-disconnect). True whenever it IS armed and the OS
     * is not conclusively blocking for us — which is the only window Windows
     * and Apple were caught leaking in on this codebase's own audit
     * (ANDROID_IPV6_FAIL_CLOSED_FIX_AND_KILL_SWITCH_SCOPE_20260807.md §2.3).
     */
    fun mustHoldBlockingInterface(
        killSwitchArmed: Boolean,
        apiLevel: Int,
        alwaysOnPackage: String?,
        lockdownEnabled: Boolean,
        ourPackage: String,
    ): Boolean {
        if (!killSwitchArmed) return false
        return !osGuaranteesBlockedWhileDown(apiLevel, alwaysOnPackage, lockdownEnabled, ourPackage)
    }
}