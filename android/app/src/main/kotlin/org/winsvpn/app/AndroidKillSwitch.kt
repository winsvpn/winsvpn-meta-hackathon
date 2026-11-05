package org.winsvpn.app

import android.content.Context
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * The Android-flavoured half of the kill switch: a best-effort armament of the
 * system always-on/block-connections facility and a `VpnService.Builder`
 * blocking interface.
 *
 * ## The system facility is hidden API, and this file is honest about it
 *
 * `android.net.VpnManager` exposes the always-on/block-connections controls
 * only behind `@SystemApi`/hidden methods (`setAlwaysOnVpn`,
 * `isVpnLockdownEnabled`, `getAlwaysOnVpnPackage`). They are present in every
 * framework the app supports but are NOT in the public SDK, so every call here
 * goes through reflection and every read is verified against the real system
 * state the way the camouflage channel ladder verifies its writes. NONE of
 * them is treated as a guarantee because writing to the framework is not
 * reading from it, and the earlier Android kill-switch document
 * (ANDROID_ALWAYS_ON_KILL_SWITCH_MEASURED_AND_SURFACED_20260807.md) measured
 * exactly why: lockdown behaviour that "should" hold has to be observed, not
 * assumed, on OEM firmware.
 *
 * When the reflective path is unavailable or fails, the caller falls back to
 * the blocking interface below, which needs nothing beyond a prepared VpnService
 * — and, where a user must turn the actual Settings toggle, to a deep link into
 * `Settings.ACTION_VPN_SETTINGS`. Fail direction is always "the OS is not
 * blocking for us", because an unverifiable safety claim is the same defect
 * class as the IPv6 log line this codebase already removed.
 */
class AndroidKillSwitch(private val service: VpnService) {

    /**
     * Names this module's `Builder` session. Reuses the shipping tunnel session
     * name so a blocking posture does not introduce a second, self-identifying
     * row in Settings > Network & internet > VPN while the disguise is in force.
     */
    private fun sessionName(): String {
        return VpnTunnelService.vpnSessionNameFor(
            camouflageEnrolled = VpnTunnelService.isCamouflageEnrolled(service),
            decoyActive = VpnTunnelService.decoyLauncherIsActive(service),
        )
    }

    /**
     * The result of a best-effort arm of the hidden always-on/block-connections
     * API. All reflection calls fail closed: they throw `Exception` subtypes
     * (`NoSuchMethodException`, `SecurityException`, ...) for the ways a hidden
     * method is absent or blocked, and each is caught and surfaced as an
     * "unavailable / not verified" outcome. Deliberately NO `catch (Throwable)`
     * — this codebase reserves `Error`-catching for the three blessed sites
     * (see WinnV3AdoptionTest), and an error surfacing here must fall through
     * to the caller's own error handling, not be swallowed by the kill switch.
     *
     * The specific reason is only used for logging granularity; every caller
     * treats REFLECTION_UNAVAILABLE and NOT_VERIFIED alike (fall back to the
     * blocking interface and/or Settings).
     */
    enum class ArmOutcome {
        /** Always-on + lockdown were written and then read back as OUR app. */
        ARMED,

        /** The hidden API is not present (below API 24) or unreachable. */
        REFLECTION_UNAVAILABLE,

        /** The write was attempted but the read-back is not OUR_APP_ACTIVE. */
        NOT_VERIFIED,
    }

    private fun manager(): Any? {
        if (Build.VERSION.SDK_INT < KillSwitchPolicy.MIN_ALWAYS_ON_API) return null
        return try {
            // Context.VPN_MANAGEMENT_SERVICE is API 30+; the string constant is
            // identical on every level that has VpnManager (24+), so it is
            // spelled out rather than gated.
            service.getSystemService("vpn_management")
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Reflectively invoke a no-argument method on the VpnManager instance.
     * Returns null when the method is absent or the call threw.
     */
    private fun invokeBoolean(methodName: String): Boolean? {
        val m = manager() ?: return null
        return try {
            m.javaClass.getMethod(methodName)
                .invoke(m) as? Boolean
        } catch (e: Exception) {
            null
        }
    }

    private fun invokeString(methodName: String): String? {
        val m = manager() ?: return null
        return try {
            m.javaClass.getMethod(methodName)
                .invoke(m) as? String
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Read the raw always-on package on API 24+ through the hidden API.
     * Below API 24 returns null (the caller classifies that as UNAVAILABLE).
     */
    fun readAlwaysOnVpnPackage(): String? {
        if (Build.VERSION.SDK_INT < KillSwitchPolicy.MIN_ALWAYS_ON_API) return null
        // On API 35 the no-arg accessor is deprecated in favour of a typed one;
        // the deprecated form still answers with the legacy always-on package,
        // which is exactly what a third-party VpnService arms.
        return invokeString("getAlwaysOnVpnPackage")
    }

    /** Read the lockdown flag on API 24+. Null when unreadable (fail-closed). */
    fun readLockdownEnabled(): Boolean? {
        if (Build.VERSION.SDK_INT < KillSwitchPolicy.MIN_ALWAYS_ON_API) return null
        return invokeBoolean("isVpnLockdownEnabled")
    }

    /**
     * The public answer for THIS service (API 29+): always-on is us and
     * lockdown is on. Null below 29 or when the call throws.
     */
    fun readPublicLockdownForUs(): Boolean? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
        return try {
            service.isAlwaysOn && service.isLockdownEnabled
        } catch (e: Exception) {
            null
        }
    }

    /** Our package when the public API proves it, else the hidden read. */
    fun effectiveAlwaysOnPackage(): String? =
        if (readPublicLockdownForUs() == true) service.packageName else readAlwaysOnVpnPackage()

    /** True when either the public API or the hidden read proves lockdown. */
    fun effectiveLockdownEnabled(): Boolean =
        readPublicLockdownForUs() == true || (readLockdownEnabled() ?: false)

    /**
     * The classified state read LIVE from the system right now. A failed read
     * is [KillSwitchPolicy.BlockConnectionsState.NOT_ARMED], not a claim.
     */
    fun readBlockConnectionsState(): KillSwitchPolicy.BlockConnectionsState {
        return KillSwitchPolicy.blockConnectionsState(
            apiLevel = Build.VERSION.SDK_INT,
            alwaysOnPackage = effectiveAlwaysOnPackage(),
            lockdownEnabled = effectiveLockdownEnabled(),
            ourPackage = service.packageName,
        )
    }

    /**
     * Best-effort arming: always-on = this package, lockdown = on.
     *
     * The hidden API shape differs between API 35 (`setAlwaysOnVpn(int, String,
     * boolean)`) and 24-34 (`setAlwaysOnVpn(String, boolean)`); both are tried
     * in order. The verdict is ALWAYS taken from [readBlockConnectionsState]
     * after the write, never from the write's own return value.
     */
    fun armAlwaysOnLockdown(): ArmOutcome {
        if (Build.VERSION.SDK_INT < KillSwitchPolicy.MIN_ALWAYS_ON_API) {
            return ArmOutcome.REFLECTION_UNAVAILABLE
        }
        val m = manager()
        if (m == null) return ArmOutcome.REFLECTION_UNAVAILABLE
        val written = try {
            val legacy = listOf(
                Triple("setAlwaysOnVpn", arrayOf(String::class.java, Boolean::class.java), arrayOf(service.packageName, true)),
                Triple(
                    "setAlwaysOnVpn",
                    arrayOf(Int::class.javaPrimitiveType, String::class.java, Boolean::class.java),
                    arrayOf(0, service.packageName, true),
                ),
            )
            var ok = false
            for ((name, signature, args) in legacy) {
                try {
                    m.javaClass.getMethod(name, *signature).invoke(m, *args)
                    ok = true
                    break
                } catch (_: NoSuchMethodException) {
                    // Try the next signature.
                } catch (e: Exception) {
                    // The call itself threw; do not keep poking.
                    break
                }
            }
            ok
        } catch (e: Exception) {
            false
        }
        if (!written) return ArmOutcome.REFLECTION_UNAVAILABLE

        val state = readBlockConnectionsState()
        Log.i(
            TAG,
            "kill switch arm write returned; read-back state=$state " +
                "alwaysOn=${readAlwaysOnVpnPackage()} lockdown=${readLockdownEnabled()}",
        )
        return if (state == KillSwitchPolicy.BlockConnectionsState.OUR_APP_ACTIVE) {
            ArmOutcome.ARMED
        } else {
            ArmOutcome.NOT_VERIFIED
        }
    }

    /**
     * Best-effort disarming: clear always-on so lockdown lifts and the device
     * returns to a user-controlled path. Only clears when the always-on package
     * is ours; never touches another app's always-on arrangement.
     */
    fun disarmAlwaysOnLockdown(): Boolean {
        val m = manager() ?: return false
        if (readAlwaysOnVpnPackage() != service.packageName) return false
        return try {
            val method = m.javaClass.getMethod("setAlwaysOnVpn", String::class.java, Boolean::class.java)
            (method.invoke(m, null, false) as? Boolean) ?: false
        } catch (e: Exception) {
            false
        }
    }

    /**
     * The `VpnService.Builder` kill switch: establish an interface that captures
     * the whole route table (IPv4 default + the IPv6 fail-closed sink) with no
     * engine draining it, so every packet routed into the tun is dropped instead
     * of egressing on the physical interface.
     *
     * Returns null (never throws) when establishment fails — e.g. the app is no
     * longer the prepared VPN package, which is exactly the state in which the
     * caller cannot block and must say so.
     */
    fun establishBlockingInterface(): ParcelFileDescriptor? {
        return try {
            // VpnService.Builder is an INNER class: it must be created through
            // the service instance (newBuilder patterns), never as
            // VpnService.Builder().
            val builder = service.Builder()
                .setSession(sessionName())
                .addAddress(BLOCK_INNER_V4, 32)
                .addRoute("0.0.0.0", 0)
                .addAddress(VpnTunnelService.IPV6_FAIL_CLOSED_SINK, 128)
                .addRoute("::", 0)
                .setMtu(BLOCK_MTU)

            // No DNS server: with both-default-pointing routes inside the tun,
            // every query the platform issues also lands in the tun and is
            // dropped with the rest of the traffic.
            val pfd = builder.establish()
            if (pfd == null) {
                Log.w(TAG, "blocking interface: Builder.establish() returned null")
            }
            pfd
        } catch (e: Exception) {
            Log.w(TAG, "blocking interface could not be established", if (BuildConfig.DEBUG) e else null)
            null
        }
    }

    private companion object {
        const val TAG = VpnTunnelService.LOG_TAG

        /** A documentation-range inner address, distinct from the relay space. */
        const val BLOCK_INNER_V4 = "10.8.2.3"

        /** Same default as the shipping tunnel; see the path_mtu notes. */
        const val BLOCK_MTU = 1280
    }
}