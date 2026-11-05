package org.amnezia.awg;

import androidx.annotation.Nullable;

/**
 * Exact official v3.1 GoBackend JNI declaration with the reviewed WinsVPN
 * live-peer update surface. The three-argument overload preserves the
 * official tunnel module's source contract while both paths enter the same
 * four-argument native implementation.
 */
public class GoBackend {
    @Nullable
    public static native String awgGetConfig(int handle);

    public static native int awgGetSocketV4(int handle);

    public static native int awgGetSocketV6(int handle);

    public static native void awgTurnOff(int handle);

    public static int awgTurnOn(String ifName, int tunFd, String settings) {
        return awgTurnOn(ifName, tunFd, settings, "");
    }

    public static native int awgTurnOn(
            String ifName, int tunFd, String settings, String uapiPath);

    public static native int awgUpdateTunnelPeers(int handle, String settings);

    public static native String awgVersion();
}
