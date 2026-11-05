# Release R8 keep contract.
#
# Android instantiates manifest components by class name. JNI binds native
# methods by class and member name. Flutter looks up GeneratedPluginRegistrant
# and constructs the plugins named there. Keep those names. Do not keep the
# rest of the implementation surface.
#
# These rules are a static contract. They do not prove a successful R8 run.

# JNI ABI: keep native method names and the types that appear in their
# descriptors. Covers org.amnezia.awg.GoBackend and package:jni natives.
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# AWG userspace JNI class. Keep the class name and native methods only; the
# rest of the AAR (config, crypto, unused VpnService backend) is not an
# entrypoint. The 3-arg Java awgTurnOn overload is not native and is unused.
-keep class org.amnezia.awg.GoBackend {
    native <methods>;
}

# Manifest components. The system constructs them with the public no-arg
# constructor. Lifecycle overrides remain reachable through the Android SDK
# base classes and do not need member wildcards.
-keep class org.winsvpn.app.MainActivity {
    <init>();
}
-keep class org.winsvpn.app.RealLauncherActivity {
    <init>();
}
-keep class org.winsvpn.app.DecoyLauncherActivity {
    <init>();
}
-keep class org.winsvpn.app.VpnTunnelService {
    <init>();
}
-keep class org.winsvpn.app.WatchCommandService {
    <init>();
}

# Flutter looks this up by name from the embedding and invokes registerWith.
-keep class io.flutter.plugins.GeneratedPluginRegistrant {
    public static void registerWith(io.flutter.embedding.engine.FlutterEngine);
}

# Plugins constructed by GeneratedPluginRegistrant. JniPlugin.setClassLoader
# is native (covered above). JniFlutterPlugin application/activity accessors
# are invoked from Dart JNI by name.
-keep class com.github.dart_lang.jni.JniPlugin {
    public <init>();
    native <methods>;
}
-keep class com.github.dart_lang.jni_flutter.JniFlutterPlugin {
    public <init>();
    public static android.content.Context getApplicationContext();
    public static android.app.Activity getActivity(long);
}

# The AAR still references its optional HEV backend. This app removes that
# service from the merged manifest and does not ship HEV.
-dontwarn org.amnezia.awg.hevtunnel.TProxyService

# Release logcat must not carry the tunnel timeline. Strip verbose, debug and
# info logging (debugLog is Log.i). Warnings and errors stay for field triage.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static boolean isLoggable(java.lang.String, int);
}
