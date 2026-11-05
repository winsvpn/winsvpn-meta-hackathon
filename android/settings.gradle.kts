pluginManagement {
    val flutterSdkPath =
        run {
            val properties = java.util.Properties()
            file("local.properties").inputStream().use { properties.load(it) }
            val flutterSdkPath = properties.getProperty("flutter.sdk")
            require(flutterSdkPath != null) { "flutter.sdk not set in local.properties" }
            flutterSdkPath
        }

    includeBuild("$flutterSdkPath/packages/flutter_tools/gradle")

    // gradlePluginPortal() is DELIBERATELY absent (supply-chain finding S2,
    // SUPPLY_CHAIN_AUDIT_20260810.md, HIGH): a plugin runs arbitrary build-time
    // code before any artifact check applies, and the portal is the least-policed
    // of the public Maven repositories. Every plugin this build resolves comes
    // from google() (com.android.application is google-only), mavenCentral()
    // (org.jetbrains.kotlin.android is central-only) or the Flutter composite
    // includeBuild above (dev.flutter.flutter-*). Verified 2026-08-10 in Colima:
    // `:app:properties` configures with zero requests to plugins.gradle.org.
    // Do not re-add the portal; guard: tools/test_gradle_plugin_repository_policy.py.
    repositories {
        google()
        mavenCentral()
    }
}

plugins {
    id("dev.flutter.flutter-plugin-loader") version "1.0.0"
    id("com.android.application") version "9.4.1" apply false
    id("org.jetbrains.kotlin.android") version "2.4.20" apply false
}

include(":app")
