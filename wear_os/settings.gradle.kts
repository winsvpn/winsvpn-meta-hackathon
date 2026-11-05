// Deliberately a standalone Gradle build, not a module inside `android/`.
//
// `android/settings.gradle.kts` bootstraps the Flutter tooling plugin from
// `local.properties`, so every task in that build depends on a resolvable
// Flutter SDK and on the release-signing gate in `android/app/build.gradle.kts`.
// The watch APK shares nothing with the Flutter engine -- it is a thin remote
// control that talks to the phone over the Wearable Data Layer -- so keeping it
// out of that build means the phone app in Play review cannot be perturbed by
// watch-side changes, and the watch APK stays buildable on a machine that has
// no Flutter SDK at all.
//
// Play still treats this as the Wear OS form factor of the same app: the
// applicationId in `app/build.gradle.kts` matches the phone app and the APK
// must be signed with the same upload key.

// gradlePluginPortal() is deliberately absent (supply-chain finding S2,
// SUPPLY_CHAIN_AUDIT_20260810.md): AGP resolves from google(), the Kotlin
// plugin markers resolve from mavenCentral(). Verified 2026-08-10 in Colima.
pluginManagement {
    repositories {
        google()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "wins_vpn_wear"

include(":app")
