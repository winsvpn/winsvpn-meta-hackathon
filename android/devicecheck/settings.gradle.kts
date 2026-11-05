// Standalone throwaway project. It is deliberately NOT included from
// android/settings.gradle.kts, so nothing here can reach the shipping
// application, its version, its application id, or its signing config.
// gradlePluginPortal() is deliberately absent (supply-chain finding S2,
// SUPPLY_CHAIN_AUDIT_20260810.md): AGP resolves from google() only.
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

plugins {
    id("com.android.application") version "9.4.1" apply false
}

rootProject.name = "winn-devicecheck"
include(":app")
