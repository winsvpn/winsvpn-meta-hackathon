plugins {
    // AGP 9 has built-in Kotlin support; the standalone Kotlin plugin is
    // rejected, exactly as in the shipping app's build file.
    id("com.android.application")
}

// Environment-provided signing, mirroring the shipping app's rule exactly:
// all four WINS_ANDROID_* values together, or none. A keystore is NEVER taken
// from a repository-local file -- the path comes from the process environment
// only, so a stray committed keystore can never sign this harness.
val environmentSigning = mapOf(
    "storeFile" to System.getenv("WINS_DEVICECHECK_KEYSTORE")?.trim(),
    "keyAlias" to System.getenv("WINS_DEVICECHECK_KEY_ALIAS")?.trim(),
    "keyPassword" to System.getenv("WINS_DEVICECHECK_KEY_PASSWORD"),
    "storePassword" to System.getenv("WINS_DEVICECHECK_STORE_PASSWORD"),
)
val hasAnyEnvironmentSigning = environmentSigning.values.any { !it.isNullOrEmpty() }
val hasCompleteEnvironmentSigning = environmentSigning.values.all { !it.isNullOrEmpty() }
if (hasAnyEnvironmentSigning && !hasCompleteEnvironmentSigning) {
    throw GradleException(
        "WINS_DEVICECHECK_KEYSTORE, WINS_DEVICECHECK_KEY_ALIAS, WINS_DEVICECHECK_KEY_PASSWORD, and WINS_DEVICECHECK_STORE_PASSWORD must be supplied together.",
    )
}

android {
    // The namespace is org.winsvpn.app so the REAL host sources, copied in
    // byte-for-byte from android/app/src/main/kotlin/org/winsvpn/app/, compile
    // unmodified -- WinnAndroidEngineHost.kt refers to its own BuildConfig.
    // The APPLICATION ID is different, so this harness installs alongside the
    // shipping app and can never replace it.
    namespace = "org.winsvpn.app"
    compileSdk = 37
    ndkVersion = "30.0.16248370"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        buildConfig = true
    }

    defaultConfig {
        applicationId = "org.winsvpn.devicecheck"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "devicecheck"
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
        // connectedCheck drives :app:connectedDebugAndroidTest through this
        // runner. The hardware-attestation checks live in src/androidTest.
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // AGP creates instrumentation tasks only for testBuildType. Keep developer
    // evidence on debug, but select release whenever the owner supplies the
    // complete release-signing family so assembleReleaseAndroidTest exists and
    // the target plus test APKs share that exact signer.
    testBuildType = if (hasCompleteEnvironmentSigning) "release" else "debug"

    packaging {
        jniLibs {
            // Same rule as the shipping app: legacy packaging so the engine is
            // extracted into nativeLibraryDir as a real, executable file.
            useLegacyPackaging = true
        }
    }

    signingConfigs {
        // Only populated when ALL four WINS_ANDROID_* env values are present.
        // With none present the config stays empty and the debug variant's
        // Android debug key is used (the debug build), never a repo keystore.
        create("release") {
            if (hasCompleteEnvironmentSigning) {
                keyAlias = environmentSigning.getValue("keyAlias")
                keyPassword = environmentSigning.getValue("keyPassword")
                storeFile = rootProject.file(environmentSigning.getValue("storeFile")!!)
                storePassword = environmentSigning.getValue("storePassword")
            }
        }
    }

    buildTypes {
        getByName("debug") {
            isMinifyEnabled = false
            // The standalone devicecheck APK is what gets installed on the
            // phone, so when the complete WINS_ANDROID_* environment is present
            // it signs the DEBUG build with the release-keystore-family key too.
            // That is what lets on-device hardware key attestation bind back to
            // the release signing family rather than to the Android debug key.
            // With no environment present it keeps the ordinary Android debug
            // key, so a stray repo-local keystore can never sign this harness.
            if (hasCompleteEnvironmentSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
        getByName("release") {
            isMinifyEnabled = false
            if (hasCompleteEnvironmentSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    lint {
        abortOnError = false
    }
}

dependencies {
    // The SHIPPING AmneziaWG engine, referenced in place from the shipping
    // app's libs directory rather than copied, so the handshake this harness
    // proves is performed by the very libam-go.so that the release APK ships.
    // Nothing is written back to android/app.
    implementation(files("../../app/libs/amneziawg.aar"))

    // Pinned to the same version the shipping app declares. WinnCarrierProfile.kt
    // gained an @androidx.annotation.RequiresApi gate on 2026-08-08 -- the fix for
    // a NoClassDefFoundError that crashed every API 24/25 user on first connect --
    // and this harness copies that file in verbatim, so it needs the annotation on
    // its own classpath. Fully-qualified in the source, so no import drift here.
    implementation("androidx.annotation:annotation:1.11.0")

    // On-device hardware key attestation checks. androidTest needs the JUnit4
    // instrumentation runner and core. The runner 1.7.0 <-> monitor 1.8.0 and
    // ext-junit 1.3.0 set is what makes connectedCheck actually execute the
    // tests in src/androidTest, so connectedCheck is no longer a NO-SOURCE pass.
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:core:1.7.0")
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}
