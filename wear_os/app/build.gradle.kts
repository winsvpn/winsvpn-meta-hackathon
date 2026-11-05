// Release signing mirrors `android/app/build.gradle.kts` on purpose: Play only
// accepts this APK as the Wear OS form factor of org.winsvpn.app if it is
// signed with the same upload key as the phone APK, and the phone build already
// refuses to materialise that key from anything but the process environment.
val environmentSigning = mapOf(
    "storeFile" to System.getenv("WINS_ANDROID_KEYSTORE")?.trim(),
    "keyAlias" to System.getenv("WINS_ANDROID_KEY_ALIAS")?.trim(),
    "keyPassword" to System.getenv("WINS_ANDROID_KEY_PASSWORD"),
    "storePassword" to System.getenv("WINS_ANDROID_STORE_PASSWORD"),
)
val hasAnyEnvironmentSigning = environmentSigning.values.any { !it.isNullOrEmpty() }
val hasCompleteEnvironmentSigning = environmentSigning.values.all { !it.isNullOrEmpty() }
if (hasAnyEnvironmentSigning && !hasCompleteEnvironmentSigning) {
    throw GradleException(
        "OWNER-BLOCKED: missing Android upload keystore. " +
            "WINS_ANDROID_KEYSTORE, WINS_ANDROID_KEY_ALIAS, WINS_ANDROID_KEY_PASSWORD, and WINS_ANDROID_STORE_PASSWORD must be supplied together.",
    )
}

// AGP 9 applies the Kotlin plugin itself, so `org.jetbrains.kotlin.android`
// must not be applied here -- it fails the build if it is.
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.winsvpn.app.wear"
    compileSdk = 37
    // Same stable NDK r30 pin as phone/TV. Wear does not package VPN engines, but
    // ABI filters and Play 16 KiB alignment still resolve against this NDK.
    ndkVersion = "30.0.16248370"

    defaultConfig {
        // Must equal the phone app's applicationId: Play identifies the Wear OS
        // APK as the same app by package name, and the Wearable Data Layer only
        // pairs a watch node with a phone node that shares the package name and
        // signing certificate.
        applicationId = "org.winsvpn.app"
        // Wear OS 3 and newer. Older watches run the phone-tethered Wear 2.x
        // stack, which this Compose UI does not target.
        minSdk = 30
        targetSdk = 37
        // OWNER ACTION: Play requires every APK in a single release to carry a
        // distinct versionCode. Keep this above the phone APK's code (currently
        // 34) and bump both together. Scheme: phone <code>*100 + 1, so a phone
        // bump moves the watch to 3401.
        versionCode = 3401
        versionName = "1.0.17"
        ndk {
            // Exact Wear Play ABI set. Native Winn v3 / AWG / Xray engines are
            // not packaged here; they remain on the paired phone form factor.
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }

    signingConfigs {
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
        getByName("release") {
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

// Same fail-fast contract as the phone build: refuse to even start a release
// packaging task without a complete signing environment, rather than silently
// emitting a debug-signed watch APK that Play would reject at upload.
//
// THE MATCHES ARE EXACT, AND THAT MATTERS -- this module had the phone
// build's own bug, uncorrected: `startsWith("packageRelease")` also caught
// `:app:packageReleaseResources`, an AAPT2 step that signs nothing, needs no
// key, and is a dependency of `lintRelease` as well as of the real packaging
// tasks. Through it this gate was refusing lint on release sources, so
// nobody had ever run it; found while establishing what this module's build
// actually supports (2026-08-08), narrowed the same way
// `android/app/build.gradle.kts` was narrowed earlier the same day.
//
// Both real signing paths stay fail-closed, because each is caught more than
// once: `assembleRelease` schedules `:app:assembleRelease` AND
// `:app:packageRelease`; `bundleRelease` schedules `:app:bundleRelease`,
// `:app:packageReleaseBundle` AND `:app:signReleaseBundle`. There is no way
// to reach a signed artifact without one of these exact names appearing in
// the graph.
fun wearCompanionMustNotPackagePhoneVpnEngines() {
    val forbidden = listOf(
        "libwinnengine.so",
        "libam-go.so",
        "libam.so",
        "libam-quick.so",
        "libxray.so",
        "amneziawg.aar",
    )
    val roots = listOf(file("src"), file("libs"))
    val hits = forbidden.filter { name ->
        roots.any { root ->
            root.isDirectory && fileTree(root) { include("**/$name") }.files.any { it.isFile }
        }
    }
    if (hits.isNotEmpty()) {
        throw GradleException(
            "Wear OS companion must not package phone VPN engines. " +
                "Winn v3 primary and Winn v1 AWG/Xray fallback remain on the paired phone. " +
                "Found: ${hits.sorted().joinToString(", ")}",
        )
    }
}

fun verifyWearReleaseIdentityAndApi37() {
    val androidExt = extensions.getByType<com.android.build.api.dsl.ApplicationExtension>()
    if (androidExt.compileSdk != 37) {
        throw GradleException(
            "Wear compileSdk must remain 37 for the 2026-10-06 API-37 adoption ruling.",
        )
    }
    if (androidExt.ndkVersion != "30.0.16248370") {
        throw GradleException(
            "Wear ndkVersion must remain 30.0.16248370 (NDK r30) for the 2026-10-06 API-37 adoption ruling.",
        )
    }
    val releaseDefaults =
        androidExt.javaClass.getMethod("getDefaultConfig").invoke(androidExt)
            as com.android.build.api.dsl.ApplicationDefaultConfig
    if (releaseDefaults.applicationId != "org.winsvpn.app") {
        throw GradleException("Wear applicationId must be org.winsvpn.app.")
    }
    if (!releaseDefaults.applicationIdSuffix.isNullOrEmpty()) {
        throw GradleException("Wear applicationIdSuffix would contaminate the shared Play package.")
    }
    val wearCode = releaseDefaults.versionCode
    if (wearCode == null || wearCode <= 3301) {
        throw GradleException("Wear OS versionCode $wearCode does not clear observed floor 3301.")
    }
    if (wearCode != 3401) {
        throw GradleException("Wear versionCode must be 3401 for 1.0.17+34.")
    }
    if (releaseDefaults.versionName != "1.0.17") {
        throw GradleException("Wear versionName must be 1.0.17 for 1.0.17+34.")
    }
    if (releaseDefaults.minSdk != 30) {
        throw GradleException("Wear minSdk must remain 30 for Wear OS 3+.")
    }
    if (releaseDefaults.targetSdk != 37) {
        throw GradleException(
            "Wear targetSdk must remain 37 for the 2026-10-06 API-37 adoption ruling.",
        )
    }
    val release = androidExt.buildTypes.getByName("release")
    if (!release.isMinifyEnabled || !release.isShrinkResources) {
        throw GradleException("Wear release requires R8 minify and resource shrinking.")
    }
}

fun wearReleaseSigningIsOwnerUploadKey() {
    if (!hasCompleteEnvironmentSigning) {
        throw GradleException(
            "OWNER-BLOCKED: missing Android upload keystore. " +
                "The Wear OS AAB must be signed with the same upload key as the phone APK; " +
                "debug and test keys are refused.",
        )
    }
    val keystore = environmentSigning.getValue("storeFile")!!
    val alias = environmentSigning.getValue("keyAlias")!!
    if (!keystore.startsWith("/")) {
        throw GradleException(
            "OWNER-BLOCKED: WINS_ANDROID_KEYSTORE must be an absolute external path.",
        )
    }
    val keystoreName = keystore.substringAfterLast('/').lowercase()
    val foldedAlias = alias.lowercase()
    if (
        "debug" in keystoreName ||
        "debug" in foldedAlias ||
        "test" in keystoreName ||
        "test" in foldedAlias
    ) {
        throw GradleException(
            "OWNER-BLOCKED: Wear release must not use a debug or test key.",
        )
    }
}

val appProjectPath = project.path
gradle.taskGraph.whenReady {
    val requestsReleaseArtifact = allTasks.any { task ->
        task.project.path == appProjectPath &&
            (task.name == "assembleRelease" ||
                task.name == "bundleRelease" ||
                task.name == "packageRelease" ||
                task.name == "packageReleaseBundle" ||
                task.name.startsWith("signRelease"))
    }
    if (requestsReleaseArtifact) {
        wearCompanionMustNotPackagePhoneVpnEngines()
        verifyWearReleaseIdentityAndApi37()
        wearReleaseSigningIsOwnerUploadKey()
    }
}

dependencies {
    // compileSdk is 37 (2026-10-06 owner decision), the newest stable platform
    // AGP 9.4 supports, so the newest stables whose AAR minCompileSdk is 37
    // (core-ktx 1.19.x, lifecycle 2.11.x) are now in range.
    implementation("androidx.core:core-ktx:1.19.1")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.11.0")

    implementation("androidx.wear.compose:compose-material:1.7.0")
    implementation("androidx.wear.compose:compose-foundation:1.7.0")
    implementation("androidx.compose.material:material-icons-core:1.7.8")

    // Wearable Data Layer: MessageClient (commands) + DataClient (state).
    // 20.0.1 is the phone app's pin and the latest stable (Google recommends
    // it as the minimum for apps targeting API 37). The pairing contract
    // requires the watch and phone to resolve the same artifact; both move
    // together.
    implementation("com.google.android.gms:play-services-wearable:20.0.1")
    // `Task<T>.await()`, so the Data Layer calls read as straight-line code.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-play-services:1.11.0")

    testImplementation("junit:junit:4.13.2")
    // Android ships org.json, but the JVM unit-test classpath does not, so the
    // snapshot parser can be exercised without an emulator.
    testImplementation("org.json:json:20260814")
}
