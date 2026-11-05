import com.android.build.api.dsl.ApplicationExtension
import com.flutter.gradle.tasks.FlutterTask
import java.nio.file.Files
import java.nio.file.LinkOption
// Imported, never written qualified: inside a Gradle Kotlin script `java` is the
// project's java extension accessor, so a fully qualified java security class
// name does not resolve there and the whole script fails to compile for every
// task, debug included.
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.zip.ZipFile
import org.gradle.kotlin.dsl.support.serviceOf

val androidReleaseAbis = listOf("arm64-v8a", "x86_64", "armeabi-v7a")
val androidReleaseStagedEngines =
    listOf("libwinnengine.so", "libwinn_tun_bulk.so")
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
        "WINS_ANDROID_KEYSTORE, WINS_ANDROID_KEY_ALIAS, WINS_ANDROID_KEY_PASSWORD, and WINS_ANDROID_STORE_PASSWORD must be supplied together.",
    )
}

// Explicit opt-in for producing an UNSIGNED release artifact. Play-upload
// signing happens out-of-band with the owner's upload key, which is not
// present on this host; the owner signs this host's output elsewhere. Fail
// closed: the flag refuses to coexist with ANY signing input, and the release
// variant is then built with NO signing config at all, so neither a real key
// nor the Android debug key can ever be used to sign a release build.
val unsignedReleaseRequested =
    System.getenv("WINS_ANDROID_UNSIGNED_RELEASE")?.trim() == "1"
if (unsignedReleaseRequested && hasAnyEnvironmentSigning) {
    throw GradleException(
        "WINS_ANDROID_UNSIGNED_RELEASE is set but Android signing input is also present. " +
            "An unsigned bundle cannot be requested with signing credentials in the environment.",
    )
}

plugins {
    id("com.android.application")
    id("dev.flutter.flutter-gradle-plugin")
}

extensions.configure<ApplicationExtension> {
    namespace = "org.winsvpn.app"
    // Pinned explicitly so a future Flutter release cannot silently bump the
    // compile/target SDK. Owner decision 2026-10-06 ("bump ... SDKs and
    // everything else to latest"): API 37 (Android 17) is the latest stable
    // platform AGP 9.4 supports, one level above Flutter's own default (36).
    compileSdk = 37
    // Pin the latest final stable NDK (r30 LTS, released 2026-09-08) so native
    // engine builds never fall back to a host-dependent toolchain selection.
    ndkVersion = "30.0.16248370"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        buildConfig = true
    }

    defaultConfig {
        applicationId = "org.winsvpn.app"
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // Pinned explicitly (not flutter.targetSdkVersion) so the release is
        // never silently bumped by a Flutter-default change. Value 37 follows
        // the 2026-10-06 owner decision; the Android 17 runtime-behavior
        // qualification items live in docs/rulings/ANDROID_API37_ADOPTION_20261006.json.
        targetSdk = 37
        versionCode = 34
        versionName = "1.0.17"
        ndk {
            // Every declared ABI must carry the complete release engine set:
            // standalone Winn v3 plus the explicitly selected Winn v1
            // AmneziaWG/Xray path. The release graph below refuses any partial
            // ABI rather than shipping a device-specific missing-engine trap.
            abiFilters += androidReleaseAbis
        }
    }

    // TV is a PRODUCT FLAVOR, not a build type. The deliverable is the tv
    // flavor's RELEASE variant (`assembleTvRelease` -> `app-tv-release.apk`),
    // built under the unsigned-release gate in the same way as the phone
    // release: the gate in the release build type below nulls the signing
    // config. A flavor (rather than the old `tv` build type, which was
    // debug-based and never reached release signing) is what makes the
    // `tv <-> release` cross-product exist and a store-ready unsigned APK
    // buildable end to end.
    //
    // The `tv` flavor activates the `src/tv/` source set (manifest, res,
    // banner) automatically -- AGP wires `src/<flavorName>/` for manifests,
    // res and Java -- so no manual sourceSets wiring is needed. That source
    // set carries the Android TV manifest which declares BOTH
    // `android.software.leanback` and `android.hardware.touchscreen` as NOT
    // required, so a TV form factor (no touchscreen) can install the app.
    // Never disguises on TV.
    flavorDimensions += "formFactor"
    productFlavors {
        // `phone` MUST exist and MUST be declared first. Gradle requires every
        // variant to take a flavor from each declared dimension, so with `tv` as
        // the only flavor there was NO phone variant at all: every release build
        // became tvRelease. Phone and TV intentionally share `org.winsvpn.app`
        // so Play can attach TV as a form factor of the existing listing.
        // Measured 2026-08-11: `gradlew :app:tasks --all` listed tvRelease and no
        // phone equivalent. `phone` carries no suffix, so the store package stays
        // exactly `org.winsvpn.app` as Play Console expects.
        create("phone") {
            dimension = "formFactor"
            isDefault = true
        }
        create("tv") {
            dimension = "formFactor"
            // Follow wear_os versionCode scheme (lines 40-45): phone*100+offset
            // so every form factor sorts above the phone and distinct from each
            // other. Phone is 34, wear is 3401 (34*100+1), and TV is 3402
            // (34*100+2). Bump all form factors with the pubspec build number.
            // Distinct codes matter because Play serves phone, Wear, and TV
            // form factors under the same application ID.
            versionCode = 3402
        }
    }

    signingConfigs {
        create("release") {
            if (hasCompleteEnvironmentSigning) {
                keyAlias = environmentSigning.getValue("keyAlias")
                keyPassword = environmentSigning.getValue("keyPassword")
                storeFile = rootProject.file(environmentSigning.getValue("storeFile")!!)
                storePassword = environmentSigning.getValue("storePassword")
                enableV1Signing = true
                enableV2Signing = true
                // tools/verify_android_aab_signers.py requires APK Signature
                // Scheme v2 and v3 on every release APK.
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        // The debug variant installs ALONGSIDE the store build instead of
        // replacing it.
        //
        // Without a suffix the debug variant is also `org.winsvpn.app`, and
        // because it is signed with the debug key rather than the release key,
        // Android refuses to install it over the store build: the only way to
        // put a debug build on a device that already has the release one is to
        // UNINSTALL the release build first. On the owner's own device that is
        // destructive and partly irreversible -- `SecureFileStore` holds
        // `client_keypair.json`, `user_pin.txt` and `install_id.txt`, and the
        // install id regenerates on reinstall, which is what enforces the
        // three-device limit, so a reinstall burns a device slot on top of
        // losing the PIN and the keypair.
        //
        // A distinct application id removes the choice entirely: the two builds
        // are different packages to the package manager and simply coexist.
        //
        // This is safe in this codebase, which was verified rather than
        // assumed:
        //   - Winn engine discovery does not key off the application id. The
        //     channel name is `winn-engine-<32 random hex>`
        //     (`WinnAndroidEngineHost.newChannelName`) and the binary is found
        //     through `context.applicationInfo.nativeLibraryDir`
        //     (`resolveEngineExecutable`), both of which follow the package
        //     they run in.
        //   - There is no `google-services.json`, no Play Integrity, no
        //     SafetyNet, no attestation and no signature pinning anywhere in
        //     the app or in the Dart layer, so nothing checks the package name
        //     or certificate against a registered value.
        //
        // RELEASE IS UNAFFECTED. This block adds no suffix to the release
        // variant, and does not touch the version, the application id or the
        // signing config.
        //
        // Known consequence, and a desirable one: the Wear OS companion pairs
        // over the Data Layer, which matches on package name AND signature, so
        // the watch will not pair with the debug build. That is correct -- it
        // keeps the watch bound to the real app.
        getByName("debug") {
            applicationIdSuffix = ".debug"
        }

        // A `test` variant installs ALONGSIDE the debug and store builds, for
        // QA to exercise a signed identity that is distinct from the debug
        // build. It is signed with the Android debug key: the release key
        // signs only artifacts that pass the release gate below.
        // A `qa` variant installs ALONGSIDE the debug and store builds, for
        // QA to exercise a signed identity that is distinct from the debug
        // build. Its application id is org.winsvpn.app.test. The qa build
        // type has no R8, no Dart obfuscation, no engine/identity gate and no
        // src/release manifest hardening, so it never gets the release key. (Named `qa` not
        // `test`: AGP rejects buildType names starting with "test".)
        // The `.debug` suffix and the store build (no suffix) are untouched.
        create("qa") {
            applicationIdSuffix = ".test"
            signingConfig = signingConfigs.getByName("debug")
        }

        getByName("release") {
            signingConfig =
                if (unsignedReleaseRequested) null else signingConfigs.getByName("release")
            // Flutter's release pipeline owns native symbol extraction. A
            // manual debugSymbolLevel override prevents AGP from producing the
            // libapp.so metadata that Flutter validates before accepting AABs.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    packaging {
        jniLibs {
            // Required so the bundled Xray Android binary can be copied/executed as libxray.so.
            useLegacyPackaging = true
            excludes += listOf(
                "**/x86/*.so",
                "**/libam-quick.so",
                "**/libam.so",
                // Android refuses Xray (VpnTunnelService.kt:1451); never ship it.
                "**/libxray.so",
            )
        }
    }

    if (providers.gradleProperty("wins.apkAbiSplits").orNull == "true") {
        defaultConfig.ndk.abiFilters.clear()
        splits {
            abi {
                isEnable = true
                reset()
                include(*androidReleaseAbis.toTypedArray())
                isUniversalApk = false
            }
        }
    }

    lint {
        // Flutter regenerates android/local.properties with Windows-style paths.
        // Keep release lint focused on app/package issues instead of local SDK metadata.
        disable += "PropertyEscape"
    }
}

// Flutter's release entry points ultimately schedule one of these packaging
// tasks. Fail as soon as Gradle has the task graph, before compilation or
// packaging begins, while leaving debug and inspection tasks usable without
// materializing signing secrets in every developer process.
//
// THE MATCHES ARE EXACT, AND THAT MATTERS. `startsWith("packageRelease")` also
// caught `:app:packageReleaseResources` -- an AAPT2 step that signs nothing,
// needs no key, and is a dependency of every release task. Through it the
// guard was refusing `compileReleaseKotlin`, `minifyReleaseWithR8`,
// `lintRelease` and `lintVitalRelease` as well, so R8, resource shrinking and
// lint's `NewApi` check had never once run on this code and release-only
// breakage was invisible.
//
// Both real signing paths stay fail-closed, because each is caught more than
// once: `assembleRelease` schedules `:app:assembleRelease` AND
// `:app:packageRelease`; `bundleRelease` schedules `:app:bundleRelease`,
// `:app:packageReleaseBundle` AND `:app:signReleaseBundle`. There is no way to
// reach a signed artifact without one of these names appearing in the graph.
val appProjectPath = project.path

fun isSafeNonEmptyReleaseInput(file: File): Boolean =
    Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS) && file.length() > 0L

// Signed Winn release stamp. `android/tools/prepare_android_winn_assets.sh
// --stage-release DIR` verifies DIR once with `tools/winn_release.py verify`
// (Ed25519 signature by the pinned release authority key, every artifact
// sha256, two byte-identical builds) and writes src/<variant>/winn-release.json.
// --stage (dev) writes no stamp and deletes any existing one, so a release
// build can only package Winn engines that came out of a signed release.
// The stamp retains the signed release manifest and its detached signature.
// Release packaging authenticates that payload under the pinned key in
// tools/winn_release_authority.json and checks the selected engine against
// the signed manifest entry; no hex-shaped stamp field is trusted.
val winnReleaseStampName = "winn-release.json"
val winnReleaseStampContract = "winsvpn-winn-release-android-stage-v1"
val winnReleaseAbiTargets =
    mapOf(
        "arm64-v8a" to "datapath-android-arm64",
        "armeabi-v7a" to "datapath-android-arm",
        "x86_64" to "datapath-android-amd64",
    )

fun sha256Hex(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buffer = ByteArray(1 shl 20)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            digest.update(buffer, 0, read)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

// Returns null when the stamp binds these exact engine bytes to a manifest
// signed by the pinned release authority, else the problem.
fun verifyWinnReleaseStamp(abi: String, engine: File, stamp: File): String? {
    val where = stamp.relativeTo(projectDir).path
    return try {
        fun objectFrom(text: String): Map<*, *> =
            groovy.json.JsonSlurper().parseText(text) as? Map<*, *>
                ?: throw IllegalArgumentException("expected a JSON object")

        fun hex(value: Any?, bytes: Int): ByteArray {
            val text = value as? String
                ?: throw IllegalArgumentException("missing hexadecimal value")
            require(Regex("[0-9a-f]{${bytes * 2}}").matches(text)) {
                "invalid hexadecimal value"
            }
            return ByteArray(bytes) { index ->
                text.substring(index * 2, index * 2 + 2).toInt(16).toByte()
            }
        }

        require(isSafeNonEmptyReleaseInput(stamp) && stamp.length() <= 4L * 1024 * 1024) {
            "missing or invalid release stamp; stage with " +
                "android/tools/prepare_android_winn_assets.sh --stage-release <signed release dir>"
        }
        require(isSafeNonEmptyReleaseInput(engine)) {
            "missing or invalid staged engine"
        }
        val envelope = objectFrom(stamp.readText(Charsets.UTF_8))
        require(envelope["contract"] == winnReleaseStampContract) {
            "invalid stamp contract"
        }
        val payload = Base64.getDecoder().decode(
            envelope["manifest_b64"] as? String
                ?: throw IllegalArgumentException("missing signed manifest"),
        )
        val signatureBytes = hex(envelope["manifest_signature"], 64)
        val authorityFile = rootProject.file("../tools/winn_release_authority.json")
        require(
            isSafeNonEmptyReleaseInput(authorityFile) &&
                authorityFile.length() <= 64L * 1024,
        ) { "invalid release authority file" }
        val authority = objectFrom(authorityFile.readText(Charsets.UTF_8))
        require(
            authority["contract"] == "winsvpn-winn-release-authority-v1" &&
                authority["algorithm"] == "ed25519",
        ) { "invalid release authority" }
        val publicKey = KeyFactory.getInstance("Ed25519").generatePublic(
            X509EncodedKeySpec(
                hex("302a300506032b6570032100", 12) +
                    hex(authority["public_key"], 32),
            ),
        )
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(publicKey)
        verifier.update("WINSVPN-WINN-RELEASE-MANIFEST-V1\u0000".toByteArray(Charsets.US_ASCII))
        verifier.update(payload)
        require(verifier.verify(signatureBytes)) {
            "release signature does not verify"
        }
        val manifest = objectFrom(payload.toString(Charsets.UTF_8))
        require(manifest["contract"] == "winsvpn-winn-release-manifest-v1") {
            "invalid manifest contract"
        }
        val target = winnReleaseAbiTargets.getValue(abi)
        val entries = manifest["artifacts"] as? List<*>
            ?: throw IllegalArgumentException("manifest has no artifacts")
        val row = entries.mapNotNull { it as? Map<*, *> }
            .filter { it["target"] == target }
            .singleOrNull()
            ?: throw IllegalArgumentException("expected exactly one entry for $target")
        val digest = sha256Hex(engine)
        require(
            row["sha256"] == digest &&
                row["build_a_sha256"] == digest &&
                row["build_b_sha256"] == digest &&
                row["size"].toString() == engine.length().toString(),
        ) { "staged engine differs from the signed manifest" }
        null
    } catch (exc: Exception) {
        "$abi/libwinnengine.so: $where: ${exc.message ?: exc.javaClass.simpleName}"
    }
}

fun verifyAndroidReleaseEngineInputs() {
    val missing = mutableListOf<String>()
    for (abi in androidReleaseAbis) {
        for (engine in androidReleaseStagedEngines) {
            // OI-13 (Round 36 treaty): validate the file the build actually
            // packages. The src/release source set shadows src/main, so an
            // unsafe release-side file must fail the gate even when a safe
            // main candidate exists behind it; the old "any safe candidate"
            // check could be satisfied by the file that loses the shadowing
            // contest.
            val releaseCandidate = file("src/release/jniLibs/$abi/$engine")
            val selected =
                if (Files.exists(releaseCandidate.toPath(), LinkOption.NOFOLLOW_LINKS)) {
                    releaseCandidate
                } else {
                    file("src/main/jniLibs/$abi/$engine")
                }
            if (!isSafeNonEmptyReleaseInput(selected)) {
                missing += "$abi/$engine (selected: ${selected.relativeTo(projectDir)})"
            } else if (engine == "libwinnengine.so") {
                // The Winn engine must come from a signed Winn release: the
                // source set that wins the shadowing contest must carry the
                // winn-release.json stamp written by
                // `prepare_android_winn_assets.sh --stage-release`, and the
                // packaged bytes must hash to the stamp's entry for this ABI.
                val sourceSetDir = selected.parentFile.parentFile.parentFile
                verifyWinnReleaseStamp(abi, selected, File(sourceSetDir, winnReleaseStampName))
                    ?.let { missing += it }
            }
        }
    }

    val awgArchive = file("libs/amneziawg.aar")
    if (!isSafeNonEmptyReleaseInput(awgArchive)) {
        missing += "libs/amneziawg.aar"
    } else {
        try {
            ZipFile(awgArchive).use { archive ->
                val entries = archive.entries().asSequence().toList()
                for (abi in androidReleaseAbis) {
                    val member = "jni/$abi/libam-go.so"
                    val matches = entries.filter { it.name == member && !it.isDirectory }
                    val entry = matches.singleOrNull()
                    if (entry == null || entry.size <= 0L) {
                        missing += "$member in libs/amneziawg.aar"
                    }
                }
            }
        } catch (error: Exception) {
            throw GradleException("Cannot inspect Android AmneziaWG release archive.", error)
        }
    }

    if (missing.isNotEmpty()) {
        throw GradleException(
            "Android release engine inputs are incomplete. Required for every declared ABI: " +
                "libwinnengine.so (Winn v3, staged from a signed Winn release with its winn-release.json stamp), " +
                "libwinn_tun_bulk.so (the bulk tun reader; run android/tools/build_winn_tun_bulk.sh, " +
                "which installs it into every shipping source set) " +
                "and libam-go.so (AmneziaWG). " +
                "Missing or unsafe: ${missing.sorted().joinToString(", ")}",
        )
    }
}

fun verifyAndroidReleaseIdentityAndApi37() {
    val androidExt = extensions.getByType<ApplicationExtension>()
    if (androidExt.compileSdk != 37) {
        throw GradleException(
            "Android compileSdk must remain 37 for the 2026-10-06 API-37 adoption ruling.",
        )
    }
    if (androidExt.ndkVersion != "30.0.16248370") {
        throw GradleException(
            "Android ndkVersion must remain 30.0.16248370 (NDK r30) for the 2026-10-06 API-37 adoption ruling.",
        )
    }
    val releaseDefaults =
        androidExt.javaClass.getMethod("getDefaultConfig").invoke(androidExt)
            as com.android.build.api.dsl.ApplicationDefaultConfig
    val applicationId = releaseDefaults.applicationId
    if (applicationId != "org.winsvpn.app") {
        throw GradleException("Android applicationId must be org.winsvpn.app.")
    }
    if (applicationId == "com.example.wins_vpn") {
        throw GradleException("Android applicationId must not be the stale debug package.")
    }
    val phoneCode = releaseDefaults.versionCode
    if (phoneCode == null || phoneCode <= 33) {
        throw GradleException("Android phone versionCode $phoneCode does not clear observed floor 33.")
    }
    if (phoneCode != 34) {
        throw GradleException("Android phone versionCode must be 34 for 1.0.17+34.")
    }
    if (releaseDefaults.versionName != "1.0.17") {
        throw GradleException("Android versionName must be 1.0.17 for 1.0.17+34.")
    }
    if (releaseDefaults.targetSdk != 37) {
        throw GradleException(
            "Android targetSdk must remain 37 for the 2026-10-06 API-37 adoption ruling.",
        )
    }
    val phone = androidExt.productFlavors.getByName("phone")
    val television = androidExt.productFlavors.getByName("tv")
    if (!phone.applicationIdSuffix.isNullOrEmpty()) {
        throw GradleException("phone flavor must not add an applicationIdSuffix.")
    }
    if (!television.applicationIdSuffix.isNullOrEmpty() ||
        (television.applicationId != null && television.applicationId != "org.winsvpn.app")
    ) {
        throw GradleException(
            "TV flavor must share applicationId org.winsvpn.app; a distinct TV package is contamination.",
        )
    }
    val tvCode = television.versionCode
    if (tvCode == null || tvCode <= 3302) {
        throw GradleException("TV flavor versionCode $tvCode does not clear observed floor 3302.")
    }
    if (tvCode != 3402) {
        throw GradleException("TV flavor versionCode must be 3402 for 1.0.17+34.")
    }
    val release = androidExt.buildTypes.getByName("release")
    if (!release.isMinifyEnabled || !release.isShrinkResources) {
        throw GradleException("Android release requires R8 minify and resource shrinking.")
    }
}

fun verifyAndroidReleaseR8AndFlutterObfuscation(tasks: Collection<org.gradle.api.Task>) {
    val dartObfuscationProperty = findProperty("dart-obfuscation")?.toString()?.toBoolean() == true
    val splitDebugInfoProperty = findProperty("split-debug-info")?.toString()
    if (!dartObfuscationProperty) {
        throw GradleException(
            "Android release requires Flutter Dart obfuscation. Build with " +
                "flutter build ... --release --obfuscate --split-debug-info=<private dir>.",
        )
    }
    if (splitDebugInfoProperty.isNullOrBlank()) {
        throw GradleException(
            "Android release requires Flutter --split-debug-info for private symbol custody.",
        )
    }
    val flutterTasks = tasks.filterIsInstance<FlutterTask>().filter { task ->
        task.project.path == appProjectPath &&
            task.buildMode?.equals("release", ignoreCase = true) == true
    }
    if (flutterTasks.isEmpty()) {
        throw GradleException(
            "Android release packaging scheduled without a release FlutterTask; " +
                "Flutter --obfuscate / --split-debug-info cannot be verified.",
        )
    }
    for (task in flutterTasks) {
        if (task.dartObfuscation != true) {
            throw GradleException(
                "Android release requires Flutter Dart obfuscation. Build with " +
                    "flutter build ... --release --obfuscate --split-debug-info=<private dir>.",
            )
        }
        if (task.splitDebugInfo.isNullOrBlank()) {
            throw GradleException(
                "Android release requires Flutter --split-debug-info for private symbol custody.",
            )
        }
    }
}

gradle.taskGraph.whenReady {
    val requestsReleaseArtifact = allTasks.any { task ->
        task.project.path == appProjectPath &&
            (task.name == "assembleRelease" ||
                task.name == "assemblePhoneRelease" ||
                task.name == "assembleTvRelease" ||
                task.name == "bundleRelease" ||
                task.name == "bundlePhoneRelease" ||
                task.name == "bundleTvRelease" ||
                task.name == "packageRelease" ||
                task.name == "packagePhoneRelease" ||
                task.name == "packageTvRelease" ||
                task.name == "packageReleaseBundle" ||
                task.name == "packagePhoneReleaseBundle" ||
                task.name == "packageTvReleaseBundle" ||
                task.name.startsWith("signRelease") ||
                task.name.startsWith("signPhoneRelease") ||
                task.name.startsWith("signTvRelease"))
    }
    if (requestsReleaseArtifact) {
        verifyAndroidReleaseEngineInputs()
        verifyAndroidReleaseIdentityAndApi37()
        verifyAndroidReleaseR8AndFlutterObfuscation(allTasks)
        // GRADLE_USER_HOME/gradle.properties outranks the project file, so the
        // effective mode must be checked, not just the checked-in property.
        if (gradle.startParameter.dependencyVerificationMode !=
            org.gradle.api.artifacts.verification.DependencyVerificationMode.STRICT
        ) {
            throw GradleException(
                "Android release requires strict Gradle dependency verification " +
                    "(check android/gradle.properties, GRADLE_USER_HOME/gradle.properties and the command line).",
            )
        }
    }
    if (requestsReleaseArtifact &&
        !hasCompleteEnvironmentSigning &&
        !unsignedReleaseRequested
    ) {
        throw GradleException(
            "Missing Android release signing input. Use the owner-only current-user DPAPI preseed or the complete WINS_ANDROID_* process environment; never use a repository-local properties file or the Android debug key.",
        )
    }
}

flutter {
    source = "../.."
}

dependencies {
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.aar", "*.jar"))))
    implementation("androidx.annotation:annotation:1.11.0")
    implementation("androidx.collection:collection:1.6.0")
    implementation("com.squareup.okhttp3:okhttp:5.5.0")
    implementation("com.squareup.okhttp3:okhttp-dnsoverhttps:5.5.0")
    // Wearable Data Layer, for the Wear OS companion in `wear_os/`. Used only
    // to exchange connect/disconnect intent and status with a paired watch; it
    // carries no analytics and no account data.
    implementation("com.google.android.gms:play-services-wearable:20.0.1")
    testImplementation("junit:junit:4.13.2")
    // Instrumented tests (src/androidTest/AndroidKillSwitchTest.kt) run on the
    // connected device; this is the commander-set that makes connectedCheck
    // execute them. Same family the sibling devicecheck module uses.
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test:core:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:rules:1.7.0")
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

// ShippedEngineFreshnessTest reads two things Gradle does not otherwise know
// the unit tests touch: the engines staged under `src/<variant>/jniLibs`, and
// the packaged APKs under `build/app/outputs`. Undeclared, they are invisible
// to up-to-date checking, so the guard does not re-run when the only thing
// that changed is the artifact it exists to inspect.
//
// MEASURED 2026-08-09, and the reason this block exists. The guard was pointed
// at an APK carrying a v3-less engine -- an APK it must fail, and does fail
// when it runs. `testDebugUnitTest` reported UP-TO-DATE, the build succeeded,
// and the JUnit XML on disk was still the previous run's file, unchanged, down
// to its timestamp. Nothing had executed. The exit status said PASS about an
// artifact no test had opened, which is the same false green in build-tool
// form that the guard itself was written to catch.
//
// The staged engines are declared as input files. The packaged APKs are
// declared as a fingerprint property instead, because they are the output of
// `packageDebug`/`packageRelease`: declaring them as an input file collection
// would make Gradle require the dependency and every unit-test run would
// assemble an APK first.
val winnStagedEngines =
    fileTree("src") { include("*/jniLibs/**/libwinnengine.so", "*/$winnReleaseStampName") }
val winnFreshnessSourceInputs =
    fileTree("../../winn_protocol_experimental") {
        include("**/*.go", "go.mod", "go.sum")
        exclude("**/vendor/**", "**/.git/**", "**/evidence/**")
    }
val winnFreshnessGateInputs =
    files(
        "../../tools/verify_shipped_native_artifact_freshness.py",
        "../../tools/build_winn_protocol_engine.sh",
        "../../tools/winn_release.py",
        "../../tools/toolchain-pins.json",
    )
val winnFreshnessGoRoot =
    providers.environmentVariable("WINS_FRESHNESS_GO_ROOT")
        .orElse(
            providers.systemProperty("user.home")
                .map { home -> "$home/.local/toolchains/go1.27.1" },
        )
val winnPackagedApkRoots = listOf(
    layout.buildDirectory.dir("outputs/apk"),
    layout.buildDirectory.dir("outputs/flutter-apk"),
)

// Winn v3 descriptor ring for Android release assemble.
//
// Flutter's plugin copies project.findProperty("dart-defines") onto
// FlutterTask.dartDefines (FlutterPlugin.kt). That property is a
// comma-separated list of base64("NAME=VALUE") blobs, then assemble is
// invoked with --DartDefines=... (BaseFlutterTaskHelper.kt). Extra Gradle
// properties cannot override a -Pdart-defines already set by
// `flutter build` (Project.findProperty prefers the command line).
// Mutating FlutterTask.dartDefines after the plugin configures the task
// is the injection point that still reaches String.fromEnvironment.
// Same encoding as Flutter encodeDartDefines (build_info.dart).
//
// "After the plugin configures the task" is the whole point, and a
// configureEach action on FlutterTask registered here is NOT after it.
// MEASURED 2026-09-23 on Flutter 3.44.6 / Gradle 9.7.1: the plugin
// registers each compileFlutterBuild* task from its applicationVariants
// callback with `tasks.register(name) { dartDefines = dartDefinesValue }`.
// Gradle runs container-level configureEach actions that already exist
// BEFORE that registration action (DefaultNamedDomainObjectCollection
// AbstractDomainObjectCreatingProvider), so the old append ran first, saw
// buildMode == null, and the plugin's plain assignment then overwrote it
// with the CLI value; the measured builds carried none of these defines
// from this file. The mutation below therefore runs when the task graph is
// ready: every FlutterTask is fully configured by then, and task inputs are
// not yet fingerprinted.
//
// Override policy. These six names are owned by this file: the four
// descriptor-ring names (three pubkeys and the ring digest) and the two
// activation gates (ENABLED_PLATFORMS, DUAL_AUTH).
//   debug and release (QA qualifies through its resolved release mode):
//     all six are appended exactly once. A CLI entry with the identical
//     value is dropped; a different value fails the build.
//   profile: no activation gate is added, and ring defines that are absent
//     stay absent (lib/ carries the reviewed ring as its defaults). A CLI
//     ring entry must carry the identical value; repeats are deduplicated.
//   any other or missing buildMode fails the build.
// Unrelated CLI defines keep their order. The same mode policy and the same
// expectations are enforced again by the execution guard below, which reads
// the exact field BaseFlutterTaskHelper turns into --DartDefines=.
//
// The merge relies on non-configuration-cache execution
// (org.gradle.configuration-cache=false in android/gradle.properties) and is
// not verified under the configuration cache, so a build that requests the
// cache and schedules a FlutterTask is refused.
//
// Identity is WIRE-FORM
// 52e91c72ca52d23059724e0a6c25c2f45bae574a85a84c884c5b7fd367cbf032
// never the ceremony MANIFEST digest
// 29c66c18f5aef6eb064e065a5d7c3c98aa1548f758ac6d19b19a9d4a7863e7fb
// Duplicate names keep the last occurrence (Flutter assemble / Apple gate).
val winn3ReleaseDartDefines =
    listOf(
        "V0lOU19XSU5OM19ERVNDUklQVE9SX1BVQktFWV9HMT1MMm1BWWRZSVhQQ0Z1Tm9INW50Z0JCdWJGU25ubHpJQW5Yd0t0dHBlaGFRPQ==",
        "V0lOU19XSU5OM19ERVNDUklQVE9SX1BVQktFWV9HMj1lVkNBSFdYcVVNMSttNW5sVnkySlIrUTQvbWtZR1R4bGsxMTlhaVFoODlNPQ==",
        "V0lOU19XSU5OM19ERVNDUklQVE9SX1BVQktFWV9HMz01M0poc1FCeEtINURHMTQ1TGNhQnVuT1g0bGJ0K0o3SnMwb1B5Sm5qOVEwPQ==",
        "V0lOU19XSU5OM19ERVNDUklQVE9SX1JJTkdfU0hBMjU2PTUyZTkxYzcyY2E1MmQyMzA1OTcyNGUwYTZjMjVjMmY0NWJhZTU3NGE4NWE4NGM4ODRjNWI3ZmQzNjdjYmYwMzI=",
        "V0lOU19XSU5OM19FTkFCTEVEX1BMQVRGT1JNUz1hbmRyb2lk",
        // Dual-signature gate: C-8. base64("WINS_WINN3_DUAL_AUTH=true").
        // Android's [winn] parser accepts the dual-signature attestation keys
        // and the native host can verify them, so the release build flips
        // this define for BOTH release and debug targets (the injection
        // below covers the two modes). lib/ reads it as
        // kWinn3DualAuthHostSupported and emits auth_ed25519/auth_mldsa65
        // only when it is set. test/android_winn3_dual_auth_define_test.dart
        // decodes this list and pins the define's presence.
        "V0lOU19XSU5OM19EVUFMX0FVVEg9dHJ1ZQ==",
    ).joinToString(",")

fun decodeWinn3DartDefine(blob: String): String =
    try {
        String(Base64.getDecoder().decode(blob), Charsets.UTF_8)
    } catch (error: IllegalArgumentException) {
        throw GradleException("A dart-define is not valid base64; cannot merge the Winn v3 ring.", error)
    }

val winn3PinnedDartDefines: Map<String, String> =
    winn3ReleaseDartDefines.split(",").associate { blob ->
        val entry = decodeWinn3DartDefine(blob)
        entry.substringBefore("=") to entry
    }

val winn3RingDefineNames =
    setOf(
        "WINS_WINN3_DESCRIPTOR_PUBKEY_G1",
        "WINS_WINN3_DESCRIPTOR_PUBKEY_G2",
        "WINS_WINN3_DESCRIPTOR_PUBKEY_G3",
        "WINS_WINN3_DESCRIPTOR_RING_SHA256",
    )
if (winn3PinnedDartDefines.size != 6 || !winn3PinnedDartDefines.keys.containsAll(winn3RingDefineNames)) {
    throw GradleException("winn3ReleaseDartDefines must pin the four ring names and the two activation gates.")
}

// The one mode policy for the merge and the execution guard. The plugin sets
// buildMode from the build type (FlutterPluginUtils.buildModeFor: "profile"
// by name, a debuggable type is "debug", anything else, QA included, is
// "release"). There is no task-name fallback: anything else is unresolved.
fun winn3FlutterTaskMode(task: FlutterTask): String =
    when (val mode = task.buildMode?.lowercase().orEmpty()) {
        "debug", "release", "profile" -> mode
        else -> throw GradleException(
            "${task.path}: Flutter buildMode '${task.buildMode}' is not debug, profile or release; " +
                "no Winn v3 define policy applies, refusing to compile.",
        )
    }

fun winn3DartDefineEntries(task: FlutterTask): List<Pair<String, String>> =
    task.dartDefines.orEmpty().split(",").map { it.trim() }.filter { it.isNotEmpty() }
        .map { blob -> blob to decodeWinn3DartDefine(blob) }

fun mergeWinn3DartDefines(task: FlutterTask) {
    val activates = winn3FlutterTaskMode(task) != "profile"
    val keptRing = mutableSetOf<String>()
    val entries = winn3DartDefineEntries(task)
    val kept =
        entries.filter { (_, entry) ->
            val name = entry.substringBefore("=")
            val pinned = winn3PinnedDartDefines[name]
            when {
                pinned == null -> true
                !activates && name !in winn3RingDefineNames -> true
                entry != pinned -> throw GradleException(
                    "${task.path}: --dart-define $name conflicts with the value pinned in " +
                        "android/app/build.gradle.kts. Remove it from the command line; the " +
                        "Winn v3 ring and its gates are not overridable.",
                )
                activates -> false
                else -> keptRing.add(name)
            }
        }.map { it.first }
    if (activates) {
        task.dartDefines = (kept + winn3ReleaseDartDefines).joinToString(",")
    } else if (kept.size != entries.size) {
        task.dartDefines = kept.joinToString(",")
    }
}

val winn3ConfigurationCache = project.serviceOf<org.gradle.api.configuration.BuildFeatures>().configurationCache

gradle.taskGraph.whenReady {
    val flutterTasks = tasks.withType<FlutterTask>().filter { hasTask(it) }
    if (flutterTasks.isNotEmpty() &&
        (winn3ConfigurationCache.requested.getOrElse(false) || winn3ConfigurationCache.active.getOrElse(false))
    ) {
        throw GradleException(
            "The Winn v3 dart-define merge is not verified under the Gradle configuration cache. " +
                "Build Flutter tasks without --configuration-cache.",
        )
    }
    flutterTasks.forEach { mergeWinn3DartDefines(it) }
}

// Execution-time proof, independent of how the merge above is wired: read
// the exact field BaseFlutterTaskHelper turns into --DartDefines= and fail
// before flutter assemble runs if the result breaks the policy above. Before
// this guard, a clobbered injection compiled without a word.
fun verifyWinn3DartDefines(task: FlutterTask) {
    val activates = winn3FlutterTaskMode(task) != "profile"
    val entries = winn3DartDefineEntries(task).map { it.second }
    for ((name, pinned) in winn3PinnedDartDefines) {
        val matches = entries.filter { it.substringBefore("=") == name }
        val ok =
            when {
                activates -> matches == listOf(pinned)
                name in winn3RingDefineNames -> matches.isEmpty() || matches == listOf(pinned)
                else -> true
            }
        if (!ok) {
            throw GradleException(
                "${task.path}: $name does not match the Winn v3 policy for this mode " +
                    "(found ${matches.size}, pinned value required).",
            )
        }
    }
}

tasks.withType<FlutterTask>().configureEach {
    doFirst("verifyWinn3DartDefines") { verifyWinn3DartDefines(this as FlutterTask) }
}

tasks.withType<Test>().configureEach {
    inputs.files(winnStagedEngines)
        .withPropertyName("winnStagedEngines")
        .withPathSensitivity(org.gradle.api.tasks.PathSensitivity.RELATIVE)
    inputs.files(winnFreshnessSourceInputs)
        .withPropertyName("winnFreshnessSourceInputs")
        .withPathSensitivity(org.gradle.api.tasks.PathSensitivity.RELATIVE)
    inputs.files(winnFreshnessGateInputs)
        .withPropertyName("winnFreshnessGateInputs")
        .withPathSensitivity(org.gradle.api.tasks.PathSensitivity.RELATIVE)
    inputs.file(winnFreshnessGoRoot.map { root -> file("$root/bin/go") })
        .withPropertyName("winnFreshnessReviewedGo")
        .withPathSensitivity(org.gradle.api.tasks.PathSensitivity.NONE)
        .optional()
    inputs.property("winnFreshnessGoRoot", winnFreshnessGoRoot)
    inputs.property(
        "winnFreshnessGoModCacheTreeSha256",
        providers.environmentVariable("WINS_STORE_GOMODCACHE_TREE_SHA256").orElse(""),
    )

    // Selecting a single APK must re-trigger the guard; otherwise the run that
    // narrows the check is the run that silently does not happen.
    inputs.property(
        "winnPackagedApkUnderTest",
        providers.environmentVariable("WINN_PACKAGED_APK_UNDER_TEST").orElse(""),
    )

    inputs.property(
        "winnPackagedApkFingerprint",
        providers.provider {
            winnPackagedApkRoots
                .map { it.get().asFile }
                .filter { it.isDirectory }
                .flatMap { root ->
                    root.walkTopDown()
                        .filter { it.isFile && it.name.endsWith(".apk") }
                        .map { "${it.relativeTo(root).path}:${it.length()}:${it.lastModified()}" }
                        .toList()
                }
                .sorted()
                .joinToString(";")
        },
    )
}
