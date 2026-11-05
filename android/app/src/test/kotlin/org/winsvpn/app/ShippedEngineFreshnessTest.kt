package org.winsvpn.app

import java.io.File
import java.util.concurrent.TimeUnit
import java.util.zip.ZipFile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Asserts things about the engine binary the APK ACTUALLY PACKAGES -- by
 * opening the APK.
 *
 * WHY THIS EXISTS, AND WHY [WinnEngineInteropTest] IS NOT ENOUGH.
 *
 * WinnEngineInteropTest drives the real Go engine over the real framing and is
 * thorough about it -- argv, frame bytes, opcode vocabulary, config schema,
 * carrier profiles, SPA, mutation checks. Every assertion in it is sound. But
 * look at how it obtains the engine: `WINN_DATAPATH_BINARY`, else `go build` of
 * `./cmd/winn-datapath` into a temp file. It tests a binary compiled from
 * source, at test time, and throws it away.
 *
 * On 2026-08-08 source and shipped binary disagreed for 23 hours:
 *
 *   staged libwinnengine.so   built 00:44, sha256 ec99928f...
 *   -print-contract           emitted NO "payloads" key at all
 *   WinnV3Host.engineSupportsV3(banner) -> false
 *   -> NO_V3_ENGINE for every v3 session, on every handset
 *
 * while `go build` of the same-named package produced an engine that
 * advertised `"payloads":["awg-datagram","ip-packet"]` and worked. Three
 * separate lanes reported v3 as working. The whole Android unit suite was
 * green, including every interop assertion, because not one of them ever
 * opened the file the user installs.
 *
 * WHAT THIS FILE USED TO DO, AND WHY THAT WAS THE SAME BUG.
 *
 * Until 2026-08-09 this class opened with the sentence above -- "the engine
 * binary the APK ACTUALLY PACKAGES" -- and then called `stagedEngines()`, which
 * reads `android/app/src/<variant>/jniLibs/<abi>/libwinnengine.so`. It never
 * opened an APK. It asserted on the *input* to packaging and reported on the
 * *output*, which is the identical mistake it was written to catch, one level
 * further out: a test that validates a staging directory while the user
 * installs an APK is green exactly when the two have diverged.
 *
 * That is not hypothetical here. On 2026-08-09, with the v3 engine correctly
 * staged, `build/app/outputs/apk/profile/app-profile.apk` still carried
 * `ec99928f...` -- zero winn3 references -- because nothing had rebuilt it.
 * The staging tree was right and the artifact was wrong, and the old assertions
 * could not see it.
 *
 * WHY PRESENCE, NOT A HASH.
 *
 * A staged hash can never equal a packaged hash, so an equality assertion
 * against staging is guaranteed-false rather than merely weak. AGP runs the
 * native libraries through `strip<Variant>DebugSymbols` on the way into the
 * APK. Measured on this tree, 2026-08-09, arm64-v8a:
 *
 *   staged / merged_native_libs    sha256 b89d2cb6...   9730680 bytes
 *   stripped_native_libs           sha256 c31bc40b...   9730680 bytes
 *   entry in app-debug.apk         sha256 c31bc40b...   9730680 bytes
 *
 * Same size, different bytes: the transform rewrites sections, so a size check
 * would not notice it either. What DOES survive the transform intact is the
 * Go package path table -- 535 `winn3` strings and 379 `winnprotocol/winn3`
 * references before and after, identically. So the assertions below are
 * presence checks on symbols, which is the property that is stable across
 * packaging, architecture, and linker flags.
 *
 * That last point matters beyond hashes: the reference COUNT is not stable
 * either. arm64-v8a release carries 379 `winnprotocol/winn3` references and
 * x86_64 release carries 378, from one build of one source tree; a bare
 * `go build` gives 704. Any gate pinned to an exact count fails an
 * architecture it was not measured on. Nothing here counts.
 *
 * THE HALVES.
 *
 * 1. Packaged: open every APK under `build/app/outputs/`, extract
 *    `lib/<abi>/libwinnengine.so`, and assert the v3 symbols are in those
 *    bytes. This is the half whose absence let the regression ship.
 * 2. Staged: the same symbols in the jniLibs inputs. Cheap, and it localises a
 *    failure to "staged wrong" versus "staged right, packaged stale".
 * 3. Source: rebuild every shipped artifact and compare by content, delegated
 *    to `tools/verify_shipped_native_artifact_freshness.py` so Apple and
 *    Android are checked by one implementation rather than two that drift.
 * 4. Release binding: `prepare_android_winn_assets.sh --stage-release DIR`
 *    stages engines out of a signed Winn release (`tools/winn_release.py`)
 *    and writes `src/<variant>/winn-release.json` with each ABI's sha256. Any
 *    stamp present must name exactly the bytes staged beside it; the Gradle
 *    release gate (`verifyAndroidReleaseEngineInputs`) additionally requires
 *    the stamp for the source set a release build packages.
 */
class ShippedEngineFreshnessTest {

    private companion object {
        /**
         * The five Go packages that make an engine a v3 engine.
         *
         * A name check is worthless -- `libwinnengine.so` is called that no
         * matter what went into it, and on 2026-08-08 the staging script built
         * `cmd/winn-clientinfo`, which links none of these, instead of
         * `cmd/winn-datapath`, which links all five. The file was the right
         * name, the right place and the right size, and carried no v3 at all.
         * This is the same vocabulary `android/tools/prepare_android_winn_assets.sh`
         * gates staging on, deliberately, so staged and packaged are judged by
         * one standard.
         */
        val V3_REQUIRED_SYMBOLS = listOf(
            "winsvpn.local/winnprotocol/winn3/core",
            "winsvpn.local/winnprotocol/winn3/session",
            "winsvpn.local/winnprotocol/winn3/carrier",
            "winsvpn.local/winnprotocol/winn3/tun",
            "winsvpn.local/winnprotocol/winn3/driver",
        )

        /**
         * The strings `WinnV3Host.engineSupportsV3` parses out of the engine's
         * `-print-contract` banner. An engine can link the v3 packages and
         * still fail the probe if the banner predates the `payloads` field, so
         * these are checked separately from the symbols above: absence of
         * `payloads` is the single byte sequence that explains a fleet-wide
         * NO_V3_ENGINE.
         */
        val V3_PROBE_MARKERS = listOf("payloads", "ip-packet", "awg-datagram")

        const val ENGINE = "libwinnengine.so"

        /**
         * Restricts this test to ONE APK, and exists so the guard can be
         * proven to fail: point it at a v3-less APK and these assertions must
         * go red, point it at a v3 APK and they must go green. A guard nobody
         * has watched fail is a guard nobody has tested.
         *
         * Never set this in CI. It can only narrow what is examined, so a CI
         * job that sets it is a CI job that stopped checking the artifacts it
         * did not name.
         */
        const val APK_UNDER_TEST = "WINN_PACKAGED_APK_UNDER_TEST"

        /** Written by `prepare_android_winn_assets.sh --stage-release`. */
        const val RELEASE_STAMP = "winn-release.json"
        const val RELEASE_STAMP_CONTRACT = "winsvpn-winn-release-android-stage-v1"
        val RELEASE_TARGETS = mapOf(
            "arm64-v8a" to "datapath-android-arm64",
            "armeabi-v7a" to "datapath-android-arm",
            "x86_64" to "datapath-android-amd64",
        )

        /**
         * What the freshness gate needs to rebuild from source. There is no
         * ReleaseGo custody any more: the pins in tools/toolchain-pins.json
         * and the sealed module-cache digest are the whole authority.
         */
        const val GO_ROOT_ENV = "WINS_FRESHNESS_GO_ROOT"
        const val DEFAULT_GO_ROOT = ".local/toolchains/go1.27.1"
        const val MODULE_CACHE_ENV = "WINS_STORE_GOMODCACHE"
        const val MODULE_CACHE_DIGEST_ENV = "WINS_STORE_GOMODCACHE_TREE_SHA256"

        val ENGINE_ENTRY = Regex("""lib/([^/]+)/\Q$ENGINE\E""")
        val ANY_NATIVE_ENTRY = Regex("""lib/([^/]+)/[^/]+\.so""")
    }

    // ---------------- the packaged artifact ----------------

    /**
     * The v3 symbols, in the bytes inside the APK.
     *
     * This is the assertion the old version of this file claimed to make.
     */
    @Test
    fun everyPackagedApkCarriesAnEngineWithTheV3Symbols() {
        for (apk in packagedApks()) {
            val engines = packagedEngines(apk)
            assertTrue(
                "${apk.path} packages no $ENGINE for any ABI. The app resolves the " +
                    "engine through context.applicationInfo.nativeLibraryDir, so an " +
                    "APK without it cannot start a tunnel at all. Check that the " +
                    "variant's jniLibs source set is populated and that " +
                    "packaging.jniLibs.excludes does not match it.",
                engines.isNotEmpty(),
            )
            for ((abi, bytes) in engines) {
                for (symbol in V3_REQUIRED_SYMBOLS + V3_PROBE_MARKERS) {
                    assertTrue(
                        describeMissing(apk, abi, symbol, bytes.size),
                        bytes.containsSequence(symbol.toByteArray(Charsets.US_ASCII)),
                    )
                }
            }
        }
    }

    /**
     * If an ABI gets native code at all, it gets the engine.
     *
     * A per-ABI drop is worse than a total one: the APK installs, the arm64
     * handsets work, and the failure is confined to whichever devices nobody
     * tested on. Expressed against the ABIs actually present rather than a
     * hard-coded list, so it stays true if the abiFilters change.
     */
    @Test
    fun everyAbiWithNativeCodeAlsoGetsTheEngine() {
        for (apk in packagedApks()) {
            val withNativeCode = abisWithNativeCode(apk)
            val withEngine = packagedEngines(apk).keys
            val missing = withNativeCode - withEngine
            assertTrue(
                "${apk.path} ships native code for $withNativeCode but packages " +
                    "$ENGINE only for $withEngine. Devices on $missing would install " +
                    "this build and find no engine.",
                missing.isEmpty(),
            )
        }
    }

    // ---------------- the staging inputs ----------------

    /**
     * The same symbols one step upstream, in the jniLibs the packaging tasks
     * read.
     *
     * Kept because it separates two failures that look identical from the
     * outside: staging built the wrong thing, versus staging is correct and the
     * APK on disk is old. Both are real; they have different fixes.
     */
    @Test
    fun everyStagedEngineCarriesTheMarkersTheV3ProbeDependsOn() {
        val staged = stagedEngines()
        assertTrue(
            "no staged $ENGINE found under android/app/src/*/jniLibs/; " +
                "if the engine is no longer staged this test must be updated, not deleted",
            staged.isNotEmpty(),
        )
        for (engine in staged) {
            val bytes = engine.readBytes()
            for (symbol in V3_REQUIRED_SYMBOLS + V3_PROBE_MARKERS) {
                assertTrue(
                    "${engine.path} does not contain '$symbol'. This is the file the " +
                        "APK packages. An engine without 'payloads' makes " +
                        "WinnV3Host.engineSupportsV3() return false and NO_V3_ENGINE " +
                        "fire for every v3 session on every handset, no matter what " +
                        "a build of the Go source does. Restage it with: " +
                        "bash android/tools/prepare_android_winn_assets.sh " +
                        "--stage-release <signed release dir> (or --stage for a dev build)",
                    bytes.containsSequence(symbol.toByteArray(Charsets.US_ASCII)),
                )
            }
        }
    }

    /** All six staged copies are one build per ABI, so they must agree. */
    @Test
    fun theStagedEnginesAreTheSameBuildAcrossEveryVariant() {
        val byAbi = stagedEngines().groupBy { it.absoluteFile.parentFile.name }
        for ((abi, engines) in byAbi) {
            val digests = engines.associate { it.path to sha256(it) }
            assertTrue(
                "the staged $abi engines differ between build variants, so debug, " +
                    "profile and release would ship different engines: $digests",
                digests.values.toSet().size == 1,
            )
        }
    }

    /**
     * A signed Winn release stamp binds the engines staged beside it.
     *
     * `--stage-release` writes the stamp only after the release verified
     * (signature and every artifact sha256) and the copied bytes matched the
     * manifest; `--stage` deletes it. So a stamp that disagrees with the bytes
     * next to it means the engines were replaced after a signed stage, and a
     * release build would package bytes no signed release vouches for.
     */
    @Test
    fun everySignedReleaseStampNamesTheEnginesStagedBesideIt() {
        val repository = repositoryRoot() ?: throw AssertionError(
            "cannot locate the repository root from ${System.getProperty("user.dir")}"
        )
        for (variant in listOf("main", "debug", "profile", "release")) {
            val stamp = File(repository, "android/app/src/$variant/$RELEASE_STAMP")
            if (!stamp.exists()) continue
            assertTrue("${stamp.path} must be a regular file", stamp.isFile)
            val json = stamp.readText(Charsets.UTF_8)
            assertEquals(
                "${stamp.path} contract",
                RELEASE_STAMP_CONTRACT,
                stampString(json, "contract"),
            )
            assertTrue(
                "${stamp.path} is not marked signed",
                Regex("\"signed\"\\s*:\\s*true\\b").containsMatchIn(json),
            )
            for (key in listOf("release_manifest_sha256", "signature_public_key")) {
                assertTrue(
                    "${stamp.path} $key is not 64 lowercase hex",
                    stampString(json, key)?.matches(Regex("[0-9a-f]{64}")) == true,
                )
            }
            for ((abi, target) in RELEASE_TARGETS) {
                val engine = File(repository, "android/app/src/$variant/jniLibs/$abi/$ENGINE")
                assertTrue("${stamp.path} vouches for ${engine.path}, which is missing", engine.isFile)
                val entry = Regex("\"${Regex.escape(abi)}\"\\s*:\\s*\\{([^{}]*)\\}")
                    .findAll(json).map { it.groupValues[1] }.toList()
                assertEquals("${stamp.path} entries for $abi", 1, entry.size)
                assertEquals("${stamp.path} target for $abi", target, stampString(entry[0], "target"))
                assertEquals(
                    "${engine.path} is not the engine its signed release stamp names. " +
                        "Restage with prepare_android_winn_assets.sh --stage-release.",
                    stampString(entry[0], "sha256"),
                    sha256Full(engine),
                )
            }
        }
    }

    // ---------------- the general gate ----------------

    /**
     * Every shipped native artifact, Android and Apple, rebuilt from current
     * source and compared by content.
     *
     * This is the assertion that generalises. The symbol tests above pin one
     * known regression; this one fails for any divergence, including the next
     * one nobody has thought of.
     */
    @Test
    fun everyShippedNativeArtifactMatchesABuildOfCurrentSource() {
        val repository = repositoryRoot() ?: throw AssertionError(
            "cannot locate the repository root from ${System.getProperty("user.dir")}"
        )
        val gate = File(repository, "tools/verify_shipped_native_artifact_freshness.py")
        assertTrue(
            "the freshness gate is missing at ${gate.path}. It is the only check " +
                "that compares the packaged artifact against current source; if it " +
                "has been removed, this suite is back to validating source while " +
                "the app ships a binary.",
            gate.isFile,
        )
        val goRoot = pinnedGoRoot()
        assumeTrue(
            "ShippedEngineFreshnessTest: SKIPPED (INCONCLUSIVE): python3, the pinned " +
                "Go root ($GO_ROOT_ENV, default ${goRoot.path}), the sealed module " +
                "cache ($MODULE_CACHE_ENV and $MODULE_CACHE_DIGEST_ENV), or " +
                "winn_protocol_experimental/go.mod are absent on this machine. " +
                "Ambient PATH Go is intentionally not accepted. The source-comparison " +
                "gate cannot run here, so this suite is INCONCLUSIVE, not green. Run " +
                "python3 tools/verify_shipped_native_artifact_freshness.py " +
                "--only android somewhere that can build.",
            verificationRuntimeAvailable(repository, goRoot),
        )

        val builder = ProcessBuilder(
            "python3", gate.absolutePath, "--only", "android",
        ).directory(repository).redirectErrorStream(true)
        // The same root Gradle fingerprints (build.gradle.kts winnFreshnessGoRoot),
        // passed explicitly: the gate accepts it only if bin/go, the install
        // tree and `go version` equal tools/toolchain-pins.json.
        builder.environment()[GO_ROOT_ENV] = goRoot.path
        val process = builder.start()
        val output = process.inputStream.readBytes().toString(Charsets.UTF_8)
        val finished = process.waitFor(30, TimeUnit.MINUTES)
        assertTrue(
            "the freshness gate did not finish within 30 minutes and is hung. " +
                "Output so far:\n$output",
            finished,
        )
        val rc = process.exitValue()
        // The inputs were checked present above, so exit 2 means the gate
        // refused them (a Go root or module cache that does not match its
        // pins) or could not run: a failure, not a skip.
        assertTrue(
            "the freshness gate could not run with the configured pinned Go and " +
                "sealed module cache (exit $rc):\n$output",
            rc != 2,
        )
        assertTrue(
            "a shipped native artifact does not match a build of current source.\n" +
                "The APK would ship the first digest; every test that builds from " +
                "source is exercising the second.\n\n$output",
            rc == 0,
        )
    }

    // ------------------------------------------------------------------

    /**
     * Every APK this repository has produced, or the single one named by
     * [APK_UNDER_TEST].
     *
     * Absence is a failure, not a skip. This test's whole subject is the
     * packaged artifact; with no artifact it has verified nothing, and a green
     * result would say the opposite. That is the precedent set when a build
     * script was found validating a stale leftover and was changed to refuse to
     * validate a file it had not just written -- the same refusal, applied to a
     * file that is not there at all.
     */
    private fun packagedApks(): List<File> {
        val override = System.getenv(APK_UNDER_TEST)?.trim()
        if (!override.isNullOrEmpty()) {
            val chosen = File(override)
            assertTrue(
                "$APK_UNDER_TEST is set to '$override', which is not a file. Unset it " +
                    "to check every packaged APK.",
                chosen.isFile,
            )
            return listOf(chosen)
        }

        val repository = repositoryRoot() ?: throw AssertionError(
            "cannot locate the repository root from ${System.getProperty("user.dir")}"
        )
        val outputs = File(repository, "build/app/outputs")
        // flutter-apk/ holds copies of the same files apk/<variant>/ does;
        // de-duplicate so one stale artifact is not reported twice.
        val unique = LinkedHashMap<String, File>()
        for (root in listOf(File(outputs, "apk"), File(outputs, "flutter-apk"))) {
            if (!root.isDirectory) continue
            root.walkTopDown()
                .filter { it.isFile && it.name.endsWith(".apk") }
                .sortedBy { it.path }
                .forEach { unique.putIfAbsent(it.canonicalPath, it) }
        }
        assertTrue(
            "no APK found under ${outputs.path}. This test opens the artifact the " +
                "user installs; with no artifact it has checked nothing, so it fails " +
                "rather than reporting a pass it did not earn. Build one first -- " +
                "`flutter build apk --debug` -- or set $APK_UNDER_TEST to the APK to " +
                "examine.",
            unique.isNotEmpty(),
        )
        return unique.values.toList()
    }

    /** `lib/<abi>/libwinnengine.so` for every ABI in the APK, by ABI. */
    private fun packagedEngines(apk: File): Map<String, ByteArray> {
        val engines = LinkedHashMap<String, ByteArray>()
        ZipFile(apk).use { zip ->
            for (entry in zip.entries()) {
                val abi = ENGINE_ENTRY.matchEntire(entry.name)?.groupValues?.get(1) ?: continue
                engines[abi] = zip.getInputStream(entry).use { it.readBytes() }
            }
        }
        return engines
    }

    private fun abisWithNativeCode(apk: File): Set<String> {
        val abis = LinkedHashSet<String>()
        ZipFile(apk).use { zip ->
            for (entry in zip.entries()) {
                ANY_NATIVE_ENTRY.matchEntire(entry.name)?.let { abis.add(it.groupValues[1]) }
            }
        }
        return abis
    }

    /**
     * The failure message carries the staged engine's state alongside the
     * packaged one, because the two possible causes need different fixes and
     * the difference is not visible from the assertion alone.
     */
    private fun describeMissing(apk: File, abi: String, symbol: String, size: Int): String {
        val repository = repositoryRoot()
        val staged = repository?.let {
            listOf("release", "profile", "debug")
                .map { variant -> File(it, "android/app/src/$variant/jniLibs/$abi/$ENGINE") }
                .firstOrNull { file -> file.isFile }
        }
        val stagedState = when {
            staged == null -> "no staged engine for $abi to compare against"
            staged.readBytes().containsSequence(symbol.toByteArray(Charsets.US_ASCII)) ->
                "the STAGED engine ${staged.path} DOES contain '$symbol', so staging is " +
                    "correct and this APK is stale: it was packaged before the current " +
                    "engine was staged. Rebuild the APK; restaging alone will not fix it."
            else ->
                "the STAGED engine ${staged.path} does NOT contain '$symbol' either, so " +
                    "the APK faithfully packaged a bad input. Fix staging first: the " +
                    "engine must be built from cmd/winn-datapath, which links the winn3 " +
                    "packages, not from a command that does not."
        }
        return "${apk.path} packages a $ENGINE for $abi ($size bytes) that does not " +
            "contain '$symbol'.\nThis is the file the user installs, read out of the " +
            "APK, after AGP's strip transform.\n$stagedState"
    }

    private fun stagedEngines(): List<File> {
        val repository = repositoryRoot() ?: return emptyList()
        val found = LinkedHashSet<File>()
        for (variant in listOf("debug", "profile", "release")) {
            for (abi in listOf("arm64-v8a", "armeabi-v7a", "x86_64")) {
                found.add(File(
                    repository,
                    "android/app/src/$variant/jniLibs/$abi/$ENGINE",
                ))
            }
        }
        val missing = found.filterNot { it.isFile }
        assertTrue(
            "expected one staged engine per variant/ABI under " +
                "android/app/src/*/jniLibs/, but these are missing: $missing. " +
                "If the staging inventory changed, update this assertion first.",
            missing.isEmpty(),
        )
        return found.filter { it.isFile }.toList()
    }

    /** Substring search over the binary; the moral equivalent of `strings | grep`. */
    private fun ByteArray.containsSequence(needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > size) return false
        val first = needle[0]
        outer@ for (start in 0..(size - needle.size)) {
            if (this[start] != first) continue
            for (offset in 1 until needle.size) {
                if (this[start + offset] != needle[offset]) continue@outer
            }
            return true
        }
        return false
    }

    private fun stampString(json: String, key: String): String? =
        Regex("\"${Regex.escape(key)}\"\\s*:\\s*\"([^\"\\\\]*)\"").find(json)?.groupValues?.get(1)

    private fun sha256Full(file: File): String =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(file.readBytes())
            .joinToString("") { "%02x".format(it) }

    private fun sha256(file: File): String =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(file.readBytes())
            .joinToString("") { "%02x".format(it) }
            .take(16)

    /**
     * The pinned Go install root: $GO_ROOT_ENV, else the default
     * build.gradle.kts fingerprints. Only the gate decides whether it is the
     * pinned Go; this just names it.
     */
    private fun pinnedGoRoot(): File {
        val configured = System.getenv(GO_ROOT_ENV)?.trim().orEmpty()
        if (configured.isNotEmpty()) return File(configured)
        return File(System.getProperty("user.home") ?: "", DEFAULT_GO_ROOT)
    }

    private fun verificationRuntimeAvailable(repository: File, goRoot: File): Boolean {
        val path = (System.getenv("PATH") ?: "").split(File.pathSeparator)
        val hasPython = path.any { File(it, "python3").canExecute() }
        val cache = System.getenv(MODULE_CACHE_ENV)?.trim().orEmpty()
        val cacheDigest = System.getenv(MODULE_CACHE_DIGEST_ENV)?.trim().orEmpty()
        return hasPython &&
            File(goRoot, "bin/go").isFile &&
            cache.isNotEmpty() && File(cache).isDirectory &&
            cacheDigest.matches(Regex("[0-9a-f]{64}")) &&
            File(repository, "winn_protocol_experimental/go.mod").isFile &&
            File(repository, "tools/toolchain-pins.json").isFile &&
            File(repository, "tools/build_winn_protocol_engine.sh").isFile
    }

    /** Walks up from the test's working directory to the repository root. */
    private fun repositoryRoot(): File? {
        var directory: File? = File(System.getProperty("user.dir") ?: return null).absoluteFile
        while (directory != null) {
            if (File(directory, "winn_protocol_experimental/go.mod").isFile) return directory
            directory = directory.parentFile
        }
        return null
    }
}
