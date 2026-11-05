package org.winsvpn.app

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Drives the REAL `winn-datapath` engine binary with the REAL Kotlin framing.
 *
 * WHY THIS TEST EXISTS. The Android lane and the Go datapath lane were both
 * green and both shipped: each had a thorough test suite, and each tested
 * against its own double. WinnEngineDouble speaks whatever WinnProtocolFraming
 * speaks, and the Go duplex tests drive the Go reader with the Go writer. Two
 * self-consistent halves that could not exchange a single byte, and no test in
 * either lane could notice, because no test ever put the two real
 * implementations in the same room.
 *
 * What was actually wrong, all four of which this test would have caught at the
 * first assertion:
 *
 *  1. argv. The host spawned `<engine> tunnel`; the binary takes flags only and
 *     dies on any positional argument.
 *  2. Channel discovery. The host passed the socket name in
 *     `WINN_ENGINE_CHANNEL`; the binary reads no environment at all and takes
 *     `-control`.
 *  3. Framing. The host wrote a 4-byte `type:u8 + len:u24` big-endian header;
 *     the binary reads the 16-byte little-endian WNN3 header.
 *  4. Payload semantics. The host pumped raw IP packets off the tun; the engine
 *     carries AmneziaWG outer datagrams and refuses `payload:"ip-packet"`.
 *
 * A fifth, which nobody had listed: every key in the host's config JSON was an
 * unknown field to `datapath.Config`, which decodes with
 * `DisallowUnknownFields`.
 *
 * TRANSPORT. This test uses `-transport stdio`, not the unix socket, because a
 * plain JVM cannot send SCM_RIGHTS. That single gap is covered on real hardware
 * by `android/devicecheck/`, which runs this same host code against this same
 * binary over a real LocalSocket. Everything else -- the argv, the frame bytes,
 * the opcode vocabulary, the direction rules, the config schema and the payload
 * refusal -- is exercised here against the real binary on every test run.
 */
class WinnEngineInteropTest {

    // ------------------------------------------------------------------
    // Always-on: the bytes this host emits, pinned against the normative
    // format. These vectors were produced BY the Go implementation, which is
    // itself pinned byte-for-byte to windows/runner/winn_frame.h by its own
    // conformance test. They run even where the engine binary cannot be built,
    // so the framing cannot drift silently.
    // ------------------------------------------------------------------

    @Test
    fun encoderMatchesTheNormativeGoldenBytes() {
        val vectors = listOf(
            Triple(WinnFraming.OP_CREATE, "{}", "574e4e330100010002000000000000007b7d"),
            Triple(
                WinnFraming.OP_CREATE_ACK,
                "{\"up\":true}",
                "574e4e33010002000b000000000000007b227570223a747275657d",
            ),
            Triple(WinnFraming.OP_INBOUND, "AB", "574e4e330100100002000000000000004142"),
            Triple(
                WinnFraming.OP_OUTBOUND,
                "packet-bytes",
                "574e4e33010011000c000000000000007061636b65742d6279746573",
            ),
            Triple(WinnFraming.OP_STATUS_REQUEST, "", "574e4e33010020000000000000000000"),
            Triple(
                WinnFraming.OP_STATUS_RESPONSE,
                "{}",
                "574e4e330100210002000000000000007b7d",
            ),
            Triple(WinnFraming.OP_CLOSE, "", "574e4e33010030000000000000000000"),
            Triple(WinnFraming.OP_CLOSE_ACK, "", "574e4e33010031000000000000000000"),
            Triple(WinnFraming.OP_ERROR, "x", "574e4e330100f000010000000000000078"),
        )
        for ((opcode, payload, expected) in vectors) {
            val out = ByteArrayOutputStream()
            WinnFraming.writeFrame(out, opcode, payload.toByteArray(Charsets.UTF_8))
            assertEquals(
                "golden bytes for ${WinnFraming.opcodeName(opcode)}",
                expected,
                out.toByteArray().toHex(),
            )
        }
    }

    // ------------------------------------------------------------------
    // Live: the real binary.
    // ------------------------------------------------------------------

    @Test
    fun realEngineAdvertisesTheFramingThisHostImplements() {
        val engine = engineBinary() ?: return
        val banner = runCapturing(engine, "-print-contract")
        assertTrue("contract banner: $banner", banner.contains("\"frame_magic\":\"0x334E4E57\""))
        assertTrue(banner, banner.contains("\"frame_version\":1"))
        assertTrue(banner, banner.contains("\"frame_header_size\":16"))
        assertTrue(banner, banner.contains("\"max_frame_payload\":65535"))
        // The MACHINE-READABLE payload list, not the prose. The engine also
        // states the same fact in English in "payload_semantics" ("...carry
        // AmneziaWG outer datagrams and not raw IP packets"), but a host must
        // never probe that sentence: it names "ip packets" inside a clause that
        // says the opposite, so a naive substring search for it reads as
        // support. This pins the list WinnV3Host.ENGINE_SEAM was waiting for
        // instead -- byte for byte, so a formatting drift here is caught too.
        assertTrue(banner, banner.contains("\"payloads\":[\"awg-datagram\",\"ip-packet\"]"))
        // THE CONSEQUENCE THAT MATTERS MORE THAN THE STRING ABOVE: the real
        // probe, against the real binary's real banner, must now say yes. Before
        // this banner grew the "payloads" list, WinnV3Host.engineSupportsV3
        // returned false here and NO_V3_ENGINE fired for every v3 session on the
        // shipping engine; asserting only the literal above -- and not the
        // probe's own verdict -- could stay green while that regressed.
        assertTrue(banner, WinnV3Host.engineSupportsV3(banner))
        assertEquals(WinnFraming.MAGIC, 0x334E4E57)
        assertEquals(WinnFraming.FRAMING_VERSION, 1)
        assertEquals(WinnFraming.HEADER_BYTES, 16)
        assertEquals(WinnFraming.MAX_PAYLOAD_BYTES, 65535)
    }

    /**
     * The regression itself. The argv this host used to spawn is still a fatal
     * error for the real binary, so if anyone reintroduces a positional
     * subcommand this fails immediately and by name.
     */
    @Test
    fun theOldSpawnContractIsStillFatal() {
        val engine = engineBinary() ?: return
        val process = ProcessBuilder(engine.absolutePath, "tunnel")
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.readBytes().toString(Charsets.UTF_8)
        assertTrue(process.waitFor(20, TimeUnit.SECONDS))
        assertEquals("the packaged engine must reject a positional argument", 1, process.exitValue())
        assertTrue(output, output.contains("unexpected argument \"tunnel\""))
    }

    /** The argv this host now spawns is the argv the binary parses. */
    @Test
    fun theSpawnContractMatchesTheFlagsTheEngineParses() {
        val arguments = WinnAndroidEngineHost.engineArguments("/lib/libwinnengine.so", "winn-engine-abc")
        assertEquals(
            listOf(
                "/lib/libwinnengine.so",
                "-transport", "unix",
                "-control", "@winn-engine-abc",
                "-receive-fd",
            ),
            arguments,
        )
        // No positional argument, which is what killed the old contract.
        assertTrue("argv must not carry a subcommand", arguments.none { it == "tunnel" })

        val engine = engineBinary() ?: return
        // The binary must at least PARSE these flags. Pointed at a socket that
        // does not exist it fails to connect, which proves parsing succeeded:
        // a rejected flag reports the flag instead.
        val output = runCapturingStderr(
            engine,
            "-transport", "unix",
            "-control", "@winn-interop-nonexistent-${System.nanoTime()}",
            "-receive-fd",
        )
        assertTrue(
            "expected a connect failure, not a flag parse failure: $output",
            output.contains("connect control socket"),
        )
        assertTrue(output, !output.contains("flag provided but not defined"))
    }

    /**
     * The carrier argv, and the flag that changes which `Open` the engine
     * calls.
     *
     * `-carrier-profile PATH` is the entire difference between
     * `datapath.Open` (direct-awg, classical AmneziaWG on the wire) and
     * `datapath.OpenWithCarrier` (authenticated Winn envelopes over HTTP/3
     * CONNECT-UDP with a post-quantum TLS 1.3 handshake). If it is dropped from
     * argv, the engine silently starts the weaker one -- so the argv is
     * asserted, not assumed.
     */
    @Test
    fun theCarrierProfileFlagIsOnTheArgvWhenAProfileExists() {
        val withProfile = WinnAndroidEngineHost.engineArguments(
            "/lib/libwinnengine.so", "winn-engine-abc", "/data/user/0/app/files/winn/p.json",
        )
        assertEquals(
            listOf(
                "/lib/libwinnengine.so",
                "-transport", "unix",
                "-control", "@winn-engine-abc",
                "-receive-fd",
                "-carrier-profile", "/data/user/0/app/files/winn/p.json",
            ),
            withProfile,
        )
        // A direct-awg session must NOT carry the flag: the engine refuses a
        // profile supplied beside a direct-awg configuration.
        val withoutProfile =
            WinnAndroidEngineHost.engineArguments("/lib/libwinnengine.so", "winn-engine-abc")
        assertTrue(withoutProfile.none { it == "-carrier-profile" })

        // A blank path would make the engine fall back to datapath.Open and
        // start direct-awg for a session configured for a carrier, which is the
        // silent downgrade the gates exist to prevent.
        try {
            WinnAndroidEngineHost.engineArguments("/lib/e.so", "winn-engine-abc", "   ")
            fail("a blank carrier profile path should have been refused")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!, e.message!!.contains("direct-awg"))
        }
    }

    /**
     * THE PROOF THAT MATTERS FOR THIS STAGE: the REAL Go loader accepts the
     * REAL document Kotlin writes.
     *
     * `carrierhost.Profile` decodes with `DisallowUnknownFields` and runs a
     * long `normalize()` -- version, carrier, per-carrier field exclusivity,
     * an IP-literal public target, a parseable suite, six mandatory credential
     * paths, a 32-hex session id, a 64-hex manifest digest, a known
     * authorization mode. A single wrong key or missing field kills the process
     * before it dials the control socket.
     *
     * `main.go` loads and validates the profile BEFORE any transport is
     * established, precisely so a bad profile is a message on stderr rather
     * than an Error frame after the host has protected a socket and handed the
     * descriptor over. That ordering is what lets this test prove the document
     * is well-formed without provisioning real cryptographic material: the
     * credential files are opened later, by `BuildDialer` at Create time.
     *
     * So this test writes the document with the shipping Kotlin path, points
     * the real binary at it, and asserts the engine got past validation and
     * failed on the socket instead.
     */
    @Test
    fun theRealEngineAcceptsTheProfileDocumentKotlinWrites() {
        val engine = engineBinary() ?: return
        val root = java.nio.file.Files.createTempDirectory("winn-carrier-interop").toFile()
        try {
            val profileFile = writeKotlinCarrierProfile(root)
            val output = runCapturingStderr(
                engine,
                "-transport", "unix",
                "-control", "@winn-interop-nonexistent-${System.nanoTime()}",
                "-receive-fd",
                "-carrier-profile", profileFile.absolutePath,
            )
            // The refusals this document must NOT trigger, each named so a
            // failure says which rule the Kotlin writer broke.
            for (refusal in listOf(
                "unknown field",
                "winn carrier profile version is not",
                "is required",
                "does not belong to the carrier it names",
                "names a gateway manifest",
                "anonymous-token",
                "must be an IP literal",
                "session_id must be",
                "manifest_digest must be",
                "single JSON object",
                "flag provided but not defined",
            )) {
                assertTrue(
                    "the real loader rejected the Kotlin-written profile: $output",
                    !output.contains(refusal),
                )
            }
            // The engine logged the profile it accepted...
            assertTrue(
                "expected the engine's own profile summary: $output",
                output.contains("winn carrier profile: carrier=http3-connect-udp"),
            )
            assertTrue(output, output.contains("suite=x25519-mlkem768"))
            assertTrue(output, output.contains("mode=identity"))
            assertTrue(output, output.contains("manifest_verified=false"))
            // ...and then failed on the socket, which is how far this test can
            // go without a running carrier server.
            assertTrue(
                "expected a connect failure after a valid profile: $output",
                output.contains("connect control socket"),
            )
        } finally {
            root.deleteRecursively()
        }
    }

    /**
     * THE PROOF THAT SPA IS ACTUALLY REACHABLE: the real Go engine parses a
     * carrier profile that the shipping Kotlin emitter wrote with single packet
     * authorization turned on.
     *
     * This is the assertion the previous state of the tree could not make. Every
     * platform emitter carried a closed key allowlist that excluded every
     * `spa_` field, so the fields existed in `carrierhost.Profile`, no client
     * could put one in a document, and nothing failed anywhere -- the capability
     * was simply unreachable. A unit test on the emitted string would not have
     * caught that either, because the string was well-formed; only the real
     * loader, decoding with `DisallowUnknownFields` and running
     * `normalizeSPA`, settles whether the document means what this host thinks
     * it means.
     */
    @Test
    fun theRealEngineAcceptsAnSpaProfileKotlinWrites() {
        val engine = engineBinary() ?: return
        val root = java.nio.file.Files.createTempDirectory("winn-carrier-spa").toFile()
        try {
            val profileFile = writeKotlinCarrierProfile(root, spa = true)
            // The document really does carry the knock parameters -- otherwise
            // the engine assertions below would pass on a profile with no SPA
            // in it at all, which is exactly the failure being guarded against.
            val document = profileFile.readText()
            assertTrue(document, document.contains("\"spa_mode\":\"required\""))
            assertTrue(document, document.contains("\"spa_target\":\"198.51.100.20:9111\""))
            assertTrue(document, document.contains("\"spa_packet_size\":256"))

            val output = runCapturingStderr(
                engine,
                "-transport", "unix",
                "-control", "@winn-interop-nonexistent-${System.nanoTime()}",
                "-receive-fd",
                "-carrier-profile", profileFile.absolutePath,
            )
            // Every refusal carrierhost.normalizeSPA can produce. Each is named
            // so a failure says which rule the Kotlin writer broke.
            for (refusal in listOf(
                "unknown field",
                "spa_ field without spa_mode",
                "spa_mode",
                "spa_key_path is required",
                "spa_target",
                "spa_packet_size must be within",
                "spa freshness policy",
                "which this host cannot do",
                "is required",
            )) {
                assertTrue(
                    "the real loader rejected the Kotlin-written SPA profile " +
                        "on '$refusal': $output",
                    !output.contains(refusal),
                )
            }
            // The engine's own summary reports SPA as ON. This is the line that
            // distinguishes "the document parsed" from "the document parsed and
            // the knock is actually armed".
            assertTrue(
                "expected the engine to report spa=required: $output",
                output.contains("spa=required"),
            )
            // ...and then failed on the socket, which is how far this test can
            // go without a running carrier server.
            assertTrue(
                "expected a connect failure after a valid profile: $output",
                output.contains("connect control socket"),
            )
        } finally {
            root.deleteRecursively()
        }
    }

    /**
     * The mutation check for the SPA test above: the real loader is not simply
     * accepting anything with `spa_` in it.
     *
     * Each mutation is a way single packet authorization could quietly have
     * become a no-op or a misdirected knock, and each must be a hard failure of
     * the real binary. Without this, `theRealEngineAcceptsAnSpaProfileKotlinWrites`
     * would prove only that the engine does not crash.
     */
    @Test
    fun theRealEngineRefusesEverySpaMutation() {
        val engine = engineBinary() ?: return
        val root = java.nio.file.Files.createTempDirectory("winn-carrier-spa-mut").toFile()
        try {
            val good = writeKotlinCarrierProfile(root, spa = true).readText()
            val mutations = mapOf(
                // SPA silently disarmed while the parameters stay: the engine
                // must refuse rather than run an unknocked session that will be
                // dropped by a gate nobody told it about.
                "mode turned off under the parameters" to
                    good.replace("\"spa_mode\":\"required\"", "\"spa_mode\":\"off\""),
                // A mode this build does not implement.
                "an invented mode" to
                    good.replace("\"spa_mode\":\"required\"", "\"spa_mode\":\"advisory\""),
                // A hostname target: the engine will not resolve one, because
                // that lookup would leave outside the tunnel.
                "a hostname knock target" to
                    good.replace("\"198.51.100.20:9111\"", "\"gate.example:9111\""),
                // Too small to hold a 16-byte nonce plus a 32-byte tag.
                "a knock too small to hold a tag" to
                    good.replace("\"spa_packet_size\":256", "\"spa_packet_size\":16"),
                // Larger than one unfragmented datagram.
                "a knock that would have to fragment" to
                    good.replace("\"spa_packet_size\":256", "\"spa_packet_size\":4000"),
                // A misspelled key. DisallowUnknownFields makes this a hard
                // failure, which is the property the whole key-generation
                // change exists to keep honest.
                "a misspelled spa key" to
                    good.replace("\"spa_target\"", "\"spa_targets\""),
            )
            for ((label, document) in mutations) {
                val file = File(root, "mutation-${label.hashCode()}.json")
                file.writeText(document)
                file.setReadable(false, false)
                file.setWritable(false, false)
                file.setReadable(true, true)
                file.setWritable(true, true)
                val output = runCapturingStderr(
                    engine,
                    "-transport", "unix",
                    "-control", "@winn-interop-nonexistent-${System.nanoTime()}",
                    "-receive-fd",
                    "-carrier-profile", file.absolutePath,
                )
                // A refusal means the engine never reached the socket stage.
                assertTrue(
                    "the real engine ACCEPTED '$label', so the SPA test above " +
                        "proves nothing: $output",
                    !output.contains("connect control socket"),
                )
            }
        } finally {
            root.deleteRecursively()
        }
    }

    /**
     * The mutation check for the test above.
     *
     * If the real loader accepted anything, the assertions above would prove
     * nothing. Each mutation below is a way a carrier session could quietly
     * have become something weaker or unverified, and each must be a hard
     * failure of the real binary.
     */
    @Test
    fun theRealEngineRefusesProfilesThatWouldWeakenTheSession() {
        val engine = engineBinary() ?: return
        val root = java.nio.file.Files.createTempDirectory("winn-carrier-mutation").toFile()
        try {
            val good = writeKotlinCarrierProfile(root).readText()
            val mutations = listOf(
                // A manifest the host does not verify. carrierhost refuses
                // rather than reading its own transport fields and calling them
                // verified.
                "manifest_path" to good.replaceFirst(
                    "{", "{\"manifest_path\":\"/data/manifest.json\","
                ),
                // The anonymous-token route, which needs an issued
                // privacy-token pool this host does not have.
                "anonymous-token" to
                    good.replace("\"authorization_mode\":\"identity\"",
                        "\"authorization_mode\":\"anonymous-token\""),
                // The trust anchor removed.
                "controller_pins_path" to
                    good.replace(Regex("\"controller_pins_path\":\"[^\"]*\""),
                        "\"controller_pins_path\":\"\""),
                // ECH dropped, which would make the TLS profile a
                // single-probe fingerprint.
                "ech_config_list_path" to
                    good.replace(Regex("\"ech_config_list_path\":\"[^\"]*\""),
                        "\"ech_config_list_path\":\"\""),
                // A key the schema does not define.
                "unknown field" to good.replaceFirst("{", "{\"mlkem_public_key\":\"BASE64\","),
                // The wrong carrier's field.
                "h2_url" to good.replaceFirst("{", "{\"h2_url\":\"https://c.example/w\","),
                // A hostname public target, which would introduce a second,
                // silent naming scheme for the gateway.
                "public_target" to
                    good.replace(Regex("\"public_target\":\"[^\"]*\""),
                        "\"public_target\":\"gateway.example:51820\""),
            )
            for ((label, document) in mutations) {
                val file = File(root, "mutated.json")
                file.delete()
                file.writeText(document)
                file.setReadable(false, false)
                file.setWritable(false, false)
                file.setReadable(true, true)
                file.setWritable(true, true)
                val output = runCapturingStderr(
                    engine,
                    "-transport", "unix",
                    "-control", "@winn-interop-nonexistent-${System.nanoTime()}",
                    "-receive-fd",
                    "-carrier-profile", file.absolutePath,
                )
                assertTrue(
                    "mutation '$label' was ACCEPTED by the real loader, so the " +
                        "acceptance test above proves nothing: $output",
                    !output.contains("connect control socket"),
                )
                assertTrue(
                    "mutation '$label' failed for an unrelated reason: $output",
                    output.contains("winn-datapath:"),
                )
            }
        } finally {
            root.deleteRecursively()
        }
    }

    /**
     * The one mutation the engine does NOT catch at startup, and why the Kotlin
     * allowlist is load-bearing rather than defensive duplication.
     *
     * MEASURED, not assumed: `carrierhost.normalize` checks only that `suite`
     * is non-empty. `tlsconfig.ParseSuite` runs inside `BuildDialer`, which
     * `openWithProfile` calls at CREATE time -- after the host has opened a UDP
     * socket, called `VpnService.protect` on it, spawned the engine and passed
     * the descriptor over SCM_RIGHTS. A profile naming a classical group
     * therefore starts the engine cleanly and fails later, with a protected
     * socket already handed to a child process.
     *
     * `WinnCarrierProfile.SUPPORTED_SUITES` is what turns that into a local
     * refusal before anything is allocated. This test proves both halves: that
     * the real engine really does accept the bad suite at startup, and that
     * Kotlin really does refuse to write it.
     */
    @Test
    fun aClassicalSuiteIsCaughtByKotlinBecauseTheEngineDefersIt() {
        // Half one: Kotlin refuses to write it at all.
        val root = java.nio.file.Files.createTempDirectory("winn-carrier-suite").toFile()
        try {
            val credentials = WinnCarrierProfile.credentialDirectory(root)
            assertTrue(credentials.mkdirs() || credentials.isDirectory)
            for ((name, _) in WinnCarrierProfile.CredentialSet.REQUIRED_FILES) {
                File(credentials, name).writeText("placeholder")
            }
            for (classical in listOf("x25519", "p256", "p384", "rsa")) {
                try {
                    WinnCarrierProfile.from(
                        section = mapOf(
                            "carrier" to WinnCarrierProfile.CARRIER_HTTP3,
                            "masque_template" to
                                "https://c.example/.well-known/masque/udp/{target_host}/{target_port}/",
                            "public_target" to "198.51.100.20:51820",
                            "server_name" to "gateway.example",
                            "suite" to classical,
                            "controller_id" to "controller-1",
                            "device_id" to "device-1",
                            "device_pq_algorithm" to "mldsa65",
                            "manifest_digest" to "a".repeat(64),
                        ),
                        carrier = WinnCarrierProfile.CARRIER_HTTP3,
                        credentialDirectory = credentials,
                    )
                    fail("Kotlin must refuse the classical group '$classical'")
                } catch (e: IllegalArgumentException) {
                    assertTrue(e.message!!, e.message!!.contains("post-quantum"))
                }
            }

            // Half two: the engine, given one anyway, gets PAST startup. If this
            // ever starts failing, the engine has gained a startup check and
            // this test should say so rather than quietly pass.
            val engine = engineBinary() ?: return
            val good = writeKotlinCarrierProfile(root).readText()
            val file = File(root, "classical-suite.json")
            file.writeText(good.replace("x25519-mlkem768", "x25519"))
            file.setReadable(false, false)
            file.setWritable(false, false)
            file.setReadable(true, true)
            file.setWritable(true, true)
            val output = runCapturingStderr(
                engine,
                "-transport", "unix",
                "-control", "@winn-interop-nonexistent-${System.nanoTime()}",
                "-receive-fd",
                "-carrier-profile", file.absolutePath,
            )
            assertTrue(
                "The engine now refuses a classical suite at startup. That is an " +
                    "improvement -- update this test and the comment on " +
                    "WinnCarrierProfile.SUPPORTED_SUITES: $output",
                output.contains("connect control socket"),
            )
        } finally {
            root.deleteRecursively()
        }
    }

    /**
     * Writes a carrier profile with the SHIPPING Kotlin path -- the same
     * [WinnCarrierProfile.from] and [WinnCarrierProfile.writeTo] the service
     * calls -- so this test exercises the real writer rather than a fixture
     * that happens to look like its output.
     *
     * The credential files are placeholders. They are never opened by the
     * validation this test reaches: `main.go` runs `LoadProfile` at startup and
     * `BuildDialer` only at Create time, so the six paths are checked for
     * presence here and parsed only when a tunnel is actually created. Real
     * cryptographic material is a provisioning question, not a document-shape
     * one.
     */
    private fun writeKotlinCarrierProfile(root: File, spa: Boolean = false): File {
        val credentials = WinnCarrierProfile.credentialDirectory(root)
        assertTrue(credentials.mkdirs() || credentials.isDirectory)
        for ((name, _) in WinnCarrierProfile.CredentialSet.REQUIRED_FILES) {
            File(credentials, name).writeText("placeholder for $name")
        }
        if (spa) {
            // A syntactically valid single-line hex key. It is never opened by
            // the validation this test reaches -- LoadKeysFromFile runs inside
            // BuildDialer at Create time -- but it must EXIST, because the
            // Kotlin emitter refuses to name a knock key that is not there.
            File(credentials, WinnCarrierProfileKeys.SPA_KEY_CREDENTIAL_FILE_NAME)
                .writeText("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n")
        }
        val spaSection = if (!spa) emptyMap() else mapOf(
            "spa_mode" to "required",
            "spa_target" to "198.51.100.20:9111",
            "spa_packet_size" to "256",
            "spa_bucket_window_seconds" to "10",
            "spa_max_skew_seconds" to "60",
        )
        val section = spaSection + mapOf(
            "enabled" to "true",
            "endpoint" to "203.0.113.7:51820",
            "carrier" to WinnCarrierProfile.CARRIER_HTTP3,
            "masque_template" to
                "https://carrier.example/.well-known/masque/udp/{target_host}/{target_port}/",
            "public_target" to "198.51.100.20:51820",
            "server_name" to "gateway.example",
            "suite" to "x25519-mlkem768",
            "controller_id" to "controller-1",
            "device_id" to "device-1",
            "device_pq_algorithm" to "mldsa65",
            "manifest_digest" to "a".repeat(64),
        )
        // Routed through WinnEngineConfig first, exactly as the service does,
        // so the carrier this profile is built for is the carrier the Create
        // document will name. The engine refuses a mismatch between the two.
        val engineConfig = WinnEngineConfig.from(section = section, mtu = 1280)
        assertTrue(engineConfig.requiresCarrierProfile)
        return WinnCarrierProfile.from(
            section = section,
            carrier = engineConfig.carrier,
            credentialDirectory = credentials,
        ).writeTo(WinnCarrierProfile.profileDirectory(root))
    }

    /**
     * The full conversation, end to end, over the real binary: Create ->
     * CreateAck, StatusRequest -> StatusResponse, Close -> CloseAck.
     *
     * `allow_own_socket` is true here and ONLY here, because stdio cannot carry
     * a descriptor. Production sets it false; see
     * [productionConfigReachesTheSocketRuleWhichMeansTheSchemaIsAccepted].
     */
    @Test
    fun realEngineCompletesTheFullConversation() {
        val engine = engineBinary() ?: return
        withEngine(engine) { session ->
            val config = """
                {"contract":"winn-datapath/1","payload":"awg-datagram",
                 "carrier":"direct-awg","gateway_endpoint":"203.0.113.7:51820",
                 "max_datagram":1500,"allow_own_socket":true}
            """.trimIndent().replace("\n", "")

            session.write(WinnFraming.OP_CREATE, config.toByteArray(Charsets.UTF_8))
            val ack = session.read()
            assertNotNull("engine closed instead of acknowledging create", ack)
            assertEquals(
                "engine said: ${ack!!.payloadAsText()}",
                WinnFraming.OP_CREATE_ACK,
                ack.opcode,
            )
            val status = ack.payloadAsText()
            assertTrue(status, status.contains("\"contract\":\"winn-datapath/1\""))
            assertTrue(status, status.contains("\"payload\":\"awg-datagram\""))
            assertTrue(status, status.contains("\"up\":true"))

            session.write(WinnFraming.OP_STATUS_REQUEST, ByteArray(0))
            val statusFrame = session.readOf(WinnFraming.OP_STATUS_RESPONSE)
            assertTrue(
                statusFrame.payloadAsText(),
                statusFrame.payloadAsText().contains("\"gateway_endpoint\":\"203.0.113.7:51820\""),
            )

            session.write(WinnFraming.OP_CLOSE, ByteArray(0))
            val closeAck = session.readOf(WinnFraming.OP_CLOSE_ACK)
            // CloseAck carries no payload by the normative framing. A host that
            // wants final counters must ask before closing.
            assertEquals(0, closeAck.payload.size)
        }
    }

    /**
     * The production config document, verbatim from [WinnEngineConfig], is fed
     * to the real engine.
     *
     * It cannot succeed over stdio: production sets `allow_own_socket:false`
     * and there is no descriptor on a pipe. What matters is WHICH refusal comes
     * back. `ErrOwnSocketRefused` means the engine decoded every field, matched
     * the contract string, accepted the payload and carrier modes, parsed the
     * endpoint, and then stopped at the socket rule -- i.e. the schema is
     * right. A JSON decode error would mean it is not, which is exactly what
     * the previous config document produced on its very first key.
     */
    @Test
    fun productionConfigReachesTheSocketRuleWhichMeansTheSchemaIsAccepted() {
        val engine = engineBinary() ?: return
        val config = WinnEngineConfig.from(
            section = mapOf("enabled" to "true", "endpoint" to "203.0.113.7:51820"),
            mtu = 1280,
        ).toConfigJson()

        withEngine(engine) { session ->
            session.write(WinnFraming.OP_CREATE, config.toByteArray(Charsets.UTF_8))
            val reply = session.readOf(WinnFraming.OP_ERROR)
            val text = reply.payloadAsText()
            assertTrue(
                "expected the socket rule, got: $text",
                text.contains("allow_own_socket is false"),
            )
            // Prove it is NOT a schema failure.
            assertTrue(text, !text.contains("unknown field"))
            assertTrue(text, !text.contains("cannot unmarshal"))
            assertTrue(text, !text.contains("contract must be"))
        }
    }

    /**
     * The payload-semantics gap, asserted rather than described. If a future
     * change makes this host declare `ip-packet` so it can pump the tun again,
     * the real engine refuses it and this test says why.
     */
    @Test
    fun realEngineRefusesRawIpPacketsAsAPayloadMode() {
        val engine = engineBinary() ?: return
        withEngine(engine) { session ->
            val config = """
                {"contract":"winn-datapath/1","payload":"ip-packet",
                 "carrier":"direct-awg","gateway_endpoint":"203.0.113.7:51820",
                 "allow_own_socket":true}
            """.trimIndent().replace("\n", "")
            session.write(WinnFraming.OP_CREATE, config.toByteArray(Charsets.UTF_8))
            val text = session.readOf(WinnFraming.OP_ERROR).payloadAsText()
            assertTrue(text, text.contains("is not implemented"))
            assertTrue(text, text.contains("no in-process AmneziaWG encapsulator"))
            assertTrue(text, text.contains("awg-datagram"))
        }
        // And the host never declares it.
        assertEquals("awg-datagram", WinnEngineConfig.PAYLOAD_AWG_DATAGRAM)
    }

    /**
     * The old Android framing, replayed against the real engine. This is the
     * failure the two lanes could not see: a 4-byte `type:u8 + len:u24` header
     * is not a WNN3 frame, and the engine tears the channel down rather than
     * scanning forward for a magic it might recognise.
     */
    @Test
    fun theOldAndroidFramingIsRejectedWithoutResynchronising() {
        val engine = engineBinary() ?: return
        // The exact document the old host sent, in the old frame: HELLO(0x01)
        // then a 24-bit big-endian length. It must be at least a header's worth
        // of bytes or the engine simply blocks waiting for one, which would
        // prove nothing.
        val oldPayload =
            "{\"winn_framing_version\":1,\"role\":\"client\",\"endpoint\":\"a:1\",\"mtu\":1280}"
                .toByteArray(Charsets.UTF_8)
        val oldFrame = byteArrayOf(
            0x01,
            ((oldPayload.size ushr 16) and 0xFF).toByte(),
            ((oldPayload.size ushr 8) and 0xFF).toByte(),
            (oldPayload.size and 0xFF).toByte(),
        ) + oldPayload

        withEngine(engine) { session ->
            session.raw(oldFrame)
            val reply = session.read()
            // The engine's last act on a bad frame is a best-effort Error, then
            // the stream ends. Either is a rejection; neither is acceptance.
            if (reply != null) {
                assertEquals(WinnFraming.OP_ERROR, reply.opcode)
                assertTrue(reply.payloadAsText(), reply.payloadAsText().contains("magic"))
            }
            assertTrue("the engine must exit rather than continue", session.awaitExit())
        }
    }

    /**
     * The fifth incompatibility, which nobody had listed: even with the framing
     * fixed, every key of the old config document is an unknown field to
     * `datapath.Config`, which decodes with `DisallowUnknownFields`. The very
     * first key fails the decode.
     */
    @Test
    fun theOldConfigSchemaIsRejectedFieldByField() {
        val engine = engineBinary() ?: return
        withEngine(engine) { session ->
            val old =
                "{\"winn_framing_version\":1,\"role\":\"client\",\"endpoint\":\"a:1\",\"mtu\":1280}"
            session.write(WinnFraming.OP_CREATE, old.toByteArray(Charsets.UTF_8))
            val text = session.readOf(WinnFraming.OP_ERROR).payloadAsText()
            assertTrue(text, text.contains("unknown field"))
            assertTrue(text, text.contains("winn_framing_version"))
        }
    }

    /** The host's own reader refuses to resynchronise, mirroring the engine. */
    @Test
    fun hostReaderLatchesAndDoesNotResynchronise() {
        val good = ByteArrayOutputStream()
        WinnFraming.writeFrame(good, WinnFraming.OP_CREATE_ACK, "{}".toByteArray())
        // A corrupt header followed by a perfectly good frame. A resynchronising
        // reader would hand back the second one; this one must not.
        val corrupt = ByteArray(WinnFraming.HEADER_BYTES) { 0x11 }
        val stream = (corrupt + good.toByteArray()).inputStream()
        val reader = WinnFrameReader(stream, acceptEngineToHost = true)
        try {
            reader.read()
            fail("expected the corrupt header to be rejected")
        } catch (e: IOException) {
            assertTrue(e.message!!, e.message!!.contains("magic"))
        }
        try {
            reader.read()
            fail("a latched reader must not return the frame after a bad header")
        } catch (e: IOException) {
            assertTrue(e.message!!, e.message!!.contains("magic"))
        }
    }

    // ------------------------------------------------------------------
    // The payload source: WinnAwgLoopbackSeam, against the real engine
    // ------------------------------------------------------------------

    /**
     * The seam, the bridge and the real engine binary, all at once.
     *
     * This is the JVM-level half of what `android/devicecheck/` proves on
     * hardware. It cannot cover two things and does not pretend to: the
     * SCM_RIGHTS descriptor hand-off (a plain JVM cannot send one, so the
     * transport below no-ops `sendDescriptor` and the engine is told
     * `allow_own_socket:true`), and AmneziaWG itself (the datagrams here are
     * marked bytes, not Noise messages). Everything between those two -- the
     * seam's loopback relay, its peer pinning, the bridge's two pumps, the WNN3
     * frames and the real engine's forwarding -- is the production code.
     */
    @Test
    fun theLoopbackSeamCarriesRealDatagramsThroughTheRealEngineBothWays() {
        val engine = engineBinary() ?: return

        // Stands in for the gateway: whatever it is sent, it sends back with a
        // marker, so a reply cannot be confused with an echo of the request by
        // some layer in between.
        val gateway = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        gateway.soTimeout = 20_000
        val gatewayDone = java.util.concurrent.CountDownLatch(1)
        Thread {
            try {
                val buffer = ByteArray(2048)
                val packet = DatagramPacket(buffer, buffer.size)
                gateway.receive(packet)
                val reply = "REPLY:".toByteArray() +
                    buffer.copyOf(packet.length)
                gateway.send(DatagramPacket(reply, reply.size, packet.socketAddress))
            } catch (_: Exception) {
            } finally {
                gatewayDone.countDown()
            }
        }.apply { isDaemon = true; start() }

        val seam = WinnAwgLoopbackSeam.open()
        // Stands in for the AmneziaWG engine: an ordinary socket that treats
        // the seam's port as its peer endpoint, which is exactly what
        // `Endpoint = 127.0.0.1:<port>` makes the real one do.
        val awg = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        awg.soTimeout = 20_000

        val config = """
            {"contract":"winn-datapath/1","payload":"awg-datagram",
             "carrier":"direct-awg","gateway_endpoint":"127.0.0.1:${gateway.localPort}",
             "max_datagram":1500,"allow_own_socket":true}
        """.trimIndent().replace("\n", "")

        val host = StdioSeamHost(engine, seam)
        val bridge = WinnTunnelBridge(host = host, maxDatagram = 1500, configJson = config)
        try {
            bridge.start()

            val outgoing = "outer-awg-datagram".toByteArray()
            awg.send(
                DatagramPacket(
                    outgoing, outgoing.size,
                    InetSocketAddress(InetAddress.getByName("127.0.0.1"), seam.localPort),
                )
            )

            val buffer = ByteArray(2048)
            val received = DatagramPacket(buffer, buffer.size)
            awg.receive(received)
            val text = String(buffer, 0, received.length, Charsets.UTF_8)

            assertEquals("REPLY:outer-awg-datagram", text)
            // The reply must arrive from the seam's port, i.e. the AWG engine
            // sees one stable peer and never learns the gateway's address.
            assertEquals(seam.localPort, received.port)
            assertTrue("seam counters: ${seam.describeForLog()}", seam.outgoingCount >= 1)
            assertTrue("seam counters: ${seam.describeForLog()}", seam.incomingCount >= 1)
        } finally {
            try { bridge.close() } catch (_: Exception) {}
            awg.close()
            gateway.close()
            gatewayDone.await(2, TimeUnit.SECONDS)
        }
    }

    /**
     * Only the AmneziaWG engine may use the relay. Without this, any process on
     * the device could inject datagrams into the tunnel or collect the
     * gateway's replies by racing to speak first.
     */
    @Test
    fun theLoopbackSeamPinsItsPeerAndIgnoresEveryOtherLocalSender() {
        val seam = WinnAwgLoopbackSeam.open()
        val dropped = ArrayList<String>()
        val pinnedSeam = WinnAwgLoopbackSeam.open(onDropped = { synchronized(dropped) { dropped.add(it) } })
        seam.close()

        val awg = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val intruder = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val target = InetSocketAddress(InetAddress.getByName("127.0.0.1"), pinnedSeam.localPort)
        try {
            val first = "from-awg".toByteArray()
            awg.send(DatagramPacket(first, first.size, target))
            val buffer = ByteArray(1500)
            assertEquals(first.size, pinnedSeam.readOutgoingDatagram(buffer))

            // The intruder speaks second, so it can never be the pinned peer.
            val bad = "from-somebody-else".toByteArray()
            intruder.send(DatagramPacket(bad, bad.size, target))
            val second = "from-awg-again".toByteArray()
            awg.send(DatagramPacket(second, second.size, target))

            val length = pinnedSeam.readOutgoingDatagram(buffer)
            assertEquals(
                "the intruder's datagram must not be carried",
                "from-awg-again",
                String(buffer, 0, length, Charsets.UTF_8),
            )
            synchronized(dropped) {
                assertTrue(dropped.toString(), dropped.any { it.contains("unexpected local sender") })
            }

            // Replies go to the pinned peer, never to the intruder.
            val inbound = "gateway-reply".toByteArray()
            pinnedSeam.writeIncomingDatagram(inbound, inbound.size)
            awg.soTimeout = 5_000
            val back = DatagramPacket(ByteArray(1500), 1500)
            awg.receive(back)
            assertEquals("gateway-reply", String(back.data, 0, back.length, Charsets.UTF_8))
        } finally {
            pinnedSeam.close()
            awg.close()
            intruder.close()
        }
    }

    /**
     * A datagram the engine cannot carry must be dropped whole. Silently
     * forwarding a truncated one would hand the gateway a corrupt AmneziaWG
     * frame, which is worse than losing it.
     */
    @Test
    fun theLoopbackSeamDropsOversizedDatagramsInsteadOfTruncatingThem() {
        val dropped = ArrayList<String>()
        val seam = WinnAwgLoopbackSeam.open(onDropped = { synchronized(dropped) { dropped.add(it) } })
        val awg = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val target = InetSocketAddress(InetAddress.getByName("127.0.0.1"), seam.localPort)
        try {
            val buffer = ByteArray(64)
            val oversized = ByteArray(200) { 'x'.code.toByte() }
            awg.send(DatagramPacket(oversized, oversized.size, target))
            val fits = ByteArray(32) { 'y'.code.toByte() }
            awg.send(DatagramPacket(fits, fits.size, target))

            assertEquals(32, seam.readOutgoingDatagram(buffer))
            synchronized(dropped) {
                assertTrue(dropped.toString(), dropped.any { it.contains("exceeds the engine's max_datagram") })
            }
        } finally {
            seam.close()
            awg.close()
        }
    }

    /** close() must release the bridge's inbound pump, which is parked in receive(). */
    @Test
    fun closingTheLoopbackSeamUnblocksAReaderRatherThanHangingShutdown() {
        val seam = WinnAwgLoopbackSeam.open()
        val result = java.util.concurrent.atomic.AtomicInteger(Int.MIN_VALUE)
        val reader = Thread { result.set(seam.readOutgoingDatagram(ByteArray(1500))) }
        reader.start()
        Thread.sleep(200)
        seam.close()
        reader.join(5_000)
        assertTrue("reader did not return after close()", !reader.isAlive)
        assertEquals(-1, result.get())
    }

    /**
     * The endpoint handed to AmneziaWG and the address this relay binds are
     * produced by the same class, and the address is always loopback. This is
     * the structural containment the design rests on, so it gets an assertion
     * rather than only a comment.
     */
    @Test
    fun theSeamOnlyEverAdvertisesALoopbackEndpoint() {
        val seam = WinnAwgLoopbackSeam.open()
        try {
            val endpoint = WinnAwgLoopbackSeam.peerEndpoint(seam.localPort)
            assertEquals("127.0.0.1:${seam.localPort}", endpoint)
            assertTrue(endpoint, WinnEngineConfig.isIpLiteralEndpoint(endpoint))
            assertTrue(
                endpoint,
                InetAddress.getByName(endpoint.substringBeforeLast(':')).isLoopbackAddress,
            )
        } finally {
            seam.close()
        }
    }

    /**
     * The redirect is what actually puts the AmneziaWG engine on the seam. If
     * it silently did nothing, AmneziaWG would keep talking to the gateway from
     * its own socket while everything else believed Winn was carrying the
     * traffic, so it must fail closed rather than pass the config through.
     */
    @Test
    fun theAwgEndpointRedirectRewritesExactlyOnePeerEndpoint() {
        val original = """
            [Interface]
            PrivateKey = aaa
            MTU = 1280

            [Peer]
            PublicKey = bbb
            Endpoint = 203.0.113.7:51820
            AllowedIPs = 0.0.0.0/0
        """.trimIndent()

        val redirected = WinnAwgLoopbackSeam.redirectPeerEndpoint(original, 41234)
        assertTrue(redirected, redirected.contains("Endpoint = 127.0.0.1:41234"))
        assertTrue(redirected, !redirected.contains("203.0.113.7"))
        // Nothing else may move: the keys, the MTU and the routes are untouched.
        assertTrue(redirected, redirected.contains("PrivateKey = aaa"))
        assertTrue(redirected, redirected.contains("AllowedIPs = 0.0.0.0/0"))
        assertEquals(original.lines().size, redirected.lines().size)
    }

    @Test
    fun theAwgEndpointRedirectRefusesAConfigWithNoEndpoint() {
        try {
            WinnAwgLoopbackSeam.redirectPeerEndpoint("[Peer]\nPublicKey = bbb", 41234)
            fail("a config with no endpoint must be refused, not passed through")
        } catch (e: IOException) {
            assertTrue(e.message!!, e.message!!.contains("has 0 peer endpoints"))
        }
    }

    @Test
    fun theAwgEndpointRedirectRefusesAConfigWithSeveralEndpoints() {
        val two = "[Peer]\nEndpoint = 203.0.113.7:51820\n[Peer]\nEndpoint = 203.0.113.8:51820"
        try {
            WinnAwgLoopbackSeam.redirectPeerEndpoint(two, 41234)
            fail("two peers must be refused: one of them would bypass Winn entirely")
        } catch (e: IOException) {
            assertTrue(e.message!!, e.message!!.contains("has 2 peer endpoints"))
        }
    }

    /**
     * The host that drives the seam test: the real bridge, the real seam, the
     * real engine binary, and the two things a plain JVM cannot provide.
     */
    private class StdioSeamHost(
        private val engine: File,
        private val seam: WinnAwgLoopbackSeam,
    ) : WinnEngineHost {

        override fun openProtectedUnderlaySocket(): WinnUnderlaySocket =
            object : WinnUnderlaySocket {
                override val descriptor: java.io.FileDescriptor = java.io.FileDescriptor()
                // The engine in this test opens its own socket, which is why
                // the config says allow_own_socket:true. On Android this is
                // false and the descriptor really crosses; that path is
                // covered by android/devicecheck/.
                override val protectedBeforeHandoff: Boolean = true
                override val localPort: Int = 0
                override fun close() {}
            }

        override fun startEngineProcess(): WinnEngineProcess {
            val process = ProcessBuilder(engine.absolutePath, "-transport", "stdio").start()
            Thread {
                try {
                    process.errorStream.bufferedReader().forEachLine { }
                } catch (_: Exception) {
                }
            }.apply { isDaemon = true; start() }
            return object : WinnEngineProcess {
                override val transport: WinnEngineTransport = StdioTransport(process)
                override fun isAlive(): Boolean = process.isAlive
                override fun describe(): String = "winn-datapath -transport stdio"
                override fun close() {
                    try { process.outputStream.close() } catch (_: Exception) {}
                    if (!process.waitFor(3, TimeUnit.SECONDS)) process.destroyForcibly()
                }
            }
        }

        override fun openAwgDatagramSeam(): WinnAwgDatagramSeam = seam
        override fun onDebug(message: String) {}
        override fun onWarning(message: String, error: Throwable?) {}
        override fun onError(message: String, error: Throwable?) {}
    }

    private class StdioTransport(process: Process) : WinnEngineTransport {
        private val out: OutputStream = process.outputStream
        private val reader = WinnFrameReader(process.inputStream, acceptEngineToHost = true)
        private val writeLock = Object()
        private val stream = process.outputStream

        override fun writeFrame(opcode: Int, payload: ByteArray) {
            synchronized(writeLock) { WinnFraming.writeFrame(out, opcode, payload) }
        }

        /**
         * A pipe cannot carry a descriptor. This is the ONE part of the contract
         * that only a real LocalSocket can exercise, and it is why
         * android/devicecheck/ exists.
         */
        override fun sendDescriptor(fd: java.io.FileDescriptor) = Unit

        override fun readFrame(): WinnFrame? = reader.read()

        /** stdio has no socket timeout; the engine's replies are awaited instead. */
        override fun setReadTimeoutMs(timeoutMs: Int) = Unit

        override fun close() {
            try { stream.close() } catch (_: Exception) {}
        }
    }

    // ------------------------------------------------------------------
    // Plumbing
    // ------------------------------------------------------------------

    private class Session(
        private val process: Process,
        private val out: OutputStream,
        input: InputStream,
    ) {
        private val reader = WinnFrameReader(input, acceptEngineToHost = true)

        fun write(opcode: Int, payload: ByteArray) = WinnFraming.writeFrame(out, opcode, payload)

        fun raw(bytes: ByteArray) {
            out.write(bytes)
            out.flush()
        }

        fun read(): WinnFrame? = reader.read()

        fun readOf(opcode: Int): WinnFrame {
            val frame = read() ?: throw AssertionError(
                "engine closed the channel instead of sending ${WinnFraming.opcodeName(opcode)}"
            )
            assertEquals(
                "engine said: ${frame.payloadAsText().take(400)}",
                WinnFraming.opcodeName(opcode),
                WinnFraming.opcodeName(frame.opcode),
            )
            return frame
        }

        fun awaitExit(): Boolean = process.waitFor(20, TimeUnit.SECONDS)
    }

    private fun withEngine(engine: File, body: (Session) -> Unit) {
        // redirectErrorStream stays FALSE: under -transport stdio the frames
        // are on stdout and a merged diagnostic would corrupt the stream.
        val process = ProcessBuilder(engine.absolutePath, "-transport", "stdio").start()
        val stderr = StringBuilder()
        val drain = Thread {
            try {
                process.errorStream.bufferedReader().forEachLine { synchronized(stderr) { stderr.appendLine(it) } }
            } catch (_: Exception) {
            }
        }.apply { isDaemon = true; start() }
        try {
            body(Session(process, process.outputStream, process.inputStream))
        } catch (t: Throwable) {
            drain.join(500)
            synchronized(stderr) {
                if (stderr.isNotEmpty()) System.err.println("engine stderr:\n$stderr")
            }
            throw t
        } finally {
            try {
                process.outputStream.close()
            } catch (_: Exception) {
            }
            if (!process.waitFor(5, TimeUnit.SECONDS)) process.destroyForcibly()
        }
    }

    private fun runCapturing(engine: File, vararg arguments: String): String {
        val process = ProcessBuilder(listOf(engine.absolutePath) + arguments)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.readBytes().toString(Charsets.UTF_8)
        process.waitFor(20, TimeUnit.SECONDS)
        return output
    }

    private fun runCapturingStderr(engine: File, vararg arguments: String): String {
        val process = ProcessBuilder(listOf(engine.absolutePath) + arguments).start()
        val output = process.errorStream.readBytes().toString(Charsets.UTF_8)
        process.waitFor(20, TimeUnit.SECONDS)
        return output
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    companion object {
        private var cached: File? = null
        private var attempted = false

        /**
         * The real engine binary, or null when this machine cannot produce one.
         *
         * Resolution order: `WINN_DATAPATH_BINARY`, then a `go build` of
         * `winn_protocol_experimental/cmd/winn-datapath`. It skips rather than
         * fails when there is no Go toolchain or no checkout of the other
         * lane's module, for the same reason the Go side skips its C++
         * conformance test: absence of the other lane's tree is not evidence
         * that this side is wrong. The golden-byte test above still runs and
         * still pins the format.
         */
        @Synchronized
        fun engineBinary(): File? {
            if (attempted) {
                val binary = cached
                assumeTrue(
                    "no winn-datapath binary and no Go toolchain to build one; " +
                        "set WINN_DATAPATH_BINARY to run the interop assertions",
                    binary != null,
                )
                return binary
            }
            attempted = true
            cached = resolveEngine()
            val binary = cached
            assumeTrue(
                "no winn-datapath binary and no Go toolchain to build one; " +
                    "set WINN_DATAPATH_BINARY to run the interop assertions",
                binary != null,
            )
            return binary
        }

        private fun resolveEngine(): File? {
            System.getenv("WINN_DATAPATH_BINARY")?.let { path ->
                val supplied = File(path)
                if (supplied.canExecute()) return supplied
            }
            val module = findModule() ?: return null
            if (whichGo() == null) return null
            val output = File.createTempFile("winn-datapath-interop", "")
            output.deleteOnExit()
            val process = ProcessBuilder(
                "go", "build", "-o", output.absolutePath, "./cmd/winn-datapath",
            ).directory(module).redirectErrorStream(true).start()
            val log = process.inputStream.readBytes().toString(Charsets.UTF_8)
            if (!process.waitFor(10, TimeUnit.MINUTES) || process.exitValue() != 0) {
                System.err.println("winn-datapath build failed:\n$log")
                return null
            }
            output.setExecutable(true)
            return output
        }

        /** Walks up from the test's working directory to the Go module. */
        private fun findModule(): File? {
            val workingDirectory = System.getProperty("user.dir") ?: return null
            var directory: File? = File(workingDirectory).absoluteFile
            while (directory != null) {
                val candidate = File(directory, "winn_protocol_experimental")
                if (File(candidate, "go.mod").isFile) return candidate
                directory = directory.parentFile
            }
            return null
        }

        private fun whichGo(): String? =
            (System.getenv("PATH") ?: "").split(File.pathSeparator)
                .map { File(it, "go") }
                .firstOrNull { it.canExecute() }
                ?.absolutePath
    }
}
