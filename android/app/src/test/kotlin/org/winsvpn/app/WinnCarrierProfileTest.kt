package org.winsvpn.app

import java.io.File
import java.io.IOException
import java.nio.file.Files
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * The carrier profile document, and the refusals around it.
 *
 * `carrierhost.Profile` decodes with `DisallowUnknownFields` and refuses a
 * document that does not declare its version, so a key this host invents is a
 * hard engine-startup failure rather than a silent default. These tests pin the
 * shape, the fail-closed behaviour when credentials are absent, and the one
 * property that matters most: that no key material is ever written into the
 * document.
 */
class WinnCarrierProfileTest {

    private lateinit var root: File
    private lateinit var credentials: File

    @Before
    fun setUp() {
        root = Files.createTempDirectory("winn-carrier-profile-test").toFile()
        credentials = WinnCarrierProfile.credentialDirectory(root)
    }

    @After
    fun tearDown() {
        root.deleteRecursively()
    }

    /** Writes placeholder files with the names the profile expects. */
    private fun provisionCredentials() {
        assertTrue(credentials.mkdirs() || credentials.isDirectory)
        for ((name, _) in WinnCarrierProfile.CredentialSet.REQUIRED_FILES) {
            File(credentials, name).writeText("lab placeholder for $name")
        }
    }

    private fun section(vararg overrides: Pair<String, String>): Map<String, String> {
        val base = linkedMapOf(
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
        for ((key, value) in overrides) {
            if (value.isEmpty()) base.remove(key) else base[key] = value
        }
        return base
    }

    private fun profile(vararg overrides: Pair<String, String>): WinnCarrierProfile =
        WinnCarrierProfile.from(
            section = section(*overrides),
            carrier = WinnCarrierProfile.CARRIER_HTTP3,
            credentialDirectory = credentials,
        )

    // ---------------------------------------------------------------- shape

    @Test
    fun emitsOnlyFieldsCarrierhostDefines() {
        provisionCredentials()
        val json = profile().toJson()
        val keys = Regex("\"([a-z0-9_]+)\":").findAll(json).map { it.groupValues[1] }.toList()
        // Exactly the JSON tags of carrierhost.Profile that this host sets, in
        // the order it writes them. Anything else fails DisallowUnknownFields.
        assertEquals(
            listOf(
                "profile", "carrier", "masque_template", "public_target",
                "server_name", "suite", "controller_id", "controller_pins_path",
                "root_ca_path", "ech_config_list_path", "authorization_mode",
                "device_id", "device_pq_algorithm", "device_seed_path",
                "client_cert_path", "client_key_path", "session_id",
                "manifest_digest", "max_inner_datagram", "privacy_profile",
            ),
            keys,
        )
        assertTrue(json, json.contains("\"profile\":\"winn-carrier-profile/1\""))
        assertTrue(json, json.contains("\"carrier\":\"http3-connect-udp\""))
        assertTrue(json, json.contains("\"authorization_mode\":\"identity\""))
    }

    @Test
    fun neverNamesAGatewayManifestItDoesNotVerify() {
        // carrierhost REFUSES a profile carrying manifest_path, because it does
        // not run LoadVerifiedNodeV2 and will not read its own transport fields
        // while claiming a manifest was checked. Emitting the key would turn
        // every carrier session into a startup failure.
        provisionCredentials()
        assertFalse(profile().toJson().contains("manifest_path"))
    }

    @Test
    fun neverRequestsAnonymousTokenAuthorization() {
        // carrierhost refuses it: the anonymous route needs an issued
        // privacy-token pool verified against the signed manifest's issuer
        // keys, which is not a file a loader can read.
        provisionCredentials()
        val json = profile().toJson()
        assertFalse(json, json.contains("anonymous-token"))
        assertTrue(json, json.contains("\"authorization_mode\":\"identity\""))
    }

    @Test
    fun h2FieldsAreNeverSetOnAnH3Profile() {
        // `h2_url` on an http3 profile is ErrCarrierFieldMismatch.
        provisionCredentials()
        assertFalse(profile().toJson().contains("h2_url"))
    }

    @Test
    fun defaultsMatchCarrierhostRatherThanBeingInvented() {
        provisionCredentials()
        val json = profile().toJson()
        // The zero value of PrivacyProfile pads, matching
        // EnvelopeConfig.DisableLengthPadding, so an unspecified profile still
        // gets the defence.
        assertTrue(json, json.contains("\"privacy_profile\":\"high-risk\""))
        assertTrue(json, json.contains("\"max_inner_datagram\":1500"))
        // sequence_epoch defaults to session_id inside carrierhost, so it is
        // omitted rather than guessed at here.
        assertFalse(json, json.contains("sequence_epoch"))
    }

    // -------------------------------------------------------- key material

    @Test
    fun secretsAreNamedByPathAndNeverInlined() {
        provisionCredentials()
        // Every credential file gets distinctive content. If any of it appears
        // in the document, this host read a secret it has no business reading.
        val canary = "CANARY-e3b0c44298fc1c149afbf4c8996fb924"
        for ((name, _) in WinnCarrierProfile.CredentialSet.REQUIRED_FILES) {
            File(credentials, name).writeText("$canary-$name")
        }
        val json = profile().toJson()
        assertFalse(
            "The profile document contains credential file CONTENT. Secrets are " +
                "named by path and read by the loader that owns each format; this " +
                "class must never open one.",
            json.contains(canary),
        )
        // ...and each one is named by path.
        for ((name, _) in WinnCarrierProfile.CredentialSet.REQUIRED_FILES) {
            assertTrue(name, json.contains(File(credentials, name).absolutePath))
        }
    }

    @Test
    fun theLogSummaryNamesNoPathAndNoSecret() {
        provisionCredentials()
        val described = profile().describeForLog()
        assertFalse(described, described.contains(credentials.absolutePath))
        assertFalse(described, described.contains(root.absolutePath))
        // Not one credential file is named, even by basename.
        for ((name, _) in WinnCarrierProfile.CredentialSet.REQUIRED_FILES) {
            assertFalse(described, described.contains(name))
        }
        // The only '/' is the one inside the profile version constant.
        assertEquals(1, described.count { it == '/' })
        assertTrue(described, described.contains("carrier=http3-connect-udp"))
        assertTrue(described, described.contains("manifest_verified=false"))
    }

    @Test
    fun theProfileFileIsOwnerOnly() {
        provisionCredentials()
        val file = profile().writeTo(WinnCarrierProfile.profileDirectory(root))
        // securefile.ReadPrivateLimited refuses a profile whose mode grants
        // group or other access BEFORE it parses a byte, so a wider mode would
        // not be a weaker session -- it would be a session that never starts.
        // Asserting it here means the failure is caught in this suite instead.
        val permissions = Files.getPosixFilePermissions(file.toPath())
        assertTrue(
            "profile mode is $permissions, want owner-only",
            permissions.none { it.name.startsWith("GROUP_") || it.name.startsWith("OTHERS_") },
        )
        assertTrue(WinnCarrierProfile.isOwnerOnly(file))
    }

    @Test
    fun aStaleProfileIsReplacedRatherThanAppendedTo() {
        provisionCredentials()
        val directory = WinnCarrierProfile.profileDirectory(root)
        val first = profile().writeTo(directory)
        val firstText = first.readText()
        val second = profile().writeTo(directory)
        val secondText = second.readText()
        assertEquals(first.absolutePath, second.absolutePath)
        assertTrue(secondText.startsWith("{"))
        assertTrue(secondText.endsWith("}"))
        // A fresh session identifier each time proves the file was rewritten,
        // not appended to or reused.
        assertNotEquals(firstText, secondText)
    }

    // ------------------------------------------------------- fail closed

    @Test
    fun anUnprovisionedCredentialIsNamedRatherThanDefaulted() {
        provisionCredentials()
        for ((name, _) in WinnCarrierProfile.CredentialSet.REQUIRED_FILES) {
            val file = File(credentials, name)
            assertTrue(file.delete())
            try {
                profile()
                fail("A missing '$name' must refuse, not substitute a default")
            } catch (e: IOException) {
                assertTrue(e.message, e.message!!.contains(name))
                // Specifically the not-provisioned refusal. Asserting only that
                // SOME IOException mentioned the file let a mutation through:
                // removing the isFile check still threw, from the length check
                // below it, with a message that also named the file.
                assertTrue(e.message, e.message!!.contains("not provisioned"))
                assertTrue(e.message, e.message!!.contains(file.absolutePath))
            }
            file.writeText("restored")
        }
    }

    @Test
    fun noCredentialDirectoryAtAllIsARefusalAndNotADirectAwgFallback() {
        // This is the honest state of the platform today: the wiring is
        // complete and the credentials are not provisioned. The refusal must
        // name what is missing and must never resolve to a weaker carrier.
        try {
            profile()
            fail("An unprovisioned device must refuse an authenticated carrier")
        } catch (e: IOException) {
            assertTrue(e.message, e.message!!.contains("not provisioned"))
            assertFalse(e.message, e.message!!.contains("direct-awg"))
        }
    }

    @Test
    fun anEmptyCredentialIsRefused() {
        provisionCredentials()
        val seed = File(credentials, "device_mldsa_seed.bin")
        seed.writeText("")
        try {
            profile()
            fail("An empty credential must refuse")
        } catch (e: IOException) {
            assertTrue(e.message, e.message!!.contains("empty"))
        }
    }

    // ------------------------------------------------------ field validation

    @Test
    fun http2IsRefusedForTheSocketItWouldNeed() {
        provisionCredentials()
        try {
            WinnCarrierProfile.from(
                section = section("carrier" to WinnCarrierProfile.CARRIER_HTTP2),
                carrier = WinnCarrierProfile.CARRIER_HTTP2,
                credentialDirectory = credentials,
            )
            fail("http2-stream must be refused by this host")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message, e.message!!.contains("CONNECTED"))
            assertTrue(e.message, e.message!!.contains("TCP"))
        }
    }

    @Test
    fun directAwgHasNoProfile() {
        provisionCredentials()
        try {
            WinnCarrierProfile.from(
                section = section(),
                carrier = WinnEngineConfig.CARRIER_DIRECT_AWG,
                credentialDirectory = credentials,
            )
            fail("direct-awg must not produce a carrier profile")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message, e.message!!.contains("no carrier profile"))
        }
    }

    @Test
    fun aSuiteOutsideTheHybridSetIsRefused() {
        provisionCredentials()
        // The whole point of the carrier is the post-quantum key agreement. A
        // classical group here would be the downgrade the session exists to
        // prevent, so it is refused rather than passed to ParseSuite.
        for (suite in listOf("x25519", "p256", "", "x25519-mlkem768-draft", "rsa")) {
            try {
                profile("suite" to suite)
                fail("suite '$suite' must be refused")
            } catch (e: IllegalArgumentException) {
                assertTrue(e.message, e.message!!.contains("suite"))
            }
        }
        // ...and every hybrid group tlsconfig.ParseSuite knows is accepted.
        for (suite in WinnCarrierProfile.SUPPORTED_SUITES) {
            assertTrue(suite, profile("suite" to suite).toJson().contains(suite))
        }
    }

    @Test
    fun aNonHybridPqAlgorithmIsRefused() {
        provisionCredentials()
        // "ML-DSA-65" is in this list on purpose. It is the NIST spelling and
        // it is NOT the value this protocol uses -- `pqauth` takes `mldsa65`
        // -- and an earlier revision of this host emitted the pretty form,
        // which the real engine refused with "is not an ML-DSA parameter set
        // this build knows". Refusing it here means that failure lands in this
        // suite rather than on a device.
        for (algorithm in listOf("ed25519", "ML-DSA-65", "mldsa44", "", "mlkem768")) {
            try {
                profile("device_pq_algorithm" to algorithm)
                fail("device_pq_algorithm '$algorithm' must be refused")
            } catch (e: IllegalArgumentException) {
                assertTrue(e.message, e.message!!.contains("ML-DSA"))
            }
        }
        for (algorithm in WinnCarrierProfile.SUPPORTED_PQ_ALGORITHMS) {
            assertTrue(
                algorithm,
                profile("device_pq_algorithm" to algorithm).toJson()
                    .contains("\"device_pq_algorithm\":\"$algorithm\""),
            )
        }
    }

    @Test
    fun aPublicTargetHostnameIsRefused() {
        provisionCredentials()
        for (target in listOf("gateway.example:51820", "51820", "", "0.0.0.0:51820")) {
            try {
                profile("public_target" to target)
                fail("public_target '$target' must be refused")
            } catch (e: IllegalArgumentException) {
                assertTrue(e.message, e.message!!.contains("public_target"))
            }
        }
    }

    @Test
    fun aNonHttpsTemplateIsRefused() {
        provisionCredentials()
        for (template in listOf(
            "http://carrier.example/x",
            "carrier.example/x",
            "https://",
            "",
        )) {
            try {
                profile("masque_template" to template)
                fail("masque_template '$template' must be refused")
            } catch (e: IllegalArgumentException) {
                assertTrue(e.message, e.message!!.contains("masque_template"))
            }
        }
        // The RFC 9298 expansions are not a URI-parser's idea of legal, and
        // must still be accepted.
        assertTrue(
            profile().toJson().contains("{target_host}"),
        )
    }

    @Test
    fun aMalformedManifestDigestIsRefused() {
        provisionCredentials()
        for (digest in listOf("", "a".repeat(63), "a".repeat(65), "g".repeat(64), "0x" + "a".repeat(62))) {
            try {
                profile("manifest_digest" to digest)
                fail("manifest_digest '$digest' must be refused")
            } catch (e: IllegalArgumentException) {
                assertTrue(e.message, e.message!!.contains("manifest_digest"))
            }
        }
    }

    @Test
    fun anUppercaseDigestIsNormalizedRatherThanRefused() {
        provisionCredentials()
        // carrierhost requires LOWERCASE hex, so an uppercase digest served by
        // a gateway would be refused by the engine after this host had already
        // protected a socket. Case does not change a hex value, so normalizing
        // is safe -- and it is normalization, not leniency: what reaches the
        // document is the lowercase form the engine accepts.
        val json = profile("manifest_digest" to "AB".repeat(32)).toJson()
        assertTrue(json, json.contains("\"manifest_digest\":\"${"ab".repeat(32)}\""))
        assertFalse(json, json.contains("AB"))
    }

    @Test
    fun theSessionIdIsGeneratedHereAndIsAValidMobilitySessionId() {
        provisionCredentials()
        val ids = (1..32).map { WinnCarrierProfile.newSessionId() }.toSet()
        // mobility.ValidSessionID: 32 lowercase hexadecimal characters.
        for (id in ids) {
            assertTrue(id, WinnCarrierProfile.isHex(id, 32))
        }
        // Distinct, because a session identifier reused across sessions would
        // link them.
        assertEquals(32, ids.size)
        // It is never served: nothing in the section supplies it.
        assertFalse(section().containsKey("session_id"))
        val json = profile().toJson()
        val emitted = Regex("\"session_id\":\"([0-9a-f]{32})\"").find(json)
        assertTrue(json, emitted != null)
    }

    // ------------------------------------- single packet authorization (SPA)

    /** The six always-required files plus the knock key. */
    private fun provisionCredentialsWithKnockKey() {
        provisionCredentials()
        // A hex-shaped placeholder. It is never opened by this host -- the
        // engine's knock.LoadKeysFromFile owns the format -- so its value is a
        // marker chosen so a test can assert it did NOT reach the document.
        File(credentials, WinnCarrierProfileKeys.SPA_KEY_CREDENTIAL_FILE_NAME)
            .writeText("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n")
    }

    private val spaSection = arrayOf(
        "spa_mode" to "required",
        "spa_target" to "198.51.100.20:9111",
        "spa_packet_size" to "256",
        "spa_bucket_window_seconds" to "10",
        "spa_max_skew_seconds" to "60",
    )

    /**
     * THE HEADLINE TEST. Every served knock parameter reaches the document,
     * unmodified, alongside the device-local key path this host resolved.
     *
     * Before this change the emitter carried a closed allowlist that excluded
     * every `spa_` key, so a profile carrying these five was stripped to
     * nothing on the way to the engine and single packet authorization could
     * not be deployed from any client at all.
     */
    @Test
    fun spaParametersSurviveTheEmitterUnmodified() {
        provisionCredentialsWithKnockKey()
        val json = profile(*spaSection).toJson()

        assertTrue(json, json.contains("\"spa_mode\":\"required\""))
        assertTrue(json, json.contains("\"spa_target\":\"198.51.100.20:9111\""))
        // Numbers, not strings: carrierhost decodes these into ints and a
        // quoted value is a parse failure.
        assertTrue(json, json.contains("\"spa_packet_size\":256"))
        assertTrue(json, json.contains("\"spa_bucket_window_seconds\":10"))
        assertTrue(json, json.contains("\"spa_max_skew_seconds\":60"))

        // The key is named by PATH, and its contents never appear.
        assertTrue(
            json,
            json.contains(
                "\"spa_key_path\":\"" +
                    File(
                        credentials,
                        WinnCarrierProfileKeys.SPA_KEY_CREDENTIAL_FILE_NAME,
                    ).absolutePath + "\"",
            ),
        )
        assertFalse(json, json.contains("00112233445566778899aabbccddeeff"))
    }

    /**
     * The exact key list, in order. `carrierhost.Profile` declares the six
     * `spa_` fields last and in this order, and the four platform emitters are
     * compared byte for byte in review.
     */
    @Test
    fun spaFieldsAreEmittedLastAndInSchemaOrder() {
        provisionCredentialsWithKnockKey()
        val json = profile(*spaSection).toJson()
        val keys = Regex("\"([a-z0-9_]+)\":").findAll(json).map { it.groupValues[1] }.toList()
        assertEquals(
            listOf(
                "spa_mode", "spa_key_path", "spa_target", "spa_packet_size",
                "spa_bucket_window_seconds", "spa_max_skew_seconds",
            ),
            keys.filter { it.startsWith("spa_") },
        )
        assertEquals("privacy_profile", keys[keys.indexOf("spa_mode") - 1])
    }

    /**
     * SPA OFF EMITS NOTHING, and this is a contract rather than tidiness -- but
     * be exact about the reason. `carrierhost.normalizeSPA` REFUSES a document
     * carrying a NON-EMPTY `spa_` field while the mode is off
     * (`ErrSPAFieldWithoutMode`); an emitter that wrote `"spa_mode":"off"` or
     * `"spa_target":""` would NOT break non-SPA carrier sessions, because the
     * stray sweep tests `TrimSpace(...) != ""` and `!= 0`, so those parse fine.
     * (An earlier version of this comment claimed the opposite; it was checked
     * against ParseProfile and is false.) The assertion below is still the
     * right one: "no `spa_` substring anywhere" is checkable without modelling
     * which empty values are forgiven, and it makes the one shape that IS a
     * hard refusal -- a non-empty stray -- unreachable from this emitter.
     */
    @Test
    fun aProfileWithoutSpaEmitsNoSpaFieldAtAll() {
        provisionCredentials()
        val json = profile().toJson()
        assertFalse(json, json.contains("spa_"))
        assertTrue(json, profile().describeForLog().contains("spa=off"))
    }

    /**
     * A stray `spa_` field with the mode off is a REFUSAL, not a silent drop.
     * Dropping it is precisely how this whole capability came to be
     * unreachable: every host quietly discarded a key it did not recognise.
     */
    @Test
    fun aStraySpaFieldWithoutTheModeIsRefused() {
        provisionCredentialsWithKnockKey()
        for (stray in WinnCarrierProfileKeys.SPA.filter { it != "spa_mode" }) {
            try {
                profile(stray to if (stray == "spa_target") "198.51.100.20:9111" else "10")
                fail("a $stray without spa_mode must be refused")
            } catch (e: IllegalArgumentException) {
                assertTrue(e.message!!, e.message!!.contains(stray))
            }
        }
    }

    /**
     * The refusal that replaces a silent runtime failure.
     *
     * `carrierhost` accepts any non-empty `spa_key_path` at PARSE time -- the
     * file is not opened until `BuildDialer`, at Create time, long after this
     * host has protected a socket and spawned the engine. So an unprovisioned
     * device would build a valid-looking profile, start a tunnel and then fail
     * somewhere a user only experiences as "it doesn't connect".
     */
    @Test
    fun spaWithNoProvisionedKnockKeyIsRefusedByName() {
        provisionCredentials() // the six, but NOT the knock key
        try {
            profile(*spaSection)
            fail("SPA with no knock key on the device must be refused")
        } catch (e: IOException) {
            assertTrue(
                e.message!!,
                e.message!!.contains(WinnCarrierProfileKeys.SPA_KEY_CREDENTIAL_FILE_NAME),
            )
            // It says WHY, so the next reader is not left guessing whether the
            // app was supposed to have generated one.
            assertTrue(e.message!!, e.message!!.contains("out of band"))
        }
    }

    /** A knock key is NOT required by an ordinary carrier session. */
    @Test
    fun anOrdinaryCarrierProfileNeedsNoKnockKey() {
        provisionCredentials()
        val json = profile().toJson()
        assertTrue(json, json.contains("\"carrier\":\"http3-connect-udp\""))
    }

    @Test
    fun anUnknownSpaModeIsRefused() {
        provisionCredentialsWithKnockKey()
        try {
            profile("spa_mode" to "advisory", "spa_target" to "198.51.100.20:9111")
            fail("an unknown spa_mode must be refused")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!, e.message!!.contains("spa_mode"))
        }
    }

    /**
     * `spa_target` is required and must be an IP literal. There is deliberately
     * no default: the gate may sit in front of the carrier listener or in front
     * of the AmneziaWG gateway, and a wrong guess would send the deployment's
     * shared credential to a host that is not supposed to have it.
     */
    @Test
    fun spaTargetMustBeAnIpLiteralWithAPort() {
        provisionCredentialsWithKnockKey()
        for (bad in listOf("", "gate.example:9111", "198.51.100.20", "0.0.0.0:9111")) {
            try {
                profile("spa_mode" to "required", "spa_target" to bad)
                fail("spa_target '$bad' must be refused")
            } catch (e: IllegalArgumentException) {
                assertTrue(e.message!!, e.message!!.contains("spa_target"))
            }
        }
    }

    @Test
    fun spaScalarsAreRangeChecked() {
        provisionCredentialsWithKnockKey()
        val bad = listOf(
            "spa_packet_size" to "47",
            "spa_packet_size" to "1501",
            "spa_packet_size" to "-1",
            "spa_packet_size" to "not-a-number",
            "spa_max_skew_seconds" to "5", // below the 10s bucket below
        )
        for ((key, value) in bad) {
            try {
                profile(
                    "spa_mode" to "required",
                    "spa_target" to "198.51.100.20:9111",
                    "spa_bucket_window_seconds" to "10",
                    key to value,
                )
                fail("$key = $value must be refused")
            } catch (e: IllegalArgumentException) {
                assertTrue(e.message!!, e.message!!.contains(key))
            }
        }
    }

    /**
     * Omitting an optional scalar is legal and means "let the engine derive
     * it", which is exactly what a zero means in `carrierhost.Profile`.
     */
    @Test
    fun theOptionalSpaScalarsMayBeOmitted() {
        provisionCredentialsWithKnockKey()
        val json = profile(
            "spa_mode" to "required",
            "spa_target" to "198.51.100.20:9111",
        ).toJson()
        assertTrue(json, json.contains("\"spa_mode\":\"required\""))
        assertFalse(json, json.contains("spa_packet_size"))
        assertFalse(json, json.contains("spa_bucket_window_seconds"))
        assertFalse(json, json.contains("spa_max_skew_seconds"))
    }

    /**
     * The log line names the MODE and nothing else. The key path names a
     * credential file and the target names a host that is supposed to be
     * invisible -- publishing either in a log would undo the point of gating it.
     */
    @Test
    fun theLogSummaryNamesTheModeAndNeverTheKeyPathOrTarget() {
        provisionCredentialsWithKnockKey()
        val described = profile(*spaSection).describeForLog()
        assertTrue(described, described.contains("spa=required"))
        assertFalse(described, described.contains("198.51.100.20:9111"))
        assertFalse(described, described.contains("spa_knock_key"))
        assertFalse(described, described.contains(credentials.absolutePath))
    }

    /**
     * The generated key list really is the one this emitter uses, and it really
     * does carry the SPA keys. If [WinnCarrierProfileKeys] were ever hand-edited
     * back to a stale copy, this fails here as well as in the Go drift test.
     */
    @Test
    fun theGeneratedKeyListCarriesEverySpaParameter() {
        assertTrue(WinnCarrierProfile.CARRIER_KEYS.containsAll(WinnCarrierProfileKeys.SPA))
        assertEquals(
            setOf(
                "spa_mode", "spa_target", "spa_packet_size",
                "spa_bucket_window_seconds", "spa_max_skew_seconds",
            ),
            WinnCarrierProfileKeys.SPA,
        )
        // spa_key_path is a DEVICE-LOCAL path, never a served key. A control
        // plane that could choose it would be choosing which file the engine
        // opens.
        assertFalse(WinnCarrierProfile.CARRIER_KEYS.contains("spa_key_path"))
    }
}
