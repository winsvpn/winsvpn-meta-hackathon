package org.winsvpn.app

import java.io.File
import java.io.IOException
import java.security.SecureRandom

/**
 * The carrier profile document `winn-datapath` reads from `-carrier-profile
 * PATH`, and the file this host writes to produce it.
 *
 * THE SCHEMA IS THE ENGINE'S, NOT THIS FILE'S. Every key below is a field of
 * `carrierhost.Profile` in
 * `winn_protocol_experimental/datapath/carrierhost/profile.go`, which decodes
 * with `DisallowUnknownFields` and refuses a document that does not declare
 * [PROFILE_VERSION]. A misspelled key is therefore a hard startup failure in
 * the engine, not a silent default -- so this file emits those keys and nothing
 * else.
 *
 * # Why a file on argv, and not the Create frame
 *
 * `datapath/carrier.go` records the rule: an authenticated carrier
 * configuration has no business crossing the C ABI as a JSON blob, and the same
 * objection applies to the duplex frame channel, whose payload is peer-supplied
 * by construction. A PATH is different in kind -- the engine opens the file
 * itself, under this application's own uid, and makes every trust decision
 * there rather than trusting whoever wrote a frame.
 *
 * Android is the platform where this works at all: it spawns the engine as a
 * SUBPROCESS speaking the framed WNN3 duplex protocol, so the child has argv
 * and a filesystem. (iOS and macOS reach the datapath through the C ABI in
 * `cdatapath/`, which has neither, which is why this seam is Android-and-
 * Windows-shaped.)
 *
 * # KEY MATERIAL NEVER APPEARS IN THIS DOCUMENT
 *
 * Every secret -- the device ML-DSA seed, the client private key -- is named by
 * PATH and read by the loader that already owns that file format
 * (`pqauth.LoadSigner`, `tlsconfig.Client*`). This class therefore never opens
 * a credential file, never parses one, and never holds one in memory. It checks
 * that each exists and is a regular file, and writes its path. That is the
 * whole of its relationship with key material, and [CredentialSet.resolve] is
 * written so it cannot acquire a larger one by accident.
 *
 * The profile document itself is written 0600 because
 * `securefile.ReadPrivateLimited` refuses a profile whose mode grants group or
 * other access before it parses a byte of it. On Android `filesDir` is already
 * 0700 and not backed up; the mode on the file is belt and braces, and it is
 * asserted by a test rather than assumed.
 *
 * # What a profile does and does not buy
 *
 * A session built from one really does perform the post-quantum carrier
 * handshake: TLS 1.3 restricted to the named hybrid group, Encrypted Client
 * Hello from the configured list, ML-DSA request signing by the device key and
 * ML-DSA response verification against PINNED controller keys.
 *
 * It does NOT prove node selection. The production route binds the transport,
 * the suite, the ECH list and the public target to a controller-signed,
 * transparency-logged gateway manifest, and `carrierhost` deliberately REFUSES
 * a profile that names one rather than pretending to verify it. This class
 * never emits `manifest_path` for exactly that reason: a profile without a
 * manifest is the direct-pin route, and it is exactly as trustworthy as the
 * channel that delivered the `[winn]` section, and no more.
 *
 * Deliberately free of Android imports so it can be exercised on a plain JVM,
 * the same way [WinnTunnelBridge] is.
 */
internal class WinnCarrierProfile private constructor(
    val carrier: String,
    private val masqueTemplate: String,
    private val publicTarget: String,
    private val serverName: String,
    private val suite: String,
    private val controllerId: String,
    private val credentials: ResolvedCredentials,
    private val deviceId: String,
    private val deviceAlgorithm: String,
    private val sessionId: String,
    private val sequenceEpoch: String,
    private val manifestDigest: String,
    private val maxInnerDatagram: Int,
    private val privacyProfile: String,
    private val spa: ResolvedSpa?,
) {

    /**
     * The document. Contains no key material -- only paths -- but it names
     * every private file this device holds, so it is not logged. Use
     * [describeForLog].
     */
    fun toJson(): String {
        val sb = StringBuilder(1024)
        sb.append('{')
        appendPair(sb, "profile", PROFILE_VERSION)
        sb.append(',')
        appendPair(sb, "carrier", carrier)
        // masque_template is HTTP/3 only, and `h2_url` set on an HTTP/3 profile
        // is ErrCarrierFieldMismatch, so the field for the other carrier is
        // never emitted rather than emitted empty.
        if (carrier == CARRIER_HTTP3) {
            sb.append(',')
            appendPair(sb, "masque_template", masqueTemplate)
        }
        sb.append(',')
        appendPair(sb, "public_target", publicTarget)
        sb.append(',')
        appendPair(sb, "server_name", serverName)
        sb.append(',')
        appendPair(sb, "suite", suite)
        sb.append(',')
        appendPair(sb, "controller_id", controllerId)
        sb.append(',')
        appendPair(sb, "controller_pins_path", credentials.controllerPins)
        sb.append(',')
        appendPair(sb, "root_ca_path", credentials.rootCA)
        sb.append(',')
        appendPair(sb, "ech_config_list_path", credentials.echConfigList)
        // Identity mode only. carrierhost refuses "anonymous-token" outright --
        // that route needs an issued privacy-token pool verified against the
        // signed manifest's issuer keys, which is not a file a loader can read
        // -- so this host does not offer a way to ask for it.
        sb.append(',')
        appendPair(sb, "authorization_mode", AUTH_MODE_IDENTITY)
        sb.append(',')
        appendPair(sb, "device_id", deviceId)
        sb.append(',')
        appendPair(sb, "device_pq_algorithm", deviceAlgorithm)
        sb.append(',')
        appendPair(sb, "device_seed_path", credentials.deviceSeed)
        sb.append(',')
        appendPair(sb, "client_cert_path", credentials.clientCert)
        sb.append(',')
        appendPair(sb, "client_key_path", credentials.clientKey)
        sb.append(',')
        appendPair(sb, "session_id", sessionId)
        if (sequenceEpoch.isNotEmpty()) {
            sb.append(',')
            appendPair(sb, "sequence_epoch", sequenceEpoch)
        }
        sb.append(',')
        appendPair(sb, "manifest_digest", manifestDigest)
        sb.append(',')
        appendPair(sb, "max_inner_datagram", maxInnerDatagram.toString(), quoted = false)
        sb.append(',')
        appendPair(sb, "privacy_profile", privacyProfile)
        // SINGLE PACKET AUTHORIZATION. Emitted only when it is actually on, so
        // every field below is inside the null check rather than emitted empty.
        //
        // Be exact about why. `carrierhost.normalizeSPA` REFUSES a document
        // that carries a NON-EMPTY `spa_` field while the mode is off or absent
        // (`ErrSPAFieldWithoutMode`), because a stray target left behind after
        // SPA was turned off is the operator believing something is armed that
        // is not. It does NOT refuse an empty one: the stray sweep tests
        // `TrimSpace(...) != ""` for strings and `!= 0` for the scalars, so
        // `"spa_mode":"off"` and `"spa_target":""` parse fine and are
        // indistinguishable from absent. An earlier version of this comment
        // claimed they were a hard parse failure; that was checked against
        // ParseProfile and is false. Omitting is still the rule, because a
        // document with no `spa_` substring cannot be misread, and because the
        // failure that IS real is one-sided: a non-empty stray refuses the
        // whole profile, and an emitter that never writes these keys unless SPA
        // is on can never produce one.
        //
        // Field order matches `carrierhost.Profile`'s own declaration order.
        spa?.let { active ->
            sb.append(',')
            appendPair(sb, "spa_mode", SPA_MODE_REQUIRED)
            sb.append(',')
            // A PATH, never the key. This class resolves it from the credential
            // directory and never opens it: `knock.LoadKeysFromFile`, the loader
            // that owns the format, reads it inside the engine's BuildDialer.
            appendPair(sb, "spa_key_path", active.keyPath)
            sb.append(',')
            appendPair(sb, "spa_target", active.target)
            // Zero means "use the engine's derived/default value" for each of
            // these, and the engine does exactly that, so omitting is identical
            // to sending 0 and produces a smaller document.
            if (active.packetSize != 0) {
                sb.append(',')
                appendPair(sb, "spa_packet_size", active.packetSize.toString(), quoted = false)
            }
            if (active.bucketWindowSeconds != 0) {
                sb.append(',')
                appendPair(
                    sb, "spa_bucket_window_seconds",
                    active.bucketWindowSeconds.toString(), quoted = false,
                )
            }
            if (active.maxSkewSeconds != 0) {
                sb.append(',')
                appendPair(
                    sb, "spa_max_skew_seconds",
                    active.maxSkewSeconds.toString(), quoted = false,
                )
            }
        }
        // `manifest_path` is NEVER emitted. See the class KDoc: naming a
        // manifest makes carrierhost refuse the profile, because it does not run
        // LoadVerifiedNodeV2 and will not read its own transport fields while
        // claiming a manifest was checked.
        sb.append('}')
        return sb.toString()
    }

    /**
     * Key names, modes and scalars only -- never a path, because a path names a
     * private file. Safe to log; [toJson] is not.
     */
    fun describeForLog(): String =
        "winn carrier profile: version=$PROFILE_VERSION carrier=$carrier suite=$suite " +
            "mode=$AUTH_MODE_IDENTITY privacy=$privacyProfile pq_algorithm=$deviceAlgorithm " +
            "max_inner_datagram=$maxInnerDatagram manifest_verified=false " +
            // The MODE only. Never the key path, never the target: the path
            // names a credential file and the target names a host that is
            // supposed to be invisible, and the whole point of SPA is that
            // neither is discoverable from this device's logs. Matches
            // `carrierhost.Profile.DescribeForLog`, which prints the same one
            // field for the same reason.
            "spa=${if (spa == null) SPA_MODE_OFF else SPA_MODE_REQUIRED}"

    /**
     * Writes the profile to [directory] with mode 0600 and returns the file.
     *
     * The mode is set BEFORE the bytes are written, so the document is never
     * momentarily readable by another uid, and it is set through
     * [java.io.File] rather than `java.nio.file.Files` because
     * `setPosixFilePermissions` needs API 26 and this app's minSdk is 24.
     *
     * @throws IOException if the file cannot be created with owner-only access.
     *   Never falls back to a wider mode: `securefile.ReadPrivateLimited`
     *   refuses the profile anyway, and a wider one would be worse than the
     *   refusal because it would look like it had worked.
     */
    @Throws(IOException::class)
    fun writeTo(directory: File): File {
        if (!directory.isDirectory && !directory.mkdirs()) {
            throw IOException("Winn carrier profile directory could not be created")
        }
        // The directory is owner-only too. On Android filesDir already is, but
        // this class is JVM-testable and must not depend on that.
        restrictToOwner(directory, executable = true)
        val file = File(directory, PROFILE_FILE_NAME)
        // A stale profile from a previous session must not survive to be read
        // by a later one, and creating fresh is what makes the mode calls below
        // apply to the inode the engine will actually open.
        if (file.exists() && !file.delete()) {
            throw IOException("A previous Winn carrier profile could not be removed")
        }
        if (!file.createNewFile()) {
            throw IOException("Winn carrier profile could not be created")
        }
        restrictToOwner(file, executable = false)
        file.writeText(toJson(), Charsets.UTF_8)
        if (file.canRead() && !isOwnerOnly(file)) {
            file.delete()
            throw IOException(
                "Refusing to hand the engine a Winn carrier profile that is not owner-only; " +
                    "the engine's own loader would refuse it, and a readable profile names " +
                    "every private credential file on this device."
            )
        }
        return file
    }

    private fun appendPair(sb: StringBuilder, key: String, value: String, quoted: Boolean = true) {
        sb.append(WinnEngineConfig.jsonString(key)).append(':')
        if (quoted) sb.append(WinnEngineConfig.jsonString(value)) else sb.append(value)
    }

    /**
     * An ACTIVE single-packet-authorization configuration.
     *
     * Its existence is the mode: a non-null [ResolvedSpa] means `spa_mode` is
     * "required", and null means the field is not emitted at all. Modelling it
     * as a nullable object rather than as a mode string beside five loose
     * fields is what makes "half-enabled SPA" unrepresentable in this class --
     * the engine refuses that combination, and a shape that cannot express it
     * cannot produce it.
     *
     * [keyPath] is a PATH and never key material. Nothing in this class opens
     * it.
     *
     * The three scalars are zero when the served config did not name them,
     * which means "use the engine's own derived or default value" -- the same
     * meaning zero has in `carrierhost.Profile`.
     */
    internal class ResolvedSpa(
        val keyPath: String,
        val target: String,
        val packetSize: Int,
        val bucketWindowSeconds: Int,
        val maxSkewSeconds: Int,
    )

    /** The six credential files, resolved to absolute paths. */
    internal class ResolvedCredentials(
        val controllerPins: String,
        val rootCA: String,
        val echConfigList: String,
        val deviceSeed: String,
        val clientCert: String,
        val clientKey: String,
    )

    /**
     * The credential files a carrier profile references, by fixed name inside
     * one directory.
     *
     * NONE OF THESE IS PRODUCED BY THIS APP TODAY. Provisioning them is a
     * PKI-and-deployment programme, not code in this repository: the device
     * ML-DSA identity has to be generated on the device and registered with the
     * controller, the client certificate has to be issued by the Winn CA, the
     * pinned controller verifier set and the ECH config list have to be
     * distributed and rotated, and the whole lot has to be bound to a
     * controller-signed gateway manifest before the direct-pin route this
     * profile describes stops being "as trustworthy as the channel that
     * delivered it".
     *
     * So [resolve] FAILS CLOSED and names the first file that is absent. That
     * refusal is the honest state of this platform: the Kotlin, the argv and
     * the engine are wired, and the credentials are not there yet. Substituting
     * a default, a generated key or a system trust store for any of these would
     * turn a missing-credential failure into a session that looks post-quantum
     * and is not.
     */
    internal class CredentialSet(private val directory: File) {

        /**
         * @throws IOException naming the first missing or unusable file. Never
         *   returns a partially resolved set.
         */
        @Throws(IOException::class)
        fun resolve(): ResolvedCredentials {
            val paths = REQUIRED_FILES.map { (name, purpose) ->
                val file = File(directory, name)
                if (!file.isFile) {
                    throw IOException(
                        "Winn carrier credential '$name' ($purpose) is not provisioned on this " +
                            "device. The Winn carrier needs a device ML-DSA identity, a client " +
                            "certificate issued by the Winn CA, the Winn root CA, an ECH config " +
                            "list and the pinned controller verifier set. None of these is " +
                            "generated by this app; until they are provisioned, a winn/3 " +
                            "session cannot use an authenticated carrier. Refusing rather than " +
                            "starting an unauthenticated one. Expected: ${file.absolutePath}"
                    )
                }
                if (file.length() <= 0L) {
                    throw IOException("Winn carrier credential '$name' ($purpose) is empty")
                }
                // Read access is checked, not exercised. This class must never
                // open a credential file: the point of naming secrets by path
                // is that only the loader which owns each format ever reads one.
                if (!file.canRead()) {
                    throw IOException("Winn carrier credential '$name' ($purpose) is unreadable")
                }
                file.absolutePath
            }
            return ResolvedCredentials(
                controllerPins = paths[0],
                rootCA = paths[1],
                echConfigList = paths[2],
                deviceSeed = paths[3],
                clientCert = paths[4],
                clientKey = paths[5],
            )
        }

        /**
         * The SPA key file's absolute path, or a refusal naming it.
         *
         * SEPARATE FROM [resolve] ON PURPOSE. The six files above are needed by
         * every carrier session; this one is needed only by a session whose
         * served config turned SPA on. Folding it into [REQUIRED_FILES] would
         * make every existing carrier profile fail on a device that has no
         * knock key, which is every device today.
         *
         * IT FAILS CLOSED, and that is the whole reason this method exists
         * rather than the caller simply writing the path. `carrierhost` accepts
         * any non-empty `spa_key_path` at parse time -- the file is not opened
         * until `BuildDialer`, at Create time, long after the host has protected
         * a socket and spawned the engine. So a device with no provisioned key
         * would build a perfectly valid-looking profile, start a tunnel, and
         * then fail somewhere the user experiences as "it just doesn't
         * connect". Checking here converts that into a named refusal before
         * anything is allocated.
         *
         * @throws IOException naming the file, never its contents.
         */
        @Throws(IOException::class)
        fun resolveSpaKey(): String {
            val file = File(directory, WinnCarrierProfileKeys.SPA_KEY_CREDENTIAL_FILE_NAME)
            if (!file.isFile) {
                throw IOException(
                    "This server asked for single packet authorization, but the knock key " +
                        "'${WinnCarrierProfileKeys.SPA_KEY_CREDENTIAL_FILE_NAME}' is not " +
                        "provisioned on this device. The key is a deployment-scoped shared " +
                        "secret distributed out of band by the operator; nothing in this app " +
                        "generates one. Without it the engine would send a knock no gate can " +
                        "verify and the connection would fail with nothing reporting why, so " +
                        "it is refused here instead. Expected: ${file.absolutePath}"
                )
            }
            if (file.length() <= 0L) {
                throw IOException(
                    "The Winn knock key file is empty at: ${file.absolutePath}"
                )
            }
            if (!file.canRead()) {
                throw IOException(
                    "The Winn knock key file is unreadable at: ${file.absolutePath}"
                )
            }
            // Read access is CHECKED, not exercised. This class must never open
            // a credential file -- knock.LoadKeysFromFile owns this format, the
            // same rule the six files above follow.
            return file.absolutePath
        }

        companion object {
            /**
             * Ordered, because [resolve] positionally maps the result. Each
             * entry is (file name, what it is) and the order matches
             * [ResolvedCredentials]'s constructor.
             */
            val REQUIRED_FILES: List<Pair<String, String>> = listOf(
                "controller_pins.json" to "the PINNED controller ML-DSA verifier set, the " +
                    "profile's trust anchor",
                "winn_root_ca.pem" to "the Winn CA the carrier certificate must chain to; the " +
                    "system trust store is not it",
                "ech_config_list.bin" to "the Encrypted Client Hello config list, without which " +
                    "the TLS profile is a single-probe fingerprint",
                "device_mldsa_seed.bin" to "the device's ML-DSA private seed",
                "client_cert.pem" to "the mTLS client certificate identity mode requires",
                "client_key.pem" to "the mTLS client private key",
            )
        }
    }

    companion object {
        /** `carrierhost.ProfileVersion`. */
        const val PROFILE_VERSION = "winn-carrier-profile/1"

        /** `connectivity.CarrierHTTP3`. */
        const val CARRIER_HTTP3 = "http3-connect-udp"

        /** `connectivity.CarrierHTTP2`. */
        const val CARRIER_HTTP2 = "http2-stream"

        /** `carrierauth.AuthModeIdentity`. The only mode carrierhost builds. */
        const val AUTH_MODE_IDENTITY = "identity"

        /** `carrierauth.PrivacyStandard` / `PrivacyHighRisk`. */
        const val PRIVACY_STANDARD = "standard"
        const val PRIVACY_HIGH_RISK = "high-risk"

        /**
         * `protocol.AuthMLDSA65` / `AuthMLDSA87`, via `pqauth`.
         *
         * These are the WIRE spellings, and they are not the pretty ones. The
         * NIST name is written "ML-DSA-65"; the value this protocol uses is
         * `mldsa65`, and `pqauth.LoadSigner` refuses anything else. No alias is
         * accepted here, because inventing one would let a section that names
         * an algorithm no other document in this repository uses reach the
         * engine and fail there instead.
         */
        val SUPPORTED_PQ_ALGORITHMS = setOf("mldsa65", "mldsa87")

        /**
         * `tlsconfig.ParseSuite`. The hybrid post-quantum groups.
         *
         * THIS ALLOWLIST IS LOAD-BEARING, not defensive duplication.
         * `carrierhost.normalize` checks only that `suite` is non-empty;
         * `ParseSuite` runs inside `BuildDialer`, which the engine calls at
         * CREATE time -- after this host has opened a UDP socket, protected it,
         * spawned the engine and passed the descriptor over SCM_RIGHTS. A
         * profile naming a classical group therefore starts the engine cleanly
         * and fails late, with a protected socket already handed to a child.
         *
         * Measured, not assumed: see
         * `WinnEngineInteropTest.aClassicalSuiteIsCaughtByKotlinBecauseTheEngineDefersIt`,
         * which drives the real binary both ways round.
         */
        val SUPPORTED_SUITES = setOf("x25519-mlkem768", "p256-mlkem768", "p384-mlkem1024")

        /** `carrier.DefaultMaxDatagram` bounds; mirrors `carrierhost.normalize`. */
        const val MIN_INNER_DATAGRAM = 32
        const val MAX_INNER_DATAGRAM = 1500

        /** Where the profile and its credentials live under `filesDir`. */
        const val PROFILE_DIRECTORY_NAME = "winn"
        const val PROFILE_FILE_NAME = "carrier-profile.json"
        const val CREDENTIAL_DIRECTORY_NAME = "credentials"

        /**
         * The `[winn]` keys that describe a carrier. They are consumed here and
         * never forwarded into `datapath.Config`, whose decoder would reject
         * every one of them.
         *
         * They carry NO secret. Each is a public transport parameter the
         * gateway selected -- a URI template, an address, a suite name, an
         * identifier, a digest. The material that would be dangerous to put in
         * an INI section served over the wire is exactly the material this
         * design keeps in [CredentialSet], on the device, named by path.
         *
         * NOT WRITTEN HERE ANY MORE. [WinnCarrierProfileKeys.SERVED] is
         * generated from `carrierhost.Profile`'s own json tags, and
         * `carrierhost.TestGeneratedPlatformKeyFilesAreCurrent` fails an
         * ordinary `go test ./...` if it drifts.
         *
         * This used to be a hand-typed list, one of four identical copies
         * across Kotlin, Swift, Dart and C++. That all four agreed with each
         * other is exactly why nobody noticed that none of them agreed with the
         * schema: `carrierhost.Profile` grew five `spa_*` fields, every copy
         * silently excluded them, nothing failed anywhere, and single packet
         * authorization was unreachable from every platform at once.
         */
        val CARRIER_KEYS: Set<String> = WinnCarrierProfileKeys.SERVED

        /** `carrierhost.SPAModeOff` / `SPAModeRequired`. */
        const val SPA_MODE_OFF = WinnCarrierProfileKeys.SPA_MODE_OFF
        const val SPA_MODE_REQUIRED = WinnCarrierProfileKeys.SPA_MODE_REQUIRED

        /** `knock.HeaderSize` (16-byte nonce + 32-byte tag) and
         * `carrier.AbsoluteMaxDatagram`. A knock is ONE unfragmented datagram:
         * a censor that already drops or flags fragmented UDP would turn the
         * knock into a worse fingerprint than having no SPA at all. */
        const val MIN_SPA_PACKET_SIZE = 48
        const val MAX_SPA_PACKET_SIZE = 1500

        private val RANDOM = SecureRandom()

        /**
         * Builds the profile for a `[winn]` section whose carrier is not
         * direct-awg.
         *
         * @param section the `[winn]` INI section.
         * @param carrier the carrier [WinnEngineConfig] already resolved and
         *   accepted. Passed in rather than re-read so the two documents cannot
         *   disagree about which carrier this session is: the engine refuses a
         *   profile/config carrier mismatch, and this removes the only way this
         *   host could produce one.
         * @param credentialDirectory where the six credential files live.
         * @throws IllegalArgumentException naming the offending field, never
         *   its value.
         * @throws IOException if a credential is not provisioned.
         */
        @Throws(IOException::class)
        fun from(
            section: Map<String, String>,
            carrier: String,
            credentialDirectory: File,
        ): WinnCarrierProfile {
            require(carrier == CARRIER_HTTP3) {
                if (carrier == CARRIER_HTTP2) {
                    // Named specifically rather than lumped in with "unknown".
                    // H2 is implemented in the engine and refused HERE, and the
                    // reason is a host capability, not a protocol gap.
                    "Winn carrier '$CARRIER_HTTP2' needs a CONNECTED, protected TCP socket. This " +
                        "host opens one UNCONNECTED UDP socket and hands it over by SCM_RIGHTS, " +
                        "which is what $CARRIER_HTTP3 takes. Building an H2 profile would produce " +
                        "a dialer the engine then refuses for a socket-kind mismatch, so it is " +
                        "refused here where the reason can be stated."
                } else {
                    "Winn carrier '$carrier' has no carrier profile; only $CARRIER_HTTP3 does"
                }
            }

            val masqueTemplate = section["masque_template"].orEmpty().trim()
            require(isAbsoluteHttpsUrl(masqueTemplate)) {
                "Winn masque_template must be an absolute https URL naming a host"
            }

            val publicTarget = section["public_target"].orEmpty().trim()
            // The proxy resolves this, not the device, so the DNS-leak rule that
            // governs the gateway endpoint does not apply -- but the AmneziaWG
            // gateway is named by address everywhere else in this client and a
            // hostname here would be a second, silent naming scheme. carrierhost
            // enforces the same rule.
            require(WinnEngineConfig.isIpLiteralEndpoint(publicTarget)) {
                "Winn public_target must be an IP literal with a port, not a hostname"
            }

            val serverName = section["server_name"].orEmpty().trim()
            require(serverName.isNotEmpty() && serverName.length <= 253) {
                "Winn server_name is required; it is the inner ClientHello name the carrier " +
                    "certificate must match"
            }
            require(serverName.none { it.isWhitespace() || it == '"' || it == '\\' }) {
                "Winn server_name is not a host name"
            }

            val suite = section["suite"].orEmpty().trim().lowercase()
            require(suite in SUPPORTED_SUITES) {
                "Winn suite '$suite' is not a hybrid post-quantum group this engine offers; " +
                    "refusing rather than letting the session negotiate a weaker one. The " +
                    "engine does not check this until create time, by which point a protected " +
                    "socket has already been handed to the child."
            }

            val controllerId = section["controller_id"].orEmpty().trim()
            require(controllerId.isNotEmpty() && controllerId.length <= 128) {
                "Winn controller_id is required; it identifies the controller whose ML-DSA " +
                    "signature every carrier response must carry"
            }

            val deviceId = section["device_id"].orEmpty().trim()
            require(deviceId.isNotEmpty() && deviceId.length <= 128) {
                "Winn device_id is required in identity mode"
            }

            val deviceAlgorithm = section["device_pq_algorithm"].orEmpty().trim().lowercase()
            require(deviceAlgorithm in SUPPORTED_PQ_ALGORITHMS) {
                "Winn device_pq_algorithm must name the ML-DSA parameter set the device key was " +
                    "generated for"
            }

            val manifestDigest = section["manifest_digest"].orEmpty().trim().lowercase()
            require(isHex(manifestDigest, 64)) {
                "Winn manifest_digest must be 64 lowercase hexadecimal characters; the carrier " +
                    "server compares it, so an absent value would silently claim a different " +
                    "deployment"
            }

            val sequenceEpoch = section["sequence_epoch"].orEmpty().trim().lowercase()
            require(sequenceEpoch.isEmpty() || isHex(sequenceEpoch, 32)) {
                "Winn sequence_epoch must be 32 lowercase hexadecimal characters"
            }

            val maxInnerDatagram = section["max_inner_datagram"]?.trim()?.takeIf { it.isNotEmpty() }
                ?.let { raw ->
                    val parsed = raw.toIntOrNull()
                    require(parsed != null && parsed in MIN_INNER_DATAGRAM..MAX_INNER_DATAGRAM) {
                        "Winn max_inner_datagram must be within " +
                            "[$MIN_INNER_DATAGRAM, $MAX_INNER_DATAGRAM]"
                    }
                    parsed
                } ?: MAX_INNER_DATAGRAM

            val privacyProfile = section["privacy_profile"]?.trim()?.lowercase()
                ?.takeIf { it.isNotEmpty() } ?: PRIVACY_HIGH_RISK
            require(privacyProfile == PRIVACY_STANDARD || privacyProfile == PRIVACY_HIGH_RISK) {
                "Winn privacy_profile must be '$PRIVACY_STANDARD' or '$PRIVACY_HIGH_RISK'"
            }

            // SINGLE PACKET AUTHORIZATION.
            //
            // Parsed before the credentials so a malformed spa_ field fails on
            // itself rather than on a knock key that is merely absent, and so
            // the `spa_mode` off path never touches the credential directory at
            // all.
            //
            // No http3-versus-http2 check is needed here: this whole method
            // already refuses every carrier but CARRIER_HTTP3 at its first
            // statement, which is strictly stronger than the engine's own SPA
            // rule (`ErrSPAStreamCarrierUnsupported`).
            val spaMode = section["spa_mode"]?.trim()?.lowercase().orEmpty()
            val spaFieldsPresent = WinnCarrierProfileKeys.SPA
                .filter { it != "spa_mode" }
                .filter { section[it]?.trim().isNullOrEmpty().not() }
            val spa: ResolvedSpa?
            if (spaMode.isEmpty() || spaMode == SPA_MODE_OFF) {
                // Refused, not ignored -- `ErrSPAFieldWithoutMode`. A target
                // left behind after SPA was turned off is the operator
                // believing a defence is armed that is not.
                require(spaFieldsPresent.isEmpty()) {
                    "Winn ${spaFieldsPresent.first()} is set without spa_mode = " +
                        "$SPA_MODE_REQUIRED; refusing rather than silently ignoring a " +
                        "configured single-packet-authorization parameter"
                }
                spa = null
            } else {
                require(spaMode == SPA_MODE_REQUIRED) {
                    "Winn spa_mode must be '$SPA_MODE_OFF' or '$SPA_MODE_REQUIRED'"
                }
                val spaTarget = section["spa_target"].orEmpty().trim()
                // No default, deliberately: the gate may sit in front of the
                // carrier listener or in front of the AmneziaWG gateway, and a
                // wrong guess sends the deployment's shared credential to a
                // host that is not supposed to have it.
                require(WinnEngineConfig.isIpLiteralEndpoint(spaTarget)) {
                    "Winn spa_target is required when spa_mode is $SPA_MODE_REQUIRED, and " +
                        "must be an IP literal with a port, not a hostname"
                }
                val spaPacketSize = spaScalar(section, "spa_packet_size")
                require(
                    spaPacketSize == 0 ||
                        spaPacketSize in MIN_SPA_PACKET_SIZE..MAX_SPA_PACKET_SIZE
                ) {
                    "Winn spa_packet_size must be within " +
                        "[$MIN_SPA_PACKET_SIZE, $MAX_SPA_PACKET_SIZE]"
                }
                val spaBucket = spaScalar(section, "spa_bucket_window_seconds")
                val spaSkew = spaScalar(section, "spa_max_skew_seconds")
                // `knock.Options.resolve`: a bucket is at least a second and
                // the skew is at least a bucket. A pair that violates this
                // produces a knock that silently never verifies, which looks
                // identical to a wrong key -- so it is refused where the reason
                // can still be stated.
                require(spaBucket == 0 || spaBucket >= 1) {
                    "Winn spa_bucket_window_seconds must be at least 1 second"
                }
                require(spaSkew == 0 || spaBucket == 0 || spaSkew >= spaBucket) {
                    "Winn spa_max_skew_seconds must be at least spa_bucket_window_seconds"
                }
                spa = ResolvedSpa(
                    keyPath = CredentialSet(credentialDirectory).resolveSpaKey(),
                    target = spaTarget,
                    packetSize = spaPacketSize,
                    bucketWindowSeconds = spaBucket,
                    maxSkewSeconds = spaSkew,
                )
            }

            // Resolved LAST, so a malformed section fails on the field that is
            // wrong rather than on the credentials that are merely absent.
            val credentials = CredentialSet(credentialDirectory).resolve()

            return WinnCarrierProfile(
                carrier = carrier,
                masqueTemplate = masqueTemplate,
                publicTarget = publicTarget,
                serverName = serverName,
                suite = suite,
                controllerId = controllerId,
                credentials = credentials,
                deviceId = deviceId,
                deviceAlgorithm = deviceAlgorithm,
                // Generated here, never served. It is bound into every signed
                // carrier request and the server verifies the signature over
                // it rather than pre-agreeing it, so a device-chosen value is
                // both correct and the anti-correlation choice: a session
                // identifier the control plane picked would link the session to
                // the account that fetched the config.
                sessionId = newSessionId(),
                sequenceEpoch = sequenceEpoch,
                manifestDigest = manifestDigest,
                maxInnerDatagram = maxInnerDatagram,
                privacyProfile = privacyProfile,
                spa = spa,
            )
        }

        /**
         * An optional non-negative `spa_` scalar. Zero means absent, which is
         * the same thing zero means in `carrierhost.Profile`: use the engine's
         * own derived or default value.
         */
        private fun spaScalar(section: Map<String, String>, key: String): Int {
            val raw = section[key]?.trim().orEmpty()
            if (raw.isEmpty()) return 0
            val parsed = raw.toIntOrNull()
            require(parsed != null && parsed >= 0) {
                "Winn $key must be a non-negative whole number"
            }
            return parsed
        }

        /** The credential directory for an app `filesDir`. */
        fun credentialDirectory(filesDir: File): File =
            File(File(filesDir, PROFILE_DIRECTORY_NAME), CREDENTIAL_DIRECTORY_NAME)

        /** The directory the profile document is written into. */
        fun profileDirectory(filesDir: File): File = File(filesDir, PROFILE_DIRECTORY_NAME)

        /** `mobility.ValidSessionID`: 32 lowercase hexadecimal characters. */
        fun newSessionId(): String {
            val bytes = ByteArray(16)
            RANDOM.nextBytes(bytes)
            val hex = StringBuilder(32)
            for (b in bytes) hex.append("%02x".format(b.toInt() and 0xFF))
            return hex.toString()
        }

        internal fun isHex(value: String, length: Int): Boolean =
            value.length == length && value.all { it in '0'..'9' || it in 'a'..'f' }

        /**
         * Mirrors `carrierhost.validateAbsoluteHTTPS`: the https scheme and a
         * non-empty host. Written by hand rather than with `java.net.URI`
         * because the RFC 9298 template carries `{target_host}` and
         * `{target_port}` expansions, which URI rejects as illegal characters.
         */
        internal fun isAbsoluteHttpsUrl(value: String): Boolean {
            val prefix = "https://"
            if (!value.startsWith(prefix)) return false
            val rest = value.substring(prefix.length)
            if (rest.isEmpty()) return false
            val hostEnd = rest.indexOfFirst { it == '/' || it == '?' || it == '#' }
            val host = if (hostEnd < 0) rest else rest.substring(0, hostEnd)
            if (host.isEmpty()) return false
            return host.none { it.isWhitespace() }
        }

        /**
         * 0600 for a file, 0700 for a directory, through the `java.io.File`
         * API so it works at minSdk 24.
         *
         * The `false` second argument clears the bit for group and other; the
         * `true` one then sets it for the owner alone. Order matters: setting
         * owner access first and clearing afterwards would clear it again.
         */
        private fun restrictToOwner(file: File, executable: Boolean) {
            file.setReadable(false, false)
            file.setWritable(false, false)
            file.setExecutable(false, false)
            file.setReadable(true, true)
            file.setWritable(true, true)
            if (executable) file.setExecutable(true, true)
        }

        /**
         * The group and other permission bits of a POSIX mode -- `0o077`.
         *
         * `securefile.ReadPrivateLimited` refuses a file for which
         * `Perm()&0o077 != 0`, so this mask, and only this mask, is the
         * condition [modeIsOwnerOnly] answers.
         */
        internal const val GROUP_AND_OTHER_BITS = 0b111_111

        /**
         * Whether a POSIX [mode] grants nothing to group or other.
         *
         * Split out from [isOwnerOnly] because it is the whole policy and it
         * depends on no platform at all: it can be enumerated exhaustively in a
         * unit test on any host, which the file-reading half cannot be.
         */
        internal fun modeIsOwnerOnly(mode: Int): Boolean =
            mode and GROUP_AND_OTHER_BITS == 0

        /**
         * Whether [file] grants nothing to group or other, which is the
         * condition `securefile.ReadPrivateLimited` checks
         * (`Perm()&0o077 != 0` is a refusal).
         *
         * `java.io.File` cannot report another principal's access, so the mode
         * has to come from a platform call -- see [posixModeOrNull] for which
         * one, and why there are two.
         *
         * When the mode genuinely cannot be read the answer is conservatively
         * reported as satisfied: the engine re-checks it either way, and it is
         * the engine's check that is load-bearing. That case is now close to
         * unreachable on Android -- before this was API-gated it was the case
         * every API 24 and 25 handset took, by crashing.
         */
        internal fun isOwnerOnly(file: File): Boolean {
            val mode = posixModeOrNull(file) ?: return true
            return modeIsOwnerOnly(mode)
        }

        /**
         * [file]'s POSIX permission bits under the effective Android API level.
         *
         * Delegates to [posixModeOrNullFor], passing the level read from
         * [android.os.Build.VERSION.SDK_INT]. The gate itself is that
         * parameterized function so the chosen branch for a given level can be
         * asserted by a unit test -- `SDK_INT` on the unit-test `android.jar`
         * is a `static final` constant the runtime will not let a test rewrite,
         * so before this split the API gate could only be pinned by reading
         * this function's source, never by running it.
         */
        private fun posixModeOrNull(file: File): Int? =
            posixModeOrNullFor(android.os.Build.VERSION.SDK_INT, file)

        /**
         * [posixModeOrNull]'s API-level gate, as a pure function of [sdkInt].
         *
         * [file]'s POSIX permission bits, or null when this host genuinely
         * cannot report them.
         *
         * TWO IMPLEMENTATIONS, AND THE GATE BETWEEN THEM IS A CRASH FIX.
         * `java.nio.file` did not exist on Android before **API 26**, and this
         * app's `minSdk` is **24**. Reaching `Files.getPosixFilePermissions`
         * (or even `File.toPath`) on an API 24 or 25 handset does not raise an
         * `Exception` that a `catch` can absorb -- the class is simply absent,
         * so the runtime raises `NoClassDefFoundError`, an `Error`. The
         * previous `catch (_: Exception)` did not catch it and could not: every
         * user on those two API levels crashed out of [writeTo]. Lint found it
         * the first time it was ever able to run on this code (`NewApi`, two
         * errors on one line).
         *
         * So the fix is the gate, not a wider `catch`. Below API 26 the answer
         * comes from `android.system.Os.stat`, which has been public since API
         * 21 and reports the same bits in the same encoding -- a real answer on
         * those handsets rather than a swallowed one. The `catch (Throwable)`
         * inside each half is then belt to the gate's braces, for a filesystem
         * with no POSIX view (`UnsupportedOperationException`), a path that
         * moved under us, or a vendor image whose `java.nio` is partial.
         *
         * `SDK_INT` reads **0** off a device -- the unit-test `android.jar`
         * initialises it to 0 -- so `1 until O` is exactly "on a device, below
         * 26", and 0 falls through to the `java.nio` half, which is genuinely
         * present and genuinely correct on the JVM the unit tests run on.
         * Routing 0 to `Os.stat` instead would send every unit test into a
         * `Method ... not mocked` stub and quietly turn the owner-only
         * assertion in `WinnCarrierProfileTest` into the null branch above,
         * i.e. into a test that passes without testing anything.
         */
        internal fun posixModeOrNullFor(sdkInt: Int, file: File): Int? {
            if (sdkInt >= android.os.Build.VERSION_CODES.O) {
                // The gate is the *parameter*, not `SDK_INT`, so lint cannot
                // see it and reports this call as reaching `nioPosixModeOrNull`
                // on API 24/25. It cannot: the branch above is exactly what
                // excludes those two levels, and the parameterized gate is
                // what makes the same choice assertable by `WinnCarrierProfileTest`
                // (unit-test `SDK_INT` is a constant the runtime freezes to 0).
                // Same scoped-local suppression pattern as the off-device branch
                // below, which lint flags for the exact opposite reason.
                @android.annotation.SuppressLint("NewApi")
                val nioMode = nioPosixModeOrNull(file)
                return nioMode
            }
            if (sdkInt > 0) {
                // API 24 and 25, the two levels that used to crash here.
                return statPosixModeOrNull(file)
            }
            // NOT ANDROID AT ALL. `SDK_INT` is 0 only under the unit-test
            // `android.jar` stub, i.e. on the desktop JVM the Gradle test task
            // runs on, where `java.nio.file` is genuinely present and
            // `android.system.Os` is a `Method ... not mocked` stub.
            //
            // The suppression is scoped to this one local and is correct BY
            // CONSTRUCTION rather than by assertion: both branches above have
            // already returned for every SDK_INT >= 1, so no Android device can
            // reach this line. It is here so `WinnCarrierProfileTest` measures
            // a real mode instead of falling into the "cannot tell" branch and
            // asserting `true` against nothing -- which is what a version of
            // this fix that routed 0 to `Os.stat` would have quietly done.
            @android.annotation.SuppressLint("NewApi")
            val offDeviceMode = nioPosixModeOrNull(file)
            return offDeviceMode
        }

        /** API 26+, and every non-Android JVM -- see [posixModeOrNull]. */
        @androidx.annotation.RequiresApi(android.os.Build.VERSION_CODES.O)
        private fun nioPosixModeOrNull(file: File): Int? {
            return try {
                val permissions = java.nio.file.Files.getPosixFilePermissions(file.toPath())
                var mode = 0
                for (permission in permissions) {
                    val bit = when (permission.name) {
                        "OWNER_READ" -> 0b100_000_000
                        "OWNER_WRITE" -> 0b010_000_000
                        "OWNER_EXECUTE" -> 0b001_000_000
                        "GROUP_READ" -> 0b000_100_000
                        "GROUP_WRITE" -> 0b000_010_000
                        "GROUP_EXECUTE" -> 0b000_001_000
                        "OTHERS_READ" -> 0b000_000_100
                        "OTHERS_WRITE" -> 0b000_000_010
                        "OTHERS_EXECUTE" -> 0b000_000_001
                        // An enum constant this build does not know about is
                        // not a reason to report "no group or other access":
                        // say we cannot tell, and let the engine decide.
                        else -> return null
                    }
                    mode = mode or bit
                }
                mode
            } catch (_: Throwable) {
                null
            }
        }

        /**
         * API 24 and 25. `android.system.Os` is API 21, so this half is always
         * present where it is called from, and `StructStat.st_mode` carries the
         * permission bits in the same low nine positions `java.nio` was decoded
         * into above.
         */
        private fun statPosixModeOrNull(file: File): Int? {
            return try {
                android.system.Os.stat(file.absolutePath).st_mode and 0b111_111_111
            } catch (_: Throwable) {
                null
            }
        }
    }
}
