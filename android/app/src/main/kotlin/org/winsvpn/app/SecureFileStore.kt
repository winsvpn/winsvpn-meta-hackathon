package org.winsvpn.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.util.Log
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.File
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Encrypts sensitive app state with a non-exportable Android Keystore key. */
internal class SecureFileStore(private val context: Context) {
    companion object {
        private const val TAG = VpnTunnelService.LOG_TAG
        private const val FILE_MAGIC = 0x57565331 // WVS1
        private const val MAX_PLAINTEXT_BYTES = 4 * 1024 * 1024
        // VpnTunnelService.KILL_SWITCH_STATE, named here so this file stands alone.
        private const val KILL_SWITCH_RECORD = "wins_kill_switch_armed"
        private const val INSTALL_ID_RECORD = "install_id.txt"
        private val allowedNames = setOf(
            "client_keypair.json",
            "calc_session.json",
            "calc_state.json",
            "install_id.txt",
            "node_cache.json",
            "pending_logout.json",
            "user_pin.txt",
            "vpn_config.txt",
            "vpn_settings.txt",
            "wins_vpn_restart_config.conf",
            "wins_vpn_restart_node.txt",
            "wins_kill_switch_armed",
            // The winn/3 static identity of this device (lib/winn3_device_key.dart).
            "winn3_keypair.json",
            "direct_udp_transport_memory.json",
            // The user's current Double VPN choice (VpnTunnelService.DOUBLE_VPN_INTENT_RECORD).
            "route_intent.txt",
        )

        internal fun isAllowedName(name: String): Boolean = name in allowedNames

        private var applicationStore: SecureFileStore? = null

        @Synchronized
        internal fun forApplication(context: Context): SecureFileStore =
            applicationStore ?: SecureFileStore(context.applicationContext).also {
                applicationStore = it
            }

        /**
         * Whether a decrypt failure proves the record itself is unusable: a
         * failed GCM tag, or a malformed envelope (the format checks throw
         * IllegalArgumentException, a truncated file EOFException). Any other
         * failure (keystore, I/O) may pass, so the record must be kept.
         */
        internal fun isPermanentRecordFailure(e: Exception): Boolean =
            e is AEADBadTagException ||
                e is IllegalArgumentException ||
                e is EOFException

        /** Whether the existing key is gone for good (invalidated or unrecoverable). */
        internal fun isPermanentKeyFailure(e: Exception): Boolean =
            e is KeyPermanentlyInvalidatedException ||
                e is UnrecoverableKeyException

        internal fun requireExistingKey(key: java.security.Key?): SecretKey =
            key as? SecretKey
                ?: throw java.security.KeyStoreException(
                    "Existing secure storage key unavailable",
                )

        /**
         * Whether a record that fails to authenticate is kept, and its read
         * fails, instead of being removed and read as absent. Only the account
         * cleanup journal: while it exists, startup and activation stay closed
         * (`_accountCleanupJournalExists` in lib/main.dart, which reads a
         * failed read as present), and the journal is deleted only after its
         * artifacts are verified gone. Removing an unusable journal would turn
         * an unresolved cleanup into "nothing pending" while those artifacts
         * are still stored (Sol-core-T12-1). Every other record keeps the
         * remove-and-read-as-absent rule above.
         */
        internal fun isKeptWhenUnusable(name: String): Boolean =
            name == "calc_session.json"

        /**
         * Records whose one reader fails closed on a throw
         * (VpnTunnelService.isKillSwitchArmed). A copy that fails
         * authentication is kept and rethrown, never removed and read as
         * absent, so a lost or recreated key cannot turn an armed kill switch
         * off. The next write replaces the file.
         */
        private val failClosedNames = setOf("wins_kill_switch_armed")

        /**
         * The settings record also carries the legacy kill-switch preference
         * (`always_on_enabled`), which VpnTunnelService.isKillSwitchArmed reads
         * only while no explicit `wins_kill_switch_armed` record exists.
         */
        private const val LEGACY_KILL_SWITCH_SOURCE = "vpn_settings.txt"

        /** android.security.KeyStoreException.ERROR_KEY_CORRUPTED (public from API 33). */
        internal const val PLATFORM_KEY_CORRUPTED = 7

        /**
         * Whether an UnrecoverableKeyException from KeyStore.getKey proves the
         * secure-files key is permanently lost: it carries no cause (a
         * permanently invalidated key, which AndroidKeyStoreSpi.engineGetKey
         * converts without one), or its platform cause reports a corrupted key.
         * Every other cause keeps the alias: SYSTEM_ERROR from a lost Keystore
         * daemon, any other code, and any cause below API 33, where the code is
         * not public.
         */
        internal fun keyLossIsPermanent(hasCause: Boolean, platformErrorCode: Int?): Boolean =
            !hasCause || platformErrorCode == PLATFORM_KEY_CORRUPTED

        /**
         * On-disk basename for each logical record.
         *
         * The logical names above are the ones the whole codebase reads and
         * are deliberately descriptive. The names on the FILESYSTEM are not,
         * and must not be: the offline duress branch has to keep the settings
         * record so the queued alert can still be sent, so on a phone that has
         * just been through a duress wipe the one surviving file used to be
         * called, literally, `vpn_settings.txt.wvs`. Inside a calculator. That
         * announced both what the app is and that something was kept.
         *
         * These replacements are mundane, generic, and say nothing about a
         * VPN, a tunnel, a PIN, an alert or a decoy. The AAD in [aad] still
         * binds the ciphertext to the LOGICAL name, so the mapping is purely
         * cosmetic on disk and a record stays decryptable across it.
         *
         * Do not "simplify" this to a hash of the name: a directory of opaque
         * hex blobs reads as deliberate concealment, which is its own tell.
         */
        private val onDiskNames = mapOf(
            "client_keypair.json" to "keystore.dat",
            "calc_session.json" to "history.dat",
            "calc_state.json" to "state.dat",
            "install_id.txt" to "device.dat",
            "node_cache.json" to "index.dat",
            "pending_logout.json" to "outbox.dat",
            "user_pin.txt" to "profile.dat",
            "vpn_config.txt" to "session.dat",
            "vpn_settings.txt" to "prefs.dat",
            "wins_vpn_restart_config.conf" to "restore.dat",
            "wins_vpn_restart_node.txt" to "restore_index.dat",
            // The user's kill-switch intent. A neutral, generic on-disk name:
            // nothing here may read as a VPN, a block, or an app identity to
            // anyone listing the directory. The logical name stays bound via
            // AAD so the record remains decryptable across the rename.
            "wins_kill_switch_armed" to "mode.dat",
            // A second key record. As mundane as the rest: calculator memory.
            "winn3_keypair.json" to "memory.dat",
            "direct_udp_transport_memory.json" to "routing.dat",
            // As mundane as the rest: calculator layout.
            "route_intent.txt" to "layout.dat",
        )

        /**
         * The pre-rename on-disk name. Kept ONLY so [migrateLegacyLayout] can
         * move an existing install's records across; nothing else may use it.
         * A rename that orphaned a queued duress record would silently destroy
         * the only copy of an undelivered alert, which is worse than the
         * filename it fixes.
         */
        internal fun legacyOnDiskName(name: String): String = "$name.wvs"

        internal fun onDiskName(name: String): String =
            onDiskNames[name] ?: "$name.wvs"
    }

    private val keyAlias = "${context.packageName}.secure-files.v1"
    private val secureDirectory = File(context.filesDir, "secure_state")

    // CORE-7-T15C-claude. The marker exists from the moment a local account
    // reset starts until it is verified complete. While it exists, journal
    // reads fail and writes are refused, in this process and in the next, so
    // neither ordinary cleanup nor a late writer acts on half-erased storage.
    private val accountResetMarker = File(secureDirectory, "repair.dat")

    // CORE-7-T17C-claude. Tunnel starts are sealed before the stop-proof
    // that precedes a reset (sealAccountStartsForRecovery), and stay sealed
    // in this process, including while the reset lifts the storage seal for
    // the carried kill-switch record. A surviving marker seals both in the
    // next process.
    @Volatile
    private var accountDataResetStarted =
        resetAttributes(accountResetMarker.toPath()) != null

    @Volatile
    private var accountStartsSealed = accountDataResetStarted

    fun accountResetPending(): Boolean =
        accountStartsSealed || accountDataResetStarted

    @Synchronized
    fun sealAccountStartsForRecovery(): Boolean {
        accountStartsSealed = true
        return true
    }

    private fun resetAttributes(path: Path): BasicFileAttributes? =
        try {
            Files.readAttributes(
                path,
                BasicFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS,
            )
        } catch (_: NoSuchFileException) {
            null
        }

    private fun resetChildren(path: Path): List<Path> =
        Files.newDirectoryStream(path).use { stream ->
            stream.toList().sortedBy { it.toString() }
        }

    // The O_DIRECTORY open flag is not public API (the API 37 stubs of
    // OsConstants lack it). The same refusal from public API: the open
    // follows no final symlink (O_NOFOLLOW), cannot block on a FIFO
    // (O_NONBLOCK) or take a terminal (O_NOCTTY), and the descriptor is
    // synced only when fstat of that same descriptor says it is a directory;
    // anything else fails with ENOTDIR, as O_DIRECTORY fails.
    private fun syncResetDirectory(path: Path) {
        val fd = Os.open(
            path.toString(),
            OsConstants.O_RDONLY or
                OsConstants.O_NOFOLLOW or
                OsConstants.O_NONBLOCK or
                OsConstants.O_NOCTTY or
                OsConstants.O_CLOEXEC,
            0,
        )
        try {
            if (!OsConstants.S_ISDIR(Os.fstat(fd).st_mode)) {
                throw ErrnoException("open", OsConstants.ENOTDIR)
            }
            Os.fsync(fd)
        } finally {
            Os.close(fd)
        }
    }

    private fun eraseForAccountReset(
        path: Path,
        kept: Set<Path>,
        keepDirectory: Boolean = false,
    ) {
        val attributes = resetAttributes(path) ?: return
        if (path in kept) {
            check(attributes.isRegularFile) {
                "Account reset barrier is not a regular file"
            }
            return
        }

        if (attributes.isDirectory) {
            for (child in resetChildren(path)) {
                eraseForAccountReset(child, kept)
            }
            // One sync per directory, after its last child, makes every
            // deletion in it durable before the caller moves on. The parent
            // of this path is synced the same way when its own loop ends.
            syncResetDirectory(path)
            if (keepDirectory || kept.any { it.startsWith(path) }) return
        }

        Files.delete(path)
        check(resetAttributes(path) == null) {
            "Account reset deletion was not verified"
        }
    }

    private fun verifyAccountResetTree(path: Path, kept: Set<Path>) {
        val attributes = resetAttributes(path) ?: return
        if (path in kept) {
            check(attributes.isRegularFile) {
                "Account reset barrier is not a regular file"
            }
            return
        }
        check(attributes.isDirectory) {
            "Stored account data remains after reset"
        }
        for (child in resetChildren(path)) {
            verifyAccountResetTree(child, kept)
        }
    }

    /**
     * Deletes every account's local data, after the user confirms it, when
     * the cleanup journal can no longer be read. Three device-held items are
     * kept, because ordinary account cleanup never removes them either:
     * `shared_prefs`, which holds the camouflage enrollment flag that is
     * never cleared (VpnTunnelService.markCamouflageEnrolled); the install id
     * the app reads (`app_flutter/install_id.txt`); and the kill-switch
     * intent, which is written again under a fresh key once the wrapping key
     * is gone, because erasing it would stop the always-on lockdown re-arm.
     * The journal goes only after every other deletion and the wrapping key's
     * removal are verified, and the marker goes last.
     */
    @Synchronized
    fun resetAllLocalAccountData(): Boolean {
        fun normalized(file: File): Path =
            file.toPath().toAbsolutePath().normalize()

        val documents = File(context.applicationInfo.dataDir, "app_flutter")
        val roots = listOf(
            documents,
            context.filesDir,
            context.cacheDir,
            context.codeCacheDir,
            context.noBackupFilesDir,
            File(context.applicationInfo.dataDir, "databases"),
        ).map(::normalized).distinct().sortedBy { it.toString() }

        for (root in roots) {
            val attributes = resetAttributes(root)
            check(attributes == null || attributes.isDirectory) {
                "Account reset storage root is unavailable"
            }
        }

        secureDirectory.mkdirs()
        val secureRoot = normalized(secureDirectory)
        check(resetAttributes(secureRoot)?.isDirectory == true) {
            "Account reset secure directory is unavailable"
        }
        syncResetDirectory(normalized(context.filesDir))

        val marker = normalized(accountResetMarker)
        val existingMarker = resetAttributes(marker)
        check(existingMarker == null || existingMarker.isRegularFile) {
            "Account reset marker is unavailable"
        }

        // Read before anything changes. A record that cannot be read counts
        // as unarmed, as VpnTunnelService.isKillSwitchArmed already reads it.
        val killSwitchArmed = runCatching {
            read(KILL_SWITCH_RECORD)?.trim()?.toBooleanStrictOrNull() == true
        }.getOrDefault(false)
        // The install id lives in this store under the wrapping key the reset
        // destroys (CORE-32), so it is read now and written again under the
        // fresh key below, as the kill-switch intent is. An unreadable or
        // short value is not carried; the app then mints a new one.
        val carriedInstallId = runCatching {
            read(INSTALL_ID_RECORD)?.trim()
        }.getOrNull()?.takeIf { it.length >= 24 }

        // Sealed from here: no write lands until this process ends.
        accountDataResetStarted = true
        FileOutputStream(accountResetMarker).use { stream ->
            stream.write(1)
            stream.fd.sync()
        }
        syncResetDirectory(secureRoot)

        val journalPaths = setOf(
            normalized(File(secureDirectory, onDiskName("calc_session.json"))),
            normalized(
                File(secureDirectory, legacyOnDiskName("calc_session.json")),
            ),
            normalized(File(documents, "calc_session.json")),
        )
        val killSwitchRecord =
            normalized(File(secureDirectory, onDiskName(KILL_SWITCH_RECORD)))
        val killSwitchPaths = setOf(
            killSwitchRecord,
            normalized(
                File(secureDirectory, legacyOnDiskName(KILL_SWITCH_RECORD)),
            ),
        )
        val installId = normalized(File(documents, "install_id.txt"))
        val secureInstallId =
            normalized(File(secureDirectory, onDiskName(INSTALL_ID_RECORD)))
        val secureInstallIdPaths = setOf(
            secureInstallId,
            normalized(
                File(secureDirectory, legacyOnDiskName(INSTALL_ID_RECORD)),
            ),
        )
        // Sets only: a Path is itself an Iterable<Path>, so `set + path`
        // would add the path's name segments instead of the path.
        val kept = journalPaths + killSwitchPaths + secureInstallIdPaths +
            setOf(installId, marker)

        for (root in roots) {
            eraseForAccountReset(root, kept, keepDirectory = true)
        }
        for (root in roots) {
            verifyAccountResetTree(root, kept)
        }

        // Nothing the old key wrote can be decrypted again, including blocks
        // the deletions above leave behind on flash.
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }
        if (keyStore.containsAlias(keyAlias)) {
            keyStore.deleteEntry(keyAlias)
        }
        check(!keyStore.containsAlias(keyAlias)) {
            "Account reset wrapping key remains"
        }

        // One rename replaces the old record with one under a fresh key. The
        // seal lifts for this write only, inside this same monitor, so no
        // other caller can write while it is lifted.
        if (killSwitchArmed) {
            accountDataResetStarted = false
            try {
                write(KILL_SWITCH_RECORD, "true")
            } finally {
                accountDataResetStarted = true
            }
        } else {
            check(delete(KILL_SWITCH_RECORD)) {
                "Account reset kill-switch record remains"
            }
        }
        if (carriedInstallId != null) {
            accountDataResetStarted = false
            try {
                write(INSTALL_ID_RECORD, carriedInstallId)
            } finally {
                accountDataResetStarted = true
            }
        } else {
            check(delete(INSTALL_ID_RECORD)) {
                "Account reset install id record remains"
            }
        }

        for (journal in journalPaths.sortedBy { it.toString() }) {
            if (resetAttributes(journal) != null) {
                Files.delete(journal)
                check(resetAttributes(journal) == null) {
                    "Account reset journal deletion was not verified"
                }
                syncResetDirectory(journal.parent)
            }
        }

        val survivors = setOf(marker, installId) +
            (if (killSwitchArmed) setOf(killSwitchRecord) else emptySet()) +
            (if (carriedInstallId != null) setOf(secureInstallId) else emptySet())
        for (root in roots) {
            verifyAccountResetTree(root, survivors)
        }

        Files.delete(marker)
        check(resetAttributes(marker) == null) {
            "Account reset marker deletion was not verified"
        }
        syncResetDirectory(secureRoot)
        return true
    }

    @Synchronized
    fun write(name: String, plaintext: String) {
        require(isAllowedName(name)) { "Unsupported secure file name" }
        check(!accountDataResetStarted) {
            "Local account reset requires restart"
        }
        val clearBytes = plaintext.toByteArray(StandardCharsets.UTF_8)
        require(clearBytes.size <= MAX_PLAINTEXT_BYTES) { "Secure file is too large" }

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        cipher.updateAAD(aad(name))
        val encryptedBytes = cipher.doFinal(clearBytes)

        val encoded = ByteArrayOutputStream().use { buffer ->
            DataOutputStream(buffer).use { output ->
                output.writeInt(FILE_MAGIC)
                output.writeByte(cipher.iv.size)
                output.write(cipher.iv)
                output.writeInt(encryptedBytes.size)
                output.write(encryptedBytes)
            }
            buffer.toByteArray()
        }

        secureDirectory.mkdirs()
        val destination = secureFile(name)
        val temporary = File(secureDirectory, ".${destination.name}.${System.nanoTime()}.tmp")
        try {
            FileOutputStream(temporary).use { stream ->
                stream.write(encoded)
                stream.fd.sync()
            }
            Os.rename(temporary.absolutePath, destination.absolutePath)
        } finally {
            if (temporary.exists()) temporary.delete()
        }
        // The record just written supersedes any `.wvs` record a failed
        // layout migration left beside it. Best effort: while one is left,
        // read and delete still never let it take this record's place.
        val superseded = File(secureDirectory, legacyOnDiskName(name))
        if (superseded.absolutePath != destination.absolutePath) {
            runCatching { if (superseded.exists()) superseded.delete() }
        }
    }

    @Synchronized
    fun read(name: String, legacyFile: File? = null): String? {
        require(isAllowedName(name)) { "Unsupported secure file name" }
        if (name == "calc_session.json") {
            check(!accountDataResetStarted) {
                "Local account reset requires explicit recovery"
            }
        }
        val encryptedFile = secureFile(name)
        if (encryptedFile.exists()) {
            try {
                val plaintext = decrypt(name, encryptedFile.readBytes())
                finishInterruptedMigration(legacyFile)
                return plaintext
            } catch (e: Exception) {
                // Only a record that is itself unusable may be removed. A
                // failure that may pass is rethrown with the record kept, so
                // Dart sees a read error (CORE-6 then refuses to overwrite),
                // never absence.
                if (!isPermanentRecordFailure(e)) throw e
                // The cleanup journal is kept with everything beside it, so
                // its barrier holds (Sol-core-T12-1).
                if (isKeptWhenUnusable(name)) throw e
                // Only a record that is provably bad is removed. A Keystore or
                // provider failure says nothing about the file: keep it and fail.
                if (!isCorruptRecord(e) || name in failClosedNames) throw e
                // A plaintext copy beside a record that failed to authenticate
                // is the leftover of a migration whose wipe failed (the write
                // succeeded, then wipeLegacyFile threw). It is older than the
                // record, so it is never imported in the record's place. It is
                // wiped FIRST: if that throws, the record is kept and the read
                // fails, so no later read can find plaintext without it.
                legacyFile?.let { wipeLegacyFile(it) }
                // The same holds for a `.wvs` record beside this one: a layout
                // migration whose rename failed left it there, and every write
                // goes to this record's name, so it is older than this record
                // and is never returned in its place. It goes FIRST: once this
                // record is gone, migrateLegacyLayout would rename it into this
                // name on the next call. If it cannot be removed, this record
                // is kept and the read fails.
                retireSupersededLegacyRecord(name)
                keepKillSwitchArmedBeforeRemoving(name)
                Log.w(TAG, "A secure record failed authentication; removing it")
                encryptedFile.delete()
            }
        }
        // Belt and braces for the on-disk rename: if migrateLegacyLayout could
        // not move the record (a failed rename, a read-only moment), read it
        // where it still is rather than reporting the record as absent. An
        // absent vpn_settings record would look like "no queued alert".
        legacySecureFile(name)?.let { legacy ->
            try {
                val plaintext = decrypt(name, legacy.readBytes())
                finishInterruptedMigration(legacyFile)
                return plaintext
            } catch (e: Exception) {
                if (!isPermanentRecordFailure(e)) throw e
                if (isKeptWhenUnusable(name)) throw e
                // Only a record that is provably bad is removed. A Keystore or
                // provider failure says nothing about the file: keep it and fail.
                if (!isCorruptRecord(e) || name in failClosedNames) throw e
                legacyFile?.let { wipeLegacyFile(it) }
                keepKillSwitchArmedBeforeRemoving(name)
                Log.w(TAG, "A secure record failed authentication; removing it")
                legacy.delete()
            }
        }

        if (legacyFile != null && legacyFile.isFile) {
            val legacyText = legacyFile.readText(StandardCharsets.UTF_8)
            write(name, legacyText)
            wipeLegacyFile(legacyFile)
            return legacyText
        }
        return null
    }

    @Synchronized
    fun delete(name: String, legacyFile: File? = null): Boolean {
        require(isAllowedName(name)) { "Unsupported secure file name" }
        var deleted = true
        val encryptedFile = secureFile(name)
        // A record the rename could not move must still be deletable, or a
        // duress wipe would leave it behind under the old, self-describing
        // name -- the exact residue this change exists to remove.
        legacySecureFile(name)?.let { deleted = it.delete() && deleted }
        // That record goes FIRST, and while it is still there the current
        // record is kept: once the current record is gone, migrateLegacyLayout
        // would rename the older one into its name and the next read would
        // return the older value.
        if (deleted && encryptedFile.exists()) deleted = encryptedFile.delete()
        if (legacyFile?.exists() == true) deleted = legacyFile.delete() && deleted
        return deleted
    }

    /**
     * Removing an unreadable settings record would turn the legacy kill-switch
     * preference it carried from unknown into "off" whenever no explicit
     * record exists. An explicit "true" is written first, so the loss fails
     * closed exactly as an unreadable explicit record does (failClosedNames),
     * and the user's next toggle replaces it. A write failure propagates, and
     * the settings record is then kept, not removed.
     */
    private fun keepKillSwitchArmedBeforeRemoving(name: String) {
        if (name != LEGACY_KILL_SWITCH_SOURCE) return
        if (secureFile(KILL_SWITCH_RECORD).exists() ||
            legacySecureFile(KILL_SWITCH_RECORD) != null
        ) {
            return
        }
        write(KILL_SWITCH_RECORD, "true")
    }

    /** The platform KeyStoreException's public error code, where the platform exposes one. */
    private fun platformErrorCodeOf(cause: Throwable?): Int? =
        if (cause != null &&
            android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU
        ) {
            platformErrorCode(cause)
        } else {
            null
        }

    @androidx.annotation.RequiresApi(android.os.Build.VERSION_CODES.TIRAMISU)
    private fun platformErrorCode(cause: Throwable): Int? =
        (cause as? android.security.KeyStoreException)?.numericErrorCode

    private fun isCorruptRecord(e: Exception): Boolean =
        e is javax.crypto.AEADBadTagException ||
            e is IllegalArgumentException ||
            e is java.io.EOFException

    private fun decrypt(name: String, encoded: ByteArray): String {
        return DataInputStream(ByteArrayInputStream(encoded)).use { input ->
            require(input.readInt() == FILE_MAGIC) { "Unsupported secure file format" }
            val ivLength = input.readUnsignedByte()
            require(ivLength in 12..16) { "Invalid secure file IV" }
            val iv = ByteArray(ivLength)
            input.readFully(iv)
            val encryptedLength = input.readInt()
            require(encryptedLength in 16..(MAX_PLAINTEXT_BYTES + 32)) {
                "Invalid secure file payload"
            }
            val encryptedBytes = ByteArray(encryptedLength)
            input.readFully(encryptedBytes)
            require(input.available() == 0) { "Trailing secure file data" }

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))
            cipher.updateAAD(aad(name))
            String(cipher.doFinal(encryptedBytes), StandardCharsets.UTF_8)
        }
    }

    private fun aad(name: String): ByteArray {
        return "${context.packageName}:$name:v1".toByteArray(StandardCharsets.UTF_8)
    }

    private fun secureFile(name: String): File {
        migrateLegacyLayout(name)
        return File(secureDirectory, onDiskName(name))
    }

    /**
     * Moves a record written under the old `<logical name>.wvs` filename to
     * its neutral name, in place, before any read/write/delete looks for it.
     *
     * A plain rename is enough and is what is used: the AAD binds the
     * ciphertext to the logical name, not to the path, so the bytes stay
     * decryptable. Best-effort by design -- if the rename fails the legacy
     * file is left exactly where it was and is still found by the fallback in
     * [read] and still removed by [delete], so a queued duress alert can never
     * be stranded by this migration.
     */
    private fun migrateLegacyLayout(name: String) {
        val current = File(secureDirectory, onDiskName(name))
        if (current.exists()) return
        val legacy = File(secureDirectory, legacyOnDiskName(name))
        if (!legacy.exists() || legacy.absolutePath == current.absolutePath) return
        runCatching { Os.rename(legacy.absolutePath, current.absolutePath) }
    }

    /**
     * Removes the `.wvs` record a failed [migrateLegacyLayout] rename left
     * beside a current record. Throws if it is still there afterwards, so a
     * caller about to remove the current record keeps it instead.
     */
    private fun retireSupersededLegacyRecord(name: String) {
        val legacy = File(secureDirectory, legacyOnDiskName(name))
        check(!legacy.exists() || legacy.delete()) {
            "Unable to remove superseded legacy secure record"
        }
    }

    /** The still-unmigrated legacy path, or null once nothing is left there. */
    private fun legacySecureFile(name: String): File? {
        val legacy = File(secureDirectory, legacyOnDiskName(name))
        return if (legacy.exists()) legacy else null
    }

    /**
     * A plaintext copy beside a record that just authenticated is the leftover
     * of a migration that stopped after its write (process death, or a wipe
     * that threw). The record is current, so the copy is only residue. Best
     * effort: a failed wipe never fails a good read, and the next read retries.
     */
    private fun finishInterruptedMigration(legacyFile: File?) {
        if (legacyFile == null) return
        runCatching { wipeLegacyFile(legacyFile) }.onFailure {
            Log.w(TAG, "Legacy plaintext cleanup is still pending")
        }
    }

    private fun wipeLegacyFile(file: File) {
        if (!file.exists()) return
        runCatching {
            file.outputStream().use { stream ->
                stream.channel.truncate(0)
                stream.fd.sync()
            }
        }
        check(!file.exists() || file.delete()) { "Unable to remove legacy plaintext file" }
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        // getKey decides whether the key exists, not containsAlias. On
        // Keystore 2, containsAlias answers false for ANY Keystore error
        // (AndroidKeyStoreSpi.getKeyMetadata logs and returns null), and
        // generating under an alias that still exists replaces the only key
        // that opens the user's records. getKey returns null only for a key
        // that does not exist and throws for every other Keystore error.
        val stored = try {
            keyStore.getKey(keyAlias, null)
        } catch (e: java.security.UnrecoverableKeyException) {
            // getKey reports two conditions this way. A permanently
            // invalidated key arrives with no cause. A lost Keystore daemon
            // (KeyStore2 maps it to SYSTEM_ERROR after one retry) and every
            // other Keystore error arrive with the platform KeyStoreException
            // as the cause. Only a loss that is provably permanent may cost
            // the alias; anything else propagates and the key is kept.
            if (!keyLossIsPermanent(e.cause != null, platformErrorCodeOf(e.cause))) throw e
            Log.w(TAG, "Secure-files key unrecoverable; recreating")
            keyStore.deleteEntry(keyAlias)
            null
        }
        if (stored != null) {
            try {
                val existing = stored as? SecretKey
                    ?: throw java.security.KeyStoreException("secure-files alias holds no secret key")
                val probeCipher = Cipher.getInstance("AES/GCM/NoPadding")
                probeCipher.init(Cipher.ENCRYPT_MODE, existing)
                return existing
            } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
                Log.w(TAG, "Secure-files key permanently invalidated; recreating")
                keyStore.deleteEntry(keyAlias)
            }
            // Every other failure propagates: a transient Keystore error must
            // never destroy the only key that opens the user's records.
        }

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore",
        )
        val spec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }
}
