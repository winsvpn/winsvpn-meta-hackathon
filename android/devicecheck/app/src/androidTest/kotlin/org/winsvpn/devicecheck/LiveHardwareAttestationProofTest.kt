package org.winsvpn.devicecheck

import android.app.KeyguardManager
import android.app.Application
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.hardware.display.DisplayManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.os.SystemClock
import android.os.UserManager
import android.provider.Settings
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.system.Os
import android.system.OsConstants
import android.system.StructStat
import android.util.Base64
import android.view.Display
import android.view.WindowManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey

/**
 * Proves live possession of the persistent RSA key already bound by the
 * owner-authorized hardware-attestation receipt.
 *
 * This test never creates, replaces, or deletes a key. It derives the public
 * identity of every existing attested RSA private-key entry and signs one
 * locally measured, canonical v4 report only when exactly one entry matches
 * the owner-authorized key ID supplied by the evidence collector. The host can
 * supply a fresh session nonce, that key ID, and one transcript-context
 * SHA-256, but no other semantic report fields.
 */
@RunWith(AndroidJUnit4::class)
class LiveHardwareAttestationProofTest {

    @Test
    fun provePossessionOfOwnerAttestedKey() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val arguments = InstrumentationRegistry.getArguments()
        if (arguments.keySet() != ALLOWED_ARGUMENTS) {
            refuse(
                "only the class selector, session nonce, attested key ID, and " +
                    "transcript-context SHA-256 are accepted",
            )
        }
        if (arguments.getString(RUNNER_CLASS_ARGUMENT) != TEST_CLASS_NAME) {
            refuse("instrumentation class selector is absent or ambiguous")
        }
        val nonceHex = exactLowerHex(
            arguments.getString(NONCE_ARGUMENT),
            64,
            "host session nonce",
        )
        val expectedKeyId = exactLowerHex(
            arguments.getString(KEY_ID_ARGUMENT),
            64,
            "attested key ID",
        )
        val transcriptContextSha256 = exactLowerHex(
            arguments.getString(TRANSCRIPT_CONTEXT_SHA256_ARGUMENT),
            64,
            "attestation transcript-context SHA-256",
        )
        val nonce = decodeHex(nonceHex)
        if (nonce.all { it == 0.toByte() }) {
            refuse("host session nonce must not be all zeroes")
        }
        claimSessionNonce(nonceHex)

        if (Build.VERSION.SDK_INT < MIN_SUPPORTED_API) {
            refuse("API 31 or newer is required for exact hardware security-level evidence")
        }
        val targetContext = instrumentation.targetContext
        val testContext = instrumentation.context
        if (targetContext.packageName != TARGET_PACKAGE_ID) {
            refuse("instrumentation target package is not the fixed devicecheck package")
        }
        if (testContext.packageName != TEST_APK_PACKAGE_ID) {
            refuse("instrumentation test package is not the fixed devicecheck test package")
        }

        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val matches = matchingAttestedKeys(keyStore, expectedKeyId)
        if (matches.size != 1) {
            refuse("expected exactly one owner-authorized attested RSA key")
        }
        val keyEvidence = matches.single()
        val packageManager = targetContext.packageManager
        val targetPackage = installedPackageEvidence(
            packageManager,
            targetContext.applicationInfo,
            TARGET_PACKAGE_ID,
        )
        val testPackage = installedPackageEvidence(
            packageManager,
            testContext.applicationInfo,
            TEST_APK_PACKAGE_ID,
        )
        requireDistinctBaseApks(targetPackage, testPackage)
        val bootEvidence = currentBootEvidence(targetContext, keyEvidence.attestation)
        val displayEvidence = displayEvidence(targetContext, nonce)
        val runtimeEvidence = localRuntimeEvidence(targetContext, nonce)
        val report = canonicalReport(
            nonceHex = nonceHex,
            transcriptContextSha256 = transcriptContextSha256,
            expectedKeyId = expectedKeyId,
            targetPackage = targetPackage,
            testPackage = testPackage,
            keyEvidence = keyEvidence,
            bootEvidence = bootEvidence,
            displayEvidence = displayEvidence,
            runtimeEvidence = runtimeEvidence,
            nonce = nonce,
        )

        val signer = Signature.getInstance(SIGNATURE_ALGORITHM)
        signer.initSign(keyEvidence.privateKey)
        signer.update(SIGNATURE_DOMAIN)
        signer.update(nonce)
        signer.update(report)
        val signatureHex = signer.sign().toHex()
        val expectedSignatureHexLength = keyEvidence.modulusBits / 4
        if (
            signatureHex.length != expectedSignatureHexLength ||
            signatureHex.length > MAX_SIGNATURE_HEX_CHARS
        ) {
            refuse("hardware-backed signing returned a noncanonical signature")
        }
        val reportBase64 = Base64.encodeToString(report, Base64.NO_WRAP)
        if (reportBase64.isEmpty() || reportBase64.length > MAX_REPORT_BASE64_CHARS) {
            refuse("canonical attestation report exceeds its status bound")
        }

        val status = Bundle().apply {
            putString(REPORT_STATUS, reportBase64)
            putString(SIGNATURE_STATUS, signatureHex)
            putString(KEY_ID_STATUS, expectedKeyId)
            putString(SCHEMA_STATUS, REPORT_SCHEMA)
        }
        if (status.keySet() != STATUS_KEYS) {
            refuse("live attestation status schema drifted")
        }

        // AndroidJUnitRunner emits final INSTRUMENTATION_CODE: -1 after this
        // test returns normally. This is the sole custom status bundle.
        instrumentation.sendStatus(STATUS_IN_PROGRESS, status)
    }

    private fun matchingAttestedKeys(
        keyStore: KeyStore,
        expectedKeyId: String,
    ): List<KeyEvidence> {
        val aliases = mutableListOf<String>()
        val uniqueAliases = mutableSetOf<String>()
        val enumeration = keyStore.aliases()
        while (enumeration.hasMoreElements()) {
            val alias = enumeration.nextElement()
            if (!uniqueAliases.add(alias)) {
                refuse("AndroidKeyStore returned a duplicate alias")
            }
            aliases += alias
        }

        val matches = mutableListOf<KeyEvidence>()
        for (alias in aliases.sorted()) {
            if (!keyStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry::class.java)) {
                continue
            }
            val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
                ?: refuse("AndroidKeyStore private-key entry changed during lookup")
            val leaf = entry.certificate as? X509Certificate
                ?: refuse("AndroidKeyStore private-key certificate is not X.509")
            val publicKey = leaf.publicKey as? RSAPublicKey ?: continue
            if (publicKey.publicExponent != RSA_PUBLIC_EXPONENT) {
                continue
            }
            if (
                publicKey.modulus.bitLength() !in RSA_MODULUS_BITS ||
                !publicKey.modulus.testBit(0)
            ) {
                continue
            }
            val privateKey = entry.privateKey
            if (!privateKey.algorithm.equals("RSA", ignoreCase = true)) {
                continue
            }
            if (attestedKeyId(publicKey) != expectedKeyId) {
                continue
            }

            val chain = keyStore.getCertificateChain(alias)
                ?: refuse("owner-authorized key has no attestation certificate chain")
            if (chain.size !in MIN_CERTIFICATE_CHAIN_LENGTH..MAX_CERTIFICATE_CHAIN_LENGTH) {
                refuse("owner-authorized key has an invalid attestation chain length")
            }
            val certificates = chain.map {
                it as? X509Certificate
                    ?: refuse("attestation chain contains a non-X.509 certificate")
            }
            if (!MessageDigest.isEqual(leaf.encoded, certificates.first().encoded)) {
                refuse("AndroidKeyStore leaf certificate changed during lookup")
            }
            val extensionHolders = certificates.filter {
                (it.getExtensionValue(ATTESTATION_OID) as? ByteArray)?.isNotEmpty() == true
            }
            if (extensionHolders.size != 1 || extensionHolders.single() !== certificates.first()) {
                refuse("attestation extension is absent, duplicated, or not on the leaf")
            }
            val attestationExtension = leaf.getExtensionValue(ATTESTATION_OID) as? ByteArray
                ?: refuse("owner-authorized key has no attestation extension")
            val attestation = parseAttestationExtension(attestationExtension)

            val keyInfo = try {
                KeyFactory.getInstance("RSA", ANDROID_KEYSTORE)
                    .getKeySpec(privateKey, KeyInfo::class.java)
            } catch (exception: Exception) {
                refuse("owner-authorized key has no trustworthy KeyInfo: ${exception.javaClass.simpleName}")
            }
            if (keyInfo.keystoreAlias != alias) {
                refuse("KeyInfo alias does not identify the enumerated persistent key")
            }
            if (keyInfo.origin != KeyProperties.ORIGIN_GENERATED) {
                refuse("owner-authorized key was not generated in AndroidKeyStore")
            }
            if (keyInfo.purposes != KeyProperties.PURPOSE_SIGN) {
                refuse("owner-authorized key must authorize exactly SIGN")
            }
            if (
                keyInfo.digests.size != 1 ||
                keyInfo.digests.single() != KeyProperties.DIGEST_SHA256
            ) {
                refuse("owner-authorized key must authorize exactly SHA-256")
            }
            if (
                keyInfo.signaturePaddings.size != 1 ||
                keyInfo.signaturePaddings.single() != KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
            ) {
                refuse("owner-authorized key must authorize exactly RSA PKCS1 signing padding")
            }
            if (keyInfo.encryptionPaddings.isNotEmpty() || keyInfo.blockModes.isNotEmpty()) {
                refuse("owner-authorized signing key has unrelated cipher authorizations")
            }
            if (keyInfo.keySize != publicKey.modulus.bitLength()) {
                refuse("KeyInfo size contradicts the attested RSA public key")
            }
            val securityLevel = when (keyInfo.securityLevel) {
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "tee"
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
                else -> refuse("owner-authorized key is software-backed or has unknown security")
            }
            if (
                attestation.attestationSecurityLevel != securityLevel ||
                attestation.keyMintSecurityLevel != securityLevel
            ) {
                refuse("KeyInfo and attestation security levels disagree")
            }
            matches += KeyEvidence(
                privateKey = privateKey,
                modulusBits = publicKey.modulus.bitLength(),
                leafSha256 = sha256(leaf.encoded),
                attestationExtensionSha256 = sha256(attestationExtension),
                securityLevel = securityLevel,
                attestation = attestation,
            )
        }
        return matches
    }

    private data class KeyEvidence(
        val privateKey: PrivateKey,
        val modulusBits: Int,
        val leafSha256: String,
        val attestationExtensionSha256: String,
        val securityLevel: String,
        val attestation: AttestationEvidence,
    )

    private data class PackageEvidence(
        val packageId: String,
        val versionNameUtf8Hex: String,
        val versionCode: Long,
        val baseApk: InstalledBaseApkEvidence,
        val signerSha256: String,
        val installingPackage: String,
        val initiatingPackage: String,
        val originatingPackage: String,
    )

    private data class InstalledPackageMetadata(
        val packageId: String,
        val versionNameUtf8Hex: String,
        val versionCode: Long,
        val sourceDir: String,
        val signerSha256: String,
        val installingPackage: String,
        val initiatingPackage: String,
        val originatingPackage: String,
    )

    private data class ApkFileIdentity(
        val device: Long,
        val inode: Long,
        val mode: Int,
        val linkCount: Long,
        val uid: Int,
        val gid: Int,
        val deviceType: Long,
        val size: Long,
        val blocks: Long,
        val modifiedSeconds: Long,
        val modifiedNanoseconds: Long,
        val changedSeconds: Long,
        val changedNanoseconds: Long,
    )

    private data class InstalledBaseApkEvidence(
        val canonicalPath: String,
        val identity: ApkFileIdentity,
        val sha256: String,
        val bytes: Long,
    )

    @Suppress("DEPRECATION")
    private fun installedPackageEvidence(
        packageManager: PackageManager,
        contextApplicationInfo: ApplicationInfo,
        expectedPackageId: String,
    ): PackageEvidence {
        val contextSourceDir = exactBaseApkSource(
            contextApplicationInfo,
            expectedPackageId,
        )
        val before = installedPackageMetadata(
            packageManager,
            contextApplicationInfo,
            expectedPackageId,
        )
        if (before.sourceDir != contextSourceDir) {
            refuse("package and context ApplicationInfo sourceDir values are ambiguous")
        }
        val baseApk = installedBaseApkEvidence(before.sourceDir, expectedPackageId)
        val after = installedPackageMetadata(
            packageManager,
            contextApplicationInfo,
            expectedPackageId,
        )
        if (after != before) {
            refuse("installed package identity or source changed during base APK measurement")
        }
        return PackageEvidence(
            packageId = before.packageId,
            versionNameUtf8Hex = before.versionNameUtf8Hex,
            versionCode = before.versionCode,
            baseApk = baseApk,
            signerSha256 = before.signerSha256,
            installingPackage = before.installingPackage,
            initiatingPackage = before.initiatingPackage,
            originatingPackage = before.originatingPackage,
        )
    }

    @Suppress("DEPRECATION")
    private fun installedPackageMetadata(
        packageManager: PackageManager,
        contextApplicationInfo: ApplicationInfo,
        expectedPackageId: String,
    ): InstalledPackageMetadata {
        val info: PackageInfo = try {
            packageManager.getPackageInfo(
                expectedPackageId,
                PackageManager.GET_SIGNING_CERTIFICATES,
            )
        } catch (exception: PackageManager.NameNotFoundException) {
            refuse("required installed package is absent: $expectedPackageId")
        }
        if (info.packageName != expectedPackageId) {
            refuse("PackageManager returned an ambiguous package identity")
        }
        if (!info.splitNames.isNullOrEmpty()) {
            refuse("installed package has split APK names")
        }
        val applicationInfo = info.applicationInfo
            ?: refuse("installed package ApplicationInfo is absent")
        if (applicationInfo.uid != contextApplicationInfo.uid) {
            refuse("package and context ApplicationInfo UIDs are ambiguous")
        }
        val sourceDir = exactBaseApkSource(applicationInfo, expectedPackageId)
        val versionName = info.versionName
            ?: refuse("installed package has no version name: $expectedPackageId")
        val versionNameBytes = versionName.toByteArray(StandardCharsets.UTF_8)
        if (
            versionNameBytes.isEmpty() ||
            versionNameBytes.size > MAX_VERSION_NAME_BYTES ||
            String(versionNameBytes, StandardCharsets.UTF_8) != versionName
        ) {
            refuse("installed package version name is not bounded canonical UTF-8")
        }
        val versionCode = info.longVersionCode
        if (versionCode <= 0) {
            refuse("installed package version code is absent")
        }

        val signingInfo = info.signingInfo
            ?: refuse("installed package signing information is absent")
        if (signingInfo.hasMultipleSigners()) {
            refuse("installed package has multiple current signers")
        }
        val signers = signingInfo.apkContentsSigners
            ?: refuse("installed package signer set is absent")
        if (signers.size != 1) {
            refuse("installed package must have exactly one current signer")
        }
        val history = signingInfo.signingCertificateHistory
            ?: refuse("installed package signing history is absent")
        if (
            history.size != 1 ||
            !MessageDigest.isEqual(history.single().toByteArray(), signers.single().toByteArray())
        ) {
            refuse("installed package signer history is duplicated or ambiguous")
        }
        val signerBytes = signers.single().toByteArray()
        if (signerBytes.isEmpty() || signerBytes.size > MAX_SIGNING_CERTIFICATE_BYTES) {
            refuse("installed package signer certificate exceeds its bound")
        }

        val source = try {
            packageManager.getInstallSourceInfo(expectedPackageId)
        } catch (exception: PackageManager.NameNotFoundException) {
            refuse("installed package source disappeared during lookup")
        }
        val installing = canonicalPackageOrNone(source.installingPackageName)
        val initiating = canonicalPackageOrNone(source.initiatingPackageName)
        val originating = canonicalPackageOrNone(source.originatingPackageName)
        if (installing == NONE && initiating == NONE && originating == NONE) {
            refuse("installed package has no locally observable install source")
        }
        return InstalledPackageMetadata(
            packageId = expectedPackageId,
            versionNameUtf8Hex = versionNameBytes.toHex(),
            versionCode = versionCode,
            sourceDir = sourceDir,
            signerSha256 = sha256(signerBytes),
            installingPackage = installing,
            initiatingPackage = initiating,
            originatingPackage = originating,
        )
    }

    private fun exactBaseApkSource(
        applicationInfo: ApplicationInfo,
        expectedPackageId: String,
    ): String {
        if (applicationInfo.packageName != expectedPackageId) {
            refuse("ApplicationInfo returned an ambiguous package identity")
        }
        if (
            !applicationInfo.splitNames.isNullOrEmpty() ||
            !applicationInfo.splitSourceDirs.isNullOrEmpty() ||
            !applicationInfo.splitPublicSourceDirs.isNullOrEmpty()
        ) {
            refuse("installed package must contain exactly one base APK and no splits")
        }
        val sourceDir = applicationInfo.sourceDir
            ?: refuse("installed package sourceDir is absent")
        val publicSourceDir = applicationInfo.publicSourceDir
            ?: refuse("installed package publicSourceDir is absent")
        if (sourceDir != publicSourceDir) {
            refuse("installed package sourceDir and publicSourceDir are ambiguous")
        }
        return canonicalBaseApkPath(sourceDir)
    }

    private fun canonicalBaseApkPath(sourceDir: String): String {
        val sourceBytes = sourceDir.toByteArray(StandardCharsets.UTF_8)
        val sourceFile = File(sourceDir)
        val canonicalPath = try {
            sourceFile.canonicalPath
        } catch (exception: Exception) {
            refuse("installed base APK sourceDir cannot be canonicalized")
        }
        if (
            sourceBytes.isEmpty() ||
            sourceBytes.size > MAX_APK_SOURCE_DIR_BYTES ||
            String(sourceBytes, StandardCharsets.UTF_8) != sourceDir ||
            sourceDir.any { it == '\u0000' } ||
            !sourceFile.isAbsolute ||
            sourceFile.absolutePath != sourceDir ||
            canonicalPath != sourceDir
        ) {
            refuse("installed base APK sourceDir is noncanonical or ambiguous")
        }
        return canonicalPath
    }

    private fun installedBaseApkEvidence(
        sourceDir: String,
        expectedPackageId: String,
    ): InstalledBaseApkEvidence {
        val canonicalPathBefore = canonicalBaseApkPath(sourceDir)
        val pathBefore = try {
            Os.lstat(sourceDir)
        } catch (exception: Exception) {
            refuse("installed base APK path is unavailable: $expectedPackageId")
        }
        requireBoundedRegularBaseApk(pathBefore, expectedPackageId)
        val pathIdentityBefore = apkFileIdentity(pathBefore)
        val descriptor = try {
            Os.open(
                sourceDir,
                OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW,
                0,
            )
        } catch (exception: Exception) {
            refuse("installed base APK descriptor-open failed: $expectedPackageId")
        }
        try {
            val before = Os.fstat(descriptor)
            requireBoundedRegularBaseApk(before, expectedPackageId)
            val identityBefore = apkFileIdentity(before)
            if (identityBefore != pathIdentityBefore) {
                refuse("installed base APK path changed before descriptor measurement")
            }

            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(APK_READ_BUFFER_BYTES)
            var bytesRead = 0L
            while (bytesRead < before.st_size) {
                val requested = minOf(
                    buffer.size.toLong(),
                    before.st_size - bytesRead,
                ).toInt()
                val count = Os.read(descriptor, buffer, 0, requested)
                if (count <= 0) {
                    refuse("installed base APK was truncated during descriptor read")
                }
                digest.update(buffer, 0, count)
                bytesRead += count.toLong()
            }
            val trailing = Os.read(descriptor, buffer, 0, 1)
            if (trailing < 0) {
                refuse("installed base APK descriptor returned an invalid read count")
            }
            if (trailing > 0) {
                refuse("installed base APK grew during descriptor read")
            }
            if (bytesRead != before.st_size) {
                refuse("installed base APK byte count contradicts descriptor identity")
            }

            val after = Os.fstat(descriptor)
            requireBoundedRegularBaseApk(after, expectedPackageId)
            val identityAfter = apkFileIdentity(after)
            if (identityAfter != identityBefore) {
                refuse("installed base APK mutated during descriptor read")
            }
            val pathAfter = try {
                Os.lstat(sourceDir)
            } catch (exception: Exception) {
                refuse("installed base APK path disappeared during descriptor read")
            }
            requireBoundedRegularBaseApk(pathAfter, expectedPackageId)
            val pathIdentityAfter = apkFileIdentity(pathAfter)
            val canonicalPathAfter = canonicalBaseApkPath(sourceDir)
            if (
                pathIdentityAfter != identityAfter ||
                canonicalPathAfter != canonicalPathBefore
            ) {
                refuse("installed base APK path was substituted during descriptor read")
            }
            return InstalledBaseApkEvidence(
                canonicalPath = canonicalPathBefore,
                identity = identityAfter,
                sha256 = digest.digest().toHex(),
                bytes = bytesRead,
            )
        } finally {
            Os.close(descriptor)
        }
    }

    private fun requireBoundedRegularBaseApk(stat: StructStat, packageId: String) {
        if (
            !OsConstants.S_ISREG(stat.st_mode) ||
            stat.st_nlink != 1L ||
            stat.st_size !in 1L..MAX_BASE_APK_BYTES
        ) {
            refuse("installed base APK is empty, oversized, non-regular, or multiply linked: $packageId")
        }
    }

    private fun apkFileIdentity(stat: StructStat): ApkFileIdentity = ApkFileIdentity(
        device = stat.st_dev,
        inode = stat.st_ino,
        mode = stat.st_mode,
        linkCount = stat.st_nlink,
        uid = stat.st_uid,
        gid = stat.st_gid,
        deviceType = stat.st_rdev,
        size = stat.st_size,
        blocks = stat.st_blocks,
        modifiedSeconds = stat.st_mtim.tv_sec,
        modifiedNanoseconds = stat.st_mtim.tv_nsec,
        changedSeconds = stat.st_ctim.tv_sec,
        changedNanoseconds = stat.st_ctim.tv_nsec,
    )

    private fun requireDistinctBaseApks(
        targetPackage: PackageEvidence,
        testPackage: PackageEvidence,
    ) {
        val targetApk = targetPackage.baseApk
        val testApk = testPackage.baseApk
        if (
            targetApk.canonicalPath == testApk.canonicalPath ||
            (
                targetApk.identity.device == testApk.identity.device &&
                    targetApk.identity.inode == testApk.identity.inode
                )
        ) {
            refuse("target and androidTest packages resolve to the same base APK")
        }
    }

    private fun canonicalPackageOrNone(value: String?): String {
        if (value == null) return NONE
        if (value.length !in 3..MAX_PACKAGE_NAME_CHARS || !PACKAGE_NAME.matches(value)) {
            refuse("install source package name is not canonical")
        }
        return value
    }

    private data class BootEvidence(
        val verifiedBootState: String,
        val flashLocked: String,
        val vbmetaDeviceState: String,
        val userDeviceSecure: Boolean,
        val userUnlocked: Boolean,
        val deviceProvisioned: Boolean,
        val bootCount: Int,
    )

    private fun currentBootEvidence(
        context: Context,
        attestation: AttestationEvidence,
    ): BootEvidence {
        if (!attestation.deviceLocked || attestation.verifiedBootState != VERIFIED_BOOT_STATE_NAME) {
            refuse("attested boot state is not locked and green")
        }
        val verifiedBootState = exactSystemProperty(VERIFIED_BOOT_STATE_PROPERTY)
        val flashLocked = exactSystemProperty(FLASH_LOCKED_PROPERTY)
        val vbmetaDeviceState = exactSystemProperty(VBMETA_DEVICE_STATE_PROPERTY)
        if (
            verifiedBootState != VERIFIED_BOOT_STATE_NAME ||
            flashLocked != FLASH_LOCKED_VALUE ||
            vbmetaDeviceState != VBMETA_LOCKED_VALUE
        ) {
            refuse("current boot properties do not prove locked green verified boot")
        }

        val keyguardManager = context.getSystemService(KeyguardManager::class.java)
            ?: refuse("local keyguard runtime is unavailable")
        val userManager = context.getSystemService(UserManager::class.java)
            ?: refuse("local user runtime is unavailable")
        val userDeviceSecure = keyguardManager.isDeviceSecure
        val userUnlocked = userManager.isUserUnlocked
        val deviceProvisioned = Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.DEVICE_PROVISIONED,
            0,
        ) == 1
        val bootCount = Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.BOOT_COUNT,
            -1,
        )
        if (!userDeviceSecure || !userUnlocked || !deviceProvisioned || bootCount < 0) {
            refuse("local device-lock or boot runtime facts are unavailable")
        }
        return BootEvidence(
            verifiedBootState = verifiedBootState,
            flashLocked = flashLocked,
            vbmetaDeviceState = vbmetaDeviceState,
            userDeviceSecure = userDeviceSecure,
            userUnlocked = userUnlocked,
            deviceProvisioned = deviceProvisioned,
            bootCount = bootCount,
        )
    }

    private fun exactSystemProperty(name: String): String {
        if (name !in ALLOWED_SYSTEM_PROPERTIES) refuse("system property is not allowlisted")
        val process = try {
            ProcessBuilder(GETPROP_PATH, name).start()
        } catch (exception: Exception) {
            refuse("local verified-boot property runtime is unavailable")
        }
        try {
            val stdout = readBounded(process.inputStream, MAX_SYSTEM_PROPERTY_OUTPUT_BYTES)
            val stderr = readBounded(process.errorStream, MAX_SYSTEM_PROPERTY_OUTPUT_BYTES)
            val exitCode = process.waitFor()
            if (exitCode != 0 || stderr.isNotEmpty()) {
                refuse("local verified-boot property query failed")
            }
            if (stdout.any { (it.toInt() and 0xff) !in ASCII_PRINTABLE_OR_NEWLINE }) {
                refuse("local verified-boot property is not canonical ASCII")
            }
            val raw = String(stdout, StandardCharsets.US_ASCII)
            val value = if (raw.endsWith("\n")) raw.dropLast(1) else raw
            if (value.isEmpty() || value.length > MAX_SYSTEM_PROPERTY_VALUE_CHARS) {
                refuse("local verified-boot property is absent or oversized")
            }
            if (value.any { it == '\n' || it == '\r' }) {
                refuse("local verified-boot property is ambiguous")
            }
            return value
        } finally {
            process.destroy()
        }
    }

    private fun readBounded(stream: java.io.InputStream, maximum: Int): ByteArray {
        val result = ByteArray(maximum)
        var count = 0
        while (count < result.size) {
            val read = stream.read(result, count, result.size - count)
            if (read < 0) return result.copyOf(count)
            if (read == 0) continue
            count += read
        }
        if (stream.read() >= 0) refuse("local runtime output exceeds its bound")
        return result
    }

    private data class DisplayEvidence(
        val displayCount: Int,
        val displayId: Int,
        val nameNonceSha256: String,
        val flags: Int,
        val state: Int,
        val rotation: Int,
        val modeId: Int,
        val physicalWidthPixels: Int,
        val physicalHeightPixels: Int,
        val refreshMilliHertz: Int,
        val currentWidthPixels: Int,
        val currentHeightPixels: Int,
        val maximumWidthPixels: Int,
        val maximumHeightPixels: Int,
        val densityDpi: Int,
    )

    @Suppress("DEPRECATION")
    private fun displayEvidence(context: Context, nonce: ByteArray): DisplayEvidence {
        val displayManager = context.getSystemService(DisplayManager::class.java)
            ?: refuse("local display runtime is unavailable")
        val displays = displayManager.displays.toList()
        if (displays.size != 1) {
            refuse("local display endpoint is absent or ambiguous")
        }
        val display = displays.single()
        val windowManager = context.getSystemService(WindowManager::class.java)
            ?: refuse("local window runtime is unavailable")
        if (
            display.displayId != Display.DEFAULT_DISPLAY ||
            windowManager.defaultDisplay.displayId != display.displayId ||
            !display.isValid ||
            display.state != Display.STATE_ON
        ) {
            refuse("default display endpoint is invalid or not live")
        }
        val mode = display.mode
        val refreshMilliHertz = (mode.refreshRate * 1000.0f).toInt()
        val currentBounds = windowManager.currentWindowMetrics.bounds
        val maximumBounds = windowManager.maximumWindowMetrics.bounds
        val densityDpi = context.resources.configuration.densityDpi
        val dimensions = listOf(
            mode.physicalWidth,
            mode.physicalHeight,
            currentBounds.width(),
            currentBounds.height(),
            maximumBounds.width(),
            maximumBounds.height(),
        )
        if (
            dimensions.any { it !in MIN_DISPLAY_PIXELS..MAX_DISPLAY_PIXELS } ||
            refreshMilliHertz !in MIN_REFRESH_MILLIHERTZ..MAX_REFRESH_MILLIHERTZ ||
            densityDpi !in MIN_DENSITY_DPI..MAX_DENSITY_DPI ||
            display.rotation !in MIN_DISPLAY_ROTATION..MAX_DISPLAY_ROTATION ||
            mode.modeId <= 0
        ) {
            refuse("local display endpoint facts are implausible")
        }
        return DisplayEvidence(
            displayCount = displays.size,
            displayId = display.displayId,
            nameNonceSha256 = nonceSaltedHash(nonce, "display_name", display.name),
            flags = display.flags,
            state = display.state,
            rotation = display.rotation,
            modeId = mode.modeId,
            physicalWidthPixels = mode.physicalWidth,
            physicalHeightPixels = mode.physicalHeight,
            refreshMilliHertz = refreshMilliHertz,
            currentWidthPixels = currentBounds.width(),
            currentHeightPixels = currentBounds.height(),
            maximumWidthPixels = maximumBounds.width(),
            maximumHeightPixels = maximumBounds.height(),
            densityDpi = densityDpi,
        )
    }

    private data class LinkEndpointEvidence(
        val interfaceNameUtf8Hex: String,
        val linkAddressCount: Int,
        val routeCount: Int,
        val dnsServerCount: Int,
        val mtu: Int,
        val endpointNonceSha256: String,
    )

    private data class NetworkEvidence(
        val networkCount: Int,
        val activeNetworkHandle: Long,
        val activeTransports: String,
        val activeValidated: Boolean,
        val activeInternet: Boolean,
        val activeEndpoint: LinkEndpointEvidence,
        val vpnPresent: Boolean,
        val vpnNetworkHandle: Long,
        val vpnEndpoint: LinkEndpointEvidence,
    )

    private data class RuntimeEvidence(
        val processNameUtf8Hex: String,
        val processId: Int,
        val processUid: Int,
        val elapsedRealtimeMillis: Long,
        val uptimeMillis: Long,
        val wallClockMillis: Long,
        val androidSdk: Int,
        val securityPatch: String,
        val buildNonceHashes: List<Pair<String, String>>,
        val network: NetworkEvidence,
    )

    private fun localRuntimeEvidence(context: Context, nonce: ByteArray): RuntimeEvidence {
        val processName = Application.getProcessName()
        val processNameBytes = processName.toByteArray(StandardCharsets.UTF_8)
        val processId = Process.myPid()
        val processUid = Process.myUid()
        val elapsedRealtimeMillis = SystemClock.elapsedRealtime()
        val uptimeMillis = SystemClock.uptimeMillis()
        val wallClockMillis = System.currentTimeMillis()
        if (
            processName != TARGET_PACKAGE_ID ||
            processNameBytes.isEmpty() ||
            processNameBytes.size > MAX_PROCESS_NAME_BYTES ||
            processId <= 0 ||
            processUid != context.applicationInfo.uid ||
            uptimeMillis <= 0 ||
            elapsedRealtimeMillis < uptimeMillis ||
            wallClockMillis < MIN_WALL_CLOCK_MILLIS
        ) {
            refuse("local instrumentation runtime is absent or contradictory")
        }
        val securityPatch = Build.VERSION.SECURITY_PATCH
        if (!SECURITY_PATCH.matches(securityPatch)) {
            refuse("Android security patch fact is absent or noncanonical")
        }
        val buildFacts = listOf(
            "board" to Build.BOARD,
            "bootloader" to Build.BOOTLOADER,
            "brand" to Build.BRAND,
            "device" to Build.DEVICE,
            "display" to Build.DISPLAY,
            "fingerprint" to Build.FINGERPRINT,
            "hardware" to Build.HARDWARE,
            "host" to Build.HOST,
            "id" to Build.ID,
            "manufacturer" to Build.MANUFACTURER,
            "model" to Build.MODEL,
            "product" to Build.PRODUCT,
            "soc_manufacturer" to Build.SOC_MANUFACTURER,
            "soc_model" to Build.SOC_MODEL,
            "supported_abis" to Build.SUPPORTED_ABIS.joinToString(","),
            "tags" to Build.TAGS,
            "type" to Build.TYPE,
            "user" to Build.USER,
            "version_incremental" to Build.VERSION.INCREMENTAL,
            "version_release" to Build.VERSION.RELEASE,
        )
        if (buildFacts.map { it.first } != BUILD_HASH_LABELS) {
            refuse("fixed Build fact schema drifted")
        }
        val buildHashes = buildFacts.map { (label, value) ->
            val bytes = value.toByteArray(StandardCharsets.UTF_8)
            if (bytes.isEmpty() || bytes.size > MAX_BUILD_FACT_BYTES) {
                refuse("local Build fact is absent or exceeds its bound")
            }
            label to nonceSaltedHash(nonce, "build_$label", value)
        }
        return RuntimeEvidence(
            processNameUtf8Hex = processNameBytes.toHex(),
            processId = processId,
            processUid = processUid,
            elapsedRealtimeMillis = elapsedRealtimeMillis,
            uptimeMillis = uptimeMillis,
            wallClockMillis = wallClockMillis,
            androidSdk = Build.VERSION.SDK_INT,
            securityPatch = securityPatch,
            buildNonceHashes = buildHashes,
            network = localNetworkEvidence(context, nonce),
        )
    }

    private fun localNetworkEvidence(context: Context, nonce: ByteArray): NetworkEvidence {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
            ?: refuse("local connectivity runtime is unavailable")
        val networks = connectivity.allNetworks.toList()
        val handles = networks.map { it.networkHandle }
        if (
            networks.isEmpty() ||
            networks.size > MAX_NETWORK_COUNT ||
            handles.any { it <= 0L } ||
            handles.toSet().size != handles.size
        ) {
            refuse("local network runtime is absent, duplicated, or oversized")
        }
        val activeBefore = connectivity.activeNetwork
            ?: refuse("local active network runtime is unavailable")
        val activeHandle = activeBefore.networkHandle
        if (activeHandle !in handles) refuse("active network is absent from local inventory")

        val snapshots = networks.associateBy(
            { it.networkHandle },
            {
                val capabilities = connectivity.getNetworkCapabilities(it)
                    ?: refuse("local network capabilities changed during measurement")
                val properties = connectivity.getLinkProperties(it)
                    ?: refuse("local network endpoint changed during measurement")
                capabilities to properties
            },
        )
        if (snapshots.size != networks.size) refuse("local network inventory is ambiguous")
        val activeSnapshot = snapshots[activeHandle]
            ?: refuse("active network snapshot is absent")
        val activeCapabilities = activeSnapshot.first
        val activeInternet = activeCapabilities.hasCapability(
            NetworkCapabilities.NET_CAPABILITY_INTERNET,
        )
        val activeValidated = activeCapabilities.hasCapability(
            NetworkCapabilities.NET_CAPABILITY_VALIDATED,
        )
        if (!activeInternet || !activeValidated) {
            refuse("local active network is not an exact validated runtime endpoint")
        }
        val activeTransports = canonicalTransports(activeCapabilities)
        val activeEndpoint = linkEndpointEvidence(
            activeSnapshot.second,
            nonce,
            "active_network_endpoint",
        )

        val vpnHandles = snapshots.entries.filter {
            it.value.first.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        }.map { it.key }
        if (vpnHandles.size > 1) refuse("multiple VPN runtime endpoints are ambiguous")
        val vpnPresent = vpnHandles.size == 1
        val vpnHandle = vpnHandles.singleOrNull() ?: NO_NETWORK_HANDLE
        if (vpnPresent && vpnHandle != activeHandle) {
            refuse("VPN runtime endpoint is not the active tested endpoint")
        }
        val vpnEndpoint = if (vpnPresent) {
            val snapshot = snapshots[vpnHandle]
                ?: refuse("VPN runtime endpoint disappeared")
            linkEndpointEvidence(snapshot.second, nonce, "vpn_network_endpoint")
        } else {
            LinkEndpointEvidence(
                interfaceNameUtf8Hex = NONE.toByteArray(StandardCharsets.US_ASCII).toHex(),
                linkAddressCount = 0,
                routeCount = 0,
                dnsServerCount = 0,
                mtu = 0,
                endpointNonceSha256 = nonceSaltedHash(
                    nonce,
                    "vpn_network_endpoint",
                    NONE,
                ),
            )
        }
        val activeAfter = connectivity.activeNetwork
            ?: refuse("active network disappeared after local measurement")
        val endingHandles = connectivity.allNetworks.map { it.networkHandle }.toSet()
        if (activeAfter.networkHandle != activeHandle || endingHandles != handles.toSet()) {
            refuse("local network runtime changed during measurement")
        }
        return NetworkEvidence(
            networkCount = networks.size,
            activeNetworkHandle = activeHandle,
            activeTransports = activeTransports,
            activeValidated = activeValidated,
            activeInternet = activeInternet,
            activeEndpoint = activeEndpoint,
            vpnPresent = vpnPresent,
            vpnNetworkHandle = vpnHandle,
            vpnEndpoint = vpnEndpoint,
        )
    }

    private fun requireCanonicalNetworkSchema(
        network: NetworkEvidence,
        nonce: ByteArray,
    ) {
        val transports = network.activeTransports.split(',')
        val allowedTransports = NETWORK_TRANSPORTS.map { it.first }
        val activeEndpoint = network.activeEndpoint
        if (
            transports.isEmpty() ||
            transports.toSet().size != transports.size ||
            transports != allowedTransports.filter { it in transports } ||
            network.networkCount !in 1..MAX_NETWORK_COUNT ||
            network.activeNetworkHandle <= NO_NETWORK_HANDLE ||
            !network.activeValidated ||
            !network.activeInternet ||
            activeEndpoint.interfaceNameUtf8Hex == NONE_UTF8_HEX ||
            activeEndpoint.linkAddressCount !in 1..MAX_LINK_ADDRESS_COUNT ||
            activeEndpoint.routeCount !in 1..MAX_ROUTE_COUNT ||
            activeEndpoint.dnsServerCount !in 0..MAX_DNS_SERVER_COUNT ||
            activeEndpoint.mtu !in 0..MAX_NETWORK_MTU ||
            activeEndpoint.endpointNonceSha256.length != SHA256_HEX_CHARS ||
            activeEndpoint.endpointNonceSha256.any { it !in LOWER_HEX }
        ) {
            refuse("active network evidence contradicts the canonical report schema")
        }

        val vpnTransportPresent = "vpn" in transports
        val absentVpnEndpointSha256 = nonceSaltedHash(
            nonce,
            "vpn_network_endpoint",
            NONE,
        )
        val vpnEndpoint = network.vpnEndpoint
        if (network.vpnPresent) {
            if (
                !vpnTransportPresent ||
                network.networkCount < 2 ||
                network.vpnNetworkHandle != network.activeNetworkHandle ||
                vpnEndpoint.interfaceNameUtf8Hex == NONE_UTF8_HEX ||
                vpnEndpoint.interfaceNameUtf8Hex != activeEndpoint.interfaceNameUtf8Hex ||
                vpnEndpoint.linkAddressCount != activeEndpoint.linkAddressCount ||
                vpnEndpoint.routeCount != activeEndpoint.routeCount ||
                vpnEndpoint.dnsServerCount != activeEndpoint.dnsServerCount ||
                vpnEndpoint.mtu != activeEndpoint.mtu ||
                vpnEndpoint.endpointNonceSha256.length != SHA256_HEX_CHARS ||
                vpnEndpoint.endpointNonceSha256.any { it !in LOWER_HEX } ||
                vpnEndpoint.endpointNonceSha256 == activeEndpoint.endpointNonceSha256 ||
                vpnEndpoint.endpointNonceSha256 == absentVpnEndpointSha256
            ) {
                refuse("present VPN evidence contradicts the canonical report schema")
            }
        } else if (
            vpnTransportPresent ||
            network.vpnNetworkHandle != NO_NETWORK_HANDLE ||
            vpnEndpoint.interfaceNameUtf8Hex != NONE_UTF8_HEX ||
            vpnEndpoint.linkAddressCount != 0 ||
            vpnEndpoint.routeCount != 0 ||
            vpnEndpoint.dnsServerCount != 0 ||
            vpnEndpoint.mtu != 0 ||
            vpnEndpoint.endpointNonceSha256 != absentVpnEndpointSha256
        ) {
            refuse("absent VPN evidence contradicts the canonical report schema")
        }
    }

    private fun canonicalTransports(capabilities: NetworkCapabilities): String {
        val present = NETWORK_TRANSPORTS.filter { capabilities.hasTransport(it.second) }
        if (present.isEmpty()) refuse("local network has no recognized transport")
        return present.joinToString(",") { it.first }
    }

    private fun linkEndpointEvidence(
        properties: LinkProperties,
        nonce: ByteArray,
        label: String,
    ): LinkEndpointEvidence {
        val interfaceName = properties.interfaceName
            ?: refuse("local network interface name is absent")
        val interfaceBytes = interfaceName.toByteArray(StandardCharsets.UTF_8)
        if (
            interfaceBytes.isEmpty() ||
            interfaceBytes.size > MAX_INTERFACE_NAME_BYTES ||
            String(interfaceBytes, StandardCharsets.UTF_8) != interfaceName
        ) {
            refuse("local network interface name is not bounded canonical UTF-8")
        }
        val addresses = properties.linkAddresses.map { address ->
            val host = address.address.hostAddress
                ?: refuse("local link address is absent")
            "$host/${address.prefixLength}"
        }.sorted()
        val routes = properties.routes.map { route ->
            val destination = route.destination?.toString()
                ?: refuse("local route destination is absent")
            val gateway = route.gateway?.hostAddress ?: NONE
            val routeInterface = route.`interface` ?: NONE
            "$destination|$gateway|$routeInterface"
        }.sorted()
        val dnsServers = properties.dnsServers.map {
            it.hostAddress ?: refuse("local DNS endpoint is absent")
        }.sorted()
        if (
            addresses.isEmpty() ||
            addresses.size > MAX_LINK_ADDRESS_COUNT ||
            routes.isEmpty() ||
            routes.size > MAX_ROUTE_COUNT ||
            dnsServers.size > MAX_DNS_SERVER_COUNT ||
            properties.mtu !in 0..MAX_NETWORK_MTU
        ) {
            refuse("local network endpoint facts are absent or oversized")
        }
        val canonical = buildString {
            append("interface=").append(interfaceName).append('\n')
            append("mtu=").append(properties.mtu).append('\n')
            append("addresses=").append(addresses.joinToString(",")).append('\n')
            append("routes=").append(routes.joinToString(",")).append('\n')
            append("dns=").append(dnsServers.joinToString(",")).append('\n')
            append("domains=").append(properties.domains ?: NONE).append('\n')
            append("private_dns=").append(properties.privateDnsServerName ?: NONE).append('\n')
        }
        return LinkEndpointEvidence(
            interfaceNameUtf8Hex = interfaceBytes.toHex(),
            linkAddressCount = addresses.size,
            routeCount = routes.size,
            dnsServerCount = dnsServers.size,
            mtu = properties.mtu,
            endpointNonceSha256 = nonceSaltedHash(nonce, label, canonical),
        )
    }

    private data class AttestationEvidence(
        val attestationVersion: Int,
        val attestationSecurityLevel: String,
        val keyMintVersion: Int,
        val keyMintSecurityLevel: String,
        val challengeSha256: String,
        val verifiedBootKeySha256: String,
        val verifiedBootHashSha256: String,
        val deviceLocked: Boolean,
        val verifiedBootState: String,
    )

    private data class DerValue(
        val tagClass: Int,
        val constructed: Boolean,
        val tagNumber: Int,
        val contentStart: Int,
        val end: Int,
    )

    private fun parseAttestationExtension(extension: ByteArray): AttestationEvidence {
        val outer = readDerValue(extension, 0, extension.size)
        requireDerTag(outer, DER_CLASS_UNIVERSAL, false, DER_TAG_OCTET_STRING)
        if (outer.end != extension.size) {
            refuse("attestation extension has trailing DER data")
        }
        val descriptionBytes = extension.copyOfRange(outer.contentStart, outer.end)
        val description = readDerValue(descriptionBytes, 0, descriptionBytes.size)
        requireDerTag(description, DER_CLASS_UNIVERSAL, true, DER_TAG_SEQUENCE)
        if (description.end != descriptionBytes.size) {
            refuse("attestation KeyDescription has trailing DER data")
        }
        val fields = derChildren(descriptionBytes, description)
        if (fields.size != KEY_DESCRIPTION_FIELD_COUNT) {
            refuse("attestation KeyDescription is absent or ambiguous")
        }
        val attestationVersion = derInteger(descriptionBytes, fields[0], DER_TAG_INTEGER)
        if (attestationVersion !in SUPPORTED_ATTESTATION_VERSIONS) {
            refuse("persistent key uses an unsupported attestation schema")
        }
        val attestationSecurityLevel = derSecurityLevel(descriptionBytes, fields[1])
        val keyMintVersion = derInteger(descriptionBytes, fields[2], DER_TAG_INTEGER)
        if (keyMintVersion <= 0 || keyMintVersion > MAX_KEYMINT_VERSION) {
            refuse("persistent key uses an unsupported KeyMint version")
        }
        val keyMintSecurityLevel = derSecurityLevel(descriptionBytes, fields[3])
        val challenge = derOctets(descriptionBytes, fields[4])
        if (challenge.size !in MIN_ATTESTATION_CHALLENGE_BYTES..MAX_ATTESTATION_CHALLENGE_BYTES) {
            refuse("persistent key attestation challenge has an invalid size")
        }
        val uniqueId = derOctets(descriptionBytes, fields[5])
        if (uniqueId.size > MAX_ATTESTATION_UNIQUE_ID_BYTES) {
            refuse("persistent key attestation unique ID exceeds its bound")
        }
        requireDerTag(fields[6], DER_CLASS_UNIVERSAL, true, DER_TAG_SEQUENCE)
        requireDerTag(fields[7], DER_CLASS_UNIVERSAL, true, DER_TAG_SEQUENCE)
        if (findContextTags(descriptionBytes, fields[6], ROOT_OF_TRUST_TAG).isNotEmpty()) {
            refuse("root of trust must not be software-enforced")
        }
        val roots = findContextTags(descriptionBytes, fields[7], ROOT_OF_TRUST_TAG)
        if (roots.size != 1) {
            refuse("hardware-enforced root of trust is absent or duplicated")
        }
        val explicitRootChildren = derChildren(descriptionBytes, roots.single())
        if (explicitRootChildren.size != 1) {
            refuse("hardware-enforced root of trust is not canonical DER")
        }
        val root = explicitRootChildren.single()
        requireDerTag(root, DER_CLASS_UNIVERSAL, true, DER_TAG_SEQUENCE)
        val rootFields = derChildren(descriptionBytes, root)
        if (rootFields.size != ROOT_OF_TRUST_FIELD_COUNT) {
            refuse("hardware root of trust lacks current verified-boot evidence")
        }
        val verifiedBootKey = derOctets(descriptionBytes, rootFields[0])
        if (verifiedBootKey.size !in MIN_BOOT_DIGEST_BYTES..MAX_BOOT_DIGEST_BYTES) {
            refuse("verified-boot key digest has an invalid size")
        }
        val deviceLocked = derBoolean(descriptionBytes, rootFields[1])
        val verifiedBootState = derInteger(
            descriptionBytes,
            rootFields[2],
            DER_TAG_ENUMERATED,
        )
        val verifiedBootHash = derOctets(descriptionBytes, rootFields[3])
        if (verifiedBootHash.size !in MIN_BOOT_DIGEST_BYTES..MAX_BOOT_DIGEST_BYTES) {
            refuse("verified-boot hash has an invalid size")
        }
        if (!deviceLocked || verifiedBootState != VERIFIED_BOOT_STATE_VERIFIED) {
            refuse("hardware root of trust does not prove locked green verified boot")
        }
        return AttestationEvidence(
            attestationVersion = attestationVersion,
            attestationSecurityLevel = attestationSecurityLevel,
            keyMintVersion = keyMintVersion,
            keyMintSecurityLevel = keyMintSecurityLevel,
            challengeSha256 = sha256(challenge),
            verifiedBootKeySha256 = sha256(verifiedBootKey),
            verifiedBootHashSha256 = sha256(verifiedBootHash),
            deviceLocked = deviceLocked,
            verifiedBootState = VERIFIED_BOOT_STATE_NAME,
        )
    }

    private fun readDerValue(bytes: ByteArray, offset: Int, limit: Int): DerValue {
        if (offset < 0 || offset >= limit || limit > bytes.size) {
            refuse("DER value is truncated")
        }
        var cursor = offset
        val identifier = bytes[cursor++].toInt() and 0xff
        val tagClass = identifier ushr 6
        val constructed = (identifier and DER_CONSTRUCTED) != 0
        var tagNumber = identifier and DER_LOW_TAG_MASK
        if (tagNumber == DER_LOW_TAG_MASK) {
            tagNumber = 0
            var first = true
            while (true) {
                if (cursor >= limit) refuse("DER high tag number is truncated")
                val octet = bytes[cursor++].toInt() and 0xff
                if (first && (octet and 0x7f) == 0) {
                    refuse("DER high tag number is not minimally encoded")
                }
                if (tagNumber > (MAX_DER_TAG_NUMBER ushr 7)) {
                    refuse("DER tag number exceeds its bound")
                }
                tagNumber = (tagNumber shl 7) or (octet and 0x7f)
                first = false
                if ((octet and 0x80) == 0) break
            }
            if (tagNumber < DER_LOW_TAG_MASK) {
                refuse("DER high tag number uses a noncanonical form")
            }
        }
        if (cursor >= limit) refuse("DER length is truncated")
        val firstLength = bytes[cursor++].toInt() and 0xff
        val length = if ((firstLength and 0x80) == 0) {
            firstLength
        } else {
            val count = firstLength and 0x7f
            if (count == 0 || count > MAX_DER_LENGTH_BYTES || cursor + count > limit) {
                refuse("DER length is indefinite or exceeds its bound")
            }
            if ((bytes[cursor].toInt() and 0xff) == 0) {
                refuse("DER length has a leading zero")
            }
            var value = 0
            repeat(count) {
                if (value > (MAX_DER_VALUE_BYTES ushr 8)) {
                    refuse("DER value length exceeds its bound")
                }
                value = (value shl 8) or (bytes[cursor++].toInt() and 0xff)
            }
            if (value < 0x80) refuse("DER length is not minimally encoded")
            value
        }
        if (length > MAX_DER_VALUE_BYTES || cursor > limit - length) {
            refuse("DER value is truncated or too large")
        }
        return DerValue(tagClass, constructed, tagNumber, cursor, cursor + length)
    }

    private fun derChildren(bytes: ByteArray, parent: DerValue): List<DerValue> {
        if (!parent.constructed) refuse("DER parent is not constructed")
        val children = mutableListOf<DerValue>()
        var cursor = parent.contentStart
        while (cursor < parent.end) {
            if (children.size >= MAX_DER_CHILDREN) refuse("DER parent has too many children")
            val child = readDerValue(bytes, cursor, parent.end)
            children += child
            cursor = child.end
        }
        if (cursor != parent.end) refuse("DER child escaped its parent")
        return children
    }

    private fun findContextTags(
        bytes: ByteArray,
        parent: DerValue,
        tagNumber: Int,
    ): List<DerValue> = derChildren(bytes, parent).filter {
        it.tagClass == DER_CLASS_CONTEXT && it.constructed && it.tagNumber == tagNumber
    }

    private fun derInteger(bytes: ByteArray, value: DerValue, expectedTag: Int): Int {
        requireDerTag(value, DER_CLASS_UNIVERSAL, false, expectedTag)
        val length = value.end - value.contentStart
        if (length !in 1..MAX_DER_INTEGER_BYTES) refuse("DER integer has an invalid size")
        val first = bytes[value.contentStart].toInt() and 0xff
        if ((first and 0x80) != 0) refuse("DER integer must not be negative")
        if (
            length > 1 && first == 0 &&
            (bytes[value.contentStart + 1].toInt() and 0x80) == 0
        ) {
            refuse("DER integer is not minimally encoded")
        }
        var result = 0
        for (index in value.contentStart until value.end) {
            if (result > (Int.MAX_VALUE ushr 8)) refuse("DER integer exceeds Int")
            result = (result shl 8) or (bytes[index].toInt() and 0xff)
        }
        if (result < 0) refuse("DER integer exceeds Int")
        return result
    }

    private fun derBoolean(bytes: ByteArray, value: DerValue): Boolean {
        requireDerTag(value, DER_CLASS_UNIVERSAL, false, DER_TAG_BOOLEAN)
        if (value.end - value.contentStart != 1) refuse("DER boolean has an invalid size")
        return when (bytes[value.contentStart].toInt() and 0xff) {
            0x00 -> false
            0xff -> true
            else -> refuse("DER boolean is not canonical")
        }
    }

    private fun derOctets(bytes: ByteArray, value: DerValue): ByteArray {
        requireDerTag(value, DER_CLASS_UNIVERSAL, false, DER_TAG_OCTET_STRING)
        return bytes.copyOfRange(value.contentStart, value.end)
    }

    private fun derSecurityLevel(bytes: ByteArray, value: DerValue): String =
        when (derInteger(bytes, value, DER_TAG_ENUMERATED)) {
            ATTESTATION_SECURITY_LEVEL_TEE -> "tee"
            ATTESTATION_SECURITY_LEVEL_STRONGBOX -> "strongbox"
            else -> refuse("attestation reports a software or unknown security level")
        }

    private fun requireDerTag(
        value: DerValue,
        tagClass: Int,
        constructed: Boolean,
        tagNumber: Int,
    ) {
        if (
            value.tagClass != tagClass ||
            value.constructed != constructed ||
            value.tagNumber != tagNumber
        ) {
            refuse("DER value has an unexpected tag")
        }
    }

    private fun canonicalReport(
        nonceHex: String,
        transcriptContextSha256: String,
        expectedKeyId: String,
        targetPackage: PackageEvidence,
        testPackage: PackageEvidence,
        keyEvidence: KeyEvidence,
        bootEvidence: BootEvidence,
        displayEvidence: DisplayEvidence,
        runtimeEvidence: RuntimeEvidence,
        nonce: ByteArray,
    ): ByteArray {
        if (
            nonce.size != SESSION_NONCE_BYTES ||
            !MessageDigest.isEqual(nonce, decodeHex(nonceHex)) ||
            transcriptContextSha256.length != SHA256_HEX_CHARS ||
            transcriptContextSha256.any { it !in LOWER_HEX } ||
            targetPackage.packageId != TARGET_PACKAGE_ID ||
            testPackage.packageId != TEST_APK_PACKAGE_ID ||
            targetPackage.baseApk.sha256.length != SHA256_HEX_CHARS ||
            targetPackage.baseApk.sha256.any { it !in LOWER_HEX } ||
            targetPackage.baseApk.bytes !in 1L..MAX_BASE_APK_BYTES ||
            targetPackage.baseApk.bytes != targetPackage.baseApk.identity.size ||
            testPackage.baseApk.sha256.length != SHA256_HEX_CHARS ||
            testPackage.baseApk.sha256.any { it !in LOWER_HEX } ||
            testPackage.baseApk.bytes !in 1L..MAX_BASE_APK_BYTES ||
            testPackage.baseApk.bytes != testPackage.baseApk.identity.size ||
            (
                targetPackage.baseApk.sha256 == testPackage.baseApk.sha256 &&
                    targetPackage.baseApk.bytes == testPackage.baseApk.bytes
                )
        ) {
            refuse("canonical report inputs contradict the fixed semantic schema")
        }
        requireCanonicalNetworkSchema(runtimeEvidence.network, nonce)
        val fields = mutableListOf(
            "schema" to REPORT_SCHEMA,
            "host_session_nonce" to nonceHex,
            "transcript_context_sha256" to transcriptContextSha256,
            "persistent_key_id" to expectedKeyId,
            "target_package_id" to targetPackage.packageId,
            "target_version_name_utf8_hex" to targetPackage.versionNameUtf8Hex,
            "target_version_code" to targetPackage.versionCode.toString(),
            "target_signer_sha256" to targetPackage.signerSha256,
            "target_base_apk_sha256" to targetPackage.baseApk.sha256,
            "target_base_apk_bytes" to targetPackage.baseApk.bytes.toString(),
            "target_installing_package" to targetPackage.installingPackage,
            "target_initiating_package" to targetPackage.initiatingPackage,
            "target_originating_package" to targetPackage.originatingPackage,
            "test_apk_package_id" to testPackage.packageId,
            "test_apk_version_name_utf8_hex" to testPackage.versionNameUtf8Hex,
            "test_apk_version_code" to testPackage.versionCode.toString(),
            "test_apk_signer_sha256" to testPackage.signerSha256,
            "test_apk_sha256" to testPackage.baseApk.sha256,
            "test_apk_bytes" to testPackage.baseApk.bytes.toString(),
            "test_apk_installing_package" to testPackage.installingPackage,
            "test_apk_initiating_package" to testPackage.initiatingPackage,
            "test_apk_originating_package" to testPackage.originatingPackage,
            "key_origin" to KEY_ORIGIN_GENERATED,
            "key_purposes" to KEY_PURPOSES_SIGN,
            "key_digests" to KEY_DIGESTS_SHA256,
            "key_signature_paddings" to KEY_PADDING_RSA_PKCS1,
            "key_security_level" to keyEvidence.securityLevel,
            "key_rsa_modulus_bits" to keyEvidence.modulusBits.toString(),
            "key_rsa_public_exponent" to RSA_PUBLIC_EXPONENT.toString(),
            "attestation_leaf_certificate_sha256" to keyEvidence.leafSha256,
            "attestation_extension_sha256" to keyEvidence.attestationExtensionSha256,
            "attestation_version" to keyEvidence.attestation.attestationVersion.toString(),
            "attestation_security_level" to keyEvidence.attestation.attestationSecurityLevel,
            "keymint_version" to keyEvidence.attestation.keyMintVersion.toString(),
            "keymint_security_level" to keyEvidence.attestation.keyMintSecurityLevel,
            "attestation_challenge_sha256" to keyEvidence.attestation.challengeSha256,
            "attested_verified_boot_key_sha256" to
                keyEvidence.attestation.verifiedBootKeySha256,
            "attested_verified_boot_hash_sha256" to
                keyEvidence.attestation.verifiedBootHashSha256,
            "attested_device_locked" to canonicalBoolean(keyEvidence.attestation.deviceLocked),
            "attested_verified_boot_state" to keyEvidence.attestation.verifiedBootState,
            "current_verified_boot_state" to bootEvidence.verifiedBootState,
            "current_flash_locked" to bootEvidence.flashLocked,
            "current_vbmeta_device_state" to bootEvidence.vbmetaDeviceState,
            "user_device_secure" to canonicalBoolean(bootEvidence.userDeviceSecure),
            "user_unlocked" to canonicalBoolean(bootEvidence.userUnlocked),
            "device_provisioned" to canonicalBoolean(bootEvidence.deviceProvisioned),
            "boot_count" to bootEvidence.bootCount.toString(),
            "android_sdk" to runtimeEvidence.androidSdk.toString(),
            "android_security_patch" to runtimeEvidence.securityPatch,
        )
        fields += runtimeEvidence.buildNonceHashes.map { (label, digest) ->
            "build_${label}_nonce_sha256" to digest
        }
        fields += listOf(
            "display_count" to displayEvidence.displayCount.toString(),
            "display_id" to displayEvidence.displayId.toString(),
            "display_name_nonce_sha256" to displayEvidence.nameNonceSha256,
            "display_flags" to displayEvidence.flags.toString(),
            "display_state" to displayEvidence.state.toString(),
            "display_rotation" to displayEvidence.rotation.toString(),
            "display_mode_id" to displayEvidence.modeId.toString(),
            "display_physical_width_pixels" to displayEvidence.physicalWidthPixels.toString(),
            "display_physical_height_pixels" to displayEvidence.physicalHeightPixels.toString(),
            "display_refresh_millihertz" to displayEvidence.refreshMilliHertz.toString(),
            "display_current_width_pixels" to displayEvidence.currentWidthPixels.toString(),
            "display_current_height_pixels" to displayEvidence.currentHeightPixels.toString(),
            "display_maximum_width_pixels" to displayEvidence.maximumWidthPixels.toString(),
            "display_maximum_height_pixels" to displayEvidence.maximumHeightPixels.toString(),
            "display_density_dpi" to displayEvidence.densityDpi.toString(),
            "runtime_process_name_utf8_hex" to runtimeEvidence.processNameUtf8Hex,
            "runtime_process_id" to runtimeEvidence.processId.toString(),
            "runtime_process_uid" to runtimeEvidence.processUid.toString(),
            "runtime_elapsed_realtime_millis" to runtimeEvidence.elapsedRealtimeMillis.toString(),
            "runtime_uptime_millis" to runtimeEvidence.uptimeMillis.toString(),
            "runtime_wall_clock_millis" to runtimeEvidence.wallClockMillis.toString(),
            "network_count" to runtimeEvidence.network.networkCount.toString(),
            "active_network_handle" to runtimeEvidence.network.activeNetworkHandle.toString(),
            "active_network_transports" to runtimeEvidence.network.activeTransports,
            "active_network_validated" to
                canonicalBoolean(runtimeEvidence.network.activeValidated),
            "active_network_internet" to canonicalBoolean(runtimeEvidence.network.activeInternet),
            "active_interface_name_utf8_hex" to
                runtimeEvidence.network.activeEndpoint.interfaceNameUtf8Hex,
            "active_link_address_count" to
                runtimeEvidence.network.activeEndpoint.linkAddressCount.toString(),
            "active_route_count" to runtimeEvidence.network.activeEndpoint.routeCount.toString(),
            "active_dns_server_count" to
                runtimeEvidence.network.activeEndpoint.dnsServerCount.toString(),
            "active_network_mtu" to runtimeEvidence.network.activeEndpoint.mtu.toString(),
            "active_endpoint_nonce_sha256" to
                runtimeEvidence.network.activeEndpoint.endpointNonceSha256,
            "vpn_present" to canonicalBoolean(runtimeEvidence.network.vpnPresent),
            "vpn_network_handle" to runtimeEvidence.network.vpnNetworkHandle.toString(),
            "vpn_interface_name_utf8_hex" to
                runtimeEvidence.network.vpnEndpoint.interfaceNameUtf8Hex,
            "vpn_link_address_count" to
                runtimeEvidence.network.vpnEndpoint.linkAddressCount.toString(),
            "vpn_route_count" to runtimeEvidence.network.vpnEndpoint.routeCount.toString(),
            "vpn_dns_server_count" to
                runtimeEvidence.network.vpnEndpoint.dnsServerCount.toString(),
            "vpn_network_mtu" to runtimeEvidence.network.vpnEndpoint.mtu.toString(),
            "vpn_endpoint_nonce_sha256" to
                runtimeEvidence.network.vpnEndpoint.endpointNonceSha256,
        )
        if (
            fields.map { it.first } != CANONICAL_REPORT_FIELD_ORDER ||
            fields.map { it.first }.toSet().size != fields.size
        ) {
            refuse("canonical report field order or uniqueness drifted")
        }
        val canonicalText = buildString {
            for ((name, value) in fields) {
                if (!REPORT_FIELD_NAME.matches(name) || !REPORT_FIELD_VALUE.matches(value)) {
                    refuse("canonical report contains a noncanonical field")
                }
                append(name).append('=').append(value).append('\n')
            }
        }
        val bytes = canonicalText.toByteArray(StandardCharsets.US_ASCII)
        if (
            bytes.isEmpty() ||
            bytes.size > MAX_REPORT_BYTES ||
            String(bytes, StandardCharsets.US_ASCII) != canonicalText
        ) {
            refuse("canonical report is absent, non-ASCII, or oversized")
        }
        return bytes
    }

    private fun canonicalBoolean(value: Boolean): String = if (value) "true" else "false"

    private fun nonceSaltedHash(nonce: ByteArray, label: String, value: String): String {
        if (nonce.size != SESSION_NONCE_BYTES || !NONCE_HASH_LABEL.matches(label)) {
            refuse("nonce-salted hash input schema is invalid")
        }
        val labelBytes = label.toByteArray(StandardCharsets.US_ASCII)
        val valueBytes = value.toByteArray(StandardCharsets.UTF_8)
        if (valueBytes.isEmpty() || valueBytes.size > MAX_NONCE_HASH_VALUE_BYTES) {
            refuse("nonce-salted hash value is absent or oversized")
        }
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(NONCE_SALTED_HASH_DOMAIN)
        digest.update(nonce)
        digest.update(0.toByte())
        digest.update(labelBytes)
        digest.update(0.toByte())
        digest.update(valueBytes)
        return digest.digest().toHex()
    }

    private fun sha256(value: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(value).toHex()

    private fun claimSessionNonce(nonceHex: String) {
        synchronized(SEEN_SESSION_NONCES) {
            if (SEEN_SESSION_NONCES.size >= MAX_IN_PROCESS_NONCES) {
                refuse("in-process session nonce ledger is full")
            }
            if (!SEEN_SESSION_NONCES.add(nonceHex)) {
                refuse("host session nonce was already used in this instrumentation process")
            }
        }
    }

    private fun attestedKeyId(publicKey: RSAPublicKey): String {
        val modulusHex = publicKey.modulus.toString(16)
        if (modulusHex.isEmpty() || publicKey.modulus.signum() <= 0) {
            refuse("attested RSA modulus is invalid")
        }
        val canonical = (
            "{\"algorithm\":\"rsa\",\"exponent\":65537," +
                "\"modulus_hex\":\"$modulusHex\"}"
            ).toByteArray(StandardCharsets.US_ASCII)
        return MessageDigest.getInstance("SHA-256").digest(canonical).toHex()
    }

    private fun exactLowerHex(value: String?, length: Int, label: String): String {
        if (value == null || value.length != length || value.any { it !in LOWER_HEX }) {
            refuse("$label must be exactly $length lowercase hexadecimal characters")
        }
        return value
    }

    private fun decodeHex(value: String): ByteArray {
        val result = ByteArray(value.length / 2)
        for (index in result.indices) {
            val offset = index * 2
            result[index] = value.substring(offset, offset + 2).toInt(16).toByte()
        }
        return result
    }

    private fun ByteArray.toHex(): String {
        val result = CharArray(size * 2)
        for (index in indices) {
            val value = this[index].toInt() and 0xff
            result[index * 2] = HEX_ALPHABET[value ushr 4]
            result[index * 2 + 1] = HEX_ALPHABET[value and 0x0f]
        }
        return String(result)
    }

    private fun refuse(message: String): Nothing = throw AssertionError(message)

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
        const val REPORT_SCHEMA = "winsvpn-android-live-hardware-attestation-evidence-v4"
        const val NONCE_ARGUMENT = "winsvpn_attestation_session_nonce"
        const val KEY_ID_ARGUMENT = "winsvpn_attestation_key_id"
        const val TRANSCRIPT_CONTEXT_SHA256_ARGUMENT =
            "winsvpn_attestation_transcript_context_sha256"
        const val RUNNER_CLASS_ARGUMENT = "class"
        const val TEST_CLASS_NAME = "org.winsvpn.devicecheck.LiveHardwareAttestationProofTest"
        const val TARGET_PACKAGE_ID = "org.winsvpn.devicecheck"
        const val TEST_APK_PACKAGE_ID = "org.winsvpn.devicecheck.test"
        const val REPORT_STATUS = "winsvpn_attestation_report_b64"
        const val SIGNATURE_STATUS = "winsvpn_attestation_signature_hex"
        const val KEY_ID_STATUS = "winsvpn_attestation_key_id"
        const val SCHEMA_STATUS = "winsvpn_attestation_schema"
        const val SIGNATURE_ALGORITHM = "SHA256withRSA"
        const val STATUS_IN_PROGRESS = 0
        const val SESSION_NONCE_BYTES = 32
        const val SHA256_HEX_CHARS = 64
        const val MIN_SUPPORTED_API = 31
        const val MAX_REPORT_BYTES = 16 * 1024
        const val MAX_REPORT_BASE64_CHARS = 21_848
        const val MAX_SIGNATURE_HEX_CHARS = 1024
        const val MAX_IN_PROCESS_NONCES = 128
        const val MIN_CERTIFICATE_CHAIN_LENGTH = 2
        const val MAX_CERTIFICATE_CHAIN_LENGTH = 16
        const val MAX_VERSION_NAME_BYTES = 256
        const val MAX_PACKAGE_NAME_CHARS = 255
        const val MAX_SIGNING_CERTIFICATE_BYTES = 64 * 1024
        const val MAX_APK_SOURCE_DIR_BYTES = 4096
        const val MAX_BASE_APK_BYTES = 512L * 1024L * 1024L
        const val APK_READ_BUFFER_BYTES = 64 * 1024
        const val MAX_PROCESS_NAME_BYTES = 256
        const val MAX_BUILD_FACT_BYTES = 2048
        const val MAX_NONCE_HASH_VALUE_BYTES = 16 * 1024
        const val MIN_WALL_CLOCK_MILLIS = 1_577_836_800_000L
        const val MIN_DISPLAY_PIXELS = 240
        const val MAX_DISPLAY_PIXELS = 16_384
        const val MIN_REFRESH_MILLIHERTZ = 10_000
        const val MAX_REFRESH_MILLIHERTZ = 1_000_000
        const val MIN_DENSITY_DPI = 72
        const val MAX_DENSITY_DPI = 2_000
        const val MIN_DISPLAY_ROTATION = 0
        const val MAX_DISPLAY_ROTATION = 3
        const val MAX_NETWORK_COUNT = 32
        const val MAX_LINK_ADDRESS_COUNT = 64
        const val MAX_ROUTE_COUNT = 256
        const val MAX_DNS_SERVER_COUNT = 32
        const val MAX_NETWORK_MTU = 65_535
        const val MAX_INTERFACE_NAME_BYTES = 128
        const val NO_NETWORK_HANDLE = 0L
        const val NONE = "none"
        const val NONE_UTF8_HEX = "6e6f6e65"

        const val KEY_ORIGIN_GENERATED = "generated"
        const val KEY_PURPOSES_SIGN = "sign"
        const val KEY_DIGESTS_SHA256 = "sha256"
        const val KEY_PADDING_RSA_PKCS1 = "rsa-pkcs1-v1_5-sign"

        const val VERIFIED_BOOT_STATE_PROPERTY = "ro.boot.verifiedbootstate"
        const val FLASH_LOCKED_PROPERTY = "ro.boot.flash.locked"
        const val VBMETA_DEVICE_STATE_PROPERTY = "ro.boot.vbmeta.device_state"
        const val VERIFIED_BOOT_STATE_NAME = "green"
        const val FLASH_LOCKED_VALUE = "1"
        const val VBMETA_LOCKED_VALUE = "locked"
        const val GETPROP_PATH = "/system/bin/getprop"
        const val MAX_SYSTEM_PROPERTY_OUTPUT_BYTES = 256
        const val MAX_SYSTEM_PROPERTY_VALUE_CHARS = 128

        const val DER_CLASS_UNIVERSAL = 0
        const val DER_CLASS_CONTEXT = 2
        const val DER_CONSTRUCTED = 0x20
        const val DER_LOW_TAG_MASK = 0x1f
        const val DER_TAG_BOOLEAN = 1
        const val DER_TAG_INTEGER = 2
        const val DER_TAG_OCTET_STRING = 4
        const val DER_TAG_ENUMERATED = 10
        const val DER_TAG_SEQUENCE = 16
        const val ROOT_OF_TRUST_TAG = 704
        const val KEY_DESCRIPTION_FIELD_COUNT = 8
        const val ROOT_OF_TRUST_FIELD_COUNT = 4
        const val VERIFIED_BOOT_STATE_VERIFIED = 0
        const val ATTESTATION_SECURITY_LEVEL_TEE = 1
        const val ATTESTATION_SECURITY_LEVEL_STRONGBOX = 2
        const val MAX_KEYMINT_VERSION = 500
        const val MIN_ATTESTATION_CHALLENGE_BYTES = 16
        const val MAX_ATTESTATION_CHALLENGE_BYTES = 128
        const val MAX_ATTESTATION_UNIQUE_ID_BYTES = 64
        const val MIN_BOOT_DIGEST_BYTES = 16
        const val MAX_BOOT_DIGEST_BYTES = 128
        const val MAX_DER_TAG_NUMBER = 4096
        const val MAX_DER_LENGTH_BYTES = 4
        const val MAX_DER_VALUE_BYTES = 64 * 1024
        const val MAX_DER_CHILDREN = 256
        const val MAX_DER_INTEGER_BYTES = 4

        const val HEX_ALPHABET = "0123456789abcdef"
        val RSA_PUBLIC_EXPONENT: BigInteger = BigInteger.valueOf(65537L)
        val RSA_MODULUS_BITS: Set<Int> = setOf(2048, 3072, 4096)
        val LOWER_HEX: Set<Char> = HEX_ALPHABET.toSet()
        val SUPPORTED_ATTESTATION_VERSIONS: Set<Int> = setOf(3, 4, 100, 200, 300, 400, 500)
        val ALLOWED_ARGUMENTS: Set<String> =
            setOf(
                RUNNER_CLASS_ARGUMENT,
                NONCE_ARGUMENT,
                KEY_ID_ARGUMENT,
                TRANSCRIPT_CONTEXT_SHA256_ARGUMENT,
            )
        val STATUS_KEYS: Set<String> =
            setOf(REPORT_STATUS, SIGNATURE_STATUS, KEY_ID_STATUS, SCHEMA_STATUS)
        val ALLOWED_SYSTEM_PROPERTIES: Set<String> = setOf(
            VERIFIED_BOOT_STATE_PROPERTY,
            FLASH_LOCKED_PROPERTY,
            VBMETA_DEVICE_STATE_PROPERTY,
        )
        val ASCII_PRINTABLE_OR_NEWLINE: Set<Int> = (0x20..0x7e).toSet() + 0x0a
        val PACKAGE_NAME = Regex("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+")
        val SECURITY_PATCH = Regex("20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])")
        val REPORT_FIELD_NAME = Regex("[a-z][a-z0-9_]{0,95}")
        val REPORT_FIELD_VALUE = Regex("[A-Za-z0-9._,:+\\-]{1,2048}")
        val NONCE_HASH_LABEL = Regex("[a-z][a-z0-9_]{0,63}")

        val SIGNATURE_DOMAIN: ByteArray =
            "WINSVPN-ANDROID-LIVE-HARDWARE-ATTESTATION-EVIDENCE-V4\u0000"
                .toByteArray(StandardCharsets.US_ASCII)
        val NONCE_SALTED_HASH_DOMAIN: ByteArray =
            "WINSVPN-ANDROID-ATTESTATION-NONCE-SALTED-HASH-V2\u0000"
                .toByteArray(StandardCharsets.US_ASCII)
        val SEEN_SESSION_NONCES: MutableSet<String> = mutableSetOf()

        val BUILD_HASH_LABELS: List<String> = listOf(
            "board",
            "bootloader",
            "brand",
            "device",
            "display",
            "fingerprint",
            "hardware",
            "host",
            "id",
            "manufacturer",
            "model",
            "product",
            "soc_manufacturer",
            "soc_model",
            "supported_abis",
            "tags",
            "type",
            "user",
            "version_incremental",
            "version_release",
        )
        val NETWORK_TRANSPORTS: List<Pair<String, Int>> = listOf(
            "cellular" to NetworkCapabilities.TRANSPORT_CELLULAR,
            "wifi" to NetworkCapabilities.TRANSPORT_WIFI,
            "bluetooth" to NetworkCapabilities.TRANSPORT_BLUETOOTH,
            "ethernet" to NetworkCapabilities.TRANSPORT_ETHERNET,
            "vpn" to NetworkCapabilities.TRANSPORT_VPN,
            "wifi_aware" to NetworkCapabilities.TRANSPORT_WIFI_AWARE,
            "lowpan" to NetworkCapabilities.TRANSPORT_LOWPAN,
        )
        val CANONICAL_REPORT_FIELD_ORDER: List<String> = listOf(
            "schema",
            "host_session_nonce",
            "transcript_context_sha256",
            "persistent_key_id",
            "target_package_id",
            "target_version_name_utf8_hex",
            "target_version_code",
            "target_signer_sha256",
            "target_base_apk_sha256",
            "target_base_apk_bytes",
            "target_installing_package",
            "target_initiating_package",
            "target_originating_package",
            "test_apk_package_id",
            "test_apk_version_name_utf8_hex",
            "test_apk_version_code",
            "test_apk_signer_sha256",
            "test_apk_sha256",
            "test_apk_bytes",
            "test_apk_installing_package",
            "test_apk_initiating_package",
            "test_apk_originating_package",
            "key_origin",
            "key_purposes",
            "key_digests",
            "key_signature_paddings",
            "key_security_level",
            "key_rsa_modulus_bits",
            "key_rsa_public_exponent",
            "attestation_leaf_certificate_sha256",
            "attestation_extension_sha256",
            "attestation_version",
            "attestation_security_level",
            "keymint_version",
            "keymint_security_level",
            "attestation_challenge_sha256",
            "attested_verified_boot_key_sha256",
            "attested_verified_boot_hash_sha256",
            "attested_device_locked",
            "attested_verified_boot_state",
            "current_verified_boot_state",
            "current_flash_locked",
            "current_vbmeta_device_state",
            "user_device_secure",
            "user_unlocked",
            "device_provisioned",
            "boot_count",
            "android_sdk",
            "android_security_patch",
        ) + BUILD_HASH_LABELS.map { "build_${it}_nonce_sha256" } + listOf(
            "display_count",
            "display_id",
            "display_name_nonce_sha256",
            "display_flags",
            "display_state",
            "display_rotation",
            "display_mode_id",
            "display_physical_width_pixels",
            "display_physical_height_pixels",
            "display_refresh_millihertz",
            "display_current_width_pixels",
            "display_current_height_pixels",
            "display_maximum_width_pixels",
            "display_maximum_height_pixels",
            "display_density_dpi",
            "runtime_process_name_utf8_hex",
            "runtime_process_id",
            "runtime_process_uid",
            "runtime_elapsed_realtime_millis",
            "runtime_uptime_millis",
            "runtime_wall_clock_millis",
            "network_count",
            "active_network_handle",
            "active_network_transports",
            "active_network_validated",
            "active_network_internet",
            "active_interface_name_utf8_hex",
            "active_link_address_count",
            "active_route_count",
            "active_dns_server_count",
            "active_network_mtu",
            "active_endpoint_nonce_sha256",
            "vpn_present",
            "vpn_network_handle",
            "vpn_interface_name_utf8_hex",
            "vpn_link_address_count",
            "vpn_route_count",
            "vpn_dns_server_count",
            "vpn_network_mtu",
            "vpn_endpoint_nonce_sha256",
        )
    }
}
