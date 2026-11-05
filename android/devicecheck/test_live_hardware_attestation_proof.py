#!/usr/bin/env python3
"""Source-only custody tests for the live hardware-attestation proof class."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import stat
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(os.path.abspath(__file__)).parents[2]
SOURCE = (
    ROOT
    / "android/devicecheck/app/src/androidTest/kotlin/org/winsvpn/devicecheck"
    / "LiveHardwareAttestationProofTest.kt"
)

MAX_SOURCE_BYTES = 512 * 1024
OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd
LSTAT_SUPPORTS_DIR_FD = os.lstat in os.supports_dir_fd
EXPECTED_SCHEMA = "winsvpn-android-live-hardware-attestation-evidence-v4"
EXPECTED_SIGNATURE_DOMAIN = (
    "WINSVPN-ANDROID-LIVE-HARDWARE-ATTESTATION-EVIDENCE-V4\\u0000"
)
EXPECTED_NONCE_HASH_DOMAIN = (
    "WINSVPN-ANDROID-ATTESTATION-NONCE-SALTED-HASH-V2\\u0000"
)
EXPECTED_STATUS_KEYS = (
    "REPORT_STATUS",
    "SIGNATURE_STATUS",
    "KEY_ID_STATUS",
    "SCHEMA_STATUS",
)
EXPECTED_BUILD_LABELS = (
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
EXPECTED_REPORT_PREFIX = (
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
)
EXPECTED_REPORT_SUFFIX = (
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
EXPECTED_REPORT_FIELDS = (
    EXPECTED_REPORT_PREFIX
    + tuple(f"build_{label}_nonce_sha256" for label in EXPECTED_BUILD_LABELS)
    + EXPECTED_REPORT_SUFFIX
)


def _custody_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _source_components(
    path: pathlib.Path,
    repository_root: pathlib.Path,
) -> tuple[str, ...]:
    root_parts = pathlib.PurePath(os.fspath(repository_root)).parts
    path_parts = pathlib.PurePath(os.fspath(path)).parts
    if not root_parts or not path_parts or root_parts[0] != os.sep:
        raise AssertionError("live-attestation source paths must be absolute")
    if path_parts[: len(root_parts)] != root_parts:
        raise AssertionError("live-attestation source escapes its repository root")
    components = path_parts[len(root_parts) :]
    if not components or any(component in (os.curdir, os.pardir) for component in components):
        raise AssertionError("live-attestation source path is not canonical")
    return components


def _require_directory(metadata: os.stat_result) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise AssertionError("live-attestation source ancestor is not a directory")


def _require_source_file(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size not in range(1, MAX_SOURCE_BYTES + 1)
    ):
        raise AssertionError(
            "live-attestation source is not one bounded, single-link regular file"
        )


def read_authenticated_source(
    path: pathlib.Path,
    *,
    repository_root: pathlib.Path = ROOT,
) -> tuple[str, str]:
    """Read one source snapshot through a symlink-refusing descriptor walk."""
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or not OPEN_SUPPORTS_DIR_FD
        or not LSTAT_SUPPORTS_DIR_FD
    ):
        raise AssertionError("descriptor-relative no-follow source reads are unavailable")
    components = _source_components(path, repository_root)
    nofollow = os.O_NOFOLLOW
    common_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
    directory_flags = common_flags | os.O_DIRECTORY
    root_path = os.fspath(repository_root)
    root_path_before = os.lstat(root_path)
    _require_directory(root_path_before)
    descriptors: list[int] = []
    directory_bindings: list[tuple[int, str, int, os.stat_result]] = []
    try:
        root_descriptor = os.open(root_path, directory_flags)
        descriptors.append(root_descriptor)
        root_before = os.fstat(root_descriptor)
        _require_directory(root_before)
        if _custody_identity(root_path_before) != _custody_identity(root_before):
            raise AssertionError(
                "live-attestation repository root path and descriptor differ"
            )

        parent_descriptor = root_descriptor
        for component in components[:-1]:
            path_before = os.lstat(component, dir_fd=parent_descriptor)
            _require_directory(path_before)
            child_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=parent_descriptor,
            )
            descriptors.append(child_descriptor)
            descriptor_before = os.fstat(child_descriptor)
            _require_directory(descriptor_before)
            if _custody_identity(path_before) != _custody_identity(descriptor_before):
                raise AssertionError(
                    "live-attestation source ancestor path and descriptor differ"
                )
            directory_bindings.append(
                (
                    parent_descriptor,
                    component,
                    child_descriptor,
                    descriptor_before,
                )
            )
            parent_descriptor = child_descriptor

        source_name = components[-1]
        source_path_before = os.lstat(source_name, dir_fd=parent_descriptor)
        _require_source_file(source_path_before)
        source_descriptor = os.open(
            source_name,
            common_flags,
            dir_fd=parent_descriptor,
        )
        descriptors.append(source_descriptor)
        source_before = os.fstat(source_descriptor)
        _require_source_file(source_before)
        if _custody_identity(source_path_before) != _custody_identity(source_before):
            raise AssertionError(
                "live-attestation source path and descriptor identities differ"
            )

        chunks: list[bytes] = []
        size = 0
        while size < source_before.st_size:
            chunk = os.read(
                source_descriptor,
                min(64 * 1024, source_before.st_size - size),
            )
            if not chunk:
                raise AssertionError(
                    "live-attestation source was truncated during authenticated read"
                )
            chunks.append(chunk)
            size += len(chunk)
        if os.read(source_descriptor, 1):
            raise AssertionError("live-attestation source grew during authenticated read")

        source_after = os.fstat(source_descriptor)
        source_path_after = os.lstat(source_name, dir_fd=parent_descriptor)
        if (
            _custody_identity(source_after) != _custody_identity(source_before)
            or _custody_identity(source_path_after) != _custody_identity(source_before)
            or size != source_before.st_size
        ):
            raise AssertionError("live-attestation source changed during authenticated read")

        for (
            bound_parent,
            component,
            child_descriptor,
            descriptor_before,
        ) in reversed(directory_bindings):
            path_after = os.lstat(component, dir_fd=bound_parent)
            descriptor_after = os.fstat(child_descriptor)
            if (
                _custody_identity(path_after) != _custody_identity(descriptor_before)
                or _custody_identity(descriptor_after)
                != _custody_identity(descriptor_before)
            ):
                raise AssertionError(
                    "live-attestation source ancestor changed during authenticated read"
                )

        root_path_after = os.lstat(root_path)
        root_after = os.fstat(root_descriptor)
        if (
            _custody_identity(root_path_after) != _custody_identity(root_before)
            or _custody_identity(root_after) != _custody_identity(root_before)
        ):
            raise AssertionError(
                "live-attestation repository root changed during authenticated read"
            )
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    raw = b"".join(chunks)
    if b"\x00" in raw:
        raise AssertionError("live-attestation source contains a NUL byte")
    return raw.decode("utf-8"), hashlib.sha256(raw).hexdigest()


def _between(source: str, start: str, end: str) -> str:
    start_at = source.find(start)
    if start_at < 0:
        raise AssertionError(f"missing source-contract boundary: {start}")
    end_at = source.find(end, start_at + len(start))
    if end_at < 0:
        raise AssertionError(f"missing source-contract boundary: {end}")
    return source[start_at:end_at]


def _literal_list(block: str) -> tuple[str, ...]:
    return tuple(
        re.findall(r'^\s*"([a-z][a-z0-9_]*)",\s*$', block, flags=re.MULTILINE)
    )


def _constant_list(block: str) -> tuple[str, ...]:
    return tuple(
        re.findall(r"^\s*([A-Z][A-Z0-9_]+),\s*$", block, flags=re.MULTILINE)
    )


def _report_pairs(block: str) -> tuple[str, ...]:
    return tuple(
        re.findall(
            r'^\s*"([a-z][a-z0-9_]*)"\s+to(?:\s|$)',
            block,
            flags=re.MULTILINE,
        )
    )


def validate_source_contract(source: str) -> None:
    required = (
        "class LiveHardwareAttestationProofTest",
        'REPORT_SCHEMA = "winsvpn-android-live-hardware-attestation-evidence-v4"',
        'NONCE_ARGUMENT = "winsvpn_attestation_session_nonce"',
        'KEY_ID_ARGUMENT = "winsvpn_attestation_key_id"',
        'TRANSCRIPT_CONTEXT_SHA256_ARGUMENT =',
        '"winsvpn_attestation_transcript_context_sha256"',
        'RUNNER_CLASS_ARGUMENT = "class"',
        'TARGET_PACKAGE_ID = "org.winsvpn.devicecheck"',
        'TEST_APK_PACKAGE_ID = "org.winsvpn.devicecheck.test"',
        "arguments.keySet() != ALLOWED_ARGUMENTS",
        "arguments.getString(NONCE_ARGUMENT)",
        "arguments.getString(KEY_ID_ARGUMENT)",
        "arguments.getString(TRANSCRIPT_CONTEXT_SHA256_ARGUMENT)",
        "val transcriptContextSha256 = exactLowerHex(",
        '"attestation transcript-context SHA-256"',
        "exactLowerHex(",
        "claimSessionNonce(nonceHex)",
        "nonce.all { it == 0.toByte() }",
        "Build.VERSION.SDK_INT < MIN_SUPPORTED_API",
        "val targetContext = instrumentation.targetContext",
        "val testContext = instrumentation.context",
        "targetContext.packageName != TARGET_PACKAGE_ID",
        "testContext.packageName != TEST_APK_PACKAGE_ID",
        "targetContext.applicationInfo",
        "testContext.applicationInfo",
        "val targetPackage = installedPackageEvidence(",
        "val testPackage = installedPackageEvidence(",
        "requireDistinctBaseApks(targetPackage, testPackage)",
        "val before = installedPackageMetadata(",
        "val after = installedPackageMetadata(",
        "after != before",
        "info.applicationInfo",
        "!info.splitNames.isNullOrEmpty()",
        "!applicationInfo.splitNames.isNullOrEmpty()",
        "!applicationInfo.splitSourceDirs.isNullOrEmpty()",
        "!applicationInfo.splitPublicSourceDirs.isNullOrEmpty()",
        "sourceDir != publicSourceDir",
        "sourceFile.canonicalPath",
        "sourceFile.absolutePath != sourceDir",
        "canonicalPath != sourceDir",
        "Os.lstat(sourceDir)",
        "Os.open(",
        "OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW",
        "val before = Os.fstat(descriptor)",
        "val after = Os.fstat(descriptor)",
        "!OsConstants.S_ISREG(stat.st_mode)",
        "stat.st_nlink != 1L",
        "stat.st_size !in 1L..MAX_BASE_APK_BYTES",
        "while (bytesRead < before.st_size)",
        "if (count <= 0)",
        "val trailing = Os.read(descriptor, buffer, 0, 1)",
        "bytesRead != before.st_size",
        "identityAfter != identityBefore",
        "pathIdentityAfter != identityAfter",
        "canonicalPathAfter != canonicalPathBefore",
        "Os.close(descriptor)",
        "targetApk.canonicalPath == testApk.canonicalPath",
        "targetApk.identity.device == testApk.identity.device",
        "targetApk.identity.inode == testApk.identity.inode",
        '"target_base_apk_sha256" to targetPackage.baseApk.sha256',
        '"target_base_apk_bytes" to targetPackage.baseApk.bytes.toString()',
        '"test_apk_sha256" to testPackage.baseApk.sha256',
        '"test_apk_bytes" to testPackage.baseApk.bytes.toString()',
        "targetPackage.baseApk.bytes != targetPackage.baseApk.identity.size",
        "testPackage.baseApk.bytes != testPackage.baseApk.identity.size",
        "signingInfo.hasMultipleSigners()",
        "signers.size != 1",
        "history.size != 1",
        "PackageManager.GET_SIGNING_CERTIFICATES",
        "packageManager.getInstallSourceInfo(expectedPackageId)",
        'KeyStore.getInstance(ANDROID_KEYSTORE)',
        "keyStore.aliases()",
        "uniqueAliases.add(alias)",
        "KeyStore.PrivateKeyEntry::class.java",
        "aliases.sorted()",
        "matches.size != 1",
        "leaf.getExtensionValue(ATTESTATION_OID)",
        "extensionHolders.size != 1",
        "leaf.publicKey as? RSAPublicKey",
        "publicKey.publicExponent != RSA_PUBLIC_EXPONENT",
        "publicKey.modulus.bitLength() !in RSA_MODULUS_BITS",
        "!publicKey.modulus.testBit(0)",
        'privateKey.algorithm.equals("RSA"',
        "KeyFactory.getInstance(\"RSA\", ANDROID_KEYSTORE)",
        "keyInfo.origin != KeyProperties.ORIGIN_GENERATED",
        "keyInfo.purposes != KeyProperties.PURPOSE_SIGN",
        "keyInfo.digests.size != 1",
        "keyInfo.digests.single() != KeyProperties.DIGEST_SHA256",
        "keyInfo.signaturePaddings.size != 1",
        "KeyProperties.SIGNATURE_PADDING_RSA_PKCS1",
        "KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT",
        "KeyProperties.SECURITY_LEVEL_STRONGBOX",
        'else -> refuse("owner-authorized key is software-backed or has unknown security")',
        "parseAttestationExtension(attestationExtension)",
        "ROOT_OF_TRUST_TAG = 704",
        "roots.size != 1",
        "!deviceLocked || verifiedBootState != VERIFIED_BOOT_STATE_VERIFIED",
        "currentBootEvidence(targetContext, keyEvidence.attestation)",
        'VERIFIED_BOOT_STATE_PROPERTY = "ro.boot.verifiedbootstate"',
        'FLASH_LOCKED_PROPERTY = "ro.boot.flash.locked"',
        'VBMETA_DEVICE_STATE_PROPERTY = "ro.boot.vbmeta.device_state"',
        "keyguardManager.isDeviceSecure",
        "userManager.isUserUnlocked",
        "Settings.Global.BOOT_COUNT",
        "val displayEvidence = displayEvidence(targetContext, nonce)",
        "displays.size != 1",
        "display.state != Display.STATE_ON",
        "val runtimeEvidence = localRuntimeEvidence(targetContext, nonce)",
        "Application.getProcessName()",
        "buildFacts.map { it.first } != BUILD_HASH_LABELS",
        "nonceSaltedHash(nonce, \"build_$label\", value)",
        "val connectivity = context.getSystemService(ConnectivityManager::class.java)",
        "local active network runtime is unavailable",
        "activeNetworkHandle",
        "vpnHandles.size > 1",
        "VPN runtime endpoint is not the active tested endpoint",
        "requireCanonicalNetworkSchema(runtimeEvidence.network, nonce)",
        "active network evidence contradicts the canonical report schema",
        "present VPN evidence contradicts the canonical report schema",
        "absent VPN evidence contradicts the canonical report schema",
        "transports != allowedTransports.filter { it in transports }",
        "network.networkCount < 2",
        "network.vpnNetworkHandle != network.activeNetworkHandle",
        "vpnEndpoint.interfaceNameUtf8Hex != activeEndpoint.interfaceNameUtf8Hex",
        "vpnEndpoint.endpointNonceSha256 == activeEndpoint.endpointNonceSha256",
        "network.vpnNetworkHandle != NO_NETWORK_HANDLE",
        "vpnEndpoint.interfaceNameUtf8Hex != NONE_UTF8_HEX",
        "vpnEndpoint.endpointNonceSha256 != absentVpnEndpointSha256",
        "fields.map { it.first } != CANONICAL_REPORT_FIELD_ORDER",
        "fields.map { it.first }.toSet().size != fields.size",
        "append(name).append('=').append(value).append('\\n')",
        "StandardCharsets.US_ASCII",
        '"WINSVPN-ANDROID-ATTESTATION-NONCE-SALTED-HASH-V2\\u0000"',
        'SIGNATURE_ALGORITHM = "SHA256withRSA"',
        "val report = canonicalReport(",
        "signer.initSign(keyEvidence.privateKey)",
        "Base64.encodeToString(report, Base64.NO_WRAP)",
        "reportBase64.length > MAX_REPORT_BASE64_CHARS",
        "signatureHex.length > MAX_SIGNATURE_HEX_CHARS",
        "putString(REPORT_STATUS, reportBase64)",
        "putString(SIGNATURE_STATUS, signatureHex)",
        "putString(KEY_ID_STATUS, expectedKeyId)",
        "putString(SCHEMA_STATUS, REPORT_SCHEMA)",
        "status.keySet() != STATUS_KEYS",
        "instrumentation.sendStatus(STATUS_IN_PROGRESS, status)",
        "INSTRUMENTATION_CODE: -1",
    )
    for needle in required:
        if needle not in source:
            raise AssertionError(f"missing live-attestation contract: {needle}")

    forbidden = (
        '"winsvpn_attestation_challenge_sha256"',
        "challengeHex",
        "signer.update(challenge)",
        "KeyPairGenerator",
        "KeyGenerator",
        "KeyGenParameterSpec",
        "generateKey",
        "generateKeyPair",
        "deleteEntry",
        "setEntry",
        "privateKey.encoded",
        "instrumentation.finish(",
    )
    for needle in forbidden:
        if needle in source:
            raise AssertionError(f"forbidden live-attestation operation: {needle}")

    main = _between(
        source,
        "fun provePossessionOfOwnerAttestedKey()",
        "private fun matchingAttestedKeys(",
    )
    argument_reads = tuple(re.findall(r"arguments\.getString\(([^)]+)\)", main))
    if argument_reads != (
        "RUNNER_CLASS_ARGUMENT",
        "NONCE_ARGUMENT",
        "KEY_ID_ARGUMENT",
        "TRANSCRIPT_CONTEXT_SHA256_ARGUMENT",
    ):
        raise AssertionError("caller argument surface is not exact")
    if len(re.findall(r"\barguments\b", main)) != 6:
        raise AssertionError("caller arguments are aliased or read outside the exact surface")
    if source.count("InstrumentationRegistry.getArguments()") != 1:
        raise AssertionError("instrumentation arguments must have one local authority")
    allowed_arguments = _between(
        source,
        "val ALLOWED_ARGUMENTS: Set<String>",
        "val STATUS_KEYS:",
    )
    if _constant_list(allowed_arguments) != (
        "RUNNER_CLASS_ARGUMENT",
        "NONCE_ARGUMENT",
        "KEY_ID_ARGUMENT",
        "TRANSCRIPT_CONTEXT_SHA256_ARGUMENT",
    ):
        raise AssertionError("allowed instrumentation argument authority drifted")
    transcript_parse = (
        "val transcriptContextSha256 = exactLowerHex(\n"
        "            arguments.getString(TRANSCRIPT_CONTEXT_SHA256_ARGUMENT),\n"
        "            64,\n"
        '            "attestation transcript-context SHA-256",\n'
        "        )"
    )
    if main.count(transcript_parse) != 1:
        raise AssertionError("transcript SHA-256 parser is not exact")
    if (
        "if (value == null || value.length != length || "
        "value.any { it !in LOWER_HEX })"
        not in source
    ):
        raise AssertionError("lowercase hexadecimal parser semantics drifted")
    signer_updates = tuple(re.findall(r"signer\.update\(([^)]+)\)", main))
    if signer_updates != ("SIGNATURE_DOMAIN", "nonce", "report"):
        raise AssertionError("signature preimage is not exact domain || nonce || report")
    if not (
        main.index("val report = canonicalReport(")
        < main.index("val signer = Signature.getInstance(SIGNATURE_ALGORITHM)")
        < main.index("signer.initSign(keyEvidence.privateKey)")
    ):
        raise AssertionError("local report must be complete before exact-key signing")

    status_block = _between(main, "val status = Bundle().apply {", "if (status.keySet()")
    status_puts = tuple(re.findall(r"putString\(([^,]+),", status_block))
    if status_puts != EXPECTED_STATUS_KEYS:
        raise AssertionError("custom instrumentation status fields drifted")

    canonical = _between(source, "private fun canonicalReport(", "private fun canonicalBoolean(")
    if _report_pairs(canonical) != EXPECTED_REPORT_PREFIX + EXPECTED_REPORT_SUFFIX:
        raise AssertionError("canonical report construction fields or order drifted")
    fixed_fields = _between(
        canonical,
        "val fields = mutableListOf(",
        "fields += runtimeEvidence.buildNonceHashes",
    )
    exact_new_bindings = (
        '"transcript_context_sha256" to transcriptContextSha256,',
        '"target_base_apk_sha256" to targetPackage.baseApk.sha256,',
        '"target_base_apk_bytes" to targetPackage.baseApk.bytes.toString(),',
        '"test_apk_sha256" to testPackage.baseApk.sha256,',
        '"test_apk_bytes" to testPackage.baseApk.bytes.toString(),',
    )
    for binding in exact_new_bindings:
        if fixed_fields.count(binding) != 1:
            raise AssertionError(f"new local report binding drifted: {binding}")
    caller_values = tuple(
        re.findall(
            r"\b(nonceHex|transcriptContextSha256|expectedKeyId)\b",
            fixed_fields,
        )
    )
    if caller_values != ("nonceHex", "transcriptContextSha256", "expectedKeyId"):
        raise AssertionError("caller values escaped their three fixed report bindings")
    if "arguments" in canonical or "Bundle" in canonical:
        raise AssertionError("canonical report accepts caller-authored semantic state")
    if canonical.count("requireCanonicalNetworkSchema(runtimeEvidence.network, nonce)") != 1:
        raise AssertionError("canonical report does not enforce one local network schema")

    network_schema = _between(
        source,
        "private fun requireCanonicalNetworkSchema(",
        "private fun canonicalTransports(",
    )
    network_schema_conditions = (
        "transports.toSet().size != transports.size",
        "transports != allowedTransports.filter { it in transports }",
        "network.networkCount !in 1..MAX_NETWORK_COUNT",
        "network.activeNetworkHandle <= NO_NETWORK_HANDLE",
        "!network.activeValidated",
        "!network.activeInternet",
        'val vpnTransportPresent = "vpn" in transports',
        "!vpnTransportPresent ||",
        "network.networkCount < 2",
        "network.vpnNetworkHandle != network.activeNetworkHandle",
        "vpnEndpoint.interfaceNameUtf8Hex != activeEndpoint.interfaceNameUtf8Hex",
        "vpnEndpoint.linkAddressCount != activeEndpoint.linkAddressCount",
        "vpnEndpoint.routeCount != activeEndpoint.routeCount",
        "vpnEndpoint.dnsServerCount != activeEndpoint.dnsServerCount",
        "vpnEndpoint.mtu != activeEndpoint.mtu",
        "vpnEndpoint.endpointNonceSha256 == activeEndpoint.endpointNonceSha256",
        "} else if (\n            vpnTransportPresent ||",
        "network.vpnNetworkHandle != NO_NETWORK_HANDLE",
        "vpnEndpoint.interfaceNameUtf8Hex != NONE_UTF8_HEX",
        "vpnEndpoint.linkAddressCount != 0",
        "vpnEndpoint.routeCount != 0",
        "vpnEndpoint.dnsServerCount != 0",
        "vpnEndpoint.mtu != 0",
        "vpnEndpoint.endpointNonceSha256 != absentVpnEndpointSha256",
    )
    for condition in network_schema_conditions:
        if network_schema.count(condition) != 1:
            raise AssertionError(f"network/VPN schema condition drifted: {condition}")
    if "arguments" in network_schema or "Bundle" in network_schema:
        raise AssertionError("network/VPN schema accepts caller-authored semantic state")

    apk_reader = _between(
        source,
        "private fun installedBaseApkEvidence(",
        "private fun requireBoundedRegularBaseApk(",
    )
    ordered_apk_steps = (
        "val canonicalPathBefore = canonicalBaseApkPath(sourceDir)",
        "val pathBefore = try",
        "Os.lstat(sourceDir)",
        "val descriptor = try",
        "Os.open(",
        "val before = Os.fstat(descriptor)",
        "while (bytesRead < before.st_size)",
        "val trailing = Os.read(descriptor, buffer, 0, 1)",
        "val after = Os.fstat(descriptor)",
        "val pathAfter = try",
        "val canonicalPathAfter = canonicalBaseApkPath(sourceDir)",
        "return InstalledBaseApkEvidence(",
    )
    positions = tuple(apk_reader.find(step) for step in ordered_apk_steps)
    if any(position < 0 for position in positions) or positions != tuple(
        sorted(positions)
    ):
        raise AssertionError("descriptor-bound APK measurement order drifted")
    if apk_reader.count("Os.fstat(descriptor)") != 2:
        raise AssertionError("APK descriptor must retain before and after fstat identity")
    if apk_reader.count("Os.lstat(sourceDir)") != 2:
        raise AssertionError("APK path must retain before and after lstat identity")
    if apk_reader.count("canonicalBaseApkPath(sourceDir)") != 2:
        raise AssertionError("APK sourceDir must retain before and after canonical identity")
    fail_closed_conditions = (
        (
            "!applicationInfo.splitNames.isNullOrEmpty() ||\n"
            "            !applicationInfo.splitSourceDirs.isNullOrEmpty() ||\n"
            "            !applicationInfo.splitPublicSourceDirs.isNullOrEmpty()"
        ),
        (
            "!OsConstants.S_ISREG(stat.st_mode) ||\n"
            "            stat.st_nlink != 1L ||\n"
            "            stat.st_size !in 1L..MAX_BASE_APK_BYTES"
        ),
        (
            "pathIdentityAfter != identityAfter ||\n"
            "                canonicalPathAfter != canonicalPathBefore"
        ),
        (
            "targetApk.canonicalPath == testApk.canonicalPath ||\n"
            "            (\n"
            "                targetApk.identity.device == testApk.identity.device &&\n"
            "                    targetApk.identity.inode == testApk.identity.inode\n"
            "                )"
        ),
    )
    for condition in fail_closed_conditions:
        if source.count(condition) != 1:
            raise AssertionError("fail-closed APK boolean composition drifted")
    exact_fail_closed_blocks = (
        "if (targetContext.packageName != TARGET_PACKAGE_ID) {",
        "if (testContext.packageName != TEST_APK_PACKAGE_ID) {",
        "if (!info.splitNames.isNullOrEmpty()) {",
        "if (after != before) {",
        (
            "if (\n"
            "            !applicationInfo.splitNames.isNullOrEmpty() ||\n"
            "            !applicationInfo.splitSourceDirs.isNullOrEmpty() ||\n"
            "            !applicationInfo.splitPublicSourceDirs.isNullOrEmpty()\n"
            "        ) {"
        ),
        (
            "if (\n"
            "            !OsConstants.S_ISREG(stat.st_mode) ||\n"
            "            stat.st_nlink != 1L ||\n"
            "            stat.st_size !in 1L..MAX_BASE_APK_BYTES\n"
            "        ) {"
        ),
    )
    for block in exact_fail_closed_blocks:
        if source.count(block) != 1:
            raise AssertionError("fail-closed local context block drifted")
    order_block = _between(
        source,
        "val CANONICAL_REPORT_FIELD_ORDER: List<String>",
        "\n    }\n}",
    )
    if _literal_list(order_block) != EXPECTED_REPORT_PREFIX + EXPECTED_REPORT_SUFFIX:
        raise AssertionError("canonical report order authority drifted")
    build_block = _between(
        source,
        "val BUILD_HASH_LABELS: List<String>",
        "val NETWORK_TRANSPORTS:",
    )
    if _literal_list(build_block) != EXPECTED_BUILD_LABELS:
        raise AssertionError("nonce-salted Build field schema drifted")
    if len(EXPECTED_REPORT_FIELDS) != len(set(EXPECTED_REPORT_FIELDS)):
        raise AssertionError("test report field authority contains duplicates")

    if f'REPORT_SCHEMA = "{EXPECTED_SCHEMA}"' not in source:
        raise AssertionError("report schema drifted")
    if f'"{EXPECTED_SIGNATURE_DOMAIN}"' not in source:
        raise AssertionError("signature domain drifted")
    if f'"{EXPECTED_NONCE_HASH_DOMAIN}"' not in source:
        raise AssertionError("preserved nonce-hash measurement domain drifted")
    for obsolete_version in ("V2", "V3"):
        if (
            f'"WINSVPN-ANDROID-LIVE-HARDWARE-ATTESTATION-EVIDENCE-{obsolete_version}\\u0000"'
            in source
        ):
            raise AssertionError("obsolete outer signature context remains reachable")


class LiveHardwareAttestationProofSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source, cls.source_sha256 = read_authenticated_source(SOURCE)
        validate_source_contract(cls.source)

    def assert_mutation_rejected(self, name: str, old: str, new: str) -> None:
        self.assertEqual(self.source.count(old), 1, name)
        hostile = self.source.replace(old, new, 1)
        self.assertNotEqual(hostile, self.source, name)
        with self.assertRaises(AssertionError, msg=name):
            validate_source_contract(hostile)

    def test_authenticated_source_snapshot_is_bounded_and_stable(self) -> None:
        self.assertRegex(self.source_sha256, r"^[0-9a-f]{64}$")
        self.assertLessEqual(len(self.source.encode("utf-8")), MAX_SOURCE_BYTES)
        second_source, second_sha256 = read_authenticated_source(SOURCE)
        self.assertEqual(second_source, self.source)
        self.assertEqual(second_sha256, self.source_sha256)

    def test_authenticated_source_reader_rejects_symlinks_and_hardlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            repository = parent / "repository"
            source_directory = repository / "android" / "devicecheck"
            source_directory.mkdir(parents=True)
            source = source_directory / "source.kt"
            source.write_text("trusted source\n", encoding="utf-8")

            root_link = parent / "repository-link"
            root_link.symlink_to(repository, target_is_directory=True)
            with self.assertRaises((AssertionError, OSError)):
                read_authenticated_source(
                    root_link / "android" / "devicecheck" / source.name,
                    repository_root=root_link,
                )

            directory_link = repository / "linked-devicecheck"
            directory_link.symlink_to(source_directory, target_is_directory=True)
            with self.assertRaises((AssertionError, OSError)):
                read_authenticated_source(
                    directory_link / source.name,
                    repository_root=repository,
                )

            source_link = source_directory / "source-link.kt"
            source_link.symlink_to(source)
            with self.assertRaises((AssertionError, OSError)):
                read_authenticated_source(
                    source_link,
                    repository_root=repository,
                )

            hardlink = source_directory / "source-hardlink.kt"
            os.link(source, hardlink)
            with self.assertRaisesRegex(AssertionError, "single-link regular file"):
                read_authenticated_source(source, repository_root=repository)

    def test_authenticated_source_reader_binds_lstat_to_open_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = pathlib.Path(temporary) / "repository"
            repository.mkdir()
            source = repository / "source.kt"
            source.write_text("trusted source\n", encoding="utf-8")
            replacement = repository / "replacement.kt"
            replacement.write_text("hostile source\n", encoding="utf-8")
            real_open = os.open
            swapped = False

            def swap_before_open(
                path: os.PathLike[str] | str,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal swapped
                if path == source.name and dir_fd is not None and not swapped:
                    os.replace(replacement, source)
                    swapped = True
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(os, "open", side_effect=swap_before_open):
                with self.assertRaisesRegex(AssertionError, "identities differ"):
                    read_authenticated_source(source, repository_root=repository)
            self.assertTrue(swapped)

    def test_authenticated_source_reader_retains_custody_through_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = pathlib.Path(temporary) / "repository"
            repository.mkdir()
            source = repository / "source.kt"
            source.write_text("trusted source\n", encoding="utf-8")
            replacement = repository / "replacement.kt"
            replacement.write_text("trusted source\n", encoding="utf-8")
            real_read = os.read
            swapped = False

            def swap_during_read(descriptor: int, size: int) -> bytes:
                nonlocal swapped
                if not swapped:
                    os.replace(replacement, source)
                    swapped = True
                return real_read(descriptor, size)

            with mock.patch.object(os, "read", side_effect=swap_during_read):
                with self.assertRaisesRegex(AssertionError, "changed during"):
                    read_authenticated_source(source, repository_root=repository)
            self.assertTrue(swapped)

    def test_only_exact_nonce_key_id_transcript_context_and_class_are_accepted(
        self,
    ) -> None:
        self.assertIn("class LiveHardwareAttestationProofTest", self.source)
        self.assertIn('"winsvpn_attestation_session_nonce"', self.source)
        self.assertIn('"winsvpn_attestation_key_id"', self.source)
        self.assertIn(
            '"winsvpn_attestation_transcript_context_sha256"', self.source
        )
        self.assertNotIn('"winsvpn_attestation_challenge_sha256"', self.source)
        self.assertIn("InstrumentationRegistry.getArguments()", self.source)
        self.assertIn("arguments.keySet() != ALLOWED_ARGUMENTS", self.source)
        self.assertIn("exactLowerHex(", self.source)
        self.assertEqual(self.source.count("arguments.getString("), 4)
        self.assertIn("val transcriptContextSha256 = exactLowerHex(", self.source)
        self.assertIn(
            "arguments.getString(TRANSCRIPT_CONTEXT_SHA256_ARGUMENT)", self.source
        )
        self.assertIn("nonce.all { it == 0.toByte() }", self.source)
        self.assertIn("claimSessionNonce(nonceHex)", self.source)

    def test_only_one_existing_owner_key_can_sign(self) -> None:
        self.assertIn('KeyStore.getInstance(ANDROID_KEYSTORE)', self.source)
        self.assertIn("keyStore.aliases()", self.source)
        self.assertIn("uniqueAliases.add(alias)", self.source)
        self.assertIn("KeyStore.PrivateKeyEntry::class.java", self.source)
        self.assertIn("aliases.sorted()", self.source)
        self.assertIn("matches.size != 1", self.source)
        for forbidden in (
            "KeyPairGenerator",
            "KeyGenerator",
            "KeyGenParameterSpec",
            "generateKey",
            "generateKeyPair",
            "deleteEntry",
            "setEntry",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.source)

    def test_exact_generated_hardware_keyinfo_and_attestation_are_required(self) -> None:
        self.assertIn('ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"', self.source)
        self.assertIn("leaf.getExtensionValue(ATTESTATION_OID)", self.source)
        self.assertIn("extensionHolders.size != 1", self.source)
        self.assertIn("leaf.publicKey as? RSAPublicKey", self.source)
        self.assertIn("publicKey.publicExponent != RSA_PUBLIC_EXPONENT", self.source)
        self.assertIn("publicKey.modulus.bitLength() !in RSA_MODULUS_BITS", self.source)
        self.assertIn("!publicKey.modulus.testBit(0)", self.source)
        self.assertIn('privateKey.algorithm.equals("RSA"', self.source)
        self.assertIn("keyInfo.origin != KeyProperties.ORIGIN_GENERATED", self.source)
        self.assertIn("keyInfo.purposes != KeyProperties.PURPOSE_SIGN", self.source)
        self.assertIn("keyInfo.digests.size != 1", self.source)
        self.assertIn("KeyProperties.DIGEST_SHA256", self.source)
        self.assertIn("keyInfo.signaturePaddings.size != 1", self.source)
        self.assertIn("KeyProperties.SIGNATURE_PADDING_RSA_PKCS1", self.source)
        self.assertIn("KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT", self.source)
        self.assertIn("KeyProperties.SECURITY_LEVEL_STRONGBOX", self.source)

    def test_key_id_matches_the_collectors_canonical_public_key_identity(self) -> None:
        modulus = "ab" * 256
        canonical = json.dumps(
            {"algorithm": "rsa", "exponent": 65537, "modulus_hex": modulus},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        expected = hashlib.sha256(canonical).hexdigest()
        kotlin_literal = (
            '{"algorithm":"rsa","exponent":65537,'
            '"modulus_hex":"' + modulus + '"}'
        ).encode("ascii")
        self.assertEqual(hashlib.sha256(kotlin_literal).hexdigest(), expected)
        self.assertRegex(
            self.source,
            re.compile(
                r'"\{\\"algorithm\\":\\"rsa\\",\\"exponent\\":65537,"'
                r"\s*\+\s*"
                r'"\\"modulus_hex\\":\\"\$modulusHex\\"\}"'
            ),
        )
        self.assertIn('MessageDigest.getInstance("SHA-256")', self.source)

    def test_exact_packages_versions_signers_and_install_sources_are_measured(self) -> None:
        self.assertIn('TARGET_PACKAGE_ID = "org.winsvpn.devicecheck"', self.source)
        self.assertIn('TEST_APK_PACKAGE_ID = "org.winsvpn.devicecheck.test"', self.source)
        self.assertIn("info.longVersionCode", self.source)
        self.assertIn("versionName.toByteArray(StandardCharsets.UTF_8)", self.source)
        self.assertIn("signingInfo.hasMultipleSigners()", self.source)
        self.assertIn("signers.size != 1", self.source)
        self.assertIn("history.size != 1", self.source)
        self.assertIn("packageManager.getInstallSourceInfo(expectedPackageId)", self.source)

    def test_exact_installed_base_apk_bytes_are_descriptor_bound_and_distinct(
        self,
    ) -> None:
        for needle in (
            "info.applicationInfo",
            "sourceDir != publicSourceDir",
            "!applicationInfo.splitSourceDirs.isNullOrEmpty()",
            "!applicationInfo.splitPublicSourceDirs.isNullOrEmpty()",
            "sourceFile.canonicalPath",
            "canonicalPath != sourceDir",
            "OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW",
            "val before = Os.fstat(descriptor)",
            "val after = Os.fstat(descriptor)",
            "!OsConstants.S_ISREG(stat.st_mode)",
            "stat.st_nlink != 1L",
            "stat.st_size !in 1L..MAX_BASE_APK_BYTES",
            "while (bytesRead < before.st_size)",
            "val trailing = Os.read(descriptor, buffer, 0, 1)",
            "identityAfter != identityBefore",
            "pathIdentityAfter != identityAfter",
            "requireDistinctBaseApks(targetPackage, testPackage)",
            '"target_base_apk_sha256" to targetPackage.baseApk.sha256',
            '"target_base_apk_bytes" to targetPackage.baseApk.bytes.toString()',
            '"test_apk_sha256" to testPackage.baseApk.sha256',
            '"test_apk_bytes" to testPackage.baseApk.bytes.toString()',
        ):
            with self.subTest(needle=needle):
                self.assertIn(needle, self.source)

    def test_verified_boot_and_current_device_lock_are_both_local_gates(self) -> None:
        self.assertIn("ROOT_OF_TRUST_TAG = 704", self.source)
        self.assertIn("roots.size != 1", self.source)
        self.assertIn("VERIFIED_BOOT_STATE_VERIFIED = 0", self.source)
        self.assertIn('VERIFIED_BOOT_STATE_PROPERTY = "ro.boot.verifiedbootstate"', self.source)
        self.assertIn('FLASH_LOCKED_PROPERTY = "ro.boot.flash.locked"', self.source)
        self.assertIn('VBMETA_DEVICE_STATE_PROPERTY = "ro.boot.vbmeta.device_state"', self.source)
        self.assertIn("keyguardManager.isDeviceSecure", self.source)
        self.assertIn("userManager.isUserUnlocked", self.source)
        self.assertIn("Settings.Global.BOOT_COUNT", self.source)

    def test_report_fields_are_unique_fixed_order_ascii(self) -> None:
        self.assertEqual(len(EXPECTED_REPORT_FIELDS), len(set(EXPECTED_REPORT_FIELDS)))
        self.assertIn("fields.map { it.first } != CANONICAL_REPORT_FIELD_ORDER", self.source)
        self.assertIn("fields.map { it.first }.toSet().size != fields.size", self.source)
        self.assertIn("StandardCharsets.US_ASCII", self.source)
        self.assertIn("append(name).append('=').append(value).append('\\n')", self.source)
        canonical = _between(
            self.source,
            "private fun canonicalReport(",
            "private fun canonicalBoolean(",
        )
        self.assertEqual(
            _report_pairs(canonical),
            EXPECTED_REPORT_PREFIX + EXPECTED_REPORT_SUFFIX,
        )

    def test_local_build_display_runtime_and_vpn_endpoint_facts_are_required(self) -> None:
        for needle in (
            "buildFacts.map { it.first } != BUILD_HASH_LABELS",
            "NONCE_SALTED_HASH_DOMAIN",
            "displayEvidence(targetContext, nonce)",
            "displays.size != 1",
            "display.state != Display.STATE_ON",
            "localRuntimeEvidence(targetContext, nonce)",
            "Application.getProcessName()",
            "localNetworkEvidence(context, nonce)",
            "local active network runtime is unavailable",
            "vpnHandles.size > 1",
            "VPN runtime endpoint is not the active tested endpoint",
            "requireCanonicalNetworkSchema(runtimeEvidence.network, nonce)",
            "active network evidence contradicts the canonical report schema",
            "present VPN evidence contradicts the canonical report schema",
            "absent VPN evidence contradicts the canonical report schema",
            "active_endpoint_nonce_sha256",
            "vpn_endpoint_nonce_sha256",
        ):
            with self.subTest(needle=needle):
                self.assertIn(needle, self.source)

    def test_signature_preimage_and_bounded_status_are_exact(self) -> None:
        self.assertIn('SIGNATURE_ALGORITHM = "SHA256withRSA"', self.source)
        self.assertIn(f'"{EXPECTED_SIGNATURE_DOMAIN}"', self.source)
        self.assertIn("signer.initSign(keyEvidence.privateKey)", self.source)
        main = _between(
            self.source,
            "fun provePossessionOfOwnerAttestedKey()",
            "private fun matchingAttestedKeys(",
        )
        self.assertEqual(
            tuple(re.findall(r"signer\.update\(([^)]+)\)", main)),
            ("SIGNATURE_DOMAIN", "nonce", "report"),
        )
        self.assertIn("signer.sign().toHex()", self.source)
        self.assertNotIn("SHA256withRSA/PSS", self.source)
        self.assertIn("reportBase64.length > MAX_REPORT_BASE64_CHARS", self.source)
        self.assertIn("signatureHex.length > MAX_SIGNATURE_HEX_CHARS", self.source)
        self.assertIn("putString(REPORT_STATUS, reportBase64)", self.source)
        self.assertIn("putString(SIGNATURE_STATUS, signatureHex)", self.source)
        self.assertIn("putString(KEY_ID_STATUS, expectedKeyId)", self.source)
        self.assertIn("putString(SCHEMA_STATUS, REPORT_SCHEMA)", self.source)
        self.assertIn("status.keySet() != STATUS_KEYS", self.source)
        self.assertIn("instrumentation.sendStatus(STATUS_IN_PROGRESS, status)", self.source)
        self.assertIn("INSTRUMENTATION_CODE: -1", self.source)
        self.assertIn('SIGNATURE_STATUS = "winsvpn_attestation_signature_hex"', self.source)
        self.assertIn('KEY_ID_STATUS = "winsvpn_attestation_key_id"', self.source)
        self.assertNotIn("putString(\"alias", self.source)
        self.assertNotIn("privateKey.encoded", self.source)

    def test_hostile_opaque_digest_and_caller_semantic_inputs_are_rejected(self) -> None:
        self.assert_mutation_rejected(
            "opaque host digest signing",
            "signer.update(SIGNATURE_DOMAIN)\n        signer.update(nonce)\n        signer.update(report)",
            "signer.update(nonce)",
        )
        self.assert_mutation_rejected(
            "caller semantic field",
            "val arguments = InstrumentationRegistry.getArguments()",
            "val arguments = InstrumentationRegistry.getArguments()\n"
            '        arguments.getString("target_version_code")',
        )
        self.assert_mutation_rejected(
            "caller transcript substituted for local package value",
            '"target_version_code" to targetPackage.versionCode.toString(),',
            '"target_version_code" to transcriptContextSha256,',
        )

    def test_hostile_missing_or_malformed_transcript_hash_is_rejected(self) -> None:
        self.assert_mutation_rejected(
            "missing transcript SHA-256",
            "arguments.getString(TRANSCRIPT_CONTEXT_SHA256_ARGUMENT)",
            "null",
        )
        self.assert_mutation_rejected(
            "wrong transcript SHA-256 length",
            "arguments.getString(TRANSCRIPT_CONTEXT_SHA256_ARGUMENT),\n"
            "            64,\n"
            '            "attestation transcript-context SHA-256",',
            "arguments.getString(TRANSCRIPT_CONTEXT_SHA256_ARGUMENT),\n"
            "            63,\n"
            '            "attestation transcript-context SHA-256",',
        )
        self.assert_mutation_rejected(
            "uppercase transcript SHA-256 accepted",
            "if (value == null || value.length != length || "
            "value.any { it !in LOWER_HEX }) {",
            "if (value == null || value.length != length || "
            "value.uppercase() == value) {",
        )

    def test_hostile_omitted_or_substituted_apk_report_fields_are_rejected(
        self,
    ) -> None:
        for name, binding in (
            (
                "omitted target APK digest",
                '            "target_base_apk_sha256" to targetPackage.baseApk.sha256,\n',
            ),
            (
                "omitted target APK byte count",
                '            "target_base_apk_bytes" to '
                "targetPackage.baseApk.bytes.toString(),\n",
            ),
            (
                "omitted test APK digest",
                '            "test_apk_sha256" to testPackage.baseApk.sha256,\n',
            ),
            (
                "omitted test APK byte count",
                '            "test_apk_bytes" to testPackage.baseApk.bytes.toString(),\n',
            ),
        ):
            with self.subTest(name=name):
                self.assert_mutation_rejected(name, binding, "")
        self.assert_mutation_rejected(
            "test APK digest reuses target APK digest",
            '"test_apk_sha256" to testPackage.baseApk.sha256,',
            '"test_apk_sha256" to targetPackage.baseApk.sha256,',
        )

    def test_hostile_split_symlink_and_source_ambiguity_are_rejected(self) -> None:
        for name, old, new in (
            (
                "split APK accepted",
                "!applicationInfo.splitSourceDirs.isNullOrEmpty() ||",
                "applicationInfo.splitSourceDirs.isNullOrEmpty() ||",
            ),
            (
                "public split APK accepted",
                "!applicationInfo.splitPublicSourceDirs.isNullOrEmpty()",
                "applicationInfo.splitPublicSourceDirs.isNullOrEmpty()",
            ),
            (
                "split rejection weakened to conjunction",
                "!applicationInfo.splitNames.isNullOrEmpty() ||\n"
                "            !applicationInfo.splitSourceDirs.isNullOrEmpty() ||",
                "!applicationInfo.splitNames.isNullOrEmpty() &&\n"
                "            !applicationInfo.splitSourceDirs.isNullOrEmpty() ||",
            ),
            (
                "public source ambiguity accepted",
                "sourceDir != publicSourceDir",
                "false",
            ),
            (
                "noncanonical sourceDir accepted",
                "canonicalPath != sourceDir",
                "false",
            ),
            (
                "final-component symlink followed",
                "OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or "
                "OsConstants.O_NOFOLLOW",
                "OsConstants.O_RDONLY or OsConstants.O_CLOEXEC",
            ),
        ):
            with self.subTest(name=name):
                self.assert_mutation_rejected(name, old, new)

    def test_hostile_same_apk_reuse_and_toctou_are_rejected(self) -> None:
        for name, old, new in (
            (
                "same APK reuse gate omitted",
                "requireDistinctBaseApks(targetPackage, testPackage)",
                "Unit",
            ),
            (
                "same APK path accepted",
                "targetApk.canonicalPath == testApk.canonicalPath ||",
                "false ||",
            ),
            (
                "same APK inode accepted",
                "targetApk.identity.inode == testApk.identity.inode",
                "false",
            ),
            (
                "after fstat omitted",
                "val after = Os.fstat(descriptor)",
                "val after = before",
            ),
            (
                "descriptor mutation accepted",
                "identityAfter != identityBefore",
                "false",
            ),
            (
                "path substitution accepted",
                "pathIdentityAfter != identityAfter ||",
                "false ||",
            ),
            (
                "growth probe omitted",
                "val trailing = Os.read(descriptor, buffer, 0, 1)",
                "val trailing = 0",
            ),
            (
                "truncation accepted at EOF",
                "if (count <= 0) {",
                "if (count < 0) {",
            ),
            (
                "regular-file rejection weakened to conjunction",
                "!OsConstants.S_ISREG(stat.st_mode) ||\n"
                "            stat.st_nlink != 1L ||",
                "!OsConstants.S_ISREG(stat.st_mode) &&\n"
                "            stat.st_nlink != 1L ||",
            ),
        ):
            with self.subTest(name=name):
                self.assert_mutation_rejected(name, old, new)

    def test_hostile_network_and_vpn_schema_contradictions_are_rejected(self) -> None:
        for name, old, new in (
            (
                "network schema gate omitted",
                "requireCanonicalNetworkSchema(runtimeEvidence.network, nonce)",
                "Unit",
            ),
            (
                "noncanonical transport order accepted",
                "transports != allowedTransports.filter { it in transports } ||",
                "false ||",
            ),
            (
                "VPN transport contradiction accepted",
                "!vpnTransportPresent ||",
                "false ||",
            ),
            (
                "single-network VPN accepted",
                "network.networkCount < 2 ||",
                "false ||",
            ),
            (
                "VPN and active handles may differ",
                "network.vpnNetworkHandle != network.activeNetworkHandle ||",
                "false ||",
            ),
            (
                "VPN and active endpoints may differ",
                "vpnEndpoint.interfaceNameUtf8Hex != activeEndpoint.interfaceNameUtf8Hex ||",
                "false ||",
            ),
            (
                "absent VPN transport accepted",
                "vpnTransportPresent ||\n            network.vpnNetworkHandle",
                "false ||\n            network.vpnNetworkHandle",
            ),
            (
                "absent VPN handle accepted",
                "network.vpnNetworkHandle != NO_NETWORK_HANDLE ||",
                "false ||",
            ),
            (
                "absent VPN endpoint hash accepted",
                "vpnEndpoint.endpointNonceSha256 != absentVpnEndpointSha256",
                "false",
            ),
        ):
            with self.subTest(name=name):
                self.assert_mutation_rejected(name, old, new)

    def test_hostile_signature_and_transcript_context_drift_are_rejected(self) -> None:
        self.assert_mutation_rejected(
            "obsolete signature context",
            '"WINSVPN-ANDROID-LIVE-HARDWARE-ATTESTATION-EVIDENCE-V4\\u0000"',
            '"WINSVPN-ANDROID-LIVE-HARDWARE-ATTESTATION-EVIDENCE-V3\\u0000"',
        )
        self.assert_mutation_rejected(
            "transcript context rebound",
            '"transcript_context_sha256" to transcriptContextSha256,',
            '"transcript_context_sha256" to expectedKeyId,',
        )
        self.assert_mutation_rejected(
            "target package context accepted",
            "if (targetContext.packageName != TARGET_PACKAGE_ID) {",
            "if (false && targetContext.packageName != TARGET_PACKAGE_ID) {",
        )

    def test_hostile_noncanonical_fields_and_order_are_rejected(self) -> None:
        self.assert_mutation_rejected(
            "swapped canonical fields",
            '"schema" to REPORT_SCHEMA,\n            "host_session_nonce" to nonceHex,',
            '"host_session_nonce" to nonceHex,\n            "schema" to REPORT_SCHEMA,',
        )
        self.assert_mutation_rejected(
            "duplicate canonical field",
            '"persistent_key_id" to expectedKeyId,',
            '"persistent_key_id" to expectedKeyId,\n'
            '            "persistent_key_id" to expectedKeyId,',
        )

    def test_hostile_software_key_and_duplicate_signer_or_key_are_rejected(self) -> None:
        self.assert_mutation_rejected(
            "software key",
            'else -> refuse("owner-authorized key is software-backed or has unknown security")',
            'else -> "software"',
        )
        self.assert_mutation_rejected(
            "duplicate signer",
            "signers.size != 1",
            "signers.isEmpty()",
        )
        self.assert_mutation_rejected(
            "duplicate persistent key",
            "matches.size != 1",
            "matches.isEmpty()",
        )

    def test_hostile_missing_inputs_runtime_and_status_drift_are_rejected(self) -> None:
        self.assert_mutation_rejected(
            "missing nonce",
            "arguments.getString(NONCE_ARGUMENT)",
            "null",
        )
        self.assert_mutation_rejected(
            "missing key ID",
            "arguments.getString(KEY_ID_ARGUMENT)",
            "null",
        )
        self.assert_mutation_rejected(
            "missing local runtime",
            "val runtimeEvidence = localRuntimeEvidence(targetContext, nonce)",
            "val runtimeEvidence = callerRuntimeEvidence(arguments)",
        )
        self.assert_mutation_rejected(
            "status drift",
            "putString(SCHEMA_STATUS, REPORT_SCHEMA)",
            'putString("schema", REPORT_SCHEMA)',
        )

    def test_hostile_key_creation_deletion_and_algorithm_drift_are_rejected(self) -> None:
        for name, marker in (
            ("creates a key", "KeyPairGenerator"),
            ("deletes the key", "deleteEntry"),
            ("exports private key", "privateKey.encoded"),
        ):
            with self.subTest(name=name), self.assertRaises(AssertionError):
                validate_source_contract(self.source + f"\n// {marker}\n")
        self.assert_mutation_rejected(
            "signature algorithm drift",
            'SIGNATURE_ALGORITHM = "SHA256withRSA"',
            'SIGNATURE_ALGORITHM = "SHA512withRSA"',
        )


if __name__ == "__main__":
    raise SystemExit(unittest.main())
