#!/usr/bin/env python3
"""Focused AAB identity-inspector regressions for held-byte verification."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import inspect
import io
import json
import os
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
import xml.etree.ElementTree as ET
from unittest import mock
import shutil
import stat


ROOT = pathlib.Path(__file__).resolve().parents[1]
ELF_STUB = b"\x7fELF" + b"\x00" * 12


def r8_mapping_bytes(class_count: int = 40, stem: str = "Synthetic") -> bytes:
    body_lines = []
    for index in range(class_count):
        body_lines.append(f"org.winsvpn.app.internal.{stem}{index:04d} -> a{index:04d}:")
        body_lines.append("    1:1:void run():0:0 -> a")
    body = "\n".join(body_lines) + "\n"
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    header = (
        "# compiler: R8\n"
        "# compiler_version: 9.3.16\n"
        "# min_api: 26\n"
        f"# pg_map_hash: SHA-256 {digest}\n"
    )
    return (header + body).encode("utf-8")


def padded_trivial_r8_mapping() -> bytes:
    body_lines = ["org.winsvpn.app.internal.Tiny -> t:"]
    body_lines.extend(["# padding"] * 250)
    body = "\n".join(body_lines) + "\n"
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    header = "# compiler: R8\n" f"# pg_map_hash: SHA-256 {digest}\n"
    return (header + body).encode("utf-8")


def load_signer():
    spec = importlib.util.spec_from_file_location(
        "verify_android_aab_signers", ROOT / "tools/verify_android_aab_signers.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def der_len(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_len(len(body)) + body


def fake_cert(cn: str) -> bytes:
    cn_oid = tlv(0x06, bytes.fromhex("550403"))
    cn_val = tlv(0x0C, cn.encode("ascii"))
    rdn = tlv(0x31, tlv(0x30, cn_oid + cn_val))
    subject = tlv(0x30, rdn)
    tbs = tlv(0x30, tlv(0x02, b"\x01") + subject)
    alg = tlv(0x30, tlv(0x06, bytes.fromhex("2a864886f70d01010b")))
    sig = tlv(0x03, b"\x00\x00")
    return tlv(0x30, tbs + alg + sig)


def fake_pkcs7(cert: bytes) -> bytes:
    oid = tlv(0x06, bytes.fromhex("2a864886f70d010702"))
    version = tlv(0x02, b"\x01")
    digest_algs = tlv(0x31, b"")
    content_info = tlv(0x30, tlv(0x06, bytes.fromhex("2a864886f70d010701")))
    certs = tlv(0xA0, cert)
    signer_info = tlv(0x30, tlv(0x02, b"\x01") + tlv(0x30, b"") + tlv(0x30, b""))
    signed = tlv(0x30, version + digest_algs + content_info + certs + tlv(0x31, signer_info))
    return tlv(0x30, oid + tlv(0xA0, signed))


class AndroidAabIdentityInspectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_signer()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="aab-identity-")
        self.work = pathlib.Path(self.temporary.name)
        self.cert = fake_cert("WinUpload")
        self.pkcs7 = fake_pkcs7(self.cert)
        self.pin = hashlib.sha256(self.cert).hexdigest()
        self.pin_patch = mock.patch.object(
            self.module, "_reviewed_upload_certificate", return_value=self.pin
        )
        self.pin_patch.start()
        self.addCleanup(self.pin_patch.stop)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def feature(self, name: str, required: str | None = None) -> bytes:
        attributes = [
            self.module.encode_xml_attribute(
                "name", name, namespace=self.module.ANDROID_NS
            )
        ]
        if required is not None:
            attributes.append(
                self.module.encode_xml_attribute(
                    "required",
                    required,
                    namespace=self.module.ANDROID_NS,
                    compiled=self.module.encode_compiled_bool(required == "true"),
                )
            )
        return self.module.encode_xml_node_element(
            self.module.encode_xml_element("uses-feature", attributes, [])
        )

    def category(self, name: str) -> bytes:
        return self.module.encode_xml_node_element(
            self.module.encode_xml_element(
                "category",
                [
                    self.module.encode_xml_attribute(
                        "name", name, namespace=self.module.ANDROID_NS
                    )
                ],
                [],
            )
        )

    def permission(self, name: str) -> bytes:
        return self.module.encode_xml_node_element(
            self.module.encode_xml_element(
                "uses-permission",
                [
                    self.module.encode_xml_attribute(
                        "name", name, namespace=self.module.ANDROID_NS
                    )
                ],
                [],
            )
        )

    def vpn_service(self) -> bytes:
        intent = self.module.encode_xml_node_element(
            self.module.encode_xml_element(
                "intent-filter",
                [],
                [
                    self.module.encode_xml_node_element(
                        self.module.encode_xml_element(
                            "action",
                            [
                                self.module.encode_xml_attribute(
                                    "name",
                                    "android.net.VpnService",
                                    namespace=self.module.ANDROID_NS,
                                )
                            ],
                            [],
                        )
                    )
                ],
            )
        )
        return self.module.encode_xml_node_element(
            self.module.encode_xml_element(
                "service",
                [
                    self.module.encode_xml_attribute(
                        "name",
                        "org.winsvpn.app.VpnTunnelService",
                        namespace=self.module.ANDROID_NS,
                    ),
                    self.module.encode_xml_attribute(
                        "permission",
                        "android.permission.BIND_VPN_SERVICE",
                        namespace=self.module.ANDROID_NS,
                    ),
                    self.module.encode_xml_attribute(
                        "exported",
                        "false",
                        namespace=self.module.ANDROID_NS,
                        compiled=self.module.encode_compiled_bool(False),
                    ),
                ],
                [intent],
            )
        )

    def activity(
        self,
        name: str,
        categories: tuple[str, ...],
        *,
        screen_orientation: str | None = None,
        compiled_orientation: int | None = None,
        bind_screen_orientation: bool = True,
        exported: bool = True,
    ) -> bytes:
        intent = self.module.encode_xml_node_element(
            self.module.encode_xml_element(
                "intent-filter",
                [],
                [
                    self.module.encode_xml_node_element(
                        self.module.encode_xml_element(
                            "action",
                            [
                                self.module.encode_xml_attribute(
                                    "name",
                                    "android.intent.action.MAIN",
                                    namespace=self.module.ANDROID_NS,
                                )
                            ],
                            [],
                        )
                    ),
                    *[self.category(item) for item in categories],
                ],
            )
        )
        attributes = [
            self.module.encode_xml_attribute(
                "name", name, namespace=self.module.ANDROID_NS
            ),
            self.module.encode_xml_attribute(
                "exported",
                "true" if exported else "false",
                namespace=self.module.ANDROID_NS,
                compiled=self.module.encode_compiled_bool(exported),
            ),
        ]
        if screen_orientation is not None:
            attributes.append(
                self.module.encode_xml_attribute(
                    "screenOrientation",
                    screen_orientation,
                    namespace=self.module.ANDROID_NS,
                    resource_id=(
                        self.module.ATTR_SCREEN_ORIENTATION
                        if bind_screen_orientation
                        else 0
                    ),
                    compiled=(
                        self.module.encode_compiled_int(compiled_orientation)
                        if compiled_orientation is not None
                        else None
                    ),
                )
            )
        return self.module.encode_xml_node_element(
            self.module.encode_xml_element(
                "activity",
                attributes,
                [intent],
            )
        )

    def activity_alias(
        self,
        name: str,
        target_activity: str,
        categories: tuple[str, ...],
    ) -> bytes:
        intent = self.module.encode_xml_node_element(
            self.module.encode_xml_element(
                "intent-filter",
                [],
                [self.category(item) for item in categories],
            )
        )
        return self.module.encode_xml_node_element(
            self.module.encode_xml_element(
                "activity-alias",
                [
                    self.module.encode_xml_attribute(
                        "name", name, namespace=self.module.ANDROID_NS
                    ),
                    self.module.encode_xml_attribute(
                        "targetActivity",
                        target_activity,
                        namespace=self.module.ANDROID_NS,
                    ),
                ],
                [intent],
            )
        )

    def proto_manifest(
        self,
        *,
        package: str = "org.winsvpn.app",
        version_name: str = "1.0.16",
        version_code: int = 33,
        form: str = "phone",
        tv_screen_orientation: str | None = "landscape",
        tv_compiled_orientation: int | None = 0,
        tv_bind_screen_orientation: bool = True,
        tv_main_categories: tuple[str, ...] = (
            "android.intent.category.LEANBACK_LAUNCHER",
        ),
        tv_additional_activities: tuple[bytes, ...] = (),
    ) -> bytes:
        children = []
        application_attrs = [
            self.module.encode_xml_attribute(
                "label",
                "Win's VPN" if form == "tv" else "Calculator",
                namespace=self.module.ANDROID_NS,
            ),
            self.module.encode_xml_attribute(
                "icon", "@mipmap/ic_launcher", namespace=self.module.ANDROID_NS
            ),
            self.module.encode_xml_attribute(
                "debuggable",
                "false",
                namespace=self.module.ANDROID_NS,
                compiled=self.module.encode_compiled_bool(False),
            ),
        ]
        min_sdk = 30 if form == "wear" else 26
        children.append(
            self.module.encode_xml_node_element(
                self.module.encode_xml_element(
                    "uses-sdk",
                    [
                        self.module.encode_xml_attribute(
                            "minSdkVersion",
                            str(min_sdk),
                            namespace=self.module.ANDROID_NS,
                            compiled=self.module.encode_compiled_int(min_sdk),
                        ),
                        self.module.encode_xml_attribute(
                            "targetSdkVersion",
                            "37",
                            namespace=self.module.ANDROID_NS,
                            compiled=self.module.encode_compiled_int(37),
                        ),
                    ],
                    [],
                )
            )
        )
        activities = []
        if form != "wear":
            children.extend(
                [
                    self.permission("android.permission.INTERNET"),
                    self.permission("android.permission.QUERY_ALL_PACKAGES"),
                ]
            )
        if form == "tv":
            children.extend(
                [
                    self.feature("android.software.leanback", "false"),
                    self.feature("android.hardware.touchscreen", "false"),
                ]
            )
            application_attrs.append(
                self.module.encode_xml_attribute(
                    "banner", "@drawable/banner", namespace=self.module.ANDROID_NS
                )
            )
            activities.append(
                self.activity(
                    "org.winsvpn.app.MainActivity",
                    tv_main_categories,
                    screen_orientation=tv_screen_orientation,
                    compiled_orientation=tv_compiled_orientation,
                    bind_screen_orientation=tv_bind_screen_orientation,
                )
            )
            activities.extend(tv_additional_activities)
        elif form == "wear":
            children.append(self.feature("android.hardware.type.watch", "true"))
            activities.append(
                self.activity(
                    "org.winsvpn.app.wear.MainActivity",
                    ("android.intent.category.LAUNCHER",),
                )
            )
        else:
            activities.append(
                self.activity(
                    "org.winsvpn.app.MainActivity",
                    ("android.intent.category.LAUNCHER",),
                )
            )
        if form != "wear":
            application_attrs.extend(
                [
                    self.module.encode_xml_attribute(
                        "usesCleartextTraffic",
                        "false",
                        namespace=self.module.ANDROID_NS,
                        compiled=self.module.encode_compiled_bool(False),
                    ),
                    self.module.encode_xml_attribute(
                        "networkSecurityConfig",
                        "@xml/network_security_config",
                        namespace=self.module.ANDROID_NS,
                    ),
                ]
            )
        application_children = list(activities)
        if form != "wear":
            application_children.append(self.vpn_service())
        else:
            application_children.append(
                self.module.encode_xml_node_element(
                    self.module.encode_xml_element(
                        "meta-data",
                        [
                            self.module.encode_xml_attribute(
                                "name",
                                "com.google.android.wearable.standalone",
                                namespace=self.module.ANDROID_NS,
                            ),
                            self.module.encode_xml_attribute(
                                "value",
                                "false",
                                namespace=self.module.ANDROID_NS,
                                compiled=self.module.encode_compiled_bool(False),
                            ),
                        ],
                        [],
                    )
                )
            )
        children.append(
            self.module.encode_xml_node_element(
                self.module.encode_xml_element(
                    "application", application_attrs, application_children
                )
            )
        )
        return self.module.encode_xml_node_element(
            self.module.encode_xml_element(
                "manifest",
                [
                    self.module.encode_xml_attribute("package", package),
                    self.module.encode_xml_attribute(
                        "versionName",
                        version_name,
                        namespace=self.module.ANDROID_NS,
                        resource_id=self.module.ATTR_VERSION_NAME,
                    ),
                    self.module.encode_xml_attribute(
                        "versionCode",
                        str(version_code),
                        namespace=self.module.ANDROID_NS,
                        resource_id=self.module.ATTR_VERSION_CODE,
                        compiled=self.module.encode_compiled_int(version_code),
                    ),
                ],
                children,
                ns_decls=[
                    self.module.encode_xml_namespace("android", self.module.ANDROID_NS)
                ],
            )
        )

    def members_for(
        self,
        *,
        form: str = "phone",
        version_code: int | None = None,
        package: str = "org.winsvpn.app",
        version_name: str = "1.0.16",
        extra: dict[str, bytes] | None = None,
        pkcs7: bytes | None = None,
        include_release_payload: bool = True,
        tv_screen_orientation: str | None = "landscape",
        tv_compiled_orientation: int | None = 0,
        tv_bind_screen_orientation: bool = True,
    ) -> dict[str, bytes]:
        if version_code is None:
            version_code = {"phone": 33, "tv": 3302, "wear": 3301}[form]
        abis = (
            self.module.WEAR_ABIS if form == "wear" else self.module.PHONE_TV_ABIS
        )
        members: dict[str, bytes] = {
            self.module.BUNDLE_CONFIG_MEMBER: self.module.encode_bundle_config(),
            self.module.MANIFEST_MEMBER: self.proto_manifest(
                package=package,
                version_name=version_name,
                version_code=version_code,
                form=form,
                tv_screen_orientation=tv_screen_orientation,
                tv_compiled_orientation=tv_compiled_orientation,
                tv_bind_screen_orientation=tv_bind_screen_orientation,
            ),
        }
        for abi in sorted(abis):
            members[f"base/lib/{abi}/libapp.so"] = b"native"
            if form != "wear":
                members[
                    "BUNDLE-METADATA/com.android.tools.build.debugsymbols/"
                    f"{abi}/libapp.so.sym"
                ] = b"app-sym"
                members[
                    "BUNDLE-METADATA/com.android.tools.build.debugsymbols/"
                    f"{abi}/libflutter.so.dbg"
                ] = b"flutter-dbg"
                if include_release_payload:
                    for engine in sorted(self.module.PHONE_TV_REQUIRED_NATIVE_ENGINES):
                        members[f"base/lib/{abi}/{engine}"] = ELF_STUB
        if form != "wear" and include_release_payload:
            members[self.module.OFFICIAL_PROGUARD_MAP] = r8_mapping_bytes()
        members.update(extra or {})
        return self.jar_wrap(members, pkcs7 if pkcs7 is not None else self.pkcs7)

    def jar_wrap(self, members: dict[str, bytes], pkcs7: bytes) -> dict[str, bytes]:
        payload = dict(members)
        parts = [b"Manifest-Version: 1.0\r\n\r\n"]
        for name in sorted(payload):
            digest = base64.b64encode(hashlib.sha256(payload[name]).digest()).decode("ascii")
            parts.append(f"Name: {name}\r\nSHA-256-Digest: {digest}\r\n\r\n".encode("ascii"))
        manifest = b"".join(parts)
        signature = (
            b"Signature-Version: 1.0\r\nSHA-256-Digest-Manifest: "
            + base64.b64encode(hashlib.sha256(manifest).digest())
            + b"\r\n\r\n"
        )
        payload["META-INF/MANIFEST.MF"] = manifest
        payload["META-INF/UPLOAD.SF"] = signature
        payload["META-INF/UPLOAD.RSA"] = pkcs7
        return payload

    def write_aab(
        self,
        name: str = "candidate.aab",
        members: dict[str, bytes] | None = None,
        *,
        form: str = "phone",
        raw: bytes | None = None,
    ) -> pathlib.Path:
        path = self.work / name
        if raw is not None:
            path.write_bytes(raw)
            return path
        payload = members if members is not None else self.members_for(form=form)
        with zipfile.ZipFile(path, "w") as archive:
            for member, data in payload.items():
                archive.writestr(member, data)
        return path

    def write_apk(
        self,
        name: str = "candidate.apk",
        *,
        form: str = "phone",
        extra: dict[str, bytes] | None = None,
        pkcs7: bytes | None = None,
        package: str = "org.winsvpn.app",
        version_name: str = "1.0.16",
        version_code: int | None = None,
    ) -> pathlib.Path:
        if version_code is None:
            version_code = {"phone": 33, "tv": 3302}[form]
        members: dict[str, bytes] = {
            self.module.APK_MANIFEST_MEMBER: self.module.encode_apk_binary_manifest(
                package=package,
                version_name=version_name,
                version_code=version_code,
                form=form,
            )
        }
        for abi in sorted(self.module.PHONE_TV_ABIS):
            for engine in sorted(self.module.PHONE_TV_REQUIRED_NATIVE_ENGINES):
                members[f"lib/{abi}/{engine}"] = ELF_STUB
        members.update(extra or {})
        unsigned = {
            key: value
            for key, value in members.items()
            if not key.startswith("META-INF/")
        }
        payload = self.jar_wrap(unsigned, pkcs7 if pkcs7 is not None else self.pkcs7)
        path = self.work / name
        with zipfile.ZipFile(path, "w") as archive:
            for member, data in payload.items():
                archive.writestr(member, data)
        return path

    def bind_mock_apksigner(self, analysis: dict[str, object]) -> dict[str, object]:
        analysis["apk_signing"] = {
            "verified_v2": True,
            "verified_v3": True,
            "signer_count": 1,
            "certificate_sha256": self.pin,
            "certificate_subject": "CN=WinUpload",
        }
        return analysis

    def bundletool_manifest_xml(self, form: str) -> bytes:
        version_code = {"phone": 33, "tv": 3302, "wear": 3301}[form]
        activity = {
            "phone": "org.winsvpn.app.MainActivity",
            "tv": "org.winsvpn.app.MainActivity",
            "wear": "org.winsvpn.app.wear.MainActivity",
        }[form]
        orientation = ' android:screenOrientation="landscape"' if form == "tv" else ""
        category = (
            "android.intent.category.LEANBACK_LAUNCHER"
            if form == "tv"
            else "android.intent.category.LAUNCHER"
        )
        min_sdk = 30 if form == "wear" else 26
        permissions = (
            '<uses-permission android:name="android.permission.INTERNET" />'
            '<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />'
            if form != "wear"
            else ""
        )
        features = {
            "phone": "",
            "tv": (
                '<uses-feature android:name="android.software.leanback" android:required="false" />'
                '<uses-feature android:name="android.hardware.touchscreen" android:required="false" />'
            ),
            "wear": (
                '<uses-feature android:name="android.hardware.type.watch" android:required="true" />'
            ),
        }[form]
        application_attributes = (
            'android:label="Win\'s VPN" android:icon="@mipmap/ic_launcher" '
            'android:banner="@drawable/banner" android:debuggable="false" '
            'android:usesCleartextTraffic="false" '
            'android:networkSecurityConfig="@xml/network_security_config"'
            if form == "tv"
            else (
                'android:label="Calculator" android:icon="@mipmap/ic_launcher" '
                'android:debuggable="false" android:usesCleartextTraffic="false" '
                'android:networkSecurityConfig="@xml/network_security_config"'
                if form == "phone"
                else (
                    'android:label="Calculator" android:icon="@mipmap/ic_launcher" '
                    'android:debuggable="false"'
                )
            )
        )
        service = (
            '<service android:name="org.winsvpn.app.VpnTunnelService" '
            'android:permission="android.permission.BIND_VPN_SERVICE" '
            'android:exported="false"><intent-filter><action '
            'android:name="android.net.VpnService" /></intent-filter></service>'
            if form != "wear"
            else (
                '<meta-data android:name="com.google.android.wearable.standalone" '
                'android:value="false" />'
            )
        )
        return (
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            'package="org.winsvpn.app" android:versionName="1.0.16" '
            f'android:versionCode="{version_code}">'
            f'<uses-sdk android:minSdkVersion="{min_sdk}" android:targetSdkVersion="37" />'
            f'{permissions}{features}<application {application_attributes}>'
            f'<activity android:name="{activity}" android:exported="true"{orientation}>'
            '<intent-filter><action android:name="android.intent.action.MAIN" />'
            f'<category android:name="{category}" /></intent-filter></activity>{service}'
            "</application></manifest>"
        ).encode("ascii")

    def held_tool_runner(self, form: str):
        seen: list[tuple[list[str], dict[str, object]]] = []
        fingerprint = ":".join(
            self.pin.upper()[offset : offset + 2]
            for offset in range(0, len(self.pin), 2)
        )

        def run(arguments, **kwargs):
            argv = [str(value) for value in arguments]
            recorded = dict(kwargs)
            recorded["_pass_fd_modes"] = tuple(
                stat.S_IMODE(os.fstat(descriptor).st_mode)
                for descriptor in kwargs.get("pass_fds", ())
            )
            seen.append((argv, recorded))
            if argv[-1:] == ["version"]:
                return subprocess.CompletedProcess(argv, 0, b"1.18.3\n", None)
            if "-verify" in argv:
                return subprocess.CompletedProcess(argv, 0, b"jar verified.\n", None)
            if "-importcert" in argv:
                return subprocess.CompletedProcess(argv, 0, b"Certificate was added to keystore\n", None)
            if "-printcert" in argv and "-rfc" in argv:
                pem = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
                return subprocess.CompletedProcess(argv, 0, pem, None)
            if "-printcert" in argv:
                output = f"Owner: CN=WinUpload\nSHA256: {fingerprint}\n".encode("ascii")
                return subprocess.CompletedProcess(argv, 0, output, None)
            if "dump" in argv and "manifest" in argv:
                return subprocess.CompletedProcess(
                    argv, 0, self.bundletool_manifest_xml(form), None
                )
            raise AssertionError(f"unexpected held-AAB tool invocation: {argv!r}")

        return run, seen

    @contextlib.contextmanager
    def held_tool_context(self, form: str, runner=None):
        resolved_work = self.work.resolve(strict=True)
        bindir = resolved_work / "sealed-jdk" / "bin"
        bindir.mkdir(parents=True, exist_ok=True)
        tools: dict[str, str] = {}
        for name in ("java", "jarsigner", "keytool"):
            path = bindir / name
            if path.exists():
                path.chmod(0o755)
            path.write_text("#!/bin/sh\nexit 97\n", encoding="ascii")
            path.chmod(0o555)
            tools[name] = str(path)
        bundletool = resolved_work / "bundletool-all-1.18.3.jar"
        if bundletool.exists():
            bundletool.chmod(0o644)
        bundletool.write_bytes(b"reviewed synthetic bundletool fixture")
        bundletool.chmod(0o444)
        bundletool_digest = hashlib.sha256(bundletool.read_bytes()).hexdigest()
        module = self.module

        class FakeHeldTools:
            def __init__(self, *, bind_bundletool: bool = True) -> None:
                self.bind_bundletool = bind_bundletool
                self.fd = -1
                self.token = None
                self.custody = resolved_work / f"held-tools-{id(self)}"
                self.private_tools: dict[str, str] = {}
                self.private_tool_fds: dict[str, int] = {}
                self.bundletool = self.custody / "bundletool.jar"
                self.bundle_stat = None

            @property
            def jdk_tools(self):
                return tuple(
                    self.private_tools[name]
                    for name in ("java", "jarsigner", "keytool")
                )

            @property
            def jdk_root(self):
                return self.custody / "jdk"

            @property
            def bundletool_path(self):
                if self.fd < 0:
                    raise module.SignerError("held bundletool custody is not active")
                return pathlib.Path(f"/dev/fd/{self.fd}")

            @property
            def pass_fds(self):
                descriptors = list(self.private_tool_fds.values())
                if self.fd >= 0:
                    descriptors.append(self.fd)
                return tuple(descriptors)

            def jdk_tool_fd(self, name):
                return self.private_tool_fds[name]

            def __enter__(self):
                bindir = self.custody / "jdk" / "bin"
                bindir.mkdir(parents=True, mode=0o700)
                self.custody.chmod(0o700)
                (self.custody / "jdk").chmod(0o700)
                for name, original in tools.items():
                    private = bindir / name
                    private.write_bytes(pathlib.Path(original).read_bytes())
                    private.chmod(0o500)
                    self.private_tools[name] = str(private)
                    self.private_tool_fds[name] = os.open(
                        private, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                    )
                if self.bind_bundletool:
                    self.bundletool.write_bytes(bundletool.read_bytes())
                    self.bundletool.chmod(0o400)
                    self.fd = os.open(
                        self.bundletool, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                    )
                    self.bundletool.unlink()
                    self.bundle_stat = module._held_stat_identity(os.fstat(self.fd))
                self.token = module._ACTIVE_ANDROID_TOOLS.set(self)
                return self

            def revalidate(self, *, full_tree: bool = False):
                del full_tree
                if self.bind_bundletool:
                    info = os.fstat(self.fd)
                    if (
                        stat.S_IMODE(info.st_mode) != 0o400
                        or module._held_stat_identity(info) != self.bundle_stat
                        or hashlib.sha256(os.pread(self.fd, info.st_size, 0)).hexdigest()
                        != bundletool_digest
                    ):
                        raise module.SignerError("reviewed bundletool custody changed")
                for name, private in self.private_tools.items():
                    info = pathlib.Path(private).lstat()
                    if (
                        stat.S_IMODE(info.st_mode) != 0o500
                        or hashlib.sha256(pathlib.Path(private).read_bytes()).hexdigest()
                        != hashlib.sha256(pathlib.Path(tools[name]).read_bytes()).hexdigest()
                    ):
                        raise module.SignerError("reviewed JDK custody changed")

            def __exit__(self, exc_type, exc, traceback):
                try:
                    self.revalidate()
                finally:
                    if self.token is not None:
                        module._ACTIVE_ANDROID_TOOLS.reset(self.token)
                    if self.fd >= 0:
                        os.close(self.fd)
                    for descriptor in self.private_tool_fds.values():
                        os.close(descriptor)
                    self.private_tool_fds.clear()
                    for private in self.private_tools.values():
                        pathlib.Path(private).unlink()
                    (self.custody / "jdk" / "bin").rmdir()
                    (self.custody / "jdk").rmdir()
                    self.custody.rmdir()
                return False

        if runner is None:
            runner, seen = self.held_tool_runner(form)
        else:
            seen = []
        def fake_run(
            arguments,
            label,
            *,
            timeout=120,
            pass_fds=(),
            revalidate=None,
            executable_fd=None,
            watch_fds=(),
        ):
            if revalidate is not None:
                revalidate()
            try:
                completed = runner(
                    arguments,
                    timeout=timeout,
                    pass_fds=pass_fds,
                    executable_fd=executable_fd,
                    watch_fds=watch_fds,
                )
            except subprocess.TimeoutExpired as exc:
                raise module.SignerError(f"{label} timed out and failed closed") from exc
            except module.SignerError:
                raise
            except Exception as exc:
                raise module.SignerError(
                    f"{label} could not execute and failed closed"
                ) from exc
            finally:
                if revalidate is not None:
                    revalidate()
            if completed.returncode != 0:
                raise module.SignerError(f"{label} failed closed")
            return completed.stdout

        try:
            with (
                mock.patch.object(
                    self.module, "BUNDLETOOL_ALL_SHA256", bundletool_digest
                ),
                mock.patch.dict(
                    os.environ,
                    {self.module.BUNDLETOOL_ENV: str(bundletool)},
                    clear=False,
                ),
                mock.patch.object(
                    self.module, "_HeldAndroidVerificationTools", FakeHeldTools
                ),
                mock.patch.object(self.module, "_run", side_effect=fake_run),
            ):
                yield seen
        finally:
            pass

    def call_held_validator(
        self, source: pathlib.Path, target_id: str, *, source_fd: int | None = None
    ) -> dict[str, object]:
        close_source = source_fd is None
        if source_fd is None:
            source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(source_fd)
            return self.module.verify_held_aab_artifact(
                target_id=target_id,
                source_fd=source_fd,
                expected_identity=(info.st_dev, info.st_ino),
                expected_size=info.st_size,
                expected_sha256=hashlib.sha256(os.pread(source_fd, info.st_size, 0)).hexdigest(),
            )
        finally:
            if close_source:
                os.close(source_fd)

    def test_held_aab_api_validates_one_descriptor_snapshot_and_returns_canonical_evidence(
        self,
    ) -> None:
        source = self.write_aab("held-phone.aab", form="phone")
        with self.held_tool_context("phone") as seen:
            evidence = self.call_held_validator(
                source, "android-phone-tablet-aab"
            )
        self.assertTrue(evidence["ok"])
        self.assertEqual(
            evidence["contract"], self.module.HELD_AAB_VALIDATION_CONTRACT
        )
        self.assertEqual(evidence["target_id"], "android-phone-tablet-aab")
        self.assertEqual(
            evidence["artifact"]["sha256"], hashlib.sha256(source.read_bytes()).hexdigest()
        )
        self.assertEqual(evidence["package_identity"]["version_code"], 33)
        self.assertEqual(
            evidence["signing"]["jar_signature"], "jarsigner-strict-verified"
        )
        self.assertEqual(
            evidence["decoders"]["jdk_tree_sha256"],
            self.module.OWNER_JDK_TREE_SHA256,
        )
        self.assertEqual(
            evidence["decoders"]["jdk_tools_sha256"],
            dict(sorted(self.module.OWNER_JDK_TOOL_SHA256.items())),
        )
        self.assertEqual(evidence["upload_certificate_pin"]["sha256"], self.pin)
        self.assertEqual(
            evidence["upload_certificate_pin"]["source"],
            self.module.DESCRIPTOR_RELATIVE,
        )
        artifact_paths: list[str] = []
        for argv, kwargs in seen:
            if "-verify" in argv or "-printcert" in argv:
                artifact_paths.append(argv[-1])
            for value in argv:
                if value.startswith("--bundle="):
                    artifact_paths.append(value.split("=", 1)[1])
            for mode in kwargs.get("_pass_fd_modes", ()):
                self.assertIn(mode, {0o400, 0o500, 0o555})
        self.assertEqual(len(artifact_paths), 4)
        self.assertEqual(len(set(artifact_paths)), 1)
        self.assertTrue(artifact_paths[0].startswith("/dev/fd/"))

    def test_local_extra_accepts_only_zipalign_zero_padding(self) -> None:
        fields = self.module._zip_extra_fields
        for padding in (b"\x00", b"\x00\x00", b"\x00\x00\x00"):
            self.assertEqual(fields(padding, "local-file entry"), {})
        aligned = b"\x35\xd9\x02\x00\x00\x04" + b"\x00\x00"
        self.assertEqual(fields(aligned, "local-file entry"), {0xD935: b"\x00\x04"})
        for refused, label in (
            (b"\x00\x01", "local-file entry"),
            (b"\x00", "central-directory entry"),
            (b"\x35\xd9\x09\x00", "local-file entry"),
        ):
            with self.assertRaises(self.module.SignerError):
                fields(refused, label)

    def test_symbolic_manifest_attributes_compare_by_compiled_value(self) -> None:
        # aapt2 compiles these to integers; the held parser keeps the raw names and
        # bundletool prints the integer, so the cross-check compares canonical values.
        canonical = self.module._canonical_symbolic_value
        changes = "orientation|keyboardHidden|keyboard|screenSize|smallestScreenSize|locale|layoutDirection|fontScale|screenLayout|density|uiMode"
        self.assertEqual(canonical("configChanges", changes), canonical("configChanges", "0x40003fb4"))
        self.assertEqual(canonical("protectionLevel", "signature"), canonical("protectionLevel", "0x00000002"))
        self.assertEqual(canonical("launchMode", "singleTop"), canonical("launchMode", "1"))
        self.assertEqual(canonical("foregroundServiceType", "specialUse"), canonical("foregroundServiceType", "0x40000000"))
        self.assertEqual(canonical("windowSoftInputMode", "adjustResize"), canonical("windowSoftInputMode", "0x00000010"))
        self.assertNotEqual(canonical("protectionLevel", "signature"), canonical("protectionLevel", "0x00000003"))
        self.assertNotEqual(canonical("configChanges", "orientation|madeUp"), canonical("configChanges", "0x80"))
        self.assertEqual(canonical("label", "Win's VPN"), "Win's VPN")
        android = self.module.ANDROID_ATTRIBUTE_NAMESPACE
        held = (("activity", ((android + "launchMode", "singleTop"),)),)
        printed = (("activity", ((android + "launchMode", "1"),)),)
        self.assertEqual(self.module._canonical_projection(held), self.module._canonical_projection(printed))

    def test_held_aab_api_accepts_no_caller_selected_trust_or_tool_paths(self) -> None:
        signature = inspect.signature(self.module.verify_held_aab_artifact)
        self.assertEqual(
            list(signature.parameters),
            [
                "target_id",
                "source_fd",
                "expected_identity",
                "expected_size",
                "expected_sha256",
            ],
        )
        self.assertTrue(
            all(
                parameter.kind is inspect.Parameter.KEYWORD_ONLY
                for parameter in signature.parameters.values()
            )
        )

    def test_held_aab_api_accepts_each_exact_release_target(self) -> None:
        cases = (
            ("android-phone-tablet-aab", "phone", 33, "phone-tablet"),
            ("android-tv-aab", "tv", 3302, "tv"),
            ("wear-os-aab", "wear", 3301, "wear"),
        )
        for target_id, form, version_code, evidence_form in cases:
            with self.subTest(target_id=target_id):
                source = self.write_aab(f"held-{form}.aab", form=form)
                with self.held_tool_context(form):
                    evidence = self.call_held_validator(source, target_id)
                self.assertEqual(evidence["target_id"], target_id)
                self.assertEqual(
                    evidence["package_identity"],
                    {
                        "package": "org.winsvpn.app",
                        "version_name": "1.0.16",
                        "version_code": version_code,
                        "form": evidence_form,
                    },
                )

    def test_held_aab_api_uses_open_descriptor_not_replaced_source_path(self) -> None:
        source = self.write_aab("source-path.aab", form="phone")
        original = self.work / "source-path-original.aab"
        source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.rename(source, original)
            self.write_aab("source-path.aab", form="tv")
            with self.held_tool_context("phone"):
                evidence = self.call_held_validator(
                    source,
                    "android-phone-tablet-aab",
                    source_fd=source_fd,
                )
            self.assertEqual(evidence["package_identity"]["version_code"], 33)
        finally:
            os.close(source_fd)

    def test_held_aab_api_rejects_wrong_descriptor_identity(self) -> None:
        phone = self.write_aab("identity-phone.aab", form="phone")
        tv = self.write_aab("identity-tv.aab", form="tv")
        phone_fd = os.open(phone, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        tv_fd = os.open(tv, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            phone_info = os.fstat(phone_fd)
            with self.held_tool_context("tv"):
                with self.assertRaisesRegex(
                    self.module.SignerError, "descriptor identity is not exact"
                ):
                    self.module.verify_held_aab_artifact(
                        target_id="android-tv-aab",
                        source_fd=tv_fd,
                        expected_identity=(phone_info.st_dev, phone_info.st_ino),
                        expected_size=os.fstat(tv_fd).st_size,
                        expected_sha256=hashlib.sha256(tv.read_bytes()).hexdigest(),
                    )
        finally:
            os.close(phone_fd)
            os.close(tv_fd)

    def test_held_aab_api_rejects_caller_descriptor_rebinding_during_tool(self) -> None:
        phone = self.write_aab("rebound-phone.aab", form="phone")
        tv = self.write_aab("rebound-tv.aab", form="tv")
        source_fd = os.open(phone, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        source_info = os.fstat(source_fd)
        base_runner, _seen = self.held_tool_runner("phone")
        rebound = False

        def runner(arguments, **kwargs):
            nonlocal rebound
            argv = [str(value) for value in arguments]
            if "-verify" in argv and not rebound:
                rebound = True
                os.close(source_fd)
                replacement = os.open(tv, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
                if replacement != source_fd:
                    os.dup2(replacement, source_fd)
                    os.close(replacement)
            return base_runner(arguments, **kwargs)

        try:
            with self.held_tool_context("phone", runner=runner):
                with self.assertRaisesRegex(
                    self.module.SignerError,
                    "caller descriptor was closed|custody changed",
                ):
                    self.module.verify_held_aab_artifact(
                        target_id="android-phone-tablet-aab",
                        source_fd=source_fd,
                        expected_identity=(source_info.st_dev, source_info.st_ino),
                        expected_size=source_info.st_size,
                        expected_sha256=hashlib.sha256(phone.read_bytes()).hexdigest(),
                    )
        finally:
            try:
                os.close(source_fd)
            except OSError:
                pass

    def test_held_aab_api_rejects_source_mutation_during_external_tool(self) -> None:
        source = self.write_aab("mutated-source.aab", form="phone")
        original = source.read_bytes()
        base_runner, _seen = self.held_tool_runner("phone")
        mutated = False

        def runner(arguments, **kwargs):
            nonlocal mutated
            argv = [str(value) for value in arguments]
            if "-verify" in argv and not mutated:
                mutated = True
                with source.open("r+b") as stream:
                    stream.seek(0)
                    stream.write(b"X")
                    stream.flush()
                    os.fsync(stream.fileno())
                    stream.seek(0)
                    stream.write(original)
                    stream.truncate()
                    stream.flush()
                    os.fsync(stream.fileno())
            return base_runner(arguments, **kwargs)

        with self.held_tool_context("phone", runner=runner):
            with self.assertRaisesRegex(
                self.module.SignerError, "custody observed transient mutation|custody changed"
            ):
                self.call_held_validator(source, "android-phone-tablet-aab")

    def test_held_aab_api_private_snapshot_has_no_replaceable_path(self) -> None:
        source = self.write_aab("snapshot-swap.aab", form="phone")
        base_runner, _seen = self.held_tool_runner("phone")
        swapped = False

        def runner(arguments, **kwargs):
            nonlocal swapped
            argv = [str(value) for value in arguments]
            if "-verify" in argv and not swapped:
                swapped = True
                snapshot = pathlib.Path(argv[-1])
                self.assertEqual(snapshot.parent, pathlib.Path("/dev/fd"))
                with self.assertRaises(OSError):
                    os.rename(snapshot, snapshot.with_name("artifact.old"))
            return base_runner(arguments, **kwargs)

        with self.held_tool_context("phone", runner=runner):
            evidence = self.call_held_validator(
                source, "android-phone-tablet-aab"
            )
        self.assertTrue(swapped)
        self.assertTrue(evidence["ok"])

    def test_held_aab_api_rejects_cross_target_artifact(self) -> None:
        source = self.write_aab("phone-as-tv.aab", form="phone")
        with self.held_tool_context("phone"):
            with self.assertRaisesRegex(
                self.module.SignerError, "another target|another exact target"
            ):
                self.call_held_validator(source, "android-tv-aab")

    def test_held_aab_api_revalidates_and_cleans_up_after_signer_failure(self) -> None:
        source = self.write_aab("signer-failure.aab", form="phone")
        base_runner, _seen = self.held_tool_runner("phone")

        def runner(arguments, **kwargs):
            argv = [str(value) for value in arguments]
            if "-verify" in argv:
                return subprocess.CompletedProcess(argv, 1, b"jar is unsigned\n", None)
            return base_runner(arguments, **kwargs)

        temporary_root = pathlib.Path(tempfile.gettempdir())
        before = set(temporary_root.glob(f"{self.module.HELD_AAB_SNAPSHOT_PREFIX}*"))
        with self.held_tool_context("phone", runner=runner):
            with self.assertRaisesRegex(self.module.SignerError, "failed closed"):
                self.call_held_validator(source, "android-phone-tablet-aab")
        self.assertEqual(
            set(temporary_root.glob(f"{self.module.HELD_AAB_SNAPSHOT_PREFIX}*")), before
        )

    def test_held_aab_api_revalidates_and_cleans_up_after_timeout(self) -> None:
        source = self.write_aab("signer-timeout.aab", form="phone")
        base_runner, _seen = self.held_tool_runner("phone")

        def runner(arguments, **kwargs):
            argv = [str(value) for value in arguments]
            if "-verify" in argv:
                raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 0))
            return base_runner(arguments, **kwargs)

        temporary_root = pathlib.Path(tempfile.gettempdir())
        before = set(temporary_root.glob(f"{self.module.HELD_AAB_SNAPSHOT_PREFIX}*"))
        with self.held_tool_context("phone", runner=runner):
            with self.assertRaisesRegex(self.module.SignerError, "timed out"):
                self.call_held_validator(source, "android-phone-tablet-aab")
        self.assertEqual(
            set(temporary_root.glob(f"{self.module.HELD_AAB_SNAPSHOT_PREFIX}*")), before
        )

    def test_real_subprocess_stdout_and_stderr_floods_fail_closed(self) -> None:
        cases = (
            (1, "MAX_TOOL_STDOUT_BYTES", "stdout"),
            (2, "MAX_TOOL_STDERR_BYTES", "stderr"),
        )
        for descriptor, constant, stream in cases:
            with self.subTest(stream=stream), mock.patch.object(
                self.module, constant, 4096
            ), mock.patch.object(
                self.module,
                "_safe_tool_environment",
                return_value={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            ):
                script = (
                    "import os\n"
                    f"os.write({descriptor}, b'X' * 8192)\n"
                    "while True:\n"
                    f"    os.write({descriptor}, b'Y' * 8192)\n"
                )
                with mock.patch.object(
                    self.module.subprocess, "Popen", wraps=self.module.subprocess.Popen
                ) as popen:
                    with self.assertRaisesRegex(
                        self.module.SignerError, f"{stream} exceeded 4096 bytes"
                    ):
                        self.module._run(
                            [
                                self.module.sys.executable,
                                "-I",
                                "-S",
                                "-c",
                                script,
                            ],
                            f"hostile {stream} flood",
                            timeout=5,
                        )
                    popen.assert_called_once()

    def test_real_subprocess_deadline_kills_and_fails_closed(self) -> None:
        started = self.module.time.monotonic()
        with mock.patch.object(
            self.module,
            "_safe_tool_environment",
            return_value={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        ):
            with self.assertRaisesRegex(self.module.SignerError, "timed out"):
                self.module._run(
                    [
                        self.module.sys.executable,
                        "-I",
                        "-S",
                        "-c",
                        "import time; time.sleep(30)",
                    ],
                    "hostile deadline process",
                    timeout=1,
                )
        self.assertLess(self.module.time.monotonic() - started, 5)

    def test_setsid_descendant_holding_pipes_fails_closed_at_deadline(self) -> None:
        # A descendant that calls setsid() leaves the process group, so the
        # group kill cannot reach it (residual risk accepted by the owner
        # ruling). It still cannot make the run pass: while it holds the
        # output pipes the run fails closed at the deadline.
        pid_file = self.work / "descendant.pid"
        script = (
            "import os, pathlib, sys, time\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    os.setsid()\n"
            "    pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n"
            "    time.sleep(30)\n"
            "    os._exit(0)\n"
            "time.sleep(0.2)\n"
            "os._exit(0)\n"
        )
        started = self.module.time.monotonic()
        try:
            with mock.patch.object(
                self.module,
                "_safe_tool_environment",
                return_value={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            ):
                with self.assertRaisesRegex(self.module.SignerError, "timed out"):
                    self.module._run(
                        [
                            self.module.sys.executable,
                            "-I",
                            "-S",
                            "-c",
                            script,
                            str(pid_file),
                        ],
                        "leader-exited hostile descendant",
                        timeout=2,
                    )
            self.assertLess(self.module.time.monotonic() - started, 6)
        finally:
            if pid_file.exists():
                try:
                    os.kill(int(pid_file.read_text()), 9)
                except ProcessLookupError:
                    pass

    def test_held_aab_api_revalidates_and_cleans_up_after_runner_exception(self) -> None:
        source = self.write_aab("runner-exception.aab", form="phone")
        base_runner, _seen = self.held_tool_runner("phone")

        def runner(arguments, **kwargs):
            argv = [str(value) for value in arguments]
            if "-printcert" in argv:
                raise RuntimeError("synthetic runner exception")
            return base_runner(arguments, **kwargs)

        temporary_root = pathlib.Path(tempfile.gettempdir())
        before = set(temporary_root.glob(f"{self.module.HELD_AAB_SNAPSHOT_PREFIX}*"))
        with self.held_tool_context("phone", runner=runner):
            with self.assertRaisesRegex(self.module.SignerError, "could not execute"):
                self.call_held_validator(source, "android-phone-tablet-aab")
        self.assertEqual(
            set(temporary_root.glob(f"{self.module.HELD_AAB_SNAPSHOT_PREFIX}*")), before
        )

    def test_held_aab_api_rejects_read_write_source_descriptor(self) -> None:
        source = self.write_aab("read-write-source.aab", form="phone")
        source_fd = os.open(source, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(source_fd)
            with self.held_tool_context("phone"):
                with self.assertRaisesRegex(
                    self.module.SignerError, "source descriptor identity is not exact"
                ):
                    self.module.verify_held_aab_artifact(
                        target_id="android-phone-tablet-aab",
                        source_fd=source_fd,
                        expected_identity=(info.st_dev, info.st_ino),
                        expected_size=info.st_size,
                        expected_sha256=hashlib.sha256(
                            os.pread(source_fd, info.st_size, 0)
                        ).hexdigest(),
                    )
        finally:
            os.close(source_fd)

    def test_held_aab_api_rejects_final_evidence_window_mutation(self) -> None:
        source = self.write_aab("final-window-source.aab", form="phone")
        original_builder = self.module._canonical_held_aab_evidence

        def mutate_after_evidence(*args, **kwargs):
            evidence = original_builder(*args, **kwargs)
            with source.open("r+b") as stream:
                stream.seek(0)
                stream.write(b"Z")
                stream.flush()
                os.fsync(stream.fileno())
            return evidence

        with self.held_tool_context("phone"):
            with mock.patch.object(
                self.module,
                "_canonical_held_aab_evidence",
                side_effect=mutate_after_evidence,
            ):
                with self.assertRaisesRegex(
                    self.module.SignerError,
                    "custody observed transient mutation|custody changed",
                ):
                    self.call_held_validator(source, "android-phone-tablet-aab")

    def test_upload_certificate_pin_does_not_reopen_mutable_build_script(self) -> None:
        source = (ROOT / "tools/verify_android_aab_signers.py").read_text(
            encoding="ascii"
        )
        self.assertNotIn("UPLOAD_PIN_SOURCE", source)
        self.assertNotIn("build_android_release_macos.sh", source)
        with mock.patch.object(
            pathlib.Path,
            "read_text",
            side_effect=AssertionError("mutable certificate-pin source reopened"),
        ):
            self.pin_patch.stop()
            try:
                self.assertEqual(
                    self.module._reviewed_upload_certificate(),
                    self.module.REVIEWED_UPLOAD_CERTIFICATE_SHA256,
                )
            finally:
                self.pin_patch.start()

    def test_pinned_jdk_support_tree_and_tools_are_retained(self) -> None:
        pinned_root = self.module._pinned_jdk_identity()["root"]
        if not pinned_root.exists():
            with self.assertRaisesRegex(self.module.SignerError, "absent or unsafe"):
                with self.module._HeldAndroidVerificationTools(bind_bundletool=False):
                    pass
            return
        with self.module._HeldAndroidVerificationTools(bind_bundletool=False) as held:
            self.assertEqual(
                held.jdk_tools,
                tuple(
                    str(pinned_root / "bin" / name)
                    for name in ("java", "jarsigner", "keytool")
                ),
            )
            self.assertEqual(set(held._tool_fds), {"java", "jarsigner", "keytool"})
            self.assertFalse(held._private_tool_fds)
            self.assertIsNone(held._private_jdk_path)
            self.assertEqual(
                set(held.pass_fds),
                {
                    held.jdk_tool_fd("java"),
                    held.jdk_tool_fd("jarsigner"),
                    held.jdk_tool_fd("keytool"),
                },
            )
            self.assertGreater(len(held._directories), 1)
            held.revalidate(full_tree=True)

    def test_missing_pinned_jdk_fails_closed(self) -> None:
        missing = self.work.resolve(strict=True) / "missing-test-jdk"
        with mock.patch.dict(
            os.environ, {self.module.JDK_ROOT_ENV: str(missing)}, clear=False
        ):
            with self.assertRaisesRegex(self.module.SignerError, "absent or unsafe"):
                with self.module._HeldAndroidVerificationTools(bind_bundletool=False):
                    pass

    def test_tool_context_exit_performs_final_full_tree_revalidation_and_cleanup(self) -> None:
        if not self.module._pinned_jdk_identity()["root"].exists():
            self.skipTest("pinned Android JDK is absent")
        held = self.module._HeldAndroidVerificationTools(bind_bundletool=False)
        held.__enter__()
        self.assertIs(self.module._ACTIVE_ANDROID_TOOLS.get(), held)
        with mock.patch.object(
            held,
            "_tree_state",
            return_value=("0" * 64, dict(held._tree_inventory)),
        ):
            with self.assertRaisesRegex(
                self.module.SignerError, "support-tree custody changed"
            ):
                held.__exit__(None, None, None)
        self.assertIsNone(self.module._ACTIVE_ANDROID_TOOLS.get())
        self.assertFalse(held._directories)
        self.assertFalse(held._tool_fds)

    def test_post_hash_bundletool_path_replacement_fails_closed(self) -> None:
        bundletool = self.work / "replaceable-bundletool.jar"
        bundletool.write_bytes(b"reviewed bundletool bytes")
        bundletool.chmod(0o444)
        digest = hashlib.sha256(bundletool.read_bytes()).hexdigest()
        replacement = self.work / "replacement-bundletool.jar"
        replacement.write_bytes(b"attacker bundletool bytes")
        replacement.chmod(0o444)
        with (
            mock.patch.object(self.module, "BUNDLETOOL_ALL_SHA256", digest),
            mock.patch.dict(
                os.environ,
                {self.module.BUNDLETOOL_ENV: str(bundletool)},
                clear=False,
            ),
        ):
            held = self.module._HeldAndroidVerificationTools()
            held.__enter__()
            try:
                calls = []

                def version_runner(
                    arguments,
                    label,
                    *,
                    timeout=120,
                    pass_fds=(),
                    revalidate=None,
                    executable_fd=None,
                    watch_fds=(),
                ):
                    calls.append(
                        (
                            [str(value) for value in arguments],
                            {"label": label, "timeout": timeout, "pass_fds": pass_fds},
                        )
                    )
                    if revalidate is not None:
                        revalidate()
                        revalidate()
                    return b"1.18.3\n"

                with mock.patch.object(self.module, "_run", side_effect=version_runner):
                    executed = self.module._assert_frozen_bundletool()
                self.assertEqual(
                    executed,
                    held._bundle_directory_path / self.module.BUNDLETOOL_SNAPSHOT_NAME,
                )
                self.assertEqual(
                    os.listdir(held._bundle_directory_path),
                    [self.module.BUNDLETOOL_SNAPSHOT_NAME],
                )
                self.assertEqual(stat.S_IMODE(executed.lstat().st_mode), 0o400)
                self.assertEqual(
                    stat.S_IMODE(held._bundle_directory_path.lstat().st_mode), 0o500
                )
                self.assertEqual(executed.read_bytes(), b"reviewed bundletool bytes")
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0][0][2], str(executed))
                self.assertIn(held._bundle_snapshot_fd, calls[0][1]["pass_fds"])
                original = bundletool.with_suffix(".original")
                os.rename(bundletool, original)
                os.rename(replacement, bundletool)
                with self.assertRaisesRegex(
                    self.module.SignerError,
                    "bundletool .*changed|bundletool .*substituted|bundletool custody changed",
                ):
                    held.revalidate(full_tree=False)
            finally:
                held.close()

    def test_private_bundletool_is_unlinked_and_descriptor_bound(self) -> None:
        source = self.write_aab("private-bundletool-swap.aab", form="phone")
        base_runner, _seen = self.held_tool_runner("phone")
        observed_descriptor = False

        def runner(arguments, **kwargs):
            nonlocal observed_descriptor
            argv = [str(value) for value in arguments]
            if argv[-1:] == ["version"] and not observed_descriptor:
                observed_descriptor = True
                private_jar = pathlib.Path(argv[2])
                self.assertTrue(str(private_jar).startswith("/dev/fd/"))
                self.assertEqual(
                    private_jar.read_bytes(), b"reviewed synthetic bundletool fixture"
                )
            return base_runner(arguments, **kwargs)

        with self.held_tool_context("phone", runner=runner):
            self.call_held_validator(source, "android-phone-tablet-aab")
        self.assertTrue(observed_descriptor)

    def test_real_java_execution_uses_pinned_path_and_retained_custody(
        self,
    ) -> None:
        pinned_root = self.module._pinned_jdk_identity()["root"]
        if not pinned_root.exists():
            self.skipTest("pinned Android JDK is absent")
        held = self.module._HeldAndroidVerificationTools(bind_bundletool=False)
        held.__enter__()
        try:
            self.assertIsNone(held._private_jdk_path)
            self.assertEqual(held.jdk_tools[0], str(pinned_root / "bin" / "java"))
            java_info = pathlib.Path(held.jdk_tools[0]).stat()
            self.assertIn(java_info.st_uid, {0, os.geteuid()})
            self.assertEqual(stat.S_IMODE(java_info.st_mode) & 0o022, 0)
            revalidations = []

            def revalidate() -> None:
                revalidations.append(True)
                held.revalidate(full_tree=True)

            output = self.module._run(
                [held.jdk_tools[0], "-version"],
                "retained pinned JDK executable",
                timeout=60,
                pass_fds=held.pass_fds,
                watch_fds=held.pass_fds,
                revalidate=revalidate,
            )
            self.assertEqual(output, b"")
            self.assertEqual(len(revalidations), 2)
        finally:
            held.close()

    def test_inspector_source_does_not_use_apkanalyzer(self) -> None:
        source = (ROOT / "tools/verify_android_aab_signers.py").read_text(encoding="utf-8")
        self.assertNotIn("apkanalyzer", source)
        self.assertIn("closed-format", source)
        self.assertIn("_private_held_copy", source)
        self.assertIn(self.module.BUNDLETOOL_VERSION, source)
        self.assertIn(self.module.BUNDLETOOL_ALL_SHA256, source)

    def test_phone_tv_wear_require_architecture_package_and_version(self) -> None:
        cases = (
            ("android-phone-tablet-aab", "phone", 33, self.module.PHONE_TV_ABIS),
            ("android-tv-aab", "tv", 3302, self.module.PHONE_TV_ABIS),
            ("wear-os-aab", "wear", 3301, self.module.WEAR_ABIS),
        )
        for target, form, version_code, abis in cases:
            with self.subTest(target=target):
                analysis = self.module.analyze_held_aab(
                    self.write_aab(f"{form}.aab", form=form).read_bytes()
                )
                self.assertEqual(analysis["package"], "org.winsvpn.app")
                self.assertEqual(analysis["version_name"], "1.0.16")
                self.assertEqual(analysis["version_code"], version_code)
                self.assertEqual(analysis["abis"], abis)
                self.assertEqual(analysis["modules"], frozenset({"base"}))
                self.assertEqual(analysis["certificate_sha256"], self.pin)
                self.module._enforce_target_identity(target, analysis)

    def test_release_identity_is_source_bound_and_never_rereads_mutable_json(self) -> None:
        self.assertFalse(hasattr(self.module, "RELEASE_IDENTITY_PATH"))
        expected = {
            "android-phone-tablet-aab": ("org.winsvpn.app", "1.0.16", 33),
            "android-tv-aab": ("org.winsvpn.app", "1.0.16", 3302),
            "wear-os-aab": ("org.winsvpn.app", "1.0.16", 3301),
        }
        with (
            mock.patch.object(
                pathlib.Path,
                "read_text",
                side_effect=AssertionError("mutable release identity was reread"),
            ),
            mock.patch.object(
                self.module.json,
                "loads",
                side_effect=AssertionError("caller-selected identity JSON was decoded"),
            ),
        ):
            observed = {
                target: self.module._reviewed_target_identity(target)
                for target in expected
            }
            self.assertEqual(observed, expected)
            self.assertEqual(self.module.canonical_android_release(), "1.0.16+33")

    def test_release_identity_rejects_exact_source_byte_drift(self) -> None:
        for relative in self.module.RELEASE_IDENTITY_SOURCE_SHA256:
            source = ROOT / relative
            target = self.work / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        with mock.patch.object(self.module, "ROOT", self.work):
            self.assertEqual(
                self.module._source_bound_android_release_identity(),
                ("org.winsvpn.app", "1.0.16", 33, 3302),
            )
            pubspec = self.work / "pubspec.yaml"
            pubspec.write_bytes(pubspec.read_bytes().replace(b"1.0.16+33", b"1.0.16+34"))
            with self.assertRaisesRegex(
                self.module.SignerError, "release identity source hash changed"
            ):
                self.module._source_bound_android_release_identity()

    def test_malformed_bundle_is_not_a_zip(self) -> None:
        with self.assertRaisesRegex(self.module.SignerError, "invalid AAB ZIP"):
            self.module.analyze_held_aab(b"not-a-bundle")

    def test_zip_bomb_and_path_limits_run_before_testzip_decompression(self) -> None:
        def raw_zip(
            name: str,
            members: tuple[tuple[str, bytes], ...],
            *,
            compression: int = zipfile.ZIP_STORED,
        ) -> bytes:
            path = self.work / name
            with zipfile.ZipFile(path, "w", compression=compression) as archive:
                for member, payload in members:
                    archive.writestr(member, payload)
            return path.read_bytes()

        cases = (
            (
                "entry count",
                raw_zip("entries.zip", (("a", b"a"), ("b", b"b"))),
                "MAX_AAB_ZIP_ENTRIES",
                1,
                "entry count",
            ),
            (
                "member size",
                raw_zip("member.zip", (("a", b"a" * 9),)),
                "MAX_AAB_ZIP_MEMBER_BYTES",
                8,
                "member exceeds",
            ),
            (
                "aggregate size",
                raw_zip("aggregate.zip", (("a", b"a" * 6), ("b", b"b" * 6))),
                "MAX_AAB_ZIP_TOTAL_BYTES",
                10,
                "aggregate size",
            ),
            (
                "compression ratio",
                raw_zip(
                    "ratio.zip",
                    (("a", b"A" * 4096),),
                    compression=zipfile.ZIP_DEFLATED,
                ),
                "MAX_AAB_ZIP_COMPRESSION_RATIO",
                2,
                "compression ratio",
            ),
            (
                "casefold alias",
                raw_zip("casefold.zip", (("base/File", b"a"), ("base/file", b"b"))),
                None,
                None,
                "path alias",
            ),
            (
                "unsafe path",
                raw_zip("path.zip", (("base/../manifest", b"a"),)),
                None,
                None,
                "path alias",
            ),
        )
        for label, payload, constant, value, error in cases:
            with self.subTest(limit=label):
                patches = (
                    contextlib.nullcontext()
                    if constant is None
                    else mock.patch.object(self.module, constant, value)
                )
                with patches, mock.patch.object(
                    zipfile.ZipFile,
                    "testzip",
                    side_effect=AssertionError("testzip ran before ZIP prevalidation"),
                ):
                    with self.assertRaisesRegex(self.module.SignerError, error):
                        self.module._open_held_zip(payload)

    def test_nested_archive_bomb_is_rejected_before_outer_testzip(self) -> None:
        inner_path = self.work / "inner-bomb.zip"
        with zipfile.ZipFile(
            inner_path, "w", compression=zipfile.ZIP_DEFLATED
        ) as inner:
            inner.writestr("payload", b"A" * 4096)
        outer_path = self.work / "outer-bomb.zip"
        with zipfile.ZipFile(outer_path, "w") as outer:
            outer.writestr("base/assets/payload.bin", inner_path.read_bytes())
        with (
            mock.patch.object(self.module, "MAX_AAB_ZIP_COMPRESSION_RATIO", 2),
            mock.patch.object(
                zipfile.ZipFile,
                "testzip",
                side_effect=AssertionError("outer testzip ran before nested prevalidation"),
            ),
        ):
            with self.assertRaisesRegex(
                self.module.SignerError, "compression ratio"
            ):
                self.module._open_held_zip(outer_path.read_bytes())

    def test_malformed_proto_manifest_fails_closed(self) -> None:
        members = self.members_for()
        members[self.module.MANIFEST_MEMBER] = b"\x03\x00\x08\x00not-proto"
        members = self.jar_wrap(
            {
                name: data
                for name, data in members.items()
                if not name.startswith("META-INF/")
            },
            self.pkcs7,
        )
        with self.assertRaisesRegex(self.module.SignerError, "APK binary XML"):
            self.module.analyze_held_aab(self.write_aab("axml.aab", members).read_bytes())

    def test_duplicate_modules_fail_closed(self) -> None:
        extra = self.members_for()
        unsigned = {
            name: data
            for name, data in extra.items()
            if not name.startswith("META-INF/")
        }
        unsigned["BASE/root/file.txt"] = b"other-module"
        members = self.jar_wrap(unsigned, self.pkcs7)
        with self.assertRaisesRegex(self.module.SignerError, "duplicate modules"):
            self.module.analyze_held_aab(
                self.write_aab("duplicate-modules.aab", members).read_bytes()
            )

    def test_path_aliases_fail_closed(self) -> None:
        cases = (
            ("base/foo/../manifest/AndroidManifest.xml", b"alias"),
            ("base/./lib/arm64-v8a/libapp.so", b"native"),
            ("base//lib/arm64-v8a/libapp.so", b"native"),
        )
        for alias, payload in cases:
            with self.subTest(alias=alias):
                unsigned = {
                    name: data
                    for name, data in self.members_for().items()
                    if not name.startswith("META-INF/")
                }
                unsigned[alias] = payload
                members = self.jar_wrap(unsigned, self.pkcs7)
                with self.assertRaisesRegex(self.module.SignerError, "path alias"):
                    self.module.analyze_held_aab(
                        self.write_aab("alias.aab", members).read_bytes()
                    )

        unsigned = {
            name: data
            for name, data in self.members_for().items()
            if not name.startswith("META-INF/")
        }
        unsigned["base\\root\\alias.txt"] = b"alias"
        members = self.jar_wrap(unsigned, self.pkcs7)
        path = self.work / "backslash.aab"
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in members.items():
                if "\\" in name:
                    archive.writestr(zipfile.ZipInfo(name), data)
                else:
                    archive.writestr(name, data)
        with self.assertRaisesRegex(self.module.SignerError, "path alias"):
            self.module.analyze_held_aab(path.read_bytes())

    def test_signer_substitution_fails_closed(self) -> None:
        other = fake_pkcs7(fake_cert("OtherUpload"))
        unsigned = {
            name: data
            for name, data in self.members_for().items()
            if not name.startswith("META-INF/")
        }
        members = self.jar_wrap(unsigned, self.pkcs7)
        members["META-INF/OTHER.RSA"] = other
        members["META-INF/OTHER.SF"] = members["META-INF/UPLOAD.SF"]
        with self.assertRaisesRegex(self.module.SignerError, "exactly one signature block"):
            self.module.analyze_held_aab(
                self.write_aab("substituted.aab", members).read_bytes()
            )
        swapped = self.jar_wrap(unsigned, other)
        analysis = self.module.analyze_held_aab(
            self.write_aab("wrong-cert.aab", swapped).read_bytes()
        )
        with self.assertRaisesRegex(self.module.SignerError, "reviewed upload certificate"):
            self.module._enforce_target_identity("android-phone-tablet-aab", analysis)

    def test_debug_signer_fails_closed(self) -> None:
        debug = fake_pkcs7(fake_cert("Android Debug"))
        unsigned = {
            name: data
            for name, data in self.members_for().items()
            if not name.startswith("META-INF/")
        }
        with self.assertRaisesRegex(self.module.SignerError, "debug signer"):
            self.module.analyze_held_aab(
                self.write_aab("debug.aab", self.jar_wrap(unsigned, debug)).read_bytes()
            )

    def test_wrong_package_and_version_fail_closed(self) -> None:
        cases = (
            {"package": "org.winsvpn.other"},
            {"version_name": "9.9.9"},
            {"version_code": 999},
        )
        for override in cases:
            with self.subTest(override=override):
                analysis = self.module.analyze_held_aab(
                    self.write_aab(
                        "wrong.aab",
                        self.members_for(form="phone", **override),
                    ).read_bytes()
                )
                with self.assertRaisesRegex(self.module.SignerError, "version identity"):
                    self.module._enforce_target_identity(
                        "android-phone-tablet-aab", analysis
                    )

    def test_bundletool_disagreement_fails_closed(self) -> None:
        data = self.write_aab("held.aab", form="phone").read_bytes()
        analysis = self.module.analyze_held_aab(data)
        xml = self.bundletool_manifest_xml("phone").replace(
            b'package="org.winsvpn.app"', b'package="org.winsvpn.other"'
        )
        with mock.patch.object(self.module, "_bundletool_dump_manifest", return_value=xml):
            with self.assertRaisesRegex(self.module.SignerError, "disagrees"):
                self.module._cross_check_bundletool_identity(data, analysis)

    def test_bundletool_landscape_disagreement_fails_closed(self) -> None:
        data = self.write_aab("tv-held.aab", form="tv").read_bytes()
        analysis = self.module.analyze_held_aab(data)
        xml = self.bundletool_manifest_xml("tv").replace(
            b' android:screenOrientation="landscape"', b""
        )
        with mock.patch.object(self.module, "_bundletool_dump_manifest", return_value=xml):
            with self.assertRaisesRegex(self.module.SignerError, "manifest posture disagrees"):
                self.module._cross_check_bundletool_identity(data, analysis)

    def test_bundletool_rejects_every_security_posture_disagreement(self) -> None:
        android = self.module.ANDROID
        cases = (
            ("package", "phone", ".", "package", "org.winsvpn.other"),
            ("version name", "phone", ".", android + "versionName", "9.9.9"),
            ("version code", "phone", ".", android + "versionCode", "31"),
            (
                "permission",
                "phone",
                "uses-permission",
                android + "name",
                "android.permission.ACCESS_FINE_LOCATION",
            ),
            (
                "service name",
                "phone",
                "./application/service",
                android + "name",
                "org.winsvpn.app.OtherService",
            ),
            (
                "VpnService permission",
                "phone",
                "./application/service",
                android + "permission",
                "android.permission.INTERNET",
            ),
            (
                "VpnService exported",
                "phone",
                "./application/service",
                android + "exported",
                "true",
            ),
            (
                "VpnService action",
                "phone",
                "./application/service/intent-filter/action",
                android + "name",
                "android.net.OtherService",
            ),
            (
                "activity exported",
                "phone",
                "./application/activity",
                android + "exported",
                "false",
            ),
            (
                "activity category",
                "phone",
                "./application/activity/intent-filter/category",
                android + "name",
                "android.intent.category.DEFAULT",
            ),
            (
                "activity action",
                "phone",
                "./application/activity/intent-filter/action",
                android + "name",
                "android.intent.action.VIEW",
            ),
            (
                "feature required",
                "tv",
                "uses-feature",
                android + "required",
                "true",
            ),
            (
                "application label",
                "phone",
                "application",
                android + "label",
                "Win's VPN",
            ),
            (
                "application icon",
                "phone",
                "application",
                android + "icon",
                "@mipmap/other",
            ),
            (
                "application banner",
                "tv",
                "application",
                android + "banner",
                "@drawable/other",
            ),
            (
                "debuggable",
                "phone",
                "application",
                android + "debuggable",
                "true",
            ),
            (
                "cleartext",
                "phone",
                "application",
                android + "usesCleartextTraffic",
                "true",
            ),
            (
                "network security config",
                "phone",
                "application",
                android + "networkSecurityConfig",
                "@xml/other",
            ),
            (
                "minimum SDK",
                "phone",
                "uses-sdk",
                android + "minSdkVersion",
                "23",
            ),
            (
                "target SDK",
                "phone",
                "uses-sdk",
                android + "targetSdkVersion",
                "35",
            ),
            (
                "TV trait",
                "tv",
                "./application/activity/intent-filter/category",
                android + "name",
                "android.intent.category.LAUNCHER",
            ),
            (
                "Wear trait",
                "wear",
                "./application/meta-data",
                android + "value",
                "true",
            ),
        )
        for label, form, path, attribute, value in cases:
            with self.subTest(posture=label):
                data = self.write_aab(f"posture-{form}.aab", form=form).read_bytes()
                analysis = self.module.analyze_held_aab(data)
                root = ET.fromstring(self.bundletool_manifest_xml(form))
                node = root if path == "." else root.find(path)
                self.assertIsNotNone(node)
                node.set(attribute, value)
                with self.assertRaisesRegex(self.module.SignerError, "disagrees"):
                    self.module._cross_check_bundletool_manifest(
                        ET.tostring(root, encoding="utf-8"), analysis
                    )

    def test_bundletool_rejects_complete_component_and_intent_data_drift(self) -> None:
        data = self.write_aab("complete-posture.aab", form="phone").read_bytes()
        analysis = self.module.analyze_held_aab(data)
        android = self.module.ANDROID

        def add_receiver(root: ET.Element) -> None:
            application = root.find("application")
            self.assertIsNotNone(application)
            ET.SubElement(
                application,
                "receiver",
                {android + "name": "org.winsvpn.app.HostileReceiver", android + "exported": "true"},
            )

        def add_provider(root: ET.Element) -> None:
            application = root.find("application")
            self.assertIsNotNone(application)
            ET.SubElement(
                application,
                "provider",
                {
                    android + "name": "org.winsvpn.app.HostileProvider",
                    android + "authorities": "org.winsvpn.app.hostile",
                    android + "exported": "true",
                },
            )

        def add_permission_variant(root: ET.Element) -> None:
            root.append(
                ET.Element(
                    "uses-permission-sdk-23",
                    {android + "name": "android.permission.ACCESS_FINE_LOCATION"},
                )
            )

        def add_intent_data(root: ET.Element) -> None:
            intent = root.find("./application/activity/intent-filter")
            self.assertIsNotNone(intent)
            ET.SubElement(
                intent,
                "data",
                {android + "scheme": "https", android + "host": "attacker.invalid"},
            )

        def change_application_security(root: ET.Element) -> None:
            application = root.find("application")
            self.assertIsNotNone(application)
            application.set(android + "allowBackup", "true")

        for label, mutate in (
            ("receiver", add_receiver),
            ("provider", add_provider),
            ("permission variant", add_permission_variant),
            ("intent data", add_intent_data),
            ("application security", change_application_security),
        ):
            with self.subTest(posture=label):
                root = ET.fromstring(self.bundletool_manifest_xml("phone"))
                mutate(root)
                with self.assertRaisesRegex(self.module.SignerError, "disagrees"):
                    self.module._cross_check_bundletool_manifest(
                        ET.tostring(root, encoding="utf-8"), analysis
                    )

    def test_proto_duplicate_scalar_fields_fail_closed(self) -> None:
        attribute = self.module.encode_xml_attribute(
            "name", "value", namespace=self.module.ANDROID_NS, resource_id=1
        )
        duplicate_attribute_fields = (
            self.module._ld(1, b"duplicate-namespace"),
            self.module._ld(2, b"duplicate-name"),
            self.module._ld(3, b"duplicate-value"),
            self.module._varint_field(5, 2),
        )
        for duplicate in duplicate_attribute_fields:
            with self.subTest(attribute_field=duplicate):
                with self.assertRaisesRegex(
                    self.module.SignerError, "attribute scalar is duplicated"
                ):
                    self.module._decode_xml_attribute(attribute + duplicate)
        element = self.module.encode_xml_element("manifest", [], [], namespace="urn:test")
        for duplicate in (
            self.module._ld(2, b"urn:other"),
            self.module._ld(3, b"application"),
        ):
            with self.subTest(element_field=duplicate):
                with self.assertRaisesRegex(
                    self.module.SignerError, "element scalar is duplicated"
                ):
                    self.module._decode_xml_element(element + duplicate)

    def test_bundletool_required_security_fields_must_decode(self) -> None:
        data = self.write_aab("required-fields.aab", form="phone").read_bytes()
        analysis = self.module.analyze_held_aab(data)
        android = self.module.ANDROID
        cases = (
            ("integer", "uses-sdk", android + "targetSdkVersion", "android-36"),
            ("boolean", "./application/service", android + "exported", "sometimes"),
        )
        for label, path, attribute, value in cases:
            with self.subTest(field_type=label):
                root = ET.fromstring(self.bundletool_manifest_xml("phone"))
                node = root.find(path)
                self.assertIsNotNone(node)
                node.set(attribute, value)
                with self.assertRaisesRegex(self.module.SignerError, f"decoded {label}"):
                    self.module._cross_check_bundletool_manifest(
                        ET.tostring(root, encoding="utf-8"), analysis
                    )

    def test_tv_artifact_rejected_as_phone(self) -> None:
        analysis = self.module.analyze_held_aab(
            self.write_aab(
                "tv-as-phone.aab",
                self.members_for(form="tv", version_code=33),
            ).read_bytes()
        )
        with self.assertRaisesRegex(self.module.SignerError, "another exact target"):
            self.module._enforce_target_identity("android-phone-tablet-aab", analysis)

    def test_missing_bundletool_fails_closed(self) -> None:
        path = self.write_aab("held.aab", form="phone")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(self.module.BUNDLETOOL_ENV, None)
        with self.assertRaisesRegex(
            self.module.SignerError, "retained Android JDK and bundletool custody"
        ):
                self.module._verify_target_identity("android-phone-tablet-aab", path)

    def test_current_byte_revalidation_detects_replacement(self) -> None:
        path = self.write_aab("mutating.aab", form="phone")
        original = path.read_bytes()
        real_analyze = self.module.analyze_held_aab

        def mutate(data: bytes) -> dict[str, object]:
            path.write_bytes(original + b"tamper")
            return real_analyze(data)

        with (
            mock.patch.object(self.module, "_assert_frozen_bundletool"),
            mock.patch.object(self.module, "_cross_check_bundletool_identity"),
            mock.patch.object(self.module, "analyze_held_aab", side_effect=mutate),
        ):
            with self.assertRaisesRegex(self.module.SignerError, "current bytes changed"):
                self.module._verify_target_identity("android-phone-tablet-aab", path)

    def test_identity_inspection_revalidates_unchanged_bytes(self) -> None:
        path = self.write_aab("stable.aab", form="phone")
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        with (
            mock.patch.object(self.module, "_assert_frozen_bundletool"),
            mock.patch.object(self.module, "_cross_check_bundletool_identity"),
        ):
            self.module._verify_target_identity("android-phone-tablet-aab", path)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)

    def test_phone_tv_aab_requires_r8_engines_permissions_and_vpn(self) -> None:
        for target, form in (
            ("android-phone-tablet-aab", "phone"),
            ("android-tv-aab", "tv"),
        ):
            with self.subTest(target=target):
                analysis = self.module.analyze_held_aab(
                    self.write_aab(f"{form}-ready.aab", form=form).read_bytes()
                )
                self.assertTrue(analysis["metadata"]["proguard_map"])
                self.assertEqual(analysis["r8"]["ok"], True)
                self.assertGreaterEqual(analysis["r8"]["class_mapping_count"], 32)
                self.module._enforce_target_identity(target, analysis)

    def test_tv_requires_landscape_in_produced_manifest_bytes(self) -> None:
        analysis = self.module.analyze_held_aab(
            self.write_aab("tv-landscape.aab", form="tv").read_bytes()
        )
        self.assertEqual(
            analysis["activity_orientations"]["org.winsvpn.app.MainActivity"],
            "landscape",
        )
        missing = self.module.analyze_held_aab(
            self.write_aab(
                "tv-missing-landscape.aab",
                self.members_for(
                    form="tv",
                    tv_screen_orientation=None,
                    tv_compiled_orientation=None,
                ),
            ).read_bytes()
        )
        self.assertIsNone(
            missing["activity_orientations"]["org.winsvpn.app.MainActivity"]
        )
        with self.assertRaisesRegex(self.module.SignerError, "must be landscape"):
            self.module._enforce_target_identity("android-tv-aab", missing)

    def test_tv_rejects_conflicting_raw_and_compiled_orientation(self) -> None:
        path = self.write_aab(
            "tv-conflicting-landscape.aab",
            self.members_for(
                form="tv",
                tv_screen_orientation="landscape",
                tv_compiled_orientation=1,
            ),
        )
        with self.assertRaisesRegex(
            self.module.SignerError, "raw and compiled values disagree"
        ):
            self.module.analyze_held_aab(path.read_bytes())

    def test_tv_rejects_uncompiled_or_unbound_orientation(self) -> None:
        cases = (
            {
                "name": "tv-uncompiled-landscape.aab",
                "tv_compiled_orientation": None,
            },
            {
                "name": "tv-unbound-landscape.aab",
                "tv_bind_screen_orientation": False,
            },
        )
        for case in cases:
            with self.subTest(name=case["name"]):
                name = str(case["name"])
                options = {
                    key: value for key, value in case.items() if key != "name"
                }
                path = self.write_aab(
                    name,
                    self.members_for(form="tv", **options),
                )
            with self.assertRaisesRegex(
                self.module.SignerError,
                "screenOrientation attribute is malformed|compiled identity is not canonical",
                ):
                    self.module.analyze_held_aab(path.read_bytes())

        unsupported = self.module.encode_xml_attribute(
            "screenOrientation",
            "landscape",
            namespace=self.module.ANDROID_NS,
            resource_id=self.module.ATTR_SCREEN_ORIENTATION,
            compiled=self.module._ld(1, b""),
        )
        with self.assertRaisesRegex(
            self.module.SignerError,
            "screenOrientation attribute is malformed|compiled identity is not canonical",
        ):
            self.module._decode_xml_attribute(unsupported)

    def test_tv_requires_landscape_on_actual_leanback_launcher(self) -> None:
        leanback = self.activity(
            "org.winsvpn.app.TvLauncherActivity",
            ("android.intent.category.LEANBACK_LAUNCHER",),
        )
        manifest = self.proto_manifest(
            form="tv",
            version_code=3302,
            tv_main_categories=("android.intent.category.LAUNCHER",),
            tv_additional_activities=(leanback,),
        )
        unsigned = {
            name: payload
            for name, payload in self.members_for(form="tv").items()
            if not name.startswith("META-INF/")
        }
        unsigned[self.module.MANIFEST_MEMBER] = manifest
        analysis = self.module.analyze_held_aab(
            self.write_aab(
                "tv-launcher-missing-landscape.aab",
                self.jar_wrap(unsigned, self.pkcs7),
            ).read_bytes()
        )
        self.assertEqual(
            analysis["leanback_launcher_activities"],
            frozenset({"org.winsvpn.app.TvLauncherActivity"}),
        )
        with self.assertRaisesRegex(self.module.SignerError, "leanback launcher"):
            self.module._enforce_target_identity("android-tv-aab", analysis)

    def test_tv_leanback_alias_target_must_be_landscape(self) -> None:
        portrait = self.activity(
            "org.winsvpn.app.PortraitActivity",
            (),
        )
        alias = self.activity_alias(
            ".TvLauncherAlias",
            ".PortraitActivity",
            ("android.intent.category.LEANBACK_LAUNCHER",),
        )
        manifest = self.proto_manifest(
            form="tv",
            version_code=3302,
            tv_additional_activities=(portrait, alias),
        )
        unsigned = {
            name: payload
            for name, payload in self.members_for(form="tv").items()
            if not name.startswith("META-INF/")
        }
        unsigned[self.module.MANIFEST_MEMBER] = manifest
        analysis = self.module.analyze_held_aab(
            self.write_aab(
                "tv-alias-target-portrait.aab",
                self.jar_wrap(unsigned, self.pkcs7),
            ).read_bytes()
        )
        self.assertEqual(
            analysis["leanback_launcher_components"][
                "org.winsvpn.app.TvLauncherAlias"
            ],
            "org.winsvpn.app.PortraitActivity",
        )
        with self.assertRaisesRegex(self.module.SignerError, "leanback launcher"):
            self.module._enforce_target_identity("android-tv-aab", analysis)

    def test_duplicate_tv_activity_identity_fails_closed(self) -> None:
        duplicate = self.activity(
            "org.winsvpn.app.MainActivity",
            ("android.intent.category.LEANBACK_LAUNCHER",),
            screen_orientation="landscape",
            compiled_orientation=0,
        )
        manifest = self.proto_manifest(
            form="tv",
            version_code=3302,
            tv_screen_orientation=None,
            tv_compiled_orientation=None,
            tv_additional_activities=(duplicate,),
        )
        unsigned = {
            name: payload
            for name, payload in self.members_for(form="tv").items()
            if not name.startswith("META-INF/")
        }
        unsigned[self.module.MANIFEST_MEMBER] = manifest
        with self.assertRaisesRegex(self.module.SignerError, "duplicate activity"):
            self.module.analyze_held_aab(
                self.write_aab(
                    "tv-duplicate-main.aab",
                    self.jar_wrap(unsigned, self.pkcs7),
                ).read_bytes()
            )

    def test_aapt_resources_proto_field_numbers_are_exact(self) -> None:
        encoded = self.module.encode_xml_attribute(
            "screenOrientation",
            "landscape",
            namespace=self.module.ANDROID_NS,
            resource_id=self.module.ATTR_SCREEN_ORIENTATION,
            compiled=self.module.encode_compiled_int(0),
        )
        fields = {(number, wire) for number, wire, _value in self.module._fields(encoded)}
        self.assertIn((5, 0), fields)
        self.assertIn((6, 2), fields)
        self.assertNotIn((4, 0), fields)
        self.assertEqual(
            self.module._decode_xml_attribute(encoded),
            (self.module.ANDROID_NS, "screenOrientation", "landscape"),
        )

    def test_missing_or_trivial_r8_mapping_fails_closed(self) -> None:
        missing = self.module.analyze_held_aab(
            self.write_aab(
                "no-r8.aab",
                self.members_for(form="phone", include_release_payload=False),
            ).read_bytes()
        )
        with self.assertRaisesRegex(self.module.SignerError, "R8 proguard.map"):
            self.module._enforce_target_identity("android-phone-tablet-aab", missing)
        unsigned = {
            name: data
            for name, data in self.members_for(form="phone").items()
            if not name.startswith("META-INF/")
        }
        unsigned[self.module.OFFICIAL_PROGUARD_MAP] = padded_trivial_r8_mapping()
        with self.assertRaisesRegex(self.module.SignerError, "too trivial"):
            self.module.analyze_held_aab(
                self.write_aab(
                    "trivial-r8.aab", self.jar_wrap(unsigned, self.pkcs7)
                ).read_bytes()
            )

    def test_missing_or_forbidden_native_engines_fail_closed(self) -> None:
        unsigned = {
            name: data
            for name, data in self.members_for(
                form="phone", include_release_payload=False
            ).items()
            if not name.startswith("META-INF/")
        }
        unsigned[self.module.OFFICIAL_PROGUARD_MAP] = r8_mapping_bytes()
        missing = self.module.analyze_held_aab(
            self.write_aab(
                "no-engines.aab", self.jar_wrap(unsigned, self.pkcs7)
            ).read_bytes()
        )
        with self.assertRaisesRegex(self.module.SignerError, "Winn v3/AWG native"):
            self.module._enforce_target_identity("android-phone-tablet-aab", missing)
        extra = self.members_for(form="phone")
        unsigned = {
            name: data
            for name, data in extra.items()
            if not name.startswith("META-INF/")
        }
        unsigned["base/lib/arm64-v8a/libam.so"] = ELF_STUB
        with self.assertRaisesRegex(self.module.SignerError, "forbidden native"):
            self.module._enforce_target_identity(
                "android-phone-tablet-aab",
                self.module.analyze_held_aab(
                    self.write_aab(
                        "forbidden.aab", self.jar_wrap(unsigned, self.pkcs7)
                    ).read_bytes()
                ),
            )
        # Android refuses Xray mode and Gradle excludes libxray.so: a package
        # that carries it means the exclusion broke, so it is refused too, and
        # the set the gate requires is exactly Winn v3 plus AmneziaWG.
        self.assertEqual(
            self.module.PHONE_TV_REQUIRED_NATIVE_ENGINES,
            frozenset({"libwinnengine.so", "libam-go.so"}),
        )
        self.assertIn("libxray.so", self.module.PHONE_TV_FORBIDDEN_NATIVE_ENGINES)
        for abi in ("arm64-v8a", "x86_64"):
            with self.subTest(abi=abi):
                with_xray = {
                    name: data
                    for name, data in extra.items()
                    if not name.startswith("META-INF/")
                }
                with_xray[f"base/lib/{abi}/libxray.so"] = ELF_STUB
                with self.assertRaisesRegex(self.module.SignerError, "forbidden native"):
                    self.module._enforce_target_identity(
                        "android-phone-tablet-aab",
                        self.module.analyze_held_aab(
                            self.write_aab(
                                f"with-xray-{abi}.aab",
                                self.jar_wrap(with_xray, self.pkcs7),
                            ).read_bytes()
                        ),
                    )
        # libwinn_tun_bulk.so is neither required nor forbidden: it must not
        # disturb the exact engine-set equality.
        with_bulk = {
            name: data
            for name, data in extra.items()
            if not name.startswith("META-INF/")
        }
        for abi in self.module.PHONE_TV_ABIS:
            with_bulk[f"base/lib/{abi}/libwinn_tun_bulk.so"] = ELF_STUB
        bulk_analysis = self.module.analyze_held_aab(
            self.write_aab(
                "with-bulk.aab", self.jar_wrap(with_bulk, self.pkcs7)
            ).read_bytes()
        )
        self.module._enforce_target_identity("android-phone-tablet-aab", bulk_analysis)
        for engines in bulk_analysis["native_engines"].values():
            self.assertEqual(engines, {"libwinnengine.so", "libam-go.so"})

    def test_phone_tv_apk_identity_r8_privacy_and_engines(self) -> None:
        for target, form, version_code in (
            ("android-phone-tablet-apk", "phone", 33),
            ("android-tv-apk", "tv", 3302),
        ):
            with self.subTest(target=target):
                analysis = self.bind_mock_apksigner(
                    self.module.analyze_held_apk(
                        self.write_apk(f"{form}.apk", form=form).read_bytes()
                    )
                )
                self.assertEqual(analysis["package"], "org.winsvpn.app")
                self.assertEqual(analysis["version_code"], version_code)
                self.assertEqual(analysis["decoder"], "apk-binary-xml")
                self.assertFalse(analysis["private_symbols_leaked"])
                self.module._enforce_apk_target_identity(target, analysis)
        leaked = self.write_apk(
            "leaked.apk",
            form="phone",
            extra={"mapping.txt": r8_mapping_bytes()},
        )
        analysis = self.bind_mock_apksigner(
            self.module.analyze_held_apk(leaked.read_bytes())
        )
        with self.assertRaisesRegex(self.module.SignerError, "private R8"):
            self.module._enforce_apk_target_identity("android-phone-tablet-apk", analysis)
        tv_as_phone = self.bind_mock_apksigner(
            self.module.analyze_held_apk(
                self.write_apk("tv-as-phone.apk", form="tv", version_code=33).read_bytes()
            )
        )
        with self.assertRaisesRegex(self.module.SignerError, "another exact target"):
            self.module._enforce_apk_target_identity(
                "android-phone-tablet-apk", tv_as_phone
            )

    def test_reviewed_store_metadata_is_canonical_and_fail_closed(self) -> None:
        phone = self.module._reviewed_store_metadata("android-phone-tablet-aab")
        tv = self.module._reviewed_store_metadata("android-tv-aab")
        self.assertEqual(phone["version_code"], 33)
        self.assertEqual(tv["version_code"], 3302)
        self.assertEqual(phone["tunnel_protocol"]["primary"], "winn-v3")
        self.assertEqual(phone["tunnel_protocol"]["fallback"], ["awg"])
        self.assertFalse(phone["upload_authorized"])
        self.assertEqual(phone["query_all_packages_status"], "PENDING")
        self.assertEqual(
            phone["sha256"],
            self.module._reviewed_store_metadata("android-phone-tablet-apk")["sha256"],
        )
        self.assertNotEqual(phone["sha256"], tv["sha256"])
        source = (ROOT / "tools/verify_android_aab_signers.py").read_text(encoding="utf-8")
        self.assertIn("_reviewed_store_metadata", source)
        self.assertIn("--verify-apk", source)
        adapter = source[
            source.index("def canonical_gate_verify") : source.index(
                "def _receipt_hex64"
            )
        ]
        self.assertIn("_reviewed_store_metadata", adapter)
        self.assertIn("_reviewed_wear_store_metadata", adapter)
        wear = self.module._reviewed_wear_store_metadata()
        self.assertEqual(wear["version_code"], 3301)
        self.assertFalse(wear["upload_authorized"])
        self.assertRegex(wear["sha256"], r"^[0-9a-f]{64}$")

    def test_canonical_gate_never_splits_signature_and_identity_artifact(self) -> None:
        artifact = self.write_aab("candidate.aab", form="phone")
        observed: dict[str, object] = {}

        def verify_one_held_descriptor(**kwargs):
            descriptor = kwargs["source_fd"]
            info = os.fstat(descriptor)
            held = os.pread(descriptor, info.st_size, 0)
            observed["held_sha256"] = hashlib.sha256(held).hexdigest()
            observed["descriptor"] = descriptor
            moved = self.work / "candidate.original"
            os.rename(artifact, moved)
            self.write_aab("candidate.aab", form="tv")
            observed["held_after_swap_sha256"] = hashlib.sha256(
                os.pread(descriptor, info.st_size, 0)
            ).hexdigest()
            return {"ok": True}

        with (
            mock.patch.object(self.module, "ROOT", self.work),
            mock.patch.object(
                self.module, "_canonical_gate_artifact", return_value=artifact
            ),
            mock.patch.object(
                self.module,
                "verify_held_aab_artifact",
                side_effect=verify_one_held_descriptor,
            ) as held_verify,
            mock.patch.object(self.module, "_reviewed_store_metadata"),
            mock.patch.object(
                self.module,
                "_verify_cryptographic_signature",
                side_effect=AssertionError("mutable original was reopened for signature"),
            ),
            mock.patch.object(
                self.module,
                "_verify_target_identity",
                side_effect=AssertionError("separate artifact was reopened for identity"),
            ),
        ):
            with self.assertRaisesRegex(
                self.module.SignerError, "descriptor custody changed|ancestor was substituted"
            ):
                self.module.canonical_gate_verify(
                    "android-phone-tablet-aab", "candidate.aab"
                )
        held_verify.assert_called_once()
        self.assertEqual(observed["held_sha256"], observed["held_after_swap_sha256"])
        self.assertNotEqual(
            observed["held_sha256"], hashlib.sha256(artifact.read_bytes()).hexdigest()
        )

    def test_unsealed_substituted_jdk_is_rejected_before_canary_execution(self) -> None:
        fake_jdk = self.work / "hostile-jdk"
        (fake_jdk / "bin").mkdir(parents=True)
        marker = self.work / "jdk-canary-executed"
        for name in ("java", "jarsigner", "keytool"):
            tool = fake_jdk / "bin" / name
            tool.write_text(
                f"#!/bin/sh\nprintf executed > {marker}\n",
                encoding="ascii",
            )
            tool.chmod(0o555)
        with mock.patch.dict(
            os.environ,
            {self.module.JDK_ROOT_ENV: str(fake_jdk.resolve(strict=True))},
            clear=False,
        ):
            with self.assertRaisesRegex(
                self.module.SignerError, "does not match the pin|absent or unsafe"
            ):
                with self.module._HeldAndroidVerificationTools(
                    bind_bundletool=False
                ):
                    self.fail("unsealed substituted JDK reached execution scope")
        self.assertFalse(marker.exists())

    def test_identity_java_tools_ignore_host_path_java(self) -> None:
        source = (ROOT / "tools/verify_android_aab_signers.py").read_text(encoding="ascii")
        self.assertNotIn("shutil.which", source)
        self.assertNotIn("import shutil", source)
        self.assertIn("bind_java_identity_tools", source)
        self.assertIn("retained private JDK tool paths are required", source)
        canary_dir = pathlib.Path(
            tempfile.mkdtemp(prefix="wins-aab-host-java-")
        ).resolve(strict=True)
        self.addCleanup(lambda: shutil.rmtree(canary_dir, ignore_errors=True))
        canary = canary_dir / "java"
        canary.write_text("#!/bin/sh\necho HOST_JAVA_CANARY\n", encoding="ascii")
        canary.chmod(0o755)
        bindir = canary_dir / "sealed" / "bin"
        bindir.mkdir(parents=True)
        tools = {}
        for name in ("java", "jarsigner", "keytool"):
            path = bindir / name
            path.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            path.chmod(0o755)
            tools[name] = str(path)
        with mock.patch.dict(os.environ, {"PATH": f"{canary_dir}{os.pathsep}{os.environ.get('PATH', '')}"}):
            with self.assertRaisesRegex(
                self.module.SignerError, "retained private JDK tool paths are required"
            ):
                self.module._bound_jdk_tool("java")
            with self.assertRaisesRegex(
                self.module.SignerError, "absolute authenticated JDK tool path"
            ):
                self.module.bind_java_identity_tools(
                    tools["java"], tools["jarsigner"], tools["keytool"]
                )
            self.assertNotEqual(
                str(self.module._pinned_jdk_identity()["root"] / "bin/java"), str(canary)
            )
        with self.assertRaisesRegex(self.module.SignerError, "exactly --verify"):
            self.module._main_authenticated(
                ["--verify", "android-phone-tablet-aab", "missing.aab"]
            )
        with self.assertRaisesRegex(
            self.module.SignerError, "absolute authenticated JDK tool path"
        ):
            self.module._main_authenticated(
                [
                    "--verify",
                    "android-phone-tablet-aab",
                    "missing.aab",
                    "--java",
                    str(canary),
                    "--jarsigner",
                    tools["jarsigner"],
                    "--keytool",
                    tools["keytool"],
                ]
            )

    def test_self_test_still_covers_signer_structure(self) -> None:
        self.module.self_test()

    def test_phone_calculator_label_and_wear_payload_fail_closed(self) -> None:
        phone = self.module.analyze_held_aab(
            self.write_aab("phone-label.aab", form="phone").read_bytes()
        )
        phone["application_label"] = "Win's VPN"
        with self.assertRaisesRegex(self.module.SignerError, "Calculator application label"):
            self.module._enforce_target_identity("android-phone-tablet-aab", phone)
        apk = self.bind_mock_apksigner(
            self.module.analyze_held_apk(
                self.write_apk("phone-label.apk", form="phone").read_bytes()
            )
        )
        apk["application_label"] = "Win's VPN"
        with self.assertRaisesRegex(self.module.SignerError, "Calculator application label"):
            self.module._enforce_apk_target_identity("android-phone-tablet-apk", apk)
        wear = self.module.analyze_held_aab(
            self.write_aab("wear-payload.aab", form="wear").read_bytes()
        )
        wear["permissions"] = {"android.permission.INTERNET"}
        with self.assertRaisesRegex(self.module.SignerError, "phone/TV Play permission"):
            self.module._enforce_target_identity("wear-os-aab", wear)
        wear["permissions"] = {"android.permission.QUERY_ALL_PACKAGES"}
        with self.assertRaisesRegex(self.module.SignerError, "phone/TV Play permission"):
            self.module._enforce_target_identity("wear-os-aab", wear)
        wear["permissions"] = set()
        wear["vpn_services"] = ["org.winsvpn.app.VpnTunnelService"]
        with self.assertRaisesRegex(self.module.SignerError, "VPN service"):
            self.module._enforce_target_identity("wear-os-aab", wear)
        wear["vpn_services"] = []
        wear["native_engines"] = {"arm64-v8a": {"libwinnengine.so"}}
        with self.assertRaisesRegex(self.module.SignerError, "forbidden native"):
            self.module._enforce_target_identity("wear-os-aab", wear)

    def test_missing_abi_native_debug_symbols_fail_closed(self) -> None:
        unsigned = {
            name: data
            for name, data in self.members_for(form="phone").items()
            if not name.startswith("META-INF/")
        }
        del unsigned[
            "BUNDLE-METADATA/com.android.tools.build.debugsymbols/armeabi-v7a/libapp.so.sym"
        ]
        analysis = self.module.analyze_held_aab(
            self.write_aab(
                "missing-abi-symbols.aab", self.jar_wrap(unsigned, self.pkcs7)
            ).read_bytes()
        )
        self.assertTrue(analysis["metadata"]["libapp_debug"])
        with self.assertRaisesRegex(self.module.SignerError, "native debug-symbol"):
            self.module._enforce_target_identity("android-phone-tablet-aab", analysis)

    def test_private_r8_map_must_bind_the_exact_aab_and_reject_swaps(self) -> None:
        mapping = r8_mapping_bytes()
        other = r8_mapping_bytes(stem="Other")
        phone = self.write_aab("phone-r8.aab", form="phone").read_bytes()
        tv = self.write_aab("tv-r8.aab", form="tv").read_bytes()
        bound = self.module.bind_private_r8_mapping_bytes(
            "android-phone-tablet-aab", phone, mapping
        )
        self.assertTrue(bound["ok"])
        self.assertEqual(bound["target_id"], "android-phone-tablet-aab")
        self.assertRegex(bound["pg_map_hash"], r"^[0-9a-f]{64}$")
        with self.assertRaisesRegex(
            self.module.SignerError, "not bound to the exact artifact"
        ):
            self.module.bind_private_r8_mapping_bytes(
                "android-phone-tablet-aab", phone, other
            )
        with self.assertRaisesRegex(
            self.module.SignerError, "another exact target"
        ):
            self.module.bind_private_r8_mapping_bytes("android-tv-aab", phone, mapping)
        with self.assertRaisesRegex(
            self.module.SignerError, "another exact target"
        ):
            self.module.bind_private_r8_mapping_bytes(
                "android-phone-tablet-aab", tv, mapping
            )
        apk = self.write_apk("phone-r8.apk", form="phone").read_bytes()
        apk_bound = self.module.bind_private_r8_mapping_bytes(
            "android-phone-tablet-apk", apk, mapping
        )
        self.assertTrue(apk_bound["ok"])
        leaked = self.write_apk(
            "leaked-r8.apk",
            form="phone",
            extra={"mapping.txt": mapping},
        ).read_bytes()
        with self.assertRaisesRegex(self.module.SignerError, "private R8"):
            self.module.bind_private_r8_mapping_bytes(
                "android-phone-tablet-apk", leaked, mapping
            )
        with self.assertRaisesRegex(self.module.SignerError, "unsupported exact Android R8"):
            self.module.bind_private_r8_mapping_bytes("wear-os-aab", phone, mapping)

    def test_wrong_certificate_is_not_an_owner_blocker(self) -> None:
        with mock.patch.object(
            self.module,
            "verify_held_aab_artifact",
            side_effect=self.module.SignerError(
                "AAB signer does not exactly match the reviewed upload certificate"
            ),
        ):
            with self.assertRaisesRegex(
                self.module.SignerError, "reviewed upload certificate"
            ) as raised:
                self.module._require_owner_issued_android_signature_held(
                    "android-phone-tablet-aab", (7, (1, 2), 3, "a" * 64)
                )
        self.assertNotIn("owner/environment blocker", str(raised.exception))

    def test_unsigned_artifact_stays_owner_blocked(self) -> None:
        with mock.patch.object(
            self.module,
            "verify_held_aab_artifact",
            side_effect=self.module.SignerError(
                "jarsigner did not prove a cryptographically verified AAB"
            ),
        ):
            with self.assertRaisesRegex(
                self.module.SignerError, "no owner-issued Play upload signature"
            ):
                self.module._require_owner_issued_android_signature_held(
                    "android-phone-tablet-aab", (7, (1, 2), 3, "a" * 64)
                )

    def test_form_factor_mismatch_is_not_an_owner_blocker(self) -> None:
        with mock.patch.object(
            self.module,
            "verify_held_aab_artifact",
            side_effect=self.module.SignerError(
                "AAB form-factor identity belongs to another exact target"
            ),
        ):
            with self.assertRaisesRegex(
                self.module.SignerError, "another exact target"
            ) as raised:
                self.module._require_owner_issued_android_signature_held(
                    "android-phone-tablet-aab", (7, (1, 2), 3, "a" * 64)
                )
        self.assertNotIn("owner/environment blocker", str(raised.exception))

    def test_raw_zip_local_headers_crc_method_name_and_offsets_are_exact(self) -> None:
        original = self.write_aab("raw-zip.aab", form="phone").read_bytes()
        eocd = original.rfind(b"PK\x05\x06")
        central = struct.unpack_from("<L", original, eocd + 16)[0]
        mutations = {
            "method": (8, 99),
            "crc": (14, original[14] ^ 0x01),
            "name": (30, original[30] ^ 0x01),
            "central-local-offset": (central + 42, 1),
        }
        for label, (offset, value) in mutations.items():
            with self.subTest(label=label):
                hostile = bytearray(original)
                hostile[offset] = value
                with self.assertRaises(self.module.SignerError):
                    with self.module._open_held_zip(bytes(hostile)):
                        self.fail("contradictory raw ZIP metadata was accepted")

    def test_raw_zip_data_descriptor_is_reconciled_exactly(self) -> None:
        class Unseekable(io.BytesIO):
            def seekable(self) -> bool:
                return False

            def seek(self, *args, **kwargs):
                raise io.UnsupportedOperation("unseekable")

        stream = Unseekable()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("payload.txt", b"descriptor payload")
        payload = stream.getvalue()
        with self.module._open_held_zip(payload) as archive:
            self.assertEqual(archive.read("payload.txt"), b"descriptor payload")
        descriptor = payload.index(b"PK\x07\x08")
        hostile = bytearray(payload)
        hostile[descriptor + 4] ^= 0x01
        with self.assertRaisesRegex(self.module.SignerError, "data descriptor"):
            with self.module._open_held_zip(bytes(hostile)):
                self.fail("contradictory ZIP data descriptor was accepted")

    def test_raw_zip64_local_sizes_are_reconciled_exactly(self) -> None:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            with archive.open("zip64.txt", "w", force_zip64=True) as member:
                member.write(b"zip64 payload")
        payload = stream.getvalue()
        with self.module._open_held_zip(payload) as archive:
            self.assertEqual(archive.read("zip64.txt"), b"zip64 payload")
        name_size, extra_size = struct.unpack_from("<HH", payload, 26)
        self.assertGreaterEqual(extra_size, 20)
        extra = 30 + name_size
        self.assertEqual(payload[extra : extra + 2], b"\x01\x00")
        hostile = bytearray(payload)
        hostile[extra + 4] ^= 0x01
        with self.assertRaisesRegex(self.module.SignerError, "ZIP64|sizes"):
            with self.module._open_held_zip(bytes(hostile)):
                self.fail("contradictory local ZIP64 size was accepted")

    def test_raw_zip64_data_descriptor_width_follows_local_header(self) -> None:
        class Unseekable(io.BytesIO):
            def seekable(self) -> bool:
                return False

            def seek(self, *args, **kwargs):
                raise io.UnsupportedOperation("unseekable")

        stream = Unseekable()
        with zipfile.ZipFile(stream, "w") as archive:
            with archive.open("zip64.txt", "w", force_zip64=True) as member:
                member.write(b"zip64 payload")
        payload = stream.getvalue()
        descriptor = payload.index(b"PK\x07\x08")
        central = payload.index(b"PK\x01\x02", descriptor)
        signature, crc, compressed, uncompressed = struct.unpack(
            "<4sLQQ", payload[descriptor:central]
        )
        self.assertEqual(signature, b"PK\x07\x08")
        self.assertLess(compressed, 0xFFFFFFFF)
        self.assertLess(uncompressed, 0xFFFFFFFF)
        with self.module._open_held_zip(payload) as archive:
            self.assertEqual(archive.read("zip64.txt"), b"zip64 payload")

        def replace_descriptor(replacement: bytes) -> bytes:
            changed = bytearray(payload[:descriptor] + replacement + payload[central:])
            new_eocd = changed.rfind(b"PK\x05\x06")
            struct.pack_into(
                "<L", changed, new_eocd + 16, descriptor + len(replacement)
            )
            return bytes(changed)

        valid_unsigned = replace_descriptor(
            struct.pack("<LQQ", crc, compressed, uncompressed)
        )
        with self.module._open_held_zip(valid_unsigned) as archive:
            self.assertEqual(archive.read("zip64.txt"), b"zip64 payload")

        hostile_descriptors = {
            "contradictory": struct.pack(
                "<4sLQQ", signature, crc, compressed + 1, uncompressed
            ),
            "truncated": payload[descriptor : central - 1],
            "mixed-width": struct.pack(
                "<4sLLL", signature, crc, compressed, uncompressed
            ),
            "bad-signature": struct.pack(
                "<4sLQQ", b"BAD!", crc, compressed, uncompressed
            ),
        }
        for label, replacement in hostile_descriptors.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                self.module.SignerError, "data descriptor"
            ):
                with self.module._open_held_zip(replace_descriptor(replacement)):
                    self.fail(f"{label} ZIP64 data descriptor was accepted")

        local_name_size, local_extra_size = struct.unpack_from("<HH", payload, 26)
        self.assertGreaterEqual(local_extra_size, 20)
        local_extra = 30 + local_name_size
        local_drift = bytearray(payload)
        local_drift[local_extra + 4] ^= 0x01
        with self.assertRaisesRegex(self.module.SignerError, "ZIP64|local-header sizes"):
            with self.module._open_held_zip(bytes(local_drift)):
                self.fail("local ZIP64 values drifted from the descriptor")

        central_drift = bytearray(payload)
        needed = struct.unpack_from("<H", central_drift, central + 6)[0]
        struct.pack_into("<H", central_drift, central + 6, needed - 1)
        with self.assertRaisesRegex(
            self.module.SignerError, "local header and central directory"
        ):
            with self.module._open_held_zip(bytes(central_drift)):
                self.fail("local and central extraction versions drifted")

    def test_proto_identity_raw_and_compiled_forms_must_agree(self) -> None:
        cases = (
            (
                "versionCode",
                self.module.encode_xml_attribute(
                    "versionCode",
                    "30",
                    namespace=self.module.ANDROID_NS,
                    resource_id=self.module.ATTR_VERSION_CODE,
                    compiled=self.module.encode_compiled_int(31),
                ),
            ),
            (
                "versionName",
                self.module.encode_xml_attribute(
                    "versionName",
                    "1.0.15",
                    namespace=self.module.ANDROID_NS,
                    resource_id=self.module.ATTR_VERSION_NAME,
                    compiled=self.module._ld(2, b"1.0.16"),
                ),
            ),
            (
                "debuggable",
                self.module.encode_xml_attribute(
                    "debuggable",
                    "false",
                    namespace=self.module.ANDROID_NS,
                    compiled=self.module.encode_compiled_bool(True),
                ),
            ),
        )
        for label, attribute in cases:
            with self.subTest(label=label), self.assertRaisesRegex(
                self.module.SignerError, "raw and compiled values disagree"
            ):
                self.module._decode_xml_attribute(attribute)

    def test_release_manifests_require_explicit_non_debuggable_and_api_36(self) -> None:
        aab = self.module.analyze_held_aab(
            self.write_aab("posture.aab", form="phone").read_bytes()
        )
        aab["debuggable"] = None
        with self.assertRaisesRegex(self.module.SignerError, "explicitly non-debuggable"):
            self.module._enforce_target_identity("android-phone-tablet-aab", aab)
        apk = self.bind_mock_apksigner(
            self.module.analyze_held_apk(
                self.write_apk("posture.apk", form="phone").read_bytes()
            )
        )
        apk["target_sdk"] = 35
        with self.assertRaisesRegex(self.module.SignerError, "target SDK"):
            self.module._enforce_apk_target_identity("android-phone-tablet-apk", apk)
        apk["target_sdk"] = 37
        apk["debuggable"] = None
        with self.assertRaisesRegex(self.module.SignerError, "explicitly non-debuggable"):
            self.module._enforce_apk_target_identity("android-phone-tablet-apk", apk)

    def test_strict_receipt_json_rejects_duplicates_and_nonfinite_numbers(self) -> None:
        for payload in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.subTest(payload=payload), self.assertRaisesRegex(
                self.module.SignerError, "strict duplicate-free finite JSON"
            ):
                self.module._receipt_document(payload, "receipt")
        with self.assertRaisesRegex(
            self.module.SignerError, "strict duplicate-free finite JSON"
        ):
            self.module._receipt_document({"a": float("nan")}, "receipt")
        with (
            mock.patch.object(
                self.module,
                "_hash_live_repo_file",
                return_value=("a" * 64, 13, b'{"a":1,"a":2}'),
            ),
            self.assertRaisesRegex(
                self.module.SignerError, "strict duplicate-free finite JSON"
            ),
        ):
            self.module._load_store_json("store.json", "store metadata")

    def test_upload_journal_records_have_exact_schemas(self) -> None:
        hostile = (
            json.dumps(
                {
                    "schema": self.module.UPLOAD_RECEIPT_JOURNAL_SCHEMA,
                    "kind": "issued",
                    "unexpected": True,
                },
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
        with self.assertRaises(self.module.SignerError):
            self.module._parse_upload_receipt_journal(hostile)

    def test_apk_resource_table_resolves_icon_and_banner_ids(self) -> None:
        def pool(strings: list[str]) -> bytes:
            body = b""
            offsets = []
            for text in strings:
                offsets.append(len(body))
                raw = text.encode("utf-8")
                body += bytes([len(text), len(raw)]) + raw + b"\x00"
            body += b"\x00" * (-len(body) % 4)
            header_size = 28
            start = header_size + 4 * len(strings)
            size = start + len(body)
            return (
                struct.pack("<HHIIIIII", 0x0001, header_size, size, len(strings), 0, 0x100, start, 0)
                + b"".join(struct.pack("<I", value) for value in offsets)
                + body
            )

        types = pool(["mipmap", "drawable"])
        keys = pool(["ic_launcher", "banner"])
        config = struct.pack("<I", 64) + b"\x00" * 60
        entries = [
            struct.pack("<HHI", 8, 0, 0) + struct.pack("<HBBI", 8, 0, 0x03, 0),
            struct.pack("<HHI", 8, 0, 1) + struct.pack("<HBBI", 8, 0, 0x03, 0),
        ]
        type_header = 20 + len(config)
        entries_start = type_header + 4 * len(entries)
        type_body = b"".join(struct.pack("<I", 16 * index) for index in range(len(entries))) + b"".join(entries)
        type_chunk = (
            struct.pack("<HHIBBHII", 0x0201, type_header, type_header + len(type_body), 2, 0, 0, len(entries), entries_start)
            + config
            + type_body
        )
        package_header = 288
        package_body = types + keys + type_chunk
        package = (
            struct.pack("<HHII", 0x0200, package_header, package_header + len(package_body), 0x7F)
            + b"\x00" * 256
            + struct.pack("<IIIII", package_header, 0, package_header + len(types), 0, 0)
            + package_body
        )
        values = pool([])
        table = struct.pack("<HHII", 0x0002, 12, 12 + len(values) + len(package), 1) + values + package
        resolve = self.module._arsc_resource_name
        self.assertEqual(resolve(table, 0x7F020001), "@drawable/banner")
        self.assertEqual(resolve(table, 0x7F020000), "@drawable/ic_launcher")
        self.assertIsNone(resolve(table, 0x7F020005))
        self.assertIsNone(resolve(table, 0x7E020001))
        self.assertIsNone(resolve(table[: len(table) // 2], 0x7F020001))
        self.assertIsNone(resolve(b"", 0x7F020001))

    def test_apksigner_v3_signer_lines_from_build_tools_37_are_accepted(self) -> None:
        head = (
            "Verifies\n"
            "Verified using v2 scheme (APK Signature Scheme v2): true\n"
            "Verified using v3 scheme (APK Signature Scheme v3): true\n"
            "Number of signers: 1\n"
        )
        v3_lines = (
            "V3.0 Signer: certificate DN: CN=WinUpload\n"
            f"V3.0 Signer: certificate SHA-256 digest: {self.pin}\n"
        )
        parsed = self.module._parse_apksigner_verification((head + v3_lines).encode("ascii"))
        self.assertEqual(parsed["certificate_sha256"], self.pin)
        both = head + "Signer #1 certificate DN: CN=WinUpload\n" + f"Signer #1 certificate SHA-256 digest: {self.pin}\n" + v3_lines
        self.assertEqual(
            self.module._parse_apksigner_verification(both.encode("ascii"))["certificate_sha256"],
            self.pin,
        )
        other = "0" * 64 if self.pin != "0" * 64 else "1" * 64
        split = head + "Signer #1 certificate DN: CN=WinUpload\n" + f"Signer #1 certificate SHA-256 digest: {other}\n" + v3_lines
        with self.assertRaises(self.module.SignerError):
            self.module._parse_apksigner_verification(split.encode("ascii"))

    def test_apksigner_signer_under_any_role_label_must_name_the_one_certificate(self) -> None:
        # Label forms of the pinned build-tools 37 ApkSignerTool.verify: hybrid
        # and rotation signers carry their own role label and an SDK range.
        head = (
            "Verifies\n"
            "Verified using v2 scheme (APK Signature Scheme v2): true\n"
            "Verified using v3 scheme (APK Signature Scheme v3): true\n"
            "Number of signers: 1\n"
        )
        other = "0" * 64 if self.pin != "0" * 64 else "1" * 64

        def lines(label: str, digest: str, subject: str) -> str:
            return (
                f"{label} certificate DN: CN={subject}\n"
                f"{label} certificate SHA-256 digest: {digest}\n"
            )

        v3_lines = lines("V3.0 Signer:", self.pin, "WinUpload")
        for label in (
            "V3.2 Hybrid PQC Signer: (minSdkVersion=37, maxSdkVersion=2147483647)",
            "V3.2 Hybrid Classical Signer: (minSdkVersion=37, maxSdkVersion=2147483647)",
            "V3.1 Signer: (minSdkVersion=33 (dev release=true), maxSdkVersion=2147483647)",
            "V2 Signer #2:",
        ):
            with self.subTest(label=label), self.assertRaises(self.module.SignerError):
                self.module._parse_apksigner_verification(
                    (head + v3_lines + lines(label, other, "Other")).encode("ascii")
                )
        stamped = head + v3_lines + lines("Source Stamp Signer:", other, "Play Stamp")
        self.assertEqual(
            self.module._parse_apksigner_verification(stamped.encode("ascii"))["certificate_sha256"],
            self.pin,
        )

    def test_apksigner_output_proves_v2_v3_one_signer_and_exact_certificate(self) -> None:
        valid = (
            "Verifies\n"
            "Verified using v2 scheme (APK Signature Scheme v2): true\n"
            "Verified using v3 scheme (APK Signature Scheme v3): true\n"
            "Number of signers: 1\n"
            "Signer #1 certificate DN: CN=WinUpload\n"
            f"Signer #1 certificate SHA-256 digest: {self.pin}\n"
        ).encode("ascii")
        parsed = self.module._parse_apksigner_verification(valid)
        self.assertTrue(parsed["verified_v2"])
        self.assertTrue(parsed["verified_v3"])
        self.assertEqual(parsed["signer_count"], 1)
        self.assertEqual(parsed["certificate_sha256"], self.pin)
        for label, hostile in (
            ("v2", valid.replace(b"v2): true", b"v2): false")),
            ("count", valid.replace(b"signers: 1", b"signers: 2")),
            ("debug", valid.replace(b"CN=WinUpload", b"CN=Android Debug")),
        ):
            with self.subTest(label=label), self.assertRaises(self.module.SignerError):
                self.module._parse_apksigner_verification(hostile)

    def test_absent_exact_apksigner_fails_closed_without_apk_pass(self) -> None:
        missing = self.work.resolve(strict=True) / "missing-sdk"
        with mock.patch.dict(
            os.environ, {"ANDROID_SDK_ROOT": str(missing)}, clear=False
        ):
            with self.assertRaisesRegex(self.module.SignerError, "apksigner.*absent"):
                with self.module._HeldApksigner():
                    self.fail("missing apksigner entered an execution scope")
        source = (ROOT / "tools/verify_android_aab_signers.py").read_text(
            encoding="ascii"
        )
        apk_gate = source[
            source.index("def verify_held_apk_artifact") : source.index(
                "def _parse_manifest"
            )
        ]
        self.assertIn("_HeldApksigner", apk_gate)
        self.assertNotIn("_verify_cryptographic_signature", apk_gate)

    def test_apk_gate_retains_one_candidate_descriptor_through_result(self) -> None:
        artifact = self.write_apk("candidate.apk", form="phone")
        artifact.chmod(0o444)
        observed: dict[str, object] = {}

        def verify_one_descriptor(**kwargs):
            descriptor = kwargs["source_fd"]
            info = os.fstat(descriptor)
            observed["sha256"] = hashlib.sha256(
                os.pread(descriptor, info.st_size, 0)
            ).hexdigest()
            moved = self.work / "candidate.original.apk"
            os.rename(artifact, moved)
            replacement = self.write_apk("candidate.apk", form="tv")
            replacement.chmod(0o444)
            observed["held_after_swap"] = hashlib.sha256(
                os.pread(descriptor, info.st_size, 0)
            ).hexdigest()
            return {"ok": True}

        with (
            mock.patch.object(self.module, "ROOT", self.work),
            mock.patch.object(self.module, "_canonical_gate_apk", return_value=artifact),
            mock.patch.object(
                self.module,
                "verify_held_apk_artifact",
                side_effect=verify_one_descriptor,
            ) as held_verify,
            mock.patch.object(self.module, "_reviewed_store_metadata"),
        ):
            with self.assertRaisesRegex(
                self.module.SignerError, "descriptor custody changed|ancestor was substituted"
            ):
                self.module.canonical_apk_gate_verify(
                    "android-phone-tablet-apk", "candidate.apk"
                )
        held_verify.assert_called_once()
        self.assertEqual(observed["sha256"], observed["held_after_swap"])

    def test_python_39_is_rejected_before_any_release_authority(self) -> None:
        with (
            mock.patch.object(self.module.sys, "version_info", (3, 9, 19)),
            mock.patch.object(self.module, "_main_authenticated") as authority,
        ):
            with self.assertRaisesRegex(
                self.module.SignerError, "release Python 3.14.7.*before authority"
            ):
                self.module.main(["--self-test"])
        authority.assert_not_called()

    def test_production_entry_and_macos_caller_pin_releasepython_314(self) -> None:
        source = (ROOT / "tools/verify_android_aab_signers.py").read_text(
            encoding="ascii"
        )
        self.assertEqual(source.splitlines()[0], "#!/usr/bin/env python3")
        self.assertNotIn("/Library/WinsVPN", source)
        launcher = (ROOT / "tools/launch_macos_release_android_toolchains.py").read_text(
            encoding="ascii"
        )
        producer = (ROOT / "tools/build_android_release_macos.sh").read_text(
            encoding="ascii"
        )
        exact = "/Library/WinsVPN/ReleasePython/3.14.7/launcher/python3.14"
        self.assertIn(exact, launcher)
        self.assertIn("require_loaded_cpython_314_identity", launcher)
        signer_calls = producer[
            producer.index('local signer="${script_root}/tools/verify_android_aab_signers.py"') :
            producer.index("snapshot_inputs", producer.index('local signer="${script_root}/tools/verify_android_aab_signers.py"'))
        ]
        invocation_lines = [
            line.strip()
            for line in signer_calls.splitlines()
            if '"${signer}"' in line
        ]
        self.assertEqual(len(invocation_lines), 8)
        self.assertTrue(
            all(line.startswith("wins_release_python_run ") for line in invocation_lines)
        )
        self.assertNotRegex(signer_calls, r"(?:^|[ ;])python3(?:[ ;]|$)")

    def test_release_python_wrapper_executes_verifier_with_exact_isolation(self) -> None:
        wrapper = ROOT / "tools/release_python_archive_custody.sh"
        runtime = self.work / "recording-runtime"
        vendor = runtime / "vendor"
        tools_dir = self.work / "hostile-stage" / "tools"
        scratch = self.work / "scratch"
        for directory in (
            vendor,
            tools_dir,
            runtime / "launcher",
            scratch / "home",
            scratch / "tmp",
        ):
            directory.mkdir(parents=True, exist_ok=True)
        recorder = runtime / "record-python-argv"
        recorder.write_text(
            "#!/bin/sh\n"
            "printf 'ARGV'\n"
            "for arg do\n"
            "  printf '\\t%s' \"$arg\"\n"
            "done\n"
            "printf '\\n'\n",
            encoding="ascii",
        )
        recorder.chmod(0o700)
        verifier_probe = tools_dir / "verify_android_aab_signers.py"
        generic_probe = tools_dir / "generic_consumer.py"
        verifier_probe.write_text("raise SystemExit('must not execute')\n", encoding="ascii")
        generic_probe.write_text("raise SystemExit('must not execute')\n", encoding="ascii")
        shell = r'''
set -euo pipefail
source "$1"
_WINS_RP_ACTIVE_RUNTIME="$2"
_WINS_RP_ACTIVE_SCRATCH="$3"
_WINS_RP_ACTIVE_BIN="$4"
_WINS_RP_ACTIVE_LAUNCHER="$2/launcher/python3.14"
_WINS_RP_ACTIVE_VENDOR="$2/vendor"
_WINS_RP_ACTIVE_FRAMEWORK="$2/Python.framework"
_wins_rp_bind_execution() {
  _WINS_RP_EXEC_FRAMEWORK="$_WINS_RP_ACTIVE_FRAMEWORK"
  _WINS_RP_EXEC_BIN="$_WINS_RP_ACTIVE_BIN"
}
wins_release_python_run "$5"
wins_release_python_run "$6"
'''
        completed = subprocess.run(
            [
                "/bin/bash",
                "-c",
                shell,
                "android-verifier-wrapper-test",
                str(wrapper),
                str(runtime),
                str(scratch),
                str(recorder),
                str(verifier_probe),
                str(generic_probe),
            ],
            cwd=ROOT,
            env={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "PYTHONPATH": str(vendor),
            },
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(
            completed.returncode, 0, completed.stdout + completed.stderr
        )
        verifier_result, generic_result = (
            line.split("\t")[1:] for line in completed.stdout.splitlines()
        )
        self.assertEqual(
            verifier_result,
            ["-I", "-S", str(verifier_probe)],
        )
        self.assertEqual(generic_result, ["-S", str(generic_probe)])

    def test_authorization_commit_is_batch_transactional_and_retry_safe(self) -> None:
        def auth(seed: str) -> dict[str, object]:
            return {
                "authenticated": True,
                "issuer": self.module.UPLOAD_RECEIPT_ISSUER,
                "run_id": seed * 64,
                "nonce": chr(ord(seed) + 1) * 64,
                "issued_at": "2026-08-27T12:00:00Z",
                "challenge": chr(ord(seed) + 2) * 128,
                "target_id": "android-phone-tablet-aab",
                "architectures": sorted(self.module.PHONE_TV_ABIS),
                "release": self.module.CANONICAL_RELEASE,
                "artifact_sha256": chr(ord(seed) + 3) * 64,
                "artifact_bytes": 100,
            }

        first = auth("a")
        second = auth("f")
        records = [
            {"schema": self.module.UPLOAD_RECEIPT_JOURNAL_SCHEMA, "kind": "issued", **first}
        ]
        appended: list[dict[str, object]] = []

        def journal(mutate):
            extra = mutate(records)
            if extra is not None:
                appended.append(extra)
                records.append(extra)
            return records

        with mock.patch.object(
            self.module, "_with_upload_receipt_journal", side_effect=journal
        ):
            with self.assertRaisesRegex(
                self.module.SignerError, self.module.RECEIPT_UNAUTHENTICATED_ERROR
            ):
                self.module._consume_upload_receipt_challenges([first, second])
            self.assertEqual(appended, [])
            records.append(
                {
                    "schema": self.module.UPLOAD_RECEIPT_JOURNAL_SCHEMA,
                    "kind": "issued",
                    **second,
                }
            )
            self.module._consume_upload_receipt_challenges([first, second])
        self.assertEqual(len(appended), 1)
        self.assertEqual(appended[0]["kind"], "consumed-batch")
        self.assertEqual(len(appended[0]["bindings"]), 2)

    def test_authorization_commit_waits_for_all_candidate_custody_exits(self) -> None:
        targets = tuple(self.module.REQUIRED_ANDROID_UPLOAD_TARGETS)
        records = {
            target: {
                "artifact": {
                    "path": f"artifacts/{target}.aab",
                    "sha256": "a" * 64,
                    "bytes": 100,
                }
            }
            for target in targets
        }
        artifacts = {target: ("a" * 64, 100) for target in targets}

        @contextlib.contextmanager
        def retained(relative, _label):
            yield (7, (1, 2), 100, "a" * 64)
            if relative.endswith(f"{targets[-1]}.aab"):
                raise self.module.SignerError("final retained custody changed")

        authentications = iter(
            {
                "authenticated": True,
                "target_id": target,
            }
            for target in targets
        )

        def bind(target_id, _record, **_kwargs):
            return {"ok": True, "target_id": target_id}, next(authentications)

        with (
            mock.patch.object(
                self.module, "_receipt_document", side_effect=lambda value, _label: value
            ),
            mock.patch.object(
                self.module, "_unique_receipt_digest_pairs", return_value=[]
            ),
            mock.patch.object(self.module, "_bind_shared_upload_paths"),
            mock.patch.object(
                self.module, "_retained_live_repo_file", side_effect=retained
            ),
            mock.patch.object(
                self.module, "_bind_package_upload_receipt_locked", side_effect=bind
            ),
            mock.patch.object(
                self.module, "_consume_upload_receipt_challenges"
            ) as consume,
        ):
            with self.assertRaisesRegex(
                self.module.SignerError, "final retained custody changed"
            ):
                self.module._bind_android_package_upload_receipts_locked(
                    records, artifacts
                )
        consume.assert_not_called()

    def test_receipt_authentication_validation_does_not_consume_authority(self) -> None:
        now = self.module._upload_receipt_now().strftime("%Y-%m-%dT%H:%M:%SZ")
        auth = {
            "authenticated": True,
            "issuer": self.module.UPLOAD_RECEIPT_ISSUER,
            "run_id": "a" * 64,
            "nonce": "b" * 64,
            "issued_at": now,
            "challenge": "c" * 128,
            "target_id": "android-phone-tablet-aab",
            "architectures": sorted(self.module.PHONE_TV_ABIS),
            "release": self.module.CANONICAL_RELEASE,
            "artifact_sha256": "d" * 64,
            "artifact_bytes": 123,
        }
        with (
            mock.patch.object(self.module, "_validate_upload_receipt_challenge") as validate,
            mock.patch.object(self.module, "_consume_upload_receipt_challenge") as consume,
        ):
            returned = self.module._bind_upload_receipt_authentication(
                "android-phone-tablet-aab",
                {"authentication": auth},
                artifact_sha256="d" * 64,
                artifact_bytes=123,
                architectures=tuple(sorted(self.module.PHONE_TV_ABIS)),
                release=self.module.CANONICAL_RELEASE,
            )
        self.assertEqual(returned, auth)
        validate.assert_called_once_with(auth)
        consume.assert_not_called()

    def test_dummy_live_files_do_not_make_an_upload_receipt_green(self) -> None:
        digest = hashlib.sha256(b"dummy-aab-bytes").hexdigest()
        build_digest = hashlib.sha256(b"dummy-build-receipt").hexdigest()
        producer_digest = hashlib.sha256(b"dummy-producer").hexdigest()
        freeze_digest = hashlib.sha256(b"dummy-freeze").hexdigest()
        descriptor_digest = hashlib.sha256(b"dummy-descriptor").hexdigest()
        privacy_digest = hashlib.sha256(b"dummy-privacy").hexdigest()
        metadata_digest = hashlib.sha256(b"dummy-store-metadata").hexdigest()
        size = 17
        record = {
            "ok": True,
            "schema_version": self.module.PACKAGE_UPLOAD_RECEIPT_SCHEMA_VERSION,
            "contract": self.module.PACKAGE_UPLOAD_RECEIPT_CONTRACT,
            "release": self.module.CANONICAL_RELEASE,
            "target_id": "android-phone-tablet-aab",
            "platform": "android",
            "artifact": {
                "path": "artifacts/android-phone-tablet-aab.aab",
                "sha256": digest,
                "bytes": size,
            },
            "build_receipt": {
                "path": ".artifacts/release-build-receipts/android/android-phone-tablet-aab.json",
                "sha256": build_digest,
                "target": "google-play-phone-tablet",
            },
            "producer": {
                "id": "tools/verify_android_aab_signers.py",
                "path": "tools/verify_android_aab_signers.py",
                "sha256": producer_digest,
            },
            "package_identity": {
                "package": "org.winsvpn.app",
                "version_name": "1.0.16",
                "version_code": 33,
                "form": "phone-tablet",
            },
            "architectures": ["arm64-v8a", "armeabi-v7a", "x86_64"],
            "signing": {
                "contract": "play-upload-certificate",
                "certificate_sha256": self.pin,
            },
            "store_evidence": {
                "surface": "google-play-phone-tablet",
                "status": "not_uploaded",
                "metadata_sha256": metadata_digest,
            },
            "descriptor": {
                "path": "tools/verify_android_aab_signers.py",
                "sha256": descriptor_digest,
            },
            "source_freeze": {
                "path": ".artifacts/release-freeze-1.0.16+33/SOURCE_FREEZE_RECEIPT.json",
                "sha256": freeze_digest,
            },
            "obfuscation_privacy": {
                "path": "tools/release_obfuscation_contract.py",
                "sha256": privacy_digest,
            },
            "publication_authorized": False,
            "upload_attempted": False,
            "owner_authorization": {
                "contract": self.module.OWNER_AUTHORIZATION_CONTRACT,
                "schema_version": self.module.PACKAGE_UPLOAD_RECEIPT_SCHEMA_VERSION,
                "status": "pending",
                "credentials_authorized": False,
                "upload_authorized": False,
            },
            "authentication": {"authenticated": True},
        }
        path = self.write_aab("dummy.aab", form="phone")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        size = path.stat().st_size
        record["artifact"] = {
            "path": "dummy.aab",
            "sha256": digest,
            "bytes": size,
        }
        locked = (
            (ROOT / "tools/verify_android_aab_signers.py")
            .read_text(encoding="utf-8")
            .split("def _bind_package_upload_receipt_locked", 1)[1]
            .split("def bind_android_package_upload_receipts", 1)[0]
        )
        self.assertGreater(
            locked.find("_require_owner_issued_android_signature"),
            locked.find("_require_live_upload_bindings"),
        )
        with (
            mock.patch.object(self.module, "ROOT", self.work),
            mock.patch.object(
                self.module,
                "canonical_android_release",
                return_value=self.module.CANONICAL_RELEASE,
            ),
            mock.patch.object(self.module, "_bind_upload_receipt_authentication"),
            mock.patch.object(self.module, "_require_live_upload_bindings"),
            mock.patch.object(
                self.module,
                "_reviewed_store_metadata",
                return_value={"sha256": metadata_digest},
            ),
            mock.patch.object(
                self.module,
                "verify_held_aab_artifact",
                side_effect=self.module.SignerError(
                    "jarsigner did not prove a cryptographically verified AAB"
                ),
            ),
        ):
            with self.assertRaisesRegex(
                self.module.SignerError,
                "no owner-issued Play upload signature",
            ):
                result = self.module.bind_package_upload_receipt(
                    "android-phone-tablet-aab",
                    record,
                    artifact_sha256=digest,
                    artifact_bytes=size,
                )
                self.fail(f"receipt bind went green: {result}")


PINNED_PYTHON = pathlib.Path("/Users/owner/.local/toolchains/python3.14.7/bin/python3.14")
REVIEWED_BUNDLETOOL = pathlib.Path(
    "/Users/owner/.winsvpn/tool-cache/bundletool/bundletool-all-1.18.3.jar"
)


def custody_tree_digest(root: pathlib.Path) -> str:
    """Independent copy of the pinned-JDK custody tree encoding."""

    digest = hashlib.sha256()

    def feed(*parts: object) -> None:
        for part in parts:
            value = str(part).encode("utf-8", "surrogateescape")
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)

    def scan(directory: pathlib.Path, relative: str) -> None:
        for name in sorted(os.listdir(directory), key=os.fsencode):
            child = directory / name
            child_relative = f"{relative}/{name}" if relative else name
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode):
                feed("L", child_relative, os.readlink(child))
            elif stat.S_ISDIR(info.st_mode):
                feed("D", child_relative, 0o500)
                scan(child, child_relative)
            else:
                mode = 0o500 if stat.S_IMODE(info.st_mode) & 0o111 else 0o400
                feed(
                    "F",
                    child_relative,
                    mode,
                    info.st_size,
                    hashlib.sha256(child.read_bytes()).hexdigest(),
                )

    scan(root, "")
    return digest.hexdigest()


class PinnedSignerToolchainTests(unittest.TestCase):
    """Pinned interpreter, bounded runner, pinned JDK, and pinned apksigner."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_signer()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="aab-toolchain-")
        self.addCleanup(self.temporary.cleanup)
        self.work = pathlib.Path(self.temporary.name).resolve(strict=True)
        self.addCleanup(self._restore_modes)

    def _restore_modes(self) -> None:
        for directory, _dirs, _files in os.walk(self.work):
            os.chmod(directory, 0o700)

    def sha256(self, path: pathlib.Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def no_scope(self, *_args, **_kwargs):
        self.fail("unsafe pinned input reached an authority scope")

    # Pinned release Python (replaces the /Library ReleasePython launcher).

    @contextlib.contextmanager
    def fake_runtime(self, executable: pathlib.Path, digest: str, *, isolated=True):
        flags = mock.Mock(isolated=1 if isolated else 0, no_site=1 if isolated else 0)
        with (
            mock.patch.object(
                self.module,
                "_pinned_python_identity",
                return_value=(executable, digest),
            ),
            mock.patch.object(self.module.sys, "executable", str(executable)),
            mock.patch.object(self.module.sys, "version_info", (3, 14, 7, "final", 0)),
            mock.patch.object(self.module.sys, "flags", flags),
        ):
            yield

    def interpreter_fixture(self, name: str = "python3.14") -> pathlib.Path:
        bindir = self.work / "toolchains" / "python3.14.7" / "bin"
        bindir.mkdir(parents=True, exist_ok=True)
        executable = bindir / name
        executable.write_bytes(b"\xcf\xfa\xed\xfe synthetic pinned interpreter bytes")
        executable.chmod(0o755)
        return executable

    def test_pinned_runtime_accepts_exact_interpreter_bytes(self) -> None:
        executable = self.interpreter_fixture()
        with self.fake_runtime(executable, self.sha256(executable)):
            with self.module._pinned_release_python_runtime():
                entered = True
        self.assertTrue(entered)

    def test_pinned_runtime_refuses_unpinned_or_unsafe_interpreter(self) -> None:
        executable = self.interpreter_fixture()
        digest = self.sha256(executable)
        other = self.interpreter_fixture("python3.14-other")
        cases = {}
        cases["sha256 mismatch"] = (executable, "1" * 64, executable, True, "sha256")
        cases["different path"] = (executable, digest, other, True, "reviewed path")
        cases["no -I -S"] = (executable, digest, executable, False, "-I -S")
        for label, (pinned, pin, running, isolated, pattern) in cases.items():
            with self.subTest(case=label):
                with self.fake_runtime(pinned, pin, isolated=isolated):
                    with mock.patch.object(self.module.sys, "executable", str(running)):
                        with self.assertRaisesRegex(self.module.SignerError, pattern):
                            with self.module._pinned_release_python_runtime():
                                self.no_scope()
        with self.fake_runtime(executable, digest):
            with mock.patch.object(self.module.sys, "version_info", (3, 9, 6, "final", 0)):
                with self.assertRaisesRegex(self.module.SignerError, "3.14.7"):
                    with self.module._pinned_release_python_runtime():
                        self.no_scope()

    def test_pinned_runtime_refuses_symlink_hardlink_and_writable_interpreter(self) -> None:
        executable = self.interpreter_fixture()
        digest = self.sha256(executable)
        link = executable.parent / "python3"
        link.symlink_to(executable.name)
        with self.fake_runtime(link, digest):
            with self.assertRaisesRegex(self.module.SignerError, "symlink|absent or unsafe"):
                with self.module._pinned_release_python_runtime():
                    self.no_scope()
        linked_parent = self.work / "linked-toolchains"
        linked_parent.symlink_to(self.work / "toolchains")
        through_link = linked_parent / "python3.14.7" / "bin" / executable.name
        with self.fake_runtime(through_link, digest):
            with self.assertRaisesRegex(self.module.SignerError, "symlink|absent or unsafe"):
                with self.module._pinned_release_python_runtime():
                    self.no_scope()
        hardlink = self.work / "python-hardlink"
        os.link(executable, hardlink)
        try:
            with self.fake_runtime(executable, digest):
                with self.assertRaisesRegex(self.module.SignerError, "single-link"):
                    with self.module._pinned_release_python_runtime():
                        self.no_scope()
        finally:
            hardlink.unlink()
        for mode in (0o775, 0o757):
            executable.chmod(mode)
            with self.subTest(mode=oct(mode)), self.fake_runtime(executable, digest):
                with self.assertRaisesRegex(self.module.SignerError, "group or world writable"):
                    with self.module._pinned_release_python_runtime():
                        self.no_scope()
        executable.chmod(0o755)
        executable.parent.chmod(0o777)
        try:
            with self.fake_runtime(executable, digest):
                with self.assertRaisesRegex(self.module.SignerError, "ancestor"):
                    with self.module._pinned_release_python_runtime():
                        self.no_scope()
        finally:
            executable.parent.chmod(0o755)

    def test_pinned_python_identity_comes_from_toolchain_pins(self) -> None:
        pins = json.loads((ROOT / "tools/toolchain-pins.json").read_text(encoding="utf-8"))
        python = pins["tools"]["python"]
        host = self.module._release_host_key()
        path, digest = self.module._pinned_python_identity()
        self.assertEqual(str(path), python["reviewed_executable_path"][host])
        self.assertEqual(digest, python["executable_sha256"][host])
        self.assertEqual(python["version"], "3.14.7")

    def test_toolchain_pins_are_strict_json(self) -> None:
        tools_dir = self.work / "tools"
        tools_dir.mkdir()
        (tools_dir / "toolchain-pins.json").write_text(
            '{"tools": {"python": {"version": "3.14.7"}, "python": {}}}',
            encoding="ascii",
        )
        with mock.patch.object(self.module, "ROOT", self.work):
            with self.assertRaisesRegex(self.module.SignerError, "duplicate-free"):
                self.module._toolchain_pins()

    def test_real_pinned_interpreter_runs_verifier_entry(self) -> None:
        if not PINNED_PYTHON.exists():
            self.skipTest("pinned release Python 3.14.7 is absent")
        script = ROOT / "tools/verify_android_aab_signers.py"
        environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": os.environ.get("HOME", str(self.work)),
            "TMPDIR": str(self.work),
        }
        isolated = subprocess.run(
            [str(PINNED_PYTHON), "-I", "-S", str(script), "--self-test"],
            cwd=self.work,
            env=environment,
            capture_output=True,
            timeout=120,
        )
        self.assertEqual(isolated.returncode, 0, isolated.stderr)
        self.assertIn(b"ANDROID AAB SINGLE SIGNER SELF-TEST: PASS", isolated.stdout)
        unisolated = subprocess.run(
            [str(PINNED_PYTHON), str(script), "--self-test"],
            cwd=self.work,
            env=environment,
            capture_output=True,
            timeout=120,
        )
        self.assertEqual(unisolated.returncode, 1)
        self.assertIn(b"started with -I -S is required", unisolated.stderr)

    def test_entry_point_has_no_owner_launcher_dependency(self) -> None:
        source = (ROOT / "tools/verify_android_aab_signers.py").read_text(encoding="ascii")
        self.assertEqual(source.splitlines()[0], "#!/usr/bin/env python3")
        self.assertNotIn("/Library/WinsVPN", source)
        self.assertNotIn("SF_IMMUTABLE", source)
        self.assertNotIn("_require_process_execution_boundary", source)

    # Bounded tool runner (replaces the always-refusing process boundary).

    def test_run_executes_child_and_returns_stdout(self) -> None:
        self.assertEqual(
            self.module._run(["/bin/echo", "pinned", "runner"], "echo probe"),
            b"pinned runner\n",
        )

    def test_run_reads_stdin_from_dev_null(self) -> None:
        self.assertEqual(self.module._run(["/bin/cat"], "stdin probe", timeout=10), b"")

    def test_run_passes_retained_descriptors_and_revalidates_around_child(self) -> None:
        payload = self.work / "payload.bin"
        payload.write_bytes(b"retained descriptor bytes")
        descriptor = os.open(payload, os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, descriptor)
        calls = []
        output = self.module._run(
            ["/bin/cat", f"/dev/fd/{descriptor}"],
            "descriptor probe",
            pass_fds=(descriptor,),
            watch_fds=(descriptor,),
            revalidate=lambda: calls.append(True),
        )
        self.assertEqual(output, b"retained descriptor bytes")
        self.assertEqual(len(calls), 2)

    def test_run_detects_watched_descriptor_mutation(self) -> None:
        target = self.work / "watched.bin"
        target.write_bytes(b"before")
        descriptor = os.open(target, os.O_RDWR | os.O_CLOEXEC)
        self.addCleanup(os.close, descriptor)
        with self.assertRaisesRegex(self.module.SignerError, "custody changed"):
            self.module._run(
                ["/bin/sh", "-c", f"printf mutated >> /dev/fd/{descriptor}"],
                "watched descriptor probe",
                pass_fds=(descriptor,),
                watch_fds=(descriptor,),
            )

    def test_run_nonzero_exit_fails_closed(self) -> None:
        with self.assertRaisesRegex(self.module.SignerError, "exit status 3: boom"):
            self.module._run(["/bin/sh", "-c", "echo boom >&2; exit 3"], "failing probe")

    def test_run_refuses_relative_command_and_invalid_descriptors(self) -> None:
        with self.assertRaisesRegex(self.module.SignerError, "absolute"):
            self.module._run(["echo", "x"], "relative probe")
        with self.assertRaisesRegex(self.module.SignerError, "descriptor set"):
            self.module._run(["/bin/echo"], "stdio probe", pass_fds=(1,))
        with self.assertRaisesRegex(self.module.SignerError, "deadline"):
            self.module._run(["/bin/echo"], "deadline probe", timeout=0)

    def test_run_output_bounds_fail_closed(self) -> None:
        cases = (
            ("MAX_TOOL_STDOUT_BYTES", "stdout", "/usr/bin/yes"),
            ("MAX_TOOL_STDERR_BYTES", "stderr", "/usr/bin/yes >&2"),
        )
        for constant, stream, command in cases:
            with self.subTest(stream=stream), mock.patch.object(self.module, constant, 4096):
                started = self.module.time.monotonic()
                with self.assertRaisesRegex(
                    self.module.SignerError, f"{stream} exceeded 4096 bytes"
                ):
                    self.module._run(["/bin/sh", "-c", command], f"{stream} flood", timeout=20)
                self.assertLess(self.module.time.monotonic() - started, 10)

    def wait_gone(self, pid: int) -> bool:
        deadline = self.module.time.monotonic() + 5
        while self.module.time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            self.module.time.sleep(0.05)
        return False

    def kill_quietly(self, pid_file: pathlib.Path) -> None:
        if pid_file.exists() and pid_file.read_text().strip():
            try:
                os.kill(int(pid_file.read_text().strip()), 9)
            except ProcessLookupError:
                pass

    def test_run_timeout_kills_whole_process_group(self) -> None:
        leader_file = self.work / "leader.pid"
        child_file = self.work / "grandchild.pid"
        self.addCleanup(self.kill_quietly, child_file)
        script = (
            f"echo $$ > {leader_file}; "
            f"/bin/sleep 60 & echo $! > {child_file}; "
            "wait"
        )
        started = self.module.time.monotonic()
        with self.assertRaisesRegex(self.module.SignerError, "timed out"):
            self.module._run(["/bin/sh", "-c", script], "sleeping group", timeout=2)
        self.assertLess(self.module.time.monotonic() - started, 8)
        self.assertTrue(self.wait_gone(int(leader_file.read_text())))
        self.assertTrue(self.wait_gone(int(child_file.read_text())))

    def test_run_kills_group_stragglers_after_leader_exits(self) -> None:
        child_file = self.work / "straggler.pid"
        self.addCleanup(self.kill_quietly, child_file)
        script = f"/bin/sleep 60 & echo $! > {child_file}; exit 0"
        started = self.module.time.monotonic()
        output = self.module._run(["/bin/sh", "-c", script], "straggler group", timeout=20)
        self.assertEqual(output, b"")
        self.assertLess(self.module.time.monotonic() - started, 10)
        self.assertTrue(self.wait_gone(int(child_file.read_text())))

    def test_run_child_leads_a_new_session(self) -> None:
        script = (
            "import os, sys\n"
            "sys.stdout.write('%d %d %d' % (os.getpid(), os.getpgrp(), os.getsid(0)))\n"
        )
        output = self.module._run(
            [self.module.sys.executable, "-I", "-S", "-c", script], "session probe"
        ).decode("ascii")
        pid, group, session = (int(value) for value in output.split())
        self.assertEqual(pid, group)
        self.assertEqual(pid, session)
        self.assertNotEqual(group, os.getpgrp())

    def test_run_scrubs_jvm_and_loader_environment(self) -> None:
        hostile = {
            "JAVA_TOOL_OPTIONS": "-javaagent:/tmp/agent.jar",
            "_JAVA_OPTIONS": "-Xbootclasspath/a:/tmp/x",
            "JDK_JAVA_OPTIONS": "--add-opens=java.base/java.lang=ALL-UNNAMED",
            "CLASSPATH": "/tmp/hostile",
            "LD_PRELOAD": "/tmp/hostile.so",
            "DYLD_INSERT_LIBRARIES": "/tmp/hostile.dylib",
        }
        script = "import json, os\nprint(json.dumps(sorted(os.environ)))\n"
        command = [self.module.sys.executable, "-I", "-S", "-c", script]
        with mock.patch.dict(os.environ, hostile, clear=False):
            names = set(json.loads(self.module._run(command, "env probe")))
        self.assertFalse(names & set(hostile), names)
        self.assertIn("PATH", names)
        injected = {"PATH": "/usr/bin:/bin", **hostile}
        with mock.patch.object(
            self.module, "_safe_tool_environment", return_value=injected
        ):
            names = set(json.loads(self.module._run(command, "env probe")))
        self.assertFalse(names & set(hostile), names)

    # Pinned JDK (replaces the root-owned SF_IMMUTABLE /Library JDK custody).

    def jdk_fixture(self, *, runtime_version: str = "17.0.20.1+1") -> pathlib.Path:
        root = self.work / "toolchains" / "jdk-17.0.20.1"
        (root / "bin").mkdir(parents=True)
        (root / "lib").mkdir()
        for name in ("java", "jarsigner", "keytool"):
            tool = root / "bin" / name
            tool.write_text(f"#!/bin/sh\necho fixture-{name}\n", encoding="ascii")
            tool.chmod(0o555)
        (root / "lib" / "modules").write_bytes(b"synthetic module image")
        (root / "lib" / "modules").chmod(0o444)
        (root / "release").write_text(
            'IMPLEMENTOR="Eclipse Adoptium"\n'
            f'JAVA_RUNTIME_VERSION="{runtime_version}"\n'
            'JAVA_VERSION="17.0.20.1"\n',
            encoding="ascii",
        )
        (root / "release").chmod(0o444)
        return root

    @contextlib.contextmanager
    def pinned_jdk(self, root: pathlib.Path, *, tree_sha256: str | None = None, tools=None):
        identity = {
            "root": root,
            "tree_sha256": tree_sha256 or custody_tree_digest(root),
            "version": "17.0.20.1",
            "runtime_version": "17.0.20.1+1",
            "vendor": "Eclipse Adoptium",
        }
        tool_pins = tools or {
            name: self.sha256(root / "bin" / name)
            for name in ("java", "jarsigner", "keytool")
        }
        with (
            mock.patch.object(self.module, "_pinned_jdk_identity", return_value=identity),
            mock.patch.object(self.module, "OWNER_JDK_TOOL_SHA256", tool_pins),
        ):
            yield

    def test_pinned_jdk_fixture_binds_by_tree_and_tool_sha256(self) -> None:
        root = self.jdk_fixture()
        with self.pinned_jdk(root):
            with self.module._HeldAndroidVerificationTools(bind_bundletool=False) as held:
                self.assertEqual(held.jdk_root, root)
                self.assertEqual(
                    held.jdk_tools,
                    tuple(str(root / "bin" / name) for name in ("java", "jarsigner", "keytool")),
                )
                self.assertEqual(
                    self.module._run([held.jdk_tools[0]], "fixture java", pass_fds=held.pass_fds),
                    b"fixture-java\n",
                )
                held.revalidate(full_tree=True)
            self.assertEqual(
                str(self.module._authenticate_jdk_tool(str(root / "bin" / "java"), "java")),
                str(root / "bin" / "java"),
            )
            with self.assertRaisesRegex(self.module.SignerError, "absolute authenticated"):
                self.module._authenticate_jdk_tool(
                    "/Library/WinsVPN/ReleaseAndroidToolchains/jdk-17.0.20.1/bin/java", "java"
                )

    def test_pinned_jdk_refuses_tree_digest_mismatch(self) -> None:
        root = self.jdk_fixture()
        with self.pinned_jdk(root, tree_sha256="2" * 64):
            with self.assertRaisesRegex(self.module.SignerError, "install tree sha256"):
                with self.module._HeldAndroidVerificationTools(bind_bundletool=False):
                    self.no_scope()

    def test_pinned_jdk_refuses_tool_digest_mismatch(self) -> None:
        root = self.jdk_fixture()
        tools = {name: self.sha256(root / "bin" / name) for name in ("java", "jarsigner", "keytool")}
        tools["jarsigner"] = "3" * 64
        with self.pinned_jdk(root, tools=tools):
            with self.assertRaisesRegex(self.module.SignerError, "jarsigner sha256"):
                with self.module._HeldAndroidVerificationTools(bind_bundletool=False):
                    self.no_scope()

    def test_pinned_jdk_refuses_wrong_release_identity(self) -> None:
        root = self.jdk_fixture(runtime_version="17.0.20+8")
        with self.pinned_jdk(root):
            with self.assertRaisesRegex(self.module.SignerError, "JAVA_RUNTIME_VERSION"):
                with self.module._HeldAndroidVerificationTools(bind_bundletool=False):
                    self.no_scope()

    def test_pinned_jdk_refuses_writable_hardlinked_or_symlinked_entries(self) -> None:
        root = self.jdk_fixture()
        modules = root / "lib" / "modules"
        for mode in (0o464, 0o446):
            modules.chmod(mode)
            with self.subTest(mode=oct(mode)), self.pinned_jdk(root):
                with self.assertRaisesRegex(self.module.SignerError, "not group or world writable"):
                    with self.module._HeldAndroidVerificationTools(bind_bundletool=False):
                        self.no_scope()
        modules.chmod(0o444)
        (root / "lib").chmod(0o775)
        with self.subTest(entry="writable directory"), self.pinned_jdk(root):
            with self.assertRaisesRegex(self.module.SignerError, "not group or world writable"):
                with self.module._HeldAndroidVerificationTools(bind_bundletool=False):
                    self.no_scope()
        (root / "lib").chmod(0o755)
        hardlink = self.work / "modules-hardlink"
        os.link(modules, hardlink)
        with self.subTest(entry="hardlink"), self.pinned_jdk(root):
            with self.assertRaisesRegex(self.module.SignerError, "single-link"):
                with self.module._HeldAndroidVerificationTools(bind_bundletool=False):
                    self.no_scope()
        hardlink.unlink()
        (root / "lib" / "alias").symlink_to("modules")
        with self.subTest(entry="symlink"), self.pinned_jdk(root):
            with self.assertRaisesRegex(self.module.SignerError, "symlink"):
                with self.module._HeldAndroidVerificationTools(bind_bundletool=False):
                    self.no_scope()
        (root / "lib" / "alias").unlink()

    def test_pinned_jdk_refuses_symlinked_or_writable_ancestor(self) -> None:
        root = self.jdk_fixture()
        alias = self.work / "alias-toolchains"
        alias.symlink_to(root.parent)
        with self.pinned_jdk(alias / root.name, tree_sha256=custody_tree_digest(root)):
            with self.assertRaisesRegex(self.module.SignerError, "absent or unsafe"):
                with self.module._HeldAndroidVerificationTools(bind_bundletool=False):
                    self.no_scope()
        root.parent.chmod(0o777)
        try:
            with self.pinned_jdk(root):
                with self.assertRaisesRegex(self.module.SignerError, "absent or unsafe"):
                    with self.module._HeldAndroidVerificationTools(bind_bundletool=False):
                        self.no_scope()
        finally:
            root.parent.chmod(0o755)

    def test_pinned_jdk_ancestor_activity_is_allowed_but_substitution_fails(self) -> None:
        root = self.jdk_fixture()
        with self.pinned_jdk(root):
            held = self.module._HeldAndroidVerificationTools(bind_bundletool=False)
            held.__enter__()
            try:
                (root.parent / "unrelated-neighbour").write_bytes(b"x")
                (self.work / "unrelated-home-entry").mkdir()
                held.revalidate(full_tree=True)
                moved = root.parent.with_name("toolchains-moved")
                os.rename(root.parent, moved)
                shutil.copytree(moved, root.parent, symlinks=True)
                with self.assertRaisesRegex(self.module.SignerError, "substituted"):
                    held.revalidate(full_tree=True)
            finally:
                held.close()

    def test_pinned_jdk_root_resolution_and_pin_agreement(self) -> None:
        home = self.work / "home"
        with mock.patch.dict(os.environ, {"HOME": str(home)}, clear=False):
            os.environ.pop(self.module.JDK_ROOT_ENV, None)
            identity = self.module._pinned_jdk_identity()
            self.assertEqual(
                identity["root"], home / ".local" / "toolchains" / "jdk-17.0.20.1"
            )
            self.assertEqual(identity["tree_sha256"], self.module.OWNER_JDK_TREE_SHA256)
            self.assertEqual(identity["runtime_version"], "17.0.20.1+1")
            self.assertEqual(identity["vendor"], "Eclipse Adoptium")
            os.environ[self.module.JDK_ROOT_ENV] = str(self.work / "explicit-jdk")
            self.assertEqual(
                self.module._pinned_jdk_identity()["root"], self.work / "explicit-jdk"
            )
            for hostile in ("relative/jdk", str(self.work / "a" / ".." / "jdk")):
                os.environ[self.module.JDK_ROOT_ENV] = hostile
                with self.assertRaisesRegex(self.module.SignerError, "absolute normalized"):
                    self.module._pinned_jdk_identity()
            os.environ.pop(self.module.JDK_ROOT_ENV, None)
            with mock.patch.object(self.module, "OWNER_JDK_TREE_SHA256", "4" * 64):
                with self.assertRaisesRegex(self.module.SignerError, "disagrees"):
                    self.module._pinned_jdk_identity()

    def test_pinned_jdk_tool_pins_match_installed_tools(self) -> None:
        root = self.module._pinned_jdk_identity()["root"]
        if not root.exists():
            self.skipTest("pinned Android JDK is absent")
        for name, digest in self.module.OWNER_JDK_TOOL_SHA256.items():
            self.assertEqual(self.sha256(root / "bin" / name), digest, name)

    def test_real_pinned_jdk_runs_reviewed_bundletool(self) -> None:
        root = self.module._pinned_jdk_identity()["root"]
        if not root.exists() or not REVIEWED_BUNDLETOOL.exists():
            self.skipTest("pinned Android JDK or reviewed bundletool is absent")
        with mock.patch.dict(
            os.environ, {self.module.BUNDLETOOL_ENV: str(REVIEWED_BUNDLETOOL)}, clear=False
        ):
            with self.module._HeldAndroidVerificationTools() as held:
                jar = self.module._assert_frozen_bundletool()
                self.assertEqual(jar.parent, held._bundle_directory_path)
                self.assertEqual(self.sha256(jar), self.module.BUNDLETOOL_ALL_SHA256)
                private_directory = held._bundle_directory_path
        self.assertFalse(private_directory.exists())

    # Pinned apksigner (replaces the root-owned /Library apksigner custody).

    def sdk_fixture(self) -> tuple[pathlib.Path, pathlib.Path]:
        sdk = self.work / "android-sdk"
        jar = sdk.joinpath(*self.module.APKSIGNER_JAR_RELATIVE)
        jar.parent.mkdir(parents=True)
        jar.write_bytes(b"PK synthetic apksigner fixture")
        jar.chmod(0o644)
        (jar.parent / "d8.jar").write_bytes(b"neighbour files are allowed")
        return sdk, jar

    @contextlib.contextmanager
    def pinned_sdk(self, sdk: pathlib.Path, digest: str):
        with (
            mock.patch.dict(os.environ, {"ANDROID_SDK_ROOT": str(sdk)}, clear=False),
            mock.patch.object(self.module, "OWNER_APKSIGNER_JAR_SHA256", digest),
        ):
            yield

    def test_pinned_apksigner_binds_by_sha256_into_private_snapshot(self) -> None:
        sdk, jar = self.sdk_fixture()
        with self.pinned_sdk(sdk, self.sha256(jar)):
            with self.module._HeldApksigner() as apksigner:
                snapshot = apksigner.path
                self.assertNotEqual(snapshot, jar)
                self.assertEqual(snapshot.read_bytes(), jar.read_bytes())
                self.assertEqual(stat.S_IMODE(snapshot.lstat().st_mode), 0o400)
                self.assertEqual(stat.S_IMODE(snapshot.parent.lstat().st_mode), 0o500)
                self.assertEqual(os.listdir(snapshot.parent), [snapshot.name])
                apksigner.revalidate()
        self.assertFalse(snapshot.parent.exists())

    def test_pinned_apksigner_refuses_unpinned_or_unsafe_jar(self) -> None:
        sdk, jar = self.sdk_fixture()
        digest = self.sha256(jar)
        with self.subTest(case="sha256"), self.pinned_sdk(sdk, "5" * 64):
            with self.assertRaisesRegex(self.module.SignerError, "sha256"):
                with self.module._HeldApksigner():
                    self.no_scope()
        for mode in (0o664, 0o646):
            jar.chmod(mode)
            with self.subTest(mode=oct(mode)), self.pinned_sdk(sdk, digest):
                with self.assertRaisesRegex(self.module.SignerError, "group or world writable"):
                    with self.module._HeldApksigner():
                        self.no_scope()
        jar.chmod(0o644)
        hardlink = self.work / "apksigner-hardlink.jar"
        os.link(jar, hardlink)
        with self.subTest(case="hardlink"), self.pinned_sdk(sdk, digest):
            with self.assertRaisesRegex(self.module.SignerError, "single-link"):
                with self.module._HeldApksigner():
                    self.no_scope()
        hardlink.unlink()
        moved = jar.with_name("apksigner-real.jar")
        os.rename(jar, moved)
        jar.symlink_to(moved.name)
        with self.subTest(case="symlink"), self.pinned_sdk(sdk, digest):
            with self.assertRaisesRegex(self.module.SignerError, "symlink"):
                with self.module._HeldApksigner():
                    self.no_scope()
        jar.unlink()
        os.rename(moved, jar)
        alias = self.work / "alias-sdk"
        alias.symlink_to(sdk)
        with self.subTest(case="symlinked ancestor"), self.pinned_sdk(alias, digest):
            with self.assertRaisesRegex(self.module.SignerError, "symlink"):
                with self.module._HeldApksigner():
                    self.no_scope()

    def test_pinned_apksigner_sdk_root_precedence(self) -> None:
        relative = pathlib.Path(*self.module.APKSIGNER_JAR_RELATIVE)
        home = self.work / "home"
        environment = {
            "HOME": str(home),
            "ANDROID_SDK_ROOT": str(self.work / "sdk-root"),
            "ANDROID_HOME": str(self.work / "sdk-home"),
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            self.assertEqual(
                self.module._pinned_apksigner_jar(), self.work / "sdk-root" / relative
            )
            os.environ.pop("ANDROID_SDK_ROOT")
            self.assertEqual(
                self.module._pinned_apksigner_jar(), self.work / "sdk-home" / relative
            )
            os.environ.pop("ANDROID_HOME")
            self.assertEqual(
                self.module._pinned_apksigner_jar(),
                home / ".local" / "android-sdk" / relative,
            )
            os.environ["ANDROID_SDK_ROOT"] = "relative-sdk"
            with self.assertRaisesRegex(self.module.SignerError, "absolute normalized"):
                self.module._pinned_apksigner_jar()

    def test_real_pinned_apksigner_runs_on_pinned_jdk(self) -> None:
        sdk = os.environ.get("WINS_TEST_APKSIGNER_SDK_ROOT", "")
        root = self.module._pinned_jdk_identity()["root"]
        if not sdk or not root.exists():
            self.skipTest("set WINS_TEST_APKSIGNER_SDK_ROOT to an SDK with build-tools 37.0.0")
        with mock.patch.dict(os.environ, {"ANDROID_SDK_ROOT": sdk}, clear=False):
            with (
                self.module._HeldAndroidVerificationTools(bind_bundletool=False) as tools,
                self.module._HeldApksigner() as apksigner,
            ):
                output = self.module._run(
                    [tools.jdk_tools[0], "-jar", str(apksigner.path), "version"],
                    "pinned apksigner version",
                    timeout=60,
                    pass_fds=(*tools.pass_fds, *apksigner.pass_fds),
                    watch_fds=(*tools.pass_fds, *apksigner.pass_fds),
                    revalidate=lambda: (tools.revalidate(full_tree=True), apksigner.revalidate()),
                )
        self.assertRegex(output.decode("ascii"), r"^[0-9]+\.[0-9]+")


if __name__ == "__main__":
    unittest.main()
