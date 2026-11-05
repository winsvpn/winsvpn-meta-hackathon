#!/usr/bin/env python3
"""Adversarial tests for artifact-only Linux cross-store gate adapters."""

from __future__ import annotations

import hashlib
import contextlib
import datetime
import gzip
import importlib.util
import io
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = pathlib.Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import tools.linux_cross_store_artifact_gate as gate
import tools.release_obfuscation_contract as obfuscation
import linux_cross_store_artifact_gate as canonical_gate


EXECUTABLES = {
    "wins_vpn",
    "winsvpn-bypass-bpf",
    "xray",
    "awg",
    "awg-quick",
    "amneziawg-go",
    "winn-datapath",
    "install.sh",
    "tools/native_messaging/host/wins_bridge_host",
    "tools/native_messaging/install_native_host.sh",
}
# The native-host source closure binds the live store_ids.json bytes, so the fixture
# packages the committed owner-issued record and its ids.
STORE_IDS_BYTES = (ROOT / "tools/native_messaging/manifests/store_ids.json").read_bytes()
CHROME_ID = json.loads(STORE_IDS_BYTES)["chrome"]
EDGE_ID = json.loads(STORE_IDS_BYTES)["edge"]
# Until the owner pins the upload-receipt trust, receipts stop at that blocker; once it is
# pinned (aca7fea), an unsigned receipt stops at the missing external authorization.
_UNAUTHORIZED_RECEIPT_REFUSAL = (
    "pending without owner evidence|no owner-issued Sigstore|OWNER-BLOCKED"
    if gate.owner_upload_receipt_trust_blocked()
    else "externally authorized upload receipt is missing"
)


def real_executable_elf(
    machine: int, *, marker: bytes = b"WINS", debug: bool = False
) -> bytes:
    names = (
        "",
        ".text",
        ".note.gnu.build-id",
        *((".debug_info", ".symtab", ".strtab") if debug else ()),
        ".shstrtab",
    )
    strtab = b""
    name_offsets: list[int] = []
    for name in names:
        name_offsets.append(len(strtab))
        strtab += name.encode("ascii") + b"\0"
    text = marker + bytes(32 - min(32, len(marker)))
    debug_payload = b"debug-info\x00" if debug else b""
    symbol_payload = bytearray(48) if debug else bytearray()
    symbol_strings = b"\0fixture_symbol\0" if debug else b""
    if debug:
        struct.pack_into("<IBBHQQ", symbol_payload, 24, 1, 0x12, 0, 1, 0, 16)
    build_id = hashlib.sha1(machine.to_bytes(2, "little") + marker).digest()
    note_payload = struct.pack("<III", 4, len(build_id), 3) + b"GNU\0" + build_id
    text_off = 64 + 56
    note_off = text_off + len(text)
    debug_off = note_off + len(note_payload)
    symbol_off = debug_off + len(debug_payload)
    symbol_str_off = symbol_off + len(symbol_payload)
    str_off = symbol_str_off + len(symbol_strings)
    shoff = str_off + len(strtab)
    shoff += (8 - (shoff % 8)) % 8
    shnum = len(names)
    data = bytearray(shoff + (shnum * 64))
    data[0:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    data[6] = 1
    data[7] = 0
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        data,
        16,
        3,
        machine,
        1,
        0x400000 + text_off,
        64,
        shoff,
        0,
        64,
        56,
        1,
        64,
        shnum,
        shnum - 1,
    )
    filesz = text_off + len(text)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0x400000, filesz, filesz, 0x1000)
    data[text_off : text_off + len(text)] = text
    data[note_off : note_off + len(note_payload)] = note_payload
    if debug:
        data[debug_off : debug_off + len(debug_payload)] = debug_payload
        data[symbol_off : symbol_off + len(symbol_payload)] = symbol_payload
        data[symbol_str_off : symbol_str_off + len(symbol_strings)] = symbol_strings
    data[str_off : str_off + len(strtab)] = strtab
    for index, name in enumerate(names):
        hdr = shoff + (index * 64)
        struct.pack_into("<I", data, hdr, name_offsets[index])
        if name == ".text":
            struct.pack_into("<I", data, hdr + 4, 1)
            struct.pack_into("<Q", data, hdr + 24, text_off)
            struct.pack_into("<Q", data, hdr + 32, len(text))
        elif name == ".note.gnu.build-id":
            struct.pack_into("<I", data, hdr + 4, 7)
            struct.pack_into("<Q", data, hdr + 24, note_off)
            struct.pack_into("<Q", data, hdr + 32, len(note_payload))
        elif name == ".debug_info":
            struct.pack_into("<I", data, hdr + 4, 1)
            struct.pack_into("<Q", data, hdr + 24, debug_off)
            struct.pack_into("<Q", data, hdr + 32, len(debug_payload))
        elif name == ".symtab":
            struct.pack_into("<I", data, hdr + 4, 2)
            struct.pack_into("<Q", data, hdr + 24, symbol_off)
            struct.pack_into("<Q", data, hdr + 32, len(symbol_payload))
            struct.pack_into("<I", data, hdr + 40, names.index(".strtab"))
            struct.pack_into("<I", data, hdr + 44, 1)
            struct.pack_into("<Q", data, hdr + 56, 24)
        elif name == ".strtab":
            struct.pack_into("<I", data, hdr + 4, 3)
            struct.pack_into("<Q", data, hdr + 24, symbol_str_off)
            struct.pack_into("<Q", data, hdr + 32, len(symbol_strings))
        elif name == ".shstrtab":
            struct.pack_into("<I", data, hdr + 4, 3)
            struct.pack_into("<Q", data, hdr + 24, str_off)
            struct.pack_into("<Q", data, hdr + 32, len(strtab))
    return bytes(data)


def ring_bound_elf(machine: int, *, marker: bytes = b"libapp") -> bytes:
    return real_executable_elf(machine, marker=marker) + (
        gate.REVIEWED_WINN3_DESCRIPTOR_RING_SHA256.encode("ascii")
    )


def fixture_libapp_build_id(machine: int) -> str:
    return hashlib.sha1(machine.to_bytes(2, "little") + b"libapp").hexdigest()


@contextlib.contextmanager
def retained_extraction_directory(path: pathlib.Path):
    chain = gate._retain_complete_directory_chain(
        path.parent, "fixture extraction directory"
    )
    fd = gate._openat_child(
        chain.leaf_fd,
        path.name,
        gate._dir_open_flags(),
        label="fixture extraction directory",
    )
    retained = gate._RetainedExtractionDirectory(
        path=path,
        name=path.name,
        fd=fd,
        identity=gate._directory_identity(os.fstat(fd)),
        parent_generation=(
            os.fstat(chain.leaf_fd).st_mtime_ns,
            os.fstat(chain.leaf_fd).st_ctime_ns,
        ),
        parent_chain=chain,
    )
    try:
        yield retained
    finally:
        retained.close()
        chain.close()


def winn3_attestation_document(identity: str | None = None) -> bytes:
    return gate._canonical_winn3_descriptor_ring_attestation(
        identity or gate.REVIEWED_WINN3_DESCRIPTOR_RING_SHA256
    )


def truncated_elf_header(machine: int) -> bytes:
    payload = bytearray(64)
    payload[:6] = b"\x7fELF\x02\x01"
    payload[16:18] = (3).to_bytes(2, "little")
    payload[18:20] = machine.to_bytes(2, "little")
    return bytes(payload)


def _write_json_fixture(path: pathlib.Path, record: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )


def _source_freeze_receipt_fixture() -> dict[str, object]:
    return {
        "schema_version": 1,
        "contract": gate.freeze.SOURCE_FREEZE_RECEIPT_CONTRACT,
        "release": gate.CANONICAL_RELEASE,
        "created_utc": "2026-08-25T00:00:00+00:00",
        "issuance_id": "a" * 32,
        "authenticated": True,
        "issuer": gate.freeze.SOURCE_FREEZE_RECEIPT_ISSUER,
        "app_source_lock": {
            "path": ".artifacts/release-freeze-1.0.17+34/APP_SOURCE_LOCK.json",
            "sha256": hashlib.sha256(b"adapter-app-source-lock").hexdigest(),
        },
    }


def _build_receipt_fixture(target: str) -> dict[str, object]:
    digest = hashlib.sha256(target.encode("ascii")).hexdigest()
    source_path = (
        ".artifacts/release-freeze-1.0.17+34/SOURCE_FREEZE_RECEIPT.json"
    )
    return {
        "schema_version": 1,
        "contract": gate.freeze.BUILD_RECEIPT_CONTRACT,
        "release": gate.CANONICAL_RELEASE,
        "platform": "linux",
        "begun_utc": "2026-08-25T00:00:00+00:00",
        "finished_utc": "2026-08-25T00:00:01+00:00",
        "build_begin_receipt": {
            "path": f".artifacts/release-build-receipts/linux/{target}.begin.json",
            "sha256": hashlib.sha256(f"{target}-begin".encode("ascii")).hexdigest(),
        },
        "build_attempt": {
            "contract": gate.freeze.BUILD_ATTEMPT_CONTRACT,
            "nonce": hashlib.sha256(f"{target}-nonce".encode("ascii")).hexdigest(),
        },
        "release_input_index": {
            "path": ".artifacts/freeze/RELEASE_INPUT_INDEX.json",
            "sha256": hashlib.sha256(b"adapter-release-index").hexdigest(),
        },
        "platform_manifest": {
            "path": ".artifacts/freeze/LINUX_INPUTS.json",
            "sha256": hashlib.sha256(b"adapter-linux-inputs").hexdigest(),
        },
        "shared_revision": "adapter-pristine-fixture",
        "producer": {
            "path": gate.freeze.PLATFORM_BUILD_PRODUCERS["linux"],
            "sha256": hashlib.sha256(b"adapter-linux-producer").hexdigest(),
        },
        "toolchain": {"target": target},
        "source_freeze": {
            "path": source_path,
            "sha256": hashlib.sha256(
                json.dumps(
                    _source_freeze_receipt_fixture(),
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
                + b"\n"
            ).hexdigest(),
            "issuance_id": "a" * 32,
        },
        "toolchain_custody": {
            "path": ".artifacts/release-freeze-1.0.17+34/TOOLCHAIN_CUSTODY_RECEIPT.json",
            "sha256": hashlib.sha256(b"adapter-toolchain-custody").hexdigest(),
            "issuance_id": "b" * 32,
        },
        "artifact": {
            "path": f".artifacts/linux/{target}.fixture",
            "sha256": digest,
            "bytes": len(target),
        },
        "sha256_anchor": {
            "path": f".artifacts/linux/{target}.fixture.sha256",
            "sha256": hashlib.sha256(f"{digest}  {target}.fixture\n".encode("ascii")).hexdigest(),
        },
        "publication_authorized": False,
    }


def _obfuscation_receipt_fixture(
    target_id: str, artifact_path: str, artifact_sha256: str, artifact_size: int
) -> dict[str, object]:
    return {
        "schema_version": 2,
        "contract": "winsvpn-release-obfuscation-and-secret-free-v2",
        "contract_sha256": hashlib.sha256(
            b"tools/release_obfuscation_contract.py"
        ).hexdigest(),
        "platform": "linux",
        "app_version": gate.CANONICAL_PRODUCT_VERSION,
        "build_number": "34",
        "created_at_utc": "2026-08-25T00:00:00+00:00",
        "private_symbols_not_packaged": True,
        "verification": {
            "artifact_privacy": True,
            "private_symbols_separate": True,
        },
        "artifacts": [
            {
                "path": artifact_path,
                "sha256": artifact_sha256,
                "size": artifact_size,
            }
        ],
        "symbols": [],
        "target_id": target_id,
    }


def _authenticated_snapshot(path: pathlib.Path, label: str) -> gate.AuthenticatedSnapshot:
    return gate._snapshot_artifact(path.resolve(strict=True), label)


def _build_provenance_custody(
    receipt: pathlib.Path, source_freeze_receipt: pathlib.Path
) -> gate._BuildProvenanceCustody:
    receipt_snapshot = _authenticated_snapshot(receipt, "fixture Linux build receipt")
    try:
        source_snapshot = _authenticated_snapshot(
            source_freeze_receipt, "fixture source-freeze receipt"
        )
    except BaseException:
        gate._close_retained_snapshots((receipt_snapshot,))
        raise
    return gate._BuildProvenanceCustody(receipt_snapshot, source_snapshot)


class LinuxPackageGateFixtures:
    """Shared authenticated package fixtures for adapter and focused gate tests."""
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name)
        self.downloads = self.repo / ".artifacts/linux"
        self.downloads.mkdir(parents=True)
        self.receipt = self.downloads / "LINUX_BUILD_RECEIPT.json"
        _write_json_fixture(self.receipt, _build_receipt_fixture("linux-x64"))
        self.source_freeze_receipt = (
            self.downloads / "SOURCE_FREEZE_RECEIPT.json"
        )
        _write_json_fixture(
            self.source_freeze_receipt, _source_freeze_receipt_fixture()
        )
        self.bundle = self.downloads / "bundle.sigstore.json"
        self.bundle.write_text("{}\n", encoding="utf-8")
        self.root_patch = mock.patch.object(gate, "ROOT", self.repo)
        self.root_patch.start()
        identity = self.repo / gate.RELEASE_IDENTITY_PATH
        identity.parent.mkdir(parents=True, exist_ok=True)
        identity.write_bytes((ROOT / gate.RELEASE_IDENTITY_PATH).read_bytes())
        trust_anchor = self.repo / gate.TRUSTED_LOCAL_COSIGN_KEY
        trust_anchor.parent.mkdir(parents=True, exist_ok=True)
        trust_anchor.write_text("reviewed fixture key\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.root_patch.stop()
        self.temporary.cleanup()

    def _signature_custody(
        self, _snapshot: gate.AuthenticatedSnapshot
    ) -> gate.AuthenticatedSnapshot:
        return _authenticated_snapshot(self.bundle, "fixture Linux Sigstore bundle")

    def _build_custody(
        self, _snapshot: gate.AuthenticatedSnapshot, _target: str
    ) -> gate._BuildProvenanceCustody:
        return _build_provenance_custody(
            self.receipt, self.source_freeze_receipt
        )

    def _source_freeze_custody(
        self,
    ) -> tuple[str, gate.AuthenticatedSnapshot]:
        return (
            self.source_closure[0],
            _authenticated_snapshot(
                self.source_freeze_receipt, "fixture source-freeze receipt"
            ),
        )

    def _payloads(self, machine: int = 62) -> dict[str, bytes]:
        payloads = {
            name: (
                b"#!/bin/sh\n"
                if name in {"awg-quick", "install.sh"}
                else real_executable_elf(machine, marker=name.encode("ascii"))
            )
            for name in (
                "wins_vpn",
                "winsvpn-bypass-bpf",
                "xray",
                "awg",
                "awg-quick",
                "amneziawg-go",
                "winn-datapath",
                "install.sh",
            )
        }
        payloads.update(
            {
                "lib/libapp.so": ring_bound_elf(machine, marker=b"libapp"),
                "lib/libflutter_linux_gtk.so": real_executable_elf(
                    machine, marker=b"libflutter"
                ),
                "data/icudtl.dat": b"icu-data-payload",
                "data/flutter_assets/AssetManifest.bin": b"asset-manifest",
                "data/flutter_assets/FontManifest.json": b"[]\n",
                gate.WINN3_DESCRIPTOR_RING_ATTESTATION_NAME: winn3_attestation_document(),
                "share/applications/org.winsvpn.app.desktop": b"[Desktop Entry]\nExec=wins_vpn %U\n",
                "share/metainfo/org.winsvpn.app.metainfo.xml": (
                    b"<component><id>org.winsvpn.app</id><releases>"
                    b'<release version="1.0.17" date="2026-08-23" />'
                    b'<release version="1.0.14" date="2026-07-13" />'
                    b"</releases></component>\n"
                ),
                "share/icons/hicolor/512x512/apps/org.winsvpn.app.png": b"png",
                "share/doc/wins-vpn/THIRD_PARTY_NOTICES.md": b"notices\n",
                "share/doc/wins-vpn/RECOVERY.md": b"recovery\n",
            }
        )
        installed_host = gate.NATIVE_HOST_INSTALLED_PATH
        payloads.update(
            {
                "extension/manifest/firefox.jsonc": (ROOT / "extension/manifest/firefox.jsonc").read_bytes(),
                "extension/tools/jsonc.py": (ROOT / "extension/tools/jsonc.py").read_bytes(),
                gate.NATIVE_HOST_PATH: real_executable_elf(machine, marker=b"native-host"),
                "tools/native_messaging/install_native_host.sh": (
                    ROOT / "tools/native_messaging/install_native_host.sh"
                ).read_bytes(),
                "tools/native_messaging/native_host_layout.py": (
                    ROOT / "tools/native_messaging/native_host_layout.py"
                ).read_bytes(),
                "tools/native_messaging/render_host_manifest.py": (
                    ROOT / "tools/native_messaging/render_host_manifest.py"
                ).read_bytes(),
                "tools/native_messaging/manifests/store_ids.json": STORE_IDS_BYTES,
                "tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json": json.dumps(
                    {
                        "name": "org.winsvpn.bridge",
                        "description": "Win's VPN browser bridge",
                        "path": installed_host,
                        "type": "stdio",
                        "allowed_origins": [f"chrome-extension://{CHROME_ID}/"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
                + b"\n",
                "tools/native_messaging/manifests/org.winsvpn.bridge.edge.json": json.dumps(
                    {
                        "name": "org.winsvpn.bridge",
                        "description": "Win's VPN browser bridge",
                        "path": installed_host,
                        "type": "stdio",
                        "allowed_origins": [f"chrome-extension://{EDGE_ID}/"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
                + b"\n",
                "tools/native_messaging/manifests/org.winsvpn.bridge.firefox.json": json.dumps(
                    {
                        "name": "org.winsvpn.bridge",
                        "description": "Win's VPN browser bridge",
                        "path": installed_host,
                        "type": "stdio",
                        "allowed_extensions": ["companion@winsvpn.org"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
                + b"\n",
            }
        )
        source_inputs = []
        for relative in gate.native_host_source_paths():
            if relative in payloads:
                source = payloads[relative]
            else:
                source = (ROOT / relative).read_bytes()
            source_inputs.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(source).hexdigest(),
                    "bytes": len(source),
                }
            )
        source_encoding = (
            json.dumps(source_inputs, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode("ascii")
        self.source_closure = (
            hashlib.sha256(source_encoding).hexdigest(),
            source_inputs,
        )
        packaged_assets = []
        for relative in sorted(gate.NATIVE_HOST_PACKAGED_ASSETS):
            value = payloads[relative]
            packaged_assets.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(value).hexdigest(),
                    "bytes": len(value),
                    "mode": 0o755 if relative in EXECUTABLES else 0o644,
                }
            )
        pins = json.loads((ROOT / "tools/toolchain-pins.json").read_text(encoding="utf-8"))[
            "tools"
        ]["flutter"]
        arch = "x64" if machine == 62 else "arm64"
        provenance = {
            "schema_version": 1,
            "kind": "winsvpn.linux.native_messaging_host.provenance.v1",
            "architecture": arch,
            "elf_machine": machine,
            "installed_host_path": installed_host,
            "hardening": {
                "compile_mode": "dart-aot-product",
                "tree_shaken": True,
                "debug_info_detached": True,
                "delivery_symbols_stripped": True,
                "host_dart_sources_shipped": False,
            },
            "toolchain": {
                "dart_version": pins["dart_version"],
                "flutter_version": pins["version"],
                "flutter_revision": pins["revision"],
                "compile_arguments": [
                    "compile",
                    "exe",
                    "--target-os=linux",
                    f"--target-arch={arch}",
                    "--save-debugging-info=<private-custody>/wins_bridge_host.debug",
                    "bin/wins_bridge_host.dart",
                ],
            },
            "source_closure_sha256": self.source_closure[0],
            "source_inputs": source_inputs,
            "packaged_assets": packaged_assets,
            "private_debug_info": {
                "sha256": "d" * 64,
                "bytes": 4096,
                "mode": 0o600,
            },
        }
        payloads[gate.NATIVE_HOST_PROVENANCE_PATH] = (
            json.dumps(provenance, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode("ascii")
        return payloads

    def _write_archive(
        self,
        arch: str = "x64",
        machine: int = 62,
        *,
        mutate_manifest: bool = False,
        unsafe_member: tarfile.TarInfo | None = None,
        payload_overrides: dict[str, bytes] | None = None,
        omit: set[str] | None = None,
        mode_overrides: dict[str, int] | None = None,
    ) -> pathlib.Path:
        artifact = self.downloads / f"wins-vpn-linux-{arch}.tar.gz"
        payloads = self._payloads(machine)
        payloads.update(payload_overrides or {})
        for name in omit or set():
            payloads.pop(name, None)
        manifest = "".join(
            f"{hashlib.sha256(payload).hexdigest()}  {name}\n"
            for name, payload in sorted(payloads.items())
        ).encode("ascii")
        if mutate_manifest:
            manifest = manifest.replace(b"a", b"b", 1)
        payloads["release-manifest.sha256"] = manifest
        tar_buffer = io.BytesIO()
        entries: list[tuple[str, tarfile.TarInfo, bytes]] = []
        for name, payload in payloads.items():
            info = tarfile.TarInfo(f"./{name}")
            info.size = len(payload)
            info.uid = 0
            info.gid = 0
            info.mtime = 0
            info.mode = (mode_overrides or {}).get(
                name, 0o755 if name in EXECUTABLES else 0o644
            )
            entries.append((info.name, info, payload))
        if unsafe_member is not None:
            unsafe_member.mtime = 0
            entries.append((unsafe_member.name, unsafe_member, b"x"))
        with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
            for _name, info, payload in sorted(entries, key=lambda item: item[0]):
                archive.addfile(info, io.BytesIO(payload))
        with artifact.open("wb") as output:
            with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
                compressed.write(tar_buffer.getvalue())
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        artifact.with_name(artifact.name + ".sha256").write_text(
            f"{digest}  {artifact.name}\n", encoding="ascii"
        )
        return artifact

    def _verify(
        self,
        target: str,
        artifact: pathlib.Path,
        *,
        bind_owner: bool = True,
        owner_ids: dict[str, str] | None = None,
    ) -> dict[str, object]:
        issued = owner_ids or {"chrome": CHROME_ID, "edge": EDGE_ID}
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    gate, "_verify_signature", side_effect=self._signature_custody
                )
            )
            stack.enter_context(
                mock.patch.object(
                    gate, "_verify_build_provenance", side_effect=self._build_custody
                )
            )
            stack.enter_context(
                mock.patch.object(
                    gate,
                    "_bind_native_host_source_freeze_custody",
                    side_effect=self._source_freeze_custody,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    gate,
                    "OWNER_COSIGN_TRUST_ANCHOR_SHA256",
                    "a" * 64,
                )
            )
            if bind_owner:
                stack.enter_context(
                    mock.patch.object(
                        gate, "_owner_issued_chromium_ids", return_value=issued
                    )
                )
            return gate.verify_package(
                target, artifact.relative_to(self.repo).as_posix()
            )


class LinuxPackageAdapterTests(LinuxPackageGateFixtures, unittest.TestCase):
    def test_x64_and_arm64_archives_bind_exact_target_without_processes(self) -> None:
        x64 = self._write_archive("x64", 62)
        x64_result = self._verify("linux-x64-package", x64)
        with x64_result:
            self.assertEqual(x64_result["elf_machine"], 62)
            self.assertEqual(x64_result["appstream_version"], "1.0.17")
            self.assertEqual(x64_result["debian_version"], "1.0.17-34")
            self.assertIn("lib/libapp.so", x64_result["flutter_identities"])
            x64_libapp = x64_result["flutter_identities"]["lib/libapp.so"][
                "sha256"
            ]
        x64.unlink()
        x64.with_name(x64.name + ".sha256").unlink()
        arm64 = self._write_archive("arm64", 183)
        arm64_result = self._verify("linux-arm64-package", arm64)
        with arm64_result:
            self.assertEqual(arm64_result["elf_machine"], 183)
            self.assertNotEqual(
                x64_libapp,
                arm64_result["flutter_identities"]["lib/libapp.so"]["sha256"],
            )

    def test_stale_appstream_version_fails_closed(self) -> None:
        stale = (
            b"<component><id>org.winsvpn.app</id><releases>"
            b'<release version="9.9.9" date="2026-08-23" />'
            b'<release version="1.0.17" date="2026-08-22" />'
            b"</releases></component>\n"
        )
        artifact = self._write_archive(
            payload_overrides={
                "share/metainfo/org.winsvpn.app.metainfo.xml": stale
            }
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "canonical release version"
        ):
            self._verify("linux-x64-package", artifact)

    def test_schema_v2_receipt_identity_fails_closed_on_v1(self) -> None:
        identity_path = self.repo / gate.RELEASE_IDENTITY_PATH
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
        identity["schema_version"] = 1
        identity_path.write_text(json.dumps(identity, sort_keys=True) + "\n", encoding="utf-8")
        artifact = self._write_archive()
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "AppStream/Debian"
        ):
            self._verify("linux-x64-package", artifact)

    def test_stale_debian_identity_mapping_fails_closed(self) -> None:
        identity_path = self.repo / gate.RELEASE_IDENTITY_PATH
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
        identity["platform_mappings"]["linux"]["debian_version"] = "9.9.9-999"
        identity_path.write_text(
            json.dumps(identity, sort_keys=True) + "\n", encoding="utf-8"
        )
        artifact = self._write_archive()
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "AppStream/Debian"
        ):
            self._verify("linux-x64-package", artifact)

    def test_wrong_target_architecture_and_filename_fail_closed(self) -> None:
        x64 = self._write_archive("x64", 62)
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "another exact target"
        ):
            self._verify("linux-arm64-package", x64)
        arm64_named = self.downloads / "wins-vpn-linux-arm64.tar.gz"
        x64.rename(arm64_named)
        x64.with_name(x64.name + ".sha256").rename(
            arm64_named.with_name(arm64_named.name + ".sha256")
        )
        digest = hashlib.sha256(arm64_named.read_bytes()).hexdigest()
        arm64_named.with_name(arm64_named.name + ".sha256").write_text(
            f"{digest}  {arm64_named.name}\n", encoding="ascii"
        )
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "ELF machine"):
            self._verify("linux-arm64-package", arm64_named)

    def test_manifest_tamper_and_checksum_tamper_fail_closed(self) -> None:
        artifact = self._write_archive(mutate_manifest=True)
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "manifest"):
            self._verify("linux-x64-package", artifact)
        artifact.unlink()
        artifact.with_name(artifact.name + ".sha256").unlink()
        artifact = self._write_archive()
        artifact.with_name(artifact.name + ".sha256").write_text(
            f"{'0' * 64}  {artifact.name}\n", encoding="ascii"
        )
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "checksum"):
            self._verify("linux-x64-package", artifact)

    def test_native_host_and_both_browser_registration_assets_are_mandatory(self) -> None:
        for missing in (
            gate.NATIVE_HOST_PATH,
            "tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json",
            "tools/native_messaging/manifests/org.winsvpn.bridge.edge.json",
            "tools/native_messaging/manifests/org.winsvpn.bridge.firefox.json",
            "tools/native_messaging/install_native_host.sh",
            gate.NATIVE_HOST_PROVENANCE_PATH,
            "lib/libapp.so",
            "lib/libflutter_linux_gtk.so",
            "data/icudtl.dat",
            "winsvpn-bypass-bpf",
        ):
            with self.subTest(missing=missing):
                artifact = self._write_archive(omit={missing})
                with self.assertRaisesRegex(gate.LinuxArtifactGateError, "incomplete|Flutter/runtime"):
                    self._verify("linux-x64-package", artifact)
                artifact.unlink()
                artifact.with_name(artifact.name + ".sha256").unlink()

    def test_native_host_wrong_architecture_placeholder_and_provenance_tamper_fail_closed(self) -> None:
        artifact = self._write_archive(
            payload_overrides={
                gate.NATIVE_HOST_PATH: real_executable_elf(183, marker=b"native-host")
            }
        )
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "ELF machine"):
            self._verify("linux-x64-package", artifact)
        artifact.unlink()
        artifact.with_name(artifact.name + ".sha256").unlink()

        bad_chrome = b'{"name":"org.winsvpn.bridge","path":"PLACEHOLDER"}\n'
        artifact = self._write_archive(
            payload_overrides={
                "tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json": bad_chrome
            }
        )
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "Chrome native-host manifest"):
            self._verify("linux-x64-package", artifact)
        artifact.unlink()
        artifact.with_name(artifact.name + ".sha256").unlink()

        payloads = self._payloads()
        provenance = json.loads(payloads[gate.NATIVE_HOST_PROVENANCE_PATH])
        provenance["packaged_assets"][0]["sha256"] = "0" * 64
        tampered = (
            json.dumps(provenance, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        artifact = self._write_archive(
            payload_overrides={gate.NATIVE_HOST_PROVENANCE_PATH: tampered}
        )
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "does not bind"):
            self._verify("linux-x64-package", artifact)

    def test_native_host_unstripped_or_nonexecutable_delivery_fails_closed(self) -> None:
        debug_host = real_executable_elf(62, marker=b"native-host", debug=True)
        artifact = self._write_archive(
            payload_overrides={gate.NATIVE_HOST_PATH: debug_host}
        )
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "debug sections"):
            self._verify("linux-x64-package", artifact)
        artifact.unlink()
        artifact.with_name(artifact.name + ".sha256").unlink()

        artifact = self._write_archive(
            mode_overrides={gate.NATIVE_HOST_PATH: 0o644}
        )
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "unsafe mode"):
            self._verify("linux-x64-package", artifact)

    def test_sixty_four_byte_elf_header_is_rejected(self) -> None:
        artifact = self._write_archive(
            payload_overrides={"wins_vpn": truncated_elf_header(62)}
        )
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "64-byte ELF header"):
            self._verify("linux-x64-package", artifact)

    def test_stale_hardcoded_source_closure_constant_is_gone(self) -> None:
        self.assertFalse(hasattr(gate, "NATIVE_HOST_SOURCE_CLOSURE_SHA256"))
        source = (ROOT / "tools/linux_cross_store_artifact_gate.py").read_text(encoding="utf-8")
        self.assertNotIn("a55a98f3c0f620b1fb4d5cd2dbee8d97fce663b66d66c5c4e2612645dc175767", source)
        self.assertNotIn("b1a4aded213267ad79af941cb0be43cf90e6ac969ca596aa49fc7dd0f88685d3", source)

    def test_stale_source_closure_digest_fails_closed(self) -> None:
        artifact = self._write_archive()
        with (
            mock.patch.object(
                gate,
                "_verify_signature",
                side_effect=self._signature_custody,
            ),
            mock.patch.object(
                gate,
                "_verify_build_provenance",
                side_effect=self._build_custody,
            ),
            mock.patch.object(
                gate,
                "_bind_native_host_source_freeze_custody",
                side_effect=lambda: (
                    "a" * 64,
                    _authenticated_snapshot(
                        self.source_freeze_receipt,
                        "stale fixture source-freeze receipt",
                    ),
                ),
            ),
            mock.patch.object(
                gate,
                "_owner_issued_chromium_ids",
                return_value={"chrome": CHROME_ID, "edge": EDGE_ID},
            ),
            self.assertRaisesRegex(gate.LinuxArtifactGateError, "source-freeze|provenance identity"),
        ):
            gate.verify_package(
                "linux-x64-package", artifact.relative_to(self.repo).as_posix()
            )

    def test_missing_source_freeze_receipt_fails_closed(self) -> None:
        artifact = self._write_archive()
        with (
            mock.patch.object(
                gate,
                "_verify_signature",
                side_effect=self._signature_custody,
            ),
            mock.patch.object(
                gate,
                "_verify_build_provenance",
                side_effect=self._build_custody,
            ),
            mock.patch.object(
                gate,
                "_bind_native_host_source_freeze_custody",
                side_effect=gate.LinuxArtifactGateError(
                    "native-host source closure is not bound to a current "
                    "authenticated source-freeze receipt: No immutable APP_SOURCE_LOCK"
                ),
            ),
            self.assertRaisesRegex(
                gate.LinuxArtifactGateError, "source-freeze receipt"
            ),
        ):
            gate.verify_package(
                "linux-x64-package", artifact.relative_to(self.repo).as_posix()
            )

    def test_archive_size_ceiling_fails_before_decompression(self) -> None:
        artifact = self._write_archive()
        with (
            mock.patch.object(gate, "MAX_ARCHIVE_BYTES", 1),
            self.assertRaisesRegex(gate.LinuxArtifactGateError, "size ceiling"),
        ):
            self._verify("linux-x64-package", artifact)

    def test_tar_traversal_and_special_members_fail_closed(self) -> None:
        traversal = tarfile.TarInfo("../escape")
        traversal.size = 1
        traversal.uid = 0
        traversal.gid = 0
        traversal.mode = 0o644
        artifact = self._write_archive(unsafe_member=traversal)
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "unsafe"):
            self._verify("linux-x64-package", artifact)
        artifact.unlink()
        artifact.with_name(artifact.name + ".sha256").unlink()
        symlink = tarfile.TarInfo("./escape-link")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "/tmp/escape"
        symlink.uid = 0
        symlink.gid = 0
        symlink.mode = 0o777
        artifact = self._write_archive(unsafe_member=symlink)
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "unsafe"):
            self._verify("linux-x64-package", artifact)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_artifact_symlink_and_path_escape_fail_closed(self) -> None:
        artifact = self._write_archive()
        real = artifact.with_suffix(".real")
        artifact.rename(real)
        artifact.symlink_to(real.name)
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "symbolic"):
            self._verify("linux-x64-package", artifact)
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "canonical"):
            gate.verify_package("linux-x64-package", "../outside.tar.gz")

    @unittest.skipUnless(hasattr(os, "link"), "hard links unavailable")
    def test_hard_linked_artifact_fails_closed(self) -> None:
        artifact = self._write_archive()
        linked = self.downloads / "linked.tar.gz"
        os.link(artifact, linked)
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "non-linked"):
            self._verify("linux-x64-package", artifact)

    def test_gzip_trailer_crc_mismatch_fails_closed(self) -> None:
        artifact = self._write_archive()
        payload = bytearray(artifact.read_bytes())
        payload[-1] ^= 0x01
        artifact.write_bytes(bytes(payload))
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        artifact.with_name(artifact.name + ".sha256").write_text(
            f"{digest}  {artifact.name}\n", encoding="ascii"
        )
        snapshot = gate._snapshot_artifact(artifact.resolve(), "Linux package artifact")
        try:
            with self.assertRaisesRegex(
                gate.LinuxArtifactGateError, "gzip CRC|gzip ISIZE"
            ):
                gate._read_gzip_tar_snapshot(snapshot)
        finally:
            snapshot.close()
            shutil.rmtree(snapshot.root, ignore_errors=True)

    def test_trust_anchor_swap_during_cosign_fails_closed(self) -> None:
        artifact = self._write_archive()
        bundle = artifact.with_name(artifact.name + ".sigstore.json")
        bundle.write_text("{}\n", encoding="utf-8")
        fd = os.open(artifact, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        trust = self.repo / gate.TRUSTED_LOCAL_COSIGN_KEY

        @contextlib.contextmanager
        def authenticated_fixture():
            yield fd

        def run(argv, **kwargs):
            trust.write_text("attacker key\n", encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0, stdout="Verified OK\n", stderr="")

        snap = gate._snapshot_artifact(artifact.resolve(), "artifact")
        bundle_snap = gate._snapshot_artifact(bundle.resolve(), "bundle")
        pin = hashlib.sha256(trust.read_bytes()).hexdigest()
        try:
            with (
                mock.patch.object(gate, "OWNER_COSIGN_TRUST_ANCHOR_SHA256", pin),
                mock.patch.object(
                    gate.linux_release_signing, "open_authenticated_cosign", authenticated_fixture
                ),
                mock.patch.object(
                    gate.linux_release_signing, "_proc_fd_path", return_value="/proc/self/fd/fixture"
                ),
                mock.patch.object(gate, "_run_bounded_subprocess", side_effect=run),
                self.assertRaisesRegex(
                    gate.LinuxArtifactGateError, "swapped or restored|trust anchor"
                ),
            ):
                gate._run_cosign(snap, bundle_snap)
        finally:
            snap.close()
            bundle_snap.close()
            shutil.rmtree(snap.root, ignore_errors=True)
            shutil.rmtree(bundle_snap.root, ignore_errors=True)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_snapshot_symlink_fails_closed_as_gate_error(self) -> None:
        artifact = self._write_archive()
        real = artifact.with_suffix(".real")
        artifact.rename(real)
        artifact.symlink_to(real.name)
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "bound regular file|symbolic"
        ):
            gate._snapshot_artifact(artifact, "Linux package artifact")

    def test_origin_swap_during_verification_fails_closed(self) -> None:
        artifact = self._write_archive()
        original = artifact.read_bytes()
        swapped = original + b"\x00"

        real_inspect = gate._inspect_archive

        def swap_then_inspect(snapshot, *args, **kwargs):
            artifact.write_bytes(swapped)
            return real_inspect(snapshot, *args, **kwargs)

        with (
            mock.patch.object(
                gate,
                "_verify_signature",
                side_effect=self._signature_custody,
            ),
            mock.patch.object(
                gate,
                "_verify_build_provenance",
                side_effect=self._build_custody,
            ),
            mock.patch.object(
                gate,
                "_bind_native_host_source_freeze_custody",
                side_effect=self._source_freeze_custody,
            ),
            mock.patch.object(
                gate,
                "_owner_issued_chromium_ids",
                return_value={"chrome": CHROME_ID, "edge": EDGE_ID},
            ),
            mock.patch.object(gate, "_inspect_archive", side_effect=swap_then_inspect),
            self.assertRaisesRegex(gate.LinuxArtifactGateError, "swapped or restored"),
        ):
            gate.verify_package(
                "linux-x64-package", artifact.relative_to(self.repo).as_posix()
            )

    def test_cosign_verification_uses_authenticated_local_key_and_minimal_env(self) -> None:
        artifact = self._write_archive()
        bundle = artifact.with_name(artifact.name + ".sigstore.json")
        bundle.write_text("{}\n", encoding="utf-8")
        calls: list[list[str]] = []
        envs: list[dict[str, str]] = []
        fd = os.open(artifact, os.O_RDONLY)
        self.addCleanup(os.close, fd)

        @contextlib.contextmanager
        def authenticated_fixture():
            yield fd

        def run(argv, **kwargs):
            calls.append(list(argv))
            envs.append(gate._subprocess_env())
            return subprocess.CompletedProcess(argv, 0, stdout="Verified OK\n", stderr="")

        snap = gate._snapshot_artifact(artifact.resolve(), "artifact")
        bundle_snap = gate._snapshot_artifact(bundle.resolve(), "bundle")
        pin = hashlib.sha256(
            (self.repo / gate.TRUSTED_LOCAL_COSIGN_KEY).read_bytes()
        ).hexdigest()
        try:
            with (
                mock.patch.object(gate, "OWNER_COSIGN_TRUST_ANCHOR_SHA256", pin),
                mock.patch.object(gate.linux_release_signing, "open_authenticated_cosign", authenticated_fixture),
                mock.patch.object(gate.linux_release_signing, "_proc_fd_path", return_value="/proc/self/fd/fixture"),
                mock.patch.object(gate, "_run_bounded_subprocess", side_effect=run),
            ):
                gate._run_cosign(snap, bundle_snap)
        finally:
            snap.close()
            bundle_snap.close()
            shutil.rmtree(snap.root, ignore_errors=True)
            shutil.rmtree(bundle_snap.root, ignore_errors=True)
        self.assertIn("verify-blob", calls[0])
        self.assertIn("--key", calls[0])
        self.assertIn("--offline", calls[0])
        self.assertIn("--insecure-ignore-tlog", calls[0])
        self.assertNotIn("--certificate-identity", calls[0])
        self.assertNotIn("--yes", calls[0])
        self.assertEqual(envs[0], gate._subprocess_env())
        self.assertNotIn("COSIGN_EXPERIMENTAL", envs[0])
        self.assertNotIn("GITHUB_TOKEN", envs[0])

    def test_untrusted_adjacent_local_key_is_not_a_trust_anchor(self) -> None:
        artifact = self._write_archive()
        bundle = artifact.with_name(artifact.name + ".sigstore.json")
        bundle.write_text("{}\n", encoding="utf-8")
        artifact.with_name(artifact.name + ".cosign.pub").write_text(
            "attacker key\n", encoding="utf-8"
        )
        snap = gate._snapshot_artifact(artifact.resolve(), "artifact")
        bundle_snap = gate._snapshot_artifact(bundle.resolve(), "bundle")
        try:
            with self.assertRaisesRegex(gate.LinuxArtifactGateError, "trust anchor"):
                gate._run_cosign(snap, bundle_snap)
        finally:
            snap.close()
            bundle_snap.close()
            shutil.rmtree(snap.root, ignore_errors=True)
            shutil.rmtree(bundle_snap.root, ignore_errors=True)

    def test_getmembers_is_not_used(self) -> None:
        source = (ROOT / "tools/linux_cross_store_artifact_gate.py").read_text(encoding="utf-8")
        self.assertNotIn("getmembers", source)
        self.assertNotIn("tarfile.open(path", source)

    def test_receipt_binding_does_not_pass_none_or_swallow_freeze_errors(self) -> None:
        source = (ROOT / "tools/linux_cross_store_artifact_gate.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(
            'freeze.verify_build_receipt(root, index_path, "linux", receipt, None)',
            source,
        )
        self.assertIn("freeze.verify_build_receipt(", source)
        self.assertIn("origin", source)
        self.assertNotIn(
            "except (OSError, ValueError, json.JSONDecodeError, freeze.DependencyFreezeError):",
            source,
        )

    def test_missing_owner_identity_is_owner_blocked_even_with_packaged_ids(self) -> None:
        artifact = self._write_archive()
        # The committed record now carries the owner-issued ids; an absent record
        # must still block the package even though it packages ids of its own.
        renderer = gate._native_host_renderer()
        with mock.patch.object(renderer, "_load_store_ids_file", return_value=None):
            with self.assertRaisesRegex(
                gate.LinuxArtifactGateError, r"owner/environment blocker"
            ):
                self._verify("linux-x64-package", artifact, bind_owner=False)

    def test_chrome_only_store_ids_and_missing_edge_manifest_fail_closed(self) -> None:
        artifact = self._write_archive(
            payload_overrides={
                "tools/native_messaging/manifests/store_ids.json": json.dumps(
                    {"chrome": CHROME_ID}, sort_keys=True, separators=(",", ":")
                ).encode("ascii")
                + b"\n"
            }
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"native-host store id record fields are incomplete|owner-issued",
        ):
            self._verify("linux-x64-package", artifact)
        artifact.unlink()
        artifact.with_name(artifact.name + ".sha256").unlink()
        artifact = self._write_archive(
            omit={"tools/native_messaging/manifests/org.winsvpn.bridge.edge.json"}
        )
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "incomplete"):
            self._verify("linux-x64-package", artifact)

    def test_arbitrary_valid_shape_ids_are_refused_when_they_are_not_owner_issued(
        self,
    ) -> None:
        other = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        installed_host = gate.NATIVE_HOST_INSTALLED_PATH
        artifact = self._write_archive(
            payload_overrides={
                "tools/native_messaging/manifests/store_ids.json": json.dumps(
                    {"chrome": other, "edge": EDGE_ID},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
                + b"\n",
                "tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json": json.dumps(
                    {
                        "name": "org.winsvpn.bridge",
                        "description": "Win's VPN browser bridge",
                        "path": installed_host,
                        "type": "stdio",
                        "allowed_origins": [f"chrome-extension://{other}/"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
                + b"\n",
            }
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, r"do not match the owner-issued"
        ):
            self._verify("linux-x64-package", artifact)

    def test_duplicate_store_id_json_keys_are_refused(self) -> None:
        artifact = self._write_archive(
            payload_overrides={
                "tools/native_messaging/manifests/store_ids.json": (
                    b'{"chrome":"%s","chrome":"%s","edge":"%s"}\n'
                    % (CHROME_ID.encode("ascii"), EDGE_ID.encode("ascii"), EDGE_ID.encode("ascii"))
                )
            }
        )
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "duplicate JSON key"):
            self._verify("linux-x64-package", artifact)


class LinuxManifestAdapterTests(unittest.TestCase):
    def _load(self, relative: str, name: str):
        spec = importlib.util.spec_from_file_location(name, ROOT / relative)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_manifest_adapters_require_canonical_target_path(self) -> None:
        for relative, module_name, target, filename in (
            ("linux/packaging/flathub/manifest_artifact.py", "flat_gate", "linux-flathub-manifest", "org.winsvpn.app.json"),
            ("linux/packaging/snap/manifest_artifact.py", "snap_gate", "linux-snap-manifest", "snapcraft.yaml"),
        ):
            try:
                module = self._load(relative, module_name)
            except RuntimeError as exc:
                self.assertIn("source-freeze receipt", str(exc))
                continue
            with tempfile.TemporaryDirectory(dir=ROOT / ".artifacts") as temporary:
                output = pathlib.Path(temporary) / filename
                output.write_text("fixture\n", encoding="utf-8")
                with self.assertRaisesRegex(module.contract.ManifestContractError, "unsupported"):
                    module.canonical_gate_verify("wrong-target", output.relative_to(ROOT).as_posix())
                wrong = output.with_name("wrong" + output.suffix)
                output.rename(wrong)
                with self.assertRaises(module.contract.ManifestContractError):
                    module.canonical_gate_verify(target, wrong.relative_to(ROOT).as_posix())

    def test_hardening_routes_all_four_linux_targets_without_building(self) -> None:
        calls: list[tuple[str, tuple[str, ...], str]] = []

        def record(relative: str, arguments: list[str], label: str) -> None:
            calls.append((relative, tuple(arguments), label))

        with mock.patch.object(obfuscation, "_run_cross_store_tool", side_effect=record):
            obfuscation.canonical_linux_gate_verify(
                "linux-flathub-manifest", ".artifacts/linux/org.winsvpn.app.json"
            )
            obfuscation.canonical_linux_gate_verify(
                "linux-snap-manifest", ".artifacts/linux/snapcraft.yaml"
            )
        self.assertEqual(len(calls), 4)
        self.assertEqual(calls[0][1][0], "--verify")
        self.assertEqual(calls[2][1][0], "--verify")

    def test_package_hardening_binds_both_architectures_and_private_symbols(self) -> None:
        fixture = ROOT / ".artifacts/linux-hardening-test.tar.gz"
        fixture.parent.mkdir(exist_ok=True)
        fixture.write_bytes(b"fixture")
        verified: list[tuple[str, pathlib.Path, pathlib.Path, list[pathlib.Path], str | None]] = []
        try:
            with (
                mock.patch.object(canonical_gate, "_secure_regular_repo_path", return_value=fixture),
                mock.patch.object(canonical_gate, "verify_package", return_value={"ok": True}),
                mock.patch.object(obfuscation, "pubspec_version", return_value=("1.0.17", "34")),
                mock.patch.object(
                    obfuscation,
                    "verify",
                    side_effect=lambda platform, manifest, symbols, artifacts, target_id=None: verified.append(
                        (platform, manifest, symbols, artifacts, target_id)
                    ),
                ),
                mock.patch.object(obfuscation, "_run_cross_store_tool"),
            ):
                obfuscation.canonical_linux_gate_verify(
                    "linux-x64-package", ".artifacts/wins-vpn-linux-x64.tar.gz"
                )
                obfuscation.canonical_linux_gate_verify(
                    "linux-arm64-package", ".artifacts/wins-vpn-linux-arm64.tar.gz"
                )
            self.assertEqual(len(verified), 2)
            self.assertTrue(all(item[0] == "linux" for item in verified))
            self.assertTrue(
                verified[0][1].as_posix().endswith("/linux/x64/1.0.17+34/manifest.json")
            )
            self.assertTrue(
                verified[1][1].as_posix().endswith("/linux/arm64/1.0.17+34/manifest.json")
            )
            self.assertNotEqual(verified[0][1], verified[1][1])
            self.assertEqual(
                [item[4] for item in verified],
                ["linux-x64-package", "linux-arm64-package"],
            )
        finally:
            fixture.unlink(missing_ok=True)

    def test_shell_producer_dispatches_verify_before_build_initialization(self) -> None:
        source = (ROOT / "tools/build_linux_release.sh").read_text(encoding="utf-8")
        dispatch = source.index('if [[ "${1:-}" == "--verify" ]]')
        version_read = source.index('APP_VERSION="$(awk')
        self.assertLess(dispatch, version_read)
        self.assertIn('exec python3 "$ROOT/tools/linux_cross_store_artifact_gate.py" "$@"', source)


class LinuxStorePackageBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name)
        (self.repo / ".artifacts/linux").mkdir(parents=True)
        self.root_patch = mock.patch.object(gate, "ROOT", self.repo)
        self.root_patch.start()
        identity = self.repo / gate.RELEASE_IDENTITY_PATH
        identity.parent.mkdir(parents=True, exist_ok=True)
        identity.write_bytes((ROOT / gate.RELEASE_IDENTITY_PATH).read_bytes())
        self.receipt = self.repo / ".artifacts/linux/LINUX_BUILD_RECEIPT.json"
        _write_json_fixture(
            self.receipt, _build_receipt_fixture("linux-store-package")
        )
        self.source_freeze_receipt = (
            self.repo / ".artifacts/linux/SOURCE_FREEZE_RECEIPT.json"
        )
        _write_json_fixture(
            self.source_freeze_receipt, _source_freeze_receipt_fixture()
        )
        self.bundle = self.repo / ".artifacts/linux/bundle.sigstore.json"
        self.bundle.write_text("{}\n", encoding="ascii")

    def tearDown(self) -> None:
        self.root_patch.stop()
        self.temporary.cleanup()

    def _signature_custody(
        self, _snapshot: gate.AuthenticatedSnapshot
    ) -> gate.AuthenticatedSnapshot:
        return _authenticated_snapshot(self.bundle, "fixture Linux Sigstore bundle")

    def _build_custody(
        self, _snapshot: gate.AuthenticatedSnapshot, _target: str
    ) -> gate._BuildProvenanceCustody:
        return _build_provenance_custody(
            self.receipt, self.source_freeze_receipt
        )

    def _recipe_text(self, spec: dict[str, object]) -> str:
        if spec["kind"] == "Flatpak":
            architecture = (
                'case "${FLATPAK_ARCH}" in\n'
                "  x86_64) flutter_arch=x64 ;;\n"
                "  aarch64) flutter_arch=arm64 ;;\n"
                "esac\n"
            )
            install_target = "/app/share/winsvpn/winn3-descriptor-ring-attestation.json"
        else:
            architecture = (
                'case "${CRAFT_ARCH_BUILD_FOR}" in\n'
                "  amd64) flutter_arch=x64 ;;\n"
                "  arm64) flutter_arch=arm64 ;;\n"
                "esac\n"
            )
            install_target = (
                "$CRAFT_PART_INSTALL/share/winsvpn/"
                "winn3-descriptor-ring-attestation.json"
            )
        script = (
            "set -eu\n"
            + architecture
            + "flutter_sdk=/opt/flutter/bin/flutter\n"
            + '"$flutter_sdk" build linux --release --no-pub --obfuscate '
            "--split-debug-info=/private/symbols "
            "--extra-gen-snapshot-options=--strip\n"
            + "for engine in winn-datapath awg amneziawg-go xray; do\n"
            + '  test -x "$engine"\n'
            + "done\n"
            + 'install -Dm0644 "$bundle/winn3-descriptor-ring-attestation.json" '
            + f'"{install_target}"\n'
        )
        if spec["kind"] == "Flatpak":
            document = {
                "id": "org.winsvpn.app",
                "runtime": "org.freedesktop.Platform",
                "runtime-version": "26.08",
                "sdk": "org.freedesktop.Sdk",
                "command": "wins_vpn",
                "finish-args": ["--share=network"],
                "modules": [
                    {
                        "name": "winsvpn",
                        "buildsystem": "simple",
                        "build-commands": [script],
                        "sources": [
                            {"type": "archive", "url": "https://example.invalid/source", "sha256": "a" * 64},
                            {"type": "archive", "url": "https://example.invalid/x64", "sha256": "b" * 64, "only-arches": ["x86_64"]},
                            {"type": "archive", "url": "https://example.invalid/arm64", "sha256": "c" * 64, "only-arches": ["aarch64"]},
                        ],
                    }
                ],
            }
            return json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
        return (
            "name: wins-vpn\n"
            "version: '1.0.17'\n"
            "grade: stable\n"
            "confinement: classic\n"
            "platforms:\n"
            "  amd64:\n"
            "  arm64:\n"
            "apps:\n"
            "  wins-vpn:\n"
            "    command: bin/wins_vpn\n"
            "parts:\n"
            "  winsvpn:\n"
            "    plugin: nil\n"
            "    override-build: |\n"
            + "\n".join(f"      {line}" for line in script.splitlines())
            + "\n"
        )

    def _write_recipe(self, target: str) -> pathlib.Path:
        spec = gate.STORE_MANIFEST_TARGETS[target]
        recipe = self.repo / ".artifacts/linux" / spec["recipe_name"]
        recipe.write_text(self._recipe_text(spec), encoding="utf-8")
        return recipe

    def _write_symbols(self, store_kind: str, arch: str) -> pathlib.Path:
        path = (
            self.repo
            / gate.PRIVATE_STORE_SYMBOL_ROOT
            / store_kind
            / arch
            / gate._linux_release_stamp()
            / "app.symbols"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        machine = gate.STORE_PACKAGE_ARCHITECTURES[arch]
        path.write_bytes(real_executable_elf(machine, marker=b"libapp", debug=True))
        return path

    def _write_gzip_tar(
        self,
        path: pathlib.Path,
        payloads: dict[str, bytes],
        *,
        executable_names: frozenset[str] | None = None,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tar_buffer = io.BytesIO()
        entries: list[tuple[str, tarfile.TarInfo, bytes]] = []
        executables = (
            gate.STORE_PACKAGE_EXECUTABLES if executable_names is None else executable_names
        )
        for name, payload in payloads.items():
            info = tarfile.TarInfo(f"./{name}")
            info.size = len(payload)
            info.uid = 0
            info.gid = 0
            info.mtime = 0
            info.mode = 0o755 if pathlib.PurePosixPath(name).name in executables else 0o644
            entries.append((info.name, info, payload))
        with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
            for _name, info, payload in sorted(entries, key=lambda item: item[0]):
                archive.addfile(info, io.BytesIO(payload))
        with path.open("wb") as output:
            with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
                compressed.write(tar_buffer.getvalue())

    def _store_payloads(
        self,
        spec: dict[str, object],
        machine: int,
        recipe: pathlib.Path,
        *,
        stamp: bytes | None = None,
        website_layout: bool = False,
    ) -> dict[str, bytes]:
        prefix = "" if website_layout else str(spec["payload_prefix"])
        payloads: dict[str, bytes] = {}
        for name in gate.STORE_PACKAGE_PAYLOADS:
            payloads[f"{prefix}bin/{name}"] = (
                b"#!/bin/sh\n" if name == "awg-quick" else real_executable_elf(machine, marker=name.encode())
            )
        flutter = spec["flutter"]
        payloads[f"{prefix}{flutter['libapp']}"] = ring_bound_elf(machine, marker=b"libapp")
        payloads[f"{prefix}{flutter['libflutter']}"] = real_executable_elf(
            machine, marker=b"libflutter"
        )
        payloads[f"{prefix}{flutter['icu']}"] = b"icu-data-payload"
        payloads[f"{prefix}{flutter['asset_manifest']}"] = b"asset-manifest"
        payloads[f"{prefix}{flutter['font_manifest']}"] = b"[]\n"
        payloads[f"{prefix}share/applications/org.winsvpn.app.desktop"] = (
            b"[Desktop Entry]\nExec=wins_vpn %U\n"
        )
        payloads[f"{prefix}share/metainfo/org.winsvpn.app.metainfo.xml"] = (
            b"<component><id>org.winsvpn.app</id><releases>"
            b'<release version="1.0.17" date="2026-08-23" />'
            b"</releases></component>\n"
        )
        if website_layout:
            return {
                "wins_vpn": real_executable_elf(machine, marker=b"wins_vpn"),
                "release-manifest.sha256": b"deadbeef  wins_vpn\n",
            }
        digest = hashlib.sha256(recipe.read_bytes()).hexdigest()
        payloads[f"{prefix}share/winsvpn/store-recipe.sha256"] = stamp or (
            f"{digest}  {recipe.name}\n".encode("ascii")
        )
        payloads[
            f"{prefix}{gate.STORE_WINN3_DESCRIPTOR_RING_ATTESTATION_RELATIVE}"
        ] = winn3_attestation_document()
        hashed = {
            name: payload
            for name, payload in payloads.items()
            if name != f"{prefix}share/winsvpn/release-manifest.sha256"
        }
        manifest = "".join(
            f"{hashlib.sha256(payload).hexdigest()}  {name}\n"
            for name, payload in sorted(hashed.items())
        ).encode("ascii")
        payloads[f"{prefix}share/winsvpn/release-manifest.sha256"] = manifest
        return payloads

    def _write_store_package(
        self,
        recipe: pathlib.Path,
        target: str,
        arch: str,
        machine: int,
        *,
        stamp: bytes | None = None,
        website_layout: bool = False,
        native_snap: bool = False,
    ) -> pathlib.Path:
        spec = gate.STORE_MANIFEST_TARGETS[target]
        package = recipe.parent / arch / spec["package_name"]
        package.parent.mkdir(parents=True, exist_ok=True)
        if native_snap:
            package.write_bytes(b"hsqs" + os.urandom(32) + machine.to_bytes(2, "little"))
            return package
        self._write_gzip_tar(
            package,
            self._store_payloads(
                spec, machine, recipe, stamp=stamp, website_layout=website_layout
            ),
            executable_names=frozenset() if website_layout else None,
        )
        return package

    def _verify_store(self, target: str, recipe: pathlib.Path) -> dict[str, object]:
        with (
            mock.patch.object(
                gate, "_verify_build_provenance", side_effect=self._build_custody
            ),
            mock.patch.object(
                gate, "_verify_signature", side_effect=self._signature_custody
            ),
        ):
            return gate.verify_store_packages(
                target, recipe.relative_to(self.repo).as_posix()
            )

    def test_manifest_declaration_alone_cannot_pass(self) -> None:
        for target in ("linux-flathub-manifest", "linux-snap-manifest"):
            with self.subTest(target=target):
                recipe = self._write_recipe(target)
                with self.assertRaisesRegex(
                    gate.LinuxArtifactGateError, "owner/build-system blocker"
                ):
                    self._verify_store(target, recipe)

    def test_marker_only_store_recipes_are_not_valid_manifests(self) -> None:
        for target in ("linux-flathub-manifest", "linux-snap-manifest"):
            spec = gate.STORE_MANIFEST_TARGETS[target]
            marker_only = ("\n".join(spec["recipe_markers"]) + "\n").encode("utf-8")
            with self.subTest(target=target), self.assertRaisesRegex(
                gate.LinuxArtifactGateError,
                "canonical JSON|unsupported YAML syntax|schema",
            ):
                gate._require_recipe_markers(
                    marker_only, spec["recipe_markers"], spec["kind"]
                )

    def test_comment_and_print_only_store_declarations_fail_closed(self) -> None:
        for target in ("linux-flathub-manifest", "linux-snap-manifest"):
            spec = gate.STORE_MANIFEST_TARGETS[target]
            declarations = " ".join(str(marker) for marker in spec["recipe_markers"])
            hostile_script = (
                f"# {declarations}\n"
                f"printf '%s\\n' \"{declarations}\"\n"
                "python3 - <<'PY'\n"
                'case "${FLATPAK_ARCH}" in\n'
                "  x86_64) flutter_arch=x64 ;;\n"
                "  aarch64) flutter_arch=arm64 ;;\n"
                '"$flutter_sdk" build linux --obfuscate '
                "--split-debug-info=/fake --extra-gen-snapshot-options=--strip\n"
                "for engine in winn-datapath awg amneziawg-go xray; do\n"
                'install -Dm0644 "$bundle/winn3-descriptor-ring-attestation.json" '
                '"/fake/winn3-descriptor-ring-attestation.json"\n'
                "PY\n"
            )
            honest = self._recipe_text(spec)
            if spec["kind"] == "Flatpak":
                document = json.loads(honest)
                document["modules"][0]["build-commands"] = [hostile_script]
                hostile = json.dumps(
                    document, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            else:
                prefix, _separator, _script = honest.partition("    override-build: |\n")
                hostile = (
                    prefix
                    + "    override-build: |\n"
                    + "\n".join(
                        f"      {line}" for line in hostile_script.splitlines()
                    )
                    + "\n"
                ).encode("utf-8")
            with self.subTest(target=target), self.assertRaisesRegex(
                gate.LinuxArtifactGateError, "hardening/payload recipe"
            ):
                gate._require_recipe_markers(
                    hostile, spec["recipe_markers"], str(spec["kind"])
                )

    def test_required_store_commands_inside_false_branch_fail_closed(self) -> None:
        for target in ("linux-flathub-manifest", "linux-snap-manifest"):
            spec = gate.STORE_MANIFEST_TARGETS[target]
            honest = self._recipe_text(spec)
            if spec["kind"] == "Flatpak":
                document = json.loads(honest)
                script = document["modules"][0]["build-commands"][0]
                document["modules"][0]["build-commands"] = [
                    "if false; then\n" + script + "fi\n"
                ]
                hostile = json.dumps(
                    document, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            else:
                prefix, _separator, script = honest.partition("    override-build: |\n")
                body = "if false; then\n" + "\n".join(
                    line[6:] for line in script.splitlines()
                ) + "\nfi\n"
                hostile = (
                    prefix
                    + "    override-build: |\n"
                    + "\n".join(f"      {line}" for line in body.splitlines())
                    + "\n"
                ).encode("utf-8")
            with self.subTest(target=target), self.assertRaisesRegex(
                gate.LinuxArtifactGateError, "hardening/payload recipe"
            ):
                gate._require_recipe_markers(
                    hostile, spec["recipe_markers"], str(spec["kind"])
                )

    def test_required_store_commands_after_successful_exit_fail_closed(self) -> None:
        for target in ("linux-flathub-manifest", "linux-snap-manifest"):
            spec = gate.STORE_MANIFEST_TARGETS[target]
            honest = self._recipe_text(spec)
            if spec["kind"] == "Flatpak":
                document = json.loads(honest)
                script = document["modules"][0]["build-commands"][0]
                document["modules"][0]["build-commands"] = ["exit 0\n" + script]
                hostile = json.dumps(
                    document, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            else:
                prefix, _separator, script = honest.partition(
                    "    override-build: |\n"
                )
                body = "exit 0\n" + "\n".join(
                    line[6:] for line in script.splitlines()
                ) + "\n"
                hostile = (
                    prefix
                    + "    override-build: |\n"
                    + "\n".join(f"      {line}" for line in body.splitlines())
                    + "\n"
                ).encode("utf-8")
            with self.subTest(target=target), self.assertRaisesRegex(
                gate.LinuxArtifactGateError, "early exit"
            ):
                gate._require_recipe_markers(
                    hostile, spec["recipe_markers"], str(spec["kind"])
                )

    def test_required_store_commands_inside_uncalled_function_fail_closed(self) -> None:
        for target in ("linux-flathub-manifest", "linux-snap-manifest"):
            spec = gate.STORE_MANIFEST_TARGETS[target]
            honest = self._recipe_text(spec)
            if spec["kind"] == "Flatpak":
                document = json.loads(honest)
                script = document["modules"][0]["build-commands"][0]
                document["modules"][0]["build-commands"] = [
                    "unreachable_release_recipe() {\n" + script + "}\n"
                ]
                hostile = json.dumps(
                    document, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            else:
                prefix, _separator, script = honest.partition(
                    "    override-build: |\n"
                )
                body = "unreachable_release_recipe() {\n" + "\n".join(
                    line[6:] for line in script.splitlines()
                ) + "\n}\n"
                hostile = (
                    prefix
                    + "    override-build: |\n"
                    + "\n".join(f"      {line}" for line in body.splitlines())
                    + "\n"
                ).encode("utf-8")
            with self.subTest(target=target), self.assertRaisesRegex(
                gate.LinuxArtifactGateError, "unaudited function"
            ):
                gate._require_recipe_markers(
                    hostile, spec["recipe_markers"], str(spec["kind"])
                )

    def test_snap_recipe_rejects_duplicate_keys_and_yaml_authority_features(self) -> None:
        honest = self._recipe_text(gate.STORE_MANIFEST_TARGETS["linux-snap-manifest"])
        for hostile in (
            honest + "name: attacker\n",
            honest.replace("plugin: nil", "plugin: &hostile nil"),
            honest.replace("plugin: nil", "plugin: *hostile"),
            honest.replace("plugin: nil", "<<: hostile"),
        ):
            with self.subTest(hostile=hostile[-40:]), self.assertRaises(
                gate.LinuxArtifactGateError
            ):
                gate._require_recipe_markers(
                    hostile.encode("utf-8"),
                    gate.STORE_MANIFEST_TARGETS["linux-snap-manifest"]["recipe_markers"],
                    "Snap",
                )

    def test_split_debug_companion_is_elf_and_build_id_bound(self) -> None:
        path = self._write_symbols("snap", "x64")
        expected = fixture_libapp_build_id(62)
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "OWNER-BLOCKED"):
            gate._require_split_debug_symbols(
                "snap",
                "x64",
                "Snap",
                expected_machine=62,
                expected_build_id=expected,
            )
        with mock.patch.object(
            gate, "_verify_signature", side_effect=self._signature_custody
        ):
            snapshot, bundle = gate._require_split_debug_symbols(
                "snap",
                "x64",
                "Snap",
                expected_machine=62,
                expected_build_id=expected,
            )
        try:
            self.assertEqual(snapshot.origin, path.resolve(strict=True))
            self.assertEqual(snapshot.digest, hashlib.sha256(path.read_bytes()).hexdigest())
        finally:
            gate._close_retained_snapshots([snapshot, bundle])

    def test_split_debug_plaintext_cross_build_and_postverify_swap_fail_closed(self) -> None:
        path = self._write_symbols("flathub", "x64")
        path.write_text("not an ELF debug companion\n", encoding="ascii")
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "not an ELF"):
            gate._require_split_debug_symbols(
                "flathub",
                "x64",
                "Flatpak",
                expected_machine=62,
                expected_build_id=fixture_libapp_build_id(62),
            )
        path.write_bytes(real_executable_elf(62, marker=b"other-libapp", debug=True))
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "do not match"):
            gate._require_split_debug_symbols(
                "flathub",
                "x64",
                "Flatpak",
                expected_machine=62,
                expected_build_id=fixture_libapp_build_id(62),
            )
        path.write_bytes(real_executable_elf(62, marker=b"libapp", debug=True))
        with mock.patch.object(
            gate, "_verify_signature", side_effect=self._signature_custody
        ):
            snapshot, bundle = gate._require_split_debug_symbols(
                "flathub",
                "x64",
                "Flatpak",
                expected_machine=62,
                expected_build_id=fixture_libapp_build_id(62),
            )
        path.write_bytes(real_executable_elf(62, marker=b"attacker", debug=True))
        with self.assertRaises(gate.LinuxArtifactGateError):
            gate._close_retained_snapshots([snapshot, bundle])

    def test_gzip_tar_surrogate_is_not_native_store_package(self) -> None:
        recipe = self._write_recipe("linux-flathub-manifest")
        self._write_symbols("flathub", "x64")
        self._write_symbols("flathub", "arm64")
        self._write_store_package(recipe, "linux-flathub-manifest", "x64", 62)
        self._write_store_package(recipe, "linux-flathub-manifest", "arm64", 183)
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "gzip-tar surrogate is not a native"
        ):
            self._verify_store("linux-flathub-manifest", recipe)

    def test_package_substitution_fails_closed(self) -> None:
        recipe = self._write_recipe("linux-flathub-manifest")
        self._write_symbols("flathub", "x64")
        self._write_symbols("flathub", "arm64")
        self._write_store_package(recipe, "linux-flathub-manifest", "x64", 62, website_layout=True)
        self._write_store_package(recipe, "linux-flathub-manifest", "arm64", 183, website_layout=True)
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "gzip-tar surrogate|substituted|incomplete"
        ):
            self._verify_store("linux-flathub-manifest", recipe)

    def test_missing_native_tool_is_an_honest_environment_blocker(self) -> None:
        recipe = self._write_recipe("linux-snap-manifest")
        self._write_symbols("snap", "x64")
        self._write_symbols("snap", "arm64")
        self._write_store_package(recipe, "linux-snap-manifest", "x64", 62, native_snap=True)
        self._write_store_package(recipe, "linux-snap-manifest", "arm64", 183, native_snap=True)
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "owner/environment blocker"
        ):
            self._verify_store("linux-snap-manifest", recipe)

    def test_x64_and_arm64_evidence_cannot_cross_bind(self) -> None:
        recipe = self._write_recipe("linux-snap-manifest")
        self._write_symbols("snap", "x64")
        self._write_symbols("snap", "arm64")
        shared = {
            "files": 8,
            "elf_machine": 62,
            "payload_identities": {"wins_vpn": "a" * 64, "libapp": "b" * 64},
            "libapp_build_id": fixture_libapp_build_id(62),
        }

        def inspect(snapshot, **kwargs):
            return {
                **shared,
                "elf_machine": kwargs["expected_machine"],
                "libapp_build_id": fixture_libapp_build_id(kwargs["expected_machine"]),
            }

        self._write_store_package(recipe, "linux-snap-manifest", "x64", 62, native_snap=True)
        self._write_store_package(recipe, "linux-snap-manifest", "arm64", 183, native_snap=True)
        with (
            mock.patch.object(gate, "_inspect_native_store_package", side_effect=inspect),
            mock.patch.object(
                gate, "_verify_build_provenance", side_effect=self._build_custody
            ),
            mock.patch.object(
                gate, "_verify_signature", side_effect=self._signature_custody
            ),
            mock.patch.object(gate, "OWNER_COSIGN_TRUST_ANCHOR_SHA256", "a" * 64),
            mock.patch.object(
                gate,
                "OWNER_STORE_TOOL_SHA256",
                {"Flatpak": "c" * 64, "Snap": "d" * 64},
            ),
            self.assertRaisesRegex(gate.LinuxArtifactGateError, "cross-bind"),
        ):
            gate.verify_store_packages(
                "linux-snap-manifest", recipe.relative_to(self.repo).as_posix()
            )

    def test_bound_local_packages_cannot_green_without_owner_pins(self) -> None:
        for target, store_kind in (
            ("linux-flathub-manifest", "flathub"),
            ("linux-snap-manifest", "snap"),
        ):
            with self.subTest(target=target):
                recipe = self._write_recipe(target)
                self._write_symbols(store_kind, "x64")
                self._write_symbols(store_kind, "arm64")
                self._write_store_package(recipe, target, "x64", 62, native_snap=True)
                self._write_store_package(recipe, target, "arm64", 183, native_snap=True)
                def inspect(snapshot, **kwargs):
                    machine = kwargs["expected_machine"]
                    marker = str(machine).encode("ascii")
                    return {
                        "files": 12,
                        "elf_machine": machine,
                        "libapp_build_id": fixture_libapp_build_id(machine),
                        "payload_identities": {
                            "wins_vpn": hashlib.sha256(b"vpn" + marker).hexdigest(),
                            "libapp": hashlib.sha256(b"app" + marker).hexdigest(),
                            "libflutter": hashlib.sha256(b"flutter" + marker).hexdigest(),
                        },
                    }

                with (
                    mock.patch.object(
                        gate, "_inspect_native_store_package", side_effect=inspect
                    ),
                    mock.patch.object(
                        gate,
                        "_verify_build_provenance",
                        side_effect=self._build_custody,
                    ),
                    mock.patch.object(
                        gate,
                        "_verify_signature",
                        side_effect=self._signature_custody,
                    ),
                    self.assertRaisesRegex(
                        gate.LinuxArtifactGateError,
                        r"OWNER-BLOCKED: ABSENT",
                    ),
                ):
                    gate.verify_store_packages(
                        target, recipe.relative_to(self.repo).as_posix()
                    )

    def test_missing_store_owner_signature_stays_pending(self) -> None:
        recipe = self._write_recipe("linux-snap-manifest")
        self._write_symbols("snap", "x64")
        self._write_symbols("snap", "arm64")
        self._write_store_package(recipe, "linux-snap-manifest", "x64", 62, native_snap=True)
        self._write_store_package(recipe, "linux-snap-manifest", "arm64", 183, native_snap=True)
        def inspect(snapshot, **kwargs):
            machine = kwargs["expected_machine"]
            return {
                "files": 12,
                "elf_machine": machine,
                "libapp_build_id": fixture_libapp_build_id(machine),
                "payload_identities": {
                    "wins_vpn": hashlib.sha256(b"vpn" + str(machine).encode()).hexdigest(),
                    "libapp": hashlib.sha256(b"app" + str(machine).encode()).hexdigest(),
                },
            }

        with (
            mock.patch.object(gate, "_inspect_native_store_package", side_effect=inspect),
            mock.patch.object(
                gate, "_verify_build_provenance", side_effect=self._build_custody
            ),
            self.assertRaisesRegex(
                gate.LinuxArtifactGateError, "owner/environment blocker"
            ),
        ):
            gate.verify_store_packages(
                "linux-snap-manifest", recipe.relative_to(self.repo).as_posix()
                )

    def _store_modes(self, payloads: dict[str, bytes]) -> dict[str, int]:
        modes: dict[str, int] = {}
        for name in payloads:
            basename = pathlib.PurePosixPath(name).name
            modes[name] = (
                0o755 if basename in gate.STORE_PACKAGE_EXECUTABLES else 0o644
            )
        return modes

    def _rebuild_store_manifest(self, payloads: dict[str, bytes], prefix: str) -> None:
        manifest_name = f"{prefix}share/winsvpn/release-manifest.sha256"
        hashed = {
            name: payload
            for name, payload in payloads.items()
            if name != manifest_name
        }
        payloads[manifest_name] = "".join(
            f"{hashlib.sha256(payload).hexdigest()}  {name}\n"
            for name, payload in sorted(hashed.items())
        ).encode("ascii")

    def _validate_store_files(
        self,
        target: str,
        machine: int,
        *,
        mutate: object | None = None,
    ) -> dict[str, object]:
        spec = gate.STORE_MANIFEST_TARGETS[target]
        recipe = self._write_recipe(target)
        payloads = self._store_payloads(spec, machine, recipe)
        if mutate is not None:
            mutate(payloads, str(spec["payload_prefix"]))
            self._rebuild_store_manifest(payloads, str(spec["payload_prefix"]))
        modes = self._store_modes(payloads)
        digest = hashlib.sha256(recipe.read_bytes()).hexdigest()
        return gate._validate_store_package_files(
            payloads,
            modes,
            prefix=str(spec["payload_prefix"]),
            expected_machine=machine,
            expected_appstream_version="1.0.17",
            recipe_name=str(spec["recipe_name"]),
            recipe_sha256=digest,
            flutter=spec["flutter"],
        )

    def test_store_recipe_missing_attestation_marker_fails_closed(self) -> None:
        spec = gate.STORE_MANIFEST_TARGETS["linux-flathub-manifest"]
        recipe = self.repo / ".artifacts/linux" / spec["recipe_name"]
        honest = self._recipe_text(spec)
        recipe.write_text(
            honest.replace(gate.WINN3_DESCRIPTOR_RING_ATTESTATION_NAME, "omitted-attestation"),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "hardening/payload recipe"
        ):
            self._verify_store("linux-flathub-manifest", recipe)

    def test_store_package_attestation_membership_hash_and_mode_fail_closed(self) -> None:
        for target in ("linux-flathub-manifest", "linux-snap-manifest"):
            with self.subTest(target=target):
                result = self._validate_store_files(target, 62)
                self.assertEqual(result["elf_machine"], 62)
                self.assertIn("libapp", result["payload_identities"])

                def omit(payloads: dict[str, bytes], prefix: str) -> None:
                    payloads.pop(
                        f"{prefix}{gate.STORE_WINN3_DESCRIPTOR_RING_ATTESTATION_RELATIVE}"
                    )

                with self.assertRaisesRegex(
                    gate.LinuxArtifactGateError, r"incomplete or substituted"
                ):
                    self._validate_store_files(target, 62, mutate=omit)

                def extra(payloads: dict[str, bytes], prefix: str) -> None:
                    payloads[f"{prefix}{gate.WINN3_DESCRIPTOR_RING_ATTESTATION_NAME}"] = (
                        winn3_attestation_document()
                    )

                with self.assertRaisesRegex(
                    gate.LinuxArtifactGateError,
                    r"extra Winn3 descriptor ring attestation",
                ):
                    self._validate_store_files(target, 62, mutate=extra)

                def stale(payloads: dict[str, bytes], prefix: str) -> None:
                    payloads[
                        f"{prefix}{gate.STORE_WINN3_DESCRIPTOR_RING_ATTESTATION_RELATIVE}"
                    ] = winn3_attestation_document("a" * 64)

                with self.assertRaisesRegex(
                    gate.LinuxArtifactGateError, r"stale or unbound"
                ):
                    self._validate_store_files(target, 62, mutate=stale)

                spec = gate.STORE_MANIFEST_TARGETS[target]
                recipe = self._write_recipe(target)
                payloads = self._store_payloads(spec, 62, recipe)
                modes = self._store_modes(payloads)
                modes[
                    f"{spec['payload_prefix']}{gate.STORE_WINN3_DESCRIPTOR_RING_ATTESTATION_RELATIVE}"
                ] = 0o755
                digest = hashlib.sha256(recipe.read_bytes()).hexdigest()
                with self.assertRaisesRegex(gate.LinuxArtifactGateError, r"unsafe mode"):
                    gate._validate_store_package_files(
                        payloads,
                        modes,
                        prefix=str(spec["payload_prefix"]),
                        expected_machine=62,
                        expected_appstream_version="1.0.17",
                        recipe_name=str(spec["recipe_name"]),
                        recipe_sha256=digest,
                        flutter=spec["flutter"],
                    )

                def unbound(payloads: dict[str, bytes], prefix: str) -> None:
                    payloads[f"{prefix}{spec['flutter']['libapp']}"] = real_executable_elf(
                        62, marker=b"libapp"
                    )

                with self.assertRaisesRegex(
                    gate.LinuxArtifactGateError,
                    r"does not bind the verified artifact hash",
                ):
                    self._validate_store_files(target, 62, mutate=unbound)

                def wrong_arch(payloads: dict[str, bytes], prefix: str) -> None:
                    payloads[f"{prefix}{spec['flutter']['libapp']}"] = ring_bound_elf(
                        183, marker=b"libapp"
                    )

                with self.assertRaisesRegex(
                    gate.LinuxArtifactGateError, r"ELF machine"
                ):
                    self._validate_store_files(target, 62, mutate=wrong_arch)

    @unittest.skipUnless(hasattr(os, "link"), "hard links unavailable")
    def test_extracted_hard_linked_attestation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path = root / gate.STORE_WINN3_DESCRIPTOR_RING_ATTESTATION_RELATIVE
            path.parent.mkdir(parents=True)
            path.write_bytes(winn3_attestation_document())
            os.link(path, path.with_name("linked-attestation.json"))
            with retained_extraction_directory(root) as retained:
                with self.assertRaisesRegex(
                    gate.LinuxArtifactGateError, r"unsafe member"
                ):
                    gate._walk_extracted_payloads(retained)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_extracted_symlink_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            root = parent / "extracted"
            outside = parent / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "payload").write_bytes(b"attacker")
            (root / "linked-directory").symlink_to(outside, target_is_directory=True)
            with retained_extraction_directory(root) as retained:
                with self.assertRaisesRegex(
                    gate.LinuxArtifactGateError, r"symlink member"
                ):
                    gate._walk_extracted_payloads(retained)

    def test_extracted_root_substitute_restore_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            root = parent / "extracted"
            authentic = parent / "extracted-authentic"
            root.mkdir()
            (root / "payload").write_bytes(b"authentic")
            with retained_extraction_directory(root) as retained:
                root.rename(authentic)
                root.mkdir()
                (root / "payload").write_bytes(b"attacker")
                try:
                    with self.assertRaisesRegex(
                        gate.LinuxArtifactGateError,
                        r"substituted or restored|replaced or removed",
                    ):
                        gate._walk_extracted_payloads(retained)
                finally:
                    shutil.rmtree(root)
                    authentic.rename(root)

    def test_extracted_root_transient_substitute_restore_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            root = parent / "extracted"
            authentic = parent / "extracted-authentic"
            root.mkdir()
            (root / "payload").write_bytes(b"authentic")
            with retained_extraction_directory(root) as retained:
                root.rename(authentic)
                root.mkdir()
                (root / "payload").write_bytes(b"attacker")
                shutil.rmtree(root)
                authentic.rename(root)
                with self.assertRaisesRegex(
                    gate.LinuxArtifactGateError, r"substituted or restored"
                ):
                    gate._walk_extracted_payloads(retained)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _dummy_authentication(
    target_id: str,
    *,
    digest: str,
    size: int,
) -> dict[str, object]:
    del digest, size
    return {
        "contract": gate.UPLOAD_AUTHORIZATION_CONTRACT,
        "schema_version": gate.UPLOAD_AUTHORIZATION_SCHEMA_VERSION,
        "authority_receipt_path": gate._upload_authorization_relative(target_id),
        "authority_receipt_sha256": _digest(f"{target_id}-external-authorization"),
    }


def _pending_owner() -> dict[str, object]:
    return {
        "contract": gate.OWNER_AUTHORIZATION_CONTRACT,
        "schema_version": gate.PACKAGE_UPLOAD_RECEIPT_SCHEMA_VERSION,
        "status": "pending",
        "credentials_authorized": False,
        "upload_authorized": False,
    }


def _upload_receipt(
    target_id: str,
    *,
    digest: str,
    size: int,
) -> dict[str, object]:
    spec = gate.LINUX_PACKAGE_UPLOAD_TARGETS[target_id]
    identity: dict[str, object] = {
        "name": spec["package_name"],
        "appstream_version": "1.0.17",
        "debian_version": "1.0.17-34",
    }
    if "elf_machine" in spec["identity_keys"]:
        identity["elf_machine"] = spec["elf_machine"]
    else:
        identity["elf_machines"] = dict(spec["elf_machines"])
    return {
        "ok": True,
        "schema_version": gate.PACKAGE_UPLOAD_RECEIPT_SCHEMA_VERSION,
        "contract": gate.PACKAGE_UPLOAD_RECEIPT_CONTRACT,
        "release": gate.CANONICAL_RELEASE,
        "target_id": target_id,
        "platform": spec["platform"],
        "artifact": {
            "path": f".artifacts/linux/{spec['artifact_name']}",
            "sha256": digest,
            "bytes": size,
        },
        "build_receipt": {
            "path": f".artifacts/release-build-receipts/linux/{target_id}.json",
            "sha256": _digest(f"{target_id}-build"),
            "target": spec["build_receipt_target"],
        },
        "producer": {
            "id": spec["producer"],
            "path": spec["producer"],
            "sha256": _digest(f"{target_id}-producer"),
        },
        "package_identity": identity,
        "architectures": list(spec["architectures"]),
        "signing": {
            "contract": spec["signing_contract"],
            "trust_anchor": spec["trust_anchor"],
            "status": spec["signing_status"],
        },
        "store_evidence": {
            "surface": spec["store_surface"],
            "status": "not_uploaded",
            "metadata_sha256": "0" * 64,
        },
        "descriptor": {
            "path": "tools/linux_cross_store_artifact_gate.py",
            "sha256": _digest(f"{target_id}-descriptor"),
        },
        "source_freeze": {
            "path": ".artifacts/release-freeze-1.0.17+34/SOURCE_FREEZE_RECEIPT.json",
            "sha256": _digest(f"{target_id}-source"),
        },
        "obfuscation_privacy": {
            "path": "tools/release_obfuscation_contract.py",
            "sha256": _digest(f"{target_id}-privacy"),
        },
        "winn3_descriptor_ring_attestation": gate._winn3_descriptor_ring_attestation_receipt_binding(
            target_id
        ),
        "publication_authorized": False,
        "upload_attempted": False,
        "owner_authorization": _pending_owner(),
        "authentication": _dummy_authentication(
            target_id, digest=digest, size=size
        ),
    }


class LinuxPackageUploadReceiptBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name)
        identity = self.repo / gate.RELEASE_IDENTITY_PATH
        identity.parent.mkdir(parents=True, exist_ok=True)
        identity.write_bytes((ROOT / gate.RELEASE_IDENTITY_PATH).read_bytes())
        self._root = mock.patch.object(gate, "ROOT", self.repo)
        self._root.start()
        self.x64_size = 11
        self.arm64_size = 13
        self.flathub_size = 17
        self.snap_size = 19
        self.records = {
            "linux-x64-package": _upload_receipt(
                "linux-x64-package", digest=_digest("linux-x64-1.0.17+34"), size=self.x64_size
            ),
            "linux-arm64-package": _upload_receipt(
                "linux-arm64-package", digest=_digest("linux-arm64-1.0.17+34"), size=self.arm64_size
            ),
            "linux-flathub-manifest": _upload_receipt(
                "linux-flathub-manifest",
                digest=_digest("linux-flathub-1.0.17+34"),
                size=self.flathub_size,
            ),
            "linux-snap-manifest": _upload_receipt(
                "linux-snap-manifest", digest=_digest("linux-snap-1.0.17+34"), size=self.snap_size
            ),
        }
        self._install_live_upload_files()
        self.x64_digest = self.records["linux-x64-package"]["artifact"]["sha256"]
        self.arm64_digest = self.records["linux-arm64-package"]["artifact"]["sha256"]
        self.flathub_digest = self.records["linux-flathub-manifest"]["artifact"]["sha256"]
        self.snap_digest = self.records["linux-snap-manifest"]["artifact"]["sha256"]
        self.artifacts = {
            "linux-x64-package": (self.x64_digest, self.x64_size),
            "linux-arm64-package": (self.arm64_digest, self.arm64_size),
            "linux-flathub-manifest": (self.flathub_digest, self.flathub_size),
            "linux-snap-manifest": (self.snap_digest, self.snap_size),
        }

    def _bind_one(self, target_id: str) -> dict[str, object]:
        record = self.records[target_id]
        return gate.bind_package_upload_receipt(
            target_id,
            record,
            artifact_sha256=str(record["artifact"]["sha256"]),
            artifact_bytes=int(record["artifact"]["bytes"]),
        )

    def _write_live(self, relative: str, payload: bytes) -> tuple[str, int]:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        os.chmod(path, 0o644)
        return hashlib.sha256(payload).hexdigest(), len(payload)

    def _install_live_upload_files(self) -> None:
        descriptor_digest, _unused = self._write_live(
            "tools/linux_cross_store_artifact_gate.py",
            (ROOT / "tools/linux_cross_store_artifact_gate.py").read_bytes(),
        )
        privacy_digest, _unused = self._write_live(
            "tools/release_obfuscation_contract.py",
            (ROOT / "tools/release_obfuscation_contract.py").read_bytes(),
        )
        source_path = ".artifacts/release-freeze-1.0.17+34/SOURCE_FREEZE_RECEIPT.json"
        source_payload = (
            json.dumps(
                _source_freeze_receipt_fixture(),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
        source_digest, _unused = self._write_live(
            source_path, source_payload
        )
        producer_digests: dict[str, str] = {}
        payloads = {
            "linux-x64-package": b"x64-linux!!",
            "linux-arm64-package": b"arm64-linux!",
            "linux-flathub-manifest": b'{"id":"flathub"}\n',
            "linux-snap-manifest": b"name: wins-vpn\n",
        }
        for target_id, record in self.records.items():
            spec = gate.LINUX_PACKAGE_UPLOAD_TARGETS[target_id]
            producer = str(spec["producer"])
            if producer not in producer_digests:
                producer_digests[producer], _unused = self._write_live(
                    producer, (ROOT / producer).read_bytes()
                )
            artifact_payload = payloads[target_id]
            artifact_digest, artifact_size = self._write_live(
                str(record["artifact"]["path"]), artifact_payload
            )
            record["artifact"]["sha256"] = artifact_digest
            record["artifact"]["bytes"] = artifact_size
            record["authentication"] = _dummy_authentication(
                target_id, digest=artifact_digest, size=artifact_size
            )
            if spec["kind"] == "DEB":
                sidecar = f"{artifact_digest}  {spec['artifact_name']}\n"
                self._write_live(str(record["artifact"]["path"]) + ".sha256", sidecar.encode("ascii"))
            build_payload = (
                json.dumps(
                    _build_receipt_fixture(str(spec["build_receipt_target"])),
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("ascii")
            build_digest, _unused = self._write_live(
                str(record["build_receipt"]["path"]), build_payload
            )
            record["build_receipt"]["sha256"] = build_digest
            record["producer"]["sha256"] = producer_digests[producer]
            record["descriptor"]["sha256"] = descriptor_digest
            record["source_freeze"]["path"] = source_path
            record["source_freeze"]["sha256"] = source_digest
            record["obfuscation_privacy"]["sha256"] = privacy_digest
            if target_id == "linux-x64-package":
                self.x64_size = artifact_size
            elif target_id == "linux-arm64-package":
                self.arm64_size = artifact_size
            elif target_id == "linux-flathub-manifest":
                self.flathub_size = artifact_size
            else:
                self.snap_size = artifact_size
        self._install_store_metadata_and_obfuscation_receipts()

    def _install_store_metadata_and_obfuscation_receipts(self) -> None:
        shutil.copytree(ROOT / "app_store/linux", self.repo / "app_store/linux")
        for relative in (
            "linux/packaging/org.winsvpn.app.metainfo.xml",
            "linux/packaging/org.winsvpn.app.desktop",
        ):
            self._write_live(relative, (ROOT / relative).read_bytes())
        reviewed = gate._reviewed_store_metadata()
        for target_id, record in self.records.items():
            record["store_evidence"]["metadata_sha256"] = reviewed["sha256"]
            self._write_obfuscation_receipt(target_id)

    def _write_obfuscation_receipt(self, target_id: str) -> None:
        record = self.records[target_id]
        relative = gate.obfuscation_receipt_relative(target_id)
        payload = (
            json.dumps(
                _obfuscation_receipt_fixture(
                    target_id,
                    str(record["artifact"]["path"]),
                    str(record["artifact"]["sha256"]),
                    int(record["artifact"]["bytes"]),
                ),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
        self._write_live(relative, payload)

    def _install_upload_authorization(self, target_id: str) -> pathlib.Path:
        record = self.records[target_id]
        now = datetime.datetime.now(datetime.timezone.utc)
        authority = {
            "contract": gate.UPLOAD_AUTHORIZATION_CONTRACT,
            "schema_version": gate.UPLOAD_AUTHORIZATION_SCHEMA_VERSION,
            "issuer": gate.UPLOAD_RECEIPT_ISSUER,
            "authorization_id": _digest(f"{target_id}-authorization-id"),
            "nonce": _digest(f"{target_id}-authorization-nonce"),
            "issued_at": now.isoformat(),
            "expires_at": (now + datetime.timedelta(minutes=5)).isoformat(),
            "target_id": target_id,
            "architectures": list(gate.LINUX_PACKAGE_UPLOAD_TARGETS[target_id]["architectures"]),
            "release": gate.CANONICAL_RELEASE,
            "artifact_sha256": record["artifact"]["sha256"],
            "artifact_bytes": record["artifact"]["bytes"],
            "upload_receipt_binding_sha256": gate._canonical_upload_receipt_binding(record),
            "publication_authorized": False,
            "upload_attempted": False,
        }
        relative = gate._upload_authorization_relative(target_id)
        payload = (
            json.dumps(authority, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        digest, _size = self._write_live(relative, payload)
        record["authentication"] = {
            "contract": gate.UPLOAD_AUTHORIZATION_CONTRACT,
            "schema_version": gate.UPLOAD_AUTHORIZATION_SCHEMA_VERSION,
            "authority_receipt_path": relative,
            "authority_receipt_sha256": digest,
        }
        bundle = self.repo / (relative + ".sigstore.json")
        bundle.write_text('{"fixture":"externally-signed"}\n', encoding="ascii")
        return self.repo / relative

    def _signed_authorization_custody(
        self, snapshot: gate.AuthenticatedSnapshot
    ) -> gate.AuthenticatedSnapshot:
        self.assertTrue(
            snapshot.origin.as_posix().endswith("upload-receipt-authorizations/" + snapshot.origin.name)
        )
        bundle = pathlib.Path(str(snapshot.origin) + ".sigstore.json")
        return gate._snapshot_artifact(bundle, "fixture external upload authorization signature")

    def tearDown(self) -> None:
        self._root.stop()
        self.temporary.cleanup()

    def test_required_deb_snap_flathub_receipts_bind_canonical_release(self) -> None:
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            _UNAUTHORIZED_RECEIPT_REFUSAL,
        ):
            gate.bind_linux_package_upload_receipts(self.records, self.artifacts)
        self.assertEqual(
            self.records["linux-x64-package"]["package_identity"]["debian_version"],
            "1.0.17-34",
        )
        self.assertEqual(
            self.records["linux-x64-package"]["package_identity"]["elf_machine"], 62
        )
        self.assertEqual(
            self.records["linux-arm64-package"]["package_identity"]["elf_machine"], 183
        )
        self.assertEqual(
            self.records["linux-flathub-manifest"]["architectures"], ["x64", "arm64"]
        )
        self.assertEqual(
            self.records["linux-snap-manifest"]["store_evidence"]["status"],
            "not_uploaded",
        )
        self.assertEqual(
            self.records["linux-x64-package"]["producer"]["sha256"],
            self.records["linux-arm64-package"]["producer"]["sha256"],
        )
        self.assertEqual(
            self.records["linux-x64-package"]["descriptor"]["sha256"],
            self.records["linux-snap-manifest"]["descriptor"]["sha256"],
        )
        self.assertNotEqual(self.x64_digest, self.arm64_digest)

    def test_inline_authenticated_true_cannot_replace_external_signature(self) -> None:
        target_id = "linux-x64-package"
        record = self.records[target_id]
        record["authentication"] = {
            "authenticated": True,
            "issuer": gate.UPLOAD_RECEIPT_ISSUER,
        }
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            "schema fields are invalid|not authenticated",
        ):
            self._bind_one(target_id)

    def test_external_signed_authorization_binds_exact_receipt(self) -> None:
        target_id = "linux-x64-package"
        self._install_upload_authorization(target_id)
        with (
            mock.patch.object(gate, "OWNER_COSIGN_TRUST_ANCHOR_SHA256", "a" * 64),
            mock.patch.object(gate, "OWNER_UPLOAD_RECEIPT_TRUST_SHA256", "a" * 64),
            mock.patch.object(
                gate,
                "_verify_signature",
                side_effect=self._signed_authorization_custody,
            ) as verifier,
        ):
            result = self._bind_one(target_id)
        self.assertTrue(result["ok"])
        self.assertEqual(verifier.call_count, 1)
        self.assertFalse(result["publication_authorized"])

    def test_caller_selected_upload_trust_digest_is_rejected(self) -> None:
        target_id = "linux-x64-package"
        self._install_upload_authorization(target_id)
        with (
            mock.patch.object(gate, "OWNER_COSIGN_TRUST_ANCHOR_SHA256", "a" * 64),
            mock.patch.object(gate, "OWNER_UPLOAD_RECEIPT_TRUST_SHA256", "b" * 64),
            self.assertRaisesRegex(
                gate.LinuxArtifactGateError, "external Sigstore public-key digest"
            ),
        ):
            self._bind_one(target_id)

    def test_external_authorization_signature_and_receipt_drift_fail_closed(self) -> None:
        target_id = "linux-x64-package"
        authority_path = self._install_upload_authorization(target_id)
        with (
            mock.patch.object(gate, "OWNER_COSIGN_TRUST_ANCHOR_SHA256", "a" * 64),
            mock.patch.object(gate, "OWNER_UPLOAD_RECEIPT_TRUST_SHA256", "a" * 64),
            mock.patch.object(
                gate, "_verify_signature", side_effect=gate.LinuxArtifactGateError("unsigned")
            ),
            self.assertRaisesRegex(gate.LinuxArtifactGateError, "unsigned"),
        ):
            self._bind_one(target_id)
        authority = json.loads(authority_path.read_text(encoding="ascii"))
        authority["artifact_sha256"] = "0" * 64
        authority_path.write_text(
            json.dumps(authority, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        self.records[target_id]["authentication"]["authority_receipt_sha256"] = hashlib.sha256(
            authority_path.read_bytes()
        ).hexdigest()
        with (
            mock.patch.object(gate, "OWNER_COSIGN_TRUST_ANCHOR_SHA256", "a" * 64),
            mock.patch.object(gate, "OWNER_UPLOAD_RECEIPT_TRUST_SHA256", "a" * 64),
            self.assertRaisesRegex(gate.LinuxArtifactGateError, "not authenticated"),
        ):
            self._bind_one(target_id)

    def test_production_cli_reaches_external_upload_authorization_boundary(self) -> None:
        target_id = "linux-x64-package"
        self._install_upload_authorization(target_id)
        record = self.records[target_id]
        receipt_relative = ".artifacts/linux/upload-receipts/linux-x64-package.json"
        receipt_path = self.repo / receipt_relative
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        output = io.StringIO()
        with (
            mock.patch.object(gate, "OWNER_COSIGN_TRUST_ANCHOR_SHA256", "a" * 64),
            mock.patch.object(gate, "OWNER_UPLOAD_RECEIPT_TRUST_SHA256", "a" * 64),
            mock.patch.object(
                gate,
                "_verify_signature",
                side_effect=self._signed_authorization_custody,
            ),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(
                gate.main(
                    [
                        "--bind-upload-receipt",
                        target_id,
                        receipt_relative,
                        str(record["artifact"]["path"]),
                    ]
                ),
                0,
            )
        result = json.loads(output.getvalue())
        self.assertTrue(result["ok"])
        self.assertFalse(result["publication_authorized"])

    def test_missing_receipts_remain_pending_without_owner_evidence(self) -> None:
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            "pending without owner evidence",
        ):
            gate.bind_linux_package_upload_receipts({}, {})
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            "pending without owner evidence",
        ):
            gate.bind_linux_package_upload_receipts(
                {"linux-x64-package": self.records["linux-x64-package"]},
                {"linux-x64-package": self.artifacts["linux-x64-package"]},
            )

    def test_schema_v1_receipt_fails_closed(self) -> None:
        self.records["linux-x64-package"]["schema_version"] = 1
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "receipt binding is invalid"
        ):
            gate.bind_linux_package_upload_receipts(self.records, self.artifacts)

    def test_receipt_reuse_and_byte_swap_fail_closed(self) -> None:
        x64_path = self.repo / self.records["linux-x64-package"]["artifact"]["path"]
        arm64_path = self.repo / self.records["linux-arm64-package"]["artifact"]["path"]
        arm64_path.write_bytes(x64_path.read_bytes())
        self.records["linux-arm64-package"]["artifact"]["sha256"] = self.x64_digest
        self.records["linux-arm64-package"]["artifact"]["bytes"] = self.x64_size
        self.records["linux-arm64-package"]["authentication"] = _dummy_authentication(
            "linux-arm64-package", digest=self.x64_digest, size=self.x64_size
        )
        self.artifacts["linux-arm64-package"] = (self.x64_digest, self.x64_size)
        arm64_sidecar = arm64_path.with_name(arm64_path.name + ".sha256")
        arm64_sidecar.write_text(
            f"{self.x64_digest}  {arm64_path.name}\n", encoding="ascii"
        )
        self._write_obfuscation_receipt("linux-arm64-package")
        with (
            mock.patch.object(gate, "OWNER_COSIGN_TRUST_ANCHOR_SHA256", "a" * 64),
            mock.patch.object(gate, "OWNER_UPLOAD_RECEIPT_TRUST_SHA256", "a" * 64),
            self.assertRaisesRegex(gate.LinuxArtifactGateError, "receipt reuse"),
        ):
            gate.bind_linux_package_upload_receipts(self.records, self.artifacts)
        self.records["linux-arm64-package"]["artifact"]["sha256"] = self.arm64_digest
        self.records["linux-arm64-package"]["artifact"]["bytes"] = self.arm64_size
        self.records["linux-arm64-package"]["authentication"] = _dummy_authentication(
            "linux-arm64-package", digest=self.arm64_digest, size=self.arm64_size
        )
        self.artifacts["linux-arm64-package"] = (self.arm64_digest, self.arm64_size)
        arm64_path.write_bytes(b"arm64-linux!")
        arm64_sidecar.write_text(
            f"{self.arm64_digest}  {arm64_path.name}\n", encoding="ascii"
        )
        self._write_obfuscation_receipt("linux-arm64-package")
        flathub_build = self.records["linux-flathub-manifest"]["build_receipt"]
        snap_build = self.records["linux-snap-manifest"]["build_receipt"]
        shutil.copy2(self.repo / flathub_build["path"], self.repo / snap_build["path"])
        self.records["linux-snap-manifest"]["build_receipt"]["sha256"] = flathub_build[
            "sha256"
        ]
        with (
            mock.patch.object(gate, "OWNER_COSIGN_TRUST_ANCHOR_SHA256", "a" * 64),
            mock.patch.object(gate, "OWNER_UPLOAD_RECEIPT_TRUST_SHA256", "a" * 64),
            self.assertRaisesRegex(gate.LinuxArtifactGateError, "receipt reuse"),
        ):
            gate.bind_linux_package_upload_receipts(self.records, self.artifacts)
        self.records["linux-snap-manifest"]["build_receipt"]["sha256"] = _digest(
            "linux-snap-manifest-build"
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "swapped or does not bind"
        ):
            gate.bind_package_upload_receipt(
                "linux-x64-package",
                self.records["linux-x64-package"],
                artifact_sha256=_digest("swapped-deb"),
                artifact_bytes=self.x64_size,
            )

    def test_architecture_and_debian_identity_fail_closed(self) -> None:
        self.records["linux-x64-package"]["architectures"] = ["arm64"]
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "architecture inventory"
        ):
            self._bind_one("linux-x64-package")
        self.records["linux-x64-package"]["architectures"] = ["x64"]
        self.records["linux-flathub-manifest"]["architectures"] = ["x64"]
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "architecture inventory"
        ):
            self._bind_one("linux-flathub-manifest")
        self.records["linux-flathub-manifest"]["architectures"] = ["x64", "arm64"]
        self.records["linux-x64-package"]["package_identity"]["debian_version"] = (
            "9.9.9-999"
        )
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "package identity"):
            self._bind_one("linux-x64-package")

    def test_signing_store_evidence_and_privacy_bindings_fail_closed(self) -> None:
        self.records["linux-x64-package"]["signing"]["status"] = "not_present"
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "signing evidence"
        ):
            self._bind_one("linux-x64-package")
        self.records["linux-x64-package"]["signing"]["status"] = "required"
        self.records["linux-snap-manifest"]["store_evidence"]["status"] = "uploaded"
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "store evidence"):
            self._bind_one("linux-snap-manifest")
        self.records["linux-snap-manifest"]["store_evidence"]["status"] = "not_uploaded"
        self.records["linux-flathub-manifest"]["obfuscation_privacy"]["sha256"] = "0" * 63
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "digest is invalid"):
            self._bind_one("linux-flathub-manifest")

    def test_owner_approval_inside_receipt_is_refused(self) -> None:
        self.records["linux-flathub-manifest"]["owner_authorization"]["status"] = (
            "approved"
        )
        self.records["linux-flathub-manifest"]["owner_authorization"][
            "upload_authorized"
        ] = True
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            "remain pending without owner evidence",
        ):
            self._bind_one("linux-flathub-manifest")

    def test_invented_deb_target_is_unsupported(self) -> None:
        extra = dict(self.records)
        extra["linux-x64-deb"] = _upload_receipt(
            "linux-x64-package", digest=self.x64_digest, size=self.x64_size
        )
        extra["linux-x64-deb"]["target_id"] = "linux-x64-deb"
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "unexpected Linux package/upload receipt target"
        ):
            gate.bind_linux_package_upload_receipts(extra, self.artifacts)

    def test_ancestor_path_and_duplicate_json_upload_receipts_fail_closed(self) -> None:
        record = dict(self.records["linux-x64-package"])
        record["artifact"] = dict(record["artifact"])
        record["artifact"]["path"] = ".artifacts/../tools/wins-vpn-linux-x64.tar.gz"
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "canonical repository-relative path"
        ):
            gate.bind_package_upload_receipt(
                "linux-x64-package",
                record,
                artifact_sha256=self.x64_digest,
                artifact_bytes=self.x64_size,
            )
        poisoned = (
            b'{"ok": true, "ok": false, "schema_version": 2, "contract": "x"}\n'
        )
        with self.assertRaisesRegex(gate.LinuxArtifactGateError, "duplicate JSON key"):
            gate.bind_package_upload_receipt(
                "linux-x64-package",
                poisoned,
                artifact_sha256=self.x64_digest,
                artifact_bytes=self.x64_size,
            )

    def test_unsigned_deb_receipts_stay_pending_with_live_shared_custody(self) -> None:
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            _UNAUTHORIZED_RECEIPT_REFUSAL,
        ):
            gate.bind_linux_package_upload_receipts(self.records, self.artifacts)


if __name__ == "__main__":
    unittest.main()
