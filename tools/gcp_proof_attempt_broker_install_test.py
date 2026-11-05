#!/usr/bin/env python3
"""No-network tests for authenticated protocol-attempt broker install."""

from __future__ import annotations

import contextlib
import importlib.util
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile
import unittest
from typing import Any, Iterator, Mapping
from unittest import mock


TOOLS = Path(__file__).resolve().parent


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


REMOTE = load_module(
    "gcp_proof_attempt_broker_install_subject", TOOLS / "gcp_proof_remote_install.py"
)
FIXTURES = load_module(
    "gcp_proof_attempt_broker_install_fixtures",
    TOOLS / "gcp_proof_remote_install_test.py",
)


class _RootOwnedStat:
    def __init__(self, inner: os.stat_result) -> None:
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        if name in {"st_uid", "st_gid"}:
            return 0
        return getattr(self._inner, name)


@contextlib.contextmanager
def _as_root_owned(*paths: Path) -> Iterator[None]:
    wanted = {os.path.abspath(os.fspath(path)) for path in paths}

    def _refresh() -> None:
        wanted.update(os.path.abspath(os.fspath(path)) for path in paths)

    real_lstat = os.lstat
    real_fstat = os.fstat
    real_stat = os.stat

    def _matches(info: os.stat_result) -> bool:
        _refresh()
        for path in list(wanted):
            try:
                current = real_lstat(path)
            except OSError:
                continue
            if (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino):
                return True
        return False

    def fake_lstat(path: os.PathLike[str] | str, *args: Any, **kwargs: Any) -> Any:
        info = real_lstat(path, *args, **kwargs)
        if os.path.abspath(os.fspath(path)) in wanted or _matches(info):
            return _RootOwnedStat(info)
        return info

    def fake_path_lstat(path: Path) -> Any:
        return fake_lstat(path)

    def fake_fstat(fd: int) -> Any:
        info = real_fstat(fd)
        if _matches(info):
            return _RootOwnedStat(info)
        return info

    def fake_stat(path: os.PathLike[str] | str, *args: Any, **kwargs: Any) -> Any:
        info = real_stat(path, *args, **kwargs)
        if _matches(info):
            return _RootOwnedStat(info)
        return info

    with mock.patch("os.lstat", fake_lstat), mock.patch("os.fstat", fake_fstat), mock.patch(
        "os.stat", fake_stat
    ), mock.patch.object(REMOTE.os, "lstat", fake_lstat), mock.patch.object(
        REMOTE.os, "fstat", fake_fstat
    ), mock.patch.object(REMOTE.os, "stat", fake_stat), mock.patch.object(
        REMOTE.Path, "lstat", fake_path_lstat
    ):
        yield


def sample_fleet_binding(
    *, fleet_id: str = "123456789abc", instance: str = "proof-control-a1"
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "contract": REMOTE.ATTEMPT_BROKER_FLEET_BINDING_CONTRACT,
        "project": "winsproof123",
        "fleet_id": fleet_id,
        "control": {"instance": instance, "zone": "us-east1-b"},
        "data-winn3": {"instance": "proof-winn3-a1", "zone": "us-central1-a"},
        "data-cover": {"instance": "proof-cover-a1", "zone": "us-east1-b"},
    }


def _owned_paths(
    destination: Path,
    identity_path: Path,
    role_path: Path,
    fleet_binding_path: Path,
    unit_root: Path,
    config_root: Path,
) -> tuple[Path, ...]:
    names = [
        destination,
        identity_path,
        role_path,
        fleet_binding_path,
        unit_root / "winsvpn-gcp-proof-attempt-broker.socket",
        unit_root / "winsvpn-gcp-proof-attempt-broker.service",
    ]
    names.extend(
        unit_root / name for _relative, _install_path, name in REMOTE.ATTEMPT_BROKER_UNITS
    )
    names.extend(
        config_root / name for _relative, _install_path, name in REMOTE.ATTEMPT_BROKER_CONFIGS
    )
    return tuple(names)


def _overwrite(path: Path, data: bytes, mode: int) -> None:
    os.chmod(path, 0o600)
    path.write_bytes(data)
    os.chmod(path, mode)


def _install(
    extracted: Path,
    record: dict[str, Any],
    destination: Path,
    identity_path: Path,
    role_path: Path,
    fleet_binding_path: Path,
    unit_root: Path,
    config_root: Path,
    *,
    fleet_id: str = "123456789abc",
    instance: str = "proof-control-a1",
    include_fleet_binding: bool = True,
    fleet_binding: Mapping[str, Any] | None = None,
    **overrides: Any,
) -> dict[str, Any]:
    kwargs = {
        "role": "control",
        "fleet_id": fleet_id,
        "instance": instance,
        "candidate_id": record["candidate_id"],
        "destination": destination,
        "identity_path": identity_path,
        "role_path": role_path,
        "fleet_binding_path": fleet_binding_path,
        "unit_root": unit_root,
        "config_root": config_root,
        "fleet_binding": (
            None
            if not include_fleet_binding
            else sample_fleet_binding(fleet_id=fleet_id, instance=instance)
            if fleet_binding is None
            else fleet_binding
        ),
    }
    kwargs.update(overrides)
    owned = _owned_paths(
        destination, identity_path, role_path, fleet_binding_path, unit_root, config_root
    )
    with _as_root_owned(*owned), mock.patch.object(REMOTE.os, "chown"), mock.patch.object(
        REMOTE.os, "fchown"
    ), mock.patch.object(REMOTE.subprocess, "run") as run:
        bound = REMOTE.install_attempt_broker(extracted, record, **kwargs)
        run.assert_not_called()
    return bound


class AttemptBrokerInstallTests(unittest.TestCase):
    def test_exact_preexisting_role_and_templates_are_adopted_not_replaced(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            destination = root / "libexec" / "winsvpn-gcp-proof-attempt-broker"
            identity_path = root / "state" / "attempt-broker.json"
            role_path = root / "etc" / "winsvpn" / "role"
            fleet_binding_path = root / "state" / "fleet-binding.json"
            unit_root = root / "systemd"
            config_root = root / "proof-client"
            FIXTURES.write_extracted_tree(extracted, record, files)
            role_path.parent.mkdir(parents=True)
            role_path.write_bytes(b"control\n")
            os.chmod(role_path, 0o400)
            config_root.mkdir(parents=True)
            for relative, _install_path, config_name in REMOTE.ATTEMPT_BROKER_CONFIGS:
                (config_root / config_name).write_bytes(files[relative])
                os.chmod(config_root / config_name, 0o400)
            identities = {
                path: (path.lstat().st_dev, path.lstat().st_ino)
                for path in (role_path, *(config_root / item[2] for item in REMOTE.ATTEMPT_BROKER_CONFIGS))
            }
            _install(
                extracted,
                record,
                destination,
                identity_path,
                role_path,
                fleet_binding_path,
                unit_root,
                config_root,
            )
            self.assertEqual(
                {
                    path: (path.lstat().st_dev, path.lstat().st_ino)
                    for path in identities
                },
                identities,
            )

    def test_differing_preexisting_role_refuses_before_any_install_mutation(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            destination = root / "libexec" / "winsvpn-gcp-proof-attempt-broker"
            identity_path = root / "state" / "attempt-broker.json"
            role_path = root / "etc" / "winsvpn" / "role"
            fleet_binding_path = root / "state" / "fleet-binding.json"
            unit_root = root / "systemd"
            config_root = root / "proof-client"
            FIXTURES.write_extracted_tree(extracted, record, files)
            role_path.parent.mkdir(parents=True)
            role_path.write_bytes(b"data-cover\n")
            os.chmod(role_path, 0o400)
            with self.assertRaisesRegex(
                REMOTE.RemoteInstallError, "preexisting file is not exact"
            ):
                _install(
                    extracted,
                    record,
                    destination,
                    identity_path,
                    role_path,
                    fleet_binding_path,
                    unit_root,
                    config_root,
                )
            self.assertEqual(role_path.read_bytes(), b"data-cover\n")
            self.assertFalse(destination.exists())
            self.assertFalse(identity_path.exists())

    def test_late_install_failure_preserves_adopted_role_and_template_inode(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            destination = root / "libexec" / "winsvpn-gcp-proof-attempt-broker"
            identity_path = root / "state" / "attempt-broker.json"
            role_path = root / "etc" / "winsvpn" / "role"
            fleet_binding_path = root / "state" / "fleet-binding.json"
            unit_root = root / "systemd"
            config_root = root / "proof-client"
            FIXTURES.write_extracted_tree(extracted, record, files)
            role_path.parent.mkdir(parents=True)
            role_path.write_bytes(b"control\n")
            os.chmod(role_path, 0o400)
            config_root.mkdir(parents=True)
            relative, _install_path, config_name = REMOTE.ATTEMPT_BROKER_CONFIGS[0]
            config_path = config_root / config_name
            config_path.write_bytes(files[relative])
            os.chmod(config_path, 0o400)
            identities = {
                path: (path.lstat().st_dev, path.lstat().st_ino)
                for path in (role_path, config_path)
            }
            with mock.patch.object(
                REMOTE,
                "require_complete_attempt_broker",
                side_effect=REMOTE.RemoteInstallError("injected completion failure"),
            ):
                with self.assertRaisesRegex(
                    REMOTE.RemoteInstallError, "injected completion failure"
                ):
                    _install(
                        extracted,
                        record,
                        destination,
                        identity_path,
                        role_path,
                        fleet_binding_path,
                        unit_root,
                        config_root,
                    )
            self.assertEqual(
                {
                    path: (path.lstat().st_dev, path.lstat().st_ino)
                    for path in identities
                },
                identities,
            )
            self.assertFalse(destination.exists())
            self.assertFalse(identity_path.exists())

    def test_installs_exact_manifest_bytes_units_configs_role_and_fleet_binding(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            destination = root / "libexec" / "winsvpn-gcp-proof-attempt-broker"
            identity_path = root / "state" / "attempt-broker.json"
            role_path = root / "etc" / "winsvpn" / "role"
            fleet_binding_path = root / "state" / "fleet-binding.json"
            unit_root = root / "systemd"
            config_root = root / "proof-client"
            FIXTURES.write_extracted_tree(extracted, record, files)
            bound = _install(
                extracted,
                record,
                destination,
                identity_path,
                role_path,
                fleet_binding_path,
                unit_root,
                config_root,
            )
            self.assertEqual(destination.read_bytes(), files[FIXTURES.BROKER_PATH])
            self.assertEqual(REMOTE.sha256_bytes(destination.read_bytes()), bound["sha256"])
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(identity_path.stat().st_mode), 0o400)
            self.assertEqual(role_path.read_bytes(), b"control\n")
            self.assertEqual(stat.S_IMODE(role_path.stat().st_mode), 0o400)
            fleet = REMOTE.strict_json(fleet_binding_path.read_bytes(), "fleet binding")
            self.assertEqual(fleet["fleet_id"], "123456789abc")
            self.assertEqual(fleet["control"]["instance"], "proof-control-a1")
            self.assertEqual(
                fleet_binding_path.read_bytes(), REMOTE.canonical_bytes(fleet)
            )
            self.assertEqual(stat.S_IMODE(fleet_binding_path.stat().st_mode), 0o400)
            socket = unit_root / "winsvpn-gcp-proof-attempt-broker.socket"
            service = unit_root / "winsvpn-gcp-proof-attempt-broker.service"
            self.assertEqual(socket.read_bytes(), files[REMOTE.ATTEMPT_BROKER_SOCKET_SOURCE])
            self.assertEqual(service.read_bytes(), files[REMOTE.ATTEMPT_BROKER_SERVICE_SOURCE])
            self.assertEqual(stat.S_IMODE(socket.stat().st_mode), 0o444)
            for relative, _install_path, unit_name in REMOTE.ATTEMPT_BROKER_UNITS:
                installed = unit_root / unit_name
                self.assertEqual(installed.read_bytes(), files[relative])
                self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o444)
            for relative, _install_path, config_name in REMOTE.ATTEMPT_BROKER_CONFIGS:
                installed = config_root / config_name
                self.assertEqual(installed.read_bytes(), files[relative])
                self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o400)
            identity = REMOTE.strict_json(identity_path.read_bytes(), "identity")
            info = destination.lstat()
            self.assertEqual(identity["role"], "control")
            self.assertEqual(identity["required_roles"], ["control"])
            self.assertEqual(identity["source_path"], FIXTURES.BROKER_PATH)
            self.assertEqual(identity["path"], os.fspath(destination))
            self.assertEqual(identity["st_dev"], info.st_dev)
            self.assertEqual(identity["st_ino"], info.st_ino)

    def test_path_hash_mode_substitution_partial_install_and_rollback_fail(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            destination = root / "libexec" / "winsvpn-gcp-proof-attempt-broker"
            identity_path = root / "state" / "attempt-broker.json"
            role_path = root / "etc" / "winsvpn" / "role"
            fleet_binding_path = root / "state" / "fleet-binding.json"
            unit_root = root / "systemd"
            config_root = root / "proof-client"
            FIXTURES.write_extracted_tree(extracted, record, files)
            broker = extracted.joinpath(*PurePosixPath(FIXTURES.BROKER_PATH).parts)

            broker.write_bytes(b"#!/usr/bin/python3\nsubstituted-broker\n")
            os.chmod(broker, 0o755)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "SHA-256|not bound"):
                _install(
                    extracted,
                    record,
                    destination,
                    identity_path,
                    role_path,
                    fleet_binding_path,
                    unit_root,
                    config_root,
                )
            self.assertFalse(destination.exists())
            self.assertFalse(identity_path.exists())
            self.assertFalse(role_path.exists())
            self.assertFalse(fleet_binding_path.exists())

            broker.write_bytes(files[FIXTURES.BROKER_PATH])
            os.chmod(broker, 0o644)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "path/hash/mode"):
                _install(
                    extracted,
                    record,
                    destination,
                    identity_path,
                    role_path,
                    fleet_binding_path,
                    unit_root,
                    config_root,
                )
            self.assertFalse(destination.exists())
            self.assertFalse((unit_root / "winsvpn-gcp-proof-attempt-broker.service").exists())

            os.chmod(broker, 0o755)
            bound = _install(
                extracted,
                record,
                destination,
                identity_path,
                role_path,
                fleet_binding_path,
                unit_root,
                config_root,
            )
            identity_path.unlink()
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "incomplete"):
                _install(
                    extracted,
                    record,
                    destination,
                    identity_path,
                    role_path,
                    fleet_binding_path,
                    unit_root,
                    config_root,
                )

    def test_unexpected_role_and_stale_identity_are_refused(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            destination = root / "libexec" / "winsvpn-gcp-proof-attempt-broker"
            identity_path = root / "state" / "attempt-broker.json"
            role_path = root / "etc" / "winsvpn" / "role"
            fleet_binding_path = root / "state" / "fleet-binding.json"
            unit_root = root / "systemd"
            config_root = root / "proof-client"
            FIXTURES.write_extracted_tree(extracted, record, files)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "unexpected role"):
                _install(
                    extracted,
                    record,
                    destination,
                    identity_path,
                    role_path,
                    fleet_binding_path,
                    unit_root,
                    config_root,
                    role="data-winn3",
                )
            self.assertFalse(destination.exists())
            _install(
                extracted,
                record,
                destination,
                identity_path,
                role_path,
                fleet_binding_path,
                unit_root,
                config_root,
            )
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "stale"):
                _install(
                    extracted,
                    record,
                    destination,
                    identity_path,
                    role_path,
                    fleet_binding_path,
                    unit_root,
                    config_root,
                    candidate_id="a" * 64,
                )
            self.assertEqual(destination.read_bytes(), files[FIXTURES.BROKER_PATH])

    def test_unit_config_and_fleet_binding_substitution_fail_closed(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            destination = root / "libexec" / "winsvpn-gcp-proof-attempt-broker"
            identity_path = root / "state" / "attempt-broker.json"
            role_path = root / "etc" / "winsvpn" / "role"
            fleet_binding_path = root / "state" / "fleet-binding.json"
            unit_root = root / "systemd"
            config_root = root / "proof-client"
            FIXTURES.write_extracted_tree(extracted, record, files)
            bound = _install(
                extracted,
                record,
                destination,
                identity_path,
                role_path,
                fleet_binding_path,
                unit_root,
                config_root,
            )
            unit = unit_root / "winsvpn-proof-winn3-probe.service"
            _overwrite(unit, b"[Service]\nExecStart=/bin/true\n", 0o444)
            owned = _owned_paths(
                destination, identity_path, role_path, fleet_binding_path, unit_root, config_root
            )
            with _as_root_owned(*owned), self.assertRaisesRegex(
                REMOTE.RemoteInstallError, "SHA-256|not bound"
            ):
                REMOTE.require_complete_attempt_broker(
                    destination,
                    identity_path,
                    expected_sha256=bound["sha256"],
                    expected_bytes=bound["bytes"],
                    expected_mode=REMOTE.ATTEMPT_BROKER_INSTALL_MODE,
                    role="control",
                    fleet_id="123456789abc",
                    instance="proof-control-a1",
                    candidate_id=record["candidate_id"],
                    source_path=FIXTURES.BROKER_PATH,
                    binding=record["attempt_broker"],
                    role_path=role_path,
                    fleet_binding_path=fleet_binding_path,
                    unit_root=unit_root,
                    config_root=config_root,
                    require_fleet_binding=True,
                )
            _overwrite(
                unit,
                files["tools/gcp_proof_attempt_broker/winsvpn-proof-winn3-probe.service"],
                0o444,
            )
            _overwrite(role_path, b"data-cover\n", 0o400)
            with _as_root_owned(*owned), self.assertRaisesRegex(
                REMOTE.RemoteInstallError, "role file is invalid"
            ):
                REMOTE.require_complete_attempt_broker(
                    destination,
                    identity_path,
                    expected_sha256=bound["sha256"],
                    expected_bytes=bound["bytes"],
                    expected_mode=REMOTE.ATTEMPT_BROKER_INSTALL_MODE,
                    role="control",
                    fleet_id="123456789abc",
                    instance="proof-control-a1",
                    candidate_id=record["candidate_id"],
                    source_path=FIXTURES.BROKER_PATH,
                    binding=record["attempt_broker"],
                    role_path=role_path,
                    fleet_binding_path=fleet_binding_path,
                    unit_root=unit_root,
                    config_root=config_root,
                    require_fleet_binding=True,
                )
            _overwrite(role_path, b"control\n", 0o400)
            swapped = sample_fleet_binding()
            swapped["data-cover"]["instance"] = "proof-control-a1"
            _overwrite(fleet_binding_path, REMOTE.canonical_bytes(swapped), 0o400)
            with _as_root_owned(*owned), self.assertRaisesRegex(
                REMOTE.RemoteInstallError, "same-node fallback is forbidden"
            ):
                REMOTE.require_complete_attempt_broker(
                    destination,
                    identity_path,
                    expected_sha256=bound["sha256"],
                    expected_bytes=bound["bytes"],
                    expected_mode=REMOTE.ATTEMPT_BROKER_INSTALL_MODE,
                    role="control",
                    fleet_id="123456789abc",
                    instance="proof-control-a1",
                    candidate_id=record["candidate_id"],
                    source_path=FIXTURES.BROKER_PATH,
                    binding=record["attempt_broker"],
                    role_path=role_path,
                    fleet_binding_path=fleet_binding_path,
                    unit_root=unit_root,
                    config_root=config_root,
                    require_fleet_binding=True,
                )

    def test_missing_fleet_binding_fails_finalize_but_install_can_omit_it(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            destination = root / "libexec" / "winsvpn-gcp-proof-attempt-broker"
            identity_path = root / "state" / "attempt-broker.json"
            role_path = root / "etc" / "winsvpn" / "role"
            fleet_binding_path = root / "state" / "fleet-binding.json"
            unit_root = root / "systemd"
            config_root = root / "proof-client"
            FIXTURES.write_extracted_tree(extracted, record, files)
            bound = _install(
                extracted,
                record,
                destination,
                identity_path,
                role_path,
                fleet_binding_path,
                unit_root,
                config_root,
                include_fleet_binding=False,
            )
            self.assertTrue(destination.exists())
            self.assertFalse(fleet_binding_path.exists())
            owned = _owned_paths(
                destination, identity_path, role_path, fleet_binding_path, unit_root, config_root
            )
            with _as_root_owned(*owned), self.assertRaisesRegex(
                REMOTE.RemoteInstallError, "unreadable|incomplete|fleet binding"
            ):
                REMOTE.require_complete_attempt_broker(
                    destination,
                    identity_path,
                    expected_sha256=bound["sha256"],
                    expected_bytes=bound["bytes"],
                    expected_mode=REMOTE.ATTEMPT_BROKER_INSTALL_MODE,
                    role="control",
                    fleet_id="123456789abc",
                    instance="proof-control-a1",
                    candidate_id=record["candidate_id"],
                    source_path=FIXTURES.BROKER_PATH,
                    binding=record["attempt_broker"],
                    role_path=role_path,
                    fleet_binding_path=fleet_binding_path,
                    unit_root=unit_root,
                    config_root=config_root,
                    require_fleet_binding=True,
                )

    def test_test_only_host_cannot_emit_production_evidence(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            FIXTURES.write_extracted_tree(extracted, record, files)
            self.assertNotEqual(os.geteuid(), 0)
            with self.assertRaisesRegex(
                REMOTE.RemoteInstallError, "test-only host cannot emit production evidence"
            ):
                REMOTE.install_attempt_broker(
                    extracted,
                    record,
                    role="control",
                    fleet_id="123456789abc",
                    instance="proof-control-a1",
                    candidate_id=record["candidate_id"],
                    destination=REMOTE.ATTEMPT_BROKER_INSTALL_FILE,
                    identity_path=REMOTE.ATTEMPT_BROKER_IDENTITY_PATH,
                    fleet_binding=sample_fleet_binding(),
                )


if __name__ == "__main__":
    unittest.main()
