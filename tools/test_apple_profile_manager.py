#!/usr/bin/env python3
"""Hostile local tests for Apple provisioning-profile custody."""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import io
import os
import plistlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import apple_profile_manager as manager


NOW = dt.datetime(2026, 8, 26, 12, 0, tzinfo=dt.timezone.utc)
UUID = "12345678-1234-1234-1234-1234567890AB"


def profile_payload(
    *,
    bundle_id: str = manager.IOS_BUNDLE_ID,
    team_id: str = manager.DEFAULT_TEAM_ID,
    name: str = "Wins VPN Ad Hoc",
    uuid: str = UUID,
    platforms: list[str] | None = None,
    development: bool = False,
    devices: list[str] | None = None,
    provisions_all_devices: bool = False,
    creation: dt.datetime | None = None,
    expiration: dt.datetime | None = None,
    certificates: list[bytes] | None = None,
) -> dict[str, object]:
    if platforms is None:
        platforms = ["iOS"]
    if devices is None:
        devices = ["00008110-0011223344556677"]
    if certificates is None:
        certificates = [b"D" * 128]
    entitlements: dict[str, object] = {
        "application-identifier": f"{team_id}.{bundle_id}",
        "com.apple.developer.team-identifier": team_id,
        "get-task-allow": development,
        "com.apple.developer.networking.networkextension": ["packet-tunnel-provider"],
        "com.apple.security.application-groups": [manager.IOS_APP_GROUP_ID],
        "keychain-access-groups": [f"{team_id}.{manager.SHARED_KEYCHAIN_SUFFIX}"],
    }
    return {
        "UUID": uuid,
        "Name": name,
        "TeamIdentifier": [team_id],
        "ApplicationIdentifierPrefix": [team_id],
        "Platform": platforms,
        "ProvisionedDevices": devices,
        "ProvisionsAllDevices": provisions_all_devices,
        "DeveloperCertificates": certificates,
        "CreationDate": creation or dt.datetime(2026, 1, 1),
        "ExpirationDate": expiration or dt.datetime(2099, 1, 1),
        "Entitlements": entitlements,
    }


def certificate_subject(*, development: bool = False, team_id: str = manager.DEFAULT_TEAM_ID) -> str:
    kind = "Apple Development" if development else "Apple Distribution"
    return f"subject=UID = TEST, CN = {kind}: Win's VPN Inc ({team_id}), OU = {team_id}"


class TemporaryProfile:
    def __init__(self, directory: Path, name: str = "profile.mobileprovision", content: bytes = b"cms-profile"):
        self.path = directory / name
        self.path.write_bytes(content)
        self.path.chmod(0o600)


class ParseProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.source = TemporaryProfile(self.directory)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def parse(self, payload: dict[str, object] | None = None, *, subject: str | None = None):
        with mock.patch.object(
            manager,
            "run_security_decode",
            return_value=payload or profile_payload(),
        ), mock.patch.object(
            manager,
            "cert_subject",
            return_value=subject or certificate_subject(),
        ):
            return manager.parse_profile(self.source.path, now=NOW)

    def test_valid_profile_binds_file_payload_and_certificate(self) -> None:
        parsed = self.parse()
        self.assertEqual(parsed.bundle_id, manager.IOS_BUNDLE_ID)
        self.assertEqual(parsed.team_prefix, manager.DEFAULT_TEAM_ID)
        self.assertEqual(parsed.distribution_class, "ad-hoc")
        self.assertEqual(parsed.content, b"cms-profile")
        self.assertEqual(parsed.sha256, manager.hashlib.sha256(b"cms-profile").hexdigest())
        self.assertEqual(parsed.certificate_sha1s, (manager.hashlib.sha1(b"D" * 128).hexdigest().upper(),))
        self.assertIsNotNone(parsed.source_identity)

    def test_expired_profile_is_rejected(self) -> None:
        with self.assertRaisesRegex(manager.ProfileError, "expired"):
            self.parse(profile_payload(expiration=dt.datetime(2026, 8, 26, 11, 59)))

    def test_future_profile_is_rejected(self) -> None:
        with self.assertRaisesRegex(manager.ProfileError, "future"):
            self.parse(profile_payload(creation=dt.datetime(2026, 8, 27)))

    def test_cross_team_entitlement_is_rejected(self) -> None:
        payload = profile_payload()
        entitlements = dict(payload["Entitlements"])
        entitlements["com.apple.developer.team-identifier"] = "AAAAAAAAAA"
        payload["Entitlements"] = entitlements
        with self.assertRaisesRegex(manager.ProfileError, "team identifier"):
            self.parse(payload)

    def test_wildcard_bundle_id_is_rejected(self) -> None:
        payload = profile_payload()
        entitlements = dict(payload["Entitlements"])
        entitlements["application-identifier"] = f"{manager.DEFAULT_TEAM_ID}.org.winsvpn.*"
        payload["Entitlements"] = entitlements
        with self.assertRaisesRegex(manager.ProfileError, "exact bundle"):
            self.parse(payload)

    def test_ambiguous_application_identifiers_are_rejected(self) -> None:
        payload = profile_payload()
        entitlements = dict(payload["Entitlements"])
        entitlements["com.apple.application-identifier"] = (
            f"{manager.DEFAULT_TEAM_ID}.org.winsvpn.other"
        )
        payload["Entitlements"] = entitlements
        with self.assertRaisesRegex(manager.ProfileError, "ambiguous"):
            self.parse(payload)

    def test_non_boolean_task_allow_is_rejected(self) -> None:
        payload = profile_payload()
        entitlements = dict(payload["Entitlements"])
        entitlements["get-task-allow"] = "false"
        payload["Entitlements"] = entitlements
        with self.assertRaisesRegex(manager.ProfileError, "get-task-allow"):
            self.parse(payload)

    def test_development_entitlement_with_distribution_certificate_is_rejected(self) -> None:
        with self.assertRaisesRegex(manager.ProfileError, "do not match"):
            self.parse(profile_payload(development=True))

    def test_cross_platform_profile_is_rejected(self) -> None:
        with self.assertRaisesRegex(manager.ProfileError, "platform"):
            self.parse(profile_payload(platforms=["iOS", "OSX"]))

    def test_noncanonical_uuid_is_rejected(self) -> None:
        with self.assertRaisesRegex(manager.ProfileError, "UUID"):
            self.parse(profile_payload(uuid="../../hostile"))

    def test_duplicate_certificates_are_rejected(self) -> None:
        certificate = b"D" * 128
        with self.assertRaisesRegex(manager.ProfileError, "duplicate developer certificates"):
            self.parse(profile_payload(certificates=[certificate, certificate]))

    def test_wrong_team_certificate_is_rejected(self) -> None:
        with self.assertRaisesRegex(manager.ProfileError, "wrong team"):
            self.parse(subject=certificate_subject(team_id="AAAAAAAAAA"))

    def test_ambiguous_certificate_common_name_is_rejected(self) -> None:
        subject = certificate_subject() + ", CN = Apple Development: Other (5YT8H4U72M)"
        with self.assertRaisesRegex(manager.ProfileError, "ambiguous"):
            self.parse(subject=subject)

    def test_enterprise_or_developer_id_profile_is_rejected(self) -> None:
        with self.assertRaisesRegex(manager.ProfileError, "unsupported"):
            self.parse(profile_payload(devices=[], provisions_all_devices=True))

    def test_symlink_profile_is_rejected(self) -> None:
        link = self.directory / "link.mobileprovision"
        link.symlink_to(self.source.path)
        with self.assertRaisesRegex(manager.ProfileError, "regular file"):
            manager.parse_profile(link, now=NOW)

    def test_hardlinked_profile_is_rejected(self) -> None:
        os.link(self.source.path, self.directory / "hard.mobileprovision")
        with self.assertRaisesRegex(manager.ProfileError, "hard link"):
            self.parse()

    def test_group_writable_profile_is_rejected(self) -> None:
        self.source.path.chmod(0o620)
        with self.assertRaisesRegex(manager.ProfileError, "group/world writable"):
            self.parse()

    def test_oversized_profile_is_rejected_before_decode(self) -> None:
        with self.source.path.open("wb") as handle:
            handle.truncate(manager.MAX_PROFILE_BYTES + 1)
        with self.assertRaisesRegex(manager.ProfileError, "size"):
            self.parse()

    def test_path_replacement_during_decode_is_rejected(self) -> None:
        payload = profile_payload()

        def replace_source(_content: bytes) -> dict[str, object]:
            replacement = self.directory / "replacement"
            replacement.write_bytes(b"different-cms")
            replacement.chmod(0o600)
            os.replace(replacement, self.source.path)
            return payload

        with mock.patch.object(manager, "run_security_decode", side_effect=replace_source), mock.patch.object(
            manager, "cert_subject", return_value=certificate_subject()
        ):
            with self.assertRaisesRegex(manager.ProfileError, "during validation"):
                manager.parse_profile(self.source.path, now=NOW)

    def test_same_inode_content_mutation_during_decode_is_rejected(self) -> None:
        payload = profile_payload()

        def mutate_source(_content: bytes) -> dict[str, object]:
            self.source.path.write_bytes(b"mutated-cms")
            self.source.path.chmod(0o600)
            return payload

        with mock.patch.object(manager, "run_security_decode", side_effect=mutate_source), mock.patch.object(
            manager, "cert_subject", return_value=certificate_subject()
        ):
            with self.assertRaisesRegex(manager.ProfileError, "during validation"):
                manager.parse_profile(self.source.path, now=NOW)


class DiscoveryAndReadinessTests(unittest.TestCase):
    def test_wildcard_capability_groups_do_not_satisfy_exact_custody(self) -> None:
        team = manager.DEFAULT_TEAM_ID
        self.assertFalse(
            manager.has_expected_keychain_group([f"{team}.*"], team)
        )
        self.assertFalse(
            manager.has_expected_keychain_group([manager.SHARED_KEYCHAIN_SUFFIX], team)
        )
        self.assertFalse(
            manager.has_expected_app_group(
                [manager.IOS_APP_GROUP_ID, f"{team}.*"],
                manager.IOS_APP_GROUP_ID,
                team,
            )
        )

    def test_duplicate_profile_content_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            first = TemporaryProfile(directory, "first.mobileprovision", b"one")
            second = TemporaryProfile(directory, "second.mobileprovision", b"two")
            one = manager.make_fake_profile(bundle_id=manager.IOS_BUNDLE_ID, name="One")
            two = dataclasses.replace(
                manager.make_fake_profile(bundle_id=manager.IOS_BUNDLE_ID, name="Two"),
                sha256=one.sha256,
            )
            mapping = {first.path.name: one, second.path.name: two}
            with mock.patch.object(manager, "parse_profile", side_effect=lambda path: mapping[path.name]):
                with self.assertRaisesRegex(manager.ProfileError, "duplicate provisioning profile content"):
                    manager.discover_profiles([directory])

    def test_duplicate_uuid_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            first = TemporaryProfile(directory, "first.mobileprovision", b"one")
            second = TemporaryProfile(directory, "second.mobileprovision", b"two")
            one = manager.make_fake_profile(bundle_id=manager.IOS_BUNDLE_ID, name="One")
            two = dataclasses.replace(
                manager.make_fake_profile(bundle_id=manager.IOS_BUNDLE_ID, name="Two"),
                uuid=one.uuid,
                sha256="1" * 64,
            )
            mapping = {first.path.name: one, second.path.name: two}
            with mock.patch.object(manager, "parse_profile", side_effect=lambda path: mapping[path.name]):
                with self.assertRaisesRegex(manager.ProfileError, "duplicate provisioning profile UUID"):
                    manager.discover_profiles([directory])

    def test_duplicate_profile_name_for_same_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            first = TemporaryProfile(directory, "first.mobileprovision", b"one")
            second = TemporaryProfile(directory, "second.mobileprovision", b"two")
            one = manager.make_fake_profile(bundle_id=manager.IOS_BUNDLE_ID, name="Same")
            two = dataclasses.replace(
                manager.make_fake_profile(bundle_id=manager.IOS_BUNDLE_ID, name="Other"),
                name="Same",
                sha256="2" * 64,
            )
            mapping = {first.path.name: one, second.path.name: two}
            with mock.patch.object(manager, "parse_profile", side_effect=lambda path: mapping[path.name]):
                with self.assertRaisesRegex(manager.ProfileError, "ambiguous provisioning profile name"):
                    manager.discover_profiles([directory])

    def test_ambiguous_usable_release_profiles_fail_readiness(self) -> None:
        profiles = [
            manager.make_fake_profile(bundle_id=manager.IOS_BUNDLE_ID, name="One"),
            manager.make_fake_profile(bundle_id=manager.IOS_BUNDLE_ID, name="Two"),
        ]
        ready, reason, usable = manager.readiness_for(profiles, manager.IOS_BUNDLE_ID)
        self.assertFalse(ready)
        self.assertIn("ambiguous", reason)
        self.assertEqual(len(usable), 2)

    def test_ambiguous_usable_macos_profiles_fail_readiness(self) -> None:
        profiles = [
            manager.make_fake_profile(
                bundle_id=manager.MACOS_BUNDLE_ID,
                name=name,
                platforms=("OSX",),
                provisioned_device_count=0,
            )
            for name in ("One", "Two")
        ]
        ready, reason, usable = manager.macos_readiness_for(
            profiles, manager.MACOS_BUNDLE_ID, development=False
        )
        self.assertFalse(ready)
        self.assertIn("ambiguous", reason)
        self.assertEqual(len(usable), 2)


class SigningIdentityTests(unittest.TestCase):
    def test_parser_accepts_exact_current_apple_identity(self) -> None:
        output = (
            b'  1) AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "Apple Distribution: '
            b"Win's VPN Inc (5YT8H4U72M)" b'"\n     1 valid identities found\n'
        )
        identities = manager.parse_codesigning_identities(output)
        self.assertEqual(len(identities), 1)
        self.assertEqual(identities[0].team_id, manager.DEFAULT_TEAM_ID)

    def test_parser_rejects_duplicate_identity(self) -> None:
        line = (
            b'  1) AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "Apple Distribution: '
            b"Win's VPN Inc (5YT8H4U72M)" b'"\n'
        )
        with self.assertRaisesRegex(manager.ProfileError, "duplicate identity"):
            manager.parse_codesigning_identities(line + line.replace(b"1)", b"2)"))

    def test_parser_rejects_unrecognized_output(self) -> None:
        with self.assertRaisesRegex(manager.ProfileError, "unrecognized"):
            manager.parse_codesigning_identities(b"surprise output\n")

    def test_parser_allows_exact_ignored_developer_id_identity(self) -> None:
        output = (
            b'  1) CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC "Developer ID Application: '
            b"Win's VPN Inc (5YT8H4U72M)" b'"\n     1 valid identities found\n'
        )
        self.assertEqual(manager.parse_codesigning_identities(output), [])

    def test_parser_rejects_lookalike_identity_name(self) -> None:
        output = (
            b'  1) CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC "Apple Distribution : '
            b"Win's VPN Inc (5YT8H4U72M)" b'"\n'
        )
        with self.assertRaisesRegex(manager.ProfileError, "unsupported identity"):
            manager.parse_codesigning_identities(output)

    def test_parser_rejects_invalid_utf8(self) -> None:
        with self.assertRaisesRegex(manager.ProfileError, "UTF-8"):
            manager.parse_codesigning_identities(b"\xff")

    def test_selector_binds_team_kind_and_profile_certificate(self) -> None:
        profile = dataclasses.replace(
            manager.make_fake_profile(bundle_id=manager.IOS_BUNDLE_ID),
            certificate_sha1s=("A" * 40,),
        )
        selected = manager.select_signing_identity(
            profile,
            [
                manager.SigningIdentity(
                    sha1="A" * 40,
                    name="Apple Distribution: Win's VPN Inc (5YT8H4U72M)",
                    kind="Apple Distribution",
                    team_id=manager.DEFAULT_TEAM_ID,
                )
            ],
        )
        self.assertEqual(selected.sha1, "A" * 40)

    def test_selector_rejects_ambiguous_matches(self) -> None:
        profile = dataclasses.replace(
            manager.make_fake_profile(bundle_id=manager.IOS_BUNDLE_ID),
            certificate_sha1s=("A" * 40, "B" * 40),
        )
        identities = [
            manager.SigningIdentity(
                sha1=value * 40,
                name=f"Apple Distribution: Name {value} ({manager.DEFAULT_TEAM_ID})",
                kind="Apple Distribution",
                team_id=manager.DEFAULT_TEAM_ID,
            )
            for value in ("A", "B")
        ]
        with self.assertRaisesRegex(manager.ProfileError, "exactly one"):
            manager.select_signing_identity(profile, identities)

    def test_selector_rejects_cross_team_identity(self) -> None:
        profile = manager.make_fake_profile(bundle_id=manager.IOS_BUNDLE_ID)
        identity = manager.SigningIdentity(
            sha1="A" * 40,
            name="Apple Distribution: Other (AAAAAAAAAA)",
            kind="Apple Distribution",
            team_id="AAAAAAAAAA",
        )
        with self.assertRaisesRegex(manager.ProfileError, "exactly one"):
            manager.select_signing_identity(profile, [identity])


class AtomicInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = TemporaryProfile(self.root, content=b"held-profile")
        self.destination = self.root / "installed"
        self.destination.mkdir(mode=0o700)
        payload = profile_payload()
        with mock.patch.object(manager, "run_security_decode", return_value=payload), mock.patch.object(
            manager, "cert_subject", return_value=certificate_subject()
        ):
            self.profile = manager.parse_profile(self.source.path, now=NOW)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_install_is_atomic_exact_and_idempotent(self) -> None:
        first = manager.install_profiles([self.profile], install_dir=self.destination)
        target = manager.installed_profile_path(self.profile, self.destination)
        self.assertEqual(target.read_bytes(), b"held-profile")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        second = manager.install_profiles([self.profile], install_dir=self.destination)
        self.assertIn("installed:", first[0])
        self.assertIn("already installed:", second[0])

    def test_source_mutation_after_validation_is_rejected(self) -> None:
        self.source.path.write_bytes(b"changed-profile")
        self.source.path.chmod(0o600)
        with self.assertRaisesRegex(manager.ProfileError, "changed after validation"):
            manager.install_profiles([self.profile], install_dir=self.destination)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_existing_different_destination_is_not_replaced(self) -> None:
        target = manager.installed_profile_path(self.profile, self.destination)
        target.write_bytes(b"different")
        target.chmod(0o600)
        with self.assertRaisesRegex(manager.ProfileError, "different existing"):
            manager.install_profiles([self.profile], install_dir=self.destination)
        self.assertEqual(target.read_bytes(), b"different")

    def test_symlink_destination_is_not_followed(self) -> None:
        victim = self.root / "victim"
        victim.write_bytes(b"victim")
        target = manager.installed_profile_path(self.profile, self.destination)
        target.symlink_to(victim)
        with self.assertRaises(OSError):
            manager.install_profiles([self.profile], install_dir=self.destination)
        self.assertEqual(victim.read_bytes(), b"victim")

    def test_failed_link_cleans_only_its_temporary_file(self) -> None:
        unrelated = self.destination / ".unrelated"
        unrelated.write_bytes(b"keep")
        with mock.patch.object(manager.os, "link", side_effect=OSError("link failed")):
            with self.assertRaises(OSError):
                manager.install_profiles([self.profile], install_dir=self.destination)
        self.assertEqual(unrelated.read_bytes(), b"keep")
        self.assertEqual([path for path in self.destination.iterdir() if ".wins-" in path.name], [])

    def test_xcconfig_refuses_symlink_and_different_existing_content(self) -> None:
        target = self.root / "signing.xcconfig"
        manager.write_private_xcconfig(target, "A = B\n")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        manager.write_private_xcconfig(target, "A = B\n")
        with self.assertRaisesRegex(manager.ProfileError, "different existing"):
            manager.write_private_xcconfig(target, "A = C\n")
        target.unlink()
        victim = self.root / "victim-xcconfig"
        victim.write_text("victim\n", encoding="ascii")
        target.symlink_to(victim)
        with self.assertRaises(OSError):
            manager.write_private_xcconfig(target, "A = B\n")
        self.assertEqual(victim.read_text(encoding="ascii"), "victim\n")


class ToolBoundaryTests(unittest.TestCase):
    def test_security_decode_uses_exact_snapshot_and_strict_plist(self) -> None:
        seen: dict[str, object] = {}

        def fake_bounded(argv, **_kwargs):
            seen["argv"] = argv
            seen["content"] = Path(argv[-1]).read_bytes()
            return subprocess.CompletedProcess(
                argv,
                0,
                stdout=plistlib.dumps({"Name": "Fixture"}),
                stderr=b"",
            )

        with mock.patch.object(manager, "_bounded_run", side_effect=fake_bounded):
            decoded = manager.run_security_decode(b"signed-cms-fixture")
        self.assertEqual(decoded["Name"], "Fixture")
        self.assertEqual(seen["content"], b"signed-cms-fixture")
        self.assertEqual(seen["argv"][:4], ["/usr/bin/security", "cms", "-D", "-i"])

    def test_security_decode_rejects_duplicate_plist_keys(self) -> None:
        duplicate = b"""<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Name</key><string>One</string>
<key>Name</key><string>Two</string>
</dict></plist>"""
        completed = subprocess.CompletedProcess(
            ["security"], 0, stdout=duplicate, stderr=b""
        )
        with mock.patch.object(manager, "_bounded_run", return_value=completed):
            with self.assertRaisesRegex(manager.ProfileError, "duplicate property-list key"):
                manager.run_security_decode(b"signed-cms-fixture")

    def test_security_decode_rejects_excessive_nesting(self) -> None:
        value: object = "leaf"
        for _ in range(18):
            value = {"child": value}
        completed = subprocess.CompletedProcess(
            ["security"], 0, stdout=plistlib.dumps(value), stderr=b""
        )
        with mock.patch.object(manager, "_bounded_run", return_value=completed):
            with self.assertRaisesRegex(manager.ProfileError, "too complex"):
                manager.run_security_decode(b"signed-cms-fixture")

    def test_certificate_expiry_check_is_mandatory(self) -> None:
        subject = subprocess.CompletedProcess(
            ["openssl"],
            0,
            stdout=certificate_subject().encode("ascii"),
            stderr=b"",
        )
        expired = subprocess.CompletedProcess(
            ["openssl"],
            0,
            stdout=(
                b"notBefore=Jan  1 00:00:00 2020 GMT\n"
                b"notAfter=Jan  1 00:00:00 2021 GMT\n"
            ),
            stderr=b"",
        )
        with mock.patch.object(manager, "_bounded_run", side_effect=[subject, expired]) as runner:
            with self.assertRaisesRegex(manager.ProfileError, "not currently valid"):
                manager.cert_subject(b"D" * 128)
        self.assertIn("-dates", runner.call_args_list[1].args[0])

    def test_bounded_run_rejects_oversized_output(self) -> None:
        def fake_run(_argv, **kwargs):
            kwargs["stdout"].write(b"X" * (manager.MAX_TOOL_OUTPUT_BYTES + 1))
            return subprocess.CompletedProcess(["tool"], 0)

        with mock.patch.object(manager.subprocess, "run", side_effect=fake_run):
            with self.assertRaisesRegex(manager.ProfileError, "exceeded"):
                manager._bounded_run(["/usr/bin/security", "cms"])

    def test_bounded_run_rejects_timeout(self) -> None:
        with mock.patch.object(
            manager.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["security"], 1),
        ):
            with self.assertRaisesRegex(manager.ProfileError, "execution failed"):
                manager._bounded_run(["/usr/bin/security", "cms"])

    def test_bounded_run_uses_sanitized_tool_environment(self) -> None:
        captured: dict[str, object] = {}

        def fake_run(_argv, **kwargs):
            captured.update(kwargs)
            return subprocess.CompletedProcess(["tool"], 0)

        with mock.patch.object(manager.subprocess, "run", side_effect=fake_run):
            manager._bounded_run(["/usr/bin/security", "cms"])
        environment = captured["env"]
        self.assertEqual(
            set(environment),
            {"HOME", "LANG", "LC_ALL", "PATH"},
        )
        self.assertNotIn("OPENSSL_CONF", environment)

    def test_guarded_check_fails_closed_without_traceback(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(
            manager, "check_profiles", side_effect=manager.ProfileError("hostile profile")
        ), contextlib.redirect_stderr(stderr):
            self.assertFalse(
                manager.guarded_check_profiles(
                    [], install=False, quiet=True, require_macos=False
                )
            )
        self.assertIn("hostile profile", stderr.getvalue())

    def test_install_is_not_attempted_without_matching_keychain_identity(self) -> None:
        profiles = [
            manager.make_fake_profile(bundle_id=manager.IOS_BUNDLE_ID, name="App"),
            manager.make_fake_profile(
                bundle_id=manager.IOS_PACKET_TUNNEL_BUNDLE_ID, name="Tunnel"
            ),
            manager.make_fake_profile(
                bundle_id=manager.WATCHOS_BUNDLE_ID,
                name="Watch",
                has_packet_tunnel=False,
                has_ios_app_group=False,
                has_shared_keychain_group=False,
            ),
        ]
        stderr = io.StringIO()
        with mock.patch.object(manager, "discover_profiles", return_value=profiles), mock.patch.object(
            manager, "list_codesigning_identities", return_value=[]
        ), mock.patch.object(manager, "install_profiles") as install_mock, contextlib.redirect_stderr(
            stderr
        ), contextlib.redirect_stdout(io.StringIO()):
            ready = manager.check_profiles(
                [], install=True, quiet=True, require_macos=False
            )
        self.assertFalse(ready)
        install_mock.assert_not_called()
        self.assertIn("Refusing to install", stderr.getvalue())

    def test_install_cannot_disable_identity_custody(self) -> None:
        with self.assertRaisesRegex(manager.ProfileError, "cannot bypass"):
            manager.check_profiles(
                [],
                install=True,
                quiet=True,
                require_macos=False,
                require_signing_identity=False,
            )

    def test_selftest_still_passes(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(manager.run_selftest(), 0)
        self.assertIn("self-test passed", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
