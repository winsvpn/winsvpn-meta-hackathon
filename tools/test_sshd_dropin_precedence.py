#!/usr/bin/env python3
"""Focused regression tests for one-touch OpenSSH drop-in precedence.

OpenSSH generally keeps the first value obtained for scalar options. Ubuntu's
50-cloud-init.conf therefore overrides a later 99-* file even though the later
name looks more authoritative. These tests keep the installers on an early
drop-in, exercise first-value resolution with conflicting provider defaults,
and statically require transactional rollback plus effective-config checks.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
ROLES = {
    "control": {
        "path": ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh",
        "function": "harden_control_sshd",
        "early": "20-winsvpn-hub.conf",
        "legacy": "99-winsvpn-hub.conf",
        "rollback": "rollback_control_sshd_dropins",
    },
    "data": {
        "path": ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh",
        "function": "harden_sshd",
        "early": "20-winsvpn-node.conf",
        "legacy": "99-winsvpn-node.conf",
        "rollback": "rollback_data_sshd_dropins",
    },
    "core": {
        "path": ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh",
        "function": "harden_sshd",
        "early": "20-wins-core.conf",
        "legacy": "99-wins-core.conf",
        "rollback": "rollback_core_sshd_dropins",
    },
}


def function_body(source: str, name: str) -> str:
    marker = f"{name}() {{"
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"missing function {name}")
    next_start = source.find("\n}", start)
    while next_start >= 0:
        candidate = source[start : next_start + 2]
        if candidate.count("{") == candidate.count("}"):
            return candidate
        next_start = source.find("\n}", next_start + 2)
    raise AssertionError(f"unterminated function {name}")


def read_first_values(config_dir: pathlib.Path) -> dict[str, str]:
    """Small executable model of sshd's first-obtained scalar behavior."""
    values: dict[str, str] = {}
    for path in sorted(config_dir.glob("*.conf"), key=lambda item: item.name):
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            option, value = line.split(None, 1)
            values.setdefault(option.lower(), value.strip().lower())
    return values


class SshdDropInPrecedenceTests(unittest.TestCase):
    def test_installers_use_early_transactional_dropins(self) -> None:
        for role, spec in ROLES.items():
            with self.subTest(role=role):
                source = spec["path"].read_text(encoding="utf-8")
                body = function_body(source, str(spec["function"]))
                self.assertLess("10-winsvpn-recovery.conf", str(spec["early"]))
                self.assertLess(str(spec["early"]), "50-cloud-init.conf")
                self.assertIn(f'/etc/ssh/sshd_config.d/{spec["early"]}', body)
                self.assertIn(f'/etc/ssh/sshd_config.d/{spec["legacy"]}', body)
                self.assertIn('/etc/ssh/sshd_config.d/10-winsvpn-recovery.conf', body)
                self.assertIn('cp -a -- "${legacy_config}" "${backup_dir}/legacy"', body)
                self.assertIn('cp -a -- "${recovery_config}" "${backup_dir}/recovery"', body)
                self.assertIn('rm -f -- "${legacy_config}"', body)
                self.assertIn('rm -f -- "${recovery_config}"', body)
                self.assertGreaterEqual(body.count(str(spec["rollback"])), 3)
                self.assertIn("sshd -t", body)
                self.assertIn("sshd -T -C", body)
                self.assertIn("sshd_effective_value_is", body)
                self.assertIn("systemctl reload ssh", body)
                self.assertNotIn("systemctl restart ssh", body)

    def test_effective_policy_beats_conflicting_cloud_init(self) -> None:
        policies = {
            "control-key": {
                "permitrootlogin": "prohibit-password",
                "passwordauthentication": "no",
                "kbdinteractiveauthentication": "no",
                "pubkeyauthentication": "yes",
                "allowtcpforwarding": "remote",
            },
            "control-recovery": {
                "permitrootlogin": "yes",
                "passwordauthentication": "yes",
                "kbdinteractiveauthentication": "no",
                "pubkeyauthentication": "yes",
                "allowtcpforwarding": "remote",
            },
            "data": {
                "permitrootlogin": "prohibit-password",
                "passwordauthentication": "no",
                "kbdinteractiveauthentication": "no",
                "pubkeyauthentication": "yes",
                "allowtcpforwarding": "no",
            },
            "core-key": {
                "permitrootlogin": "no",
                "passwordauthentication": "no",
                "kbdinteractiveauthentication": "no",
                "pubkeyauthentication": "yes",
                "allowtcpforwarding": "no",
            },
            "core-recovery": {
                "permitrootlogin": "no",
                "passwordauthentication": "yes",
                "kbdinteractiveauthentication": "yes",
                "pubkeyauthentication": "yes",
                "allowtcpforwarding": "no",
            },
        }
        conflicting_provider = {
            "permitrootlogin": "yes",
            "passwordauthentication": "yes",
            "kbdinteractiveauthentication": "yes",
            "pubkeyauthentication": "no",
            "allowtcpforwarding": "yes",
        }
        with tempfile.TemporaryDirectory(prefix="wins-sshd-precedence-") as temp:
            config_dir = pathlib.Path(temp)
            for name, policy in policies.items():
                with self.subTest(policy=name):
                    for old in config_dir.glob("*.conf"):
                        old.unlink()
                    (config_dir / "20-winsvpn-test.conf").write_text(
                        "\n".join(f"{key} {value}" for key, value in policy.items()) + "\n",
                        encoding="utf-8",
                    )
                    (config_dir / "50-cloud-init.conf").write_text(
                        "\n".join(
                            f"{key} {value}" for key, value in conflicting_provider.items()
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    effective = read_first_values(config_dir)
                    self.assertEqual(policy, {key: effective[key] for key in policy})

    def test_late_legacy_dropin_reproduces_original_bug(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-sshd-legacy-") as temp:
            config_dir = pathlib.Path(temp)
            (config_dir / "50-cloud-init.conf").write_text(
                "PasswordAuthentication yes\n", encoding="utf-8"
            )
            (config_dir / "99-winsvpn-node.conf").write_text(
                "PasswordAuthentication no\n", encoding="utf-8"
            )
            self.assertEqual(
                "yes", read_first_values(config_dir)["passwordauthentication"]
            )

    def test_emergency_recovery_remains_ahead_of_role_policy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-sshd-recovery-") as temp:
            config_dir = pathlib.Path(temp)
            (config_dir / "10-winsvpn-recovery.conf").write_text(
                "PasswordAuthentication yes\n", encoding="utf-8"
            )
            (config_dir / "20-winsvpn-role.conf").write_text(
                "PasswordAuthentication no\n", encoding="utf-8"
            )
            (config_dir / "50-cloud-init.conf").write_text(
                "PasswordAuthentication no\n", encoding="utf-8"
            )
            self.assertEqual(
                "yes", read_first_values(config_dir)["passwordauthentication"]
            )

    def test_recovery_helpers_install_the_reserved_early_file(self) -> None:
        recovery_helpers = (
            ROOT / "tools" / "recover_home_core_ssh.sh",
            ROOT / "tools" / "recover_ionos_hub_ssh.sh",
        )
        for helper in recovery_helpers:
            with self.subTest(helper=helper.name):
                source = helper.read_text(encoding="utf-8")
                self.assertIn(
                    "/etc/ssh/sshd_config.d/10-winsvpn-recovery.conf", source
                )

    def test_real_sshd_keeps_first_scalar_values_when_available(self) -> None:
        # WSL commonly inherits Windows system paths.  Do not fall back to a PE
        # sshd.exe from a Linux test process: it cannot be executed as the
        # native daemon and turns an optional integration check into an
        # environment-dependent Exec format error.
        executable_suffix = ".exe" if os.name == "nt" else ""
        sshd = shutil.which(f"sshd{executable_suffix}")
        ssh_keygen = shutil.which(f"ssh-keygen{executable_suffix}")
        if not sshd or not ssh_keygen:
            self.skipTest("OpenSSH server/client tools are not installed")
        with tempfile.TemporaryDirectory(prefix="wins-real-sshd-") as temp:
            root = pathlib.Path(temp)
            dropins = root / "sshd_config.d"
            dropins.mkdir()
            host_key = root / "ssh_host_ed25519_key"
            key_result = subprocess.run(
                [ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            self.assertEqual(0, key_result.returncode, key_result.stdout)
            (dropins / "20-winsvpn-test.conf").write_text(
                "PermitRootLogin no\n"
                "PasswordAuthentication no\n"
                "KbdInteractiveAuthentication no\n"
                "PubkeyAuthentication yes\n"
                "AllowTcpForwarding no\n"
                "DisableForwarding yes\n"
                "AllowUsers root support\n",
                encoding="utf-8",
            )
            (dropins / "50-cloud-init.conf").write_text(
                "PermitRootLogin yes\n"
                "PasswordAuthentication yes\n"
                "KbdInteractiveAuthentication yes\n"
                "PubkeyAuthentication no\n"
                "AllowTcpForwarding yes\n",
                encoding="utf-8",
            )
            main_config = root / "sshd_config"
            main_config.write_text(
                (dropins / "20-winsvpn-test.conf").read_text(encoding="utf-8")
                + (dropins / "50-cloud-init.conf").read_text(encoding="utf-8")
                + f'HostKey "{host_key.as_posix()}"\n'
                + f'PidFile "{(root / "sshd.pid").as_posix()}"\n',
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sshd,
                    "-T",
                    "-f",
                    str(main_config),
                    "-C",
                    "user=root,host=localhost,addr=127.0.0.1",
                ],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            self.assertEqual(0, result.returncode, result.stdout)
            effective: dict[str, list[str]] = {}
            for line in result.stdout.splitlines():
                if " " in line:
                    option, value = line.split(None, 1)
                    effective.setdefault(option.lower(), []).append(value.strip().lower())
            joined = {key: " ".join(values) for key, values in effective.items()}
            self.assertEqual("no", joined.get("permitrootlogin"), result.stdout)
            self.assertEqual("no", joined.get("passwordauthentication"), result.stdout)
            self.assertEqual("no", joined.get("kbdinteractiveauthentication"), result.stdout)
            self.assertEqual("yes", joined.get("pubkeyauthentication"), result.stdout)
            self.assertEqual("no", joined.get("allowtcpforwarding"), result.stdout)
            self.assertEqual("yes", joined.get("disableforwarding"), result.stdout)
            self.assertEqual("root support", joined.get("allowusers"), result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
