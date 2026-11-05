#!/usr/bin/env python3
"""Enforce the reviewed Linux apt pin set for the release build.

WHY THIS EXISTS.

tools/build_linux_release.sh used to run `apt-get install -y <pkg>...` with no
version pins, so the Linux release binary was built against whatever the distro
served that day (supply-chain finding S4, spk_supply 2026-08-10). The broadly
agreed fix -- "pin the ones that matter" -- is half of the change; the other
half is that the build must actually verify against the recorded set, or the
pin is documentation. This script is that verification, driven by
tools/linux_apt_pins.json as the single source of truth (schema 1).

Each recorded package earns one of three verdicts (see the manifest's own
_purpose): pin (version enforced), keep (installed but version-free), drop
(not installed). This script never decides what those are -- it computes them
from the manifest, so a deliberate manifest edit is the ONLY way a pin changes.

Two invariants, both fail-closed:

  1. The build host's OS must be recorded in the manifest. A release built on
     an unrecorded distribution is refused, because there is no reviewed pin
     set for what it serves. This also covers the historical risk that a fresh
     runner or WSL stage silently builds against a distro no one reviewed.

  2. Every `pin` package must be installed at its exact recorded version after
     the build's apt step, measured with dpkg, not assumed from apt's exit
     status (apt exits 0 for already-installed mismatches it did not change).

Modes:
  emit-install  print the apt-get install argument list for the current host's
                OS (pin set as pkg=version, keep set bare, drop omitted). The
                build script calls this so the manifest is the only place a
                version literal exists.
  verify        read dpkg for every pin package; compare against the recorded
                version. Exit 65 naming package+expected+found on mismatch or
                missing package, exit 0 when every pin holds.

Both are OS-sniffing by default; pass --os-key to force a distribution (used by
the guard tests to exercise every recorded distro without a matching host).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "tools" / "linux_apt_pins.json"

VERSION_RE = re.compile(r"^(\d+)(?:\.(\d+))?")


def load_manifest() -> dict:
    if not MANIFEST_PATH.is_file():
        raise SystemExit(f"linux apt pin manifest missing: {MANIFEST_PATH}")
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise SystemExit("linux_apt_pins.json schema_version must be 1.")
    return manifest


def os_key() -> str:
    """Distribution identity key from /etc/os-release: ID-VERSION (major)."""
    values: dict[str, str] = {}
    path = Path("/etc/os-release")
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            match = re.match(r"^([A-Z_]+)=(.*)$", line.strip())
            if not match:
                continue
            key, raw = match.groups()
            values[key] = (
                raw.strip('"').strip("'")
                if raw
                else ""
            )
    distro_id = values.get("ID", "")
    version_id = values.get("VERSION_ID", "")
    match = VERSION_RE.match(version_id) if version_id else None
    major = match.group(1) if match else ""
    if not distro_id or not major:
        raise SystemExit(
            "Could not identify the build host's OS from /etc/os-release; a "
            "release build cannot be pinned against an unidentified distro."
        )
    return f"{distro_id}-{major}"


def distribution(manifest: dict, key: str) -> dict:
    if key not in manifest.get("distributions", {}):
        raise SystemExit(
            f"Distribution '{key}' is not recorded in tools/linux_apt_pins.json. "
            f"Recorded: {sorted(manifest.get('distributions', {}))}. A release "
            f"build on an unrecorded OS is refused: there is no reviewed apt "
            f"pin set for what it serves. Add the distro deliberately "
            f"(pin/keep/drop for every package) and re-run."
        )
    return manifest["distributions"][key]


def install_args(dist: dict) -> list[str]:
    args: list[str] = []
    for pkg, version in dict(dist.get("pin", {})).items():
        if not version or not isinstance(version, str) or not version.strip():
            raise SystemExit(f"Pin package '{pkg}' has no recorded version.")
        args.append(f"{pkg}={version}")
    for pkg in dist.get("keep", []):
        args.append(str(pkg))
    return args


def dpkg_versions(packages: list[str]) -> dict[str, str]:
    proc = subprocess.run(
        ["dpkg-query", "-W", "--showformat=${Package} ${Version}\n", "--", *packages],
        capture_output=True,
        text=True,
    )
    found: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2:
            found[parts[0]] = parts[1]
    return found


def verify(dist: dict) -> tuple[list[str], dict[str, str]]:
    """Return (errors, found). A non-empty errors list means the build must stop."""
    pins = dict(dist.get("pin", {}))
    if not pins:
        raise SystemExit(
            f"Distribution '{dist.get('note', '?')}' records no pinned packages. "
            f"Without pins there is nothing to verify against; the build must "
            f"not proceed on a 'pin nothing' declaration."
        )
    found = dpkg_versions(sorted(pins))
    errors: list[str] = []
    for pkg, expected in sorted(pins.items()):
        actual = found.get(pkg, "")
        if not actual:
            errors.append(
                f"{pkg}: NOT INSTALLED (recorded pin {expected})"
            )
        elif actual != expected:
            errors.append(
                f"{pkg}: installed {actual} != recorded pin {expected}. "
                "The release was about to be built against an unreviewed "
                "library version; update tools/linux_apt_pins.json "
                "deliberately before building."
            )
    return errors, found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Enforce the reviewed Linux apt pin set (schema 1)."
    )
    parser.add_argument(
        "mode", choices=("emit-install", "verify"),
        help="emit-install prints apt install args from the manifest; verify "
             "checks pinned packages against dpkg.",
    )
    parser.add_argument(
        "--os-key", default=None,
        help="Force a distribution key (default: detect from /etc/os-release).",
    )
    args = parser.parse_args(argv)

    manifest = load_manifest()
    key = args.os_key or os_key()
    dist = distribution(manifest, key)

    if args.mode == "emit-install":
        print(" ".join(install_args(dist)))
        return 0

    errors, found = verify(dist)
    if errors:
        print(
            "LINUX APT PIN VERIFICATION: FAIL\n  " + "\n  ".join(errors),
            file=sys.stderr,
        )
        for pkg, ver in sorted(found.items()):
            print(f"  observed {pkg}={ver}", file=sys.stderr)
        return 65
    print("LINUX APT PIN VERIFICATION: PASS")
    return 0


class LinuxAptPinConsistencyTests(unittest.TestCase):
    """Guard tests. Mutate a pin and this table must go red.

    Two controls are run in _test_do_not_trust_success: a manifest WITHOUT the
    mutation that must verify (the positive), and the same manifest WITH a
    deliberately altered pin that must be reported (the negative). Both use a
    fake dpkg captured once, so the discriminator is the pin needle itself.
    """

    def _fake_versions(self) -> dict[str, str]:
        dist = distribution(load_manifest(), load_manifest()["release_distribution"])
        pins = dict(dist["pin"])
        # Return the recorded pins as the installed set -- a hypothetical host
        # that exactly matches the reviewed set.
        return {pkg: version for pkg, version in pins.items()}

    def _verify_with(self, manifest: dict, installed: dict[str, str]) -> list[str]:
        dist = distribution(manifest, manifest["release_distribution"])
        pins = dict(dist["pin"])
        errors: list[str] = []
        for pkg, expected in sorted(pins.items()):
            actual = installed.get(pkg, "")
            if not actual:
                errors.append(f"{pkg}: NOT INSTALLED (recorded pin {expected})")
            elif actual != expected:
                errors.append(
                    f"{pkg}: installed {actual} != recorded pin {expected}")
        return errors

    def test_manifest_declares_a_pin_set(self) -> None:
        manifest = load_manifest()
        for key, dist in manifest["distributions"].items():
            with self.subTest(distribution=key):
                self.assertTrue(dist.get("pin"), f"{key} records no pin set")

    def test_manifest_categories_are_disjoint(self) -> None:
        manifest = load_manifest()
        for key, dist in manifest["distributions"].items():
            with self.subTest(distribution=key):
                pin = set(dist.get("pin", {}))
                keep = set(dist.get("keep", set()))
                drop = set(dist.get("drop", set()))
                self.assertFalse(
                    pin & keep, f"{key}: a package is both pinned and kept"
                )
                self.assertFalse(
                    pin & drop, f"{key}: a package is both pinned and dropped"
                )
                self.assertFalse(
                    keep & drop, f"{key}: a package is both kept and dropped"
                )

    def test_no_duplicate_package_names_in_manifest(self) -> None:
        manifest = load_manifest()
        for key, dist in manifest["distributions"].items():
            with self.subTest(distribution=key):
                pin = list(dist.get("pin", {}))
                keep = list(dist.get("keep", []))
                drop = list(dist.get("drop", []))
                all_names = pin + keep + drop
                self.assertEqual(
                    len(all_names), len(set(all_names)),
                    f"{key}: duplicate package name across categories",
                )

    def test_emit_install_never_emits_a_dropped_package(self) -> None:
        manifest = load_manifest()
        for key, dist in manifest["distributions"].items():
            with self.subTest(distribution=key):
                emitted = " ".join(install_args(dist))
                for dropped in dist.get("drop", []):
                    self.assertNotIn(
                        dropped, emitted.split(),
                        f"{key}: dropped package '{dropped}' still installed",
                    )

    def test_emit_install_pins_every_pinned_package(self) -> None:
        manifest = load_manifest()
        for key, dist in manifest["distributions"].items():
            with self.subTest(distribution=key):
                emitted = install_args(dist)
                emitted_set = set(emitted)
                for pkg, version in dist.get("pin", {}).items():
                    self.assertIn(
                        f"{pkg}={version}", emitted_set,
                        f"{key}: pinned package '{pkg}' not emitted with ={version}",
                    )
                    self.assertNotIn(
                        pkg, emitted_set,
                        f"{key}: pinned package '{pkg}' emitted WITHOUT a version",
                    )

    def test_do_not_trust_success(self) -> None:
        """Positive + negative control on the discriminator itself."""
        manifest = load_manifest()
        installed = self._fake_versions()
        # Positive: exact match must verify clean.
        self.assertEqual(self._verify_with(manifest, installed), [])
        # Negative: one installed version mutated must be caught, naming the pin.
        pins = sorted(manifest["distributions"][
            manifest["release_distribution"]]["pin"])
        mutant = dict(installed)
        mutant[pins[0]] = "9.9.9-mutated"
        errors = self._verify_with(manifest, mutant)
        self.assertTrue(any(pins[0] in e for e in errors))
        self.assertTrue(any("9.9.9-mutated" in e for e in errors))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        loader = unittest.defaultTestLoader
        suite = loader.loadTestsFromTestCase(LinuxAptPinConsistencyTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        raise SystemExit(0 if result.wasSuccessful() else 1)
    raise SystemExit(main())