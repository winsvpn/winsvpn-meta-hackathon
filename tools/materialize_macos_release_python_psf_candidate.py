#!/usr/bin/env python3
"""Materialize and audit a macOS 13 ReleasePython candidate without privilege.

This producer never rewrites Mach-O load commands or signatures. If the pinned
PSF package or wheels are not already compliant, it emits a complete violation
report and exits 3. Rewriting would invalidate the PSF signature and must not be
misrepresented as a PSF-produced runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PINS = ROOT / "tools" / "toolchain-pins.json"
MANIFEST = ROOT / "tools" / "macos_release_python_inputs.custody.json"
INSTALLER = ROOT / "tools" / "install_macos_release_python_inputs.py"
WRAPPER = ROOT / "tools" / "release_python_archive_custody.sh"
EXPECTED_PACKAGE_SHA256 = "70c5239ad2d62925d2947e46921d0ddd3d35be3d2f0a2d50db33da507dbcb419"
EXPECTED_BUNDLE_SHA256 = "c8e8af7129581634031508dbbf4831b0436e11716796d85eccb08f305664dd6b"
PSF_INSTALLER = "Developer ID Installer: Python Software Foundation (BMM5U3QVKW)"
PSF_APPLICATION = "Developer ID Application: Python Software Foundation (BMM5U3QVKW)"


class ProducerError(RuntimeError):
    pass


def run(argv: list[str], *, maximum: int = 1024 * 1024) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=180,
    )
    if len(completed.stdout) > maximum or len(completed.stderr) > maximum:
        raise ProducerError(f"command output exceeded its limit: {argv[0]}")
    return completed


def require_ok(completed: subprocess.CompletedProcess[bytes], label: str) -> str:
    output = (completed.stdout + completed.stderr).decode("utf-8", "replace")
    if completed.returncode != 0:
        raise ProducerError(f"{label} failed: {output.strip()[:1000]}")
    return output


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def local_pins(source: Path) -> bytes:
    document = json.loads(PINS.read_text(encoding="ascii"))
    custody = document["tools"]["python"]["archive_custody"]["darwin_arm64"]
    for key in ("package", "sigstore_bundle", "sigstore_trusted_root", "sigstore_verifier"):
        custody[key]["path"] = str(source / Path(custody[key]["path"]).name)
    for index in range(custody["wheel_count"]):
        record = custody["wheels"][str(index)]
        record["path"] = str(source / Path(record["path"]).name)
    return (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("ascii")


def parse_load_commands(path: Path) -> tuple[list[str], list[str]]:
    output = require_ok(run(["/usr/bin/otool", "-l", str(path)]), f"otool {path}")
    lines = output.splitlines()
    minimums: list[str] = []
    rpaths: list[str] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped in {"cmd LC_BUILD_VERSION", "cmd LC_VERSION_MIN_MACOSX"}:
            field = "minos" if stripped.endswith("BUILD_VERSION") else "version"
            for candidate in lines[index + 1 : index + 12]:
                parts = candidate.strip().split()
                if len(parts) == 2 and parts[0] == field:
                    minimums.append(parts[1])
                    break
        elif stripped == "cmd LC_RPATH":
            for candidate in lines[index + 1 : index + 8]:
                parts = candidate.strip().split()
                if len(parts) >= 2 and parts[0] == "path":
                    rpaths.append(parts[1])
                    break
    return minimums, rpaths


def audit_runtime(candidate: Path) -> tuple[list[dict[str, object]], dict[str, object]]:
    expected_children = {"Python.framework", "vendor", "launcher"}
    if {path.name for path in candidate.iterdir()} != expected_children:
        raise ProducerError("candidate root children are not exact")
    interpreter = candidate / "Python.framework/Versions/3.14/bin/python3.14"
    if not interpreter.is_file() or interpreter.is_symlink():
        raise ProducerError("candidate interpreter is unavailable")
    interpreter_kind = require_ok(run(["/usr/bin/file", "-b", str(interpreter)]), "file interpreter")
    violations: list[dict[str, object]] = []
    macho_count = 0
    minimum_counts: dict[str, int] = {}
    for path in sorted(candidate.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        kind = require_ok(run(["/usr/bin/file", "-b", str(path)]), f"file {path}")
        if "Mach-O" not in kind:
            continue
        macho_count += 1
        relative = str(path.relative_to(candidate))
        minimums, rpaths = parse_load_commands(path)
        for minimum in minimums:
            minimum_counts[minimum] = minimum_counts.get(minimum, 0) + 1
        if not minimums or any(minimum != "13.0" for minimum in minimums):
            violations.append(
                {"kind": "minimum-macos", "minimums": minimums, "path": relative}
            )
        if rpaths:
            violations.append({"kind": "lc-rpath", "paths": rpaths, "path": relative})
        signature = run(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures", str(path)])
        if signature.returncode != 0:
            violations.append({"kind": "static-signature", "path": relative})
    if "universal binary" not in interpreter_kind or not all(
        architecture in interpreter_kind for architecture in ("x86_64", "arm64")
    ):
        violations.append(
            {"kind": "interpreter-architecture", "reported": interpreter_kind.strip()}
        )
    return violations, {
        "interpreter_file": interpreter_kind.strip(),
        "macho_count": macho_count,
        "minimum_macos_counts": dict(sorted(minimum_counts.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("work", type=Path)
    args = parser.parse_args()
    try:
        if sys.platform != "darwin" or os.uname().machine != "arm64" or os.geteuid() == 0:
            raise ProducerError("producer requires a non-root Apple-silicon macOS host")
        if (
            not args.source.is_absolute()
            or not args.work.is_absolute()
            or args.source.is_symlink()
            or args.work.is_symlink()
        ):
            raise ProducerError("source and work must be absolute non-symlink paths")
        source = args.source.resolve(strict=True)
        work = args.work.resolve(strict=True)
        if any(work.iterdir()):
            raise ProducerError("source must be real and work must be one empty directory")
        preflight = require_ok(
            run([sys.executable, "-I", "-S", str(INSTALLER), "preflight", str(source), str(MANIFEST)]),
            "input custody preflight",
        )
        package = source / "python-3.14.7-macos11.pkg"
        bundle = source / "python-3.14.7-macos11.pkg.sigstore"
        trusted_root = source / "trusted_root.json"
        verifier = source / "cosign"
        if sha256(package) != EXPECTED_PACKAGE_SHA256 or sha256(bundle) != EXPECTED_BUNDLE_SHA256:
            raise ProducerError("package or Sigstore bundle digest is not exact")
        signature = require_ok(run(["/usr/sbin/pkgutil", "--check-signature", str(package)]), "pkgutil signature")
        if PSF_INSTALLER not in signature or "Notarization: trusted" not in signature:
            raise ProducerError("package is not the notarized PSF installer")
        sigstore = require_ok(
            run(
                [
                    str(verifier), "verify-blob", "--bundle", str(bundle),
                    "--trusted-root", str(trusted_root), "--certificate-identity",
                    "hugo@python.org", "--certificate-oidc-issuer",
                    "https://github.com/login/oauth", "--offline=true",
                    "--max-workers=1", str(package),
                ]
            ),
            "offline Sigstore verification",
        )
        pins = work / "toolchain-pins.local.json"
        pins.write_bytes(local_pins(source))
        pins.chmod(0o444)
        candidate = work / "candidate"
        candidate.mkdir(mode=0o700)
        command = (
            "source \"$1\" && "
            "wins_release_python_materialize_unsealed \"$2\" \"$3\""
        )
        require_ok(
            run(["/bin/bash", "-c", command, "producer", str(WRAPPER), str(candidate), str(pins)], maximum=4 * 1024 * 1024),
            "runtime materialization",
        )
        violations, summary = audit_runtime(candidate)
        evidence = {
            "candidate": str(candidate),
            "input_manifest_sha256": sha256(MANIFEST),
            "package_sha256": sha256(package),
            "package_signature_identity": PSF_INSTALLER,
            "preflight": preflight.strip(),
            "sigstore": sigstore.strip().splitlines()[-1],
            **summary,
        }
        (work / "producer-evidence.json").write_text(
            json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="ascii"
        )
        (work / "native-policy-violations.json").write_text(
            json.dumps(violations, sort_keys=True, indent=2) + "\n", encoding="ascii"
        )
        if violations:
            print(
                "ReleasePython producer: STOP: pinned PSF inputs violate the exact "
                f"macOS 13 policy ({len(violations)} violations)",
                file=sys.stderr,
            )
            return 3
        app = candidate / "Python.framework/Versions/3.14/Resources/Python.app"
        gatekeeper = require_ok(
            run(["/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=4", str(app)]),
            "Python.app Gatekeeper assessment",
        )
        codesign = require_ok(run(["/usr/bin/codesign", "-dvv", str(app)]), "Python.app codesign")
        if PSF_APPLICATION not in codesign + gatekeeper:
            raise ProducerError("candidate Python.app is not bound to the PSF application identity")
        print(f"ReleasePython producer: PASS: unsealed candidate at {candidate}")
        return 0
    except (OSError, ValueError, ProducerError, subprocess.TimeoutExpired) as exc:
        print(f"ReleasePython producer: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
