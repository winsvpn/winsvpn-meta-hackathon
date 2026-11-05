#!/usr/bin/env python3
"""Release gate: shipped Windows/Android/Apple embedded Go engines must
embed the exact reviewed Go toolchain.

Owner latest-stable policy, discovered 2026-10-06: official go.dev lists
Go 1.27.1 as the current stable release (released 2026-09-01;
https://go.dev/dl/ and https://go.dev/doc/devel/release). This gate
requires that exact version in every inspected Windows, Android, and Apple
embedded Go engine. It rejects older patch releases (including 1.27.0,
1.26.5 and 1.25.12), newer unreviewed patches (including 1.27.2),
prereleases (including 1.27rc), missing version strings, and malformed
tokens.

This script does NOT rebuild anything. It only inspects the Go build
version already baked into the binaries that are committed/vendored in
this tree, plus any Apple libwg-go.a slices already on disk, and fails the
gate if any of them are not exactly go1.27.1. Actually producing a newer
binary (rebuilding Xray-core / amneziawg-go from source with a current Go
toolchain, or pulling a newer upstream release) is a separate, tracked
build action -- see docs/RELEASE_ENGINE_BINARY_REFRESH.md.

The Apple WireGuard/Xray Go bridge slices (produced by
tools/build_apple_wg_go_bridge.sh, default output under
.artifacts/apple-wg-go/<platform>/libwg-go.a) are the one exception to
"committed/vendored": they are gitignored build output, not a file checked
into the repo, so this gate only checks whichever of the three platform
slices already exist on disk instead of requiring all of them
unconditionally -- see _apple_wg_go_bridge_candidates(). That build script
calls this gate itself immediately after producing all three slices, when
they are guaranteed to be present, which is what actually enforces this
check for Apple releases.

Official go.dev documents macOS 13 Ventura or later for Go 1.27
(https://go.dev/doc/go1.27). WinsVPN also uses macOS 13 as the Apple app
deployment floor. That floor remains project policy even though it matches
the current Go toolchain minimum. This gate checks the embedded Go version,
not LC_BUILD_VERSION.

Historical CVE facts below were independently verified against
https://pkg.go.dev/vuln/ and https://go.dev/doc/devel/release on
2026-07-22 (queried directly, not copied from any AI-generated report).
They explain why the 2026-07-24 rebuild happened. They are NOT the
current acceptance criteria:

  - GO-2026-4866 / CVE-2026-33810  crypto/x509 DNS-constraint bypass   -> fixed 1.26.2
  - GO-2026-4870 / CVE-2026-32283  crypto/tls KeyUpdate DoS            -> fixed 1.25.9  / 1.26.2
  - GO-2026-4981 / CVE-2026-33811  net cgo resolver double-free        -> fixed 1.25.10 / 1.26.3
  - GO-2026-5037 / CVE-2026-27145  crypto/x509 VerifyHostname DoS      -> fixed 1.25.11 / 1.26.4
  - Go 1.26.5 / 1.25.12 (2026-07-07 golang-announce) additionally fix an
    os.Root symlink escape (CVE-2026-39822) and a TLS ECH privacy leak
    (CVE-2026-42505). Reachability from Xray/AmneziaWG's own code paths is
    not proven for every symbol.

On 2026-07-22 those 1.26.5 and 1.25.12 builds were the then-current patch
releases on their branches. They are no longer latest stable and are not
accepted for shipped engines.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REVIEWED_GO = (1, 27, 1)
REVIEWED_GO_VERSION = "1.27.1"
REVIEWED_GO_DISCOVERY_DATE = "2026-10-06"
OFFICIAL_GO_MACOS_MINIMUM = "13"
WINSVPN_MACOS_APP_DEPLOYMENT_FLOOR = "13"
APPLE_AWG_31_REVIEWED_GO = REVIEWED_GO
WINDOWS_AMNEZIAWG_SHA256 = (
    "12525f397d957659354df03ac1e9568170d8842aa8fa0d16942d8a59d7307d41"
)
WINDOWS_AMNEZIAWG_SOURCE_COMMIT = "ca5dd3b983bd19c335ab095ccd21fc2f804ec968"
WINDOWS_AMNEZIAWG_GO_ARCHIVE_SHA256 = (
    "a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d"
)
WINDOWS_REVIEWED_GO_VERSION = REVIEWED_GO_VERSION

# Exact go1.MAJOR.PATCH with no prerelease suffix. go1.27, go1.27rc,
# go1.27.1rc1, and go1.27.1.1 must not parse as go1.27.1.
_GO_VERSION_TOKEN_RE = re.compile(r"(?:^|[\s:\x00])go1\.(\d+)\.(\d+)(?=$|[\s:\x00])")
_PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e]{6,}")


@dataclass(frozen=True)
class EngineBinary:
    label: str
    path: Path
    minimum: tuple[int, int, int]
    note: str
    requires_exact_go_version: bool = True


def _apple_wg_go_bridge_candidates() -> list[EngineBinary]:
    # tools/build_apple_wg_go_bridge.sh writes one universal (lipo -create)
    # static archive per Apple platform slice here -- default
    # APPLE_WG_GO_OUTPUT_DIR is ".artifacts/apple-wg-go/<platform>/libwg-go.a"
    # for platform in {macosx, iphoneos, iphonesimulator}. Unlike the
    # Windows/Android entries below, this is gitignored build output, not a
    # binary committed to the repo, so -- like the Android jniLibs loop
    # below -- only check slices that actually exist on disk: every other
    # caller of this gate (Windows/Linux/Android release scripts, and
    # build_apple_release_candidates.sh's begin_receipts, which runs before
    # this builder does) has no reason to have ever produced an Apple build
    # and must not fail over an artifact it was never going to make.
    # build_apple_wg_go_bridge.sh itself calls this gate immediately after
    # building all three slices, when they are guaranteed to be present --
    # see run_embedded_runtime_gate() there.
    apple_output_dir = ROOT / ".artifacts" / "apple-wg-go"
    candidates: list[EngineBinary] = []
    for platform in ("macosx", "iphoneos", "iphonesimulator"):
        archive = apple_output_dir / platform / "libwg-go.a"
        if archive.is_file():
            candidates.append(
                EngineBinary(
                    f"Apple WireGuard/Xray Go bridge ({archive.relative_to(ROOT)})",
                    archive,
                    APPLE_AWG_31_REVIEWED_GO,
                    "built from source by tools/build_apple_wg_go_bridge.sh -- rebuild it "
                    "(bump REVIEWED_GO_VERSION there, and the matching exact-version policy "
                    "here, only "
                    "after independently re-verifying the new release's official hashes). "
                    f"Official go.dev requires macOS {OFFICIAL_GO_MACOS_MINIMUM} or later "
                    f"for Go {REVIEWED_GO_VERSION}; WinsVPN also uses macOS "
                    f"{WINSVPN_MACOS_APP_DEPLOYMENT_FLOOR} as the app deployment floor.",
                    requires_exact_go_version=True,
                )
            )
    return candidates


def _candidate_engine_binaries() -> list[EngineBinary]:
    candidates = [
        EngineBinary(
            "Windows Xray (installer/windows/dependencies/xray.exe)",
            ROOT / "installer" / "windows" / "dependencies" / "xray.exe",
            REVIEWED_GO,
            "vendored prebuilt binary -- needs a refreshed upstream/rebuilt artifact",
        ),
        EngineBinary(
            "Windows AmneziaWG maintenance helper "
            "(installer/windows/dependencies/amneziawg.exe)",
            ROOT / "installer" / "windows" / "dependencies" / "amneziawg.exe",
            REVIEWED_GO,
            "source-rebuilt by tools/build_windows_amneziawg_client.ps1; the exact "
            "unsigned artifact/provenance are pinned and the Windows release producer "
            "must Authenticode-sign its staged copy before packaging",
        ),
    ]
    jni_libs = ROOT / "android" / "app" / "src" / "main" / "jniLibs"
    if jni_libs.is_dir():
        for abi_dir in sorted(jni_libs.iterdir()):
            so_path = abi_dir / "libxray.so"
            if so_path.is_file():
                candidates.append(
                    EngineBinary(
                        f"Android Xray ({so_path.relative_to(ROOT)})",
                        so_path,
                        REVIEWED_GO,
                        "vendored prebuilt binary -- needs a refreshed upstream/rebuilt artifact",
                    )
                )
    candidates.extend(_apple_wg_go_bridge_candidates())
    return candidates


def parse_go_version_text(text: str) -> tuple[int, int, int] | None:
    """Return the highest exact go1.MAJOR.PATCH token in text, or None.

    Prerelease suffixes (go1.27rc, go1.27.1rc1), two-component tokens
    (go1.27), extra components (go1.27.1.1), and empty/malformed strings
    do not count.
    """
    best: tuple[int, int, int] | None = None
    for match in _GO_VERSION_TOKEN_RE.finditer(text):
        candidate = (1, int(match.group(1)), int(match.group(2)))
        if best is None or candidate > best:
            best = candidate
    return best


def is_reviewed_go_version(version: tuple[int, int, int] | None) -> bool:
    return version == REVIEWED_GO


def _go_binary_on_path() -> str | None:
    return shutil.which("go")


def _version_via_go_tool(go_exe: str, binary_path: Path) -> tuple[int, int, int] | None:
    try:
        result = subprocess.run(
            [go_exe, "version", "-m", str(binary_path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    first_line = result.stdout.splitlines()[0] if result.stdout else ""
    return parse_go_version_text(first_line)


def _extract_printable_runs(data: bytes) -> list[bytes]:
    return [m.group(0) for m in _PRINTABLE_RUN_RE.finditer(data)]


def _version_via_strings(binary_path: Path) -> tuple[int, int, int] | None:
    payload = binary_path.read_bytes()
    strings_exe = shutil.which("strings")
    if strings_exe:
        try:
            result = subprocess.run(
                [strings_exe, "-a", str(binary_path)],
                capture_output=True,
                timeout=60,
                check=False,
            )
            parsed = parse_go_version_text(
                result.stdout.decode("latin-1", errors="replace")
            )
            if parsed is not None:
                return parsed
        except OSError:
            pass
    parsed = parse_go_version_text(payload.decode("latin-1", errors="replace"))
    if parsed is not None:
        return parsed
    best: tuple[int, int, int] | None = None
    for line in _extract_printable_runs(payload):
        candidate = parse_go_version_text(line.decode("latin-1", errors="replace"))
        if candidate is None:
            continue
        if best is None or candidate > best:
            best = candidate
    return best


def detect_go_version(binary_path: Path) -> tuple[tuple[int, int, int] | None, str]:
    """Return (version_tuple_or_None, method_used_or_error)."""
    go_exe = _go_binary_on_path()
    if go_exe:
        version = _version_via_go_tool(go_exe, binary_path)
        if version is not None:
            return version, "go version -m"
    version = _version_via_strings(binary_path)
    if version is not None:
        return version, "buildinfo string scan"
    return None, "undetectable (no `go` toolchain and no plausible goN.N.N buildinfo string found)"


def format_version(version: tuple[int, int, int]) -> str:
    return "go" + ".".join(str(part) for part in version)


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _exact_version_error(
    label: str,
    version: tuple[int, int, int] | None,
    method: str,
    required: tuple[int, int, int],
    note: str,
) -> str | None:
    if version is None:
        return f"{label}: could not determine embedded Go version ({method})"
    if version != required or not is_reviewed_go_version(version):
        return (
            f"{label}: built with {format_version(version)} (via {method}), but "
            f"requires exactly reviewed Go {format_version(required)}. "
            f"{note}"
        )
    return None


def check_binary(engine: EngineBinary) -> str | None:
    """Return an error string, or None if the binary passes."""
    if not engine.path.is_file():
        return f"{engine.label}: file not found at {_display_path(engine.path)}"
    version, method = detect_go_version(engine.path)
    return _exact_version_error(
        engine.label, version, method, engine.minimum, engine.note
    )


def check_windows_amneziawg_provenance() -> list[str]:
    binary_path = (
        ROOT / "installer" / "windows" / "dependencies" / "amneziawg.exe"
    )
    provenance_path = Path(f"{binary_path}.provenance.json")
    if not binary_path.is_file():
        return []
    if not provenance_path.is_file():
        return [
            "Windows AmneziaWG maintenance helper provenance is missing at "
            f"{provenance_path.relative_to(ROOT)}"
        ]
    actual_sha256 = hashlib.sha256(binary_path.read_bytes()).hexdigest()
    if actual_sha256 != WINDOWS_AMNEZIAWG_SHA256:
        return [
            "Windows AmneziaWG maintenance helper SHA-256 differs from the "
            f"reviewed Go {WINDOWS_REVIEWED_GO_VERSION} rebuild: {actual_sha256}"
        ]
    try:
        evidence = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return [f"Windows AmneziaWG provenance is unreadable/invalid: {error}"]
    required = {
        "schema_version": 2,
        "source_repository": (
            "https://github.com/amnezia-vpn/amneziawg-windows-client.git"
        ),
        "source_version": "3.1.0",
        "source_commit": WINDOWS_AMNEZIAWG_SOURCE_COMMIT,
        "go_version": WINDOWS_REVIEWED_GO_VERSION,
        "go_archive_sha256": WINDOWS_AMNEZIAWG_GO_ARCHIVE_SHA256,
        "go_toolchain_policy": "verified_archive_only",
        "go_module_policy": "readonly",
        "go_checksum_database": "sum.golang.org",
        "target": "windows-amd64",
        "unsigned_artifact_sha256": WINDOWS_AMNEZIAWG_SHA256,
        "authenticode_status": "pending_release_signing",
        "release_signing_required": True,
    }
    mismatches = [
        name
        for name, expected in required.items()
        if evidence.get(name) != expected
    ]
    if mismatches:
        return [
            "Windows AmneziaWG provenance contract differs in: "
            + ", ".join(mismatches)
        ]
    return []


def check_amneziawg_android_aar() -> list[str]:
    aar_path = ROOT / "android" / "app" / "libs" / "amneziawg.aar"
    if not aar_path.is_file():
        return [f"AmneziaWG Android AAR not found at {aar_path.relative_to(ROOT)}"]
    problems: list[str] = []
    note = (
        "this is a third-party prebuilt artifact -- refresh it from upstream "
        "amnezia-vpn/amneziawg-android once a build using exact reviewed Go "
        f"{REVIEWED_GO_VERSION} is available, or build the AAR from source "
        "with that pinned release"
    )
    with tempfile.TemporaryDirectory(prefix="winsvpn-aar-govercheck-") as tmp_name:
        tmp_dir = Path(tmp_name)
        with zipfile.ZipFile(aar_path) as archive:
            go_members = [
                name
                for name in archive.namelist()
                if name.startswith("jni/") and name.endswith("libam-go.so")
            ]
            if not go_members:
                return [
                    "AmneziaWG Android AAR: no jni/*/libam-go.so member found -- "
                    "AAR layout may have changed, update this checker"
                ]
            for member in go_members:
                archive.extract(member, tmp_dir)
                extracted = tmp_dir / member
                version, method = detect_go_version(extracted)
                label = f"AmneziaWG Android AAR ({member})"
                error = _exact_version_error(
                    label, version, method, REVIEWED_GO, note
                )
                if error:
                    problems.append(error)
    return problems


def main() -> int:
    problems: list[str] = []
    for engine in _candidate_engine_binaries():
        error = check_binary(engine)
        if error:
            problems.append(error)
    problems.extend(check_windows_amneziawg_provenance())
    problems.extend(check_amneziawg_android_aar())

    if problems:
        sys.stderr.write("embedded engine runtime version gate FAILED:\n")
        for problem in problems:
            sys.stderr.write(f"  - {problem}\n")
        sys.stderr.write(
            "\nThe Windows/Android artifacts above are vendored/prebuilt binaries; this "
            "script cannot fabricate a fix by editing source. Rebuild Xray from source with "
            f"exact reviewed Go {REVIEWED_GO_VERSION} (discovered {REVIEWED_GO_DISCOVERY_DATE} "
            "as the current stable release on go.dev; official go.dev requires macOS "
            f"{OFFICIAL_GO_MACOS_MINIMUM} or later, while WinsVPN also uses "
            f"macOS {WINSVPN_MACOS_APP_DEPLOYMENT_FLOOR} as the Apple app deployment floor), "
            "or obtain a refreshed upstream "
            "build. Any Apple Go bridge slice "
            "above is instead built from source in this repo -- bump REVIEWED_GO_VERSION in "
            "tools/build_apple_wg_go_bridge.sh (only after independently re-verifying the new "
            "release's official hashes) and re-run it. Then re-run this gate.\n"
        )
        return 1

    sys.stdout.write("embedded engine runtime version gate passed.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
