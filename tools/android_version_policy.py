#!/usr/bin/env python3
"""Version-code / version-name policy for the two Android apps in this tree.

Codifies the decision made 2026-08-10 (lane androidver) so the policy is an
executable check, not a sentence in a handoff. Read the Handoff section of the
accompanying test for the evidence; this module only encodes it.

Policy rules enforced here:

1. A release versionCode must be STRICTLY GREATER than every version code that
   any evidence says was ever uploaded to Google Play for that applicationId,
   across every track (production, beta, alpha, internal). Play rejects an
   upload whose versionCode is not greater than the app's highest-ever-used
   code, and rejects any code reuse outright.
2. A release versionCode must never equal one of the app's burned codes
   (uploaded before, then retired/rejected -- still unresuable forever).
3. The two apps use INDEPENDENT version-code number spaces. They do not share a
   keystore or a listing, so a code valid for one is meaningless for the other.
4. versionName is the user-facing marketing string; it must parse as the
   semantic part of the tree's `version: x.y.z+N` line.

KNOWN-USED / BURNED SETS (with citation):

org.winsvpn.app (Win's VPN)
  * COMBINED_HANDOFF_ALL_FIVE_20260731.md: "Production in review: version code
    14 (1.0+14). Do not reuse 10, 12, or 13."
  * MACBOOK_SYNC_CHANGES_20260710.md: "Google Play production remains code 16
    in review; build 29 is intended only for the Alpha closed-testing track."
  * TREE_DIVERGENCE_20260804.md Gate 0 / §2: two release-signed artifacts
    already carry 1.0.14+29 and store status is not readable from the tree, so
    a THIRD artifact under that identity is forbidden; bump the build number.
  * WINN_ANDROID_CAPABILITY_HONESTY_20260804.md: the attached device carries
    org.winsvpn.app at versionCode 29 (sideloaded, not a Play upload).
  => Known Play-used codes: {10, 12, 13, 14, 16}. Tree-claimed-but-never-
     uploaded codes: {6..9, 17, 18, 29}. Because the store consoles cannot be
     read from this tree, the first provably-safe next code is
     max(known_play_used, tree_claimed) + 1 = 30.

com.winsvpn.security (Win For All)
  * WFA_ANDROID_RELEASE_SIGNED_20260810.md §7.1: signed artifacts carry
    versionCode 1; "If anything has ever been uploaded ... this artifact cannot
    be uploaded as-is." No keystore existed before 2026-08-10, so no signed
    upload could have preceded it; nothing was ever uploaded.
  => Known Play-used codes: {}; first upload uses versionCode 1 (0.1.0+1).
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


VERSION_LINE_RE = re.compile(r"^version:\s*(\d+)\.(\d+)\.(\d+)\+(\d+)\s*$")

# Pinned literals in android/app/build.gradle.kts `defaultConfig`. A non-patched
# (flutter.versionName / flutter.versionCode derived) file has no integer literal
# for versionCode, so it is treated as not-pinned and reported as drift.
GRADLE_VERSION_CODE_RE = re.compile(r"^(\s*)versionCode\s*=\s*(\d+)\s*$")
GRADLE_VERSION_NAME_RE = re.compile(r'^(\s*)versionName\s*=\s*"([^"]+)"\s*$')

# applicationId -> (highest code any evidence attributes to a Play track,
#                   codes Play refuses outright if reused)
PLAY_HISTORY: dict[str, dict] = {
    "org.winsvpn.app": {
        "known_play_used": {10, 12, 13, 14, 16},
        "tree_claimed_never_uploaded": {6, 7, 8, 9, 11, 15, 17, 18, 29},
    },
    "com.winsvpn.security": {
        "known_play_used": set(),
        "tree_claimed_never_uploaded": set(),
    },
}


def parse_pubspec_version(pubspec: Path) -> tuple[int, int, int, int]:
    for raw in pubspec.read_text(encoding="utf-8").splitlines():
        match = VERSION_LINE_RE.match(raw)
        if match:
            return tuple(int(part) for part in match.groups())  # (major, minor, patch, code)
    raise ValueError(f"pubspec.yaml has no valid 'version: x.y.z+N' line: {pubspec}")


# Hardware/observed installed device floors in the field.
# org.winsvpn.app installed packages observed:
# - phone: 32
# - tv: 3202
# - wear_os: 3001
OBSERVED_DEVICE_FLOORS: dict[str, dict[str, int]] = {
    "org.winsvpn.app": {
        "phone": 32,
        "tv": 3202,
        "wear_os": 3001,
    },
    "com.winsvpn.security": {},
}


def minimum_build_number_for_device_floors(application_id: str) -> int:
    floors = OBSERVED_DEVICE_FLOORS.get(application_id)
    if not floors:
        return 1
    phone_min = floors.get("phone", 0) + 1
    tv_raw = floors.get("tv", 2)
    tv_min = ((tv_raw - 2) // 100) + 1
    wear_raw = floors.get("wear_os", 1)
    wear_min = ((wear_raw - 1) // 100) + 1
    return max(phone_min, tv_min, wear_min)


def safe_next_version_code(application_id: str) -> int:
    history = PLAY_HISTORY[application_id]
    known = history["known_play_used"]
    claimed = history["tree_claimed_never_uploaded"]
    combined = set(known) | set(claimed)
    floor_code = minimum_build_number_for_device_floors(application_id)
    if not combined:
        return floor_code
    return max(max(combined) + 1, floor_code)


def policy_error(application_id: str, code: int) -> str | None:
    if application_id not in PLAY_HISTORY:
        raise ValueError(f"no version policy recorded for {application_id}")
    history = PLAY_HISTORY[application_id]
    known = history["known_play_used"]
    claimed = history["tree_claimed_never_uploaded"]
    if code in known:
        return (
            f"versionCode {code} for {application_id} was used on a Play track "
            "before and Play refuses code reuse outright; use "
            f"{safe_next_version_code(application_id)} or higher"
        )
    if code < safe_next_version_code(application_id):
        return (
            f"versionCode {code} for {application_id} is not strictly greater "
            "than the highest code with any Play history "
            f"({', '.join(str(c) for c in sorted(known))}); a lower-or-equal "
            "code is rejected at upload. Use "
            f"{safe_next_version_code(application_id)} or higher"
        )
    return None


def check_pubspec(application_id: str, pubspec: Path) -> int:
    major, minor, patch, code = parse_pubspec_version(pubspec)
    version_name = f"{major}.{minor}.{patch}"
    error = policy_error(application_id, code)
    if error:
        print(f"VERSION POLICY FAIL: {error}", file=sys.stderr)
        return 2
    print(f"version_name={version_name} versionCode={code} applicationId={application_id} OK")
    return 0


def _git(args: list[str]) -> subprocess.CompletedProcess:
    """Run a read-only git subcommand. Never mutates the repo."""
    return subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _strip_comments(text: str) -> str:
    """Replace Kotlin line and block comments with whitespace of equal length to preserve spans."""
    def repl(m: re.Match) -> str:
        s = m.group(0)
        return "\n" * s.count("\n") + " " * (len(s) - s.count("\n"))
    pattern = r'(//[^\n]*)|(/\*.*?\*/)'
    return re.sub(pattern, repl, text, flags=re.DOTALL)


def git_version_lines(repo_root: Path) -> list[str]:
    """Collect the pubspec 'version:' lines carried by every reachable Git tag.

    Read-only git: lists tags with `git for-each-ref` (which does not touch the
    index or working tree) and reads each tag's pubspec via `git show`. Returns
    the raw semantic lines so callers can parse them with VERSION_LINE_RE. An
    empty result means there is no usable tag history, not an error. Fails closed
    on non-zero git exit.
    """
    listed = _git(["-C", str(repo_root), "for-each-ref", "refs/tags", "--format=%(refname:strip=2)"])
    if listed.returncode != 0:
        raise ValueError(f"git for-each-ref failed: {listed.stderr.strip()}")
    if not listed.stdout.strip():
        return []
    lines: list[str] = []
    for tag in listed.stdout.splitlines():
        tag = tag.strip()
        if not tag:
            continue
        shown = _git(["-C", str(repo_root), "show", f"{tag}:pubspec.yaml"])
        if shown.returncode != 0:
            raise ValueError(f"git show {tag}:pubspec.yaml failed: {shown.stderr.strip()}")
        for raw in shown.stdout.splitlines():
            match = VERSION_LINE_RE.match(raw)
            if match:
                lines.append(match.group(0))
                break
    return lines


def parse_tag_versions(version_lines: list[str]) -> list[tuple[int, int, int, int]]:
    """Turn collected pubspec version lines into (major, minor, patch, code)."""
    out: list[tuple[int, int, int, int]] = []
    for line in version_lines:
        match = VERSION_LINE_RE.match(line)
        if match:
            out.append(tuple(int(p) for p in match.groups()))  # type: ignore[return-value]
    return out


def next_semantic_version(version_lines: list[str], fallback: tuple[int, int, int]) -> str:
    """Deterministic next versionName: bump the patch of the highest semantic
    version named across tags and the fallback (working-tree pubspec).
    """
    tag_versions = parse_tag_versions(version_lines)
    semantic_versions = [fallback]
    semantic_versions.extend((v[0], v[1], v[2]) for v in tag_versions)
    major, minor, patch = max(semantic_versions)
    return f"{major}.{minor}.{patch + 1}"


def next_version_description(application_id: str, repo_root: Path, pubspec: Path) -> str:
    """Compute the deterministic next versionName/versionCode for a release.

    versionCode: strictly greater than every code any evidence names
    (policy sets + every Git-tag pubspec + working tree pubspec + device floors).
    versionName: bump the patch of the highest semantic version named by any Git tag
    or working tree pubspec; never more than one minor per release interval.
    """
    current = parse_pubspec_version(pubspec)
    _major, _minor, _patch, current_code = current
    tag_lines = git_version_lines(repo_root)
    history = PLAY_HISTORY[application_id]
    combined = (
        set(history["known_play_used"])
        | set(history["tree_claimed_never_uploaded"])
    )
    # Policy rule 3: the two apps keep INDEPENDENT version-code number spaces,
    # so a code valid for one is meaningless for the other. The Git tags in
    # THIS repo are the recorded history of the app it publishes
    # (org.winsvpn.app); folding them into the sibling's space would leak a
    # code between spaces. Only the app this repo records may absorb them.
    if application_id == "org.winsvpn.app":
        combined |= {v[3] for v in parse_tag_versions(tag_lines)}
        combined.add(current_code)
        floor = minimum_build_number_for_device_floors(application_id)
        combined.add(floor)
    next_code = (max(combined) + 1) if combined else 1
    name = next_semantic_version(tag_lines, fallback=(_major, _minor, _patch))
    error = policy_error(application_id, next_code)
    if error:
        raise ValueError(f"derived versionCode {next_code} violates policy: {error}")
    return f"{name}+{next_code}"


def _gradle_named_block_span(text: str, header: str) -> tuple[int, int, str]:
    """Return (start, end, interior) of the unique `header { ... }` Gradle block."""
    matches = list(re.finditer(rf"(?m)^[ \t]*{re.escape(header)}[ \t]*\{{", text))
    if not matches:
        if text.find(header) >= 0:
            raise ValueError(f"Gradle block {header} is not a brace block")
        raise ValueError(f"missing Gradle block {header}")
    if len(matches) > 1:
        raise ValueError(f"duplicate Gradle block {header}")
    brace = matches[0].end() - 1
    depth = 0
    for index, char in enumerate(text[brace:], brace):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return brace + 1, index, text[brace + 1 : index]
    raise ValueError(f"unclosed Gradle block {header}")


def _gradle_named_block(text: str, header: str) -> str:
    """Return the interior of the unique `header { ... }` Gradle block."""
    return _gradle_named_block_span(text, header)[2]


def patch_gradle_versions(gradle_kts: Path, next_version: str) -> tuple[bool, int, str]:
    """Patch versionName/versionCode literals into android/app/build.gradle.kts.

    Replaces the active versionCode and versionName assignments in defaultConfig
    with the deterministic literals, so the same Git state always produces the
    same APK identity regardless of pubspec or local.conf drift.
    Returns (changed, versionCode, versionName-string-part).
    """
    text = gradle_kts.read_text(encoding="utf-8")
    name_part, code_part = next_version.split("+")
    version_code = int(code_part)

    c_start, c_end, interior = _gradle_named_block_span(text, "defaultConfig")

    active_interior = _strip_comments(interior)
    code_matches = list(re.finditer(r'(?m)^[ \t]*versionCode[ \t]*=[ \t]*(.+)$', active_interior))
    name_matches = list(re.finditer(r'(?m)^[ \t]*versionName[ \t]*=[ \t]*(.+)$', active_interior))

    if len(code_matches) == 0:
        raise ValueError("defaultConfig has no versionCode assignment")
    if len(code_matches) > 1:
        raise ValueError(f"defaultConfig has multiple ({len(code_matches)}) versionCode assignments")
    if len(name_matches) == 0:
        raise ValueError("defaultConfig has no versionName assignment")
    if len(name_matches) > 1:
        raise ValueError(f"defaultConfig has multiple ({len(name_matches)}) versionName assignments")

    code_val = code_matches[0].group(1).strip()
    name_val = name_matches[0].group(1).strip()

    target_code_val = str(version_code)
    target_name_val = f'"{name_part}"'

    if code_val == target_code_val and name_val == target_name_val:
        return False, version_code, name_part

    code_m = code_matches[0]
    line_start = interior.rfind('\n', 0, code_m.start())
    line_start = 0 if line_start < 0 else line_start + 1
    line_end = interior.find('\n', code_m.end())
    if line_end < 0:
        line_end = len(interior)

    orig_code_line = interior[line_start:line_end]
    indent_m = re.match(r'^[ \t]*', orig_code_line)
    indent = indent_m.group(0) if indent_m else ""
    new_code_line = f"{indent}versionCode = {version_code}"

    name_m = name_matches[0]
    n_line_start = interior.rfind('\n', 0, name_m.start())
    n_line_start = 0 if n_line_start < 0 else n_line_start + 1
    n_line_end = interior.find('\n', name_m.end())
    if n_line_end < 0:
        n_line_end = len(interior)

    orig_name_line = interior[n_line_start:n_line_end]
    n_indent_m = re.match(r'^[ \t]*', orig_name_line)
    n_indent = n_indent_m.group(0) if n_indent_m else ""
    new_name_line = f'{n_indent}versionName = "{name_part}"'

    if line_start < n_line_start:
        new_interior = (
            interior[:line_start]
            + new_code_line
            + interior[line_end:n_line_start]
            + new_name_line
            + interior[n_line_end:]
        )
    else:
        new_interior = (
            interior[:n_line_start]
            + new_name_line
            + interior[n_line_end:line_start]
            + new_code_line
            + interior[line_end:]
        )

    verify_active = _strip_comments(new_interior)
    v_code = list(re.finditer(r'(?m)^[ \t]*versionCode[ \t]*=[ \t]*(.+)$', verify_active))
    v_name = list(re.finditer(r'(?m)^[ \t]*versionName[ \t]*=[ \t]*(.+)$', verify_active))
    if len(v_code) != 1 or v_code[0].group(1).strip() != target_code_val:
        raise ValueError("post-patch verification failed for versionCode")
    if len(v_name) != 1 or v_name[0].group(1).strip() != target_name_val:
        raise ValueError("post-patch verification failed for versionName")

    patched = text[:c_start] + new_interior + text[c_end:]
    if patched == text:
        return False, version_code, name_part
    gradle_kts.write_text(patched, encoding="utf-8")
    return True, version_code, name_part


def _pinned_version_literals(block: str, label: str) -> tuple[int | None, str | None]:
    code: int | None = None
    name: str | None = None
    for raw in block.splitlines():
        matched_code = GRADLE_VERSION_CODE_RE.match(raw)
        if matched_code:
            if code is not None:
                raise ValueError(f"{label} has more than one versionCode literal")
            code = int(matched_code.group(2))
        matched_name = GRADLE_VERSION_NAME_RE.match(raw)
        if matched_name:
            if name is not None:
                raise ValueError(f"{label} has more than one versionName literal")
            name = matched_name.group(2)
    return code, name


def read_gradle_pinned(gradle_kts: Path) -> tuple[int, str]:
    """Read the pinned versionCode (int) and versionName (str) literals from a
    build.gradle.kts `defaultConfig`. Only integer/literal forms are accepted;
    a file still using `flutter.versionCode`/`flutter.versionName` derivation
    has no pinned identity and is surfaced as an error rather than assumed.
    Flavor versionCode overrides, including Android TV, are ignored here.
    """
    block = _gradle_named_block(gradle_kts.read_text(encoding="utf-8"), "defaultConfig")
    code, name = _pinned_version_literals(block, f"{gradle_kts} defaultConfig")
    if code is None or name is None:
        raise ValueError(
            f"{gradle_kts} defaultConfig has no pinned literals for both "
            "versionCode and versionName (a file still deriving from "
            "flutter.versionCode/flutter.versionName is not pinned)."
        )
    return code, name


def read_tv_flavor_version_code(gradle_kts: Path) -> int:
    """Read the Android TV product-flavor versionCode from create("tv")."""
    block = _gradle_named_block(gradle_kts.read_text(encoding="utf-8"), 'create("tv")')
    code, _name = _pinned_version_literals(block, f"{gradle_kts} tv flavor")
    if code is None:
        raise ValueError(f"{gradle_kts} tv flavor has no pinned versionCode literal")
    return code


def default_enforce() -> int:
    """Enforce the working-tree pin when invoked with no arguments.

    Treats pubspec.yaml as the single source of truth for the version triple
    (versionName/versionCode), validates it against the Play-console history in
    PLAY_HISTORY, and refuses on drift between pubspec and the Gradle pins that
    actually produce the phone, TV, and Wear artifacts. Phone uses
    defaultConfig. TV uses create("tv") versionCode phone*100+2. Wear uses its
    own defaultConfig versionCode phone*100+1. Nothing is bumped here; this
    lane only checks alignment.
    """
    root = Path(__file__).resolve().parent.parent
    pubspec: Path = root / "pubspec.yaml"
    gradle: Path = root / "android" / "app" / "build.gradle.kts"
    wear_gradle: Path = root / "wear_os" / "app" / "build.gradle.kts"
    application_id = "org.winsvpn.app"

    major, minor, patch, pub_code = parse_pubspec_version(pubspec)
    pub_name = f"{major}.{minor}.{patch}"
    expected_tv = pub_code * 100 + 2
    expected_wear = pub_code * 100 + 1

    error = policy_error(application_id, pub_code)
    if error:
        print(f"VERSION POLICY FAIL: {error}", file=sys.stderr)
        return 2

    try:
        g_code, g_name = read_gradle_pinned(gradle)
        tv_code = read_tv_flavor_version_code(gradle)
        wear_code, wear_name = read_gradle_pinned(wear_gradle)
    except ValueError as exc:
        print(f"VERSION POLICY FAIL: {exc}", file=sys.stderr)
        return 1
    drift = (
        (g_code != pub_code)
        or (g_name != pub_name)
        or (tv_code != expected_tv)
        or (wear_code != expected_wear)
        or (wear_name != pub_name)
    )

    print(
        f"pinned triple versionName={pub_name} versionCode={pub_code} "
        f"applicationId={application_id} (pubspec: version: {pub_name}+{pub_code})"
    )
    print(
        f"gradle defaultConfig versionCode={g_code} versionName={g_name} ({gradle})"
    )
    print(
        f"tv flavor versionCode={tv_code} expected={expected_tv}; "
        f"wear defaultConfig versionCode={wear_code} versionName={wear_name} "
        f"expected={expected_wear}"
    )
    # Phone AAB/APK share defaultConfig. TV and Wear keep distinct Play
    # versionCodes under the same application ID: phone*100+2 and phone*100+1.
    next_code = pub_code + 1
    print(
        f"next build alignment: phone AAB/APK emit versionCode={g_code} "
        f"versionName={g_name}; TV emits {tv_code}; Wear emits {wear_code}; "
        f"a future phone bump steps versionCode to {next_code} with matching "
        f"TV {next_code * 100 + 2} and Wear {next_code * 100 + 1}"
    )
    if drift:
        print(
            "VERSION POLICY FAIL: Android phone/TV/Wear version pins drifted "
            f"from pubspec.yaml (pubspec {pub_name}+{pub_code}, phone "
            f"{g_name}+{g_code}, TV {tv_code}, Wear {wear_name}+{wear_code}). "
            "Refusing.",
            file=sys.stderr,
        )
        return 1

    print(
        "ALIGNED: pubspec, phone defaultConfig, TV flavor, and Wear "
        f"defaultConfig agree on the {pub_name}+{pub_code} Play identity."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args_list = list(argv) if argv is not None else list(sys.argv[1:])

    # Running with no arguments is the default enforcement mode: read the
    # working-tree source of truth (pubspec.yaml), verify the Play-console
    # policy, and make sure android/app/build.gradle.kts is not drifted from it.
    # Exit 0 only when the pinned triple is policy-legal AND the phone
    # defaultConfig, TV flavor, and Wear defaultConfig align with it.
    if not args_list:
        return default_enforce()

    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("application_id", choices=sorted(PLAY_HISTORY))
    parser.add_argument("pubspec", type=Path)
    parser.add_argument("--repo", type=Path, default=None,
                        help="Git repo root; enables deriving the next release version from git tags.")
    parser.add_argument("--patch-gradle", type=Path, default=None,
                        help="android/app/build.gradle.kts to patch with the derived version.")
    args = parser.parse_args(argv)

    if args.repo is not None:
        next_version = next_version_description(args.application_id, args.repo, args.pubspec)
        name_part, code_part = next_version.split("+")
        print(f"next_version_name={name_part} next_versionCode={code_part} applicationId={args.application_id} NEXT={next_version}")
        if args.patch_gradle is not None:
            changed, code, name = patch_gradle_versions(args.patch_gradle, next_version)
            print(f"gradle patched={changed} versionCode={code} versionName={name} target={args.patch_gradle}")
        return 0
    if args.patch_gradle is not None:
        parser.error("--patch-gradle requires --repo (the git tag history is the deterministic source).")
    return check_pubspec(args.application_id, args.pubspec)


if __name__ == "__main__":
    raise SystemExit(main())