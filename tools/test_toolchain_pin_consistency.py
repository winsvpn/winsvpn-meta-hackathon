#!/usr/bin/env python3
"""Toolchain pin drift guard.

WHY THIS EXISTS.

The Flutter version this repository builds with is written out as a bare
literal in twelve separate places, the Flutter framework revision in nine, and
the CocoaPods version in two. Four more files hard-code the same strings again
as assertions. Nothing connected any of them, so they were free to drift
apart independently -- and on 2026-08-03 they did. `tools/build_android_release.ps1`
moved to Flutter 3.44.8 while the other eleven declaration sites stayed on
3.44.6. The only thing that noticed was
`tools/test_android_release_producer.py::test_both_producers_pin_the_exact_reviewed_flutter_revision`,
which has been failing ever since, reporting a real disagreement between the
two Android producers that nobody acted on.

That is the failure mode this guard closes. `tools/toolchain-pins.json` is now
the single declared source of truth. This file checks three properties against
it:

  1. (Historical.) Every enumerated declaration site used to be checked against
     the declared value. Since the 2026-08-10 refactor the declaration sites
     READ the manifest at run time instead of carrying a literal, so `sites`
     is empty and this check is a no-op by construction.
  2. (Historical.) Same for the former guard-mirror files -- they now read the
     manifest or assert resolver wiring in their own bodies.
  3. No UNDECLARED LITERAL pin site may exist. If a bare literal reappears in
     a scanned file, discovery flags it. An indirect value (one that resolves
     from the manifest or a variable at run time) is the refactored shape and
     is NOT flagged.

WHAT THIS GUARD DOES NOT DO.

It does not change any build -- and neither do the build scripts anymore: the
declaration-site refactor this guard was once deliberately NOT part of (see
tools/toolchain-pins.json `_purpose`) has LANDED. Every site that used to
carry a literal now resolves its value from the manifest at run time
(`read_wins_toolchain_pin` on the sh side, `Read-WinsToolchainPin`
(ConvertFrom-Json) on the PowerShell side, a jq "Resolve the reviewed
toolchain pin" step in the GitHub workflows, and `--build-arg FLUTTER_REF=`
resolved from the pin in tools/build_linux_desktop_container.sh). The next
pin bump is one edit to this file.

Authoritative scanning now also covers Go, Python, Flutter/Dart, Node,
OpenSSL, Chrome/browser, JDK, Gradle, NDK, AWG, and Xray literals in
production build, packaging, installer, and deployment scripts via
tools/toolchain_pin_scan.py. Generated or provenance mirrors are allowed
only through explicit path+field mappings and must match the canonical
pins. Latest/range/floating selectors in those release paths fail closed.
Docs and tests are not pin sites.

It also covers TOOLCHAIN versions only. The Maven/Gradle dependency graph in
this repository is neither locked nor hash-verified, which is a much larger
exposure and is tracked in
docs/handoff/SUPPLY_CHAIN_PARITY_AUDIT_20260806.md.

TWO RULES FOR ANYONE ADDING AN ASSERTION HERE
(borrowed from wins_security/tools/test_android_supply_chain_guards.sh, which
learned them the hard way):

  * Accumulate. Every mismatch is collected and reported via subTest. A guard
    that dies on the first failure hides every check after it, which is worse
    than no guard, because it still looks like it ran.
  * Assert the property, not a byte sequence. The patterns below are anchored
    to the VARIABLE NAME, not to an exact indented source line, so
    reformatting a build script does not produce a phantom failure while a
    genuine version change still does.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass

TOOLS = pathlib.Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
import toolchain_pin_scan as pin_scan

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "tools" / "toolchain-pins.json"
MANIFEST = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

APPLE_AWG_COMPONENT_IDENTITIES = {
    "wrapper": {
        "tag": "v3.1.20260814",
        "commit": "fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d",
    },
    "embedded_engine": {
        "tag": "v3.1.20260828",
        "commit": "b5928efb6ca19f0153958460c3d141f04abc5c2e",
    },
}

_APPLE_AWG_SYMBOL_BINDINGS = {
    "APPLE_AWG_EXPECTED_TAG": ("wrapper", "tag"),
    "APPLE_AWG_EXPECTED_COMMIT": ("wrapper", "commit"),
    "AMNEZIAWG_APPLE_TAG": ("wrapper", "tag"),
    "AMNEZIAWG_APPLE_COMMIT": ("wrapper", "commit"),
    "AMNEZIAWG_GO_TAG": ("embedded_engine", "tag"),
    "AMNEZIAWG_GO_COMMIT": ("embedded_engine", "commit"),
    "AWG_GO_TAG": ("embedded_engine", "tag"),
    "AWG_GO_VERSION": ("embedded_engine", "tag"),
    "AWG_GO_COMMIT": ("embedded_engine", "commit"),
}

_APPLE_AWG_SOURCE_BINDINGS = {
    "apple/EngineArtifacts/apple_awg_31_engine_provenance.json": {
        "source.tag": ("wrapper", "tag"),
        "source.commit": ("wrapper", "commit"),
    },
    "tools/build_apple_engine_wrappers.sh": {
        "APPLE_AWG_EXPECTED_TAG": ("wrapper", "tag"),
        "APPLE_AWG_EXPECTED_COMMIT": ("wrapper", "commit"),
    },
    "tools/stage_apple_engine_artifacts.sh": {
        "APPLE_AWG_EXPECTED_TAG": ("wrapper", "tag"),
        "APPLE_AWG_EXPECTED_COMMIT": ("wrapper", "commit"),
    },
    "tools/build_apple_wg_go_bridge.sh": {
        "AMNEZIAWG_APPLE_TAG": ("wrapper", "tag"),
        "AMNEZIAWG_APPLE_COMMIT": ("wrapper", "commit"),
        "AMNEZIAWG_GO_TAG": ("embedded_engine", "tag"),
        "AMNEZIAWG_GO_COMMIT": ("embedded_engine", "commit"),
    },
}

_APPLE_AWG_ASSIGNMENT_RE = re.compile(
    r'^(?P<symbol>'
    + "|".join(
        sorted(
            (re.escape(symbol) for symbol in _APPLE_AWG_SYMBOL_BINDINGS),
            key=len,
            reverse=True,
        )
    )
    + r')\s*=\s*["\'](?P<value>[^"\']*)["\']',
    re.MULTILINE,
)


@dataclass(frozen=True)
class AppleAwgComponentPinHit:
    path: str
    symbol: str
    component: str
    field: str
    value: str
    canonical: str

    @property
    def conflict(self) -> bool:
        return self.value != self.canonical

    def describe(self) -> str:
        state = "conflict" if self.conflict else "match"
        return (
            f"{self.path} :: apple_awg.{self.component}.{self.field} "
            f"{self.symbol}={self.value!r} canonical={self.canonical!r} {state}"
        )


def _classify_apple_awg_component_field(
    path: str,
    symbol: str,
    value: str,
) -> AppleAwgComponentPinHit | None:
    binding = _APPLE_AWG_SOURCE_BINDINGS.get(path, {}).get(symbol)
    if binding is None:
        return None
    component, field = binding
    return AppleAwgComponentPinHit(
        path=path,
        symbol=symbol,
        component=component,
        field=field,
        value=value,
        canonical=APPLE_AWG_COMPONENT_IDENTITIES[component][field],
    )


def _scan_apple_awg_component_assignments(
    path: str,
    text: str,
) -> list[AppleAwgComponentPinHit]:
    hits: list[AppleAwgComponentPinHit] = []
    for match in _APPLE_AWG_ASSIGNMENT_RE.finditer(text):
        hit = _classify_apple_awg_component_field(
            path,
            match.group("symbol"),
            match.group("value"),
        )
        if hit is not None:
            hits.append(hit)
    return hits


def _component_canonical_for_pin_hit(hit: pin_scan.PinHit) -> str:
    binding = _APPLE_AWG_SYMBOL_BINDINGS.get(hit.symbol)
    if binding is None:
        binding = _APPLE_AWG_SOURCE_BINDINGS.get(hit.path, {}).get(hit.symbol)
    if binding is None:
        return hit.canonical
    component, field = binding
    return APPLE_AWG_COMPONENT_IDENTITIES[component][field]


def _pin_hit_conflicts(hit: pin_scan.PinHit) -> bool:
    canonical = _component_canonical_for_pin_hit(hit)
    return not pin_scan.pins_equal(hit.tool, hit.field, hit.value, canonical)


def _describe_component_aware_pin_hit(hit: pin_scan.PinHit) -> str:
    canonical = _component_canonical_for_pin_hit(hit)
    if canonical == hit.canonical:
        return hit.describe()
    state = "conflict" if _pin_hit_conflicts(hit) else "match"
    mapped = "mapped" if hit.mapped else "unmapped"
    return (
        f"{hit.path} :: {hit.tool}.{hit.field} {hit.kind} "
        f"{hit.symbol}={hit.value!r} canonical={canonical!r} {state} {mapped}"
    )

SCAN_EXTENSIONS = {".sh", ".ps1", ".py", ".yml", ".yaml", ".linux-desktop"}
SCAN_SKIP_DIR_NAMES = {"__pycache__", ".staging", "node_modules", ".git"}

# Values that are an interpolation rather than a literal (an f-string field, a
# shell/PowerShell variable expansion). Discovery still records the site so it
# must be declared, but there is no literal to compare.
INDIRECT_VALUE = re.compile(r"[{}$]")


def _declaration_pattern(kind: str, symbol: str) -> re.Pattern[str]:
    """Anchor on the symbol, not on surrounding formatting."""
    sym = re.escape(symbol)
    if kind == "sh_assign":
        return re.compile(rf'^{sym}="([^"]*)"', re.MULTILINE)
    if kind == "ps_assign":
        return re.compile(rf"\${sym}\s*=\s*'([^']*)'")
    if kind == "sh_local_assign":
        return re.compile(rf"local\s+{sym}='([^']*)'")
    if kind == "yaml_key":
        return re.compile(rf'^\s*{sym}:\s*"([^"]*)"', re.MULTILINE)
    if kind == "path_token":
        return re.compile(r"flutter-(\d+\.\d+\.\d+)-extract")
    if kind == "docker_arg_assign":
        return re.compile(rf"^ARG\s+{sym}=(.*)$", re.MULTILINE)
    raise AssertionError(f"unknown declaration kind: {kind}")


def _expected_value(site: dict) -> str:
    """The declared value for a site, honouring an explicit divergence."""
    for divergence in MANIFEST["declared_divergences"]:
        if (
            divergence["path"] == site["path"]
            and divergence["tool"] == site["tool"]
            and divergence["field"] == site["field"]
        ):
            return divergence["value"]
    return MANIFEST["tools"][site["tool"]][site["field"]]


def _authoritative_value(site: dict) -> str:
    return MANIFEST["tools"][site["tool"]][site["field"]]


def _discover_sites() -> dict[tuple[str, str], set[str]]:
    """Every (relative path, symbol) pair in the tree that looks like a pin."""
    patterns = {
        "sh_assign": re.compile(
            r'^(REQUIRED_FLUTTER_VERSION|REQUIRED_FLUTTER_REVISION'
            r'|REQUIRED_COCOAPODS_VERSION)="([^"]*)"',
            re.MULTILINE,
        ),
        "ps_assign": re.compile(
            r"\$(RequiredFlutterVersion|RequiredFlutterRevision"
            r"|RequiredCocoaPodsVersion|ExpectedFlutterVersion"
            r"|ExpectedFlutterRevision)\s*=\s*'([^']*)'"
        ),
        "sh_local_assign": re.compile(
            r"local\s+(required_version|required_revision)='([^']*)'"
        ),
        "yaml_key": re.compile(r'^\s*(flutter-version):\s*"([^"]*)"', re.MULTILINE),
        "path_token": re.compile(r"(flutter)-(\d+\.\d+\.\d+)-extract"),
        "docker_arg_assign": re.compile(
            r"^ARG\s+(FLUTTER_REF)=(\S+)", re.MULTILINE
        ),
    }
    found: dict[tuple[str, str], set[str]] = {}
    for scan_root in MANIFEST["discovery_scan_roots"]:
        base = ROOT / scan_root
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in SCAN_EXTENSIONS and path.name != "Dockerfile":
                continue
            if any(part in SCAN_SKIP_DIR_NAMES for part in path.parts):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = path.relative_to(ROOT).as_posix()
            for kind, pattern in patterns.items():
                for match in pattern.finditer(text):
                    symbol = (
                        "flutter-extract-dir"
                        if kind == "path_token"
                        else match.group(1)
                    )
                    found.setdefault((rel, symbol), set()).add(match.group(2))
    return found


class ToolchainPinConsistencyTests(unittest.TestCase):
    def test_manifest_is_internally_well_formed(self) -> None:
        self.assertEqual(MANIFEST["schema_version"], 1)
        for tool in (
            "flutter",
            "cocoapods",
            "gradle",
            "android_gradle_plugin",
            "kotlin",
        ):
            self.assertIn(tool, MANIFEST["tools"], f"{tool} missing from manifest")
        flutter = MANIFEST["tools"]["flutter"]
        self.assertRegex(flutter["version"], r"^\d+\.\d+\.\d+$")
        self.assertRegex(flutter["revision"], r"^[0-9a-f]{40}$")
        self.assertRegex(MANIFEST["tools"]["cocoapods"]["version"], r"^\d+\.\d+\.\d+$")
        self.assertRegex(MANIFEST["tools"]["gradle"]["distribution_version"], r"^\d+\.\d+\.\d+$")
        self.assertRegex(MANIFEST["tools"]["android_gradle_plugin"]["version"], r"^\d+\.\d+\.\d+$")
        self.assertRegex(MANIFEST["tools"]["kotlin"]["version"], r"^\d+\.\d+\.\d+$")
        gradle_hashes = MANIFEST["tools"]["gradle"]["distribution_sha256_by_flavour"]
        self.assertEqual(set(gradle_hashes), {"all", "bin"})
        for flavour, digest in gradle_hashes.items():
            with self.subTest(gradle_flavour=flavour):
                self.assertRegex(
                    digest,
                    r"^[0-9a-f]{64}$",
                    f"Gradle {flavour} archive hash must be a 64-character SHA-256",
                )
        self.assertNotEqual(gradle_hashes["all"], gradle_hashes["bin"])

    def test_android_plugin_pins_match_the_manifest(self) -> None:
        agp = MANIFEST["tools"]["android_gradle_plugin"]["version"]
        kotlin = MANIFEST["tools"]["kotlin"]["version"]
        expected = {
            "android/settings.gradle.kts": {
                "com.android.application": agp,
                "org.jetbrains.kotlin.android": kotlin,
            },
            "android/devicecheck/settings.gradle.kts": {
                "com.android.application": agp,
            },
            "wear_os/build.gradle.kts": {
                "com.android.application": agp,
                "org.jetbrains.kotlin.plugin.compose": kotlin,
            },
        }
        pattern = re.compile(r'id\("([^"]+)"\)\s+version\s+"([^"]+)"')
        for relative, wanted in expected.items():
            found = dict(pattern.findall((ROOT / relative).read_text(encoding="utf-8")))
            with self.subTest(path=relative):
                self.assertEqual({key: found.get(key) for key in wanted}, wanted)

    def test_every_declared_site_file_exists(self) -> None:
        """A half-finished refactor that deletes a site must not pass silently."""
        for site in MANIFEST["sites"]:
            with self.subTest(path=site["path"]):
                self.assertTrue(
                    (ROOT / site["path"]).is_file(),
                    f"{site['path']} is declared in toolchain-pins.json but does "
                    f"not exist. Either restore it or drop its entry.",
                )

    def test_every_declaration_site_matches_the_single_source_of_truth(self) -> None:
        for site in MANIFEST["sites"]:
            if site["role"] != "declaration":
                continue
            path = ROOT / site["path"]
            if not path.is_file():
                continue  # reported by test_every_declared_site_file_exists
            text = path.read_text(encoding="utf-8", errors="replace")
            pattern = _declaration_pattern(site["kind"], site["symbol"])
            found = pattern.findall(text)
            expected = _expected_value(site)
            with self.subTest(path=site["path"], symbol=site["symbol"]):
                self.assertTrue(
                    found,
                    f"{site['path']} declares no {site['symbol']}; the manifest "
                    f"says it should pin {site['tool']}.{site['field']}.",
                )
                for actual in set(found):
                    self.assertEqual(
                        actual,
                        expected,
                        f"{site['path']} pins {site['symbol']}={actual!r} but "
                        f"toolchain-pins.json declares {expected!r}. Either move "
                        f"the manifest deliberately (and every other site with "
                        f"it) or add an entry to declared_divergences explaining "
                        f"why this one differs.",
                    )

    def test_every_guard_mirror_asserts_the_single_source_of_truth(self) -> None:
        """Guards must expect the declared value, not a locally softened one."""
        for site in MANIFEST["sites"]:
            if site["role"] != "guard" or site["kind"] != "contains":
                continue
            path = ROOT / site["path"]
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            needle = site["template"].format(value=_authoritative_value(site))
            with self.subTest(path=site["path"], symbol=site["symbol"]):
                self.assertIn(
                    needle,
                    text,
                    f"{site['path']} no longer asserts {needle!r}. A guard that "
                    f"stops expecting the declared pin has been weakened, not "
                    f"fixed -- confirm the manifest moved first.",
                )

    def test_no_undeclared_pin_site_exists(self) -> None:
        """A thirteenth copy of the version string cannot appear silently."""
        declared = {(site["path"], site["symbol"]) for site in MANIFEST["sites"]}
        undeclared = []
        for (rel, symbol), values in sorted(_discover_sites().items()):
            if (rel, symbol) in declared:
                continue
            if any(not INDIRECT_VALUE.search(v) for v in values):
                undeclared.append(f"{rel} :: {symbol} -> {sorted(values)}")
        self.assertEqual(
            undeclared,
            [],
            "Undeclared toolchain pin site(s) found. Every place that hard-codes "
            "a toolchain version must be listed in tools/toolchain-pins.json so "
            "it is checked, or the manifest stops being a single source of "
            "truth:\n  " + "\n  ".join(undeclared),
        )

    def test_refactored_sh_sites_resolve_the_pin_at_runtime(self) -> None:
        """Every refactored sh declaration site must actually READ the manifest.

        With `sites` empty by design (each site resolves this file at run
        time), the manifest is only the source of truth if a wrong key or a
        return-to-a-literal is caught. Run each sh site's own resolver against
        the manifest and require the declared values.
        """
        if shutil.which("python3") is None:
            self.skipTest("python3 is required to resolve the toolchain pin")
        flutter = MANIFEST["tools"]["flutter"]
        cocoapods_version = MANIFEST["tools"]["cocoapods"]["version"]
        scripts = (
            ("tools/verify_apple_readiness.sh", True),
            ("tools/apple_runtime_smoke.sh", True),
            ("tools/build_apple_release_candidates.sh", False),
            ("tools/build_linux_release.sh", False),
            ("tools/build_android_release_macos.sh", False),
        )
        env = dict(
            os.environ,
            ROOT=str(ROOT),
            ROOT_DIR=str(ROOT),
            PYTHON_BIN="python3",
        )
        for rel, carries_pods in scripts:
            text = (ROOT / rel).read_text(encoding="utf-8")
            match = re.search(r"(?m)^read_wins_toolchain_pin\(\) \{", text)
            self.assertIsNotNone(match, f"{rel}: pin resolver not present")
            assert match is not None
            close = re.search(r"(?m)^\}$", text[match.start():])
            self.assertIsNotNone(close, f"{rel}: pin resolver never closes")
            assert close is not None
            resolver = text[match.start(): match.start() + close.start() + 1]
            expected = [
                ("tools.flutter.version", flutter["version"]),
                ("tools.flutter.revision", flutter["revision"]),
            ]
            if carries_pods:
                expected.append(("tools.cocoapods.version", cocoapods_version))
            for key, want in expected:
                with self.subTest(path=rel, key=key):
                    completed = subprocess.run(
                        ["bash", "-c", resolver + f"\nread_wins_toolchain_pin {key}\n"],
                        capture_output=True,
                        text=True,
                        env=env,
                    )
                    self.assertEqual(
                        completed.returncode, 0, completed.stderr[-500:]
                    )
                    self.assertEqual(
                        completed.stdout.strip(),
                        want,
                        f"{rel} resolves {key!r} to "
                        f"{completed.stdout.strip()!r}; toolchain-pins.json "
                        f"declares {want!r}. A refactored site that returns the "
                        f"wrong value enforces a different toolchain than the "
                        f"manifest pins.",
                    )

    def test_declared_divergences_carry_a_reason_and_a_review_status(self) -> None:
        """A divergence is allowed to exist, but never anonymously."""
        for divergence in MANIFEST["declared_divergences"]:
            with self.subTest(path=divergence["path"], field=divergence["field"]):
                for key in ("reason", "review_status", "owner_decision_required"):
                    self.assertIn(key, divergence)
                self.assertTrue(str(divergence["reason"]).strip())
                self.assertIn(
                    divergence["review_status"],
                    {"reviewed", "unreviewed-in-this-repo", "pending-review"},
                )

    def test_gradle_distribution_is_hash_pinned_in_every_gradle_project(self) -> None:
        """The one Gradle-side control this repo has must hold everywhere.

        Asserts the property -- "Gradle 9.1.0, and hash-pinned to the recorded
        hash for whichever archive flavour this wrapper names" -- rather than
        one literal. Two flavours of the same Gradle are legitimately in use
        (`-all` and `-bin`) and they have different, both-correct hashes, so a
        single-literal assertion would fail on a real project while teaching
        nothing about whether the pin is actually present.
        """
        gradle = MANIFEST["tools"]["gradle"]
        declared_version = gradle["distribution_version"]
        by_flavour = gradle["distribution_sha256_by_flavour"]
        url_pattern = re.compile(
            r"distributionUrl=.*?gradle-(?P<version>[\d.]+)-(?P<flavour>all|bin)\.zip"
        )
        wrappers = sorted(
            p
            for p in ROOT.rglob("gradle/wrapper/gradle-wrapper.properties")
            if p.is_file()
            and pin_scan.path_role(p.relative_to(ROOT).as_posix()) == "authoritative"
        )
        self.assertTrue(wrappers, "no gradle-wrapper.properties found at all")
        found_wrappers = {wrapper.relative_to(ROOT).as_posix() for wrapper in wrappers}
        for rel in (
            "android/gradle/wrapper/gradle-wrapper.properties",
            "android/devicecheck/gradle/wrapper/gradle-wrapper.properties",
            "wear_os/gradle/wrapper/gradle-wrapper.properties",
        ):
            self.assertIn(rel, found_wrappers)
        for wrapper in wrappers:
            rel = wrapper.relative_to(ROOT).as_posix()
            text = wrapper.read_text(encoding="utf-8", errors="replace")
            with self.subTest(path=rel):
                match = url_pattern.search(text)
                self.assertIsNotNone(
                    match,
                    f"{rel} has no recognisable Gradle distributionUrl.",
                )
                assert match is not None
                self.assertEqual(
                    match.group("version"),
                    declared_version,
                    f"{rel} uses Gradle {match.group('version')} but "
                    f"toolchain-pins.json declares {declared_version}.",
                )
                flavour = match.group("flavour")
                self.assertIn(
                    flavour,
                    by_flavour,
                    f"{rel} uses the '{flavour}' Gradle archive, which has no "
                    f"recorded hash in toolchain-pins.json. Record its sha256 "
                    f"deliberately rather than leaving the flavour unpinned.",
                )
                self.assertIn(
                    f"distributionSha256Sum={by_flavour[flavour]}",
                    text,
                    f"{rel} does not hash-pin the Gradle distribution to the "
                    f"recorded {flavour} hash. Without a matching "
                    f"distributionSha256Sum the wrapper will run whatever the "
                    f"download server returns.",
                )


class ExpandedToolchainPinScanTests(unittest.TestCase):
    """Authoritative scan, provenance mirrors, floating selectors, mutations."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.canonical = pin_scan.canonical_pins(MANIFEST)
        cls.report = pin_scan.scan_repository(ROOT, manifest=MANIFEST)

    def test_scanner_discovers_go_python_flutter_ndk_awg_and_xray(self) -> None:
        """A scan that cannot see the known producer literals is incomplete."""
        by_key = {(hit.path, hit.tool, hit.field) for hit in self.report.hits}
        required = (
            ("tools/build_linux_release.sh", "go", "version"),
            ("tools/build_linux_release.sh", "xray", "version"),
            ("tools/build_linux_release.sh", "awg", "engine_version"),
            ("tools/build_xray_engine.sh", "go", "version"),
            ("tools/build_xray_engine.sh", "ndk", "version"),
            ("tools/build_xray_engine.sh", "xray", "tag"),
            ("tools/build_amneziawg_android_engine.sh", "awg", "engine_version"),
            ("linux/packaging/store_manifest_contract.py", "flutter", "version"),
            ("linux/packaging/flathub/manifest_artifact.py", "flutter", "version"),
            ("linux/packaging/snap/manifest_artifact.py", "flutter", "version"),
            ("android/app/build.gradle.kts", "ndk", "version"),
            ("android/settings.gradle.kts", "android_gradle_plugin", "version"),
            ("android/gradle/wrapper/gradle-wrapper.properties", "gradle", "distribution_version"),
            (
                "android/devicecheck/gradle/wrapper/gradle-wrapper.properties",
                "gradle",
                "distribution_version",
            ),
            ("wear_os/gradle/wrapper/gradle-wrapper.properties", "gradle", "distribution_version"),
            ("router/base-image.pin", "python", "version"),
            ("router/Dockerfile", "python", "version"),
            ("tools/build_android_release_macos.sh", "java", "version"),
            ("tools/release_openssl_archive_custody.py", "openssl", "version"),
            ("tools/release_openssl_archive_custody.py", "openssl", "source_archive_name"),
            ("tools/release_openssl_archive_custody.py", "openssl", "build_transaction"),
            ("tools/release_openssl_archive_custody.py", "openssl", "build_receipt_env"),
            (
                "tools/release_openssl_archive_custody.py",
                "openssl",
                "compiler_identity.sha256",
            ),
        )
        missing = [item for item in required if item not in by_key]
        self.assertEqual(missing, [], f"scanner missed {missing}")

    def test_discovered_authoritative_literals_match_canonical_pins(self) -> None:
        conflicts = [
            _describe_component_aware_pin_hit(hit)
            for hit in self.report.hits
            if _pin_hit_conflicts(hit)
        ]
        self.assertEqual(
            conflicts,
            [],
            "Authoritative toolchain literals disagree with "
            "tools/toolchain-pins.json or the reviewed engine pins:\n  "
            + "\n  ".join(conflicts),
        )

    def test_explicit_provenance_mirrors_exist_and_match(self) -> None:
        self.assertEqual(
            list(self.report.missing_mappings),
            [],
            "Mapped provenance/generated pin files are missing or unreadable: "
            + ", ".join(self.report.missing_mappings),
        )
        mirrors = [hit for hit in self.report.hits if hit.kind == "mirror"]
        self.assertGreaterEqual(len(mirrors), len(pin_scan.MIRROR_MAPPINGS))
        mismatched = [
            _describe_component_aware_pin_hit(hit)
            for hit in mirrors
            if _pin_hit_conflicts(hit) or not hit.mapped
        ]
        self.assertEqual(mismatched, [])

    def test_apple_awg_component_fields_match_their_own_identities(self) -> None:
        hits: list[AppleAwgComponentPinHit] = []
        script_paths = (
            "tools/build_apple_engine_wrappers.sh",
            "tools/stage_apple_engine_artifacts.sh",
            "tools/build_apple_wg_go_bridge.sh",
        )
        for relative in script_paths:
            hits.extend(
                _scan_apple_awg_component_assignments(
                    relative,
                    (ROOT / relative).read_text(encoding="utf-8"),
                )
            )

        provenance_path = "apple/EngineArtifacts/apple_awg_31_engine_provenance.json"
        provenance = json.loads((ROOT / provenance_path).read_text(encoding="utf-8"))
        for pointer, value in (
            ("source.tag", provenance["source"]["tag"]),
            ("source.commit", provenance["source"]["commit"]),
        ):
            hit = _classify_apple_awg_component_field(
                provenance_path,
                pointer,
                str(value),
            )
            self.assertIsNotNone(hit, pointer)
            assert hit is not None
            hits.append(hit)

        expected_fields = {
            (
                "tools/build_apple_engine_wrappers.sh",
                "APPLE_AWG_EXPECTED_TAG",
            ),
            (
                "tools/build_apple_engine_wrappers.sh",
                "APPLE_AWG_EXPECTED_COMMIT",
            ),
            (
                "tools/stage_apple_engine_artifacts.sh",
                "APPLE_AWG_EXPECTED_TAG",
            ),
            (
                "tools/stage_apple_engine_artifacts.sh",
                "APPLE_AWG_EXPECTED_COMMIT",
            ),
            ("tools/build_apple_wg_go_bridge.sh", "AMNEZIAWG_APPLE_TAG"),
            ("tools/build_apple_wg_go_bridge.sh", "AMNEZIAWG_APPLE_COMMIT"),
            ("tools/build_apple_wg_go_bridge.sh", "AMNEZIAWG_GO_TAG"),
            ("tools/build_apple_wg_go_bridge.sh", "AMNEZIAWG_GO_COMMIT"),
            (provenance_path, "source.tag"),
            (provenance_path, "source.commit"),
        }
        self.assertEqual({(hit.path, hit.symbol) for hit in hits}, expected_fields)
        self.assertEqual([hit.describe() for hit in hits if hit.conflict], [])

    def test_apple_awg_cross_component_substitutions_are_conflicts(self) -> None:
        wrapper = APPLE_AWG_COMPONENT_IDENTITIES["wrapper"]
        engine = APPLE_AWG_COMPONENT_IDENTITIES["embedded_engine"]
        # amneziawg-apple and amneziawg-go use independent upstream version
        # schemes (tools/build_apple_wg_go_bridge.sh). Since 705bedd the
        # shipped wrapper v3.1.20260814 embeds engine v3.1.20260828, so a tag
        # swapped across components is a conflict just like a swapped commit.
        self.assertNotEqual(wrapper["tag"], engine["tag"])
        self.assertNotEqual(wrapper["commit"], engine["commit"])
        substitutions = (
            (
                "apple/EngineArtifacts/apple_awg_31_engine_provenance.json",
                "source.commit",
                engine["commit"],
            ),
            (
                "apple/EngineArtifacts/apple_awg_31_engine_provenance.json",
                "source.tag",
                engine["tag"],
            ),
            (
                "tools/build_apple_engine_wrappers.sh",
                "APPLE_AWG_EXPECTED_COMMIT",
                engine["commit"],
            ),
            (
                "tools/build_apple_engine_wrappers.sh",
                "APPLE_AWG_EXPECTED_TAG",
                engine["tag"],
            ),
            (
                "tools/build_apple_wg_go_bridge.sh",
                "AMNEZIAWG_GO_COMMIT",
                wrapper["commit"],
            ),
            (
                "tools/build_apple_wg_go_bridge.sh",
                "AMNEZIAWG_GO_TAG",
                wrapper["tag"],
            ),
        )
        for path, symbol, substituted_value in substitutions:
            with self.subTest(path=path, symbol=symbol):
                hit = _classify_apple_awg_component_field(
                    path,
                    symbol,
                    substituted_value,
                )
                self.assertIsNotNone(hit)
                assert hit is not None
                self.assertTrue(hit.conflict, hit.describe())

        scanner_hits = pin_scan.scan_text(
            "tools/build_apple_engine_wrappers.sh",
            f'APPLE_AWG_EXPECTED_COMMIT="{engine["commit"]}"\n',
            self.canonical,
        )
        self.assertEqual(len(scanner_hits), 1, scanner_hits)
        self.assertFalse(scanner_hits[0].conflict, scanner_hits[0].describe())
        self.assertTrue(
            _pin_hit_conflicts(scanner_hits[0]),
            _describe_component_aware_pin_hit(scanner_hits[0]),
        )

        engine_hits = pin_scan.scan_text(
            "tools/build_linux_release.sh",
            f'AWG_GO_COMMIT="{wrapper["commit"]}"\n',
            self.canonical,
        )
        self.assertEqual(len(engine_hits), 1, engine_hits)
        self.assertTrue(
            _pin_hit_conflicts(engine_hits[0]),
            _describe_component_aware_pin_hit(engine_hits[0]),
        )

    def test_apple_awg_identities_match_the_shipped_engine_bytes(self) -> None:
        # The provenance JSON names the wrapper; only the Go build info inside
        # the shipped dylibs names the embedded amneziawg-go version.
        provenance = json.loads(
            (ROOT / "apple/EngineArtifacts/apple_awg_31_engine_provenance.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(
            provenance["source"]["repository"],
            "https://github.com/amnezia-vpn/amneziawg-apple.git",
        )
        engine_dep = re.compile(
            rb"\ndep\tgithub\.com/amnezia-vpn/amneziawg-go/v3\t(v[0-9][^\t\n]*)\t"
        )
        for relative in (
            "apple/EngineArtifacts/macos/libWinsAmneziaWGPacketEngine.dylib",
            "apple/EngineArtifacts/ios/iphoneos/libWinsAmneziaWGPacketEngine.dylib",
        ):
            with self.subTest(artifact=relative):
                data = (ROOT / relative).read_bytes()
                self.assertTrue(
                    b"path\tgithub.com/amnezia-vpn/amneziawg-apple\n"
                    b"mod\tgithub.com/amnezia-vpn/amneziawg-apple\t" in data,
                    "the Go build info does not name amneziawg-apple as main module",
                )
                versions = {m.decode("ascii") for m in engine_dep.findall(data)}
                self.assertEqual(
                    versions,
                    {APPLE_AWG_COMPONENT_IDENTITIES["embedded_engine"]["tag"]},
                )

    def test_unmapped_provenance_json_is_rejected(self) -> None:
        self.assertEqual(
            list(self.report.unmapped_mirrors),
            [],
            "Generated/provenance pin copies must be listed as explicit "
            "path+field mappings:\n  "
            + "\n  ".join(self.report.unmapped_mirrors),
        )

    def test_release_paths_reject_latest_range_and_floating_selectors(self) -> None:
        floating = [item.describe() for item in self.report.floating]
        self.assertEqual(
            floating,
            [],
            "Release/build/packaging/installer/deployment paths contain "
            "floating toolchain selectors:\n  " + "\n  ".join(floating),
        )

    def test_docs_and_tests_are_not_authoritative_pin_sites(self) -> None:
        for hit in self.report.hits:
            role = pin_scan.path_role(hit.path)
            self.assertEqual(
                role,
                "authoritative",
                f"scanner leaked a {role} path: {hit.describe()}",
            )
        stale = 'GO_VERSION="1.26.0"\nXRAY_VERSION="1.8.4"\nndkVersion = "26.1.10909125"\n'
        self.assertEqual(
            pin_scan.scan_text("docs/example.md", stale, self.canonical),
            [],
        )
        self.assertEqual(
            pin_scan.scan_text("tools/test_example.py", stale, self.canonical),
            [],
        )
        self.assertEqual(
            pin_scan.scan_text("linux/packaging/tests/test_pins.py", stale, self.canonical),
            [],
        )
        self.assertEqual(pin_scan.scan_floating("docs/example.md", "FROM python:latest\n"), [])
        self.assertEqual(
            pin_scan.scan_floating("tools/test_example.py", "GO_VERSION=latest\n"),
            [],
        )

    def test_stale_assignment_mutation_is_a_conflict(self) -> None:
        hits = pin_scan.scan_text(
            "tools/build_linux_release.sh",
            'GO_VERSION="1.26.0"\n',
            self.canonical,
        )
        go_hits = [hit for hit in hits if hit.tool == "go" and hit.kind == "assignment"]
        self.assertTrue(go_hits)
        self.assertTrue(all(hit.conflict for hit in go_hits))

    def test_stale_hidden_url_mutation_is_a_conflict(self) -> None:
        hits = pin_scan.scan_text(
            "installer/windows/build_installer.ps1",
            "https://go.dev/dl/go1.26.0.windows-amd64.zip\n",
            self.canonical,
        )
        hidden = [hit for hit in hits if hit.kind == "url_token" and hit.tool == "go"]
        self.assertTrue(hidden)
        self.assertTrue(all(hit.conflict for hit in hidden))

    def test_stale_node_openssl_chrome_and_jdk_literals_conflict(self) -> None:
        text = (
            'NODE_VERSION="v18.20.0"\n'
            'OPENSSL_VERSION="3.5.0"\n'
            "chrome-mac-arm64-120.0.6099.109.zip\n"
            'JAVA_VERSION="17.0.1"\n'
        )
        hits = pin_scan.scan_text("tools/build_linux_release.sh", text, self.canonical)
        by_tool = {hit.tool: hit for hit in hits if hit.conflict}
        for tool in ("node", "openssl", "browser", "java"):
            self.assertIn(tool, by_tool, f"missing stale {tool} hit: {hits}")

    def test_hidden_duplicate_path_token_is_discovered(self) -> None:
        version = self.canonical["flutter"]["version"]
        hits = pin_scan.scan_text(
            "tools/build_android_release_macos.sh",
            f"dir=flutter-{version}-extract\n",
            self.canonical,
        )
        tokens = [
            hit
            for hit in hits
            if hit.kind == "path_token" and hit.tool == "flutter"
        ]
        self.assertTrue(tokens)
        self.assertTrue(all(not hit.conflict for hit in tokens))
        self.assertTrue(all(not hit.mapped for hit in tokens))

    def test_stale_hidden_duplicate_in_packaging_is_a_conflict(self) -> None:
        hits = pin_scan.scan_text(
            "linux/packaging/store_manifest_contract.py",
            'REVIEWED_FLUTTER_VERSION = "3.44.6"\n',
            self.canonical,
        )
        flutter = [hit for hit in hits if hit.tool == "flutter" and hit.field == "version"]
        self.assertTrue(flutter)
        self.assertTrue(all(hit.conflict for hit in flutter))

    def test_isolated_tree_mutation_flags_stale_and_hidden_duplicates(self) -> None:
        """Mutations stay on a private copy. The shared tree is not written."""
        with tempfile.TemporaryDirectory() as tmp:
            fake = pathlib.Path(tmp)
            (fake / "tools").mkdir()
            (fake / "docs").mkdir()
            (fake / "installer/windows").mkdir(parents=True)
            (fake / "tools" / "toolchain-pins.json").write_text(
                MANIFEST_PATH.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            (fake / "tools" / "build_linux_release.sh").write_text(
                'GO_VERSION="1.26.0"\n'
                "curl https://go.dev/dl/go1.26.0.linux-amd64.tar.gz\n",
                encoding="ascii",
            )
            (fake / "docs" / "notes.md").write_text(
                'GO_VERSION="1.26.0"\nFROM python:latest\n',
                encoding="ascii",
            )
            (fake / "tools" / "test_fake.py").write_text(
                'XRAY_VERSION="1.8.4"\n',
                encoding="ascii",
            )
            report = pin_scan.scan_repository(fake, manifest=MANIFEST)
            conflicts = [hit.describe() for hit in report.conflicts]
            self.assertTrue(
                any("tools/build_linux_release.sh" in item and "go.version" in item for item in conflicts),
                conflicts,
            )
            leaked = [
                hit.path
                for hit in report.hits
                if hit.path.startswith("docs/") or hit.path.startswith("tools/test_")
            ]
            self.assertEqual(leaked, [])

    def test_two_symbols_with_one_value_in_one_file_are_both_reported(self) -> None:
        # R24 V2 F-02: the repository dedup key omitted the symbol, so a file
        # assigning the wrapper commit to both the wrapper symbol and the engine
        # symbol kept one hit, and the component-aware layer saw no conflict.
        wrapper = APPLE_AWG_COMPONENT_IDENTITIES["wrapper"]
        with tempfile.TemporaryDirectory() as tmp:
            fake = pathlib.Path(tmp)
            (fake / "tools").mkdir()
            (fake / "tools" / "toolchain-pins.json").write_text(
                MANIFEST_PATH.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            (fake / "tools" / "build_apple_engine_wrappers.sh").write_text(
                f'APPLE_AWG_EXPECTED_COMMIT="{wrapper["commit"]}"\n'
                f'AWG_GO_COMMIT="{wrapper["commit"]}"\n',
                encoding="ascii",
            )
            report = pin_scan.scan_repository(fake, manifest=MANIFEST)
            symbols = {
                hit.symbol
                for hit in report.hits
                if hit.path == "tools/build_apple_engine_wrappers.sh"
            }
            self.assertEqual(symbols, {"APPLE_AWG_EXPECTED_COMMIT", "AWG_GO_COMMIT"})
            self.assertEqual(
                [hit.symbol for hit in report.hits if _pin_hit_conflicts(hit)],
                ["AWG_GO_COMMIT"],
            )

    def test_floating_selector_mutation_is_rejected(self) -> None:
        hits = pin_scan.scan_floating(
            "tools/build_linux_release.sh",
            'GO_VERSION="latest"\nFROM python:latest\ngo install golang.org/x/tools/gopls@latest\n',
        )
        selectors = {item.selector for item in hits}
        self.assertIn("latest", selectors)
        self.assertIn("@latest", selectors)
        self.assertTrue(any(item.selector.startswith("python:") for item in hits))

    def test_range_selector_mutation_is_rejected(self) -> None:
        hits = pin_scan.scan_floating(
            "linux/packaging/install.sh",
            'PYTHON_VERSION=">=3.14"\nFLUTTER_VERSION="^3.47.6"\n',
        )
        self.assertTrue(hits)
        self.assertTrue(all(item.path == "linux/packaging/install.sh" for item in hits))

    def test_unmapped_provenance_json_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = pathlib.Path(tmp)
            (fake / "tools").mkdir()
            (fake / "tools" / "toolchain-pins.json").write_text(
                MANIFEST_PATH.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            (fake / "tools" / "extra-engine-provenance.json").write_text(
                json.dumps({"go_version": self.canonical["go"]["version"]}),
                encoding="ascii",
            )
            report = pin_scan.scan_repository(fake, manifest=MANIFEST)
            self.assertTrue(
                any("extra-engine-provenance.json" in item for item in report.unmapped_mirrors),
                report.unmapped_mirrors,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
