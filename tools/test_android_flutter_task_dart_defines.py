#!/usr/bin/env python3
"""Behavioural gate: the Winn v3 defines must reach every Android FlutterTask.

The source-text tests (test/android_winn3_dual_auth_define_test.dart and
tools/test_winn3_release_enablement.py) decode the list written in
android/app/build.gradle.kts. They passed while the measured Android builds
carried none of those defines from the Gradle file: the old injection ran in a
configureEach action on FlutterTask, which Gradle executes BEFORE the Flutter
plugin's own `tasks.register(...) { dartDefines = dartDefinesValue }` action,
so the plugin overwrote it with the CLI value (MEASURED 2026-09-23 on
Flutter 3.44.6 / Gradle 9.7.1).

This test asks Gradle instead of the source:

* Merge policy. The real app project is configured in dry-run mode (-m,
  nothing executes) with an init script whose task-graph listener runs after
  the build script's, and FlutterTask.dartDefines is read: the exact field
  BaseFlutterTaskHelper turns into `flutter assemble --DartDefines=`. Every
  variant is probed, and every conflict case runs as its own Gradle
  invocation naming one task, so a rejection by one variant cannot hide a
  missing rejection in another.
* Execution guard. The FlutterTask really executes (`--rerun`), with its
  flutter executable swapped for a stub that records its argv to a marker
  file and exits non-zero. A listener that runs after the merge then removes,
  duplicates or changes an owned define, or unresolves buildMode. The guard
  must fail the task and the marker must not exist: the compiler was never
  invoked. A control run without mutation must create the marker, so the
  harness itself is proven able to see an invocation.

Test hooks exist only as init scripts written into a temporary directory and
passed with -I to the Gradle invocations below. Nothing in the repository
build reads a hook property or file, so a real build cannot enable one.

Expected values come from the canonical reviewed ring in
tools/winn3_descriptor_ring_defines.py, not from the Gradle file under test.

It needs the Android toolchain the app already needs (android/local.properties
with flutter.sdk, a JDK, the Gradle offline cache). A missing toolchain is a
FAILURE, never a skip: a skip would count as success in tools/run_test_suite.py.
All Gradle calls share one aggregate deadline below the runner's 120 s limit.
"""

from __future__ import annotations

import base64
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

TOOLS = pathlib.Path(__file__).resolve().parent
ROOT = TOOLS.parent
ANDROID = ROOT / "android"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from winn3_descriptor_ring_defines import RING, REVIEWED_RING_SHA256  # noqa: E402

AGGREGATE_BUDGET_SECONDS = 110.0
_DEADLINE = time.monotonic() + AGGREGATE_BUDGET_SECONDS
PROBE_PREFIX = "WINN3PROBE"

RING_DEFINES = {
    "WINS_WINN3_DESCRIPTOR_PUBKEY_G1": RING["g1"],
    "WINS_WINN3_DESCRIPTOR_PUBKEY_G2": RING["g2"],
    "WINS_WINN3_DESCRIPTOR_PUBKEY_G3": RING["g3"],
    "WINS_WINN3_DESCRIPTOR_RING_SHA256": REVIEWED_RING_SHA256,
}
GATE_DEFINES = {
    "WINS_WINN3_ENABLED_PLATFORMS": "android",
    "WINS_WINN3_DUAL_AUTH": "true",
}
EXPECTED = {**RING_DEFINES, **GATE_DEFINES}
EXPECTED_ENTRIES = [f"{k}={v}" for k, v in EXPECTED.items()]
CONFLICTING = {
    "WINS_WINN3_DESCRIPTOR_PUBKEY_G1": base64.b64encode(b"\x01" * 32).decode("ascii"),
    "WINS_WINN3_DESCRIPTOR_PUBKEY_G2": base64.b64encode(b"\x02" * 32).decode("ascii"),
    "WINS_WINN3_DESCRIPTOR_PUBKEY_G3": base64.b64encode(b"\x03" * 32).decode("ascii"),
    "WINS_WINN3_DESCRIPTOR_RING_SHA256": "0" * 64,
}

ACTIVATING_TASKS = (
    ":app:compileFlutterBuildPhoneDebug",
    ":app:compileFlutterBuildPhoneRelease",
    ":app:compileFlutterBuildPhoneQa",
    ":app:compileFlutterBuildTvDebug",
    ":app:compileFlutterBuildTvRelease",
    ":app:compileFlutterBuildTvQa",
)
PROFILE_TASKS = (
    ":app:compileFlutterBuildPhoneProfile",
    ":app:compileFlutterBuildTvProfile",
)
ALL_TASKS = ACTIVATING_TASKS + PROFILE_TASKS

FLUTTER_TASK_MATCH = "it.class.name.startsWith('com.flutter.gradle.tasks.FlutterTask')"

PROBE_INIT = """
gradle.projectsEvaluated {
    gradle.taskGraph.whenReady { graph ->
        graph.allTasks.findAll { %(match)s }.each { t ->
            def raw = t.dartDefines
            println "%(p)s task ${t.path} ${raw == null ? '' : raw}"
        }
    }
}
""" % {"match": FLUTTER_TASK_MATCH, "p": PROBE_PREFIX}

# Registered at init time, so it runs BEFORE the build script's listener.
PRE_MERGE_INIT = """
gradle.taskGraph.whenReady { graph ->
    graph.allTasks.findAll { %(match)s }.each { t -> t.buildMode = %(mode)s }
}
"""

# Registered in projectsEvaluated, so it runs AFTER the build script's merge.
POST_MERGE_INIT = """
def winn3Name = { String blob -> new String(blob.decodeBase64(), 'UTF-8').split('=')[0] }
def winn3Blob = { String entry -> entry.bytes.encodeBase64().toString() }
gradle.projectsEvaluated {
    gradle.taskGraph.whenReady { graph ->
        graph.allTasks.findAll { %(match)s }.each { t ->
            t.flutterExecutable = new File('%(stub)s')
            def blobs = (t.dartDefines ?: '').split(',').findAll { it }
            %(mutation)s
        }
    }
}
"""

MUTATIONS = {
    "none": "",
    "remove_dual_auth": "t.dartDefines = blobs.findAll { winn3Name(it) != 'WINS_WINN3_DUAL_AUTH' }.join(',')",
    "remove_ring_sha": "t.dartDefines = blobs.findAll { winn3Name(it) != 'WINS_WINN3_DESCRIPTOR_RING_SHA256' }.join(',')",
    "duplicate_g1": "t.dartDefines = (blobs + blobs.findAll { winn3Name(it) == 'WINS_WINN3_DESCRIPTOR_PUBKEY_G1' }).join(',')",
    "change_ring_sha": (
        "t.dartDefines = (blobs.findAll { winn3Name(it) != 'WINS_WINN3_DESCRIPTOR_RING_SHA256' }"
        " + [winn3Blob('WINS_WINN3_DESCRIPTOR_RING_SHA256=" + "0" * 64 + "')]).join(',')"
    ),
    "change_g2": (
        "t.dartDefines = (blobs.findAll { winn3Name(it) != 'WINS_WINN3_DESCRIPTOR_PUBKEY_G2' }"
        " + [winn3Blob('WINS_WINN3_DESCRIPTOR_PUBKEY_G2=" + CONFLICTING["WINS_WINN3_DESCRIPTOR_PUBKEY_G2"] + "')]).join(',')"
    ),
    "add_duplicate_identical_ring_sha": (
        "t.dartDefines = (blobs + [winn3Blob('WINS_WINN3_DESCRIPTOR_RING_SHA256=" + REVIEWED_RING_SHA256 + "')] * 2).join(',')"
    ),
    "build_mode_null": "t.buildMode = null",
    "build_mode_blank": "t.buildMode = ''",
    "build_mode_bogus": "t.buildMode = 'jit_release'",
}


def _encode(entry: str) -> str:
    return base64.b64encode(entry.encode("utf-8")).decode("ascii")


def _decode_csv(raw: str) -> list[str]:
    return [
        base64.b64decode(blob, validate=True).decode("utf-8")
        for blob in raw.split(",")
        if blob.strip()
    ]


def _toolchain_problem() -> str | None:
    local = ANDROID / "local.properties"
    if not local.is_file():
        return "android/local.properties is absent: this checkout cannot configure Android"
    for line in local.read_text(encoding="utf-8").splitlines():
        if line.startswith("flutter.sdk="):
            sdk = pathlib.Path(line.split("=", 1)[1].strip())
            if (sdk / "packages" / "flutter_tools" / "gradle").is_dir():
                return None
            return f"flutter.sdk {sdk} has no packages/flutter_tools/gradle"
    return "android/local.properties has no flutter.sdk"


class AndroidFlutterTaskDartDefinesTest(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        problem = _toolchain_problem()
        if problem is not None:
            raise AssertionError(f"Android toolchain required, not skipping: {problem}")
        cls._tmp = tempfile.TemporaryDirectory(prefix="winn3-probe-")
        cls.tmp = pathlib.Path(cls._tmp.name)
        cls.probe = cls.tmp / "probe.init.gradle"
        cls.probe.write_text(PROBE_INIT, encoding="utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def _gradle(self, extra: list[str], tasks: list[str]) -> subprocess.CompletedProcess[str]:
        remaining = _DEADLINE - time.monotonic()
        if remaining <= 1:
            self.fail(f"aggregate Gradle deadline of {AGGREGATE_BUDGET_SECONDS:.0f}s exhausted")
        return subprocess.run(
            [str(ANDROID / "gradlew"), "--offline", "-q", *extra, *tasks],
            cwd=ANDROID,
            env=dict(os.environ),
            capture_output=True,
            text=True,
            timeout=remaining,
            check=False,
        )

    def _cli(self, entries: list[str] | None) -> list[str]:
        if entries is None:
            return []
        return ["-Pdart-defines=" + ",".join(_encode(e) for e in entries)]

    def _probe(self, cli: list[str] | None, tasks: tuple[str, ...]) -> dict[str, list[str]]:
        completed = self._gradle(["-m", "-I", str(self.probe), *self._cli(cli)], list(tasks))
        self.assertEqual(
            completed.returncode,
            0,
            f"gradle dry-run failed:\n{completed.stdout[-3000:]}\n{completed.stderr[-3000:]}",
        )
        seen: dict[str, list[str]] = {}
        for line in completed.stdout.splitlines():
            if line.startswith(PROBE_PREFIX + " task "):
                parts = line.split(" ", 3)
                seen[parts[2]] = _decode_csv(parts[3] if len(parts) > 3 else "")
        self.assertEqual(
            sorted(seen),
            sorted(tasks),
            "the probe must observe every requested FlutterTask; an empty observation is not a pass",
        )
        return seen

    def _assert_rejected(self, completed: subprocess.CompletedProcess[str], needle: str) -> None:
        output = completed.stdout + completed.stderr
        self.assertNotEqual(completed.returncode, 0, output[-2000:])
        self.assertIn(needle, output)

    def _assert_activated(self, task: str, entries: list[str]) -> None:
        for name, value in EXPECTED.items():
            self.assertEqual(
                [e for e in entries if e.split("=", 1)[0] == name],
                [f"{name}={value}"],
                f"{task} must hand {name} to flutter assemble exactly once",
            )

    def test_without_cli_defines_every_variant_follows_its_mode_policy(self):
        seen = self._probe(None, ALL_TASKS)
        for task in ACTIVATING_TASKS:
            self._assert_activated(task, seen[task])
        for task in PROFILE_TASKS:
            self.assertEqual(
                [e for e in seen[task] if e.startswith("WINS_WINN3_")],
                [],
                f"{task}: profile receives no automatic Winn v3 defines",
            )

    def test_identical_cli_ring_is_deduplicated_and_other_defines_keep_order(self):
        cli = [
            "FOO_L16=1",
            f"WINS_WINN3_DESCRIPTOR_PUBKEY_G1={RING['g1']}",
            f"WINS_WINN3_DESCRIPTOR_RING_SHA256={REVIEWED_RING_SHA256}",
            "WINS_WINN3_ENABLED_PLATFORMS=android",
            "BAR_L16=2",
            f"WINS_WINN3_DESCRIPTOR_PUBKEY_G1={RING['g1']}",
            f"WINS_WINN3_DESCRIPTOR_RING_SHA256={REVIEWED_RING_SHA256}",
        ]
        seen = self._probe(cli, ALL_TASKS)
        for task in ACTIVATING_TASKS:
            self.assertEqual(seen[task], ["FOO_L16=1", "BAR_L16=2", *EXPECTED_ENTRIES], task)
        for task in PROFILE_TASKS:
            self.assertEqual(seen[task], cli[:5], f"{task}: identical ring repeats dropped, order kept")

    def test_profile_passes_an_explicit_activation_gate_through(self):
        for task in PROFILE_TASKS:
            with self.subTest(task=task):
                seen = self._probe(["WINS_WINN3_DUAL_AUTH=false"], (task,))
                self.assertEqual(seen[task], ["WINS_WINN3_DUAL_AUTH=false"])

    def test_every_variant_rejects_each_conflicting_ring_define_in_isolation(self):
        for task in ALL_TASKS:
            for name, value in CONFLICTING.items():
                with self.subTest(task=task, name=name):
                    completed = self._gradle(["-m", *self._cli([f"{name}={value}"])], [task])
                    self._assert_rejected(completed, f"{task}: --dart-define {name} conflicts")

    def test_activating_variants_reject_a_conflicting_gate_in_isolation(self):
        for task in ACTIVATING_TASKS:
            with self.subTest(task=task):
                completed = self._gradle(["-m", *self._cli(["WINS_WINN3_DUAL_AUTH=false"])], [task])
                self._assert_rejected(completed, f"{task}: --dart-define WINS_WINN3_DUAL_AUTH conflicts")

    def test_unresolved_build_mode_is_rejected_by_the_merge(self):
        for task, mode in (
            (":app:compileFlutterBuildPhoneDebug", "null"),
            (":app:compileFlutterBuildPhoneRelease", "''"),
            (":app:compileFlutterBuildTvProfile", "'jit_release'"),
        ):
            with self.subTest(task=task, mode=mode):
                hook = self.tmp / f"pre_{abs(hash((task, mode)))}.init.gradle"
                hook.write_text(PRE_MERGE_INIT % {"match": FLUTTER_TASK_MATCH, "mode": mode}, encoding="utf-8")
                completed = self._gradle(["-m", "-I", str(hook)], [task])
                self._assert_rejected(completed, f"{task}: Flutter buildMode")

    def _execute(self, task: str, mutation: str) -> tuple[subprocess.CompletedProcess[str], pathlib.Path]:
        case = self.tmp / f"exec_{task.rsplit(':', 1)[1]}_{mutation}"
        case.mkdir()
        marker = case / "flutter_invoked"
        stub = case / "flutter_stub.sh"
        stub.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{marker}"\nexit 3\n', encoding="utf-8")
        stub.chmod(0o755)
        hook = case / "post_merge.init.gradle"
        hook.write_text(
            POST_MERGE_INIT % {"match": FLUTTER_TASK_MATCH, "stub": stub, "mutation": MUTATIONS[mutation]},
            encoding="utf-8",
        )
        return self._gradle(["-I", str(hook)], [task, "--rerun"]), marker

    def test_execution_guard_control_reaches_the_compiler_stub(self):
        for task in (":app:compileFlutterBuildPhoneDebug", ":app:compileFlutterBuildTvProfile"):
            with self.subTest(task=task):
                completed, marker = self._execute(task, "none")
                self.assertNotEqual(completed.returncode, 0)
                self.assertTrue(marker.is_file(), f"control must invoke the stub:\n{completed.stdout[-2000:]}")
                argv = marker.read_text(encoding="utf-8").splitlines()
                encoded = [a.split("=", 1)[1] for a in argv if a.startswith("--DartDefines=")]
                entries = _decode_csv(encoded[0]) if encoded else []
                if task.endswith("Profile"):
                    self.assertEqual([e for e in entries if e.startswith("WINS_WINN3_")], [])
                else:
                    self.assertEqual(len(encoded), 1)
                    self._assert_activated(task, entries)

    def test_execution_guard_fails_before_the_compiler_on_post_merge_mutation(self):
        cases = (
            (":app:compileFlutterBuildPhoneDebug", "remove_dual_auth", "WINS_WINN3_DUAL_AUTH does not match"),
            (":app:compileFlutterBuildPhoneDebug", "duplicate_g1", "WINS_WINN3_DESCRIPTOR_PUBKEY_G1 does not match"),
            (":app:compileFlutterBuildPhoneDebug", "change_ring_sha", "WINS_WINN3_DESCRIPTOR_RING_SHA256 does not match"),
            (":app:compileFlutterBuildPhoneRelease", "remove_ring_sha", "WINS_WINN3_DESCRIPTOR_RING_SHA256 does not match"),
            (":app:compileFlutterBuildTvQa", "change_g2", "WINS_WINN3_DESCRIPTOR_PUBKEY_G2 does not match"),
            (":app:compileFlutterBuildPhoneProfile", "change_ring_sha", "WINS_WINN3_DESCRIPTOR_RING_SHA256 does not match"),
            (":app:compileFlutterBuildTvProfile", "add_duplicate_identical_ring_sha", "WINS_WINN3_DESCRIPTOR_RING_SHA256 does not match"),
            # A null buildMode never reaches doFirst: buildMode is a required
            # @Input (BaseFlutterTask.kt), so Gradle's own input validation
            # fails the task first. Either way the compiler must not run.
            (":app:compileFlutterBuildPhoneDebug", "build_mode_null", "property 'buildMode' doesn't have a configured value"),
            (":app:compileFlutterBuildTvRelease", "build_mode_blank", "Flutter buildMode ''"),
            (":app:compileFlutterBuildPhoneProfile", "build_mode_bogus", "Flutter buildMode 'jit_release'"),
        )
        for task, mutation, needle in cases:
            with self.subTest(task=task, mutation=mutation):
                completed, marker = self._execute(task, mutation)
                self._assert_rejected(completed, needle if mutation == "build_mode_null" else f"{task}: {needle}")
                self.assertFalse(marker.exists(), f"{task} {mutation}: the compiler stub was invoked")


if __name__ == "__main__":
    unittest.main()
