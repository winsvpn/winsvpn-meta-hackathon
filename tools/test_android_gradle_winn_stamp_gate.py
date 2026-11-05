#!/usr/bin/env python3
"""Compiles and runs the Gradle release gate's Winn stamp check for real.

android/app/build.gradle.kts verifyWinnReleaseStamp is extracted verbatim,
wrapped with stand-ins for the two Gradle properties it touches (projectDir and
rootProject.file), compiled with the Kotlin compiler that ships inside the
pinned Gradle distribution (kotlin-compiler-embeddable, groovy-json), and run
on the JDK against stamps made here: one genuinely signed by the pinned (test)
key, one fabricated without a signature, one signed by another key, one whose
engine changed, and one whose signed manifest lacks the ABI's target. Only the
genuine stamp may pass.

Skipped when java or the Gradle distribution's compiler jars are not on this
host. No network and no Gradle daemon are involved.
"""

from __future__ import annotations

import base64
import glob
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
GRADLE_SCRIPT = ROOT / "android" / "app" / "build.gradle.kts"
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "tools"))
import winn_release_testkit as testkit  # noqa: E402

ABI = "arm64-v8a"
TARGET = "datapath-android-arm64"
STAMP_CONTRACT = "winsvpn-winn-release-android-stage-v1"
COMPILER_JARS = (
    "kotlin-compiler-embeddable-*.jar", "kotlin-stdlib-*.jar", "kotlin-script-runtime-*.jar",
    "kotlin-reflect-*.jar", "kotlin-daemon-embeddable-*.jar", "kotlinx-coroutines-core-jvm-*.jar",
    "annotations-*.jar",
)
RUNTIME_JARS = ("kotlin-stdlib-*.jar", "groovy-json-*.jar", "groovy-[0-9]*.jar")

HARNESS_HEAD = """\
import java.io.File
{script_imports}

// Gradle's Kotlin DSL puts the project's `java` extension accessor in scope, so
// in the real script `java` names that extension before the java package. The
// stand-in reproduces that shadowing; a qualified java.security.X reference
// then fails here exactly as it fails when Gradle compiles the script.
class GradleJavaExtensionStandIn
val java = GradleJavaExtensionStandIn()

val projectDir: File = File(System.getProperty("stub.projectDir"))

object rootProject {
    fun file(path: String): File = File(System.getProperty("stub.rootDir"), path)
}

"""
HARNESS_MAIN = """
fun main(args: Array<String>) {
    for (case in args) {
        val parts = case.split("|")
        val problem = verifyWinnReleaseStamp(parts[0], File(parts[1]), File(parts[2]))
        println(if (problem == null) "ACCEPTED" else "REFUSED " + problem)
    }
}
"""


def gradle_lib() -> pathlib.Path | None:
    pattern = os.path.expanduser("~/.gradle/wrapper/dists/gradle-*/*/gradle-*/lib")
    for candidate in sorted(glob.glob(pattern), reverse=True):
        lib = pathlib.Path(candidate)
        if all(glob.glob(str(lib / jar)) for jar in COMPILER_JARS + RUNTIME_JARS):
            return lib
    return None


def classpath(lib: pathlib.Path, patterns: tuple[str, ...]) -> str:
    return ":".join(sorted(glob.glob(str(lib / pattern)))[0] for pattern in patterns)


def script_imports(text: str) -> str:
    """The script's own java.* imports, so the harness resolves names as Gradle does."""
    return "\n".join(line for line in text.splitlines() if line.startswith("import java."))


def extract_gate(text: str) -> str:
    """The exact Gradle declarations the stamp check uses, in source order."""
    safe_start = text.index("fun isSafeNonEmptyReleaseInput(")
    safe_end = text.index("\n\n", safe_start)
    stamp_start = text.index("val winnReleaseStampName")
    stamp_end = text.index("fun verifyAndroidReleaseEngineInputs()")
    return text[safe_start:safe_end] + "\n\n" + text[stamp_start:stamp_end]


@unittest.skipUnless(shutil.which("java") and gradle_lib() is not None,
                     "java and the Gradle distribution's Kotlin compiler are needed")
class GradleWinnStampGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="gradle-winn-stamp.")).resolve()
        lib = gradle_lib()
        assert lib is not None
        source = cls.tmp / "Gate.kt"
        script = GRADLE_SCRIPT.read_text(encoding="utf-8")
        source.write_text(HARNESS_HEAD.replace("{script_imports}", script_imports(script))
                          + extract_gate(script) + HARNESS_MAIN, encoding="utf-8")
        cls.runtime = classpath(lib, RUNTIME_JARS)
        compiled = subprocess.run(
            ["java", "-cp", classpath(lib, COMPILER_JARS), "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler",
             "-no-stdlib", "-no-reflect", "-cp", cls.runtime, "-d", str(cls.tmp / "classes"), str(source)],
            capture_output=True, text=True, timeout=600, check=False,
        )
        if compiled.returncode != 0:
            shutil.rmtree(cls.tmp, ignore_errors=True)
            raise AssertionError("the Gradle stamp gate does not compile:\n" + compiled.stderr[-4000:])

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self) -> None:
        self.case = pathlib.Path(tempfile.mkdtemp(dir=self.tmp))
        self.android = self.case / "android"
        self.app = self.android / "app"
        (self.case / "tools").mkdir(parents=True)
        (self.case / "tools" / "winn_release_authority.json").write_bytes(
            testkit.authority_document(testkit.TEST_SEED))
        self.engine = self.app / "src" / "release" / "jniLibs" / ABI / "libwinnengine.so"
        self.engine.parent.mkdir(parents=True)
        self.engine.write_bytes(b"\x7fELF arm64 winn engine bytes")
        self.counter = 0

    def stamp(self, *, seed: bytes | None = testkit.TEST_SEED, target: str = TARGET,
              fabricated: bool = False) -> pathlib.Path:
        self.counter += 1
        path = self.app / "src" / "release" / f"winn-release-{self.counter}.json"
        digest = hashlib.sha256(self.engine.read_bytes()).hexdigest()
        engines = {ABI: {"sha256": digest, "size": self.engine.stat().st_size, "target": TARGET}}
        if fabricated:
            document = {"contract": STAMP_CONTRACT, "engines": engines, "signed": True,
                        "release_manifest_sha256": "cd" * 32,
                        "signature_public_key": testkit.public_key_hex(), "source_commit": "1" * 40}
        else:
            release = self.case / f"release-{self.counter}"
            testkit.write_release(release, {target: ("libwinnengine.so", self.engine.read_bytes())},
                                  seed=seed)
            raw = (release / "manifest.json").read_bytes()
            signature = json.loads((release / "manifest.sig.json").read_text())["signature"]
            document = {"contract": STAMP_CONTRACT, "engines": engines, "signed": True,
                        "manifest_b64": base64.b64encode(raw).decode("ascii"),
                        "manifest_signature": signature,
                        "release_manifest_sha256": hashlib.sha256(raw).hexdigest(),
                        "signature_public_key": testkit.public_key_hex(), "source_commit": "1" * 40}
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def run_gate(self, *stamps: pathlib.Path) -> list[str]:
        result = subprocess.run(
            ["java", f"-Dstub.projectDir={self.app}", f"-Dstub.rootDir={self.android}",
             "-cp", f"{self.tmp / 'classes'}:{self.runtime}", "GateKt",
             *[f"{ABI}|{self.engine}|{stamp}" for stamp in stamps]],
            capture_output=True, text=True, timeout=120, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines()

    def test_only_a_stamp_signed_by_the_pinned_key_passes(self) -> None:
        genuine = self.stamp()
        fabricated = self.stamp(fabricated=True)
        other_key = self.stamp(seed=testkit.WRONG_SEED)
        missing_target = self.stamp(target="datapath-android-amd64")
        lines = self.run_gate(genuine, fabricated, other_key, missing_target)
        self.assertEqual(lines[0], "ACCEPTED")
        self.assertTrue(lines[1].startswith("REFUSED "), lines[1])
        self.assertIn("missing signed manifest", lines[1])
        self.assertTrue(lines[2].startswith("REFUSED "), lines[2])
        self.assertIn("release signature does not verify", lines[2])
        self.assertTrue(lines[3].startswith("REFUSED "), lines[3])
        self.assertIn("expected exactly one entry", lines[3])

    def test_gate_compiles_with_the_gradle_java_extension_in_scope(self) -> None:
        # setUpClass compiled the gate with `java` shadowed as in a Gradle
        # script; a qualified java.security.X reference fails that compile.
        self.assertTrue((self.tmp / "classes" / "GateKt.class").is_file())
        script = GRADLE_SCRIPT.read_text(encoding="utf-8")
        body = "\n".join(line for line in script.splitlines() if not line.startswith("import "))
        self.assertNotIn("java.security.", body)

    def test_changed_engine_bytes_are_refused(self) -> None:
        genuine = self.stamp()
        self.engine.write_bytes(b"\x7fELF arm64 different engine bytes")
        lines = self.run_gate(genuine)
        self.assertTrue(lines[0].startswith("REFUSED "), lines[0])
        self.assertIn("staged engine differs from the signed manifest", lines[0])


if __name__ == "__main__":
    unittest.main()
