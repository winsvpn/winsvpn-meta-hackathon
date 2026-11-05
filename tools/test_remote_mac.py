import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from typing import Optional


ROOT = pathlib.Path(__file__).resolve().parents[1]
REMOTE_MAC = (ROOT / "tools/remote_mac.ps1").read_text(encoding="utf-8")
ZSH = pathlib.Path("/bin/zsh")
LOCK_START = REMOTE_MAC.index("REMOTE_FLUTTER_LOCK_DIR=")
LOCK_END = REMOTE_MAC.index("\n'@\n", LOCK_START)
REMOTE_FLUTTER_LOCK = REMOTE_MAC[LOCK_START:LOCK_END]
RESOLVER_START = REMOTE_MAC.index("resolve_reviewed_flutter() {")
RESOLVER_END = REMOTE_MAC.index("\n'@\n", RESOLVER_START)
REMOTE_FLUTTER_RESOLVER = REMOTE_MAC[RESOLVER_START:RESOLVER_END]


def action_block(action: str, next_action: Optional[str] = None) -> str:
    start = REMOTE_MAC.index(f"    '{action}' {{")
    if next_action is None:
        return REMOTE_MAC[start:]
    end = REMOTE_MAC.index(f"    '{next_action}' {{", start)
    return REMOTE_MAC[start:end]


class RemoteMacTests(unittest.TestCase):
    @staticmethod
    def manifest_pin() -> tuple[str, str]:
        manifest = json.loads(
            (ROOT / "tools/toolchain-pins.json").read_text(encoding="utf-8")
        )
        return (
            manifest["tools"]["flutter"]["version"],
            manifest["tools"]["flutter"]["revision"],
        )

    def run_fake_managed_flutter(
        self,
        framework_version: str,
        framework_revision: str,
        pin_version: Optional[str] = None,
        pin_revision: Optional[str] = None,
    ) -> subprocess.CompletedProcess:
        if pin_version is None or pin_revision is None:
            pv, pr = self.manifest_pin()
            pin_version = pin_version or pv
            pin_revision = pin_revision or pr
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            pin_dir = home / "tools"
            pin_dir.mkdir(parents=True)
            (pin_dir / "toolchain-pins.json").write_text(
                json.dumps(
                    {
                        "tools": {
                            "flutter": {
                                "version": pin_version,
                                "revision": pin_revision,
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            flutter = (
                home
                / "Library/Application Support/WinsVPN/toolchains"
                / f"flutter-{pin_version}-extract/flutter/bin/flutter"
            )
            flutter.parent.mkdir(parents=True)
            flutter.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' "
                f"'{{\"frameworkVersion\":\"{framework_version}\","
                f"\"frameworkRevision\":\"{framework_revision}\"}}'\n",
                encoding="utf-8",
            )
            flutter.chmod(0o755)
            environment = os.environ.copy()
            environment["HOME"] = str(home)
            environment["PATH"] = "/usr/bin:/bin"
            return subprocess.run(
                [
                    "/bin/zsh",
                    "-c",
                    "set -e\n"
                    + REMOTE_FLUTTER_RESOLVER
                    + '\nprintf \'resolved=%s\\n\' "$REVIEWED_FLUTTER"\n',
                ],
                cwd=str(home),
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )

    def run_lock_script(self, body: str) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as temporary:
            return subprocess.run(
                [
                    str(ZSH),
                    "-c",
                    "set -e\ncd \"$1\"\n" + REMOTE_FLUTTER_LOCK + "\n" + body,
                    "remote-mac-lock-test",
                    temporary,
                ],
                check=False,
                capture_output=True,
                text=True,
            )

    @staticmethod
    def arm_lock_trap() -> str:
        return (
            "trap remote_flutter_lock_on_exit EXIT\n"
            "trap 'exit 129' HUP\n"
            "trap 'exit 130' INT\n"
            "trap 'exit 143' TERM\n"
        )

    def test_resolver_prefers_pinned_user_managed_flutter(self) -> None:
        self.assertNotIn("/Users/winsvpn/development/flutter/bin/flutter", REMOTE_MAC)
        # The resolver must derive the reviewed version and revision from
        # tools/toolchain-pins.json at run time, never from literals -- the
        # whole point of the refactor is that a bare value here would
        # desynchronise on the next pin bump.
        self.assertNotIn("required_version='3.44.6'", REMOTE_MAC)
        self.assertNotIn("required_revision='ee80f08bbf97172ec030b8751ceab557177a34a6'", REMOTE_MAC)
        for required in (
            "resolve_reviewed_flutter()",
            'local pin_file="${PWD}/tools/toolchain-pins.json"',
            '"${pin_file}" tools.flutter.version',
            '"${pin_file}" tools.flutter.revision',
            'flutter-${required_version}-extract/flutter/bin/flutter',
            'candidate="$(command -v flutter 2>/dev/null || true)"',
            '"${candidate}" != /*',
            '"${candidate}" --version --machine',
            'value.get("frameworkVersion", "")',
            'value.get("frameworkRevision", "")',
            'export FLUTTER_BIN="${candidate}"',
        ):
            self.assertIn(required, REMOTE_MAC)

    @unittest.skipUnless(ZSH.exists(), "requires the target Mac zsh")
    def test_resolver_executes_managed_path_with_spaces_safely(self) -> None:
        version, revision = self.manifest_pin()
        completed = self.run_fake_managed_flutter(version, revision)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(
            "/Library/Application Support/WinsVPN/toolchains/", completed.stdout
        )

    @unittest.skipUnless(ZSH.exists(), "requires the target Mac zsh")
    def test_resolver_reads_the_reviewed_revision_from_the_pin(self) -> None:
        # The resolver must follow the pin FILE, not a baked-in constant. Give
        # it a pin that differs from the repo manifest and a fake flutter that
        # matches that pin; it must pass. If the resolver ignored the file and
        # used a literal, this would report a mismatch and return 65.
        completed = self.run_fake_managed_flutter(
            "9.9.9", "b" * 40, pin_version="9.9.9", pin_revision="b" * 40
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(
            "/Library/Application Support/WinsVPN/toolchains/", completed.stdout
        )

    @unittest.skipUnless(ZSH.exists(), "requires the target Mac zsh")
    def test_resolver_fails_clearly_on_version_or_revision_mismatch(self) -> None:
        version, _ = self.manifest_pin()
        completed = self.run_fake_managed_flutter("3.44.5", "wrong-revision")
        self.assertEqual(completed.returncode, 65)
        self.assertIn(f"Flutter {version}", completed.stderr)
        self.assertIn("is required; found 3.44.5 (wrong-revision)", completed.stderr)

    def test_ios_action_resolves_before_preserved_build_order(self) -> None:
        block = action_block("BuildIOS", "BuildMacOS")
        lock = block.index("$RemoteFlutterLock")
        acquire = block.index("acquire_remote_flutter_lock ios")
        trap = block.index("trap remote_flutter_lock_on_exit EXIT")
        resolver = block.index("$RemoteFlutterResolver")
        pub_get = block.index('"`$REVIEWED_FLUTTER" pub get')
        config = block.index(
            '"`$REVIEWED_FLUTTER" build ios --simulator --debug --config-only'
        )
        xcode = block.index(
            "xcodebuild -workspace ios/Runner.xcworkspace -scheme Runner "
            "-sdk iphonesimulator -configuration Debug build "
            "CODE_SIGNING_ALLOWED=NO"
        )
        self.assertLess(lock, acquire)
        self.assertLess(lock, trap)
        self.assertLess(trap, acquire)
        self.assertLess(acquire, resolver)
        self.assertLess(resolver, pub_get)
        self.assertLess(pub_get, config)
        self.assertLess(config, xcode)

    def test_macos_action_resolves_before_preserved_build_order(self) -> None:
        block = action_block("BuildMacOS", "Simulators")
        lock = block.index("$RemoteFlutterLock")
        acquire = block.index("acquire_remote_flutter_lock macos")
        trap = block.index("trap remote_flutter_lock_on_exit EXIT")
        resolver = block.index("$RemoteFlutterResolver")
        pub_get = block.index('"`$REVIEWED_FLUTTER" pub get')
        config = block.index(
            '"`$REVIEWED_FLUTTER" build macos --debug --config-only'
        )
        xcode = block.index(
            "xcodebuild -workspace macos/Runner.xcworkspace -scheme Runner "
            "-configuration Debug build CODE_SIGNING_ALLOWED=NO"
        )
        self.assertLess(lock, acquire)
        self.assertLess(lock, trap)
        self.assertLess(trap, acquire)
        self.assertLess(acquire, resolver)
        self.assertLess(resolver, pub_get)
        self.assertLess(pub_get, config)
        self.assertLess(config, xcode)

    def test_verify_apple_exports_the_same_reviewed_flutter_first(self) -> None:
        block = action_block("VerifyApple")
        self.assertLess(
            block.index("trap remote_flutter_lock_on_exit EXIT"),
            block.index("acquire_remote_flutter_lock apple-verify"),
        )
        self.assertLess(
            block.index("acquire_remote_flutter_lock apple-verify"),
            block.index("$RemoteFlutterResolver"),
        )
        self.assertLess(
            block.index("$RemoteFlutterResolver"),
            block.index("bash tools/verify_apple_readiness.sh"),
        )

    def test_simulator_action_remains_a_read_only_xcrun_query(self) -> None:
        block = action_block("Simulators", "VerifyApple")
        self.assertIn(
            'Invoke-MacScript "xcrun simctl list devices available"', block
        )
        self.assertNotIn("REVIEWED_FLUTTER", block)
        self.assertNotIn("pub get", block)

    @unittest.skipUnless(ZSH.exists(), "requires the target Mac zsh")
    def test_lock_is_owned_and_released_on_success(self) -> None:
        completed = self.run_lock_script(
            "(\n"
            + self.arm_lock_trap()
            + "acquire_remote_flutter_lock ios\n"
            + "test -s \"$REMOTE_FLUTTER_LOCK_OWNER\"\n"
            + "test \"$(/usr/bin/sed -n 's/^action=//p' \"$REMOTE_FLUTTER_LOCK_OWNER\")\" = ios\n"
            + ")\n"
            + "test ! -e \"$REMOTE_FLUTTER_LOCK_DIR\"\n"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    @unittest.skipUnless(ZSH.exists(), "requires the target Mac zsh")
    def test_lock_contention_fails_closed_without_changing_owner(self) -> None:
        completed = self.run_lock_script(
            "mkdir -p \"$REMOTE_FLUTTER_LOCK_DIR\"\n"
            "printf 'sentinel-owner\\n' >\"$REMOTE_FLUTTER_LOCK_OWNER\"\n"
            + self.arm_lock_trap()
            + "acquire_remote_flutter_lock ios\n"
        )
        self.assertEqual(completed.returncode, 73)
        self.assertIn("no Flutter command was started", completed.stderr)

    @unittest.skipUnless(ZSH.exists(), "requires the target Mac zsh")
    def test_lock_cleanup_refuses_foreign_owner_metadata(self) -> None:
        completed = self.run_lock_script(
            self.arm_lock_trap()
            + "acquire_remote_flutter_lock macos\n"
            "printf 'token=foreign-owner\\n' >\"$REMOTE_FLUTTER_LOCK_OWNER\"\n"
        )
        self.assertEqual(completed.returncode, 74)
        self.assertIn("no longer owned by this process", completed.stderr)

    @unittest.skipUnless(ZSH.exists(), "requires the target Mac zsh")
    def test_lock_releases_on_failing_command_and_preserves_status(self) -> None:
        completed = self.run_lock_script(
            "set +e\n"
            + "(\n"
            + "set -e\n"
            + self.arm_lock_trap()
            + "acquire_remote_flutter_lock apple-verify\n"
            + "exit 42\n"
            + ")\n"
            + "observed_exit=$?\n"
            + "set -e\n"
            + "test \"$observed_exit\" = 42\n"
            + "test ! -e \"$REMOTE_FLUTTER_LOCK_DIR\"\n"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
