#!/usr/bin/env python3
"""Windows Winn v3 relay, producer, and installer identity regressions."""

from __future__ import annotations

import json
import pathlib
import platform
import re
import shlex
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "build_windows_winn3_relay.sh"
SOURCE = SCRIPT.read_text(encoding="utf-8")
INSTALLER = (ROOT / "installer/windows/build_installer.ps1").read_text(encoding="utf-8")
PINS = json.loads(
    (ROOT / "tools" / "toolchain-pins.json").read_text(encoding="utf-8")
)
REQUIRED_GO_VERSION = PINS["tools"]["go"]["version"]


def _host_go_pair() -> tuple[str, str]:
    system = platform.system()
    machine = platform.machine()
    os_names = {"Darwin": "darwin", "Linux": "linux"}
    arch_names = {
        "arm64": "arm64",
        "aarch64": "arm64",
        "x86_64": "amd64",
        "amd64": "amd64",
        "AMD64": "amd64",
    }
    return os_names[system], arch_names[machine]


def _go_version_line(version: str | None = None) -> str:
    host_os, host_arch = _host_go_pair()
    return f"go version go{version or REQUIRED_GO_VERSION} {host_os}/{host_arch}"


def _write_executable(path: pathlib.Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def _write_go_stub(
    path: pathlib.Path,
    *,
    log: pathlib.Path,
    version_line: str,
    host_os: str,
    host_arch: str,
) -> None:
    _write_executable(
        path,
        "#!/bin/sh\n"
        f"log={shlex.quote(str(log))}\n"
        "{ printf 'argv:%s\\n' \"$*\"; "
        "env | grep -E '^(GOENV|GOTOOLDIR|GOROOT|GOPATH|GOMODCACHE|GOTOOLCHAIN)='; "
        " } >>\"$log\" 2>/dev/null || true\n"
        'cmd="${1:-}"\n'
        "shift || true\n"
        'if [ "$cmd" = version ]; then\n'
        f"  printf '%s\\n' {shlex.quote(version_line)}\n"
        "  exit 0\n"
        "fi\n"
        'if [ "$cmd" = env ]; then\n'
        '  case "${1:-}" in\n'
        f"    GOHOSTOS) printf '%s\\n' {shlex.quote(host_os)} ;;\n"
        f"    GOHOSTARCH) printf '%s\\n' {shlex.quote(host_arch)} ;;\n"
        '    GOOS) printf \'%s\\n\' "${GOOS:-}" ;;\n'
        '    GOARCH) printf \'%s\\n\' "${GOARCH:-}" ;;\n'
        "  esac\n"
        "  exit 0\n"
        "fi\n"
        'printf \'unexpected go invocation: %s %s\\n\' "$cmd" "$*" >&2\n'
        "exit 97\n",
    )


def _write_path_trap(path: pathlib.Path, marker: pathlib.Path) -> None:
    _write_executable(
        path,
        "#!/bin/sh\n"
        f"printf 'invoked argv:%s\\n' \"$*\" >{shlex.quote(str(marker))}\n"
        f"printf '%s\\n' {shlex.quote(_go_version_line())}\n"
        "exit 0\n",
    )


def _run_builder(
    tmp: pathlib.Path,
    *,
    env_updates: dict[str, str] | None = None,
    extra_path: pathlib.Path | None = None,
    unset: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    home = tmp / "home"
    work_tmp = tmp / "tmp"
    output = tmp / "out"
    home.mkdir(exist_ok=True)
    work_tmp.mkdir(exist_ok=True)
    output.mkdir(exist_ok=True)
    path = "/usr/bin:/bin:/usr/sbin:/sbin"
    if extra_path is not None:
        path = f"{extra_path}:{path}"
    env = {
        "HOME": str(home),
        "TMPDIR": str(work_tmp),
        "PATH": path,
        "LC_ALL": "C",
    }
    if env_updates:
        env.update(env_updates)
    for name in unset:
        env.pop(name, None)
    return subprocess.run(
        ["bash", str(SCRIPT), str(output)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


class WindowsWinn3RelayBuilderTests(unittest.TestCase):
    def test_shell_syntax(self) -> None:
        completed = subprocess.run(
            ["bash", "-n", str(SCRIPT)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_reads_go_pin_and_requires_explicit_release_go(self) -> None:
        self.assertEqual(REQUIRED_GO_VERSION, "1.27.1")
        self.assertIn(
            'REQUIRED_GO_VERSION="$(read_wins_toolchain_pin tools.go.version)"',
            SOURCE,
        )
        self.assertIn("go version go${REQUIRED_GO_VERSION}", SOURCE)
        self.assertIn('go_bin="${WINS_RELEASE_GO:-}"', SOURCE)
        self.assertIn("ambient PATH go is not used", SOURCE)
        self.assertNotIn("command -v go", SOURCE)
        self.assertNotRegex(SOURCE, r"(?m)^\s+go (vet|test|build)\b")
        self.assertIn('"${go_bin}" vet ./...', SOURCE)
        self.assertIn('"${go_bin}" test -race ./...', SOURCE)
        self.assertIn('"${go_bin}" build -trimpath -buildvcs=false', SOURCE)

    def test_sanitizes_go_env_and_keeps_deterministic_flags(self) -> None:
        self.assertIn("export GOENV=off", SOURCE)
        self.assertIn("export GOTOOLCHAIN=local", SOURCE)
        self.assertIn("unset GOTOOLDIR", SOURCE)
        self.assertIn("unset GOROOT", SOURCE)
        self.assertIn("unset GOPATH", SOURCE)
        self.assertIn("unset GOMODCACHE", SOURCE)
        self.assertIn('GOFLAGS=-mod=readonly', SOURCE)
        self.assertIn(
            '"${go_bin}" build -trimpath -buildvcs=false -ldflags="-s -w -buildid="',
            SOURCE,
        )
        self.assertIn("require_windows_target_identity", SOURCE)
        self.assertIn("winsvpn_winn3_engine.go-identity", SOURCE)
        self.assertIn("FILE_BIN=\"/usr/bin/file\"", SOURCE)
        self.assertIn("role relay", SOURCE)
        self.assertIn("targets windows/amd64 windows/arm64", SOURCE)

    def test_rejects_fake_path_go_when_release_go_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            tmp = pathlib.Path(name)
            trap_dir = tmp / "trap-bin"
            trap_dir.mkdir()
            marker = tmp / "path-go-invoked"
            _write_path_trap(trap_dir / "go", marker)
            completed = _run_builder(
                tmp,
                extra_path=trap_dir,
                unset=("WINS_RELEASE_GO",),
            )
            combined = completed.stdout + completed.stderr
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("WINS_RELEASE_GO", combined)
            self.assertIn("ambient PATH go is not used", combined)
            self.assertFalse(marker.exists())
            self.assertFalse((tmp / "out" / "winsvpn_winn3_engine.go-identity").exists())

    def test_rejects_relative_symlink_and_wrong_identity(self) -> None:
        host_os, host_arch = _host_go_pair()
        with tempfile.TemporaryDirectory() as name:
            tmp = pathlib.Path(name)
            trap_dir = tmp / "trap-bin"
            trap_dir.mkdir()
            marker = tmp / "path-go-invoked"
            _write_path_trap(trap_dir / "go", marker)

            relative = _run_builder(
                tmp,
                env_updates={"WINS_RELEASE_GO": "go"},
                extra_path=trap_dir,
            )
            self.assertNotEqual(relative.returncode, 0)
            self.assertIn("absolute", relative.stderr)
            self.assertFalse(marker.exists())

            real = tmp / "real-go"
            _write_executable(real, "#!/bin/sh\nexit 0\n")
            link = tmp / "go-link"
            link.symlink_to(real)
            symlink = _run_builder(
                tmp,
                env_updates={"WINS_RELEASE_GO": str(link)},
                extra_path=trap_dir,
            )
            self.assertNotEqual(symlink.returncode, 0)
            self.assertIn("non-symlink", symlink.stderr)
            self.assertFalse(marker.exists())

            log = tmp / "wrong-version.log"
            stub = tmp / "wrong-version-go"
            _write_go_stub(
                stub,
                log=log,
                version_line=_go_version_line("1.26.5"),
                host_os=host_os,
                host_arch=host_arch,
            )
            wrong = _run_builder(
                tmp,
                env_updates={"WINS_RELEASE_GO": str(stub)},
                extra_path=trap_dir,
            )
            self.assertNotEqual(wrong.returncode, 0)
            self.assertIn("identity mismatch", wrong.stderr)
            self.assertIn("go1.27.1", wrong.stderr)
            self.assertIn("go1.26.5", wrong.stderr)
            self.assertFalse(marker.exists())
            self.assertTrue(log.exists())
            self.assertIn("argv:version", log.read_text(encoding="utf-8"))
            self.assertNotIn("argv:vet", log.read_text(encoding="utf-8"))
            self.assertNotIn("argv:build", log.read_text(encoding="utf-8"))

    def test_selected_go_is_used_and_ambient_go_env_is_sanitized(self) -> None:
        host_os, host_arch = _host_go_pair()
        with tempfile.TemporaryDirectory() as name:
            tmp = pathlib.Path(name)
            trap_dir = tmp / "trap-bin"
            trap_dir.mkdir()
            marker = tmp / "path-go-invoked"
            _write_path_trap(trap_dir / "go", marker)
            log = tmp / "selected-go.log"
            stub = tmp / "reviewed-go"
            _write_go_stub(
                stub,
                log=log,
                version_line=_go_version_line(),
                host_os=host_os,
                host_arch=host_arch,
            )
            completed = _run_builder(
                tmp,
                env_updates={
                    "WINS_RELEASE_GO": str(stub),
                    "GOENV": str(tmp / "attacker-goenv"),
                    "GOTOOLDIR": str(tmp / "attacker-gotool"),
                    "GOROOT": str(tmp / "attacker-goroot"),
                    "GOPATH": str(tmp / "attacker-gopath"),
                    "GOMODCACHE": str(tmp / "attacker-modcache"),
                    "GOTOOLCHAIN": "auto",
                },
                extra_path=trap_dir,
            )
            combined = completed.stdout + completed.stderr
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("unexpected go invocation: vet", combined)
            self.assertFalse(marker.exists())
            self.assertFalse(
                (tmp / "out" / "winsvpn_winn3_engine.go-identity").exists(),
                "failed relay tests must not publish a toolchain identity receipt",
            )
            self.assertIn(_go_version_line(), completed.stdout)
            recorded = log.read_text(encoding="utf-8")
            self.assertIn("argv:version", recorded)
            self.assertIn("argv:env GOHOSTOS", recorded)
            self.assertIn("argv:env GOHOSTARCH", recorded)
            self.assertIn("GOENV=off", recorded)
            self.assertIn("GOTOOLCHAIN=local", recorded)
            self.assertNotIn("attacker-goenv", recorded)
            self.assertNotIn("attacker-gotool", recorded)
            self.assertNotIn("attacker-goroot", recorded)
            self.assertNotIn("attacker-gopath", recorded)
            self.assertNotIn("attacker-modcache", recorded)
            self.assertNotRegex(recorded, r"(?m)^GOTOOLDIR=")
            self.assertNotRegex(recorded, r"(?m)^GOROOT=")
            self.assertNotRegex(recorded, r"(?m)^GOPATH=")
            self.assertNotRegex(recorded, r"(?m)^GOMODCACHE=")
            self.assertNotIn("argv:build", recorded)

    def test_windows_installer_consumes_one_verified_release_pair(self) -> None:
        for marker in (
            "[string]$WinnReleaseDir = $env:WINS_WINN_RELEASE_DIR",
            '$WinnReleaseTool = Join-Path $RepoRoot "tools\\winn_release.py"',
            '$target = "datapath-windows-$($script:WindowsAwgGoArch)"',
            '$relayTarget = "winn3-relay-windows-$($script:WindowsAwgGoArch)"',
            "Assert-Winn3PairCustodyUnchanged",
            "Open-Winn3RetainedPayload",
            "Assert-Winn3RetainedPayloadUnchanged",
            "CoreRetained = $coreRetained",
            "RelayRetained = $relayRetained",
        ):
            self.assertIn(marker, INSTALLER)
        invoke = re.search(
            r"function Invoke-Winn3ArtifactProvenanceVerification \{(.*?)\n\}",
            INSTALLER,
            re.DOTALL,
        )
        self.assertIsNotNone(invoke)
        body = invoke.group(1)
        # Both images come from the same verified release, each bound to its
        # manifest digest, then role-checked, before custody is taken.
        self.assertIn("@{ Role = 'core'; Target = $target; FileName = 'winn-datapath.exe' }", body)
        self.assertIn(
            "@{ Role = 'relay'; Target = $relayTarget; FileName = 'winsvpn_winn3_engine.exe' }",
            body,
        )
        self.assertIn("$releaseTool.Path, 'verify', '--release', $releaseRoot, '--print-manifest'", body)
        self.assertIn("$manifest = ([string]$verification.Stdout[0]) | ConvertFrom-Json -ErrorAction Stop", body)
        self.assertNotIn("'--print-artifact'", body)
        self.assertIn("$verification.ExitCode -ne 0 -or $verification.Stdout.Count -ne 1", body)
        self.assertIn("([string]$rows[0].path) -cne $relative", body)
        self.assertIn("if ($verified.Sha256 -cne [string]$rows[0].sha256)", body)
        self.assertIn("if ($core.Sha256 -cne $manifestSha256)", body)
        self.assertIn("if ($relay.Sha256 -cne $relayManifestSha256)", body)
        self.assertIn("$roleTool.Sha256 -cne $Winn3ArtifactProvenanceToolSha256", body)
        for role in ("core", "relay"):
            self.assertIn(
                f"Assert-Winn3CompiledRole -Python $python -Tool $roleTool.Path -Role '{role}'",
                body,
            )
        self.assertLess(body.index("Assert-Winn3CompiledRole"), body.index("Invoke-ProductSigning"))
        self.assertLess(body.index("Invoke-ProductSigning"), body.index("Open-Winn3RetainedPayload"))
        # Unsigned releases are dev only and refused wherever signing is required.
        self.assertIn("if ($AllowUnsignedWinnRelease -and $mustSign)", body)
        self.assertIn("$verifyArguments += '--allow-unsigned'", body)
        self.assertLess(
            body.index("if ($AllowUnsignedWinnRelease -and $mustSign)"),
            body.index("$verifyArguments += '--allow-unsigned'"),
        )
        self.assertNotIn("Stage-Winn3Artifact", INSTALLER)

    def test_installer_holds_winn_pair_across_iscc_and_manifest_capture(self) -> None:
        iscc = INSTALLER.index("& $iscc @innoArguments")
        before = INSTALLER.rfind("Assert-Winn3PairCustodyUnchanged", 0, iscc)
        after = INSTALLER.find("Assert-Winn3PairCustodyUnchanged", iscc)
        payload = INSTALLER.index("$payloadEntries = @(", iscc)
        manifest_recheck = INSTALLER.find("Assert-Winn3PairCustodyUnchanged", payload)
        self.assertGreater(before, 0)
        self.assertGreater(after, iscc)
        self.assertGreater(manifest_recheck, payload)
        self.assertIn("[IO.FileShare]::Read", INSTALLER)
        self.assertIn("CoreStream", INSTALLER)
        self.assertIn("RelayStream", INSTALLER)

    def test_windows_installer_scrubs_python_and_path_injection(self) -> None:
        helper = re.search(
            r"function Invoke-Winn3PythonTool \{(.*?)\n\}", INSTALLER, re.DOTALL
        )
        self.assertIsNotNone(helper)
        body = helper.group(1)
        for name in (
            "PATH",
            "PYTHONHOME",
            "PYTHONPATH",
            "PYTHONSTARTUP",
            "PYTHONINSPECT",
            "PYTHONUSERBASE",
            "PYTHONWARNINGS",
            "PYTHONSAFEPATH",
        ):
            self.assertIn(f"'{name}'", body)
        self.assertIn("$env:SystemRoot\\System32;$env:SystemRoot", body)
        self.assertIn("& $Python -I -B @Arguments 2>&1", body)
        self.assertIn("finally {", body)

    def test_windows_installer_rejects_legacy_inputs_and_marker_authority(self) -> None:
        for forbidden in (
            "Stage-Winn3Artifact",
            "Test-FileContainsMarker",
            "containsCoreMarker",
            "windows_winn3_artifact_provenance.json",
            "$Winn3DatapathInput",
            "$Winn3RelayInput",
            "$Winn3ProducerSource",
            "$Winn3CoreSource",
            "$Winn3RelaySource",
            "--producer $Winn3ProducerSource",
            "--core-builder $Winn3CoreSource",
            "--relay-builder $Winn3RelaySource",
        ):
            self.assertNotIn(forbidden, INSTALLER)
        for forbidden in (
            "$WinnEngineBuilder",
            "$Winn3RelayBuilder",
            "Find-Bash",
            "& $bash",
        ):
            self.assertNotIn(forbidden, INSTALLER)

    def test_windows_installer_binds_arch_and_has_no_retired_ledger(self) -> None:
        self.assertIn("'x64' = 'amd64'", INSTALLER)
        self.assertIn("'arm64' = 'arm64'", INSTALLER)
        for retired in (
            "WINS_WINDOWS_WINN3_CANDIDATE_ID",
            "WINS_WINDOWS_WINN3_RECEIPT_SHA256",
            "WINS_WINDOWS_WINN3_SEALED_GENERATION",
            "ReleaseWindowsWinn3Authority",
            "authorization-ledger",
            "verify-sealed-pair",
            "windows-winn3-fixed-loader.exe",
            "ReleasePython\\3.14.7",
            "Winn3RelayDir",
        ):
            self.assertNotIn(retired, INSTALLER)

if __name__ == "__main__":
    unittest.main()
