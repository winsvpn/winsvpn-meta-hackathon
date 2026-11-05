#!/usr/bin/env python3
"""Fail-closed regressions for server Xray pin overrides.

Release and deployment paths must install the reviewed Xray tag v26.9.30
with its matching linux-64 archive hash and the exact extracted executable
bytes. Caller env may not select an older tag+hash pair. Fixture injection
is limited to the non-release ``--self-test-xray-pin`` /
``WINS_XRAY_PIN_SELFTEST_*`` mechanism.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
CORE = ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh"
DATA = ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh"
PROBE = ROOT / "tools" / "xray_external_core_probe.sh"
BASH32 = "/bin/bash"

REVIEWED_VERSION = "26.9.30"
REVIEWED_HASH = "f851110beaff16e78d643f0ccfd9524b4a44dfd59bae3e34bb52bba378f7690e"
REVIEWED_BIN_HASH = "96efb28b8b2086275598dc46e73b5dc340da948b4e1ccc4f1719f83f67b793a7"
OLD_VERSION = "25.9.11"
OLD_HASH = "a" * 64
WRONG_HASH = "b" * 64

SCRIPTS = (
    ("core", CORE, "XRAY_VERSION", "XRAY_LINUX_64_SHA256"),
    ("data", DATA, "XRAY_VERSION_DEFAULT", "XRAY_LINUX_64_SHA256_DEFAULT"),
    ("probe", PROBE, "xray_version", "xray_sha256"),
)

UNAME_MOCK = """
uname() {
  case "${1:-}" in
    -s) printf '%s\\n' "${MOCK_UNAME_S:-Linux}" ;;
    -m) printf '%s\\n' "${MOCK_UNAME_M:-x86_64}" ;;
    *) printf '%s\\n' "${MOCK_UNAME_S:-Linux}" ;;
  esac
}
"""

SHA256_ACCEPT_MOCK = f"""
sha256sum() {{
  printf '%s  %s\\n' "{REVIEWED_BIN_HASH}" "${{1:-}}"
}}
shasum() {{
  sha256sum "$@"
}}
"""

SHA256_FAIL_MOCK = """
sha256sum() {
  return 1
}
shasum() {
  return 1
}
"""

STAT_FLIP_MOCK = """
stat() {
  local count_file="${WINS_STAT_CALL_FILE:?}"
  local n=0
  [[ -f "${count_file}" ]] && n="$(cat "${count_file}")"
  n=$((n + 1))
  printf '%s' "${n}" > "${count_file}"
  if ((n % 2 == 1)); then
    printf '1:1:1:10\\n'
  else
    printf '2:2:1:10\\n'
  fi
}
"""


def function_body(source: str, name: str) -> str:
    marker = f"{name}() {{"
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"missing function {name}")
    cursor = source.find("\n}", start)
    while cursor >= 0:
        candidate = source[start : cursor + 2]
        if candidate.count("{") == candidate.count("}"):
            return candidate
        cursor = source.find("\n}", cursor + 2)
    raise AssertionError(f"unterminated function {name}")


def pin_functions(source: str) -> str:
    return "\n\n".join(
        function_body(source, name)
        for name in (
            "wins_require_reviewed_xray_pin",
            "wins_lock_deployed_xray_pin",
            "wins_self_test_xray_pin",
            "wins_xray_file_sha256",
            "wins_xray_file_identity",
            "wins_reviewed_xray_binary_installed",
            "wins_require_reviewed_xray_binary",
            "wins_xray_linux_fd_exec",
            "wins_exec_reviewed_xray",
            "wins_require_linux_amd64_xray_preflight",
            "wins_xray_pin_self_test_requested",
            "wins_dispatch_xray_pin_self_test",
        )
    )


def generated_sync_agent(source: str) -> str:
    marker = 'cat > "${sync_tmp}" <<\'EOF\''
    start = source.find(marker)
    if start < 0:
        raise AssertionError("missing core sync agent heredoc")
    body_start = source.find("\n", start) + 1
    end = source.find("\nEOF\n", body_start)
    if end < 0:
        raise AssertionError("unterminated core sync agent heredoc")
    return source[body_start : end + 1]


def _curl(url: str, timeout: int) -> bytes:
    """Fetch URL bytes with the absolute system curl. SSL/transport errors raise OSError."""
    if not os.access("/usr/bin/curl", os.X_OK):
        raise OSError("/usr/bin/curl is not executable")
    try:
        proc = subprocess.run(
            [
                "/usr/bin/curl",
                "-fsSL",
                "--retry",
                "2",
                "--connect-timeout",
                "10",
                "--max-time",
                str(timeout),
                "-A",
                "winsvpn-xray-pin-fail-closed-test",
                url,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 5,
        )
    except subprocess.TimeoutExpired as exc:
        raise OSError(f"curl timed out fetching {url}") from exc
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip() or f"curl exit {proc.returncode}"
        raise OSError(err)
    return proc.stdout


def retrieve_official_xray_linux64_provenance() -> dict[str, str]:
    """Independently retrieve official v26.9.30 linux-64 bytes.

    Latest-stable discovery is recorded first, then the exact freeze is
    fetched. Offline or transport failure is UNVERIFIED, never a
    self-consistent pass against in-tree constants.
    """
    result = {
        "status": "UNVERIFIED",
        "latest_tag": "",
        "zip_sha256": "",
        "bin_sha256": "",
        "detail": "network unavailable",
    }
    try:
        latest = json.loads(
            _curl(
                "https://api.github.com/repos/XTLS/Xray-core/releases/latest",
                timeout=15,
            ).decode("utf-8")
        )
        result["latest_tag"] = str(latest.get("tag_name") or "")
    except (OSError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        result["detail"] = f"latest-stable discovery failed: {exc}"
        return result
    try:
        dgst = _curl(
            "https://github.com/XTLS/Xray-core/releases/download/v26.9.30/Xray-linux-64.zip.dgst",
            timeout=20,
        ).decode("utf-8")
    except (OSError, TimeoutError, UnicodeDecodeError) as exc:
        result["detail"] = f"official dgst retrieval failed: {exc}"
        return result
    zip_hash = ""
    for line in dgst.splitlines():
        stripped = line.strip().replace(" ", "")
        if stripped.upper().startswith("SHA2-256="):
            zip_hash = stripped.split("=", 1)[1].strip().lower()
            break
    if not zip_hash:
        result["status"] = "FAIL"
        result["detail"] = "official dgst did not contain SHA2-256"
        return result
    try:
        archive = _curl(
            "https://github.com/XTLS/Xray-core/releases/download/v26.9.30/Xray-linux-64.zip",
            timeout=90,
        )
    except (OSError, TimeoutError) as exc:
        result["detail"] = f"official zip retrieval failed after dgst: {exc}"
        return result
    computed_zip = hashlib.sha256(archive).hexdigest()
    if computed_zip != zip_hash:
        result["status"] = "FAIL"
        result["zip_sha256"] = computed_zip
        result["detail"] = "official zip bytes do not match official dgst"
        return result
    result["zip_sha256"] = computed_zip
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            payload = zipped.read("xray")
    except (KeyError, zipfile.BadZipFile) as exc:
        result["status"] = "FAIL"
        result["detail"] = f"official zip did not contain xray: {exc}"
        return result
    result["bin_sha256"] = hashlib.sha256(payload).hexdigest()
    result["status"] = "VERIFIED"
    result["detail"] = "official v26.9.30 linux-64 zip and executable retrieved"
    return result


def clean_env(**overrides: str) -> dict[str, str]:
    env = {
        "HOME": os.environ.get("HOME", "/tmp"),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
        "TERM": "dumb",
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }
    env.update(overrides)
    return env


def run_extracted(
    source: str,
    call: str,
    extra_env: dict[str, str] | None = None,
    assignments: str = "",
    prefix: str = "",
    mock_absolute_tools: bool = False,
    mock_stat: bool = False,
) -> subprocess.CompletedProcess[str]:
    functions = pin_functions(source)
    if mock_absolute_tools:
        # This substitution exists only inside the generated unit-test shell.
        # Production source must retain absolute reviewed system-tool paths.
        functions = (
            functions.replace("/usr/bin/sha256sum", "sha256sum")
            .replace("/usr/bin/shasum", "shasum")
            .replace("/usr/bin/uname", "uname")
            .replace("if [[ -x sha256sum ]]; then", "if declare -F sha256sum >/dev/null; then")
            .replace("elif [[ -x shasum ]]; then", "elif declare -F shasum >/dev/null; then")
        )
        if mock_stat:
            functions = functions.replace("/usr/bin/stat", "stat").replace(
                "if [[ ! -x stat ]]; then", "if false; then"
            )
    script = f"""set -euo pipefail
err() {{ printf '%s\\n' "$*" >&2; }}
{prefix}
{assignments}
{functions}
{call}
"""
    return subprocess.run(
        [BASH32, "-c", script],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=clean_env(**(extra_env or {})),
    )


def run_script(
    script: pathlib.Path,
    args: list[str],
    extra_env: dict[str, str] | None = None,
    bash: str = BASH32,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [bash, str(script), *args],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=clean_env(**(extra_env or {})),
        timeout=60,
    )


def run_self_test(
    script: pathlib.Path, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    bash = BASH32 if script == PROBE else "bash"
    return run_script(script, ["--self-test-xray-pin"], extra_env=extra_env, bash=bash)


def network_stub_env(raw: str) -> str:
    fake_bin = pathlib.Path(raw) / "bin"
    fake_bin.mkdir()
    for name in ("curl", "wget", "sudo", "apt-get", "systemctl"):
        stub = fake_bin / name
        stub.write_text("#!/bin/sh\necho unexpected-$0 >&2\nexit 97\n", encoding="utf-8")
        stub.chmod(0o755)
    return f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}"


class ServerXrayPinFailClosedTests(unittest.TestCase):
    def test_shell_syntax(self) -> None:
        for _name, path, _version_var, _hash_var in SCRIPTS:
            with self.subTest(script=path.name, bash="bash"):
                subprocess.run(["bash", "-n", str(path)], cwd=ROOT, check=True)
        subprocess.run([BASH32, "-n", str(PROBE)], cwd=ROOT, check=True)
        for name, path, _version_var, _hash_var in SCRIPTS:
            snippet = f"""set -euo pipefail
err() {{ printf '%s\\n' "$*" >&2; }}
{pin_functions(path.read_text(encoding="utf-8"))}
"""
            with self.subTest(script=path.name, bash="bash32-helpers"):
                subprocess.run(
                    [BASH32, "-n", "-c", snippet],
                    cwd=ROOT,
                    check=True,
                )

    def test_reviewed_tag_and_hash_are_exact(self) -> None:
        core = CORE.read_text(encoding="utf-8")
        data = DATA.read_text(encoding="utf-8")
        probe = PROBE.read_text(encoding="utf-8")
        self.assertIn('XRAY_VERSION="${XRAY_VERSION:-26.9.30}"', core)
        self.assertIn(
            f'XRAY_LINUX_64_SHA256="${{XRAY_LINUX_64_SHA256:-{REVIEWED_HASH}}}"',
            core,
        )
        self.assertIn(
            f'XRAY_LINUX_64_BIN_SHA256="${{XRAY_LINUX_64_BIN_SHA256:-{REVIEWED_BIN_HASH}}}"',
            core,
        )
        self.assertIn('XRAY_VERSION_DEFAULT="${XRAY_VERSION:-26.9.30}"', data)
        self.assertIn(
            f'XRAY_LINUX_64_SHA256_DEFAULT="${{XRAY_LINUX_64_SHA256:-{REVIEWED_HASH}}}"',
            data,
        )
        self.assertIn(
            f'XRAY_LINUX_64_BIN_SHA256_DEFAULT="${{XRAY_LINUX_64_BIN_SHA256:-{REVIEWED_BIN_HASH}}}"',
            data,
        )
        self.assertIn('xray_version="${XRAY_VERSION:-26.9.30}"', probe)
        self.assertIn(
            f'xray_sha256="${{XRAY_LINUX_64_SHA256:-{REVIEWED_HASH}}}"',
            probe,
        )
        self.assertIn(
            f'xray_bin_sha256="${{XRAY_LINUX_64_BIN_SHA256:-{REVIEWED_BIN_HASH}}}"',
            probe,
        )
        for source in (core, data, probe):
            require = function_body(source, "wins_require_reviewed_xray_pin")
            self.assertIn(f'reviewed_version="{REVIEWED_VERSION}"', require)
            self.assertIn(f'reviewed_hash="{REVIEWED_HASH}"', require)
            binary = function_body(source, "wins_require_reviewed_xray_binary")
            self.assertIn(f'reviewed_hash="{REVIEWED_BIN_HASH}"', binary)
            self.assertIn("/usr/local/bin/xray", binary)
            identity = function_body(source, "wins_xray_file_identity")
            self.assertIn("/usr/bin/stat", identity)
            self.assertIn("regular non-hardlinked file", identity)
            exec_fn = function_body(source, "wins_exec_reviewed_xray")
            self.assertIn("wins_require_reviewed_xray_binary", exec_fn)
            self.assertIn("wins_xray_linux_fd_exec", exec_fn)
            bind = function_body(source, "wins_xray_linux_fd_exec")
            self.assertIn("/usr/bin/python3", bind)
            self.assertIn("/proc/self/fd", bind)
            self.assertIn("/usr/bin/sha256sum", bind)
            self.assertIn("O_NOFOLLOW", bind)

    def test_install_and_probe_lock_before_download(self) -> None:
        download = "Xray-linux-64.zip"
        for path in (CORE, DATA):
            body = function_body(path.read_text(encoding="utf-8"), "install_xray")
            self.assertIn("wins_lock_deployed_xray_pin", body)
            self.assertLess(body.index("wins_lock_deployed_xray_pin"), body.index(download))
            self.assertIn("wins_reviewed_xray_binary_installed /usr/local/bin/xray", body)
            self.assertIn('wins_require_reviewed_xray_binary "${staging}/xray"', body)
            self.assertIn("wins_require_reviewed_xray_binary /usr/local/bin/xray", body)
            self.assertIn("| /usr/bin/sha256sum -c -", body)
            self.assertIn("wins_require_linux_amd64_xray_preflight", body)
            self.assertLess(
                body.index("wins_require_linux_amd64_xray_preflight"),
                body.index(download),
            )
            self.assertNotIn("command -v xray", body)
            self.assertNotIn("WINS_XRAY_PIN_SELFTEST_VERSION:-${", body)
        probe = PROBE.read_text(encoding="utf-8")
        after_dispatch = probe.find('wins_dispatch_xray_pin_self_test "$@"')
        self.assertGreater(after_dispatch, -1)
        lock_call = probe.find("wins_lock_deployed_xray_pin", after_dispatch)
        preflight_call = probe.find("wins_require_linux_amd64_xray_preflight", after_dispatch)
        download_at = probe.find(download, after_dispatch)
        binary_at = probe.find("wins_require_reviewed_xray_binary", after_dispatch)
        self.assertLess(lock_call, preflight_call)
        self.assertLess(preflight_call, download_at)
        self.assertLess(download_at, binary_at)
        self.assertIn("| /usr/bin/sha256sum -c -", probe)
        self.assertNotIn("WINS_XRAY_PIN_SELFTEST_VERSION:-${", probe[after_dispatch:])

    def test_extracted_require_accepts_only_the_reviewed_pair(self) -> None:
        for name, path, _version_var, _hash_var in SCRIPTS:
            source = path.read_text(encoding="utf-8")
            with self.subTest(script=name, case="reviewed"):
                proc = run_extracted(
                    source,
                    f'wins_require_reviewed_xray_pin "{REVIEWED_VERSION}" "{REVIEWED_HASH}"',
                )
                self.assertEqual(proc.returncode, 0, proc.stdout)
            with self.subTest(script=name, case="old-version"):
                proc = run_extracted(
                    source,
                    f'wins_require_reviewed_xray_pin "{OLD_VERSION}" "{OLD_HASH}"',
                )
                self.assertNotEqual(proc.returncode, 0, proc.stdout)
                self.assertIn("Caller env may not select Xray", proc.stdout)
                self.assertIn(OLD_VERSION, proc.stdout)
                self.assertIn(REVIEWED_VERSION, proc.stdout)
            with self.subTest(script=name, case="mismatched-hash"):
                proc = run_extracted(
                    source,
                    f'wins_require_reviewed_xray_pin "{REVIEWED_VERSION}" "{WRONG_HASH}"',
                )
                self.assertNotEqual(proc.returncode, 0, proc.stdout)
                self.assertIn("refusing mismatched pin", proc.stdout)
            with self.subTest(script=name, case="old-version-reviewed-hash"):
                proc = run_extracted(
                    source,
                    f'wins_require_reviewed_xray_pin "{OLD_VERSION}" "{REVIEWED_HASH}"',
                )
                self.assertNotEqual(proc.returncode, 0, proc.stdout)
                self.assertIn("Caller env may not select Xray", proc.stdout)

    def test_deploy_lock_refuses_selftest_fixtures(self) -> None:
        for name, path, _version_var, _hash_var in SCRIPTS:
            source = path.read_text(encoding="utf-8")
            with self.subTest(script=name):
                proc = run_extracted(
                    source,
                    f'wins_lock_deployed_xray_pin "{REVIEWED_VERSION}" "{REVIEWED_HASH}"',
                    extra_env={
                        "WINS_XRAY_PIN_SELFTEST_VERSION": OLD_VERSION,
                        "WINS_XRAY_PIN_SELFTEST_SHA256": OLD_HASH,
                    },
                )
                self.assertNotEqual(proc.returncode, 0, proc.stdout)
                self.assertIn("non-release fixture", proc.stdout)

    def test_self_test_dispatches_before_credential_files(self) -> None:
        core = CORE.read_text(encoding="utf-8")
        data = DATA.read_text(encoding="utf-8")
        probe = PROBE.read_text(encoding="utf-8")
        for source, secrets_marker in (
            (core, 'WINS_SECRETS_FILE="${WINS_SECRETS_FILE:-/root/winsvpn-secrets.env}"'),
            (data, 'load_existing_node_env "${NODE_ENV_FILE}"'),
        ):
            swap_guard = function_body(source, "wins_early_plaintext_swap_guard")
            pin_fn = source.find("wins_self_test_xray_pin() {")
            dispatch = source.find("wins_dispatch_xray_pin_self_test")
            guard_call = source.find('wins_early_plaintext_swap_guard "$@"')
            secrets = source.find(secrets_marker)
            self.assertIn("--self-test-xray-pin", swap_guard)
            self.assertIn('if [[ "$#" -eq 1 ]]; then', swap_guard)
            self.assertGreater(pin_fn, -1)
            self.assertGreater(dispatch, pin_fn)
            self.assertGreater(guard_call, dispatch)
            self.assertGreater(secrets, guard_call)
        digest_map = core.find("declare -A CORE_AI_MODEL_DIGESTS=")
        gemma_key = core.find('["gemma4:12b"]')
        self.assertGreater(digest_map, core.find("wins_dispatch_xray_pin_self_test"))
        self.assertGreater(gemma_key, digest_map)
        data_secrets = data.find('WINS_SECRETS_FILE="${WINS_SECRETS_FILE:-/root/winsvpn-secrets.env}"')
        self.assertGreater(data_secrets, data.find("wins_dispatch_xray_pin_self_test"))
        probe_dispatch = probe.find('wins_dispatch_xray_pin_self_test "$@"')
        probe_env = probe.find('xray_version="${XRAY_VERSION:-26.9.30}"')
        probe_lock = probe.find('wins_lock_deployed_xray_pin "${xray_version}" "${xray_sha256}"')
        probe_curl = probe.find("curl -fsSL")
        self.assertGreater(probe_env, probe_dispatch)
        self.assertGreater(probe_lock, probe_env)
        self.assertGreater(probe_curl, probe_lock)

    def test_self_test_flag_accepts_reviewed_pin(self) -> None:
        for name, path, _version_var, _hash_var in SCRIPTS:
            with self.subTest(script=name):
                proc = run_self_test(path)
                self.assertEqual(proc.returncode, 0, proc.stdout)
                self.assertIn(f"reviewed_xray_pin={REVIEWED_VERSION}", proc.stdout)

    def test_self_test_flag_refuses_old_env_override(self) -> None:
        for name, path, _version_var, _hash_var in SCRIPTS:
            with self.subTest(script=name):
                proc = run_self_test(
                    path,
                    extra_env={
                        "XRAY_VERSION": OLD_VERSION,
                        "XRAY_LINUX_64_SHA256": OLD_HASH,
                    },
                )
                self.assertNotEqual(proc.returncode, 0, proc.stdout)
                self.assertIn("Caller env may not select Xray", proc.stdout)
                self.assertIn(OLD_VERSION, proc.stdout)

    def test_self_test_flag_refuses_mismatched_hash(self) -> None:
        for name, path, _version_var, _hash_var in SCRIPTS:
            with self.subTest(script=name):
                proc = run_self_test(
                    path,
                    extra_env={
                        "XRAY_VERSION": REVIEWED_VERSION,
                        "XRAY_LINUX_64_SHA256": WRONG_HASH,
                    },
                )
                self.assertNotEqual(proc.returncode, 0, proc.stdout)
                self.assertIn("refusing mismatched pin", proc.stdout)

    def test_named_fixture_injection_is_self_test_only(self) -> None:
        for name, path, version_var, hash_var in SCRIPTS:
            source = path.read_text(encoding="utf-8")
            self_test = function_body(source, "wins_self_test_xray_pin")
            lock = function_body(source, "wins_lock_deployed_xray_pin")
            if path == PROBE:
                after_dispatch = source.find('wins_dispatch_xray_pin_self_test "$@"')
                download_region = source[after_dispatch:]
            else:
                download_region = function_body(source, "install_xray")
            with self.subTest(script=name, surface="fixture-read"):
                self.assertIn("WINS_XRAY_PIN_SELFTEST_VERSION:-", self_test)
                self.assertIn("WINS_XRAY_PIN_SELFTEST_SHA256:-", self_test)
            with self.subTest(script=name, surface="deploy-refuse"):
                self.assertIn("WINS_XRAY_PIN_SELFTEST_*", lock)
                self.assertIn("non-release fixture", lock)
            with self.subTest(script=name, surface="install-not-fixture"):
                self.assertIn("wins_lock_deployed_xray_pin", download_region)
                self.assertNotIn("WINS_XRAY_PIN_SELFTEST_VERSION:-${", download_region)
            with self.subTest(script=name, surface="fixture-old-version"):
                proc = run_extracted(
                    source,
                    "wins_self_test_xray_pin",
                    extra_env={
                        "WINS_XRAY_PIN_SELFTEST_VERSION": OLD_VERSION,
                        "WINS_XRAY_PIN_SELFTEST_SHA256": OLD_HASH,
                    },
                    assignments=(
                        f'{version_var}="{REVIEWED_VERSION}"\n'
                        f'{hash_var}="{REVIEWED_HASH}"\n'
                    ),
                )
                self.assertNotEqual(proc.returncode, 0, proc.stdout)
                self.assertIn(OLD_VERSION, proc.stdout)
            with self.subTest(script=name, surface="live-fixture-old-version"):
                proc = run_self_test(
                    path,
                    extra_env={
                        "WINS_XRAY_PIN_SELFTEST_VERSION": OLD_VERSION,
                        "WINS_XRAY_PIN_SELFTEST_SHA256": OLD_HASH,
                    },
                )
                self.assertNotEqual(proc.returncode, 0, proc.stdout)
                self.assertIn("Caller env may not select Xray", proc.stdout)

    def test_self_test_does_not_download_or_deploy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-xray-pin-") as raw:
            path_value = network_stub_env(raw)
            for _name, path, _version_var, _hash_var in SCRIPTS:
                with self.subTest(script=path.name):
                    proc = run_self_test(path, extra_env={"PATH": path_value})
                    self.assertEqual(proc.returncode, 0, proc.stdout)
                    self.assertNotIn("unexpected-", proc.stdout)

    def test_self_test_does_not_load_secret_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-xray-secrets-") as raw:
            secret = pathlib.Path(raw) / "secrets.env"
            secret.write_text("echo SECRET_FILE_LOADED\nexit 97\n", encoding="utf-8")
            extra = {
                "WINS_SECRETS_FILE": str(secret),
                "WINS_DEFAULTS_FILE": str(secret),
                "NODE_ENV_FILE": str(secret),
                "CORE_ENV_FILE": str(secret),
                "AWG_OBFUSCATION_PROFILE": str(secret),
                "PATH": network_stub_env(raw),
            }
            for _name, path, _version_var, _hash_var in SCRIPTS:
                with self.subTest(script=path.name):
                    proc = run_self_test(path, extra_env=extra)
                    self.assertEqual(proc.returncode, 0, proc.stdout)
                    self.assertNotIn("SECRET_FILE_LOADED", proc.stdout)
                    self.assertIn(f"reviewed_xray_pin={REVIEWED_VERSION}", proc.stdout)

    def test_mixed_or_surplus_arguments_are_rejected_before_network(self) -> None:
        mixed_cases = (
            ["--self-test-xray-pin", "--deploy"],
            ["--deploy", "--self-test-xray-pin"],
            ["--self-test-xray-pin", "extra"],
        )
        with tempfile.TemporaryDirectory(prefix="wins-xray-mixed-") as raw:
            path_value = network_stub_env(raw)
            extra = {"PATH": path_value}
            for name, path, _version_var, _hash_var in SCRIPTS:
                bash = BASH32 if path == PROBE else "bash"
                for args in mixed_cases:
                    with self.subTest(script=name, args=args):
                        proc = run_script(path, args, extra_env=extra, bash=bash)
                        self.assertNotEqual(proc.returncode, 0, proc.stdout)
                        self.assertIn("must be the sole argument", proc.stdout)
                        self.assertNotIn("unexpected-", proc.stdout)
                        self.assertNotIn(f"reviewed_xray_pin={REVIEWED_VERSION}", proc.stdout)
                if path == PROBE:
                    with self.subTest(script=name, args=["--unexpected"]):
                        proc = run_script(path, ["--unexpected"], extra_env=extra, bash=bash)
                        self.assertNotEqual(proc.returncode, 0, proc.stdout)
                        self.assertNotIn("unexpected-", proc.stdout)

    def test_path_substitution_cannot_satisfy_binary_attestation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-xray-path-") as raw:
            fake_bin = pathlib.Path(raw) / "bin"
            fake_bin.mkdir()
            fake_xray = fake_bin / "xray"
            fake_xray.write_text(
                "#!/bin/sh\nprintf 'Xray 26.9.30 (Xray, Penetrates Everything.)\\n'\n",
                encoding="utf-8",
            )
            fake_xray.chmod(0o755)
            modified = pathlib.Path(raw) / "modified-xray"
            modified.write_bytes(b"same-version-wrong-bytes")
            path_value = f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}"
            for name, path, _version_var, _hash_var in SCRIPTS:
                source = path.read_text(encoding="utf-8")
                with self.subTest(script=name):
                    proc = run_extracted(
                        source,
                        f'wins_require_reviewed_xray_binary "{modified}"',
                        extra_env={"PATH": path_value},
                    )
                    self.assertNotEqual(proc.returncode, 0, proc.stdout)
                    self.assertIn("does not match reviewed v26.9.30 linux-64 bytes", proc.stdout)
                    installed = run_extracted(
                        source,
                        "wins_reviewed_xray_binary_installed",
                        extra_env={"PATH": path_value},
                    )
                    self.assertNotEqual(installed.returncode, 0, installed.stdout)

    def test_attestation_uses_absolute_system_tools_and_rejects_symlinks(self) -> None:
        for name, path, _version_var, _hash_var in SCRIPTS:
            source = path.read_text(encoding="utf-8")
            with self.subTest(script=name, check="absolute-tools"):
                self.assertIn("/usr/bin/uname -s", source)
                self.assertIn("/usr/bin/uname -m", source)
                self.assertIn("/usr/bin/sha256sum", source)
                self.assertIn("/usr/bin/shasum", source)
                self.assertIn("/usr/bin/stat", source)
                self.assertIn("/usr/bin/python3", source)
            with tempfile.TemporaryDirectory(prefix="wins-xray-symlink-") as raw:
                target = pathlib.Path(raw) / "target"
                target.write_bytes(b"reviewed-xray-bytes")
                link = pathlib.Path(raw) / "xray"
                link.symlink_to(target)
                proc = run_extracted(
                    source,
                    f'wins_require_reviewed_xray_binary "{link}"',
                    prefix=SHA256_ACCEPT_MOCK,
                    mock_absolute_tools=True,
                )
                self.assertNotEqual(proc.returncode, 0, proc.stdout)

    def test_modified_same_version_binary_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-xray-modified-") as raw:
            modified = pathlib.Path(raw) / "xray"
            modified.write_bytes(b"Xray 26.9.30 patched-not-reviewed")
            for name, path, _version_var, _hash_var in SCRIPTS:
                source = path.read_text(encoding="utf-8")
                with self.subTest(script=name):
                    proc = run_extracted(
                        source,
                        f'wins_reviewed_xray_binary_installed "{modified}"',
                    )
                    self.assertNotEqual(proc.returncode, 0, proc.stdout)
                    required = run_extracted(
                        source,
                        f'wins_require_reviewed_xray_binary "{modified}"',
                    )
                    self.assertNotEqual(required.returncode, 0, required.stdout)
                    self.assertIn("does not match reviewed v26.9.30 linux-64 bytes", required.stdout)

    def test_exact_binary_bytes_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-xray-exact-") as raw:
            reviewed = pathlib.Path(raw) / "xray"
            reviewed.write_bytes(b"reviewed-xray-bytes")
            for name, path, _version_var, _hash_var in SCRIPTS:
                source = path.read_text(encoding="utf-8")
                with self.subTest(script=name):
                    proc = run_extracted(
                        source,
                        f'wins_require_reviewed_xray_binary "{reviewed}"',
                        prefix=SHA256_ACCEPT_MOCK,
                        mock_absolute_tools=True,
                    )
                    self.assertEqual(proc.returncode, 0, proc.stdout)
                    installed = run_extracted(
                        source,
                        f'wins_reviewed_xray_binary_installed "{reviewed}"',
                        prefix=SHA256_ACCEPT_MOCK,
                        mock_absolute_tools=True,
                    )
                    self.assertEqual(installed.returncode, 0, installed.stdout)

    def test_os_and_architecture_preflight_refusal(self) -> None:
        cases = (
            ("Darwin", "x86_64", "requires Linux", False),
            ("Linux", "aarch64", "requires amd64", False),
            ("Linux", "arm64", "requires amd64", False),
            ("Linux", "x86_64", "", True),
            ("Linux", "amd64", "", True),
        )
        for name, path, _version_var, _hash_var in SCRIPTS:
            source = path.read_text(encoding="utf-8")
            for kernel, machine, needle, ok in cases:
                with self.subTest(script=name, kernel=kernel, machine=machine):
                    proc = run_extracted(
                        source,
                        "wins_require_linux_amd64_xray_preflight",
                        extra_env={"MOCK_UNAME_S": kernel, "MOCK_UNAME_M": machine},
                        prefix=UNAME_MOCK,
                        mock_absolute_tools=True,
                    )
                    if ok:
                        self.assertEqual(proc.returncode, 0, proc.stdout)
                    else:
                        self.assertNotEqual(proc.returncode, 0, proc.stdout)
                        self.assertIn(needle, proc.stdout)

    def test_hardlink_is_refused_before_execution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-xray-hardlink-") as raw:
            target = pathlib.Path(raw) / "xray"
            alias = pathlib.Path(raw) / "xray-alias"
            target.write_bytes(b"reviewed-xray-bytes")
            os.link(target, alias)
            self.assertGreaterEqual(target.stat().st_nlink, 2)
            marker = pathlib.Path(raw) / "executed"
            for name, path, _version_var, _hash_var in SCRIPTS:
                source = path.read_text(encoding="utf-8")
                with self.subTest(script=name):
                    required = run_extracted(
                        source,
                        f'wins_require_reviewed_xray_binary "{target}"',
                    )
                    self.assertNotEqual(required.returncode, 0, required.stdout)
                    self.assertIn("regular non-hardlinked file", required.stdout)
                    self.assertFalse(marker.exists())
                    executed = run_extracted(
                        source,
                        f'wins_exec_reviewed_xray "{target}" version; printf executed > "{marker}"',
                    )
                    self.assertNotEqual(executed.returncode, 0, executed.stdout)
                    self.assertFalse(marker.exists())

    def test_hash_tool_failure_is_refused_before_execution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-xray-hashfail-") as raw:
            reviewed = pathlib.Path(raw) / "xray"
            reviewed.write_bytes(b"reviewed-xray-bytes")
            marker = pathlib.Path(raw) / "executed"
            for name, path, _version_var, _hash_var in SCRIPTS:
                source = path.read_text(encoding="utf-8")
                with self.subTest(script=name):
                    proc = run_extracted(
                        source,
                        f'wins_exec_reviewed_xray "{reviewed}" version; printf executed > "{marker}"',
                        prefix=SHA256_FAIL_MOCK,
                        mock_absolute_tools=True,
                    )
                    self.assertNotEqual(proc.returncode, 0, proc.stdout)
                    self.assertIn("Unable to hash Xray executable", proc.stdout)
                    self.assertFalse(marker.exists())

    def test_identity_change_during_attestation_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-xray-identity-") as raw:
            reviewed = pathlib.Path(raw) / "xray"
            reviewed.write_bytes(b"reviewed-xray-bytes")
            count_file = pathlib.Path(raw) / "stat-calls"
            for name, path, _version_var, _hash_var in SCRIPTS:
                source = path.read_text(encoding="utf-8")
                count_file.write_text("0", encoding="utf-8")
                with self.subTest(script=name):
                    proc = run_extracted(
                        source,
                        f'wins_require_reviewed_xray_binary "{reviewed}"',
                        extra_env={"WINS_STAT_CALL_FILE": str(count_file)},
                        prefix=SHA256_ACCEPT_MOCK + STAT_FLIP_MOCK,
                        mock_absolute_tools=True,
                        mock_stat=True,
                    )
                    self.assertNotEqual(proc.returncode, 0, proc.stdout)
                    self.assertIn("identity changed during attestation", proc.stdout)

    def test_marker_replacement_never_executes_before_attestation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-xray-marker-") as raw:
            marker = pathlib.Path(raw) / "executed"
            fake = pathlib.Path(raw) / "xray"
            fake.write_text(
                "#!/bin/sh\n"
                f'printf executed > "{marker}"\n'
                "printf 'Xray 26.9.30 (Xray, Penetrates Everything.)\\n'\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            for name, path, _version_var, _hash_var in SCRIPTS:
                source = path.read_text(encoding="utf-8")
                with self.subTest(script=name, path="exec-helper"):
                    proc = run_extracted(
                        source,
                        f'wins_exec_reviewed_xray "{fake}" version',
                    )
                    self.assertNotEqual(proc.returncode, 0, proc.stdout)
                    self.assertFalse(marker.exists(), proc.stdout)
                    self.assertIn(
                        "does not match reviewed v26.9.30 linux-64 bytes",
                        proc.stdout,
                    )
            core = CORE.read_text(encoding="utf-8")
            postflight = function_body(core, "postflight_core")
            with self.subTest(surface="core-postflight-order"):
                require_at = postflight.index(
                    "wins_require_reviewed_xray_binary /usr/local/bin/xray"
                )
                exec_at = postflight.index("wins_exec_reviewed_xray -test")
                version_at = postflight.index("wins_exec_reviewed_xray version")
                self.assertLess(require_at, exec_at)
                self.assertLess(exec_at, version_at)
                self.assertNotIn("/usr/local/bin/xray -test", postflight)
                self.assertNotIn("/usr/local/bin/xray version", postflight)
            data = function_body(
                DATA.read_text(encoding="utf-8"), "postflight_data_plane"
            )
            with self.subTest(surface="data-postflight-order"):
                require_at = data.index(
                    "wins_require_reviewed_xray_binary /usr/local/bin/xray"
                )
                exec_at = data.index("wins_exec_reviewed_xray -test")
                version_at = data.index("wins_exec_reviewed_xray version")
                self.assertLess(require_at, exec_at)
                self.assertLess(exec_at, version_at)
                self.assertNotIn("/usr/local/bin/xray -test", data)
                self.assertNotIn("/usr/local/bin/xray version", data)
            install_core = function_body(core, "install_xray")
            with self.subTest(surface="core-install-config-test"):
                self.assertLess(
                    install_core.index(
                        "wins_require_reviewed_xray_binary /usr/local/bin/xray"
                    ),
                    install_core.index("wins_exec_reviewed_xray -test"),
                )
                self.assertNotIn("/usr/local/bin/xray -test", install_core)

    def test_generated_agent_and_refresh_attest_before_xray_execution(self) -> None:
        core = CORE.read_text(encoding="utf-8")
        agent = generated_sync_agent(core)
        self.assertIn("wins_exec_reviewed_xray() {", agent)
        self.assertIn("wins_xray_linux_fd_exec() {", agent)
        self.assertIn("wins_require_reviewed_xray_binary() {", agent)
        self.assertIn("/usr/bin/python3", agent)
        self.assertIn("/proc/self/fd", agent)
        for site in (
            'wins_exec_reviewed_xray -test -config "${tmp}" >/dev/null || { rm -f -- "${tmp}"; return 1; }',
            'wins_exec_reviewed_xray -test -config "${config}" >/dev/null || return 1',
            'wins_exec_reviewed_xray -test -config "${xray_config}" >/dev/null || {',
        ):
            self.assertIn(site, agent)
        self.assertNotIn("/usr/local/bin/xray -test", agent)
        self.assertNotIn("/usr/local/bin/xray version", agent)
        for name in (
            "wins_xray_file_identity",
            "wins_require_reviewed_xray_binary",
            "wins_xray_linux_fd_exec",
            "wins_exec_reviewed_xray",
        ):
            self.assertEqual(function_body(core, name), function_body(agent, name))
        refresh = function_body(core, "refresh_core_sync_route")
        first_require = refresh.index(
            "wins_require_reviewed_xray_binary /usr/local/bin/xray"
        )
        rewrite_at = refresh.index("rewrite_core_sync_env")
        write_at = refresh.index("write_core_sync_agent")
        self.assertLess(first_require, rewrite_at)
        self.assertLess(rewrite_at, write_at)
        self.assertLess(
            refresh.rindex("wins_require_reviewed_xray_binary /usr/local/bin/xray"),
            write_at,
        )
        writer = function_body(core, "write_core_sync_agent")
        self.assertLess(
            writer.index("wins_require_reviewed_xray_binary /usr/local/bin/xray"),
            writer.index("CORE_SYNC_BUSY_EXIT_CODE=75 /usr/local/bin/wins-core-sync"),
        )
        validate = function_body(core, "validate_core_exit_runtime")
        self.assertIn(
            'wins_exec_reviewed_xray -test -config "${xray_config}" >/dev/null || return 1',
            validate,
        )
        self.assertNotIn("/usr/local/bin/xray -test", validate)

    def test_official_v26_9_30_linux64_provenance(self) -> None:
        result = retrieve_official_xray_linux64_provenance()
        self.assertIn(result["status"], {"VERIFIED", "UNVERIFIED", "FAIL"})
        if result["status"] == "UNVERIFIED":
            self.assertTrue(result["detail"])
            self.assertNotEqual(result["detail"], "matches in-tree pin")
            self.assertNotIn("self-consistent", result["detail"])
            return
        self.assertEqual(result["status"], "VERIFIED", result)
        self.assertTrue(result["latest_tag"])
        self.assertEqual(result["zip_sha256"], REVIEWED_HASH)
        self.assertEqual(result["bin_sha256"], REVIEWED_BIN_HASH)


if __name__ == "__main__":
    unittest.main()
