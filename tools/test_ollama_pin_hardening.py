#!/usr/bin/env python3
"""M-4 regression contracts for the core server's Ollama setup.

`server/wins_core_server_setup_ONETOUCH.sh` is the only Ollama setup script.
It pulls mutable model tags, then fail-closes unless the digest reported by
Ollama's local API matches the reviewed Gemma 4 allowlist. The aicore router
is separately served by vLLM and must not be treated as an Ollama deployment.
"""

from __future__ import annotations

import http.server
import importlib.util
import os
import pathlib
import re
import shlex
import subprocess
import sys
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORE_SCRIPT_PATH = ROOT / "server/wins_core_server_setup_ONETOUCH.sh"
AUDIT_SCRIPT_PATH = ROOT / "tools/verify_deployment_supply_chain.py"

CORE_SOURCE = CORE_SCRIPT_PATH.read_text(encoding="utf-8")

_SPEC = importlib.util.spec_from_file_location("verify_deployment_supply_chain", AUDIT_SCRIPT_PATH)
assert _SPEC and _SPEC.loader
AUDIT = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = AUDIT
_SPEC.loader.exec_module(AUDIT)

HEX64 = re.compile(r"^[0-9a-f]{64}$")
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def _find_associative_array_bash() -> str | None:
    """Find Bash 4+ when macOS also exposes its legacy Bash 3 shell."""

    candidates: list[str] = []
    for directory in os.get_exec_path():
        candidate = str(pathlib.Path(directory) / "bash")
        if candidate not in candidates and pathlib.Path(candidate).is_file():
            candidates.append(candidate)
    for candidate in candidates:
        result = subprocess.run(
            [candidate, "-c", '[[ "${BASH_VERSINFO[0]}" -ge 4 ]]'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode == 0:
            return candidate
    return None


BASH_WITH_ASSOCIATIVE_ARRAYS = _find_associative_array_bash()


def _extract_bash_array(source: str, name: str) -> str:
    pattern = r"declare -A " + re.escape(name) + r"=\(\n(.*?)\n\)\n"
    match = re.search(pattern, source, re.DOTALL)
    assert match, f"could not find declare -A block for {name}"
    return match.group(0)


def _extract_bash_function(source: str, name: str) -> str:
    pattern = re.escape(name) + r"\(\) \{\n(.*?)\n\}\n"
    match = re.search(pattern, source, re.DOTALL)
    assert match, f"could not find bash function {name}()"
    return match.group(0)


def _parse_bash_digest_map(block: str) -> dict[str, str]:
    return dict(re.findall(r'\["([^"]+)"\]="([0-9a-f]{64})"', block))


class _FakeOllamaServer:
    """A minimal stand-in for a local `ollama serve`'s /api/tags endpoint."""

    def __init__(self, models: list[dict]) -> None:
        import json

        payload = json.dumps({"models": models}).encode("utf-8")

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 (stdlib method name)
                if self.path != "/api/tags":
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args: object) -> None:  # silence stdlib logging
                return

        self._httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def __enter__(self) -> "_FakeOllamaServer":
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


def _make_ollama_stub(tmpdir: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    """A fake `ollama` executable that just logs its argv, for asserting
    whether/how a real bash script attempts to clean up an untrusted model.
    """

    log_path = tmpdir / "ollama_invocations.log"
    stub_path = tmpdir / "ollama"
    stub_path.write_text("#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> " + shlex.quote(str(log_path)) + "\n")
    stub_path.chmod(0o755)
    return stub_path, log_path


def _run_bash_digest_check(
    *,
    declare_block: str,
    function_block: str,
    function_name: str,
    port_var: str,
    port: int,
    model: str,
    ollama_stub_dir: str | None = None,
) -> subprocess.CompletedProcess:
    script = "\n".join(
        [
            "#!/usr/bin/env bash",
            "set -Eeuo pipefail",
            "log() { printf '[LOG] %s\\n' \"$*\"; }",
            "warn() { printf '[WARN] %s\\n' \"$*\" >&2; }",
            declare_block,
            function_block,
            f"{port_var}={port}",
            f"{function_name} {shlex.quote(model)}",
        ]
    )
    env = None
    if ollama_stub_dir is not None:
        env = dict(os.environ)
        env["PATH"] = f"{ollama_stub_dir}:{env.get('PATH', '')}"
    return subprocess.run(
        [BASH_WITH_ASSOCIATIVE_ARRAYS, "-c", script],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )


class SourceContractTests(unittest.TestCase):
    """Source-level assertions for the only Ollama setup script."""

    def test_core_script_pins_a_reviewed_ollama_version(self) -> None:
        match = re.search(r'CORE_AI_OLLAMA_PINNED_VERSION="\$\{CORE_AI_OLLAMA_PINNED_VERSION:-([^}]+)\}"', CORE_SOURCE)
        self.assertIsNotNone(match, "CORE_AI_OLLAMA_PINNED_VERSION default is missing")
        self.assertEqual(match.group(1), "0.40.2")
        self.assertTrue(SEMVER.match(match.group(1)), f"not a reviewed semver pin: {match.group(1)!r}")

    def test_core_script_uses_the_pin_at_install_time_and_verifies_after(self) -> None:
        # Installer fix wave, lane FX-CORE-B Turn 3 (Sol OI-COREB-T2-2): the
        # pinned version now selects a digest-pinned release archive that is
        # verified before extraction; upstream install.sh is no longer run.
        self.assertNotIn("ollama.com/install.sh", CORE_SOURCE)
        url = 'releases/download/v${CORE_AI_OLLAMA_PINNED_VERSION}/ollama-linux-amd64.tar.zst'
        self.assertIn(url, CORE_SOURCE)
        download = CORE_SOURCE.index(url)
        archive_check = CORE_SOURCE.index('"${CORE_AI_OLLAMA_ARCHIVE_SHA256}" "${archive}" | sha256sum -c -', download)
        extract = CORE_SOURCE.index('zstd -dc -- "${archive}" | tar -x', archive_check)
        staged_check = CORE_SOURCE.index('"${staged_sha}" != "${CORE_AI_OLLAMA_BINARY_SHA256}"', extract)
        version_check = CORE_SOURCE.index("installed_ollama_version=", staged_check)
        mismatch_guard = CORE_SOURCE.index("does not match pinned CORE_AI_OLLAMA_PINNED_VERSION", version_check)
        self.assertLess(download, archive_check)
        self.assertLess(extract, staged_check)
        self.assertLess(version_check, mismatch_guard)

    def test_core_script_has_reviewed_model_digest_allowlist(self) -> None:
        digests = _parse_bash_digest_map(_extract_bash_array(CORE_SOURCE, "CORE_AI_MODEL_DIGESTS"))
        self.assertEqual(set(digests), {"gemma4:12b", "gemma4:e4b"})
        for tag, digest in digests.items():
            self.assertTrue(HEX64.match(digest), f"{tag} digest is not 64 lowercase hex chars: {digest!r}")

    def test_core_script_gates_hoppy_creation_on_digest_verification(self) -> None:
        pull = CORE_SOURCE.index('ollama pull "${CORE_AI_BASE_MODEL}"')
        verify_call = CORE_SOURCE.index('if verify_core_ai_model_digest "${CORE_AI_BASE_MODEL}"; then', pull)
        write_hoppy = CORE_SOURCE.index("write_hoppy_core_model", verify_call)
        self.assertLess(pull, verify_call)
        self.assertLess(verify_call, write_hoppy)
        # write_hoppy_core_model must be inside the success branch, not called
        # unconditionally afterwards.
        between = CORE_SOURCE[verify_call:write_hoppy]
        self.assertNotIn("\nelse\n", between)

    def test_pinned_ollama_version_matches_the_registry_audit_contract(self) -> None:
        core_version = re.search(r'CORE_AI_OLLAMA_PINNED_VERSION="\$\{CORE_AI_OLLAMA_PINNED_VERSION:-([^}]+)\}"', CORE_SOURCE).group(1)
        self.assertEqual(core_version, AUDIT.OLLAMA_PINNED_VERSION)

    def test_model_content_digests_match_the_registry_audit_contract(self) -> None:
        core_digests = _parse_bash_digest_map(_extract_bash_array(CORE_SOURCE, "CORE_AI_MODEL_DIGESTS"))
        self.assertEqual(core_digests, AUDIT.OLLAMA_MODEL_CONTENT_DIGESTS)

    def test_core_model_selection_is_gemma4_only_with_no_qwen_fallback(self) -> None:
        selector = _extract_bash_function(CORE_SOURCE, "choose_core_ai_base_model")
        self.assertIn("printf 'gemma4:12b'", selector)
        self.assertIn("printf 'gemma4:e4b'", selector)
        self.assertIn("Refusing to serve Hoppy from a qwen2.5 fallback", selector)
        self.assertNotRegex(selector, r"printf ['\"]qwen")


@unittest.skipUnless(BASH_WITH_ASSOCIATIVE_ARRAYS, "no Bash executable supports associative arrays")
class BashModelDigestMechanismTests(unittest.TestCase):
    """Executes the real bash digest-verification logic against a fake server."""

    CORE = {
        "source": CORE_SOURCE,
        "array_name": "CORE_AI_MODEL_DIGESTS",
        "function_name": "verify_core_ai_model_digest",
        "port_var": "CORE_AI_PORT",
    }

    def _check(
        self, *, model: str, models_response: list[dict], ollama_stub_dir: str | None = None
    ) -> subprocess.CompletedProcess:
        spec = self.CORE
        declare_block = _extract_bash_array(spec["source"], spec["array_name"])
        function_block = _extract_bash_function(spec["source"], spec["function_name"])
        with _FakeOllamaServer(models_response) as server:
            return _run_bash_digest_check(
                declare_block=declare_block,
                function_block=function_block,
                function_name=spec["function_name"],
                port_var=spec["port_var"],
                port=server.port,
                model=model,
                ollama_stub_dir=ollama_stub_dir,
            )

    def test_accepts_a_matching_digest(self) -> None:
        result = self._check(
            model="gemma4:12b",
            models_response=[
                {"name": "gemma4:12b", "model": "gemma4:12b", "digest": "sha256:6114515d63c17436a7c0417d82820ac65ad643e2806c5a3c89cb62846436ed0b"}
            ],
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Verified gemma4:12b content digest matches the reviewed pin", result.stdout)

    def test_rejects_a_mismatched_digest(self) -> None:
        result = self._check(
            model="gemma4:12b",
            models_response=[{"name": "gemma4:12b", "model": "gemma4:12b", "digest": "sha256:" + "0" * 64}],
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Content digest mismatch for gemma4:12b", result.stderr)

    def test_rejects_when_model_absent_from_api_response(self) -> None:
        result = self._check(
            model="gemma4:12b",
            models_response=[{"name": "some-other-model:latest", "model": "some-other-model:latest", "digest": "sha256:" + "1" * 64}],
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Could not read a local digest for gemma4:12b", result.stderr)

    def test_rejects_an_unpinned_model_tag(self) -> None:
        result = self._check(model="qwen2.5:3b", models_response=[])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No reviewed content digest is pinned for qwen2.5:3b", result.stderr)

    def test_matches_regardless_of_bare_vs_sha256_prefixed_digest_field(self) -> None:
        # Ollama's own /api/tags has returned bare hex digests in some
        # versions; the check must not depend on the "sha256:" prefix.
        result = self._check(
            model="gemma4:e4b",
            models_response=[{"name": "gemma4:e4b", "model": "gemma4:e4b", "digest": "dc35e8d9c6061baa6f0fa870975ab6932e2542b579b13ea0f199fa4bb7300c9c"}],
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_removes_the_untrusted_local_copy_on_mismatch(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            stub_dir = pathlib.Path(tmp)
            _, log_path = _make_ollama_stub(stub_dir)
            result = self._check(
                model="gemma4:12b",
                models_response=[{"name": "gemma4:12b", "model": "gemma4:12b", "digest": "sha256:" + "0" * 64}],
                ollama_stub_dir=str(stub_dir),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(log_path.exists(), "verify function never invoked ollama to clean up")
            self.assertEqual(log_path.read_text().strip(), "rm gemma4:12b")

    def test_does_not_invoke_ollama_rm_when_digest_matches(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            stub_dir = pathlib.Path(tmp)
            _, log_path = _make_ollama_stub(stub_dir)
            result = self._check(
                model="gemma4:12b",
                models_response=[
                    {"name": "gemma4:12b", "model": "gemma4:12b", "digest": "sha256:6114515d63c17436a7c0417d82820ac65ad643e2806c5a3c89cb62846436ed0b"}
                ],
                ollama_stub_dir=str(stub_dir),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(log_path.exists(), "verified pull unexpectedly triggered a cleanup rm")


if __name__ == "__main__":
    unittest.main()
