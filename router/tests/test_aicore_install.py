"""Offline adversarial tests for the aicore Smart Router deployment producer."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


ROUTER_DIR = Path(__file__).resolve().parent.parent
INSTALLER = ROUTER_DIR / "install_aicore_router.sh"
UNIT = ROUTER_DIR / "wins-edge-router.service.example"
ENV_EXAMPLE = ROUTER_DIR / "aicore.env.example"
RUNTIME_FILES = (
    "fallback.py",
    "gemini_client.py",
    "local_gemma_client.py",
    "main.py",
    "provider_common.py",
    "schemas.py",
    "security.py",
    "requirements.lock",
    "requirements.txt",
)
SOURCE_FILES = (*RUNTIME_FILES, "install_aicore_router.sh", "wins-edge-router.service.example")
TEST_SECRET = "offline-test-hmac-secret-0123456789abcdef"
TEST_MODEL_REVISION = "0123456789abcdef0123456789abcdef01234567"
TEST_ARTIFACT_FILES = {
    "config.json": ("config", b'{"model_type":"gemma"}\n'),
    "tokenizer.json": ("tokenizer", b'{"tokenizer_class":"GemmaTokenizer"}\n'),
    "weights/gemma.safetensors": ("weights", b"offline model weight fixture\n"),
}


def _test_artifact_inventory() -> str:
    entries = ["D . 0555", "D weights 0555"]
    for relative, (kind, data) in TEST_ARTIFACT_FILES.items():
        digest = hashlib.sha256(data).hexdigest()
        entries.append(f"F {kind} {relative} 0444 {digest}")
    return hashlib.sha256(("\n".join(sorted(entries)) + "\n").encode("ascii")).hexdigest()


TEST_ARTIFACT_INVENTORY = _test_artifact_inventory()
TEST_VLLM_MODELS_URL = ""
TEST_VLLM_MODEL_REVISION = TEST_MODEL_REVISION
TEST_VLLM_ARTIFACT_INVENTORY = TEST_ARTIFACT_INVENTORY


class _VllmModelsHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/v1/models":
            body = (
                '{"data":[{"id":"reviewed-gemma-model",'
                f'"model_revision":"{TEST_VLLM_MODEL_REVISION}",'
                f'"artifact_inventory_sha256":"{TEST_VLLM_ARTIFACT_INVENTORY}"}}]}}'
            ).encode("ascii")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def log_message(self, _format: str, *_args: object) -> None:
        return


@pytest.fixture(scope="session", autouse=True)
def vllm_models_server():
    global TEST_VLLM_MODELS_URL
    server = ThreadingHTTPServer(("127.0.0.1", 0), _VllmModelsHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    TEST_VLLM_MODELS_URL = f"http://{host}:{port}/v1/models"
    try:
        yield
    finally:
        TEST_VLLM_MODELS_URL = ""
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

VALID_ENV = f"""\
SMART_ROUTER_HMAC_SECRET={TEST_SECRET}
SMART_ROUTER_GEMMA_MODEL=reviewed-gemma-model
SMART_ROUTER_GEMMA_MODEL_REVISION={TEST_MODEL_REVISION}
SMART_ROUTER_GEMMA_ARTIFACT_ROOT=/opt/gemma-artifact
SMART_ROUTER_GEMMA_ARTIFACT_INVENTORY_SHA256=__TEST_GEMMA_INVENTORY__
SMART_ROUTER_GEMMA_URL=http://127.0.0.1:8002
GEMINI_API_KEY=
GEMINI_MODEL=
SMART_ROUTER_TOTAL_BUDGET_MS=2000
SMART_ROUTER_LOCAL_TIMEOUT_MS=850
SMART_ROUTER_GOOGLE_TIMEOUT_MS=850
SMART_ROUTER_QUEUE_TIMEOUT_MS=20
SMART_ROUTER_MAX_CONCURRENT_REQUESTS=8
SMART_ROUTER_MAX_BODY_BYTES=32768
SMART_ROUTER_RATE_LIMIT_REQUESTS=120
SMART_ROUTER_RATE_WINDOW_SECONDS=60
SMART_ROUTER_AUTH_WINDOW_SECONDS=30
SMART_ROUTER_NONCE_JOURNAL_PATH=/var/lib/winsvpn-router/replay-nonces.sqlite3
SMART_ROUTER_NONCE_JOURNAL_MAX_ENTRIES=10000
SMART_ROUTER_NONCE_JOURNAL_MAX_BYTES=16777216
SMART_ROUTER_NONCE_JOURNAL_LOCK_TIMEOUT_MS=2000
DECISIONS_FILE=/var/lib/winsvpn-router/router-decisions.jsonl
"""


def _write(path: Path, text: str, mode: int = 0o755) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


@dataclass
class Harness:
    source: Path
    target: Path
    env_file: Path
    bin_dir: Path
    state_dir: Path
    python: Path
    python_command: str
    systemctl: Path
    ss: Path
    gemma_inventory: str

    @property
    def current(self) -> Path:
        return self.target / "opt/winsvpn-router/current"

    @property
    def releases(self) -> Path:
        return self.target / "opt/winsvpn-router/releases"

    @property
    def unit(self) -> Path:
        return self.target / "etc/systemd/system/wins-edge-router.service"

    @property
    def helper(self) -> Path:
        return self.target / "usr/local/libexec/winsvpn-router-install"

    @property
    def log(self) -> Path:
        return self.state_dir / "systemctl.log"

    def run(
        self,
        mode: str,
        *,
        env_text: str | None = None,
        ss_output: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if env_text is not None:
            env_text = env_text.replace(
                "__TEST_GEMMA_INVENTORY__", self.gemma_inventory
            )
            self.env_file.write_text(env_text, encoding="utf-8")
            self.env_file.chmod(0o600)
        environment = self.environment(ss_output=ss_output)
        return subprocess.run(
            self.command(mode),
            cwd=self.source,
            env=environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def command(self, mode: str) -> list[str]:
        return [
            str(self.source / "install_aicore_router.sh"),
            mode,
            "--target-root",
            str(self.target),
            "--env-file",
            str(self.env_file),
            "--python",
            str(self.python),
            "--systemctl",
            str(self.systemctl),
            "--ss",
            str(self.ss),
        ]

    def environment(
        self,
        *,
        ss_output: str | None = None,
        extra: dict[str, str] | None = None,
    ) -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{self.bin_dir}:{environment.get('PATH', '')}",
                "WINSVPN_ROUTER_TESTING": "1",
                "WINSVPN_ROUTER_TEST_VLLM_MODELS_URL": TEST_VLLM_MODELS_URL,
                "FAKE_SYSTEMD_DIR": str(self.state_dir),
                "FAKE_SS_OUTPUT": ss_output
                if ss_output is not None
                else "LISTEN 0 4096 127.0.0.1:8002 0.0.0.0:*",
            }
        )
        if extra is not None:
            environment.update(extra)
        return environment

    def start(
        self,
        mode: str,
        *,
        extra_env: dict[str, str],
    ) -> subprocess.Popen[str]:
        return subprocess.Popen(
            self.command(mode),
            cwd=self.source,
            env=self.environment(extra=extra_env),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


@pytest.fixture()
def harness(tmp_path: Path) -> Harness:
    source = tmp_path / "router"
    shutil.copytree(
        ROUTER_DIR,
        source,
        ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"),
    )
    (source / "install_aicore_router.sh").chmod(0o755)
    target = tmp_path / "target"
    target.mkdir()
    (target / "var/tmp").mkdir(parents=True)
    artifact_root = target / "opt/gemma-artifact"
    (artifact_root / "weights").mkdir(parents=True)
    for relative, (_kind, data) in TEST_ARTIFACT_FILES.items():
        artifact_path = artifact_root / relative
        artifact_path.write_bytes(data)
        artifact_path.chmod(0o444)
    (artifact_root / "weights").chmod(0o555)
    artifact_root.chmod(0o555)
    env_file = tmp_path / "router.env"
    inventory = TEST_ARTIFACT_INVENTORY
    env_file.write_text(
        VALID_ENV.replace("__TEST_GEMMA_INVENTORY__", inventory),
        encoding="utf-8",
    )
    env_file.chmod(0o600)
    bin_dir = tmp_path / "bin"
    state_dir = tmp_path / "systemd-state"
    bin_dir.mkdir()
    state_dir.mkdir()

    # Under release-Python custody, sys.executable is the clean-environment
    # launcher by design. This fixture must preserve its explicit fake service
    # environment, so delegate to the authenticated base interpreter instead.
    real_python = Path(getattr(sys, "_base_executable", sys.executable))
    framework_root = next(
        (parent for parent in real_python.parents if parent.name == "Python.framework"),
        None,
    )
    if framework_root is None:
        relocated_python = str(real_python)
    else:
        runtime_root = framework_root.parent
        relocated_python = (
            f"/usr/bin/env DYLD_FRAMEWORK_PATH={runtime_root} "
            f"DYLD_LIBRARY_PATH={framework_root / 'Versions/3.14/lib'} {real_python}"
        )
    fake_python = _write(
        bin_dir / "python3.14",
        f"""#!/usr/bin/env bash
set -eu
if [[ "$*" == *"platform.python_version"* ]]; then
  printf '3.14.7\\n'
  exit 0
fi
if [[ "$*" == *"-m venv"* ]]; then
  destination="${{!#}}"
  mkdir -p "$destination/bin"
  cat >"$destination/bin/python" <<'RUNTIME'
#!/usr/bin/env bash
set -eu
if [[ "$*" == *"platform.python_version"* ]]; then printf '3.14.7\\n'; fi
exit 0
RUNTIME
  chmod 0755 "$destination/bin/python"
  exit 0
fi
exec {relocated_python} "$@"
""",
    )
    fake_systemctl = _write(
        bin_dir / "systemctl",
        """#!/usr/bin/env bash
set -eu
state="$FAKE_SYSTEMD_DIR"
command="$1"
if [[ "$command" == "--version" ]]; then printf 'systemd 255\n'; exit 0; fi
printf '%s\n' "$*" >>"$state/systemctl.log"
case "$command" in
  is-active) [[ -f "$state/active" ]] ;;
  is-enabled) [[ -f "$state/enabled" ]] ;;
  daemon-reload) [[ ! -f "$state/fail-daemon-reload" ]] ;;
  enable) touch "$state/enabled" ;;
  disable) rm -f "$state/enabled" ;;
  restart)
    if [[ -f "$state/fail-next-restart" ]]; then
      rm -f "$state/fail-next-restart"
      exit 1
    fi
    touch "$state/active"
    ;;
  start) touch "$state/active" ;;
  stop) rm -f "$state/active" ;;
  *) exit 2 ;;
esac
""",
    )
    fake_ss = _write(
        bin_dir / "ss",
        """#!/usr/bin/env bash
set -eu
printf '%s\n' "$FAKE_SS_OUTPUT"
""",
    )
    _write(bin_dir / "flock", "#!/bin/sh\nexit 0\n")
    _write(
        bin_dir / "id",
        f"""#!/usr/bin/env bash
set -eu
case "$1" in
  -u) if (($# == 1)); then printf '{os.getuid()}\\n'; else printf '1001\\n'; fi ;;
  -g) if (($# == 1)); then printf '{os.getgid()}\\n'; else printf '1001\\n'; fi ;;
  *) exit 2 ;;
esac
""",
    )
    fixture = Harness(
        source=source,
        target=target,
        env_file=env_file,
        bin_dir=bin_dir,
        state_dir=state_dir,
        python=fake_python,
        python_command=relocated_python,
        systemctl=fake_systemctl,
        ss=fake_ss,
        gemma_inventory=inventory,
    )
    try:
        yield fixture
    finally:
        for root, directories, files in os.walk(target, topdown=False, followlinks=False):
            root_path = Path(root)
            for name in files:
                path = root_path / name
                if not path.is_symlink():
                    path.chmod(0o644, follow_symlinks=False)
            for name in directories:
                path = root_path / name
                if not path.is_symlink():
                    path.chmod(0o755, follow_symlinks=False)
            root_path.chmod(0o755, follow_symlinks=False)


def _tree_digest(root: Path) -> str:
    rows: list[str] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if path.is_symlink():
            rows.append(f"L {relative} {os.readlink(path)}")
        elif path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            rows.append(f"F {relative} {stat.S_IMODE(info.st_mode):04o} {digest}")
        else:
            rows.append(f"D {relative} {stat.S_IMODE(info.st_mode):04o}")
    return hashlib.sha256("\n".join(rows).encode("utf-8")).hexdigest()


def _assert_failed_without_secret(
    result: subprocess.CompletedProcess[str],
) -> None:
    assert result.returncode != 0
    rendered = result.stdout + result.stderr
    assert TEST_SECRET not in rendered


def _start_deploy_paused_after_preflight(
    harness: Harness,
) -> tuple[subprocess.Popen[str], Path, Path]:
    ready = harness.state_dir / "flock-ready"
    proceed = harness.state_dir / "flock-proceed"
    _write(
        harness.bin_dir / "flock",
        """#!/usr/bin/env bash
set -eu
: "${FAKE_FLOCK_READY:?}"
: "${FAKE_FLOCK_PROCEED:?}"
touch "$FAKE_FLOCK_READY"
while [[ ! -f "$FAKE_FLOCK_PROCEED" ]]; do sleep 0.01; done
exit 0
""",
    )
    process = harness.start(
        "--deploy",
        extra_env={
            "FAKE_FLOCK_READY": str(ready),
            "FAKE_FLOCK_PROCEED": str(proceed),
        },
    )
    deadline = time.monotonic() + 10
    while not ready.exists():
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(f"installer exited before hostile swap window: {stdout}\n{stderr}")
        if time.monotonic() >= deadline:
            process.kill()
            stdout, stderr = process.communicate()
            pytest.fail(f"installer did not reach hostile swap window: {stdout}\n{stderr}")
        time.sleep(0.01)
    return process, ready, proceed


def _assert_swap_refused(
    harness: Harness,
    process: subprocess.Popen[str],
    proceed: Path,
    substituted_bytes: bytes,
) -> None:
    proceed.touch()
    stdout, stderr = process.communicate(timeout=30)
    assert process.returncode not in (None, 0), (stdout, stderr)
    assert "router source identity changed after staging" in stderr
    assert TEST_SECRET not in stdout + stderr
    assert not harness.helper.exists()
    if harness.helper.exists():
        assert harness.helper.read_bytes() != substituted_bytes
    if harness.log.exists():
        log = harness.log.read_text(encoding="utf-8")
        assert "daemon-reload" not in log
        assert "restart " not in log
        assert "start " not in log


def test_post_preflight_installer_leaf_swap_is_refused(harness: Harness) -> None:
    process, _ready, proceed = _start_deploy_paused_after_preflight(harness)
    substituted = b"#!/bin/sh\nprintf 'substituted helper ran\\n' >&2\nexit 0\n"
    replacement = harness.source.parent / "substituted-helper"
    replacement.write_bytes(substituted)
    replacement.chmod(0o755)
    os.replace(replacement, harness.source / "install_aicore_router.sh")
    _assert_swap_refused(harness, process, proceed, substituted)


def test_post_preflight_source_parent_swap_is_refused(harness: Harness) -> None:
    process, _ready, proceed = _start_deploy_paused_after_preflight(harness)
    original = harness.source.with_name("router-original")
    harness.source.rename(original)
    shutil.copytree(
        original,
        harness.source,
        ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"),
    )
    substituted = b"#!/bin/sh\nprintf 'parent-swapped helper ran\\n' >&2\nexit 0\n"
    (harness.source / "install_aicore_router.sh").write_bytes(substituted)
    (harness.source / "install_aicore_router.sh").chmod(0o755)
    _assert_swap_refused(harness, process, proceed, substituted)


def test_installer_and_unit_static_security_contract() -> None:
    script = INSTALLER.read_text(encoding="utf-8")
    unit = UNIT.read_text(encoding="utf-8")
    assert stat.S_IMODE(INSTALLER.stat().st_mode) == 0o755
    assert "set -Eeuo pipefail" in script
    assert "--require-hashes --only-binary=:all:" in script
    assert "-I -m venv --copies --without-scm-ignore-files" in script
    assert 'REQUIRED_PYTHON_VERSION="3.14.7"' in script
    assert "SOURCE_MANIFEST.sha256" in script
    assert "stage_source_closure" in script
    assert "verify_source_origin_binding" in script
    assert "verify_installed_helper" in script
    assert 'exec "${SOURCE_STAGE_DIR}/${INSTALLER_NAME}" --deploy' in script
    assert "atomic_symlink" in script
    assert "rollback_deploy" in script
    digest_match = re.search(
        r'readonly CANONICAL_UNIT_SHA256="([0-9a-f]{64})"', script
    )
    assert digest_match is not None
    assert hashlib.sha256(UNIT.read_bytes()).hexdigest() == digest_match.group(1)
    assert "set -x" not in script
    assert "eval " not in script
    assert "source \"$ENV_FILE\"" not in script
    assert "Type=exec" in unit
    assert "Slice=wins-ai.slice" in unit
    assert (
        "ExecStartPre=+/usr/local/libexec/winsvpn-router-install "
        "--verify-runtime"
    ) in unit
    assert (
        "ExecStart=/opt/winsvpn-router/current/.venv/bin/python "
        "-I -m uvicorn"
    ) in unit
    assert "--host 127.0.0.1 --port 8090 --no-access-log" in unit
    assert "http://127.0.0.1:8090/live" in script
    assert "http://127.0.0.1:8090/ready" in script
    assert "verify_deployed_endpoints" in script
    assert "StateDirectory=winsvpn-router" in unit
    assert "StateDirectoryMode=0700" in unit
    assert "ProtectHome=true" in unit
    assert "CapabilityBoundingSet=" in unit


def test_env_example_contains_no_invented_secret_or_model() -> None:
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    assert "SMART_ROUTER_HMAC_SECRET=\n" in text
    assert "SMART_ROUTER_GEMMA_MODEL=\n" in text
    assert "SMART_ROUTER_GEMMA_MODEL_REVISION=\n" in text
    assert "SMART_ROUTER_GEMMA_ARTIFACT_ROOT=\n" in text
    assert "SMART_ROUTER_GEMMA_ARTIFACT_INVENTORY_SHA256=\n" in text
    assert "SMART_ROUTER_GEMMA_URL=http://127.0.0.1:8002\n" in text
    assert "DECISIONS_FILE=/var/lib/winsvpn-router/router-decisions.jsonl" in text
    assert "gemma12b" not in text


def test_preflight_is_read_only_and_never_restarts(harness: Harness) -> None:
    before = _tree_digest(harness.target)
    result = harness.run("--preflight")
    assert result.returncode == 0, result.stderr
    assert "Smart Router preflight: PASS" in result.stdout
    assert _tree_digest(harness.target) == before
    assert not harness.log.exists()


def test_explicit_deploy_builds_exact_release_and_second_run_is_noop(
    harness: Harness,
) -> None:
    first = harness.run("--deploy")
    assert first.returncode == 0, first.stderr
    assert harness.current.is_symlink()
    release = (harness.current.parent / os.readlink(harness.current)).resolve()
    assert release.parent == harness.releases.resolve()
    assert {path.name for path in release.iterdir() if path.is_file()} == {
        *SOURCE_FILES,
        "SOURCE_MANIFEST.sha256",
        "VENV_MANIFEST.json",
    }
    assert harness.unit.read_bytes() == (harness.source / UNIT.name).read_bytes()
    assert harness.helper.read_bytes() == (harness.source / INSTALLER.name).read_bytes()
    assert stat.S_IMODE((release / "SOURCE_MANIFEST.sha256").stat().st_mode) == 0o600
    first_log = harness.log.read_text(encoding="utf-8")
    assert "daemon-reload" in first_log
    assert "enable wins-edge-router.service" in first_log
    assert "restart wins-edge-router.service" in first_log

    harness.log.unlink()
    second = harness.run("--deploy")
    assert second.returncode == 0, second.stderr
    assert "already current, no restart" in second.stdout
    second_log = harness.log.read_text(encoding="utf-8")
    assert "restart " not in second_log
    assert "daemon-reload" not in second_log
    assert len(list(harness.releases.iterdir())) == 1


def test_verify_runtime_detects_release_tampering(harness: Harness) -> None:
    assert harness.run("--deploy").returncode == 0
    assert harness.run("--verify-runtime").returncode == 0
    release = harness.current.parent / os.readlink(harness.current)
    (release / "main.py").write_text("# tampered\n", encoding="utf-8")
    _assert_failed_without_secret(harness.run("--verify-runtime"))


def test_verify_runtime_rejects_writable_release_file(harness: Harness) -> None:
    assert harness.run("--deploy").returncode == 0
    release = harness.current.parent / os.readlink(harness.current)
    (release / "main.py").chmod(0o666)
    _assert_failed_without_secret(harness.run("--verify-runtime"))


def test_verify_runtime_rejects_bearer_snapshot_unit(harness: Harness) -> None:
    assert harness.run("--deploy").returncode == 0
    canonical = harness.unit.read_bytes()
    harness.unit.write_text(
        """[Unit]
Description=Legacy bearer router

[Service]
ExecStart=/home/aicore/edge-router/venv/bin/python /home/aicore/edge-router/edge_router.py
EnvironmentFile=/etc/wins-edge-router.env
User=aicore

[Install]
WantedBy=multi-user.target
""",
        encoding="utf-8",
    )
    harness.unit.chmod(0o644)
    _assert_failed_without_secret(harness.run("--verify-runtime"))
    harness.unit.write_bytes(canonical)
    harness.unit.chmod(0o644)
    assert harness.run("--verify-runtime").returncode == 0


def test_verify_runtime_rejects_extra_unit_environment_override(harness: Harness) -> None:
    assert harness.run("--deploy").returncode == 0
    with harness.unit.open("a", encoding="utf-8") as stream:
        stream.write("Environment=SMART_ROUTER_HMAC_SECRET=unreviewed-override\n")
    _assert_failed_without_secret(harness.run("--verify-runtime"))


def test_verify_runtime_rejects_any_service_dropin(harness: Harness) -> None:
    assert harness.run("--deploy").returncode == 0
    dropin = (
        harness.target
        / "etc/systemd/system/wins-edge-router.service.d/cursor-gemma.conf"
    )
    dropin.parent.mkdir(parents=True)
    dropin.write_text(
        "[Service]\nEnvironmentFile=/etc/wins-edge-router.env\n",
        encoding="utf-8",
    )
    dropin.chmod(0o644)
    _assert_failed_without_secret(harness.run("--verify-runtime"))


def test_noop_deploy_starts_inactive_service_without_restart(
    harness: Harness,
) -> None:
    assert harness.run("--deploy").returncode == 0
    (harness.state_dir / "active").unlink()
    harness.log.unlink()
    result = harness.run("--deploy")
    assert result.returncode == 0, result.stderr
    log = harness.log.read_text(encoding="utf-8")
    assert "start wins-edge-router.service" in log
    assert "restart wins-edge-router.service" not in log
    assert (harness.state_dir / "active").is_file()


def test_failed_restart_rolls_back_current_and_new_release(
    harness: Harness,
) -> None:
    assert harness.run("--deploy").returncode == 0
    previous_target = os.readlink(harness.current)
    previous_unit = harness.unit.read_bytes()
    previous_helper = harness.helper.read_bytes()
    main = harness.source / "main.py"
    main.write_text(
        main.read_text(encoding="utf-8") + "\n# next release\n",
        encoding="utf-8",
    )
    (harness.state_dir / "fail-next-restart").touch()
    harness.log.unlink()
    result = harness.run("--deploy")
    _assert_failed_without_secret(result)
    assert "previous service state was restored" in result.stderr
    assert os.readlink(harness.current) == previous_target
    assert harness.unit.read_bytes() == previous_unit
    assert harness.helper.read_bytes() == previous_helper
    assert len(list(harness.releases.iterdir())) == 1
    assert harness.log.read_text(encoding="utf-8").count(
        "restart wins-edge-router.service"
    ) == 2


def test_build_failure_does_not_touch_running_service(harness: Harness) -> None:
    (harness.state_dir / "active").touch()
    (harness.state_dir / "enabled").touch()
    bad_python = _write(
        harness.bin_dir / "bad-venv-python",
        f"""#!/usr/bin/env bash
if [[ "$*" == *"platform.python_version"* ]]; then printf '3.14.7\\n'; exit 0; fi
if [[ "$*" == *"-m venv"* ]]; then exit 1; fi
exec {harness.python_command} "$@"
""",
    )
    original = harness.python
    harness.python = bad_python
    try:
        result = harness.run("--deploy")
    finally:
        harness.python = original
    _assert_failed_without_secret(result)
    log = harness.log.read_text(encoding="utf-8")
    assert "restart " not in log
    assert "stop " not in log
    assert not harness.current.exists()


@pytest.mark.parametrize(
    "mutation",
    [
        "non_loopback_url",
        "unknown_key",
        "duplicate_alias",
        "partial_google",
        "invalid_budget",
        "missing_journal",
        "missing_artifact_inventory",
        "unserved_model",
    ],
)
def test_environment_errors_fail_closed(harness: Harness, mutation: str) -> None:
    text = VALID_ENV
    if mutation == "non_loopback_url":
        text = text.replace("http://127.0.0.1:8002", "http://0.0.0.0:8002")
    elif mutation == "unknown_key":
        text += "SMART_ROUTER_GEMMA_MODLE=typo\n"
    elif mutation == "duplicate_alias":
        text += "GEMMA_MODEL=another-model\n"
    elif mutation == "partial_google":
        text = text.replace("GEMINI_API_KEY=\n", "GEMINI_API_KEY=temporary-google-key\n")
    elif mutation == "invalid_budget":
        text = text.replace("SMART_ROUTER_LOCAL_TIMEOUT_MS=850", "SMART_ROUTER_LOCAL_TIMEOUT_MS=1200")
    elif mutation == "missing_journal":
        text = text.replace(
            "SMART_ROUTER_NONCE_JOURNAL_PATH=/var/lib/winsvpn-router/replay-nonces.sqlite3\n",
            "",
        )
    elif mutation == "missing_artifact_inventory":
        text = text.replace(
            "SMART_ROUTER_GEMMA_ARTIFACT_INVENTORY_SHA256=__TEST_GEMMA_INVENTORY__\n",
            "SMART_ROUTER_GEMMA_ARTIFACT_INVENTORY_SHA256=\n",
        )
    elif mutation == "unserved_model":
        text = text.replace("reviewed-gemma-model", "not-served-by-vllm")
    _assert_failed_without_secret(harness.run("--preflight", env_text=text))
    assert not harness.current.exists()


def test_same_alias_with_different_revision_fails_closed(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        sys.modules[__name__], "TEST_VLLM_MODEL_REVISION", "f" * 40
    )
    result = harness.run("--preflight")
    _assert_failed_without_secret(result)
    assert not harness.current.exists()


def test_mutable_gemma_artifact_tree_fails_closed(harness: Harness) -> None:
    assert harness.run("--deploy").returncode == 0
    weights = harness.target / "opt/gemma-artifact/weights/gemma.safetensors"
    weights.chmod(0o644)
    _assert_failed_without_secret(harness.run("--verify-runtime"))


def test_symlinked_gemma_artifact_tree_fails_closed(harness: Harness) -> None:
    assert harness.run("--deploy").returncode == 0
    artifact_root = harness.target / "opt/gemma-artifact"
    config = artifact_root / "config.json"
    weights_dir = artifact_root / "weights"
    artifact_root.chmod(0o755)
    weights_dir.chmod(0o755)
    config.unlink()
    config.symlink_to(artifact_root / "tokenizer.json")
    weights_dir.chmod(0o555)
    artifact_root.chmod(0o555)
    try:
        result = harness.run("--verify-runtime")
    finally:
        weights_dir.chmod(0o755)
        artifact_root.chmod(0o755)
        if config.is_symlink():
            config.unlink()
        config.write_bytes(TEST_ARTIFACT_FILES["config.json"][1])
        config.chmod(0o444)
    _assert_failed_without_secret(result)


@pytest.mark.parametrize("mode", [0o640, 0o644, 0o666])
def test_environment_permissions_fail_closed(harness: Harness, mode: int) -> None:
    harness.env_file.chmod(mode)
    _assert_failed_without_secret(harness.run("--preflight"))


def test_environment_symlink_fails_closed(harness: Harness, tmp_path: Path) -> None:
    real = tmp_path / "real.env"
    real.write_text(VALID_ENV, encoding="utf-8")
    real.chmod(0o600)
    harness.env_file.unlink()
    harness.env_file.symlink_to(real)
    _assert_failed_without_secret(harness.run("--preflight"))


@pytest.mark.parametrize(
    "listener",
    [
        "LISTEN 0 4096 0.0.0.0:8002 0.0.0.0:*",
        "LISTEN 0 4096 [::]:8002 [::]:*",
        "LISTEN 0 4096 127.0.0.1:9000 0.0.0.0:*",
        "",
    ],
)
def test_vllm_must_be_exclusively_loopback_bound(
    harness: Harness,
    listener: str,
) -> None:
    _assert_failed_without_secret(harness.run("--preflight", ss_output=listener))


def test_mixed_loopback_and_public_vllm_listener_fails(harness: Harness) -> None:
    listeners = (
        "LISTEN 0 4096 127.0.0.1:8002 0.0.0.0:*\n"
        "LISTEN 0 4096 0.0.0.0:8002 0.0.0.0:*"
    )
    _assert_failed_without_secret(harness.run("--preflight", ss_output=listeners))


def test_unclassified_runtime_source_fails_closed(harness: Harness) -> None:
    (harness.source / "new_runtime.py").write_text("VALUE = 1\n", encoding="utf-8")
    _assert_failed_without_secret(harness.run("--preflight"))


def test_retired_edge_router_source_fails_closed(harness: Harness) -> None:
    (harness.source / "edge_router.py").write_text("VALUE = 1\n", encoding="utf-8")
    _assert_failed_without_secret(harness.run("--preflight"))


def test_bearer_snapshot_environment_key_fails_closed(harness: Harness) -> None:
    _assert_failed_without_secret(
        harness.run(
            "--preflight",
            env_text=VALID_ENV + "CURSOR_GEMMA_API_KEY=retired\n",
        )
    )


def test_symlinked_runtime_source_fails_closed(harness: Harness) -> None:
    (harness.source / "main.py").unlink()
    (harness.source / "main.py").symlink_to(harness.source / "fallback.py")
    _assert_failed_without_secret(harness.run("--preflight"))


def test_unhashed_lock_fails_closed(harness: Harness) -> None:
    lock = harness.source / "requirements.lock"
    lock.write_text(
        lock.read_text(encoding="utf-8").replace("--hash=sha256:", "--hash=sha512:"),
        encoding="utf-8",
    )
    _assert_failed_without_secret(harness.run("--preflight"))


def test_wrong_python_patch_fails_closed(harness: Harness) -> None:
    wrong_python = _write(
        harness.bin_dir / "python3.14-wrong-patch",
        """#!/usr/bin/env bash
set -eu
if [[ "$*" == *"platform.python_version"* ]]; then
  printf '3.14.6\\n'
  exit 0
fi
exit 91
""",
    )
    original = harness.python
    harness.python = wrong_python
    try:
        result = harness.run("--preflight")
    finally:
        harness.python = original
    _assert_failed_without_secret(result)
    assert "Python 3.14.7 is required" in result.stderr


def test_cli_rejects_ambiguous_modes(harness: Harness) -> None:
    result = subprocess.run(
        [str(harness.source / "install_aicore_router.sh"), "--preflight", "--deploy"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert not harness.current.exists()


def test_non_root_target_override_requires_test_guard(harness: Harness) -> None:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key != "WINSVPN_ROUTER_TESTING"
    }
    result = subprocess.run(
        [
            str(harness.source / "install_aicore_router.sh"),
            "--preflight",
            "--target-root",
            str(harness.target),
        ],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "restricted to the offline test harness" in result.stderr


def test_astra_runtime_accepts_absent_optional_provider(harness: Harness) -> None:
    assert harness.run("--deploy").returncode == 0
    result = harness.run("--verify-runtime", ss_output="")
    assert result.returncode == 0, result.stderr


def test_astra_runtime_still_rejects_public_provider(harness: Harness) -> None:
    assert harness.run("--deploy").returncode == 0
    result = harness.run("--verify-runtime", ss_output="LISTEN 0 4096 0.0.0.0:8002 0.0.0.0:*")
    _assert_failed_without_secret(result)


def test_astra_runtime_does_not_require_provider_response(harness: Harness, monkeypatch) -> None:
    assert harness.run("--deploy").returncode == 0
    monkeypatch.setattr(sys.modules[__name__], "TEST_VLLM_MODEL_REVISION", "unavailable-test-provider")
    result = harness.run("--verify-runtime")
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("change", ["bytes", "extra_file", "permissions"])
def test_astra_runtime_checks_venv_inventory(harness: Harness, change: str) -> None:
    assert harness.run("--deploy").returncode == 0
    release = (harness.target / "opt/winsvpn-router/current").resolve()
    binary = release / ".venv/bin/python"
    if change == "bytes":
        binary.write_bytes(binary.read_bytes() + b"\n")
    elif change == "extra_file":
        (release / ".venv/unexpected.txt").write_text("fixture\n")
    else:
        binary.chmod(0o777)
    _assert_failed_without_secret(harness.run("--verify-runtime"))
