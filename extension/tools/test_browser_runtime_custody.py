#!/usr/bin/env python3
"""Adversarial custody tests for authenticated browser runtime execution.

These tests prove descriptor-walked snapshots, receipt-bound digests, codesign,
Seatbelt-helper re-verification, debugging-pipe isolation, and fail-closed
descendant cleanup. They do not claim kernel-bound exact execution against
same-UID path replacement on macOS: that boundary is unavailable, and Chrome
is launched only if it is proven.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parents[1]
sys.path.insert(0, str(TOOLS))

import core_tests  # noqa: E402
import cdp  # noqa: E402

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="macOS posix_spawn required")


def _compile(tmp_path: Path, name: str, source: str, extra: list[str] | None = None) -> Path:
    src = tmp_path / f"{name}.c"
    out = tmp_path / name
    src.write_text(source, encoding="utf-8")
    subprocess.run(
        ["/usr/bin/clang", "-Os", "-o", str(out), str(src), *(extra or ())],
        check=True,
        capture_output=True,
        text=True,
    )
    out.chmod(0o755)
    return out


def _compile_dylib(tmp_path: Path, name: str, source: str) -> Path:
    src = tmp_path / f"{name}.c"
    out = tmp_path / f"{name}.dylib"
    src.write_text(source, encoding="utf-8")
    subprocess.run(
        [
            "/usr/bin/clang",
            "-dynamiclib",
            "-install_name",
            f"@rpath/{out.name}",
            "-Os",
            "-o",
            str(out),
            str(src),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    out.chmod(0o755)
    return out


def _env(tmp_path: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    home = tmp_path / "home"
    tmp = tmp_path / "tmp"
    home.mkdir(exist_ok=True)
    tmp.mkdir(exist_ok=True)
    return core_tests.browser_child_env(str(home), str(tmp), extra)


def _pin(path: Path, *, root: Path | None = None, app: Path | None = None) -> dict[str, str | bool | None]:
    executable = Path(path)
    tree = app or root or core_tests.app_bundle_for_executable(executable) or executable
    entries = core_tests.inspect_source_tree(tree)
    kwargs: dict[str, str | bool | None] = {
        "expected_executable_sha256": core_tests._sha256_path(str(executable)),
        "expected_tree_sha256": core_tests.tree_binding_digest(entries),
        "archive_tree": False,
    }
    if app is not None:
        kwargs["source_app"] = str(app)
    if root is not None:
        kwargs["source_root"] = str(root)
        kwargs["source_app"] = str(app or core_tests.app_bundle_for_executable(executable) or "")
    elif core_tests.app_bundle_for_executable(executable) is not None:
        kwargs["source_app"] = str(core_tests.app_bundle_for_executable(executable))
    return kwargs


def _codesign_app(app: Path) -> str:
    completed = subprocess.run(
        ["/usr/bin/codesign", "-s", "-", "--force", "--deep", str(app)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        pytest.skip(f"adhoc codesign unavailable: {completed.stderr}")
    identity, _designated = core_tests._codesign_display(app)
    return identity


def _make_framework_app(tmp_path: Path, *, marker_text: str) -> tuple[Path, Path]:
    app = tmp_path / "Honest.app"
    macos = app / "Contents" / "MacOS"
    frameworks = app / "Contents" / "Frameworks"
    macos.mkdir(parents=True)
    frameworks.mkdir(parents=True)
    (app / "Contents" / "Info.plist").write_text(
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' "
        "'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>\n"
        "<plist version='1.0'><dict>"
        "<key>CFBundleExecutable</key><string>tool</string>"
        "<key>CFBundleIdentifier</key><string>org.winsvpn.fixture.browser</string>"
        "<key>CFBundleName</key><string>tool</string>"
        "</dict></plist>\n",
        encoding="utf-8",
    )
    dylib = _compile_dylib(
        tmp_path,
        "libmarker",
        f"""
#include <stdio.h>
#include <stdlib.h>
void marker(void) {{
  const char *path = getenv("MARKER_PATH");
  FILE *file = fopen(path, "w");
  if (!file) return;
  fputs("{marker_text}\\n", file);
  fclose(file);
}}
""",
    )
    dest_dylib = frameworks / "libmarker.dylib"
    dest_dylib.write_bytes(dylib.read_bytes())
    dest_dylib.chmod(0o755)
    tool = _compile(
        tmp_path,
        "tool",
        """
void marker(void);
int main(void) {
  marker();
  return 0;
}
""",
        extra=[str(dest_dylib), "-Wl,-rpath,@executable_path/../Frameworks"],
    )
    spawn = macos / "tool"
    spawn.write_bytes(tool.read_bytes())
    spawn.chmod(0o755)
    return app, spawn


def test_core_tests_source_uses_pipe_not_released_port():
    source = (TOOLS / "core_tests.py").read_text(encoding="utf-8")
    assert "--remote-debugging-pipe" in source
    assert "--remote-debugging-port" not in source
    assert "cdp_port" not in source
    assert "wait_for_endpoint" not in source
    assert "list_targets(" not in source
    assert "subprocess.Popen" not in source
    assert "posix_spawn" in source
    assert "sandbox-exec" in source
    assert "WINS_RELEASE_BROWSER_SHA256" in source
    assert "WINS_RELEASE_BROWSER_TREE_SHA256" in source
    assert "receipt" in source
    assert "request_path.read_text" not in source
    assert "write_spawn_request_fd" in source
    assert "process_birth_identity" in source


def test_replacement_bytes_never_execute(tmp_path: Path):
    marker = tmp_path / "marker"
    original = _compile(
        tmp_path,
        "original",
        r"""
#include <stdio.h>
#include <stdlib.h>
int main(void) {
  const char *path = getenv("MARKER_PATH");
  FILE *file = fopen(path, "w");
  if (!file) return 11;
  fputs("original-bytes\n", file);
  fclose(file);
  return 0;
}
""",
    )
    replacement = _compile(
        tmp_path,
        "replacement",
        r"""
#include <stdio.h>
#include <stdlib.h>
int main(void) {
  const char *path = getenv("MARKER_PATH");
  FILE *file = fopen(path, "w");
  if (!file) return 12;
  fputs("replacement-bytes\n", file);
  fclose(file);
  return 0;
}
""",
    )
    pin = _pin(original)
    image = core_tests.authenticated_execution_image(str(original), **pin)
    try:
        os.replace(replacement, original)
        child = core_tests.spawn_execution_image(
            image, [], _env(tmp_path, {"MARKER_PATH": str(marker)})
        )
        try:
            assert child.wait(timeout=5) == 0
        finally:
            child.terminate(timeout=2)
    finally:
        if not getattr(image, "_cleaned", False):
            image.cleanup()
    assert marker.read_text(encoding="utf-8") == "original-bytes\n"


def test_pre_open_substitution_is_rejected_against_receipt(tmp_path: Path):
    original = _compile(tmp_path, "honest", "int main(void) { return 0; }\n")
    replacement = _compile(tmp_path, "hostile", "int main(void) { return 13; }\n")
    pin = _pin(original)
    os.replace(replacement, original)
    with pytest.raises(RuntimeError, match="receipt digest"):
        core_tests.authenticated_execution_image(str(original), **pin)


def test_custody_post_check_rejects_mutated_execution_image(tmp_path: Path):
    original = _compile(tmp_path, "honest", "int main(void) { return 0; }\n")
    replacement = _compile(tmp_path, "mutated", "int main(void) { return 13; }\n")
    image = core_tests.authenticated_execution_image(str(original), **_pin(original))
    try:
        path = Path(image.path)
        if stat.UF_IMMUTABLE:
            try:
                os.chflags(path, 0)
            except OSError:
                pass
        os.chmod(path, 0o700)
        path.write_bytes(replacement.read_bytes())
        os.chmod(path, 0o500)
        with pytest.raises(RuntimeError, match="digest changed|tree changed|receipt"):
            core_tests.spawn_execution_image(image, [], _env(tmp_path))
    finally:
        image.cleanup()


def test_verify_to_spawn_swap_is_rejected_by_helper(tmp_path: Path):
    original = _compile(tmp_path, "honest", "int main(void) { return 0; }\n")
    replacement = _compile(tmp_path, "swap", "int main(void) { return 14; }\n")
    image = core_tests.authenticated_execution_image(str(original), **_pin(original))
    real_seal = image.seal
    real_verify = image.verify
    calls = {"verify": 0}

    def verify_once() -> None:
        calls["verify"] += 1
        if calls["verify"] == 1:
            real_verify()

    def swap_after_seal() -> None:
        real_seal()
        core_tests._clear_tree_for_delete(Path(image.sealed_root))
        Path(image.path).write_bytes(replacement.read_bytes())

    image.verify = verify_once  # type: ignore[method-assign]
    image.seal = swap_after_seal  # type: ignore[method-assign]
    try:
        with pytest.raises(RuntimeError, match="helper did not reach verified posix_spawn|digest|inode"):
            core_tests.spawn_execution_image(image, [], _env(tmp_path))
    finally:
        image.cleanup()


def test_framework_replacement_is_rejected(tmp_path: Path):
    app, spawn = _make_framework_app(tmp_path, marker_text="honest-framework")
    identity = _codesign_app(app)
    pin = _pin(spawn, app=app)
    hostile = _compile_dylib(
        tmp_path,
        "hostilemarker",
        r"""
#include <stdio.h>
#include <stdlib.h>
void marker(void) {
  const char *path = getenv("MARKER_PATH");
  FILE *file = fopen(path, "w");
  if (!file) return;
  fputs("hostile-framework\n", file);
  fclose(file);
}
""",
    )
    os.replace(hostile, app / "Contents" / "Frameworks" / "libmarker.dylib")
    with pytest.raises(RuntimeError, match="receipt digest"):
        core_tests.authenticated_execution_image(
            str(spawn),
            expected_signing_identity=identity,
            **pin,
        )


def test_framework_app_positive_control_runs_signed_bundle(tmp_path: Path):
    marker = tmp_path / "marker"
    app, spawn = _make_framework_app(tmp_path, marker_text="honest-framework")
    identity = _codesign_app(app)
    pin = _pin(spawn, app=app)
    child = core_tests.spawn_authenticated(
        str(spawn),
        [],
        _env(tmp_path, {"MARKER_PATH": str(marker)}),
        expected_signing_identity=identity,
        **pin,
    )
    try:
        assert child.wait(timeout=5) == 0
    finally:
        child.terminate(timeout=2)
    assert marker.read_text(encoding="utf-8") == "honest-framework\n"


def test_mixed_bundle_is_rejected(tmp_path: Path):
    app, spawn = _make_framework_app(tmp_path, marker_text="honest-framework")
    extra = app / "Contents" / "Extra.app" / "Contents" / "MacOS"
    extra.mkdir(parents=True)
    (extra / "evil").write_bytes(spawn.read_bytes())
    (extra / "evil").chmod(0o755)
    with pytest.raises(RuntimeError, match="mixed application bundle"):
        core_tests.authenticated_execution_image(str(spawn), **_pin(spawn, app=app))


def test_environment_poisoning_is_omitted_from_browser_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    marker = tmp_path / "environ"
    probe = _compile(
        tmp_path,
        "envprobe",
        r"""
#include <stdio.h>
#include <stdlib.h>
extern char **environ;
int main(void) {
  const char *path = getenv("MARKER_PATH");
  FILE *file = fopen(path, "w");
  if (!file) return 14;
  for (char **cursor = environ; *cursor; cursor++) {
    fputs(*cursor, file);
    fputc('\n', file);
  }
  fclose(file);
  return 0;
}
""",
    )
    poisoned = {
        "DYLD_INSERT_LIBRARIES": "/private/tmp/attacker.dylib",
        "DYLD_FRAMEWORK_PATH": "/private/tmp/python-framework",
        "PYTHONPATH": "/private/tmp/evil-python",
        "PYTHONHOME": "/private/tmp/evil-home",
        "JAVA_HOME": "/private/tmp/java",
        "OPENSSL_CONF": "/private/tmp/openssl.cnf",
        "WINS_RELEASE_OPENSSL": "/private/tmp/openssl",
        "WINS_ANDROID_KEY_PASSWORD": "must-not-reach-browser",
        "WINS_RELEASE_CHILD_PYTHON": "/private/tmp/python",
        "WINS_RELEASE_BROWSER": "/private/tmp/browser",
        "BROWSER_BIN": "/private/tmp/browser",
    }
    for name, value in poisoned.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match="DYLD_INSERT_LIBRARIES"):
        core_tests.browser_child_env(
            str(tmp_path), str(tmp_path), extra={"DYLD_INSERT_LIBRARIES": "x"}
        )
    child = core_tests.spawn_authenticated(
        str(probe), [], _env(tmp_path, {"MARKER_PATH": str(marker)}), **_pin(probe)
    )
    try:
        assert child.wait(timeout=5) == 0
    finally:
        child.terminate(timeout=2)
    dumped = marker.read_text(encoding="utf-8")
    for name in poisoned:
        assert name not in dumped
        assert poisoned[name] not in dumped
    assert "MARKER_PATH=" in dumped
    assert "PYTHONPATH=" not in dumped
    assert "DYLD_" not in dumped
    assert "JAVA_HOME=" not in dumped
    assert "OPENSSL" not in dumped
    assert "WINS_RELEASE_BROWSER=" not in dumped


def test_adversarial_loopback_claimant_cannot_satisfy_cdp(tmp_path: Path):
    connections = {"count": 0}

    class Claimant(threading.Thread):
        def __init__(self) -> None:
            super().__init__(daemon=True)
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("127.0.0.1", 0))
            self.port = self.sock.getsockname()[1]
            self.sock.listen(16)
            self.sock.settimeout(0.2)
            self.stop = threading.Event()

        def run(self) -> None:
            while not self.stop.is_set():
                try:
                    conn, _addr = self.sock.accept()
                except (TimeoutError, socket.timeout):
                    continue
                connections["count"] += 1
                try:
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                        b'{"webSocketDebuggerUrl":"ws://127.0.0.1/devtools/browser/hostile"}'
                    )
                except OSError:
                    pass
                conn.close()

        def close(self) -> None:
            self.stop.set()
            try:
                self.sock.close()
            except OSError:
                pass

    marker = tmp_path / "argv"
    fixture = _compile(
        tmp_path,
        "fake-chrome",
        r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
  const char *path = getenv("MARKER_PATH");
  FILE *file = fopen(path, "w");
  if (!file) return 15;
  for (int i = 0; i < argc; i++) {
    fputs(argv[i], file);
    fputc('\n', file);
  }
  fclose(file);
  usleep(400000);
  return 0;
}
""",
    )
    claimant = Claimant()
    claimant.start()
    try:
        child = core_tests.spawn_authenticated(
            str(fixture),
            [
                f"--user-data-dir={tmp_path / 'profile'}",
                "--enable-unsafe-extension-debugging",
                "--remote-debugging-pipe",
                "--headless=new",
                "about:blank",
            ],
            _env(tmp_path, {"MARKER_PATH": str(marker)}),
            debugging_pipe=True,
            **_pin(fixture),
        )
        try:
            child.wait(timeout=5)
        finally:
            child.terminate(timeout=2)
    finally:
        claimant.close()
        claimant.join(timeout=2)
    argv = marker.read_text(encoding="utf-8").splitlines()
    assert any(arg == "--remote-debugging-pipe" for arg in argv)
    assert all(not arg.startswith("--remote-debugging-port") for arg in argv)
    assert connections["count"] == 0
    source = (TOOLS / "core_tests.py").read_text(encoding="utf-8")
    assert "launch_headless_chrome" in source
    assert "--remote-debugging-pipe" in source.split("def launch_headless_chrome", 1)[1]


def test_timeout_kills_descendants_including_new_process_group(tmp_path: Path):
    marker = tmp_path / "pids"
    sleeper = _compile(
        tmp_path,
        "forker",
        r"""
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(void) {
  const char *path = getenv("MARKER_PATH");
  pid_t child = fork();
  if (child == 0) {
    setpgid(0, 0);
    signal(SIGTERM, SIG_IGN);
    for (;;) pause();
  }
  FILE *file = fopen(path, "w");
  if (!file) return 16;
  fprintf(file, "%d %d\n", getpid(), child);
  fclose(file);
  for (;;) pause();
}
""",
    )
    child = core_tests.spawn_authenticated(
        str(sleeper), [], _env(tmp_path, {"MARKER_PATH": str(marker)}), **_pin(sleeper)
    )
    deadline = time.time() + 5
    while time.time() < deadline and not marker.exists():
        time.sleep(0.05)
    pids = marker.read_text(encoding="utf-8").split()
    parent_pid, grandchild_pid = int(pids[0]), int(pids[1])
    child.terminate(timeout=2)
    time.sleep(0.2)
    assert not core_tests._pid_alive(parent_pid)
    assert not core_tests._pid_alive(grandchild_pid)


def test_late_fork_setsid_is_reaped_or_cleanup_fails(tmp_path: Path):
    marker = tmp_path / "pids"
    sleeper = _compile(
        tmp_path,
        "latefork",
        r"""
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(void) {
  const char *path = getenv("MARKER_PATH");
  pid_t helper = fork();
  if (helper == 0) {
    usleep(400000);
    pid_t child = fork();
    if (child == 0) {
      setsid();
      signal(SIGTERM, SIG_IGN);
      for (;;) pause();
    }
    FILE *file = fopen(path, "w");
    if (!file) _exit(16);
    fprintf(file, "%d %d %d\n", getppid(), getpid(), child);
    fclose(file);
    for (;;) pause();
  }
  for (;;) pause();
}
""",
    )
    child = core_tests.spawn_authenticated(
        str(sleeper), [], _env(tmp_path, {"MARKER_PATH": str(marker)}), **_pin(sleeper)
    )
    deadline = time.time() + 5
    while time.time() < deadline and not marker.exists():
        time.sleep(0.05)
    pids = [int(item) for item in marker.read_text(encoding="utf-8").split()]
    assert len(pids) == 3
    grandchild = pids[2]
    cleanup_error = None
    try:
        child.terminate(timeout=3)
    except core_tests.ProcessTreeCleanupError as exc:
        cleanup_error = exc
    time.sleep(0.2)
    alive = core_tests._pid_alive(grandchild)
    if alive:
        try:
            os.kill(grandchild, 9)
        except OSError:
            pass
    assert cleanup_error is not None or not alive


def test_unknown_status_is_nonzero_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    fixture = _compile(tmp_path, "ok", "int main(void) { return 0; }\n")
    child = core_tests.spawn_authenticated(str(fixture), [], _env(tmp_path), **_pin(fixture))
    try:
        def boom(_pid: int, _flags: int = 0) -> tuple[int, int]:
            raise ChildProcessError("already reaped")

        monkeypatch.setattr(os, "waitpid", boom)
        with pytest.raises(RuntimeError, match="status is unavailable"):
            child.wait(timeout=1)
    finally:
        monkeypatch.undo()
        try:
            child.terminate(timeout=2)
        except core_tests.ProcessTreeCleanupError:
            pass


def test_unknown_wait_status_is_nonzero_failure():
    with pytest.raises(RuntimeError, match="unknown wait status"):
        core_tests._status_to_exitcode(0x7F)


def test_cleanup_failure_is_raised(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    fixture = _compile(tmp_path, "ok", "int main(void) { return 0; }\n")
    child = core_tests.spawn_authenticated(str(fixture), [], _env(tmp_path), **_pin(fixture))
    child.wait(timeout=5)

    def survivors(_root: int, seen_pids: set[int], seen_groups: set[int]):
        return {999999}, seen_groups | {999999}, ["permission error signalling pid 999999"]

    monkeypatch.setattr(core_tests, "_live_tracked", survivors)
    with pytest.raises(core_tests.ProcessTreeCleanupError, match="permission error|survivors"):
        child.terminate(timeout=0.2)


def test_debugging_pipe_is_process_owned_and_not_a_tcp_port(tmp_path: Path):
    fixture = _compile(
        tmp_path,
        "pipe-child",
        r"""
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(void) {
  const char *path = getenv("MARKER_PATH");
  FILE *file = fopen(path, "w");
  if (!file) return 17;
  fprintf(file, "fd3=%d\n", fcntl(3, F_GETFD) != -1);
  fprintf(file, "fd4=%d\n", fcntl(4, F_GETFD) != -1);
  char buf[8];
  ssize_t n = read(3, buf, sizeof(buf));
  fprintf(file, "read3=%zd errno=%d\n", n, errno);
  fclose(file);
  return 0;
}
""",
    )
    marker = tmp_path / "pipe"
    child = core_tests.spawn_authenticated(
        str(fixture),
        [],
        _env(tmp_path, {"MARKER_PATH": str(marker)}),
        debugging_pipe=True,
        **_pin(fixture),
    )
    try:
        assert child.transport is not None
        assert isinstance(child.transport, cdp.PipeTransport)
        child.transport.send('{"id":1,"method":"Browser.getVersion"}')
        child.wait(timeout=5)
    finally:
        child.terminate(timeout=2)
    text = marker.read_text(encoding="utf-8")
    assert "fd3=1" in text
    assert "fd4=1" in text
    assert "read3=" in text
    assert "read3=-1" not in text


def test_browser_child_env_omits_python_java_openssl_and_secrets():
    env = core_tests.browser_child_env("/tmp/home", "/tmp/tmp")
    for name in env:
        assert not core_tests.env_is_forbidden(name)
    assert env["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin"
    assert "DYLD_FRAMEWORK_PATH" not in env
    assert "PYTHONPATH" not in env
    assert "JAVA_HOME" not in env
    assert "OPENSSL_CONF" not in env
    assert "BROWSER_BIN" not in env
    assert "WINS_RELEASE_BROWSER" not in env
    with pytest.raises(ValueError):
        core_tests.browser_child_env("/tmp/home", "/tmp/tmp", extra={"JAVA_HOME": "x"})
    with pytest.raises(ValueError):
        core_tests.browser_child_env(
            "/tmp/home", "/tmp/tmp", extra={"WINS_ANDROID_STORE_PASSWORD": "x"}
        )
    with pytest.raises(ValueError):
        core_tests.browser_child_env("/tmp/home", "/tmp/tmp", extra={"OPENSSL_CONF": "x"})
    with pytest.raises(ValueError):
        core_tests.browser_child_env(
            "/tmp/home", "/tmp/tmp", extra={"WINS_RELEASE_BROWSER": "/private/tmp/chrome"}
        )


def test_spawn_refuses_freshly_calculated_authority(tmp_path: Path):
    fixture = _compile(tmp_path, "ok", "int main(void) { return 0; }\n")
    with pytest.raises(RuntimeError, match="freshly calculated"):
        core_tests.spawn_authenticated(str(fixture), [], _env(tmp_path))


def test_chrome_launch_fails_closed_without_kernel_exec_bound(tmp_path: Path):
    if core_tests.exact_execution_defended():
        pytest.skip("this owner/environment has a kernel exec-from-fd bound")
    with pytest.raises(core_tests.ExactExecutionUnavailable, match="owner/environment"):
        core_tests.launch_headless_chrome("/usr/bin/true", tmp_path)


def test_browser_session_requires_pipe_transport():
    with pytest.raises(TypeError, match="debugging pipe"):
        cdp.BrowserSession(object())  # type: ignore[arg-type]


def test_request_swap_cannot_redirect_spawn(tmp_path: Path):
    marker = tmp_path / "marker"
    original = _compile(
        tmp_path,
        "honest",
        r"""
#include <stdio.h>
#include <stdlib.h>
int main(void) {
  const char *path = getenv("MARKER_PATH");
  FILE *file = fopen(path, "w");
  if (!file) return 11;
  fputs("original-bytes\n", file);
  fclose(file);
  return 0;
}
""",
    )
    image = core_tests.authenticated_execution_image(str(original), **_pin(original))
    hostile = {
        "spawn_path": "/usr/bin/true",
        "argv": ["/usr/bin/true"],
        "env": {},
        "helper": "swapped",
    }
    planted = Path(image.root) / core_tests.REQUEST_NAME
    planted.write_text(json.dumps(hostile), encoding="utf-8")
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, core_tests.spawn_request_bytes({"ok": True, "helper": {}}))
        os.close(write_fd)
        write_fd = -1
        planted.write_text(json.dumps({"ok": False, "helper": "path-swap"}), encoding="utf-8")
        payload = core_tests.read_spawn_request_fd(read_fd)
        read_fd = -1
    finally:
        if read_fd >= 0:
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
    assert payload["ok"] is True
    assert core_tests._seatbelt_spawn_helper([str(planted)]) == 2
    try:
        child = core_tests.spawn_execution_image(
            image, [], _env(tmp_path, {"MARKER_PATH": str(marker)})
        )
        try:
            assert child.wait(timeout=5) == 0
        finally:
            child.terminate(timeout=2)
    finally:
        if not getattr(image, "_cleaned", False):
            image.cleanup()
    assert marker.read_text(encoding="utf-8") == "original-bytes\n"


def test_helper_swap_is_rejected(tmp_path: Path):
    dest = tmp_path / "helper"
    dest.mkdir(mode=0o700)
    expected = core_tests.stage_helper_modules(dest)
    core_tests.verify_staged_helper(dest, expected)
    staged = dest / "core_tests.py"
    os.chmod(staged, 0o600)
    staged.write_text("# hostile helper source\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="helper source was swapped"):
        core_tests.verify_staged_helper(dest, expected)
    fake_python = _compile(tmp_path, "python", "int main(void) { return 0; }\n")
    with pytest.raises(RuntimeError, match="identity changed"):
        core_tests._verify_file_identity(
            fake_python, expected["interpreter"], "helper interpreter"
        )
    imported = Path(cdp.__file__).resolve()
    current = core_tests._file_identity(imported)
    hostile_imported = dict(current)
    hostile_imported["digest"] = "0" * 64
    with pytest.raises(RuntimeError, match="identity changed"):
        core_tests._verify_file_identity(imported, hostile_imported, "imported cdp")


def test_byte_identical_root_inode_swap_is_rejected(tmp_path: Path):
    original = _compile(tmp_path, "honest", "int main(void) { return 0; }\n")
    image = core_tests.authenticated_execution_image(str(original), **_pin(original))
    clone = Path(str(image.root) + ".clone")
    swapped = Path(str(image.root) + ".orig")
    rc = core_tests._LIBC.clonefile(os.fsencode(str(image.root)), os.fsencode(str(clone)), 0)
    assert rc == 0
    try:
        os.rename(image.root, swapped)
        os.rename(clone, image.root)
        with pytest.raises(RuntimeError, match="inode was replaced"):
            core_tests.spawn_execution_image(image, [], _env(tmp_path))
    finally:
        if Path(image.root).exists() or Path(image.root).is_symlink():
            if swapped.exists() or swapped.is_symlink():
                os.rename(image.root, clone)
                os.rename(swapped, image.root)
        elif swapped.exists() or swapped.is_symlink():
            os.rename(swapped, image.root)
        try:
            image.cleanup()
        except RuntimeError:
            pass
        if clone.exists() or clone.is_symlink():
            shutil.rmtree(clone, ignore_errors=True)
        if swapped.exists() or swapped.is_symlink():
            shutil.rmtree(swapped, ignore_errors=True)
        if Path(image.root).exists() or Path(image.root).is_symlink():
            shutil.rmtree(image.root, ignore_errors=True)


def test_symlink_cleanup_does_not_follow(tmp_path: Path):
    victim = tmp_path / "victim"
    victim.mkdir()
    secret = victim / "secret"
    secret.write_text("keep-mode", encoding="utf-8")
    secret.chmod(0o400)
    original = _compile(tmp_path, "honest", "int main(void) { return 0; }\n")
    image = core_tests.authenticated_execution_image(str(original), **_pin(original))
    try:
        core_tests._clear_tree_for_delete(Path(image.sealed_root))
        target = Path(image.path)
        target.unlink()
        os.symlink(secret, target)
        try:
            image.cleanup()
        except RuntimeError:
            pass
        assert secret.read_text(encoding="utf-8") == "keep-mode"
        assert stat.S_IMODE(secret.stat().st_mode) == 0o400
    finally:
        if not getattr(image, "_cleaned", False):
            try:
                image.cleanup()
            except RuntimeError:
                pass
        if Path(image.root).exists() or Path(image.root).is_symlink():
            if Path(image.path).is_symlink():
                Path(image.path).unlink()
        assert secret.read_text(encoding="utf-8") == "keep-mode"
        assert stat.S_IMODE(secret.stat().st_mode) == 0o400
        target = Path(image.path)
        if target.is_symlink():
            target.unlink()
        if Path(image.root).exists():
            shutil.rmtree(image.root, ignore_errors=True)


def test_repeat_run_residue_is_failure(tmp_path: Path):
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    core_tests.create_browser_state_dirs(work)
    with pytest.raises(RuntimeError, match="residue"):
        core_tests.create_browser_state_dirs(work)
    fixture = _compile(tmp_path, "ok", "int main(void) { return 0; }\n")
    child = core_tests.spawn_authenticated(str(fixture), [], _env(tmp_path), **_pin(fixture))
    root = child.image.root
    child.wait(timeout=5)
    child.terminate(timeout=2)
    assert not root.exists()
    leftover = work / "profile"
    assert leftover.is_dir()
    with pytest.raises(RuntimeError, match="residue"):
        core_tests.create_browser_state_dirs(work)


def test_profile_symlink_is_rejected(tmp_path: Path):
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    victim = tmp_path / "victim"
    victim.mkdir()
    secret = victim / "secret"
    secret.write_text("untouched", encoding="utf-8")
    os.symlink(victim, work / "profile")
    with pytest.raises(RuntimeError, match="symbolic profile|residue"):
        core_tests.create_browser_state_dirs(work)
    assert secret.read_text(encoding="utf-8") == "untouched"
    os.symlink(victim, work / "home")
    with pytest.raises(RuntimeError, match="symbolic home|residue|symbolic profile"):
        core_tests.create_browser_state_dirs(work)


def test_pid_reuse_is_not_signalled(monkeypatch: pytest.MonkeyPatch):
    recorded = core_tests.ProcessBirth(
        pid=424242, uniqueid=1, uuid=b"\x00" * 16, puniqueid=0
    )
    reused = core_tests.ProcessBirth(
        pid=424242, uniqueid=99, uuid=b"\x11" * 16, puniqueid=0
    )
    killed: list[int] = []

    def fake_birth(pid: int) -> core_tests.ProcessBirth:
        if pid == 424242:
            return reused
        raise core_tests.ProcessTreeCleanupError(f"missing pid {pid}")

    def fake_kill(pid: int, sig: int) -> None:
        killed.append(pid)
        raise AssertionError("reused pid must not be signalled")

    monkeypatch.setattr(core_tests, "process_birth_identity", fake_birth)
    monkeypatch.setattr(os, "kill", fake_kill)
    errors = core_tests._kill_pid(424242, 9, {424242: recorded})
    assert killed == []
    assert any("reused" in item for item in errors)


def test_self_authored_runtime_receipt_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    fake_bin = _compile(tmp_path, "chrome", "int main(void) { return 0; }\n")
    digest = core_tests._sha256_path(str(fake_bin))
    runtime = tmp_path / "wins-release-browser.fake"
    root = runtime / "extracted" / core_tests.CHROME_ROOT_NAME
    app = root / core_tests.CHROME_APP_NAME
    exe = app / core_tests.CHROME_EXECUTABLE_REL
    exe.parent.mkdir(parents=True)
    exe.write_bytes(fake_bin.read_bytes())
    exe.chmod(0o500)
    monkeypatch.setenv("WINS_RELEASE_BROWSER", str(exe))
    monkeypatch.setenv("WINS_RELEASE_BROWSER_SHA256", digest)
    monkeypatch.setenv("WINS_RELEASE_BROWSER_TREE_SHA256", digest)
    monkeypatch.setenv("WINS_RELEASE_BROWSER_APP", str(app))
    monkeypatch.setenv("WINS_RELEASE_BROWSER_ROOT", str(root))
    monkeypatch.setenv("WINS_RELEASE_BROWSER_RUNTIME", str(runtime))
    monkeypatch.setenv("WINS_RELEASE_BROWSER_SIGNING_IDENTITY", "adhoc")
    monkeypatch.setenv("WINS_RELEASE_BROWSER_PRODUCT", core_tests.CHROME_PRODUCT)
    monkeypatch.setenv("WINS_RELEASE_BROWSER_VERSION", "1.0.0.0")
    with pytest.raises(RuntimeError, match="externally authenticated|trust|receipt"):
        core_tests.require_release_browser_identity()


def test_fake_pipe_transport_is_rejected():
    with pytest.raises(TypeError, match="debugging pipe"):
        cdp.PipeTransport(3, 4)

    class FakePipe(cdp.PipeTransport):
        def __init__(self) -> None:
            self._read_fd = 3
            self._write_fd = 4
            self._producer = object()

    with pytest.raises(TypeError, match="debugging pipe"):
        cdp.BrowserSession(FakePipe())  # type: ignore[arg-type]


def test_credential_bearing_extra_env_is_rejected(tmp_path: Path):
    home = str(tmp_path / "home")
    tmp = str(tmp_path / "tmp")
    for name in (
        "AWS_SECRET_ACCESS_KEY",
        "API_KEY",
        "CREDENTIAL_FILE",
        "AUTHORIZATION",
        "BEARER_TOKEN",
        "HTTP_COOKIE",
        "PRIVATE_KEY",
        "ACCESS_KEY_ID",
        "SESSION_KEY",
    ):
        with pytest.raises(ValueError, match=name):
            core_tests.browser_child_env(home, tmp, extra={name: "credential-value"})


def _browser_pin_from_manifest(manifest: Path) -> dict[str, str] | None:
    try:
        document = json.loads(manifest.read_text(encoding="utf-8"))
        browser = document["tools"]["browser"]
        pin = {
            "product": str(browser["product"]),
            "version": str(browser["version"]),
            "archive": str(browser["archive_path"]["darwin_arm64"]),
            "archive_sha": str(browser["archive_sha256"]["darwin_arm64"]),
            "tree_sha": str(browser["install_tree_sha256"]["darwin_arm64"]),
            "root": str(browser["top_level_root"]),
            "executable": str(browser["executable"]),
            "executable_sha": str(browser["executable_sha256"]),
            "signing_identity": str(browser["signing_identity"]),
        }
    except (KeyError, TypeError, OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if pin["product"] != core_tests.CHROME_PRODUCT:
        return None
    if pin["root"] != core_tests.CHROME_ROOT_NAME:
        return None
    if pin["executable"] != str(Path(core_tests.CHROME_APP_NAME) / core_tests.CHROME_EXECUTABLE_REL):
        return None
    for key in ("archive_sha", "tree_sha", "executable_sha"):
        if core_tests.HEX_RE.fullmatch(pin[key]) is None:
            return None
    return pin


def _local_chrome_archive() -> tuple[object, dict[str, str]] | None:
    sys.path.insert(0, str(REPO / "tools"))
    import release_browser_archive_custody as browser_custody

    manifest = REPO / "tools" / "toolchain-pins.json"
    try:
        pin = browser_custody.load_pin(manifest)
    except Exception:
        pin = _browser_pin_from_manifest(manifest)
        if pin is None:
            return None
    archive = Path(pin["archive"])
    if not archive.is_file():
        return None
    measured = core_tests._sha256_path(str(archive))
    if measured != pin["archive_sha"]:
        raise AssertionError(
            "local Chrome archive exists but is not the pin receipt digest"
        )
    return browser_custody, pin


def _restore_fixture_tree_permissions(path: Path) -> None:
    """Make an extracted hostile fixture removable without following symlinks."""

    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if stat.S_ISLNK(mode):
        return
    if not stat.S_ISDIR(mode):
        path.chmod(0o600)
        return
    path.chmod(0o700)
    with os.scandir(path) as entries:
        children = [path / entry.name for entry in entries]
    for child in children:
        _restore_fixture_tree_permissions(child)


def _remove_fixture_tree(path: Path) -> None:
    _restore_fixture_tree_permissions(path)
    shutil.rmtree(path, ignore_errors=False)


@pytest.fixture
def chrome_runtime_fixture(tmp_path: Path):
    runtime = tmp_path / "chrome-runtime"
    runtime.mkdir(mode=0o700)
    try:
        yield runtime
    finally:
        _remove_fixture_tree(runtime)


def test_real_chrome_bundle_codesign_tree_positive_control(
    tmp_path: Path, chrome_runtime_fixture: Path
):
    loaded = _local_chrome_archive()
    if loaded is None:
        try:
            identity = core_tests.require_release_browser_identity()
        except RuntimeError:
            pytest.skip("local authenticated Chrome bytes are absent")
        image = core_tests.authenticated_execution_image(
            str(identity.executable),
            expected_executable_sha256=identity.executable_sha256,
            expected_tree_sha256=identity.tree_sha256,
            expected_signing_identity=identity.signing_identity,
            source_root=str(identity.root),
            source_app=str(identity.app),
            archive_tree=True,
        )
        try:
            image.verify()
            assert Path(image.path).is_file()
        finally:
            image.cleanup()
        if not core_tests.exact_execution_defended():
            with pytest.raises(core_tests.ExactExecutionUnavailable, match="owner/environment"):
                core_tests.launch_headless_chrome(str(identity.executable), tmp_path)
        return

    browser_custody, pin = loaded
    runtime = chrome_runtime_fixture
    incoming = runtime / "incoming.zip"
    extracted = runtime / "extracted"
    (runtime / "state").mkdir(mode=0o700)
    (runtime / "state" / "home").mkdir(mode=0o700)
    (runtime / "state" / "tmp").mkdir(mode=0o700)
    (runtime / "exec").mkdir(mode=0o700)
    authenticated = browser_custody.copy_stable(Path(pin["archive"]), incoming, pin["archive_sha"])
    try:
        root = browser_custody.safe_extract(authenticated, extracted, pin["root"])
    finally:
        authenticated.close()
    binary = root / pin["executable"]
    app = root / "Google Chrome for Testing.app"
    assert browser_custody.tree_hash(root) == pin["tree_sha"]
    assert browser_custody.digest_file(binary) == pin["executable_sha"]
    measured_identity = browser_custody._codesign_identity(runtime, app, binary)
    assert measured_identity == pin["signing_identity"]
    image = core_tests.authenticated_execution_image(
        str(binary),
        expected_executable_sha256=pin["executable_sha"],
        expected_tree_sha256=pin["tree_sha"],
        expected_signing_identity=pin["signing_identity"],
        source_root=str(root),
        source_app=str(app),
        archive_tree=True,
    )
    try:
        image.verify()
        assert core_tests._sha256_path(image.path) == pin["executable_sha"]
        assert image.signing_identity == pin["signing_identity"]
        assert image.designated_requirement
    finally:
        image.cleanup()
    if not core_tests.exact_execution_defended():
        with pytest.raises(core_tests.ExactExecutionUnavailable, match="owner/environment"):
            core_tests.launch_headless_chrome(str(binary), tmp_path)
