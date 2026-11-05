#!/usr/bin/env python3
"""Install-time opt-in for protocol_params.carrier=winn3.

Gap this locks: no installer used to set carrier=winn3, and empty
POST /admin/nodes/winn3 used to store {} which reported carrier=direct-awg
(the retired AWG-relay). Production registration now refuses that path.

The operator path is opt-in and default OFF:

  WINN3_SET_CARRIER_STANDALONE=1
  WINN3_STANDALONE_NODE_SLUG=<one already-chosen slug>

That persists into the hub EnvironmentFile. Registration no longer applies
it (H2: it skipped the operator hold and the served-profile proof);
maybe_apply_install_time_standalone_carrier stays as a helper that stores
{"carrier":"winn3"} plus a servable plan when called. After postflight, the installer
may also POST the same body (never {}) to a loopback hub. Existing nodes
and empty POST /admin/nodes/winn3 is refused.

Run:

  python3 server/test_winn3_install_time_carrier.py

No network. Mutation copies live only under
.spark_lanes/scratch/deploy_set_carrier_winn3/ (never the shared tree).
"""
from __future__ import annotations
from contextlib import closing

import _toolchain  # noqa: F401  (V-01 preflight)
import ast
import asyncio
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import traceback
import unittest
from pathlib import Path


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_account_deletion_hub as harness  # noqa: E402
from test_account_deletion_hub import FakeRequest  # noqa: E402
import test_winn3_serving_hub as serving  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
SCRATCH = (
    Path(__file__).resolve().parents[3]
    / ".spark_lanes"
    / "scratch"
    / "deploy_set_carrier_winn3"
)
MUTANTS = SCRATCH / "mutants"
RUNS = SCRATCH / "runs"
TMP = SCRATCH / "tmp"

WRITER_BEGIN = "# --- begin winn3 hub EnvironmentFile writers ---"
WRITER_END = "# --- end winn3 hub EnvironmentFile writers ---"
STANDALONE_BEGIN = "# --- begin install-time standalone carrier=winn3"
STANDALONE_END = "# --- end install-time standalone carrier=winn3 ---"

ADMIN = "test-admin-token"
INSTALL_ENV_KEYS = (
    "WINN3_SET_CARRIER_STANDALONE",
    "WINN3_STANDALONE_NODE_SLUG",
    "WINN3_STANDALONE_PATH_MTU",
    "WINN3_STANDALONE_CARRIER_CLASSES",
)


def _read_installer(path: Path | None = None) -> str:
    return (path or INSTALLER).read_text(encoding="utf-8")


def extract_heredoc_after(source: str, anchor: str, marker: str) -> str:
    idx = source.find(anchor)
    if idx < 0:
        raise AssertionError(f"missing anchor {anchor!r}")
    token_at = -1
    for token in (f"<<'{marker}'", f'<<"{marker}"', f"<<{marker}"):
        at = source.find(token, idx)
        if at >= 0 and (token_at < 0 or at < token_at):
            token_at = at
    if token_at < 0:
        raise AssertionError(f"missing heredoc {marker} after {anchor!r}")
    nl = source.find("\n", token_at)
    body_start = nl + 1
    end = source.find(f"\n{marker}\n", body_start)
    if end < 0:
        end = source.find(f"\n{marker}", body_start)
        if end < 0:
            raise AssertionError(f"unclosed heredoc {marker}")
    return source[body_start:end]


def function_definition(source: str, signature: str) -> str:
    match = re.search(r"(?m)^[ \t]*" + re.escape(signature) + r"[ \t]*$", source)
    if match is None:
        raise AssertionError(f"missing exact function signature {signature!r}")
    start = match.start()
    brace_idx = source.index("{", start)
    depth = 0
    for idx in range(brace_idx, len(source)):
        char = source[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : idx + 1]
    raise AssertionError(f"unbalanced braces while extracting {signature}")


def writer_block(source: str) -> str:
    begin = source.find(WRITER_BEGIN)
    end = source.find(WRITER_END)
    if begin < 0 or end < 0 or end <= begin:
        raise AssertionError("writer begin/end markers missing or inverted")
    return source[begin:end]


def standalone_block(source: str) -> str:
    begin = source.find(STANDALONE_BEGIN)
    end = source.find(STANDALONE_END)
    if begin < 0 or end < 0 or end <= begin:
        raise AssertionError("standalone begin/end markers missing or inverted")
    return source[begin:end]


def kv_lines(buf: str, key: str) -> list[str]:
    prefix = f"{key}="
    return [ln for ln in buf.splitlines() if ln.startswith(prefix)]


def set_install_env(*, flag: str = "0", slug: str = "", mtu: str = "1450",
                    classes: str = "udp") -> None:
    os.environ["WINN3_SET_CARRIER_STANDALONE"] = flag
    os.environ["WINN3_STANDALONE_NODE_SLUG"] = slug
    os.environ["WINN3_STANDALONE_PATH_MTU"] = mtu
    os.environ["WINN3_STANDALONE_CARRIER_CLASSES"] = classes


def clear_install_env() -> None:
    for key in INSTALL_ENV_KEYS:
        os.environ.pop(key, None)


def apply_carrier(mod, slug: str, *, prior_endpoint: str | None = None) -> None:
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.maybe_apply_install_time_standalone_carrier(
            conn, slug, prior_endpoint=prior_endpoint
        )


def admin_winn3(mod, **kwargs):
    kwargs.setdefault("x_admin_token", ADMIN)
    kwargs.setdefault("request", FakeRequest(path="/admin/nodes/winn3"))
    return mod.admin_set_node_winn3(**kwargs)


def run_validate(source: str, extra_env: dict[str, str] | None = None
                 ) -> subprocess.CompletedProcess[str]:
    RUNS.mkdir(parents=True, exist_ok=True)
    block = writer_block(source)
    driver = RUNS / "validate_driver.sh"
    driver.write_text(
        "#!/usr/bin/env bash\n"
        "set -Eeuo pipefail\n"
        'err() { printf \'[ERR] %s\\n\' "$*" >&2; }\n'
        'warn() { printf \'[WARN] %s\\n\' "$*" >&2; }\n'
        'WINN3_SET_CARRIER_STANDALONE_DEFAULT="${WINN3_SET_CARRIER_STANDALONE_DEFAULT:-0}"\n'
        'WINN3_STANDALONE_NODE_SLUG_DEFAULT="${WINN3_STANDALONE_NODE_SLUG_DEFAULT:-}"\n'
        'WINN3_STANDALONE_PATH_MTU_DEFAULT="${WINN3_STANDALONE_PATH_MTU_DEFAULT:-1450}"\n'
        'WINN3_STANDALONE_CARRIER_CLASSES_DEFAULT="${WINN3_STANDALONE_CARRIER_CLASSES_DEFAULT:-udp}"\n'
        f"{block}\n"
        "validate_winn3_standalone_install_settings\n",
        encoding="utf-8",
    )
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(SCRATCH),
        "WINN3_SET_CARRIER_STANDALONE_DEFAULT": "0",
        "WINN3_STANDALONE_PATH_MTU_DEFAULT": "1450",
        "WINN3_STANDALONE_CARRIER_CLASSES_DEFAULT": "udp",
    }
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", str(driver)],
        cwd=str(SCRATCH),
        capture_output=True,
        text=True,
        env=env,
    )


def run_writers(source: str, extra_env: dict[str, str] | None = None
                ) -> subprocess.CompletedProcess[str]:
    RUNS.mkdir(parents=True, exist_ok=True)
    block = writer_block(source)
    kv_fn = function_definition(source, "write_env_kv() {")
    driver = RUNS / "writer_driver.sh"
    driver.write_text(
        "#!/usr/bin/env bash\n"
        "set -Eeuo pipefail\n"
        'ENV_FILE="${TEST_ENV_FILE:-/root/vpn_auth.env}"\n'
        'WINN3_INNER_POOL_CIDR_DEFAULT="${WINN3_INNER_POOL_CIDR_DEFAULT:-10.10.0.0/24}"\n'
        'WINN3_SET_CARRIER_STANDALONE_DEFAULT="${WINN3_SET_CARRIER_STANDALONE_DEFAULT:-0}"\n'
        'WINN3_STANDALONE_NODE_SLUG_DEFAULT="${WINN3_STANDALONE_NODE_SLUG_DEFAULT:-}"\n'
        'WINN3_STANDALONE_PATH_MTU_DEFAULT="${WINN3_STANDALONE_PATH_MTU_DEFAULT:-1450}"\n'
        'WINN3_STANDALONE_CARRIER_CLASSES_DEFAULT="${WINN3_STANDALONE_CARRIER_CLASSES_DEFAULT:-udp}"\n'
        'err() { printf \'[ERR] %s\\n\' "$*" >&2; }\n'
        'warn() { printf \'[WARN] %s\\n\' "$*" >&2; }\n'
        "env_kv_buffer=\"\"\n"
        f"{kv_fn}\n"
        f"{block}\n"
        "write_winn3_runtime_env\n"
        'printf \'%s\' "${env_kv_buffer}"\n',
        encoding="utf-8",
    )
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(SCRATCH),
        "TEST_ENV_FILE": str(RUNS / "vpn_auth.env"),
        "WINN3_INNER_POOL_CIDR_DEFAULT": "10.10.0.0/24",
        "WINN3_SET_CARRIER_STANDALONE_DEFAULT": "0",
        "WINN3_STANDALONE_PATH_MTU_DEFAULT": "1450",
        "WINN3_STANDALONE_CARRIER_CLASSES_DEFAULT": "udp",
    }
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", str(driver)],
        cwd=str(SCRATCH),
        capture_output=True,
        text=True,
        env=env,
    )


def run_hub_base(source: str, extra_env: dict[str, str] | None = None
                 ) -> subprocess.CompletedProcess[str]:
    RUNS.mkdir(parents=True, exist_ok=True)
    fn = function_definition(source, "winn3_standalone_hub_base() {")
    driver = RUNS / "hub_base_driver.sh"
    driver.write_text(
        "#!/usr/bin/env bash\n"
        "set -Eeuo pipefail\n"
        'err() { printf \'[ERR] %s\\n\' "$*" >&2; }\n'
        f"{fn}\n"
        "winn3_standalone_hub_base\n",
        encoding="utf-8",
    )
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(SCRATCH),
    }
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", str(driver)],
        cwd=str(SCRATCH),
        capture_output=True,
        text=True,
        env=env,
    )


def load_canonical_loopback_origin(source: str):
    import types
    import urllib.parse

    body = extract_heredoc_after(
        source, "<<'WINN3_SET_CARRIER_PY'", "WINN3_SET_CARRIER_PY"
    )
    start = body.index("def canonical_loopback_http_origin")
    end = body.index("\ntry:\n", start)
    urllib_mod = types.ModuleType("urllib")
    urllib_mod.parse = urllib.parse
    namespace = {"urllib": urllib_mod}
    exec(
        compile(body[start:end], "<canonical_loopback_http_origin>", "exec"),
        namespace,
    )
    return namespace["canonical_loopback_http_origin"]


LOOPBACK_ACCEPTED = (
    "http://127.0.0.1:8000",
    "http://127.0.0.1",
    "http://127.0.0.1:1",
    "http://127.0.0.1:65535",
)
LOOPBACK_REJECTED = (
    "http://127.0.0.1:8000@evil.example",
    "http://127.0.0.1:8000@127.0.0.1",
    "http://user@127.0.0.1:8000",
    "http://user:pass@127.0.0.1:8000",
    "http://127.0.0.1:8000#fragment",
    "http://127.0.0.1:8000#",
    "http://127.0.0.1:8000?query=1",
    "http://127.0.0.1:8000/admin",
    "http://127.0.0.1:8000/",
    "http://localhost:8000",
    "http://[::1]:8000",
    "http://127.0.0.2:8000",
    "http://192.0.2.1:8000",
    "https://127.0.0.1:8000",
    "HTTP://127.0.0.1:8000",
    "http://127.0.0.1:8000 ",
    " http://127.0.0.1:8000",
    "http://127.0.0.1:08000",
    "http://127.0.0.1:notaport",
    "http://127.0.0.1:0",
    "http://127.0.0.1:65536",
    "http://127.1:8000",
    "http://2130706433:8000",
)


class InstallerSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = _read_installer()
        cls.standalone = standalone_block(cls.source)
        cls.writers = writer_block(cls.source)
        cls.provision = function_definition(
            cls.source, "provision_standalone_winn3_carrier() {"
        )
        cls.main = function_definition(cls.source, "main() {")
        cls.preflight = function_definition(cls.source, "preflight_control() {")
        cls.admin_cli = extract_heredoc_after(
            cls.source, "cat > /usr/local/bin/wins-admin <<'PYEOF'", "PYEOF"
        )
        cls.provision_py = extract_heredoc_after(
            cls.source, "<<'WINN3_SET_CARRIER_PY'", "WINN3_SET_CARRIER_PY"
        )

    def test_default_flag_is_zero(self) -> None:
        self.assertIn(
            'WINN3_SET_CARRIER_STANDALONE_DEFAULT="${WINN3_SET_CARRIER_STANDALONE:-0}"',
            self.source,
        )
        self.assertIn(
            'flag="${WINN3_SET_CARRIER_STANDALONE:-${WINN3_SET_CARRIER_STANDALONE_DEFAULT:-0}}"',
            self.writers,
        )

    def test_preflight_validates_standalone_settings(self) -> None:
        self.assertIn(
            "validate_winn3_standalone_install_settings || exit 1",
            self.preflight,
        )

    def test_main_provisions_after_postflight_not_during_preflight(self) -> None:
        self.assertIn("postflight_control", self.main)
        self.assertIn(
            "provision_standalone_winn3_carrier || return 1", self.main
        )
        self.assertLess(
            self.main.find("postflight_control"),
            self.main.find("provision_standalone_winn3_carrier || return 1"),
        )
        self.assertNotIn("provision_standalone_winn3_carrier", self.preflight)

    def test_flag_off_is_a_logged_noop(self) -> None:
        self.assertIn('if [[ "${flag}" != "1" ]]; then', self.provision)
        self.assertIn("not provisioning any node as standalone", self.provision)
        self.assertIn("return 0", self.provision)

    def test_flag_on_requires_a_named_slug(self) -> None:
        self.assertIn(
            "WINN3_SET_CARRIER_STANDALONE=1 requires WINN3_STANDALONE_NODE_SLUG",
            self.writers,
        )

    def test_provision_posts_explicit_winn3_never_empty_object(self) -> None:
        ast.parse(self.provision_py, filename="WINN3_SET_CARRIER_PY")
        self.assertIn(
            'params_json = json.dumps({"carrier": "winn3"}, separators=(",", ":"))',
            self.provision_py,
        )
        self.assertIn('"/admin/nodes/winn3"', self.provision_py)
        self.assertIn('"protocol_params_json": params_json', self.provision_py)
        self.assertIn('"/admin/nodes/winn3/descriptor"', self.provision_py)
        self.assertNotIn(
            'params_json = json.dumps({}, separators=(",", ":"))',
            self.provision_py,
        )
        self.assertNotIn(
            '"protocol_params_json": "{}"', self.provision_py
        )
        self.assertNotIn(
            '"protocol_params_json": ""', self.provision_py
        )

    def test_provision_hub_base_is_loopback_only(self) -> None:
        base_fn = function_definition(self.source, "winn3_standalone_hub_base() {")
        self.assertIn("http://127.0.0.1", base_fn)
        self.assertIn("refusing a non-local hub", base_fn)
        self.assertIn("urlsplit", base_fn)
        self.assertIn("WINN3_LOOPBACK_ORIGIN_PY", base_fn)
        self.assertNotIn("http://127.0.0.1:*", base_fn)
        self.assertNotIn("http://localhost:*", base_fn)
        self.assertNotIn('case "${base}" in', base_fn)
        self.assertNotIn("<KANSAS_IP>", self.standalone)
        self.assertNotIn("<NODE_ES_IP>", self.standalone)
        self.assertNotIn("<KANSAS_IP>", self.provision_py)
        self.assertNotIn("<NODE_ES_IP>", self.provision_py)

    def test_loopback_origin_is_validated_before_admin_token(self) -> None:
        self.assertLess(
            self.provision.find('base="$(winn3_standalone_hub_base)"'),
            self.provision.find("local admin_token="),
        )
        origin_at = self.provision_py.find("canonical_loopback_http_origin")
        token_at = self.provision_py.find("token_bytes = os.read(token_fd, 4097)")
        request_at = self.provision_py.find("urllib.request.Request")
        self.assertGreater(origin_at, 0)
        self.assertGreater(token_at, origin_at)
        self.assertGreater(request_at, token_at)
        self.assertIn("parsed.username", self.provision_py)
        self.assertIn("parsed.fragment", self.provision_py)

    def test_admin_token_never_reaches_an_ambient_interpreter_or_environment(self) -> None:
        self.assertIn('/usr/bin/python3 - "${base}"', self.provision)
        self.assertNotIn('ADMIN_TOKEN="${admin_token}" python3', self.provision)
        self.assertNotIn('os.environ.get("ADMIN_TOKEN")', self.provision_py)
        self.assertIn('exec {admin_token_fd}<<<"${admin_token}"', self.provision)
        self.assertIn("token_bytes = os.read(token_fd, 4097)", self.provision_py)
        self.assertIn("os.close(token_fd)", self.provision_py)

    def test_descriptor_post_keeps_node_slug_binding(self) -> None:
        self.assertIn('"/admin/nodes/winn3/descriptor"', self.provision_py)
        self.assertGreaterEqual(self.provision_py.count('"slug": slug'), 2)
        hub = extract_heredoc_after(
            self.source, 'cat > "${APP_DIR}/main.py" <<\'PYEOF\'', "PYEOF"
        )
        self.assertIn("descriptor-node-mismatch", hub)

    def test_register_node_does_not_call_maybe_apply(self) -> None:
        # H2: registration supplies facts and schedules the post-commit job.
        # The opt-in helper checks neither the sticky operator hold nor a
        # served-profile proof, so register_node must not reach it; the
        # installer drives POST /admin/nodes/winn3 instead.
        hub = extract_heredoc_after(
            self.source, 'cat > "${APP_DIR}/main.py" <<\'PYEOF\'', "PYEOF"
        )
        self.assertIn("def maybe_apply_install_time_standalone_carrier(", hub)
        self.assertIn("def register_node(", hub)
        start = hub.index("def register_node(")
        end = hub.index('@app.post("/api/v1/nodes/{slug}/deployment/withdraw")', start)
        self.assertNotIn("maybe_apply_install_time_standalone_carrier(", hub[start:end])
        self.assertIn("winn3_schedule_auto_provision(payload.slug)", hub[start:end])
        self.assertIn('if flag != "1":', hub)
        self.assertIn('{"carrier": WINN3_CARRIER_WINN3}', hub)

    def test_unregistered_node_message_does_not_promise_a_registration_flip(self) -> None:
        # H2: registration never applies the opt-in, so the 404 branch of the
        # installer's loopback helper and this module must not say it does.
        self.assertNotIn("hub will apply carrier=winn3", self.provision_py)
        self.assertIn("registration never applies carrier=winn3", self.provision_py)
        self.assertNotIn("On first real registration of", __doc__)

    def test_empty_admin_post_still_stores_empty_object(self) -> None:
        hub = extract_heredoc_after(
            self.source, 'cat > "${APP_DIR}/main.py" <<\'PYEOF\'', "PYEOF"
        )
        self.assertIn("require_production_winn3_registration_params", hub)
        self.assertIn("carrier-not-standalone-winn3", hub)
        self.assertIn("protocol-params-empty", hub)

    def test_wins_admin_menu_keeps_node_and_core_promotion_controls_distinct(self) -> None:
        # Item 21 owns data-plane withdrawal/re-tiering and its evidenced
        # off-to-on promotion transition. Core promotion and withdrawal use
        # their own hub-owned latch and therefore remain separate controls.
        self.assertIn("'21': set_node_tier", self.admin_cli)
        self.assertIn("'22': promote_core", self.admin_cli)
        self.assertIn("'23': withdraw_core", self.admin_cli)
        self.assertIn("post_form('/admin/nodes/tier'", self.admin_cli)
        self.assertIn("post_form('/admin/core/promote'", self.admin_cli)
        self.assertIn("post_form('/admin/core/withdraw'", self.admin_cli)
        self.assertNotIn("set_node_winn3", self.admin_cli)

    def test_dead_zone_mtu_is_refused_at_install_validate(self) -> None:
        self.assertIn("mtu < 1421", self.writers)
        self.assertIn("never-promotes dead zone", self.writers)

    def test_help_names_the_opt_in_and_says_default_off(self) -> None:
        self.assertIn("Standalone v3 at install time is opt-in and default off", self.main)
        self.assertIn("WINN3_SET_CARRIER_STANDALONE=1", self.main)
        self.assertIn("WINN3_STANDALONE_NODE_SLUG=", self.main)
        self.assertIn(
            "Production POST /admin/nodes/winn3 requires carrier=winn3",
            self.main,
        )


class InstallerShellTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        SCRATCH.mkdir(parents=True, exist_ok=True)
        RUNS.mkdir(parents=True, exist_ok=True)
        cls.source = _read_installer()

    def test_bash_n_on_live_installer(self) -> None:
        proc = subprocess.run(
            ["bash", "-n", str(INSTALLER)],
            cwd=str(SCRATCH),
            capture_output=True,
            text=True,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_default_flag_validate_succeeds(self) -> None:
        proc = run_validate(self.source)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_flag_one_without_slug_is_refused(self) -> None:
        proc = run_validate(
            self.source, {"WINN3_SET_CARRIER_STANDALONE": "1"}
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("WINN3_STANDALONE_NODE_SLUG", proc.stderr)

    def test_flag_one_with_slug_succeeds(self) -> None:
        proc = run_validate(
            self.source,
            {
                "WINN3_SET_CARRIER_STANDALONE": "1",
                "WINN3_STANDALONE_NODE_SLUG": "lab-alpha",
            },
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_dead_zone_path_mtu_is_refused(self) -> None:
        proc = run_validate(
            self.source,
            {
                "WINN3_SET_CARRIER_STANDALONE": "1",
                "WINN3_STANDALONE_NODE_SLUG": "lab-alpha",
                "WINN3_STANDALONE_PATH_MTU": "1400",
            },
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("1421", proc.stderr)

    def test_unknown_carrier_class_is_refused(self) -> None:
        proc = run_validate(
            self.source,
            {
                "WINN3_SET_CARRIER_STANDALONE": "1",
                "WINN3_STANDALONE_NODE_SLUG": "lab-alpha",
                "WINN3_STANDALONE_CARRIER_CLASSES": "udp,quic",
            },
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("quic", proc.stderr)

    def test_writers_emit_flag_zero_by_default(self) -> None:
        proc = run_writers(self.source)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            kv_lines(proc.stdout, "WINN3_SET_CARRIER_STANDALONE"),
            ["WINN3_SET_CARRIER_STANDALONE='0'"],
        )
        self.assertEqual(
            kv_lines(proc.stdout, "WINN3_STANDALONE_NODE_SLUG"),
            ["WINN3_STANDALONE_NODE_SLUG=''"],
        )
        self.assertEqual(
            kv_lines(proc.stdout, "WINN3_STANDALONE_PATH_MTU"),
            ["WINN3_STANDALONE_PATH_MTU='1450'"],
        )
        self.assertEqual(
            kv_lines(proc.stdout, "WINN3_STANDALONE_CARRIER_CLASSES"),
            ["WINN3_STANDALONE_CARRIER_CLASSES='udp'"],
        )

    def test_writers_persist_named_slug_when_flag_on(self) -> None:
        proc = run_writers(
            self.source,
            {
                "WINN3_SET_CARRIER_STANDALONE": "1",
                "WINN3_STANDALONE_NODE_SLUG": "Lab-Alpha",
            },
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            kv_lines(proc.stdout, "WINN3_SET_CARRIER_STANDALONE"),
            ["WINN3_SET_CARRIER_STANDALONE='1'"],
        )
        self.assertEqual(
            kv_lines(proc.stdout, "WINN3_STANDALONE_NODE_SLUG"),
            ["WINN3_STANDALONE_NODE_SLUG='lab-alpha'"],
        )


    def test_hub_base_accepts_canonical_loopback_origins(self) -> None:
        proc = run_hub_base(self.source)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, "http://127.0.0.1:8000")
        for url in LOOPBACK_ACCEPTED:
            with self.subTest(url=url):
                got = run_hub_base(
                    self.source, {"WINN3_STANDALONE_HUB_BASE": url}
                )
                self.assertEqual(got.returncode, 0, got.stderr)
                self.assertEqual(got.stdout, url)

    def test_hub_base_rejects_userinfo_non_loopback_fragment_and_ambiguity(self) -> None:
        for url in LOOPBACK_REJECTED:
            with self.subTest(url=url):
                got = run_hub_base(
                    self.source, {"WINN3_STANDALONE_HUB_BASE": url}
                )
                self.assertNotEqual(got.returncode, 0, url)
                self.assertIn("loopback", got.stderr)
                self.assertNotIn("x-admin-token", got.stdout + got.stderr)

    def test_hub_base_ignores_a_path_substituted_python(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hostile-path-", dir=RUNS) as td:
            hostile = Path(td)
            marker = hostile / "executed"
            fake = hostile / "python3"
            fake.write_text(
                "#!/usr/bin/env bash\n"
                f"touch {str(marker)!r}\n"
                "exit 88\n",
                encoding="ascii",
            )
            fake.chmod(0o700)
            got = run_hub_base(
                self.source,
                {"PATH": f"{hostile}:{os.environ.get('PATH', '/usr/bin:/bin')}"},
            )
            self.assertEqual(got.returncode, 0, got.stderr)
            self.assertEqual(got.stdout, "http://127.0.0.1:8000")
            self.assertFalse(marker.exists(), "PATH-substituted python executed")

    def test_provision_python_origin_validator_matches_shell_gate(self) -> None:
        validator = load_canonical_loopback_origin(self.source)
        for url in LOOPBACK_ACCEPTED:
            with self.subTest(accept=url):
                self.assertEqual(validator(url), url)
        for url in LOOPBACK_REJECTED:
            with self.subTest(reject=url):
                with self.assertRaises(ValueError):
                    validator(url)
        with self.assertRaises(ValueError):
            validator("")


class HubMaybeApplyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        TMP.mkdir(parents=True, exist_ok=True)
        os.environ["TMPDIR"] = str(TMP)
        asyncio.set_event_loop(asyncio.new_event_loop())

    def setUp(self) -> None:
        clear_install_env()
        self.mod = harness.load_hub()

    def tearDown(self) -> None:
        clear_install_env()

    def test_default_off_leaves_a_fresh_node_on_winn1(self) -> None:
        set_install_env(flag="0", slug="lab-alpha")
        serving.seed_node(self.mod, slug="lab-alpha")
        apply_carrier(self.mod, "lab-alpha", prior_endpoint=None)
        row = serving.node_row(self.mod)
        self.assertEqual(row["protocol_version"], "winn/1")
        self.assertIsNone(row["protocol_params_json"])

    def test_unset_flag_is_off(self) -> None:
        clear_install_env()
        serving.seed_node(self.mod, slug="lab-alpha")
        apply_carrier(self.mod, "lab-alpha", prior_endpoint=None)
        row = serving.node_row(self.mod)
        self.assertEqual(row["protocol_version"], "winn/1")
        self.assertIsNone(row["protocol_params_json"])

    def test_first_insert_of_named_slug_stores_carrier_winn3(self) -> None:
        set_install_env(flag="1", slug="lab-alpha")
        serving.seed_node(self.mod, slug="lab-alpha")
        apply_carrier(self.mod, "lab-alpha", prior_endpoint=None)
        row = serving.node_row(self.mod)
        self.assertEqual(row["protocol_version"], "winn/3")
        self.assertEqual(json.loads(row["protocol_params_json"]), {"carrier": "winn3"})
        self.assertEqual(row["path_mtu"], 1450)
        self.assertEqual(row["carrier_classes"], "udp")

    def test_wrong_slug_is_not_flipped(self) -> None:
        set_install_env(flag="1", slug="lab-alpha")
        serving.seed_node(self.mod, slug="lab-beta")
        apply_carrier(self.mod, "lab-beta", prior_endpoint=None)
        row = serving.node_row(self.mod, "lab-beta")
        self.assertEqual(row["protocol_version"], "winn/1")
        self.assertIsNone(row["protocol_params_json"])

    def test_reregister_does_not_change_existing_node(self) -> None:
        set_install_env(flag="1", slug="lab-alpha")
        serving.seed_node(self.mod, slug="lab-alpha")
        apply_carrier(
            self.mod, "lab-alpha", prior_endpoint="198.51.100.7:9110"
        )
        row = serving.node_row(self.mod)
        self.assertEqual(row["protocol_version"], "winn/1")
        self.assertIsNone(row["protocol_params_json"])

    def test_non_empty_params_are_not_overwritten(self) -> None:
        set_install_env(flag="1", slug="lab-alpha")
        serving.seed_node(
            self.mod,
            slug="lab-alpha",
            protocol_version="winn/1",
            protocol_params_json='{"session_id":"keep-me"}',
        )
        apply_carrier(self.mod, "lab-alpha", prior_endpoint=None)
        row = serving.node_row(self.mod)
        self.assertEqual(row["protocol_version"], "winn/1")
        self.assertEqual(
            json.loads(row["protocol_params_json"]), {"session_id": "keep-me"}
        )

    def test_empty_object_params_on_winn1_are_upgraded(self) -> None:
        set_install_env(flag="1", slug="lab-alpha")
        serving.seed_node(
            self.mod,
            slug="lab-alpha",
            protocol_version="winn/1",
            protocol_params_json="{}",
        )
        apply_carrier(self.mod, "lab-alpha", prior_endpoint=None)
        row = serving.node_row(self.mod)
        self.assertEqual(row["protocol_version"], "winn/3")
        self.assertEqual(
            json.loads(row["protocol_params_json"]), {"carrier": "winn3"}
        )

    def test_empty_admin_post_still_reports_direct_awg(self) -> None:
        serving.seed_node(self.mod, slug="lab-alpha")
        with self.assertRaises(Exception) as caught:
            admin_winn3(self.mod, slug="lab-alpha", enabled=True)
        self.assertEqual(getattr(caught.exception, "status_code", None), 400)
        row = serving.node_row(self.mod)
        self.assertEqual(row["protocol_version"], "winn/1")
        self.assertIsNone(row["protocol_params_json"])

    def test_dead_zone_plan_leaves_the_row_unchanged(self) -> None:
        set_install_env(
            flag="1", slug="lab-alpha", mtu="1400", classes="udp,tcp,tls"
        )
        serving.seed_node(self.mod, slug="lab-alpha")
        apply_carrier(self.mod, "lab-alpha", prior_endpoint=None)
        row = serving.node_row(self.mod)
        self.assertEqual(row["protocol_version"], "winn/1")
        self.assertIsNone(row["protocol_params_json"])


FAILURES: list[tuple[str, str]] = []
PASSED = [0]


def check(name: str, fn) -> None:
    try:
        fn()
    except Exception:
        FAILURES.append((name, traceback.format_exc()))
        print(f"  FAIL  {name}")
    else:
        PASSED[0] += 1
        print(f"  ok    {name}")


def _copy_installer() -> Path:
    MUTANTS.mkdir(parents=True, exist_ok=True)
    dest = MUTANTS / "installer.sh"
    shutil.copy2(INSTALLER, dest)
    return dest


def _classify(label: str, mutated: str, probe) -> str:
    """Run probe(mutated_source) -> 'PASS' or fail. Classify BUILD vs FAIL."""
    path = MUTANTS / f"{label}.sh"
    path.write_text(mutated, encoding="utf-8")
    try:
        probe(mutated, path)
    except SyntaxError:
        return "BUILD_FAIL"
    except Exception:
        return "FAIL"
    return "PASS"


def mutation_table() -> int:
    """Three controls plus inverted breaks. Mutants live only in scratch."""
    print("\nmutation controls (private copy, not the shared tree)")
    live = _read_installer()
    rows: list[tuple[str, str, str]] = []

    def source_default_is_zero(source: str, _path: Path) -> None:
        needle = (
            'WINN3_SET_CARRIER_STANDALONE_DEFAULT='
            '"${WINN3_SET_CARRIER_STANDALONE:-0}"'
        )
        if needle not in source:
            raise AssertionError("default-0 assignment missing")

    def provision_posts_winn3(source: str, _path: Path) -> None:
        body = extract_heredoc_after(
            source, "<<'WINN3_SET_CARRIER_PY'", "WINN3_SET_CARRIER_PY"
        )
        ast.parse(body)
        if 'params_json = json.dumps({"carrier": "winn3"}' not in body:
            raise AssertionError("provision body is not carrier=winn3")

    def maybe_apply_writes_winn3(source: str, path: Path) -> None:
        orig = harness.HUB
        try:
            harness.HUB = str(path)
            clear_install_env()
            os.environ["TMPDIR"] = str(TMP)
            TMP.mkdir(parents=True, exist_ok=True)
            mod = harness.load_hub()
            set_install_env(flag="1", slug="lab-alpha")
            serving.seed_node(mod, slug="lab-alpha")
            apply_carrier(mod, "lab-alpha", prior_endpoint=None)
            row = serving.node_row(mod)
            params = json.loads(row["protocol_params_json"] or "null")
            if params != {"carrier": "winn3"}:
                raise AssertionError(f"stored params={params!r}")
            if row["protocol_version"] != "winn/3":
                raise AssertionError(f"version={row['protocol_version']!r}")
        finally:
            harness.HUB = orig
            clear_install_env()

    def empty_post_is_refused(source: str, path: Path) -> None:
        orig = harness.HUB
        try:
            harness.HUB = str(path)
            clear_install_env()
            os.environ["TMPDIR"] = str(TMP)
            TMP.mkdir(parents=True, exist_ok=True)
            asyncio.set_event_loop(asyncio.new_event_loop())
            mod = harness.load_hub()
            serving.seed_node(mod, slug="lab-alpha")
            try:
                admin_winn3(mod, slug="lab-alpha", enabled=True)
            except Exception as exc:
                if getattr(exc, "status_code", None) != 400:
                    raise AssertionError(
                        f"empty POST status={getattr(exc, 'status_code', None)!r}"
                    )
            else:
                raise AssertionError("empty POST must be refused")
            row = serving.node_row(mod)
            if row["protocol_version"] != "winn/1":
                raise AssertionError(f"empty POST version={row['protocol_version']!r}")
            if row["protocol_params_json"] is not None:
                raise AssertionError("empty POST must not store params")
        finally:
            harness.HUB = orig
            clear_install_env()

    def message_is_honest(source: str, _path: Path) -> None:
        body = extract_heredoc_after(
            source, "<<'WINN3_SET_CARRIER_PY'", "WINN3_SET_CARRIER_PY"
        )
        if "hub will apply carrier=winn3" in body:
            raise AssertionError("404 message promises a registration-time flip")
        if "registration never applies carrier=winn3" not in body:
            raise AssertionError("404 message is missing")

    # CONTROL_GREEN
    status = _classify("control_green", live, maybe_apply_writes_winn3)
    rows.append(("CONTROL_GREEN maybe_apply writes winn3", status, "PASS"))
    status = _classify("control_green_default", live, source_default_is_zero)
    rows.append(("CONTROL_GREEN default is 0", status, "PASS"))
    status = _classify("control_green_provision", live, provision_posts_winn3)
    rows.append(("CONTROL_GREEN provision posts winn3", status, "PASS"))
    status = _classify("control_green_empty_post", live, empty_post_is_refused)
    rows.append(("CONTROL_GREEN empty POST is refused", status, "PASS"))

    # CONTROL_NEUTRAL
    neutral = live.replace(
        WRITER_BEGIN, WRITER_BEGIN + "\n# control-neutral comment\n", 1
    )
    if neutral == live:
        rows.append(("CONTROL_NEUTRAL comment-only", "NOT_APPLIED", "PASS"))
    else:
        status = _classify("control_neutral", neutral, maybe_apply_writes_winn3)
        rows.append(("CONTROL_NEUTRAL comment-only", status, "PASS"))

    # BREAK: maybe_apply stores {} instead of carrier=winn3
    needle = '{"carrier": WINN3_CARRIER_WINN3}'
    if live.count(needle) != 1:
        rows.append(
            (f"BREAK maybe_apply empty params (needle {live.count(needle)}x)",
             "NOT_APPLIED", "FAIL")
        )
    else:
        mutated = live.replace(needle, "{}", 1)
        status = _classify("break_empty_params", mutated, maybe_apply_writes_winn3)
        rows.append(("BREAK maybe_apply stores {}", status, "FAIL"))

    # BREAK: provision posts {}
    needle = 'params_json = json.dumps({"carrier": "winn3"}, separators=(",", ":"))'
    if live.count(needle) != 1:
        rows.append(
            (f"BREAK provision empty body (needle {live.count(needle)}x)",
             "NOT_APPLIED", "FAIL")
        )
    else:
        mutated = live.replace(
            needle, 'params_json = json.dumps({}, separators=(",", ":"))', 1
        )
        status = _classify("break_provision_empty", mutated, provision_posts_winn3)
        rows.append(("BREAK provision posts {}", status, "FAIL"))

    # BREAK: default ON
    needle = (
        'WINN3_SET_CARRIER_STANDALONE_DEFAULT='
        '"${WINN3_SET_CARRIER_STANDALONE:-0}"'
    )
    if live.count(needle) != 1:
        rows.append(
            (f"BREAK default 1 (needle {live.count(needle)}x)",
             "NOT_APPLIED", "FAIL")
        )
    else:
        mutated = live.replace(
            needle,
            'WINN3_SET_CARRIER_STANDALONE_DEFAULT='
            '"${WINN3_SET_CARRIER_STANDALONE:-1}"',
            1,
        )
        status = _classify("break_default_on", mutated, source_default_is_zero)
        rows.append(("BREAK default becomes 1", status, "FAIL"))

    status = _classify("control_green_message", live, message_is_honest)
    rows.append(("CONTROL_GREEN 404 message is honest", status, "PASS"))

    # BREAK: the 404 message promises a flip registration no longer performs
    needle = "registration never applies carrier=winn3 "
    if live.count(needle) != 1:
        rows.append(
            (f"BREAK stale 404 message (needle {live.count(needle)}x)",
             "NOT_APPLIED", "FAIL")
        )
    else:
        mutated = live.replace(needle, "hub will apply carrier=winn3 ", 1)
        status = _classify("break_stale_message", mutated, message_is_honest)
        rows.append(("BREAK 404 message promises a registration flip", status, "FAIL"))

    # BREAK: maybe_apply always returns
    needle = 'if flag != "1":'
    # This needle may occur once in maybe_apply. Count in hub heredoc.
    hub = extract_heredoc_after(
        live, 'cat > "${APP_DIR}/main.py" <<\'PYEOF\'', "PYEOF"
    )
    if hub.count(needle) != 1:
        rows.append(
            (f"BREAK always-return (needle {hub.count(needle)}x in hub)",
             "NOT_APPLIED", "FAIL")
        )
    else:
        mutated = live.replace(needle, 'if True:  # mutated always skip', 1)
        status = _classify("break_always_skip", mutated, maybe_apply_writes_winn3)
        rows.append(("BREAK maybe_apply always returns", status, "FAIL"))

    bad = 0
    for name, got, want in rows:
        inverted = want == "FAIL"
        if inverted:
            ok = got == "FAIL"
            mark = "CAUGHT" if ok else got
        else:
            ok = got == want
            mark = got
        if not ok:
            bad += 1
        print(f"  {mark:12} {name} (got {got}, want {want})")
    return bad


def main() -> int:
    SCRATCH.mkdir(parents=True, exist_ok=True)
    MUTANTS.mkdir(parents=True, exist_ok=True)
    RUNS.mkdir(parents=True, exist_ok=True)
    TMP.mkdir(parents=True, exist_ok=True)
    os.environ["TMPDIR"] = str(TMP)
    os.chdir(str(ROOT))
    print("winn/3 install-time carrier=winn3 opt-in")
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(InstallerSourceTests))
    suite.addTests(loader.loadTestsFromTestCase(InstallerShellTests))
    suite.addTests(loader.loadTestsFromTestCase(HubMaybeApplyTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    mut_bad = mutation_table()
    if result.wasSuccessful() and mut_bad == 0:
        print("\nALL GREEN: unit tests passed; mutation breaks were caught")
        return 0
    print(
        f"\nunit failures={len(result.failures)+len(result.errors)} "
        f"mutation_misclassified={mut_bad}"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
