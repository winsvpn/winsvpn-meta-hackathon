"""S5 source-backed offline fixtures: adoption of standalone-built nodes, the
pre-adoption backup and its restore, --winn3-rollback and --preflight coverage.
Test key material is generated per run and never leaves the temporary area."""
import contextlib
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import ExitStack
from unittest.mock import patch

import test_winn3_onetouch_s4 as s4
from test_winn3_onetouch_s4 import BASH, NODE, SOURCE, embedded, shell_function

X25519_PRIVATE = "302e020100300506032b656e04220420"
X25519_PUBLIC = "302a300506032b656e032100"
REAL_RUN = subprocess.run
REAL_REPLACE = os.replace


def section(start, end):
    """A slice of the production installer between two literal markers."""
    return SOURCE.split(start, 1)[1].split(end, 1)[0]


class AdoptionBase(unittest.TestCase):
    """A fixture area that looks root-owned to the node tool, as S4's does."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.area = Path(self.temp.name).resolve()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.callback(os.umask, os.umask(0o022))
        real_lstat = os.lstat

        def directory(path, private=False):
            path = Path(path)
            if path != self.area and self.area not in path.parents:
                raise NODE.Refusal("fixture directory escaped")
            for ancestor in (path, *path.parents):
                if ancestor == self.area.parent:
                    break
                info = real_lstat(ancestor)
                if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
                    raise NODE.Refusal("unsafe directory: " + str(ancestor))
            if private and stat.S_IMODE(real_lstat(path).st_mode) != 0o700:
                raise NODE.Refusal("credentials directory must be root 0700")
        self.stack.enter_context(patch.object(NODE, "secure_directory", directory))

        def rooted(real):
            def call(*args, **kwargs):
                info = real(*args, **kwargs)
                fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
                return types.SimpleNamespace(**{**fields, "st_uid": 0, "st_gid": 0})
            return call
        for name in ("fstat", "lstat", "stat"):
            self.stack.enter_context(patch.object(os, name, rooted(getattr(os, name))))
        for name in ("fchown", "chown"):
            self.stack.enter_context(patch.object(os, name, lambda *args, **kwargs: None))
        original_mkdtemp = tempfile.mkdtemp

        def temporary(prefix=None, dir=None, suffix=None):
            if dir == "/run":
                (self.area / "run").mkdir(exist_ok=True)
                dir = str(self.area / "run")
            return original_mkdtemp(prefix=prefix, dir=dir, suffix=suffix)
        self.stack.enter_context(patch.object(tempfile, "mkdtemp", temporary))
        self.cred = self.area / "etc/winn/credentials"
        self.unit = self.area / "etc/systemd/system/winn3-gateway.service"
        self.env = self.area / "etc/winn/winn3-gateway.env"
        self.node_env = self.area / "root/node.env"
        self.public_identity = self.area / "etc/winn/public/gateway-identity.json"
        for path in (self.cred, self.unit.parent, self.node_env.parent, self.public_identity.parent):
            path.mkdir(parents=True, exist_ok=True)
        self.cred.chmod(0o700)
        self.binary_calls = []

    # ---- key material -------------------------------------------------
    def make_keys(self):
        static = os.urandom(32)
        seed = os.urandom(32)
        ed_public = NODE.openssl_public(NODE.ED25519_PRIVATE, NODE.ED25519_PUBLIC, seed)
        x_public = NODE.openssl_public(X25519_PRIVATE, X25519_PUBLIC, static)
        self.bodies = {
            "static.key": static.hex().encode(), "admission.key": os.urandom(32).hex().encode(),
            "auth_ed25519.seed": (seed + ed_public).hex().encode(), "auth_mldsa65.seed": os.urandom(32).hex().encode(),
            "public/static.pub": x_public.hex().encode(), "public/auth_ed25519.pub": ed_public.hex().encode(),
            "public/auth_mldsa65.pub": (bytes([7]) * 1952).hex().encode()}
        return self.bodies

    LEGACY = {"static.key": "winn3-gateway-static.key", "admission.key": "winn3-gateway-admission.key",
              "auth_ed25519.seed": "winn3-gateway-auth-ed25519.seed", "auth_mldsa65.seed": "winn3-gateway-auth-mldsa65.seed"}
    CREDENTIAL = {"static.key": "static.key", "admission.key": "admission.key",
                  "auth_ed25519.seed": "dual-auth-ed-key", "auth_mldsa65.seed": "dual-auth-ml-seed"}

    def write(self, path, body, mode):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body if isinstance(body, bytes) else body.encode())
        path.chmod(mode)
        return path

    def standalone(self, canonical=False, publics=False, mode=0o600):
        """Keys the way the standalone installer left them. Returns the path of each secret."""
        self.make_keys()
        paths = {}
        for name in NODE.SECRETS:
            paths[name] = self.write(self.cred / (name if canonical else self.LEGACY[name]), self.bodies[name], mode)
        if publics:
            for name in NODE.PUBLICS:
                self.write(self.cred / name, self.bodies[name], 0o644)
        self.legacy_paths = paths
        self.write(self.unit, self.unit_text(paths), 0o644)
        return paths

    def unit_text(self, paths, exec_extra="", literal=None):
        literal = literal or {}
        lines = ["[Unit]", "Description=Winn Protocol v3 gateway", "", "[Service]"]
        lines += ["LoadCredential=" + self.CREDENTIAL[name] + ":" + str(paths[name]) for name in NODE.SECRETS]
        lines += ["ExecStartPre=+/bin/sh -c 'true'", "ExecStart=/usr/local/libexec/winn/winn3-gateway \\", "  -mode serve \\",
                  "  -listen ${WINN3_GATEWAY_LISTEN} \\", "  -static /run/winn3-gateway/static.key \\",
                  "  -gateway-id " + literal.get("gateway-id", "${WINN3_GATEWAY_ID}") + " \\",
                  "  -inner-v4 " + literal.get("inner-v4", "${WINN3_GATEWAY_INNER_V4}") + " \\",
                  "  -plan " + literal.get("plan", "udp") + " \\", "  -path-mtu " + literal.get("path-mtu", "1450") + " \\",
                  "  -forward -resolver -forward-cidr " + literal.get("forward-cidr", "10.10.0.0/24") + exec_extra, ""]
        return "\n".join(lines)

    def env_text(self, **values):
        base = {"WINN3_GATEWAY_LISTEN": "0.0.0.0:9111", "WINN3_GATEWAY_ID": "fra1-gw9",
                "WINN3_GATEWAY_PATH_MTU": "1450", "WINN3_GATEWAY_INNER_V4": "10.10.0.1",
                "WINN3_GATEWAY_FORWARD_CIDR": "10.10.0.0/24", "WINN3_GATEWAY_PLAN": "udp"}
        base.update(values)
        return "# standalone env\n" + "".join(key + "=" + value + "\n" for key, value in base.items() if value is not None)

    def host(self, **env):
        self.write(self.env, self.env_text(**env), 0o600)

    def node(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["node", *argv]), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            NODE.main()
        self.stderr = err.getvalue()
        return out.getvalue()

    def snapshot(self):
        state = {}
        run = self.area / "run"
        for path in sorted(self.area.rglob("*")):
            info = os.lstat(path)
            # /run is tmpfs: phase A's derive-public adds and removes one private
            # directory there, which moves only that directory's own mtime.
            state[str(path)] = (info.st_mode, info.st_ino, None if path == run else info.st_mtime_ns,
                                hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() and not path.is_symlink() else "")
        return state

    def store(self, gateway_id="fra1-gw9"):
        return NODE.Credentials(self.cred, gateway_id)

    def shown(self, pid=0, dropins=(), reload="no", load="loaded", fragment=None):
        """`systemctl show` output for the gateway unit (winn3gw_unit_view)."""
        return ("LoadState=" + load + "\nFragmentPath=" + str(self.unit if fragment is None else fragment)
                + "\nDropInPaths=" + " ".join(str(d) for d in dropins) + "\nNeedDaemonReload=" + reload
                + "\nMainPID=" + str(pid) + "\n")

    def running(self, pid, argv):
        """A /proc entry for the running gateway with this argv."""
        proc = self.area / "proc"
        if (proc / str(pid) / "cmdline").exists():
            (proc / str(pid) / "cmdline").unlink()
        self.write(proc / str(pid) / "cmdline", b"\0".join(a.encode() for a in argv) + b"\0", 0o444)
        return proc

    def fake_binary(self, derive=True, calls=None):
        """subprocess.run that stands in for the gateway binary only; openssl stays real."""
        calls = self.binary_calls if calls is None else calls

        def run(command, **kwargs):
            if command[0] == "openssl":
                return REAL_RUN(command, **kwargs)
            calls.append(command)
            self.assertNotIn("keygen", command, "adoption must never generate keys")
            if "derive-public" not in command or not derive:
                return types.SimpleNamespace(returncode=1)
            out = Path(command[command.index("-out") + 1])
            out.mkdir(mode=0o700)
            for name in NODE.PUBLICS:
                (out / Path(name).name).write_bytes(self.bodies[name])
                (out / Path(name).name).chmod(0o600)
            return types.SimpleNamespace(returncode=0)
        return patch.object(subprocess, "run", run)


# ---------------------------------------------------------------------------
# Identity precedence (design 2.6)
# ---------------------------------------------------------------------------

class IdentityPrecedenceTests(AdoptionBase):
    def resolve(self, requested=None, **kwargs):
        return NODE.adoption_identity(self.cred, self.public_identity, self.node_env, self.env, self.unit,
                                      requested or {})

    def test_standalone_values_are_kept_and_defaults_never_override_them(self):
        self.standalone()
        self.host(WINN3_GATEWAY_ID="fra1-gw9", WINN3_GATEWAY_INNER_V4="10.10.4.1", WINN3_GATEWAY_FORWARD_CIDR="10.10.4.0/24")
        self.write(self.unit, self.unit_text(self.legacy_paths, literal={"forward-cidr": "10.10.4.0/24"}), 0o644)
        resolved, asynchronous, flags, env = self.resolve()
        self.assertEqual(resolved, {"gateway_id": "fra1-gw9", "path_mtu": "1450", "inner_v4": "10.10.4.1",
                                    "forward_cidr": "10.10.4.0/24", "slice": "4"})
        self.assertFalse(asynchronous)

    def test_second_node_on_the_shared_slice_and_an_assigned_slice_both_keep_theirs(self):
        for slice_value in ("0", "7", "255"):
            with self.subTest(slice=slice_value):
                self.standalone()
                self.host(WINN3_GATEWAY_INNER_V4="10.10." + slice_value + ".1",
                          WINN3_GATEWAY_FORWARD_CIDR="10.10." + slice_value + ".0/24")
                self.write(self.unit, self.unit_text(self.legacy_paths, literal={"forward-cidr": "10.10." + slice_value + ".0/24"}), 0o644)
                self.assertEqual(self.resolve()[0]["slice"], slice_value)

    def test_every_pair_of_levels_that_disagree_refuses_by_field_name(self):
        # Field, then the level whose value is changed. The other levels agree.
        literal = {"gateway-id": "fra1-gw9", "inner-v4": "10.10.0.1", "path-mtu": "1450", "forward-cidr": "10.10.0.0/24"}
        sources = {"gateway_id": "fra1-gw9", "path_mtu": "1450", "inner_v4": "10.10.0.1", "forward_cidr": "10.10.0.0/24"}
        different = {"gateway_id": "other-gw1", "path_mtu": "1400", "inner_v4": "10.10.0.1", "forward_cidr": "10.10.0.0/24"}
        different["inner_v4"] = "10.10.0.1"
        node_env_keys = {"gateway_id": "WINN3_GATEWAY_ID", "path_mtu": "WINN3_GATEWAY_PATH_MTU",
                         "inner_v4": "WINN3_GATEWAY_INNER_V4", "forward_cidr": "WINN3_GATEWAY_FORWARD_CIDR"}
        unit_keys = {"gateway_id": "gateway-id", "path_mtu": "path-mtu", "inner_v4": "inner-v4", "forward_cidr": "forward-cidr"}
        for field in sources:
            changed = {"gateway_id": "other-gw1", "path_mtu": "1400", "inner_v4": "10.10.0.1", "forward_cidr": "10.10.0.0/24"}[field]
            if field == "inner_v4":
                changed = "10.10.1.1"
            if field == "forward_cidr":
                changed = "10.10.0.0/24"
            for level in ("node.env", "unit", "env file", "published identity"):
                if level == "published identity" and field == "forward_cidr":
                    continue
                if field == "forward_cidr":
                    changed = "10.10.1.0/24"
                with self.subTest(field=field, level=level):
                    for path in (self.node_env, self.public_identity):
                        if path.exists():
                            path.unlink()
                    self.standalone()
                    env_values = {node_env_keys[f]: sources[f] for f in sources}
                    unit_literal = dict(literal)
                    node_lines = {node_env_keys[f]: sources[f] for f in sources}
                    identity = {"gateway_id": sources["gateway_id"], "path_mtu": int(sources["path_mtu"]),
                                "inner_router_v4": sources["inner_v4"]}
                    if level == "node.env":
                        node_lines[node_env_keys[field]] = changed
                    elif level == "unit":
                        unit_literal[unit_keys[field]] = changed
                    elif level == "env file":
                        env_values[node_env_keys[field]] = changed
                    else:
                        identity[{"gateway_id": "gateway_id", "path_mtu": "path_mtu", "inner_v4": "inner_router_v4"}[field]] = \
                            int(changed) if field == "path_mtu" else changed
                    self.write(self.env, self.env_text(**env_values), 0o600)
                    self.write(self.unit, self.unit_text(self.legacy_paths, literal=unit_literal), 0o644)
                    self.write(self.node_env, "".join(k + "=" + v + "\n" for k, v in node_lines.items()), 0o600)
                    self.write(self.public_identity, json.dumps(identity), 0o644)
                    with self.assertRaisesRegex(NODE.Refusal, "identity conflict: " + field):
                        self.resolve()

    def test_a_credential_record_for_another_gateway_id_refuses(self):
        self.standalone(canonical=True, publics=True)
        self.host()
        NODE.atomic_file(self.cred / "winn3-identity.complete",
                         NODE.canonical({"gateway_id": "another-gw1", "sha256": {n: NODE.digest(self.bodies[n]) for n in NODE.ORDER}}), 0o600)
        with self.assertRaisesRegex(NODE.Refusal, "identity conflict: gateway_id"):
            self.resolve()

    def test_forward_cidr_and_router_outside_the_slice_regime_refuse(self):
        cases = (("forward_cidr", "WINN3_GATEWAY_FORWARD_CIDR", "10.64.0.0/24"), ("forward_cidr", "WINN3_GATEWAY_FORWARD_CIDR", "10.10.0.0/16"),
                 ("forward_cidr", "WINN3_GATEWAY_FORWARD_CIDR", "10.10.256.0/24"), ("forward_cidr", "WINN3_GATEWAY_FORWARD_CIDR", "192.168.1.0/24"),
                 ("inner_v4", "WINN3_GATEWAY_INNER_V4", "10.64.0.1"), ("inner_v4", "WINN3_GATEWAY_INNER_V4", "10.10.0.2"))
        for field, key, value in cases:
            with self.subTest(value=value):
                self.standalone()
                self.write(self.unit, self.unit_text(self.legacy_paths, literal={"forward-cidr": value}) if field == "forward_cidr"
                           else self.unit_text(self.legacy_paths), 0o644)
                self.host(**{key: value})
                with self.assertRaisesRegex(NODE.Refusal, field + " outside the slice regime"):
                    self.resolve()

    def test_router_and_cidr_in_different_slices_and_a_wrong_node_env_slice_refuse(self):
        self.standalone()
        self.host(WINN3_GATEWAY_INNER_V4="10.10.1.1", WINN3_GATEWAY_FORWARD_CIDR="10.10.2.0/24")
        self.write(self.unit, self.unit_text(self.legacy_paths, literal={"forward-cidr": "10.10.2.0/24"}), 0o644)
        with self.assertRaisesRegex(NODE.Refusal, "identity conflict: forward_cidr"):
            self.resolve()
        self.host()
        self.write(self.unit, self.unit_text(self.legacy_paths), 0o644)
        self.write(self.node_env, "WINN3_INNER_SLICE=3\n", 0o600)
        with self.assertRaisesRegex(NODE.Refusal, "identity conflict: WINN3_INNER_SLICE"):
            self.resolve()

    def test_unrecorded_or_unusable_values_refuse(self):
        self.standalone()
        self.host(WINN3_GATEWAY_ID=None)
        with self.assertRaisesRegex(NODE.Refusal, "gateway_id is not recorded"):
            self.resolve()
        for value in ("1500", "1199", "abc", "145"):
            with self.subTest(mtu=value):
                self.host(WINN3_GATEWAY_PATH_MTU=value)
                self.write(self.unit, self.unit_text(self.legacy_paths, literal={"path-mtu": value}), 0o644)
                with self.assertRaisesRegex(NODE.Refusal, "path_mtu"):
                    self.resolve()
        self.host(WINN3_GATEWAY_INNER_V4=None, WINN3_GATEWAY_FORWARD_CIDR=None)
        self.write(self.unit, self.unit_text(self.legacy_paths, literal={"forward-cidr": "${X}"}), 0o644)
        with self.assertRaisesRegex(NODE.Refusal, "inner_v4 is not recorded"):
            self.resolve()

    def test_an_explicit_request_that_differs_from_the_adopted_value_refuses(self):
        self.standalone()
        self.host()
        with self.assertRaisesRegex(NODE.Refusal, r"identity conflict: gateway_id \(requested 'x-gw1', adopted 'fra1-gw9'\)"):
            self.resolve({"gateway_id": "x-gw1"})
        with self.assertRaisesRegex(NODE.Refusal, "identity conflict: slice"):
            self.resolve({"slice": "9"})
        self.assertEqual(self.resolve({"gateway_id": "fra1-gw9", "path_mtu": "", "slice": "0"})[0]["slice"], "0")

    def test_forward_async_is_seen_in_the_env_file_and_in_the_unit(self):
        for source in ("env", "unit"):
            with self.subTest(source=source):
                self.standalone()
                if source == "env":
                    self.host(WINN3_GATEWAY_FORWARD_ASYNC="1")
                else:
                    self.host()
                    self.write(self.unit, self.unit_text(self.legacy_paths, exec_extra=" -forward-async-write"), 0o644)
                self.assertTrue(self.resolve()[1])
        self.host(WINN3_GATEWAY_FORWARD_ASYNC="0")
        self.write(self.unit, self.unit_text(self.legacy_paths), 0o644)
        self.assertFalse(self.resolve()[1])

    def test_the_operation_prints_six_lines_and_reports_each_convergence(self):
        self.standalone()
        self.host(WINN3_GATEWAY_PLAN="udp,tcp", WINN3_GATEWAY_LISTEN="0.0.0.0:51833", WINN3_GATEWAY_FORWARD_ASYNC="1")
        self.write(self.unit, self.unit_text(self.legacy_paths, literal={"plan": "udp,tcp"}), 0o644)
        output = self.node("adopt-identity", str(self.cred), str(self.public_identity), str(self.node_env), str(self.env),
                           str(self.unit), self.shown(), "", "", "", "", "").split("\n")
        self.assertEqual(output[:6], ["fra1-gw9", "1450", "10.10.0.1", "10.10.0.0/24", "0", "1"])
        for text in ("plan udp,tcp converges", "listen 0.0.0.0:51833 converges", "forward-async is on"):
            self.assertIn(text, self.stderr)

    def test_a_vault_link_for_node_env_is_followed_and_a_foreign_link_refused(self):
        self.standalone()
        self.host()
        vault = self.area / "vault"
        vault.mkdir()
        self.write(vault / "node.env", "WINN3_GATEWAY_ID=fra1-gw9\n", 0o600)
        self.node_env.symlink_to(vault / "node.env")
        self.assertEqual(self.resolve()[0]["gateway_id"], "fra1-gw9")
        self.node_env.unlink()
        self.write(vault / "node.env", "WINN3_GATEWAY_ID=other-gw1\n", 0o600)
        self.node_env.symlink_to(vault / "node.env")
        with self.assertRaisesRegex(NODE.Refusal, "identity conflict: gateway_id"):
            self.resolve()

    def test_unsafe_unit_or_env_files_are_refused(self):
        self.standalone()
        self.host()
        self.env.chmod(0o666)
        with self.assertRaisesRegex(NODE.Refusal, "unsafe file"):
            self.resolve()
        self.env.chmod(0o600)
        self.unit.chmod(0o666)
        with self.assertRaisesRegex(NODE.Refusal, "unsafe file"):
            self.resolve()


# ---------------------------------------------------------------------------
# The live unit (design 2.6 level 3; Turn 1 Q4, Astra and Sol): what systemd
# has loaded and what the running gateway was started with, never a file that
# may differ from both.
# ---------------------------------------------------------------------------

class LiveUnitTests(AdoptionBase):
    def resolve(self, shown, proc=None):
        return NODE.adoption_identity(self.cred, self.public_identity, self.node_env, self.env, self.unit, {}, shown, proc)

    def test_a_unit_file_systemd_did_not_load_as_it_is_refuses(self):
        self.standalone()
        self.host()
        for kwargs, message in (({"reload": "yes"}, "changed since systemd loaded it"),
                                ({"reload": ""}, "changed since systemd loaded it"),
                                ({"load": "not-found", "fragment": ""}, "is not loaded by systemd"),
                                ({"load": "masked", "fragment": "/dev/null"}, "is not loaded by systemd"),
                                ({"fragment": "/usr/lib/systemd/system/winn3-gateway.service"}, "systemd loads the gateway from"),
                                ({"pid": "x"}, "invalid MainPID")):
            with self.subTest(**kwargs):
                with self.assertRaisesRegex(NODE.Refusal, message):
                    self.resolve(self.shown(**kwargs))
                with self.fake_binary(), self.assertRaisesRegex(NODE.Refusal, message):
                    self.store().adopt("fixture-binary", self.unit, plan_only=True, shown=self.shown(**kwargs))
        self.assertEqual(self.resolve(self.shown())[0]["gateway_id"], "fra1-gw9")

    def test_no_unit_on_disk_and_none_loaded_leaves_the_live_level_empty(self):
        self.standalone()
        self.host()
        self.unit.unlink()
        self.assertEqual(self.resolve(self.shown(load="not-found", fragment=""))[0]["gateway_id"], "fra1-gw9")

    def test_a_drop_in_that_replaces_exec_start_is_the_live_command(self):
        self.standalone()
        self.host()
        dropin = self.write(self.area / "etc/systemd/system/winn3-gateway.service.d/30-override.conf",
                            "[Service]\nExecStart=\nExecStart=/usr/local/libexec/winn/winn3-gateway -mode serve"
                            " -gateway-id other-gw1 -path-mtu 1450\n", 0o644)
        with self.assertRaisesRegex(NODE.Refusal, r"identity conflict: gateway_id \(.*live unit 'other-gw1'"):
            self.resolve(self.shown(dropins=[dropin]))
        # Reading the unit file alone does not see the override.
        self.assertEqual(self.resolve(None)[0]["gateway_id"], "fra1-gw9")
        dropin.write_text("[Service]\nExecStart=/bin/true\n")
        with self.assertRaisesRegex(NODE.Refusal, "more than one ExecStart"):
            self.resolve(self.shown(dropins=[dropin]))
        dropin.write_text("[Service]\nLimitCORE=0\n")
        self.assertEqual(self.resolve(self.shown(dropins=[dropin]))[0]["gateway_id"], "fra1-gw9")
        dropin.chmod(0o666)
        with self.assertRaisesRegex(NODE.Refusal, "unsafe file"):
            self.resolve(self.shown(dropins=[dropin]))
        with self.assertRaisesRegex(NODE.Refusal, "unsafe drop-in path"):
            self.resolve(self.shown(dropins=["relative.conf"]))

    def test_key_files_named_by_a_drop_in_are_the_ones_adopted(self):
        paths = self.standalone()
        self.host()
        moved = self.area / "etc/winn/keys-elsewhere"
        moved.mkdir(mode=0o700)
        ed = self.write(moved / "ed.seed", self.bodies["auth_ed25519.seed"], 0o600)
        ml = self.write(moved / "ml.seed", self.bodies["auth_mldsa65.seed"], 0o600)
        self.write(self.unit, "\n".join(l for l in self.unit.read_text().splitlines() if "dual-auth" not in l), 0o644)
        dropin = self.write(self.area / "etc/systemd/system/winn3-gateway.service.d/30-dual-auth-resolver.conf",
                            "[Service]\nLoadCredential=dual-auth-ed-key:" + str(ed) + "\nLoadCredential=dual-auth-ml-seed:"
                            + str(ml) + "\n", 0o644)
        paths["auth_ed25519.seed"].unlink()
        paths["auth_mldsa65.seed"].unlink()
        with self.fake_binary(), self.assertRaisesRegex(NODE.Refusal, "missing key: auth_ed25519.seed"):
            self.store().adopt("fixture-binary", self.unit)
        sources = self.store().legacy_sources(self.unit, NODE.unit_view(self.unit, self.shown(dropins=[dropin]))[0])
        self.assertEqual((sources["auth_ed25519.seed"], sources["auth_mldsa65.seed"]), (ed, ml))
        twice = self.write(self.area / "etc/systemd/system/winn3-gateway.service.d/40-twice.conf",
                           "[Service]\nLoadCredential=dual-auth-ed-key:" + str(self.area / "x/other.seed") + "\n", 0o644)
        with self.fake_binary(), self.assertRaisesRegex(NODE.Refusal, "dual-auth-ed-key is loaded from two different paths"):
            self.store().adopt("fixture-binary", self.unit, shown=self.shown(dropins=[dropin, twice]))
        with self.fake_binary():
            self.assertEqual(self.store().adopt("fixture-binary", self.unit, shown=self.shown(dropins=[dropin])), "derive-public")
        self.assertEqual((self.cred / "auth_mldsa65.seed").read_bytes(), self.bodies["auth_mldsa65.seed"])

    def test_the_running_gateway_argv_is_the_live_identity(self):
        self.standalone()
        self.host()
        program = "/usr/local/libexec/winn/winn3-gateway"
        proc = self.running(4242, [program, "-mode", "serve", "-gateway-id", "fra1-gw7", "-inner-v4", "10.10.0.1",
                                   "-path-mtu", "1450"])
        # Astra's counterexample: the running gateway is A, the unit and env say B.
        with self.assertRaisesRegex(NODE.Refusal, r"identity conflict: gateway_id \(.*running gateway 'fra1-gw7'"):
            self.resolve(self.shown(pid=4242), proc)
        proc = self.running(4242, [program, "-mode", "serve", "-gateway-id", "fra1-gw9", "-forward",
                                   "-accept-transit=true", "-forward-async-write"])
        resolved, asynchronous = self.resolve(self.shown(pid=4242), proc)[:2]
        self.assertEqual(resolved["gateway_id"], "fra1-gw9")
        self.assertTrue(asynchronous)
        # A gateway that exited after systemctl show leaves the loaded unit live.
        self.assertEqual(self.resolve(self.shown(pid=4243), proc)[0]["gateway_id"], "fra1-gw9")

    def test_the_running_gateway_must_hold_the_adopted_keys(self):
        self.standalone()
        self.host()
        runtime = self.area / "run/winn3-gateway"
        runtime.mkdir(parents=True)
        copies = {flag: self.write(runtime / name.replace(".", "-"), self.bodies[name], 0o600)
                  for flag, name in NODE.RUNNING_SECRET_FLAGS}
        argv = ["/usr/local/libexec/winn/winn3-gateway", "-mode", "serve"]
        for flag, path in copies.items():
            argv += ["-" + flag, str(path)]
        proc = self.running(4242, argv)
        for flag, name in NODE.RUNNING_SECRET_FLAGS:
            with self.subTest(flag=flag):
                copies[flag].write_bytes(os.urandom(SIZES_OF[name]).hex().encode())
                with self.fake_binary(), self.assertRaisesRegex(
                        NODE.Refusal, "identity conflict: " + re.escape(name) + r" \(the running gateway"):
                    self.store().adopt("fixture-binary", self.unit, plan_only=True, shown=self.shown(pid=4242), proc=proc)
                copies[flag].write_bytes(self.bodies[name])
        copies["admission"].unlink()
        with self.fake_binary(), self.assertRaisesRegex(NODE.Refusal, "key copy cannot be read"):
            self.store().adopt("fixture-binary", self.unit, plan_only=True, shown=self.shown(pid=4242), proc=proc)
        self.write(copies["admission"], self.bodies["admission.key"], 0o400)
        with self.fake_binary():
            self.assertEqual(self.store().adopt("fixture-binary", self.unit, plan_only=True, shown=self.shown(pid=4242),
                                                proc=proc), "fresh")
            self.assertEqual(self.store().adopt("fixture-binary", self.unit, shown=self.shown(pid=4242), proc=proc),
                             "derive-public")

    def test_each_operation_reads_the_live_view_it_is_given(self):
        self.standalone()
        self.host()
        with self.assertRaisesRegex(NODE.Refusal, "changed since systemd loaded it"):
            self.node("adopt-identity", str(self.cred), str(self.public_identity), str(self.node_env), str(self.env),
                      str(self.unit), self.shown(reload="yes"), "", "", "", "", "")
        for operation in ("adopt-plan", "adopt-credentials"):
            with self.subTest(operation=operation), self.fake_binary(), \
                    self.assertRaisesRegex(NODE.Refusal, "changed since systemd loaded it"):
                self.node(operation, str(self.cred), "fra1-gw9", "fixture-binary", str(self.unit), self.shown(reload="yes"), "")
        self.assertEqual(self.store().classify(), "fresh")


SIZES_OF = {"static.key": 32, "admission.key": 32, "auth_ed25519.seed": 64, "auth_mldsa65.seed": 32}


# ---------------------------------------------------------------------------
# Credentials: classification, adoption transaction, public-key sourcing
# ---------------------------------------------------------------------------

class AdoptionCredentialTests(AdoptionBase):
    def snapshot_files(self, root):
        return {str(p): (p.read_bytes(), os.lstat(p).st_ino, os.lstat(p).st_mtime_ns) for p in sorted(Path(root).rglob("*")) if p.is_file()}

    def test_a_complete_legacy_set_with_or_without_public_halves_is_classified_legacy(self):
        for publics in (False, True):
            with self.subTest(publics=publics):
                for path in self.cred.rglob("*"):
                    if path.is_file():
                        path.unlink()
                self.standalone(canonical=True, publics=publics)
                self.assertEqual(self.store().classify(), "legacy")

    def test_legacy_named_keys_are_invisible_to_the_canonical_classifier(self):
        self.standalone()
        self.assertEqual(self.store().classify(), "fresh")

    def test_a_partial_set_still_refuses_by_name(self):
        for name in NODE.ORDER:
            with self.subTest(name=name):
                for path in self.cred.rglob("*"):
                    if path.is_file():
                        path.unlink()
                self.standalone(canonical=True, publics=True)
                (self.cred / name).unlink()
                with self.assertRaisesRegex(NODE.Refusal, re.escape("partial winn3 credential set: missing " + name)):
                    self.store().classify()
        for path in self.cred.rglob("*"):
            if path.is_file():
                path.unlink()
        self.standalone(canonical=True, publics=False)
        (self.cred / "public").mkdir(exist_ok=True)
        self.write(self.cred / "public/static.pub", self.bodies["public/static.pub"], 0o644)
        with self.assertRaisesRegex(NODE.Refusal, "missing public/auth_ed25519.pub"):
            self.store().classify()

    def test_plain_keygen_install_refuses_a_legacy_set_and_never_runs_keygen(self):
        self.standalone(canonical=True)
        with self.fake_binary():
            with self.assertRaisesRegex(NODE.Refusal, "requires adoption"):
                self.store().install("never-executed")
        self.assertEqual(self.binary_calls, [])

    def test_adoption_from_legacy_named_files_keeps_every_byte_and_leaves_the_originals(self):
        paths = self.standalone()
        before = self.snapshot_files(self.cred)
        with self.fake_binary():
            self.assertEqual(self.store().adopt("fixture-binary", self.unit), "derive-public")
        self.assertEqual(self.store().classify(), "complete")
        for name in NODE.ORDER:
            self.assertEqual((self.cred / name).read_bytes(), self.bodies[name])
        for name, path in paths.items():
            self.assertEqual(path.read_bytes(), self.bodies[name])
            self.assertEqual(self.snapshot_files(self.cred)[str(path)], before[str(path)])
        record = json.loads((self.cred / "winn3-identity.complete").read_bytes())
        self.assertEqual(record["gateway_id"], "fra1-gw9")
        self.assertEqual(record["sha256"]["admission.key"], NODE.digest(self.bodies["admission.key"]))
        self.assertFalse(list(self.cred.glob(".staging-*")))
        self.assertFalse(list((self.area / "run").glob("winn3-derive.*")))
        self.assertEqual(stat.S_IMODE((self.cred / "static.key").stat().st_mode), 0o600)

    def test_adoption_in_place_never_rewrites_a_canonical_secret(self):
        self.standalone(canonical=True, publics=True)
        (self.cred / "static.key").chmod(0o400)
        before = self.snapshot_files(self.cred)
        with self.fake_binary():
            self.store().adopt("fixture-binary", self.unit)
        after = self.snapshot_files(self.cred)
        for name in NODE.ORDER:
            path = str(self.cred / name)
            self.assertEqual(after[path][:3], before[path][:3], name)
        self.assertEqual(stat.S_IMODE((self.cred / "static.key").stat().st_mode), 0o600)
        self.assertEqual(self.store().classify(), "complete")

    def test_a_second_adoption_changes_nothing(self):
        self.standalone()
        with self.fake_binary():
            self.store().adopt("fixture-binary", self.unit)
            snapshot = self.snapshot()
            self.binary_calls.clear()
            self.assertEqual(self.store().adopt("fixture-binary", self.unit), "complete")
        self.assertEqual(snapshot, self.snapshot())
        self.assertEqual(self.binary_calls, [])

    def test_every_missing_key_refuses_by_name(self):
        for name in NODE.SECRETS:
            with self.subTest(name=name):
                paths = self.standalone()
                paths[name].unlink()
                with self.fake_binary(), self.assertRaisesRegex(NODE.Refusal, "missing key: " + re.escape(name)):
                    self.store().adopt("fixture-binary", self.unit)

    def test_insecure_keys_refuse_by_name(self):
        for name in NODE.SECRETS:
            for mode in (0o640, 0o644, 0o660, 0o604, 0o700):
                with self.subTest(name=name, mode=oct(mode)):
                    paths = self.standalone()
                    paths[name].chmod(mode)
                    with self.fake_binary(), self.assertRaisesRegex(NODE.Refusal, "insecure key: " + re.escape(name)):
                        self.store().adopt("fixture-binary", self.unit)
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                paths = self.standalone()
                target = paths["admission.key"]
                moved = self.area / "elsewhere"
                moved.write_bytes(target.read_bytes())
                moved.chmod(0o600)
                target.unlink()
                if kind == "symlink":
                    target.symlink_to(moved)
                else:
                    os.link(moved, target)
                with self.fake_binary(), self.assertRaisesRegex(NODE.Refusal, "insecure key: admission.key"):
                    self.store().adopt("fixture-binary", self.unit)
                moved.unlink()

    def test_0400_secrets_are_accepted(self):
        paths = self.standalone(mode=0o400)
        with self.fake_binary():
            self.store().adopt("fixture-binary", self.unit)
        self.assertEqual(self.store().classify(), "complete")

    def test_malformed_key_bodies_refuse(self):
        for name, body in (("static.key", b"zz" * 32), ("admission.key", b"ab" * 31), ("auth_mldsa65.seed", b"AB" * 32)):
            with self.subTest(name=name):
                paths = self.standalone()
                paths[name].write_bytes(body)
                with self.fake_binary(), self.assertRaisesRegex(NODE.Refusal, "invalid credential format: " + re.escape(name)):
                    self.store().adopt("fixture-binary", self.unit)

    def test_an_ed25519_seed_whose_embedded_half_is_not_its_own_refuses(self):
        paths = self.standalone()
        body = self.bodies["auth_ed25519.seed"]
        paths["auth_ed25519.seed"].write_bytes(body[:128 - 2] + b"00" if body[126:] != b"00" else body[:126] + b"11")
        with self.fake_binary(), self.assertRaisesRegex(NODE.Refusal, "embedded public half"):
            self.store().adopt("fixture-binary", self.unit)

    def test_phase_a_catches_an_ed25519_seed_whose_embedded_half_is_wrong_without_any_public_source(self):
        paths = self.standalone()
        body = self.bodies["auth_ed25519.seed"]
        paths["auth_ed25519.seed"].write_bytes(body[:-2] + (b"00" if body[-2:] != b"00" else b"11"))
        before = self.snapshot()
        with self.fake_binary(), self.assertRaisesRegex(NODE.Refusal, "embedded public half"):
            self.node("adopt-plan", str(self.cred), "fra1-gw9", "fixture-binary", str(self.unit), self.shown(), "")
        self.assertEqual(before, self.snapshot())

    def test_canonical_and_legacy_files_that_differ_are_an_identity_conflict(self):
        for name in NODE.SECRETS:
            with self.subTest(name=name):
                for path in self.cred.glob("*"):
                    path.unlink()
                self.standalone()
                for other in NODE.SECRETS:
                    body = self.bodies[other]
                    if other == name:
                        body = body[:-2] + (b"00" if body[-2:] != b"00" else b"11")
                    self.write(self.cred / other, body, 0o600)
                with self.fake_binary(), self.assertRaisesRegex(NODE.Refusal, "identity conflict: " + re.escape(name)):
                    self.store().adopt("fixture-binary", self.unit)
        for path in self.cred.glob("*"):
            path.unlink()
        self.standalone()
        for name in NODE.SECRETS:
            self.write(self.cred / name, self.bodies[name], 0o600)
        with self.fake_binary():
            self.store().adopt("fixture-binary", self.unit)
        self.assertEqual(self.store().classify(), "complete")

    def test_unit_credential_paths_must_be_absolute_and_free_of_dotdot(self):
        self.standalone()
        for bad in ("relative/key", str(self.cred) + "/../escape"):
            with self.subTest(bad=bad):
                text = self.unit.read_text().replace(str(self.legacy_paths["static.key"]), bad)
                self.write(self.unit, text, 0o644)
                with self.fake_binary(), self.assertRaisesRegex(NODE.Refusal, "unsafe key path"):
                    self.store().adopt("fixture-binary", self.unit)
                self.write(self.unit, self.unit_text(self.legacy_paths), 0o644)

    # ---- public-key sourcing -------------------------------------------
    def test_existing_public_halves_are_used_first_and_checked_against_the_derived_ones(self):
        self.standalone(canonical=True, publics=True)
        with self.fake_binary():
            self.assertEqual(self.store().adopt("fixture-binary", self.unit), "existing public halves")
        self.assertEqual(len(self.binary_calls), 1)

    def test_a_wrong_existing_half_is_caught_by_openssl_or_by_the_derived_cross_check(self):
        self.standalone(canonical=True, publics=True)
        (self.cred / "public/static.pub").write_bytes(self.bodies["public/auth_ed25519.pub"])
        with self.fake_binary(), self.assertRaisesRegex(NODE.Refusal, "public half does not match: public/static.pub"):
            self.store().adopt("fixture-binary", self.unit)
        (self.cred / "public/static.pub").write_bytes(self.bodies["public/static.pub"])
        (self.cred / "public/auth_mldsa65.pub").write_bytes((bytes([9]) * 1952).hex().encode())
        with self.fake_binary(), self.assertRaisesRegex(NODE.Refusal, r"public half does not match: public/auth_mldsa65.pub \(derive-public\)"):
            self.store().adopt("fixture-binary", self.unit)

    def test_derive_public_is_run_on_the_legacy_paths_and_supplies_all_three_halves(self):
        paths = self.standalone()
        with self.fake_binary():
            self.store().adopt("fixture-binary", self.unit)
        command = self.binary_calls[0]
        self.assertEqual(command[:2], ["fixture-binary", "-mode"])
        self.assertEqual(command[command.index("-static") + 1], str(paths["static.key"]))
        self.assertEqual(command[command.index("-dual-auth-ed-key") + 1], str(paths["auth_ed25519.seed"]))
        self.assertEqual(command[command.index("-dual-auth-ml-seed") + 1], str(paths["auth_mldsa65.seed"]))

    def key_directory(self, name="winn3-keys-fra1", halves=None):
        directory = self.area / "root" / name
        directory.mkdir(parents=True)
        directory.chmod(0o700)
        for public, body in (halves or {n: self.bodies[n] for n in NODE.PUBLICS}).items():
            self.write(directory / Path(public).name, body, 0o600)
        return directory

    def test_the_keys_directory_is_the_last_source_and_needs_exactly_one_match(self):
        self.standalone()
        with patch.object(NODE, "KEY_DIRECTORY_PARENT", str(self.area / "root")):
            with self.fake_binary(derive=False), self.assertRaisesRegex(NODE.Refusal, "0 winn3-keys-\\* directories"):
                self.store().adopt("fixture-binary", self.unit)
            one = self.key_directory()
            with self.fake_binary(derive=False):
                self.assertEqual(self.store().adopt("fixture-binary", self.unit), "winn3-keys directory")
            self.assertEqual(self.store().classify(), "complete")
            # 2.6: the keys directory is kept until the hub records the slug as proven.
            self.assertEqual(sorted(p.name for p in one.iterdir()), ["auth_ed25519.pub", "auth_mldsa65.pub", "static.pub"])
            for path in sorted(self.cred.rglob("*"), reverse=True):
                path.unlink() if path.is_file() else path.rmdir()
            shutil.rmtree(one)
            self.standalone()
            one = self.key_directory()
            self.key_directory("winn3-keys-fra2")
            with self.fake_binary(derive=False), self.assertRaisesRegex(NODE.Refusal, "2 winn3-keys-\\* directories"):
                self.store().adopt("fixture-binary", self.unit)
            with self.fake_binary(derive=False):
                self.assertEqual(self.store().adopt("fixture-binary", self.unit, keydir=str(one)), "winn3-keys directory")

    def test_the_keys_directory_override_must_be_absolute_secure_and_well_formed(self):
        self.standalone()
        with self.fake_binary(derive=False):
            with self.assertRaisesRegex(NODE.Refusal, "must be an absolute path"):
                self.store().adopt("fixture-binary", self.unit, keydir="relative")
            loose = self.key_directory()
            loose.chmod(0o777)
            with self.assertRaisesRegex(NODE.Refusal, "unsafe directory"):
                self.store().adopt("fixture-binary", self.unit, keydir=str(loose))
            loose.chmod(0o700)
            (loose / "auth_mldsa65.pub").write_bytes(b"nothex")
            with self.assertRaisesRegex(NODE.Refusal, "invalid credential format: public/auth_mldsa65.pub"):
                self.store().adopt("fixture-binary", self.unit, keydir=str(loose))
            self.write(loose / "auth_mldsa65.pub", self.bodies["public/auth_mldsa65.pub"], 0o666)
            with self.assertRaisesRegex(NODE.Refusal, "unsafe file"):
                self.store().adopt("fixture-binary", self.unit, keydir=str(loose))

    def test_a_keys_directory_half_that_does_not_match_the_secret_refuses(self):
        self.standalone()
        halves = {n: self.bodies[n] for n in NODE.PUBLICS}
        halves["public/static.pub"] = self.bodies["public/auth_ed25519.pub"]
        directory = self.key_directory(halves=halves)
        with self.fake_binary(derive=False), self.assertRaisesRegex(NODE.Refusal, "public half does not match: public/static.pub"):
            self.store().adopt("fixture-binary", self.unit, keydir=str(directory))

    def test_ml_dsa_needs_source_two_or_three_because_openssl_cannot_derive_it(self):
        self.standalone()
        with patch.object(NODE, "KEY_DIRECTORY_PARENT", str(self.area / "empty")):
            (self.area / "empty").mkdir()
            with self.fake_binary(derive=False), self.assertRaises(NODE.Refusal):
                self.store().adopt("fixture-binary", self.unit)
        self.assertEqual(self.store().classify(), "fresh")

    # ---- the transaction -------------------------------------------------
    def test_a_crash_after_each_rename_resumes_the_same_identity_without_derive_or_keygen(self):
        for crash in range(1, len(NODE.ORDER) + 1):
            with self.subTest(crash=crash):
                for path in sorted(self.cred.rglob("*"), reverse=True):
                    path.unlink() if path.is_file() or path.is_symlink() else path.rmdir()
                self.standalone()
                count = 0

                def replace(source, destination):
                    nonlocal count
                    count += 1
                    if count == crash:
                        raise OSError("injected crash")
                    return REAL_REPLACE(source, destination)
                with self.fake_binary(), patch.object(NODE.os, "replace", replace), self.assertRaises(OSError):
                    self.store().adopt("fixture-binary", self.unit)
                self.binary_calls.clear()
                with self.fake_binary():
                    self.store().adopt("fixture-binary", self.unit)
                self.assertEqual(self.store().classify(), "complete")
                for name in NODE.ORDER:
                    self.assertEqual((self.cred / name).read_bytes(), self.bodies[name])

    def test_an_incomplete_staging_directory_is_discarded_and_adoption_proceeds(self):
        self.standalone()
        stage = self.cred / ".staging-leftover"
        stage.mkdir(mode=0o700)
        (stage / "public").mkdir()
        self.write(stage / "static.key", b"00" * 32, 0o600)
        with self.fake_binary():
            self.store().adopt("fixture-binary", self.unit)
        self.assertEqual(self.store().classify(), "complete")
        self.assertEqual((self.cred / "static.key").read_bytes(), self.bodies["static.key"])
        self.assertFalse(list(self.cred.glob(".staging-*")))

    def test_the_cleanup_of_a_finished_transaction_survives_a_second_stage(self):
        self.standalone()
        with self.fake_binary():
            self.store().adopt("fixture-binary", self.unit)
        self.write(self.cred / ".staging-late/staging.complete", b"x", 0o600)
        with self.assertRaises(NODE.Refusal):
            self.store().classify()

    # ---- phase A is read only ---------------------------------------------
    def test_phase_a_operations_change_nothing_on_the_host(self):
        self.standalone()
        self.host()
        self.write(self.node_env, "NODE_SLUG=fra1\n", 0o600)
        (self.area / "run").mkdir()
        before = self.snapshot()
        with self.fake_binary():
            self.assertEqual(self.node("classify", str(self.cred), "fra1-gw9").strip(), "fresh")
            self.assertEqual(self.node("adopt-plan", str(self.cred), "fra1-gw9", "fixture-binary", str(self.unit),
                                       self.shown(), "").strip(), "fresh")
            self.node("adopt-identity", str(self.cred), str(self.public_identity), str(self.node_env), str(self.env),
                      str(self.unit), self.shown(), "", "", "", "", "")
        # derive-public ran once, into a private tmpfs directory that is gone again.
        self.assertEqual([c[:3] for c in self.binary_calls], [["fixture-binary", "-mode", "derive-public"]])
        self.assertEqual(before, self.snapshot())

    def test_phase_a_proves_missing_and_insecure_keys_before_anything_is_written(self):
        paths = self.standalone()
        paths["auth_mldsa65.seed"].chmod(0o644)
        before = self.snapshot()
        with self.fake_binary(), self.assertRaisesRegex(NODE.Refusal, "insecure key: auth_mldsa65.seed"):
            self.node("adopt-plan", str(self.cred), "fra1-gw9", "fixture-binary", str(self.unit), self.shown(), "")
        self.assertEqual(before, self.snapshot())
        paths["auth_mldsa65.seed"].chmod(0o600)
        paths["static.key"].unlink()
        before = self.snapshot()
        with self.fake_binary(), self.assertRaisesRegex(NODE.Refusal, "missing key: static.key"):
            self.node("adopt-plan", str(self.cred), "fra1-gw9", "fixture-binary", str(self.unit), self.shown(), "")
        self.assertEqual(before, self.snapshot())

    def test_phase_a_checks_existing_halves_and_an_explicit_keys_directory(self):
        self.standalone(canonical=True, publics=True)
        (self.cred / "public/auth_ed25519.pub").write_bytes(self.bodies["public/static.pub"])
        with self.fake_binary(), self.assertRaisesRegex(NODE.Refusal, "public half does not match: public/auth_ed25519.pub"):
            self.node("adopt-plan", str(self.cred), "fra1-gw9", "fixture-binary", str(self.unit), self.shown(), "")
        for path in sorted(self.cred.rglob("*"), reverse=True):
            path.unlink() if path.is_file() else path.rmdir()
        self.standalone()
        halves = {n: self.bodies[n] for n in NODE.PUBLICS}
        halves["public/auth_ed25519.pub"] = self.bodies["public/static.pub"]
        directory = self.key_directory(halves=halves)
        with self.fake_binary(), self.assertRaisesRegex(NODE.Refusal, "public half does not match: public/auth_ed25519.pub"):
            self.node("adopt-plan", str(self.cred), "fra1-gw9", "fixture-binary", str(self.unit), self.shown(), str(directory))

    def test_adopt_credentials_operation_adopts_and_names_the_source(self):
        self.standalone()
        with self.fake_binary():
            self.assertEqual(self.node("adopt-credentials", str(self.cred), "fra1-gw9", "fixture-binary", str(self.unit),
                                       self.shown(), "").strip(),
                             "derive-public")
        self.assertEqual(self.node("classify", str(self.cred), "fra1-gw9").strip(), "complete")

    # ---- Turn 1 (Astra 3, Sol 3): ML-DSA needs source 2 or 3, in phase A too --
    def test_existing_halves_without_derive_public_still_need_the_keys_directory_for_ml_dsa(self):
        self.standalone(canonical=True, publics=True)
        (self.cred / "public/auth_mldsa65.pub").write_bytes((bytes([9]) * 1952).hex().encode())
        with patch.object(NODE, "KEY_DIRECTORY_PARENT", str(self.area / "root")):
            with self.fake_binary(derive=False), self.assertRaisesRegex(NODE.Refusal, "derive-public is unavailable"):
                self.store().adopt("fixture-binary", self.unit)
            self.assertEqual(self.store().classify(), "legacy")
            self.key_directory()
            with self.fake_binary(derive=False), self.assertRaisesRegex(
                    NODE.Refusal, r"public half does not match: public/auth_mldsa65.pub \(winn3-keys directory\)"):
                self.store().adopt("fixture-binary", self.unit)
            self.assertEqual(self.store().classify(), "legacy")
            (self.cred / "public/auth_mldsa65.pub").write_bytes(self.bodies["public/auth_mldsa65.pub"])
            with self.fake_binary(derive=False):
                self.assertEqual(self.store().adopt("fixture-binary", self.unit), "existing public halves")

    def test_phase_a_catches_a_wrong_existing_ml_dsa_half_before_anything_changes(self):
        self.standalone(canonical=True, publics=True)
        (self.cred / "public/auth_mldsa65.pub").write_bytes((bytes([9]) * 1952).hex().encode())
        (self.area / "run").mkdir()
        before = self.snapshot()
        with self.fake_binary(), self.assertRaisesRegex(
                NODE.Refusal, r"public half does not match: public/auth_mldsa65.pub \(derive-public\)"):
            self.node("adopt-plan", str(self.cred), "fra1-gw9", "fixture-binary", str(self.unit), self.shown(), "")
        self.assertEqual(before, self.snapshot())
        self.assertEqual([c[:3] for c in self.binary_calls], [["fixture-binary", "-mode", "derive-public"]])

    def test_an_explicit_keys_directory_is_cross_checked_even_when_derive_public_works(self):
        self.standalone()
        halves = {n: self.bodies[n] for n in NODE.PUBLICS}
        halves["public/auth_mldsa65.pub"] = (bytes([9]) * 1952).hex().encode()
        directory = self.key_directory(halves=halves)
        with self.fake_binary(), self.assertRaisesRegex(
                NODE.Refusal, r"public half does not match: public/auth_mldsa65.pub \(winn3-keys directory\)"):
            self.store().adopt("fixture-binary", self.unit, keydir=str(directory))
        self.assertEqual(self.store().classify(), "fresh")

    def test_a_binary_that_cannot_run_counts_as_no_derive_public(self):
        self.standalone()

        def run(command, **kwargs):
            if command[0] == "openssl":
                return REAL_RUN(command, **kwargs)
            raise PermissionError("not executable")
        with patch.object(subprocess, "run", run), patch.object(NODE, "KEY_DIRECTORY_PARENT", str(self.area / "root")):
            with self.assertRaisesRegex(NODE.Refusal, "derive-public is unavailable"):
                self.store().adopt("fixture-binary", self.unit)
            self.key_directory()
            self.assertEqual(self.store().adopt("fixture-binary", self.unit), "winn3-keys directory")
        self.assertFalse(list((self.area / "run").glob("winn3-derive.*")))


# ---------------------------------------------------------------------------
# Backup and restore (design 2.6 and section 4, item 3)
# ---------------------------------------------------------------------------

class BackupAndRestoreTests(AdoptionBase):
    def setUp(self):
        super().setUp()
        self.parent = self.area / "var/backups/winsvpn"
        self.parent.parent.mkdir(parents=True)
        self.files = {}
        layout = {"etc/systemd/system/winn3-gateway.service": (b"unit\n", 0o644),
                  "etc/systemd/system/winn3-gateway-firewall.service": (b"helper unit\n", 0o644),
                  "usr/local/sbin/winn3-gateway-firewall": (b"#!/bin/sh\necho helper\n", 0o700),
                  "etc/winn/winn3-gateway.env": (b"WINN3_GATEWAY_ID=x\n", 0o600),
                  "usr/local/libexec/winn/winn3-gateway": (os.urandom(4096), 0o755),
                  "etc/winsvpn/.winn3_gateway_installer.sha256": (b"stamp\ninstaller_path=/root/standalone.sh\n", 0o600),
                  "root/node.env": (b"NODE_TOKEN=\"redacted-fixture\"\n", 0o600),
                  "etc/iptables/rules.v4": (b"*filter\nCOMMIT\n", 0o600),
                  "etc/winsvpn/role": (b"data-winn3\n", 0o600),
                  "root/standalone.sh": (b"#!/bin/bash\necho standalone\n", 0o755)}
        for relative, (body, mode) in layout.items():
            self.files[self.area / relative] = (body, mode)
            self.write(self.area / relative, body, mode)
        self.program = self.write(self.area / "program.py", "# node program fixture\n", 0o600)
        self.installer = {"path": str(self.area / "root/installer.sh"), "sha256": "a" * 64}
        self.run_log = []

    def systemctl(self, enabled="enabled", active="active", fail=()):
        def run(command, **kwargs):
            self.run_log.append(command)
            if command[:2] == ["systemctl", "is-enabled"]:
                return types.SimpleNamespace(returncode=0, stdout=enabled + "\n")
            if command[:2] == ["systemctl", "is-active"]:
                return types.SimpleNamespace(returncode=0, stdout=active + "\n")
            return types.SimpleNamespace(returncode=1 if " ".join(command[:2]) in fail else 0, stdout="")
        return run

    def backup(self, stamp="20261007T120000Z", **kwargs):
        return NODE.adopt_backup(stamp, str(self.program), [str(p) for p in self.files], self.installer,
                                 parent=str(self.parent), run=self.systemctl(**kwargs))

    def damage(self):
        for path, (body, mode) in self.files.items():
            path.write_bytes(b"changed by ONETOUCH\n")
            path.chmod(0o600)

    def test_every_path_the_design_lists_is_backed_up_with_a_manifest_and_a_restore_script(self):
        directory, reused = self.backup()
        self.assertFalse(reused)
        self.assertEqual(directory.name, "winn3-pre-onetouch-20261007T120000Z")
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        manifest = json.loads((directory / "manifest.json").read_bytes())
        self.assertEqual({e["path"] for e in manifest["entries"]}, {str(p) for p in self.files})
        for path, (body, mode) in self.files.items():
            copy = directory / "files" / str(path).lstrip("/")
            self.assertEqual(copy.read_bytes(), body)
            self.assertEqual(stat.S_IMODE(copy.stat().st_mode), 0o600)
        entry = next(e for e in manifest["entries"] if e["path"].endswith("winn3-gateway-firewall"))
        self.assertEqual((entry["mode"], entry["uid"], entry["gid"]), (0o700, 0, 0))
        listed = dict(line.split("  ", 1)[::-1] for line in (directory / "MANIFEST.sha256").read_text().splitlines())
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((directory / name).read_bytes()).hexdigest(), digest)
        self.assertIn("manifest.json", listed)
        self.assertEqual((directory / "restore.sh").read_text(), NODE.BACKUP_RESTORE_SCRIPT)
        self.assertEqual(stat.S_IMODE((directory / "restore.sh").stat().st_mode), 0o700)
        self.assertEqual((directory / "winn3-node.py").read_bytes(), self.program.read_bytes())
        self.assertEqual(manifest["services"]["winn3-gateway.service"], {"enabled": "enabled", "active": "active"})
        self.assertEqual(manifest["installer"], self.installer)
        self.assertEqual(sorted(p.name for p in self.parent.iterdir()), [directory.name])

    def test_absent_paths_are_recorded_and_a_non_root_or_special_file_refuses_cleanly(self):
        missing = self.area / "root/standalone.sh"
        missing.unlink()
        directory, _ = self.backup()
        manifest = json.loads((directory / "manifest.json").read_bytes())
        self.assertEqual(next(e for e in manifest["entries"] if e["path"] == str(missing)), {"path": str(missing), "present": False})
        for kind in ("directory", "foreign"):
            with self.subTest(kind=kind):
                shutil_parent = self.area / "var/backups/other"
                paths = [str(p) for p in self.files if p != missing]
                if kind == "directory":
                    paths.append(str(self.area / "etc"))
                    patcher = contextlib.nullcontext()
                else:
                    real = os.lstat

                    def foreign(path, *a, **k):
                        info = real(path, *a, **k)
                        return types.SimpleNamespace(**{**{k2: getattr(info, k2) for k2 in dir(info) if k2.startswith("st_")},
                                                       "st_uid": 1000 if str(path).endswith("rules.v4") else 0})
                    patcher = patch.object(os, "lstat", foreign)
                with patcher, self.assertRaisesRegex(NODE.Refusal, "cannot back up a non-regular or non-root file"):
                    NODE.adopt_backup("20261007T130000Z", str(self.program), paths, self.installer,
                                      parent=str(shutil_parent), run=self.systemctl())
                self.assertEqual(sorted(p.name for p in shutil_parent.iterdir()), [])

    def test_a_path_that_was_absent_when_saved_is_reported_and_left_alone(self):
        missing = self.area / "root/standalone.sh"
        missing.unlink()
        directory, _ = self.backup()
        self.write(missing, b"created later by something else\n", 0o644)
        self.damage_except(missing)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            NODE.adopt_restore(directory, run=self.systemctl())
        self.assertIn("absent when saved, left as is: " + str(missing), out.getvalue())
        self.assertEqual(missing.read_bytes(), b"created later by something else\n")

    def damage_except(self, kept):
        for path in self.files:
            if path != kept and path.exists():
                path.write_bytes(b"changed by ONETOUCH\n")
                path.chmod(0o600)

    def test_a_symlinked_node_env_is_saved_by_content_and_restored_into_its_target(self):
        vault = self.area / "vault"
        vault.mkdir()
        target = self.write(vault / "node.env", b"NODE_TOKEN=fixture\n", 0o600)
        link = self.area / "root/node.env"
        link.unlink()
        link.symlink_to(target)
        directory, _ = self.backup()
        entry = next(e for e in json.loads((directory / "manifest.json").read_bytes())["entries"] if e["path"] == str(link))
        self.assertEqual(entry["link"], str(target))
        target.write_bytes(b"changed\n")
        NODE.adopt_restore(directory, run=self.systemctl())
        self.assertTrue(link.is_symlink())
        self.assertEqual(target.read_bytes(), b"NODE_TOKEN=fixture\n")

    def test_the_stamp_is_validated_and_a_taken_name_refuses(self):
        for stamp in ("", "2026-10-07", "20261007T12000Z", "../x"):
            with self.subTest(stamp=stamp), self.assertRaisesRegex(NODE.Refusal, "invalid backup stamp"):
                self.backup(stamp)

    def test_an_unrestored_backup_is_the_restore_point_and_the_oldest_wins(self):
        first, _ = self.backup("20261007T120000Z")
        self.damage()
        again, reused = self.backup("20261007T130000Z")
        self.assertEqual((again, reused), (first, True))
        self.assertEqual(sorted(p.name for p in self.parent.iterdir()), [first.name])
        newer = self.parent / "winn3-pre-onetouch-20261008T000000Z"
        shutil.copytree(first, newer)
        self.assertEqual(self.backup("20261009T000000Z")[0], first)

    def test_a_damaged_backup_blocks_adoption_instead_of_being_reused(self):
        directory, _ = self.backup()
        copy = directory / "files" / str(next(iter(self.files))).lstrip("/")
        copy.write_bytes(b"tampered")
        with self.assertRaisesRegex(NODE.Refusal, "backup file fails its digest"):
            self.backup("20261008T000000Z")
        (directory / "winn3-node.py").unlink()
        with self.assertRaises((NODE.Refusal, OSError)):
            self.backup("20261008T000000Z")

    def test_a_restored_backup_is_not_reused_and_a_new_one_is_taken(self):
        first, _ = self.backup()
        NODE.adopt_restore(first, run=self.systemctl())
        self.assertTrue((first / "RESTORED").exists())
        second, reused = self.backup("20261008T000000Z")
        self.assertFalse(reused)
        self.assertNotEqual(first, second)

    def test_restore_puts_back_every_file_byte_for_byte_with_modes_and_orders_the_services(self):
        directory, _ = self.backup()
        self.damage()
        NODE.adopt_restore(directory, run=self.systemctl())
        for path, (body, mode) in self.files.items():
            self.assertEqual(path.read_bytes(), body, str(path))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode, str(path))
        commands = [" ".join(c[:3]) for c in self.run_log if c[:2] not in (["systemctl", "is-enabled"], ["systemctl", "is-active"])]
        self.assertEqual(commands[0], "systemctl disable --now")
        self.assertEqual(commands[1], "systemctl daemon-reload")
        self.assertEqual(commands[2:], ["systemctl enable winn3-gateway-firewall.service", "systemctl enable winn3-gateway.service",
                                        "systemctl restart winn3-gateway-firewall.service", "systemctl restart winn3-gateway.service"])
        self.assertFalse(list(self.area.rglob(".winn3-restore-*")))

    def test_units_that_were_off_stay_off(self):
        directory, _ = self.backup(enabled="disabled", active="inactive")
        self.damage()
        self.run_log.clear()
        NODE.adopt_restore(directory, run=self.systemctl())
        self.assertEqual([c[1] for c in self.run_log if c[1] in ("enable", "restart")], [])

    def test_a_tampered_backup_refuses_before_any_command_or_file_change(self):
        directory, _ = self.backup()
        self.damage()
        copy = directory / "files" / str(next(iter(self.files))).lstrip("/")
        copy.write_bytes(b"tampered")
        self.run_log.clear()
        before = {p: p.read_bytes() for p in self.files}
        with self.assertRaisesRegex(NODE.Refusal, "fails its digest"):
            NODE.adopt_restore(directory, run=self.systemctl())
        self.assertEqual(self.run_log, [])
        self.assertEqual(before, {p: p.read_bytes() for p in self.files})

    def test_a_backup_file_that_changes_after_the_manifest_check_is_never_installed(self):
        directory, _ = self.backup()
        self.damage()
        victim = next(iter(self.files))
        real_verify = NODE.verify_backup

        def verify_then_tamper(path):
            manifest = real_verify(path)
            (Path(path) / "files" / str(victim).lstrip("/")).write_bytes(b"swapped after the check")
            return manifest
        self.run_log.clear()
        with patch.object(NODE, "verify_backup", verify_then_tamper), self.assertRaises(SystemExit) as caught:
            NODE.adopt_restore(directory, run=self.systemctl())
        self.assertEqual(caught.exception.code, 3)
        self.assertEqual(victim.read_bytes(), b"changed by ONETOUCH\n")
        # Fail closed (Turn 1): the restore stops at the first failure, so no
        # later file is replaced and no unit is enabled or started.
        for path in self.files:
            self.assertEqual(path.read_bytes(), b"changed by ONETOUCH\n")
        self.assertEqual([c[1] for c in self.run_log], ["disable"])
        self.assertFalse(list(self.area.rglob(".winn3-restore-*")))
        self.assertFalse((directory / "RESTORED").exists())

    def test_a_failed_stop_changes_no_file_starts_nothing_and_leaves_no_restored_mark(self):
        directory, _ = self.backup()
        self.damage()
        self.run_log.clear()
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as caught:
            NODE.adopt_restore(directory, run=self.systemctl(fail=("systemctl disable",)))
        self.assertEqual(caught.exception.code, 3)
        for path in self.files:
            self.assertEqual(path.read_bytes(), b"changed by ONETOUCH\n")
        self.assertEqual([c[1] for c in self.run_log], ["disable"])
        self.assertIn("no file was changed", err.getvalue())
        self.assertFalse((directory / "RESTORED").exists())

    # ---- Turn 1 (Astra 1, Sol 1): a recorded failure fails closed ------------
    def restore_with(self, latch, guard, fail=(), entry_failure=None):
        """One restore with an injected failure; returns (exit code, guard calls)."""
        calls = []
        base = self.systemctl(fail=fail)

        def run(command, **kwargs):
            if command[0] == str(guard):
                calls.append(command)
                return types.SimpleNamespace(returncode=0, stdout="")
            return base(command, **kwargs)
        real_entry = NODE.restore_entry
        seen = []

        def entry(directory, item, root):
            seen.append(item["path"])
            if entry_failure is not None and len(seen) == entry_failure:
                raise OSError("injected copy failure")
            return real_entry(directory, item, root)
        directory, _ = self.backup()
        self.damage()
        self.run_log.clear()
        code = 0
        with patch.object(NODE, "LATCH_FILE", str(latch)), patch.object(NODE, "LATCH_GUARD", str(guard)), \
                patch.object(NODE, "restore_entry", entry), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                NODE.adopt_restore(directory, run=run)
            except SystemExit as error:
                code = error.code
        return code, calls, directory

    def test_a_failed_file_restore_never_enables_restarts_or_releases_the_latch(self):
        sha = hashlib.sha256(b"installer bytes\n").hexdigest()
        latch, installer, guard = self.latch_fixture(sha, sha)
        for point, fail, entry_failure in (("copy", (), 3), ("stop", ("systemctl disable",), None),
                                           ("daemon-reload", ("systemctl daemon-reload",), None)):
            with self.subTest(point=point):
                for stale in self.parent.glob("*"):
                    shutil.rmtree(stale)
                for path, (body, mode) in self.files.items():
                    self.write(path, body, mode)
                code, calls, directory = self.restore_with(latch, guard, fail, entry_failure)
                self.assertEqual(code, 3)
                verbs = [c[1] for c in self.run_log if c[0] == "systemctl"]
                self.assertNotIn("enable", verbs)
                self.assertNotIn("restart", verbs)
                self.assertEqual(calls, [], "the latch must stay held")
                self.assertTrue(latch.exists())
                self.assertFalse((directory / "RESTORED").exists())

    def test_a_failed_enable_or_start_stops_both_units_again_and_keeps_the_latch(self):
        sha = hashlib.sha256(b"installer bytes\n").hexdigest()
        latch, installer, guard = self.latch_fixture(sha, sha)
        for point in ("systemctl enable", "systemctl restart"):
            with self.subTest(point=point):
                for stale in self.parent.glob("*"):
                    shutil.rmtree(stale)
                for path, (body, mode) in self.files.items():
                    self.write(path, body, mode)
                code, calls, directory = self.restore_with(latch, guard, (point,))
                self.assertEqual(code, 3)
                self.assertEqual(calls, [])
                commands = [c for c in self.run_log if c[0] == "systemctl"]
                failed = next(i for i, c in enumerate(commands) if " ".join(c[:2]) == point)
                self.assertEqual(commands[failed + 1:], [["systemctl", "disable", "--now", *NODE.GATEWAY_UNITS]])
                self.assertFalse((directory / "RESTORED").exists())

    def test_the_latch_is_released_only_when_the_backed_up_installer_digest_matches(self):
        sha = hashlib.sha256(b"installer bytes\n").hexdigest()
        latch, installer, guard = self.latch_fixture(sha, sha)
        directory, _ = self.backup()
        # The installer at the recorded path is now another run, and the latch names that run.
        installer.write_bytes(b"another installer run\n")
        other = hashlib.sha256(b"another installer run\n").hexdigest()
        latch.write_text("VERSION=1\nREASON=installer-rerun:" + other + "\nDISABLED_EPOCH=1\n")
        calls = []
        base = self.systemctl()

        def run(command, **kwargs):
            if command[0] == str(guard):
                calls.append(command)
                return types.SimpleNamespace(returncode=0, stdout="")
            return base(command, **kwargs)
        err = io.StringIO()
        with patch.object(NODE, "LATCH_FILE", str(latch)), patch.object(NODE, "LATCH_GUARD", str(guard)), \
                contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            NODE.adopt_restore(directory, run=run)
        self.assertEqual(calls, [])
        self.assertIn("latch does not match the backed-up installer run", err.getvalue())
        with patch.object(NODE, "LATCH_FILE", str(latch)), patch.object(NODE, "LATCH_GUARD", str(guard)):
            for recorded in ("", "A" * 64, None, sha):
                with self.subTest(recorded=recorded):
                    self.assertIn("latch does not match the backed-up installer run",
                                  NODE.release_installer_latch({"path": str(installer), "sha256": recorded}, "", run))
            self.assertEqual(NODE.release_installer_latch({"path": str(installer), "sha256": other}, "", run), "")
            # Sol: the backup digest, the latch and the installer bytes must all agree.
            latch.write_text("VERSION=1\nREASON=installer-rerun:" + sha + "\nDISABLED_EPOCH=1\n")
            self.assertIn("is not at its recorded path",
                          NODE.release_installer_latch({"path": str(installer), "sha256": sha}, "", run))
        self.assertEqual(len(calls), 1)

    def test_a_late_failure_record_refuses_the_restore_before_any_change(self):
        directory, _ = self.backup()
        self.damage()
        record = self.area / "var/lib/winsvpn/winn3-late-failure.json"
        for kind in ("file", "link"):
            with self.subTest(kind=kind):
                record.parent.mkdir(parents=True, exist_ok=True)
                if kind == "file":
                    self.write(record, b"", 0o600)
                else:
                    record.unlink()
                    record.symlink_to(self.area / "nowhere")
                self.run_log.clear()
                before = {p: p.read_bytes() for p in self.files}
                with patch.object(NODE, "LATE_FAILURE_RECORD", str(record)), \
                        self.assertRaisesRegex(NODE.Refusal, "late-failure record exists"):
                    NODE.adopt_restore(directory, run=self.systemctl())
                self.assertEqual(self.run_log, [])
                self.assertEqual(before, {p: p.read_bytes() for p in self.files})
                self.assertFalse((directory / "RESTORED").exists())

    def test_rules_v4_is_put_back_last_under_the_firewall_lock_after_the_release_saved_over_it(self):
        sha = hashlib.sha256(b"installer bytes\n").hexdigest()
        latch, installer, guard = self.latch_fixture(sha, sha)
        rules = self.area / "etc/iptables/rules.v4"
        lock = self.write(self.area / "run/lock/wins-firewall.lock", b"", 0o644)
        directory, _ = self.backup()
        self.damage()
        base = self.systemctl()
        held = []

        def run(command, **kwargs):
            if command[0] == str(guard):
                # release-deployment persists the live rules (apply_enabled_chain).
                rules.write_bytes(b"*filter\n# live snapshot saved by the release\nCOMMIT\n")
                return types.SimpleNamespace(returncode=0, stdout="")
            return base(command, **kwargs)
        real_entry = NODE.restore_entry

        def entry(directory, item, root):
            if item["path"] == str(rules):
                probe = os.open(lock, os.O_RDONLY)
                try:
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    held.append(False)
                except BlockingIOError:
                    held.append(True)
                finally:
                    os.close(probe)
            return real_entry(directory, item, root)
        with patch.object(NODE, "LATCH_FILE", str(latch)), patch.object(NODE, "LATCH_GUARD", str(guard)), \
                patch.object(NODE, "RULES_V4", str(rules)), patch.object(NODE, "FIREWALL_LOCK", str(lock)), \
                patch.object(NODE, "restore_entry", entry), contextlib.redirect_stdout(io.StringIO()):
            NODE.adopt_restore(directory, run=run)
        self.assertEqual(rules.read_bytes(), b"*filter\nCOMMIT\n")
        self.assertEqual(held, [False, True])
        self.assertTrue((directory / "RESTORED").exists())

    def latch_fixture(self, reason_sha, installer_sha):
        latch = self.area / "etc/winsvpn/local-serving.disabled"
        self.write(latch, "VERSION=1\nREASON=installer-rerun:" + reason_sha + "\nDISABLED_EPOCH=1\n", 0o600)
        installer = self.write(self.area / "root/installer.sh", b"installer bytes\n", 0o755)
        self.installer = {"path": str(installer), "sha256": hashlib.sha256(installer.read_bytes()).hexdigest()}
        guard = self.write(self.area / "usr/local/sbin/wins-node-local-serving", "#!/bin/sh\n", 0o700)
        return latch, installer, guard

    def test_serving_is_released_only_for_the_exact_installer_run_that_engaged_the_latch(self):
        installer = self.write(self.area / "root/installer.sh", b"installer bytes\n", 0o755)
        sha = hashlib.sha256(installer.read_bytes()).hexdigest()
        for reason, released in ((sha, True), ("b" * 64, False)):
            with self.subTest(reason=reason[:4]):
                latch, installer, guard = self.latch_fixture(reason, sha)
                for stale in self.parent.glob("*"):
                    shutil.rmtree(stale)
                directory, _ = self.backup()
                run = self.systemctl()
                calls = []

                def recording(command, **kwargs):
                    if command[0] == str(guard):
                        calls.append((command, kwargs["env"]["WINS_NODE_LOCAL_SERVING_INSTALLER_PATH"]))
                        return types.SimpleNamespace(returncode=0, stdout="")
                    return run(command, **kwargs)
                with patch.object(NODE, "LATCH_FILE", str(latch)), patch.object(NODE, "LATCH_GUARD", str(guard)):
                    if released:
                        NODE.adopt_restore(directory, run=recording)
                        self.assertEqual(calls, [([str(guard), "release-deployment", "--installer-sha256", sha], str(installer))])
                    else:
                        with self.assertRaises(SystemExit):
                            NODE.adopt_restore(directory, run=recording)
                        self.assertEqual(calls, [])

    def test_a_manual_latch_or_a_missing_installer_keeps_serving_closed(self):
        latch, installer, guard = self.latch_fixture("c" * 64, "c" * 64)
        latch.write_text("VERSION=1\nREASON=manual-hold\n")
        directory, _ = self.backup()
        with patch.object(NODE, "LATCH_FILE", str(latch)), patch.object(NODE, "LATCH_GUARD", str(guard)):
            with self.assertRaises(SystemExit):
                NODE.adopt_restore(directory, run=self.systemctl())

    def test_the_restore_script_checks_root_and_the_manifest_then_runs_the_embedded_tool(self):
        text = NODE.BACKUP_RESTORE_SCRIPT
        self.assertLess(text.index("EUID"), text.index("sha256sum -c"))
        self.assertLess(text.index("sha256sum -c"), text.index("exec python3 -I"))
        self.assertIn("adopt-restore", text)
        directory, _ = self.backup()
        if os.geteuid() != 0:
            result = subprocess.run([BASH, str(directory / "restore.sh")], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 1)
            self.assertIn("run as root", result.stderr)

    def test_the_restore_tool_inside_the_backup_is_the_installer_node_program(self):
        program = s4.embedded("WINS_S4_NODE_PY")
        compile(program, "node", "exec")
        for operation in ("adopt-restore", "adopt-backup", "adopt-identity", "adopt-plan", "adopt-credentials"):
            self.assertIn('operation == "' + operation + '"', program)


# ---------------------------------------------------------------------------
# Shell: classifier, phases, backup call, rollback, argument handling
# ---------------------------------------------------------------------------

class ShellBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.area = Path(self.temp.name)
        self.trace = self.area / "trace"
        self.trace.write_text("")

    def run_shell(self, source, rc=0, **extra):
        env = dict(os.environ, TEST_TRACE=str(self.trace), AREA=str(self.area), **extra)
        result = subprocess.run([BASH, "-c", source], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, rc, result.stderr + result.stdout)
        self.result = result
        return self.trace.read_text().splitlines()

    def write(self, name, body="", mode=0o600):
        path = self.area / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
        path.chmod(mode)
        return path


STUBS = '''set -Eeuo pipefail
trace() { printf '%s\\n' "$*" >> "$TEST_TRACE"; }
err() { printf 'ERR %s\\n' "$*" >&2; }
winn3gw_log() { printf 'LOG %s\\n' "$*"; }
winn3gw_warn() { printf 'WARN %s\\n' "$*" >&2; }
'''


class ClassifierTests(ShellBase):
    def classify(self, role, env=True, node_env=None, stamp=False):
        function = shell_function("winn3gw_adoption_candidate").replace("/etc/winsvpn/role", str(self.area / "role"))
        if role is not None:
            self.write("role", role + "\n")
        script = STUBS + f'''WINN3_GATEWAY_ENV_FILE="$AREA/winn3-gateway.env"
DATA_PLANE_CODE_STAMP="$AREA/stamp"
NODE_ENV_FILE="$AREA/node.env"
''' + function + '''
if winn3gw_adoption_candidate; then trace candidate; else trace "no: ${WINN3_ADOPTION_WHY}"; fi
'''
        if env:
            self.write("winn3-gateway.env", "X=1\n")
        if node_env is not None:
            self.write("node.env", node_env)
        if stamp:
            self.write("stamp", "sha\n")
        return self.run_shell(script)[-1]

    def test_the_candidate_matrix(self):
        cases = (("data-cover", {}, "candidate"), ("data-winn3", {}, "candidate"),
                 ("data-winn3", {"stamp": True}, "no: role data-winn3 beside a data-plane install marker"),
                 ("data-cover", {"stamp": True}, "candidate"),
                 ("control", {}, "no: role is 'control'"), ("hub", {}, "no: role is 'hub'"),
                 (None, {}, "no: role is ''"), ("data-cover", {"env": False}, "no: no standalone gateway env file"),
                 ("data-cover", {"node_env": "NODE_SLUG=x\nWINN3_GATEWAY_ID=a\n"}, "no: node.env already carries Winn v3 keys"),
                 ("data-winn3", {"node_env": "export WINN3_INNER_SLICE=2\n"}, "no: node.env already carries Winn v3 keys"),
                 ("data-cover", {"node_env": "NODE_SLUG=x\n# WINN3_GATEWAY_ID=a\nOTHER_WINN3_X=1\n"}, "candidate"),
                 ("data-winn3", {"node_env": "NODE_SLUG=x\n"}, "candidate"))
        for role, kwargs, expected in cases:
            with self.subTest(role=role, kwargs=kwargs):
                self.temp.cleanup()
                self.setUp()
                self.assertEqual(self.classify(role, **kwargs), expected)

    def test_a_symlinked_env_file_still_counts_as_a_standalone_node(self):
        self.write("target.env", "X=1\n")
        (self.area / "winn3-gateway.env").symlink_to(self.area / "target.env")
        self.assertEqual(self.classify("data-cover", env=False), "candidate")

    def test_role_check_asks_the_classifier_for_data_winn3_only(self):
        body = shell_function("preflight_data_plane")
        block = re.search(r'(?s)  # Design 2\.6: the role check first asks.*?\n  fi\n', body).group(0)
        for role, candidate, refused in (("data-cover", 1, False), ("data-winn3", 0, False), ("data-winn3", 1, True),
                                         ("control", 0, True), ("data-cover-x", 0, True)):
            with self.subTest(role=role, candidate=candidate):
                self.trace.write_text("")
                self.write("role", role + "\n")
                script = STUBS + f'''role_file="$AREA/role"
winn3gw_adoption_candidate() {{ trace asked; return {candidate}; }}
check() {{
{block}
}}
( check )
'''
                lines = self.run_shell(script, 1 if refused else 0)
                self.assertEqual("asked" in lines, role == "data-winn3")
                if refused:
                    self.assertIn("already marked for a different Win's VPN role", self.result.stderr)


class PhaseTests(ShellBase):
    def test_phase_a_resolves_adoption_identity_before_defaults_and_verifies_after_classify(self):
        names = ("wins_late_failure_hold", "deployment_session_is_direct_remote", "data_resolve_node_defaults", "validate_config",
                 "verify_staged_binary", "winn3gw_cover_material", "require_root_private_keyfile", "require_root_regular_file",
                 "winn3_offnode_check_digest_ok", "winn3gw_adoption_identity", "winn3gw_resolve_onetouch", "winn3gw_adoption_verify")
        stubs = "".join(f'{name}() {{ trace {name}; }}\n' for name in names)
        stubs = stubs.replace("wins_late_failure_hold() { trace wins_late_failure_hold; }", "wins_late_failure_hold() { return 1; }")
        script = STUBS + stubs + '''winn3_node_tool() { trace "tool $1"; [[ "$1" == classify ]] && printf legacy; return 0; }
sha256sum() { printf '%s  x\\n' "$WINN3_ONETOUCH_BINARY_SHA256"; }
WINN3_ONETOUCH_BINARY_SHA256=db0c5ba32a7811eabd96c4dfaab392f3e82d515cdb83e5369d73a1570d48aee0
WINN3_GATEWAY_STAGING_DIR=$AREA WINN3_GATEWAY_BIN_NAME=bin WINN3_GATEWAY_INSTALL_PATH=$AREA/none
WINN3_GATEWAY_CREDENTIALS_DIR=$AREA/cred WINN3_GATEWAY_ID=fixture-gw1
DATA_NODE_DEFAULTS_RESOLVED=0 DATA_AUTO_SLUG=fixture DATA_DETECTED_PUBLIC_IPV4=192.0.2.9 NODE_ENV_FILE=$AREA/node.env
''' + shell_function("winn3gw_phase_a") + "\nwinn3gw_phase_a\n"
        lines = self.run_shell(script)
        order = [lines.index(x) for x in ("tool identity-context", "winn3gw_adoption_identity", "winn3gw_resolve_onetouch",
                                          "tool classify", "winn3gw_adoption_verify", "winn3_offnode_check_digest_ok")]
        self.assertEqual(order, sorted(order))
        self.assertEqual(lines[-1], "winn3_offnode_check_digest_ok")

    def test_phase_a_accepts_the_legacy_credential_state_and_rejects_unknown_ones(self):
        body = shell_function("winn3gw_phase_a")
        self.assertIn("fresh|resume|discard|complete|legacy)", body)

    def test_main_backs_up_after_the_preflight_exit_and_before_the_first_mutation(self):
        main = shell_function("main")
        order = [main.index(x) for x in ("\n  preflight_data_plane\n", 'if [[ "${WINSVPN_VALIDATE_ONLY:-0}" == "1" ]]', "return 0\n  fi",
                                         "\n  winn3gw_adoption_backup || return 1\n",
                                         "\n  begin_data_deployment_withdrawal_before_mutation\n",
                                         "\n  data_exchange_grant_before_reboot\n", "\n  mark_data_role\n", "\n  apt_install\n",
                                         "\n  winn3gw_phase_b\n")]
        self.assertEqual(order, sorted(order))
        self.assertEqual(main.count("winn3gw_adoption_backup"), 1)

    def test_the_role_is_migrated_before_the_data_plane_marker_can_exist(self):
        # Turn 1 Q2 (split): moving the data-winn3 rewrite into phase B would
        # strand a rerun. install_awg writes the data-plane marker before phase
        # B, and a data-winn3 role beside that marker is not a candidate, so the
        # role check would refuse every rerun after a failure in between.
        main = shell_function("main")
        self.assertLess(main.index("\n  mark_data_role\n"), main.index("\n  install_awg\n"))
        self.assertLess(main.index("\n  install_awg\n"), main.index("\n  winn3gw_phase_b\n"))
        self.assertIn("record_data_plane_code_stamp", shell_function("install_awg"))
        self.assertIn('if [[ -e "${DATA_PLANE_CODE_STAMP}" || -L "${DATA_PLANE_CODE_STAMP}" ]]; then',
                      shell_function("winn3gw_adoption_candidate"))

    def test_preflight_runs_phase_a_and_stops_before_backup_withdrawal_and_every_mutation(self):
        names = sorted(set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", shell_function("main"))))
        sys.path.insert(0, str(s4.ROOT / "tools"))
        from winn3_gateway_block import segment
        defined = {item["name"] for item in segment(SOURCE.split("\n")) if item["kind"] == "func"}
        stubs = "".join(f"{name}() {{ trace {name}; }}\n" for name in names if name in defined and name != "main")
        for validate, expected in (("1", False), ("0", True)):
            with self.subTest(validate=validate):
                self.trace.write_text("")
                script = STUBS.replace("-Eeuo", "-Eeo") + stubs + "mark_data_role() { trace mark_data_role; exit 77; }\n" \
                    + shell_function("main") + f"\nWINSVPN_VALIDATE_ONLY={validate}\nmain\n"
                lines = self.run_shell(script, 77 if expected else 0)
                self.assertIn("preflight_data_plane", lines)
                self.assertEqual("winn3gw_adoption_backup" in lines, expected)
                self.assertEqual("begin_data_deployment_withdrawal_before_mutation" in lines, expected)
                self.assertEqual("mark_data_role" in lines, expected)
                self.assertNotIn("winn3gw_phase_b", lines)
                self.assertNotIn("apt_install", lines)
                if expected:
                    self.assertLess(lines.index("winn3gw_adoption_backup"), lines.index("begin_data_deployment_withdrawal_before_mutation"))

    def test_phase_b_adopts_for_a_candidate_and_runs_plain_keygen_otherwise(self):
        for state, operation in (("candidate", "adopt-credentials"), ("none", "credentials"), ("", "credentials")):
            with self.subTest(state=state):
                self.trace.write_text("")
                stubs = ''.join(f'{n}() {{ trace {n}; }}\n' for n in (
                    "ensure_service_user", "install_binary", "winn3gw_cover_material", "validate_cover",
                    "normalize_credential_cert_modes", "ensure_peer_registry", "winn3gw_write_stable_env", "write_unit",
                    "winn3_write_serving_activator", "winn3_write_offnode_check", "winn3_write_hub_key_prune",
                    "winn3gw_render_helper", "enable_service", "winn3gw_sign_identity", "record_gateway_code_stamp",
                    "check_gateway_egress_mtu", "invalidate_gateway_code_stamp", "install", "chmod", "chown"))
                script = STUBS + stubs + '''winn3gw_bundle_digest() { printf fixture; }
winn3gw_unit_view() { trace view; printf VIEW; }
winn3_node_tool() { trace "tool $*"; }
winn3_node_program() { :; }
sha256sum() { printf '%s  x\\n' "$WINN3_ONETOUCH_BINARY_SHA256"; }
WINN3_ONETOUCH_BINARY_SHA256=db0c5ba32a7811eabd96c4dfaab392f3e82d515cdb83e5369d73a1570d48aee0
WINN3_GATEWAY_INSTALL_PATH=$AREA/gateway WINN3_GATEWAY_CREDENTIALS_DIR=/cred WINN3_GATEWAY_ID=fra1-gw9
WINN3_GATEWAY_UNIT_PATH=/unit WINN3_GATEWAY_SERVICE_USER=u NODE_ENV_FILE=/n WINN3_GATEWAY_PATH_MTU=1450
WINN3_GATEWAY_INNER_V4=10.10.0.1 WINN3_GATEWAY_FORWARD_CIDR=10.10.0.0/24 WINN3_OFFNODE_CHECK_PATH=/c
''' + (f"WINN3_ADOPTION_STATE={state}\n" if state else "unset WINN3_ADOPTION_STATE\n") \
                    + 'touch "$WINN3_GATEWAY_INSTALL_PATH"\n' \
                    + shell_function("winn3gw_phase_b").replace("/usr/local/libexec/winsvpn/winn3-node", "$AREA/node") + "\nwinn3gw_phase_b\n"
                lines = self.run_shell(script)
                if operation == "adopt-credentials":
                    self.assertIn("tool adopt-credentials /cred fra1-gw9 " + str(self.area / "gateway") + " /unit VIEW ", lines)
                    self.assertLess(lines.index("view"), [i for i, l in enumerate(lines) if l.startswith("tool adopt-credentials")][0])
                else:
                    self.assertNotIn("view", lines)
                self.assertIn("tool " + operation + " /cred fra1-gw9 " + str(self.area / "gateway")
                              + (" /unit " if operation == "adopt-credentials" else ""), "\n".join(lines).replace(self.area.as_posix(), self.area.as_posix()))
                self.assertEqual(sum(1 for l in lines if l.startswith("tool adopt-credentials") or l.startswith("tool credentials")), 1)
                self.assertLess([i for i, l in enumerate(lines) if l.startswith("tool " + operation)][0],
                                lines.index("tool record-node-env /n fra1-gw9 1450 10.10.0.1 10.10.0.0/24"))


class AdoptionShellTests(ShellBase):
    def identity_script(self, tool_body, extra=""):
        function = shell_function("winn3gw_adoption_identity")
        return STUBS + f'''winn3gw_adoption_candidate() {{ return ${{CANDIDATE:-0}}; }}
winn3gw_unit_view() {{ [[ "${{VIEW_FAILS:-0}}" == 0 ]] || return 1; printf VIEW; }}
winn3_node_tool() {{ trace "tool $*"; {tool_body}; }}
WINN3_GATEWAY_CREDENTIALS_DIR=/cred WINN3_GATEWAY_ENV_FILE=/env WINN3_GATEWAY_UNIT_PATH=/unit NODE_ENV_FILE=/node.env
WINN3_GATEWAY_ID="" WINN3_GATEWAY_PATH_MTU="" WINN3_GATEWAY_INNER_V4="" WINN3_GATEWAY_FORWARD_CIDR=""
{extra}''' + function + "\n"

    def test_a_candidate_takes_every_resolved_value_before_defaults_apply(self):
        script = self.identity_script("printf 'fra1-gw9\\n1400\\n10.10.5.1\\n10.10.5.0/24\\n5\\n1\\n'") + '''winn3gw_adoption_identity
printf '%s|%s|%s|%s|%s|%s|%s\\n' "$WINN3_ADOPTION_STATE" "$WINN3_GATEWAY_ID" "$WINN3_GATEWAY_PATH_MTU" "$WINN3_GATEWAY_INNER_V4" \\
  "$WINN3_GATEWAY_FORWARD_CIDR" "$WINN3_INNER_SLICE" "$WINN3_ADOPTION_ASYNC" >> "$TEST_TRACE"
'''
        lines = self.run_shell(script)
        self.assertEqual(lines[0], "tool adopt-identity /cred /etc/winn/public/gateway-identity.json /node.env /env /unit VIEW" + " " * 5)
        self.assertEqual(lines[1], "candidate|fra1-gw9|1400|10.10.5.1|10.10.5.0/24|5|1")
        self.assertIn("Adoption candidate: gateway fra1-gw9, inner router 10.10.5.1, path MTU 1400", self.result.stdout)

    def test_requested_values_are_passed_so_a_changed_identity_can_refuse(self):
        script = self.identity_script("printf 'x\\n1450\\n10.10.0.1\\n10.10.0.0/24\\n0\\n0\\n'",
                                      "WINN3_GATEWAY_ID=req-gw1 WINN3_GATEWAY_PATH_MTU=1300 WINN3_INNER_SLICE=4\n") \
            + "winn3gw_adoption_identity\n"
        lines = self.run_shell(script)
        self.assertEqual(lines[0], "tool adopt-identity /cred /etc/winn/public/gateway-identity.json /node.env /env /unit VIEW req-gw1 1300   4")

    def test_a_live_unit_systemd_cannot_report_refuses_phase_a(self):
        self.run_shell(self.identity_script("exit 99") + "winn3gw_adoption_identity\n", 1, VIEW_FAILS="1")
        self.assertIn("systemd could not report the live gateway unit", self.result.stderr)
        self.assertNotIn("tool adopt-identity", self.trace.read_text())

    def test_a_non_candidate_leaves_every_value_alone(self):
        script = self.identity_script("exit 99", "WINN3_GATEWAY_ID=keep\n") + '''CANDIDATE=1
WINN3_ADOPTION_STATE=candidate
winn3gw_adoption_identity
printf '%s|%s\\n' "$WINN3_ADOPTION_STATE" "$WINN3_GATEWAY_ID" >> "$TEST_TRACE"
'''
        self.assertEqual(self.run_shell(script), ["none|keep"])

    def test_a_refusal_from_the_tool_stops_phase_a_and_a_bad_shape_is_rejected(self):
        self.run_shell(self.identity_script("return 1") + "winn3gw_adoption_identity\n", 1)
        self.run_shell(self.identity_script("printf 'a\\nb\\n'") + "winn3gw_adoption_identity\n", 1)
        self.assertIn("unexpected shape", self.result.stderr)

    def verify_script(self, state, adoption="candidate", env=True, binary=True, asynchronous=0, live="pin", tool="return 0"):
        function = shell_function("winn3gw_adoption_verify")
        if env:
            self.write("env", "X=1\n")
        if binary:
            self.write("gateway", "x")
        return STUBS + f'''winn3_node_tool() {{ trace "tool $1"; {tool}; }}
winn3gw_adoption_candidate() {{ WINN3_ADOPTION_WHY="role is 'x'"; return 1; }}
sha256sum() {{ printf '%s  x\\n' "{'$WINN3_ONETOUCH_BINARY_SHA256' if live == 'pin' else 'f' * 64}"; }}
WINN3_ONETOUCH_BINARY_SHA256=db0c5ba32a7811eabd96c4dfaab392f3e82d515cdb83e5369d73a1570d48aee0
WINN3_GATEWAY_ENV_FILE=$AREA/env WINN3_GATEWAY_INSTALL_PATH=$AREA/gateway WINN3_GATEWAY_CREDENTIALS_DIR=/cred
WINN3_GATEWAY_ID=fra1-gw9 WINN3_GATEWAY_UNIT_PATH=/unit WINN3_ADOPT_KEYDIR=/keys
WINN3_GATEWAY_STAGING_DIR=/stage WINN3_GATEWAY_BIN_NAME=bin WINN3_ADOPTION_UNIT_VIEW=VIEW
WINN3_ADOPTION_STATE={adoption} WINN3_ADOPTION_ASYNC={asynchronous} WINN3_CREDENTIAL_STATE={state}
''' + function + "\nwinn3gw_adoption_verify\n"

    def test_a_standalone_env_without_a_completed_record_never_gets_new_keys(self):
        for state in ("fresh", "legacy", "discard"):
            with self.subTest(state=state):
                self.run_shell(self.verify_script(state, adoption="none"), 1)
                self.assertIn("refusing to create a new identity", self.result.stderr)
        for state in ("complete", "resume"):
            with self.subTest(state=state):
                self.run_shell(self.verify_script(state, adoption="none"), 0)

    def test_a_host_without_a_standalone_env_is_untouched_by_verification(self):
        script = self.verify_script("fresh", adoption="none", env=False).replace('WINN3_GATEWAY_ENV_FILE=$AREA/env', 'WINN3_GATEWAY_ENV_FILE=$AREA/absent')
        self.assertEqual(self.run_shell(script), [])

    def test_a_candidate_proves_its_keys_with_the_read_only_plan(self):
        for state, planned in (("legacy", True), ("fresh", True), ("discard", True), ("complete", False), ("resume", False)):
            with self.subTest(state=state):
                self.trace.write_text("")
                lines = self.run_shell(self.verify_script(state))
                self.assertEqual(lines, ["tool adopt-plan"] if planned else [])
        self.run_shell(self.verify_script("legacy", tool="return 1"), 1)

    def test_the_plan_runs_the_pinned_staged_binary_on_the_live_view(self):
        lines = self.run_shell(self.verify_script("legacy", tool='trace "args $*"'))
        self.assertIn("args adopt-plan /cred fra1-gw9 /stage/bin /unit VIEW /keys", lines)

    def test_a_legacy_set_on_a_host_that_is_not_a_candidate_refuses_in_phase_a(self):
        # Turn 1 Sol 5: phase B's plain install would refuse it after mutation.
        script = self.verify_script("legacy", adoption="none", env=False).replace(
            'WINN3_GATEWAY_ENV_FILE=$AREA/env', 'WINN3_GATEWAY_ENV_FILE=$AREA/absent')
        self.run_shell(script, 1)
        self.assertIn("complete legacy Winn v3 credential set is present but this host is not an adoption candidate",
                      self.result.stderr)
        for state in ("fresh", "complete", "resume", "discard"):
            with self.subTest(state=state):
                self.run_shell(self.verify_script(state, adoption="none", env=False).replace(
                    'WINN3_GATEWAY_ENV_FILE=$AREA/env', 'WINN3_GATEWAY_ENV_FILE=$AREA/absent'), 0)

    def test_a_missing_installed_binary_refuses(self):
        self.run_shell(self.verify_script("complete", binary=False), 1)
        self.assertIn("installed gateway binary", self.result.stderr)

    def test_forward_async_on_an_unreviewed_binary_refuses_and_on_the_reviewed_one_converges_with_a_report(self):
        self.run_shell(self.verify_script("complete", asynchronous=1, live="other"), 1)
        self.assertIn("forward_async is on and the installed binary is not the reviewed one", self.result.stderr)
        self.run_shell(self.verify_script("complete", asynchronous=1, live="pin"), 0)
        self.assertIn("forward-async 1 converges to the derived value 0", self.result.stderr)
        self.run_shell(self.verify_script("complete", asynchronous=0, live="other"), 0)

    def backup_script(self, tool="trace \"tool $*\"; printf 'created %s/backup\\n' \"$AREA\"", candidate=True, stamp=True):
        function = shell_function("winn3gw_adoption_backup").replace("/run/winn3-node.", "$AREA/prog.")
        if stamp:
            self.write("stamp", "sha\ninstaller_path=" + str(self.area / "standalone.sh") + "\nwritten_at=x\n")
        return STUBS + f'''data_plane_installer_path() {{ printf /root/installer.sh; }}
data_plane_installer_sha256() {{ printf '%064d' 1; }}
winn3_node_program() {{ printf 'program\\n'; }}
winn3_node_tool() {{ {tool}; }}
date() {{ printf 20261007T120000Z; }}
WINN3_GATEWAY_UNIT_PATH=/u WINN3_GATEWAY_ENV_FILE=/e WINN3_GATEWAY_INSTALL_PATH=/b WINN3_GATEWAY_CODE_STAMP=$AREA/stamp NODE_ENV_FILE=/n
WINN3_ADOPTION_STATE={'candidate' if candidate else 'none'} WINN3_ADOPTION_BACKUP_DIR=""
''' + function + "\nwinn3gw_adoption_backup\nprintf 'dir=%s\\n' \"${WINN3_ADOPTION_BACKUP_DIR}\" >> \"$TEST_TRACE\"\n"

    def test_the_backup_names_every_path_the_design_lists_and_the_standalone_script(self):
        lines = self.run_shell(self.backup_script())
        words = lines[0].split()
        self.assertEqual(words[:3], ["tool", "adopt-backup", "20261007T120000Z"])
        self.assertEqual(words[4:6], ["/root/installer.sh", "0" * 63 + "1"])
        self.assertEqual(words[6:], ["/u", "/etc/systemd/system/winn3-gateway-firewall.service", "/usr/local/sbin/winn3-gateway-firewall",
                                    "/e", "/b", str(self.area / "stamp"), "/n", "/etc/iptables/rules.v4", "/etc/winsvpn/role",
                                    str(self.area / "standalone.sh")])
        self.assertEqual(lines[1], "dir=" + str(self.area / "backup"))
        self.assertFalse(list(self.area.glob("prog.*")), "the program copy is removed")

    def test_no_stamp_means_no_standalone_script_path_and_a_failed_backup_stops_the_install(self):
        lines = self.run_shell(self.backup_script(stamp=False))
        self.assertNotIn("standalone.sh", lines[0])
        self.run_shell(self.backup_script(tool="return 1"), 1)
        self.assertFalse(list(self.area.glob("prog.*")))

    def test_a_non_candidate_writes_no_backup(self):
        self.assertEqual(self.run_shell(self.backup_script(candidate=False)), ["dir="])

    def test_the_backup_dir_reports_whether_it_reused_an_earlier_one(self):
        script = self.backup_script(tool="printf 'reused %s/old\\n' \"$AREA\"")
        self.run_shell(script)
        self.assertIn("LOG Adoption backup (reused)", self.result.stdout)


class RollbackTests(ShellBase):
    def rollback_script(self, fail=(), active=(), edge=True, admission=True, rules="-A INPUT -j ACCEPT", hub=False,
                        keep_env=False):
        function = shell_function("winn3gw_rollback")
        function = function.replace("/usr/local/bin/wins-edge-hardening", "$AREA/edge").replace("/root/vpn_auth", "$AREA/vpn_auth")
        self.write("cred/static.key", "k")
        self.write("journal/replay.journal", "j")
        self.write("peers.json", "{}")
        self.write("winn3-gateway.env", "WINN3_GATEWAY_ID=x\n")
        if hub:
            (self.area / "vpn_auth").mkdir()
        if edge:
            self.write("edge", '#!/bin/bash\n[[ ! -e "$AREA/winn3-gateway.env" ]] || exit 90\necho "edge" >> "$TEST_TRACE"\n'
                       + ('exit 1\n' if "edge" in fail else ''), 0o755)
        if admission:
            self.write("admission.env", "PUBLIC_VPN_INGRESS_ADMISSION=1\n")
        return STUBS + f'''refuse_retired_winn_protocol_v3_enable() {{ trace refuse_retired; }}
require_root() {{ trace require_root; }}
systemctl() {{ trace "systemctl $*"; [[ "$1" == is-active || "$1" == is-enabled ]] && {{ [[ " {' '.join(active)} " == *" $3 "* ]]; return; }}; return 0; }}
teardown_forwarding_firewall() {{ if [[ -e "$AREA/winn3-gateway.env" ]]; then trace "teardown env=present"; else trace "teardown env=absent"; fi; {'return 1' if 'teardown' in fail else 'true'}; }}
sync() {{ trace "sync $*"; }}
iptables() {{ trace "iptables $*"; printf '%s\\n' '{rules}'; }}
PUBLIC_VPN_INGRESS_ADMISSION_FILE_DEFAULT=$AREA/admission.env
WINN3_GATEWAY_ENV_FILE=$AREA/winn3-gateway.env
''' + function + "\nwinn3gw_rollback\n"

    def test_rollback_runs_the_design_steps_in_order_and_keeps_keys_journal_and_registry(self):
        lines = self.run_shell(self.rollback_script())
        steps = ["refuse_retired", "require_root", "systemctl disable --now winn3-gateway.service winn3-gateway-firewall.service",
                 "systemctl is-active --quiet winn3-gateway.service", "systemctl is-enabled --quiet winn3-gateway.service",
                 "systemctl is-active --quiet winn3-gateway-firewall.service", "systemctl is-enabled --quiet winn3-gateway-firewall.service",
                 "teardown env=present", "sync -f " + str(self.area), "edge", "iptables -w 10 -S"]
        self.assertEqual(lines, steps)
        self.assertFalse((self.area / "winn3-gateway.env").exists())
        for kept in ("cred/static.key", "journal/replay.journal", "peers.json"):
            self.assertTrue((self.area / kept).exists(), kept)
        self.assertIn("a normal rerun restores v3 with the same identity", self.result.stdout)

    def test_every_refusal_that_can_be_checked_up_front_changes_nothing(self):
        for label, kwargs in (("no edge script", {"edge": False}), ("no admission state", {"admission": False}), ("hub", {"hub": True})):
            with self.subTest(label=label):
                self.temp.cleanup()
                self.setUp()
                lines = self.run_shell(self.rollback_script(**kwargs), 1)
                self.assertFalse([l for l in lines if l.startswith("teardown")])
                self.assertFalse([l for l in lines if l.startswith("systemctl")])
                self.assertTrue((self.area / "winn3-gateway.env").exists())

    def test_a_unit_that_stays_active_or_enabled_stops_the_rollback_before_any_firewall_change(self):
        for unit in ("winn3-gateway.service", "winn3-gateway-firewall.service"):
            with self.subTest(unit=unit):
                self.temp.cleanup()
                self.setUp()
                lines = self.run_shell(self.rollback_script(active=(unit,)), 1)
                self.assertFalse([l for l in lines if l.startswith("teardown")])
                self.assertTrue((self.area / "winn3-gateway.env").exists())
                self.assertIn("still active or enabled", self.result.stderr)

    def test_a_failed_teardown_keeps_the_env_file_so_a_rerun_can_finish(self):
        self.run_shell(self.rollback_script(fail=("teardown",)), 1)
        self.assertTrue((self.area / "winn3-gateway.env").exists())

    def test_a_failed_edge_rebuild_and_leftover_9111_rules_are_reported(self):
        self.run_shell(self.rollback_script(fail=("edge",)), 1)
        self.assertIn("edge firewall rebuild failed", self.result.stderr)
        for rules in ("-A WINVPN-INPUT -p udp -m udp --dport 9111 -j ACCEPT", "-N WINN3GW-INPUT"):
            with self.subTest(rules=rules):
                self.trace.write_text("")
                self.run_shell(self.rollback_script(rules=rules), 1)
                self.assertIn("still carries 9111 or WINN3GW rules", self.result.stderr)

    def test_rollback_is_safe_to_run_again(self):
        script = self.rollback_script().replace("\nwinn3gw_rollback\n", "\nwinn3gw_rollback\nwinn3gw_rollback\n")
        lines = self.run_shell(script)
        self.assertEqual([l for l in lines if l.startswith("teardown")], ["teardown env=present", "teardown env=absent"])

    def test_the_rollback_never_touches_credentials_the_journal_or_the_registry(self):
        body = shell_function("winn3gw_rollback")
        for forbidden in ("credentials", "journal", "peers", "rm -rf", "shred", "winn3-peers"):
            self.assertNotIn(forbidden, body.replace("Credentials, replay journal and peer registry were kept", ""))
        self.assertEqual(body.count("rm -f"), 1)

    def test_the_argument_loop_makes_rollback_the_sole_argument_and_ignores_the_environment(self):
        loop = section("WINSVPN_WINN3_ROLLBACK=0\nfor arg in", "\ndone\n")
        loop = "WINSVPN_WINN3_ROLLBACK=0\nfor arg in" + loop + "\ndone\n"
        harness = STUBS + 'main_args() {\n' + loop + '\n}\n'
        for args, rc, expect in ((["--winn3-rollback"], 0, "1"), (["--winn3-rollback", "--preflight"], 2, None),
                                 (["--preflight", "--winn3-rollback"], 2, None), (["--preflight"], 0, "0"), ([], 0, "0")):
            with self.subTest(args=args):
                script = harness + "( main_args " + " ".join(args) + ' ; printf "%s\\n" "$WINSVPN_WINN3_ROLLBACK" >> "$TEST_TRACE" )\n'
                self.trace.write_text("")
                lines = self.run_shell(script, rc, WINSVPN_WINN3_ROLLBACK="1")
                if expect is not None:
                    self.assertEqual(lines, [expect])
                else:
                    self.assertIn("must be the sole argument", self.result.stderr)

    def test_dispatch_reaches_rollback_only_through_the_guarded_variable_and_help_names_the_mode(self):
        self.assertRegex(SOURCE, r'(?s)if \[\[ "\$\{BASH_SOURCE\[0\]\}" == "\$0" \]\]; then\n  if \[\[ "\$\{WINSVPN_WINN3_ROLLBACK:-0\}" == "1" \]\]; then\n    winn3gw_rollback\n  else\n    main "\$@"\n  fi\nfi\n$')
        self.assertIn("--winn3-rollback is an explicit recovery mode", SOURCE)
        self.assertEqual(SOURCE.count("|--winn3-rollback|--self-test-xray-pin]"), 2)

    def test_the_early_swap_guard_and_main_pin_are_unchanged_by_the_new_mode(self):
        self.assertIn('wins_early_plaintext_swap_guard "$@"', SOURCE)
        self.assertIn("  refuse_retired_winn_protocol_v3_enable\n  require_root\n  preflight_data_plane", shell_function("main"))


# ---------------------------------------------------------------------------
# The real standalone installer's own output is what adoption must read
# ---------------------------------------------------------------------------

class RealStandaloneInstallerTests(AdoptionBase):
    # Slice S6 made the standalone installer a tombstone. Its pre-tombstone text,
    # byte-identical to the file these tests were written against (sha256
    # 34230892...), is the frozen copy S3 and S6 prove the move against.
    INSTALLER = s4.ROOT / "server/testdata/winn3_gateway_install_retired/wins_winn3_gateway_install.sh.snapshot"

    def render(self, function, **overrides):
        values = {"PATH": "/usr/bin:/bin:/sbin", "LC_ALL": "C",
                  "WINN3_GATEWAY_MEMINFO": str(s4.ROOT / "server/testdata/winn3_gateway_meminfo/large"),
                  "WINN3_GATEWAY_ID": "fra1-gw9", "WINN3_GATEWAY_PATH_MTU": "1450", "WINN3_GATEWAY_INNER_V4": "10.10.3.1",
                  "WINN3_GATEWAY_FORWARD": "1", "WINN3_GATEWAY_RESOLVER": "1", "WINN3_GATEWAY_FORWARD_CIDR": "10.10.3.0/24",
                  "WINN3_GATEWAY_PLAN": "udp",
                  "WINN3_STATIC_KEY_PATH": str(self.cred / "winn3-gateway-static.key"),
                  "WINN3_ADMISSION_KEY_PATH": str(self.cred / "winn3-gateway-admission.key"),
                  "WINN3_GATEWAY_DUAL_AUTH_ED_KEY": str(self.cred / "winn3-gateway-auth-ed25519.seed"),
                  "WINN3_GATEWAY_DUAL_AUTH_ML_SEED": str(self.cred / "winn3-gateway-auth-mldsa65.seed")}
        values.update(overrides)
        result = subprocess.run([BASH, "-c", "source " + shlex.quote(str(self.INSTALLER)) + "; " + function],
                                env=values, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def lay_down(self, **overrides):
        self.make_keys()
        for name, legacy in self.LEGACY.items():
            self.write(self.cred / legacy, self.bodies[name], 0o600)
        self.write(self.unit, self.render("emit_unit_text", **overrides), 0o644)
        self.write(self.env, self.render("emit_env_text", **overrides), 0o600)

    def test_the_identity_the_standalone_installer_wrote_is_the_identity_adopted(self):
        self.lay_down()
        resolved, asynchronous, flags, env = NODE.adoption_identity(self.cred, self.public_identity, self.node_env, self.env,
                                                                    self.unit, {})
        self.assertEqual(resolved, {"gateway_id": "fra1-gw9", "path_mtu": "1450", "inner_v4": "10.10.3.1",
                                    "forward_cidr": "10.10.3.0/24", "slice": "3"})
        self.assertFalse(asynchronous)
        self.assertEqual(flags["plan"], "udp")

    def test_forward_async_baked_into_the_real_unit_is_detected(self):
        self.lay_down(WINN3_GATEWAY_FORWARD_ASYNC="1")
        self.assertTrue(NODE.adoption_identity(self.cred, self.public_identity, self.node_env, self.env, self.unit, {})[1])

    def test_the_real_unit_names_the_key_files_adoption_copies(self):
        self.lay_down()
        sources = self.store().legacy_sources(self.unit)
        self.assertEqual(sources, {name: self.cred / legacy for name, legacy in self.LEGACY.items()})
        with self.fake_binary():
            self.assertEqual(self.store().adopt("fixture-binary", self.unit), "derive-public")
        self.assertEqual(self.store().classify(), "complete")
        record = json.loads((self.cred / "winn3-identity.complete").read_bytes())
        self.assertEqual(record["gateway_id"], "fra1-gw9")

    def test_an_env_file_edited_after_the_unit_was_baked_is_a_path_mtu_conflict(self):
        self.lay_down()
        self.write(self.env, self.env.read_text().replace("WINN3_GATEWAY_PATH_MTU=1450", "WINN3_GATEWAY_PATH_MTU=1400"), 0o600)
        with self.assertRaisesRegex(NODE.Refusal, "identity conflict: path_mtu"):
            NODE.adoption_identity(self.cred, self.public_identity, self.node_env, self.env, self.unit, {})

    def test_a_reflector_node_without_forwarding_still_adopts_to_a_slice(self):
        self.lay_down(WINN3_GATEWAY_FORWARD="0", WINN3_GATEWAY_RESOLVER="0", WINN3_GATEWAY_INNER_V4="10.10.0.1",
                      WINN3_GATEWAY_FORWARD_CIDR="")
        resolved = NODE.adoption_identity(self.cred, self.public_identity, self.node_env, self.env, self.unit, {})[0]
        self.assertEqual((resolved["slice"], resolved["forward_cidr"]), ("0", "10.10.0.0/24"))


class OperationWiringTests(AdoptionBase):
    def test_backup_and_restore_operations_pass_their_arguments_through(self):
        recorded = []
        with patch.object(NODE, "adopt_backup", lambda *a, **k: recorded.append((a, k)) or (self.area / "d", True)):
            self.assertEqual(self.node("adopt-backup", "20261007T120000Z", "/p", "/i.sh", "a" * 64, "/x", "/y"), "reused " + str(self.area / "d") + "\n")
        self.assertEqual(recorded[0][0], ("20261007T120000Z", "/p", ["/x", "/y"], {"path": "/i.sh", "sha256": "a" * 64}))
        with patch.object(NODE, "adopt_restore", lambda *a, **k: recorded.append(a)):
            self.node("adopt-restore", "/dir")
        self.assertEqual(recorded[-1], ("/dir",))

    def test_unknown_operations_and_refusals_exit_nonzero_from_the_program(self):
        program = self.area / "program.py"
        program.write_text(embedded("WINS_S4_NODE_PY"))
        result = subprocess.run([sys.executable, "-I", str(program), "no-such-operation"], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertIn("winn3 node: unknown node operation", result.stderr)

    def test_data_winn3_is_rewritten_to_data_cover_by_the_existing_role_step_and_restored_from_the_backup(self):
        role = self.area / "etc/winsvpn/role"
        self.write(role, "data-winn3\n", 0o600)
        parent = self.area / "var/backups"
        parent.mkdir(parents=True)
        program = self.write(self.area / "program.py", "x\n", 0o600)
        directory, _ = NODE.adopt_backup("20261007T120000Z", str(program), [str(role)], {"path": "", "sha256": ""},
                                         parent=str(parent / "winsvpn"), run=lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="x\n"))
        function = shell_function("mark_data_role").replace("/etc/winsvpn", str(self.area / "etc/winsvpn"))
        result = subprocess.run([BASH, "-c", "NODE_DEPLOYMENT_READY_FILE_DEFAULT=" + shlex.quote(str(self.area / "ready")) + "\n" + function + "\nmark_data_role"],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(role.read_text(), "data-cover\n")
        NODE.adopt_restore(directory, run=lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=""))
        self.assertEqual(role.read_text(), "data-winn3\n")


if __name__ == "__main__":
    unittest.main()
