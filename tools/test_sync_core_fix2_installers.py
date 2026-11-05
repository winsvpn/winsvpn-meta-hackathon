"""IA-SYNC fix wave 2, lane sync_core: installer-side regressions.

SYNC-02: the Core's wins-core-sync agent renders each hub-managed corexN from
the EXIT's AmneziaWG profile carried in the assignment, and reports its own
core0 profile to the hub. SYNC-10: the data plane's heartbeat oneshot has a
start timeout. The generated shell is extracted from the installers and run
under bash 4+ with stubs for docker and ip; nothing touches a real host.
"""
from pathlib import Path
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh"
DATA = ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh"

KEYS = ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4")
EXIT_PROFILE = {
    "Jc": 5, "Jmin": 40, "Jmax": 70, "S1": 37, "S2": 91, "S3": 16, "S4": 0,
    "H1": 1034567891, "H2": "2000000000-2000000999", "H3": 3100000000, "H4": 4200000000,
}
LOCAL_PROFILE = {
    "Jc": "2", "Jmin": "10", "Jmax": "30", "S1": "16", "S2": "80", "S3": "16", "S4": "0",
    "H1": "11", "H2": "22", "H3": "33", "H4": "44",
}


def modern_bash() -> str:
    for candidate in (shutil.which("bash"), "/opt/homebrew/bin/bash", "/usr/local/bin/bash", "/bin/bash"):
        if not candidate:
            continue
        probe = subprocess.run([candidate, "-c", 'printf %s "${BASH_VERSINFO[0]}"'],
                               text=True, capture_output=True)
        if probe.returncode == 0 and probe.stdout.isdigit() and int(probe.stdout) >= 4:
            return candidate
    raise AssertionError("bash 4 or newer is required (associative arrays)")


def sync_agent() -> str:
    text = CORE.read_text(encoding="utf-8")
    start = text.index("cat > \"${sync_tmp}\" <<'EOF'\n") + len("cat > \"${sync_tmp}\" <<'EOF'\n")
    return text[start:text.index("\nEOF\n", start)] + "\n"


def function(source: str, name: str) -> str:
    match = re.search(rf"(?m)^{re.escape(name)}\(\) [{{(]\n", source)
    if not match:
        raise AssertionError(f"function {name} not found")
    end = re.compile(r"(?m)^[})]\n").search(source, match.end())
    return source[match.start():end.end()]


def node_register_service() -> str:
    text = DATA.read_text(encoding="utf-8")
    start = text.index("cat > /etc/systemd/system/wins-node-register.service <<'EOF'\n")
    start = text.index("\n", start) + 1
    return text[start:text.index("\nEOF\n", start)] + "\n"


class CoreExitProfileTests(unittest.TestCase):
    """ensure_exit_iface renders the exit's profile, and only falls back when absent."""

    def setUp(self):
        self.bash = modern_bash()
        self.tmp = Path(tempfile.mkdtemp(prefix="synccore-exit-"))
        agent = sync_agent()
        names = ("valid_iface_name", "write_exit_transport_state", "remove_exit_container_if_present",
                 "valid_awg_obfuscation_value", "ensure_exit_iface")
        self.functions = "\n".join(function(agent, name) for name in names)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_ensure(self, item: dict) -> subprocess.CompletedProcess:
        state = self.tmp / "state"
        script = "\n".join([
            "set -Eeuo pipefail",
            "declare -A ENSURED_EXIT_IFACES=()",
            "warn() { printf '[WARN] %s\\n' \"$*\" >&2; }",
            "log() { :; }",
            "docker() { if [[ \"$1\" == ps ]]; then printf '%s\\n' \"wins-core-exit-${ITEM_IFACE}\"; fi; return 0; }",
            "ip() { return 0; }",
            "select_awg_image() { printf 'image'; }",
            f"CORE_SYNC_STATE_DIR={json.dumps(str(state))}",
            "CORE_EXIT_IFACE_PREFIX=corex CORE_EXIT_TRANSPORT_MODE=direct CORE_EXIT_DIRECT_GRACE_SECONDS=20",
            "CORE_EXIT_XRAY_LOCAL_PORT_BASE=43000 CORE_AWG_MTU=1280 CORE_EXIT_PRIVATE_KEY=exit-private-key",
            "AWG_JC=2 AWG_JMIN=10 AWG_JMAX=30 AWG_S1=16 AWG_S2=80 AWG_S3=16 AWG_S4=0",
            "AWG_H1=11 AWG_H2=22 AWG_H3=33 AWG_H4=44",
            self.functions,
            'ITEM_IFACE="$(jq -r .iface <<<"$1")"',
            'ensure_exit_iface "$1"',
        ])
        return subprocess.run([self.bash, "-c", script, "harness", json.dumps(item)],
                              text=True, capture_output=True, timeout=60)

    def item(self, **overrides) -> dict:
        base = {
            "iface": "corex3", "table_id": 52003, "core_exit_ip": "10.8.255.5",
            "exit_public_key": "E" * 43 + "=", "exit_endpoint": "203.0.113.9:9110",
            "exit_direct_awg_enabled": True, "exit_stealth_endpoint": "",
            "exit_obfuscation": dict(EXIT_PROFILE),
        }
        base.update(overrides)
        return base

    def rendered(self) -> dict:
        conf = (self.tmp / "state" / "corex3.conf").read_text(encoding="utf-8")
        interface = conf.split("[Peer]", 1)[0]
        values = {}
        for line in interface.splitlines():
            key, sep, value = line.partition(" = ")
            if sep and key in KEYS:
                values[key] = value
        return values

    def test_corex_renders_the_exit_profile_not_the_local_one(self):
        result = self.run_ensure(self.item())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.rendered(), {key: str(value) for key, value in EXIT_PROFILE.items()})

    def test_widest_legal_range_is_accepted(self):
        result = self.run_ensure(self.item(exit_obfuscation=dict(EXIT_PROFILE, H4="0-4294967294")))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.rendered()["H4"], "0-4294967294")

    def test_changed_exit_profile_rerenders_the_config(self):
        self.assertEqual(self.run_ensure(self.item()).returncode, 0)
        changed = dict(EXIT_PROFILE, H1=77, S1=41)
        result = self.run_ensure(self.item(exit_obfuscation=changed))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.rendered()["H1"], "77")
        self.assertEqual(self.rendered()["S1"], "41")

    def test_older_hub_without_profile_falls_back_to_local_values(self):
        item = self.item()
        del item["exit_obfuscation"]
        result = self.run_ensure(item)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.rendered(), LOCAL_PROFILE)

    def test_unusable_exit_profile_fails_closed_and_writes_nothing(self):
        bad_profiles = {
            "null": None,
            "list": [1, 2],
            "missing-key": {k: v for k, v in EXIT_PROFILE.items() if k != "S2"},
            "null-value": dict(EXIT_PROFILE, S1=None),
            "newline-injection": dict(EXIT_PROFILE, H1="11\nPostUp = touch /tmp/pwned"),
            "last-key-newline": dict(EXIT_PROFILE, H4="44\nPostUp = touch /tmp/pwned"),
            "space-injection": dict(EXIT_PROFILE, Jc="2 3"),
            "trailing-space": dict(EXIT_PROFILE, H4="44 "),
            "negative": dict(EXIT_PROFILE, S1=-1),
            "fraction": dict(EXIT_PROFILE, S1=1.5),
            "over-uint32": dict(EXIT_PROFILE, H3=4294967296),
            "range-on-scalar": dict(EXIT_PROFILE, S1="10-20"),
            "inverted-range": dict(EXIT_PROFILE, H2="900-100"),
            "range-over-uint32": dict(EXIT_PROFILE, H4="1-4294967296"),
            "range-full-keyspace": dict(EXIT_PROFILE, H4="0-4294967295"),
            "range-end-over-uint32": dict(EXIT_PROFILE, H4="4294967290-4294967296"),
            "bool": dict(EXIT_PROFILE, Jc=True),
        }
        for name, profile in bad_profiles.items():
            with self.subTest(name=name):
                shutil.rmtree(self.tmp / "state", ignore_errors=True)
                result = self.run_ensure(self.item(exit_obfuscation=profile))
                self.assertNotEqual(result.returncode, 0, name)
                self.assertIn("class=exit_obfuscation_invalid", result.stderr)
                self.assertFalse((self.tmp / "state" / "corex3.conf").exists())
                self.assertNotIn("11\nPostUp", result.stderr)


class CoreIngressProfileReportTests(unittest.TestCase):
    """The Core reports what its core0 ingress config actually carries."""

    def setUp(self):
        self.bash = modern_bash()
        self.tmp = Path(tempfile.mkdtemp(prefix="synccore-ingress-"))
        agent = sync_agent()
        self.functions = "\n".join(function(agent, name) for name in (
            "core_ingress_obfuscation_json", "core_registration_payload_with_obfuscation"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def render_ingress_conf(self, profile: dict) -> Path:
        # Render with the installer's own install_awg_ingress heredoc.
        text = CORE.read_text(encoding="utf-8")
        start = text.index('cat > "/etc/amnezia/wins-core/${CORE_INGRESS_IFACE}.conf" <<EOF\n')
        start = text.index("\n", start) + 1
        body = text[start:text.index("\nEOF\n", start)]
        conf = self.tmp / "core0.conf"
        env = dict(os.environ, CORE_INGRESS_ADDR="10.9.1.1/16", CORE_INGRESS_PORT="9210",
                   CORE_INGRESS_PRIVATE_KEY="ingress-private-key", CORE_AWG_MTU="1280",
                   **{f"AWG_{k.upper()}": str(v) for k, v in profile.items()})
        rendered = subprocess.run([self.bash, "-c", f"cat <<EOF\n{body}\nEOF"], env=env,
                                  text=True, capture_output=True, check=True).stdout
        conf.write_text(rendered + "\n[Peer]\nPublicKey = peer\nH1 = 999\n", encoding="utf-8")
        return conf

    def run_payload(self, conf: str) -> subprocess.CompletedProcess:
        script = "\n".join([
            "set -Eeuo pipefail",
            "warn() { printf '[WARN] %s\\n' \"$*\" >&2; }",
            "CORE_INGRESS_IFACE=core0",
            f"CORE_INGRESS_CONF_FILE={json.dumps(conf)}",
            self.functions,
            "core_registration_payload_with_obfuscation jq -n --arg core_id c1 '{core_id:$core_id,status:\"online\"}'",
        ])
        return subprocess.run([self.bash, "-c", script], text=True, capture_output=True, timeout=60)

    def test_payload_carries_core0_profile_as_rendered(self):
        profile = dict(EXIT_PROFILE)
        conf = self.render_ingress_conf(profile)
        result = self.run_payload(str(conf))
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["core_id"], "c1")
        self.assertEqual(json.loads(payload["obfuscation_json"]),
                         {k: str(v) for k, v in profile.items()})

    def test_unreadable_or_incomplete_profile_is_omitted_not_defaulted(self):
        conf = self.render_ingress_conf(dict(EXIT_PROFILE))
        broken = self.tmp / "broken.conf"
        broken.write_text(conf.read_text().replace("S2 = 91\n", ""), encoding="utf-8")
        link = self.tmp / "link.conf"
        link.symlink_to(conf)
        for path in (str(self.tmp / "absent.conf"), str(broken), str(link)):
            with self.subTest(path=Path(path).name):
                result = self.run_payload(path)
                self.assertEqual(result.returncode, 0, result.stderr)
                payload = json.loads(result.stdout)
                self.assertNotIn("obfuscation_json", payload)
                self.assertIn("registering without it", result.stderr)

    def test_register_core_builds_its_payload_through_the_wrapper(self):
        body = function(sync_agent(), "register_core")
        # Env assignments may prefix the call (lane_core_b passes the Xray UUID
        # to jq through WINS_CORE_XRAY_UUID); the builder must still be jq -n
        # run through the wrapper.
        self.assertRegex(
            body, r'(?m)^  payload="\$\((?:[A-Z_][A-Z0-9_]*="[^"]*" )*'
                  r'core_registration_payload_with_obfuscation jq -n \\$')


def register_script() -> str:
    text = DATA.read_text(encoding="utf-8")
    start = text.index("cat > /usr/local/bin/wins-node-register <<'EOF'\n")
    start = text.index("\n", start) + 1
    return text[start:text.index("\nEOF\n", start)] + "\n"


def installer_function(name: str) -> str:
    return function(DATA.read_text(encoding="utf-8"), name)


class NodeRuntimeIdentityTests(unittest.TestCase):
    """SYNC-18: the node names its AWG runtime on every resync request, and hands
    it only to the invocation that asked for it (round 3, N-5)."""

    def setUp(self):
        self.bash = modern_bash()
        self.tmp = Path(tempfile.mkdtemp(prefix="synccore-identity-"))
        self.rundir = self.tmp / "run"
        tail = register_script()
        tail = tail[tail.index('peer_runtime_dir="/run/winsvpn"'):]
        self.tail = tail.replace('"/run/winsvpn"', json.dumps(str(self.rundir)))
        self.assertNotIn("/run/winsvpn", self.tail)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_tail(self, identity_container="amnezia-awg2", started="2026-09-30T01:02:03.456789Z",
                 marker=None, answer='{"ok": true, "failed": 0}', url_env=None, identity_out=None):
        if marker is not None:
            self.rundir.mkdir(parents=True, exist_ok=True)
            (self.rundir / "node-peer-runtime").write_text(marker + "\n")
        record = self.tmp / "curl.stdin"
        script = "\n".join([
            "set -Eeuo pipefail",
            f"curl() {{ cat > {json.dumps(str(record))}; printf '%s' {json.dumps(answer)}; }}",
            # Name resolution always succeeds here. A later lane (sync_dp) waits
            # for the hub host before the resync with a helper defined above
            # this tail; stand it in, and record what it was asked to resolve
            # so the identity query can be shown not to reach resolution.
            f"wait_for_hub_host() {{ printf '%s\\n' \"$*\" >> {json.dumps(str(self.tmp / 'getent.log'))}; return 0; }}",
            f"active_awg_container={json.dumps(identity_container)}",
            f"container_started_at={json.dumps(started)}",
            "peer_count=3 NODE_TOKEN=node-token NODE_SLUG=node-a HUB_API_BASE=https://hub.example.test",
            (f"HUB_NODE_RESYNC_PEERS_URL={json.dumps(url_env)}" if url_env else "unset HUB_NODE_RESYNC_PEERS_URL"),
            (f"export WINS_NODE_REGISTER_IDENTITY_OUT={json.dumps(str(identity_out))}" if identity_out
             else "unset WINS_NODE_REGISTER_IDENTITY_OUT"),
            self.tail,
        ])
        result = subprocess.run([self.bash, "-c", script], text=True, capture_output=True, timeout=60)
        sent = record.read_text() if record.exists() else ""
        return result, sent

    def written_files(self):
        return sorted(str(path.relative_to(self.tmp)) for path in self.tmp.rglob("*") if path.is_file())

    def test_request_names_the_runtime_and_the_marker_follows_success(self):
        result, sent = self.run_tail()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('url = "https://hub.example.test/api/v1/nodes/node-a/resync-peers'
                      '?runtime_identity=amnezia-awg2%3A2026-09-30T01%3A02%3A03.456789Z"', sent)
        self.assertIn('header = "x-node-token: node-token"', sent)
        resolved = (self.tmp / "getent.log").read_text() if (self.tmp / "getent.log").exists() else ""
        for line in resolved.splitlines():
            self.assertTrue(line.startswith("https://hub.example.test/"), line)
        identity = "amnezia-awg2:2026-09-30T01:02:03.456789Z"
        self.assertEqual((self.rundir / "node-peer-runtime").read_text(), identity + "\n")

    def test_configured_url_with_a_query_gets_an_ampersand(self):
        result, sent = self.run_tail(url_env="https://h.example.test/r?x=1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('url = "https://h.example.test/r?x=1&runtime_identity=', sent)

    def test_identity_is_handed_only_to_the_invocation_that_asked(self):
        identity = "amnezia-awg2:2026-09-30T01:02:03.456789Z"
        out = self.tmp / "mine.identity"
        result, sent = self.run_tail(marker=identity, identity_out=out)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sent, "")
        self.assertEqual(out.read_text(), identity + "\n")

    def test_a_timer_run_writes_no_shared_identity_file(self):
        # N-5: an overlapping timer run must have nowhere to put its identity
        # that the installer's check could read.
        result, _ = self.run_tail(marker="amnezia-awg2:2026-09-30T01:02:03.456789Z")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.written_files(), ["run/node-peer-runtime"])
        self.assertNotIn("node-peer-runtime.current", register_script())

    def test_failed_resync_writes_no_marker(self):
        result, sent = self.run_tail(answer='{"ok": false, "failed": 2}')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("runtime_identity=", sent)
        self.assertFalse((self.rundir / "node-peer-runtime").exists())


class InstallTimeVerifyTests(unittest.TestCase):
    """OI-SYNC_CORE-5, N-1, OI-6 and N-5: the install-time check is bounded,
    joins a running pass, demands a pass that started after it began, and uses
    only the identity its own register run produced."""

    IDENTITY = "amnezia-awg2:2026-09-30T01:02:03Z"

    def setUp(self):
        self.bash = modern_bash()
        self.tmp = Path(tempfile.mkdtemp(prefix="synccore-verify-"))
        self.body = installer_function("verify_hub_node_management")
        self.assertNotIn("/run/winsvpn/", self.body)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_verify(self, register="own", answers=('{"ok": true}',), arg="fresh"):
        """register: "own" writes this run's identity to the file the check
        named; "none" writes nothing (a run that exits early); "overlap" also
        lets a concurrent older run write old-A everywhere it can reach."""
        log = self.tmp / "calls.log"
        answers_file = self.tmp / "answers"
        answers_file.write_text("\n".join(answers) + "\n")
        shared = self.tmp / "shared-run"
        shared.mkdir(exist_ok=True)
        steps = [f"printf 'timeout %s out=%s\\n' \"$*\" \"${{WINS_NODE_REGISTER_IDENTITY_OUT:-}}\" >> {json.dumps(str(log))}"]
        if register in ("own", "overlap"):
            steps.append(f"printf '%s\\n' {json.dumps(self.IDENTITY)} > \"${{WINS_NODE_REGISTER_IDENTITY_OUT}}\"")
        if register == "overlap":
            # An older timer invocation finishing after this one: it has no
            # WINS_NODE_REGISTER_IDENTITY_OUT, so all it can do is write shared
            # places, which the check must never read.
            steps.append(f"printf '%s\\n' old-awg:2026-09-01T00:00:00Z > {json.dumps(str(shared / 'node-peer-runtime.current'))}")
        script = "\n".join([
            "set -Eeuo pipefail",
            "log() { :; }", "warn() { :; }", "err() { printf '%s\\n' \"$*\" >&2; }",
            "sleep() { :; }",
            "timeout() { " + "; ".join(steps) + "; }",
            # Keep the check's temp files inside this test's directory (macOS
            # mktemp ignores TMPDIR), so a mutant that leaks one leaks it here.
            f"mktemp() {{ command mktemp {json.dumps(str(self.tmp))}/identity.XXXXXX; }}",
            f"curl() {{ printf 'curl %s\\n' \"$*\" >> {json.dumps(str(log))}; "
            f"sed -n 's/^url = \\(.*\\)$/url \\1/p' >> {json.dumps(str(log))}; "
            f"head -n 1 {json.dumps(str(answers_file))}; sed -i.bak 1d {json.dumps(str(answers_file))}; }}",
            "NODE_TOKEN=node-token NODE_SLUG=node-a HUB_API_BASE=https://hub.example.test",
            "unset HUB_NODE_RESYNC_PEERS_URL",
            self.body,
            f"verify_hub_node_management {arg}",
        ])
        result = subprocess.run([self.bash, "-c", script], text=True, capture_output=True, timeout=60)
        return result, log.read_text() if log.exists() else ""

    def urls(self, calls):
        return [line[4:] for line in calls.splitlines() if line.startswith("url ")]

    def test_register_run_and_resync_request_are_both_bounded(self):
        result, calls = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("timeout --kill-after=10 300 /usr/local/bin/wins-node-register", calls)
        curl_line = next(line for line in calls.splitlines() if line.startswith("curl "))
        self.assertIn("--connect-timeout 10", curl_line)
        self.assertIn("--max-time 100", curl_line)
        self.assertRegex(self.urls(calls)[0],
                         r'^"https://hub\.example\.test/api/v1/nodes/node-a/resync-peers'
                         r'\?fresh=[0-9a-f]{32}&runtime_identity=amnezia-awg2%3A2026-09-30T01%3A02%3A03Z"$')

    def test_one_fresh_token_for_the_whole_check_and_a_new_one_per_check(self):
        result, calls = self.run_verify(answers=("", "", '{"ok": true}'))
        self.assertEqual(result.returncode, 0, result.stderr)
        tokens = {re.search(r"fresh=([0-9a-f]{32})", url).group(1) for url in self.urls(calls)}
        self.assertEqual(len(self.urls(calls)), 3)
        self.assertEqual(len(tokens), 1)
        (self.tmp / "calls.log").unlink()
        result, calls2 = self.run_verify()
        token2 = re.search(r"fresh=([0-9a-f]{32})", self.urls(calls2)[0]).group(1)
        self.assertNotIn(token2, tokens)

    def test_check_before_hardening_sends_no_fresh_token(self):
        # Seat C N-7: a token would make the first check wait out the register
        # service's pass and then run a second one.
        result, calls = self.run_verify(arg="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.urls(calls),
                         ['"https://hub.example.test/api/v1/nodes/node-a/resync-peers'
                          '?runtime_identity=amnezia-awg2%3A2026-09-30T01%3A02%3A03Z"'])

    def test_only_the_check_after_hardening_asks_for_a_fresh_pass(self):
        text = DATA.read_text(encoding="utf-8")
        calls = re.findall(r"(?m)^  verify_hub_node_management( fresh)?$", text)
        self.assertEqual(calls, ["", " fresh"])
        harden = text.index("\n  harden_sshd\n  verify_hub_node_management fresh\n")
        first = text.index("\n  verify_hub_node_management\n")
        self.assertLess(first, harden)

    def test_identity_comes_only_from_this_run(self):
        result, calls = self.run_verify(register="overlap")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("old-awg", calls)
        self.assertIn("runtime_identity=amnezia-awg2%3A2026-09-30T01%3A02%3A03Z", calls)
        (self.tmp / "calls.log").unlink()
        result, calls = self.run_verify(register="none")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("runtime_identity=", "\n".join(self.urls(calls)))

    def test_each_attempt_gets_its_own_identity_file_and_removes_it(self):
        result, calls = self.run_verify(answers=("", '{"ok": true}'))
        self.assertEqual(result.returncode, 0, result.stderr)
        outs = re.findall(r"out=(\S+)", calls)
        self.assertEqual(len(outs), 2)
        self.assertEqual(len(set(outs)), 2)
        for out in outs:
            self.assertFalse(Path(out).exists(), out)

    def test_busy_hub_is_retried_and_success_ends_the_loop(self):
        result, calls = self.run_verify(answers=("", "", '{"ok": true}', '{"ok": true}'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls.count("timeout --kill-after=10 300"), 3)

    def test_verify_waits_longer_than_the_hub_join_window(self):
        # The hub holds a joining request up to PEER_RESYNC_JOIN_WAIT_SECONDS
        # (75 s); the check's request must outlive that, under Cloudflare's 125 s.
        hub = (ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh").read_text(encoding="utf-8")
        join = float(re.search(r"(?m)^PEER_RESYNC_JOIN_WAIT_SECONDS = ([0-9.]+)$", hub).group(1))
        body = installer_function("verify_hub_node_management")
        limit = int(re.search(r"--max-time ([0-9]+) --config -", body).group(1))
        self.assertGreater(limit, join + 10)
        self.assertLess(limit, 125)
        node = register_script()
        node_limit = int(re.search(r"--max-time ([0-9]+) --config - 2>/dev/null \|\| true\)\"\n    if jq", node).group(1))
        self.assertGreater(node_limit, join)


class NodeHeartbeatTimeoutTests(unittest.TestCase):
    """SYNC-10: the heartbeat oneshot cannot wedge the timer forever."""

    def test_register_oneshot_has_a_bounded_start_timeout(self):
        unit = node_register_service()
        service = unit.split("[Service]", 1)[1]
        self.assertIn("Type=oneshot", service)
        values = re.findall(r"(?m)^TimeoutStartSec=(\S+)$", service)
        self.assertEqual(len(values), 1, unit)
        self.assertRegex(values[0], r"^[0-9]+$")
        seconds = int(values[0])
        # Above the slowest pass that still makes progress (40 s key wait,
        # two 30 s registration attempts, 12 s key pull, 90 s self-resync),
        # and below NODE_HEARTBEAT_STALE_SECONDS (600) minus one 120 s tick.
        self.assertGreaterEqual(seconds, 40 + 2 * 30 + 2 * 12 + 90)
        self.assertLess(seconds, 600 - 120)

    def test_timeout_budget_matches_the_script_it_bounds(self):
        text = DATA.read_text(encoding="utf-8")
        start = text.index("cat > /usr/local/bin/wins-node-register <<'EOF'\n")
        script = text[start:text.index("\nEOF\n", start)]
        self.assertIn("--max-time 90 --config -", script)
        self.assertIn("--max-time 12 --config -", script)
        self.assertEqual(script.count("--max-time 12 --config -"), 1)
        # Two pubkey URLs at 12 s each: 24 s in the budget above.
        self.assertIn('for url in "${HUB_PUBKEY_URL:-}" "${HUB_API_BASE:+${HUB_API_BASE%/}/api/v1/pubkey}"; do', script)
        self.assertIn("for _ in $(seq 1 20); do", script)
        self.assertIn("OnUnitActiveSec=120s", text)


if __name__ == "__main__":
    unittest.main()
