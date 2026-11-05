#!/usr/bin/env python3
"""Round HV F2 on the repo lineage (lane L57 port of lane L46's test_hub_offnode.py).

L46 F2 local test (v3, Round HV turn 3): an operator-off node gets no peers and
loses existing access, including its Core exit peer, in every node status; a resync
that races a closure cannot restore a peer; promotion and retirement need a confirmed
cleanup record AND a node-side gate record the hub verified itself.

What the port changes, and only this (every L46 assertion is kept):
  * the hub is the repo control installer's app, extracted from its
    `cat > "${APP_DIR}/main.py" <<'PYEOF'` heredoc (or a main.py given directly);
  * registry publication is NOT stubbed. The repo's real
    sync_winn3_registry_to_node runs: it records the publication in the Round O
    authority ledger before the remote write and settles it after, and its real
    remote shell command is executed by bash against a scratch /etc/winn per
    node (getent, install, chown and flock shimmed, as in
    server/test_winn3_departure_grace_hub.py). PUBLISHED is read from the file
    that landed. "publish_ok False" is an unreachable node (ssh exit 255). Any
    other remote command fails without running; nothing contacts a host;
  * checks added for the repo lineage (L57-A: departure grants, decision (a);
    L57-B: the authority ledger, decision (b)); R2b hashes the landed bytes.

Harness shape from lanes L42/L45 (temporary SQLite, TestClient, no startup hook,
network guard, random never-printed credentials, documentation-range
endpoints). Node I/O is replaced after import with recorders:
  sync_peer_to_node            records (host, AWG key) pushes
  sync_winn3_registry_to_node  BUILDS the real snapshot with the module's own
                               winn3_peer_registry_document() and records the
                               static keys it would publish (so the published
                               content is the code under test, not a stub)
  remove_peer_from_node        records (host, AWG key) removals; can be set to fail
France here is a winn/3 node (protocol_version 'winn/3') with preassigned
devices that each hold an AWG peer and a v3 static identity, plus a Double VPN
assignment through it and the single canary binding configured for it.

Usage: tools/test_hub_offnode_f2.py [installer.sh | main.py] [label]
Default: server/wins_control_plane_setup_ONETOUCH.sh. Asserts the REPAIRED
behaviour; an installer without the F2 port is expected to exit 1 (RED).
"""
import base64
import hashlib
import importlib.util
import logging.handlers
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from datetime import timedelta

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_PATH = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    ROOT, "server", "wins_control_plane_setup_ONETOUCH.sh")
LABEL = sys.argv[2] if len(sys.argv) > 2 else "repo"
with open(MAIN_PATH, "rb") as handle:
    print(f"[{LABEL}] source sha256={hashlib.sha256(handle.read()).hexdigest()}")
TMP = tempfile.mkdtemp(prefix=f"l57f2_{LABEL}_", dir=os.environ.get("L46_TMP") or None)
if not MAIN_PATH.endswith(".py"):
    _text = open(MAIN_PATH, encoding="utf-8").read()
    _match = re.search(r"""cat > "\$\{APP_DIR\}/main\.py" <<'PYEOF'\n(.*?)\nPYEOF\n""", _text, re.S)
    if not _match:
        sys.exit(f"hub heredoc not found in {MAIN_PATH}")
    MAIN_PATH = os.path.join(TMP, "main.py")
    with open(MAIN_PATH, "w", encoding="utf-8") as handle:
        handle.write(_match.group(1) + "\n")
    with open(MAIN_PATH, "rb") as handle:
        print(f"[{LABEL}] module sha256={hashlib.sha256(handle.read()).hexdigest()}")


def _refuse(*_a, **_k):
    raise RuntimeError("L46 network guard: outbound connection refused")


socket.socket.connect = _refuse
socket.socket.connect_ex = _refuse
socket.getaddrinfo = _refuse
socket.create_connection = _refuse
_real_makedirs = os.makedirs


def _makedirs(path, *args, **kwargs):
    path = str(path)
    # REGISTRY-PUSH (harness portability, from the Flash seat, precedence as
    # the GLM Max seat wrote it): a macOS tempdir lives under /var/folders, so
    # redirecting a path that is already under TMP would re-prefix it on every
    # recursion level of the real makedirs and blow the stack. Only foreign
    # absolute roots are redirected.
    if not path.startswith(TMP) and (path.startswith("/var/") or path.startswith("/root/")):
        path = os.path.join(TMP, path.lstrip("/"))
    return _real_makedirs(path, *args, **kwargs)


_RealWatched = logging.handlers.WatchedFileHandler


def _watched(filename, *args, **kwargs):
    filename = os.path.join(TMP, "log", os.path.basename(str(filename)))
    _real_makedirs(os.path.dirname(filename), exist_ok=True)
    return _RealWatched(filename, *args, **kwargs)


def wg_key():
    return base64.b64encode(secrets.token_bytes(32)).decode()


ADMIN = secrets.token_hex(32)           # test-only, never printed
NODE_TOKEN = secrets.token_urlsafe(48)  # test-only, never printed
CORE_ID = "l46-core"
FR, UK, ES, WD, RT = "france-fr1", "uk-lon1", "es-mad1", "de-fra1", "nl-ams1"
RB, RD = "pl-waw1", "cz-prg1"   # race nodes: closure before the push, closure during it
CANARY_PUBLIC = wg_key()
os.environ.update({
    "DATABASE_PATH": os.path.join(TMP, "vpn_users.db"),
    "SECURITY_EVENTS_DB": os.path.join(TMP, "security_events.db"),
    "ADMIN_TOKEN": ADMIN,
    "RATE_LIMIT_SECRET": secrets.token_hex(32),
    "HIDE_CONTROL_ORIGIN": "1",
    "VERIFY_ACCOUNT_RATE_LIMIT_PER_HOUR": "1000",
    "VERIFY_IP_RATE_LIMIT_PER_MINUTE": "1000",
    "FREE_VERIFY_IP_RATE_LIMIT_PER_MINUTE": "1000",
    "FREE_VERIFY_DEVICE_RATE_LIMIT_PER_HOUR": "1000",
    "WINN3_INNER_POOL_CIDR": "10.10.0.0/24",
    "DOUBLE_VPN_ENABLED": "1",
    "DOUBLE_VPN_CORE_ID": CORE_ID,
    "WINN3_CANARY_NODE_SLUG": FR,
    "WINN3_CANARY_STATIC_PUBLIC": CANARY_PUBLIC,
    "WINN3_CANARY_INNER_V4": "10.10.0.250",
})
os.makedirs = _makedirs
logging.handlers.WatchedFileHandler = _watched
try:
    spec = importlib.util.spec_from_file_location(f"hub_{LABEL}", MAIN_PATH)
    hub = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hub)
finally:
    os.makedirs = _real_makedirs
    logging.handlers.WatchedFileHandler = _RealWatched

ALERTS = []
hub.security_alert = lambda priority, event_type, **kw: ALERTS.append((priority, event_type))
PEER_SYNCS, REMOVALS, PUBLISHED = [], [], {}
CONTROL = {"remove_ok": True, "publish_ok": True, "close_during_push": None, "close_before_push": None,
           "concurrent_uncertain": None}


def _close(slug):
    with db() as conn:
        conn.execute("UPDATE nodes SET operator_enabled=0 WHERE slug=?", (slug,))


def _sync_peer(node_ip, cfg):
    PEER_SYNCS.append((node_ip, cfg.get("client_public_key")))
    slug = CONTROL["close_during_push"]
    if slug and node_ip == HOST[slug]:
        CONTROL["close_during_push"] = None
        _close(slug)          # a concurrent closure lands while this push runs
    return True


_real_parse = hub.parse_iso_datetime


def _parse_hook(value):
    # The resync reads each row's expiry right after taking its snapshot and
    # before pushing; a closure armed here lands between snapshot and push.
    slug = CONTROL["close_before_push"]
    if slug:
        CONTROL["close_before_push"] = None
        _close(slug)
    return _real_parse(value)


hub.parse_iso_datetime = _parse_hook


REAL_RUN = subprocess.run
FLEET = os.path.join(TMP, "fleet")
SHIMS = os.path.join(FLEET, "shims")
os.makedirs(SHIMS)
# timeout(1) bounds the registry command's stdin read and macOS does not ship it;
# sync(8) on macOS flushes the whole machine, so it is a no-op here; older macOS
# ships shasum only, and the command checks the stream with sha256sum.
_TOOLS = [("getent", "exit 0"), ("chown", "exit 0"), ("flock", "exit 0"),
          ("timeout", 'shift; exec "$@"'), ("sync", "exit 0"),
          ("install", 'for last; do :; done; mkdir -p "$last"')]
if shutil.which("sha256sum") is None:
    _TOOLS.append(("sha256sum", 'exec shasum -a 256 "$@"'))
for _name, _body in _TOOLS:
    with open(os.path.join(SHIMS, _name), "w") as handle:
        handle.write("#!/bin/bash\n" + _body + "\n")
    os.chmod(os.path.join(SHIMS, _name), stat.S_IRWXU)
UNSIMULATED = []


class _Result:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def node_dir(slug):
    return os.path.join(FLEET, slug, "etc_winn")


def landed_bytes(slug):
    try:
        with open(os.path.join(node_dir(slug), "winn3-peers.json"), "rb") as handle:
            return handle.read()
    except FileNotFoundError:
        return None


def _node_command(node_ip, remote_cmd, *args, **kwargs):
    return ["l57-node", str(node_ip), remote_cmd]


def _run(args, *a, **kwargs):
    if isinstance(args, list) and len(args) == 3 and args[0] == "l57-node":
        host, command = args[1], args[2]
        slug = next((s for s, h in HOST.items() if h == host), None)
        if slug is None or "/etc/winn/winn3-peers.json" not in command:
            UNSIMULATED.append(host)
            return _Result(1, "", "l57 test: remote command not simulated")
        if not CONTROL["publish_ok"]:
            return _Result(255, "", "ssh: connect to host: Connection timed out")
        target = node_dir(slug)
        os.makedirs(target, exist_ok=True)
        env = dict(os.environ, PATH=SHIMS + os.pathsep + os.environ.get("PATH", ""))
        done = REAL_RUN(["bash", "--noprofile", "--norc", "-c", command.replace("/etc/winn", target)],
                        input=kwargs.get("input"), capture_output=True, text=True, env=env, check=False)
        if done.returncode == 0 and landed_bytes(slug) is not None:
            PUBLISHED[slug] = sorted(p["static_public"] for p in json.loads(landed_bytes(slug))["peers"])
        if done.returncode == 0 and CONTROL["concurrent_uncertain"] == slug:
            # Another publisher (the refresh drain, say) records a newer write to
            # the same gateway whose outcome never becomes known.
            CONTROL["concurrent_uncertain"] = None
            hub.record_winn3_publication_intent(slug, {"peers": []}, [], host)
        return _Result(done.returncode, done.stdout, done.stderr)
    if isinstance(args, list) and args[:2] == ["bash", "-lc"]:
        UNSIMULATED.append("local")
        return _Result(1, "", "l57 test: local node command not simulated")
    return REAL_RUN(args, *a, **kwargs)


def _remove_peer(node_ip, key):
    REMOVALS.append((node_ip, key))
    return CONTROL["remove_ok"]


hub.sync_peer_to_node = _sync_peer
hub.node_ssh_command = _node_command
hub.subprocess.run = _run
hub.remove_peer_from_node = _remove_peer
hub._wait_for_core_assignment_ready_sync = lambda core_id, device_id, revision: True

from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(hub.app, raise_server_exceptions=False)
HDR = {"x-admin-token": ADMIN}
HOST = {s: hub.node_management_hostname(s) for s in (FR, UK, ES, WD, RT, RB, RD)}
RESULTS = []


def _short(value):
    """Print keys as short digests only (they are random test keys, but the habit matters),
    and long lists as their first three items plus a count."""
    if isinstance(value, str) and len(value) == 44 and value.endswith("="):
        return "k:" + hashlib.sha256(value.encode()).hexdigest()[:12]
    if isinstance(value, (list, tuple)):
        items = [_short(v) for v in value]
        if len(items) > 6:
            items = items[:3] + [f"(and {len(items) - 3} more)"]
        return type(value)(items)
    return value


def check(name, actual, expected):
    ok = actual == expected
    RESULTS.append(ok)
    print(f"[{LABEL}] {'PASS' if ok else 'FAIL'} {name}: got={_short(actual)!r} expected={_short(expected)!r}")


def db():
    conn = sqlite3.connect(os.environ["DATABASE_PATH"])
    conn.row_factory = sqlite3.Row
    return conn


def seed_node(slug, octet, *, enabled, protocol="winn/1", status="online", free=1, withdrawal=None, retired=False):
    now = hub.utcnow().isoformat()
    with db() as conn:
        conn.execute(
            "INSERT INTO nodes (slug, name, flag, endpoint, public_key, status, last_heartbeat,"
            " ssh_host, node_token_hash, free_access_enabled, operator_enabled, management_status,"
            " management_checked_at, data_plane_status, data_plane_ok_at,"
            " data_plane_udp_status, data_plane_udp_ok_at, tunnel_gateway_ipv4,"
            " obfuscation_json, max_peers, protocol_version, deployment_withdrawal_id, retired_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (slug, slug, "FR", f"198.51.100.{octet}:9110", wg_key(), status, now,
             HOST[slug], hub.token_digest(NODE_TOKEN), free, enabled, "ok", now, "ok", now,
             "ok", now, "10.8.1.1", hub.json.dumps(hub.DEFAULT_OBFUSCATION), 250, protocol,
             withdrawal, now if retired else None))
        conn.execute(
            "INSERT INTO node_promotion_events (promotion_id, slug, promoted_at, tier,"
            " evidence_sha256, operator_source_hash, node_status, management_status,"
            " management_checked_at, data_plane_status, data_plane_ok_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (secrets.token_hex(16), slug, "2026-09-11T04:43:22", "free", "0" * 64, "x",
             "online", "ok", now, "ok", now))
    if retired:
        with db() as conn:
            conn.execute("UPDATE nodes SET ssh_host='', endpoint='' WHERE slug=?", (slug,))


def seed_account(acc):
    with db() as conn:
        conn.execute(
            "INSERT INTO users (account_number, email, subscriber_name, status, expiration_date)"
            " VALUES (?,?,?,?,?)",
            (acc, "", "l46", "active", (hub.utcnow() + timedelta(days=30)).isoformat()))


IP = iter(range(10, 250))


def seed_device(acc, device_id, slug):
    n = next(IP)
    dev = {"acc": acc, "device_id": device_id, "key": wg_key(), "v3": wg_key(), "slug": slug}
    now = hub.utcnow().isoformat()
    with db() as conn:
        conn.execute(
            "INSERT INTO devices (device_id, account_number, device_model, hardware_hash,"
            " vpn_internal_ip, client_private_key, client_public_key, preshared_key, last_seen,"
            " location_slug, updated_at, device_auth_token_hash, winn3_static_public, winn3_inner_v4)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (device_id, acc, "Android", hub.device_identity_bucket(device_id), f"10.8.0.{n}", "",
             dev["key"], "", now, slug, now, hub.token_digest(secrets.token_urlsafe(32)),
             dev["v3"], f"10.10.0.{n}"))
    return dev


def bind(dev, slug):
    with db() as conn:
        conn.execute("UPDATE devices SET location_slug=? WHERE device_id=?", (slug, dev["device_id"]))


def slug_of(dev):
    with db() as conn:
        return conn.execute("SELECT location_slug FROM devices WHERE device_id=?", (dev["device_id"],)).fetchone()[0]


def resync(slug=""):
    PEER_SYNCS.clear()
    REMOVALS.clear()
    PUBLISHED.clear()
    r = client.post("/admin/nodes/resync-peers", headers=HDR, params={"node_slug": slug} if slug else None)
    return r.json() if r.status_code == 200 else {"http": r.status_code}


def pushed_to(slug):
    return sorted(k for h, k in PEER_SYNCS if h == HOST[slug])


def removed_from(slug):
    return sorted(k for h, k in REMOVALS if h == HOST[slug])


def pending_revocations(slug):
    with db() as conn:
        return conn.execute("SELECT COUNT(*) FROM peer_revocations WHERE node_ip=?", (HOST[slug],)).fetchone()[0]


def node_field(slug, field):
    with db() as conn:
        return conn.execute(f"SELECT {field} FROM nodes WHERE slug=?", (slug,)).fetchone()[0]


def free_verify(location, install):
    body = {
        "device_id": install, "device_fingerprint": install,
        "device_model": "motorola edge plus 2023", "platform": "android",
        "app_version": "1.0.16", "locale": "en", "location": location,
        "client_public_key": wg_key(),
        "accepted_terms": True, "accepted_hold_harmless": True,
        "accepted_limitation_liability": True, "accepted_electronic_records": True,
        "accepted_android_vpn_service_disclosure": True,
        "android_vpn_service_disclosure_version": hub.ANDROID_VPN_SERVICE_DISCLOSURE_ACCEPTED_VERSIONS[-1],
        "android_vpn_service_disclosure_accepted_at": "2026-09-20T00:00:00Z",
        "legal_version": hub.LEGAL_DOCUMENT_VERSION, "legal_hash": hub.LEGAL_DOCUMENT_HASH,
    }
    return client.post("/free/verify", json=body)


def served(r):
    try:
        return r.json()["vpn_config"]["node_slug"]
    except Exception:
        return None


with db() as conn:
    hub.ensure_schema(conn)
    conn.commit()
seed_node(UK, 21, enabled=1)
seed_node(FR, 20, enabled=0, protocol="winn/3")                 # France after redeploy: online, verified, off
seed_node(ES, 22, enabled=0)                                     # winn/1 node for the end-to-end promotion
seed_node(WD, 23, enabled=0, status="maintenance", withdrawal="wd-" + secrets.token_hex(4))
seed_node(RT, 24, enabled=0, status="offline", retired=True)
seed_node(RB, 25, enabled=1)
seed_node(RD, 26, enabled=1)
A1, A2, A3 = "1111-2222-3333", "4444-5555-6666", "7777-8888-9999"
for a in (A1, A2, A3):
    seed_account(a)
FR1 = seed_device(A1, "fr-bound-1", FR)       # the "two devices still assigned to France"
FR2 = seed_device(A2, "fr-bound-2", FR)
UK1 = seed_device(A3, "uk-bound-1", UK)
WD1 = seed_device(A3, "wd-bound-1", WD)
RT1 = seed_device(A3, "rt-bound-1", RT)
now = hub.utcnow().isoformat()
with db() as conn:   # a Double VPN assignment that exits through France, and its Core
    conn.execute(
        "INSERT INTO core_servers (core_id, name, region, management_status, management_checked_at,"
        " ingress_endpoint, tunnel_gateway_ipv4, ingress_public_key, exit_public_key,"
        " regional_aliases, direct_awg_enabled, status, runtime_ready, promoted,"
        " active_promotion_id, last_heartbeat, runtime_checked_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (CORE_ID, "core", "na", "ok", now, "198.51.100.40:9120", "10.9.1.1", wg_key(), wg_key(),
         "[]", 1, "online", 1, 1, secrets.token_hex(8), now, now))
    core_exit_key = conn.execute("SELECT exit_public_key FROM core_servers").fetchone()[0]
    conn.execute("INSERT INTO core_exit_peers (core_id, exit_slug, core_exit_ip, table_id, iface, updated_at)"
                 " VALUES (?,?,?,?,?,?)", (CORE_ID, FR, "10.8.255.2", 52001, "corex1", now))
    conn.execute("INSERT INTO double_vpn_assignments (device_id, account_number, core_id, exit_slug,"
                 " client_public_key, client_ip, preshared_key, status, assigned_at, updated_at)"
                 " VALUES (?,?,?,?,?,?,?,?,?,?)",
                 (FR2["device_id"], A2, CORE_ID, FR, FR2["key"], "10.9.1.2", "", "active", now, now))


def cleanup_state(slug):
    with db() as conn:
        try:
            row = conn.execute("SELECT state FROM node_closure_cleanup WHERE slug=?", (slug,)).fetchone()
        except sqlite3.OperationalError:
            return "no-table"
        return row[0] if row else None


def dvpn_status():
    with db() as conn:
        return conn.execute("SELECT status FROM double_vpn_assignments WHERE device_id=?", (FR2["device_id"],)).fetchone()[0]


check("S0 France off, winn/3, two devices preassigned",
      (node_field(FR, "operator_enabled"), node_field(FR, "protocol_version"), slug_of(FR1), slug_of(FR2)),
      (0, "winn/3", FR, FR))

# ---------------------------------------------------------------- resync of the off node
out = resync(FR)
check("R1 no AWG peer pushed to the off node (customers or Core exit)", pushed_to(FR), [])
check("R2 v3 registry republished with the canary only, no device", PUBLISHED.get(FR), [CANARY_PUBLIC])
check("R3 both devices unassigned", (slug_of(FR1), slug_of(FR2)), ("", ""))
check("R4 both device AWG peers AND the Core exit peer removed from the off node",
      removed_from(FR), sorted([FR1["key"], FR2["key"], core_exit_key]))
check("R4 revocation outbox drained", pending_revocations(FR), 0)
check("R5 resync reports the unbinding, the Core exit revocation, confirmed cleanup, success",
      (out.get("offnode_devices_unbound"), out.get("offnode_revocations_queued"),
       out.get("offnode_core_exit_revocations_queued"), out.get("offnode_cleanup_confirmed"),
       out.get("ok")), (2, 2, 1, [FR], True))
check("R5 durable cleanup record says confirmed", cleanup_state(FR), "confirmed")
check("R6 Double VPN assignment through the off exit invalidated", dvpn_status(), "inactive")
check("R6 Core exit peer not pushed to the off exit", core_exit_key in pushed_to(FR), False)
out = resync(FR)
check("R7 second resync is idempotent (nothing left to unbind or push)",
      (out.get("offnode_devices_unbound"), pushed_to(FR), PUBLISHED.get(FR), cleanup_state(FR)),
      (0, [], [CANARY_PUBLIC], "confirmed"))

# more revocations than one drain call handles (64)
many = [seed_device(A1, f"fr-many-{i}", FR) for i in range(70)]
out = resync(FR)
check("R8 70 devices on the off node: all unassigned, all removed, cleanup confirmed",
      (out.get("offnode_devices_unbound"), len([k for k in removed_from(FR) if k != core_exit_key]),
       out.get("offnode_cleanup_pending"), out.get("ok")), (70, 70, [], True))

# ---------------------------------------------------------------- enabled node unaffected
out = resync(UK)
check("E1 enabled node: its device's AWG peer is pushed", pushed_to(UK), [UK1["key"]])
check("E1 enabled node: its device stays in the v3 registry", PUBLISHED.get(UK), [UK1["v3"]])
check("E1 enabled node: nothing unbound, nothing removed",
      (out.get("offnode_devices_unbound"), removed_from(UK), slug_of(UK1)), (0, [], UK))

# ---------------------------------------------------------------- registry filter is itself the policy
bind(FR1, FR)   # a binding that appeared by any other route (direct SQL, a race)
with db() as conn:
    doc = hub.winn3_peer_registry_document(conn, FR)
check("G1 snapshot of an off node never lists an assigned device (canary kept)",
      sorted(p["static_public"] for p in doc["peers"]), [CANARY_PUBLIC])
r = client.post(f"/api/v1/nodes/{FR}/resync-peers", headers={"x-node-token": NODE_TOKEN})
check("G2 the node's own self-service resync also unbinds and revokes",
      (r.status_code, r.json().get("offnode_devices_unbound"), slug_of(FR1)), (200, 1, ""))

# ---------------------------------------------------------------- fleet-wide: withdrawal and retirement
out = resync("")
check("W1 fleet resync pushes nothing to the off, withdrawn or retired nodes",
      (pushed_to(FR), pushed_to(WD), pushed_to(RT)), ([], [], []))
check("W2 device on a node under an installer withdrawal is unassigned", slug_of(WD1), "")
check("W2 its AWG peer revocation was sent to that node", removed_from(WD), [WD1["key"]])
check("W3 device on a retired node is unassigned (no management host left to revoke on)",
      (slug_of(RT1), removed_from(RT)), ("", []))
check("W4 the enabled node's device is still pushed in the fleet resync", pushed_to(UK), [UK1["key"]])

# ---------------------------------------------------------------- failed cleanup
bind(FR2, FR)
CONTROL["remove_ok"] = False
out = resync(FR)
check("C1 removal failure: device still unassigned, snapshot still clean",
      (slug_of(FR2), PUBLISHED.get(FR)), ("", [CANARY_PUBLIC]))
check("C1 removal failure keeps the revocation queued, records cleanup pending, fails the resync",
      (pending_revocations(FR) >= 1, out.get("offnode_cleanup_pending"), cleanup_state(FR), out.get("ok")),
      (True, [FR], "pending", False))
CONTROL["remove_ok"] = True
with db() as conn:
    conn.execute("UPDATE peer_revocations SET next_attempt_at=0")
hub.drain_peer_revocation_outbox()
check("C2 the queued revocation completes on a later drain", pending_revocations(FR), 0)
bind(FR1, FR)
CONTROL["publish_ok"] = False
out = resync(FR)
check("C3 registry publish failure is reported, cleanup pending, and the binding is still gone",
      (out.get("winn3_registry_failed"), out.get("ok"), slug_of(FR1), cleanup_state(FR)), (1, False, "", "pending"))
r = client.post("/admin/nodes/tier", headers=HDR, data={"slug": FR, "tier": "free", "confirm_slug": FR,
                "evidence_sha256": hashlib.sha256(b"x").hexdigest()})
check("C3 promotion refused while closure cleanup is pending",
      (r.status_code, "cleanup is pending" in str(r.json().get("detail"))), (409, True))
CONTROL["publish_ok"] = True
out = resync(FR)
check("C3 next resync publishes the clean snapshot and confirms",
      (PUBLISHED.get(FR), out.get("ok"), cleanup_state(FR)), ([CANARY_PUBLIC], True, "confirmed"))

# ---------------------------------------------------------------- closed node in maintenance / offline
for status in ("maintenance", "offline"):
    with db() as conn:
        conn.execute("UPDATE nodes SET status=? WHERE slug=?", (status, FR))
    bind(FR2, FR)
    out = resync(FR)
    check(f"M1 {status}: canary-only v3 snapshot still published", PUBLISHED.get(FR), [CANARY_PUBLIC])
    check(f"M1 {status}: device and Core exit AWG peers removed, device unassigned",
          (removed_from(FR), slug_of(FR2)), (sorted([FR2["key"], core_exit_key]), ""))
    check(f"M1 {status}: cleanup confirmed", (cleanup_state(FR), out.get("ok")), ("confirmed", True))
    CONTROL["publish_ok"] = False
    out = resync(FR)
    check(f"M2 {status}: unreachable publish means pending and failure",
          (cleanup_state(FR), out.get("ok"), FR in out.get("offnode_cleanup_pending", [])), ("pending", False, True))
    CONTROL["publish_ok"] = True
    out = resync(FR)
with db() as conn:
    conn.execute("UPDATE nodes SET status='online' WHERE slug=?", (FR,))
out = resync(FR)
check("M3 back online: cleanup confirmed again", cleanup_state(FR), "confirmed")

# ---------------------------------------------------------------- races with a concurrent closure
RB1 = seed_device(A3, "rb-bound-1", RB)
CONTROL["close_before_push"] = RB
out = resync(RB)
check("K1 closure between snapshot and push: nothing pushed", pushed_to(RB), [])
out = resync(RB)
check("K1 the next resync cleans it (unassigned, removed, confirmed)",
      (slug_of(RB1), removed_from(RB), cleanup_state(RB)), ("", [RB1["key"]], "confirmed"))
RD1 = seed_device(A3, "rd-bound-1", RD)
CONTROL["close_during_push"] = RD
out = resync(RD)
check("K2 closure during the push: the pushed peer is taken back in the same resync",
      (pushed_to(RD), removed_from(RD), out.get("offnode_raced_pushes_revoked"), pending_revocations(RD)),
      ([RD1["key"]], [RD1["key"]], 1, 0))

# ---------------------------------------------------------------- node-side gate records (HV turn 3)
def expected_v3(slug):
    # Built independently of the hub: a closed node's snapshot is the canary (France) or empty.
    peers = [{"static_public": CANARY_PUBLIC, "inner_v4": "10.10.0.250", "not_after": 0}] if slug == FR else []
    raw = hub.json.dumps({"version": 1, "peers": peers}, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def confirmed_at(slug):
    with db() as conn:
        try:
            row = conn.execute("SELECT confirmed_at FROM node_closure_cleanup WHERE slug=?", (slug,)).fetchone()
        except sqlite3.OperationalError:   # a file without F2's cleanup record
            return ""
        return (row[0] or "") if row else ""


def node_report(slug, winn3=True, started_after="1", awg_peers=0):
    lines = [f"AWGPEER {secrets.token_hex(8)} device_pool {secrets.token_hex(8)} lt3m" for _ in range(awg_peers)]
    lines.append(f"AWG_READ ok iface=awg0 peers={awg_peers}")
    if winn3:
        lines += [f"V3_FILE present sha256={expected_v3(slug)} size=90 mode=0o640 regular=1 age_s=30",
                  "V3_VALID gateway_rules=ok pool_known=1",
                  f"GW unit=active pid_known=1 forward=1 registry_flag_matches=1 gateway_can_read=1 "
                  f"started_after_file={started_after} reload_failed_since_file=0"]
    else:
        lines += ["V3_FILE absent", "GW unit=inactive pid_known=0 forward=0 registry_flag_matches=0 "
                  "gateway_can_read=unknown started_after_file=unknown reload_failed_since_file=unknown"]
    return "\n".join(lines) + "\n"


def gate_digest(slug, report, ext=""):
    canonical = "\n".join(["l46-offnode-gate-v3", f"slug={slug}", f"expected_v3_sha256={expected_v3(slug)}",
                           f"cleanup_confirmed_at={confirmed_at(slug)}", f"external_evidence_sha256={ext}",
                           f"node_report_sha256={hashlib.sha256(report.encode()).hexdigest()}"]) + "\n"
    return hashlib.sha256(canonical.encode()).hexdigest()


def record_gate(slug, report, digest=None):
    digest = digest or gate_digest(slug, report)
    r = client.post("/admin/nodes/offnode-gate", headers=HDR,
                    data={"slug": slug, "gate_sha256": digest, "node_report": report})
    return r, digest


def promote(slug, evidence):
    return client.post("/admin/nodes/tier", headers=HDR,
                       data={"slug": slug, "tier": "free", "evidence_sha256": evidence, "confirm_slug": slug})


check("R2b the file that landed on France is byte for byte the canary-only snapshot built independently",
      hashlib.sha256(landed_bytes(FR) or b"").hexdigest(), expected_v3(FR))

XN = "sk-bts1"   # a closed node that has never been resynced: no cleanup record at all
HOST[XN] = hub.node_management_hostname(XN)
seed_node(XN, 27, enabled=0)
r = promote(XN, hashlib.sha256(b"any evidence").hexdigest())
check("X1 promotion of a node with NO cleanup record refused",
      (r.status_code, "never recorded" in str(r.json().get("detail"))), (409, True))
r = promote(FR, hashlib.sha256(b"an arbitrary 64-hex digest").hexdigest())
check("X2 promotion with an arbitrary evidence digest refused (cleanup confirmed, no gate record)",
      (r.status_code, "no verified node-side gate record" in str(r.json().get("detail"))), (409, True))
r, _ = record_gate(FR, node_report(FR, started_after="0"))
check("X3 gate refused when the gateway is older than the registry file",
      (r.status_code, "started after" in str(r.json().get("detail"))), (409, True))
r, _ = record_gate(FR, node_report(FR, awg_peers=1))
check("X4 gate refused with any AWG peer present (no lab exception at promotion)", r.status_code, 409)
r, _ = record_gate(FR, node_report(FR), digest=hashlib.sha256(b"wrong").hexdigest())
check("X5 gate refused when gate_sha256 is not the canonical digest", r.status_code, 409)
stale_report = node_report(FR)
r, stale = record_gate(FR, stale_report)
check("X6 a valid gate is recorded", r.status_code, 200)
resync(FR)   # a new cleanup confirmation after the gate
r = promote(FR, stale)
check("X6 a gate bound to an older cleanup confirmation is refused",
      (r.status_code, "changed after the gate" in str(r.json().get("detail"))), (409, True))
r = client.post("/admin/nodes/retire", headers=HDR, data={"slug": RB, "reason": "l46 test"})
check("X7 retirement without a gate record refused",
      (r.status_code, "Retirement refused" in str(r.json().get("detail"))), (409, True))
r = client.post("/admin/nodes/retire", headers=HDR, data={"slug": UK, "reason": "l46 test", "confirm_last_servable_node": UK})
check("X7 retirement of an open node refused", (r.status_code, "latch is open" in str(r.json().get("detail"))), (409, True))
r, g = record_gate(WD, node_report(WD, winn3=False))
r2 = client.post("/admin/nodes/retire", headers=HDR, data={"slug": WD, "reason": "l46 test", "offnode_gate_sha256": g})
check("X8 retirement with a verified gate accepted; cleanup record kept as 'retired'",
      (r.status_code, r2.status_code, cleanup_state(WD)), (200, 200, "retired"))

# ---------------------------------------------------------------- gated promotion still works
r = client.post("/admin/nodes/tier", headers=HDR, data={"slug": FR, "tier": "free", "confirm_slug": FR})
check("P0 promotion without evidence still refused", r.status_code, 400)
r, gate_fr = record_gate(FR, node_report(FR))
r = promote(FR, gate_fr)
check("P1 gated promotion of the winn/3 node with a verified gate accepted",
      (r.status_code, r.json().get("operator_enabled"), cleanup_state(FR)), (200, True, "promoted"))
out = resync(FR)
check("P2 promotion restores no stale access (nobody is assigned any more)",
      (pushed_to(FR), PUBLISHED.get(FR)), ([], [CANARY_PUBLIC]))
bind(FR1, FR)   # an admission after promotion
out = resync(FR)
check("P3 promoted node: an admitted device is pushed and published (canary kept)",
      (pushed_to(FR), PUBLISHED.get(FR)), ([FR1["key"]], sorted([FR1["v3"], CANARY_PUBLIC])))
r = client.post("/admin/nodes/tier", headers=HDR, data={"slug": FR, "tier": "off"})
out = resync(FR)
r5 = promote(FR, gate_fr)
check("P5 the used gate cannot promote the node again", r5.status_code, 409)
check("P4 tier off again: the admitted device is revoked on the next resync",
      (r.status_code, pushed_to(FR), sorted(k for k in removed_from(FR) if k != core_exit_key), slug_of(FR1), PUBLISHED.get(FR)),
      (200, [], [FR1["key"]], "", [CANARY_PUBLIC]))

# end to end on a winn/1 node: promote, real /free/verify admission, resync, withdraw
install = "INSTALL-" + secrets.token_hex(8).upper()
r = free_verify(ES, install)
check("Q0 off winn/1 node refuses an explicit free request", r.status_code, 503)
r, gate_es = record_gate(ES, node_report(ES, winn3=False))
r = promote(ES, gate_es)
check("Q1 gated promotion of the winn/1 node accepted", (r.status_code, r.json().get("operator_enabled")), (200, True))
r = free_verify(ES, install)
check("Q2 promoted node serves a real /free/verify admission", (r.status_code, served(r)), (200, ES))
free_device_id = hub.free_identity_for_device(install)[1]
with db() as conn:
    free_key = conn.execute("SELECT client_public_key FROM devices WHERE device_id=?", (free_device_id,)).fetchone()[0]
out = resync(ES)
check("Q3 resync of the promoted node pushes the admitted device", pushed_to(ES), [free_key])
client.post("/admin/nodes/tier", headers=HDR, data={"slug": ES, "tier": "off"})
out = resync(ES)
check("Q4 after tier off the admitted device is revoked and unassigned",
      (pushed_to(ES), removed_from(ES), out.get("offnode_devices_unbound")), ([], [free_key], 1))

# ---------------------------------------------------------------- free path unchanged
r = free_verify("auto", "INSTALL-" + secrets.token_hex(8).upper())
check("F0 free automatic unchanged: served by the enabled node", (r.status_code, served(r)), (200, UK))
r = free_verify(FR, "INSTALL-" + secrets.token_hex(8).upper())
check("F1 free explicit request for the off node still refused", r.status_code, 503)

# ---------------------------------------------------------------- L57-A departure grants (decision a)
def inner_of(dev):
    with db() as conn:
        return conn.execute("SELECT winn3_inner_v4 FROM devices WHERE device_id=?", (dev["device_id"],)).fetchone()[0]


def publication_kinds(slug):
    with db() as conn:
        document, meta = hub.winn3_peer_registry_publication(conn, slug)
    return sorted(m["kind"] for m in meta), document


def grant_expiry(grant_device, slug):
    with db() as conn:
        return conn.execute("SELECT MAX(expires_at) FROM winn3_departure_grants WHERE device_id=? AND node_slug=?",
                            (grant_device["device_id"], slug)).fetchone()[0]


def queued_refresh(slug):
    with db() as conn:
        return conn.execute("SELECT COUNT(*) FROM winn3_registry_refreshes WHERE node_slug=?", (slug,)).fetchone()[0]


DGF = seed_device(A3, "dg-left-france", UK)   # left France for the UK before France closed
DGU = seed_device(A3, "dg-left-uk", "")       # left the (open) UK node, not yet placed
with db() as conn:
    hub.issue_winn3_departure_grant(conn, device_id=DGF["device_id"], account_number=A3, node_slug=FR,
                                    static_public=DGF["v3"], inner_v4=inner_of(DGF))
    hub.issue_winn3_departure_grant(conn, device_id=DGU["device_id"], account_number=A3, node_slug=UK,
                                    static_public=DGU["v3"], inner_v4=inner_of(DGU))
kinds, doc = publication_kinds(FR)
check("L57-A1 a closed node publishes no departure entry: its snapshot is the canary alone",
      (kinds, sorted(p["static_public"] for p in doc["peers"])), (["canary"], [CANARY_PUBLIC]))
kinds, doc = publication_kinds(UK)
uk_grant = [p for p in doc["peers"] if p["static_public"] == DGU["v3"]]
check("L57-A2 an open node still publishes its departure grant, bounded (Round O unchanged)",
      ("departure" in kinds, len(uk_grant), bool(uk_grant) and 0 < uk_grant[0]["not_after"]
       <= int(hub.winn3_clock()) + hub.WINN3_DEPARTURE_GRACE_SECONDS + 1), (True, 1, True))
out = resync(FR)
check("L57-A3 the closure resync retires the grant held AT the closed node, and only that one",
      (out.get("offnode_departure_grants_retired"), grant_expiry(DGF, FR) <= hub.winn3_clock(),
       grant_expiry(DGU, UK) > hub.winn3_clock()), (1, True, True))
check("L57-A4 France's file stays canary-only and its cleanup is confirmed",
      (PUBLISHED.get(FR), cleanup_state(FR), hashlib.sha256(landed_bytes(FR) or b"").hexdigest()),
      ([CANARY_PUBLIC], "confirmed", expected_v3(FR)))
check("L57-A5 the confirmed closed-node publication leaves no queued republish (the sweep would restart the gate)",
      queued_refresh(FR), 0)
with db() as conn:
    charged = conn.execute("SELECT COUNT(*) FROM winn3_departure_grants WHERE node_slug=? AND cleanup_queued=1",
                           (FR,)).fetchone()[0]
with hub.winn3_authority_ledger() as ledger:
    fr_charges = ledger.execute("SELECT COUNT(*) FROM winn3_departure_charges WHERE node_slug=?", (FR,)).fetchone()[0]
check("L57-A6 the retired grant is marked cleaned and was never charged (never published)", (charged, fr_charges), (1, 0))


# ---------------------------------------------------------------- L57-B authority ledger (decision b)
def ledger_latest(slug):
    gateway = hub.winn3_gateway_of(HOST[slug])
    with hub.winn3_authority_ledger() as ledger:
        row = ledger.execute("SELECT seq, outcome FROM winn3_publications WHERE node_slug=? AND gateway=?"
                             " ORDER BY seq DESC LIMIT 1", (slug, gateway)).fetchone()
        if row is None:
            return None, []
        entries = sorted((e["static_public"], e["kind"]) for e in ledger.execute(
            "SELECT static_public, kind FROM winn3_publication_entries WHERE seq=?", (row["seq"],)))
    return row["outcome"], entries


check("L57-B1 the ledger's latest publication to France's gateway is confirmed and holds the canary alone",
      ledger_latest(FR), ("confirmed", [(CANARY_PUBLIC, "canary")]))
bind(FR1, FR)
CONTROL["publish_ok"] = False
out = resync(FR)
check("L57-B2 unreachable: device unbound, ledger row uncertain, cleanup pending, republish stays queued",
      (slug_of(FR1), ledger_latest(FR)[0], cleanup_state(FR), queued_refresh(FR) >= 1, out.get("ok")),
      ("", "uncertain", "pending", True, False))
with db() as conn:
    conn.execute("UPDATE nodes SET operator_enabled=1 WHERE slug=?", (FR,))
    helper = getattr(hub, "winn3_closed_node_withdrawal_confirmed", None)
    confirmed_ok = helper(conn, FR) if helper else "helper absent"
    conn.execute("UPDATE nodes SET operator_enabled=0 WHERE slug=?", (FR,))
check("L57-B3 an uncertain latest publication never counts as a confirmed withdrawal", confirmed_ok, False)
CONTROL["publish_ok"] = True
with db() as conn:
    conn.execute("UPDATE winn3_registry_refreshes SET next_attempt_at=0")
drained = hub.drain_winn3_registry_refreshes(32, [FR])
check("L57-B4 the repo's own refresh drain republishes the canary-only file once the node is back",
      (drained.get("published"), ledger_latest(FR)), (1, ("confirmed", [(CANARY_PUBLIC, "canary")])))
out = resync(FR)
check("L57-B5 the next resync confirms the cleanup", (cleanup_state(FR), out.get("ok")), ("confirmed", True))
CONTROL["concurrent_uncertain"] = FR
out = resync(FR)
check("L57-B7 a newer publication of unknown outcome keeps the cleanup pending, though this write was acknowledged",
      (ledger_latest(FR)[0], cleanup_state(FR), out.get("ok"), FR in out.get("offnode_cleanup_pending", [])),
      ("uncertain", "pending", False, True))
out = resync(FR)
check("L57-B8 the next acknowledged resync confirms it again", (cleanup_state(FR), out.get("ok")), ("confirmed", True))
# ---------------------------------------------------------------- R25 closed node, queued removal in a long backoff
# germany-de1 (2026-10-19): a reachable closed node's queued AWG removals sat in a
# 900 s backoff earned while the node was unreachable, node_closure_cleanup counts
# every queued row, and the data-plane installer's management check gives up after
# about 100 s, so a reinstalled node could never pass. A slug-scoped resync that
# finds the node answering management makes that node's unleased rows due and
# drains them; another node's rows, a row a drain holds a lease on, and a
# fleet-wide resync keep their backoff.
def put_revocation(slug, key, attempts, wait, lease=None):
    now = time.time()
    with db() as conn:
        conn.execute(
            "INSERT INTO peer_revocations (revocation_id, node_ip, client_public_key, attempts,"
            " next_attempt_at, lease_until, last_failure_kind, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (secrets.token_hex(16), HOST[slug], key, attempts, now + wait,
             None if lease is None else now + lease, "remove_failed", hub.utcnow().isoformat()))


def revocation_row(slug, key):
    with db() as conn:
        row = conn.execute("SELECT attempts, next_attempt_at, lease_until FROM peer_revocations"
                           " WHERE node_ip=? AND client_public_key=?", (HOST[slug], key)).fetchone()
    return tuple(row) if row else None


def cleanup_awg_pending(slug):
    with db() as conn:
        row = conn.execute("SELECT awg_pending FROM node_closure_cleanup WHERE slug=?", (slug,)).fetchone()
    return row[0] if row else None


RV1 = seed_device(A3, "rv-bound-1", FR)
CONTROL["remove_ok"] = False
resync(FR)                     # France is closed: RV1 is unbound and its removal is queued, and fails
CONTROL["remove_ok"] = True
with db() as conn:             # the row as a long outage leaves it: attempt 6, 900 s backoff
    conn.execute("UPDATE peer_revocations SET attempts=6, next_attempt_at=? WHERE node_ip=? AND client_public_key=?",
                 (time.time() + 900, HOST[FR], RV1["key"]))
UK_KEY, ES_KEY = wg_key(), wg_key()
put_revocation(UK, UK_KEY, 3, 600)              # another node, backed off
put_revocation(ES, ES_KEY, 2, 900, lease=90)    # another node, a drain holds the lease
uk_before, es_before = revocation_row(UK, UK_KEY), revocation_row(ES, ES_KEY)
# Every resync of the closed node also re-queues and removes its Core exit peer (CX).
check("V0 before the resync: both removals wait in their backoff and the cleanup is pending",
      (pending_revocations(FR), cleanup_state(FR), revocation_row(FR, RV1["key"])[0]), (2, "pending", 6))
out = resync(FR)
check("V1 the reachable closed node's backed-off removals are retried at once and succeed",
      (removed_from(FR), pending_revocations(FR)), (sorted([core_exit_key, RV1["key"]]), 0))
check("V1 cleanup confirmed with nothing queued, and the resync succeeds",
      (cleanup_state(FR), cleanup_awg_pending(FR), out.get("ok")), ("confirmed", 0, True))
check("V2 another node's backed-off row is neither made due nor removed",
      (revocation_row(UK, UK_KEY), removed_from(UK)), (uk_before, []))
check("V3 a row another drain holds the lease on is neither made due nor removed",
      (revocation_row(ES, ES_KEY), removed_from(ES)), (es_before, []))
with db() as conn:
    conn.execute("DELETE FROM peer_revocations WHERE client_public_key IN (?, ?)", (UK_KEY, ES_KEY))
LEASED = wg_key()
put_revocation(FR, LEASED, 4, 900, lease=90)    # a drain in flight holds this closed node's row
leased_before = revocation_row(FR, LEASED)
out = resync(FR)
check("V4 a leased row at the closed node is left alone and the cleanup stays pending",
      (revocation_row(FR, LEASED), removed_from(FR), cleanup_state(FR), cleanup_awg_pending(FR), out.get("ok")),
      (leased_before, [core_exit_key], "pending", 1, False))
with db() as conn:                              # the lease ends; the backoff has not
    conn.execute("UPDATE peer_revocations SET lease_until=NULL WHERE client_public_key=?", (LEASED,))
out = resync(FR)
check("V5 once unleased, the next scoped resync removes it and confirms the cleanup",
      (removed_from(FR), cleanup_state(FR), out.get("ok")), (sorted([core_exit_key, LEASED]), "confirmed", True))
WIDE = wg_key()
put_revocation(FR, WIDE, 5, 900)
wide_before = revocation_row(FR, WIDE)
resync("")
check("V6 a fleet-wide resync does not override a node's backoff",
      (revocation_row(FR, WIDE), removed_from(FR)), (wide_before, [core_exit_key]))
out = resync(FR)
check("V7 the scoped resync then clears it", (removed_from(FR), cleanup_state(FR), out.get("ok")),
      (sorted([core_exit_key, WIDE]), "confirmed", True))

check("L57-B6 no remote command other than a registry publication was attempted on a node host",
      sorted(set(UNSIMULATED) - {"local"}), [])

print(f"[{LABEL}] {sum(RESULTS)}/{len(RESULTS)} assertions held")
sys.exit(0 if all(RESULTS) else 1)
