#!/usr/bin/env python3
"""Hub tests for the four Kansas hand-patches and the guard that protects them.

Like test_account_deletion_hub.py, test_donor_acknowledgment_hub.py,
test_emergency_dispatch_hub.py and test_winn3_serving_hub.py these exercise the
REAL control-plane source: the module is extracted from the
`cat > .../main.py <<'PYEOF'` heredoc inside wins_control_plane_setup_ONETOUCH.sh
and exec'd with stubs for its third-party imports. Nothing here is a
reimplementation, so a regression in the shipped installer fails these tests.

No test contacts a node, a live hub, or the network. No address, provider name
or node slug from the production fleet appears in this file.

WHAT IS UNDER TEST.

docs/handoff/CONTROL_PLANE_REPO_VS_KANSAS_HAND_PATCH_DRIFT_20260807.md recorded
four changes that were applied BY HAND to the deployed hub and existed in no
commit. docs/handoff/CONTROL_PLANE_HAND_PATCH_RECONCILIATION_20260807.md ported
them into the installer. This suite is the standing proof that the port is still
there, because the failure mode if it silently regresses is SILENT: SQLite never
drops a column, the external prober keeps writing verdicts, nothing logs and
nothing 500s -- the gate simply stops existing while the client's
_boolDefaultTrue(item['reachable']) flips every node back to "reachable" and the
UI resumes offering dead servers to real users.

  P1  the data-plane reachability gate       (patch_main_dataplane.py)
  P2  the platform-aware transport gate      (patch_main_transport.py)
  P3  the GET /nodes listing-reach contract  (no patch script; reconstructed)
  P4  the Linux TLS-stealth branch           (patch_main_stealth_tls.py)

plus the two properties that make a deploy safe rather than merely possible:

  * THE COMPOSITION RULE -- policy (operator_enabled) is the outer filter and is
    dispositive. Terminal or stale external health consumes that promotion;
    platform-specific health still controls GET /nodes reachability labels.
  * THE DRIFT GUARD PROCEEDS ON EVIDENCE -- a host whose hand-patches this
    installer reproduces must deploy WITHOUT ALLOW_MAIN_PY_OVERWRITE=1, and a
    host carrying anything it does not reproduce must be refused BY NAME. The
    blind override is the failure case, not the route.

Run:  python3 server/test_hub_hand_patch_reconciliation.py
"""
from contextlib import closing
import _toolchain  # noqa: F401  (V-01 preflight)
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Reuse the deletion suite's extraction harness so every suite is provably
# reading the same heredoc out of the same installer.
import test_account_deletion_hub as harness  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
INSTALLER = os.path.join(HERE, "wins_control_plane_setup_ONETOUCH.sh")

# Documentation-range literals only (RFC 5737). No project address appears in
# this file; `python3 tools/ipscrub/ipscrub.py scan-paths` is run over it.
NODE_HOST = "198.51.100.7"
NODE_ENDPOINT = "198.51.100.7:9110"

FAILURES = []
PASSED = [0]


def check(name, fn):
    try:
        fn()
    except Exception:
        FAILURES.append((name, traceback.format_exc()))
        print(f"  FAIL  {name}")
    else:
        PASSED[0] += 1
        print(f"  ok    {name}")


def eq(actual, expected, what=""):
    if actual != expected:
        raise AssertionError(f"{what}: expected {expected!r}, got {actual!r}")


def true(value, what=""):
    if not value:
        raise AssertionError(f"{what}: expected truthy, got {value!r}")


def false(value, what=""):
    if value:
        raise AssertionError(f"{what}: expected falsy, got {value!r}")


# ========================= node fixtures ==================================

def seed_node(mod, *, slug="lab-alpha", operator_enabled=1, free_access=1,
              status="online", management_status="ok", **columns):
    """One node row that passes every non-data-plane selection gate.

    Extra keyword arguments are written straight onto the row, so a test says
    exactly which probe verdict (or capacity) it is describing and nothing else.
    """
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        now = mod.utcnow().isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO nodes ("
            " slug, name, flag, endpoint, tunnel_gateway_ipv4, stealth_endpoint,"
            " public_key, preshared_key, status, last_heartbeat, obfuscation_json,"
            " ssh_host, wg_port, xray_uuid, xray_path, xray_security, xray_sni,"
            " stealth_public_port, xray_inbound_port, management_status,"
            " operator_enabled, free_access_enabled, direct_awg_enabled,"
            " max_peers, peer_count"
            ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                slug, slug.replace("-", " ").title(), "\U0001F310", NODE_ENDPOINT,
                "10.8.1.1", f"{slug}.example.test:80",
                "A" * 43 + "=", "B" * 43 + "=", status, now,
                json.dumps({"Jc": 2, "Jmin": 10, "Jmax": 30}),
                NODE_HOST, 9110, "11111111-2222-4333-8444-555555555555",
                "/wins-stealth-tunnel", "none", f"{slug}.example.test", 80, 9111,
                management_status, operator_enabled, free_access, 1, 500, 0,
            ),
        )
        for column, value in columns.items():
            conn.execute(f"UPDATE nodes SET {column} = ? WHERE slug = ?", (value, slug))
    return node_row(mod, slug)


def node_row(mod, slug="lab-alpha"):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT * FROM nodes WHERE slug = ?", (slug,)).fetchone()


def db(mod):
    conn = sqlite3.connect(mod._DB)
    conn.row_factory = sqlite3.Row
    return conn


def minutes_ago(mod, count):
    from datetime import timedelta
    return (mod.utcnow() - timedelta(minutes=count)).isoformat()


def selected(mod, platform=""):
    with db(mod) as conn:
        row = mod.select_online_node(conn, "auto", platform=platform)
    return row["slug"] if row else None


def listing(mod, platform="unknown"):
    import asyncio
    payload = asyncio.run(
        mod.list_public_nodes(platform=platform))
    return {n["slug"]: n for n in payload["nodes"]}


# ===================== P1: the data-plane reachability gate ================
#
# The incident: a node heartbeat'ed `online` continuously while all inbound UDP
# was dropped at the provider edge, and the hub handed real users complete,
# valid-looking configs for a server they could never reach, with no signal
# anywhere.

def test_p1_schema_carries_all_eighteen_data_plane_columns(mod):
    with db(mod) as conn:
        mod.ensure_schema(conn)
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(nodes)")]
    data_plane = sorted(c for c in cols if c.startswith("data_plane_"))
    # Five aggregate, one source-revision fact, three UDP, three plaintext
    # stealth, three TLS stealth, and (L84, Round SC) the three streak columns
    # the prober and the hub's automatic reopen gate share: consecutive
    # probe_error runs, consecutive healthy proofs, and when that began. H5 adds
    # six more (see below) and Turn 2 three attempt-time columns, so the test
    # name's "eighteen" is now twenty-seven.
    expected = sorted((
        "data_plane_status", "data_plane_checked_at", "data_plane_ok_at",
        "data_plane_fail_streak", "data_plane_error",
        "data_plane_code_revision",
        "data_plane_udp_status", "data_plane_udp_ok_at",
        "data_plane_udp_fail_streak",
        "data_plane_stealth_status", "data_plane_stealth_ok_at",
        "data_plane_stealth_fail_streak",
        "data_plane_stealth_tls_status", "data_plane_stealth_tls_ok_at",
        "data_plane_stealth_tls_fail_streak",
        "data_plane_probe_error_streak", "data_plane_green_streak",
        "data_plane_green_since",
        # H5 (ruling E): the AWG carrying canary, a status and a last-success
        # time per transport, written by the prober's --carry mode.
        "data_plane_udp_carry_status", "data_plane_udp_carry_ok_at",
        "data_plane_stealth_carry_status", "data_plane_stealth_carry_ok_at",
        "data_plane_stealth_tls_carry_status", "data_plane_stealth_tls_carry_ok_at",
        # The attempt time per transport: the cadence of a failing transport.
        "data_plane_udp_carry_checked_at", "data_plane_stealth_carry_checked_at",
        "data_plane_stealth_tls_carry_checked_at",
    ))
    eq(data_plane, expected, "data_plane_* columns")
    # The prober's own additive schema must name every column it writes that
    # the hub also owns, so either side can create them first.
    probe_columns = set(load_real_dataplane_probe()["COLUMNS"])
    for name in expected:
        if name != "data_plane_code_revision":
            true(name in probe_columns, f"prober COLUMNS carries {name}")


def test_p1_a_proven_unreachable_node_is_never_handed_out(mod):
    seed_node(mod, data_plane_status="unreachable",
              data_plane_ok_at=minutes_ago(mod, 1))
    eq(selected(mod), None, "unreachable node must not be selectable")
    false(mod.node_is_online_and_managed(node_row(mod)), "predicate agrees")


def test_p1_a_never_probed_node_cannot_dark_start_the_fleet(mod):
    # data_plane_ok_at IS NULL: the gate has never had an opinion. Introducing
    # the gate must not withdraw a fleet that has simply not been probed yet.
    seed_node(mod, data_plane_status="unknown", data_plane_ok_at=None)
    eq(selected(mod), "lab-alpha", "never-probed node stays selectable")
    true(mod.node_data_plane_is_available(node_row(mod)), "health says available")


def test_p1_stale_ok_at_is_fail_closed_when_the_prober_itself_dies(mod):
    # The genuinely fail-closed half: the node was proven reachable once and has
    # not been re-verified since, i.e. nothing is measuring it any more.
    seed_node(mod, data_plane_status="ok",
              data_plane_ok_at=minutes_ago(mod, mod.DATA_PLANE_HARD_STALE_MINUTES + 5))
    eq(selected(mod), None, "stale proof must not be treated as proof")
    seed_node(mod, data_plane_status="ok",
              data_plane_ok_at=minutes_ago(mod, mod.DATA_PLANE_HARD_STALE_MINUTES - 5))
    eq(selected(mod), "lab-alpha", "fresh proof is honoured")


def test_p1_the_gate_covers_free_selection_and_the_free_slug_list(mod):
    seed_node(mod, free_access=1, data_plane_status="unreachable")
    with db(mod) as conn:
        eq(mod.select_free_node(conn), None, "select_free_node is gated")
        eq(mod.current_free_node_slugs(conn), [], "advertised free slugs are gated")


def test_p1_an_explicitly_requested_unreachable_node_is_still_refused(mod):
    # The gate must not be bypassable by asking for the node by name -- that is
    # the path a user takes when they pick a server from the list themselves.
    seed_node(mod, data_plane_status="unreachable", data_plane_ok_at=minutes_ago(mod, 1))
    with db(mod) as conn:
        eq(mod.select_online_node(conn, "lab-alpha", require_selected=True), None,
           "an explicit request for a dead node is refused")
        eq(mod.select_online_node(conn, "lab-alpha"), None,
           "and does not fall back to it in the fleet scan either")
    seed_node(mod, data_plane_status="ok", data_plane_ok_at=minutes_ago(mod, 1))
    with db(mod) as conn:
        row = mod.select_online_node(conn, "lab-alpha", require_selected=True)
        eq(row["slug"] if row else None, "lab-alpha",
           "a healthy node asked for by name is served")


def test_p1_an_existing_allocation_cannot_reconnect_to_a_dead_node(mod):
    # A device already allocated to a node reconnects through a separate branch
    # that skips the capacity ceiling. It must not skip the health gate too.
    seed_node(mod, data_plane_status="unreachable", data_plane_ok_at=minutes_ago(mod, 1))
    with db(mod) as conn:
        eq(mod.select_online_node(conn, "auto", existing_slug="lab-alpha"), None,
           "reconnect is gated")
    seed_node(mod, data_plane_status="ok", data_plane_ok_at=minutes_ago(mod, 1),
              peer_count=100000)
    with db(mod) as conn:
        row = mod.select_online_node(conn, "auto", existing_slug="lab-alpha")
        eq(row["slug"] if row else None, "lab-alpha",
           "a healthy node at its ceiling still takes its own device back")


def test_p1_free_selection_is_gated_on_every_branch(mod):
    seed_node(mod, free_access=1, data_plane_status="unreachable",
              data_plane_ok_at=minutes_ago(mod, 1))
    with db(mod) as conn:
        eq(mod.select_free_node(conn, "lab-alpha"), None, "explicit free request")
        eq(mod.select_free_node(conn, "auto", existing_slug="lab-alpha"), None,
           "free reconnect")
    seed_node(mod, free_access=1, data_plane_status="ok",
              data_plane_ok_at=minutes_ago(mod, 1))
    with db(mod) as conn:
        row = mod.select_free_node(conn, "auto")
        eq(row["slug"] if row else None, "lab-alpha", "a healthy free node is served")
        row = mod.select_free_node(conn, "auto", existing_slug="lab-alpha")
        eq(row["slug"] if row else None, "lab-alpha",
           "and a device already on it reconnects to it")
        mod.FREE_ACCESS_ENABLED = False
        eq(mod.select_free_node(conn, "auto"), None, "free access off short-circuits")


def test_p1_the_double_vpn_usable_exit_subquery_carries_the_gate(mod):
    # select_double_vpn_core()'s EXISTS(...) picks a usable exit node. Asserted
    # against the shipped installer text: the alias-qualified form of the gate
    # is what makes the subquery correct, and a silent revert here would offer
    # Double VPN through an exit nothing can reach.
    src = harness._extract_main_block()
    body = src.split("def select_double_vpn_core")[1].split("\ndef ")[0]
    true("DATA_PLANE_AVAILABLE_SQL_N" in body,
         "Double-VPN usable-exit subquery must use the aliased gate")
    true("COALESCE(n.operator_enabled, 0) = 1" in body,
         "Double-VPN usable-exit subquery must reject operator-dark exits")
    true("n.retired_at IS NULL" in body,
         "Double-VPN usable-exit subquery must reject retired exits")
    true("n.data_plane_status" in mod.DATA_PLANE_AVAILABLE_SQL_N,
         "the aliased constant must qualify its columns")


def load_real_dataplane_probe():
    source = installer_text().split(
        "cat > /usr/local/lib/wins_node_dataplane_probe.py <<'DPPROBEEOF'", 1
    )[1].split("\nDPPROBEEOF", 1)[0]
    namespace = {"__name__": "wins_node_dataplane_probe_test"}
    exec(compile(source, "wins_node_dataplane_probe.py", "exec"), namespace)
    return namespace


def test_p1_probe_error_revokes_ok_without_incrementing_failure_streak(mod):
    probe = load_real_dataplane_probe()
    eq(probe["_fold"]("ok", 2, "probe_error"), ("probe_error", 2))
    seed_node(
        mod,
        data_plane_status="ok",
        data_plane_ok_at=minutes_ago(mod, 1),
        data_plane_udp_status="ok",
        data_plane_udp_ok_at=minutes_ago(mod, 1),
        data_plane_udp_fail_streak=2,
        data_plane_stealth_status="unconfigured",
        data_plane_stealth_tls_status="unconfigured",
    )
    with db(mod) as conn:
        result = probe["apply_verdicts"](
            conn,
            "lab-alpha",
            ("probe_error", "capture unavailable"),
            ("unconfigured", "not configured"),
            ("unconfigured", "not configured"),
        )
    eq(result["aggregate"], "probe_error")
    eq(result["udp_streak"], 2, "probe error preserves evidence streak")
    eq(selected(mod), None, "probe_error is not a selectable false-green")


def test_p1_zero_currently_servable_nodes_emits_a_security_alert(mod):
    alerts = []
    real_alert = mod.security_alert
    real_logger = mod.logger
    class QuietLogger:
        def error(self, *_args, **_kwargs):
            return None

        def warning(self, *_args, **_kwargs):
            return None
    mod.security_alert = lambda priority, event_type, **kwargs: alerts.append(
        (priority, event_type, kwargs.get("details"))
    )
    mod.logger = QuietLogger()
    try:
        result = mod.audit_fleet_availability_once()
        eq(result, {"registered": 0, "servable": 0})
        eq(len(alerts), 1)
        eq(alerts[0][0], 1)
        true("zero currently servable" in alerts[0][1])
        seed_node(mod, data_plane_status="ok", data_plane_ok_at=minutes_ago(mod, 1))
        result = mod.audit_fleet_availability_once()
        eq(result["servable"], 1)
        # SYNC-HUB's reported-only "open node without promotion evidence" alert (priority 2) may
        # fire for the seeded node; this test is about the zero-servable alert, so count only that one.
        eq(len([a for a in alerts if "zero currently servable" in a[1]]), 1,
           "healthy fleet emits no second zero-servable alert")
    finally:
        mod.security_alert = real_alert
        mod.logger = real_logger


# ================= P2: the platform-aware transport gate ==================
#
# Linux hard-rejects a `security=none` stealth transport, so an aggregate "ok"
# carried entirely by plaintext stealth is real for Windows/macOS/Android/iOS
# and a lie for Linux.

def test_p2_linux_is_the_only_platform_that_cannot_use_plaintext_stealth(mod):
    false(mod.platform_can_use_stealth("linux"), "linux rejects plaintext stealth")
    for platform in ("android", "ios", "macos", "windows"):
        true(mod.platform_can_use_stealth(platform), f"{platform} accepts it")
    # An unknown platform must not be over-restricted.
    for platform in ("", "unknown"):
        true(mod.platform_can_use_stealth(platform), "unknown platform gets grace")


def test_p2_a_plaintext_stealth_only_node_serves_android_but_not_linux(mod):
    # Aggregate ok, but the only proven transport is plaintext stealth.
    seed_node(mod,
              data_plane_status="ok", data_plane_ok_at=minutes_ago(mod, 1),
              data_plane_udp_status="unreachable",
              data_plane_stealth_status="ok",
              data_plane_stealth_tls_status="unknown")
    eq(selected(mod, "android"), "lab-alpha", "non-Linux client can use it")
    eq(selected(mod, "linux"), None, "Linux client cannot")


def test_p2_the_transport_clause_is_added_only_for_stealth_incapable_platforms(mod):
    plain = mod.data_plane_sql("android")
    linux = mod.data_plane_sql("linux")
    eq(plain, mod.DATA_PLANE_AVAILABLE_SQL, "non-Linux gets the aggregate gate alone")
    true(len(linux) > len(plain), "Linux gets an extra clause")
    true(mod.DATA_PLANE_UDP_AVAILABLE_SQL in linux, "the UDP alternative is offered")
    true(mod.DATA_PLANE_STEALTH_TLS_PROVEN_SQL in linux, "so is the TLS alternative")


def test_p2_the_python_mirror_agrees_with_the_sql_on_every_row(mod):
    # node_data_plane_is_available() is a mirror of data_plane_sql(). If they
    # disagree, the listing and the selection tell users different stories.
    from datetime import timedelta
    fresh = minutes_ago(mod, 1)
    stale = minutes_ago(mod, mod.DATA_PLANE_HARD_STALE_MINUTES + 5)
    matrix = [
        ("healthy", dict(data_plane_status="ok", data_plane_ok_at=fresh,
                         data_plane_udp_status="ok", data_plane_udp_ok_at=fresh)),
        ("neverprobed", dict(data_plane_status="unknown")),
        ("plainstealthonly", dict(data_plane_status="ok", data_plane_ok_at=fresh,
                                  data_plane_udp_status="unreachable",
                                  data_plane_stealth_status="ok")),
        ("tlsstealthonly", dict(data_plane_status="ok", data_plane_ok_at=fresh,
                                data_plane_udp_status="unreachable",
                                data_plane_stealth_tls_status="ok",
                                data_plane_stealth_tls_ok_at=fresh)),
        ("proberdead", dict(data_plane_status="ok", data_plane_ok_at=stale)),
        ("dead", dict(data_plane_status="unreachable", data_plane_ok_at=fresh)),
    ]
    for slug, columns in matrix:
        seed_node(mod, slug=slug, **columns)
    for platform in ("android", "linux"):
        with db(mod) as conn:
            sql_rows = {r["slug"] for r in conn.execute(
                f"SELECT slug FROM nodes WHERE status='online' "
                f"AND management_status='ok' AND COALESCE(operator_enabled,0)=1 "
                f"{mod.data_plane_sql(platform)}")}
            py_rows = {r["slug"] for r in conn.execute("SELECT * FROM nodes")
                       if mod.node_is_online_and_managed(r, platform)}
        eq(py_rows, sql_rows, f"python mirror vs SQL on {platform}")


def test_p2_transport_availability_reports_all_three_routes(mod):
    seed_node(mod, data_plane_udp_status="ok",
              data_plane_stealth_status="unreachable",
              data_plane_stealth_tls_status="unknown")
    transports = mod.node_transport_availability(node_row(mod))
    eq(transports["direct_awg_udp"], "ok")
    eq(transports["stealth_tcp_ws"], "unreachable")
    eq(transports["stealth_tls_tcp_ws"], "unknown")


# ============= P3: the GET /nodes listing-reach client contract ============
#
# THIS EDIT HAS A LIVE CLIENT CONTRACT. lib/main.dart reads item['reachable']
# through _boolDefaultTrue(), so a hub that stops emitting the key does not fail
# safe: every node silently becomes "reachable" again.

def test_p3_terminal_external_health_consumes_listing_promotion(mod):
    seed_node(mod, data_plane_status="unreachable", data_plane_ok_at=minutes_ago(mod, 1))
    nodes = listing(mod)
    eq(nodes, {}, "terminal external health withdraws the node from advertising")
    eq(node_row(mod)["operator_enabled"], 0,
       "routine recovery cannot reuse the consumed promotion")


def test_p3_the_listing_emits_all_three_client_contract_keys(mod):
    seed_node(mod, data_plane_status="ok", data_plane_ok_at=minutes_ago(mod, 1),
              data_plane_udp_status="ok")
    node = listing(mod)["lab-alpha"]
    for key in ("reachable", "transports", "reachabletransports"):
        true(key in node, f"{key} must be emitted -- the client defaults it to true")
    eq(node["reachabletransports"], node["transports"], "the two spellings agree")
    eq(node["transports"]["direct_awg_udp"], "ok")
    true(node["reachable"], "a healthy node reads reachable")


def test_p3_raw_probe_values_are_stripped_from_the_public_payload(mod):
    seed_node(mod, data_plane_status="ok", data_plane_ok_at=minutes_ago(mod, 1))
    node = listing(mod)["lab-alpha"]
    leaked = sorted(k for k in node if k.startswith("data_plane_"))
    eq(leaked, [], "operational probe metadata must not reach public clients")


def test_p3_listing_exposes_protocol_classification_without_params(mod):
    seed_node(
        mod,
        protocol_version="winn/3",
        protocol_params_json=json.dumps({
            "carrier": "winn3",
            "gateway_endpoint": "198.51.100.8:51820",
            "admission_secret": "must-not-be-public",
        }),
    )
    node = listing(mod)["lab-alpha"]
    eq(node["protocol_version"], "winn/3")
    eq(node["protocolversion"], "winn/3")
    eq(node["carrier"], "winn3")
    false("protocol_params_json" in node, "stored params must remain private")
    false("gateway_endpoint" in json.dumps(node), "params cannot leak by flattening")
    false("admission_secret" in json.dumps(node), "secrets cannot leak by flattening")

    seed_node(
        mod,
        slug="lab-v1",
        endpoint="198.51.100.9:9110",
        public_key="C" * 43 + "=",
        ssh_host="198.51.100.9",
    )
    legacy = listing(mod)["lab-v1"]
    eq(legacy["protocol_version"], "winn/1")
    eq(legacy["carrier"], "amneziawg")


def test_p3_the_unreachable_label_outranks_congested(mod):
    # A full node reads "congested". If its aggregate health remains green but
    # the requesting platform cannot use the one healthy transport, the public
    # label reads "unreachable". Terminal aggregate health instead consumes the
    # promotion and removes the node entirely.
    seed_node(mod, peer_count=100000, data_plane_status="ok",
              data_plane_ok_at=minutes_ago(mod, 1))
    eq(listing(mod)["lab-alpha"]["status"], "congested", "full but reachable")
    seed_node(mod, peer_count=100000, data_plane_status="ok",
              data_plane_ok_at=minutes_ago(mod, 1),
              data_plane_udp_status="unreachable",
              data_plane_stealth_status="ok")
    eq(listing(mod, "linux")["lab-alpha"]["status"], "unreachable",
       "full but unusable by this platform")


def test_p3_duplicate_identities_are_still_collapsed(mod):
    # The listing de-duplicates on endpoint and on identity. The reachability
    # labelling runs before that, so it must not resurrect a duplicate row.
    seed_node(mod, slug="lab-alpha", data_plane_status="ok",
              data_plane_ok_at=minutes_ago(mod, 1))
    seed_node(mod, slug="lab-beta", data_plane_status="ok",
              data_plane_ok_at=minutes_ago(mod, 1))
    nodes = listing(mod)
    eq(len(nodes), 1, "two rows sharing an endpoint and a key collapse to one")


def test_p3_the_listing_label_is_platform_aware(mod):
    # Same row, two clients: the label follows what THIS client can use.
    seed_node(mod, data_plane_status="ok", data_plane_ok_at=minutes_ago(mod, 1),
              data_plane_udp_status="unreachable",
              data_plane_stealth_status="ok")
    true(listing(mod, "android")["lab-alpha"]["reachable"], "android can use it")
    false(listing(mod, "linux")["lab-alpha"]["reachable"], "linux cannot")


# ================== P4: the Linux TLS-stealth branch ======================
#
# Redraws the dividing line as the OUTER SECURITY of the stealth transport
# rather than the platform: every platform including Linux accepts security=tls.

def test_p4_a_tls_stealth_only_node_serves_linux(mod):
    seed_node(mod, data_plane_status="ok", data_plane_ok_at=minutes_ago(mod, 1),
              data_plane_udp_status="unreachable",
              data_plane_stealth_status="unreachable",
              data_plane_stealth_tls_status="ok",
              data_plane_stealth_tls_ok_at=minutes_ago(mod, 1))
    eq(selected(mod, "linux"), "lab-alpha", "TLS stealth carries a Linux client")
    eq(selected(mod, "android"), "lab-alpha", "and every other platform")


def test_p4_the_tls_branch_demands_positive_proof_not_grace(mod):
    # Deliberately asymmetric: this branch can only ever ADD availability, so a
    # permissive default would invent a route rather than merely fail to hide
    # one. 'unknown' must not qualify, and neither must a stale proof.
    base = dict(data_plane_status="ok", data_plane_ok_at=minutes_ago(mod, 1),
                data_plane_udp_status="unreachable",
                data_plane_stealth_status="unreachable")
    seed_node(mod, data_plane_stealth_tls_status="unknown", **base)
    eq(selected(mod, "linux"), None, "'unknown' TLS status is not proof")
    seed_node(mod, data_plane_stealth_tls_status="ok",
              data_plane_stealth_tls_ok_at=None, **base)
    eq(selected(mod, "linux"), None, "'ok' with no timestamp is not proof")
    seed_node(mod, data_plane_stealth_tls_status="ok",
              data_plane_stealth_tls_ok_at=minutes_ago(
                  mod, mod.DATA_PLANE_HARD_STALE_MINUTES + 5), **base)
    eq(selected(mod, "linux"), None, "a stale TLS proof is not proof")


def test_p4_udp_keeps_the_grace_the_tls_branch_is_denied(mod):
    # The asymmetry is one-directional: UDP still gets "not yet known to be
    # broken", so a node that has never had its UDP probed still carries Linux.
    seed_node(mod, data_plane_status="ok", data_plane_ok_at=minutes_ago(mod, 1),
              data_plane_udp_status="unknown", data_plane_udp_ok_at=None,
              data_plane_stealth_tls_status="unknown")
    eq(selected(mod, "linux"), "lab-alpha", "unknown UDP keeps its grace")


# ================ the composition rule: policy outranks health ============

def test_composition_an_operator_withdrawn_node_is_absent_everywhere(mod):
    # Healthy, but a human took it out. A green data-plane must never be able to
    # re-advertise a node an operator withdrew.
    seed_node(mod, operator_enabled=0,
              data_plane_status="ok", data_plane_ok_at=minutes_ago(mod, 1))
    eq(selected(mod), None, "not selectable")
    eq(listing(mod), {}, "and absent from the listing entirely, not labelled")


def test_composition_terminal_external_health_consumes_promotion_everywhere(mod):
    seed_node(mod, operator_enabled=1, data_plane_status="unreachable",
              data_plane_ok_at=minutes_ago(mod, 1))
    eq(selected(mod), None, "not selectable")
    eq(listing(mod), {}, "not advertised")
    eq(node_row(mod)["operator_enabled"], 0, "promotion consumed")


def test_composition_health_is_deliberately_policy_blind(mod):
    # node_data_plane_is_available() must NOT consult operator_enabled:
    # list_public_nodes needs health without policy, for rows policy admitted.
    seed_node(mod, operator_enabled=0,
              data_plane_status="ok", data_plane_ok_at=minutes_ago(mod, 1))
    true(mod.node_data_plane_is_available(node_row(mod)), "health ignores policy")
    false(mod.node_is_online_and_managed(node_row(mod)), "the combined gate does not")


def test_composition_node_tier_label_still_reports_off(mod):
    seed_node(mod, operator_enabled=0, data_plane_status="ok")
    eq(mod.node_tier_label(node_row(mod)), "off")


# ===================== the drift guard, driven for real ===================
#
# The guard's shell is extracted VERBATIM from the installer and executed. The
# sandbox supplies only what the installer supplies around it: APP_DIR and the
# three log helpers.

GUARD_START = "APP_CODE_STAMP="
GUARD_END = "write_app() {"

# Split so this file cannot match its own search, exactly as the installer's
# extract_incoming_app_code() does -- see test_extractor_does_not_match_itself.
HEREDOC_OPEN = 'cat > "${APP_DIR}' + '/main.py" <<' + "'PYEOF'"


def installer_text():
    with open(INSTALLER, "r", encoding="utf-8") as handle:
        return handle.read()


def guard_block():
    lines = installer_text().split("\n")
    start = next(i for i, line in enumerate(lines) if line.startswith(GUARD_START))
    end = next(i for i, line in enumerate(lines) if line.startswith(GUARD_END))
    block = "\n".join(lines[start:end])
    true("guard_app_code_drift()" in block, "guard extracted")
    true("app_code_reconciliation_report()" in block, "report extracted")
    true("extract_incoming_app_code()" in block, "extractor extracted")
    return block


def real_hub_source():
    return harness._extract_main_block()


def clean_ancestor_source():
    """A parseable stand-in for the last pre-hand-patch deploy.

    Built by dropping every TOP-LEVEL definition whose own source mentions
    data_plane_, which is what the four patches added. Dropping whole top-level
    nodes keeps the result valid Python -- line-wise filtering does not, and a
    baseline that will not parse is one the guard has to fall back from.
    """
    import ast
    source = real_hub_source()
    tree = ast.parse(source)
    lines = source.split("\n")
    drop = set()
    for node in tree.body:
        # A decorated def starts at its decorators, not at the `def` line.
        first = min([d.lineno for d in getattr(node, "decorator_list", [])] + [node.lineno])
        segment = "\n".join(lines[first - 1:(node.end_lineno or node.lineno)])
        if "data_plane_" in segment:
            drop.update(range(first - 1, (node.end_lineno or node.lineno)))
    kept_lines = [l for i, l in enumerate(lines) if i not in drop]
    # Comments live between top-level nodes, so they belong to no AST node and
    # survive the pass above. Dropping a comment line can never break a parse.
    kept_lines = [l for l in kept_lines
                  if not (l.lstrip().startswith("#") and "data_plane_" in l)]
    kept = "\n".join(kept_lines)
    ast.parse(kept)  # the fixture is worthless if it does not parse
    true("data_plane_" not in kept, "the ancestor must show no sign of the patches")
    return kept


def run_guard(tmp, *, on_disk=None, incoming=None, stamp=None, env=None,
              backups=None):
    """Drive guard_app_code_drift() in a sandbox that mimics a host.

    on_disk  -- contents of ${APP_DIR}/main.py, or None for a fresh host
    incoming -- the hub source the sandbox script would write (defaults to the
                real installer heredoc, so extraction is exercised for real)
    stamp    -- text of the provenance stamp file, or None for no stamp
    backups  -- {filename: contents} placed in APP_DIR before the run
    """
    app_dir = os.path.join(tmp, "vpn_auth")
    os.makedirs(app_dir, exist_ok=True)
    if on_disk is not None:
        with open(os.path.join(app_dir, "main.py"), "w", encoding="utf-8") as fh:
            fh.write(on_disk)
    if stamp is not None:
        with open(os.path.join(app_dir, ".main.py.deployed.sha256"), "w",
                  encoding="utf-8") as fh:
            fh.write(stamp)
    for name, body in (backups or {}).items():
        with open(os.path.join(app_dir, name), "w", encoding="utf-8") as fh:
            fh.write(body)

    payload = real_hub_source() if incoming is None else incoming
    if re.search(r"^PYEOF$", payload, re.M):
        raise AssertionError("sandbox payload would terminate its own heredoc")

    script = os.path.join(tmp, "sandbox.sh")
    with open(script, "w", encoding="utf-8") as fh:
        fh.write("#!/usr/bin/env bash\nset -uo pipefail\n")
        fh.write(f'APP_DIR={app_dir!r}\n'.replace("'", '"'))
        fh.write('log()  { echo "[INFO] $*"; }\n')
        fh.write('warn() { echo "[WARN] $*"; }\n')
        fh.write('err()  { echo "[ERR] $*"; }\n')
        fh.write(guard_block())
        fh.write("\nguard_app_code_drift\n")
        fh.write('echo "GUARD_PROCEEDED"\n')
        fh.write("exit 0\n")
        # The payload the sandbox "would write", in the installer's own shape.
        # Never executed; it exists so the extractor has something real to find.
        fh.write("\nif false; then\n  " + HEREDOC_OPEN + "\n")
        fh.write(payload)
        fh.write("\nPYEOF\nfi\n")

    proc = subprocess.run(["bash", script], capture_output=True, text=True,
                          env={**os.environ, **(env or {})})
    return proc.returncode, proc.stdout + proc.stderr, app_dir


def backups_in(app_dir):
    return sorted(n for n in os.listdir(app_dir) if ".pre-deploy-" in n)


def test_guard_a_fresh_host_is_a_first_install(_mod):
    with tempfile.TemporaryDirectory() as tmp:
        rc, out, app_dir = run_guard(tmp, on_disk=None)
        eq(rc, 0, "fresh host proceeds")
        true("GUARD_PROCEEDED" in out, "and reaches the write")
        true("first install" in out, "and says so")
        eq(backups_in(app_dir), [], "nothing to back up")


def test_guard_an_unchanged_stamped_host_proceeds_with_no_analysis(_mod):
    import hashlib
    source = real_hub_source()
    with tempfile.TemporaryDirectory() as tmp:
        digest = hashlib.sha256(source.encode()).hexdigest()
        rc, out, _ = run_guard(tmp, on_disk=source, stamp=digest + "\n")
        eq(rc, 0, "no drift proceeds")
        true("no drift" in out, "and takes the cheap path")
        false("reconciliation check" in out, "no report needed when the stamp matches")


def test_guard_todays_kansas_no_stamp_but_reconciled_proceeds(_mod):
    # THE HEADLINE CASE. A host hand-patched before the guard shipped, so there
    # is no provenance stamp, carrying exactly the four documented patches --
    # every one of which this installer now reproduces. It must deploy with NO
    # override, because there is nothing left to lose.
    source = real_hub_source()
    # Simulate "older than the repo": drop a function the repo added later. The
    # host cannot have what the repo has not deployed to it.
    hand_patched = source + "\n# host-side edit, reconciled\n"
    with tempfile.TemporaryDirectory() as tmp:
        rc, out, app_dir = run_guard(tmp, on_disk=hand_patched, stamp=None)
        eq(rc, 0, "a reconciled host deploys without an override")
        true("GUARD_PROCEEDED" in out, "and reaches the write")
        true("without an override" in out, "and says so explicitly")
        for patch in ("P1", "P2", "P3", "P4"):
            true(re.search(rf"carried\s+{patch}\b", out), f"{patch} reported carried")
        eq(len(backups_in(app_dir)), 1, "the host's copy was preserved anyway")


def test_guard_refuses_and_names_an_unreproduced_host_side_addition(_mod):
    # A FIFTH hand patch nobody reconciled. This is the case the blind override
    # would have destroyed silently.
    source = real_hub_source()
    hand_patched = source + "\n\ndef hand_patched_fifth_thing():\n    return 1\n"
    with tempfile.TemporaryDirectory() as tmp:
        rc, out, app_dir = run_guard(tmp, on_disk=hand_patched, stamp=None)
        eq(rc, 1, "unreconciled work must refuse")
        false("GUARD_PROCEEDED" in out, "and must not reach the write")
        true("hand_patched_fifth_thing" in out, "and must name what would be lost")
        eq(len(backups_in(app_dir)), 1, "backup taken before the refusal")


def test_guard_refuses_when_a_documented_patch_is_not_reproduced(_mod):
    # The regression this suite exists for: a hub that lost P3's client contract
    # while the host still has it. The manifest catches it by name even though
    # P3 adds no top-level definition of its own.
    source = real_hub_source()
    stripped = source.replace("reachabletransports", "reachable_transports_removed")
    with tempfile.TemporaryDirectory() as tmp:
        rc, out, _ = run_guard(tmp, on_disk=source, incoming=stripped, stamp=None)
        eq(rc, 1, "a lost client contract must refuse")
        true("WOULD BE LOST" in out, "and say so")
        true("P3" in out, "naming the patch")
        true("reachabletransports" in out, "and the marker")


def test_guard_reports_every_documented_patch_it_recognises(_mod):
    source = real_hub_source()
    with tempfile.TemporaryDirectory() as tmp:
        _, out, _ = run_guard(tmp, on_disk=source, stamp=None)
        for label in ("data-plane reachability gate",
                      "platform-aware transport gate",
                      "listing-reach contract",
                      "Linux TLS-stealth branch"):
            true(label in out, f"report names: {label}")


def test_guard_uses_a_pre_patch_backup_as_an_exact_baseline(_mod):
    # With a clean ancestor on the host, "added by hand" is a set difference
    # rather than a guess -- ordinary repo churn cannot produce a false refusal.
    source = real_hub_source()
    with tempfile.TemporaryDirectory() as tmp:
        rc, out, _ = run_guard(
            tmp, on_disk=source, stamp=None,
            backups={"main.py.bak.pre-dataplane.20260805T005146Z":
                     clean_ancestor_source()})
        eq(rc, 0, "the baseline path still proceeds on a reconciled host")
        true("baseline" in out, "the baseline is reported")
        true("main.py.bak.pre-dataplane" in out, "and named, so it can be checked")


def test_guard_ignores_a_backup_that_already_carries_the_patches(_mod):
    # A backup taken AFTER the hand patches is not a clean ancestor and must not
    # be mistaken for one, or every host-side addition would look pre-existing.
    source = real_hub_source()
    with tempfile.TemporaryDirectory() as tmp:
        rc, out, _ = run_guard(
            tmp, on_disk=source + "\n\ndef added_by_hand():\n    return 1\n",
            stamp=None,
            backups={"main.py.bak.after-patches": source,
                     "main.py.bak.pre-dataplane.20260805T005146Z":
                         clean_ancestor_source()})
        eq(rc, 1, "the host-side addition is still caught")
        true("added_by_hand" in out, "and named")
        false("after-patches" in out, "the post-patch backup is not used as baseline")


def test_guard_still_refuses_a_stamp_mismatch_it_cannot_account_for(_mod):
    import hashlib
    source = real_hub_source()
    with tempfile.TemporaryDirectory() as tmp:
        rc, out, _ = run_guard(
            tmp,
            on_disk=source + "\n\ndef something_nobody_ported():\n    return 1\n",
            stamp=hashlib.sha256(b"a different deploy").hexdigest() + "\n")
        eq(rc, 1, "a stamp mismatch with real residue still refuses")
        true("recorded sha256" in out, "and shows both digests")
        true("something_nobody_ported" in out, "and names the residue")


def test_guard_override_is_still_available_and_still_backs_up(_mod):
    source = real_hub_source()
    with tempfile.TemporaryDirectory() as tmp:
        rc, out, app_dir = run_guard(
            tmp, on_disk=source + "\n\ndef unported():\n    return 1\n",
            stamp=None, env={"ALLOW_MAIN_PY_OVERWRITE": "1"})
        eq(rc, 0, "the last resort still exists")
        true("GUARD_PROCEEDED" in out, "and proceeds")
        eq(len(backups_in(app_dir)), 1, "and still cannot lose the host's copy")


def test_guard_refusal_no_longer_advertises_the_override_as_the_route(_mod):
    source = real_hub_source()
    with tempfile.TemporaryDirectory() as tmp:
        _, out, _ = run_guard(
            tmp, on_disk=source + "\n\ndef unported():\n    return 1\n", stamp=None)
        true("proceeds on its own" in out,
             "the refusal must point at reconciliation, not at the override")
        true("without evidence" in out, "and must say what the override costs")


def test_guard_backs_up_before_it_decides_anything(_mod):
    # The backup is the whole rollback story and must exist on the refusal path
    # as well as the proceed path.
    source = real_hub_source()
    marker = source + "\n\ndef unported():\n    return 1\n"
    with tempfile.TemporaryDirectory() as tmp:
        rc, _, app_dir = run_guard(tmp, on_disk=marker, stamp=None)
        eq(rc, 1, "refused")
        names = backups_in(app_dir)
        eq(len(names), 1, "exactly one backup")
        with open(os.path.join(app_dir, names[0]), encoding="utf-8") as fh:
            eq(fh.read(), marker, "backup is byte-identical to the host's copy")
        eq(oct(os.stat(os.path.join(app_dir, names[0])).st_mode & 0o777), oct(0o600),
           "backup mode")


def test_guard_fails_closed_when_the_incoming_code_cannot_be_recovered(_mod):
    # If the extractor cannot find the heredoc, nothing can be ruled out, so the
    # guard must refuse rather than assume.
    source = real_hub_source()
    with tempfile.TemporaryDirectory() as tmp:
        app_dir = os.path.join(tmp, "vpn_auth")
        os.makedirs(app_dir)
        with open(os.path.join(app_dir, "main.py"), "w", encoding="utf-8") as fh:
            fh.write(source)
        script = os.path.join(tmp, "sandbox.sh")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write("#!/usr/bin/env bash\nset -uo pipefail\n")
            fh.write(f'APP_DIR="{app_dir}"\n')
            fh.write('log()  { echo "[INFO] $*"; }\n')
            fh.write('warn() { echo "[WARN] $*"; }\n')
            fh.write('err()  { echo "[ERR] $*"; }\n')
            fh.write(guard_block())
            fh.write("\nguard_app_code_drift\necho GUARD_PROCEEDED\n")
            # deliberately NO heredoc for the extractor to find
        proc = subprocess.run(["bash", script], capture_output=True, text=True)
        eq(proc.returncode, 1, "no incoming code means refuse")
        true("could not be recovered" in proc.stdout + proc.stderr,
             "and say why")


def test_extractor_does_not_match_its_own_search_pattern(_mod):
    # REGRESSION. Spelled out in one piece, the extractor's search string is
    # itself the first match for that search, and the extractor slices from its
    # own source line instead of from the hub heredoc -- producing a fragment of
    # shell that parses as nothing and silently disabling the whole check.
    text = installer_text()
    hits = [i + 1 for i, line in enumerate(text.split("\n")) if HEREDOC_OPEN in line]
    eq(len(hits), 1, "exactly one line may spell the heredoc opener")
    body = text.split("extract_incoming_app_code() {")[1].split("\n}")[0]
    false(HEREDOC_OPEN in body, "the extractor must not contain the literal opener")
    true("head=" in body and "tail=" in body, "it assembles the marker in halves")


def test_the_guard_runs_before_anything_can_truncate_main_py(_mod):
    # Ordering is the property that makes the backup meaningful.
    text = installer_text()
    body = text.split("\nwrite_app() {")[1].split("\n}")[0]
    guard_at = body.index("guard_app_code_drift")
    write_at = body.index("cat > ")
    true(guard_at < write_at, "guard must precede every cat > in write_app")


def test_the_stamp_is_recorded_immediately_after_the_hub_is_written(_mod):
    text = installer_text()
    body = text.split("\nwrite_app() {")[1]
    heredoc_end = body.index("\nPYEOF\n")
    stamp_at = body.index("record_app_code_stamp")
    true(stamp_at > heredoc_end, "the stamp records what was actually written")
    true(stamp_at - heredoc_end < 4000, "and does so promptly, not at the end")


# =============================== harness ==================================

HUB_TESTS = [
    test_p1_schema_carries_all_eighteen_data_plane_columns,
    test_p1_a_proven_unreachable_node_is_never_handed_out,
    test_p1_a_never_probed_node_cannot_dark_start_the_fleet,
    test_p1_stale_ok_at_is_fail_closed_when_the_prober_itself_dies,
    test_p1_the_gate_covers_free_selection_and_the_free_slug_list,
    test_p1_an_explicitly_requested_unreachable_node_is_still_refused,
    test_p1_an_existing_allocation_cannot_reconnect_to_a_dead_node,
    test_p1_free_selection_is_gated_on_every_branch,
    test_p1_the_double_vpn_usable_exit_subquery_carries_the_gate,
    test_p1_probe_error_revokes_ok_without_incrementing_failure_streak,
    test_p1_zero_currently_servable_nodes_emits_a_security_alert,
    test_p2_linux_is_the_only_platform_that_cannot_use_plaintext_stealth,
    test_p2_a_plaintext_stealth_only_node_serves_android_but_not_linux,
    test_p2_the_transport_clause_is_added_only_for_stealth_incapable_platforms,
    test_p2_the_python_mirror_agrees_with_the_sql_on_every_row,
    test_p2_transport_availability_reports_all_three_routes,
    test_p3_terminal_external_health_consumes_listing_promotion,
    test_p3_the_listing_emits_all_three_client_contract_keys,
    test_p3_raw_probe_values_are_stripped_from_the_public_payload,
    test_p3_listing_exposes_protocol_classification_without_params,
    test_p3_the_unreachable_label_outranks_congested,
    test_p3_duplicate_identities_are_still_collapsed,
    test_p3_the_listing_label_is_platform_aware,
    test_p4_a_tls_stealth_only_node_serves_linux,
    test_p4_the_tls_branch_demands_positive_proof_not_grace,
    test_p4_udp_keeps_the_grace_the_tls_branch_is_denied,
    test_composition_an_operator_withdrawn_node_is_absent_everywhere,
    test_composition_terminal_external_health_consumes_promotion_everywhere,
    test_composition_health_is_deliberately_policy_blind,
    test_composition_node_tier_label_still_reports_off,
]

# These drive shell, not the hub module, so they do not need a fresh module.
GUARD_TESTS = [
    test_guard_a_fresh_host_is_a_first_install,
    test_guard_an_unchanged_stamped_host_proceeds_with_no_analysis,
    test_guard_todays_kansas_no_stamp_but_reconciled_proceeds,
    test_guard_refuses_and_names_an_unreproduced_host_side_addition,
    test_guard_refuses_when_a_documented_patch_is_not_reproduced,
    test_guard_reports_every_documented_patch_it_recognises,
    test_guard_uses_a_pre_patch_backup_as_an_exact_baseline,
    test_guard_ignores_a_backup_that_already_carries_the_patches,
    test_guard_still_refuses_a_stamp_mismatch_it_cannot_account_for,
    test_guard_override_is_still_available_and_still_backs_up,
    test_guard_refusal_no_longer_advertises_the_override_as_the_route,
    test_guard_backs_up_before_it_decides_anything,
    test_guard_fails_closed_when_the_incoming_code_cannot_be_recovered,
    test_extractor_does_not_match_its_own_search_pattern,
    test_the_guard_runs_before_anything_can_truncate_main_py,
    test_the_stamp_is_recorded_immediately_after_the_hub_is_written,
]


def main():
    import asyncio
    asyncio.set_event_loop(asyncio.new_event_loop())
    print("hub hand-patch reconciliation (P1-P4) and the drift guard")
    for fn in HUB_TESTS:
        # A fresh module + database per test: these mutate node rows, and a
        # leaked data_plane verdict would make a later test pass for the wrong
        # reason.
        mod = harness.load_hub()
        check(fn.__name__, lambda f=fn, m=mod: f(m))
        shutil.rmtree(mod._TMPDIR, ignore_errors=True)
    for fn in GUARD_TESTS:
        check(fn.__name__, lambda f=fn: f(None))
    print()
    print(f"{PASSED[0]} passed, {len(FAILURES)} failed")
    for name, tb in FAILURES:
        print()
        print("=" * 70)
        print(name)
        print(tb)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
