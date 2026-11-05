#!/usr/bin/env python3
"""Hub tests for the L41 edge broker (Round CF revision).

Exercises the REAL control-plane source: the hub module is extracted from the
`cat > "${APP_DIR}/main.py" <<'PYEOF'` heredoc of the patched
wins_control_plane_setup_ONETOUCH.sh by the shared harness
(server/test_account_deletion_hub.py). Cloudflare is an in-memory fake
injected in place of edge_cf_request; no test touches the network or a real
credential.

Properties under test:
  * subjects act only on canonical hostnames the operator assigned to them;
  * the reservation inventory is operator-owned and fail-closed (503 until
    attested; any change clears the attestation);
  * assignments and the inventory accept only EDGE_ADMIN_TOKEN, never the
    fleet ADMIN_TOKEN and never a node token;
  * plaintext exceptions are exact (hostname, path, subject) pairs: a second
    node's path never becomes an exception on the first node's hostname;
  * rollback verifies the complete recorded state before mutating either the
    redirect rule or Always Use HTTPS, returns 409 with no mutation on any
    conflict, and restores the setting only when no retained exception needs
    it off;
  * every Cloudflare call runs under a lease that is fenced before the call;
    an expired or lost lease stops the operation with no further mutation;
  * responses, logs and the hub database never carry the Cloudflare token or
    the hub origin address.

Anti-vacuity: four checks are re-run against deliberate mutations and must
FAIL there: a permissive assignment table, a host-set x path-set renderer, a
rollback that skips state verification, and a lease fence that never fences.
Round CF Turn 2 adds: an unassignment landing between authorization and the
Cloudflare mutation must stop the operation with no mutation (DNS, ACME,
Origin CA, plaintext exception); an operator assignment change must wait for a
running operation; after a lost lease no further Cloudflare call, not even a
read, is made.

Run:  python3 server/test_edge_broker_hub.py [path/to/wins_control_plane_setup_ONETOUCH.sh]
"""
import sys
sys.dont_write_bytecode = True  # keep the server/ tree free of .pyc files

import copy
import io
import json
import logging
import os
import re
import traceback
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
# In the repo this file sits in server/ next to the shared harness; a copy run
# from elsewhere points WINS_REPO_SERVER_DIR at a server/ directory.
REPO_SERVER = os.environ.get("WINS_REPO_SERVER_DIR") or HERE
sys.path.insert(0, REPO_SERVER)

import test_account_deletion_hub as harness  # noqa: E402
from test_account_deletion_hub import FakeRequest, HTTPException  # noqa: E402

PATCHED_HUB = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "wins_control_plane_setup_ONETOUCH.sh")
harness.HUB = os.path.abspath(PATCHED_HUB)

ZONE = "edge-zone.example"
ZONE_ID = "ab" * 16
FAKE_CREDENTIAL = "fake-appzone-credential-NOT-REAL-7f3a91c2"
EDGE_ADMIN = "fake-edge-admin-credential-0123456789abcdef"
FLEET_ADMIN = "test-admin-token"
HUB_ORIGIN_IP = "203.0.113.77"
HUB_ROUTE = f"hubroute.{ZONE}"
PUBLIC_A = "1.1.1.1"
PUBLIC_B = "9.9.9.9"
CSR = ("-----BEGIN CERTIFICATE REQUEST-----\n" + ("QUJD" * 16 + "\n") * 4
       + "-----END CERTIFICATE REQUEST-----\n")
VALIDATION = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
PAIR_RE = re.compile(r'\(http\.host eq "([^"]+)" and http\.request\.uri\.path eq "([^"]+)"\)')

FAILURES = []
PASSED = [0]
RESPONSES = []
DETAILS = []


class FakeCloudflare:
    """dns_records, certificates, the dynamic-redirect entrypoint, rulesets,
    rules and always_use_https. Anything else answers 404. `hooks` run before
    a matching call, so a test can change state mid-operation."""

    def __init__(self):
        self.records = {}
        self.ruleset = None
        self.auh = "on"
        self.calls = []
        self.fail = []
        self.hooks = []
        self.seq = 0

    def _id(self):
        self.seq += 1
        return f"id{self.seq:05d}"

    @staticmethod
    def ok(result):
        return 200, {"success": True, "errors": [], "result": result}

    @staticmethod
    def err(status):
        return status, {"success": False, "errors": [{"code": 1000, "message": "fake"}], "result": None}

    def mutations(self):
        return [c for c in self.calls if c[0] != "GET"]

    def __call__(self, method, path, payload=None):
        for index, (m, fragment, fn) in enumerate(list(self.hooks)):
            if m == method and fragment in path:
                del self.hooks[index]
                fn()
                break
        self.calls.append((method, path, copy.deepcopy(payload)))
        for index, (m, fragment) in enumerate(self.fail):
            if m == method and fragment in path:
                del self.fail[index]
                return self.err(400)
        split = urllib.parse.urlsplit("/" + path.lstrip("/"))
        parts = split.path.strip("/").split("/")
        query = dict(urllib.parse.parse_qsl(split.query))
        if parts == ["certificates"] and method == "POST":
            return self.ok({"id": self._id(), "certificate": "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
                            "hostnames": payload["hostnames"], "expires_on": "2028-09-24"})
        if parts[:2] != ["zones", ZONE_ID]:
            return self.err(404)
        rest = parts[2:]
        if rest == ["dns_records"]:
            if method == "GET":
                rows = [r for r in self.records.values()
                        if r["name"] == query.get("name") and (not query.get("type") or r["type"] == query["type"])]
                return self.ok(copy.deepcopy(rows))
            if method == "POST":
                rid = self._id()
                self.records[rid] = dict(payload, id=rid)
                return self.ok(copy.deepcopy(self.records[rid]))
        if len(rest) == 2 and rest[0] == "dns_records" and rest[1] in self.records:
            if method == "PUT":
                self.records[rest[1]] = dict(payload, id=rest[1])
                return self.ok(copy.deepcopy(self.records[rest[1]]))
            if method == "DELETE":
                del self.records[rest[1]]
                return self.ok({"id": rest[1]})
        if rest == ["settings", "always_use_https"]:
            if method == "PATCH":
                self.auh = payload["value"]
            return self.ok({"id": "always_use_https", "value": self.auh})
        if rest == ["rulesets", "phases", "http_request_dynamic_redirect", "entrypoint"] and method == "GET":
            return self.ok(copy.deepcopy(self.ruleset)) if self.ruleset else self.err(404)
        if rest == ["rulesets"] and method == "POST":
            self.ruleset = {"id": self._id(), "phase": payload["phase"],
                            "rules": [dict(rule, id=self._id()) for rule in payload["rules"]]}
            return self.ok(copy.deepcopy(self.ruleset))
        if self.ruleset and len(rest) >= 2 and rest[0] == "rulesets" and rest[1] == self.ruleset["id"]:
            if rest[2:] == ["rules"] and method == "POST":
                self.ruleset["rules"].append(dict(payload, id=self._id()))
                return self.ok(copy.deepcopy(self.ruleset))
            if len(rest) == 4 and rest[2] == "rules":
                for index, rule in enumerate(self.ruleset["rules"]):
                    if rule["id"] == rest[3]:
                        if method == "PATCH":
                            self.ruleset["rules"][index] = dict(payload, id=rule["id"])
                            return self.ok(copy.deepcopy(self.ruleset))
                        if method == "DELETE":
                            del self.ruleset["rules"][index]
                            return self.ok(copy.deepcopy(self.ruleset))
        return self.err(404)


def check(name, fn):
    try:
        fn()
        PASSED[0] += 1
        print(f"PASS: {name}")
    except Exception:
        FAILURES.append(name)
        print(f"FAIL: {name}")
        traceback.print_exc()


def expect_status(call, status):
    try:
        result = call()
    except HTTPException as exc:
        assert exc.status_code == status, f"expected HTTP {status}, got {exc.status_code}: {exc.detail}"
        DETAILS.append(str(exc.detail))
        return exc
    raise AssertionError(f"expected HTTP {status}, but the call succeeded: {result}")


def rec(result):
    RESPONSES.append(json.dumps(result, default=str))
    return result


MOD = harness.load_hub(
    CLOUDFLARE_APPCLOUD_API_TOKEN=FAKE_CREDENTIAL,
    CLOUDFLARE_APPCLOUD_ZONE_ID=ZONE_ID,
    CLOUDFLARE_APPCLOUD_ZONE_NAME=ZONE,
    CLOUDFLARE_APPCLOUD_RECORDS=HUB_ROUTE,
    CLOUDFLARE_RETIRED_APPCLOUD_HUB_RECORDS=f"{ZONE} sync.{ZONE}",
    EDGE_ADMIN_TOKEN=EDGE_ADMIN,
    IONOS_HUB_IP=HUB_ORIGIN_IP,
)
LOG = io.StringIO()
_handler = logging.StreamHandler(LOG)
_handler.setLevel(logging.DEBUG)
MOD.logger.addHandler(_handler)
MOD.logger.setLevel(logging.DEBUG)
REAL_EDGE_CF_REQUEST = MOD.edge_cf_request


def fresh_cf():
    fake = FakeCloudflare()
    MOD.edge_cf_request = fake
    return fake


def req():
    return FakeRequest(headers={"user-agent": "edge-test"})


def new_node(slug):
    with MOD.get_db() as conn:
        MOD.ensure_schema(conn)
        grant = MOD.create_bootstrap_grant(conn, "node", slug)
    return MOD.bootstrap_node(MOD.NodeBootstrapRequest(slug=slug, bootstrap_token=grant), req())["node_token"]


def new_core(core_id):
    with MOD.get_db() as conn:
        MOD.ensure_schema(conn)
        grant = MOD.create_bootstrap_grant(conn, "core", core_id)
    return MOD.bootstrap_core(MOD.CoreBootstrapRequest(core_id=core_id, bootstrap_token=grant), req())["core_token"]


def reservations(action, hostnames=None, token=EDGE_ADMIN):
    return rec(MOD.admin_edge_reservations(MOD.EdgeReservationRequest(action=action, hostnames=hostnames or []),
                                           req(), x_edge_admin_token=token))


def bind(kind, subject, hostnames, action="bind", token=EDGE_ADMIN, remove_exceptions=None):
    extra = {} if remove_exceptions is None else {"remove_exceptions": remove_exceptions}
    return rec(MOD.admin_edge_hostname_bindings(
        MOD.EdgeHostnameBindingRequest(subject_kind=kind, subject_id=subject, hostnames=hostnames, action=action, **extra),
        req(), x_edge_admin_token=token))


def dns(slug, token, hostnames, ipv4=PUBLIC_A):
    return rec(MOD.node_edge_dns(slug, MOD.EdgeDnsRequest(hostnames=hostnames, ipv4=ipv4), req(), x_node_token=token))


def exempt(slug, token, path, hostnames=None):
    return rec(MOD.node_edge_plaintext_exemption(
        slug, MOD.EdgePlaintextExemptionRequest(path=path, hostnames=hostnames or []), req(), x_node_token=token))


def rollback(slug, token, txn):
    return rec(MOD.node_edge_plaintext_exemption_rollback(slug, txn, req(), x_node_token=token))


def commit(slug, token, txn):
    return rec(MOD.node_edge_plaintext_exemption_commit(slug, txn, req(), x_node_token=token))


def managed_rule(cf):
    return [r for r in (cf.ruleset or {}).get("rules", []) if r.get("ref") == MOD.EDGE_REDIRECT_RULE_REF]


def rule_pairs(cf):
    rules = managed_rule(cf)
    return set(PAIR_RE.findall(rules[0]["expression"])) if rules else set()


def clear_exceptions():
    with MOD.edge_db() as conn:
        conn.execute("DELETE FROM edge_plaintext_exceptions")
        conn.execute("DELETE FROM edge_redirect_transactions")
        conn.execute("DELETE FROM edge_zone_state WHERE key = 'baseline_always_use_https'")
        conn.execute("DELETE FROM edge_zone_leases")


TOK_A = new_node("node-a")
TOK_B = new_node("node-b")
HA = f"node-a.{ZONE}"
HB = f"node-b.{ZONE}"


# ------------------------------------------------------------------ tests ---

def t_wire_request_carries_bearer_only_in_header():
    captured = {}

    class Opener:
        def open(self, request, timeout=0):
            captured["url"] = request.full_url
            captured["headers"] = dict(request.header_items())
            captured["data"] = request.data or b""
            raise MOD.urllib.error.URLError("offline test")

    saved = MOD._CLOUDFLARE_NO_REDIRECT_OPENER
    MOD._CLOUDFLARE_NO_REDIRECT_OPENER = Opener()
    try:
        expect_status(lambda: REAL_EDGE_CF_REQUEST("POST", f"zones/{ZONE_ID}/dns_records", {"name": "x"}), 502)
    finally:
        MOD._CLOUDFLARE_NO_REDIRECT_OPENER = saved
    assert captured["url"].startswith("https://api.cloudflare.com/client/v4/zones/")
    assert FAKE_CREDENTIAL not in captured["url"] and FAKE_CREDENTIAL.encode() not in captured["data"]
    assert captured["headers"].get("Authorization") == f"Bearer {FAKE_CREDENTIAL}"


def t_inventory_fail_closed_until_attested():
    cf = fresh_cf()
    expect_status(lambda: MOD.node_edge_hostnames("node-a", req(), x_node_token=TOK_A), 503)
    expect_status(lambda: dns("node-a", TOK_A, [HA]), 503)
    expect_status(lambda: bind("node", "node-a", [f"x.{ZONE}"]), 503)
    assert not cf.calls
    out = reservations("attest")
    assert out["attested"] is True and ZONE in out["reserved"] and HUB_ROUTE in out["reserved"], out
    assert rec(MOD.node_edge_hostnames("node-a", req(), x_node_token=TOK_A))["hostnames"] == [HA]
    # Any inventory change clears the attestation until the operator attests again.
    out = reservations("add", [f"live-hub.{ZONE}"])
    assert out["attested"] is False
    expect_status(lambda: MOD.node_edge_hostnames("node-a", req(), x_node_token=TOK_A), 503)
    assert reservations("attest")["attested"] is True


def t_binding_admin_is_edge_only():
    fresh_cf()
    expect_status(lambda: bind("node", "node-a", [f"a2.{ZONE}"], token=FLEET_ADMIN), 401)
    expect_status(lambda: bind("node", "node-a", [f"a2.{ZONE}"], token=TOK_A), 401)
    expect_status(lambda: bind("node", "node-a", [f"a2.{ZONE}"], token=None), 401)
    expect_status(lambda: reservations("remove", [f"live-hub.{ZONE}"], token=FLEET_ADMIN), 401)
    saved = MOD.EDGE_ADMIN_TOKEN
    try:
        MOD.EDGE_ADMIN_TOKEN = ""
        expect_status(lambda: bind("node", "node-a", [f"a2.{ZONE}"]), 503)
        MOD.EDGE_ADMIN_TOKEN = MOD.ADMIN_SECRET_TOKEN
        expect_status(lambda: bind("node", "node-a", [f"a2.{ZONE}"], token=MOD.ADMIN_SECRET_TOKEN), 503)
    finally:
        MOD.EDGE_ADMIN_TOKEN = saved
    # There is no node-token route that changes an assignment.
    for (method, path) in MOD.app.routes:
        if "hostname-bindings" in path or "reservations" in path or "adopt" in path:
            assert path.startswith("/admin/edge/"), path


def t_dns_default_create_update_unchanged():
    cf = fresh_cf()
    assert dns("node-a", TOK_A, [HA]) == {"ok": True, "records": {HA: "created"}}
    (record,) = cf.records.values()
    assert record["type"] == "A" and record["content"] == PUBLIC_A and record["proxied"] is True and record["ttl"] == 1
    assert dns("node-a", TOK_A, [HA.upper() + "."])["records"][HA] == "unchanged"
    assert dns("node-a", TOK_A, [HA], PUBLIC_B)["records"][HA] == "updated"


def cross_subject_refused():
    cf = fresh_cf()
    expect_status(lambda: dns("node-a", TOK_A, [HB]), 403)
    assert not cf.mutations(), cf.mutations()


def t_dns_cross_subject_refused():
    cross_subject_refused()


def t_anti_vacuity_permissive_mutation_is_caught():
    # Both authorization layers (the request check and the pre-mutation guard)
    # read edge_allowed_hostnames; make it grant every name.
    original = MOD.edge_allowed_hostnames
    MOD.edge_allowed_hostnames = lambda conn, kind, subject: [HA, HB]
    try:
        try:
            cross_subject_refused()
        except AssertionError:
            return
        raise RuntimeError("the cross-subject check passed against a permissive broker: it is vacuous")
    finally:
        MOD.edge_allowed_hostnames = original


def t_reserved_names_refused():
    cf = fresh_cf()
    expect_status(lambda: dns("node-a", TOK_A, [HUB_ROUTE]), 403)
    expect_status(lambda: dns("node-a", TOK_A, [f"sync.{ZONE}"]), 403)
    expect_status(lambda: dns("node-a", TOK_A, [f"live-hub.{ZONE}"]), 403)
    expect_status(lambda: dns("node-a", TOK_A, [ZONE]), 400)
    expect_status(lambda: dns("node-a", TOK_A, ["node-a.other.example"]), 400)
    expect_status(lambda: bind("node", "node-a", [f"live-hub.{ZONE}"]), 403)
    # An inventory row also removes a subject's implicit default name.
    tok = new_node("node-z")
    reservations("add", [f"node-z.{ZONE}"])
    reservations("attest")
    assert rec(MOD.node_edge_hostnames("node-z", req(), x_node_token=tok))["hostnames"] == []
    expect_status(lambda: dns("node-z", tok, [f"node-z.{ZONE}"]), 403)
    # Reserving an assigned name is refused until it is unassigned.
    bind("node", "node-a", [f"alias-r.{ZONE}"])
    expect_status(lambda: reservations("add", [f"alias-r.{ZONE}"]), 409)
    bind("node", "node-a", [f"alias-r.{ZONE}"], action="unbind")
    assert not cf.mutations()


def t_dns_rejects_non_public_ipv4():
    cf = fresh_cf()
    for address in ("10.0.0.7", "127.0.0.1", "169.254.1.1", "100.64.0.1", "224.0.0.1", "0.0.0.0", "not-an-ip", "::1"):
        expect_status(lambda a=address: dns("node-a", TOK_A, [HA], a), 400)
    assert not cf.calls


def t_dns_existing_cname_is_not_overwritten():
    cf = fresh_cf()
    cf.records["pre1"] = {"id": "pre1", "type": "CNAME", "name": HA, "content": "t.cfargotunnel.com", "proxied": True, "ttl": 1}
    expect_status(lambda: dns("node-a", TOK_A, [HA]), 409)
    assert not cf.mutations()


def t_auth_wrong_token_and_retired():
    fresh_cf()
    expect_status(lambda: dns("node-a", TOK_B, [HA]), 401)
    expect_status(lambda: dns("node-a", None, [HA]), 401)
    tok = new_node("node-ret")
    with MOD.get_db() as conn:
        conn.execute("UPDATE nodes SET retired_at = '2026-09-01T00:00:00+00:00' WHERE slug = 'node-ret'")
    expect_status(lambda: dns("node-ret", tok, [f"node-ret.{ZONE}"]), 409)


def t_alias_assignment():
    cf = fresh_cf()
    alias = f"frankfurt.{ZONE}"
    expect_status(lambda: dns("node-a", TOK_A, [alias]), 403)
    assert bind("node", "node-a", [alias])["hostnames"] == [HA, alias]
    assert dns("node-a", TOK_A, [alias])["records"][alias] == "created"
    expect_status(lambda: bind("node", "node-b", [alias]), 409)
    expect_status(lambda: bind("node", "node-a", [HB]), 409)
    expect_status(lambda: dns("node-b", TOK_B, [alias]), 403)
    bind("node", "node-a", [alias], action="unbind")
    expect_status(lambda: dns("node-a", TOK_A, [alias]), 403)
    assert len(cf.records) == 1


def t_slug_core_collision_gets_no_implicit_default():
    fresh_cf()
    tok_node = new_node("dup1")
    tok_core = new_core("dup1")
    assert rec(MOD.node_edge_hostnames("dup1", req(), x_node_token=tok_node))["hostnames"] == []
    assert rec(MOD.core_edge_hostnames("dup1", req(), x_core_token=tok_core))["hostnames"] == []
    bind("core", "dup1", [f"dup1.{ZONE}"])
    assert rec(MOD.core_edge_hostnames("dup1", req(), x_core_token=tok_core))["hostnames"] == [f"dup1.{ZONE}"]
    assert rec(MOD.node_edge_hostnames("dup1", req(), x_node_token=tok_node))["hostnames"] == []


def t_core_endpoints():
    cf = fresh_cf()
    tok = new_core("north-core")
    host = f"north-core.{ZONE}"
    out = rec(MOD.core_edge_dns("north-core", MOD.EdgeDnsRequest(hostnames=[host], ipv4=PUBLIC_A), req(), x_core_token=tok))
    assert out["records"] == {host: "created"}
    expect_status(lambda: MOD.core_edge_dns("north-core", MOD.EdgeDnsRequest(hostnames=[host], ipv4=PUBLIC_A), req(), x_core_token=TOK_A), 401)
    expect_status(lambda: MOD.core_edge_dns("north-core", MOD.EdgeDnsRequest(hostnames=[HA], ipv4=PUBLIC_A), req(), x_core_token=tok), 403)
    assert len(cf.records) == 1


def origin(slug, token, hostnames, validity=730, csr=CSR, request_type="origin-rsa"):
    return rec(MOD.node_edge_origin_certificate(slug, MOD.EdgeOriginCertificateRequest(
        csr=csr, hostnames=hostnames, requested_validity=validity, request_type=request_type), req(), x_node_token=token))


def t_origin_certificate():
    cf = fresh_cf()
    out = origin("node-a", TOK_A, ["Node-A." + ZONE])
    assert out["ok"] and out["certificate"].startswith("-----BEGIN CERTIFICATE-----")
    (call,) = [c for c in cf.calls if c[1] == "certificates"]
    assert call[2]["hostnames"] == [HA] and call[2]["requested_validity"] == 730
    expect_status(lambda: origin("node-a", TOK_A, [f"*.{ZONE}"]), 400)
    expect_status(lambda: origin("node-a", TOK_A, [HA], validity=12), 400)
    expect_status(lambda: origin("node-a", TOK_A, [HA], request_type="keyless-certificate"), 400)
    expect_status(lambda: origin("node-a", TOK_A, [HB]), 403)
    expect_status(lambda: origin("node-a", TOK_A, [HA], csr="not a csr"), 400)
    assert len([c for c in cf.calls if c[1] == "certificates"]) == 1


def acme(slug, token, action, hostname, validation=VALIDATION):
    return rec(MOD.node_edge_acme_challenge(slug, MOD.EdgeAcmeChallengeRequest(
        action=action, hostname=hostname, validation=validation), req(), x_node_token=token))


def t_acme_challenge():
    cf = fresh_cf()
    assert acme("node-a", TOK_A, "present", HA)["state"] == "created"
    assert acme("node-a", TOK_A, "present", HA)["state"] == "present"
    txt = [r for r in cf.records.values() if r["type"] == "TXT"]
    assert len(txt) == 1 and txt[0]["name"] == f"_acme-challenge.{HA}" and txt[0]["content"] == VALIDATION
    other = "Z" * 43
    acme("node-a", TOK_A, "present", HA, other)
    assert acme("node-a", TOK_A, "cleanup", HA)["removed"] == 1
    assert [r["content"] for r in cf.records.values() if r["type"] == "TXT"] == [other]
    expect_status(lambda: acme("node-a", TOK_A, "present", HA, "short"), 400)
    expect_status(lambda: acme("node-a", TOK_A, "present", HB), 403)
    expect_status(lambda: acme("node-a", TOK_A, "upsert", HA), 400)
    for n in range(3):
        acme("node-a", TOK_A, "present", HA, chr(ord("a") + n) * 43)
    expect_status(lambda: acme("node-a", TOK_A, "present", HA, "q" * 43), 409)


def t_pairs_are_exact_across_subjects():
    cf = fresh_cf()
    clear_exceptions()
    exempt("node-a", TOK_A, "/a")
    exempt("node-b", TOK_B, "/b")
    assert rule_pairs(cf) == {(HA, "/a"), (HB, "/b")}, rule_pairs(cf)
    assert (HA, "/b") not in rule_pairs(cf) and (HB, "/a") not in rule_pairs(cf)
    expression = managed_rule(cf)[0]["expression"]
    assert expression.startswith("(not ssl and not (") and " in {" not in expression, expression


def t_setting_restored_only_when_no_exception_remains():
    cf = fresh_cf()
    clear_exceptions()
    assert cf.auh == "on"
    txn_a = exempt("node-a", TOK_A, "/a")["transaction_id"]
    assert cf.auh == "off"
    txn_b = exempt("node-b", TOK_B, "/b")["transaction_id"]
    rollback("node-a", TOK_A, txn_a)
    assert cf.auh == "off", "a retained exception still needs Always Use HTTPS off"
    assert rule_pairs(cf) == {(HB, "/b")}
    rollback("node-b", TOK_B, txn_b)
    assert cf.auh == "on" and not managed_rule(cf), (cf.auh, managed_rule(cf))


def t_rollback_conflict_on_setting_is_409_without_mutation():
    cf = fresh_cf()
    clear_exceptions()
    txn_a = exempt("node-a", TOK_A, "/a")["transaction_id"]
    exempt("node-b", TOK_B, "/b")
    cf.auh = "on"  # changed outside the broker
    before = copy.deepcopy((cf.ruleset, cf.auh))
    count = len(cf.mutations())
    expect_status(lambda: rollback("node-a", TOK_A, txn_a), 409)
    assert len(cf.mutations()) == count and (cf.ruleset, cf.auh) == before
    with MOD.edge_db() as conn:
        assert conn.execute("SELECT state FROM edge_redirect_transactions WHERE transaction_id = ?", (txn_a,)).fetchone()["state"] == "armed"


def t_rollback_conflict_on_rule_is_409_without_mutation():
    cf = fresh_cf()
    clear_exceptions()
    txn_a = exempt("node-a", TOK_A, "/a")["transaction_id"]
    managed_rule(cf)[0]["expression"] = '(not ssl and not ((http.host eq "evil.example" and http.request.uri.path eq "/x")))'
    count = len(cf.mutations())
    expect_status(lambda: rollback("node-a", TOK_A, txn_a), 409)
    expect_status(lambda: exempt("node-b", TOK_B, "/b"), 409)
    assert len(cf.mutations()) == count


def t_legacy_rule_needs_operator_adoption():
    cf = fresh_cf()
    clear_exceptions()
    legacy = f'(not ssl and not ((http.host in {{"{HA}" "{HB}"}}) and (http.request.uri.path in {{"/a" "/b"}})))'
    cf.ruleset = {"id": "rs-legacy", "phase": "http_request_dynamic_redirect",
                  "rules": [dict(MOD.edge_redirect_rule(legacy), id="rule-legacy")]}
    cf.auh = "off"
    expect_status(lambda: exempt("node-a", TOK_A, "/a"), 409)
    assert not cf.mutations()
    adopt = lambda expected, token=EDGE_ADMIN: rec(MOD.admin_edge_plaintext_adopt(MOD.EdgePlaintextAdoptRequest(
        pairs=[{"hostname": HA, "path": "/a", "subject_kind": "node", "subject_id": "node-a"},
               {"hostname": HB, "path": "/b", "subject_kind": "node", "subject_id": "node-b"}],
        expected_expression=expected, baseline_always_use_https="on"), req(), x_edge_admin_token=token))
    expect_status(lambda: adopt(legacy, token=FLEET_ADMIN), 401)
    expect_status(lambda: adopt("something else"), 409)
    assert not cf.mutations()
    assert adopt(legacy)["adopted"] == 2
    assert rule_pairs(cf) == {(HA, "/a"), (HB, "/b")}
    # The legacy cross pairs (A, /b) and (B, /a) are gone.
    assert out_ok(exempt("node-a", TOK_A, "/a"))
    expect_status(lambda: adopt(legacy), 409)


def out_ok(result):
    return result.get("ok") is True


def t_lease_expiry_stops_before_mutation():
    cf = fresh_cf()
    clear_exceptions()

    def expire():
        with MOD.edge_db() as conn:
            conn.execute("UPDATE edge_zone_leases SET expires_at = '2000-01-01T00:00:00+00:00'")

    cf.hooks.append(("GET", "settings/always_use_https", expire))
    expect_status(lambda: exempt("node-a", TOK_A, "/a"), 409)
    assert not cf.mutations(), cf.mutations()
    with MOD.edge_db() as conn:
        states = {row["state"] for row in conn.execute("SELECT state FROM edge_redirect_transactions").fetchall()}
    assert "armed" not in states, states
    # Rollback path: the lease expires after verification, before any mutation.
    txn = exempt("node-a", TOK_A, "/a")["transaction_id"]
    count = len(cf.mutations())
    cf.hooks.append(("GET", "settings/always_use_https", expire))
    expect_status(lambda: rollback("node-a", TOK_A, txn), 409)
    assert len(cf.mutations()) == count


def t_expired_lease_of_another_writer_is_taken_over():
    cf = fresh_cf()
    clear_exceptions()
    with MOD.edge_db() as conn:
        conn.execute("INSERT INTO edge_zone_leases (name, holder, expires_at) VALUES ('zone', 'stale', '2000-01-01T00:00:00+00:00')")
    assert exempt("node-a", TOK_A, "/a")["added"] == 1
    with MOD.edge_db() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM edge_zone_leases").fetchone()["n"] == 0


def t_live_lease_blocks_second_writer():
    fresh_cf()
    clear_exceptions()
    saved = MOD.EDGE_ZONE_LEASE_WAIT_SECONDS
    MOD.EDGE_ZONE_LEASE_WAIT_SECONDS = 0
    try:
        with MOD.edge_db() as conn:
            conn.execute("INSERT INTO edge_zone_leases (name, holder, expires_at) VALUES ('zone', 'other', '2999-01-01T00:00:00+00:00')")
        expect_status(lambda: exempt("node-a", TOK_A, "/a"), 409)
    finally:
        MOD.EDGE_ZONE_LEASE_WAIT_SECONDS = saved
        clear_exceptions()


def t_internal_failure_is_undone_by_hub():
    cf = fresh_cf()
    clear_exceptions()
    cf.fail.append(("PATCH", "settings/always_use_https"))
    expect_status(lambda: exempt("node-a", TOK_A, "/a"), 502)
    assert not managed_rule(cf) and cf.auh == "on"
    with MOD.edge_db() as conn:
        assert conn.execute("SELECT state FROM edge_redirect_transactions ORDER BY created_at DESC LIMIT 1").fetchone()["state"] == "rolled_back"


def t_transaction_ownership_and_states():
    cf = fresh_cf()
    clear_exceptions()
    txn = exempt("node-a", TOK_A, "/a")["transaction_id"]
    expect_status(lambda: rollback("node-b", TOK_B, txn), 404)
    expect_status(lambda: commit("node-b", TOK_B, txn), 404)
    expect_status(lambda: rollback("node-a", TOK_A, "not-a-txn"), 400)
    assert commit("node-a", TOK_A, txn)["state"] == "committed"
    assert commit("node-a", TOK_A, txn)["state"] == "committed"
    expect_status(lambda: rollback("node-a", TOK_A, txn), 409)
    count = len(cf.mutations())
    again = exempt("node-a", TOK_A, "/a")
    assert again["added"] == 0 and len(cf.mutations()) == count
    expect_status(lambda: exempt("node-a", TOK_A, "no-slash"), 400)
    expect_status(lambda: exempt("node-a", TOK_A, '/x"y'), 400)
    expect_status(lambda: exempt("node-a", TOK_A, "/w", [HB]), 403)


def t_bootstrap_grant_ttl_bounds():
    grant = lambda ttl: MOD.mint_bootstrap_grant(MOD.BootstrapGrantRequest(role="node", subject_id="node-new", ttl_seconds=ttl),
                                                 req(), x_admin_token=FLEET_ADMIN)
    assert grant(0)["expires_in_seconds"] == 600
    assert grant(3600)["expires_in_seconds"] == 3600
    expect_status(lambda: grant(3601), 400)
    expect_status(lambda: grant(30), 400)


def t_unconfigured_zone_is_503():
    fresh_cf()
    saved = MOD.CLOUDFLARE_APPCLOUD_API_TOKEN
    MOD.CLOUDFLARE_APPCLOUD_API_TOKEN = ""
    try:
        expect_status(lambda: dns("node-a", TOK_A, [HA]), 503)
    finally:
        MOD.CLOUDFLARE_APPCLOUD_API_TOKEN = saved


def t_no_token_or_origin_address_leaks():
    for secret in (FAKE_CREDENTIAL, HUB_ORIGIN_IP, EDGE_ADMIN):
        assert secret not in LOG.getvalue(), f"leak in hub log output: {secret[:6]}"
        for blob in RESPONSES + DETAILS:
            assert secret not in blob, f"leak in a response or error detail: {secret[:6]}"
    assert len(RESPONSES) > 20, "the leak check needs responses to inspect"
    for root, _dirs, files in os.walk(MOD._TMPDIR):
        for name in files:
            with open(os.path.join(root, name), "rb") as handle:
                data = handle.read()
            assert FAKE_CREDENTIAL.encode() not in data and EDGE_ADMIN.encode() not in data, f"leak in {name}"


# --- Round CF Turn 2: assignment changes cannot race a subject operation ----

def unbind_right_after_authorization(host):
    """Wrap edge_require_hostnames so the operator's unassignment lands in the
    gap between the subject's authorization and its Cloudflare mutation."""
    original = MOD.edge_require_hostnames

    def racing(conn, kind, subject, hostnames, request=None):
        result = original(conn, kind, subject, hostnames, request)
        conn.execute("DELETE FROM edge_hostname_bindings WHERE hostname = ?", (host,))
        return result

    MOD.edge_require_hostnames = racing
    return original


def assert_no_mutation_after_unbind(call, host, rebind=True):
    cf = fresh_cf()
    clear_exceptions()
    if rebind:
        bind("node", "node-a", [host])
    original = unbind_right_after_authorization(host)
    try:
        try:
            call()
        except HTTPException as exc:
            assert exc.status_code in {403, 409}, exc.status_code
            DETAILS.append(str(exc.detail))
        else:
            raise AssertionError("the operation completed after its hostname was unassigned")
    finally:
        MOD.edge_require_hostnames = original
    assert not cf.mutations(), cf.mutations()


def t_unassigned_name_dns_is_refused_before_mutation():
    alias = f"race-dns.{ZONE}"
    assert_no_mutation_after_unbind(lambda: dns("node-a", TOK_A, [alias]), alias)


def t_unassigned_name_acme_is_refused_before_mutation():
    alias = f"race-acme.{ZONE}"
    assert_no_mutation_after_unbind(lambda: acme("node-a", TOK_A, "present", alias), alias)


def t_unassigned_name_origin_is_refused_before_mutation():
    alias = f"race-origin.{ZONE}"
    assert_no_mutation_after_unbind(lambda: origin("node-a", TOK_A, [alias]), alias)


def t_unassigned_name_exemption_is_refused_before_mutation():
    alias = f"race-exempt.{ZONE}"
    assert_no_mutation_after_unbind(lambda: exempt("node-a", TOK_A, "/r", [alias]), alias)


def t_assignment_change_waits_for_a_running_operation():
    cf = fresh_cf()
    alias = f"race-lock.{ZONE}"
    bind("node", "node-a", [alias])
    outcome = {}

    def operator_unbinds():
        try:
            bind("node", "node-a", [alias], action="unbind")
            outcome["unbind"] = "applied"
        except HTTPException as exc:
            outcome["unbind"] = exc.status_code

    cf.hooks.append(("GET", "dns_records", operator_unbinds))
    saved = MOD.EDGE_ZONE_LEASE_WAIT_SECONDS
    MOD.EDGE_ZONE_LEASE_WAIT_SECONDS = 0
    try:
        assert dns("node-a", TOK_A, [alias])["records"][alias] == "created"
    finally:
        MOD.EDGE_ZONE_LEASE_WAIT_SECONDS = saved
    assert outcome.get("unbind") == 409, outcome
    bind("node", "node-a", [alias], action="unbind")


def t_reads_after_lease_loss_are_not_made():
    cf = fresh_cf()
    clear_exceptions()

    def expire():
        with MOD.edge_db() as conn:
            conn.execute("UPDATE edge_zone_leases SET expires_at = '2000-01-01T00:00:00+00:00'")
        marker["calls"] = len(cf.calls)

    marker = {}
    cf.hooks.append(("GET", "rulesets/phases", expire))
    expect_status(lambda: exempt("node-a", TOK_A, "/a"), 409)
    # The entrypoint read itself is the call during which the lease expired;
    # nothing, not even a read, may follow it.
    assert len(cf.calls) == marker["calls"] + 1, cf.calls[marker["calls"]:]


# --- Round CF Turn 3: an exception pair pins its hostname -------------------

def binding_owner(host):
    with MOD.edge_db() as conn:
        row = conn.execute("SELECT subject_kind, subject_id FROM edge_hostname_bindings WHERE hostname = ?", (host,)).fetchone()
    return (row["subject_kind"], row["subject_id"]) if row else None


def t_unbind_refused_while_alias_has_exception():
    cf = fresh_cf()
    clear_exceptions()
    alias = f"pin-a.{ZONE}"
    bind("node", "node-a", [alias])
    commit("node-a", TOK_A, exempt("node-a", TOK_A, "/pin", [alias])["transaction_id"])
    count = len(cf.mutations())
    expect_status(lambda: bind("node", "node-a", [alias], action="unbind"), 409)
    assert (alias, "/pin") in rule_pairs(cf) and binding_owner(alias) == ("node", "node-a")
    assert len(cf.mutations()) == count
    # Nor can another subject take it over while the exception exists.
    expect_status(lambda: bind("node", "node-b", [alias]), 409)
    bind("node", "node-a", [alias], action="unbind", remove_exceptions=True)
    clear_exceptions()


def t_unbind_with_removal_clears_the_exception_first():
    cf = fresh_cf()
    clear_exceptions()
    alias = f"pin-b.{ZONE}"
    bind("node", "node-a", [alias])
    assert cf.auh == "on"
    commit("node-a", TOK_A, exempt("node-a", TOK_A, "/pin", [alias])["transaction_id"])
    assert (alias, "/pin") in rule_pairs(cf) and cf.auh == "off"
    bind("node", "node-a", [alias], action="unbind", remove_exceptions=True)
    assert (alias, "/pin") not in rule_pairs(cf), rule_pairs(cf)
    assert cf.auh == "on", "no exception remains, so the recorded baseline is restored"
    assert binding_owner(alias) is None
    assert bind("node", "node-b", [alias])["hostnames"][-1] == alias
    assert rule_pairs(cf) == set()
    bind("node", "node-b", [alias], action="unbind")


def t_unbind_removal_keeps_other_subjects_pairs():
    cf = fresh_cf()
    clear_exceptions()
    alias = f"pin-c.{ZONE}"
    bind("node", "node-a", [alias])
    commit("node-a", TOK_A, exempt("node-a", TOK_A, "/pin", [alias])["transaction_id"])
    commit("node-b", TOK_B, exempt("node-b", TOK_B, "/b")["transaction_id"])
    bind("node", "node-a", [alias], action="unbind", remove_exceptions=True)
    assert rule_pairs(cf) == {(HB, "/b")} and cf.auh == "off"
    clear_exceptions()


def t_bind_refused_while_any_exception_names_the_hostname():
    fresh_cf()
    clear_exceptions()
    alias = f"pin-d.{ZONE}"
    with MOD.edge_db() as conn:
        conn.execute(
            "INSERT INTO edge_plaintext_exceptions (hostname, path, subject_kind, subject_id, transaction_id, state, created_at) "
            "VALUES (?, '/stale', 'node', 'node-a', ?, 'committed', '2026-09-25T00:00:00')",
            (alias, "f" * 32),
        )
    expect_status(lambda: bind("node", "node-b", [alias]), 409)
    assert binding_owner(alias) is None
    clear_exceptions()


def t_commit_rechecks_assignment():
    fresh_cf()
    clear_exceptions()
    alias = f"pin-e.{ZONE}"
    bind("node", "node-a", [alias])
    txn = exempt("node-a", TOK_A, "/pin", [alias])["transaction_id"]
    with MOD.edge_db() as conn:
        conn.execute("DELETE FROM edge_hostname_bindings WHERE hostname = ?", (alias,))
    try:
        commit("node-a", TOK_A, txn)
    except HTTPException as exc:
        assert exc.status_code in {403, 409}, exc.status_code
        DETAILS.append(str(exc.detail))
    else:
        raise AssertionError("commit succeeded for a hostname no longer assigned to the subject")
    with MOD.edge_db() as conn:
        assert conn.execute("SELECT state FROM edge_redirect_transactions WHERE transaction_id = ?", (txn,)).fetchone()["state"] == "armed"
    rollback("node-a", TOK_A, txn)
    clear_exceptions()


def txn_state(txn):
    with MOD.edge_db() as conn:
        return conn.execute("SELECT state FROM edge_redirect_transactions WHERE transaction_id = ?", (txn,)).fetchone()["state"]


def t_commit_after_unbind_removal_is_refused():
    # Round CF Turn 4, CF-2: begin, unbind the alias with remove_exceptions,
    # then commit. The unbind turns the armed pair into removed_on_unbind, so
    # no armed pair names the lost hostname; commit must still refuse (409),
    # judged on the transaction's ORIGINAL opened hostname set, and leave the
    # transaction armed for rollback.
    cf = fresh_cf()
    clear_exceptions()
    alias = f"pin-f.{ZONE}"
    bind("node", "node-a", [alias])
    txn = exempt("node-a", TOK_A, "/pin", [alias])["transaction_id"]
    bind("node", "node-a", [alias], action="unbind", remove_exceptions=True)
    assert binding_owner(alias) is None and rule_pairs(cf) == set()
    count = len(cf.mutations())
    expect_status(lambda: commit("node-a", TOK_A, txn), 409)
    assert txn_state(txn) == "armed", "the refused transaction is left for rollback"
    assert len(cf.mutations()) == count, "a refused commit makes no Cloudflare call"
    assert rollback("node-a", TOK_A, txn)["state"] == "rolled_back"
    assert rule_pairs(cf) == set() and cf.auh == "on"
    clear_exceptions()


def t_commit_after_partial_unbind_removal_is_refused():
    # The same when the transaction opened the default name and an alias and
    # only the alias was unbound: the surviving armed pair must not let the
    # transaction commit as if nothing were lost.
    cf = fresh_cf()
    clear_exceptions()
    alias = f"pin-g.{ZONE}"
    bind("node", "node-a", [alias])
    txn = exempt("node-a", TOK_A, "/pin", [HA, alias])["transaction_id"]
    assert rule_pairs(cf) == {(HA, "/pin"), (alias, "/pin")}, rule_pairs(cf)
    bind("node", "node-a", [alias], action="unbind", remove_exceptions=True)
    assert rule_pairs(cf) == {(HA, "/pin")}, rule_pairs(cf)
    expect_status(lambda: commit("node-a", TOK_A, txn), 409)
    assert txn_state(txn) == "armed"
    assert rollback("node-a", TOK_A, txn)["state"] == "rolled_back"
    assert rule_pairs(cf) == set() and cf.auh == "on"
    clear_exceptions()


def txn_count():
    with MOD.edge_db() as conn:
        return conn.execute("SELECT COUNT(*) AS n FROM edge_redirect_transactions").fetchone()["n"]


def t_repeat_exemption_is_idempotent():
    # Round CF Turn 5, CF-2: a repeat installer run with an unchanged plaintext
    # exception must not open a zero-pair transaction whose commit can never
    # succeed. It creates no transaction and reports the committed state.
    cf = fresh_cf()
    clear_exceptions()
    txn = exempt("node-a", TOK_A, "/r")["transaction_id"]
    assert commit("node-a", TOK_A, txn)["state"] == "committed"
    count, txns = len(cf.mutations()), txn_count()
    again = exempt("node-a", TOK_A, "/r")
    assert again["ok"] is True and again["added"] == 0, again
    assert again["transaction_id"] is None and again["state"] == "committed", again
    assert txn_count() == txns, "a repeat request creates no transaction"
    assert len(cf.mutations()) == count
    assert rule_pairs(cf) == {(HA, "/r")}
    clear_exceptions()


def t_repeat_exemption_while_armed_returns_the_open_transaction():
    cf = fresh_cf()
    clear_exceptions()
    txn = exempt("node-a", TOK_A, "/s")["transaction_id"]
    txns = txn_count()
    again = exempt("node-a", TOK_A, "/s")
    assert again["transaction_id"] == txn and again["state"] == "armed" and again["added"] == 0, again
    assert txn_count() == txns
    assert commit("node-a", TOK_A, again["transaction_id"])["state"] == "committed"
    assert rule_pairs(cf) == {(HA, "/s")}
    clear_exceptions()


def t_new_pair_while_own_transaction_is_open_is_refused():
    cf = fresh_cf()
    clear_exceptions()
    alias = f"pin-h.{ZONE}"
    bind("node", "node-a", [alias])
    txn = exempt("node-a", TOK_A, "/t", [HA])["transaction_id"]
    count, txns = len(cf.mutations()), txn_count()
    expect_status(lambda: exempt("node-a", TOK_A, "/t", [HA, alias]), 409)
    assert txn_count() == txns and len(cf.mutations()) == count
    assert rollback("node-a", TOK_A, txn)["state"] == "rolled_back"
    bind("node", "node-a", [alias], action="unbind")
    clear_exceptions()


def refused_without_id(call, txn):
    exc = expect_status(call, 409)
    assert txn not in str(exc.detail), "a refused retry must not hand back the open transaction ID"


def t_retry_subset_of_open_transaction_is_refused():
    # Round CF Turn 6, CF-2: the subject armed (A, /p) and (B, /p), lost its
    # handle, and retries with only A. Returning the open transaction would let
    # the retry commit (B, /p), which it did not ask for.
    cf = fresh_cf()
    clear_exceptions()
    alias = f"pin-i.{ZONE}"
    bind("node", "node-a", [alias])
    txn = exempt("node-a", TOK_A, "/p", [HA, alias])["transaction_id"]
    count, txns = len(cf.mutations()), txn_count()
    refused_without_id(lambda: exempt("node-a", TOK_A, "/p", [HA]), txn)
    assert txn_count() == txns and len(cf.mutations()) == count
    assert txn_state(txn) == "armed"
    assert rollback("node-a", TOK_A, txn)["state"] == "rolled_back"
    assert rule_pairs(cf) == set() and cf.auh == "on"
    bind("node", "node-a", [alias], action="unbind")
    clear_exceptions()


def t_retry_superset_of_open_transaction_is_refused():
    # A request wider than the open transaction is refused too, both when the
    # extra pair is new and when it is already committed by another
    # transaction (the case rev6 answered with the open transaction's ID).
    cf = fresh_cf()
    clear_exceptions()
    alias = f"pin-j.{ZONE}"
    bind("node", "node-a", [alias])
    done = exempt("node-a", TOK_A, "/q", [alias])["transaction_id"]
    assert commit("node-a", TOK_A, done)["state"] == "committed"
    txn = exempt("node-a", TOK_A, "/q", [HA])["transaction_id"]
    count, txns = len(cf.mutations()), txn_count()
    refused_without_id(lambda: exempt("node-a", TOK_A, "/q", [HA, alias]), txn)
    other = f"pin-k.{ZONE}"
    bind("node", "node-a", [other])
    refused_without_id(lambda: exempt("node-a", TOK_A, "/q", [HA, other]), txn)
    assert txn_count() == txns and len(cf.mutations()) == count
    assert rollback("node-a", TOK_A, txn)["state"] == "rolled_back"
    assert rule_pairs(cf) == {(alias, "/q")}
    clear_exceptions()
    for host in (alias, other):
        bind("node", "node-a", [host], action="unbind")


def t_disjoint_retry_with_open_transaction_is_refused():
    # A request sharing no pair with the subject's open transaction must not
    # open a second transaction beside it (the first would stay unsettled).
    cf = fresh_cf()
    clear_exceptions()
    txn = exempt("node-a", TOK_A, "/d1", [HA])["transaction_id"]
    count, txns = len(cf.mutations()), txn_count()
    refused_without_id(lambda: exempt("node-a", TOK_A, "/d2", [HA]), txn)
    assert txn_count() == txns and len(cf.mutations()) == count
    assert rule_pairs(cf) == {(HA, "/d1")}
    # Once the open transaction is settled, the same request proceeds.
    assert rollback("node-a", TOK_A, txn)["state"] == "rolled_back"
    fresh = exempt("node-a", TOK_A, "/d2", [HA])
    assert fresh["added"] == 1 and fresh["transaction_id"] not in (None, txn)
    assert commit("node-a", TOK_A, fresh["transaction_id"])["state"] == "committed"
    clear_exceptions()


def t_all_committed_request_with_disjoint_open_transaction_is_refused():
    # Round CF Turn 7, CF-2: commit (A, /p), arm a disjoint (A, /o), then send
    # an all-committed request for (A, /p). The open transaction must not be
    # passed over with the idempotent success: 409, no transaction ID.
    cf = fresh_cf()
    clear_exceptions()
    done = exempt("node-a", TOK_A, "/p", [HA])["transaction_id"]
    assert commit("node-a", TOK_A, done)["state"] == "committed"
    txn = exempt("node-a", TOK_A, "/o", [HA])["transaction_id"]
    count, txns = len(cf.mutations()), txn_count()
    refused_without_id(lambda: exempt("node-a", TOK_A, "/p", [HA]), txn)
    assert txn_count() == txns and len(cf.mutations()) == count
    assert txn_state(txn) == "armed"
    # With no open transaction left, the all-committed reply is idempotent again.
    assert rollback("node-a", TOK_A, txn)["state"] == "rolled_back"
    again = exempt("node-a", TOK_A, "/p", [HA])
    assert again["transaction_id"] is None and again["state"] == "committed", again
    clear_exceptions()


def t_open_transaction_emptied_by_unbind_still_blocks():
    # Sol's second Turn 7 path: remove_exceptions turns the open transaction's
    # only pair into removed_on_unbind, so no live pair shows it; the
    # transaction table still does, and a new request must wait for it.
    cf = fresh_cf()
    clear_exceptions()
    alias = f"pin-l.{ZONE}"
    bind("node", "node-a", [alias])
    txn = exempt("node-a", TOK_A, "/u", [alias])["transaction_id"]
    bind("node", "node-a", [alias], action="unbind", remove_exceptions=True)
    assert txn_state(txn) == "armed" and rule_pairs(cf) == set()
    count, txns = len(cf.mutations()), txn_count()
    refused_without_id(lambda: exempt("node-a", TOK_A, "/v", [HA]), txn)
    assert txn_count() == txns and len(cf.mutations()) == count
    assert rollback("node-a", TOK_A, txn)["state"] == "rolled_back"
    fresh = exempt("node-a", TOK_A, "/v", [HA])
    assert fresh["added"] == 1 and fresh["transaction_id"] not in (None, txn)
    assert rollback("node-a", TOK_A, fresh["transaction_id"])["state"] == "rolled_back"
    clear_exceptions()


def t_zero_pair_transaction_from_older_code_settles():
    # Older code recorded an armed transaction with no pair for a repeat
    # request; the installer then kept it as commit-pending. Its commit (the
    # reconciliation call) must settle it, and so must a rollback.
    cf = fresh_cf()
    clear_exceptions()
    old_commit, old_rollback = "c" * 32, "d" * 32
    with MOD.edge_db() as conn:
        for txn in (old_commit, old_rollback):
            conn.execute(
                "INSERT INTO edge_redirect_transactions (transaction_id, subject_kind, subject_id, state, created_at) "
                "VALUES (?, 'node', 'node-a', 'armed', '2026-09-25T00:00:00')",
                (txn,),
            )
    count = len(cf.mutations())
    assert commit("node-a", TOK_A, old_commit)["state"] == "committed"
    assert txn_state(old_commit) == "committed"
    assert len(cf.mutations()) == count, "settling an empty transaction changes nothing at Cloudflare"
    assert rollback("node-a", TOK_A, old_rollback)["state"] == "rolled_back"
    assert txn_state(old_rollback) == "rolled_back"
    clear_exceptions()


def must_fail_under(mutations, test):
    """Run `test` with module attributes replaced; it must raise."""
    saved = {name: getattr(MOD, name) for name in mutations}
    try:
        for name, value in mutations.items():
            setattr(MOD, name, value)
        try:
            test()
        except (AssertionError, HTTPException):
            return
        raise RuntimeError(f"{test.__name__} still passed with {sorted(mutations)} mutated: it is vacuous")
    finally:
        for name, value in saved.items():
            setattr(MOD, name, value)
        clear_exceptions()


def t_anti_vacuity_cartesian_render_is_caught():
    def cartesian(pairs):
        pairs = list(pairs)
        hosts = sorted({h for h, _p in pairs})
        paths = sorted({p for _h, p in pairs})
        return MOD.__dict__["edge_render_pairs_original"]([(h, p) for h in hosts for p in paths])
    MOD.edge_render_pairs_original = MOD.edge_render_pairs
    must_fail_under({"edge_render_pairs": cartesian}, t_pairs_are_exact_across_subjects)


def t_anti_vacuity_unverified_rollback_is_caught():
    must_fail_under({"edge_verify_recorded_state": lambda current, auh, live: None},
                    t_rollback_conflict_on_setting_is_409_without_mutation)


def t_anti_vacuity_unfenced_lease_is_caught():
    must_fail_under({"edge_lease_fence": lambda lease: None}, t_lease_expiry_stops_before_mutation)


def main():
    tests = [
        t_wire_request_carries_bearer_only_in_header,
        t_inventory_fail_closed_until_attested,
        t_binding_admin_is_edge_only,
        t_dns_default_create_update_unchanged,
        t_dns_cross_subject_refused,
        t_anti_vacuity_permissive_mutation_is_caught,
        t_reserved_names_refused,
        t_dns_rejects_non_public_ipv4,
        t_dns_existing_cname_is_not_overwritten,
        t_auth_wrong_token_and_retired,
        t_alias_assignment,
        t_slug_core_collision_gets_no_implicit_default,
        t_core_endpoints,
        t_origin_certificate,
        t_acme_challenge,
        t_pairs_are_exact_across_subjects,
        t_setting_restored_only_when_no_exception_remains,
        t_rollback_conflict_on_setting_is_409_without_mutation,
        t_rollback_conflict_on_rule_is_409_without_mutation,
        t_legacy_rule_needs_operator_adoption,
        t_lease_expiry_stops_before_mutation,
        t_expired_lease_of_another_writer_is_taken_over,
        t_live_lease_blocks_second_writer,
        t_internal_failure_is_undone_by_hub,
        t_transaction_ownership_and_states,
        t_bootstrap_grant_ttl_bounds,
        t_unconfigured_zone_is_503,
        t_unassigned_name_dns_is_refused_before_mutation,
        t_unassigned_name_acme_is_refused_before_mutation,
        t_unassigned_name_origin_is_refused_before_mutation,
        t_unassigned_name_exemption_is_refused_before_mutation,
        t_assignment_change_waits_for_a_running_operation,
        t_reads_after_lease_loss_are_not_made,
        t_unbind_refused_while_alias_has_exception,
        t_unbind_with_removal_clears_the_exception_first,
        t_unbind_removal_keeps_other_subjects_pairs,
        t_bind_refused_while_any_exception_names_the_hostname,
        t_commit_rechecks_assignment,
        t_commit_after_unbind_removal_is_refused,
        t_commit_after_partial_unbind_removal_is_refused,
        t_repeat_exemption_is_idempotent,
        t_repeat_exemption_while_armed_returns_the_open_transaction,
        t_new_pair_while_own_transaction_is_open_is_refused,
        t_zero_pair_transaction_from_older_code_settles,
        t_retry_subset_of_open_transaction_is_refused,
        t_retry_superset_of_open_transaction_is_refused,
        t_disjoint_retry_with_open_transaction_is_refused,
        t_all_committed_request_with_disjoint_open_transaction_is_refused,
        t_open_transaction_emptied_by_unbind_still_blocks,
        t_anti_vacuity_cartesian_render_is_caught,
        t_anti_vacuity_unverified_rollback_is_caught,
        t_anti_vacuity_unfenced_lease_is_caught,
        t_no_token_or_origin_address_leaks,
    ]
    for test in tests:
        check(test.__name__, test)
    print(f"\n{PASSED[0]} passed, {len(FAILURES)} failed")
    if FAILURES:
        print("FAILED: " + ", ".join(FAILURES))
        sys.exit(1)


if __name__ == "__main__":
    main()
