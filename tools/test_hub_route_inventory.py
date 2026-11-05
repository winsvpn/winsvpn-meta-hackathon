#!/usr/bin/env python3
"""Lane L54 / L51 C3: the control-plane installer must ship what the certified
live hub runs.

The certified live hub application (/root/vpn_auth/main.py, sha256 9c438377...)
is the deployed 28ef1bc0 plus four certified patches, applied in this order:
  L42  hub_autoenable_fix.diff (France redeploy round FR2): registration never
       reopens operator_enabled; only the evidenced admin promotion does.
  HK   hub_sitekey_fix_v3.diff (Round HK): the site-AI tunnel endpoint removes
       only the authorized_keys lines it recorded as its own, and validates
       the key blob's embedded type.
  F1   hub_paid_verify_repair.diff (Round HV F1): paid /verify enrollment
       helpers and the activation-secret expiry argument.
  F2   hub_offnode_access.diff (Round HV F2 v3): off-node peer policy, the
       closure cleanup record, POST /admin/nodes/offnode-gate, and promotion
       and retirement consuming a hub-verified gate record.

This test extracts the hub module from the installer's
`cat > "${APP_DIR}/main.py" <<'PYEOF'` heredoc (or reads a main.py given
directly) and checks, with the AST and exact markers:
  1. every route of the certified live hub exists in the installer's app;
  2. each certified patch's defining functions and call sites are present;
  3. the repo-only edge broker routes (diff 03) are still present.
Behaviour is covered by the certified tests themselves; lane L54 ran them
against the extracted installer app (L42 23/23, HK 20/20, F1 36/36, F2 11/63).

usage: tools/test_hub_route_inventory.py [installer.sh | main.py]
Exit 0 only when every check holds.
"""
import ast
import os
import re
import sys

sys.dont_write_bytecode = True

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT = os.path.join(ROOT, "server", "wins_control_plane_setup_ONETOUCH.sh")

# (method, path) of every route in the certified live hub source 9c438377,
# captured by lane L54 on 2026-09-26 from the rebuild deployed 28ef1bc0 +
# L42 + HK v3 + F1 + F2 v3 (each step hash-checked against its certificate).
CERTIFIED_LIVE_ROUTES = [
    ("GET", "/admin/core/promotions"),
    ("GET", "/admin/device/list"),
    ("GET", "/admin/donor-acknowledgments"),
    ("GET", "/admin/emergency/outbox"),
    ("GET", "/admin/free-access-events"),
    ("GET", "/admin/hoppy-agent/outbox"),
    ("GET", "/admin/nodes/promotions"),
    ("GET", "/admin/nodes/retirements"),
    ("GET", "/admin/nodes/tier"),
    ("GET", "/admin/nodes/winn3"),
    ("GET", "/admin/nodes/winn3/descriptor"),
    ("GET", "/admin/payment-clicks"),
    ("GET", "/admin/paypal/dead-letter"),
    ("GET", "/admin/redemption/batches"),
    ("GET", "/api/site/crypto-config"),
    ("GET", "/api/site/geo-scene"),
    ("GET", "/api/site/wallet-config"),
    ("GET", "/api/v1/core/assignments"),
    ("GET", "/api/v1/pubkey"),
    ("GET", "/free/status"),
    ("GET", "/healthz"),
    ("GET", "/legal/current"),
    ("GET", "/nodes"),
    ("GET", "/pay/crypto/return"),
    ("GET", "/pay/{option_key}"),
    ("GET", "/paypal/cancel"),
    ("GET", "/paypal/return"),
    ("GET", "/ref/{referral_code}"),
    ("GET", "/referral/{referral_code}"),
    ("ON_EVENT", "startup"),
    ("POST", "/account/deletion/cancel"),
    ("POST", "/account/deletion/confirm"),
    ("POST", "/account/deletion/request"),
    ("POST", "/account/deletion/status"),
    ("POST", "/account/status"),
    ("POST", "/admin/announce"),
    ("POST", "/admin/app-version-gate"),
    ("POST", "/admin/bootstrap-grant"),
    ("POST", "/admin/core/bootstrap-management-tunnel"),
    ("POST", "/admin/core/promote"),
    ("POST", "/admin/core/verify-management"),
    ("POST", "/admin/core/withdraw"),
    ("POST", "/admin/device/remove"),
    ("POST", "/admin/donor-acknowledgment/annual-summary"),
    ("POST", "/admin/donor-acknowledgment/issue"),
    ("POST", "/admin/donor-acknowledgment/outbox/drain"),
    ("POST", "/admin/donor-acknowledgment/resend"),
    ("POST", "/admin/double-vpn/free-access"),
    ("POST", "/admin/emergency/outbox/drain"),
    ("POST", "/admin/hoppy-agent/outbox/drain"),
    ("POST", "/admin/maintenance"),
    ("POST", "/admin/monero/poll"),
    ("POST", "/admin/nodes/bootstrap-management-tunnel"),
    ("POST", "/admin/nodes/direct-awg"),
    ("POST", "/admin/nodes/free-access"),
    ("POST", "/admin/nodes/offnode-gate"),
    ("POST", "/admin/nodes/restore"),
    ("POST", "/admin/nodes/resync-peers"),
    ("POST", "/admin/nodes/retire"),
    ("POST", "/admin/nodes/tier"),
    ("POST", "/admin/nodes/winn3"),
    ("POST", "/admin/nodes/winn3/admission/retire"),
    ("POST", "/admin/nodes/winn3/descriptor"),
    ("POST", "/admin/paypal/retry"),
    ("POST", "/admin/paypal/sync"),
    ("POST", "/admin/provision"),
    ("POST", "/admin/redemption/batch"),
    ("POST", "/admin/redemption/outbox/drain"),
    ("POST", "/admin/redemption/revoke"),
    ("POST", "/admin/renew"),
    ("POST", "/admin/resend"),
    ("POST", "/api/agent/v1/credentials-resend"),
    ("POST", "/api/agent/v1/device-limit-reset"),
    ("POST", "/api/agent/v1/device-revoke"),
    ("POST", "/api/agent/v1/preferred-server"),
    ("POST", "/api/agent/v1/receipt-reissue"),
    ("POST", "/api/redeem"),
    ("POST", "/api/redeem/ack"),
    ("POST", "/api/site/ai-chat"),
    ("POST", "/api/site/translate"),
    ("POST", "/api/v1/core/assignments/ack"),
    ("POST", "/api/v1/core/bootstrap"),
    ("POST", "/api/v1/core/promotion/ack"),
    ("POST", "/api/v1/core/register"),
    ("POST", "/api/v1/core/{core_id}/deployment/complete"),
    ("POST", "/api/v1/core/{core_id}/deployment/withdraw"),
    ("POST", "/api/v1/nodes/bootstrap"),
    ("POST", "/api/v1/nodes/heartbeat"),
    ("POST", "/api/v1/nodes/register"),
    ("POST", "/api/v1/nodes/{slug}/deployment/complete"),
    ("POST", "/api/v1/nodes/{slug}/deployment/withdraw"),
    ("POST", "/api/v1/nodes/{slug}/heartbeat"),
    ("POST", "/api/v1/nodes/{slug}/resync-peers"),
    ("POST", "/api/v1/site-ai/tunnel-key"),
    ("POST", "/emergency/dispatch"),
    ("POST", "/free/logout"),
    ("POST", "/free/verify"),
    ("POST", "/legal/accept"),
    ("POST", "/logout"),
    ("POST", "/pay/crypto/create-invoice"),
    ("POST", "/pay/monero/create-order"),
    ("POST", "/pay/wallet/capture"),
    ("POST", "/pay/wallet/create-order"),
    ("POST", "/verify"),
    ("POST", "/webhook/btcpay"),
    ("POST", "/webhook/paypal"),
]

# Routes the repo carries and the live hub does not yet run (edge broker,
# Round CF diff 03). A port of the live patches must not drop them.
REPO_EDGE_ROUTES = [
    ("GET", "/api/v1/core/{core_id}/edge/hostnames"),
    ("GET", "/api/v1/nodes/{slug}/edge/hostnames"),
    ("POST", "/admin/edge/hostname-bindings"),
    ("POST", "/admin/edge/plaintext-exceptions/adopt"),
    ("POST", "/admin/edge/reservations"),
    ("POST", "/api/v1/core/{core_id}/edge/acme-challenge"),
    ("POST", "/api/v1/core/{core_id}/edge/dns"),
    ("POST", "/api/v1/core/{core_id}/edge/origin-certificate"),
    ("POST", "/api/v1/nodes/{slug}/edge/acme-challenge"),
    ("POST", "/api/v1/nodes/{slug}/edge/dns"),
    ("POST", "/api/v1/nodes/{slug}/edge/origin-certificate"),
    ("POST", "/api/v1/nodes/{slug}/edge/plaintext-exemption"),
    ("POST", "/api/v1/nodes/{slug}/edge/plaintext-exemption/{transaction_id}/commit"),
    ("POST", "/api/v1/nodes/{slug}/edge/plaintext-exemption/{transaction_id}/rollback"),
]

FAILURES = []


def check(ok, label):
    print(("PASS " if ok else "FAIL ") + label)
    if not ok:
        FAILURES.append(label)


def load_source(path):
    text = open(path, encoding="utf-8").read()
    if path.endswith(".py"):
        return text
    match = re.search(r"""cat > "\$\{APP_DIR\}/main\.py" <<'PYEOF'\n(.*?)\nPYEOF\n""", text, re.S)
    if not match:
        sys.exit(f"hub heredoc not found in {path}")
    return match.group(1) + "\n"


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    source = load_source(path)
    tree = ast.parse(source)
    functions = {}
    routes = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.setdefault(node.name, []).append(node)
            for dec in node.decorator_list:
                if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                        and isinstance(dec.func.value, ast.Name) and dec.func.value.id == "app"
                        and dec.args and isinstance(dec.args[0], ast.Constant)):
                    routes.add((dec.func.attr.upper(), dec.args[0].value))

    def one(name):
        return len(functions.get(name, [])) == 1

    def calls(func, callee):
        for fn in functions.get(func, []):
            for node in ast.walk(fn):
                if isinstance(node, ast.Call):
                    target = node.func
                    name = target.id if isinstance(target, ast.Name) else getattr(target, "attr", "")
                    if name == callee:
                        return True
        return False

    def call_nodes(func, callee):
        found = []
        for fn in functions.get(func, []):
            for node in ast.walk(fn):
                if isinstance(node, ast.Call):
                    target = node.func
                    name = target.id if isinstance(target, ast.Name) else getattr(target, "attr", "")
                    if name == callee:
                        found.append(node)
        return found

    def params(func):
        fn = (functions.get(func) or [None])[0]
        if fn is None:
            return set()
        a = fn.args
        return {x.arg for x in a.args + a.kwonlyargs + a.posonlyargs}

    print(f"# source: {path}")
    missing = [r for r in CERTIFIED_LIVE_ROUTES if r not in routes]
    for route in missing:
        check(False, f"certified live route {route[0]} {route[1]} is absent from the installer app")
    check(not missing, f"all {len(CERTIFIED_LIVE_ROUTES)} certified live routes present ({len(missing)} missing)")

    # L42: no registration arm may reopen the latch from a promotion event.
    check("node_promotion_events WHERE slug = nodes.slug" not in source,
          "L42: registration upsert has no auto-enable arm")

    # HK v3: exact-line ownership and blob validation.
    for name in ("_site_ai_ownership_path", "_site_ai_owned_lines", "_site_ai_save_owned_lines",
                 "_site_ai_key_blob_valid", "_authorized_key_line_blob", "_is_site_ai_tunnel_line"):
        check(one(name), f"HK: {name} defined once")
    check(calls("register_site_ai_tunnel_key", "_site_ai_key_blob_valid")
          and calls("register_site_ai_tunnel_key", "_site_ai_owned_lines"),
          "HK: register_site_ai_tunnel_key validates the blob and removes only owned lines")

    # F1: paid /verify repair.
    for name in ("create_double_vpn_enrollment_leases_table", "acquire_double_vpn_enrollment_lease",
                 "release_double_vpn_enrollment_lease", "verify_and_consume_activation_secret",
                 "verify_advisory_request_authorized", "require_verify_authorization"):
        check(one(name), f"F1: {name} defined once")
    check("activation_secret_expires_at" in params("require_verify_authorization"),
          "F1: require_verify_authorization takes activation_secret_expires_at")
    # AUDIT-FIX 2 (84d524d) split ensure_schema into a cached fast path and
    # _ensure_schema_full; the full pass is where the table is created.
    check(one("ensure_schema") and one("_ensure_schema_full")
          and calls("ensure_schema", "_ensure_schema_full")
          and calls("_ensure_schema_full", "create_double_vpn_enrollment_leases_table"),
          "F1: ensure_schema creates the enrollment lease table")

    # F2 v3: off-node gate.
    check(("POST", "/admin/nodes/offnode-gate") in routes, "F2: POST /admin/nodes/offnode-gate route")
    for name in ("node_admits_peer", "peer_push_still_admitted", "close_node_runtime",
                 "offnode_gate_digest", "verify_offnode_gate_for_use", "consume_offnode_gate",
                 "create_node_offnode_gates_table", "create_node_closure_cleanup_table"):
        check(one(name), f"F2: {name} defined once")
    # Round SC (5026058) moved the manual promotion's readiness checks, the
    # gate verification included, into node_promotion_readiness_failures,
    # shared with the automatic reopen. Only the automatic reopen may accept
    # a hub-sourced gate record, so the manual path must not pass
    # allow_hub_gate at all.
    readiness_calls = call_nodes("admin_set_node_tier", "node_promotion_readiness_failures")
    check(one("node_promotion_readiness_failures")
          and bool(readiness_calls)
          and all(len(c.args) <= 3 and not c.keywords for c in readiness_calls)
          and calls("node_promotion_readiness_failures", "verify_offnode_gate_for_use")
          and calls("admin_set_node_tier", "consume_offnode_gate"),
          "F2: promotion verifies and consumes a hub-verified gate record")
    check("offnode_gate_sha256" in params("admin_retire_node")
          and calls("admin_retire_node", "consume_offnode_gate"),
          "F2: retirement requires and consumes a gate record")
    check(calls("resync_active_peers_to_node", "close_node_runtime"),
          "F2: resync runs the closed-node cleanup first")

    lost = [r for r in REPO_EDGE_ROUTES if r not in routes]
    check(not lost, f"edge broker routes kept ({len(lost)} of {len(REPO_EDGE_ROUTES)} missing)")

    if FAILURES:
        print(f"{len(FAILURES)} check(s) failed")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
