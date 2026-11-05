#!/usr/bin/env python3
"""tierb_hub.py: the Tier B hub operations hub_lite.py's CLI does not offer, on the same --state directory.

hub_lite.py bootstraps and registers its own emulated nodes. In Tier B the node is the real guest: the data-plane
installer bootstraps, registers and calls complete-fresh itself, through the stubbed edge, against
`hub_lite.py serve` running from the same state directory (design v17 5.3: "A full fresh --deploy of the real
data-plane installer runs against hub-lite with the Cloudflare edge stubbed"). What the hub side still needs from the
harness is what the operator does around a real deploy (runbook R4): a bootstrap grant to stage, a t1 ticket minted
from the node's SSH host key before the deploy, and the node's identity for hub-lite's node transport, which answers
the hub's identity pull. This module adds exactly those, plus a sweep that uses the node's own heartbeats and a read
of the client-facing node list. It edits nothing in hub_lite.py and replaces nothing in main.py.

  grant        --slug S                       POST /admin/bootstrap-grant; the token is written 0600 to
                                              STATE/tierb/S.bootstrap_token and never printed
  ticket       --slug S --action A [--endpoint-ip IP] [--gateway-id G] [--go-live auto|manual] [--tier free|premium]
               stdin: the node's /etc/ssh/ssh_host_ed25519_key.pub line (public), or nothing once import-node ran (the
               imported identity then names the host key, endpoint and gateway id); signed with hub-lite's test t1 key
               and posted through the real POST /admin/nodes/winn3/signer-ticket
  signer-state --slug S --verb suspend|unsuspend
                                              hub_lite's STEP-14 suspend or unsuspend, its t1 ticket bound to the
                                              imported node's real host key (hub_lite's own binds a key it made)
  import-node  --slug S                       stdin: the node's answer to the hub's own identity pull (the remote
                                              program of main.winn3_pull_identity, run on the guest); no bootstrap
  sweep        --slug S [--wait-budget] [--canary ...] [--offnode ...] [--carry JSON]
                                              hub_lite's sweep without its emulated heartbeats (the guest sends its own)
  served       --slug S                       GET /nodes?platform=P for default, android, linux and ios

Output is one JSON object; no line carries a token, a secret or key material.
"""
import argparse
import ast
import base64
import hashlib
import json
import re
import secrets
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import hub_lite as hl  # noqa: E402

PLATFORMS = ("default", "android", "linux", "ios")
PULL_KEYS = {"identity", "identity_sig", "admission_secret", "detected_public_ip"}


def pull_identity_remote(cp_installer=hl.CP_INSTALLER):
    """The Python program main.winn3_pull_identity runs on the node, exactly as main.py carries it."""
    # the same cut as H1's heredoc() (which hub_lite.extract uses), without importing that test module and its
    # toolchain checks, so `tier_b.py plan` needs nothing but this tree
    source = Path(cp_installer).read_text(encoding="utf-8")
    start = source.index(hl.MAIN_HEADER + "\n") + len(hl.MAIN_HEADER) + 1
    main = source[start:source.index("\nPYEOF\n", start) + 1]
    # the program itself holds a column-0 `def read`, so the function is not cut at the next `def`
    body = main.split("\ndef winn3_pull_identity(", 1)[1]
    match = re.match(r"[^\n]*\n    \"\"\"[^\n]*\"\"\"\n    remote = ('''.*?''')\n", body, re.S)
    if not match:
        raise hl.HubLiteError("winn3_pull_identity carries no remote program")
    return ast.literal_eval(match.group(1))


def host_key_fingerprint(line):
    """`ssh-ed25519 AAAA... comment` -> the SHA256:... form tickets carry (as hub_lite and ssh-keygen -l print it)."""
    parts = (line or "").split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise hl.HubLiteError("stdin is not an ssh-ed25519 public key line")
    blob = base64.b64decode(parts[1], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def grant(hub, slug, ttl=3600):
    status, body = hub.http("POST", "/admin/bootstrap-grant", admin=True,
                            json_body={"role": "node", "subject_id": slug, "ttl_seconds": ttl})
    if status != 200 or not isinstance(body.get("bootstrap_token"), str):
        return {"ok": False, "status_code": status, "detail": body.get("detail")}
    path = hl.private_dir(hub.state / "tierb") / (slug + ".bootstrap_token")
    hl.write_private(path, body["bootstrap_token"] + "\n")
    return {"ok": True, "slug": slug, "token_file": str(path), "ttl_seconds": ttl}


def imported_identity(hub, slug):
    """(identity, endpoint_ip) of a node import-node recorded, else (None, None)."""
    meta = hub.node_meta(slug)
    if not meta.get("imported"):
        return None, None
    return hub.identity(slug), meta.get("endpoint_ip")


def mint(hub, slug, action, host_key_line=None, endpoint_ip=None, gateway_id=None, go_live="auto", tier="free"):
    """hub_lite.HubLite.ticket's bytes (3.8), for a node whose host key hub-lite did not make. Without a host key line
    or endpoint the imported identity supplies them."""
    identity, imported_ip = imported_identity(hub, slug)
    if not (host_key_line or "").strip():
        if identity is None:
            raise hl.HubLiteError("no host key on stdin and no imported identity for this slug")
        host_key_line = identity["ssh_host_ed25519_key"]
    endpoint_ip = endpoint_ip or imported_ip
    if not endpoint_ip:
        raise hl.HubLiteError("no --endpoint-ip and no imported identity for this slug")
    gateway_id = gateway_id or (identity or {}).get("gateway_id") or slug + "-gw1"
    status, body = hub.http("GET", "/admin/nodes/winn3/signer-ticket", admin=True)
    if status != 200 or not isinstance(body.get("epoch"), int):
        raise hl.HubLiteError("the signer epoch is unavailable (%s)" % status)
    fields = {"slug": slug, "action": action, "epoch": body["epoch"], "endpoint_ip": endpoint_ip,
              "gateway_id": gateway_id, "host_key_sha256": host_key_fingerprint(host_key_line),
              "go_live": go_live, "tier": tier, "nonce": secrets.token_hex(16),
              "not_after": int(hub.clock.time() + 3 * hl.DAY)}
    raw = hl.canonical(fields)
    work = Path(tempfile.mkdtemp(dir=hub.dirs["work"]))
    try:
        sig = hl._h1().openssl_sign(hub.dirs["keys"] / "t1.ed25519.pem", b"winsvpn-winn3-signer-ticket/v1\x00" + raw, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return {"payload": base64.b64encode(raw).decode(), "sig": base64.b64encode(sig).decode()}, fields


def ticket(hub, slug, action, host_key_line=None, endpoint_ip=None, gateway_id=None, go_live="auto", tier="free"):
    """Mint and post through the real POST /admin/nodes/winn3/signer-ticket."""
    envelope, fields = mint(hub, slug, action, host_key_line, endpoint_ip, gateway_id, go_live, tier)
    status, posted = hub.http("POST", "/admin/nodes/winn3/signer-ticket", admin=True,
                              json_body={"slug": slug, "ticket": envelope})
    return {"ok": status == 200, "posted_status": status, "detail": posted.get("detail"), "slug": slug,
            "action": action, "epoch": fields["epoch"], "nonce": fields["nonce"], "go_live": go_live, "tier": tier,
            "gateway_id": fields["gateway_id"], "endpoint_ip": fields["endpoint_ip"],
            "host_key_sha256": fields["host_key_sha256"]}


def signer_state(hub, slug, verb):
    """hub_lite.HubLite.signer_state_verb with the ticket bound to the imported node's host key: the generation must
    have been bumped first (hold or withhold) for a suspend, and the ticket goes to the hub's real signer client."""
    if verb not in ("suspend", "unsuspend"):
        raise hl.HubLiteError("verb must be suspend or unsuspend")
    row = hub.row(slug)
    if row is None:
        return {"ok": False, "error": "node-not-found"}
    if verb == "suspend" and not (row["winn3_operator_hold"] or not row["winn3_descriptor_json"]):
        return {"ok": False, "error": "generation-not-bumped-first"}
    envelope, fields = mint(hub, slug, verb)
    with hub.activated():
        try:
            reply = hub.mod.winn3_signer_client({"verb": verb, "slug": slug, "ticket": envelope})
        except ValueError as exc:
            return {"ok": False, "error": str(exc), "ticket_nonce": fields["nonce"]}
    return {"ok": True, "verb": verb, "state": reply.get("state"), "ticket_nonce": fields["nonce"],
            "deployment_generation": row["deployment_generation"]}


def import_node(hub, slug, pulled_text):
    """Record the real node's pulled identity where hub-lite's node transport reads it. The node itself must already
    be registered (it bootstrapped and registered through the served hub); nothing is bootstrapped here."""
    try:
        pulled = json.loads(pulled_text)
    except ValueError:
        return {"ok": False, "error": "the identity pull output is not JSON"}
    if not isinstance(pulled, dict) or set(pulled) != PULL_KEYS:
        return {"ok": False, "error": "the identity pull must hold exactly %s" % ", ".join(sorted(PULL_KEYS))}
    try:
        identity = json.loads(base64.b64decode(pulled["identity"], validate=True))
    except ValueError:
        return {"ok": False, "error": "the pulled identity does not decode"}
    if identity.get("slug") != slug:
        return {"ok": False, "error": "the pulled identity names another slug"}
    row = hub.row(slug)
    if row is None:
        return {"ok": False, "error": "node-not-registered: the guest has not registered with this hub"}
    revision = str(row.get("data_plane_code_revision") or "")
    meta = hub.node_meta(slug)
    meta.update({"slug": slug, "ssh_host": row["ssh_host"], "endpoint_ip": pulled["detected_public_ip"],
                 "installer_sha256": revision[len("sha256:"):] if revision.startswith("sha256:") else "",
                 "gateway_id": identity.get("gateway_id"), "awg_public_key": row.get("public_key"),
                 "stealth": meta.get("stealth", ""), "imported": True})
    meta.setdefault("plan", {})
    directory = hub.node_dir(slug)
    hl.write_private(directory / "pulled.json", hl.canonical(pulled))
    hl.write_private(directory / "node.json", json.dumps(meta, indent=1, sort_keys=True))
    if "HL-D1" in hub.manifest["deviations"]:
        hub._pin_endpoint_ip(slug, pulled["detected_public_ip"], identity["ssh_host_ed25519_key"])
    return {"ok": True, "slug": slug, "gateway_id": identity.get("gateway_id"),
            "endpoint_ip": pulled["detected_public_ip"], "installer_sha256": meta["installer_sha256"],
            "ssh_host_known": bool(row["ssh_host"]), "identity_sha256": hashlib.sha256(
                base64.b64decode(pulled["identity"])).hexdigest()}


def served(hub, slug):
    out = {}
    for platform in PLATFORMS:
        status, body = hub.http("GET", "/nodes?platform=" + platform)
        nodes = body if isinstance(body, list) else (body.get("nodes") if isinstance(body, dict) else None) or []
        entry = next((n for n in nodes if isinstance(n, dict) and n.get("slug") == slug), None)
        out[platform] = {"status_code": status, "listed": entry is not None,
                         "reachable": bool(entry and entry.get("reachable")), "status": entry.get("status") if entry else None}
    return {"ok": True, "slug": slug, "platforms": out}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="tierb_hub.py", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add(name):
        p = sub.add_parser(name)
        p.add_argument("--state", required=True)
        p.add_argument("--slug", required=True)
        return p
    add("grant")
    p = add("ticket")
    p.add_argument("--action", required=True, choices=("new", "reset", "endpoint", "rekey", "suspend", "unsuspend"))
    p.add_argument("--endpoint-ip")
    p.add_argument("--gateway-id")
    p.add_argument("--go-live", default="auto", choices=("auto", "manual"))
    p.add_argument("--tier", default="free", choices=("free", "premium"))
    add("import-node")
    p = add("signer-state")
    p.add_argument("--verb", required=True, choices=("suspend", "unsuspend"))
    p = add("sweep")
    p.add_argument("--wait-budget", action="store_true")
    p.add_argument("--canary", default="ok", choices=("ok", "fail", "stale", "none"))
    p.add_argument("--offnode", default="healthy")
    p.add_argument("--carry", default="{}")
    add("served")
    args = parser.parse_args(argv)
    try:
        hub = hl.HubLite(args.state, start_signer=args.cmd in ("ticket", "sweep", "signer-state"))
    except hl.HubLiteError as exc:
        return hl._emit({"ok": False, "error": str(exc)})
    try:
        if args.cmd == "grant":
            return hl._emit(grant(hub, args.slug))
        if args.cmd == "ticket":
            return hl._emit(ticket(hub, args.slug, args.action, sys.stdin.read(), args.endpoint_ip,
                                   gateway_id=args.gateway_id, go_live=args.go_live, tier=args.tier))
        if args.cmd == "signer-state":
            return hl._emit(signer_state(hub, args.slug, args.verb))
        if args.cmd == "import-node":
            return hl._emit(import_node(hub, args.slug, sys.stdin.read()))
        if args.cmd == "sweep":
            out = hub.sweep(args.slug, carry=json.loads(args.carry), canary=args.canary, offnode=args.offnode,
                            heartbeat=False, wait_budget=args.wait_budget)
            out["status"] = hub.status(args.slug)
            return hl._emit(dict(out, ok=True))
        if args.cmd == "served":
            return hl._emit(served(hub, args.slug))
    except hl.HubLiteError as exc:
        return hl._emit({"ok": False, "error": str(exc)})
    finally:
        hub.close()
    return 2


if __name__ == "__main__":
    sys.exit(main())
