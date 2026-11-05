#!/usr/bin/env python3
"""H4: the hub's signer-ticket route (design v17 3.8, 3.17 and their 5.5 tests).

These exercise the REAL control-plane source: the module is extracted from
the `cat > "${APP_DIR}/main.py" <<'PYEOF'` heredoc inside
wins_control_plane_setup_ONETOUCH.sh and exec'd with the harness's stubs for
its third-party imports, exactly as test_winn3_descriptor_hub.py and
test_account_deletion_hub.py do. Signatures are produced by REAL openssl(1) at
test time from a throwaway t1 key made in a temp directory; no real key is
used or created, and nothing contacts a node, a signer or the network (the
signer status read is patched to a fake, and the unreachable path is asserted
through the real function against a socket path that does not exist here).

WHAT IS UNDER TEST:

  * THE EXACT BYTES ARE STORED. The hub stores the posted payload and sig
    verbatim (3.8: "The hub stores the exact signed bytes"), so the use-time
    re-verification (3.17) reads what the operator's tool signed.
  * THE HUB RE-VERIFIES AT POST. The t1 signature under the ticket domain, the
    canonical form (H1 contract ruling), the closed field set, the enums and
    the lifetime bound are all checked before anything is stored, and a
    descriptor signature never passes as a ticket.
  * THE EPOCH COMES FROM THE SIGNER. The app can neither read nor write the
    signer's config (3.8), so the minting query is answered from the signer's
    status verb, and the route fails closed when the signer is unreachable.
"""
from contextlib import closing
import _toolchain  # noqa: F401  (V-01 preflight)
import base64
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_account_deletion_hub as harness  # noqa: E402
from test_account_deletion_hub import FakeRequest, HTTPException  # noqa: E402
import test_winn3_descriptor_hub as desc_harness  # noqa: E402

ADMIN = "test-admin-token"
TICKET_DOMAIN = b"winsvpn-winn3-signer-ticket/v1"
DESCRIPTOR_DOMAIN = b"winsvpn-winn3-descriptor/v1"

FAILURES = []
PASSED = [0]


def check(name, fn):
    try:
        fn()
    except Exception:
        import traceback
        FAILURES.append((name, traceback.format_exc()))
        print(f"FAIL {name}")
    else:
        PASSED[0] += 1
        print(f"ok   {name}")


# ------------------------------------------------------------------ keys --

_T1 = {}


def t1_keypair(tmp):
    """A throwaway t1 Ed25519 keypair; the public half pins the hub's env."""
    if "key" not in _T1:
        key = os.path.join(tmp, "t1.pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", key],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        der = subprocess.run(["openssl", "pkey", "-in", key, "-pubout", "-outform", "DER"],
                             check=True, stdout=subprocess.PIPE).stdout
        _T1["key"], _T1["pub"] = key, der[12:]
    return _T1["key"], _T1["pub"]


def sign(message, key):
    with tempfile.TemporaryDirectory() as work:
        msg = os.path.join(work, "m.bin")
        with open(msg, "wb") as handle:
            handle.write(message)
        return subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", key,
                               "-in", msg], check=True, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL).stdout


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def ticket_body(slug="lab-alpha", action="new", epoch=1, endpoint_ip="198.51.100.7",
                gateway_id="lab-alpha-gw1", host_key="SHA256:" + "A" * 43,
                go_live="auto", tier="free", nonce=None, not_after=None,
                drop=(), extra=None):
    body = {"slug": slug, "action": action, "epoch": epoch,
            "endpoint_ip": endpoint_ip, "gateway_id": gateway_id,
            "host_key_sha256": host_key, "go_live": go_live, "tier": tier,
            "nonce": nonce or hashlib.sha256(slug.encode()).hexdigest(),
            "not_after": not_after if not_after is not None
            else int(time.time()) + 3 * 86400}
    for name in drop:
        body.pop(name, None)
    if extra:
        body.update(extra)
    return body


def envelope(mod, body, key=None, domain=TICKET_DOMAIN, raw=None):
    payload = raw if raw is not None else canonical(body)
    signature = sign(domain + b"\x00" + payload, key or _T1["key"])
    return {"payload": base64.b64encode(payload).decode(),
            "sig": base64.b64encode(signature).decode()}


# ------------------------------------------------------------------- hub --

def load(tmp, monkeypatch_status=None):
    key, pub = t1_keypair(tmp)
    mod = harness.load_hub(WINN3_SIGNER_TICKET_PUBKEY_T1=base64.b64encode(pub).decode())
    if monkeypatch_status is not None:
        mod.winn3_signer_status = lambda timeout=5.0: monkeypatch_status
    desc_harness.seed_node(mod, slug="lab-alpha")
    desc_harness.seed_node(mod, slug="lab-beta")
    return mod


def post(mod, slug, env, token=ADMIN):
    payload = mod.SignerTicketPost(
        slug=slug, ticket=mod.SignerTicketEnvelope(payload=env["payload"], sig=env["sig"]))
    request = FakeRequest(headers={"content-type": "application/json"}, body={})
    return mod.admin_post_node_winn3_signer_ticket(payload, request, x_admin_token=token)


def post_expect(mod, slug, env, token=ADMIN, status=400):
    try:
        post(mod, slug, env, token)
    except HTTPException as exc:
        assert exc.status_code == status, (exc.status_code, exc.detail)
        return exc.detail
    raise AssertionError(f"expected HTTP {status}")


def stored(mod, slug):
    with closing(sqlite3.connect(mod._DB)) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(
            "SELECT * FROM winn3_signer_tickets WHERE slug = ?", (slug,)).fetchall()]


# ------------------------------------------------------------------ tests --

def t_post_stores_the_exact_signed_bytes(tmp):
    mod = load(tmp)
    body = ticket_body()
    env = envelope(mod, body)
    reply = post(mod, "lab-alpha", env)
    assert reply == {"ok": True, "slug": "lab-alpha", "action": "new", "epoch": 1,
                     "nonce": body["nonce"], "stored": True}, reply
    rows = stored(mod, "lab-alpha")
    assert len(rows) == 1
    # The exact posted bytes, verbatim (3.8).
    assert rows[0]["payload"] == env["payload"] and rows[0]["sig"] == env["sig"]
    assert rows[0]["go_live"] == "auto" and rows[0]["tier"] == "free"
    assert rows[0]["not_after"] == body["not_after"]
    # A second action for the same slug is stored alongside (prepare_subject
    # mints an unsuspend and a rekey in one session, 3.9 step 4).
    env2 = envelope(mod, ticket_body(action="unsuspend", nonce="ab" * 32))
    assert post(mod, "lab-alpha", env2)["ok"]
    assert len(stored(mod, "lab-alpha")) == 2
    # Re-posting the same ticket is idempotent.
    assert post(mod, "lab-alpha", env)["ok"]
    assert len(stored(mod, "lab-alpha")) == 2


def t_post_refuses_unauthorized_and_unknown(tmp):
    mod = load(tmp)
    env = envelope(mod, ticket_body())
    detail = post_expect(mod, "lab-alpha", env, token="wrong-token", status=401)
    assert "Unauthorized" in detail
    assert stored(mod, "lab-alpha") == []
    post_expect(mod, "", envelope(mod, ticket_body(slug="")), status=400)
    # A slug a bootstrap grant could never name is refused.
    for bad in ("A", "x", "-bad", "bad_slug", "a" * 41):
        post_expect(mod, bad, envelope(mod, ticket_body(slug=bad)), status=400)
    assert stored(mod, "no-such-node") == []


def t_post_stores_a_ticket_for_a_node_that_has_not_installed_yet(tmp):
    # prepare_subject posts the ticket BEFORE the node installs, and the nodes
    # row is created only by /api/v1/nodes/bootstrap (3.1 steps 1 and 2): the
    # ticket for a brand new slug must be storable with no nodes row.
    mod = load(tmp)
    with closing(sqlite3.connect(mod._DB)) as conn:
        assert conn.execute("SELECT 1 FROM nodes WHERE slug = 'sg-new'").fetchone() is None
    env = envelope(mod, ticket_body(slug="sg-new", gateway_id="sg-new-gw1"))
    assert post(mod, "sg-new", env)["stored"] is True
    rows = stored(mod, "sg-new")
    assert len(rows) == 1 and rows[0]["payload"] == env["payload"]
    listing = mod.admin_get_node_winn3_signer_ticket(
        FakeRequest(headers={}, body={}), slug="sg-new", x_admin_token=ADMIN)
    assert [row["nonce"] for row in listing["tickets"]] == [rows[0]["nonce"]]


def t_post_stores_every_action_for_a_slug_with_no_node_row(tmp):
    # Sol blocker 1: preparation precedes registration for every action, an
    # unsuspend for an omitted recovery slug included. Admin auth and the t1
    # signature stay required, and storing a ticket never registers a node.
    mod = load(tmp)
    for index, action in enumerate(("new", "reset", "endpoint", "rekey", "suspend", "unsuspend")):
        slug = f"pre-{index}"
        env = envelope(mod, ticket_body(slug=slug, action=action, gateway_id=f"{slug}-gw1"))
        assert post(mod, slug, env)["stored"] is True
        assert [row["action"] for row in stored(mod, slug)] == [action]
    with closing(sqlite3.connect(mod._DB)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM nodes WHERE slug LIKE 'pre-%'").fetchone()[0] == 0
    post_expect(mod, "pre-9", envelope(mod, ticket_body(slug="pre-9")), token="wrong-token", status=401)
    post_expect(mod, "pre-9", envelope(mod, ticket_body(slug="pre-9"), domain=DESCRIPTOR_DOMAIN))
    assert stored(mod, "pre-9") == []


def t_post_refuses_malformed_envelopes(tmp):
    mod = load(tmp)
    post_expect(mod, "lab-alpha", {"payload": "", "sig": ""})
    post_expect(mod, "lab-alpha", {"payload": "!!!", "sig": "AAAA"})
    post_expect(mod, "lab-alpha", {"payload": "e30", "sig": "AAAA"})  # {} not a ticket
    assert stored(mod, "lab-alpha") == []


def t_post_refuses_non_canonical_payloads(tmp):
    mod = load(tmp)
    body = ticket_body()
    # Keys out of order, and spaced separators: both signed by the real t1.
    shuffled = json.dumps(body, separators=(", ", ": ")).encode()
    post_expect(mod, "lab-alpha", envelope(mod, body, raw=shuffled))
    reordered = json.dumps(body, sort_keys=False, separators=(",", ":")).encode()
    post_expect(mod, "lab-alpha", envelope(mod, body, raw=reordered))
    # The canonical form of the same ticket is accepted.
    assert post(mod, "lab-alpha", envelope(mod, body))["ok"]


def t_post_refuses_a_wrong_field_set(tmp):
    mod = load(tmp)
    post_expect(mod, "lab-alpha", envelope(mod, ticket_body(drop=("tier",))))
    post_expect(mod, "lab-alpha", envelope(mod, ticket_body(extra={"surprise": 1})))
    post_expect(mod, "lab-alpha", envelope(mod, ticket_body(slug="lab-beta")))
    post_expect(mod, "lab-alpha", envelope(mod, ticket_body(action="promote")))
    post_expect(mod, "lab-alpha", envelope(mod, ticket_body(epoch=0)))
    post_expect(mod, "lab-alpha", envelope(mod, ticket_body(epoch="1")))
    post_expect(mod, "lab-alpha", envelope(mod, ticket_body(endpoint_ip="999.1.1.1")))
    post_expect(mod, "lab-alpha", envelope(mod, ticket_body(endpoint_ip="198.51.100.7.5")))
    post_expect(mod, "lab-alpha", envelope(mod, ticket_body(gateway_id="  ")))
    post_expect(mod, "lab-alpha", envelope(mod, ticket_body(host_key="SHA256:AAAA")))
    post_expect(mod, "lab-alpha", envelope(mod, ticket_body(go_live="yes")))
    post_expect(mod, "lab-alpha", envelope(mod, ticket_body(tier="gold")))
    post_expect(mod, "lab-alpha", envelope(mod, ticket_body(nonce="AB" * 32)))
    post_expect(mod, "lab-alpha", envelope(mod, ticket_body(nonce="ab" * 8)))
    post_expect(mod, "lab-alpha", envelope(mod, ticket_body(not_after=int(time.time()) - 1)))
    post_expect(mod, "lab-alpha", envelope(
        mod, ticket_body(not_after=int(time.time()) + 8 * 86400)))
    assert stored(mod, "lab-alpha") == []


def t_post_refuses_bad_signatures(tmp):
    mod = load(tmp)
    body = ticket_body()
    # Signed by a different key.
    other = os.path.join(tmp, "other.pem")
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", other],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    post_expect(mod, "lab-alpha", envelope(mod, body, key=other))
    # The descriptor domain never passes as a ticket domain, and a descriptor
    # signature is not a ticket signature.
    post_expect(mod, "lab-alpha", envelope(mod, body, domain=DESCRIPTOR_DOMAIN))
    # A signature over different bytes than the posted payload.
    env = envelope(mod, body)
    tampered = json.loads(base64.b64decode(env["payload"]))
    tampered["tier"] = "premium"
    env["payload"] = base64.b64encode(canonical(tampered)).decode()
    post_expect(mod, "lab-alpha", env)
    assert stored(mod, "lab-alpha") == []


def t_post_refuses_without_the_pinned_t1(tmp):
    # os.environ is process-wide: clear the pinned key a earlier test set.
    os.environ.pop("WINN3_SIGNER_TICKET_PUBKEY_T1", None)
    mod = harness.load_hub()  # no WINN3_SIGNER_TICKET_PUBKEY_T1 in the env
    desc_harness.seed_node(mod, slug="lab-alpha")
    env = envelope(mod, ticket_body())
    detail = post_expect(mod, "lab-alpha", env)
    assert "signer-ticket-key-not-configured" in detail, detail
    assert stored(mod, "lab-alpha") == []


def t_get_answers_the_epoch_from_the_signer(tmp):
    status = {"ok": True, "epoch": 7, "active_slot": "g2", "key_ready": True,
              "ledger_present": True, "disabled": False, "recovery_pending": False}
    mod = load(tmp, monkeypatch_status=status)
    request = FakeRequest(headers={}, body={})
    reply = mod.admin_get_node_winn3_signer_ticket(request, slug="", x_admin_token=ADMIN)
    assert reply["ok"] and reply["epoch"] == 7 and reply["signer_reachable"] is True
    assert reply["active_slot"] == "g2" and reply["ledger_present"] is True
    # The stored tickets are listed verbatim for one slug.
    env = envelope(mod, ticket_body())
    assert post(mod, "lab-alpha", env)["ok"]
    listed = mod.admin_get_node_winn3_signer_ticket(
        FakeRequest(headers={}, body={}), slug="lab-alpha", x_admin_token=ADMIN)
    assert listed["ok"] and len(listed["tickets"]) == 1
    assert listed["tickets"][0]["payload"] == env["payload"]
    assert listed["tickets"][0]["sig"] == env["sig"]
    assert listed["tickets"][0]["action"] == "new"
    # The admin token is required for the listing too.
    try:
        mod.admin_get_node_winn3_signer_ticket(
            FakeRequest(headers={}, body={}), slug="lab-alpha", x_admin_token="no")
    except HTTPException as exc:
        assert exc.status_code == 401
    else:
        raise AssertionError("expected 401")


def t_get_fails_closed_when_the_signer_is_unreachable(tmp):
    mod = load(tmp)  # the real status reader: no signer socket exists here
    try:
        mod.admin_get_node_winn3_signer_ticket(
            FakeRequest(headers={}, body={}), slug="", x_admin_token=ADMIN)
    except HTTPException as exc:
        assert exc.status_code == 503, exc.status_code
    else:
        raise AssertionError("expected 503")


def t_go_live_and_tier_come_only_from_the_verified_bytes(tmp):
    mod = load(tmp)
    body = ticket_body(go_live="auto", tier="free")
    env = envelope(mod, body)
    assert post(mod, "lab-alpha", env)["ok"]
    row = stored(mod, "lab-alpha")[0]
    assert row["go_live"] == "auto" and row["tier"] == "free"
    # Tampering after signing: the stored bytes are re-verified at use
    # (3.17), so an altered go_live or tier fails the t1 signature, and the
    # final tier cannot be changed without the operator's key.
    for field, value in (("go_live", "manual"), ("tier", "premium")):
        tampered = json.loads(base64.b64decode(row["payload"]))
        tampered[field] = value
        tampered_raw = canonical(tampered)
        signature = base64.b64decode(row["sig"])
        try:
            mod.winn3_verify_signer_ticket_signature(tampered_raw, signature)
        except mod.Winn3ContractError as exc:
            assert exc.reason == "signer-ticket-signature-invalid", exc.reason
        else:
            raise AssertionError(f"tampered {field} passed verification")
        # The decoder still reads the (canonical) tampered bytes; the
        # signature check is what refuses them.
        assert mod.winn3_decode_signer_ticket(tampered_raw, slug="lab-alpha")[field] == value


def t_schema_is_additive(tmp):
    mod = load(tmp)
    with closing(sqlite3.connect(mod._DB)) as conn:
        columns = [row[1] for row in conn.execute("PRAGMA table_info(winn3_signer_tickets)")]
    assert columns == ["slug", "action", "epoch", "nonce", "payload", "sig",
                       "go_live", "tier", "not_after", "posted_at"], columns


# --------------------------------------------- input nested too deep (H4R-T4) --
#
# The signer's replies and the node's identity pull are bounded at 64 KiB. On
# the hub's interpreter (python 3.12) a JSON nesting that fits there already
# exceeds the C recursion limit; on 3.14 the limit is the thread's stack. These
# cases run on a thread with a 2 MiB stack and first check that the very bytes
# they use raise RecursionError there, so none passes vacuously. Each parse
# must turn it into the function's own refusal, never a RecursionError. 2 MiB,
# not less: 3.12's guard is a counter, not stack-aware, and on a 512 KiB or
# 1 MiB thread it overruns the stack (SIGBUS) before the counter trips.

SMALL_STACK = 2 * 1024 * 1024


def on_small_stack(fn):
    out = {}

    def run():
        try:
            out["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - handed back to the test
            out["error"] = exc

    previous = threading.stack_size(SMALL_STACK)
    try:
        worker = threading.Thread(target=run)
        worker.start()
    finally:
        threading.stack_size(previous)
    worker.join()
    if "error" in out:
        raise out["error"]
    return out["value"]


def deep_bytes(depth):
    return b"[" * depth + b"]" * depth


def too_deep_on_small_stack(blob):
    def parse():
        try:
            json.loads(blob)
        except RecursionError:
            return True
        return False
    return on_small_stack(parse)


def rebound(mod, name, **overrides):
    """One hub function bound to a copy of the module namespace with the given
    names replaced; the loaded module itself is left untouched."""
    fn = mod.__dict__[name]
    namespace = dict(mod.__dict__)
    namespace.update(overrides)
    copy = types.FunctionType(fn.__code__, namespace, fn.__name__, fn.__defaults__, fn.__closure__)
    copy.__kwdefaults__ = fn.__kwdefaults__
    return copy


def fake_unix_socket_module(reply):
    class Conn:
        def __init__(self, *args):
            self.reply = reply

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def settimeout(self, value):
            pass

        def connect(self, path):
            pass

        def sendall(self, data):
            pass

        def recv(self, size):
            chunk, self.reply = self.reply[:size], self.reply[size:]
            return chunk

        def close(self):
            pass

    return types.SimpleNamespace(AF_UNIX=socket.AF_UNIX, SOCK_STREAM=socket.SOCK_STREAM, socket=Conn)


def raised(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - the test inspects it
        return exc
    raise AssertionError("expected a refusal")


def t_signer_status_reply_too_deep_to_parse_is_unreachable(tmp):
    mod = load(tmp)
    reply = deep_bytes(32000) + b"\n"
    assert len(reply) <= 65536 and too_deep_on_small_stack(reply[:-1])
    status = rebound(mod, "winn3_signer_status", socket=fake_unix_socket_module(reply))
    assert on_small_stack(status) is None
    # The route answers it as an unreachable signer: 503, epoch unknown.
    route = rebound(mod, "admin_get_node_winn3_signer_ticket", winn3_signer_status=status)
    exc = raised(lambda: on_small_stack(lambda: route(
        FakeRequest(headers={}, body={}), slug="", x_admin_token=ADMIN)))
    assert isinstance(exc, HTTPException) and exc.status_code == 503, repr(exc)


def t_signer_client_reply_too_deep_to_parse_is_malformed(tmp):
    mod = load(tmp)
    reply = deep_bytes(32000) + b"\n"
    assert len(reply) <= 65536 and too_deep_on_small_stack(reply[:-1])
    client = rebound(mod, "winn3_signer_client", socket=fake_unix_socket_module(reply))
    exc = raised(lambda: on_small_stack(lambda: client({"verb": "status"})))
    assert type(exc) is ValueError and str(exc) == "signer-reply-malformed", repr(exc)


def t_identity_pull_too_deep_to_parse_is_malformed(tmp):
    mod = load(tmp)
    stdout = deep_bytes(32000)
    assert len(stdout) <= 65536 and too_deep_on_small_stack(stdout)
    fake_subprocess = types.SimpleNamespace(
        run=lambda argv, **kw: types.SimpleNamespace(returncode=0, stdout=stdout))
    # The pull reads through the bounded management runner; bind that runner
    # to the same fake transport.
    runner = rebound(
        mod, "run_management_ssh_bounded",
        management_ssh_env=lambda: {"PATH": "/usr/bin:/bin"},
        subprocess=fake_subprocess)
    pull = rebound(
        mod, "winn3_pull_identity",
        node_ssh_command=lambda host, command, **kw: ["ssh-test"],
        management_ssh_env=lambda: {"PATH": "/usr/bin:/bin"},
        subprocess=fake_subprocess,
        run_management_ssh_bounded=runner)
    node = {"slug": "lab-alpha", "ssh_host": "node.example.test", "endpoint": "198.51.100.7:51820"}
    exc = raised(lambda: on_small_stack(lambda: pull(node)))
    assert type(exc) is ValueError and str(exc) == "identity-pull-malformed", repr(exc)


def t_pulled_identity_too_deep_to_parse_is_malformed(tmp):
    mod = load(tmp)
    raw = deep_bytes(20000)
    assert too_deep_on_small_stack(raw)
    pulled = {"identity": base64.b64encode(raw).decode(), "identity_sig": base64.b64encode(b"sig").decode(),
              "admission_secret": "ab" * 32, "detected_public_ip": "198.51.100.7"}
    # The pull bounds stdout at 64 KiB, so this identity is one a node can send.
    assert len(json.dumps(pulled)) <= 65536
    node = {"slug": "lab-alpha", "endpoint": "198.51.100.7:51820"}
    exc = raised(lambda: on_small_stack(lambda: mod.winn3_check_pulled_identity(node, pulled)))
    assert type(exc) is ValueError and str(exc) == "identity-malformed", repr(exc)


def main():
    tmp = tempfile.mkdtemp(prefix="winshub-h4-ticket-")
    for name, fn in sorted(globals().items()):
        if name.startswith("t_") and callable(fn):
            check(name, lambda fn=fn: fn(tmp))
    print(f"\n{PASSED[0]} passed, {len(FAILURES)} failed")
    for name, tb in FAILURES:
        print(f"\n===== {name} =====\n{tb}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
