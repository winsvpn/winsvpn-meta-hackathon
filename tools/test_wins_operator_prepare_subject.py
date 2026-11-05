#!/usr/bin/env python3
"""H4: t1 ticket minting in tools/wins_operator_prepare_subject.sh (design v17
3.1 step 1, 3.8 and their 5.5 tests).

The real tool is driven under bash with a curl shim on PATH, because this Mac
has no hub to talk to and the lane allows no network: the shim records every
call (method, URL, header, body file) and answers with canned responses, the
way the H1 suite shims stat, install and readlink for the installer's bash
functions. Every key is a throwaway made in a temp directory.

WHAT IS UNDER TEST:

  * REQUIRED, WITH NO DEFAULT. The tool refuses to mint a ticket without
    --go-live and --tier (5.5), and refuses an incomplete ticket input set.
  * THE CANONICAL CONTRACT. The payload is canonical JSON (sorted keys,
    compact separators), exactly what the signer accepts and the hub
    re-verifies (H1 contract ruling), signed by t1 over the ticket domain.
  * THE EPOCH COMES FROM THE SIGNER. The tool asks the hub's ticket route
    before signing, and dies when it cannot learn the epoch.
"""
import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(REPO, "tools", "wins_operator_prepare_subject.sh")
TICKET_DOMAIN = b"winsvpn-winn3-signer-ticket/v1"

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


def run_openssl(argv, data=None):
    done = subprocess.run(["openssl", *argv], input=data, capture_output=True, check=False)
    assert done.returncode == 0, done.stderr.decode()
    return done.stdout


class Rig:
    """A temp directory with throwaway keys, a host-keys file and a curl shim."""

    def __init__(self, tmp):
        self.tmp = tmp
        self.calls = os.path.join(tmp, "calls.log")
        self.shim = os.path.join(tmp, "shim", "curl")
        os.makedirs(os.path.dirname(self.shim))
        with open(self.shim, "w") as fh:
            fh.write(CURL_SHIM)
        os.chmod(self.shim, 0o755)
        # The throwaway t1 key and the target's verified host key.
        self.t1 = os.path.join(tmp, "t1.pem")
        run_openssl(["genpkey", "-algorithm", "ED25519", "-out", self.t1])
        self.t1_pub = run_openssl(["pkey", "-in", self.t1, "-pubout", "-outform", "DER"])[12:]
        host = os.path.join(tmp, "host_ed25519")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", host],
                       check=True, capture_output=True)
        self.host_line = open(host + ".pub").read().split()
        blob = base64.b64decode(self.host_line[1])
        self.host_fp = "SHA256:" + base64.b64encode(
            hashlib.sha256(blob).digest()).decode().rstrip("=")
        self.host_keys = os.path.join(tmp, "host-keys")
        with open(self.host_keys, "w") as fh:
            fh.write(f"{self.host_line[0]} {self.host_line[1]} test-host\n")
        os.chmod(self.host_keys, 0o600)
        self.admin = os.path.join(tmp, "admin-token")
        with open(self.admin, "w") as fh:
            fh.write("a" * 48 + "\n")
        os.chmod(self.admin, 0o600)
        self.out = os.path.join(tmp, "out.env")

    def env(self, get_epoch=3, post_ok=True, get_fail=False):
        return {
            "PATH": os.path.dirname(self.shim) + ":" + os.environ["PATH"],
            "PREPARE_CALLS": self.calls,
            "PREPARE_GET_EPOCH": str(get_epoch),
            "PREPARE_GET_FAIL": "1" if get_fail else "",
            "PREPARE_POST_OK": "1" if post_ok else "",
        }

    def base_args(self):
        return [TOOL, "--role", "data", "--subject", "test-node-1",
                "--hub", "https://hub.example.test",
                "--admin-token-file", self.admin, "--out", self.out,
                "--host-keys-file", self.host_keys,
                "--no-tunnel", "--no-grant"]

    def ticket_args(self):
        return ["--endpoint-ip", "203.0.113.10", "--t1-key", self.t1,
                "--action", "new", "--go-live", "auto", "--tier", "free"]

    def run(self, args, env=None):
        return subprocess.run(["bash", *args], capture_output=True, text=True,
                              env={**os.environ, **(env or self.env())})

    def calls_of(self, method=None):
        if not os.path.exists(self.calls):
            return []
        rows = []
        for line in open(self.calls):
            parts = line.rstrip("\n").split("\t")
            if method is None or parts[0] == method:
                rows.append(parts)
        return rows


CURL_SHIM = r'''#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
config = sys.stdin.read()
out, method, body, url, header = None, "GET", None, None, None
i = 0
while i < len(args):
    a = args[i]
    if a == "-o": out, i = args[i + 1], i + 2
    elif a == "-X": method, i = args[i + 1], i + 2
    elif a == "--data-binary": body, i = args[i + 1], i + 2
    elif a == "-w": i += 2
    elif a == "-H": header, i = args[i + 1], i + 2
    elif a.startswith("-"): i += 1
    else: url, i = a, i + 1
config_header = ""
for line in config.splitlines():
    if line.startswith("header = "):
        config_header = line[len("header = "):].strip('"')
# The tool's EXIT trap removes its work directory, so the body is copied to a
# persistent file before the call is recorded.
recorded_body = ""
if body:
    bodies = os.environ["PREPARE_CALLS"] + ".d"
    os.makedirs(bodies, exist_ok=True)
    recorded_body = os.path.join(bodies, f"{method}-{len(os.listdir(bodies))}.body")
    with open(body[1:] if body.startswith("@") else body, "rb") as src:
        data = src.read()
    with open(recorded_body, "wb") as dst:
        dst.write(data)
with open(os.environ["PREPARE_CALLS"], "a") as fh:
    fh.write(f"{method}\t{url}\t{config_header}\t{header or ''}\t{recorded_body}\n")
code = "200"
text = '{"ok": false, "detail": "nope"}'
if method == "GET" and url.endswith("/admin/nodes/winn3/signer-ticket"):
    if os.environ.get("PREPARE_GET_FAIL"):
        code = "000"
    else:
        text = '{"ok": true, "epoch": %s, "signer_reachable": true}' % os.environ["PREPARE_GET_EPOCH"]
elif method == "POST" and url.endswith("/admin/nodes/winn3/signer-ticket"):
    text = '{"ok": true, "stored": true}' if os.environ.get("PREPARE_POST_OK") \
        else '{"ok": false, "detail": "Rejected: signer ticket (reason=signer-ticket-action)."}'
elif method == "POST" and url.endswith("/admin/bootstrap-grant"):
    text = '{"ok": true, "bootstrap_token": "%s"}' % ("b" * 43)
elif method == "POST" and url.endswith("bootstrap-management-tunnel"):
    text = '{"ok": true, "management_mode": "cloudflare_tunnel", "tunnel_token": "%s", "ssh_host": "t.example.test", "tunnel_id": "%s"}' % ("c" * 90, "12345678-1234-4123-8123-123456789012")
with open(out, "w") as fh:
    fh.write(text)
print(code)
'''


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def post_body(rig):
    rows = rig.calls_of("POST")
    assert len(rows) == 1, rows
    method, url, config_header, header, body_file = rows[0]
    assert url == "https://hub.example.test/admin/nodes/wins3/signer-ticket".replace("wins3", "winn3"), url
    assert config_header == "x-admin-token: " + "a" * 48, config_header
    assert header == "Content-Type: application/json", header
    return json.loads(open(body_file).read())


def decode_posted_ticket(rig):
    body = post_body(rig)
    assert set(body) == {"slug", "ticket"}, body
    assert body["slug"] == "test-node-1"
    assert set(body["ticket"]) == {"payload", "sig"}
    payload = base64.b64decode(body["ticket"]["payload"])
    signature = base64.b64decode(body["ticket"]["sig"])
    return body, payload, signature


def verify_t1(rig, payload, signature):
    """The posted signature verifies under the throwaway t1 public half."""
    with tempfile.TemporaryDirectory() as work:
        key = os.path.join(work, "t1.der")
        msg = os.path.join(work, "m.bin")
        sig = os.path.join(work, "s.bin")
        with open(key, "wb") as fh:
            fh.write(bytes.fromhex("302a300506032b6570032100") + rig.t1_pub)
        with open(msg, "wb") as fh:
            fh.write(TICKET_DOMAIN + b"\x00" + payload)
        with open(sig, "wb") as fh:
            fh.write(signature)
        done = subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                               "-inkey", key, "-keyform", "DER", "-sigfile", sig,
                               "-in", msg], capture_output=True)
        assert done.returncode == 0, done.stderr.decode()


# ------------------------------------------------------------------ tests --

def t_mints_a_canonical_signed_ticket(rig):
    before = int(time.time())
    done = rig.run(rig.base_args() + rig.ticket_args())
    assert done.returncode == 0, done.stderr
    # One GET for the epoch, one POST of the ticket, in that order.
    rows = rig.calls_of()
    assert [r[0] for r in rows] == ["GET", "POST"], rows
    get = rows[0]
    assert get[1] == "https://hub.example.test/admin/nodes/winn3/signer-ticket"
    assert get[2] == "x-admin-token: " + "a" * 48, get
    assert get[3] == "Accept: application/json", get
    body, payload, signature = decode_posted_ticket(rig)
    # Canonical JSON, exactly (H1 contract ruling).
    ticket = json.loads(payload)
    assert canonical(ticket) == payload
    assert set(ticket) == {"slug", "action", "epoch", "endpoint_ip", "gateway_id",
                           "host_key_sha256", "go_live", "tier", "nonce", "not_after"}
    assert ticket["slug"] == "test-node-1"
    assert ticket["action"] == "new"
    assert ticket["epoch"] == 3
    assert ticket["endpoint_ip"] == "203.0.113.10"
    assert ticket["gateway_id"] == "test-node-1-gw1"
    assert ticket["host_key_sha256"] == rig.host_fp
    assert ticket["go_live"] == "auto" and ticket["tier"] == "free"
    assert len(ticket["nonce"]) == 64 and ticket["nonce"] == ticket["nonce"].lower()
    assert all(c in "0123456789abcdef" for c in ticket["nonce"])
    # Seven days less a ten minute margin: the hub and the signer measure the
    # 7 day maximum on their own clocks, and a Mac whose clock leads would be
    # refused at exactly 7 days.
    assert before + 7 * 86400 - 600 <= ticket["not_after"] <= int(time.time()) + 7 * 86400 - 600
    # The t1 signature over DOMAIN || 0x00 || payload verifies.
    verify_t1(rig, payload, signature)
    # The host key fingerprint is the ssh-keygen form of the verified host key.
    fp = subprocess.run(["ssh-keygen", "-lf", rig.host_keys], capture_output=True, text=True)
    assert rig.host_fp in fp.stdout, fp.stdout
    assert "Minted and posted the t1 new ticket" in done.stdout, done.stdout


def t_refuses_to_mint_without_go_live(rig):
    args = [a for a in rig.ticket_args() if a != "--go-live" and a != "auto"]
    done = rig.run(rig.base_args() + args)
    assert done.returncode != 0
    assert "--go-live is required" in done.stderr, done.stderr
    assert rig.calls_of("POST") == []


def t_refuses_to_mint_without_tier(rig):
    args = [a for a in rig.ticket_args() if a != "--tier" and a != "free"]
    done = rig.run(rig.base_args() + args)
    assert done.returncode != 0
    assert "--tier is required" in done.stderr, done.stderr
    assert rig.calls_of("POST") == []


def t_refuses_incomplete_ticket_inputs(rig):
    cases = [(["--endpoint-ip", "203.0.113.10"], "together"),
             (["--t1-key", rig.t1], "together"),
             (["--action", "new"], "together"),
             (["--go-live", "auto"], "--go-live is required"),
             (["--tier", "free"], "--tier is required")]
    for missing, message in cases:
        args = list(rig.ticket_args())
        for value in missing:
            args.remove(value)
        done = rig.run(rig.base_args() + args)
        assert done.returncode != 0, (missing, done.stdout)
        assert message in done.stderr, (missing, done.stderr)
    assert rig.calls_of("POST") == []
    # A lone --go-live is an incomplete set too.
    done = rig.run(rig.base_args() + ["--go-live", "auto"])
    assert done.returncode != 0 and "--tier is required" in done.stderr, done.stderr


def t_refuses_a_ticket_for_a_core(rig):
    # Signer tickets are for data-plane nodes (3.8): a Core id is never a slug.
    args = [a if a != "data" else "core" for a in rig.base_args()]
    done = rig.run(args + rig.ticket_args())
    assert done.returncode != 0 and "--role data" in done.stderr, done.stderr
    assert rig.calls_of() == []


def t_refuses_invalid_ticket_values(rig):
    bad = [(["--action", "promote"], "--action must be"),
           (["--go-live", "yes"], "--go-live must be"),
           (["--tier", "gold"], "--tier must be"),
           (["--endpoint-ip", "999.1.1.1"], "--endpoint-ip must be"),
           (["--endpoint-ip", "203.0.113.10.5"], "--endpoint-ip must be"),
           (["--endpoint-ip", "203.0.113.010"], "--endpoint-ip must be"),
           (["--endpoint-ip", "hub.example.test"], "--endpoint-ip must be")]
    for replacement, message in bad:
        args = list(rig.ticket_args())
        flag = replacement[0]
        index = args.index(flag)
        args[index + 1] = replacement[1]
        done = rig.run(rig.base_args() + args)
        assert done.returncode != 0, (replacement, done.stdout)
        assert message in done.stderr, (replacement, done.stderr)
    assert rig.calls_of("POST") == []


# H4R-T4: an octet is compared as a number only after it matched the octet
# pattern. Bash arithmetic would otherwise evaluate the operator's text,
# including a command substitution in an array subscript.
def t_an_endpoint_ip_is_never_evaluated_as_arithmetic(rig):
    args = list(rig.ticket_args())
    args[args.index("--endpoint-ip") + 1] = "203.0.113.0+octets[$(echo EVALUATED >&2; echo 0)]"
    done = rig.run(rig.base_args() + args)
    assert done.returncode != 0, done.stdout
    assert "--endpoint-ip must be" in done.stderr, done.stderr
    assert "EVALUATED" not in done.stderr, done.stderr
    assert rig.calls_of() == []


# H4R-T5: the value is matched whole before it is split. `read` drops a
# trailing empty field and reads one line only, so a trailing dot or a second
# line after a valid address must not pass as four octets.
def t_an_endpoint_ip_with_a_trailing_dot_or_a_newline_is_refused(rig):
    for value in ("203.0.113.10.", "203.0.113.10\n203.0.113.11", "203.0.113.10\n"):
        args = list(rig.ticket_args())
        args[args.index("--endpoint-ip") + 1] = value
        done = rig.run(rig.base_args() + args)
        assert done.returncode != 0, (value, done.stdout)
        assert "--endpoint-ip must be" in done.stderr, (value, done.stderr)
    assert rig.calls_of() == []


def t_refuses_a_loose_t1_key_and_ambiguous_host_keys(rig):
    loose = os.path.join(rig.tmp, "loose.pem")
    shutil.copy(rig.t1, loose)
    os.chmod(loose, 0o644)
    args = list(rig.ticket_args())
    args[args.index("--t1-key") + 1] = loose
    done = rig.run(rig.base_args() + args)
    assert done.returncode != 0 and "group or other" in done.stderr, done.stderr
    # Two ssh-ed25519 host keys: the ticket cannot pin one.
    other = os.path.join(rig.tmp, "host_ed25519_2")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", other],
                   check=True, capture_output=True)
    with open(rig.host_keys, "a") as fh:
        fh.write(open(other + ".pub").read())
    done = rig.run(rig.base_args() + rig.ticket_args())
    assert done.returncode != 0 and "exactly one ssh-ed25519" in done.stderr, done.stderr
    # No ssh-ed25519 line at all.
    with open(rig.host_keys, "w") as fh:
        fh.write("ssh-rsa " + "A" * 68 + " rsa-host\n")
    done = rig.run(rig.base_args() + rig.ticket_args())
    assert done.returncode != 0 and "exactly one ssh-ed25519" in done.stderr, done.stderr
    assert rig.calls_of("POST") == []


def t_dies_when_the_epoch_is_unavailable(rig):
    done = rig.run(rig.base_args() + rig.ticket_args(),
                   env=rig.env(get_fail=True))
    assert done.returncode != 0
    assert "ticket epoch" in done.stderr, done.stderr
    assert rig.calls_of("POST") == []


def t_dies_when_the_hub_refuses_the_post(rig):
    done = rig.run(rig.base_args() + rig.ticket_args(), env=rig.env(post_ok=False))
    assert done.returncode != 0
    assert "The hub refused the signer ticket" in done.stderr, done.stderr


def t_without_ticket_inputs_behaves_as_before(rig):
    done = rig.run(rig.base_args())
    assert done.returncode == 0, done.stderr
    # No ticket call at all, and the fragment is written as before.
    assert rig.calls_of() == []
    text = open(rig.out).read()
    assert "NODE_SLUG='test-node-1'" in text
    assert stat.S_IMODE(os.stat(rig.out).st_mode) == 0o600
    assert "ADMIN" not in text


def t_suspend_ticket_mints_with_the_same_contract(rig):
    args = list(rig.ticket_args())
    args[args.index("--action") + 1] = "suspend"
    args[args.index("--go-live") + 1] = "manual"
    args[args.index("--tier") + 1] = "premium"
    done = rig.run(rig.base_args() + args, env=rig.env(get_epoch=9))
    assert done.returncode == 0, done.stderr
    body, payload, signature = decode_posted_ticket(rig)
    ticket = json.loads(payload)
    assert canonical(ticket) == payload
    assert ticket["action"] == "suspend" and ticket["epoch"] == 9
    assert ticket["go_live"] == "manual" and ticket["tier"] == "premium"
    verify_t1(rig, payload, signature)


def t_preserves_an_explicit_adopted_gateway_id(rig):
    # 2.6: an adopted gateway keeps the ID recorded for it, so the operator
    # passes it; the default stays <slug>-gw1 for a fresh node (2.3).
    done = rig.run(rig.base_args() + rig.ticket_args() + ["--gateway-id", "adopted.gw:7_a-b"])
    assert done.returncode == 0, done.stderr
    _body, payload, signature = decode_posted_ticket(rig)
    assert json.loads(payload)["gateway_id"] == "adopted.gw:7_a-b"
    verify_t1(rig, payload, signature)


def t_refuses_a_gateway_id_the_canary_would_refuse(rig):
    good = rig.run(rig.base_args() + rig.ticket_args() + ["--gateway-id", "good-gw1"])
    assert good.returncode == 0, good.stderr
    posted = len(rig.calls_of("POST"))
    os.unlink(rig.out)
    for bad in ("", " lead", "trail ", "a b", "tab\there", "x" * 129, "caf\u00e9", "a/b", "a\"b"):
        args = list(rig.ticket_args()) + ["--gateway-id", bad]
        done = rig.run(rig.base_args() + args)
        assert done.returncode != 0, (bad, done.stdout)
        assert "--gateway-id" in done.stderr or "--go-live" in done.stderr, (bad, done.stderr)
    assert len(rig.calls_of("POST")) == posted
    # A lone --gateway-id is an incomplete ticket set, not a legacy preparation.
    done = rig.run(rig.base_args() + ["--gateway-id", "solo-gw1"])
    assert done.returncode != 0 and "--go-live is required" in done.stderr, done.stderr
    assert len(rig.calls_of("POST")) == posted
    # So is a lone, explicitly empty --gateway-id (rebase: the only case the
    # gateway_id_given guard decides on its own).
    done = rig.run(rig.base_args() + ["--gateway-id", ""])
    assert done.returncode != 0 and "--gateway-id" in done.stderr, done.stderr
    assert len(rig.calls_of("POST")) == posted


def t_a_gateway_id_for_a_core_is_refused(rig):
    args = [a if a != "data" else "core" for a in rig.base_args()]
    done = rig.run(args + ["--gateway-id", "x-gw1"])
    assert done.returncode != 0 and "--role data" in done.stderr, done.stderr
    assert rig.calls_of() == []


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("t_") and callable(fn):
            rig = Rig(tempfile.mkdtemp(prefix="wins-prepare-subject-h4-"))
            check(name, lambda fn=fn, rig=rig: fn(rig))
    print(f"\n{PASSED[0]} passed, {len(FAILURES)} failed")
    for name, tb in FAILURES:
        print(f"\n===== {name} =====\n{tb}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
