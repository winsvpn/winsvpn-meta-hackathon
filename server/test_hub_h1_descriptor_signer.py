#!/usr/bin/env python3
"""H1 descriptor signer, design v17 sections 3.4 to 3.13 and their 5.5 / 5.6 tests.

The signer program is extracted from the control-plane installer heredoc and
driven in-process with throwaway keys made in temp directories: a g-slot key,
a t1 ticket key and an SSH host key. No real key is used or created. The
installer's own bash functions (key injection with the active-slot pin and the
scrub, config, env) run under bash with small GNU shims, because this Mac has
BSD stat, install and readlink.

What needs a real systemd sandbox (SO_PEERPIDFD from wins-hub.service,
PrivateNetwork, the socket unit's ownership, InaccessiblePaths from the hub's
context) is Tier A work and is not run here.
"""
import _toolchain  # noqa: F401
import base64
import errno
import hashlib
import importlib.util
import json
import os
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = Path(__file__).resolve().parent / "wins_control_plane_setup_ONETOUCH.sh"
SOURCE = INSTALLER.read_text(encoding="utf-8")
OPENSSL = _toolchain.require_openssl_ed25519()
BASH = _toolchain.bash4()
SSH_KEYGEN = shutil.which("ssh-keygen")

SIGNER_HEADER = "cat > /usr/local/lib/wins_descriptor_signer.py <<'DESCSIGNEREOF'"
MAIL_HEADER = "cat > /usr/local/lib/wins_descriptor_signer_digest_mail.py <<'DESCDIGESTMAILEOF'"
SIGNER_UNIT = "cat > /etc/systemd/system/wins-descriptor-signer.service <<'EOF'"
SOCKET_UNIT = "cat > /etc/systemd/system/wins-descriptor-signer.socket <<'EOF'"
DIGEST_UNIT = "cat > /etc/systemd/system/wins-descriptor-signer-digest.service <<'EOF'"
MAIL_UNIT = "cat > /etc/systemd/system/wins-descriptor-signer-digest-mail.service <<'EOF'"
TIMER_UNIT = "cat > /etc/systemd/system/wins-descriptor-signer-digest.timer <<'EOF'"
HUB_UNIT = 'cat > "${SERVICE_FILE}" <<EOF'
TMPFILES = "cat > /etc/tmpfiles.d/wins-hub-runtime.conf <<'EOF'"
BACKUP_SCRIPT = "cat > /usr/local/bin/wins-hub-backup <<'EOF'"
LITESTREAM_CONFIG = "cat > /etc/litestream.yml <<LSYAML"
T0 = 1_800_000_000
DAY = 86400


def heredoc(source, header):
    tag = re.search(r"<<-?'?([A-Za-z_][A-Za-z0-9_]*)'?$", header).group(1)
    start = source.index(header + "\n") + len(header) + 1
    return source[start:source.index("\n" + tag + "\n", start) + 1]


def unit(source, header):
    props = {}
    for line in heredoc(source, header).splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            props.setdefault(key, []).append(value)
    return props


def run(argv, data=None):
    done = subprocess.run(argv, input=data, capture_output=True, check=False)
    assert done.returncode == 0, done.stderr.decode()
    return done.stdout


# ------------------------------------------------------------------ signer --

def load_signer(tmp, slot="g2"):
    path = tmp / "wins_descriptor_signer.py"
    path.write_text(heredoc(SOURCE, SIGNER_HEADER))
    spec = importlib.util.spec_from_file_location(f"signer_{id(tmp)}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for name in ("config", "state", "work", "digest"):
        (tmp / name).mkdir(mode=0o700)
    mod.CONFIG_DIR, mod.STATE_DIR = str(tmp / "config"), str(tmp / "state")
    mod.WORK_DIR, mod.DIGEST_DIR = str(tmp / "work"), str(tmp / "digest")
    mod.HUB_KEY_HISTORY = str(tmp / "hub-key-history")
    mod.OPERATOR_SSH_KEYS = str(tmp / "operator-ssh-keys")
    mod.OPENSSL, mod.SSH_KEYGEN = OPENSSL, SSH_KEYGEN
    return mod


def genkey(path):
    run([OPENSSL, "genpkey", "-algorithm", "ED25519", "-out", str(path)])
    return run([OPENSSL, "pkey", "-in", str(path), "-pubout", "-outform", "DER"])[12:]


def openssl_sign(key, message, tmp):
    msg = tmp / "m.bin"
    msg.write_bytes(message)
    return run([OPENSSL, "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(msg)])


class Hub:
    """One hub-lite: a signer config, throwaway keys and request builders."""

    def __init__(self, tmp, slot="g2"):
        self.tmp = tmp
        self.mod = load_signer(tmp)
        self.clock = [T0]
        self.mod.CLOCK = lambda: self.clock[0]
        self.slot = slot
        self.gkey = tmp / "config" / f"{slot}.ed25519.pem"
        self.gpub = genkey(self.gkey)
        self.t1 = tmp / "t1.pem"
        self.t1pub = genkey(self.t1)
        self.write_config()
        (tmp / "config" / "ticket-epoch").write_text("1\n")
        # The signer never creates its ledger (3.12): the operator CLI does.
        self.mod.write_ledger(self.mod.empty_ledger())
        self.hosts = {}
        self.nonce = 0

    def write_config(self, slot=None, pub=None):
        (self.tmp / "config" / "signer.json").write_text(json.dumps({
            "active_slot": slot or self.slot,
            "active_slot_pubkey": base64.b64encode(pub or self.gpub).decode(),
            "ticket_pubkey_t1": base64.b64encode(self.t1pub).decode()}))

    def signer(self):
        return self.mod.Signer()

    def host(self, name):
        if name not in self.hosts:
            key = self.tmp / f"host-{name}"
            run([SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
            line = (self.tmp / f"host-{name}.pub").read_text().split()
            blob = base64.b64decode(line[1])
            fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
            self.hosts[name] = (key, f"{line[0]} {line[1]}", fp)
        return self.hosts[name]

    def ticket(self, slug, action="new", host="a", endpoint_ip="203.0.113.10", gateway_id=None,
               epoch=1, not_after=None, go_live="auto", tier="free", domain=None, key=None):
        self.nonce += 1
        body = {"slug": slug, "action": action, "epoch": epoch, "endpoint_ip": endpoint_ip,
                "gateway_id": gateway_id or f"{slug}-gw1", "host_key_sha256": self.host(host)[2],
                "go_live": go_live, "tier": tier, "nonce": f"{self.nonce:032x}",
                "not_after": not_after if not_after is not None else self.clock[0] + 3 * DAY}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        sig = openssl_sign(key or self.t1, (domain or self.mod.TICKET_DOMAIN) + b"\x00" + raw, self.tmp)
        return {"payload": base64.b64encode(raw).decode(), "sig": base64.b64encode(sig).decode()}

    def identity(self, slug, host="a", sign_host=None, endpoint_ip="203.0.113.10", gateway_id=None,
                 secret=None, static=b"\x11" * 32, tamper=None):
        secret = secret or hashlib.sha256(slug.encode()).hexdigest()
        body = {"slug": slug, "gateway_id": gateway_id or f"{slug}-gw1",
                "endpoint": f"{endpoint_ip}:9111", "inner_router_v4": "10.10.0.1",
                "inner_resolver_v4": "10.10.0.1", "path_mtu": 1450, "plan": "udp",
                "static_pub_hex": static.hex(), "auth_ed25519_hex": ("22" * 32),
                "auth_mldsa65_hex": ("33" * 1952),
                "admission_fingerprint": self.mod.admission_fingerprint(secret),
                "credential_record_sha256": "44" * 32,
                "ssh_host_ed25519_key": self.host(host)[1]}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        doc = self.tmp / "identity.json"
        doc.write_bytes(raw)
        sig_path = self.tmp / "identity.json.sig"
        if sig_path.exists():
            sig_path.unlink()
        run([SSH_KEYGEN, "-q", "-Y", "sign", "-f", str(self.host(sign_host or host)[0]),
             "-n", "winsvpn-winn3-identity/v1", str(doc)])
        if tamper:
            raw = tamper(raw)
        return {"identity": base64.b64encode(raw).decode(),
                "identity_sig": base64.b64encode(sig_path.read_bytes()).decode(),
                "admission_secret": secret}

    def sign(self, signer, slug, eps=-1, generation=1, verb="sign", action="new", ticket=None, **kw):
        request = {"verb": verb, "slug": slug, "generation": generation, "expected_prior_seq": eps,
                   "ticket": ticket or self.ticket(slug, action=action, **{k: v for k, v in kw.items() if k in ("host", "endpoint_ip", "gateway_id")})}
        request.update(self.identity(slug, **{k: v for k, v in kw.items() if k in ("host", "sign_host", "endpoint_ip", "gateway_id", "secret", "static", "tamper")}))
        return signer.handle(request)

    def payload(self, reply):
        raw = base64.b64decode(reply["payload"])
        message = self.mod.DESCRIPTOR_DOMAIN + b"\x00" + raw
        assert self.mod.ed25519_verify(self.gpub, message, base64.b64decode(reply["sig"]))
        return json.loads(raw)


@pytest.fixture
def hub(tmp_path):
    return Hub(tmp_path)


def ledger(hub):
    return json.loads((hub.tmp / "state" / "ledger.json").read_text())


# 5.5 Signer: sign happy path, the descriptor format (3.6) and its persistence.
def test_sign_issues_a_verified_format3_descriptor_and_persists_before_reply(hub):
    signer = hub.signer()
    reply = hub.sign(signer, "sg-1")
    assert reply["ok"] and reply["orphan"] is False, reply
    payload = hub.payload(reply)
    assert payload["v"] == 3 and payload["alg"] == "ed25519" and payload["kid"] == "g2"
    assert payload["node"] == "sg-1" and payload["endpoint"] == "203.0.113.10:9111"
    assert base64.b64decode(payload["admission_secret"]) == hashlib.sha256(b"sg-1").hexdigest().encode()
    assert base64.b64decode(payload["gateway_id"]) == b"sg-1-gw1"
    assert payload["not_after"] - payload["iat"] == 14 * DAY and payload["seq"] == 0
    assert payload["admission_gen"] == 1 and reply["go_live"] == "auto" and reply["tier"] == "free"
    assert set(payload) == {"v", "alg", "kid", "node", "endpoint", "inner_router_v4", "inner_resolver_v4",
                            "static_pub", "gateway_id", "admission_secret", "admission_gen", "tag_size",
                            "padding", "bucket_window_s", "max_skew_s", "auth_ed25519", "auth_mldsa65",
                            "seq", "iat", "not_after"}
    assert reply["identity_sha256"] == hub.mod.identity_sha256(payload)
    state = ledger(hub)
    assert state["slugs"]["sg-1"]["floor"] == 0 and len(state["nonces"]) == 1
    assert stat.S_IMODE(os.stat(hub.tmp / "state" / "ledger.json").st_mode) == 0o600
    assert hub.mod.audit_chain_ok(state)


# 5.5: a ticket is required; domain separation; single use.
def test_ticket_required_domain_separated_and_single_use(hub):
    signer = hub.signer()
    assert hub.sign(signer, "a1", ticket={"payload": "", "sig": ""})["error"] == "ticket-malformed"
    wrong_domain = hub.ticket("a1", domain=hub.mod.DESCRIPTOR_DOMAIN)
    assert hub.sign(signer, "a1", ticket=wrong_domain)["error"] == "ticket-signature-invalid"
    # A descriptor signed by the g key never passes as a ticket either.
    descriptor_key = hub.ticket("a1", key=hub.gkey)
    assert hub.sign(signer, "a1", ticket=descriptor_key)["error"] == "ticket-signature-invalid"
    ticket = hub.ticket("a1")
    first = hub.sign(signer, "a1", ticket=ticket)
    assert first["ok"]
    # Replay with another expected_prior_seq is a new request: the nonce is spent.
    assert hub.sign(signer, "a1", eps=first["seq"], ticket=ticket)["error"] == "ticket-already-spent"
    assert hub.signer().handle({"verb": "renew", "slug": "a2", "generation": 1,
                                "expected_prior_seq": -1})["error"] == "no-live-issuance"


# 5.5: wrong host key, modified identity, identity relayed for the wrong slug.
def test_identity_host_key_signature_binds_the_ticketed_machine(hub):
    signer = hub.signer()
    assert hub.sign(signer, "b1", host="b", ticket=hub.ticket("b1", host="a"))["error"] == "identity-host-key-not-ticketed"
    assert hub.sign(signer, "b1", sign_host="b", ticket=hub.ticket("b1"))["error"] == "identity-host-signature-invalid"
    tampered = hub.sign(signer, "b1", ticket=hub.ticket("b1"),
                        tamper=lambda raw: raw.replace(b'"path_mtu":1450', b'"path_mtu":1400'))
    assert tampered["error"] == "identity-host-signature-invalid"
    relayed = hub.identity("b2")
    request = {"verb": "sign", "slug": "b1", "generation": 1, "expected_prior_seq": -1,
               "ticket": hub.ticket("b1"), **relayed}
    assert signer.handle(request)["error"] == "identity-wrong-slug"
    assert hub.sign(signer, "b1", ticket=hub.ticket("b2"))["error"] == "ticket-wrong-slug"
    unsigned = hub.identity("b1")
    unsigned["identity_sig"] = ""
    assert signer.handle({"verb": "sign", "slug": "b1", "generation": 1, "expected_prior_seq": -1,
                          "ticket": hub.ticket("b1"), **unsigned})["ok"] is False


# 5.5 residual-exposure test: bounds, not a refusal.
def test_residual_exposure_bounds_with_an_unused_ticket(hub):
    signer = hub.signer()
    ticket = hub.ticket("r1")
    changed = hub.sign(signer, "r1", ticket=ticket, static=b"\x99" * 32)
    assert changed["ok"]
    state = ledger(hub)
    spends = [e for e in state["audit"] if e["event"] == "ticket-spend"]
    assert spends[-1]["identity_sha256"] == changed["identity_sha256"]
    hub.mod.digest()
    text = (hub.tmp / "digest" / "latest.txt").read_text()
    assert changed["identity_sha256"] in text and "ticket-spend r1 new" in text
    # The operator's legitimate install is then refused: the ticket is spent.
    assert hub.sign(signer, "r1", eps=changed["seq"], ticket=ticket)["error"] == "ticket-already-spent"
    for kwargs, reason in (({"endpoint_ip": "198.51.100.7"}, "identity-endpoint-not-ticketed"),
                           ({"gateway_id": "other"}, "identity-gateway-id-not-ticketed"),
                           ({"host": "c"}, "identity-host-key-not-ticketed")):
        ticket = hub.ticket("r2")
        assert hub.sign(signer, "r2", ticket=ticket, **kwargs)["error"] == reason


# 5.5: rate limits, 4 new identities and 64 signatures per 24 h, 64 slugs.
def test_rate_limits_and_slug_cap(hub):
    signer = hub.signer()
    for n in range(4):
        assert hub.sign(signer, f"n{n}")["ok"]
    assert hub.sign(signer, "n4")["error"] == "rate-limit-new-identities"
    hub.clock[0] += DAY + 1
    assert hub.sign(signer, "n4")["ok"]
    state = ledger(hub)
    template = state["slugs"]["n0"]["issuances"][0]
    for n in range(63):
        state["slugs"][f"x{n}"] = {"state": "active", "floor": 0, "presented_stored": -1,
                                   "issuances": [dict(template, issued_at=hub.clock[0] - 10)]}
    hub.mod.write_ledger(state)
    signer = hub.signer()
    assert hub.sign(signer, "n5")["error"] == "rate-limit-signatures"
    hub.clock[0] += DAY + 1
    assert hub.sign(signer, "n6")["error"] == "slug-cap"


# 5.5: the kill file.
def test_kill_file_stops_every_issuance_and_status_still_answers(hub):
    signer = hub.signer()
    (hub.tmp / "config" / "DISABLED").write_text("")
    assert hub.sign(signer, "k1")["error"] == "signer-disabled"
    status = signer.handle({"verb": "status"})
    assert status["ok"] and status["disabled"] is True


# 5.5: the peer credential and cgroup check, with the pidfd pinning the process.
class FakeConn:
    def __init__(self, pid, uid, pidfd):
        self.creds = struct.pack("3i", pid, uid, 0)
        self.pidfd = pidfd

    def getsockopt(self, level, name, size=None):
        if size is not None:
            return self.creds
        if self.pidfd is None:
            raise OSError(errno.ENOPROTOOPT, "no SO_PEERPIDFD")
        if self.pidfd == "gone":
            raise OSError(errno.ESRCH, "peer exited")
        if isinstance(self.pidfd, OSError):
            raise self.pidfd
        return self.pidfd


def test_peer_check_requires_uid0_hub_cgroup_and_a_live_pidfd(hub, tmp_path, monkeypatch):
    mod = hub.mod
    proc = tmp_path / "proc"
    for pid, cgroup in ((10, "0::/system.slice/wins-hub.service\n"),
                        (11, "0::/system.slice/wins-hub.service.evil\n"),
                        (12, "0::/user.slice/user-0.slice/session-3.scope\n")):
        (proc / str(pid)).mkdir(parents=True)
        (proc / str(pid) / "cgroup").write_text(cgroup)
    assert mod.cgroup_is_hub(10, str(proc)) and not mod.cgroup_is_hub(11, str(proc))
    assert not mod.cgroup_is_hub(12, str(proc)) and not mod.cgroup_is_hub(13, str(proc))
    real_cgroup_is_hub = mod.cgroup_is_hub
    monkeypatch.setattr(mod, "cgroup_is_hub", lambda pid, root=None: real_cgroup_is_hub(pid, str(proc)))
    monkeypatch.setattr(mod.os, "close", lambda fd: None)
    monkeypatch.setattr(mod.socket, "SO_PEERCRED", 17, raising=False)   # Linux value; absent on macOS
    pids = {}
    monkeypatch.setattr(mod, "pidfd_pid", lambda fd: pids[fd].pop(0) if isinstance(pids[fd], list) else pids[fd])
    monkeypatch.setattr(mod, "pidfd_alive", lambda fd: fd != 99)
    pids[50] = 10
    assert mod.peer_is_hub(FakeConn(10, 0, 50))
    assert not mod.peer_is_hub(FakeConn(10, 1000, 50))          # not uid 0
    pids[51] = 12
    assert not mod.peer_is_hub(FakeConn(12, 0, 51))             # not the hub cgroup
    pids[52] = 11
    assert not mod.peer_is_hub(FakeConn(10, 0, 52))             # pidfd names another process
    pids[99] = 10
    assert not mod.peer_is_hub(FakeConn(10, 0, 99))             # exited during the read
    pids[53] = [10, -1]
    assert not mod.peer_is_hub(FakeConn(10, 0, 53))             # reaped, pid then reusable
    assert mod.peer_is_hub(FakeConn(10, 0, None))               # pre-6.5 kernel fallback
    assert not mod.peer_is_hub(FakeConn(12, 0, None))
    assert not mod.peer_is_hub(FakeConn(10, 0, "gone"))         # pidfd failed: no fallback


# Sol H1-T2: only ENOPROTOOPT (a kernel without the option) takes the unpinned
# pid fallback. Any other pidfd failure, and a negative descriptor, is refused
# without consulting the cgroup.
def test_only_enoprotoopt_takes_the_pid_fallback(hub, monkeypatch):
    mod = hub.mod
    consulted = []
    monkeypatch.setattr(mod, "cgroup_is_hub", lambda pid, proc=None: consulted.append(pid) or True)
    monkeypatch.setattr(mod.os, "close", lambda fd: None)
    monkeypatch.setattr(mod.socket, "SO_PEERCRED", 17, raising=False)
    for code in (errno.EMFILE, errno.ENFILE, errno.ENODATA, errno.EPERM, errno.EINVAL, errno.ESRCH):
        assert not mod.peer_is_hub(FakeConn(10, 0, OSError(code, "pidfd failed"))), code
    assert not mod.peer_is_hub(FakeConn(10, 0, OSError("no errno")))
    assert not mod.peer_is_hub(FakeConn(10, 0, -1))              # negative descriptor
    assert consulted == []
    assert mod.peer_is_hub(FakeConn(10, 0, OSError(errno.ENOPROTOOPT, "unsupported")))
    assert consulted == [10]


def test_socket_framing_one_request_one_reply(hub, monkeypatch):
    mod = hub.mod
    signer = hub.signer()
    for admitted, request, expected in ((True, b'{"verb":"status"}\n', True),
                                        (False, b'{"verb":"status"}\n', "peer-refused"),
                                        (True, b"x" * (mod.REQUEST_MAX_BYTES + 2), "request-malformed")):
        monkeypatch.setattr(mod, "peer_is_hub", lambda conn: admitted)
        left, right = socket.socketpair()
        with left, right:
            def send():
                try:
                    right.sendall(request)
                    right.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            sender = threading.Thread(target=send)
            sender.start()
            mod.serve_connection(signer, left)
            left.shutdown(socket.SHUT_WR)
            reply = json.loads(right.makefile("rb").readline())
            sender.join()
        assert reply["ok"] is True if expected is True else reply["error"] == expected


# 5.5: the sequence is written before the reply, and a failed write leaks nothing.
def test_sequence_written_and_fsynced_before_reply(hub, monkeypatch):
    signer = hub.signer()
    real = hub.mod.write_ledger
    monkeypatch.setattr(hub.mod, "write_ledger", lambda state: (_ for _ in ()).throw(OSError("disk full")))
    ticket = hub.ticket("w1")
    failed = hub.sign(signer, "w1", ticket=ticket)
    assert failed == {"ok": False, "error": "ledger-write-failed"}
    assert "w1" not in signer.ledger["slugs"] and not signer.ledger["nonces"]
    monkeypatch.setattr(hub.mod, "write_ledger", real)
    ok = hub.sign(signer, "w1", ticket=ticket)
    assert ok["ok"] and ledger(hub)["slugs"]["w1"]["floor"] == ok["seq"]


# 5.5: audit chain integrity.
def test_audit_chain_tamper_is_detected_and_blocks_issuance(hub):
    signer = hub.signer()
    assert hub.sign(signer, "c1")["ok"]
    state = ledger(hub)
    state["audit"][0]["seq"] = 7
    (hub.tmp / "state" / "ledger.json").write_text(json.dumps(state))
    signer = hub.signer()
    assert signer.ledger_ok is False
    assert hub.sign(signer, "c2")["error"] == "ledger-integrity"
    # Dropping the newest entry keeps the remaining links consistent; the head catches it.
    state = ledger(hub)
    state["audit"][0]["seq"] = 0
    assert hub.mod.audit_chain_ok(state)
    state["audit"].pop()
    assert not hub.mod.audit_chain_ok(state)
    hub.mod.digest()
    assert "BROKEN" in (hub.tmp / "digest" / "latest.txt").read_text()


# 5.5: idempotent re-fetch after a crash between ticket consumption and store.
def test_idempotent_refetch_returns_identical_bytes_without_a_second_ticket(hub):
    ticket = hub.ticket("i1")
    first = hub.sign(hub.signer(), "i1", ticket=ticket)
    again = hub.sign(hub.signer(), "i1", ticket=ticket)       # signer restarted
    assert again == first and len(ledger(hub)["nonces"]) == 1


def renew(hub, signer, slug, eps, generation=1):
    return signer.handle({"verb": "renew", "slug": slug, "generation": generation, "expected_prior_seq": eps})


# 5.5: renewal identical or refused; two renewal windows; stale prior refused.
def test_renewal_changes_only_seq_iat_not_after_and_two_windows(hub):
    signer = hub.signer()
    first = hub.sign(signer, "rn")
    assert renew(hub, signer, "rn", first["seq"])["error"] == "outside-renewal-window"
    hub.clock[0] += 8 * DAY
    second = renew(hub, signer, "rn", first["seq"])
    a, b = hub.payload(first), hub.payload(second)
    assert {k for k in a if a[k] != b[k]} == {"seq", "iat", "not_after"}
    assert b["seq"] > a["seq"] and b["not_after"] > a["not_after"]
    assert renew(hub, signer, "rn", first["seq"]) == second          # retry, identical bytes
    assert renew(hub, signer, "rn", second["seq"])["error"] in ("outside-renewal-window", "rate-limit-renewal")
    hub.clock[0] += 8 * DAY
    third = renew(hub, signer, "rn", second["seq"])
    assert third["ok"] and hub.payload(third)["not_after"] > b["not_after"] and third["seq"] > second["seq"]
    # The generation is not in the idempotency key: an old cycle's retry of the
    # second issuance gets its identical bytes, flagged as an orphan re-fetch.
    late = renew(hub, signer, "rn", first["seq"], generation=7)
    assert late["payload"] == second["payload"] and late["orphan"] is True
    # Below what the hub presented as stored, or above the live issue: stale.
    assert renew(hub, signer, "rn", -1)["error"] == "expected-prior-seq-stale"
    assert renew(hub, signer, "rn", third["seq"] + 5)["error"] == "expected-prior-seq-stale"


def test_renewal_rate_limit_one_per_slug_per_day(hub):
    signer = hub.signer()
    first = hub.sign(signer, "rl")
    hub.clock[0] += 13 * DAY
    second = renew(hub, signer, "rl", first["seq"])
    assert second["ok"]
    # Even if the hub somehow stored it and asked again inside 24 h.
    state = signer.ledger
    state["slugs"]["rl"]["issuances"][-1]["not_after"] = hub.clock[0] + DAY
    assert renew(hub, signer, "rl", second["seq"])["error"] == "rate-limit-renewal"


# 5.5 orphan after a generation bump (withdrawal or operator hold).
def test_orphan_identity_unchanged_is_refetched_with_orphan_true(hub):
    signer = hub.signer()
    stored = hub.sign(signer, "o1")
    hub.clock[0] += 8 * DAY
    issued = renew(hub, signer, "o1", stored["seq"], generation=1)    # N+1, never stored
    again = renew(hub, signer, "o1", stored["seq"], generation=2)     # new cycle after the bump
    assert again["orphan"] is True and again["payload"] == issued["payload"] and again["sig"] == issued["sig"]
    assert ledger(hub)["slugs"]["o1"]["floor"] == issued["seq"]


def test_orphan_identity_changed_is_superseded_then_reissued_above(hub):
    signer = hub.signer()
    stored = hub.sign(signer, "o2")
    hub.clock[0] += 8 * DAY
    orphan = renew(hub, signer, "o2", stored["seq"], generation=1)
    rekey_ticket = hub.ticket("o2", action="rekey")
    reply = hub.sign(signer, "o2", eps=stored["seq"], generation=2, verb="rekey", ticket=rekey_ticket,
                     static=b"\x55" * 32)
    assert reply["orphan"] is True and reply["seq"] == orphan["seq"]
    assert not ledger(hub)["nonces"].get(json.loads(base64.b64decode(rekey_ticket["payload"]))["nonce"])
    sup = {"verb": "supersede", "slug": "o2", "generation": 2, "seq": orphan["seq"]}
    assert signer.handle(sup)["ok"] and hub.signer().handle(sup)["ok"]     # idempotent, across a crash
    signer = hub.signer()
    # Straight after the burn, the old cycle's retry key never returns N+1.
    assert renew(hub, signer, "o2", stored["seq"], generation=1).get("seq") != orphan["seq"]
    fresh = hub.sign(signer, "o2", eps=stored["seq"], generation=2, verb="rekey", ticket=rekey_ticket,
                     static=b"\x55" * 32)
    assert fresh["ok"] and fresh["orphan"] is False and fresh["seq"] == orphan["seq"] + 1
    assert hub.payload(fresh)["admission_gen"] == 2
    # A retry key that names the superseded N+1 never returns it.
    old_key = renew(hub, signer, "o2", stored["seq"], generation=1)
    assert old_key.get("seq") != orphan["seq"]
    assert signer.handle({"verb": "supersede", "slug": "o2", "generation": 2,
                          "seq": stored["seq"]})["error"] == "sequence-presented-as-stored"


# 5.5 resume after a withhold, with suspend and unsuspend tickets.
def test_withhold_suspend_unsuspend_then_renew_from_the_retained_floor(hub):
    signer = hub.signer()
    stored = hub.sign(signer, "wh")
    suspend = {"verb": "suspend", "slug": "wh", "ticket": hub.ticket("wh", action="suspend")}
    assert signer.handle(suspend)["state"] == "suspended" and signer.handle(suspend)["ok"]
    hub.clock[0] += 8 * DAY
    assert renew(hub, signer, "wh", stored["seq"])["error"] == "slug-suspended"
    assert hub.sign(signer, "wh", eps=stored["seq"], verb="rekey", action="rekey")["error"] == "slug-suspended"
    wrong = {"verb": "unsuspend", "slug": "wh", "ticket": hub.ticket("wh", action="suspend")}
    assert signer.handle(wrong)["error"] == "ticket-wrong-action"
    assert signer.handle({"verb": "unsuspend", "slug": "wh", "ticket": hub.ticket("wh", action="unsuspend")})["ok"]
    resumed = renew(hub, signer, "wh", stored["seq"])
    assert resumed["ok"] and resumed["seq"] == stored["seq"] + 1


# 5.5 ledger loss without a checkpoint: old-epoch tickets refused.
def test_old_epoch_tickets_refused_spent_or_not(hub):
    signer = hub.signer()
    spent = hub.ticket("ep")
    first = hub.sign(signer, "ep", ticket=spent)
    unspent = hub.ticket("ep", action="reset")
    (hub.tmp / "config" / "ticket-epoch").write_text("2\n")
    # Replay of the consumed ticket is refused (old epoch); an unconsumed one too.
    assert hub.sign(signer, "ep", eps=first["seq"], ticket=spent)["error"] == "ticket-epoch-stale"
    assert hub.sign(signer, "ep", eps=first["seq"], ticket=unspent)["error"] == "ticket-epoch-stale"
    assert hub.sign(signer, "eq", ticket=hub.ticket("eq", epoch=1))["error"] == "ticket-epoch-stale"
    assert hub.sign(signer, "eq", ticket=hub.ticket("eq", epoch=2))["ok"]


def test_ticket_expiry_and_lifetime(hub):
    signer = hub.signer()
    assert hub.sign(signer, "tx", ticket=hub.ticket("tx", not_after=T0))["error"] == "ticket-expired"
    assert hub.sign(signer, "tx", ticket=hub.ticket("tx", not_after=T0 + 8 * DAY))["error"] == "ticket-lifetime-too-long"


# 5.5 recovery through unequal floors (the signer half), and 5.6 v8 fix 6 mutants.
def test_no_live_issuance_rule_issues_above_the_larger_floor(hub):
    signer = hub.signer()
    state = signer.ledger
    state["slugs"]["fl"] = {"state": "active", "floor": 1_000_041, "presented_stored": -1, "issuances": []}
    hub.mod.write_ledger(state)
    signer = hub.signer()
    assert renew(hub, signer, "fl", 41)["error"] == "no-live-issuance"
    reply = hub.sign(signer, "fl", eps=41, verb="rekey", action="rekey")
    assert reply["ok"] and reply["seq"] == 1_000_042
    assert ledger(hub)["slugs"]["fl"]["presented_stored"] == 41
    hub.clock[0] += 8 * DAY
    assert renew(hub, signer, "fl", reply["seq"])["seq"] == 1_000_043
    high = hub.sign(signer, "hi", eps=5_000_000)
    assert high["seq"] == 5_000_001


# 5.5 sequence bound, and 5.6 v9 fix 8 mutant.
def test_sequence_bound(hub):
    signer = hub.signer()
    bound = 2 ** 53 - 1 - 2 ** 32
    ok = hub.sign(signer, "sb", eps=bound)
    assert ok["ok"] and ok["seq"] <= 2 ** 53 - 1
    assert hub.sign(signer, "sc", eps=bound + 1)["error"] == "expected-prior-seq-out-of-bound"
    assert renew(hub, signer, "sb", bound + 1)["error"] == "expected-prior-seq-out-of-bound"


def test_admission_gen_increments_on_reset_and_new_is_refused_for_a_known_slug(hub):
    signer = hub.signer()
    first = hub.sign(signer, "ag")
    assert hub.sign(signer, "ag", eps=first["seq"])["error"] == "ticket-new-for-known-slug"
    reset = hub.sign(signer, "ag", eps=first["seq"], action="reset", static=b"\x77" * 32)
    assert hub.payload(reset)["admission_gen"] == hub.payload(first)["admission_gen"] + 1


# 5.6: go_live and tier come only from the verified ticket bytes.
def test_go_live_and_tier_only_from_the_verified_ticket(hub):
    signer = hub.signer()
    request = {"verb": "sign", "slug": "gl", "generation": 1, "expected_prior_seq": -1,
               "ticket": hub.ticket("gl", go_live="manual", tier="premium"),
               "go_live": "auto", "tier": "free", **hub.identity("gl")}
    reply = signer.handle(request)
    assert reply["go_live"] == "manual" and reply["tier"] == "premium"


# 5.5: ledger_bootstrap is not on the app socket, nor any allowance grant.
def test_socket_verbs_are_exactly_the_design_api(hub):
    assert set(hub.mod.VERBS) == {"sign", "renew", "rekey", "supersede", "suspend", "unsuspend", "status"}
    signer = hub.signer()
    for verb in ("ledger_bootstrap", "bootstrap", "grant_allowance", "sign_bytes", "reconcile"):
        assert signer.handle({"verb": verb})["error"] == "unknown-verb"


# 5.5: g3 activation against a configured active slot (3.10).
def test_g3_active_slot_sets_kid_and_uses_its_key(tmp_path):
    hub = Hub(tmp_path, slot="g3")
    reply = hub.sign(hub.signer(), "g3n")
    assert hub.payload(reply)["kid"] == "g3"
    hub.write_config(pub=b"\x01" * 32)
    assert hub.signer().key_ready is False
    assert hub.sign(hub.signer(), "g3m")["error"] == "signer-key-unavailable"


def test_digest_writes_protected_checkpoint_and_public_digest(hub):
    signer = hub.signer()
    reply = hub.sign(signer, "dg")
    (hub.tmp / "hub-key-history").write_text("t ssh-ed25519 AAAA SHA256:x\n")
    assert hub.mod.digest() == 0
    checkpoint = json.loads((hub.tmp / "state" / "checkpoint.json").read_text())
    assert checkpoint["chain_ok"] and checkpoint["ledger"]["slugs"]["dg"]["floor"] == reply["seq"]
    assert stat.S_IMODE(os.stat(hub.tmp / "state" / "checkpoint.json").st_mode) == 0o600
    report = json.loads((hub.tmp / "digest" / "latest.json").read_text())
    assert report["slugs"]["dg"]["identity_sha256"] == reply["identity_sha256"]
    assert report["hub_key_history_sha256"] == hashlib.sha256(b"t ssh-ed25519 AAAA SHA256:x\n").hexdigest()
    assert report["operator_ssh_keys_sha256"] == "absent"
    assert stat.S_IMODE(os.stat(hub.tmp / "digest" / "latest.txt").st_mode) == 0o644
    assert base64.b64decode(hub.payload(reply)["admission_secret"]).decode() not in json.dumps(report)


# ------------------------------------------------- control-plane installer --

SANDBOX = {"NoNewPrivileges": "true", "ProtectSystem": "strict", "PrivateTmp": "true",
           "PrivateDevices": "true", "ProtectKernelTunables": "true", "ProtectKernelModules": "true",
           "ProtectControlGroups": "true", "RestrictSUIDSGID": "true", "RestrictNamespaces": "true",
           "LockPersonality": "true", "CapabilityBoundingSet": "", "LimitCORE": "0"}


def check_signer_units(source):
    failures = []
    for header in (SIGNER_UNIT, DIGEST_UNIT):
        props = unit(source, header)
        expected = dict(SANDBOX, User="wins-desc-signer", PrivateNetwork="yes", IPAddressDeny="any",
                        RestrictAddressFamilies="AF_UNIX", MemoryDenyWriteExecute="true",
                        StateDirectory="wins-descriptor-signer", ProtectHome="true")
        for key, value in expected.items():
            if props.get(key) != [value]:
                failures.append(f"{header}: {key}={props.get(key)}")
        if props.get("ExecStart", [""])[0].split()[:3] != ["/usr/bin/python3", "-I", "/usr/local/lib/wins_descriptor_signer.py"]:
            failures.append(f"{header}: ExecStart")
    if unit(source, SIGNER_UNIT).get("RuntimeDirectory") != ["wins-descriptor-signer/work"]:
        failures.append("signer RuntimeDirectory")
    sock = unit(source, SOCKET_UNIT)
    for key, value in (("ListenStream", "/run/wins-descriptor-signer/sock"), ("SocketUser", "wins-desc-signer"),
                       ("SocketGroup", "root"), ("SocketMode", "0660")):
        if sock.get(key) != [value]:
            failures.append(f"socket {key}={sock.get(key)}")
    mail = unit(source, MAIL_UNIT)
    for key, value in SANDBOX.items():
        if mail.get(key) != [value]:
            failures.append(f"mail {key}={mail.get(key)}")
    hub = unit(source, HUB_UNIT)
    if "/etc/winsvpn/descriptor-signer /var/lib/wins-descriptor-signer" not in hub.get("InaccessiblePaths", []):
        failures.append("hub InaccessiblePaths")
    if "/etc/wins-descriptor-signer-input" not in hub.get("InaccessiblePaths", []):
        failures.append("hub InaccessiblePaths input dir")
    signer, digest_unit = unit(source, SIGNER_UNIT), unit(source, DIGEST_UNIT)
    if signer.get("TemporaryFileSystem") != ["/etc/winsvpn:ro"] or digest_unit.get("TemporaryFileSystem") != ["/etc/winsvpn:ro"]:
        failures.append("signer or digest private /etc/winsvpn")
    if signer.get("BindReadOnlyPaths") != ["/etc/winsvpn/descriptor-signer"]:
        failures.append("signer bind of its config directory")
    if digest_unit.get("BindReadOnlyPaths") != ["-/etc/winsvpn/hub-key-history -/etc/winsvpn/operator-ssh-keys -/etc/winsvpn/descriptor-signer/RECOVERY-PENDING"]:
        failures.append("digest binds of the two public files and the recovery marker")
    account = SOURCE_FUNCTION(source, "write_descriptor_signer_account")
    if 'install -d -m 0700 -o root -g root "${DESCRIPTOR_SIGNER_INPUT_DIR}"' not in account \
            or 'DESCRIPTOR_SIGNER_INPUT_DIR="/etc/wins-descriptor-signer-input"' not in source:
        failures.append("protected injection input directory")
    if not any("/run/wins-descriptor-signer" in v.split() for v in hub.get("BindReadOnlyPaths", [])):
        failures.append("hub bind of the signer socket directory")
    if "d /run/wins-descriptor-signer 0750 wins-desc-signer root -" not in heredoc(source, TMPFILES):
        failures.append("tmpfiles runtime directory")
    if unit(source, TIMER_UNIT).get("Unit") != ["wins-descriptor-signer-digest-mail.service"]:
        failures.append("digest timer")
    return failures


def SOURCE_FUNCTION(source, name):
    start = source.index(f"\n{name}() {{\n") + 1
    return source[start:source.index("\n}\n", start) + 3]


def check_backup_exclusions(source):
    script = heredoc(source, BACKUP_SCRIPT)
    return [name for name in ("etc/winsvpn/descriptor-signer", "var/lib/wins-descriptor-signer")
            if f"--exclude='{name}'" not in script]


def test_signer_units_hub_barrier_and_runtime_dir():
    assert check_signer_units(SOURCE) == []


# 5.6 mutants: signer gets network; signer key owned by root; key or checkpoint in backups.
@pytest.mark.parametrize("old,new", [
    ("PrivateNetwork=yes\nIPAddressDeny=any\nRestrictAddressFamilies=AF_UNIX\nNoNewPrivileges=true\nPrivateTmp=true\nPrivateDevices=true\nProtectSystem=strict\nProtectHome=true\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\nProtectKernelLogs=true\nProtectClock=true\nProtectHostname=true\nRestrictSUIDSGID=true\nRestrictRealtime=true\nRestrictNamespaces=true\nMemoryDenyWriteExecute=true\nCapabilityBoundingSet=\nAmbientCapabilities=\nSystemCallArchitectures=native\nLockPersonality=true\nLimitCORE=0\nEOF\n  cat > /etc/systemd/system/wins-descriptor-signer-digest.service",
     "IPAddressDeny=any\nRestrictAddressFamilies=AF_UNIX AF_INET\nNoNewPrivileges=true\nPrivateTmp=true\nPrivateDevices=true\nProtectSystem=strict\nProtectHome=true\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\nProtectKernelLogs=true\nProtectClock=true\nProtectHostname=true\nRestrictSUIDSGID=true\nRestrictRealtime=true\nRestrictNamespaces=true\nMemoryDenyWriteExecute=true\nCapabilityBoundingSet=\nAmbientCapabilities=\nSystemCallArchitectures=native\nLockPersonality=true\nLimitCORE=0\nEOF\n  cat > /etc/systemd/system/wins-descriptor-signer-digest.service"),
    ("User=wins-desc-signer\nGroup=wins-desc-signer\nExecStart=/usr/bin/python3 -I /usr/local/lib/wins_descriptor_signer.py serve",
     "User=root\nGroup=root\nExecStart=/usr/bin/python3 -I /usr/local/lib/wins_descriptor_signer.py serve"),
    ("InaccessiblePaths=/etc/winsvpn/descriptor-signer /var/lib/wins-descriptor-signer\n", ""),
    ("CapabilityBoundingSet=\nAmbientCapabilities=\nSystemCallArchitectures=native\nLockPersonality=true\nLimitCORE=0\nEOF\n  cat > /etc/systemd/system/wins-descriptor-signer-digest.service",
     "CapabilityBoundingSet=CAP_DAC_OVERRIDE\nAmbientCapabilities=\nSystemCallArchitectures=native\nLockPersonality=true\nLimitCORE=0\nEOF\n  cat > /etc/systemd/system/wins-descriptor-signer-digest.service"),
    # Turn 1 review fixes (2026-10-06): the private /etc/winsvpn binds, and the
    # protected injection input directory.
    ("TemporaryFileSystem=/etc/winsvpn:ro\nBindReadOnlyPaths=/etc/winsvpn/descriptor-signer\n", ""),
    ("BindReadOnlyPaths=/etc/winsvpn/descriptor-signer\n", ""),
    ("TemporaryFileSystem=/etc/winsvpn:ro\nBindReadOnlyPaths=-/etc/winsvpn/hub-key-history -/etc/winsvpn/operator-ssh-keys -/etc/winsvpn/descriptor-signer/RECOVERY-PENDING\n", ""),
    # Whole-tree vote: the digest unit must see the recovery marker (3.12).
    (" -/etc/winsvpn/descriptor-signer/RECOVERY-PENDING\nPrivateNetwork=yes", "\nPrivateNetwork=yes"),
    ("InaccessiblePaths=/etc/wins-descriptor-signer-input\n", ""),
    ('  install -d -m 0700 -o root -g root "${DESCRIPTOR_SIGNER_INPUT_DIR}"\n', ""),
])
def test_unit_mutants_are_killed(old, new):
    assert SOURCE.count(old) == 1
    assert check_signer_units(SOURCE.replace(old, new)) != []


def test_backup_excludes_both_signer_directories_and_tar_honours_it(tmp_path):
    assert check_backup_exclusions(SOURCE) == []
    for name in ("etc/winsvpn/descriptor-signer", "var/lib/wins-descriptor-signer"):
        mutated = SOURCE.replace(f"  --exclude='{name}' \\\n", "", 1)
        assert check_backup_exclusions(mutated) == [name]
    root = tmp_path / "root"
    for rel in ("etc/winsvpn/descriptor-signer/g2.ed25519.pem", "etc/winsvpn/backup.env",
                "var/lib/wins-descriptor-signer/checkpoint.json"):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text("x")
    excludes = re.findall(r"--exclude='([^']+)'", heredoc(SOURCE, BACKUP_SCRIPT))
    archive = tmp_path / "a.tar"
    subprocess.run(["tar", *[f"--exclude={e}" for e in excludes], "-C", str(root), "-cf", str(archive),
                    "etc/winsvpn", "var/lib"], check=True)
    members = subprocess.run(["tar", "-tf", str(archive)], capture_output=True, text=True, check=True).stdout
    assert "etc/winsvpn/backup.env" in members and "descriptor-signer" not in members
    # Litestream streams only the hub database.
    assert "descriptor-signer" not in heredoc(SOURCE, LITESTREAM_CONFIG)


def test_signer_env_writers_live_in_the_env_writer_block():
    block = SOURCE[SOURCE.index("# --- begin winn3 hub EnvironmentFile writers ---"):
                   SOURCE.index("# --- end winn3 hub EnvironmentFile writers ---")]
    assert "\nwrite_descriptor_signer_env() {" in block and 'WINN3_DESCRIPTOR_SIGNER_ACTIVE_SLOT_DEFAULT="g2"' in block


def test_ring_constants_match_the_reviewed_ring_defines():
    spec = importlib.util.spec_from_file_location("ring_defines", ROOT / "tools/winn3_descriptor_ring_defines.py")
    defines = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(defines)
    for slot, value in defines.RING.items():
        assert f"{slot}) printf '%s' '{value}' ;;" in SOURCE


def test_write_systemd_orders_account_hardening_then_key():
    body = SOURCE[SOURCE.index("write_systemd() {"):]
    body = body[:body.index("\n}\n")]
    order = [body.index(step) for step in ("write_descriptor_signer_account", "write_hub_runtime_dirs",
                                           "write_descriptor_signer_units", 'cat > "${SERVICE_FILE}"',
                                           "systemctl restart wins-hub.service",
                                           "provision_descriptor_signer_key", "start_descriptor_signer")]
    assert order == sorted(order)
    assert "write_descriptor_signer_env || return 1" in SOURCE


# ------------------------------------------- installer functions under bash --

SHIMS = {
    "stat": "#!/usr/bin/env python3\nimport os,pwd,sys\nst=os.stat(sys.argv[-1])\n"
            "print(pwd.getpwuid(st.st_uid).pw_name+':'+format(st.st_mode&0o777,'o'))\n",
    "install": "#!/usr/bin/env python3\nimport subprocess,sys\na=sys.argv[1:];out=[]\n"
               "while a:\n x=a.pop(0)\n if x in('-o','-g'):\n  a.pop(0);continue\n out.append(x)\n"
               "sys.exit(subprocess.call(['/usr/bin/install',*out]))\n",
    "chown": "#!/bin/sh\nexit 0\n",
    "readlink": "#!/usr/bin/env python3\nimport os,sys\nprint(os.path.realpath(sys.argv[-1]))\n",
}


def shell_function(name):
    start = SOURCE.index(f"\n{name}() {{\n") + 1
    return SOURCE[start:SOURCE.index("\n}\n", start) + 3]


def bash(tmp, script, env=None):
    shims = tmp / "shims"
    shims.mkdir(exist_ok=True)
    for name, body in SHIMS.items():
        (shims / name).write_text(body)
        (shims / name).chmod(0o755)
    block = SOURCE[SOURCE.index("# --- begin descriptor signer"):SOURCE.index("# --- end descriptor signer ---")]
    lib = tmp / "lib.sh"
    env_writers = 'WINN3_DESCRIPTOR_SIGNER_ACTIVE_SLOT_DEFAULT="g2"\n' + "".join(
        shell_function(name) for name in ("winn3_descriptor_pubkey_is_raw32_b64", "winn3_descriptor_ring_pinned_pubkey",
                                          "descriptor_signer_active_slot", "descriptor_signer_ticket_pubkey",
                                          "write_descriptor_signer_env"))
    lib.write_text("err(){ echo \"ERR $*\" >&2; }\nwarn(){ echo \"WARN $*\" >&2; }\nlog(){ echo \"LOG $*\" >&2; }\n"
                   + env_writers + block)
    full_env = {"PATH": f"{shims}:{Path(OPENSSL).parent}:/usr/bin:/bin", "HOME": str(tmp)}
    full_env.update(env or {})
    # An injected key arrives the only accepted way: the input directory's
    # secrets file (Claude H1-T2), unless a test names its own files.
    key = full_env.get("WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64")
    if key is not None and "WINS_SECRETS_FILE" not in full_env:
        (tmp / "input").mkdir(mode=0o700, exist_ok=True)
        (tmp / "input" / "secrets.env").write_text(f"WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64='{key}'\n")
        full_env["WINS_SECRETS_FILE"] = str(tmp / "input" / "secrets.env")
    return subprocess.run([BASH, "-c", f"set -Eeuo pipefail\nsource {lib}\n"
                           f"DESCRIPTOR_SIGNER_USER=$(id -un)\nDESCRIPTOR_SIGNER_CONFIG_DIR={tmp}/cfg\n"
                           f"DESCRIPTOR_SIGNER_INPUT_DIR={tmp}/input\n"
                           f"DESCRIPTOR_SIGNER_INJECT_TMPDIR={tmp}/inj\n{script}"],
                          capture_output=True, text=True, env=full_env)


def key_b64(path):
    return base64.b64encode(Path(path).read_bytes()).decode()


def pin_override(pub):
    return ("winn3_descriptor_ring_pinned_pubkey(){ case \"$1\" in g2) printf '%s' '"
            + base64.b64encode(pub).decode() + "';; *) return 1;; esac; }\n")


# 5.5 control plane: the injection pin check against the active slot, and the scrub.
def test_key_injection_pin_check_places_0400_and_scrubs(tmp_path):
    (tmp_path / "cfg").mkdir(mode=0o700)
    (tmp_path / "inj").mkdir(mode=0o700)
    good, bad = tmp_path / "good.pem", tmp_path / "bad.pem"
    pub = genkey(good)
    genkey(bad)
    check = ('rc=0; provision_descriptor_signer_key || rc=$?\n'
             'echo "rc=${rc} ready=${DESCRIPTOR_SIGNER_KEY_READY} var=${WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64-unset}"\n'
             'ls -A "$DESCRIPTOR_SIGNER_INJECT_TMPDIR" | wc -l | tr -d " "\n')
    refused = bash(tmp_path, pin_override(pub) + check, {"WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64": key_b64(bad)})
    assert "rc=1 ready=0 var=unset" in refused.stdout and refused.stdout.strip().endswith("0"), refused
    assert not (tmp_path / "cfg" / "g2.ed25519.pem").exists() and "not slot g2's pinned key" in refused.stderr
    placed = bash(tmp_path, pin_override(pub) + check, {"WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64": key_b64(good)})
    assert "rc=0 ready=1 var=unset" in placed.stdout, placed
    dest = tmp_path / "cfg" / "g2.ed25519.pem"
    assert stat.S_IMODE(dest.stat().st_mode) == 0o400 and dest.read_bytes() == good.read_bytes()
    # A rerun without injection verifies the placed key against the pin.
    rerun = bash(tmp_path, pin_override(pub) + check)
    assert "rc=0 ready=1" in rerun.stdout
    # The real pins never match a throwaway key: injection is refused.
    real = bash(tmp_path, check, {"WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64": key_b64(good)})
    assert "rc=1 ready=0 var=unset" in real.stdout


def test_existing_key_with_wrong_mode_or_no_key_keeps_signing_off(tmp_path):
    (tmp_path / "cfg").mkdir(mode=0o700)
    good = tmp_path / "cfg" / "g2.ed25519.pem"
    pub = genkey(good)
    good.chmod(0o440)
    check = 'rc=0; provision_descriptor_signer_key || rc=$?; echo "rc=${rc} ready=${DESCRIPTOR_SIGNER_KEY_READY}"\n'
    loose = bash(tmp_path, pin_override(pub) + check)
    assert "rc=1 ready=0" in loose.stdout and "mode 0400" in loose.stderr
    good.unlink()
    absent = bash(tmp_path, pin_override(pub) + check)
    assert "rc=0 ready=0" in absent.stdout and "automatic signing stays off" in absent.stderr


def test_relocated_config_dir_never_receives_a_key(tmp_path):
    (tmp_path / "vault" / "cfg").mkdir(parents=True)
    (tmp_path / "cfg").symlink_to(tmp_path / "vault" / "cfg")
    (tmp_path / "inj").mkdir()
    key = tmp_path / "k.pem"
    pub = genkey(key)
    check = ('rc=0; provision_descriptor_signer_key || rc=$?\n'
             'echo "rc=${rc} ready=${DESCRIPTOR_SIGNER_KEY_READY} var=${WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64-unset}"\n')
    injected = bash(tmp_path, pin_override(pub) + check, {"WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64": key_b64(key)})
    assert "rc=1 ready=0 var=unset" in injected.stdout and not list((tmp_path / "vault" / "cfg").iterdir())
    plain = bash(tmp_path, pin_override(pub) + check)
    assert "rc=0 ready=0" in plain.stdout and "signing stays off" in plain.stderr


def test_active_slot_and_t1_validation(tmp_path):
    out = bash(tmp_path, 'descriptor_signer_active_slot; echo; WINN3_DESCRIPTOR_SIGNER_ACTIVE_SLOT=g3 descriptor_signer_active_slot\n')
    assert out.stdout.split() == ["g2", "g3"]
    bad = bash(tmp_path, "WINN3_DESCRIPTOR_SIGNER_ACTIVE_SLOT=g4 descriptor_signer_active_slot\n")
    assert bad.returncode != 0 and "must be g1, g2 or g3" in bad.stderr
    ring = bash(tmp_path, "WINN3_SIGNER_TICKET_PUBKEY_T1='eVCAHWXqUM1+m5nlVy2JR+Q4/mkYGTxlk119aiQh89M=' descriptor_signer_ticket_pubkey\n")
    assert ring.returncode != 0 and "separate key" in ring.stderr
    short = bash(tmp_path, "WINN3_SIGNER_TICKET_PUBKEY_T1='AAAA' descriptor_signer_ticket_pubkey\n")
    assert short.returncode != 0
    t1 = base64.b64encode(b"\x05" * 32).decode()
    env = bash(tmp_path, "write_env_kv(){ echo \"$1=$2\"; }\nwrite_descriptor_signer_env\n",
               {"WINN3_SIGNER_TICKET_PUBKEY_T1": t1, "WINN3_DESCRIPTOR_SIGNER_ACTIVE_SLOT": "g3"})
    assert env.stdout.split() == ["WINN3_DESCRIPTOR_SIGNER_ACTIVE_SLOT=g3", f"WINN3_SIGNER_TICKET_PUBKEY_T1={t1}"]


def test_config_writer_pins_slot_and_never_resets_the_epoch(tmp_path):
    (tmp_path / "cfg").mkdir(mode=0o700)
    t1 = base64.b64encode(b"\x06" * 32).decode()
    out = bash(tmp_path, "write_descriptor_signer_config\n", {"WINN3_SIGNER_TICKET_PUBKEY_T1": t1})
    assert out.returncode == 0, out.stderr
    config = json.loads((tmp_path / "cfg" / "signer.json").read_text())
    assert config == {"active_slot": "g2", "active_slot_pubkey": "eVCAHWXqUM1+m5nlVy2JR+Q4/mkYGTxlk119aiQh89M=",
                      "ticket_pubkey_t1": t1}
    assert (tmp_path / "cfg" / "ticket-epoch").read_text() == "1\n"
    assert stat.S_IMODE((tmp_path / "cfg" / "signer.json").stat().st_mode) == 0o440
    (tmp_path / "cfg" / "ticket-epoch").chmod(0o640)
    (tmp_path / "cfg" / "ticket-epoch").write_text("5\n")
    assert bash(tmp_path, "write_descriptor_signer_config\n").returncode == 0
    assert (tmp_path / "cfg" / "ticket-epoch").read_text() == "5\n"


def test_digest_mailer_reads_smtp_settings_as_data(tmp_path):
    path = tmp_path / "mail.py"
    path.write_text(heredoc(SOURCE, MAIL_HEADER))
    spec = importlib.util.spec_from_file_location("digest_mail", path)
    mail = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mail)
    env = tmp_path / "vpn_auth.env"
    marker = tmp_path / "executed"
    env.write_text(f"SMTP_USER='u'\nSMTP_PASS='$(touch {marker})'\nADMIN_TOKEN='secret'\n")
    assert mail.load_env(str(env)) == {"SMTP_USER": "u", "SMTP_PASS": f"$(touch {marker})"}
    assert not marker.exists()



# --------------------------------------- Turn 1 review fixes (2026-10-06) --
# Claude seat (counted) and Sol seat findings, implementation review of H1.

def test_signer_and_digest_units_bind_their_paths_under_a_private_etc_winsvpn():
    # main() runs write_hub_recovery_contract (install -d -m 700 /etc/winsvpn)
    # after write_systemd, so the signer user reaches its files only through
    # the binds PID 1 makes into an empty /etc/winsvpn.
    main_body = SOURCE[SOURCE.index("\nmain() {"):]
    assert main_body.index("\n  write_systemd\n") < main_body.index("\n  write_hub_recovery_contract\n")
    signer, digest = unit(SOURCE, SIGNER_UNIT), unit(SOURCE, DIGEST_UNIT)
    assert signer["TemporaryFileSystem"] == digest["TemporaryFileSystem"] == ["/etc/winsvpn:ro"]
    assert signer["BindReadOnlyPaths"] == ["/etc/winsvpn/descriptor-signer"]
    assert digest["BindReadOnlyPaths"] == ["-/etc/winsvpn/hub-key-history -/etc/winsvpn/operator-ssh-keys -/etc/winsvpn/descriptor-signer/RECOVERY-PENDING"]
    # The key stays where the hub's InaccessiblePaths barrier covers it: no
    # alias of the signer's config under the hub-visible /run directory.
    assert "/run/wins-descriptor-signer/config" not in SOURCE


def test_digest_tells_an_unreadable_file_from_an_absent_one(hub):
    hub.sign(hub.signer(), "du")
    (hub.tmp / "hub-key-history").mkdir()
    assert hub.mod.digest() == 0
    report = json.loads((hub.tmp / "digest" / "latest.json").read_text())
    assert report["hub_key_history_sha256"] == "unreadable"
    assert report["operator_ssh_keys_sha256"] == "absent"


def test_renewal_after_a_slot_switch_takes_the_active_kid(tmp_path):
    hub = Hub(tmp_path)
    ticket = hub.ticket("sw")
    first = hub.sign(hub.signer(), "sw", ticket=ticket)
    g3pub = genkey(tmp_path / "config" / "g3.ed25519.pem")
    hub.write_config(slot="g3", pub=g3pub)
    hub.clock[0] += 8 * DAY
    second = renew(hub, hub.signer(), "sw", first["seq"])
    a = hub.payload(first)
    raw = base64.b64decode(second["payload"])
    b = json.loads(raw)
    assert {k for k in a if a[k] != b[k]} == {"seq", "iat", "not_after", "kid"}
    assert (a["kid"], b["kid"], second["kid"]) == ("g2", "g3", "g3")
    message = hub.mod.DESCRIPTOR_DOMAIN + b"\x00" + raw
    assert hub.mod.ed25519_verify(g3pub, message, base64.b64decode(second["sig"]))
    assert not hub.mod.ed25519_verify(hub.gpub, message, base64.b64decode(second["sig"]))
    # Sol H1-KID: a retry of the earlier issuance still returns its original g2 envelope.
    retry = hub.signer().handle({"verb": "sign", "slug": "sw", "generation": 1, "expected_prior_seq": -1,
                                 "ticket": ticket, **hub.identity("sw")})
    assert (retry["payload"], retry["sig"], retry["kid"]) == (first["payload"], first["sig"], "g2")


def test_identity_bytes_secret_and_ticket_fields_are_exact(hub):
    signer = hub.signer()
    request = {"verb": "sign", "slug": "e1", "generation": 1, "expected_prior_seq": -1,
               "ticket": hub.ticket("e1"), **hub.identity("e1")}
    request["admission_secret"] = "ab" * 32
    assert signer.handle(request)["error"] == "admission-secret-fingerprint-mismatch"
    body = json.loads(base64.b64decode(hub.identity("e2")["identity"]))
    doc = hub.tmp / "loose.json"
    doc.write_bytes(json.dumps(body, sort_keys=True).encode())
    run([SSH_KEYGEN, "-q", "-Y", "sign", "-f", str(hub.host("a")[0]),
         "-n", "winsvpn-winn3-identity/v1", str(doc)])
    loose = {"identity": base64.b64encode(doc.read_bytes()).decode(),
             "identity_sig": base64.b64encode((hub.tmp / "loose.json.sig").read_bytes()).decode(),
             "admission_secret": hashlib.sha256(b"e2").hexdigest()}
    assert signer.handle({"verb": "sign", "slug": "e2", "generation": 1, "expected_prior_seq": -1,
                          "ticket": hub.ticket("e2"), **loose})["error"] == "identity-not-canonical"
    ticket = json.loads(base64.b64decode(hub.ticket("e3")["payload"]))
    ticket["note"] = "x"
    raw = json.dumps(ticket, sort_keys=True, separators=(",", ":")).encode()
    sig = openssl_sign(hub.t1, hub.mod.TICKET_DOMAIN + b"\x00" + raw, hub.tmp)
    extra = {"payload": base64.b64encode(raw).decode(), "sig": base64.b64encode(sig).decode()}
    assert hub.sign(signer, "e3", ticket=extra)["error"] == "ticket-malformed"


def test_ticket_payload_must_be_canonical(hub):
    signer = hub.signer()
    body = json.loads(base64.b64decode(hub.ticket("c1")["payload"]))
    compact = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    spaced = json.dumps(body, sort_keys=True).encode()
    duplicated = compact.replace(b'"tier":"free"', b'"tier":"premium","tier":"free"')
    for raw in (spaced, duplicated):
        sig = openssl_sign(hub.t1, hub.mod.TICKET_DOMAIN + b"\x00" + raw, hub.tmp)
        ticket = {"payload": base64.b64encode(raw).decode(), "sig": base64.b64encode(sig).decode()}
        assert hub.sign(signer, "c1", ticket=ticket)["error"] == "ticket-not-canonical"
    assert hub.sign(signer, "c1")["ok"]


# Claude H1-FORMATS: the identity digest every slice (S4, H2, H7) computes.
def test_identity_digest_definition_is_the_descriptor_projection(hub):
    reply = hub.sign(hub.signer(), "id1")
    payload = hub.payload(reply)
    secret = base64.b64decode(payload["admission_secret"]).decode("ascii")
    projection = {"node": "id1", "endpoint": "203.0.113.10:9111",
                  "static_pub": base64.b64encode(b"\x11" * 32).decode(),
                  "gateway_id": base64.b64encode(b"id1-gw1").decode(),
                  "inner_router_v4": "10.10.0.1", "inner_resolver_v4": "10.10.0.1",
                  "auth_ed25519": base64.b64encode(b"\x22" * 32).decode(),
                  "auth_mldsa65": base64.b64encode(b"\x33" * 1952).decode(),
                  "admission_fingerprint": hashlib.sha256(b"winn3-admission-fingerprint-v1"
                                                          + secret.encode()).hexdigest()[:16]}
    expected = hashlib.sha256(json.dumps(projection, sort_keys=True, separators=(",", ":"),
                                         ensure_ascii=False).encode()).hexdigest()
    assert reply["identity_sha256"] == expected == hub.mod.identity_sha256(payload)
    # Descriptor encodings, never the identity file's hex fields, and never the secret.
    assert len(projection["admission_fingerprint"]) == 16 and secret not in json.dumps(projection)


# Sol H1-4: a lost ledger is never replaced by a fresh one.
def test_missing_ledger_fails_closed_and_is_never_recreated(hub):
    signer = hub.signer()
    ticket = hub.ticket("ml")
    assert hub.sign(signer, "ml", ticket=ticket)["ok"]
    assert hub.mod.digest() == 0
    checkpoint = (hub.tmp / "state" / "checkpoint.json").read_bytes()
    (hub.tmp / "state" / "ledger.json").unlink()
    restarted = hub.signer()
    assert restarted.ledger_ok is False
    # A consumed, still-valid ticket is not accepted again on fresh state.
    assert hub.sign(restarted, "ml", ticket=ticket)["error"] == "ledger-integrity"
    assert hub.sign(restarted, "m2")["error"] == "ledger-integrity"
    status = restarted.handle({"verb": "status"})
    assert status["ok"] and status["ledger_ok"] is False
    hub.clock[0] += 2 * hub.mod.REFUSAL_FLUSH_S
    assert hub.sign(restarted, "m3")["error"] == "ledger-integrity"
    assert not (hub.tmp / "state" / "ledger.json").exists()
    # The digest reports it and keeps the last valid checkpoint.
    assert hub.mod.digest() == 0
    assert (hub.tmp / "state" / "checkpoint.json").read_bytes() == checkpoint
    assert "BROKEN" in (hub.tmp / "digest" / "latest.txt").read_text()
    (hub.tmp / "state" / "ledger.json").write_text('{"version": 2}')
    assert hub.signer().ledger_ok is False


# Sol H1-5: every live envelope stays retrievable; burned ones never return.
def test_retry_of_an_older_live_issuance_returns_identical_bytes(hub):
    signer = hub.signer()
    ticket = hub.ticket("rt")
    first = hub.sign(signer, "rt", ticket=ticket)
    hub.clock[0] += 8 * DAY
    second = renew(hub, signer, "rt", first["seq"])
    hub.clock[0] += 8 * DAY
    third = renew(hub, signer, "rt", second["seq"])
    assert first["seq"] < second["seq"] < third["seq"]
    again = hub.sign(hub.signer(), "rt", ticket=ticket)
    assert again == first
    assert renew(hub, hub.signer(), "rt", first["seq"]) == second


# Sol H1-5: the ledger keeps the exact verified inputs as 3.5 step 5 evidence.
def test_ledger_keeps_identity_signature_and_ticket_evidence_even_when_burned(hub):
    signer = hub.signer()
    stored = hub.sign(signer, "ev")
    item = ledger(hub)["slugs"]["ev"]["issuances"][0]
    identity = hub.identity("ev")
    assert base64.b64decode(item["identity"]) == base64.b64decode(identity["identity"])
    assert item["identity_sig"] and set(item["ticket"]) == {"payload", "sig"}
    assert json.loads(base64.b64decode(item["ticket"]["payload"]))["slug"] == "ev"
    hub.clock[0] += 8 * DAY
    orphan = renew(hub, signer, "ev", stored["seq"])
    rekey = hub.sign(signer, "ev", eps=stored["seq"], generation=2, verb="rekey", action="rekey",
                     static=b"\x56" * 32)
    assert rekey["orphan"] is True
    assert signer.handle({"verb": "supersede", "slug": "ev", "generation": 2, "seq": orphan["seq"]})["ok"]
    fresh = hub.sign(signer, "ev", eps=stored["seq"], generation=2, verb="rekey", action="rekey",
                     static=b"\x56" * 32)
    assert fresh["ok"]
    items = ledger(hub)["slugs"]["ev"]["issuances"]
    burned = next(entry for entry in items if entry["seq"] == orphan["seq"])
    assert burned["superseded"] and "payload" not in burned and "sig" not in burned
    assert all("identity" in entry and "ticket" in entry for entry in items if entry["kind"] == "identity")


# Sol H1-6: a recovery allowance is spent by the signer and counts toward no quota.
def test_recovery_allowance_bypasses_fleet_quotas_and_is_spent_durably(hub):
    signer = hub.signer()
    for n in range(4):
        assert hub.sign(signer, f"ra{n}")["ok"]
    assert hub.sign(signer, "ra4")["error"] == "rate-limit-new-identities"
    state = ledger(hub)
    state["recovery_allowance_remaining"] = 2
    hub.mod.write_ledger(state)
    signer = hub.signer()
    assert hub.sign(signer, "ra4")["ok"] and hub.sign(signer, "ra5")["ok"]
    after = ledger(hub)
    assert after["recovery_allowance_remaining"] == 0
    assert [after["slugs"][f"ra{n}"]["issuances"][0]["recovery_allowance"] for n in range(6)] == [False] * 4 + [True] * 2
    assert hub.sign(signer, "ra6")["error"] == "rate-limit-new-identities"
    # Allowance issuances do not count toward the 64 signatures either.
    assert hub.mod.issued_since(after, hub.clock[0] - DAY) == 4
    # With the 64 signatures spent, an allowance unit still issues; a renewal
    # never spends one and stays under the fleet limit.
    hub.clock[0] += 8 * DAY
    template = after["slugs"]["ra0"]["issuances"][0]
    after["slugs"]["rx"] = {"state": "active", "floor": 63, "presented_stored": -1,
                            "issuances": [dict(template, seq=n, issued_at=hub.clock[0] - 10) for n in range(64)]}
    after["recovery_allowance_remaining"] = 1
    hub.mod.write_ledger(after)
    signer = hub.signer()
    assert renew(hub, signer, "ra4", 0)["error"] == "rate-limit-signatures"
    assert ledger(hub)["recovery_allowance_remaining"] == 1
    assert hub.sign(signer, "ra6")["ok"]
    assert ledger(hub)["recovery_allowance_remaining"] == 0
    for bad in (-1, 65, True, "2"):
        state = ledger(hub)
        state["recovery_allowance_remaining"] = bad
        hub.mod.write_ledger(state)
        assert hub.sign(hub.signer(), "ra7")["error"] == "recovery-allowance-malformed"


# Sol H1-7: every recorded event reaches the digest, whatever the timer jitter.
def test_digest_lists_every_recorded_event_and_keeps_the_valid_checkpoint(hub):
    signer = hub.signer()
    early = hub.sign(signer, "de")
    hub.clock[0] += 3 * DAY
    later = hub.sign(signer, "df")
    assert hub.mod.digest() == 0
    report = json.loads((hub.tmp / "digest" / "latest.json").read_text())
    assert [e["seq"] for e in report["events"] if e["event"] == "ticket-spend"] == [early["seq"], later["seq"]]
    assert early["identity_sha256"] in (hub.tmp / "digest" / "latest.txt").read_text()
    checkpoint_path = hub.tmp / "state" / "checkpoint.json"
    good = checkpoint_path.read_bytes()
    assert report["checkpoint_sha256"] == hashlib.sha256(good).hexdigest()
    state = ledger(hub)
    state["audit"][0]["seq"] = 99
    (hub.tmp / "state" / "ledger.json").write_text(json.dumps(state))
    hub.clock[0] += DAY
    assert hub.mod.digest() == 0
    assert checkpoint_path.read_bytes() == good
    report = json.loads((hub.tmp / "digest" / "latest.json").read_text())
    assert report["chain_ok"] is False and report["checkpoint_sha256"] == hashlib.sha256(good).hexdigest()


def write_env_kv_lines(tmp, pairs):
    start = SOURCE.index("  write_env_kv() {\n")
    body = SOURCE[start:SOURCE.index("\n  }\n", start) + 5]
    calls = "".join(f"write_env_kv {key} {shlex_quote(value)}\n" for key, value in pairs)
    script = "err(){ echo \"ERR $*\" >&2; }\nenv_kv_buffer=''\n" + body + calls + 'printf "%s" "${env_kv_buffer}"\n'
    done = subprocess.run([BASH, "-c", script], capture_output=True, text=True, check=True)
    path = tmp / "vpn_auth.env"
    path.write_text(done.stdout)
    return path


def shlex_quote(value):
    import shlex
    return shlex.quote(value)


def test_digest_mailer_decodes_values_written_by_write_env_kv(tmp_path):
    path = tmp_path / "mail.py"
    path.write_text(heredoc(SOURCE, MAIL_HEADER))
    spec = importlib.util.spec_from_file_location("digest_mail_kv", path)
    mail = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mail)
    marker = tmp_path / "executed"
    values = {"SMTP_USER": "o'brien", "SMTP_PASS": f"pa'ss$(touch {marker})`id`'", "SMTP_PORT": "587",
              "EMAIL_SENDER": "a@b", "ADMIN_TOKEN": "never-read"}
    env = write_env_kv_lines(tmp_path, values.items())
    loaded = mail.load_env(str(env))
    assert loaded == {k: v for k, v in values.items() if k != "ADMIN_TOKEN"}
    assert not marker.exists()
    bad = tmp_path / "bad.env"
    bad.write_text("SMTP_PASS='a'b'\n")
    with pytest.raises(ValueError):
        mail.load_env(str(bad))


# Sol H1-3: t1 is compared as key bytes; a noncanonical alias of a ring key is refused.
def b64_alias(encoded):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = alphabet.index(encoded[42])
    return encoded[:42] + alphabet[last ^ 1] + encoded[43:]


def test_t1_noncanonical_aliases_of_every_ring_slot_are_refused(tmp_path):
    spec = importlib.util.spec_from_file_location("ring_defines_t1", ROOT / "tools/winn3_descriptor_ring_defines.py")
    defines = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(defines)
    for slot, value in defines.RING.items():
        alias = b64_alias(value)
        assert alias != value and base64.b64decode(alias) == base64.b64decode(value)
        out = bash(tmp_path, "descriptor_signer_ticket_pubkey\n", {"WINN3_SIGNER_TICKET_PUBKEY_T1": alias})
        assert out.returncode != 0 and f"slot {slot}" in out.stderr, (slot, out)
    canonical = base64.b64encode(b"\x07" * 32).decode()
    ok = bash(tmp_path, "descriptor_signer_ticket_pubkey\n", {"WINN3_SIGNER_TICKET_PUBKEY_T1": b64_alias(canonical)})
    assert ok.returncode == 0 and ok.stdout == canonical


# Sol H1-2 and Claude H1: the injection variable never reaches a child process,
# and every exit path of provisioning scrubs it, including the captured copy.
def test_injection_variable_is_never_exported_and_always_scrubbed(tmp_path):
    head = SOURCE[:SOURCE.index("export DEBIAN_FRONTEND=noninteractive\n")]
    assert "$(" not in head and "\nexport -n WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64\n" in head
    probe = subprocess.run([BASH, "-c", head + "env | grep -c '^WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64=' || true\n"],
                           capture_output=True, text=True, env={"PATH": "/usr/bin:/bin",
                                                                "WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64": "c2VjcmV0"})
    assert probe.stdout.strip() == "0", probe
    defaults = SOURCE[SOURCE.index('. "${WINS_DEFAULTS_FILE}"\n'):]
    assert defaults.index("  set +a\nfi\n# H1: set -a above exports it; never put the signer key in the defaults file.\n"
                          "export -n WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64\n") < defaults.index("WINS_OPERATOR_INTENT_KEYS=()")
    overlay = SOURCE[SOURCE.index("\noverlay_wins_secrets_file || exit 1\n"):]
    assert overlay.index("export -n WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64") < overlay.index("IONOS_HUB_IP=")
    (tmp_path / "cfg").mkdir(mode=0o700)
    (tmp_path / "inj").mkdir(mode=0o700)
    check = ('declare -A WINS_OPERATOR_INTENT_PENDING=([WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64]=x [OTHER]=y)\n'
             'declare -A WINS_OPERATOR_INTENT_OWNED=([WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64]=x)\n'
             'rc=0; provision_descriptor_signer_key || rc=$?\n'
             'echo "rc=${rc} var=${WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64-unset} '
             'pending=${!WINS_OPERATOR_INTENT_PENDING[*]} owned=${#WINS_OPERATOR_INTENT_OWNED[@]}"\n')
    no_pin = "winn3_descriptor_ring_pinned_pubkey(){ return 1; }\n"
    out = bash(tmp_path, no_pin + check, {"WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64": "c2VjcmV0"})
    assert "rc=1 var=unset pending=OTHER owned=0" in out.stdout, out
    out = bash(tmp_path, check, {"WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64": "c2VjcmV0"})
    assert "var=unset pending=OTHER owned=0" in out.stdout, out


# Claude H1-T2 (Sol H1-2 enforcement): the only accepted key route is the input
# directory's secrets file. A key in the defaults file, in another secrets file
# or only in the process environment is refused and scrubbed. Sol H1-T2 adds a
# symlink whose target escapes the directory and a similarly named sibling.
def test_signer_key_outside_the_input_directory_is_refused(tmp_path):
    (tmp_path / "cfg").mkdir(mode=0o700)
    (tmp_path / "inj").mkdir(mode=0o700)
    (tmp_path / "input").mkdir(mode=0o700)
    (tmp_path / "input-evil").mkdir(mode=0o700)
    good = tmp_path / "good.pem"
    pub = genkey(good)
    line = f"WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64='{key_b64(good)}'\n"
    exposed = tmp_path / "secrets.env"
    exposed.write_text("SMTP_USER='u'\n" + line)
    protected = tmp_path / "input" / "secrets.env"
    protected.write_text(line)
    other = tmp_path / "input" / "other.env"
    other.write_text("SMTP_USER='u'\n")
    sibling = tmp_path / "input-evil" / "secrets.env"
    sibling.write_text(line)
    escape = tmp_path / "input" / "escape.env"
    escape.symlink_to(exposed)
    defaults = tmp_path / "defaults.env"
    defaults.write_text("export " + line)
    check = ('rc=0; provision_descriptor_signer_key || rc=$?\n'
             'echo "rc=${rc} ready=${DESCRIPTOR_SIGNER_KEY_READY} var=${WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64-unset}"\n')
    dest = tmp_path / "cfg" / "g2.ed25519.pem"
    for env in ({"WINS_SECRETS_FILE": str(exposed)},
                {"WINS_SECRETS_FILE": str(tmp_path / "missing.env")},
                {"WINS_SECRETS_FILE": str(other)},
                {"WINS_SECRETS_FILE": str(sibling)},
                {"WINS_SECRETS_FILE": str(escape)},
                {"WINS_SECRETS_FILE": str(protected), "WINS_DEFAULTS_FILE": str(defaults)}):
        out = bash(tmp_path, pin_override(pub) + check,
                   {**env, "WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64": key_b64(good)})
        assert "rc=1 ready=0 var=unset" in out.stdout and "accepted only from" in out.stderr, (env, out)
        assert not dest.exists()
    placed = bash(tmp_path, pin_override(pub) + check,
                  {"WINS_SECRETS_FILE": str(protected), "WINS_DEFAULTS_FILE": str(tmp_path / "none.env"),
                   "WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64": key_b64(good)})
    assert "rc=0 ready=1 var=unset" in placed.stdout, placed


def test_secrets_overlay_never_exports_the_signer_key(tmp_path):
    body = shell_function("wins_require_trusted_env_file") + shell_function("overlay_wins_secrets_file")
    secrets = tmp_path / "secrets.env"
    secrets.write_text("export WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64='c2VjcmV0'\nexport OTHER_SECRET='x'\n")
    secrets.chmod(0o600)
    probe = subprocess.run(
        [BASH, "-c", "set -Eeuo pipefail\n" + body +
         "wins_require_trusted_env_file(){ :; }\n"
         f"WINS_SECRETS_FILE={secrets}\noverlay_wins_secrets_file\n"
         'echo "set=${WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64:+yes}"\n'
         "env | grep -c '^WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64=' || true\n"],
        capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
    assert probe.stdout.split() == ["set=yes", "0"], probe
    secrets.write_text("WINN3_X='a'\nfalse\n")
    failed = subprocess.run(
        [BASH, "-c", body + "wins_require_trusted_env_file(){ :; }\n"
         f"WINS_SECRETS_FILE={secrets}\noverlay_wins_secrets_file || echo refused\n"],
        capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
    assert failed.stdout.strip() == "refused", failed


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q", "-p", "no:cacheprovider"]))
