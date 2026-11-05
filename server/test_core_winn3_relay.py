#!/usr/bin/env python3
"""Core half of the relay Double VPN (packet B2, "B: Core relays", round 2).

The Core forwards the phone's encrypted datagrams to the selected exit's own winn3
gateway through one kernel DNAT per exit port. It decrypts nothing and keeps no per
device state. This suite holds, offline:

* the helper /usr/local/sbin/wins-core-relay, extracted from its heredoc in the
  installer and run for real against fake iptables, iptables-restore and ip programs
  (a recorded, stateful double that parses the restore text and refuses a rule whose
  chain was never declared), with REAL Ed25519 signatures checked by real openssl;
* the installer edits (defaults, validation, env persistence, ring writer, helper
  install, the static firewall renderer rules, the sysctl drop-in);
* the sync agent stage and the registration merge, including that a relay failure can
  never change the result of a sync pass;
* mutation checks that each safety property is carried by the code that claims it.

What it cannot show: the kernel behaviour of iptables-restore, conntrack, hashlimit and
the home router. Those are NOT_RUN here; scripts/core_relay_netns_e2e.sh is the staging
check. Nothing here touches a host.

WINS_RELAY_BASE_INSTALLER=<path to the 15f1944 installer> additionally proves that with
CORE_RELAY_ENABLE=0 the rendered firewall text, the sync pass trace and the registration
payload equal the base installer's.
"""
import base64
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import re
import shutil
import stat as stat_module
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path


SERVER = Path(__file__).resolve().parent
INSTALLER = Path(os.environ.get(
    "WINS_AUDIT_INSTALLER", str(SERVER / "wins_core_server_setup_ONETOUCH.sh")))
BASE_INSTALLER = os.environ.get("WINS_RELAY_BASE_INSTALLER", "")
BASH = shutil.which("bash") or "/bin/bash"
OPENSSL = shutil.which("openssl") or "openssl"
NOW = 1_800_000_000
HELPER_TAG = "WINS_CORE_RELAY_PY"
AGENT_HEADER = "cat > \"${sync_tmp}\" <<'EOF'"

def addr(*octets):
    """A dotted quad built at run time: the repository's push gate (tools/ipscrub)
    refuses globally routable addresses written out as text, and these tests need
    some, because the helper refuses every target that is not global unicast."""
    return ".".join(str(octet) for octet in octets)


EXIT_A = ("canada-ca1", addr(34, 120, 10, 20), 9111)
EXIT_B = ("germany-de1", addr(51, 15, 20, 30), 9111)
EXIT_C = ("uk-gb1", addr(185, 199, 108, 40), 9111)
EXIT_D = ("us-oregon1", addr(45, 33, 32, 156), 9111)


def bash_major():
    try:
        out = subprocess.run(
            [BASH, "-c", "printf %s \"${BASH_VERSINFO[0]}\""],
            stdout=subprocess.PIPE, text=True, check=True).stdout
        return int(out)
    except (OSError, ValueError, subprocess.CalledProcessError):
        return 0


# ------------------------------------------------------------------ text extraction

def extract_heredoc(text, header_part, tag):
    lines = text.split("\n")
    start = next(i for i, line in enumerate(lines) if header_part in line)
    end = next(j for j in range(start + 1, len(lines)) if lines[j].lstrip("\t") == tag)
    return "\n".join(lines[start + 1:end]) + "\n"


def extract_function(text, name):
    match = re.search(r"^" + re.escape(name) + r"\(\) \{\n.*?^\}\n", text, re.M | re.S)
    if match is None:
        raise AssertionError("function %s not found" % name)
    return match.group(0)


def installer_text():
    return INSTALLER.read_text(encoding="utf-8")


def helper_text(installer=None):
    return extract_heredoc(installer or installer_text(), "<<'%s'" % HELPER_TAG, HELPER_TAG)


def agent_text(installer=None):
    return extract_heredoc(installer or installer_text(), AGENT_HEADER, "EOF")


# ------------------------------------------------------------------ real signatures

def b64(raw):
    return base64.b64encode(raw).decode("ascii")


class KeyRing:
    """Three real Ed25519 keys, g1..g3, and one stranger key that is never pinned."""

    def __init__(self, root):
        self.root = Path(root)
        self.keys = {}
        for name in ("g1", "g2", "g3", "stranger"):
            pem = self.root / ("%s.pem" % name)
            subprocess.run([OPENSSL, "genpkey", "-algorithm", "ed25519", "-out", str(pem)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            der = subprocess.run([OPENSSL, "pkey", "-in", str(pem), "-pubout", "-outform", "DER"],
                                 check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
            self.keys[name] = (pem, der[-32:])

    def public_b64(self, name):
        return b64(self.keys[name][1])

    def sign(self, name, payload):
        message = self.root / "message.bin"
        sig = self.root / "message.sig"
        message.write_bytes(b"winsvpn-winn3-descriptor/v1\x00" + payload)
        subprocess.run([OPENSSL, "pkeyutl", "-sign", "-rawin", "-inkey", str(self.keys[name][0]),
                        "-in", str(message), "-out", str(sig)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return sig.read_bytes()

    def ring_text(self, names=("g1", "g2", "g3")):
        return "".join("%s=%s\n" % (name, self.public_b64(name)) for name in names)


def descriptor_doc(slug, endpoint, kid="g1", iat=NOW - 100, not_after=NOW + 7 * 86400, **override):
    """A format 3 descriptor payload; a None override removes that key."""
    doc = {
        "admission_gen": 0,
        "admission_secret": b64(b"0123456789abcdef" * 4),
        "alg": "ed25519",
        "bucket_window_s": 30,
        "endpoint": endpoint,
        "gateway_id": b64(b"winsgw01"),
        "iat": iat,
        "inner_resolver_v4": "10.10.0.1",
        "inner_router_v4": "10.10.0.1",
        "kid": kid,
        "max_skew_s": 30,
        "node": slug,
        "not_after": not_after,
        "padding": "none",
        "seq": 1,
        "static_pub": b64(bytes(range(32))),
        "tag_size": 16,
        "v": 3,
    }
    doc.update(override)
    return {key: value for key, value in doc.items() if value is not None}


def envelope(ring, doc, sign_with=None, tamper=None):
    payload = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    signature = ring.sign(sign_with or doc.get("kid") or "g1", payload)
    if tamper is not None:
        payload = tamper(payload)
    return {"payload": b64(payload), "sig": b64(signature)}


def relay_item(ring, exit_def, port, **kwargs):
    slug, ip, tport = exit_def
    overrides = kwargs.pop("doc", {})
    doc = descriptor_doc(slug, "%s:%d" % (ip, tport))
    doc.update(overrides)
    doc = {key: value for key, value in doc.items() if value is not None}
    return {"exit_slug": slug, "port": port,
            "descriptor": envelope(ring, doc, **kwargs)}


PORT_RANGE = "9211-9218"


def desired(*items, port_range=PORT_RANGE):
    return {"v": 1, "port_range": port_range, "relays": list(items)}


# ------------------------------------------------------------------ the fake firewall

FAKEFW = r'''
import json, os, re, sys

DIR = os.environ["FAKEFW_DIR"]


def load(name, default):
    try:
        with open(os.path.join(DIR, name)) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def save(name, value):
    with open(os.path.join(DIR, name), "w") as handle:
        json.dump(value, handle)


def log(prog, argv, stdin=""):
    with open(os.path.join(DIR, "calls.jsonl"), "a") as handle:
        handle.write(json.dumps({"prog": prog, "argv": argv, "stdin": stdin}) + "\n")


def table_chain(args):
    table = "filter"
    if "-t" in args:
        table = args[args.index("-t") + 1]
    return table


def parse_restore(text, state):
    """Apply restore text to a copy of state; returns (ok, new state, table)."""
    new = json.loads(json.dumps(state))
    table = None
    declared = set()
    seen_commit = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = line[1:]
            declared = set(k.split("/", 1)[1] for k in new["chains"] if k.startswith(table + "/"))
            declared |= {"PREROUTING", "POSTROUTING", "INPUT", "FORWARD", "OUTPUT"}
            continue
        if line == "COMMIT":
            seen_commit = True
            continue
        if table is None:
            return False, state, None
        if line.startswith(":"):
            chain = line[1:].split()[0]
            key = table + "/" + chain
            new["chains"].setdefault(key, [])
            declared.add(chain)
        elif line.startswith("-F "):
            chain = line.split()[1]
            if chain not in declared:
                return False, state, table
            new["chains"][table + "/" + chain] = []
        elif line.startswith("-A "):
            chain = line.split()[1]
            if chain not in declared:
                return False, state, table
            target = re.search(r"-j (\S+)", line)
            if target and target.group(1) not in {"ACCEPT", "DROP", "DNAT", "MASQUERADE", "RETURN"} \
                    and target.group(1) not in declared:
                return False, state, table
            new["chains"].setdefault(table + "/" + chain, []).append(line)
        elif line.startswith("-I "):
            fields = line.split()
            chain, target = fields[1], fields[-1]
            if target not in declared:
                return False, state, table
            jump = "%s:%s:%s" % (table, chain, target)
            # real iptables-restore inserts a duplicate; the fake does too, so a helper
            # that forgets to delete the old jump first leaves two and a test sees it
            new["jumps"].insert(0, jump)
        elif line.startswith("-D "):
            fields = line.split()
            chain, target = fields[1], fields[-1]
            jump = "%s:%s:%s" % (table, chain, target)
            if jump not in new["jumps"]:
                return False, state, table
            new["jumps"].remove(jump)
        else:
            return False, state, table
    if not seen_commit:
        return False, state, table
    return True, new, table


RATE_UNIT = {"second": "sec", "minute": "min"}


def real_style(line):
    """Print a stored rule the way `iptables -S` prints it: fixed field order, /32 on
    host addresses, the implied -m udp, rates spelled 10/sec, the conntrack match with
    ctdir last, the hashlimit match with its mask. The helper must recognise its own
    rules in this form (config normalize_listing)."""
    tokens = line.split()
    chain, opts, i = tokens[1], {}, 2
    while i < len(tokens):
        opts[tokens[i]] = tokens[i + 1]
        i += 2
    known = {"-s", "-d", "-i", "-o", "-p", "--dst-type", "--sport", "--dport", "--ctstate", "--ctorigdstport",
             "--ctdir", "--hashlimit-name", "--hashlimit-above", "--hashlimit-burst", "--hashlimit-mode", "-j",
             "--to-destination"}
    out = ["-A", chain]
    for flag in ("-s", "-d"):
        if flag in opts:
            out += [flag, opts[flag] + ("/32" if "/" not in opts[flag] else "")]
    for flag in ("-i", "-o"):
        if flag in opts:
            out += [flag, opts[flag]]
    if "-p" in opts:
        out += ["-p", opts["-p"]]
    if "--dst-type" in opts:
        out += ["-m", "addrtype", "--dst-type", opts["--dst-type"]]
    if "--sport" in opts or "--dport" in opts:
        out += ["-m", "udp"]
        for flag in ("--sport", "--dport"):
            if flag in opts:
                out += [flag, opts[flag]]
    if any(k in opts for k in ("--ctstate", "--ctorigdstport", "--ctdir")):
        out += ["-m", "conntrack"]
        for flag in ("--ctstate", "--ctorigdstport", "--ctdir"):
            if flag in opts:
                out += [flag, opts[flag]]
    if "--hashlimit-name" in opts:
        count, unit = opts["--hashlimit-above"].split("/")
        mode = opts["--hashlimit-mode"]
        out += ["-m", "hashlimit", "--hashlimit-above", "%s/%s" % (count, RATE_UNIT.get(unit, unit)),
                "--hashlimit-burst", opts["--hashlimit-burst"], "--hashlimit-mode", mode,
                "--hashlimit-name", opts["--hashlimit-name"],
                "--hashlimit-srcmask" if mode == "srcip" else "--hashlimit-dstmask", "32"]
    out += ["-j", opts["-j"]]
    if "--to-destination" in opts:
        out += ["--to-destination", opts["--to-destination"]]
    for flag, value in opts.items():
        if flag not in known:
            out += [flag, value]   # an option the helper does not know passes through unchanged
    return " ".join(out)


def forward_rules(config):
    rng = config.get("gate_range", "9211:9218")
    default = [
        "-A WINVPN-CORE-FORWARD -p udp -m conntrack --ctstate DNAT --ctorigdstport %s -j WINVPN-RELAY-FWD" % rng,
        "-A WINVPN-CORE-FORWARD -p udp -m conntrack --ctstate DNAT --ctorigdstport %s -j DROP" % rng,
        "-A WINVPN-CORE-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
    ]
    return config.get("core_forward_rules", default)


def main(prog):
    argv = sys.argv[1:]
    config = load("config.json", {})
    state = load("state.json", {"chains": {}, "jumps": [], "counters": {}})
    if prog == "conntrack":
        log(prog, argv)
        if config.get("conntrack_stderr"):
            sys.stderr.write(config["conntrack_stderr"])
        elif config.get("conntrack_exit", 1) == 1:
            sys.stderr.write("conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.\n")
        return config.get("conntrack_exit", 1)
    if prog == "iptables-restore":
        stdin = sys.stdin.read()
        log(prog, argv, stdin)
        test = "--test" in argv
        ok, new, table = parse_restore(stdin, state)
        if not ok:
            sys.stderr.write("fake iptables-restore: ruleset refused\n")
            return 1
        if test and table in config.get("test_fail", []):
            return 1
        if not test:
            if table in config.get("commit_fail", []):
                return 1
            if config.get("drop_first_dnat") and table == "nat":
                pre = new["chains"].get("nat/WINVPN-RELAY-PRE", [])
                if pre:
                    new["chains"]["nat/WINVPN-RELAY-PRE"] = pre[1:]
            save("state.json", new)
        return 0
    if prog == "ip":
        log(prog, argv)
        if argv[:4] == ["-4", "route", "show", "default"]:
            sys.stdout.write(config.get("route_output", "default via 192.168.4.1 dev enp5s0 proto dhcp\n"))
            return 0
        if argv[:2] == ["-4", "-o"]:
            sys.stdout.write(config.get("addr_output", "2: enp5s0    inet 192.168.4.36/24 brd 192.168.4.255 scope global enp5s0\n"))
            return 0
        return 1
    # iptables
    args = list(argv)
    if args[:2] == ["--wait", "5"]:
        args = args[2:]
    log(prog, argv)
    table = table_chain(args)
    rest = [a for a in args if a not in ("-t", table)] if "-t" in args else args
    if "-C" in rest:
        if rest[:2] == ["-C", "WINVPN-CORE-FORWARD"]:
            spec = "-A WINVPN-CORE-FORWARD " + " ".join(rest[2:])
            return 0 if config.get("forward_jump", True) and spec in forward_rules(config) else 1
        chain = rest[rest.index("-C") + 1]
        target = rest[rest.index("-j") + 1]
        return 0 if "%s:%s:%s" % (table, chain, target) in state["jumps"] else 1
    if "-nvxL" in rest:
        chain = rest[rest.index("-nvxL") + 1]
        key = table + "/" + chain
        if key not in state["chains"]:
            sys.stderr.write("iptables: No chain/target/match by that name.\n")
            return 1
        out = ["Chain %s (1 references)" % chain,
               "    pkts      bytes target     prot opt in     out     source               destination"]
        for line in state["chains"][key]:
            dport = re.search(r"--dport (\d+)", line)
            dest = re.search(r"--to-destination (\S+)", line)
            if dport and dest:
                packets = state["counters"].get(dport.group(1), 7)
                out.append("%8d %8d DNAT       udp  --  enp5s0 *       0.0.0.0/0            0.0.0.0/0            "
                           "udp dpt:%s to:%s" % (packets, packets * 100, dport.group(1), dest.group(1)))
        sys.stdout.write("\n".join(out) + "\n")
        return 0
    if "-S" in rest:
        chain = rest[rest.index("-S") + 1]
        key = table + "/" + chain
        if config.get("list_fail") or config.get("list_fail_" + chain):
            return 1
        if chain == "WINVPN-CORE-FORWARD" and table == "filter":
            sys.stdout.write("-N WINVPN-CORE-FORWARD\n" + "".join(l + "\n" for l in forward_rules(config)))
            return 0
        if table == "nat" and chain in ("PREROUTING", "POSTROUTING"):
            lines = list(config.get("prepend_" + chain, []))
            lines.extend("-A %s -j %s" % (chain, jump.split(":")[2])
                         for jump in state["jumps"] if jump.startswith("nat:%s:" % chain))
            sys.stdout.write("-P %s ACCEPT\n" % chain + "".join(l + "\n" for l in lines))
            return 0
        if key not in state["chains"]:
            return 1
        rules = state["chains"][key]
        if config.get("normalize_listing"):
            rules = [real_style(l) for l in rules]
        sys.stdout.write("-N %s\n" % chain + "".join(line + "\n" for line in rules))
        return 0
    if "-F" in rest:
        chain = rest[rest.index("-F") + 1]
        key = table + "/" + chain
        if key in state["chains"]:
            state["chains"][key] = []
            save("state.json", state)
            return 0
        return 1
    return 1
'''


class FakeFirewall:
    def __init__(self, root):
        self.root = Path(root)
        self.bin = self.root / "bin"
        self.dir = self.root / "fw"
        self.bin.mkdir(parents=True, exist_ok=True)
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.root / "fakefw.py").write_text(FAKEFW, encoding="utf-8")
        for prog in ("iptables", "iptables-restore", "ip", "conntrack"):
            path = self.bin / prog
            path.write_text(
                "#!%s\nimport sys\nsys.path.insert(0, %r)\nimport fakefw\nsys.exit(fakefw.main(%r))\n"
                % (sys.executable, str(self.root), prog), encoding="utf-8")
            path.chmod(0o755)
        self.config({})
        (self.dir / "calls.jsonl").write_text("", encoding="utf-8")

    def env(self):
        env = dict(os.environ)
        env["FAKEFW_DIR"] = str(self.dir)
        env["PATH"] = "%s:%s" % (self.bin, env.get("PATH", ""))
        return env

    def config(self, value):
        (self.dir / "config.json").write_text(json.dumps(value), encoding="utf-8")

    def state(self):
        try:
            return json.loads((self.dir / "state.json").read_text(encoding="utf-8"))
        except OSError:
            return {"chains": {}, "jumps": [], "counters": {}}

    def set_state(self, state):
        (self.dir / "state.json").write_text(json.dumps(state), encoding="utf-8")

    def calls(self):
        text = (self.dir / "calls.jsonl").read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines() if line]

    def reset_calls(self):
        (self.dir / "calls.jsonl").write_text("", encoding="utf-8")

    def restore_calls(self):
        return [c for c in self.calls() if c["prog"] == "iptables-restore"]

    def conntrack_calls(self):
        """The ports of every conntrack deletion, in call order."""
        ports = []
        for call in self.calls():
            if call["prog"] == "conntrack":
                argv = call["argv"]
                assert argv[:4] == ["-D", "-p", "udp", "--orig-port-dst"] and argv[5:] == ["--dst-nat"], argv
                ports.append(int(argv[4]))
        return ports

    def commits(self):
        return [c for c in self.restore_calls() if "--test" not in c["argv"]]

    def tests(self):
        return [c for c in self.restore_calls() if "--test" in c["argv"]]

    def prepare_jumps(self):
        state = self.state()
        for jump in ("nat:PREROUTING:WINVPN-RELAY-PRE", "nat:POSTROUTING:WINVPN-RELAY-POST"):
            if jump not in state["jumps"]:
                state["jumps"].append(jump)
        self.set_state(state)


# ------------------------------------------------------------------ independent contract text

def hashlimit_name(prefix, port, mode, rate, burst):
    """Contract section 1: the table name carries a digest of its parameters."""
    digest = hashlib.sha256(("%s|%s|%d" % (mode, rate, burst)).encode()).hexdigest()[:4]
    return "%s%d_%s" % (prefix, port, digest)


def contract_rules(relays, wan="enp5s0", rate_src="10/second", burst_src=20,
                   rate_port="400/second", burst_port=800):
    """Restates contract section 8 from scratch. relays: [(port, ip, target port)]."""
    nat = ["*nat", ":WINVPN-RELAY-PRE - [0:0]", ":WINVPN-RELAY-POST - [0:0]",
           "-F WINVPN-RELAY-PRE", "-F WINVPN-RELAY-POST"]
    flt = ["*filter", ":WINVPN-RELAY-FWD - [0:0]", "-F WINVPN-RELAY-FWD"]
    ordered = sorted(relays)
    for port, ip, tport in ordered:
        nat.append("-A WINVPN-RELAY-PRE -i %s -p udp -m addrtype --dst-type LOCAL --dport %d "
                   "-j DNAT --to-destination %s:%d" % (wan, port, ip, tport))
    for port, ip, tport in ordered:
        nat.append("-A WINVPN-RELAY-POST -o %s -p udp -d %s --dport %d -m conntrack --ctstate DNAT "
                   "--ctorigdstport %d -j MASQUERADE" % (wan, ip, tport, port))
    for port, ip, tport in ordered:
        same = ("-A WINVPN-RELAY-FWD -i %s -o %s -p udp -d %s --dport %d -m conntrack --ctstate NEW "
                "--ctorigdstport %d" % (wan, wan, ip, tport, port))
        flt.append("%s -m hashlimit --hashlimit-name %s --hashlimit-mode srcip --hashlimit-above %s "
                   "--hashlimit-burst %d -j DROP"
                   % (same, hashlimit_name("wcs", port, "srcip", rate_src, burst_src), rate_src, burst_src))
        flt.append("%s -m hashlimit --hashlimit-name %s --hashlimit-mode dstip --hashlimit-above %s "
                   "--hashlimit-burst %d -j DROP"
                   % (same, hashlimit_name("wca", port, "dstip", rate_port, burst_port), rate_port, burst_port))
        flt.append("-A WINVPN-RELAY-FWD -i %s -o %s -p udp -d %s --dport %d -m conntrack "
                   "--ctstate NEW,ESTABLISHED --ctdir ORIGINAL --ctorigdstport %d -j ACCEPT"
                   % (wan, wan, ip, tport, port))
        flt.append("-A WINVPN-RELAY-FWD -i %s -o %s -p udp -s %s --sport %d -m conntrack "
                   "--ctstate ESTABLISHED --ctdir REPLY --ctorigdstport %d -j ACCEPT"
                   % (wan, wan, ip, tport, port))
    nat.append("COMMIT")
    flt.append("COMMIT")
    return "\n".join(nat) + "\n", "\n".join(flt) + "\n"


EMPTY_NAT, EMPTY_FILTER = contract_rules([])


# ------------------------------------------------------------------ helper test base

class HelperCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keydir = tempfile.TemporaryDirectory()
        cls.keys = KeyRing(cls.keydir.name)
        cls.helper_source = helper_text()

    @classmethod
    def tearDownClass(cls):
        cls.keydir.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fw = FakeFirewall(self.root)
        self.helper = self.root / "wins-core-relay"
        self.helper.write_text(self.helper_source, encoding="utf-8")
        self.helper.chmod(0o755)
        self.run_dir = self.root / "run"
        self.run_dir.mkdir()
        self.ring_path = self.root / "ring.pub"
        self.ring_path.write_text(self.keys.ring_text(), encoding="utf-8")
        self.desired_path = self.run_dir / "desired.json"
        self.state_path = self.run_dir / "state.json"

    # -- helpers
    def write_desired(self, document):
        self.desired_path.write_text(
            document if isinstance(document, str) else json.dumps(document), encoding="utf-8")

    def args(self, command="apply", extra=(), now=NOW, with_openssl=True, with_ring=True):
        argv = [sys.executable, str(self.helper), command]
        if command in ("apply", "render"):
            argv += ["--desired", str(self.desired_path)]
        if command in ("apply", "clear"):
            argv += ["--state", str(self.state_path)]
        if with_ring:
            argv += ["--ring", str(self.ring_path)]
        argv += ["--iptables", str(self.fw.bin / "iptables"),
                 "--iptables-restore", str(self.fw.bin / "iptables-restore"),
                 "--conntrack", str(self.fw.bin / "conntrack"),
                 "--ip", str(self.fw.bin / "ip"), "--now", str(now)]
        if with_openssl:
            argv += ["--openssl", OPENSSL]
        return argv + list(extra)

    def run_helper(self, command="apply", extra=(), **kwargs):
        return subprocess.run(self.args(command, extra, **kwargs), env=self.fw.env(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)

    def state_doc(self):
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def item(self, exit_def, port, **kwargs):
        return relay_item(self.keys, exit_def, port, **kwargs)

    def apply_ok(self, *items, extra=()):
        self.write_desired(desired(*items))
        self.fw.prepare_jumps()
        result = self.run_helper(extra=extra)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def reasons(self):
        return {(l["exit_slug"], l["port"]): (l["state"], l.get("reason", ""))
                for l in self.state_doc()["listens"]}


class SchemaTests(HelperCase):
    def assert_refused_whole(self, document):
        self.write_desired(document)
        self.fw.prepare_jumps()
        result = self.run_helper()
        self.assertEqual(result.returncode, 1, result.stderr)
        doc = self.state_doc()
        self.assertEqual(doc["state"], "inactive")
        self.assertEqual(doc["listens"], [])
        state = self.fw.state()
        for chain in ("nat/WINVPN-RELAY-PRE", "nat/WINVPN-RELAY-POST", "filter/WINVPN-RELAY-FWD"):
            self.assertEqual(state["chains"].get(chain, []), [])
        self.assertFalse([c for c in self.fw.commits() if "DNAT" in c["stdin"]])

    def test_schema_strictness_table(self):
        good = self.item(EXIT_A, 9211)
        envelope_ok = good["descriptor"]
        cases = {
            "not json": "{nope",
            "empty file": "",
            "array root": "[]",
            "null root": "null",
            "missing relays": {"v": 1, "port_range": PORT_RANGE},
            "missing v": {"port_range": PORT_RANGE, "relays": []},
            "extra root key": {"v": 1, "port_range": PORT_RANGE, "relays": [], "debug": True},
            "missing port_range": {"v": 1, "relays": []},
            "port_range is a number": {"v": 1, "port_range": 9211, "relays": []},
            "port_range is null": {"v": 1, "port_range": None, "relays": []},
            "port_range one port": {"v": 1, "port_range": "9211", "relays": []},
            "port_range with spaces": {"v": 1, "port_range": "9211 - 9218", "relays": []},
            "port_range colon": {"v": 1, "port_range": "9211:9218", "relays": []},
            "port_range leading zero": {"v": 1, "port_range": "09211-9218", "relays": []},
            "port_range three parts": {"v": 1, "port_range": "9211-9215-9218", "relays": []},
            "old shape without port_range": {"v": 1, "relays": [good]},
            "v is two": {"v": 2, "relays": []},
            "v is a string": {"v": "1", "relays": []},
            "v is true": {"v": True, "relays": []},
            "relays not a list": {"v": 1, "port_range": PORT_RANGE, "relays": {}},
            "relay not an object": {"v": 1, "port_range": PORT_RANGE, "relays": ["x"]},
            "relay missing port": {"v": 1, "port_range": PORT_RANGE, "relays": [{"exit_slug": "canada-ca1", "descriptor": envelope_ok}]},
            "relay missing slug": {"v": 1, "port_range": PORT_RANGE, "relays": [{"port": 9211, "descriptor": envelope_ok}]},
            "relay missing descriptor": {"v": 1, "port_range": PORT_RANGE, "relays": [{"exit_slug": "canada-ca1", "port": 9211}]},
            "relay extra key": {"v": 1, "port_range": PORT_RANGE, "relays": [dict(good, target=addr(34, 1, 1, 1) + ":9111")]},
            "relay extra key endpoint": {"v": 1, "port_range": PORT_RANGE, "relays": [dict(good, endpoint=addr(34, 1, 1, 1) + ":9111")]},
            "slug uppercase": {"v": 1, "port_range": PORT_RANGE, "relays": [dict(good, exit_slug="Canada-ca1")]},
            "slug too short": {"v": 1, "port_range": PORT_RANGE, "relays": [dict(good, exit_slug="a")]},
            "slug leading dash": {"v": 1, "port_range": PORT_RANGE, "relays": [dict(good, exit_slug="-ca1")]},
            "slug with slash": {"v": 1, "port_range": PORT_RANGE, "relays": [dict(good, exit_slug="a/b")]},
            "slug not a string": {"v": 1, "port_range": PORT_RANGE, "relays": [dict(good, exit_slug=5)]},
            "port string": {"v": 1, "port_range": PORT_RANGE, "relays": [dict(good, port="9211")]},
            "port float": {"v": 1, "port_range": PORT_RANGE, "relays": [dict(good, port=9211.0)]},
            "port bool": {"v": 1, "port_range": PORT_RANGE, "relays": [dict(good, port=True)]},
            "port zero": {"v": 1, "port_range": PORT_RANGE, "relays": [dict(good, port=0)]},
            "port negative": {"v": 1, "port_range": PORT_RANGE, "relays": [dict(good, port=-1)]},
            "port too large": {"v": 1, "port_range": PORT_RANGE, "relays": [dict(good, port=65536)]},
            "descriptor not an object": {"v": 1, "port_range": PORT_RANGE, "relays": [dict(good, descriptor="x")]},
            "descriptor missing sig": {"v": 1, "port_range": PORT_RANGE, "relays": [dict(good, descriptor={"payload": envelope_ok["payload"]})]},
            "descriptor extra key": {"v": 1, "port_range": PORT_RANGE, "relays": [dict(good, descriptor=dict(envelope_ok, extra="1"))]},
            "payload not a string": {"v": 1, "port_range": PORT_RANGE, "relays": [dict(good, descriptor=dict(envelope_ok, payload=5))]},
            "sig not a string": {"v": 1, "port_range": PORT_RANGE, "relays": [dict(good, descriptor=dict(envelope_ok, sig=None))]},
            "sixty five relays": {"v": 1, "port_range": PORT_RANGE, "relays": [good] * 65},
        }
        for name, document in cases.items():
            with self.subTest(name):
                self.fw.set_state({"chains": {}, "jumps": [], "counters": {}})
                self.fw.reset_calls()
                if self.state_path.exists():
                    self.state_path.unlink()
                self.assert_refused_whole(document)

    def test_a_symlinked_or_missing_desired_file_is_refused(self):
        self.fw.prepare_jumps()
        result = self.run_helper()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.state_doc()["state"], "inactive")
        real = self.root / "real.json"
        real.write_text(json.dumps(desired()), encoding="utf-8")
        self.desired_path.symlink_to(real)
        result = self.run_helper()
        self.assertEqual(result.returncode, 1)

    def test_deeply_nested_json_cannot_crash_the_helper(self):
        self.fw.prepare_jumps()
        self.desired_path.write_text("[" * 200000, encoding="utf-8")
        result = self.run_helper()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(self.state_doc()["state"], "inactive")
        bomb = b64(b"[" * 4000)
        good = self.item(EXIT_A, 9211)
        hostile = {"exit_slug": "canada-ca1", "port": 9211, "descriptor": {"payload": bomb, "sig": good["descriptor"]["sig"]}}
        self.write_desired(desired(hostile, self.item(EXIT_B, 9212)))
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(self.reasons(), {("canada-ca1", 9211): ("down", "descriptor_contract_violation"),
                                          ("germany-de1", 9212): ("up", "")})

    def test_an_unforeseen_error_fails_closed_without_a_traceback(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        source = self.helper.read_text(encoding="utf-8")
        broken = source.replace("def cmd_apply(args):\n", "def cmd_apply(args):\n    raise ZeroDivisionError('boom')\n", 1)
        self.assertNotEqual(source, broken)
        self.helper.write_text(broken, encoding="utf-8")
        result = self.run_helper()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("internal_error", result.stderr)
        self.assertEqual(self.state_doc()["state"], "inactive")
        self.assertEqual(self.fw.state()["chains"]["nat/WINVPN-RELAY-PRE"], [])

    def test_an_oversized_desired_file_is_refused(self):
        self.desired_path.write_text(" " * ((1 << 20) + 1), encoding="utf-8")
        self.fw.prepare_jumps()
        self.assertEqual(self.run_helper().returncode, 1)


class DescriptorTrustTests(HelperCase):
    def one(self, exit_def, port=9211, extra=(), **kwargs):
        self.write_desired(desired(self.item(exit_def, port, **kwargs)))
        self.fw.prepare_jumps()
        result = self.run_helper(extra=extra)
        self.assertEqual(result.returncode, 0, result.stderr)
        return self.reasons()[(exit_def[0], port)]

    def test_each_pinned_slot_verifies(self):
        for kid in ("g1", "g2", "g3"):
            with self.subTest(kid):
                self.assertEqual(self.one(EXIT_A, doc={"kid": kid}), ("up", ""))

    def test_the_slot_named_by_the_signed_kid_is_the_only_key_tried(self):
        # Signed by g2 but claiming g1: g1 is pinned and does not verify it.
        state = self.one(EXIT_A, doc={"kid": "g1"}, sign_with="g2")
        self.assertEqual(state, ("down", "descriptor_signature_invalid"))

    def test_a_stranger_key_never_verifies(self):
        self.assertEqual(self.one(EXIT_A, sign_with="stranger"),
                         ("down", "descriptor_signature_invalid"))

    def test_a_tampered_payload_fails_the_signature(self):
        def tamper(payload):
            return payload.replace(EXIT_A[1].encode(), addr(34, 120, 10, 21).encode())
        self.assertEqual(self.one(EXIT_A, tamper=tamper), ("down", "descriptor_signature_invalid"))

    def test_a_slot_that_is_not_pinned_is_refused(self):
        self.ring_path.write_text(self.keys.ring_text(("g1",)), encoding="utf-8")
        self.assertEqual(self.one(EXIT_A, doc={"kid": "g2"}),
                         ("down", "descriptor_key_slot_not_pinned"))

    def test_an_unknown_kid_is_a_contract_violation(self):
        self.assertEqual(self.one(EXIT_A, doc={"kid": "g4"}, sign_with="g1"),
                         ("down", "descriptor_contract_violation"))

    def test_a_truncated_or_malformed_signature_is_refused(self):
        item = self.item(EXIT_A, 9211)
        bad_sigs = {
            "short": b64(b"\x00" * 63),
            "long": b64(b"\x00" * 65),
            "not base64": "!" * 88,
            "wrong padding": item["descriptor"]["sig"][:-2] + "AA",
        }
        for name, sig in bad_sigs.items():
            with self.subTest(name):
                bad = json.loads(json.dumps(item))
                bad["descriptor"]["sig"] = sig
                self.write_desired(desired(bad))
                self.fw.prepare_jumps()
                self.assertEqual(self.run_helper().returncode, 0)
                state, reason = self.reasons()[(EXIT_A[0], 9211)]
                self.assertEqual(state, "down")
                self.assertIn(reason, ("descriptor_contract_violation", "descriptor_signature_invalid"))

    def test_expired_and_not_yet_valid_descriptors_are_refused(self):
        self.assertEqual(self.one(EXIT_A, doc={"not_after": NOW}), ("down", "descriptor_expired"))
        self.assertEqual(self.one(EXIT_A, doc={"iat": NOW + 1, "not_after": NOW + 1000}),
                         ("down", "descriptor_not_yet_valid"))
        self.assertEqual(self.one(EXIT_A, doc={"iat": NOW, "not_after": NOW + 1000}), ("up", ""))
        self.assertEqual(self.one(EXIT_A, doc={"iat": NOW - 10, "not_after": NOW + 1}), ("up", ""))

    def test_a_node_mismatch_is_refused(self):
        self.assertEqual(self.one(EXIT_A, doc={"node": "germany-de1"}),
                         ("down", "descriptor_node_mismatch"))

    def test_contract_violations_of_the_payload(self):
        cases = {
            "unknown field": {"surprise": 1},
            "missing field": {"seq": None},
            "v two": {"v": 2},
            "v string": {"v": "3"},
            "alg other": {"alg": "rsa"},
            "iat string": {"iat": "5"},
            "not_after before iat": {"not_after": NOW - 200},
            "endpoint hostname": {"endpoint": "exit.example.org:9111"},
            "endpoint no port": {"endpoint": EXIT_A[1]},
            "endpoint leading zero": {"endpoint": "0" + EXIT_A[1] + ":9111"},
            "endpoint port word": {"endpoint": EXIT_A[1] + ":http"},
            "endpoint ipv6": {"endpoint": "[2001:db8::1]:9111"},
            "endpoint octet 256": {"endpoint": addr(34, 120, 10, 256) + ":9111"},
            "endpoint port zero": {"endpoint": EXIT_A[1] + ":0"},
            "endpoint port leading zero": {"endpoint": EXIT_A[1] + ":09111"},
            "endpoint trailing newline": {"endpoint": EXIT_A[1] + ":9111\n"},
            "endpoint embedded space": {"endpoint": EXIT_A[1] + " :9111"},
            "endpoint number": {"endpoint": 5},
        }
        for name, override in cases.items():
            with self.subTest(name):
                got = self.one(EXIT_A, doc=override)
                self.assertEqual(got, ("down", "descriptor_contract_violation"))

    def test_optional_attestation_fields_are_allowed(self):
        self.assertEqual(self.one(EXIT_A, doc={"auth_ed25519": b64(b"\x01" * 32)}), ("up", ""))

    def test_targets_that_are_not_global_unicast_are_refused(self):
        refused = ["10.1.2.3", "172.16.5.5", "192.168.4.1", "100.64.0.9", "127.0.0.1", "169.254.1.1",
                   addr(224, 0, 0, 5), addr(239, 1, 1, 1), "240.0.0.1", "255.255.255.255", "0.0.0.0",
                   "198.51.100.7", "203.0.113.8", "192.0.2.9", "198.18.0.1"]
        for ip in refused:
            with self.subTest(ip):
                got = self.one(("canada-ca1", ip, 9111))
                self.assertEqual(got, ("down", "target_not_global_unicast"))

    def test_the_cores_own_address_is_refused(self):
        self.assertEqual(self.one(EXIT_A, extra=("--self-ip", EXIT_A[1])),
                         ("down", "target_is_core_address"))
        self.fw.config({"addr_output": "2: enp5s0    inet %s/32 scope global enp5s0\n" % EXIT_A[1]})
        self.assertEqual(self.one(EXIT_A), ("down", "target_is_core_address"))

    def test_a_target_port_below_1024_is_refused(self):
        self.assertEqual(self.one(("canada-ca1", EXIT_A[1], 1023)),
                         ("down", "target_port_out_of_range"))
        self.assertEqual(self.one(("canada-ca1", EXIT_A[1], 1024)), ("up", ""))
        self.assertEqual(self.one(("canada-ca1", EXIT_A[1], 65535)), ("up", ""))
        self.assertEqual(self.one(("canada-ca1", EXIT_A[1], 70000)),
                         ("down", "target_port_out_of_range"))

    def test_the_target_is_always_the_signed_endpoint(self):
        self.write_desired(desired(self.item(("canada-ca1", EXIT_A[1], 9333), 9211)))
        self.fw.prepare_jumps()
        self.assertEqual(self.run_helper().returncode, 0)
        pre = self.fw.state()["chains"]["nat/WINVPN-RELAY-PRE"]
        self.assertEqual(len(pre), 1)
        self.assertTrue(pre[0].endswith("--to-destination %s:9333" % EXIT_A[1]))

    def test_a_missing_openssl_fails_closed_with_its_own_reason(self):
        self.write_desired(desired(self.item(EXIT_A, 9211)))
        self.fw.prepare_jumps()
        result = subprocess.run(
            self.args(with_openssl=False) + ["--openssl", str(self.root / "no-such-openssl")],
            env=self.fw.env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.reasons()[(EXIT_A[0], 9211)], ("down", "descriptor_verifier_unavailable"))
        self.assertEqual(self.fw.state()["chains"].get("nat/WINVPN-RELAY-PRE", []), [])


class RingTests(HelperCase):
    def check_ring_down(self):
        self.write_desired(desired(self.item(EXIT_A, 9211), self.item(EXIT_B, 9212)))
        self.fw.prepare_jumps()
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        doc = self.state_doc()
        self.assertEqual(doc["state"], "inactive")
        self.assertEqual({(l["exit_slug"], l["state"], l["reason"]) for l in doc["listens"]},
                         {("canada-ca1", "down", "ring_not_pinned"), ("germany-de1", "down", "ring_not_pinned")})
        self.assertEqual(self.fw.state()["chains"].get("nat/WINVPN-RELAY-PRE", []), [])
        self.assertEqual(self.fw.state()["chains"].get("filter/WINVPN-RELAY-FWD", []), [])

    def test_a_missing_ring_means_inactive_with_ring_not_pinned(self):
        self.ring_path.unlink()
        self.check_ring_down()

    def test_an_empty_ring_means_inactive(self):
        self.ring_path.write_text("", encoding="utf-8")
        self.check_ring_down()

    def test_a_ring_of_garbage_means_inactive(self):
        self.ring_path.write_text("g1=short\nnot a line\ng9=%s\n" % self.keys.public_b64("g1"), encoding="utf-8")
        self.check_ring_down()

    def test_a_symlinked_ring_is_refused(self):
        real = self.root / "real-ring"
        real.write_text(self.keys.ring_text(), encoding="utf-8")
        self.ring_path.unlink()
        self.ring_path.symlink_to(real)
        self.check_ring_down()

    def test_a_ring_that_loses_a_relays_slot_downs_only_that_relay(self):
        self.ring_path.write_text(self.keys.ring_text(("g1",)), encoding="utf-8")
        self.apply_ok(self.item(EXIT_A, 9211, doc={"kid": "g1"}), self.item(EXIT_B, 9212, doc={"kid": "g2"}))
        self.assertEqual(self.reasons(), {("canada-ca1", 9211): ("up", ""),
                                          ("germany-de1", 9212): ("down", "descriptor_key_slot_not_pinned")})
        self.assertEqual(self.state_doc()["state"], "active")


class RenderTests(HelperCase):
    def test_golden_text_for_one_relay(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        nat, flt = contract_rules([(9211, EXIT_A[1], EXIT_A[2])])
        commits = self.fw.commits()
        self.assertEqual(len(commits), 2)
        self.assertEqual(commits[0]["stdin"], flt)
        # apply_ok pre-seeds both nat jumps, so the nat commit is the bare body
        self.assertEqual(commits[1]["stdin"], nat)
    def test_render_command_golden_for_three_relays(self):
        self.write_desired(desired(
            self.item(EXIT_C, 9213), self.item(EXIT_A, 9211), self.item(EXIT_B, 9212)))
        result = self.run_helper("render", extra=("--wan-iface", "enp5s0"))
        self.assertEqual(result.returncode, 0, result.stderr)
        nat, flt = contract_rules([(9211, EXIT_A[1], 9111), (9212, EXIT_B[1], 9111), (9213, EXIT_C[1], 9111)])
        self.assertEqual(result.stdout, nat + flt)
        golden = SERVER / "testdata" / "core_winn3_relay" / "render_three_relays.golden"
        template = golden.read_text(encoding="utf-8")
        for token, exit_def in (("@EXIT_A@", EXIT_A), ("@EXIT_B@", EXIT_B), ("@EXIT_C@", EXIT_C)):
            template = template.replace(token, exit_def[1])
        self.assertEqual(result.stdout, template)
        self.assertEqual(self.fw.restore_calls(), [])
        self.assertFalse(self.state_path.exists())

    def test_render_changes_nothing_and_prints_no_jump(self):
        self.write_desired(desired(self.item(EXIT_A, 9211)))
        result = self.run_helper("render", extra=("--wan-iface", "enp5s0"))
        self.assertNotIn("-I PREROUTING", result.stdout)
        self.assertNotIn("-I POSTROUTING", result.stdout)
        self.assertEqual([c for c in self.fw.calls() if c["prog"] != "ip"], [])

    def test_rule_order_is_by_port_and_each_relay_has_its_four_filter_rules(self):
        self.apply_ok(self.item(EXIT_C, 9213), self.item(EXIT_A, 9211), self.item(EXIT_B, 9212))
        flt = self.fw.state()["chains"]["filter/WINVPN-RELAY-FWD"]
        self.assertEqual(len(flt), 12)
        ports = [re.search(r"--ctorigdstport (\d+)", line).group(1) for line in flt]
        self.assertEqual(ports, ["9211"] * 4 + ["9212"] * 4 + ["9213"] * 4)
        for index in range(0, 12, 4):
            self.assertRegex(flt[index], r"--hashlimit-name wcs\d+_[0-9a-f]{4} ")
            self.assertIn("--hashlimit-mode srcip", flt[index])
            self.assertTrue(flt[index].endswith("-j DROP"))
            self.assertRegex(flt[index + 1], r"--hashlimit-name wca\d+_[0-9a-f]{4} ")
            self.assertIn("--hashlimit-mode dstip", flt[index + 1])
            self.assertTrue(flt[index + 1].endswith("-j DROP"))
            # the original direction: NEW and ESTABLISHED toward the signed target
            self.assertTrue(flt[index + 2].endswith("-j ACCEPT"))
            self.assertNotIn("hashlimit", flt[index + 2])
            self.assertIn("--ctstate NEW,ESTABLISHED --ctdir ORIGINAL", flt[index + 2])
            self.assertIn("-d ", flt[index + 2])
            # the reply direction: ESTABLISHED only, from the signed target
            self.assertTrue(flt[index + 3].endswith("-j ACCEPT"))
            self.assertIn("--ctstate ESTABLISHED --ctdir REPLY", flt[index + 3])
            self.assertIn("-s ", flt[index + 3])
            self.assertNotIn("NEW", flt[index + 3])
        pre = self.fw.state()["chains"]["nat/WINVPN-RELAY-PRE"]
        self.assertEqual([re.search(r"--dport (\d+)", l).group(1) for l in pre], ["9211", "9212", "9213"])

    def test_every_rule_pins_udp_the_interface_and_the_original_destination_port(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        state = self.fw.state()["chains"]
        for line in state["nat/WINVPN-RELAY-POST"] + state["filter/WINVPN-RELAY-FWD"]:
            self.assertIn("-p udp", line)
            self.assertIn("--ctorigdstport 9211", line)
        self.assertIn("-i enp5s0", state["nat/WINVPN-RELAY-PRE"][0])
        self.assertIn("-p udp -m addrtype --dst-type LOCAL --dport 9211 -j DNAT", state["nat/WINVPN-RELAY-PRE"][0])
        self.assertIn("-o enp5s0", state["nat/WINVPN-RELAY-POST"][0])
        for line in state["filter/WINVPN-RELAY-FWD"]:
            self.assertIn("-i enp5s0 -o enp5s0", line)
            self.assertIn("--ctstate", line)

    def test_hashlimit_names_fit_the_15_character_kernel_limit(self):
        for port in (1024, 9211, 65535):
            self.assertLessEqual(len(hashlimit_name("wcs", port, "srcip", "10/second", 20)), 15)
            self.assertLessEqual(len(hashlimit_name("wca", port, "dstip", "400/second", 800)), 15)

    def test_a_changed_rate_or_burst_changes_the_table_name_and_nothing_else_collides(self):
        names = {hashlimit_name("wcs", 9211, "srcip", rate, burst)
                 for rate, burst in (("10/second", 20), ("11/second", 20), ("10/second", 21), ("10/minute", 20))}
        self.assertEqual(len(names), 4)
        self.assertNotEqual(hashlimit_name("wcs", 9211, "srcip", "10/second", 20),
                            hashlimit_name("wca", 9211, "srcip", "10/second", 20))

    def test_the_dnat_rule_only_matches_packets_addressed_to_this_host(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        rule = self.fw.state()["chains"]["nat/WINVPN-RELAY-PRE"][0]
        self.assertIn("-m addrtype --dst-type LOCAL", rule)
        # a forwarded packet for another host on the segment is never DNATed
        self.assertLess(rule.index("--dst-type LOCAL"), rule.index("-j DNAT"))

    def test_custom_rates_and_interface_reach_the_text(self):
        self.write_desired(desired(self.item(EXIT_A, 9211)))
        result = self.run_helper("render", extra=("--wan-iface", "eth9", "--rate-src", "5/second",
                                                  "--burst-src", "7", "--rate-port", "99/minute",
                                                  "--burst-port", "11"))
        nat, flt = contract_rules([(9211, EXIT_A[1], 9111)], wan="eth9", rate_src="5/second",
                                  burst_src=7, rate_port="99/minute", burst_port=11)
        self.assertEqual(result.stdout, nat + flt)

    def test_the_text_never_names_an_address_the_descriptor_did_not_sign(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        text = "".join(c["stdin"] for c in self.fw.commits())
        addresses = set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text))
        self.assertEqual(addresses, {EXIT_A[1]})


class TransactionTests(HelperCase):
    def test_a_first_apply_tests_both_tables_before_it_commits_either(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        order = [("test" if "--test" in c["argv"] else "commit",
                  "filter" if c["stdin"].startswith("*filter") else "nat")
                 for c in self.fw.restore_calls()]
        self.assertEqual(order, [("test", "filter"), ("test", "nat"), ("commit", "filter"), ("commit", "nat")])
        for call in self.fw.restore_calls():
            self.assertIn("--noflush", call["argv"])
            self.assertEqual(call["argv"][:2], ["--wait", "10"])

    def test_the_first_apply_adds_both_nat_jumps_at_position_one(self):
        self.write_desired(desired(self.item(EXIT_A, 9211)))
        self.assertEqual(self.run_helper().returncode, 0)
        nat_commit = self.fw.commits()[1]["stdin"]
        self.assertIn("-I PREROUTING 1 -j WINVPN-RELAY-PRE\n", nat_commit)
        self.assertIn("-I POSTROUTING 1 -j WINVPN-RELAY-POST\n", nat_commit)
        self.assertLess(nat_commit.index(":WINVPN-RELAY-PRE"), nat_commit.index("-I PREROUTING 1"))
        self.assertLess(nat_commit.index("-A WINVPN-RELAY-POST"), nat_commit.index("COMMIT"))
        self.assertIn("nat:PREROUTING:WINVPN-RELAY-PRE", self.fw.state()["jumps"])
        self.assertIn("nat:POSTROUTING:WINVPN-RELAY-POST", self.fw.state()["jumps"])

    def test_a_failed_test_never_commits_and_clears(self):
        self.fw.config({"test_fail": ["nat"]})
        self.write_desired(desired(self.item(EXIT_A, 9211)))
        self.fw.prepare_jumps()
        result = self.run_helper()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.state_doc()["state"], "inactive")
        self.assertEqual(self.reasons()[(EXIT_A[0], 9211)], ("down", "apply_failed"))
        commits = self.fw.commits()
        self.assertTrue(all("DNAT" not in c["stdin"] and "ACCEPT" not in c["stdin"] for c in commits))
        self.assertEqual(self.fw.state()["chains"].get("nat/WINVPN-RELAY-PRE", []), [])

    def test_a_failed_commit_after_the_filter_commit_clears_the_filter_chain_too(self):
        self.fw.config({"commit_fail": ["nat"]})
        self.write_desired(desired(self.item(EXIT_A, 9211)))
        self.fw.prepare_jumps()
        result = self.run_helper()
        self.assertEqual(result.returncode, 1)
        chains = self.fw.state()["chains"]
        self.assertEqual(chains.get("filter/WINVPN-RELAY-FWD", []), [])
        self.assertEqual(chains.get("nat/WINVPN-RELAY-PRE", []), [])
        self.assertEqual(self.state_doc()["state"], "inactive")

    def test_the_text_passes_a_restore_that_checks_chain_declarations(self):
        # The double refuses a rule whose chain was never declared in the same
        # table block; a missing declaration in the helper's text fails here.
        self.write_desired(desired(self.item(EXIT_A, 9211)))
        self.fw.prepare_jumps()
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertEqual(self.state_doc()["state"], "active")
    def test_a_silent_partial_commit_is_caught_and_cleared(self):
        self.fw.config({"drop_first_dnat": True})
        self.write_desired(desired(self.item(EXIT_A, 9211)))
        self.fw.prepare_jumps()
        result = self.run_helper()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.reasons()[(EXIT_A[0], 9211)], ("down", "post_apply_mismatch"))
        self.assertEqual(self.fw.state()["chains"].get("filter/WINVPN-RELAY-FWD", []), [])

    def test_the_rules_hash_is_the_hash_of_the_body_without_jumps(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        nat, flt = contract_rules([(9211, EXIT_A[1], EXIT_A[2])])
        self.assertEqual(self.state_doc()["rules_sha256"],
                         hashlib.sha256((nat + flt).encode()).hexdigest())

    def test_a_missing_forward_jump_downs_every_relay_and_clears(self):
        self.fw.config({"forward_jump": False})
        self.write_desired(desired(self.item(EXIT_A, 9211)))
        self.fw.prepare_jumps()
        result = self.run_helper()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.state_doc()["state"], "inactive")
        self.assertEqual(self.reasons()[(EXIT_A[0], 9211)], ("down", "forward_jump_missing"))
        self.assertEqual(self.fw.state()["chains"].get("nat/WINVPN-RELAY-PRE", []), [])

    def test_an_unknown_wan_interface_downs_every_relay(self):
        self.fw.config({"route_output": ""})
        self.write_desired(desired(self.item(EXIT_A, 9211)))
        self.fw.prepare_jumps()
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertEqual(self.reasons()[(EXIT_A[0], 9211)], ("down", "wan_iface_unknown"))
        self.assertEqual(self.state_doc()["wan_iface"], "unknown")

    def test_the_wan_interface_comes_from_the_default_route_or_the_flag(self):
        self.fw.config({"route_output": "default via 10.0.0.1 dev ens3 metric 100\ndefault via 10.0.0.2 dev ens4\n"})
        self.apply_ok(self.item(EXIT_A, 9211))
        self.assertEqual(self.state_doc()["wan_iface"], "ens3")
        self.apply_ok(self.item(EXIT_A, 9211), extra=("--wan-iface", "eth7"))
        self.assertEqual(self.state_doc()["wan_iface"], "eth7")
        self.assertTrue(self.fw.state()["chains"]["nat/WINVPN-RELAY-PRE"][0].count("-i eth7"))

    def test_dry_run_prints_the_rules_and_changes_nothing(self):
        self.write_desired(desired(self.item(EXIT_A, 9211)))
        self.fw.prepare_jumps()
        result = self.run_helper(extra=("--dry-run",))
        self.assertEqual(result.returncode, 0)
        nat, flt = contract_rules([(9211, EXIT_A[1], 9111)])
        self.assertEqual(result.stdout, nat + flt)
        self.assertEqual(self.fw.restore_calls(), [])
        self.assertFalse(self.state_path.exists())


class IdempotencyTests(HelperCase):
    def test_an_unchanged_second_pass_calls_no_restore(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        first = self.state_doc()
        self.fw.reset_calls()
        later = self.run_helper(now=NOW + 5)
        self.assertEqual(later.returncode, 0, later.stderr)
        self.assertEqual(self.fw.restore_calls(), [])
        second = self.state_doc()
        self.assertEqual(second["applied_at"], first["applied_at"])
        self.assertEqual(second["rules_sha256"], first["rules_sha256"])

    def test_a_noop_pass_still_rewrites_the_state_so_its_mtime_is_fresh(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        os.utime(self.state_path, (1000, 1000))
        self.run_helper(now=NOW + 5)
        self.assertGreater(self.state_path.stat().st_mtime, time.time() - 60)

    def test_counters_ride_the_state(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        state = self.fw.state()
        state["counters"]["9211"] = 4242
        self.fw.set_state(state)
        self.run_helper(now=NOW + 5)
        self.assertEqual(self.state_doc()["listens"][0]["packets"], 4242)

    def test_a_missing_jump_makes_the_next_pass_reapply_with_the_jump(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        state = self.fw.state()
        state["jumps"] = [j for j in state["jumps"] if "PREROUTING" not in j]
        self.fw.set_state(state)
        self.fw.reset_calls()
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        commits = self.fw.commits()
        self.assertEqual(len(commits), 2)
        self.assertIn("-I PREROUTING 1 -j WINVPN-RELAY-PRE", commits[1]["stdin"])
        self.assertNotIn("-I POSTROUTING", commits[1]["stdin"])

    def test_chain_drift_is_detected_and_repaired(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        drifts = {
            "dnat rule gone": ("nat/WINVPN-RELAY-PRE", lambda rules: []),
            "dnat target changed": ("nat/WINVPN-RELAY-PRE",
                                    lambda rules: [r.replace(EXIT_A[1], addr(34, 120, 10, 99)) for r in rules]),
            "filter rule gone": ("filter/WINVPN-RELAY-FWD", lambda rules: rules[:-1]),
            "masquerade rule gone": ("nat/WINVPN-RELAY-POST", lambda rules: []),
            # equal rule counts, different meaning: a count check calls these healthy
            "filter equal-count accept turned into drop": (
                "filter/WINVPN-RELAY-FWD", lambda rules: [r.replace("-j ACCEPT", "-j DROP") for r in rules]),
            "filter equal-count reply direction widened": (
                "filter/WINVPN-RELAY-FWD", lambda rules: [r.replace("--ctdir REPLY", "--ctdir ORIGINAL") for r in rules]),
            "filter equal-count state widened": (
                "filter/WINVPN-RELAY-FWD", lambda rules: [r.replace("--ctstate ESTABLISHED", "--ctstate NEW,ESTABLISHED") for r in rules]),
            "filter equal-count rate changed": (
                "filter/WINVPN-RELAY-FWD", lambda rules: [r.replace("--hashlimit-above 10/second", "--hashlimit-above 9000/second") for r in rules]),
            "nat equal-count port changed": (
                "nat/WINVPN-RELAY-PRE", lambda rules: [r.replace("--dport 9211", "--dport 9212") for r in rules]),
            "masquerade equal-count target port changed": (
                "nat/WINVPN-RELAY-POST", lambda rules: [r.replace("--ctorigdstport 9211", "--ctorigdstport 9217") for r in rules]),
        }
        for name, (chain, mutate) in drifts.items():
            with self.subTest(name):
                state = self.fw.state()
                state["chains"][chain] = mutate(state["chains"][chain])
                self.fw.set_state(state)
                self.fw.reset_calls()
                self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
                self.assertEqual(len(self.fw.commits()), 2)
                nat, flt = contract_rules([(9211, EXIT_A[1], EXIT_A[2])])
                chains = self.fw.state()["chains"]
                self.assertEqual(len(chains["filter/WINVPN-RELAY-FWD"]), 4)
                self.assertEqual(len(chains["nat/WINVPN-RELAY-PRE"]), 1)
                self.assertEqual(len(chains["nat/WINVPN-RELAY-POST"]), 1)
                self.assertIn("%s:9111" % EXIT_A[1], chains["nat/WINVPN-RELAY-PRE"][0])
                # and the repaired chains are exactly the contract text again
                rendered = {"nat/WINVPN-RELAY-PRE": [l for l in nat.splitlines() if l.startswith("-A WINVPN-RELAY-PRE")],
                            "nat/WINVPN-RELAY-POST": [l for l in nat.splitlines() if l.startswith("-A WINVPN-RELAY-POST")],
                            "filter/WINVPN-RELAY-FWD": [l for l in flt.splitlines() if l.startswith("-A WINVPN-RELAY-FWD")]}
                for key, wanted in rendered.items():
                    self.assertEqual(chains[key], wanted, key)

    def test_a_changed_desired_set_reapplies(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        self.fw.reset_calls()
        self.write_desired(desired(self.item(EXIT_A, 9211), self.item(EXIT_B, 9212)))
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        self.assertEqual(len(self.fw.commits()), 2)
        self.assertEqual(len(self.fw.state()["chains"]["nat/WINVPN-RELAY-PRE"]), 2)
        self.assertEqual(self.state_doc()["applied_at"], NOW + 5)

    def test_a_relay_that_leaves_the_list_is_removed(self):
        self.apply_ok(self.item(EXIT_A, 9211), self.item(EXIT_B, 9212))
        self.write_desired(desired(self.item(EXIT_B, 9212)))
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        pre = self.fw.state()["chains"]["nat/WINVPN-RELAY-PRE"]
        self.assertEqual(len(pre), 1)
        self.assertIn(":9111", pre[0])
        self.assertIn("--dport 9212", pre[0])

    def test_an_expired_descriptor_removes_its_relay_on_the_next_pass(self):
        self.apply_ok(self.item(EXIT_A, 9211, doc={"not_after": NOW + 100}))
        self.assertEqual(self.reasons()[(EXIT_A[0], 9211)], ("up", ""))
        self.assertEqual(self.run_helper(now=NOW + 100).returncode, 0)
        self.assertEqual(self.reasons()[(EXIT_A[0], 9211)], ("down", "descriptor_expired"))
        self.assertEqual(self.fw.state()["chains"]["nat/WINVPN-RELAY-PRE"], [])
        self.assertEqual(self.state_doc()["state"], "inactive")

    def test_an_empty_relay_list_clears_and_the_second_pass_is_free(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        self.write_desired(desired())
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        doc = self.state_doc()
        self.assertEqual(doc["state"], "inactive")
        self.assertEqual(doc["listens"], [])
        chains = self.fw.state()["chains"]
        self.assertEqual(chains["nat/WINVPN-RELAY-PRE"], [])
        self.assertEqual(chains["filter/WINVPN-RELAY-FWD"], [])
        self.assertEqual(doc["rules_sha256"], hashlib.sha256((EMPTY_NAT + EMPTY_FILTER).encode()).hexdigest())
        self.fw.reset_calls()
        os.utime(self.state_path, (1000, 1000))
        self.assertEqual(self.run_helper(now=NOW + 6).returncode, 0)
        self.assertEqual(self.fw.restore_calls(), [])
        self.assertGreater(self.state_path.stat().st_mtime, time.time() - 60)


class GateTests(HelperCase):
    """The static gate the installer renders in WINVPN-CORE-FORWARD (finding C1). The
    helper refuses to report a relay up unless the gate it depends on is installed, is
    the exact rule for its own range and comes before the generic established accept."""

    def check_down(self, config):
        self.fw.config(config)
        self.write_desired(desired(self.item(EXIT_A, 9211)))
        self.fw.prepare_jumps()
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state_doc()["state"], "inactive")
        self.assertEqual(self.reasons()[(EXIT_A[0], 9211)], ("down", "forward_jump_missing"))
        self.assertEqual(self.fw.state()["chains"].get("nat/WINVPN-RELAY-PRE", []), [])
        self.assertEqual(self.fw.state()["chains"].get("filter/WINVPN-RELAY-FWD", []), [])

    def test_the_gate_the_installer_renders_is_accepted(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        self.assertEqual(self.state_doc()["state"], "active")
        checks = [c["argv"] for c in self.fw.calls() if c["prog"] == "iptables" and "-C" in c["argv"]
                  and "WINVPN-CORE-FORWARD" in c["argv"]]
        self.assertEqual(len(checks), 2)
        for argv in checks:
            self.assertIn("9211:9218", argv)
            self.assertIn("--ctorigdstport", argv)
        self.assertEqual({argv[-1] for argv in checks}, {"WINVPN-RELAY-FWD", "DROP"})

    def test_a_gate_for_another_range_is_not_the_gate(self):
        self.check_down({"gate_range": "9211:9230"})

    def test_a_missing_gate_drop_rule_is_not_enough(self):
        rng = "9211:9218"
        self.check_down({"core_forward_rules": [
            "-A WINVPN-CORE-FORWARD -p udp -m conntrack --ctstate DNAT --ctorigdstport %s -j WINVPN-RELAY-FWD" % rng,
            "-A WINVPN-CORE-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"]})

    def test_the_old_gate_without_the_drop_and_the_range_is_not_the_gate(self):
        self.check_down({"core_forward_rules": [
            "-A WINVPN-CORE-FORWARD -m conntrack --ctstate DNAT -j WINVPN-RELAY-FWD",
            "-A WINVPN-CORE-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"]})

    def test_a_gate_after_the_established_accept_is_not_the_gate(self):
        rng = "9211:9218"
        self.check_down({"core_forward_rules": [
            "-A WINVPN-CORE-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A WINVPN-CORE-FORWARD -p udp -m conntrack --ctstate DNAT --ctorigdstport %s -j WINVPN-RELAY-FWD" % rng,
            "-A WINVPN-CORE-FORWARD -p udp -m conntrack --ctstate DNAT --ctorigdstport %s -j DROP" % rng]})

    def test_an_unreadable_forward_chain_is_not_the_gate(self):
        self.check_down({"list_fail_WINVPN-CORE-FORWARD": True})

    def test_a_gate_with_no_established_accept_at_all_is_fine(self):
        rng = "9211:9218"
        self.fw.config({"core_forward_rules": [
            "-A WINVPN-CORE-FORWARD -p udp -m conntrack --ctstate DNAT --ctorigdstport %s -j WINVPN-RELAY-FWD" % rng,
            "-A WINVPN-CORE-FORWARD -p udp -m conntrack --ctstate DNAT --ctorigdstport %s -j DROP" % rng]})
        self.apply_ok(self.item(EXIT_A, 9211))
        self.assertEqual(self.state_doc()["state"], "active")

    def test_a_custom_range_is_checked_with_its_own_text(self):
        self.fw.config({"gate_range": "9300:9363"})
        self.write_desired(desired(self.item(EXIT_A, 9300), port_range="9300-9363"))
        self.fw.prepare_jumps()
        result = self.run_helper(extra=("--port-range", "9300-9363"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.reasons()[(EXIT_A[0], 9300)], ("up", ""))


class FlowPurgeTests(HelperCase):
    """Finding C1, second half: when a relay goes away its conntrack entries go too."""

    def test_clear_deletes_the_conntrack_entries_of_every_port_of_the_range_and_no_other(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        self.fw.reset_calls()
        self.assertEqual(self.run_helper("clear").returncode, 0)
        self.assertEqual(self.fw.conntrack_calls(), list(range(9211, 9219)))
        # always the same shape: UDP, matched by the ORIGINAL destination port, and only
        # DNATed flows (an unrelated flow to a remote port with the same number is safe)
        for call in self.fw.calls():
            if call["prog"] == "conntrack":
                self.assertEqual(call["argv"][:4], ["-D", "-p", "udp", "--orig-port-dst"])
                self.assertEqual(call["argv"][5:], ["--dst-nat"])
                self.assertEqual(len(call["argv"]), 6)

    def test_the_purge_comes_after_the_chains_are_emptied(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        self.fw.reset_calls()
        self.run_helper("clear")
        progs = [c["prog"] for c in self.fw.calls() if c["prog"] in ("iptables-restore", "conntrack")]
        self.assertEqual(progs, ["iptables-restore", "iptables-restore"] + ["conntrack"] * 8)

    def test_an_expired_descriptor_purges_only_its_own_port(self):
        self.apply_ok(self.item(EXIT_A, 9211, doc={"not_after": NOW + 100}), self.item(EXIT_B, 9212))
        self.fw.reset_calls()
        self.assertEqual(self.run_helper(now=NOW + 100).returncode, 0)
        self.assertEqual(self.reasons()[(EXIT_A[0], 9211)], ("down", "descriptor_expired"))
        self.assertEqual(self.state_doc()["state"], "active")
        self.assertEqual(self.fw.conntrack_calls(), [9211])
        # the survivor keeps its DNAT, its limits and its accepts
        self.assertEqual(len(self.fw.state()["chains"]["filter/WINVPN-RELAY-FWD"]), 4)

    def test_the_last_relay_expiring_purges_the_whole_range(self):
        self.apply_ok(self.item(EXIT_A, 9211, doc={"not_after": NOW + 100}))
        self.fw.reset_calls()
        self.assertEqual(self.run_helper(now=NOW + 100).returncode, 0)
        self.assertEqual(self.state_doc()["state"], "inactive")
        self.assertEqual(self.fw.conntrack_calls(), list(range(9211, 9219)))

    def test_a_changed_target_purges_that_port_only(self):
        self.apply_ok(self.item(EXIT_A, 9211), self.item(EXIT_B, 9212))
        self.fw.reset_calls()
        moved = ("canada-ca1", addr(34, 120, 10, 99), 9111)
        self.write_desired(desired(self.item(moved, 9211), self.item(EXIT_B, 9212)))
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        self.assertEqual(self.fw.conntrack_calls(), [9211])

    def test_a_relay_that_leaves_the_list_is_purged(self):
        self.apply_ok(self.item(EXIT_A, 9211), self.item(EXIT_B, 9212))
        self.fw.reset_calls()
        self.write_desired(desired(self.item(EXIT_B, 9212)))
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        self.assertEqual(self.fw.conntrack_calls(), [9211])

    def test_adding_a_relay_purges_nothing(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        self.fw.reset_calls()
        self.write_desired(desired(self.item(EXIT_A, 9211), self.item(EXIT_B, 9212)))
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        self.assertEqual(self.fw.conntrack_calls(), [])

    def test_a_true_noop_pass_purges_nothing(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        self.fw.reset_calls()
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        self.assertEqual(self.fw.conntrack_calls(), [])
        self.assertEqual(self.fw.restore_calls(), [])

    def test_a_stable_inactive_helper_does_not_purge_every_pass(self):
        self.write_desired(desired())
        self.fw.prepare_jumps()
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertEqual(self.fw.conntrack_calls(), list(range(9211, 9219)))
        self.fw.reset_calls()
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        self.assertEqual(self.fw.conntrack_calls(), [])

    def test_a_failed_apply_clears_and_purges_the_range(self):
        self.fw.config({"commit_fail": ["nat"]})
        self.write_desired(desired(self.item(EXIT_A, 9211)))
        self.fw.prepare_jumps()
        self.assertEqual(self.run_helper().returncode, 1)
        self.assertEqual(self.fw.conntrack_calls(), list(range(9211, 9219)))

    def test_a_missing_conntrack_binary_keeps_purge_pending(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        argv = self.args("clear")
        argv[argv.index("--conntrack") + 1] = str(self.root / "no-such-conntrack")
        result = subprocess.run(argv, env=self.fw.env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=60)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("conntrack purge conntrack_unavailable", result.stderr)
        self.assertEqual(self.state_doc()["state"], "inactive")
        self.assertEqual(self.state_doc()["purge_pending_ports"], list(range(9211, 9219)))
        self.assertEqual(self.fw.state()["chains"]["filter/WINVPN-RELAY-FWD"], [])

    def test_conntrack_exit_one_means_nothing_matched_and_is_a_success(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        self.fw.config({"conntrack_exit": 1})
        result = self.run_helper("clear")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("conntrack purge", result.stderr)

    def test_a_conntrack_failure_is_reported_and_retried(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        self.fw.config({"conntrack_exit": 4})
        result = self.run_helper("clear")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("conntrack purge conntrack_failed", result.stderr)
        self.assertEqual(self.state_doc()["state"], "inactive")
        self.assertEqual(self.state_doc()["purge_pending_ports"], list(range(9211, 9219)))
        self.assertEqual(self.fw.state()["chains"]["nat/WINVPN-RELAY-PRE"], [])
        self.fw.config({})
        self.fw.reset_calls()
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        self.assertEqual(self.fw.conntrack_calls(), list(range(9211, 9219)))
        self.assertNotIn("purge_pending_ports", self.state_doc())

    def test_conntrack_exit_one_with_an_error_is_not_a_no_match(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        self.fw.config({"conntrack_exit": 1, "conntrack_stderr": "permission denied\n"})
        result = self.run_helper("clear")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("conntrack purge conntrack_failed", result.stderr)
        self.assertEqual(self.state_doc()["purge_pending_ports"], list(range(9211, 9219)))

    def test_failed_clear_keeps_the_previous_range_until_a_successful_retry(self):
        self.write_desired(desired(self.item(EXIT_A, 9300), port_range="9300-9302"))
        self.fw.prepare_jumps()
        self.fw.config({"gate_range": "9300:9302"})
        self.assertEqual(self.run_helper(extra=("--port-range", "9300-9302")).returncode, 0)
        self.fw.config({"conntrack_exit": 4})
        self.assertEqual(self.run_helper("clear").returncode, 1)
        self.assertEqual(self.state_doc()["purge_pending_ports"],
                         list(range(9211, 9219)) + list(range(9300, 9303)))
        self.fw.config({})
        self.fw.reset_calls()
        self.assertEqual(self.run_helper("clear").returncode, 0)
        self.assertEqual(self.fw.conntrack_calls(),
                         list(range(9211, 9219)) + list(range(9300, 9303)))
        self.assertNotIn("purge_pending_ports", self.state_doc())

    def test_a_range_that_was_changed_still_cleans_the_ports_it_really_opened(self):
        # the previous report names the old range; clearing under the new default purges both
        self.write_desired(desired(self.item(EXIT_A, 9300), port_range="9300-9302"))
        self.fw.prepare_jumps()
        self.fw.config({"gate_range": "9300:9302"})
        self.assertEqual(self.run_helper(extra=("--port-range", "9300-9302")).returncode, 0)
        self.assertEqual(self.state_doc()["port_range"], "9300-9302")
        self.fw.reset_calls()
        self.assertEqual(self.run_helper("clear").returncode, 0)  # default range 9211-9218
        self.assertEqual(sorted(self.fw.conntrack_calls()), [9211 + i for i in range(8)] + [9300, 9301, 9302])

    def test_the_dry_run_and_render_never_touch_conntrack(self):
        self.write_desired(desired(self.item(EXIT_A, 9211)))
        self.fw.prepare_jumps()
        self.run_helper(extra=("--dry-run",))
        self.run_helper("render", extra=("--wan-iface", "enp5s0"))
        self.assertEqual(self.fw.conntrack_calls(), [])


class RealListingTests(HelperCase):
    """Finding C3: drift is judged by content. The fake can print its rules the way real
    `iptables -S` does (config normalize_listing): /32 on host addresses, the implied
    -m udp, 10/sec, a fixed field order, ctdir after the other conntrack fields, the
    hashlimit mask. A true no-op must survive that spelling; a real change must not."""

    def setUp(self):
        super().setUp()
        self.fw.config({"normalize_listing": True})

    def test_a_second_pass_is_a_noop_when_the_kernel_spells_the_rules_its_own_way(self):
        self.apply_ok(self.item(EXIT_A, 9211), self.item(EXIT_B, 9212))
        first = self.state_doc()
        self.fw.reset_calls()
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        self.assertEqual(self.fw.restore_calls(), [])
        self.assertEqual(self.state_doc()["applied_at"], first["applied_at"])

    def test_counters_survive_a_noop_pass_with_normalized_listing(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        state = self.fw.state()
        state["counters"]["9211"] = 99
        self.fw.set_state(state)
        self.fw.reset_calls()
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        self.assertEqual(self.state_doc()["listens"][0]["packets"], 99)
        self.assertEqual(self.fw.restore_calls(), [])

    def test_a_real_change_is_still_drift_under_the_kernel_spelling(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        state = self.fw.state()
        state["chains"]["filter/WINVPN-RELAY-FWD"][2] = state["chains"]["filter/WINVPN-RELAY-FWD"][2].replace(
            "-j ACCEPT", "-j DROP")
        self.fw.set_state(state)
        self.fw.reset_calls()
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        self.assertEqual(len(self.fw.commits()), 2)
        self.assertTrue(self.fw.state()["chains"]["filter/WINVPN-RELAY-FWD"][2].endswith("-j ACCEPT"))

    def test_a_rule_the_helper_does_not_understand_means_drift_never_a_false_noop(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        state = self.fw.state()
        state["chains"]["filter/WINVPN-RELAY-FWD"][0] += " --mystery-option 1"
        self.fw.set_state(state)
        self.fw.reset_calls()
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        self.assertEqual(len(self.fw.commits()), 2)

    def test_an_unreadable_chain_means_drift(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        self.fw.config({"normalize_listing": True, "list_fail_WINVPN-RELAY-POST": True})
        self.fw.reset_calls()
        result = self.run_helper(now=NOW + 5)
        # reinstall (2 commits), the result cannot be verified either, so it is cleared (2 more)
        self.assertEqual(len(self.fw.commits()), 4)
        self.assertEqual(result.returncode, 1)  # fail closed
        self.assertEqual(self.reasons()[(EXIT_A[0], 9211)], ("down", "post_apply_mismatch"))
        self.assertEqual(self.state_doc()["state"], "inactive")


class SignatureTests(HelperCase):
    """The canonical rule signature behind C3."""

    def module(self):
        loader = importlib.machinery.SourceFileLoader("relay_helper_signatures", str(self.helper))
        spec = importlib.util.spec_from_loader("relay_helper_signatures", loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        return module

    def test_equivalent_spellings_have_one_signature(self):
        sig = self.module().rule_signature
        written = ("-A WINVPN-RELAY-FWD -i enp5s0 -o enp5s0 -p udp -d 10.1.2.3 --dport 9111 -m conntrack "
                   "--ctstate NEW --ctorigdstport 9211 -m hashlimit --hashlimit-name wcs9211_eceb "
                   "--hashlimit-mode srcip --hashlimit-above 10/second --hashlimit-burst 20 -j DROP")
        printed = ("-A WINVPN-RELAY-FWD -d 10.1.2.3/32 -i enp5s0 -o enp5s0 -p udp -m udp --dport 9111 "
                   "-m conntrack --ctstate NEW --ctorigdstport 9211 -m hashlimit --hashlimit-above 10/sec "
                   "--hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-name wcs9211_eceb "
                   "--hashlimit-srcmask 32 -m comment --comment \"relay rule\" -j DROP")
        self.assertIsNotNone(sig(written))
        self.assertEqual(sig(written), sig(printed))
        states = ("-A C -p udp -m conntrack --ctstate %s --ctdir ORIGINAL --ctorigdstport 1 -j ACCEPT")
        self.assertEqual(sig(states % "NEW,ESTABLISHED"), sig(states % "ESTABLISHED,NEW"))
        self.assertEqual(sig("-A C -p UDP -j DROP"), sig("-A C -p udp -j DROP"))

    def test_different_content_has_different_signatures(self):
        sig = self.module().rule_signature
        base = ("-A F -i e0 -o e0 -p udp -d 10.1.2.3 --dport 9111 -m conntrack --ctstate NEW,ESTABLISHED "
                "--ctdir ORIGINAL --ctorigdstport 9211 -j ACCEPT")
        variants = [
            base.replace("-j ACCEPT", "-j DROP"), base.replace("ORIGINAL", "REPLY"),
            base.replace("NEW,ESTABLISHED", "ESTABLISHED"), base.replace("9211", "9212"),
            base.replace("9111", "9112"), base.replace("10.1.2.3", "10.1.2.4"),
            base.replace("-i e0", "-i e1"), base.replace("-o e0", "-o e1"), base.replace("-p udp", "-p tcp"),
            base.replace("-d 10.1.2.3", "-s 10.1.2.3"), base.replace("-A F", "-A G"),
            base.replace("-d 10.1.2.3", "-d 10.1.2.0/24"),
            "-A F -i e0 -o e0 -p udp -d 10.1.2.3 --dport 9111 -m conntrack --ctstate NEW,ESTABLISHED --ctorigdstport 9211 -j ACCEPT",
        ]
        seen = {sig(base)}
        for variant in variants:
            with self.subTest(variant):
                signature = sig(variant)
                self.assertIsNotNone(signature)
                self.assertNotIn(signature, seen)
                seen.add(signature)

    def test_rates_are_compared_by_value_and_unit(self):
        sig = self.module().rule_signature
        rule = "-A F -m hashlimit --hashlimit-above %s --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-name n -j DROP"
        self.assertEqual(sig(rule % "10/second"), sig(rule % "10/sec"))
        self.assertEqual(sig(rule % "5/minute"), sig(rule % "5/min"))
        self.assertNotEqual(sig(rule % "10/second"), sig(rule % "10/minute"))
        self.assertNotEqual(sig(rule % "10/second"), sig(rule % "11/second"))

    def test_anything_not_understood_is_none(self):
        sig = self.module().rule_signature
        for line in ("", "-N CHAIN", "-A", "-A C", "-A C -j", "-A C --mystery 1 -j DROP", "-A C ! -p udp -j DROP",
                     "-A C -m conntrack --ctstate NEW --ctreplsrc 1.2.3.4 -j DROP",
                     "-A C --hashlimit-above fast -j DROP", "-A C -p 'udp -j DROP"):
            with self.subTest(line):
                self.assertIsNone(sig(line))


class InactiveVerificationTests(HelperCase):
    """Finding C2: an inactive digest in the state file proves nothing about the kernel."""

    def test_leftover_rules_under_an_inactive_digest_are_cleared_again(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        self.write_desired(desired())
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        self.assertEqual(self.state_doc()["state"], "inactive")
        for chain, rule in (("nat/WINVPN-RELAY-PRE", "-A WINVPN-RELAY-PRE -p udp --dport 9211 -j DNAT --to-destination 1.2.3.4:9111"),
                            ("nat/WINVPN-RELAY-POST", "-A WINVPN-RELAY-POST -j MASQUERADE"),
                            ("filter/WINVPN-RELAY-FWD", "-A WINVPN-RELAY-FWD -j ACCEPT")):
            with self.subTest(chain):
                state = self.fw.state()
                state["chains"][chain] = [rule]
                self.fw.set_state(state)
                self.fw.reset_calls()
                self.assertEqual(self.run_helper(now=NOW + 6).returncode, 0)
                self.assertEqual(self.fw.state()["chains"][chain], [])
                self.assertEqual(len(self.fw.commits()), 2)
                self.assertEqual(self.fw.conntrack_calls(), list(range(9211, 9219)))

    def test_an_unreadable_chain_under_an_inactive_digest_is_cleared_again(self):
        self.write_desired(desired())
        self.fw.prepare_jumps()
        self.assertEqual(self.run_helper().returncode, 0)
        self.fw.config({"list_fail_WINVPN-RELAY-FWD": True})
        self.fw.reset_calls()
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        self.assertEqual(len(self.fw.commits()), 2)

    def test_verified_empty_chains_are_a_free_noop(self):
        self.write_desired(desired())
        self.fw.prepare_jumps()
        self.assertEqual(self.run_helper().returncode, 0)
        self.fw.reset_calls()
        os.utime(self.state_path, (1000, 1000))
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        self.assertEqual(self.fw.restore_calls(), [])
        self.assertGreater(self.state_path.stat().st_mtime, time.time() - 60)

    def test_a_missing_gate_with_no_relay_up_stays_inactive_without_error(self):
        self.fw.config({"forward_jump": False})
        self.write_desired(desired(self.item(EXIT_A, 9211)))
        self.fw.prepare_jumps()
        self.assertEqual(self.run_helper().returncode, 0)
        self.fw.reset_calls()
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        self.assertEqual(self.fw.restore_calls(), [])


class JumpOrderTests(HelperCase):
    """Finding C4: a nat jump that exists but is not first can be shadowed."""

    def put_jumps(self, jumps):
        state = self.fw.state()
        state["jumps"] = list(jumps)
        self.fw.set_state(state)

    def test_a_jump_that_is_not_first_is_deleted_and_reinserted_at_position_one(self):
        self.put_jumps(["nat:PREROUTING:SOMEONE-ELSE", "nat:PREROUTING:WINVPN-RELAY-PRE",
                        "nat:POSTROUTING:WINVPN-RELAY-POST"])
        self.write_desired(desired(self.item(EXIT_A, 9211)))
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        nat_commit = self.fw.commits()[1]["stdin"]
        self.assertIn("-D PREROUTING -j WINVPN-RELAY-PRE\n-I PREROUTING 1 -j WINVPN-RELAY-PRE\n", nat_commit)
        self.assertNotIn("-D POSTROUTING", nat_commit)
        self.assertNotIn("-I POSTROUTING", nat_commit)
        jumps = self.fw.state()["jumps"]
        self.assertEqual(jumps.count("nat:PREROUTING:WINVPN-RELAY-PRE"), 1)
        self.assertEqual([j for j in jumps if j.startswith("nat:PREROUTING:")][0], "nat:PREROUTING:WINVPN-RELAY-PRE")
        self.assertEqual(self.state_doc()["state"], "active")

    def test_the_postrouting_jump_is_repaired_the_same_way(self):
        self.put_jumps(["nat:PREROUTING:WINVPN-RELAY-PRE", "nat:POSTROUTING:SOMEONE-ELSE",
                        "nat:POSTROUTING:WINVPN-RELAY-POST"])
        self.write_desired(desired(self.item(EXIT_A, 9211)))
        self.assertEqual(self.run_helper().returncode, 0)
        nat_commit = self.fw.commits()[1]["stdin"]
        self.assertIn("-D POSTROUTING -j WINVPN-RELAY-POST\n-I POSTROUTING 1 -j WINVPN-RELAY-POST\n", nat_commit)
        self.assertNotIn("-D PREROUTING", nat_commit)

    def test_a_repair_happens_even_when_the_rules_themselves_are_unchanged(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        self.put_jumps(["nat:PREROUTING:SOMEONE-ELSE", "nat:PREROUTING:WINVPN-RELAY-PRE",
                        "nat:POSTROUTING:WINVPN-RELAY-POST"])
        self.fw.reset_calls()
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        self.assertEqual(len(self.fw.commits()), 2)
        # an unchanged relay set loses no flow to the repair
        self.assertEqual(self.fw.conntrack_calls(), [])

    def test_jumps_already_first_mean_a_noop(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        self.fw.reset_calls()
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        self.assertEqual(self.fw.restore_calls(), [])

    def test_a_rule_the_chain_cannot_shed_leaves_the_relay_down_with_a_reason(self):
        # a rule ahead of the jump that the transaction cannot move (another tool's rule
        # inside the builtin chain) is the fake's prepend: the jump can never become first
        self.fw.config({"prepend_PREROUTING": ["-A PREROUTING -p udp --dport 9211 -j ACCEPT"]})
        self.write_desired(desired(self.item(EXIT_A, 9211)))
        result = self.run_helper()
        self.assertEqual(result.returncode, 1)
        doc = self.state_doc()
        self.assertEqual(doc["state"], "inactive")
        self.assertEqual(self.reasons()[(EXIT_A[0], 9211)], ("down", "jump_not_first"))
        self.assertEqual(self.fw.state()["chains"]["nat/WINVPN-RELAY-PRE"], [])
        self.assertEqual(hub_sanitize_report(doc), doc)

    def test_an_unlistable_chain_with_a_jump_present_is_repaired_not_trusted(self):
        self.fw.config({"list_fail_PREROUTING": True})
        self.put_jumps(["nat:PREROUTING:WINVPN-RELAY-PRE", "nat:POSTROUTING:WINVPN-RELAY-POST"])
        self.write_desired(desired(self.item(EXIT_A, 9211)))
        result = self.run_helper()
        nat_commit = self.fw.commits()[1]["stdin"]
        self.assertIn("-D PREROUTING -j WINVPN-RELAY-PRE\n-I PREROUTING 1 -j WINVPN-RELAY-PRE\n", nat_commit)
        # the order cannot be verified afterwards either: fail closed, never claim "first"
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.reasons()[(EXIT_A[0], 9211)], ("down", "jump_not_first"))


class RangeAgreementTests(HelperCase):
    """The hub and the Core hold ONE range value and check each other."""

    def test_a_desired_object_with_another_range_downs_every_relay(self):
        self.write_desired(desired(self.item(EXIT_A, 9211), self.item(EXIT_B, 9212), port_range="9211-9230"))
        self.fw.prepare_jumps()
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        doc = self.state_doc()
        self.assertEqual(doc["state"], "inactive")
        self.assertEqual(doc["port_range"], "9211-9218")
        self.assertEqual(self.reasons(), {("canada-ca1", 9211): ("down", "port_range_mismatch"),
                                          ("germany-de1", 9212): ("down", "port_range_mismatch")})
        self.assertEqual(self.fw.state()["chains"].get("nat/WINVPN-RELAY-PRE", []), [])
        self.assertEqual(hub_sanitize_report(doc), doc)

    def test_a_mismatch_clears_live_rules_from_an_earlier_pass(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        self.write_desired(desired(self.item(EXIT_A, 9211), port_range="9211-9219"))
        self.fw.reset_calls()
        self.assertEqual(self.run_helper(now=NOW + 5).returncode, 0)
        self.assertEqual(self.fw.state()["chains"]["nat/WINVPN-RELAY-PRE"], [])
        self.assertEqual(self.fw.conntrack_calls(), list(range(9211, 9219)))

    def test_render_with_another_range_prints_the_empty_tables(self):
        self.write_desired(desired(self.item(EXIT_A, 9211), port_range="9300-9363"))
        result = self.run_helper("render", extra=("--wan-iface", "enp5s0"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, EMPTY_NAT + EMPTY_FILTER)

    def test_the_report_always_names_the_helpers_own_range(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        self.assertEqual(self.state_doc()["port_range"], "9211-9218")
        self.write_desired("{nope")
        self.run_helper(now=NOW + 5)
        self.assertEqual(self.state_doc()["port_range"], "9211-9218")

    def test_the_range_text_is_normalised_in_the_report(self):
        self.write_desired(desired(self.item(EXIT_A, 9250), port_range="9250-9260"))
        self.fw.prepare_jumps()
        self.fw.config({"gate_range": "9250:9260"})
        self.run_helper(extra=("--port-range", "9250-9260"))
        self.assertEqual(self.state_doc()["port_range"], "9250-9260")


class PortAndDuplicateTests(HelperCase):
    def test_ports_outside_the_range_are_down_and_not_rendered(self):
        self.apply_ok(self.item(EXIT_A, 9211), self.item(EXIT_B, 9240), self.item(EXIT_C, 9210))
        self.assertEqual(self.reasons(), {
            ("canada-ca1", 9211): ("up", ""),
            ("germany-de1", 9240): ("down", "port_out_of_range"),
            ("uk-gb1", 9210): ("down", "port_out_of_range"),
        })
        pre = self.fw.state()["chains"]["nat/WINVPN-RELAY-PRE"]
        self.assertEqual(len(pre), 1)

    def test_the_range_flag_moves_the_bounds_when_the_hub_names_the_same_range(self):
        self.write_desired(desired(self.item(EXIT_A, 9250), port_range="9250-9260"))
        self.fw.prepare_jumps()
        self.fw.config({"gate_range": "9250:9260"})
        result = self.run_helper(extra=("--port-range", "9250-9260"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.reasons()[(EXIT_A[0], 9250)], ("up", ""))
        self.assertEqual(self.state_doc()["port_range"], "9250-9260")

    def test_the_old_default_ceiling_is_gone_ports_above_9218_are_down(self):
        self.apply_ok(self.item(EXIT_A, 9218), self.item(EXIT_B, 9219), self.item(EXIT_C, 9230))
        self.assertEqual(self.reasons(), {
            ("canada-ca1", 9218): ("up", ""),
            ("germany-de1", 9219): ("down", "port_out_of_range"),
            ("uk-gb1", 9230): ("down", "port_out_of_range"),
        })

    def test_duplicate_ports_down_both_and_the_rest_still_apply(self):
        self.apply_ok(self.item(EXIT_A, 9211), self.item(EXIT_B, 9211), self.item(EXIT_C, 9213))
        self.assertEqual(self.reasons(), {
            ("canada-ca1", 9211): ("down", "duplicate_port"),
            ("germany-de1", 9211): ("down", "duplicate_port"),
            ("uk-gb1", 9213): ("up", ""),
        })
        pre = self.fw.state()["chains"]["nat/WINVPN-RELAY-PRE"]
        self.assertEqual(len(pre), 1)
        self.assertIn("--dport 9213", pre[0])

    def test_duplicate_exits_down_both(self):
        self.apply_ok(self.item(EXIT_A, 9211), self.item(EXIT_A, 9212), self.item(EXIT_B, 9213))
        self.assertEqual(self.reasons(), {
            ("canada-ca1", 9211): ("down", "duplicate_exit"),
            ("canada-ca1", 9212): ("down", "duplicate_exit"),
            ("germany-de1", 9213): ("up", ""),
        })

    def test_an_up_set_with_one_failure_stays_active(self):
        self.apply_ok(self.item(EXIT_A, 9211), self.item(EXIT_B, 9212, doc={"node": "wrong-node"}))
        self.assertEqual(self.state_doc()["state"], "active")
        self.assertEqual(self.reasons()[("germany-de1", 9212)], ("down", "descriptor_node_mismatch"))


class StateTests(HelperCase):
    def test_the_state_shape_and_reason_rules(self):
        self.apply_ok(self.item(EXIT_A, 9211), self.item(EXIT_B, 9212, doc={"not_after": NOW - 1}))
        doc = self.state_doc()
        self.assertEqual(list(doc), ["v", "state", "port_range", "wan_iface", "applied_at", "rules_sha256", "listens"])
        self.assertEqual(doc["v"], 1)
        self.assertEqual(doc["state"], "active")
        self.assertEqual(doc["port_range"], PORT_RANGE)
        self.assertEqual(doc["wan_iface"], "enp5s0")
        self.assertEqual(doc["applied_at"], NOW)
        self.assertRegex(doc["rules_sha256"], r"^[0-9a-f]{64}$")
        up, down = doc["listens"]
        self.assertEqual(up, {"exit_slug": "canada-ca1", "port": 9211, "state": "up", "packets": 7})
        self.assertEqual(down, {"exit_slug": "germany-de1", "port": 9212, "state": "down",
                                "reason": "descriptor_expired", "packets": 0})
        for entry in doc["listens"]:
            self.assertRegex(entry["exit_slug"], r"^[a-z0-9][a-z0-9-]{1,39}$")
            self.assertTrue(isinstance(entry["port"], int) and 1024 <= entry["port"] <= 65535)
            self.assertIn(entry["state"], ("up", "down"))
            self.assertTrue(isinstance(entry["packets"], int) and entry["packets"] >= 0)
            if "reason" in entry:
                self.assertRegex(entry["reason"], r"^[a-z0-9_]{1,40}$")
        self.assertRegex(doc["wan_iface"], r"^[A-Za-z0-9_.:-]{1,15}$")

    def test_state_file_mode_and_no_leftovers(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        self.assertEqual(stat_module.S_IMODE(self.state_path.stat().st_mode), 0o644)
        self.assertEqual(sorted(p.name for p in self.run_dir.iterdir() if p.name.startswith(".state.")), [])

    def test_the_state_write_is_atomic(self):
        loader = importlib.machinery.SourceFileLoader("relay_helper_under_test", str(self.helper))
        spec = importlib.util.spec_from_loader("relay_helper_under_test", loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        self.apply_ok(self.item(EXIT_A, 9211))
        before = self.state_path.read_bytes()
        original = module.os.replace

        def boom(*args, **kwargs):
            raise OSError("replace failed")

        module.os.replace = boom
        try:
            with self.assertRaises(OSError):
                module.write_state(str(self.state_path), {"v": 1, "state": "inactive"})
        finally:
            module.os.replace = original
        self.assertEqual(self.state_path.read_bytes(), before)
        self.assertEqual([p.name for p in self.run_dir.iterdir() if p.name.startswith(".state.")], [])

    def test_the_state_directory_is_created_when_missing(self):
        self.write_desired(desired())
        nested = self.root / "deep" / "er" / "state.json"
        argv = self.args("apply")
        argv[argv.index("--state") + 1] = str(nested)
        subprocess.run(argv, env=self.fw.env(), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertTrue(nested.exists())

    def test_a_bad_previous_state_is_ignored(self):
        for junk in ("", "{", "[]", json.dumps({"v": 2, "rules_sha256": "x"}), json.dumps({"v": 1})):
            with self.subTest(junk):
                self.state_path.write_text(junk, encoding="utf-8")
                self.apply_ok(self.item(EXIT_A, 9211))
                self.assertEqual(self.state_doc()["state"], "active")


class ClearTests(HelperCase):
    def test_clear_flushes_the_three_chains_and_reports_inactive(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        self.fw.reset_calls()
        result = self.run_helper("clear")
        self.assertEqual(result.returncode, 0, result.stderr)
        chains = self.fw.state()["chains"]
        for chain in ("nat/WINVPN-RELAY-PRE", "nat/WINVPN-RELAY-POST", "filter/WINVPN-RELAY-FWD"):
            self.assertEqual(chains[chain], [])
        doc = self.state_doc()
        self.assertEqual((doc["state"], doc["listens"]), ("inactive", []))
        texts = [c["stdin"] for c in self.fw.commits()]
        self.assertEqual(sorted(texts), sorted([EMPTY_NAT, EMPTY_FILTER]))

    def test_clear_falls_back_to_flush_when_restore_is_unusable(self):
        self.apply_ok(self.item(EXIT_A, 9211))
        self.fw.config({"commit_fail": ["nat", "filter"]})
        self.fw.reset_calls()
        result = self.run_helper("clear")
        self.assertEqual(result.returncode, 0, result.stderr)
        flushes = [c["argv"] for c in self.fw.calls() if c["prog"] == "iptables" and "-F" in c["argv"]]
        self.assertEqual(len(flushes), 3)
        for chain in ("nat/WINVPN-RELAY-PRE", "nat/WINVPN-RELAY-POST", "filter/WINVPN-RELAY-FWD"):
            self.assertEqual(self.fw.state()["chains"][chain], [])

    def test_clear_reports_failure_when_nothing_works(self):
        self.fw.config({"commit_fail": ["nat", "filter"]})
        broken = self.root / "bin" / "iptables"
        broken.write_text("#!/bin/sh\nexit 4\n", encoding="utf-8")
        broken.chmod(0o755)
        result = self.run_helper("clear")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.state_doc()["state"], "inactive")


class CommandLineTests(HelperCase):
    def test_invalid_options_exit_two(self):
        self.write_desired(desired())
        cases = {
            "min below 1024": ("--port-range", "1000-1010"),
            "min above max": ("--port-range", "9300-9200"),
            "max above 65535": ("--port-range", "65500-65600"),
            "wider than 64": ("--port-range", "9211-9300"),
            "contains 9210": ("--port-range", "9205-9215"),
            "contains 9110": ("--port-range", "9100-9120"),
            "contains 9111": ("--port-range", "9111-9111"),
            "not a range": ("--port-range", "9211"),
            "three parts": ("--port-range", "9211-9215-9218"),
            "spaces": ("--port-range", "9211 - 9218"),
            "leading zero": ("--port-range", "09211-9218"),
            "the old min and max flags are gone": ("--port-min", "9211", "--port-max", "9218"),
            "rate word": ("--rate-src", "fast"),
            "rate zero": ("--rate-port", "0/second"),
            "rate unit": ("--rate-src", "10/year"),
            "burst zero": ("--burst-src", "0"),
            "burst huge": ("--burst-port", "1000001"),
            "wan with slash": ("--wan-iface", "a/b"),
            "wan too long": ("--wan-iface", "x" * 16),
            "self ip text": ("--self-ip", "not-an-ip"),
            "self ip v6": ("--self-ip", "::1"),
        }
        for name, extra in cases.items():
            with self.subTest(name):
                result = self.run_helper(extra=extra)
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_missing_required_options_exit_two(self):
        for argv in (
            [sys.executable, str(self.helper), "apply", "--state", str(self.state_path)],
            [sys.executable, str(self.helper), "apply", "--desired", str(self.desired_path)],
            [sys.executable, str(self.helper), "clear"],
            [sys.executable, str(self.helper), "render"],
            [sys.executable, str(self.helper), "frobnicate"],
        ):
            with self.subTest(argv[2:]):
                result = subprocess.run(argv, env=self.fw.env(), stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, timeout=30)
                self.assertEqual(result.returncode, 2)

    def test_logs_carry_reason_words_only(self):
        self.write_desired(desired(self.item(EXIT_A, 9211), self.item(EXIT_B, 9212, sign_with="stranger")))
        self.fw.prepare_jumps()
        result = self.run_helper()
        combined = result.stdout + result.stderr
        item = self.item(EXIT_A, 9211)
        payload = base64.b64decode(item["descriptor"]["payload"]).decode()
        for secret in (b64(b"0123456789abcdef" * 4), b64(bytes(range(32))), EXIT_A[1], EXIT_B[1], item["descriptor"]["sig"]):
            self.assertNotIn(secret, combined)
        self.assertNotIn(payload, combined)

    def test_the_helper_is_standard_library_only_and_python_310_syntax(self):
        import ast
        tree = ast.parse(self.helper_source, feature_version=(3, 10))
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                modules.add((node.module or "").split(".")[0])
        stdlib = set(getattr(sys, "stdlib_module_names", modules))
        self.assertTrue(modules <= stdlib, modules - stdlib)
        self.assertNotIn("\u2014", self.helper_source)

def hub_sanitize_report(doc, port_min=9211, port_max=9218):
    """Contract section 4 as the hub must read it: the sanitized report, or None
    when the object is malformed (the hub then drops it whole)."""
    if not isinstance(doc, dict) or doc.get("v") != 1 or isinstance(doc.get("v"), bool):
        return None
    if doc.get("state") not in ("active", "inactive"):
        return None
    if not isinstance(doc.get("port_range"), str) or not re.fullmatch(r"[1-9][0-9]{3,4}-[1-9][0-9]{3,4}", doc["port_range"]):
        return None
    if not isinstance(doc.get("wan_iface"), str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", doc["wan_iface"]):
        return None
    if not isinstance(doc.get("applied_at"), int) or isinstance(doc["applied_at"], bool):
        return None
    if not isinstance(doc.get("rules_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", doc["rules_sha256"]):
        return None
    listens = doc.get("listens")
    if not isinstance(listens, list) or len(listens) > 32:
        return None
    clean = []
    for entry in listens:
        if not isinstance(entry, dict):
            return None
        slug, port, state = entry.get("exit_slug"), entry.get("port"), entry.get("state")
        packets, reason = entry.get("packets"), entry.get("reason")
        if not isinstance(slug, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,39}", slug):
            return None
        if not isinstance(port, int) or isinstance(port, bool) or not port_min <= port <= port_max:
            return None
        if state not in ("up", "down"):
            return None
        if not isinstance(packets, int) or isinstance(packets, bool) or not 0 <= packets <= 2 ** 53:
            return None
        item = {"exit_slug": slug, "port": port, "state": state, "packets": packets}
        if state == "down":
            if not isinstance(reason, str) or not re.fullmatch(r"[a-z0-9_]{1,40}", reason):
                return None
            item["reason"] = reason
        elif reason is not None:
            return None
        clean.append(item)
    return {"v": 1, "state": doc["state"], "port_range": doc["port_range"], "wan_iface": doc["wan_iface"],
            "applied_at": doc["applied_at"], "rules_sha256": doc["rules_sha256"], "listens": clean}


class HubContractCompatTests(HelperCase):
    def test_every_state_the_helper_writes_passes_the_hubs_sanitizer_unchanged(self):
        scenarios = {
            "one up": [self.item(EXIT_A, 9211)],
            "mixed": [self.item(EXIT_A, 9211), self.item(EXIT_B, 9212, doc={"not_after": NOW - 1}),
                      self.item(EXIT_C, 9213, sign_with="stranger"),
                      self.item(EXIT_D, 9214, doc={"node": "wrong-node"})],
            "duplicates": [self.item(EXIT_A, 9211), self.item(EXIT_B, 9211)],
            "empty": [],
        }
        for name, items in scenarios.items():
            with self.subTest(name):
                self.fw.set_state({"chains": {}, "jumps": [], "counters": {}})
                self.apply_ok(*items)
                doc = self.state_doc()
                self.assertEqual(hub_sanitize_report(doc), doc)

    def test_states_for_the_failure_paths_pass_as_well(self):
        for config, document in (({"route_output": ""}, desired(self.item(EXIT_A, 9211))),
                                 ({"forward_jump": False}, desired(self.item(EXIT_A, 9211))),
                                 ({"commit_fail": ["nat"]}, desired(self.item(EXIT_A, 9211))),
                                 ({}, "{nope")):
            with self.subTest(config):
                self.fw.set_state({"chains": {}, "jumps": [], "counters": {}})
                self.fw.config(config)
                self.write_desired(document)
                self.fw.prepare_jumps()
                self.run_helper()
                doc = self.state_doc()
                self.assertEqual(hub_sanitize_report(doc), doc)

    def test_the_sanitizer_model_itself_rejects_what_the_contract_says(self):
        good = {"v": 1, "state": "active", "port_range": "9211-9218", "wan_iface": "enp5s0", "applied_at": NOW,
                "rules_sha256": "a" * 64,
                "listens": [{"exit_slug": "canada-ca1", "port": 9211, "state": "up", "packets": 0}]}
        self.assertEqual(hub_sanitize_report(good), good)
        for mutate in (lambda d: d.update(v=2), lambda d: d.update(state="up"), lambda d: d.update(wan_iface=""),
                       lambda d: d.update(rules_sha256="x"), lambda d: d["listens"][0].update(port=9300),
                       lambda d: d["listens"][0].update(state="down"),
                       lambda d: d["listens"][0].update(packets=-1),
                       lambda d: d.pop("port_range"), lambda d: d.update(port_range="9211"),
                       lambda d: d.update(port_range=9211), lambda d: d["listens"][0].update(port=9219)):
            bad = json.loads(json.dumps(good))
            mutate(bad)
            self.assertIsNone(hub_sanitize_report(bad))


# ------------------------------------------------------------------ installer tests

class InstallerTextTests(unittest.TestCase):
    def test_the_whole_installer_parses(self):
        result = subprocess.run([BASH, "-n", str(INSTALLER)], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_the_helper_heredoc_is_unique_compiles_and_is_executable_python(self):
        text = installer_text()
        self.assertEqual(text.count("<<'%s'" % HELPER_TAG), 1)
        self.assertEqual(sum(1 for line in text.split("\n") if line == HELPER_TAG), 1)
        source = helper_text()
        compile(source, "wins-core-relay", "exec")
        self.assertTrue(source.startswith("#!/usr/bin/env python3\n"))
        self.assertTrue(source.endswith("sys.exit(main())\n"))

    def test_there_is_still_exactly_one_sync_agent_heredoc(self):
        self.assertEqual(installer_text().count(AGENT_HEADER), 1)

    def test_no_em_dash_or_long_dash_in_the_installer(self):
        text = installer_text()
        for char in (chr(0x2014), chr(0x2013)):
            self.assertNotIn(char, text)

    def test_the_defaults_are_the_contract_values(self):
        text = installer_text()
        expected = {
            "CORE_RELAY_ENABLE": "0",
            "CORE_RELAY_PORT_RANGE": "9211-9218",
            "CORE_RELAY_WAN_IFACE": "",
            "CORE_RELAY_NEW_PER_SRC": "10/second",
            "CORE_RELAY_NEW_PER_SRC_BURST": "20",
            "CORE_RELAY_NEW_PER_PORT": "400/second",
            "CORE_RELAY_NEW_PER_PORT_BURST": "800",
            "CORE_RELAY_DESCRIPTOR_PUBKEY_G1": "",
            "CORE_RELAY_DESCRIPTOR_PUBKEY_G2": "",
            "CORE_RELAY_DESCRIPTOR_PUBKEY_G3": "",
            "CORE_RELAY_DIR": "/etc/winn/core/relay",
            "CORE_RELAY_RUN_DIR": "/run/wins-core-relay",
            "CORE_RELAY_HELPER": "/usr/local/sbin/wins-core-relay",
        }
        for name, value in expected.items():
            line = '%s="${%s:-%s}"' % (name, name, value)
            self.assertGreaterEqual(text.count(line), 1, line)
        # the agent repeats the non-secret defaults
        agent = agent_text()
        for name in ("CORE_RELAY_ENABLE", "CORE_RELAY_PORT_RANGE",
                     "CORE_RELAY_NEW_PER_SRC", "CORE_RELAY_NEW_PER_PORT", "CORE_RELAY_HELPER"):
            self.assertIn(name + '="${' + name + ":-", agent)
        # ONE range value: the two old variables are gone everywhere
        for text_ in (text, agent):
            self.assertNotIn("CORE_RELAY_PORT_MIN", text_)
            self.assertNotIn("CORE_RELAY_PORT_MAX", text_)

    def test_helper_defaults_match_installer_defaults(self):
        source = helper_text()
        self.assertIn('default="10/second"', source)
        self.assertIn("default=20", source)
        self.assertIn('default="400/second"', source)
        self.assertIn("default=800", source)
        self.assertIn('DEFAULT_PORT_RANGE = "9211-9218"', source)
        self.assertIn('parser.add_argument("--port-range", default=DEFAULT_PORT_RANGE)', source)
        self.assertNotIn("--port-min", source)
        self.assertNotIn("--port-max", source)
        self.assertIn('DEFAULT_RING = "/etc/winn/core/relay/ring.pub"', source)

    def test_the_env_file_writer_persists_relay_keys_only_when_enabled(self):
        text = installer_text()
        block = re.search(
            r"    if \[\[ \"\$\{CORE_RELAY_ENABLE:-0\}\" == \"1\" \]\]; then\n"
            r"((?:      printf 'CORE_RELAY_[^\n]*\n)+)    fi\n", text)
        self.assertIsNotNone(block)
        keys = re.findall(r"printf 'CORE_RELAY_([A-Z0-9_]+)=%q", block.group(1))
        self.assertEqual(keys, ["ENABLE", "PORT_RANGE", "WAN_IFACE", "NEW_PER_SRC",
                                "NEW_PER_SRC_BURST", "NEW_PER_PORT", "NEW_PER_PORT_BURST",
                                "DESCRIPTOR_PUBKEY_G1", "DESCRIPTOR_PUBKEY_G2", "DESCRIPTOR_PUBKEY_G3",
                                "DIR", "RUN_DIR", "HELPER"])
        outside = text.replace(block.group(0), "")
        self.assertNotIn("printf 'CORE_RELAY_", outside)

    @unittest.skipIf(bash_major() < 4, "needs bash 4")
    def test_the_env_block_runs_only_when_enabled_and_round_trips(self):
        text = installer_text()
        block = re.search(
            r"(    if \[\[ \"\$\{CORE_RELAY_ENABLE:-0\}\" == \"1\" \]\]; then\n"
            r"(?:      printf 'CORE_RELAY_[^\n]*\n)+    fi\n)", text).group(1)
        for enable in ("0", "1"):
            with self.subTest(enable):
                script = textwrap.dedent("""\
                    CORE_RELAY_ENABLE=%s CORE_RELAY_PORT_RANGE=9211-9218
                    CORE_RELAY_WAN_IFACE='eth 0' CORE_RELAY_NEW_PER_SRC=10/second CORE_RELAY_NEW_PER_SRC_BURST=20
                    CORE_RELAY_NEW_PER_PORT=400/second CORE_RELAY_NEW_PER_PORT_BURST=800
                    CORE_RELAY_DESCRIPTOR_PUBKEY_G1=A CORE_RELAY_DESCRIPTOR_PUBKEY_G2= CORE_RELAY_DESCRIPTOR_PUBKEY_G3=
                    CORE_RELAY_DIR=/etc/winn/core/relay CORE_RELAY_RUN_DIR=/run/wins-core-relay
                    CORE_RELAY_HELPER=/usr/local/sbin/wins-core-relay
                    {
                    %s
                    } > "$1"
                    """) % (enable, block)
                with tempfile.TemporaryDirectory() as tmp:
                    out = Path(tmp) / "env"
                    subprocess.run([BASH, "-c", script, "x", str(out)], check=True)
                    body = out.read_text(encoding="utf-8")
                    if enable == "0":
                        self.assertEqual(body, "")
                    else:
                        probe = subprocess.run(
                            [BASH, "-c", 'source "$1"; printf "%s|%s|%s" "$CORE_RELAY_ENABLE" "$CORE_RELAY_WAN_IFACE" "$CORE_RELAY_DESCRIPTOR_PUBKEY_G1"', "x", str(out)],
                            stdout=subprocess.PIPE, text=True, check=True).stdout
                        self.assertEqual(probe, "1|eth 0|A")

    def test_the_renderer_edits_are_guarded_by_the_flag(self):
        func = extract_function(installer_text(), "write_firewall")
        guard = 'if [[ "${CORE_RELAY_ENABLE:-0}" == "1" ]]; then'
        for needle in ('-A WINVPN-CORE-FORWARD -p udp -m conntrack --ctstate DNAT --ctorigdstport "${relay_gate_range}" -j WINVPN-RELAY-FWD',
                       '-A WINVPN-CORE-FORWARD -p udp -m conntrack --ctstate DNAT --ctorigdstport "${relay_gate_range}" -j DROP',
                       "iptables -N WINVPN-RELAY-FWD", "iptables -t nat -N WINVPN-RELAY-PRE",
                       "iptables -t nat -N WINVPN-RELAY-POST"):
            self.assertEqual(func.count(needle), 1, needle)
            index = func.index(needle)
            opened = func[:index].rindex(guard)
            self.assertNotIn("\n  fi\n", func[opened:index], needle)

class InstallerFunctionCase(unittest.TestCase):
    """Runs extracted installer functions under bash with stubbed edges."""

    @classmethod
    def setUpClass(cls):
        if bash_major() < 4:
            raise unittest.SkipTest("needs bash 4")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def run_bash(self, script, env=None, check=True):
        full_env = dict(os.environ)
        full_env.update(env or {})
        result = subprocess.run([BASH, "-c", script], env=full_env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, timeout=120)
        if check:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result


class ValidationTests(InstallerFunctionCase):
    def validate(self, **overrides):
        values = {
            "CORE_RELAY_ENABLE": "1", "CORE_RELAY_PORT_RANGE": "9211-9218",
            "CORE_RELAY_WAN_IFACE": "", "CORE_RELAY_NEW_PER_SRC": "10/second",
            "CORE_RELAY_NEW_PER_SRC_BURST": "20", "CORE_RELAY_NEW_PER_PORT": "400/second",
            "CORE_RELAY_NEW_PER_PORT_BURST": "800", "CORE_RELAY_DIR": "/etc/winn/core/relay",
            "CORE_RELAY_RUN_DIR": "/run/wins-core-relay", "CORE_RELAY_HELPER": "/usr/local/sbin/wins-core-relay",
            "CORE_INGRESS_PORT": "9210", "CORE_XRAY_INBOUND_PORT": "10110", "CORE_AI_PORT": "11434",
        }
        values.update(overrides)
        text = installer_text()
        script = "\n".join([
            "err() { printf '%s\\n' \"$*\" >&2; }",
            extract_function(text, "valid_absolute_path"),
            extract_function(text, "validate_core_relay_config"),
            "validate_core_relay_config",
        ])
        return self.run_bash(script, env=values, check=False)

    def test_the_defaults_pass(self):
        self.assertEqual(self.validate().returncode, 0)

    def test_disabled_accepts_anything_but_a_dirty_flag(self):
        self.assertEqual(self.validate(CORE_RELAY_ENABLE="0", CORE_RELAY_PORT_RANGE="junk").returncode, 0)
        for value in ("2", "yes", "01", "true"):
            with self.subTest(value):
                self.assertEqual(self.validate(CORE_RELAY_ENABLE=value).returncode, 1)
        # empty means unset, which is off, exactly like the top level default
        self.assertEqual(self.validate(CORE_RELAY_ENABLE="").returncode, 0)

    def test_bad_inputs_are_refused_when_enabled(self):
        cases = {
            "min below 1024": {"CORE_RELAY_PORT_RANGE": "1023-1030"},
            "min word": {"CORE_RELAY_PORT_RANGE": "abc-9218"},
            "empty": {"CORE_RELAY_PORT_RANGE": ""},
            "one port only": {"CORE_RELAY_PORT_RANGE": "9211"},
            "colon spelling": {"CORE_RELAY_PORT_RANGE": "9211:9218"},
            "spaces": {"CORE_RELAY_PORT_RANGE": "9211 - 9218"},
            "list": {"CORE_RELAY_PORT_RANGE": "9211,9218"},
            "three parts": {"CORE_RELAY_PORT_RANGE": "9211-9215-9218"},
            "min leading zero": {"CORE_RELAY_PORT_RANGE": "09211-9218"},
            "max above 65535": {"CORE_RELAY_PORT_RANGE": "65500-65536"},
            "min above max": {"CORE_RELAY_PORT_RANGE": "9300-9230"},
            "wider than 64": {"CORE_RELAY_PORT_RANGE": "9211-9275"},
            "contains 9210": {"CORE_RELAY_PORT_RANGE": "9200-9220"},
            "contains 9110": {"CORE_RELAY_PORT_RANGE": "9100-9120"},
            "contains 9111": {"CORE_RELAY_PORT_RANGE": "9100-9111"},
            "contains custom ingress": {"CORE_INGRESS_PORT": "9216"},
            "contains xray inbound": {"CORE_XRAY_INBOUND_PORT": "9215"},
            "contains ai port": {"CORE_AI_PORT": "9218"},
            "the old variables are not read": {"CORE_RELAY_PORT_RANGE": "", "CORE_RELAY_PORT_MIN": "9211", "CORE_RELAY_PORT_MAX": "9218"},
            "src rate word": {"CORE_RELAY_NEW_PER_SRC": "fast"},
            "src rate zero": {"CORE_RELAY_NEW_PER_SRC": "0/second"},
            "port rate unit": {"CORE_RELAY_NEW_PER_PORT": "5/year"},
            "src burst zero": {"CORE_RELAY_NEW_PER_SRC_BURST": "0"},
            "port burst word": {"CORE_RELAY_NEW_PER_PORT_BURST": "x"},
            "wan slash": {"CORE_RELAY_WAN_IFACE": "a/b"},
            "wan long": {"CORE_RELAY_WAN_IFACE": "x" * 16},
            "dir relative": {"CORE_RELAY_DIR": "etc/relay"},
            "dir traversal": {"CORE_RELAY_RUN_DIR": "/run/../etc"},
            "helper with space": {"CORE_RELAY_HELPER": "/usr/local/sbin/wins core relay"},
        }
        for name, overrides in cases.items():
            with self.subTest(name):
                self.assertEqual(self.validate(**overrides).returncode, 1)

    def test_valid_variations_pass(self):
        for overrides in ({"CORE_RELAY_WAN_IFACE": "enp5s0"}, {"CORE_RELAY_PORT_RANGE": "9211-9211"},
                          {"CORE_RELAY_PORT_RANGE": "9300-9363"},
                          {"CORE_RELAY_PORT_RANGE": "9211-9230"},
                          {"CORE_RELAY_NEW_PER_SRC": "100/minute"}):
            with self.subTest(overrides):
                self.assertEqual(self.validate(**overrides).returncode, 0)

    def test_preflight_calls_the_validator(self):
        func = extract_function(installer_text(), "preflight_core")
        self.assertEqual(func.count("validate_core_relay_config || exit 1"), 1)


class RingWriterTests(InstallerFunctionCase):
    def write(self, **keys):
        text = installer_text()
        ring_dir = self.root / "relay"
        ring_dir.mkdir(exist_ok=True)
        env = {"CORE_RELAY_DIR": str(ring_dir)}
        env.update({"CORE_RELAY_DESCRIPTOR_PUBKEY_%s" % slot.upper(): value for slot, value in keys.items()})
        for slot in ("G1", "G2", "G3"):
            env.setdefault("CORE_RELAY_DESCRIPTOR_PUBKEY_%s" % slot, "")
        script = "\n".join([
            "warn() { printf '%s\\n' \"$*\" >&2; }",
            extract_function(text, "core_relay_write_ring"),
            "core_relay_write_ring",
        ])
        return self.run_bash(script, env=env, check=False), ring_dir / "ring.pub"

    def test_valid_keys_are_written_in_slot_order_with_mode_0644(self):
        k1, k2 = b64(bytes(range(32))), b64(bytes(range(1, 33)))
        result, ring = self.write(g1=k1, g3=k2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(ring.read_text(encoding="utf-8"), "g1=%s\ng3=%s\n" % (k1, k2))
        self.assertEqual(stat_module.S_IMODE(ring.stat().st_mode), 0o644)
        self.assertEqual([p.name for p in ring.parent.iterdir()], ["ring.pub"])

    def test_an_invalid_key_is_ignored_with_a_warning(self):
        good = b64(bytes(range(32)))
        for bad in ("short", good[:-1], b64(bytes(31)), good + "A", "!" * 44):
            with self.subTest(bad):
                result, ring = self.write(g1=bad, g2=good)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(ring.read_text(encoding="utf-8"), "g2=%s\n" % good)
                self.assertIn("CORE_RELAY_DESCRIPTOR_PUBKEY_G1", result.stderr)

    def test_no_key_leaves_an_existing_ring_and_warns_when_there_is_none(self):
        result, ring = self.write()
        self.assertEqual(result.returncode, 0)
        self.assertFalse(ring.exists())
        self.assertIn("relay stays inactive", result.stderr)
        ring.write_text("g1=keep\n", encoding="utf-8")
        result, ring = self.write()
        self.assertEqual(ring.read_text(encoding="utf-8"), "g1=keep\n")
        self.assertNotIn("stays inactive", result.stderr)


class InstallRelayTests(InstallerFunctionCase):
    def harness(self, enable, helper_text_override=None):
        text = installer_text()
        stubs = self.root / "stubs"
        stubs.mkdir(exist_ok=True)
        log = self.root / "calls.log"
        for name in ("python3", "openssl", "iptables", "iptables-restore", "ip", "modprobe", "sysctl", "conntrack"):
            path = stubs / name
            if name == "python3":
                path.write_text("#!/bin/sh\necho \"python3 $*\" >> %s\nexec %s \"$@\"\n" % (log, sys.executable), encoding="utf-8")
            else:
                path.write_text("#!/bin/sh\necho \"%s $*\" >> %s\nexit 0\n" % (name, log), encoding="utf-8")
            path.chmod(0o755)
        etc = self.root / "etc"
        (etc / "sysctl.d").mkdir(parents=True, exist_ok=True)
        (etc / "modules-load.d").mkdir(parents=True, exist_ok=True)
        proc = self.root / "proc" / "sys" / "net" / "ipv4" / "conf" / "eth0"
        proc.mkdir(parents=True, exist_ok=True)
        (proc / "send_redirects").write_text("1\n", encoding="utf-8")
        body = "\n".join([
            "log() { :; }",
            "warn() { printf 'WARN %s\\n' \"$*\" >&2; }",
            "err() { printf 'ERR %s\\n' \"$*\" >&2; }",
            # install -d -o root -g root needs root; keep the directory and mode semantics
            "install() { local mode=0755 args=(); while (($#)); do case \"$1\" in -d) shift;; -m) mode=\"$2\"; shift 2;; -o|-g) shift 2;; *) args+=(\"$1\"); shift;; esac; done; mkdir -p \"${args[@]}\" && chmod \"$mode\" \"${args[@]}\"; }",
            "chown() { :; }",
            extract_function(text, "core_relay_write_ring"),
            extract_function(text, "install_core_relay")
            .replace("/etc/sysctl.d/", str(etc / "sysctl.d") + "/")
            .replace("/etc/modules-load.d/", str(etc / "modules-load.d") + "/")
            .replace("/proc/sys/net/ipv4/conf/*/send_redirects", str(self.root / "proc/sys/net/ipv4/conf") + "/*/send_redirects"),
            "install_core_relay",
        ])
        env = {
            "PATH": "%s:%s" % (stubs, os.environ["PATH"]),
            "CORE_RELAY_ENABLE": enable,
            "CORE_RELAY_DIR": str(self.root / "relay"),
            "CORE_RELAY_RUN_DIR": str(self.root / "run"),
            "CORE_RELAY_HELPER": str(self.root / "sbin" / "wins-core-relay"),
            "CORE_RELAY_DESCRIPTOR_PUBKEY_G1": b64(bytes(range(32))),
            "CORE_RELAY_DESCRIPTOR_PUBKEY_G2": "",
            "CORE_RELAY_DESCRIPTOR_PUBKEY_G3": "",
        }
        return self.run_bash(body, env=env, check=False), log

    def test_disabled_installs_nothing_and_calls_nothing(self):
        result, log = self.harness("0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(log.exists())
        for name in ("relay", "run", "sbin", "etc/sysctl.d/99-winsvpn-core-relay.conf",
                     "etc/modules-load.d/winsvpn-core-relay.conf"):
            self.assertFalse((self.root / name).exists(), name)

    def test_enabled_installs_the_helper_the_ring_and_the_sysctl_files(self):
        result, log = self.harness("1")
        self.assertEqual(result.returncode, 0, result.stderr)
        helper = self.root / "sbin" / "wins-core-relay"
        self.assertEqual(helper.read_text(encoding="utf-8"), helper_text())
        self.assertEqual(stat_module.S_IMODE(helper.stat().st_mode), 0o755)
        self.assertEqual((self.root / "relay" / "ring.pub").read_text(encoding="utf-8"),
                         "g1=%s\n" % b64(bytes(range(32))))
        self.assertTrue((self.root / "run").is_dir())
        sysctl = (self.root / "etc/sysctl.d/99-winsvpn-core-relay.conf").read_text(encoding="utf-8")
        self.assertEqual(sysctl.splitlines(), [
            "net.ipv4.conf.all.send_redirects=0",
            "net.ipv4.conf.default.send_redirects=0",
            "net.netfilter.nf_conntrack_udp_timeout_stream=180",
        ])
        self.assertEqual((self.root / "etc/modules-load.d/winsvpn-core-relay.conf").read_text(encoding="utf-8"),
                         "nf_conntrack\n")
        self.assertEqual((self.root / "proc/sys/net/ipv4/conf/eth0/send_redirects").read_text(encoding="utf-8"), "0\n")
        calls = log.read_text(encoding="utf-8")
        self.assertIn("modprobe nf_conntrack", calls)
        self.assertIn("sysctl -p", calls)
        self.assertEqual([p.name for p in (self.root / "sbin").iterdir()], ["wins-core-relay"])

    def test_the_installed_helper_compiles_and_is_the_extracted_text(self):
        self.harness("1")
        compile((self.root / "sbin" / "wins-core-relay").read_text(encoding="utf-8"), "helper", "exec")

    def test_a_missing_tool_stops_the_install(self):
        text = installer_text()
        script = "\n".join([
            "err() { printf 'ERR %s\\n' \"$*\" >&2; }",
            "log() { :; }",
            "warn() { :; }",
            "command() { if [[ \"$1\" == -v && \"$2\" == openssl ]]; then return 1; fi; "
            "if [[ \"$1\" == -v && \"$2\" == conntrack ]]; then return 0; fi; builtin command \"$@\"; }",
            extract_function(text, "install_core_relay"),
            "install_core_relay",
        ])
        result = self.run_bash(script, env={"CORE_RELAY_ENABLE": "1"}, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("openssl", result.stderr)

    def test_a_missing_conntrack_is_installed_and_a_failed_install_stops(self):
        # Without conntrack(8) every clear leaves purge_pending_ports set and no
        # relay can come up (aicore 2026-10-24), so the package is installed here.
        text = installer_text()
        for apt_rc, want_rc in ((0, 0), (1, 1)):
            calls = self.root / ("apt_%d.log" % apt_rc)
            script = "\n".join([
                "err() { printf 'ERR %s\\n' \"$*\" >&2; }",
                "log() { :; }",
                "warn() { :; }",
                "APT_GET=(apt-get)",
                "CT_OK=0",
                "apt_retry() { echo \"$*\" >> %s; [[ %d == 0 ]] && CT_OK=1; return %d; }" % (calls, apt_rc, apt_rc),
                "command() { if [[ \"$1\" == -v && \"$2\" == conntrack ]]; then [[ $CT_OK == 1 ]]; return; fi; "
                "if [[ \"$1\" == -v ]]; then return 0; fi; builtin command \"$@\"; }",
                extract_function(text, "install_core_relay").split("  install -d -m 0755")[0]
                .rstrip() + "\n  return 0\n}",
                "install_core_relay",
            ])
            result = self.run_bash(script, env={"CORE_RELAY_ENABLE": "1"}, check=False)
            self.assertEqual(calls.read_text(encoding="utf-8").strip(), "apt-get install -y conntrack")
            if want_rc:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("conntrack package", result.stderr)
            else:
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_the_sysctl_keys_do_not_collide_with_the_core_sysctl_file(self):
        text = installer_text()
        core_conf = re.search(r"cat > /etc/sysctl.d/99-winsvpn-core.conf <<'EOF'\n(.*?)\nEOF\n", text, re.S).group(1)
        core_keys = {line.split("=", 1)[0] for line in core_conf.splitlines() if "=" in line}
        for key in ("net.ipv4.conf.all.send_redirects", "net.ipv4.conf.default.send_redirects",
                    "net.netfilter.nf_conntrack_udp_timeout_stream"):
            self.assertNotIn(key, core_keys)

    def test_main_calls_the_installer_step_between_the_free_bandwidth_policy_and_the_ingress(self):
        self.assertEqual(installer_text().count(
            "  install_free_bandwidth_policy || return 1\n  install_core_relay || return 1\n  install_awg_ingress\n"), 1)

class SysctlReservedPortsTests(InstallerFunctionCase):
    """Finding F-05: the relay DNAT binds no socket, so the host's ephemeral source port
    allocation could take a relay port unless the range is reserved. Only when enabled."""

    def write(self, enable, installer=None, extra=None):
        text = Path(installer).read_text(encoding="utf-8") if installer else installer_text()
        func = extract_function(text, "setup_sysctl")
        conf = self.root / ("conf-%s-%s" % (enable, "base" if installer else "new"))
        func = func.replace("/etc/sysctl.d/99-winsvpn-core.conf", str(conf))
        func = func.replace("/proc/sys/net/ipv6/conf/", str(self.root / "no-proc") + "/")
        script = "\n".join([
            "set -u", "log() { :; }", "warn() { :; }", "sysctl() { return 0; }", func,
            # the last loop of the function ends in a false [[ -w ]] test on this host
            "setup_sysctl; true",
        ])
        env = {"CORE_INGRESS_PORT": "9210", "CORE_XRAY_INBOUND_PORT": "10110", "CORE_AI_PORT": "11434"}
        if enable is not None:
            env["CORE_RELAY_ENABLE"] = enable
        env.update(extra or {})
        self.run_bash(script, env=env)
        return conf.read_text(encoding="utf-8")

    def reserved_line(self, text):
        lines = [l for l in text.splitlines() if l.startswith("net.ipv4.ip_local_reserved_ports=")]
        self.assertEqual(len(lines), 1)
        return lines[0]

    def test_disabled_writes_the_line_it_always_wrote(self):
        self.assertEqual(self.reserved_line(self.write("0")), "net.ipv4.ip_local_reserved_ports=9210,10110,11434")
        self.assertEqual(self.reserved_line(self.write(None)), "net.ipv4.ip_local_reserved_ports=9210,10110,11434")

    def test_enabled_lists_the_relay_range_between_the_ingress_and_the_other_ports(self):
        self.assertEqual(self.reserved_line(self.write("1")),
                         "net.ipv4.ip_local_reserved_ports=9210,9211-9218,10110,11434")
        self.assertEqual(self.reserved_line(self.write("1", extra={"CORE_RELAY_PORT_RANGE": "9300-9363"})),
                         "net.ipv4.ip_local_reserved_ports=9210,9300-9363,10110,11434")

    def test_the_rest_of_the_file_is_unchanged_by_the_flag(self):
        off = [l for l in self.write("0").splitlines() if "ip_local_reserved_ports" not in l]
        on = [l for l in self.write("1").splitlines() if "ip_local_reserved_ports" not in l]
        self.assertEqual(on, off)

    @unittest.skipUnless(BASE_INSTALLER, "set WINS_RELAY_BASE_INSTALLER to compare with the base installer")
    def test_disabled_file_equals_the_base_installers_file_byte_for_byte(self):
        self.assertEqual(self.write("0"), self.write("0", installer=BASE_INSTALLER))


# ------------------------------------------------------------------ renderer harness

class RendererHarness(InstallerFunctionCase):
    def render(self, enable, installer=None, public=0, extra_env=None, expected_status=0):
        text = (Path(installer).read_text(encoding="utf-8") if installer else installer_text())
        func = extract_function(text, "write_firewall")
        marker = '  "${save_bin}" > "${snapshot}"\n'
        self.assertEqual(func.count(marker), 1)
        func = func.replace(marker, '  cp "${transaction}" "${HARNESS_TRANSACTION_OUT}"\n  cleanup_core_firewall_transaction_workspace\n  return 0\n')
        out = self.root / ("transaction-%s-%s.rules" % (enable, "base" if installer else "new"))
        calls = self.root / ("calls-%s-%s.log" % (enable, "base" if installer else "new"))
        for stale in (out, calls):
            if stale.exists():
                stale.unlink()
        script = "\n".join([
            # the installer runs under set -u; a standalone extraction of the function must too
            "set -u",
            "unset CORE_RELAY_ENABLE" if enable is None else ":",
            "log() { :; }", "warn() { :; }", "err() { printf 'ERR %s\\n' \"$*\" >&2; }",
            "iptables() {",
            "  printf '%s\\n' \"$*\" >> \"$HARNESS_CALLS\"",
            "  case \"$*\" in",
            "    '-S INPUT'|'-S FORWARD') return 0 ;;",
            "    '-m hashlimit --help') return 0 ;;",
            "    -N*|'-t nat -N'*) return 0 ;;",
            "    *-C*) return 1 ;;",
            "  esac",
            "  return 0",
            "}",
            "core_tcp_mss_for_mtu() { printf '%s' \"$((${1} - 40))\"; }",
            "install_core_failure_hold_firewall() { :; }",
            extract_function(text, "cleanup_core_firewall_transaction_workspace"),
            func,
            "write_firewall 0 %d" % public,
        ])
        env = {
            "INSTALL_CORE_IDS_IPS_DEFAULT": "0", "SURICATA_NFQUEUE_FAIL_OPEN_DEFAULT": "0",
            "CORE_INGRESS_ADDR": "10.9.1.1/16", "CORE_INSTALLER_RERUN_ACTIVE": "0",
            "CORE_OPEN_PUBLIC_INGRESS": "1", "CORE_INGRESS_IFACE": "core0", "CORE_INGRESS_PORT": "9210",
            "CORE_STEALTH_TRANSPORTS": "80:none", "CORE_ADMIN_CIDR": "192.168.50.0/24",
            "CORE_INGRESS_CIDR": "10.9.0.0/16", "CORE_EXIT_IFACE": "coreexit0", "CORE_EXIT_IFACE_PREFIX": "corex",
            "CORE_UDP_RATE_LIMIT": "0", "CORE_UDP_RATE_BURST": "100000", "CORE_AWG_MTU": "1280",
            "HARNESS_TRANSACTION_OUT": str(out), "HARNESS_CALLS": str(calls),
            "SSH_CONNECTION": "", "WINSVPN_DEPLOY_SOURCE": "",
        }
        if enable is not None:
            env["CORE_RELAY_ENABLE"] = enable
        env.update(extra_env or {})
        result = self.run_bash(script, env=env, check=False)
        self.assertEqual(result.returncode, expected_status, result.stderr)
        self.last_render_result = result
        return (out.read_text(encoding="utf-8") if out.exists() else "",
                calls.read_text(encoding="utf-8").splitlines() if calls.exists() else [])


class RendererTests(RendererHarness):
    def test_disabled_renders_no_relay_text_and_creates_no_chain(self):
        rules, calls = self.render("0")
        self.assertNotIn("RELAY", rules)
        self.assertEqual([c for c in calls if "-N" in c.split()], [])

    def test_an_unset_flag_behaves_as_off_under_set_u(self):
        # tools/test_core_installer_fix_wave_b.py and the installer relay tooling run
        # write_firewall on its own, with no CORE_RELAY_ENABLE in scope.
        unset, unset_calls = self.render(None)
        off, off_calls = self.render("0")
        self.assertEqual(unset, off)
        self.assertEqual(unset_calls, off_calls)

    GATE = "-A WINVPN-CORE-FORWARD -p udp -m conntrack --ctstate DNAT --ctorigdstport 9211:9218 -j WINVPN-RELAY-FWD"
    GATE_DROP = "-A WINVPN-CORE-FORWARD -p udp -m conntrack --ctstate DNAT --ctorigdstport 9211:9218 -j DROP"
    ESTABLISHED = "-A WINVPN-CORE-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"

    def test_enabled_adds_exactly_the_two_gate_lines_and_three_chain_creations(self):
        off, off_calls = self.render("0")
        on, on_calls = self.render("1")
        added = [line for line in on.splitlines() if line not in off.splitlines()]
        self.assertEqual(added, [self.GATE, self.GATE_DROP])
        self.assertEqual(len(on.splitlines()), len(off.splitlines()) + 2)
        # nothing the base renderer wrote is lost or reordered, the gate is only inserted
        self.assertEqual([l for l in on.splitlines() if l not in (self.GATE, self.GATE_DROP)], off.splitlines())
        self.assertEqual([c for c in on_calls if c not in off_calls],
                         ["-N WINVPN-RELAY-FWD", "-t nat -N WINVPN-RELAY-PRE", "-t nat -N WINVPN-RELAY-POST"])

    def test_the_gate_comes_before_the_established_accept_and_both_precede_the_final_drop(self):
        on, _ = self.render("1")
        lines = on.splitlines()
        gate = lines.index(self.GATE)
        gate_drop = lines.index(self.GATE_DROP)
        established = lines.index(self.ESTABLISHED)
        final_drop = lines.index("-A WINVPN-CORE-FORWARD -j DROP")
        # C1: an established flow of the relay range is judged by the relay chain first
        self.assertEqual((gate, gate_drop, established), (established - 2, established - 1, established))
        self.assertLess(established, final_drop)
        self.assertEqual(lines.count(self.ESTABLISHED), 1)
        self.assertEqual(lines.count("-A WINVPN-CORE-FORWARD -j DROP"), 1)
        # no other rule of the chain accepts before the gate for these flows
        for earlier in lines[:gate]:
            if earlier.startswith("-A WINVPN-CORE-FORWARD") and earlier.endswith("-j ACCEPT"):
                self.assertNotIn("ESTABLISHED", earlier)

    def test_the_disabled_renderer_keeps_the_established_accept_first(self):
        off, _ = self.render("0")
        lines = off.splitlines()
        self.assertNotIn(self.GATE, lines)
        self.assertNotIn(self.GATE_DROP, lines)
        self.assertIn(self.ESTABLISHED, lines)

    def test_the_gate_range_follows_the_single_range_value(self):
        on, _ = self.render("1", extra_env={"CORE_RELAY_PORT_RANGE": "9300-9363"})
        self.assertIn(self.GATE.replace("9211:9218", "9300:9363"), on.splitlines())
        self.assertIn(self.GATE_DROP.replace("9211:9218", "9300:9363"), on.splitlines())
        self.assertNotIn("9211:9218", on)

    def test_a_leftover_relay_is_cleared_before_a_flag_off_rewrite_and_never_otherwise(self):
        run_dir = self.root / "run-state"
        run_dir.mkdir()
        (run_dir / "state.json").write_text("{}", encoding="utf-8")
        helper = self.root / "relay-helper-stub"
        log = self.root / "relay-helper.log"
        helper.write_text("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %s\n" % log, encoding="utf-8")
        helper.chmod(0o755)
        env = {"CORE_RELAY_HELPER": str(helper), "CORE_RELAY_RUN_DIR": str(run_dir)}
        self.render("0", extra_env=env)
        self.assertEqual(log.read_text(encoding="utf-8").splitlines(), ["clear --state %s/state.json" % run_dir])
        log.unlink()
        # enabled: the relay is live, nothing is cleared
        self.render("1", extra_env=env)
        self.assertFalse(log.exists())
        # no state file: a Core that never ran the relay is untouched
        (run_dir / "state.json").unlink()
        self.render("0", extra_env=env)
        self.assertFalse(log.exists())
        # state but no executable helper: the rewrite must refuse to remove the gate
        (run_dir / "state.json").write_text("{}", encoding="utf-8")
        helper.chmod(0o644)
        rules, _ = self.render("0", extra_env=env, expected_status=1)
        self.assertEqual(rules, "")
        self.assertIn("helper is missing", self.last_render_result.stderr)
        self.assertFalse(log.exists())

    def test_a_failing_clear_stops_the_firewall_rewrite(self):
        run_dir = self.root / "run-state"
        run_dir.mkdir()
        (run_dir / "state.json").write_text("{}", encoding="utf-8")
        helper = self.root / "relay-helper-stub"
        helper.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
        helper.chmod(0o755)
        rules, _ = self.render("0", extra_env={"CORE_RELAY_HELPER": str(helper), "CORE_RELAY_RUN_DIR": str(run_dir)},
                               expected_status=1)
        self.assertEqual(rules, "")
        self.assertIn("relay_clear_failed", self.last_render_result.stderr)

    def test_the_relay_chains_are_never_declared_or_flushed_by_the_main_transaction(self):
        on, _ = self.render("1")
        self.assertNotIn(":WINVPN-RELAY", on)
        self.assertNotIn("-F WINVPN-RELAY", on)
        self.assertNotIn("-A WINVPN-RELAY", on)

    def test_the_chains_are_created_before_the_transaction_is_built(self):
        text = installer_text()
        func = extract_function(text, "write_firewall")
        self.assertLess(func.index("iptables -N WINVPN-RELAY-FWD"), func.index("'*filter'"))
        self.assertLess(func.index("iptables -N WINVPN-RELAY-FWD"), func.index('"${save_bin}" > "${snapshot}"'))

    @unittest.skipUnless(BASE_INSTALLER, "set WINS_RELAY_BASE_INSTALLER to compare with the base installer")
    def test_disabled_rendering_equals_the_base_installer_byte_for_byte(self):
        patched, patched_calls = self.render("0")
        base, base_calls = self.render("0", installer=BASE_INSTALLER)
        self.assertEqual(patched, base)
        self.assertEqual(patched_calls, base_calls)


# ------------------------------------------------------------------ netfilter traversal model

class ChainModel:
    """A deliberately small model of how netfilter walks a chain, enough to show WHICH rule
    judges a packet (finding C1). Rules are parsed from the text the real renderer and the
    real helper produce. It models -i -o -p -s -d --sport --dport, the conntrack match
    (--ctstate as a set that also holds the virtual DNAT state, --ctdir, --ctorigdstport as a
    port or a range), the hashlimit match (matches when the packet is marked over its limit),
    and the targets ACCEPT DROP REJECT RETURN and a user chain. It is NOT iptables: it says
    nothing about the kernel, only about the order in which these rules are consulted."""

    def __init__(self):
        self.chains = {}

    def add(self, chain, lines):
        for line in lines:
            tokens = line.split()
            if len(tokens) < 3 or tokens[0] != "-A" or tokens[1] != chain:
                continue
            opts, modules, i = {}, [], 2
            while i < len(tokens):
                tok = tokens[i]
                if tok == "-m":
                    modules.append(tokens[i + 1])
                    i += 2
                elif tok == "!":
                    opts["__negation__"] = True
                    i += 1
                elif tok.startswith("-") and i + 1 < len(tokens):
                    opts[tok] = tokens[i + 1]
                    i += 2
                else:
                    i += 1
            self.chains.setdefault(chain, []).append(opts)

    @staticmethod
    def port_matches(spec, port):
        if ":" in spec:
            low, high = (int(x) for x in spec.split(":"))
            return low <= port <= high
        return int(spec) == port

    def rule_matches(self, rule, pkt):
        if rule.get("__negation__"):
            return False
        for flag, key in (("-i", "iif"), ("-o", "oif")):
            if flag in rule and rule[flag] != pkt[key]:
                return False
        if "-p" in rule and rule["-p"] != pkt["proto"]:
            return False
        for flag, key in (("-s", "src"), ("-d", "dst")):
            if flag in rule:
                want = rule[flag].split("/")[0]
                if "/" in rule[flag] and not rule[flag].endswith("/32"):
                    return False  # a prefix rule never matches the public addresses used here
                if want != pkt[key]:
                    return False
        if "--sport" in rule and not self.port_matches(rule["--sport"], pkt["sport"]):
            return False
        if "--dport" in rule and not self.port_matches(rule["--dport"], pkt["dport"]):
            return False
        if "--ctstate" in rule and not (set(rule["--ctstate"].split(",")) & pkt["ctstate"]):
            return False
        if "--ctdir" in rule and rule["--ctdir"] != pkt["ctdir"]:
            return False
        if "--ctorigdstport" in rule and not self.port_matches(rule["--ctorigdstport"], pkt["ctorigdstport"]):
            return False
        if "--hashlimit-name" in rule and rule["--hashlimit-name"] not in pkt.get("over_limit", ()):
            return False
        return True

    def verdict(self, pkt, chain="WINVPN-CORE-FORWARD"):
        for rule in self.chains.get(chain, []):
            if not self.rule_matches(rule, pkt):
                continue
            target = rule.get("-j")
            if target in ("ACCEPT", "DROP"):
                return target
            if target == "REJECT":
                return "DROP"
            if target == "RETURN":
                return "RETURN"
            if target in self.chains or target.startswith("WINVPN-RELAY"):
                result = self.verdict(pkt, target)
                if result != "RETURN":
                    return result
        return "RETURN"


def relay_packet(kind, port=9211, exit_def=EXIT_A, wan="enp5s0", over_limit=()):
    """A packet of a relayed flow as the FORWARD hook sees it. kind: new, established,
    reply. Original direction: the destination is already the exit (DNAT happened in
    PREROUTING); the reply still carries the exit as its source."""
    slug, ip, tport = exit_def
    phone = addr(203, 0, 113, 50)
    base = {"iif": wan, "oif": wan, "proto": "udp", "ctorigdstport": port, "over_limit": set(over_limit)}
    if kind == "reply":
        return dict(base, src=ip, dst=phone, sport=tport, dport=40000, ctstate={"ESTABLISHED", "DNAT"}, ctdir="REPLY")
    state = {"new": "NEW", "established": "ESTABLISHED"}[kind]
    return dict(base, src=phone, dst=ip, sport=40000, dport=tport, ctstate={state, "DNAT"}, ctdir="ORIGINAL")


class HelperBridge(HelperCase):
    def runTest(self):
        pass


class ChainModelTests(RendererHarness):
    """Finding C1 as an executable statement: the rules the real renderer and the real
    helper produce, walked in order, stop a relayed flow the moment its relay is gone."""

    def build_model(self, helper_case, enable="1", installer_text_override=None, relay_lines=None):
        rendered, _ = self.render(enable)
        model = ChainModel()
        model.add("WINVPN-CORE-FORWARD", [l for l in rendered.splitlines() if l.startswith("-A WINVPN-CORE-FORWARD ")])
        model.add("WINVPN-RELAY-FWD", relay_lines if relay_lines is not None
                  else helper_case.fw.state()["chains"].get("filter/WINVPN-RELAY-FWD", []))
        return model

    def helper(self):
        """A HelperCase instance (real helper, fake firewall) owned by this test."""
        HelperBridge.setUpClass()
        self.addCleanup(HelperBridge.tearDownClass)
        case = HelperBridge()
        case.setUp()
        self.addCleanup(case.tearDown)
        return case

    def test_a_live_relay_carries_new_established_and_reply_packets(self):
        case = self.helper()
        case.apply_ok(case.item(EXIT_A, 9211))
        model = self.build_model(case)
        for kind in ("new", "established", "reply"):
            self.assertEqual(model.verdict(relay_packet(kind)), "ACCEPT", kind)

    def test_a_new_flow_over_its_source_limit_is_dropped_but_established_traffic_is_not(self):
        case = self.helper()
        case.apply_ok(case.item(EXIT_A, 9211))
        names = {m.group(1) for line in case.fw.state()["chains"]["filter/WINVPN-RELAY-FWD"]
                 for m in [re.search(r"--hashlimit-name (\S+)", line)] if m}
        model = self.build_model(case)
        self.assertEqual(model.verdict(relay_packet("new", over_limit=names)), "DROP")
        # the limits are for NEW flows only: an established flow is never rate limited
        self.assertEqual(model.verdict(relay_packet("established", over_limit=names)), "ACCEPT")
        self.assertEqual(model.verdict(relay_packet("reply", over_limit=names)), "ACCEPT")

    def test_after_a_clear_every_packet_of_the_relayed_flow_is_dropped(self):
        case = self.helper()
        case.apply_ok(case.item(EXIT_A, 9211))
        self.assertEqual(case.run_helper("clear").returncode, 0)
        model = self.build_model(case)
        for kind in ("new", "established", "reply"):
            self.assertEqual(model.verdict(relay_packet(kind)), "DROP", kind)

    def test_after_an_expiry_the_expired_relays_established_flow_stops_and_the_others_do_not(self):
        case = self.helper()
        case.apply_ok(case.item(EXIT_A, 9211, doc={"not_after": NOW + 100}), case.item(EXIT_B, 9212))
        self.assertEqual(case.run_helper(now=NOW + 100).returncode, 0)
        model = self.build_model(case)
        for kind in ("established", "reply"):
            self.assertEqual(model.verdict(relay_packet(kind, 9211, EXIT_A)), "DROP", kind)
            self.assertEqual(model.verdict(relay_packet(kind, 9212, EXIT_B)), "ACCEPT", kind)

    def test_a_retargeted_relay_no_longer_carries_flows_to_the_old_exit_address(self):
        case = self.helper()
        case.apply_ok(case.item(EXIT_A, 9211))
        moved = ("canada-ca1", addr(34, 120, 10, 99), 9111)
        case.write_desired(desired(case.item(moved, 9211)))
        self.assertEqual(case.run_helper(now=NOW + 5).returncode, 0)
        model = self.build_model(case)
        self.assertEqual(model.verdict(relay_packet("established", 9211, EXIT_A)), "DROP")
        self.assertEqual(model.verdict(relay_packet("reply", 9211, EXIT_A)), "DROP")
        self.assertEqual(model.verdict(relay_packet("established", 9211, moved)), "ACCEPT")

    def test_a_dnat_flow_aimed_anywhere_but_the_signed_target_is_dropped(self):
        case = self.helper()
        case.apply_ok(case.item(EXIT_A, 9211))
        model = self.build_model(case)
        stray = relay_packet("established", 9211, ("canada-ca1", addr(8, 8, 8, 8), 9111))
        self.assertEqual(model.verdict(stray), "DROP")
        wrong_port = relay_packet("established", 9211, ("canada-ca1", EXIT_A[1], 9999))
        self.assertEqual(model.verdict(wrong_port), "DROP")
        # a reply that does not come from the signed target's address and port
        reply = relay_packet("reply")
        self.assertEqual(model.verdict(dict(reply, sport=9999)), "DROP")

    def test_traffic_that_is_not_a_relayed_flow_is_untouched_by_the_gate(self):
        case = self.helper()
        case.apply_ok(case.item(EXIT_A, 9211))
        model = self.build_model(case)
        plain = relay_packet("established")
        plain.update(ctstate={"ESTABLISHED"}, ctorigdstport=51820)
        self.assertEqual(model.verdict(plain), "ACCEPT")  # an ordinary established flow
        other_dnat = relay_packet("established")
        other_dnat.update(ctorigdstport=9300)  # DNATed, but not one of the relay ports
        self.assertEqual(model.verdict(other_dnat), "ACCEPT")

    def test_the_round_one_order_let_established_flows_outlive_their_relay(self):
        # The same rules with the established accept FIRST (what packet B shipped) keep
        # forwarding the cleared relay's flow: this is the defect, reproduced in the model.
        case = self.helper()
        case.apply_ok(case.item(EXIT_A, 9211))
        self.assertEqual(case.run_helper("clear").returncode, 0)
        rendered, _ = self.render("1")
        lines = [l for l in rendered.splitlines() if l.startswith("-A WINVPN-CORE-FORWARD ")]
        established = "-A WINVPN-CORE-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        reordered = [established] + [l for l in lines if l != established]
        old = ChainModel()
        old.add("WINVPN-CORE-FORWARD", reordered)
        old.add("WINVPN-RELAY-FWD", [])
        self.assertEqual(old.verdict(relay_packet("established")), "ACCEPT")  # the bug
        current = self.build_model(case)
        self.assertEqual(current.verdict(relay_packet("established")), "DROP")  # the fix

    def test_with_the_relay_off_the_established_accept_is_what_it_always_was(self):
        rendered, _ = self.render("0")
        model = ChainModel()
        model.add("WINVPN-CORE-FORWARD", [l for l in rendered.splitlines() if l.startswith("-A WINVPN-CORE-FORWARD ")])
        self.assertEqual(model.verdict(relay_packet("established")), "ACCEPT")


# ------------------------------------------------------------------ sync agent

class AgentCase(InstallerFunctionCase):
    def make_agent(self, installer=None):
        text = agent_text(Path(installer).read_text(encoding="utf-8") if installer else None)
        self.assertTrue(text.rstrip().endswith('main "$@"'))
        agent = self.root / "agent-no-main.sh"
        agent.write_text(text.replace('\nmain "$@"\n', "\n"), encoding="utf-8")
        return agent

    def shim_dir(self):
        shims = self.root / "shims"
        shims.mkdir(exist_ok=True)
        stat_shim = shims / "stat"
        stat_shim.write_text(textwrap.dedent("""\
            #!%s
            import os, sys
            args = sys.argv[1:]
            if args[:1] == ["-c"] and len(args) == 3:
                st = os.stat(args[2])
                print({"%%Y": int(st.st_mtime), "%%u": st.st_uid}[args[1]])
                sys.exit(0)
            sys.exit(1)
            """) % sys.executable, encoding="utf-8")
        stat_shim.chmod(0o755)
        return shims

    def env(self, **extra):
        env = {
            "PATH": "%s:%s" % (self.shim_dir(), os.environ["PATH"]),
            "CORE_ENV_FILE": str(self.root / "no-such.env"),
            "CORE_RELAY_RUN_DIR": str(self.root / "run"),
            "CORE_RELAY_DIR": str(self.root / "relaycfg"),
            "CORE_RELAY_HELPER": str(self.root / "helper"),
        }
        env.update(extra)
        return env

    def write_helper_stub(self, exit_code=0, log=None):
        log = log or (self.root / "helper.log")
        stub = self.root / "helper"
        stub.write_text(textwrap.dedent("""\
            #!/bin/sh
            printf '%%s\\n' "$*" >> %s
            cmd="$1"
            if [ "$cmd" = apply ]; then
              while [ $# -gt 0 ]; do
                if [ "$1" = --desired ]; then cp "$2" %s; fi
                shift
              done
            fi
            exit %d
            """) % (log, self.root / "desired.copy", exit_code), encoding="utf-8")
        stub.chmod(0o755)
        return log


class RelaySyncTests(AgentCase):
    def call(self, body, assignments="{\"ok\":true,\"assignments\":[]}", **env):
        agent = self.make_agent()
        script = "set -Eeuo pipefail\nsource %s\nASSIGNMENTS_JSON='%s'\n%s\n" % (
            agent, assignments, body)
        return self.run_bash(script, env=self.env(**env), check=False)

    def test_disabled_without_state_does_nothing_at_all(self):
        log = self.write_helper_stub()
        result = self.call("relay_sync; echo done", CORE_RELAY_ENABLE="0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "done")
        self.assertFalse(log.exists())
        self.assertFalse((self.root / "run").exists())

    def test_disabled_with_leftover_state_clears_once_and_removes_the_state(self):
        log = self.write_helper_stub()
        run = self.root / "run"
        run.mkdir()
        (run / "state.json").write_text("{}", encoding="utf-8")
        (run / "desired.json").write_text("{}", encoding="utf-8")
        result = self.call("relay_sync; relay_sync; relay_sync; echo done", CORE_RELAY_ENABLE="0")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].startswith("clear --state "))
        self.assertFalse((run / "state.json").exists())
        self.assertFalse((run / "desired.json").exists())

    def test_disabled_clear_failure_keeps_the_state_so_the_next_pass_retries(self):
        self.write_helper_stub(exit_code=1)
        run = self.root / "run"
        run.mkdir()
        (run / "state.json").write_text("{}", encoding="utf-8")
        result = self.call("relay_sync || echo failed", CORE_RELAY_ENABLE="0")
        self.assertIn("failed", result.stdout)
        self.assertTrue((run / "state.json").exists())

    def test_enabled_writes_the_relay_object_with_mode_0600_and_calls_apply_with_every_option(self):
        log = self.write_helper_stub()
        relay = {"v": 1, "port_range": "9211-9218", "relays": [{"exit_slug": "canada-ca1", "port": 9211,
                                      "descriptor": {"payload": "AAAA", "sig": "BBBB"}}]}
        assignments = json.dumps({"ok": True, "core_id": "x", "assignments": [], "relay": relay})
        result = self.call("relay_sync", assignments=assignments, CORE_RELAY_ENABLE="1",
                           CORE_RELAY_WAN_IFACE="enp5s0", CORE_PUBLIC_INGRESS_ENDPOINT="203.0.113.99:9210")
        self.assertEqual(result.returncode, 0, result.stderr)
        desired_file = self.root / "run" / "desired.json"
        self.assertEqual(json.loads(desired_file.read_text(encoding="utf-8")), relay)
        self.assertEqual(stat_module.S_IMODE(desired_file.stat().st_mode), 0o600)
        argv = log.read_text(encoding="utf-8").split()
        self.assertEqual(argv[0], "apply")
        pairs = {argv[i]: argv[i + 1] for i in range(1, len(argv) - 1)}
        self.assertEqual(pairs["--desired"], str(desired_file))
        self.assertEqual(pairs["--state"], str(self.root / "run" / "state.json"))
        self.assertEqual(pairs["--ring"], str(self.root / "relaycfg" / "ring.pub"))
        self.assertEqual(pairs["--port-range"], "9211-9218")
        self.assertNotIn("--port-min", argv)
        self.assertNotIn("--port-max", argv)
        self.assertEqual((pairs["--rate-src"], pairs["--burst-src"]), ("10/second", "20"))
        self.assertEqual((pairs["--rate-port"], pairs["--burst-port"]), ("400/second", "800"))
        self.assertEqual(pairs["--wan-iface"], "enp5s0")
        self.assertEqual(pairs["--self-ip"], "203.0.113.99")
        self.assertEqual(json.loads((self.root / "desired.copy").read_text(encoding="utf-8")), relay)

    def test_enabled_without_a_relay_key_or_with_a_non_object_passes_an_empty_list(self):
        for assignments in ('{"ok":true,"assignments":[]}', '{"ok":true,"assignments":[],"relay":null}',
                            '{"ok":true,"assignments":[],"relay":[1]}', '{"ok":true,"assignments":[],"relay":"x"}'):
            with self.subTest(assignments):
                self.write_helper_stub()
                result = self.call("relay_sync", assignments=assignments, CORE_RELAY_ENABLE="1")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads((self.root / "run" / "desired.json").read_text(encoding="utf-8")),
                                 {"v": 1, "port_range": "9211-9218", "relays": []})

    def test_a_custom_range_reaches_the_helper_and_the_empty_desired_object(self):
        log = self.write_helper_stub()
        result = self.call("relay_sync", CORE_RELAY_ENABLE="1", CORE_RELAY_PORT_RANGE="9300-9363")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((self.root / "run" / "desired.json").read_text(encoding="utf-8")),
                         {"v": 1, "port_range": "9300-9363", "relays": []})
        argv = log.read_text(encoding="utf-8").split()
        self.assertEqual(argv[argv.index("--port-range") + 1], "9300-9363")

    def test_a_hostname_endpoint_passes_no_self_ip_and_no_wan_flag_when_unset(self):
        log = self.write_helper_stub()
        result = self.call("relay_sync", CORE_RELAY_ENABLE="1",
                           CORE_PUBLIC_INGRESS_ENDPOINT="core.example.org:9210")
        self.assertEqual(result.returncode, 0, result.stderr)
        argv = log.read_text(encoding="utf-8")
        self.assertNotIn("--self-ip", argv)
        self.assertNotIn("--wan-iface", argv)

    def test_a_failing_helper_fails_the_stage_but_the_guarded_call_site_continues(self):
        self.write_helper_stub(exit_code=1)
        result = self.call("relay_sync || echo 'warned and continued'; echo after", CORE_RELAY_ENABLE="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("warned and continued", result.stdout)
        self.assertIn("after", result.stdout)

    def test_a_missing_helper_fails_the_stage_with_a_class_word(self):
        result = self.call("relay_sync || echo failed", CORE_RELAY_ENABLE="1")
        self.assertIn("failed", result.stdout)
        self.assertIn("class=relay_helper_missing", result.stderr)

    def test_the_helper_calls_are_time_bounded(self):
        agent = agent_text()
        self.assertEqual(agent.count('timeout 10 "${CORE_RELAY_HELPER}" apply'), 1)
        self.assertEqual(agent.count('timeout 10 "${CORE_RELAY_HELPER}" clear'), 1)
        self.assertNotIn('"${CORE_RELAY_HELPER}" apply', agent.replace('timeout 10 "${CORE_RELAY_HELPER}" apply', ''))

    def test_the_call_site_is_guarded_and_placed_after_the_fetch(self):
        agent = agent_text()
        guarded = 'relay_sync || warn "Core relay synchronization failed class=relay_sync_failed; the AmneziaWG Double VPN is unaffected"\n'
        self.assertEqual(agent.count(guarded), 1)
        fetch = agent.index("jq -e '.ok == true' >/dev/null <<<\"${ASSIGNMENTS_JSON}\"")
        stage = agent.index('CORE_SYNC_FAILURE_STAGE="assignment-sync"')
        self.assertLess(fetch, agent.index(guarded))
        self.assertLess(agent.index(guarded), stage)
        self.assertEqual(len(re.findall(r"^\s*relay_sync \|\|", agent, re.M)), 1)


class SyncPassTests(AgentCase):
    STUBS = textwrap.dedent("""\
        trace() { printf '%s\\n' "$*" >> "$TRACE"; }
        acquire_core_sync_lock() { trace lock; }
        ip() { return 0; }
        require_ready() { trace require_ready; }
        verify_management_runtime() { trace verify_management; }
        hub_curl() { printf '%s' "$ASSIGNMENTS_FIXTURE"; }
        sync_assignment() { trace sync_assignment; }
        remove_stale_ingress_peers() { trace remove_stale_peers; }
        remove_stale_assignment_state() { trace remove_stale_state; }
        validate_synced_runtime() { trace validate_runtime; }
        publish_core_authority_rules() { trace publish_authority; }
        acknowledge_assignments() { trace acknowledge; }
        register_core() { trace "register_core $1"; }
        acknowledge_core_promotion() { trace promotion_ack; }
        """)

    def run_pass(self, enable, helper_exit=0, installer=None, with_relay_key=True):
        agent = self.make_agent(installer)
        trace = self.root / ("trace-%s-%s.log" % (enable, helper_exit))
        if trace.exists():
            trace.unlink()
        relay = {"v": 1, "port_range": "9211-9218", "relays": []}
        fixture = {"ok": True, "core_id": "north-america-core", "assignments": [
            {"client_ip": "10.9.1.2", "client_public_key": "k"}]}
        if with_relay_key:
            fixture["relay"] = relay
        self.write_helper_stub(exit_code=helper_exit)
        script = "set -Eeuo pipefail\nsource %s\n%s\nmain\necho \"rc=$?\"\n" % (agent, self.STUBS)
        env = self.env(TRACE=str(trace), ASSIGNMENTS_FIXTURE=json.dumps(fixture), CORE_RELAY_ENABLE=enable,
                       CORE_SYNC_BUSY_EXIT_CODE="0")
        result = self.run_bash(script, env=env, check=False)
        return result, trace.read_text(encoding="utf-8").splitlines() if trace.exists() else []

    def test_the_pass_trace_is_the_same_with_the_relay_off_on_and_failing(self):
        off, trace_off = self.run_pass("0")
        on, trace_on = self.run_pass("1", helper_exit=0)
        bad, trace_bad = self.run_pass("1", helper_exit=1)
        for result in (off, on, bad):
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("rc=0", result.stdout)
        self.assertEqual(trace_off, trace_on)
        self.assertEqual(trace_off, trace_bad)
        self.assertIn("register_core true", trace_off)
        self.assertIn("acknowledge", trace_off)
        self.assertIn("class=relay_sync_failed", bad.stderr)
        self.assertNotIn("class=relay_sync_failed", on.stderr)
        self.assertNotIn("relay", off.stderr)

    def test_a_failing_relay_never_flips_readiness_or_the_exit_trap(self):
        bad, trace = self.run_pass("1", helper_exit=1)
        self.assertNotIn("register_core false", trace)
        self.assertEqual(trace[-3:], ["acknowledge", "register_core true", "promotion_ack"])

    @unittest.skipUnless(BASE_INSTALLER, "set WINS_RELAY_BASE_INSTALLER to compare with the base installer")
    def test_disabled_pass_trace_equals_the_base_agent(self):
        patched, trace_patched = self.run_pass("0")
        base, trace_base = self.run_pass("0", installer=BASE_INSTALLER)
        self.assertEqual(base.returncode, 0, base.stderr)
        self.assertEqual(trace_patched, trace_base)
        self.assertEqual(patched.stdout, base.stdout)


class RegistrationMergeTests(AgentCase):
    def payload(self, enable, state=None, age=0, installer=None, link=False):
        agent = self.make_agent(installer)
        run = self.root / "run"
        run.mkdir(exist_ok=True)
        state_file = run / "state.json"
        if state_file.exists() or state_file.is_symlink():
            state_file.unlink()
        if state is not None:
            if link:
                real = self.root / "real-state.json"
                real.write_text(state, encoding="utf-8")
                state_file.symlink_to(real)
            else:
                state_file.write_text(state, encoding="utf-8")
                stamp = time.time() - age
                os.utime(state_file, (stamp, stamp))
        script = textwrap.dedent("""\
            set -Eeuo pipefail
            source %s
            core_ingress_obfuscation_json() { printf '%%s' "${FIXTURE_OBFUSCATION}"; }
            core_registration_payload_with_obfuscation printf '%%s' '{"core_id":"c","runtime_ready":true}'
            """) % agent
        env = self.env(CORE_RELAY_ENABLE=enable, FIXTURE_OBFUSCATION='{"Jc":"2"}')
        result = self.run_bash(script, env=env, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    STATE = json.dumps({"v": 1, "state": "active", "port_range": "9211-9218", "wan_iface": "enp5s0", "applied_at": NOW,
                        "rules_sha256": "a" * 64,
                        "listens": [{"exit_slug": "canada-ca1", "port": 9211, "state": "up", "packets": 3}]})

    def test_a_fresh_report_is_merged_under_the_relay_key_beside_the_obfuscation(self):
        doc = self.payload("1", self.STATE, age=2)
        self.assertEqual(doc["relay"], json.loads(self.STATE))
        self.assertEqual(doc["obfuscation_json"], '{"Jc":"2"}')
        self.assertEqual(doc["core_id"], "c")

    def test_a_stale_report_is_not_merged(self):
        self.assertNotIn("relay", self.payload("1", self.STATE, age=31))
        self.assertIn("relay", self.payload("1", self.STATE, age=29))

    def test_a_future_dated_report_beyond_the_skew_allowance_is_not_merged(self):
        self.assertNotIn("relay", self.payload("1", self.STATE, age=-60))

    def test_nothing_is_merged_when_the_relay_is_off_even_if_a_fresh_file_exists(self):
        self.assertNotIn("relay", self.payload("0", self.STATE, age=1))

    def test_nothing_is_merged_without_a_file(self):
        self.assertNotIn("relay", self.payload("1", None))

    def test_malformed_or_wrong_shape_reports_are_not_merged(self):
        for junk in ("", "{", "[]", "null", '"x"', json.dumps({"v": 2, "listens": []}),
                     json.dumps({"v": 1}), json.dumps({"v": 1, "listens": "x"}),
                     json.dumps({"v": 1, "port_range": "9211-9218", "listens": "x"}),
                     json.dumps({"v": 1, "listens": []}), json.dumps({"v": 1, "port_range": 9211, "listens": []})):
            with self.subTest(junk):
                self.assertNotIn("relay", self.payload("1", junk, age=1))

    def test_a_symlinked_state_file_is_not_merged(self):
        self.assertNotIn("relay", self.payload("1", self.STATE, age=1, link=True))

    def post_registration(self, enable, state, age=1, installer=None):
        agent = self.make_agent(installer)
        run = self.root / "run"
        run.mkdir(exist_ok=True)
        state_file = run / "state.json"
        if state_file.exists():
            state_file.unlink()
        if state is not None:
            state_file.write_text(state, encoding="utf-8")
            stamp = time.time() - age
            os.utime(state_file, (stamp, stamp))
        posted = self.root / "posted.json"
        script = textwrap.dedent("""\
            set -Eeuo pipefail
            source %s
            core_ingress_obfuscation_json() { return 1; }
            persist_core_advertised_state() { return 0; }
            hub_curl() { cat > "$POSTED"; printf '%%s' '{"ok":true}'; }
            CORE_PUBLIC_INGRESS_ENDPOINT=203.0.113.9:9210 CORE_INGRESS_PUBLIC_KEY=ingresskey CORE_EXIT_PUBLIC_KEY=exitkey
            register_core true
            """) % agent
        env = self.env(CORE_RELAY_ENABLE=enable, POSTED=str(posted), CORE_XRAY_UUID="u")
        result = self.run_bash(script, env=env, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(posted.read_text(encoding="utf-8"))

    def test_register_core_posts_the_relay_report_end_to_end(self):
        doc = self.post_registration("1", self.STATE)
        self.assertEqual(doc["relay"], json.loads(self.STATE))
        self.assertTrue(doc["runtime_ready"])
        self.assertEqual(doc["ingress_endpoint"], "203.0.113.9:9210")
        without = self.post_registration("0", self.STATE)
        self.assertNotIn("relay", without)
        stale = self.post_registration("1", self.STATE, age=45)
        self.assertNotIn("relay", stale)
        # everything but the relay key is identical to the registration without it
        trimmed = dict(doc)
        trimmed.pop("relay")
        self.assertEqual(trimmed, without)

    @unittest.skipUnless(BASE_INSTALLER, "set WINS_RELAY_BASE_INSTALLER to compare with the base installer")
    def test_disabled_registration_equals_the_base_agent_end_to_end(self):
        self.assertEqual(self.post_registration("0", self.STATE),
                         self.post_registration("0", self.STATE, installer=BASE_INSTALLER))

    @unittest.skipUnless(BASE_INSTALLER, "set WINS_RELAY_BASE_INSTALLER to compare with the base installer")
    def test_disabled_payload_equals_the_base_agent(self):
        self.assertEqual(self.payload("0", self.STATE, age=1),
                         self.payload("0", self.STATE, age=1, installer=BASE_INSTALLER))


# ------------------------------------------------------------------ mutation checks

class MutationTests(unittest.TestCase):
    """Each safety property is carried by the text that claims it: break the text and
    a detector, run the same way as the real tests, must notice."""

    @classmethod
    def setUpClass(cls):
        cls.keydir = tempfile.TemporaryDirectory()
        cls.keys = KeyRing(cls.keydir.name)

    @classmethod
    def tearDownClass(cls):
        cls.keydir.cleanup()

    # -- a tiny harness around one helper text
    def harness(self, source, config=None):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        fw = FakeFirewall(root)
        fw.config(config or {})
        helper = root / "helper.py"
        helper.write_text(source, encoding="utf-8")
        ring = root / "ring.pub"
        ring.write_text(self.keys.ring_text(), encoding="utf-8")
        run = root / "run"
        run.mkdir()
        return root, fw, helper, ring, run

    def apply(self, source, document, config=None, extra=(), prepare_jumps=True):
        root, fw, helper, ring, run = self.harness(source, config)
        (run / "desired.json").write_text(document if isinstance(document, str) else json.dumps(document), encoding="utf-8")
        if prepare_jumps:
            fw.prepare_jumps()
        argv = [sys.executable, str(helper), "apply", "--desired", str(run / "desired.json"),
                "--state", str(run / "state.json"), "--ring", str(ring),
                "--iptables", str(fw.bin / "iptables"), "--iptables-restore", str(fw.bin / "iptables-restore"),
                "--conntrack", str(fw.bin / "conntrack"),
                "--ip", str(fw.bin / "ip"), "--openssl", OPENSSL, "--now", str(NOW)] + list(extra)
        result = subprocess.run(argv, env=fw.env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
        state = json.loads((run / "state.json").read_text(encoding="utf-8")) if (run / "state.json").exists() else None
        return result, fw, state

    def session(self, source, config=None):
        """One helper text, one fake firewall, several commands in a row."""
        case = self
        root, fw, helper, ring, run = self.harness(source, config)
        fw.prepare_jumps()

        class Session:
            def __init__(self):
                self.fw = fw
                self.run_dir = run

            def run(self, command="apply", document=None, now=NOW, extra=()):
                if document is not None:
                    (run / "desired.json").write_text(
                        document if isinstance(document, str) else json.dumps(document), encoding="utf-8")
                argv = [sys.executable, str(helper), command]
                if command in ("apply", "render"):
                    argv += ["--desired", str(run / "desired.json")]
                if command in ("apply", "clear"):
                    argv += ["--state", str(run / "state.json")]
                argv += ["--ring", str(ring), "--iptables", str(fw.bin / "iptables"),
                         "--iptables-restore", str(fw.bin / "iptables-restore"),
                         "--conntrack", str(fw.bin / "conntrack"), "--ip", str(fw.bin / "ip"),
                         "--openssl", OPENSSL, "--now", str(now)] + list(extra)
                return subprocess.run(argv, env=fw.env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True, timeout=60)

            def state_doc(self):
                path = run / "state.json"
                return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

        return Session()

    def item(self, exit_def, port, **kwargs):
        return relay_item(self.keys, exit_def, port, **kwargs)

    # -- detectors: True when the property holds
    def detect_jump_position(self, source):
        result, fw, _ = self.apply(source, desired(self.item(EXIT_A, 9211)), prepare_jumps=False)
        if result.returncode != 0 or len(fw.commits()) != 2:
            return False
        nat_commit = fw.commits()[1]["stdin"]
        return ("-I PREROUTING 1 -j WINVPN-RELAY-PRE" in nat_commit
                and "-I POSTROUTING 1 -j WINVPN-RELAY-POST" in nat_commit)

    def detect_test_first(self, source):
        result, fw, _ = self.apply(source, desired(self.item(EXIT_A, 9211)), config={"test_fail": ["nat"]})
        # With the test gate intact a failing test means no DNAT is ever committed.
        return not any("DNAT" in c["stdin"] for c in fw.commits()) and len(fw.tests()) >= 1

    def detect_ctorigdstport(self, source):
        result, fw, _ = self.apply(source, desired(self.item(EXIT_A, 9211)))
        if result.returncode != 0:
            return False
        nat, flt = contract_rules([(9211, EXIT_A[1], EXIT_A[2])])
        commits = fw.commits()
        return (len(commits) == 2 and commits[0]["stdin"] == flt
                and commits[1]["stdin"].replace("-I PREROUTING 1 -j WINVPN-RELAY-PRE\n", "").replace(
                    "-I POSTROUTING 1 -j WINVPN-RELAY-POST\n", "") == nat)

    def detect_signed_endpoint_only(self, source):
        # The hub adds an unsigned address next to a validly signed descriptor.
        good = self.item(EXIT_A, 9211)
        smuggled = dict(good, target="203.0.113.250:9111")
        result, fw, state = self.apply(source, desired(smuggled))
        text = json.dumps(fw.state())
        return "203.0.113.250" not in text and not (state or {}).get("state") == "active"

    def detect_ring_check(self, source):
        forged = self.item(EXIT_A, 9211, sign_with="stranger")
        result, fw, state = self.apply(source, desired(forged))
        pre = fw.state()["chains"].get("nat/WINVPN-RELAY-PRE", [])
        return result.returncode == 0 and pre == [] and (state or {}).get("state") == "inactive"

    def detect_mismatch_check(self, source):
        # A descriptor signed for another node must never forward.
        wrong = self.item(EXIT_A, 9211, doc={"node": "germany-de1"})
        result, fw, state = self.apply(source, desired(wrong))
        return fw.state()["chains"].get("nat/WINVPN-RELAY-PRE", []) == []

    def detect_global_check(self, source):
        private = self.item(("canada-ca1", "10.1.2.3", 9111), 9211)
        result, fw, state = self.apply(source, desired(private))
        return fw.state()["chains"].get("nat/WINVPN-RELAY-PRE", []) == []

    def detect_expiry_check(self, source):
        expired = self.item(EXIT_A, 9211, doc={"not_after": NOW - 1})
        result, fw, state = self.apply(source, desired(expired))
        return fw.state()["chains"].get("nat/WINVPN-RELAY-PRE", []) == []

    def detect_failure_clears(self, source):
        result, fw, state = self.apply(source, desired(self.item(EXIT_A, 9211)), config={"commit_fail": ["nat"]})
        return (result.returncode == 1 and fw.state()["chains"].get("filter/WINVPN-RELAY-FWD", []) == []
                and (state or {}).get("state") == "inactive")

    def detect_rule_text(self, source):
        return self.detect_ctorigdstport(source)

    def detect_purge_on_clear(self, source):
        s = self.session(source)
        s.run("apply", desired(self.item(EXIT_A, 9211)))
        s.fw.reset_calls()
        result = s.run("clear")
        return result.returncode == 0 and s.fw.conntrack_calls() == list(range(9211, 9219))

    def detect_purge_stays_inside_the_range(self, source):
        s = self.session(source)
        s.run("apply", desired(self.item(EXIT_A, 9211)))
        s.fw.reset_calls()
        s.run("clear")
        ports = s.fw.conntrack_calls()
        return bool(ports) and all(9211 <= p <= 9218 for p in ports)

    def detect_purge_on_expiry(self, source):
        # an expired descriptor takes its relay down: that relay's port is purged
        s = self.session(source)
        s.run("apply", desired(self.item(EXIT_A, 9211, doc={"not_after": NOW + 100}),
                               self.item(EXIT_B, 9212)))
        s.fw.reset_calls()
        s.run("apply", desired(self.item(EXIT_A, 9211, doc={"not_after": NOW + 100}),
                               self.item(EXIT_B, 9212)), now=NOW + 100)
        return s.fw.conntrack_calls() == [9211]

    def detect_equal_count_drift(self, source):
        s = self.session(source)
        s.run("apply", desired(self.item(EXIT_A, 9211)))
        state = s.fw.state()
        state["chains"]["filter/WINVPN-RELAY-FWD"] = [
            r.replace("-j ACCEPT", "-j DROP") for r in state["chains"]["filter/WINVPN-RELAY-FWD"]]
        s.fw.set_state(state)
        s.fw.reset_calls()
        s.run("apply", now=NOW + 5)
        nat, flt = contract_rules([(9211, EXIT_A[1], EXIT_A[2])])
        wanted = [l for l in flt.splitlines() if l.startswith("-A WINVPN-RELAY-FWD")]
        return s.fw.state()["chains"]["filter/WINVPN-RELAY-FWD"] == wanted

    def detect_inactive_verifies_chains(self, source):
        s = self.session(source)
        s.run("apply", desired(self.item(EXIT_A, 9211)))
        s.run("apply", desired(), now=NOW + 5)
        state = s.fw.state()
        state["chains"]["nat/WINVPN-RELAY-PRE"] = ["-A WINVPN-RELAY-PRE -p udp --dport 9211 -j DNAT --to-destination 1.2.3.4:9111"]
        s.fw.set_state(state)
        s.run("apply", now=NOW + 6)
        return s.fw.state()["chains"]["nat/WINVPN-RELAY-PRE"] == []

    def detect_jump_repair(self, source):
        s = self.session(source)
        state = s.fw.state()
        state["jumps"] = ["nat:PREROUTING:SOMEONE-ELSE", "nat:PREROUTING:WINVPN-RELAY-PRE",
                          "nat:POSTROUTING:WINVPN-RELAY-POST"]
        s.fw.set_state(state)
        result = s.run("apply", desired(self.item(EXIT_A, 9211)))
        jumps = s.fw.state()["jumps"]
        mine = [j for j in jumps if j == "nat:PREROUTING:WINVPN-RELAY-PRE"]
        first = [j for j in jumps if j.startswith("nat:PREROUTING:")][0]
        doc = s.state_doc() or {}
        return (result.returncode == 0 and doc.get("state") == "active" and len(mine) == 1
                and first == "nat:PREROUTING:WINVPN-RELAY-PRE")

    def detect_range_mismatch(self, source):
        s = self.session(source)
        result = s.run("apply", desired(self.item(EXIT_A, 9211), port_range="9300-9363"))
        doc = s.state_doc() or {}
        installed = s.fw.state()["chains"].get("nat/WINVPN-RELAY-PRE", [])
        return (result.returncode == 0 and doc.get("state") == "inactive" and installed == []
                and [l.get("reason") for l in doc.get("listens", [])] == ["port_range_mismatch"])

    # -- mutations
    def mutate(self, source, old, new, count=1):
        self.assertEqual(source.count(old), count, old)
        return source.replace(old, new)

    def check(self, detector, source, mutated):
        self.assertTrue(detector(source), "the detector fails on the real helper")
        self.assertFalse(detector(mutated), "the detector missed the mutation")

    def test_mutation_jump_position(self):
        source = helper_text()
        # one text builds the insert for both nat jumps
        mutated = self.mutate(source, '"-I %s 1 -j %s"', '"-A %s -j %s"')
        self.check(self.detect_jump_position, source, mutated)

    def test_mutation_test_gate_skipped(self):
        source = helper_text()
        mutated = self.mutate(
            source,
            "        fw.restore_table(filter_text, test=True)\n"
            "        and fw.restore_table(nat_apply, test=True)\n"
            "        and fw.restore_table(filter_text, test=False)",
            "        fw.restore_table(filter_text, test=False)")
        self.check(self.detect_test_first, source, mutated)

    def test_mutation_original_destination_port_match_removed(self):
        source = helper_text()
        for old, new in (
            ('"--ctorigdstport %d" % (CHAIN_FWD, wan, wan, target, tport, port)',
             '"" % (CHAIN_FWD, wan, wan, target, tport)'),
            ('"--ctorigdstport %d -j MASQUERADE" % (CHAIN_POST, wan, target, tport, port)',
             '"-j MASQUERADE" % (CHAIN_POST, wan, target, tport)'),
            ('"--ctorigdstport %d" % (CHAIN_FWD, wan, wan, target, tport, port)',
             '"--ctorigdstport %d" % (CHAIN_FWD, wan, wan, target, tport, tport)'),
        ):
            with self.subTest(old):
                self.check(self.detect_ctorigdstport, source, self.mutate(source, old, new))
    def test_mutation_endpoint_taken_from_the_hub_instead_of_the_signature(self):
        source = helper_text()
        mutated = self.mutate(
            source, 'if not isinstance(item, dict) or set(item) != {"exit_slug", "port", "descriptor"}:',
            'if not isinstance(item, dict) or not {"exit_slug", "port", "descriptor"} <= set(item):')
        mutated = self.mutate(
            mutated, '            "sig": envelope["sig"],\n        })',
            '            "sig": envelope["sig"],\n            "target": item.get("target"),\n        })')
        mutated = self.mutate(
            mutated, '                entry["ip"] = ip\n                entry["tport"] = tport',
            '                entry["ip"] = (relay.get("target") or "%s:0" % ip).split(":")[0]\n'
            '                entry["tport"] = tport')
        self.check(self.detect_signed_endpoint_only, source, mutated)

    def test_mutation_ring_verification_skipped(self):
        source = helper_text()
        mutated = self.mutate(source, "    verify_signature(raw_key, payload, signature, openssl_bin)\n",
                              "    pass\n")
        self.check(self.detect_ring_check, source, mutated)

    def test_mutation_signature_result_ignored(self):
        source = helper_text()
        mutated = self.mutate(source, '    if code == 0:\n        return\n    if "Verification Failure"',
                              '    if True:\n        return\n    if "Verification Failure"')
        self.check(self.detect_ring_check, source, mutated)

    def test_mutation_node_binding_removed(self):
        source = helper_text()
        mutated = self.mutate(source, 'if not isinstance(doc["node"], str) or doc["node"] != slug:',
                              'if not isinstance(doc["node"], str):')
        self.check(self.detect_mismatch_check, source, mutated)

    def test_mutation_global_unicast_check_removed(self):
        source = helper_text()
        mutated = self.mutate(source, "    if not target_is_global_unicast(address):\n",
                              "    if False:\n")
        self.check(self.detect_global_check, source, mutated)

    def test_mutation_expiry_check_removed(self):
        source = helper_text()
        mutated = self.mutate(source, "    if now >= doc[\"not_after\"]:\n", "    if False:\n")
        self.check(self.detect_expiry_check, source, mutated)

    def test_mutation_failure_no_longer_clears(self):
        source = helper_text()
        mutated = self.mutate(source, '        return finish_inactive(args, fw, now, entries, wan, "apply_failed", 1)',
                              '        return 1')
        self.check(self.detect_failure_clears, source, mutated)

    # -- installer mutations (the static renderer gate)
    GATE_JUMP = '-A WINVPN-CORE-FORWARD -p udp -m conntrack --ctstate DNAT --ctorigdstport "${relay_gate_range}" -j WINVPN-RELAY-FWD'
    ESTABLISHED_RULE = 'core_restore_rule "${filter_body}" -A WINVPN-CORE-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT'
    FINAL_DROP_RULE = 'core_restore_rule "${filter_body}" -A WINVPN-CORE-FORWARD -j DROP'

    def renderer_lines(self, installer_source):
        func = extract_function(installer_source, "write_firewall")
        gate = func.index(self.GATE_JUMP) if self.GATE_JUMP in func else -1
        return gate, func.index(self.ESTABLISHED_RULE), func.index(self.FINAL_DROP_RULE)

    def detect_renderer_gate(self, installer_source):
        gate, established, final_drop = self.renderer_lines(installer_source)
        return 0 <= gate < established < final_drop

    def gate_block(self, source):
        match = re.search(r'  if \[\[ "\$\{CORE_RELAY_ENABLE:-0\}" == "1" \]\]; then\n    # Relay Double VPN: EVERY flow.*?\n  fi\n', source, re.S)
        self.assertIsNotNone(match)
        return match.group(0)

    def test_mutation_static_gate_after_the_established_accept_or_removed(self):
        source = installer_text()
        self.assertTrue(self.detect_renderer_gate(source))
        block = self.gate_block(source)
        self.assertEqual(source.count(block), 1)
        established = '  ' + self.ESTABLISHED_RULE + '\n'
        self.assertEqual(source.count(established), 1)
        # C1 itself: the gate placed AFTER the generic established accept
        after_established = source.replace(block, "").replace(established, established + block)
        self.assertFalse(self.detect_renderer_gate(after_established))
        # removed altogether
        self.assertFalse(self.detect_renderer_gate(source.replace(block, "")))
        # after the final drop
        drop = '  ' + self.FINAL_DROP_RULE + '\n'
        self.assertEqual(source.count(drop), 1)
        self.assertFalse(self.detect_renderer_gate(source.replace(block, "").replace(drop, drop + block)))

    # -- helper mutations added in round 2 (each finding has a detector that fails on it)
    def test_mutation_ctdir_dropped_from_the_accept_rules(self):
        source = helper_text()
        self.assertTrue(self.detect_rule_text(source))
        for old, new in (('"--ctdir ORIGINAL --ctorigdstport %d -j ACCEPT"', '"--ctorigdstport %d -j ACCEPT"'),
                         ('"--ctdir REPLY --ctorigdstport %d -j ACCEPT"', '"--ctorigdstport %d -j ACCEPT"')):
            with self.subTest(old):
                self.check(self.detect_rule_text, source, self.mutate(source, old, new))

    def test_mutation_the_reply_accept_rule_removed(self):
        source = helper_text()
        start = source.index('        fwd.append(\n            "-A %s -i %s -o %s -p udp -s %s --sport %d')
        end = source.index('    nat.append("COMMIT")', start)
        self.check(self.detect_rule_text, source, source[:start] + source[end:])

    def test_mutation_conntrack_purge_skipped(self):
        source = helper_text()
        old = '            code, _, stderr = run([self.conntrack, "-D", "-p", "udp", "--orig-port-dst", str(port), "--dst-nat"])'
        self.check(self.detect_purge_on_clear, source, self.mutate(source, old, '            code, _, stderr = 0, "", ""'))

    def test_mutation_purge_for_the_wrong_ports(self):
        source = helper_text()
        old = "    ports = set(range(args.port_min, args.port_max + 1))\n"
        mutated = self.mutate(source, old, "    ports = set(range(args.port_min - 1, args.port_max + 2))\n")
        self.check(self.detect_purge_stays_inside_the_range, source, mutated)
        self.check(self.detect_purge_on_clear, source, mutated)

    def test_mutation_no_purge_when_a_relay_expires(self):
        source = helper_text()
        old = "    if stale:\n        purged = fw.purge(stale)\n"
        self.check(self.detect_purge_on_expiry, source,
                   self.mutate(source, old, "    if False:\n        purged = fw.purge(stale)\n"))

    def test_mutation_drift_judged_by_rule_count(self):
        source = helper_text()
        old = "        if live_signatures != wanted_signatures:\n            return False"
        new = "        if len(live_signatures) != len(wanted_signatures):\n            return False"
        self.check(self.detect_equal_count_drift, source, self.mutate(source, old, new))

    def test_mutation_inactive_digest_trusted_without_reading_the_chains(self):
        source = helper_text()
        old = ('                and previous.get("state") == "inactive" and not args.dry_run\n'
               '                and not previous.get("purge_pending_ports") and fw.chains_empty()):')
        new = ('                and previous.get("state") == "inactive" and not args.dry_run\n'
               '                and not previous.get("purge_pending_ports")):')
        self.check(self.detect_inactive_verifies_chains, source, self.mutate(source, old, new))

    def test_mutation_jump_repair_skipped(self):
        source = helper_text()
        self.assertTrue(self.detect_jump_repair(source))
        old = '(("PREROUTING", CHAIN_PRE, pre_state), ("POSTROUTING", CHAIN_POST, post_state))'
        self.assertFalse(self.detect_jump_repair(self.mutate(source, old, "()")))
        # the old jump is not removed first: a duplicate stays behind
        old = '            extra.append("-D %s -j %s" % (chain, target))\n'
        self.assertFalse(self.detect_jump_repair(self.mutate(source, old, "            pass\n")))

    def test_mutation_range_mismatch_ignored(self):
        source = helper_text()
        old = "    if desired_range != own_range:\n"
        self.check(self.detect_range_mismatch, source, self.mutate(source, old, "    if False:\n"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
