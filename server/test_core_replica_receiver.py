#!/usr/bin/env python3
"""LSR (2026-10-02): the Core installer's optional Litestream replica receiver
(owner-approved for aicore).

The receiver is one unprivileged SFTP-only account plus an outbound reverse
forward to the hub. These tests run the SHIPPED bash extracted from
server/wins_core_server_setup_ONETOUCH.sh under Bash 4+, with every host
effect (useradd, getent, chown, install -o/-g, systemctl, sshd -T) faked and
every path redirected into a private temporary directory. Real `ssh-keygen`
makes the keys. Nothing is contacted and nothing on the host is changed.

  Inputs     validate_core_replica_receiver_inputs: off by default and then
             inert; when on, every input is checked before any mutation.
  sshd       harden_sshd adds exactly <user>@127.0.0.1 to AllowUsers when
             the receiver is on, and nothing when it is off.
  Receiver   install_core_replica_receiver: LUKS root required, or (fleet reset
             TP-C1, owner ruling 2026-10-08) the verified substitute posture
             with CORE_REPLICA_ALLOW_UNENCRYPTED_ROOT=1, warned every run; the account
             has no shell; ~/.ssh is root-owned; the one key line is
             restrict + from="127.0.0.1" + internal-sftp -d /data, and sshd
             confines the account with a Match User block (ChrootDirectory
             <home>, ForceCommand internal-sftp, nothing forwarded, no TTY);
             the hub host key is pinned; the reverse-forward unit holds no
             secret and no capability; reruns are idempotent; disabling
             stops the forward and deletes nothing.
  Verify     verify_core_replica_receiver reads the result back and refuses
             tampering.

Run:  python3 server/test_core_replica_receiver.py
      WINS_LSR_CORE_INSTALLER=/path/to/installer python3 server/test_core_replica_receiver.py
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

try:
    import _toolchain  # noqa: F401  (V-01 preflight)

    BASH = _toolchain.bash4()
except ModuleNotFoundError:
    BASH = os.environ.get("WINS_TEST_BASH") or shutil.which("bash") or "/bin/bash"

if hasattr(os, "geteuid") and os.geteuid() == 0:
    raise SystemExit("refusing to run as root: this suite must never be able to modify the host")

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path(os.environ.get("WINS_LSR_CORE_INSTALLER", str(ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh")))
SOURCE = SCRIPT.read_text(encoding="utf-8")
UNIT = "/etc/systemd/system/wins-core-replica-tunnel.service"

RECEIVER_FUNCS = (
    "core_replica_host_prerequisites",
    "core_replica_public_key_ok",
    "validate_core_replica_receiver_inputs",
    "core_replica_authorized_key_line",
    "core_replica_known_hosts_line",
    "core_replica_sshd_confined",
    "write_core_replica_tunnel_unit",
    "core_replica_install_file",
    "verify_core_replica_receiver",
    "install_core_replica_receiver",
)


def function_definition(name: str) -> str:
    signature = f"\n{name}() {{\n"
    # The installer's own main() is the LAST one: the generated sync agent
    # embeds another main() in a heredoc earlier in the file.
    start = SOURCE.rfind(signature) if name == "main" else SOURCE.find(signature)
    if start < 0:
        raise AssertionError(f"installer defines no function {name}")
    start += 1
    out = []
    terminator = None
    for line in SOURCE[start:].split("\n"):
        out.append(line)
        if terminator is not None:
            if line.strip("\t") == terminator:
                terminator = None
            continue
        if line == "}":
            return "\n".join(out)
        if "<<<" not in line and not line.lstrip().startswith("#"):
            match = re.search(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", line)
            if match:
                terminator = match.group(1)
    raise AssertionError(f"unterminated function {name}")


def optional_functions(*names: str) -> str:
    """Definitions for the names this installer has; absent ones become stubs
    that fail, so the suite runs (and fails on behaviour) against the tree
    before this change."""
    out = []
    for n in names:
        if f"\n{n}() {{\n" in SOURCE:
            out.append(function_definition(n))
        else:
            out.append(f"{n}() {{ echo 'MISSING FUNCTION {n}' >&2; return 97; }}")
    return "\n".join(out)


def run(script: str, env: dict | None = None) -> subprocess.CompletedProcess:
    base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp"), "LANG": "C"}
    if env:
        base.update(env)
    return subprocess.run([BASH, "-c", script], env=base, capture_output=True, text=True, timeout=120)


def write_fake(bin_dir: Path, name: str, body: str) -> Path:
    path = bin_dir / name
    path.write_text("#!/bin/bash\n" + textwrap.dedent(body), encoding="utf-8")
    path.chmod(0o755)
    return path


def keygen(path: Path, key_type: str = "ed25519") -> str:
    subprocess.run(["ssh-keygen", "-q", "-t", key_type, "-N", "", "-C", "lsr-core-test", "-f", str(path)],
                   check=True, capture_output=True)
    fields = Path(str(path) + ".pub").read_text().split()
    return f"{fields[0]} {fields[1]}"


_KEYDIR = Path(tempfile.mkdtemp(prefix="lsr-core-keys-"))
HUB_LITESTREAM = keygen(_KEYDIR / "hub_litestream")
HUB_HOST = keygen(_KEYDIR / "hub_host")
HUB_HOST_ECDSA = keygen(_KEYDIR / "hub_host_ecdsa", "ecdsa")

VALIDATION_HELPERS = ("valid_dns_hostname", "valid_port", "valid_absolute_path", "sshd_effective_value_is")

BASE_STUBS = r"""
log() { printf '[LOG] %s\n' "$*" >&2; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
err() { printf '[ERR] %s\n' "$*" >&2; }
"""


def good_inputs(**extra: str) -> dict:
    env = {
        "CORE_REPLICA_RECEIVER_ENABLED": "1",
        "CORE_REPLICA_USER": "wins-replica",
        "CORE_REPLICA_HOME": "/srv/wins-replica",
        "CORE_REPLICA_HUB_LITESTREAM_PUBLIC_KEY": HUB_LITESTREAM,
        "CORE_REPLICA_HUB_SSH_HOST": "",
        "CORE_AI_HUB_SSH_HOST": "hub-ssh.example.test",
        "CORE_REPLICA_HUB_SSH_PORT": "22",
        "CORE_REPLICA_HUB_SSH_USER": "wins-replica-tunnel",
        "CORE_REPLICA_HUB_HOST_KEY": HUB_HOST,
        "CORE_REPLICA_HUB_LISTEN_PORT": "2232",
        "CORE_REPLICA_TUNNEL_KEY": "/root/.ssh/wins_replica_tunnel_ed25519",
        "CORE_REPLICA_TUNNEL_KNOWN_HOSTS": "/root/.ssh/wins_replica_hub_known_hosts",
        "CORE_SSH_ADMIN_USER": "ubuntu",
    }
    env.update(extra)
    return env


# --------------------------------------------------------------------------
# Inputs
# --------------------------------------------------------------------------


class ReceiverInputs(unittest.TestCase):
    def validate(self, **extra: str) -> subprocess.CompletedProcess:
        script = f"""
set -Eeuo pipefail
{BASE_STUBS}
{optional_functions(*VALIDATION_HELPERS)}
{optional_functions(*RECEIVER_FUNCS)}
validate_core_replica_receiver_inputs
printf 'HOST=%s\\n' "${{CORE_REPLICA_HUB_SSH_HOST}}"
"""
        return run(script, env=good_inputs(**extra))

    def test_disabled_needs_nothing(self) -> None:
        r = self.validate(CORE_REPLICA_RECEIVER_ENABLED="0", CORE_REPLICA_USER="root",
                          CORE_REPLICA_HUB_LITESTREAM_PUBLIC_KEY="", CORE_REPLICA_HUB_HOST_KEY="")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_good_inputs_pass_and_the_hub_host_defaults_to_the_ai_tunnel_host(self) -> None:
        r = self.validate()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("HOST=hub-ssh.example.test", r.stdout)

    def test_explicit_hub_host_and_ecdsa_pin_pass(self) -> None:
        r = self.validate(CORE_REPLICA_HUB_SSH_HOST="ssh.hub.example.test", CORE_REPLICA_HUB_HOST_KEY=HUB_HOST_ECDSA)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("HOST=ssh.hub.example.test", r.stdout)

    def test_type_only_key_blobs_are_refused(self) -> None:
        # Sol N-4: a blob carrying only its SSH type string is not a key.
        import base64
        name = b"ecdsa-sha2-nistp256"
        bare = "ecdsa-sha2-nistp256 " + base64.b64encode(len(name).to_bytes(4, "big") + name).decode()
        for var in ("CORE_REPLICA_HUB_LITESTREAM_PUBLIC_KEY", "CORE_REPLICA_HUB_HOST_KEY"):
            r = self.validate(**{var: bare})
            self.assertNotEqual(r.returncode, 0, f"{var}: {r.stderr}")
            self.assertIn("not a complete public key", r.stderr)

    def test_bad_inputs_are_refused(self) -> None:
        kind, blob = HUB_LITESTREAM.split()
        cases = {
            "CORE_REPLICA_RECEIVER_ENABLED": ["2", "yes", ""],
            "CORE_REPLICA_USER": ["root", "ubuntu", "-x", "Wins", "a" * 33, ""],
            "CORE_REPLICA_HOME": ["/etc/wins-replica", "/srv", "/srv/a/b", "/home/wins", "srv/x", "/srv/../etc", "/var/lib/"],
            "CORE_REPLICA_HUB_LITESTREAM_PUBLIC_KEY": ["", f"ssh-rsa {blob}", f"{kind} {blob} hub", f"{kind} AAAA", HUB_HOST],
            "CORE_REPLICA_HUB_HOST_KEY": ["", f"{kind} {blob[:-3]}", "garbage"],
            "CORE_AI_HUB_SSH_HOST": ["", "198.51.100.7", "localhost"],
            "CORE_REPLICA_HUB_SSH_PORT": ["0", "70000", "22x", ""],
            "CORE_REPLICA_HUB_LISTEN_PORT": ["22", "1023", "70000", "2232x", ""],
            "CORE_REPLICA_HUB_SSH_USER": ["-oProxyCommand=x", "Root", ""],
            "CORE_REPLICA_TUNNEL_KEY": ["relative/key", "/root/../etc/key", "/root/.ssh/key with space"],
            "CORE_REPLICA_TUNNEL_KNOWN_HOSTS": ["known", "/root/.ssh/../../x"],
        }
        for name, values in cases.items():
            for value in values:
                r = self.validate(**{name: value})
                self.assertNotEqual(r.returncode, 0, f"{name}={value!r} was accepted: {r.stderr}")

    def test_preflight_validates_before_any_mutation(self) -> None:
        body = function_definition("preflight_core")
        self.assertIn("validate_core_replica_receiver_inputs || exit 1", body)

    def test_inputs_are_persisted_for_reruns(self) -> None:
        body = function_definition("load_or_create_env")
        for key in ("RECEIVER_ENABLED", "USER", "HOME", "HUB_LITESTREAM_PUBLIC_KEY", "HUB_SSH_HOST", "HUB_SSH_PORT",
                    "HUB_SSH_USER", "HUB_HOST_KEY", "HUB_LISTEN_PORT", "TUNNEL_KEY", "TUNNEL_KNOWN_HOSTS"):
            line = f"printf 'CORE_REPLICA_{key}=%q\\n' \"${{CORE_REPLICA_{key}}}\""
            self.assertIn(line, body, f"CORE_REPLICA_{key} is not persisted")

    def test_default_is_off(self) -> None:
        self.assertIn('CORE_REPLICA_RECEIVER_ENABLED="${CORE_REPLICA_RECEIVER_ENABLED:-0}"', SOURCE)

    def test_the_unencrypted_root_acceptance_is_zero_or_one_off_by_default_and_persisted(self) -> None:
        # Fleet reset TP-C1 (owner ruling 2026-10-08).
        self.assertIn('CORE_REPLICA_ALLOW_UNENCRYPTED_ROOT="${CORE_REPLICA_ALLOW_UNENCRYPTED_ROOT:-0}"', SOURCE)
        self.assertIn("printf 'CORE_REPLICA_ALLOW_UNENCRYPTED_ROOT=%q\\n' \"${CORE_REPLICA_ALLOW_UNENCRYPTED_ROOT}\"",
                      function_definition("load_or_create_env"))
        for value in ("0", "1"):
            r = self.validate(CORE_REPLICA_ALLOW_UNENCRYPTED_ROOT=value)
            self.assertEqual(r.returncode, 0, f"{value}: {r.stderr}")
        for value in ("2", "yes", "true"):
            r = self.validate(CORE_REPLICA_ALLOW_UNENCRYPTED_ROOT=value)
            self.assertNotEqual(r.returncode, 0, value)
            self.assertIn("CORE_REPLICA_ALLOW_UNENCRYPTED_ROOT must be 0 or 1", r.stderr)

    def test_tunnel_key_is_in_the_secret_permission_floor(self) -> None:
        body = function_definition("core_secret_path_specs")
        self.assertIn('"${CORE_REPLICA_TUNNEL_KEY:-/root/.ssh/wins_replica_tunnel_ed25519}|077|', body)

    def test_main_installs_the_receiver_once_after_ai_and_before_postflight(self) -> None:
        main = function_definition("main")
        calls = re.findall(r"^\s*install_core_replica_receiver\s*$", main, re.M)
        self.assertEqual(len(calls), 1)
        self.assertLess(main.index("\n  install_local_ai_support\n"), main.index("\n  install_core_replica_receiver\n"))
        self.assertLess(main.index("\n  install_core_replica_receiver\n"), main.index("\n  postflight_core\n"))
        self.assertLess(main.index("\n  install_core_replica_receiver\n"), main.index("\n  verify_core_secret_permissions\n"))

    def test_firewall_is_not_changed(self) -> None:
        self.assertNotIn("REPLICA", function_definition("write_firewall"))
        self.assertNotIn("REPLICA", function_definition("install_core_failure_hold_firewall"))


# --------------------------------------------------------------------------
# sshd AllowUsers
# --------------------------------------------------------------------------

SSHD_HARNESS = r'''
set -Eeuo pipefail
source "$1"
CAPTURE="$2"
install() {
  if [[ "${1:-}" == "-d" ]]; then return 0; fi
  if [[ "${*: -1}" == *"/20-wins-core.conf" ]]; then
    cp -- "${*: -2:1}" "$CAPTURE"
  fi
  return 0
}
prepare_core_ssh_authorized_keys() { :; }
ssh-keygen() { return 0; }
sshd() {
  case "${1:-}" in
    -t) return 0 ;;
    -T)
      printf 'port 22\npermitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\nallowtcpforwarding no\ndisableforwarding yes\n'
      for u in ${allow_users}; do printf 'allowusers %s\n' "$u"; done
      # For the receiver account, report the Match User block that the drop-in
      # really holds (keys lowercased like sshd -T), unless told to lose it.
      if [[ "$*" == *"user=${CORE_REPLICA_USER:-wins-replica},"* && "${FAKE_DROP_MATCH:-0}" != 1 && -f "$CAPTURE" ]]; then
        awk -v u="${CORE_REPLICA_USER:-wins-replica}" '
          $1 == "Match" { inblk = ($2 == "User" && $3 == u); next }
          inblk && NF >= 2 { k = tolower($1); $1 = ""; sub(/^ /, ""); print k " " $0 }' "$CAPTURE"
      fi
      ;;
  esac
}
systemctl() { return 0; }
mkdir() { return 0; }
fail2ban-client() { return 0; }
CORE_SSH_ADMIN_USER=myadmin
CORE_SSH_PASSWORD_AUTH=0
unset SUDO_USER
# As in test_wins_core_sshd_password_scope.py: the fail2ban jail write after
# the drop-in is not under test and cannot land on this host.
set +e
harden_sshd
printf 'RC=%s\n' "$?"
'''


class SshdAllowUsers(unittest.TestCase):
    def run_harden(self, enabled: str, **extra: str) -> tuple[subprocess.CompletedProcess, str]:
        with tempfile.TemporaryDirectory() as tmp:
            capture = Path(tmp) / "20-wins-core.conf"
            env = {"PATH": os.environ.get("PATH", ""), "HOME": tmp, "LANG": "C",
                   "CORE_REPLICA_RECEIVER_ENABLED": enabled, "CORE_REPLICA_USER": "wins-replica",
                   "CORE_REPLICA_HOME": "/srv/wins-replica"}
            env.update(extra)
            proc = subprocess.run(
                [BASH, "-c", SSHD_HARNESS, "_", str(SCRIPT), str(capture)],
                env=env, capture_output=True, text=True, timeout=120,
            )
            return proc, (capture.read_text() if capture.exists() else "")

    def harden(self, enabled: str) -> str:
        proc, text = self.run_harden(enabled)
        self.assertIn("RC=", proc.stdout, proc.stderr)
        self.assertNotIn("effective-config validation", proc.stderr)
        self.assertNotIn("prior drop-ins were restored", proc.stderr)
        return text

    MATCH_BLOCK = [
        "Match User wins-replica",
        "ChrootDirectory /srv/wins-replica",
        "ForceCommand internal-sftp -d /data",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "AllowTcpForwarding no",
        "AllowAgentForwarding no",
        "AllowStreamLocalForwarding no",
        "DisableForwarding yes",
        "X11Forwarding no",
        "PermitTTY no",
        "PermitTunnel no",
    ]

    def test_receiver_on_is_chrooted_sftp_only_by_sshd(self) -> None:
        lines = self.harden("1").splitlines()
        start = lines.index("Match User wins-replica")
        self.assertEqual(lines[start:start + len(self.MATCH_BLOCK)], self.MATCH_BLOCK)
        self.assertEqual(len(lines), start + len(self.MATCH_BLOCK), "the Match block must be the last thing in the drop-in")

    def test_receiver_off_has_no_match_block(self) -> None:
        self.assertNotIn("Match User", self.harden("0"))

    def test_a_drop_in_whose_match_block_sshd_does_not_apply_is_rolled_back(self) -> None:
        proc, _ = self.run_harden("1", FAKE_DROP_MATCH="1")
        self.assertIn("replica-receiver Match block failed effective-config validation", proc.stderr)
        self.assertIn("prior drop-ins were restored", proc.stderr)
        self.assertNotIn("RC=0", proc.stdout)

    def allow_users_lines(self, text: str) -> list[str]:
        return [l for l in text.splitlines() if l.startswith("AllowUsers")]

    def test_receiver_on_admits_its_account_from_loopback_only(self) -> None:
        self.assertEqual(self.allow_users_lines(self.harden("1")), ["AllowUsers myadmin wins-replica@127.0.0.1"])

    def test_receiver_off_leaves_allowusers_unchanged(self) -> None:
        self.assertEqual(self.allow_users_lines(self.harden("0")), ["AllowUsers myadmin"])

    def test_nothing_else_in_the_dropin_changes(self) -> None:
        on = self.harden("1").splitlines()
        on = on[:on.index("Match User wins-replica")]
        while on and (on[-1] == "" or on[-1].startswith("#")):
            on.pop()
        on = [l for l in on if not l.startswith("AllowUsers")]
        off = [l for l in self.harden("0").splitlines() if not l.startswith("AllowUsers")]
        self.assertEqual(on, off)


# --------------------------------------------------------------------------
# Receiver install, verification and disable
# --------------------------------------------------------------------------


class Receiver(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="lsr-core-"))
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.calls = self.tmp / "calls.log"
        self.owners = self.tmp / "owners.tsv"
        self.owners.write_text("")
        self.passwd = self.tmp / "passwd"
        self.passwd.write_text("")
        self.home = self.tmp / "srv" / "wins-replica"
        self.ssh = self.tmp / "root-ssh"
        self.unit = self.tmp / "unit" / "wins-core-replica-tunnel.service"
        self.unit.parent.mkdir()
        self.etc_ssh = self.tmp / "etc-ssh"
        self.etc_ssh.mkdir()
        keygen(self.etc_ssh / "ssh_host_ed25519_key")
        keygen(self.etc_ssh / "ssh_host_ecdsa_key", "ecdsa")
        write_fake(self.bin, "getent", f'grep -E "^$2:" {str(self.passwd)!r} || exit 2\n')
        write_fake(
            self.bin,
            "useradd",
            f"""
            echo "useradd $*" >> {str(self.calls)!r}
            user="${{@: -1}}"; home=""; shell=""
            while [[ $# -gt 1 ]]; do
              case "$1" in --home-dir) home="$2"; shift 2 ;; --shell) shell="$2"; shift 2 ;; *) shift ;; esac
            done
            echo "${{user}}:x:997:997::${{home}}:${{shell}}" >> {str(self.passwd)!r}
            """,
        )
        write_fake(
            self.bin,
            "systemctl",
            f"""
            echo "systemctl $*" >> {str(self.calls)!r}
            case "$1" in
              is-enabled) [[ "${{FAKE_UNIT_ENABLED:-1}}" == 1 ]] ;;
              is-active) [[ "${{FAKE_UNIT_ACTIVE:-1}}" == 1 ]] ;;
              *) exit 0 ;;
            esac
            """,
        )
        write_fake(
            self.bin,
            "sshd",
            """
            [[ "${FAKE_SSHD_FAIL:-0}" == 1 ]] && exit 1
            printf 'passwordauthentication no\\nallowtcpforwarding no\\ndisableforwarding yes\\n'
            printf 'allowagentforwarding no\\nx11forwarding no\\npermittty no\\npermittunnel no\\n'
            printf 'allowusers ubuntu\\n'
            [[ "${FAKE_SSHD_NO_REPLICA:-0}" == 1 ]] || printf 'allowusers wins-replica@127.0.0.1\\n'
            [[ "${FAKE_SSHD_NO_CHROOT:-0}" == 1 ]] || printf 'chrootdirectory %s\\n' "${CORE_REPLICA_HOME}"
            [[ "${FAKE_SSHD_NO_CHROOT:-0}" == 1 || "${FAKE_SSHD_NO_FORCECOMMAND:-0}" == 1 ]] || printf 'forcecommand internal-sftp -d /data\\n'
            """,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def stubs(self) -> str:
        owners = str(self.owners)
        return f"""
{BASE_STUBS}
_own() {{ local spec="$1"; shift; local p; for p in "$@"; do printf '%s\\t%s\\n' "$p" "$spec" >> {owners!r}; done; }}
chown() {{ echo "chown $*" >> {str(self.calls)!r}; _own "$1" "${{@:2}}"; }}
# A rename carries the recorded owner of its source to its destination.
mv() {{
  local src="${{@: -2:1}}" dst="${{@: -1}}" spec
  command mv "$@" || return
  spec="$(awk -F'\\t' -v p="$src" '$1 == p {{s = $2}} END {{print s}}' {owners!r})"
  [[ -z "$spec" ]] || _own "$spec" "$dst"
}}
install() {{
  local mode="" owner=root group=root dirs=()
  if [[ "$1" != "-d" ]]; then command install "$@"; return; fi
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in -o) owner="$2"; shift 2 ;; -g) group="$2"; shift 2 ;; -m) mode="$2"; shift 2 ;; *) dirs+=("$1"); shift ;; esac
  done
  mkdir -p "${{dirs[@]}}"
  [[ -z "$mode" ]] || chmod "$mode" "${{dirs[@]}}"
  _own "$owner:$group" "${{dirs[@]}}"
  echo "install -d -o $owner -g $group -m $mode ${{dirs[*]}}" >> {str(self.calls)!r}
}}
# GNU stat -c with %U %G %a: owners as recorded by the chown/install fakes
# (root:root when never recorded), modes as they really are.
stat() {{
  local fmt="$2" path="$3" spec mode
  [[ -e "$path" || -L "$path" ]] || return 1
  spec="$(awk -F'\\t' -v p="$path" '$1 == p {{s = $2}} END {{print (s == "" ? "root:root" : s)}}' {owners!r})"
  mode="$(python3 -c 'import os,stat,sys; print(format(stat.S_IMODE(os.lstat(sys.argv[1]).st_mode), "o"))' "$path")"
  fmt="${{fmt//%U/${{spec%%:*}}}}"; fmt="${{fmt//%G/${{spec#*:}}}}"; fmt="${{fmt//%a/$mode}}"
  printf '%s\\n' "$fmt"
}}
sha256sum() {{ command shasum -a 256 "$@"; }}
"""

    def script(self, call: str) -> str:
        body = optional_functions(*VALIDATION_HELPERS) + "\n" + optional_functions(*RECEIVER_FUNCS)
        body = body.replace(UNIT, str(self.unit))
        body = body.replace("/etc/ssh/ssh_host_ecdsa_key.pub", str(self.etc_ssh) + "/ssh_host_ecdsa_key.pub")
        return f"""
set -Eeuo pipefail
{self.stubs()}
{body}
{call}
"""

    def env(self, **extra: str) -> dict:
        env = good_inputs(
            CORE_REPLICA_HUB_SSH_HOST="hub-ssh.example.test",
            CORE_REPLICA_HOME=str(self.home),
            CORE_REPLICA_TUNNEL_KEY=str(self.ssh / "wins_replica_tunnel_ed25519"),
            CORE_REPLICA_TUNNEL_KNOWN_HOSTS=str(self.ssh / "wins_replica_hub_known_hosts"),
            CORE_DISK_ENCRYPTION_EFFECTIVE="luks",
        )
        env["PATH"] = f"{self.bin}:{os.environ.get('PATH', '')}"
        env.update(extra)
        return env

    def install(self, **extra: str) -> subprocess.CompletedProcess:
        self.home.parent.mkdir(parents=True, exist_ok=True)
        return run(self.script("install_core_replica_receiver"), env=self.env(**extra))

    def owner(self, path: Path) -> str:
        spec = "root:root"
        for line in self.owners.read_text().splitlines():
            p, s = line.split("\t")
            if p == str(path):
                spec = s
        return spec

    def mode(self, path: Path) -> str:
        return oct(path.stat().st_mode & 0o777)[2:]

    def expected_line(self) -> str:
        return f'restrict,from="127.0.0.1",command="internal-sftp -d /data" {HUB_LITESTREAM} wins-litestream-hub\n'

    # --- happy path --------------------------------------------------------

    def test_installs_an_sftp_only_loopback_account(self) -> None:
        r = self.install()
        self.assertEqual(r.returncode, 0, r.stderr)
        added = self.calls.read_text()
        self.assertEqual(added.count("useradd "), 1)
        self.assertIn("--shell /usr/sbin/nologin", added)
        self.assertIn("--system", added)
        self.assertIn(f"--home-dir {self.home}", added)
        ak = self.home / ".ssh" / "authorized_keys"
        self.assertEqual(ak.read_text(), self.expected_line())
        for path, owner, mode in (
            (self.home, "root:wins-replica", "750"),
            (self.home / ".ssh", "root:wins-replica", "750"),
            (ak, "root:wins-replica", "640"),
            (self.home / "data", "wins-replica:wins-replica", "700"),
        ):
            self.assertEqual((self.owner(path), self.mode(path)), (owner, mode), str(path))

    def test_key_line_cannot_forward_or_get_a_shell(self) -> None:
        self.assertEqual(self.install().returncode, 0)
        line = (self.home / ".ssh" / "authorized_keys").read_text()
        options = line.split(" ", 1)[0]
        self.assertTrue(options.startswith("restrict,"), options)
        for forbidden in ("port-forwarding", "pty", "agent-forwarding", "X11-forwarding", "user-rc", "permitopen", "permitlisten"):
            self.assertNotIn(forbidden, options)
        self.assertIn('from="127.0.0.1"', options)
        self.assertIn('command="internal-sftp', line)

    def test_hub_host_key_is_pinned_and_tunnel_key_generated(self) -> None:
        self.assertEqual(self.install().returncode, 0)
        known = self.ssh / "wins_replica_hub_known_hosts"
        self.assertEqual(known.read_text(), f"hub-ssh.example.test {HUB_HOST}\n")
        self.assertEqual(self.mode(known), "600")
        key = self.ssh / "wins_replica_tunnel_ed25519"
        self.assertEqual(self.mode(key), "600")
        self.assertTrue(Path(str(key) + ".pub").read_text().startswith("ssh-ed25519 "))

    def test_non_default_hub_port_uses_the_bracketed_known_hosts_form(self) -> None:
        self.assertEqual(self.install(CORE_REPLICA_HUB_SSH_PORT="2222").returncode, 0)
        known = (self.ssh / "wins_replica_hub_known_hosts").read_text()
        self.assertEqual(known, f"[hub-ssh.example.test]:2222 {HUB_HOST}\n")
        self.assertIn(" -p 2222 ", self.unit.read_text())

    def test_reverse_forward_unit_is_pinned_and_holds_nothing(self) -> None:
        self.assertEqual(self.install().returncode, 0)
        unit = self.unit.read_text()
        execs = [l for l in unit.splitlines() if l.startswith("ExecStart=")]
        self.assertEqual(len(execs), 1)
        cmd = execs[0]
        for token in (
            "ExecStart=/usr/bin/autossh -M 0 -N -F /dev/null",
            "-o BatchMode=yes",
            "-o ExitOnForwardFailure=yes",
            "-o StrictHostKeyChecking=yes",
            f"-o UserKnownHostsFile={self.ssh}/wins_replica_hub_known_hosts",
            "-o GlobalKnownHostsFile=/dev/null",
            "-o UpdateHostKeys=no",
            "-o IdentitiesOnly=yes",
            f"-i {self.ssh}/wins_replica_tunnel_ed25519",
            "-p 22 ",
            "-R 127.0.0.1:2232:127.0.0.1:22 ",
            "wins-replica-tunnel@hub-ssh.example.test",
        ):
            self.assertIn(token, cmd)
        for setting in ("NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=read-only",
                        "CapabilityBoundingSet=", "AmbientCapabilities=", "PrivateTmp=true",
                        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", "Restart=always"):
            self.assertIn(setting + "\n", unit)
        self.assertNotIn("EnvironmentFile", unit)
        self.assertNotIn("Requires=ssh", unit)
        self.assertNotIn("ReadWritePaths", unit)
        calls = self.calls.read_text()
        self.assertIn("systemctl enable wins-core-replica-tunnel.service", calls)
        self.assertIn("systemctl restart wins-core-replica-tunnel.service", calls)

    def test_rerun_is_idempotent(self) -> None:
        self.assertEqual(self.install().returncode, 0)
        key = (self.ssh / "wins_replica_tunnel_ed25519").read_bytes()
        self.calls.unlink()
        r = self.install()
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.calls.read_text()
        self.assertNotIn("useradd", calls)
        self.assertNotIn("restart wins-core-replica-tunnel", calls)
        self.assertIn("systemctl start wins-core-replica-tunnel.service", calls)
        self.assertEqual((self.ssh / "wins_replica_tunnel_ed25519").read_bytes(), key)
        self.assertEqual((self.home / ".ssh" / "authorized_keys").read_text(), self.expected_line())

    def test_inactive_forward_only_warns(self) -> None:
        r = self.install(FAKE_UNIT_ACTIVE="0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("not active yet", r.stderr)

    def test_prints_the_values_the_hub_needs(self) -> None:
        r = self.install()
        self.assertEqual(r.returncode, 0, r.stderr)
        tunnel_pub = " ".join(Path(str(self.ssh / "wins_replica_tunnel_ed25519") + ".pub").read_text().split()[:2])
        self.assertIn(f"LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY (this host's tunnel key): {tunnel_pub}", r.stderr)
        host_pub = " ".join((self.etc_ssh / "ssh_host_ecdsa_key.pub").read_text().split()[:2])
        self.assertIn(f"LITESTREAM_SFTP_HOST_KEY (this host's ECDSA sshd key, read here): {host_pub}", r.stderr)

    # --- refusals ----------------------------------------------------------

    def test_refuses_without_a_luks_root(self) -> None:
        for posture in ("substitute", ""):
            r = self.install(CORE_DISK_ENCRYPTION_EFFECTIVE=posture)
            self.assertNotEqual(r.returncode, 0, r.stderr)
            self.assertFalse(self.calls.exists() and "useradd" in self.calls.read_text())
            self.assertFalse((self.home / ".ssh" / "authorized_keys").exists())

    def test_a_plain_root_installs_only_with_the_owner_acceptance_on_the_substitute_posture(self) -> None:
        # Fleet reset TP-C1 (owner ruling 2026-10-08): aicore has no LUKS.
        for posture, knob in (("substitute", "0"), ("", "1"), ("unknown", "1")):
            r = self.install(CORE_DISK_ENCRYPTION_EFFECTIVE=posture, CORE_REPLICA_ALLOW_UNENCRYPTED_ROOT=knob)
            self.assertNotEqual(r.returncode, 0, f"{posture!r} {knob}: {r.stderr}")
            self.assertIn("CORE_REPLICA_ALLOW_UNENCRYPTED_ROOT=1", r.stderr)
            self.assertFalse((self.home / ".ssh" / "authorized_keys").exists())
        r = self.install(CORE_DISK_ENCRYPTION_EFFECTIVE="substitute", CORE_REPLICA_ALLOW_UNENCRYPTED_ROOT="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Replica receiver on an UNENCRYPTED root", r.stderr)
        self.assertEqual((self.home / ".ssh" / "authorized_keys").read_text(), self.expected_line())

    def test_refuses_a_foreign_existing_account(self) -> None:
        for entry in (
            f"wins-replica:x:1000:1000::{self.home}:/bin/bash\n",
            f"wins-replica:x:0:0::{self.home}:/usr/sbin/nologin\n",
            "wins-replica:x:997:997::/home/wins-replica:/usr/sbin/nologin\n",
        ):
            self.passwd.write_text(entry)
            r = self.install()
            self.assertNotEqual(r.returncode, 0, f"{entry!r}: {r.stderr}")
            self.assertFalse((self.home / ".ssh" / "authorized_keys").exists())

    def test_refuses_a_symlinked_home(self) -> None:
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        self.home.parent.mkdir(parents=True, exist_ok=True)
        self.home.symlink_to(elsewhere)
        r = self.install()
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertFalse((elsewhere / ".ssh").exists())

    def test_fails_when_sshd_does_not_chroot_the_account(self) -> None:
        r = self.install(FAKE_SSHD_NO_CHROOT="1")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("chrootdirectory", r.stderr)

    def test_fails_when_sshd_does_not_force_sftp_for_the_account(self) -> None:
        # A chroot without ForceCommand internal-sftp would leave the account
        # whatever its key line allows; the effective check must see both.
        r = self.install(FAKE_SSHD_NO_FORCECOMMAND="1")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("forcecommand", r.stderr)

    def test_refuses_without_an_ecdsa_host_key_before_creating_anything(self) -> None:
        (self.etc_ssh / "ssh_host_ecdsa_key.pub").unlink()
        r = self.install()
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("ssh_host_ecdsa_key.pub is missing", r.stderr)
        self.assertFalse(self.calls.exists() and "useradd" in self.calls.read_text())
        self.assertFalse((self.home / ".ssh").exists())

    def test_fails_when_sshd_does_not_admit_the_account(self) -> None:
        r = self.install(FAKE_SSHD_NO_REPLICA="1")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("AllowUsers", r.stderr)

    def test_fails_when_the_unit_is_not_enabled(self) -> None:
        r = self.install(FAKE_UNIT_ENABLED="0")
        self.assertNotEqual(r.returncode, 0, r.stderr)

    # --- verification reads the result back --------------------------------

    def verify(self, **extra: str) -> subprocess.CompletedProcess:
        return run(self.script("verify_core_replica_receiver"), env=self.env(**extra))

    def test_verify_refuses_an_added_key_line(self) -> None:
        self.assertEqual(self.install().returncode, 0)
        self.assertEqual(self.verify().returncode, 0)
        ak = self.home / ".ssh" / "authorized_keys"
        ak.write_text(ak.read_text() + f"{HUB_HOST} extra\n")
        self.assertNotEqual(self.verify().returncode, 0)

    def test_verify_refuses_a_relaxed_key_line(self) -> None:
        self.assertEqual(self.install().returncode, 0)
        ak = self.home / ".ssh" / "authorized_keys"
        ak.write_text(ak.read_text().replace('restrict,from="127.0.0.1",', ""))
        self.assertNotEqual(self.verify().returncode, 0)

    def test_verify_refuses_loose_modes_and_owners(self) -> None:
        self.assertEqual(self.install().returncode, 0)
        (self.home / "data").chmod(0o750)
        self.assertNotEqual(self.verify().returncode, 0)
        (self.home / "data").chmod(0o700)
        self.assertEqual(self.verify().returncode, 0)
        with self.owners.open("a") as fh:
            fh.write(f"{self.home / '.ssh'}\twins-replica:wins-replica\n")
        self.assertNotEqual(self.verify().returncode, 0)

    def test_verify_refuses_an_unpinned_or_altered_known_hosts(self) -> None:
        self.assertEqual(self.install().returncode, 0)
        known = self.ssh / "wins_replica_hub_known_hosts"
        known.write_text(f"hub-ssh.example.test {HUB_HOST_ECDSA}\n")
        self.assertNotEqual(self.verify().returncode, 0)

    def test_verify_fails_when_sshd_cannot_answer(self) -> None:
        self.assertEqual(self.install().returncode, 0)
        self.assertNotEqual(self.verify(FAKE_SSHD_FAIL="1").returncode, 0)

    # --- disable ------------------------------------------------------------

    def test_disabled_does_nothing_on_a_host_without_the_receiver(self) -> None:
        r = self.install(CORE_REPLICA_RECEIVER_ENABLED="0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.calls.exists())
        self.assertFalse(self.home.exists())

    def test_disabling_stops_the_forward_and_deletes_nothing(self) -> None:
        self.assertEqual(self.install().returncode, 0)
        (self.home / "data" / "ltx").mkdir()
        self.calls.unlink()
        r = self.install(CORE_REPLICA_RECEIVER_ENABLED="0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("systemctl disable --now wins-core-replica-tunnel.service", self.calls.read_text())
        self.assertTrue((self.home / "data" / "ltx").is_dir())
        self.assertTrue((self.home / ".ssh" / "authorized_keys").is_file())


# --------------------------------------------------------------------------
# Main order (Claude N-9): the receiver's host conditions are checked in the
# preflight phase, before the Core is locked, withdrawn or sshd is touched.
# --------------------------------------------------------------------------

MUTATING_STEPS = ("acquire_core_deployment_lock", "begin_core_deployment_withdrawal_before_mutation",
                  "harden_sshd", "install_core_replica_receiver")


class MainOrder(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="lsr-core-main-"))
        self.calls = self.tmp / "calls.log"
        self.etc_ssh = self.tmp / "etc-ssh"
        self.etc_ssh.mkdir()
        keygen(self.etc_ssh / "ssh_host_ecdsa_key", "ecdsa")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_main(self, mode: str = "--deploy", **extra: str) -> subprocess.CompletedProcess:
        main = function_definition("main")
        defined = set(re.findall(r"^([a-z_][a-z0-9_]*)\(\) \{$", SOURCE, re.M))
        called = sorted(n for n in defined if re.search(rf"\b{n}\b", main) and n != "main")
        real = {"core_replica_host_prerequisites", "log", "warn", "err"}
        stubs = "\n".join(f'{n}() {{ echo {n} >> {str(self.calls)!r}; }}' for n in called if n not in real)
        prereq = optional_functions("core_replica_host_prerequisites").replace(
            "/etc/ssh/ssh_host_ecdsa_key.pub", str(self.etc_ssh / "ssh_host_ecdsa_key.pub"))
        script = f"""
set -Eeuo pipefail
{BASE_STUBS}
{stubs}
{prereq}
{main}
main {mode}
"""
        env = {"CORE_REPLICA_RECEIVER_ENABLED": "1", "CORE_DISK_ENCRYPTION_EFFECTIVE": "luks",
               "XRAY_VERSION": "", "XRAY_LINUX_64_SHA256": "", "INSTALL_CORE_IDS_IPS": "0",
               "INSTALL_CORE_IDS_IPS_DEFAULT": "0", "CORE_FAILURE_HOLD_RECEIPT_ROOT": str(self.tmp / "holds"),
               "CORE_INGRESS_PUBLIC_KEY": "x", "CORE_EXIT_PUBLIC_KEY": "x", "CORE_ENV_FILE": "x",
               "CORE_XRAY_PATH": "/x", "CORE_SYNC_STATE_DIR": str(self.tmp / "sync"), "CORE_ENABLE_EXIT": "0"}
        env.update(extra)
        return run(script, env=env)

    def steps(self) -> list[str]:
        return self.calls.read_text().split() if self.calls.exists() else []

    def assert_untouched(self, r: subprocess.CompletedProcess) -> None:
        self.assertNotEqual(r.returncode, 0, r.stderr)
        steps = self.steps()
        self.assertIn("verify_disk_encryption_posture", steps)
        for step in MUTATING_STEPS:
            self.assertNotIn(step, steps, f"{step} ran before the refusal")

    def test_a_non_luks_root_is_refused_before_the_core_is_touched(self) -> None:
        r = self.run_main(CORE_DISK_ENCRYPTION_EFFECTIVE="substitute")
        self.assert_untouched(r)
        self.assertIn("approved only on a LUKS root", r.stderr)

    def test_a_missing_ecdsa_host_key_is_refused_before_the_core_is_touched(self) -> None:
        (self.etc_ssh / "ssh_host_ecdsa_key.pub").unlink()
        r = self.run_main()
        self.assert_untouched(r)
        self.assertIn("ssh_host_ecdsa_key.pub is missing", r.stderr)

    def test_preflight_mode_reports_it_too(self) -> None:
        r = self.run_main("--preflight", CORE_DISK_ENCRYPTION_EFFECTIVE="substitute")
        self.assert_untouched(r)

    def test_a_qualifying_host_deploys_in_the_usual_order(self) -> None:
        r = self.run_main()
        self.assertEqual(r.returncode, 0, r.stderr)
        steps = self.steps()
        for step in MUTATING_STEPS:
            self.assertIn(step, steps)
        self.assertLess(steps.index("verify_disk_encryption_posture"), steps.index("acquire_core_deployment_lock"))

    def test_a_plain_root_with_the_owner_acceptance_deploys(self) -> None:
        # Fleet reset TP-C1 (owner ruling 2026-10-08).
        r = self.run_main(CORE_DISK_ENCRYPTION_EFFECTIVE="substitute", CORE_REPLICA_ALLOW_UNENCRYPTED_ROOT="1",
                          CORE_REPLICA_HOME="/srv/wins-replica")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("UNENCRYPTED root", r.stderr)
        for step in MUTATING_STEPS:
            self.assertIn(step, self.steps())

    def test_receiver_off_needs_neither(self) -> None:
        (self.etc_ssh / "ssh_host_ecdsa_key.pub").unlink()
        r = self.run_main(CORE_REPLICA_RECEIVER_ENABLED="0", CORE_DISK_ENCRYPTION_EFFECTIVE="substitute")
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
