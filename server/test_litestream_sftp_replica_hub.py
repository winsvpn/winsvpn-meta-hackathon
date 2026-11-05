#!/usr/bin/env python3
"""LSR (2026-10-02): the hub's Litestream replica moves from gs:// to an SFTP
replica on an owner-controlled host (aicore, through its reverse forward), and
the nightly rclone backup tolerates an unreachable Drive remote.

Every behavioural test runs the SHIPPED bash extracted from
server/wins_control_plane_setup_ONETOUCH.sh under Bash 4+, with host effects
stubbed and every absolute path it writes redirected into a private temporary
directory. Real `ssh-keygen` makes the test keys; nothing is contacted.

  Contract   validate_durability_replication_contract: with
             DURABILITY_BARRIER_REQUIRED=1 only an sftp:// replica with a
             valid URL and a pinned, well-formed, non-local host key passes;
             gs://, a local path, file:// and any other scheme are refused;
             with the barrier not required they only warn.
  Configure  configure_litestream_replication writes url, key-path and a
             quoted host-key, no Environment=/GOOGLE_APPLICATION_CREDENTIALS
             line, generates the client key only when absent, restarts only
             on change, and authorises the reverse forward for exactly one
             loopback listen port.
  Backup     an unreachable rclone remote no longer stops the deploy
             (configure_rclone_credentials), the nightly archive is kept
             root-only locally with exit 75, and the first backup's 75 does
             not stop public cutover while every other failure still does.

Run:  python3 server/test_litestream_sftp_replica_hub.py
      WINS_LSR_CP_INSTALLER=/path/to/installer python3 server/test_litestream_sftp_replica_hub.py
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

try:
    import _toolchain  # noqa: F401  (V-01 preflight)

    BASH = _toolchain.bash4()
except ModuleNotFoundError:  # a tree without server/_toolchain.py
    BASH = os.environ.get("WINS_TEST_BASH") or shutil.which("bash") or "/bin/bash"

if hasattr(os, "geteuid") and os.geteuid() == 0:
    raise SystemExit("refusing to run as root: this suite must never be able to modify the host")

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = Path(
    os.environ.get("WINS_LSR_CP_INSTALLER", str(ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"))
)
SOURCE = INSTALLER.read_text(encoding="utf-8")
SSH_KEYGEN = shutil.which("ssh-keygen")

HELPERS = (
    # current helpers
    "litestream_sftp_key_path",
    "litestream_sftp_key_ok",
    "litestream_sftp_url_ok",
    "litestream_sftp_url_host_port",
    "litestream_ssh_public_key_ok",
    "litestream_sftp_host_key_not_local",
    "control_path_absent",
    "litestream_replica_target_ok",
    "ensure_litestream_sftp_key",
    "ensure_litestream_sftp_tunnel_account",
    "litestream_tunnel_dirs_safe",
    "litestream_tunnel_account_is_managed",
    "end_litestream_sftp_tunnel_sessions",
    "disable_litestream_sftp_tunnel_account",
    # the retired gs:// helpers, so the suite runs (and fails on behaviour)
    # against the tree before this change
    "litestream_gcs_credentials_path",
    "litestream_gcs_credentials_ok",
)


def function_definition(name: str) -> str:
    """`name() { ... }` verbatim, up to the first column-0 `}` outside a heredoc."""
    signature = f"\n{name}() {{\n"
    start = SOURCE.find(signature)
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
    return "\n".join(function_definition(n) for n in names if f"\n{n}() {{\n" in SOURCE)


STUBS = r"""
log() { printf '[LOG] %s\n' "$*" >&2; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
err() { printf '[ERR] %s\n' "$*" >&2; }
# GNU stat/find emulation for macOS. Ownership is reported as root (0) unless
# the path is FAKE_NONROOT_PATH; %U:%G come from FAKE_OWNERS (path<TAB>u:g,
# written by the chown/install fakes, root:root when absent); the mode is the
# real one.
stat() {
  local fmt="" path out mode uid=0 spec
  if [[ "$1" == "-c" ]]; then fmt="$2"; shift 2; fi
  for path in "$@"; do
    [[ -e "${path}" || -L "${path}" ]] || return 1
    mode="$(python3 -c 'import os,stat,sys; print(format(stat.S_IMODE(os.lstat(sys.argv[1]).st_mode), "o"))' "${path}")"
    [[ -n "${FAKE_NONROOT_PATH:-}" && "${path}" == "${FAKE_NONROOT_PATH}" ]] && uid=1000
    spec="root:root"
    if [[ -n "${FAKE_OWNERS:-}" && -f "${FAKE_OWNERS}" ]]; then
      spec="$(awk -F'\t' -v p="${path}" '$1 == p {s = $2} END {print (s == "" ? "root:root" : s)}' "${FAKE_OWNERS}")"
    fi
    out="${fmt//%u/${uid}}"
    out="${out//%U/${spec%%:*}}"
    out="${out//%G/${spec#*:}}"
    out="${out//%a/${mode}}"
    printf '%s\n' "${out}"
  done
}
find() {
  # The `find PATH -prune -perm /MASK -print -quit` idiom is emulated (macOS
  # find has no /MASK); anything else is the real find. FAKE_FIND_RC makes
  # find fail with no output (only for FAKE_FIND_PATH, when that is set).
  local first="$1"
  [[ "${first}" == -[HLP] ]] && first="$2"
  if [[ -n "${FAKE_FIND_RC:-}" && ( -z "${FAKE_FIND_PATH:-}" || "${first}" == "${FAKE_FIND_PATH:-}" ) ]]; then
    echo "find: ${first}: Input/output error" >&2
    return "${FAKE_FIND_RC}"
  fi
  local path="$1" mask="" a
  for a in "$@"; do [[ "${a}" == -perm ]] && mask=x; done
  [[ -n "${mask}" ]] || { command find "$@"; return; }
  mask=""
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in -perm) mask="${2#/}"; shift 2 ;; *) shift ;; esac
  done
  python3 -c 'import os,stat,sys
m=stat.S_IMODE(os.lstat(sys.argv[1]).st_mode)
print(sys.argv[1] if m & int(sys.argv[2], 8) else "", end="")' "${path}" "${mask}"
}
"""


def run(script: str, env: dict | None = None) -> subprocess.CompletedProcess:
    base = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "C",
    }
    if env:
        base.update(env)
    return subprocess.run([BASH, "-c", script], env=base, capture_output=True, text=True, timeout=120)


def write_fake(bin_dir: Path, name: str, body: str) -> Path:
    path = bin_dir / name
    path.write_text("#!/bin/bash\n" + textwrap.dedent(body), encoding="utf-8")
    path.chmod(0o755)
    return path


def keygen(path: Path, key_type: str = "ed25519") -> str:
    """A real OpenSSH key pair; returns '<type> <base64>' of the public half."""
    assert SSH_KEYGEN, "ssh-keygen is required"
    subprocess.run(
        [SSH_KEYGEN, "-q", "-t", key_type, "-N", "", "-C", "lsr-test", "-f", str(path)],
        check=True, capture_output=True,
    )
    fields = (path.parent / (path.name + ".pub")).read_text().split()
    return f"{fields[0]} {fields[1]}"


class _Keys:
    tmp = Path(tempfile.mkdtemp(prefix="lsr-keys-"))
    host = keygen(tmp / "receiver_host")
    host_ecdsa = keygen(tmp / "receiver_host_ecdsa", "ecdsa")
    tunnel = keygen(tmp / "tunnel")
    hub_own = keygen(tmp / "hub_own_host")


KEYS = _Keys()


def default_line(name: str) -> str:
    m = re.search(rf'^{name}_DEFAULT="\$\{{{name}:-(.*)\}}"$', SOURCE, re.M)
    if not m:
        raise AssertionError(f"no top-level default for {name}")
    return m.group(1)


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="lsr-cp-"))
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.calls = self.tmp / "calls.log"
        self.key = self.tmp / "ssh" / "wins_litestream_ed25519"
        self.local_keys = self.tmp / "etc-ssh"
        self.local_keys.mkdir()
        (self.local_keys / "ssh_host_ed25519_key.pub").write_text(KEYS.hub_own + " root@hub\n")
        write_fake(
            self.bin,
            "systemctl",
            f"""
            echo "systemctl $*" >> {str(self.calls)!r}
            exit 0
            """,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def env(self, **extra: str) -> dict:
        env = {
            "PATH": f"{self.bin}:{os.environ.get('PATH', '')}",
            "LITESTREAM_LOCAL_SSH_HOST_KEY_DIR": str(self.local_keys),
            "LITESTREAM_SFTP_KEY_PATH": str(self.key),
        }
        env.update(extra)
        return env

    def defaults(self, url_default: str = "") -> str:
        return f"""
DURABILITY_BARRIER_REQUIRED_DEFAULT=1
LITESTREAM_REPLICA_URL_DEFAULT={url_default!r}
LITESTREAM_SFTP_KEY_PATH_DEFAULT=/root/.ssh/wins_litestream_ed25519
LITESTREAM_SFTP_HOST_KEY_DEFAULT=''
LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY_DEFAULT=''
LITESTREAM_SFTP_TUNNEL_USER_DEFAULT=wins-replica-tunnel
"""

    def good_key(self, mode: int = 0o600) -> None:
        self.key.parent.mkdir(parents=True, exist_ok=True)
        keygen(self.key)
        self.key.chmod(mode)


# --------------------------------------------------------------------------
# Preflight contract
# --------------------------------------------------------------------------

GOOD_URL = "sftp://wins-replica@127.0.0.1:2232/srv/wins-replica/data/kansas/vpn_users"


class ReplicaContract(_Base):
    def contract(self, url_default: str = "", **extra: str) -> subprocess.CompletedProcess:
        script = f"""
set -Eeuo pipefail
{STUBS}
{self.defaults(url_default)}
{optional_functions(*HELPERS)}
{function_definition("validate_durability_replication_contract")}
validate_durability_replication_contract
"""
        return run(script, env=self.env(**extra))

    def sftp(self, **extra: str) -> subprocess.CompletedProcess:
        values = {"LITESTREAM_REPLICA_URL": GOOD_URL, "LITESTREAM_SFTP_HOST_KEY": KEYS.host}
        values.update(extra)
        return self.contract(**values)

    # --- defaults and retired / on-host targets ---------------------------

    def test_default_replica_url_is_empty(self) -> None:
        self.assertEqual(default_line("LITESTREAM_REPLICA_URL"), "")

    def test_shipped_default_is_refused_when_required(self) -> None:
        r = self.contract(url_default=default_line("LITESTREAM_REPLICA_URL"))
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_gs_is_refused_when_required_even_with_credentials(self) -> None:
        creds = self.tmp / "gcs.json"
        creds.write_text('{"type": "service_account"}')
        creds.chmod(0o600)
        r = self.contract(LITESTREAM_REPLICA_URL="gs://bucket/db", GOOGLE_APPLICATION_CREDENTIALS=str(creds))
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("retired", r.stderr)

    def test_local_path_is_refused_when_required(self) -> None:
        # Reverses the old test_preflight_local_replica_unaffected: a replica
        # on the hub's own disk never met "replicated off this host".
        r = self.contract(LITESTREAM_REPLICA_URL="/var/backups/litestream/vpn_users")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("on this host", r.stderr)

    def test_file_url_is_refused_when_required(self) -> None:
        r = self.contract(LITESTREAM_REPLICA_URL="file:///var/backups/litestream/vpn_users")
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_unknown_scheme_is_refused_when_required(self) -> None:
        for url in ("s3://bucket/db", "abs://acct@container/db", "webdav://h/db", "SFTP://u@h/p"):
            r = self.contract(LITESTREAM_REPLICA_URL=url)
            self.assertNotEqual(r.returncode, 0, f"{url}: {r.stderr}")

    def test_local_path_only_warns_when_not_required(self) -> None:
        r = self.contract(LITESTREAM_REPLICA_URL="/var/backups/litestream/vpn_users", DURABILITY_BARRIER_REQUIRED="0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("[WARN]", r.stderr)

    def test_gs_only_warns_when_not_required(self) -> None:
        r = self.contract(LITESTREAM_REPLICA_URL="gs://bucket/db", DURABILITY_BARRIER_REQUIRED="0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("[WARN]", r.stderr)

    # --- sftp ------------------------------------------------------------

    def test_good_sftp_accepted_with_key_not_yet_generated(self) -> None:
        r = self.sftp()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("does not exist yet", r.stderr)

    def test_good_sftp_accepted_with_key_present(self) -> None:
        self.good_key()
        r = self.sftp()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("[ERR]", r.stderr)

    def test_good_sftp_accepted_with_default_port_and_ecdsa_pin(self) -> None:
        r = self.sftp(LITESTREAM_REPLICA_URL="sftp://wins-replica@replica.example.test/srv/r/kansas",
                      LITESTREAM_SFTP_HOST_KEY=KEYS.host_ecdsa)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_non_ecdsa_pin_is_accepted_with_a_negotiation_warning(self) -> None:
        r = self.sftp()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("prefers ECDSA, then RSA, then Ed25519", r.stderr)
        self.assertIn("only if the receiver offers no ECDSA host key", r.stderr)
        self.assertIn("When the receiver offers ECDSA", r.stderr)
        r = self.sftp(LITESTREAM_SFTP_HOST_KEY=KEYS.host_ecdsa)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("prefers ECDSA", r.stderr)

    def test_missing_host_key_is_refused(self) -> None:
        r = self.sftp(LITESTREAM_SFTP_HOST_KEY="")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("LITESTREAM_SFTP_HOST_KEY is required", r.stderr)

    def test_malformed_host_keys_are_refused(self) -> None:
        kind, blob = KEYS.host.split()
        for bad in (
            f"ssh-rsa {blob}",               # declared type does not match the blob
            f"{kind} {blob} comment",        # comment
            f"{kind} {blob[:-4]}",           # truncated
            f'{kind} {blob}"',               # quote would break the YAML
            f"{kind}",                       # no blob
            f"ssh-dss {blob}",               # unsupported type
            f"{kind} {blob}\n{kind} {blob}", # two lines
        ):
            r = self.sftp(LITESTREAM_SFTP_HOST_KEY=bad)
            self.assertNotEqual(r.returncode, 0, f"{bad!r}: {r.stderr}")

    def test_type_only_key_blobs_are_refused(self) -> None:
        # Sol N-4: a blob carrying only its SSH type string (no curve, no
        # point) passed the type check; ssh-keygen -l rejects it.
        import base64
        name = b"ecdsa-sha2-nistp256"
        bare = base64.b64encode(len(name).to_bytes(4, "big") + name).decode()
        r = self.sftp(LITESTREAM_SFTP_HOST_KEY=f"ecdsa-sha2-nistp256 {bare}")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("not a complete public key", r.stderr)
        r = self.sftp(LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY=f"ecdsa-sha2-nistp256 {bare}")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        # A truncated point is refused as well.
        full = KEYS.host_ecdsa.split()[1]
        raw = base64.b64decode(full)[:-8]
        r = self.sftp(LITESTREAM_SFTP_HOST_KEY="ecdsa-sha2-nistp256 " + base64.b64encode(raw).decode())
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_password_in_url_is_refused(self) -> None:
        r = self.sftp(LITESTREAM_REPLICA_URL="sftp://wins-replica:hunter2@127.0.0.1:2232/srv/r/kansas")
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_malformed_urls_are_refused(self) -> None:
        for url in (
            "sftp://127.0.0.1:2232/srv/r/kansas",          # no user
            "sftp://wins-replica@127.0.0.1:2232",           # no path
            "sftp://wins-replica@127.0.0.1:2232/",          # root path
            "sftp://wins-replica@127.0.0.1:2232/srv/../etc",
            "sftp://wins-replica@127.0.0.1:2232/srv/./r",
            "sftp://wins-replica@127.0.0.1:2232/srv//r",
            "sftp://wins-replica@127.0.0.1:2232/srv/$HOME",
            "sftp://wins-replica@127.0.0.1:2232/srv/r?x=1",
            "sftp://wins-replica@127.0.0.1:99999/srv/r",
            "sftp://wins-replica@127.0.0.1:0/srv/r",
            "sftp://-oProxyCommand@127.0.0.1/srv/r",
            "sftp://wins-replica@-host/srv/r",
            "sftp://wins-replica@host..example/srv/r",
            "sftp://wins-replica@127.0.0.1:2232/srv/r kansas",
        ):
            r = self.sftp(LITESTREAM_REPLICA_URL=url)
            self.assertNotEqual(r.returncode, 0, f"{url}: {r.stderr}")

    def test_group_readable_key_is_refused(self) -> None:
        self.good_key(0o640)
        r = self.sftp()
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_symlinked_key_is_refused(self) -> None:
        self.good_key()
        link = self.tmp / "link_key"
        link.symlink_to(self.key)
        # On macOS the link's own mode can be 0600, so only the symlink check
        # (not the mode check, which reads the link itself) can refuse it.
        if hasattr(os, "lchmod"):
            os.lchmod(link, 0o600)
        r = self.sftp(LITESTREAM_SFTP_KEY_PATH=str(link))
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("non-symlink", r.stderr)

    def test_non_root_key_is_refused(self) -> None:
        self.good_key()
        r = self.sftp(FAKE_NONROOT_PATH=str(self.key))
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_the_hubs_own_host_key_is_refused(self) -> None:
        r = self.sftp(LITESTREAM_SFTP_HOST_KEY=KEYS.hub_own)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("own host key", r.stderr)

    def test_bad_sftp_only_warns_when_not_required(self) -> None:
        r = self.sftp(LITESTREAM_SFTP_HOST_KEY="", DURABILITY_BARRIER_REQUIRED="0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("[WARN]", r.stderr)

    # --- reverse-forward authorisation inputs ----------------------------

    def test_tunnel_key_with_loopback_url_is_accepted(self) -> None:
        r = self.sftp(LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY=KEYS.tunnel)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_tunnel_key_requires_a_loopback_url(self) -> None:
        r = self.sftp(LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY=KEYS.tunnel,
                      LITESTREAM_REPLICA_URL="sftp://wins-replica@replica.example.test:2232/srv/r/kansas")
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_tunnel_port_must_be_unprivileged(self) -> None:
        r = self.sftp(LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY=KEYS.tunnel,
                      LITESTREAM_REPLICA_URL="sftp://wins-replica@127.0.0.1:22/srv/r/kansas")
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_tunnel_key_must_not_be_the_host_key(self) -> None:
        r = self.sftp(LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY=KEYS.host)
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_malformed_tunnel_key_is_refused(self) -> None:
        r = self.sftp(LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY="ssh-ed25519 AAAA")
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_root_tunnel_user_is_refused(self) -> None:
        r = self.sftp(LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY=KEYS.tunnel, LITESTREAM_SFTP_TUNNEL_USER="root")
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_client_key_is_in_the_secret_permission_floor(self) -> None:
        specs = function_definition("control_secret_path_specs")
        self.assertIn(
            '"${LITESTREAM_SFTP_KEY_PATH:-${LITESTREAM_SFTP_KEY_PATH_DEFAULT:-/root/.ssh/wins_litestream_ed25519}}|077|',
            specs,
        )

    def test_contract_still_runs_before_host_mutation(self) -> None:
        secret = function_definition("validate_external_secret_contract")
        self.assertIn("validate_durability_replication_contract || return 1", secret)
        preflight = function_definition("preflight_control")
        self.assertIn("validate_external_secret_contract", preflight)


# --------------------------------------------------------------------------
# configure_litestream_replication
# --------------------------------------------------------------------------


class ReplicaConfigure(_Base):
    def setUp(self) -> None:
        super().setUp()
        self.etc = self.tmp / "etc"
        (self.etc / "systemd" / "system").mkdir(parents=True)
        self.varlib = self.tmp / "varlib"
        self.varlib.mkdir()
        self.useradd_log = self.tmp / "useradd.log"
        self.passwd = self.tmp / "passwd"
        self.passwd.write_text("")
        self.owners = self.tmp / "owners.tsv"
        self.owners.write_text("")
        write_fake(
            self.bin,
            "getent",
            f"""
            grep -E "^$2:" {str(self.passwd)!r} || exit 2
            """,
        )
        write_fake(self.bin, "pkill", f'echo "pkill $*" >> {str(self.calls)!r}\nexit "${{FAKE_PKILL_RC:-0}}"\n')
        # pgrep: 1 = no process left (the normal case after pkill).
        write_fake(self.bin, "pgrep", f'echo "pgrep $*" >> {str(self.calls)!r}\n[[ "${{FAKE_PGREP_RC:-1}}" != 0 ]] || echo 4242\nexit "${{FAKE_PGREP_RC:-1}}"\n')
        # ps -o stat= -p PID: the state of the process pgrep reported.
        write_fake(self.bin, "ps", f'echo "ps $*" >> {str(self.calls)!r}\n[[ "${{FAKE_PS_RC:-0}}" == 0 ]] || exit "${{FAKE_PS_RC}}"\necho "${{FAKE_PS_STATE-S}}"\n')
        # Recorded so a test can prove the account is never deleted.
        for tool in ("userdel", "deluser"):
            write_fake(self.bin, tool, f'echo "{tool} $*" >> {str(self.calls)!r}\n')
        write_fake(
            self.bin,
            "useradd",
            f"""
            echo "useradd $*" >> {str(self.useradd_log)!r}
            user="${{@: -1}}"
            home=""; shell=""
            while [[ $# -gt 1 ]]; do
              case "$1" in --home-dir) home="$2"; shift 2 ;; --shell) shell="$2"; shift 2 ;; *) shift ;; esac
            done
            echo "${{user}}:x:997:997::${{home}}:${{shell}}" >> {str(self.passwd)!r}
            """,
        )

    def configure_script(self) -> str:
        body = function_definition("configure_litestream_replication")
        body = body.replace("/etc/litestream.yml", str(self.etc / "litestream.yml"))
        body = body.replace("/etc/systemd/system/litestream.service", str(self.etc / "systemd/system/litestream.service"))
        helpers = optional_functions(*HELPERS).replace('home="/var/lib/${user}"', f'home="{self.varlib}/${{user}}"')
        return f"""
set -Eeuo pipefail
{STUBS}
_own() {{ local spec="$1" q; shift; for q in "$@"; do printf '%s\t%s\n' "$q" "$spec" >> {str(self.owners)!r}; done; }}
chown() {{
  echo "chown $*" >> {str(self.calls)!r}
  [[ "$1" == "-h" ]] && shift
  # FAKE_CHOWN_IGNORED: a path whose ownership change does not take effect.
  [[ -n "${{FAKE_CHOWN_IGNORED:-}}" && "${{@: -1}}" == "${{FAKE_CHOWN_IGNORED}}" ]] && return 0
  _own "$@"
}}
mv() {{
  # A rename carries the recorded owner of its source to its destination.
  local src="${{@: -2:1}}" dst="${{@: -1}}" spec
  command mv "$@" || return
  spec="$(awk -F'\t' -v p="$src" '$1 == p {{s = $2}} END {{print s}}' {str(self.owners)!r})"
  [[ -z "$spec" ]] || _own "$spec" "$dst"
}}
install() {{
  # install -d [-o U] [-g G] [-m MODE] DIR...: like GNU install, it follows a
  # symlinked directory (that is what the code under test must not rely on).
  local mode="" owner=root group=root dirs=()
  [[ "$1" == "-d" ]] || {{ command install "$@"; return; }}
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in -o) owner="$2"; shift 2 ;; -g) group="$2"; shift 2 ;; -m) mode="$2"; shift 2 ;; *) dirs+=("$1"); shift ;; esac
  done
  mkdir -p "${{dirs[@]}}"
  [[ -z "${{mode}}" ]] || chmod "${{mode}}" "${{dirs[@]}}"
  _own "$owner:$group" "${{dirs[@]}}"
  echo "install -d -m ${{mode}} ${{dirs[*]}}" >> {str(self.calls)!r}
}}
{self.defaults()}
sleep() {{ echo "sleep $*" >> {str(self.calls)!r}; }}
bin=/usr/local/bin/litestream
{helpers}
{body}
configure_litestream_replication
"""

    def configure(self, **extra: str) -> subprocess.CompletedProcess:
        values = {"LITESTREAM_REPLICA_URL": GOOD_URL, "LITESTREAM_SFTP_HOST_KEY": KEYS.host,
                  "FAKE_OWNERS": str(self.owners)}
        values.update(extra)
        return run(self.configure_script(), env=self.env(**values))

    def yaml(self) -> str:
        return (self.etc / "litestream.yml").read_text()

    def unit(self) -> str:
        return (self.etc / "systemd/system/litestream.service").read_text()

    def test_renders_sftp_replica_with_pinned_host_key(self) -> None:
        r = self.configure()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            self.yaml(),
            "socket:\n"
            "  enabled: true\n"
            "  path: /run/litestream/litestream.sock\n"
            "dbs:\n"
            "  - path: /root/vpn_auth/vpn_users.db\n"
            "    replicas:\n"
            f"      - url: {GOOD_URL}\n"
            f"        key-path: {self.key}\n"
            f'        host-key: "{KEYS.host}"\n',
        )
        self.assertEqual(oct((self.etc / "litestream.yml").stat().st_mode & 0o777), "0o600")

    def test_socket_is_where_the_sync_cli_looks(self) -> None:
        # Litestream 0.5.15's `sync` reads neither socket.path from the config
        # nor LITESTREAM_SOCKET; without -socket it dials /var/run/litestream.sock
        # (measured with the pinned binary in the lane's round trip). LSR
        # integration on H0: the hub unit sees only /run/litestream of the
        # host's /run, so the daemon listens in that directory and the hub
        # barrier and the postflight both name that exact socket with -socket.
        socket = "/run/litestream/litestream.sock"
        r = self.configure()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"socket:\n  enabled: true\n  path: {socket}\n", self.yaml())
        head = 'cat > "${APP_DIR}/main.py" <<\'PYEOF\'\n'
        start = SOURCE.index(head) + len(head)
        main_py = SOURCE[start:SOURCE.index("\nPYEOF\n", start)]
        self.assertIn(f'\nLITESTREAM_SOCKET_PATH = "{socket}"\n', main_py)
        runner = main_py[main_py.index("def _run_litestream_sync("):main_py.index("_DURABILITY_BARRIER_RUNNER = ")]
        self.assertIn('LITESTREAM_BIN, "sync",\n        "-socket", LITESTREAM_SOCKET_PATH,\n', runner)
        self.assertIn(f'sync -socket {socket} -wait ', function_definition("litestream_barrier_round_trip_ok"))
        hub_unit = SOURCE[SOURCE.index('cat > "${SERVICE_FILE}" <<EOF\n'):]
        hub_unit = hub_unit[:hub_unit.index("\nEOF\n")]
        self.assertIn("\nTemporaryFileSystem=/run:ro\n", hub_unit)
        self.assertRegex(hub_unit, r"\nBindReadOnlyPaths=(\S+ )*/run/litestream( \S+)*\n")

    def test_unit_carries_no_google_credentials(self) -> None:
        r = self.configure()
        self.assertEqual(r.returncode, 0, r.stderr)
        unit = self.unit()
        self.assertNotIn("GOOGLE_APPLICATION_CREDENTIALS", unit)
        self.assertNotIn("Environment=", unit)
        self.assertIn("ExecStart=/usr/local/bin/litestream replicate", unit)
        self.assertNotIn("\n\n\nExecStartPre", unit)

    def test_configure_never_names_google_credentials(self) -> None:
        # The gs:// branch and its Environment= line are gone, not just unused.
        body = function_definition("configure_litestream_replication")
        self.assertNotIn("GOOGLE_APPLICATION_CREDENTIALS", body)
        self.assertNotIn("Environment=", body)
        self.assertNotIn("litestream_gcs_credentials", SOURCE)

    def test_client_key_is_generated_when_absent(self) -> None:
        r = self.configure()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.key.is_file())
        self.assertEqual(oct(self.key.stat().st_mode & 0o777), "0o600")
        pub = Path(str(self.key) + ".pub").read_text().split()
        self.assertEqual(pub[0], "ssh-ed25519")
        self.assertIn(pub[1], r.stderr, "the public key to authorise on the receiver is not printed")

    def test_existing_client_key_is_kept(self) -> None:
        self.good_key()
        before = hashlib.sha256(self.key.read_bytes()).hexdigest()
        r = self.configure()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(hashlib.sha256(self.key.read_bytes()).hexdigest(), before)

    def test_generated_key_that_is_not_root_owned_is_refused(self) -> None:
        # The key is absent at the target check, so only the gate after
        # generation can see that it did not end up root-owned (a chown that
        # did not take effect).
        r = self.configure(FAKE_NONROOT_PATH=str(self.key))
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("must be owned by root", r.stderr)
        self.assertFalse((self.etc / "litestream.yml").exists())

    def test_loose_existing_key_is_refused(self) -> None:
        self.good_key(0o644)
        r = self.configure()
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.etc / "litestream.yml").exists())

    def test_restart_only_on_change(self) -> None:
        self.assertEqual(self.configure().returncode, 0)
        first = self.calls.read_text()
        self.assertIn("systemctl restart litestream.service", first)
        self.calls.unlink()
        r = self.configure()
        self.assertEqual(r.returncode, 0, r.stderr)
        second = self.calls.read_text()
        self.assertNotIn("restart litestream.service", second)
        self.assertIn("systemctl start litestream.service", second)

    def test_gs_is_refused_and_nothing_is_written(self) -> None:
        r = self.configure(LITESTREAM_REPLICA_URL="gs://bucket/db")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.etc / "litestream.yml").exists())
        self.assertFalse(self.calls.exists() and "enable" in self.calls.read_text())

    def test_local_path_is_refused_when_required(self) -> None:
        r = self.configure(LITESTREAM_REPLICA_URL=str(self.tmp / "replica"))
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.etc / "litestream.yml").exists())

    def test_unpinned_sftp_is_never_written_even_when_not_required(self) -> None:
        r = self.configure(LITESTREAM_SFTP_HOST_KEY="", DURABILITY_BARRIER_REQUIRED="0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.etc / "litestream.yml").exists())

    def test_no_tunnel_account_without_a_tunnel_key(self) -> None:
        r = self.configure()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.useradd_log.exists())

    def test_tunnel_account_authorises_one_loopback_listen_port(self) -> None:
        r = self.configure(LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY=KEYS.tunnel)
        self.assertEqual(r.returncode, 0, r.stderr)
        added = self.useradd_log.read_text()
        self.assertIn("--shell /usr/sbin/nologin", added)
        self.assertIn("--system", added)
        authorized = self.varlib / "wins-replica-tunnel" / ".ssh" / "authorized_keys"
        self.assertEqual(
            authorized.read_text(),
            f'restrict,port-forwarding,permitlisten="127.0.0.1:2232",command="/usr/sbin/nologin" {KEYS.tunnel} wins-litestream-tunnel\n',
        )
        self.assertEqual(oct(authorized.stat().st_mode & 0o777), "0o640")
        self.assertIn(f"chown root:wins-replica-tunnel", self.calls.read_text())
        # Idempotent: a rerun rewrites the same single line and adds no account.
        self.assertEqual(self.configure(LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY=KEYS.tunnel).returncode, 0)
        self.assertEqual(self.useradd_log.read_text().count("useradd"), 1)
        self.assertEqual(len(authorized.read_text().splitlines()), 1)

    def test_tunnel_account_refuses_a_foreign_existing_account(self) -> None:
        for entry in (
            f"wins-replica-tunnel:x:1000:1000::{self.varlib}/wins-replica-tunnel:/bin/bash\n",
            f"wins-replica-tunnel:x:0:0::{self.varlib}/wins-replica-tunnel:/usr/sbin/nologin\n",
            "wins-replica-tunnel:x:997:997::/home/other:/usr/sbin/nologin\n",
        ):
            self.passwd.write_text(entry)
            r = self.configure(LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY=KEYS.tunnel)
            self.assertNotEqual(r.returncode, 0, f"{entry!r}: {r.stderr}")
            self.assertFalse((self.varlib / "wins-replica-tunnel" / ".ssh" / "authorized_keys").exists())


# --------------------------------------------------------------------------
# Backup remote outage
# --------------------------------------------------------------------------

CRYPT_CONF = """[base]
type = drive

[GoogleDrive_secured]
type = crypt
remote = base:winsvpn
password = obscured-one
password2 = obscured-two
"""


class TunnelAccountSafety(ReplicaConfigure):
    """LSR R2: Sol N-2 (symlinks) and Claude N-5 (de-authorisation)."""

    def existing_account(self) -> Path:
        home = self.varlib / "wins-replica-tunnel"
        self.passwd.write_text(f"wins-replica-tunnel:x:997:997::{home}:/usr/sbin/nologin\n")
        return home

    def test_symlinked_ssh_dir_is_refused_and_its_target_untouched(self) -> None:
        # Sol's probe: an otherwise acceptable account whose ~/.ssh points at
        # another directory holding an authorization file.
        home = self.existing_account()
        home.mkdir()
        other = self.tmp / "other-ssh"
        other.mkdir()
        (other / "authorized_keys").write_text("operator line\n")
        (home / ".ssh").symlink_to(other)
        r = self.configure(LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY=KEYS.tunnel)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("symlink", r.stderr)
        self.assertEqual((other / "authorized_keys").read_text(), "operator line\n")
        self.assertEqual([p.name for p in other.iterdir()], ["authorized_keys"])
        self.assertTrue((home / ".ssh").is_symlink())
        self.assertNotIn(str(other), self.owners.read_text())

    def test_symlinked_home_is_refused(self) -> None:
        home = self.existing_account()
        other = self.tmp / "other-home"
        other.mkdir()
        home.symlink_to(other)
        r = self.configure(LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY=KEYS.tunnel)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertEqual(list(other.iterdir()), [])

    def test_symlinked_authorized_keys_is_refused(self) -> None:
        home = self.existing_account()
        (home / ".ssh").mkdir(parents=True)
        target = self.tmp / "elsewhere"
        target.write_text("keep\n")
        (home / ".ssh" / "authorized_keys").symlink_to(target)
        r = self.configure(LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY=KEYS.tunnel)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertEqual(target.read_text(), "keep\n")

    def test_a_directory_whose_ownership_does_not_read_back_is_refused(self) -> None:
        # The owner and mode are read back after chown/chmod; a .ssh that is
        # still not root:<account> 0750 gets no authorization file.
        home = self.existing_account()
        (home / ".ssh").mkdir(parents=True)
        r = self.configure(LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY=KEYS.tunnel, FAKE_CHOWN_IGNORED=str(home / ".ssh"))
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("is not a root:wins-replica-tunnel 0750 directory after setup", r.stderr)
        self.assertFalse((home / ".ssh" / "authorized_keys").exists())

    def test_existing_real_directories_are_set_to_root_owned_0750(self) -> None:
        home = self.existing_account()
        (home / ".ssh").mkdir(parents=True)
        (home / ".ssh").chmod(0o777)
        r = self.configure(LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY=KEYS.tunnel)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(oct((home / ".ssh").stat().st_mode & 0o777), "0o750")
        self.assertIn(f"{home / '.ssh'}\troot:wins-replica-tunnel", self.owners.read_text())

    def test_unset_tunnel_key_removes_the_authorisation_but_keeps_the_account(self) -> None:
        self.assertEqual(self.configure(LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY=KEYS.tunnel).returncode, 0)
        authorized = self.varlib / "wins-replica-tunnel" / ".ssh" / "authorized_keys"
        self.assertTrue(authorized.read_text().strip())
        self.calls.unlink()
        r = self.configure()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(authorized.read_text(), "")
        self.assertEqual(oct(authorized.stat().st_mode & 0o777), "0o640")
        calls = self.calls.read_text()
        self.assertIn("pkill -u wins-replica-tunnel", calls)
        self.assertNotIn("userdel", calls)
        self.assertNotIn("deluser", calls)
        self.assertIn("wins-replica-tunnel:", self.passwd.read_text())
        self.assertIn("holds no reverse-forward authorisation and no session", r.stderr)

    FOREIGN = (
        ("uid 0, login shell", "0", "{home}", "/bin/bash"),
        ("uid 0, nologin, expected home", "0", "{home}", "/usr/sbin/nologin"),
        ("ordinary uid 1000, nologin, expected home", "1000", "{home}", "/usr/sbin/nologin"),
        ("system uid, login shell", "997", "{home}", "/bin/bash"),
        ("system uid, other home", "997", "/home/other", "/usr/sbin/nologin"),
    )

    def test_disable_refuses_a_foreign_account_and_changes_nothing(self) -> None:
        # Sol N-8: the unset-key path must apply the authorising checks before
        # emptying any key file or signalling any process.
        home = self.varlib / "wins-replica-tunnel"
        (home / ".ssh").mkdir(parents=True)
        authorized = home / ".ssh" / "authorized_keys"
        for label, uid, entry_home, shell in self.FOREIGN:
            with self.subTest(label):
                authorized.write_text("operator line\n")
                if self.calls.exists():
                    self.calls.unlink()
                self.passwd.write_text(f"wins-replica-tunnel:x:{uid}:{uid}::{entry_home.format(home=home)}:{shell}\n")
                r = self.configure()
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertIn("is not the Litestream tunnel account this installer manages", r.stderr)
                self.assertEqual(authorized.read_text(), "operator line\n")
                calls = self.calls.read_text() if self.calls.exists() else ""
                self.assertNotIn("pkill", calls)
                self.assertNotIn(str(home), calls)

    def test_authorising_refuses_a_non_system_uid(self) -> None:
        home = self.varlib / "wins-replica-tunnel"
        self.passwd.write_text(f"wins-replica-tunnel:x:1000:1000::{home}:/usr/sbin/nologin\n")
        r = self.configure(LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY=KEYS.tunnel)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertFalse((home / ".ssh" / "authorized_keys").exists())

    def disabled_after_authorising(self, **extra: str):
        self.assertEqual(self.configure(LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY=KEYS.tunnel).returncode, 0)
        self.calls.unlink()
        return self.configure(**extra)

    def test_a_failing_pkill_is_a_failure(self) -> None:
        # Sol N-9: exit 2 or more from pkill is not "sessions ended".
        r = self.disabled_after_authorising(FAKE_PKILL_RC="2")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("pkill -u wins-replica-tunnel failed (exit 2)", r.stderr)
        self.assertNotIn("holds no reverse-forward authorisation", r.stderr)

    def test_pkill_finding_nothing_is_fine(self) -> None:
        r = self.disabled_after_authorising(FAKE_PKILL_RC="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("pgrep -u wins-replica-tunnel", self.calls.read_text())

    def test_sessions_that_survive_pkill_are_a_failure(self) -> None:
        r = self.disabled_after_authorising(FAKE_PGREP_RC="0")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("still running after pkill", r.stderr)
        self.assertIn("sleep", self.calls.read_text())

    def test_zombies_left_behind_are_not_live_sessions(self) -> None:
        # Measured in the round trip: a killed session whose parent is gone
        # stays a zombie until PID 1 reaps it; it holds no forward.
        r = self.disabled_after_authorising(FAKE_PGREP_RC="0", FAKE_PS_STATE="Z")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ps -o stat= -p 4242", self.calls.read_text())

    def test_a_failing_ps_is_never_proof_that_a_session_ended(self) -> None:
        # Sol N-11 (R4-1): pkill 0, pgrep reports a PID, ps exits 2 with no
        # output. That is an unknown state, so it counts as live.
        r = self.disabled_after_authorising(FAKE_PGREP_RC="0", FAKE_PS_RC="2")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("4242(ps failed, exit 2)", r.stderr)
        self.assertNotIn("holds no reverse-forward authorisation", r.stderr)

    def test_an_empty_state_is_never_proof_that_a_session_ended(self) -> None:
        r = self.disabled_after_authorising(FAKE_PGREP_RC="0", FAKE_PS_STATE="")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("4242(no state)", r.stderr)

    def test_a_failing_pgrep_is_a_failure(self) -> None:
        r = self.disabled_after_authorising(FAKE_PGREP_RC="3")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("pgrep -u wins-replica-tunnel failed (exit 3)", r.stderr)

    def test_every_unset_run_ends_and_checks_sessions_again(self) -> None:
        # Idempotent: a rerun after the file is already empty (for example
        # after a failed termination) still terminates and verifies.
        self.assertEqual(self.disabled_after_authorising(FAKE_PKILL_RC="2").returncode != 0, True)
        authorized = self.varlib / "wins-replica-tunnel" / ".ssh" / "authorized_keys"
        self.assertEqual(authorized.read_text(), "")
        self.calls.unlink()
        r = self.configure()
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.calls.read_text()
        self.assertIn("pkill -u wins-replica-tunnel", calls)
        self.assertIn("pgrep -u wins-replica-tunnel", calls)

    def test_unset_tunnel_key_without_an_account_does_nothing(self) -> None:
        r = self.configure()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.varlib / "wins-replica-tunnel").exists())
        self.assertNotIn("pkill", self.calls.read_text() if self.calls.exists() else "")



# TunnelAccountSafety reuses ReplicaConfigure's harness, not its tests.
for _name in [n for n in vars(ReplicaConfigure) if n.startswith("test_")]:
    if _name not in vars(TunnelAccountSafety):
        setattr(TunnelAccountSafety, _name, None)


class BackupRemoteOutage(_Base):
    def rclone_fake(self, lsd_rc: int = 1, copy_rc: int = 0, cryptcheck_rc: int = 0, kind: str = "crypt",
                    lsjson_rc: int = 0) -> None:
        write_fake(
            self.bin,
            "rclone",
            f"""
            echo "rclone $*" >> {str(self.calls)!r}
            case "$1" in
              listremotes) printf 'base:\\nGoogleDrive_secured:\\n' ;;
              lsd) exit {lsd_rc} ;;
              config) printf '{{"GoogleDrive_secured":{{"type":"{kind}","remote":"base:winsvpn"}},"base":{{"type":"drive"}}}}\\n' ;;
              copy) exit {copy_rc} ;;
              cryptcheck)
                if [[ {cryptcheck_rc} -ne 0 ]]; then
                  echo "ERROR : wins-hub-backup-hub-test-1.tar.gz.age: hashes differ" >&2
                fi
                exit {cryptcheck_rc} ;;
              lsjson)
                if [[ {lsjson_rc} -ne 0 ]]; then
                  echo "Failed to create file system: couldn't fetch token: unauthorized_client" >&2
                  exit {lsjson_rc}
                fi
                echo '[]' ;;
              *) exit 0 ;;
            esac
            """,
        )

    def credentials(self, conf: str = CRYPT_CONF, **extra: str) -> subprocess.CompletedProcess:
        root = self.tmp / "root"
        source = self.tmp / "rclone.conf"
        source.write_text(conf)
        source.chmod(0o600)
        body = function_definition("configure_rclone_credentials")
        for prefix in ("/root/.config", "/etc/winsvpn"):
            body = body.replace(prefix, str(root) + prefix)
        script = f"""
set -Eeuo pipefail
{STUBS}
sleep() {{ :; }}
validate_backup_retention_contract() {{ :; }}
validate_backup_encryption_contract() {{ :; }}
backup_encryption_live_check() {{ :; }}
resolve_backup_host_id() {{ RESOLVED_BACKUP_HOST_ID=hub-test; }}
{function_definition("rclone_crypt_remote_contract")}
RCLONE_REMOTE_DEFAULT=GoogleDrive_secured
REQUIRE_REMOTE_BACKUP_DEFAULT=1
BACKUP_RETENTION_DAYS_DEFAULT=30
BACKUP_MANIFEST_RETENTION_DAYS_DEFAULT=365
BACKUP_PRUNE_DRY_RUN_DEFAULT=0
REQUIRE_BACKUP_PRUNING_DEFAULT=1
BACKUP_AGE_RECIPIENTS_FILE_DEFAULT=/etc/winsvpn/backup-recipients.age
REQUIRE_BACKUP_ENCRYPTION_DEFAULT=1
LITESTREAM_REPLICA_URL_DEFAULT=''
WINS_SECRETS_FILE=/nonexistent/secrets.env
{body}
configure_rclone_credentials
"""
        return run(script, env=self.env(RCLONE_CONFIG_SOURCE=str(source), **extra))

    def test_deploy_survives_an_unreachable_remote(self) -> None:
        self.rclone_fake(lsd_rc=1)
        r = self.credentials()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Deploy continues", r.stderr)
        self.assertEqual(self.calls.read_text().count("rclone lsd"), 3)

    def test_reachable_remote_is_still_verified(self) -> None:
        self.rclone_fake(lsd_rc=0)
        r = self.credentials()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("[WARN]", r.stderr)

    def test_a_non_crypt_remote_is_still_refused(self) -> None:
        self.rclone_fake(lsd_rc=0)
        r = self.credentials(conf=CRYPT_CONF.replace("type = crypt", "type = drive"))
        self.assertNotEqual(r.returncode, 0, r.stderr)

    # --- the nightly script's upload section -------------------------------

    def upload_section(self, through_end: bool = False) -> str:
        head = "cat > /usr/local/bin/wins-hub-backup <<'EOF'\n"
        start = SOURCE.index(head) + len(head)
        backup = SOURCE[start:SOURCE.index("\nEOF\n", start)]
        a = backup.index('(cd "${UPLOAD_DIR}" && sha256sum "${ARCHIVE_NAME}" > "${ARCHIVE_NAME}.sha256")')
        b = len(backup) if through_end else backup.index("# Sanitised long-retention manifest.")
        return self.backup_helpers() + backup[a:b]

    @staticmethod
    def backup_script() -> str:
        head = "cat > /usr/local/bin/wins-hub-backup <<'EOF'\n"
        start = SOURCE.index(head) + len(head)
        return SOURCE[start:SOURCE.index("\nEOF\n", start)]

    def backup_helpers(self) -> str:
        """path_kind and kind_or_fail as the backup script defines them (R5);
        nothing for a tree that predates them."""
        backup = self.backup_script()
        if "\nkind_or_fail() {\n" not in backup:
            return ""
        a = backup.index("\npath_kind() {\n") + 1
        k = backup.index("\nkind_or_fail() {\n")
        b = backup.index("\n}\n", k) + 3
        return backup[a:b] + "\n"

    def backup_slice(self, start: str, end: str) -> str:
        backup = self.backup_script()
        a = backup.index(start) + len(start)
        return backup[a:backup.index(end, a)]

    def real_pruner(self, source_root: Path, conf: Path) -> tuple[Path, dict]:
        """The SHIPPED wins-hub-backup-prune, run by Bash 4+, with its paths
        pointed into the test tree. Returns the wrapper and its environment."""
        head = "cat > /usr/local/bin/wins-hub-backup-prune <<'EOF'\n"
        start = SOURCE.index(head) + len(head)
        body = SOURCE[start:SOURCE.index("\nEOF\n", start)] + "\n"
        script = self.tmp / "wins-hub-backup-prune"
        script.write_text(body)
        wrapper = write_fake(self.bin, "prune", f'echo "prune local_only=${{WINS_PRUNE_LOCAL_ONLY:-unset}}" >> {str(self.calls)!r}\nexec {BASH!r} {str(script)!r} "$@"\n')
        self.manifests = self.tmp / "manifests"
        self.manifests.mkdir(exist_ok=True)
        env = {
            "WINS_BACKUP_ENV": str(self.tmp / "no-backup.env"),
            "WINS_LOCAL_BACKUP_DIR": str(source_root / "var/backups/winsvpn"),
            "WINS_BACKUP_MANIFEST_DIR": str(self.manifests),
            "WINS_RCLONE_CONFIG": str(conf),
            "BACKUP_HOST_ID": "hub-test",
            "RCLONE_REMOTE": "GoogleDrive_secured",
        }
        return wrapper, env

    def upload(self, required: str = "1", with_rclone: bool = True, prune_rc: int = 0, real_prune: bool = False,
               through_end: bool = False, stale_local: bool = False,
               broken_manifests: bool = False, stale_manifest: bool = False, unreadable_manifests: bool = False,
               litestream: bool = False, find_fail: str = "", find_fail_arg: str = "",
               locked_manifest_parent: bool = False, locked_rclone_parent: bool = False) -> tuple[subprocess.CompletedProcess, Path]:
        upload_dir = self.tmp / "upload"
        upload_dir.mkdir()
        (upload_dir / "wins-hub-backup-hub-test-1.tar.gz.age").write_bytes(b"ciphertext")
        source_root = self.tmp / "src"
        (source_root / "root/.config/rclone").mkdir(parents=True)
        conf = source_root / "root/.config/rclone/rclone.conf"
        if with_rclone:
            conf.write_text(CRYPT_CONF)
        extra_env: dict = {}
        local_dir = source_root / "var/backups/winsvpn"
        locked: list[Path] = []
        if real_prune:
            prune, extra_env = self.real_pruner(source_root, conf)
            extra_env["REQUIRE_REMOTE_BACKUP"] = required
            if locked_manifest_parent:
                # Sol N-14: a configured manifest directory under a parent the
                # pruner cannot traverse, holding a 400-day-old manifest.
                parent = self.tmp / "locked"
                (parent / "manifests").mkdir(parents=True)
                old = parent / "manifests" / "manifest-old.json"
                old.write_text("{}")
                os.utime(old, (time.time() - 400 * 86400,) * 2)
                extra_env["WINS_BACKUP_MANIFEST_DIR"] = str(parent / "manifests")
                parent.chmod(0o000)
                locked.append(parent)
            if stale_local:
                local_dir.mkdir(parents=True, mode=0o700)
                old = local_dir / "wins-hub-backup-hub-test-0.tar.gz.age"
                old.write_bytes(b"old ciphertext")
                os.utime(old, (time.time() - 40 * 86400,) * 2)
            if broken_manifests or stale_manifest or unreadable_manifests:
                stale = self.manifests / "manifest-old.json"
                stale.write_text("{}")
                os.utime(stale, (time.time() - 400 * 86400,) * 2)
            if broken_manifests:
                self.manifests.chmod(0o500)
            if unreadable_manifests:
                self.manifests.chmod(0o000)
            if litestream:
                replica = self.tmp / "litestream-replica"
                (replica / "ltx").mkdir(parents=True)
                (replica / "ltx" / "fresh.ltx").write_bytes(b"new")
                old_ltx = replica / "ltx" / "old.ltx"
                old_ltx.write_bytes(b"old")
                os.utime(old_ltx, (time.time() - 40 * 86400,) * 2)
                extra_env["WINS_LITESTREAM_REPLICA_DIR"] = str(replica)
            if find_fail:
                # find that fails (exit 2) for one directory, optionally only
                # when one more argument is present; otherwise the real find.
                real_find = shutil.which("find", path="/usr/bin:/bin")
                write_fake(self.bin, "find", f"""
                    hit=0; extra=0
                    for a in "$@"; do
                      [[ "$a" == "$FAKE_FIND_FAIL_PATH" ]] && hit=1
                      [[ -z "$FAKE_FIND_FAIL_ARG" || "$a" == "$FAKE_FIND_FAIL_ARG" ]] && extra=1
                    done
                    if (( hit && extra )); then
                      echo "find: $FAKE_FIND_FAIL_PATH: Input/output error" >&2
                      exit 2
                    fi
                    exec {real_find} "$@"
                    """)
                extra_env["FAKE_FIND_FAIL_PATH"] = find_fail
                extra_env["FAKE_FIND_FAIL_ARG"] = find_fail_arg
        else:
            prune = write_fake(self.bin, "prune", f'echo "prune" >> {str(self.calls)!r}\nexit {prune_rc}\n')
        if locked_rclone_parent:
            (source_root / "root/.config").chmod(0o000)
            locked.append(source_root / "root/.config")
        script = f"""
set -Eeuo pipefail
umask 077
SOURCE_ROOT={str(source_root)!r}
root_path() {{ printf '%s/%s' "${{SOURCE_ROOT%/}}" "$1"; }}
UPLOAD_DIR={str(upload_dir)!r}
ARCHIVE_NAME=wins-hub-backup-hub-test-1.tar.gz.age
RCLONE_CONFIG_FILE={str(conf)!r}
RCLONE_REMOTE=GoogleDrive_secured
REMOTE="GoogleDrive_secured:winsvpn-backups/hub-test"
REQUIRED={required}
WINS_BACKUP_PRUNE_BIN={str(prune)!r}
WINS_BACKUP_MANIFEST_BIN=/usr/bin/true
{self.upload_section(through_end)}
echo UPLOAD_SECTION_DONE
"""
        try:
            return run(script, env=self.env(**extra_env)), local_dir
        finally:
            if broken_manifests or unreadable_manifests:
                self.manifests.chmod(0o700)
            for path in locked:
                path.chmod(0o700)

    def test_unreachable_remote_keeps_the_archive_and_exits_75(self) -> None:
        self.rclone_fake(copy_rc=1)
        r, local = self.upload()
        self.assertEqual(r.returncode, 75, r.stdout + r.stderr)
        self.assertEqual(
            sorted(p.name for p in local.iterdir()),
            ["wins-hub-backup-hub-test-1.tar.gz.age", "wins-hub-backup-hub-test-1.tar.gz.age.sha256"],
        )
        self.assertIn("prune", self.calls.read_text())

    def test_remote_outage_with_a_failed_local_prune_is_not_75(self) -> None:
        # Sol N-3: 75 must mean "only the remote failed". A local pruning
        # failure keeps the archive but exits 1, which stops cutover.
        self.rclone_fake(copy_rc=1)
        r, local = self.upload(prune_rc=1)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("local retention pruning failed", r.stderr)
        self.assertTrue((local / "wins-hub-backup-hub-test-1.tar.gz.age").is_file())

    # --- the same, with the SHIPPED pruner (Claude N-7, Sol N-7) -----------

    def test_real_pruner_remote_outage_with_listing_failing_is_75(self) -> None:
        # Upload fails AND the remote cannot be listed (a disabled OAuth
        # client): every local stage succeeds, so the run is a remote outage.
        self.rclone_fake(copy_rc=1, lsjson_rc=1)
        r, local = self.upload(real_prune=True, stale_local=True)
        self.assertEqual(r.returncode, 75, r.stdout + r.stderr)
        self.assertIn("local-only run: stages 1-3 done", r.stdout)
        self.assertIn("prune local_only=1", self.calls.read_text())
        self.assertNotIn("rclone lsjson", self.calls.read_text())
        self.assertEqual(
            sorted(p.name for p in local.iterdir()),
            ["wins-hub-backup-hub-test-1.tar.gz.age", "wins-hub-backup-hub-test-1.tar.gz.age.sha256"],
            "stage 1 must still remove the archive past the window",
        )

    def test_real_pruner_remote_outage_with_a_failing_local_stage_is_1(self) -> None:
        self.rclone_fake(copy_rc=1, lsjson_rc=1)
        r, local = self.upload(real_prune=True, broken_manifests=True)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("local retention pruning failed", r.stderr)
        self.assertTrue((local / "wins-hub-backup-hub-test-1.tar.gz.age").is_file())

    def test_real_pruner_uploaded_but_remote_prune_failing_is_1(self) -> None:
        # Decision: after a SUCCESSFUL upload the remote is reachable, so a
        # failure to prune it is a retention failure, not an outage: exit 1
        # (REQUIRE_BACKUP_PRUNING=1), never 75.
        self.rclone_fake(copy_rc=0, cryptcheck_rc=0, lsjson_rc=1)
        r, _ = self.upload(real_prune=True, through_end=True)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("Could not list the backup remote", r.stderr)
        self.assertIn("Backup retention pruning failed", r.stderr)
        self.assertIn("prune local_only=0", self.calls.read_text())

    def test_real_pruner_uploaded_and_remote_reachable_succeeds(self) -> None:
        self.rclone_fake(copy_rc=0, cryptcheck_rc=0, lsjson_rc=0)
        r, _ = self.upload(real_prune=True, through_end=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("retention window enforced", r.stdout)
        self.assertIn("rclone lsjson", self.calls.read_text())

    def test_real_pruner_optional_remote_outage_succeeds_locally(self) -> None:
        self.rclone_fake(copy_rc=1, lsjson_rc=1)
        r, local = self.upload(required="0", real_prune=True, through_end=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("UPLOAD_SECTION_DONE", r.stdout)
        self.assertNotIn("rclone lsjson", self.calls.read_text())
        self.assertTrue((local / "wins-hub-backup-hub-test-1.tar.gz.age").is_file())

    def test_failed_verification_also_keeps_the_archive(self) -> None:
        # R4-3 (Sol N-13, Claude N-12): the copy succeeded, so the remote was
        # reachable; a failed cryptcheck is an integrity failure, never 75.
        self.rclone_fake(copy_rc=0, cryptcheck_rc=1)
        r, local = self.upload()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("FAILED integrity verification", r.stderr)
        self.assertIn("This is not a remote outage", r.stderr)
        self.assertTrue((local / "wins-hub-backup-hub-test-1.tar.gz.age").is_file())

    def test_real_pruner_copy_ok_but_hashes_differ_is_1(self) -> None:
        # Copy succeeds, cryptcheck reports differing hashes, the remote is
        # reachable (listing works): exit 1, archive kept, full pruner run.
        self.rclone_fake(copy_rc=0, cryptcheck_rc=1, lsjson_rc=0)
        r, local = self.upload(real_prune=True)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("hashes differ", r.stderr)
        self.assertIn("FAILED integrity verification", r.stderr)
        self.assertIn("prune local_only=0", self.calls.read_text())
        self.assertTrue((local / "wins-hub-backup-hub-test-1.tar.gz.age").is_file())

    # --- R5-1 (Sol N-14, Claude N-14): an inspection failure is never "absent"

    def prune_alone(self, **env: str) -> subprocess.CompletedProcess:
        """The shipped pruner on its own, local stages only."""
        source_root = self.tmp / "src"
        source_root.mkdir(exist_ok=True)
        prune, base = self.real_pruner(source_root, self.tmp / "no-rclone.conf")
        base.update({"WINS_PRUNE_LOCAL_ONLY": "1", "REQUIRE_REMOTE_BACKUP": "0"})
        base.update(env)
        return run(f"exec {str(prune)!r}", env=self.env(**base))

    def locked_dir_with_old_file(self, name: str, filename: str, days: int) -> tuple[Path, Path, Path]:
        parent = self.tmp / f"locked-{name}"
        target = parent / name
        target.mkdir(parents=True)
        old = target / filename
        old.write_text("old")
        os.utime(old, (time.time() - days * 86400,) * 2)
        return parent, target, old

    def assert_locked_stage_fails(self, stage: str, var: str, name: str, filename: str, days: int,
                                  **extra: str) -> None:
        parent, target, old = self.locked_dir_with_old_file(name, filename, days)
        parent.chmod(0o000)
        try:
            r = self.prune_alone(**{var: str(target)}, **extra)
        finally:
            parent.chmod(0o700)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn(f"{stage}: could not inspect {target}", r.stderr)
        self.assertIn("Permission denied", r.stderr)
        self.assertTrue(old.exists(), "the expired file must still be there")

    def test_pruner_archive_directory_under_an_untraversable_parent_is_1(self) -> None:
        self.assert_locked_stage_fails("stage 1 local archives", "WINS_LOCAL_BACKUP_DIR", "winsvpn",
                                       "wins-hub-backup-hub-test-0.tar.gz.age", 40)

    def test_pruner_history_directory_under_an_untraversable_parent_is_1(self) -> None:
        self.assert_locked_stage_fails("stage 2 litestream history", "WINS_LITESTREAM_REPLICA_DIR", "replica",
                                       "old.ltx", 40)

    def test_pruner_manifest_directory_under_an_untraversable_parent_is_1(self) -> None:
        self.assert_locked_stage_fails("stage 3 sanitised manifests", "WINS_BACKUP_MANIFEST_DIR", "manifests",
                                       "manifest-old.json", 400)

    def test_pruner_directory_that_is_not_a_directory_is_1(self) -> None:
        notdir = self.tmp / "manifests-file"
        notdir.write_text("x")
        r = self.prune_alone(WINS_BACKUP_MANIFEST_DIR=str(notdir))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("exists but is not a directory", r.stderr)

    def test_pruner_genuinely_absent_directories_are_still_skipped(self) -> None:
        gone = self.tmp / "never-created"
        r = self.prune_alone(WINS_LOCAL_BACKUP_DIR=str(gone / "a"), WINS_LITESTREAM_REPLICA_DIR=str(gone / "b"),
                             WINS_BACKUP_MANIFEST_DIR=str(gone / "c"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("stage 1 local archives: 0 past", r.stdout)
        self.assertIn(f"stage 2 litestream history: {gone / 'b'} does not exist", r.stdout)
        self.assertIn("stage 3 sanitised manifests: 0 past", r.stdout)

    def test_pruner_uninspectable_backup_env_is_1(self) -> None:
        parent = self.tmp / "locked-env"
        parent.mkdir()
        (parent / "backup.env").write_text("BACKUP_RETENTION_DAYS=30\n")
        parent.chmod(0o000)
        try:
            r = self.prune_alone(WINS_BACKUP_ENV=str(parent / "backup.env"))
        finally:
            parent.chmod(0o700)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn(f"Could not inspect {parent / 'backup.env'}", r.stderr)

    def test_pruner_uninspectable_rclone_configuration_is_1(self) -> None:
        # Remote stages (not local-only), remote optional: an rclone.conf that
        # cannot be inspected is not "no rclone configuration".
        parent = self.tmp / "locked-rclone"
        parent.mkdir()
        (parent / "rclone.conf").write_text(CRYPT_CONF)
        parent.chmod(0o000)
        try:
            r = self.prune_alone(WINS_PRUNE_LOCAL_ONLY="0", WINS_RCLONE_CONFIG=str(parent / "rclone.conf"))
        finally:
            parent.chmod(0o700)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("remote copies are NOT being pruned", r.stderr)
        self.assertNotIn("no rclone configuration; remote stages skipped", r.stdout)

    def test_real_pruner_remote_outage_with_an_untraversable_manifest_parent_is_1(self) -> None:
        # Sol's exact N-14 chain: failed copy, failed listing, 400-day manifest
        # under a mode-000 parent. Round 4 returned 75.
        self.rclone_fake(copy_rc=1, lsjson_rc=1)
        r, _ = self.upload(real_prune=True, locked_manifest_parent=True)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("stage 3 sanitised manifests: could not inspect", r.stderr)
        self.assertIn("local retention pruning failed", r.stderr)
        self.assertTrue((self.tmp / "locked" / "manifests" / "manifest-old.json").exists())

    def test_uninspectable_rclone_configuration_stops_the_backup(self) -> None:
        # Remote optional: round 4 read an unreadable rclone.conf as "no
        # remote configured" and succeeded.
        self.rclone_fake()
        r, local = self.upload(required="0", locked_rclone_parent=True)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("could not inspect the rclone configuration", r.stderr)
        self.assertNotIn("rclone copy", self.calls.read_text() if self.calls.exists() else "")

    def test_uninspectable_rclone_configuration_keeps_the_archive(self) -> None:
        # Claude N-18: the night's archive is kept root-only (and local
        # retention enforced) before the run refuses.
        self.rclone_fake()
        r, local = self.upload(required="1", locked_rclone_parent=True)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("this archive was retained root-only", r.stderr)
        self.assertEqual(
            sorted(p.name for p in local.iterdir()),
            ["wins-hub-backup-hub-test-1.tar.gz.age", "wins-hub-backup-hub-test-1.tar.gz.age.sha256"],
        )
        self.assertIn("prune", self.calls.read_text())

    # --- R5-1 in the backup script's other guards (item 5) ------------------

    def run_slice(self, body: str, **env: str) -> subprocess.CompletedProcess:
        script = f"""
set -Eeuo pipefail
{STUBS}
{self.backup_helpers()}
{body}
echo SLICE_DONE
"""
        return run(script, env=self.env(**env))

    def test_backup_env_that_is_a_dangling_link_stops_the_backup(self) -> None:
        body = self.backup_slice('install -d -m 700 "${PAYLOAD_DIR}" "${UPLOAD_DIR}"\n', "# `hostname -s` is NOT unique")
        env_link = self.tmp / "backup.env"
        env_link.symlink_to(self.tmp / "missing-target")
        r = self.run_slice(f"BACKUP_ENV={str(env_link)!r}\n" + body)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("could not inspect backup.env", r.stderr)
        self.assertIn("dangling symbolic link", r.stderr)

    def test_backup_env_absent_or_present_behaves_as_before(self) -> None:
        body = self.backup_slice('install -d -m 700 "${PAYLOAD_DIR}" "${UPLOAD_DIR}"\n', "# `hostname -s` is NOT unique")
        r = self.run_slice(f"BACKUP_ENV={str(self.tmp / 'nope.env')!r}\n" + body)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        env_file = self.tmp / "backup.env"
        env_file.write_text("LSR_SOURCED=yes\n")
        r = self.run_slice(f"BACKUP_ENV={str(env_file)!r}\n" + body + 'echo "sourced=${LSR_SOURCED:-no}"\n')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("sourced=yes", r.stdout)

    def sources_slice(self) -> str:
        return "sources=(\n" + self.backup_slice("\nsources=(\n", "# A hub archive is state for a freshly installed")

    def source_tree(self) -> Path:
        root = self.tmp / "srcroot"
        for rel in ("root/vpn_auth/main.py", "root/vpn_auth.env", "etc/systemd/system/wins-hub.service",
                    "etc/iptables/rules.v4"):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text("x")
        (root / "etc/nginx").mkdir(parents=True, exist_ok=True)
        return root

    def test_optional_source_that_is_a_dangling_link_stops_the_backup(self) -> None:
        root = self.source_tree()
        (root / "etc/cloudflared").symlink_to(root / "missing")
        body = self.sources_slice()
        r = self.run_slice(f"SOURCE_ROOT={str(root)!r}\nroot_path() {{ printf '%s/%s' \"${{SOURCE_ROOT%/}}\" \"$1\"; }}\n" + body)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("could not inspect etc/cloudflared", r.stderr)

    def test_optional_sources_absent_are_still_skipped(self) -> None:
        root = self.source_tree()
        body = self.sources_slice()
        r = self.run_slice(f"SOURCE_ROOT={str(root)!r}\nroot_path() {{ printf '%s/%s' \"${{SOURCE_ROOT%/}}\" \"$1\"; }}\n"
                           + body + 'printf "present=%s\\n" "${present_sources[*]}"\n')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("etc/cloudflared", r.stdout.split("present=", 1)[1])

    def test_hub_database_that_is_a_dangling_link_stops_the_backup(self) -> None:
        body = self.backup_slice('chmod 600 "${PAYLOAD_DIR}/etc/winsvpn/hub-backup-recovery.env"\n',
                                 "# CP-10: the authority ledger")
        db = self.tmp / "vpn_users.db"
        db.symlink_to(self.tmp / "missing.db")
        r = self.run_slice(f"DB_SOURCE={str(db)!r}\n" + body)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("could not inspect the hub database", r.stderr)

    def test_authority_ledger_that_is_a_dangling_link_stops_the_backup(self) -> None:
        body = self.backup_slice("# CP-10: the authority ledger, from the same prepared consistent snapshot.\n",
                                 "# Archive live state directly")
        ledger = self.tmp / "winn3_authority_ledger.db"
        ledger.symlink_to(self.tmp / "missing.db")
        r = self.run_slice(f"LEDGER_SOURCE={str(ledger)!r}\n" + body)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("could not inspect the Winn3 authority ledger", r.stderr)

    def test_recipients_file_that_is_a_dangling_link_stops_the_backup(self) -> None:
        # With REQUIRE_BACKUP_ENCRYPTION=0, round 4 read an uninspectable
        # recipients file as "none configured" and shipped the archive as is.
        body = self.backup_slice("# --- F-8: independent encryption", '(cd "${UPLOAD_DIR}" && sha256sum').split("\n", 1)[1]
        link = self.tmp / "recipients.age"
        link.symlink_to(self.tmp / "missing-recipients")
        r = self.run_slice(f"BACKUP_AGE_RECIPIENTS_FILE={str(link)!r}\nREQUIRE_BACKUP_ENCRYPTION=0\n"
                           f"ARCHIVE=x\nARCHIVE_NAME=x\n" + body)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("could not inspect BACKUP_AGE_RECIPIENTS_FILE", r.stderr)

    # --- R5-4 (Sol N-17): the recipients permission check checks find -------

    def encryption(self, mode: int = 0o600, find_rc: str = "") -> subprocess.CompletedProcess:
        body = self.backup_slice("# --- F-8: independent encryption", '(cd "${UPLOAD_DIR}" && sha256sum').split("\n", 1)[1]
        upload = self.tmp / "enc-upload"
        upload.mkdir()
        (upload / "a.tar.gz").write_bytes(b"plain")
        recipients = self.tmp / "recipients.age"
        recipients.write_text("age1example\n")
        recipients.chmod(mode)
        write_fake(self.bin, "age", 'out=""; while [[ $# -gt 0 ]]; do [[ "$1" == -o ]] && out="$2"; shift; done; echo ct > "$out"\n')
        script = f"""
eval "$(declare -f find | sed '1s/^find/stub_find/')"
find() {{
  if [[ -n "${{FAKE_FIND_RC:-}}" ]]; then echo "find: $1: Input/output error" >&2; return "${{FAKE_FIND_RC}}"; fi
  stub_find "$@"
}}
UPLOAD_DIR={str(upload)!r}
ARCHIVE={str(upload / 'a.tar.gz')!r}
ARCHIVE_NAME=a.tar.gz
BACKUP_AGE_RECIPIENTS_FILE={str(recipients)!r}
{body}
echo "encrypted=${{ARCHIVE_NAME}}"
"""
        extra = {"FAKE_FIND_RC": find_rc} if find_rc else {}
        return self.run_slice(script, **extra)

    def test_a_failed_permission_find_stops_the_backup(self) -> None:
        r = self.encryption(find_rc="2")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("Could not inspect the permissions of BACKUP_AGE_RECIPIENTS_FILE (find failed, exit 2)", r.stderr)
        self.assertNotIn("encrypted=", r.stdout)

    def test_permission_check_still_encrypts_a_private_file(self) -> None:
        r = self.encryption()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("encrypted=a.tar.gz.age", r.stdout)

    def test_permission_check_still_refuses_a_group_writable_file(self) -> None:
        r = self.encryption(mode=0o620)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("writable by group or other", r.stderr)

    # --- R5-2 (Sol N-15): integrity failure exits 1, required or optional ----

    def test_real_pruner_copy_ok_but_hashes_differ_with_the_remote_optional_is_1(self) -> None:
        self.rclone_fake(copy_rc=0, cryptcheck_rc=1, lsjson_rc=0)
        r, local = self.upload(required="0", real_prune=True, through_end=True)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("FAILED integrity verification (REQUIRE_REMOTE_BACKUP=0)", r.stderr)
        self.assertNotIn("UPLOAD_SECTION_DONE", r.stdout)
        self.assertTrue((local / "wins-hub-backup-hub-test-1.tar.gz.age").is_file())

    def test_real_pruner_copy_ok_but_hashes_differ_with_the_remote_required_is_1(self) -> None:
        self.rclone_fake(copy_rc=0, cryptcheck_rc=1, lsjson_rc=0)
        r, local = self.upload(required="1", real_prune=True, through_end=True)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("FAILED integrity verification (REQUIRE_REMOTE_BACKUP=1)", r.stderr)
        self.assertTrue((local / "wins-hub-backup-hub-test-1.tar.gz.age").is_file())

    def test_remote_not_configured_runs_no_copy_and_no_check(self) -> None:
        # The migration's state: REQUIRE_REMOTE_BACKUP=0, no rclone.conf.
        self.rclone_fake()
        r, local = self.upload(required="0", with_rclone=False, real_prune=True, through_end=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        calls = self.calls.read_text() if self.calls.exists() else ""
        self.assertNotIn("rclone copy", calls)
        self.assertNotIn("rclone cryptcheck", calls)
        self.assertTrue((local / "wins-hub-backup-hub-test-1.tar.gz.age").is_file())

    # --- R4-2 (Sol N-12, Claude N-13): a failed enumeration fails the stage --

    def assert_enumeration_failure(self, r: subprocess.CompletedProcess, stage: str, survivor: Path) -> None:
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn(f"{stage}: could not enumerate", r.stderr)
        self.assertIn("local retention pruning failed", r.stderr)
        self.assertTrue(survivor.exists(), f"{survivor} must still be there (nothing was pruned blind)")

    def test_real_pruner_failed_archive_enumeration_is_1(self) -> None:
        self.rclone_fake(copy_rc=1, lsjson_rc=1)
        local_dir = self.tmp / "src/var/backups/winsvpn"
        r, local = self.upload(real_prune=True, stale_local=True, find_fail=str(local_dir))
        self.assert_enumeration_failure(r, "stage 1 local archives", local / "wins-hub-backup-hub-test-0.tar.gz.age")

    def test_real_pruner_failed_recent_history_enumeration_is_1(self) -> None:
        self.rclone_fake(copy_rc=1, lsjson_rc=1)
        replica = self.tmp / "litestream-replica"
        r, _ = self.upload(real_prune=True, litestream=True, find_fail=str(replica), find_fail_arg="-30")
        self.assert_enumeration_failure(r, "stage 2 litestream history (recent)", replica / "ltx" / "old.ltx")

    def test_real_pruner_failed_history_enumeration_is_1(self) -> None:
        self.rclone_fake(copy_rc=1, lsjson_rc=1)
        replica = self.tmp / "litestream-replica"
        r, _ = self.upload(real_prune=True, litestream=True, find_fail=str(replica), find_fail_arg="+30")
        self.assert_enumeration_failure(r, "stage 2 litestream history", replica / "ltx" / "old.ltx")

    def test_real_pruner_failed_manifest_enumeration_is_1(self) -> None:
        self.rclone_fake(copy_rc=1, lsjson_rc=1)
        r, _ = self.upload(real_prune=True, stale_manifest=True, find_fail=str(self.tmp / "manifests"))
        self.assert_enumeration_failure(r, "stage 3 sanitised manifests", self.tmp / "manifests" / "manifest-old.json")

    def test_real_pruner_unreadable_manifest_directory_is_1(self) -> None:
        # The real find, on a directory it cannot read.
        self.rclone_fake(copy_rc=1, lsjson_rc=1)
        r, _ = self.upload(real_prune=True, unreadable_manifests=True)
        self.assert_enumeration_failure(r, "stage 3 sanitised manifests", self.tmp / "manifests" / "manifest-old.json")
        self.assertIn("Permission denied", r.stderr)

    def test_real_pruner_prunes_history_and_manifests_when_enumeration_works(self) -> None:
        self.rclone_fake(copy_rc=1, lsjson_rc=1)
        r, _ = self.upload(real_prune=True, litestream=True, stale_manifest=True)
        self.assertEqual(r.returncode, 75, r.stdout + r.stderr)
        self.assertFalse((self.tmp / "litestream-replica" / "ltx" / "old.ltx").exists())
        self.assertTrue((self.tmp / "litestream-replica" / "ltx" / "fresh.ltx").exists())
        self.assertFalse((self.tmp / "manifests" / "manifest-old.json").exists())

    def test_successful_upload_is_unchanged(self) -> None:
        self.rclone_fake()
        r, local = self.upload()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("UPLOAD_SECTION_DONE", r.stdout)
        self.assertIn("integrity-verified", r.stdout)
        # No local archive is kept; only the empty verified-upload marker the
        # weekly freshness audit reads is written.
        self.assertEqual(sorted(p.name for p in local.iterdir()), ["remote-last-verified"])
        self.assertEqual((local / "remote-last-verified").stat().st_size, 0)

    def test_no_rclone_configuration_still_fails_with_1(self) -> None:
        self.rclone_fake()
        r, local = self.upload(with_rclone=False)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertTrue((local / "wins-hub-backup-hub-test-1.tar.gz.age").is_file())

    def test_optional_remote_failure_keeps_the_archive_and_continues(self) -> None:
        self.rclone_fake(copy_rc=1)
        r, local = self.upload(required="0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("UPLOAD_SECTION_DONE", r.stdout)
        self.assertTrue((local / "wins-hub-backup-hub-test-1.tar.gz.age").is_file())

    def test_drive_absent_backup_succeeds_locally(self) -> None:
        # Owner ruling 2026-10-02: no GCP, so no Drive credential exists. With
        # no rclone configuration and REQUIRE_REMOTE_BACKUP=0 the nightly run
        # keeps the encrypted archive root-only on the hub and succeeds.
        self.rclone_fake()
        r, local = self.upload(required="0", with_rclone=False)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("UPLOAD_SECTION_DONE", r.stdout)
        self.assertTrue((local / "wins-hub-backup-hub-test-1.tar.gz.age").is_file())
        self.assertFalse(self.calls.exists() and "rclone copy" in self.calls.read_text())

    def test_drive_absent_deploy_does_not_touch_rclone(self) -> None:
        self.rclone_fake()
        root = self.tmp / "root"
        body = function_definition("configure_rclone_credentials")
        for prefix in ("/root/.config", "/etc/winsvpn"):
            body = body.replace(prefix, str(root) + prefix)
        script = f"""
set -Eeuo pipefail
{STUBS}
validate_backup_retention_contract() {{ :; }}
validate_backup_encryption_contract() {{ :; }}
backup_encryption_live_check() {{ :; }}
resolve_backup_host_id() {{ RESOLVED_BACKUP_HOST_ID=hub-test; }}
RCLONE_REMOTE_DEFAULT=GoogleDrive_secured
REQUIRE_REMOTE_BACKUP_DEFAULT=1
BACKUP_RETENTION_DAYS_DEFAULT=30
BACKUP_MANIFEST_RETENTION_DAYS_DEFAULT=365
BACKUP_PRUNE_DRY_RUN_DEFAULT=0
REQUIRE_BACKUP_PRUNING_DEFAULT=1
BACKUP_AGE_RECIPIENTS_FILE_DEFAULT=/etc/winsvpn/backup-recipients.age
REQUIRE_BACKUP_ENCRYPTION_DEFAULT=1
LITESTREAM_REPLICA_URL_DEFAULT=''
WINS_SECRETS_FILE=/nonexistent/secrets.env
{body}
configure_rclone_credentials
"""
        r = run(script, env=self.env(REQUIRE_REMOTE_BACKUP="0"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Remote backup is disabled", r.stderr)
        self.assertFalse(self.calls.exists() and "rclone" in self.calls.read_text())
        self.assertIn("REQUIRE_REMOTE_BACKUP=0", (root / "etc/winsvpn/backup.env").read_text())

    def test_a_non_crypt_remote_still_refuses_to_upload(self) -> None:
        self.rclone_fake(kind="drive")
        r, local = self.upload()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertNotIn("rclone copy", self.calls.read_text())

    # --- the deploy's first backup ----------------------------------------

    def initial(self, start_rc: int, status: str, show_rc: int = 0, required: str = "1", ran: bool = True,
                before: str = "1000", before_fails: bool = False, active_polls: int = 0,
                timer_status: str = "0", active_fails: bool = False,
                timer_active: bool = True, run_stamp: str = "2000",
                clock: tuple[str, str] = ("1900", "2100"), clock_fails: str = "",
                late: tuple[str, ...] | None = None,
                race: tuple[str, ...] | None = None, run_exit: str | None = None,
                snap_active: str | None = None, reread_fails: bool = False,
                snap_omit: tuple[str, ...] = (), snap_fails: bool = False) -> subprocess.CompletedProcess:
        """A per-query fake of the backup unit (LSR R8 to R11).

        - `ActiveState` is "activating" for the first `active_polls` reads (a
          timer-started run in progress), then "inactive"; when that run ends
          its start timestamp becomes 1500 and its status `timer_status`.
          `active_fails` makes every ActiveState read fail.
        - The first ExecMainStartTimestampMonotonic read is the baseline:
          `before`, or a failed read when `before_fails`. Later reads give the
          current timestamp.
        - `start` begins a new run (timestamp `run_stamp`, status `status`)
          only when `ran`; it exits `start_rc` either way. A `run_stamp` inside
          the clock window is a run that began during the start (the deploy's
          own, or a timer job queued behind the snapshot that the start
          joined); one before the window is a run the start merged into.
        - Each run also has an exit timestamp and a unit state. The run the
          start began ends at `run_exit` (default `run_stamp` + 50, inside
          the default window) and leaves the unit "failed" (status not 0) or
          "inactive".
        - `python3` is the monotonic clock and answers only the exact shipped
          expression (CLOCK_MONOTONIC in microseconds, Claude N-30): the
          first read gives `clock[0]` (just before the start), later reads
          `clock[1]` (just after it returned). `clock_fails` "before" or
          "after" fails that read.
        - `late` (timestamp, status[, exit, state]): a run the timer began,
          visible from the first timestamp read after the start; by default
          still running (exit 0, "activating").
        - `race` (timestamp, status[, exit, state]): what the status read
          sees; by default a run that has ended (exit 2200, after the
          default window, "inactive"). The same timestamp as `late` is the
          admitted timer run finishing (Sol N-30).
        - The one-call snapshot is a `show` without `--value`. Like systemd
          255 it prints `Name=value` only for the properties requested, in
          its reply order (start, exit, status, state, as measured on l80),
          and nothing for one it does not know (Claude N-33).
          `snap_active` replaces its state value ("" prints `ActiveState=`);
          `snap_omit` leaves properties out of the reply; `reread_fails`
          leaves out the start timestamp (and fails a separate third
          timestamp read, as round 9 made); `snap_fails` fails only this
          call.
        - ExecMainStatus is the current status: `status` after a new run, or
          the earlier run's left behind.
        - `show_rc` (non-zero) makes every show query fail, as before.
        - `timer_active`: whether wins-hub-backup.timer is active (it keeps
          the unit loaded between runs on systemd 255).
        """
        state = self.tmp / "unit-state"
        state.mkdir(exist_ok=True)
        (state / "stamp").write_text(before)
        (state / "status").write_text(status)
        (state / "polls").write_text("0")
        (state / "stamp_reads").write_text("0")
        (state / "clock_reads").write_text("0")
        if run_exit is None:
            run_exit = str(int(run_stamp) + 50) if run_stamp.isdigit() else "0"

        def move(run: tuple[str, ...] | None, exit_default: str, state_default: str) -> str:
            if not run:
                return ":"
            stamp_, status_ = run[0], run[1]
            exit_ = run[2] if len(run) > 2 else exit_default
            state_ = run[3] if len(run) > 3 else state_default
            return (f"echo {stamp_!r} > \"$S/stamp\"; echo {status_!r} > \"$S/status\"; "
                    f"echo {exit_!r} > \"$S/exit\"; echo {state_!r} > \"$S/state\"")

        late_sh = move(late, "0", "activating")
        race_sh = move(race, "2200", "inactive")
        ran_state = "inactive" if status == "0" else "failed"
        (state / "exit").write_text("0")
        (state / "state").write_text("inactive")
        write_fake(
            self.bin,
            "python3",
            f"""
            S={str(state)!r}
            echo "clock" >> {str(self.calls)!r}
            [[ $# -eq 2 && "$1" == -c && "$2" == 'import time; print(time.clock_gettime_ns(time.CLOCK_MONOTONIC) // 1000)' ]] || exit 2
            c=$(cat "$S/clock_reads"); echo $((c + 1)) > "$S/clock_reads"
            if (( c == 0 )); then
              [[ {clock_fails!r} != before ]] || exit 1
              echo {clock[0]!r}
            else
              [[ {clock_fails!r} != after ]] || exit 1
              echo {clock[1]!r}
            fi
            """,
        )
        write_fake(
            self.bin,
            "systemctl",
            f"""
            S={str(state)!r}
            echo "systemctl $*" >> {str(self.calls)!r}
            case "$1" in
              is-active)
                [[ "$*" == *wins-hub-backup.timer* ]] || exit 3
                exit {0 if timer_active else 3} ;;
              start)
                if [[ {1 if ran else 0} -eq 1 ]]; then
                  echo {run_stamp!r} > "$S/stamp"; echo {status!r} > "$S/status"
                  echo {run_exit!r} > "$S/exit"; echo {ran_state!r} > "$S/state"
                fi
                exit {start_rc} ;;
              show)
                [[ {show_rc} -eq 0 ]] || exit {show_rc}
                if [[ " $* " != *" --value "* ]]; then
                  [[ {1 if snap_fails else 0} -eq 0 ]] || exit 1
                  {race_sh}
                  st=$(cat "$S/state"); [[ {0 if snap_active is None else 1} -eq 0 ]] || st={(snap_active or "")!r}
                  want=" ${{*}} "
                  omit={" ".join(snap_omit + (("ExecMainStartTimestampMonotonic",) if reread_fails else ()))!r}
                  for prop in ExecMainStartTimestampMonotonic ExecMainExitTimestampMonotonic ExecMainStatus ActiveState; do
                    [[ "$want" == *" -p $prop "* ]] || continue
                    [[ " $omit " != *" $prop "* ]] || continue
                    case "$prop" in
                      ExecMainStartTimestampMonotonic) echo "$prop=$(cat "$S/stamp")" ;;
                      ExecMainExitTimestampMonotonic) echo "$prop=$(cat "$S/exit")" ;;
                      ExecMainStatus) echo "$prop=$(cat "$S/status")" ;;
                      ActiveState) echo "$prop=$st" ;;
                    esac
                  done
                  exit 0
                fi
                case "$*" in
                  *ActiveState*)
                    [[ {1 if active_fails else 0} -eq 0 ]] || exit 1
                    n=$(cat "$S/polls"); echo $((n + 1)) > "$S/polls"
                    if (( n < {active_polls} )); then echo activating; exit 0; fi
                    if (( n == {active_polls} && {active_polls} > 0 )); then echo 1500 > "$S/stamp"; echo {timer_status!r} > "$S/status"; fi
                    echo inactive ;;
                  *ExecMainStartTimestampMonotonic*)
                    r=$(cat "$S/stamp_reads"); echo $((r + 1)) > "$S/stamp_reads"
                    if (( r == 0 )) && [[ {1 if before_fails else 0} -eq 1 ]]; then exit 1; fi
                    if (( r == 1 )); then {late_sh}; fi
                    if (( r == 2 )) && [[ {1 if reread_fails else 0} -eq 1 ]]; then exit 1; fi
                    cat "$S/stamp" ;;
                  *ExecMainStatus*) {race_sh}; cat "$S/status" ;;
                  *) exit 0 ;;
                esac ;;
            esac
            """,
        )
        script = f"""
set -Eeuo pipefail
{STUBS}
sleep() {{ echo "sleep $*" >> {str(self.calls)!r}; }}
RCLONE_REMOTE_DEFAULT=GoogleDrive_secured
{function_definition("run_initial_backup")}
run_initial_backup
"""
        return run(script, env=self.env(REQUIRE_REMOTE_BACKUP=required))

    def test_first_backup_remote_outage_does_not_stop_cutover(self) -> None:
        r = self.initial(start_rc=1, status="75")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("[WARN]", r.stderr)
        self.assertIn("rclone copy to the remote", r.stderr)
        self.assertIn("failed (remote unavailable)", r.stderr)

    def test_any_other_first_backup_failure_still_stops_cutover(self) -> None:
        for status, show_rc in (("1", 0), ("0", 0), ("", 0), ("75", 1)):
            r = self.initial(start_rc=1, status=status, show_rc=show_rc)
            self.assertNotEqual(r.returncode, 0, f"status={status!r} show_rc={show_rc}: {r.stderr}")
            self.assertIn("Public cutover was not performed", r.stderr)

    # --- R7-1 (Claude N-21): a backup that did not run is never read -------

    def test_a_stale_75_after_a_failed_snapshot_unit_stops_cutover(self) -> None:
        # An earlier run exited 75; this start never ran the backup (its
        # snapshot unit failed), so ExecMainStatus is still that old 75.
        for required in ("0", "1"):
            with self.subTest(required=required):
                r = self.initial(start_rc=1, status="75", ran=False, required=required)
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertIn("did not run this time", r.stderr)
                self.assertNotIn("rclone copy to the remote", r.stderr)

    def test_a_first_ever_start_that_never_ran_stops_cutover(self) -> None:
        r = self.initial(start_rc=1, status="0", ran=False, before="0")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("did not run this time", r.stderr)

    def test_a_real_new_75_continues(self) -> None:
        r = self.initial(start_rc=1, status="75", ran=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("failed (remote unavailable)", r.stderr)

    def test_a_real_new_1_stops_cutover(self) -> None:
        for required in ("0", "1"):
            with self.subTest(required=required):
                r = self.initial(start_rc=1, status="1", ran=True, required=required)
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertIn("Public cutover was not performed", r.stderr)
                self.assertNotIn("did not run this time", r.stderr)

    # --- R8 (Sol N-25, N-26; Claude N-24, N-25) ------------------------------

    def test_an_unreadable_baseline_stops_before_the_start(self) -> None:
        # Sol N-25: baseline read fails, later reads work, the start would run
        # nothing and leave the earlier 75.
        for required in ("0", "1"):
            with self.subTest(required=required):
                r = self.initial(start_rc=1, status="75", ran=False, before_fails=True, required=required)
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertIn("Could not read the start timestamp", r.stderr)
                self.assertNotIn("systemctl start", self.calls.read_text())

    def test_a_baseline_of_0_is_valid(self) -> None:
        r = self.initial(start_rc=0, status="0", ran=True, before="0")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_successful_start_without_a_new_run_stops_cutover(self) -> None:
        # Sol N-26: a start that returns 0 but began no new invocation.
        for required in ("0", "1"):
            with self.subTest(required=required):
                r = self.initial(start_rc=0, status="0", ran=False, required=required)
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertIn("did not run this time", r.stderr)

    def test_a_timer_run_in_progress_is_waited_for_then_a_new_run_counts(self) -> None:
        # The timer's run is in progress for 3 polls and fails; the deploy's
        # own new run then succeeds and is what counts.
        r = self.initial(start_rc=0, status="0", ran=True, active_polls=3, timer_status="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.calls.read_text().splitlines()
        self.assertEqual(sum(1 for c in calls if c == "sleep 5"), 3)
        start = calls.index("systemctl start wins-hub-backup.service")
        last_state = max(i for i, c in enumerate(calls) if "ActiveState" in c)
        self.assertGreater(start, last_state, "the deploy starts its own run only after the timer's run ended")

    def test_a_timer_run_in_progress_that_succeeds_does_not_stand_in_for_the_deploys_run(self) -> None:
        r = self.initial(start_rc=0, status="0", ran=False, active_polls=2, timer_status="0")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("did not run this time", r.stderr)

    def test_a_run_that_never_ends_stops_after_the_bound(self) -> None:
        r = self.initial(start_rc=0, status="0", ran=True, active_polls=10_000)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("still running (activating) after 30 minutes", r.stderr)
        self.assertEqual(self.calls.read_text().count("sleep 5"), 360)
        self.assertNotIn("systemctl start", self.calls.read_text())

    def test_an_unreadable_unit_state_stops_before_the_start(self) -> None:
        r = self.initial(start_rc=0, status="0", ran=True, active_fails=True)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("Could not read the state of wins-hub-backup.service", r.stderr)
        self.assertNotIn("systemctl start", self.calls.read_text())

    def test_an_inactive_backup_timer_stops_before_the_start(self) -> None:
        # Measured on systemd 255: without the timer referencing it, a oneshot
        # is unloaded after a successful run and its start timestamp reads 0.
        r = self.initial(start_rc=0, status="0", ran=True, timer_active=False)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("wins-hub-backup.timer is not active", r.stderr)
        self.assertNotIn("systemctl start", self.calls.read_text())

    def test_a_run_that_started_and_failed_says_so(self) -> None:
        # Claude N-25: "did not run" only when no new run happened.
        r = self.initial(start_rc=1, status="1", ran=True, required="1")
        self.assertIn("ran and failed (exit status 1)", r.stderr)
        self.assertNotIn("did not run this time", r.stderr)

    # --- R9 (Sol N-27): only a run that began inside the start window -------

    def test_the_clock_brackets_the_start(self) -> None:
        r = self.initial(start_rc=0, status="0", ran=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.calls.read_text().splitlines()
        start = calls.index("systemctl start wins-hub-backup.service")
        self.assertEqual(calls[start - 1], "clock", "the window opens immediately before the start")
        self.assertEqual(calls[start + 1], "clock", "the window closes immediately after the start returns")
        baseline = next(i for i, c in enumerate(calls) if "ExecMainStartTimestampMonotonic" in c)
        self.assertLess(baseline, start - 1)

    def test_a_timer_job_queued_into_the_start_window_counts(self) -> None:
        # The Claude seat's l80 case: the timer queued a job behind the
        # snapshot after the baseline; the start joined it and its one run
        # began inside the window, running the installed script.
        for start_rc, status, rc in ((0, "0", 0), (1, "75", 0), (1, "1", 1)):
            with self.subTest(status=status):
                r = self.initial(start_rc=start_rc, status=status, ran=True, run_stamp="1950")
                self.assertEqual(r.returncode, rc, r.stderr)
                self.assertNotIn("began before", r.stderr)

    def test_a_run_that_began_before_the_start_is_not_counted(self) -> None:
        # A timer run began after the baseline but before the start, which
        # merged into it: new, but not inside the window.
        for required in ("0", "1"):
            with self.subTest(required=required):
                r = self.initial(start_rc=0, status="0", ran=True, run_stamp="1200", required=required)
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertIn("began before the start", r.stderr)
                self.assertIn("Public cutover was not performed", r.stderr)

    def test_a_timer_run_after_the_start_returned_does_not_mask_the_deploys_failure(self) -> None:
        # Sol N-27, interleaving 2: the deploy's own run exits 1, then the
        # timer begins a run (75) before the inspection.
        for required in ("0", "1"):
            with self.subTest(required=required):
                r = self.initial(start_rc=1, status="1", ran=True, late=("3000", "75"), required=required)
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertIn("began after this deploy's start returned", r.stderr)
                self.assertNotIn("failed (remote unavailable)", r.stderr)

    def test_a_timer_run_after_a_successful_start_returned_stops(self) -> None:
        for required in ("0", "1"):
            with self.subTest(required=required):
                r = self.initial(start_rc=0, status="0", ran=True, late=("3000", "0"), required=required)
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertIn("began after this deploy's start returned", r.stderr)

    def test_a_run_beginning_between_the_check_and_the_status_read_stops(self) -> None:
        for required in ("0", "1"):
            with self.subTest(required=required):
                r = self.initial(start_rc=1, status="1", ran=True, race=("3000", "75"), required=required)
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertIn("while this deploy was reading its first backup's exit status", r.stderr)
                self.assertNotIn("failed (remote unavailable)", r.stderr)

    def test_a_failed_clock_read_before_the_start_stops_before_the_start(self) -> None:
        for required in ("0", "1"):
            with self.subTest(required=required):
                r = self.initial(start_rc=0, status="0", ran=True, clock_fails="before", required=required)
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertIn("Could not read the monotonic clock before the first backup", r.stderr)
                self.assertNotIn("systemctl start", self.calls.read_text())

    def test_a_failed_clock_read_after_the_start_stops(self) -> None:
        for required in ("0", "1"):
            with self.subTest(required=required):
                r = self.initial(start_rc=1, status="75", ran=True, clock_fails="after", required=required)
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertIn("Could not read the monotonic clock after the first backup's start returned", r.stderr)
                self.assertNotIn("failed (remote unavailable)", r.stderr)

    # --- R10 (Sol N-30; Claude N-30, N-31): after a failed start the counted
    # run must also have finished inside the window -------------------------

    def test_sols_n30_sequence_stops(self) -> None:
        # Sol's exact fake sequence: the deploy's run exits 1; a timer run
        # begins inside the window (2050, still running at the timestamp
        # read) and has finished with 75 by the status read.
        for required in ("0", "1"):
            with self.subTest(required=required):
                r = self.initial(start_rc=1, status="1", run_stamp="2000", required=required,
                                 late=("2050", "0"), race=("2050", "75"), clock=("1900", "2100"))
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertIn("did not finish inside this deploy's start window", r.stderr)
                self.assertNotIn("failed (remote unavailable)", r.stderr)

    def test_an_admitted_run_still_running_at_the_status_read_stops(self) -> None:
        for required in ("0", "1"):
            with self.subTest(required=required):
                r = self.initial(start_rc=1, status="1", required=required, late=("2050", "0"))
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertIn("was still running (activating) when its exit status was read", r.stderr)

    def test_the_deploys_own_failed_run_inside_the_window_counts(self) -> None:
        # The deploy's own run exited before its start returned: 2000 to 2050
        # inside 1900 to 2100. 75 continues with the warning, 1 stops.
        for required in ("0", "1"):
            with self.subTest(required=required, status="75"):
                r = self.initial(start_rc=1, status="75", required=required)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn("failed (remote unavailable)", r.stderr)
                self.assertIn("ExecMainExitTimestampMonotonic", self.calls.read_text())
            with self.subTest(required=required, status="1"):
                r = self.initial(start_rc=1, status="1", required=required)
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertIn("ran and failed (exit status 1)", r.stderr)
        r = self.initial(start_rc=1, status="75", run_exit="2100")
        self.assertEqual(r.returncode, 0, "an exit at the second clock reading is inside the window: " + r.stderr)

    def test_a_run_whose_end_is_missing_or_outside_the_window_stops(self) -> None:
        for run_exit in ("0", "1990", "2000", "2101", "", "abc"):
            with self.subTest(run_exit=run_exit):
                r = self.initial(start_rc=1, status="75", run_exit=run_exit)
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertIn("did not finish inside this deploy's start window", r.stderr)
                self.assertNotIn("failed (remote unavailable)", r.stderr)

    def test_a_unit_still_deactivating_at_the_status_read_stops(self) -> None:
        r = self.initial(start_rc=1, status="75", snap_active="deactivating")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("was still running (deactivating)", r.stderr)

    def test_only_the_timestamp_reread_failing_stops(self) -> None:
        # Claude N-31 X10: the status reads 75 and the run ended inside the
        # window, but its start timestamp cannot be read again.
        for required in ("0", "1"):
            with self.subTest(required=required):
                r = self.initial(start_rc=1, status="75", reread_fails=True, required=required)
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertNotIn("failed (remote unavailable)", r.stderr)

    # --- R11 (Sol N-33; Claude N-33): the state must be present and finished;
    # the snapshot is the only status read --------------------------------

    def test_sols_n33_reply_without_a_state_stops(self) -> None:
        # Sol's exact reply: start 2000, exit 2050, window close 2100,
        # status 75, no ActiveState line.
        for required in ("0", "1"):
            with self.subTest(required=required):
                r = self.initial(start_rc=1, status="75", run_stamp="2000", run_exit="2050",
                                 clock=("1900", "2100"), snap_omit=("ActiveState",), required=required)
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertIn("was missing or not inactive or failed", r.stderr)
                self.assertNotIn("failed (remote unavailable)", r.stderr)

    def test_an_empty_or_unknown_state_stops(self) -> None:
        for value in ("", "maintenance", "Failed", "unknown", "inactive "):
            with self.subTest(state=value):
                r = self.initial(start_rc=1, status="75", snap_active=value)
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertIn("was missing or not inactive or failed", r.stderr)

    def test_a_finished_state_inactive_or_failed_counts(self) -> None:
        for value in ("inactive", "failed"):
            with self.subTest(state=value):
                r = self.initial(start_rc=1, status="75", snap_active=value)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn("failed (remote unavailable)", r.stderr)

    def test_only_the_snapshot_call_failing_stops(self) -> None:
        for required in ("0", "1"):
            with self.subTest(required=required):
                r = self.initial(start_rc=1, status="75", snap_fails=True, required=required)
                self.assertNotEqual(r.returncode, 0, r.stderr)
                self.assertNotIn("failed (remote unavailable)", r.stderr)

    def test_the_snapshot_requests_all_four_values_and_no_status_read_follows(self) -> None:
        r = self.initial(start_rc=1, status="75")
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.calls.read_text().splitlines()
        snaps = [i for i, c in enumerate(calls) if c.startswith("systemctl show") and "--value" not in c]
        self.assertEqual(len(snaps), 1, calls)
        for prop in ("ActiveState", "ExecMainStartTimestampMonotonic", "ExecMainExitTimestampMonotonic", "ExecMainStatus"):
            self.assertIn(f"-p {prop} ", calls[snaps[0]] + " ")
        self.assertFalse([c for c in calls if "ExecMainStatus" in c and "--value" in c],
                         "the exit status is read only from the snapshot")
        self.assertFalse([c for c in calls[snaps[0] + 1:] if c.startswith("systemctl show")],
                         "no unit read follows the snapshot")

    def test_a_real_new_0_continues(self) -> None:
        r = self.initial(start_rc=0, status="0", ran=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_first_backup_failure_with_the_remote_optional_stops_cutover(self) -> None:
        # Sol N-18: REQUIRE_REMOTE_BACKUP=0 no longer turns a failed backup
        # (exit 1: a local stage, an inspection or an integrity check) into 0.
        r = self.initial(start_rc=1, status="1", required="0")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("with the remote optional", r.stderr)
        self.assertIn("Public cutover was not performed", r.stderr)
        self.assertIn("systemctl show", self.calls.read_text())

    def test_first_backup_outage_with_the_remote_optional_still_continues(self) -> None:
        r = self.initial(start_rc=1, status="75", required="0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("failed (remote unavailable)", r.stderr)

    def test_first_backup_with_no_remote_configured_is_unchanged(self) -> None:
        r = self.initial(start_rc=0, status="0", required="0")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_integrity_failure_with_the_remote_optional_stops_cutover_end_to_end(self) -> None:
        # The uploader's real exit status, fed to the deploy caller as the
        # unit's ExecMainStatus: copy OK, cryptcheck fails, remote optional.
        self.rclone_fake(copy_rc=0, cryptcheck_rc=1, lsjson_rc=0)
        up, local = self.upload(required="0", real_prune=True, through_end=True)
        self.assertEqual(up.returncode, 1, up.stdout + up.stderr)
        self.assertTrue((local / "wins-hub-backup-hub-test-1.tar.gz.age").is_file())
        r = self.initial(start_rc=1, status=str(up.returncode), required="0")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("Public cutover was not performed", r.stderr)

    def test_remote_not_configured_end_to_end_lets_cutover_continue(self) -> None:
        self.rclone_fake()
        up, _ = self.upload(required="0", with_rclone=False, real_prune=True, through_end=True)
        self.assertEqual(up.returncode, 0, up.stdout + up.stderr)
        r = self.initial(start_rc=0, status=str(up.returncode), required="0")
        self.assertEqual(r.returncode, 0, r.stderr)

    # --- R6-4 (Claude N-19): the cases the seat's mutants S8, S1, S6 needed

    def test_pruner_follows_a_symlinked_stage_directory(self) -> None:
        real = self.tmp / "real-archives"
        real.mkdir()
        old = real / "wins-hub-backup-hub-test-0.tar.gz.age"
        old.write_text("old")
        os.utime(old, (time.time() - 40 * 86400,) * 2)
        link = self.tmp / "archives-link"
        link.symlink_to(real)
        r = self.prune_alone(WINS_LOCAL_BACKUP_DIR=str(link))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(old.exists(), "a symlinked stage directory is pruned through, not refused")

    def test_pruner_never_follows_a_symlink_inside_a_stage_directory(self) -> None:
        # Claude N-23 T8: an archive-named symlink inside the stage directory
        # pointing at an expired file outside it; the outside file must stay.
        stage = self.tmp / "archives"
        stage.mkdir()
        outside = self.tmp / "outside-precious.dat"
        outside.write_text("precious\n")
        os.utime(outside, (time.time() - 40 * 86400,) * 2)
        link = stage / "wins-hub-backup-hub-test-0.tar.gz.age"
        link.symlink_to(outside)
        r = self.prune_alone(WINS_LOCAL_BACKUP_DIR=str(stage))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(outside.exists())
        self.assertEqual(outside.read_text(), "precious\n")
        # Not even the link is treated as an archive: only regular files below
        # the stage directory are pruned (GNU shred would follow it and
        # overwrite the target; on macOS the fallback rm removes the link).
        self.assertTrue(link.is_symlink(), "a symlink inside the stage directory is not an archive")
        self.assertIn("stage 1 local archives: 0 past", r.stdout)

    def test_pruner_stage_directory_under_a_regular_file_is_1(self) -> None:
        notdir = self.tmp / "a-file"
        notdir.write_text("x")
        r = self.prune_alone(WINS_BACKUP_MANIFEST_DIR=str(notdir / "manifests"))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("Not a directory", r.stderr)

    def test_pruner_backup_env_that_is_not_a_file_is_1(self) -> None:
        env_dir = self.tmp / "backup.env"
        env_dir.mkdir()
        r = self.prune_alone(WINS_BACKUP_ENV=str(env_dir))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    def test_successful_first_backup_is_unchanged(self) -> None:
        r = self.initial(start_rc=0, status="0")
        self.assertEqual(r.returncode, 0, r.stderr)
        # R7: the start timestamp is read before starting; a successful start
        # reads no exit status.
        self.assertNotIn("ExecMainStatus", self.calls.read_text())


# --------------------------------------------------------------------------
# LSR R6 (Sol N-19 and the sweep): a failed permission inspection never passes
# --------------------------------------------------------------------------


class PermissionInspection(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="lsr-perm-"))
        self.key = self.tmp / "wins_litestream_ed25519"
        self.key.write_text("not really a key\n")
        self.key.chmod(0o644)

    def tearDown(self) -> None:
        for path in self.tmp.rglob("*"):
            try:
                path.chmod(0o700)
            except OSError:
                pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def call(self, functions: list[str], call: str, prelude: str = "", **env: str) -> subprocess.CompletedProcess:
        body = "\n".join(optional_functions(f) for f in functions)
        script = f"""
set -Eeuo pipefail
{STUBS}
{prelude}
{body}
{call}
echo CALL_RETURNED_0
"""
        base = {"PATH": os.environ.get("PATH", "")}
        base.update(env)
        return run(script, env=base)

    # --- the Litestream SFTP client key (R6-2) ------------------------------

    def test_key_validator_refuses_when_find_fails(self) -> None:
        r = self.call(["litestream_sftp_key_ok"], f"litestream_sftp_key_ok {str(self.key)!r}", FAKE_FIND_RC="2")
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn("Could not inspect the permissions of the Litestream SFTP client key (find failed, exit 2)", r.stderr)

    def test_key_validator_still_refuses_a_0644_key(self) -> None:
        r = self.call(["litestream_sftp_key_ok"], f"litestream_sftp_key_ok {str(self.key)!r}")
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn("must have mode 0600 or stricter", r.stderr)

    # --- the final secret-permission floor (R6-2 and the sweep) -------------

    FLOOR = ["control_path_absent", "control_flag_is_on", "verify_control_secret_permissions"]

    def floor(self, specs: str, **env: str) -> subprocess.CompletedProcess:
        prelude = f"control_secret_path_specs() {{ {specs}; }}\nCONTROL_DISK_ENCRYPTION_EFFECTIVE=luks\n"
        return self.call(self.FLOOR, "verify_control_secret_permissions", prelude=prelude, **env)

    def test_floor_refuses_when_find_fails(self) -> None:
        r = self.floor(f"printf '%s\\n' {str(self.key) + '|077|test key'!r}", FAKE_FIND_RC="2")
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn(f"Could not inspect the permissions of secret path {self.key} (test key) (find failed, exit 2)", r.stderr)

    def test_floor_still_passes_a_private_key_and_refuses_a_0644_one(self) -> None:
        r = self.floor(f"printf '%s\\n' {str(self.key) + '|077|test key'!r}")
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn("is accessible beyond its owner", r.stderr)
        self.key.chmod(0o600)
        r = self.floor(f"printf '%s\\n' {str(self.key) + '|077|test key'!r}")
        self.assertIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn("verified across 1 existing path", r.stderr)

    def test_floor_refuses_a_secret_path_it_cannot_inspect(self) -> None:
        locked = self.tmp / "locked"
        locked.mkdir()
        hidden = locked / "secret.env"
        hidden.write_text("x\n")
        hidden.chmod(0o600)
        locked.chmod(0o000)
        r = self.floor(f"printf '%s\\n' {str(hidden) + '|077|hidden secret'!r}")
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn(f"Secret path {hidden} (hidden secret) could not be inspected", r.stderr)

    def test_floor_skips_a_confirmed_absent_path(self) -> None:
        r = self.floor(f"printf '%s\\n' {str(self.tmp / 'nope') + '|077|absent secret'!r}")
        self.assertIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn("verified across 0 existing path", r.stderr)

    def test_floor_refuses_when_the_secret_list_cannot_be_produced(self) -> None:
        r = self.floor("printf '%s\\n' /x\\|077\\|y; return 1")
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn("Could not enumerate the control-plane secret paths", r.stderr)

    def specs(self, **env: str) -> subprocess.CompletedProcess:
        # Every secret directory the list walks is pointed into the test tree,
        # so the host's own /etc/ssh or /var/backups never decide the result.
        for var in ("CONTROL_SSH_HOST_KEY_DIR", "WINS_LOCAL_BACKUP_DIR", "WINS_BACKUP_MANIFEST_DIR", "APP_DIR",
                    "CONTROL_ALERTS_DIR", "WINN_CREDENTIALS_DIR"):
            env.setdefault(var, str(self.tmp / f"no-{var.lower()}"))
        return self.call(["control_path_absent", "secret_dir_entries", "control_secret_path_specs"],
                         "control_secret_path_specs", **env)

    def test_secret_list_fails_when_a_secret_directory_cannot_be_listed(self) -> None:
        creds = self.tmp / "credentials"
        creds.mkdir()
        (creds / "a.cred").write_text("x")
        r = self.specs(WINN_CREDENTIALS_DIR=str(creds), FAKE_FIND_RC="2", FAKE_FIND_PATH=str(creds))
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn(f"Could not list {creds} (find failed)", r.stderr)

    def test_secret_list_fails_when_a_secret_directory_cannot_be_inspected(self) -> None:
        locked = self.tmp / "locked2"
        (locked / "credentials").mkdir(parents=True)
        locked.chmod(0o000)
        r = self.specs(WINN_CREDENTIALS_DIR=str(locked / "credentials"))
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn("cannot inspect", r.stderr)

    def test_secret_list_lists_directory_entries_and_skips_absent_directories(self) -> None:
        creds = self.tmp / "credentials"
        creds.mkdir()
        (creds / "a.cred").write_text("x")
        r = self.specs(WINN_CREDENTIALS_DIR=str(creds))
        self.assertIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn(f"{creds / 'a.cred'}|077|winn-server credential file", r.stdout)

    # --- the other permission checks the sweep fixed ------------------------

    def test_trusted_env_gate_refuses_when_find_fails_on_the_file(self) -> None:
        env_file = self.tmp / "defaults.env"
        env_file.write_text("X=1\n")
        env_file.chmod(0o600)
        r = self.call(["wins_require_trusted_env_file"], f"wins_require_trusted_env_file {str(env_file)!r} WINS_DEFAULTS_FILE",
                      FAKE_FIND_RC="2", FAKE_FIND_PATH=str(env_file))
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn(f"Could not inspect the permissions of WINS_DEFAULTS_FILE {env_file} (find failed, exit 2)", r.stderr)

    def test_trusted_env_gate_refuses_when_find_fails_on_an_ancestor(self) -> None:
        env_file = self.tmp / "defaults.env"
        env_file.write_text("X=1\n")
        env_file.chmod(0o600)
        r = self.call(["wins_require_trusted_env_file"], f"wins_require_trusted_env_file {str(env_file)!r} WINS_DEFAULTS_FILE",
                      FAKE_FIND_RC="2", FAKE_FIND_PATH=str(self.tmp))
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn(f"Could not inspect the permissions of WINS_DEFAULTS_FILE ancestor {self.tmp}", r.stderr)

    def test_recipients_preflight_refuses_when_find_fails(self) -> None:
        rec = self.tmp / "backup-recipients.age"
        rec.write_text("age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs\n")
        rec.chmod(0o600)
        prelude = "REQUIRE_BACKUP_ENCRYPTION_DEFAULT=1\nBACKUP_AGE_RECIPIENTS_FILE_DEFAULT=''\nbackup_encryption_owner_instructions() { :; }\n"
        r = self.call(["validate_backup_encryption_contract"], "validate_backup_encryption_contract", prelude=prelude,
                      BACKUP_AGE_RECIPIENTS_FILE=str(rec), FAKE_FIND_RC="2")
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn("Could not inspect the permissions of BACKUP_AGE_RECIPIENTS_FILE (find failed, exit 2)", r.stderr)

    def test_rclone_source_preflight_refuses_when_find_fails(self) -> None:
        conf = self.tmp / "rclone.conf"
        conf.write_text(CRYPT_CONF)
        conf.chmod(0o600)
        prelude = "REQUIRE_REMOTE_BACKUP_DEFAULT=1\nRCLONE_REMOTE_DEFAULT=GoogleDrive_secured\nWINS_SECRETS_FILE=/x\n"
        r = self.call(["rclone_crypt_remote_contract", "validate_rclone_injection_contract"], "validate_rclone_injection_contract",
                      prelude=prelude, RCLONE_CONFIG_SOURCE=str(conf), FAKE_FIND_RC="2")
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn("Could not inspect the permissions of RCLONE_CONFIG_SOURCE (find failed, exit 2)", r.stderr)

    def test_vertex_credentials_preflight_refuses_when_find_fails(self) -> None:
        creds = self.tmp / "vertex.json"
        creds.write_text('{"client_email": "a", "private_key": "b", "token_uri": "c"}')
        creds.chmod(0o600)
        prelude = "\n".join(f"{v}_DEFAULT=''" for v in (
            "REQUIRE_SITE_AI_BACKUP", "SITE_AI_CHAT_MODE", "SITE_AI_VERTEX_PROJECT", "SITE_AI_VERTEX_LOCATION",
            "SITE_AI_VERTEX_CREDENTIALS_PATH", "SITE_AI_VERTEX_MODEL")) + "\nREQUIRE_SITE_AI_BACKUP_DEFAULT=0\n"
        r = self.call(["validate_site_ai_contract"], "validate_site_ai_contract", prelude=prelude,
                      SITE_AI_VERTEX_PROJECT="wins-test-proj", SITE_AI_VERTEX_LOCATION="us-central1",
                      SITE_AI_VERTEX_CREDENTIALS_PATH=str(creds), FAKE_FIND_RC="2")
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn("Could not inspect the permissions of SITE_AI_VERTEX_CREDENTIALS_PATH (find failed, exit 2)", r.stderr)

    def host_keys(self) -> Path:
        d = self.tmp / "etc-ssh"
        d.mkdir()
        (d / "ssh_host_ed25519_key.pub").write_text(KEYS.hub_own + " root@hub\n")
        return d

    def test_own_host_key_check_refuses_an_unreadable_host_key(self) -> None:
        d = self.host_keys()
        (d / "ssh_host_ed25519_key.pub").chmod(0o000)
        r = self.call(["control_path_absent", "litestream_sftp_host_key_not_local"],
                      f"litestream_sftp_host_key_not_local {KEYS.host!r}", LITESTREAM_LOCAL_SSH_HOST_KEY_DIR=str(d))
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn("Could not read this hub's host key", r.stderr)

    def test_own_host_key_check_refuses_an_unlistable_key_directory(self) -> None:
        d = self.host_keys()
        r = self.call(["control_path_absent", "litestream_sftp_host_key_not_local"],
                      f"litestream_sftp_host_key_not_local {KEYS.host!r}", LITESTREAM_LOCAL_SSH_HOST_KEY_DIR=str(d),
                      FAKE_FIND_RC="2", FAKE_FIND_PATH=str(d))
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn("Could not list this hub's host keys", r.stderr)

    def host_key_check(self, d: Path, key: str) -> subprocess.CompletedProcess:
        return self.call(["control_path_absent", "litestream_sftp_host_key_not_local"],
                         f"litestream_sftp_host_key_not_local {key!r}", LITESTREAM_LOCAL_SSH_HOST_KEY_DIR=str(d))

    def test_own_host_key_is_refused_through_a_symlinked_directory(self) -> None:
        # Sol N-21 / Claude N-22 (R7-2)
        real = self.host_keys()
        link = self.tmp / "etc-ssh-link"
        link.symlink_to(real)
        r = self.host_key_check(link, KEYS.hub_own)
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn("is this hub's own host key", r.stderr)

    def test_own_host_key_is_refused_through_a_symlinked_pub(self) -> None:
        real = self.host_keys()
        d = self.tmp / "etc-ssh-linkpub"
        d.mkdir()
        (d / "ssh_host_ed25519_key.pub").symlink_to(real / "ssh_host_ed25519_key.pub")
        r = self.host_key_check(d, KEYS.hub_own)
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn("is this hub's own host key", r.stderr)

    def test_a_dangling_host_key_link_holds_no_key(self) -> None:
        d = self.tmp / "etc-ssh-dangling"
        d.mkdir()
        (d / "ssh_host_ed25519_key.pub").symlink_to(self.tmp / "nowhere.pub")
        r = self.host_key_check(d, KEYS.hub_own)
        self.assertIn("CALL_RETURNED_0", r.stdout, r.stderr)

    def test_an_unresolvable_host_key_link_fails(self) -> None:
        locked = self.tmp / "locked-keys"
        locked.mkdir()
        (locked / "ssh_host_ed25519_key.pub").write_text(KEYS.hub_own + " root@hub\n")
        d = self.tmp / "etc-ssh-unresolvable"
        d.mkdir()
        (d / "ssh_host_ed25519_key.pub").symlink_to(locked / "ssh_host_ed25519_key.pub")
        locked.chmod(0o000)
        r = self.host_key_check(d, KEYS.host)
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn("Could not resolve this hub's host key link", r.stderr)

    def test_crypt_contract_refuses_a_parser_that_failed_after_printing(self) -> None:
        # Sol N-23 (R7-3): the mandatory rows, then awk exit 2.
        conf = self.tmp / "rclone.conf"
        conf.write_text(CRYPT_CONF)
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        real_awk = shutil.which("awk", path="/usr/bin:/bin")
        write_fake(bin_dir, "awk", f'{real_awk} "$@"\nexit 2\n')
        r = self.call(["rclone_crypt_remote_contract"], f"rclone_crypt_remote_contract {str(conf)!r} GoogleDrive_secured",
                      PATH=f"{bin_dir}:{os.environ.get('PATH', '')}")
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn("Could not parse the rclone configuration", r.stderr)

    def test_crypt_contract_still_accepts_a_good_crypt_remote(self) -> None:
        conf = self.tmp / "rclone.conf"
        conf.write_text(CRYPT_CONF)
        r = self.call(["rclone_crypt_remote_contract"], f"rclone_crypt_remote_contract {str(conf)!r} GoogleDrive_secured")
        self.assertIn("CALL_RETURNED_0", r.stdout, r.stderr)

    def legacy_key_block(self) -> str:
        body = function_definition("harden_sensitive_artifacts")
        a = body.index('  local legacy_website_key="/root/website-ev.key"')
        block = body[a:body.rindex("\n}")]
        return block

    def legacy_key(self, grep_rc: str = "", referenced: bool = False,
                   locked_conf: bool = False) -> tuple[subprocess.CompletedProcess, Path]:
        legacy = self.tmp / "website-ev.key"
        legacy.write_text("KEY\n")
        protected = self.tmp / "protected-website-ev.key"
        protected.write_text("KEY\n")
        conf = {name: self.tmp / name for name in ("nginx", "systemd", "cloudflared")}
        for d in conf.values():
            d.mkdir()
        if referenced:
            (conf["nginx"] / "site.conf").write_text(f"ssl_certificate_key {legacy};\n")
        if locked_conf:
            # a configuration directory under a parent that cannot be traversed
            parent = self.tmp / "locked-conf"
            parent.mkdir()
            conf["cloudflared"] = parent / "cloudflared"
            conf["cloudflared"].mkdir()
            parent.chmod(0o000)
        block = self.legacy_key_block()
        block = block.replace("/root/website-ev.key", str(legacy))
        block = block.replace("/etc/nginx /etc/systemd/system /etc/cloudflared",
                              f"{conf['nginx']} {conf['systemd']} {conf['cloudflared']}")
        env = {"WEBSITE_TLS_KEY": str(protected)}
        if grep_rc:
            bin_dir = self.tmp / "bin"
            bin_dir.mkdir(exist_ok=True)
            write_fake(bin_dir, "grep", f'echo "grep: injected I/O error" >&2\nexit {grep_rc}\n')
            env["PATH"] = f"{bin_dir}:{os.environ.get('PATH', '')}"
        r = self.call(["control_path_absent"], f"harden_legacy_key() {{\n{block}\n}}\nharden_legacy_key", **env)
        return r, legacy

    def test_legacy_key_is_kept_when_the_reference_search_fails(self) -> None:
        # Sol N-24 (R7-4): grep exit 2 is not "no reference".
        r, legacy = self.legacy_key(grep_rc="2")
        self.assertIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertTrue(legacy.exists(), "a key whose references could not be checked must never be deleted")
        self.assertIn("reference search could not be completed (status 2)", r.stderr)

    def test_legacy_key_is_removed_only_when_the_search_succeeds_and_finds_nothing(self) -> None:
        r, legacy = self.legacy_key()
        self.assertIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertFalse(legacy.exists())
        self.assertIn("Removed an unreferenced duplicate legacy website private key", r.stderr)

    def test_legacy_key_is_kept_when_a_configuration_directory_cannot_be_inspected(self) -> None:
        r, legacy = self.legacy_key(locked_conf=True)
        self.assertIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertTrue(legacy.exists())
        self.assertIn("reference search could not be completed (status 2)", r.stderr)

    def test_legacy_key_is_kept_when_still_referenced(self) -> None:
        r, legacy = self.legacy_key(referenced=True)
        self.assertTrue(legacy.exists())
        self.assertIn("still names it", r.stderr)

    def test_floor_checks_files_inside_a_vault_linked_directory(self) -> None:
        # Sol N-22 (R7-5): APP_DIR linked into the partial vault, holding a
        # mode-0644 pre-deploy database backup.
        vault = self.tmp / "vault"
        (vault / "app").mkdir(parents=True)
        vault.chmod(0o700)
        (vault / "app").chmod(0o700)
        bak = vault / "app" / "vpn_users.db.pre-fixed-1.bak"
        bak.write_text("db")
        bak.chmod(0o644)
        app = self.tmp / "app-link"
        app.symlink_to(vault / "app")
        env = {var: str(self.tmp / f"no-{var.lower()}") for var in (
            "CONTROL_SSH_HOST_KEY_DIR", "WINS_LOCAL_BACKUP_DIR", "WINS_BACKUP_MANIFEST_DIR",
            "CONTROL_ALERTS_DIR", "WINN_CREDENTIALS_DIR")}
        env.update(APP_DIR=str(app), WINS_PARTIAL_VAULT_ENABLED="1", WINS_PARTIAL_VAULT_MOUNT=str(vault))
        r = self.call(["control_path_absent", "secret_dir_entries", "control_secret_path_specs", "control_flag_is_on",
                       "verify_control_secret_permissions"], "verify_control_secret_permissions",
                      prelude="CONTROL_DISK_ENCRYPTION_EFFECTIVE=luks\n", **env)
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn(f"Secret path {app}/vpn_users.db.pre-fixed-1.bak (pre-deploy database backup) is accessible beyond its owner", r.stderr)

    def test_own_host_key_check_still_finds_and_refuses_the_hubs_own_key(self) -> None:
        d = self.host_keys()
        r = self.call(["control_path_absent", "litestream_sftp_host_key_not_local"],
                      f"litestream_sftp_host_key_not_local {KEYS.hub_own!r}", LITESTREAM_LOCAL_SSH_HOST_KEY_DIR=str(d))
        self.assertNotIn("CALL_RETURNED_0", r.stdout, r.stderr)
        self.assertIn("is this hub's own host key", r.stderr)
        r = self.call(["control_path_absent", "litestream_sftp_host_key_not_local"],
                      f"litestream_sftp_host_key_not_local {KEYS.host!r}", LITESTREAM_LOCAL_SSH_HOST_KEY_DIR=str(d))
        self.assertIn("CALL_RETURNED_0", r.stdout, r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
