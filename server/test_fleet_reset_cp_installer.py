#!/usr/bin/env python3
"""Fleet reset plan 2026-10-08, control-plane installer fixes (FLEET1).

Each test runs the SHIPPED bash of server/wins_control_plane_setup_ONETOUCH.sh
(a function or a here-document, extracted verbatim) under Bash 4+, with host
effects faked on a private PATH (fleet_reset_testlib) and host paths rewritten
into a per-test directory. Nothing on the host is changed.

  TP-H1  wins-hub-restore-preflight reads the .tar.gz.age archive the backup
         writes (decrypts with the escrowed identity, checks the plaintext,
         leaves no plaintext behind). FLEET1 Turn 7: a work-directory stat
         that fails is never root-controlled, and the recovery-contract
         writers the repair runs beneath `if !` refuse every failed write.
  TP-H2  the hub archive carries awg-canary, winn3-canary and the donor
         acknowledgments.
  TP-H3  a rotation of the Access service token is announced, never its secret.
  TP-H4  a signer with no ledger names the operator command that applies.
  TP-H5  preflight refuses every Monero wallet-RPC form the hub refuses.
  TP-H7  preflight uses the built-in Wins zone ids.
  TP-H8, D7, TP-P9  write_env writes the keys the hub reads.
  TP-P9  preflight accepts only BTC and DASH (or none) as BTCPay chains.
  TP-D3  the retired-flag refusal no longer sends the operator to the
         standalone gateway installer.
  TP-R2  (owner-directed) GRUB superuser and boot-chain integrity, luks only.
  TP-H6, TP-W1  the recovery contract and netlify.toml.

Run: python3 -B -m pytest -q -p no:cacheprovider server/test_fleet_reset_cp_installer.py
     WINS_FLEET_CP=/path/to/installer ... (mutant runs)
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import tarfile
import textwrap
import types
import unittest
from pathlib import Path

import fleet_reset_testlib as lib

CP = lib.installer("WINS_FLEET_CP", "server/wins_control_plane_setup_ONETOUCH.sh")
SRC = CP.read_text(encoding="utf-8")
AGE = lib.shutil.which("age")
AGE_KEYGEN = lib.shutil.which("age-keygen")


def restore_preflight_body() -> str:
    return lib.heredoc(SRC, "cat > /usr/local/bin/wins-hub-restore-preflight <<'EOF'", "EOF")


class Case(unittest.TestCase):
    def setUp(self) -> None:
        self.sb = lib.Sandbox()

    def tearDown(self) -> None:
        self.sb.cleanup()


# --- TP-H1 ---------------------------------------------------------------------

@unittest.skipUnless(AGE and AGE_KEYGEN, "age and age-keygen are required")
class RestorePreflightAgeTests(Case):
    SOURCE_ID = "11111111-2222-3333-4444-555555555555"
    TARGET_ID = "66666666-7777-8888-9999-000000000000"

    def setUp(self) -> None:
        super().setUp()
        sb = self.sb
        (sb.bin / "age").symlink_to(AGE)
        self.script = sb.path("wins-hub-restore-preflight")
        body = restore_preflight_body()
        self.assertIn("/usr/bin/python3 - ", body)
        self.script.write_text(body)
        self.script.chmod(0o700)
        self.backups = sb.path("backups")
        self.backups.mkdir(mode=0o755)
        self.work = sb.path("work")
        self.work.mkdir(mode=0o700)
        self.target = sb.path("target")
        (self.target / "etc" / "winsvpn").mkdir(parents=True, mode=0o755)
        contract = self.target / "etc" / "winsvpn" / "hub-install-contract.env"
        contract.write_text("WINS_HUB_RECOVERY_CONTRACT_VERSION=1\n"
                            f"WINS_HUB_INSTALL_ID={self.TARGET_ID}\n"
                            "WINS_HUB_INSTALL_EPOCH=2000\n"
                            "WINS_HUB_RESTORE_ORDER=fresh-install-then-state\n")
        contract.chmod(0o600)
        for d in (sb.tmp, self.target, self.target / "etc", self.target / "etc" / "winsvpn"):
            d.chmod(0o755)
        self.identity = sb.path("identity.txt")
        subprocess.run([AGE_KEYGEN, "-o", str(self.identity)], check=True, capture_output=True)
        self.recipient = subprocess.run([AGE_KEYGEN, "-y", str(self.identity)], check=True,
                                        capture_output=True, text=True).stdout.strip()
        self.plain = self.backups / "wins-hub-backup-hub-20261009_021500.tar.gz"
        self.plain.write_bytes(self.archive_bytes())

    def archive_bytes(self) -> bytes:
        payload = ("WINS_HUB_RECOVERY_CONTRACT_VERSION=1\n"
                   f"WINS_HUB_SOURCE_INSTALL_ID={self.SOURCE_ID}\n"
                   "WINS_HUB_SOURCE_INSTALL_EPOCH=1000\n"
                   "WINS_HUB_BACKUP_EPOCH=1500\n"
                   "WINS_HUB_RESTORE_ORDER=fresh-install-then-state\n").encode()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for d in ("./etc", "./etc/winsvpn"):
                info = tarfile.TarInfo(d)
                info.type = tarfile.DIRTYPE
                info.mode = 0o700
                tar.addfile(info)
            info = tarfile.TarInfo("./etc/winsvpn/hub-backup-recovery.env")
            info.size = len(payload)
            info.mode = 0o600
            tar.addfile(info, io.BytesIO(payload))
        return buf.getvalue()

    def manifest(self, artifact: Path) -> Path:
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        sums = artifact.with_name(artifact.name + ".sha256")
        sums.write_text(f"{digest}  {artifact.name}\n")
        return sums

    def encrypt(self) -> Path:
        enc = self.plain.with_name(self.plain.name + ".age")
        subprocess.run([AGE, "-r", self.recipient, "-o", str(enc), str(self.plain)], check=True)
        self.plain.unlink()
        return enc

    def preflight(self, archive: Path, **env: str) -> subprocess.CompletedProcess:
        sums = self.manifest(archive)
        env.setdefault("WINS_RESTORE_TARGET_ROOT", str(self.target))
        env.setdefault("WINS_RESTORE_WORK_DIR", str(self.work))
        return subprocess.run([lib.BASH, str(self.script), str(archive), str(sums)],
                              capture_output=True, text=True, env=self.sb.env(**env), timeout=60)

    def leftovers(self) -> list[str]:
        return sorted(p.name for p in self.work.iterdir())

    def test_the_age_archive_the_backup_writes_passes_with_the_escrowed_identity(self) -> None:
        enc = self.encrypt()
        r = self.preflight(enc, WINS_RESTORE_AGE_IDENTITY=str(self.identity))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("PASS hub restore preflight", r.stdout)
        self.assertEqual(self.leftovers(), [], "the decrypted plaintext must not outlive the preflight")

    def test_an_age_archive_without_the_identity_is_refused_by_name(self) -> None:
        r = self.preflight(self.encrypt())
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("WINS_RESTORE_AGE_IDENTITY", r.stderr)
        self.assertEqual(self.leftovers(), [])

    def test_a_wrong_identity_is_refused_and_leaves_nothing(self) -> None:
        enc = self.encrypt()
        other = self.sb.path("other.txt")
        subprocess.run([AGE_KEYGEN, "-o", str(other)], check=True, capture_output=True)
        r = self.preflight(enc, WINS_RESTORE_AGE_IDENTITY=str(other))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("could not decrypt", r.stderr)
        self.assertEqual(self.leftovers(), [])

    def test_a_symlinked_identity_is_refused(self) -> None:
        enc = self.encrypt()
        link = self.sb.path("identity-link")
        link.symlink_to(self.identity)
        r = self.preflight(enc, WINS_RESTORE_AGE_IDENTITY=str(link))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("WINS_RESTORE_AGE_IDENTITY", r.stderr)

    def test_a_world_writable_work_dir_is_refused(self) -> None:
        enc = self.encrypt()
        self.work.chmod(0o777)
        r = self.preflight(enc, WINS_RESTORE_AGE_IDENTITY=str(self.identity))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("WINS_RESTORE_WORK_DIR", r.stderr)

    def test_a_plaintext_archive_still_passes(self) -> None:
        r = self.preflight(self.plain)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("PASS hub restore preflight", r.stdout)

    def test_a_tampered_age_archive_fails_the_manifest_before_decryption(self) -> None:
        enc = self.encrypt()
        sums = self.manifest(enc)
        data = bytearray(enc.read_bytes())
        data[-1] ^= 1
        enc.write_bytes(bytes(data))
        r = subprocess.run([lib.BASH, str(self.script), str(enc), str(sums)], capture_output=True, text=True,
                           env=self.sb.env(WINS_RESTORE_TARGET_ROOT=str(self.target),
                                           WINS_RESTORE_WORK_DIR=str(self.work),
                                           WINS_RESTORE_AGE_IDENTITY=str(self.identity)), timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("SHA-256 verification failed", r.stderr)
        self.assertEqual(self.leftovers(), [])

    # FLEET1 Turn 7: secure_root_directory_path runs only as a condition, so
    # errexit never stops it. A stat of the work directory that fails, or that
    # prints no octal mode, must refuse the directory that receives every hub
    # secret in plaintext. (An empty mode used to be an arithmetic error that
    # read as "not group or world writable".)
    STAT_FAULT = r'''#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
fmt = args[args.index("-c") + 1] if "-c" in args else ""
paths = [a for a in args if not a.startswith("-") and a != fmt]
target = os.path.realpath(os.environ.get("FLEET_STAT_FAULT_PATH", "/nonexistent"))
if fmt == os.environ.get("FLEET_STAT_FAULT_FMT") and [os.path.realpath(p) for p in paths] == [target]:
    sys.stdout.write(os.environ.get("FLEET_STAT_FAULT_OUT", ""))
    sys.exit(int(os.environ.get("FLEET_STAT_FAULT_RC", "1")))
os.execv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "stat-shim"), ["stat"] + args)
'''

    def test_a_work_dir_stat_that_fails_is_never_root_controlled(self) -> None:
        (self.sb.bin / "stat").rename(self.sb.bin / "stat-shim")
        (self.sb.bin / "stat").write_text(self.STAT_FAULT)
        (self.sb.bin / "stat").chmod(0o755)
        enc = self.encrypt()
        ok = self.preflight(enc, WINS_RESTORE_AGE_IDENTITY=str(self.identity))
        self.assertEqual(ok.returncode, 0, ok.stderr)
        for fmt, out, rc in (("%a", "", "1"), ("%a", "700\n", "1"), ("%a", "", "0"), ("%u", "0\n", "1")):
            with self.subTest(format=fmt, printed=out, status=rc):
                r = self.preflight(enc, WINS_RESTORE_AGE_IDENTITY=str(self.identity),
                                   FLEET_STAT_FAULT_PATH=str(self.work), FLEET_STAT_FAULT_FMT=fmt,
                                   FLEET_STAT_FAULT_OUT=out, FLEET_STAT_FAULT_RC=rc)
                self.assertNotEqual(r.returncode, 0)
                self.assertNotIn("PASS hub restore preflight", r.stdout)
                self.assertIn("WINS_RESTORE_WORK_DIR must be an absolute, root-controlled", r.stderr)
                self.assertEqual(self.leftovers(), [])


class RestoreDirectoryParentStatusTests(unittest.TestCase):
    def probe(self, status: int) -> subprocess.CompletedProcess:
        function = lib.function_text(
            restore_preflight_body(), "secure_root_directory_path"
        )
        stubs = r'''
realpath() { printf '/usr\n'; }
stat() {
  case "$2" in
    %u) printf '0\n' ;;
    %a) printf '700\n' ;;
    *) return 99 ;;
  esac
}
dirname() { printf '/\n'; return "$DIRNAME_RC"; }
'''
        return subprocess.run(
            [lib.BASH, "-c",
             "set -Eeuo pipefail\n" + function + stubs
             + "\nsecure_root_directory_path /usr || exit $?\n"],
            capture_output=True,
            text=True,
            timeout=10,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                 "DIRNAME_RC": str(status)},
        )

    def test_successful_parent_lookup_passes(self) -> None:
        result = self.probe(0)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_parent_lookup_refuses_its_printed_path(self) -> None:
        result = self.probe(1)
        self.assertEqual(result.returncode, 1, result.stderr)


# --- FLEET1 Turn 7: the writers the recovery-contract repair runs beneath `if !`

def section(name: str, next_name: str) -> str:
    """name() through the line before next_name(): the here-documents inside
    hold column-0 braces, so function_text would stop early."""
    start = SRC.index(f"\n{name}() {{\n") + 1
    return SRC[start:SRC.index(f"\n{next_name}() {{\n", start) + 1]


class RecoveryContractWriteStatusTests(Case):
    # Each fault makes one command of the writer fail the way a full disk or
    # an unwritable path would; the writer is called as the repair calls it.
    FAULTS = textwrap.dedent('''
        fleet_cats=0
        cat() {
          if [[ $# == 1 && "$1" == */uuid ]]; then
            command cat "$@" || return $?
            return "${FLEET_UUID_RC:-0}"
          fi
          if (( $# == 0 )); then
            fleet_cats=$((fleet_cats + 1))
            if (( fleet_cats == ${FLEET_CAT_FAILS_AT:-0} )); then
              head -c 20; return 1
            fi
          fi
          command cat "$@"
        }
        date() {
          if [[ $# == 1 && "$1" == +%s ]]; then
            printf '1000\\n'
            return "${FLEET_EPOCH_RC:-0}"
          fi
          command date "$@"
        }
        stat() {
          command stat "$@" || return $?
          if [[ $# == 3 && "$1" == -c && "$2" == %u:%a && "$3" == */hub-install-contract.env ]]; then
            return "${FLEET_CONTRACT_STAT_RC:-0}"
          fi
          return 0
        }
        install() { [[ "${FLEET_INSTALL_FAILS:-0}" == 1 ]] && return 1; command install "$@"; }
        chown() {
          [[ -n "${FLEET_CHOWN_FAILS:-}" && "$*" == *"${FLEET_CHOWN_FAILS}"* ]] && return 1
          command chown "$@"
        }
        chmod() {
          [[ -n "${FLEET_CHMOD_FAILS:-}" && "$*" == *"${FLEET_CHMOD_FAILS}"* ]] && return 1
          command chmod "$@"
        }
    ''')

    def setUp(self) -> None:
        super().setUp()
        self.etc = self.sb.path("etc", "winsvpn")
        self.out = self.sb.path("usr-local-bin")
        self.out.mkdir()
        self.uuid = self.sb.path("uuid")
        self.uuid.write_text("11111111-2222-3333-4444-555555555555\n")

    def contract(self, **env: str) -> subprocess.CompletedProcess:
        fn = section("write_hub_recovery_contract", "write_backup_timer")
        fn = (fn.replace("/etc/winsvpn", str(self.etc)).replace("/usr/local/bin/", f"{self.out}/")
              .replace("/proc/sys/kernel/random/uuid", str(self.uuid)))
        script = (lib.LOG_STUBS + "set -Eeuo pipefail\nWINN_PROTOCOL_V3_ENABLE_DEFAULT=0\n" + self.FAULTS + fn
                  + "\nif write_hub_recovery_contract; then echo WROTE; else echo REFUSED; exit 1; fi\n")
        return self.sb.run(script, **env)

    def backup(self, **env: str) -> subprocess.CompletedProcess:
        fn = section("write_backup_script", "write_backup_prune_script").replace("/usr/local/bin/", f"{self.out}/")
        script = (lib.LOG_STUBS + "set -Eeuo pipefail\n" + self.FAULTS
                  + lib.stub_functions("write_backup_prune_script", rc=int(env.pop("FLEET_PRUNE_RC", "0"))) + fn
                  + "\nif WINS_SKIP_TRANSIENT_BACKUP_CLEANUP=1 write_backup_script; then echo WROTE; "
                  "else echo REFUSED; exit 1; fi\n")
        return self.sb.run(script, **env)

    def test_a_good_run_writes_the_contract_and_the_preflight(self) -> None:
        r = self.contract()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("WROTE", r.stdout)
        text = (self.etc / "hub-install-contract.env").read_text()
        self.assertIn("WINS_HUB_INSTALL_ID=11111111-2222-3333-4444-555555555555\n", text)
        self.assertIn("WINS_HUB_INSTALL_EPOCH=1000\n", text)
        self.assertTrue(text.endswith("WINS_HUB_RESTORE_ORDER=fresh-install-then-state\n"))
        self.assertEqual(oct((self.etc / "hub-install-contract.env").stat().st_mode & 0o777), "0o600")
        preflight = self.out / "wins-hub-restore-preflight"
        self.assertTrue(preflight.read_text().endswith("runtime executables verified\"\n"))
        self.assertEqual(oct(preflight.stat().st_mode & 0o777), "0o700")
        r = self.backup()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(oct((self.out / "wins-hub-backup").stat().st_mode & 0o777), "0o700")
        self.assertIn("write_backup_prune_script", " ".join(self.sb.logged()))

    def test_a_failed_contract_stat_refuses_its_valid_printed_mode(self) -> None:
        good = self.contract(FLEET_CONTRACT_STAT_RC="0")
        self.assertEqual(good.returncode, 0, good.stderr)
        contract = self.etc / "hub-install-contract.env"
        before = contract.read_bytes()
        (self.out / "wins-hub-restore-preflight").unlink()
        good = self.contract(FLEET_CONTRACT_STAT_RC="0")
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertEqual(contract.read_bytes(), before)
        (self.out / "wins-hub-restore-preflight").unlink()

        r = self.contract(FLEET_CONTRACT_STAT_RC="1")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("REFUSED", r.stdout)
        self.assertIn("Existing hub recovery contract is not a root-owned mode-600 regular file.", r.stderr)
        self.assertEqual(contract.read_bytes(), before)
        self.assertFalse((self.out / "wins-hub-restore-preflight").exists())

    def test_a_failed_uuid_read_refuses_its_valid_printed_uuid(self) -> None:
        r = self.contract(FLEET_UUID_RC="1")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("REFUSED", r.stdout)
        self.assertFalse((self.etc / "hub-install-contract.env").exists())
        self.assertFalse((self.out / "wins-hub-restore-preflight").exists())

    def test_a_failed_epoch_read_refuses_its_valid_printed_epoch(self) -> None:
        r = self.contract(FLEET_EPOCH_RC="1")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("REFUSED", r.stdout)
        self.assertFalse((self.etc / "hub-install-contract.env").exists())
        self.assertFalse((self.out / "wins-hub-restore-preflight").exists())

    def test_every_failed_contract_or_preflight_step_refuses(self) -> None:
        faults = (
            ({"FLEET_INSTALL_FAILS": "1"}, "", False),
            # /etc/winsvpn and a valid contract exist: only install's own
            # status tells that the directory mode was not enforced.
            ({"FLEET_INSTALL_FAILS": "1"}, "", True),
            ({"FLEET_CAT_FAILS_AT": "1"}, "Could not write", False),
            ({"FLEET_CHOWN_FAILS": "hub-install-contract.env"}, "", False),
            ({"FLEET_CHMOD_FAILS": "hub-install-contract.env"}, "", False),
            ({"FLEET_CAT_FAILS_AT": "2"}, "Could not write", False),
            ({"FLEET_CHOWN_FAILS": "wins-hub-restore-preflight"}, "", False),
            ({"FLEET_CHMOD_FAILS": "wins-hub-restore-preflight"}, "", False),
        )
        for env, message, existing in faults:
            with self.subTest(existing_contract=existing, **env):
                lib.shutil.rmtree(self.sb.path("etc"), ignore_errors=True)
                (self.out / "wins-hub-restore-preflight").unlink(missing_ok=True)
                if existing:
                    self.etc.mkdir(parents=True, mode=0o700)
                    (self.etc / "hub-install-contract.env").write_text(
                        "WINS_HUB_RECOVERY_CONTRACT_VERSION=1\n"
                        "WINS_HUB_INSTALL_ID=11111111-2222-3333-4444-555555555555\n"
                        "WINS_HUB_INSTALL_EPOCH=1000\n"
                        "WINS_HUB_RESTORE_ORDER=fresh-install-then-state\n")
                    (self.etc / "hub-install-contract.env").chmod(0o600)
                    self.assertEqual(self.contract().returncode, 0, "the existing contract is valid")
                    (self.out / "wins-hub-restore-preflight").unlink()
                r = self.contract(**env)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("REFUSED", r.stdout)
                self.assertIn(message, r.stderr)
                if env.get("FLEET_CAT_FAILS_AT") == "1":
                    # A contract cut short is removed, so the next run writes a
                    # whole one instead of refusing an invalid one forever.
                    self.assertFalse((self.etc / "hub-install-contract.env").exists())

    def test_every_failed_backup_helper_step_refuses(self) -> None:
        for env in ({"FLEET_CAT_FAILS_AT": "1"}, {"FLEET_CHMOD_FAILS": "wins-hub-backup"}, {"FLEET_PRUNE_RC": "1"}):
            with self.subTest(**env):
                r = self.backup(**dict(env))
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("REFUSED", r.stdout)


# --- TP-H2 ---------------------------------------------------------------------

class HubArchiveSourcesTests(Case):
    def segment(self) -> str:
        body = lib.heredoc(SRC, "cat > /usr/local/bin/wins-hub-backup <<'EOF'", "EOF")
        start = body.index("sources=(\n")
        end = body.index("\n# A hub archive is state for a freshly installed control plane")
        return body[start:end]

    def present_sources(self, present: list[str]) -> subprocess.CompletedProcess:
        root = self.sb.path("root")
        for rel in ("root/vpn_auth/main.py", "root/vpn_auth.env", "etc/systemd/system/wins-hub.service",
                    "etc/iptables/rules.v4"):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text("x\n")
        (root / "etc" / "nginx").mkdir(parents=True, exist_ok=True)
        for rel in present:
            (root / rel).mkdir(parents=True, exist_ok=True)
        script = textwrap.dedent('''
            set -Eeuo pipefail
            SOURCE_ROOT="$1"
            root_path() { printf '%s/%s' "${SOURCE_ROOT%/}" "$1"; }
            kind_or_fail() { if [[ -L "$2" ]]; then echo symlink; elif [[ -d "$2" ]]; then echo directory; elif [[ -e "$2" ]]; then echo file; else echo absent; fi; }
        ''') + self.segment() + '\nprintf "PRESENT %s\\n" "${present_sources[@]}"\n'
        return subprocess.run([lib.BASH, "-c", script, "x", str(root)], capture_output=True, text=True,
                              env=self.sb.env(), timeout=60)

    def test_canary_keys_and_donor_acknowledgments_are_archived_when_present(self) -> None:
        r = self.present_sources(["root/vpn_auth/awg-canary", "root/vpn_auth/winn3-canary",
                                  "root/vpn_auth/donor_acknowledgments"])
        self.assertEqual(r.returncode, 0, r.stderr)
        present = set(re.findall(r"^PRESENT (\S+)$", r.stdout, re.M))
        for rel in ("root/vpn_auth/awg-canary", "root/vpn_auth/winn3-canary", "root/vpn_auth/donor_acknowledgments",
                    "root/vpn_auth/main.py", "root/vpn_auth.env", "etc/nginx"):
            self.assertIn(rel, present)

    def test_a_hub_without_canary_keys_reports_them_and_still_archives(self) -> None:
        r = self.present_sources([])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("listed source is absent on this host and is not archived: root/vpn_auth/awg-canary", r.stderr)
        self.assertIn("listed source is absent on this host and is not archived: root/vpn_auth/winn3-canary", r.stderr)
        self.assertNotIn("donor_acknowledgments", r.stderr, "the donor directory is optional and silent")

    def test_the_signer_directories_stay_excluded(self) -> None:
        body = lib.heredoc(SRC, "cat > /usr/local/bin/wins-hub-backup <<'EOF'", "EOF")
        self.assertIn("--exclude='etc/winsvpn/descriptor-signer'", body)
        self.assertIn("--exclude='var/lib/wins-descriptor-signer'", body)


# --- TP-H3 ---------------------------------------------------------------------

class AccessTokenRotationWarningTests(Case):
    SECRET = "s" * 40 + "-rotated-secret"

    def run_ensure(self, client_secret: str, extra: str = "") -> subprocess.CompletedProcess:
        listing = json.dumps({"result": [{"id": "0" * 8 + "-1111-2222-3333-" + "4" * 12, "name": "winsvpn-management-hub",
                                          "client_id": "abc.access", "created_at": "2026-01-01"}]})
        rotate = json.dumps({"result": {"client_id": "abc.access", "client_secret": self.SECRET}})
        script = lib.LOG_STUBS + textwrap.dedent(f'''
            cloudflare_access_shell_json() {{
              case "$2" in
                *'?per_page=1000') printf '%s' '{listing}' ;;
                */rotate) printf '%s\\n' "rotate" >> "$FLEET_CALLS"; printf '%s' '{rotate}' ;;
                */refresh) printf '{{}}' ;;
              esac
            }}
            replace_runtime_env_kv() {{ printf 'persist %s\\n' "$1" >> "$FLEET_CALLS"; }}
            ENV_FILE=/root/vpn_auth.env
            WINS_SECRETS_FILE=/root/winsvpn-secrets.env
            HIDE_CONTROL_ORIGIN=1 REQUIRE_CLOUDFLARE_ACCESS=1
            CLOUDFLARE_TUNNEL_ACCOUNT_ID={"a" * 32}
            CLOUDFLARE_ACCESS_SERVICE_TOKEN_NAME=winsvpn-management-hub
            TUNNEL_SERVICE_TOKEN_SECRET='{client_secret}'
        ''') + extra + lib.function_text(SRC, "ensure_cloudflare_access_service_token") \
            + "\nensure_cloudflare_access_service_token\n"
        return self.sb.run(script)

    def test_a_rotation_is_announced_and_the_secret_is_never_printed(self) -> None:
        r = self.run_ensure("")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("rotate", self.sb.logged())
        self.assertIn("Rotating the Cloudflare Access service token 'winsvpn-management-hub'", r.stderr)
        self.assertIn("restore /root/vpn_auth.env before the run", r.stderr)
        self.assertNotIn(self.SECRET, r.stdout + r.stderr)

    def test_a_known_secret_is_kept_without_rotation_or_warning(self) -> None:
        r = self.run_ensure("k" * 40)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("rotate", self.sb.logged())
        self.assertNotIn("Rotating", r.stderr)

    def test_the_wallet_token_is_compared_with_the_final_management_token(self) -> None:
        # FLEET1 Turn 3 (Claude seat, D7): on a fresh run the preflight compared
        # against an empty management token; the comparison is repeated once
        # the token is loaded or rotated, after it is persisted.
        dedicated = ("MONERO_WALLET_RPC_CF_ACCESS=1\nMONERO_WALLET_RPC_CF_ACCESS_CLIENT_ID=0123456789abcdef.access\n"
                     "MONERO_WALLET_RPC_CF_ACCESS_CLIENT_SECRET=" + "w" * 64 + "\n")
        cases = {
            "rotated secret reused": (dedicated.replace("w" * 64, self.SECRET), 1),
            "management id reused": (dedicated.replace("0123456789abcdef.access", "abc.access"), 1),
            "dedicated token": (dedicated, 0),
            "flag off": (dedicated.replace("ACCESS=1", "ACCESS=0").replace("w" * 64, self.SECRET), 0),
        }
        for label, (extra, rc) in cases.items():
            with self.subTest(label=label):
                self.tearDown()
                self.setUp()
                r = self.run_ensure("", extra)
                self.assertEqual(r.returncode, rc, label + r.stderr)
                self.assertIn("persist TUNNEL_SERVICE_TOKEN_SECRET", self.sb.logged(), "the rotated secret is kept")
                if rc:
                    self.assertIn("is the management service token", r.stderr)
                self.assertNotIn(self.SECRET, r.stdout + r.stderr)


# --- TP-H4 ---------------------------------------------------------------------

class SignerLedgerWarningTests(Case):
    def run_start(self, ledger: bool, marker: bool, ready: int = 1) -> subprocess.CompletedProcess:
        state = self.sb.path("state")
        config = self.sb.path("config")
        state.mkdir()
        config.mkdir()
        if ledger:
            (state / "ledger.json").write_text("{}")
        if marker:
            (config / "LEDGER-INITIALIZED").write_text("1\n")
        script = lib.LOG_STUBS + lib.stub_functions("systemctl") + textwrap.dedent(f'''
            DESCRIPTOR_SIGNER_KEY_READY={ready}
            DESCRIPTOR_SIGNER_STATE_DIR={state}
            DESCRIPTOR_SIGNER_CONFIG_DIR={config}
        ''') + lib.function_text(SRC, "start_descriptor_signer") + "\nstart_descriptor_signer\n"
        return self.sb.run(script)

    def test_a_first_install_names_ledger_bootstrap_and_reconcile(self) -> None:
        r = self.run_start(ledger=False, marker=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("no ledger is installed", r.stderr)
        self.assertIn("wins_descriptor_signer.py ledger-bootstrap", r.stderr)
        self.assertIn("wins_descriptor_signer.py reconcile", r.stderr)

    def test_a_lost_ledger_names_restore_and_reconcile_and_forbids_bootstrap(self) -> None:
        r = self.run_start(ledger=False, marker=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("was installed on this hub and is now missing", r.stderr)
        self.assertIn("restore-checkpoint", r.stderr)
        self.assertIn("Never ledger-bootstrap", r.stderr)

    def test_a_present_ledger_is_quiet(self) -> None:
        r = self.run_start(ledger=True, marker=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("ledger", r.stderr)

    def test_no_key_no_warning(self) -> None:
        r = self.run_start(ledger=False, marker=False, ready=0)
        self.assertNotIn("ledger", r.stderr)


# --- TP-H5, TP-H7, TP-P9 (preflight contract) ----------------------------------

class SecretContractTests(Case):
    BASE = {
        "STRICT_ONE_TOUCH_SECRETS": "1", "REQUIRE_CLOUDFLARE_AUTOMATION": "0", "HIDE_CONTROL_ORIGIN": "0",
        "REQUIRE_ACTIVE_GATEWAY_AUTOMATION": "0", "PAYPAL_WEBHOOK_AUTO_ENSURE": "1",
        "ADMIN_TOKEN": "a" * 40, "SMTP_USER": "u", "SMTP_PASS": "p", "PAYPAL_PUBLIC_CLIENT_ID": "c",
        "PAYPAL_CLIENT_ID": "c", "PAYPAL_CLIENT_SECRET": "s", "PAYPAL_PLAN_1M": "p1", "PAYPAL_PLAN_1Y": "p2",
        "PAYPAL_PLAN_PERSONAL": "p3", "PAYPAL_LIFETIME_SUPPORT_URL": "https://example.test/a",
        "PAYPAL_LIFETIME_NO_SUPPORT_URL": "https://example.test/b", "PAYPAL_LIFETIME_SUPPORT_AMOUNT": "100.00",
        "PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT": "10.00", "PAYPAL_LIFETIME_CURRENCY": "USD",
        "HUB_ADMIN_SSH_CIDRS": "203.0.113.10/32", "SPA_KEY": "A" * 43 + "=", "SPA_HMAC": "B" * 43 + "=",
    }
    DEFAULTS = textwrap.dedent('''
        CLOUDFLARE_WINSVPN_ORG_ZONE_ID_DEFAULT="CF_ZONE_ID_ORG_REDACTED"
        CLOUDFLARE_WINSVPN_COM_ZONE_ID_DEFAULT="CF_ZONE_ID_COM_REDACTED"
        WINS_SECRETS_FILE=/root/winsvpn-secrets.env
    ''')

    def contract(self, **env: str) -> subprocess.CompletedProcess:
        merged = dict(self.BASE)
        merged.update(env)
        script = (lib.LOG_STUBS
                  + lib.stub_functions("validate_rclone_injection_contract", "validate_backup_encryption_contract",
                                       "validate_durability_replication_contract", "validate_site_ai_contract")
                  + self.DEFAULTS + lib.function_text(SRC, "validate_external_secret_contract")
                  + "\nvalidate_external_secret_contract\n")
        return self.sb.run(script, **merged)

    def monero(self, url: str, user: str = "winsmonero", pw: str = "digest-pass", **extra: str):
        return self.contract(MONERO_WALLET_RPC_URL=url, MONERO_WALLET_RPC_USER=user, MONERO_WALLET_RPC_PASS=pw, **extra)

    def test_the_baseline_passes(self) -> None:
        r = self.contract()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_monero_forms_the_hub_accepts_pass(self) -> None:
        for url in ("http://127.0.0.1:18083", "http://localhost:18083", "https://monero-rpc.winsvpn.org",
                    "https://monero-rpc.winsvpn.org:443", "https://monero-rpc.winsvpn.org/"):
            with self.subTest(url=url):
                r = self.monero(url)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_monero_forms_the_hub_disables_are_refused(self) -> None:
        for url in ("http://10.8.0.1:18083", "http://monero-rpc.winsvpn.org", "https://monero-rpc.winsvpn.org:8443",
                    "https://user:pw@monero-rpc.winsvpn.org", "https://monero-rpc.winsvpn.org/json_rpc?x=1",
                    "ftp://127.0.0.1"):
            with self.subTest(url=url):
                r = self.monero(url)
                self.assertNotEqual(r.returncode, 0, url)
                self.assertIn("MONERO_WALLET_RPC_URL must be", r.stderr)

    def test_monero_credentials_are_always_required(self) -> None:
        for user, pw in (("", ""), ("winsmonero", ""), ("", "digest-pass")):
            with self.subTest(user=user, pw=pw):
                r = self.monero("https://monero-rpc.winsvpn.org", user, pw)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("must be set whenever MONERO_WALLET_RPC_URL is set", r.stderr)

    D7 = {"MONERO_WALLET_RPC_CF_ACCESS_CLIENT_ID": "0123456789abcdef.access",
          "MONERO_WALLET_RPC_CF_ACCESS_CLIENT_SECRET": "w" * 64,
          "TUNNEL_SERVICE_TOKEN_ID": "fedcba9876543210.access"}

    def test_the_access_flag_needs_a_dedicated_token(self) -> None:
        r = self.monero("https://monero-rpc.winsvpn.org", MONERO_WALLET_RPC_CF_ACCESS="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("MONERO_WALLET_RPC_CF_ACCESS_CLIENT_ID", r.stderr)
        same = dict(self.D7, TUNNEL_SERVICE_TOKEN_ID="0123456789abcdef.access")
        r = self.monero("https://monero-rpc.winsvpn.org", MONERO_WALLET_RPC_CF_ACCESS="1", **same)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("is the management service token", r.stderr)
        short = dict(self.D7, MONERO_WALLET_RPC_CF_ACCESS_CLIENT_SECRET="short")
        self.assertNotEqual(self.monero("https://monero-rpc.winsvpn.org", MONERO_WALLET_RPC_CF_ACCESS="1",
                                        **short).returncode, 0)
        self.assertNotIn("w" * 64, r.stdout + r.stderr)

    def test_the_dedicated_token_differs_in_both_halves_and_has_no_whitespace(self) -> None:
        # FLEET1 Turn 2 (Astra merge): the secret alone equal to the management
        # secret is the management token too; a secret is a header value.
        same_secret = dict(self.D7, TUNNEL_SERVICE_TOKEN_SECRET="w" * 64)
        r = self.monero("https://monero-rpc.winsvpn.org", MONERO_WALLET_RPC_CF_ACCESS="1", **same_secret)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("is the management service token", r.stderr)
        self.assertNotIn("w" * 64, r.stdout + r.stderr)
        for bad_id in ("not-an-access-id", "x y.access", "0123456789abcdef.access.evil", ".access"):
            with self.subTest(client_id=bad_id):
                r = self.monero("https://monero-rpc.winsvpn.org", MONERO_WALLET_RPC_CF_ACCESS="1",
                                **dict(self.D7, MONERO_WALLET_RPC_CF_ACCESS_CLIENT_ID=bad_id))
                self.assertNotEqual(r.returncode, 0, bad_id)
                self.assertIn("own service token", r.stderr)
        for label, value in (("inner space", "w" * 20 + " " + "w" * 20), ("tab", "w" * 40 + "\t")):
            with self.subTest(label=label):
                spaced = dict(self.D7, MONERO_WALLET_RPC_CF_ACCESS_CLIENT_SECRET=value)
                r = self.monero("https://monero-rpc.winsvpn.org", MONERO_WALLET_RPC_CF_ACCESS="1", **spaced)
                self.assertNotEqual(r.returncode, 0, label)
                self.assertIn("own service token", r.stderr)

    def test_the_access_flag_is_zero_or_one_and_needs_https(self) -> None:
        self.assertEqual(self.monero("https://monero-rpc.winsvpn.org", MONERO_WALLET_RPC_CF_ACCESS="1",
                                     **self.D7).returncode, 0)
        r = self.monero("http://127.0.0.1:18083", MONERO_WALLET_RPC_CF_ACCESS="1", **self.D7)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("needs an https://", r.stderr)
        r = self.contract(MONERO_WALLET_RPC_CF_ACCESS="yes")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("MONERO_WALLET_RPC_CF_ACCESS must be 0 or 1", r.stderr)

    def test_btcpay_checkout_chains(self) -> None:
        for value in ("", "none", "BTC", "DASH", "BTC,DASH"):
            with self.subTest(value=value):
                self.assertEqual(self.contract(BTCPAY_CHECKOUT_CHAINS=value).returncode, 0, value)
        for value in ("btc", "LTC", "BTC,", "BTC DASH", "BTC,LTC", "all"):
            with self.subTest(value=value):
                r = self.contract(BTCPAY_CHECKOUT_CHAINS=value)
                self.assertNotEqual(r.returncode, 0, value)
                self.assertIn("BTCPAY_CHECKOUT_CHAINS must be", r.stderr)

    def test_the_wins_zone_ids_fall_back_to_their_defaults(self) -> None:
        r = self.contract(REQUIRE_CLOUDFLARE_AUTOMATION="1", CLOUDFLARE_APPCLOUD_API_TOKEN="t",
                          CLOUDFLARE_APPCLOUD_ZONE_ID="z", CLOUDFLARE_WINS_API_TOKEN="w")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.contract(REQUIRE_CLOUDFLARE_AUTOMATION="1", CLOUDFLARE_APPCLOUD_API_TOKEN="t",
                          CLOUDFLARE_WINS_API_TOKEN="w")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("CLOUDFLARE_APPCLOUD_ZONE_ID", r.stderr)
        self.assertNotIn("CLOUDFLARE_WINSVPN_ORG_ZONE_ID", r.stderr)


# --- TP-H8, D7, TP-P9 (runtime file) -------------------------------------------

class WriteEnvKeysTests(unittest.TestCase):
    def test_write_env_writes_the_keys_the_hub_reads(self) -> None:
        body = lib.function_text(SRC, "write_env")
        for line in ('write_env_kv EMERGENCY_DISPATCH_ENABLED "${EMERGENCY_DISPATCH_ENABLED:-0}"',
                     'write_env_kv EMERGENCY_FROM_EMAIL "${EMERGENCY_FROM_EMAIL:-}"',
                     'write_env_kv EMERGENCY_FROM_NAME "${EMERGENCY_FROM_NAME:-Safety Notification}"',
                     'write_env_kv EMERGENCY_ALLOW_BRANDED_SENDER "${EMERGENCY_ALLOW_BRANDED_SENDER:-0}"',
                     'write_env_kv MONERO_WALLET_RPC_CF_ACCESS "${MONERO_WALLET_RPC_CF_ACCESS:-0}"',
                     'write_env_kv MONERO_WALLET_RPC_CF_ACCESS_CLIENT_ID "${MONERO_WALLET_RPC_CF_ACCESS_CLIENT_ID:-}"',
                     'write_env_kv MONERO_WALLET_RPC_CF_ACCESS_CLIENT_SECRET "${MONERO_WALLET_RPC_CF_ACCESS_CLIENT_SECRET:-}"',
                     'write_env_kv BTCPAY_CHECKOUT_CHAINS "${BTCPAY_CHECKOUT_CHAINS:-none}"'):
            self.assertEqual(body.count(line), 1, line)

    def test_every_written_key_is_read_by_the_hub(self) -> None:
        for key in ("EMERGENCY_DISPATCH_ENABLED", "EMERGENCY_FROM_EMAIL", "EMERGENCY_FROM_NAME",
                    "EMERGENCY_ALLOW_BRANDED_SENDER", "MONERO_WALLET_RPC_CF_ACCESS", "BTCPAY_CHECKOUT_CHAINS",
                    "MONERO_WALLET_RPC_CF_ACCESS_CLIENT_ID", "MONERO_WALLET_RPC_CF_ACCESS_CLIENT_SECRET"):
            self.assertRegex(SRC, r'(os\.getenv|_emergency_flag)\("%s"' % key)


# --- TP-D3 ---------------------------------------------------------------------

class RetiredFlagGuidanceTests(Case):
    def test_the_refusal_points_at_the_data_plane_installer(self) -> None:
        script = (lib.LOG_STUBS + 'WINN_PROTOCOL_V3_ENABLE_DEFAULT=1\n'
                  + lib.function_text(SRC, "refuse_retired_winn_protocol_v3_enable")
                  + "\nrefuse_retired_winn_protocol_v3_enable || echo REFUSED\n")
        r = self.sb.run(script)
        self.assertIn("REFUSED", r.stdout)
        self.assertNotIn("Use the standalone gateway installer instead", r.stderr)
        self.assertIn("installed by the data-plane installer itself", r.stderr)
        self.assertIn("retired tombstone", r.stderr)

    def test_no_message_sends_the_operator_to_the_tombstone(self) -> None:
        self.assertNotIn("Use server/" + "wins_winn3_gateway" + "_install.sh", SRC)
        self.assertNotIn("Use the standalone gateway installer instead", SRC)


# --- TP-R2 (owner-directed hardening) -----------------------------------------

PBKDF2 = "grub.pbkdf2.sha512.600000." + "A1" * 32 + "." + "B2" * 64

UPDATE_GRUB = r'''#!/usr/bin/env bash
# Test generator in the shape of grub-mkconfig: /etc/default/grub.d is sourced,
# /etc/grub.d scripts run in order, 10_linux's CLASS is used for the entries.
set -euo pipefail
echo "update-grub" >> "$FLEET_CALLS"
[[ "${FLEET_UPDATE_GRUB_FAILS:-0}" == 1 ]] && { : > "$FLEET_GRUB_CFG"; exit 1; }
GRUB_DISABLE_RECOVERY=false
for f in "$FLEET_DEFAULT_D"/*.cfg; do [[ -e "$f" ]] && . "$f"; done
out="$FLEET_GRUB_CFG.new"
: > "$out"
if [[ -n "${FLEET_GRUB_DEFAULT:-}" ]]; then
  printf 'if [ "${next_entry}" ] ; then\n   set default="${next_entry}"\nelse\n   set default="%s"\nfi\n' "$FLEET_GRUB_DEFAULT" >> "$out"
fi
for s in "$FLEET_GRUB_D"/*; do
  [[ -x "$s" && "$(basename "$s")" != 10_linux ]] && "$s" >> "$out"
done
class="$(sed -n 's/^CLASS="\(.*\)"$/\1/p' "$FLEET_GRUB_D/10_linux")"
[[ "${FLEET_BREAK_CLASS:-0}" == 1 ]] && class="--class gnu-linux --class gnu --class os"
printf "menuentry 'Ubuntu' --class ubuntu %s \$menuentry_id_option 'gnulinux-simple' {\n  linux /vmlinuz root=/dev/mapper/root_crypt ro\n}\n" "$class" >> "$out"
printf "submenu 'Advanced options for Ubuntu' \$menuentry_id_option 'gnulinux-advanced' {\n" >> "$out"
printf "  menuentry 'Ubuntu, with Linux 6.8.0-146-generic' --class ubuntu %s {\n    linux /vmlinuz-6.8.0-146-generic ro\n  }\n" "$class" >> "$out"
if [[ "$GRUB_DISABLE_RECOVERY" != true ]]; then
  printf "  menuentry 'Ubuntu, with Linux 6.8.0-146-generic (recovery mode)' --class ubuntu %s {\n    linux /vmlinuz-6.8.0-146-generic ro recovery nomodeset\n  }\n" "$class" >> "$out"
fi
printf "}\n" >> "$out"
mv -f "$out" "$FLEET_GRUB_CFG"
'''


CHMOD = r'''#!/bin/sh
# FLEET_CHMOD_FAILS=1: the grub.cfg mode change fails (go-rwx).
if [ "${FLEET_CHMOD_FAILS:-0}" = 1 ] && [ "$1" = go-rwx ]; then exit 1; fi
exec /bin/chmod "$@"
'''
CHOWN = r'''#!/bin/sh
# Ownership cannot change without root here; FLEET_CHOWN_FAILS=1 fails it.
printf 'chown %s\n' "$*" >> "${FLEET_CALLS:-/dev/null}"
[ "${FLEET_CHOWN_FAILS:-0}" = 1 ] && exit 1
exit 0
'''


GREP_FAILS = r'''#!/bin/sh
# FLEET_GREP_FAIL=<first argument>: that grep form fails as on a read error
# (rc 2) after printing FLEET_GREP_OUT; every other grep is the real one.
if [ "$1" = "${FLEET_GREP_FAIL:-}" ]; then printf '%s\n' "${FLEET_GREP_OUT:-}"; exit 2; fi
exec /usr/bin/grep "$@"
'''


class GrubSuperuserTests(Case):
    STOCK_10_LINUX = '#! /bin/sh\nset -e\nCLASS="--class gnu-linux --class gnu --class os"\necho linux\n'
    PREVIOUS_CFG = "# the hub's grub.cfg before this run\nmenuentry 'Ubuntu' --class gnu-linux {\n}\n"

    def setUp(self) -> None:
        super().setUp()
        sb = self.sb
        (sb.bin / "update-grub").write_text(UPDATE_GRUB)
        (sb.bin / "update-grub").chmod(0o755)
        (sb.bin / "chmod").write_text(CHMOD)
        (sb.bin / "chmod").chmod(0o755)
        (sb.bin / "chown").write_text(CHOWN)
        (sb.bin / "chown").chmod(0o755)
        self.grubd = sb.path("grub.d")
        self.grubd.mkdir()
        self.default_d = sb.path("default.d")
        self.cfg = sb.path("grub.cfg")
        self.linux10 = self.grubd / "10_linux"
        self.linux10.write_text(self.STOCK_10_LINUX)
        self.linux10.chmod(0o755)
        self.input = sb.path("grub-superuser.pbkdf2")
        self.cfg.write_text(self.PREVIOUS_CFG)

    def configure(self, posture: str = "luks", **env: str) -> subprocess.CompletedProcess:
        names = ("hub_console_hardening_applies", "read_grub_superuser_pbkdf2", "verify_grub_superuser_config",
                 "configure_hub_grub_superuser")
        script = lib.LOG_STUBS + textwrap.dedent(f'''
            set -Eeuo pipefail
            CONTROL_DISK_ENCRYPTION_EFFECTIVE={posture}
            WINS_GRUB_10_LINUX_CLASS_STOCK='CLASS="--class gnu-linux --class gnu --class os"'
            WINS_GRUB_10_LINUX_CLASS_UNRESTRICTED='CLASS="--class gnu-linux --class gnu --class os --unrestricted"'
            CONTROL_GRUB_SUPERUSER_PBKDF2_FILE_DEFAULT={self.input}
            CONTROL_GRUB_SUPERUSER_NAME_DEFAULT=winsvpn-console
        ''') + "".join(lib.function_text(SRC, n) for n in names) + "\nconfigure_hub_grub_superuser\n"
        base = dict(WINS_GRUB_D_DIR=str(self.grubd), WINS_GRUB_DEFAULT_D_DIR=str(self.default_d),
                    WINS_GRUB_CFG=str(self.cfg), WINS_GRUB_BACKUP_DIR=str(self.sb.path("grub-backup")),
                    FLEET_GRUB_D=str(self.grubd), FLEET_DEFAULT_D=str(self.default_d), FLEET_GRUB_CFG=str(self.cfg))
        base.update(env)
        return self.sb.run(script, **base)

    def stage_input(self, text: str = PBKDF2 + "\n", mode: int = 0o600) -> None:
        self.input.write_text(text)
        self.input.chmod(mode)

    def test_the_superuser_protects_edits_and_leaves_the_default_boot_unattended(self) -> None:
        self.stage_input()
        r = self.configure()
        self.assertEqual(r.returncode, 0, r.stderr)
        cfg = self.cfg.read_text()
        self.assertIn('set superusers="winsvpn-console"', cfg)
        self.assertIn(f"password_pbkdf2 winsvpn-console {PBKDF2}", cfg)
        self.assertRegex(cfg, r"menuentry 'Ubuntu' --class ubuntu --class gnu-linux --class gnu --class os --unrestricted")
        self.assertNotIn("recovery mode", cfg)
        self.assertIn('CLASS="--class gnu-linux --class gnu --class os --unrestricted"', self.linux10.read_text())
        su = self.grubd / "01_winsvpn_superusers"
        self.assertEqual(oct(su.stat().st_mode & 0o777), "0o700")
        self.assertEqual(oct(self.cfg.stat().st_mode & 0o077), "0o0", "grub.cfg holds the hash: not readable by others")
        self.assertNotIn(PBKDF2, r.stdout + r.stderr, "the hash is never printed")
        txns = list(self.sb.path("grub-backup").iterdir())
        self.assertEqual(len(txns), 1)
        self.assertEqual((txns[0] / "0").read_text(), self.STOCK_10_LINUX)
        self.assertEqual((txns[0] / "3").read_text(), self.PREVIOUS_CFG)
        self.assertFalse((txns[0] / "1").exists(), "no superuser script existed before")

    def test_a_rerun_is_idempotent(self) -> None:
        self.stage_input()
        self.assertEqual(self.configure().returncode, 0)
        first = self.cfg.read_text()
        r = self.configure()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.cfg.read_text(), first)
        self.assertEqual(self.linux10.read_text().count("--unrestricted"), 1)

    def test_no_input_skips_cleanly(self) -> None:
        r = self.configure()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("skipped (no owner input", r.stdout)
        self.assertFalse((self.grubd / "01_winsvpn_superusers").exists())
        self.assertEqual(self.linux10.read_text(), self.STOCK_10_LINUX)
        self.assertNotIn("update-grub", self.sb.logged())

    def test_not_luks_is_a_no_op_even_with_input(self) -> None:
        self.stage_input()
        r = self.configure(posture="substitute")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.grubd / "01_winsvpn_superusers").exists())
        self.assertNotIn("update-grub", self.sb.logged())

    def test_bad_inputs_are_refused_before_anything_changes(self) -> None:
        cases = {
            "world-readable": (PBKDF2 + "\n", 0o644),
            "not a hash": ("hunter2\n", 0o600),
            "two lines": (PBKDF2 + "\n" + PBKDF2 + "\n", 0o600),
            "weak iterations": ("grub.pbkdf2.sha512.1000." + "A1" * 32 + "." + "B2" * 64 + "\n", 0o600),
        }
        for label, (text, mode) in cases.items():
            with self.subTest(label=label):
                self.stage_input(text, mode)
                r = self.configure()
                self.assertNotEqual(r.returncode, 0, label)
                self.assertFalse((self.grubd / "01_winsvpn_superusers").exists())
                self.assertEqual(self.linux10.read_text(), self.STOCK_10_LINUX)
                self.assertNotIn("hunter2", r.stdout + r.stderr)

    def test_an_unknown_10_linux_is_refused(self) -> None:
        self.stage_input()
        self.linux10.write_text('#! /bin/sh\nCLASS="--class gnu-linux --class os"\n')
        r = self.configure()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("does not carry exactly one known CLASS line", r.stderr)
        self.assertFalse((self.grubd / "01_winsvpn_superusers").exists())

    # --- FLEET1 Turn 4: a read error in the GRUB step is never a pass.

    def grep_fails(self, form: str, out: str = "") -> subprocess.CompletedProcess:
        (self.sb.bin / "grep").write_text(GREP_FAILS)
        (self.sb.bin / "grep").chmod(0o755)
        return self.configure(FLEET_GREP_FAIL=form, FLEET_GREP_OUT=out)

    def test_a_short_read_of_the_owner_hash_is_refused(self) -> None:
        # A read error that still printed a count of 1, or a truncated line
        # that still looks like a pbkdf2 hash, must never become the password.
        short = PBKDF2[:-40]
        self.assertRegex(short, r"^grub\.pbkdf2\.sha512\.600000\.[0-9A-F]{64}\.[0-9A-F]{64,}$")
        for label, (form, out) in {"count read error": ("-cv", "1"), "hash line short read": ("-v", short)}.items():
            with self.subTest(label=label):
                self.tearDown()
                self.setUp()
                self.stage_input()
                r = self.grep_fails(form, out)
                self.assertNotEqual(r.returncode, 0, label)
                self.assertIn(f"Could not read {self.input}.", r.stderr)
                self.assertFalse((self.grubd / "01_winsvpn_superusers").exists())
                self.assertEqual(self.linux10.read_text(), self.STOCK_10_LINUX)
                self.assertNotIn("update-grub", self.sb.logged())
                self.assertEqual(self.cfg.read_text(), self.PREVIOUS_CFG)

    def test_an_unreadable_10_linux_is_a_read_error_not_a_class_verdict(self) -> None:
        for form in ("-cxF", "-qxF"):
            with self.subTest(form=form):
                self.tearDown()
                self.setUp()
                self.stage_input()
                r = self.grep_fails(form)
                self.assertNotEqual(r.returncode, 0, form)
                self.assertIn(f"Could not read {self.linux10}.", r.stderr)
                self.assertNotIn("update-grub", self.sb.logged())
                self.assertFalse((self.grubd / "01_winsvpn_superusers").exists())
                self.assertEqual(self.linux10.read_text(), self.STOCK_10_LINUX)
                self.assertEqual(self.cfg.read_text(), self.PREVIOUS_CFG)

    def test_a_config_that_would_lock_the_default_boot_is_rolled_back(self) -> None:
        self.stage_input()
        r = self.configure(FLEET_BREAK_CLASS="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("restoring the previous GRUB setup", r.stderr)
        self.assertFalse((self.grubd / "01_winsvpn_superusers").exists())
        self.assertFalse((self.default_d / "90-winsvpn-no-recovery.cfg").exists())
        self.assertEqual(self.linux10.read_text(), self.STOCK_10_LINUX)
        self.assertNotIn("superusers", self.cfg.read_text())
        self.assertEqual(self.cfg.read_text(), self.PREVIOUS_CFG, "the previous grub.cfg itself is back")

    def test_a_failed_ownership_stat_is_refused_whatever_it_printed(self) -> None:
        # FLEET1 Turn 5 (Astra): a stat that prints 0 and then fails is never
        # proof that root owns the owner's hash file.
        self.stage_input()
        (self.sb.bin / "stat").write_text("#!/bin/sh\necho 0\nexit 1\n")
        r = self.configure()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(f"Could not stat {self.input}.", r.stderr)
        self.assertFalse((self.grubd / "01_winsvpn_superusers").exists())
        self.assertEqual(self.linux10.read_text(), self.STOCK_10_LINUX)
        self.assertNotIn("update-grub", self.sb.logged())

    def test_an_owner_hash_file_not_owned_by_root_is_refused(self) -> None:
        self.stage_input()
        r = self.configure(FLEET_STAT_UID="1000")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(f"{self.input} must be owned by root.", r.stderr)
        self.assertFalse((self.grubd / "01_winsvpn_superusers").exists())
        self.assertEqual(self.linux10.read_text(), self.STOCK_10_LINUX)
        self.assertNotIn("update-grub", self.sb.logged())

    def test_a_rollback_that_cannot_remove_the_superuser_never_arms_a_locked_boot(self) -> None:
        # First run, the verification fails, and rm cannot remove the superuser
        # script this run created: the next update-grub (any kernel update; the
        # dpkg guard is not installed yet) must still boot unattended.
        self.stage_input()
        (self.sb.bin / "rm").write_text('#!/bin/sh\ncase "$*" in *01_winsvpn_superusers*) exit 1;; esac\nexec /bin/rm "$@"\n')
        (self.sb.bin / "rm").chmod(0o755)
        r = self.configure(FLEET_BREAK_CLASS="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("GRUB rollback failed", r.stderr)
        self.assertEqual(self.cfg.read_text(), self.PREVIOUS_CFG)
        self.assertIn(self.STOCK_10_LINUX.splitlines()[2].replace('os"', 'os --unrestricted"'), self.linux10.read_text())
        env = self.sb.env(FLEET_GRUB_D=str(self.grubd), FLEET_DEFAULT_D=str(self.default_d), FLEET_GRUB_CFG=str(self.cfg))
        subprocess.run([str(self.sb.bin / "update-grub")], env=env, check=True)
        self.assertRegex(self.cfg.read_text(), r"menuentry 'Ubuntu' [^\n]*--unrestricted")

    def test_a_superuser_script_left_without_its_exec_bit_still_restores_10_linux(self) -> None:
        # grub-mkconfig runs only executable /etc/grub.d scripts: a superuser
        # script whose chmod 0700 and removal both failed is never run, so
        # the rollback still puts the exact previous 10_linux back.
        self.stage_input()
        (self.sb.bin / "chmod").write_text('#!/bin/sh\n[ "$1" = 0700 ] && exit 1\nexec /bin/chmod "$@"\n')
        (self.sb.bin / "rm").write_text('#!/bin/sh\ncase "$*" in *01_winsvpn_superusers*) exit 1;; esac\nexec /bin/rm "$@"\n')
        (self.sb.bin / "rm").chmod(0o755)
        r = self.configure()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("GRUB rollback failed", r.stderr)
        su = self.grubd / "01_winsvpn_superusers"
        self.assertTrue(su.exists())
        self.assertFalse(os.access(su, os.X_OK))
        self.assertEqual(self.linux10.read_text(), self.STOCK_10_LINUX)
        self.assertEqual(self.cfg.read_text(), self.PREVIOUS_CFG)
        self.assertNotIn("update-grub", self.sb.logged())

    # --- FLEET1 Turn 2 (Astra item 4): failures never remove earlier protection.

    def protected(self) -> dict:
        self.stage_input()
        r = self.configure()
        self.assertEqual(r.returncode, 0, r.stderr)
        files = {p: p.read_bytes() for p in (self.linux10, self.grubd / "01_winsvpn_superusers",
                                             self.default_d / "90-winsvpn-no-recovery.cfg", self.cfg)}
        self.assertIn(b"superusers", files[self.cfg])
        return files

    def test_a_failed_rerun_on_a_protected_hub_keeps_every_file(self) -> None:
        failures = {"verification fails": {"FLEET_BREAK_CLASS": "1"},
                    "update-grub fails": {"FLEET_UPDATE_GRUB_FAILS": "1"},
                    "grub.cfg mode cannot be set": {"FLEET_CHMOD_FAILS": "1"}}
        for label, env in failures.items():
            with self.subTest(label=label):
                self.tearDown()
                self.setUp()
                before = self.protected()
                r = self.configure(**env)
                self.assertNotEqual(r.returncode, 0, label)
                self.assertIn("restoring the previous GRUB setup", r.stderr)
                for path, content in before.items():
                    self.assertTrue(path.exists(), f"{label}: {path.name} removed")
                    self.assertEqual(path.read_bytes(), content, f"{label}: {path.name} changed")
                self.assertNotIn(PBKDF2, r.stdout + r.stderr)

    def test_a_first_run_failing_mid_write_restores_every_file(self) -> None:
        # 10_linux is patched and two files are written before the failure.
        self.stage_input()
        r = self.configure(FLEET_CHOWN_FAILS="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("restoring the previous GRUB setup", r.stderr)
        self.assertEqual(self.linux10.read_text(), self.STOCK_10_LINUX)
        self.assertFalse((self.grubd / "01_winsvpn_superusers").exists())
        self.assertFalse((self.default_d / "90-winsvpn-no-recovery.cfg").exists())
        self.assertEqual(self.cfg.read_text(), self.PREVIOUS_CFG)
        self.assertNotIn("update-grub", self.sb.logged())

    def test_a_rerun_failing_mid_write_keeps_the_protection(self) -> None:
        before = self.protected()
        r = self.configure(FLEET_CHOWN_FAILS="1")
        self.assertNotEqual(r.returncode, 0)
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content, path.name)

    def test_a_first_run_with_an_unsettable_cfg_mode_rolls_back(self) -> None:
        self.stage_input()
        r = self.configure(FLEET_CHMOD_FAILS="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Could not make", r.stderr)
        self.assertFalse((self.grubd / "01_winsvpn_superusers").exists())
        self.assertEqual(self.cfg.read_text(), self.PREVIOUS_CFG)

    def test_a_default_inside_the_restricted_submenu_is_rolled_back(self) -> None:
        # Seat fix G1: GRUB authenticates the submenu itself, so a default (or a
        # saved or one-shot next entry) inside "Advanced options" would wait for
        # the password at every unattended boot.
        cases = {
            "submenu path": ("gnulinux-advanced-x>gnulinux-6.8.0-146-generic-advanced-x", ""),
            "submenu index": ("1", ""),
            "saved entry in the submenu": ("${saved_entry}", "saved_entry=1>0\n"),
            "one-shot next entry": ("0", "next_entry=1>0\n"),
        }
        for label, (default, grubenv) in cases.items():
            with self.subTest(label=label):
                self.tearDown()
                self.setUp()
                self.stage_input()
                if grubenv:
                    self.sb.path("grubenv").write_text("# GRUB Environment Block\n" + grubenv)
                r = self.configure(FLEET_GRUB_DEFAULT=default)
                self.assertNotEqual(r.returncode, 0, label)
                self.assertIn("is not an unrestricted top-level Linux entry", r.stderr)
                self.assertFalse((self.grubd / "01_winsvpn_superusers").exists())
                self.assertEqual(self.linux10.read_text(), self.STOCK_10_LINUX)

    def test_a_top_level_default_passes(self) -> None:
        for default in ("0", "gnulinux-simple", "Ubuntu", "${saved_entry}"):
            with self.subTest(default=default):
                self.tearDown()
                self.setUp()
                self.stage_input()
                r = self.configure(FLEET_GRUB_DEFAULT=default)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_non_regular_file_is_refused_before_any_change(self) -> None:
        # FLEET1-T2 seat: the transaction copies regular files only.
        self.stage_input()
        self.default_d.mkdir()
        (self.default_d / "90-winsvpn-no-recovery.cfg").mkdir()
        r = self.configure()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("is not a regular file", r.stderr)
        self.assertEqual(self.linux10.read_text(), self.STOCK_10_LINUX)
        self.assertFalse((self.grubd / "01_winsvpn_superusers").exists())
        self.assertEqual(self.cfg.read_text(), self.PREVIOUS_CFG)
        self.assertNotIn("update-grub", self.sb.logged())

    def test_the_parser_the_installer_uses_for_the_next_boot_still_reads_the_config(self) -> None:
        self.stage_input()
        self.assertEqual(self.configure().returncode, 0)
        start = SRC.index("def parse_grub(txt):")
        end = SRC.index("\ndef entries(", start)
        ns: dict = {"re": re}
        exec(SRC[start:end], ns)
        tree, _, _ = ns["parse_grub"](self.cfg.read_text())
        top = [c for c in tree["children"] if c["kind"] == "menuentry"]
        self.assertEqual([c["title"] for c in top], ["Ubuntu"])
        self.assertEqual(top[0]["linux"], ["root=/dev/mapper/root_crypt ro"])


class GrubSuperuserGuardTests(Case):
    STOCK = '#! /bin/sh\nset -e\nCLASS="--class gnu-linux --class gnu --class os"\necho linux\n'

    def run_guard(self, linux10: str | None, superuser: bool = True, shell: str = "/bin/sh",
                  **env: str) -> subprocess.CompletedProcess:
        grubd = self.sb.path("grub.d")
        grubd.mkdir(exist_ok=True)
        if linux10 is not None:
            (grubd / "10_linux").write_text(linux10)
        if superuser:
            (grubd / "01_winsvpn_superusers").write_text("#!/bin/sh\n")
        elif (grubd / "01_winsvpn_superusers").exists():
            (grubd / "01_winsvpn_superusers").unlink()
        for name in ("update-grub", "logger"):
            (self.sb.bin / name).write_text(f'#!/bin/sh\nprintf "{name} %s\\n" "$*" >> "$FLEET_CALLS"\n'
                                            + ('exit "${FLEET_UPDATE_GRUB_RC:-0}"\n' if name == "update-grub" else ""))
            (self.sb.bin / name).chmod(0o755)
        body = lib.heredoc(SRC, "/usr/local/sbin/wins-grub-superuser-guard <<'GRUBGUARDEOF'", "GRUBGUARDEOF")
        script = self.sb.path("guard")
        script.write_text(body.replace("/etc/grub.d", str(grubd))
                          .replace("/var/lib/wins-boot-integrity", str(self.sb.path("state"))))
        return subprocess.run([shell, str(script)], capture_output=True, text=True, env=self.sb.env(**env), timeout=60)

    def test_a_replaced_stock_10_linux_gets_unrestricted_again(self) -> None:
        r = self.run_guard(self.STOCK)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('CLASS="--class gnu-linux --class gnu --class os --unrestricted"',
                      self.sb.path("grub.d", "10_linux").read_text())
        self.assertTrue(self.sb.path("grub.d", "01_winsvpn_superusers").exists())
        calls = self.sb.logged()
        self.assertTrue(any("GRUB-SUPERUSER REAPPLIED" in c for c in calls), calls)
        self.assertIn("update-grub ", calls)

    def test_an_unknown_10_linux_drops_the_superuser(self) -> None:
        r = self.run_guard('#! /bin/sh\nCLASS="--class gnu-linux --class os"\n')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.sb.path("grub.d", "01_winsvpn_superusers").exists())
        self.assertTrue(any("GRUB-SUPERUSER REMOVED" in c for c in self.sb.logged()))
        self.assertIn("update-grub ", self.sb.logged())

    def test_an_intact_setup_and_no_superuser_change_nothing(self) -> None:
        unrestricted = self.STOCK.replace('os"', 'os --unrestricted"')
        self.assertEqual(self.run_guard(unrestricted).returncode, 0)
        self.assertEqual(self.sb.logged(), [])
        self.assertEqual(self.run_guard(self.STOCK, superuser=False).returncode, 0)
        self.assertEqual(self.sb.logged(), [])
        self.assertNotIn("--unrestricted", self.sb.path("grub.d", "10_linux").read_text())

    # --- FLEET1 Turn 3 (Claude seat, Astra): never a repair that did not land.

    def stub(self, name: str, body: str) -> None:
        (self.sb.bin / name).write_text(body)
        (self.sb.bin / name).chmod(0o755)

    def pending(self) -> bool:
        return self.sb.path("state", "MISMATCH").exists()

    def test_a_patch_that_does_not_land_drops_the_superuser(self) -> None:
        # A failed sed -i (a full disk), or one that changed nothing, is never
        # logged as REAPPLIED while every entry stays restricted.
        seds = {"sed fails": "#!/bin/sh\necho 'sed: No space left on device' >&2\nexit 4\n",
                "sed changes nothing": "#!/bin/sh\nexit 0\n"}
        for label, sed in seds.items():
            for shell in ("/bin/sh", lib.BASH):
                with self.subTest(label=label, shell=shell):
                    self.tearDown()
                    self.setUp()
                    self.stub("sed", sed)
                    r = self.run_guard(self.STOCK, shell=shell)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertNotIn("--unrestricted", self.sb.path("grub.d", "10_linux").read_text())
                    self.assertFalse(self.sb.path("grub.d", "01_winsvpn_superusers").exists())
                    calls = self.sb.logged()
                    self.assertFalse(any("REAPPLIED" in c for c in calls), calls)
                    self.assertTrue(any("GRUB-SUPERUSER REMOVED" in c for c in calls), calls)
                    self.assertLess(calls.index("update-grub "),
                                    next(i for i, c in enumerate(calls) if "GRUB-SUPERUSER REMOVED" in c))
                    self.assertFalse(self.pending(), "a landed removal needs no hold")

    def test_neither_patch_nor_removal_landing_fails_and_holds_the_re_baseline(self) -> None:
        self.stub("sed", "#!/bin/sh\nexit 4\n")
        self.stub("rm", "#!/bin/sh\nexit 1\n")
        for shell in ("/bin/sh", lib.BASH):
            with self.subTest(shell=shell):
                self.sb.calls.unlink(missing_ok=True)
                self.sb.path("state", "MISMATCH").unlink(missing_ok=True)
                r = self.run_guard(self.STOCK, shell=shell)
                self.assertEqual(r.returncode, 1, r.stderr)
                calls = self.sb.logged()
                self.assertTrue(self.sb.path("grub.d", "01_winsvpn_superusers").exists())
                self.assertFalse(any("REAPPLIED" in c or "GRUB-SUPERUSER REMOVED" in c for c in calls), calls)
                self.assertTrue(any("GRUB-SUPERUSER FAILED: could not patch" in c and "--accept-current" in c
                                    for c in calls), calls)
                self.assertNotIn("update-grub ", calls)
                self.assertTrue(self.pending())

    def test_a_failed_update_grub_is_never_a_repair(self) -> None:
        cases = {"reapplied": (self.STOCK, "after", True),
                 "removed": ('#! /bin/sh\nCLASS="--class gnu-linux --class os"\n', "was removed", False)}
        for label, (linux10, phrase, keeps_superuser) in cases.items():
            with self.subTest(label=label):
                self.tearDown()
                self.setUp()
                r = self.run_guard(linux10, FLEET_UPDATE_GRUB_RC="1")
                self.assertEqual(r.returncode, 1, r.stderr)
                calls = self.sb.logged()
                self.assertIn("update-grub ", calls)
                self.assertFalse(any("REAPPLIED" in c or "GRUB-SUPERUSER REMOVED" in c for c in calls), calls)
                self.assertTrue(any("GRUB-SUPERUSER FAILED: update-grub failed" in c and phrase in c for c in calls),
                                calls)
                self.assertEqual(self.sb.path("grub.d", "01_winsvpn_superusers").exists(), keeps_superuser)
                self.assertTrue(self.pending())

    def test_the_hold_stops_the_dpkg_re_baseline_until_the_owner_accepts(self) -> None:
        # The 99 hook runs after this guard: with the hold, the restricted
        # grub.cfg of a failed repair never becomes the sanctioned baseline.
        root = self.sb.path("root")
        (root / "boot" / "grub").mkdir(parents=True)
        (root / "boot" / "grub" / "grub.cfg").write_text("cfg")
        bi = self.sb.path("wins-boot-integrity")
        bi.write_text(lib.heredoc(SRC, "/usr/local/sbin/wins-boot-integrity <<'BOOTINTEGRITYEOF'",
                                  "BOOTINTEGRITYEOF"))
        env = self.sb.env(WINS_BOOT_INTEGRITY_ROOT=str(root), WINS_BOOT_INTEGRITY_STATE_DIR=str(self.sb.path("state")))
        run = lambda *a: subprocess.run([lib.BASH, str(bi), *a], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(run("record", "--source", "installer").returncode, 0)
        recorded = self.sb.path("state", "manifest.sha256").read_text()
        self.assertEqual(self.run_guard(self.STOCK, FLEET_UPDATE_GRUB_RC="1").returncode, 1)
        (root / "boot" / "grub" / "grub.cfg").write_text("restricted cfg from the package's update-grub")
        r = run("record", "--source", "dpkg")
        self.assertEqual(r.returncode, 0)
        self.assertIn("re-baseline refused (dpkg)", r.stdout)
        self.assertEqual(self.sb.path("state", "manifest.sha256").read_text(), recorded)
        self.assertEqual(run("record", "--accept-current").returncode, 0)
        self.assertFalse(self.pending())

    def test_an_unwritable_hold_is_reported(self) -> None:
        self.sb.path("state").write_text("not a directory")
        r = self.run_guard(self.STOCK, FLEET_UPDATE_GRUB_RC="1")
        self.assertEqual(r.returncode, 1)
        calls = self.sb.logged()
        self.assertTrue(any("could not hold the boot-chain re-baseline" in c for c in calls), calls)
        self.assertTrue(any("GRUB-SUPERUSER FAILED: update-grub failed" in c for c in calls), calls)

    def test_the_hook_runs_before_the_re_baseline_and_postflight_checks_it(self) -> None:
        start = SRC.index("\nwrite_hub_boot_integrity() {\n")
        body = SRC[start:SRC.index("\nverify_hub_console_hardening() {\n", start)]
        self.assertIn("/etc/apt/apt.conf.d/98winsvpn-grub-superuser-guard", body)
        self.assertLess("98winsvpn", "99winsvpn")
        self.assertIn("wins-grub-superuser-guard", lib.function_text(SRC, "verify_hub_console_hardening"))


class BootIntegrityTests(Case):
    def setUp(self) -> None:
        super().setUp()
        self.root = self.sb.path("root")
        boot = self.root / "boot"
        (boot / "grub").mkdir(parents=True)
        (boot / "efi" / "EFI" / "ubuntu").mkdir(parents=True)
        (boot / "vmlinuz-6.8.0-146-generic").write_text("kernel")
        (boot / "initrd.img-6.8.0-146-generic").write_text("initrd")
        (boot / "grub" / "grub.cfg").write_text("cfg")
        (boot / "efi" / "EFI" / "ubuntu" / "grubx64.efi").write_text("efi")
        (boot / "vmlinuz").symlink_to("vmlinuz-6.8.0-146-generic")
        self.state = self.sb.path("state")
        self.script = self.sb.path("wins-boot-integrity")
        self.script.write_text(lib.heredoc(SRC, "/usr/local/sbin/wins-boot-integrity <<'BOOTINTEGRITYEOF'",
                                           "BOOTINTEGRITYEOF"))
        self.script.chmod(0o700)

    def bi(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([lib.BASH, str(self.script), *args], capture_output=True, text=True, timeout=60,
                              env=self.sb.env(WINS_BOOT_INTEGRITY_ROOT=str(self.root),
                                              WINS_BOOT_INTEGRITY_STATE_DIR=str(self.state)))

    def manifest(self) -> str:
        return (self.state / "manifest.sha256").read_text()

    def test_record_then_check_passes_and_covers_kernel_initrd_grub_and_efi(self) -> None:
        r = self.bi("record", "--source", "installer")
        self.assertEqual(r.returncode, 0, r.stderr)
        listed = [line.split("  ", 1)[1] for line in self.manifest().splitlines()]
        self.assertEqual(listed, ["/boot/efi/EFI/ubuntu/grubx64.efi", "/boot/grub/grub.cfg",
                                  "/boot/initrd.img-6.8.0-146-generic", "/boot/vmlinuz-6.8.0-146-generic"])
        self.assertEqual(oct((self.state / "manifest.sha256").stat().st_mode & 0o777), "0o600")
        r = self.bi("check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("verified 4 boot-chain file(s)", r.stdout)

    def test_a_changed_initramfs_is_a_held_mismatch_until_the_owner_accepts(self) -> None:
        self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
        recorded = self.manifest()
        (self.root / "boot" / "initrd.img-6.8.0-146-generic").write_text("tampered")
        r = self.bi("check")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("BOOT-CHAIN MISMATCH", r.stdout)
        self.assertIn("/boot/initrd.img-6.8.0-146-generic", r.stdout)
        self.assertTrue((self.state / "MISMATCH").exists())
        r = self.bi("record", "--source", "dpkg")
        self.assertEqual(r.returncode, 0, "a dpkg hook must never fail apt")
        self.assertIn("re-baseline refused (dpkg)", r.stdout)
        self.assertEqual(self.manifest(), recorded, "a pending mismatch is not re-baselined by dpkg")
        self.assertNotEqual(self.bi("check").returncode, 0)
        r = self.bi("record", "--accept-current")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.state / "MISMATCH").exists())
        self.assertEqual(self.bi("check").returncode, 0)

    def test_an_added_or_removed_file_is_a_mismatch(self) -> None:
        self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
        (self.root / "boot" / "vmlinuz-6.9.0-1-generic").write_text("new")
        r = self.bi("check")
        self.assertIn("BOOT-CHAIN MISMATCH", r.stdout)
        self.assertIn("/boot/vmlinuz-6.9.0-1-generic", r.stdout)
        self.assertEqual(self.bi("record", "--accept-current").returncode, 0)
        (self.root / "boot" / "grub" / "grub.cfg").unlink()
        r = self.bi("check")
        self.assertIn("BOOT-CHAIN MISMATCH", r.stdout)
        self.assertIn("/boot/grub/grub.cfg", r.stdout)

    def test_no_manifest_is_reported_as_unrecorded(self) -> None:
        r = self.bi("check")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("BOOT-CHAIN UNRECORDED", r.stdout)

    def test_an_unrecorded_boot_is_held_until_the_owner_accepts(self) -> None:
        # FLEET1 Turn 2 (Astra): a later dpkg run must not silently make the
        # first baseline after a boot found no manifest.
        self.assertNotEqual(self.bi("check").returncode, 0)
        self.assertTrue((self.state / "MISMATCH").exists())
        r = self.bi("record", "--source", "dpkg")
        self.assertEqual(r.returncode, 0)
        self.assertIn("re-baseline refused (dpkg)", r.stdout)
        self.assertFalse((self.state / "manifest.sha256").exists())
        self.assertEqual(self.bi("record", "--accept-current").returncode, 0)
        self.assertEqual(self.bi("check").returncode, 0)

    def test_a_dpkg_run_that_changed_no_boot_file_re_hashes_nothing(self) -> None:
        # FLEET1 Turn 3 (Claude seat, speed): the dpkg hook skips the re-hash
        # while every boot-chain file keeps its size, ctime and inode; a
        # changed or added file is re-hashed and the boot check still compares
        # full hashes.
        self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
        before = self.manifest()
        r = self.bi("record", "--source", "dpkg")
        self.assertEqual(r.returncode, 0)
        self.assertIn("nothing re-hashed (dpkg)", r.stdout)
        self.assertEqual(self.manifest(), before)
        (self.root / "boot" / "grub" / "grub.cfg").write_text("cfg after update-grub")
        r = self.bi("record", "--source", "dpkg")
        self.assertIn("recorded", r.stdout)
        self.assertNotEqual(self.manifest(), before)
        self.assertEqual(self.bi("check").returncode, 0)
        (self.root / "boot" / "vmlinuz-6.9.0-1-generic").write_text("new kernel")
        r = self.bi("record", "--source", "dpkg")
        self.assertIn("recorded 5 boot-chain file(s) (dpkg)", r.stdout)
        self.assertEqual(self.bi("check").returncode, 0)

    def test_the_installer_and_the_owner_always_re_hash(self) -> None:
        self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
        for args in (("record", "--source", "installer"), ("record", "--accept-current")):
            with self.subTest(args=args):
                r = self.bi(*args)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertNotIn("nothing re-hashed", r.stdout)
                self.assertIn("recorded 4 boot-chain file(s)", r.stdout)

    def test_a_failed_stat_is_never_a_match(self) -> None:
        self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
        self.assertTrue((self.state / "manifest.stat").exists())
        (self.sb.bin / "stat").write_text("#!/bin/sh\nexit 1\n")
        r = self.bi("record", "--source", "dpkg")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("recorded 4 boot-chain file(s) (dpkg)", r.stdout)
        self.assertFalse((self.state / "manifest.stat").exists(), "no stat record: the next run re-hashes")

    # --- FLEET1 Turn 4 (Astra): a failed read or hash never counts.

    def test_a_failed_hash_records_no_manifest(self) -> None:
        (self.sb.bin / "sha256sum").write_text("#!/bin/sh\nexit 1\n")
        r = self.bi("record", "--source", "installer")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("could not read or hash", r.stderr)
        self.assertFalse((self.state / "manifest.sha256").exists())
        self.assertFalse((self.state / "manifest.stat").exists())

    def test_a_failed_hash_preserves_the_manifest_stat_and_hold(self) -> None:
        self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
        recorded = self.manifest()
        stat_file = self.state / "manifest.stat"
        stat_before = stat_file.read_bytes()
        pending = self.state / "MISMATCH"
        pending.write_text("held\n")
        (self.sb.bin / "sha256sum").write_text("#!/bin/sh\nexit 1\n")
        r = self.bi("record", "--accept-current")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.manifest(), recorded)
        self.assertEqual(stat_file.read_bytes(), stat_before)
        self.assertEqual(pending.read_text(), "held\n")
        self.assertEqual(sorted(p.name for p in self.state.iterdir()),
                         ["MISMATCH", "manifest.sha256", "manifest.stat"])

    def test_repeated_hash_failure_never_verifies_a_malformed_manifest(self) -> None:
        self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
        malformed = re.sub(r"(?m)^[0-9a-f]{64}", "", self.manifest())
        (self.state / "manifest.sha256").write_text(malformed)
        (self.sb.bin / "sha256sum").write_text("#!/bin/sh\nexit 1\n")
        r = self.bi("check")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("BOOT-CHAIN MISMATCH", r.stdout)
        self.assertNotIn("verified ", r.stdout)
        self.assertTrue((self.state / "MISMATCH").exists())

    def test_a_hash_that_exits_0_without_a_full_digest_never_counts(self) -> None:
        # A sha256sum that succeeds but prints an empty, short or non-hex
        # digest (a short read of its output): never recorded, never verified.
        digests = {"empty": "", "short": "a" * 63, "not hex": "g" * 64, "upper case": "A" * 64}
        for label, digest in digests.items():
            with self.subTest(label=label):
                self.tearDown()
                self.setUp()
                self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
                recorded = self.manifest()
                (self.sb.bin / "sha256sum").write_text(f"#!/bin/sh\ncat >/dev/null\nprintf '%s  -\\n' '{digest}'\n")
                r = self.bi("record", "--accept-current")
                self.assertNotEqual(r.returncode, 0, label)
                self.assertIn("could not read or hash", r.stderr)
                self.assertEqual(self.manifest(), recorded)
                r = self.bi("check")
                self.assertNotEqual(r.returncode, 0, label)
                self.assertIn("BOOT-CHAIN MISMATCH: could not read or hash", r.stdout)
                self.assertTrue((self.state / "MISMATCH").exists())

    def test_a_manifest_with_an_empty_or_short_digest_never_verifies(self) -> None:
        # Even when the files hash the same way twice, the manifest itself
        # must be one full lowercase digest per line.
        self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
        good = self.manifest()
        first = good.splitlines()[0]
        broken = {"empty digest": good.replace(first, first[64:], 1),
                  "short digest": good.replace(first, first[1:], 1),
                  "blank line between entries": good.replace("\n", "\n\n", 1),
                  "only a newline": "\n",
                  "unreadable": good}
        for label, text in broken.items():
            with self.subTest(label=label):
                (self.state / "manifest.sha256").write_text(text)
                (self.state / "manifest.sha256").chmod(0o000 if label == "unreadable" else 0o600)
                (self.state / "MISMATCH").unlink(missing_ok=True)
                r = self.bi("check")
                self.assertNotEqual(r.returncode, 0, label)
                self.assertIn("BOOT-CHAIN MISMATCH: the manifest at", r.stdout)
                self.assertIn("is unreadable or malformed", r.stdout)
                self.assertNotIn("verified ", r.stdout)
                self.assertTrue((self.state / "MISMATCH").exists())
        (self.state / "manifest.sha256").chmod(0o600)
        (self.state / "manifest.sha256").write_text(good)
        self.assertEqual(self.bi("record", "--accept-current").returncode, 0)
        self.assertEqual(self.bi("check").returncode, 0)

    def test_a_hash_that_fails_after_printing_a_digest_never_counts(self) -> None:
        self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
        recorded = self.manifest()
        (self.sb.bin / "sha256sum").write_text(f"#!/bin/sh\ncat >/dev/null\necho '{'a' * 64}  -'\nexit 1\n")
        r = self.bi("record", "--accept-current")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("could not read or hash", r.stderr)
        self.assertEqual(self.manifest(), recorded)
        r = self.bi("check")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("BOOT-CHAIN MISMATCH: could not read or hash", r.stdout)

    def test_a_boot_chain_with_no_files_is_never_verified(self) -> None:
        self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
        lib.shutil.rmtree(self.root / "boot")
        r = self.bi("check")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("BOOT-CHAIN MISMATCH: could not read or hash the boot chain (or found no boot-chain file)", r.stdout)
        self.assertTrue((self.state / "MISMATCH").exists())

    def test_a_failed_enumeration_is_never_a_stat_match(self) -> None:
        # A sort that printed every path and then failed: the enumeration is
        # not trusted, so the dpkg stat gate never skips on it.
        self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
        recorded = self.manifest()
        (self.sb.bin / "sort").write_text('#!/bin/sh\n/usr/bin/sort "$@"\nexit 1\n')
        (self.sb.bin / "sort").chmod(0o755)
        r = self.bi("record", "--source", "dpkg")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("nothing re-hashed", r.stdout)
        self.assertIn("could not read or hash", r.stderr)
        self.assertEqual(self.manifest(), recorded)

    def test_a_failed_enumeration_records_nothing(self) -> None:
        # The file list is a pipe into sort: a sort that fails after one line
        # must not record a one-file manifest.
        self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
        recorded = self.manifest()
        (self.sb.bin / "sort").write_text('#!/bin/sh\n/usr/bin/sort "$@" | head -n 1\nexit 1\n')
        (self.sb.bin / "sort").chmod(0o755)
        for args in (("record", "--accept-current"), ("record", "--source", "dpkg")):
            with self.subTest(args=args):
                (self.root / "boot" / "grub" / "grub.cfg").write_text("cfg " + " ".join(args))
                r = self.bi(*args)
                self.assertNotEqual(r.returncode, 0, args)
                self.assertIn("could not read or hash", r.stderr)
                self.assertEqual(self.manifest(), recorded)
        r = self.bi("check")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("BOOT-CHAIN MISMATCH: could not read or hash", r.stdout)

    def test_a_manifest_that_cannot_be_written_is_not_published(self) -> None:
        self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
        recorded = self.manifest()
        (self.root / "boot" / "grub" / "grub.cfg").write_text("cfg after update-grub")
        (self.sb.bin / "chmod").write_text('#!/bin/sh\n[ "$1" = 0600 ] && exit 1\nexec /bin/chmod "$@"\n')
        (self.sb.bin / "chmod").chmod(0o755)
        r = self.bi("record", "--source", "dpkg")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("could not write the boot-chain manifest", r.stderr)
        self.assertEqual(self.manifest(), recorded)
        self.assertEqual(sorted(p.name for p in self.state.iterdir()), ["manifest.sha256", "manifest.stat"])

    def test_a_check_that_cannot_hold_still_says_its_line(self) -> None:
        # The journal line is what the alert monitor raises: it comes first,
        # and a hold that cannot be written is said as well.
        self.state.write_text("not a directory")
        r = self.bi("check")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("BOOT-CHAIN UNRECORDED", r.stdout)
        self.assertIn("could not hold the result", r.stdout)
        self.state.unlink()
        self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
        (self.root / "boot" / "initrd.img-6.8.0-146-generic").write_text("tampered")
        (self.state / "MISMATCH").mkdir()
        r = self.bi("check")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("BOOT-CHAIN MISMATCH: changed since the last sanctioned install or upgrade: "
                      "/boot/initrd.img-6.8.0-146-generic", r.stdout)
        self.assertIn("could not hold the result", r.stdout)

    # --- FLEET1 Turn 5 (Astra): bytes are validated before command
    # substitution can drop a NUL or a trailing newline.

    def test_raw_manifest_bytes_are_validated_before_shell_conversion(self) -> None:
        self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
        manifest = self.state / "manifest.sha256"
        good = manifest.read_bytes()
        broken = {
            "trailing blank line": good + b"\n",
            "NUL inside digest": good[:32] + b"\0" + good[32:],
            "missing final newline": good[:-1],
            "CRLF": good.replace(b"\n", b"\r\n"),
            "NUL in place of a newline": good.replace(b"\n", b"\0", 1),
        }
        for label, data in broken.items():
            with self.subTest(label=label):
                manifest.write_bytes(data)
                (self.state / "MISMATCH").unlink(missing_ok=True)
                result = self.bi("check")
                self.assertNotEqual(result.returncode, 0, label)
                self.assertIn("is unreadable or malformed", result.stdout)
                self.assertNotIn("verified ", result.stdout)
                self.assertTrue((self.state / "MISMATCH").exists())
                self.assertEqual(manifest.read_bytes(), data)

    def test_the_verdict_does_not_depend_on_the_callers_locale(self) -> None:
        # FLEET1 Turn 6 (Claude seat, Turn 5 item 8c): the helper runs under
        # dpkg (the admin's locale) and under systemd (the system locale). It
        # exports LC_ALL=C, so both read the manifest bytes the same way. Under
        # a UTF-8 locale bash's [[:cntrl:]] also matches U+0080 to U+009F, so
        # a boot file accepted under C was refused, and a check held as a
        # MISMATCH, under C.UTF-8. (The export also ends a macOS-only crash of
        # Homebrew bash restoring the locale in a forked subshell.)
        probe = subprocess.run([lib.BASH, "-c", "[[ $'\\xc2\\x85' =~ ^[^[:cntrl:]]+$ ]]"],
                               env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, capture_output=True)
        if probe.returncode == 0:
            self.skipTest("this host has no C.UTF-8 locale that treats U+0085 as a control")
        name = "grub\u0085x64.efi"
        (self.root / "boot" / "efi" / "EFI" / "ubuntu" / name).write_text("efi2")

        def run(*args: str, **locale: str) -> subprocess.CompletedProcess:
            env = self.sb.env(WINS_BOOT_INTEGRITY_ROOT=str(self.root),
                              WINS_BOOT_INTEGRITY_STATE_DIR=str(self.state))
            env.pop("LC_ALL")
            env.update(locale)
            return subprocess.run([lib.BASH, str(self.script), *args], capture_output=True, text=True,
                                  timeout=60, env=env)

        r = run("record", "--source", "installer", LANG="C.UTF-8")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(f"  /boot/efi/EFI/ubuntu/{name}\n", self.manifest())
        for locale in ({"LANG": "C.UTF-8"}, {"LC_ALL": "C"}, {"LC_ALL": "C.UTF-8"}, {}):
            with self.subTest(locale=locale):
                r = run("check", **locale)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("verified ", r.stdout)
                self.assertFalse((self.state / "MISMATCH").exists())

    def test_a_manifest_read_that_fails_part_way_never_verifies(self) -> None:
        # The read's own status counts: a read that returns exactly the lines
        # the boot chain hashes to and then fails is not the stored manifest.
        self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
        manifest = self.state / "manifest.sha256"
        manifest.write_text(manifest.read_text() + "0" * 64 + "  /boot/vmlinuz-extra\n")
        (self.sb.bin / "tr").write_text(
            '#!/bin/sh\nn=$(( $(/bin/cat "$FLEET_TR_COUNT" 2>/dev/null || echo 0) + 1 ))\necho "$n" > "$FLEET_TR_COUNT"\n'
            'if [ "$n" -le 4 ]; then exec /usr/bin/tr "$@"; fi\n/usr/bin/tr "$@" | head -n 4\nexit 1\n')
        (self.sb.bin / "tr").chmod(0o755)
        r = subprocess.run([lib.BASH, str(self.script), "check"], capture_output=True, text=True, timeout=60,
                           env=self.sb.env(WINS_BOOT_INTEGRITY_ROOT=str(self.root),
                                           WINS_BOOT_INTEGRITY_STATE_DIR=str(self.state),
                                           FLEET_TR_COUNT=str(self.sb.path("tr.count"))))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("is unreadable or malformed", r.stdout)
        self.assertNotIn("verified ", r.stdout)
        self.assertTrue((self.state / "MISMATCH").exists())

    def test_a_nul_in_hash_output_never_records_or_verifies(self) -> None:
        self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
        recorded = self.manifest()
        stat_file = self.state / "manifest.stat"
        stat_before = stat_file.read_bytes()
        pending = self.state / "MISMATCH"
        pending.write_text("held\n")
        (self.sb.bin / "sha256sum").write_text(
            "#!/usr/bin/env python3\n"
            "import hashlib, sys\n"
            "digest = hashlib.sha256(sys.stdin.buffer.read()).hexdigest()\n"
            'sys.stdout.buffer.write((digest[:32] + "\\0" + digest[32:] + "  -\\n").encode())\n'
        )
        result = self.bi("record", "--accept-current")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not read or hash", result.stderr)
        self.assertEqual(self.manifest(), recorded)
        self.assertEqual(stat_file.read_bytes(), stat_before)
        self.assertEqual(pending.read_text(), "held\n")
        result = self.bi("check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("BOOT-CHAIN MISMATCH: could not read or hash", result.stdout)
        self.assertNotIn("verified ", result.stdout)

    def test_a_stat_record_read_that_fails_is_never_a_match(self) -> None:
        # Astra: a cat of manifest.stat that printed the matching record and
        # then failed skipped the re-hash. A failed read re-hashes.
        self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
        recorded = self.manifest()
        (self.sb.bin / "cat").write_text('#!/bin/sh\n/bin/cat "$@"\nexit 1\n')
        (self.sb.bin / "cat").chmod(0o755)
        r = self.bi("record", "--source", "dpkg")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("nothing re-hashed", r.stdout)
        self.assertIn("recorded 4 boot-chain file(s) (dpkg)", r.stdout)
        self.assertEqual(self.manifest(), recorded)

    def test_a_sanctioned_dpkg_change_is_re_baselined(self) -> None:
        self.assertEqual(self.bi("record", "--source", "installer").returncode, 0)
        (self.root / "boot" / "grub" / "grub.cfg").write_text("cfg after update-grub")
        self.assertEqual(self.bi("record", "--source", "dpkg").returncode, 0)
        self.assertEqual(self.bi("check").returncode, 0)

    def test_the_monitor_raises_a_p1_alert_for_both_lines(self) -> None:
        mon = lib.heredoc(SRC, "cat > /usr/local/bin/wins-security-alert-monitor <<'PYEOF'", "PYEOF")
        tree = ast.parse(mon)
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "monitor_journal")
        sent = []
        lines = ("1760000000.0 hub wins-boot-integrity[812]: wins-boot-integrity: BOOT-CHAIN MISMATCH: changed since "
                 "the last sanctioned install or upgrade: /boot/initrd.img-6.8.0-146-generic\n"
                 "1760000001.0 hub wins-boot-integrity[813]: wins-boot-integrity: BOOT-CHAIN UNRECORDED: no manifest\n"
                 "1760000002.0 hub wins-boot-integrity[814]: wins-boot-integrity: verified 4 boot-chain file(s)\n")

        class FakeSubprocess:
            PIPE = -1
            DEVNULL = -3

            @staticmethod
            def run(*a, **k):
                return types.SimpleNamespace(stdout=lines)

            @staticmethod
            def Popen(*a, **k):
                return types.SimpleNamespace(
                    stdout=lines.splitlines(True), returncode=0, wait=lambda timeout=None: 0)

        ns = {"STATE_DIR": self.sb.tmp, "time": __import__("time"), "re": re, "subprocess": FakeSubprocess,
              "send_alert": lambda p, t, s, d, **k: sent.append((p, t, s, d, k)),
              "event_hash": lambda v: "h", "source_from_line": lambda line: "",
              "source_in_admin_ssh_network": lambda ip: False, "write_journal_cursor": lambda *a: None}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), "monitor", "exec"), ns)
        ns["monitor_journal"]()
        self.assertEqual([(p, t) for p, t, *_ in sent], [(1, "boot chain integrity mismatch")] * 2)
        self.assertEqual([d["unrecorded"] for *_, d, _ in sent], [False, True])
        # FLEET1 Turn 3: a guard that FAILED is never reported as a repair.
        sent.clear()
        lines = ("1760000003.0 hub wins-grub-superuser-guard[901]: GRUB-SUPERUSER REAPPLIED: a package replaced x\n"
                 "1760000004.0 hub wins-grub-superuser-guard[902]: GRUB-SUPERUSER REMOVED: x\n"
                 "1760000005.0 hub wins-grub-superuser-guard[903]: GRUB-SUPERUSER FAILED: update-grub failed\n")
        ns["monitor_journal"]()
        self.assertEqual([(p, t) for p, t, *_ in sent], [(1, "grub superuser guard acted")] * 3)
        self.assertEqual([(d["removed"], d["failed"]) for *_, d, _ in sent],
                         [(False, False), (True, False), (False, True)])

    def test_the_installer_wires_the_hook_the_unit_and_the_gate(self) -> None:
        start = SRC.index("\nwrite_hub_boot_integrity() {\n")
        body = SRC[start:SRC.index("\nverify_hub_console_hardening() {\n", start)]
        self.assertIn('DPkg::Post-Invoke { "if [ -x /usr/local/sbin/wins-boot-integrity ]; then '
                      '/usr/local/sbin/wins-boot-integrity record --source dpkg || true; fi"; };', body)
        self.assertIn("ExecStart=/usr/local/sbin/wins-boot-integrity check", body)
        self.assertIn("RequiresMountsFor=/boot", body)
        self.assertIn("record --source installer", body)
        # FLEET1 Turn 2 (Astra): install -d changes an existing directory's
        # mode, so /usr/local/sbin is never made root-only here.
        self.assertIn("  install -d -m 0755 /usr/local/sbin || return 1\n", body)
        for line in body.splitlines():
            if line.strip().startswith("install -d") and "/usr/local/sbin" in line:
                self.assertIn("-m 0755", line, line)
        self.assertEqual(body.lstrip("\n").split("\n", 2)[1].strip(), "hub_console_hardening_applies || return 0")
        main = SRC[SRC.rindex("\nmain() {\n"):]
        self.assertLess(main.index("  configure_hub_grub_superuser || exit 1\n"), main.index("  write_hub_boot_integrity || exit 1\n"))
        self.assertLess(main.index("  write_hub_boot_integrity || exit 1\n"), main.index("  postflight_control\n"))
        self.assertIn("  verify_hub_console_hardening || return 1\n", lib.function_text(SRC, "postflight_control"))
        applies = lib.function_text(SRC, "hub_console_hardening_applies")
        self.assertIn('[[ "${CONTROL_DISK_ENCRYPTION_EFFECTIVE:-}" == "luks" ]]', applies)


CAT_FAILS = r'''#!/bin/sh
# FLEET_CAT_FAIL_AT=N: the Nth cat writes 40 bytes and fails, as on a full disk.
n=$(( $(/bin/cat "$FLEET_CAT_COUNT" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$FLEET_CAT_COUNT"
if [ "$n" = "${FLEET_CAT_FAIL_AT:-0}" ]; then head -c 40; exit 1; fi
exec /bin/cat "$@"
'''


class WriteBootIntegrityTests(Case):
    """write_hub_boot_integrity under main's `|| exit 1` (errexit off), sandboxed (FLEET1 Turn 4)."""

    TARGETS = ("usr/local/sbin/wins-boot-integrity", "etc/apt/apt.conf.d/99winsvpn-boot-integrity",
               "usr/local/sbin/wins-grub-superuser-guard", "etc/apt/apt.conf.d/98winsvpn-grub-superuser-guard",
               "etc/systemd/system/wins-boot-integrity.service")

    def setUp(self) -> None:
        super().setUp()
        self.r = self.sb.path("r")
        for d in ("etc/apt/apt.conf.d", "etc/systemd/system", "boot/grub"):
            (self.r / d).mkdir(parents=True)
        (self.r / "boot/grub/grub.cfg").write_text("cfg")
        for name, body in {"cat": CAT_FAILS, "chown": CHOWN,
                           "systemctl": '#!/bin/sh\nprintf "systemctl %s\\n" "$*" >> "$FLEET_CALLS"\n'}.items():
            (self.sb.bin / name).write_text(body)
            (self.sb.bin / name).chmod(0o755)

    def write(self, **env: str) -> subprocess.CompletedProcess:
        # The here-documents hold column-0 braces: take the text up to the next function.
        fn = SRC[SRC.index("\nwrite_hub_boot_integrity() {\n") + 1:SRC.index("\nverify_hub_console_hardening() {\n") + 1]
        for prefix in ("/usr/local/sbin", "/var/lib/wins-boot-integrity", "/etc/apt/apt.conf.d", "/etc/systemd/system"):
            fn = fn.replace(prefix, f"{self.r}{prefix}")
        script = (lib.LOG_STUBS + "set -Eeuo pipefail\nCONTROL_DISK_ENCRYPTION_EFFECTIVE=luks\n"
                  + lib.function_text(SRC, "hub_console_hardening_applies") + fn
                  + '\nwrite_hub_boot_integrity || { echo "step failed"; exit 1; }\n')
        return self.sb.run(script, WINS_BOOT_INTEGRITY_ROOT=str(self.r),
                           FLEET_CAT_COUNT=str(self.sb.path("cat.count")), **env)

    def test_every_file_is_written_and_the_manifest_recorded(self) -> None:
        r = self.write()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for target in self.TARGETS:
            self.assertTrue((self.r / target).stat().st_size > 100, target)
        self.assertEqual(self.sb.path("cat.count").read_text().strip(), str(len(self.TARGETS)))
        self.assertIn("recorded 1 boot-chain file(s) (installer)", r.stdout)
        self.assertIn("systemctl daemon-reload", self.sb.logged())

    def test_a_write_that_fails_stops_the_step(self) -> None:
        for at, target in enumerate(self.TARGETS, start=1):
            with self.subTest(target=target):
                self.tearDown()
                self.setUp()
                r = self.write(FLEET_CAT_FAIL_AT=str(at))
                self.assertEqual(r.returncode, 1, target)
                self.assertIn("step failed", r.stdout)
                self.assertEqual(self.sb.path("cat.count").read_text().strip(), str(at), "nothing after it is written")
                self.assertNotIn("systemctl daemon-reload", self.sb.logged())
                self.assertFalse((self.r / "var/lib/wins-boot-integrity/manifest.sha256").exists())


    # --- FLEET1 Turn 5 (Claude seat): a rerun that cannot write keeps every
    # previous file whole (temp file plus rename) and leaves no temp file.

    MODES = (0o700, 0o644, 0o700, 0o644, 0o644)

    def temps(self) -> list[str]:
        return sorted(str(p) for d in ("usr/local/sbin", "etc/apt/apt.conf.d", "etc/systemd/system")
                      for p in (self.r / d).iterdir() if p.name.startswith("."))

    def stub(self, name: str, body: str) -> None:
        (self.sb.bin / name).write_text(body)
        (self.sb.bin / name).chmod(0o755)

    def test_generated_files_get_their_modes_owner_and_a_hidden_temp(self) -> None:
        self.stub("mktemp", '#!/bin/sh\nprintf "mktemp %s\\n" "$*" >> "$FLEET_CALLS"\nexec /usr/bin/mktemp "$@"\n')
        r = self.write()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for target, mode in zip(self.TARGETS, self.MODES):
            self.assertEqual(oct((self.r / target).stat().st_mode & 0o777), oct(mode), target)
        self.assertEqual(self.temps(), [])
        calls = self.sb.logged()
        templates = [c.split(" ", 1)[1] for c in calls if c.startswith("mktemp ")]
        self.assertEqual(templates[:-1], [f"{self.r}/{t.rsplit('/', 1)[0]}/.{t.rsplit('/', 1)[1]}.XXXXXX"
                                     for t in self.TARGETS])
        self.assertTrue(templates[-1].endswith("/var/lib/wins-boot-integrity/manifest.XXXXXX"), templates)
        owned = [c for c in calls if c.startswith("chown root:root ")]
        self.assertEqual(len(owned), len(self.TARGETS), calls)
        self.assertTrue(all("/." in c for c in owned), owned)

    def test_a_failed_rewrite_keeps_every_previous_file(self) -> None:
        failures = {f"write {at} fails": {"FLEET_CAT_FAIL_AT": str(at)} for at in range(1, len(self.TARGETS) + 1)}
        failures["chown fails"] = {"FLEET_CHOWN_FAILS": "1"}
        failures["rename fails"] = {"FLEET_MV_FAILS": "1"}
        for label, env in failures.items():
            with self.subTest(label=label):
                self.tearDown()
                self.setUp()
                self.assertEqual(self.write().returncode, 0)
                before = {t: (self.r / t).read_bytes() for t in self.TARGETS}
                self.assertTrue(all(len(b) > 100 for b in before.values()))
                self.sb.path("cat.count").unlink()
                self.stub("mv", '#!/bin/sh\n[ "${FLEET_MV_FAILS:-0}" = 1 ] && exit 1\nexec /bin/mv "$@"\n')
                self.sb.calls.unlink(missing_ok=True)
                r = self.write(**env)
                self.assertEqual(r.returncode, 1, label)
                self.assertIn("step failed", r.stdout)
                for target, mode in zip(self.TARGETS, self.MODES):
                    self.assertEqual((self.r / target).read_bytes(), before[target], f"{label}: {target}")
                    self.assertEqual(oct((self.r / target).stat().st_mode & 0o777), oct(mode), f"{label}: {target}")
                self.assertEqual(self.temps(), [], label)
                self.assertNotIn("systemctl daemon-reload", self.sb.logged())

    def test_a_directory_in_place_of_a_file_is_refused(self) -> None:
        (self.r / "usr/local/sbin/wins-boot-integrity").mkdir(parents=True)
        r = self.write()
        self.assertEqual(r.returncode, 1)
        self.assertIn("is a directory; refusing to replace it", r.stderr)
        self.assertEqual(list((self.r / "usr/local/sbin/wins-boot-integrity").iterdir()), [])
        self.assertEqual(self.temps(), [])

    def test_the_h0_inventory_still_lists_the_generated_files(self) -> None:
        spec = importlib.util.spec_from_file_location("h0_inv", lib.ROOT / "server" / "h0_privileged_job_inventory.py")
        h0 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(h0)
        data = h0.inventory(SRC)
        helpers = {h["target"]: h for h in data["helpers"]}
        for target in ("/usr/local/sbin/wins-boot-integrity", "/usr/local/sbin/wins-grub-superuser-guard"):
            self.assertIn(target, helpers)
            self.assertEqual(helpers[target]["language"], "shell")
        units = {u["target"]: u for u in data["units"]}
        unit = units["/etc/systemd/system/wins-boot-integrity.service"]
        self.assertEqual(unit["linked_helpers"], ["/usr/local/sbin/wins-boot-integrity"])
        self.assertEqual(unit["sandbox"]["ProtectSystem"], ["strict"])


class ConsoleHardeningPostflightTests(Case):
    """verify_hub_console_hardening run against a sandbox root (FLEET1 Turn 3)."""

    def setUp(self) -> None:
        super().setUp()
        self.r = self.sb.path("r")
        self.sbin = self.r / "usr/local/sbin"
        self.state = self.r / "var/lib/wins-boot-integrity"
        self.apt = self.r / "etc/apt/apt.conf.d"
        for d in (self.sbin, self.state, self.apt):
            d.mkdir(parents=True)
        body = SRC[SRC.index("\nwrite_hub_boot_integrity() {\n"):SRC.index("\nverify_hub_console_hardening() {\n")]
        for name in ("99winsvpn-boot-integrity", "98winsvpn-grub-superuser-guard"):
            hook = lib.heredoc(body, f"/etc/apt/apt.conf.d/{name} <<'EOF'", "EOF")
            (self.apt / name).write_text(hook.replace("/usr/local/sbin/", f"{self.r}/usr/local/sbin/"))
        for name in ("wins-boot-integrity", "wins-grub-superuser-guard"):
            (self.sbin / name).write_text('#!/bin/sh\nprintf "%s %s\\n" "${0##*/}" "$*" >> "$FLEET_CALLS"\n'
                                          'exit "${FLEET_BI_RC:-0}"\n')
            (self.sbin / name).chmod(0o700)
        (self.state / "manifest.sha256").write_text("0" * 64 + "  /boot/grub/grub.cfg\n")
        (self.sb.bin / "systemctl").write_text('#!/bin/sh\n[ "$1" = is-enabled ] && echo "${FLEET_ENABLED:-enabled}"\n'
                                              'exit 0\n')
        (self.sb.bin / "systemctl").chmod(0o755)

    def verify(self, **env: str) -> subprocess.CompletedProcess:
        fn = lib.function_text(SRC, "verify_hub_console_hardening")
        for prefix in ("/usr/local/sbin/", "/var/lib/wins-boot-integrity/", "/etc/apt/apt.conf.d/"):
            fn = fn.replace(prefix, f"{self.r}{prefix}")
        script = (lib.LOG_STUBS + "CONTROL_DISK_ENCRYPTION_EFFECTIVE=luks\n"
                  + lib.function_text(SRC, "hub_console_hardening_applies") + fn + "\nverify_hub_console_hardening\n")
        return self.sb.run(script, **env)

    def test_an_intact_setup_passes_and_checks_the_boot_chain(self) -> None:
        r = self.verify()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("wins-boot-integrity check", self.sb.logged())

    def test_a_missing_or_unwired_grub_guard_fails_postflight(self) -> None:
        # Claude seat's surviving mutant: postflight without the guard check.
        breaks = {
            "guard missing": lambda: (self.sbin / "wins-grub-superuser-guard").unlink(),
            "guard not executable": lambda: (self.sbin / "wins-grub-superuser-guard").chmod(0o600),
            "hook missing": lambda: (self.apt / "98winsvpn-grub-superuser-guard").unlink(),
            "hook does not run the guard": lambda: (self.apt / "98winsvpn-grub-superuser-guard").write_text("// x\n"),
        }
        for label, breaker in breaks.items():
            with self.subTest(label=label):
                self.tearDown()
                self.setUp()
                breaker()
                r = self.verify()
                self.assertEqual(r.returncode, 1, label)
                self.assertIn("TP-R2: the GRUB superuser dpkg guard is missing.", r.stderr)

    def test_the_other_gates_fail_postflight(self) -> None:
        breaks = {
            "helper mode": (lambda: (self.sbin / "wins-boot-integrity").chmod(0o755), {}, "not root 0700"),
            "re-baseline hook": (lambda: (self.apt / "99winsvpn-boot-integrity").write_text("// x\n"), {},
                                 "the dpkg re-baseline hook is missing"),
            "unit disabled": (lambda: None, {"FLEET_ENABLED": "disabled"}, "is not enabled"),
            "check fails": (lambda: None, {"FLEET_BI_RC": "1"}, "does not match the manifest"),
        }
        for label, (breaker, env, needle) in breaks.items():
            with self.subTest(label=label):
                self.tearDown()
                self.setUp()
                breaker()
                r = self.verify(**env)
                self.assertEqual(r.returncode, 1, label)
                self.assertIn(needle, r.stderr)

    def test_a_stat_or_systemctl_that_fails_is_never_a_pass(self) -> None:
        # FLEET1 Turn 5 (Astra's stat class): the right words from a command
        # that then failed are not a verification.
        breaks = {
            "stat prints 0:700 and fails": ("stat", "#!/bin/sh\necho 0:700\nexit 1\n", "not root 0700"),
            "is-enabled prints enabled and fails": (
                "systemctl", '#!/bin/sh\n[ "$1" = is-enabled ] && { echo enabled; exit 1; }\nexit 0\n', "is not enabled"),
        }
        for label, (name, body, needle) in breaks.items():
            with self.subTest(label=label):
                self.tearDown()
                self.setUp()
                (self.sb.bin / name).write_text(body)
                (self.sb.bin / name).chmod(0o755)
                r = self.verify()
                self.assertEqual(r.returncode, 1, label)
                self.assertIn(needle, r.stderr)

    def test_a_missing_manifest_names_the_remedy_when_a_boot_holds_it(self) -> None:
        (self.state / "manifest.sha256").unlink()
        r = self.verify()
        self.assertEqual(r.returncode, 1)
        self.assertIn("TP-R2: no boot-chain manifest is recorded.", r.stderr)
        self.assertNotIn("--accept-current", r.stderr)
        (self.state / "MISMATCH").write_text("2026-10-09T00:00:00Z\n")
        r = self.verify()
        self.assertEqual(r.returncode, 1)
        self.assertIn("A boot found none and it is held", r.stderr)
        self.assertIn("wins-boot-integrity record --accept-current", r.stderr)

    def test_a_pending_mismatch_warns_and_skips_the_check(self) -> None:
        (self.state / "MISMATCH").write_text("2026-10-09T00:00:00Z\n")
        r = self.verify(FLEET_BI_RC="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("record --accept-current", r.stderr)
        self.assertNotIn("wins-boot-integrity check", self.sb.logged())


# --- TP-H6, TP-W1 --------------------------------------------------------------

class DocsAndSiteConfigTests(unittest.TestCase):
    def test_the_recovery_contract_matches_what_the_tools_do(self) -> None:
        doc = (lib.ROOT / "docs" / "HUB_BACKUP_RECOVERY_CONTRACT.md").read_text(encoding="utf-8")
        for needle in ("WINS_RESTORE_AGE_IDENTITY", ".tar.gz.age", "EXCLUDING\n   `./root/vpn_auth/main.py`",
                       "stop `wins-hub.service`", "`litestream.service`", "litestream restore",
                       "/root/.ssh/wins_litestream_ed25519", "/etc/winsvpn/backup-recipients.age",
                       "`--validate` is an\n   alias of `--preflight`"):
            self.assertIn(needle, doc)
        self.assertNotIn("installer postflight/canary checks", doc)
        self.assertIn('identity="${WINS_RESTORE_AGE_IDENTITY:-}"', restore_preflight_body())

    def test_the_restore_drops_stale_wal_files_and_checks_the_reconciliation(self) -> None:
        doc = (lib.ROOT / "docs" / "HUB_BACKUP_RECOVERY_CONTRACT.md").read_text(encoding="utf-8")
        step6 = doc.split("\n6. ", 1)[1].split("\n7. ", 1)[0]
        holders = "find /proc/[0-9]*/fd -lname '/root/vpn_auth/*.db*'"
        sidecars = "rm -f /root/vpn_auth/vpn_users.db-wal /root/vpn_auth/vpn_users.db-shm"
        reconcile = ("sqlite3 -bail -cmd '.timeout 30000' /root/vpn_auth/vpn_users.db"
                     " < server/db/reconcile_redemption_ack_outbox.sql")
        count = 'test "$(sqlite3 -readonly /root/vpn_auth/vpn_users.db'
        for needle in (holders, sidecars, reconcile, count,
                       "/root/vpn_auth/winn3_authority_ledger.db-wal /root/vpn_auth/winn3_authority_ledger.db-shm"):
            self.assertIn(needle, step6)
        # A WAL left by step 4 is replayed over the restored file by the first
        # opener, so it goes after the holder check and before the extract and
        # before Litestream reopens the database.
        self.assertLess(step6.index(holders), step6.index(sidecars))
        self.assertLess(step6.index(sidecars), step6.index("decrypt and extract the archive EXCLUDING"))
        self.assertLess(step6.index(sidecars), step6.index("then start\n   `litestream.service` again"))
        self.assertLess(step6.index(reconcile), step6.index(count))
        self.assertLess(step6.index(count), step6.index("litestream sync"))

    def test_netlify_routes_to_the_live_sync_hostname(self) -> None:
        text = (lib.ROOT / "netlify.toml").read_text(encoding="utf-8")
        self.assertNotIn("app-cloud-sync.net", text)
        self.assertEqual(re.findall(r'^to = "(https://[^/]+)/', text, re.M), ["https://sync.winsvpn.org"] * 3)
        retired = re.search(r'CLOUDFLARE_RETIRED_APPCLOUD_HUB_RECORDS_DEFAULT="\$\{CLOUDFLARE_RETIRED_APPCLOUD_HUB_RECORDS:-([^}]*)\}"', SRC)
        self.assertIn("sync.app-cloud-sync.net", retired.group(1).split(), "the installer deletes that record")


if __name__ == "__main__":
    unittest.main()
