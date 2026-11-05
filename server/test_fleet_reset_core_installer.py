#!/usr/bin/env python3
"""Fleet reset plan 2026-10-08 (FLEET1): Core installer changes.

The SHIPPED bash of server/wins_core_server_setup_ONETOUCH.sh is extracted and
run under Bash 4+ with host effects faked (fleet_reset_testlib). Nothing on
the host changes. The replica receiver's own TP-C1 cases are in
server/test_core_replica_receiver.py.

  TP-C1  the disk-encryption default is auto (as the comment says): a LUKS
         root resolves to luks, a plain root to substitute, which still needs
         the exact acceptance.
  TP-C2  a hub that answers 401 to this Core's persisted token: with a fresh
         grant, the grant is exchanged before any host mutation and the run
         continues only through an authenticated withdrawal (FLEET1 Turn 2,
         Astra: 401 does not prove there is no promotion); without one, or
         when the new credential is refused too, the run stops; every other
         refusal still stops the run with nothing changed. FLEET1 Turn 7
         (Astra): a transfer that printed 200 and a valid body, then failed,
         is HTTP 000 and never a withdrawal.
  TP-C3  hub pairing inputs supplied for this run replace the persisted ones.
  TP-C4  no implicit 'ubuntu' admin account under a non-sudo root run.

Run: python3 -B -m pytest -q -p no:cacheprovider server/test_fleet_reset_core_installer.py
     WINS_FLEET_CORE=/path/to/installer ... (mutant runs)
"""

from __future__ import annotations

import json
import re
import subprocess
import textwrap
import unittest

import fleet_reset_testlib as lib

CORE = lib.installer("WINS_FLEET_CORE", "server/wins_core_server_setup_ONETOUCH.sh")
SRC = CORE.read_text(encoding="utf-8")


class Case(unittest.TestCase):
    def setUp(self) -> None:
        self.sb = lib.Sandbox()

    def tearDown(self) -> None:
        self.sb.cleanup()


# --- TP-C1 ---------------------------------------------------------------------

class DiskPostureDefaultTests(Case):
    def posture(self, luks: bool, accept: str = "") -> subprocess.CompletedProcess:
        default = re.search(r'^CORE_DISK_ENCRYPTION_MODE="\$\{CORE_DISK_ENCRYPTION_MODE:-[a-z]+\}"$', SRC, re.M).group(0)
        script = lib.LOG_STUBS + textwrap.dedent(f'''
            root_backed_by_luks() {{ return {0 if luks else 1}; }}
            unencrypted_swap_devices() {{ :; }}
            refuse_legacy_loop_swap() {{ :; }}
            refuse_disk_swap_request() {{ :; }}
            CORE_DISK_ENCRYPTION_SUBSTITUTE_ACCEPT_REQUIRED=I_ACCEPT_OFFLINE_DISK_AND_SNAPSHOT_EXPOSURE
            CORE_DISK_ENCRYPTION_SUBSTITUTE_ACCEPT='{accept}'
            ENABLE_WINS_SWAPFILE=0 WINS_CRYPTSWAP_ENABLED=0
            unset CORE_DISK_ENCRYPTION_MODE
            {default}
        ''') + lib.function_text(SRC, "verify_disk_encryption_posture") + (
            '\n(verify_disk_encryption_posture) >/dev/null 2>"$FLEET_CALLS.err"; rc=$?\n'
            'cat "$FLEET_CALLS.err" >&2; printf "RC=%s\\n" "$rc"\n'
            'verify_disk_encryption_posture >/dev/null 2>&1 && printf "EFFECTIVE=%s\\n" "$CORE_DISK_ENCRYPTION_EFFECTIVE"\n')
        return self.sb.run(script)

    def test_the_default_is_auto(self) -> None:
        self.assertIn('CORE_DISK_ENCRYPTION_MODE="${CORE_DISK_ENCRYPTION_MODE:-auto}"', SRC)
        self.assertIn('echo "CORE_DISK_ENCRYPTION_MODE=auto|luks|substitute (default auto)"', SRC)

    def test_a_luks_root_still_resolves_to_luks(self) -> None:
        r = self.posture(luks=True)
        self.assertIn("RC=0", r.stdout, r.stderr)
        self.assertIn("EFFECTIVE=luks", r.stdout)

    def test_a_plain_root_needs_the_exact_acceptance(self) -> None:
        r = self.posture(luks=False)
        self.assertIn("RC=1", r.stdout)
        self.assertIn("resolved to the substitute posture, which requires explicit operator acceptance", r.stderr)
        self.assertNotIn("luks was requested", r.stderr)


# --- TP-C2 ---------------------------------------------------------------------

CURL = r"""#!/usr/bin/env bash
# -o FILE and -w '%{http_code}' as curl does; -f fails on >= 400 with no body.
# The hub's grant exchange (/api/v1/core/bootstrap) answers a new token, or
# fails (FLEET_BOOTSTRAP_FAILS=1). Withdrawals answer FLEET_CURL_CODES in turn.
printf 'curl %s\n' "$*" >> "$FLEET_CALLS"
out="" fail=0 writeout="" url="" req=""
while (($#)); do
  case "$1" in
    -o) out="$2"; shift ;;
    -w) writeout="$2"; shift ;;
    -fsS|-f) fail=1 ;;
    --config) cat "$2" >> "$FLEET_CALLS.config"; shift ;;
    --data-binary) req="${2#@}"; shift ;;
    -H|-X|--connect-timeout|--max-time) shift ;;
    http*) url="$1" ;;
  esac
  shift
done
if [[ "$url" == */api/v1/core/bootstrap ]]; then
  printf 'bootstrap\n' >> "$FLEET_CALLS"
  printf '%s\n' "$req" > "$FLEET_CALLS.req"
  [[ "${FLEET_BOOTSTRAP_FAILS:-0}" == 1 ]] && exit 22
  printf '{"ok":true,"core_token":"%s"}' "$FLEET_NEW_TOKEN"
  exit 0
fi
n=$(( $(cat "$FLEET_CALLS.n" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$FLEET_CALLS.n"
IFS=, read -ra codes <<< "${FLEET_CURL_CODES:-200}"
last=$(( ${#codes[@]} - 1 )); code="${codes[$((n - 1))]:-${codes[$last]}}"  # bash 3.2 has no [-1]
printf 'withdraw %s\n' "$code" >> "$FLEET_CALLS"
if ((fail)) && ((code >= 400)); then exit 22; fi
if [[ -n "$out" ]]; then printf '%s' "${FLEET_CURL_BODY:-}" > "$out"; else printf '%s' "${FLEET_CURL_BODY:-}"; fi
[[ -n "$writeout" ]] && printf '%s' "$code"
# FLEET1 Turn 7: a transfer that printed its status and body, then failed.
exit "${FLEET_CURL_RC:-0}"
"""
SYSTEMCTL = r"""#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "$FLEET_CALLS"
[[ "$1" == cat ]] && exit "${FLEET_TIMER_PRESENT:-0}"
exit 0
"""
FLOCK = '#!/bin/sh\nexit 0\n'
# FLEET1 Turn 3: jq that cannot build the grant request (FLEET_JQ_N_FAILS=1),
# and rm that cannot remove the spent grant request (FLEET_RM_REQ_FAILS=1).
JQ = '#!/bin/sh\n[ "$1" = -n ] && [ "${FLEET_JQ_N_FAILS:-0}" = 1 ] && exit 5\nexec %s "$@"\n' % lib.shutil.which("jq")
RM = r'''#!/bin/sh
for a in "$@"; do last="$a"; done
if [ "${FLEET_RM_REQ_FAILS:-0}" = 1 ] && [ -f "$FLEET_CALLS.req" ] && [ "$last" = "$(cat "$FLEET_CALLS.req")" ]; then
  exit 1
fi
exec /bin/rm "$@"
'''

GOOD = {"ok": True, "core_id": "north-america-core", "runtime_ready": False, "promoted": False,
        "pending_promotion_id": "", "active_promotion_id": "", "withdrawal_id": "a" * 32}


class RepairTests(Case):
    TOKEN = "persisted-core-token-value-0123456789"
    NEW_TOKEN = "fresh-core-token-from-the-grant-0123456789"
    GRANT = "G" * 40

    def setUp(self) -> None:
        super().setUp()
        for name, body in (("curl", CURL), ("systemctl", SYSTEMCTL), ("flock", FLOCK), ("jq", JQ), ("rm", RM)):
            (self.sb.bin / name).write_text(body)
            (self.sb.bin / name).chmod(0o755)
        self.core_dir = self.sb.path("wins-core")
        self.core_dir.mkdir()
        self.env_file = self.core_dir / "wins_core.env"
        self.env_file.write_text(f"CORE_ID=north-america-core\nCORE_TOKEN={self.TOKEN}\nADMIN_TOKEN=''\nCORE_NAME=x\n")
        self.env_file.chmod(0o600)

    def withdraw(self, codes: int | str, body: dict | str = "", grant: str = "", **env: str) -> subprocess.CompletedProcess:
        script = lib.LOG_STUBS + lib.stub_functions("persist_core_installer_withdrawal_state",
                                                    "select_awg_image",
                                                    "install_core_failure_hold_firewall") + textwrap.dedent(f"""
            set -Eeuo pipefail
            CORE_ENV_FILE={self.env_file}
            CORE_TOKEN='{self.TOKEN}'
            CORE_ID=north-america-core
            HUB_API_BASE=https://hub.winsvpn.org
            CORE_BOOTSTRAP_TOKEN='{grant}'
            CORE_SYNC_LOCK_FILE={self.sb.path("sync.lock")}
            CORE_SYNC_AGENT_PATH={self.sb.path("wins-core-sync")}
        """) + lib.function_text(SRC, "persist_core_token") + lib.function_text(SRC, "bootstrap_core_token") \
            + lib.function_text(SRC, "begin_core_deployment_withdrawal_before_mutation") + (
            '\nbegin_core_deployment_withdrawal_before_mutation; printf "RC=0 TOKEN=[%s] RERUN=%s\\n" '
            '"$CORE_TOKEN" "${CORE_INSTALLER_RERUN_ACTIVE:-0}"\n')
        payload = body if isinstance(body, str) else json.dumps(body)
        return self.sb.run(script, FLEET_CURL_CODES=str(codes), FLEET_CURL_BODY=payload,
                           FLEET_NEW_TOKEN=self.NEW_TOKEN, **env)

    def persisted_token(self) -> str:
        return re.search(r"^CORE_TOKEN=(.*)$", self.env_file.read_text(), re.M).group(1)

    def headers_sent(self) -> str:
        cfg = self.sb.path("calls.log.config")
        return cfg.read_text() if cfg.exists() else ""

    def test_a_401_with_a_grant_exchanges_it_then_withdraws_with_the_new_credential(self) -> None:
        # FLEET1 Turn 2 (Astra): 401 never skips the withdrawal; the grant is
        # validated by the hub before any host mutation, and the run continues
        # only through the authenticated withdrawal and its serving hold.
        r = self.withdraw("401,200", GOOD, grant=self.GRANT)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("HTTP 401 does not prove that this Core has no active promotion", r.stderr)
        self.assertIn(f"RC=0 TOKEN=[{self.NEW_TOKEN}] RERUN=1", r.stdout)
        self.assertEqual(self.persisted_token(), self.NEW_TOKEN)
        calls = self.sb.logged()
        self.assertEqual([c for c in calls if c in ("withdraw 401", "bootstrap", "withdraw 200")],
                         ["withdraw 401", "bootstrap", "withdraw 200"])
        self.assertLess(calls.index("withdraw 200"),
                        next(i for i, c in enumerate(calls) if c.startswith("persist_core_installer_withdrawal_state")))
        self.assertIn("install_core_failure_hold_firewall installer-rerun-" + "a" * 32, calls)
        sent = self.headers_sent().splitlines()
        self.assertEqual(len(sent), 2)
        self.assertIn(self.TOKEN, sent[0])
        self.assertIn(self.NEW_TOKEN, sent[1])
        for secret in (self.GRANT, self.TOKEN, self.NEW_TOKEN):
            self.assertNotIn(secret, r.stderr)

    def test_a_401_without_a_grant_refuses_and_changes_nothing(self) -> None:
        r = self.withdraw(401, '{"detail":"Unauthorized"}')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("HTTP 401 does not prove that this Core has no active promotion", r.stderr)
        self.assertEqual(self.persisted_token(), self.TOKEN)
        self.assertNotIn("bootstrap", self.sb.logged())
        self.assertFalse(any("systemctl disable" in c for c in self.sb.logged()))

    def test_a_refused_grant_changes_nothing(self) -> None:
        r = self.withdraw(401, "", grant=self.GRANT, FLEET_BOOTSTRAP_FAILS="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("re-pair grant exchange failed", r.stderr)
        self.assertEqual(self.persisted_token(), self.TOKEN)
        self.assertNotIn("persist_core_installer_withdrawal_state", " ".join(self.sb.logged()))
        self.assertFalse(any("systemctl disable" in c for c in self.sb.logged()))

    def test_a_401_for_the_new_credential_refuses_without_a_second_exchange(self) -> None:
        r = self.withdraw("401,401", "", grant=self.GRANT)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("rejected the freshly exchanged Core credential (HTTP 401)", r.stderr)
        self.assertEqual(self.sb.logged().count("bootstrap"), 1)
        self.assertNotIn("install_core_failure_hold_firewall", " ".join(self.sb.logged()))

    def test_other_refusals_stop_even_with_a_grant(self) -> None:
        for code, body in ((403, '{"detail":"Forbidden"}'), (500, ""), (400, '{"detail":"Core ID is invalid."}')):
            with self.subTest(code=code):
                r = self.withdraw(code, body, grant=self.GRANT)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(f"(HTTP {code})", r.stderr)
                self.assertEqual(self.persisted_token(), self.TOKEN)

    def test_an_error_body_that_looks_like_a_withdrawal_is_not_accepted(self) -> None:
        r = self.withdraw(409, GOOD, grant=self.GRANT)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("(HTTP 409)", r.stderr)

    def test_a_short_grant_does_not_unlock_the_re_pair(self) -> None:
        r = self.withdraw(401, "", grant="short")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.persisted_token(), self.TOKEN)
        self.assertNotIn("bootstrap", self.sb.logged())

    def test_the_old_agent_stops_only_after_the_authenticated_withdrawal(self) -> None:
        r = self.withdraw("401,200", GOOD, grant=self.GRANT)
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.sb.logged()
        self.assertLess(calls.index("withdraw 200"), calls.index("systemctl disable --now wins-core-sync.timer"))

    # --- FLEET1 Turn 3 (Astra): the exchanged credential is on disk, or the
    # run stops; request preparation failures stop before the grant is sent.

    def test_a_credential_that_cannot_be_saved_stops_the_re_pair(self) -> None:
        self.core_dir.chmod(0o500)  # mktemp beside the env file fails
        try:
            r = self.withdraw("401,200", GOOD, grant=self.GRANT)
        finally:
            self.core_dir.chmod(0o700)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("could not be saved", r.stderr)
        self.assertIn("refusing further host mutation", r.stderr)
        self.assertEqual(self.persisted_token(), self.TOKEN)
        calls = self.sb.logged()
        self.assertEqual(calls.count("bootstrap"), 1)
        self.assertNotIn("withdraw 200", calls)
        self.assertNotIn("install_core_failure_hold_firewall", " ".join(calls))
        self.assertFalse(any("systemctl disable" in c for c in calls))
        self.assertEqual(sorted(x.name for x in self.core_dir.iterdir()), ["wins_core.env"], "no temp file left")
        self.assertNotIn(self.NEW_TOKEN, r.stdout + r.stderr)

    def test_a_first_install_bootstrap_needs_the_env_file(self) -> None:
        self.env_file.unlink()
        script = lib.LOG_STUBS + textwrap.dedent(f"""
            set -Eeuo pipefail
            CORE_ENV_FILE={self.env_file}
            CORE_TOKEN=''
            CORE_ID=north-america-core
            HUB_API_BASE=https://hub.winsvpn.org
            CORE_BOOTSTRAP_TOKEN='{self.GRANT}'
        """) + lib.function_text(SRC, "persist_core_token") + lib.function_text(SRC, "bootstrap_core_token") + (
            '\nif bootstrap_core_token; then echo "RC=0 TOKEN=[$CORE_TOKEN]"; else echo "RC=1 TOKEN=[$CORE_TOKEN]"; fi\n')
        r = self.sb.run(script, FLEET_NEW_TOKEN=self.NEW_TOKEN)
        self.assertIn("RC=1 TOKEN=[]", r.stdout)
        self.assertIn("is missing", r.stderr)

    def test_an_env_file_holding_only_token_lines_is_rewritten(self) -> None:
        # grep -v selecting nothing (rc 1) is not a failure.
        self.env_file.write_text(f"CORE_TOKEN={self.TOKEN}\nADMIN_TOKEN=''\n")
        r = self.withdraw("401,200", GOOD, grant=self.GRANT)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.env_file.read_text(), f"CORE_TOKEN={self.NEW_TOKEN}\nADMIN_TOKEN=''\n")

    def test_a_grant_request_that_cannot_be_built_is_never_sent(self) -> None:
        r = self.withdraw(401, "", grant=self.GRANT, FLEET_JQ_N_FAILS="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("bootstrap", self.sb.logged())
        self.assertEqual(self.persisted_token(), self.TOKEN)

    def test_a_spent_grant_request_left_behind_still_persists_the_credential(self) -> None:
        # Deviation from Astra's literal code (`rm ... || return 1`): once the
        # hub has answered, the grant is consumed and the token hash replaced;
        # returning before persisting would strand the only valid credential.
        r = self.withdraw("401,200", GOOD, grant=self.GRANT, FLEET_RM_REQ_FAILS="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("holds the spent bootstrap grant", r.stderr)
        self.assertEqual(self.persisted_token(), self.NEW_TOKEN)
        self.assertNotIn(self.GRANT, r.stdout + r.stderr)

    def test_a_failed_transfer_is_never_a_withdrawal(self) -> None:
        # FLEET1 Turn 7 (Astra): curl printed 200 and a complete withdrawal
        # body, then exited non-zero (56 receive error, 18 partial file, 28
        # timeout). Its status is "000", and nothing is persisted or held.
        for rc in ("56", "18", "28"):
            with self.subTest(curl_rc=rc):
                for leftover in ("calls.log", "calls.log.n", "calls.log.config"):
                    self.sb.path(leftover).unlink(missing_ok=True)
                r = self.withdraw(200, GOOD, grant=self.GRANT, FLEET_CURL_RC=rc)
                self.assertNotEqual(r.returncode, 0)
                self.assertNotIn("RC=0", r.stdout)
                self.assertIn("Hub refused the pre-mutation Core deployment withdrawal (HTTP 000)", r.stderr)
                calls = " ".join(self.sb.logged())
                self.assertIn("withdraw 200", calls)
                self.assertNotIn("persist_core_installer_withdrawal_state", calls)
                self.assertNotIn("install_core_failure_hold_firewall", calls)
                self.assertNotIn("bootstrap", self.sb.logged())

    def test_a_good_withdrawal_takes_the_usual_path(self) -> None:
        r = self.withdraw(200, GOOD, grant=self.GRANT)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"TOKEN=[{self.TOKEN}] RERUN=1", r.stdout)
        self.assertIn("persist_core_installer_withdrawal_state", " ".join(self.sb.logged()))
        self.assertNotIn("bootstrap", self.sb.logged())
        self.assertNotIn(self.TOKEN, r.stderr)


# --- TP-C3 ---------------------------------------------------------------------

class SuppliedPairingInputsTests(Case):
    OLD_KEY = "ecdsa-sha2-nistp256 AAAAold"
    NEW_KEY = "ecdsa-sha2-nistp256 AAAAnew"

    def load(self, supplied: dict[str, str]) -> subprocess.CompletedProcess:
        env_file = self.sb.path("wins_core.env")
        env_file.write_text(f"CORE_REPLICA_HUB_HOST_KEY='{self.OLD_KEY}'\nCORE_REPLICA_HUB_SSH_HOST=old.example.test\n"
                            "CORE_AI_HUB_SSH_HOST=old.example.test\nCORE_NAME=persisted\n")
        env_file.chmod(0o600)
        decl = "declare -gA WINS_CORE_OPERATOR_SUPPLIED=()\n" + "".join(
            f"WINS_CORE_OPERATOR_SUPPLIED[{k}]='{v}'\n" for k, v in supplied.items())
        fn = (lib.function_text(SRC, "core_restore_operator_supplied_pairing_inputs")
              if "\ncore_restore_operator_supplied_pairing_inputs() {\n" in SRC else "")
        script = lib.LOG_STUBS + decl + f"CORE_ENV_FILE={env_file}\n" + fn + lib.function_text(
            SRC, "load_existing_core_env_for_preflight") + (
            "\nload_existing_core_env_for_preflight\n"
            'printf "KEY=%s\\nHOST=%s\\nAI=%s\\nNAME=%s\\n" "$CORE_REPLICA_HUB_HOST_KEY" "$CORE_REPLICA_HUB_SSH_HOST" '
            '"$CORE_AI_HUB_SSH_HOST" "$CORE_NAME"\n')
        return self.sb.run(script)

    def test_supplied_pairing_inputs_replace_persisted_ones(self) -> None:
        r = self.load({"CORE_REPLICA_HUB_HOST_KEY": self.NEW_KEY, "CORE_REPLICA_HUB_SSH_HOST": "new.example.test",
                       "CORE_NAME": "supplied"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"KEY={self.NEW_KEY}", r.stdout)
        self.assertIn("HOST=new.example.test", r.stdout)
        self.assertIn("AI=old.example.test", r.stdout, "not supplied: the persisted value stays")
        self.assertIn("NAME=persisted", r.stdout, "every other persisted value still wins (IA-CORE-08)")
        self.assertIn("CORE_NAME from", r.stderr)
        self.assertIn("CORE_REPLICA_HUB_HOST_KEY: the value supplied for this run replaces", r.stdout)

    def test_an_empty_supplied_value_does_not_erase_the_persisted_pin(self) -> None:
        r = self.load({"CORE_REPLICA_HUB_HOST_KEY": ""})
        self.assertIn(f"KEY={self.OLD_KEY}", r.stdout)

    def test_both_env_loads_restore_the_supplied_inputs(self) -> None:
        self.assertIn("core_restore_operator_supplied_pairing_inputs",
                      lib.function_text(SRC, "load_existing_core_env_for_preflight"))
        start = SRC.index("\nload_or_create_env() {\n")
        body = SRC[start:SRC.index("\n  CORE_MAX_XRAY_CONNECTIONS=", start)]
        self.assertIn('    source "${CORE_ENV_FILE}"\n    core_restore_operator_supplied_pairing_inputs\n', body)


# --- TP-C4 ---------------------------------------------------------------------

class ImplicitAdminUserTests(Case):
    def guard(self) -> str:
        body = lib.function_text(SRC, "preflight_core")
        start = body.find('  if [[ -z "${SUDO_USER:-}" && ! -f "${CORE_ENV_FILE}" \\')
        self.assertGreaterEqual(start, 0, "preflight_core has no implicit-admin-user guard")
        return body[start:body.index("\n  fi\n", start) + 6]

    def run_guard(self, sudo_user: str, env_file: bool, supplied: str) -> subprocess.CompletedProcess:
        path = self.sb.path("wins_core.env")
        if env_file:
            path.write_text("CORE_SSH_ADMIN_USER=aicore\n")
        elif path.exists():
            path.unlink()
        script = lib.LOG_STUBS + "declare -gA WINS_CORE_OPERATOR_SUPPLIED=()\n" + (
            f"WINS_CORE_OPERATOR_SUPPLIED[CORE_SSH_ADMIN_USER]='{supplied}'\n" if supplied else "") + (
            f"CORE_ENV_FILE={path}\nSUDO_USER='{sudo_user}'\n[[ -n \"$SUDO_USER\" ]] || unset SUDO_USER\n"
            f"run() {{\n{self.guard()}\n  echo PASSED\n}}\nrun\n")
        return self.sb.run(script)

    def test_a_root_run_with_nothing_supplied_is_refused(self) -> None:
        r = self.run_guard("", False, "")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("would default to 'ubuntu'", r.stderr)

    def test_any_named_source_passes(self) -> None:
        for sudo_user, env_file, supplied in (("aicore", False, ""), ("", True, ""), ("", False, "aicore")):
            with self.subTest(sudo_user=sudo_user, env_file=env_file, supplied=supplied):
                r = self.run_guard(sudo_user, env_file, supplied)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn("PASSED", r.stdout)

    def test_the_guard_runs_before_any_mutation(self) -> None:
        body = lib.function_text(SRC, "preflight_core")
        self.assertLess(body.index("CORE_SSH_ADMIN_USER is invalid."), body.index("would default to 'ubuntu'"))
        main = lib.function_text(SRC[SRC.rindex("\nmain() {\n"):], "main")
        self.assertLess(main.index("  preflight_core\n"), main.index("  acquire_core_deployment_lock\n"))


if __name__ == "__main__":
    unittest.main()
