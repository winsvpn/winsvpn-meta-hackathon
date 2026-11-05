#!/usr/bin/env bash
# Prove that a WINN3_GATEWAY_FORWARD=0 install is loud, and that the default
# is still 0. Mutates a PRIVATE copy under scratch — never the shared tree.
#
# A green this file cannot make fail is not evidence. Controls:
#   no-mutation   (live script)     must PASS
#   comment-only  (private copy)    must PASS
#   deliberate break (private copy) must FAIL, naming what broke
#     break-calls     comment out main() call sites
#     break-body      empty announce_non_forwarding_gateway
#     break-default   flip :-0 to :-1
#     break-stderr    announce uses winn3gw_warn (stderr-only) instead of warn_both
#     break-start     bare `start_service` so set -e skips the banner
#
# Dual-auth attestation coverage (env-gated, fail-closed):
#   dual-auth suite (live script)     must PASS
#     break-dualauth  strip the -dual-auth-ed-key flag line so a configured
#                     emission loses its flags (must FAIL the dual suite)
#
# F-02 replay-journal coverage (required; emission/resolve checks on every
# host, provisioning checks on Linux+root only):
#   replay-journal suite (live script) must PASS
#     break-replayjournal  strip the StateDirectory emission so a required
#                     unit loses the writable-path grant (must FAIL)
#
# Usage:
#   bash wins_winn3_gateway_install_forward_loud_test.sh
#   bash wins_winn3_gateway_install_forward_loud_test.sh /path/to/wins_winn3_gateway_install.sh
#
# Linux certification tool: the live installer's install path uses
# `install -d -o root -g root`, which fails on macOS ("unknown group root"),
# so the run_suite-based forward-loud controls and the dual-auth suite can
# never pass on a non-Linux audit host: those run on Linux only. The key-file
# security suite calls the installer's validation functions DIRECTLY
# (source + call, no install command), so it runs on every host and is what a
# macOS audit host executes. SKIP counts are named in the summary.
IS_LINUX=0
if [[ "$(uname -s)" == "Linux" ]]; then
  IS_LINUX=1
fi
set -euo pipefail
# OI-K4 (Round K): the installer reads MemTotal for host fit and fails closed
# without it. These cases test other properties, so they run against a
# 128 TiB fixture on which every explicit session count fits and an unset
# count still selects 64.
export WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO:-$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/testdata/winn3_gateway_meminfo/large}"

HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
INSTALL="$(python3 -B "${HERE}/../tools/winn3_gateway_test_source.py" "${1:-${HERE}/wins_data_plane_setup_ONETOUCH.sh}" --legacy-compat)"
# Never /tmp: detached lanes cannot read it back. Default is this lane's scratch.
WORKDIR="${WINN3_FORWARD_LOUD_WORKDIR:-${HERE}/../../../.spark_lanes/scratch/deploy_gateway_forward_default/testwork}"
mkdir -p "${WORKDIR}"

PASS=0
FAIL=0
BUILD_FAIL=0
SKIP=0

fail() { FAIL=$((FAIL + 1)); printf 'FAIL: %s\n' "$*"; }
pass() { PASS=$((PASS + 1)); printf 'PASS: %s\n' "$*"; }
build_fail() { BUILD_FAIL=$((BUILD_FAIL + 1)); printf 'BUILD_FAIL: %s\n' "$*"; }

SUITE_FAIL=0
SUITE_PASS=0
SUITE_BUILD=0

sfail() { SUITE_FAIL=$((SUITE_FAIL + 1)); printf '  FAIL: %s\n' "$*"; }
spass() { SUITE_PASS=$((SUITE_PASS + 1)); printf '  PASS: %s\n' "$*"; }
sbuild() { SUITE_BUILD=$((SUITE_BUILD + 1)); printf '  BUILD_FAIL: %s\n' "$*"; }

NEEDLES=(
  "THIS INSTALL IS A REFLECTOR"
  "CARRIES NO USER TRAFFIC"
  "DOES NOTHING"
  "WINN3_GATEWAY_FORWARD=1"
  "wins_winn3_gateway_install.sh --install"
  "--start"
  "CAP_NET_ADMIN"
  "write_unit"
)

# run_suite SCRIPT LABEL — structural + runtime checks against one copy.
# Sets SUITE_FAIL / SUITE_PASS / SUITE_BUILD for the caller. Does not touch
# the outer FAIL counter: inverted controls need to see a red suite without
# poisoning the final summary.
run_suite() {
  local script="$1" label="$2"
  local default_val calls src_rc start_rc needle
  SUITE_FAIL=0
  SUITE_PASS=0
  SUITE_BUILD=0

  if ! bash -n "${script}" 2>"${WORKDIR}/bash_n.err"; then
    sbuild "${label}: bash -n failed: $(tr '\n' ' ' < "${WORKDIR}/bash_n.err")"
    return 0
  fi
  spass "${label}: bash -n clean"

  if grep -F -q 'WINN3_GATEWAY_FORWARD="${WINN3_GATEWAY_FORWARD:-0}"' "${script}"; then
    spass "${label}: default assignment is still :-0"
  else
    sfail "${label}: default assignment WINN3_GATEWAY_FORWARD:-0 is missing or changed"
  fi

  if grep -F -q 'if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then' "${script}"; then
    spass "${label}: BASH_SOURCE guard present (script can be sourced without running main)"
  else
    sfail "${label}: BASH_SOURCE guard missing; sourcing would run main/require_root"
  fi

  awk '
    $0 == "main() {" {p=1}
    p {print}
    p && $0 == "}" {exit}
  ' "${script}" > "${WORKDIR}/main_body.txt"
  calls="$(grep -E -c '^[[:space:]]+announce_non_forwarding_gateway$' "${WORKDIR}/main_body.txt" || true)"
  if [[ "${calls}" -ge 2 ]]; then
    spass "${label}: main() calls announce_non_forwarding_gateway ${calls} times (need >=2: preflight + install/start)"
  else
    sfail "${label}: main() call count for announce_non_forwarding_gateway is ${calls}, need >=2 (a defined-but-uncalled function is a false green)"
  fi

  if grep -E -q 'start_service \|\| start_rc=\$\?' "${WORKDIR}/main_body.txt"; then
    spass "${label}: main() captures start_service status (start_service || start_rc=\$?)"
  else
    sfail "${label}: main() does not capture start_service status; set -e will skip the banner on a failed start"
  fi
  if grep -F -q 'return "${start_rc}"' "${WORKDIR}/main_body.txt"; then
    spass "${label}: main() returns start_rc after the banner"
  else
    sfail "${label}: main() does not return start_rc after the banner (a failed --start would look like success)"
  fi

  # Runtime: source (must not run main) and invoke the function.
  # Split stdout/stderr: a 2>&1 merge cannot see a stderr-only banner, which
  # is the hole `script --install > install.log` used to hit.
  src_rc=0
  env -u WINN3_GATEWAY_FORWARD bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    printf "DEFAULT=%s\n" "${WINN3_GATEWAY_FORWARD}"
    WINN3_GATEWAY_MODE=install
    announce_non_forwarding_gateway
  ' _ "${script}" >"${WORKDIR}/announce_default.stdout" 2>"${WORKDIR}/announce_default.stderr" || src_rc=$?
  if [[ "${src_rc}" -ne 0 ]]; then
    sfail "${label}: sourcing + announce at default FORWARD exited ${src_rc}"
    return 0
  fi

  default_val="$(awk -F= '/^DEFAULT=/ {print $2; exit}' "${WORKDIR}/announce_default.stdout")"
  if [[ "${default_val}" == "0" ]]; then
    spass "${label}: sourced default WINN3_GATEWAY_FORWARD is 0"
  else
    sfail "${label}: sourced default WINN3_GATEWAY_FORWARD is '${default_val}', want 0"
  fi

  for needle in "${NEEDLES[@]}"; do
    if grep -F -q -- "${needle}" "${WORKDIR}/announce_default.stdout"; then
      spass "${label}: default-FORWARD announce stdout contains '${needle}'"
    else
      sfail "${label}: default-FORWARD announce stdout missing '${needle}' (stderr-only is not loud in a redirected install log)"
    fi
    if grep -F -q -- "${needle}" "${WORKDIR}/announce_default.stderr"; then
      spass "${label}: default-FORWARD announce stderr contains '${needle}'"
    else
      sfail "${label}: default-FORWARD announce stderr missing '${needle}'"
    fi
  done

  src_rc=0
  env WINN3_GATEWAY_FORWARD=1 bash -c '
    set -euo pipefail
    source "$1"
    WINN3_GATEWAY_FORWARD=1
    WINN3_GATEWAY_MODE=install
    announce_non_forwarding_gateway
  ' _ "${script}" >"${WORKDIR}/announce_forward1.stdout" 2>"${WORKDIR}/announce_forward1.stderr" || src_rc=$?
  if [[ "${src_rc}" -ne 0 ]]; then
    sfail "${label}: announce at FORWARD=1 exited ${src_rc}"
    return 0
  fi
  if grep -F -q "THIS INSTALL IS A REFLECTOR" "${WORKDIR}/announce_forward1.stdout" \
     || grep -F -q "THIS INSTALL IS A REFLECTOR" "${WORKDIR}/announce_forward1.stderr"; then
    sfail "${label}: FORWARD=1 announce still printed THIS INSTALL IS A REFLECTOR"
  else
    spass "${label}: FORWARD=1 announce does not print the reflector banner"
  fi

  # Runtime: stubbed --start whose start_service returns 1 must still print
  # the banner on stdout, then exit nonzero. Install steps are stubbed so
  # this never touches /etc, systemd, or iptables.
  start_rc=0
  env -u WINN3_GATEWAY_FORWARD bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    require_root() { :; }
    refuse_on_hub() { :; }
    require_supported_production_os() { :; }
    validate_config() { return 0; }
    validate_cover() { :; }
    verify_staged_binary() { :; }
    ensure_service_user() { :; }
    install_binary() { :; }
    write_env_file() { :; }
    write_unit() { :; }
    enable_service() { :; }
    report_firewall() { :; }
    preflight_gateway_listen_layout() { :; }
    preflight_resolver() { :; }
    apply_listen_firewall() { :; }
    start_service() { return 1; }
    main --start
  ' _ "${script}" >"${WORKDIR}/start_fail.stdout" 2>"${WORKDIR}/start_fail.stderr" || start_rc=$?
  if grep -F -q "THIS INSTALL IS A REFLECTOR" "${WORKDIR}/start_fail.stdout"; then
    spass "${label}: stubbed --start with start_service=1 still printed the reflector banner on stdout"
  else
    sfail "${label}: stubbed --start with start_service=1 did not print THIS INSTALL IS A REFLECTOR on stdout (set -e likely skipped the banner)"
  fi
  if [[ "${start_rc}" -ne 0 ]]; then
    spass "${label}: stubbed --start with start_service=1 exited ${start_rc} (nonzero, banner did not swallow the failure)"
  else
    sfail "${label}: stubbed --start with start_service=1 exited 0; the failure was swallowed"
  fi
}

if [[ "${IS_LINUX}" -ne 1 ]]; then
  echo "SKIP: forward-loud run_suite controls (no-mutation, comment-only, break-*) require Linux: the stubbed install path uses install -o root -g root"
  SKIP=$((SKIP + 1))
else
  echo "=== no-mutation (live script) ==="
echo "script=${INSTALL}"
run_suite "${INSTALL}" "no-mutation"
if [[ "${SUITE_FAIL}" -eq 0 && "${SUITE_BUILD}" -eq 0 ]]; then
  pass "control no-mutation: suite passed (inner pass=${SUITE_PASS})"
else
  fail "control no-mutation: suite did not pass (inner fail=${SUITE_FAIL} build_fail=${SUITE_BUILD})"
fi

LIVE_COPY="${WORKDIR}/live.sh"
COMMENT_COPY="${WORKDIR}/comment_only.sh"
BREAK_CALLS="${WORKDIR}/break_calls.sh"
BREAK_BODY="${WORKDIR}/break_body.sh"
BREAK_DEFAULT="${WORKDIR}/break_default.sh"
BREAK_STDERR="${WORKDIR}/break_stderr.sh"
BREAK_START="${WORKDIR}/break_start.sh"

cat "${INSTALL}" > "${LIVE_COPY}"

echo "=== comment-only (private copy) ==="
cat "${LIVE_COPY}" > "${COMMENT_COPY}"
python3 -c '
import pathlib, sys
p = pathlib.Path(sys.argv[1])
text = p.read_text()
old = "#!/usr/bin/env bash\n"
if not text.startswith(old):
    sys.exit("shebang not at start")
p.write_text(old + "# comment-only mutation control; no behaviour change\n" + text[len(old):])
' "${COMMENT_COPY}"
run_suite "${COMMENT_COPY}" "comment-only"
if [[ "${SUITE_FAIL}" -eq 0 && "${SUITE_BUILD}" -eq 0 ]]; then
  pass "control comment-only: suite passed (inner pass=${SUITE_PASS})"
else
  fail "control comment-only: suite did not pass (inner fail=${SUITE_FAIL} build_fail=${SUITE_BUILD})"
fi

echo "=== deliberate break: comment out main() call sites (must FAIL) ==="
cat "${LIVE_COPY}" > "${BREAK_CALLS}"
python3 -c '
import pathlib, sys, re
p = pathlib.Path(sys.argv[1])
text = p.read_text()
new, n = re.subn(
    r"(?m)^([ \t]+)announce_non_forwarding_gateway$",
    r"\1# announce_non_forwarding_gateway",
    text,
)
if n < 2:
    sys.exit(f"expected to comment out >=2 call sites, got {n}")
p.write_text(new)
print(f"commented_out_calls={n}")
' "${BREAK_CALLS}"
run_suite "${BREAK_CALLS}" "break-calls"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control break-calls: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control break-calls: suite stayed green after commenting out the calls — the test cannot see its own guard"
fi

echo "=== deliberate break: empty announce body (must FAIL) ==="
cat "${LIVE_COPY}" > "${BREAK_BODY}"
python3 -c '
import pathlib, sys, re
p = pathlib.Path(sys.argv[1])
text = p.read_text()
new, n = re.subn(
    r"announce_non_forwarding_gateway\(\) \{.*?\n\}",
    "announce_non_forwarding_gateway() {\n  return 0\n}",
    text,
    count=1,
    flags=re.S,
)
if n != 1:
    sys.exit(f"expected to replace announce body once, got {n}")
p.write_text(new)
print("emptied_announce_body=1")
' "${BREAK_BODY}"
run_suite "${BREAK_BODY}" "break-body"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control break-body: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control break-body: suite stayed green after emptying the banner — needles were not actually required at runtime"
fi

echo "=== deliberate break: flip default to :-1 (must FAIL) ==="
cat "${LIVE_COPY}" > "${BREAK_DEFAULT}"
python3 -c '
import pathlib, sys, re
p = pathlib.Path(sys.argv[1])
text = p.read_text()
new, n = re.subn(
    r"^WINN3_GATEWAY_FORWARD=\"\$\{WINN3_GATEWAY_FORWARD:-0\}\"$",
    "WINN3_GATEWAY_FORWARD=\"${WINN3_GATEWAY_FORWARD:-1}\"",
    text,
    count=1,
    flags=re.M,
)
if n != 1:
    sys.exit(f"expected to flip default once, got {n}")
p.write_text(new)
print("flipped_default_to_1=1")
' "${BREAK_DEFAULT}"
run_suite "${BREAK_DEFAULT}" "break-default"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control break-default: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control break-default: suite stayed green after flipping the default to 1"
fi

echo "=== deliberate break: announce uses winn3gw_warn (stderr-only) (must FAIL) ==="
cat "${LIVE_COPY}" > "${BREAK_STDERR}"
python3 -c '
import pathlib, sys, re
p = pathlib.Path(sys.argv[1])
text = p.read_text()
new, n = re.subn(r"warn_both \"", "winn3gw_warn \"", text)
if n < 8:
    sys.exit(f"expected to rewrite >=8 warn_both calls, got {n}")
p.write_text(new)
print(f"rewrote_warn_both_calls={n}")
' "${BREAK_STDERR}"
run_suite "${BREAK_STDERR}" "break-stderr"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control break-stderr: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control break-stderr: suite stayed green after making the banner stderr-only — stdout needles were not required"
fi

echo "=== deliberate break: bare start_service (must FAIL) ==="
cat "${LIVE_COPY}" > "${BREAK_START}"
python3 -c '
import pathlib, sys, re
p = pathlib.Path(sys.argv[1])
text = p.read_text()
new, n = re.subn(
    r"(?m)^([ \t]+)start_service \|\| start_rc=\$\?$",
    r"\1start_service",
    text,
    count=1,
)
if n != 1:
    sys.exit(f"expected to strip || start_rc once, got {n}")
p.write_text(new)
print("stripped_start_service_status_capture=1")
' "${BREAK_START}"
run_suite "${BREAK_START}" "break-start"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control break-start: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control break-start: suite stayed green after a bare start_service — set -e skipping the banner was not visible"
fi

fi  # IS_LINUX

# ---------------------------------------------------------------------------
# Dual-auth attestation suite (live script only; standalone PASS/FAIL).
#
# The installer gained env-gated dual-auth support (WINN3_GATEWAY_DUAL_AUTH_ED_KEY
# / WINN3_GATEWAY_DUAL_AUTH_ML_SEED -> LoadCredential + 0400 runtime copies +
# -dual-auth-ed-key/-dual-auth-ml-seed flags) mirroring the fleet's
# 30-dual-auth-resolver.conf drop-in. This suite proves:
#   1. unset pair contributes NOTHING to the emitted unit,
#   2. set pair emits the two flags, the two LoadCredential rows, and the
#      0400 runtime re-install ExecStartPre,
#   3. validate_config and validate_dual_auth fail closed on a half-pair,
#      a loose-permissioned file, and a noncanonical hex shape.
# run_dual_auth_suite SCRIPT LABEL; sets SUITE_FAIL/SUITE_PASS/SUITE_BUILD
# like run_suite so the mutation control can reuse the same counters.
# Only full-line systemd comments are excluded; every other line remains checked.
unit_has_dual_auth_line() {
  awk '!/^[[:space:]]*[#;]/ && /dual-auth/ { found = 1 } END { exit !found }' "$1"
}

run_dual_auth_suite() {
  local script="$1" label="$2" rc
  SUITE_FAIL=0
  SUITE_PASS=0
  SUITE_BUILD=0

  if ! bash -n "${script}" 2>"${WORKDIR}/dual_bash_n.err"; then
    sbuild "${label}: bash -n failed: $(tr '\n' ' ' < "${WORKDIR}/dual_bash_n.err")"
    return 0
  fi
  spass "${label}: bash -n clean"

  # Structural: the gate and the emission block must exist in the text.
  grep -F -q 'WINN3_GATEWAY_DUAL_AUTH_ED_KEY="${WINN3_GATEWAY_DUAL_AUTH_ED_KEY:-}"' "${script}" \
    && spass "${label}: dual-auth env defaults declared" \
    || sfail "${label}: dual-auth env defaults missing (WINN3_GATEWAY_DUAL_AUTH_ED_KEY/ML_SEED)"
  grep -F -q 'validate_dual_auth' "${script}" \
    && spass "${label}: validate_dual_auth exists" \
    || sfail "${label}: validate_dual_auth is missing"
  grep -F -q 'preflight_dual_auth' "${script}" \
    && spass "${label}: preflight_dual_auth exists" \
    || sfail "${label}: preflight_dual_auth is missing"
  grep -F -q 'LoadCredential=dual-auth-ed-key:${WINN3_GATEWAY_DUAL_AUTH_ED_KEY}' "${script}" \
    && spass "${label}: dual-auth LoadCredential emission present" \
    || sfail "${label}: dual-auth LoadCredential emission missing"

  # Ordinary comment and active-directive controls keep the unset-pair gate exact.
  local comment_line active_line
  for comment_line in '# dual-auth' '  # dual-auth' '; dual-auth' '  ; dual-auth'; do
    printf '%s\n' "${comment_line}" > "${WORKDIR}/dual-comment-control.unit"
    if unit_has_dual_auth_line "${WORKDIR}/dual-comment-control.unit"; then
      sfail "${label}: full-line systemd comment counted as active dual-auth"
    else
      spass "${label}: full-line systemd comment ignored"
    fi
  done
  for active_line in 'LoadCredential=dual-auth-ed-key:/fixture/key' \
    '  -dual-auth-ed-key /run/fixture/key' \
    'ExecStartPre=/bin/cp /fixture/key /run/fixture/dual-auth-ed-key'; do
    printf '%s\n' "${active_line}" > "${WORKDIR}/dual-active-control.unit"
    if unit_has_dual_auth_line "${WORKDIR}/dual-active-control.unit"; then
      spass "${label}: active dual-auth line detected"
    else
      sfail "${label}: active dual-auth line ignored"
    fi
  done

  # Unset pair: the emitted unit must carry NOTHING dual-auth.
  rc=0
  env -u WINN3_GATEWAY_DUAL_AUTH_ED_KEY -u WINN3_GATEWAY_DUAL_AUTH_ML_SEED bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_PATH_MTU=1450
    WINN3_GATEWAY_PLAN=udp
    emit_unit_text
  ' _ "${script}" >"${WORKDIR}/dual_default.unit" 2>"${WORKDIR}/dual_default.err" || rc=$?
  if [[ "${rc}" -ne 0 ]]; then
    sfail "${label}: emit_unit_text with dual-auth unset exited ${rc}"
    return 0
  fi
  if unit_has_dual_auth_line "${WORKDIR}/dual_default.unit"; then
    sfail "${label}: unset dual-auth pair still emitted dual-auth lines (unset must contribute nothing)"
  else
    spass "${label}: unset dual-auth pair contributes nothing to the unit"
  fi

  # Set pair (well-formed temp files): flags + credentials + 0400 ExecStartPre.
  ED_FILE="${WORKDIR}/dual-ed.hex"
  ML_FILE="${WORKDIR}/dual-ml.hex"
  head -c 128 /dev/zero | tr '\0' 'e' > "${ED_FILE}"
  head -c 64 /dev/zero | tr '\0' 'f' > "${ML_FILE}"
  chmod 600 "${ED_FILE}" "${ML_FILE}"
  rc=0
  env WINN3_GATEWAY_DUAL_AUTH_ED_KEY="${ED_FILE}" WINN3_GATEWAY_DUAL_AUTH_ML_SEED="${ML_FILE}" bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_PATH_MTU=1450
    WINN3_GATEWAY_PLAN=udp
    emit_unit_text
  ' _ "${script}" >"${WORKDIR}/dual_on.unit" 2>"${WORKDIR}/dual_on.err" || rc=$?
  if [[ "${rc}" -ne 0 ]]; then
    sfail "${label}: emit_unit_text with dual-auth set exited ${rc}"
    return 0
  fi
  grep -F -q -- '-dual-auth-ed-key /run/winn3-gateway/dual-auth-ed-key' "${WORKDIR}/dual_on.unit" \
    && spass "${label}: set dual-auth pair emits -dual-auth-ed-key on the runtime path" \
    || sfail "${label}: set dual-auth pair did not emit -dual-auth-ed-key /run/winn3-gateway/dual-auth-ed-key"
  grep -F -q -- '-dual-auth-ml-seed /run/winn3-gateway/dual-auth-ml-seed' "${WORKDIR}/dual_on.unit" \
    && spass "${label}: set dual-auth pair emits -dual-auth-ml-seed on the runtime path" \
    || sfail "${label}: set dual-auth pair did not emit -dual-auth-ml-seed /run/winn3-gateway/dual-auth-ml-seed"
  grep -F -q -- "LoadCredential=dual-auth-ed-key:${ED_FILE}" "${WORKDIR}/dual_on.unit" \
    && spass "${label}: set dual-auth pair emits LoadCredential for the ed25519 key" \
    || sfail "${label}: set dual-auth pair did not emit LoadCredential=dual-auth-ed-key"
  grep -F -q -- "LoadCredential=dual-auth-ml-seed:${ML_FILE}" "${WORKDIR}/dual_on.unit" \
    && spass "${label}: set dual-auth pair emits LoadCredential for the ML-DSA-65 seed" \
    || sfail "${label}: set dual-auth pair did not emit LoadCredential=dual-auth-ml-seed"
  grep -F -q -- 'install -m 0400' "${WORKDIR}/dual_on.unit" \
    && spass "${label}: set dual-auth pair emits the 0400 runtime re-install (binary refuses group-readable secrets)" \
    || sfail "${label}: set dual-auth pair did not emit install -m 0400 (the 0440 LoadCredential surface would be refused)"
  grep -F -q -- 'for f in dual-auth-ed-key dual-auth-ml-seed' "${WORKDIR}/dual_on.unit" \
    && spass "${label}: dual-auth ExecStartPre covers both files" \
    || sfail "${label}: dual-auth ExecStartPre does not name both files"

  # Fail-closed gates, each in its own subshell because validate_dual_auth dies.
  rc=0
  env -u WINN3_GATEWAY_DUAL_AUTH_ED_KEY -u WINN3_GATEWAY_DUAL_AUTH_ML_SEED bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_DUAL_AUTH_ED_KEY=""
    WINN3_GATEWAY_DUAL_AUTH_ML_SEED=""
    validate_dual_auth
  ' _ "${script}" >"${WORKDIR}/dual_off.log" 2>&1 || rc=$?
  [[ "${rc}" -eq 0 ]] \
    && spass "${label}: validate_dual_auth accepts an unset pair (attestation off)" \
    || sfail "${label}: validate_dual_auth refused an unset pair (rc=${rc}); unset must be the legal off state"

  rc=0
  env -u WINN3_GATEWAY_DUAL_AUTH_ED_KEY -u WINN3_GATEWAY_DUAL_AUTH_ML_SEED bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_DUAL_AUTH_ED_KEY="'"${ED_FILE}"'"
    WINN3_GATEWAY_DUAL_AUTH_ML_SEED=""
    validate_dual_auth
  ' _ "${script}" >"${WORKDIR}/dual_half.log" 2>&1 || rc=$?
  [[ "${rc}" -ne 0 ]] \
    && spass "${label}: validate_dual_auth refuses a half-pair (ed only)" \
    || sfail "${label}: validate_dual_auth ACCEPTED a half-pair (ed only); the binary would crash-loop"

  rc=0
  env -u WINN3_GATEWAY_DUAL_AUTH_ED_KEY -u WINN3_GATEWAY_DUAL_AUTH_ML_SEED bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_DUAL_AUTH_ED_KEY=""
    WINN3_GATEWAY_DUAL_AUTH_ML_SEED="'"${ML_FILE}"'"
    validate_dual_auth
  ' _ "${script}" >"${WORKDIR}/dual_half2.log" 2>&1 || rc=$?
  [[ "${rc}" -ne 0 ]] \
    && spass "${label}: validate_dual_auth refuses a half-pair (ml only)" \
    || sfail "${label}: validate_dual_auth ACCEPTED a half-pair (ml only); the binary would crash-loop"

  # Group-readable source file: 0644 must be refused (securefile floor).
  chmod 644 "${ED_FILE}"
  rc=0
  env -u WINN3_GATEWAY_DUAL_AUTH_ED_KEY -u WINN3_GATEWAY_DUAL_AUTH_ML_SEED bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_DUAL_AUTH_ED_KEY="'"${ED_FILE}"'"
    WINN3_GATEWAY_DUAL_AUTH_ML_SEED="'"${ML_FILE}"'"
    validate_dual_auth
  ' _ "${script}" >"${WORKDIR}/dual_loose.log" 2>&1 || rc=$?
  chmod 600 "${ED_FILE}"
  [[ "${rc}" -ne 0 ]] \
    && spass "${label}: validate_dual_auth refuses a group/other-readable source (0644)" \
    || sfail "${label}: validate_dual_auth ACCEPTED a 0644 dual-auth secret; securefile would refuse it at start"

  # Noncanonical shape: 64 hex chars in the ed25519 slot is the decoded trap.
  head -c 64 /dev/zero | tr '\0' 'a' > "${WORKDIR}/dual-bad.hex"
  chmod 600 "${WORKDIR}/dual-bad.hex"
  rc=0
  env -u WINN3_GATEWAY_DUAL_AUTH_ED_KEY -u WINN3_GATEWAY_DUAL_AUTH_ML_SEED bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_DUAL_AUTH_ED_KEY="'"${WORKDIR}/dual-bad.hex"'"
    WINN3_GATEWAY_DUAL_AUTH_ML_SEED="'"${ML_FILE}"'"
    validate_dual_auth
  ' _ "${script}" >"${WORKDIR}/dual_shape.log" 2>&1 || rc=$?
  [[ "${rc}" -ne 0 ]] \
    && spass "${label}: validate_dual_auth refuses a 64-char ed25519 slot (hex-decoded trap)" \
    || sfail "${label}: validate_dual_auth ACCEPTED a 64-char ed25519 slot; the binary would refuse at start"

  # validate_config must fail closed on the half-pair too (preflight gate).
  rc=0
  env -u WINN3_GATEWAY_DUAL_AUTH_ED_KEY -u WINN3_GATEWAY_DUAL_AUTH_ML_SEED bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_ID="gwtest"
    WINN3_GATEWAY_PATH_MTU="1450"
    WINN3_GATEWAY_INNER_V4="10.10.0.2"
    WINN3_GATEWAY_DUAL_AUTH_ED_KEY="'"${ED_FILE}"'"
    WINN3_GATEWAY_DUAL_AUTH_ML_SEED=""
    validate_config
  ' _ "${script}" >"${WORKDIR}/dual_cfg_half.log" 2>&1 || rc=$?
  [[ "${rc}" -ne 0 ]] \
    && spass "${label}: validate_config refuses a half-configured dual-auth pair" \
    || sfail "${label}: validate_config ACCEPTED a half-configured dual-auth pair at preflight"

  rc=0
  env -u WINN3_GATEWAY_DUAL_AUTH_ED_KEY -u WINN3_GATEWAY_DUAL_AUTH_ML_SEED bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_ID="gwtest"
    WINN3_GATEWAY_PATH_MTU="1450"
    WINN3_GATEWAY_INNER_V4="10.10.0.2"
    WINN3_GATEWAY_DUAL_AUTH_ED_KEY="'"${ED_FILE}"'"
    WINN3_GATEWAY_DUAL_AUTH_ML_SEED="'"${ML_FILE}"'"
    validate_config
  ' _ "${script}" >"${WORKDIR}/dual_cfg_on.log" 2>&1 || rc=$?
  [[ "${rc}" -eq 0 ]] \
    && spass "${label}: validate_config accepts a complete dual-auth pair" \
    || sfail "${label}: validate_config refused a complete dual-auth pair (rc=${rc}): $(tr '\n' ' ' < "${WORKDIR}/dual_cfg_on.log")"
}

echo "=== dual-auth attestation (live script) ==="
if [[ "${IS_LINUX}" -ne 1 ]]; then
  echo "SKIP: dual-auth suite requires Linux root semantics (root-owned fixtures; stat -c ownership checks)"
  SKIP=$((SKIP + 1))
else
  run_dual_auth_suite "${INSTALL}" "dual-auth"
  if [[ "${SUITE_FAIL}" -eq 0 && "${SUITE_BUILD}" -eq 0 ]]; then
  pass "dual-auth suite: passed (inner pass=${SUITE_PASS})"
else
  fail "dual-auth suite: did not pass (inner fail=${SUITE_FAIL} build_fail=${SUITE_BUILD})"
fi

echo "=== deliberate break: strip the dual-auth flag emission (must FAIL) ==="
BREAK_DUALAUTH="${WORKDIR}/break_dualauth.sh"
cat "${LIVE_COPY}" > "${BREAK_DUALAUTH}"
python3 -c '
import pathlib, sys, re
p = pathlib.Path(sys.argv[1])
text = p.read_text()
new, n = re.subn(
    r"([ \\])-dual-auth-ed-key /run/winn3-gateway/dual-auth-ed-key",
    r"\1-dual-auth-ed-key /run/winn3-gateway/REMOVED",
    text,
    count=1,
)
if n != 1:
    sys.exit(f"expected to rewrite the dual-auth-ed-key flag once, got {n}")
p.write_text(new)
print("stripped_dual_auth_ed_flag=1")
' "${BREAK_DUALAUTH}"
run_dual_auth_suite "${BREAK_DUALAUTH}" "break-dualauth"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control break-dualauth: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control break-dualauth: suite stayed green after stripping the dual-auth flag emission — the dual-auth checks are not actually required"
fi

fi  # IS_LINUX (dual-auth suite)

# ---------------------------------------------------------------------------
# Key-file security suite (runs on EVERY host, macOS included).
#
# Local portable uid reader: GNU coreutils speak `stat -c`; the macOS audit
# host only understands `stat -f`. Same dual-dialect trick the installer's own
# stat_uid_mode uses.
file_uid() {
  local v
  if v="$(stat -c '%u' "$1" 2>/dev/null)"; then
    [[ "${v}" =~ ^[0-9]+$ ]] && printf '%s\n' "${v}" && return 0
    return 1
  fi
  if v="$(stat -f '%u' "$1" 2>/dev/null)"; then
    [[ "${v}" =~ ^[0-9]+$ ]] && printf '%s\n' "${v}" && return 0
    return 1
  fi
  return 1
}
# Portable mode reader for the replay-journal suite: GNU stat -c %a, macOS
# stat -f %Lp. Same dual-dialect shape as file_uid.
file_mode() {
  local v
  if v="$(stat -c '%a' "$1" 2>/dev/null)"; then
    [[ "${v}" =~ ^[0-7]+$ ]] && printf '%s\n' "${v}" && return 0
    return 1
  fi
  if v="$(stat -f '%Lp' "$1" 2>/dev/null)"; then
    [[ "${v}" =~ ^[0-7]+$ ]] && printf '%s\n' "${v}" && return 0
    return 1
  fi
  return 1
}
# 2026-08-22: preflight/validate now DIE on operator-supplied key files that
# are symlinks, non-regular files, group/other-readable, or owned by someone
# other than root (require_root_private_keyfile for the secret half --
# static/admission/cover key/ECH keys/dual-auth -- and
# require_root_regular_file for the public certificate half, called from
# inspect_credentials, validate_cover, preflight_cover, validate_dual_auth and
# preflight_dual_auth). This suite proves the validator ITSELF, by direct
# source-and-call, which is why it works where the install path does not.
# Mirror of the dual-auth suite shape: bash -n, structural checks that the
# gate is defined AND called from each site, runtime refusal cases on crafted
# files (0644 / symlink / wrong-owner), a valid-case control when the host is
# root (the ubuntu container), and a break-keyfile mutation that must turn the
# suite red.
# run_keyfile_security_suite SCRIPT LABEL; sets SUITE_FAIL/SUITE_PASS/
# SUITE_BUILD like run_suite.
run_keyfile_security_suite() {
  local script="$1" label="$2" rc
  SUITE_FAIL=0
  SUITE_PASS=0
  SUITE_BUILD=0

  if ! bash -n "${script}" 2>"${WORKDIR}/kf_bash_n.err"; then
    sbuild "${label}: bash -n failed: $(tr '\n' ' ' < "${WORKDIR}/kf_bash_n.err")"
    return 0
  fi
  spass "${label}: bash -n clean"

  # Structural: the gate functions exist as definitions...
  grep -F -q 'require_root_private_keyfile() {' "${script}" \
    && spass "${label}: require_root_private_keyfile() is defined" \
    || sfail "${label}: require_root_private_keyfile() definition missing"
  grep -F -q 'require_root_regular_file() {' "${script}" \
    && spass "${label}: require_root_regular_file() is defined" \
    || sfail "${label}: require_root_regular_file() definition missing"
  grep -F -q 'stat_uid_mode() {' "${script}" \
    && spass "${label}: stat_uid_mode() portable reader is defined (macOS audit host needs stat -f)" \
    || sfail "${label}: stat_uid_mode() definition missing"

  # ...and CALLED from every validation/preflight site -- a defined-but-
  # uncalled gate is a false green, the same shape as the announce call-count
  # checks above.
  local fn calls
  for fn in inspect_credentials validate_cover preflight_cover validate_dual_auth preflight_dual_auth; do
    awk -v f="${fn}" '
      $0 == f"() {" {p=1}
      p {print}
      p && $0 == "}" {exit}
    ' "${script}" > "${WORKDIR}/kf_body.txt"
    calls="$(grep -c -E 'require_root_(private_keyfile|regular_file)' "${WORKDIR}/kf_body.txt" || true)"
    if [[ "${calls}" -ge 1 ]]; then
      spass "${label}: ${fn}() calls the root-private key-file gate (${calls} call-site line(s))"
    else
      sfail "${label}: ${fn}() does not call require_root_private_keyfile/regular_file"
    fi
  done

  # Runtime fixtures. Content is irrelevant: the gate inspects type, owner and
  # mode, never bytes.
  KF_BASE="${WORKDIR}/kf-base.key"
  KF_LOOSE="${WORKDIR}/kf-loose.key"
  KF_LINK="${WORKDIR}/kf-link.key"
  KF_OWNER="${WORKDIR}/kf-owner.key"
  KF_OK="${WORKDIR}/kf-ok.key"
  printf 'k' > "${KF_BASE}"
  chmod 600 "${KF_BASE}"
  cp "${KF_BASE}" "${KF_LOOSE}"
  chmod 644 "${KF_LOOSE}"
  if [[ -e "${KF_LINK}" || -L "${KF_LINK}" ]]; then rm -f "${KF_LINK}"; fi
  ln -s "${KF_BASE}" "${KF_LINK}"
  cp "${KF_BASE}" "${KF_OWNER}"
  chmod 600 "${KF_OWNER}"

  # 1) 0644 group/other-readable must be refused, naming the mode floor.
  rc=0
  bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    require_root_private_keyfile "$2" "test key"
  ' _ "${script}" "${KF_LOOSE}" >"${WORKDIR}/kf_loose.log" 2>&1 || rc=$?
  if [[ "${rc}" -ne 0 ]] && grep -q 'group/other' "${WORKDIR}/kf_loose.log"; then
    spass "${label}: a 0644 key file is refused with a group/other refusal (rc=${rc})"
  else
    sfail "${label}: a 0644 key file was NOT refused with a group/other refusal (rc=${rc})"
  fi

  # 2) A symlink must be refused, naming the link.
  rc=0
  bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    require_root_private_keyfile "$2" "test key"
  ' _ "${script}" "${KF_LINK}" >"${WORKDIR}/kf_link.log" 2>&1 || rc=$?
  if [[ "${rc}" -ne 0 ]] && grep -q 'symlink' "${WORKDIR}/kf_link.log"; then
    spass "${label}: a symlink key file is refused with a symlink refusal (rc=${rc})"
  else
    sfail "${label}: a symlink key file was NOT refused with a symlink refusal (rc=${rc})"
  fi

  # 3) A 0600 file owned by uid != 0 must be refused, naming the ownership.
  # On a non-root audit host the local user's own file IS the wrong-owner
  # case; as root this chowns to uid 1 first. Some shared mounts (virtiofs,
  # sshfs) silently squash chown -- detect that and report the case as
  # host-gated instead of failing the suite for a fixture it could not stage.
  if [[ "$(id -u)" == "0" ]]; then
    chown 1 "${KF_OWNER}" 2>/dev/null || true
  fi
  if [[ "$(file_uid "${KF_OWNER}" 2>/dev/null || echo '?')" == "0" ]]; then
    spass "${label}: wrong-owner case is host-gated (this filesystem squashes chown; the file stayed root-owned); the container run stages it"
  else
    rc=0
    bash -c '
      set -euo pipefail
      # shellcheck disable=SC1090
      source "$1"
      require_root_private_keyfile "$2" "test key"
    ' _ "${script}" "${KF_OWNER}" >"${WORKDIR}/kf_owner.log" 2>&1 || rc=$?
    if [[ "${rc}" -ne 0 ]] && grep -q 'not root' "${WORKDIR}/kf_owner.log"; then
      spass "${label}: a non-root-owned 0600 key file is refused with an ownership refusal (rc=${rc})"
    else
      sfail "${label}: a non-root-owned 0600 key file was NOT refused with an ownership refusal (rc=${rc})"
    fi
  fi

  # 4) The valid case: a root-owned 0600 regular file passes. Provable as
  # root only (a non-root host cannot own a file as root; ownership IS the
  # gate), which is exactly what the ubuntu container run provides; on a
  # non-root host this case is reported as host-gated rather than counted
  # against the suite.
  if [[ "$(id -u)" == "0" ]]; then
    cp "${KF_BASE}" "${KF_OK}"
    chmod 600 "${KF_OK}"
    chown 0 "${KF_OK}" 2>/dev/null || true
    rc=0
    bash -c '
      set -euo pipefail
      # shellcheck disable=SC1090
      source "$1"
      require_root_private_keyfile "$2" "test key"
    ' _ "${script}" "${KF_OK}" >"${WORKDIR}/kf_ok.log" 2>&1 || rc=$?
    if [[ "${rc}" -eq 0 ]]; then
      spass "${label}: a root-owned 0600 regular key file is accepted (rc=0)"
    else
      sfail "${label}: a root-owned 0600 regular key file was REFUSED (rc=${rc}): $(tr '\n' ' ' < "${WORKDIR}/kf_ok.log")"
    fi
  else
    spass "${label}: valid root-owned 0600 case is host-gated (this host is not root); the container run proves it"
  fi
}

echo "=== key-file security (live script; runs on every host) ==="
run_keyfile_security_suite "${INSTALL}" "keyfile"
if [[ "${SUITE_FAIL}" -eq 0 && "${SUITE_BUILD}" -eq 0 ]]; then
  pass "keyfile security suite: passed (inner pass=${SUITE_PASS})"
else
  fail "keyfile security suite: did not pass (inner fail=${SUITE_FAIL} build_fail=${SUITE_BUILD})"
fi

echo "=== deliberate break: disable the key-file gate definition (must FAIL) ==="
BREAK_KEYFILE="${WORKDIR}/break_keyfile.sh"
cat "${INSTALL}" > "${BREAK_KEYFILE}"
python3 -c '
import pathlib, sys
p = pathlib.Path(sys.argv[1])
text = p.read_text()
new = text.replace("require_root_private_keyfile() {", "require_root_private_keyfile_disabled() {", 1)
if new == text:
    sys.exit("expected to rename the gate definition once")
p.write_text(new)
print("renamed_gate_definition=1")
' "${BREAK_KEYFILE}"
run_keyfile_security_suite "${BREAK_KEYFILE}" "break-keyfile"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control break-keyfile: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control break-keyfile: suite stayed green after renaming the gate definition — the structural checks are not actually required"
fi

# ---------------------------------------------------------------------------
# F-02 replay-journal suite (live script; emission/resolve checks on every
# host, provisioning checks on Linux+root only).
#
# The installer requires a durable replay journal
# (WINN3_GATEWAY_REPLAY_JOURNAL=0 is refused; /var/lib/winn3-gateway is
# provisioned 0700 root with a 0640 root replay.journal, WINN3_REPLAY_JOURNAL
# is always emitted, StateDirectory=winn3-gateway is always in the unit).
# This suite proves:
#   1. flag=1 and unset: the env emission carries WINN3_REPLAY_JOURNAL and
#      the unit carries StateDirectory=winn3-gateway + StateDirectoryMode=0700,
#   2. explicit flag=0: emit_env_text, emit_unit_text, resolve, and
#      provision refuse before writing anything journal-off,
#   3. resolve_replay_journal_env: ON for a new install (no env file),
#      ON for an upgrade whose env file lacks the line, preserves the canonical
#      value, refuses an unsafe custom path, and refuses explicit 0,
#   4. provision_replay_journal: dir 0700 root-owned, journal 0640
#      root-owned (Linux+root hosts only; install -o root -g root).
# run_replay_journal_suite SCRIPT LABEL; sets SUITE_FAIL/SUITE_PASS/
# SUITE_BUILD like the other suites so the mutation control can reuse them.
run_replay_journal_suite() {
  local script="$1" label="$2" rc
  SUITE_FAIL=0
  SUITE_PASS=0
  SUITE_BUILD=0

  if ! bash -n "${script}" 2>"${WORKDIR}/rj_bash_n.err"; then
    sbuild "${label}: bash -n failed: $(tr '\n' ' ' < "${WORKDIR}/rj_bash_n.err")"
    return 0
  fi
  spass "${label}: bash -n clean"

  # Structural: the flag, the path constants, the gates and the call sites
  # must exist in the text (a defined-but-uncalled gate is a false green).
  grep -F -q 'WINN3_GATEWAY_REPLAY_JOURNAL="${WINN3_GATEWAY_REPLAY_JOURNAL:-}"' "${script}" \
    && spass "${label}: replay-journal flag declared" \
    || sfail "${label}: replay-journal flag declaration missing"
  grep -F -q 'WINN3_GATEWAY_REPLAY_JOURNAL_DIR="${WINN3_GATEWAY_REPLAY_JOURNAL_DIR:-/var/lib/winn3-gateway}"' "${script}" \
    && spass "${label}: journal directory constant is /var/lib/winn3-gateway" \
    || sfail "${label}: journal directory constant missing or not /var/lib/winn3-gateway"
  grep -F -q 'resolve_replay_journal_env() {' "${script}" \
    && spass "${label}: resolve_replay_journal_env is defined" \
    || sfail "${label}: resolve_replay_journal_env definition missing"
  grep -F -q 'provision_replay_journal() {' "${script}" \
    && spass "${label}: provision_replay_journal is defined" \
    || sfail "${label}: provision_replay_journal definition missing"
  grep -F -q 'install -d -m 700 -o root -g root "${WINN3_GATEWAY_REPLAY_JOURNAL_DIR}"' "${script}" \
    && spass "${label}: journal directory provisioning is pinned to root-owned 0700" \
    || sfail "${label}: journal directory provisioning lost root-owned 0700"
  grep -F -q 'normalize_replay_journal_node \' "${script}" \
    && grep -F -q 'os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW' "${script}" \
    && grep -F -q 'os.fchmod(fd, mode)' "${script}" \
    && grep -F -q 'os.fchown(fd, owner.pw_uid, -1)' "${script}" \
    && grep -F -q '    "640" \' "${script}" \
    && spass "${label}: journal file provisioning is descriptor-bound, no-follow, exclusive-create, root-owned 0640" \
    || sfail "${label}: journal file provisioning lost descriptor-bound root-owned 0640 hardening"
  grep -F -q 'StateDirectory=winn3-gateway' "${script}" \
    && spass "${label}: StateDirectory=winn3-gateway emission text present" \
    || sfail "${label}: StateDirectory=winn3-gateway emission text missing"
  grep -F -q 'WINN3_GATEWAY_REPLAY_JOURNAL=0 is refused: durable replay is a non-bypassable production invariant' "${script}" \
    && spass "${label}: explicit disable is refused as a production invariant" \
    || sfail "${label}: explicit-disable refusal phrase missing"
  awk '
    $0 == "write_env_file() {" {p=1}
    p {print}
    p && $0 == "}" {exit}
  ' "${script}" > "${WORKDIR}/rj_wef.txt"
  local calls
  calls="$(grep -c -E 'resolve_replay_journal_env|preserve_replay_journal_env_value|provision_replay_journal' "${WORKDIR}/rj_wef.txt" || true)"
  if [[ "${calls}" -ge 3 ]]; then
    spass "${label}: write_env_file calls resolve/preserve/provision (${calls} call-site line(s))"
  else
    sfail "${label}: write_env_file does not call all three journal steps (${calls} lines; a defined-but-uncalled gate is a false green)"
  fi

  # 1) flag=1: env emission carries the journal path; unit carries the
  #    StateDirectory grant.
  rc=0
  env WINN3_GATEWAY_REPLAY_JOURNAL=1 bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_PATH_MTU=1450
    WINN3_GATEWAY_PLAN=udp
    WINN3_GATEWAY_REPLAY_JOURNAL=1
    emit_env_text
  ' _ "${script}" >"${WORKDIR}/rj_on.env" 2>"${WORKDIR}/rj_on.env.err" || rc=$?
  if [[ "${rc}" -ne 0 ]]; then
    sfail "${label}: emit_env_text with replay-journal=1 exited ${rc}"
    return 0
  fi
  grep -F -q -- 'WINN3_REPLAY_JOURNAL=/var/lib/winn3-gateway/replay.journal' "${WORKDIR}/rj_on.env" \
    && spass "${label}: flag=1 env emission carries WINN3_REPLAY_JOURNAL=/var/lib/winn3-gateway/replay.journal" \
    || sfail "${label}: flag=1 env emission is missing the WINN3_REPLAY_JOURNAL line"

  rc=0
  env WINN3_GATEWAY_REPLAY_JOURNAL=1 bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_PATH_MTU=1450
    WINN3_GATEWAY_PLAN=udp
    WINN3_GATEWAY_REPLAY_JOURNAL=1
    emit_unit_text
  ' _ "${script}" >"${WORKDIR}/rj_on.unit" 2>"${WORKDIR}/rj_on.unit.err" || rc=$?
  if [[ "${rc}" -ne 0 ]]; then
    sfail "${label}: emit_unit_text with replay-journal=1 exited ${rc}"
    return 0
  fi
  grep -F -q -- 'StateDirectory=winn3-gateway' "${WORKDIR}/rj_on.unit" \
    && spass "${label}: flag=1 unit carries StateDirectory=winn3-gateway" \
    || sfail "${label}: flag=1 unit did not carry StateDirectory=winn3-gateway"
  grep -F -q -- 'StateDirectoryMode=0700' "${WORKDIR}/rj_on.unit" \
    && spass "${label}: flag=1 unit carries StateDirectoryMode=0700" \
    || sfail "${label}: flag=1 unit did not carry StateDirectoryMode=0700"
  grep -F -q -- 'UMask=0077' "${WORKDIR}/rj_on.unit" \
    && spass "${label}: flag=1 unit keeps UMask=0077" \
    || sfail "${label}: flag=1 unit lost UMask=0077"
  grep -F -q -- 'SocketBindDeny=any' "${WORKDIR}/rj_on.unit" \
    && spass "${label}: flag=1 unit keeps SocketBindDeny=any (the journal grant does not touch the bind sandbox)" \
    || sfail "${label}: flag=1 unit lost SocketBindDeny=any"

  # Unset flag still emits the journal (durable replay is not optional).
  rc=0
  env -u WINN3_GATEWAY_REPLAY_JOURNAL bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_PATH_MTU=1450
    WINN3_GATEWAY_PLAN=udp
    WINN3_GATEWAY_REPLAY_JOURNAL=""
    emit_env_text
  ' _ "${script}" >"${WORKDIR}/rj_unset.env" 2>"${WORKDIR}/rj_unset.env.err" || rc=$?
  if [[ "${rc}" -ne 0 ]]; then
    sfail "${label}: emit_env_text with unset replay-journal flag exited ${rc}"
  elif grep -F -q -- 'WINN3_REPLAY_JOURNAL=/var/lib/winn3-gateway/replay.journal' "${WORKDIR}/rj_unset.env"; then
    spass "${label}: unset flag env emission still carries WINN3_REPLAY_JOURNAL"
  else
    sfail "${label}: unset flag env emission is missing WINN3_REPLAY_JOURNAL"
  fi

  rc=0
  env -u WINN3_GATEWAY_REPLAY_JOURNAL bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_PATH_MTU=1450
    WINN3_GATEWAY_PLAN=udp
    WINN3_GATEWAY_REPLAY_JOURNAL=""
    emit_unit_text
  ' _ "${script}" >"${WORKDIR}/rj_unset.unit" 2>"${WORKDIR}/rj_unset.unit.err" || rc=$?
  if [[ "${rc}" -ne 0 ]]; then
    sfail "${label}: emit_unit_text with unset replay-journal flag exited ${rc}"
  elif grep -F -q -- 'StateDirectory=winn3-gateway' "${WORKDIR}/rj_unset.unit"; then
    spass "${label}: unset flag unit still carries StateDirectory=winn3-gateway"
  else
    sfail "${label}: unset flag unit lost StateDirectory=winn3-gateway"
  fi

  # 2) explicit flag=0: emitters and resolve refuse before writing a
  #    journal-off unit. This is the independently reproduced bypass.
  rc=0
  env WINN3_GATEWAY_REPLAY_JOURNAL=0 bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_PATH_MTU=1450
    WINN3_GATEWAY_PLAN=udp
    WINN3_GATEWAY_REPLAY_JOURNAL=0
    emit_env_text
  ' _ "${script}" >"${WORKDIR}/rj_off.env" 2>"${WORKDIR}/rj_off.env.err" || rc=$?
  if [[ "${rc}" -eq 0 ]]; then
    sfail "${label}: emit_env_text with replay-journal=0 succeeded; explicit disable must fail"
  elif grep -F -q 'WINN3_GATEWAY_REPLAY_JOURNAL=0 is refused: durable replay is a non-bypassable production invariant' "${WORKDIR}/rj_off.env.err"; then
    spass "${label}: explicit flag=0 env emission is refused"
  else
    sfail "${label}: flag=0 env refusal did not name the production invariant (rc=${rc})"
  fi
  if grep -q '^WINN3_REPLAY_JOURNAL=' "${WORKDIR}/rj_off.env" 2>/dev/null; then
    sfail "${label}: flag=0 env emission still carried WINN3_REPLAY_JOURNAL after refusal"
  fi

  rc=0
  env WINN3_GATEWAY_REPLAY_JOURNAL=0 bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_PATH_MTU=1450
    WINN3_GATEWAY_PLAN=udp
    WINN3_GATEWAY_REPLAY_JOURNAL=0
    emit_unit_text
  ' _ "${script}" >"${WORKDIR}/rj_off.unit" 2>"${WORKDIR}/rj_off.unit.err" || rc=$?
  if [[ "${rc}" -eq 0 ]]; then
    sfail "${label}: emit_unit_text with replay-journal=0 succeeded; explicit disable must fail"
  elif grep -F -q 'WINN3_GATEWAY_REPLAY_JOURNAL=0 is refused: durable replay is a non-bypassable production invariant' "${WORKDIR}/rj_off.unit.err"; then
    spass "${label}: explicit flag=0 unit emission is refused"
  else
    sfail "${label}: flag=0 unit refusal did not name the production invariant (rc=${rc})"
  fi
  if grep -q 'StateDirectory' "${WORKDIR}/rj_off.unit" 2>/dev/null; then
    sfail "${label}: flag=0 unit emission still carried a StateDirectory after refusal"
  fi

  # 3) resolve_replay_journal_env against scratch env files (portable: no
  #    root, no install command, WINN3_GATEWAY_ENV_FILE is overridden).
  RJ_NONE="${WORKDIR}/rj-resolve-none.env"
  RJ_PLAIN="${WORKDIR}/rj-resolve-plain.env"
  RJ_EXISTING="${WORKDIR}/rj-resolve-existing.env"
  RJ_UNSAFE="${WORKDIR}/rj-resolve-unsafe.env"
  rm -f "${RJ_NONE}" "${RJ_PLAIN}" "${RJ_EXISTING}" "${RJ_UNSAFE}"
  printf 'WINN3_GATEWAY_LISTEN=0.0.0.0:9111\n' > "${RJ_PLAIN}"
  printf 'WINN3_REPLAY_JOURNAL=/var/lib/winn3-gateway/replay.journal\n' > "${RJ_EXISTING}"
  printf 'WINN3_REPLAY_JOURNAL=/custom/journal.jrn\n' > "${RJ_UNSAFE}"

  local resolved=""
  resolved="$(env -u WINN3_GATEWAY_REPLAY_JOURNAL bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_ENV_FILE="$2"
    WINN3_GATEWAY_REPLAY_JOURNAL=""
    resolve_replay_journal_env
    printf "%s" "${WINN3_GATEWAY_REPLAY_JOURNAL}"
  ' _ "${script}" "${RJ_NONE}")"
  [[ "${resolved}" == "1" ]] \
    && spass "${label}: unset flag + no env file resolves to 1 (new installs default ON)" \
    || sfail "${label}: unset flag + no env file resolved to '${resolved}', want 1 (new installs default ON)"

  resolved="$(env -u WINN3_GATEWAY_REPLAY_JOURNAL bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_ENV_FILE="$2"
    WINN3_GATEWAY_REPLAY_JOURNAL=""
    resolve_replay_journal_env
    printf "%s" "${WINN3_GATEWAY_REPLAY_JOURNAL}"
  ' _ "${script}" "${RJ_PLAIN}")"
  [[ "${resolved}" == "1" ]] \
    && spass "${label}: unset flag + existing env without the line resolves to 1 (upgrades default ON)" \
    || sfail "${label}: unset flag + existing env without the line resolved to '${resolved}', want 1 (upgrades must enable durable replay by default)"

  local existing_out=""
  existing_out="$(env -u WINN3_GATEWAY_REPLAY_JOURNAL bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_ENV_FILE="$2"
    WINN3_GATEWAY_REPLAY_JOURNAL=""
    resolve_replay_journal_env
    preserve_replay_journal_env_value
    printf "%s|%s" "${WINN3_GATEWAY_REPLAY_JOURNAL}" "${WINN3_GATEWAY_REPLAY_JOURNAL_VALUE}"
  ' _ "${script}" "${RJ_EXISTING}")"
  if [[ "${existing_out}" == "1|/var/lib/winn3-gateway/replay.journal" ]]; then
    spass "${label}: existing env that carries the canonical journal path resolves on and preserves it"
  else
    sfail "${label}: existing canonical WINN3_REPLAY_JOURNAL resolved to '${existing_out}', want '1|/var/lib/winn3-gateway/replay.journal'"
  fi

  local unsafe_rc=0
  env -u WINN3_GATEWAY_REPLAY_JOURNAL bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_ENV_FILE="$2"
    WINN3_GATEWAY_REPLAY_JOURNAL=""
    resolve_replay_journal_env
    preserve_replay_journal_env_value
  ' _ "${script}" "${RJ_UNSAFE}" >"${WORKDIR}/rj_unsafe.out" 2>"${WORKDIR}/rj_unsafe.err" || unsafe_rc=$?
  if [[ "${unsafe_rc}" -ne 0 ]] && grep -F -q 'outside the supported production path' "${WORKDIR}/rj_unsafe.err"; then
    spass "${label}: existing journal path outside StateDirectory is refused fail-closed"
  else
    sfail "${label}: unsafe existing journal path was not refused clearly (rc=${unsafe_rc})"
  fi

  disable_rc=0
  env WINN3_GATEWAY_REPLAY_JOURNAL=0 bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_ENV_FILE="$2"
    resolve_replay_journal_env
    printf "%s" "${WINN3_GATEWAY_REPLAY_JOURNAL}"
  ' _ "${script}" "${RJ_EXISTING}" >"${WORKDIR}/rj_disable.out" 2>"${WORKDIR}/rj_disable.err" || disable_rc=$?
  if [[ "${disable_rc}" -eq 0 ]]; then
    sfail "${label}: explicit 0 resolved instead of refusing over an existing journal line"
  elif grep -F -q 'WINN3_GATEWAY_REPLAY_JOURNAL=0 is refused: durable replay is a non-bypassable production invariant' "${WORKDIR}/rj_disable.err"; then
    spass "${label}: explicit 0 is refused even over an existing journal line"
  else
    sfail "${label}: explicit 0 refusal did not name the production invariant (rc=${disable_rc})"
  fi

  provision_off_rc=0
  env WINN3_GATEWAY_REPLAY_JOURNAL=0 bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_REPLAY_JOURNAL=0
    provision_replay_journal
  ' _ "${script}" >"${WORKDIR}/rj_provision_off.out" 2>"${WORKDIR}/rj_provision_off.err" || provision_off_rc=$?
  if [[ "${provision_off_rc}" -eq 0 ]]; then
    sfail "${label}: provision_replay_journal with flag=0 succeeded; explicit disable must fail"
  elif grep -F -q 'WINN3_GATEWAY_REPLAY_JOURNAL=0 is refused: durable replay is a non-bypassable production invariant' "${WORKDIR}/rj_provision_off.err"; then
    spass "${label}: provision_replay_journal refuses explicit disable"
  else
    sfail "${label}: provision flag=0 refusal did not name the production invariant (rc=${provision_off_rc})"
  fi

  # 4) provision_replay_journal: dir 0700 root-owned, journal 0640
  #    root-owned. Linux+root only (install -o root -g root; on macOS the
  #    group root does not exist), same gate as the dual-auth/keyfile
  #    valid-case. The journal path constants are overridden into scratch.
  if [[ "${IS_LINUX}" -ne 1 || "$(id -u)" != "0" ]]; then
    spass "${label}: provisioning checks are host-gated (need Linux root: install -o root -g root); the container run proves them"
  else
    RJ_DIR="${WORKDIR}/rj-provision-state"
    rm -rf "${RJ_DIR}"
    rc=0
    env WINN3_GATEWAY_REPLAY_JOURNAL=1 WINN3_GATEWAY_REPLAY_JOURNAL_DIR="${RJ_DIR}" WINN3_GATEWAY_REPLAY_JOURNAL_PATH="${RJ_DIR}/replay.journal" bash -c '
      set -euo pipefail
      # shellcheck disable=SC1090
      source "$1"
      WINN3_GATEWAY_REPLAY_JOURNAL=1
      provision_replay_journal
    ' _ "${script}" >"${WORKDIR}/rj_provision.log" 2>&1 || rc=$?
    if [[ "${rc}" -ne 0 ]]; then
      sfail "${label}: provision_replay_journal exited ${rc}: $(tr '\n' ' ' < "${WORKDIR}/rj_provision.log")"
      return 0
    fi
    local duid dmode fuid fmode
    duid="$(file_uid "${RJ_DIR}")" || duid="?"
    dmode="$(file_mode "${RJ_DIR}")" || dmode="?"
    [[ "${duid}" == "0" && "${dmode}" == "700" ]] \
      && spass "${label}: journal directory is 0700 root-owned (uid ${duid} mode ${dmode})" \
      || sfail "${label}: journal directory is uid ${duid} mode ${dmode}, want 0/700"
    fuid="$(file_uid "${RJ_DIR}/replay.journal")" || fuid="?"
    fmode="$(file_mode "${RJ_DIR}/replay.journal")" || fmode="?"
    [[ "${fuid}" == "0" && "${fmode}" == "640" ]] \
      && spass "${label}: journal file is 0640 root-owned (uid ${fuid} mode ${fmode})" \
      || sfail "${label}: journal file is uid ${fuid} mode ${fmode}, want 0/640"
    [[ -f "${RJ_DIR}/replay.journal" && ! -s "${RJ_DIR}/replay.journal" ]] \
      && spass "${label}: the provisioned journal is an empty file (a valid empty journal; the gateway appends from here)" \
      || sfail "${label}: the provisioned journal is not an empty file (a torn journal would refuse the gateway at load)"
    # Idempotency: re-provisioning must not clobber a journal with records.
    printf 'x' > "${RJ_DIR}/replay.journal"
    env WINN3_GATEWAY_REPLAY_JOURNAL=1 WINN3_GATEWAY_REPLAY_JOURNAL_DIR="${RJ_DIR}" WINN3_GATEWAY_REPLAY_JOURNAL_PATH="${RJ_DIR}/replay.journal" bash -c '
      set -euo pipefail
      # shellcheck disable=SC1090
      source "$1"
      WINN3_GATEWAY_REPLAY_JOURNAL=1
      provision_replay_journal
    ' _ "${script}" >"${WORKDIR}/rj_provision2.log" 2>&1 || rc=$?
    if [[ -s "${RJ_DIR}/replay.journal" ]]; then
      spass "${label}: re-provisioning leaves an existing journal untouched (records survive)"
    else
      sfail "${label}: re-provisioning clobbered an existing journal"
    fi
  fi
}

echo "=== F-02 replay-journal (live script; portable checks on every host) ==="
run_replay_journal_suite "${INSTALL}" "replay-journal"
if [[ "${SUITE_FAIL}" -eq 0 && "${SUITE_BUILD}" -eq 0 ]]; then
  pass "replay-journal suite: passed (inner pass=${SUITE_PASS})"
else
  fail "replay-journal suite: did not pass (inner fail=${SUITE_FAIL} build_fail=${SUITE_BUILD})"
fi

echo "=== deliberate break: strip the StateDirectory emission (must FAIL) ==="
BREAK_REPLAYJOURNAL="${WORKDIR}/break_replayjournal.sh"
# LIVE_COPY only exists when the Linux-only run_suite block executed; on a
# non-Linux host the mutation copy is taken from the live installer instead.
cat "${LIVE_COPY:-${INSTALL}}" > "${BREAK_REPLAYJOURNAL}"
python3 -c '
import pathlib, sys, re
p = pathlib.Path(sys.argv[1])
text = p.read_text()
new, n = re.subn(
    r"^StateDirectory=winn3-gateway$",
    "StateDirectory=winn3-REMOVED",
    text,
    count=1,
    flags=re.M,
)
if n != 1:
    sys.exit(f"expected to rewrite the StateDirectory emission once, got {n}")
p.write_text(new)
print("stripped_state_directory_emission=1")
' "${BREAK_REPLAYJOURNAL}"
run_replay_journal_suite "${BREAK_REPLAYJOURNAL}" "break-replayjournal"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control break-replayjournal: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control break-replayjournal: suite stayed green after stripping the StateDirectory emission — the journal checks are not actually required"
fi

# ---------------------------------------------------------------------------
# F-GW WINN3GW-INPUT inner-firewall suite (live script; portable text checks
# on every host).
#
# Fleet true positive (2026-08-23): WINN3GW-INPUT admitted TCP/53 alone, so
# the promotion probe's in-tunnel ICMP echo to -inner-v4 and the reflector
# canaries' echo traffic died on the host INPUT DROP, and UDP/53 died beside
# it. This suite proves BOTH chain builders -- the boot-time oneshot heredoc
# and apply_winn3gw_input_firewall -- carry, in order, before the trailing
# DROP:
#   1. RELATED,ESTABLISHED accept (base-chain posture preserved),
#   2. icmp echo-request / echo-reply / time-exceeded accepts (ALWAYS at
#      FORWARD=1, resolver or not),
#   3. udp/53 + tcp/53 accepts ONLY inside the RESOLVER=1 guard,
#   4. an INPUT jump widened to -i IFACE -d INNER (no protocol filter),
#   5. every dport 53 line still carries -i and -d (no open resolver).
# run_winn3gw_input_suite SCRIPT LABEL; sets SUITE_FAIL/SUITE_PASS/SUITE_BUILD.
run_winn3gw_input_suite() {
  local script="$1" label="$2"
  SUITE_FAIL=0
  SUITE_PASS=0
  SUITE_BUILD=0

  if ! bash -n "${script}" 2>"${WORKDIR}/gw_bash_n.err"; then
    sbuild "${label}: bash -n failed: $(tr '\n' ' ' < "${WORKDIR}/gw_bash_n.err")"
    return 0
  fi
  spass "${label}: bash -n clean"

  # Structural: the widened apply and teardown must exist as definitions.
  grep -F -q 'apply_winn3gw_input_firewall() {' "${script}" \
    && spass "${label}: apply_winn3gw_input_firewall is defined" \
    || sfail "${label}: apply_winn3gw_input_firewall definition missing"
  grep -F -q 'teardown_winn3gw_input_firewall() {' "${script}" \
    && spass "${label}: teardown_winn3gw_input_firewall is defined" \
    || sfail "${label}: teardown_winn3gw_input_firewall definition missing"

  # Extract the boot-time oneshot heredoc (same awk shape the firewall boot
  # test uses) and the apply function body.
  awk -v needle="cat <<'EOF' # the boot helper: /usr/local/sbin/winn3-gateway-firewall" '
    index($0, needle) {capture=1; next}
    capture && $0 == "EOF" {exit}
    capture {print}
  ' "${script}" > "${WORKDIR}/gw_boot_script.txt"
  [[ -s "${WORKDIR}/gw_boot_script.txt" ]] \
    && spass "${label}: boot-time firewall heredoc extracted" \
    || sfail "${label}: boot-time firewall heredoc missing or empty"

  awk '
    $0 == "apply_winn3gw_input_firewall() {" {p=1}
    p {print}
    p && $0 == "}" {exit}
  ' "${script}" > "${WORKDIR}/gw_apply_body.txt"
  [[ -s "${WORKDIR}/gw_apply_body.txt" ]] \
    && spass "${label}: apply_winn3gw_input_firewall body extracted" \
    || sfail "${label}: apply_winn3gw_input_firewall body missing"

  check_winn3gw_chain_block "${WORKDIR}/gw_boot_script.txt" "${label} boot-oneshot"
  check_winn3gw_chain_block "${WORKDIR}/gw_apply_body.txt" "${label} apply-function"

  # The apply must be called exactly once from apply_forwarding_firewall, on
  # the FORWARD=1 path, NOT resolver-gated (the icmp trio is always-on).
  local calls
  calls="$(grep -E -c '^[[:space:]]+apply_winn3gw_input_firewall( \|\||$)' "${script}" || true)"
  if [[ "${calls}" -eq 1 ]]; then
    spass "${label}: apply_winn3gw_input_firewall is called exactly once"
  else
    sfail "${label}: apply_winn3gw_input_firewall call count is ${calls}, want 1"
  fi
  if grep -E -q '^[[:space:]]+apply_winn3gw_input_firewall \|\| return 1$' "${script}"; then
    spass "${label}: apply_forwarding_firewall calls apply_winn3gw_input_firewall with fail-closed return"
  else
    sfail "${label}: apply_forwarding_firewall does not call apply_winn3gw_input_firewall with || return 1"
  fi

  # Teardown must remove the widened jump shape (and the legacy narrow one).
  grep -F -q -- '-D INPUT -i "${WINN3_GATEWAY_FORWARD_IF}" -d "${WINN3_GATEWAY_INNER_V4}" -j WINN3GW-INPUT' "${script}" \
    && spass "${label}: teardown removes the widened INPUT jump" \
    || sfail "${label}: teardown does not remove the widened INPUT jump"
}

# check_winn3gw_chain_block FILE LABEL -- one builder's WINN3GW-INPUT block.
check_winn3gw_chain_block() {
  local file="$1" label="$2"
  local req_n rep_n tte_n udp_n tcp_n drop_n guard_n est_n jump_n

  grep -F -q -- '-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' "${file}" \
    && spass "${label}: RELATED,ESTABLISHED accept present" \
    || sfail "${label}: RELATED,ESTABLISHED accept missing"
  grep -F -q -- '-p icmp --icmp-type echo-request -j ACCEPT' "${file}" \
    && spass "${label}: icmp echo-request accept present" \
    || sfail "${label}: icmp echo-request accept missing"
  grep -F -q -- '-p icmp --icmp-type echo-reply -j ACCEPT' "${file}" \
    && spass "${label}: icmp echo-reply accept present" \
    || sfail "${label}: icmp echo-reply accept missing"
  grep -F -q -- '-p icmp --icmp-type time-exceeded -j ACCEPT' "${file}" \
    && spass "${label}: icmp time-exceeded accept present" \
    || sfail "${label}: icmp time-exceeded accept missing"
  grep -F -q -- '-p udp --dport 53 -j ACCEPT' "${file}" \
    && spass "${label}: udp/53 accept present" \
    || sfail "${label}: udp/53 accept missing"
  grep -F -q -- '-p tcp --dport 53 -j ACCEPT' "${file}" \
    && spass "${label}: tcp/53 accept present" \
    || sfail "${label}: tcp/53 accept missing"

  # Ordering: icmp trio BEFORE the RESOLVER=1 guard (always-on); udp/53 and
  # tcp/53 INSIDE the guard; every accept BEFORE the trailing DROP.
  # `|| true` is load-bearing under set -e: on a mutated copy a grep can miss
  # and the pipeline fails, which must red the check, not kill the suite.
  req_n="$( { grep -n -F -- '-p icmp --icmp-type echo-request -j ACCEPT' "${file}" || true; } | cut -d: -f1 | head -1)"
  guard_n="$( { grep -n -E -- 'if \[\[ "\$\{WINN3_GATEWAY_RESOLVER(:-0)?\}" == "1" \]\]; then' "${file}" || true; } | cut -d: -f1 | head -1)"
  udp_n="$( { grep -n -F -- '-p udp --dport 53 -j ACCEPT' "${file}" || true; } | cut -d: -f1 | head -1)"
  tcp_n="$( { grep -n -F -- '-p tcp --dport 53 -j ACCEPT' "${file}" || true; } | cut -d: -f1 | head -1)"
  drop_n="$( { grep -n -F -- '-j DROP' "${file}" || true; } | cut -d: -f1 | tail -1)"
  if [[ -n "${req_n}" && -n "${guard_n}" && -n "${udp_n}" && -n "${tcp_n}" && -n "${drop_n}" \
     && "${req_n}" -lt "${guard_n}" \
     && "${udp_n}" -gt "${guard_n}" && "${tcp_n}" -gt "${guard_n}" \
     && "${udp_n}" -lt "${drop_n}" && "${tcp_n}" -lt "${drop_n}" \
     && "${req_n}" -lt "${drop_n}" ]]; then
    spass "${label}: ordering: icmp trio before the RESOLVER=1 guard; udp/53+tcp/53 inside the guard; all accepts before the trailing DROP"
  else
    sfail "${label}: ordering wrong (icmp=${req_n:-?} guard=${guard_n:-?} udp53=${udp_n:-?} tcp53=${tcp_n:-?} drop=${drop_n:-?}); want icmp < guard < 53s < DROP"
  fi

  # The widened jump (no protocol filter) and legacy-narrow-jump removal.
  # Design v17 2.2 item 2: both builders place it right behind the
  # SSH-recovery jump through place_winn3gw_input_jump, never at INPUT 1
  # (the interactions suite runs the placement itself).
  if grep -F -q -- 'place_winn3gw_input_jump "${iface}" "${inner}"' "${file}"; then
    spass "${label}: INPUT jump is widened to -i IFACE -d INNER (no protocol filter)"
  else
    sfail "${label}: widened INPUT jump missing"
  fi
  grep -F -q -- '-D INPUT -i "${iface}" -d "${inner}" -p tcp --dport 53 -j WINN3GW-INPUT' "${file}" \
    && spass "${label}: legacy narrow TCP/53-only jump is removed on re-apply" \
    || sfail "${label}: legacy narrow jump removal missing"

  # Every dport 53 line must carry -i and -d (never an open resolver).
  local line stripped bad=0
  while IFS= read -r line; do
    stripped="${line#"${line%%[![:space:]]*}"}"
    [[ "${stripped}" == \#* ]] && continue
    if [[ "${line}" == *'dport 53'* && ! ( "${line}" == *-i* && "${line}" == *-d* ) ]]; then
      sfail "${label}: dport 53 line missing -i or -d: ${line}"
      bad=1
    fi
  done < "${file}"
  [[ "${bad}" -eq 0 ]] && spass "${label}: every non-comment dport 53 line carries both -i and -d"
}

echo "=== F-GW WINN3GW-INPUT inner firewall (live script; portable checks on every host) ==="
run_winn3gw_input_suite "${INSTALL}" "winn3gw-input"
if [[ "${SUITE_FAIL}" -eq 0 && "${SUITE_BUILD}" -eq 0 ]]; then
  pass "winn3gw-input suite: passed (inner pass=${SUITE_PASS})"
else
  fail "winn3gw-input suite: did not pass (inner fail=${SUITE_FAIL} build_fail=${SUITE_BUILD})"
fi

echo "=== deliberate break: strip the icmp echo-request accept (must FAIL) ==="
BREAK_WINN3GW="${WORKDIR}/break_winn3gw.sh"
cat "${LIVE_COPY:-${INSTALL}}" > "${BREAK_WINN3GW}"
python3 -c '
import pathlib, sys
p = pathlib.Path(sys.argv[1])
text = p.read_text()
new = text.replace("-p icmp --icmp-type echo-request -j ACCEPT", "-p icmp --icmp-type echo-request -j REMOVED")
if new == text:
    sys.exit("expected to rewrite the icmp echo-request accept at least once")
p.write_text(new)
print("stripped_icmp_echo_request_accept=1")
' "${BREAK_WINN3GW}"
run_winn3gw_input_suite "${BREAK_WINN3GW}" "break-winn3gw"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control break-winn3gw: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control break-winn3gw: suite stayed green after stripping the icmp echo-request accept — the chain checks are not actually required"
fi

echo
echo "SUMMARY pass=${PASS} fail=${FAIL} build_fail=${BUILD_FAIL} skip=${SKIP}"
echo "WORKDIR=${WORKDIR}"

if [[ "${FAIL}" -ne 0 || "${BUILD_FAIL}" -ne 0 ]]; then
  exit 1
fi
exit 0
