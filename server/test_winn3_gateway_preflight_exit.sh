#!/usr/bin/env bash
# Prove --preflight fails (nonzero) when credentials are missing, and names
# the missing files. The 2026-08-12 dress-rehearsal defect: main() called
# `inspect_credentials || true` and then printed "Preflight passed" gated
# only on validate_config, so a runbook step "confirm preflight passes"
# succeeded on a node that cannot start.
#
# Mutates a PRIVATE copy under scratch — never the shared tree.
#
# Controls:
#   no-mutation   (live script)     must PASS after the fix
#   comment-only  (private copy)    must PASS
#   deliberate break (private copy) must FAIL, naming what broke
#     break-swallow   restore `inspect_credentials || true` and drop the
#                     creds_ok gate so missing keys look like a pass
#
# Usage:
#   bash test_winn3_gateway_preflight_exit.sh
#   bash test_winn3_gateway_preflight_exit.sh /path/to/wins_winn3_gateway_install.sh
set -euo pipefail
# OI-K4 (Round K): the installer reads MemTotal for host fit and fails closed
# without it. These cases test other properties, so they run against a
# 128 TiB fixture on which every explicit session count fits and an unset
# count still selects 64.
export WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO:-$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/testdata/winn3_gateway_meminfo/large}"

HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
INSTALL="$(python3 -B "${HERE}/../tools/winn3_gateway_test_source.py" "${1:-${HERE}/wins_data_plane_setup_ONETOUCH.sh}" --legacy-compat)"
# Per-run unique scratch: this path is shared by every checkout of this repo on
# one coordinator (HERE/../../../ resolves to ~/.spark_lanes for all of them),
# so a fixed directory lets concurrent lanes clobber each other's combined
# outputs mid-assertion. mktemp isolates each invocation; the env override
# stays for callers that need a stable directory.
if [[ -n "${WINN3_PREFLIGHT_EXIT_WORKDIR:-}" ]]; then
  WORKDIR="${WINN3_PREFLIGHT_EXIT_WORKDIR}"
  mkdir -p "${WORKDIR}"
else
  WORKDIR_PARENT="${HERE}/../../../.spark_lanes/scratch/v3_preflight_exit_defect"
  mkdir -p "${WORKDIR_PARENT}"
  WORKDIR="$(mktemp -d "${WORKDIR_PARENT}/testwork-XXXXXX")"
  trap 'rm -rf -- "${WORKDIR}"' EXIT
fi

PASS=0
FAIL=0
BUILD_FAIL=0

fail() { FAIL=$((FAIL + 1)); printf 'FAIL: %s\n' "$*"; }
pass() { PASS=$((PASS + 1)); printf 'PASS: %s\n' "$*"; }
build_fail() { BUILD_FAIL=$((BUILD_FAIL + 1)); printf 'BUILD_FAIL: %s\n' "$*"; }

SUITE_FAIL=0
SUITE_PASS=0
SUITE_BUILD=0
sfail() { SUITE_FAIL=$((SUITE_FAIL + 1)); printf '  FAIL: %s\n' "$*"; }
spass() { SUITE_PASS=$((SUITE_PASS + 1)); printf '  PASS: %s\n' "$*"; }
sbuild() { SUITE_BUILD=$((SUITE_BUILD + 1)); printf '  BUILD_FAIL: %s\n' "$*"; }

# GNU-stat / sha256sum shims for the credentials-present control on macOS.
# inspect_credentials uses `stat -c %s` / `%a` and admission_fingerprint uses
# sha256sum. Missing-key cases never call those; the present-key case does.
SHIMDIR="${WORKDIR}/shim"
mkdir -p "${SHIMDIR}"
cat > "${SHIMDIR}/stat" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-c" && "${2:-}" == "%s" && -n "${3:-}" ]]; then
  wc -c < "${3}" | tr -d '[:space:]'
  exit 0
fi
if [[ "${1:-}" == "-c" && "${2:-}" == "%a" && -n "${3:-}" ]]; then
  python3 -c 'import os, sys; print(oct(os.stat(sys.argv[1]).st_mode)[-3:])' "${3}"
  exit 0
fi
exec /usr/bin/stat "$@"
SHIM
cat > "${SHIMDIR}/sha256sum" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
if command -v sha256sum >/dev/null 2>&1 && [[ "$(command -v sha256sum)" != "$0" ]]; then
  exec sha256sum "$@"
fi
if [[ "${1:-}" == "-c" ]]; then
  # GNU sha256sum -c FILE: each line is '<64hex>  <name>' with the name
  # resolved relative to the current directory. Implement enough of it for
  # verify_staged_binary's ( cd staging && sha256sum -c winn3-gateway.sha256 ).
  ck="${2:-}"
  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ -z "${line}" ]] && continue
    if [[ ! "${line}" =~ ^([0-9a-fA-F]{64})[[:space:]]+\*?([^[:space:]]+)[[:space:]]*$ ]]; then
      echo "sha256sum: ${ck}: no properly formatted checksum lines found" >&2
      exit 1
    fi
    want="${BASH_REMATCH[1]}"
    name="${BASH_REMATCH[2]}"
    [[ -f "${name}" ]] || { echo "sha256sum: ${name}: No such file or directory" >&2; exit 1; }
    got="$(shasum -a 256 -- "${name}" | awk '{print $1}')"
    # bash 3.2 on the macOS coordinator has no ${var,,}; normalize hex case
    # with tr instead.
    want="$(printf '%s' "${want}" | tr '[:upper:]' '[:lower:]')"
    got="$(printf '%s' "${got}" | tr '[:upper:]' '[:lower:]')"
    if [[ "${got}" != "${want}" ]]; then
      echo "sha256sum: WARNING: 1 computed checksum did NOT match" >&2
      exit 1
    fi
    echo "${name}: OK"
  done < "${ck}"
  exit 0
fi
if [[ -n "${1:-}" && -f "${1}" ]]; then
  shasum -a 256 "${1}" | awk '{print $1"  "$2}'
  exit 0
fi
shasum -a 256 | awk '{print $1"  -"}'
SHIM
chmod +x "${SHIMDIR}/stat" "${SHIMDIR}/sha256sum"

# --- current preflight contract fixtures (2026-08-22) --------------------
# Dummy credentials alone no longer satisfy --preflight: the failure-summary
# now also names the staged binary (verified via sha256sum -c) and the
# cover/ECH + Winn leaf material the unit cannot start without. The controls
# below stage that material once so the missing-credential cases can still
# pin their own die lines.
STAGING="${WORKDIR}/staging"
mkdir -p "${STAGING}"
STAGED_BIN="${STAGING}/winn3-gateway"
if command -v cc >/dev/null 2>&1; then
  printf 'int main(void) { return 0; }\n' | cc -x c -o "${STAGED_BIN}" - >/dev/null
else
  # Non-empty stand-in. verify_staged_binary's arch check only inspects
  # `file` output on x86_64/aarch64 hosts; the copied interpreter binary
  # reports a matching ELF/Mach-O arch there, and on coordinators whose
  # uname -m is unrecognised the check is skipped entirely.
  cp -- "$(command -v bash)" "${STAGED_BIN}"
fi
( cd "${STAGING}" && shasum -a 256 winn3-gateway | awk '{print $1"  "$2}' > winn3-gateway.sha256 )

COVER_DIR="${WORKDIR}/cover"
mkdir -p "${COVER_DIR}"
COVER_CERT="${COVER_DIR}/cover-fullchain.pem"
COVER_KEY="${COVER_DIR}/cover-privkey.pem"
ECH_KEYS="${COVER_DIR}/ech-keys"
WINN_CERT="${COVER_DIR}/winn-leaf.pem"
WINN_KEY="${COVER_DIR}/winn-leaf-key.pem"
printf '%s\n' "dummy-cover-fullchain" > "${COVER_CERT}"
printf '%s\n' "dummy-cover-privkey" > "${COVER_KEY}"
printf '%s\n' "dummy-ech-keys" > "${ECH_KEYS}"
printf '%s\n' "dummy-winn-leaf" > "${WINN_CERT}"
printf '%s\n' "dummy-winn-leaf-key" > "${WINN_KEY}"

run_preflight() {
  # $1 script  $2 creds dir (may be empty / missing files)  $3 stdout  $4 stderr
  local script="$1" creds="$2" out="$3" errf="$4"
  local rc=0
  env \
    PATH="${SHIMDIR}:/usr/bin:/bin:/usr/sbin:/sbin" \
    WINN3_GATEWAY_ID=winsgw-preflight-exit-test \
    WINN3_GATEWAY_PATH_MTU=1450 \
    WINN3_GATEWAY_INNER_V4=10.10.0.1 \
    WINN3_GATEWAY_FORWARD=0 \
    WINN3_GATEWAY_RESOLVER=0 \
    WINN3_GATEWAY_CREDENTIALS_DIR="${creds}" \
    WINN3_GATEWAY_STATIC_KEY_PATH="${creds}/winn3-gateway-static.key" \
    WINN3_GATEWAY_ADMISSION_KEY_PATH="${creds}/winn3-gateway-admission.key" \
    WINN3_GATEWAY_STAGING_DIR="${STAGING}" \
    WINN3_GATEWAY_COVER_CERT="${COVER_CERT}" \
    WINN3_GATEWAY_COVER_KEY="${COVER_KEY}" \
    WINN3_GATEWAY_ECH_KEYS="${ECH_KEYS}" \
    WINN3_GATEWAY_WINN_CERT="${WINN_CERT}" \
    WINN3_GATEWAY_WINN_KEY="${WINN_KEY}" \
    bash -c '
      set -euo pipefail
      # shellcheck disable=SC1090
      source "$1"
      require_root() { :; }
      refuse_on_hub() { :; }
      require_supported_production_os() { :; }
      # The coordinator runs as a mortal uid (501 on this Mac); the ownership
      # gates the install enforces on production root-owned material are not
      # what this suite measures, so stub them the same way require_root is.
      # Their behaviour is covered by the container-mutation suite elsewhere.
      require_root_private_keyfile() { :; }
      require_root_regular_file() { :; }
      report_firewall() { winn3gw_log "report_firewall stub (no iptables)"; }
      preflight_gateway_listen_layout() { winn3gw_log "preflight_gateway_listen_layout stub (no iptables)"; }
      main --preflight
    ' _ "${script}" >"${out}" 2>"${errf}" || rc=$?
  printf '%s' "${rc}"
}

assert_missing_both() {
  local label="$1" script="$2"
  local creds="${WORKDIR}/creds_missing_${label}"
  rm -rf "${creds}"
  mkdir -p "${creds}"
  local out="${WORKDIR}/${label}.stdout"
  local errf="${WORKDIR}/${label}.stderr"
  local rc
  rc="$(run_preflight "${script}" "${creds}" "${out}" "${errf}")"
  local combined="${WORKDIR}/${label}.combined"
  cat "${out}" "${errf}" > "${combined}"

  if [[ "${rc}" == "0" ]]; then
    sfail "${label}: --preflight exited 0 with both credentials missing"
  else
    spass "${label}: --preflight exited ${rc} (nonzero) with both credentials missing"
  fi

  if grep -F -q "Preflight passed" "${combined}"; then
    sfail "${label}: printed 'Preflight passed' while credentials are missing"
  else
    spass "${label}: did not print Preflight passed"
  fi

  local die_line=""
  die_line="$(grep -F "Preflight failed:" "${combined}" | tail -1 || true)"
  if [[ -n "${die_line}" ]]; then
    spass "${label}: printed Preflight failed:"
  else
    sfail "${label}: did not print Preflight failed:"
  fi

  # The DIE line must name the files. inspect_credentials already prints
  # ERR lines with the paths; a last-line that only says "credentials" is
  # the remaining half of the dress-rehearsal defect.
  if [[ "${die_line}" == *"static key at ${creds}/winn3-gateway-static.key"* ]]; then
    spass "${label}: die line names static key path"
  else
    sfail "${label}: die line does not name static key path; die_line=${die_line}"
  fi

  if [[ "${die_line}" == *"admission secret at ${creds}/winn3-gateway-admission.key"* ]]; then
    spass "${label}: die line names admission secret path"
  else
    sfail "${label}: die line does not name admission secret path; die_line=${die_line}"
  fi

  if grep -E -q "Missing static key" "${combined}"; then
    spass "${label}: inspect_credentials reported Missing static key"
  else
    sfail "${label}: missing 'Missing static key' from inspect_credentials"
  fi

  if grep -E -q "Missing admission secret" "${combined}"; then
    spass "${label}: inspect_credentials reported Missing admission secret"
  else
    sfail "${label}: missing 'Missing admission secret' from inspect_credentials"
  fi

  # Read-only: stubs plus FORWARD=0 must not mention an iptables insert as executed.
  if grep -E -q '^\[winn3-gw\] Inserting: iptables -I' "${combined}"; then
    sfail "${label}: preflight executed an iptables insert"
  else
    spass "${label}: no iptables insert executed"
  fi
}

assert_missing_one() {
  local label="$1" script="$2" which="$3"
  local creds="${WORKDIR}/creds_one_${label}"
  rm -rf "${creds}"
  mkdir -p "${creds}"
  # Shape-valid dummy material (64 hex chars). Not a real key. Never printed.
  local dummy
  dummy="$(python3 -c 'print("ab"*32)')"
  if [[ "${which}" == "static" ]]; then
    printf '%s' "${dummy}" > "${creds}/winn3-gateway-admission.key"
    chmod 600 "${creds}/winn3-gateway-admission.key"
  else
    printf '%s' "${dummy}" > "${creds}/winn3-gateway-static.key"
    chmod 600 "${creds}/winn3-gateway-static.key"
  fi
  local out="${WORKDIR}/${label}.stdout"
  local errf="${WORKDIR}/${label}.stderr"
  local rc
  rc="$(run_preflight "${script}" "${creds}" "${out}" "${errf}")"
  local combined="${WORKDIR}/${label}.combined"
  cat "${out}" "${errf}" > "${combined}"

  if [[ "${rc}" == "0" ]]; then
    sfail "${label}: --preflight exited 0 with ${which} key missing"
  else
    spass "${label}: --preflight exited ${rc} with ${which} key missing"
  fi
  if grep -F -q "Preflight passed" "${combined}"; then
    sfail "${label}: printed Preflight passed with ${which} key missing"
  else
    spass "${label}: did not print Preflight passed"
  fi
  local die_line=""
  die_line="$(grep -F "Preflight failed:" "${combined}" | tail -1 || true)"
  if [[ "${which}" == "static" ]]; then
    if [[ "${die_line}" == *"static key at ${creds}/winn3-gateway-static.key"* ]]; then
      spass "${label}: die line names missing static key path"
    else
      sfail "${label}: die line does not name missing static key path; die_line=${die_line}"
    fi
    if [[ "${die_line}" == *"admission secret at"* ]]; then
      sfail "${label}: die line names admission secret which is present; die_line=${die_line}"
    else
      spass "${label}: die line does not claim admission secret is missing"
    fi
  else
    if [[ "${die_line}" == *"admission secret at ${creds}/winn3-gateway-admission.key"* ]]; then
      spass "${label}: die line names missing admission secret path"
    else
      sfail "${label}: die line does not name missing admission secret path; die_line=${die_line}"
    fi
    if [[ "${die_line}" == *"static key at"* ]]; then
      sfail "${label}: die line names static key which is present; die_line=${die_line}"
    else
      spass "${label}: die line does not claim static key is missing"
    fi
  fi
}

assert_shape_bad() {
  local label="$1" script="$2"
  local creds="${WORKDIR}/creds_shape_${label}"
  rm -rf "${creds}"
  mkdir -p "${creds}"
  local dummy
  dummy="$(python3 -c 'print("cd"*32)')"
  printf 'short' > "${creds}/winn3-gateway-static.key"
  printf '%s' "${dummy}" > "${creds}/winn3-gateway-admission.key"
  chmod 600 "${creds}/winn3-gateway-static.key" "${creds}/winn3-gateway-admission.key"
  local out="${WORKDIR}/${label}.stdout"
  local errf="${WORKDIR}/${label}.stderr"
  local rc
  rc="$(run_preflight "${script}" "${creds}" "${out}" "${errf}")"
  local combined="${WORKDIR}/${label}.combined"
  cat "${out}" "${errf}" > "${combined}"
  if [[ "${rc}" == "0" ]]; then
    sfail "${label}: --preflight exited 0 with invalid static key shape"
  else
    spass "${label}: --preflight exited ${rc} with invalid static key shape"
  fi
  local die_line=""
  die_line="$(grep -F "Preflight failed:" "${combined}" | tail -1 || true)"
  if [[ "${die_line}" == *"credential shape"* ]]; then
    spass "${label}: die line names credential shape"
  else
    sfail "${label}: die line does not name credential shape; die_line=${die_line}"
  fi
  if grep -F -q "Preflight passed" "${combined}"; then
    sfail "${label}: printed Preflight passed with invalid static key shape"
  else
    spass "${label}: did not print Preflight passed"
  fi
}

assert_present_both() {
  local label="$1" script="$2"
  local creds="${WORKDIR}/creds_present_${label}"
  rm -rf "${creds}"
  mkdir -p "${creds}"
  local dummy
  dummy="$(python3 -c 'print("cd"*32)')"
  printf '%s' "${dummy}" > "${creds}/winn3-gateway-static.key"
  printf '%s' "${dummy}" > "${creds}/winn3-gateway-admission.key"
  chmod 600 "${creds}/winn3-gateway-static.key" "${creds}/winn3-gateway-admission.key"
  local out="${WORKDIR}/${label}.stdout"
  local errf="${WORKDIR}/${label}.stderr"
  local rc
  rc="$(run_preflight "${script}" "${creds}" "${out}" "${errf}")"
  local combined="${WORKDIR}/${label}.combined"
  cat "${out}" "${errf}" > "${combined}"

  if [[ "${rc}" != "0" ]]; then
    sfail "${label}: --preflight exited ${rc} with both dummy credentials present; combined follows"
    sed 's/^/    /' "${combined}" | head -40
  else
    spass "${label}: --preflight exited 0 with both dummy credentials present"
  fi
  if grep -F -q "Preflight passed" "${combined}"; then
    spass "${label}: printed Preflight passed"
  else
    sfail "${label}: did not print Preflight passed with credentials present"
  fi
  if grep -E -q "Preflight failed" "${combined}"; then
    sfail "${label}: printed Preflight failed despite credentials present"
  else
    spass "${label}: did not print Preflight failed"
  fi
}

run_suite() {
  local script="$1" label="$2"
  SUITE_FAIL=0
  SUITE_PASS=0
  SUITE_BUILD=0
  if [[ ! -f "${script}" ]]; then
    sbuild "${label}: script missing: ${script}"
    return 0
  fi
  if ! bash -n "${script}"; then
    sbuild "${label}: bash -n failed"
    return 0
  fi
  spass "${label}: bash -n clean"
  assert_missing_both "${label}-both-missing" "${script}"
  assert_missing_one "${label}-static-missing" "${script}" static
  assert_missing_one "${label}-admission-missing" "${script}" admission
  assert_shape_bad "${label}-shape-bad" "${script}"
  assert_present_both "${label}-both-present" "${script}"
}

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
BREAK_SWALLOW="${WORKDIR}/break_swallow.sh"
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

echo "=== deliberate break: swallow inspect_credentials (must FAIL the inner suite) ==="
cat "${LIVE_COPY}" > "${BREAK_SWALLOW}"
python3 -c '
import pathlib, sys
p = pathlib.Path(sys.argv[1])
text = p.read_text()
old = "    inspect_credentials || creds_ok=1\n"
if old not in text:
    sys.exit("expected inspect_credentials || creds_ok=1 not found; cannot apply swallow mutation")
text = text.replace(old, "    inspect_credentials || true\n", 1)
# Drop the creds_ok contribution so the original gate (config only) is restored.
# If creds_ok stays 0 forever, the missing-key cases would still pass the new
# gate. Force the historical swallow.
old_gate = "    if [[ \"${creds_ok}\" -ne 0 ]]; then"
if old_gate not in text:
    sys.exit("expected creds_ok gate not found; cannot apply swallow mutation")
# Neutralise the creds_ok block by forcing creds_ok=0 after the swallow.
text = text.replace(
    "    inspect_credentials || true\n",
    "    inspect_credentials || true\n    creds_ok=0\n",
    1,
)
p.write_text(text)
print("applied swallow mutation")
' "${BREAK_SWALLOW}"
run_suite "${BREAK_SWALLOW}" "break-swallow"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control break-swallow: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control break-swallow: suite stayed green after restoring inspect_credentials || true — the test cannot see its own guard"
fi

echo
echo "PASS=${PASS} FAIL=${FAIL} BUILD_FAIL=${BUILD_FAIL}"
if [[ "${FAIL}" -ne 0 || "${BUILD_FAIL}" -ne 0 ]]; then
  exit 1
fi
exit 0
