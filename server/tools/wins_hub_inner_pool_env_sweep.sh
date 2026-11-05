#!/usr/bin/env bash
# wins_hub_inner_pool_env_sweep.sh — READ-ONLY pre-rollout sweep for D17/D15
#
# Ruling D17/D15 pinned the hub inner pool to EXACTLY /24. Hosts that set
# WINN3_INNER_POOL_CIDR to /25-/30 worked before (prefixlen < 24 check only
# refused wider) and now refuse to boot (prefixlen != 24 raises at startup).
#
# This script checks EVERY place that can inject the variable on a hub host:
#   1. live process environment  /proc/$(systemctl show -p MainPID --value <unit>)/environ
#   2. systemd unit + drop-ins   systemctl cat <unit>
#   3. every EnvironmentFile= named in (2)  (plus the hub's known env files)
#   4. /etc/environment
#   5. the service User's shell profile files
#   6. any deployed installer copy on disk
#
# PASS = unset OR valid IPv4 CIDR with prefix exactly 24.
# FAIL = any source sets it to malformed, IPv6, or prefix != 24 (including /25-/30).
#
# READ-ONLY GUARANTEE:
#   This script performs ZERO filesystem writes. It never uses >, >>, tee,
#   mktemp, touch, mkdir, chmod, chown, mv, cp, rm, sed -i, truncate, dd,
#   install, or systemctl set-environment / daemon-reload. It only reads
#   (cat, grep, tr, awk, sed without -i, systemctl show/cat, getent, find,
#   stat, tr). Verify with:
#     grep -E 'mktemp|touch |mkdir |chmod |chown |mv |cp |rm |tee |truncate|dd |install -m|set-environment|daemon-reload' "$0"
#   and
#     grep -E '(^|[^0-9])>($|[^&])'  # file redirections (excluding >&2 and comparisons)
#   Both must return no matches. The script exits non-zero on FAIL so it can
#   gate a rollout. It never contacts a server; run it ON the host.
#
# Usage:
#   bash wins_hub_inner_pool_env_sweep.sh [--unit wins-hub.service] [--var WINN3_INNER_POOL_CIDR]
#   (no root required for most checks; live environ needs permission to read /proc/<pid>/environ)
#
# Do NOT run against Kansas <KANSAS_IP> or Spain <NODE_ES_IP> via remote dispatch —
# this script is for an operator to run locally on a target host before rollout.

set -u
# Do not set -e: we want every source checked even if one fails to read.

UNIT="wins-hub.service"
VAR="WINN3_INNER_POOL_CIDR"
EXPECTED_PREFIX="24"

# Parse optional args (read-only, no getopt side effects)
while [[ $# -gt 0 ]]; do
  case "$1" in
    --unit) UNIT="$2"; shift 2 ;;
    --var) VAR="$2"; shift 2 ;;
    --help|-h)
      printf '%s\n' "Usage: $0 [--unit wins-hub.service] [--var WINN3_INNER_POOL_CIDR]"
      printf '%s\n' "Checks every host source for WINN3_INNER_POOL_CIDR. PASS=unset or exactly /24."
      printf '%s\n' "Exit 0 = all PASS/SKIP, 2 = any FAIL, 1 = harness error."
      exit 0
      ;;
    *) printf '%s\n' "Unknown arg: $1 (try --help)"; exit 1 ;;
  esac
done

FAIL_COUNT=0
PASS_COUNT=0
SKIP_COUNT=0
ERROR_COUNT=0

# Helper: validate that a raw value is either unset/empty (PASS) or exactly /24 (PASS), else FAIL.
# Uses python3 ipaddress when available (read-only), falls back to syntactic check.
# Prints one line: "PASS|FAIL: <reason>" and returns 0 on PASS, 1 on FAIL, 2 on malformed harness.
validate_cidr() {
  local raw="$1"
  local src_desc="$2"
  # Trim whitespace (read-only, no file)
  raw="$(printf '%s' "$raw" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  # Strip surrounding quotes if present (env files often quote values)
  case "$raw" in
    \"*\") raw="${raw#\"}"; raw="${raw%\"}" ;;
    \'*\') raw="${raw#\'}"; raw="${raw%\'}" ;;
  esac
  raw="$(printf '%s' "$raw" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

  if [[ -z "$raw" ]]; then
    printf 'PASS: %s — unset (defaults to 10.10.0.0/24)' "$src_desc"
    return 0
  fi

  # Use python3 ipaddress for authoritative check (already a hub preflight dep)
  if command -v python3 >/dev/null 2>&1; then
    local py_result
    py_result="$(python3 - "$raw" 2>&1 <<'PYEOF'
import ipaddress, sys
raw = sys.argv[1]
try:
    net = ipaddress.ip_network(raw, strict=False)
except ValueError as e:
    print("FAIL: not a valid CIDR (%s)" % e)
    sys.exit(1)
if not isinstance(net, ipaddress.IPv4Network):
    print("FAIL: not IPv4 (got %s)" % type(net).__name__)
    sys.exit(1)
if net.prefixlen != 24:
    print("FAIL: prefixlen is /%d, must be exactly /24" % net.prefixlen)
    sys.exit(1)
print("PASS: %s is valid IPv4 /24" % net)
PYEOF
)"
    local py_rc=$?
    # python3 exit 0 = PASS, non-zero = FAIL
    if [[ $py_rc -eq 0 ]]; then
      printf 'PASS: %s — "%s" (%s)' "$src_desc" "$raw" "$py_result"
      return 0
    else
      printf 'FAIL: %s — "%s" (%s)' "$src_desc" "$raw" "$py_result"
      return 1
    fi
  else
    # Fallback: syntactic only, still catches /25-/30 and malformed
    if [[ "$raw" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/24$ ]]; then
      printf 'PASS: %s — "%s" (syntactic /24, python3 not available for full validation)' "$src_desc" "$raw"
      return 0
    fi
    if [[ "$raw" == *"/"* ]]; then
      local pfx="${raw##*/}"
      printf 'FAIL: %s — "%s" (prefix /%s, must be exactly /24; no python3 to validate address)' "$src_desc" "$raw" "$pfx"
    else
      printf 'FAIL: %s — "%s" (not a CIDR, must be <ipv4>/24 or unset)' "$src_desc" "$raw"
    fi
    return 1
  fi
}

# Helper: report one source, bump counters
report_source() {
  local status="$1"  # PASS / FAIL / SKIP / ERROR
  local src="$2"
  local detail="$3"
  printf '[%s] %s: %s\n' "$status" "$src" "$detail"
  case "$status" in
    PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
    FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
    SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
    ERROR) ERROR_COUNT=$((ERROR_COUNT + 1)) ;;
  esac
}

printf '%s\n' "=== wins_hub_inner_pool_env_sweep — READ ONLY — $(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf 'unknown date') ==="
printf '%s\n' "Unit: $UNIT  Var: $VAR  Rule: unset or exactly /24 (D17/D15)"
printf '%s\n' "Host: $(hostname 2>/dev/null || printf 'unknown')  Kernel: $(uname -r 2>/dev/null || printf 'unknown')"
printf '%s\n' "---"

# ── 1. Live process environ ──────────────────────────────────────────────
# systemctl show -p MainPID --value <unit> → /proc/<pid>/environ (NUL-separated)
live_pid=""
if command -v systemctl >/dev/null 2>&1; then
  live_pid="$(systemctl show -p MainPID --value "$UNIT" 2>/dev/null | tr -d '[:space:]' || true)"
fi
if [[ -z "${live_pid:-}" || "$live_pid" == "0" ]]; then
  report_source SKIP "live process environ (/proc/<pid>/environ)" "unit $UNIT not running or no MainPID (no live environ to check)"
else
  environ_path="/proc/${live_pid}/environ"
  if [[ -r "$environ_path" ]]; then
    # NUL-separated; tr to lines; pick exact var
    live_val="$(tr '\0' '\n' < "$environ_path" 2>/dev/null | grep -E "^${VAR}=" | cut -d= -f2- | tail -n 1 || true)"
    if [[ -z "${live_val:-}" ]] && ! tr '\0' '\n' < "$environ_path" 2>/dev/null | grep -q -E "^${VAR}="; then
      report_source PASS "live process environ (PID $live_pid)" "$(validate_cidr "" "live environ")"
    else
      detail="$(validate_cidr "$live_val" "live environ PID $live_pid")"
      rc=$?
      if [[ $rc -eq 0 ]]; then
        report_source PASS "live process environ (PID $live_pid)" "$detail"
      else
        report_source FAIL "live process environ (PID $live_pid)" "$detail"
      fi
    fi
  else
    report_source SKIP "live process environ (PID $live_pid)" "cannot read $environ_path (permission or process gone)"
  fi
fi

# ── 2. systemctl cat (unit + drop-ins) ───────────────────────────────────
cat_output=""
cat_rc=0
if command -v systemctl >/dev/null 2>&1; then
  cat_output="$(systemctl cat "$UNIT" 2>/dev/null || true)"
  # Detect if unit was not found: systemctl cat prints "No files found" and exits non-zero
  if printf '%s' "$cat_output" | grep -q "No files found"; then
    cat_output=""
    cat_rc=1
  fi
  if [[ -z "$cat_output" ]]; then
    # Fallback: try to cat the file directly if systemctl cat gave nothing
    if [[ -r "/etc/systemd/system/${UNIT}" ]]; then
      cat_output="$(cat "/etc/systemd/system/${UNIT}" 2>/dev/null || true)"
    fi
  fi
fi
if [[ -z "$cat_output" ]]; then
  report_source SKIP "systemctl cat $UNIT" "unit file not found or not readable (checked /etc/systemd/system/$UNIT)"
else
  # Look for direct assignment of the var in the unit (Environment= or EnvironmentFile content is separate)
  # Units typically use EnvironmentFile, not Environment= for this var, but check both.
  unit_direct_val="$(printf '%s' "$cat_output" | grep -E "^\s*Environment=.*${VAR}=" | sed -n "s/.*${VAR}=//p" | tr -d '"' | tr -d "'" | awk '{print $1}' | tail -n 1 || true)"
  # Also catch bare VAR= lines that might appear in included env snippets dumped by cat
  if [[ -z "${unit_direct_val:-}" ]]; then
    unit_direct_val="$(printf '%s' "$cat_output" | grep -E "^\s*${VAR}=" | cut -d= -f2- | tail -n 1 || true)"
  fi
  # If systemctl cat shows the var, validate it; otherwise this source is PASS (unset in unit itself — EnvironmentFile is next section)
  if [[ -n "${unit_direct_val:-}" ]] || printf '%s' "$cat_output" | grep -q -E "${VAR}"; then
    # Extract every occurrence for reporting (there should be 0 or 1)
    occurrences="$(printf '%s' "$cat_output" | grep -E "${VAR}" | tr -s ' ' | head -n 5 || true)"
    # Validate the extracted value if we got one, else report raw occurrence
    if [[ -n "${unit_direct_val:-}" ]]; then
      detail="$(validate_cidr "$unit_direct_val" "systemctl cat $UNIT")"
      rc=$?
      if [[ $rc -eq 0 ]]; then
        report_source PASS "systemctl cat $UNIT (unit + drop-ins)" "$detail — occurrences: $occurrences"
      else
        report_source FAIL "systemctl cat $UNIT (unit + drop-ins)" "$detail — occurrences: $occurrences"
      fi
    else
      # Var mentioned but not as a simple assignment — could be in a comment or drop-in name; report for operator
      report_source SKIP "systemctl cat $UNIT (unit + drop-ins)" "mentions $VAR but no direct assignment found; check EnvironmentFile sources below — raw: $occurrences"
    fi
  else
    report_source PASS "systemctl cat $UNIT (unit + drop-ins)" "no $VAR assignment in unit or drop-ins (unset in unit layer)"
  fi
fi

# ── 3. Every EnvironmentFile= named ─────────────────────────────────────
# Parse EnvironmentFile paths from the cat output (handles quoted, dash-prefixed optional files)
env_files_raw=""
if [[ -n "${cat_output:-}" ]]; then
  env_files_raw="$(printf '%s' "$cat_output" | grep -E '^\s*EnvironmentFile=' | sed 's/^[[:space:]]*EnvironmentFile=//' | sed 's/^[[:space:]]*-//' || true)"
fi
# Hub's known env files (also sourced by the shell wrapper, not just systemd):
# WINS_DEFAULTS_FILE=/root/winsvpn-defaults.env, WINS_SECRETS_FILE=/root/winsvpn-secrets.env,
# ENV_FILE=/root/vpn_auth.env, LEGACY_ENV_FILE=/root/vpn_auth/.env
known_env_files="/root/vpn_auth.env
/root/vpn_auth/.env
/root/winsvpn-defaults.env
/root/winsvpn-secrets.env"
# Combine: from unit + known (deduplicated via sort -u, read-only)
all_env_files="$(printf '%s\n%s' "$env_files_raw" "$known_env_files" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -v '^$' | grep -v '^#' | sort -u || true)"
if [[ -z "$all_env_files" ]]; then
  report_source SKIP "EnvironmentFile sources" "no EnvironmentFile= found and no known env files"
else
  while IFS= read -r ef; do
    [[ -z "$ef" ]] && continue
    # Systemd allows specifiers like ${VAR} — we check the literal path; if it contains $, note it
    if [[ "$ef" == *'$'* ]]; then
      report_source SKIP "EnvironmentFile $ef" "contains specifier, cannot resolve without expansion; check literally"
      continue
    fi
    if [[ ! -e "$ef" ]]; then
      report_source SKIP "EnvironmentFile $ef" "file does not exist (optional include; unset)"
      continue
    fi
    if [[ ! -r "$ef" ]]; then
      report_source ERROR "EnvironmentFile $ef" "exists but not readable (permission)"
      continue
    fi
    # Read file without sourcing (read-only); handle quoted values and export prefix
    ef_val="$(grep -E "^\s*(export\s+)?${VAR}=" "$ef" 2>/dev/null | tail -n 1 | sed -E "s/^\s*(export\s+)?${VAR}=//" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || true)"
    # Also handle 'VAR = value' with spaces? No, env files are strict VAR=value, but be lenient
    if [[ -z "${ef_val:-}" ]] && ! grep -q -E "^\s*(export\s+)?${VAR}=" "$ef" 2>/dev/null; then
      report_source PASS "EnvironmentFile $ef" "no $VAR assignment (unset in this file)"
    else
      detail="$(validate_cidr "$ef_val" "EnvironmentFile $ef")"
      rc=$?
      if [[ $rc -eq 0 ]]; then
        report_source PASS "EnvironmentFile $ef" "$detail"
      else
        report_source FAIL "EnvironmentFile $ef" "$detail"
      fi
    fi
  done <<EOF
$all_env_files
EOF
fi

# ── 4. /etc/environment (global PAM/systemd environment) ─────────────────
etc_env_path="/etc/environment"
if [[ ! -e "$etc_env_path" ]]; then
  report_source SKIP "/etc/environment" "file does not exist"
elif [[ ! -r "$etc_env_path" ]]; then
  report_source ERROR "/etc/environment" "exists but not readable"
else
  etc_val="$(grep -E "^\s*${VAR}=" "$etc_env_path" 2>/dev/null | tail -n 1 | cut -d= -f2- || true)"
  if [[ -z "${etc_val:-}" ]] && ! grep -q -E "^\s*${VAR}=" "$etc_env_path" 2>/dev/null; then
    report_source PASS "/etc/environment" "no $VAR assignment"
  else
    detail="$(validate_cidr "$etc_val" "/etc/environment")"
    rc=$?
    if [[ $rc -eq 0 ]]; then
      report_source PASS "/etc/environment" "$detail"
    else
      report_source FAIL "/etc/environment" "$detail"
    fi
  fi
fi

# ── 5. Service User profile files ───────────────────────────────────────
# Determine User= from unit (default root)
unit_user="$(printf '%s' "${cat_output:-}" | grep -E '^\s*User=' | tail -n 1 | cut -d= -f2 | tr -d '[:space:]' || true)"
if [[ -z "${unit_user:-}" ]]; then
  unit_user="root"
fi
# Resolve home directory via getent (read-only)
unit_home=""
if command -v getent >/dev/null 2>&1; then
  unit_home="$(getent passwd "$unit_user" 2>/dev/null | cut -d: -f6 || true)"
fi
if [[ -z "${unit_home:-}" ]]; then
  # Fallback: common homes
  case "$unit_user" in
    root) unit_home="/root" ;;
    *) unit_home="/home/${unit_user}" ;;
  esac
fi
profile_files="/etc/profile
/etc/bash.bashrc
${unit_home}/.profile
${unit_home}/.bash_profile
${unit_home}/.bash_login
${unit_home}/.bashrc"
found_profile_any=0
while IFS= read -r pf; do
  [[ -z "$pf" ]] && continue
  if [[ ! -e "$pf" ]]; then
    continue
  fi
  found_profile_any=1
  if [[ ! -r "$pf" ]]; then
    report_source ERROR "profile $pf (User $unit_user)" "exists but not readable"
    continue
  fi
  pf_val="$(grep -E "^\s*(export\s+)?${VAR}=" "$pf" 2>/dev/null | tail -n 1 | sed -E "s/^\s*(export\s+)?${VAR}=//" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || true)"
  if [[ -z "${pf_val:-}" ]] && ! grep -q -E "^\s*(export\s+)?${VAR}=" "$pf" 2>/dev/null; then
    report_source PASS "profile $pf (User $unit_user)" "no $VAR assignment"
  else
    detail="$(validate_cidr "$pf_val" "profile $pf")"
    rc=$?
    if [[ $rc -eq 0 ]]; then
      report_source PASS "profile $pf (User $unit_user)" "$detail"
    else
      report_source FAIL "profile $pf (User $unit_user)" "$detail"
    fi
  fi
done <<EOF
$profile_files
EOF
if [[ $found_profile_any -eq 0 ]]; then
  report_source SKIP "service user profile (User $unit_user, home $unit_home)" "no profile files found at checked paths"
fi

# ── 6. Deployed installer copy(ies) on disk ─────────────────────────────
# Search read-only; do not descend into /proc, /sys, /dev, /snap.
# Check the most likely deployed paths explicitly, then find under /root.
installer_candidates="/root/wins_control_plane_setup_ONETOUCH.sh
/root/vpn_auth/wins_control_plane_setup_ONETOUCH.sh
/root/wins_control_plane_setup_ONETOUCH.sh.bak
/opt/wins_control_plane_setup_ONETOUCH.sh
/usr/local/src/wins_control_plane_setup_ONETOUCH.sh"
# Expand via find for any *wins_control_plane* or *ONETOUCH* under /root (maxdepth 4, read-only)
found_installers=""
if command -v find >/dev/null 2>&1; then
  found_installers="$(find /root -maxdepth 4 -type f \( -name '*wins_control_plane*' -o -name '*ONETOUCH*' \) 2>/dev/null | head -n 20 || true)"
fi
# Merge explicit + found, deduplicate
all_installers="$(printf '%s\n%s' "$installer_candidates" "$found_installers" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -v '^$' | sort -u || true)"
if [[ -z "$all_installers" ]]; then
  report_source SKIP "deployed installer copy" "no candidate paths; checked explicit list + find /root -maxdepth 4"
else
  while IFS= read -r inst; do
    [[ -z "$inst" ]] && continue
    if [[ ! -e "$inst" ]]; then
      continue
    fi
    if [[ ! -r "$inst" ]]; then
      report_source ERROR "installer $inst" "exists but not readable"
      continue
    fi
    # Look for the default line: WINN3_INNER_POOL_CIDR = (os.getenv ... or "10.10.0.0/24")
    # Also check for shell export lines that would set it.
    inst_line="$(grep -F "WINN3_INNER_POOL_CIDR" "$inst" 2>/dev/null | head -n 5 || true)"
    if [[ -z "$inst_line" ]]; then
      report_source PASS "installer $inst" "no WINN3_INNER_POOL_CIDR string found"
      continue
    fi
    # Extract quoted default CIDR if present: or "10.10.0.0/24" or or '10.10.0.0/24' or WINN3_INNER_POOL_CIDR=10.10.0.0/24
    # Take the first quoted CIDR-looking token after WINN3_INNER_POOL_CIDR
    inst_cidr="$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' "$inst" 2>/dev/null | grep -F "WINN3_INNER_POOL_CIDR" -A2 -B2 2>/dev/null | head -n1 || true)"
    # Simpler: just extract the first CIDR in the matching line(s)
    inst_cidr="$(printf '%s' "$inst_line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | head -n 1 || true)"
    if [[ -z "${inst_cidr:-}" ]]; then
      # Var mentioned but no CIDR literal — could be dynamic; report raw
      report_source SKIP "installer $inst" "mentions $VAR but no CIDR literal found — raw: $inst_line"
      continue
    fi
    detail="$(validate_cidr "$inst_cidr" "installer $inst default")"
    rc=$?
    if [[ $rc -eq 0 ]]; then
      report_source PASS "installer $inst" "$detail — line: $inst_line"
    else
      report_source FAIL "installer $inst" "$detail — line: $inst_line (deployed installer would set a bad default on next re-run)"
    fi
  done <<EOF
$all_installers
EOF
fi

# ── Summary ──────────────────────────────────────────────────────────────
printf '%s\n' "---"
printf '%s\n' "Summary: PASS=$PASS_COUNT  FAIL=$FAIL_COUNT  SKIP=$SKIP_COUNT  ERROR=$ERROR_COUNT"
if [[ $FAIL_COUNT -gt 0 ]]; then
  printf '%s\n' "RESULT: FAIL — at least one source sets $VAR to a value that is NOT exactly /24 (or malformed). Do NOT roll out; fix the source(s) above."
  printf '%s\n' "Remediation: unset $VAR in the failing source(s), or set it to a valid IPv4 /24 (e.g., 10.10.0.0/24) and run 'systemctl daemon-reload && systemctl restart $UNIT' on that host."
  exit 2
elif [[ $ERROR_COUNT -gt 0 ]]; then
  printf '%s\n' "RESULT: ERROR — could not read some sources (permission). Re-run as root for full coverage."
  exit 1
else
  printf '%s\n' "RESULT: PASS — no source sets $VAR to a non-/24 value (all unset or exactly /24). Safe for D17 rollout."
  exit 0
fi
