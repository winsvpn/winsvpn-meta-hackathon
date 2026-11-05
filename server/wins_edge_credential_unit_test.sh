#!/usr/bin/env bash
# L41 unit test: nodes hold no Cloudflare credential.
#
# Proves, without root, a network, a hub, Cloudflare, or any real credential:
#   * the certbot DNS-01 hook body is byte-identical in the Data installer, the
#     Core installer and the migration script (drift guard), and parses;
#   * neither node installer references the Cloudflare API or a certbot
#     Cloudflare credentials file any more;
#   * the hook posts to the node- or Core-scoped hub endpoint with the token in
#     the stdin curl config only (never argv), refuses bad input before any
#     request, and fails on a hub refusal;
#   * wins_edge_credential_migrate.sh: --check reports by NAME; --apply refuses
#     (changing nothing) when the hub broker does not serve or bind the node,
#     moves a dns-cloudflare ACME lineage to hub hooks before removing anything,
#     removes the credential, destroys the legacy credentials file, detects and
#     lists stray copies by VALUE without ever rewriting them; records the first
#     pre-migration state once; restores hook and renewal files on a failed
#     reconfigure or test renewal; --revert is explicit and time-limited;
#     no output ever contains a credential value.
#
# It also covers tools/wins_operator_prepare_subject.sh (admin-only steps run
# operator-side; the fragment carries no ADMIN_TOKEN or Cloudflare credential).
#
# Mutation controls (must FAIL, proving the checks are not vacuous):
#   MUT-1 a hook copy with one changed byte is reported as drift
#   MUT-2 a migration script that skips the hub probe is caught by the
#         "hub down changes nothing" case
#   MUT-3 a migration script that skips the dns_cloudflare_* strip after
#         reconfigure (the v8 behaviour) is caught by the M16a case, because the
#         fake certbot carries those keys over as certbot 2.9.0 does
#
# Usage: bash wins_edge_credential_unit_test.sh [server_dir]
#   server_dir defaults to ./server relative to this file's parent, or the
#   directory holding the patched scripts.
set -Eeuo pipefail

HERE="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SERVER_DIR="${1:-${WINS_EDGE_SERVER_DIR:-${HERE}}}"
DATA="${SERVER_DIR}/wins_data_plane_setup_ONETOUCH.sh"
CORE="${SERVER_DIR}/wins_core_server_setup_ONETOUCH.sh"
MIGRATE="${SERVER_DIR}/wins_edge_credential_migrate.sh"
for f in "${DATA}" "${CORE}" "${MIGRATE}"; do
  [[ -f "${f}" ]] || { echo "missing ${f}" >&2; exit 2; }
done
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wins-edge-l41.XXXXXX")"
trap 'rm -rf -- "${WORK}"' EXIT

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); printf 'PASS: %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL: %s\n' "$*"; }
check() { local label="$1"; shift; if "$@"; then pass "${label}"; else fail "${label}"; fi; }
refute() { local label="$1"; shift; if "$@"; then fail "${label}"; else pass "${label}"; fi; }

FAKE_VALUE='FAKE-cf-credential-l41-0123456789abcdef'
NODE_TOKEN_VALUE='fake-node-token-l41-abcdefghijklmnop'

hook_body() {
  awk "/cat <<'WINS_EDGE_ACME_HOOK_BODY'/{f=1;next} f && /^WINS_EDGE_ACME_HOOK_BODY\$/{exit} f{print}" "$1"
}

# ------------------------------------------------------------------ drift ---
hook_body "${DATA}" > "${WORK}/hook.data"
hook_body "${CORE}" > "${WORK}/hook.core"
hook_body "${MIGRATE}" > "${WORK}/hook.migrate"
check "hook body present in all three scripts" test -s "${WORK}/hook.data" -a -s "${WORK}/hook.core" -a -s "${WORK}/hook.migrate"
check "hook body identical: data == core" cmp -s "${WORK}/hook.data" "${WORK}/hook.core"
check "hook body identical: data == migrate" cmp -s "${WORK}/hook.data" "${WORK}/hook.migrate"
check "hook body parses" bash -n "${WORK}/hook.data"
# shellcheck disable=SC2016  # the literal ${...} text is what the mutation edits
sed 's/sleep "${WINS_EDGE_ACME_PROPAGATION_SECONDS:-30}"/sleep 31/' "${WORK}/hook.data" > "${WORK}/hook.mut"
refute "MUT-1 a one-byte hook drift is detected" cmp -s "${WORK}/hook.data" "${WORK}/hook.mut"

# ----------------------------------------------------------------- static ---
for script in "${DATA}" "${CORE}"; do
  name="$(basename "${script}")"
  refute "${name}: no Cloudflare API host" grep -q 'api\.cloudflare\.com' "${script}"
  refute "${name}: no certbot Cloudflare credentials file writer" grep -q 'dns_cloudflare_api_token' "${script}"
  refute "${name}: no --dns-cloudflare authenticator" grep -Eq -- '--dns-cloudflare([[:space:]]|-credentials)' "${script}"
done
check "data installer refuses a node-held fleet credential in preflight" grep -q 'data_refuse_node_fleet_credentials || exit 1' "${DATA}"
check "core installer refuses a host-held fleet credential in preflight" grep -q 'core_refuse_node_fleet_credentials || exit 1' "${CORE}"
check "data preflight accepts only a subject token or bootstrap grant" grep -q 'data_require_subject_credential || exit 1' "${DATA}"
check "core preflight accepts only a subject token or bootstrap grant" grep -q 'core_require_subject_credential || exit 1' "${CORE}"
for script in "${DATA}" "${CORE}"; do
  name="$(basename "${script}")"
  refute "${name}: never sends x-admin-token" grep -q 'x-admin-token' "${script}"
  refute "${name}: never calls the admin binding endpoint" grep -q '/admin/edge/hostname-bindings"' "${script}"
  refute "${name}: preflight no longer requires ADMIN_TOKEN" grep -q 'ADMIN_TOKEN is missing or invalid' "${script}"
done

# ------------------------------------------------------------- fake curl ---
FAKEBIN="${WORK}/bin"
mkdir -p "${FAKEBIN}"
cat > "${FAKEBIN}/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
# Fake hub. Records argv, the stdin curl config and the request body.
log_dir="${FAKE_HUB_LOG:?}"
output="" body="" url="" previous=""
for arg in "$@"; do
  case "${previous}" in
    -o) output="${arg}" ;;
    --data-binary) body="${arg#@}" ;;
  esac
  [[ "${arg}" != http*://* ]] || url="${arg}"
  previous="${arg}"
done
n=$(( $(cat "${log_dir}/count" 2>/dev/null || echo 0) + 1 ))
printf '%s' "${n}" > "${log_dir}/count"
printf '%s\n' "$*" > "${log_dir}/argv.${n}"
printf '%s\n' "${url}" > "${log_dir}/url.${n}"
if [[ " $* " == *" --config - "* ]]; then cat > "${log_dir}/config.${n}"; fi
[[ -z "${body}" ]] || cp "${body}" "${log_dir}/body.${n}"
case "${FAKE_HUB_MODE:-ok}" in
  down) printf '%s\n' '{"detail":"unavailable"}' > "${output}"; printf '503'; exit 0 ;;
  refuse) printf '%s\n' '{"detail":"Hostname is not bound to this subject"}' > "${output}"; printf '403'; exit 0 ;;
esac
case "${url}" in
  */edge/hostnames)
    printf '{"ok":true,"zone":"edge-zone.example","hostnames":%s}\n' "${FAKE_HUB_HOSTNAMES:-[]}" > "${output}" ;;
  */admin/edge/hostname-bindings)
    jq -c '{ok:true,hostnames:(["default.edge-zone.example"] + (.hostnames | map(ascii_downcase)))}' "${body}" > "${output}" ;;
  */admin/nodes/bootstrap-management-tunnel|*/admin/core/bootstrap-management-tunnel)
    printf '{"ok":true,"management_mode":"cloudflare_tunnel","tunnel_token":"%s","ssh_host":"node-x-0123456789abcdef.mgmt.example","tunnel_id":"12345678-1234-1234-1234-123456789abc"}\n' \
      "$(printf 'T%.0s' $(seq 1 100))" > "${output}" ;;
  */admin/bootstrap-grant)
    printf '%s\n' '{"ok":true,"bootstrap_token":"fake-grant-l41-abcdefghijklmnopqrstuvwxyz0123"}' > "${output}" ;;
  *) printf '%s\n' '{"ok":true,"state":"created"}' > "${output}" ;;
esac
printf '200'
FAKE_CURL
chmod 755 "${FAKEBIN}/curl"
export PATH="${FAKEBIN}:${PATH}"

reset_log() { rm -rf -- "${WORK}/log"; mkdir -p "${WORK}/log"; export FAKE_HUB_LOG="${WORK}/log"; }
calls() { cat "${WORK}/log/count" 2>/dev/null || echo 0; }
any_argv_contains() { cat "${WORK}"/log/argv.* 2>/dev/null | grep -qF -- "$1"; }

# ------------------------------------------------------------------- hook ---
make_hook() {
  local kind="$1" env_file="$2" out="$3"
  { printf '#!/usr/bin/env bash\n'
    printf 'WINS_EDGE_KIND=%q\n' "${kind}"
    printf 'WINS_EDGE_ENV_FILE=%q\n' "${env_file}"
    cat "${WORK}/hook.data"; } > "${out}"
  chmod 700 "${out}"
}
cat > "${WORK}/node.env" <<EOF
NODE_SLUG="node-a"
NODE_TOKEN="${NODE_TOKEN_VALUE}"
HUB_API_BASE="https://hub.example.test"
EOF
chmod 600 "${WORK}/node.env"
make_hook node "${WORK}/node.env" "${WORK}/hook-node"
export WINS_EDGE_ACME_PROPAGATION_SECONDS=0

reset_log
check "hook present succeeds" env CERTBOT_DOMAIN=Node-A.edge-zone.example CERTBOT_VALIDATION=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG "${WORK}/hook-node" present
check "hook present posts to the node-scoped hub endpoint" grep -qx 'https://hub.example.test/api/v1/nodes/node-a/edge/acme-challenge' "${WORK}/log/url.1"
json_true() { jq -e "$1" "$2" >/dev/null; }
check "hook body carries action/hostname/validation" json_true '.action == "present" and .hostname == "node-a.edge-zone.example" and (.validation | length) == 43' "${WORK}/log/body.1"
refute "hook never puts the node token in argv" any_argv_contains "${NODE_TOKEN_VALUE}"
check "hook sends the node token as an x-node-token header via stdin config" grep -qF "header = \"x-node-token: ${NODE_TOKEN_VALUE}\"" "${WORK}/log/config.1"
reset_log
check "hook cleanup succeeds" env CERTBOT_DOMAIN=node-a.edge-zone.example CERTBOT_VALIDATION=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG "${WORK}/hook-node" cleanup
check "hook cleanup sends action=cleanup" json_true '.action == "cleanup"' "${WORK}/log/body.1"
reset_log
refute "hook refuses a malformed validation" env CERTBOT_DOMAIN=node-a.edge-zone.example CERTBOT_VALIDATION='bad value' "${WORK}/hook-node" present 2>/dev/null
check "hook made no request for malformed input" test "$(calls)" = 0
refute "hook refuses an unknown mode" "${WORK}/hook-node" upsert 2>/dev/null
reset_log
refute "hook fails when the hub refuses" env FAKE_HUB_MODE=refuse CERTBOT_DOMAIN=node-a.edge-zone.example CERTBOT_VALIDATION=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG "${WORK}/hook-node" present 2>/dev/null
cat > "${WORK}/core.env" <<EOF
CORE_ID=north-core
CORE_TOKEN=${NODE_TOKEN_VALUE}
HUB_API_BASE=https://hub.example.test
EOF
chmod 600 "${WORK}/core.env"
make_hook core "${WORK}/core.env" "${WORK}/hook-core"
reset_log
check "core hook present succeeds" env CERTBOT_DOMAIN=north-core.edge-zone.example CERTBOT_VALIDATION=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG "${WORK}/hook-core" present
check "core hook uses the Core-scoped endpoint" grep -qx 'https://hub.example.test/api/v1/core/north-core/edge/acme-challenge' "${WORK}/log/url.1"
check "core hook uses x-core-token" grep -qF 'header = "x-core-token: ' "${WORK}/log/config.1"

# Round CF Turn 2 (CF-3): the token only ever goes to https://<fronted hub hostname>.
hook_with_base() {
  local base="$1"
  printf 'NODE_SLUG="node-a"\nNODE_TOKEN="%s"\nHUB_API_BASE="%s"\n' "${NODE_TOKEN_VALUE}" "${base}" > "${WORK}/node-base.env"
  chmod 600 "${WORK}/node-base.env"
  make_hook node "${WORK}/node-base.env" "${WORK}/hook-base"
  reset_log
  env CERTBOT_DOMAIN=node-a.edge-zone.example CERTBOT_VALIDATION=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG "${WORK}/hook-base" present 2>/dev/null
}
for bad_base in "http://hub.example.test" "https://192.0.2.10" "https://hub.example.test:8443" "https://hub.example.test/api" "ftp://hub.example.test" "https://" "https://hub.example.test.evil/x?"; do
  refute "hook refuses hub base ${bad_base}" hook_with_base "${bad_base}"
  check "hook sent nothing for ${bad_base}" test "$(calls)" = 0
done
check "hook accepts https://fronted-hostname" hook_with_base "https://hub.example.test"
check "hook pins curl to https" grep -q -- "--proto =https" "${WORK}/log/argv.1"

# -------------------------------------------------------------- migration ---
FAKE_ADMIN_VALUE='FAKE-fleet-admin-l41-0123456789abcdefghij'
new_root() {
  local root="${WORK}/root-$1"
  rm -rf -- "${root}"
  mkdir -p "${root}/root" "${root}/etc/letsencrypt/renewal" "${root}/var/lib/cloud/instance" "${root}/usr/local/sbin"
  cat > "${root}/root/node.env" <<EOF
NODE_SLUG="node-a"
NODE_TOKEN="${NODE_TOKEN_VALUE}"
HUB_API_BASE="https://hub.example.test"
STEALTH_HOST="node-a.edge-zone.example"
REGIONAL_GATEWAY_ALIASES="frankfurt.edge-zone.example"
ADMIN_TOKEN=""
EOF
  cat > "${root}/root/winsvpn-secrets.env" <<EOF
ADMIN_TOKEN='${FAKE_ADMIN_VALUE}'
RCLONE_CONFIG_B64='ZmFrZS1yY2xvbmUtY29uZmln'
CLOUDFLARE_ACCOUNT_ID='0123456789abcdef0123456789abcdef'
CLOUDFLARE_API_TOKEN='${FAKE_VALUE}'
CLOUDFLARE_ZONE_ID='abababababababababababababababab'
EOF
  printf 'dns_cloudflare_api_token = %s\n' "${FAKE_VALUE}" > "${root}/etc/letsencrypt/winsvpn-cloudflare.ini"
  chmod 600 "${root}/root/node.env" "${root}/root/winsvpn-secrets.env" "${root}/etc/letsencrypt/winsvpn-cloudflare.ini"
  printf '%s' "${root}"
}
run_migrate() {
  local root="$1"
  shift
  env WINS_MIGRATE_ROOT="${root}" WINS_MIGRATE_ALLOW_NONROOT=1 bash "${MIGRATE_UNDER_TEST:-${MIGRATE}}" "$@" > "${WORK}/migrate.out" 2>&1
}
out_has_value() { grep -qF -- "${FAKE_VALUE}" "${WORK}/migrate.out" || grep -qF -- "${FAKE_ADMIN_VALUE}" "${WORK}/migrate.out"; }
value_anywhere() { grep -rqF -- "${FAKE_VALUE}" "$1" || grep -rqF -- "${FAKE_ADMIN_VALUE}" "$1"; }
both_hosts='["node-a.edge-zone.example","frankfurt.edge-zone.example"]'
STATE_REL="var/lib/winsvpn/edge-credential-migration"

# M1 --check is read-only and states its limits
R="$(new_root m1)"
before_tree="$(cd "${R}" && find . -type f -exec cksum {} + | sort)"
reset_log
rc=0; FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${R}" --check || rc=$?
check "M1 --check on a dirty node exits 2" test "${rc}" = 2
check "M1 --check names both fleet credentials" grep -q 'CLOUDFLARE_API_TOKEN.*ADMIN_TOKEN\|ADMIN_TOKEN.*CLOUDFLARE_API_TOKEN' "${WORK}/migrate.out"
check "M1 --check lists the scanned locations" grep -q 'locations scanned' "${WORK}/migrate.out"
check "M1 --check states what it cannot establish" grep -q 'LIMITS: this scan cannot see provider snapshots' "${WORK}/migrate.out"
check "M1 --check changed no file" test "$(cd "${R}" && find . -type f -exec cksum {} + | sort)" = "${before_tree}"
refute "M1 --check never prints a value" out_has_value

# M2 hub down: nothing changes
hub_down_changes_nothing() {
  local root before rc=0
  root="$(new_root m2)"
  before="$(cksum < "${root}/root/winsvpn-secrets.env")"
  reset_log
  FAKE_HUB_MODE=down run_migrate "${root}" --apply || rc=$?
  [[ "${rc}" == 3 && "$(cksum < "${root}/root/winsvpn-secrets.env")" == "${before}" \
      && -f "${root}/etc/letsencrypt/winsvpn-cloudflare.ini" && ! -e "${root}/${STATE_REL}" ]]
}
check "M2 --apply with the hub down exits 3 and changes nothing" hub_down_changes_nothing
refute "M2 output never prints a value" out_has_value
sed 's/^  hub_probe || die "Refusing to migrate/  true || die "Refusing to migrate/' "${MIGRATE}" > "${WORK}/migrate.mut"
check "MUT-2 mutation applied" grep -q '^  true || die "Refusing to migrate' "${WORK}/migrate.mut"
MIGRATE_UNDER_TEST="${WORK}/migrate.mut"
refute "MUT-2 a migration that skips the hub probe is caught" hub_down_changes_nothing
unset MIGRATE_UNDER_TEST

# M3 alias not assigned on the hub: nothing changes
R="$(new_root m3)"
reset_log
rc=0; FAKE_HUB_HOSTNAMES='["node-a.edge-zone.example"]' run_migrate "${R}" --apply || rc=$?
check "M3 --apply with an unassigned alias exits 3" test "${rc}" = 3
check "M3 names the unassigned alias" grep -q 'frankfurt.edge-zone.example' "${WORK}/migrate.out"
check "M3 left the credentials in place" grep -q '^CLOUDFLARE_API_TOKEN=' "${R}/root/winsvpn-secrets.env"

# M4 success without an ACME lineage; M4b re-apply keeps the first record
R="$(new_root m4)"
reset_log
rc=0; FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${R}" --apply || rc=$?
check "M4 --apply exits 0" test "${rc}" = 0
refute "M4 Cloudflare credential removed" grep -q '^CLOUDFLARE_API_TOKEN=' "${R}/root/winsvpn-secrets.env"
refute "M4 fleet ADMIN_TOKEN removed" grep -q '^ADMIN_TOKEN=' "${R}/root/winsvpn-secrets.env"
check "M4 unrelated secrets kept" grep -q '^RCLONE_CONFIG_B64=' "${R}/root/winsvpn-secrets.env"
perm="$(stat -c '%a' "${R}/root/winsvpn-secrets.env" 2>/dev/null || stat -f '%Lp' "${R}/root/winsvpn-secrets.env")"
check "M4 secrets file stays mode 600" test "${perm}" = 600
check "M4 legacy credentials file destroyed" test ! -e "${R}/etc/letsencrypt/winsvpn-cloudflare.ini"
check "M4 pre-migration state recorded" grep -q '^L41_CREDENTIAL_NAMES=CLOUDFLARE_API_TOKEN ADMIN_TOKEN$' "${R}/${STATE_REL}/pre-migration/state.env"
check "M4 node marked migrated" grep -q '^L41_APPLIED_EPOCH=' "${R}/${STATE_REL}/migrated.env"
refute "M4 no value anywhere under the fake root" value_anywhere "${R}"
refute "M4 output never prints a value" out_has_value
refute "M4 node token never in argv" any_argv_contains "${NODE_TOKEN_VALUE}"
pre_sum="$(cksum < "${R}/${STATE_REL}/pre-migration/state.env")"
rc=0; FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${R}" --apply || rc=$?
check "M4b a second --apply succeeds" test "${rc}" = 0
check "M4b the first pre-migration record is never overwritten" test "$(cksum < "${R}/${STATE_REL}/pre-migration/state.env")" = "${pre_sum}"
check "M4b re-apply is recorded without replacing the first apply" grep -q '^L41_REAPPLIED_AT=' "${R}/${STATE_REL}/migrated.env"
rc=0; FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${R}" --check || rc=$?
check "M4 --check afterwards reports clean (exit 0)" test "${rc}" = 0

# M5 stray copies are listed for the owner and never rewritten
R="$(new_root m5)"
cp "${R}/root/winsvpn-secrets.env" "${R}/root/winsvpn-secrets.env.bak"
printf '#cloud-config\nwrite_files:\n  - content: "CLOUDFLARE_API_TOKEN=%s"\n' "${FAKE_VALUE}" > "${R}/var/lib/cloud/instance/user-data.txt"
stray_before="$(cksum < "${R}/var/lib/cloud/instance/user-data.txt") $(cksum < "${R}/root/winsvpn-secrets.env.bak")"
reset_log
rc=0; FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${R}" --apply || rc=$?
check "M5 migration with stray copies exits 7" test "${rc}" = 7
check "M5 stray paths are listed for owner review" grep -q 'var/lib/cloud/instance/user-data.txt' "${WORK}/migrate.out"
check "M5 stray files are left byte-identical" test "$(cksum < "${R}/var/lib/cloud/instance/user-data.txt") $(cksum < "${R}/root/winsvpn-secrets.env.bak")" = "${stray_before}"
refute "M5 managed credential still removed" grep -q '^CLOUDFLARE_API_TOKEN=' "${R}/root/winsvpn-secrets.env"
refute "M5 output never prints a value" out_has_value
refute "M5 the scrub option no longer exists" grep -q -- '--scrub-residual' "${MIGRATE}"

# M6 ACME lineages: staging reconfigure, saved-config check, test renewal
cat > "${FAKEBIN}/certbot" <<'FAKE_CERTBOT'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${FAKE_HUB_LOG}/certbot.argv"
cert="" previous=""
for arg in "$@"; do
  [[ "${previous}" != "--cert-name" ]] || cert="${arg}"
  previous="${arg}"
done
if [[ -n "${FAKE_CERTBOT_RENEWAL_DIR:-}" ]]; then
  conf="${FAKE_CERTBOT_RENEWAL_DIR}/${cert}.conf"
else
  conf="${FAKE_CERTBOT_CONF:?}"
fi
case "$1" in
  reconfigure)
    [[ "${FAKE_CERTBOT_RECONFIGURE:-ok}" == ok ]] || exit 1
    [[ "${cert}" != "${FAKE_CERTBOT_FAIL_CERT:-}" ]] || exit 1
    # Like certbot 2.9.0 (measured on the canary data plane, 2026-09-25): the
    # previous authenticator's dns_cloudflare_* parameters are carried into the
    # new renewal file ("Var dns_cloudflare_credentials=... (set by user).").
    carried="$(grep -E '^[[:space:]]*dns_cloudflare_' "${conf}" 2>/dev/null || true)"
    {
      printf 'version = 2.9.0\n[renewalparams]\naccount = 0123456789abcdef0123456789abcdef\n'
      printf 'authenticator = manual\nserver = https://acme-v02.api.letsencrypt.org/directory\nkey_type = ecdsa\npref_challs = dns-01,\n'
      [[ -z "${carried}" ]] || printf '%s\n' "${carried}"
      printf 'manual_auth_hook = /usr/local/sbin/wins-edge-acme-hook present\n'
      printf 'manual_cleanup_hook = /usr/local/sbin/wins-edge-acme-hook cleanup\n'
    } > "${conf}"
    /bin/cp "${conf}" "${FAKE_HUB_LOG}/reconfigured.${cert}.conf"
    # Makes the renewal directory unwritable after the reconfigure (M16b).
    [[ "${FAKE_CERTBOT_LOCK_DIR:-0}" != 1 ]] || chmod a-w "$(dirname -- "${conf}")"
    ;;
  renew)
    [[ " $* " == *" --dry-run "* ]] || exit 9
    [[ "${FAKE_CERTBOT_RENEW:-ok}" == ok ]] || exit 1
    ;;
  *) exit 2 ;;
esac
FAKE_CERTBOT
chmod 755 "${FAKEBIN}/certbot"
lineage_root() {
  local root
  root="$(new_root "$1")"
  # The [renewalparams] keys measured on the canary before migration.
  printf '[renewalparams]\nauthenticator = dns-cloudflare\ndns_cloudflare_propagation_seconds = 30\ndns_cloudflare_credentials = /etc/letsencrypt/winsvpn-cloudflare.ini\n' \
    > "${root}/etc/letsencrypt/renewal/winsvpn-node-origin.conf"
  printf '%s' "${root}"
}
conf_of() { printf '%s/etc/letsencrypt/renewal/winsvpn-node-origin.conf' "$1"; }

R="$(lineage_root m6a)"; conf_before="$(cksum < "$(conf_of "${R}")")"
reset_log
rc=0; FAKE_CERTBOT_RECONFIGURE=fail FAKE_CERTBOT_CONF="$(conf_of "${R}")" FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${R}" --apply || rc=$?
check "M6a failed staging reconfigure exits 4" test "${rc}" = 4
check "M6a renewal config left as it was" test "$(cksum < "$(conf_of "${R}")")" = "${conf_before}"
check "M6a the hook it created is removed again" test ! -e "${R}/usr/local/sbin/wins-edge-acme-hook"
check "M6a credentials left in place" grep -q '^CLOUDFLARE_API_TOKEN=' "${R}/root/winsvpn-secrets.env"
check "M6a residual state is reported" grep -q 'residual state after the failed apply' "${WORK}/migrate.out"

R="$(lineage_root m6b)"; conf_before="$(cksum < "$(conf_of "${R}")")"
reset_log
rc=0; FAKE_CERTBOT_RENEW=fail FAKE_CERTBOT_CONF="$(conf_of "${R}")" FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${R}" --apply || rc=$?
check "M6b failed test renewal exits 4" test "${rc}" = 4
check "M6b reconfigured renewal config restored to dns-cloudflare" test "$(cksum < "$(conf_of "${R}")")" = "${conf_before}"
check "M6b hook removed again" test ! -e "${R}/usr/local/sbin/wins-edge-acme-hook"
check "M6b credentials and legacy file left in place" test -f "${R}/etc/letsencrypt/winsvpn-cloudflare.ini"
check "M6b test renewal was attempted with --dry-run" grep -q -- 'renew --non-interactive --cert-name winsvpn-node-origin --dry-run' "${WORK}/log/certbot.argv"

R="$(lineage_root m6)"
reset_log
rc=0; FAKE_CERTBOT_CONF="$(conf_of "${R}")" FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${R}" --apply || rc=$?
check "M6 lineage migration exits 0" test "${rc}" = 0
check "M6 staging reconfigure used the hub hooks" grep -q -- '--manual-auth-hook /usr/local/sbin/wins-edge-acme-hook present' "${WORK}/log/certbot.argv"
check "M6 test renewal ran after reconfigure" test "$(grep -c '^renew ' "${WORK}/log/certbot.argv")" = 1
refute "M6 certbot never received a credential" grep -qF -- "${FAKE_VALUE}" "${WORK}/log/certbot.argv"
check "M6 renewal config now names the hub hooks" grep -q '^authenticator = manual$' "$(conf_of "${R}")"
check "M6 installed hook body matches the installers" cmp -s <(sed '1,4d' "${R}/usr/local/sbin/wins-edge-acme-hook") "${WORK}/hook.data"
check "M6 pre-migration renewal config saved once" grep -q 'dns-cloudflare' "${R}/${STATE_REL}/pre-migration/winsvpn-node-origin.renewal.conf"
refute "M6 no value anywhere under the fake root" value_anywhere "${R}"

# M16 (Round CF10): certbot 2.9.0 carries the previous authenticator's
# dns_cloudflare_* keys into the reconfigured renewal file (measured on the
# canary 2026-09-25; --apply exited 4 there). The apply removes exactly those
# keys before the saved-config check and the test renewal; a removal that
# cannot write takes the restore path with nothing removed.
perm_of() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
strip_temp_left() { compgen -G "$1/etc/letsencrypt/renewal/.*l41strip*" >/dev/null; }
M16_ROOT=""
M16_RC=""
strip_apply_succeeds() {
  local conf
  M16_ROOT="$(lineage_root "$1")"
  conf="$(conf_of "${M16_ROOT}")"
  chmod 644 "${conf}"
  reset_log
  M16_RC=0
  FAKE_CERTBOT_CONF="${conf}" FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${M16_ROOT}" --apply || M16_RC=$?
  [[ "${M16_RC}" == 0 ]] \
    && grep -qx 'authenticator = manual' "${conf}" \
    && grep -qxF 'manual_auth_hook = /usr/local/sbin/wins-edge-acme-hook present' "${conf}" \
    && grep -qxF 'manual_cleanup_hook = /usr/local/sbin/wins-edge-acme-hook cleanup' "${conf}" \
    && ! grep -q '^[[:space:]]*dns_cloudflare' "${conf}" \
    && ! grep -q '^CLOUDFLARE_API_TOKEN=' "${M16_ROOT}/root/winsvpn-secrets.env" \
    && [[ ! -e "${M16_ROOT}/etc/letsencrypt/winsvpn-cloudflare.ini" ]]
}
check "M16a apply succeeds when certbot carries the dns_cloudflare_* keys over" strip_apply_succeeds m16a
R16="${M16_ROOT}"
written16="${WORK}/log/reconfigured.winsvpn-node-origin.conf"
check "M16a setup: the fake certbot carried both measured keys into the file it wrote" \
  grep -qx 'dns_cloudflare_propagation_seconds = 30' "${written16}"
check "M16a setup: the carried credentials key too" grep -qx 'dns_cloudflare_credentials = /etc/letsencrypt/winsvpn-cloudflare.ini' "${written16}"
check "M16a saved file: authenticator = manual" grep -qx 'authenticator = manual' "$(conf_of "${R16}")"
check "M16a saved file names both hub hooks" test "$(grep -cE '^manual_(auth|cleanup)_hook = /usr/local/sbin/wins-edge-acme-hook (present|cleanup)$' "$(conf_of "${R16}")")" = 2
refute "M16a saved file has no dns_cloudflare line" grep -q '^[[:space:]]*dns_cloudflare' "$(conf_of "${R16}")"
check "M16a exactly the dns_cloudflare_* lines were removed, every other line kept in order" \
  cmp -s <(grep -v '^dns_cloudflare_' "${written16}") "$(conf_of "${R16}")"
check "M16a the renewal file keeps its mode" test "$(perm_of "$(conf_of "${R16}")")" = 644
refute "M16a no strip temp file is left in the renewal directory" strip_temp_left "${R16}"
check "M16a the test renewal ran once, after the strip" test "$(grep -c '^renew ' "${WORK}/log/certbot.argv")" = 1
refute "M16a Cloudflare credential removed" grep -q '^CLOUDFLARE_API_TOKEN=' "${R16}/root/winsvpn-secrets.env"
refute "M16a fleet ADMIN_TOKEN removed" grep -q '^ADMIN_TOKEN=' "${R16}/root/winsvpn-secrets.env"
check "M16a legacy credentials file destroyed" test ! -e "${R16}/etc/letsencrypt/winsvpn-cloudflare.ini"
check "M16a pre-migration snapshot keeps the original dns-cloudflare file" grep -qx 'dns_cloudflare_propagation_seconds = 30' "${R16}/${STATE_REL}/pre-migration/winsvpn-node-origin.renewal.conf"
refute "M16a no value anywhere under the fake root" value_anywhere "${R16}"
refute "M16a output never prints a value" out_has_value

cat > "${FAKEBIN}/mv" <<'FAKE_MV'
#!/usr/bin/env bash
for arg in "$@"; do
  if [[ -n "${FAKE_MV_FAIL_SUBSTR:-}" && "${arg}" == *"${FAKE_MV_FAIL_SUBSTR}"* ]]; then
    exit 1
  fi
done
exec /bin/mv "$@"
FAKE_MV
chmod 755 "${FAKEBIN}/mv"
strip_failure_restores() {
  local mode="$1" root conf hook secrets ini hook_before conf_before secrets_before ini_before rc=0
  root="$(lineage_root "m16b-${mode}")"
  conf="$(conf_of "${root}")"
  hook="${root}/usr/local/sbin/wins-edge-acme-hook"
  secrets="${root}/root/winsvpn-secrets.env"
  ini="${root}/etc/letsencrypt/winsvpn-cloudflare.ini"
  printf '#!/usr/bin/env bash\n# operator-installed hook, must survive\nexit 0\n' > "${hook}"
  chmod 700 "${hook}"
  hook_before="$(sha256_of_file "${hook}")"
  conf_before="$(sha256_of_file "${conf}")"
  secrets_before="$(sha256_of_file "${secrets}")"
  ini_before="$(sha256_of_file "${ini}")"
  reset_log
  if [[ "${mode}" == readonly ]]; then
    FAKE_CERTBOT_LOCK_DIR=1 FAKE_CERTBOT_CONF="${conf}" FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${root}" --apply || rc=$?
    chmod u+w "${root}/etc/letsencrypt/renewal"
  else
    FAKE_MV_FAIL_SUBSTR=l41strip FAKE_CERTBOT_CONF="${conf}" FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${root}" --apply || rc=$?
  fi
  [[ "${rc}" == 4 \
      && "$(sha256_of_file "${hook}")" == "${hook_before}" \
      && "$(sha256_of_file "${conf}")" == "${conf_before}" \
      && "$(sha256_of_file "${secrets}")" == "${secrets_before}" \
      && "$(sha256_of_file "${ini}")" == "${ini_before}" ]] \
    && grep -q '^reconfigure ' "${WORK}/log/certbot.argv" \
    && ! grep -q '^renew ' "${WORK}/log/certbot.argv" \
    && grep -q '^CLOUDFLARE_API_TOKEN=' "${secrets}" \
    && grep -q '^ADMIN_TOKEN=' "${secrets}" \
    && grep -q 'keys certbot carried into the saved renewal configuration could not be removed' "${WORK}/migrate.out" \
    && grep -q 'lineage winsvpn-node-origin: restored' "${WORK}/migrate.out" \
    && ! strip_temp_left "${root}"
}
sha256_of_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum < "$1"; else shasum -a 256 < "$1"; fi | awk '{print $1}'; }
check "M16b a strip that cannot write its temp file (renewal dir read-only) exits 4 and restores hook and renewal file byte-exact" strip_failure_restores readonly
check "M16b a strip whose atomic replace fails exits 4 and restores hook and renewal file byte-exact" strip_failure_restores mvfail
rm -f "${FAKEBIN}/mv"

# shellcheck disable=SC2016  # the literal ${conf} text is what the mutation edits
sed 's/^      elif ! strip_cloudflare_renewal_params "${conf}"; then$/      elif false; then/' "${MIGRATE}" > "${WORK}/migrate.mut3"
check "MUT-3 mutation applied" grep -q '^      elif false; then$' "${WORK}/migrate.mut3"
MIGRATE_UNDER_TEST="${WORK}/migrate.mut3"
refute "MUT-3 a migration that skips the dns_cloudflare_* strip is caught by M16a" strip_apply_succeeds m16mut
check "MUT-3 the mutant exits 4, refused by the saved-config check" test "${M16_RC}" = 4
check "MUT-3 the mutant names the saved-config check" grep -q 'the saved renewal configuration does not name the hub hooks' "${WORK}/migrate.out"
unset MIGRATE_UNDER_TEST

# M11 (Round CF Turn 2, CF-4): several lineages are all-or-nothing. A failure
# on a later lineage restores every lineage changed earlier in the same apply
# and the shared hook, and reports each lineage's exact state.
R11="$(lineage_root m11)"
printf '[renewalparams]\nauthenticator = dns-cloudflare\ndns_cloudflare_credentials = /etc/letsencrypt/winsvpn-cloudflare.ini\n' \
  > "${R11}/etc/letsencrypt/renewal/a-first-origin.conf"
first_before="$(cksum < "${R11}/etc/letsencrypt/renewal/a-first-origin.conf")"
second_before="$(cksum < "$(conf_of "${R11}")")"
reset_log
rc=0; FAKE_CERTBOT_RENEWAL_DIR="${R11}/etc/letsencrypt/renewal" FAKE_CERTBOT_FAIL_CERT=winsvpn-node-origin FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${R11}" --apply || rc=$?
check "M11 a failure on the second lineage exits 4" test "${rc}" = 4
check "M11 the first lineage was converted before the failure" grep -q 'reconfigure .*--cert-name a-first-origin' "${WORK}/log/certbot.argv"
check "M11 the earlier lineage is restored too" test "$(cksum < "${R11}/etc/letsencrypt/renewal/a-first-origin.conf")" = "${first_before}"
check "M11 the failing lineage is left as it was" test "$(cksum < "$(conf_of "${R11}")")" = "${second_before}"
check "M11 the shared hook is removed (it did not exist before)" test ! -e "${R11}/usr/local/sbin/wins-edge-acme-hook"
check "M11 the report names each lineage's final state" grep -q 'lineage a-first-origin: restored' "${WORK}/migrate.out"
check "M11 the report names the failing lineage's final state" grep -q 'lineage winsvpn-node-origin: ' "${WORK}/migrate.out"
check "M11 credentials left in place" grep -q '^CLOUDFLARE_API_TOKEN=' "${R11}/root/winsvpn-secrets.env"

# M12 (Round CF Turn 3, CF-4): every backup copy is checked and verified by
# digest before the first change; a failed or corrupted copy aborts before
# anything (hook, renewal config, certbot) is touched.
cat > "${FAKEBIN}/cp" <<'FAKE_CP'
#!/usr/bin/env bash
for arg in "$@"; do
  if [[ -n "${FAKE_CP_FAIL_SUBSTR:-}" && "${arg}" == *"${FAKE_CP_FAIL_SUBSTR}"* ]]; then
    exit 1
  fi
done
/bin/cp "$@" || exit $?
if [[ -n "${FAKE_CP_CORRUPT_DEST_SUBSTR:-}" ]]; then
  dest="${!#}"
  if [[ "${dest}" == *"${FAKE_CP_CORRUPT_DEST_SUBSTR}"* && -f "${dest}" ]]; then
    printf 'X' >> "${dest}"
  fi
fi
FAKE_CP
chmod 755 "${FAKEBIN}/cp"
backup_failure_changes_nothing() {
  local mode="$1" root hook_before conf_before rc=0
  root="$(lineage_root "m12-${mode}")"
  printf '#!/usr/bin/env bash\n# operator-installed hook, must survive\nexit 0\n' > "${root}/usr/local/sbin/wins-edge-acme-hook"
  chmod 700 "${root}/usr/local/sbin/wins-edge-acme-hook"
  hook_before="$(cksum < "${root}/usr/local/sbin/wins-edge-acme-hook")"
  conf_before="$(cksum < "$(conf_of "${root}")")"
  reset_log
  if [[ "${mode}" == fail ]]; then
    FAKE_CP_FAIL_SUBSTR=wins-edge-acme-hook FAKE_CERTBOT_CONF="$(conf_of "${root}")" FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${root}" --apply || rc=$?
  else
    FAKE_CP_CORRUPT_DEST_SUBSTR=/.run. FAKE_CERTBOT_CONF="$(conf_of "${root}")" FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${root}" --apply || rc=$?
  fi
  [[ "${rc}" == 4 \
      && "$(cksum < "${root}/usr/local/sbin/wins-edge-acme-hook")" == "${hook_before}" \
      && "$(cksum < "$(conf_of "${root}")")" == "${conf_before}" \
      && ! -s "${WORK}/log/certbot.argv" \
      && -f "${root}/etc/letsencrypt/winsvpn-cloudflare.ini" ]] \
    && grep -q '^CLOUDFLARE_API_TOKEN=' "${root}/root/winsvpn-secrets.env"
}
check "M12 a failed backup copy of the hook aborts before any change" backup_failure_changes_nothing fail
check "M12 the abort names the failed backup" grep -q 'verified backup copy' "${WORK}/migrate.out"
check "M12 a backup copy whose digest differs aborts before any change" backup_failure_changes_nothing corrupt

# M13 (Round CF Turn 4, CF-4): the durable pre-migration snapshot is verified
# by SHA-256 against its source when written. A copy that succeeds but
# corrupts only the .pre destination aborts the apply before any change.
pre_corrupt_changes_nothing() {
  local root conf_before rc=0
  root="$(lineage_root m13)"
  conf_before="$(cksum < "$(conf_of "${root}")")"
  reset_log
  FAKE_CP_CORRUPT_DEST_SUBSTR=/.pre. FAKE_CERTBOT_CONF="$(conf_of "${root}")" FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${root}" --apply || rc=$?
  [[ "${rc}" == 4 \
      && "$(cksum < "$(conf_of "${root}")")" == "${conf_before}" \
      && ! -e "${root}/usr/local/sbin/wins-edge-acme-hook" \
      && ! -s "${WORK}/log/certbot.argv" \
      && ! -e "${root}/${STATE_REL}/pre-migration" \
      && ! -e "${root}/${STATE_REL}/migrated.env" \
      && -f "${root}/etc/letsencrypt/winsvpn-cloudflare.ini" ]] \
    && grep -q '^CLOUDFLARE_API_TOKEN=' "${root}/root/winsvpn-secrets.env"
}
check "M13 a corrupt write of the durable .pre snapshot aborts before any change" pre_corrupt_changes_nothing
check "M13 the abort names the snapshot" grep -q 'pre-migration snapshot of lineage winsvpn-node-origin' "${WORK}/migrate.out"
no_pre_staging_left() { compgen -G "${WORK}/root-m13/${STATE_REL}/.pre.*" >/dev/null; }
refute "M13 no staging snapshot directory is left behind" no_pre_staging_left

# M14 (Round CF Turn 4, CF-4): revert verifies the durable snapshot against the
# digests recorded at write time, and verifies the restore copy, before it
# changes anything; a mismatch refuses the revert (exit 6).
migrated_lineage_root() {
  local root rc=0
  root="$(lineage_root "$1")"
  reset_log
  FAKE_CERTBOT_CONF="$(conf_of "${root}")" FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${root}" --apply >/dev/null 2>&1 || rc=$?
  [[ "${rc}" == 0 ]] || { printf 'setup apply for %s exited %s\n' "$1" "${rc}" >&2; return 1; }
  printf '%s' "${root}"
}
revert_refused_nothing_changed() {
  local root="$1" conf_before secrets_before rc=0
  conf_before="$(cksum < "$(conf_of "${root}")")"
  secrets_before="$(cksum < "${root}/root/winsvpn-secrets.env")"
  run_migrate "${root}" --revert --reinject-from "${WORK}/reinject-m14.env" --before-revocation || rc=$?
  [[ "${rc}" == 6 \
      && "$(cksum < "$(conf_of "${root}")")" == "${conf_before}" \
      && "$(cksum < "${root}/root/winsvpn-secrets.env")" == "${secrets_before}" \
      && ! -e "${root}/etc/letsencrypt/winsvpn-cloudflare.ini" \
      && -f "${root}/${STATE_REL}/migrated.env" ]] \
    && ! compgen -G "${root}/etc/letsencrypt/renewal/.*l41restore*" >/dev/null
}
printf "CLOUDFLARE_API_TOKEN='%s'\n" "${FAKE_VALUE}" > "${WORK}/reinject-m14.env"
chmod 600 "${WORK}/reinject-m14.env"
R14="$(migrated_lineage_root m14)"
check "M14 setup: the apply recorded a snapshot digest manifest" test -s "${R14}/${STATE_REL}/pre-migration/renewal.sha256"
sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum < "$1"; else shasum -a 256 < "$1"; fi | awk '{print $1}'; }
m14_source_digest="$(sha256_of "$(conf_of "$(lineage_root m14ref)")")"
check "M14 the recorded digest is the source renewal file's SHA-256" grep -qx "${m14_source_digest}  winsvpn-node-origin.renewal.conf" "${R14}/${STATE_REL}/pre-migration/renewal.sha256"
printf 'X' >> "${R14}/${STATE_REL}/pre-migration/winsvpn-node-origin.renewal.conf"
check "M14 a tampered .pre snapshot makes revert refuse with nothing changed" revert_refused_nothing_changed "${R14}"
check "M14 the refusal names the digest mismatch" grep -q 'does not match its recorded SHA-256' "${WORK}/migrate.out"
R14b="$(migrated_lineage_root m14b)"
rm -f "${R14b}/${STATE_REL}/pre-migration/renewal.sha256"
check "M14b a snapshot with no recorded digests makes revert refuse" revert_refused_nothing_changed "${R14b}"
R14c="$(migrated_lineage_root m14c)"
reset_log
restore_copy_corrupted() { FAKE_CP_CORRUPT_DEST_SUBSTR=/etc/letsencrypt/renewal/ revert_refused_nothing_changed "$1"; }
check "M14c a restore copy corrupted in flight makes revert refuse" restore_copy_corrupted "${R14c}"
check "M14c the refusal names the staged restore" grep -q 'staged restore of lineage winsvpn-node-origin does not match' "${WORK}/migrate.out"
R14d="$(migrated_lineage_root m14d)"
printf 'X' >> "${R14d}/${STATE_REL}/pre-migration/winsvpn-node-origin.renewal.conf"
reset_log
rc=0; FAKE_CERTBOT_CONF="$(conf_of "${R14d}")" FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${R14d}" --apply || rc=$?
check "M14d a later apply refuses to build on a tampered snapshot" test "${rc}" = 4
check "M14d the refusal names the failed snapshot" grep -q 'failed verification; refusing to migrate on top of it' "${WORK}/migrate.out"
# M14e (Gemini L04 F-11): a re-inject file without a Cloudflare token, on a
# node whose snapshot restores an ACME lineage, is refused before the secrets
# file or any renewal config changes.
printf "ADMIN_TOKEN='%s'\n" "${FAKE_VALUE}" > "${WORK}/reinject-m14e.env"
chmod 600 "${WORK}/reinject-m14e.env"
R14e="$(migrated_lineage_root m14e)"
reset_log
no_token_revert_changes_nothing() {
  local root="$1" conf_before secrets_before rc=0
  conf_before="$(cksum < "$(conf_of "${root}")")"
  secrets_before="$(cksum < "${root}/root/winsvpn-secrets.env")"
  run_migrate "${root}" --revert --reinject-from "${WORK}/reinject-m14e.env" --before-revocation || rc=$?
  [[ "${rc}" == 6 \
      && "$(cksum < "$(conf_of "${root}")")" == "${conf_before}" \
      && "$(cksum < "${root}/root/winsvpn-secrets.env")" == "${secrets_before}" \
      && ! -e "${root}/etc/letsencrypt/winsvpn-cloudflare.ini" \
      && -f "${root}/${STATE_REL}/migrated.env" ]] \
    && ! compgen -G "${root}/etc/letsencrypt/renewal/.*l41restore*" >/dev/null \
    && ! compgen -G "${root}/root/winsvpn-secrets.env.*" >/dev/null
}
check "M14e a re-inject file with no Cloudflare token makes revert refuse with nothing changed" no_token_revert_changes_nothing "${R14e}"
check "M14e the refusal names the missing token" grep -q 'carries no usable Cloudflare token' "${WORK}/migrate.out"

# M15 (Round CF Turn 5, CF-4): the snapshot binds the COMPLETE lineage set.
# Deleting a recorded snapshot file together with its manifest line must not
# pass verification; revert fails when any lineage present at migration time
# is missing from the snapshot.
two_lineage_migrated_root() {
  local root rc=0
  root="$(lineage_root "$1")"
  printf '[renewalparams]\nauthenticator = dns-cloudflare\ndns_cloudflare_credentials = /etc/letsencrypt/winsvpn-cloudflare.ini\n' \
    > "${root}/etc/letsencrypt/renewal/a-first-origin.conf"
  reset_log
  FAKE_CERTBOT_RENEWAL_DIR="${root}/etc/letsencrypt/renewal" FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${root}" --apply >/dev/null 2>&1 || rc=$?
  [[ "${rc}" == 0 ]] || { printf 'setup apply for %s exited %s\n' "$1" "${rc}" >&2; return 1; }
  printf '%s' "${root}"
}
drop_snapshot_lineage() {
  local pre="$1/${STATE_REL}/pre-migration"
  rm -f -- "${pre}/a-first-origin.renewal.conf"
  grep -v '  a-first-origin\.renewal\.conf$' "${pre}/renewal.sha256" > "${pre}/renewal.sha256.new" || true
  mv -f -- "${pre}/renewal.sha256.new" "${pre}/renewal.sha256"
}
first_lineage_unrestored() {
  local root="$1" first_before rc=0
  first_before="$(cksum < "${root}/etc/letsencrypt/renewal/a-first-origin.conf")"
  revert_refused_nothing_changed "${root}" \
    && [[ "$(cksum < "${root}/etc/letsencrypt/renewal/a-first-origin.conf")" == "${first_before}" ]]
}
R15="$(two_lineage_migrated_root m15)"
check "M15 setup: the state record binds the lineage list" grep -qx 'L41_CLOUDFLARE_LINEAGES=a-first-origin,winsvpn-node-origin' "${R15}/${STATE_REL}/pre-migration/state.env"
check "M15 setup: the state record binds the lineage count" grep -qx 'L41_SNAPSHOT_COUNT=2' "${R15}/${STATE_REL}/pre-migration/state.env"
check "M15 setup: the state record binds the whole manifest by SHA-256" grep -qx "L41_SNAPSHOT_MANIFEST_SHA256=$(sha256_of "${R15}/${STATE_REL}/pre-migration/renewal.sha256")" "${R15}/${STATE_REL}/pre-migration/state.env"
check "M15 setup: the migration record repeats the manifest binding" grep -qx "L41_PRE_MANIFEST_SHA256=$(sha256_of "${R15}/${STATE_REL}/pre-migration/renewal.sha256")" "${R15}/${STATE_REL}/migrated.env"
drop_snapshot_lineage "${R15}"
check "M15 removing a snapshot file and its manifest line makes revert refuse with nothing changed" first_lineage_unrestored "${R15}"
check "M15 the refusal names the manifest digest mismatch" grep -q 'does not match the SHA-256 recorded for it' "${WORK}/migrate.out"
R15b="$(two_lineage_migrated_root m15b)"
drop_snapshot_lineage "${R15b}"
pre15b="${R15b}/${STATE_REL}/pre-migration"
new_digest="$(sha256_of "${pre15b}/renewal.sha256")"
sed -e "s/^L41_SNAPSHOT_MANIFEST_SHA256=.*/L41_SNAPSHOT_MANIFEST_SHA256=${new_digest}/" \
    -e 's/^L41_SNAPSHOT_COUNT=.*/L41_SNAPSHOT_COUNT=1/' \
    -e 's/^L41_CLOUDFLARE_LINEAGES=.*/L41_CLOUDFLARE_LINEAGES=winsvpn-node-origin/' \
    "${pre15b}/state.env" > "${pre15b}/state.env.new"
mv -f -- "${pre15b}/state.env.new" "${pre15b}/state.env"
check "M15b a snapshot whose own record was rewritten to match is still refused (migration record binding)" first_lineage_unrestored "${R15b}"
check "M15b the refusal names the migration record binding" grep -q 'recorded in the migration record' "${WORK}/migrate.out"
R15c="$(two_lineage_migrated_root m15c)"
sed -i.bak 's/^L41_SNAPSHOT_COUNT=.*/L41_SNAPSHOT_COUNT=1/' "${R15c}/${STATE_REL}/pre-migration/state.env" && rm -f "${R15c}/${STATE_REL}/pre-migration/state.env.bak"
check "M15c a recorded count that disagrees with the lineage list makes revert refuse" first_lineage_unrestored "${R15c}"
R15d="$(two_lineage_migrated_root m15d)"
rm -rf -- "${R15d}/${STATE_REL}/pre-migration"
check "M15d a missing snapshot directory makes revert refuse instead of restoring nothing" first_lineage_unrestored "${R15d}"
check "M15d the refusal names the missing snapshot" grep -q 'pre-migration snapshot .* is missing; refusing to revert' "${WORK}/migrate.out"
R15e="$(two_lineage_migrated_root m15e)"
check "M15e an intact two-lineage snapshot still reverts both lineages" run_migrate "${R15e}" --revert --reinject-from "${WORK}/reinject-m14.env" --before-revocation
check "M15e both lineages are restored" test "$(grep -c '^authenticator = dns-cloudflare$' "${R15e}/etc/letsencrypt/renewal/a-first-origin.conf" "$(conf_of "${R15e}")" | grep -c ':1$')" = 2
R15f="$(lineage_root m15f)"
rc=0; FAKE_CERTBOT_RECONFIGURE=fail FAKE_CERTBOT_CONF="$(conf_of "${R15f}")" FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${R15f}" --apply || rc=$?
printf '[renewalparams]\nauthenticator = dns-cloudflare\ndns_cloudflare_credentials = /etc/letsencrypt/winsvpn-cloudflare.ini\n' \
  > "${R15f}/etc/letsencrypt/renewal/a-later-origin.conf"
reset_log
rc=0; FAKE_CERTBOT_RENEWAL_DIR="${R15f}/etc/letsencrypt/renewal" FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${R15f}" --apply || rc=$?
check "M15f a re-apply refuses a dns-cloudflare lineage missing from the first snapshot" test "${rc}" = 4
check "M15f the refusal names that lineage" grep -q 'lineage a-later-origin renews with dns-cloudflare but is not in the recorded pre-migration snapshot' "${WORK}/migrate.out"
check "M15f nothing was reconfigured" test ! -s "${WORK}/log/certbot.argv"
rm -f "${FAKEBIN}/cp"

# M7 revert: explicit, allowlisted, time-limited
printf "CLOUDFLARE_API_TOKEN='%s'\nADMIN_TOKEN='%s'\n" "${FAKE_VALUE}" "${FAKE_ADMIN_VALUE}" > "${WORK}/reinject.env"
chmod 600 "${WORK}/reinject.env"
rc=0; run_migrate "${R}" --revert --reinject-from "${WORK}/reinject.env" || rc=$?
check "M7 revert without --before-revocation is refused" test "${rc}" = 6
rc=0; run_migrate "${R}" --revert --reinject-from "${WORK}/reinject.env" --before-revocation || rc=$?
check "M7 --revert inside the window exits 0" test "${rc}" = 0
check "M7 credential re-injected" grep -q '^CLOUDFLARE_API_TOKEN=' "${R}/root/winsvpn-secrets.env"
check "M7 renewal config restored" grep -q '^authenticator = dns-cloudflare$' "$(conf_of "${R}")"
check "M7 legacy credentials file restored" grep -q '^dns_cloudflare_api_token = ' "${R}/etc/letsencrypt/winsvpn-cloudflare.ini"
refute "M7 output never prints a value" out_has_value
printf 'SOMETHING_ELSE=1\n' > "${WORK}/reinject-bad.env"
chmod 600 "${WORK}/reinject-bad.env"
R2="$(new_root m7w)"
rc=0; FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${R2}" --apply || rc=$?
rc=0; run_migrate "${R2}" --revert --reinject-from "${WORK}/reinject-bad.env" --before-revocation || rc=$?
check "M7 revert refuses names outside the allowlist" test "${rc}" = 6
sed -i.bak 's/^L41_APPLIED_EPOCH=.*/L41_APPLIED_EPOCH=1000/' "${R2}/${STATE_REL}/migrated.env" && rm -f "${R2}/${STATE_REL}/migrated.env.bak"
rc=0; run_migrate "${R2}" --revert --reinject-from "${WORK}/reinject.env" --before-revocation || rc=$?
check "M7 revert after the recovery window is refused" test "${rc}" = 6
check "M7 window refusal names the broker path" grep -q 'recover through the hub broker' "${WORK}/migrate.out"

# M8 unsafe permissions are refused
R="$(new_root m8)"
chmod 640 "${R}/root/winsvpn-secrets.env"
rc=0; FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${R}" --apply || rc=$?
check "M8 a group-readable secrets file is refused" test "${rc}" = 1

# M10 migration refuses a non-HTTPS hub before sending the node token
R="$(new_root m10)"
sed -i.bak 's#^HUB_API_BASE=.*#HUB_API_BASE="http://hub.example.test"#' "${R}/root/node.env" && rm -f "${R}/root/node.env.bak"
reset_log
rc=0; FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${R}" --apply || rc=$?
check "M10 a plaintext hub URL is refused" test "${rc}" != 0
check "M10 no request was sent to it" test "$(calls)" = 0
check "M10 credentials left in place" grep -q '^CLOUDFLARE_API_TOKEN=' "${R}/root/winsvpn-secrets.env"
rc=0; FAKE_HUB_HOSTNAMES="${both_hosts}" run_migrate "${R}" --check || rc=$?
check "M10 --check sends nothing to a plaintext hub either" test "$(calls)" = 0

# M9 Core role
R="$(new_root m9)"
rm -f -- "${R}/root/node.env" "${R}/etc/letsencrypt/winsvpn-cloudflare.ini"
printf 'CORE_ID=north-core\nCORE_TOKEN=%s\nHUB_API_BASE=https://hub.example.test\nCORE_STEALTH_HOST=north-core.edge-zone.example\n' "${NODE_TOKEN_VALUE}" > "${R}/root/wins_core.env"
chmod 600 "${R}/root/wins_core.env"
printf 'dns_cloudflare_api_token = %s\n' "${FAKE_VALUE}" > "${R}/etc/letsencrypt/winsvpn-core-cloudflare.ini"
chmod 600 "${R}/etc/letsencrypt/winsvpn-core-cloudflare.ini"
reset_log
rc=0; FAKE_HUB_HOSTNAMES='["north-core.edge-zone.example"]' run_migrate "${R}" --apply || rc=$?
check "M9 Core --apply exits 0" test "${rc}" = 0
check "M9 Core probe used the Core endpoint" grep -qx 'https://hub.example.test/api/v1/core/north-core/edge/hostnames' "${WORK}/log/url.1"
check "M9 Core legacy credentials file destroyed" test ! -e "${R}/etc/letsencrypt/winsvpn-core-cloudflare.ini"
refute "M9 no value anywhere under the fake root" value_anywhere "${R}"

# ------------------------------------------------------- operator tooling ---
PREP="${WINS_EDGE_TOOLS_DIR:-${SERVER_DIR}/../tools}/wins_operator_prepare_subject.sh"
if [[ -f "${PREP}" ]]; then
  OP="${WORK}/operator"
  mkdir -p "${OP}"
  printf '%s\n' "${FAKE_ADMIN_VALUE}" > "${OP}/admin.token"
  printf '%s\n' 'FAKE-edge-admin-l41-0123456789abcdefghijk' > "${OP}/edge.token"
  printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeHostKeyForTestsOnly0123456789abcdef\n' > "${OP}/hostkeys.pub"
  chmod 600 "${OP}/admin.token" "${OP}/edge.token"
  prep() { bash "${PREP}" "$@" > "${WORK}/prep.out" 2>&1; }
  reset_log
  check "P1 data preparation succeeds" prep --role data --subject node-new --hub https://hub.example.test \
    --admin-token-file "${OP}/admin.token" --edge-admin-token-file "${OP}/edge.token" \
    --hostname Frankfurt.edge-zone.example --host-keys-file "${OP}/hostkeys.pub" --out "${OP}/node-new.fragment"
  check "P1 fragment carries the slug, grant and tunnel material" grep -q "^NODE_BOOTSTRAP_TOKEN='fake-grant-l41-" "${OP}/node-new.fragment"
  check "P1 fragment carries the tunnel connector" grep -q "^NODE_MGMT_TUNNEL_ID='12345678-1234-1234-1234-123456789abc'$" "${OP}/node-new.fragment"
  refute "P1 fragment carries no ADMIN_TOKEN or Cloudflare credential" grep -Eq '^(ADMIN_TOKEN|CLOUDFLARE_|EDGE_ADMIN)' "${OP}/node-new.fragment"
  refute "P1 fragment carries no admin value" grep -qF -- "${FAKE_ADMIN_VALUE}" "${OP}/node-new.fragment"
  perm="$(stat -c '%a' "${OP}/node-new.fragment" 2>/dev/null || stat -f '%Lp' "${OP}/node-new.fragment")"
  check "P1 fragment is owner-only" test "${perm}" = 600
  refute "P1 admin credential never in argv" any_argv_contains "${FAKE_ADMIN_VALUE}"
  check "P1 assignment used the edge admin header" grep -qF 'header = "x-edge-admin-token: ' "${WORK}/log/config.1"
  check "P1 tunnel minted with the admin header" grep -qx 'https://hub.example.test/admin/nodes/bootstrap-management-tunnel' "${WORK}/log/url.2"
  check "P1 grant requested with a bounded TTL" json_true '.ttl_seconds == 3600 and .subject_id == "node-new" and .role == "node"' "${WORK}/log/body.3"
  refute "P1 refuses to overwrite an existing fragment" prep --role data --subject node-new --hub https://hub.example.test \
    --admin-token-file "${OP}/admin.token" --host-keys-file "${OP}/hostkeys.pub" --out "${OP}/node-new.fragment"
  refute "P2 refuses an IP-literal hub" prep --role data --subject node-new --hub https://192.0.2.10 \
    --admin-token-file "${OP}/admin.token" --host-keys-file "${OP}/hostkeys.pub" --out "${OP}/p2.fragment"
  chmod 640 "${OP}/admin.token"
  refute "P3 refuses a group-readable admin token file" prep --role data --subject node-new --hub https://hub.example.test \
    --admin-token-file "${OP}/admin.token" --host-keys-file "${OP}/hostkeys.pub" --out "${OP}/p3.fragment"
  chmod 600 "${OP}/admin.token"
  reset_log
  refute "P4 a hub refusal fails" env FAKE_HUB_MODE=refuse bash "${PREP}" --role data --subject node-new --hub https://hub.example.test \
    --admin-token-file "${OP}/admin.token" --host-keys-file "${OP}/hostkeys.pub" --out "${OP}/p4.fragment"
  check "P4 no fragment written on refusal" test ! -e "${OP}/p4.fragment"
  reset_log
  check "P5 Core preparation succeeds" prep --role core --subject north-core --hub https://hub.example.test \
    --admin-token-file "${OP}/admin.token" --host-keys-file "${OP}/hostkeys.pub" --ssh-user ubuntu --out "${OP}/core.fragment"
  check "P5 Core tunnel uses the Core admin route" grep -qx 'https://hub.example.test/admin/core/bootstrap-management-tunnel' "${WORK}/log/url.1"
  check "P5 Core fragment uses CORE_* names" grep -q "^CORE_ID='north-core'$" "${OP}/core.fragment"
else
  fail "operator tool not found at ${PREP}"
fi

printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
((FAIL == 0))
