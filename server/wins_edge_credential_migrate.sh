#!/usr/bin/env bash
# wins_edge_credential_migrate.sh (L41, Round CF)
#
# Moves an EXISTING data plane or Core off node-held fleet credentials: the
# zone-wide Cloudflare API token (and any certbot Cloudflare credentials file)
# and the fleet-wide hub ADMIN_TOKEN. Afterwards the node authenticates only
# with its own hub token and the hub edge broker performs its DNS, Origin CA,
# ACME and redirect operations.
#
#   --check    READ-ONLY. Reports credential names present, legacy renewal
#              configuration, a read-only hub probe, and the locations scanned
#              for copies of the credential values. Exit 0 clean, 2 needs work.
#   --apply    1. verifies the live hub route and every hostname this node needs
#                 is assigned to it (nothing changes otherwise, exit 3);
#              2. records the first pre-migration state once, every file verified
#                 by SHA-256 and its digest recorded (never overwritten);
#              3. for each ACME lineage renewing with dns-cloudflare: installs the
#                 hub hook, runs certbot's staging reconfigure, checks the saved
#                 renewal configuration, and runs a test renewal (certbot renew
#                 --dry-run) through the hub. Every renewal file and an existing
#                 hook are first copied and verified by digest; a failed or
#                 mismatched copy aborts before anything is touched. All lineages
#                 succeed or none stays changed: on any failure it restores every
#                 renewal file and the hook changed in this apply, reports each
#                 lineage's exact final state, and removes nothing (exit 4);
#              4. lists copies of the credential values found outside the managed
#                 files for owner review; it NEVER rewrites them;
#              5. removes the managed credential lines and destroys the legacy
#                 credentials file, verifies the resulting local state, and marks
#                 the node migrated (exit 0, or 7 when copies were listed).
#   --revert --reinject-from FILE --before-revocation
#              TIME-LIMITED recovery path (default 72 h after --apply, override
#              with WINS_EDGE_REVERT_WINDOW_HOURS) for use BEFORE the old token is
#              revoked: re-injects allowlisted lines from a root-only FILE and
#              restores the recorded pre-migration renewal configuration, refusing
#              (exit 6, nothing changed) unless it matches its recorded digests and
#              holds every lineage recorded at migration time. It is
#              not an inverse of residual cleanup (none is done). After the token
#              is revoked, recovery goes through the hub broker instead.
#   --role data|core   default: detected from /root/node.env or /root/wins_core.env
#
# LIMITS, stated plainly: a path scan is evidence, not proof. It cannot see
# provider snapshots, the provider metadata service, off-host backups, journald
# contents that were already rotated, or storage remanence. Only revoking the
# old token makes those copies harmless.
#
# Never prints, logs or writes a credential VALUE: only names, paths, counts.
# Makes no Cloudflare API call; the only network requests go to the hub, and
# only to https://<fronted hub hostname> from the node's own env file (a
# plaintext, IP-literal, port or path URL is refused before any request), and,
# through certbot, to the ACME staging endpoint via the hub hook.
set -Eeuo pipefail
umask 077

ROOT_PREFIX="${WINS_MIGRATE_ROOT:-}"
CREDENTIAL_NAMES=(CLOUDFLARE_API_TOKEN CLOUDFLARE_ORIGIN_CA_API_TOKEN CLOUDFLARE_API_KEY CLOUDFLARE_ORIGIN_CA_KEY CF_API_TOKEN ADMIN_TOKEN)
REINJECT_ALLOWED=(CLOUDFLARE_API_TOKEN CLOUDFLARE_ORIGIN_CA_API_TOKEN CLOUDFLARE_ZONE_ID CLOUDFLARE_ACCOUNT_ID ADMIN_TOKEN)
SECRETS_FILE="${WINS_SECRETS_FILE:-${ROOT_PREFIX}/root/winsvpn-secrets.env}"
STATE_DIR="${WINS_MIGRATE_STATE_DIR:-${ROOT_PREFIX}/var/lib/winsvpn/edge-credential-migration}"
PRE_DIR="${STATE_DIR}/pre-migration"
RENEWAL_DIR="${WINS_MIGRATE_RENEWAL_DIR:-${ROOT_PREFIX}/etc/letsencrypt/renewal}"
WINS_EDGE_ACME_HOOK="${WINS_EDGE_ACME_HOOK:-${ROOT_PREFIX}/usr/local/sbin/wins-edge-acme-hook}"
# The hook path recorded in certbot's renewal config is the on-host path.
HOOK_RUNTIME_PATH="${WINS_EDGE_ACME_HOOK_RUNTIME_PATH:-/usr/local/sbin/wins-edge-acme-hook}"
REVERT_WINDOW_HOURS="${WINS_EDGE_REVERT_WINDOW_HOURS:-72}"

mode=""
role=""
reinject_from=""
before_revocation=0

log() { printf '[edge-migrate] %s\n' "$*"; }
warn() { printf '[edge-migrate][WARN] %s\n' "$*" >&2; }
die() { printf '[edge-migrate][ERR] %s\n' "$*" >&2; exit "${2:-1}"; }

usage() {
  sed -n '2,48p' "$0" | sed 's/^# \{0,1\}//'
}

while (($# > 0)); do
  case "$1" in
    --check|--apply|--revert)
      [[ -z "${mode}" ]] || die "Choose exactly one of --check, --apply, --revert."
      mode="${1#--}"
      ;;
    --role) shift; role="${1:-}" ;;
    --reinject-from) shift; reinject_from="${1:-}" ;;
    --before-revocation) before_revocation=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
  shift
done
[[ -n "${mode}" ]] || { usage >&2; exit 1; }
if [[ "${EUID:-$(id -u)}" -ne 0 && "${WINS_MIGRATE_ALLOW_NONROOT:-0}" != "1" ]]; then
  die "Run as root."
fi

file_uid() { stat -c '%u' -- "$1" 2>/dev/null || stat -f '%u' -- "$1"; }
file_mode() { stat -c '%a' -- "$1" 2>/dev/null || stat -f '%Lp' -- "$1"; }
file_size() { stat -c '%s' -- "$1" 2>/dev/null || stat -f '%z' -- "$1"; }
file_digest() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$1" 2>/dev/null | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -- "$1" 2>/dev/null | awk '{print $1}'
  else
    openssl dgst -sha256 -r -- "$1" 2>/dev/null | awk '{print $1}'
  fi
}
# Copy and prove the copy by digest. Every return code is checked by callers:
# do_apply runs this under `|| die`, where Bash does not stop on errors.
verified_copy() {
  local src="$1" dst="$2" want got
  cp -p -- "${src}" "${dst}" || return 1
  want="$(file_digest "${src}")"
  got="$(file_digest "${dst}")"
  [[ ${#want} -eq 64 && "${want}" == "${got}" ]]
}

require_private_file() {
  local path="$1" label="$2" uid perms
  [[ -f "${path}" && ! -L "${path}" ]] || die "${label} ${path} is missing or not a regular file."
  uid="$(file_uid "${path}")"
  perms="$(file_mode "${path}")"
  [[ "${uid}" == "$(id -u)" ]] || die "${label} ${path} must be owned by the invoking root user."
  (( (8#${perms} & 8#077) == 0 )) || die "${label} ${path} must not be accessible to group or other."
}

if [[ -z "${role}" ]]; then
  if [[ -f "${ROOT_PREFIX}/root/node.env" ]]; then
    role="data"
  elif [[ -f "${ROOT_PREFIX}/root/wins_core.env" ]]; then
    role="core"
  else
    die "Cannot detect the role; pass --role data or --role core."
  fi
fi
case "${role}" in
  data)
    ENV_FILE="${WINS_NODE_ENV_FILE:-${ROOT_PREFIX}/root/node.env}"
    RUNTIME_ENV_FILE="/root/node.env"
    LEGACY_INI="${WINS_EDGE_LEGACY_ACME_CREDENTIALS:-${ROOT_PREFIX}/etc/letsencrypt/winsvpn-cloudflare.ini}"
    ;;
  core)
    ENV_FILE="${WINS_CORE_ENV_FILE:-${ROOT_PREFIX}/root/wins_core.env}"
    RUNTIME_ENV_FILE="/root/wins_core.env"
    LEGACY_INI="${WINS_EDGE_LEGACY_ACME_CREDENTIALS:-${ROOT_PREFIX}/etc/letsencrypt/winsvpn-core-cloudflare.ini}"
    ;;
  *) die "--role must be data or core." ;;
esac
SCAN_ROOTS=(
  "${ROOT_PREFIX}/root" "${ROOT_PREFIX}/etc" "${ROOT_PREFIX}/var/lib/cloud" "${ROOT_PREFIX}/usr/local"
  "${ROOT_PREFIX}/opt" "${ROOT_PREFIX}/var/backups" "${ROOT_PREFIX}/var/lib/winsvpn" "${ROOT_PREFIX}/srv"
  "${ROOT_PREFIX}/home" "${ROOT_PREFIX}/var/tmp" "${ROOT_PREFIX}/tmp"
)

# --- identity from the node's own env file ---------------------------------
load_identity() {
  require_private_file "${ENV_FILE}" "Role env file"
  # shellcheck disable=SC1090
  . "${ENV_FILE}"
  HUB_BASE="${HUB_API_BASE:-}"
  HUB_BASE="${HUB_BASE%/}"
  # The node token goes only to https://<Cloudflare-fronted hub hostname>.
  local hub_host=""
  if [[ "${HUB_BASE}" =~ ^https://([A-Za-z0-9.-]+)$ ]]; then
    hub_host="${BASH_REMATCH[1]}"
  fi
  [[ "${hub_host}" == *.* && ! "${hub_host}" =~ ^[0-9.]+$ && "${hub_host}" != .* && "${hub_host}" != *. && "${hub_host}" != *..* ]] \
    || die "HUB_API_BASE in ${ENV_FILE} must be https://<fronted hub hostname>; refusing to send the ${role} token anywhere else. Nothing was changed." 3
  REQUIRED_HOSTS=()
  if [[ "${role}" == "data" ]]; then
    SUBJECT="${NODE_SLUG:-}"
    SUBJECT_TOKEN="${NODE_TOKEN:-}"
    TOKEN_HEADER="x-node-token"
    URL_SEGMENT="nodes"
    local host
    local -a aliases=()
    IFS=',' read -r -a aliases <<<"${REGIONAL_GATEWAY_ALIASES:-}"
    for host in "${STEALTH_HOST:-}" ${aliases[@]+"${aliases[@]}"}; do
      host="$(printf '%s' "${host}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
      [[ -n "${host}" && ! "${host}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || continue
      [[ " ${REQUIRED_HOSTS[*]-} " == *" ${host} "* ]] || REQUIRED_HOSTS+=("${host}")
    done
  else
    SUBJECT="${CORE_ID:-}"
    SUBJECT_TOKEN="${CORE_TOKEN:-}"
    TOKEN_HEADER="x-core-token"
    URL_SEGMENT="core"
    if [[ -n "${CORE_STEALTH_HOST:-}" ]]; then
      REQUIRED_HOSTS+=("$(printf '%s' "${CORE_STEALTH_HOST}" | tr '[:upper:]' '[:lower:]')")
    fi
  fi
  [[ "${SUBJECT}" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || die "The ${role} identity in ${ENV_FILE} is missing or invalid."
  [[ -n "${SUBJECT_TOKEN}" && "${SUBJECT_TOKEN}" != *[[:space:]\"]* ]] || die "The ${role} hub token in ${ENV_FILE} is missing; the node needs its own token before fleet credentials are removed."
}

# --- credential discovery, by name; values stay in memory only -------------
CREDENTIAL_VALUES=()
FOUND_NAMES=()
discover_credentials() {
  local name value
  CREDENTIAL_VALUES=()
  FOUND_NAMES=()
  if [[ -f "${SECRETS_FILE}" ]]; then
    require_private_file "${SECRETS_FILE}" "Secrets file"
    for name in "${CREDENTIAL_NAMES[@]}"; do
      if grep -Eq "^[[:space:]]*(export[[:space:]]+)?${name}=" "${SECRETS_FILE}"; then
        # The value crosses only a pipe: never argv, a log, or a file.
        value="$(set +u; # shellcheck disable=SC1090
          . "${SECRETS_FILE}" >/dev/null 2>&1; printf '%s' "${!name-}")"
        # An empty assignment (ADMIN_TOKEN="") is still removed, but not scanned for.
        FOUND_NAMES+=("${name}")
        if ((${#value} >= 16)); then
          CREDENTIAL_VALUES+=("${value}")
        fi
      fi
    done
  fi
  if [[ -f "${LEGACY_INI}" ]]; then
    value="$(sed -n 's/^[[:space:]]*dns_cloudflare_api_token[[:space:]]*=[[:space:]]*//p' "${LEGACY_INI}" | head -n 1)"
    if ((${#value} >= 16)) && [[ " ${CREDENTIAL_VALUES[*]-} " != *" ${value} "* ]]; then
      CREDENTIAL_VALUES+=("${value}")
    fi
  fi
}

# Renewal configs that still renew with the Cloudflare plugin.
cloudflare_lineages() {
  local conf
  [[ -d "${RENEWAL_DIR}" ]] || return 0
  for conf in "${RENEWAL_DIR}"/*.conf; do
    [[ -f "${conf}" ]] || continue
    if grep -Eq '^[[:space:]]*authenticator[[:space:]]*=[[:space:]]*dns-cloudflare[[:space:]]*$' "${conf}"; then
      basename "${conf}" .conf
    fi
  done
}

renewal_uses_hub_hooks() {
  local conf="$1"
  grep -Eq '^[[:space:]]*authenticator[[:space:]]*=[[:space:]]*manual[[:space:]]*$' "${conf}" \
    && grep -Fq "manual_auth_hook = ${HOOK_RUNTIME_PATH} present" "${conf}" \
    && grep -Fq "manual_cleanup_hook = ${HOOK_RUNTIME_PATH} cleanup" "${conf}" \
    && ! grep -Eq '^[[:space:]]*dns_cloudflare' "${conf}"
}

# Measured on the canary data plane on 2026-09-25 (certbot 2.9.0, Ubuntu
# 24.04): `certbot reconfigure --manual --preferred-challenges dns
# --manual-auth-hook "<hook> present" --manual-cleanup-hook "<hook> cleanup"`
# passed its staging test ("Successfully updated configuration") but carried
# the previous authenticator's parameters into the new renewal file. Its debug
# log at the write: "Var dns_cloudflare_propagation_seconds=30 (set by user).",
# "Var dns_cloudflare_credentials=/etc/letsencrypt/winsvpn-cloudflare.ini (set
# by user).", "Writing new config .../renewal/winsvpn-node-origin.conf.new."
# renewal_uses_hub_hooks then failed on the dns_cloudflare lines and --apply
# exited 4 with everything restored. So after a successful reconfigure exactly
# the dns_cloudflare_* keys are removed from that lineage's saved renewal file:
# an atomic replace in the same directory through a temp name that does not end
# in .conf (certbot reads only *.conf), mode and owner kept, and verified to
# leave no dns_cloudflare line. The saved-config check and the test renewal then
# run against the cleaned file. Any failure returns 1, and the caller restores
# every file from the verified pre-apply copies in its run directory.
strip_cloudflare_renewal_params() {
  local conf="$1" key='^[[:space:]]*dns_cloudflare_[A-Za-z0-9_]*[[:space:]]*=' dir tmp perms uid gid rc=0
  [[ -f "${conf}" && ! -L "${conf}" ]] || return 1
  grep -Eq "${key}" "${conf}" || rc=$?
  ((rc != 1)) || return 0
  ((rc == 0)) || return 1
  dir="$(dirname -- "${conf}")"
  perms="$(file_mode "${conf}")" && uid="$(file_uid "${conf}")" \
    && gid="$(stat -c '%g' -- "${conf}" 2>/dev/null || stat -f '%g' -- "${conf}")" || return 1
  [[ "${perms}" =~ ^[0-7]{3,4}$ && "${uid}" =~ ^[0-9]+$ && "${gid}" =~ ^[0-9]+$ ]] || return 1
  tmp="$(mktemp "${dir}/.$(basename -- "${conf}" .conf).l41strip.XXXXXX")" || return 1
  if ! { sed -E "/${key}/d" "${conf}" > "${tmp}" \
      && chown "${uid}:${gid}" "${tmp}" && chmod "${perms}" "${tmp}" \
      && mv -f -- "${tmp}" "${conf}"; }; then
    rm -f -- "${tmp}"
    return 1
  fi
  ! grep -Eq '^[[:space:]]*dns_cloudflare' "${conf}" \
    && [[ "$(file_mode "${conf}")" == "${perms}" && "$(file_uid "${conf}")" == "${uid}" ]] \
    && [[ "$(stat -c '%g' -- "${conf}" 2>/dev/null || stat -f '%g' -- "${conf}")" == "${gid}" ]]
}

# --- hub probe: live route plus every required assignment -------------------
hub_probe() {
  local response code host
  local -a missing=()
  response="$(mktemp)"
  code="$(printf 'header = "%s: %s"\n' "${TOKEN_HEADER}" "${SUBJECT_TOKEN}" \
    | curl --config - --proto =https --proto-redir =https -sS --connect-timeout 10 --max-time 30 -o "${response}" -w '%{http_code}' \
        "${HUB_BASE%/}/api/v1/${URL_SEGMENT}/${SUBJECT}/edge/hostnames" 2>/dev/null)" || code="000"
  if [[ ! "${code}" =~ ^2[0-9][0-9]$ ]] || ! jq -e '.ok == true and (.hostnames | type == "array")' "${response}" >/dev/null 2>&1; then
    rm -f -- "${response}"
    HUB_PROBE_DETAIL="the hub edge broker did not answer for ${role} ${SUBJECT} (HTTP ${code})"
    return 1
  fi
  for host in ${REQUIRED_HOSTS[@]+"${REQUIRED_HOSTS[@]}"}; do
    jq -e --arg host "${host}" '.hostnames | index($host) != null' "${response}" >/dev/null 2>&1 || missing+=("${host}")
  done
  rm -f -- "${response}"
  if ((${#missing[@]} > 0)); then
    HUB_PROBE_DETAIL="the hub has not assigned ${missing[*]} to ${role} ${SUBJECT}; the operator preassigns them first"
    return 1
  fi
  HUB_PROBE_DETAIL="hub edge broker answers for ${role} ${SUBJECT} with all ${#REQUIRED_HOSTS[@]} required hostname(s) assigned"
}

# --- residual scan by VALUE (evidence only; never rewrites) ----------------
RESIDUAL_PATHS=()
scan_residual() {
  local root
  local -a roots=()
  RESIDUAL_PATHS=()
  ((${#CREDENTIAL_VALUES[@]} > 0)) || return 0
  for root in "${SCAN_ROOTS[@]}"; do
    [[ -d "${root}" ]] && roots+=("${root}")
  done
  ((${#roots[@]} > 0)) || return 0
  mapfile -t RESIDUAL_PATHS < <(
    grep -rlsF -f <(printf '%s\n' "${CREDENTIAL_VALUES[@]}") -- "${roots[@]}" 2>/dev/null | sort -u || true
  )
}

stray_paths() {
  local path
  for path in ${RESIDUAL_PATHS[@]+"${RESIDUAL_PATHS[@]}"}; do
    [[ "${path}" == "${SECRETS_FILE}" || "${path}" == "${LEGACY_INI}" ]] || printf '%s\n' "${path}"
  done
}

journal_matches() {
  command -v journalctl >/dev/null 2>&1 || { printf '0'; return 0; }
  ((${#CREDENTIAL_VALUES[@]} > 0)) || { printf '0'; return 0; }
  journalctl --no-pager -o cat 2>/dev/null | grep -cF -f <(printf '%s\n' "${CREDENTIAL_VALUES[@]}") || true
}

destroy_file() {
  local path="$1" size
  [[ -e "${path}" || -L "${path}" ]] || return 0
  if [[ -f "${path}" && ! -L "${path}" ]]; then
    if command -v shred >/dev/null 2>&1; then
      shred -f -z -n 1 -- "${path}"
    else
      size="$(file_size "${path}")"
      head -c "${size}" /dev/zero > "${path}"
    fi
  fi
  rm -f -- "${path}"
}

write_hook() {
  local hook_tmp
  install -d -m 755 "$(dirname -- "${WINS_EDGE_ACME_HOOK}")"
  hook_tmp="$(mktemp "${WINS_EDGE_ACME_HOOK}.XXXXXX")"
  {
    printf '#!/usr/bin/env bash\n'
    printf '# Generated by wins_edge_credential_migrate.sh (L41). Do not edit.\n'
    printf 'WINS_EDGE_KIND=%q\n' "$([[ "${role}" == data ]] && echo node || echo core)"
    printf 'WINS_EDGE_ENV_FILE=%q\n' "${RUNTIME_ENV_FILE}"
    cat <<'WINS_EDGE_ACME_HOOK_BODY'
set -Eeuo pipefail
umask 077
# certbot runs this as --manual-auth-hook "<path> present" and
# --manual-cleanup-hook "<path> cleanup". It publishes or removes the DNS-01
# TXT record through the hub edge broker, authenticated with this host's own
# hub token. No Cloudflare credential exists on this host.
mode="${1:-}"
case "${mode}" in
  present|cleanup) ;;
  *) echo "usage: wins-edge-acme-hook present|cleanup" >&2; exit 2 ;;
esac
[[ -f "${WINS_EDGE_ENV_FILE}" && ! -L "${WINS_EDGE_ENV_FILE}" ]] || {
  echo "edge ACME hook: ${WINS_EDGE_ENV_FILE} is missing or not a regular file" >&2
  exit 1
}
# shellcheck disable=SC1090
. "${WINS_EDGE_ENV_FILE}"
case "${WINS_EDGE_KIND}" in
  node) subject="${NODE_SLUG:-}"; token="${NODE_TOKEN:-}"; header="x-node-token"; segment="nodes" ;;
  core) subject="${CORE_ID:-}"; token="${CORE_TOKEN:-}"; header="x-core-token"; segment="core" ;;
  *) echo "edge ACME hook: unknown subject kind" >&2; exit 2 ;;
esac
base="${HUB_API_BASE:-}"
base="${base%/}"
host="$(printf '%s' "${CERTBOT_DOMAIN:-}" | tr '[:upper:]' '[:lower:]')"
validation="${CERTBOT_VALIDATION:-}"
[[ "${subject}" =~ ^[a-z0-9][a-z0-9-]{0,62}$ && -n "${token}" && "${token}" != *[[:space:]\"]* ]] || {
  echo "edge ACME hook: the hub identity in ${WINS_EDGE_ENV_FILE} is incomplete" >&2
  exit 1
}
# The subject token goes only to https://<Cloudflare-fronted hub hostname>:
# no plaintext scheme, no IP literal, no port, no path. Anything else is refused
# before a request is made.
hub_host=""
if [[ "${base}" =~ ^https://([A-Za-z0-9.-]+)$ ]]; then
  hub_host="${BASH_REMATCH[1]}"
fi
[[ "${hub_host}" == *.* && ! "${hub_host}" =~ ^[0-9.]+$ && "${hub_host}" != .* && "${hub_host}" != *. && "${hub_host}" != *..* ]] || {
  echo "edge ACME hook: HUB_API_BASE must be https://<fronted hub hostname>; refusing to send the token anywhere else" >&2
  exit 1
}
[[ "${host}" =~ ^[a-z0-9.-]{1,253}$ && "${validation}" =~ ^[A-Za-z0-9_-]{20,128}$ ]] || {
  echo "edge ACME hook: certbot supplied an unexpected domain or validation value" >&2
  exit 1
}
body="$(mktemp)"
response="$(mktemp)"
trap 'rm -f -- "${body}" "${response}"' EXIT
jq -n --arg action "${mode}" --arg hostname "${host}" --arg validation "${validation}" \
  '{action:$action,hostname:$hostname,validation:$validation}' > "${body}"
# The token travels in a curl config read from stdin, never in argv.
code="$(printf 'header = "%s: %s"\n' "${header}" "${token}" \
  | curl --config - --proto =https --proto-redir =https -sS --connect-timeout 10 --max-time 60 -o "${response}" -w '%{http_code}' \
      -X POST -H 'Content-Type: application/json' --data-binary "@${body}" \
      "${base%/}/api/v1/${segment}/${subject}/edge/acme-challenge" 2>/dev/null)" || code="000"
if [[ ! "${code}" =~ ^2[0-9][0-9]$ ]] || ! jq -e '.ok == true' "${response}" >/dev/null 2>&1; then
  echo "edge ACME hook: hub refused ${mode} for ${host} (HTTP ${code}): $(jq -r '.detail // empty' "${response}" 2>/dev/null | head -c 200)" >&2
  exit 1
fi
if [[ "${mode}" == "present" ]]; then
  sleep "${WINS_EDGE_ACME_PROPAGATION_SECONDS:-30}"
fi
WINS_EDGE_ACME_HOOK_BODY
  } > "${hook_tmp}"
  chmod 700 "${hook_tmp}"
  bash -n "${hook_tmp}" || { rm -f -- "${hook_tmp}"; return 1; }
  mv -f -- "${hook_tmp}" "${WINS_EDGE_ACME_HOOK}"
}

credential_pattern() {
  printf '^[[:space:]]*(export[[:space:]]+)?(%s)=' "$(IFS='|'; printf '%s' "${CREDENTIAL_NAMES[*]}")"
}

rewrite_secrets_without_credentials() {
  local tmp
  tmp="$(mktemp "${SECRETS_FILE}.XXXXXX")"
  chmod 600 "${tmp}"
  grep -Ev "$(credential_pattern)" "${SECRETS_FILE}" > "${tmp}" || true
  mv -f -- "${tmp}" "${SECRETS_FILE}"
}

# Record the FIRST pre-migration state once; later runs never overwrite it.
# The digest manifest of the durable snapshot: "<sha256>  <lineage>.renewal.conf".
PRE_DIGESTS="renewal.sha256"
# Read one KEY=value line from a record file (first match only).
record_value() { sed -n "s/^$2=\\(.*\\)\$/\\1/p" "$1" 2>/dev/null | head -n 1; }
# Verify the durable pre-migration snapshot as a COMPLETE set. state.env
# records, at write time, the lineage list, the lineage count and the SHA-256
# of the whole manifest; migrated.env repeats the manifest digest and lineage
# list when the apply completes. Verification requires: the manifest digest
# equals every recorded copy of it, the manifest names exactly the recorded
# lineages (same count, none missing, none extra, no duplicate), every
# snapshot file matches its recorded digest, and no unlisted snapshot file
# exists. Removing a file together with its manifest line therefore fails.
verify_pre_snapshot() {
  local manifest="${PRE_DIR}/${PRE_DIGESTS}" state="${PRE_DIR}/state.env" want name got path line
  local recorded_lineages recorded_count recorded_digest manifest_digest bound_digest bound_lineages lineage lines=0
  local -A listed=()
  local -a expected=()
  [[ -f "${manifest}" && ! -L "${manifest}" ]] || { warn "pre-migration snapshot has no digest manifest"; return 1; }
  [[ -f "${state}" && ! -L "${state}" ]] || { warn "pre-migration snapshot has no state record"; return 1; }
  recorded_lineages="$(record_value "${state}" L41_CLOUDFLARE_LINEAGES)"
  recorded_count="$(record_value "${state}" L41_SNAPSHOT_COUNT)"
  recorded_digest="$(record_value "${state}" L41_SNAPSHOT_MANIFEST_SHA256)"
  [[ "${recorded_count}" =~ ^[0-9]+$ && "${recorded_digest}" =~ ^[0-9a-f]{64}$ ]] \
    || { warn "pre-migration state record does not bind the snapshot (lineage count and manifest digest missing)"; return 1; }
  manifest_digest="$(file_digest "${manifest}")"
  [[ "${manifest_digest}" == "${recorded_digest}" ]] \
    || { warn "pre-migration digest manifest does not match the SHA-256 recorded for it when it was written"; return 1; }
  if [[ -f "${STATE_DIR}/migrated.env" ]]; then
    bound_digest="$(record_value "${STATE_DIR}/migrated.env" L41_PRE_MANIFEST_SHA256)"
    bound_lineages="$(record_value "${STATE_DIR}/migrated.env" L41_PRE_LINEAGES)"
    if [[ -n "${bound_digest}" || "${PRE_REQUIRE_BINDING:-0}" == "1" ]]; then
      [[ "${bound_digest}" == "${manifest_digest}" && "${bound_lineages}" == "${recorded_lineages}" ]] \
        || { warn "pre-migration snapshot does not match the manifest digest and lineage list recorded in the migration record"; return 1; }
    fi
  elif [[ "${PRE_REQUIRE_BINDING:-0}" == "1" ]]; then
    warn "no migration record binds the pre-migration snapshot"
    return 1
  fi
  if [[ -n "${recorded_lineages}" ]]; then
    IFS=, read -r -a expected <<< "${recorded_lineages}"
  fi
  ((${#expected[@]} == recorded_count)) || { warn "pre-migration state record lists ${#expected[@]} lineage(s) but records a count of ${recorded_count}"; return 1; }
  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ -n "${line}" ]] || continue
    [[ "${line}" =~ ^([0-9a-f]{64})\ \ ([A-Za-z0-9._-]+\.renewal\.conf)$ ]] || { warn "pre-migration digest manifest has a malformed line"; return 1; }
    want="${BASH_REMATCH[1]}"
    name="${BASH_REMATCH[2]}"
    [[ -z "${listed[${name}]-}" ]] || { warn "pre-migration digest manifest lists ${name} twice"; return 1; }
    path="${PRE_DIR}/${name}"
    [[ -f "${path}" && ! -L "${path}" ]] || { warn "pre-migration snapshot ${name} is missing"; return 1; }
    got="$(file_digest "${path}")"
    [[ "${got}" == "${want}" ]] || { warn "pre-migration snapshot ${name} does not match its recorded SHA-256"; return 1; }
    listed["${name}"]=1
    lines=$((lines + 1))
  done < "${manifest}"
  ((lines == recorded_count)) || { warn "pre-migration digest manifest lists ${lines} snapshot(s); ${recorded_count} were recorded"; return 1; }
  for lineage in "${expected[@]}"; do
    [[ "${lineage}" =~ ^[A-Za-z0-9._-]+$ ]] || { warn "pre-migration state record has a malformed lineage name"; return 1; }
    [[ -n "${listed[${lineage}.renewal.conf]-}" ]] \
      || { warn "lineage ${lineage}, present at migration time, is missing from the pre-migration snapshot"; return 1; }
  done
  for path in "${PRE_DIR}"/*.renewal.conf; do
    [[ -e "${path}" ]] || continue
    [[ -n "${listed[$(basename "${path}")]-}" ]] || { warn "pre-migration snapshot $(basename "${path}") has no recorded digest"; return 1; }
  done
  return 0
}

record_pre_migration_state() {
  local lineage recorded current
  local -a lineages=()
  if [[ -d "${PRE_DIR}" ]]; then
    verify_pre_snapshot || die "The recorded pre-migration snapshot in ${PRE_DIR} failed verification; refusing to migrate on top of it. Nothing was changed." 4
    # Every lineage this apply would move must be in the first record, or a
    # revert could not restore it.
    recorded=",$(record_value "${PRE_DIR}/state.env" L41_CLOUDFLARE_LINEAGES),"
    while IFS= read -r current; do
      [[ -n "${current}" ]] || continue
      [[ "${recorded}" == *",${current},"* ]] \
        || die "ACME lineage ${current} renews with dns-cloudflare but is not in the recorded pre-migration snapshot; refusing to migrate it. Nothing was changed." 4
    done < <(cloudflare_lineages)
    log "pre-migration state already recorded and verified in ${PRE_DIR}; keeping the first record"
    return 0
  fi
  install -d -m 700 "${STATE_DIR}"
  mapfile -t lineages < <(cloudflare_lineages)
  local staging
  staging="$(mktemp -d "${STATE_DIR}/.pre.XXXXXX")"
  {
    printf 'L41_RECORDED_AT=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'L41_ROLE=%s\n' "${role}"
    printf 'L41_CREDENTIAL_NAMES=%s\n' "${FOUND_NAMES[*]-}"
    printf 'L41_LEGACY_INI_PRESENT=%s\n' "$([[ -e "${LEGACY_INI}" ]] && echo 1 || echo 0)"
    printf 'L41_HOOK_PRESENT=%s\n' "$([[ -e "${WINS_EDGE_ACME_HOOK}" ]] && echo 1 || echo 0)"
    printf 'L41_CLOUDFLARE_LINEAGES=%s\n' "$(IFS=,; printf '%s' "${lineages[*]-}")"
  } > "${staging}/state.env"
  # Each snapshot copy is proved by SHA-256 against its source at write time,
  # and the source digest is recorded; revert verifies it again before use.
  : > "${staging}/${PRE_DIGESTS}"
  for lineage in "${lineages[@]}"; do
    if ! verified_copy "${RENEWAL_DIR}/${lineage}.conf" "${staging}/${lineage}.renewal.conf"; then
      rm -rf -- "${staging}"
      die "The pre-migration snapshot of lineage ${lineage} could not be written as a verified copy; nothing was changed." 4
    fi
    printf '%s  %s\n' "$(file_digest "${RENEWAL_DIR}/${lineage}.conf")" "${lineage}.renewal.conf" >> "${staging}/${PRE_DIGESTS}"
  done
  # Bind the complete set: the lineage count and a digest over the whole
  # manifest, so that removing a snapshot file and its line is detected.
  {
    printf 'L41_SNAPSHOT_COUNT=%s\n' "${#lineages[@]}"
    printf 'L41_SNAPSHOT_MANIFEST_SHA256=%s\n' "$(file_digest "${staging}/${PRE_DIGESTS}")"
  } >> "${staging}/state.env"
  chmod -R go-rwx "${staging}"
  mv -- "${staging}" "${PRE_DIR}"
  verify_pre_snapshot || die "The recorded pre-migration snapshot in ${PRE_DIR} failed verification after it was written; nothing was changed." 4
  log "recorded and verified the pre-migration state in ${PRE_DIR} (${#lineages[@]} lineage(s))"
}

# Move EVERY dns-cloudflare lineage to the hub hooks, all or nothing. Each
# lineage gets the staging reconfigure, a saved-config check and a test
# renewal. If any step fails for any lineage, every renewal file changed in
# this apply and the shared hook are put back, and the exact final state of
# each lineage and of the hook is reported.
LINEAGE_REPORT=()
migrate_all_lineages() {
  local lineage run_dir conf reason="" failed="" hook_existed=0 state hook_state all_restored=1 backup_failed=""
  local -a lineages=()
  mapfile -t lineages < <(cloudflare_lineages)
  ((${#lineages[@]} > 0)) || return 0
  run_dir="$(mktemp -d "${STATE_DIR}/.run.XXXXXX")" || { warn "could not create the backup directory; nothing was changed"; return 1; }
  # Every backup copy is made and verified by digest BEFORE the first change.
  # Any failure aborts here, with the hook and every renewal file untouched.
  for lineage in "${lineages[@]}"; do
    if ! verified_copy "${RENEWAL_DIR}/${lineage}.conf" "${run_dir}/${lineage}.conf"; then
      backup_failed="${RENEWAL_DIR}/${lineage}.conf"
      break
    fi
  done
  if [[ -z "${backup_failed}" && -e "${WINS_EDGE_ACME_HOOK}" ]]; then
    hook_existed=1
    verified_copy "${WINS_EDGE_ACME_HOOK}" "${run_dir}/hook" || backup_failed="${WINS_EDGE_ACME_HOOK}"
  fi
  if [[ -n "${backup_failed}" ]]; then
    rm -rf -- "${run_dir}"
    warn "could not make a verified backup copy of ${backup_failed}; aborting before any change (hook, renewal configuration and credentials untouched)"
    LINEAGE_REPORT=("nothing changed: backup of ${backup_failed} failed or did not match by digest")
    printf '  %s\n' "${LINEAGE_REPORT[@]}" >&2
    return 1
  fi
  if ! write_hook; then
    reason="the generated hook failed a syntax check"
    failed="(hook)"
  else
    for lineage in "${lineages[@]}"; do
      conf="${RENEWAL_DIR}/${lineage}.conf"
      if ! certbot reconfigure --non-interactive --cert-name "${lineage}" \
          --manual --preferred-challenges dns \
          --manual-auth-hook "${HOOK_RUNTIME_PATH} present" \
          --manual-cleanup-hook "${HOOK_RUNTIME_PATH} cleanup"; then
        reason="certbot reconfigure (staging test) failed"
      elif ! strip_cloudflare_renewal_params "${conf}"; then
        reason="the dns_cloudflare_* keys certbot carried into the saved renewal configuration could not be removed"
      elif ! renewal_uses_hub_hooks "${conf}"; then
        reason="the saved renewal configuration does not name the hub hooks"
      elif ! certbot renew --non-interactive --cert-name "${lineage}" --dry-run; then
        reason="the test renewal through the hub hook failed"
      fi
      if [[ -n "${reason}" ]]; then
        failed="${lineage}"
        break
      fi
      log "ACME lineage ${lineage}: hook installed, staging reconfigure passed, saved config checked, test renewal passed"
    done
  fi
  if [[ -z "${reason}" ]]; then
    rm -rf -- "${run_dir}"
    return 0
  fi
  warn "ACME lineage ${failed}: ${reason}; restoring every file this apply changed"
  LINEAGE_REPORT=()
  for lineage in "${lineages[@]}"; do
    conf="${RENEWAL_DIR}/${lineage}.conf"
    if [[ "$(file_digest "${conf}")" == "$(file_digest "${run_dir}/${lineage}.conf")" ]]; then
      state="unchanged"
    elif verified_copy "${run_dir}/${lineage}.conf" "${conf}"; then
      state="restored"
    else
      state="NOT RESTORED (verified pre-apply copy kept at ${run_dir}/${lineage}.conf)"
      all_restored=0
    fi
    LINEAGE_REPORT+=("lineage ${lineage}: ${state}")
  done
  if ((hook_existed == 1)); then
    if verified_copy "${run_dir}/hook" "${WINS_EDGE_ACME_HOOK}"; then hook_state="restored to its previous content"; else hook_state="NOT RESTORED (verified copy kept at ${run_dir}/hook)"; all_restored=0; fi
  elif rm -f -- "${WINS_EDGE_ACME_HOOK}" && [[ ! -e "${WINS_EDGE_ACME_HOOK}" ]]; then
    hook_state="removed (it did not exist before)"
  else
    hook_state="still present at ${WINS_EDGE_ACME_HOOK}"
    all_restored=0
  fi
  LINEAGE_REPORT+=("hook: ${hook_state}")
  warn "residual state after the failed apply (no credential was removed):"
  printf '  %s\n' "${LINEAGE_REPORT[@]}" >&2
  ((all_restored == 0)) || rm -rf -- "${run_dir}"
  return 1
}

report_state() {
  local lineage
  log "role=${role} subject=${SUBJECT:-unknown}"
  if ((${#FOUND_NAMES[@]} > 0)); then
    log "fleet credential names present in ${SECRETS_FILE}: ${FOUND_NAMES[*]}"
  else
    log "no fleet credential names in ${SECRETS_FILE}"
  fi
  if [[ -e "${LEGACY_INI}" ]]; then log "legacy certbot credentials file present: ${LEGACY_INI}"; else log "legacy certbot credentials file absent"; fi
  while IFS= read -r lineage; do
    [[ -n "${lineage}" ]] && log "ACME lineage ${lineage} renews with dns-cloudflare (needs the credential)"
  done < <(cloudflare_lineages)
}

do_check() {
  local root
  load_identity
  discover_credentials
  report_state
  if hub_probe; then log "read-only hub probe: ${HUB_PROBE_DETAIL}"; else warn "read-only hub probe: ${HUB_PROBE_DETAIL}"; fi
  scan_residual
  log "locations scanned for copies of the credential values:"
  for root in "${SCAN_ROOTS[@]}"; do [[ -d "${root}" ]] && printf '  %s\n' "${root}"; done
  log "copies found: ${#RESIDUAL_PATHS[@]}"
  ((${#RESIDUAL_PATHS[@]} == 0)) || printf '  %s\n' "${RESIDUAL_PATHS[@]}"
  log "LIMITS: this scan cannot see provider snapshots, the provider metadata service, off-host backups, rotated journals or storage remanence; only revoking the old token makes those harmless."
  if ((${#FOUND_NAMES[@]} > 0 || ${#RESIDUAL_PATHS[@]} > 0)) || [[ -e "${LEGACY_INI}" ]] || [[ -n "$(cloudflare_lineages)" ]]; then
    exit 2
  fi
  log "clean: this ${role} holds no fleet credential"
}

do_apply() {
  local lineage journal_count path
  local -a stray=()
  load_identity
  discover_credentials
  report_state
  hub_probe || die "Refusing to migrate: ${HUB_PROBE_DETAIL}. Nothing was changed." 3
  log "hub probe: ${HUB_PROBE_DETAIL}"
  record_pre_migration_state

  migrate_all_lineages || die "The ACME lineages could not all be moved to the hub; every change of this apply was undone as reported above, and no credential was removed." 4

  # Stray copies are listed for the owner and NEVER rewritten.
  scan_residual
  mapfile -t stray < <(stray_paths)
  if ((${#stray[@]} > 0)); then
    warn "copies of the credential values exist outside the managed files; they are NOT modified (owner review):"
    printf '  %s\n' "${stray[@]}" >&2
  fi

  if ((${#FOUND_NAMES[@]} > 0)); then
    rewrite_secrets_without_credentials
    log "removed ${FOUND_NAMES[*]} from ${SECRETS_FILE}"
  fi
  if [[ -e "${LEGACY_INI}" || -L "${LEGACY_INI}" ]]; then
    destroy_file "${LEGACY_INI}"
    log "destroyed ${LEGACY_INI}"
  fi

  # Verify the resulting local state.
  if [[ -f "${SECRETS_FILE}" ]] && grep -Eq "$(credential_pattern)" "${SECRETS_FILE}"; then
    die "Verification failed: ${SECRETS_FILE} still names a fleet credential." 5
  fi
  [[ ! -e "${LEGACY_INI}" ]] || die "Verification failed: ${LEGACY_INI} still exists." 5
  [[ -z "$(cloudflare_lineages)" ]] || die "Verification failed: a lineage still renews with dns-cloudflare." 5
  scan_residual
  for path in ${RESIDUAL_PATHS[@]+"${RESIDUAL_PATHS[@]}"}; do
    [[ "${path}" != "${SECRETS_FILE}" && "${path}" != "${LEGACY_INI}" ]] || die "Verification failed: ${path} still holds a credential value." 5
  done
  journal_count="$(journal_matches)"
  ((journal_count == 0)) || warn "the systemd journal holds ${journal_count} line(s) containing a credential value; journald cannot be edited in place."

  if [[ ! -f "${STATE_DIR}/migrated.env" ]]; then
    {
      printf 'L41_APPLIED_AT=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf 'L41_APPLIED_EPOCH=%s\n' "$(date -u +%s)"
      printf 'L41_ROLE=%s\n' "${role}"
      printf 'L41_STRAY_COPIES=%s\n' "${#stray[@]}"
      # A second, independent copy of the snapshot binding.
      printf 'L41_PRE_MANIFEST_SHA256=%s\n' "$(file_digest "${PRE_DIR}/${PRE_DIGESTS}")"
      printf 'L41_PRE_LINEAGES=%s\n' "$(record_value "${PRE_DIR}/state.env" L41_CLOUDFLARE_LINEAGES)"
    } > "${STATE_DIR}/migrated.env"
    chmod 600 "${STATE_DIR}/migrated.env"
  else
    printf 'L41_REAPPLIED_AT=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${STATE_DIR}/migrated.env"
  fi
  log "migrated: no managed fleet credential remains in ${SECRETS_FILE}; legacy credentials file absent; renewals use the hub"
  log "LIMITS: provider snapshots, the metadata service, off-host backups, journals and storage remanence are not covered; roll the app-zone token and the admin token once every node is accounted for."
  if ((${#stray[@]} > 0)); then
    exit 7
  fi
}

do_revert() {
  local name line tmp value applied_epoch now lineage
  local -a names=()
  ((before_revocation == 1)) || die "--revert is a recovery path for use BEFORE the old token is revoked; confirm with --before-revocation. After revocation, recover through the hub broker." 6
  [[ -n "${reinject_from}" ]] || die "--revert needs --reinject-from FILE (the node keeps no copy of any credential)." 6
  [[ -f "${STATE_DIR}/migrated.env" ]] || die "No migration record in ${STATE_DIR}; nothing to revert." 6
  applied_epoch="$(sed -n 's/^L41_APPLIED_EPOCH=\([0-9]*\)$/\1/p' "${STATE_DIR}/migrated.env" | head -n 1)"
  now="$(date -u +%s)"
  [[ "${applied_epoch}" =~ ^[0-9]+$ ]] || die "The migration record has no apply time." 6
  [[ "${REVERT_WINDOW_HOURS}" =~ ^[0-9]+$ ]] || die "WINS_EDGE_REVERT_WINDOW_HOURS must be a whole number of hours." 6
  (( now - applied_epoch <= REVERT_WINDOW_HOURS * 3600 )) \
    || die "The ${REVERT_WINDOW_HOURS} h recovery window after migration has passed; recover through the hub broker instead." 6
  require_private_file "${reinject_from}" "Re-inject file"
  [[ -f "${SECRETS_FILE}" ]] || die "Secrets file ${SECRETS_FILE} is missing." 6
  require_private_file "${SECRETS_FILE}" "Secrets file"
  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ -z "${line}" || "${line}" == \#* ]] && continue
    name="${line%%=*}"
    name="${name#export }"
    [[ " ${REINJECT_ALLOWED[*]} " == *" ${name} "* ]] || die "Re-inject file may only contain ${REINJECT_ALLOWED[*]}." 6
    names+=("${name}")
  done < "${reinject_from}"
  ((${#names[@]} > 0)) || die "Re-inject file contains no credential lines." 6
  # The snapshot is verified against its recorded digests, and every restore
  # copy is staged and verified, BEFORE anything is changed. Any mismatch
  # refuses the revert with the node left exactly as it was.
  local -a staged=() targets=()
  # Every apply records the snapshot before any change, so a missing snapshot
  # or one that no longer binds every lineage recorded at migration time is
  # refused rather than treated as nothing to restore.
  [[ -d "${PRE_DIR}" ]] || die "The pre-migration snapshot ${PRE_DIR} is missing; refusing to revert. Nothing was changed." 6
  PRE_REQUIRE_BINDING=1 verify_pre_snapshot || die "The pre-migration snapshot in ${PRE_DIR} does not match its recorded SHA-256 digests and lineage set; refusing to revert. Nothing was changed." 6
  for line in "${PRE_DIR}"/*.renewal.conf; do
    [[ -f "${line}" ]] || continue
    lineage="$(basename "${line}" .renewal.conf)"
    tmp="$(mktemp "${RENEWAL_DIR}/.${lineage}.conf.l41restore.XXXXXX")" || die "Could not stage the restore of lineage ${lineage}; nothing was changed." 6
    staged+=("${tmp}")
    if ! verified_copy "${line}" "${tmp}"; then
      rm -f -- "${staged[@]}"
      die "The staged restore of lineage ${lineage} does not match the verified snapshot; refusing to revert. Nothing was changed." 6
    fi
    targets+=("${RENEWAL_DIR}/${lineage}.conf")
  done
  tmp="$(mktemp "${SECRETS_FILE}.XXXXXX")"
  chmod 600 "${tmp}"
  grep -Ev "^[[:space:]]*(export[[:space:]]+)?($(IFS='|'; printf '%s' "${names[*]}"))=" "${SECRETS_FILE}" > "${tmp}" || true
  grep -Ev '^[[:space:]]*(#|$)' "${reinject_from}" >> "${tmp}"
  # Gemini L04 F-11: a restored ACME lineage needs a Cloudflare token. Check the
  # staged secrets file now, so a refusal still leaves the node unchanged.
  if ((${#staged[@]} > 0)); then
    value="$(set +u; # shellcheck disable=SC1090
      . "${tmp}" >/dev/null 2>&1; printf '%s' "${CLOUDFLARE_API_TOKEN:-${CLOUDFLARE_ORIGIN_CA_API_TOKEN:-}}")"
    if ((${#value} < 16)); then
      value=""
      rm -f -- "${tmp}" "${staged[@]}"
      die "The re-injected file carries no usable Cloudflare token for the restored ACME lineage(s). Nothing was changed." 6
    fi
    value=""
  fi
  mv -f -- "${tmp}" "${SECRETS_FILE}"
  log "re-injected ${names[*]} into ${SECRETS_FILE}"
  local restored=0 i
  for i in "${!staged[@]}"; do
    mv -f -- "${staged[i]}" "${targets[i]}" || die "Could not put the verified restore of ${targets[i]} in place." 6
    lineage="$(basename "${targets[i]}" .conf)"
    [[ "$(file_digest "${targets[i]}")" == "$(file_digest "${PRE_DIR}/${lineage}.renewal.conf")" ]] \
      || die "The restored ${targets[i]} does not match the verified snapshot." 6
    restored=$((restored + 1))
  done
  if ((restored > 0)); then
    value="$(set +u; # shellcheck disable=SC1090
      . "${SECRETS_FILE}" >/dev/null 2>&1; printf '%s' "${CLOUDFLARE_API_TOKEN:-${CLOUDFLARE_ORIGIN_CA_API_TOKEN:-}}")"
    ((${#value} >= 16)) || die "The re-injected file carries no usable Cloudflare token for the restored ACME lineage(s)." 6
    install -d -m 700 "$(dirname -- "${LEGACY_INI}")"
    printf 'dns_cloudflare_api_token = %s\n' "${value}" > "${LEGACY_INI}"
    chmod 600 "${LEGACY_INI}"
    value=""
    log "restored ${restored} pre-migration renewal configuration(s) and ${LEGACY_INI}"
  fi
  mv -f -- "${STATE_DIR}/migrated.env" "${STATE_DIR}/reverted-$(date -u +%Y%m%dT%H%M%SZ).env"
  for name in "${names[@]}"; do
    grep -Eq "^[[:space:]]*(export[[:space:]]+)?${name}=" "${SECRETS_FILE}" || die "Revert verification failed for ${name}." 6
  done
  log "revert verified. This recovery works only until the old token is revoked; a patched installer refuses to run while these credentials are present."
}

case "${mode}" in
  check) do_check ;;
  apply) do_apply ;;
  revert) do_revert ;;
esac
