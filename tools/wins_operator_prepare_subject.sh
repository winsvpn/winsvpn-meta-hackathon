#!/usr/bin/env bash
# wins_operator_prepare_subject.sh (L41, Round CF)
#
# OPERATOR-SIDE ONLY. Performs every admin-only hub step a fresh data plane or
# Core needs, so neither the fleet ADMIN_TOKEN nor the edge admin credential
# ever reaches the node:
#   1. preassign custom stealth hostnames to the subject (EDGE_ADMIN_TOKEN);
#   2. mint the subject's management tunnel (ADMIN_TOKEN), pinning the host
#      keys the operator already verified for the target;
#   3. mint a short-lived, subject-bound bootstrap grant (ADMIN_TOKEN);
#   4. sign and post the subject's t1 signer ticket (ADMIN_TOKEN), when the
#      ticket inputs are given (design v17 3.8): --endpoint-ip, --t1-key,
#      --action, --go-live and --tier. --go-live and --tier are required with
#      no default: the tool refuses to mint a ticket without them, so
#      automatic go-live is always an explicit choice recorded in the signed
#      ticket. The ticket payload is canonical JSON and the epoch comes from
#      the signer itself, through the hub's ticket route.
# It writes a new owner-only fragment with NODE_SLUG / NODE_BOOTSTRAP_TOKEN /
# NODE_MGMT_TUNNEL_TOKEN / NODE_MGMT_SSH_HOST / NODE_MGMT_TUNNEL_ID (Core: the
# CORE_* equivalents), which the preseed tool appends to that one target's
# role secrets file. The installer consumes the grant, installs the connector,
# and removes that material from the node's secrets file.
#
# Usage:
#   wins_operator_prepare_subject.sh --role data|core --subject ID --hub https://HUB_HOSTNAME \
#       --admin-token-file FILE --out FILE [--host-keys-file FILE] [--ssh-user USER] \
#       [--edge-admin-token-file FILE --hostname NAME ...] [--grant-ttl SECONDS] \
#       [--no-tunnel] [--no-grant] \
#       [--endpoint-ip IPV4 --t1-key FILE --action new|reset|endpoint|rekey|suspend|unsuspend \
#        --go-live auto|manual --tier free|premium [--gateway-id ID]]
#
# Credentials are read from owner-only files and sent in a curl config on
# stdin, never on a command line. Nothing secret is printed.
set -Eeuo pipefail
umask 077

role="" subject="" hub="" admin_file="" edge_admin_file="" host_keys_file="" out="" ssh_user="ubuntu"
grant_ttl=3600 do_tunnel=1 do_grant=1
hostnames=()
endpoint_ip="" t1_key="" ticket_action="" go_live="" tier="" gateway_id="" gateway_id_given=0

die() { printf '[prepare-subject][ERR] %s\n' "$*" >&2; exit "${2:-1}"; }
log() { printf '[prepare-subject] %s\n' "$*"; }

while (($# > 0)); do
  case "$1" in
    --role) shift; role="${1:-}" ;;
    --subject) shift; subject="${1:-}" ;;
    --hub) shift; hub="${1:-}" ;;
    --admin-token-file) shift; admin_file="${1:-}" ;;
    --edge-admin-token-file) shift; edge_admin_file="${1:-}" ;;
    --host-keys-file) shift; host_keys_file="${1:-}" ;;
    --hostname) shift; hostnames+=("${1:-}") ;;
    --ssh-user) shift; ssh_user="${1:-}" ;;
    --grant-ttl) shift; grant_ttl="${1:-}" ;;
    --out) shift; out="${1:-}" ;;
    --no-tunnel) do_tunnel=0 ;;
    --no-grant) do_grant=0 ;;
    --endpoint-ip) shift; endpoint_ip="${1:-}" ;;
    --t1-key) shift; t1_key="${1:-}" ;;
    --action) shift; ticket_action="${1:-}" ;;
    --go-live) shift; go_live="${1:-}" ;;
    --tier) shift; tier="${1:-}" ;;
    --gateway-id) shift; gateway_id="${1:-}"; gateway_id_given=1 ;;
    -h|--help) sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
  shift
done

file_mode() { stat -c '%a' -- "$1" 2>/dev/null || stat -f '%Lp' -- "$1"; }
read_secret_file() {
  local path="$1" label="$2" value
  [[ -f "${path}" && ! -L "${path}" ]] || die "${label} file is missing or not a regular file."
  (( (8#$(file_mode "${path}") & 8#077) == 0 )) || die "${label} file must not be accessible to group or other."
  value="$(head -n 1 -- "${path}" | tr -d '\r\n')"
  [[ ${#value} -ge 32 && "${value}" != *[[:space:]\"]* ]] || die "${label} is missing or malformed."
  printf '%s' "${value}"
}

case "${role}" in
  data) kind="node"; prefix="NODE"; id_name="NODE_SLUG" ;;
  core) kind="core"; prefix="CORE"; id_name="CORE_ID" ;;
  *) die "--role must be data or core." ;;
esac
[[ "${subject}" =~ ^[a-z0-9][a-z0-9-]{1,39}$ ]] || die "--subject must be 2-40 lowercase letters, digits or hyphens."
[[ "${hub}" =~ ^https://([A-Za-z0-9.-]+)$ ]] || die "--hub must be https://HOSTNAME (no path, no port)."
[[ ! "${BASH_REMATCH[1]}" =~ ^[0-9.]+$ ]] || die "--hub must be the fronted hub hostname, never an IP address."
[[ -n "${out}" ]] || die "--out is required."
[[ ! -e "${out}" && ! -L "${out}" ]] || die "--out already exists; refusing to overwrite a secrets fragment."
if ! { [[ "${grant_ttl}" =~ ^[0-9]+$ ]] && ((grant_ttl >= 60 && grant_ttl <= 3600)); }; then
  die "--grant-ttl must be 60 to 3600 seconds."
fi
[[ "${ssh_user}" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "--ssh-user is invalid."
((do_tunnel == 0)) || [[ -n "${host_keys_file}" ]] || die "--host-keys-file (the target's verified SSH host public keys) is required to mint its tunnel."
((${#hostnames[@]} == 0)) || [[ -n "${edge_admin_file}" ]] || die "--hostname needs --edge-admin-token-file."

# A t1 signer ticket (3.8) is minted only when every ticket input is given.
# --go-live and --tier have no default: without them the tool refuses to mint,
# so automatic go-live is always an explicit choice in the signed bytes.
ticket_inputs=0
for value in "${endpoint_ip}" "${t1_key}" "${ticket_action}" "${go_live}" "${tier}" "${gateway_id}"; do
  [[ -n "${value}" ]] && ticket_inputs=1
done
((gateway_id_given)) && ticket_inputs=1
if ((ticket_inputs)); then
  [[ "${role}" == data ]] || die "A signer ticket is for a data-plane node (--role data)."
  # A fresh node is <slug>-gw1 (2.3). An adopted or retained node keeps the
  # gateway id recorded for it (2.6), so the recorded value is passed here.
  # The charset is the canary's (1 to 128 of A-Za-z0-9._:-), which also rules
  # out edge whitespace and control characters.
  # An explicit --gateway-id is never replaced by the default, even when empty.
  ((gateway_id_given)) || gateway_id="${subject}-gw1"
  [[ "${gateway_id}" =~ ^[A-Za-z0-9._:-]{1,128}$ ]] \
    || die "--gateway-id must be 1 to 128 characters of A-Z a-z 0-9 . _ : -"
  [[ -n "${go_live}" ]] || die "--go-live is required to mint a signer ticket (no default)."
  [[ -n "${tier}" ]] || die "--tier is required to mint a signer ticket (no default)."
  [[ -n "${endpoint_ip}" && -n "${t1_key}" && -n "${ticket_action}" ]] \
    || die "A signer ticket needs --endpoint-ip, --t1-key and --action together."
  [[ "${go_live}" == "auto" || "${go_live}" == "manual" ]] || die "--go-live must be auto or manual."
  [[ "${tier}" == "free" || "${tier}" == "premium" ]] || die "--tier must be free or premium."
  case "${ticket_action}" in
    new|reset|endpoint|rekey|suspend|unsuspend) ;;
    *) die "--action must be new, reset, endpoint, rekey, suspend or unsuspend." ;;
  esac
  ip_ok=1
  # The whole value first: `read` drops a trailing empty field and stops at
  # the first newline, so "a.b.c.d." and "a.b.c.d<newline>x" would split
  # into four valid octets.
  [[ "${endpoint_ip}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || ip_ok=0
  IFS='.' read -r -a octets <<< "${endpoint_ip}"
  (( ${#octets[@]} == 4 )) || ip_ok=0
  for octet in "${octets[@]}"; do
    # Compared only once the pattern matched: bash arithmetic evaluates any
    # other text, command substitutions in array subscripts included.
    if [[ "${octet}" =~ ^(0|[1-9][0-9]{0,2})$ ]]; then
      (( 10#${octet} <= 255 )) || ip_ok=0
    else
      ip_ok=0
    fi
  done
  (( ip_ok )) || die "--endpoint-ip must be an IPv4 address."
  [[ -f "${t1_key}" && ! -L "${t1_key}" ]] || die "--t1-key is missing or not a regular file."
  (( (8#$(file_mode "${t1_key}") & 8#077) == 0 )) || die "--t1-key must not be accessible to group or other."
  [[ -n "${host_keys_file}" ]] || die "--host-keys-file is required to mint a signer ticket."
fi

admin_token=""
if ((do_tunnel == 1 || do_grant == 1 || ticket_inputs == 1)); then
  admin_token="$(read_secret_file "${admin_file}" "Admin token")"
fi

# hub_post PATH HEADER TOKEN BODY_FILE RESPONSE_FILE -> HTTP code on stdout
hub_post() {
  printf 'header = "%s: %s"\n' "$2" "$3" \
    | curl --config - --proto =https --proto-redir =https -sS --connect-timeout 10 --max-time 90 -o "$5" -w '%{http_code}' \
        -X POST -H 'Content-Type: application/json' --data-binary "@$4" "${hub%/}$1" 2>/dev/null || printf '000'
}

# hub_get PATH HEADER TOKEN RESPONSE_FILE -> HTTP code on stdout
hub_get() {
  printf 'header = "%s: %s"\n' "$2" "$3" \
    | curl --config - --proto =https --proto-redir =https -sS --connect-timeout 10 --max-time 90 -o "$4" -w '%{http_code}' \
        -H 'Accept: application/json' "${hub%/}$1" 2>/dev/null || printf '000'
}

work="$(mktemp -d)"
trap 'rm -rf -- "${work}"' EXIT
declare -A material=()
material["${id_name}"]="${subject}"

if ((${#hostnames[@]} > 0)); then
  edge_token="$(read_secret_file "${edge_admin_file}" "Edge admin token")"
  printf '%s\n' "${hostnames[@]}" | jq -R . | jq -s --arg kind "${kind}" --arg subject "${subject}" \
    '{subject_kind:$kind,subject_id:$subject,hostnames:.,action:"bind"}' > "${work}/bind.json"
  code="$(hub_post /admin/edge/hostname-bindings x-edge-admin-token "${edge_token}" "${work}/bind.json" "${work}/bind.out")"
  edge_token=""
  if ! { [[ "${code}" =~ ^2 ]] && jq -e '.ok == true' "${work}/bind.out" >/dev/null 2>&1; }; then
    die "The hub refused the hostname assignment (HTTP ${code}): $(jq -r '.detail // empty' "${work}/bind.out" 2>/dev/null | head -c 200)"
  fi
  for host in "${hostnames[@]}"; do
    host="$(printf '%s' "${host}" | tr '[:upper:]' '[:lower:]')"
    jq -e --arg host "${host}" '.hostnames | index($host) != null' "${work}/bind.out" >/dev/null \
      || die "The hub did not list ${host} for ${kind} ${subject} after assignment."
  done
  log "Assigned ${#hostnames[@]} hostname(s) to ${kind} ${subject}"
fi

if ((do_tunnel == 1)); then
  [[ -f "${host_keys_file}" && ! -L "${host_keys_file}" ]] || die "--host-keys-file is missing."
  awk '$1 ~ /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521))$/ && $2 ~ /^[A-Za-z0-9+\/=]+$/ {print $1 " " $2}' "${host_keys_file}" \
    | jq -Rsc 'split("\n") | map(select(length > 0)) | unique' > "${work}/keys.json"
  jq -e 'type == "array" and length > 0 and length <= 8' "${work}/keys.json" >/dev/null || die "No usable SSH host public keys in --host-keys-file."
  if [[ "${kind}" == "node" ]]; then
    jq -n --arg slug "${subject}" --slurpfile keys "${work}/keys.json" '{node_slug:$slug,ssh_host_keys:$keys[0]}' > "${work}/tunnel.json"
    tunnel_path=/admin/nodes/bootstrap-management-tunnel
  else
    jq -n --arg id "${subject}" --arg user "${ssh_user}" --slurpfile keys "${work}/keys.json" \
      '{core_id:$id,ssh_user:$user,ssh_host_keys:$keys[0]}' > "${work}/tunnel.json"
    tunnel_path=/admin/core/bootstrap-management-tunnel
  fi
  code="$(hub_post "${tunnel_path}" x-admin-token "${admin_token}" "${work}/tunnel.json" "${work}/tunnel.out")"
  if ! { [[ "${code}" =~ ^2 ]] && jq -e '.ok == true and .management_mode == "cloudflare_tunnel"' "${work}/tunnel.out" >/dev/null 2>&1; }; then
    die "The hub refused to mint the management tunnel (HTTP ${code}): $(jq -r '.detail // empty' "${work}/tunnel.out" 2>/dev/null | head -c 200)"
  fi
  material["${prefix}_MGMT_TUNNEL_TOKEN"]="$(jq -r '.tunnel_token // empty' "${work}/tunnel.out")"
  material["${prefix}_MGMT_SSH_HOST"]="$(jq -r '.ssh_host // empty' "${work}/tunnel.out")"
  material["${prefix}_MGMT_TUNNEL_ID"]="$(jq -r '.tunnel_id // empty' "${work}/tunnel.out")"
  [[ ${#material[${prefix}_MGMT_TUNNEL_TOKEN]} -ge 80 && "${material[${prefix}_MGMT_TUNNEL_TOKEN]}" =~ ^[A-Za-z0-9+/=_.-]+$ ]] \
    || die "The hub returned an invalid tunnel connector token."
  [[ "${material[${prefix}_MGMT_SSH_HOST]}" =~ ^[a-z0-9.-]{4,253}$ ]] || die "The hub returned an invalid management hostname."
  [[ "${material[${prefix}_MGMT_TUNNEL_ID]}" =~ ^[A-Fa-f0-9-]{36}$ ]] || die "The hub returned an invalid tunnel ID."
  log "Minted the management tunnel for ${kind} ${subject}"
fi

if ((do_grant == 1)); then
  jq -n --arg role "${kind}" --arg subject "${subject}" --argjson ttl "${grant_ttl}" \
    '{role:$role,subject_id:$subject,ttl_seconds:$ttl}' > "${work}/grant.json"
  code="$(hub_post /admin/bootstrap-grant x-admin-token "${admin_token}" "${work}/grant.json" "${work}/grant.out")"
  material["${prefix}_BOOTSTRAP_TOKEN"]="$(jq -r '.bootstrap_token // empty' "${work}/grant.out" 2>/dev/null || true)"
  [[ "${code}" =~ ^2 && "${material[${prefix}_BOOTSTRAP_TOKEN]}" =~ ^[A-Za-z0-9_-]{32,}$ ]] \
    || die "The hub refused to mint a bootstrap grant (HTTP ${code}): $(jq -r '.detail // empty' "${work}/grant.out" 2>/dev/null | head -c 200)"
  log "Minted a ${grant_ttl}-second bootstrap grant bound to ${kind} ${subject}"
fi

if ((ticket_inputs)); then
  # The ticket epoch is the signer's, and the app can neither read nor write it
  # (3.8): the hub's ticket route answers it from the signer's status.
  code="$(hub_get /admin/nodes/winn3/signer-ticket x-admin-token "${admin_token}" "${work}/epoch.out")"
  if ! { [[ "${code}" =~ ^2 ]] && jq -e '.ok == true and (.epoch | type == "number")' "${work}/epoch.out" >/dev/null 2>&1; }; then
    die "The hub did not report the signer's current ticket epoch (HTTP ${code})."
  fi
  epoch="$(jq -r '.epoch' "${work}/epoch.out")"
  [[ "${epoch}" =~ ^[1-9][0-9]*$ ]] || die "The hub reported an invalid ticket epoch."
  # The host key the ticket pins: exactly one ssh-ed25519 line in the
  # operator-verified host-keys file. The fingerprint is the ssh-keygen form
  # SHA256:<43 base64>, no padding.
  ed25519_blob="$(awk '$1 == "ssh-ed25519" && $2 ~ /^[A-Za-z0-9+\/=]+$/ {print $2}' "${host_keys_file}")"
  [[ "$(printf '%s\n' "${ed25519_blob}" | grep -c .)" -eq 1 ]] \
    || die "A signer ticket needs exactly one ssh-ed25519 host key in --host-keys-file."
  host_key_fp="$(printf '%s' "${ed25519_blob}" \
    | openssl base64 -d -A 2>/dev/null | openssl dgst -sha256 -binary 2>/dev/null \
    | openssl base64 -A 2>/dev/null | tr -d '=')"
  [[ "${host_key_fp}" =~ ^[A-Za-z0-9+/]{43}$ ]] || die "Could not compute the host key fingerprint."
  nonce="$(openssl rand -hex 32)"
  # 7 days is the signer's and the hub's maximum, measured on THEIR clocks, so
  # minting at exactly 7 days is refused whenever this Mac's clock leads.
  not_after=$(( $(date +%s) + 604800 - 600 ))
  # Canonical JSON (sorted keys, compact separators): the signer refuses any
  # other serialization of the ticket payload (H1 contract ruling). jq's
  # trailing newline is stripped: the signed bytes are exactly the canonical
  # form, nothing more.
  ticket_json="$(jq -ncS \
      --arg slug "${subject}" --arg action "${ticket_action}" --argjson epoch "${epoch}" \
      --arg endpoint_ip "${endpoint_ip}" --arg gateway_id "${gateway_id}" \
      --arg host_key_sha256 "SHA256:${host_key_fp}" --arg go_live "${go_live}" --arg tier "${tier}" \
      --arg nonce "${nonce}" --argjson not_after "${not_after}" \
      '{slug:$slug,action:$action,epoch:$epoch,endpoint_ip:$endpoint_ip,gateway_id:$gateway_id,host_key_sha256:$host_key_sha256,go_live:$go_live,tier:$tier,nonce:$nonce,not_after:$not_after}')"
  printf '%s' "${ticket_json}" > "${work}/ticket.json"
  ticket_payload_b64="$(openssl base64 -A -in "${work}/ticket.json")"
  # Domain-separated t1 signature over DOMAIN || 0x00 || payload (3.8).
  # Ed25519 is one-shot: openssl needs a seekable -in, so the message is a
  # file, never a pipe.
  { printf 'winsvpn-winn3-signer-ticket/v1'; printf '\0'; cat "${work}/ticket.json"; } \
    > "${work}/ticket.msg"
  ticket_sig="$(openssl pkeyutl -sign -rawin -inkey "${t1_key}" -in "${work}/ticket.msg" 2>/dev/null \
    | openssl base64 -A)"
  [[ "${ticket_sig}" =~ ^[A-Za-z0-9+/]{86}==$ ]] || die "Could not sign the signer ticket."
  jq -ncS --arg slug "${subject}" --arg payload "${ticket_payload_b64}" --arg sig "${ticket_sig}" \
    '{slug:$slug,ticket:{payload:$payload,sig:$sig}}' > "${work}/post-ticket.json"
  code="$(hub_post /admin/nodes/winn3/signer-ticket x-admin-token "${admin_token}" "${work}/post-ticket.json" "${work}/post-ticket.out")"
  if ! { [[ "${code}" =~ ^2 ]] && jq -e '.ok == true and .stored == true' "${work}/post-ticket.out" >/dev/null 2>&1; }; then
    die "The hub refused the signer ticket (HTTP ${code}): $(jq -r '.detail // empty' "${work}/post-ticket.out" 2>/dev/null | head -c 200)"
  fi
  log "Minted and posted the t1 ${ticket_action} ticket for ${kind} ${subject} (epoch ${epoch}, expires in 7 days)"
fi
admin_token=""

tmp="$(mktemp "${out}.XXXXXX")"
{
  printf '# One-time material for %s %s (L41). Append to that target'"'"'s role secrets only.\n' "${kind}" "${subject}"
  for name in "${id_name}" "${prefix}_BOOTSTRAP_TOKEN" "${prefix}_MGMT_TUNNEL_TOKEN" "${prefix}_MGMT_SSH_HOST" "${prefix}_MGMT_TUNNEL_ID"; do
    [[ -n "${material[${name}]:-}" ]] || continue
    printf "%s='%s'\n" "${name}" "${material[${name}]}"
  done
} > "${tmp}"
chmod 600 "${tmp}"
mv -f -- "${tmp}" "${out}"
log "Wrote ${out} (owner-only). It contains no ADMIN_TOKEN and no Cloudflare credential."
