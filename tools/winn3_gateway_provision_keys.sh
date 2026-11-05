#!/usr/bin/env bash
# Provision the two winn/3 gateway credentials onto a node, and bring the
# client's half back, without either secret ever touching a repository, a log,
# a command line, an environment variable, or a frame channel.
#
#   ./winn3_gateway_provision_keys.sh --generate <node> <local-out-dir>
#   ./winn3_gateway_provision_keys.sh --fingerprint <node> [<local-out-dir>]
#   ./winn3_gateway_provision_keys.sh --verify <node> <local-out-dir>
#   ./winn3_gateway_provision_keys.sh --generate-ech <node> <local-out-dir>
#   ./winn3_gateway_provision_keys.sh --generate-successor <node> <local-out-dir> [--dry-run]
#   ./winn3_gateway_provision_keys.sh --swap-successor     <node> <local-out-dir> [--dry-run]
#   ./winn3_gateway_provision_keys.sh --rollback-successor <node> <local-out-dir> [<stamp>] [--dry-run]
#   ./winn3_gateway_provision_keys.sh --successor-status   <node>
#
# ---------------------------------------------------------------------------
# WHY THIS EXISTS
# ---------------------------------------------------------------------------
#
# No script anywhere in this repository places a static key or an admission
# secret on a server. Every existing credential path either downloads a pinned
# public artifact, or checks that a secret a human already placed is present
# and refuses to invent one. That refusal is the right default and is preserved
# here: server/wins_winn3_gateway_install.sh still generates nothing. This is
# the missing other half -- the deliberate, auditable act of putting the two
# secrets where that script expects them.
#
# ---------------------------------------------------------------------------
# THE TWO SECRETS
# ---------------------------------------------------------------------------
#
#   static.key      the gateway's 32-byte X25519 private key, hex-encoded.
#                   ASYMMETRIC. The client needs only the matching PUBLIC key.
#                   It therefore never has to leave the node, and under the
#                   default mode it never does.
#
#   admission.key   the admission secret. SYMMETRIC: the gateway and every
#                   client that may reach it hold the same bytes. One network
#                   hop is unavoidable for this one, and this script confines
#                   that hop to a single SSH stdin stream.
#
# ---------------------------------------------------------------------------
# THE TRAP THIS SCRIPT IS BUILT AROUND
# ---------------------------------------------------------------------------
#
# THE ADMISSION SECRET IS OPAQUE BYTES AND IS NEVER DECODED.
#
# keygen writes it hex-encoded, which makes hex-decoding it on the way to the
# server look like the obviously correct thing to do. It is not. Every consumer
# -- cmd/winn3-gateway (main.go buildSessionConfig), cmd/winn-datapath
# (winn3_run.go:372) and cmd/winn3-labrig (main.go:384) -- reads the FILE'S
# BYTES with only trailing CR/LF removed, so the ASCII TEXT of the hex IS the
# secret. Decode on one end only and that end computes a different admission
# tag; ReadInitiation fails; and the gateway answers with the same silence it
# answers every unauthenticated datagram with.
#
# Under this project's threat model that is the worst possible failure: a
# client timing out against a healthy-looking gateway is indistinguishable from
# a censored path or a dead host, which is precisely what the protocol's
# silence property is designed to make indistinguishable.
#
# So this script moves the file as an opaque byte stream and never interprets
# it, and it ends by comparing a fingerprint computed identically on both ends.
#
# ---------------------------------------------------------------------------
# CHANNEL RULES
# ---------------------------------------------------------------------------
#
# FORBIDDEN, and none of them are used here:
#   - the datapath framed-duplex stdio channel (cmd/winn-datapath's frames)
#   - the hub API, the control-plane database, node register/heartbeat payloads
#   - the signed hub descriptor -- it carries a gateway_id and a public key,
#     never a secret
#   - a command-line argument (visible in ps, in shell history, in the journal)
#   - an environment variable (visible in /proc/PID/environ)
#   - any repository, any artifact directory, any log
#
# USED, and only this:
#   - the operator's existing SSH management channel, as a single stdin stream
#     into a `cat` that writes straight to a 0600 file under umask 077
#
# ---------------------------------------------------------------------------
# WHERE GENERATION HAPPENS, AND WHY IT MATTERS
# ---------------------------------------------------------------------------
#
# --generate runs `winn3-gateway -mode keygen` ON THE NODE, into a directory on
# /run, which is tmpfs -- RAM, never written to the disk, and gone on reboot.
#
# Two things follow, and both are the point:
#
#   1. static.key is created on the node and installed on the node. THE
#      GATEWAY'S PRIVATE KEY NEVER CROSSES THE NETWORK AT ALL. Generating
#      locally and pushing it would work and would be one line shorter; it
#      would also mean the private key existed on a laptop and traversed a
#      link, for no benefit, since nothing off-node ever needs it.
#
#   2. The binary that writes the files is the same build that will read them,
#      so the file format cannot drift between generator and consumer.
#
# What comes BACK is only: admission.key (shared, unavoidable), static.pub
# (public), client.key and client.pub (the client's own pair). The tmpfs
# directory is removed before the connection closes.
#
# ---------------------------------------------------------------------------
# --generate-ech: PER-NODE ECH KEY (Round GK OI-GK-3 step 1, 2026-09-26)
# ---------------------------------------------------------------------------
#
# Every data plane shipped the same ech-keys.json. --generate-ech replaces it
# on ONE node with a two-entry file built ON the node: a new key generated
# there (send_as_retry) followed by the node's existing key (send_as_retry
# cleared), so a peer holding the old shared config is still accepted.
# winn-ech-keygen -add-to reads the existing file and writes the new one into
# tmpfs; the private halves of both keys stay on the node. Nothing that comes
# back is secret: SHA-256 digests, the public ECH config list, and the public
# fields winn-ech-keygen -describe prints.
#
# The ECH key file is NOT like admission.key: no client needs its private half,
# so no private byte of it crosses the network in either direction.
#
# winn-ech-keygen must already be installed on the node. /run is mounted
# noexec on Ubuntu, so the binary cannot be staged in tmpfs; it is a public
# build of cmd/winn-ech-keygen, not a secret.
#
# The previous file is kept on the node as ech-keys.json.pre-gk3-<UTC stamp>
# (0400 root), which is the rollback. It holds only the shared key the new
# file also holds, so it adds no exposure; destroying shared private keys is a
# later step behind the owner's confirmation. This mode does NOT restart the
# gateway.
#
# ---------------------------------------------------------------------------
# --generate-successor / --swap-successor / --rollback-successor
# (Round GK3 OI-GK3-2, the Canada rotation, 2026-09-26)
# ---------------------------------------------------------------------------
#
# A full rotation of a node's four per-node gateway secrets: static.key, the
# admission secret, and both dual-auth attestation keys. The gateway takes one
# of each and cannot reload them, so a rotation is one cold restart; these
# modes split it so that nothing live changes until the operator's cut.
#
#   --generate-successor  runs `winn3-gateway -mode keygen` ON THE NODE into
#       tmpfs and stages the four secrets as <live>.gk2-new (0600 root) beside
#       the live files. The live files, the unit and the running gateway are
#       not touched. What comes back: static.pub, auth_ed25519.pub and
#       auth_mldsa65.pub (public), and admission.key, the one SYMMETRIC secret,
#       because the signed descriptor carries it to every client and the
#       offline signer needs its bytes. static.key, both dual-auth private
#       keys and keygen's client.key never leave the node.
#   --swap-successor  refuses unless each staged file's sha256 equals the one
#       --generate-successor recorded in <out-dir>/staging-record.txt (the set
#       whose public halves were signed). It then copies each live file to <live>.pre-gk2-<UTC stamp>
#       (cp -p: same bytes, mode, owner, mtime) and then renames each
#       <live>.gk2-new over <live>. Same directory, so each rename is atomic
#       and the unit's LoadCredential path never sees a partial file. It does
#       NOT restart the gateway: the running process keeps the /run copies it
#       made at start until the operator's one `systemctl restart`.
#   --rollback-successor  copies each live (successor) file to
#       <live>.gk2-rolledback-<stamp>, then puts <live>.pre-gk2-<stamp> back.
#       Nothing is deleted by any of these modes; deleting the leaked backups
#       is a later step behind the owner's confirmation.
#   --successor-status  read-only: digests of the live, staged, backup and
#       /run copies, and the unit state.
#
# Every mode first proves that the unit loads EXACTLY these four paths
# (one LoadCredential line per ID, naming this path), so a swap cannot land on
# files the gateway does not read. --dry-run runs every check, prints the
# plan, and changes nothing on the node.

set -euo pipefail

MODE=""
NODE=""
OUT_DIR=""

SSH_IDENTITY="${WINN3_SSH_IDENTITY:-${HOME}/.ssh/winsvpn_deploy_ed25519}"
SSH_USER="${WINN3_SSH_USER:-root}"
GATEWAY_BIN="${WINN3_GATEWAY_INSTALL_PATH:-/usr/local/libexec/winn/winn3-gateway}"
CRED_DIR="${WINN_CREDENTIALS_DIR:-/etc/winn/credentials}"
STATIC_DEST="${CRED_DIR}/winn3-gateway-static.key"
ADMISSION_DEST="${CRED_DIR}/winn3-gateway-admission.key"
ECH_KEYGEN_BIN="${WINN3_ECH_KEYGEN_INSTALL_PATH:-/usr/local/libexec/winn/winn-ech-keygen}"
ECH_DEST="${CRED_DIR}/ech-keys.json"
# Same variable names the installer writes into the gateway env file.
AUTH_ED_DEST="${WINN3_GATEWAY_DUAL_AUTH_ED_KEY:-${CRED_DIR}/winn3-gateway-auth-ed25519.seed}"
AUTH_ML_DEST="${WINN3_GATEWAY_DUAL_AUTH_ML_SEED:-${CRED_DIR}/winn3-gateway-auth-mldsa65.seed}"
GATEWAY_UNIT="${WINN3_GATEWAY_UNIT:-winn3-gateway.service}"
DRY_RUN=0
ROLLBACK_STAMP=""
SWAP_EXPECT=()

log()  { printf '\033[1;32m[winn3-keys]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[winn3-keys][WARN]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[winn3-keys][ERR]\033[0m %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------
#
# -T: no pseudo-terminal. Load-bearing rather than tidy: a tty would put the
# line discipline in the path of an opaque byte stream, and CR translation on a
# secret is exactly the class of silent corruption this whole script exists to
# prevent.
#
# IdentitiesOnly=yes: without it the agent offers keys in its own order and a
# wrong one is refused before the right one is tried, which reads as "no access
# to this host" rather than "wrong key".
node_ssh() {
  ssh -T \
    -o IdentitiesOnly=yes \
    -o BatchMode=yes \
    -o ConnectTimeout=20 \
    -o StrictHostKeyChecking=yes \
    -i "${SSH_IDENTITY}" \
    "${SSH_USER}@${NODE}" "$@"
}

# ---------------------------------------------------------------------------
# Fingerprints -- comparable on both ends, revealing on neither
# ---------------------------------------------------------------------------
#
# A domain-separated, truncated digest of the EXACT bytes a consumer will use:
# the file with trailing CR/LF removed and nothing else done to it.
#
# Domain-separated so this is a fingerprint OF the secret rather than a hash of
# it; truncated because 64 bits is far more than enough to catch a transfer
# fault, an encoding conversion, or two ends configured from different files.
#
# It is safe to paste into a ticket. The secret is not.
FP_DOMAIN='winn3-admission-fingerprint-v1'

# sha256_stdin exists because this half runs on the operator's machine, which is
# macOS today (shasum) and could be Linux tomorrow (sha256sum). Picking the
# wrong one would make every comparison fail with a tool error that looks like a
# credential fault.
sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256
  else
    die "Neither sha256sum nor shasum is available; cannot fingerprint."
  fi
}

local_fingerprint() {
  local path="$1"
  [[ -s "${path}" ]] || { printf 'ABSENT\n'; return 0; }
  { printf '%s' "${FP_DOMAIN}"; tr -d '\r\n' < "${path}"; } \
    | sha256_stdin | cut -c1-16
}

# The remote half computes the identical value with sha256sum. Both sides strip
# CR and LF and nothing else, which is what makes the comparison meaningful
# rather than merely reassuring.
remote_fingerprint_cmd() {
  printf '%s' "if [ -s '$1' ]; then { printf %s '${FP_DOMAIN}'; tr -d '\\r\\n' < '$1'; } | sha256sum | cut -c1-16; else echo ABSENT; fi"
}

# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------

# refuse_repo_out_dir is the "never lands in a repo" rule, enforced rather than
# documented. A secret committed once is a secret forever, and the obvious
# convenient place to put an out-dir is right beside the checkout.
refuse_repo_out_dir() {
  local dir="$1" resolved
  mkdir -p "${dir}"
  resolved="$(cd "${dir}" && pwd -P)"

  if git -C "${resolved}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    local top
    top="$(git -C "${resolved}" rev-parse --show-toplevel 2>/dev/null || echo '?')"
    die "Refusing to write key material into ${resolved}: it is inside the git work tree at ${top}.
  Choose a directory outside any repository, e.g. ~/.winn3-keys/<node>."
  fi
  case "${resolved}" in
    */wins_vpn|*/wins_vpn/*|*/wins_security|*/wins_security/*)
      die "Refusing to write key material into ${resolved}: that path is inside a Win's VPN source tree." ;;
  esac
  if [[ "${resolved}" == /tmp/* || "${resolved}" == /var/folders/* ]]; then
    warn "${resolved} is a system temp directory; it may be world-readable and is cleared unpredictably."
  fi

  # 0700 before anything is written into it.
  chmod 700 "${resolved}"
  OUT_DIR="${resolved}"
}

require_remote_binary() {
  node_ssh "test -x '${GATEWAY_BIN}'" \
    || die "No executable at ${GATEWAY_BIN} on ${NODE}.
  Install it first with server/wins_winn3_gateway_install.sh --install.
  Generation runs on the node deliberately, so the binary must be there already."
}

warn_on_overwrite() {
  local existing
  existing="$(node_ssh "test -s '${STATIC_DEST}' && echo yes || echo no" 2>/dev/null || echo unknown)"
  if [[ "${existing}" == "yes" ]]; then
    warn "${NODE} ALREADY HAS a gateway static key at ${STATIC_DEST}."
    warn "  Generating new material invalidates every client profile issued against the"
    warn "  old one. Those clients will not see an error -- they will see silence, which"
    warn "  is this protocol's response to an unauthenticated peer and is indistinguishable"
    warn "  from censorship."
    warn "  Re-run with WINN3_ALLOW_ROTATE=1 if that is genuinely intended."
    [[ "${WINN3_ALLOW_ROTATE:-0}" == "1" ]] \
      || die "Refusing to overwrite existing key material."
    warn "WINN3_ALLOW_ROTATE=1 set; proceeding with rotation."
  fi
}

# ---------------------------------------------------------------------------
# --generate
# ---------------------------------------------------------------------------

do_generate() {
  require_remote_binary
  warn_on_overwrite

  log "Generating on ${NODE}, in tmpfs under /run (RAM only, never on disk)."

  # One connection, one script, no secret on any command line.
  #
  # The heredoc is quoted ('REMOTE') so the LOCAL shell expands nothing: every
  # variable below is evaluated on the node. The two paths that must come from
  # here are passed as positional arguments to bash, which are configuration,
  # not secrets.
  local remote_out
  remote_out=$(node_ssh "bash -s -- '${GATEWAY_BIN}' '${CRED_DIR}' '${STATIC_DEST}' '${ADMISSION_DEST}'" <<'REMOTE'
set -euo pipefail
BIN="$1"; CRED_DIR="$2"; STATIC_DEST="$3"; ADMISSION_DEST="$4"

umask 077

# /run is tmpfs on Ubuntu. Material generated here exists in RAM and is gone at
# reboot; there is no block device to have to shred afterwards.
TMP="$(mktemp -d -p /run winn3-keygen.XXXXXXXX)"
cleanup() { rm -rf "${TMP}"; }
trap cleanup EXIT INT TERM

# keygen writes static.key, static.pub, admission.key, client.key, client.pub.
# Its own stdout line names only PUBLIC keys, so it is safe to discard rather
# than to have to scrub.
"${BIN}" -mode keygen -out "${TMP}" >/dev/null

install -d -m 700 -o root -g root "${CRED_DIR}"

# install() copies; the tmpfs originals are removed by the EXIT trap above, so
# the only copy that outlives this script is the 0600 root-owned one under
# CRED_DIR. The transient copies lived in RAM and were never on a block device,
# which is why no shredding step is needed or would help.
install -m 600 -o root -g root "${TMP}/static.key"    "${STATIC_DEST}"
install -m 600 -o root -g root "${TMP}/admission.key" "${ADMISSION_DEST}"

# Everything the operator needs back, in one stream, delimited so the local end
# can split it without a second connection.
#
# The gateway's static.key is NOT in this list and must never be added to it.
echo "---BEGIN winn3 provisioning result---"
echo "static.pub $(cat "${TMP}/static.pub")"
echo "client.key $(cat "${TMP}/client.key")"
echo "client.pub $(cat "${TMP}/client.pub")"
echo "admission.key $(cat "${TMP}/admission.key")"
echo "admission.fp $({ printf %s 'winn3-admission-fingerprint-v1'; tr -d '\r\n' < "${TMP}/admission.key"; } | sha256sum | cut -c1-16)"
echo "installed.static.bytes $(stat -c %s "${STATIC_DEST}")"
echo "installed.admission.fp $({ printf %s 'winn3-admission-fingerprint-v1'; tr -d '\r\n' < "${ADMISSION_DEST}"; } | sha256sum | cut -c1-16)"
echo "---END winn3 provisioning result---"
REMOTE
) || die "Remote generation failed."

  case "${remote_out}" in
    *'---END winn3 provisioning result---'*) ;;
    *) die "Remote generation produced no complete result block." ;;
  esac

  # Write the local half. Files first, at 0600, inside a 0700 directory.
  local field value
  for field in static.pub client.key client.pub admission.key; do
    value="$(printf '%s\n' "${remote_out}" | awk -v k="${field}" '$1==k {print $2; exit}')"
    [[ -n "${value}" ]] || die "Remote result did not carry ${field}."
    ( umask 077; printf '%s' "${value}" > "${OUT_DIR}/${field}" )
    chmod 600 "${OUT_DIR}/${field}"
  done
  # The public halves are not secrets and are marked as such, so that a later
  # reader can tell at a glance which two files here actually matter.
  chmod 644 "${OUT_DIR}/static.pub" "${OUT_DIR}/client.pub"

  local remote_fp installed_fp local_fp static_bytes
  remote_fp="$(printf '%s\n' "${remote_out}" | awk '$1=="admission.fp" {print $2; exit}')"
  installed_fp="$(printf '%s\n' "${remote_out}" | awk '$1=="installed.admission.fp" {print $2; exit}')"
  static_bytes="$(printf '%s\n' "${remote_out}" | awk '$1=="installed.static.bytes" {print $2; exit}')"
  local_fp="$(local_fingerprint "${OUT_DIR}/admission.key")"

  log "Installed on ${NODE}:"
  log "  ${STATIC_DEST}      ${static_bytes} bytes, 0600 root:root  (never left the node)"
  log "  ${ADMISSION_DEST}   fingerprint ${installed_fp}"
  log "Written locally under ${OUT_DIR} (0700):"
  log "  admission.key  0600  fingerprint ${local_fp}   <- the client needs this"
  log "  client.key     0600                            <- the client needs this"
  log "  static.pub     0644                            <- the client needs this"
  log "  client.pub     0644"

  if [[ "${local_fp}" != "${remote_fp}" || "${remote_fp}" != "${installed_fp}" ]]; then
    err "FINGERPRINT MISMATCH."
    err "  generated on node : ${remote_fp}"
    err "  installed on node : ${installed_fp}"
    err "  written locally   : ${local_fp}"
    err "  The admission secret did not survive the transfer byte-for-byte. Do not"
    err "  start the gateway: the two ends would compute different admission tags and"
    err "  the resulting refusal is silent and unattributable."
    exit 1
  fi
  log "Admission fingerprint matches on both ends: ${local_fp}"

  cat <<EOF

Next, and not before:
  1. Configure the client with EXACTLY these, byte for byte:
       gateway public key : $(cat "${OUT_DIR}/static.pub")
       admission secret   : ${OUT_DIR}/admission.key      (opaque bytes, do NOT hex-decode)
       client private key : ${OUT_DIR}/client.key
       gateway id         : the operator string, RAW bytes, identical on both ends
       path MTU           : identical on both ends -- nothing negotiates it
  2. Start the gateway:  systemctl start winn3-gateway
  3. Prove external UDP ingress before believing anything. A bound socket is not
     reachability. See docs/WINN3_GATEWAY_DEPLOYMENT_RUNBOOK_20260809.md step 6.
EOF
}

# ---------------------------------------------------------------------------
# --generate-ech
# ---------------------------------------------------------------------------

do_generate_ech() {
  node_ssh "test -x '${ECH_KEYGEN_BIN}'" \
    || die "No executable at ${ECH_KEYGEN_BIN} on ${NODE}.
  Install a build of cmd/winn-ech-keygen for this node's architecture there first.
  /run is noexec, so it cannot be staged in tmpfs."

  log "Rotating ${NODE}:${ECH_DEST} to a two-entry file, generated on the node in tmpfs."

  # Same shape as --generate: one connection, a quoted heredoc so the LOCAL
  # shell expands nothing, and only configuration paths as arguments.
  local remote_out
  remote_out=$(node_ssh "bash -s -- '${ECH_KEYGEN_BIN}' '${ECH_DEST}'" <<'REMOTE'
set -euo pipefail
BIN="$1"; ECH_DEST="$2"

umask 077
[ -s "${ECH_DEST}" ] || { echo "no ECH key file at ${ECH_DEST}" >&2; exit 3; }

TMP="$(mktemp -d -p /run winn3-echgen.XXXXXXXX)"
cleanup() { rm -rf "${TMP}"; }
trap cleanup EXIT INT TERM

# Reads ECH_DEST, writes ech-server-keys.json (two entries) and
# ech-config-list.bin (the new public config) into tmpfs. It refuses a file
# that already holds two entries, so a re-run cannot push the old key back.
# Its stdout names only public fields; it is discarded anyway.
"${BIN}" -add-to "${ECH_DEST}" -out "${TMP}" >/dev/null
# The public list is sent back from tmpfs and not kept on the node: the
# gateway never reads it, and the data-plane secrets audit
# (data_secret_path_specs) refuses any group/other bit on a file here.
LIST="${TMP}/ech-config-list.bin"

BACKUP="${ECH_DEST}.pre-gk3-$(date -u +%Y%m%dT%H%M%SZ)"
[ ! -e "${BACKUP}" ] || { echo "backup ${BACKUP} already exists" >&2; exit 3; }
install -m 400 -o root -g root "${ECH_DEST}" "${BACKUP}"
# Same directory, then rename: the unit's LoadCredential path never sees a
# partial file.
install -m 400 -o root -g root "${TMP}/ech-server-keys.json" "${ECH_DEST}.gk3-new"
mv -f "${ECH_DEST}.gk3-new" "${ECH_DEST}"

# Everything below is public. The key files themselves are hashed, never read
# out: no cat, no base64, no copy of ECH_DEST, BACKUP or the tmpfs key file.
echo "---BEGIN winn3 ech provisioning result---"
echo "backup ${BACKUP}"
echo "installed.sha256 $(sha256sum < "${ECH_DEST}" | cut -d' ' -f1)"
echo "backup.sha256 $(sha256sum < "${BACKUP}" | cut -d' ' -f1)"
"${BIN}" -describe "${ECH_DEST}"
echo "ech_config_list.sha256 $(sha256sum < "${LIST}" | cut -d' ' -f1)"
echo "ech_config_list.b64 $(base64 -w0 < "${LIST}")"
echo "---END winn3 ech provisioning result---"
REMOTE
) || die "Remote ECH rotation failed. List ${NODE}:${ECH_DEST}* (names and sha256 only) before retrying: a failure after the rename leaves the two-entry file and a .pre-gk3- backup in place."

  case "${remote_out}" in
    *'---END winn3 ech provisioning result---'*) ;;
    *) die "Remote ECH rotation produced no complete result block." ;;
  esac

  local field value backup installed_sha backup_sha ech_pub list_sha list_b64 entries local_list_sha
  field_of() { printf '%s\n' "${remote_out}" | awk -v k="$1" '$1==k {print $2; exit}'; }
  backup="$(field_of backup)"
  installed_sha="$(field_of installed.sha256)"
  backup_sha="$(field_of backup.sha256)"
  ech_pub="$(field_of ech_public_key_sha256)"
  list_sha="$(field_of ech_config_list.sha256)"
  list_b64="$(field_of ech_config_list.b64)"
  entries="$(field_of entries)"
  for field in backup installed_sha backup_sha ech_pub list_sha list_b64 entries; do
    value="${!field}"
    [[ -n "${value}" ]] || die "Remote result did not carry ${field}."
  done
  [[ "${entries}" == "2" ]] || die "Installed ECH key file holds ${entries} entries, expected 2."
  [[ "${installed_sha}" != "${backup_sha}" ]] || die "Installed ECH key file is unchanged."

  # Public material only: the new ECH config list and the digests for the hub.
  printf '%s' "${list_b64}" | base64 -d > "${OUT_DIR}/ech-config-list.bin"
  chmod 644 "${OUT_DIR}/ech-config-list.bin"
  local_list_sha="$(sha256_stdin < "${OUT_DIR}/ech-config-list.bin" | cut -d' ' -f1)"
  [[ "${local_list_sha}" == "${list_sha}" ]] \
    || die "ECH config list digest mismatch: node ${list_sha}, local ${local_list_sha}."
  printf '%s\n' "${remote_out}" \
    | sed -n '/^---BEGIN winn3 ech provisioning result---$/,/^---END winn3 ech provisioning result---$/p' \
    | grep -v '^ech_config_list.b64 ' > "${OUT_DIR}/ech-public-digests.txt"
  chmod 644 "${OUT_DIR}/ech-public-digests.txt"

  log "Installed on ${NODE}: ${ECH_DEST} (2 entries, sha256 ${installed_sha})"
  log "Previous file kept at ${backup} (sha256 ${backup_sha})"
  log "New ECH public key sha256 ${ech_pub}"
  log "Written locally under ${OUT_DIR}: ech-config-list.bin, ech-public-digests.txt (public)"

  cat <<EOF

Next, and not before:
  1. Load the new file:  systemctl restart winn3-gateway   (on ${NODE})
     then confirm it is active and serving before touching the next node.
  2. Record the PUBLIC digests at the hub (the admin token is referenced, never printed):
       curl -sS -X POST "\$HUB_BASE/admin/nodes/winn3/key-digests" \\
         -H "x-admin-token: \$WINS_ADMIN_TOKEN" \\
         -F 'slug=<node slug>' \\
         -F 'ech_public_key_sha256=${ech_pub}' \\
         -F 'ech_config_list_sha256=${list_sha}'
     A 409 means another node already holds this key: stop and investigate.
  3. Rollback (on ${NODE}), restores the single shared-key file:
       install -m 400 -o root -g root '${backup}' '${ECH_DEST}' && systemctl restart winn3-gateway
EOF
}

# ---------------------------------------------------------------------------
# --generate-successor / --swap-successor / --rollback-successor /
# --successor-status
# ---------------------------------------------------------------------------

GK2_BEGIN='---BEGIN winn3 gk2 result---'
GK2_END='---END winn3 gk2 result---'
gk2_out=""

# gk2_field KEY -- the second field of the first "KEY ..." result line.
gk2_field() { printf '%s\n' "${gk2_out}" | awk -v k="$1" '$1==k {print $2; exit}'; }

# gk2_block -- the result block alone, markers included.
gk2_block() {
  printf '%s\n' "${gk2_out}" | sed -n "/^${GK2_BEGIN}\$/,/^${GK2_END}\$/p"
}

# The paths reach the node inside one single-quoted bash -s argument string,
# so a quote or a space in one would change the command. Refuse, never escape.
require_plain_word() {
  [[ "$2" =~ ^[A-Za-z0-9._/@:+=-]+$ ]] \
    || die "$1 '$2' has a character outside [A-Za-z0-9._/@:+=-]; refusing to pass it to the node."
}

# hex_to_b64 HEX BYTES -- base64 of the raw bytes, as the signer takes the
# public keys, refusing a value of the wrong length. Public input only.
hex_to_b64() {
  python3 - "$1" "$2" <<'PY'
import base64, sys
raw = bytes.fromhex(sys.argv[1])
if len(raw) != int(sys.argv[2]):
    sys.exit(f"public key is {len(raw)} bytes, expected {sys.argv[2]}")
print(base64.b64encode(raw).decode())
PY
}

# successor_remote_script -- print the node-side script. It lives in its own
# function, outside any $(...), because bash 3.2 (macOS /bin/bash) misparses
# case patterns in a heredoc nested inside a command substitution.
successor_remote_script() {
  cat <<'REMOTE'
set -euo pipefail
shopt -s nullglob
ACTION="$1"; DRY="$2"; BIN="$3"; UNIT="$4"; STAMP="$5"
# The four live credential files in one fixed order, the unit's
# LoadCredential ID for each, the length of the lowercase hex text keygen
# writes for each, and keygen's own file name for each.
LIVE=("$6" "$7" "$8" "$9")
# swap only: the sha256 of each staged file as --generate-successor recorded
# it locally, i.e. the set whose public halves were signed. Digests, public.
EXPECT=("${10:-}" "${11:-}" "${12:-}" "${13:-}")
IDS=(static.key admission.key dual-auth-ed-key dual-auth-ml-seed)
LENS=(64 64 128 64)
GEN_NAMES=(static.key admission.key auth_ed25519.seed auth_mldsa65.seed)
umask 077

fail() { echo "REFUSED: $*" >&2; exit 3; }
sha() { sha256sum < "$1" | cut -d' ' -f1; }
fp() { { printf %s 'winn3-admission-fingerprint-v1'; tr -d '\r\n' < "$1"; } | sha256sum | cut -c1-16; }

# A secret file these modes may hash, copy or rename: a regular file, not a
# symlink, owned by root, no group/other bit (the installer's
# require_root_private_keyfile rule and the data-plane secrets audit's).
private_file() {
  { [ ! -L "$1" ] && [ -f "$1" ]; } || fail "$1 is missing, a symlink, or not a regular file"
  [ "$(stat -c %u "$1")" = 0 ] || fail "$1 is not owned by root"
  case "$(stat -c %a "$1")" in 400|600) ;; *) fail "$1 has group/other permission bits" ;; esac
}
# A generated or staged file must also have keygen's exact shape: LEN
# lowercase hex bytes, no newline. grep -q reads it and prints nothing.
keygen_shape() {
  [ "$(stat -c %s "$1")" = "$2" ] || fail "$1 is not $2 bytes"
  LC_ALL=C grep -q -x -E "[0-9a-f]{$2}" "$1" || fail "$1 is not $2 lowercase hex bytes"
}
emit_live() { local i; for i in 0 1 2 3; do echo "live ${LIVE[$i]} $(sha "${LIVE[$i]}")"; done; }

# The unit must load exactly these four paths: one LoadCredential line per
# ID, naming this path. Otherwise a swap would land on files the gateway
# does not read, and the restart would bring back the old keys.
UNIT_TEXT="$(systemctl cat "${UNIT}" 2>/dev/null)" || fail "cannot read unit ${UNIT}"
for i in 0 1 2 3; do
  n="$(grep -c -e "^LoadCredential=${IDS[$i]//./\\.}:" <<<"${UNIT_TEXT}" || true)"
  [ "${n}" = 1 ] || fail "${UNIT} has ${n} LoadCredential lines for ${IDS[$i]}, want exactly 1"
  grep -q -x -F -e "LoadCredential=${IDS[$i]}:${LIVE[$i]}" <<<"${UNIT_TEXT}" \
    || fail "${UNIT} does not load ${IDS[$i]} from ${LIVE[$i]}"
done
for i in 0 1 2 3; do private_file "${LIVE[$i]}"; done

case "${ACTION}" in
stage)
  [ -x "${BIN}" ] || fail "no executable at ${BIN}"
  [ "$(findmnt -n -o FSTYPE /run)" = tmpfs ] || fail "/run is not tmpfs; refusing to generate key material onto a disk"
  for i in 0 1 2 3; do
    [ ! -e "${LIVE[$i]}.gk2-new" ] || fail "${LIVE[$i]}.gk2-new already exists: a successor set is already staged. Inspect it with --successor-status and never overwrite it; its public halves may already be signed"
  done
  BEFORE="$(emit_live)"
  if [ "${DRY}" = 1 ]; then
    echo "---BEGIN winn3 gk2 result---"
    echo "action stage"
    echo "dry_run 1"
    printf '%s\n' "${BEFORE}"
    for i in 0 1 2 3; do echo "would_stage ${LIVE[$i]}.gk2-new"; done
    echo "---END winn3 gk2 result---"
    exit 0
  fi

  # /run is tmpfs: generated material exists in RAM and is gone at reboot.
  TMP="$(mktemp -d -p /run winn3-gk2gen.XXXXXXXX)"
  CREATED=()
  COMMITTED=0
  cleanup() {
    rm -rf "${TMP}"
    # A failed run removes only the staged files IT created, so a re-run is
    # not blocked by a half-staged set. It never touches a live file.
    if [ "${COMMITTED}" != 1 ]; then
      for f in "${CREATED[@]+"${CREATED[@]}"}"; do rm -f "${f}"; done
    fi
  }
  trap cleanup EXIT INT TERM

  # keygen writes static.key/.pub, admission.key, client.key/.pub and
  # auth_ed25519.seed/.pub, auth_mldsa65.seed/.pub. Its stdout names only
  # public keys; it is discarded anyway. client.key/.pub are not used: the
  # rotation keeps every client identity and the peer registry as they are.
  "${BIN}" -mode keygen -out "${TMP}" >/dev/null
  for i in 0 1 2 3; do keygen_shape "${TMP}/${GEN_NAMES[$i]}" "${LENS[$i]}"; done
  keygen_shape "${TMP}/static.pub" 64
  keygen_shape "${TMP}/auth_ed25519.pub" 64
  keygen_shape "${TMP}/auth_mldsa65.pub" 3904

  # install copies; the tmpfs originals go with the EXIT trap. The .gk2-new
  # files are the only copies that outlive this script, and nothing live is
  # written: the gateway keeps running on the /run copies it made at start.
  for i in 0 1 2 3; do
    CREATED+=("${LIVE[$i]}.gk2-new")
    install -m 600 -o root -g root "${TMP}/${GEN_NAMES[$i]}" "${LIVE[$i]}.gk2-new"
    [ "$(sha "${LIVE[$i]}.gk2-new")" = "$(sha "${TMP}/${GEN_NAMES[$i]}")" ] \
      || fail "staged ${GEN_NAMES[$i]} differs from the generated file"
    [ "$(sha "${LIVE[$i]}.gk2-new")" != "$(sha "${LIVE[$i]}")" ] \
      || fail "generated ${GEN_NAMES[$i]} equals the live file"
  done
  AFTER="$(emit_live)"
  [ "${AFTER}" = "${BEFORE}" ] || fail "a live credential file changed during staging"
  COMMITTED=1

  # Everything the operator needs back, in one stream. The public halves,
  # and admission.key: the one SYMMETRIC secret, which the signed descriptor
  # carries to every client, so the offline signer needs its bytes.
  # static.key, auth_ed25519.seed, auth_mldsa65.seed and client.key are NOT
  # in this block and must never be added to it.
  echo "---BEGIN winn3 gk2 result---"
  echo "action stage"
  echo "dry_run 0"
  printf '%s\n' "${AFTER}"
  for i in 0 1 2 3; do
    echo "staged ${LIVE[$i]}.gk2-new $(sha "${LIVE[$i]}.gk2-new") $(stat -c '%s %a %U:%G' "${LIVE[$i]}.gk2-new")"
  done
  echo "static.pub $(cat "${TMP}/static.pub")"
  echo "auth_ed25519.pub $(cat "${TMP}/auth_ed25519.pub")"
  echo "auth_mldsa65.pub $(cat "${TMP}/auth_mldsa65.pub")"
  echo "admission.key $(cat "${TMP}/admission.key")"
  echo "admission.fp $(fp "${TMP}/admission.key")"
  echo "staged.admission.fp $(fp "${LIVE[1]}.gk2-new")"
  echo "---END winn3 gk2 result---"
  ;;

swap)
  STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
  NEW=()
  for i in 0 1 2 3; do
    private_file "${LIVE[$i]}.gk2-new"
    keygen_shape "${LIVE[$i]}.gk2-new" "${LENS[$i]}"
    [ "$(sha "${LIVE[$i]}.gk2-new")" != "$(sha "${LIVE[$i]}")" ] || fail "${LIVE[$i]}.gk2-new equals the live file"
    [ ! -e "${LIVE[$i]}.pre-gk2-${STAMP}" ] || fail "${LIVE[$i]}.pre-gk2-${STAMP} already exists"
    NEW+=("$(sha "${LIVE[$i]}.gk2-new")")
    # Promote only the set that was signed: a set staged by anything else
    # would restart the gateway on keys no published descriptor names.
    [ -n "${EXPECT[$i]}" ] || fail "no expected digest for ${LIVE[$i]}.gk2-new"
    [ "${NEW[$i]}" = "${EXPECT[$i]}" ] || fail "${LIVE[$i]}.gk2-new is not the file recorded in staging-record.txt"
  done
  if [ "${DRY}" = 1 ]; then
    echo "---BEGIN winn3 gk2 result---"
    echo "action swap"
    echo "dry_run 1"
    echo "stamp ${STAMP}"
    emit_live
    for i in 0 1 2 3; do
      echo "would_backup ${LIVE[$i]} ${LIVE[$i]}.pre-gk2-${STAMP}"
      echo "would_promote ${LIVE[$i]}.gk2-new ${LIVE[$i]} ${NEW[$i]}"
    done
    echo "---END winn3 gk2 result---"
    exit 0
  fi

  BACKED=()
  PROMOTED=0
  cleanup() {
    local status=$?
    [ "${status}" = 0 ] && return 0
    if [ "${PROMOTED}" = 0 ]; then
      # Nothing live moved: the backups this run made are redundant copies.
      for f in "${BACKED[@]+"${BACKED[@]}"}"; do rm -f "${f}"; done
    else
      echo "PARTIAL SWAP: ${PROMOTED} of 4 renames ran. Undo with --rollback-successor and stamp ${STAMP}; do not restart the gateway first." >&2
    fi
  }
  trap cleanup EXIT INT TERM
  # cp -p keeps bytes, mode, owner and mtime, so a rollback restores the
  # file exactly as it was.
  for i in 0 1 2 3; do
    cp -p "${LIVE[$i]}" "${LIVE[$i]}.pre-gk2-${STAMP}"
    BACKED+=("${LIVE[$i]}.pre-gk2-${STAMP}")
    [ "$(sha "${LIVE[$i]}.pre-gk2-${STAMP}")" = "$(sha "${LIVE[$i]}")" ] \
      || fail "backup of ${LIVE[$i]} is not byte-identical"
  done
  # Same directory, so each rename is atomic: LoadCredential never reads a
  # partial file. Nothing restarts here.
  for i in 0 1 2 3; do
    PROMOTED=$((PROMOTED + 1))
    mv -f "${LIVE[$i]}.gk2-new" "${LIVE[$i]}"
  done
  for i in 0 1 2 3; do
    private_file "${LIVE[$i]}"
    [ "$(sha "${LIVE[$i]}")" = "${NEW[$i]}" ] || fail "${LIVE[$i]} does not hold the staged bytes after the rename"
  done
  echo "---BEGIN winn3 gk2 result---"
  echo "action swap"
  echo "dry_run 0"
  echo "stamp ${STAMP}"
  for i in 0 1 2 3; do
    echo "backup ${LIVE[$i]}.pre-gk2-${STAMP} $(sha "${LIVE[$i]}.pre-gk2-${STAMP}")"
    echo "promoted ${LIVE[$i]} $(sha "${LIVE[$i]}")"
  done
  echo "---END winn3 gk2 result---"
  ;;

rollback)
  if [ -z "${STAMP}" ]; then
    SETS=("${LIVE[0]}".pre-gk2-*)
    [ "${#SETS[@]}" = 1 ] || fail "found ${#SETS[@]} backup sets for ${LIVE[0]}; name the stamp"
    STAMP="${SETS[0]##*.pre-gk2-}"
  fi
  [[ "${STAMP}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || fail "backup stamp '${STAMP}' is malformed"
  OLD=()
  for i in 0 1 2 3; do
    private_file "${LIVE[$i]}.pre-gk2-${STAMP}"
    [ ! -e "${LIVE[$i]}.gk2-rolledback-${STAMP}" ] || fail "${LIVE[$i]}.gk2-rolledback-${STAMP} exists: this stamp was already rolled back"
    [ ! -e "${LIVE[$i]}.gk2-rb" ] || fail "leftover ${LIVE[$i]}.gk2-rb from an interrupted rollback; inspect it first"
    OLD+=("$(sha "${LIVE[$i]}.pre-gk2-${STAMP}")")
  done
  if [ "${DRY}" = 1 ]; then
    echo "---BEGIN winn3 gk2 result---"
    echo "action rollback"
    echo "dry_run 1"
    echo "stamp ${STAMP}"
    emit_live
    for i in 0 1 2 3; do
      echo "would_keep ${LIVE[$i]} ${LIVE[$i]}.gk2-rolledback-${STAMP}"
      echo "would_restore ${LIVE[$i]}.pre-gk2-${STAMP} ${LIVE[$i]} ${OLD[$i]}"
    done
    echo "---END winn3 gk2 result---"
    exit 0
  fi
  # Keep the successor set (nothing is deleted), then put the backup back
  # through a same-directory temporary and an atomic rename.
  for i in 0 1 2 3; do
    cp -p "${LIVE[$i]}" "${LIVE[$i]}.gk2-rolledback-${STAMP}"
    [ "$(sha "${LIVE[$i]}.gk2-rolledback-${STAMP}")" = "$(sha "${LIVE[$i]}")" ] \
      || fail "copy of ${LIVE[$i]} before rollback is not byte-identical"
  done
  for i in 0 1 2 3; do
    cp -p "${LIVE[$i]}.pre-gk2-${STAMP}" "${LIVE[$i]}.gk2-rb"
    mv -f "${LIVE[$i]}.gk2-rb" "${LIVE[$i]}"
  done
  for i in 0 1 2 3; do
    private_file "${LIVE[$i]}"
    [ "$(sha "${LIVE[$i]}")" = "${OLD[$i]}" ] || fail "${LIVE[$i]} does not hold the backup bytes after the rollback"
  done
  echo "---BEGIN winn3 gk2 result---"
  echo "action rollback"
  echo "dry_run 0"
  echo "stamp ${STAMP}"
  for i in 0 1 2 3; do
    echo "kept ${LIVE[$i]}.gk2-rolledback-${STAMP} $(sha "${LIVE[$i]}.gk2-rolledback-${STAMP}")"
    echo "restored ${LIVE[$i]} $(sha "${LIVE[$i]}")"
  done
  echo "---END winn3 gk2 result---"
  ;;

status)
  RD="$(systemctl show -p RuntimeDirectory --value "${UNIT}" | cut -d' ' -f1)"
  echo "---BEGIN winn3 gk2 result---"
  echo "action status"
  echo "unit ${UNIT} $(systemctl show -p ActiveState --value "${UNIT}") pid=$(systemctl show -p MainPID --value "${UNIT}") restarts=$(systemctl show -p NRestarts --value "${UNIT}")"
  for i in 0 1 2 3; do
    echo "live ${LIVE[$i]} $(sha "${LIVE[$i]}")"
    f="${LIVE[$i]}.gk2-new"
    if [ -e "${f}" ]; then echo "staged ${f} $(sha "${f}")"; fi
    for f in "${LIVE[$i]}".pre-gk2-*; do echo "backup ${f} $(sha "${f}")"; done
    for f in "${LIVE[$i]}".gk2-rolledback-*; do echo "rolledback ${f} $(sha "${f}")"; done
    f="/run/${RD}/${IDS[$i]}"
    if [ -n "${RD}" ] && [ -f "${f}" ]; then echo "runtime ${f} $(sha "${f}")"; else echo "runtime ${f} ABSENT"; fi
  done
  echo "---END winn3 gk2 result---"
  ;;

*)
  fail "unknown action ${ACTION}"
  ;;
esac
REMOTE
}

# run_successor ACTION -- run successor_remote_script, the one node-side
# script behind all four successor modes, so there is a single thing to
# audit. ACTION is stage, swap, rollback or status. Leaves the node's stdout
# in gk2_out; node stderr (REFUSED: ..., PARTIAL SWAP: ...) reaches the
# operator's terminal directly.
run_successor() {
  local action="$1" p
  for p in GATEWAY_BIN GATEWAY_UNIT STATIC_DEST ADMISSION_DEST AUTH_ED_DEST AUTH_ML_DEST; do
    require_plain_word "${p}" "${!p}"
  done
  [[ -z "${ROLLBACK_STAMP}" || "${ROLLBACK_STAMP}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] \
    || die "stamp '${ROLLBACK_STAMP}' is not of the form YYYYMMDDTHHMMSSZ"
  for p in ${SWAP_EXPECT[@]+"${SWAP_EXPECT[@]}"}; do
    [[ "${p}" =~ ^[0-9a-f]{64}$ ]] || die "expected digest '${p}' is not a sha256"
  done

  # Same shape as --generate: one connection, a quoted heredoc so the LOCAL
  # shell expands nothing, and only configuration as arguments.
  gk2_out=$(successor_remote_script | node_ssh "bash -s -- '${action}' '${DRY_RUN}' '${GATEWAY_BIN}' '${GATEWAY_UNIT}' '${ROLLBACK_STAMP}' '${STATIC_DEST}' '${ADMISSION_DEST}' '${AUTH_ED_DEST}' '${AUTH_ML_DEST}' ${SWAP_EXPECT[*]+${SWAP_EXPECT[*]}}") \
    || return 1
  case "${gk2_out}" in
    *"${GK2_END}"*) ;;
    *) return 1 ;;
  esac
}

do_generate_successor() {
  require_remote_binary
  log "Staging a successor key set on ${NODE}, generated there in tmpfs.$([[ "${DRY_RUN}" == "1" ]] && printf ' DRY RUN.')"
  run_successor stage \
    || die "Remote staging failed. No live file was touched. Run --successor-status ${NODE} to see what is there before retrying."

  if [[ "$(gk2_field dry_run)" == "1" ]]; then
    gk2_block
    log "DRY RUN: every check passed; nothing was generated or written on ${NODE}."
    return 0
  fi

  local field value
  for field in static.pub auth_ed25519.pub auth_mldsa65.pub admission.key admission.fp staged.admission.fp; do
    value="$(gk2_field "${field}")"
    [[ -n "${value}" ]] || die "Remote result did not carry ${field}."
  done

  # Public halves: hex as keygen writes them, and base64 of the raw bytes as
  # tools/winn3_sign_descriptor.py takes them.
  local name bytes b64
  for name in static.pub:32:static_pub auth_ed25519.pub:32:auth_ed25519 auth_mldsa65.pub:1952:auth_mldsa65; do
    field="${name%%:*}"; bytes="${name#*:}"; bytes="${bytes%%:*}"
    printf '%s' "$(gk2_field "${field}")" > "${OUT_DIR}/${field}"
    b64="$(hex_to_b64 "$(gk2_field "${field}")" "${bytes}")" \
      || die "${field} from the node is not a ${bytes}-byte public key."
    printf '%s\n' "${b64}" > "${OUT_DIR}/${name##*:}.b64"
    chmod 644 "${OUT_DIR}/${field}" "${OUT_DIR}/${name##*:}.b64"
  done
  ( umask 077; printf '%s' "$(gk2_field admission.key)" > "${OUT_DIR}/admission.key" )
  chmod 600 "${OUT_DIR}/admission.key"
  # The record is an allowlist of public lines: never the admission.key line.
  gk2_block | grep -E '^(action|dry_run|live|staged|admission\.fp|staged\.admission\.fp) ' \
    > "${OUT_DIR}/staging-record.txt"
  chmod 644 "${OUT_DIR}/staging-record.txt"

  local remote_fp staged_fp local_fp
  remote_fp="$(gk2_field admission.fp)"
  staged_fp="$(gk2_field staged.admission.fp)"
  local_fp="$(local_fingerprint "${OUT_DIR}/admission.key")"

  log "Staged on ${NODE} (0600 root, NOT live; the gateway was not touched):"
  awk '$1=="staged" {printf "  %s  sha256 %s  %s bytes\n", $2, substr($3,1,12), $4}' "${OUT_DIR}/staging-record.txt" \
    | while IFS= read -r line; do log "${line}"; done
  log "Written locally under ${OUT_DIR} (0700):"
  log "  admission.key  0600  fingerprint ${local_fp}   <- the descriptor carries this"
  log "  static_pub.b64 auth_ed25519.b64 auth_mldsa65.b64 and the hex .pub files  0644 (public)"
  log "  staging-record.txt  0644 (digests only)"

  if [[ "${local_fp}" != "${remote_fp}" || "${remote_fp}" != "${staged_fp}" ]]; then
    err "FINGERPRINT MISMATCH."
    err "  generated on node : ${remote_fp}"
    err "  staged on node    : ${staged_fp}"
    err "  written locally   : ${local_fp}"
    err "  Do not sign with this admission.key. The staged set is unused and not live;"
    err "  inspect it with --successor-status before deciding what to do with it."
    exit 1
  fi
  log "Admission fingerprint matches on both ends: ${local_fp}"

  cat <<EOF

Next, and not before (see the execution checklist):
  1. Sign offline at seq S+1, admission_gen G+1 with the ring key:
       python3 tools/winn3_sign_descriptor.py sign --key <verified g1 PEM> --kid g1 \\
         --node <slug> --endpoint <stored> --inner-router-v4 <stored> --inner-resolver-v4 <stored> \\
         --gateway-id-b64 <stored> \\
         --static-pub "\$(cat '${OUT_DIR}/static_pub.b64')" \\
         --auth-ed25519 "\$(cat '${OUT_DIR}/auth_ed25519.b64')" \\
         --auth-mldsa65 "\$(cat '${OUT_DIR}/auth_mldsa65.b64')" \\
         --admission-secret-file '${OUT_DIR}/admission.key' \\
         --admission-gen <G+1> --seq <S+1> --prev-seq <S> --ttl <stored ttl> --out-dir <0700 dir>
  2. At the cut: withhold at the hub, then --swap-successor ${NODE} ${OUT_DIR}, then ONE restart.
  Undo before the cut: the four .gk2-new files are unused; the running gateway never read them.
EOF
}

do_swap_successor() {
  # The digests --generate-successor recorded for the set it staged, in the
  # node script's LIVE order. The node refuses a staged file that differs.
  local record="${OUT_DIR}/staging-record.txt" dest sha
  [[ -s "${record}" ]] || die "No ${record}: swap only the set --generate-successor staged into this out dir."
  SWAP_EXPECT=()
  for dest in "${STATIC_DEST}" "${ADMISSION_DEST}" "${AUTH_ED_DEST}" "${AUTH_ML_DEST}"; do
    sha="$(awk -v f="${dest}.gk2-new" '$1=="staged" && $2==f {print $3; exit}' "${record}")"
    [[ -n "${sha}" ]] || die "${record} has no staged digest for ${dest}.gk2-new."
    SWAP_EXPECT+=("${sha}")
  done
  log "Swapping the staged successor set into place on ${NODE}.$([[ "${DRY_RUN}" == "1" ]] && printf ' DRY RUN.')"
  run_successor swap \
    || die "Remote swap failed. Run --successor-status ${NODE} before anything else; a partial swap is undone with --rollback-successor and the stamp printed above."

  local stamp
  stamp="$(gk2_field stamp)"
  if [[ "$(gk2_field dry_run)" == "1" ]]; then
    gk2_block
    log "DRY RUN: every check passed; nothing was copied or renamed on ${NODE}."
    return 0
  fi
  gk2_block > "${OUT_DIR}/swap-record-${stamp}.txt"
  chmod 644 "${OUT_DIR}/swap-record-${stamp}.txt"
  log "Swapped on ${NODE}, stamp ${stamp}. Live files now hold the successor set; backups are <live>.pre-gk2-${stamp}."
  log "Record: ${OUT_DIR}/swap-record-${stamp}.txt (digests only)"
  cat <<EOF

The running gateway still uses the OLD keys from its /run copies. Next:
  1. Restart it ONCE (never pkill by pattern):  systemctl restart ${GATEWAY_UNIT}   (on ${NODE})
  2. Verify: --successor-status ${NODE} shows every runtime digest equal to its live digest.
  Rollback (only if the successor set will not start or will not carry):
       --rollback-successor ${NODE} ${OUT_DIR} ${stamp}   then ONE restart.
EOF
}

do_rollback_successor() {
  log "Rolling ${NODE} back to its pre-swap key set.$([[ "${DRY_RUN}" == "1" ]] && printf ' DRY RUN.')"
  run_successor rollback \
    || die "Remote rollback failed. Run --successor-status ${NODE} and inspect before retrying."

  local stamp
  stamp="$(gk2_field stamp)"
  if [[ "$(gk2_field dry_run)" == "1" ]]; then
    gk2_block
    log "DRY RUN: every check passed; nothing was copied or renamed on ${NODE}."
    return 0
  fi
  gk2_block > "${OUT_DIR}/rollback-record-${stamp}.txt"
  chmod 644 "${OUT_DIR}/rollback-record-${stamp}.txt"
  log "Rolled back on ${NODE}: live files equal <live>.pre-gk2-${stamp} again; the successor set is kept as <live>.gk2-rolledback-${stamp}."
  cat <<EOF

Next:
  1. Restart ONCE:  systemctl restart ${GATEWAY_UNIT}   (on ${NODE})
  2. Keep v3 for this node WITHHELD at the hub: no envelope for these keys can be published again.
     Fix forward with a fresh --generate-successor.
EOF
}

do_successor_status() {
  run_successor status || die "Could not read the successor state on ${NODE}."
  gk2_block
}

# ---------------------------------------------------------------------------
# --fingerprint / --verify
# ---------------------------------------------------------------------------

do_fingerprint() {
  local remote_fp
  remote_fp="$(node_ssh "$(remote_fingerprint_cmd "${ADMISSION_DEST}")")" \
    || die "Could not read the node's admission fingerprint."
  log "${NODE}:${ADMISSION_DEST}  ${remote_fp}"

  if [[ -n "${OUT_DIR}" && -s "${OUT_DIR}/admission.key" ]]; then
    local local_fp
    local_fp="$(local_fingerprint "${OUT_DIR}/admission.key")"
    log "local:${OUT_DIR}/admission.key  ${local_fp}"
    if [[ "${local_fp}" == "${remote_fp}" ]]; then
      log "MATCH -- both ends will compute the same admission tag."
    else
      err "MISMATCH -- the two ends hold different secrets."
      err "  This is the failure that looks exactly like 'there is no gateway there'."
      err "  The most common cause is an intermediate step that hex-decoded the file."
      exit 1
    fi
  fi
}

do_verify() {
  do_fingerprint

  log "Node-side credential state:"
  node_ssh "
    for f in '${STATIC_DEST}' '${ADMISSION_DEST}'; do
      if [ -s \"\$f\" ]; then
        printf '  %s  %s bytes  mode %s  owner %s\n' \"\$f\" \"\$(stat -c %s \"\$f\")\" \"\$(stat -c %a \"\$f\")\" \"\$(stat -c %U:%G \"\$f\")\"
      else
        printf '  %s  ABSENT\n' \"\$f\"
      fi
    done
    printf '  service: %s\n' \"\$(systemctl is-active winn3-gateway 2>/dev/null || echo not-installed)\"
  " || true
}

# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

usage() {
  cat <<'EOF'
Usage:
  winn3_gateway_provision_keys.sh --generate    <node> <local-out-dir>
  winn3_gateway_provision_keys.sh --fingerprint <node> [<local-out-dir>]
  winn3_gateway_provision_keys.sh --verify      <node> <local-out-dir>
  winn3_gateway_provision_keys.sh --generate-ech <node> <local-out-dir>
  winn3_gateway_provision_keys.sh --generate-successor <node> <local-out-dir> [--dry-run]
  winn3_gateway_provision_keys.sh --swap-successor     <node> <local-out-dir> [--dry-run]
  winn3_gateway_provision_keys.sh --rollback-successor <node> <local-out-dir> [<stamp>] [--dry-run]
  winn3_gateway_provision_keys.sh --successor-status   <node>

  --generate     Generate on the node in tmpfs, install the two credentials
                 there, bring the client's half back. The gateway's private key
                 never crosses the network.
  --fingerprint  Print the node's admission fingerprint; compare with a local
                 copy if one is given. Reveals no secret.
  --verify       Fingerprint comparison plus node-side file and service state.
  --generate-ech Replace the node's ECH key file with a two-entry file built on
                 the node: a new per-node key (send_as_retry) plus the existing
                 key. Only public digests and the public config come back. Does
                 not restart the gateway.
  --generate-successor
                 Generate a full successor set (static, admission, both
                 dual-auth keys) on the node in tmpfs and stage it as
                 <live>.gk2-new, 0600 root, beside the live files. Nothing live
                 changes. Brings back the public halves and admission.key only.
  --swap-successor
                 Refuse unless the staged set is the one recorded in
                 <local-out-dir>/staging-record.txt, then back up each live
                 file to <live>.pre-gk2-<stamp> and rename <live>.gk2-new over
                 it. Does not restart the gateway.
  --rollback-successor
                 Keep the live set as <live>.gk2-rolledback-<stamp> and put
                 <live>.pre-gk2-<stamp> back. Does not restart the gateway.
                 The stamp may be omitted when exactly one backup set exists.
  --successor-status
                 Read-only: live, staged, backup, rolled-back and /run digests.
  --dry-run      With the three changing successor modes: run every check,
                 print the plan, change nothing.

Environment:
  WINN3_SSH_IDENTITY   default ~/.ssh/winsvpn_deploy_ed25519
  WINN3_SSH_USER       default root
  WINN3_ALLOW_ROTATE   set to 1 to overwrite existing key material
  WINN3_ECH_KEYGEN_INSTALL_PATH  default /usr/local/libexec/winn/winn-ech-keygen
  WINN_CREDENTIALS_DIR           default /etc/winn/credentials
  WINN3_GATEWAY_DUAL_AUTH_ED_KEY default <credentials dir>/winn3-gateway-auth-ed25519.seed
  WINN3_GATEWAY_DUAL_AUTH_ML_SEED default <credentials dir>/winn3-gateway-auth-mldsa65.seed
  WINN3_GATEWAY_UNIT             default winn3-gateway.service
EOF
}

main() {
  local args=() a
  for a in "$@"; do
    if [[ "${a}" == "--dry-run" ]]; then DRY_RUN=1; else args+=("${a}"); fi
  done
  set -- ${args[@]+"${args[@]}"}

  case "${1:-}" in
    --generate)    MODE=generate ;;
    --fingerprint) MODE=fingerprint ;;
    --verify)      MODE=verify ;;
    --generate-ech) MODE=generate-ech ;;
    --generate-successor) MODE=generate-successor ;;
    --swap-successor)     MODE=swap-successor ;;
    --rollback-successor) MODE=rollback-successor ;;
    --successor-status)   MODE=successor-status ;;
    -h|--help|"")  usage; exit 0 ;;
    *) usage; die "Unknown argument '${1}'." ;;
  esac
  shift
  case "${MODE}" in
    generate-successor|swap-successor|rollback-successor) ;;
    *) [[ "${DRY_RUN}" == "0" ]] || die "--dry-run is supported only by --generate-successor, --swap-successor and --rollback-successor." ;;
  esac

  NODE="${1:-}"
  [[ -n "${NODE}" ]] || { usage; die "A node host or address is required."; }
  shift || true

  [[ -r "${SSH_IDENTITY}" ]] || die "No readable SSH identity at ${SSH_IDENTITY}. Set WINN3_SSH_IDENTITY."

  local requested_out="${1:-}"
  if [[ "${MODE}" == "fingerprint" && -z "${requested_out}" ]]; then
    OUT_DIR=""
  elif [[ "${MODE}" == "successor-status" ]]; then
    [[ -z "${requested_out}" ]] || die "--successor-status takes no output directory; it writes nothing."
    OUT_DIR=""
  else
    [[ -n "${requested_out}" ]] || { usage; die "A local output directory is required for --${MODE}."; }
    refuse_repo_out_dir "${requested_out}"
  fi
  if [[ "${MODE}" == "rollback-successor" ]]; then
    ROLLBACK_STAMP="${2:-}"
  fi

  case "${MODE}" in
    generate)    do_generate ;;
    fingerprint) do_fingerprint ;;
    verify)      do_verify ;;
    generate-ech) do_generate_ech ;;
    generate-successor) do_generate_successor ;;
    swap-successor)     do_swap_successor ;;
    rollback-successor) do_rollback_successor ;;
    successor-status)   do_successor_status ;;
  esac
}

main "$@"
