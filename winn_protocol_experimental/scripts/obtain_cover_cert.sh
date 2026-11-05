#!/usr/bin/env bash
# Obtain and install the cover certificate a Winn listener requires.
#
#   sudo ./obtain_cover_cert.sh --domain cdn.example.com --email you@example.com
#
# Winn refuses to start a reachable listener without a cover certificate. That
# refusal is deliberate: a leaf carries its issuer's Distinguished Name in the
# clear to anyone who completes a handshake, so without cover every prober reads
# the Winn CA and every deployment under that CA is linked to every other one.
#
# This script does four things, and the checks are the point:
#   1. refuses a name that cannot work as cover, BEFORE spending an ACME order
#   2. obtains a publicly-trusted DV certificate
#   3. verifies the result against the same rules internal/coverlisten enforces,
#      so a bad certificate is caught here rather than at service start
#   4. installs it and wires renewal to restart the unit
#
# Renewal MUST restart the unit. Rewriting the files alone leaves the old
# certificate in the running process until something else restarts it, which is
# a silent expiry waiting to happen.
set -euo pipefail

DOMAIN=""; EMAIL=""; UNIT="winn-carrier-server"; DEST="/etc/winn/credentials"
WINN_CERT=""; SKIP_DNS=0

usage() {
  cat >&2 <<'USAGE'
Usage: sudo obtain_cover_cert.sh --domain <fqdn> --email <address> [options]

  --domain, -d      Cover FQDN. Must resolve publicly and must NOT be a name on
                    the Winn server certificate.
  --email, -m       ACME account address for expiry notices.
  --winn-cert       Path to the Winn server certificate, to check the cover name
                    does not collide with its SANs. Strongly recommended.
  --unit            systemd unit to restart on renewal (default winn-carrier-server).
  --dest            Install directory (default /etc/winn/credentials).
  --skip-dns-check  Skip the public resolution check. Split-horizon DNS only.
USAGE
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain|-d) DOMAIN="${2:-}"; shift 2 ;;
    --email|-m) EMAIL="${2:-}"; shift 2 ;;
    --winn-cert) WINN_CERT="${2:-}"; shift 2 ;;
    --unit) UNIT="${2:-}"; shift 2 ;;
    --dest) DEST="${2:-}"; shift 2 ;;
    --skip-dns-check) SKIP_DNS=1; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown argument: $1" >&2; usage ;;
  esac
done

[[ -n "${DOMAIN}" && -n "${EMAIL}" ]] || usage

die() { echo "REFUSED: $*" >&2; exit 1; }

# DNS names are case-insensitive and may carry one trailing root dot; the
# pre-flight below matches case-sensitively and certbot names its lineage
# after the normalized name, so normalize once, before anything uses DOMAIN.
DOMAIN="${DOMAIN%.}"
DOMAIN="$(printf '%s' "${DOMAIN}" | LC_ALL=C tr '[:upper:]' '[:lower:]')"

# Name validation runs before the root check on purpose: a bad cover name should
# be rejected without the operator having to re-run under sudo to find out.

# ---------------------------------------------------------------- pre-flight
# Each check mirrors one internal/coverlisten applies at start-up. Failing here
# costs nothing; failing at service start costs an outage.

case "${DOMAIN}" in
  *.local|*.localhost|*.internal|*.test|*.example|*.invalid|localhost)
    die "'${DOMAIN}' is in a reserved TLD (RFC 6761/6762). No real public origin can use one, so it cannot serve as cover." ;;
esac
[[ "${DOMAIN}" == *.* ]] || die "'${DOMAIN}' is a single label; cover needs a real FQDN."
[[ "${DOMAIN}" =~ ^[0-9.]+$ ]] && die "'${DOMAIN}' is an IP literal, not a name."

if [[ -n "${WINN_CERT}" ]]; then
  [[ -f "${WINN_CERT}" ]] || die "--winn-cert '${WINN_CERT}' not found."
  if openssl x509 -in "${WINN_CERT}" -noout -ext subjectAltName 2>/dev/null \
       | grep -qiE "DNS:${DOMAIN//./\\.}([,[:space:]]|$)"; then
    die "'${DOMAIN}' is a SAN on the Winn server certificate. That name is the private ECH-inner name which selects the strict profile; reusing it as cover collapses the split the cover profile exists to create."
  fi
  echo "ok  cover name does not collide with the Winn certificate's SANs"
fi

if [[ "${SKIP_DNS}" == "0" ]]; then
  RESOLVED="$(getent ahostsv4 "${DOMAIN}" 2>/dev/null | awk 'NR==1{print $1}' || true)"
  [[ -n "${RESOLVED}" ]] || die "'${DOMAIN}' does not resolve. Point an A record at this host first: ACME cannot validate a name that does not resolve, and a cover name that does not resolve is not a plausible origin."
  echo "ok  ${DOMAIN} resolves to ${RESOLVED}"
fi

[[ "$(id -u)" == "0" ]] || { echo "Run as root: certbot and ${DEST} need it." >&2; exit 1; }
command -v certbot >/dev/null || die "certbot not installed (apt install certbot)."

# ------------------------------------------------------------------- obtain
echo "==> requesting a certificate for ${DOMAIN}"
certbot certonly --standalone --non-interactive --agree-tos \
  --email "${EMAIL}" --domain "${DOMAIN}" --keep-until-expiring

LIVE="/etc/letsencrypt/live/${DOMAIN}"
[[ -f "${LIVE}/fullchain.pem" && -f "${LIVE}/privkey.pem" ]] \
  || die "certbot reported success but ${LIVE} is missing its files."

# ------------------------------------------------------- verify before install
LEAF="$(mktemp)"; trap 'rm -f "${LEAF}"' EXIT
openssl x509 -in "${LIVE}/fullchain.pem" -outform pem > "${LEAF}"

SUBJ="$(openssl x509 -in "${LEAF}" -noout -subject -nameopt sep_multiline,utf8 | tail -n +2 | sed 's/^[[:space:]]*//')"
while IFS= read -r line; do
  [[ -z "${line}" ]] && continue
  case "${line}" in
    CN=*|commonName=*) ;;
    *) die "certificate subject carries '${line}'. A cover certificate's subject may contain nothing but a Common Name; anything else exists to identify an organization or a person. This looks like an OV or EV certificate. Obtain a plain DV one." ;;
  esac
done <<<"${SUBJ}"
echo "ok  subject carries only a Common Name"

ISSUER="$(openssl x509 -in "${LEAF}" -noout -issuer)"
SUBJECT="$(openssl x509 -in "${LEAF}" -noout -subject)"
[[ "${ISSUER#issuer=}" != "${SUBJECT#subject=}" ]] || die "certificate is self-signed. No real public origin is."
echo "ok  not self-signed"

if openssl x509 -in "${LEAF}" -noout -ext basicConstraints 2>/dev/null | grep -qi "CA:TRUE"; then
  die "certificate has CA:TRUE. A leaf served to clients must not be a CA certificate."
fi
echo "ok  CA:FALSE"

CHAIN_COUNT="$(grep -c 'BEGIN CERTIFICATE' "${LIVE}/fullchain.pem")"
[[ "${CHAIN_COUNT}" -ge 2 ]] || die "fullchain.pem holds ${CHAIN_COUNT} certificate(s). A real origin serves its intermediates; a bare leaf is a distinguisher."
echo "ok  chain includes ${CHAIN_COUNT} certificates"

# ------------------------------------------------------------------ install
# 0700 like the installer creates it: install -d re-modes an existing
# directory, and this one holds every service's private keys.
install -d -m 0700 -o root -g root "${DEST}"
install -m 0644 -o root -g root "${LIVE}/fullchain.pem" "${DEST}/cover.pem"
install -m 0600 -o root -g root "${LIVE}/privkey.pem"   "${DEST}/cover-key.pem"
echo "ok  installed ${DEST}/cover.pem and ${DEST}/cover-key.pem"

# ------------------------------------------------------------------ renewal
HOOK="/etc/letsencrypt/renewal-hooks/deploy/50-winn-cover.sh"
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > "${HOOK}" <<HOOKEOF
#!/usr/bin/env bash
# Installed by obtain_cover_cert.sh. Copies the renewed cover certificate into
# place AND restarts the unit. The restart is required: rewriting the files
# alone leaves the old certificate in the running process.
set -euo pipefail
[[ "\${RENEWED_LINEAGE:-}" == "${LIVE}" ]] || exit 0
install -m 0644 -o root -g root "\${RENEWED_LINEAGE}/fullchain.pem" "${DEST}/cover.pem"
install -m 0600 -o root -g root "\${RENEWED_LINEAGE}/privkey.pem"   "${DEST}/cover-key.pem"
systemctl restart ${UNIT}
HOOKEOF
chmod 0755 "${HOOK}"
echo "ok  renewal hook at ${HOOK} (restarts ${UNIT})"

cat <<DONE

Done. Start the server with:

  -cover-cert ${DEST}/cover.pem \\
  -cover-key ${DEST}/cover-key.pem

Do NOT pass -cover-server-name ${DOMAIN}.

That flag is the PRIVATE ECH-inner SNI that selects the Winn TLS profile, not the
public cover name -- see cmd/winn3-gateway/main.go: "private ECH-inner SNI that
selects the Winn TLS profile; empty derives it from -cert". Setting it to the
public cover FQDN means a prober who sends SNI=${DOMAIN} matches the strict Winn
profile, which turns the cover into a detector for the very thing it exists to
hide. Leave it empty so it derives from -cert.

Two things this script cannot check, and they are the ones that matter most:

  1. Whether ${DOMAIN} has any public link back to Win's VPN -- registrar
     account, WHOIS, billing, shared nameservers, or being issued alongside
     another of your certificates in the same Certificate Transparency window.
  2. Whether something plausible is actually served at ${DOMAIN}. A censor who
     resolves it and finds nothing has learned something.

Both are procurement and hosting decisions, not validation. See OPERATIONS.md.
DONE
