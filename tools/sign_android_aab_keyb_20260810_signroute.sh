#!/usr/bin/env bash
# ds_signroute — sign an unsigned Win's VPN release AAB with key B (the
# Play-registered upload key) and ASSERT the resulting certificate equals key B.
#
# This is the Mac-side half of the split signing route:
#   winpc builds the UNSIGNED release AAB  ->  pulled to the Mac  ->  signed here.
# Key B never leaves the Mac. The password is read from the owner-only env file
# into shell variables and handed to jarsigner via -storepass:env / -keypass:env,
# so it never appears on a command line (ps-invisible) and is never echoed.
#
# Usage: sign_android_aab_keyb_20260810_signroute.sh <unsigned.aab> [outdir]
# Fails closed: any verification mismatch -> exit 1, no signed artifact claimed.
set -Eeuo pipefail

# Play-registered upload key for org.winsvpn.app (key B), read from the Play
# Console itself on 2026-08-10. This is the value the resulting cert MUST match.
KEY_B_SHA256="4E:BB:FF:15:A1:27:4E:7B:07:27:67:FA:37:F0:0E:8F:FB:EA:FA:B8:0C:B6:1B:51:A5:AB:59:8A:F6:DB:E6:EE"

JAR="/Users/owner/.local/jdk17/jdk-17.0.9+9/Contents/Home/bin/jarsigner"
KEYT="/Users/owner/.local/jdk17/jdk-17.0.9+9/Contents/Home/bin/keytool"
ENV_FILE="/Users/owner/.winsvpn/android-release.env"

IN="${1:?path to unsigned AAB required}"
OUTDIR="${2:-$(dirname "${IN}")}"
mkdir -p "${OUTDIR}"

[[ -f "${IN}" ]] || { echo "FAIL: input AAB missing: ${IN}"; exit 1; }
[[ -f "${ENV_FILE}" ]] || { echo "FAIL: owner-only signing env missing: ${ENV_FILE}"; exit 1; }

# Source the env into shell variables. Never print any of them.
set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

for name in WINS_ANDROID_KEYSTORE WINS_ANDROID_KEY_ALIAS WINS_ANDROID_KEY_PASSWORD WINS_ANDROID_STORE_PASSWORD; do
  [[ -n "${!name:-}" ]] || { echo "FAIL: ${name} not set by ${ENV_FILE}"; exit 1; }
done

ALIAS="${WINS_ANDROID_KEY_ALIAS}"
STORE="${WINS_ANDROID_KEYSTORE}"
expected="$(printf '%s' "${KEY_B_SHA256}" | tr -d ':' | tr '[:upper:]' '[:lower:]')"

# 1. Verify the keystore itself IS key B before touching the artifact.
report="$("${KEYT}" -list -v -keystore "${STORE}" -alias "${ALIAS}" '-storepass:env' WINS_ANDROID_STORE_PASSWORD 2>&1)"
ks_digest="$(printf '%s\n' "${report}" | sed -nE 's/^[[:space:]]*SHA256:[[:space:]]*([0-9A-Fa-f:]+)[[:space:]]*$/\1/p' | head -n1 | tr -d ':' | tr '[:upper:]' '[:lower:]')"
[[ "${ks_digest}" == "${expected}" ]] \
  || { echo "FAIL: keystore cert != key B (got ${ks_digest})"; exit 1; }
echo "KEYSTORE CERT: key B PASS"

# 2. Confirm the input is UNSIGNED (the expected pre-sign state). If it is
#    already JAR-signed with a NON-key-B cert, strip that v1 signature first so
#    key B can be applied cleanly; if it is already key B, this is a no-op.
TO_SIGN="${IN}"
sig_before="$("${JAR}" -verify "${IN}" 2>&1 || true)"
case "${sig_before}" in
  *"jar is unsigned."*)
    echo "INPUT: unsigned (expected)" ;;
  *"jar verified."*)
    cert_before="$("${KEYT}" -printcert -jarfile "${IN}" 2>&1)"
    digest_before="$(printf '%s\n' "${cert_before}" | sed -nE 's/^[[:space:]]*SHA256:[[:space:]]*([0-9A-Fa-f:]+)[[:space:]]*$/\1/p' | head -n1 | tr -d ':' | tr '[:upper:]' '[:lower:]')"
    sig_files="$(unzip -Z1 "${IN}" 2>/dev/null | grep -iE '^META-INF/.*\.(SF|RSA|DSA|EC|SIG)$' | tr '\n' ' ')"
    [[ -n "${sig_files}" ]] || { echo "FAIL: signed AAB has no removable signature files"; exit 1; }
    if [[ "${digest_before}" == "${expected}" ]]; then
      echo "INPUT: already signed with key B ($(basename "${IN}"))"
      OUT="${OUTDIR}/$(basename "${IN}" .aab)-signed-keyB.aab"
      cp "${IN}" "${OUT}"
      cert="$("${KEYT}" -printcert -jarfile "${OUT}" 2>&1)"
      digest="$(printf '%s\n' "${cert}" | sed -nE 's/^[[:space:]]*SHA256:[[:space:]]*([0-9A-Fa-f:]+)[[:space:]]*$/\1/p' | head -n1 | tr -d ':' | tr '[:upper:]' '[:lower:]')"
      [[ -n "${digest}" && "${digest}" == "${expected}" ]] \
        || { echo "FAIL: signed AAB cert != key B (got ${digest:-none})"; exit 1; }
      echo "SIGNED AAB CERT: key B PASS  ${OUT}"
      echo "SHA256: $(shasum -a 256 "${OUT}" | awk '{print $1}')"
      echo "RESULT: SIGNED_KEY_B ${OUT}"
      exit 0
    else
      echo "INPUT: signed with NON-key-B cert (${digest_before}); stripping v1 JAR signature first"
      stripped="${OUTDIR}/$(basename "${IN}" .aab).stripped.aab"
      cp "${IN}" "${stripped}"
      # shellcheck disable=SC2086
      zip -q -d "${stripped}" ${sig_files} 'META-INF/MANIFEST.MF' || { echo "FAIL: strip signature failed"; exit 1; }
      after="$("${JAR}" -verify "${stripped}" 2>&1 || true)"
      case "${after}" in
        *"jar is unsigned."*) echo "STRIP: PASS (now unsigned)" ;;
        *) echo "FAIL: strip did not produce unsigned AAB"; exit 1 ;;
      esac
      TO_SIGN="${stripped}"
    fi ;;
  *)
    echo "INPUT: unverifiable JAR signature state; proceeding as-is" ;;
esac

OUT="${OUTDIR}/$(basename "${IN}" .aab)-signed-keyB.aab"

# 3. Sign with key B. Passwords via -storepass:env / -keypass:env (never on the
#    command line as a literal, never echoed).
"${JAR}" -keystore "${STORE}" \
  '-storepass:env' WINS_ANDROID_STORE_PASSWORD \
  '-keypass:env' WINS_ANDROID_KEY_PASSWORD \
  -storetype PKCS12 \
  -sigalg SHA256withRSA -digestalg SHA-256 \
  -signedjar "${OUT}" "${TO_SIGN}" "${ALIAS}" 2>&1
echo "JARSIGNER RC: ok"

# 4. Verify integrity.
verify_out="$("${JAR}" -verify "${OUT}" 2>&1 || true)"
case "${verify_out}" in
  *"jar verified."*) echo "JAR VERIFY: PASS" ;;
  *) echo "FAIL: jarsigner did not say 'jar verified.'"; echo "${verify_out}"; exit 1 ;;
esac

# 5. Assert the resulting certificate SHA-256 == key B. A green that does not
#    check the certificate is worthless here (the exact failure that once
#    shipped a wrong-key bundle). Assert character-for-character after case
#    normalization.
cert="$("${KEYT}" -printcert -jarfile "${OUT}" 2>&1)"
digest="$(printf '%s\n' "${cert}" | sed -nE 's/^[[:space:]]*SHA256:[[:space:]]*([0-9A-Fa-f:]+)[[:space:]]*$/\1/p' | head -n1 | tr -d ':' | tr '[:upper:]' '[:lower:]')"
[[ -n "${digest}" && "${digest}" == "${expected}" ]] \
  || { echo "FAIL: signed AAB cert != key B (got ${digest:-none})"; exit 1; }

echo "SIGNED AAB CERT: key B PASS  ${OUT}"
echo "SHA256: $(shasum -a 256 "${OUT}" | awk '{print $1}')"
echo "RESULT: SIGNED_KEY_B ${OUT}"