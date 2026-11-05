#!/usr/bin/env bash
# vpnperms (2026-09-26) unit tests: the two operator-supplied TLS
# certificates inside WINN3_GATEWAY_CREDENTIALS_DIR end at 0600 after --install, the
# directory's mask-077 policy that the data-plane installer's
# verify_data_secret_permissions enforces on a co-located node.
# --install normalizes (normalize_credential_cert_modes, called from main right
# after validate_cover); --preflight only reports (report_credential_cert_modes
# from preflight_cover) and changes nothing.
# Round EX3 adds the directory-chain refusal and the held-descriptor fchmod,
# with a race harness that swaps names at a fixed point inside the helper, and
# (Turn 2) the hard-link refusal: a certificate with st_nlink != 1 is never
# changed, because the change would reach its other names.
# Pure functions against fixtures under a private mktemp directory; never
# invokes installer main, systemd, or any path under /etc.
# Test doubles, all confined to this file:
# - stat_uid_mode: fixture paths read as uid 0 (a mortal test host owns
#   them) except realpaths a case lists in FOREIGN (uid 1234); directories
#   above the fixture root read as 0:755, because the host's own /tmp and home
#   are not what a case measures. Permission bits under the fixture root are
#   always the real ones.
# - python3: a PATH shim that records each call and runs the helper under
#   racewrap.py, which gives os.fstat the same uid view as stat_uid_mode and,
#   when RACE_MODE is set, performs a rename/symlink swap immediately before
#   the helper's os.open or its os.fchmod/os.chmod.
# - chmod: recorded; the normalizer must never run the chmod command.
# The WINN3_GATEWAY_* assignments are read by the sourced installer.
# shellcheck disable=SC2034
set -euo pipefail
# In the bash macOS ships as /bin/bash (3.2.57, measured 2026-09-26) a failing
# [[ ]] does not stop set -e, which silences every assertion below except the
# last of each case. Refuse such a bash instead of passing in it, and run the
# cases in the bash that runs this driver.
if "${BASH}" -c 'set -e; [[ 1 == 2 ]]; exit 0'; then
  printf 'refusing to run: in %s (%s) a failing [[ ]] does not stop set -e\n' "${BASH}" "${BASH_VERSION}" >&2
  exit 2
fi
export WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO:-$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/testdata/winn3_gateway_meminfo/large}"
HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
if [[ "${1:-}" != --case ]]; then
  INSTALL="$(python3 -B "${HERE}/../tools/winn3_gateway_test_source.py" "${1:-${HERE}/wins_data_plane_setup_ONETOUCH.sh}" --legacy-compat)"
  FIXTURES="$(mktemp -d "${TMPDIR:-/tmp}/winn3-cert-modes.XXXXXX")"
  trap 'rm -rf "${FIXTURES}"' EXIT
  for test_case in normalize outside preflight symlink_escape already_private \
      foreign_owner dir_not_private ancestor_unsafe hardlink helper_direct race local_var wiring; do
    env -i PATH=/usr/bin:/bin LC_ALL=C WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO}" \
      FIXTURES="${FIXTURES}" "${BASH}" "$0" --case "${test_case}" "${INSTALL}"
    printf 'PASS %s\n' "${test_case}"
  done
  exit
fi
test_case="$2"
INSTALL="$3"
umask 022
WINN3_GATEWAY_ID=synthetic-test
WINN3_GATEWAY_PATH_MTU=1450
WINN3_GATEWAY_INNER_V4=192.0.2.1
# shellcheck disable=SC1090
source "${INSTALL}"

ROOT_DIR="${FIXTURES}/${test_case}"
mkdir -p "${ROOT_DIR}"
FIXTURES_REAL="$(readlink -f -- "${FIXTURES}")"
ROOT_REAL="$(readlink -f -- "${ROOT_DIR}")"
CALLS="${ROOT_DIR}/mode.calls"
: > "${CALLS}"
FOREIGN=()
export RACE_MODE='' RACE_PATH='' RACE_DIR='' RACE_MOVED='' RACE_TARGET='' FOREIGN_PY=''

# python3 shim: record the call, then run the helper under racewrap.py.
REAL_PY="$(command -v python3)"
mkdir -p "${ROOT_DIR}/bin"
cat > "${ROOT_DIR}/bin/racewrap.py" <<'PYEOF'
import os
import sys

_open, _fchmod, _chmod, _fstat = os.open, os.fchmod, os.chmod, os.fstat
mode = os.environ.get("RACE_MODE", "")
state = {"done": False}
foreign = set()
for p in filter(None, os.environ.get("FOREIGN_PY", "").split("\n")):
    try:
        st = os.stat(p, follow_symlinks=False)
        foreign.add((st.st_dev, st.st_ino))
    except OSError:
        pass


def swap(kind):
    if state["done"] or mode != kind:
        return
    state["done"] = True
    if kind in ("dir_before_open", "dir_before_chmod"):
        # The whole credentials directory becomes a symlink to an outside
        # directory holding a same-named file.
        os.rename(os.environ["RACE_DIR"], os.environ["RACE_MOVED"])
        os.symlink(os.environ["RACE_TARGET"], os.environ["RACE_DIR"])
    elif kind == "cert_before_open":
        # The certificate name itself becomes a symlink to an outside file.
        os.rename(os.environ["RACE_PATH"], os.environ["RACE_MOVED"])
        os.symlink(os.environ["RACE_TARGET"], os.environ["RACE_PATH"])
    elif kind in ("hardlink_before_open", "hardlink_before_chmod"):
        # A second name for the certificate's inode appears outside.
        os.link(os.environ["RACE_PATH"], os.environ["RACE_TARGET"])


class _Stat:
    def __init__(self, st):
        self._st = st
        self.st_uid = 1234 if (st.st_dev, st.st_ino) in foreign else 0

    def __getattr__(self, name):
        return getattr(self._st, name)


def hooked_open(path, *a, **k):
    if path == os.environ.get("RACE_PATH"):
        swap("dir_before_open")
        swap("cert_before_open")
        swap("hardlink_before_open")
    return _open(path, *a, **k)


def hooked_fchmod(fd, m):
    swap("dir_before_chmod")
    swap("hardlink_before_chmod")
    return _fchmod(fd, m)


def hooked_chmod(path, m, *a, **k):
    swap("dir_before_chmod")
    swap("hardlink_before_chmod")
    return _chmod(path, m, *a, **k)


def hooked_fstat(fd):
    return _Stat(_fstat(fd))


os.open, os.fchmod, os.chmod, os.fstat = hooked_open, hooked_fchmod, hooked_chmod, hooked_fstat
if sys.argv[1] != "-":
    sys.exit("racewrap: expected a script on stdin")
code = sys.stdin.read()
sys.argv = ["-"] + sys.argv[2:]
exec(compile(code, "<stdin>", "exec"), {"__name__": "__main__"})
PYEOF
cat > "${ROOT_DIR}/bin/python3" <<EOF
#!/bin/sh
printf 'python3 %s\n' "\$*" >> "${CALLS}"
exec "${REAL_PY}" "${ROOT_DIR}/bin/racewrap.py" "\$@"
EOF
command chmod 755 "${ROOT_DIR}/bin/python3"
PATH="${ROOT_DIR}/bin:${PATH}"

eval "real_stat_uid_mode() $(declare -f stat_uid_mode | tail -n +2)"
stat_uid_mode() {
  local out real f
  out="$(real_stat_uid_mode "$1")" || return 1
  real="$(readlink -f -- "$1" 2>/dev/null || true)"
  if [[ "${real}" != "${FIXTURES_REAL}" && "${real}" != "${FIXTURES_REAL}/"* ]]; then
    printf '0:755\n'
    return 0
  fi
  for f in "${FOREIGN[@]+"${FOREIGN[@]}"}"; do
    if [[ -n "${real}" && "${real}" == "${f}" && ! -L "$1" ]]; then
      printf '1234:%s\n' "${out#*:}"
      return 0
    fi
  done
  printf '0:%s\n' "${out#*:}"
}
set_foreign() {
  FOREIGN=("$@")
  FOREIGN_PY="$(printf '%s\n' "$@")"
}
chmod() {
  printf 'chmod %s\n' "$*" >> "${CALLS}"
  command chmod "$@"
}

mode_of() {
  local out
  out="$(real_stat_uid_mode "$1")"
  printf '%s\n' "${out#*:}"
}

calls() { wc -l < "${CALLS}" | tr -d ' '; }
chmod_calls() { grep -c '^chmod ' "${CALLS}" || true; }

# $1 directory: a credentials directory at 0700 with the three key files
# (0600) the cover gate also checks. Sets WINN3_GATEWAY_CREDENTIALS_DIR and the key vars.
make_cred_dir() {
  local d="$1"
  mkdir -p "${d}"
  command chmod 0700 "${d}"
  WINN3_GATEWAY_CREDENTIALS_DIR="${d}"
  WINN3_GATEWAY_COVER_KEY="${d}/cover-key.pem"
  WINN3_GATEWAY_ECH_KEYS="${d}/ech-keys.json"
  WINN3_GATEWAY_WINN_KEY="${d}/winn-leaf-key.pem"
  local k
  for k in "${WINN3_GATEWAY_COVER_KEY}" "${WINN3_GATEWAY_ECH_KEYS}" "${WINN3_GATEWAY_WINN_KEY}"; do
    printf 'k\n' > "${k}"
    command chmod 0600 "${k}"
  done
}

# $1 path, $2 mode
make_cert() {
  mkdir -p "$(dirname -- "$1")"
  printf 'cert\n' > "$1"
  command chmod "$2" "$1"
}

strip_colour() { sed $'s/\033\\[[0-9;]*m//g'; }

# Two 0644 certificates in a fresh credentials directory under ROOT_DIR/$1.
two_certs() {
  cred="${ROOT_DIR}/$1/etc/winn/credentials"
  make_cred_dir "${cred}"
  WINN3_GATEWAY_COVER_CERT="${cred}/cover.pem"
  WINN3_GATEWAY_WINN_CERT="${cred}/winn-leaf.pem"
  make_cert "${WINN3_GATEWAY_COVER_CERT}" 0644
  make_cert "${WINN3_GATEWAY_WINN_CERT}" 0644
}

case "${test_case}" in
  normalize)
    cred="${ROOT_DIR}/etc/winn/credentials"
    make_cred_dir "${cred}"
    WINN3_GATEWAY_COVER_CERT="${cred}/cover.pem"
    WINN3_GATEWAY_WINN_CERT="${cred}/winn-leaf.pem"
    make_cert "${WINN3_GATEWAY_COVER_CERT}" 0644
    make_cert "${WINN3_GATEWAY_WINN_CERT}" 0640
    # The existing gate passes on these: 0644 is not refused for a certificate.
    validate_cover >/dev/null
    msg="$(normalize_credential_cert_modes 2>&1 | strip_colour)"
    [[ "$(mode_of "${WINN3_GATEWAY_COVER_CERT}")" == 600 ]]
    [[ "$(mode_of "${WINN3_GATEWAY_WINN_CERT}")" == 600 ]]
    # Two held-descriptor helper runs, and never the chmod command.
    [[ "$(calls)" == 2 && "$(chmod_calls)" == 0 ]]
    [[ "$(grep -c 'Normalized certificate' <<< "${msg}")" == 2 ]]
    [[ "${msg}" == *"Normalized certificate ${WINN3_GATEWAY_COVER_CERT} "*"from 644 to 0600"* ]]
    [[ "${msg}" == *"Normalized certificate ${WINN3_GATEWAY_WINN_CERT} "*"from 640 to 0600"* ]]
    # Keys are never touched by this step.
    [[ "$(mode_of "${WINN3_GATEWAY_COVER_KEY}")" == 600 ]]
    # Idempotent: a second run changes and logs nothing.
    msg="$(normalize_credential_cert_modes 2>&1 | strip_colour)"
    [[ "$(calls)" == 2 && "${msg}" != *'Normalized'* ]]
    # A credentials directory reached through a symlink still counts: the
    # comparison is realpath to realpath.
    alias_dir="${ROOT_DIR}/alias"
    ln -s "${cred}" "${alias_dir}"
    command chmod 0644 "${WINN3_GATEWAY_COVER_CERT}"
    WINN3_GATEWAY_CREDENTIALS_DIR="${alias_dir}"
    WINN3_GATEWAY_COVER_CERT="${alias_dir}/cover.pem"
    msg="$(normalize_credential_cert_modes 2>&1 | strip_colour)"
    [[ "$(mode_of "${cred}/cover.pem")" == 600 && "$(calls)" == 3 ]]
    [[ "$(grep -c 'Normalized certificate' <<< "${msg}")" == 1 ]]
    ;;
  outside)
    cred="${ROOT_DIR}/etc/winn/credentials"
    make_cred_dir "${cred}"
    # A sibling whose name shares the directory's prefix is still outside.
    WINN3_GATEWAY_COVER_CERT="${ROOT_DIR}/etc/winn/credentials-other/cover.pem"
    WINN3_GATEWAY_WINN_CERT="${ROOT_DIR}/etc/ssl/winn-leaf.pem"
    make_cert "${WINN3_GATEWAY_COVER_CERT}" 0644
    make_cert "${WINN3_GATEWAY_WINN_CERT}" 0644
    validate_cover >/dev/null
    msg="$(normalize_credential_cert_modes 2>&1 | strip_colour)"
    [[ "$(mode_of "${WINN3_GATEWAY_COVER_CERT}")" == 644 ]]
    [[ "$(mode_of "${WINN3_GATEWAY_WINN_CERT}")" == 644 ]]
    [[ "$(calls)" == 0 && "${msg}" != *'Normalized'* ]]
    # Preflight is silent about them too: 0644 is their ordinary mode there.
    msg="$(preflight_cover 2>&1 | strip_colour)"
    [[ "${msg}" != *'will normalize'* ]]
    # A credentials directory that does not exist resolves nowhere: nothing is touched.
    WINN3_GATEWAY_CREDENTIALS_DIR="${ROOT_DIR}/does-not-exist"
    WINN3_GATEWAY_WINN_CERT="${cred}/winn-leaf.pem"
    make_cert "${WINN3_GATEWAY_WINN_CERT}" 0644
    normalize_credential_cert_modes >/dev/null 2>&1
    [[ "$(mode_of "${WINN3_GATEWAY_WINN_CERT}")" == 644 && "$(calls)" == 0 ]]
    ;;
  preflight)
    cred="${ROOT_DIR}/etc/winn/credentials"
    make_cred_dir "${cred}"
    WINN3_GATEWAY_COVER_CERT="${cred}/cover.pem"
    WINN3_GATEWAY_WINN_CERT="${cred}/winn-leaf.pem"
    make_cert "${WINN3_GATEWAY_COVER_CERT}" 0644
    make_cert "${WINN3_GATEWAY_WINN_CERT}" 0604
    rc=0
    msg="$(preflight_cover 2>&1 | strip_colour)" || rc=$?
    # Complete material: preflight_cover passes, and REPORTS both certificates.
    [[ "${rc}" == 0 ]]
    [[ "${msg}" == *"certificate ${WINN3_GATEWAY_COVER_CERT} has mode 644 inside ${cred}; --install will normalize it to 0600"* ]]
    [[ "${msg}" == *"certificate ${WINN3_GATEWAY_WINN_CERT} has mode 604 inside ${cred}; --install will normalize it to 0600"* ]]
    [[ "$(grep -c -- '--preflight changed nothing' <<< "${msg}")" == 2 ]]
    # ...and changes nothing.
    [[ "$(mode_of "${WINN3_GATEWAY_COVER_CERT}")" == 644 ]]
    [[ "$(mode_of "${WINN3_GATEWAY_WINN_CERT}")" == 604 ]]
    [[ "$(calls)" == 0 && "${msg}" != *'Normalized'* ]]
    # The reporter alone, too.
    report_credential_cert_modes >/dev/null 2>&1
    [[ "$(mode_of "${WINN3_GATEWAY_COVER_CERT}")" == 644 && "$(calls)" == 0 ]]
    # Private certificates produce no report line.
    command chmod 0600 "${WINN3_GATEWAY_COVER_CERT}" "${WINN3_GATEWAY_WINN_CERT}"
    msg="$(preflight_cover 2>&1 | strip_colour)"
    [[ "${msg}" != *'will normalize'* && "$(calls)" == 0 ]]
    ;;
  symlink_escape)
    cred="${ROOT_DIR}/etc/winn/credentials"
    make_cred_dir "${cred}"
    outside="${ROOT_DIR}/outside"
    make_cert "${outside}/victim.pem" 0644
    make_cert "${outside}/sub/victim2.pem" 0644
    make_cert "${cred}/winn-leaf.pem" 0600
    WINN3_GATEWAY_WINN_CERT="${cred}/winn-leaf.pem"
    # (a) The certificate name itself is a symlink leaving the directory: the
    # existing gate refuses it, in the install step and in preflight alike,
    # and the target keeps its mode.
    ln -s "${outside}/victim.pem" "${cred}/cover.pem"
    WINN3_GATEWAY_COVER_CERT="${cred}/cover.pem"
    rc=0
    msg="$(normalize_credential_cert_modes 2>&1 | strip_colour)" || rc=$?
    [[ "${rc}" != 0 && "${msg}" == *'is a symlink'* ]]
    [[ "$(mode_of "${outside}/victim.pem")" == 644 && "$(calls)" == 0 ]]
    rc=0
    (preflight_cover >/dev/null 2>&1) || rc=$?
    [[ "${rc}" != 0 && "$(mode_of "${outside}/victim.pem")" == 644 && "$(calls)" == 0 ]]
    # (b) A directory symlink inside the credentials directory: the last
    # component is a regular root-owned file, so the gate passes, but its
    # realpath is outside. Untouched, not logged, not reported.
    ln -s "${outside}/sub" "${cred}/esc"
    WINN3_GATEWAY_COVER_CERT="${cred}/esc/victim2.pem"
    validate_cover >/dev/null
    msg="$(normalize_credential_cert_modes 2>&1 | strip_colour)"
    [[ "$(mode_of "${outside}/sub/victim2.pem")" == 644 ]]
    [[ "$(calls)" == 0 && "${msg}" != *'Normalized'* ]]
    msg="$(preflight_cover 2>&1 | strip_colour)"
    [[ "${msg}" != *'will normalize'* && "$(calls)" == 0 ]]
    ;;
  already_private)
    cred="${ROOT_DIR}/etc/winn/credentials"
    make_cred_dir "${cred}"
    WINN3_GATEWAY_COVER_CERT="${cred}/cover.pem"
    WINN3_GATEWAY_WINN_CERT="${cred}/winn-leaf.pem"
    make_cert "${WINN3_GATEWAY_COVER_CERT}" 0600
    make_cert "${WINN3_GATEWAY_WINN_CERT}" 0400
    rc=0
    msg="$(normalize_credential_cert_modes 2>&1 | strip_colour)" || rc=$?
    [[ "${rc}" == 0 ]]
    [[ "$(mode_of "${WINN3_GATEWAY_COVER_CERT}")" == 600 ]]
    # 0400 has no group/other bit: left alone, not raised to 0600.
    [[ "$(mode_of "${WINN3_GATEWAY_WINN_CERT}")" == 400 ]]
    [[ "$(calls)" == 0 ]]
    [[ -z "${msg}" ]]
    ;;
  foreign_owner)
    cred="${ROOT_DIR}/etc/winn/credentials"
    make_cred_dir "${cred}"
    WINN3_GATEWAY_COVER_CERT="${cred}/cover.pem"
    WINN3_GATEWAY_WINN_CERT="${cred}/winn-leaf.pem"
    make_cert "${WINN3_GATEWAY_COVER_CERT}" 0644
    make_cert "${WINN3_GATEWAY_WINN_CERT}" 0644
    set_foreign "$(readlink -f -- "${WINN3_GATEWAY_COVER_CERT}")"
    rc=0
    msg="$(normalize_credential_cert_modes 2>&1 | strip_colour)" || rc=$?
    [[ "${rc}" != 0 && "${msg}" == *'is owned by uid 1234, not root'* ]]
    [[ "$(mode_of "${WINN3_GATEWAY_COVER_CERT}")" == 644 && "$(calls)" == 0 ]]
    # Same file as the Winn leaf slot, second in the loop: the first (root)
    # certificate is normalized, then the foreign one refuses, unchanged.
    set_foreign "$(readlink -f -- "${WINN3_GATEWAY_WINN_CERT}")"
    rc=0
    msg="$(normalize_credential_cert_modes 2>&1 | strip_colour)" || rc=$?
    [[ "${rc}" != 0 && "${msg}" == *'is owned by uid 1234, not root'* ]]
    [[ "$(mode_of "${WINN3_GATEWAY_COVER_CERT}")" == 600 ]]
    [[ "$(mode_of "${WINN3_GATEWAY_WINN_CERT}")" == 644 && "$(calls)" == 1 ]]
    ;;
  dir_not_private)
    cred="${ROOT_DIR}/etc/winn/credentials"
    make_cred_dir "${cred}"
    command chmod 0750 "${cred}"
    WINN3_GATEWAY_COVER_CERT="${cred}/cover.pem"
    WINN3_GATEWAY_WINN_CERT="${cred}/winn-leaf.pem"
    make_cert "${WINN3_GATEWAY_COVER_CERT}" 0644
    make_cert "${WINN3_GATEWAY_WINN_CERT}" 0644
    rc=0
    msg="$(normalize_credential_cert_modes 2>&1 | strip_colour)" || rc=$?
    [[ "${rc}" != 0 && "${msg}" == *'the credentials directory must have no group/other bit'* ]]
    [[ "$(mode_of "${WINN3_GATEWAY_COVER_CERT}")" == 644 && "$(calls)" == 0 ]]
    msg="$(preflight_cover 2>&1 | strip_colour)"
    [[ "${msg}" == *'its directory chain is unsafe'* && "$(calls)" == 0 ]]
    ;;
  ancestor_unsafe)
    # Every directory from the certificate's parent up to / must be root-owned
    # with no group/other write bit. Each variant: install refuses naming the
    # directory, nothing changes (no helper run), preflight reports it.
    check_refused() {  # $1 offending directory (as created), $2 message fragment
      local rc=0 msg real
      real="$(readlink -f -- "$1")"
      msg="$(normalize_credential_cert_modes 2>&1 | strip_colour)" || rc=$?
      [[ "${rc}" != 0 ]]
      [[ "${msg}" == *"its directory chain is unsafe (${real} $2"* ]]
      [[ "$(mode_of "${WINN3_GATEWAY_COVER_CERT}")" == 644 ]]
      [[ "$(mode_of "${WINN3_GATEWAY_WINN_CERT}")" == 644 ]]
      [[ "$(calls)" == 0 ]]
      rc=0
      msg="$(preflight_cover 2>&1 | strip_colour)" || rc=$?
      [[ "${rc}" == 0 ]]
      [[ "$(grep -c "directory chain is unsafe: ${real} $2" <<< "${msg}")" == 2 ]]
      [[ "$(mode_of "${WINN3_GATEWAY_COVER_CERT}")" == 644 && "$(calls)" == 0 ]]
    }
    # Group-writable grandparent.
    two_certs group
    command chmod 0775 "${ROOT_DIR}/group/etc/winn"
    check_refused "${ROOT_DIR}/group/etc/winn" 'has mode 775 (group/other write'
    # Grandparent owned by uid 1234, mode 0755.
    two_certs owner
    set_foreign "$(readlink -f -- "${ROOT_DIR}/owner/etc")"
    check_refused "${ROOT_DIR}/owner/etc" 'is owned by uid 1234, not root'
    set_foreign
    # Sticky world-writable parent-of-parent, the /tmp shape: still unsafe.
    two_certs sticky
    command chmod 1777 "${ROOT_DIR}/sticky/etc"
    check_refused "${ROOT_DIR}/sticky/etc" 'has mode '
    msg="$(normalize_credential_cert_modes 2>&1 | strip_colour || true)"
    [[ "${msg}" == *'77 (group/other write; sticky does not make it safe)'* ]]
    # A group-writable directory BETWEEN the credentials directory and the
    # certificate counts too.
    two_certs sub
    mkdir -p "${cred}/sub"
    command chmod 0770 "${cred}/sub"
    WINN3_GATEWAY_COVER_CERT="${cred}/sub/cover.pem"
    make_cert "${WINN3_GATEWAY_COVER_CERT}" 0644
    rc=0
    msg="$(normalize_credential_cert_modes 2>&1 | strip_colour)" || rc=$?
    [[ "${rc}" != 0 && "${msg}" == *"$(readlink -f -- "${cred}/sub") has mode 770"* ]]
    [[ "$(mode_of "${WINN3_GATEWAY_COVER_CERT}")" == 644 && "$(calls)" == 0 ]]
    # Control: the same tree once safe is normalized.
    command chmod 0755 "${cred}/sub"
    normalize_credential_cert_modes >/dev/null
    [[ "$(mode_of "${WINN3_GATEWAY_COVER_CERT}")" == 600 && "$(calls)" == 2 ]]
    ;;
  hardlink)
    # A real hard link: the certificate inside the directory and a name
    # outside it share one inode. Every other gate passes (same owner, same
    # dev/ino); only the link count tells them apart.
    two_certs hl
    outside="${ROOT_DIR}/hl/outside"
    mkdir -p "${outside}"
    ln "${WINN3_GATEWAY_COVER_CERT}" "${outside}/victim.pem"
    [[ "$(stat_nlink "${outside}/victim.pem")" == 2 ]]
    validate_cover >/dev/null
    rc=0
    msg="$(normalize_credential_cert_modes 2>&1 | strip_colour)" || rc=$?
    # The outside name keeps 0644 (and so does the shared inode); no helper ran.
    [[ "$(mode_of "${outside}/victim.pem")" == 644 && "$(mode_of "${WINN3_GATEWAY_COVER_CERT}")" == 644 ]]
    [[ "${rc}" != 0 && "${msg}" == *"certificate ${WINN3_GATEWAY_COVER_CERT}: it has 2 hard links"* ]]
    [[ "$(calls)" == 0 && "${msg}" != *'Normalized certificate'* ]]
    # Preflight reports it and changes nothing.
    rc=0
    msg="$(preflight_cover 2>&1 | strip_colour)" || rc=$?
    [[ "${rc}" == 0 && "${msg}" == *"certificate ${WINN3_GATEWAY_COVER_CERT} has 2 hard links; --install will REFUSE"* ]]
    [[ "$(mode_of "${outside}/victim.pem")" == 644 && "$(calls)" == 0 ]]
    # An already-private hard-linked certificate needs no change: left alone.
    command chmod 0600 "${WINN3_GATEWAY_COVER_CERT}"
    rc=0
    msg="$(normalize_credential_cert_modes 2>&1 | strip_colour)" || rc=$?
    [[ "${rc}" == 0 && "$(grep -c 'Normalized certificate' <<< "${msg}")" == 1 ]]
    [[ "${msg}" == *"Normalized certificate ${WINN3_GATEWAY_WINN_CERT} "* ]]
    [[ "$(mode_of "${outside}/victim.pem")" == 600 && "$(calls)" == 1 ]]
    # Removing the second name makes the first certificate changeable again.
    command chmod 0644 "${WINN3_GATEWAY_COVER_CERT}"
    rm -f "${outside}/victim.pem"
    normalize_credential_cert_modes >/dev/null
    [[ "$(mode_of "${WINN3_GATEWAY_COVER_CERT}")" == 600 && "$(calls)" == 2 ]]
    ;;
  helper_direct)
    # fchmod_credential_cert_held_fd on its own, each refusal in isolation.
    dir="${ROOT_DIR}/d"
    mkdir -p "${dir}"
    make_cert "${dir}/ok.pem" 0644
    ident() { stat_dev_ino "$(readlink -f -- "$1")" | tr ':' ' '; }
    read -r dev ino <<< "$(ident "${dir}/ok.pem")"
    real="$(readlink -f -- "${dir}/ok.pem")"
    [[ "$(fchmod_credential_cert_held_fd "${real}" "${dev}" "${ino}")" == 644 ]]
    [[ "$(mode_of "${real}")" == 600 ]]
    # Foreign owner seen on the descriptor.
    make_cert "${dir}/foreign.pem" 0644
    real="$(readlink -f -- "${dir}/foreign.pem")"
    read -r dev ino <<< "$(ident "${real}")"
    set_foreign "${real}"
    rc=0
    msg="$(fchmod_credential_cert_held_fd "${real}" "${dev}" "${ino}" 2>&1)" || rc=$?
    [[ "${rc}" != 0 && "${msg}" == *'owned by uid 1234 once opened, not root'* ]]
    [[ "$(mode_of "${real}")" == 644 ]]
    set_foreign
    # A symlink at the name: O_NOFOLLOW.
    make_cert "${dir}/target.pem" 0644
    ln -s "${dir}/target.pem" "${dir}/link.pem"
    read -r dev ino <<< "$(ident "${dir}/target.pem")"
    rc=0
    msg="$(fchmod_credential_cert_held_fd "$(readlink -f -- "${dir}")/link.pem" "${dev}" "${ino}" 2>&1)" || rc=$?
    [[ "${rc}" != 0 && "${msg}" == *'O_NOFOLLOW refused it'* ]]
    [[ "$(mode_of "${dir}/target.pem")" == 644 ]]
    # Wrong identity: dev/ino of another file.
    make_cert "${dir}/other.pem" 0644
    read -r dev ino <<< "$(ident "${dir}/other.pem")"
    real="$(readlink -f -- "${dir}/target.pem")"
    rc=0
    msg="$(fchmod_credential_cert_held_fd "${real}" "${dev}" "${ino}" 2>&1)" || rc=$?
    [[ "${rc}" != 0 && "${msg}" == *'changed between the directory walk and the open'* ]]
    [[ "$(mode_of "${real}")" == 644 ]]
    # Not a regular file.
    mkdir -p "${dir}/notreg"
    command chmod 0755 "${dir}/notreg"
    read -r dev ino <<< "$(ident "${dir}/notreg")"
    rc=0
    msg="$(fchmod_credential_cert_held_fd "$(readlink -f -- "${dir}/notreg")" "${dev}" "${ino}" 2>&1)" || rc=$?
    [[ "${rc}" != 0 && "${msg}" == *'is not a regular file once opened'* ]]
    [[ "$(mode_of "${dir}/notreg")" == 755 ]]
    # A hard-linked file with its correct identity: refused on the descriptor,
    # and the other name keeps its mode.
    make_cert "${dir}/linked.pem" 0644
    ln "${dir}/linked.pem" "${ROOT_DIR}/second-name.pem"
    real="$(readlink -f -- "${dir}/linked.pem")"
    read -r dev ino <<< "$(ident "${real}")"
    rc=0
    msg="$(fchmod_credential_cert_held_fd "${real}" "${dev}" "${ino}" 2>&1)" || rc=$?
    [[ "$(mode_of "${ROOT_DIR}/second-name.pem")" == 644 && "$(mode_of "${real}")" == 644 ]]
    [[ "${rc}" != 0 && "${msg}" == *'has 2 hard links once opened'* ]]
    [[ "$(chmod_calls)" == 0 ]]
    ;;
  race)
    # A deterministic swap at a fixed point inside the helper, after every bash
    # gate and the directory walk have passed. The outside file must never
    # change. $1 race mode; sets up a fresh tree under ROOT_DIR/$1.
    setup_race() {
      two_certs "$1"
      evil="${ROOT_DIR}/$1/evil"
      mkdir -p "${evil}"
      make_cert "${evil}/cover.pem" 0644
      RACE_MODE="$1"
      RACE_PATH="$(readlink -f -- "${WINN3_GATEWAY_COVER_CERT}")"
      RACE_DIR="$(readlink -f -- "${cred}")"
      RACE_MOVED="${ROOT_DIR}/$1/moved"
      RACE_TARGET="${evil}"
    }
    # Control: the shim and hook in place, no swap.
    setup_race none
    normalize_credential_cert_modes >/dev/null
    [[ "$(mode_of "${WINN3_GATEWAY_COVER_CERT}")" == 600 && "$(calls)" == 2 ]]
    : > "${CALLS}"
    # (1) The credentials directory becomes a symlink to evil/ between the
    # gates and the open. O_NOFOLLOW does not see it (the final component is a
    # regular file); the dev/ino comparison refuses.
    setup_race dir_before_open
    rc=0
    msg="$(normalize_credential_cert_modes 2>&1 | strip_colour)" || rc=$?
    [[ -L "${cred}" && -d "${RACE_MOVED}" ]]
    [[ "${rc}" != 0 && "${msg}" == *'changed between the directory walk and the open'* ]]
    [[ "$(mode_of "${evil}/cover.pem")" == 644 ]]
    [[ "$(mode_of "${RACE_MOVED}/cover.pem")" == 644 ]]
    # (2) The certificate name becomes a symlink to evil/cover.pem between the
    # gates and the open: O_NOFOLLOW refuses it.
    setup_race cert_before_open
    RACE_TARGET="${evil}/cover.pem"
    RACE_MOVED="${RACE_DIR}/cover.pem.orig"
    rc=0
    msg="$(normalize_credential_cert_modes 2>&1 | strip_colour)" || rc=$?
    [[ -L "${RACE_PATH}" ]]
    [[ "${rc}" != 0 && "${msg}" == *'is a symlink now (O_NOFOLLOW refused it)'* ]]
    [[ "$(mode_of "${evil}/cover.pem")" == 644 && "$(mode_of "${RACE_MOVED}")" == 644 ]]
    # (3) The directory is swapped after every check, immediately before the
    # mode change. The descriptor still names the checked inode, so only that
    # inode changes; the name check then reports the swap.
    setup_race dir_before_chmod
    rc=0
    msg="$(normalize_credential_cert_modes 2>&1 | strip_colour)" || rc=$?
    [[ -L "${cred}" && -d "${RACE_MOVED}" ]]
    [[ "${rc}" != 0 && "${msg}" == *'was replaced while its mode was being normalized'* ]]
    [[ "$(mode_of "${evil}/cover.pem")" == 644 ]]
    [[ "$(mode_of "${RACE_MOVED}/cover.pem")" == 600 ]]
    # (4) A hard link to the certificate appears outside after every bash
    # gate, before the open: the descriptor's st_nlink refuses; the outside
    # name keeps 0644.
    setup_race hardlink_before_open
    RACE_TARGET="${evil}/linked.pem"
    rc=0
    msg="$(normalize_credential_cert_modes 2>&1 | strip_colour)" || rc=$?
    [[ "$(mode_of "${evil}/linked.pem")" == 644 ]]
    [[ "$(stat_nlink "${evil}/linked.pem")" == 2 ]]
    [[ "${rc}" != 0 && "${msg}" == *'has 2 hard links once opened'* ]]
    # (5) The hard link appears after the descriptor checks, immediately
    # before fchmod. The change reaches the new name (one inode); the re-check
    # after fchmod reports it and the install stops.
    setup_race hardlink_before_chmod
    RACE_TARGET="${evil}/linked.pem"
    rc=0
    msg="$(normalize_credential_cert_modes 2>&1 | strip_colour)" || rc=$?
    [[ "$(stat_nlink "${evil}/linked.pem")" == 2 ]]
    [[ "${rc}" != 0 && "${msg}" == *'gained hard links while its mode was being normalized (now 2)'* ]]
    [[ "$(chmod_calls)" == 0 ]]
    ;;
  local_var)
    # The loop variables are local: a caller's variables survive the calls.
    two_certs lv
    p=caller-p out=caller-out rc=caller-rc rest=caller-rest cert_real=caller-cr
    cert_mode=caller-cm cert_dev=caller-cd cert_ino=caller-ci old=caller-old
    normalize_credential_cert_modes >/dev/null
    report_credential_cert_modes >/dev/null 2>&1
    [[ "${p}" == caller-p && "${out}" == caller-out && "${rc}" == caller-rc && "${rest}" == caller-rest ]]
    [[ "${cert_real}" == caller-cr && "${cert_mode}" == caller-cm && "${cert_dev}" == caller-cd ]]
    [[ "${cert_ino}" == caller-ci && "${old}" == caller-old ]]
    [[ "$(mode_of "${WINN3_GATEWAY_COVER_CERT}")" == 600 ]]
    ;;
  wiring)
    fn_body() { awk -v f="$1" '$0 == f"() {" {p=1} p {print} p && $0 == "}" {exit}' "${INSTALL}"; }
    body="$(fn_body main)"
    # --install/--start: the normalization runs after validate_cover and
    # before the unit is written.
    after_config="${body#*Refusing to install with an incomplete configuration.}"
    [[ "${after_config}" != "${body}" ]]
    before_unit="${after_config%%$'\n'  write_unit*}"
    [[ "${before_unit}" != "${after_config}" ]]
    after_cover="${before_unit#*$'\n'  validate_cover$'\n'}"
    [[ "${after_cover}" != "${before_unit}" ]]
    [[ "${after_cover}" == *$'\n  normalize_credential_cert_modes\n'* ]]
    [[ "${before_unit%%$'\n'  validate_cover$'\n'*}" != *normalize_credential_cert_modes* ]]
    # --preflight: the reporter, never the normalizer or the helper.
    preflight_branch="${body#*if [[ \"\${WINN3_GATEWAY_MODE}\" == \"preflight\" ]]; then}"
    preflight_branch="${preflight_branch%%Preflight passed*}"
    [[ "${preflight_branch}" != *normalize_credential_cert_modes* ]]
    [[ "${preflight_branch}" != *fchmod_credential_cert_held_fd* ]]
    [[ "$(fn_body preflight_cover)" == *$'\n  report_credential_cert_modes\n'* ]]
    # validate_cover keeps its refuse-before-anything-is-written contract, and
    # the read-only functions contain no chmod of any kind.
    for f in validate_cover preflight_cover report_credential_cert_modes credential_cert_mode_status \
        credential_cert_dir_chain_problem stat_dev_ino stat_nlink normalize_credential_cert_modes; do
      text="$(fn_body "${f}")"
      [[ -n "${text}" && "${text}" != *chmod\ * ]]
    done
    # The helper changes a mode exactly once, through the descriptor.
    helper="$(fn_body fchmod_credential_cert_held_fd)"
    [[ "$(grep -c 'os\.fchmod(fd, 0o600)' <<< "${helper}")" == 1 ]]
    [[ "${helper}" != *'os.chmod('* && "${helper}" != *'os.lchmod('* ]]
    # shellcheck disable=SC2016  # a literal line of installer source
    [[ "$(fn_body normalize_credential_cert_modes)" == *'fchmod_credential_cert_held_fd "${cert_real}"'* ]]
    ;;
  *) exit 2 ;;
esac
