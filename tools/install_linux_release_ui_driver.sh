#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DRIVER_SOURCE="${ROOT}/tools/linux_release_ui_driver.py"
CANARY_SOURCE="${ROOT}/tools/linux_split_tunnel_live_canary.sh"
INSTALL_ROOT=/usr/local/libexec
DRIVER_TARGET="${INSTALL_ROOT}/winsvpn-release-ui-driver.py"
CANARY_TARGET="${INSTALL_ROOT}/winsvpn-release-split-canary.sh"

[[ "$(uname -s)" == Linux ]] || {
  echo 'The Linux release UI driver can only be installed on Linux.' >&2
  exit 64
}
[[ "${EUID}" -eq 0 ]] || {
  echo 'Run this installer as root.' >&2
  exit 77
}

if [[ "${1:-}" == --uninstall ]]; then
  rm -f -- "${DRIVER_TARGET}" "${CANARY_TARGET}"
  rmdir --ignore-fail-on-non-empty "${INSTALL_ROOT}" 2>/dev/null || true
  echo 'LINUX RELEASE UI DRIVER UNINSTALL: PASS'
  exit 0
fi

for source in "${DRIVER_SOURCE}" "${CANARY_SOURCE}"; do
  [[ -f "${source}" && ! -L "${source}" ]] || {
    echo "Required release-tool source is missing or unsafe: ${source}" >&2
    exit 65
  }
done

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  export APT_LISTCHANGES_FRONTEND=none
  export NEEDRESTART_MODE=a
  apt-get -o DPkg::Lock::Timeout=300 -o Acquire::Retries=3 update
  apt-get \
    -o DPkg::Lock::Timeout=300 \
    -o Acquire::Retries=3 \
    -o Dpkg::Options::=--force-confdef \
    -o Dpkg::Options::=--force-confold \
    install -y --no-install-recommends \
    at-spi2-core gir1.2-atspi-2.0 imagemagick libatk-adaptor libglib2.0-bin \
    python3 python3-pyatspi tesseract-ocr xdotool
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y at-spi2-core glib2 ImageMagick python3 python3-pyatspi tesseract xdotool
elif command -v pacman >/dev/null 2>&1; then
  pacman -Syu --needed --noconfirm at-spi2-core glib2 imagemagick python-pyatspi tesseract xdotool
else
  echo 'Supported package manager not found. Use Ubuntu/Debian, Fedora, or Arch Linux.' >&2
  exit 65
fi

install -d -m 0755 -o root -g root "${INSTALL_ROOT}"
install -m 0755 -o root -g root "${DRIVER_SOURCE}" "${DRIVER_TARGET}"
install -m 0755 -o root -g root "${CANARY_SOURCE}" "${CANARY_TARGET}"

for command_name in gdbus import tesseract xdotool; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    echo "Required Linux evidence command is unavailable: ${command_name}" >&2
    exit 65
  }
done
/usr/bin/python3 -c 'import pyatspi' || {
  echo 'The system Python AT-SPI module is unavailable after installation.' >&2
  exit 65
}

[[ "$(sha256sum "${DRIVER_SOURCE}" | awk '{print $1}')" == \
    "$(sha256sum "${DRIVER_TARGET}" | awk '{print $1}')" ]]
[[ "$(sha256sum "${CANARY_SOURCE}" | awk '{print $1}')" == \
    "$(sha256sum "${CANARY_TARGET}" | awk '{print $1}')" ]]
[[ "$(stat -c '%U:%G:%a' "${DRIVER_TARGET}")" == root:root:755 ]]
[[ "$(stat -c '%U:%G:%a' "${CANARY_TARGET}")" == root:root:755 ]]

/usr/bin/python3 "${DRIVER_TARGET}" --self-test
echo "LINUX RELEASE UI DRIVER INSTALL: PASS (${DRIVER_TARGET})"
