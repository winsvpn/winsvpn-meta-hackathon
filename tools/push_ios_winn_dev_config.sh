#!/bin/bash
# Copy a DEV-ONLY winn/3 config JSON or raw INI template into the Win's VPN
# app's own data container on a connected iPhone/iPad. The older JSON path uses
# `WINN_DEV_CONFIG_PATH`; the standalone raw-config lab target uses
# `WINN_IOS_RAW_CONFIG_PATH=container:<name>.ini`.
#
# WHY THIS SCRIPT EXISTS
#
# On macOS an operator points WINN_DEV_CONFIG_PATH at
# ~/Library/Containers/org.winsvpn.app/Data/<name>.json -- a normal directory on
# the same machine. On iOS the app container is
# /private/var/mobile/Containers/Data/Application/<UUID>/ on the PHONE, the UUID
# changes on every reinstall, and nothing on the Mac can write to it directly.
# So there was no way to place the file the define points at. This is that way.
#
# WHAT IT REQUIRES
#
#  * A DEVELOPMENT-SIGNED build of the app installed on the device. `devicectl`
#    can only reach the data container of an app with get-task-allow, which is
#    exactly what a development build has and a TestFlight/App Store build does
#    not. That is a good property, not a limitation: this cannot touch a real
#    user's installed app.
#  * The device unlocked, paired and connected (USB or network).
#
# WHAT IT DOES NOT DO
#
# It does not start a tunnel, install anything, or modify the app. It copies one
# file. The dev session still has to be launched deliberately, with both
# dart-defines, from a debug build.
#
# SECRETS: JSON input contains client key material. A standalone raw INI carries
# `static_private` but MUST carry only the literal Keychain placeholder for the
# `[Interface] PrivateKey`; the native Debug bridge substitutes that existing
# device key without exposing it to Dart. This script never prints contents.
# Only path and size are echoed.
set -euo pipefail

# Default to the coexisting Debug app. Requiring an explicit override for the
# production id prevents a lab operator who omitted one environment variable
# from copying secret-bearing material into the owner's real app container.
BUNDLE_ID="${WINN_DEV_IOS_BUNDLE_ID:-org.winsvpn.app.debug}"
CONTAINER_SUBDIR="Documents"

usage() {
  cat >&2 <<USAGE
Usage: $(basename "$0") <local-config> [destination-name]

  <local-config>      Path on this Mac to a dev winn/3 JSON config or raw INI.
  [destination-name]  Name inside the container's ${CONTAINER_SUBDIR}/.
                      Defaults to the local file's basename.

Environment:
  WINN_DEV_IOS_DEVICE      Device UDID. Optional when exactly one device is
                           connected; required when there is more than one.
  WINN_DEV_IOS_BUNDLE_ID   Defaults to ${BUNDLE_ID}.

Then run either dev target.

Legacy JSON/relay path:
  flutter run -d <device> \\
    --target=lib/winn_protocol_dev_session_main.dart \\
    --dart-define=WINN_DEV_SESSION=true \\
    --dart-define=WINN_DEV_UNSAFE_IOS_OVERRIDE=true \\
    --dart-define=WINN_DEV_CONFIG_PATH=container:<destination-name.json>

Standalone raw INI path (carrier = winn3):
  flutter run -d <device> \\
    --target=lib/winn_protocol_ios_raw_config_main.dart \\
    --dart-define=WINN_IOS_RAW_CONFIG_LAB=true \\
    --dart-define=WINN_IOS_RAW_CONFIG_PATH=container:<destination-name.ini>
USAGE
  exit 64
}

[ $# -ge 1 ] || usage
LOCAL_PATH="$1"
DEST_NAME="${2:-$(basename "$LOCAL_PATH")}"

if [ ! -f "$LOCAL_PATH" ]; then
  printf 'FATAL: no such file: %s\n' "$LOCAL_PATH" >&2
  exit 66
fi

case "$DEST_NAME" in
  *.ini)
    count="$(grep -Fxc 'PrivateKey = __WINS_EXISTING_KEYCHAIN_PRIVATE_KEY__' "$LOCAL_PATH" || true)"
    if [ "$count" != "1" ]; then
      printf 'FATAL: raw INI must contain exactly one Interface Keychain placeholder; found %s.\n' "$count" >&2
      exit 65
    fi
    if grep -Eiq '^[[:space:]]*carrier[[:space:]]*=[[:space:]]*(direct-awg|http3-connect-udp)[[:space:]]*$' "$LOCAL_PATH"; then
      printf 'FATAL: raw INI selected a relay carrier; this seam requires carrier = winn3.\n' >&2
      exit 65
    fi
    ;;
esac

case "$DEST_NAME" in
  */*|..*|"")
    printf 'FATAL: destination must be a plain file name inside %s/, got "%s".\n' \
      "$CONTAINER_SUBDIR" "$DEST_NAME" >&2
    exit 64
    ;;
esac

case "$DEST_NAME" in
  *.json|*.ini) ;;
  *)
    printf 'FATAL: destination must end in .json or .ini, got "%s".\n' "$DEST_NAME" >&2
    exit 64
    ;;
esac

if ! xcrun devicectl --version >/dev/null 2>&1; then
  printf 'FATAL: xcrun devicectl is unavailable. Xcode 15 or newer is required.\n' >&2
  printf 'Alternative: Xcode > Window > Devices and Simulators > select the app >\n' >&2
  printf 'the gear menu > "Download Container...", add the file under %s/, then\n' >&2
  printf '"Replace Container...".\n' >&2
  exit 69
fi

DEVICE="${WINN_DEV_IOS_DEVICE:-}"
if [ -z "$DEVICE" ]; then
  DEVICE_LIST="$(xcrun devicectl list devices 2>/dev/null || true)"
  DEVICE_COUNT="$(printf '%s\n' "$DEVICE_LIST" | grep -c 'connected' || true)"
  if [ "$DEVICE_COUNT" != "1" ]; then
    printf 'FATAL: expected exactly one connected device, found %s.\n' "$DEVICE_COUNT" >&2
    printf 'Set WINN_DEV_IOS_DEVICE=<udid>. Devices seen:\n%s\n' "$DEVICE_LIST" >&2
    exit 69
  fi
  DEVICE="$(printf '%s\n' "$DEVICE_LIST" | awk '/connected/ {print $(NF-2)}' | head -1)"
fi

printf 'Pushing %s (%s bytes) -> %s:%s/%s/%s\n' \
  "$LOCAL_PATH" \
  "$(wc -c < "$LOCAL_PATH" | tr -d ' ')" \
  "$DEVICE" \
  "$BUNDLE_ID" \
  "$CONTAINER_SUBDIR" \
  "$DEST_NAME" >&2

xcrun devicectl device copy to \
  --device "$DEVICE" \
  --domain-type appDataContainer \
  --domain-identifier "$BUNDLE_ID" \
  --source "$LOCAL_PATH" \
  --destination "$CONTAINER_SUBDIR/$DEST_NAME"

case "$DEST_NAME" in
  *.ini)
    printf 'Done. Launch the raw lab with --dart-define=WINN_IOS_RAW_CONFIG_PATH=container:%s\n' \
      "$DEST_NAME" >&2
    ;;
  *)
    printf 'Done. Launch the dev session with --dart-define=WINN_DEV_CONFIG_PATH=container:%s\n' \
      "$DEST_NAME" >&2
    ;;
esac
