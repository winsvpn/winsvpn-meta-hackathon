#!/bin/sh
set -eu

spike_script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
spike_root="$(CDPATH='' cd -- "${spike_script_dir}/.." && pwd)"
spike_device_udid="${WINN_SPIKE_DEVICE_UDID:-<DEVICE_UDID>}"

command -v xcodebuild >/dev/null 2>&1 || {
  echo "BLOCKED: xcodebuild is unavailable." >&2
  exit 78
}
command -v xcrun >/dev/null 2>&1 || {
  echo "BLOCKED: xcrun is unavailable." >&2
  exit 78
}
command -v security >/dev/null 2>&1 || {
  echo "BLOCKED: security is unavailable." >&2
  exit 78
}

test -f "${spike_root}/PrivacyCore/Package.swift" || {
  echo "BLOCKED: isolated PrivacyCore package is missing." >&2
  exit 78
}
test ! -e "${spike_root}/PrivacySpike.xcodeproj" || {
  echo "INFO: isolated Xcode project exists; validating signing prerequisites."
}

device_listing="$(xcrun xcdevice list 2>/dev/null || true)"
case "${device_listing}" in
  *"${spike_device_udid}"*) ;;
  *)
    echo "BLOCKED: the configured physical iPhone is unavailable." >&2
    exit 78
    ;;
esac

identity_listing="$(security find-identity -v -p codesigning 2>&1 || true)"
case "${identity_listing}" in
  *"0 valid identities found"*)
    echo "BLOCKED: no valid Apple Development signing identity is installed." >&2
    echo "Create/import the identity before generating or building the Packet Tunnel project." >&2
    exit 78
    ;;
esac

spike_profile_roots="
/Users/winsvpn/Library/MobileDevice/Provisioning Profiles
/Users/winsvpn/Library/Developer/Xcode/UserData/Provisioning Profiles
"

spike_profile_supports() {
  spike_expected_bundle="$1"
  spike_profile_found=1
  spike_saved_ifs="${IFS}"
  IFS='
'
  for spike_profile_path in $(
    for spike_profile_root in ${spike_profile_roots}; do
      if test -d "${spike_profile_root}"; then
        find "${spike_profile_root}" -maxdepth 1 -type f \
          \( -name '*.mobileprovision' -o -name '*.provisionprofile' \)
      fi
    done
  ); do
    spike_profile_platform="$(
      security cms -D -i "${spike_profile_path}" 2>/dev/null |
        plutil -extract Platform json -o - - 2>/dev/null || true
    )"
    case "${spike_profile_platform}" in
      *iOS*) ;;
      *) continue ;;
    esac
    spike_profile_entitlements="$(
      security cms -D -i "${spike_profile_path}" 2>/dev/null |
        plutil -extract Entitlements xml1 -o - - 2>/dev/null |
        plutil -p - 2>/dev/null || true
    )"
    case "${spike_profile_entitlements}" in
      *".${spike_expected_bundle}\""*) ;;
      *) continue ;;
    esac
    case "${spike_profile_entitlements}" in
      *"packet-tunnel-provider"*) ;;
      *) continue ;;
    esac
    case "${spike_profile_entitlements}" in
      *"group.org.winsvpn.experimental.wcf3privacyspike"*)
        spike_profile_found=0
        break
        ;;
    esac
  done
  IFS="${spike_saved_ifs}"
  return "${spike_profile_found}"
}

spike_host_bundle="org.winsvpn.experimental.wcf3privacyspike"
spike_provider_bundle="${spike_host_bundle}.PacketTunnel"
if ! spike_profile_supports "${spike_host_bundle}"; then
  echo "BLOCKED: no iOS development profile binds the experimental host, Packet Tunnel entitlement, and App Group." >&2
  exit 78
fi
if ! spike_profile_supports "${spike_provider_bundle}"; then
  echo "BLOCKED: no iOS development profile binds the experimental provider, Packet Tunnel entitlement, and App Group." >&2
  exit 78
fi

echo "PASS: Xcode, physical iPhone, signing identity, and isolated iOS profiles are visible."
