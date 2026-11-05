#!/usr/bin/env bash
set -euo pipefail

srcroot="${SRCROOT:-}"
target_build_dir="${TARGET_BUILD_DIR:-}"
resources_path="${UNLOCALIZED_RESOURCES_FOLDER_PATH:-}"
derived_file_dir="${DERIVED_FILE_DIR:-}"

if [[ -z "${srcroot}" || -z "${target_build_dir}" || -z "${resources_path}" ]]; then
  echo "warning: macOS app icon normalization skipped because Xcode build paths are unavailable" >&2
  exit 0
fi

if [[ -z "${derived_file_dir}" ]]; then
  derived_file_dir="${target_build_dir}"
fi

source_icon="${srcroot}/Runner/Assets.xcassets/AppIcon.appiconset/app_icon_1024.png"
output_icon="${target_build_dir}/${resources_path}/AppIcon.icns"
iconset="${derived_file_dir}/WinsVPNAppIcon.iconset"

if [[ ! -f "${source_icon}" ]]; then
  echo "error: Win Empire macOS app icon source is missing: ${source_icon}" >&2
  exit 1
fi

rm -rf "${iconset}"
mkdir -p "${iconset}"
mkdir -p "$(dirname "${output_icon}")"

make_icon() {
  local size="$1"
  local name="$2"
  /usr/bin/sips -s format png -z "${size}" "${size}" "${source_icon}" --out "${iconset}/${name}" >/dev/null
}

make_icon 16 "icon_16x16.png"
make_icon 32 "icon_16x16@2x.png"
make_icon 32 "icon_32x32.png"
make_icon 64 "icon_32x32@2x.png"
make_icon 128 "icon_128x128.png"
make_icon 256 "icon_128x128@2x.png"
make_icon 256 "icon_256x256.png"
make_icon 512 "icon_256x256@2x.png"
make_icon 512 "icon_512x512.png"
make_icon 1024 "icon_512x512@2x.png"

/usr/bin/iconutil -c icns "${iconset}" -o "${output_icon}"

echo "Normalized Win Empire macOS AppIcon.icns at ${output_icon}"
