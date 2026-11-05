#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
OUTPUT_DIR=${1:-"$ROOT_DIR/dist"}
SBOM_TOOL_VERSION=v1.10.0
GO_BIN=${GO_BIN:-go}
TOOLCHAIN_GO=$("$GO_BIN" env GOROOT)/bin/go

if [ -e "$OUTPUT_DIR" ]; then
  if [ -n "$(find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    echo "release output already exists and is not empty: $OUTPUT_DIR" >&2
    exit 1
  fi
else
  mkdir -p "$OUTPUT_DIR"
fi

build_binary() {
  target_os=$1
  target_arch=$2
  command=$3
  suffix=$4
  destination="$OUTPUT_DIR/${command}-${target_os}-${target_arch}${suffix}"
  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" "$GO_BIN" build \
    -mod=readonly \
    -trimpath \
    -buildvcs=false \
    -ldflags="-s -w -buildid=" \
    -o "$destination" \
    "./cmd/$command"
  # `go version -m` prefixes its report with the path it was given. Preserve
  # the useful module and build settings while replacing that build-host path
  # with the release artifact's stable basename.
  artifact_name=${destination##*/}
  "$GO_BIN" version -m "$destination" |
    {
      IFS= read -r buildinfo_header
      case "$buildinfo_header" in
      "$destination":*)
        printf '%s%s\n' "$artifact_name" "${buildinfo_header#"$destination"}"
        ;;
      *)
        echo "unexpected go version -m header: $buildinfo_header" >&2
        exit 1
        ;;
      esac
      cat
    } >"$destination.buildinfo"
}

cd "$ROOT_DIR"
"$GO_BIN" mod verify

for target in linux-amd64 linux-arm64 darwin-arm64; do
  target_os=${target%-*}
  target_arch=${target#*-}
  for command in winn-server winn-client winn-carrier-server winn-carrier-client winn-token-issuer winn-token winn-manifest winn-admin winn-audit winn-pki; do
    build_binary "$target_os" "$target_arch" "$command" ""
  done
done

for command in winn-server winn-client winn-carrier-server winn-carrier-client winn-token-issuer winn-token winn-manifest winn-admin winn-audit winn-pki; do
  build_binary windows amd64 "$command" ".exe"
done
build_binary android arm64 winn-client ""
build_binary android arm64 winn-carrier-client ""

cp go.mod go.sum "$OUTPUT_DIR/"
mkdir -p "$OUTPUT_DIR/third_party_licenses"
cp internal/masque/LICENSE \
  "$OUTPUT_DIR/third_party_licenses/github.com_quic-go_masque-go_v0.4.0-winn-fork.LICENSE"
cp internal/masque/UPSTREAM.md \
  "$OUTPUT_DIR/third_party_licenses/github.com_quic-go_masque-go_v0.4.0-winn-fork.PROVENANCE.md"
# Captured first: /bin/sh has no pipefail, so a failing `go list` piped
# straight into the loop would exit 0 with no licences copied. A failed
# command substitution in an assignment does stop `set -e`.
module_list=$("$GO_BIN" list -m -f '{{if and (not .Main) .Dir}}{{.Path}}|{{.Version}}|{{.Dir}}{{end}}' all)
printf '%s\n' "$module_list" |
  while IFS='|' read -r module_name module_version module_directory; do
    if [ -z "$module_name" ]; then
      continue
    fi
    license_source=""
    for license_name_candidate in LICENSE LICENSE.md LICENSE.txt COPYING; do
      if [ -f "$module_directory/$license_name_candidate" ]; then
        license_source="$module_directory/$license_name_candidate"
        break
      fi
    done
    if [ -z "$license_source" ]; then
      echo "dependency has no root LICENSE file: $module_name $module_version" >&2
      exit 1
    fi
    license_name=$(printf '%s_%s' "$module_name" "$module_version" | tr '/@' '__')
    cp "$license_source" "$OUTPUT_DIR/third_party_licenses/$license_name.LICENSE"
  done
cp "$("$GO_BIN" env GOROOT)/LICENSE" "$OUTPUT_DIR/third_party_licenses/Go-standard-library.LICENSE"
GOTOOLCHAIN=local "$TOOLCHAIN_GO" run "github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@$SBOM_TOOL_VERSION" \
  mod -json -noserial -notimestamp -output "$OUTPUT_DIR/winn-protocol.cdx.json"
GOTOOLCHAIN=local "$TOOLCHAIN_GO" run ./cmd/winn-sbom-augment \
  -bom "$OUTPUT_DIR/winn-protocol.cdx.json" \
  -source-root "$ROOT_DIR"

MANIFEST_TMP=$(mktemp "${TMPDIR:-/tmp}/winn-protocol-sha256.XXXXXX")
cleanup_manifest() {
  if [ -n "$MANIFEST_TMP" ]; then
    rm -f "$MANIFEST_TMP"
  fi
}
trap cleanup_manifest EXIT HUP INT TERM
(
  cd "$OUTPUT_DIR"
  find . -type f ! -name SHA256SUMS -print |
    LC_ALL=C sort |
    xargs shasum -a 256
) >"$MANIFEST_TMP"
chmod 0644 "$MANIFEST_TMP"
mv "$MANIFEST_TMP" "$OUTPUT_DIR/SHA256SUMS"
MANIFEST_TMP=""
trap - EXIT HUP INT TERM

echo "Release artifacts, build metadata, CycloneDX SBOM, and SHA-256 manifest: $OUTPUT_DIR"
