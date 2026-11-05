#!/bin/sh
#
# Build the Linux H3 vertical-proof driver with a reproducible manifest of
# every exact main-module input selected by the Go toolchain.
#
# Usage:
#   ./scripts/build_h3_e2e_linux.sh OUTPUT_DIRECTORY

set -eu

if [ "$#" -ne 1 ]; then
	echo "usage: $0 OUTPUT_DIRECTORY" >&2
	exit 64
fi

output_directory=$1
if [ ! -d "$output_directory" ]; then
	echo "output directory does not exist: $output_directory" >&2
	exit 1
fi

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
source_manifest=$output_directory/winn-h3-e2e.source.sha256
binary=$output_directory/winn-h3-e2e
temporary_binary=$(mktemp "$output_directory/.winn-h3-e2e.XXXXXX")
temporary_manifest=$(mktemp "$output_directory/.winn-h3-e2e-source.XXXXXX")

cleanup() {
	rm -f "$temporary_binary" "$temporary_manifest"
}
trap cleanup EXIT HUP INT TERM

source_digest=$(
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		"$script_directory/source_manifest.sh" \
		./cmd/winn-h3-e2e "$source_manifest"
)

# -mod=readonly and -buildvcs=false are required, not stylistic: without
# -buildvcs=false a build from a git checkout embeds VCS stamps, so this script
# and scripts/reproducible_build_test.sh disagree about the binary's bytes and an
# auditor following this script concludes tampering where there is none. Matches
# scripts/build_release.sh:25-30 and build_auto_e2e_linux.sh.
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
	-mod=readonly \
	-trimpath \
	-buildvcs=false \
	-ldflags="-s -w -buildid= -X main.sourceDigest=$source_digest" \
	-o "$temporary_binary" \
	./cmd/winn-h3-e2e

post_build_digest=$(
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		"$script_directory/source_manifest.sh" \
		./cmd/winn-h3-e2e "$temporary_manifest"
)
if [ "$source_digest" != "$post_build_digest" ] ||
	! cmp -s "$source_manifest" "$temporary_manifest"; then
	echo "H3 E2E source inputs changed during the build" >&2
	exit 1
fi

chmod 0755 "$temporary_binary"
mv "$temporary_binary" "$binary"

if command -v sha256sum >/dev/null 2>&1; then
	artifact_digest=$(sha256sum "$binary" | awk '{ print $1 }')
else
	artifact_digest=$(shasum -a 256 "$binary" | awk '{ print $1 }')
fi

printf 'SOURCE_MANIFEST=%s\n' "$source_manifest"
printf 'SOURCE_DIGEST=%s\n' "$source_digest"
printf 'ARTIFACT=%s\n' "$binary"
printf 'ARTIFACT_DIGEST=%s\n' "$artifact_digest"
