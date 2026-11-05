#!/bin/sh
#
# Build the Linux production-reference Auto driver with a reproducible
# manifest of every exact main-module input selected by the Linux Go build.
#
# Usage:
#   ./scripts/build_auto_e2e_linux.sh OUTPUT_DIRECTORY

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
source_manifest=$output_directory/winn-auto-e2e.source.sha256
binary=$output_directory/winn-auto-e2e
temporary_binary=$(mktemp "$output_directory/.winn-auto-e2e.XXXXXX")
temporary_manifest=$(mktemp "$output_directory/.winn-auto-e2e-source.XXXXXX")

cleanup() {
	rm -f "$temporary_binary" "$temporary_manifest"
}
trap cleanup EXIT HUP INT TERM

source_digest=$(
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		"$script_directory/source_manifest.sh" \
		./cmd/winn-auto-e2e "$source_manifest"
)

# -mod=readonly and -buildvcs=false match scripts/build_release.sh. Without
# -buildvcs=false the Go toolchain stamps VCS state into the binary, so the
# artifact digest depends on whether the build ran inside a git checkout and on
# whether that checkout was dirty. The stage builds ran without VCS stamping, so
# an auditor rebuilding from a git clone with the previous flag set got
# different bytes than the shipped stage binary and could reasonably conclude
# the artifact had been tampered with. Both flags are required for the digest to
# be a function of the source tree alone.
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
	-mod=readonly \
	-trimpath \
	-buildvcs=false \
	-ldflags="-s -w -buildid= -X main.sourceDigest=$source_digest" \
	-o "$temporary_binary" \
	./cmd/winn-auto-e2e

post_build_digest=$(
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		"$script_directory/source_manifest.sh" \
		./cmd/winn-auto-e2e "$temporary_manifest"
)
if [ "$source_digest" != "$post_build_digest" ] ||
	! cmp -s "$source_manifest" "$temporary_manifest"; then
	echo "Auto E2E source inputs changed during the build" >&2
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
