#!/bin/sh
#
# Build the Linux forced-abort carrier conservation smoke with a reproducible
# manifest of every exact main-module input selected by the Linux Go build, and
# stamp that manifest's digest into the binary so the evidence it seals names
# the source tree that produced it.
#
# Mirrors scripts/build_auto_e2e_linux.sh, including -mod=readonly, -trimpath,
# and -buildvcs=false, so the artifact digest is a function of the source tree
# alone.
#
# Usage:
#   ./scripts/build_conservation_smoke_linux.sh OUTPUT_DIRECTORY

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
source_manifest=$output_directory/winn-phase1-conservation-smoke.source.sha256
binary=$output_directory/winn-phase1-conservation-smoke
temporary_binary=$(mktemp "$output_directory/.winn-conservation-smoke.XXXXXX")
temporary_manifest=$(mktemp "$output_directory/.winn-conservation-source.XXXXXX")

cleanup() {
	rm -f "$temporary_binary" "$temporary_manifest"
}
trap cleanup EXIT HUP INT TERM

source_digest=$(
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		"$script_directory/source_manifest.sh" \
		./cmd/winn-phase1-conservation-smoke "$source_manifest"
)

# The stamped digest is now load-bearing: the smoke refuses to produce any
# evidence unless its own stamp is 64 lower-hex characters and equals the
# SHA-256 the runner computes over the deployed manifest. A malformed stamp
# must therefore fail the build, not the run.
if ! printf '%s' "$source_digest" | grep -qE '^[0-9a-f]{64}$'; then
	echo "source manifest digest is not 64 lower-hex characters: $source_digest" >&2
	exit 1
fi

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
	-mod=readonly \
	-trimpath \
	-buildvcs=false \
	-ldflags="-s -w -buildid= -X main.sourceDigest=$source_digest" \
	-o "$temporary_binary" \
	./cmd/winn-phase1-conservation-smoke

post_build_digest=$(
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		"$script_directory/source_manifest.sh" \
		./cmd/winn-phase1-conservation-smoke "$temporary_manifest"
)
if [ "$source_digest" != "$post_build_digest" ] ||
	! cmp -s "$source_manifest" "$temporary_manifest"; then
	echo "conservation smoke source inputs changed during the build" >&2
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
