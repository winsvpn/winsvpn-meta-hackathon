#!/bin/sh
set -eu

# Reproducibly build the Winn v3 AmneziaWG userspace engine from the frozen
# latest-stable official amneziawg-go tag plus the reviewable fast-handshake
# scheduling patch. The same target consumes stock amneziawg-go; it must not
# retain a pre-v3 commit when v3.1 is current.
#
# Usage:
#   ./scripts/build_winn_awg_engine.sh AMNEZIAWG_GO_REPOSITORY OUTPUT_DIRECTORY

if [ "$#" -ne 2 ]; then
	echo "usage: $0 AMNEZIAWG_GO_REPOSITORY OUTPUT_DIRECTORY" >&2
	exit 64
fi

source_repository=$1
output_directory=$2
# Live-verified 2026-08-24 against official GitHub tags: latest stable
# amneziawg-go is v3.1.20260828 at commit b5928efb6ca19f0153958460c3d141f04abc5c2e.
# This is not the Windows client 3.1.0 tag and not amneziawg-tools v3.1.20260812.
upstream_repository=https://github.com/amnezia-vpn/amneziawg-go.git
upstream_tag=v3.1.20260828
upstream_commit=b5928efb6ca19f0153958460c3d141f04abc5c2e
# GitHub archive/${upstream_commit}.tar.gz. This script consumes a local git
# commit via `git archive`, so it does not re-hash that tarball at build time.
upstream_github_archive_sha256=10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4
# LF git-blob hashes. Windows CRLF conversions are a different identity.
upstream_go_mod_sha256=9fd0084da2acc4f96225daee85c0f866a0ec1079d5bdc4cf98c50e8a8fa0baf6
upstream_go_sum_sha256=eab202288b6f879fe1f6b0d9da0c528cfb310d74a7a4d409c7268c2b26b98a0a
constants_sha256=5989645bff55a3ce3f21271a6942361050eff078d17a87c718136bebf156714a
engine_version=winn-v3-v3.1.20260828-b5928efb6ca1-fast-handshake-v1
rejected_pre_v3_commit=c1e9bb3758e71bb1adc402598465565bfc9663fd

# The upstream commit, the constants digest, and the patch are all pinned, but
# the Go toolchain was not, so the engine's bytes depended on whichever `go`
# happened to be on PATH -- and that choice was recoverable only from the
# produced binary's own buildinfo, which is circular for an auditor trying to
# reproduce it. Pin it here and fail closed on mismatch. GOTOOLCHAIN=local
# during the build keeps the assertion binding: the upstream module carries its
# own go.mod, and under the default GOTOOLCHAIN=auto a `go`/`toolchain`
# directive there could silently switch to a different toolchain after this
# check passed.
expected_go_version=go1.27.1
go_bin=${GO_BIN:-go}

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{ print $1 }'
	else
		shasum -a 256 "$1" | awk '{ print $1 }'
	fi
}

actual_go_version=$("$go_bin" version 2>/dev/null | awk '{ print $3 }')
if [ "$actual_go_version" != "$expected_go_version" ]; then
	echo "engine build requires $expected_go_version, found ${actual_go_version:-none}" >&2
	exit 1
fi

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
patch_file=$script_directory/../patches/amneziawg-go-fast-handshake-v1.patch
if [ ! -d "$source_repository/.git" ] ||
	[ ! -d "$output_directory" ] ||
	[ ! -f "$patch_file" ]; then
	echo "source repository, output directory, or patch is missing" >&2
	exit 1
fi
if [ "$upstream_commit" = "$rejected_pre_v3_commit" ]; then
	echo "refusing the retired pre-v3 AmneziaWG commit" >&2
	exit 1
fi
if [ "$(git -C "$source_repository" rev-parse "$upstream_commit^{commit}")" != \
	"$upstream_commit" ]; then
	echo "pinned AmneziaWG commit is unavailable" >&2
	exit 1
fi
if [ "$(git -C "$source_repository" rev-parse "$upstream_tag^{commit}")" != \
	"$upstream_commit" ]; then
	echo "pinned AmneziaWG tag $upstream_tag is not bound to $upstream_commit" >&2
	exit 1
fi
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/winn-awg-engine.XXXXXXXX")
temporary_binary=$(mktemp "$output_directory/.winn-awg-engine.XXXXXXXX")
cleanup() {
	rm -rf "$temporary_directory"
	rm -f "$temporary_binary"
}
trap cleanup EXIT HUP INT TERM

git -C "$source_repository" show \
	"$upstream_commit:device/constants.go" \
	>"$temporary_directory/constants.go"
actual_constants_sha=$(sha256_file "$temporary_directory/constants.go")
if [ "$actual_constants_sha" != "$constants_sha256" ]; then
	echo "pinned AmneziaWG constants source digest changed" >&2
	exit 1
fi
rm -f "$temporary_directory/constants.go"

git -C "$source_repository" archive "$upstream_commit" |
	tar -x -C "$temporary_directory"
if [ ! -f "$temporary_directory/go.mod" ] || [ ! -f "$temporary_directory/go.sum" ]; then
	echo "pinned AmneziaWG tree is missing go.mod or go.sum" >&2
	exit 1
fi
if ! grep -Fxq 'module github.com/amnezia-vpn/amneziawg-go/v3' \
	"$temporary_directory/go.mod"; then
	echo "pinned AmneziaWG module identity is not amneziawg-go/v3" >&2
	exit 1
fi
if [ "$(sha256_file "$temporary_directory/go.mod")" != "$upstream_go_mod_sha256" ] ||
	[ "$(sha256_file "$temporary_directory/go.sum")" != "$upstream_go_sum_sha256" ]; then
	echo "pinned AmneziaWG go.mod/go.sum digest changed" >&2
	exit 1
fi
patch -d "$temporary_directory" -p1 <"$patch_file"
printf 'package main\n\nconst Version = "%s"\n' "$engine_version" \
	>"$temporary_directory/version.go"

(
	cd "$temporary_directory"
	GOTOOLCHAIN=local "$go_bin" test ./device
	CGO_ENABLED=0 GOTOOLCHAIN=local "$go_bin" build \
		-trimpath \
		-ldflags="-s -w -buildid=" \
		-o "$temporary_binary" \
		.
)
chmod 0755 "$temporary_binary"
mv "$temporary_binary" "$output_directory/amneziawg-go-winn-v3"

artifact_digest=$(sha256_file "$output_directory/amneziawg-go-winn-v3")
patch_digest=$(sha256_file "$patch_file")
printf 'UPSTREAM_REPOSITORY=%s\n' "$upstream_repository"
printf 'UPSTREAM_TAG=%s\n' "$upstream_tag"
printf 'UPSTREAM_COMMIT=%s\n' "$upstream_commit"
printf 'UPSTREAM_GITHUB_ARCHIVE_SHA256=%s\n' "$upstream_github_archive_sha256"
printf 'PATCH_DIGEST=%s\n' "$patch_digest"
printf 'GO_TOOLCHAIN=%s\n' "$expected_go_version"
printf 'ENGINE_VERSION=%s\n' "$engine_version"
printf 'ARTIFACT=%s\n' "$output_directory/amneziawg-go-winn-v3"
printf 'ARTIFACT_DIGEST=%s\n' "$artifact_digest"
