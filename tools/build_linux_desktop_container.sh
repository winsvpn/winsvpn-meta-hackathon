#!/usr/bin/env bash
# Build the Win's VPN Linux desktop bundle from tools/Dockerfile.linux-desktop.
#
#   tools/build_linux_desktop_container.sh arm64   # native on an aarch64 host
#   tools/build_linux_desktop_container.sh x64     # qemu-x86_64 on an aarch64 host
#
# Why a script and not a bare `docker build .`: the repo root carries multi-GB
# `.artifacts/` and `build/` trees. Sending that as a build context is minutes of
# wasted I/O per build, and this docker has no BuildKit (`docker buildx` is
# absent), so the per-Dockerfile `.dockerignore` trick is unavailable. This
# stages exactly the paths the Dockerfile COPYs into a temporary context.
#
# `windows/` is in the staging list ON PURPOSE -- linux/runner/linux_winn_host.cc
# includes ../../windows/runner/winn_frame.h, so a partial windows/ breaks the
# LINUX build. Do not "tidy" it out.
#
# COMPILES AND LINKS, DOES NOT RUN. This produces and architecture-verifies a
# bundle. It executes nothing, starts no VPN session, and establishes no runtime
# guarantee. It is also NOT the signed release pipeline; that is
# tools/build_linux_release.sh.
set -euo pipefail

# The base image is pinned by PLATFORM MANIFEST DIGEST, not by tag, because
# `docker build --platform` does not work without buildx (see the Dockerfile
# header). `docker run` emulation is registered, so an amd64 base image builds
# genuinely-amd64 layers under qemu-x86_64 -- slowly, but repeatably.
# Refresh with: docker manifest inspect ubuntu:24.04
UBUNTU_ARM64_DIGEST="${UBUNTU_ARM64_DIGEST:-sha256:08571ca13e00ca07a2a84eab83a959b4242e22cceb16486a11bef1428c9e93a7}"
UBUNTU_AMD64_DIGEST="${UBUNTU_AMD64_DIGEST:-sha256:f610ab94648195aa356059f5b41d6085c9d4d903c072430cdd1af7bdb646106b}"

target="${1:-arm64}"
case "$target" in
    arm64)
        base="ubuntu:24.04@${UBUNTU_ARM64_DIGEST}"
        bundle_dir=build/linux/arm64/release/bundle
        expect_flutter_arch=linux-arm64
        ;;
    x64)
        base="ubuntu:24.04@${UBUNTU_AMD64_DIGEST}"
        bundle_dir=build/linux/x64/release/bundle
        expect_flutter_arch=linux-x64
        ;;
    *) echo "usage: $(basename "$0") [arm64|x64]" >&2; exit 2 ;;
esac

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="winsvpn-linux-desktop-builder:${target}"
container="winsvpn-linux-desktop-export-$$"
outdir="${OUTPUT_DIR:-$repo/build/linux-container/$target}"

# The Flutter tag comes from tools/toolchain-pins.json at run time, never from
# a literal -- the next pin bump must reach every build, and the Dockerfile's
# ARG has no default for exactly that reason. Fail loudly if the pin cannot be
# resolved, so an empty clone tag is never passed silently.
flutter_version="$(python3 - "$repo/tools/toolchain-pins.json" tools.flutter.version <<'WINS_PIN_EOF'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    value = value[part]
sys.stdout.write(str(value))
WINS_PIN_EOF
)"
if [[ ! "${flutter_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "unable to resolve the pinned Flutter tag from tools/toolchain-pins.json" >&2
    exit 1
fi

# Exactly the paths tools/Dockerfile.linux-desktop COPYs.
sources=(pubspec.yaml pubspec.lock analysis_options.yaml .metadata lib linux windows assets)

context="$(mktemp -d "${TMPDIR:-/tmp}/winsvpn-linux-ctx.XXXXXX")"
cleanup() {
    rm -rf "$context"
    docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== staging build context ($context) ==="
for path in "${sources[@]}"; do
    [ -e "$repo/$path" ] || { echo "missing source path: $path" >&2; exit 1; }
done
# --exclude '._*' drops macOS AppleDouble sidecars, which .gitignore also
# ignores and which are not part of the source.
tar -C "$repo" --exclude '._*' --exclude '.DS_Store' -cf - "${sources[@]}" \
    | tar -C "$context" -xf -
cp "$repo/tools/Dockerfile.linux-desktop" "$context/Dockerfile"
for path in "${sources[@]}"; do
    if [ -d "$context/$path" ]; then
        printf '  %-10s %s files\n' "$path" "$(find "$context/$path" -type f | wc -l | tr -d ' ')"
    fi
done

echo "=== docker build --build-arg BASE_IMAGE=$base --build-arg FLUTTER_REF=$flutter_version -t $image ==="
docker build --build-arg "BASE_IMAGE=$base" --build-arg "FLUTTER_REF=$flutter_version" -t "$image" "$context"

# The image must be the architecture that was ASKED FOR. The Dockerfile derives
# its target from dpkg inside the container and records it, so comparing that
# recorded value against the request catches a base image that resolved to the
# wrong platform -- which is exactly what a bare `--platform` flag does silently
# on a daemon that ignores it.
built_arch="$(docker run --rm --entrypoint cat "$image" /opt/flutter-target-arch | tr -d '\r\n')"
if [ "$built_arch" != "$expect_flutter_arch" ]; then
    echo "ARCH MISMATCH: asked for $expect_flutter_arch, image built $built_arch." >&2
    echo "The base image digest did not resolve to the requested platform." >&2
    docker rmi "$image" >/dev/null 2>&1 || true
    exit 1
fi
echo "=== image architecture confirmed: $built_arch ==="

echo "=== exporting $bundle_dir ==="
mkdir -p "$outdir"
rm -rf "${outdir:?}/bundle"
docker create --name "$container" "$image" >/dev/null
docker cp "$container:/src/$bundle_dir" "$outdir/bundle"
docker rm -f "$container" >/dev/null

echo "=== host-side re-verification (independent of the container) ==="
ls -l "$outdir/bundle/wins_vpn"
file "$outdir/bundle/wins_vpn"
file "$outdir/bundle/lib/libapp.so"

cat <<EOF

Bundle: $outdir/bundle
Image:  $image   (remove with: docker rmi $image)

COMPILED AND LINKED, NOT EXECUTED. No Linux host of either architecture ran
this binary; no runtime, routing or tunnel behaviour was exercised.
EOF
