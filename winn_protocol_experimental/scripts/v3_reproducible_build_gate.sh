#!/bin/sh
# v3_reproducible_build_gate.sh — byte-reproducibility gate for standalone Winn Protocol v3
#
# What it proves:
#   winn3-gateway and winn3-probe built for linux/amd64 are bit-identical across
#   three independent scratch paths (different absolute output directories, empty
#   GOCACHE each time) and match a pinned digest. A tampered source, a drifted
#   Go toolchain, or a dropped -trimpath/-buildvcs/-buildid flag is caught before
#   shipping.
#
# Why pinned digests (not just cmp):
#   cmp alone proves the build is deterministic *given this toolchain and source*,
#   but does not prove the bytes are the *reviewed* bytes. Pinning the sha256
#   turns three-path determinism into a dispatch gate: any source drift or
#   toolchain tamper changes the digest and fails even though the three builds
#   still cmp-equal to each other.
#
# Recipe (must stay in sync with the builder's flags):
#   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o <scratch>/bin ./cmd/<name>
#   Language floor pinned by go.mod; exact toolchain enforced below: go1.27.1
#
# Exit 0: PASS — all three builds per binary are byte-identical, match pinned
#         digests, carry -trimpath=true, carry no vcs stamp, and ELF class is
#         correct.
# Exit 1: FAIL — any check fails, with the failing property named.
#
# To re-pin after a reviewed source change:
#   UPDATE_EXPECTED=1 ./scripts/v3_reproducible_build_gate.sh
# which prints the new digests and exits 2 (so CI does not silently pass on a pin update).
#
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
GO_BIN=${GO_BIN:-go}

# Pinned digests — the only bytes that may ship. Update only after review.
# The release digest must be remeasured on go1.27.1 darwin/arm64 from isolated
# scratch paths before this gate is used for final artifacts.
#   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags="-s -w -buildid="
# See docs/handoff/V3_FIRST_PRODUCTION_NODE_20260812_coordinator.md and the manual_three scratch.
# These digests correspond to the source tree at the time this gate was written;
# a source edit that changes either binary must update the pin after review.
EXPECTED_GATEWAY_SHA256="0ac2c9da61bbf10bb345db73dd0fda2108ea9b63bc0efaffa77de1ae2d675ecf"
EXPECTED_PROBE_SHA256="b97847504f315c8d525685957bfb59877b8ddb90d8fce4e7c05244a2e58a0550"
# For auditability, also pin the toolchain that produced these.
EXPECTED_GO_VERSION="go1.27.1"
export GOTOOLCHAIN=local

# Historical note: earlier hashes quoted in V3_FIRST_PRODUCTION_NODE (254e301b…, d920aef9…)
# were valid for that source snapshot but drifted with later edits. They are NOT the pin;
# they are retained here only as a record of the measurement that motivated this gate.
# Old gateway 254e301bb1c6ad2bac4b94a649726fabec80429f725984a003bd4015d5ab16d1
# Old probe   d920aef957665689a57367f0234767eeeb56e9f084adf7a12b133179469fda05

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

GO_VERSION=$("$GO_BIN" version 2>&1 | awk '{print $3}')
info "Go toolchain: $GO_VERSION (required exactly $EXPECTED_GO_VERSION)"
if [ "$GO_VERSION" != "$EXPECTED_GO_VERSION" ]; then
  fail "toolchain drift: got $GO_VERSION, require exactly $EXPECTED_GO_VERSION"
fi

# Three independent scratch paths — the -trimpath proof.
SCRATCH_A=$(mktemp -d "${TMPDIR:-/tmp}/v3-gate-a.XXXXXX")
SCRATCH_B=$(mktemp -d "${TMPDIR:-/tmp}/v3-gate-b.XXXXXX")
SCRATCH_C=$(mktemp -d "${TMPDIR:-/tmp}/v3-gate-c.XXXXXX")
GC_A=$(mktemp -d "${TMPDIR:-/tmp}/v3-gc-a.XXXXXX")
GC_B=$(mktemp -d "${TMPDIR:-/tmp}/v3-gc-b.XXXXXX")
GC_C=$(mktemp -d "${TMPDIR:-/tmp}/v3-gc-c.XXXXXX")

cleanup() {
  for d in "$SCRATCH_A" "$SCRATCH_B" "$SCRATCH_C" "$GC_A" "$GC_B" "$GC_C"; do
    if [ -e "$d" ]; then rm -rf "$d"; fi
  done
}
trap cleanup EXIT HUP INT TERM

cd "$ROOT_DIR"

build_one() {
  out_dir=$1
  gc=$2
  mkdir -p "$out_dir"
  GOCACHE="$gc" CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO_BIN" build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o "$out_dir/winn3-gateway" ./cmd/winn3-gateway
  GOCACHE="$gc" CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO_BIN" build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o "$out_dir/winn3-probe" ./cmd/winn3-probe
}

info "Building winn3-gateway + winn3-probe into three scratch paths..."
build_one "$SCRATCH_A" "$GC_A"
build_one "$SCRATCH_B" "$GC_B"
build_one "$SCRATCH_C" "$GC_C"
info "Builds complete. Computing digests..."

sha_gateway_a=$(shasum -a 256 "$SCRATCH_A/winn3-gateway" | awk '{print $1}')
sha_gateway_b=$(shasum -a 256 "$SCRATCH_B/winn3-gateway" | awk '{print $1}')
sha_gateway_c=$(shasum -a 256 "$SCRATCH_C/winn3-gateway" | awk '{print $1}')
sha_probe_a=$(shasum -a 256 "$SCRATCH_A/winn3-probe" | awk '{print $1}')
sha_probe_b=$(shasum -a 256 "$SCRATCH_B/winn3-probe" | awk '{print $1}')
sha_probe_c=$(shasum -a 256 "$SCRATCH_C/winn3-probe" | awk '{print $1}')

info "Digests (three scratch paths):"
info "  winn3-gateway A: $sha_gateway_a"
info "  winn3-gateway B: $sha_gateway_b"
info "  winn3-gateway C: $sha_gateway_c"
info "  winn3-probe   A: $sha_probe_a"
info "  winn3-probe   B: $sha_probe_b"
info "  winn3-probe   C: $sha_probe_c"

# Three-path cmp — proves -trimpath, not just two-path luck.
if ! cmp -s "$SCRATCH_A/winn3-gateway" "$SCRATCH_B/winn3-gateway"; then fail "winn3-gateway A != B — not byte-identical across scratch paths"; fi
if ! cmp -s "$SCRATCH_B/winn3-gateway" "$SCRATCH_C/winn3-gateway"; then fail "winn3-gateway B != C — not byte-identical across scratch paths"; fi
if ! cmp -s "$SCRATCH_A/winn3-probe" "$SCRATCH_B/winn3-probe"; then fail "winn3-probe A != B — not byte-identical across scratch paths"; fi
if ! cmp -s "$SCRATCH_B/winn3-probe" "$SCRATCH_C/winn3-probe"; then fail "winn3-probe B != C — not byte-identical across scratch paths"; fi
info "PASS: three independent builds per binary are byte-identical (cmp)"

# Pinned digest check — proves the bytes are the reviewed bytes.
if [ "${UPDATE_EXPECTED:-0}" = "1" ]; then
  info "UPDATE_EXPECTED=1 — printing new pins (gate exits 2, not 0):"
  info "  EXPECTED_GATEWAY_SHA256=\"$sha_gateway_a\""
  info "  EXPECTED_PROBE_SHA256=\"$sha_probe_a\""
  exit 2
fi

if [ "$sha_gateway_a" != "$EXPECTED_GATEWAY_SHA256" ]; then
  fail "winn3-gateway digest mismatch: got $sha_gateway_a expected $EXPECTED_GATEWAY_SHA256 (source or toolchain drift)"
fi
if [ "$sha_probe_a" != "$EXPECTED_PROBE_SHA256" ]; then
  fail "winn3-probe digest mismatch: got $sha_probe_a expected $EXPECTED_PROBE_SHA256 (source or toolchain drift)"
fi
info "PASS: digests match pinned expected values"
info "  expected gateway: $EXPECTED_GATEWAY_SHA256"
info "  expected probe:   $EXPECTED_PROBE_SHA256"

# Structural flags contract — proves the deterministic flags were not dropped.
# Both binaries must carry -trimpath=true and must NOT carry vcs stamp (buildvcs=false).
for bin in "$SCRATCH_A/winn3-gateway" "$SCRATCH_A/winn3-probe"; do
  name=$(basename "$bin")
  settings=$("$GO_BIN" version -m "$bin" 2>&1 || true)
  if ! printf '%s\n' "$settings" | grep -Fq -- "-trimpath=true"; then
    fail "$name: -trimpath=true missing in go version -m (flags drift)"
  fi
  if printf '%s\n' "$settings" | grep -q -- "^	vcs	"; then
    fail "$name: vcs stamp present despite -buildvcs=false (flags drift)"
  fi
  if ! printf '%s\n' "$settings" | grep -Fq -- "GOOS=linux"; then
    fail "$name: GOOS=linux missing in build settings"
  fi
  if ! printf '%s\n' "$settings" | grep -Fq -- "GOARCH=amd64"; then
    fail "$name: GOARCH=amd64 missing in build settings"
  fi
done
info "PASS: go version -m shows -trimpath=true, no vcs, GOOS=linux GOARCH=amd64"

# ELF sanity — correct class for the deploy target (Ubuntu 24.04 amd64, static).
for bin in "$SCRATCH_A/winn3-gateway" "$SCRATCH_A/winn3-probe"; do
  name=$(basename "$bin")
  f=$(file "$bin" 2>&1)
  case "$f" in
    *"ELF 64-bit LSB executable, x86-64"*"statically linked"*) info "PASS: $name is ELF64 x86-64 statically linked — $f" ;;
    *) fail "$name: unexpected file type: $f" ;;
  esac
done

info "PASS: v3 reproducible build gate — all checks green"
info "Digests verified: gateway $EXPECTED_GATEWAY_SHA256  probe $EXPECTED_PROBE_SHA256"
