#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
GO_BIN=${GO_BIN:-go}
FIRST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/winn-build-first.XXXXXX")
SECOND_DIR=$(mktemp -d "${TMPDIR:-/tmp}/winn-build-second.XXXXXX")
FIRST_RELEASE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/winn-release-first.XXXXXX")
SECOND_RELEASE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/winn-release-second.XXXXXX")
FIRST_RELEASE_CACHE=$(mktemp -d "${TMPDIR:-/tmp}/winn-release-cache-first.XXXXXX")
SECOND_RELEASE_CACHE=$(mktemp -d "${TMPDIR:-/tmp}/winn-release-cache-second.XXXXXX")

cleanup() {
  for directory in \
    "$FIRST_DIR" "$SECOND_DIR" \
    "$FIRST_RELEASE_DIR" "$SECOND_RELEASE_DIR" \
    "$FIRST_RELEASE_CACHE" "$SECOND_RELEASE_CACHE"; do
    if [ -e "$directory" ]; then
      rm -r "$directory"
    fi
  done
}
trap cleanup EXIT HUP INT TERM

# Single source of truth for both the build and the comparison. These were
# previously two separate literal lists, which is how the anchor tooling and the
# formal verifier came to be omitted from this gate: a command added to one list
# was silently not compared by the other.
RELEASE_COMMANDS="winn-server winn-client winn-carrier-server winn-carrier-client winn-token-issuer winn-token winn-manifest winn-admin winn-audit winn-pki"

# Anchor tooling and the formal matrix verifier. These produce and check the
# formal evidence, so an auditor must be able to rebuild them byte-for-byte;
# omitting them leaves a hole in the custody chain even when the evidence itself
# is sound. They are pinned to linux/amd64 because that is the artifact actually
# deployed to the providers and to AICORE, and therefore the one audited.
ANCHOR_COMMANDS="winn-phase1-anchor-server winn-phase1-anchor-pin winn-phase1-anchor-client winn-phase1-anchor-keygen winn-phase1-matrix-verify"

# The drivers that generate formal evidence. These were in neither list above,
# so the binaries whose output becomes sealed evidence were themselves outside
# the reproducibility gate -- a hole in the custody chain at the point where
# evidence is produced rather than merely checked. linux/amd64 for the same
# reason as the anchor set: that is the artifact deployed and audited.
AUTO_COMMANDS="winn-auto-e2e winn-auto-fixture winn-h3-e2e winn-measurement-verify"

# winn-auto-e2e and winn-h3-e2e stamp -X main.sourceDigest the way
# scripts/build_auto_e2e_linux.sh does. That value is a deterministic function
# of the source tree, so recomputing it per build leaves the two-build cmp
# valid; hardcoding it would instead make this gate pass over a stale digest.
DIGEST_STAMPED_COMMANDS="winn-auto-e2e winn-h3-e2e"

build_set() {
  output_dir=$1
  for command in $RELEASE_COMMANDS; do
    CGO_ENABLED=0 "$GO_BIN" build \
      -mod=readonly \
      -trimpath \
      -buildvcs=false \
      -ldflags="-s -w -buildid=" \
      -o "$output_dir/$command" \
      "./cmd/$command"
  done
  for command in $ANCHOR_COMMANDS; do
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO_BIN" build \
      -mod=readonly \
      -trimpath \
      -buildvcs=false \
      -ldflags="-s -w -buildid=" \
      -o "$output_dir/$command" \
      "./cmd/$command"
  done
  for command in $AUTO_COMMANDS; do
    ldflags="-s -w -buildid="
    for stamped in $DIGEST_STAMPED_COMMANDS; do
      if [ "$command" = "$stamped" ]; then
        source_digest=$(
          GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GO_BIN="$GO_BIN" \
            "$ROOT_DIR/scripts/source_manifest.sh" \
            "./cmd/$command" "$output_dir/$command.source.sha256"
        )
        ldflags="$ldflags -X main.sourceDigest=$source_digest"
      fi
    done
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO_BIN" build \
      -mod=readonly \
      -trimpath \
      -buildvcs=false \
      -ldflags="$ldflags" \
      -o "$output_dir/$command" \
      "./cmd/$command"
  done
}

cd "$ROOT_DIR"
build_set "$FIRST_DIR"
build_set "$SECOND_DIR"

for command in $RELEASE_COMMANDS $ANCHOR_COMMANDS $AUTO_COMMANDS; do
  cmp "$FIRST_DIR/$command" "$SECOND_DIR/$command"
done

# The stamped digest is an input to those binaries, so compare the source
# manifests it was derived from as well: identical bytes from a drifted input
# set would otherwise read as a pass.
for command in $DIGEST_STAMPED_COMMANDS; do
  cmp "$FIRST_DIR/$command.source.sha256" "$SECOND_DIR/$command.source.sha256"
done

# The release package includes more than executable bytes: normalized build
# metadata, module files, third-party licenses, an augmented CycloneDX SBOM,
# and the manifest that commits to all of them. Build that complete directory
# twice with separate empty build caches. Use the module cache's download tree
# as a file:// proxy so the regression is offline while still allowing Go to
# answer version/deprecation queries made by pinned tool modules.
MODULE_CACHE=$("$GO_BIN" env GOMODCACHE)
LOCAL_MODULE_PROXY=$MODULE_CACHE/cache/download
if [ ! -d "$LOCAL_MODULE_PROXY" ]; then
  echo "local Go module proxy is unavailable: $LOCAL_MODULE_PROXY" >&2
  exit 1
fi

GOTOOLCHAIN=local \
  GOPROXY="file://$LOCAL_MODULE_PROXY" \
  GOCACHE="$FIRST_RELEASE_CACHE" \
  GO_BIN="$GO_BIN" \
  "$ROOT_DIR/scripts/build_release.sh" "$FIRST_RELEASE_DIR"
GOTOOLCHAIN=local \
  GOPROXY="file://$LOCAL_MODULE_PROXY" \
  GOCACHE="$SECOND_RELEASE_CACHE" \
  GO_BIN="$GO_BIN" \
  "$ROOT_DIR/scripts/build_release.sh" "$SECOND_RELEASE_DIR"

if ! diff -qr "$FIRST_RELEASE_DIR" "$SECOND_RELEASE_DIR"; then
  echo "complete release directories are not byte-for-byte identical" >&2
  exit 1
fi

echo "PASS: two independent release builds are byte-for-byte identical"
echo "PASS: anchor tooling and formal verifier are reproducible (linux/amd64)"
echo "PASS: evidence-generating Auto drivers are reproducible (linux/amd64)"
echo "PASS: complete offline release directories are byte-for-byte identical"
