#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 RELEASE_DIRECTORY TRUSTED_SLH_DSA_PUBLIC_KEY" >&2
  exit 2
fi

RELEASE_DIR=$1
PUBLIC_KEY=$2
CONTEXT=Winn-Protocol-v2/release

# Signature first: until it verifies, SHA256SUMS is untrusted input and
# shasum -c would open whatever paths it names.
openssl pkeyutl \
  -verify \
  -pubin \
  -in "$RELEASE_DIR/SHA256SUMS" \
  -inkey "$PUBLIC_KEY" \
  -sigfile "$RELEASE_DIR/SHA256SUMS.slhdsa" \
  -pkeyopt "context-string:$CONTEXT"
(
  cd "$RELEASE_DIR"
  shasum -a 256 -c SHA256SUMS
)
