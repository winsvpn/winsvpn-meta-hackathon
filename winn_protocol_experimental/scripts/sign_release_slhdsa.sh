#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 RELEASE_DIRECTORY OFFLINE_SLH_DSA_PRIVATE_KEY" >&2
  exit 2
fi

RELEASE_DIR=$1
PRIVATE_KEY=$2
MANIFEST="$RELEASE_DIR/SHA256SUMS"
SIGNATURE="$RELEASE_DIR/SHA256SUMS.slhdsa"
PUBLIC_KEY="$RELEASE_DIR/release-signing-public.pem"
CONTEXT=Winn-Protocol-v2/release

if [ ! -f "$MANIFEST" ] || [ ! -f "$PRIVATE_KEY" ]; then
  echo "release manifest or private key is missing" >&2
  exit 1
fi
if ! openssl list -signature-algorithms 2>/dev/null | grep -q 'SLH-DSA'; then
  echo "OpenSSL with SLH-DSA support is required" >&2
  exit 1
fi

(
  cd "$RELEASE_DIR"
  shasum -a 256 -c SHA256SUMS >/dev/null
)
openssl pkey \
  -in "$PRIVATE_KEY" \
  -pubout \
  -out "$PUBLIC_KEY"
openssl pkeyutl \
  -sign \
  -in "$MANIFEST" \
  -inkey "$PRIVATE_KEY" \
  -out "$SIGNATURE" \
  -pkeyopt "context-string:$CONTEXT"

echo "SLH-DSA release signature: $SIGNATURE"
echo "Release verification key: $PUBLIC_KEY"
