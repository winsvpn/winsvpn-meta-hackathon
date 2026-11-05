#ifndef WINN_STAGE_B_PROVIDER_NATIVE_BRIDGE_H
#define WINN_STAGE_B_PROVIDER_NATIVE_BRIDGE_H

/*
 * Provider-private Swift import surface.
 *
 * This header belongs only to the Packet Tunnel target.  The containing app
 * must never import or link the native owner.  The owner API transfers the
 * mutable secret allocation to C on entry to owner_start, clears the start
 * structure immediately, and invokes its C erase-and-release callback exactly
 * once on every path.  Swift may hold the opaque start-structure address long
 * enough to make that consuming call, but must never construct the secret
 * from String or Data, inspect it, copy it, log it, or release it.
 */
#include "WinnStageBProviderNativeOwner.h"

#include <string.h>

/*
 * Consumes a C-populated start when owner creation fails before owner_start
 * can take ownership.  Keeping this operation in C preserves the same
 * erase-and-release contract without exposing the bytes to Swift.
 */
static inline __attribute__((unused)) void
winn_stage_b_provider_native_bridge_discard_start(
    WinnStageBProviderNativeStart *start) {
  WinnStageBProviderOwnedSecretBuffer secret;
  memset(&secret, 0, sizeof(secret));
  if (start == NULL) {
    return;
  }
  secret = start->config;
  memset(start, 0, sizeof(*start));
  if (secret.bytes != NULL && secret.erase_and_release != NULL) {
    memset(secret.bytes, 0, secret.allocation_size);
    secret.erase_and_release(
        secret.bytes,
        secret.allocation_size,
        secret.release_context);
  }
  memset(&secret, 0, sizeof(secret));
}

#endif
