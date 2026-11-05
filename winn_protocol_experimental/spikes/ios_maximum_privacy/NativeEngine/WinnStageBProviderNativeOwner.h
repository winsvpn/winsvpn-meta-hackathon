#ifndef WINN_STAGE_B_PROVIDER_NATIVE_OWNER_H
#define WINN_STAGE_B_PROVIDER_NATIVE_OWNER_H

#include "WinnStageBNativeEngine.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  WINN_STAGE_B_PROVIDER_NATIVE_GENERATION_NONCE_BYTES = 16,
  WINN_STAGE_B_PROVIDER_NATIVE_SHA256_BYTES = 32
};

typedef enum WinnStageBProviderNativeStatus {
  WINN_STAGE_B_PROVIDER_NATIVE_OK = 0,
  WINN_STAGE_B_PROVIDER_NATIVE_INVALID_ARGUMENT,
  WINN_STAGE_B_PROVIDER_NATIVE_REENTRANT,
  WINN_STAGE_B_PROVIDER_NATIVE_LOCK_FAILED,
  WINN_STAGE_B_PROVIDER_NATIVE_BUSY,
  WINN_STAGE_B_PROVIDER_NATIVE_INVALID_STATE,
  WINN_STAGE_B_PROVIDER_NATIVE_GENERATION_MISMATCH,
  WINN_STAGE_B_PROVIDER_NATIVE_HANDLE_MISMATCH,
  WINN_STAGE_B_PROVIDER_NATIVE_SECRET_BUFFER_INVALID,
  WINN_STAGE_B_PROVIDER_NATIVE_FRAMEWORK_FAILED,
  WINN_STAGE_B_PROVIDER_NATIVE_ATTEMPT_FAILED,
  WINN_STAGE_B_PROVIDER_NATIVE_UTUN_FAILED,
  WINN_STAGE_B_PROVIDER_NATIVE_ENGINE_FAILED,
  WINN_STAGE_B_PROVIDER_NATIVE_ABANDONED,
  WINN_STAGE_B_PROVIDER_NATIVE_STOP_NOT_INVOKED,
  WINN_STAGE_B_PROVIDER_NATIVE_CAPTURE_COUNTER_EXHAUSTED,
  WINN_STAGE_B_PROVIDER_NATIVE_POISONED
} WinnStageBProviderNativeStatus;

typedef enum WinnStageBProviderNativeState {
  WINN_STAGE_B_PROVIDER_NATIVE_STATE_READY = 0,
  WINN_STAGE_B_PROVIDER_NATIVE_STATE_STARTING,
  WINN_STAGE_B_PROVIDER_NATIVE_STATE_ABANDON_REQUESTED,
  WINN_STAGE_B_PROVIDER_NATIVE_STATE_RUNNING,
  WINN_STAGE_B_PROVIDER_NATIVE_STATE_STOPPING,
  WINN_STAGE_B_PROVIDER_NATIVE_STATE_STOP_PENDING_NOT_INVOKED,
  WINN_STAGE_B_PROVIDER_NATIVE_STATE_STOPPED,
  WINN_STAGE_B_PROVIDER_NATIVE_STATE_POISONED_AFTER_STOP_INVOCATION
} WinnStageBProviderNativeState;

typedef struct WinnStageBProviderNativeGeneration {
  uint8_t attempt_nonce[
      WINN_STAGE_B_PROVIDER_NATIVE_GENERATION_NONCE_BYTES];
  uint64_t lifecycle_sequence;
} WinnStageBProviderNativeGeneration;

/*
 * Ownership of bytes transfers to owner_start on entry, including when another
 * argument is invalid. owner_start clears this structure immediately and calls
 * erase_and_release exactly once with the complete allocation on every path.
 * Swift must not source these bytes from String or Data.
 */
typedef void (*WinnStageBProviderEraseAndRelease)(
    uint8_t *bytes,
    size_t allocation_size,
    void *context);

typedef struct WinnStageBProviderOwnedSecretBuffer {
  uint8_t *bytes;
  size_t allocation_size;
  size_t buffer_length;
  WinnStageBProviderEraseAndRelease erase_and_release;
  void *release_context;
} WinnStageBProviderOwnedSecretBuffer;

typedef struct WinnStageBProviderNativeStart {
  WinnStageBProviderNativeGeneration generation;
  WinnStageBProviderOwnedSecretBuffer config;
  uint8_t config_sha256[WINN_STAGE_B_PROVIDER_NATIVE_SHA256_BYTES];
  uint8_t expected_peer_public_key[
      WINN_STAGE_B_PROVIDER_NATIVE_SHA256_BYTES];
  uint64_t engine_generation;
  uint64_t path_generation;
} WinnStageBProviderNativeStart;

/*
 * lifecycle_handle is an in-process control value. It is never part of native
 * identity, telemetry, logs, or physical evidence.
 */
typedef struct WinnStageBProviderNativeStartResult {
  WinnStageBNativeIdentity identity;
  uint8_t signed_runtime_sha256[
      WINN_STAGE_B_PROVIDER_NATIVE_SHA256_BYTES];
  int32_t lifecycle_handle;
  uint8_t reserved[4];
} WinnStageBProviderNativeStartResult;

typedef struct WinnStageBProviderNativeCapture {
  uint64_t capture_ordinal;
  WinnStageBNativeObservation observation;
} WinnStageBProviderNativeCapture;

typedef enum WinnStageBProviderStopInvocation {
  WINN_STAGE_B_PROVIDER_STOP_NOT_INVOKED = 0,
  WINN_STAGE_B_PROVIDER_STOP_VOID_INVOCATION_RETURNED = 1
} WinnStageBProviderStopInvocation;

/*
 * VOID_INVOCATION_RETURNED proves only that the exact serialized
 * wgTurnOff(handle) invocation returned. It is not an independent observation
 * of opaque Go, device, or kernel teardown.
 */
typedef struct WinnStageBProviderNativeStopResult {
  WinnStageBProviderStopInvocation invocation;
  int32_t lifecycle_handle;
  uint8_t lifecycle_acknowledgement_permitted;
  uint8_t owner_poisoned_after_invocation;
  uint8_t reserved[2];
} WinnStageBProviderNativeStopResult;

/*
 * Copyable opaque value. storage_address is never dereferenced until the
 * process-global registry matches both it and lifecycle_token. The token is
 * never reused, so a stale copied value cannot bind to a later allocation
 * even if the allocator reuses the same address.
 */
typedef struct WinnStageBProviderNativeOwner {
  uintptr_t storage_address;
  uint64_t lifecycle_token;
} WinnStageBProviderNativeOwner;

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_create(
    WinnStageBProviderNativeOwner *output_owner);

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_start(
    const WinnStageBProviderNativeOwner *owner,
    WinnStageBProviderNativeStart *consumed_start,
    WinnStageBProviderNativeStartResult *output_result);

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_abandon(
    const WinnStageBProviderNativeOwner *owner,
    const WinnStageBProviderNativeGeneration *generation);

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_capture(
    const WinnStageBProviderNativeOwner *owner,
    const WinnStageBProviderNativeGeneration *generation,
    WinnStageBProviderNativeCapture *output_capture);

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_stop(
    const WinnStageBProviderNativeOwner *owner,
    const WinnStageBProviderNativeGeneration *generation,
    int32_t expected_handle,
    WinnStageBProviderNativeStopResult *output_result);

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_state(
    const WinnStageBProviderNativeOwner *owner,
    WinnStageBProviderNativeState *output_state);

/*
 * Refuses STARTING, RUNNING, STOPPING, and STOP_PENDING owners. It never
 * silently stops an engine. The process-lifetime framework image is never
 * unloaded. Every public call is admitted through a process-global
 * pointer-keyed registry before the owner is dereferenced. Destroy marks the
 * owner non-admitting only when no call is admitted; otherwise it returns
 * BUSY. A stale pointer used after successful removal fails without being
 * dereferenced.
 */
WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_destroy(
    WinnStageBProviderNativeOwner *owner);

#ifdef __cplusplus
}
#endif

#endif
