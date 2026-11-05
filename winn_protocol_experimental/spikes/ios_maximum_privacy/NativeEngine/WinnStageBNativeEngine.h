#ifndef WINN_STAGE_B_NATIVE_ENGINE_H
#define WINN_STAGE_B_NATIVE_ENGINE_H

#include "WinnAWGUAPISanitizer.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  WINN_STAGE_B_UUID_BYTES = 16,
  WINN_STAGE_B_SHA256_BYTES = 32,
  WINN_STAGE_B_OPAQUE_TOKEN_BYTES = 32,
  WINN_STAGE_B_MAX_CONFIG_BYTES = WINN_AWG_UAPI_MAX_INPUT_BYTES,
  WINN_STAGE_B_DARWIN_AF_SYSTEM = 32
};

typedef enum WinnStageBNativeStatus {
  WINN_STAGE_B_NATIVE_OK = 0,
  WINN_STAGE_B_NATIVE_INVALID_ARGUMENT,
  WINN_STAGE_B_NATIVE_ALLOCATION_FAILED,
  WINN_STAGE_B_NATIVE_INVALID_STATE,
  WINN_STAGE_B_NATIVE_ZERO_UTUN_CANDIDATES,
  WINN_STAGE_B_NATIVE_MULTIPLE_UTUN_CANDIDATES,
  WINN_STAGE_B_NATIVE_INVALID_UTUN_CANDIDATE,
  WINN_STAGE_B_NATIVE_EMPTY_CONFIG,
  WINN_STAGE_B_NATIVE_CONFIG_TOO_LARGE,
  WINN_STAGE_B_NATIVE_INVALID_CONFIG_TERMINATION,
  WINN_STAGE_B_NATIVE_INVALID_IDENTITY,
  WINN_STAGE_B_NATIVE_SHA256_FAILED,
  WINN_STAGE_B_NATIVE_CONFIG_SHA256_MISMATCH,
  WINN_STAGE_B_NATIVE_CSPRNG_FAILED,
  WINN_STAGE_B_NATIVE_CSPRNG_ZERO_OUTPUT,
  WINN_STAGE_B_NATIVE_TURN_ON_FAILED,
  WINN_STAGE_B_NATIVE_GET_CONFIG_FAILED,
  WINN_STAGE_B_NATIVE_INVALID_RAW_ALLOCATION,
  WINN_STAGE_B_NATIVE_GET_CONFIG_TOO_LARGE,
  WINN_STAGE_B_NATIVE_UAPI_REJECTED
} WinnStageBNativeStatus;

/*
 * A discovery record produced by the Darwin boundary after getpeername and
 * CTLIOCGINFO. The core accepts exactly one record and independently checks
 * the fail-closed relationships below. file_descriptor and unit never appear
 * in WinnStageBNativeIdentity or WinnStageBNativeObservation.
 */
typedef struct WinnStageBUtunCandidate {
  int32_t file_descriptor;
  uint32_t peer_control_id;
  uint32_t utun_control_id;
  uint32_t unit;
  uint32_t peer_address_family;
  uint32_t expected_system_address_family;
  uint8_t peer_address_length_valid;
  uint8_t reserved[3];
} WinnStageBUtunCandidate;

/*
 * config points at a caller-owned canonical C buffer. config_buffer_length
 * includes exactly one trailing NUL. Thus valid input is:
 *   config[0 .. length-2] (nonempty, no interior NUL, final byte is LF)
 *   config[length-1] == NUL.
 * The core calls wg_turn_on synchronously and never copies or retains config.
 */
typedef struct WinnStageBNativeStart {
  const uint8_t *config;
  size_t config_buffer_length;
  const WinnStageBUtunCandidate *utun_candidates;
  size_t utun_candidate_count;
  uint8_t expected_peer_public_key[32];
  uint8_t config_sha256[32];
  uint64_t engine_generation;
  uint64_t path_generation;
} WinnStageBNativeStart;

/*
 * WinnStageBNativeIdentity and WinnStageBNativeObservation are secret-free.
 * In particular they contain no private/preshared key, configuration pointer,
 * raw UAPI pointer, file descriptor, or utun unit.
 */
typedef struct WinnStageBNativeIdentity {
  /* Raw RFC 4122/9562 UUID bytes: version 4 and RFC variant are enforced. */
  uint8_t engine_instance_uuid[WINN_STAGE_B_UUID_BYTES];
  /* SHA-256 of a transient CSPRNG token; the raw token is never retained. */
  uint8_t winning_interface_token_sha256[WINN_STAGE_B_SHA256_BYTES];
  uint8_t expected_peer_sha256[WINN_STAGE_B_SHA256_BYTES];
  uint8_t config_sha256[32];
  uint64_t engine_generation;
  uint64_t path_generation;
} WinnStageBNativeIdentity;

typedef struct WinnStageBNativeObservation {
  WinnStageBNativeIdentity identity;
  WinnAWGUAPISnapshot telemetry;
} WinnStageBNativeObservation;

typedef int32_t (*WinnStageBWGTurnOn)(
    const char *settings,
    int32_t utun_file_descriptor,
    void *context);
typedef void (*WinnStageBWGTurnOff)(int32_t handle, void *context);
typedef char *(*WinnStageBWGGetConfig)(int32_t handle, void *context);
typedef size_t (*WinnStageBRawAllocationSize)(
    const char *allocation,
    void *context);
typedef void (*WinnStageBRawFree)(char *allocation, void *context);
typedef int (*WinnStageBCSPRNG)(
    uint8_t *output,
    size_t output_length,
    void *context);
typedef int (*WinnStageBSHA256)(
    const uint8_t *input,
    size_t input_length,
    uint8_t output[WINN_STAGE_B_SHA256_BYTES],
    void *context);

typedef struct WinnStageBNativeFunctions {
  WinnStageBWGTurnOn wg_turn_on;
  WinnStageBWGTurnOff wg_turn_off;
  WinnStageBWGGetConfig wg_get_config;
  WinnStageBRawAllocationSize raw_allocation_size;
  WinnStageBRawFree raw_free;
  WinnStageBCSPRNG csprng;
  WinnStageBSHA256 sha256;
  void *context;
} WinnStageBNativeFunctions;

typedef struct WinnStageBNativeEngine WinnStageBNativeEngine;

WinnStageBNativeStatus winn_stage_b_native_engine_create(
    const WinnStageBNativeFunctions *functions,
    WinnStageBNativeEngine **output_engine);

WinnStageBNativeStatus winn_stage_b_native_engine_start(
    WinnStageBNativeEngine *engine,
    const WinnStageBNativeStart *start,
    WinnStageBNativeIdentity *output_identity);

WinnStageBNativeStatus winn_stage_b_native_engine_capture(
    WinnStageBNativeEngine *engine,
    WinnStageBNativeObservation *output_observation,
    WinnAWGUAPIStatus *output_uapi_status);

/*
 * stop is idempotent. wg_turn_off is called exactly once for each successfully
 * owned handle, including when destroy performs the first stop.
 */
WinnStageBNativeStatus winn_stage_b_native_engine_stop(
    WinnStageBNativeEngine *engine);

/*
 * Records that an external serialized owner synchronously invoked
 * wgTurnOff(exact_owned_handle) and that the pinned void call returned. This
 * function performs no raw engine call. It refuses every state or handle
 * mismatch, and on success erases the engine's retained identity so a later
 * destroy cannot invoke wgTurnOff a second time.
 */
WinnStageBNativeStatus winn_stage_b_native_engine_record_external_stop(
    WinnStageBNativeEngine *engine,
    int32_t exact_owned_handle);

/*
 * destroy accepts a pointer-to-pointer, stops if needed, erases the context,
 * frees it, and writes NULL. Repeating destroy on the same pointer is safe.
 */
void winn_stage_b_native_engine_destroy(
    WinnStageBNativeEngine **engine);

/*
 * Pinned allocation contract for the future Darwin adapter:
 *
 * wgGetConfig from the pinned amneziawg-go C ABI returns a C.CString allocated
 * with C.malloc, owned by the caller. The adapter's raw_allocation_size must
 * return the complete writable allocation size (malloc_size on Darwin), and
 * raw_free must release that same allocation exactly once with C.free/free.
 *
 * Capture bounds strnlen to min(the complete reported allocation size,
 * WINN_AWG_UAPI_MAX_INPUT_BYTES + 1), so it never reads beyond malloc_size.
 * If no NUL occurs in that bound, capture
 * rejects the value, securely erases the complete reported allocation, and
 * frees it once. A zero/implausible allocation size is an adapter-contract
 * failure; raw_free must itself remain a secure erase-and-free fallback for
 * that case. wgTurnOn is also pinned to parse settings synchronously: it must
 * not retain the caller-owned configuration pointer after returning. Raw data
 * must never be logged, bridged to String, or copied.
 *
 * The Darwin owner must serialize every raw wg call across all engine contexts
 * in the packet-tunnel extension. A per-object mutex is insufficient for the
 * pinned Go library's process-global handle map. It must also keep the
 * Go-bearing dylib loaded until process exit; dlclose is prohibited because
 * upstream initialization starts a permanent signal goroutine.
 *
 * Candidate discovery/revalidation is deliberately outside this portable
 * core. The Darwin owner must enumerate once, duplicate the sole fd, re-run
 * getpeername/CTLIOCGINFO and UTUN_OPT_IFNAME checks on that duplicate directly
 * before this call, pass only that record, and close the duplicate after
 * wgTurnOn returns. It must reject descriptor reuse and zero/multiple matches.
 * The same owner must keep the secret configuration in a mutable owned buffer
 * and securely erase it immediately after start returns on every path.
 */

#ifdef __cplusplus
}
#endif

#endif
