#ifndef WINN_STAGE_B_FRAMEWORK_LOADER_H
#define WINN_STAGE_B_FRAMEWORK_LOADER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  WINN_STAGE_B_FRAMEWORK_SHA256_BYTES = 32,
  WINN_STAGE_B_FRAMEWORK_REQUIRED_SYMBOL_COUNT = 6,
  WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES = 1024
};

/*
 * The production API accepts neither a path nor a digest. The Darwin runtime
 * boundary derives the sole containing-app path from the actual provider
 * executable and reads this exact, app-signature-sealed resource:
 *
 *   WinnStageBEngineRuntimePin.manifest
 *
 * Its canonical UTF-8 representation is seven fixed-order LF-terminated lines:
 *
 * schema=winn-stageb-engine-runtime-pin/1
 * source_binary_sha256=<64 lowercase hex>
 * signed_runtime_binary_sha256=<64 lowercase hex>
 * relative_path=Frameworks/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine
 * platform=<iphoneos|iphonesimulator>
 * architectures=<arm64|arm64,x86_64>
 * install_name=@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine
 *
 * Unknown, missing, duplicate, reordered, non-canonical, or unterminated input
 * is rejected. On iOS there is no public SecStaticCode API. The boundary
 * therefore verifies the exact signed-runtime file bytes against the sealed
 * manifest before dlopen; iOS then enforces the embedded code signature while
 * mapping it. A successful map is re-bound to the retained preflight inode and
 * hash before any engine function is called. This is intentionally not
 * described as an independent pre-dlopen cryptographic signature validation.
 * Simulator acceptance is compatibility evidence only and is not represented
 * as the physical device's code-signature enforcement boundary.
 */

typedef enum WinnStageBFrameworkStatus {
  WINN_STAGE_B_FRAMEWORK_OK = 0,
  WINN_STAGE_B_FRAMEWORK_INVALID_ARGUMENT,
  WINN_STAGE_B_FRAMEWORK_UNAVAILABLE,
  WINN_STAGE_B_FRAMEWORK_REENTRANT,
  WINN_STAGE_B_FRAMEWORK_LOCK_FAILED,
  WINN_STAGE_B_FRAMEWORK_PERMANENTLY_FAILED,
  WINN_STAGE_B_FRAMEWORK_BOUNDARY_CHANGED,
  WINN_STAGE_B_FRAMEWORK_PREFLIGHT_FAILED,
  WINN_STAGE_B_FRAMEWORK_INVALID_PREFLIGHT,
  WINN_STAGE_B_FRAMEWORK_INVALID_PATH,
  WINN_STAGE_B_FRAMEWORK_INVALID_MANIFEST,
  WINN_STAGE_B_FRAMEWORK_INVALID_SOURCE_PIN,
  WINN_STAGE_B_FRAMEWORK_INVALID_RUNTIME_PIN,
  WINN_STAGE_B_FRAMEWORK_DIGEST_CONFLATED,
  WINN_STAGE_B_FRAMEWORK_INVALID_FILE_IDENTITY,
  WINN_STAGE_B_FRAMEWORK_INVALID_MACHO,
  WINN_STAGE_B_FRAMEWORK_DLOPEN_FAILED,
  WINN_STAGE_B_FRAMEWORK_SYMBOL_MISSING,
  WINN_STAGE_B_FRAMEWORK_POSTFLIGHT_FAILED,
  WINN_STAGE_B_FRAMEWORK_SYMBOL_IMAGE_MISMATCH,
  WINN_STAGE_B_FRAMEWORK_RUNTIME_REBOUND,
  WINN_STAGE_B_FRAMEWORK_CONTRACT_VERSION_MISMATCH,
  WINN_STAGE_B_FRAMEWORK_ATTEMPT_COUNTER_EXHAUSTED,
  WINN_STAGE_B_FRAMEWORK_ATTEMPT_STALE,
  WINN_STAGE_B_FRAMEWORK_ATTEMPT_ABANDONED,
  WINN_STAGE_B_FRAMEWORK_START_FAILED,
  WINN_STAGE_B_FRAMEWORK_ENGINE_CALL_FAILED
} WinnStageBFrameworkStatus;

typedef struct WinnStageBFrameworkImage WinnStageBFrameworkImage;

/*
 * The pinned upstream wgTurnOff ABI is void. This observation therefore proves
 * only that the exact synchronous invocation returned normally; it does not
 * claim an independent observation of Go, device, or kernel teardown.
 *
 * The output is always zeroed before validation. If invocation_returned is one,
 * the caller must never retry that handle, even when the function's status
 * reports a later serialization-boundary failure.
 */
typedef struct WinnStageBFrameworkTurnOffObservation {
  uint8_t invocation_returned;
  uint8_t reserved[7];
} WinnStageBFrameworkTurnOffObservation;

/*
 * Loads and publishes the one process-lifetime image. The first call is the
 * only attempt. Any failure is permanent because dlopen may already have
 * executed image initialization and the engine must never be unloaded.
 */
WinnStageBFrameworkStatus winn_stage_b_framework_shared_image(
    const WinnStageBFrameworkImage **output_image);

WinnStageBFrameworkStatus winn_stage_b_framework_measured_digest(
    const WinnStageBFrameworkImage *image,
    uint8_t output[WINN_STAGE_B_FRAMEWORK_SHA256_BYTES]);

/*
 * Attempt identifiers are nonzero and strictly increasing. Beginning a newer
 * attempt supersedes the previous one without blocking behind an engine call.
 */
WinnStageBFrameworkStatus winn_stage_b_framework_begin_attempt(
    uint64_t *output_attempt_id);
WinnStageBFrameworkStatus winn_stage_b_framework_abandon_attempt(
    uint64_t attempt_id);
uint64_t winn_stage_b_framework_current_attempt(void);

/*
 * Narrow serialized engine operations. No API exposes a symbol table or accepts
 * a callback that could retain one. turn_on performs late-success cleanup under
 * the same process-global authority when the attempt is abandoned or
 * superseded while the upstream call is running.
 */
WinnStageBFrameworkStatus winn_stage_b_framework_turn_on(
    const WinnStageBFrameworkImage *image,
    uint64_t attempt_id,
    const char *settings,
    int32_t utun_file_descriptor,
    int32_t *output_handle);

WinnStageBFrameworkStatus winn_stage_b_framework_turn_off(
    const WinnStageBFrameworkImage *image,
    int32_t handle);

WinnStageBFrameworkStatus winn_stage_b_framework_turn_off_checked(
    const WinnStageBFrameworkImage *image,
    int32_t handle,
    WinnStageBFrameworkTurnOffObservation *output_observation);

WinnStageBFrameworkStatus winn_stage_b_framework_get_config(
    const WinnStageBFrameworkImage *image,
    int32_t handle,
    char **output_config);

WinnStageBFrameworkStatus winn_stage_b_framework_set_config(
    const WinnStageBFrameworkImage *image,
    int32_t handle,
    const char *settings);

WinnStageBFrameworkStatus winn_stage_b_framework_bump_sockets(
    const WinnStageBFrameworkImage *image,
    int32_t handle);

#ifdef __cplusplus
}
#endif

#endif
