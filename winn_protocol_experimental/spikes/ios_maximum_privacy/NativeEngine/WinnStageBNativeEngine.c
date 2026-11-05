#include "WinnStageBNativeEngine.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

enum {
  WINN_STAGE_B_RAW_ALLOCATION_LIMIT =
      WINN_AWG_UAPI_MAX_INPUT_BYTES + 1
};

struct WinnStageBNativeEngine {
  WinnStageBNativeFunctions functions;
  WinnStageBNativeIdentity identity;
  uint8_t expected_peer_public_key[32];
  int32_t owned_handle;
  bool started;
};

_Static_assert(
    offsetof(WinnStageBNativeIdentity, engine_generation) == 112U,
    "WinnStageBNativeIdentity ABI offset changed");
_Static_assert(
    sizeof(WinnStageBNativeIdentity) == 128U,
    "WinnStageBNativeIdentity ABI size changed");
_Static_assert(
    sizeof(WinnStageBNativeObservation) == 192U,
    "WinnStageBNativeObservation ABI size changed");

static void winn_secure_zero(void *bytes, size_t count) {
  volatile uint8_t *cursor = (volatile uint8_t *)bytes;
  while (count != 0U) {
    *cursor = 0U;
    ++cursor;
    --count;
  }
}

static bool winn_bytes_are_nonzero(const uint8_t *bytes, size_t count) {
  uint8_t aggregate = 0U;
  size_t index;
  for (index = 0U; index < count; ++index) {
    aggregate = (uint8_t)(aggregate | bytes[index]);
  }
  return aggregate != 0U;
}

static bool winn_bytes_equal(
    const uint8_t *first,
    const uint8_t *second,
    size_t count) {
  uint8_t difference = 0U;
  size_t index;
  for (index = 0U; index < count; ++index) {
    difference = (uint8_t)(difference | (uint8_t)(first[index] ^ second[index]));
  }
  return difference == 0U;
}

static bool winn_valid_utun_candidate(
    const WinnStageBUtunCandidate *candidate) {
  return candidate->file_descriptor >= 0 &&
         candidate->peer_control_id != 0U &&
         candidate->peer_control_id == candidate->utun_control_id &&
         candidate->unit != 0U &&
         candidate->peer_address_family ==
             (uint32_t)WINN_STAGE_B_DARWIN_AF_SYSTEM &&
         candidate->expected_system_address_family ==
             (uint32_t)WINN_STAGE_B_DARWIN_AF_SYSTEM &&
         candidate->peer_address_family ==
             candidate->expected_system_address_family &&
         candidate->peer_address_length_valid == 1U &&
         candidate->reserved[0] == 0U &&
         candidate->reserved[1] == 0U &&
         candidate->reserved[2] == 0U;
}

static WinnStageBNativeStatus winn_validate_start(
    const WinnStageBNativeStart *start) {
  size_t index;
  size_t payload_length;

  if (start == NULL) {
    return WINN_STAGE_B_NATIVE_INVALID_ARGUMENT;
  }
  if (start->utun_candidate_count == 0U) {
    return WINN_STAGE_B_NATIVE_ZERO_UTUN_CANDIDATES;
  }
  if (start->utun_candidate_count != 1U) {
    return WINN_STAGE_B_NATIVE_MULTIPLE_UTUN_CANDIDATES;
  }
  if (start->utun_candidates == NULL ||
      !winn_valid_utun_candidate(&start->utun_candidates[0])) {
    return WINN_STAGE_B_NATIVE_INVALID_UTUN_CANDIDATE;
  }
  if (start->config == NULL || start->config_buffer_length < 2U) {
    return WINN_STAGE_B_NATIVE_EMPTY_CONFIG;
  }
  if (start->config_buffer_length >
      (size_t)WINN_STAGE_B_MAX_CONFIG_BYTES + 1U) {
    return WINN_STAGE_B_NATIVE_CONFIG_TOO_LARGE;
  }
  payload_length = start->config_buffer_length - 1U;
  if (start->config[payload_length] != 0U ||
      start->config[payload_length - 1U] != (uint8_t)'\n') {
    return WINN_STAGE_B_NATIVE_INVALID_CONFIG_TERMINATION;
  }
  for (index = 0U; index < payload_length; ++index) {
    if (start->config[index] == 0U) {
      return WINN_STAGE_B_NATIVE_INVALID_CONFIG_TERMINATION;
    }
  }
  if (!winn_bytes_are_nonzero(
          start->expected_peer_public_key,
          sizeof(start->expected_peer_public_key)) ||
      !winn_bytes_are_nonzero(
          start->config_sha256,
          sizeof(start->config_sha256)) ||
      start->engine_generation == 0U ||
      start->path_generation == 0U) {
    return WINN_STAGE_B_NATIVE_INVALID_IDENTITY;
  }
  return WINN_STAGE_B_NATIVE_OK;
}

WinnStageBNativeStatus winn_stage_b_native_engine_create(
    const WinnStageBNativeFunctions *functions,
    WinnStageBNativeEngine **output_engine) {
  WinnStageBNativeEngine *engine;

  if (output_engine != NULL) {
    *output_engine = NULL;
  }
  if (functions == NULL || output_engine == NULL ||
      functions->wg_turn_on == NULL ||
      functions->wg_turn_off == NULL ||
      functions->wg_get_config == NULL ||
      functions->raw_allocation_size == NULL ||
      functions->raw_free == NULL ||
      functions->csprng == NULL ||
      functions->sha256 == NULL) {
    return WINN_STAGE_B_NATIVE_INVALID_ARGUMENT;
  }
  engine = (WinnStageBNativeEngine *)calloc(1U, sizeof(*engine));
  if (engine == NULL) {
    return WINN_STAGE_B_NATIVE_ALLOCATION_FAILED;
  }
  engine->functions = *functions;
  engine->owned_handle = -1;
  *output_engine = engine;
  return WINN_STAGE_B_NATIVE_OK;
}

WinnStageBNativeStatus winn_stage_b_native_engine_start(
    WinnStageBNativeEngine *engine,
    const WinnStageBNativeStart *start,
    WinnStageBNativeIdentity *output_identity) {
  WinnStageBNativeStatus validation;
  WinnStageBNativeIdentity identity;
  uint8_t computed_config_sha256[WINN_STAGE_B_SHA256_BYTES];
  uint8_t raw_interface_token[WINN_STAGE_B_OPAQUE_TOKEN_BYTES];
  int32_t handle;

  if (output_identity != NULL) {
    memset(output_identity, 0, sizeof(*output_identity));
  }
  if (engine == NULL || output_identity == NULL) {
    return WINN_STAGE_B_NATIVE_INVALID_ARGUMENT;
  }
  if (engine->started) {
    return WINN_STAGE_B_NATIVE_INVALID_STATE;
  }
  validation = winn_validate_start(start);
  if (validation != WINN_STAGE_B_NATIVE_OK) {
    return validation;
  }

  memset(&identity, 0, sizeof(identity));
  memset(computed_config_sha256, 0, sizeof(computed_config_sha256));
  memset(raw_interface_token, 0, sizeof(raw_interface_token));
  if (engine->functions.sha256(
          start->config,
          start->config_buffer_length - 1U,
          computed_config_sha256,
          engine->functions.context) != 1) {
    winn_secure_zero(computed_config_sha256, sizeof(computed_config_sha256));
    winn_secure_zero(raw_interface_token, sizeof(raw_interface_token));
    return WINN_STAGE_B_NATIVE_SHA256_FAILED;
  }
  if (!winn_bytes_equal(
          computed_config_sha256,
          start->config_sha256,
          sizeof(computed_config_sha256))) {
    winn_secure_zero(computed_config_sha256, sizeof(computed_config_sha256));
    winn_secure_zero(raw_interface_token, sizeof(raw_interface_token));
    return WINN_STAGE_B_NATIVE_CONFIG_SHA256_MISMATCH;
  }
  winn_secure_zero(computed_config_sha256, sizeof(computed_config_sha256));

  if (engine->functions.csprng(
          identity.engine_instance_uuid,
          sizeof(identity.engine_instance_uuid),
          engine->functions.context) != 1 ||
      engine->functions.csprng(
          raw_interface_token,
          sizeof(raw_interface_token),
          engine->functions.context) != 1) {
    winn_secure_zero(&identity, sizeof(identity));
    winn_secure_zero(raw_interface_token, sizeof(raw_interface_token));
    return WINN_STAGE_B_NATIVE_CSPRNG_FAILED;
  }
  if (!winn_bytes_are_nonzero(
          identity.engine_instance_uuid,
          sizeof(identity.engine_instance_uuid)) ||
      !winn_bytes_are_nonzero(
          raw_interface_token, sizeof(raw_interface_token))) {
    winn_secure_zero(&identity, sizeof(identity));
    winn_secure_zero(raw_interface_token, sizeof(raw_interface_token));
    return WINN_STAGE_B_NATIVE_CSPRNG_ZERO_OUTPUT;
  }
  identity.engine_instance_uuid[6] =
      (uint8_t)((identity.engine_instance_uuid[6] & 0x0fU) | 0x40U);
  identity.engine_instance_uuid[8] =
      (uint8_t)((identity.engine_instance_uuid[8] & 0x3fU) | 0x80U);
  if (engine->functions.sha256(
          raw_interface_token,
          sizeof(raw_interface_token),
          identity.winning_interface_token_sha256,
          engine->functions.context) != 1 ||
      !winn_bytes_are_nonzero(
          identity.winning_interface_token_sha256,
          sizeof(identity.winning_interface_token_sha256))) {
    winn_secure_zero(&identity, sizeof(identity));
    winn_secure_zero(raw_interface_token, sizeof(raw_interface_token));
    return WINN_STAGE_B_NATIVE_SHA256_FAILED;
  }
  winn_secure_zero(raw_interface_token, sizeof(raw_interface_token));
  if (engine->functions.sha256(
          start->expected_peer_public_key,
          sizeof(start->expected_peer_public_key),
          identity.expected_peer_sha256,
          engine->functions.context) != 1 ||
      !winn_bytes_are_nonzero(
          identity.expected_peer_sha256,
          sizeof(identity.expected_peer_sha256))) {
    winn_secure_zero(&identity, sizeof(identity));
    return WINN_STAGE_B_NATIVE_SHA256_FAILED;
  }
  memcpy(
      engine->expected_peer_public_key,
      start->expected_peer_public_key,
      sizeof(engine->expected_peer_public_key));
  memcpy(
      identity.config_sha256,
      start->config_sha256,
      sizeof(identity.config_sha256));
  identity.engine_generation = start->engine_generation;
  identity.path_generation = start->path_generation;

  handle = engine->functions.wg_turn_on(
      (const char *)start->config,
      start->utun_candidates[0].file_descriptor,
      engine->functions.context);
  if (handle < 0) {
    winn_secure_zero(&identity, sizeof(identity));
    winn_secure_zero(
        engine->expected_peer_public_key,
        sizeof(engine->expected_peer_public_key));
    return WINN_STAGE_B_NATIVE_TURN_ON_FAILED;
  }

  engine->owned_handle = handle;
  engine->started = true;
  engine->identity = identity;
  *output_identity = identity;
  winn_secure_zero(&identity, sizeof(identity));
  return WINN_STAGE_B_NATIVE_OK;
}

WinnStageBNativeStatus winn_stage_b_native_engine_capture(
    WinnStageBNativeEngine *engine,
    WinnStageBNativeObservation *output_observation,
    WinnAWGUAPIStatus *output_uapi_status) {
  char *raw = NULL;
  size_t allocation_size;
  size_t scan_bound;
  size_t raw_length;
  WinnAWGUAPISnapshot telemetry;
  WinnAWGUAPIStatus uapi_status;
  WinnStageBNativeStatus result;

  if (output_observation != NULL) {
    memset(output_observation, 0, sizeof(*output_observation));
  }
  if (output_uapi_status != NULL) {
    *output_uapi_status = WINN_AWG_UAPI_INVALID_ARGUMENT;
  }
  if (engine == NULL || output_observation == NULL ||
      output_uapi_status == NULL) {
    return WINN_STAGE_B_NATIVE_INVALID_ARGUMENT;
  }
  if (!engine->started || engine->owned_handle < 0) {
    return WINN_STAGE_B_NATIVE_INVALID_STATE;
  }

  raw = engine->functions.wg_get_config(
      engine->owned_handle, engine->functions.context);
  if (raw == NULL) {
    return WINN_STAGE_B_NATIVE_GET_CONFIG_FAILED;
  }
  allocation_size = engine->functions.raw_allocation_size(
      raw, engine->functions.context);
  if (allocation_size == 0U) {
    /*
     * Do not dereference when allocator metadata cannot prove even one
     * readable byte. raw_free is the mandatory secure erase-and-free fallback.
     */
    result = WINN_STAGE_B_NATIVE_INVALID_RAW_ALLOCATION;
    goto release_raw;
  }
  scan_bound = allocation_size;
  if (scan_bound > (size_t)WINN_STAGE_B_RAW_ALLOCATION_LIMIT) {
    scan_bound = (size_t)WINN_STAGE_B_RAW_ALLOCATION_LIMIT;
  }
  raw_length = strnlen(raw, scan_bound);
  if (raw_length == scan_bound) {
    result = allocation_size >=
        (size_t)WINN_STAGE_B_RAW_ALLOCATION_LIMIT
        ? WINN_STAGE_B_NATIVE_GET_CONFIG_TOO_LARGE
        : WINN_STAGE_B_NATIVE_INVALID_RAW_ALLOCATION;
    goto erase_and_release_raw;
  }

  memset(&telemetry, 0, sizeof(telemetry));
  uapi_status = winn_awg_uapi_sanitize(
      (const uint8_t *)raw,
      raw_length,
      engine->expected_peer_public_key,
      &telemetry);
  *output_uapi_status = uapi_status;
  if (uapi_status != WINN_AWG_UAPI_OK) {
    winn_secure_zero(&telemetry, sizeof(telemetry));
    result = WINN_STAGE_B_NATIVE_UAPI_REJECTED;
    goto erase_and_release_raw;
  }

  output_observation->identity = engine->identity;
  output_observation->telemetry = telemetry;
  winn_secure_zero(&telemetry, sizeof(telemetry));
  result = WINN_STAGE_B_NATIVE_OK;

erase_and_release_raw:
  winn_secure_zero(raw, allocation_size);
release_raw:
  /*
   * On an allocation-size contract failure the injected release function is
   * the required secure erase-and-free fallback. On all conforming paths the
   * complete allocation has already been erased above.
   */
  engine->functions.raw_free(raw, engine->functions.context);
  return result;
}

WinnStageBNativeStatus winn_stage_b_native_engine_stop(
    WinnStageBNativeEngine *engine) {
  int32_t handle;
  if (engine == NULL) {
    return WINN_STAGE_B_NATIVE_INVALID_ARGUMENT;
  }
  if (!engine->started) {
    return WINN_STAGE_B_NATIVE_OK;
  }
  handle = engine->owned_handle;
  engine->owned_handle = -1;
  engine->started = false;
  winn_secure_zero(&engine->identity, sizeof(engine->identity));
  winn_secure_zero(
      engine->expected_peer_public_key,
      sizeof(engine->expected_peer_public_key));
  engine->functions.wg_turn_off(handle, engine->functions.context);
  return WINN_STAGE_B_NATIVE_OK;
}

WinnStageBNativeStatus winn_stage_b_native_engine_record_external_stop(
    WinnStageBNativeEngine *engine,
    int32_t exact_owned_handle) {
  if (engine == NULL || exact_owned_handle < 0) {
    return WINN_STAGE_B_NATIVE_INVALID_ARGUMENT;
  }
  if (!engine->started || engine->owned_handle != exact_owned_handle) {
    return WINN_STAGE_B_NATIVE_INVALID_STATE;
  }
  engine->owned_handle = -1;
  engine->started = false;
  winn_secure_zero(&engine->identity, sizeof(engine->identity));
  winn_secure_zero(
      engine->expected_peer_public_key,
      sizeof(engine->expected_peer_public_key));
  return WINN_STAGE_B_NATIVE_OK;
}

void winn_stage_b_native_engine_destroy(
    WinnStageBNativeEngine **engine) {
  if (engine == NULL || *engine == NULL) {
    return;
  }
  (void)winn_stage_b_native_engine_stop(*engine);
  winn_secure_zero(*engine, sizeof(**engine));
  free(*engine);
  *engine = NULL;
}
