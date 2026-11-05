#include "WinnStageBFrameworkLoaderInternal.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#if __has_include(<TargetConditionals.h>)
#include <TargetConditionals.h>
#else
#define TARGET_OS_SIMULATOR 0
#endif

_Static_assert(
    sizeof(void *) == sizeof(WinnStageBFrameworkSymbolAddress),
    "dlsym address width differs from a function pointer");
_Static_assert(
    sizeof(WinnStageBFrameworkSymbolAddress) ==
        sizeof(WinnStageBFrameworkWGTurnOn),
    "wgTurnOn function pointer width changed");
_Static_assert(
    sizeof(WinnStageBFrameworkSymbolAddress) ==
        sizeof(WinnStageBFrameworkWGTurnOff),
    "wgTurnOff function pointer width changed");
_Static_assert(
    sizeof(WinnStageBFrameworkSymbolAddress) ==
        sizeof(WinnStageBFrameworkWGGetConfig),
    "wgGetConfig function pointer width changed");
_Static_assert(
    sizeof(WinnStageBFrameworkSymbolAddress) ==
        sizeof(WinnStageBFrameworkWGSetConfig),
    "wgSetConfig function pointer width changed");
_Static_assert(
    sizeof(WinnStageBFrameworkSymbolAddress) ==
        sizeof(WinnStageBFrameworkWGBumpSockets),
    "wgBumpSockets function pointer width changed");
_Static_assert(
    sizeof(WinnStageBFrameworkSymbolAddress) ==
        sizeof(WinnStageBFrameworkContractVersion),
    "contract-version function pointer width changed");
_Static_assert(
    sizeof(WinnStageBFrameworkTurnOffObservation) == 8U,
    "turn-off observation ABI size changed");

static const char *const winn_required_symbols
    [WINN_STAGE_B_FRAMEWORK_REQUIRED_SYMBOL_COUNT] = {
        "wgTurnOn",
        "wgTurnOff",
        "wgGetConfig",
        "wgSetConfig",
        "wgBumpSockets",
        "wins_amneziawg_packet_engine_contract_version"};

static const char winn_runtime_path_suffix[] =
    ".app/Frameworks/WinsAmneziaWGPacketEngine.framework/"
    "WinsAmneziaWGPacketEngine";

struct WinnStageBFrameworkImage {
  WinnStageBFrameworkSymbols symbols;
  uint8_t signed_runtime_sha256[WINN_STAGE_B_FRAMEWORK_SHA256_BYTES];
  uint64_t device;
  uint64_t inode;
  uint64_t file_size;
  void *dyld_handle;
};

static pthread_mutex_t winn_authority = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t winn_attempt_authority = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local unsigned winn_authority_depth;
static _Atomic uint64_t winn_attempt_counter;
static _Atomic uint64_t winn_current_attempt;
static _Atomic unsigned winn_current_attempt_phase;

enum {
  WINN_ATTEMPT_PHASE_NONE = 0U,
  WINN_ATTEMPT_PHASE_ACTIVE = 1U,
  WINN_ATTEMPT_PHASE_COMMITTED = 2U
};

#if defined(WINN_STAGE_B_FRAMEWORK_TESTING)
static _Atomic int winn_test_commit_pause_enabled;
static _Atomic int winn_test_commit_pause_entered;
static _Atomic int winn_test_commit_pause_released;
#endif

static bool winn_shared_attempted;
static WinnStageBFrameworkStatus winn_shared_status =
    WINN_STAGE_B_FRAMEWORK_UNAVAILABLE;
static const WinnStageBFrameworkImage *winn_shared_image;
static WinnStageBFrameworkRuntimeBoundary winn_shared_boundary;

static void winn_secure_zero(void *bytes, size_t count) {
  volatile uint8_t *cursor = (volatile uint8_t *)bytes;
  while (count != 0U) {
    *cursor = 0U;
    ++cursor;
    --count;
  }
}

static bool winn_bytes_nonzero(const uint8_t *bytes, size_t count) {
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
    difference =
        (uint8_t)(difference | (uint8_t)(first[index] ^ second[index]));
  }
  return difference == 0U;
}

static WinnStageBFrameworkStatus winn_lock(void) {
  int result;
  if (winn_authority_depth != 0U) {
    return WINN_STAGE_B_FRAMEWORK_REENTRANT;
  }
  result = pthread_mutex_lock(&winn_authority);
  if (result != 0) {
    return WINN_STAGE_B_FRAMEWORK_LOCK_FAILED;
  }
  winn_authority_depth = 1U;
  return WINN_STAGE_B_FRAMEWORK_OK;
}

static WinnStageBFrameworkStatus winn_unlock(void) {
  int result;
  if (winn_authority_depth != 1U) {
    return WINN_STAGE_B_FRAMEWORK_LOCK_FAILED;
  }
  winn_authority_depth = 0U;
  result = pthread_mutex_unlock(&winn_authority);
  return result == 0 ? WINN_STAGE_B_FRAMEWORK_OK
                     : WINN_STAGE_B_FRAMEWORK_LOCK_FAILED;
}

static WinnStageBFrameworkStatus winn_attempt_lock(void) {
  return pthread_mutex_lock(&winn_attempt_authority) == 0
             ? WINN_STAGE_B_FRAMEWORK_OK
             : WINN_STAGE_B_FRAMEWORK_LOCK_FAILED;
}

static WinnStageBFrameworkStatus winn_attempt_unlock(void) {
  return pthread_mutex_unlock(&winn_attempt_authority) == 0
             ? WINN_STAGE_B_FRAMEWORK_OK
             : WINN_STAGE_B_FRAMEWORK_LOCK_FAILED;
}

const WinnStageBFrameworkExpected *winn_stage_b_framework_expected(void) {
#if TARGET_OS_SIMULATOR
  static const WinnStageBFrameworkExpected expected = {
      .source_binary_sha256 = {
          0x00, 0xa1, 0x7d, 0xfd, 0x70, 0x2d, 0xc0, 0x49,
          0x0e, 0xfd, 0x4f, 0x39, 0xbc, 0x22, 0x59, 0xfc,
          0xc3, 0x8f, 0xa4, 0xee, 0x83, 0x11, 0x88, 0x54,
          0x99, 0xb5, 0xf1, 0x61, 0x17, 0x13, 0xfa, 0x03},
      .platform = WINN_STAGE_B_FRAMEWORK_PLATFORM_IPHONESIMULATOR,
#if defined(__x86_64__)
      .architecture = WINN_STAGE_B_FRAMEWORK_ARCH_X86_64};
#else
      .architecture = WINN_STAGE_B_FRAMEWORK_ARCH_ARM64};
#endif
#else
  static const WinnStageBFrameworkExpected expected = {
      .source_binary_sha256 = {
          0xe0, 0xe8, 0x10, 0x03, 0x9d, 0x0e, 0xd4, 0x3b,
          0x1a, 0x59, 0x9b, 0xb6, 0x43, 0x20, 0xb0, 0xee,
          0x4a, 0xb4, 0x90, 0x3c, 0xbd, 0xfd, 0x33, 0xe0,
          0x48, 0xbf, 0x0f, 0xb5, 0xe7, 0xf1, 0x16, 0xcd},
      .platform = WINN_STAGE_B_FRAMEWORK_PLATFORM_IPHONEOS,
#if defined(__x86_64__)
      .architecture = WINN_STAGE_B_FRAMEWORK_ARCH_X86_64};
#else
      .architecture = WINN_STAGE_B_FRAMEWORK_ARCH_ARM64};
#endif
#endif
  return &expected;
}

static bool winn_path_is_canonical_engine(const char *path) {
  size_t length;
  size_t suffix_length = sizeof(winn_runtime_path_suffix) - 1U;
  size_t index;
  if (path == NULL || path[0] != '/') {
    return false;
  }
  length = strnlen(path, (size_t)WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES);
  if (length <= suffix_length ||
      length >= (size_t)WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES ||
      memcmp(
          path + length - suffix_length,
          winn_runtime_path_suffix,
          suffix_length) != 0) {
    return false;
  }
  for (index = 0U; index < length; ++index) {
    unsigned char byte = (unsigned char)path[index];
    if (byte < 0x20U || byte >= 0x7fU) {
      return false;
    }
    if (byte == (unsigned char)'/' && index + 1U < length) {
      unsigned char next = (unsigned char)path[index + 1U];
      if (next == (unsigned char)'/' || next == (unsigned char)'.') {
        return false;
      }
    }
  }
  return strstr(path, "/PlugIns/") == NULL;
}

static bool winn_boundary_valid(
    const WinnStageBFrameworkRuntimeBoundary *boundary) {
  return boundary != NULL && boundary->preflight != NULL &&
         boundary->dlopen_absolute != NULL &&
         boundary->dlsym_handle != NULL && boundary->postflight != NULL;
}

static bool winn_boundary_equal(
    const WinnStageBFrameworkRuntimeBoundary *first,
    const WinnStageBFrameworkRuntimeBoundary *second) {
  return first->preflight == second->preflight &&
         first->dlopen_absolute == second->dlopen_absolute &&
         first->dlsym_handle == second->dlsym_handle &&
         first->postflight == second->postflight &&
         first->context == second->context;
}

static WinnStageBFrameworkStatus winn_validate_preflight(
    const WinnStageBFrameworkExpected *expected,
    const WinnStageBFrameworkPreflight *preflight) {
  if (!winn_path_is_canonical_engine(preflight->canonical_path)) {
    return WINN_STAGE_B_FRAMEWORK_INVALID_PATH;
  }
  if (!winn_bytes_equal(
          preflight->source_binary_sha256,
          expected->source_binary_sha256,
          sizeof(preflight->source_binary_sha256))) {
    return WINN_STAGE_B_FRAMEWORK_INVALID_SOURCE_PIN;
  }
  if (!winn_bytes_nonzero(
          preflight->signed_runtime_sha256,
          sizeof(preflight->signed_runtime_sha256))) {
    return WINN_STAGE_B_FRAMEWORK_INVALID_RUNTIME_PIN;
  }
  if (winn_bytes_equal(
          preflight->source_binary_sha256,
          preflight->signed_runtime_sha256,
          sizeof(preflight->source_binary_sha256))) {
    return WINN_STAGE_B_FRAMEWORK_DIGEST_CONFLATED;
  }
  if (preflight->device == 0U || preflight->inode == 0U ||
      preflight->file_size == 0U || preflight->retained_file_token == 0U ||
      preflight->link_count != 1U) {
    return WINN_STAGE_B_FRAMEWORK_INVALID_FILE_IDENTITY;
  }
  if (preflight->platform != expected->platform ||
      preflight->architecture != expected->architecture ||
      preflight->macho_contract_valid != 1U) {
    return WINN_STAGE_B_FRAMEWORK_INVALID_MACHO;
  }
  if (preflight->manifest_strictly_parsed != 1U ||
      preflight->descriptor_relative_nofollow != 1U ||
      preflight->platform_loader_gate_expected != 1U ||
      winn_bytes_nonzero(preflight->reserved, sizeof(preflight->reserved))) {
    return WINN_STAGE_B_FRAMEWORK_INVALID_PREFLIGHT;
  }
  return WINN_STAGE_B_FRAMEWORK_OK;
}

static WinnStageBFrameworkStatus winn_validate_postflight(
    const WinnStageBFrameworkPreflight *preflight,
    const WinnStageBFrameworkPostflight *postflight) {
  if (!winn_bytes_equal(
          preflight->signed_runtime_sha256,
          postflight->signed_runtime_sha256,
          sizeof(preflight->signed_runtime_sha256)) ||
      postflight->device != preflight->device ||
      postflight->inode != preflight->inode ||
      postflight->file_size != preflight->file_size) {
    return WINN_STAGE_B_FRAMEWORK_RUNTIME_REBOUND;
  }
  if (postflight->every_symbol_same_image != 1U ||
      postflight->canonical_path_unchanged != 1U) {
    return WINN_STAGE_B_FRAMEWORK_SYMBOL_IMAGE_MISMATCH;
  }
  if (postflight->retained_inode_unchanged != 1U ||
      postflight->macho_contract_unchanged != 1U ||
      winn_bytes_nonzero(postflight->reserved, sizeof(postflight->reserved))) {
    return WINN_STAGE_B_FRAMEWORK_RUNTIME_REBOUND;
  }
  return WINN_STAGE_B_FRAMEWORK_OK;
}

static void winn_assign_symbols(
    WinnStageBFrameworkSymbols *output,
    const WinnStageBFrameworkSymbolAddress
        resolved[WINN_STAGE_B_FRAMEWORK_REQUIRED_SYMBOL_COUNT]) {
  memcpy(&output->wg_turn_on, &resolved[0], sizeof(output->wg_turn_on));
  memcpy(&output->wg_turn_off, &resolved[1], sizeof(output->wg_turn_off));
  memcpy(&output->wg_get_config, &resolved[2], sizeof(output->wg_get_config));
  memcpy(&output->wg_set_config, &resolved[3], sizeof(output->wg_set_config));
  memcpy(
      &output->wg_bump_sockets,
      &resolved[4],
      sizeof(output->wg_bump_sockets));
  memcpy(
      &output->contract_version,
      &resolved[5],
      sizeof(output->contract_version));
}

static WinnStageBFrameworkStatus winn_load_once(
    const WinnStageBFrameworkRuntimeBoundary *boundary,
    WinnStageBFrameworkImage **output_image) {
  const WinnStageBFrameworkExpected *expected = winn_stage_b_framework_expected();
  WinnStageBFrameworkPreflight preflight;
  WinnStageBFrameworkPostflight postflight;
  WinnStageBFrameworkSymbolAddress
      resolved[WINN_STAGE_B_FRAMEWORK_REQUIRED_SYMBOL_COUNT];
  WinnStageBFrameworkImage *image;
  WinnStageBFrameworkStatus status;
  void *handle;
  size_t index;

  *output_image = NULL;
  memset(&preflight, 0, sizeof(preflight));
  if (boundary->preflight(expected, &preflight, boundary->context) != 1) {
    winn_secure_zero(&preflight, sizeof(preflight));
    return WINN_STAGE_B_FRAMEWORK_PREFLIGHT_FAILED;
  }
  status = winn_validate_preflight(expected, &preflight);
  if (status != WINN_STAGE_B_FRAMEWORK_OK) {
    winn_secure_zero(&preflight, sizeof(preflight));
    return status;
  }

  handle = boundary->dlopen_absolute(
      preflight.canonical_path, RTLD_NOW | RTLD_LOCAL, boundary->context);
  if (handle == NULL) {
    winn_secure_zero(&preflight, sizeof(preflight));
    return WINN_STAGE_B_FRAMEWORK_DLOPEN_FAILED;
  }

  memset(resolved, 0, sizeof(resolved));
  for (index = 0U;
       index < (size_t)WINN_STAGE_B_FRAMEWORK_REQUIRED_SYMBOL_COUNT;
       ++index) {
    resolved[index] = boundary->dlsym_handle(
        handle, winn_required_symbols[index], boundary->context);
    if (resolved[index] == NULL) {
      winn_secure_zero(resolved, sizeof(resolved));
      winn_secure_zero(&preflight, sizeof(preflight));
      return WINN_STAGE_B_FRAMEWORK_SYMBOL_MISSING;
    }
  }

  memset(&postflight, 0, sizeof(postflight));
  if (boundary->postflight(
          handle, resolved, &preflight, &postflight, boundary->context) != 1) {
    winn_secure_zero(resolved, sizeof(resolved));
    winn_secure_zero(&postflight, sizeof(postflight));
    winn_secure_zero(&preflight, sizeof(preflight));
    return WINN_STAGE_B_FRAMEWORK_POSTFLIGHT_FAILED;
  }
  status = winn_validate_postflight(&preflight, &postflight);
  if (status != WINN_STAGE_B_FRAMEWORK_OK) {
    winn_secure_zero(resolved, sizeof(resolved));
    winn_secure_zero(&postflight, sizeof(postflight));
    winn_secure_zero(&preflight, sizeof(preflight));
    return status;
  }

  image = (WinnStageBFrameworkImage *)calloc(1U, sizeof(*image));
  if (image == NULL) {
    winn_secure_zero(resolved, sizeof(resolved));
    winn_secure_zero(&postflight, sizeof(postflight));
    winn_secure_zero(&preflight, sizeof(preflight));
    return WINN_STAGE_B_FRAMEWORK_UNAVAILABLE;
  }
  winn_assign_symbols(&image->symbols, resolved);
  if (image->symbols.contract_version() !=
      WINN_STAGE_B_FRAMEWORK_CONTRACT_VERSION) {
    winn_secure_zero(image, sizeof(*image));
    free(image);
    winn_secure_zero(resolved, sizeof(resolved));
    winn_secure_zero(&postflight, sizeof(postflight));
    winn_secure_zero(&preflight, sizeof(preflight));
    return WINN_STAGE_B_FRAMEWORK_CONTRACT_VERSION_MISMATCH;
  }
  memcpy(
      image->signed_runtime_sha256,
      postflight.signed_runtime_sha256,
      sizeof(image->signed_runtime_sha256));
  image->device = postflight.device;
  image->inode = postflight.inode;
  image->file_size = postflight.file_size;
  image->dyld_handle = handle;
  *output_image = image;

  winn_secure_zero(resolved, sizeof(resolved));
  winn_secure_zero(&postflight, sizeof(postflight));
  winn_secure_zero(&preflight, sizeof(preflight));
  return WINN_STAGE_B_FRAMEWORK_OK;
}

static WinnStageBFrameworkStatus winn_shared_with_boundary(
    const WinnStageBFrameworkRuntimeBoundary *boundary,
    const WinnStageBFrameworkImage **output_image) {
  WinnStageBFrameworkImage *loaded = NULL;
  WinnStageBFrameworkStatus status;
  WinnStageBFrameworkStatus unlock_status;

  if (output_image != NULL) {
    *output_image = NULL;
  }
  if (!winn_boundary_valid(boundary) || output_image == NULL) {
    return WINN_STAGE_B_FRAMEWORK_INVALID_ARGUMENT;
  }
  status = winn_lock();
  if (status != WINN_STAGE_B_FRAMEWORK_OK) {
    return status;
  }

  if (!winn_shared_attempted) {
    winn_shared_attempted = true;
    winn_shared_boundary = *boundary;
    status = winn_load_once(boundary, &loaded);
    winn_shared_status = status;
    if (status == WINN_STAGE_B_FRAMEWORK_OK) {
      winn_shared_image = loaded;
      *output_image = loaded;
    }
  } else if (!winn_boundary_equal(&winn_shared_boundary, boundary)) {
    status = WINN_STAGE_B_FRAMEWORK_BOUNDARY_CHANGED;
  } else if (winn_shared_status != WINN_STAGE_B_FRAMEWORK_OK ||
             winn_shared_image == NULL) {
    status = WINN_STAGE_B_FRAMEWORK_PERMANENTLY_FAILED;
  } else {
    *output_image = winn_shared_image;
    status = WINN_STAGE_B_FRAMEWORK_OK;
  }

  unlock_status = winn_unlock();
  return unlock_status == WINN_STAGE_B_FRAMEWORK_OK ? status : unlock_status;
}

WinnStageBFrameworkStatus winn_stage_b_framework_shared_image(
    const WinnStageBFrameworkImage **output_image) {
  const WinnStageBFrameworkRuntimeBoundary *boundary =
      winn_stage_b_framework_darwin_runtime_boundary();
  if (boundary == NULL) {
    if (output_image != NULL) {
      *output_image = NULL;
    }
    return WINN_STAGE_B_FRAMEWORK_UNAVAILABLE;
  }
  return winn_shared_with_boundary(boundary, output_image);
}

#if defined(WINN_STAGE_B_FRAMEWORK_TESTING)
WinnStageBFrameworkStatus winn_stage_b_framework_shared_image_for_testing(
    const WinnStageBFrameworkRuntimeBoundary *boundary,
    const WinnStageBFrameworkImage **output_image) {
  return winn_shared_with_boundary(boundary, output_image);
}

const void *winn_stage_b_framework_serialization_authority_for_testing(void) {
  return (const void *)&winn_authority;
}

void winn_stage_b_framework_commit_pause_enable_for_testing(void) {
  atomic_store(&winn_test_commit_pause_entered, 0);
  atomic_store(&winn_test_commit_pause_released, 0);
  atomic_store(&winn_test_commit_pause_enabled, 1);
}

int winn_stage_b_framework_commit_pause_entered_for_testing(void) {
  return atomic_load(&winn_test_commit_pause_entered);
}

void winn_stage_b_framework_commit_pause_release_for_testing(void) {
  atomic_store(&winn_test_commit_pause_released, 1);
}

static void winn_test_pause_after_final_attempt_check(void) {
  if (atomic_load(&winn_test_commit_pause_enabled) == 0) {
    return;
  }
  atomic_store(&winn_test_commit_pause_entered, 1);
  while (atomic_load(&winn_test_commit_pause_released) == 0) {
    atomic_signal_fence(memory_order_seq_cst);
  }
  atomic_store(&winn_test_commit_pause_enabled, 0);
}
#else
static void winn_test_pause_after_final_attempt_check(void) {}
#endif

WinnStageBFrameworkStatus winn_stage_b_framework_measured_digest(
    const WinnStageBFrameworkImage *image,
    uint8_t output[WINN_STAGE_B_FRAMEWORK_SHA256_BYTES]) {
  if (output != NULL) {
    memset(output, 0, (size_t)WINN_STAGE_B_FRAMEWORK_SHA256_BYTES);
  }
  if (image == NULL || output == NULL || image != winn_shared_image) {
    return WINN_STAGE_B_FRAMEWORK_INVALID_ARGUMENT;
  }
  memcpy(
      output,
      image->signed_runtime_sha256,
      sizeof(image->signed_runtime_sha256));
  return WINN_STAGE_B_FRAMEWORK_OK;
}

WinnStageBFrameworkStatus winn_stage_b_framework_begin_attempt(
    uint64_t *output_attempt_id) {
  uint64_t observed;
  uint64_t identifier;
  uint64_t current;
  WinnStageBFrameworkStatus status;
  WinnStageBFrameworkStatus unlock_status;
  if (output_attempt_id == NULL) {
    return WINN_STAGE_B_FRAMEWORK_INVALID_ARGUMENT;
  }
  *output_attempt_id = 0U;
  observed = atomic_load(&winn_attempt_counter);
  for (;;) {
    if (observed == UINT64_MAX) {
      return WINN_STAGE_B_FRAMEWORK_ATTEMPT_COUNTER_EXHAUSTED;
    }
    identifier = observed + UINT64_C(1);
    if (atomic_compare_exchange_weak(
            &winn_attempt_counter, &observed, identifier)) {
      break;
    }
  }
  status = winn_attempt_lock();
  if (status != WINN_STAGE_B_FRAMEWORK_OK) {
    return status;
  }
  current = atomic_load(&winn_current_attempt);
  if (current < identifier) {
    atomic_store(&winn_current_attempt, identifier);
    atomic_store(&winn_current_attempt_phase, WINN_ATTEMPT_PHASE_ACTIVE);
  }
  unlock_status = winn_attempt_unlock();
  if (unlock_status != WINN_STAGE_B_FRAMEWORK_OK) {
    return unlock_status;
  }
  *output_attempt_id = identifier;
  return WINN_STAGE_B_FRAMEWORK_OK;
}

WinnStageBFrameworkStatus winn_stage_b_framework_abandon_attempt(
    uint64_t attempt_id) {
  WinnStageBFrameworkStatus status;
  WinnStageBFrameworkStatus unlock_status;
  if (attempt_id == 0U) {
    return WINN_STAGE_B_FRAMEWORK_INVALID_ARGUMENT;
  }
  status = winn_attempt_lock();
  if (status != WINN_STAGE_B_FRAMEWORK_OK) {
    return status;
  }
  if (atomic_load(&winn_current_attempt) == attempt_id &&
      atomic_load(&winn_current_attempt_phase) == WINN_ATTEMPT_PHASE_ACTIVE) {
    atomic_store(&winn_current_attempt_phase, WINN_ATTEMPT_PHASE_NONE);
    atomic_store(&winn_current_attempt, UINT64_C(0));
    status = WINN_STAGE_B_FRAMEWORK_OK;
  } else {
    status = WINN_STAGE_B_FRAMEWORK_ATTEMPT_STALE;
  }
  unlock_status = winn_attempt_unlock();
  return unlock_status == WINN_STAGE_B_FRAMEWORK_OK ? status : unlock_status;
}

uint64_t winn_stage_b_framework_current_attempt(void) {
  return atomic_load(&winn_current_attempt);
}

static WinnStageBFrameworkStatus winn_validate_image(
    const WinnStageBFrameworkImage *image) {
  return image != NULL && image == winn_shared_image
             ? WINN_STAGE_B_FRAMEWORK_OK
             : WINN_STAGE_B_FRAMEWORK_INVALID_ARGUMENT;
}

WinnStageBFrameworkStatus winn_stage_b_framework_turn_on(
    const WinnStageBFrameworkImage *image,
    uint64_t attempt_id,
    const char *settings,
    int32_t utun_file_descriptor,
    int32_t *output_handle) {
  WinnStageBFrameworkStatus status;
  WinnStageBFrameworkStatus unlock_status;
  WinnStageBFrameworkStatus attempt_unlock_status;
  int32_t handle;
  bool cleanup_late_handle = false;
  if (output_handle != NULL) {
    *output_handle = -1;
  }
  if (winn_validate_image(image) != WINN_STAGE_B_FRAMEWORK_OK ||
      attempt_id == 0U || settings == NULL || settings[0] == '\0' ||
      utun_file_descriptor < 0 || output_handle == NULL) {
    return WINN_STAGE_B_FRAMEWORK_INVALID_ARGUMENT;
  }
  status = winn_lock();
  if (status != WINN_STAGE_B_FRAMEWORK_OK) {
    return status;
  }
  if (atomic_load(&winn_current_attempt) != attempt_id ||
      atomic_load(&winn_current_attempt_phase) != WINN_ATTEMPT_PHASE_ACTIVE) {
    status = WINN_STAGE_B_FRAMEWORK_ATTEMPT_ABANDONED;
  } else {
    handle = image->symbols.wg_turn_on(settings, utun_file_descriptor);
    status = winn_attempt_lock();
    if (status == WINN_STAGE_B_FRAMEWORK_OK) {
      if (atomic_load(&winn_current_attempt) != attempt_id ||
          atomic_load(&winn_current_attempt_phase) !=
              WINN_ATTEMPT_PHASE_ACTIVE) {
        cleanup_late_handle = handle >= 0;
        status = WINN_STAGE_B_FRAMEWORK_ATTEMPT_ABANDONED;
      } else {
        /*
         * This locked check is the commit linearization point. begin/abandon
         * cannot report success between it and publication of output_handle.
         */
        winn_test_pause_after_final_attempt_check();
        if (handle < 0) {
          status = WINN_STAGE_B_FRAMEWORK_START_FAILED;
        } else {
          atomic_store(
              &winn_current_attempt_phase, WINN_ATTEMPT_PHASE_COMMITTED);
          *output_handle = handle;
          status = WINN_STAGE_B_FRAMEWORK_OK;
        }
      }
      attempt_unlock_status = winn_attempt_unlock();
      if (attempt_unlock_status != WINN_STAGE_B_FRAMEWORK_OK) {
        status = attempt_unlock_status;
      }
    } else {
      cleanup_late_handle = handle >= 0;
    }
    if (cleanup_late_handle) {
      image->symbols.wg_turn_off(handle);
    }
    if (status == WINN_STAGE_B_FRAMEWORK_OK && handle < 0) {
      status = WINN_STAGE_B_FRAMEWORK_START_FAILED;
    }
  }
  unlock_status = winn_unlock();
  return unlock_status == WINN_STAGE_B_FRAMEWORK_OK ? status : unlock_status;
}

WinnStageBFrameworkStatus winn_stage_b_framework_turn_off(
    const WinnStageBFrameworkImage *image,
    int32_t handle) {
  WinnStageBFrameworkTurnOffObservation observation;
  return winn_stage_b_framework_turn_off_checked(
      image, handle, &observation);
}

WinnStageBFrameworkStatus winn_stage_b_framework_turn_off_checked(
    const WinnStageBFrameworkImage *image,
    int32_t handle,
    WinnStageBFrameworkTurnOffObservation *output_observation) {
  WinnStageBFrameworkStatus status;
  WinnStageBFrameworkStatus unlock_status;
  if (output_observation != NULL) {
    memset(output_observation, 0, sizeof(*output_observation));
  }
  if (winn_validate_image(image) != WINN_STAGE_B_FRAMEWORK_OK || handle < 0 ||
      output_observation == NULL) {
    return WINN_STAGE_B_FRAMEWORK_INVALID_ARGUMENT;
  }
  status = winn_lock();
  if (status != WINN_STAGE_B_FRAMEWORK_OK) {
    return status;
  }
  image->symbols.wg_turn_off(handle);
  output_observation->invocation_returned = 1U;
  unlock_status = winn_unlock();
  return unlock_status;
}

WinnStageBFrameworkStatus winn_stage_b_framework_get_config(
    const WinnStageBFrameworkImage *image,
    int32_t handle,
    char **output_config) {
  WinnStageBFrameworkStatus status;
  WinnStageBFrameworkStatus unlock_status;
  char *config;
  if (output_config != NULL) {
    *output_config = NULL;
  }
  if (winn_validate_image(image) != WINN_STAGE_B_FRAMEWORK_OK || handle < 0 ||
      output_config == NULL) {
    return WINN_STAGE_B_FRAMEWORK_INVALID_ARGUMENT;
  }
  status = winn_lock();
  if (status != WINN_STAGE_B_FRAMEWORK_OK) {
    return status;
  }
  config = image->symbols.wg_get_config(handle);
  status = config == NULL ? WINN_STAGE_B_FRAMEWORK_ENGINE_CALL_FAILED
                          : WINN_STAGE_B_FRAMEWORK_OK;
  if (status == WINN_STAGE_B_FRAMEWORK_OK) {
    *output_config = config;
  }
  unlock_status = winn_unlock();
  return unlock_status == WINN_STAGE_B_FRAMEWORK_OK ? status : unlock_status;
}

WinnStageBFrameworkStatus winn_stage_b_framework_set_config(
    const WinnStageBFrameworkImage *image,
    int32_t handle,
    const char *settings) {
  WinnStageBFrameworkStatus status;
  WinnStageBFrameworkStatus unlock_status;
  int64_t result;
  if (winn_validate_image(image) != WINN_STAGE_B_FRAMEWORK_OK || handle < 0 ||
      settings == NULL || settings[0] == '\0') {
    return WINN_STAGE_B_FRAMEWORK_INVALID_ARGUMENT;
  }
  status = winn_lock();
  if (status != WINN_STAGE_B_FRAMEWORK_OK) {
    return status;
  }
  result = image->symbols.wg_set_config(handle, settings);
  status = result < 0 ? WINN_STAGE_B_FRAMEWORK_ENGINE_CALL_FAILED
                      : WINN_STAGE_B_FRAMEWORK_OK;
  unlock_status = winn_unlock();
  return unlock_status == WINN_STAGE_B_FRAMEWORK_OK ? status : unlock_status;
}

WinnStageBFrameworkStatus winn_stage_b_framework_bump_sockets(
    const WinnStageBFrameworkImage *image,
    int32_t handle) {
  WinnStageBFrameworkStatus status;
  WinnStageBFrameworkStatus unlock_status;
  if (winn_validate_image(image) != WINN_STAGE_B_FRAMEWORK_OK || handle < 0) {
    return WINN_STAGE_B_FRAMEWORK_INVALID_ARGUMENT;
  }
  status = winn_lock();
  if (status != WINN_STAGE_B_FRAMEWORK_OK) {
    return status;
  }
  image->symbols.wg_bump_sockets(handle);
  unlock_status = winn_unlock();
  return unlock_status;
}
