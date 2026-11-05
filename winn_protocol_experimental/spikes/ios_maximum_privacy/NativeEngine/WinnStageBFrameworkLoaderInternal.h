#ifndef WINN_STAGE_B_FRAMEWORK_LOADER_INTERNAL_H
#define WINN_STAGE_B_FRAMEWORK_LOADER_INTERNAL_H

#include "WinnStageBFrameworkLoader.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
#define WINN_STAGE_B_FRAMEWORK_INTERNAL __attribute__((visibility("hidden")))
#else
#define WINN_STAGE_B_FRAMEWORK_INTERNAL
#endif

enum {
  WINN_STAGE_B_FRAMEWORK_PLATFORM_IPHONEOS = 1,
  WINN_STAGE_B_FRAMEWORK_PLATFORM_IPHONESIMULATOR = 2,
  WINN_STAGE_B_FRAMEWORK_ARCH_ARM64 = 1,
  WINN_STAGE_B_FRAMEWORK_ARCH_X86_64 = 2,
  WINN_STAGE_B_FRAMEWORK_CONTRACT_VERSION = 1
};

typedef int32_t (*WinnStageBFrameworkWGTurnOn)(
    const char *settings,
    int32_t utun_file_descriptor);
typedef void (*WinnStageBFrameworkWGTurnOff)(int32_t handle);
typedef char *(*WinnStageBFrameworkWGGetConfig)(int32_t handle);
typedef int64_t (*WinnStageBFrameworkWGSetConfig)(
    int32_t handle,
    const char *settings);
typedef void (*WinnStageBFrameworkWGBumpSockets)(int32_t handle);
typedef int (*WinnStageBFrameworkContractVersion)(void);
typedef void (*WinnStageBFrameworkSymbolAddress)(void);

typedef struct WinnStageBFrameworkSymbols {
  WinnStageBFrameworkWGTurnOn wg_turn_on;
  WinnStageBFrameworkWGTurnOff wg_turn_off;
  WinnStageBFrameworkWGGetConfig wg_get_config;
  WinnStageBFrameworkWGSetConfig wg_set_config;
  WinnStageBFrameworkWGBumpSockets wg_bump_sockets;
  WinnStageBFrameworkContractVersion contract_version;
} WinnStageBFrameworkSymbols;

typedef struct WinnStageBFrameworkExpected {
  uint8_t source_binary_sha256[WINN_STAGE_B_FRAMEWORK_SHA256_BYTES];
  uint32_t platform;
  uint32_t architecture;
} WinnStageBFrameworkExpected;

/*
 * Produced only by the trusted Darwin boundary. canonical_path is derived from
 * the actual provider executable, never from a message/default/environment.
 * retained_file_token identifies an open O_NOFOLLOW descriptor kept through
 * postflight. The token is opaque to this portable core.
 */
typedef struct WinnStageBFrameworkPreflight {
  char canonical_path[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES];
  uint8_t source_binary_sha256[WINN_STAGE_B_FRAMEWORK_SHA256_BYTES];
  uint8_t signed_runtime_sha256[WINN_STAGE_B_FRAMEWORK_SHA256_BYTES];
  uint64_t device;
  uint64_t inode;
  uint64_t file_size;
  uint64_t retained_file_token;
  uint32_t platform;
  uint32_t architecture;
  uint32_t link_count;
  uint8_t manifest_strictly_parsed;
  uint8_t descriptor_relative_nofollow;
  uint8_t macho_contract_valid;
  /*
   * Device dyld/kernel enforces the embedded signature. Simulator dyld still
   * gates platform/load compatibility, but this byte is not a claim that the
   * simulator provides the device code-signature security boundary.
   */
  uint8_t platform_loader_gate_expected;
  uint8_t reserved[4];
} WinnStageBFrameworkPreflight;

typedef struct WinnStageBFrameworkPostflight {
  uint8_t signed_runtime_sha256[WINN_STAGE_B_FRAMEWORK_SHA256_BYTES];
  uint64_t device;
  uint64_t inode;
  uint64_t file_size;
  uint8_t every_symbol_same_image;
  uint8_t canonical_path_unchanged;
  uint8_t retained_inode_unchanged;
  uint8_t macho_contract_unchanged;
  uint8_t reserved[4];
} WinnStageBFrameworkPostflight;

typedef int (*WinnStageBFrameworkPreflightFn)(
    const WinnStageBFrameworkExpected *expected,
    WinnStageBFrameworkPreflight *output,
    void *context);
typedef void *(*WinnStageBFrameworkDLOpenFn)(
    const char *absolute_path,
    int flags,
    void *context);
typedef WinnStageBFrameworkSymbolAddress (*WinnStageBFrameworkDLSymFn)(
    void *handle,
    const char *symbol_name,
    void *context);
typedef int (*WinnStageBFrameworkPostflightFn)(
    void *handle,
    const WinnStageBFrameworkSymbolAddress
        symbols[WINN_STAGE_B_FRAMEWORK_REQUIRED_SYMBOL_COUNT],
    const WinnStageBFrameworkPreflight *preflight,
    WinnStageBFrameworkPostflight *output,
    void *context);

typedef struct WinnStageBFrameworkRuntimeBoundary {
  WinnStageBFrameworkPreflightFn preflight;
  WinnStageBFrameworkDLOpenFn dlopen_absolute;
  WinnStageBFrameworkDLSymFn dlsym_handle;
  WinnStageBFrameworkPostflightFn postflight;
  void *context;
} WinnStageBFrameworkRuntimeBoundary;

WINN_STAGE_B_FRAMEWORK_INTERNAL
const WinnStageBFrameworkExpected *winn_stage_b_framework_expected(void);
WINN_STAGE_B_FRAMEWORK_INTERNAL
const WinnStageBFrameworkRuntimeBoundary *
winn_stage_b_framework_darwin_runtime_boundary(void);

#if defined(WINN_STAGE_B_FRAMEWORK_TESTING)
WINN_STAGE_B_FRAMEWORK_INTERNAL
WinnStageBFrameworkStatus winn_stage_b_framework_shared_image_for_testing(
    const WinnStageBFrameworkRuntimeBoundary *boundary,
    const WinnStageBFrameworkImage **output_image);
WINN_STAGE_B_FRAMEWORK_INTERNAL
const void *winn_stage_b_framework_serialization_authority_for_testing(void);
WINN_STAGE_B_FRAMEWORK_INTERNAL
void winn_stage_b_framework_commit_pause_enable_for_testing(void);
WINN_STAGE_B_FRAMEWORK_INTERNAL
int winn_stage_b_framework_commit_pause_entered_for_testing(void);
WINN_STAGE_B_FRAMEWORK_INTERNAL
void winn_stage_b_framework_commit_pause_release_for_testing(void);
#endif

#ifdef __cplusplus
}
#endif

#undef WINN_STAGE_B_FRAMEWORK_INTERNAL

#endif
