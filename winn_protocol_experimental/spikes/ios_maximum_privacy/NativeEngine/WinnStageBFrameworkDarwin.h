#ifndef WINN_STAGE_B_FRAMEWORK_DARWIN_H
#define WINN_STAGE_B_FRAMEWORK_DARWIN_H

#include "WinnStageBFrameworkLoaderInternal.h"

#if defined(WINN_STAGE_B_FRAMEWORK_TESTING)
int winn_stage_b_framework_darwin_derive_paths_for_testing(
    const char *provider_executable,
    char app_root[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES],
    char engine_path[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES],
    char manifest_path[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES]);
int winn_stage_b_framework_darwin_preflight_for_testing(
    const char *provider_executable,
    const WinnStageBFrameworkExpected *expected,
    WinnStageBFrameworkPreflight *output);
int winn_stage_b_framework_darwin_macho_for_testing(
    const char *absolute_path,
    const WinnStageBFrameworkExpected *expected);
void winn_stage_b_framework_darwin_reset_for_testing(void);
#endif

#endif
