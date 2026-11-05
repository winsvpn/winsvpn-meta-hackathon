#include "WinnStageBFrameworkDarwin.h"

#include <CommonCrypto/CommonDigest.h>
#include <TargetConditionals.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
  WINN_MANIFEST_MAX_BYTES = 1024,
  WINN_MACHO_MAX_LOAD_COMMAND_BYTES = 1024 * 1024,
  WINN_MACHO_MAX_SYMBOLS = 100000,
  WINN_MACHO_MAX_STRING_BYTES = 16 * 1024 * 1024,
  WINN_ENGINE_MAX_FILE_BYTES = 128 * 1024 * 1024
};

static const char winn_engine_relative_path[] =
    "Frameworks/WinsAmneziaWGPacketEngine.framework/"
    "WinsAmneziaWGPacketEngine";
static const char winn_manifest_leaf[] =
    "WinnStageBEngineRuntimePin.manifest";
static const char winn_install_name[] =
    "@rpath/WinsAmneziaWGPacketEngine.framework/"
    "WinsAmneziaWGPacketEngine";
static const char winn_manifest_schema[] =
    "winn-stageb-engine-runtime-pin/1";

static const char *const winn_required_dependencies[] = {
    "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
    "/System/Library/Frameworks/Foundation.framework/Foundation",
    "/System/Library/Frameworks/Security.framework/Security",
    "/usr/lib/libSystem.B.dylib",
    "/usr/lib/libobjc.A.dylib",
    "/usr/lib/libresolv.9.dylib"};

static const char *const winn_required_exports[] = {
    "_wgTurnOn",
    "_wgTurnOff",
    "_wgGetConfig",
    "_wgSetConfig",
    "_wgBumpSockets",
    "_wins_amneziawg_packet_engine_contract_version"};

typedef struct WinnDarwinContext {
  int retained_fd;
  WinnStageBFrameworkExpected expected;
  WinnStageBFrameworkPreflight preflight;
} WinnDarwinContext;

static WinnDarwinContext winn_darwin_context = {.retained_fd = -1};

static bool winn_checked_add_size(size_t first, size_t second, size_t *output) {
  if (first > SIZE_MAX - second) {
    return false;
  }
  *output = first + second;
  return true;
}

static bool winn_checked_add_u64(
    uint64_t first,
    uint64_t second,
    uint64_t *output) {
  if (first > UINT64_MAX - second) {
    return false;
  }
  *output = first + second;
  return true;
}

static bool winn_component_suffix(
    const char *path,
    size_t start,
    size_t end,
    const char *suffix) {
  size_t suffix_length = strlen(suffix);
  return end >= start && end - start >= suffix_length &&
         memcmp(path + end - suffix_length, suffix, suffix_length) == 0;
}

static int winn_derive_paths(
    const char *provider_executable,
    char app_root[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES],
    char engine_path[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES],
    char manifest_path[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES]) {
  size_t length;
  size_t executable_start;
  size_t appex_end;
  size_t appex_start;
  size_t plugins_end;
  size_t plugins_start;
  size_t app_end;
  size_t app_start;
  int written;

  if (provider_executable == NULL || provider_executable[0] != '/') {
    return 0;
  }
  length = strnlen(
      provider_executable, (size_t)WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES);
  if (length < 2U ||
      length >= (size_t)WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES) {
    return 0;
  }
  {
    size_t index;
    for (index = 0U; index < length; ++index) {
      unsigned char byte = (unsigned char)provider_executable[index];
      if (byte < 0x20U || byte >= 0x7fU ||
          (byte == (unsigned char)'/' && index + 1U < length &&
           (provider_executable[index + 1U] == '/' ||
            provider_executable[index + 1U] == '.'))) {
        return 0;
      }
    }
  }
  executable_start = length;
  while (executable_start > 0U &&
         provider_executable[executable_start - 1U] != '/') {
    --executable_start;
  }
  if (executable_start <= 1U || executable_start == length) {
    return 0;
  }
  appex_end = executable_start - 1U;
  appex_start = appex_end;
  while (appex_start > 0U && provider_executable[appex_start - 1U] != '/') {
    --appex_start;
  }
  if (!winn_component_suffix(
          provider_executable, appex_start, appex_end, ".appex")) {
    return 0;
  }
  plugins_end = appex_start - 1U;
  plugins_start = plugins_end;
  while (plugins_start > 0U &&
         provider_executable[plugins_start - 1U] != '/') {
    --plugins_start;
  }
  if (plugins_end - plugins_start != sizeof("PlugIns") - 1U ||
      memcmp(
          provider_executable + plugins_start,
          "PlugIns",
          sizeof("PlugIns") - 1U) != 0) {
    return 0;
  }
  app_end = plugins_start - 1U;
  app_start = app_end;
  while (app_start > 0U && provider_executable[app_start - 1U] != '/') {
    --app_start;
  }
  if (!winn_component_suffix(
          provider_executable, app_start, app_end, ".app") ||
      app_end == 0U || app_end >= (size_t)WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES) {
    return 0;
  }
  memcpy(app_root, provider_executable, app_end);
  app_root[app_end] = '\0';
  written = snprintf(
      engine_path,
      (size_t)WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES,
      "%s/%s",
      app_root,
      winn_engine_relative_path);
  if (written <= 0 ||
      (size_t)written >= (size_t)WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES) {
    return 0;
  }
  written = snprintf(
      manifest_path,
      (size_t)WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES,
      "%s/%s",
      app_root,
      winn_manifest_leaf);
  return written > 0 &&
         (size_t)written < (size_t)WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES;
}

#if defined(WINN_STAGE_B_FRAMEWORK_TESTING)
int winn_stage_b_framework_darwin_derive_paths_for_testing(
    const char *provider_executable,
    char app_root[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES],
    char engine_path[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES],
    char manifest_path[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES]) {
  if (app_root == NULL || engine_path == NULL || manifest_path == NULL) {
    return 0;
  }
  memset(app_root, 0, (size_t)WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES);
  memset(engine_path, 0, (size_t)WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES);
  memset(manifest_path, 0, (size_t)WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES);
  return winn_derive_paths(
      provider_executable, app_root, engine_path, manifest_path);
}
#endif

static int winn_open_absolute_nofollow(const char *path, int final_flags) {
  char copy[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES];
  char *cursor;
  int directory_fd;

  if (path == NULL || path[0] != '/' ||
      strnlen(path, sizeof(copy)) >= sizeof(copy)) {
    return -1;
  }
  memcpy(copy, path, strlen(path) + 1U);
  directory_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (directory_fd < 0) {
    return -1;
  }
  cursor = copy + 1;
  while (*cursor != '\0') {
    char *separator = strchr(cursor, '/');
    int next_fd;
    bool last = separator == NULL;
    if (separator != NULL) {
      *separator = '\0';
    }
    if (cursor[0] == '\0' || strcmp(cursor, ".") == 0 ||
        strcmp(cursor, "..") == 0) {
      (void)close(directory_fd);
      return -1;
    }
    next_fd = openat(
        directory_fd,
        cursor,
        last ? final_flags | O_NOFOLLOW | O_CLOEXEC
             : O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    (void)close(directory_fd);
    if (next_fd < 0) {
      return -1;
    }
    directory_fd = next_fd;
    if (last) {
      break;
    }
    cursor = separator + 1;
  }
  return directory_fd;
}

static int winn_read_exact(int fd, void *output, size_t count, uint64_t offset) {
  uint8_t *cursor = (uint8_t *)output;
  size_t total = 0U;
  while (total < count) {
    ssize_t amount = pread(
        fd,
        cursor + total,
        count - total,
        (off_t)(offset + (uint64_t)total));
    if (amount <= 0) {
      return 0;
    }
    total += (size_t)amount;
  }
  return 1;
}

static int winn_hash_fd(
    int fd,
    uint64_t file_size,
    uint8_t output[WINN_STAGE_B_FRAMEWORK_SHA256_BYTES]) {
  CC_SHA256_CTX context;
  uint8_t buffer[16384];
  uint64_t offset = 0U;
  if (file_size == 0U ||
      file_size > (uint64_t)WINN_ENGINE_MAX_FILE_BYTES ||
      CC_SHA256_Init(&context) != 1) {
    return 0;
  }
  while (offset < file_size) {
    size_t amount = sizeof(buffer);
    if (file_size - offset < (uint64_t)amount) {
      amount = (size_t)(file_size - offset);
    }
    if (!winn_read_exact(fd, buffer, amount, offset) ||
        CC_SHA256_Update(&context, buffer, (CC_LONG)amount) != 1) {
      memset(buffer, 0, sizeof(buffer));
      memset(&context, 0, sizeof(context));
      return 0;
    }
    offset += (uint64_t)amount;
  }
  memset(buffer, 0, sizeof(buffer));
  if (CC_SHA256_Final(output, &context) != 1) {
    memset(&context, 0, sizeof(context));
    return 0;
  }
  memset(&context, 0, sizeof(context));
  return 1;
}

static int winn_hex_nibble(unsigned char byte) {
  if (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') {
    return (int)(byte - (unsigned char)'0');
  }
  if (byte >= (unsigned char)'a' && byte <= (unsigned char)'f') {
    return (int)(byte - (unsigned char)'a') + 10;
  }
  return -1;
}

static int winn_parse_sha256(
    const char *text,
    uint8_t output[WINN_STAGE_B_FRAMEWORK_SHA256_BYTES]) {
  size_t index;
  for (index = 0U; index < (size_t)WINN_STAGE_B_FRAMEWORK_SHA256_BYTES;
       ++index) {
    int high = winn_hex_nibble((unsigned char)text[index * 2U]);
    int low = winn_hex_nibble((unsigned char)text[index * 2U + 1U]);
    if (high < 0 || low < 0) {
      return 0;
    }
    output[index] = (uint8_t)((unsigned)high * 16U + (unsigned)low);
  }
  return text[64] == '\0';
}

typedef struct WinnManifest {
  uint8_t source_sha256[WINN_STAGE_B_FRAMEWORK_SHA256_BYTES];
  uint8_t runtime_sha256[WINN_STAGE_B_FRAMEWORK_SHA256_BYTES];
  uint32_t platform;
  uint32_t architecture;
} WinnManifest;

static int winn_parse_manifest(
    const char *bytes,
    size_t length,
    WinnManifest *output) {
  char expected_prefix[WINN_MANIFEST_MAX_BYTES];
  char source_hex[65];
  char runtime_hex[65];
  const char *platform;
  const char *architectures;
  int prefix_length;
  int matched;

#if TARGET_OS_SIMULATOR
  platform = "iphonesimulator";
#if defined(__x86_64__)
  architectures = "arm64,x86_64";
#else
  architectures = "arm64,x86_64";
#endif
#else
  platform = "iphoneos";
  architectures = "arm64";
#endif
  prefix_length = snprintf(
      expected_prefix,
      sizeof(expected_prefix),
      "schema=%s\nsource_binary_sha256=%%64[0-9a-f]\n"
      "signed_runtime_binary_sha256=%%64[0-9a-f]\n"
      "relative_path=%s\nplatform=%s\narchitectures=%s\n"
      "install_name=%s\n%%n",
      winn_manifest_schema,
      winn_engine_relative_path,
      platform,
      architectures,
      winn_install_name);
  if (prefix_length <= 0 ||
      (size_t)prefix_length >= sizeof(expected_prefix) ||
      length == 0U || length >= (size_t)WINN_MANIFEST_MAX_BYTES ||
      bytes[length - 1U] != '\n') {
    return 0;
  }
  memset(source_hex, 0, sizeof(source_hex));
  memset(runtime_hex, 0, sizeof(runtime_hex));
  {
    int consumed = -1;
    matched = sscanf(
        bytes, expected_prefix, source_hex, runtime_hex, &consumed);
    if (matched != 2 || consumed < 0 || (size_t)consumed != length) {
      return 0;
    }
  }
  memset(output, 0, sizeof(*output));
  if (!winn_parse_sha256(source_hex, output->source_sha256) ||
      !winn_parse_sha256(runtime_hex, output->runtime_sha256)) {
    return 0;
  }
#if TARGET_OS_SIMULATOR
  output->platform = WINN_STAGE_B_FRAMEWORK_PLATFORM_IPHONESIMULATOR;
#else
  output->platform = WINN_STAGE_B_FRAMEWORK_PLATFORM_IPHONEOS;
#endif
#if defined(__x86_64__)
  output->architecture = WINN_STAGE_B_FRAMEWORK_ARCH_X86_64;
#else
  output->architecture = WINN_STAGE_B_FRAMEWORK_ARCH_ARM64;
#endif
  return 1;
}

static int winn_read_manifest(
    const char *path,
    WinnManifest *output) {
  char bytes[WINN_MANIFEST_MAX_BYTES];
  struct stat status;
  int fd = winn_open_absolute_nofollow(path, O_RDONLY);
  ssize_t count;
  if (fd < 0 || fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
      status.st_nlink != 1 || status.st_size <= 0 ||
      status.st_size >= (off_t)sizeof(bytes)) {
    if (fd >= 0) {
      (void)close(fd);
    }
    return 0;
  }
  count = winn_read_exact(fd, bytes, (size_t)status.st_size, 0U)
              ? status.st_size
              : (ssize_t)-1;
  (void)close(fd);
  if (count != status.st_size) {
    return 0;
  }
  bytes[count] = '\0';
  return winn_parse_manifest(bytes, (size_t)count, output);
}

static int winn_load_command_string(
    const uint8_t *commands,
    uint32_t sizeofcmds,
    uint32_t command_offset,
    uint32_t command_size,
    uint32_t string_offset,
    const char **output) {
  size_t absolute;
  const char *string;
  size_t maximum;
  if (string_offset >= command_size ||
      !winn_checked_add_size(
          (size_t)command_offset, (size_t)string_offset, &absolute) ||
      absolute >= (size_t)sizeofcmds) {
    return 0;
  }
  string = (const char *)(commands + absolute);
  maximum = (size_t)command_size - (size_t)string_offset;
  if (memchr(string, '\0', maximum) == NULL) {
    return 0;
  }
  *output = string;
  return 1;
}

static int winn_required_index(
    const char *value,
    const char *const *list,
    size_t count) {
  size_t index;
  for (index = 0U; index < count; ++index) {
    if (strcmp(value, list[index]) == 0) {
      return (int)index;
    }
  }
  return -1;
}

static int winn_macho_contract(
    int fd,
    uint64_t file_size,
    const WinnStageBFrameworkExpected *expected) {
  uint32_t magic;
  uint64_t slice_offset = 0U;
  uint64_t slice_size = file_size;
  struct mach_header_64 header;
  uint8_t *commands = NULL;
  uint32_t command_offset = 0U;
  bool platform_seen = false;
  bool install_name_seen = false;
  bool signature_seen = false;
  bool dependencies_seen[sizeof(winn_required_dependencies) /
                         sizeof(winn_required_dependencies[0])] = {false};
  bool exports_seen[
      sizeof(winn_required_exports) / sizeof(winn_required_exports[0])] = {
      false};
  struct symtab_command symtab;
  bool symtab_seen = false;
  uint32_t index;
  int result = 0;
  cpu_type_t wanted_cpu =
      expected->architecture == WINN_STAGE_B_FRAMEWORK_ARCH_X86_64
          ? CPU_TYPE_X86_64
          : CPU_TYPE_ARM64;

  memset(&symtab, 0, sizeof(symtab));
  if (file_size < sizeof(magic) ||
      !winn_read_exact(fd, &magic, sizeof(magic), 0U)) {
    return 0;
  }
  if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
    struct fat_header fat_header;
    uint32_t count;
    bool found = false;
    bool swapped = magic == FAT_CIGAM;
    if (!winn_read_exact(fd, &fat_header, sizeof(fat_header), 0U)) {
      return 0;
    }
    count = swapped ? OSSwapInt32(fat_header.nfat_arch)
                    : fat_header.nfat_arch;
    if (count == 0U || count > 16U) {
      return 0;
    }
    for (index = 0U; index < count; ++index) {
      struct fat_arch arch;
      uint64_t offset =
          sizeof(fat_header) + (uint64_t)index * sizeof(struct fat_arch);
      if (!winn_read_exact(fd, &arch, sizeof(arch), offset)) {
        return 0;
      }
      if ((cpu_type_t)(swapped ? OSSwapInt32((uint32_t)arch.cputype)
                               : (uint32_t)arch.cputype) == wanted_cpu) {
        uint64_t candidate_end;
        if (found) {
          return 0;
        }
        slice_offset =
            swapped ? OSSwapInt32(arch.offset) : arch.offset;
        slice_size = swapped ? OSSwapInt32(arch.size) : arch.size;
        if (!winn_checked_add_u64(
                slice_offset, slice_size, &candidate_end) ||
            candidate_end > file_size) {
          return 0;
        }
        found = true;
      }
    }
    if (!found) {
      return 0;
    }
  }
  if (slice_size < sizeof(header) ||
      !winn_read_exact(fd, &header, sizeof(header), slice_offset) ||
      header.magic != MH_MAGIC_64 || header.cputype != wanted_cpu ||
      header.filetype != MH_DYLIB || (header.flags & MH_TWOLEVEL) == 0U ||
      header.ncmds == 0U ||
      header.sizeofcmds > (uint32_t)WINN_MACHO_MAX_LOAD_COMMAND_BYTES ||
      (uint64_t)header.sizeofcmds > slice_size - sizeof(header)) {
    return 0;
  }
  commands = (uint8_t *)malloc(header.sizeofcmds);
  if (commands == NULL ||
      !winn_read_exact(
          fd,
          commands,
          header.sizeofcmds,
          slice_offset + sizeof(header))) {
    free(commands);
    return 0;
  }

  for (index = 0U; index < header.ncmds; ++index) {
    struct load_command command;
    if ((uint64_t)command_offset + sizeof(command) > header.sizeofcmds) {
      goto finish;
    }
    memcpy(&command, commands + command_offset, sizeof(command));
    if (command.cmdsize < sizeof(command) ||
        (uint64_t)command_offset + command.cmdsize > header.sizeofcmds) {
      goto finish;
    }
    if (command.cmd == LC_BUILD_VERSION) {
      struct build_version_command build;
      uint32_t expected_platform =
          expected->platform == WINN_STAGE_B_FRAMEWORK_PLATFORM_IPHONESIMULATOR
              ? PLATFORM_IOSSIMULATOR
              : PLATFORM_IOS;
      if (platform_seen || command.cmdsize < sizeof(build)) {
        goto finish;
      }
      memcpy(&build, commands + command_offset, sizeof(build));
      if (build.platform != expected_platform) {
        goto finish;
      }
      platform_seen = true;
    } else if (command.cmd == LC_ID_DYLIB ||
               command.cmd == LC_LOAD_DYLIB) {
      struct dylib_command dylib;
      const char *name;
      int required;
      if (command.cmdsize < sizeof(dylib)) {
        goto finish;
      }
      memcpy(&dylib, commands + command_offset, sizeof(dylib));
      if (!winn_load_command_string(
              commands,
              header.sizeofcmds,
              command_offset,
              command.cmdsize,
              dylib.dylib.name.offset,
              &name)) {
        goto finish;
      }
      if (command.cmd == LC_ID_DYLIB) {
        if (install_name_seen || strcmp(name, winn_install_name) != 0) {
          goto finish;
        }
        install_name_seen = true;
      } else {
        required = winn_required_index(
            name,
            winn_required_dependencies,
            sizeof(winn_required_dependencies) /
                sizeof(winn_required_dependencies[0]));
        if (required < 0 || dependencies_seen[(size_t)required]) {
          goto finish;
        }
        dependencies_seen[(size_t)required] = true;
      }
    } else if (command.cmd == LC_LOAD_WEAK_DYLIB ||
               command.cmd == LC_REEXPORT_DYLIB ||
               command.cmd == LC_LOAD_UPWARD_DYLIB ||
               command.cmd == LC_LAZY_LOAD_DYLIB ||
               command.cmd == LC_RPATH) {
      goto finish;
    } else if (command.cmd == LC_CODE_SIGNATURE) {
      struct linkedit_data_command signature;
      uint64_t signature_end;
      if (signature_seen || command.cmdsize < sizeof(signature)) {
        goto finish;
      }
      memcpy(&signature, commands + command_offset, sizeof(signature));
      if (signature.dataoff == 0U || signature.datasize == 0U ||
          !winn_checked_add_u64(
              (uint64_t)signature.dataoff,
              (uint64_t)signature.datasize,
              &signature_end) ||
          signature_end > slice_size) {
        goto finish;
      }
      signature_seen = true;
    } else if (command.cmd == LC_SYMTAB) {
      if (symtab_seen || command.cmdsize < sizeof(symtab)) {
        goto finish;
      }
      memcpy(&symtab, commands + command_offset, sizeof(symtab));
      symtab_seen = true;
    }
    command_offset += command.cmdsize;
  }
  if (command_offset != header.sizeofcmds || !platform_seen ||
      !install_name_seen || !signature_seen || !symtab_seen) {
    goto finish;
  }
  for (index = 0U;
       index < sizeof(dependencies_seen) / sizeof(dependencies_seen[0]);
       ++index) {
    if (!dependencies_seen[index]) {
      goto finish;
    }
  }
  if (symtab.nsyms == 0U || symtab.nsyms > WINN_MACHO_MAX_SYMBOLS ||
      symtab.strsize == 0U || symtab.strsize > WINN_MACHO_MAX_STRING_BYTES) {
    goto finish;
  }
  {
    struct nlist_64 *symbols;
    char *strings;
    uint64_t symbols_bytes =
        (uint64_t)symtab.nsyms * sizeof(struct nlist_64);
    uint64_t symbols_end;
    uint64_t strings_end;
    if (!winn_checked_add_u64(
            (uint64_t)symtab.symoff, symbols_bytes, &symbols_end) ||
        !winn_checked_add_u64(
            (uint64_t)symtab.stroff,
            (uint64_t)symtab.strsize,
            &strings_end) ||
        symbols_end > slice_size || strings_end > slice_size) {
      goto finish;
    }
    symbols = (struct nlist_64 *)malloc((size_t)symbols_bytes);
    strings = (char *)malloc(symtab.strsize);
    if (symbols == NULL || strings == NULL ||
        !winn_read_exact(
            fd,
            symbols,
            (size_t)symbols_bytes,
            slice_offset + symtab.symoff) ||
        !winn_read_exact(
            fd,
            strings,
            symtab.strsize,
            slice_offset + symtab.stroff)) {
      free(symbols);
      free(strings);
      goto finish;
    }
    for (index = 0U; index < symtab.nsyms; ++index) {
      uint32_t string_index = symbols[index].n_un.n_strx;
      int required;
      if (string_index == 0U || string_index >= symtab.strsize ||
          (symbols[index].n_type & N_STAB) != 0U ||
          (symbols[index].n_type & N_EXT) == 0U ||
          (symbols[index].n_type & N_TYPE) == N_UNDF ||
          memchr(
              strings + string_index,
              '\0',
              (size_t)symtab.strsize - string_index) == NULL) {
        continue;
      }
      required = winn_required_index(
          strings + string_index,
          winn_required_exports,
          sizeof(winn_required_exports) / sizeof(winn_required_exports[0]));
      if (required >= 0) {
        exports_seen[(size_t)required] = true;
      }
    }
    free(symbols);
    free(strings);
  }
  for (index = 0U; index < sizeof(exports_seen) / sizeof(exports_seen[0]);
       ++index) {
    if (!exports_seen[index]) {
      goto finish;
    }
  }
  result = 1;

finish:
  if (commands != NULL) {
    memset(commands, 0, header.sizeofcmds);
    free(commands);
  }
  return result;
}

static int winn_actual_provider_executable(
    char output[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES]) {
  char raw[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES];
  uint32_t size = (uint32_t)sizeof(raw);
  if (_NSGetExecutablePath(raw, &size) != 0 ||
      realpath(raw, output) == NULL ||
      strnlen(output, (size_t)WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES) >=
          (size_t)WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES) {
    return 0;
  }
  return 1;
}

static int winn_darwin_preflight_executable(
    const WinnStageBFrameworkExpected *expected,
    WinnStageBFrameworkPreflight *output,
    WinnDarwinContext *darwin,
    const char *executable) {
  char app_root[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES];
  char engine_path[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES];
  char manifest_path[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES];
  char resolved_engine[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES];
  WinnManifest manifest;
  struct stat status;
  uint8_t runtime_sha256[WINN_STAGE_B_FRAMEWORK_SHA256_BYTES];
  int fd = -1;

  if (expected == NULL || output == NULL || darwin == NULL ||
      executable == NULL ||
      darwin->retained_fd >= 0) {
    return 0;
  }
  memset(output, 0, sizeof(*output));
  memset(&manifest, 0, sizeof(manifest));
  if (!winn_derive_paths(
          executable, app_root, engine_path, manifest_path)) {
    return 0;
  }
  if (realpath(engine_path, resolved_engine) == NULL ||
      strcmp(engine_path, resolved_engine) != 0) {
    return 0;
  }
  if (!winn_read_manifest(manifest_path, &manifest)) {
    return 0;
  }
  if (memcmp(
          manifest.source_sha256,
          expected->source_binary_sha256,
          sizeof(manifest.source_sha256)) != 0 ||
      manifest.platform != expected->platform ||
      manifest.architecture != expected->architecture) {
    return 0;
  }
  fd = winn_open_absolute_nofollow(engine_path, O_RDONLY);
  if (fd < 0 || fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
      status.st_nlink != 1 || status.st_size <= 0 ||
      status.st_size > WINN_ENGINE_MAX_FILE_BYTES ||
      !winn_hash_fd(fd, (uint64_t)status.st_size, runtime_sha256) ||
      memcmp(
          runtime_sha256,
          manifest.runtime_sha256,
          sizeof(runtime_sha256)) != 0 ||
      !winn_macho_contract(
          fd, (uint64_t)status.st_size, expected)) {
    if (fd >= 0) {
      (void)close(fd);
    }
    return 0;
  }
  memcpy(output->canonical_path, engine_path, strlen(engine_path) + 1U);
  memcpy(
      output->source_binary_sha256,
      manifest.source_sha256,
      sizeof(output->source_binary_sha256));
  memcpy(
      output->signed_runtime_sha256,
      runtime_sha256,
      sizeof(output->signed_runtime_sha256));
  output->device = (uint64_t)status.st_dev;
  output->inode = (uint64_t)status.st_ino;
  output->file_size = (uint64_t)status.st_size;
  output->retained_file_token = (uint64_t)(unsigned)fd + UINT64_C(1);
  output->platform = expected->platform;
  output->architecture = expected->architecture;
  output->link_count = (uint32_t)status.st_nlink;
  output->manifest_strictly_parsed = 1U;
  output->descriptor_relative_nofollow = 1U;
  output->macho_contract_valid = 1U;
  /*
   * This is an enforcement expectation, not a preflight validation claim.
   * The exact signed bytes were pinned above; iOS dyld/kernel validates their
   * embedded signature when dlopen maps them.
   */
  output->platform_loader_gate_expected = 1U;
  darwin->retained_fd = fd;
  darwin->expected = *expected;
  darwin->preflight = *output;
  return 1;
}

static int winn_darwin_preflight(
    const WinnStageBFrameworkExpected *expected,
    WinnStageBFrameworkPreflight *output,
    void *context) {
  char executable[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES];
  if (!winn_actual_provider_executable(executable)) {
    return 0;
  }
  return winn_darwin_preflight_executable(
      expected, output, (WinnDarwinContext *)context, executable);
}

#if defined(WINN_STAGE_B_FRAMEWORK_TESTING)
int winn_stage_b_framework_darwin_preflight_for_testing(
    const char *provider_executable,
    const WinnStageBFrameworkExpected *expected,
    WinnStageBFrameworkPreflight *output) {
  return winn_darwin_preflight_executable(
      expected, output, &winn_darwin_context, provider_executable);
}

int winn_stage_b_framework_darwin_macho_for_testing(
    const char *absolute_path,
    const WinnStageBFrameworkExpected *expected) {
  struct stat status;
  int result;
  int fd;
  if (absolute_path == NULL || expected == NULL) {
    return 0;
  }
  fd = winn_open_absolute_nofollow(absolute_path, O_RDONLY);
  if (fd < 0 || fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
      status.st_size <= 0) {
    if (fd >= 0) {
      (void)close(fd);
    }
    return 0;
  }
  result = winn_macho_contract(fd, (uint64_t)status.st_size, expected);
  (void)close(fd);
  return result;
}

void winn_stage_b_framework_darwin_reset_for_testing(void) {
  if (winn_darwin_context.retained_fd >= 0) {
    (void)close(winn_darwin_context.retained_fd);
  }
  memset(&winn_darwin_context, 0, sizeof(winn_darwin_context));
  winn_darwin_context.retained_fd = -1;
}
#endif

static void *winn_darwin_dlopen(
    const char *absolute_path,
    int flags,
    void *context) {
  WinnDarwinContext *darwin = (WinnDarwinContext *)context;
  if (absolute_path == NULL || darwin == NULL ||
      strcmp(absolute_path, darwin->preflight.canonical_path) != 0 ||
      flags != (RTLD_NOW | RTLD_LOCAL)) {
    return NULL;
  }
  return dlopen(absolute_path, flags);
}

static WinnStageBFrameworkSymbolAddress winn_darwin_dlsym(
    void *handle,
    const char *symbol_name,
    void *context) {
  void *raw;
  WinnStageBFrameworkSymbolAddress address = NULL;
  (void)context;
  if (handle == NULL || symbol_name == NULL) {
    return NULL;
  }
  raw = dlsym(handle, symbol_name);
  if (raw != NULL) {
    memcpy(&address, &raw, sizeof(address));
  }
  return address;
}

static int winn_symbol_image(
    WinnStageBFrameworkSymbolAddress symbol,
    char output[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES],
    const void **output_base,
    struct stat *output_status) {
  Dl_info information;
  const void *raw = NULL;
  memcpy(&raw, &symbol, sizeof(raw));
  memset(&information, 0, sizeof(information));
  return raw != NULL && dladdr(raw, &information) != 0 &&
         information.dli_fname != NULL &&
         information.dli_fbase != NULL &&
         realpath(information.dli_fname, output) != NULL &&
         lstat(output, output_status) == 0 &&
         S_ISREG(output_status->st_mode) &&
         (*output_base = information.dli_fbase) != NULL;
}

static int winn_darwin_postflight(
    void *handle,
    const WinnStageBFrameworkSymbolAddress
        symbols[WINN_STAGE_B_FRAMEWORK_REQUIRED_SYMBOL_COUNT],
    const WinnStageBFrameworkPreflight *preflight,
    WinnStageBFrameworkPostflight *output,
    void *context) {
  WinnDarwinContext *darwin = (WinnDarwinContext *)context;
  struct stat retained;
  struct stat current;
  uint8_t digest[WINN_STAGE_B_FRAMEWORK_SHA256_BYTES];
  size_t index;
  const void *loaded_base = NULL;
  (void)handle;

  if (symbols == NULL || preflight == NULL || output == NULL ||
      darwin == NULL || darwin->retained_fd < 0 ||
      memcmp(preflight, &darwin->preflight, sizeof(*preflight)) != 0 ||
      fstat(darwin->retained_fd, &retained) != 0 ||
      lstat(preflight->canonical_path, &current) != 0 ||
      !S_ISREG(current.st_mode) || current.st_nlink != 1 ||
      retained.st_dev != current.st_dev || retained.st_ino != current.st_ino ||
      retained.st_size != current.st_size ||
      !winn_hash_fd(
          darwin->retained_fd, (uint64_t)retained.st_size, digest) ||
      memcmp(
          digest,
          preflight->signed_runtime_sha256,
          sizeof(digest)) != 0 ||
      !winn_macho_contract(
          darwin->retained_fd,
          (uint64_t)retained.st_size,
          &darwin->expected)) {
    return 0;
  }
  for (index = 0U;
       index < (size_t)WINN_STAGE_B_FRAMEWORK_REQUIRED_SYMBOL_COUNT;
       ++index) {
    char path[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES];
    struct stat symbol_status;
    const void *symbol_base = NULL;
    if (!winn_symbol_image(
            symbols[index], path, &symbol_base, &symbol_status) ||
        strcmp(path, preflight->canonical_path) != 0 ||
        symbol_status.st_dev != retained.st_dev ||
        symbol_status.st_ino != retained.st_ino ||
        symbol_status.st_size != retained.st_size ||
        symbol_status.st_nlink != 1 ||
        (loaded_base != NULL && symbol_base != loaded_base)) {
      return 0;
    }
    loaded_base = symbol_base;
  }
  memset(output, 0, sizeof(*output));
  memcpy(
      output->signed_runtime_sha256,
      digest,
      sizeof(output->signed_runtime_sha256));
  output->device = (uint64_t)retained.st_dev;
  output->inode = (uint64_t)retained.st_ino;
  output->file_size = (uint64_t)retained.st_size;
  output->every_symbol_same_image = 1U;
  output->canonical_path_unchanged = 1U;
  output->retained_inode_unchanged = 1U;
  output->macho_contract_unchanged = 1U;
  return 1;
}

const WinnStageBFrameworkRuntimeBoundary *
winn_stage_b_framework_darwin_runtime_boundary(void) {
  static const WinnStageBFrameworkRuntimeBoundary boundary = {
      winn_darwin_preflight,
      winn_darwin_dlopen,
      winn_darwin_dlsym,
      winn_darwin_postflight,
      &winn_darwin_context};
  return &boundary;
}
