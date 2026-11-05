#define _DARWIN_C_SOURCE 1

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <mach-o/loader.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/attr.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef WINS_BUILD_SOURCE_SHA256
#error WINS_BUILD_SOURCE_SHA256 must be supplied by the reviewed build script
#endif
#ifndef WINS_BUILD_SCRIPT_SHA256
#error WINS_BUILD_SCRIPT_SHA256 must be supplied by the reviewed build script
#endif
#ifndef WINS_BUILD_COMPILER_SHA256
#error WINS_BUILD_COMPILER_SHA256 must be supplied by the reviewed build script
#endif
#ifndef WINS_BUILD_LINKER_SHA256
#error WINS_BUILD_LINKER_SHA256 must be supplied by the reviewed build script
#endif
#ifndef WINS_BUILD_CODESIGN_SHA256
#error WINS_BUILD_CODESIGN_SHA256 must be supplied by the reviewed build script
#endif
#ifndef WINS_BUILD_INPUT_CLOSURE_SHA256
#error WINS_BUILD_INPUT_CLOSURE_SHA256 must be supplied by the reviewed build script
#endif
#ifndef WINS_OLD_CONTROLLER_SHA256
#error WINS_OLD_CONTROLLER_SHA256 must be supplied by the reviewed build script
#endif
#ifndef WINS_OLD_LAUNCHER_SHA256
#error WINS_OLD_LAUNCHER_SHA256 must be supplied by the reviewed build script
#endif
#ifndef WINS_NEW_CONTROLLER_SHA256
#error WINS_NEW_CONTROLLER_SHA256 must be supplied by the reviewed build script
#endif
#ifndef WINS_NEW_LAUNCHER_SHA256
#error WINS_NEW_LAUNCHER_SHA256 must be supplied by the reviewed build script
#endif

#ifndef WINS_UPDATER_PATH
#define WINS_UPDATER_PATH \
    "/Library/WinsVPN/ReleasePythonAuthority/v1/owner-updater"
#endif
#ifndef WINS_DESTINATION_PARENT
#define WINS_DESTINATION_PARENT "/Library/WinsVPN/ReleasePythonAuthority/v1"
#endif
#ifndef WINS_EXPECTED_UID
#define WINS_EXPECTED_UID 0
#endif
#ifndef WINS_EXPECTED_GID
#define WINS_EXPECTED_GID 0
#endif
#ifndef WINS_REQUIRE_ROOT
#define WINS_REQUIRE_ROOT 1
#endif
#ifndef WINS_REQUIRE_SELF_IMMUTABLE
#define WINS_REQUIRE_SELF_IMMUTABLE 1
#endif
#ifndef WINS_ALLOW_EXPECTED_UID_ANCESTRY
#define WINS_ALLOW_EXPECTED_UID_ANCESTRY 0
#endif
#ifndef WINS_IMMUTABLE_FLAG
#define WINS_IMMUTABLE_FLAG SF_IMMUTABLE
#endif

#define CONTROLLER_NAME "owner-provision"
#define LAUNCHER_NAME "owner-launcher"
#define AUTHORITY_NAME "authority.json"
#define UPDATER_NAME "owner-updater"
#define STAGE_PREFIX ".winsvpn-owner-updater-stage-"
#define CLEANUP_PREFIX ".winsvpn-owner-updater-cleanup-"
#define INSTALL_PREFIX ".winsvpn-owner-updater-install-"
#define JOURNAL_NAME "journal"
#define JOURNAL_NEXT_NAME "journal.next"
#define JOURNAL_CONTRACT "winsvpn-releasepython-owner-pair-update-v2"
#define MAX_COMPONENTS 64U
#define MAX_INPUT_BYTES ((uint64_t)128 * 1024 * 1024)
#define MAX_JOURNAL_BYTES 4096U
#define MAX_LOAD_COMMANDS 8192U
#define CONTROLLER_HEADER \
    "#!/usr/bin/env python3\n\"\"\"Fixed external owner boundary for ReleasePython receipt migration.\n"

extern char **environ;

__attribute__((used)) static const char build_evidence[] =
    WINS_BUILD_SOURCE_SHA256 ":" WINS_BUILD_SCRIPT_SHA256 ":"
    WINS_BUILD_COMPILER_SHA256 ":" WINS_BUILD_LINKER_SHA256 ":"
    WINS_BUILD_CODESIGN_SHA256 ":" WINS_BUILD_INPUT_CLOSURE_SHA256 ":"
    WINS_OLD_CONTROLLER_SHA256 ":" WINS_OLD_LAUNCHER_SHA256 ":"
    WINS_NEW_CONTROLLER_SHA256 ":" WINS_NEW_LAUNCHER_SHA256;

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    unsigned char block[64];
    size_t block_used;
} sha256_context;

static const uint32_t sha256_constants[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

typedef struct {
    int descriptor;
    int parent_index;
    char name[NAME_MAX + 1];
    struct stat identity;
    int leaf;
} retained_component;

typedef struct {
    retained_component components[MAX_COMPONENTS];
    size_t count;
    char absolute[PATH_MAX];
} retained_path;

typedef struct {
    retained_path controller;
    retained_path launcher;
    int queue;
} retained_sources;

typedef struct {
    int descriptor;
    struct stat identity;
    char digest[65];
} held_leaf;

typedef struct {
    char updater_sha256[65];
    char authority_sha256[65];
    uint64_t authority_device;
    uint64_t authority_inode;
    uint64_t old_controller_device;
    uint64_t old_controller_inode;
    uint64_t old_launcher_device;
    uint64_t old_launcher_inode;
    char stage_name[NAME_MAX + 1];
    char phase[64];
} journal_record;

typedef enum {
    STATE_UNRECOGNIZED = 0,
    STATE_CLEAN,
    STATE_ARMED,
    STATE_CONTROLLER_LIVE,
    STATE_BOTH_LIVE,
    STATE_COMMITTED,
} pair_state;

typedef struct {
    int parent_fd;
    int stage_fd;
    held_leaf destination_controller;
    held_leaf destination_launcher;
    held_leaf stage_controller;
    held_leaf stage_launcher;
    held_leaf authority;
    journal_record journal;
    char self_sha256[65];
    char stage_name[NAME_MAX + 1];
    char cleanup_name[NAME_MAX + 1];
    int stage_exists;
    int cleanup_exists;
    int journal_exists;
    int journal_valid;
    int journal_invalid;
    int journal_next_exists;
    int stage_is_residue;
} update_context;

static void fail(const char *message);
static void fail_errno(const char *message);
static void test_crash(int ordinal);
static int discard_stage_residue(update_context *context,
                                 const char **error);

static uint32_t rotate_right(uint32_t value, unsigned int count) {
    return (value >> count) | (value << (32U - count));
}

static void sha256_transform(sha256_context *context,
                             const unsigned char block[64]) {
    uint32_t words[64];
    uint32_t a, b, c, d, e, f, g, h;
    size_t index;
    for (index = 0; index < 16; ++index) {
        words[index] = ((uint32_t)block[index * 4] << 24) |
                       ((uint32_t)block[index * 4 + 1] << 16) |
                       ((uint32_t)block[index * 4 + 2] << 8) |
                       (uint32_t)block[index * 4 + 3];
    }
    for (index = 16; index < 64; ++index) {
        uint32_t s0 = rotate_right(words[index - 15], 7) ^
                      rotate_right(words[index - 15], 18) ^
                      (words[index - 15] >> 3);
        uint32_t s1 = rotate_right(words[index - 2], 17) ^
                      rotate_right(words[index - 2], 19) ^
                      (words[index - 2] >> 10);
        words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }
    a = context->state[0]; b = context->state[1];
    c = context->state[2]; d = context->state[3];
    e = context->state[4]; f = context->state[5];
    g = context->state[6]; h = context->state[7];
    for (index = 0; index < 64; ++index) {
        uint32_t sum1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^
                        rotate_right(e, 25);
        uint32_t choice = (e & f) ^ ((~e) & g);
        uint32_t temporary1 = h + sum1 + choice +
                              sha256_constants[index] + words[index];
        uint32_t sum0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^
                        rotate_right(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temporary2 = sum0 + majority;
        h = g; g = f; f = e; e = d + temporary1;
        d = c; c = b; b = a; a = temporary1 + temporary2;
    }
    context->state[0] += a; context->state[1] += b;
    context->state[2] += c; context->state[3] += d;
    context->state[4] += e; context->state[5] += f;
    context->state[6] += g; context->state[7] += h;
}

static void sha256_init(sha256_context *context) {
    static const uint32_t initial[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
    };
    memcpy(context->state, initial, sizeof(initial));
    context->bit_count = 0;
    context->block_used = 0;
}

static void sha256_update(sha256_context *context, const unsigned char *data,
                          size_t length) {
    while (length > 0) {
        size_t copied = 64 - context->block_used;
        if (copied > length) copied = length;
        memcpy(context->block + context->block_used, data, copied);
        context->block_used += copied;
        data += copied;
        length -= copied;
        context->bit_count += (uint64_t)copied * 8U;
        if (context->block_used == 64) {
            sha256_transform(context, context->block);
            context->block_used = 0;
        }
    }
}

static void sha256_final(sha256_context *context, unsigned char output[32]) {
    uint64_t bits = context->bit_count;
    size_t index;
    context->block[context->block_used++] = 0x80;
    if (context->block_used > 56) {
        memset(context->block + context->block_used, 0,
               64 - context->block_used);
        sha256_transform(context, context->block);
        context->block_used = 0;
    }
    memset(context->block + context->block_used, 0,
           56 - context->block_used);
    for (index = 0; index < 8; ++index) {
        context->block[63 - index] = (unsigned char)(bits >> (index * 8));
    }
    sha256_transform(context, context->block);
    for (index = 0; index < 8; ++index) {
        output[index * 4] = (unsigned char)(context->state[index] >> 24);
        output[index * 4 + 1] = (unsigned char)(context->state[index] >> 16);
        output[index * 4 + 2] = (unsigned char)(context->state[index] >> 8);
        output[index * 4 + 3] = (unsigned char)context->state[index];
    }
}

static void hex_encode(const unsigned char *input, size_t length, char *output) {
    static const char alphabet[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < length; ++index) {
        output[index * 2] = alphabet[input[index] >> 4];
        output[index * 2 + 1] = alphabet[input[index] & 15U];
    }
    output[length * 2] = '\0';
}

static int secure_equal(const char *left, const char *right) {
    unsigned char difference = 0;
    size_t index;
    if (strlen(left) != strlen(right)) return 0;
    for (index = 0; left[index] != '\0'; ++index) {
        difference |= (unsigned char)left[index] ^ (unsigned char)right[index];
    }
    return difference == 0;
}

static int valid_digest(const char *value) {
    size_t index;
    unsigned char nonzero = 0;
    if (strlen(value) != 64) return 0;
    for (index = 0; index < 64; ++index) {
        if (!((value[index] >= '0' && value[index] <= '9') ||
              (value[index] >= 'a' && value[index] <= 'f'))) return 0;
        nonzero |= (unsigned char)(value[index] != '0');
    }
    return nonzero != 0;
}

static int same_vnode(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static int same_directory_identity(const struct stat *left,
                                   const struct stat *right) {
    return same_vnode(left, right) && left->st_mode == right->st_mode &&
           left->st_uid == right->st_uid && left->st_gid == right->st_gid &&
           left->st_flags == right->st_flags;
}

static int same_leaf_identity(const struct stat *left,
                              const struct stat *right) {
    return same_directory_identity(left, right) &&
           left->st_nlink == right->st_nlink &&
           left->st_size == right->st_size &&
           left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
           left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec &&
           left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
           left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
}

static int has_empty_acl(int descriptor) {
    acl_entry_t entry;
    acl_t acl;
    int result;
    int saved_errno;
    errno = 0;
    acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED);
    if (acl == NULL) return errno == ENOENT || errno == EINVAL;
    errno = 0;
    result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
    saved_errno = errno;
    acl_free(acl);
    return result == -1 && saved_errno == EINVAL;
}

static void hash_fd(int descriptor, char output[65]) {
    sha256_context context;
    unsigned char digest[32];
    unsigned char buffer[65536];
    off_t offset = 0;
    struct stat before, after;
    if (fstat(descriptor, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_size < 0 || (uint64_t)before.st_size > MAX_INPUT_BYTES) {
        fail("retained hash input type or size is invalid");
    }
    sha256_init(&context);
    for (;;) {
        ssize_t count = pread(descriptor, buffer, sizeof(buffer), offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            fail_errno("cannot hash retained file");
        }
        if (count == 0) break;
        sha256_update(&context, buffer, (size_t)count);
        offset += count;
        if ((uint64_t)offset > MAX_INPUT_BYTES) {
            fail("retained input exceeds byte ceiling");
        }
    }
    if (offset != before.st_size || fstat(descriptor, &after) != 0 ||
        !same_vnode(&before, &after) || before.st_size != after.st_size) {
        fail("retained hash input changed or ended at the wrong size");
    }
    sha256_final(&context, digest);
    hex_encode(digest, sizeof(digest), output);
}

static int safe_absolute_path(const char *path) {
    size_t length;
    if (path == NULL || path[0] != '/') return 0;
    length = strlen(path);
    if (length < 2 || length >= PATH_MAX || path[length - 1] == '/') return 0;
    if (strstr(path, "//") != NULL || strstr(path, "/./") != NULL ||
        strstr(path, "/../") != NULL) return 0;
    if (length >= 2 && strcmp(path + length - 2, "/.") == 0) return 0;
    if (length >= 3 && strcmp(path + length - 3, "/..") == 0) return 0;
    return 1;
}

static int path_is_under_destination(const char *path) {
    size_t length = strlen(WINS_DESTINATION_PARENT);
    return strncmp(path, WINS_DESTINATION_PARENT, length) == 0 &&
           (path[length] == '\0' || path[length] == '/');
}

static void close_retained_path(retained_path *path) {
    while (path->count > 0) {
        close(path->components[--path->count].descriptor);
    }
}

static int open_retained_path(const char *absolute, int leaf_directory,
                              retained_path *path, const char **error) {
    char copy[PATH_MAX];
    char *cursor;
    int parent_fd;
    struct stat info;
    memset(path, 0, sizeof(*path));
    if (!safe_absolute_path(absolute)) {
        *error = "input path is not canonical absolute form";
        return 0;
    }
    strcpy(path->absolute, absolute);
    strcpy(copy, absolute + 1);
    parent_fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent_fd < 0 || fstat(parent_fd, &info) != 0) {
        if (parent_fd >= 0) close(parent_fd);
        *error = "cannot retain filesystem root";
        return 0;
    }
    path->components[0].descriptor = parent_fd;
    path->components[0].parent_index = -1;
    path->components[0].identity = info;
    path->count = 1;
    cursor = copy;
    while (*cursor != '\0') {
        char *slash = strchr(cursor, '/');
        int final = slash == NULL;
        int flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC;
        int descriptor;
        struct stat named, retained;
        size_t length = final ? strlen(cursor) : (size_t)(slash - cursor);
        retained_component *component;
        if (length == 0 || length > NAME_MAX || path->count >= MAX_COMPONENTS) {
            *error = "path component is invalid or exceeds custody cap";
            close_retained_path(path);
            return 0;
        }
        if (!final) *slash = '\0';
        if (!final || leaf_directory) flags |= O_DIRECTORY;
        if (fstatat(parent_fd, cursor, &named, AT_SYMLINK_NOFOLLOW) != 0) {
            *error = "cannot stat no-follow path component";
            close_retained_path(path);
            return 0;
        }
        descriptor = openat(parent_fd, cursor, flags);
        if (descriptor < 0 || fstat(descriptor, &retained) != 0) {
            if (descriptor >= 0) close(descriptor);
            *error = "cannot open no-follow path component";
            close_retained_path(path);
            return 0;
        }
        if ((final && !leaf_directory && !S_ISREG(retained.st_mode)) ||
            ((!final || leaf_directory) && !S_ISDIR(retained.st_mode)) ||
            !(S_ISDIR(retained.st_mode)
                  ? same_directory_identity(&named, &retained)
                  : same_leaf_identity(&named, &retained))) {
            close(descriptor);
            *error = "path component type or named identity changed";
            close_retained_path(path);
            return 0;
        }
        component = &path->components[path->count];
        component->descriptor = descriptor;
        component->parent_index = (int)path->count - 1;
        strcpy(component->name, cursor);
        component->identity = retained;
        component->leaf = final;
        ++path->count;
        parent_fd = descriptor;
        if (final) break;
        cursor = slash + 1;
    }
    return 1;
}

static int validate_retained_path(const retained_path *path, int hash_leaf,
                                  const char *expected_digest,
                                  const char **error) {
    size_t index;
    for (index = 0; index < path->count; ++index) {
        const retained_component *component = &path->components[index];
        struct stat retained;
        int directory = S_ISDIR(component->identity.st_mode);
        if (fstat(component->descriptor, &retained) != 0 ||
            !(directory
                  ? same_directory_identity(&retained, &component->identity)
                  : same_leaf_identity(&retained, &component->identity)) ||
            (component->leaf && !has_empty_acl(component->descriptor))) {
            *error = "retained path identity changed";
            return 0;
        }
        if (component->parent_index >= 0) {
            const retained_component *parent =
                &path->components[(size_t)component->parent_index];
            struct stat named;
            if (fstatat(parent->descriptor, component->name, &named,
                        AT_SYMLINK_NOFOLLOW) != 0 ||
                !(directory
                      ? same_directory_identity(&named, &component->identity)
                      : same_leaf_identity(&named, &component->identity))) {
                *error = "retained path name changed";
                return 0;
            }
        }
    }
    if (hash_leaf) {
        char digest[65];
        hash_fd(path->components[path->count - 1].descriptor, digest);
        if (!secure_equal(digest, expected_digest)) {
            *error = "retained source bytes changed";
            return 0;
        }
    }
    return 1;
}

static int validate_secure_ancestry(const retained_path *path, int self_leaf,
                                    const char **error) {
    size_t index;
    for (index = 0; index < path->count; ++index) {
        const struct stat *info = &path->components[index].identity;
        int leaf = path->components[index].leaf;
        int owner_ok = info->st_uid == 0;
        int acl_required = 1;
#if WINS_ALLOW_EXPECTED_UID_ANCESTRY
        owner_ok = owner_ok || info->st_uid == (uid_t)WINS_EXPECTED_UID;
        if (!leaf && info->st_uid == (uid_t)WINS_EXPECTED_UID) {
            acl_required = 0;
        }
#endif
        if (!owner_ok || (info->st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
            (info->st_mode & (S_ISUID | S_ISGID | S_ISVTX)) != 0 ||
            (!leaf && !S_ISDIR(info->st_mode))) {
            *error = "fixed custody ancestry owner, type, or mode is unsafe";
            return 0;
        }
        if (acl_required && !has_empty_acl(path->components[index].descriptor)) {
            *error = "fixed custody ancestry has an extended ACL";
            return 0;
        }
        if (leaf && self_leaf) {
            if (!S_ISREG(info->st_mode) ||
                info->st_uid != (uid_t)WINS_EXPECTED_UID ||
                info->st_gid != (gid_t)WINS_EXPECTED_GID ||
                (info->st_mode & 07777) != 0555 || info->st_nlink != 1) {
                *error = "installed updater custody is not exact";
                return 0;
            }
#if WINS_REQUIRE_SELF_IMMUTABLE
            if ((((unsigned int)info->st_flags) & WINS_IMMUTABLE_FLAG) == 0U) {
                *error = "installed updater is not system immutable";
                return 0;
            }
#endif
        }
    }
    return 1;
}

static int ensure_standard_descriptors(const char **error) {
    int descriptor;
    for (descriptor = 0; descriptor <= 2; ++descriptor) {
        if (fcntl(descriptor, F_GETFD) < 0 && errno == EBADF) {
            struct stat replacement_info;
            int replacement = open("/dev/null",
                                   (descriptor == 0 ? O_RDONLY : O_WRONLY) |
                                       O_NOFOLLOW);
            if (replacement < 0 || replacement != descriptor) {
                if (replacement >= 0) close(replacement);
                *error = "cannot normalize standard descriptors";
                return 0;
            }
            if (fstat(replacement, &replacement_info) != 0 ||
                !S_ISCHR(replacement_info.st_mode)) {
                *error = "normalized standard descriptor is not a character device";
                return 0;
            }
        }
    }
    return 1;
}

static int exact_environment(const char **error) {
    size_t index;
    int home = 0;
    int temporary = 0;
    for (index = 0; environ[index] != NULL; ++index) {
        if (strcmp(environ[index], "HOME=/var/root") == 0) ++home;
        else if (strcmp(environ[index], "TMPDIR=/private/tmp") == 0) ++temporary;
        else {
            *error = "environment must contain only exact HOME and TMPDIR";
            return 0;
        }
    }
    if (home != 1 || temporary != 1 || index != 2) {
        *error = "environment must contain only exact HOME and TMPDIR";
        return 0;
    }
    return 1;
}

static int sync_file(int descriptor, const char **error) {
    if (fsync(descriptor) != 0 || fcntl(descriptor, F_FULLFSYNC) != 0) {
        *error = "cannot fully synchronize retained file";
        return 0;
    }
    return 1;
}

static int copy_exact(int source, int destination, off_t size,
                      const char *expected, const char **error) {
    unsigned char buffer[65536];
    off_t offset = 0;
    while (offset < size) {
        size_t wanted = sizeof(buffer);
        ssize_t count;
        ssize_t written = 0;
        if ((off_t)wanted > size - offset) wanted = (size_t)(size - offset);
        count = pread(source, buffer, wanted, offset);
        if (count <= 0) {
            *error = "retained source ended during exact copy";
            return 0;
        }
        while (written < count) {
            ssize_t amount = pwrite(destination, buffer + written,
                                    (size_t)(count - written), offset + written);
            if (amount < 0 && errno == EINTR) continue;
            if (amount <= 0) {
                *error = "cannot write private update stage";
                return 0;
            }
            written += amount;
        }
        offset += count;
    }
    if (ftruncate(destination, size) != 0 ||
        fchown(destination, (uid_t)WINS_EXPECTED_UID,
               (gid_t)WINS_EXPECTED_GID) != 0 ||
        fchmod(destination, 0555) != 0) {
        *error = "cannot assign exact staged owner or mode";
        return 0;
    }
    if (!sync_file(destination, error)) return 0;
    {
        char digest[65];
        hash_fd(destination, digest);
        if (!secure_equal(digest, expected)) {
            *error = "private stage digest does not match reviewed source";
            return 0;
        }
    }
    return 1;
}

static int fd_contains_text(int descriptor, off_t size, const char *needle) {
    unsigned char buffer[65536 + 64];
    size_t needle_length = strlen(needle);
    size_t carry = 0;
    off_t offset = 0;
    while (offset < size) {
        ssize_t count = pread(descriptor, buffer + carry, 65536, offset);
        size_t total;
        size_t index;
        if (count <= 0) return 0;
        total = carry + (size_t)count;
        for (index = 0; index + needle_length <= total; ++index) {
            if (memcmp(buffer + index, needle, needle_length) == 0) return 1;
        }
        carry = total < needle_length - 1 ? total : needle_length - 1;
        memmove(buffer, buffer + total - carry, carry);
        offset += count;
    }
    return 0;
}

static int require_source_leaf(const retained_path *path, const char *expected,
                               const char **error) {
    const retained_component *leaf = &path->components[path->count - 1];
    char digest[65];
    if (!S_ISREG(leaf->identity.st_mode) || leaf->identity.st_nlink != 1 ||
        leaf->identity.st_size <= 0 ||
        (uint64_t)leaf->identity.st_size > MAX_INPUT_BYTES ||
        (leaf->identity.st_mode & (S_ISUID | S_ISGID | S_ISVTX)) != 0) {
        *error = "reviewed source type, link count, mode, or size is invalid";
        return 0;
    }
    hash_fd(leaf->descriptor, digest);
    if (!secure_equal(digest, expected)) {
        *error = "reviewed source SHA-256 mismatch";
        return 0;
    }
    return 1;
}

static int require_controller_role(int descriptor, const struct stat *info,
                                   const char **error) {
    unsigned char buffer[65536];
    size_t header_length = strlen(CONTROLLER_HEADER);
    off_t offset = 0;
    if ((uint64_t)info->st_size < header_length ||
        pread(descriptor, buffer, header_length, 0) != (ssize_t)header_length ||
        memcmp(buffer, CONTROLLER_HEADER, header_length) != 0) {
        *error = "controller source role header is invalid";
        return 0;
    }
    while (offset < info->st_size) {
        ssize_t count = pread(descriptor, buffer, sizeof(buffer), offset);
        ssize_t index;
        if (count <= 0) {
            *error = "cannot read controller source role bytes";
            return 0;
        }
        for (index = 0; index < count; ++index) {
            if (buffer[index] == 0 || buffer[index] > 0x7fU) {
                *error = "controller source is not exact NUL-free ASCII";
                return 0;
            }
        }
        offset += count;
    }
    return 1;
}

static int require_macho_role(int descriptor, const struct stat *info,
                              const char *controller_hash,
                              const char **error) {
    struct mach_header_64 header;
    off_t offset;
    uint64_t limit;
    uint32_t index;
    int signatures = 0;
    if (info->st_size < (off_t)sizeof(header) ||
        pread(descriptor, &header, sizeof(header), 0) != (ssize_t)sizeof(header) ||
        header.magic != MH_MAGIC_64 || header.cputype != CPU_TYPE_ARM64 ||
        header.filetype != MH_EXECUTE || header.ncmds == 0 ||
        header.ncmds > MAX_LOAD_COMMANDS ||
        (uint64_t)sizeof(header) + header.sizeofcmds > (uint64_t)info->st_size) {
        *error = "native source is not exact thin arm64 MH_EXECUTE";
        return 0;
    }
    limit = (uint64_t)sizeof(header) + header.sizeofcmds;
    offset = (off_t)sizeof(header);
    for (index = 0; index < header.ncmds; ++index) {
        struct load_command command;
        if (pread(descriptor, &command, sizeof(command), offset) !=
                (ssize_t)sizeof(command) ||
            command.cmdsize < sizeof(command) || (command.cmdsize % 8U) != 0U ||
            (uint64_t)offset + command.cmdsize > limit) {
            *error = "native source Mach-O load command is malformed";
            return 0;
        }
        if (command.cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command signature;
            if (command.cmdsize != sizeof(signature) ||
                pread(descriptor, &signature, sizeof(signature), offset) !=
                    (ssize_t)sizeof(signature) ||
                signature.datasize == 0 ||
                (uint64_t)signature.dataoff + signature.datasize >
                    (uint64_t)info->st_size) {
                *error = "native source code signature command is invalid";
                return 0;
            }
            ++signatures;
        }
        offset += command.cmdsize;
    }
    if ((uint64_t)offset != limit || signatures != 1) {
        *error = "native source must contain exactly one code signature";
        return 0;
    }
    if (controller_hash != NULL &&
        !fd_contains_text(descriptor, info->st_size, controller_hash)) {
        *error = "launcher bytes do not bind the selected controller SHA-256";
        return 0;
    }
    return 1;
}

static int arm_sources(retained_sources *sources, const char **error) {
    retained_path *paths[2] = {&sources->controller, &sources->launcher};
    size_t path_index;
    sources->queue = kqueue();
    if (sources->queue < 0) {
        *error = "cannot create source vnode watch";
        return 0;
    }
    for (path_index = 0; path_index < 2; ++path_index) {
        size_t index;
        for (index = 0; index < paths[path_index]->count; ++index) {
            struct kevent change;
            uint32_t notes = NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE;
            if (paths[path_index]->components[index].leaf) {
                notes |= NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_LINK;
            }
            EV_SET(&change,
                   (uintptr_t)paths[path_index]->components[index].descriptor,
                   EVFILT_VNODE, EV_ADD | EV_ENABLE | EV_CLEAR, notes, 0, NULL);
            if (kevent(sources->queue, &change, 1, NULL, 0, NULL) != 0) {
                *error = "cannot arm source vnode watch";
                return 0;
            }
        }
    }
    return 1;
}

static int validate_sources(retained_sources *sources, const char **error) {
    struct timespec zero = {0, 0};
    struct kevent event;
    if (kevent(sources->queue, NULL, 0, &event, 1, &zero) > 0) {
        *error = "reviewed source changed while retained";
        return 0;
    }
    if (!validate_retained_path(&sources->controller, 1,
                                WINS_NEW_CONTROLLER_SHA256, error) ||
        !validate_retained_path(&sources->launcher, 1,
                                WINS_NEW_LAUNCHER_SHA256, error)) {
        return 0;
    }
    if (kevent(sources->queue, NULL, 0, &event, 1, &zero) > 0) {
        *error = "reviewed source changed during revalidation";
        return 0;
    }
    return 1;
}

static int validate_leaf_at(int parent_fd, const char *name, held_leaf *leaf,
                            int expected_mode, int require_immutable,
                            const char **error) {
    struct stat retained, named;
    if (fstat(leaf->descriptor, &retained) != 0 ||
        fstatat(parent_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_vnode(&retained, &named) || !S_ISREG(retained.st_mode) ||
        retained.st_uid != (uid_t)WINS_EXPECTED_UID ||
        retained.st_gid != (gid_t)WINS_EXPECTED_GID ||
        (retained.st_mode & 07777) != expected_mode || retained.st_nlink != 1 ||
        !has_empty_acl(leaf->descriptor) ||
        (((unsigned int)retained.st_flags) & ~WINS_IMMUTABLE_FLAG) != 0U ||
        (require_immutable &&
         (((unsigned int)retained.st_flags) & WINS_IMMUTABLE_FLAG) == 0U)) {
        *error = "fixed leaf custody or pathname identity is invalid";
        return 0;
    }
    hash_fd(leaf->descriptor, leaf->digest);
    leaf->identity = retained;
    return 1;
}

static int open_leaf_at(int parent_fd, const char *name, held_leaf *leaf,
                        int expected_mode, int require_immutable,
                        const char **error) {
    memset(leaf, 0, sizeof(*leaf));
    leaf->descriptor = openat(parent_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (leaf->descriptor < 0 ||
        !validate_leaf_at(parent_fd, name, leaf, expected_mode,
                          require_immutable, error)) {
        if (leaf->descriptor >= 0) close(leaf->descriptor);
        leaf->descriptor = -1;
        if (*error == NULL) *error = "cannot open fixed leaf";
        return 0;
    }
    return 1;
}

static void close_leaf(held_leaf *leaf) {
    if (leaf->descriptor >= 0) close(leaf->descriptor);
    leaf->descriptor = -1;
}

static int require_pair_digest(const held_leaf *controller,
                               const held_leaf *launcher,
                               const char *controller_digest,
                               const char *launcher_digest,
                               const char **error) {
    if (!secure_equal(controller->digest, controller_digest) ||
        !secure_equal(launcher->digest, launcher_digest)) {
        *error = "installed pair digest is outside the reviewed transition";
        return 0;
    }
    if (!fd_contains_text(launcher->descriptor, launcher->identity.st_size,
                          controller_digest)) {
        *error = "installed launcher does not bind its controller digest";
        return 0;
    }
    return 1;
}

static int require_rename_swap_capability(int parent_fd, const char **error) {
    struct attrlist attributes;
    struct {
        uint32_t length;
        vol_capabilities_attr_t capabilities;
    } result;
    memset(&attributes, 0, sizeof(attributes));
    memset(&result, 0, sizeof(result));
    attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
    attributes.volattr = ATTR_VOL_INFO | ATTR_VOL_CAPABILITIES;
    if (fgetattrlist(parent_fd, &attributes, &result, sizeof(result), 0) != 0 ||
        result.length != sizeof(result) ||
        (result.capabilities.valid[VOL_CAPABILITIES_INTERFACES] &
         VOL_CAP_INT_RENAME_SWAP) == 0U ||
        (result.capabilities.capabilities[VOL_CAPABILITIES_INTERFACES] &
         VOL_CAP_INT_RENAME_SWAP) == 0U) {
        *error = "destination volume does not prove atomic RENAME_SWAP support";
        return 0;
    }
    return 1;
}

static int acquire_authority_lock(int parent_fd, const char **error) {
    if (flock(parent_fd, LOCK_EX | LOCK_NB) != 0) {
        *error = "another owner-provision transaction holds the authority lock";
        return 0;
    }
    return 1;
}

static int refuse_pending_provision_transaction(int parent_fd,
                                                const char **error) {
    int duplicate = dup(parent_fd);
    DIR *directory;
    struct dirent *entry;
    if (duplicate < 0 || (directory = fdopendir(duplicate)) == NULL) {
        if (duplicate >= 0) close(duplicate);
        *error = "cannot enumerate authority transaction residue";
        return 0;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, "owner-provision.transaction.json") == 0 ||
            strcmp(entry->d_name, "owner-provision.transaction.next") == 0 ||
            strncmp(entry->d_name, "authority.json.owner-provision.", 31) == 0) {
            closedir(directory);
            *error = "unfinished owner-provision transaction requires recovery";
            return 0;
        }
    }
    if (errno != 0) {
        closedir(directory);
        *error = "cannot enumerate authority transaction residue";
        return 0;
    }
    closedir(directory);
    return 1;
}

static int derive_stage_name(char output[NAME_MAX + 1]) {
    sha256_context context;
    unsigned char digest[32];
    char encoded[65];
    sha256_init(&context);
    sha256_update(&context,
                  (const unsigned char *)WINS_OLD_CONTROLLER_SHA256, 64);
    sha256_update(&context,
                  (const unsigned char *)WINS_OLD_LAUNCHER_SHA256, 64);
    sha256_update(&context,
                  (const unsigned char *)WINS_NEW_CONTROLLER_SHA256, 64);
    sha256_update(&context,
                  (const unsigned char *)WINS_NEW_LAUNCHER_SHA256, 64);
    sha256_final(&context, digest);
    hex_encode(digest, sizeof(digest), encoded);
    {
        int length = snprintf(output, NAME_MAX + 1, "%s%.32s",
                              STAGE_PREFIX, encoded);
        return length > 0 && length < NAME_MAX + 1;
    }
}

static int derive_cleanup_name(char output[NAME_MAX + 1]) {
    char stage_name[NAME_MAX + 1];
    int length;
    if (!derive_stage_name(stage_name)) return 0;
    length = snprintf(output, NAME_MAX + 1, "%s%s", CLEANUP_PREFIX,
                      stage_name + strlen(STAGE_PREFIX));
    return length > 0 && length < NAME_MAX + 1;
}

static int decimal_u64(const char *value, uint64_t *output) {
    char *end = NULL;
    unsigned long long parsed;
    const char *cursor;
    if (value == NULL || *value == '\0') return 0;
    for (cursor = value; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') return 0;
    }
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') return 0;
    *output = (uint64_t)parsed;
    return 1;
}

static int next_journal_value(char **cursor, const char *key,
                              char *output, size_t output_size) {
    size_t key_length = strlen(key);
    char *newline;
    size_t length;
    if (strncmp(*cursor, key, key_length) != 0 || (*cursor)[key_length] != '=') {
        return 0;
    }
    *cursor += key_length + 1;
    newline = strchr(*cursor, '\n');
    if (newline == NULL) return 0;
    length = (size_t)(newline - *cursor);
    if (length == 0 || length >= output_size) return 0;
    memcpy(output, *cursor, length);
    output[length] = '\0';
    *cursor = newline + 1;
    return 1;
}

static int read_journal_at(int directory_fd, const char *name,
                           journal_record *journal, const char **error) {
    char bytes[MAX_JOURNAL_BYTES + 1];
    char value[PATH_MAX];
    char *cursor = bytes;
    int descriptor;
    struct stat info;
    ssize_t count;
    descriptor = openat(directory_fd, name,
                        O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0 || fstat(descriptor, &info) != 0 ||
        !S_ISREG(info.st_mode) || info.st_uid != (uid_t)WINS_EXPECTED_UID ||
        info.st_gid != (gid_t)WINS_EXPECTED_GID ||
        (info.st_mode & 07777) != 0400 || info.st_nlink != 1 ||
        info.st_flags != 0 || !has_empty_acl(descriptor) ||
        info.st_size <= 0 || info.st_size > (off_t)MAX_JOURNAL_BYTES) {
        if (descriptor >= 0) close(descriptor);
        *error = "update journal custody is invalid";
        return 0;
    }
    count = pread(descriptor, bytes, (size_t)info.st_size, 0);
    close(descriptor);
    if (count != info.st_size) {
        *error = "cannot read exact update journal";
        return 0;
    }
    bytes[count] = '\0';
    memset(journal, 0, sizeof(*journal));
    if (!next_journal_value(&cursor, "contract", value, sizeof(value)) ||
        strcmp(value, JOURNAL_CONTRACT) != 0 ||
        !next_journal_value(&cursor, "schema_version", value, sizeof(value)) ||
        strcmp(value, "2") != 0 ||
        !next_journal_value(&cursor, "updater_sha256",
                            journal->updater_sha256,
                            sizeof(journal->updater_sha256)) ||
        !valid_digest(journal->updater_sha256) ||
        !next_journal_value(&cursor, "updater_build_source_sha256",
                            value, sizeof(value)) ||
        strcmp(value, WINS_BUILD_SOURCE_SHA256) != 0 ||
        !next_journal_value(&cursor, "authority_sha256",
                            journal->authority_sha256,
                            sizeof(journal->authority_sha256)) ||
        !valid_digest(journal->authority_sha256) ||
        !next_journal_value(&cursor, "authority_device",
                            value, sizeof(value)) ||
        !decimal_u64(value, &journal->authority_device) ||
        !next_journal_value(&cursor, "authority_inode",
                            value, sizeof(value)) ||
        !decimal_u64(value, &journal->authority_inode) ||
        !next_journal_value(&cursor, "old_controller_sha256",
                            value, sizeof(value)) ||
        strcmp(value, WINS_OLD_CONTROLLER_SHA256) != 0 ||
        !next_journal_value(&cursor, "old_controller_device",
                            value, sizeof(value)) ||
        !decimal_u64(value, &journal->old_controller_device) ||
        !next_journal_value(&cursor, "old_controller_inode",
                            value, sizeof(value)) ||
        !decimal_u64(value, &journal->old_controller_inode) ||
        !next_journal_value(&cursor, "old_launcher_sha256",
                            value, sizeof(value)) ||
        strcmp(value, WINS_OLD_LAUNCHER_SHA256) != 0 ||
        !next_journal_value(&cursor, "old_launcher_device",
                            value, sizeof(value)) ||
        !decimal_u64(value, &journal->old_launcher_device) ||
        !next_journal_value(&cursor, "old_launcher_inode",
                            value, sizeof(value)) ||
        !decimal_u64(value, &journal->old_launcher_inode) ||
        !next_journal_value(&cursor, "new_controller_sha256",
                            value, sizeof(value)) ||
        strcmp(value, WINS_NEW_CONTROLLER_SHA256) != 0 ||
        !next_journal_value(&cursor, "new_launcher_sha256",
                            value, sizeof(value)) ||
        strcmp(value, WINS_NEW_LAUNCHER_SHA256) != 0 ||
        !next_journal_value(&cursor, "stage_name",
                            journal->stage_name, sizeof(journal->stage_name)) ||
        !next_journal_value(&cursor, "phase",
                            journal->phase, sizeof(journal->phase)) ||
        *cursor != '\0') {
        *error = "update journal schema, order, or transition binding is invalid";
        return 0;
    }
    return 1;
}

static int write_all(int descriptor, const unsigned char *bytes, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = write(descriptor, bytes + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 0;
        offset += (size_t)count;
    }
    return 1;
}

static int write_journal(update_context *context, const char *phase,
                         const char **error) {
    char bytes[MAX_JOURNAL_BYTES + 1];
    int length;
    int descriptor;
    if (strchr(phase, '\n') != NULL || strlen(phase) >= sizeof(context->journal.phase)) {
        *error = "update journal phase is invalid";
        return 0;
    }
    if (!valid_digest(context->journal.authority_sha256)) {
        *error = "update journal authority binding is absent";
        return 0;
    }
    length = snprintf(
        bytes, sizeof(bytes),
        "contract=%s\n"
        "schema_version=2\n"
        "updater_sha256=%s\n"
        "updater_build_source_sha256=%s\n"
        "authority_sha256=%s\n"
        "authority_device=%llu\n"
        "authority_inode=%llu\n"
        "old_controller_sha256=%s\n"
        "old_controller_device=%llu\n"
        "old_controller_inode=%llu\n"
        "old_launcher_sha256=%s\n"
        "old_launcher_device=%llu\n"
        "old_launcher_inode=%llu\n"
        "new_controller_sha256=%s\n"
        "new_launcher_sha256=%s\n"
        "stage_name=%s\n"
        "phase=%s\n",
        JOURNAL_CONTRACT, context->self_sha256, WINS_BUILD_SOURCE_SHA256,
        context->journal.authority_sha256,
        (unsigned long long)context->journal.authority_device,
        (unsigned long long)context->journal.authority_inode,
        WINS_OLD_CONTROLLER_SHA256,
        (unsigned long long)context->journal.old_controller_device,
        (unsigned long long)context->journal.old_controller_inode,
        WINS_OLD_LAUNCHER_SHA256,
        (unsigned long long)context->journal.old_launcher_device,
        (unsigned long long)context->journal.old_launcher_inode,
        WINS_NEW_CONTROLLER_SHA256, WINS_NEW_LAUNCHER_SHA256,
        context->stage_name, phase);
    if (length <= 0 || (size_t)length >= sizeof(bytes)) {
        *error = "cannot encode bounded update journal";
        return 0;
    }
    unlinkat(context->stage_fd, JOURNAL_NEXT_NAME, 0);
    descriptor = openat(context->stage_fd, JOURNAL_NEXT_NAME,
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                        0600);
    if (descriptor < 0 || !write_all(descriptor, (unsigned char *)bytes,
                                     (size_t)length) ||
        fchown(descriptor, (uid_t)WINS_EXPECTED_UID,
               (gid_t)WINS_EXPECTED_GID) != 0 ||
        fchmod(descriptor, 0400) != 0 || !sync_file(descriptor, error)) {
        if (descriptor >= 0) close(descriptor);
        unlinkat(context->stage_fd, JOURNAL_NEXT_NAME, 0);
        if (*error == NULL) *error = "cannot publish next update journal";
        return 0;
    }
    close(descriptor);
    if (context->journal_exists) test_crash(20);
    if (renameat(context->stage_fd, JOURNAL_NEXT_NAME,
                 context->stage_fd, JOURNAL_NAME) != 0 ||
        fsync(context->stage_fd) != 0) {
        *error = "cannot atomically publish update journal";
        return 0;
    }
    strcpy(context->journal.phase, phase);
    context->journal_exists = 1;
    context->journal_valid = 1;
    return 1;
}

static void context_init(update_context *context) {
    memset(context, 0, sizeof(*context));
    context->parent_fd = -1;
    context->stage_fd = -1;
    context->destination_controller.descriptor = -1;
    context->destination_launcher.descriptor = -1;
    context->stage_controller.descriptor = -1;
    context->stage_launcher.descriptor = -1;
    context->authority.descriptor = -1;
}

static void context_close(update_context *context) {
    close_leaf(&context->authority);
    close_leaf(&context->stage_launcher);
    close_leaf(&context->stage_controller);
    close_leaf(&context->destination_launcher);
    close_leaf(&context->destination_controller);
    if (context->stage_fd >= 0) close(context->stage_fd);
}

static int validate_authority_witness(update_context *context,
                                      const char **error) {
    held_leaf current = context->authority;
    char prior_digest[65];
    struct stat prior_identity = context->authority.identity;
    strcpy(prior_digest, context->authority.digest);
    if (!validate_leaf_at(context->parent_fd, AUTHORITY_NAME, &current,
                          0444, 1, error) ||
        !same_leaf_identity(&prior_identity, &current.identity) ||
        !secure_equal(prior_digest, current.digest)) {
        *error = "controller authority witness changed during pair transition";
        return 0;
    }
    if (context->journal_exists && context->journal_valid &&
        (!secure_equal(context->journal.authority_sha256, current.digest) ||
         context->journal.authority_device !=
             (uint64_t)current.identity.st_dev ||
         context->journal.authority_inode !=
             (uint64_t)current.identity.st_ino)) {
        *error = "journal-bound authority witness changed across recovery";
        return 0;
    }
    return 1;
}

static int open_stage_directory(update_context *context, int create,
                                const char **error) {
    struct stat named, retained, parent;
    int descriptor;
    if (fstatat(context->parent_fd, context->stage_name, &named,
                AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno != ENOENT || !create) {
            if (errno == ENOENT && !create) return 1;
            *error = "cannot inspect private update stage";
            return 0;
        }
        if (mkdirat(context->parent_fd, context->stage_name, 0700) != 0) {
            *error = "cannot create private update stage";
            return 0;
        }
        if (fstatat(context->parent_fd, context->stage_name, &named,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            *error = "cannot stat created private update stage";
            return 0;
        }
    }
    descriptor = openat(context->parent_fd, context->stage_name,
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0 || fstat(descriptor, &retained) != 0 ||
        fstat(context->parent_fd, &parent) != 0 ||
        !same_vnode(&named, &retained) || !S_ISDIR(retained.st_mode) ||
        retained.st_dev != parent.st_dev ||
        retained.st_uid != (uid_t)WINS_EXPECTED_UID ||
        retained.st_gid != (gid_t)WINS_EXPECTED_GID ||
        (retained.st_mode & 07777) != 0700 || retained.st_flags != 0 ||
        !has_empty_acl(descriptor)) {
        if (descriptor >= 0) close(descriptor);
        *error = "private update stage custody is invalid";
        return 0;
    }
    context->stage_fd = descriptor;
    context->stage_exists = 1;
    return 1;
}

static int stage_inventory_exact(update_context *context, const char **error) {
    int duplicate = dup(context->stage_fd);
    DIR *directory;
    struct dirent *entry;
    if (duplicate < 0 || (directory = fdopendir(duplicate)) == NULL) {
        if (duplicate >= 0) close(duplicate);
        *error = "cannot enumerate private update stage";
        return 0;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0 &&
            strcmp(entry->d_name, CONTROLLER_NAME) != 0 &&
            strcmp(entry->d_name, LAUNCHER_NAME) != 0 &&
            strcmp(entry->d_name, JOURNAL_NAME) != 0 &&
            strcmp(entry->d_name, JOURNAL_NEXT_NAME) != 0) {
            closedir(directory);
            *error = "private update stage contains an unexpected entry";
            return 0;
        }
    }
    if (errno != 0) {
        closedir(directory);
        *error = "cannot enumerate private update stage";
        return 0;
    }
    closedir(directory);
    return 1;
}

static int prepare_stage_leaf(int stage_fd, const char *name, int source_fd,
                              const struct stat *source_info,
                              const char *expected, held_leaf *leaf,
                              const char **error) {
    int descriptor = openat(stage_fd, name,
                            O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                            0600);
    if (descriptor < 0 ||
        !copy_exact(source_fd, descriptor, source_info->st_size,
                    expected, error)) {
        if (descriptor >= 0) close(descriptor);
        unlinkat(stage_fd, name, 0);
        if (*error == NULL) *error = "cannot prepare exclusive update stage leaf";
        return 0;
    }
    leaf->descriptor = descriptor;
    if (!validate_leaf_at(stage_fd, name, leaf, 0555, 0, error) ||
        leaf->identity.st_flags != 0 ||
        !secure_equal(leaf->digest, expected)) {
        close_leaf(leaf);
        unlinkat(stage_fd, name, 0);
        *error = "prepared update stage leaf is not exact";
        return 0;
    }
    return 1;
}

static int phase_is_known(const char *phase) {
    static const char *const phases[] = {
        "armed",
        "unsealing-controller",
        "swapping-controller",
        "sealing-controller",
        "controller-live",
        "unsealing-launcher",
        "swapping-launcher",
        "sealing-launcher",
        "both-live",
        "revert-unsealing-launcher",
        "revert-swapping-launcher",
        "revert-sealing-launcher",
        "revert-unsealing-controller",
        "revert-swapping-controller",
        "revert-sealing-controller",
        "revert-sealing-pair",
        "verified",
    };
    size_t index;
    for (index = 0; index < sizeof(phases) / sizeof(phases[0]); ++index) {
        if (strcmp(phase, phases[index]) == 0) return 1;
    }
    return 0;
}

static int old_identity_is_exact(const held_leaf *leaf, uint64_t device,
                                 uint64_t inode) {
    return (uint64_t)leaf->identity.st_dev == device &&
           (uint64_t)leaf->identity.st_ino == inode;
}

static pair_state classify_state(update_context *context,
                                 const char **error) {
    int destination_old =
        secure_equal(context->destination_controller.digest,
                     WINS_OLD_CONTROLLER_SHA256) &&
        secure_equal(context->destination_launcher.digest,
                     WINS_OLD_LAUNCHER_SHA256);
    int destination_new =
        secure_equal(context->destination_controller.digest,
                     WINS_NEW_CONTROLLER_SHA256) &&
        secure_equal(context->destination_launcher.digest,
                     WINS_NEW_LAUNCHER_SHA256);
    if (!context->stage_exists || context->stage_is_residue) {
        int controller_sealed =
            (((unsigned int)context->destination_controller.identity.st_flags) &
             WINS_IMMUTABLE_FLAG) != 0U;
        int launcher_sealed =
            (((unsigned int)context->destination_launcher.identity.st_flags) &
             WINS_IMMUTABLE_FLAG) != 0U;
        if (!controller_sealed || !launcher_sealed) {
            *error = "terminal published pair is not exactly immutable";
            return STATE_UNRECOGNIZED;
        }
        if (destination_old &&
            require_pair_digest(&context->destination_controller,
                                &context->destination_launcher,
                                WINS_OLD_CONTROLLER_SHA256,
                                WINS_OLD_LAUNCHER_SHA256, error)) {
            return STATE_CLEAN;
        }
        if (destination_new &&
            require_pair_digest(&context->destination_controller,
                                &context->destination_launcher,
                                WINS_NEW_CONTROLLER_SHA256,
                                WINS_NEW_LAUNCHER_SHA256, error)) {
            return STATE_COMMITTED;
        }
        *error = "published pair is outside the reviewed transition";
        return STATE_UNRECOGNIZED;
    }
    if (!context->journal_exists || !phase_is_known(context->journal.phase) ||
        !secure_equal(context->journal.updater_sha256, context->self_sha256) ||
        strcmp(context->journal.stage_name, context->stage_name) != 0) {
        *error = "update journal does not authorize this recovery";
        return STATE_UNRECOGNIZED;
    }
    if (secure_equal(context->destination_controller.digest,
                     WINS_OLD_CONTROLLER_SHA256) &&
        secure_equal(context->destination_launcher.digest,
                     WINS_OLD_LAUNCHER_SHA256) &&
        secure_equal(context->stage_controller.digest,
                     WINS_NEW_CONTROLLER_SHA256) &&
        secure_equal(context->stage_launcher.digest,
                     WINS_NEW_LAUNCHER_SHA256) &&
        old_identity_is_exact(&context->destination_controller,
                              context->journal.old_controller_device,
                              context->journal.old_controller_inode) &&
        old_identity_is_exact(&context->destination_launcher,
                              context->journal.old_launcher_device,
                              context->journal.old_launcher_inode)) {
        return STATE_ARMED;
    }
    if (secure_equal(context->destination_controller.digest,
                     WINS_NEW_CONTROLLER_SHA256) &&
        secure_equal(context->destination_launcher.digest,
                     WINS_OLD_LAUNCHER_SHA256) &&
        secure_equal(context->stage_controller.digest,
                     WINS_OLD_CONTROLLER_SHA256) &&
        secure_equal(context->stage_launcher.digest,
                     WINS_NEW_LAUNCHER_SHA256) &&
        old_identity_is_exact(&context->stage_controller,
                              context->journal.old_controller_device,
                              context->journal.old_controller_inode) &&
        old_identity_is_exact(&context->destination_launcher,
                              context->journal.old_launcher_device,
                              context->journal.old_launcher_inode)) {
        return STATE_CONTROLLER_LIVE;
    }
    if (secure_equal(context->destination_controller.digest,
                     WINS_NEW_CONTROLLER_SHA256) &&
        secure_equal(context->destination_launcher.digest,
                     WINS_NEW_LAUNCHER_SHA256) &&
        secure_equal(context->stage_controller.digest,
                     WINS_OLD_CONTROLLER_SHA256) &&
        secure_equal(context->stage_launcher.digest,
                     WINS_OLD_LAUNCHER_SHA256) &&
        old_identity_is_exact(&context->stage_controller,
                              context->journal.old_controller_device,
                              context->journal.old_controller_inode) &&
        old_identity_is_exact(&context->stage_launcher,
                              context->journal.old_launcher_device,
                              context->journal.old_launcher_inode)) {
        return STATE_BOTH_LIVE;
    }
    *error = "published and rollback pair form an unrecognized digest state";
    return STATE_UNRECOGNIZED;
}

static const char *state_name(pair_state state) {
    switch (state) {
        case STATE_CLEAN: return "CLEAN";
        case STATE_ARMED: return "ARMED";
        case STATE_CONTROLLER_LIVE: return "CONTROLLER_LIVE";
        case STATE_BOTH_LIVE: return "BOTH_LIVE";
        case STATE_COMMITTED: return "COMMITTED";
        default: return "UNRECOGNIZED";
    }
}

static void test_crash(int ordinal) {
#ifdef WINS_TEST_CRASH_AT
    if (ordinal == WINS_TEST_CRASH_AT) {
#ifdef WINS_TEST_CRASH_MARKER_PATH
        int marker = open(WINS_TEST_CRASH_MARKER_PATH,
                          O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                          0600);
        if (marker >= 0) {
            close(marker);
            _exit(90 + ordinal);
        }
#else
        _exit(90 + ordinal);
#endif
    }
#else
    (void)ordinal;
#endif
}

static void test_pause(void) {
#ifdef WINS_TEST_HOOK_PATH
    char release_path[PATH_MAX];
    struct timespec delay = {0, 10000000};
    int length = snprintf(release_path, sizeof(release_path), "%s.release",
                          WINS_TEST_HOOK_PATH);
    if (length <= 0 || (size_t)length >= sizeof(release_path)) {
        fail("test hook path is invalid");
    }
    printf("TEST_HOOK_READY\n");
    fflush(stdout);
    while (access(release_path, F_OK) != 0) nanosleep(&delay, NULL);
#endif
}

static int seal_leaf_at(int parent_fd, const char *name, held_leaf *leaf,
                        const char *expected, const char **error) {
    if (!secure_equal(leaf->digest, expected)) {
        *error = "seal target digest is outside the reviewed transition";
        return 0;
    }
    if ((((unsigned int)leaf->identity.st_flags) & WINS_IMMUTABLE_FLAG) == 0U) {
        if (fchflags(leaf->descriptor,
                     leaf->identity.st_flags | WINS_IMMUTABLE_FLAG) != 0 ||
            !sync_file(leaf->descriptor, error)) {
            if (*error == NULL) *error = "cannot seal reviewed transition leaf";
            return 0;
        }
    }
    if (!validate_leaf_at(parent_fd, name, leaf, 0555, 1, error) ||
        !secure_equal(leaf->digest, expected)) {
        if (*error == NULL) *error = "sealed transition leaf digest changed";
        return 0;
    }
    return 1;
}

static int unseal_leaf_at(int parent_fd, const char *name, held_leaf *leaf,
                          const char *expected, const char **error) {
    if (!secure_equal(leaf->digest, expected)) {
        *error = "unseal target digest is outside the reviewed transition";
        return 0;
    }
    if ((((unsigned int)leaf->identity.st_flags) & WINS_IMMUTABLE_FLAG) != 0U) {
        if (fchflags(leaf->descriptor,
                     leaf->identity.st_flags & ~WINS_IMMUTABLE_FLAG) != 0 ||
            !sync_file(leaf->descriptor, error) || fsync(parent_fd) != 0) {
            if (*error == NULL) *error = "cannot unseal reviewed transition leaf";
            return 0;
        }
    }
    if (!validate_leaf_at(parent_fd, name, leaf, 0555, 0, error) ||
        leaf->identity.st_flags != 0 ||
        !secure_equal(leaf->digest, expected)) {
        if (*error == NULL) {
            *error = "unsealed transition leaf custody is invalid";
        }
        return 0;
    }
    return 1;
}

static int swap_role(update_context *context, const char *name,
                     held_leaf *destination, held_leaf *stage,
                     const char *incoming_digest, const char *outgoing_digest,
                     const char **error) {
    held_leaf temporary;
    if (!secure_equal(destination->digest, outgoing_digest) ||
        !secure_equal(stage->digest, incoming_digest)) {
        *error = "swap operands do not match the reviewed transition";
        return 0;
    }
    if (renameatx_np(context->stage_fd, name, context->parent_fd, name,
                     RENAME_SWAP) != 0 || fsync(context->parent_fd) != 0 ||
        fsync(context->stage_fd) != 0) {
        *error = "atomic pair-leaf RENAME_SWAP failed";
        return 0;
    }
    temporary = *destination;
    *destination = *stage;
    *stage = temporary;
    if (!validate_leaf_at(context->parent_fd, name, destination, 0555, 0,
                          error) ||
        !validate_leaf_at(context->stage_fd, name, stage, 0555, 0, error) ||
        !secure_equal(destination->digest, incoming_digest) ||
        !secure_equal(stage->digest, outgoing_digest)) {
        *error = "post-swap pair-leaf custody is invalid";
        return 0;
    }
    return 1;
}

static int arm_update(update_context *context, retained_sources *sources,
                      const char **error) {
    const struct stat *controller_info =
        &sources->controller.components[sources->controller.count - 1].identity;
    const struct stat *launcher_info =
        &sources->launcher.components[sources->launcher.count - 1].identity;
    if (!open_stage_directory(context, 1, error) ||
        !stage_inventory_exact(context, error)) return 0;
    if (fstatat(context->stage_fd, JOURNAL_NAME, &(struct stat){0},
                AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT ||
        fstatat(context->stage_fd, CONTROLLER_NAME, &(struct stat){0},
                AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT ||
        fstatat(context->stage_fd, LAUNCHER_NAME, &(struct stat){0},
                AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) {
        *error = "fresh update stage is not empty";
        return 0;
    }
    test_crash(0);
    test_pause();
    if (!validate_sources(sources, error) ||
        !validate_authority_witness(context, error) ||
        !prepare_stage_leaf(
            context->stage_fd, CONTROLLER_NAME,
            sources->controller.components[sources->controller.count - 1].descriptor,
            controller_info, WINS_NEW_CONTROLLER_SHA256,
            &context->stage_controller, error) ||
        !validate_sources(sources, error) ||
        !prepare_stage_leaf(
            context->stage_fd, LAUNCHER_NAME,
            sources->launcher.components[sources->launcher.count - 1].descriptor,
            launcher_info, WINS_NEW_LAUNCHER_SHA256,
            &context->stage_launcher, error) ||
        fsync(context->stage_fd) != 0 || fsync(context->parent_fd) != 0 ||
        !validate_sources(sources, error) ||
        !validate_authority_witness(context, error)) {
        const char *primary;
        const char *cleanup_error = NULL;
        if (*error == NULL) *error = "cannot arm exact update pair";
        primary = *error;
        context->stage_is_residue = 1;
        if (!discard_stage_residue(context, &cleanup_error)) {
            *error = cleanup_error;
            return 0;
        }
        *error = primary;
        return 0;
    }
    context->journal.old_controller_device =
        (uint64_t)context->destination_controller.identity.st_dev;
    context->journal.old_controller_inode =
        (uint64_t)context->destination_controller.identity.st_ino;
    context->journal.old_launcher_device =
        (uint64_t)context->destination_launcher.identity.st_dev;
    context->journal.old_launcher_inode =
        (uint64_t)context->destination_launcher.identity.st_ino;
    strcpy(context->journal.authority_sha256, context->authority.digest);
    context->journal.authority_device =
        (uint64_t)context->authority.identity.st_dev;
    context->journal.authority_inode =
        (uint64_t)context->authority.identity.st_ino;
    if (!write_journal(context, "armed", error)) return 0;
    test_crash(1);
    return 1;
}

static int advance_forward(update_context *context, pair_state state,
                           const char **error) {
    if (state == STATE_ARMED) {
        if (!write_journal(context, "unsealing-controller", error) ||
            !unseal_leaf_at(context->parent_fd, CONTROLLER_NAME,
                            &context->destination_controller,
                            WINS_OLD_CONTROLLER_SHA256, error)) return 0;
        test_crash(2);
        if (!write_journal(context, "swapping-controller", error) ||
            !swap_role(context, CONTROLLER_NAME,
                       &context->destination_controller,
                       &context->stage_controller,
                       WINS_NEW_CONTROLLER_SHA256,
                       WINS_OLD_CONTROLLER_SHA256, error)) return 0;
        test_crash(3);
        state = STATE_CONTROLLER_LIVE;
    }
    if (state == STATE_CONTROLLER_LIVE) {
        if (!write_journal(context, "sealing-controller", error) ||
            !seal_leaf_at(context->parent_fd, CONTROLLER_NAME,
                          &context->destination_controller,
                          WINS_NEW_CONTROLLER_SHA256, error)) return 0;
        test_crash(4);
        if (!write_journal(context, "controller-live", error) ||
            !write_journal(context, "unsealing-launcher", error) ||
            !unseal_leaf_at(context->parent_fd, LAUNCHER_NAME,
                            &context->destination_launcher,
                            WINS_OLD_LAUNCHER_SHA256, error)) return 0;
        test_crash(5);
        if (!write_journal(context, "swapping-launcher", error) ||
            !swap_role(context, LAUNCHER_NAME,
                       &context->destination_launcher,
                       &context->stage_launcher,
                       WINS_NEW_LAUNCHER_SHA256,
                       WINS_OLD_LAUNCHER_SHA256, error)) return 0;
        test_crash(6);
        state = STATE_BOTH_LIVE;
    }
    if (state == STATE_BOTH_LIVE) {
        if (!write_journal(context, "sealing-launcher", error) ||
            !seal_leaf_at(context->parent_fd, LAUNCHER_NAME,
                          &context->destination_launcher,
                          WINS_NEW_LAUNCHER_SHA256, error) ||
            !seal_leaf_at(context->parent_fd, CONTROLLER_NAME,
                          &context->destination_controller,
                          WINS_NEW_CONTROLLER_SHA256, error)) return 0;
        test_crash(7);
        if (!write_journal(context, "both-live", error)) return 0;
    }
    return 1;
}

static int advance_revert(update_context *context, pair_state state,
                          const char **error) {
    if (state == STATE_BOTH_LIVE) {
        if (!write_journal(context, "revert-unsealing-launcher", error) ||
            !unseal_leaf_at(context->parent_fd, LAUNCHER_NAME,
                            &context->destination_launcher,
                            WINS_NEW_LAUNCHER_SHA256, error) ||
            !write_journal(context, "revert-swapping-launcher", error) ||
            !swap_role(context, LAUNCHER_NAME,
                       &context->destination_launcher,
                       &context->stage_launcher,
                       WINS_OLD_LAUNCHER_SHA256,
                       WINS_NEW_LAUNCHER_SHA256, error) ||
            !write_journal(context, "revert-sealing-launcher", error) ||
            !seal_leaf_at(context->parent_fd, LAUNCHER_NAME,
                          &context->destination_launcher,
                          WINS_OLD_LAUNCHER_SHA256, error)) return 0;
        state = STATE_CONTROLLER_LIVE;
    }
    if (state == STATE_CONTROLLER_LIVE) {
        if (!write_journal(context, "revert-unsealing-controller", error) ||
            !unseal_leaf_at(context->parent_fd, CONTROLLER_NAME,
                            &context->destination_controller,
                            WINS_NEW_CONTROLLER_SHA256, error) ||
            !write_journal(context, "revert-swapping-controller", error) ||
            !swap_role(context, CONTROLLER_NAME,
                       &context->destination_controller,
                       &context->stage_controller,
                       WINS_OLD_CONTROLLER_SHA256,
                       WINS_NEW_CONTROLLER_SHA256, error) ||
            !write_journal(context, "revert-sealing-controller", error) ||
            !seal_leaf_at(context->parent_fd, CONTROLLER_NAME,
                          &context->destination_controller,
                          WINS_OLD_CONTROLLER_SHA256, error)) return 0;
    }
    return write_journal(context, "revert-sealing-pair", error) &&
           seal_leaf_at(context->parent_fd, CONTROLLER_NAME,
                        &context->destination_controller,
                        WINS_OLD_CONTROLLER_SHA256, error) &&
           seal_leaf_at(context->parent_fd, LAUNCHER_NAME,
                        &context->destination_launcher,
                        WINS_OLD_LAUNCHER_SHA256, error);
}

static int remove_transaction(update_context *context, pair_state terminal,
                              const char **error) {
    const char *destination_controller =
        terminal == STATE_COMMITTED ? WINS_NEW_CONTROLLER_SHA256
                                    : WINS_OLD_CONTROLLER_SHA256;
    const char *destination_launcher =
        terminal == STATE_COMMITTED ? WINS_NEW_LAUNCHER_SHA256
                                    : WINS_OLD_LAUNCHER_SHA256;
    const char *stage_controller =
        terminal == STATE_COMMITTED ? WINS_OLD_CONTROLLER_SHA256
                                    : WINS_NEW_CONTROLLER_SHA256;
    const char *stage_launcher =
        terminal == STATE_COMMITTED ? WINS_OLD_LAUNCHER_SHA256
                                    : WINS_NEW_LAUNCHER_SHA256;
    if (!validate_leaf_at(context->parent_fd, CONTROLLER_NAME,
                          &context->destination_controller, 0555, 1, error) ||
        !validate_leaf_at(context->parent_fd, LAUNCHER_NAME,
                          &context->destination_launcher, 0555, 1, error) ||
        !secure_equal(context->destination_controller.digest,
                      destination_controller) ||
        !secure_equal(context->destination_launcher.digest,
                      destination_launcher) ||
        !validate_leaf_at(context->stage_fd, CONTROLLER_NAME,
                          &context->stage_controller, 0555, 0, error) ||
        !validate_leaf_at(context->stage_fd, LAUNCHER_NAME,
                          &context->stage_launcher, 0555, 0, error) ||
        context->stage_controller.identity.st_flags != 0 ||
        context->stage_launcher.identity.st_flags != 0 ||
        !secure_equal(context->stage_controller.digest, stage_controller) ||
        !secure_equal(context->stage_launcher.digest, stage_launcher) ||
        !validate_authority_witness(context, error)) {
        if (*error == NULL) *error = "terminal transition custody is invalid";
        return 0;
    }
    if (terminal == STATE_COMMITTED &&
        !write_journal(context, "verified", error)) return 0;
    close_leaf(&context->stage_controller);
    close_leaf(&context->stage_launcher);
    if (unlinkat(context->stage_fd, CONTROLLER_NAME, 0) != 0) {
        *error = "cannot remove verified update transaction";
        return 0;
    }
    test_crash(21);
    if (unlinkat(context->stage_fd, LAUNCHER_NAME, 0) != 0) {
        *error = "cannot remove verified update transaction";
        return 0;
    }
    test_crash(22);
    if (unlinkat(context->stage_fd, JOURNAL_NEXT_NAME, 0) == 0 ||
        errno != ENOENT) {
        *error = "cannot finalize verified update transaction removal";
        return 0;
    }
    if (fstatat(context->parent_fd, context->cleanup_name,
                &(struct stat){0}, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT ||
        renameatx_np(context->stage_fd, JOURNAL_NAME,
                     context->parent_fd, context->cleanup_name,
                     RENAME_EXCL) != 0 ||
        fsync(context->stage_fd) != 0 || fsync(context->parent_fd) != 0) {
        *error = "cannot publish durable update cleanup witness";
        return 0;
    }
    context->cleanup_exists = 1;
    test_crash(23);
    if (unlinkat(context->parent_fd, context->stage_name, AT_REMOVEDIR) != 0 ||
        fsync(context->parent_fd) != 0) {
        *error = "cannot finalize verified update transaction removal";
        return 0;
    }
    close(context->stage_fd);
    context->stage_fd = -1;
    context->stage_exists = 0;
    test_crash(24);
    if (!validate_authority_witness(context, error) ||
        unlinkat(context->parent_fd, context->cleanup_name, 0) != 0 ||
        fsync(context->parent_fd) != 0) {
        if (*error == NULL) *error = "cannot remove verified cleanup witness";
        return 0;
    }
    context->cleanup_exists = 0;
    if (!validate_authority_witness(context, error)) return 0;
    context->journal_exists = 0;
    context->journal_valid = 0;
    test_crash(25);
    return 1;
}

static int unlink_optional(int directory, const char *name,
                           const char **error) {
    if (unlinkat(directory, name, 0) == 0 || errno == ENOENT) return 1;
    *error = "cannot unlink whitelisted update residue";
    return 0;
}

static int clear_residue_flags_if_present(int directory, const char *name,
                                          const char **error) {
    struct stat info;
    int descriptor = openat(directory, name,
                            O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) {
        if (errno == ENOENT) return 1;
        *error = "cannot open whitelisted update residue";
        return 0;
    }
    if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != (uid_t)WINS_EXPECTED_UID ||
        info.st_gid != (gid_t)WINS_EXPECTED_GID || info.st_nlink != 1 ||
        !has_empty_acl(descriptor)) {
        close(descriptor);
        *error = "whitelisted update residue custody is invalid";
        return 0;
    }
    if (info.st_flags != 0 &&
        (fchflags(descriptor, 0) != 0 || !sync_file(descriptor, error))) {
        close(descriptor);
        if (*error == NULL) *error = "cannot clear whitelisted residue flags";
        return 0;
    }
    close(descriptor);
    return 1;
}

static int discard_stage_residue(update_context *context,
                                 const char **error) {
    if (!context->stage_exists && !context->cleanup_exists) return 1;
    if (context->stage_exists && context->stage_fd < 0) {
        *error = "retained update-stage residue descriptor is absent";
        return 0;
    }
    close_leaf(&context->stage_controller);
    close_leaf(&context->stage_launcher);
    if (!validate_authority_witness(context, error)) return 0;
    if (context->stage_exists &&
        (!clear_residue_flags_if_present(context->stage_fd,
                                         CONTROLLER_NAME, error) ||
         !clear_residue_flags_if_present(context->stage_fd,
                                         LAUNCHER_NAME, error) ||
         !clear_residue_flags_if_present(context->stage_fd,
                                         JOURNAL_NEXT_NAME, error) ||
         !clear_residue_flags_if_present(context->stage_fd,
                                         JOURNAL_NAME, error) ||
         !unlink_optional(context->stage_fd, CONTROLLER_NAME, error) ||
         !unlink_optional(context->stage_fd, LAUNCHER_NAME, error) ||
         !unlink_optional(context->stage_fd, JOURNAL_NEXT_NAME, error) ||
         !unlink_optional(context->stage_fd, JOURNAL_NAME, error) ||
         fsync(context->stage_fd) != 0 ||
         unlinkat(context->parent_fd, context->stage_name, AT_REMOVEDIR) != 0 ||
         fsync(context->parent_fd) != 0)) {
        if (*error == NULL) *error = "cannot discard bounded update residue";
        return 0;
    }
    if (context->stage_exists) {
        close(context->stage_fd);
        context->stage_fd = -1;
        context->stage_exists = 0;
    }
    if (context->cleanup_exists &&
        (!validate_authority_witness(context, error) ||
         !clear_residue_flags_if_present(context->parent_fd,
                                         context->cleanup_name, error) ||
         !unlink_optional(context->parent_fd, context->cleanup_name, error) ||
         fsync(context->parent_fd) != 0)) {
        if (*error == NULL) *error = "cannot discard bounded cleanup witness";
        return 0;
    }
    context->cleanup_exists = 0;
    context->stage_is_residue = 0;
    context->journal_exists = 0;
    context->journal_valid = 0;
    context->journal_invalid = 0;
    context->journal_next_exists = 0;
    return validate_authority_witness(context, error);
}

static int discard_journal_next(update_context *context,
                                const char **error) {
    if (!context->journal_next_exists) return 1;
    if (!unlink_optional(context->stage_fd, JOURNAL_NEXT_NAME, error) ||
        fsync(context->stage_fd) != 0) {
        if (*error == NULL) *error = "cannot discard unfinished next journal";
        return 0;
    }
    context->journal_next_exists = 0;
    return 1;
}

static void load_journal_state(update_context *context, int directory_fd,
                               const char *name) {
    const char *ignored_error = NULL;
    context->journal_exists = 1;
    if (!read_journal_at(directory_fd, name, &context->journal,
                         &ignored_error) ||
        !phase_is_known(context->journal.phase) ||
        !secure_equal(context->journal.updater_sha256,
                      context->self_sha256) ||
        strcmp(context->journal.stage_name, context->stage_name) != 0) {
        context->journal_invalid = 1;
        context->journal_valid = 0;
        context->stage_is_residue = 1;
        return;
    }
    context->journal_valid = 1;
}

static int require_named_absent(int directory_fd, const char *name,
                                const char **error) {
    struct stat named;
    if (fstatat(directory_fd, name, &named, AT_SYMLINK_NOFOLLOW) == 0) {
        *error = "cleanup witness conflicts with update-stage residue";
        return 0;
    }
    if (errno != ENOENT) {
        *error = "cannot inspect update-stage cleanup state";
        return 0;
    }
    return 1;
}

static int load_context(update_context *context, const char **error) {
    struct stat stage_named;
    struct stat journal_named;
    struct stat cleanup_named;
    const char *stage_error = NULL;
    if (!open_leaf_at(context->parent_fd, CONTROLLER_NAME,
                      &context->destination_controller, 0555, 0, error) ||
        !open_leaf_at(context->parent_fd, LAUNCHER_NAME,
                      &context->destination_launcher, 0555, 0, error) ||
        !open_leaf_at(context->parent_fd, AUTHORITY_NAME,
                      &context->authority, 0444, 1, error)) return 0;
    if (fstatat(context->parent_fd, context->cleanup_name, &cleanup_named,
                AT_SYMLINK_NOFOLLOW) == 0) {
        context->cleanup_exists = 1;
    } else if (errno != ENOENT) {
        *error = "cannot inspect update cleanup witness";
        return 0;
    }
    if (fstatat(context->parent_fd, context->stage_name, &stage_named,
                AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) {
            if (context->cleanup_exists) {
                context->stage_is_residue = 1;
                load_journal_state(context, context->parent_fd,
                                   context->cleanup_name);
            }
            return 1;
        }
        *error = "cannot inspect reviewed update stage";
        return 0;
    }
    if (!open_stage_directory(context, 0, error)) return 0;
    if (context->stage_fd < 0) {
        *error = "reviewed update stage vanished during recovery";
        return 0;
    }
    if (!stage_inventory_exact(context, error)) return 0;
    if (context->cleanup_exists) {
        if (!require_named_absent(context->stage_fd, CONTROLLER_NAME, error) ||
            !require_named_absent(context->stage_fd, LAUNCHER_NAME, error) ||
            !require_named_absent(context->stage_fd, JOURNAL_NAME, error) ||
            !require_named_absent(context->stage_fd, JOURNAL_NEXT_NAME, error)) {
            return 0;
        }
        context->stage_is_residue = 1;
        load_journal_state(context, context->parent_fd,
                           context->cleanup_name);
        return 1;
    }
    if (fstatat(context->stage_fd, JOURNAL_NEXT_NAME, &journal_named,
                AT_SYMLINK_NOFOLLOW) == 0) {
        context->journal_next_exists = 1;
    } else if (errno != ENOENT) {
        *error = "cannot inspect next update journal";
        return 0;
    }
    if (fstatat(context->stage_fd, JOURNAL_NAME, &journal_named,
                AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno != ENOENT) {
            *error = "cannot inspect update journal";
            return 0;
        }
        context->stage_is_residue = 1;
        return 1;
    }
    load_journal_state(context, context->stage_fd, JOURNAL_NAME);
    if (!context->journal_valid) return 1;
    if (!open_leaf_at(context->stage_fd, CONTROLLER_NAME,
                      &context->stage_controller, 0555, 0, &stage_error) ||
        !open_leaf_at(context->stage_fd, LAUNCHER_NAME,
                      &context->stage_launcher, 0555, 0, &stage_error)) {
        close_leaf(&context->stage_controller);
        close_leaf(&context->stage_launcher);
        context->stage_is_residue = 1;
        return 1;
    }
    return 1;
}

static int reap_install_stage(int parent_fd, const char *name,
                              const char **error) {
    struct stat named, retained;
    int descriptor;
    int mode;
    if (fstatat(parent_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) return 1;
        *error = "cannot inspect bounded updater install residue";
        return 0;
    }
    descriptor = openat(parent_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    mode = named.st_mode & 07777;
    if (descriptor < 0 || fstat(descriptor, &retained) != 0 ||
        !same_vnode(&named, &retained) || !S_ISREG(retained.st_mode) ||
        retained.st_uid != (uid_t)WINS_EXPECTED_UID ||
        retained.st_gid != (gid_t)WINS_EXPECTED_GID ||
        retained.st_nlink != 1 || retained.st_flags != 0 ||
        (mode != 0600 && mode != 0555) || !has_empty_acl(descriptor)) {
        if (descriptor >= 0) close(descriptor);
        *error = "bounded updater install residue custody is invalid";
        return 0;
    }
    close(descriptor);
    if (unlinkat(parent_fd, name, 0) != 0 || fsync(parent_fd) != 0) {
        *error = "cannot reap bounded updater install residue";
        return 0;
    }
    return 1;
}

static int preflight_install_self(int parent_fd, const char *expected,
                                  int allow_active_transaction,
                                  const char **error) {
    update_context context;
    pair_state state;
    context_init(&context);
    context.parent_fd = parent_fd;
    strcpy(context.self_sha256, expected);
    if (!derive_stage_name(context.stage_name) ||
        !derive_cleanup_name(context.cleanup_name) ||
        !require_rename_swap_capability(parent_fd, error) ||
        !load_context(&context, error) ||
        !validate_authority_witness(&context, error)) {
        if (*error == NULL) {
            *error = "cannot preflight updater installation";
        }
        context_close(&context);
        return 0;
    }
    if (allow_active_transaction) {
        context_close(&context);
        return 1;
    }
    state = classify_state(&context, error);
    if (context.journal_invalid || context.stage_is_residue ||
        context.cleanup_exists) {
        if (*error == NULL) {
            *error = "first updater installation refuses invalid or cleanup residue";
        }
        context_close(&context);
        return 0;
    }
    if (context.stage_exists) {
        *error = "first updater installation refuses active transition state";
        context_close(&context);
        return 0;
    } else if (state != STATE_CLEAN && state != STATE_COMMITTED) {
        if (*error == NULL) {
            *error = "live pair is incompatible with the candidate updater";
        }
        context_close(&context);
        return 0;
    }
    context_close(&context);
    return 1;
}

static int install_self(const char *source_path, const char *expected,
                        retained_path *destination, const char **error) {
    retained_path source;
    retained_component *source_leaf;
    struct rlimit file_limit;
    int parent_fd = destination->components[destination->count - 1].descriptor;
    char process_path[PROC_PIDPATHINFO_MAXSIZE];
    char stage_name[NAME_MAX + 1] = {0};
    struct stat named;
    int stage_fd = -1;
    held_leaf installed;
    memset(&source, 0, sizeof(source));
    memset(&installed, 0, sizeof(installed));
    installed.descriptor = -1;
    if (!safe_absolute_path(source_path) || !valid_digest(expected) ||
        path_is_under_destination(source_path) ||
        proc_pidpath(getpid(), process_path, sizeof(process_path)) <= 0 ||
        !secure_equal(process_path, source_path)) {
        *error = "install-self requires the executing absolute updater and digest";
        return 0;
    }
    if (!open_retained_path(source_path, 0, &source, error) ||
        !require_source_leaf(&source, expected, error) ||
        !validate_retained_path(&source, 1, expected, error)) goto done;
    source_leaf = &source.components[source.count - 1];
    if (getrlimit(RLIMIT_FSIZE, &file_limit) != 0) {
        *error = "cannot inspect inherited file-size limit";
        goto done;
    }
    if (file_limit.rlim_cur != RLIM_INFINITY &&
        file_limit.rlim_cur < (rlim_t)source_leaf->identity.st_size) {
        *error = "inherited file-size limit is below reviewed updater size";
        goto done;
    }
    if (!require_macho_role(source_leaf->descriptor, &source_leaf->identity,
                            NULL, error)) goto done;
    if (fstatat(parent_fd, UPDATER_NAME, &named, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!preflight_install_self(parent_fd, expected, 1, error)) goto done;
        if (!open_leaf_at(parent_fd, UPDATER_NAME, &installed, 0555, 0, error) ||
            !secure_equal(installed.digest, expected)) {
            *error = "installed updater is not the owner-selected immutable byte set";
            goto done;
        }
        test_pause();
        if ((((unsigned int)installed.identity.st_flags) &
             WINS_IMMUTABLE_FLAG) == 0U) {
            if (fchflags(installed.descriptor,
                         installed.identity.st_flags | WINS_IMMUTABLE_FLAG) != 0 ||
                !sync_file(installed.descriptor, error)) {
                if (*error == NULL) *error = "cannot repair exact updater seal";
                goto done;
            }
        }
        if (!validate_leaf_at(parent_fd, UPDATER_NAME, &installed,
                              0555, 1, error) ||
            !secure_equal(installed.digest, expected)) {
            if (*error == NULL) *error = "cannot repair exact updater seal";
            goto done;
        }
        printf("ReleasePython owner updater: exact updater already installed\n");
        close_retained_path(&source);
        close_leaf(&installed);
        return 1;
    }
    if (errno != ENOENT) {
        *error = "cannot inspect fixed updater path";
        goto done;
    }
    if (!preflight_install_self(parent_fd, expected, 0, error)) goto done;
    {
        int length = snprintf(stage_name, sizeof(stage_name), "%s%.32s",
                              INSTALL_PREFIX, expected);
        if (length <= 0 || (size_t)length >= sizeof(stage_name)) {
            *error = "cannot derive exclusive updater install stage";
            goto done;
        }
    }
    if (!reap_install_stage(parent_fd, stage_name, error)) {
        goto done;
    }
    stage_fd = openat(parent_fd, stage_name,
                      O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                      0600);
    if (stage_fd < 0) {
        *error = "cannot create exclusive updater install stage";
        goto done;
    }
    if (!copy_exact(source_leaf->descriptor, stage_fd, source_leaf->identity.st_size,
                    expected, error) ||
        !validate_retained_path(&source, 1, expected, error)) {
        goto done;
    }
    installed.descriptor = stage_fd;
    stage_fd = -1;
    if (!validate_leaf_at(parent_fd, stage_name, &installed, 0555, 0, error) ||
        installed.identity.st_flags != 0 ||
        renameatx_np(parent_fd, stage_name, parent_fd, UPDATER_NAME,
                     RENAME_EXCL) != 0 || fsync(parent_fd) != 0 ||
        !validate_leaf_at(parent_fd, UPDATER_NAME, &installed, 0555, 0, error) ||
        !secure_equal(installed.digest, expected)) {
        if (*error == NULL) *error = "cannot publish exact updater bytes";
        goto done;
    }
    test_crash(30);
    if (fchflags(installed.descriptor,
                 installed.identity.st_flags | WINS_IMMUTABLE_FLAG) != 0 ||
        !sync_file(installed.descriptor, error) ||
        !validate_leaf_at(parent_fd, UPDATER_NAME, &installed, 0555, 1, error) ||
        !secure_equal(installed.digest, expected) ||
        !validate_retained_path(&source, 1, expected, error)) {
        if (*error == NULL) *error = "cannot install exact immutable updater";
        goto done;
    }
    printf("ReleasePython owner updater: installed exact immutable updater\n");
    close_retained_path(&source);
    close_leaf(&installed);
    return 1;
done:
    {
        const char *primary =
            *error == NULL ? "cannot install exact immutable updater" : *error;
        const char *cleanup_error = NULL;
        if (stage_fd >= 0) close(stage_fd);
        if (stage_name[0] != '\0' &&
            !reap_install_stage(parent_fd, stage_name, &cleanup_error)) {
            *error = cleanup_error;
        } else {
            *error = primary;
        }
    }
    close_leaf(&installed);
    close_retained_path(&source);
    return 0;
}

static void fail(const char *message) {
    fprintf(stderr, "ReleasePython owner updater: %s\n",
            message == NULL ? "unspecified refusal" : message);
    exit(126);
}

static void fail_errno(const char *message) {
    int saved = errno;
    fprintf(stderr, "ReleasePython owner updater: %s: %s\n",
            message == NULL ? "unspecified refusal" : message,
            strerror(saved));
    exit(126);
}

int main(int argc, char **argv) {
    const char *error = NULL;
    char process_path[PROC_PIDPATHINFO_MAXSIZE];
    retained_path self;
    retained_path destination;
    retained_sources sources;
    update_context context;
    pair_state state;
    struct rlimit file_limit;
    int install_action;
    int update_with_sources;

    memset(&self, 0, sizeof(self));
    memset(&destination, 0, sizeof(destination));
    memset(&sources, 0, sizeof(sources));
    sources.queue = -1;
    context_init(&context);
    (void)build_evidence;
    if (strcmp(WINS_UPDATER_PATH,
               WINS_DESTINATION_PARENT "/" UPDATER_NAME) != 0) {
        fail("compiled updater path does not match the fixed destination parent");
    }
    if (!valid_digest(WINS_OLD_CONTROLLER_SHA256) ||
        !valid_digest(WINS_OLD_LAUNCHER_SHA256) ||
        !valid_digest(WINS_NEW_CONTROLLER_SHA256) ||
        !valid_digest(WINS_NEW_LAUNCHER_SHA256) ||
        secure_equal(WINS_OLD_CONTROLLER_SHA256, WINS_NEW_CONTROLLER_SHA256) ||
        secure_equal(WINS_OLD_LAUNCHER_SHA256, WINS_NEW_LAUNCHER_SHA256)) {
        fail("compiled transition digests are invalid or not distinct");
    }
    install_action = argc == 4 && strcmp(argv[1], "install-self") == 0;
    update_with_sources = argc == 4 && strcmp(argv[1], "update") == 0;
    if (!install_action && !update_with_sources &&
        !(argc == 2 && (strcmp(argv[1], "update") == 0 ||
                        strcmp(argv[1], "revert") == 0 ||
                        strcmp(argv[1], "status") == 0 ||
                        strcmp(argv[1], "discard") == 0))) {
        fail("argv must be install-self ABSOLUTE_UPDATER UPDATER_SHA256, "
             "update [ABSOLUTE_CONTROLLER ABSOLUTE_LAUNCHER], revert, "
             "discard, or status");
    }
    if (!ensure_standard_descriptors(&error) || !exact_environment(&error)) {
        fail(error);
    }
#if WINS_REQUIRE_ROOT
    if (getuid() != 0 || geteuid() != 0 || getegid() != 0) {
        fail("real/effective uid and effective gid must be exact root:wheel");
    }
#else
    if (getuid() != (uid_t)WINS_EXPECTED_UID ||
        geteuid() != (uid_t)WINS_EXPECTED_UID) {
        fail("real and effective uid are not the test-selected owner");
    }
#endif
    umask(077);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGXFSZ, SIG_IGN);
    if (getrlimit(RLIMIT_FSIZE, &file_limit) != 0) {
        fail_errno("cannot inspect inherited file-size limit");
    }
    if (!open_retained_path(WINS_DESTINATION_PARENT, 1, &destination, &error) ||
        !validate_secure_ancestry(&destination, 0, &error) ||
        !validate_retained_path(&destination, 0, NULL, &error)) fail(error);
    context.parent_fd =
        destination.components[destination.count - 1].descriptor;
    if (!acquire_authority_lock(context.parent_fd, &error) ||
        !refuse_pending_provision_transaction(context.parent_fd, &error)) {
        fail(error);
    }
    if (install_action) {
        if (!install_self(argv[2], argv[3], &destination, &error)) fail(error);
        close_retained_path(&destination);
        return 0;
    }
    if (proc_pidpath(getpid(), process_path, sizeof(process_path)) <= 0 ||
        !secure_equal(process_path, WINS_UPDATER_PATH)) {
        fail("running updater path is not the reviewed fixed path");
    }
    if (!open_retained_path(WINS_UPDATER_PATH, 0, &self, &error) ||
        !validate_secure_ancestry(&self, 1, &error) ||
        !validate_retained_path(&self, 0, NULL, &error)) fail(error);
    hash_fd(self.components[self.count - 1].descriptor, context.self_sha256);
    if (!derive_stage_name(context.stage_name) ||
        !derive_cleanup_name(context.cleanup_name)) {
        fail("cannot derive the fixed transition residue names");
    }
    if (!require_rename_swap_capability(context.parent_fd, &error) ||
        !load_context(&context, &error) ||
        !validate_authority_witness(&context, &error)) fail(error);
    state = classify_state(&context, &error);
    if (state == STATE_UNRECOGNIZED) {
        fprintf(stderr,
                "ReleasePython owner updater: state=UNRECOGNIZED "
                "controller=%s launcher=%s stage=%s\n",
                context.destination_controller.digest,
                context.destination_launcher.digest, context.stage_name);
        fail(error);
    }
    if (strcmp(argv[1], "status") == 0) {
        if (context.journal_invalid) {
            fail("invalid update journal requires explicit discard in a terminal pair state");
        }
        printf("ReleasePython owner updater: state=%s controller=%s launcher=%s "
               "stage_residue=%s journal_valid=%s\n",
               state_name(state), context.destination_controller.digest,
               context.destination_launcher.digest,
               context.stage_is_residue ? "yes" : "no",
               context.journal_valid ? "yes" : "no");
        context_close(&context);
        close_retained_path(&self);
        close_retained_path(&destination);
        return 0;
    }
    if (strcmp(argv[1], "revert") == 0 && state == STATE_COMMITTED) {
        fail("revert refuses after verified rollback custody was committed");
    }
    if (strcmp(argv[1], "discard") == 0) {
        if ((context.stage_exists || context.cleanup_exists) &&
            !context.stage_is_residue) {
            fail("discard refuses a complete transition; use update or revert");
        }
        if (context.stage_exists || context.cleanup_exists) {
            if (!discard_stage_residue(&context, &error)) fail(error);
            printf("ReleasePython owner updater: discarded bounded terminal residue\n");
        } else {
            printf("ReleasePython owner updater: no bounded terminal residue present\n");
        }
        context_close(&context);
        close_retained_path(&self);
        close_retained_path(&destination);
        return 0;
    }
    if (context.stage_is_residue) {
        if (context.journal_invalid) {
            fail("invalid update journal requires explicit discard in a terminal pair state");
        }
        if (!discard_stage_residue(&context, &error)) fail(error);
    } else if (!discard_journal_next(&context, &error)) {
        fail(error);
    }
    if (strcmp(argv[1], "revert") == 0) {
        if (state == STATE_CLEAN) {
            printf("ReleasePython owner updater: exact old pair already restored\n");
        } else {
            if (!advance_revert(&context, state, &error) ||
                !remove_transaction(&context, STATE_CLEAN, &error)) fail(error);
            printf("ReleasePython owner updater: restored exact old pair\n");
        }
        context_close(&context);
        close_retained_path(&self);
        close_retained_path(&destination);
        return 0;
    }
    if (state == STATE_COMMITTED) {
        printf("ReleasePython owner updater: exact new pair already committed\n");
        context_close(&context);
        close_retained_path(&self);
        close_retained_path(&destination);
        return 0;
    }
    if (state == STATE_CLEAN) {
        if (!update_with_sources) {
            fail("clean-state update requires ABSOLUTE_CONTROLLER and ABSOLUTE_LAUNCHER");
        }
        if (!safe_absolute_path(argv[2]) || !safe_absolute_path(argv[3]) ||
            strcmp(argv[2], argv[3]) == 0 ||
            path_is_under_destination(argv[2]) ||
            path_is_under_destination(argv[3]) ||
            !open_retained_path(argv[2], 0, &sources.controller, &error) ||
            !open_retained_path(argv[3], 0, &sources.launcher, &error) ||
            !require_source_leaf(&sources.controller,
                                 WINS_NEW_CONTROLLER_SHA256, &error) ||
            !require_source_leaf(&sources.launcher,
                                 WINS_NEW_LAUNCHER_SHA256, &error)) fail(error);
        {
            retained_component *controller =
                &sources.controller.components[sources.controller.count - 1];
            retained_component *launcher =
                &sources.launcher.components[sources.launcher.count - 1];
            if (same_vnode(&controller->identity, &launcher->identity)) {
                fail("controller and launcher sources resolve to one vnode");
            }
            if (!require_controller_role(controller->descriptor,
                                         &controller->identity, &error) ||
                !require_macho_role(launcher->descriptor, &launcher->identity,
                                    WINS_NEW_CONTROLLER_SHA256, &error) ||
                !arm_sources(&sources, &error) ||
                !validate_sources(&sources, &error)) fail(error);
            if (file_limit.rlim_cur != RLIM_INFINITY &&
                (file_limit.rlim_cur < (rlim_t)controller->identity.st_size ||
                 file_limit.rlim_cur < (rlim_t)launcher->identity.st_size)) {
                fail("inherited file-size limit is below reviewed input size");
            }
            if (!require_pair_digest(&context.destination_controller,
                                     &context.destination_launcher,
                                     WINS_OLD_CONTROLLER_SHA256,
                                     WINS_OLD_LAUNCHER_SHA256, &error) ||
                !arm_update(&context, &sources, &error)) fail(error);
        }
        state = STATE_ARMED;
    } else if (update_with_sources) {
        fail("recovery update accepts no source paths after the journal exists");
    }
    if (!advance_forward(&context, state, &error) ||
        !remove_transaction(&context, STATE_COMMITTED, &error)) fail(error);
    printf("ReleasePython owner updater: committed exact new controller/launcher pair\n");
    if (sources.queue >= 0) close(sources.queue);
    close_retained_path(&sources.launcher);
    close_retained_path(&sources.controller);
    context_close(&context);
    close_retained_path(&self);
    close_retained_path(&destination);
    return 0;
}
