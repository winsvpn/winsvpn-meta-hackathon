#define _DARWIN_C_SOURCE 1

#include <errno.h>
#include <dirent.h>
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
#include <sys/event.h>
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

#ifndef WINS_BOOTSTRAP_PATH
#define WINS_BOOTSTRAP_PATH \
    "/Library/WinsVPN/ReleasePythonAuthority/v2/owner-installer-bootstrap"
#endif
#ifndef WINS_DESTINATION_PARENT
#define WINS_DESTINATION_PARENT "/Library/WinsVPN/ReleasePythonAuthority/v2"
#endif
#ifndef WINS_CONTROLLER_DESTINATION_NAME
#define WINS_CONTROLLER_DESTINATION_NAME "owner-provision"
#endif
#ifndef WINS_LAUNCHER_DESTINATION_NAME
#define WINS_LAUNCHER_DESTINATION_NAME "owner-launcher"
#endif
#define WINS_BOOTSTRAP_DESTINATION_NAME "owner-installer-bootstrap"
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

#define MAX_COMPONENTS 64U
#define MAX_INPUT_BYTES ((uint64_t)128 * 1024 * 1024)
#define MAX_LOAD_COMMANDS 8192U
#define STAGE_PREFIX ".winsvpn-owner-bootstrap-stage-"
#define INSTALL_SELF_PREFIX ".winsvpn-owner-bootstrap-install-"
#define CONTROLLER_HEADER \
    "#!/usr/bin/env python3\n\"\"\"Fixed external owner boundary for ReleasePython receipt migration.\n"

extern char **environ;

__attribute__((used)) static const char build_evidence[] =
    WINS_BUILD_SOURCE_SHA256 ":" WINS_BUILD_SCRIPT_SHA256 ":"
    WINS_BUILD_COMPILER_SHA256 ":" WINS_BUILD_LINKER_SHA256 ":"
    WINS_BUILD_CODESIGN_SHA256 ":" WINS_BUILD_INPUT_CLOSURE_SHA256;

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
    char digest[65];
} retained_path;

typedef struct {
    retained_path controller;
    retained_path launcher;
    int queue;
} retained_sources;

typedef struct {
    int parent_fd;
    int stage_fd;
    int controller_fd;
    int launcher_fd;
    struct stat controller_identity;
    struct stat launcher_identity;
    char stage_name[NAME_MAX + 1];
    int stage_created;
    int controller_stage_created;
    int launcher_stage_created;
    int controller_published;
    int launcher_published;
    int controller_sealed;
    int launcher_sealed;
    int cleanup_enabled;
} install_transaction;

static install_transaction transaction = {
    .parent_fd = -1,
    .stage_fd = -1,
    .controller_fd = -1,
    .launcher_fd = -1,
};

static void fail(const char *message);
static void fail_errno(const char *message);
static int same_vnode(const struct stat *left, const struct stat *right);

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

static int same_directory_identity(const struct stat *left,
                                   const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
           left->st_mode == right->st_mode && left->st_uid == right->st_uid &&
           left->st_gid == right->st_gid && left->st_flags == right->st_flags;
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

static int same_vnode(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
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
    if (strlen(path) < length) return 0;
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
    path->components[0].leaf = 0;
    path->count = 1;
    cursor = copy;
    while (*cursor != '\0') {
        char *slash = strchr(cursor, '/');
        int final = slash == NULL;
        int flags;
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
        flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC;
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
            !same_leaf_identity(&named, &retained)) {
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
            if (!S_ISREG(info->st_mode) || info->st_uid != (uid_t)WINS_EXPECTED_UID ||
                info->st_gid != (gid_t)WINS_EXPECTED_GID ||
                (info->st_mode & 07777) != 0555 || info->st_nlink != 1) {
                *error = "installed bootstrap custody is not exact";
                return 0;
            }
#if WINS_REQUIRE_SELF_IMMUTABLE
            if ((((unsigned int)info->st_flags) & WINS_IMMUTABLE_FLAG) == 0U) {
                *error = "installed bootstrap is not system immutable";
                return 0;
            }
#endif
        }
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

static int validate_sources(retained_sources *sources, const char *controller_hash,
                            const char *launcher_hash, const char **error) {
    struct timespec zero = {0, 0};
    struct kevent event;
    if (kevent(sources->queue, NULL, 0, &event, 1, &zero) > 0) {
        *error = "reviewed source changed while retained";
        return 0;
    }
    if (!validate_retained_path(&sources->controller, 1, controller_hash, error) ||
        !validate_retained_path(&sources->launcher, 1, launcher_hash, error)) {
        return 0;
    }
    if (kevent(sources->queue, NULL, 0, &event, 1, &zero) > 0) {
        *error = "reviewed source changed during revalidation";
        return 0;
    }
    return 1;
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
    if ((uint64_t)info->st_size < header_length) {
        *error = "controller source is too short for its fixed role header";
        return 0;
    }
    if (pread(descriptor, buffer, header_length, 0) != (ssize_t)header_length ||
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
            unsigned char value = buffer[index];
            if (value == 0 || value > 0x7fU) {
                *error = "controller source is not exact NUL-free ASCII";
                return 0;
            }
        }
        offset += count;
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

static int require_launcher_role(int descriptor, const struct stat *info,
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
        *error = "launcher source is not exact thin arm64 MH_EXECUTE";
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
            *error = "launcher Mach-O load command is malformed";
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
                *error = "launcher Mach-O code signature command is invalid";
                return 0;
            }
            ++signatures;
        }
        offset += command.cmdsize;
    }
    if ((uint64_t)offset != limit) {
        *error = "launcher Mach-O load-command size is inconsistent";
        return 0;
    }
    if (signatures != 1) {
        *error = "launcher Mach-O must contain exactly one code signature";
        return 0;
    }
    if (!fd_contains_text(descriptor, info->st_size, controller_hash)) {
        *error = "launcher bytes do not bind the selected controller SHA-256";
        return 0;
    }
    return 1;
}

static int require_bootstrap_role(int descriptor, const struct stat *info,
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
        *error = "bootstrap source is not exact thin arm64 MH_EXECUTE";
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
            *error = "bootstrap Mach-O load command is malformed";
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
                *error = "bootstrap Mach-O code signature command is invalid";
                return 0;
            }
            ++signatures;
        }
        offset += command.cmdsize;
    }
    if ((uint64_t)offset != limit || signatures != 1) {
        *error = "bootstrap Mach-O signature structure is not exact";
        return 0;
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

static int ensure_standard_descriptors(const char **error) {
    int descriptor;
    for (descriptor = 0; descriptor <= 2; ++descriptor) {
        if (fcntl(descriptor, F_GETFD) < 0 && errno == EBADF) {
            int replacement = open("/dev/null", descriptor == 0 ? O_RDONLY : O_WRONLY);
            if (replacement < 0 || replacement != descriptor) {
                if (replacement >= 0) close(replacement);
                *error = "cannot normalize standard descriptors";
                return 0;
            }
        }
    }
    return 1;
}

static int sync_file(int descriptor, const char **error) {
    if (fsync(descriptor) != 0 || fcntl(descriptor, F_FULLFSYNC) != 0) {
        *error = "cannot fully synchronize installed file";
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
                *error = "cannot write private install stage";
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

static int validate_installed_fd(int descriptor, int parent_fd, const char *name,
                                 const char *expected, int require_immutable,
                                 struct stat *identity, const char **error) {
    struct stat retained, named;
    char digest[65];
    if (fstat(descriptor, &retained) != 0 ||
        fstatat(parent_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_vnode(&retained, &named) || !S_ISREG(retained.st_mode) ||
        retained.st_uid != (uid_t)WINS_EXPECTED_UID ||
        retained.st_gid != (gid_t)WINS_EXPECTED_GID ||
        (retained.st_mode & 07777) != 0555 || retained.st_nlink != 1 ||
        !has_empty_acl(descriptor)) {
        *error = "installed leaf custody or pathname identity is invalid";
        return 0;
    }
    if ((((unsigned int)retained.st_flags) & ~WINS_IMMUTABLE_FLAG) != 0U ||
        (require_immutable &&
         (((unsigned int)retained.st_flags) & WINS_IMMUTABLE_FLAG) == 0U)) {
        *error = "installed leaf flags are not exact";
        return 0;
    }
    hash_fd(descriptor, digest);
    if (!secure_equal(digest, expected)) {
        *error = "installed leaf digest is not the owner-selected digest";
        return 0;
    }
    if (identity != NULL) *identity = retained;
    return 1;
}

static int open_existing_leaf(int parent_fd, const char *name,
                              const char *expected, int *descriptor,
                              struct stat *identity, const char **error) {
    struct stat named;
    int opened;
    if (fstatat(parent_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) {
            *descriptor = -1;
            return 1;
        }
        *error = "cannot inspect fixed destination leaf";
        return 0;
    }
    if (!S_ISREG(named.st_mode)) {
        *error = "fixed destination is not a regular file";
        return 0;
    }
    opened = openat(parent_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (opened < 0 ||
        !validate_installed_fd(opened, parent_fd, name, expected, 0,
                               identity, error)) {
        if (opened >= 0) close(opened);
        return 0;
    }
    *descriptor = opened;
    return 1;
}

static int stage_pair_name(const char *controller_hash, const char *launcher_hash,
                           char output[NAME_MAX + 1]) {
    sha256_context context;
    unsigned char digest[32];
    char encoded[65];
    sha256_init(&context);
    sha256_update(&context, (const unsigned char *)controller_hash, 64);
    sha256_update(&context, (const unsigned char *)launcher_hash, 64);
    sha256_final(&context, digest);
    hex_encode(digest, sizeof(digest), encoded);
    return snprintf(output, NAME_MAX + 1, "%s%.32s", STAGE_PREFIX, encoded) > 0;
}

static int open_stage_directory(int parent_fd, const char *name,
                                int *created, const char **error) {
    int descriptor;
    struct stat info;
    *created = 0;
    if (mkdirat(parent_fd, name, 0700) == 0) *created = 1;
    else if (errno != EEXIST) {
        *error = "cannot create private pair stage";
        return -1;
    }
    descriptor = openat(parent_fd, name,
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0 || fstat(descriptor, &info) != 0 ||
        !S_ISDIR(info.st_mode) || info.st_uid != (uid_t)WINS_EXPECTED_UID ||
        info.st_gid != (gid_t)WINS_EXPECTED_GID ||
        (info.st_mode & 07777) != 0700 || info.st_flags != 0 ||
        !has_empty_acl(descriptor)) {
        if (descriptor >= 0) close(descriptor);
        *error = "private pair stage custody is invalid";
        return -1;
    }
    {
        int duplicate = dup(descriptor);
        DIR *directory;
        struct dirent *entry;
        if (duplicate < 0 || (directory = fdopendir(duplicate)) == NULL) {
            if (duplicate >= 0) close(duplicate);
            close(descriptor);
            *error = "cannot enumerate private pair stage";
            return -1;
        }
        while ((entry = readdir(directory)) != NULL) {
            if (strcmp(entry->d_name, ".") != 0 &&
                strcmp(entry->d_name, "..") != 0 &&
                strcmp(entry->d_name, WINS_CONTROLLER_DESTINATION_NAME) != 0 &&
                strcmp(entry->d_name, WINS_LAUNCHER_DESTINATION_NAME) != 0) {
                closedir(directory);
                close(descriptor);
                *error = "private pair stage contains an unexpected entry";
                return -1;
            }
        }
        closedir(directory);
    }
    return descriptor;
}

static void unlink_if_same_unsealed(int parent_fd, const char *name,
                                    int descriptor, int flags) {
    struct stat retained, named;
    if (descriptor >= 0 && fstat(descriptor, &retained) == 0 &&
        fstatat(parent_fd, name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        same_vnode(&retained, &named) &&
        (((unsigned int)retained.st_flags) & WINS_IMMUTABLE_FLAG) == 0U) {
        unlinkat(parent_fd, name, flags);
    }
}

static int prepare_stage_leaf(int stage_fd, const char *name, int source_fd,
                              const struct stat *source_info,
                              const char *expected, int *created,
                              const char **error) {
    int descriptor;
    struct stat named;
    *created = 0;
    if (fstatat(stage_fd, name, &named, AT_SYMLINK_NOFOLLOW) == 0) {
        struct stat retained_identity;
        descriptor = openat(stage_fd, name,
                            O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (descriptor < 0 ||
            !validate_installed_fd(descriptor, stage_fd, name, expected, 0,
                                   &retained_identity, error) ||
            retained_identity.st_flags != 0) {
            if (descriptor >= 0) close(descriptor);
            *error = "pre-existing pair stage leaf is not an exact retry";
            return -1;
        }
        return descriptor;
    }
    if (errno != ENOENT) {
        *error = "cannot inspect private pair stage leaf";
        return -1;
    }
    descriptor = openat(stage_fd, name,
                        O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                        0600);
    if (descriptor < 0) {
        *error = "cannot create exclusive pair stage leaf";
        return -1;
    }
    *created = 1;
    if (!copy_exact(source_fd, descriptor, source_info->st_size, expected,
                    error)) {
        unlink_if_same_unsealed(stage_fd, name, descriptor, 0);
        *created = 0;
        close(descriptor);
        return -1;
    }
    return descriptor;
}

static void cleanup_current(void) {
    if (!transaction.cleanup_enabled || transaction.parent_fd < 0) return;
    if (transaction.launcher_published && !transaction.launcher_sealed &&
        transaction.launcher_fd >= 0) {
        unlink_if_same_unsealed(transaction.parent_fd,
                                WINS_LAUNCHER_DESTINATION_NAME,
                                transaction.launcher_fd, 0);
    }
    if (transaction.controller_published && !transaction.controller_sealed &&
        transaction.controller_fd >= 0) {
        unlink_if_same_unsealed(transaction.parent_fd,
                                WINS_CONTROLLER_DESTINATION_NAME,
                                transaction.controller_fd, 0);
    }
    if (transaction.stage_fd >= 0) {
        if (transaction.launcher_stage_created) {
            unlink_if_same_unsealed(transaction.stage_fd,
                                    WINS_LAUNCHER_DESTINATION_NAME,
                                    transaction.launcher_fd, 0);
        }
        if (transaction.controller_stage_created) {
            unlink_if_same_unsealed(transaction.stage_fd,
                                    WINS_CONTROLLER_DESTINATION_NAME,
                                    transaction.controller_fd, 0);
        }
    }
    if (transaction.stage_created && transaction.stage_name[0] != '\0') {
        unlink_if_same_unsealed(transaction.parent_fd, transaction.stage_name,
                                transaction.stage_fd, AT_REMOVEDIR);
    }
    fsync(transaction.parent_fd);
}

static void fail(const char *message) {
    cleanup_current();
    fprintf(stderr, "ReleasePython owner bootstrap: %s\n", message);
    exit(126);
}

static void fail_errno(const char *message) {
    int saved = errno;
    cleanup_current();
    fprintf(stderr, "ReleasePython owner bootstrap: %s: %s\n",
            message, strerror(saved));
    exit(126);
}

static void test_pause(void) {
#ifdef WINS_TEST_HOOK_PATH
    char release_path[PATH_MAX];
    struct timespec delay = {0, 10000000};
    if (snprintf(release_path, sizeof(release_path), "%s.release",
                 WINS_TEST_HOOK_PATH) <= 0) {
        fail("test hook path is invalid");
    }
    printf("TEST_HOOK_READY\n");
    fflush(stdout);
    while (access(release_path, F_OK) != 0) nanosleep(&delay, NULL);
#endif
}

static int install_self_arguments(int argc, char **argv) {
    return argc == 4 && strcmp(argv[1], "install-self") == 0 &&
           safe_absolute_path(argv[2]) && valid_digest(argv[3]) &&
           !path_is_under_destination(argv[2]);
}

static void require_arguments(int argc, char **argv) {
    if (install_self_arguments(argc, argv)) return;
    if (argc != 6 || strcmp(argv[1], "install") != 0 ||
        !safe_absolute_path(argv[2]) || !valid_digest(argv[3]) ||
        !safe_absolute_path(argv[4]) || !valid_digest(argv[5]) ||
        strcmp(argv[2], argv[4]) == 0 || secure_equal(argv[3], argv[5]) ||
        path_is_under_destination(argv[2]) ||
        path_is_under_destination(argv[4])) {
        fail("argv must be exactly: install-self ABSOLUTE_BOOTSTRAP "
             "BOOTSTRAP_SHA256, or install ABSOLUTE_CONTROLLER "
             "CONTROLLER_SHA256 ABSOLUTE_LAUNCHER LAUNCHER_SHA256");
    }
}

static int reap_install_self_stage(int parent_fd, const char *name,
                                   const char **error) {
    struct stat named, retained;
    int descriptor;
    if (fstatat(parent_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) return 1;
        *error = "cannot inspect bounded bootstrap install residue";
        return 0;
    }
    descriptor = openat(parent_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0 || fstat(descriptor, &retained) != 0 ||
        !same_vnode(&named, &retained) || !S_ISREG(retained.st_mode) ||
        retained.st_uid != (uid_t)WINS_EXPECTED_UID ||
        retained.st_gid != (gid_t)WINS_EXPECTED_GID ||
        retained.st_nlink != 1 || retained.st_flags != 0 ||
        ((retained.st_mode & 07777) != 0600 &&
         (retained.st_mode & 07777) != 0555) ||
        !has_empty_acl(descriptor)) {
        if (descriptor >= 0) close(descriptor);
        *error = "bounded bootstrap install residue custody is invalid";
        return 0;
    }
    close(descriptor);
    if (unlinkat(parent_fd, name, 0) != 0 || fsync(parent_fd) != 0) {
        *error = "cannot reap bounded bootstrap install residue";
        return 0;
    }
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
    struct stat named, installed_identity;
    int stage_fd = -1;
    int installed_fd = -1;
    int published = 0;
    memset(&source, 0, sizeof(source));
    if (proc_pidpath(getpid(), process_path, sizeof(process_path)) <= 0 ||
        !secure_equal(process_path, source_path)) {
        *error = "install-self requires the executing absolute bootstrap and digest";
        return 0;
    }
    if (!open_retained_path(source_path, 0, &source, error) ||
        !require_source_leaf(&source, expected, error) ||
        !validate_retained_path(&source, 1, expected, error)) goto done;
    source_leaf = &source.components[source.count - 1];
    if (!require_bootstrap_role(source_leaf->descriptor, &source_leaf->identity,
                                error)) goto done;
    if (getrlimit(RLIMIT_FSIZE, &file_limit) != 0 ||
        (file_limit.rlim_cur != RLIM_INFINITY &&
         file_limit.rlim_cur < (rlim_t)source_leaf->identity.st_size)) {
        *error = "inherited file-size limit is below reviewed bootstrap size";
        goto done;
    }
    if (fstatat(parent_fd, WINS_BOOTSTRAP_DESTINATION_NAME, &named,
                AT_SYMLINK_NOFOLLOW) == 0) {
        installed_fd = openat(parent_fd, WINS_BOOTSTRAP_DESTINATION_NAME,
                              O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (installed_fd < 0 ||
            !validate_installed_fd(installed_fd, parent_fd,
                                   WINS_BOOTSTRAP_DESTINATION_NAME, expected, 0,
                                   &installed_identity, error)) goto done;
        if ((((unsigned int)installed_identity.st_flags) &
             WINS_IMMUTABLE_FLAG) == 0U) {
            if (fchflags(installed_fd,
                         installed_identity.st_flags | WINS_IMMUTABLE_FLAG) != 0 ||
                !sync_file(installed_fd, error)) {
                if (*error == NULL) *error = "cannot seal exact bootstrap retry";
                goto done;
            }
        }
        if (!validate_installed_fd(installed_fd, parent_fd,
                                   WINS_BOOTSTRAP_DESTINATION_NAME, expected, 1,
                                   NULL, error)) goto done;
        printf("ReleasePython owner bootstrap: exact bootstrap already installed\n");
        close(installed_fd);
        close_retained_path(&source);
        return 1;
    }
    if (errno != ENOENT) {
        *error = "cannot inspect fixed bootstrap path";
        goto done;
    }
    if (snprintf(stage_name, sizeof(stage_name), "%s%.32s",
                 INSTALL_SELF_PREFIX, expected) <= 0 ||
        !reap_install_self_stage(parent_fd, stage_name, error)) goto done;
    stage_fd = openat(parent_fd, stage_name,
                      O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (stage_fd < 0 ||
        !copy_exact(source_leaf->descriptor, stage_fd,
                    source_leaf->identity.st_size, expected, error) ||
        !validate_retained_path(&source, 1, expected, error)) {
        if (*error == NULL) *error = "cannot create exact bootstrap install stage";
        goto done;
    }
    installed_fd = stage_fd;
    stage_fd = -1;
    if (!validate_installed_fd(installed_fd, parent_fd, stage_name, expected, 0,
                               &installed_identity, error) ||
        installed_identity.st_flags != 0 ||
        renameatx_np(parent_fd, stage_name, parent_fd,
                     WINS_BOOTSTRAP_DESTINATION_NAME, RENAME_EXCL) != 0 ||
        fsync(parent_fd) != 0) {
        if (*error == NULL) *error = "cannot exclusively publish exact bootstrap";
        goto done;
    }
    published = 1;
    stage_name[0] = '\0';
    if (!validate_installed_fd(installed_fd, parent_fd,
                               WINS_BOOTSTRAP_DESTINATION_NAME, expected, 0,
                               &installed_identity, error) ||
        fchflags(installed_fd,
                 installed_identity.st_flags | WINS_IMMUTABLE_FLAG) != 0 ||
        !sync_file(installed_fd, error) ||
        !validate_installed_fd(installed_fd, parent_fd,
                               WINS_BOOTSTRAP_DESTINATION_NAME, expected, 1,
                               NULL, error) ||
        !validate_retained_path(&source, 1, expected, error)) {
        if (*error == NULL) *error = "cannot install exact immutable bootstrap";
        goto done;
    }
    printf("ReleasePython owner bootstrap: installed exact immutable bootstrap\n");
    close(installed_fd);
    close_retained_path(&source);
    return 1;
done:
    if (stage_fd >= 0) close(stage_fd);
    if (installed_fd >= 0) close(installed_fd);
    if (!published && stage_name[0] != '\0') {
        const char *cleanup_error = NULL;
        if (!reap_install_self_stage(parent_fd, stage_name, &cleanup_error)) {
            *error = cleanup_error;
        }
    }
    close_retained_path(&source);
    return 0;
}

static void install_pair(retained_sources *sources, retained_path *destination,
                         const char *controller_hash,
                         const char *launcher_hash) {
    const char *error = NULL;
    retained_component *parent_component =
        &destination->components[destination->count - 1];
    int parent_fd = parent_component->descriptor;
    int controller_existed;
    int launcher_existed;
    struct stat controller_source =
        sources->controller.components[sources->controller.count - 1].identity;
    struct stat launcher_source =
        sources->launcher.components[sources->launcher.count - 1].identity;
    struct stat stage_named;

    transaction.parent_fd = parent_fd;
    if (!open_existing_leaf(parent_fd, WINS_CONTROLLER_DESTINATION_NAME,
                            controller_hash, &transaction.controller_fd,
                            &transaction.controller_identity, &error) ||
        !open_existing_leaf(parent_fd, WINS_LAUNCHER_DESTINATION_NAME,
                            launcher_hash, &transaction.launcher_fd,
                            &transaction.launcher_identity, &error)) {
        fail(error);
    }
    controller_existed = transaction.controller_fd >= 0;
    launcher_existed = transaction.launcher_fd >= 0;
    if (controller_existed && launcher_existed &&
        (((unsigned int)transaction.controller_identity.st_flags) &
             WINS_IMMUTABLE_FLAG) != 0U &&
        (((unsigned int)transaction.launcher_identity.st_flags) &
             WINS_IMMUTABLE_FLAG) != 0U) {
        if (!validate_sources(sources, controller_hash, launcher_hash, &error) ||
            !validate_retained_path(destination, 0, NULL, &error)) {
            fail(error);
        }
        printf("ReleasePython owner bootstrap: exact controller/launcher pair already installed\n");
        return;
    }

    if (!validate_sources(sources, controller_hash, launcher_hash, &error)) {
        fail(error);
    }
    if (!validate_retained_path(destination, 0, NULL, &error)) fail(error);
    if (!stage_pair_name(controller_hash, launcher_hash, transaction.stage_name)) {
        fail("cannot derive private pair stage name");
    }
    transaction.stage_fd = open_stage_directory(
        parent_fd, transaction.stage_name, &transaction.stage_created, &error);
    if (transaction.stage_fd < 0) fail(error);
    transaction.cleanup_enabled = 1;
    if (!validate_sources(sources, controller_hash, launcher_hash, &error) ||
        !validate_retained_path(destination, 0, NULL, &error)) {
        fail(error);
    }

    if (!controller_existed) {
        transaction.controller_fd = prepare_stage_leaf(
            transaction.stage_fd, WINS_CONTROLLER_DESTINATION_NAME,
            sources->controller.components[sources->controller.count - 1].descriptor,
            &controller_source, controller_hash,
            &transaction.controller_stage_created, &error);
        if (transaction.controller_fd < 0) fail(error);
    }
    if (!validate_sources(sources, controller_hash, launcher_hash, &error) ||
        !validate_retained_path(destination, 0, NULL, &error)) {
        fail(error);
    }
    if (!launcher_existed) {
        transaction.launcher_fd = prepare_stage_leaf(
            transaction.stage_fd, WINS_LAUNCHER_DESTINATION_NAME,
            sources->launcher.components[sources->launcher.count - 1].descriptor,
            &launcher_source, launcher_hash,
            &transaction.launcher_stage_created, &error);
        if (transaction.launcher_fd < 0) fail(error);
    }
    if (fsync(transaction.stage_fd) != 0 || fsync(parent_fd) != 0) {
        fail_errno("cannot synchronize private pair stage");
    }
    if (!validate_sources(sources, controller_hash, launcher_hash, &error)) {
        fail(error);
    }
    if (!validate_retained_path(destination, 0, NULL, &error)) fail(error);
    test_pause();
    if (!validate_sources(sources, controller_hash, launcher_hash, &error) ||
        !validate_retained_path(destination, 0, NULL, &error)) {
        fail(error);
    }

    if (!controller_existed) {
        if (renameatx_np(transaction.stage_fd, WINS_CONTROLLER_DESTINATION_NAME,
                         parent_fd, WINS_CONTROLLER_DESTINATION_NAME,
                         RENAME_EXCL) != 0) {
            fail_errno("exclusive controller publication failed");
        }
        transaction.controller_published = 1;
        transaction.controller_stage_created = 0;
        if (fsync(parent_fd) != 0) fail_errno("cannot sync controller publication");
        if (!validate_installed_fd(transaction.controller_fd, parent_fd,
                                   WINS_CONTROLLER_DESTINATION_NAME,
                                   controller_hash, 0,
                                   &transaction.controller_identity, &error) ||
            !validate_sources(sources, controller_hash, launcher_hash, &error)) {
            fail(error);
        }
        if (!validate_retained_path(destination, 0, NULL, &error)) fail(error);
    }
#ifdef WINS_TEST_CRASH_AFTER_CONTROLLER
    _exit(91);
#endif
    if (!launcher_existed) {
        if (renameatx_np(transaction.stage_fd, WINS_LAUNCHER_DESTINATION_NAME,
                         parent_fd, WINS_LAUNCHER_DESTINATION_NAME,
                         RENAME_EXCL) != 0) {
            fail_errno("exclusive launcher publication failed");
        }
        transaction.launcher_published = 1;
        transaction.launcher_stage_created = 0;
        if (fsync(parent_fd) != 0) fail_errno("cannot sync launcher publication");
        if (!validate_installed_fd(transaction.launcher_fd, parent_fd,
                                   WINS_LAUNCHER_DESTINATION_NAME,
                                   launcher_hash, 0,
                                   &transaction.launcher_identity, &error) ||
            !validate_sources(sources, controller_hash, launcher_hash, &error)) {
            fail(error);
        }
        if (!validate_retained_path(destination, 0, NULL, &error)) fail(error);
    }

    unlink_if_same_unsealed(parent_fd, transaction.stage_name,
                            transaction.stage_fd, AT_REMOVEDIR);
    if (fstatat(parent_fd, transaction.stage_name, &stage_named,
                AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) {
        fail("cannot remove the retained empty private pair stage");
    }
    transaction.stage_created = 0;
    transaction.stage_name[0] = '\0';
    if (fsync(parent_fd) != 0 ||
        !validate_sources(sources, controller_hash, launcher_hash, &error) ||
        !validate_retained_path(destination, 0, NULL, &error)) {
        if (error != NULL) fail(error);
        fail_errno("cannot sync completed pair publication");
    }

    if ((((unsigned int)transaction.controller_identity.st_flags) &
         WINS_IMMUTABLE_FLAG) == 0U) {
        if (fchflags(transaction.controller_fd,
                     transaction.controller_identity.st_flags |
                         WINS_IMMUTABLE_FLAG) != 0 ||
            !sync_file(transaction.controller_fd, &error)) {
            if (error != NULL) fail(error);
            fail_errno("cannot seal installed controller");
        }
        transaction.controller_sealed = 1;
    }
    if (!validate_sources(sources, controller_hash, launcher_hash, &error)) {
        fail(error);
    }
    if (!validate_retained_path(destination, 0, NULL, &error)) fail(error);
    if ((((unsigned int)transaction.launcher_identity.st_flags) &
         WINS_IMMUTABLE_FLAG) == 0U) {
        if (fchflags(transaction.launcher_fd,
                     transaction.launcher_identity.st_flags |
                         WINS_IMMUTABLE_FLAG) != 0 ||
            !sync_file(transaction.launcher_fd, &error)) {
            if (error != NULL) fail(error);
            fail_errno("cannot seal installed launcher");
        }
        transaction.launcher_sealed = 1;
    }
    if (fsync(parent_fd) != 0 ||
        !validate_installed_fd(transaction.controller_fd, parent_fd,
                               WINS_CONTROLLER_DESTINATION_NAME,
                               controller_hash, 1, NULL, &error) ||
        !validate_installed_fd(transaction.launcher_fd, parent_fd,
                               WINS_LAUNCHER_DESTINATION_NAME,
                               launcher_hash, 1, NULL, &error) ||
        !validate_sources(sources, controller_hash, launcher_hash, &error) ||
        !validate_retained_path(destination, 0, NULL, &error)) {
        if (error != NULL) fail(error);
        fail_errno("final installed pair validation failed");
    }
    transaction.cleanup_enabled = 0;
    printf("ReleasePython owner bootstrap: installed exact controller/launcher pair\n");
}

int main(int argc, char **argv) {
    const char *error = NULL;
    char process_path[PROC_PIDPATHINFO_MAXSIZE];
    retained_path self;
    retained_path destination;
    retained_sources sources;
    struct rlimit file_limit;
    struct stat *controller_info;
    struct stat *launcher_info;
    int install_self_action;

    memset(&self, 0, sizeof(self));
    memset(&destination, 0, sizeof(destination));
    memset(&sources, 0, sizeof(sources));
    sources.queue = -1;
    (void)build_evidence;
    require_arguments(argc, argv);
    install_self_action = strcmp(argv[1], "install-self") == 0;
    if (!ensure_standard_descriptors(&error)) fail(error);
    if (!exact_environment(&error)) fail(error);
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
    if (getrlimit(RLIMIT_FSIZE, &file_limit) != 0) {
        fail_errno("cannot inspect inherited file-size limit");
    }
    if (!open_retained_path(WINS_DESTINATION_PARENT, 1, &destination, &error) ||
        !validate_secure_ancestry(&destination, 0, &error) ||
        !validate_retained_path(&destination, 0, NULL, &error)) {
        fail(error);
    }
    if (install_self_action) {
        if (!install_self(argv[2], argv[3], &destination, &error)) fail(error);
        close_retained_path(&destination);
        return 0;
    }
    if (proc_pidpath(getpid(), process_path, sizeof(process_path)) <= 0 ||
        !secure_equal(process_path, WINS_BOOTSTRAP_PATH)) {
        fail("running bootstrap path is not the reviewed fixed path");
    }
    if (!open_retained_path(WINS_BOOTSTRAP_PATH, 0, &self, &error) ||
        !validate_secure_ancestry(&self, 1, &error) ||
        !validate_retained_path(&self, 0, NULL, &error)) {
        fail(error);
    }
    if (!open_retained_path(argv[2], 0, &sources.controller, &error) ||
        !open_retained_path(argv[4], 0, &sources.launcher, &error) ||
        !require_source_leaf(&sources.controller, argv[3], &error) ||
        !require_source_leaf(&sources.launcher, argv[5], &error)) {
        fail(error);
    }
    controller_info = &sources.controller
                           .components[sources.controller.count - 1].identity;
    launcher_info =
        &sources.launcher.components[sources.launcher.count - 1].identity;
    if (same_vnode(controller_info, launcher_info)) {
        fail("controller and launcher sources resolve to one vnode");
    }
    if (!require_controller_role(
            sources.controller.components[sources.controller.count - 1].descriptor,
            controller_info, &error) ||
        !require_launcher_role(
            sources.launcher.components[sources.launcher.count - 1].descriptor,
            launcher_info, argv[3], &error)) {
        fail(error);
    }
    if (file_limit.rlim_cur != RLIM_INFINITY &&
        (file_limit.rlim_cur < (rlim_t)controller_info->st_size ||
         file_limit.rlim_cur < (rlim_t)launcher_info->st_size)) {
        fail("inherited file-size limit is below reviewed input size");
    }
    if (!arm_sources(&sources, &error) ||
        !validate_sources(&sources, argv[3], argv[5], &error)) {
        fail(error);
    }
    install_pair(&sources, &destination, argv[3], argv[5]);
    if (sources.queue >= 0) close(sources.queue);
    close_retained_path(&sources.launcher);
    close_retained_path(&sources.controller);
    close_retained_path(&destination);
    close_retained_path(&self);
    return 0;
}
