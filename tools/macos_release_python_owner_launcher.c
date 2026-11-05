#define _DARWIN_C_SOURCE 1

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef WINS_OWNER_LAUNCHER_PATH
#define WINS_OWNER_LAUNCHER_PATH "/Library/WinsVPN/ReleasePythonAuthority/v2/owner-launcher"
#endif
#ifndef WINS_CONTROLLER_PATH
#define WINS_CONTROLLER_PATH "/Library/WinsVPN/ReleasePythonAuthority/v2/owner-provision"
#endif
#ifndef WINS_RUNTIME_ROOT
#define WINS_RUNTIME_ROOT "/Library/WinsVPN/ReleasePython/3.14.7"
#endif
#ifndef WINS_RUNTIME_LAUNCHER
#define WINS_RUNTIME_LAUNCHER WINS_RUNTIME_ROOT "/launcher/python3.14"
#endif
#ifndef WINS_RUNTIME_PYTHON
#define WINS_RUNTIME_PYTHON WINS_RUNTIME_ROOT "/Python.framework/Versions/3.14/bin/python3.14"
#endif
#ifndef WINS_RUNTIME_INTEL_SHIM
#define WINS_RUNTIME_INTEL_SHIM "Python.framework/Versions/3.14/bin/python3.14-intel64"
#endif
#ifndef WINS_RUNTIME_LIBRARY
#define WINS_RUNTIME_LIBRARY WINS_RUNTIME_ROOT "/Python.framework/Versions/3.14/lib"
#endif
#ifndef WINS_RUNTIME_VENDOR
#define WINS_RUNTIME_VENDOR WINS_RUNTIME_ROOT "/vendor"
#endif
#ifndef WINS_EXPECTED_UID
#define WINS_EXPECTED_UID 0
#endif
#ifndef WINS_RUNTIME_EXPECTED_UID
#define WINS_RUNTIME_EXPECTED_UID 0
#endif
#ifndef WINS_REQUIRE_IMMUTABLE
#define WINS_REQUIRE_IMMUTABLE 1
#endif
#ifndef WINS_PROTOCOL_TIMEOUT_MS
#define WINS_PROTOCOL_TIMEOUT_MS 300000
#endif
#ifndef WINS_TEST_PREEXEC_DELAY_US
#define WINS_TEST_PREEXEC_DELAY_US 0
#endif
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
#ifndef WINS_BUILD_SDK_CLOSURE_SHA256
#error WINS_BUILD_SDK_CLOSURE_SHA256 must be supplied by the reviewed build script
#endif
#ifndef WINS_CONTROLLER_SHA256
#error WINS_CONTROLLER_SHA256 must be supplied by the reviewed build script
#endif
#ifndef WINS_RUNTIME_LAUNCHER_SHA256
#error WINS_RUNTIME_LAUNCHER_SHA256 must be supplied by the reviewed build script
#endif
#ifndef WINS_RUNTIME_PYTHON_SHA256
#error WINS_RUNTIME_PYTHON_SHA256 must be supplied by the reviewed build script
#endif

#define CAPABILITY_CONTRACT "winsvpn-macos-release-python-native-capability-v1"
#define RUNTIME_FD 197
#define CAPABILITY_FD 198
#define CONTROLLER_FD 199
#define MAX_FILE_BYTES ((uint64_t)1024 * 1024 * 1024)
#define MAX_TREE_BYTES ((uint64_t)2 * 1024 * 1024 * 1024)
#define MAX_TREE_NODES 20000U
#define MAX_MACHO_COMMANDS 8192U
#define MAX_RECORD_BYTES 4096U
#define MAX_PROTOCOL_BYTES 16384U
#define MAX_PROTOCOL_MESSAGES 128U
#define MAX_PROTOCOL_PINGS 96U
#define MAX_CHILD_STDOUT (256U * 1024U)
#define MAX_CHILD_STDERR (256U * 1024U)
#define MAX_ANCESTORS 64U
#define MAX_DESCENDANTS 4096U
#define SF_IMMUTABLE_VALUE 0x00020000U
#define MAXIMUM_MIN_OS 0x000d0000U
#define CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0U
#define CSMAGIC_CODEDIRECTORY 0xfade0c02U
#define CSMAGIC_BLOBWRAPPER 0xfade0b01U
#define CSSLOT_CODEDIRECTORY 0U
#define CSSLOT_SIGNATURESLOT 0x10000U
#define CS_ADHOC 0x00000002U
#define CS_HASHTYPE_SHA256 2U

extern char **environ;


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
        uint32_t sum1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
        uint32_t choice = (e & f) ^ ((~e) & g);
        uint32_t temporary1 = h + sum1 + choice + sha256_constants[index] + words[index];
        uint32_t sum0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
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
    size_t copied;
    while (length > 0) {
        copied = 64 - context->block_used;
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
        memset(context->block + context->block_used, 0, 64 - context->block_used);
        sha256_transform(context, context->block);
        context->block_used = 0;
    }
    memset(context->block + context->block_used, 0, 56 - context->block_used);
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

static void fail_errno(const char *message) {
    fprintf(stderr, "ReleasePython native launcher: %s: %s\n", message, strerror(errno));
    exit(126);
}

static void fail(const char *message) {
    fprintf(stderr, "ReleasePython native launcher: %s\n", message);
    exit(126);
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

static void hex_encode(const unsigned char *input, size_t length, char *output) {
    static const char alphabet[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < length; ++index) {
        output[index * 2] = alphabet[input[index] >> 4];
        output[index * 2 + 1] = alphabet[input[index] & 15U];
    }
    output[length * 2] = '\0';
}

static void hash_fd(int descriptor, char output[65]) {
    sha256_context context;
    unsigned char digest[32];
    unsigned char buffer[65536];
    ssize_t count;
    off_t offset = 0;
    sha256_init(&context);
    for (;;) {
        count = pread(descriptor, buffer, sizeof(buffer), offset);
        if (count < 0) fail_errno("cannot hash retained file");
        if (count == 0) break;
        sha256_update(&context, buffer, (size_t)count);
        offset += count;
        if ((uint64_t)offset > MAX_FILE_BYTES) fail("retained file exceeds byte ceiling");
    }
    sha256_final(&context, digest);
    hex_encode(digest, sizeof(digest), output);
}

typedef enum {
    TREE_DIRECTORY = 1,
    TREE_FILE = 2,
    TREE_SYMLINK = 3,
} tree_kind;

typedef struct {
    char relative[PATH_MAX];
    char name[NAME_MAX + 1];
    char link_target[PATH_MAX];
    char digest[65];
    size_t parent;
    size_t child_count;
    int descriptor;
    tree_kind kind;
    struct stat identity;
    int macho_state[2];
} tree_node;

typedef struct {
    tree_node *nodes;
    size_t count;
    size_t capacity;
    size_t macho_count;
    size_t intel_shim_count;
    uint64_t bytes;
    int queue;
    char digest[65];
    char framework_digest[65];
    char vendor_digest[65];
    char launcher_digest[65];
} runtime_tree;

typedef struct {
    int descriptors[MAX_ANCESTORS];
    struct stat identities[MAX_ANCESTORS];
    char paths[MAX_ANCESTORS][PATH_MAX];
    size_t count;
} retained_ancestry;

static int same_identity(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev &&
           left->st_ino == right->st_ino &&
           left->st_mode == right->st_mode &&
           left->st_uid == right->st_uid &&
           left->st_gid == right->st_gid &&
           left->st_nlink == right->st_nlink &&
           left->st_size == right->st_size &&
           left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
           left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec &&
           left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
           left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec &&
           left->st_flags == right->st_flags;
}

static int same_ancestor_identity(const struct stat *left,
                                  const struct stat *right) {
    return left->st_dev == right->st_dev &&
           left->st_ino == right->st_ino &&
           left->st_mode == right->st_mode &&
           left->st_uid == right->st_uid &&
           left->st_gid == right->st_gid &&
           left->st_flags == right->st_flags;
}

static void require_runtime_identity(const struct stat *info, tree_kind kind) {
    int valid_type = (kind == TREE_DIRECTORY && S_ISDIR(info->st_mode)) ||
                     (kind == TREE_FILE && S_ISREG(info->st_mode)) ||
                     (kind == TREE_SYMLINK && S_ISLNK(info->st_mode));
    mode_t mode = info->st_mode & 07777;
    if ((info->st_mode & (S_ISUID | S_ISGID | S_ISVTX)) != 0) {
        fail("sealed runtime setid or sticky mode is forbidden");
    }
    if (!valid_type || info->st_uid != (uid_t)WINS_RUNTIME_EXPECTED_UID ||
        (info->st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) != 0) {
        fail("sealed runtime node identity, owner, mode, or type is invalid");
    }
    if ((kind == TREE_DIRECTORY && mode != 0555) ||
        (kind == TREE_FILE && mode != 0444 && mode != 0555)) {
        fail("sealed runtime role mode is not exact 0555 executable or 0444 data");
    }
    if (kind == TREE_FILE && info->st_nlink != 1) {
        fail("sealed runtime regular file is multiply linked");
    }
#if WINS_REQUIRE_IMMUTABLE
    if ((((unsigned int)info->st_flags) & SF_IMMUTABLE_VALUE) == 0U) {
        fail("sealed runtime node is not system immutable");
    }
#endif
}

static void reserve_tree_node(runtime_tree *tree) {
    size_t next;
    tree_node *resized;
    if (tree->count >= MAX_TREE_NODES) fail("sealed runtime node ceiling exceeded");
    if (tree->count < tree->capacity) return;
    next = tree->capacity == 0 ? 256U : tree->capacity * 2U;
    if (next > MAX_TREE_NODES) next = MAX_TREE_NODES;
    resized = realloc(tree->nodes, next * sizeof(*resized));
    if (resized == NULL) fail_errno("cannot retain sealed runtime inventory");
    tree->nodes = resized;
    tree->capacity = next;
}

static size_t append_tree_node(runtime_tree *tree, const char *relative,
                               const char *name, size_t parent, int descriptor,
                               tree_kind kind, const struct stat *identity,
                               const char *digest, const char *link_target) {
    tree_node *node;
    reserve_tree_node(tree);
    node = &tree->nodes[tree->count];
    memset(node, 0, sizeof(*node));
    if (snprintf(node->relative, sizeof(node->relative), "%s", relative) < 0 ||
        strlen(relative) >= sizeof(node->relative) ||
        snprintf(node->name, sizeof(node->name), "%s", name) < 0 ||
        strlen(name) >= sizeof(node->name)) {
        fail("sealed runtime relative path is too long");
    }
    if (digest != NULL) strcpy(node->digest, digest);
    if (link_target != NULL) {
        if (snprintf(node->link_target, sizeof(node->link_target), "%s",
                     link_target) < 0 ||
            strlen(link_target) >= sizeof(node->link_target)) {
            fail("sealed runtime symlink target is too long");
        }
    }
    node->parent = parent;
    node->descriptor = descriptor;
    node->kind = kind;
    node->identity = *identity;
    return tree->count++;
}

static int compare_names(const void *left, const void *right) {
    const char *const *a = left;
    const char *const *b = right;
    return strcmp(*a, *b);
}

static int normalize_relative(const char *input, char output[PATH_MAX]) {
    char copy[PATH_MAX];
    char *components[PATH_MAX / 2];
    size_t count = 0;
    char *cursor, *token, *save = NULL;
    size_t used = 0, index;
    if (input[0] == '/' || strlen(input) >= sizeof(copy)) return 0;
    strcpy(copy, input);
    cursor = copy;
    while ((token = strtok_r(cursor, "/", &save)) != NULL) {
        cursor = NULL;
        if (strcmp(token, ".") == 0 || token[0] == '\0') continue;
        if (strcmp(token, "..") == 0) {
            if (count == 0) return 0;
            --count;
            continue;
        }
        if (count >= sizeof(components) / sizeof(components[0])) return 0;
        components[count++] = token;
    }
    if (count == 0) {
        output[0] = '\0';
        return 1;
    }
    for (index = 0; index < count; ++index) {
        size_t length = strlen(components[index]);
        if (used + length + (index != 0) >= PATH_MAX) return 0;
        if (index != 0) output[used++] = '/';
        memcpy(output + used, components[index], length);
        used += length;
    }
    output[used] = '\0';
    return 1;
}

static void require_symlink_inside_tree(const char *relative,
                                        const char *target) {
    char combined[PATH_MAX], normalized[PATH_MAX], directory[PATH_MAX];
    char *slash;
    if (target[0] == '/') fail("sealed runtime symlink escapes its root");
    if (snprintf(directory, sizeof(directory), "%s", relative) < 0 ||
        strlen(relative) >= sizeof(directory)) fail("sealed runtime path is too long");
    slash = strrchr(directory, '/');
    if (slash != NULL) *slash = '\0';
    else directory[0] = '\0';
    if (snprintf(combined, sizeof(combined), "%s%s%s", directory,
                 directory[0] == '\0' ? "" : "/", target) < 0 ||
        strlen(directory) + strlen(target) + 2 >= sizeof(combined) ||
        !normalize_relative(combined, normalized)) {
        fail("sealed runtime symlink escapes its root");
    }
}

static void scan_runtime_directory(runtime_tree *tree, size_t parent_index) {
    tree_node *parent = &tree->nodes[parent_index];
    DIR *directory;
    struct dirent *entry;
    char **names = NULL;
    size_t count = 0, capacity = 0, index;
    int duplicate = dup(parent->descriptor);
    if (duplicate < 0) fail_errno("cannot duplicate sealed runtime directory");
    directory = fdopendir(duplicate);
    if (directory == NULL) fail_errno("cannot enumerate sealed runtime directory");
    rewinddir(directory);
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        char *saved;
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        if (strchr(entry->d_name, '/') != NULL || entry->d_name[0] == '\0') {
            fail("sealed runtime directory contains an unsafe name");
        }
        if (count == capacity) {
            size_t next = capacity == 0 ? 32U : capacity * 2U;
            char **resized = realloc(names, next * sizeof(*resized));
            if (resized == NULL) fail_errno("cannot retain sealed runtime names");
            names = resized;
            capacity = next;
        }
        saved = strdup(entry->d_name);
        if (saved == NULL) fail_errno("cannot retain sealed runtime name");
        names[count++] = saved;
    }
    if (errno != 0) fail_errno("cannot finish sealed runtime enumeration");
    closedir(directory);
    qsort(names, count, sizeof(*names), compare_names);
    tree->nodes[parent_index].child_count = count;
    for (index = 0; index < count; ++index) {
        struct stat named, opened;
        char relative[PATH_MAX], digest[65], target[PATH_MAX];
        tree_kind kind = 0;
        int descriptor, flags;
        size_t child_index;
        if (snprintf(relative, sizeof(relative), "%s%s%s",
                     tree->nodes[parent_index].relative,
                     tree->nodes[parent_index].relative[0] == '\0' ? "" : "/",
                     names[index]) < 0 ||
            strlen(tree->nodes[parent_index].relative) + strlen(names[index]) + 2 >= sizeof(relative)) {
            fail("sealed runtime path exceeds PATH_MAX");
        }
        if (fstatat(tree->nodes[parent_index].descriptor, names[index], &named,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            fail_errno("cannot stat sealed runtime node");
        }
        if (S_ISDIR(named.st_mode)) kind = TREE_DIRECTORY;
        else if (S_ISREG(named.st_mode)) kind = TREE_FILE;
        else if (S_ISLNK(named.st_mode)) kind = TREE_SYMLINK;
        else fail("sealed runtime contains a special file");
        require_runtime_identity(&named, kind);
        flags = O_RDONLY | O_CLOEXEC;
        if (kind == TREE_DIRECTORY) flags |= O_DIRECTORY | O_NOFOLLOW;
        else if (kind == TREE_FILE) flags |= O_NOFOLLOW;
        else flags |= O_SYMLINK;
        descriptor = openat(tree->nodes[parent_index].descriptor, names[index], flags);
        if (descriptor < 0) fail_errno("cannot retain sealed runtime node");
        if (fstat(descriptor, &opened) != 0) fail_errno("cannot bind sealed runtime node");
        if (!same_identity(&named, &opened)) fail("sealed runtime node changed while opened");
        digest[0] = '\0';
        target[0] = '\0';
        if (kind == TREE_FILE) {
            if (opened.st_size < 0 || (uint64_t)opened.st_size > MAX_FILE_BYTES ||
                tree->bytes + (uint64_t)opened.st_size > MAX_TREE_BYTES) {
                fail("sealed runtime byte ceiling exceeded");
            }
            hash_fd(descriptor, digest);
            tree->bytes += (uint64_t)opened.st_size;
        } else if (kind == TREE_SYMLINK) {
            ssize_t length = readlinkat(tree->nodes[parent_index].descriptor,
                                        names[index], target, sizeof(target) - 1);
            if (length < 0) fail_errno("cannot read retained sealed runtime symlink");
            if ((size_t)length >= sizeof(target) - 1) fail("sealed runtime symlink is too long");
            target[length] = '\0';
            require_symlink_inside_tree(relative, target);
        }
        child_index = append_tree_node(tree, relative, names[index], parent_index,
                                       descriptor, kind, &opened,
                                       kind == TREE_FILE ? digest : NULL,
                                       kind == TREE_SYMLINK ? target : NULL);
        if (kind == TREE_DIRECTORY) scan_runtime_directory(tree, child_index);
        free(names[index]);
    }
    free(names);
}

static ssize_t tree_lookup(const runtime_tree *tree, const char *relative);

static void hash_tree(runtime_tree *tree) {
    sha256_context context;
    unsigned char digest[32];
    size_t index;
    sha256_init(&context);
    for (index = 0; index < tree->count; ++index) {
        const tree_node *node = &tree->nodes[index];
        uint64_t lengths[3];
        unsigned char kind = (unsigned char)node->kind;
        lengths[0] = (uint64_t)strlen(node->relative);
        lengths[1] = (uint64_t)strlen(node->digest);
        lengths[2] = (uint64_t)strlen(node->link_target);
        sha256_update(&context, (const unsigned char *)lengths, sizeof(lengths));
        sha256_update(&context, &kind, sizeof(kind));
        sha256_update(&context, (const unsigned char *)node->relative,
                      (size_t)lengths[0]);
        sha256_update(&context, (const unsigned char *)node->digest,
                      (size_t)lengths[1]);
        sha256_update(&context, (const unsigned char *)node->link_target,
                      (size_t)lengths[2]);
    }
    sha256_final(&context, digest);
    hex_encode(digest, sizeof(digest), tree->digest);
}

static void hash_feed_text(sha256_context *context, const char *value) {
    uint64_t length = (uint64_t)strlen(value);
    unsigned char encoded[8];
    unsigned int shift;
    for (shift = 0; shift < 8; ++shift) {
        encoded[7 - shift] = (unsigned char)(length >> (shift * 8));
    }
    sha256_update(context, encoded, sizeof(encoded));
    sha256_update(context, (const unsigned char *)value, (size_t)length);
}

static void hash_receipt_tree(runtime_tree *tree, const char *root_relative,
                              char output[65]) {
    sha256_context context;
    unsigned char digest[32];
    char prefix[PATH_MAX], mode[32], size[32], flags[32];
    size_t index, prefix_length;
    ssize_t root_index = tree_lookup(tree, root_relative);
    if (root_index < 0 || tree->nodes[root_index].kind != TREE_DIRECTORY ||
        snprintf(prefix, sizeof(prefix), "%s/", root_relative) < 0 ||
        strlen(root_relative) + 2 > sizeof(prefix)) {
        fail("sealed runtime receipt tree root is absent");
    }
    prefix_length = strlen(prefix);
    sha256_init(&context);
    for (index = (size_t)root_index + 1; index < tree->count; ++index) {
        const tree_node *node = &tree->nodes[index];
        const char *relative;
        if (strncmp(node->relative, prefix, prefix_length) != 0) break;
        relative = node->relative + prefix_length;
        if (snprintf(mode, sizeof(mode), "%u",
                     (unsigned int)node->identity.st_mode & 07777U) < 0 ||
            snprintf(size, sizeof(size), "%lld",
                     (long long)node->identity.st_size) < 0 ||
            snprintf(flags, sizeof(flags), "%u",
                     (unsigned int)node->identity.st_flags) < 0) {
            fail("sealed runtime receipt tree identity is invalid");
        }
        if (node->kind == TREE_SYMLINK) {
            hash_feed_text(&context, "L");
            hash_feed_text(&context, relative);
            hash_feed_text(&context, node->link_target);
        } else if (node->kind == TREE_DIRECTORY) {
            hash_feed_text(&context, "D");
            hash_feed_text(&context, relative);
            hash_feed_text(&context, mode);
            hash_feed_text(&context, flags);
        } else {
            hash_feed_text(&context, "F");
            hash_feed_text(&context, relative);
            hash_feed_text(&context, mode);
            hash_feed_text(&context, size);
            hash_feed_text(&context, node->digest);
            hash_feed_text(&context, flags);
        }
    }
    sha256_final(&context, digest);
    hex_encode(digest, sizeof(digest), output);
}

static ssize_t tree_lookup(const runtime_tree *tree, const char *relative) {
    size_t index;
    for (index = 0; index < tree->count; ++index) {
        if (strcmp(tree->nodes[index].relative, relative) == 0) return (ssize_t)index;
    }
    return -1;
}

static ssize_t resolve_tree_path(const runtime_tree *tree, const char *input) {
    char current[PATH_MAX], combined[PATH_MAX], directory[PATH_MAX];
    unsigned int depth;
    if (!normalize_relative(input, current)) return -1;
    for (depth = 0; depth < 40; ++depth) {
        ssize_t found = tree_lookup(tree, current);
        const tree_node *node;
        char *slash;
        if (found < 0) return -1;
        node = &tree->nodes[found];
        if (node->kind != TREE_SYMLINK) return found;
        if (snprintf(directory, sizeof(directory), "%s", current) < 0 ||
            strlen(current) >= sizeof(directory)) return -1;
        slash = strrchr(directory, '/');
        if (slash != NULL) *slash = '\0';
        else directory[0] = '\0';
        if (snprintf(combined, sizeof(combined), "%s%s%s", directory,
                     directory[0] == '\0' ? "" : "/", node->link_target) < 0 ||
            strlen(directory) + strlen(node->link_target) + 2 >= sizeof(combined) ||
            !normalize_relative(combined, current)) return -1;
    }
    return -1;
}

static uint32_t swap32(uint32_t value) {
    return ((value & 0x000000ffU) << 24) |
           ((value & 0x0000ff00U) << 8) |
           ((value & 0x00ff0000U) >> 8) |
           ((value & 0xff000000U) >> 24);
}

static uint32_t read32(const unsigned char *data, int swapped) {
    uint32_t value;
    memcpy(&value, data, sizeof(value));
    return swapped ? swap32(value) : value;
}

static uint64_t swap64(uint64_t value) {
    return ((value & UINT64_C(0x00000000000000ff)) << 56) |
           ((value & UINT64_C(0x000000000000ff00)) << 40) |
           ((value & UINT64_C(0x0000000000ff0000)) << 24) |
           ((value & UINT64_C(0x00000000ff000000)) << 8) |
           ((value & UINT64_C(0x000000ff00000000)) >> 8) |
           ((value & UINT64_C(0x0000ff0000000000)) >> 24) |
           ((value & UINT64_C(0x00ff000000000000)) >> 40) |
           ((value & UINT64_C(0xff00000000000000)) >> 56);
}

static uint64_t read64(const unsigned char *data, int swapped) {
    uint64_t value;
    memcpy(&value, data, sizeof(value));
    return swapped ? swap64(value) : value;
}

static int has_macho_magic(const unsigned char *data, size_t size) {
    uint32_t magic;
    if (size < sizeof(magic)) return 0;
    memcpy(&magic, data, sizeof(magic));
    return magic == MH_MAGIC || magic == MH_CIGAM ||
           magic == MH_MAGIC_64 || magic == MH_CIGAM_64 ||
           magic == FAT_MAGIC || magic == FAT_CIGAM ||
           magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
}

static int path_has_unsafe_component(const char *path) {
    size_t length = strlen(path);
    return strstr(path, "//") != NULL || strstr(path, "/./") != NULL ||
           strstr(path, "/../") != NULL ||
           (length >= 2 && strcmp(path + length - 2, "/.") == 0) ||
           (length >= 3 && strcmp(path + length - 3, "/..") == 0);
}

static ssize_t require_loaded_dependency(runtime_tree *tree, const char *loader,
                                         const char *dependency) {
    char candidate[PATH_MAX], directory[PATH_MAX];
    char *slash;
    ssize_t found;
    if (dependency[0] == '/' && path_has_unsafe_component(dependency)) {
        fail("Mach-O dependency contains an unsafe path component");
    }
    if (strncmp(dependency, "/usr/lib/", 9) == 0 ||
        strncmp(dependency, "/System/Library/", 16) == 0) return -1;
    if (strncmp(dependency, "@loader_path/", 13) == 0) {
        if (snprintf(directory, sizeof(directory), "%s", loader) < 0 ||
            strlen(loader) >= sizeof(directory)) fail("Mach-O loader path is too long");
        slash = strrchr(directory, '/');
        if (slash != NULL) *slash = '\0';
        else directory[0] = '\0';
        if (snprintf(candidate, sizeof(candidate), "%s%s%s", directory,
                     directory[0] == '\0' ? "" : "/", dependency + 13) < 0 ||
            strlen(directory) + strlen(dependency + 13) + 2 >= sizeof(candidate)) {
            fail("Mach-O loader-relative dependency is too long");
        }
    } else if (strncmp(dependency, "@rpath/", 7) == 0) {
        fail("Mach-O @rpath dependency is not permitted in the sealed runtime");
    } else {
        fail("Mach-O dependency escapes the sealed runtime and system closure");
    }
    found = resolve_tree_path(tree, candidate);
    if (found < 0 || tree->nodes[found].kind != TREE_FILE) {
        fail("Mach-O dependency does not resolve to a retained runtime image");
    }
    return found;
}

static const char *load_command_string(const unsigned char *command,
                                       uint32_t command_size, int swapped) {
    uint32_t offset;
    const char *value;
    if (command_size < 12U) fail("Mach-O path load command is truncated");
    offset = read32(command + 8, swapped);
    if (offset >= command_size) fail("Mach-O path load command offset is invalid");
    value = (const char *)(command + offset);
    if (memchr(value, '\0', command_size - offset) == NULL || value[0] == '\0') {
        fail("Mach-O path load command is not terminated");
    }
    return value;
}

static uint32_t read_be32(const unsigned char *data) {
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) | (uint32_t)data[3];
}

static uint64_t read_be64(const unsigned char *data) {
    return ((uint64_t)read_be32(data) << 32) | (uint64_t)read_be32(data + 4);
}

typedef struct {
    const unsigned char *data;
    size_t size;
} macho_slice_view;

static macho_slice_view select_macho_slice(const unsigned char *data,
                                           size_t size,
                                           int expect_x86_64,
                                           int required_shape) {
    macho_slice_view selected = {data, size};
    uint32_t magic, architectures, index;
    uint64_t offsets[2] = {0, 0}, sizes[2] = {0, 0};
    size_t entry_size, table_end;
    unsigned int arm64_count = 0, x86_64_count = 0;
    int fat64, swapped;
    if (size < sizeof(uint32_t)) fail("Mach-O image is truncated");
    memcpy(&magic, data, sizeof(magic));
    if (magic == MH_MAGIC_64) {
        if (required_shape == 2) {
            fail("x86_64 execution dependency is not exact universal2 Mach-O");
        }
        return selected;
    }
    if (magic == MH_MAGIC || magic == MH_CIGAM || magic == MH_CIGAM_64) {
        fail("Mach-O slice is not native-endian 64-bit Mach-O");
    }
    if (magic != FAT_MAGIC && magic != FAT_CIGAM &&
        magic != FAT_MAGIC_64 && magic != FAT_CIGAM_64) {
        fail("Mach-O image magic is invalid");
    }
    if (required_shape == 1) {
        fail("required Intel shim is not exact thin x86_64 Mach-O");
    }
    if (size < sizeof(struct fat_header)) fail("universal Mach-O header is truncated");
    fat64 = magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
    swapped = magic == FAT_CIGAM || magic == FAT_CIGAM_64;
    architectures = read32(data + 4, swapped);
    if (architectures != 2U) {
        fail("universal2 Mach-O architecture inventory is not exact");
    }
    entry_size = fat64 ? sizeof(struct fat_arch_64) : sizeof(struct fat_arch);
    if (architectures > (size - sizeof(struct fat_header)) / entry_size) {
        fail("universal2 Mach-O architecture table is truncated");
    }
    table_end = sizeof(struct fat_header) + (size_t)architectures * entry_size;
    for (index = 0; index < architectures; ++index) {
        const unsigned char *entry = data + sizeof(struct fat_header) +
                                     (size_t)index * entry_size;
        uint32_t cpu = read32(entry, swapped);
        uint32_t subtype = read32(entry + 4, swapped);
        uint32_t align;
        uint64_t slice_end;
        uint32_t slice_magic, slice_cpu, slice_subtype;
        int slice_swapped;
        if (fat64) {
            offsets[index] = read64(entry + 8, swapped);
            sizes[index] = read64(entry + 16, swapped);
            align = read32(entry + 24, swapped);
            if (read32(entry + 28, swapped) != 0U) {
                fail("universal2 Mach-O reserved field is not zero");
            }
        } else {
            offsets[index] = read32(entry + 8, swapped);
            sizes[index] = read32(entry + 12, swapped);
            align = read32(entry + 16, swapped);
        }
        if (align > 30U || offsets[index] < table_end ||
            offsets[index] > size || sizes[index] < sizeof(struct mach_header_64) ||
            sizes[index] > size - offsets[index] ||
            (offsets[index] & (UINT64_C(1) << align) - 1U) != 0U) {
            fail("universal2 Mach-O slice bounds or alignment are invalid");
        }
        slice_end = offsets[index] + sizes[index];
        if (index > 0U && offsets[index] < offsets[0] + sizes[0] &&
            offsets[0] < slice_end) {
            fail("universal2 Mach-O slices overlap");
        }
        memcpy(&slice_magic, data + offsets[index], sizeof(slice_magic));
        if (slice_magic != MH_MAGIC_64) {
            fail("universal2 Mach-O slice is not native-endian 64-bit Mach-O");
        }
        slice_swapped = 0;
        slice_cpu = read32(data + offsets[index] + 4, slice_swapped);
        slice_subtype = read32(data + offsets[index] + 8, slice_swapped);
        if (slice_cpu != cpu || slice_subtype != subtype) {
            fail("universal2 Mach-O table and slice identities disagree");
        }
        if (cpu == (uint32_t)CPU_TYPE_ARM64 &&
            subtype == (uint32_t)CPU_SUBTYPE_ARM64_ALL) {
            ++arm64_count;
            if (!expect_x86_64) {
                selected.data = data + offsets[index];
                selected.size = (size_t)sizes[index];
            }
        } else if (cpu == (uint32_t)CPU_TYPE_X86_64 &&
                   subtype == (uint32_t)CPU_SUBTYPE_X86_64_ALL) {
            ++x86_64_count;
            if (expect_x86_64) {
                selected.data = data + offsets[index];
                selected.size = (size_t)sizes[index];
            }
        } else {
            fail("universal2 Mach-O architecture identity is not exact");
        }
    }
    if (arm64_count != 1U || x86_64_count != 1U) {
        fail("universal2 Mach-O requires exactly one arm64 and one x86_64 slice");
    }
    return selected;
}

static void validate_static_code_signature(const unsigned char *data, size_t size,
                                           uint32_t signature_offset,
                                           uint32_t signature_size) {
    const unsigned char *signature, *directory = NULL;
    uint32_t total, count, index, directory_length = 0;
    uint32_t hash_offset, code_slots, code_limit32, version, flags;
    uint64_t code_limit;
    unsigned int hash_size, hash_type, page_exponent;
    size_t page_size, expected_slots;
    int cms_present = 0;
    if (signature_offset > size || signature_size > size - signature_offset ||
        signature_size < 12U || signature_offset + signature_size != size) {
        fail("Mach-O LC_CODE_SIGNATURE bounds are not exact");
    }
    signature = data + signature_offset;
    if (read_be32(signature) != CSMAGIC_EMBEDDED_SIGNATURE) {
        fail("Mach-O embedded static code signature magic is invalid");
    }
    total = read_be32(signature + 4);
    count = read_be32(signature + 8);
    if (total > signature_size || total < 12U || count == 0U || count > 64U ||
        count > (total - 12U) / 8U) {
        fail("Mach-O static code signature superblob is malformed");
    }
    /* codesign may place per-architecture linkage data after the SuperBlob in
       the LC_CODE_SIGNATURE reservation. The receipt tree digest binds those
       non-executable bytes; the checks below independently bind every mapped
       executable page to the selected slice's SHA-256 CodeDirectory. */
    for (index = 0; index < count; ++index) {
        uint32_t type = read_be32(signature + 12U + index * 8U);
        uint32_t offset = read_be32(signature + 16U + index * 8U);
        uint32_t blob_length;
        if (offset > total || total - offset < 8U) {
            fail("Mach-O static code signature blob offset is invalid");
        }
        blob_length = read_be32(signature + offset + 4);
        if (blob_length < 8U || blob_length > total - offset) {
            fail("Mach-O static code signature blob bounds are invalid");
        }
        if (type == CSSLOT_CODEDIRECTORY) {
            if (directory != NULL ||
                read_be32(signature + offset) != CSMAGIC_CODEDIRECTORY) {
                fail("Mach-O primary CodeDirectory is not exact");
            }
            directory = signature + offset;
            directory_length = blob_length;
        } else if (type == CSSLOT_SIGNATURESLOT) {
            if (read_be32(signature + offset) != CSMAGIC_BLOBWRAPPER) {
                fail("Mach-O CMS signature wrapper is malformed");
            }
            cms_present = 1;
        }
    }
    if (directory == NULL || directory_length < 44U) {
        fail("Mach-O primary CodeDirectory is absent or truncated");
    }
    version = read_be32(directory + 8);
    flags = read_be32(directory + 12);
    hash_offset = read_be32(directory + 16);
    code_slots = read_be32(directory + 28);
    code_limit32 = read_be32(directory + 32);
    hash_size = directory[36];
    hash_type = directory[37];
    page_exponent = directory[39];
    code_limit = code_limit32;
    if (version >= 0x20300U && code_limit32 == 0U) {
        if (directory_length < 64U) fail("Mach-O CodeDirectory code limit is truncated");
        code_limit = read_be64(directory + 56);
    }
    if (hash_size != 32U || hash_type != CS_HASHTYPE_SHA256 ||
        page_exponent < 12U || page_exponent > 20U ||
        code_limit != signature_offset || code_limit > size) {
        fail("Mach-O CodeDirectory hash algorithm, page size, or code limit is invalid");
    }
    page_size = (size_t)1U << page_exponent;
    expected_slots = ((size_t)code_limit + page_size - 1U) / page_size;
    if (code_slots != expected_slots || hash_offset > directory_length ||
        code_slots > (directory_length - hash_offset) / hash_size) {
        fail("Mach-O CodeDirectory code-slot inventory is invalid");
    }
    if ((flags & CS_ADHOC) == 0U && !cms_present) {
        fail("Mach-O static code signature has neither ad hoc authority nor CMS");
    }
    for (index = 0; index < code_slots; ++index) {
        sha256_context context;
        unsigned char digest[32];
        size_t page_offset = (size_t)index * page_size;
        size_t page_length = page_size;
        if (page_length > (size_t)code_limit - page_offset) {
            page_length = (size_t)code_limit - page_offset;
        }
        sha256_init(&context);
        sha256_update(&context, data + page_offset, page_length);
        sha256_final(&context, digest);
        if (memcmp(digest, directory + hash_offset + (size_t)index * hash_size,
                   sizeof(digest)) != 0) {
            fail("Mach-O static CodeDirectory page hash mismatch");
        }
    }
}

static void validate_macho_arch(runtime_tree *tree, size_t node_index,
                                int expect_x86_64, int required_shape);

static void validate_macho_slice(runtime_tree *tree, const tree_node *node,
                                 const unsigned char *data, size_t size,
                                 int expect_x86_64) {
    uint32_t magic, commands, command_bytes, index, filetype;
    size_t header_size = 0, offset, end;
    int swapped;
    uint32_t deployment_commands = 0, code_signatures = 0, dylinkers = 0;
    uint32_t dependencies = 0, signature_offset = 0, signature_size = 0;
    const char *dependency_names[512];
    size_t runtime_length = strlen(WINS_RUNTIME_ROOT);
    const char *runtime_relative = &WINS_RUNTIME_PYTHON[runtime_length + 1];
    if (size < sizeof(uint32_t)) fail("Mach-O image is truncated");
    memcpy(&magic, data, sizeof(magic));
    if (magic == MH_MAGIC_64) header_size = sizeof(struct mach_header_64);
    else fail("fat Mach-O slice is not native-endian 64-bit Mach-O");
    swapped = 0;
    if (size < header_size) fail("Mach-O header is truncated");
    if (expect_x86_64) {
        if (read32(data + 4, swapped) != (uint32_t)CPU_TYPE_X86_64 ||
            read32(data + 8, swapped) != (uint32_t)CPU_SUBTYPE_X86_64_ALL) {
            fail("required Intel shim CPU type or subtype is not exact x86_64/all");
        }
    } else if (read32(data + 4, swapped) != (uint32_t)CPU_TYPE_ARM64 ||
               read32(data + 8, swapped) != (uint32_t)CPU_SUBTYPE_ARM64_ALL) {
        fail("Mach-O CPU type or subtype is not exact arm64/all");
    }
    filetype = read32(data + 12, swapped);
    if (filetype != MH_EXECUTE && filetype != MH_DYLIB && filetype != MH_BUNDLE) {
        fail("Mach-O file type is outside the exact release closure");
    }
    if ((filetype == MH_EXECUTE && (node->identity.st_mode & 07777) != 0555) ||
        (filetype != MH_EXECUTE && (node->identity.st_mode & 07777) != 0444)) {
        fail("Mach-O file type and role-specific mode disagree");
    }
    if (strcmp(node->relative, runtime_relative) == 0 && filetype != MH_EXECUTE) {
        fail("ReleasePython interpreter is not exact MH_EXECUTE");
    }
    if (strcmp(node->relative, WINS_RUNTIME_INTEL_SHIM) == 0 &&
        filetype != MH_EXECUTE) {
        fail("required Intel shim is not exact MH_EXECUTE");
    }
    if (expect_x86_64 &&
        strcmp(node->relative, WINS_RUNTIME_INTEL_SHIM) == 0 &&
        strcmp(node->relative, runtime_relative) == 0) {
        fail("required Intel shim cannot be the selected runtime interpreter");
    }
    commands = read32(data + 16, swapped);
    command_bytes = read32(data + 20, swapped);
    if (commands > MAX_MACHO_COMMANDS || command_bytes > size - header_size) {
        fail("Mach-O load command bounds are invalid");
    }
    offset = header_size;
    end = header_size + command_bytes;
    for (index = 0; index < commands; ++index) {
        uint32_t command, command_size;
        const unsigned char *current;
        if (end - offset < 8U) fail("Mach-O load command is truncated");
        current = data + offset;
        command = read32(current, swapped);
        command_size = read32(current + 4, swapped);
        if (command_size < 8U || command_size > end - offset) {
            fail("Mach-O load command size is invalid");
        }
        if (command == LC_RPATH) {
            (void)load_command_string(current, command_size, swapped);
            fail("Mach-O LC_RPATH is forbidden in the sealed runtime");
        }
        if (command == LC_DYLD_ENVIRONMENT) {
            (void)load_command_string(current, command_size, swapped);
            fail("Mach-O embedded DYLD environment is forbidden");
        }
        if (command == LC_LOAD_WEAK_DYLIB || command == LC_LOAD_UPWARD_DYLIB ||
            command == LC_LAZY_LOAD_DYLIB) {
            fail("Mach-O weak, upward, or lazy dependency is forbidden");
        }
        if (command == LC_LOAD_DYLIB || command == LC_REEXPORT_DYLIB) {
            const char *name = load_command_string(current, command_size, swapped);
            uint32_t seen;
            ssize_t dependency_index;
            if (dependencies >= 512U) fail("Mach-O dependency inventory exceeds its cap");
            for (seen = 0; seen < dependencies; ++seen) {
                if (strcmp(dependency_names[seen], name) == 0) {
                    fail("Mach-O dependency inventory contains a duplicate");
                }
            }
            dependency_names[dependencies++] = name;
            dependency_index = require_loaded_dependency(tree, node->relative, name);
            if (expect_x86_64 && dependency_index >= 0) {
                validate_macho_arch(tree, (size_t)dependency_index, 1, 2);
            }
        }
        if (command == LC_LOAD_DYLINKER) {
            const char *name = load_command_string(current, command_size, swapped);
            if (++dylinkers != 1U || strcmp(name, "/usr/lib/dyld") != 0) {
                fail("Mach-O dynamic linker is not exactly /usr/lib/dyld");
            }
        }
        if (command == LC_BUILD_VERSION) {
            uint32_t tools;
            if (++deployment_commands != 1U || command_size < 24U ||
                read32(current + 8, swapped) != PLATFORM_MACOS ||
                read32(current + 12, swapped) == 0U ||
                read32(current + 12, swapped) > MAXIMUM_MIN_OS) {
                fail("Mach-O platform or macOS 13 compatibility is invalid");
            }
            tools = read32(current + 20, swapped);
            if (tools > (command_size - 24U) / 8U || command_size != 24U + tools * 8U) {
                fail("Mach-O build-tool inventory is malformed");
            }
        }
        if (command == LC_VERSION_MIN_MACOSX) {
            if (++deployment_commands != 1U || command_size != 16U ||
                read32(current + 8, swapped) == 0U ||
                read32(current + 8, swapped) > MAXIMUM_MIN_OS) {
                fail("Mach-O platform or macOS 13 compatibility is invalid");
            }
        }
        if (command == LC_CODE_SIGNATURE) {
            if (++code_signatures != 1U || command_size != 16U) {
                fail("Mach-O LC_CODE_SIGNATURE inventory is not exact");
            }
            signature_offset = read32(current + 8, swapped);
            signature_size = read32(current + 12, swapped);
        }
        offset += command_size;
    }
    if (offset != end) fail("Mach-O load command inventory is inconsistent");
    if (deployment_commands != 1U || code_signatures != 1U ||
        (filetype == MH_EXECUTE && dylinkers != 1U) ||
        (filetype != MH_EXECUTE && dylinkers != 0U) || dependencies == 0U) {
        fail("Mach-O platform, signature, linker, or dependency inventory is incomplete");
    }
    validate_static_code_signature(data, size, signature_offset, signature_size);
}

static void validate_macho_arch(runtime_tree *tree, size_t node_index,
                                int expect_x86_64, int required_shape) {
    tree_node *node = &tree->nodes[node_index];
    unsigned char *data;
    macho_slice_view selected;
    size_t size;
    int state_index = expect_x86_64 ? 1 : 0;
    if (node->kind != TREE_FILE || node->macho_state[state_index] == 2) return;
    if (node->macho_state[state_index] == 1) return;
    if (node->identity.st_size < 4) {
        fail("x86_64 execution dependency is not a Mach-O image");
    }
    size = (size_t)node->identity.st_size;
    data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, node->descriptor, 0);
    if (data == MAP_FAILED) fail_errno("cannot map retained Mach-O candidate");
    if (!has_macho_magic(data, size)) {
        munmap(data, size);
        fail("x86_64 execution dependency is not a Mach-O image");
    }
    node->macho_state[state_index] = 1;
    selected = select_macho_slice(data, size, expect_x86_64, required_shape);
    validate_macho_slice(tree, node, selected.data, selected.size, expect_x86_64);
    munmap(data, size);
    node->macho_state[state_index] = 2;
}

static void validate_macho_node(runtime_tree *tree, size_t node_index) {
    tree_node *node = &tree->nodes[node_index];
    unsigned char magic_bytes[4];
    uint32_t magic;
    int is_intel_shim = strcmp(node->relative, WINS_RUNTIME_INTEL_SHIM) == 0;
    if (node->kind != TREE_FILE || node->macho_state[0] == 2 ||
        node->identity.st_size < 4 ||
        pread(node->descriptor, magic_bytes, sizeof(magic_bytes), 0) !=
            (ssize_t)sizeof(magic_bytes) ||
        !has_macho_magic(magic_bytes, sizeof(magic_bytes))) {
        return;
    }
    memcpy(&magic, magic_bytes, sizeof(magic));
    if (is_intel_shim) {
        validate_macho_arch(tree, node_index, 1, 1);
        ++tree->intel_shim_count;
    } else {
        validate_macho_arch(tree, node_index, 0, 0);
        if (magic == FAT_MAGIC || magic == FAT_CIGAM ||
            magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
            validate_macho_arch(tree, node_index, 1, 2);
        }
    }
    ++tree->macho_count;
}

static void validate_fixed_launcher_macho(int descriptor,
                                          const struct stat *identity) {
    runtime_tree system_only;
    tree_node launcher;
    unsigned char *data;
    size_t size;
    uint32_t magic;
    if (identity->st_size <= 0 || (uint64_t)identity->st_size > MAX_FILE_BYTES) {
        fail("fixed launcher Mach-O size is invalid");
    }
    size = (size_t)identity->st_size;
    data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, descriptor, 0);
    if (data == MAP_FAILED) fail_errno("cannot map retained fixed launcher");
    memcpy(&magic, data, sizeof(magic));
    if (magic != MH_MAGIC_64 && magic != MH_CIGAM_64) {
        fail("fixed launcher is not exact thin 64-bit Mach-O");
    }
    memset(&system_only, 0, sizeof(system_only));
    memset(&launcher, 0, sizeof(launcher));
    launcher.identity = *identity;
    strcpy(launcher.relative, "owner-launcher");
    validate_macho_slice(&system_only, &launcher, data, size, 0);
    munmap(data, size);
}

static void arm_tree_watch(runtime_tree *tree, const retained_ancestry *ancestry) {
    size_t index;
    tree->queue = kqueue();
    if (tree->queue < 0) fail_errno("cannot create sealed runtime vnode watch");
    for (index = 0; index < tree->count; ++index) {
        struct kevent change;
        EV_SET(&change, (uintptr_t)tree->nodes[index].descriptor, EVFILT_VNODE,
               EV_ADD | EV_ENABLE | EV_CLEAR,
               NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | NOTE_LINK |
               NOTE_RENAME | NOTE_REVOKE,
               0, NULL);
        if (kevent(tree->queue, &change, 1, NULL, 0, NULL) < 0) {
            fail_errno("cannot arm sealed runtime vnode watch");
        }
    }
    for (index = 0; index < ancestry->count; ++index) {
        struct kevent change;
        uint32_t notes = NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE;
        if (!S_ISDIR(ancestry->identities[index].st_mode)) {
            notes |= NOTE_WRITE | NOTE_EXTEND | NOTE_LINK | NOTE_ATTRIB;
        }
        EV_SET(&change, (uintptr_t)ancestry->descriptors[index], EVFILT_VNODE,
               EV_ADD | EV_ENABLE | EV_CLEAR,
               notes,
               0, NULL);
        if (kevent(tree->queue, &change, 1, NULL, 0, NULL) < 0) {
            fail_errno("cannot arm retained ancestry vnode watch");
        }
    }
}

static void validate_ancestry(const retained_ancestry *ancestry) {
    size_t index;
    for (index = 0; index < ancestry->count; ++index) {
        struct stat retained, named;
        if (fstat(ancestry->descriptors[index], &retained) != 0 ||
            lstat(ancestry->paths[index], &named) != 0 ||
            (S_ISDIR(ancestry->identities[index].st_mode)
                 ? (!same_ancestor_identity(&retained,
                                            &ancestry->identities[index]) ||
                    !same_ancestor_identity(&named,
                                            &ancestry->identities[index]))
                 : (!same_identity(&retained, &ancestry->identities[index]) ||
                    !same_identity(&named, &ancestry->identities[index])))) {
            fail("retained launcher or runtime ancestry changed");
        }
    }
}

static void validate_tree(runtime_tree *tree,
                          const retained_ancestry *ancestry) {
    struct timespec zero = {0, 0};
    struct kevent event;
    size_t index;
    if (kevent(tree->queue, NULL, 0, &event, 1, &zero) > 0) {
        fail("sealed runtime changed while retained");
    }
    validate_ancestry(ancestry);
    for (index = 0; index < tree->count; ++index) {
        tree_node *node = &tree->nodes[index];
        struct stat current, named;
        if (fstat(node->descriptor, &current) != 0 ||
            !same_identity(&current, &node->identity)) {
            fail("sealed runtime retained identity changed");
        }
        if (node->parent != SIZE_MAX) {
            tree_node *parent = &tree->nodes[node->parent];
            if (fstatat(parent->descriptor, node->name, &named,
                        AT_SYMLINK_NOFOLLOW) != 0 ||
                !same_identity(&named, &node->identity)) {
                fail("sealed runtime pathname identity changed");
            }
        }
        if (node->kind == TREE_FILE) {
            char digest[65];
            hash_fd(node->descriptor, digest);
            if (!secure_equal(digest, node->digest)) fail("sealed runtime file bytes changed");
        } else if (node->kind == TREE_DIRECTORY) {
            DIR *directory;
            struct dirent *entry;
            size_t count = 0;
            int duplicate = dup(node->descriptor);
            if (duplicate < 0) fail_errno("cannot re-enumerate sealed runtime directory");
            directory = fdopendir(duplicate);
            if (directory == NULL) fail_errno("cannot reopen sealed runtime directory");
            rewinddir(directory);
            while ((entry = readdir(directory)) != NULL) {
                if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) ++count;
            }
            closedir(directory);
            if (count != node->child_count) fail("sealed runtime directory inventory changed");
        } else {
            char target[PATH_MAX];
            ssize_t length = readlinkat(tree->nodes[node->parent].descriptor,
                                        node->name, target, sizeof(target) - 1);
            if (length < 0 || (size_t)length >= sizeof(target) - 1) {
                fail("sealed runtime symlink changed");
            }
            target[length] = '\0';
            if (strcmp(target, node->link_target) != 0) fail("sealed runtime symlink target changed");
        }
    }
}

static runtime_tree open_runtime_tree(const retained_ancestry *ancestry) {
    runtime_tree tree;
    struct rlimit limit;
    struct stat root_info;
    int root_fd;
    size_t index;
    memset(&tree, 0, sizeof(tree));
    tree.queue = -1;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0) fail_errno("cannot read descriptor limit");
    if (limit.rlim_cur < 65536U) {
        rlim_t requested = limit.rlim_max == RLIM_INFINITY || limit.rlim_max > 65536U
                               ? 65536U : limit.rlim_max;
        limit.rlim_cur = requested;
        if (setrlimit(RLIMIT_NOFILE, &limit) != 0) fail_errno("cannot retain complete runtime closure");
    }
    root_fd = open(WINS_RUNTIME_ROOT, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root_fd < 0 || fstat(root_fd, &root_info) != 0) {
        fail_errno("cannot retain sealed runtime root");
    }
    require_runtime_identity(&root_info, TREE_DIRECTORY);
    append_tree_node(&tree, "", "", SIZE_MAX, root_fd, TREE_DIRECTORY,
                     &root_info, NULL, NULL);
    scan_runtime_directory(&tree, 0);
    if (tree.nodes[0].child_count != 3U ||
        tree_lookup(&tree, "Python.framework") < 0 ||
        tree_lookup(&tree, "vendor") < 0 ||
        tree_lookup(&tree, "launcher") < 0 ||
        tree.nodes[tree_lookup(&tree, "Python.framework")].kind != TREE_DIRECTORY ||
        tree.nodes[tree_lookup(&tree, "vendor")].kind != TREE_DIRECTORY ||
        tree.nodes[tree_lookup(&tree, "launcher")].kind != TREE_DIRECTORY) {
        fail("sealed runtime top-level closure is not exact");
    }
    hash_tree(&tree);
    hash_receipt_tree(&tree, "Python.framework", tree.framework_digest);
    hash_receipt_tree(&tree, "vendor", tree.vendor_digest);
    hash_receipt_tree(&tree, "launcher", tree.launcher_digest);
    for (index = 0; index < tree.count; ++index) validate_macho_node(&tree, index);
    if (tree.intel_shim_count != 1U) {
        fail("sealed runtime requires exactly one thin x86_64 Intel shim");
    }
    arm_tree_watch(&tree, ancestry);
    validate_tree(&tree, ancestry);
    return tree;
}

static void close_runtime_tree(runtime_tree *tree) {
    size_t index;
    if (tree->queue >= 0) close(tree->queue);
    for (index = tree->count; index > 0; --index) close(tree->nodes[index - 1].descriptor);
    free(tree->nodes);
    memset(tree, 0, sizeof(*tree));
    tree->queue = -1;
}

static void retain_ancestors(const char *path, retained_ancestry *ancestry) {
    char copy[PROC_PIDPATHINFO_MAXSIZE];
    char current[PROC_PIDPATHINFO_MAXSIZE];
    char *cursor;
    struct stat info;
    int descriptor;
    if (path[0] != '/' || strlen(path) >= sizeof(copy)) fail("custody path is not safe absolute path");
    strcpy(copy, path);
    strcpy(current, "/");
    if (ancestry->count == 0) {
        descriptor = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (descriptor < 0 || fstat(descriptor, &info) != 0) {
            fail_errno("cannot retain filesystem root ancestor");
        }
        if (!S_ISDIR(info.st_mode) || info.st_uid != 0 ||
            (info.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID | S_ISVTX)) != 0) {
            close(descriptor);
            fail("filesystem root ancestor custody is unsafe");
        }
        ancestry->descriptors[0] = descriptor;
        ancestry->identities[0] = info;
        strcpy(ancestry->paths[0], "/");
        ancestry->count = 1;
    }
    cursor = copy + 1;
    while (*cursor != '\0') {
        char *slash = strchr(cursor, '/');
        size_t length;
        if (slash == NULL) break;
        length = (size_t)(slash - copy);
        if (length >= sizeof(current)) fail("custody ancestor path is too long");
        memcpy(current, copy, length);
        current[length] = '\0';
        descriptor = open(current, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (descriptor < 0) fail_errno("cannot retain custody ancestor");
        if (fstat(descriptor, &info) != 0) fail_errno("cannot stat custody ancestor");
        if (!S_ISDIR(info.st_mode) ||
            (info.st_uid != (uid_t)WINS_EXPECTED_UID && info.st_uid != 0) ||
            (info.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID | S_ISVTX)) != 0) {
            close(descriptor);
            fail("custody ancestor identity or mode is unsafe");
        }
        {
            size_t index;
            int duplicate = 0;
            for (index = 0; index < ancestry->count; ++index) {
                if (ancestry->identities[index].st_dev == info.st_dev &&
                    ancestry->identities[index].st_ino == info.st_ino) {
                    duplicate = 1;
                    break;
                }
            }
            if (duplicate) {
                close(descriptor);
            } else {
                if (ancestry->count >= MAX_ANCESTORS) {
                    close(descriptor);
                    fail("retained ancestry exceeds its fixed cap");
                }
                ancestry->descriptors[ancestry->count] = descriptor;
                ancestry->identities[ancestry->count] = info;
                strcpy(ancestry->paths[ancestry->count], current);
                ++ancestry->count;
            }
        }
        cursor = slash + 1;
    }
}

static void close_ancestry(retained_ancestry *ancestry) {
    while (ancestry->count > 0) close(ancestry->descriptors[--ancestry->count]);
}

static void retain_open_leaf(const char *path, int descriptor,
                             retained_ancestry *ancestry) {
    struct stat info;
    int duplicate;
    if (ancestry->count >= MAX_ANCESTORS) fail("fixed launcher ancestry cap exceeded");
    if (fstat(descriptor, &info) != 0) fail_errno("cannot stat fixed launcher leaf");
    duplicate = dup(descriptor);
    if (duplicate < 0) fail_errno("cannot duplicate fixed launcher leaf custody");
    ancestry->descriptors[ancestry->count] = duplicate;
    ancestry->identities[ancestry->count] = info;
    if (snprintf(ancestry->paths[ancestry->count], PATH_MAX, "%s", path) < 0 ||
        strlen(path) >= PATH_MAX) {
        close(duplicate);
        fail("fixed launcher leaf path is too long");
    }
    ++ancestry->count;
}

static int open_exact(const char *path, mode_t expected_mode, uid_t expected_uid,
                      char digest[65]) {
    struct stat before, after;
    int descriptor;
    if (lstat(path, &before) != 0) fail_errno("cannot stat custody leaf");
    descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) fail_errno("cannot open custody leaf");
    if (fstat(descriptor, &after) != 0) fail_errno("cannot stat retained custody leaf");
    if (!S_ISREG(after.st_mode) || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || after.st_uid != expected_uid ||
        after.st_nlink != 1 || (after.st_mode & 07777) != expected_mode ||
        after.st_size <= 0 || (uint64_t)after.st_size > MAX_FILE_BYTES) {
        fail("custody leaf identity, mode, link count, or size is invalid");
    }
#if WINS_REQUIRE_IMMUTABLE
    if ((((unsigned int)after.st_flags) & SF_IMMUTABLE_VALUE) == 0U) {
        fail("custody leaf is not system immutable");
    }
#endif
    hash_fd(descriptor, digest);
    return descriptor;
}

static void write_all(int descriptor, const void *data, size_t length) {
    const unsigned char *cursor = data;
    while (length > 0) {
        ssize_t count = write(descriptor, cursor, length);
        if (count < 0) {
            if (errno == EINTR) continue;
            fail_errno("capability write failed");
        }
        cursor += count;
        length -= (size_t)count;
    }
}

static uint64_t monotonic_milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        fail_errno("cannot read monotonic protocol clock");
    }
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

static pid_t tracked_descendants[MAX_DESCENDANTS];
static size_t tracked_descendant_count;

static int remember_descendant(pid_t pid) {
    size_t index;
    if (pid <= 1) return 1;
    for (index = 0; index < tracked_descendant_count; ++index) {
        if (tracked_descendants[index] == pid) return 1;
    }
    if (tracked_descendant_count >= MAX_DESCENDANTS) return 0;
    tracked_descendants[tracked_descendant_count++] = pid;
    return 1;
}

static int track_descendants(pid_t root) {
    pid_t pending[MAX_DESCENDANTS];
    size_t pending_count = 0, cursor = 0;
    if (!remember_descendant(root)) return 0;
    pending[pending_count++] = root;
    while (cursor < pending_count) {
        pid_t children[512];
        int count = proc_listchildpids(pending[cursor++], children,
                                      (int)sizeof(children));
        int index;
        if (count < 0 || count >= (int)(sizeof(children) / sizeof(children[0]))) {
            return 0;
        }
        for (index = 0; index < count; ++index) {
            if (!remember_descendant(children[index])) return 0;
            if (pending_count >= MAX_DESCENDANTS) return 0;
            pending[pending_count++] = children[index];
        }
    }
    return 1;
}

static void kill_controller_group(pid_t child) {
    int saved = errno;
    size_t index;
    if (child > 0) {
        (void)track_descendants(child);
        if (kill(-child, SIGKILL) != 0 && errno != ESRCH) {}
        if (kill(child, SIGKILL) != 0 && errno != ESRCH) {}
    }
    for (index = tracked_descendant_count; index > 0; --index) {
        if (kill(tracked_descendants[index - 1], SIGKILL) != 0 && errno != ESRCH) {}
    }
    errno = saved;
}

static int prove_descendants_gone(pid_t root) {
    size_t attempt, index;
    struct timespec pause_time = {0, 10000000L};
    for (attempt = 0; attempt < 100U; ++attempt) {
        int present = 0;
        (void)track_descendants(root);
        for (index = 0; index < tracked_descendant_count; ++index) {
            pid_t pid = tracked_descendants[index];
            if (pid == root) continue;
            if (kill(pid, 0) == 0 || errno == EPERM) {
                present = 1;
                (void)kill(pid, SIGKILL);
            }
        }
        if (!present) return 1;
        while (nanosleep(&pause_time, &pause_time) != 0 && errno == EINTR) {}
        pause_time.tv_sec = 0;
        pause_time.tv_nsec = 10000000L;
    }
    return 0;
}

static void abort_protocol(pid_t child, const char *message) {
    int status;
    kill_controller_group(child);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    fail(message);
}

static void require_input_environment(void) {
    char **entry;
    const char *home = getenv("HOME");
    const char *temporary = getenv("TMPDIR");
    if (home == NULL || strcmp(home, "/var/root") != 0 ||
        temporary == NULL || strcmp(temporary, "/private/tmp") != 0) {
        fail("input HOME or TMPDIR is not exact");
    }
    for (entry = environ; *entry != NULL; ++entry) {
        if (strncmp(*entry, "HOME=", 5) != 0 &&
            strncmp(*entry, "TMPDIR=", 7) != 0) {
            fail("unexpected input environment variable");
        }
    }
}

static void require_arguments(int argc, char **argv) {
    if (argc == 2 && (strcmp(argv[1], "recover") == 0 ||
                      strcmp(argv[1], "selftest") == 0)) return;
    if (argc == 4 && strcmp(argv[1], "apply") == 0 &&
        argv[2][0] == '/' && argv[3][0] == '/') return;
    if (argc == 4 && strcmp(argv[1], "publish-authority") == 0 &&
        argv[2][0] == '/' && argv[3][0] == '/') return;
    fail("argv must be exactly selftest, recover, publish-authority ABSOLUTE_AUTHORITY ABSOLUTE_ENVELOPE, or apply ABSOLUTE_PLAN ABSOLUTE_AUTHORIZATION");
}

static void hash_arguments(int argc, char **argv, char output[65]) {
    sha256_context context;
    unsigned char digest[32];
    int index;
    sha256_init(&context);
    for (index = 1; index < argc; ++index) {
        uint64_t length = (uint64_t)strlen(argv[index]);
        unsigned char encoded[8];
        unsigned int shift;
        for (shift = 0; shift < 8; ++shift) {
            encoded[7 - shift] = (unsigned char)(length >> (shift * 8));
        }
        sha256_update(&context, encoded, sizeof(encoded));
        sha256_update(&context, (const unsigned char *)argv[index], (size_t)length);
    }
    sha256_final(&context, digest);
    hex_encode(digest, sizeof(digest), output);
}

static void close_unneeded(int keep_one, int keep_two, int keep_three) {
    struct proc_fdinfo *files;
    int bytes, used, index;
    bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
    if (bytes <= 0 || bytes > (int)(MAX_TREE_NODES * sizeof(*files) * 2U)) {
        fail("cannot size inherited descriptor inventory");
    }
    files = malloc((size_t)bytes);
    if (files == NULL) fail_errno("cannot retain inherited descriptor inventory");
    used = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, files, bytes);
    if (used <= 0 || used > bytes || used % (int)sizeof(*files) != 0) {
        fail("cannot read inherited descriptor inventory");
    }
    for (index = 0; index < used / (int)sizeof(*files); ++index) {
        int descriptor = files[index].proc_fd;
        if (descriptor >= 3 && descriptor != keep_one &&
            descriptor != keep_two && descriptor != keep_three) {
            close(descriptor);
        }
    }
    free(files);
}

static int child_exec(int socket_fd, int controller_fd, int runtime_fd,
                      int stdout_fd, int stderr_fd, int argc, char **argv) {
    char socket_text[32], controller_text[32], runtime_text[32], script_path[64];
    char *child_argv[9];
    char capability_env[64], controller_env[64], runtime_env[64];
    char dyld_framework[512], dyld_library[512], path_env[1024];
    char python_executable[512], python_path[512];
    char *child_env[14];
    int index = 0;
    int arg_index;
    if (setsid() < 0) fail_errno("cannot isolate controller process group");
    if (dup2(stdout_fd, STDOUT_FILENO) < 0 || dup2(stderr_fd, STDERR_FILENO) < 0 ||
        dup2(runtime_fd, RUNTIME_FD) < 0 || dup2(socket_fd, CAPABILITY_FD) < 0 ||
        dup2(controller_fd, CONTROLLER_FD) < 0) {
        fail_errno("cannot place retained capability descriptors");
    }
    if (fcntl(RUNTIME_FD, F_SETFD, 0) != 0 ||
        fcntl(CAPABILITY_FD, F_SETFD, 0) != 0 ||
        fcntl(CONTROLLER_FD, F_SETFD, 0) != 0) {
        fail_errno("cannot retain capability descriptors across exec");
    }
    close_unneeded(RUNTIME_FD, CAPABILITY_FD, CONTROLLER_FD);
    snprintf(runtime_text, sizeof(runtime_text), "%d", RUNTIME_FD);
    snprintf(socket_text, sizeof(socket_text), "%d", CAPABILITY_FD);
    snprintf(controller_text, sizeof(controller_text), "%d", CONTROLLER_FD);
    snprintf(script_path, sizeof(script_path), "/dev/fd/%d", CONTROLLER_FD);
    snprintf(capability_env, sizeof(capability_env), "WINS_OWNER_CAPABILITY_FD=%s", socket_text);
    snprintf(controller_env, sizeof(controller_env), "WINS_OWNER_CONTROLLER_FD=%s", controller_text);
    snprintf(runtime_env, sizeof(runtime_env), "WINS_OWNER_RUNTIME_FD=%s", runtime_text);
    snprintf(dyld_framework, sizeof(dyld_framework), "DYLD_FRAMEWORK_PATH=%s", WINS_RUNTIME_ROOT);
    snprintf(dyld_library, sizeof(dyld_library), "DYLD_LIBRARY_PATH=%s", WINS_RUNTIME_LIBRARY);
    snprintf(path_env, sizeof(path_env), "PATH=%s/launcher:/usr/bin:/bin:/usr/sbin:/sbin", WINS_RUNTIME_ROOT);
    snprintf(python_executable, sizeof(python_executable), "PYTHONEXECUTABLE=%s", WINS_RUNTIME_LAUNCHER);
    snprintf(python_path, sizeof(python_path), "PYTHONPATH=%s", WINS_RUNTIME_VENDOR);
    child_env[index++] = "HOME=/var/root";
    child_env[index++] = "TMPDIR=/private/tmp";
    child_env[index++] = dyld_framework;
    child_env[index++] = dyld_library;
    child_env[index++] = path_env;
    child_env[index++] = "PYTHONDONTWRITEBYTECODE=1";
    child_env[index++] = python_executable;
    child_env[index++] = "PYTHONNOUSERSITE=1";
    child_env[index++] = python_path;
    child_env[index++] = runtime_env;
    child_env[index++] = capability_env;
    child_env[index++] = controller_env;
    child_env[index] = NULL;
    index = 0;
    child_argv[index++] = (char *)WINS_RUNTIME_PYTHON;
    child_argv[index++] = "-I";
    child_argv[index++] = "-S";
    child_argv[index++] = script_path;
    for (arg_index = 1; arg_index < argc; ++arg_index) child_argv[index++] = argv[arg_index];
    child_argv[index] = NULL;
#ifdef WINS_TEST_PREEXEC_MARKER
    {
        int marker = open(WINS_TEST_PREEXEC_MARKER,
                          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (marker < 0) fail_errno("cannot create test pre-exec marker");
        write_all(marker, "ready\n", 6);
        close(marker);
    }
#endif
    if (WINS_TEST_PREEXEC_DELAY_US > 0) {
        struct timespec pause_time;
        pause_time.tv_sec = WINS_TEST_PREEXEC_DELAY_US / 1000000;
        pause_time.tv_nsec = (long)(WINS_TEST_PREEXEC_DELAY_US % 1000000) * 1000L;
        while (nanosleep(&pause_time, &pause_time) != 0 && errno == EINTR) {}
    }
    execve(WINS_RUNTIME_PYTHON, child_argv, child_env);
    fail_errno("cannot exec retained ReleasePython Mach-O");
    return 126;
}

static int parent_protocol(int socket_fd, int stdout_fd, int stderr_fd,
                           pid_t child, const char *record, const char *nonce,
                           runtime_tree *tree,
                           const retained_ancestry *ancestry) {
    uint32_t length = (uint32_t)strlen(record);
    uint32_t network_length = htonl(length);
    char expected[96], line[128];
    unsigned char input[1024], output[16384];
    size_t line_used = 0, stdout_total = 0, stderr_total = 0;
    size_t protocol_total = 0, messages = 0, pings = 0;
    int status = 0, child_exited = 0, group_cleaned = 0;
    int socket_open = 1, stdout_open = 1, stderr_open = 1;
    int authenticated = 0;
    uint64_t deadline = monotonic_milliseconds() + (uint64_t)WINS_PROTOCOL_TIMEOUT_MS;
    if (fcntl(stdout_fd, F_SETFL, O_NONBLOCK) != 0 ||
        fcntl(stderr_fd, F_SETFL, O_NONBLOCK) != 0) {
        abort_protocol(child, "cannot make controller protocol nonblocking");
    }
    write_all(socket_fd, &network_length, sizeof(network_length));
    write_all(socket_fd, record, length);
    snprintf(expected, sizeof(expected), "READY %s\n", nonce);
    while (!child_exited || socket_open || stdout_open || stderr_open) {
        struct pollfd watched[4];
        nfds_t watched_count = 0;
        int socket_slot = -1, stdout_slot = -1, stderr_slot = -1, tree_slot;
        uint64_t now = monotonic_milliseconds();
        int timeout, ready;
        pid_t waited;
        if (!child_exited) {
            if (!track_descendants(child)) {
                abort_protocol(child, "complete controller descendant inventory failed closed");
            }
            do {
                waited = waitpid(child, &status, WNOHANG);
            } while (waited < 0 && errno == EINTR);
            if (waited < 0) abort_protocol(child, "cannot wait for controller");
            if (waited == child) child_exited = 1;
        }
        if (child_exited && !group_cleaned) {
            kill_controller_group(child);
            group_cleaned = 1;
        }
        if (child_exited && !socket_open && !stdout_open && !stderr_open) break;
        if (now >= deadline) abort_protocol(child, "controller exceeded its absolute protocol deadline");
        timeout = (int)(deadline - now);
        if (!child_exited && timeout > 10) timeout = 10;
        if (socket_open) {
            socket_slot = (int)watched_count;
            watched[watched_count++] = (struct pollfd){socket_fd, POLLIN | POLLHUP, 0};
        }
        if (stdout_open) {
            stdout_slot = (int)watched_count;
            watched[watched_count++] = (struct pollfd){stdout_fd, POLLIN | POLLHUP, 0};
        }
        if (stderr_open) {
            stderr_slot = (int)watched_count;
            watched[watched_count++] = (struct pollfd){stderr_fd, POLLIN | POLLHUP, 0};
        }
        tree_slot = (int)watched_count;
        watched[watched_count++] = (struct pollfd){tree->queue, POLLIN, 0};
        do {
            ready = poll(watched, watched_count, timeout);
        } while (ready < 0 && errno == EINTR);
        if (ready < 0) abort_protocol(child, "controller protocol poll failed");
        if (ready == 0) continue;
        if ((watched[tree_slot].revents & (POLLIN | POLLERR | POLLHUP)) != 0) {
            abort_protocol(child, "sealed runtime changed during controller execution");
        }
        if (socket_slot >= 0 && watched[socket_slot].revents != 0) {
            ssize_t count;
            do {
                count = read(socket_fd, input, sizeof(input));
            } while (count < 0 && errno == EINTR);
            if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                abort_protocol(child, "capability protocol read failed");
            }
            if (count == 0) {
                socket_open = 0;
                close(socket_fd);
                if (!authenticated || pings == 0 || line_used != 0) {
                    abort_protocol(child, "controller closed an incomplete capability protocol");
                }
            } else if (count > 0) {
                ssize_t byte;
                protocol_total += (size_t)count;
                if (protocol_total > MAX_PROTOCOL_BYTES) {
                    abort_protocol(child, "controller exceeded capability byte cap");
                }
                for (byte = 0; byte < count; ++byte) {
                    if (line_used + 1 >= sizeof(line)) {
                        abort_protocol(child, "controller capability line exceeded its cap");
                    }
                    line[line_used++] = (char)input[byte];
                    if (input[byte] == '\n') {
                        line[line_used] = '\0';
                        if (++messages > MAX_PROTOCOL_MESSAGES) {
                            abort_protocol(child, "controller exceeded capability message cap");
                        }
                        if (!authenticated) {
                            if (!secure_equal(line, expected)) {
                                abort_protocol(child, "child did not authenticate the native capability");
                            }
                            authenticated = 1;
                            snprintf(line, sizeof(line), "GO %s\n", nonce);
                            write_all(socket_fd, line, strlen(line));
                        } else {
                            snprintf(expected, sizeof(expected), "PING %s\n", nonce);
                            if (!secure_equal(line, expected)) {
                                abort_protocol(child, "child capability protocol drifted");
                            }
                            if (++pings > MAX_PROTOCOL_PINGS) {
                                abort_protocol(child, "controller exceeded capability PING cap");
                            }
                            snprintf(line, sizeof(line), "PONG %s\n", nonce);
                            write_all(socket_fd, line, strlen(line));
                        }
                        line_used = 0;
                    }
                }
            }
        }
        if (stdout_slot >= 0 && watched[stdout_slot].revents != 0) {
            ssize_t count;
            do {
                count = read(stdout_fd, output, sizeof(output));
            } while (count < 0 && errno == EINTR);
            if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                abort_protocol(child, "controller stdout read failed");
            }
            if (count == 0) {
                stdout_open = 0;
                close(stdout_fd);
            } else if (count > 0) {
                stdout_total += (size_t)count;
                if (stdout_total > MAX_CHILD_STDOUT) {
                    abort_protocol(child, "controller stdout exceeded its exact cap");
                }
                write_all(STDOUT_FILENO, output, (size_t)count);
            }
        }
        if (stderr_slot >= 0 && watched[stderr_slot].revents != 0) {
            ssize_t count;
            do {
                count = read(stderr_fd, output, sizeof(output));
            } while (count < 0 && errno == EINTR);
            if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                abort_protocol(child, "controller stderr read failed");
            }
            if (count == 0) {
                stderr_open = 0;
                close(stderr_fd);
            } else if (count > 0) {
                stderr_total += (size_t)count;
                if (stderr_total > MAX_CHILD_STDERR) {
                    abort_protocol(child, "controller stderr exceeded its exact cap");
                }
                write_all(STDERR_FILENO, output, (size_t)count);
            }
        }
        if (!child_exited) {
            do {
                waited = waitpid(child, &status, WNOHANG);
            } while (waited < 0 && errno == EINTR);
            if (waited < 0) abort_protocol(child, "cannot wait for controller");
            if (waited == child) child_exited = 1;
        }
        if (child_exited && !group_cleaned) {
            kill_controller_group(child);
            group_cleaned = 1;
        }
    }
    if (!prove_descendants_gone(child)) {
        fail("complete controller descendant cleanup could not be proven");
    }
    validate_tree(tree, ancestry);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 126;
}

int main(int argc, char **argv) {
    char process_path[PROC_PIDPATHINFO_MAXSIZE];
    char launcher_hash[65], controller_hash[65], runtime_launcher_hash[65];
    char runtime_python_hash[65], argv_hash[65], nonce[65];
    unsigned char nonce_bytes[32];
    char record[MAX_RECORD_BYTES];
    struct stat own_info, *runtime_info;
    runtime_tree tree;
    retained_ancestry ancestry;
    size_t runtime_root_length = strlen(WINS_RUNTIME_ROOT);
    ssize_t runtime_launcher_index, runtime_python_index;
    int own_fd, controller_fd;
    int sockets[2];
    int stdout_pipe[2], stderr_pipe[2];
    pid_t child;
    int record_length, result;

    memset(&ancestry, 0, sizeof(ancestry));
    signal(SIGPIPE, SIG_IGN);
    require_arguments(argc, argv);
    require_input_environment();
    if (geteuid() != (uid_t)WINS_EXPECTED_UID) fail("effective uid is not exact");
    if (proc_pidpath(getpid(), process_path, sizeof(process_path)) <= 0) {
        fail_errno("cannot resolve native launcher process path");
    }
    if (!secure_equal(process_path, WINS_OWNER_LAUNCHER_PATH)) {
        fail("running native launcher path is not the reviewed fixed path");
    }
    retain_ancestors(WINS_OWNER_LAUNCHER_PATH, &ancestry);
    retain_ancestors(WINS_CONTROLLER_PATH, &ancestry);
    retain_ancestors(WINS_RUNTIME_ROOT, &ancestry);
    own_fd = open_exact(WINS_OWNER_LAUNCHER_PATH, 0555, (uid_t)WINS_EXPECTED_UID, launcher_hash);
    if (fstat(own_fd, &own_info) != 0) fail_errno("cannot bind native launcher inode");
    validate_fixed_launcher_macho(own_fd, &own_info);
    controller_fd = open_exact(WINS_CONTROLLER_PATH, 0555, (uid_t)WINS_EXPECTED_UID, controller_hash);
    retain_open_leaf(WINS_OWNER_LAUNCHER_PATH, own_fd, &ancestry);
    retain_open_leaf(WINS_CONTROLLER_PATH, controller_fd, &ancestry);
    if (strncmp(WINS_RUNTIME_LAUNCHER, WINS_RUNTIME_ROOT, runtime_root_length) != 0 ||
        WINS_RUNTIME_LAUNCHER[runtime_root_length] != '/' ||
        strncmp(WINS_RUNTIME_PYTHON, WINS_RUNTIME_ROOT, runtime_root_length) != 0 ||
        WINS_RUNTIME_PYTHON[runtime_root_length] != '/') {
        fail("reviewed runtime leaves are outside the sealed runtime root");
    }
    tree = open_runtime_tree(&ancestry);
    runtime_launcher_index = resolve_tree_path(
        &tree, &WINS_RUNTIME_LAUNCHER[runtime_root_length + 1]);
    runtime_python_index = resolve_tree_path(
        &tree, &WINS_RUNTIME_PYTHON[runtime_root_length + 1]);
    if (runtime_launcher_index < 0 || runtime_python_index < 0 ||
        tree.nodes[runtime_launcher_index].kind != TREE_FILE ||
        tree.nodes[runtime_python_index].kind != TREE_FILE ||
        (tree.nodes[runtime_launcher_index].identity.st_mode & 07777) != 0555 ||
        (tree.nodes[runtime_python_index].identity.st_mode & 07777) != 0555) {
        fail("reviewed runtime launcher or Mach-O is absent from the sealed closure");
    }
    strcpy(runtime_launcher_hash, tree.nodes[runtime_launcher_index].digest);
    strcpy(runtime_python_hash, tree.nodes[runtime_python_index].digest);
    runtime_info = &tree.nodes[runtime_python_index].identity;
    if (!secure_equal(controller_hash, WINS_CONTROLLER_SHA256) ||
        !secure_equal(runtime_launcher_hash, WINS_RUNTIME_LAUNCHER_SHA256) ||
        !secure_equal(runtime_python_hash, WINS_RUNTIME_PYTHON_SHA256)) {
        fail("controller or ReleasePython runtime digest is not the reviewed build input");
    }
    arc4random_buf(nonce_bytes, sizeof(nonce_bytes));
    hex_encode(nonce_bytes, sizeof(nonce_bytes), nonce);
    hash_arguments(argc, argv, argv_hash);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) fail_errno("cannot create capability socket");
    if (pipe(stdout_pipe) != 0 || pipe(stderr_pipe) != 0) {
        fail_errno("cannot create bounded controller output pipes");
    }
    child = fork();
    if (child < 0) fail_errno("cannot fork fixed controller");
    if (child == 0) {
        close(sockets[0]);
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        close(own_fd);
        return child_exec(sockets[1], controller_fd,
                          tree.nodes[runtime_python_index].descriptor,
                          stdout_pipe[1], stderr_pipe[1], argc, argv);
    }
    close(sockets[1]);
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);
    record_length = snprintf(
        record, sizeof(record),
        "contract=%s\nnonce=%s\nparent_pid=%ld\nchild_pid=%ld\n"
        "launcher_sha256=%s\nlauncher_source_sha256=%s\nlauncher_build_sha256=%s\n"
        "launcher_compiler_sha256=%s\n"
        "launcher_linker_sha256=%s\nlauncher_sdk_closure_sha256=%s\n"
        "launcher_device=%llu\nlauncher_inode=%llu\n"
        "controller_sha256=%s\nruntime_launcher_sha256=%s\nruntime_python_sha256=%s\n"
        "runtime_closure_sha256=%s\nruntime_closure_nodes=%llu\nruntime_macho_files=%llu\n"
        "runtime_framework_tree_sha256=%s\nruntime_vendor_tree_sha256=%s\n"
        "runtime_launcher_tree_sha256=%s\n"
        "runtime_executable_device=%llu\nruntime_executable_inode=%llu\n"
        "argv_sha256=%s\n",
        CAPABILITY_CONTRACT, nonce, (long)getpid(), (long)child,
        launcher_hash, WINS_BUILD_SOURCE_SHA256, WINS_BUILD_SCRIPT_SHA256,
        WINS_BUILD_COMPILER_SHA256, WINS_BUILD_LINKER_SHA256,
        WINS_BUILD_SDK_CLOSURE_SHA256,
        (unsigned long long)own_info.st_dev, (unsigned long long)own_info.st_ino,
        controller_hash, runtime_launcher_hash, runtime_python_hash,
        tree.digest, (unsigned long long)tree.count,
        (unsigned long long)tree.macho_count,
        tree.framework_digest, tree.vendor_digest, tree.launcher_digest,
        (unsigned long long)runtime_info->st_dev,
        (unsigned long long)runtime_info->st_ino, argv_hash
    );
    if (record_length <= 0 || (size_t)record_length >= sizeof(record)) {
        kill_controller_group(child);
        fail("native capability record exceeded fixed bounds");
    }
    result = parent_protocol(sockets[0], stdout_pipe[0], stderr_pipe[0],
                             child, record, nonce, &tree, &ancestry);
    validate_tree(&tree, &ancestry);
    close(controller_fd);
    close(own_fd);
    close_runtime_tree(&tree);
    close_ancestry(&ancestry);
    return result;
}
