#define _DARWIN_C_SOURCE 1

#include <sys/param.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#error "O_NOFOLLOW is required"
#endif

#ifndef SF_IMMUTABLE
#error "SF_IMMUTABLE is required"
#endif

#define HELPER_CONTRACT "winsvpn-release-go-archive-custody-helper-v1"
#define PRIVATE_TMP "/private/tmp"
#define RUNTIME_PREFIX "wins-release-go."
#define MAX_RUNTIME_NAME 64
#define MAX_TREE_DEPTH 64
#define MAX_ENTRIES 100000

#ifdef WINS_CUSTODY_TESTING
#define CUSTODY_IMMUTABLE UF_IMMUTABLE
#else
#define CUSTODY_IMMUTABLE SF_IMMUTABLE
#endif

enum operation {
    OP_INSPECT,
    OP_SEAL,
    OP_UNSEAL,
    OP_VERIFY_CLEAR,
};

struct runtime_identity {
    uint64_t dev;
    uint64_t ino;
    uint64_t uid;
    uint64_t mode;
    uint64_t nlink;
    uint64_t mtime_ns;
    uint64_t ctime_ns;
};

struct entry_snapshot {
    char *name;
    struct stat info;
    char *link_target;
};

struct entry_list {
    struct entry_snapshot *items;
    size_t count;
    size_t capacity;
};

static uid_t caller_uid;
static dev_t runtime_device;
static size_t visited_entries;
static char first_error[512];
extern char **environ;

#ifdef WINS_CUSTODY_TESTING
static long fault_after = -1;
static long flag_calls;
static int pause_ready_fd = -1;
static int pause_continue_fd = -1;
#endif

static void record_error(const char *format, ...) {
    va_list arguments;

    if (first_error[0] != '\0') {
        return;
    }
    va_start(arguments, format);
    (void)vsnprintf(first_error, sizeof(first_error), format, arguments);
    va_end(arguments);
}

static int refuse(const char *format, ...) {
    va_list arguments;

    (void)fprintf(stderr, "release-go custody helper: ");
    va_start(arguments, format);
    (void)vfprintf(stderr, format, arguments);
    va_end(arguments);
    (void)fputc('\n', stderr);
    return 1;
}

static bool same_object(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
           left->st_uid == right->st_uid && left->st_mode == right->st_mode &&
           left->st_nlink == right->st_nlink && left->st_size == right->st_size;
}

static uint64_t timespec_ns(struct timespec value) {
    if (value.tv_sec < 0 || value.tv_nsec < 0) {
        return UINT64_MAX;
    }
    if ((uint64_t)value.tv_sec > (UINT64_MAX - (uint64_t)value.tv_nsec) / 1000000000ULL) {
        return UINT64_MAX;
    }
    return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
}

static bool parse_u64(const char **cursor, uint64_t *value, bool final) {
    char *end = NULL;
    unsigned long long parsed;

    if (**cursor == '\0' || **cursor == '-' || **cursor == '+') {
        return false;
    }
    errno = 0;
    parsed = strtoull(*cursor, &end, 10);
    if (errno != 0 || end == *cursor) {
        return false;
    }
    if (final) {
        if (*end != '\0') {
            return false;
        }
    } else if (*end != ':') {
        return false;
    }
    *value = (uint64_t)parsed;
    *cursor = final ? end : end + 1;
    return true;
}

static bool parse_identity(const char *text, struct runtime_identity *identity) {
    const char *cursor = text;

    return parse_u64(&cursor, &identity->dev, false) &&
           parse_u64(&cursor, &identity->ino, false) &&
           parse_u64(&cursor, &identity->uid, false) &&
           parse_u64(&cursor, &identity->mode, false) &&
           parse_u64(&cursor, &identity->nlink, false) &&
           parse_u64(&cursor, &identity->mtime_ns, false) &&
           parse_u64(&cursor, &identity->ctime_ns, true);
}

static bool valid_runtime_name(const char *name) {
    size_t prefix_length = strlen(RUNTIME_PREFIX);
    size_t length = strlen(name);
    size_t index;

    if (length <= prefix_length || length >= MAX_RUNTIME_NAME ||
        strncmp(name, RUNTIME_PREFIX, prefix_length) != 0) {
        return false;
    }
    if (length - prefix_length < 6 || length - prefix_length > 32) {
        return false;
    }
    for (index = prefix_length; index < length; ++index) {
        unsigned char character = (unsigned char)name[index];
        if (!((character >= 'A' && character <= 'Z') ||
              (character >= 'a' && character <= 'z') ||
              (character >= '0' && character <= '9') || character == '_' ||
              character == '-')) {
            return false;
        }
    }
    return true;
}

static bool validate_runtime_identity(
    const struct stat *info,
    const struct runtime_identity *expected
) {
    return S_ISDIR(info->st_mode) && info->st_uid == caller_uid &&
           info->st_dev == (dev_t)expected->dev &&
           info->st_ino == (ino_t)expected->ino &&
           info->st_uid == (uid_t)expected->uid &&
           info->st_mode == (mode_t)expected->mode &&
           info->st_nlink == (nlink_t)expected->nlink &&
           timespec_ns(info->st_mtimespec) == expected->mtime_ns &&
           timespec_ns(info->st_ctimespec) == expected->ctime_ns &&
           (info->st_mode & ALLPERMS) == 0700;
}

static bool safe_child_name(const char *name) {
    return name[0] != '\0' && strcmp(name, ".") != 0 &&
           strcmp(name, "..") != 0 && strchr(name, '/') == NULL;
}

static bool validate_symlink_target(const char *target, size_t directory_depth) {
    char copy[PATH_MAX + 1];
    char *cursor;
    size_t depth = directory_depth;

    if (target[0] == '\0' || target[0] == '/' || strlen(target) > PATH_MAX) {
        return false;
    }
    (void)strlcpy(copy, target, sizeof(copy));
    cursor = copy;
    while (cursor != NULL) {
        char *next = strchr(cursor, '/');
        if (next != NULL) {
            *next = '\0';
            next += 1;
        }
        if (cursor[0] == '\0' || strcmp(cursor, ".") == 0) {
            return false;
        }
        if (strcmp(cursor, "..") == 0) {
            if (depth == 0) {
                return false;
            }
            depth -= 1;
        } else {
            depth += 1;
            if (depth > MAX_TREE_DEPTH) {
                return false;
            }
        }
        cursor = next;
    }
    return true;
}

static bool validate_entry(const struct stat *info, size_t depth) {
    mode_t permissions = info->st_mode & ALLPERMS;

    if (depth > MAX_TREE_DEPTH || info->st_dev != runtime_device ||
        info->st_uid != caller_uid) {
        return false;
    }
    if ((info->st_flags & ~(u_int32_t)CUSTODY_IMMUTABLE) != 0) {
        return false;
    }
    if (S_ISREG(info->st_mode)) {
        return info->st_nlink == 1 && (permissions == 0400 || permissions == 0500);
    }
    if (S_ISDIR(info->st_mode)) {
        return permissions == 0500;
    }
    if (S_ISLNK(info->st_mode)) {
        return info->st_nlink == 1;
    }
    return false;
}

static void free_entries(struct entry_list *list) {
    size_t index;

    for (index = 0; index < list->count; ++index) {
        free(list->items[index].name);
        free(list->items[index].link_target);
    }
    free(list->items);
    memset(list, 0, sizeof(*list));
}

static bool append_entry(struct entry_list *list, const struct entry_snapshot *entry) {
    struct entry_snapshot *resized;
    size_t capacity;

    if (list->count == list->capacity) {
        capacity = list->capacity == 0 ? 16 : list->capacity * 2;
        if (capacity > MAX_ENTRIES || capacity < list->capacity) {
            return false;
        }
        resized = realloc(list->items, capacity * sizeof(*resized));
        if (resized == NULL) {
            return false;
        }
        list->items = resized;
        list->capacity = capacity;
    }
    list->items[list->count] = *entry;
    list->count += 1;
    return true;
}

static char *read_link_at(int directory_fd, const char *name) {
    char buffer[PATH_MAX + 1];
    ssize_t length = readlinkat(directory_fd, name, buffer, PATH_MAX);
    char *result;

    if (length <= 0 || length > PATH_MAX) {
        return NULL;
    }
    buffer[length] = '\0';
    result = strdup(buffer);
    return result;
}

static bool snapshot_directory(int directory_fd, size_t depth, struct entry_list *list) {
    int scan_fd = dup(directory_fd);
    DIR *directory;
    struct dirent *entry;

    if (scan_fd < 0) {
        record_error("cannot duplicate directory descriptor: %s", strerror(errno));
        return false;
    }
    if (lseek(scan_fd, 0, SEEK_SET) < 0) {
        (void)close(scan_fd);
        record_error("cannot rewind directory descriptor: %s", strerror(errno));
        return false;
    }
    directory = fdopendir(scan_fd);
    if (directory == NULL) {
        (void)close(scan_fd);
        record_error("cannot inspect directory: %s", strerror(errno));
        return false;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        struct entry_snapshot snapshot;

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (!safe_child_name(entry->d_name) || ++visited_entries > MAX_ENTRIES) {
            record_error("unsafe or excessive tree entry rejected");
            (void)closedir(directory);
            return false;
        }
        memset(&snapshot, 0, sizeof(snapshot));
        if (fstatat(directory_fd, entry->d_name, &snapshot.info, AT_SYMLINK_NOFOLLOW) != 0) {
            record_error("cannot bind tree entry %s: %s", entry->d_name, strerror(errno));
            (void)closedir(directory);
            return false;
        }
        if (!validate_entry(&snapshot.info, depth + 1)) {
            record_error("unsafe tree entry rejected: %s", entry->d_name);
            (void)closedir(directory);
            return false;
        }
        snapshot.name = strdup(entry->d_name);
        if (snapshot.name == NULL) {
            record_error("tree entry allocation failed");
            (void)closedir(directory);
            return false;
        }
        if (S_ISLNK(snapshot.info.st_mode)) {
            snapshot.link_target = read_link_at(directory_fd, entry->d_name);
            if (snapshot.link_target == NULL ||
                !validate_symlink_target(snapshot.link_target, depth)) {
                free(snapshot.name);
                free(snapshot.link_target);
                record_error("unsafe symbolic link rejected: %s", entry->d_name);
                (void)closedir(directory);
                return false;
            }
        }
        if (!append_entry(list, &snapshot)) {
            free(snapshot.name);
            free(snapshot.link_target);
            record_error("tree entry allocation failed");
            (void)closedir(directory);
            return false;
        }
        errno = 0;
    }
    if (errno != 0) {
        record_error("directory enumeration failed: %s", strerror(errno));
        (void)closedir(directory);
        return false;
    }
    if (closedir(directory) != 0) {
        record_error("cannot close directory scan: %s", strerror(errno));
        return false;
    }
    return true;
}

static const struct entry_snapshot *find_entry(
    const struct entry_list *list,
    const char *name
) {
    size_t index;
    for (index = 0; index < list->count; ++index) {
        if (strcmp(list->items[index].name, name) == 0) {
            return &list->items[index];
        }
    }
    return NULL;
}

static bool revalidate_directory(int directory_fd, const struct entry_list *list) {
    int scan_fd = dup(directory_fd);
    DIR *directory;
    struct dirent *entry;
    size_t count = 0;

    if (scan_fd < 0) {
        record_error("cannot duplicate directory descriptor: %s", strerror(errno));
        return false;
    }
    if (lseek(scan_fd, 0, SEEK_SET) < 0) {
        (void)close(scan_fd);
        record_error("cannot rewind directory descriptor: %s", strerror(errno));
        return false;
    }
    directory = fdopendir(scan_fd);
    if (directory == NULL) {
        (void)close(scan_fd);
        record_error("cannot re-open directory scan: %s", strerror(errno));
        return false;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        const struct entry_snapshot *expected;
        struct stat current;
        char *target;

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        expected = find_entry(list, entry->d_name);
        if (expected == NULL ||
            fstatat(directory_fd, entry->d_name, &current, AT_SYMLINK_NOFOLLOW) != 0 ||
            !same_object(&expected->info, &current)) {
            record_error("tree entry changed during custody: %s", entry->d_name);
            (void)closedir(directory);
            return false;
        }
        if (S_ISLNK(current.st_mode)) {
            target = read_link_at(directory_fd, entry->d_name);
            if (target == NULL || expected->link_target == NULL ||
                strcmp(target, expected->link_target) != 0) {
                free(target);
                record_error("symbolic link changed during custody: %s", entry->d_name);
                (void)closedir(directory);
                return false;
            }
            free(target);
        }
        count += 1;
        errno = 0;
    }
    if (errno != 0 || count != list->count) {
        record_error("tree membership changed during custody");
        (void)closedir(directory);
        return false;
    }
    if (closedir(directory) != 0) {
        record_error("cannot close directory rescan: %s", strerror(errno));
        return false;
    }
    return true;
}

static int change_flags(int fd, u_int32_t flags) {
#ifdef WINS_CUSTODY_TESTING
    if (fault_after >= 0 && flag_calls++ == fault_after) {
        errno = EIO;
        return -1;
    }
#endif
    return fchflags(fd, flags);
}

static bool set_immutable_state(int fd, bool sealed) {
    struct stat before;
    struct stat after;
    u_int32_t expected;

    if (fstat(fd, &before) != 0) {
        record_error("cannot inspect opened tree object: %s", strerror(errno));
        return false;
    }
    expected = sealed ? (before.st_flags | CUSTODY_IMMUTABLE)
                      : (before.st_flags & ~(u_int32_t)CUSTODY_IMMUTABLE);
    if (change_flags(fd, expected) != 0) {
        record_error("fchflags failed: %s", strerror(errno));
        return false;
    }
    if (fstat(fd, &after) != 0 ||
        (after.st_flags & CUSTODY_IMMUTABLE) !=
            (sealed ? CUSTODY_IMMUTABLE : 0)) {
        record_error("kernel flag postcondition failed");
        return false;
    }
    return true;
}

static bool open_bound_child(
    int parent_fd,
    const struct entry_snapshot *entry,
    int *child_fd
) {
    int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
    struct stat opened;

    if (S_ISDIR(entry->info.st_mode)) {
        flags |= O_DIRECTORY;
    }
    *child_fd = openat(parent_fd, entry->name, flags);
    if (*child_fd < 0) {
        record_error("cannot open bound tree entry %s: %s", entry->name, strerror(errno));
        return false;
    }
    if (fstat(*child_fd, &opened) != 0 || !same_object(&entry->info, &opened)) {
        record_error("tree entry changed before descriptor open: %s", entry->name);
        (void)close(*child_fd);
        *child_fd = -1;
        return false;
    }
    return true;
}

static bool process_directory(int directory_fd, size_t depth, enum operation operation) {
    struct stat directory_before;
    struct stat directory_after;
    struct entry_list entries = {0};
    size_t index;
    bool ok = true;

    if (fstat(directory_fd, &directory_before) != 0 ||
        !validate_entry(&directory_before, depth)) {
        record_error("unsafe directory descriptor rejected");
        return false;
    }
    if (operation == OP_UNSEAL && !set_immutable_state(directory_fd, false)) {
        ok = false;
    }
    if (!snapshot_directory(directory_fd, depth, &entries)) {
        free_entries(&entries);
        return false;
    }
    for (index = 0; index < entries.count; ++index) {
        struct entry_snapshot *entry = &entries.items[index];
        int child_fd = -1;
        struct stat linked;

        if (S_ISLNK(entry->info.st_mode)) {
            continue;
        }
        if (!open_bound_child(directory_fd, entry, &child_fd)) {
            ok = false;
            continue;
        }
        if (S_ISDIR(entry->info.st_mode)) {
            if (!process_directory(child_fd, depth + 1, operation)) {
                ok = false;
            }
        } else if (operation == OP_SEAL) {
            if (!set_immutable_state(child_fd, true)) {
                ok = false;
            }
        } else if (operation == OP_UNSEAL) {
            if (!set_immutable_state(child_fd, false)) {
                ok = false;
            }
        } else {
            struct stat current;
            if (fstat(child_fd, &current) != 0 ||
                ((operation == OP_VERIFY_CLEAR) &&
                 (current.st_flags & CUSTODY_IMMUTABLE) != 0)) {
                record_error("tree flag verification failed: %s", entry->name);
                ok = false;
            }
        }
        if (fstatat(directory_fd, entry->name, &linked, AT_SYMLINK_NOFOLLOW) != 0 ||
            !same_object(&entry->info, &linked)) {
            record_error("tree entry changed after descriptor operation: %s", entry->name);
            ok = false;
        }
        (void)close(child_fd);
    }
    if (operation == OP_SEAL && !set_immutable_state(directory_fd, true)) {
        ok = false;
    }
    if (fstat(directory_fd, &directory_after) != 0 ||
        !same_object(&directory_before, &directory_after)) {
        record_error("directory identity changed during custody");
        ok = false;
    }
    if (operation == OP_VERIFY_CLEAR &&
        (directory_after.st_flags & CUSTODY_IMMUTABLE) != 0) {
        record_error("directory system flag residue remains");
        ok = false;
    }
    if (!revalidate_directory(directory_fd, &entries)) {
        ok = false;
    }
    free_entries(&entries);
    return ok;
}

static bool clear_tree(int tree_fd) {
    int attempt;
    bool cleared = false;

    for (attempt = 0; attempt < 3; ++attempt) {
        first_error[0] = '\0';
        visited_entries = 0;
        if (process_directory(tree_fd, 0, OP_UNSEAL)) {
            first_error[0] = '\0';
            visited_entries = 0;
            if (process_directory(tree_fd, 0, OP_VERIFY_CLEAR)) {
                cleared = true;
                break;
            }
        }
    }
    return cleared;
}

static bool seal_tree(int tree_fd) {
    first_error[0] = '\0';
    visited_entries = 0;
    if (!process_directory(tree_fd, 0, OP_INSPECT)) {
        return false;
    }
    first_error[0] = '\0';
    visited_entries = 0;
    if (!process_directory(tree_fd, 0, OP_SEAL)) {
        char seal_error[sizeof(first_error)];
        (void)strlcpy(seal_error, first_error, sizeof(seal_error));
        if (!clear_tree(tree_fd)) {
            record_error("partial seal rollback failed after: %s", seal_error);
        } else {
            (void)strlcpy(first_error, seal_error, sizeof(first_error));
        }
        return false;
    }
    return true;
}

static bool bind_fixed_tree(
    const char *runtime_name,
    const struct runtime_identity *expected,
    int *runtime_fd,
    int *exec_fd,
    int *tree_fd,
    struct stat *tree_identity
) {
    int private_fd = -1;
    struct stat private_info;
    struct stat runtime_info;
    struct stat exec_info;

    *runtime_fd = -1;
    *exec_fd = -1;
    *tree_fd = -1;
    private_fd = open(PRIVATE_TMP, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (private_fd < 0 || fstat(private_fd, &private_info) != 0 ||
        !S_ISDIR(private_info.st_mode) || private_info.st_uid != 0 ||
        (private_info.st_mode & ALLPERMS) != 01777) {
        record_error("private runtime parent contract rejected");
        goto fail;
    }
    *runtime_fd = openat(
        private_fd, runtime_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    if (*runtime_fd < 0 || fstat(*runtime_fd, &runtime_info) != 0 ||
        !validate_runtime_identity(&runtime_info, expected) ||
        runtime_info.st_dev != private_info.st_dev) {
        record_error("runtime identity or owner contract rejected");
        goto fail;
    }
    runtime_device = runtime_info.st_dev;
    *exec_fd = openat(
        *runtime_fd, "exec", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    if (*exec_fd < 0 || fstat(*exec_fd, &exec_info) != 0 ||
        !S_ISDIR(exec_info.st_mode) || exec_info.st_uid != caller_uid ||
        exec_info.st_dev != runtime_device ||
        ((exec_info.st_mode & ALLPERMS) != 0700 &&
         (exec_info.st_mode & ALLPERMS) != 0500) ||
        exec_info.st_flags != 0) {
        record_error("runtime exec directory contract rejected");
        goto fail;
    }
    *tree_fd = openat(
        *exec_fd, "tree", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    if (*tree_fd < 0 || fstat(*tree_fd, tree_identity) != 0 ||
        !validate_entry(tree_identity, 0) || !S_ISDIR(tree_identity->st_mode)) {
        record_error("runtime execution tree contract rejected");
        goto fail;
    }
    (void)close(private_fd);
    return true;

fail:
    if (*tree_fd >= 0) {
        (void)close(*tree_fd);
        *tree_fd = -1;
    }
    if (*exec_fd >= 0) {
        (void)close(*exec_fd);
        *exec_fd = -1;
    }
    if (*runtime_fd >= 0) {
        (void)close(*runtime_fd);
        *runtime_fd = -1;
    }
    if (private_fd >= 0) {
        (void)close(private_fd);
    }
    return false;
}

static bool confirm_tree_binding(int exec_fd, const struct stat *expected) {
    struct stat current;
    if (fstatat(exec_fd, "tree", &current, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_object(expected, &current)) {
        record_error("runtime execution tree path changed during custody");
        return false;
    }
    return true;
}

#ifndef WINS_CUSTODY_TESTING
static bool mutation_requires_privilege(enum operation operation) {
    return operation == OP_SEAL || operation == OP_UNSEAL;
}

static bool close_inherited_descriptors(void) {
    struct rlimit limit;
    rlim_t descriptor;

    if (getrlimit(RLIMIT_NOFILE, &limit) != 0 || limit.rlim_cur == RLIM_INFINITY ||
        limit.rlim_cur > 1048576) {
        return false;
    }
    for (descriptor = 3; descriptor < limit.rlim_cur; ++descriptor) {
        (void)close((int)descriptor);
    }
    return true;
}
#endif

static void clear_environment(void) {
    static char *empty_environment[] = {NULL};
    environ = empty_environment;
}

static int run_operation(
    enum operation operation,
    const char *runtime_name,
    const char *identity_text
) {
    struct runtime_identity expected;
    struct stat tree_identity;
    int runtime_fd = -1;
    int exec_fd = -1;
    int tree_fd = -1;
    bool ok = false;

    if (!valid_runtime_name(runtime_name) || !parse_identity(identity_text, &expected) ||
        expected.uid != (uint64_t)caller_uid) {
        return refuse("runtime name or identity contract rejected");
    }
#ifndef WINS_CUSTODY_TESTING
    if (mutation_requires_privilege(operation) && geteuid() != 0) {
        return refuse("privileged helper is not executing with effective uid 0");
    }
#endif
    first_error[0] = '\0';
    if (!bind_fixed_tree(
            runtime_name,
            &expected,
            &runtime_fd,
            &exec_fd,
            &tree_fd,
            &tree_identity)) {
        return refuse("%s", first_error[0] == '\0' ? "tree binding failed" : first_error);
    }
#ifdef WINS_CUSTODY_TESTING
    if (pause_ready_fd >= 0 && pause_continue_fd >= 0) {
        char byte = 'R';
        if (write(pause_ready_fd, &byte, 1) != 1 ||
            read(pause_continue_fd, &byte, 1) != 1) {
            record_error("test synchronization failed");
        }
    }
#endif
    if (first_error[0] == '\0') {
        if (operation == OP_SEAL) {
            ok = seal_tree(tree_fd);
        } else if (operation == OP_UNSEAL) {
            ok = clear_tree(tree_fd);
        } else {
            visited_entries = 0;
            ok = process_directory(tree_fd, 0, operation);
        }
    }
    if (!confirm_tree_binding(exec_fd, &tree_identity)) {
        ok = false;
    }
    (void)close(tree_fd);
    (void)close(exec_fd);
    (void)close(runtime_fd);
    if (!ok) {
        return refuse("%s", first_error[0] == '\0' ? "custody operation failed" : first_error);
    }
    return 0;
}

#ifdef WINS_CUSTODY_TESTING
static bool parse_test_long(const char *text, long *value) {
    char *end = NULL;
    long parsed;
    errno = 0;
    parsed = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed < -1) {
        return false;
    }
    *value = parsed;
    return true;
}

static bool parse_test_fd(const char *text, int *value) {
    long parsed;
    if (!parse_test_long(text, &parsed) || parsed < 0 || parsed > INT_MAX) {
        return false;
    }
    *value = (int)parsed;
    return true;
}

static int test_partial(
    bool unseal_failure,
    const char *runtime_name,
    const char *identity_text,
    const char *fault_text
) {
    int result;
    if (!parse_test_long(fault_text, &fault_after)) {
        return refuse("invalid test fault point");
    }
    flag_calls = 0;
    if (unseal_failure) {
        fault_after = -1;
        result = run_operation(OP_SEAL, runtime_name, identity_text);
        if (result != 0) {
            return result;
        }
        if (!parse_test_long(fault_text, &fault_after)) {
            return refuse("invalid test fault point");
        }
        flag_calls = 0;
        result = run_operation(OP_UNSEAL, runtime_name, identity_text);
        if (result != 0) {
            return result;
        }
    } else {
        result = run_operation(OP_SEAL, runtime_name, identity_text);
        if (result == 0) {
            return refuse("test seal unexpectedly succeeded past injected failure");
        }
    }
    fault_after = -1;
    flag_calls = 0;
    return run_operation(OP_VERIFY_CLEAR, runtime_name, identity_text);
}
#endif

int main(int argc, char **argv) {
    enum operation operation;
    const char *action;
    int result;

    caller_uid = getuid();
#ifdef WINS_CUSTODY_TESTING
    if (argc >= 2 && strcmp(argv[1], "test-inspect-pause") == 0) {
        if (argc != 6 || !parse_test_fd(argv[4], &pause_ready_fd) ||
            !parse_test_fd(argv[5], &pause_continue_fd)) {
            return refuse("malformed test pause action");
        }
        return run_operation(OP_INSPECT, argv[2], argv[3]);
    }
    if (argc >= 2 && strcmp(argv[1], "test-seal-failure") == 0) {
        if (argc != 5) {
            return refuse("malformed test seal failure action");
        }
        return test_partial(false, argv[2], argv[3], argv[4]);
    }
    if (argc >= 2 && strcmp(argv[1], "test-unseal-failure") == 0) {
        if (argc != 5) {
            return refuse("malformed test unseal failure action");
        }
        return test_partial(true, argv[2], argv[3], argv[4]);
    }
#else
    if (!close_inherited_descriptors()) {
        return refuse("cannot close inherited descriptors");
    }
#endif
    clear_environment();
    if (argc == 2 && strcmp(argv[1], "contract") == 0) {
        (void)puts(HELPER_CONTRACT);
        return 0;
    }
    if (argc != 4) {
        return refuse("usage: helper ACTION RUNTIME_LEAF RUNTIME_IDENTITY");
    }
    action = argv[1];
    if (strcmp(action, "inspect") == 0) {
        operation = OP_INSPECT;
    } else if (strcmp(action, "seal") == 0) {
        operation = OP_SEAL;
    } else if (strcmp(action, "unseal") == 0) {
        operation = OP_UNSEAL;
    } else if (strcmp(action, "verify-clear") == 0) {
        operation = OP_VERIFY_CLEAR;
    } else {
        return refuse("unknown custody action");
    }
    result = run_operation(operation, argv[2], argv[3]);
    return result;
}
