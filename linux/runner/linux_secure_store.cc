#include "linux_secure_store.h"

#include <fcntl.h>
#include <libsecret/secret.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <set>
#include <string>

namespace {

constexpr size_t kMaximumSecureTextBytes = 4 * 1024 * 1024;
constexpr char kApplicationAttribute[] = "org.winsvpn.app";

const SecretSchema kSecureTextSchema = {
    "org.winsvpn.app.SecureText",
    SECRET_SCHEMA_NONE,
    {{"application", SECRET_SCHEMA_ATTRIBUTE_STRING},
     {"name", SECRET_SCHEMA_ATTRIBUTE_STRING},
     {nullptr, SECRET_SCHEMA_ATTRIBUTE_STRING}},
    0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr};

enum class LookupStatus { kFound, kNotFound, kError };

struct LegacyFile {
  int directory_fd = -1;
  int file_fd = -1;
  struct stat metadata = {};
  bool present = false;
};

void CloseLegacyFile(LegacyFile* legacy) {
  if (legacy == nullptr) return;
  if (legacy->file_fd >= 0) close(legacy->file_fd);
  if (legacy->directory_fd >= 0) close(legacy->directory_fd);
  legacy->file_fd = -1;
  legacy->directory_fd = -1;
  legacy->present = false;
}

void WipeString(std::string* value) {
  if (value == nullptr || value->empty()) return;
  volatile char* bytes = &(*value)[0];
  for (size_t index = 0; index < value->size(); ++index) bytes[index] = 0;
  value->clear();
}

bool IsValidSecureText(const std::string& value) {
  return value.size() <= kMaximumSecureTextBytes &&
         value.find('\0') == std::string::npos &&
         g_utf8_validate(value.data(), static_cast<gssize>(value.size()),
                         nullptr);
}

std::string UserDataDirectory() {
  const char* xdg = std::getenv("XDG_DATA_HOME");
  if (xdg != nullptr && *xdg != '\0') {
    return xdg[0] == '/' ? xdg : "";
  }
  const char* home = std::getenv("HOME");
  if (home == nullptr || home[0] != '/') return "";
  return std::string(home) + "/.local/share";
}

bool OpenDirectoryWithoutSymlinks(const std::string& absolute_path,
                                  int* directory_fd,
                                  bool* missing) {
  if (directory_fd == nullptr || missing == nullptr || absolute_path.empty() ||
      absolute_path.front() != '/') {
    return false;
  }
  *directory_fd = -1;
  *missing = false;
  int current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (current < 0) return false;
  size_t offset = 1;
  while (offset < absolute_path.size()) {
    const size_t slash = absolute_path.find('/', offset);
    const std::string component = absolute_path.substr(
        offset, slash == std::string::npos ? std::string::npos
                                           : slash - offset);
    offset = slash == std::string::npos ? absolute_path.size() : slash + 1;
    if (component.empty()) continue;
    if (component == "." || component == "..") {
      close(current);
      return false;
    }
    const int next = openat(current, component.c_str(),
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (next < 0) {
      const int saved_errno = errno;
      close(current);
      if (saved_errno == ENOENT) {
        *missing = true;
        return true;
      }
      return false;
    }
    close(current);
    current = next;
  }
  *directory_fd = current;
  return true;
}

bool OpenLegacyFile(const std::string& name,
                    LegacyFile* legacy,
                    std::string* error) {
  if (legacy == nullptr || error == nullptr ||
      !IsAllowedLinuxSecureTextName(name)) {
    if (error != nullptr) *error = "Secure text name is invalid.";
    return false;
  }
  CloseLegacyFile(legacy);
  const std::string root = UserDataDirectory();
  if (root.empty()) {
    *error = "Linux user data directory is unavailable.";
    return false;
  }
  bool missing = false;
  if (!OpenDirectoryWithoutSymlinks(root + "/wins_vpn",
                                    &legacy->directory_fd, &missing)) {
    *error = "Legacy secure state directory is unsafe.";
    return false;
  }
  if (missing) return true;
  struct stat directory_metadata = {};
  if (fstat(legacy->directory_fd, &directory_metadata) != 0 ||
      !S_ISDIR(directory_metadata.st_mode) ||
      directory_metadata.st_uid != geteuid() ||
      (directory_metadata.st_mode & 0077) != 0) {
    *error = "Legacy secure state directory is not owner-only.";
    CloseLegacyFile(legacy);
    return false;
  }
  legacy->file_fd = openat(legacy->directory_fd, name.c_str(),
                           O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  if (legacy->file_fd < 0) {
    if (errno == ENOENT) return true;
    *error = "Legacy secure text could not be opened safely.";
    CloseLegacyFile(legacy);
    return false;
  }
  if (fstat(legacy->file_fd, &legacy->metadata) != 0 ||
      !S_ISREG(legacy->metadata.st_mode) ||
      legacy->metadata.st_uid != geteuid() ||
      (legacy->metadata.st_mode & 0077) != 0 ||
      legacy->metadata.st_nlink != 1 || legacy->metadata.st_size < 0 ||
      static_cast<size_t>(legacy->metadata.st_size) >
          kMaximumSecureTextBytes) {
    *error = "Legacy secure text is not a bounded owner-only regular file.";
    CloseLegacyFile(legacy);
    return false;
  }
  legacy->present = true;
  return true;
}

bool ReadLegacyFile(LegacyFile* legacy,
                    std::string* plaintext,
                    std::string* error) {
  if (legacy == nullptr || plaintext == nullptr || error == nullptr ||
      !legacy->present || legacy->file_fd < 0) {
    if (error != nullptr) *error = "Legacy secure text state is invalid.";
    return false;
  }
  plaintext->assign(static_cast<size_t>(legacy->metadata.st_size), '\0');
  size_t offset = 0;
  while (offset < plaintext->size()) {
    const ssize_t count = pread(legacy->file_fd, &(*plaintext)[offset],
                                plaintext->size() - offset,
                                static_cast<off_t>(offset));
    if (count <= 0) {
      WipeString(plaintext);
      *error = "Legacy secure text could not be read completely.";
      return false;
    }
    offset += static_cast<size_t>(count);
  }
  if (!IsValidSecureText(*plaintext)) {
    WipeString(plaintext);
    *error = "Legacy secure text is corrupted.";
    return false;
  }
  return true;
}

bool WipeAndDeleteLegacyFile(const std::string& name,
                             LegacyFile* legacy,
                             std::string* error) {
  if (legacy == nullptr || error == nullptr || !legacy->present ||
      legacy->file_fd < 0 || legacy->directory_fd < 0) {
    if (error != nullptr) *error = "Legacy secure text state is invalid.";
    return false;
  }
  struct stat current = {};
  if (fstatat(legacy->directory_fd, name.c_str(), &current,
              AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(current.st_mode) ||
      current.st_dev != legacy->metadata.st_dev ||
      current.st_ino != legacy->metadata.st_ino) {
    *error = "Legacy secure text changed during migration.";
    return false;
  }
  std::array<char, 64 * 1024> zeros = {};
  off_t remaining = legacy->metadata.st_size;
  off_t offset = 0;
  while (remaining > 0) {
    const size_t chunk = static_cast<size_t>(
        std::min<off_t>(remaining, static_cast<off_t>(zeros.size())));
    const ssize_t written = pwrite(legacy->file_fd, zeros.data(), chunk, offset);
    if (written <= 0 || static_cast<size_t>(written) != chunk) {
      *error = "Legacy secure text could not be wiped.";
      return false;
    }
    offset += written;
    remaining -= written;
  }
  if (fsync(legacy->file_fd) != 0 || ftruncate(legacy->file_fd, 0) != 0 ||
      fsync(legacy->file_fd) != 0 ||
      unlinkat(legacy->directory_fd, name.c_str(), 0) != 0) {
    *error = "Legacy secure text could not be removed.";
    return false;
  }
  legacy->present = false;
  // The file is already unlinked and its contents were synchronously wiped.
  // Directory fsync is a best-effort durability barrier: retaining the
  // verified libsecret copy is safer than reporting data loss if a filesystem
  // does not support synchronizing directory descriptors.
  fsync(legacy->directory_fd);
  return true;
}

LookupStatus LookupSecret(const std::string& name,
                          std::string* plaintext,
                          std::string* error,
                          GCancellable* cancellable) {
  GError* secret_error = nullptr;
  gchar* password = secret_password_lookup_sync(
      &kSecureTextSchema, cancellable, &secret_error, "application",
      kApplicationAttribute, "name", name.c_str(), nullptr);
  if (secret_error != nullptr) {
    g_error_free(secret_error);
    *error = "Linux secret service is unavailable.";
    return LookupStatus::kError;
  }
  if (password == nullptr) return LookupStatus::kNotFound;
  plaintext->assign(password);
  secret_password_free(password);
  if (!IsValidSecureText(*plaintext)) {
    WipeString(plaintext);
    *error = "Stored Linux secure text is corrupted.";
    return LookupStatus::kError;
  }
  return LookupStatus::kFound;
}

bool ClearSecret(const std::string& name,
                 std::string* error,
                 GCancellable* cancellable) {
  GError* secret_error = nullptr;
  const gboolean cleared = secret_password_clear_sync(
      &kSecureTextSchema, cancellable, &secret_error, "application",
      kApplicationAttribute, "name", name.c_str(), nullptr);
  if (secret_error != nullptr) {
    g_error_free(secret_error);
    *error = "Linux secret service could not remove secure text.";
    return false;
  }
  if (cleared) return true;
  // FALSE without an error is libsecret's "no unlocked item matched". A name
  // that was never stored is already deleted, but only a lookup that finds
  // nothing proves that; a matching item that survived the clear still fails.
  std::string residue;
  std::string lookup_error;
  const LookupStatus status =
      LookupSecret(name, &residue, &lookup_error, cancellable);
  WipeString(&residue);
  if (status == LookupStatus::kNotFound) return true;
  *error = "Linux secret service could not remove secure text.";
  return false;
}

bool StoreSecretVerified(const std::string& name,
                         const std::string& plaintext,
                         std::string* error,
                         GCancellable* cancellable) {
  GError* secret_error = nullptr;
  const std::string label = "Win's VPN secure state: " + name;
  const gboolean stored = secret_password_store_sync(
      &kSecureTextSchema, SECRET_COLLECTION_DEFAULT, label.c_str(),
      plaintext.c_str(), cancellable, &secret_error, "application",
      kApplicationAttribute, "name", name.c_str(), nullptr);
  if (!stored || secret_error != nullptr) {
    if (secret_error != nullptr) g_error_free(secret_error);
    *error = "Linux secret service could not protect secure text.";
    return false;
  }
  std::string verified;
  const LookupStatus status =
      LookupSecret(name, &verified, error, cancellable);
  const bool matches = status == LookupStatus::kFound && verified == plaintext;
  WipeString(&verified);
  if (!matches) {
    // A readback error (including a cancelled verification at the request
    // deadline) does not undo the successful store above, and that store has
    // already replaced any previous value. Clearing here would destroy the
    // only copy, so keep it for a later read and report the write as
    // unverified. A readback that returns a different value or nothing is
    // still cleared, best effort and deliberately without a cancelled token.
    if (status != LookupStatus::kError) {
      std::string clear_error;
      ClearSecret(name, &clear_error, nullptr);
    }
    if (error->empty()) *error = "Linux secure text verification failed.";
    return false;
  }
  return true;
}

}  // namespace

bool IsAllowedLinuxSecureTextName(const std::string& name) {
  static const std::set<std::string> allowed = {
      "client_keypair.json", "calc_session.json",  "calc_state.json",
      "install_id.txt",      "node_cache.json",     "pending_logout.json",
      "user_pin.txt",        "vpn_config.txt",     "vpn_settings.txt",
      "wins_vpn_restart_config.conf",
      "winn3_keypair.json",
      "direct_udp_transport_memory.json",
  };
  return allowed.find(name) != allowed.end();
}

bool ReadLinuxSecureText(const std::string& name,
                         std::string* plaintext,
                         bool* found,
                         std::string* error,
                         GCancellable* cancellable) {
  if (plaintext == nullptr || found == nullptr || error == nullptr ||
      !IsAllowedLinuxSecureTextName(name)) {
    if (error != nullptr) *error = "Secure text name is invalid.";
    return false;
  }
  plaintext->clear();
  error->clear();
  *found = false;
  const LookupStatus status =
      LookupSecret(name, plaintext, error, cancellable);
  if (status == LookupStatus::kError) return false;

  LegacyFile legacy;
  if (!OpenLegacyFile(name, &legacy, error)) return false;
  if (status == LookupStatus::kFound) {
    if (legacy.present && !WipeAndDeleteLegacyFile(name, &legacy, error)) {
      WipeString(plaintext);
      CloseLegacyFile(&legacy);
      return false;
    }
    CloseLegacyFile(&legacy);
    *found = true;
    return true;
  }
  if (!legacy.present) {
    CloseLegacyFile(&legacy);
    return true;
  }

  if (!ReadLegacyFile(&legacy, plaintext, error) ||
      !StoreSecretVerified(name, *plaintext, error, cancellable)) {
    WipeString(plaintext);
    CloseLegacyFile(&legacy);
    return false;
  }
  if (!WipeAndDeleteLegacyFile(name, &legacy, error)) {
    WipeString(plaintext);
    CloseLegacyFile(&legacy);
    return false;
  }
  CloseLegacyFile(&legacy);
  *found = true;
  return true;
}

bool WriteLinuxSecureText(const std::string& name,
                          const std::string& plaintext,
                          std::string* error,
                          GCancellable* cancellable) {
  if (error == nullptr || !IsAllowedLinuxSecureTextName(name) ||
      !IsValidSecureText(plaintext)) {
    if (error != nullptr) *error = "Secure text name or value is invalid.";
    return false;
  }
  error->clear();
  LegacyFile legacy;
  if (!OpenLegacyFile(name, &legacy, error)) {
    CloseLegacyFile(&legacy);
    return false;
  }
  if (!StoreSecretVerified(name, plaintext, error, cancellable)) {
    CloseLegacyFile(&legacy);
    return false;
  }
  if (legacy.present && !WipeAndDeleteLegacyFile(name, &legacy, error)) {
    CloseLegacyFile(&legacy);
    return false;
  }
  CloseLegacyFile(&legacy);
  return true;
}

bool DeleteLinuxSecureText(const std::string& name,
                           std::string* error,
                           GCancellable* cancellable) {
  if (error == nullptr || !IsAllowedLinuxSecureTextName(name)) {
    if (error != nullptr) *error = "Secure text name is invalid.";
    return false;
  }
  error->clear();
  std::string clear_error;
  const bool cleared = ClearSecret(name, &clear_error, cancellable);
  if (!cleared) {
    // Fail closed: when the Secret Service could not be cleared, do not delete
    // the legacy migration file. The service being unreachable is exactly when
    // the legacy copy is the only recoverable data, so destroying it on a
    // failed delete would report failure while still losing data. This mirrors
    // ReadLinuxSecureText, which only wipes and removes the legacy file after a
    // successful verified store.
    *error = clear_error;
    return false;
  }
  LegacyFile legacy;
  const bool opened = OpenLegacyFile(name, &legacy, error);
  const bool removed = opened &&
                       (!legacy.present ||
                        WipeAndDeleteLegacyFile(name, &legacy, error));
  CloseLegacyFile(&legacy);
  return removed;
}

void HardenLegacyStateDirectory(const std::string& directory) {
  struct stat directory_stat = {};
  if (lstat(directory.c_str(), &directory_stat) != 0 ||
      !S_ISDIR(directory_stat.st_mode) || S_ISLNK(directory_stat.st_mode)) {
    return;
  }
  chmod(directory.c_str(), 0700);
  static const char* kLegacyFiles[] = {
      "client_keypair.json", "calc_session.json", "calc_state.json",
      "install_id.txt", "node_cache.json", "pending_logout.json",
      "user_pin.txt", "vpn_config.txt", "vpn_settings.txt",
      "wins_vpn_restart_config.conf", "winn3_keypair.json",
      "direct_udp_transport_memory.json", "wins_xray.log"};
  for (const char* file : kLegacyFiles) {
    const std::string path = directory + "/" + file;
    struct stat file_stat = {};
    if (lstat(path.c_str(), &file_stat) == 0 &&
        S_ISREG(file_stat.st_mode) && !S_ISLNK(file_stat.st_mode)) {
      chmod(path.c_str(), 0600);
    }
  }
}
