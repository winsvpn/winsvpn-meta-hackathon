#ifndef RUNNER_LINUX_SECURE_STORE_H_
#define RUNNER_LINUX_SECURE_STORE_H_

#include <gio/gio.h>

#include <string>

bool IsAllowedLinuxSecureTextName(const std::string& name);

bool ReadLinuxSecureText(const std::string& name,
                         std::string* plaintext,
                         bool* found,
                         std::string* error,
                         GCancellable* cancellable = nullptr);

bool WriteLinuxSecureText(const std::string& name,
                          const std::string& plaintext,
                          std::string* error,
                          GCancellable* cancellable = nullptr);

bool DeleteLinuxSecureText(const std::string& name,
                           std::string* error,
                           GCancellable* cancellable = nullptr);

// Hardens a legacy secure-state directory and its known files to owner-only
// (0700 directory, 0600 listed files), mirroring main()'s startup hardening so
// it can be exercised by unit tests. Missing, non-directory or symlinked
// targets and files whose names are not in the known list are left untouched;
// chmod failures are ignored.
void HardenLegacyStateDirectory(const std::string& directory);

#endif  // RUNNER_LINUX_SECURE_STORE_H_
