# Stage B engine artifact staging

This directory is intentionally source-free. The Stage B spike validates pinned,
read-only engine artifacts from the production repository custody tree and copies
them into a caller-owned derived output:

```text
Scripts/stage_stageb_engine_artifact.sh iphoneos /absolute/staging-root
Scripts/stage_stageb_engine_artifact.sh iphonesimulator /absolute/staging-root
```

The output root must already exist, use its canonical absolute spelling, be
owned by the caller, contain no symlink path component, and not be group- or
world-writable. It may contain unrelated entries, but the framework destination
must be absent. The command never changes unrelated entries and publishes
exactly this two-regular-file tree:

```text
WinsAmneziaWGPacketEngine.framework/
├── Info.plist
└── WinsAmneziaWGPacketEngine
```

It checks source-path custody, the pinned binary SHA-256, every Mach-O
architecture slice, each slice's build platform and minimum OS, the framework
install name, required defined exports (`nm -arch ... -gUj`), and an exact pinned
dependency set. `otool -L` is consumed by an exact grammar which rejects
missing prefixes, malformed version tuples, trailing data, controls, unsafe
path components, and anything outside the pinned set; the unit seam covers
mutated renderings without modifying a hash-pinned Mach-O. The generated
`Info.plist` is platform-specific: its supported
platform and minimum OS are derived from the validated slices (the maximum
slice minimum is used for a universal artifact). Source extended attributes
are not copied into the derived framework. Locally assigned extended
attributes (including macOS provenance) are outside the receipt's
regular-file content-and-mode attestation.

The shell opens the validated output root and source artifact once. A narrowly
scoped compiled publisher inherits those descriptors, reopens the root
descriptor-relatively with directory-only/no-follow flags, creates and owns
the staging descriptor, copies and generates both files, and keeps staging
non-writable to cooperating writers while waiting at the internal test
barrier. Immediately before publication it performs a closed-world
descriptor-relative enumeration: exactly the framework directory, then exactly
`Info.plist` and the binary; regular/no-symlink status; one hard link per file;
source-inode independence; exact modes; and final SHA-256 values. Darwin
requires write permission on a directory moved between parents, so the helper
restores framework mode `0755` inside its non-yielding final section and repeats
the file/tree checks before rename.

Publication uses `renameatx_np(..., RENAME_EXCL)` directly between the opened,
identity-checked staging and root directory descriptors. This remains
anchored if the original root pathname is renamed or rebound to a symlink, is
atomic, and cannot replace a destination created by a concurrent publisher.
Cleanup is likewise relative to the opened root/staging descriptors and never
recursively follows an injected symlink. Publication is intentionally
non-durable: the stager does not `fsync` the two files or their containing
directories, so a successful return is not a crash/power-loss durability
guarantee.

The one-line receipt uses a bespoke, fixed-order, compact JSON encoding; it is
not RFC 8785 JCS. All encoded values come from fixed constants or strictly
validated tokens. Receipt schema `winn-stageb-engine-artifact-receipt/4` records
`source_binary_sha256`, `binary_sha256`, `info_plist_sha256`, and
`regular_file_tree_manifest_sha256`. It also binds the exact embedded publisher
source, compiled publisher binary, and the raw bytes of the invoking stager
script through `publisher_source_sha256`, `publisher_binary_sha256`, and
`stager_script_sha256`. The stager digest is computed directly over the exact
script file before publication and is recomputed immediately before invoking
the publisher. It is an externally reproducible identification digest, not a
signature or an authenticity claim, and does not use a recursive embedded
self-hash constant. `developer_toolchain_selector_sha256` binds the selected
developer-directory path, Clang path and version rendering, and SDK path. It is
deliberately a selector-level provenance digest, not a content digest over the
compiler or SDK. The helper is compiled in a caller-private
temporary directory outside both source custody and the published tree; its
mode and hash are rechecked before use. The tree-manifest digest is SHA-256
over this exact UTF-8 byte sequence (with tabs and LF line endings):

```text
0444<TAB>{info-plist-sha256}<TAB>Info.plist<LF>
0555<TAB>{binary-sha256}<TAB>WinsAmneziaWGPacketEngine<LF>
```

The receipt also records `publication: atomic-no-replace-non-durable` to keep
that boundary explicit.

Successful `RENAME_EXCL` publication is the commit point. A subsequent failure
to verify or remove the now-empty private staging directory cannot convert the
committed framework into an unreceipted failure: the command emits exactly one
`publisher warning: framework publication committed; post-publication staging
cleanup failed at checkpoint 90` line on standard error, emits the normal
receipt on standard output, and returns success. The descriptor-anchored
staging directory may remain for diagnosis and explicit cleanup; it never
changes the already-published two-file framework.

This custody boundary does not claim protection against a malicious process
running concurrently as the same UID after publication. The framework consumer
must re-enumerate and re-hash the exact embedded/signed artifact immediately
before use; the later immutable build/runtime receipt remains mandatory.

The staged framework is not signed and is not evidence of runtime readiness.
The later generated Xcode/device lane must embed and sign it, bind both its
source and signed runtime hashes into the immutable build receipt, and prove the
native adapter starts the exact engine instance before any physical
protected-flow claim is made.
