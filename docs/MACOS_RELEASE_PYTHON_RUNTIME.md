# macOS ReleasePython runtime owner provision

`tools/provision_macos_release_python_runtime.sh` is a non-mutating repository
diagnostic. It never invokes sudo, never downloads, never reads a password, and
never logs a password. Pin and helper identity live in
`tools/macos_release_python_runtime.custody.json` plus
`tools/toolchain-pins.json`.

## Repository diagnostics stop before privilege

No repository shell or Python file is a privileged installer. Diagnostics may
read pins and report custody state as the invoking owner, but they refuse euid
0 and cannot publish `/Library/WinsVPN/ReleasePython/3.14.7`. They do not trust
`SUDO_UID`, `SUDO_GID`, a captured terminal, or caller-provided repository
identity. Privileged installation starts only at the separately reviewed fixed
native bootstrap described below.

## Schema-v3 external owner boundary and native launcher

`tools/macos_release_python_owner_provision.py` is the reviewed transaction
controller. It is not the production invocation authority. The fixed native
launcher in `tools/macos_release_python_owner_launcher.c` establishes that
authority before Python starts. The deterministic warning-clean producer is
`tools/build_macos_release_python_owner_launcher.sh`.

`tools/install_macos_release_python_owner_provision.sh` is non-privileged
preflight only. Root must never interpret repository-owned shell or Python
installer bytes. The only permitted privileged installer is the independently
reviewed C bootstrap in `tools/macos_release_python_owner_bootstrap.c`, built by
`tools/build_macos_release_python_owner_bootstrap.sh`, after its exact produced
Mach-O bytes have been hash-selected by the owner and installed at:

```
/Library/WinsVPN/ReleasePythonAuthority/v2/owner-installer-bootstrap
```

The producer accepts exactly `ABSOLUTE_OUTPUT ABSOLUTE_INPUT_CLOSURE_MANIFEST`.
It performs a closure-probe build and two warning-clean final builds, requires
the final Mach-O bytes and traced SDK closures to be identical, and publishes a
canonical manifest covering the C source, build script, retained build-support
program, exact clang, linker, codesign tool, every fixed helper, and every
compiler/linker SDK input or symlink. The installed bootstrap must be
root:wheel, mode 0555, single-link, system immutable, and match the exact
produced Mach-O SHA-256 selected by the owner.

The v2 parent is itself a create-only owner trust-root action. After a no-follow
check proves the path is absent, the exact command is:

```
/usr/bin/sudo -n /bin/mkdir -m 0755 \
  /Library/WinsVPN/ReleasePythonAuthority/v2
```

The command must fail rather than repair if the leaf already exists. Before
running `install-self`, verify the new directory is root:wheel, mode 0755,
non-symbolic, and has no extended ACL. The bootstrap independently retains and
rechecks this ancestry before its first write. No repository-owned shell or
Python runs as root in this placement step.

The privileged CLI accepts only:

```
/absolute/reviewed/owner-installer-bootstrap install-self \
  /absolute/reviewed/owner-installer-bootstrap REVIEWED_BOOTSTRAP_SHA256
/Library/WinsVPN/ReleasePythonAuthority/v2/owner-installer-bootstrap install \
  ABSOLUTE_CONTROLLER REVIEWED_CONTROLLER_SHA256 \
  ABSOLUTE_LAUNCHER REVIEWED_LAUNCHER_SHA256
```

`install-self` is the sole first-publication exception to fixed-path execution.
The executing thin arm64 bootstrap must be the named external source and match
the owner-selected digest. It publishes create-only with `RENAME_EXCL`, fully
synchronizes the file and directory, and seals the fixed v2 bootstrap
root:wheel, mode 0555, single-link, and `schg`. A byte-identical sealed retry is
accepted. A different or malformed target is never replaced or unsealed.
This first digest selection is the explicit owner trust-root action in the
2026-09-03 ruling. The bootstrap does not claim that a binary can
cryptographically attest its own SHA-256. The exact root invocation records
which reviewed digest the owner selected; the later authority is separately
covered by the pinned owner Ed25519 key.

Those four operands are the exact token order emitted by the non-privileged
preflight. The destinations are fixed in native code, never caller-selected:

```
/Library/WinsVPN/ReleasePythonAuthority/v2/owner-provision
/Library/WinsVPN/ReleasePythonAuthority/v2/owner-launcher
```

The repository shell does not install, elevate, build the launcher, download or
install Python, create an authority, publish a receipt, consume an
authorization, clear flags, or migrate a runtime. It rejects root execution,
checks the fixed bootstrap and exact source hashes without mutation, prints the
handoff, and remains OWNER-BLOCKED. Automated release work must not invoke it
with sudo or through a root shell.

Before its first write under `/Library`, the bootstrap opens every controller
and launcher path component with no-follow descriptor custody, requires
single-link bounded sources with the two exact owner-selected hashes, arms
source vnode watches, and revalidates retained and named identity, byte digest,
and ancestry. Role checks prevent path/hash-pair transposition: the controller
must have the reviewed fixed ASCII Python header, while the launcher must be a
thin arm64 `MH_EXECUTE` with exactly one code-signature command and must contain
the selected controller digest. The bootstrap copies only from retained source
descriptors into a root-private pair-derived stage, uses exclusive publication,
never overwrites or clears an installed leaf, fully synchronizes file and
directory transitions, and seals both fixed leaves root:wheel, mode 0555,
single-link, and `schg`. An exact already-installed pair and an exact partial
publication are the only retry states;
different, symbolic, multiply linked, ACL-bearing, or otherwise drifted state
fails closed.

### V1 is an inert sealed fossil

The 2026-09-03 owner ruling supersedes the v1 updater policy. Every installed
v1 leaf remains sealed and unmodified as audit evidence. No v1 binary may be
executed, including a diagnostic verb, and no v1 flag may be cleared. V2 has no
updater or transition agent. Any future v2 pair change requires a new dated
owner ruling and a separately reviewed mechanism at a previously absent path.

The installed pair accepts only the fixed immutable external authority:

```
/Library/WinsVPN/ReleasePythonAuthority/v2/authority.json
```

That initially absent leaf is created only by the installed v2 launcher and
controller using:

```
/Library/WinsVPN/ReleasePythonAuthority/v2/owner-launcher publish-authority \
  ABSOLUTE_AUTHORITY ABSOLUTE_OWNER_SIGNED_ENVELOPE
```

The create-only publisher binds the current immutable receipt bytes, new
17-file closure, native capability, runtime hashes, and a pinned fresh owner
Ed25519 key. It uses an exact-input journal and exclusive rename, then seals the
leaf root:wheel, mode 0444, single-link, and `schg`. Recovery accepts the same
authority bytes and transaction identity. If the short-lived envelope expires,
the owner may sign a fresh envelope over those identical authority bytes; the
journal advances to its new digest without changing the stage identity. A
preexisting target without that journal, a mismatched journal generation, or
any unowned stage fails closed. Resume remains available after the authority's
own validity interval only when the journal proves it was created while those
exact authority bytes were current and the replacement envelope is current.
This can finish or clean the exact publication transaction; it does not make an
expired authority valid for plan, apply, or selftest.

The external authority uses contract v2 and schema version 3. For one
migration it binds the current and candidate receipt, exact 17-file repository
closure, installed controller bytes, native launcher binary SHA-256, native
launcher C-source SHA-256, native launcher build-script SHA-256, migration
plan, authorization path, repository root, exact executed compiler and linker
SHA-256 values, complete traced SDK-closure SHA-256, sequence, nonce, issue
time, and short expiry. The authority `key_id` is the lowercase 32-byte
Ed25519 public key in hex. A canonical signed authorization binds the same
native derivation and is consumed by advancing the authority sequence. Receipt
and authority publication are journaled and fully synced. Cleanup removes
staging and rollback files first, the next-journal next, and the current
journal last only after the new pair reaches the reauthenticated `verified`
phase. Every unlink and directory fsync is idempotent. After a crash following
journal removal, recovery accepts only an exact schema-v3 authority/receipt
terminal pair with no transaction residue, reopens and validates the repository
and dependency closure, requires the authority to be currently active, and
repeats runtime authentication. Journaled recovery is distinct: its journal
must have been created while its authority was active and recovery must begin
within 30 minutes of that exact timestamp, allowing at most 30 seconds of
future clock skew. Authority expiry never creates an unbounded recovery
capability. Repository files
cannot create or replace the external trust root.

The v2 generation activation may consume the exact externally hash-bound
schema-v3 v1-generation receipt only as the migration source for sequence 1
`apply` and recovery of that apply. It never authenticates that old-closure
receipt as a v2 endpoint.
The v2 authority separately binds the receipt bytes, runtime launcher, Mach-O,
new repository closure, installed controller, and installed launcher identity.
Normal selftest and every post-activation invocation require a fresh schema-v3
receipt whose custody closure equals the v2 authority closure.
Selftest is intentionally unavailable between initial authority publication
and the sequence-one apply. That interval is an activation transaction, not a
valid v2 endpoint.
Recovery has one narrow exception for exact generation-3 through generation-5
publication interruptions. Before either active leaf is modified, immutable
mode-0400 old authority and receipt recovery anchors are created and fully
synced. If an immutable clear, rename, or reseal crashes, the production
recovery entry may authenticate only those old anchors through the root-owned
mode-0600 journal, exact phase and generation, exact old/new/stage geometry,
closure, sequence, and independently derived next authority, while no
next-journal exists. This exception is available only to `recover`; normal
apply remains blocked. Any missing, extra, stale, writable, unsealed, or drifted
input remains OWNER-BLOCKED. Recovery then restores the exact old pair or
completes the exact staged pair before normal runtime authentication resumes.

Production publication, apply, recovery, and selftest accept only the native
launcher CLI:

```
/Library/WinsVPN/ReleasePythonAuthority/v2/owner-launcher selftest
/Library/WinsVPN/ReleasePythonAuthority/v2/owner-launcher recover
/Library/WinsVPN/ReleasePythonAuthority/v2/owner-launcher publish-authority \
  ABSOLUTE_AUTHORITY ABSOLUTE_OWNER_SIGNED_ENVELOPE
/Library/WinsVPN/ReleasePythonAuthority/v2/owner-launcher apply \
  ABSOLUTE_PLAN ABSOLUTE_AUTHORIZATION
```

The visible owner-controlled root shell supplies exactly `HOME=/var/root` and
`TMPDIR=/private/tmp`; every other input environment variable is rejected. The
native launcher verifies its fixed process path, euid, root-owned non-writable
ancestry, system-immutable mode-0555 single-link binary, controller, runtime
launcher, and ReleasePython Mach-O. It embeds the reviewed source and
build-script hashes. The deterministic build also embeds the exact executed
compiler hash, exact linker hash, and a complete manifest hash for every SDK
file or symlink consumed by compiler and linker traces. It measures its final
binary at runtime, avoiding a self-hash cycle. The final launcher hash therefore
binds the source snapshot, build script, compiler, linker, SDK closure,
controller, and authority-selected runtime leaves.

The launcher creates a fresh 256-bit nonce and local socketpair, retains all
inputs, forks once, and keeps the authenticated native parent alive. Before the
fork it recursively opens every regular file, directory, and symbolic link in
the fixed ReleasePython root. Every ancestor must be root-owned and not writable
by non-root; every runtime node must be root-owned, non-writable, system
immutable in production, and free of setuid, setgid, and sticky bits.
Directories and executable files must be exact mode 0555; data,
dylib, bundle, and extension files must be exact mode 0444. Regular files are
single-link and hash-bound; symlink targets
must remain inside the runtime root. The parent retains every descriptor, exact
identity, byte digest, directory inventory, and symlink target, arms a kqueue
watch over the complete tree, and revalidates the entire closure after the
child exits. The runtime root must contain exactly `Python.framework`, `vendor`,
and `launcher`. The launcher also computes receipt-compatible content hashes
for all three trees. Apply and recovery compare those hashes to the held active
receipt, whose complete bytes are selected by the external authority.

The child keeps the authenticated runtime executable open as descriptor 197
across `execve`; descriptors 198 and 199 carry the capability socket and exact
controller. The launcher also retains the launcher leaf, controller leaf, and
every launcher, controller, and runtime ancestor until the child and all known
descendants are gone. It never closes the selected executable descriptor and
then reopens its pathname. Directory ancestors are watched only for
rename/delete/revoke and are revalidated by stable identity, so unrelated
sibling writes do not create a false rejection. Retained leaves and runtime
nodes keep their stricter mutation watches and full identity checks. The exact
retained pathname is used only while the leaf, every ancestor, and the complete
runtime tree remain descriptor-bound, identity-bound, immutable, and watched.
Any relevant event or identity drift fails closed before authority is consumed.
Python verifies descriptor 197 against both the running base executable and
the authority-selected Mach-O digest before any transaction API is accepted.

Every Mach-O image in the runtime is parsed directly from its retained FD.
Thin arm64 images remain valid. There is one required, path-scoped Intel
exception: `Python.framework/Versions/3.14/bin/python3.14-intel64` must be a
thin 64-bit x86_64/X86_64_ALL `MH_EXECUTE`. It is never an eligible runtime
interpreter, and every in-tree Mach-O dependency it loads must remain
universal2. The launcher requires exactly one such path and rejects thin x86_64
at every other runtime path. This exception is the native-launcher counterpart
of the schema-v3 receipt's fixed second authority entrypoint; it does not widen
the receipt schema. A universal2 interpreter is accepted only when
its bounded fat table contains exactly one arm64/ARM64_ALL slice and one
x86_64/X86_64_ALL slice, with exact table-to-inner-header identity, alignment,
non-overlap, bounds, and no extra architecture. Executable policy and code
signature checks apply to the arm64 slice of every image, to the x86_64 slice
of every universal2 image, and transitively across the Intel shim's dependency
closure. The interpreter must be exact `MH_EXECUTE`; dylibs and bundles must
match their roles. Every selected slice must carry exactly one nonzero
deployment command targeting at most macOS 13.0. `LC_BUILD_VERSION` must
identify platform macOS; legacy `LC_VERSION_MIN_MACOSX` is accepted for the
pinned older x86_64 wheel slices. Executables require exactly one
`LC_LOAD_DYLINKER` containing `/usr/lib/dyld`; non-executables require none.
Every image requires one bounded `LC_CODE_SIGNATURE` whose actual embedded
CodeDirectory uses SHA-256 and whose page hashes match the retained bytes. A
missing, malformed, out-of-bounds, or tampered static signature fails closed.
Loaded dependencies must be exact and may resolve only within the retained
runtime root or the fixed macOS system locations. `LC_RPATH`, `@rpath`, loader
escapes, weak/upward/lazy loads, duplicate or unresolved dependencies,
malformed load commands, and non-system absolute dependencies fail closed.

Python runs with `-I -S`, a descriptor path for the already-open controller,
an empty constructed environment, and the three fixed inherited descriptors.
It must consume the one-use framed capability, prove that the live parent PID
is executing the exact held native launcher, reconcile every measured hash
with the external authority and active receipt, complete a nonce-bound READY/GO
exchange, and retain the socket for PING/PONG liveness checks through
publication or recovery. `selftest` completes the same authenticated
READY/GO/PING exchange without consuming an authority sequence. It also
requires the exact currently valid immutable authority and active schema-v3
receipt, reopens the authority-selected repository closure, retains every
package, Sigstore, trusted-root, verifier, and wheel descriptor, performs
offline Sigstore verification, and revalidates all custody before returning.
Captured
records, imported modules, `runpy`, `-c`, `-m`, arbitrary Python, replaced
descriptors, changed argv, and environment injection have no live matching
native parent and fail closed.

The native protocol has one monotonic absolute 300-second deadline, a 16 KiB
total protocol cap, 128-message cap, and 96-PING cap. The child is isolated in
its own process group. The parent repeatedly inventories descendants by PID,
including children that call `setsid()`, and kills and proves every tracked PID
gone after the controller exits. Python reauthentication children use a fixed
no-descendant process limit and fail if any descendant appears. Stdout and
stderr are streamed by the native parent with
separate exact 256 KiB caps. Timeout, slowloris input, output flood, protocol
flood, crash, or surviving or unprovable descendant causes process-group and
per-PID kill plus bounded fail-closed cleanup. Post-publication Python
reauthentication uses the same output caps,
an absolute 180-second deadline, and process-group cleanup instead of
capture-all output.

Python-visible `sys.argv`, `sys.orig_argv`, `sys.executable`, module globals,
and environment values remain checked as defense in depth. They are not the
invocation authority. The capability must be present, one-use, live, and bound
to the retained native process and controller descriptor before any production
API can proceed. The controller derives the non-root reauthentication UID from
the externally signed `authorized_repo_root`, verifies that it names a real
local account, and never trusts caller-authored `SUDO_UID` or `SUDO_GID`.

The active schema-v3 receipt repeats the exact launcher path, final launcher
binary hash, C-source hash, build-script hash, primary ReleasePython launcher
hash, underlying framework Mach-O hash, and complete framework, vendor, and
launcher tree content hashes. The native parent measures those same three tree
hashes from retained descriptors and sends them in its live capability. The
controller rejects any difference from the held authority-selected receipt.
The native parent retains the complete runtime tree; the controller independently retains the installed native
launcher, controller, both runtime launcher leaves, underlying Mach-O, and all
ancestors. macOS vnode watches plus exact descriptor, inode, byte, flag, mode,
link, pathname, inventory, and ancestry checks remain active before and after
every publication or recovery transition. The fixed controller is loaded from
the native launcher's retained no-follow descriptor, then independently
reopened and matched to the external authority before a transaction begins.
Non-root execution, writable or multiply linked authority state, user-only
immutable flags, stale plans, replayed sequences, and partial unrecognized
publication are also refused.

The package, fixed Sigstore bundle, Sigstore trusted-root JSON, reviewed
`cosign` verifier, and every pinned wheel must each occupy the
exact content-addressed production location
`/Library/WinsVPN/ReleasePythonInputs/sha256/SHA256/LEAF`, where `SHA256` is the
leaf digest. They must be root-owned, system immutable, exact mode 0444
(0555 only for the verifier),
single-link, non-writable, free of setid/setgid/sticky bits, and held with every
ancestor outside owner-writable custody. No Downloads path is a production
fallback. They are opened once
through retained no-follow descriptors before candidate preflight. Their file
and ancestor descriptors remain held and vnode-watched through receipt and
authority publication, recovery, final runtime reauthentication, and cleanup.
The package digest and `pkgutil --check-signature` operate on that same held
package inode via `/dev/fd`; the signed status line, PSF installer identity,
trusted timestamp, bundle digest, wheel inventory, and candidate receipt must
all agree. The authority-bound pin manifest must contain exactly wheel keys
`0` through `wheel_count - 1`, plus exact verifier, trusted-root, bundle,
certificate identity, and HTTPS OIDC issuer records. The verifier runs from
its retained descriptor with a scrubbed environment, bounded output and
deadline, no descendants, an exact trusted root, and offline bundle mode. Its
success must validate the Fulcio certificate and expected identity,
transparency evidence, artifact signature, and retained package digest. A
missing tool, root, policy, malformed bundle, arbitrary text, or nonzero
verification result remains OWNER-BLOCKED. Published-mode reauthentication
repeats the current dependency
checks and fails closed on any leaf, ancestor, pathname, inode, byte, mode,
link, or transient event drift.

## Current package-input status

As of 2026-08-31, a freshly downloaded Python.org package and source archive,
their Sigstore bundles, the commit-pinned Sigstore trusted root, cosign v3.1.3,
25 runtime wheels, and three producer-only x86_64 wheel counterparts are
staged under `~/.xprize/relpy-work/runtime2/inputs` for owner review. They
remain outside installed production custody. The non-privileged installer
preflight verifies all 34
leaves against `tools/macos_release_python_inputs.custody.json` and correctly
does not write `/Library`:

- package: `python-3.14.7-macos11.pkg`
- package SHA-256: `70c5239ad2d62925d2947e46921d0ddd3d35be3d2f0a2d50db33da507dbcb419`
- Sigstore bundle SHA-256:
  `c8e8af7129581634031508dbbf4831b0436e11716796d85eccb08f305664dd6b`
- source archive SHA-256:
  `3b48dac8fb59f62eaa67ac83c1eb12bda1b7a08406dd286e252c11a66be27f81`
- source Sigstore bundle SHA-256:
  `6f41efc358b146b5548dbfc0414e9247441f8524fb6ef59f1c4ca946ffc70701`

The fresh read-only `/usr/sbin/pkgutil --check-signature` result reports a
trusted notarized Developer ID Installer chain for Python Software Foundation
team `BMM5U3QVKW`, with a trusted timestamp. Offline cosign verification of the
fixed bundle and package reports `Verified OK` for certificate identity
`hugo@python.org` and OIDC issuer `https://github.com/login/oauth`. Those checks
establish the staged bytes only. They are sufficient input for an authenticated
pre-placement distribution build, but installed production custody remains
OWNER-BLOCKED until the owner places and reseals the exact inputs through the
reviewed content-addressed installer and the fixed controller re-verifies their
retained inodes. No production input, runtime, launcher, authority,
authorization, or receipt was installed by this work.

The reviewed non-root producer entrypoint is
`tools/produce_macos_release_python_runtime_13.py`. Before it delegates any
work, it retains and authenticates one custody closure containing the production
implementation, materializer, CPython-derived C entrypoint, input generator and
manifest, pin manifest, archive wrapper, native launcher, and the relevant
hostile tests. The production implementation executes from the retained bytes;
the materializer and its inputs execute from private mode-0400 snapshots of the
same closure.

The producer opens all 34 staged leaves through one retained source-directory
descriptor with `openat` and `O_NOFOLLOW`, then holds every source descriptor
while copying into a new private mode-0700 scratch directory with `O_EXCL`.
It validates each source identity before and after copying, independently
rehashes every destination leaf, seals the snapshot directory mode 0500, and
uses only snapshot paths for package inspection, Sigstore verification,
materialization, source extraction, and x86_64 wheel merging. Coordinated
cosign or x86_64 wheel path substitution fails before any consumer executes.
The producer authenticates both Python.org Sigstore bundles, extracts
`Programs/python.c` from the authenticated CPython 3.14.7 source archive, and
requires it to equal the closure-bound C entrypoint. It
materializes only the first 25 wheels, fuses the three exact x86_64 native
counterparts, removes the headless worker's unsupported GUI and development
closures, and builds the direct universal2 interpreter plus the exact thin
x86_64 shim. The direct entrypoint is compiled twice at the same path and both
outputs must be byte-identical. The producer records and revalidates the exact
clang and linker hashes plus the reported and resolved SDK identities and SDK
version across both builds. It preserves the real deployment metadata and requires every
slice to carry exactly one nonzero deployment command targeting macOS 13 or
earlier. Modern `LC_BUILD_VERSION` must identify macOS; legacy x86_64
`LC_VERSION_MIN_MACOSX` remains valid for the pinned older-wheel slices. It
deletes every `LC_RPATH` per slice,
makes every retained in-tree dependency relocatable, and signs every retained
Mach-O plus the nested app and framework with the fixed
owner Developer ID Application identity, hardened runtime, and secure
timestamp. Only the Python.app executable, direct universal2 interpreter, and
exact thin Intel interpreter shim receive
`com.apple.security.cs.allow-unsigned-executable-memory=true`, which is required
for the x86_64 CPython `_ctypes`/libffi closure under the hardened runtime;
every other executable, library, and bundle receives no runtime-exception
entitlement. All retained dependencies use contained `@loader_path` load
commands, all dylibs receive one resolvable canonical `@loader_path`
`LC_ID_DYLIB`, and absolute non-system dependencies are rejected by both the
producer and native launcher. The producer audits minimum version, RPATH,
dependency names, duplicate dependencies, dylib ID, and dynamic linker for
each architecture independently; the native launcher repeats the transitive
per-slice closure validation.
Every retained symlink must resolve to existing content inside the candidate.

The complete signed `Python.framework`, `vendor`, and `launcher` payload plus
one hash-bound pre-submission evidence file are then placed in a flat component
package rooted at `/Library/WinsVPN`. Before any build output is created, the
producer requires the fixed App Store Connect key, key ID, and a UUID-shaped
`WINS_NOTARY_ISSUER` supplied by the release environment. It records the
complete unsigned package hash, Developer ID Installer-signs the outer package
with a secure timestamp, requires the exact team identity and Apple Developer ID
certificate chain, and
submits the whole signed package. An Accepted response is not sufficient by
itself: the matching notary log must bind the job ID, exact archive filename,
and submitted package SHA-256 with no issues. The producer then staples only
the final package. Stapling is terminal: no code, framework, payload, or
container byte is signed or rewritten afterward.

The producer validates the staple immediately after stapling. Final
verification rechecks the outer Installer signature, requires Gatekeeper's
notarized `install` policy result, and expands the package into an isolated
private scratch directory. It requires exact package metadata, disables bundle
relocation, permits no scripts, and verifies every BOM path, mode, size, and
`root:wheel` owner mapping. AppleDouble records must map exactly to native
payload paths; the verifier normalizes them with `dot_clean` and rejects stray
`._` files. The install root is fixed at mode `0755`, and the
payload root contains only `ReleasePython/3.14.7` and
`evidence/pre-submission.json`. The expanded payload manifest also catches any
case-variant collapse. The producer then rechecks every nested Developer ID
signature, the transitive per-slice dependency policy, applies Gatekeeper to
the nested app, and executes both the hardened arm64 runtime and the exact thin
x86_64 shim. The producer returns 0 only after all steps pass and the terminal
package SHA-256 still equals the immediate post-staple SHA-256.

Producer success is intentionally pre-placement evidence, not a publishable
schema-v3 receipt. That receipt binds root-owned immutable installed inode
identities plus the installed controller, native launcher, external authority,
and fixed `/Library/WinsVPN/ReleasePython/3.14.7` paths. It can therefore be
created only after the separately authorized privileged placement ceremony.
No producer or staging lane may fabricate those fields from a user-owned work
directory.

The build script copies the already-open C source descriptor into a mode-0400
private snapshot and compiles only that snapshot. It hashes and retains the
exact compiler and linker, captures compiler dependency and linker input traces,
constructs the complete SDK input closure, retains the closure plus every
ancestor descriptor, and rejects rename/delete/revoke or pathname identity
drift through final compilation. It performs a probe plus two separately signed
final builds under a scrubbed environment, requires byte-identical final
outputs, and revalidates every toolchain input after each build.

Publication uses an unpredictable private mode-0700 directory under a retained
output-directory descriptor. It creates the launcher exclusively, writes from
the retained build output, applies mode 0555, fsyncs and reopens the file,
atomically renames without replacement, fsyncs the directory, and verifies the
published inode and digest through retained descriptors. Exact retries preserve
the existing inode. A post-rename failure removes only the inode proven to be
the just-published retained stage, then fsyncs and permits a clean retry. Local
startup recovery scans at most 4,096 output-directory entries and at most 16
exact random stage names. It removes only an empty exact mode-0700 same-owner
stage or a stage containing one single-link mode-0500/0555 launcher whose bytes
match the current deterministic build. Unknown or malformed residue fails
closed. Hostile tests use actual hard exits after directory creation and after
the staged launcher is fully synced, then prove exact retry cleanup; malformed
residue is retained and blocks publication. Other local controls cover
reserved output leaves matching
`.winsvpn-owner-launcher-stage-[0-9a-f]{48}`, which are rejected before any
build or cleanup action,
transient source/compiler and `/Applications` ancestor substitution,
preexisting-output refusal, and post-rename rollback. A
deterministic native runtime/controller fixture executes the same selftest and
apply handshake without requiring or skipping an installed launcher.
