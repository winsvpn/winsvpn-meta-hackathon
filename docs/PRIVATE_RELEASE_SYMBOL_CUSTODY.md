# Private release-symbol custody

Public release artifacts must have a matching, private symbol set. These files
are needed for crash diagnosis and must not be uploaded with customer binaries
or placed in a public CI artifact.

Obfuscation is not a secret-storage mechanism. Flutter's own documentation
states that storing secrets in an app is a poor security practice and that
obfuscation does not encrypt resources or protect against reverse engineering.
It only renames selected program symbols. A reusable key, token, password,
preshared key, or private key remains recoverable when compiled or copied into
an app. Release clients must obtain short-lived, least-privilege runtime
material after installation; long-lived credentials must never enter a
distributable. Durable secrets remain server-side.

The Android, Windows, and Linux release builders stage symbols under
`.artifacts/private-release-symbols/`, which is git-ignored. Each Flutter
builder:

1. creates private Flutter obfuscation symbols;
2. retains platform-native diagnostics (Android R8 mapping and native debug
   archive, or Linux split-DWARF companions);
3. strips delivery binaries where applicable;
4. writes `custody-manifest.json` with every private-file and release-artifact
   SHA-256, plus a SHA-256 sidecar for that manifest; and
5. immediately verifies the complete custody set.

Wear OS is not a Flutter target. Its private evidence is the R8 mapping under
`.artifacts/private-release-symbols/wear-os/<versionName>+<versionCode>/`.
The gate requires `isMinifyEnabled` and `isShrinkResources` in
`wear_os/app/build.gradle.kts` and fails closed if the mapping or AAB is
absent. Android phone and TV Flutter evidence must include both private
Flutter `.symbols` files and an authenticated R8 map (`mapping.txt` or
`proguard-mapping.txt`). The receipt then claims `flutter_obfuscation_flag_required`,
`split_debug_info_flag_required`, `android_r8_minify_required`, and
`private_r8_mapping_verified`.

watchOS ships inside the iOS App Store IPA. Apple project-level Release
settings must strip binaries (`STRIP_STYLE = all`, `COPY_PHASE_STRIP = YES`)
and keep dSYM separate (`DEBUG_INFORMATION_FORMAT = "dwarf-with-dsym"`). The
same strip and dSYM-separation settings are required for macOS Release
targets. The obfuscation gate fails closed if that IPA is missing or if the
embedded WatchKit executable is absent or unstripped. iOS and macOS receipts
claim `apple_dsym_separated` and `apple_strip_style_all_required`. Private
xcarchive dSYMs remain in `tools/apple_release_symbol_custody.py` custody,
never in the customer IPA or PKG.

Windows receipts claim `windows_pdb_separated`. The installer moves `.pdb`
and other private debug companions into the architecture-specific custody
directory and refuses to ship them. Linux receipts claim
`linux_split_dwarf_required`. The Linux builder keeps Flutter split-debug
info plus native `.debug` companions from `objcopy --only-keep-debug`,
strips delivery ELF files, and retains `.gnu_debuglink`. Delivery PE/ELF
inspection still rejects remaining debug sections.

`tools/release_obfuscation_contract.py` writes schema-v2 `manifest.json`
evidence. The exact schema binds the current contract source, app
version/build, artifact path/size/SHA-256, and private Flutter `.symbols`
files, the Wear R8 map, or the Android phone/TV R8 map. It also records that
the reviewed Flutter producer requires both `--obfuscate` and
`--split-debug-info`, that inspected delivery binaries have no private debug
sections, that source maps and symbol companions are absent from the customer
payload, and that the inspected blobs contain no recognized long-lived
credential. Shared secret-scan policy in
`tools/release_secret_scan_policy.py` rejects packaged private keys, reusable
tokens, Google service-account JSON, and activation secrets. Runtime-required
public pins, public keys, and public certificates remain allowed. Receipt
claims include `obfuscation_is_not_secret_protection` and
`durable_secrets_remain_server_side`. A schema-v1 receipt is intentionally
invalid and must be regenerated from a fresh build. A missing artifact or a
missing authenticated receipt fails closed.

The native checks are format-aware:

- ELF delivery files reject `.symtab`, DWARF, compressed DWARF, GDB indexes,
  legacy STABS, and embedded mini-debug data. Dynamic symbols and the
  `.gnu_debuglink` needed to associate a privately retained companion remain
  allowed.
- Mach-O delivery files reject `__DWARF`, `__debug*`, STABS, and local symbol
  entries. Required external ABI exports remain allowed.
- PE delivery files reject COFF symbol tables, `.debug*` sections, CodeView,
  embedded PDB, and other symbol-bearing debug-directory records. Reproducible
  build and extended-DLL-characteristic records are not symbol data and remain
  allowed. PDB files stay in private custody and never enter the installer.

Android App Bundles may retain only Google's exact store-scoped native-symbol
and ProGuard metadata paths under `BUNDLE-METADATA/`; these are inspected for
credentials and local paths. APKs and all other customer packages may contain
no `.symbols`, `.sym`, `.dbg`, `.pdb`, `.map`, dSYM, or equivalent private
companion, and no inline or external source-map reference.

The browser extension is deliberately different. Chrome Web Store policy
forbids obfuscation and concealment of functionality. Store-permitted
minification is required in packaged JavaScript: whitespace and comment
removal only. Identifier shortening, file collapsing, control-flow
concealment, encrypted strings, runtime unpacking, source maps, and hidden
functionality remain forbidden. Minification is a size transform; it is not
secret protection. Exact known-server-secret scans still fail closed, and
durable secrets remain server-side. The static producer check rejects
`javascript-obfuscator`, identifier-mangling `--minify`, and source-map
emission. Customer-zip verification fails closed if JavaScript is
pretty-printed, obfuscated, or missing, or if the authenticated receipt or
artifact is absent.

Windows builders protect custody directories with a non-inherited ACL limited
to the current user and LocalSystem. POSIX builders use mode `0700` for custody
directories and `0600` for files. This protects local staging; it is not a
backup and does not establish disaster recovery.

## Publication gate

No artifact is publication-ready until its exact custody directory has been
copied to an encrypted, access-controlled off-host store and the copy has been
restored or independently hash-verified against `custody-manifest.json` and
`custody-manifest.sha256`. Keep that backup outside the repository and outside
public CI artifacts. Do not put storage credentials, object URLs containing
credentials, or recovery keys in the manifest.

An off-host encrypted-copy receipt is still an external release gate. The
repository deliberately does not invent a receipt or silently mark this gate as
passed when no credentialed symbol vault is configured.

For opaque installer formats, the obfuscation receipt covers directly
inspectable bytes only. Publication additionally requires the canonical
platform artifact gate to bind and inspect the exact pre-container payload
inventory. In particular, the Windows cross-store gate validates the
installer-bound payload manifest and rescans every inventoried source file;
the receipt by itself must not be described as proof that an opaque Inno Setup
payload was expanded.

## Authoritative references

- Flutter: <https://docs.flutter.dev/deployment/obfuscate>
- Apple Xcode build settings: <https://developer.apple.com/documentation/xcode/build-settings-reference>
- Microsoft PE/COFF format: <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>
- GNU `strip`: <https://sourceware.org/binutils/docs/binutils/strip.html>
- Chrome Web Store code readability: <https://developer.chrome.com/docs/webstore/program-policies/code-readability>
- Android R8 / resource shrinking: <https://developer.android.com/build/shrink-code>
