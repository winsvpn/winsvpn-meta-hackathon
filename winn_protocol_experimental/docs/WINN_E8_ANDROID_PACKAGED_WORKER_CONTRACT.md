# Winn E8 Android packaged retained-worker contract

Status: quarantined E8 integration contract; no release authority

The Android application must package the E8 worker as an installed native
artifact. It must never download, copy, extract, write, or `chmod` executable
worker content at runtime.

## 1. Fixed artifact

The only admitted filename is:

```text
libwinn_e8_worker.so
```

The Android host resolves it as:

```kotlin
File(applicationInfo.nativeLibraryDir, "libwinn_e8_worker.so")
```

The Go controller opens that exact path read-only and no-follow, measures the
retained descriptor, verifies the exact Android arm64 PIE form, and executes
the same descriptor through `/proc/self/fd/3`. Android's Go target necessarily
uses the fixed `/system/bin/linker64` interpreter; the verifier admits only
that interpreter and rejects every `DT_NEEDED`, RPATH, and RUNPATH entry. Path
replacement cannot replace the retained executable.

## 2. Worker build

Generate a fresh 32-byte lowercase-hex build ID for each release build. Obtain
the lowercase SHA-256 of the sole APK signing certificate from the protected
release-signing configuration. Build with the exact package name and
monotonic version code:

```sh
CGO_ENABLED=0 GOOS=android GOARCH=arm64 \
go build -trimpath -buildvcs=false -tags winn_incomplete_e8 \
  -ldflags="-s -w \
  -X main.androidPackageName=org.winsvpn.app \
  -X main.androidPackageVersion=<version-code> \
  -X main.androidSigningCertSHA256=<64-lowercase-hex> \
  -X main.androidWorkerBuildID=<64-lowercase-hex>" \
  -o app/src/main/jniLibs/arm64-v8a/libwinn_e8_worker.so \
  ./cmd/winn-local-sealed-node
```

The installed worker emits those values only after it has proved that fd 3 is
the executing inode and measured its own bytes. The controller requires the
emitted package, version, certificate, and build ID to match the
PackageManager proof. E2 and E5 carry the measured executable SHA-256 of those
exact embedded bytes.

## 3. Gradle/manifest packaging

The application must use extracted legacy JNI-library packaging so
`ApplicationInfo.nativeLibraryDir` names a PackageManager-installed executable
file. The worker must not be stripped or transformed after the Go digest is
recorded.

`build.gradle.kts`:

```kotlin
android {
    sourceSets["main"].jniLibs.srcDir("src/main/jniLibs")

    packaging {
        jniLibs {
            useLegacyPackaging = true
            keepDebugSymbols += "**/libwinn_e8_worker.so"
        }
    }
}
```

`AndroidManifest.xml` application element:

```xml
<application
    android:extractNativeLibs="true"
    ... />
```

The release task must compute the worker SHA-256 after all build steps and
must fail if the bytes inside the final APK entry
`lib/arm64-v8a/libwinn_e8_worker.so` differ. The installed file measurement is
again checked at runtime, so an APK/install transform fails closed.

## 4. PackageManager/JNI proof

The signed app host must derive all fields in one call from its own
`PackageManager` and `ApplicationInfo`. It must not accept any of them from an
intent, shell argument, preference, network response, or writable file.

Required Android-side checks:

```kotlin
val pm = context.packageManager
val packageName = context.packageName
val app = pm.getApplicationInfo(packageName, 0)
val pkg = pm.getPackageInfo(
    packageName,
    PackageManager.PackageInfoFlags.of(
        PackageManager.GET_SIGNING_CERTIFICATES.toLong()
    )
)
val currentSigners = pkg.signingInfo.apkContentsSigners
check(currentSigners.size == 1)
check(app.uid == Process.myUid())

val baseApk = File(app.sourceDir).canonicalFile
val nativeDir = File(app.nativeLibraryDir).canonicalFile
val worker = File(nativeDir, "libwinn_e8_worker.so").canonicalFile
check(worker.parentFile == nativeDir)
```

It must SHA-256:

- `currentSigners.single().toByteArray()`;
- the complete `base.apk`;
- the complete installed worker.

It then passes these in memory across the JNI boundary as the exact
`e8AndroidPackageManagerProof` shape:

```json
{
  "package_name": "org.winsvpn.app",
  "package_uid": 10000,
  "version_code": 3000001,
  "signing_certificate_sha256": "<64-lowercase-hex>",
  "base_apk_path": "/data/app/.../base.apk",
  "base_apk_sha256": "<64-lowercase-hex>",
  "native_library_dir": "/data/app/.../lib/arm64",
  "worker_sha256": "<64-lowercase-hex>",
  "worker_build_id": "<64-lowercase-hex>"
}
```

The production JNI wrapper must construct the Go proof directly in memory and
call `prepareAndroidPackagedLocalFourNode`. It must not use the physical-test
environment/file adapter. The Go boundary fixes the schema, filename, proof
version, validation bit, and binding object digest; the caller cannot supply
those authority fields.

## 5. Fail-closed requirements

Production resolution refuses:

- a UID other than the current app UID;
- any path outside `/data/app`;
- a native-library directory outside the `base.apk` install root;
- noncanonical paths or any symlink component;
- writable install root, native-library directory, base APK, or worker;
- group/world-writable package files;
- any worker filename other than the fixed name;
- APK, worker, certificate, version, build-ID, or object-digest drift;
- a non-arm64 PIE, any interpreter other than `/system/bin/linker64`, or any
  `DT_NEEDED`, RPATH, or RUNPATH entry;
- any package/build identity not emitted by the executing retained worker;
- path/inode replacement before E5 contract activation.

The retained worker still uses kernel `SCM_CREDENTIALS`, `/proc` start ticks,
pidfd ownership, deferred sealed contract fd 4, and private `SOCK_SEQPACKET`
fd 5. Ready, Start, and Terminal must retain the exact E2/E5 PID and start
ticks.
