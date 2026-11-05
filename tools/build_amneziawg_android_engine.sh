#!/usr/bin/env bash
set -Eeuo pipefail

# Build the complete Android tunnel AAR from the exact official
# amnezia-vpn/amneziawg-android source tag. No prebuilt/base AAR is accepted:
# classes.jar and every native member are produced in this build.
#
# The reviewed in-tree overlay adds the WinsVPN JNI requirements not yet in
# the official tag: a four-argument awgTurnOn compatibility entry point and
# awgUpdateTunnelPeers. The official three-argument Java API remains as a
# wrapper. Final native members retain the app's established libam-* names,
# but every byte behind those names is compiled from the pinned official
# source and pinned submodules.
#
# Usage:
#   tools/build_amneziawg_android_engine.sh <output-aar>

die() {
  printf 'BUILD AMNEZIAWG ANDROID ENGINE ERROR: %s\n' "$*" >&2
  exit 1
}

[[ "$#" -eq 1 ]] || die "Usage: $0 <output-aar>. A base AAR is forbidden."

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
JNI_OVERLAY="${SCRIPT_DIR}/amneziawg_android_official_jni"
OUTPUT_AAR="$1"
case "${OUTPUT_AAR}" in
  /*) ;;
  *) OUTPUT_AAR="$(pwd -P)/${OUTPUT_AAR}" ;;
esac
[[ ! -d "${OUTPUT_AAR}" ]] || die "Output path is a directory: ${OUTPUT_AAR}"

AWG_ANDROID_REPO="https://github.com/amnezia-vpn/amneziawg-android.git"
AWG_ANDROID_TAG="v3.1.20260814"
AWG_ANDROID_COMMIT="5c16489e2cd9ed3a0a7a27c7445bba5238132f86"
AWG_TOOLS_COMMIT="ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"
ELF_CLEANER_COMMIT="7efc05090675ec6161b7def862728086a26c3b1f"
AWG_GO_MODULE="github.com/amnezia-vpn/amneziawg-go/v3"
# Companion latest upstream Go engine tag consumed by official Android go.mod.
# No GitHub Releases; stability designation unavailable.
# Same tag string as AWG_ANDROID_TAG, different repository and commit.
AWG_GO_TAG="v3.1.20260828"
AWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"
AWG_GO_SOURCE_SHA256="10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4"

REVIEWED_GO_VERSION="1.27.1"
GO_HOST_SHA256_DARWIN_ARM64="ee215d57e0ec269c60cc9ceca68e6bda321ba9ee5afe24f4b0988703c2d87d12"
GO_HOST_SHA256_DARWIN_AMD64="8f8f52c6649542cf027bbc9b9c68d1ec042f9f34808a40413f0b8b3f66f3caa4"
GO_HOST_SHA256_LINUX_AMD64="63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445"
GO_HOST_SHA256_LINUX_ARM64="3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec"

REVIEWED_NDK_VERSION="30.0.16248370"
NDK_CLANG_API_LEVEL="24"
REVIEWED_CMAKE_VERSION="3.22.1"
REVIEWED_COMPILE_SDK="36"
REVIEWED_BUILD_TOOLS_VERSION="36.0.0"
REVIEWED_GRADLE_VERSION="8.13"
GRADLE_DISTRIBUTION_SHA256="20f1b1176237254a6fc204d8434196fa11a4cfb387567519c61556e8710aed78"
GRADLE_WRAPPER_JAR_SHA256="81a82aaea5abcc8ff68b3dfcb58b3c3c429378efd98e7433460610fecd7ae45f"
ANDROID_PACKAGE_NAME="org.winsvpn.app"
ANDROID_ELF_PAGE_ALIGNMENT="0x4000"

# Reviewed hashes for every official file modified or directly consumed by
# the build-only overlay. Source changes fail closed before patching.
UPSTREAM_SETTINGS_SHA256="bb04781e5fc35a533302305ef4b18af028ff7df898814bcafaf4e60384124cb0"
UPSTREAM_WRAPPER_PROPERTIES_SHA256="cdab1ffb439219b1db125e3c99a86cf2424f8762b9b3faa404ed061e3635ecde"
UPSTREAM_TUNNEL_BUILD_SHA256="f053633a9b23024a43db460799ddb698d26fd1592fb40329e53142f9385f29ce"
UPSTREAM_CMAKE_SHA256="378eea69e266ba0efe61c32467141b3d9a7edca4e6afa6aad20bc65aba4d71f8"
UPSTREAM_MAKEFILE_SHA256="411cd58cfa642e28b1ab6f25d3cabee1076be4874c6b2c85885c90e7b6f2a6a9"
UPSTREAM_API_SHA256="34bd3f4824c267b89f50f3306a6872d5464b058f22ccfe1d40a5cbd87d0ea86b"
UPSTREAM_JNI_SHA256="640682de14205ad1b9b1909bd04c0a4c449cf59ffe2e6c7f45c57a9c3a827edd"
UPSTREAM_JAVA_SHA256="464b6dc476d2bf2f3f6700fc7000f46b5b4fe56c17e1de45933aa296b56ba70c"
UPSTREAM_GO_MOD_SHA256="cde303cebd847b122373b4d714645b8480d48283570ab9b0bc6540c364724a16"
UPSTREAM_GO_SUM_SHA256="f8de8667720b798be4a9f2db1dd5eff0cbf09d05409fa80bec8abc6049c79e3d"

# The official wrapper tag requires amneziawg-go v3.1.20260814 and no wrapper
# tag consumes the frozen engine tag yet. The build raises exactly that one
# requirement to AWG_GO_TAG. v3.1.20260814 and v3.1.20260828 share a
# byte-identical go.mod, so the dependency graph does not change and only the
# module zip hash differs. Both hashes are the sum.golang.org values.
WRAPPER_REQUIRED_ENGINE_TAG="v3.1.20260814"
WRAPPER_REQUIRED_ENGINE_H1="h1:l2AhBD+sFycU8Im81n/bZORMxW7fWtlZJEuJ4Hh0+z0="
AWG_GO_MODULE_H1="h1:D8d8gGvwXcTxUIsE4z6F6vjy4/VZddu95vMNtOygh1c="
OVERRIDDEN_GO_MOD_SHA256="05c0ab6a8b010a334e5443199789462ca2a29ede3e7a9b15e6049c9c13d1bd53"
OVERRIDDEN_GO_SUM_SHA256="b6e8c738a3eec160d0cc58d10ea6dbbf17886b122ed140a379bd9a29eec8df82"

OVERLAY_JAVA_SHA256="882e707172c6fa2cddf47dd06e10b1f66936dc1adfd16ec43522a5b16bb3b444"
OVERLAY_API_SHA256="26a9f47d9aa18f59844558b90f98b365173cab9be8a2553398eca801c27e449b"
OVERLAY_JNI_SHA256="56fac39edeffeba722b62f0f5513c53d4519e211dd9997c2d4a05c475e581be0"
OVERLAY_ADAPT_SHA256="6420d3b2bbde542ed739c83122d93110353c11229b22e757cc6a49493814de23"
OVERLAY_ADAPT_TEST_SHA256="712e8594654e24cb23dd151824d7a202b5cd4b437623dde0477e78b280b0b11c"
GRADLE_VERIFICATION_METADATA_SHA256="c1c4ed4a290e57e553e6928638a537e9a77e1b3f545971d27df7c36818cf4fa0"

REQUIRED_JNI_EXPORTS=$'Java_org_amnezia_awg_GoBackend_awgGetConfig\nJava_org_amnezia_awg_GoBackend_awgGetSocketV4\nJava_org_amnezia_awg_GoBackend_awgGetSocketV6\nJava_org_amnezia_awg_GoBackend_awgTurnOff\nJava_org_amnezia_awg_GoBackend_awgTurnOn\nJava_org_amnezia_awg_GoBackend_awgUpdateTunnelPeers\nJava_org_amnezia_awg_GoBackend_awgVersion'

WORK_ROOT=""
cleanup() {
  if [[ -n "${WORK_ROOT}" ]]; then
    case "${WORK_ROOT}" in
      "${TMPDIR:-/tmp}"/wins-awg-android-complete-aar.*)
        chmod -R u+w -- "${WORK_ROOT}" 2>/dev/null || true
        rm -rf -- "${WORK_ROOT}"
        ;;
      *) die "Refusing to remove an unsafe build work root: ${WORK_ROOT}" ;;
    esac
  fi
}
trap cleanup EXIT

sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

verify_sha256() {
  local path="$1" expected="$2" label="$3" actual
  [[ -f "${path}" ]] || die "Missing ${label}: ${path}"
  actual="$(sha256_file "${path}")"
  [[ "${actual}" == "${expected}" ]] \
    || die "${label} SHA-256 mismatch. Got ${actual}; expected ${expected}."
}

resolve_host_go_archive() {
  local host_os host_arch
  case "$(uname -s)" in
    Darwin) host_os="darwin" ;;
    Linux) host_os="linux" ;;
    *) die "Unsupported build host OS: $(uname -s)" ;;
  esac
  case "$(uname -m)" in
    arm64|aarch64) host_arch="arm64" ;;
    x86_64) host_arch="amd64" ;;
    *) die "Unsupported build host architecture: $(uname -m)" ;;
  esac
  case "${host_os}-${host_arch}" in
    darwin-arm64) printf '%s %s %s\n' "${host_os}" "${host_arch}" "${GO_HOST_SHA256_DARWIN_ARM64}" ;;
    darwin-amd64) printf '%s %s %s\n' "${host_os}" "${host_arch}" "${GO_HOST_SHA256_DARWIN_AMD64}" ;;
    linux-amd64) printf '%s %s %s\n' "${host_os}" "${host_arch}" "${GO_HOST_SHA256_LINUX_AMD64}" ;;
    linux-arm64) printf '%s %s %s\n' "${host_os}" "${host_arch}" "${GO_HOST_SHA256_LINUX_ARM64}" ;;
  esac
}

resolve_android_sdk() {
  local candidate
  for candidate in \
    "${ANDROID_HOME:-}" \
    "${ANDROID_SDK_ROOT:-}" \
    "${HOME}/.local/android-sdk" \
    "${HOME}/Library/Android/sdk" \
    "${HOME}/Android/Sdk"
  do
    if [[ -n "${candidate}" && -d "${candidate}" ]]; then
      (cd "${candidate}" && pwd -P)
      return 0
    fi
  done
  die "Android SDK not found. Set ANDROID_HOME or ANDROID_SDK_ROOT."
}

resolve_java_home() {
  local candidate="${JAVA_HOME:-}" version
  [[ -n "${candidate}" && -x "${candidate}/bin/java" && -x "${candidate}/bin/javap" ]] \
    || die "JAVA_HOME must point to a complete JDK with java and javap."
  version="$("${candidate}/bin/java" -version 2>&1 | head -n 1)"
  [[ "${version}" == *' version "17.'* ]] \
    || die "The official Android build requires JDK 17; found ${version}."
  (cd "${candidate}" && pwd -P)
}

resolve_real_ndk_tool() {
  local candidate="$1" candidate_dir resolved
  candidate_dir="$(cd "$(dirname "${candidate}")" 2>/dev/null && pwd -P)" \
    || return 1
  # GNU coreutils needs -e/-- while macOS realpath accepts the path directly.
  # In both cases, consume only the resolved regular executable, never a
  # symlink, and keep the resolution inside the exact pinned NDK bin directory.
  resolved="$(realpath -e -- "${candidate}" 2>/dev/null || realpath "${candidate}" 2>/dev/null || true)"
  [[ -n "${resolved}" && -f "${resolved}" && -x "${resolved}" && ! -L "${resolved}" ]] \
    || return 1
  case "${resolved}" in
    "${candidate_dir}"/*) ;;
    *) return 1 ;;
  esac
  printf '%s\n' "${resolved}"
}

resolve_ndk_home() {
  local sdk="${1:-}" ndk_home props revision
  if [[ -n "${sdk}" ]]; then
    ndk_home="${sdk}/ndk/${REVIEWED_NDK_VERSION}"
  else
    ndk_home="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
    if [[ -z "${ndk_home}" ]]; then
      sdk="$(resolve_android_sdk)"
      ndk_home="${sdk}/ndk/${REVIEWED_NDK_VERSION}"
    fi
  fi
  [[ -d "${ndk_home}" ]] \
    || die "Reviewed Android NDK ${REVIEWED_NDK_VERSION} is not installed at ${ndk_home}."
  props="${ndk_home}/source.properties"
  [[ -f "${props}" ]] \
    || die "NDK source.properties is missing under ${ndk_home}; cannot verify its version."
  revision="$(sed -n 's/^Pkg\.Revision[[:space:]]*=[[:space:]]*//p' "${props}" | head -n 1)"
  [[ "${revision}" == "${REVIEWED_NDK_VERSION}" ]] \
    || die "Reviewed Android NDK is ${REVIEWED_NDK_VERSION}; found ${revision:-unknown} at ${ndk_home}."
  (cd "${ndk_home}" && pwd -P)
}

resolve_ndk_clang() {
  local goarch="$1" ndk_home="${2:-}" candidate resolved prebuilt triple
  case "${goarch}" in
    arm64) triple="aarch64-linux-android" ;;
    amd64) triple="x86_64-linux-android" ;;
    arm) triple="armv7a-linux-androideabi" ;;
    386) triple="i686-linux-android" ;;
    *) die "Unsupported Android Go architecture: ${goarch}." ;;
  esac
  [[ -n "${ndk_home}" ]] || ndk_home="$(resolve_ndk_home)"
  for prebuilt in darwin-x86_64 linux-x86_64; do
    candidate="${ndk_home}/toolchains/llvm/prebuilt/${prebuilt}/bin/${triple}${NDK_CLANG_API_LEVEL}-clang"
    resolved="$(resolve_real_ndk_tool "${candidate}")" && {
      printf '%s\n' "${resolved}"
      return 0
    }
  done
  die "No ${triple}${NDK_CLANG_API_LEVEL}-clang found in the reviewed NDK."
}

resolve_llvm_strip() {
  local ndk_home="${1:-}" candidate resolved prebuilt
  [[ -n "${ndk_home}" ]] || ndk_home="$(resolve_ndk_home)"
  for prebuilt in darwin-x86_64 linux-x86_64; do
    candidate="${ndk_home}/toolchains/llvm/prebuilt/${prebuilt}/bin/llvm-strip"
    resolved="$(resolve_real_ndk_tool "${candidate}")" && {
      printf '%s\n' "${resolved}"
      return 0
    }
  done
  die "No llvm-strip found in the reviewed NDK."
}

resolve_ndk_tool() {
  local ndk_home="$1" tool="$2" prebuilt candidate resolved
  for prebuilt in darwin-x86_64 linux-x86_64; do
    candidate="${ndk_home}/toolchains/llvm/prebuilt/${prebuilt}/bin/${tool}"
    if resolved="$(resolve_real_ndk_tool "${candidate}")"; then
      printf '%s\n' "${resolved}"
      return 0
    fi
  done
  die "${tool} was not found under the reviewed NDK ${ndk_home}."
}

verify_sdk() {
  local sdk="$1" ndk
  ndk="$(resolve_ndk_home "${sdk}")"
  [[ -x "${sdk}/cmake/${REVIEWED_CMAKE_VERSION}/bin/cmake" ]] || die "CMake ${REVIEWED_CMAKE_VERSION} is missing."
  [[ -f "${sdk}/platforms/android-${REVIEWED_COMPILE_SDK}/android.jar" ]] || die "Android platform ${REVIEWED_COMPILE_SDK} is missing."
  [[ -x "${sdk}/build-tools/${REVIEWED_BUILD_TOOLS_VERSION}/aapt2" ]] \
    || die "Android build-tools ${REVIEWED_BUILD_TOOLS_VERSION} are missing."
  resolve_ndk_clang arm64 "${ndk}" >/dev/null
  resolve_ndk_clang amd64 "${ndk}" >/dev/null
  resolve_ndk_clang arm "${ndk}" >/dev/null
  resolve_ndk_clang 386 "${ndk}" >/dev/null
  resolve_llvm_strip "${ndk}" >/dev/null
}

download_reviewed_go() {
  local host_os host_arch expected archive go_root
  read -r host_os host_arch expected < <(resolve_host_go_archive)
  archive="${WORK_ROOT}/go${REVIEWED_GO_VERSION}.${host_os}-${host_arch}.tar.gz"
  curl --proto '=https' --tlsv1.2 -fsSL --retry 4 --retry-all-errors \
    "https://go.dev/dl/go${REVIEWED_GO_VERSION}.${host_os}-${host_arch}.tar.gz" -o "${archive}"
  verify_sha256 "${archive}" "${expected}" "Go ${REVIEWED_GO_VERSION} ${host_os}-${host_arch} archive"
  go_root="${WORK_ROOT}/reviewed-go"
  mkdir -p "${go_root}"
  tar -xzf "${archive}" -C "${go_root}" --strip-components=1
  [[ "$("${go_root}/bin/go" version)" == "go version go${REVIEWED_GO_VERSION} ${host_os}/${host_arch}" ]] \
    || die "Extracted Go toolchain identity mismatch."
  printf '%s %s %s\n' "${archive}" "${go_root}/bin/go" "${host_os}-${host_arch}"
}

verify_clean_official_checkout() {
  local src="$1" status
  [[ "$(git -C "${src}" rev-parse HEAD)" == "${AWG_ANDROID_COMMIT}" ]] \
    || die "Official checkout did not land on ${AWG_ANDROID_COMMIT}."
  [[ "$(git -C "${src}" rev-parse "refs/tags/${AWG_ANDROID_TAG}^{commit}")" == "${AWG_ANDROID_COMMIT}" ]] \
    || die "Tag ${AWG_ANDROID_TAG} no longer resolves to ${AWG_ANDROID_COMMIT}."
  [[ "$(git -C "${src}/tunnel/tools/amneziawg-tools" rev-parse HEAD)" == "${AWG_TOOLS_COMMIT}" ]] \
    || die "amneziawg-tools submodule identity mismatch."
  [[ "$(git -C "${src}/tunnel/tools/elf-cleaner" rev-parse HEAD)" == "${ELF_CLEANER_COMMIT}" ]] \
    || die "elf-cleaner submodule identity mismatch."
  status="$(git -C "${src}" status --porcelain=v1 --untracked-files=all)"
  [[ -z "${status}" ]] || die "Official checkout is dirty before the reviewed overlay: ${status}"

  verify_sha256 "${src}/settings.gradle.kts" "${UPSTREAM_SETTINGS_SHA256}" "official settings.gradle.kts"
  verify_sha256 "${src}/gradle/wrapper/gradle-wrapper.properties" "${UPSTREAM_WRAPPER_PROPERTIES_SHA256}" "official Gradle wrapper properties"
  verify_sha256 "${src}/gradle/wrapper/gradle-wrapper.jar" "${GRADLE_WRAPPER_JAR_SHA256}" "official Gradle wrapper JAR"
  verify_sha256 "${src}/tunnel/build.gradle.kts" "${UPSTREAM_TUNNEL_BUILD_SHA256}" "official tunnel Gradle module"
  verify_sha256 "${src}/tunnel/tools/CMakeLists.txt" "${UPSTREAM_CMAKE_SHA256}" "official CMake build"
  verify_sha256 "${src}/tunnel/tools/libwg-go/Makefile" "${UPSTREAM_MAKEFILE_SHA256}" "official Go Makefile"
  verify_sha256 "${src}/tunnel/tools/libwg-go/api-android.go" "${UPSTREAM_API_SHA256}" "official Go Android API"
  verify_sha256 "${src}/tunnel/tools/libwg-go/jni.c" "${UPSTREAM_JNI_SHA256}" "official JNI bridge"
  verify_sha256 "${src}/tunnel/src/main/java/org/amnezia/awg/GoBackend.java" "${UPSTREAM_JAVA_SHA256}" "official Java JNI declaration"
  verify_sha256 "${src}/tunnel/tools/libwg-go/go.mod" "${UPSTREAM_GO_MOD_SHA256}" "official Go module lock"
  verify_sha256 "${src}/tunnel/tools/libwg-go/go.sum" "${UPSTREAM_GO_SUM_SHA256}" "official Go checksum lock"
}

verify_overlay_inputs() {
  verify_sha256 "${JNI_OVERLAY}/GoBackend.java" "${OVERLAY_JAVA_SHA256}" "reviewed Java JNI overlay"
  verify_sha256 "${JNI_OVERLAY}/api-android.go" "${OVERLAY_API_SHA256}" "reviewed Go JNI overlay"
  verify_sha256 "${JNI_OVERLAY}/jni.c" "${OVERLAY_JNI_SHA256}" "reviewed C JNI overlay"
  verify_sha256 "${JNI_OVERLAY}/uapi_adapt.go" "${OVERLAY_ADAPT_SHA256}" "reviewed userspace adapter"
  verify_sha256 "${JNI_OVERLAY}/uapi_adapt_test.go" "${OVERLAY_ADAPT_TEST_SHA256}" "reviewed userspace adapter test"
  verify_sha256 "${JNI_OVERLAY}/gradle-verification-metadata.xml" "${GRADLE_VERIFICATION_METADATA_SHA256}" "isolated Gradle dependency verification metadata"
}

apply_reviewed_build_overlay() {
  local src="$1" makefile="${src}/tunnel/tools/libwg-go/Makefile"
  cp "${JNI_OVERLAY}/GoBackend.java" "${src}/tunnel/src/main/java/org/amnezia/awg/GoBackend.java"
  cp "${JNI_OVERLAY}/api-android.go" "${src}/tunnel/tools/libwg-go/api-android.go"
  cp "${JNI_OVERLAY}/jni.c" "${src}/tunnel/tools/libwg-go/jni.c"
  cp "${JNI_OVERLAY}/uapi_adapt.go" "${src}/tunnel/tools/libwg-go/uapi_adapt.go"
  cp "${JNI_OVERLAY}/uapi_adapt_test.go" "${src}/tunnel/tools/libwg-go/uapi_adapt_test.go"
  cp "${JNI_OVERLAY}/gradle-verification-metadata.xml" "${src}/gradle/verification-metadata.xml"

  sed -i.bak \
    "s/ndkVersion = \"26.1.10909125\"/ndkVersion = \"${REVIEWED_NDK_VERSION}\"/" \
    "${src}/settings.gradle.kts"
  sed -i.bak -e "/^distributionUrl=/a\\
distributionSha256Sum=${GRADLE_DISTRIBUTION_SHA256}" \
    "${src}/gradle/wrapper/gradle-wrapper.properties"
  sed -i.bak \
    -e '/NDK_GO_ARCH_MAP_arm64 := arm64/a\
NDK_GO_ARCH_MAP_aarch64 := arm64' \
    -e 's/-Wl,-soname=libwg-go.so/-Wl,-soname=libam-go.so -Wl,-z,common-page-size=16384/' \
    -e "s/GO_VERSION := 1.24.2/GO_VERSION := ${REVIEWED_GO_VERSION}/" \
    -e "s/GO_HASH_darwin-amd64 := .*/GO_HASH_darwin-amd64 := ${GO_HOST_SHA256_DARWIN_AMD64}/" \
    -e "s/GO_HASH_darwin-arm64 := .*/GO_HASH_darwin-arm64 := ${GO_HOST_SHA256_DARWIN_ARM64}/" \
    -e "s/GO_HASH_linux-amd64 := .*/GO_HASH_linux-amd64 := ${GO_HOST_SHA256_LINUX_AMD64}/" \
    -e "/GO_HASH_linux-amd64 :=/a\\
GO_HASH_linux-arm64 := ${GO_HOST_SHA256_LINUX_ARM64}" \
    -e 's#github.com/amnezia-vpn/amneziawg-go/ipc.socketDirectory#github.com/amnezia-vpn/amneziawg-go/v3/ipc.socketDirectory#' \
    "${makefile}"
  # NDK r30 bionic marks strtok() deprecated. The official CMake build uses
  # -Wall -Werror, so the unchanged amneziawg-tools wg-quick/android.c fails
  # to compile under the reviewed NDK. Keep the warning visible, but stop it
  # from being fatal. No source file and no Go/cgo flag changes.
  sed -i.bak \
    's/^add_compile_options(-Wall -Werror)$/add_compile_options(-Wall -Werror -Wno-error=deprecated-declarations)/' \
    "${src}/tunnel/tools/CMakeLists.txt"
  rm -f -- \
    "${src}/settings.gradle.kts.bak" \
    "${src}/gradle/wrapper/gradle-wrapper.properties.bak" \
    "${src}/tunnel/tools/CMakeLists.txt.bak" \
    "${makefile}.bak"

  # Raise the engine requirement to the frozen tag (see WRAPPER_REQUIRED_ENGINE_TAG).
  # The pristine upstream files were already verified by verify_clean_official_checkout.
  local gomod="${src}/tunnel/tools/libwg-go/go.mod" gosum="${src}/tunnel/tools/libwg-go/go.sum"
  sed -i.bak \
    "s#^\([[:space:]]*${AWG_GO_MODULE} \)${WRAPPER_REQUIRED_ENGINE_TAG}\$#\1${AWG_GO_TAG}#" \
    "${gomod}"
  sed -i.bak \
    -e "s#^\(${AWG_GO_MODULE} \)${WRAPPER_REQUIRED_ENGINE_TAG} ${WRAPPER_REQUIRED_ENGINE_H1}\$#\1${AWG_GO_TAG} ${AWG_GO_MODULE_H1}#" \
    -e "s#^\(${AWG_GO_MODULE} \)${WRAPPER_REQUIRED_ENGINE_TAG}/go.mod #\1${AWG_GO_TAG}/go.mod #" \
    "${gosum}"
  rm -f -- "${gomod}.bak" "${gosum}.bak"
  verify_sha256 "${gomod}" "${OVERRIDDEN_GO_MOD_SHA256}" "engine-overridden Go module lock"
  verify_sha256 "${gosum}" "${OVERRIDDEN_GO_SUM_SHA256}" "engine-overridden Go checksum lock"

  grep -Fqx "    ndkVersion = \"${REVIEWED_NDK_VERSION}\"" "${src}/settings.gradle.kts" \
    || die "NDK build-only pin was not applied exactly."
  grep -Fqx "distributionSha256Sum=${GRADLE_DISTRIBUTION_SHA256}" "${src}/gradle/wrapper/gradle-wrapper.properties" \
    || die "Gradle distribution checksum was not applied exactly."
  grep -Fqx 'add_compile_options(-Wall -Werror -Wno-error=deprecated-declarations)' "${src}/tunnel/tools/CMakeLists.txt" \
    || die "NDK r30 deprecated-declarations build-only relaxation was not applied exactly."
  grep -Fqx "GO_VERSION := ${REVIEWED_GO_VERSION}" "${makefile}" \
    || die "Go build-only pin was not applied exactly."
  grep -Fq "${AWG_GO_MODULE}/ipc.socketDirectory" "${makefile}" \
    || die "Go v3 link-time package path was not applied."
  grep -Fq 'soname=libam-go.so' "${makefile}" \
    || die "App-compatible libam-go SONAME was not applied."
  grep -Fq 'common-page-size=16384' "${makefile}" \
    || die "16K common page size was not applied to the Go linker."
  grep -Fqx $'\t'"${AWG_GO_MODULE} ${AWG_GO_TAG}" "${gomod}" \
    || die "Engine requirement was not raised to ${AWG_GO_TAG}."
}

verify_overlay_delta() {
  local src="$1" actual expected
  actual="$(git -C "${src}" status --porcelain=v1 --untracked-files=all | awk '{print $2}' | LC_ALL=C sort)"
  expected=$'gradle/verification-metadata.xml\n'\
$'gradle/wrapper/gradle-wrapper.properties\n'\
$'settings.gradle.kts\n'\
$'tunnel/src/main/java/org/amnezia/awg/GoBackend.java\n'\
$'tunnel/tools/CMakeLists.txt\n'\
$'tunnel/tools/libwg-go/Makefile\n'\
$'tunnel/tools/libwg-go/api-android.go\n'\
$'tunnel/tools/libwg-go/go.mod\n'\
$'tunnel/tools/libwg-go/go.sum\n'\
$'tunnel/tools/libwg-go/jni.c\n'\
$'tunnel/tools/libwg-go/uapi_adapt.go\n'\
$'tunnel/tools/libwg-go/uapi_adapt_test.go'
  [[ "${actual}" == "${expected}" ]] \
    || die "Reviewed overlay changed an unexpected official-source path. Got: [${actual}]"
}

create_flock_shim() {
  local shim_dir="${WORK_ROOT}/build-bin" shim="${WORK_ROOT}/build-bin/flock"
  mkdir -p "${shim_dir}"
  printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    '[ "$#" -eq 3 ] && [ "$2" = "-c" ] || exit 64' \
    'exec /bin/sh -c "$3"' > "${shim}"
  chmod 0755 "${shim}"
  printf '%s\n' "${shim_dir}"
}

canonicalize_jar() {
  local jar_path="$1" jar_stage="${WORK_ROOT}/classes-stage" canonical="${WORK_ROOT}/classes-canonical.jar"
  mkdir -p "${jar_stage}"
  unzip -q "${jar_path}" -d "${jar_stage}"
  find "${jar_stage}" -type f -exec chmod 0644 {} +
  find "${jar_stage}" -exec touch -h -t 198001010000.00 {} +
  (
    cd "${jar_stage}"
    find . -type f -print | LC_ALL=C sort | zip -0 -X -q "${canonical}" -@
  )
  cp "${canonical}" "${jar_path}"
}

canonicalize_complete_aar() {
  local official_aar="$1" output="$2" stage="${WORK_ROOT}/aar-stage" abi
  mkdir -p "${stage}"
  unzip -q "${official_aar}" -d "${stage}"
  for abi in arm64-v8a armeabi-v7a x86 x86_64; do
    [[ -f "${stage}/jni/${abi}/libwg-go.so" ]] || die "Official AAR is missing ${abi}/libwg-go.so."
    [[ -f "${stage}/jni/${abi}/libwg.so" ]] || die "Official AAR is missing ${abi}/libwg.so."
    [[ -f "${stage}/jni/${abi}/libwg-quick.so" ]] || die "Official AAR is missing ${abi}/libwg-quick.so."
    mv "${stage}/jni/${abi}/libwg-go.so" "${stage}/jni/${abi}/libam-go.so"
    mv "${stage}/jni/${abi}/libwg.so" "${stage}/jni/${abi}/libam.so"
    mv "${stage}/jni/${abi}/libwg-quick.so" "${stage}/jni/${abi}/libam-quick.so"
  done
  canonicalize_jar "${stage}/classes.jar"
  find "${stage}" -type f -exec chmod 0644 {} +
  find "${stage}" -exec touch -h -t 198001010000.00 {} +
  mkdir -p "$(dirname "${output}")"
  # zip updates an existing archive in place and would retain retired members
  # from a previous AAR. The output path is the single explicit build target;
  # remove only that file before creating the canonical member set.
  rm -f -- "${output}"
  (
    cd "${stage}"
    find . -type f -print | LC_ALL=C sort | zip -0 -X -q "${output}" -@
  )
}

verify_complete_aar() {
  local aar="$1" go_bin="$2" java_home="$3" ndk_home="$4"
  local verify_dir="${WORK_ROOT}/verify-aar" classes_jar javap_out class_list
  local nm_bin readelf_bin strings_bin abi lib member actual_members expected_members symbols
  local notes dynamic strings_output go_version_output
  nm_bin="$(resolve_ndk_tool "${ndk_home}" llvm-nm)"
  readelf_bin="$(resolve_ndk_tool "${ndk_home}" llvm-readelf)"
  strings_bin="$(resolve_ndk_tool "${ndk_home}" llvm-strings)"
  mkdir -p "${verify_dir}"
  unzip -q "${aar}" -d "${verify_dir}"

  actual_members="$(unzip -Z1 "${aar}" | LC_ALL=C sort)"
  expected_members=$'AndroidManifest.xml\n'\
$'META-INF/com/android/build/gradle/aar-metadata.properties\n'\
$'R.txt\n'\
$'classes.jar\n'\
$'jni/arm64-v8a/libam-go.so\n'\
$'jni/arm64-v8a/libam-quick.so\n'\
$'jni/arm64-v8a/libam.so\n'\
$'jni/armeabi-v7a/libam-go.so\n'\
$'jni/armeabi-v7a/libam-quick.so\n'\
$'jni/armeabi-v7a/libam.so\n'\
$'jni/x86/libam-go.so\n'\
$'jni/x86/libam-quick.so\n'\
$'jni/x86/libam.so\n'\
$'jni/x86_64/libam-go.so\n'\
$'jni/x86_64/libam-quick.so\n'\
$'jni/x86_64/libam.so'
  [[ "${actual_members}" == "${expected_members}" ]] \
    || die "Complete AAR member set changed. Got: [${actual_members}]"

  classes_jar="${verify_dir}/classes.jar"
  class_list="$("${java_home}/bin/jar" tf "${classes_jar}" | LC_ALL=C sort)"
  [[ "${class_list}" == *'org/amnezia/awg/backend/AwgQuickBackend.class'* ]] \
    || die "classes.jar is not the official v3 tunnel module output."
  for member in \
    org/amnezia/awg/ProxyGoBackend.class \
    org/amnezia/awg/backend/AbstractBackend.class \
    org/amnezia/awg/config/DnsSettings.class
  do
    [[ "${class_list}" != *"${member}"* ]] || die "classes.jar retained retired-package class ${member}."
  done
  javap_out="$("${java_home}/bin/javap" -classpath "${classes_jar}" org.amnezia.awg.GoBackend)"
  [[ "${javap_out}" == *'public static native int awgTurnOn(java.lang.String, int, java.lang.String, java.lang.String);'* ]] \
    || die "classes.jar is missing four-argument awgTurnOn."
  [[ "${javap_out}" == *'public static native int awgUpdateTunnelPeers(int, java.lang.String);'* ]] \
    || die "classes.jar is missing awgUpdateTunnelPeers."
  [[ "${javap_out}" == *'public static int awgTurnOn(java.lang.String, int, java.lang.String);'* ]] \
    || die "classes.jar no longer preserves official three-argument awgTurnOn."

  for abi in arm64-v8a armeabi-v7a x86 x86_64; do
    for lib in libam-go.so libam.so libam-quick.so; do
      member="${verify_dir}/jni/${abi}/${lib}"
      "${readelf_bin}" --elf-output-style=GNU -lW "${member}" | awk -v expected="${ANDROID_ELF_PAGE_ALIGNMENT}" '
        $1 == "LOAD" { found = 1; if ($NF != expected) exit 1 }
        END { if (!found) exit 1 }
      ' || die "${abi}/${lib} does not use exact 16K ELF LOAD alignment."
      notes="$("${readelf_bin}" --elf-output-style=GNU -n "${member}")"
      if grep -Fq 'Build ID' <<< "${notes}"; then
        die "${abi}/${lib} contains a nondeterministic linker build ID."
      fi
    done

    member="${verify_dir}/jni/${abi}/libam-go.so"
    dynamic="$("${readelf_bin}" --elf-output-style=GNU -d "${member}")"
    grep -Fq 'Library soname: [libam-go.so]' <<< "${dynamic}" \
      || die "${abi}/libam-go.so SONAME is not libam-go.so."
    strings_output="$("${strings_bin}" "${member}")"
    grep -Fq "go${REVIEWED_GO_VERSION}" <<< "${strings_output}" \
      || die "${abi}/libam-go.so does not embed Go ${REVIEWED_GO_VERSION}."
    grep -Fq "${AWG_GO_MODULE}" <<< "${strings_output}" \
      || die "${abi}/libam-go.so does not embed official amneziawg-go/v3."
    if grep -Eq 'zaneschepke|github.com/wgtunnel/amneziawg-go|wireproxyawg' <<< "${strings_output}"; then
      die "${abi}/libam-go.so retains a retired fork marker."
    fi
    go_version_output="$("${go_bin}" version -m "${member}")"
    grep -Fq "go${REVIEWED_GO_VERSION}" <<< "${go_version_output}" \
      || die "${abi}/libam-go.so Go build metadata mismatch."
    grep -Fq $'\tdep\t'"${AWG_GO_MODULE}"$'\t'"${AWG_GO_TAG}"$'\t'"${AWG_GO_MODULE_H1}" <<< "${go_version_output}" \
      || die "${abi}/libam-go.so was not linked against amneziawg-go ${AWG_GO_TAG}."
    symbols="$("${nm_bin}" -D "${member}" 2>/dev/null | awk '$2=="T" && $3 ~ /^Java_org_amnezia_awg_GoBackend_/ {print $3}' | LC_ALL=C sort)"
    [[ "${symbols}" == "${REQUIRED_JNI_EXPORTS}" ]] \
      || die "${abi}/libam-go.so JNI surface mismatch. Got: [${symbols}]"
    if grep -Fq "${WORK_ROOT}" <<< "${strings_output}"; then
      die "${abi}/libam-go.so leaks its temporary build path."
    fi
  done
}

print_member_hashes() {
  local aar="$1" member
  unzip -Z1 "${aar}" | while IFS= read -r member; do
    printf '  member sha256:     %s  %s\n' \
      "$(unzip -p "${aar}" "${member}" | if command -v shasum >/dev/null 2>&1; then shasum -a 256 | awk '{print $1}'; else sha256sum | awk '{print $1}'; fi)" \
      "${member}"
  done
}

main() {
  local command_name sdk java_home ndk_home go_archive go_bin go_platform
  local src gradle_home official_aar shim_dir
  for command_name in git curl tar patch zip unzip sed awk grep find; do
    command -v "${command_name}" >/dev/null 2>&1 || die "${command_name} is required."
  done

  WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/wins-awg-android-complete-aar.XXXXXX")"
  chmod 700 "${WORK_ROOT}"
  sdk="$(resolve_android_sdk)"
  java_home="$(resolve_java_home)"
  verify_sdk "${sdk}"
  ndk_home="$(resolve_ndk_home "${sdk}")"
  verify_overlay_inputs
  read -r go_archive go_bin go_platform < <(download_reviewed_go)

  src="${WORK_ROOT}/amneziawg-android"
  git clone --quiet --no-checkout "${AWG_ANDROID_REPO}" "${src}"
  git -C "${src}" checkout --quiet --detach "${AWG_ANDROID_COMMIT}"
  git -C "${src}" submodule update --quiet --init --recursive
  verify_clean_official_checkout "${src}"
  apply_reviewed_build_overlay "${src}"
  verify_overlay_delta "${src}"

  GOROOT="$(dirname "$(dirname "${go_bin}")")" GOTOOLCHAIN=local \
    "${go_bin}" test \
      "${src}/tunnel/tools/libwg-go/uapi_adapt.go" \
      "${src}/tunnel/tools/libwg-go/uapi_adapt_test.go"

  gradle_home="${WORK_ROOT}/gradle-home"
  mkdir -p "${gradle_home}/caches/golang" "${WORK_ROOT}/go-mod-cache" "${WORK_ROOT}/go-build-cache"
  cp "${go_archive}" "${gradle_home}/caches/golang/$(basename "${go_archive}")"
  verify_sha256 \
    "${gradle_home}/caches/golang/$(basename "${go_archive}")" \
    "$(sha256_file "${go_archive}")" \
    "preseeded Go archive"
  shim_dir="$(create_flock_shim)"

  (
    cd "${src}"
    PATH="${shim_dir}:${PATH}" \
    GRADLE_USER_HOME="${gradle_home}" \
    ANDROID_HOME="${sdk}" \
    ANDROID_SDK_ROOT="${sdk}" \
    JAVA_HOME="${java_home}" \
    GOMODCACHE="${WORK_ROOT}/go-mod-cache" \
    GOCACHE="${WORK_ROOT}/go-build-cache" \
    GOTOOLCHAIN=local \
    ANDROID_PACKAGE_NAME="${ANDROID_PACKAGE_NAME}" \
    SOURCE_DATE_EPOCH=315532800 \
      ./gradlew --no-daemon --stacktrace --dependency-verification strict :tunnel:assembleRelease
  )

  official_aar="${src}/tunnel/build/outputs/aar/tunnel-release.aar"
  [[ -f "${official_aar}" ]] || die "Official Gradle module did not produce tunnel-release.aar."
  canonicalize_complete_aar "${official_aar}" "${OUTPUT_AAR}"
  verify_complete_aar "${OUTPUT_AAR}" "${go_bin}" "${java_home}" "${ndk_home}"

  [[ "${AWG_ANDROID_COMMIT}" != "${AWG_GO_COMMIT}" ]] \
    || die "Android wrapper commit must remain distinct from the Go engine commit."
  [[ "${AWG_GO_TAG}" == "v3.1.20260828" && "${AWG_GO_COMMIT}" == "b5928efb6ca19f0153958460c3d141f04abc5c2e" ]] \
    || die "Android companion Go engine pin is not the frozen latest upstream tag."
  printf 'Built complete official-source AAR: %s\n' "${OUTPUT_AAR}"
  printf '  amneziawg-android: %s (%s)\n' "${AWG_ANDROID_TAG}" "${AWG_ANDROID_COMMIT}"
  printf '  amneziawg-go:      %s (%s)\n' "${AWG_GO_TAG}" "${AWG_GO_COMMIT}"
  printf '  amneziawg-tools:   %s\n' "${AWG_TOOLS_COMMIT}"
  printf '  elf-cleaner:       %s\n' "${ELF_CLEANER_COMMIT}"
  printf '  Go archive:        %s sha256=%s\n' "${go_platform}" "$(sha256_file "${go_archive}")"
  printf '  Android NDK:       %s\n' "${REVIEWED_NDK_VERSION}"
  printf '  AAR sha256:        %s\n' "$(sha256_file "${OUTPUT_AAR}")"
  print_member_hashes "${OUTPUT_AAR}"
}

main "$@"
