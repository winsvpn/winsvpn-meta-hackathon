#!/bin/sh
set -eu

# The shell may read a script incrementally. Running this file directly from a
# writable multi-agent worktree would therefore allow an edit made during the
# build to change bytes that have not been interpreted yet. Bootstrap into a
# private, read-only copy before doing any build work, and keep the generator
# beside it under the same immutable custody.
if test -z "${WINN_SPIKE_PROVENANCE_CUSTODY_ROOT:-}" &&
  test -z "${WINN_SPIKE_PROVENANCE_LIVE_SCRIPT_DIR:-}"
then
  umask 077
  spike_bootstrap_script_dir="$(
    CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P
  )"
  spike_bootstrap_custody="$(
    mktemp -d "${TMPDIR:-/tmp}/winn-ios-spike-provenance.XXXXXX"
  )"
  spike_bootstrap_custody="$(
    CDPATH='' cd -- "${spike_bootstrap_custody}" && pwd -P
  )"
  cp "${spike_bootstrap_script_dir}/build_device.sh" \
    "${spike_bootstrap_custody}/build_device.sh" || {
    rm -R "${spike_bootstrap_custody}"
    exit 1
  }
  cp "${spike_bootstrap_script_dir}/generate_project.rb" \
    "${spike_bootstrap_custody}/generate_project.rb" || {
    rm -R "${spike_bootstrap_custody}"
    exit 1
  }
  printf '%s\n' 'winn-ios-spike-provenance-custody/1' \
    >"${spike_bootstrap_custody}/custody.schema"
  chmod 400 \
    "${spike_bootstrap_custody}/build_device.sh" \
    "${spike_bootstrap_custody}/generate_project.rb" \
    "${spike_bootstrap_custody}/custody.schema"
  chmod 500 "${spike_bootstrap_custody}"
  WINN_SPIKE_PROVENANCE_CUSTODY_ROOT="${spike_bootstrap_custody}"
  WINN_SPIKE_PROVENANCE_LIVE_SCRIPT_DIR="${spike_bootstrap_script_dir}"
  export \
    WINN_SPIKE_PROVENANCE_CUSTODY_ROOT \
    WINN_SPIKE_PROVENANCE_LIVE_SCRIPT_DIR
  # The current shell may still be reading the live file; replacement rather
  # than a child invocation is the boundary that ends that exposure.
  # shellcheck disable=SC2093
  exec /bin/sh "${spike_bootstrap_custody}/build_device.sh" "$@"
fi

if test -z "${WINN_SPIKE_PROVENANCE_CUSTODY_ROOT:-}" ||
  test -z "${WINN_SPIKE_PROVENANCE_LIVE_SCRIPT_DIR:-}"
then
  echo "FAIL: incomplete build provenance custody environment." >&2
  exit 1
fi

spike_custody_root="$(
  CDPATH='' cd -- "${WINN_SPIKE_PROVENANCE_CUSTODY_ROOT}" && pwd -P
)" || {
  echo "FAIL: build provenance custody root is unavailable." >&2
  exit 1
}
case "$(basename -- "${spike_custody_root}")" in
  winn-ios-spike-provenance.*) ;;
  *)
    echo "FAIL: invalid build provenance custody root." >&2
    exit 1
    ;;
esac
spike_custody_expected_parent="$(
  CDPATH='' cd -- "${TMPDIR:-/tmp}" && pwd -P
)"
test "$(dirname -- "${spike_custody_root}")" = \
  "${spike_custody_expected_parent}" || {
  echo "FAIL: build provenance custody is outside the temporary root." >&2
  exit 1
}
test ! -L "${WINN_SPIKE_PROVENANCE_CUSTODY_ROOT}" &&
  test -f "${spike_custody_root}/custody.schema" &&
  test "$(cat "${spike_custody_root}/custody.schema")" = \
    'winn-ios-spike-provenance-custody/1' || {
  echo "FAIL: invalid build provenance custody marker." >&2
  exit 1
}

spike_script_dir="$(
  CDPATH='' cd -- "${WINN_SPIKE_PROVENANCE_LIVE_SCRIPT_DIR}" && pwd -P
)"
spike_live_builder="${spike_script_dir}/build_device.sh"
spike_live_generator="${spike_script_dir}/generate_project.rb"
spike_pinned_builder="${spike_custody_root}/build_device.sh"
spike_pinned_generator="${spike_custody_root}/generate_project.rb"
for spike_custodied_file in \
  "${spike_pinned_builder}" \
  "${spike_pinned_generator}"
do
  test ! -L "${spike_custodied_file}" &&
    test -f "${spike_custodied_file}" || {
    echo "FAIL: invalid file in build provenance custody." >&2
    exit 1
  }
done

spike_root="$(CDPATH='' cd -- "${spike_script_dir}/.." && pwd)"
spike_experiment_root="$(CDPATH='' cd -- "${spike_root}/../.." && pwd)"
spike_device_udid="${WINN_SPIKE_DEVICE_UDID:-<DEVICE_UDID>}"
spike_input_list="$(mktemp)"
spike_snapshot_input_list="$(mktemp)"
spike_snapshot_root="$(mktemp -d "${TMPDIR:-/tmp}/winn-ios-spike-source.XXXXXX")"
# macOS spells its default temporary root as /var while Xcodeproj resolves
# references through the physical /private/var path. Bind every later project
# and provenance comparison to the one canonical spelling of this fresh root.
spike_snapshot_root="$(
  CDPATH='' cd -- "${spike_snapshot_root}" && pwd -P
)"
spike_derived_data=""

spike_cleanup() {
  rm -f "${spike_input_list}" "${spike_snapshot_input_list}"
  chmod -R u+w "${spike_snapshot_root}" 2>/dev/null || true
  rm -R "${spike_snapshot_root}"
  chmod -R u+w "${spike_custody_root}" 2>/dev/null || true
  rm -R "${spike_custody_root}"
}
trap spike_cleanup EXIT HUP INT TERM

spike_write_input_list() {
  spike_list_root="$1"
  spike_list_path="$2"
  spike_raw_input_list="$(
    mktemp "${TMPDIR:-/tmp}/winn-ios-spike-inputs.XXXXXX"
  )" || return 1
  if ! (
    cd "${spike_list_root}" || exit 1
    find \
      Host \
      PacketTunnel \
      NativeEngine \
      PrivacyCore/Sources \
      PrivacyCore/Package.swift \
      Config/Base.xcconfig \
      Scripts/build_device.sh \
      Scripts/generate_project.rb \
      Scripts/stage_stageb_engine_artifact.sh \
      PrivacySpike.xcodeproj/project.pbxproj \
      PrivacySpike.xcodeproj/xcshareddata/xcschemes/PrivacySpike.xcscheme \
      -type f -print0 >"${spike_raw_input_list}"
  ); then
    rm -f "${spike_raw_input_list}"
    return 1
  fi
  if ! ruby -e '
    paths = File.binread(ARGV.fetch(0)).split("\0", -1)
    paths.pop if paths.last == ""
    abort("empty build input list") if paths.empty?
    abort("newline in build input path") if paths.any? { |path|
      path.include?("\n") || path.include?("\r")
    }
    paths.sort_by!(&:b)
    STDOUT.write(paths.join("\n"))
    STDOUT.write("\n")
  ' "${spike_raw_input_list}" >"${spike_list_path}"; then
    rm -f "${spike_raw_input_list}"
    return 1
  fi
  rm -f "${spike_raw_input_list}"
  for spike_required_input in \
    Host/VPNController.swift \
    PacketTunnel/PacketTunnelProvider.swift \
    PacketTunnel/StageBProviderNativeAdapterSeam.swift \
    PacketTunnel/StageBProviderNativeBridge.h \
    NativeEngine/WinnAWGUAPISanitizer.c \
    NativeEngine/WinnAWGUAPISanitizer.h \
    NativeEngine/WinnStageBDarwinUtun.c \
    NativeEngine/WinnStageBDarwinUtun.h \
    NativeEngine/WinnStageBFrameworkLoader.c \
    NativeEngine/WinnStageBFrameworkLoader.h \
    NativeEngine/WinnStageBNativeEngine.c \
    NativeEngine/WinnStageBNativeEngine.h \
    NativeEngine/WinnStageBProviderNativeOwner.c \
    NativeEngine/WinnStageBProviderNativeOwner.h \
    NativeEngine/WinnStageBProviderNativeOwnerInternal.h \
    PrivacyCore/Sources/WinnStageBProviderCore/StageBAWGUAPIParser.swift \
    PrivacyCore/Sources/WinnPrivacyCore/WCF3Constants.swift \
    PrivacyCore/Package.swift \
    Config/Base.xcconfig \
    Scripts/build_device.sh \
    Scripts/generate_project.rb \
    Scripts/stage_stageb_engine_artifact.sh \
    PrivacySpike.xcodeproj/project.pbxproj \
    PrivacySpike.xcodeproj/xcshareddata/xcschemes/PrivacySpike.xcscheme
  do
    grep -Fqx "${spike_required_input}" "${spike_list_path}" || {
      echo "FAIL: required build input is absent: ${spike_required_input}" >&2
      return 1
    }
  done
}

spike_digest_input_list() {
  spike_digest_root="$1"
  spike_list_path="$2"
  spike_digest_stream="$(
    mktemp "${TMPDIR:-/tmp}/winn-ios-spike-digest.XXXXXX"
  )" || return 1
  if ! (
    cd "${spike_digest_root}" || exit 1
    while IFS= read -r spike_input; do
      test -r "${spike_input}" || {
        echo "FAIL: input file is unreadable: ${spike_input}" >&2
        exit 1
      }
      spike_hex="$(spike_sha256_file "${spike_input}")" || exit 1
      printf '%s  %s\n' "${spike_hex}" "${spike_input}"
    done <"${spike_list_path}"
  ) >"${spike_digest_stream}"; then
    rm -f "${spike_digest_stream}"
    return 1
  fi
  spike_result="$(spike_sha256_file "${spike_digest_stream}")" || {
    rm -f "${spike_digest_stream}"
    return 1
  }
  rm -f "${spike_digest_stream}"
  printf '%s\n' "${spike_result}"
}

# This script's own declaration of the unsigned device source pin.
# Scripts/stage_stageb_engine_artifact.sh declares the same value
# independently and the two are compared after staging. Agreement is NOT proof
# the artifact is the intended one -- an editor who changed both files together
# would still agree -- but a unilateral edit of either file is refused here.
# build_device.sh is itself a digested build input. The independent declaration
# still catches a unilateral stager edit, while immutable builder custody
# prevents a concurrent edit from changing the declaration being executed.
WINN_ENGINE_DEVICE_SOURCE_SHA256="e0e810039d0ed43b1a599bb64320b0ee4ab4903cbdfd33e048bf0fb5e7f116cd"

# BEGIN spike_stageb_engine_shared
# Everything between these markers is byte-identical in build_device.sh and
# build_simulator.sh. Scripts/test_stageb_engine_build_embed_faults.sh extracts
# the block from both scripts and refuses if they have diverged, so a fix
# applied to one lane cannot silently miss the other.
#
# The containing app embeds exactly one copy of the staged engine framework
# into App.app/Frameworks. The Packet Tunnel extension deliberately does NOT
# link it: an LC_LOAD_DYLIB entry would let dyld map the engine and run its
# initializers before WinnStageBFrameworkLoader could hash or signature-check
# it, which would defeat the attestation. The assertions below hold that
# property against the built binaries rather than against intent.

WINN_ENGINE_FRAMEWORK_NAME="WinsAmneziaWGPacketEngine.framework"
WINN_ENGINE_BINARY_NAME="WinsAmneziaWGPacketEngine"
WINN_ENGINE_INSTALL_NAME="@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine"
WINN_ENGINE_PROVIDER_TARGET="PrivacySpikePacketTunnel"
WINN_ENGINE_HOST_TARGET="PrivacySpike"
WINN_ENGINE_RUNTIME_PIN_MANIFEST="WinnStageBEngineRuntimePin.manifest"
WINN_ENGINE_RELATIVE_PATH="Frameworks/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine"
WINN_ENGINE_PIN_SCHEMA="winn-stageb-engine-runtime-pin/1"
WINN_ENGINE_PIN_PHASE_NAME="Seal Stage B Engine Runtime Pin"

spike_is_sha256() {
  test "${#1}" -eq 64 || return 1
  case "$1" in
    *[!0123456789abcdef]*)
      return 1
      ;;
  esac
}

spike_sha256_file() {
  spike_hash_input="$1"
  test -r "${spike_hash_input}" || {
    echo "FAIL: hash input is unreadable: ${spike_hash_input}" >&2
    return 1
  }
  spike_hash_output="$(
    shasum -a 256 "${spike_hash_input}"
  )" || {
    echo "FAIL: shasum failed for ${spike_hash_input}" >&2
    return 1
  }
  spike_hash_value="${spike_hash_output%% *}"
  spike_is_sha256 "${spike_hash_value}" || {
    echo "FAIL: shasum output is not a lowercase SHA-256: ${spike_hash_input}" >&2
    return 1
  }
  test "${spike_hash_value}" != \
    "0000000000000000000000000000000000000000000000000000000000000000" ||
    {
      echo "FAIL: all-zero SHA-256 is not a bound digest: ${spike_hash_input}" >&2
      return 1
    }
  printf '%s\n' "${spike_hash_value}"
}

# Runs a command with its real exit status preserved, capturing stdout to a
# file. Deliberately not a pipeline: piping a producer into grep or awk
# discards the producer's status, so a tool that failed outright would read as
# "produced no matches" and pass.
spike_run_capture() {
  spike_capture_path="$1"
  shift
  "$@" >"${spike_capture_path}" || {
    echo "FAIL: command failed: $1" >&2
    return 1
  }
}

# Line counts come from awk END{print NR}, never from a shell glob over wc
# output. A `case` over padded text would let a count of 10 satisfy a "*0"
# pattern and read as zero.
spike_count_lines() {
  awk 'END { print NR + 0 }' "$1"
}

spike_engine_receipt_field() {
  spike_receipt_json="$1"
  spike_receipt_key="$2"
  printf '%s' "${spike_receipt_json}" | ruby -rjson -e '
    document = JSON.parse(STDIN.read)
    key = ARGV.fetch(0)
    value = document.fetch(key) { abort("missing stager receipt key: #{key}") }
    unless value.is_a?(String)
      abort("stager receipt key is not a string: #{key}")
    end
    STDOUT.write(value)
    STDOUT.write("\n")
  ' "${spike_receipt_key}"
}

spike_macho_arch_list() {
  spike_arch_binary="$1"
  spike_arch_raw="$(xcrun lipo -archs "${spike_arch_binary}")" || {
    echo "FAIL: could not read architectures: ${spike_arch_binary}" >&2
    return 1
  }
  test -n "${spike_arch_raw}" || {
    echo "FAIL: no architectures reported: ${spike_arch_binary}" >&2
    return 1
  }
  # Unquoted on purpose: lipo emits a space-separated list to split.
  # shellcheck disable=SC2086
  printf '%s\n' ${spike_arch_raw} | sort
}

# Emits a normalized identity block for one architecture slice. Every field
# here is preserved verbatim by codesign, which is what makes source-to-runtime
# comparison meaningful across signing.
spike_macho_slice_identity() {
  spike_slice_binary="$1"
  spike_slice_arch="$2"
  spike_slice_work="$(
    mktemp -d "${TMPDIR:-/tmp}/winn-engine-slice.XXXXXX"
  )" || return 1
  spike_slice_status=0
  {
    spike_run_capture "${spike_slice_work}/build" \
      vtool -arch "${spike_slice_arch}" -show-build "${spike_slice_binary}" &&
      spike_run_capture "${spike_slice_work}/id" \
        otool -arch "${spike_slice_arch}" -D "${spike_slice_binary}" &&
      spike_run_capture "${spike_slice_work}/deps" \
        otool -arch "${spike_slice_arch}" -L "${spike_slice_binary}" &&
      spike_run_capture "${spike_slice_work}/syms" \
        nm -arch "${spike_slice_arch}" -gUj "${spike_slice_binary}"
  } || spike_slice_status=1
  if test "${spike_slice_status}" -eq 0; then
    printf 'arch\t%s\n' "${spike_slice_arch}"
    awk '$1 == "platform" || $1 == "minos" { print "build\t" $1 "\t" $2 }' \
      "${spike_slice_work}/build" | sort
    awk '/^@/ { print "install-name\t" $0 }' "${spike_slice_work}/id"
    awk 'NR > 1 { print "dependency\t" $1 }' "${spike_slice_work}/deps" | sort
    sort "${spike_slice_work}/syms" | awk '{ print "symbol\t" $0 }'
  fi
  rm -R "${spike_slice_work}"
  return "${spike_slice_status}"
}

# Refuses a missing copy, a duplicate copy anywhere in the bundle, a copy at
# any path other than the containing app's Frameworks directory, a symlink
# aliasing either the bundle or its executable, and a framework that resolves
# outside the app bundle.
spike_assert_single_embedded_engine() {
  spike_embed_app_root="$1"
  spike_embed_expected_framework="$2"
  spike_embed_work="$(
    mktemp -d "${TMPDIR:-/tmp}/winn-engine-embed.XXXXXX"
  )" || return 1
  spike_embed_status=0

  # -type d: the engine framework is a bundle directory. Without it, a plain
  # file or a symlink carrying the bundle's name is inventoried as a framework
  # copy and a duplicate can hide as a non-directory.
  if ! find "${spike_embed_app_root}" \
    -type d -name "${WINN_ENGINE_FRAMEWORK_NAME}" -print \
    >"${spike_embed_work}/frameworks"
  then
    echo "FAIL: could not enumerate embedded engine frameworks." >&2
    rm -R "${spike_embed_work}"
    return 1
  fi
  if ! find "${spike_embed_app_root}" \
    -type f -name "${WINN_ENGINE_BINARY_NAME}" -print \
    >"${spike_embed_work}/binaries"
  then
    echo "FAIL: could not enumerate embedded engine binaries." >&2
    rm -R "${spike_embed_work}"
    return 1
  fi
  # A symlink named like the framework or its executable is a second way to
  # reach an engine image, and -type d / -type f searches step straight past
  # it.
  if ! find "${spike_embed_app_root}" -type l \
    \( -name "${WINN_ENGINE_FRAMEWORK_NAME}" \
    -o -name "${WINN_ENGINE_BINARY_NAME}" \) -print \
    >"${spike_embed_work}/links"
  then
    echo "FAIL: could not enumerate engine symlink aliases." >&2
    rm -R "${spike_embed_work}"
    return 1
  fi

  spike_embed_framework_count="$(
    spike_count_lines "${spike_embed_work}/frameworks"
  )"
  spike_embed_binary_count="$(
    spike_count_lines "${spike_embed_work}/binaries"
  )"
  spike_embed_link_count="$(spike_count_lines "${spike_embed_work}/links")"

  if test "${spike_embed_link_count}" -ne 0; then
    echo "FAIL: a symlink aliases the embedded engine." >&2
    cat "${spike_embed_work}/links" >&2
    spike_embed_status=1
  fi

  if test "${spike_embed_framework_count}" -eq 0; then
    echo "FAIL: no embedded engine framework copy was produced." >&2
    spike_embed_status=1
  elif test "${spike_embed_framework_count}" -ne 1; then
    echo "FAIL: ${spike_embed_framework_count} embedded engine framework copies exist; exactly one is allowed." >&2
    cat "${spike_embed_work}/frameworks" >&2
    spike_embed_status=1
  elif ! grep -Fqx -- "${spike_embed_expected_framework}" \
    "${spike_embed_work}/frameworks"
  then
    echo "FAIL: the embedded engine framework is not at the containing app's Frameworks path." >&2
    cat "${spike_embed_work}/frameworks" >&2
    spike_embed_status=1
  fi

  if test "${spike_embed_binary_count}" -eq 0; then
    echo "FAIL: no embedded engine executable was produced." >&2
    spike_embed_status=1
  elif test "${spike_embed_binary_count}" -ne 1; then
    echo "FAIL: ${spike_embed_binary_count} embedded engine executables exist; exactly one is allowed." >&2
    cat "${spike_embed_work}/binaries" >&2
    spike_embed_status=1
  elif ! grep -Fqx -- \
    "${spike_embed_expected_framework}/${WINN_ENGINE_BINARY_NAME}" \
    "${spike_embed_work}/binaries"
  then
    echo "FAIL: the embedded engine executable is at an unexpected path." >&2
    cat "${spike_embed_work}/binaries" >&2
    spike_embed_status=1
  fi

  # Canonical containment: resolve both the app bundle and the framework and
  # require the framework to sit exactly at <app>/Frameworks/<bundle>. This
  # rejects a framework reached through a symlinked parent directory, which
  # the per-entry symlink scan above does not see.
  if test "${spike_embed_status}" -eq 0; then
    spike_embed_app_real="$(
      CDPATH='' cd -- "${spike_embed_app_root}" && pwd -P
    )" || spike_embed_status=1
    spike_embed_framework_real="$(
      CDPATH='' cd -- "${spike_embed_expected_framework}" && pwd -P
    )" || spike_embed_status=1
    if test "${spike_embed_status}" -eq 0 &&
      test "${spike_embed_framework_real}" != \
        "${spike_embed_app_real}/Frameworks/${WINN_ENGINE_FRAMEWORK_NAME}"
    then
      echo "FAIL: the embedded engine framework escapes the app bundle." >&2
      spike_embed_status=1
    fi
  fi

  rm -R "${spike_embed_work}"
  return "${spike_embed_status}"
}

# The single most important structural assertion in this lane. If the provider
# carries an engine LC_LOAD_DYLIB, dyld maps the engine at process start --
# before any loader code runs -- and no amount of later hashing can undo that.
# The required count is exactly zero, not "at most one". The runpath check is
# defence in depth: with no runpath resolving to the containing app's
# Frameworks directory, a reintroduced @rpath load command would fail to launch
# rather than silently preload.
spike_assert_no_engine_preload() {
  spike_nolink_binary="$1"
  spike_nolink_label="$2"
  spike_nolink_work="$(
    mktemp -d "${TMPDIR:-/tmp}/winn-engine-nolink.XXXXXX"
  )" || return 1
  spike_nolink_status=0

  if ! spike_run_capture "${spike_nolink_work}/deps" \
    otool -L "${spike_nolink_binary}"
  then
    rm -R "${spike_nolink_work}"
    return 1
  fi
  if ! spike_run_capture "${spike_nolink_work}/cmds" \
    otool -l "${spike_nolink_binary}"
  then
    rm -R "${spike_nolink_work}"
    return 1
  fi

  # Any load command naming the engine under any spelling, plus the exact
  # pinned install name. Counted, then required to be zero.
  spike_nolink_named="$(
    awk -v needle="${WINN_ENGINE_BINARY_NAME}" '
      NR > 1 && index($0, needle) { total += 1 }
      END { print total + 0 }
    ' "${spike_nolink_work}/deps"
  )"
  if test "${spike_nolink_named}" -ne 0; then
    echo "FAIL: ${spike_nolink_label} has ${spike_nolink_named} load-time dependencies naming the engine; dyld would map it before attestation." >&2
    cat "${spike_nolink_work}/deps" >&2
    spike_nolink_status=1
  fi

  spike_nolink_pinned="$(
    awk -v needle="${WINN_ENGINE_INSTALL_NAME}" '
      NR > 1 && index($0, needle) { total += 1 }
      END { print total + 0 }
    ' "${spike_nolink_work}/deps"
  )"
  if test "${spike_nolink_pinned}" -ne 0; then
    echo "FAIL: ${spike_nolink_label} loads the pinned engine install name." >&2
    spike_nolink_status=1
  fi

  spike_nolink_rpaths="$(
    awk '
      $1 == "path" && $2 == "@executable_path/../../Frameworks" { total += 1 }
      END { print total + 0 }
    ' "${spike_nolink_work}/cmds"
  )"
  if test "${spike_nolink_rpaths}" -ne 0; then
    echo "FAIL: ${spike_nolink_label} has a runpath resolving to the containing app Frameworks directory." >&2
    spike_nolink_status=1
  fi

  rm -R "${spike_nolink_work}"
  return "${spike_nolink_status}"
}

# Compares the staged unsigned source binary with the embedded runtime binary.
# Byte equality is NOT available on the signed lane and is not claimed here:
# codesign rewrites __LINKEDIT and appends a signature, so the two files
# legitimately differ. What is compared is the Mach-O identity that codesign
# preserves -- per-slice platform, minimum OS, install name, dependency set,
# and exported symbol set. A different or tampered engine fails this; a
# re-signed copy of the same engine passes. This is an identity-continuity
# argument, not a cryptographic proof that the runtime bytes derive from the
# source bytes; the immutable staged input and the single-copy assertions above
# are what carry the rest of that binding.
spike_assert_engine_identity_continuity() {
  spike_continuity_source="$1"
  spike_continuity_runtime="$2"
  spike_continuity_work="$(
    mktemp -d "${TMPDIR:-/tmp}/winn-engine-continuity.XXXXXX"
  )" || return 1
  spike_continuity_status=0

  if ! spike_macho_arch_list "${spike_continuity_source}" \
    >"${spike_continuity_work}/source-archs"
  then
    rm -R "${spike_continuity_work}"
    return 1
  fi
  if ! spike_macho_arch_list "${spike_continuity_runtime}" \
    >"${spike_continuity_work}/runtime-archs"
  then
    rm -R "${spike_continuity_work}"
    return 1
  fi
  if test "$(spike_count_lines "${spike_continuity_work}/runtime-archs")" -eq 0
  then
    echo "FAIL: the embedded engine reports no architecture slice." >&2
    rm -R "${spike_continuity_work}"
    return 1
  fi

  while IFS= read -r spike_continuity_arch; do
    test -n "${spike_continuity_arch}" || continue
    if ! grep -Fqx -- "${spike_continuity_arch}" \
      "${spike_continuity_work}/source-archs"
    then
      echo "FAIL: embedded engine has architecture ${spike_continuity_arch}, absent from the pinned source." >&2
      spike_continuity_status=1
      continue
    fi
    if ! spike_macho_slice_identity \
      "${spike_continuity_source}" "${spike_continuity_arch}" \
      >"${spike_continuity_work}/source-identity"
    then
      spike_continuity_status=1
      continue
    fi
    if ! spike_macho_slice_identity \
      "${spike_continuity_runtime}" "${spike_continuity_arch}" \
      >"${spike_continuity_work}/runtime-identity"
    then
      spike_continuity_status=1
      continue
    fi
    cmp -s \
      "${spike_continuity_work}/source-identity" \
      "${spike_continuity_work}/runtime-identity" || {
      echo "FAIL: embedded engine ${spike_continuity_arch} slice identity differs from the pinned source." >&2
      diff \
        "${spike_continuity_work}/source-identity" \
        "${spike_continuity_work}/runtime-identity" >&2 || true
      spike_continuity_status=1
    }
  done <"${spike_continuity_work}/runtime-archs"

  rm -R "${spike_continuity_work}"
  return "${spike_continuity_status}"
}

# Structural pre-build gate over the generated project. A basename grep would
# accept a file reference that no target compiles, so this walks the object
# graph: every NativeEngine translation unit on disk must be in the provider's
# Sources phase and nowhere in the host's, the provider must neither link nor
# copy the engine framework, and the containing app must embed exactly one copy
# into Frameworks with both CodeSignOnCopy and RemoveHeadersOnCopy.
spike_assert_engine_project_wiring() {
  spike_wiring_root="$1"
  # The Xcode build-setting references below ($(TARGET_BUILD_DIR) and
  # $(CONTENTS_FOLDER_PATH)) are literal pbxproj text and must not be
  # expanded by the shell.
  # shellcheck disable=SC2016
  ruby -e '
    require "xcodeproj"
    require "pathname"

    root = Pathname.new(ARGV.fetch(0))
    provider_name = ARGV.fetch(1)
    host_name = ARGV.fetch(2)
    engine = ARGV.fetch(3)

    def fail!(message)
      warn "FAIL: #{message}"
      exit 1
    end

    project = Xcodeproj::Project.open(
      root.join("PrivacySpike.xcodeproj").to_s
    )

    def target_named(project, name)
      project.targets.find { |target| target.name == name }
    end

    def phase_paths(files)
      files.map { |build_file|
        build_file.file_ref && build_file.file_ref.path
      }.compact
    end

    provider = target_named(project, provider_name)
    host = target_named(project, host_name)
    fail!("target is absent from the project: #{provider_name}") if provider.nil?
    fail!("target is absent from the project: #{host_name}") if host.nil?

    compiled = phase_paths(provider.source_build_phase.files)
      .select { |path| path.end_with?(".c") }
      .map { |path| File.basename(path) }.sort
    on_disk = root.join("NativeEngine").children
      .reject(&:directory?)
      .map { |child| child.basename.to_s }
      .select { |name| name.end_with?(".c") }.sort
    fail!("NativeEngine contains no C translation unit.") if on_disk.empty?
    if compiled != on_disk
      fail!(
        "NativeEngine translation units on disk #{on_disk.inspect} differ " \
        "from those compiled into the Packet Tunnel #{compiled.inspect}"
      )
    end

    host_native = phase_paths(host.source_build_phase.files)
      .select { |path| path.end_with?(".c") }
    unless host_native.empty?
      fail!(
        "the host target compiles Stage B native sources " \
        "#{host_native.inspect}; the AWG data plane must not be reachable " \
        "from the host."
      )
    end

    bridge_header = "PacketTunnel/StageBProviderNativeBridge.h"
    bridge_refs = project.files.select { |file|
      file.real_path.to_s == root.join(bridge_header).to_s
    }
    unless bridge_refs.length == 1
      fail!(
        "the project references #{bridge_header} #{bridge_refs.length} " \
        "times; exactly one provider-private bridge is required."
      )
    end
    provider.build_configurations.each do |configuration|
      value = configuration.build_settings[
        "SWIFT_OBJC_BRIDGING_HEADER"
      ]
      unless value == bridge_header
        fail!(
          "the Packet Tunnel #{configuration.name} bridging header is " \
          "#{value.inspect}, expected #{bridge_header.inspect}."
        )
      end
      header_paths = configuration.build_settings[
        "HEADER_SEARCH_PATHS"
      ].to_s
      unless header_paths.include?("$(SRCROOT)/NativeEngine")
        fail!(
          "the Packet Tunnel #{configuration.name} header search path " \
          "does not contain the provider-private NativeEngine directory."
        )
      end
    end
    host.build_configurations.each do |configuration|
      if configuration.build_settings.key?("SWIFT_OBJC_BRIDGING_HEADER")
        fail!(
          "the host #{configuration.name} imports the Stage B native " \
          "bridge; only the Packet Tunnel may import it."
        )
      end
    end

    if phase_paths(provider.frameworks_build_phase.files).include?(engine)
      fail!(
        "the Packet Tunnel links #{engine}. dyld would map the engine and " \
        "run its initializers before the loader could attest it."
      )
    end
    if phase_paths(host.frameworks_build_phase.files).include?(engine)
      fail!("the containing app links #{engine}.")
    end
    provider.copy_files_build_phases.each do |phase|
      if phase_paths(phase.files).include?(engine)
        fail!(
          "the Packet Tunnel has an extension-local copy phase for " \
          "#{engine}; exactly one embedded copy may exist."
        )
      end
    end

    engine_embeds = host.copy_files_build_phases.flat_map { |phase|
      phase.files.select { |build_file|
        build_file.file_ref && build_file.file_ref.path == engine
      }.map { |build_file| [phase, build_file] }
    }
    unless engine_embeds.length == 1
      fail!(
        "the host embeds #{engine} #{engine_embeds.length} times; exactly " \
        "one copy is allowed."
      )
    end
    embed_phase, embed_file = engine_embeds.fetch(0)
    unless embed_phase.symbol_dst_subfolder_spec == :frameworks
      fail!("#{engine} is not embedded into the Frameworks directory.")
    end
    attributes = embed_file.settings.to_h.fetch("ATTRIBUTES", [])
    unless attributes.include?("CodeSignOnCopy")
      fail!("the embedded #{engine} is not marked CodeSignOnCopy.")
    end
    unless attributes.include?("RemoveHeadersOnCopy")
      fail!("the embedded #{engine} is not marked RemoveHeadersOnCopy.")
    end

    # The runtime-pin phase must exist, must run after the embed phase, and
    # must declare the embedded engine as its input and the manifest as its
    # output. The declared input is what makes XCBuild order this task after
    # copy-and-sign; without it, phase position alone would not guarantee the
    # manifest pins final runtime bytes.
    pin_name = ARGV.fetch(4)
    manifest = ARGV.fetch(5)
    relative = ARGV.fetch(6)
    pin_phases = host.build_phases.select { |phase|
      phase.isa == "PBXShellScriptBuildPhase" && phase.name == pin_name
    }
    unless pin_phases.length == 1
      fail!(
        "the host has #{pin_phases.length} \"#{pin_name}\" phases; exactly " \
        "one is required."
      )
    end
    pin_phase = pin_phases.fetch(0)
    embed_index = host.build_phases.index(embed_phase)
    pin_index = host.build_phases.index(pin_phase)
    unless pin_index > embed_index
      fail!(
        "\"#{pin_name}\" runs at phase #{pin_index}, before the embed phase " \
        "at #{embed_index}; it would pin bytes that do not exist yet."
      )
    end
    expected_input =
      "$(TARGET_BUILD_DIR)/$(CONTENTS_FOLDER_PATH)/#{relative}"
    expected_output =
      "$(TARGET_BUILD_DIR)/$(CONTENTS_FOLDER_PATH)/#{manifest}"
    unless pin_phase.input_paths == [expected_input]
      fail!(
        "\"#{pin_name}\" input paths are #{pin_phase.input_paths.inspect}; " \
        "the embedded engine must be the declared input so the task is " \
        "ordered after copy-and-sign."
      )
    end
    unless pin_phase.output_paths == [expected_output]
      fail!(
        "\"#{pin_name}\" output paths are #{pin_phase.output_paths.inspect}; " \
        "expected #{[expected_output].inspect}."
      )
    end
    if pin_phase.shell_script.to_s.include?("WINN_STAGEB_ENGINE_RUNTIME_SHA256=")
      fail!(
        "\"#{pin_name}\" assigns a runtime digest; it must measure the " \
        "embedded bytes, never accept a supplied digest."
      )
    end
    unless pin_phase.shell_script.to_s.include?("set -C")
      fail!(
        "\"#{pin_name}\" does not create the manifest with noclobber; the " \
        "write must be an atomic O_EXCL create that adopts nothing."
      )
    end
  ' \
    "${spike_wiring_root}" \
    "${WINN_ENGINE_PROVIDER_TARGET}" \
    "${WINN_ENGINE_HOST_TARGET}" \
    "${WINN_ENGINE_FRAMEWORK_NAME}" \
    "${WINN_ENGINE_PIN_PHASE_NAME}" \
    "${WINN_ENGINE_RUNTIME_PIN_MANIFEST}" \
    "${WINN_ENGINE_RELATIVE_PATH}"
}

# Verifies the app-sealed runtime pin that WinnStageBFrameworkDarwin.c reads
# before dlopen. Its parser is a whole-file sscanf with %n, so anything other
# than these exact seven LF-terminated lines is rejected on device; this
# rebuilds the expected bytes independently of the build-phase script that
# wrote them and compares byte for byte.
#
# The runtime digest is re-measured here from the embedded binary rather than
# trusted from the file: a manifest that agrees with itself proves nothing.
#
# Producer/consumer contract, read out of the consumer rather than assumed.
# winn_read_manifest in NativeEngine/WinnStageBFrameworkDarwin.c requires
# exactly: S_ISREG, st_nlink == 1, 0 < st_size < 1024, and O_NOFOLLOW on every
# path component. It has NO uid, gid, or permission-bit predicate -- verified
# by grepping the boundary for st_uid, st_gid, S_IWOTH, S_IWGRP, S_IRWXO,
# geteuid and getuid, all of which are absent. So this function asserts those
# four properties and deliberately asserts nothing about ownership or mode:
# inventing a mode requirement the consumer does not enforce would be a
# fabricated check, and on device the installer, not this build, decides
# ownership anyway. Integrity there rests on the app signature sealing the
# file, not on its permission bits.
spike_assert_engine_runtime_pin_manifest() {
  spike_pin_app="$1"
  spike_pin_source_sha="$2"
  spike_pin_platform="$3"
  spike_pin_expected_arches="$4"
  spike_pin_engine="$5"
  spike_pin_work="$(
    mktemp -d "${TMPDIR:-/tmp}/winn-engine-pin.XXXXXX"
  )" || return 1
  spike_pin_status=0
  spike_pin_manifest="${spike_pin_app}/${WINN_ENGINE_RUNTIME_PIN_MANIFEST}"

  # The loader opens both files O_NOFOLLOW and refuses st_nlink != 1.
  for spike_pin_file in "${spike_pin_manifest}" "${spike_pin_engine}"; do
    if test -L "${spike_pin_file}" || test ! -f "${spike_pin_file}"; then
      echo "FAIL: engine runtime pin input is not a regular file: ${spike_pin_file}" >&2
      rm -R "${spike_pin_work}"
      return 1
    fi
    spike_pin_links="$(stat -f '%l' "${spike_pin_file}")"
    if test "${spike_pin_links}" != "1"; then
      echo "FAIL: ${spike_pin_file} has ${spike_pin_links} hard links; the loader requires exactly 1." >&2
      spike_pin_status=1
    fi
  done

  spike_pin_size="$(stat -f '%z' "${spike_pin_manifest}")"
  if test "${spike_pin_size}" -le 0 || test "${spike_pin_size}" -ge 1024; then
    echo "FAIL: the engine runtime pin manifest is ${spike_pin_size} bytes; the loader accepts 1..1023." >&2
    spike_pin_status=1
  fi

  spike_pin_measured="$(spike_sha256_file "${spike_pin_engine}")" || {
    rm -R "${spike_pin_work}"
    return 1
  }

  spike_pin_arches_raw="$(xcrun lipo -archs "${spike_pin_engine}")" || {
    rm -R "${spike_pin_work}"
    return 1
  }
  spike_pin_arches="$(
    # Unquoted on purpose: lipo emits a space-separated list to split.
    # shellcheck disable=SC2086
    printf '%s\n' ${spike_pin_arches_raw} |
      LC_ALL=C sort |
      awk 'BEGIN { sep = "" } { printf "%s%s", sep, $0; sep = "," } END { print "" }'
  )"
  if test "${spike_pin_arches}" != "${spike_pin_expected_arches}"; then
    echo "FAIL: embedded engine architectures ${spike_pin_arches} do not match the pinned ${spike_pin_expected_arches}." >&2
    spike_pin_status=1
  fi

  printf '%s\n' \
    "schema=${WINN_ENGINE_PIN_SCHEMA}" \
    "source_binary_sha256=${spike_pin_source_sha}" \
    "signed_runtime_binary_sha256=${spike_pin_measured}" \
    "relative_path=${WINN_ENGINE_RELATIVE_PATH}" \
    "platform=${spike_pin_platform}" \
    "architectures=${spike_pin_expected_arches}" \
    "install_name=${WINN_ENGINE_INSTALL_NAME}" \
    >"${spike_pin_work}/expected"

  if ! cmp -s "${spike_pin_work}/expected" "${spike_pin_manifest}"; then
    echo "FAIL: the engine runtime pin manifest is not the exact expected bytes." >&2
    diff "${spike_pin_work}/expected" "${spike_pin_manifest}" >&2 || true
    spike_pin_status=1
  fi

  rm -R "${spike_pin_work}"
  return "${spike_pin_status}"
}

# Stages the pinned engine for one platform into a fresh directory and proves
# the staged bytes agree with the stager's own receipt. Prints the staged
# source SHA-256.
spike_stage_engine() {
  spike_stage_script="$1"
  spike_stage_platform="$2"
  spike_stage_dir="$3"
  spike_stage_receipt="$(
    "${spike_stage_script}" "${spike_stage_platform}" "${spike_stage_dir}"
  )" || {
    echo "FAIL: the Stage B engine stager failed for ${spike_stage_platform}." >&2
    return 1
  }
  spike_stage_receipt_source="$(
    spike_engine_receipt_field "${spike_stage_receipt}" source_binary_sha256
  )" || return 1
  spike_stage_receipt_binary="$(
    spike_engine_receipt_field "${spike_stage_receipt}" binary_sha256
  )" || return 1
  spike_stage_binary="${spike_stage_dir}/${WINN_ENGINE_FRAMEWORK_NAME}/${WINN_ENGINE_BINARY_NAME}"
  spike_stage_observed="$(spike_sha256_file "${spike_stage_binary}")" || return 1
  test "${spike_stage_observed}" = "${spike_stage_receipt_binary}" || {
    echo "FAIL: the staged engine binary differs from its own staging receipt." >&2
    return 1
  }
  test "${spike_stage_observed}" = "${spike_stage_receipt_source}" || {
    echo "FAIL: the staged engine binary differs from the pinned source artifact." >&2
    return 1
  }
  printf '%s\n' "${spike_stage_observed}"
}
# END spike_stageb_engine_shared

spike_assert_live_provenance_matches_pins() {
  cmp -s "${spike_live_builder}" "${spike_pinned_builder}" || {
    echo "FAIL: live build_device.sh drifted from its immutable pre-build pin." >&2
    return 1
  }
  cmp -s "${spike_live_generator}" "${spike_pinned_generator}" || {
    echo "FAIL: live generate_project.rb drifted from its immutable pre-build pin." >&2
    return 1
  }
}

# A fail-only checkpoint for the deterministic concurrency fixture. It runs
# after immutable custody and source snapshot validation but before creating
# DerivedData or invoking any build tool. Even without a mutation it terminates
# without a receipt; it can never turn a test invocation into build evidence.
spike_run_provenance_test_checkpoint() {
  spike_hook_dir="${WINN_SPIKE_PROVENANCE_TEST_HOOK_DIR:-}"
  test -n "${spike_hook_dir}" || return 0
  test ! -L "${spike_hook_dir}" && test -d "${spike_hook_dir}" || {
    echo "FAIL: provenance test checkpoint is not a regular directory." >&2
    return 1
  }
  spike_hook_ready_staging="${spike_hook_dir}/.ready.$$"
  (
    set -C
    printf '%s\n' \
      "builderSHA256=${spike_builder_sha}" \
      "projectGeneratorSHA256=${spike_generator_sha}" \
      "sourceDigest=${spike_source_digest}" \
      >"${spike_hook_ready_staging}"
  ) || return 1
  chmod 400 "${spike_hook_ready_staging}"
  mv "${spike_hook_ready_staging}" "${spike_hook_dir}/ready"

  spike_hook_deadline="$(( $(date +%s) + 30 ))"
  while test ! -e "${spike_hook_dir}/continue"; do
    test "$(date +%s)" -lt "${spike_hook_deadline}" || {
      echo "FAIL: provenance test checkpoint timed out." >&2
      return 1
    }
    sleep 0.05
  done
  spike_assert_live_provenance_matches_pins || return 1
  echo "FAIL: provenance test checkpoint intentionally stops before build execution." >&2
  return 1
}

# Every digest the receipt carries must be a bound, non-degenerate SHA-256.
# An absent or empty value is refused by name rather than crashing on an
# unbound variable, so a missing hash is an attributable failure.
spike_require_receipt_digest() {
  spike_receipt_digest_label="$1"
  spike_receipt_digest_value="$2"
  spike_is_sha256 "${spike_receipt_digest_value}" || {
    echo "FAIL: build receipt field is not a lowercase SHA-256: ${spike_receipt_digest_label}" >&2
    return 1
  }
  test "${spike_receipt_digest_value}" != \
    "0000000000000000000000000000000000000000000000000000000000000000" || {
    echo "FAIL: build receipt field is an all-zero digest: ${spike_receipt_digest_label}" >&2
    return 1
  }
}

spike_publish_build_receipt() {
  spike_receipt_final="$1"
  spike_receipt_directory="$(dirname -- "${spike_receipt_final}")"

  # Validated before anything is created, so a missing hash cannot leave a
  # partial receipt behind.
  spike_require_receipt_digest sourceDigest \
    "${spike_source_digest-}" || return 1
  spike_require_receipt_digest appExecutableSHA256 \
    "${spike_app_executable_sha-}" || return 1
  spike_require_receipt_digest providerExecutableSHA256 \
    "${spike_provider_executable_sha-}" || return 1
  spike_require_receipt_digest engineSourceBinarySHA256 \
    "${spike_engine_source_binary_sha-}" || return 1
  spike_require_receipt_digest engineEmbeddedRuntimeBinarySHA256 \
    "${spike_engine_embedded_runtime_binary_sha-}" || return 1
  spike_require_receipt_digest evidenceVerifierSHA256 \
    "${spike_evidence_verifier_sha-}" || return 1
  spike_require_receipt_digest matrixVerifierSHA256 \
    "${spike_matrix_verifier_sha-}" || return 1
  spike_require_receipt_digest engineRuntimePinManifestSHA256 \
    "${spike_engine_runtime_pin_manifest_sha-}" || return 1
  spike_require_receipt_digest builderSHA256 \
    "${spike_builder_sha-}" || return 1
  spike_require_receipt_digest projectGeneratorSHA256 \
    "${spike_generator_sha-}" || return 1
  spike_require_receipt_digest engineStagerSHA256 \
    "${spike_stager_sha-}" || return 1

  spike_receipt_staging="$(
    mktemp \
      "${spike_receipt_directory}/.WINN_SPIKE_BUILD_RECEIPT.json.XXXXXX"
  )" || return 1
  if ! {
    printf '{\n'
    printf '  "schema":"winn-ios-privacy-spike-build-receipt/2",\n'
    printf '  "protocolVersion":"winn/3",\n'
    printf '  "configuration":"Release",\n'
    printf '  "sourceDigest":"%s",\n' "${spike_source_digest}"
    printf '  "appExecutableSHA256":"%s",\n' \
      "${spike_app_executable_sha}"
    printf '  "providerExecutableSHA256":"%s",\n' \
      "${spike_provider_executable_sha}"
    # Two distinct engine digests under two unambiguous names. The first is
    # the unsigned source dylib as pinned in apple/EngineArtifacts; the second
    # is the framework executable as it exists inside the built, signed app.
    # They are NOT expected to be equal -- codesign rewrites the binary -- and
    # the old ambiguous "artifactDigest" alias is deliberately gone, because a
    # single unqualified digest name is exactly how source-versus-runtime
    # confusion gets baked into evidence.
    printf '  "engineSourceBinarySHA256":"%s",\n' \
      "${spike_engine_source_binary_sha}"
    printf '  "engineEmbeddedRuntimeBinarySHA256":"%s",\n' \
      "${spike_engine_embedded_runtime_binary_sha}"
    printf '  "engineEmbeddedFrameworkPath":"%s",\n' \
      "${spike_engine_embedded_relative_path-}"
    printf '  "engineProviderLinkage":"none-loader-dlopen-after-attestation",\n'
    # The app-sealed runtime pin the loader reads before dlopen. Its path is
    # recorded relative to the app bundle root; its digest is over the exact
    # sealed bytes. The receipt never contains its own hash -- callers compute
    # that over the finished file.
    printf '  "engineRuntimePinManifestPath":"%s",\n' \
      "${WINN_ENGINE_RUNTIME_PIN_MANIFEST}"
    printf '  "engineRuntimePinManifestSHA256":"%s",\n' \
      "${spike_engine_runtime_pin_manifest_sha}"
    # Exact pins for the three programs that produced this build.
    printf '  "builderSHA256":"%s",\n' "${spike_builder_sha}"
    printf '  "projectGeneratorSHA256":"%s",\n' "${spike_generator_sha}"
    printf '  "engineStagerSHA256":"%s",\n' "${spike_stager_sha}"
    printf '  "evidenceVerifierSHA256":"%s",\n' \
      "${spike_evidence_verifier_sha}"
    printf '  "matrixVerifierSHA256":"%s"\n' \
      "${spike_matrix_verifier_sha}"
    printf '}\n'
  } >"${spike_receipt_staging}"; then
    rm -f "${spike_receipt_staging}"
    return 1
  fi
  chmod 400 "${spike_receipt_staging}" || {
    rm -f "${spike_receipt_staging}"
    return 1
  }
  spike_receipt_digest="$(
    spike_sha256_file "${spike_receipt_staging}"
  )" || {
    chmod u+w "${spike_receipt_staging}" 2>/dev/null || true
    rm -f "${spike_receipt_staging}"
    return 1
  }
  test ! -e "${spike_receipt_final}" || {
    echo "FAIL: build receipt destination already exists." >&2
    chmod u+w "${spike_receipt_staging}" 2>/dev/null || true
    rm -f "${spike_receipt_staging}"
    return 1
  }
  mv "${spike_receipt_staging}" "${spike_receipt_final}" || {
    chmod u+w "${spike_receipt_staging}" 2>/dev/null || true
    rm -f "${spike_receipt_staging}"
    return 1
  }
  printf '%s\n' "${spike_receipt_digest}"
}

spike_write_input_list "${spike_root}" "${spike_input_list}"
spike_builder_sha="$(spike_sha256_file "${spike_pinned_builder}")"
spike_generator_sha="$(spike_sha256_file "${spike_pinned_generator}")"
spike_assert_live_provenance_matches_pins || exit 1
spike_source_digest="$(
  spike_digest_input_list "${spike_root}" "${spike_input_list}"
)"

spike_is_sha256 "${spike_source_digest}" || {
  echo "FAIL: invalid source digest." >&2
  exit 1
}

(
  cd "${spike_root}"
  rsync -a --files-from="${spike_input_list}" ./ "${spike_snapshot_root}/"
)
chmod -R a-w "${spike_snapshot_root}"

spike_write_input_list \
  "${spike_snapshot_root}" \
  "${spike_snapshot_input_list}"
cmp -s "${spike_input_list}" "${spike_snapshot_input_list}" || {
  echo "FAIL: immutable build snapshot has a different input set." >&2
  exit 1
}
spike_snapshot_digest="$(
  spike_digest_input_list \
    "${spike_snapshot_root}" \
    "${spike_snapshot_input_list}"
)"
test "${spike_snapshot_digest}" = "${spike_source_digest}" || {
  echo "FAIL: immutable build snapshot digest mismatch." >&2
  exit 1
}
cmp -s \
  "${spike_pinned_builder}" \
  "${spike_snapshot_root}/Scripts/build_device.sh" || {
  echo "FAIL: digested snapshot builder differs from its immutable pin." >&2
  exit 1
}
cmp -s \
  "${spike_pinned_generator}" \
  "${spike_snapshot_root}/Scripts/generate_project.rb" || {
  echo "FAIL: digested snapshot generator differs from its immutable pin." >&2
  exit 1
}
spike_assert_live_provenance_matches_pins || exit 1
spike_run_provenance_test_checkpoint || exit 1

# The stager must run from the real tree: it derives the engine source custody
# root from its own location, and the snapshot is not inside the repository.
# Comparing it byte-for-byte against the snapshot copy keeps the executed
# stager bound to the digested build inputs -- and because the stager carries
# the source-engine SHA-256 pins as literal constants, that binding puts the
# engine pin itself inside sourceDigest.
spike_stager="${spike_script_dir}/stage_stageb_engine_artifact.sh"
cmp -s \
  "${spike_stager}" \
  "${spike_snapshot_root}/Scripts/stage_stageb_engine_artifact.sh" || {
  echo "FAIL: the engine stager differs from the digested snapshot copy." >&2
  exit 1
}

# Independent of the generator's literal source list: reads what is actually on
# disk and what the checked-in project actually compiles, and refuses any
# disagreement. Runs against the immutable snapshot, which is what xcodebuild
# will consume.
spike_assert_engine_project_wiring "${spike_snapshot_root}" || {
  echo "FAIL: Stage B native/engine project integration guard failed." >&2
  exit 1
}

if test -n "${WINN_SPIKE_DERIVED_DATA:-}"; then
  spike_derived_data="${WINN_SPIKE_DERIVED_DATA}"
  test ! -e "${spike_derived_data}" || {
    echo "FAIL: WINN_SPIKE_DERIVED_DATA must name a fresh path." >&2
    exit 1
  }
  mkdir -p "${spike_derived_data}"
else
  spike_derived_data="$(
    mktemp -d \
      "${TMPDIR:-/tmp}/winn-ios-spike-device-release-${spike_source_digest}.XXXXXX"
  )"
fi
# The engine stager refuses any output root with a symlink path component, and
# TMPDIR lives under /var, which is a symlink to /private/var. Resolve once.
spike_derived_data="$(
  CDPATH='' cd -- "${spike_derived_data}" && pwd -P
)"

# Build the verifier pair fresh for this device artifact. The private staging
# directory is renamed only after both -trimpath binaries and their hashes
# exist, so no stale .derived/tools program can be mistaken for the pin.
spike_tools_staging="${spike_derived_data}/.winn-tools-staging"
spike_tools="${spike_derived_data}/WinnEvidenceTools"
mkdir "${spike_tools_staging}"
(
  cd "${spike_experiment_root}"
  CGO_ENABLED=0 go build \
    -trimpath \
    -buildvcs=false \
    -o "${spike_tools_staging}/evidenceverify" \
    ./spikes/ios_maximum_privacy/evidenceverify
  CGO_ENABLED=0 go build \
    -trimpath \
    -buildvcs=false \
    -o "${spike_tools_staging}/matrixverify" \
    ./spikes/ios_maximum_privacy/matrixverify
)
chmod 500 \
  "${spike_tools_staging}/evidenceverify" \
  "${spike_tools_staging}/matrixverify"
(
  cd "${spike_tools_staging}"
  shasum -a 256 evidenceverify >evidenceverify.sha256
  shasum -a 256 matrixverify >matrixverify.sha256
  chmod 400 evidenceverify.sha256 matrixverify.sha256
)
mv "${spike_tools_staging}" "${spike_tools}"
chmod 500 "${spike_tools}"
(
  cd "${spike_tools}"
  shasum -a 256 -c evidenceverify.sha256
  shasum -a 256 -c matrixverify.sha256
)
spike_evidence_verifier_sha="$(
  spike_sha256_file "${spike_tools}/evidenceverify"
)"
spike_matrix_verifier_sha="$(
  spike_sha256_file "${spike_tools}/matrixverify"
)"

# Fresh derived staging only. mkdir refuses an existing directory and the
# stager publishes with an exclusive rename, so nothing pre-existing can be
# adopted as the engine pin.
spike_engine_dir="${spike_derived_data}/StageBEngine"
mkdir "${spike_engine_dir}"
spike_engine_source_binary_sha="$(
  spike_stage_engine "${spike_stager}" iphoneos "${spike_engine_dir}"
)"
spike_engine_staged_binary="${spike_engine_dir}/${WINN_ENGINE_FRAMEWORK_NAME}/${WINN_ENGINE_BINARY_NAME}"
test "${spike_engine_source_binary_sha}" = \
  "${WINN_ENGINE_DEVICE_SOURCE_SHA256}" || {
  echo "FAIL: the staged engine differs from this script's own device pin." >&2
  exit 1
}

xcodebuild \
  -project "${spike_snapshot_root}/PrivacySpike.xcodeproj" \
  -scheme PrivacySpike \
  -configuration Release \
  -destination "id=${spike_device_udid}" \
  -derivedDataPath "${spike_derived_data}" \
  WINN_STAGEB_ENGINE_DIR="${spike_engine_dir}" \
  WINN_STAGEB_ENGINE_SOURCE_SHA256="${spike_engine_source_binary_sha}" \
  WINN_SPIKE_SOURCE_DIGEST="${spike_source_digest}" \
  build

spike_assert_live_provenance_matches_pins || exit 1

spike_write_input_list \
  "${spike_snapshot_root}" \
  "${spike_snapshot_input_list}"
spike_post_source_digest="$(
  spike_digest_input_list \
    "${spike_snapshot_root}" \
    "${spike_snapshot_input_list}"
)"
test "${spike_post_source_digest}" = "${spike_source_digest}" || {
  echo "FAIL: immutable device-build snapshot changed." >&2
  exit 1
}

# The staged input is the pin. If it changed while Xcode ran, the embedded copy
# cannot be attributed to the artifact validated above.
spike_engine_staged_after="$(spike_sha256_file "${spike_engine_staged_binary}")"
test "${spike_engine_staged_after}" = "${spike_engine_source_binary_sha}" || {
  echo "FAIL: the staged engine input changed during the build." >&2
  exit 1
}

spike_app="${spike_derived_data}/Build/Products/Release-iphoneos/WCF3 Privacy Spike.app"
spike_provider="${spike_app}/PlugIns/WCF3 Privacy Packet Tunnel.appex"
spike_embedded_digest="$(
  plutil -extract WinnSpikeSourceDigest raw \
    -o - "${spike_provider}/Info.plist"
)"
test "${spike_embedded_digest}" = "${spike_source_digest}" || {
  echo "FAIL: provider source digest does not match build inputs." >&2
  exit 1
}
# The host reads its own WinnSpikeSourceDigest and refuses a provider
# attestation whose digest differs, so the two must be built together from one
# source snapshot. Checked here rather than discovered on the device.
spike_host_embedded_digest="$(
  plutil -extract WinnSpikeSourceDigest raw \
    -o - "${spike_app}/Info.plist"
)"
test "${spike_host_embedded_digest}" = "${spike_source_digest}" || {
  echo "FAIL: host source digest does not match build inputs." >&2
  exit 1
}
test "${spike_host_embedded_digest}" = "${spike_embedded_digest}" || {
  echo "FAIL: host and provider source digests disagree." >&2
  exit 1
}
codesign --verify --deep --strict "${spike_app}"
codesign --verify --strict "${spike_provider}"

spike_app_executable="$(
  plutil -extract CFBundleExecutable raw -o - "${spike_app}/Info.plist"
)"
spike_provider_executable="$(
  plutil -extract CFBundleExecutable raw -o - "${spike_provider}/Info.plist"
)"
spike_app_executable_sha="$(
  spike_sha256_file "${spike_app}/${spike_app_executable}"
)"
spike_provider_executable_sha="$(
  spike_sha256_file "${spike_provider}/${spike_provider_executable}"
)"

# --- Stage B engine provenance -------------------------------------------
spike_engine_embedded_relative_path="Frameworks/${WINN_ENGINE_FRAMEWORK_NAME}/${WINN_ENGINE_BINARY_NAME}"
spike_engine_embedded_framework="${spike_app}/Frameworks/${WINN_ENGINE_FRAMEWORK_NAME}"
spike_engine_embedded_binary="${spike_engine_embedded_framework}/${WINN_ENGINE_BINARY_NAME}"

spike_assert_single_embedded_engine \
  "${spike_app}" "${spike_engine_embedded_framework}" || exit 1
spike_assert_no_engine_preload \
  "${spike_provider}/${spike_provider_executable}" \
  "the Packet Tunnel extension" || exit 1
spike_assert_no_engine_preload \
  "${spike_app}/${spike_app_executable}" \
  "the containing app" || exit 1

# CodeSignOnCopy signed the embedded copy; verify that signature before its
# hash is recorded as the runtime pin.
codesign --verify --strict "${spike_engine_embedded_framework}"

spike_assert_engine_identity_continuity \
  "${spike_engine_staged_binary}" \
  "${spike_engine_embedded_binary}" || exit 1

spike_engine_embedded_runtime_binary_sha="$(
  spike_sha256_file "${spike_engine_embedded_binary}"
)"
# The signed runtime binary must NOT equal the unsigned source binary: codesign
# appends a signature. Equality here would mean CodeSignOnCopy did not run and
# the recorded runtime digest is not a signed-runtime digest at all.
test "${spike_engine_embedded_runtime_binary_sha}" != \
  "${spike_engine_source_binary_sha}" || {
  echo "FAIL: the embedded engine was not signed on copy; its runtime digest equals the unsigned source digest." >&2
  exit 1
}

# The app-sealed runtime pin. Verified against independently measured bytes,
# not against itself.
spike_assert_engine_runtime_pin_manifest \
  "${spike_app}" \
  "${spike_engine_source_binary_sha}" \
  iphoneos \
  arm64 \
  "${spike_engine_embedded_binary}" || exit 1
spike_engine_runtime_pin_manifest_sha="$(
  spike_sha256_file "${spike_app}/${WINN_ENGINE_RUNTIME_PIN_MANIFEST}"
)"
# The manifest must be sealed by the app signature, or the loader's whole
# trust argument collapses. codesign lists every sealed resource.
spike_sealed_resources="${spike_derived_data}/app-sealed-resources.txt"
codesign --display -r- --verbose=4 "${spike_app}" >/dev/null 2>&1
plutil -convert xml1 -o "${spike_sealed_resources}" \
  "${spike_app}/_CodeSignature/CodeResources"
grep -Fq "${WINN_ENGINE_RUNTIME_PIN_MANIFEST}" "${spike_sealed_resources}" || {
  echo "FAIL: the engine runtime pin manifest is not sealed by the app signature." >&2
  exit 1
}

spike_stager_sha="$(spike_sha256_file "${spike_stager}")"

# Re-check the verifier pins after the Apple build and bind every executable
# needed to evaluate collected evidence into one machine-readable receipt.
(
  cd "${spike_tools}"
  shasum -a 256 -c evidenceverify.sha256
  shasum -a 256 -c matrixverify.sha256
)
spike_assert_live_provenance_matches_pins || exit 1
spike_build_receipt="${spike_derived_data}/WINN_SPIKE_BUILD_RECEIPT.json"
spike_build_receipt_sha="$(
  spike_publish_build_receipt "${spike_build_receipt}"
)"

printf 'PASS: signed physical-device build from immutable source snapshot\n'
printf 'source_digest=%s\n' "${spike_source_digest}"
printf 'app_executable_sha256=%s\n' "${spike_app_executable_sha}"
printf 'provider_executable_sha256=%s\n' "${spike_provider_executable_sha}"
printf 'engine_source_binary_sha256=%s\n' "${spike_engine_source_binary_sha}"
printf 'engine_embedded_runtime_binary_sha256=%s\n' \
  "${spike_engine_embedded_runtime_binary_sha}"
printf 'engine_runtime_pin_manifest_sha256=%s\n' \
  "${spike_engine_runtime_pin_manifest_sha}"
printf 'evidence_verifier_sha256=%s\n' "${spike_evidence_verifier_sha}"
printf 'matrix_verifier_sha256=%s\n' "${spike_matrix_verifier_sha}"
printf 'build_receipt=%s\n' "${spike_build_receipt}"
printf 'build_receipt_sha256=%s\n' "${spike_build_receipt_sha}"
printf 'app=%s\n' "${spike_app}"
