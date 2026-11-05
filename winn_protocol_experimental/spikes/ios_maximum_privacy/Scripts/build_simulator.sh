#!/bin/sh
set -eu

# Simulator build. This is a PLUMBING CHECK ONLY: it proves the host app, the
# Packet Tunnel extension, the Stage B native translation units, and the shared
# WinnPrivacyCore package compile and link together for iOS, and that the
# staged AWG engine framework is embedded exactly once in the containing app
# with no extension-local copy and no load-time dependency from the provider.
# It runs nothing, measures nothing, and satisfies no gate. A Packet Tunnel
# extension cannot produce physical activation, memory, battery, or
# start-latency evidence in the Simulator; only the signed physical-device run
# can.
#
# Code signing is disabled on this lane, so nothing here proves anything about
# signatures. What it does prove about the engine is unsigned-copy fidelity:
# with CodeSignOnCopy unable to run, the embedded runtime binary must be
# byte-identical to the staged unsigned input, and this script refuses if it is
# not. The signed device lane legitimately produces a different runtime digest,
# which is why the two are recorded under separate names there.

spike_script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
spike_root="$(CDPATH='' cd -- "${spike_script_dir}/.." && pwd)"

# This script's own declaration of the unsigned simulator source pin. See the
# equivalent note in build_device.sh: agreement with the stager is not proof of
# intent, but a unilateral edit of either file is refused.
WINN_ENGINE_SIMULATOR_SOURCE_SHA256="00a17dfd702dc0490efd4f39bc2259fcc38fa4eed8311885499b5f1611713fa3"

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

spike_assert_engine_project_wiring "${spike_root}" || {
  echo "FAIL: Stage B native/engine project integration guard failed." >&2
  exit 1
}

# mktemp -d hands back a path under /var, which is a symlink to /private/var.
# The engine stager refuses any output root with a symlink path component, so
# resolve the fresh directory once instead of passing the logical spelling.
spike_derived_data="$(
  CDPATH='' cd -- "$(
    mktemp -d "${TMPDIR:-/tmp}/winn-ios-spike-simulator.XXXXXX"
  )" && pwd -P
)"

# Fresh derived staging only. mkdir refuses an existing directory and the
# stager publishes with an exclusive rename, so nothing pre-existing can be
# adopted as the engine pin.
spike_engine_dir="${spike_derived_data}/StageBEngine"
mkdir "${spike_engine_dir}"
spike_engine_source_binary_sha="$(
  spike_stage_engine \
    "${spike_script_dir}/stage_stageb_engine_artifact.sh" \
    iphonesimulator \
    "${spike_engine_dir}"
)"
spike_engine_staged_binary="${spike_engine_dir}/${WINN_ENGINE_FRAMEWORK_NAME}/${WINN_ENGINE_BINARY_NAME}"
test "${spike_engine_source_binary_sha}" = \
  "${WINN_ENGINE_SIMULATOR_SOURCE_SHA256}" || {
  echo "FAIL: the staged engine differs from this script's own simulator pin." >&2
  exit 1
}

# arm64 only for the app and extension. The x86_64 simulator SDK's
# `task_power_info_v2` has no `task_energy` member, which the Stage A resource
# sampler reads; that is a pre-existing property of the x86_64 slice, not of
# this change, and the physical target is arm64 in any case. The embedded
# engine framework stays universal: nothing thins an embedded framework here.

# A placeholder digest keeps the Info.plist substitution well formed. The
# provider refuses an all-zero digest at run time, which is correct: a
# simulator build is not evidence.
spike_placeholder_digest="${WINN_SPIKE_SOURCE_DIGEST:-$(
  printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
)}"

xcodebuild \
  -project "${spike_root}/PrivacySpike.xcodeproj" \
  -scheme PrivacySpike \
  -configuration Debug \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath "${spike_derived_data}" \
  ARCHS=arm64 \
  ONLY_ACTIVE_ARCH=NO \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY= \
  CODE_SIGN_ENTITLEMENTS= \
  WINN_STAGEB_ENGINE_DIR="${spike_engine_dir}" \
  WINN_STAGEB_ENGINE_SOURCE_SHA256="${spike_engine_source_binary_sha}" \
  WINN_SPIKE_SOURCE_DIGEST="${spike_placeholder_digest}" \
  build

# The staged input is the pin. If it changed while Xcode ran, the embedded copy
# cannot be attributed to the artifact validated above.
spike_engine_staged_after="$(spike_sha256_file "${spike_engine_staged_binary}")"
test "${spike_engine_staged_after}" = "${spike_engine_source_binary_sha}" || {
  echo "FAIL: the staged engine input changed during the build." >&2
  exit 1
}

spike_app="${spike_derived_data}/Build/Products/Debug-iphonesimulator/WCF3 Privacy Spike.app"
spike_provider="${spike_app}/PlugIns/WCF3 Privacy Packet Tunnel.appex"
spike_app_executable="$(
  plutil -extract CFBundleExecutable raw -o - "${spike_app}/Info.plist"
)"
spike_provider_executable="$(
  plutil -extract CFBundleExecutable raw -o - "${spike_provider}/Info.plist"
)"

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
spike_assert_engine_identity_continuity \
  "${spike_engine_staged_binary}" \
  "${spike_engine_embedded_binary}" || exit 1

spike_engine_embedded_runtime_binary_sha="$(
  spike_sha256_file "${spike_engine_embedded_binary}"
)"

# Signing is disabled on this lane, so CodeSignOnCopy cannot rewrite the
# Mach-O. The embedded runtime binary must therefore still be byte-identical to
# the staged unsigned input. This equality is a property of the UNSIGNED lane
# only.
test "${spike_engine_embedded_runtime_binary_sha}" = \
  "${spike_engine_source_binary_sha}" || {
  echo "FAIL: the unsigned embedded engine differs from the staged input." >&2
  exit 1
}

spike_assert_engine_runtime_pin_manifest \
  "${spike_app}" \
  "${spike_engine_source_binary_sha}" \
  iphonesimulator \
  arm64,x86_64 \
  "${spike_engine_embedded_binary}" || exit 1
spike_engine_runtime_pin_manifest_sha="$(
  spike_sha256_file "${spike_app}/${WINN_ENGINE_RUNTIME_PIN_MANIFEST}"
)"

# Sealing is NOT checked on this lane and is not claimed: code signing is
# disabled here, so the app has no _CodeSignature to seal the manifest into.
# This lane proves the manifest's bytes and timing-relevant content only. Only
# the signed device build can show the manifest sealed by the app signature,
# and only there does the runtime digest differ from the source digest, which
# is what makes post-signing timing observable at all.

printf 'PASS: iOS Simulator plumbing build only. No physical evidence.\n'
printf 'derived_data=%s\n' "${spike_derived_data}"
printf 'engine_source_binary_sha256=%s\n' "${spike_engine_source_binary_sha}"
printf 'engine_embedded_runtime_binary_sha256=%s\n' \
  "${spike_engine_embedded_runtime_binary_sha}"
printf 'engine_runtime_pin_manifest_sha256=%s\n' \
  "${spike_engine_runtime_pin_manifest_sha}"
printf 'engine_embedded_framework=%s\n' "${spike_engine_embedded_framework}"
