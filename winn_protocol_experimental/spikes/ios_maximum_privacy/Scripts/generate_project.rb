#!/usr/bin/env ruby
# frozen_string_literal: true

require "pathname"
require "xcodeproj"
require "digest"
require "json"

UUID_PATTERN = /\A[0-9A-F]{24}\z/.freeze

# Xcodeproj normally seeds object identifiers from SecureRandom. That makes
# two otherwise identical clean generations byte-different and weakens the
# checked-in-project drift gate. This generator is the sole creator of the
# project, so use a creation-order-stable identifier stream scoped to each
# project instance.
module WinnDeterministicProjectUUIDs
  def generate_available_uuid_list(count = 100)
    @winn_deterministic_uuid_counter ||= 0
    candidates = (0..count).map do
      @winn_deterministic_uuid_counter += 1
      Digest::SHA256.hexdigest(
        "winn-privacy-spike-xcode-object:" \
        "#{@winn_deterministic_uuid_counter}"
      )[0, 24].upcase
    end
    unique = candidates - (@generated_uuids + uuids)
    @generated_uuids += unique
    @available_uuids += unique
  end
end

Xcodeproj::Project.prepend(WinnDeterministicProjectUUIDs)

# Stage B engine framework, staged by Scripts/stage_stageb_engine_artifact.sh
# into a caller-owned derived directory that the build scripts pass to
# xcodebuild as WINN_STAGEB_ENGINE_DIR. The reference resolves through that
# build setting rather than a checked-in path, because the staged framework is
# a derived artifact and must never be committed into the spike tree.
ENGINE_FRAMEWORK_NAME = "WinsAmneziaWGPacketEngine.framework"
ENGINE_FRAMEWORK_SOURCE_TREE = "WINN_STAGEB_ENGINE_DIR"
ENGINE_RUNTIME_PIN_MANIFEST = "WinnStageBEngineRuntimePin.manifest"
ENGINE_EMBEDDED_RELATIVE_PATH =
  "Frameworks/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine"
ENGINE_INSTALL_NAME =
  "@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine"

# The app-sealed runtime pin that NativeEngine/WinnStageBFrameworkDarwin.c
# reads before dlopen. Its parser is a whole-file sscanf against a fixed
# prefix with %n, so the file must be exactly these seven LF-terminated lines
# with no trailing byte, under 1024 bytes, a regular file with st_nlink == 1,
# opened O_NOFOLLOW.
#
# Two ordering facts make this script phase correct, and both are enforced
# rather than assumed:
#
#   1. It must run AFTER the embedded framework has its final runtime bytes.
#      Declaring the embedded engine binary as the phase's input file makes
#      XCBuild order this task after the copy-and-CodeSignOnCopy task that
#      produces it. Phase position alone would not guarantee that; the
#      declared dependency does.
#
#   2. It must run BEFORE the containing app is signed, or the manifest would
#      not be sealed by the app signature. Xcode signs a target's product
#      after every build phase of that target has run, so any script phase of
#      the app target is inside that window. This phase is placed last to make
#      the intent legible.
#
# The source digest arrives as an independently pinned build setting. The
# runtime digest is measured here from the actual embedded bytes and can never
# be supplied by the caller -- a caller-supplied runtime digest would make the
# pin prove nothing, so the script refuses outright if one is present in the
# environment.
ENGINE_RUNTIME_PIN_SCRIPT = <<~'SCRIPT'
  set -eu

  # A caller-supplied runtime digest would defeat the entire pin: the point is
  # that these bytes were measured from what actually shipped.
  if [ -n "${WINN_STAGEB_ENGINE_RUNTIME_SHA256:-}" ]; then
    echo "error: the runtime digest is measured here, never supplied" >&2
    exit 1
  fi

  winn_source_sha256="${WINN_STAGEB_ENGINE_SOURCE_SHA256:-}"
  if [ "${#winn_source_sha256}" -ne 64 ]; then
    echo "error: WINN_STAGEB_ENGINE_SOURCE_SHA256 must be 64 hex digits" >&2
    exit 1
  fi
  case "${winn_source_sha256}" in
    *[!0123456789abcdef]*)
      echo "error: WINN_STAGEB_ENGINE_SOURCE_SHA256 must be lowercase hex" >&2
      exit 1
      ;;
  esac

  winn_engine="${SCRIPT_INPUT_FILE_0}"
  winn_manifest="${SCRIPT_OUTPUT_FILE_0}"

  if [ -L "${winn_engine}" ] || [ ! -f "${winn_engine}" ]; then
    echo "error: embedded engine is not a regular file: ${winn_engine}" >&2
    exit 1
  fi
  # The loader refuses st_nlink != 1, so a hard-linked copy would build here
  # and fail on device.
  winn_links="$(stat -f '%l' "${winn_engine}")"
  if [ "${winn_links}" != "1" ]; then
    echo "error: embedded engine has ${winn_links} hard links; 1 required" >&2
    exit 1
  fi

  case "${PLATFORM_NAME}" in
    iphoneos) winn_expected_arches="arm64" ;;
    iphonesimulator) winn_expected_arches="arm64,x86_64" ;;
    *)
      echo "error: unsupported platform for the engine pin" >&2
      exit 1
      ;;
  esac

  winn_raw_arches="$(xcrun lipo -archs "${winn_engine}")"
  winn_arches="$(
    printf '%s\n' ${winn_raw_arches} |
      LC_ALL=C sort |
      awk 'BEGIN { sep = "" } { printf "%s%s", sep, $0; sep = "," } END { print "" }'
  )"
  if [ "${winn_arches}" != "${winn_expected_arches}" ]; then
    echo "error: embedded engine architectures ${winn_arches} do not match ${winn_expected_arches}" >&2
    exit 1
  fi

  winn_runtime_sha256="$(shasum -a 256 "${winn_engine}" | awk '{ print $1 }')"
  if [ "${#winn_runtime_sha256}" -ne 64 ]; then
    echo "error: could not measure the embedded engine digest" >&2
    exit 1
  fi
  case "${winn_runtime_sha256}" in
    *[!0123456789abcdef]*)
      echo "error: measured engine digest is not lowercase hex" >&2
      exit 1
      ;;
  esac

  # Replacement policy for the declared output.
  #
  # Xcode does not promise to delete a script phase's declared outputs before
  # rerunning it, and this phase legitimately reruns whenever the embedded
  # engine changes. A plain noclobber create therefore fails the second valid
  # build -- verified, not assumed: build, touch the staged engine, rebuild,
  # and the second build exits 65 with "cannot overwrite existing file".
  #
  # So the stale file is removed first. That is deliberately NOT adoption: the
  # previous bytes are never opened, read, parsed, or trusted, and every byte
  # written below is derived from the measured engine plus the independently
  # pinned source digest. The distinction being enforced is replacing a file
  # inside the build's own declared output path versus inheriting content of
  # unknown provenance -- only the former happens here.
  #
  # Anything at that path which is not a plain regular file is refused rather
  # than removed, so a planted symlink or directory fails the build instead of
  # redirecting the write. The create then still uses noclobber, which is an
  # O_CREAT|O_EXCL open: it cannot follow a symlink planted in the window
  # between the removal and the create, and it fails closed if anything raced
  # in.
  #
  # Xcode script sandboxing constrains the shape of this: the phase may only
  # touch paths it declared. Writing to a temporary sibling and renaming would
  # need a second declared path, and declaring a temp file as a build output
  # would make it a tracked artifact. Removing and recreating the one declared
  # output is the only form available that is both sandbox-legal and
  # non-adopting.
  if [ -e "${winn_manifest}" ] || [ -L "${winn_manifest}" ]; then
    if [ -L "${winn_manifest}" ] || [ ! -f "${winn_manifest}" ]; then
      echo "error: refusing to replace a non-regular runtime pin at ${winn_manifest}" >&2
      exit 1
    fi
    rm -- "${winn_manifest}"
  fi
  set -C
  printf '%s\n' \
    'schema=winn-stageb-engine-runtime-pin/1' \
    "source_binary_sha256=${winn_source_sha256}" \
    "signed_runtime_binary_sha256=${winn_runtime_sha256}" \
    'relative_path=RELATIVE_PATH_TOKEN' \
    "platform=${PLATFORM_NAME}" \
    "architectures=${winn_arches}" \
    'install_name=INSTALL_NAME_TOKEN' \
    >"${winn_manifest}"
SCRIPT
    .gsub("RELATIVE_PATH_TOKEN", ENGINE_EMBEDDED_RELATIVE_PATH)
    .gsub("INSTALL_NAME_TOKEN", ENGINE_INSTALL_NAME)

# The compiled Stage B native sources and their headers are literal, ordered
# lists rather than a directory glob.
#
# Scripts/verify.sh proves the checked-in project has no manual drift by
# copying ONLY this script into an otherwise empty scratch root, regenerating
# there, and comparing UUID-independent canonical graph manifests. Any
# inclusion decision that reads the filesystem would therefore make the
# regenerated graph differ from the checked-in one in the scratch root, where
# NativeEngine does not exist at all -- a drift report with no drift.
#
# Keeping the list literal makes generation deterministic in both roots. The
# inventory guard below is what keeps the literal list honest wherever the real
# NativeEngine directory is present, and Scripts/build_device.sh and
# Scripts/build_simulator.sh independently refuse to build when a NativeEngine
# translation unit on disk is absent from the generated project.
NATIVE_ENGINE_SOURCES = [
  "WinnAWGUAPISanitizer.c",
  "WinnStageBDarwinUtun.c",
  "WinnStageBFrameworkDarwin.c",
  "WinnStageBFrameworkLoader.c",
  "WinnStageBNativeEngine.c",
  "WinnStageBProviderNativeOwner.c"
].freeze

NATIVE_ENGINE_HEADERS = [
  "WinnAWGUAPISanitizer.h",
  "WinnStageBDarwinUtun.h",
  "WinnStageBFrameworkDarwin.h",
  "WinnStageBFrameworkLoader.h",
  "WinnStageBFrameworkLoaderInternal.h",
  "WinnStageBNativeEngine.h",
  "WinnStageBProviderNativeOwner.h",
  "WinnStageBProviderNativeOwnerInternal.h"
].freeze

# Sources known to be planned but not yet present. A name listed here is NOT
# compiled; it exists only so the guard can emit a precise instruction instead
# of a generic "unexpected file" when the file lands. Promoting a name from
# this list to NATIVE_ENGINE_SOURCES and regenerating is the whole integration
# step. Empty is the steady state: nothing is currently awaiting promotion.
NATIVE_ENGINE_PENDING_SOURCES = [].freeze

def check_native_engine_inventory(native_engine_dir)
  # Skipped when the directory is absent, which is exactly the scratch-root
  # regeneration case. This guard cannot detect drift there; the build scripts
  # cover the real tree independently.
  return unless native_engine_dir.directory?

  present = native_engine_dir.children.reject(&:directory?).map { |child|
    child.basename.to_s
  }

  [
    [NATIVE_ENGINE_SOURCES, ".c", "source"],
    [NATIVE_ENGINE_HEADERS, ".h", "header"]
  ].each do |expected, extension, label|
    on_disk = present.select { |name| name.end_with?(extension) }.sort
    missing = expected - on_disk
    unless missing.empty?
      abort(
        "NativeEngine #{label}(s) referenced by this generator are absent: " \
        "#{missing.join(', ')}"
      )
    end
    unexpected = on_disk - expected
    unexpected.each do |name|
      if NATIVE_ENGINE_PENDING_SOURCES.include?(name)
        abort(
          "NativeEngine/#{name} now exists but is not compiled. Move it from " \
          "NATIVE_ENGINE_PENDING_SOURCES to NATIVE_ENGINE_SOURCES in " \
          "Scripts/generate_project.rb and regenerate the project."
        )
      end
      abort(
        "NativeEngine/#{name} is an unlisted #{label}. Add it to this " \
        "generator's literal list and regenerate the project."
      )
    end
  end
end

def canonical_project_manifest(project_path)
  plist = Xcodeproj::Plist.read_from_path(
    project_path.join("project.pbxproj").to_s
  )
  objects = plist.fetch("objects")
  hashes = objects.transform_values do |object|
    Digest::SHA256.hexdigest(
      JSON.generate(canonical_value(object) { "REF" })
    )
  end
  (objects.length + 2).times do
    previous = hashes
    hashes = objects.transform_values do |object|
      Digest::SHA256.hexdigest(
        JSON.generate(
          canonical_value(object) do |uuid|
            "REF:#{previous.fetch(uuid)}"
          end
        )
      )
    end
  end
  root_uuid = plist.fetch("rootObject")
  JSON.generate(
    "archiveVersion" => plist.fetch("archiveVersion"),
    "objectVersion" => plist.fetch("objectVersion"),
    "classes" => canonical_value(plist.fetch("classes")) { "REF" },
    "rootHash" => hashes.fetch(root_uuid),
    "objectHashes" => hashes.values.sort
  )
end

def canonical_value(value, &reference)
  case value
  when Hash
    value.keys.sort.each_with_object({}) do |key, output|
      output[key] = canonical_value(value.fetch(key), &reference)
    end
  when Array
    value.map { |element| canonical_value(element, &reference) }
  when String
    UUID_PATTERN.match?(value) ? reference.call(value) : value
  else
    value
  end
end

if ARGV.first == "--canonical-manifest"
  candidate = ARGV.fetch(1) {
    abort "usage: #{$PROGRAM_NAME} --canonical-manifest PROJECT.xcodeproj"
  }
  puts canonical_project_manifest(Pathname.new(candidate).expand_path)
  exit
end

root = Pathname.new(__dir__).parent.expand_path
project_path = root.join("PrivacySpike.xcodeproj")
abort "Refusing to overwrite #{project_path}" if project_path.exist?

check_native_engine_inventory(root.join("NativeEngine"))

project = Xcodeproj::Project.new(project_path.to_s)
project.root_object.attributes["LastSwiftUpdateCheck"] = "2650"
project.root_object.attributes["LastUpgradeCheck"] = "2650"

base_config = project.main_group.new_file("Config/Base.xcconfig")
host_group = project.main_group.new_group("Host", "Host")
provider_group = project.main_group.new_group("PacketTunnel", "PacketTunnel")
native_engine_group = project.main_group.new_group(
  "NativeEngine",
  "NativeEngine"
)

host = project.new_target(
  :application,
  "PrivacySpike",
  :ios,
  "17.0"
)
provider = project.new_target(
  :app_extension,
  "PrivacySpikePacketTunnel",
  :ios,
  "17.0"
)

# Xcodeproj seeds each new target with an explicit Foundation.framework
# reference under DEVELOPER_DIR that hardcodes the SDK version present when the
# project was generated (for example iPhoneOS26.0.sdk). That path does not
# exist on a host with a different SDK installed, and it pins the project to
# one Xcode. Swift and the C translation units here resolve Foundation through
# SDKROOT and their own imports, so drop the reference entirely rather than
# rewrite it to another version that will also go stale.
[host, provider].each do |target|
  target.frameworks_build_phase.files.to_a.each do |build_file|
    reference = build_file.file_ref
    next if reference.nil?
    build_file.remove_from_project
    # referrers still includes the owning group at this point, so an
    # emptiness test would never fire and would leave the SDK-pinned path
    # behind in the Frameworks group. Drop the reference once no build file
    # anywhere in the project still points at it.
    still_linked = project.objects.any? { |object|
      object.is_a?(Xcodeproj::Project::Object::PBXBuildFile) &&
        object.file_ref == reference
    }
    reference.remove_from_project unless still_linked
  end
end
project.frameworks_group.groups.each do |group|
  group.remove_from_project if group.children.empty?
end
if project.frameworks_group.children.empty?
  project.frameworks_group.remove_from_project
end

[
  "CollectedEvidenceValidator.swift",
  "ImmutableReceiptStore.swift",
  "PrivacySpikeApp.swift",
  "RunView.swift",
  "VPNController.swift"
].each do |name|
  host.source_build_phase.add_file_reference(host_group.new_file(name))
end
host_group.new_file("Info.plist")
host_group.new_file("Host.entitlements")

provider.source_build_phase.add_file_reference(
  provider_group.new_file("PacketTunnelProvider.swift")
)
provider.source_build_phase.add_file_reference(
  provider_group.new_file("StageBProviderNativeAdapterSeam.swift")
)
provider_group.new_file("StageBProviderNativeBridge.h")
provider_group.new_file("Info.plist")
provider_group.new_file("PacketTunnel.entitlements")

# The Stage B native translation units compile into the Packet Tunnel
# extension only. The host never links them, so no host-side code path can
# reach the AWG data plane.
NATIVE_ENGINE_SOURCES.each do |name|
  source = native_engine_group.new_file(name)
  # Xcodeproj has no default file type for ".c"; state it rather than leaving
  # the translation unit's language to Xcode's extension inference.
  source.last_known_file_type = "sourcecode.c.c"
  provider.source_build_phase.add_file_reference(source)
end
NATIVE_ENGINE_HEADERS.each do |name|
  native_engine_group.new_file(name)
end

local_package = project.new(
  Xcodeproj::Project::Object::XCLocalSwiftPackageReference
)
local_package.relative_path = "PrivacyCore"
project.root_object.package_references << local_package

# Both targets depend on WinnPrivacyCore: the provider for the Stage A
# harness, and the host for the shared start-latency model and validator that
# binds its receipt to the provider's attestation.
[provider, host].each do |target|
  dependency = project.new(
    Xcodeproj::Project::Object::XCSwiftPackageProductDependency
  )
  dependency.package = local_package
  dependency.product_name = "WinnPrivacyCore"
  target.package_product_dependencies << dependency

  build_file = project.new(Xcodeproj::Project::Object::PBXBuildFile)
  build_file.product_ref = dependency
  target.frameworks_build_phase.files << build_file
end

# Stage B remains isolated from the host and Stage A harness. Only the Packet
# Tunnel extension links the provider coordinator product, through a narrow
# native-adapter seam that is compile-gated before any physical run.
stage_b_dependency = project.new(
  Xcodeproj::Project::Object::XCSwiftPackageProductDependency
)
stage_b_dependency.package = local_package
stage_b_dependency.product_name = "WinnStageBProviderCore"
provider.package_product_dependencies << stage_b_dependency

stage_b_build_file = project.new(Xcodeproj::Project::Object::PBXBuildFile)
stage_b_build_file.product_ref = stage_b_dependency
provider.frameworks_build_phase.files << stage_b_build_file

# The staged AWG engine framework is embedded exactly once, by the containing
# app, into App.app/Frameworks. Two deliberate omissions define this design:
#
# 1. The Packet Tunnel extension does NOT link it. An LC_LOAD_DYLIB entry in
#    the provider would let dyld map the engine and run its initializers
#    before WinnStageBFrameworkLoader could hash or signature-check anything,
#    which would defeat the attestation entirely. The provider's native core
#    reaches the engine through injected `wg` callbacks populated by the
#    loader's own dlopen, after attestation -- never through a link-time
#    dependency. Scripts/build_device.sh asserts zero engine LC_LOAD_DYLIB
#    entries against the built provider binary.
#
# 2. The extension has no copy phase for it either. A second, extension-local
#    copy would give the provider a runtime binary whose signature and hash
#    are not the ones the build receipt attests, which is precisely the
#    source-vs-runtime confusion this lane exists to prevent.
engine_framework = project.new(Xcodeproj::Project::Object::PBXFileReference)
engine_framework.path = ENGINE_FRAMEWORK_NAME
engine_framework.source_tree = ENGINE_FRAMEWORK_SOURCE_TREE
engine_framework.last_known_file_type = "wrapper.framework"
engine_framework.include_in_index = "0"
project.frameworks_group << engine_framework

host.add_dependency(provider)

embed_frameworks = host.new_copy_files_build_phase("Embed Frameworks")
embed_frameworks.dst_subfolder_spec = "10"
embedded_engine = project.new(Xcodeproj::Project::Object::PBXBuildFile)
embedded_engine.file_ref = engine_framework
embedded_engine.settings = {
  "ATTRIBUTES" => %w[CodeSignOnCopy RemoveHeadersOnCopy]
}
embed_frameworks.files << embedded_engine

embed_extensions = host.new_copy_files_build_phase("Embed App Extensions")
embed_extensions.dst_subfolder_spec = "13"
embedded_provider = project.new(Xcodeproj::Project::Object::PBXBuildFile)
embedded_provider.file_ref = provider.product_reference
embedded_provider.settings = {
  "ATTRIBUTES" => ["RemoveHeadersOnCopy"]
}
embed_extensions.files << embedded_provider

# Placed last so the ordering reads copy -> manifest -> Xcode's own signing of
# the app product. The declared input/output pair is what actually enforces
# the first arrow; see ENGINE_RUNTIME_PIN_SCRIPT.
engine_pin_phase = host.new_shell_script_build_phase(
  "Seal Stage B Engine Runtime Pin"
)
engine_pin_phase.shell_path = "/bin/sh"
engine_pin_phase.shell_script = ENGINE_RUNTIME_PIN_SCRIPT
engine_pin_phase.input_paths = [
  "$(TARGET_BUILD_DIR)/$(CONTENTS_FOLDER_PATH)/#{ENGINE_EMBEDDED_RELATIVE_PATH}"
]
engine_pin_phase.output_paths = [
  "$(TARGET_BUILD_DIR)/$(CONTENTS_FOLDER_PATH)/#{ENGINE_RUNTIME_PIN_MANIFEST}"
]
engine_pin_phase.run_only_for_deployment_postprocessing = "0"
engine_pin_phase.show_env_vars_in_log = "0"

project.build_configuration_list.build_configurations.each do |config|
  config.base_configuration_reference = base_config
  config.build_settings["IPHONEOS_DEPLOYMENT_TARGET"] = "17.0"
end

host.build_configurations.each do |config|
  config.base_configuration_reference = base_config
  settings = config.build_settings
  settings["PRODUCT_BUNDLE_IDENTIFIER"] = "$(SPIKE_HOST_BUNDLE_ID)"
  settings["PRODUCT_NAME"] = "WCF3 Privacy Spike"
  settings["INFOPLIST_FILE"] = "Host/Info.plist"
  settings["CODE_SIGN_ENTITLEMENTS"] = "Host/Host.entitlements"
  settings["DEVELOPMENT_TEAM"] = "5YT8H4U72M"
  settings["CODE_SIGN_STYLE"] = "Automatic"
  settings["SUPPORTED_PLATFORMS"] = "iphoneos iphonesimulator"
  settings["SUPPORTS_MACCATALYST"] = "NO"
  settings["TARGETED_DEVICE_FAMILY"] = "1"
  settings["GENERATE_INFOPLIST_FILE"] = "NO"
  settings["SWIFT_EMIT_LOC_STRINGS"] = "YES"
end

provider.build_configurations.each do |config|
  config.base_configuration_reference = base_config
  settings = config.build_settings
  settings["PRODUCT_BUNDLE_IDENTIFIER"] = "$(SPIKE_PROVIDER_BUNDLE_ID)"
  settings["PRODUCT_NAME"] = "WCF3 Privacy Packet Tunnel"
  settings["INFOPLIST_FILE"] = "PacketTunnel/Info.plist"
  settings["CODE_SIGN_ENTITLEMENTS"] =
    "PacketTunnel/PacketTunnel.entitlements"
  settings["DEVELOPMENT_TEAM"] = "5YT8H4U72M"
  settings["CODE_SIGN_STYLE"] = "Automatic"
  settings["SUPPORTED_PLATFORMS"] = "iphoneos iphonesimulator"
  settings["SUPPORTS_MACCATALYST"] = "NO"
  settings["TARGETED_DEVICE_FAMILY"] = "1"
  settings["GENERATE_INFOPLIST_FILE"] = "NO"
  settings["APPLICATION_EXTENSION_API_ONLY"] = "YES"
  settings["SKIP_INSTALL"] = "YES"
  settings["SWIFT_OBJC_BRIDGING_HEADER"] =
    "PacketTunnel/StageBProviderNativeBridge.h"
  # No @rpath search entry resolves to App.app/Frameworks, and no framework
  # search path points at the staged engine. Both omissions are deliberate.
  # The engine's install name is
  # @rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine, so
  # withholding the runpath entry means that even if an engine LC_LOAD_DYLIB
  # were reintroduced by mistake, dyld would have no path on which to resolve
  # it -- the provider would fail to launch rather than silently mapping the
  # engine ahead of attestation.
  #
  # This layout is what NativeEngine/WinnStageBFrameworkLoader.c requires.
  # Its winn_path_is_canonical_engine predicate accepts only an absolute path
  # that ends in
  # ".app/Frameworks/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine"
  # and rejects any "//" or "/." component, so the engine must be the
  # containing app's single embedded copy and must be reached by a canonical
  # path rather than by traversal out of the extension bundle. Embedding into
  # App.app/Frameworks and refusing an extension-local copy is precisely what
  # satisfies that predicate.
  #
  # The two lanes are coupled here: if that suffix or that predicate changes,
  # this embed location and the build scripts' containment assertions must
  # change with it. Neither side can be edited alone.
  settings["LD_RUNPATH_SEARCH_PATHS"] =
    "$(inherited) @executable_path/Frameworks"
  settings["HEADER_SEARCH_PATHS"] = "$(inherited) $(SRCROOT)/NativeEngine"
end

# This project is entirely generated. Keep its collections sorted before
# saving so the deterministic identifiers above also produce stable bytes.
project.sort
project.save

scheme = Xcodeproj::XCScheme.new
scheme.configure_with_targets(host, nil, launch_target: true)
scheme.save_as(project_path.to_s, "PrivacySpike", true)

puts "Generated #{project_path}"
