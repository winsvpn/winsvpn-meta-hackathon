import Foundation

struct WinsNativeEngineArtifactLocator {
  struct Resolution {
    let isResolved: Bool
    let resolvedVia: String
    let diagnostics: [String: Any]
  }

  static func resolve(
    component: String,
    bundle: Bundle,
    fileManager: FileManager = .default
  ) -> Resolution {
    let sanitized = component.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    let artifactNames: [String]
    switch sanitized {
    case "amneziawg_packet_engine":
      artifactNames = ["WinsAmneziaWGPacketEngine", "AmneziaWGPacketEngine", "amneziawg_packet_engine"]
    case "winn_packet_engine":
      artifactNames = ["WinsWinnPacketEngine", "WinnPacketEngine", "winn_packet_engine"]
    case "xray_vless_ws_transport":
      artifactNames = ["WinsXrayVlessWsTransport", "XrayVlessWsTransport", "xray_vless_ws_transport"]
    default:
      artifactNames = [component]
    }
    let prefix = "engine_runtime_lookup_\(sanitized)_"
    var diagnostics: [String: Any] = [:]
    // Find frameworks directory
    let frameworksURLs: [URL] = [
      bundle.bundleURL.appendingPathComponent("Frameworks", isDirectory: true),
      bundle.bundleURL.deletingLastPathComponent().appendingPathComponent("Frameworks", isDirectory: true),
      bundle.bundleURL.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Frameworks", isDirectory: true),
      bundle.bundleURL.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Frameworks", isDirectory: true),
      bundle.resourceURL?.appendingPathComponent("Frameworks", isDirectory: true),
      bundle.bundleURL.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Frameworks", isDirectory: true)
    ].compactMap { $0 }

    var fwDirFound = false
    var fwDirURL: URL?
    for url in frameworksURLs {
      var isDir: ObjCBool = false
      if fileManager.fileExists(atPath: url.path, isDirectory: &isDir), isDir.boolValue {
        fwDirFound = true
        fwDirURL = url
        break
      }
    }
    // Also check Runner.app/Frameworks for test bundles
    if !fwDirFound {
      // For temporary probe bundles, the bundle is at Runner.app
      let runnerFrameworks = bundle.bundleURL.appendingPathComponent("Frameworks", isDirectory: true)
      var isDir: ObjCBool = false
      if fileManager.fileExists(atPath: runnerFrameworks.path, isDirectory: &isDir), isDir.boolValue {
        fwDirFound = true
        fwDirURL = runnerFrameworks
      }
    }
    diagnostics["\(prefix)fw_dir_found"] = fwDirFound

    var binExists = false
    var binReadable = false
    var binExecBit = false
    var resolvedVia = ""
    var isResolved = false

    if let fwDirURL = fwDirURL {
      for artifact in artifactNames {
        let frameworkDir = fwDirURL.appendingPathComponent("\(artifact).framework", isDirectory: true)
        var isDir: ObjCBool = false
        let fwExists = fileManager.fileExists(atPath: frameworkDir.path, isDirectory: &isDir) && isDir.boolValue
        if fwExists {
          let binaryURL = frameworkDir.appendingPathComponent(artifact, isDirectory: false)
          let exists = fileManager.fileExists(atPath: binaryURL.path)
          binExists = exists
          diagnostics["\(prefix)bin_exists"] = binExists
          if exists {
            binReadable = fileManager.isReadableFile(atPath: binaryURL.path)
            binExecBit = fileManager.isExecutableFile(atPath: binaryURL.path)
            diagnostics["\(prefix)bin_readable"] = binReadable
            diagnostics["\(prefix)bin_exec_bit"] = binExecBit
            // Resolved if binary exists and is readable, regardless of exec bit (the tier-2 fix)
            if binReadable {
              isResolved = true
              resolvedVia = "framework_existence"
              break
            }
          } else {
            diagnostics["\(prefix)bin_readable"] = false
            diagnostics["\(prefix)bin_exec_bit"] = false
          }
        }
      }
    }
    if diagnostics["\(prefix)bin_exists"] == nil {
      diagnostics["\(prefix)bin_exists"] = binExists
      diagnostics["\(prefix)bin_readable"] = binReadable
      diagnostics["\(prefix)bin_exec_bit"] = binExecBit
    }
    return Resolution(isResolved: isResolved, resolvedVia: resolvedVia, diagnostics: diagnostics)
  }
}
