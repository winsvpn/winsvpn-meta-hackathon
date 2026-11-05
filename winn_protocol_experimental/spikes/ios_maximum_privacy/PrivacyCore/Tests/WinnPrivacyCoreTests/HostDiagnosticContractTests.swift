import Foundation
import XCTest

final class HostDiagnosticContractTests: XCTestCase {
  private var packageRoot: URL {
    URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
  }

  private var source: String {
    get throws {
      try String(
        contentsOf: packageRoot.appendingPathComponent(
          "Sources/WinnPrivacyHostDiagnostic/main.swift"
        ),
        encoding: .utf8
      )
    }
  }

  func testExecutableDependencyClosureIsCoreOnly() throws {
    let manifest = try String(
      contentsOf: packageRoot.appendingPathComponent("Package.swift"),
      encoding: .utf8
    )
    let expected = """
        .executableTarget(
          name: "WinnPrivacyHostDiagnostic",
          dependencies: ["WinnPrivacyStageACore"]
        ),
    """
    XCTAssertTrue(
      manifest.contains(expected),
      "the diagnostic executable must depend only on WinnPrivacyStageACore"
    )
    XCTAssertTrue(
      manifest.contains(
        """
            .target(
              name: "WinnPrivacyCore",
              dependencies: ["WinnPrivacyStageACore"]
            ),
        """
      ),
      "WinnPrivacyCore must preserve its Stage-A compatibility dependency"
    )
  }

  func testExecutableSourceHasNoActivationOrNetworkSurface() throws {
    let forbidden = [
      "import NetworkExtension",
      "import Network\n",
      "NEPacketTunnelProvider",
      "packetFlow",
      "startVPNTunnel",
      "WinnStageBProviderCore",
      "StageBProviderNative",
      "group.org.",
      "NEDNS",
      "NEIPv4Route",
      "NEIPv6Route",
      "socket(",
      "connect(",
      "sendto(",
      "recvfrom(",
      "import CryptoKit",
      "import WinnPrivacyCore",
    ]
    for token in forbidden {
      XCTAssertFalse(
        try source.contains(token),
        "diagnostic source contains forbidden token \(token)"
      )
    }
  }

  func testStageAModuleHasNoStageBOrFrameworkImports() throws {
    let stageARoot = packageRoot.appendingPathComponent(
      "Sources/WinnPrivacyStageACore"
    )
    let files = try FileManager.default.contentsOfDirectory(
      at: stageARoot,
      includingPropertiesForKeys: nil
    ).filter { $0.pathExtension == "swift" }
    XCTAssertEqual(files.count, 9, "Stage-A source closure changed")
    for file in files {
      let text = try String(contentsOf: file, encoding: .utf8)
      for token in [
        "StageB",
        "WinnStageB",
        "import CryptoKit",
        "import Network",
        "import NetworkExtension",
      ] {
        XCTAssertFalse(
          text.contains(token),
          "\(file.lastPathComponent) contains forbidden token \(token)"
        )
      }
    }
  }

  func testArgumentAllowlistIsExact() throws {
    let expression = try NSRegularExpression(
      pattern: #""--[a-z0-9-]+""#
    )
    let text = try source
    let range = NSRange(text.startIndex..., in: text)
    let arguments = Set<String>(
      expression.matches(in: text, range: range).compactMap {
        guard let swiftRange = Range($0.range, in: text) else {
          return nil
        }
        return String(text[swiftRange].dropFirst().dropLast())
      }
    )
    XCTAssertEqual(
      arguments,
      Set([
        "--mode",
        "--profile",
        "--rotation",
        "--duration-ms",
        "--source-sha256",
        "--binary-sha256",
        "--toolchain",
      ])
    )
  }

  func testSchemaAndNonPhysicalClaimsAreLiteralAndImmutable() throws {
    let text = try source
    XCTAssertTrue(
      text.contains(
        #"private let diagnosticSchema = "winn-ios-privacy-host-diagnostic/1""#
      )
    )
    for claim in [
      "physicalEvidenceEligible: false",
      "networkExtensionActivated: false",
      "stageBActivated: false",
      #"platform: "macos-host-proxy""#,
    ] {
      XCTAssertTrue(text.contains(claim), "missing literal \(claim)")
    }
  }

  func testRecordDeclaresTheRequiredMetricEnvelope() throws {
    let text = try source
    for member in [
      "schema",
      "physicalEvidenceEligible",
      "networkExtensionActivated",
      "stageBActivated",
      "platform",
      "hardwareModel",
      "toolchain",
      "sourceSHA256",
      "binarySHA256",
      "mode",
      "profile",
      "rotationCadence",
      "durationMilliseconds",
      "samples",
      "residentPeakBytes",
      "physicalFootprintPeakBytes",
      "userCPUDeltaNanoseconds",
      "systemCPUDeltaNanoseconds",
      "interruptWakeupDelta",
      "platformIdleWakeupDelta",
      "timerCallbacks",
      "maximumTimerLatenessNanoseconds",
      "allocatedPrivacyCellBytes",
      "inboundQueueDepth",
      "outboundQueueDepth",
      "coverPairsAccepted",
      "coverPairsEmitted",
      "rotationCount",
      "stopLatencyNanoseconds",
      "workChangedAfterStop",
      "worstThermalProxy",
      "terminalReason",
    ] {
      XCTAssertTrue(text.contains("let \(member):"), "missing \(member)")
    }
  }
}
