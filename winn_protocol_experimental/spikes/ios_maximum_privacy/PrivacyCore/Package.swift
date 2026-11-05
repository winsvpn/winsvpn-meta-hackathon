// swift-tools-version: 5.9

import PackageDescription

let package = Package(
  name: "WinnPrivacyCore",
  platforms: [
    .iOS(.v17),
    .macOS(.v13),
  ],
  products: [
    .library(name: "WinnPrivacyCore", targets: ["WinnPrivacyCore"]),
    .library(
      name: "WinnPrivacyStageACore",
      targets: ["WinnPrivacyStageACore"]
    ),
    .executable(
      name: "WinnPrivacyHostDiagnostic",
      targets: ["WinnPrivacyHostDiagnostic"]
    ),
    .library(
      name: "WinnStageBProviderCore",
      targets: ["WinnStageBProviderCore"]
    ),
  ],
  targets: [
    .target(name: "WinnPrivacyStageACore"),
    .target(
      name: "WinnPrivacyCore",
      dependencies: ["WinnPrivacyStageACore"]
    ),
    .executableTarget(
      name: "WinnPrivacyHostDiagnostic",
      dependencies: ["WinnPrivacyStageACore"]
    ),
    .target(
      name: "WinnStageBProviderCore",
      dependencies: ["WinnPrivacyCore"]
    ),
    .testTarget(
      name: "WinnPrivacyCoreTests",
      dependencies: [
        "WinnPrivacyCore",
        "WinnPrivacyStageACore",
      ]
    ),
    .testTarget(
      name: "WinnStageBProviderCoreTests",
      dependencies: [
        "WinnPrivacyCore",
        "WinnStageBProviderCore",
      ]
    ),
  ],
  swiftLanguageVersions: [.v5]
)
