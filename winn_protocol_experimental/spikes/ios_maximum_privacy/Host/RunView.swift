import SwiftUI

struct RunView: View {
    @EnvironmentObject private var vpn: VPNController
    @State private var mode = ExperimentalSpikeMode.maximumPrivacy
    @State private var trafficProfile = ExperimentalTrafficProfile.low
    @State private var coverSemantics =
        ExperimentalCoverSemantics.continuous
    @State private var rotationCadence =
        ExperimentalRotationCadence.protocolFifteenMinutes
    @State private var testCondition =
        ExperimentalTestCondition.foregroundWiFi
    @State private var pairID = UUID().uuidString.lowercased()
    @State private var duration = ExperimentalDuration.oneMinute

    var body: some View {
        NavigationStack {
            Form {
                Section("Signing-gated physical spike") {
                    Text(vpn.status)
                    Text(vpn.startLatencySummary)
                    Picker("Mode", selection: $mode) {
                        ForEach(ExperimentalSpikeMode.allCases) {
                            Text($0.displayName).tag($0)
                        }
                    }
                    Picker("Traffic", selection: $trafficProfile) {
                        ForEach(ExperimentalTrafficProfile.allCases) {
                            Text($0.displayName).tag($0)
                        }
                    }
                    Picker("Duration", selection: $duration) {
                        ForEach(ExperimentalDuration.allCases) {
                            Text($0.displayName).tag($0)
                        }
                    }
                    Picker("Rotation", selection: $rotationCadence) {
                        ForEach(ExperimentalRotationCadence.allCases) {
                            Text($0.displayName).tag($0)
                        }
                    }
                    Picker("Cover", selection: $coverSemantics) {
                        ForEach(ExperimentalCoverSemantics.allCases) {
                            Text($0.displayName).tag($0)
                        }
                    }
                    Picker("Condition", selection: $testCondition) {
                        ForEach(ExperimentalTestCondition.allCases) {
                            Text($0.displayName).tag($0)
                        }
                    }
                    Text("Matched pair: \(pairID.prefix(8))")
                    Button("Start a new matched A/B pair") {
                        pairID = UUID().uuidString.lowercased()
                    }
                    Button("Configure selected experiment") {
                        Task {
                            await vpn.installExperimentalConfiguration(
                                configuration:
                                    ExperimentalSpikeConfiguration(
                                        mode: mode,
                                        trafficProfile: trafficProfile,
                                        coverSemantics: coverSemantics,
                                        rotationCadence: rotationCadence,
                                        testCondition: testCondition,
                                        pairID: pairID,
                                        duration: duration
                                    )
                            )
                        }
                    }
                    Button("Start selected experiment") {
                        let stageBConnectButtonT0 =
                            DispatchTime.now().uptimeNanoseconds
                        Task {
                            await vpn.start(
                                stageBConnectButtonT0:
                                    stageBConnectButtonT0
                            )
                        }
                    }
                    Button("Refresh run status") {
                        Task { await vpn.refreshRunStatus() }
                    }
                    Button("Stop") {
                        vpn.stop()
                    }
                    Button(
                        "Remove experimental VPN configuration",
                        role: .destructive
                    ) {
                        Task { await vpn.removeExperimentalConfiguration() }
                    }
                }
                Section("Safety") {
                    Text(
                        "This app uses only the experimental provider bundle "
                        + "and never removes another VPN configuration."
                    )
                    Text(
                        "Accelerated rotation is allocation-only. Use the "
                        + "15-minute cadence for protocol-realistic runs."
                    )
                    Text(
                        "The start-latency receipt measures Packet Tunnel "
                        + "activation only. It is not a usable VPN "
                        + "connection and not time-to-first-protected-"
                        + "packet."
                    )
                }
            }
            .navigationTitle("WCF3 Privacy Spike")
        }
    }
}
