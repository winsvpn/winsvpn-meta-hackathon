import CryptoKit
import Darwin
import Foundation
import NetworkExtension
import WinnPrivacyCore

private enum StageAProviderError: Error {
    case invalidConfiguration
    case missingAppGroup
    case invalidSourceDigest
    case missingExecutable
    case artifactDigestFailed
    case alreadyRunning
    case invalidLifecycle
    case criticalThermalState
    case reversedStartClock
}

private struct StageAProviderConfiguration {
    static let allowedDurations: Set<UInt64> = [
        60,
        300,
        1_800,
        28_800,
    ]

    let harness: StageAConfiguration

    init(dictionary: [String: Any]?) throws {
        guard let dictionary,
              dictionary["schema"] as? String ==
                WCF3Constants.schemaVersion,
              let modeValue = dictionary["mode"] as? String,
              let mode = SpikeMode(rawValue: modeValue),
              let profileValue =
                dictionary["traffic_profile"] as? String,
              let profile =
                SyntheticTrafficProfile(rawValue: profileValue),
              let coverValue =
                dictionary["cover_semantics"] as? String,
              let cover =
                CoverTrafficSemantics(rawValue: coverValue),
              let rotationValue =
                dictionary["rotation_cadence"] as? String,
              let rotation =
                StageARotationCadence(rawValue: rotationValue),
              let conditionValue =
                dictionary["test_condition"] as? String,
              let condition =
                StageATestCondition(rawValue: conditionValue),
              let pairID = dictionary["pair_id"] as? String,
              let durationNumber =
                dictionary["duration_seconds"] as? NSNumber
        else {
            throw StageAProviderError.invalidConfiguration
        }
        let durationSeconds = durationNumber.uint64Value
        guard Self.allowedDurations.contains(durationSeconds),
              durationNumber.doubleValue == Double(durationSeconds)
        else {
            throw StageAProviderError.invalidConfiguration
        }
        harness = try StageAConfiguration(
            mode: mode,
            trafficProfile: profile,
            coverSemantics: cover,
            rotationCadence: rotation,
            testCondition: condition,
            pairID: pairID,
            durationNanoseconds:
                durationSeconds.multipliedClamped(by: 1_000_000_000)
        )
    }
}

private struct StageAStatus: Codable {
    let schema: String
    let running: Bool
    let completed: Bool
    let runID: String?
    let evidenceRelativePath: String?
    let elapsedNanoseconds: UInt64
    let mode: String?
    let trafficProfile: String?
    let coverSemantics: String?
    let rotationCadence: String?
    let dataPath: SpikeDataPathSnapshot?
    let failureCode: String?
}

private struct StageAProviderCommand: Codable {
    let command: String
    let requestedAtMonotonicNanoseconds: UInt64
    let attemptNonce: String?
}

private struct StageAStopAcknowledgement: Codable {
    let schema: String
    let requestedAtMonotonicNanoseconds: UInt64
    let receivedAtMonotonicNanoseconds: UInt64
    let acknowledgedAtMonotonicNanoseconds: UInt64
    let status: StageAStatus
}

private final class StageAEvidenceSession {
    static let appGroup =
        "group.org.winsvpn.experimental.wcf3privacyspike"

    let runID: String
    let relativePath: String
    let writer: JSONLEvidenceWriter
    let sourceDigest: String
    let artifactDigest: String
    let osVersion: String
    let hardwareModel: String

    init(providerBundle: Bundle) throws {
        runID = UUID().uuidString.lowercased()
        guard let sourceDigest =
                providerBundle.object(
                    forInfoDictionaryKey: "WinnSpikeSourceDigest"
                ) as? String,
              Self.validDigest(sourceDigest),
              sourceDigest != String(repeating: "0", count: 64)
        else {
            throw StageAProviderError.invalidSourceDigest
        }
        self.sourceDigest = sourceDigest
        osVersion =
            ProcessInfo.processInfo.operatingSystemVersionString
        hardwareModel = Self.hardwareModel()
        guard let executable = providerBundle.executableURL else {
            throw StageAProviderError.missingExecutable
        }
        artifactDigest = try Self.sha256(fileURL: executable)
        guard let root = FileManager.default
            .containerURL(
                forSecurityApplicationGroupIdentifier: Self.appGroup
            )
        else {
            throw StageAProviderError.missingAppGroup
        }
        relativePath = "Evidence/runtime/\(runID)/stage-a.jsonl"
        writer = try JSONLEvidenceWriter(
            fileURL: root.appendingPathComponent(
                relativePath,
                isDirectory: false
            )
        )
    }

    func append(
        event: String,
        nowNanoseconds: UInt64,
        configuration: StageAConfiguration,
        resources: SpikeResourceSnapshot? = nil,
        resourceWindow: SpikeResourceWindowSnapshot? = nil,
        wholeRunResourceWindow: SpikeResourceWindowSnapshot? = nil,
        dataPath: SpikeDataPathSnapshot? = nil,
        rotationResources: RotationResourceSnapshot? = nil,
        controlLatencyNanoseconds: UInt64? = nil,
        failureCode: String? = nil,
        synchronize: Bool = false
    ) throws {
        try writer.append(
            try makeRecord(
                event: event,
                nowNanoseconds: nowNanoseconds,
                configuration: configuration,
                resources: resources,
                resourceWindow: resourceWindow,
                wholeRunResourceWindow: wholeRunResourceWindow,
                dataPath: dataPath,
                rotationResources: rotationResources,
                controlLatencyNanoseconds: controlLatencyNanoseconds,
                failureCode: failureCode
            ),
            synchronize: synchronize
        )
    }

    /// Durably appends the run's first `started` record, hashes its exact
    /// bytes including the trailing line feed, and only then captures
    /// `providerReady`. A synchronize failure propagates out of here and
    /// fails provider startup; it is never swallowed.
    func recordFirstStartedRecord(
        nowNanoseconds: UInt64,
        configuration: StageAConfiguration,
        resources: SpikeResourceSnapshot,
        dataPath: SpikeDataPathSnapshot,
        attemptNonce: String,
        requestedAtMonotonicNanoseconds: UInt64,
        providerReceivedAtMonotonicNanoseconds: UInt64
    ) throws -> ProviderStartAttestation {
        try ProviderStartAttestationRecorder.recordFirstStartedRecord(
            writer: writer,
            record: try makeRecord(
                event: "started",
                nowNanoseconds: nowNanoseconds,
                configuration: configuration,
                resources: resources,
                dataPath: dataPath,
                startAttemptNonce: attemptNonce,
                startRequestedAtMonotonicNanoseconds:
                    requestedAtMonotonicNanoseconds,
                providerReceivedAtMonotonicNanoseconds:
                    providerReceivedAtMonotonicNanoseconds
            ),
            attemptNonce: attemptNonce,
            requestedAtMonotonicNanoseconds:
                requestedAtMonotonicNanoseconds,
            providerReceivedAtMonotonicNanoseconds:
                providerReceivedAtMonotonicNanoseconds,
            providerReadyClock: {
                DispatchTime.now().uptimeNanoseconds
            }
        )
    }

    private func makeRecord(
        event: String,
        nowNanoseconds: UInt64,
        configuration: StageAConfiguration,
        resources: SpikeResourceSnapshot? = nil,
        resourceWindow: SpikeResourceWindowSnapshot? = nil,
        wholeRunResourceWindow: SpikeResourceWindowSnapshot? = nil,
        dataPath: SpikeDataPathSnapshot? = nil,
        rotationResources: RotationResourceSnapshot? = nil,
        controlLatencyNanoseconds: UInt64? = nil,
        startAttemptNonce: String? = nil,
        startRequestedAtMonotonicNanoseconds: UInt64? = nil,
        providerReceivedAtMonotonicNanoseconds: UInt64? = nil,
        failureCode: String? = nil
    ) throws -> SpikeMetricRecord {
        try SpikeMetricRecord(
            runID: runID,
            event: event,
            monotonicNanoseconds: nowNanoseconds,
            wallTimeUTC: Self.wallClock.string(from: Date()),
            platform: "ios",
            osVersion: osVersion,
            hardwareModel: hardwareModel,
            mode: configuration.mode,
            trafficProfile: configuration.trafficProfile,
            coverSemantics: configuration.coverSemantics,
            rotationCadence: configuration.rotationCadence,
            testCondition: configuration.testCondition,
            pairID: configuration.pairID,
            durationNanoseconds: configuration.durationNanoseconds,
            trafficActiveNanoseconds:
                configuration.trafficActiveNanoseconds,
            sourceDigest: sourceDigest,
            artifactDigest: artifactDigest,
            resources: resources,
            resourceWindow: resourceWindow,
            wholeRunResourceWindow: wholeRunResourceWindow,
            dataPath: dataPath,
            rotationResources: rotationResources,
            controlLatencyNanoseconds: controlLatencyNanoseconds,
            startAttemptNonce: startAttemptNonce,
            startRequestedAtMonotonicNanoseconds:
                startRequestedAtMonotonicNanoseconds,
            providerReceivedAtMonotonicNanoseconds:
                providerReceivedAtMonotonicNanoseconds,
            failureCode: failureCode
        )
    }

    private static let wallClock: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [
            .withInternetDateTime,
            .withFractionalSeconds,
        ]
        return formatter
    }()

    private static func validDigest(_ value: String) -> Bool {
        value.count == 64 && value.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
    }

    private static func sha256(fileURL: URL) throws -> String {
        guard let stream = InputStream(url: fileURL) else {
            throw StageAProviderError.artifactDigestFailed
        }
        stream.open()
        defer { stream.close() }
        var hash = SHA256()
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        while stream.hasBytesAvailable {
            let read = stream.read(
                &buffer,
                maxLength: buffer.count
            )
            guard read >= 0 else {
                throw StageAProviderError.artifactDigestFailed
            }
            if read == 0 { break }
            hash.update(data: Data(buffer[0 ..< read]))
        }
        return hash.finalize().map {
            String(format: "%02x", $0)
        }.joined()
    }

    private static func hardwareModel() -> String {
        var size = 0
        guard sysctlbyname("hw.machine", nil, &size, nil, 0) == 0,
              size > 1
        else {
            return "unknown"
        }
        var value = [CChar](repeating: 0, count: size)
        guard sysctlbyname(
            "hw.machine",
            &value,
            &size,
            nil,
            0
        ) == 0 else {
            return "unknown"
        }
        return String(cString: value)
    }
}

private enum StageAResourceSampler {
    static func sample() -> SpikeResourceSnapshot {
        let vm = taskVMInfo()
        let powerV2 = taskPowerInfoV2()
        let power = powerV2?.cpu_energy ?? taskPowerInfo()
        return SpikeResourceSnapshot(
            residentBytes: vm?.resident_size,
            physicalFootprintBytes: vm?.phys_footprint,
            availableProcessBytes:
                UInt64(os_proc_available_memory()),
            userCPUNanoseconds:
                machTicksToNanoseconds(power?.total_user),
            systemCPUNanoseconds:
                machTicksToNanoseconds(power?.total_system),
            interruptWakeups: power?.task_interrupt_wakeups,
            packageIdleWakeups:
                power?.task_platform_idle_wakeups,
            energyNanojoules: powerV2?.task_energy,
            thermalState:
                ProcessInfo.processInfo.thermalState.evidenceName,
            lowPowerMode:
                ProcessInfo.processInfo.isLowPowerModeEnabled
        )
    }

    private static func taskVMInfo() -> task_vm_info_data_t? {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<task_vm_info_data_t>.size /
                MemoryLayout<natural_t>.size
        )
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(
                to: integer_t.self,
                capacity: Int(count)
            ) {
                task_info(
                    mach_task_self_,
                    task_flavor_t(TASK_VM_INFO),
                    $0,
                    &count
                )
            }
        }
        return result == KERN_SUCCESS ? info : nil
    }

    private static func taskPowerInfo() -> task_power_info_data_t? {
        var info = task_power_info_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<task_power_info_data_t>.size /
                MemoryLayout<natural_t>.size
        )
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(
                to: integer_t.self,
                capacity: Int(count)
            ) {
                task_info(
                    mach_task_self_,
                    task_flavor_t(TASK_POWER_INFO),
                    $0,
                    &count
                )
            }
        }
        return result == KERN_SUCCESS ? info : nil
    }

    private static func taskPowerInfoV2()
        -> task_power_info_v2_data_t?
    {
        var info = task_power_info_v2_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<task_power_info_v2_data_t>.size /
                MemoryLayout<natural_t>.size
        )
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(
                to: integer_t.self,
                capacity: Int(count)
            ) {
                task_info(
                    mach_task_self_,
                    task_flavor_t(TASK_POWER_INFO_V2),
                    $0,
                    &count
                )
            }
        }
        return result == KERN_SUCCESS ? info : nil
    }

    private static func machTicksToNanoseconds(
        _ ticks: UInt64?
    ) -> UInt64? {
        guard let ticks else { return nil }
        var timebase = mach_timebase_info_data_t()
        guard mach_timebase_info(&timebase) == KERN_SUCCESS,
              timebase.denom != 0
        else {
            return nil
        }
        let (scaled, overflow) = ticks.multipliedReportingOverflow(
            by: UInt64(timebase.numer)
        )
        guard !overflow else { return nil }
        return scaled / UInt64(timebase.denom)
    }
}

/// An isolated Stage A resource harness. It installs only the RFC 2544
/// benchmark route, never reads `packetFlow`, opens no socket, and forwards no
/// user packet. All inbound/outbound cells are explicitly synthetic.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let workQueue = DispatchQueue(
        label: "org.winsvpn.experimental.wcf3privacyspike.stage-a",
        qos: .userInitiated
    )
    private lazy var stageBNativeLifecycle =
        StageBProviderNativeLifecycle(providerQueue: workQueue)
    private var timer: DispatchSourceTimer?
    private var harness: StageAHarness?
    private var configuration: StageAConfiguration?
    private var evidence: StageAEvidenceSession?
    private var resourceWindow = SpikeResourceWindowAccumulator()
    private var wholeRunResourceWindow =
        SpikeResourceWindowAccumulator()
    private var lastResourceSample: SpikeResourceSnapshot?
    private var lastResourceSampleNanoseconds: UInt64?
    private var nextSampleNanoseconds: UInt64?
    private var nextWindowNanoseconds: UInt64?
    private var lastStatus: StageAStatus = StageAStatus(
        schema: WCF3Constants.schemaVersion,
        running: false,
        completed: false,
        runID: nil,
        evidenceRelativePath: nil,
        elapsedNanoseconds: 0,
        mode: nil,
        trafficProfile: nil,
        coverSemantics: nil,
        rotationCadence: nil,
        dataPath: nil,
        failureCode: nil
    )
    private var failureLatched = false
    private var terminalRecordWritten = false
    private var startAttestation: ProviderStartAttestation?
    private var cachedStopAcknowledgement:
        StageAStopAcknowledgement?
    private var rotationResourceSamples: UInt64 = 0
    private var lastRotationResourceCount: UInt64 = 0
    private var firstTenPeakResidentBytes: UInt64?
    private var firstTenPeakPhysicalFootprintBytes: UInt64?
    private var postTenPeakResidentBytes: UInt64?
    private var postTenPeakPhysicalFootprintBytes: UInt64?

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let providerReceived = DispatchTime.now().uptimeNanoseconds
        // Nothing may precede that line: it is the provider's own receipt of
        // the host's start request and every later interval is measured from
        // it.
        workQueue.async {
            do {
                guard self.timer == nil else {
                    throw StageAProviderError.alreadyRunning
                }
                let start = try StageBProviderStartOptions.parse(
                    entries: (options ?? [:]).map {
                        (key: $0.key, value: $0.value as Any)
                    },
                    providerReceivedAtMonotonicNanoseconds:
                        providerReceived
                )
                let protocolConfiguration =
                    self.protocolConfiguration
                        as? NETunnelProviderProtocol
                let parsed = try StageAProviderConfiguration(
                    dictionary:
                        protocolConfiguration?.providerConfiguration
                )
                let initialResourceNanoseconds =
                    DispatchTime.now().uptimeNanoseconds
                let initialResource =
                    StageAResourceSampler.sample()
                let harness = try StageAHarness(
                    configuration: parsed.harness
                )
                let settings = Self.networkSettings()
                self.setTunnelNetworkSettings(settings) { error in
                    self.workQueue.async {
                        guard error == nil else {
                            completionHandler(error)
                            return
                        }
                        do {
                            // Evidence is created only after iOS accepted the
                            // tunnel settings, so a settings failure cannot
                            // leave an empty run directory/file behind.
                            let evidence = try StageAEvidenceSession(
                                providerBundle: .main
                            )
                            try self.begin(
                                harness: harness,
                                configuration: parsed.harness,
                                evidence: evidence,
                                initialResource: initialResource,
                                initialResourceNanoseconds:
                                    initialResourceNanoseconds,
                                attemptNonce: start.attemptNonce,
                                requestedAtMonotonicNanoseconds:
                                    start
                                    .requestedAtMonotonicNanoseconds,
                                providerReceivedAtMonotonicNanoseconds:
                                    providerReceived
                            )
                            completionHandler(nil)
                        } catch {
                            self.resetAfterFailedStart()
                            completionHandler(error)
                        }
                    }
                }
            } catch {
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        workQueue.async {
            let stopStarted = DispatchTime.now().uptimeNanoseconds
            self.timer?.cancel()
            self.timer = nil
            if self.lastStatus.running,
               !self.terminalRecordWritten,
               let harness = self.harness,
               let configuration = self.configuration,
               let evidence = self.evidence {
                do {
                    _ = try harness.step(
                        nowNanoseconds: stopStarted
                    )
                } catch {
                    self.fail(
                        error,
                        code: "stop-finalization-failure",
                        nowNanoseconds: stopStarted,
                        cancelTunnel: false
                    )
                    self.harness = nil
                    self.configuration = nil
                    self.evidence = nil
                    self.startAttestation = nil
                    self.finishProviderStop(completionHandler)
                    return
                }
                let snapshot = harness.stop(
                    nowNanoseconds: stopStarted
                )
                let resource = self.captureFinalResource(
                    nowNanoseconds: stopStarted
                )
                let window = self.resourceWindow.finish()
                let wholeRunWindow =
                    self.wholeRunResourceWindow.finish()
                do {
                    try evidence.append(
                        event: "stopped",
                        nowNanoseconds: stopStarted,
                        configuration: configuration,
                        resources: resource,
                        resourceWindow: window,
                        wholeRunResourceWindow: wholeRunWindow,
                        dataPath: snapshot.dataPath,
                        rotationResources:
                            self.rotationResourceSnapshot(),
                        synchronize: true
                    )
                    self.terminalRecordWritten = true
                } catch {
                    self.failureLatched = true
                }
                self.updateStatus(
                    snapshot: snapshot,
                    running: false,
                    failureCode: self.lastStatus.failureCode
                )
            }
            self.harness = nil
            self.configuration = nil
            self.evidence = nil
            self.startAttestation = nil
            self.finishProviderStop(completionHandler)
        }
    }

    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        workQueue.async {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let command = try? JSONDecoder().decode(
                StageAProviderCommand.self,
                from: messageData
            )
            switch command?.command {
            case "stop-and-ack":
                guard let command,
                      let acknowledgement = try?
                      self.stopAndAcknowledge(command)
                else {
                    completionHandler?(nil)
                    return
                }
                completionHandler?(
                    try? encoder.encode(acknowledgement)
                )
                return
            case "start-attestation":
                // Answered only for the exact attempt the host is asking
                // about, so a stale reply cannot be bound to a later attempt.
                guard let command,
                      let attestation = self.startAttestation,
                      command.attemptNonce == attestation.attemptNonce,
                      command.requestedAtMonotonicNanoseconds ==
                      attestation.requestedAtMonotonicNanoseconds
                else {
                    completionHandler?(nil)
                    return
                }
                completionHandler?(try? encoder.encode(attestation))
                return
            default:
                break
            }
            completionHandler?(try? encoder.encode(self.lastStatus))
        }
    }

    private func stopAndAcknowledge(
        _ command: StageAProviderCommand
    ) throws -> StageAStopAcknowledgement {
        if let cachedStopAcknowledgement {
            return cachedStopAcknowledgement
        }
        guard lastStatus.running,
              !terminalRecordWritten,
              !failureLatched,
              let harness,
              let configuration,
              let evidence
        else {
            throw StageAProviderError.invalidLifecycle
        }
        let received = DispatchTime.now().uptimeNanoseconds
        timer?.cancel()
        timer = nil
        _ = try harness.step(nowNanoseconds: received)
        let snapshot = harness.stop(nowNanoseconds: received)
        let resource = captureFinalResource(
            nowNanoseconds: received
        )
        let window = resourceWindow.finish()
        let wholeRunWindow = wholeRunResourceWindow.finish()
        let recordTime = DispatchTime.now().uptimeNanoseconds
        let latency = recordTime >=
            command.requestedAtMonotonicNanoseconds
            ? recordTime -
                command.requestedAtMonotonicNanoseconds
            : nil
        try evidence.append(
            event: "stop-acknowledged",
            nowNanoseconds: recordTime,
            configuration: configuration,
            resources: resource,
            resourceWindow: window,
            wholeRunResourceWindow: wholeRunWindow,
            dataPath: snapshot.dataPath,
            rotationResources: rotationResourceSnapshot(),
            controlLatencyNanoseconds: latency,
            synchronize: true
        )
        terminalRecordWritten = true
        updateStatus(snapshot: snapshot, running: false)
        let acknowledgement = StageAStopAcknowledgement(
            schema: WCF3Constants.schemaVersion,
            requestedAtMonotonicNanoseconds:
                command.requestedAtMonotonicNanoseconds,
            receivedAtMonotonicNanoseconds: received,
            acknowledgedAtMonotonicNanoseconds:
                DispatchTime.now().uptimeNanoseconds,
            status: lastStatus
        )
        cachedStopAcknowledgement = acknowledgement
        return acknowledgement
    }

    private func begin(
        harness: StageAHarness,
        configuration: StageAConfiguration,
        evidence: StageAEvidenceSession,
        initialResource: SpikeResourceSnapshot,
        initialResourceNanoseconds: UInt64,
        attemptNonce: String,
        requestedAtMonotonicNanoseconds: UInt64,
        providerReceivedAtMonotonicNanoseconds: UInt64
    ) throws {
        let now = DispatchTime.now().uptimeNanoseconds
        harness.start(nowNanoseconds: now)
        self.harness = harness
        self.configuration = configuration
        self.evidence = evidence
        resourceWindow = SpikeResourceWindowAccumulator()
        wholeRunResourceWindow =
            SpikeResourceWindowAccumulator()
        wholeRunResourceWindow.add(
            initialResource,
            monotonicNanoseconds: initialResourceNanoseconds
        )
        lastResourceSample = initialResource
        lastResourceSampleNanoseconds =
            initialResourceNanoseconds
        nextSampleNanoseconds = now.addingClamped(1_000_000_000)
        nextWindowNanoseconds = now.addingClamped(30_000_000_000)
        failureLatched = false
        terminalRecordWritten = false
        startAttestation = nil
        cachedStopAcknowledgement = nil
        rotationResourceSamples = 0
        lastRotationResourceCount = 0
        firstTenPeakResidentBytes = nil
        firstTenPeakPhysicalFootprintBytes = nil
        postTenPeakResidentBytes = nil
        postTenPeakPhysicalFootprintBytes = nil
        let snapshot = harness.snapshot(nowNanoseconds: now)
        // Durable append and fsync of the first record, then the digest of its
        // exact bytes including the trailing line feed, then `providerReady`.
        // Any failure here throws, and `startTunnel` reports it through
        // `completionHandler(error)` rather than starting anyway.
        startAttestation = try evidence.recordFirstStartedRecord(
            nowNanoseconds: now,
            configuration: configuration,
            resources: initialResource,
            dataPath: snapshot.dataPath,
            attemptNonce: attemptNonce,
            requestedAtMonotonicNanoseconds:
                requestedAtMonotonicNanoseconds,
            providerReceivedAtMonotonicNanoseconds:
                providerReceivedAtMonotonicNanoseconds
        )
        updateStatus(snapshot: snapshot, running: true)

        let timer = DispatchSource.makeTimerSource(queue: workQueue)
        timer.schedule(
            deadline: .now(),
            leeway: .milliseconds(2)
        )
        timer.setEventHandler { [weak self] in self?.tick() }
        self.timer = timer
        timer.resume()
    }

    /// Clears every provider reference installed before the durable first
    /// record was obtained. The evidence writer may retain an empty, refused
    /// file after a durability failure, but no provider state, attestation, or
    /// running status survives and a later attempt cannot observe it as a
    /// successful start.
    private func resetAfterFailedStart() {
        stageBNativeLifecycle.abandonCurrentStart()
        timer?.cancel()
        timer = nil
        harness = nil
        configuration = nil
        evidence = nil
        startAttestation = nil
        cachedStopAcknowledgement = nil
        resourceWindow = SpikeResourceWindowAccumulator()
        wholeRunResourceWindow = SpikeResourceWindowAccumulator()
        lastResourceSample = nil
        lastResourceSampleNanoseconds = nil
        nextSampleNanoseconds = nil
        nextWindowNanoseconds = nil
        lastStatus = StageAStatus(
            schema: WCF3Constants.schemaVersion,
            running: false,
            completed: false,
            runID: nil,
            evidenceRelativePath: nil,
            elapsedNanoseconds: 0,
            mode: nil,
            trafficProfile: nil,
            coverSemantics: nil,
            rotationCadence: nil,
            dataPath: nil,
            failureCode: "start-failed"
        )
    }

    /// Stage A remains the installed physical harness.  This hook gives a
    /// future Stage B start one explicit provider-owned cleanup boundary
    /// without claiming that Stage B is activated today.  Native stop runs on
    /// the bridge's control queue; the Network Extension completion returns
    /// only after that exact-handle attempt has converged or been retained
    /// fail-closed by the bridge.
    private func finishProviderStop(
        _ completionHandler: @escaping () -> Void
    ) {
        stageBNativeLifecycle.stop(completion: completionHandler)
    }

    private func tick() {
        guard !failureLatched,
              !terminalRecordWritten,
              let harness,
              let configuration,
              let evidence
        else {
            return
        }
        let now = DispatchTime.now().uptimeNanoseconds
        do {
            let snapshot = try harness.step(nowNanoseconds: now)
            sampleRotationResourcesIfNeeded(
                snapshot: snapshot,
                configuration: configuration
            )
            sampleIfDue(
                nowNanoseconds: now,
                snapshot: snapshot,
                configuration: configuration,
                evidence: evidence
            )
            guard !failureLatched, !terminalRecordWritten else {
                return
            }
            updateStatus(snapshot: snapshot, running: !snapshot.completed)
            if snapshot.completed {
                timer?.cancel()
                timer = nil
                let resource = captureFinalResource(
                    nowNanoseconds: now
                )
                let window = resourceWindow.finish()
                let wholeRunWindow =
                    wholeRunResourceWindow.finish()
                try evidence.append(
                    event: "completed",
                    nowNanoseconds: now,
                    configuration: configuration,
                    resources: resource,
                    resourceWindow: window,
                    wholeRunResourceWindow: wholeRunWindow,
                    dataPath: snapshot.dataPath,
                    rotationResources:
                        rotationResourceSnapshot(),
                    synchronize: true
                )
                terminalRecordWritten = true
            } else {
                let delay = harness
                    .recommendedNextStepDelayNanoseconds(
                        nowNanoseconds: now
                    )
                timer?.schedule(
                    deadline: .now() + .nanoseconds(Int(delay)),
                    leeway: .milliseconds(2)
                )
            }
        } catch {
            fail(
                error,
                code: "stage-a-runtime-failure",
                nowNanoseconds: now
            )
        }
    }

    private func sampleIfDue(
        nowNanoseconds: UInt64,
        snapshot: StageAHarnessSnapshot,
        configuration: StageAConfiguration,
        evidence: StageAEvidenceSession
    ) {
        guard let nextSampleNanoseconds,
              nowNanoseconds >= nextSampleNanoseconds
        else {
            return
        }
        let scheduled = 1 &+
            (nowNanoseconds - nextSampleNanoseconds) /
                1_000_000_000
        let resource = StageAResourceSampler.sample()
        lastResourceSample = resource
        lastResourceSampleNanoseconds = nowNanoseconds
        resourceWindow.add(
            resource,
            monotonicNanoseconds: nowNanoseconds,
            scheduledSamples: scheduled
        )
        wholeRunResourceWindow.add(
            resource,
            monotonicNanoseconds: nowNanoseconds,
            scheduledSamples: scheduled
        )
        self.nextSampleNanoseconds =
            nowNanoseconds.addingClamped(1_000_000_000)

        if ProcessInfo.processInfo.thermalState == .critical {
            fail(
                StageAProviderError.criticalThermalState,
                code: "critical-thermal-state",
                nowNanoseconds: nowNanoseconds
            )
            return
        }
        guard let nextWindowNanoseconds,
              nowNanoseconds >= nextWindowNanoseconds
        else {
            return
        }
        let window = resourceWindow.finish()
        do {
            try evidence.append(
                event: "sample-window",
                nowNanoseconds: nowNanoseconds,
                configuration: configuration,
                resources: resource,
                resourceWindow: window,
                dataPath: snapshot.dataPath,
                rotationResources: rotationResourceSnapshot(),
                synchronize: true
            )
            self.nextWindowNanoseconds =
                nowNanoseconds.addingClamped(30_000_000_000)
        } catch {
            fail(
                error,
                code: "evidence-write-failure",
                nowNanoseconds: nowNanoseconds
            )
        }
    }

    private func fail(
        _ error: Error,
        code: String,
        nowNanoseconds: UInt64,
        cancelTunnel: Bool = true
    ) {
        guard !failureLatched, !terminalRecordWritten else { return }
        failureLatched = true
        timer?.cancel()
        timer = nil
        var snapshot: StageAHarnessSnapshot?
        if let harness {
            snapshot = harness.stop(nowNanoseconds: nowNanoseconds)
        }
        if let configuration, let evidence {
            let resource = captureFinalResource(
                nowNanoseconds: nowNanoseconds
            )
            let window = resourceWindow.finish()
            let wholeRunWindow = wholeRunResourceWindow.finish()
            do {
                try evidence.append(
                    event: "failed",
                    nowNanoseconds: nowNanoseconds,
                    configuration: configuration,
                    resources: resource,
                    resourceWindow: window,
                    wholeRunResourceWindow: wholeRunWindow,
                    dataPath: snapshot?.dataPath,
                    rotationResources: rotationResourceSnapshot(),
                    failureCode: code,
                    synchronize: true
                )
                terminalRecordWritten = true
            } catch {
                // The failed write itself is the retained failure condition.
            }
        }
        if let snapshot {
            updateStatus(
                snapshot: snapshot,
                running: false,
                failureCode: code
            )
        }
        if cancelTunnel {
            cancelTunnelWithError(error)
        }
    }

    private func captureFinalResource(
        nowNanoseconds: UInt64
    ) -> SpikeResourceSnapshot {
        if lastResourceSampleNanoseconds == nowNanoseconds,
           let lastResourceSample {
            return lastResourceSample
        }
        let resource = StageAResourceSampler.sample()
        lastResourceSample = resource
        lastResourceSampleNanoseconds = nowNanoseconds
        resourceWindow.add(
            resource,
            monotonicNanoseconds: nowNanoseconds
        )
        wholeRunResourceWindow.add(
            resource,
            monotonicNanoseconds: nowNanoseconds
        )
        return resource
    }

    private func updateStatus(
        snapshot: StageAHarnessSnapshot,
        running: Bool,
        failureCode: String? = nil
    ) {
        lastStatus = StageAStatus(
            schema: WCF3Constants.schemaVersion,
            running: running,
            completed: snapshot.completed && failureCode == nil,
            runID: evidence?.runID,
            evidenceRelativePath: evidence?.relativePath,
            elapsedNanoseconds: snapshot.elapsedNanoseconds,
            mode: configuration?.mode.rawValue,
            trafficProfile:
                configuration?.trafficProfile.rawValue,
            coverSemantics:
                configuration?.coverSemantics.rawValue,
            rotationCadence:
                configuration?.rotationCadence.rawValue,
            dataPath: snapshot.dataPath,
            failureCode: failureCode
        )
    }

    private func sampleRotationResourcesIfNeeded(
        snapshot: StageAHarnessSnapshot,
        configuration: StageAConfiguration
    ) {
        guard configuration.rotationCadence ==
                .acceleratedAllocation,
              snapshot.dataPath.rotationCount >
                lastRotationResourceCount
        else {
            return
        }
        let resource = StageAResourceSampler.sample()
        let rotation = snapshot.dataPath.rotationCount
        rotationResourceSamples &+= 1
        lastRotationResourceCount = rotation
        if rotation <= 10 {
            firstTenPeakResidentBytes = maximum(
                firstTenPeakResidentBytes,
                resource.residentBytes
            )
            firstTenPeakPhysicalFootprintBytes = maximum(
                firstTenPeakPhysicalFootprintBytes,
                resource.physicalFootprintBytes
            )
        } else {
            postTenPeakResidentBytes = maximum(
                postTenPeakResidentBytes,
                resource.residentBytes
            )
            postTenPeakPhysicalFootprintBytes = maximum(
                postTenPeakPhysicalFootprintBytes,
                resource.physicalFootprintBytes
            )
        }
    }

    private func rotationResourceSnapshot()
        -> RotationResourceSnapshot?
    {
        guard rotationResourceSamples > 0 else { return nil }
        return RotationResourceSnapshot(
            samples: rotationResourceSamples,
            lastRotationCount: lastRotationResourceCount,
            firstTenPeakResidentBytes:
                firstTenPeakResidentBytes,
            firstTenPeakPhysicalFootprintBytes:
                firstTenPeakPhysicalFootprintBytes,
            postTenPeakResidentBytes:
                postTenPeakResidentBytes,
            postTenPeakPhysicalFootprintBytes:
                postTenPeakPhysicalFootprintBytes
        )
    }

    private func maximum(
        _ first: UInt64?,
        _ second: UInt64?
    ) -> UInt64? {
        switch (first, second) {
        case let (.some(a), .some(b)): return max(a, b)
        case let (.some(a), .none): return a
        case let (.none, .some(b)): return b
        case (.none, .none): return nil
        }
    }

    private static func networkSettings()
        -> NEPacketTunnelNetworkSettings
    {
        let settings = NEPacketTunnelNetworkSettings(
            tunnelRemoteAddress: "198.18.0.1"
        )
        let ipv4 = NEIPv4Settings(
            addresses: ["198.18.0.2"],
            subnetMasks: ["255.255.255.255"]
        )
        ipv4.includedRoutes = [
            NEIPv4Route(
                destinationAddress: "198.18.0.0",
                subnetMask: "255.254.0.0"
            ),
        ]
        ipv4.excludedRoutes = []
        settings.ipv4Settings = ipv4
        settings.dnsSettings = nil
        settings.mtu = 1_280
        return settings
    }
}

private extension ProcessInfo.ThermalState {
    var evidenceName: String {
        switch self {
        case .nominal: return "nominal"
        case .fair: return "fair"
        case .serious: return "serious"
        case .critical: return "critical"
        @unknown default: return "unknown"
        }
    }
}

private extension UInt64 {
    func addingClamped(_ other: UInt64) -> UInt64 {
        let (value, overflow) = addingReportingOverflow(other)
        return overflow ? UInt64.max : value
    }

    func multipliedClamped(by other: UInt64) -> UInt64 {
        let (value, overflow) = multipliedReportingOverflow(by: other)
        return overflow ? UInt64.max : value
    }
}
