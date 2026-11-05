package main

var constantsShape = newJSONShape("constants").required(
	"cellBytes", "payloadBytes", "ringCapacityPerDirection",
	"maximumCircuits", "shuffleNanoseconds", "coverIntervalNanoseconds",
	"coverTailNanoseconds", "circuitRotationNanoseconds",
	"spikeOverlapNanoseconds",
)

var resourceSnapshotShape = newJSONShape("resources").optional(
	"residentBytes", "physicalFootprintBytes", "availableProcessBytes",
	"userCPUNanoseconds", "systemCPUNanoseconds", "interruptWakeups",
	"packageIdleWakeups", "energyNanojoules", "thermalState", "lowPowerMode",
)

var resourceWindowShape = newJSONShape("resource window").required(
	"firstSampleMonotonicNanoseconds", "lastSampleMonotonicNanoseconds",
	"sampleCount", "scheduledSampleCount", "lowPowerModeObserved",
	"lowPowerModeAlwaysEnabled",
).optional(
	"peakResidentBytes", "peakPhysicalFootprintBytes",
	"minimumAvailableProcessBytes", "userCPUDeltaNanoseconds",
	"systemCPUDeltaNanoseconds", "interruptWakeupDelta",
	"packageIdleWakeupDelta", "energyDeltaNanojoules", "worstThermalState",
)

var dataPathShape = newJSONShape("data path").required(
	"allocatedPrivacyCellBytes", "inboundQueueDepth", "outboundQueueDepth",
	"inboundHighWatermark", "outboundHighWatermark", "occupancySamples",
	"inboundOccupancyP99Cells", "outboundOccupancyP99Cells", "acceptedCells",
	"emittedCells", "droppedCells", "retiredDataCells", "retiredCoverCells",
	"commonPathUnits", "commonPathActiveNanoseconds", "commonPathChecksum",
	"coverPairsAccepted", "coverInboundCellsAccepted",
	"coverOutboundCellsAccepted", "coverPairsEmitted",
	"coverInboundCellsEmitted", "coverOutboundCellsEmitted",
	"coverInboundCellsPending", "coverOutboundCellsPending",
	"coverInboundCellsRetired", "coverOutboundCellsRetired",
	"coverDeadlinesMissed", "maximumCoverLatenessNanoseconds",
	"queueDelaySamples", "queueDelayP99UpperBoundNanoseconds",
	"queueDelayOver25Milliseconds", "maximumObservedQueueDelayNanoseconds",
	"unaccountedWorkNanoseconds", "backpressureEvents", "backpressuredCells",
	"rotationCount", "maximumRotationOverlapNanoseconds",
).optional(
	"rotationActiveCircuit", "rotationStandbyCircuit",
	"rotationOverlapDeadlineNanoseconds",
)

var rotationResourcesShape = newJSONShape("rotation resources").required(
	"samples", "lastRotationCount",
).optional(
	"firstTenPeakResidentBytes", "firstTenPeakPhysicalFootprintBytes",
	"postTenPeakResidentBytes", "postTenPeakPhysicalFootprintBytes",
)

var metricRecordShape = newJSONShape("evidence record").required(
	"schema", "protocolVersion", "frameVersion", "platform", "osVersion",
	"hardwareModel", "runID", "event", "monotonicNanoseconds",
	"wallTimeUTC", "mode", "trafficProfile", "coverSemantics",
	"rotationCadence", "testCondition", "pairID", "durationNanoseconds",
	"trafficActiveNanoseconds", "sourceDigest", "artifactDigest",
).requiredObject("constants", constantsShape).
	optionalObject("resources", resourceSnapshotShape).
	optionalObject("resourceWindow", resourceWindowShape).
	optionalObject("wholeRunResourceWindow", resourceWindowShape).
	optionalObject("dataPath", dataPathShape).
	optionalObject("rotationResources", rotationResourcesShape).
	optional(
		"controlLatencyNanoseconds", "startAttemptNonce",
		"startRequestedAtMonotonicNanoseconds",
		"providerReceivedAtMonotonicNanoseconds", "failureCode",
	)

var startReceiptShape = newJSONShape("start receipt").required(
	"schema", "protocolVersion", "runID", "attemptNonce", "sourceDigest",
	"evidenceFileName", "firstRecordSHA256", "firstRecordBytes",
	"evidenceDurabilityBarrier",
	"requestedAtMonotonicNanoseconds",
	"providerReceivedAtMonotonicNanoseconds",
	"providerReadyAtMonotonicNanoseconds", "providerStartLatencyNanoseconds",
	"hostObservedConnectedAtMonotonicNanoseconds",
	"hostStartLatencyNanoseconds", "measurementScope",
	"artifactScope", "hostReceiptDurabilityScope",
)

var stopReceiptShape = newJSONShape("stop receipt").required(
	"schema", "protocolVersion", "runID", "evidenceFileName",
	"evidenceSHA256", "requestedAtMonotonicNanoseconds",
	"providerReceivedAtMonotonicNanoseconds",
	"providerAcknowledgedAtMonotonicNanoseconds",
	"hostReceivedAtMonotonicNanoseconds", "roundTripNanoseconds",
)

var manifestRunShape = newJSONShape("manifest run").required(
	"evidence", "evidenceSHA256", "mode", "trafficProfile",
	"coverSemantics", "rotationCadence", "testCondition", "pairID", "repeat",
	"durationSeconds", "expectedTerminal", "lowPowerMode", "startThermal",
	"unplugged", "startReceipt", "startReceiptSHA256",
).optional(
	"batteryStartBasisPoints", "batteryEndBasisPoints", "stopReceipt",
	"stopReceiptSHA256",
)

var matrixManifestShape = newJSONShape("matrix manifest").required(
	"schema", "protocolVersion", "sourceDigest", "artifactDigest",
	"osVersion", "hardwareModel",
).requiredArray("runs", manifestRunShape)
